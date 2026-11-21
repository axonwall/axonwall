package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	k8sMaxListBytes = 8 * 1024 * 1024 // 8 MiB max stdout from kubectl get -o json
	k8sMaxTextBytes = 512 * 1024      // 512 KiB max stdout for describe/logs/exec
	k8sMaxYamlBytes = 1024 * 1024     // 1 MiB max YAML apply payload
)

var (
	k8sResourceArgRegex    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`)
	k8sNamespaceArgRegex   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	k8sObjectNameRegex     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$`)
	k8sContainerNameRegex  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	k8sLabelSelectorRegex  = regexp.MustCompile(`^[A-Za-z0-9._/=!,() -]{1,256}$`)
)

// --- Validators ---

func validK8sResourceArg(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "-") || strings.Contains(s, "..") {
		return false
	}
	return k8sResourceArgRegex.MatchString(s)
}

func validK8sNamespaceArg(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || s == "_all" {
		return true
	}
	if strings.HasPrefix(s, "-") {
		return false
	}
	return k8sNamespaceArgRegex.MatchString(s)
}

func validK8sObjectName(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "-") || strings.Contains(s, "..") || strings.ContainsAny(s, "/\\ \t\r\n") {
		return false
	}
	return k8sObjectNameRegex.MatchString(s)
}

func validK8sContainerName(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	if strings.HasPrefix(s, "-") {
		return false
	}
	return k8sContainerNameRegex.MatchString(s)
}

func validK8sLabelSelector(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	if strings.HasPrefix(s, "-") || strings.ContainsAny(s, ";|&`$<>\\\n\r") {
		return false
	}
	return k8sLabelSelectorRegex.MatchString(s)
}

// --- Quantity Parsers ---

// parseK8sCPU converts a Kubernetes CPU quantity string (e.g. "250m", "2", "0.5", "500000000n") into millicores.
func parseK8sCPU(q string) int64 {
	q = strings.TrimSpace(q)
	if q == "" {
		return 0
	}
	if strings.HasSuffix(q, "m") {
		v, err := strconv.ParseFloat(strings.TrimSuffix(q, "m"), 64)
		if err != nil || v < 0 {
			return 0
		}
		return int64(v + 0.5)
	}
	if strings.HasSuffix(q, "n") {
		v, err := strconv.ParseFloat(strings.TrimSuffix(q, "n"), 64)
		if err != nil || v < 0 {
			return 0
		}
		return int64(v/1_000_000.0 + 0.5)
	}
	if strings.HasSuffix(q, "u") {
		v, err := strconv.ParseFloat(strings.TrimSuffix(q, "u"), 64)
		if err != nil || v < 0 {
			return 0
		}
		return int64(v/1_000.0 + 0.5)
	}
	v, err := strconv.ParseFloat(q, 64)
	if err != nil || v < 0 {
		return 0
	}
	return int64(v*1000.0 + 0.5)
}

// parseK8sMemory converts a Kubernetes memory/storage quantity string (e.g. "512Mi", "2Gi", "100M") into bytes.
func parseK8sMemory(q string) int64 {
	q = strings.TrimSpace(q)
	if q == "" {
		return 0
	}
	suffixes := []struct {
		suffix string
		mult   float64
	}{
		{"Ki", 1024},
		{"Mi", 1024 * 1024},
		{"Gi", 1024 * 1024 * 1024},
		{"Ti", 1024 * 1024 * 1024 * 1024},
		{"Pi", 1024 * 1024 * 1024 * 1024 * 1024},
		{"Ei", 1024 * 1024 * 1024 * 1024 * 1024 * 1024},
		{"K", 1000},
		{"k", 1000},
		{"M", 1000 * 1000},
		{"G", 1000 * 1000 * 1000},
		{"T", 1000 * 1000 * 1000 * 1000},
		{"P", 1000 * 1000 * 1000 * 1000 * 1000},
		{"m", 0.001},
	}
	for _, s := range suffixes {
		if strings.HasSuffix(q, s.suffix) {
			numStr := strings.TrimSuffix(q, s.suffix)
			v, err := strconv.ParseFloat(numStr, 64)
			if err != nil || v < 0 {
				return 0
			}
			return int64(v*s.mult + 0.5)
		}
	}
	v, err := strconv.ParseFloat(q, 64)
	if err != nil || v < 0 {
		return 0
	}
	return int64(v + 0.5)
}

// --- Bounded Execution ---

type limitedBuffer struct {
	buf       bytes.Buffer
	max       int64
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.max <= 0 {
		return len(p), nil
	}
	rem := l.max - int64(l.buf.Len())
	if rem <= 0 {
		l.truncated = true
		return len(p), nil
	}
	if int64(len(p)) > rem {
		_, _ = l.buf.Write(p[:rem])
		l.truncated = true
		return len(p), nil
	}
	return l.buf.Write(p)
}

func resolveKubectlBinary() (bin string, baseArgs []string, env []string, err error) {
	env = os.Environ()
	if os.Getenv("KUBECONFIG") == "" {
		if _, statErr := os.Stat("/etc/rancher/k3s/k3s.yaml"); statErr == nil {
			env = append(env, "KUBECONFIG=/etc/rancher/k3s/k3s.yaml")
		}
	}
	if path, lookErr := exec.LookPath("kubectl"); lookErr == nil {
		return path, nil, env, nil
	}
	if path, lookErr := exec.LookPath("k3s"); lookErr == nil {
		return path, []string{"kubectl"}, env, nil
	}
	// Bundled core-k3s plugin paths last: the daemon's PATH never
	// contains the plugin bin dir, so on an appliance whose only
	// kubectl/k3s is the staged plugin tree the LookPath attempts
	// above both miss. The plugin kubectl symlink is preferred
	// over `k3s kubectl`, matching resolveCoreK3sKubectl in k3s.go.
	if path := filepath.Join(coreK3sBinDir(), "kubectl"); isExecutableFile(path) {
		return path, nil, env, nil
	}
	if path := coreK3sBinaryPath(); isExecutableFile(path) {
		return path, []string{"kubectl"}, env, nil
	}
	return "", nil, nil, fmt.Errorf("kubectl/k3s binary not found on system")
}

func runKubectlLimited(ctx context.Context, maxBytes int64, stdin io.Reader, args ...string) ([]byte, []byte, bool, error) {
	bin, baseArgs, env, err := resolveKubectlBinary()
	if err != nil {
		return nil, nil, false, err
	}
	fullArgs := append(append([]string{}, baseArgs...), args...)
	cmd := exec.CommandContext(ctx, bin, fullArgs...)
	cmd.Env = env
	if stdin != nil {
		cmd.Stdin = stdin
	}
	stdoutBuf := &limitedBuffer{max: maxBytes}
	stderrBuf := &limitedBuffer{max: 64 * 1024}
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	runErr := cmd.Run()
	return stdoutBuf.buf.Bytes(), stderrBuf.buf.Bytes(), stdoutBuf.truncated, runErr
}

// --- Response Data Models ---

type K3sNamedCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type K3sClusterCounts struct {
	NodesReady           int `json:"nodesReady"`
	NodesTotal           int `json:"nodesTotal"`
	NodesCordoned        int `json:"nodesCordoned"`
	PodsRunning          int `json:"podsRunning"`
	PodsPending          int `json:"podsPending"`
	PodsFailed           int `json:"podsFailed"`
	PodsSucceeded        int `json:"podsSucceeded"`
	PodsUnknown          int `json:"podsUnknown"`
	PodsTotal            int `json:"podsTotal"`
	TotalRestarts        int `json:"totalRestarts"`
	DeploymentsReady     int `json:"deploymentsReady"`
	DeploymentsTotal     int `json:"deploymentsTotal"`
	StatefulSetsReady    int `json:"statefulSetsReady"`
	StatefulSetsTotal    int `json:"statefulSetsTotal"`
	DaemonSetsReady      int `json:"daemonSetsReady"`
	DaemonSetsTotal      int `json:"daemonSetsTotal"`
	JobsActive           int `json:"jobsActive"`
	JobsSucceeded        int `json:"jobsSucceeded"`
	JobsFailed           int `json:"jobsFailed"`
	CronJobsTotal        int `json:"cronJobsTotal"`
	ServicesTotal        int `json:"servicesTotal"`
	IngressesTotal       int `json:"ingressesTotal"`
	PvcsBound            int `json:"pvcsBound"`
	PvcsTotal            int `json:"pvcsTotal"`
	PvsTotal             int `json:"pvsTotal"`
	StorageClassesTotal  int `json:"storageClassesTotal"`
	NamespacesTotal      int `json:"namespacesTotal"`
	ConfigMapsTotal      int `json:"configMapsTotal"`
	SecretsTotal         int `json:"secretsTotal"`
	NetworkPoliciesTotal int `json:"networkPoliciesTotal"`
	HpasTotal            int `json:"hpasTotal"`
	CrdsTotal            int `json:"crdsTotal"`
	WarningEventsCount   int `json:"warningEventsCount"`
	NormalEventsCount    int `json:"normalEventsCount"`
}

type K3sNamespacePulse struct {
	Name          string `json:"name"`
	Status        string `json:"status"`
	PodsRunning   int    `json:"podsRunning"`
	PodsUnhealthy int    `json:"podsUnhealthy"`
	PodsTotal     int    `json:"podsTotal"`
	Services      int    `json:"services"`
	Ingresses     int    `json:"ingresses"`
	Pvcs          int    `json:"pvcs"`
}

type K3sNodeCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type K3sNodePulse struct {
	Name                 string             `json:"name"`
	Status               string             `json:"status"`
	Roles                string             `json:"roles"`
	InternalIp           string             `json:"internalIp"`
	Version              string             `json:"version"`
	OsImage              string             `json:"osImage"`
	KernelVersion        string             `json:"kernelVersion"`
	ContainerRuntime     string             `json:"containerRuntime"`
	Unschedulable        bool               `json:"unschedulable"`
	CreationTimestamp    string             `json:"creationTimestamp"`
	PodCount             int                `json:"podCount"`
	PodCapacity          int                `json:"podCapacity"`
	CpuCapacityMillis    int64              `json:"cpuCapacityMillis"`
	CpuAllocatableMillis int64              `json:"cpuAllocatableMillis"`
	CpuRequestsMillis    int64              `json:"cpuRequestsMillis"`
	CpuLimitsMillis      int64              `json:"cpuLimitsMillis"`
	CpuUsageMillis       *int64             `json:"cpuUsageMillis,omitempty"`
	MemCapacityBytes     int64              `json:"memCapacityBytes"`
	MemAllocatableBytes  int64              `json:"memAllocatableBytes"`
	MemRequestsBytes     int64              `json:"memRequestsBytes"`
	MemLimitsBytes       int64              `json:"memLimitsBytes"`
	MemUsageBytes        *int64             `json:"memUsageBytes,omitempty"`
	Conditions           []K3sNodeCondition `json:"conditions"`
	Taints               []K3sNodeTaint     `json:"taints"`
	Labels               map[string]string  `json:"labels"`
}

type K3sStorageClassUsage struct {
	Name        string `json:"name"`
	Provisioner string `json:"provisioner"`
	PvcCount    int    `json:"pvcCount"`
	BoundCount  int    `json:"boundCount"`
	TotalBytes  int64  `json:"totalBytes"`
	IsDefault   bool   `json:"isDefault"`
}

type K3sPodHotspot struct {
	Name          string `json:"name"`
	Namespace     string `json:"namespace"`
	Restarts      int    `json:"restarts"`
	Status        string `json:"status"`
	NodeName      string `json:"nodeName"`
	CpuMillis     *int64 `json:"cpuMillis,omitempty"`
	MemBytes      *int64 `json:"memBytes,omitempty"`
	CreationTimestamp string `json:"creationTimestamp"`
}

type K3sEventItem struct {
	Type           string `json:"type"`
	Reason         string `json:"reason"`
	Namespace      string `json:"namespace"`
	InvolvedKind   string `json:"involvedKind"`
	InvolvedName   string `json:"involvedName"`
	Message        string `json:"message"`
	Count          int    `json:"count"`
	LastTimestamp  string `json:"lastTimestamp"`
	Source         string `json:"source"`
}

type K3sWorkloadSummary struct {
	Kind              string   `json:"kind"`
	Resource          string   `json:"resource"`
	Name              string   `json:"name"`
	Namespace         string   `json:"namespace"`
	Ready             int      `json:"ready"`
	Desired           int      `json:"desired"`
	Available         int      `json:"available"`
	Images            []string `json:"images"`
	CreationTimestamp string   `json:"creationTimestamp"`
}

type K3sServiceSummary struct {
	Name           string   `json:"name"`
	Namespace      string   `json:"namespace"`
	Type           string   `json:"type"`
	ClusterIP      string   `json:"clusterIP"`
	ExternalIP     string   `json:"externalIP"`
	Ports          []string `json:"ports"`
	ReadyEndpoints int      `json:"readyEndpoints"`
	CreationTimestamp string `json:"creationTimestamp"`
}

type K3sIngressSummary struct {
	Name              string   `json:"name"`
	Namespace         string   `json:"namespace"`
	Class             string   `json:"class"`
	Hosts             []string `json:"hosts"`
	Address           string   `json:"address"`
	Tls               bool     `json:"tls"`
	Backends          []string `json:"backends"`
	CreationTimestamp string   `json:"creationTimestamp"`
}

type K3sPvcSummary struct {
	Name              string   `json:"name"`
	Namespace         string   `json:"namespace"`
	Status            string   `json:"status"`
	VolumeName        string   `json:"volumeName"`
	Capacity          string   `json:"capacity"`
	CapacityBytes     int64    `json:"capacityBytes"`
	AccessModes       []string `json:"accessModes"`
	StorageClass      string   `json:"storageClass"`
	CreationTimestamp string   `json:"creationTimestamp"`
}

type K3sTopologyNode struct {
	ID             string            `json:"id"`
	Kind           string            `json:"kind"` // Ingress | Service | Deployment | StatefulSet | DaemonSet | Job | Pod | Node | PVC
	Resource       string            `json:"resource"`
	Name           string            `json:"name"`
	Namespace      string            `json:"namespace,omitempty"`
	Status         string            `json:"status"`
	StatusTone     string            `json:"statusTone"` // ok | warn | err | info | muted
	Subtitle       string            `json:"subtitle,omitempty"`
	ParentNodeName string            `json:"parentNodeName,omitempty"`
	Meta           map[string]string `json:"meta,omitempty"`
}

type K3sTopologyEdge struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	Relation string `json:"relation"` // ingress-to-service | service-to-pod | workload-to-pod | pod-to-node | pod-to-pvc
	Label    string `json:"label,omitempty"`
}

type K3sTopologyGraph struct {
	Nodes []K3sTopologyNode `json:"nodes"`
	Edges []K3sTopologyEdge `json:"edges"`
}

type K3sClusterPulse struct {
	Available            bool                    `json:"available"`
	Error                string                  `json:"error,omitempty"`
	Timestamp            string                  `json:"timestamp"`
	MetricsAvailable     bool                    `json:"metricsAvailable"`
	CniPlugin            string                  `json:"cniPlugin"`
	K3sVersion           string                  `json:"k3sVersion"`
	Counts               K3sClusterCounts        `json:"counts"`
	PodPhaseDistribution []K3sNamedCount         `json:"podPhaseDistribution"`
	NamespaceStats       []K3sNamespacePulse     `json:"namespaceStats"`
	Nodes                []K3sNodePulse          `json:"nodes"`
	StorageByClass       []K3sStorageClassUsage  `json:"storageByClass"`
	TopRestartingPods    []K3sPodHotspot         `json:"topRestartingPods"`
	TopResourcePods      []K3sPodHotspot         `json:"topResourcePods"`
	RecentEvents         []K3sEventItem          `json:"recentEvents"`
	WorkloadsSummary     []K3sWorkloadSummary    `json:"workloadsSummary"`
	ServicesSummary      []K3sServiceSummary     `json:"servicesSummary"`
	IngressesSummary     []K3sIngressSummary     `json:"ingressesSummary"`
	PvcsSummary          []K3sPvcSummary         `json:"pvcsSummary"`
	Topology             K3sTopologyGraph        `json:"topology"`
}

type K3sAPIResource struct {
	Name       string   `json:"name"`
	ShortNames []string `json:"shortNames"`
	ApiVersion string   `json:"apiVersion"`
	Namespaced bool     `json:"namespaced"`
	Kind       string   `json:"kind"`
	Verbs      []string `json:"verbs"`
}

type K3sNamespaceSummary struct {
	Name              string            `json:"name"`
	Status            string            `json:"status"`
	CreationTimestamp string            `json:"creationTimestamp"`
	Labels            map[string]string `json:"labels,omitempty"`
	PodCount          int               `json:"podCount"`
}

type K3sResourceItem struct {
	UID               string            `json:"uid"`
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace,omitempty"`
	Kind              string            `json:"kind"`
	ApiVersion        string            `json:"apiVersion"`
	CreationTimestamp string            `json:"creationTimestamp"`
	Status            string            `json:"status"`
	StatusTone        string            `json:"statusTone"`
	Labels            map[string]string `json:"labels,omitempty"`
	OwnerRef          string            `json:"ownerRef,omitempty"`
	Summary           map[string]any    `json:"summary"`
}

type K3sResourceListResponse struct {
	Resource   string            `json:"resource"`
	Namespace  string            `json:"namespace"`
	Namespaced bool              `json:"namespaced"`
	Items      []K3sResourceItem `json:"items"`
	Count      int               `json:"count"`
	Error      string            `json:"error,omitempty"`
}

type K3sRelatedResource struct {
	Relation   string `json:"relation"`
	Kind       string `json:"kind"`
	Resource   string `json:"resource"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace,omitempty"`
	Status     string `json:"status,omitempty"`
	StatusTone string `json:"statusTone,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type K3sResourceInspectResponse struct {
	Resource          string                 `json:"resource"`
	Kind              string                 `json:"kind"`
	ApiVersion        string                 `json:"apiVersion"`
	Name              string                 `json:"name"`
	Namespace         string                 `json:"namespace,omitempty"`
	Object            map[string]any         `json:"object"`
	Yaml              string                 `json:"yaml"`
	Describe          string                 `json:"describe"`
	Events            []K3sEventItem         `json:"events"`
	Related           []K3sRelatedResource   `json:"related"`
	DecodedSecretData map[string]string      `json:"decodedSecretData,omitempty"`
	SecretRedacted    bool                   `json:"secretRedacted,omitempty"`
	Error             string                 `json:"error,omitempty"`
}

type K3sLogsRequest struct {
	Namespace    string `json:"namespace"`
	Name         string `json:"name"`
	Resource     string `json:"resource"`
	Container    string `json:"container"`
	Tail         int    `json:"tail"`
	Previous     bool   `json:"previous"`
	Timestamps   bool   `json:"timestamps"`
	SinceSeconds int    `json:"sinceSeconds"`
}

type K3sLogsResponse struct {
	Logs       string `json:"logs"`
	LinesCount int    `json:"linesCount"`
	Truncated  bool   `json:"truncated"`
	Container  string `json:"container,omitempty"`
	Previous   bool   `json:"previous"`
}

type K3sActionRequest struct {
	Action    string `json:"action"` // delete, scale, rollout-restart, rollout-undo, cordon, uncordon, drain, trigger-cronjob, suspend-cronjob, apply-yaml, exec
	Resource  string `json:"resource,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	Replicas  *int   `json:"replicas,omitempty"`
	Suspend   *bool  `json:"suspend,omitempty"`
	Force     bool   `json:"force,omitempty"`
	DryRun    bool   `json:"dryRun,omitempty"`
	Yaml      string `json:"yaml,omitempty"`
	Container string `json:"container,omitempty"`
	Command   string `json:"command,omitempty"`
}

type K3sActionResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	Output    string `json:"output,omitempty"`
	ExitCode  int    `json:"exitCode"`
	LatencyMs int64  `json:"latencyMs,omitempty"`
}

// --- Generic JSON navigation helpers ---

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok && m != nil {
		return m
	}
	return nil
}

func asSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

func asStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case bool:
		return strconv.FormatBool(t)
	default:
		return ""
	}
}

func asInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 0
	}
}

func asBool(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func asStrMap(v any) map[string]string {
	m := asMap(v)
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		out[k] = asStr(val)
	}
	return out
}

func asStrSlice(v any) []string {
	s := asSlice(v)
	if len(s) == 0 {
		return nil
	}
	out := make([]string, 0, len(s))
	for _, x := range s {
		if str := asStr(x); str != "" {
			out = append(out, str)
		}
	}
	return out
}

func getPath(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		cm := asMap(cur)
		if cm == nil {
			return nil
		}
		cur = cm[k]
	}
	return cur
}

func getStr(m map[string]any, keys ...string) string {
	return asStr(getPath(m, keys...))
}

func getInt(m map[string]any, keys ...string) int {
	return asInt(getPath(m, keys...))
}

func getBool(m map[string]any, keys ...string) bool {
	return asBool(getPath(m, keys...))
}

// --- Static Resource Metadata ---

var clusterScopedResourceSet = map[string]bool{
	"node": true, "nodes": true, "no": true,
	"namespace": true, "namespaces": true, "ns": true,
	"persistentvolume": true, "persistentvolumes": true, "pv": true,
	"storageclass": true, "storageclasses": true, "sc": true,
	"clusterrole": true, "clusterroles": true, "cr": true,
	"clusterrolebinding": true, "clusterrolebindings": true, "crb": true,
	"customresourcedefinition": true, "customresourcedefinitions": true, "crd": true, "crds": true,
	"ingressclass": true, "ingressclasses": true,
	"priorityclass": true, "priorityclasses": true, "pc": true,
	"runtimeclass": true, "runtimeclasses": true,
	"csidriver": true, "csidrivers": true,
	"csinode": true, "csinodes": true,
	"volumeattachment": true, "volumeattachments": true,
	"mutatingwebhookconfiguration": true, "mutatingwebhookconfigurations": true,
	"validatingwebhookconfiguration": true, "validatingwebhookconfigurations": true,
	"apiservice": true, "apiservices": true,
}

func isKnownClusterScoped(resource string) (known bool, clusterScoped bool) {
	norm := strings.ToLower(strings.TrimSpace(resource))
	if clusterScopedResourceSet[norm] {
		return true, true
	}
	knownNamespaced := map[string]bool{
		"pod": true, "pods": true, "po": true,
		"deployment": true, "deployments": true, "deploy": true,
		"statefulset": true, "statefulsets": true, "sts": true,
		"daemonset": true, "daemonsets": true, "ds": true,
		"replicaset": true, "replicasets": true, "rs": true,
		"job": true, "jobs": true,
		"cronjob": true, "cronjobs": true, "cj": true,
		"service": true, "services": true, "svc": true,
		"ingress": true, "ingresses": true, "ing": true,
		"endpoints": true, "ep": true,
		"endpointslice": true, "endpointslices": true,
		"networkpolicy": true, "networkpolicies": true, "netpol": true,
		"persistentvolumeclaim": true, "persistentvolumeclaims": true, "pvc": true,
		"configmap": true, "configmaps": true, "cm": true,
		"secret": true, "secrets": true, "sec": true,
		"event": true, "events": true, "ev": true,
		"horizontalpodautoscaler": true, "horizontalpodautoscalers": true, "hpa": true,
		"serviceaccount": true, "serviceaccounts": true, "sa": true,
		"role": true, "roles": true,
		"rolebinding": true, "rolebindings": true, "rb": true,
		"lease": true, "leases": true,
		"poddisruptionbudget": true, "poddisruptionbudgets": true, "pdb": true,
		"resourcequota": true, "resourcequotas": true, "quota": true,
		"limitrange": true, "limitranges": true, "limits": true,
	}
	if knownNamespaced[norm] {
		return true, false
	}
	return false, false
}

func resolveResourceScopeNamespaced(ctx context.Context, resource string) bool {
	if known, cs := isKnownClusterScoped(resource); known {
		return !cs
	}
	// Query api-resources dynamically for CRDs / less-common built-ins
	apiCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, _, _, err := runKubectlLimited(apiCtx, k8sMaxTextBytes, nil, "api-resources", "--no-headers")
	if err != nil {
		return true
	}
	norm := strings.ToLower(strings.TrimSpace(resource))
	for _, r := range parseAPIResourcesTable(string(out)) {
		if strings.ToLower(r.Name) == norm || strings.ToLower(r.Kind) == norm {
			return r.Namespaced
		}
		for _, sn := range r.ShortNames {
			if strings.ToLower(sn) == norm {
				return r.Namespaced
			}
		}
	}
	return true
}

func pluralResourceForKind(kind string) string {
	switch strings.ToLower(kind) {
	case "pod":
		return "pods"
	case "deployment":
		return "deployments"
	case "statefulset":
		return "statefulsets"
	case "daemonset":
		return "daemonsets"
	case "replicaset":
		return "replicasets"
	case "job":
		return "jobs"
	case "cronjob":
		return "cronjobs"
	case "service":
		return "services"
	case "ingress":
		return "ingresses"
	case "endpoints":
		return "endpoints"
	case "networkpolicy":
		return "networkpolicies"
	case "persistentvolumeclaim":
		return "persistentvolumeclaims"
	case "persistentvolume":
		return "persistentvolumes"
	case "storageclass":
		return "storageclasses"
	case "configmap":
		return "configmaps"
	case "secret":
		return "secrets"
	case "event":
		return "events"
	case "node":
		return "nodes"
	case "namespace":
		return "namespaces"
	case "horizontalpodautoscaler":
		return "horizontalpodautoscalers"
	case "serviceaccount":
		return "serviceaccounts"
	case "role":
		return "roles"
	case "rolebinding":
		return "rolebindings"
	case "clusterrole":
		return "clusterroles"
	case "clusterrolebinding":
		return "clusterrolebindings"
	case "customresourcedefinition":
		return "customresourcedefinitions"
	default:
		k := strings.ToLower(kind)
		if strings.HasSuffix(k, "s") {
			return k + "es"
		}
		return k + "s"
	}
}

// --- Top Metrics Helpers ---

type podUsageMetric struct {
	cpuMillis int64
	memBytes  int64
}

func parseTopNodesOutput(raw string) map[string]podUsageMetric {
	out := make(map[string]podUsageMetric)
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		fields := strings.Fields(line)
		// NAME CPU(cores) CPU% MEMORY(bytes) MEMORY%
		if len(fields) < 4 {
			continue
		}
		name := fields[0]
		cpu := parseK8sCPU(fields[1])
		mem := parseK8sMemory(fields[3])
		out[name] = podUsageMetric{cpuMillis: cpu, memBytes: mem}
	}
	return out
}

func parseTopPodsOutput(raw string) map[string]podUsageMetric {
	out := make(map[string]podUsageMetric)
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		fields := strings.Fields(line)
		// NAMESPACE NAME CPU(cores) MEMORY(bytes)
		if len(fields) < 4 {
			continue
		}
		key := fields[0] + "/" + fields[1]
		cpu := parseK8sCPU(fields[2])
		mem := parseK8sMemory(fields[3])
		out[key] = podUsageMetric{cpuMillis: cpu, memBytes: mem}
	}
	return out
}

// --- Pod Status & Summary Normalization ---

type podDerivedStatus struct {
	reason     string
	tone       string
	readyCount int
	totalCount int
	restarts   int
	containers []string
	cpuReq     int64
	cpuLim     int64
	memReq     int64
	memLim     int64
}

func derivePodDetails(item map[string]any) podDerivedStatus {
	spec := asMap(item["spec"])
	status := asMap(item["status"])
	meta := asMap(item["metadata"])

	phase := asStr(status["phase"])
	reason := phase
	if reason == "" {
		reason = "Unknown"
	}
	if getStr(meta, "deletionTimestamp") != "" {
		reason = "Terminating"
	} else if r := asStr(status["reason"]); r != "" {
		reason = r
	}

	var res podDerivedStatus
	for _, cAny := range asSlice(spec["containers"]) {
		c := asMap(cAny)
		if c == nil {
			continue
		}
		if cname := asStr(c["name"]); cname != "" {
			res.containers = append(res.containers, cname)
		}
		req := asMap(getPath(c, "resources", "requests"))
		lim := asMap(getPath(c, "resources", "limits"))
		res.cpuReq += parseK8sCPU(asStr(req["cpu"]))
		res.cpuLim += parseK8sCPU(asStr(lim["cpu"]))
		res.memReq += parseK8sMemory(asStr(req["memory"]))
		res.memLim += parseK8sMemory(asStr(lim["memory"]))
	}

	// Check init container waiting errors
	for _, icAny := range asSlice(status["initContainerStatuses"]) {
		ic := asMap(icAny)
		if ic == nil {
			continue
		}
		res.restarts += asInt(ic["restartCount"])
		if waitReason := getStr(ic, "state", "waiting", "reason"); waitReason != "" && reason != "Terminating" {
			reason = "Init:" + waitReason
		} else if termReason := getStr(ic, "state", "terminated", "reason"); termReason != "" && asInt(getPath(ic, "state", "terminated", "exitCode")) != 0 && reason != "Terminating" {
			reason = "Init:" + termReason
		}
	}

	cStatuses := asSlice(status["containerStatuses"])
	res.totalCount = len(cStatuses)
	if res.totalCount == 0 {
		res.totalCount = len(res.containers)
	}
	for _, csAny := range cStatuses {
		cs := asMap(csAny)
		if cs == nil {
			continue
		}
		if asBool(cs["ready"]) {
			res.readyCount++
		}
		res.restarts += asInt(cs["restartCount"])
		if reason != "Terminating" {
			if waitReason := getStr(cs, "state", "waiting", "reason"); waitReason != "" {
				reason = waitReason
			} else if termReason := getStr(cs, "state", "terminated", "reason"); termReason != "" && phase != "Running" && phase != "Succeeded" {
				reason = termReason
			}
		}
	}

	switch {
	case reason == "Running" && res.readyCount == res.totalCount && res.totalCount > 0:
		res.tone = "ok"
	case reason == "Running":
		res.tone = "warn"
	case reason == "Completed" || reason == "Succeeded":
		res.tone = "info"
	case reason == "Pending" || reason == "ContainerCreating" || reason == "PodInitializing" || reason == "Terminating":
		res.tone = "warn"
	default:
		res.tone = "err"
	}
	res.reason = reason
	return res
}

func statusToneForNode(status string, unschedulable bool) string {
	if status == "Ready" && !unschedulable {
		return "ok"
	}
	if status == "Ready" && unschedulable {
		return "warn"
	}
	return "err"
}

func formatPortsList(ports []any) []string {
	var out []string
	for _, pAny := range ports {
		p := asMap(pAny)
		if p == nil {
			continue
		}
		portNum := asInt(p["port"])
		proto := asStr(p["protocol"])
		if proto == "" {
			proto = "TCP"
		}
		nodePort := asInt(p["nodePort"])
		targetPort := asStr(p["targetPort"])
		entry := fmt.Sprintf("%d", portNum)
		if nodePort > 0 {
			entry = fmt.Sprintf("%d:%d", portNum, nodePort)
		} else if targetPort != "" && targetPort != strconv.Itoa(portNum) {
			entry = fmt.Sprintf("%d→%s", portNum, targetPort)
		}
		entry += "/" + proto
		out = append(out, entry)
	}
	return out
}

func extractIngressDetails(item map[string]any) (class string, hosts []string, address string, hasTLS bool, backends []string) {
	spec := asMap(item["spec"])
	status := asMap(item["status"])
	meta := asMap(item["metadata"])

	class = asStr(spec["ingressClassName"])
	if class == "" {
		if ann := asStrMap(meta["annotations"]); ann != nil {
			class = ann["kubernetes.io/ingress.class"]
		}
	}
	tlsSlice := asSlice(spec["tls"])
	hasTLS = len(tlsSlice) > 0

	var addrs []string
	for _, ingAny := range asSlice(getPath(status, "loadBalancer", "ingress")) {
		ing := asMap(ingAny)
		if ip := asStr(ing["ip"]); ip != "" {
			addrs = append(addrs, ip)
		} else if hn := asStr(ing["hostname"]); hn != "" {
			addrs = append(addrs, hn)
		}
	}
	address = strings.Join(addrs, ",")

	hostSeen := make(map[string]bool)
	backendSeen := make(map[string]bool)

	if defSvc := getStr(spec, "defaultBackend", "service", "name"); defSvc != "" {
		backendSeen[defSvc] = true
		backends = append(backends, defSvc)
	}
	for _, rAny := range asSlice(spec["rules"]) {
		r := asMap(rAny)
		if r == nil {
			continue
		}
		if h := asStr(r["host"]); h != "" && !hostSeen[h] {
			hostSeen[h] = true
			hosts = append(hosts, h)
		}
		for _, pathAny := range asSlice(getPath(r, "http", "paths")) {
			pathM := asMap(pathAny)
			svcName := getStr(pathM, "backend", "service", "name")
			if svcName == "" {
				svcName = getStr(pathM, "backend", "serviceName") // networking.k8s.io/v1beta1 fallback
			}
			if svcName != "" && !backendSeen[svcName] {
				backendSeen[svcName] = true
				backends = append(backends, svcName)
			}
		}
	}
	return
}

func extractContainerImages(spec map[string]any) []string {
	tplContainers := asSlice(getPath(spec, "template", "spec", "containers"))
	if len(tplContainers) == 0 {
		tplContainers = asSlice(getPath(spec, "jobTemplate", "spec", "template", "spec", "containers"))
	}
	if len(tplContainers) == 0 {
		tplContainers = asSlice(spec["containers"])
	}
	var imgs []string
	for _, cAny := range tplContainers {
		if img := getStr(asMap(cAny), "image"); img != "" {
			imgs = append(imgs, img)
		}
	}
	return imgs
}

func extractOwnerRefSummary(meta map[string]any) string {
	for _, oAny := range asSlice(meta["ownerReferences"]) {
		o := asMap(oAny)
		if o != nil {
			return fmt.Sprintf("%s/%s", asStr(o["kind"]), asStr(o["name"]))
		}
	}
	return ""
}

// --- GetClusterPulse ---

func (m *K3sManager) GetClusterPulse(ctx context.Context) (*K3sClusterPulse, error) {
	pulseCtx, cancel := context.WithTimeout(ctx, 14*time.Second)
	defer cancel()

	m.mu.Lock()
	cniPlugin := m.cfg.CniPlugin
	m.mu.Unlock()
	if cniPlugin == "" {
		cniPlugin = "flannel"
	}

	pulse := &K3sClusterPulse{
		Timestamp:            time.Now().UTC().Format(time.RFC3339),
		CniPlugin:            cniPlugin,
		PodPhaseDistribution: []K3sNamedCount{},
		NamespaceStats:       []K3sNamespacePulse{},
		Nodes:                []K3sNodePulse{},
		StorageByClass:       []K3sStorageClassUsage{},
		TopRestartingPods:    []K3sPodHotspot{},
		TopResourcePods:      []K3sPodHotspot{},
		RecentEvents:         []K3sEventItem{},
		WorkloadsSummary:     []K3sWorkloadSummary{},
		ServicesSummary:      []K3sServiceSummary{},
		IngressesSummary:     []K3sIngressSummary{},
		PvcsSummary:          []K3sPvcSummary{},
		Topology: K3sTopologyGraph{
			Nodes: []K3sTopologyNode{},
			Edges: []K3sTopologyEdge{},
		},
	}

	fetchJSONItems := func(args ...string) ([]map[string]any, error) {
		out, errOut, _, err := runKubectlLimited(pulseCtx, k8sMaxListBytes, nil, args...)
		if err != nil {
			msg := strings.TrimSpace(string(errOut))
			if msg == "" {
				msg = err.Error()
			}
			return nil, fmt.Errorf("%s", msg)
		}
		var doc struct {
			Items []map[string]any `json:"items"`
		}
		if uErr := json.Unmarshal(out, &doc); uErr != nil {
			return nil, uErr
		}
		return doc.Items, nil
	}

	var (
		nodesItems, podsItems, deployItems, stsItems, dsItems, rsItems []map[string]any
		jobItems, cjItems, svcItems, ingItems, epItems, pvcItems       []map[string]any
		pvItems, scItems, nsItems, evItems, cmItems, secItems          []map[string]any
		npItems, hpaItems, crdItems                                    []map[string]any
		nodesErr                                                       error
		topNodesRaw, topPodsRaw                                        string
		topNodesOk, topPodsOk                                          bool
	)

	var wg sync.WaitGroup
	runFetch := func(dst *[]map[string]any, errDst *error, args ...string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			items, err := fetchJSONItems(args...)
			if err == nil {
				*dst = items
			} else if errDst != nil {
				*errDst = err
			}
		}()
	}

	runFetch(&nodesItems, &nodesErr, "get", "nodes", "-o", "json")
	runFetch(&podsItems, nil, "get", "pods", "-A", "-o", "json")
	runFetch(&deployItems, nil, "get", "deployments", "-A", "-o", "json")
	runFetch(&stsItems, nil, "get", "statefulsets", "-A", "-o", "json")
	runFetch(&dsItems, nil, "get", "daemonsets", "-A", "-o", "json")
	runFetch(&rsItems, nil, "get", "replicasets", "-A", "-o", "json")
	runFetch(&jobItems, nil, "get", "jobs", "-A", "-o", "json")
	runFetch(&cjItems, nil, "get", "cronjobs", "-A", "-o", "json")
	runFetch(&svcItems, nil, "get", "services", "-A", "-o", "json")
	runFetch(&ingItems, nil, "get", "ingresses", "-A", "-o", "json")
	runFetch(&epItems, nil, "get", "endpoints", "-A", "-o", "json")
	runFetch(&pvcItems, nil, "get", "pvc", "-A", "-o", "json")
	runFetch(&pvItems, nil, "get", "pv", "-o", "json")
	runFetch(&scItems, nil, "get", "storageclass", "-o", "json")
	runFetch(&nsItems, nil, "get", "namespaces", "-o", "json")
	runFetch(&evItems, nil, "get", "events", "-A", "-o", "json")
	runFetch(&cmItems, nil, "get", "configmaps", "-A", "-o", "json")
	runFetch(&secItems, nil, "get", "secrets", "-A", "-o", "json")
	runFetch(&npItems, nil, "get", "networkpolicies", "-A", "-o", "json")
	runFetch(&hpaItems, nil, "get", "hpa", "-A", "-o", "json")
	runFetch(&crdItems, nil, "get", "crd", "-o", "json")

	wg.Add(2)
	go func() {
		defer wg.Done()
		out, _, _, err := runKubectlLimited(pulseCtx, k8sMaxTextBytes, nil, "top", "nodes", "--no-headers")
		if err == nil && len(bytes.TrimSpace(out)) > 0 {
			topNodesRaw = string(out)
			topNodesOk = true
		}
	}()
	go func() {
		defer wg.Done()
		out, _, _, err := runKubectlLimited(pulseCtx, k8sMaxTextBytes, nil, "top", "pods", "-A", "--no-headers")
		if err == nil && len(bytes.TrimSpace(out)) > 0 {
			topPodsRaw = string(out)
			topPodsOk = true
		}
	}()

	wg.Wait()

	if nodesErr != nil {
		pulse.Available = false
		pulse.Error = fmt.Sprintf("Kubernetes API unreachable: %v", nodesErr)
		return pulse, nil
	}

	pulse.Available = true
	pulse.MetricsAvailable = topNodesOk || topPodsOk
	nodeTopMap := parseTopNodesOutput(topNodesRaw)
	podTopMap := parseTopPodsOutput(topPodsRaw)

	// Per-namespace aggregation
	nsStatsMap := make(map[string]*K3sNamespacePulse)
	ensureNs := func(name string) *K3sNamespacePulse {
		if name == "" {
			name = "default"
		}
		if cur, ok := nsStatsMap[name]; ok {
			return cur
		}
		cur := &K3sNamespacePulse{Name: name, Status: "Active"}
		nsStatsMap[name] = cur
		return cur
	}
	for _, n := range nsItems {
		meta := asMap(n["metadata"])
		name := asStr(meta["name"])
		st := getStr(n, "status", "phase")
		if st == "" {
			st = "Active"
		}
		entry := ensureNs(name)
		entry.Status = st
	}

	// Node resource aggregation maps keyed by nodeName
	nodePodCounts := make(map[string]int)
	nodeCpuReq := make(map[string]int64)
	nodeCpuLim := make(map[string]int64)
	nodeMemReq := make(map[string]int64)
	nodeMemLim := make(map[string]int64)

	// ReplicaSet UID -> Deployment Name map (so Deployment -> Pod links collapse ReplicaSet)
	rsToDeploy := make(map[string]string) // key: ns/rsName -> deployName
	for _, rs := range rsItems {
		meta := asMap(rs["metadata"])
		ns := asStr(meta["namespace"])
		name := asStr(meta["name"])
		for _, oAny := range asSlice(meta["ownerReferences"]) {
			o := asMap(oAny)
			if asStr(o["kind"]) == "Deployment" {
				rsToDeploy[ns+"/"+name] = asStr(o["name"])
				break
			}
		}
	}

	phaseCounts := make(map[string]int)
	var restartingPods []K3sPodHotspot
	var resourcePods []K3sPodHotspot

	// Process Pods
	for _, pod := range podsItems {
		meta := asMap(pod["metadata"])
		spec := asMap(pod["spec"])
		status := asMap(pod["status"])
		name := asStr(meta["name"])
		ns := asStr(meta["namespace"])
		nodeName := asStr(spec["nodeName"])
		phase := asStr(status["phase"])
		created := asStr(meta["creationTimestamp"])

		derived := derivePodDetails(pod)
		pulse.Counts.PodsTotal++
		pulse.Counts.TotalRestarts += derived.restarts

		nsEntry := ensureNs(ns)
		nsEntry.PodsTotal++

		switch phase {
		case "Running":
			if derived.tone == "ok" {
				pulse.Counts.PodsRunning++
				nsEntry.PodsRunning++
			} else {
				// Running container(s) not ready yet counts as unhealthy in NS breakdown
				pulse.Counts.PodsRunning++
				nsEntry.PodsUnhealthy++
			}
		case "Pending":
			pulse.Counts.PodsPending++
			nsEntry.PodsUnhealthy++
		case "Succeeded":
			pulse.Counts.PodsSucceeded++
		case "Failed":
			pulse.Counts.PodsFailed++
			nsEntry.PodsUnhealthy++
		default:
			pulse.Counts.PodsUnknown++
			nsEntry.PodsUnhealthy++
		}

		distKey := derived.reason
		if distKey == "" {
			distKey = phase
		}
		if distKey == "" {
			distKey = "Unknown"
		}
		phaseCounts[distKey]++

		if nodeName != "" && phase != "Succeeded" && phase != "Failed" {
			nodePodCounts[nodeName]++
			nodeCpuReq[nodeName] += derived.cpuReq
			nodeCpuLim[nodeName] += derived.cpuLim
			nodeMemReq[nodeName] += derived.memReq
			nodeMemLim[nodeName] += derived.memLim
		} else if nodeName != "" {
			nodePodCounts[nodeName]++
		}

		var cpuPtr *int64
		var memPtr *int64
		if tm, ok := podTopMap[ns+"/"+name]; ok {
			cVal := tm.cpuMillis
			mVal := tm.memBytes
			cpuPtr = &cVal
			memPtr = &mVal
			resourcePods = append(resourcePods, K3sPodHotspot{
				Name:              name,
				Namespace:         ns,
				Restarts:          derived.restarts,
				Status:            derived.reason,
				NodeName:          nodeName,
				CpuMillis:         cpuPtr,
				MemBytes:          memPtr,
				CreationTimestamp: created,
			})
		}

		if derived.restarts > 0 {
			restartingPods = append(restartingPods, K3sPodHotspot{
				Name:              name,
				Namespace:         ns,
				Restarts:          derived.restarts,
				Status:            derived.reason,
				NodeName:          nodeName,
				CpuMillis:         cpuPtr,
				MemBytes:          memPtr,
				CreationTimestamp: created,
			})
		}
	}

	for k, c := range phaseCounts {
		pulse.PodPhaseDistribution = append(pulse.PodPhaseDistribution, K3sNamedCount{Name: k, Count: c})
	}
	sort.Slice(pulse.PodPhaseDistribution, func(i, j int) bool {
		if pulse.PodPhaseDistribution[i].Count != pulse.PodPhaseDistribution[j].Count {
			return pulse.PodPhaseDistribution[i].Count > pulse.PodPhaseDistribution[j].Count
		}
		return pulse.PodPhaseDistribution[i].Name < pulse.PodPhaseDistribution[j].Name
	})

	sort.Slice(restartingPods, func(i, j int) bool {
		return restartingPods[i].Restarts > restartingPods[j].Restarts
	})
	if len(restartingPods) > 10 {
		restartingPods = restartingPods[:10]
	}
	pulse.TopRestartingPods = restartingPods

	sort.Slice(resourcePods, func(i, j int) bool {
		ci, cj := int64(0), int64(0)
		if resourcePods[i].CpuMillis != nil {
			ci = *resourcePods[i].CpuMillis
		}
		if resourcePods[j].CpuMillis != nil {
			cj = *resourcePods[j].CpuMillis
		}
		if ci != cj {
			return ci > cj
		}
		mi, mj := int64(0), int64(0)
		if resourcePods[i].MemBytes != nil {
			mi = *resourcePods[i].MemBytes
		}
		if resourcePods[j].MemBytes != nil {
			mj = *resourcePods[j].MemBytes
		}
		return mi > mj
	})
	if len(resourcePods) > 10 {
		resourcePods = resourcePods[:10]
	}
	pulse.TopResourcePods = resourcePods

	// Process Nodes
	for _, nItem := range nodesItems {
		meta := asMap(nItem["metadata"])
		spec := asMap(nItem["spec"])
		status := asMap(nItem["status"])
		name := asStr(meta["name"])
		labels := asStrMap(meta["labels"])
		unsched := asBool(spec["unschedulable"])

		var roles []string
		for k := range labels {
			if strings.HasPrefix(k, "node-role.kubernetes.io/") {
				roles = append(roles, strings.TrimPrefix(k, "node-role.kubernetes.io/"))
			}
		}
		sort.Strings(roles)
		roleStr := "worker"
		if len(roles) > 0 {
			roleStr = strings.Join(roles, ",")
		}

		nodeStatus := "NotReady"
		var conds []K3sNodeCondition
		for _, cAny := range asSlice(status["conditions"]) {
			c := asMap(cAny)
			if c == nil {
				continue
			}
			cType := asStr(c["type"])
			cStat := asStr(c["status"])
			if cType == "Ready" && cStat == "True" {
				nodeStatus = "Ready"
			}
			conds = append(conds, K3sNodeCondition{
				Type:    cType,
				Status:  cStat,
				Reason:  asStr(c["reason"]),
				Message: asStr(c["message"]),
			})
		}

		var internalIP string
		for _, aAny := range asSlice(status["addresses"]) {
			a := asMap(aAny)
			if asStr(a["type"]) == "InternalIP" {
				internalIP = asStr(a["address"])
				break
			}
		}

		nodeInfo := asMap(status["nodeInfo"])
		kVer := asStr(nodeInfo["kubeletVersion"])
		if pulse.K3sVersion == "" && kVer != "" {
			pulse.K3sVersion = kVer
		}

		capMap := asMap(status["capacity"])
		allocMap := asMap(status["allocatable"])

		var taints []K3sNodeTaint
		for _, tAny := range asSlice(spec["taints"]) {
			t := asMap(tAny)
			if t == nil {
				continue
			}
			taints = append(taints, K3sNodeTaint{
				Key:    asStr(t["key"]),
				Value:  asStr(t["value"]),
				Effect: asStr(t["effect"]),
			})
		}

		pulse.Counts.NodesTotal++
		if nodeStatus == "Ready" {
			pulse.Counts.NodesReady++
		}
		if unsched {
			pulse.Counts.NodesCordoned++
		}

		var cpuUsePtr, memUsePtr *int64
		if tm, ok := nodeTopMap[name]; ok {
			cVal := tm.cpuMillis
			mVal := tm.memBytes
			cpuUsePtr = &cVal
			memUsePtr = &mVal
		}

		pulse.Nodes = append(pulse.Nodes, K3sNodePulse{
			Name:                 name,
			Status:               nodeStatus,
			Roles:                roleStr,
			InternalIp:           internalIP,
			Version:              kVer,
			OsImage:              asStr(nodeInfo["osImage"]),
			KernelVersion:        asStr(nodeInfo["kernelVersion"]),
			ContainerRuntime:     asStr(nodeInfo["containerRuntimeVersion"]),
			Unschedulable:        unsched,
			CreationTimestamp:    asStr(meta["creationTimestamp"]),
			PodCount:             nodePodCounts[name],
			PodCapacity:          asInt(allocMap["pods"]),
			CpuCapacityMillis:    parseK8sCPU(asStr(capMap["cpu"])),
			CpuAllocatableMillis: parseK8sCPU(asStr(allocMap["cpu"])),
			CpuRequestsMillis:    nodeCpuReq[name],
			CpuLimitsMillis:      nodeCpuLim[name],
			CpuUsageMillis:       cpuUsePtr,
			MemCapacityBytes:     parseK8sMemory(asStr(capMap["memory"])),
			MemAllocatableBytes:  parseK8sMemory(asStr(allocMap["memory"])),
			MemRequestsBytes:     nodeMemReq[name],
			MemLimitsBytes:       nodeMemLim[name],
			MemUsageBytes:        memUsePtr,
			Conditions:           conds,
			Taints:               taints,
			Labels:               labels,
		})
	}

	// Process Workloads (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs)
	for _, d := range deployItems {
		meta := asMap(d["metadata"])
		spec := asMap(d["spec"])
		status := asMap(d["status"])
		desired := asInt(spec["replicas"])
		ready := asInt(status["readyReplicas"])
		avail := asInt(status["availableReplicas"])
		pulse.Counts.DeploymentsTotal++
		if desired == 0 || ready >= desired {
			pulse.Counts.DeploymentsReady++
		}
		pulse.WorkloadsSummary = append(pulse.WorkloadsSummary, K3sWorkloadSummary{
			Kind:              "Deployment",
			Resource:          "deployments",
			Name:              asStr(meta["name"]),
			Namespace:         asStr(meta["namespace"]),
			Ready:             ready,
			Desired:           desired,
			Available:         avail,
			Images:            extractContainerImages(spec),
			CreationTimestamp: asStr(meta["creationTimestamp"]),
		})
	}
	for _, s := range stsItems {
		meta := asMap(s["metadata"])
		spec := asMap(s["spec"])
		status := asMap(s["status"])
		desired := asInt(spec["replicas"])
		ready := asInt(status["readyReplicas"])
		pulse.Counts.StatefulSetsTotal++
		if desired == 0 || ready >= desired {
			pulse.Counts.StatefulSetsReady++
		}
		pulse.WorkloadsSummary = append(pulse.WorkloadsSummary, K3sWorkloadSummary{
			Kind:              "StatefulSet",
			Resource:          "statefulsets",
			Name:              asStr(meta["name"]),
			Namespace:         asStr(meta["namespace"]),
			Ready:             ready,
			Desired:           desired,
			Available:         ready,
			Images:            extractContainerImages(spec),
			CreationTimestamp: asStr(meta["creationTimestamp"]),
		})
	}
	for _, ds := range dsItems {
		meta := asMap(ds["metadata"])
		spec := asMap(ds["spec"])
		status := asMap(ds["status"])
		desired := asInt(status["desiredNumberScheduled"])
		ready := asInt(status["numberReady"])
		avail := asInt(status["numberAvailable"])
		pulse.Counts.DaemonSetsTotal++
		if desired == 0 || ready >= desired {
			pulse.Counts.DaemonSetsReady++
		}
		pulse.WorkloadsSummary = append(pulse.WorkloadsSummary, K3sWorkloadSummary{
			Kind:              "DaemonSet",
			Resource:          "daemonsets",
			Name:              asStr(meta["name"]),
			Namespace:         asStr(meta["namespace"]),
			Ready:             ready,
			Desired:           desired,
			Available:         avail,
			Images:            extractContainerImages(spec),
			CreationTimestamp: asStr(meta["creationTimestamp"]),
		})
	}
	for _, j := range jobItems {
		status := asMap(j["status"])
		pulse.Counts.JobsActive += asInt(status["active"])
		pulse.Counts.JobsSucceeded += asInt(status["succeeded"])
		pulse.Counts.JobsFailed += asInt(status["failed"])
	}
	pulse.Counts.CronJobsTotal = len(cjItems)

	// Endpoints lookup for Services: ns/name -> ready addresses count & targetPodUIDs
	epReadyCounts := make(map[string]int)
	epTargetPodUIDs := make(map[string][]string)
	for _, ep := range epItems {
		meta := asMap(ep["metadata"])
		key := asStr(meta["namespace"]) + "/" + asStr(meta["name"])
		for _, subAny := range asSlice(ep["subsets"]) {
			sub := asMap(subAny)
			addrs := asSlice(sub["addresses"])
			epReadyCounts[key] += len(addrs)
			for _, aAny := range addrs {
				a := asMap(aAny)
				if uid := getStr(a, "targetRef", "uid"); uid != "" {
					epTargetPodUIDs[key] = append(epTargetPodUIDs[key], uid)
				}
			}
		}
	}

	// Process Services
	for _, svc := range svcItems {
		meta := asMap(svc["metadata"])
		spec := asMap(svc["spec"])
		status := asMap(svc["status"])
		name := asStr(meta["name"])
		ns := asStr(meta["namespace"])
		svcType := asStr(spec["type"])
		if svcType == "" {
			svcType = "ClusterIP"
		}
		extIPs := asStrSlice(spec["externalIPs"])
		for _, ingAny := range asSlice(getPath(status, "loadBalancer", "ingress")) {
			ing := asMap(ingAny)
			if ip := asStr(ing["ip"]); ip != "" {
				extIPs = append(extIPs, ip)
			} else if hn := asStr(ing["hostname"]); hn != "" {
				extIPs = append(extIPs, hn)
			}
		}
		pulse.Counts.ServicesTotal++
		ensureNs(ns).Services++
		pulse.ServicesSummary = append(pulse.ServicesSummary, K3sServiceSummary{
			Name:              name,
			Namespace:         ns,
			Type:              svcType,
			ClusterIP:         asStr(spec["clusterIP"]),
			ExternalIP:        strings.Join(extIPs, ","),
			Ports:             formatPortsList(asSlice(spec["ports"])),
			ReadyEndpoints:    epReadyCounts[ns+"/"+name],
			CreationTimestamp: asStr(meta["creationTimestamp"]),
		})
	}

	// Process Ingresses
	for _, ing := range ingItems {
		meta := asMap(ing["metadata"])
		name := asStr(meta["name"])
		ns := asStr(meta["namespace"])
		class, hosts, addr, hasTLS, backends := extractIngressDetails(ing)
		pulse.Counts.IngressesTotal++
		ensureNs(ns).Ingresses++
		pulse.IngressesSummary = append(pulse.IngressesSummary, K3sIngressSummary{
			Name:              name,
			Namespace:         ns,
			Class:             class,
			Hosts:             hosts,
			Address:           addr,
			Tls:               hasTLS,
			Backends:          backends,
			CreationTimestamp: asStr(meta["creationTimestamp"]),
		})
	}

	// Process StorageClasses & PVCs
	scMap := make(map[string]*K3sStorageClassUsage)
	for _, sc := range scItems {
		meta := asMap(sc["metadata"])
		name := asStr(meta["name"])
		ann := asStrMap(meta["annotations"])
		isDef := ann["storageclass.kubernetes.io/is-default-class"] == "true" || ann["storageclass.beta.kubernetes.io/is-default-class"] == "true"
		scMap[name] = &K3sStorageClassUsage{
			Name:        name,
			Provisioner: asStr(sc["provisioner"]),
			IsDefault:   isDef,
		}
	}
	pulse.Counts.StorageClassesTotal = len(scItems)
	pulse.Counts.PvsTotal = len(pvItems)

	for _, pvc := range pvcItems {
		meta := asMap(pvc["metadata"])
		spec := asMap(pvc["spec"])
		status := asMap(pvc["status"])
		name := asStr(meta["name"])
		ns := asStr(meta["namespace"])
		phase := asStr(status["phase"])
		scName := asStr(spec["storageClassName"])
		if scName == "" {
			scName = "default"
		}
		capStr := getStr(status, "capacity", "storage")
		if capStr == "" {
			capStr = getStr(spec, "resources", "requests", "storage")
		}
		capBytes := parseK8sMemory(capStr)

		pulse.Counts.PvcsTotal++
		if phase == "Bound" {
			pulse.Counts.PvcsBound++
		}
		ensureNs(ns).Pvcs++

		if scEntry, ok := scMap[scName]; ok {
			scEntry.PvcCount++
			if phase == "Bound" {
				scEntry.BoundCount++
			}
			scEntry.TotalBytes += capBytes
		} else {
			scMap[scName] = &K3sStorageClassUsage{
				Name:       scName,
				PvcCount:   1,
				BoundCount: map[bool]int{true: 1}[phase == "Bound"],
				TotalBytes: capBytes,
			}
		}

		pulse.PvcsSummary = append(pulse.PvcsSummary, K3sPvcSummary{
			Name:              name,
			Namespace:         ns,
			Status:            phase,
			VolumeName:        asStr(spec["volumeName"]),
			Capacity:          capStr,
			CapacityBytes:     capBytes,
			AccessModes:       asStrSlice(spec["accessModes"]),
			StorageClass:      scName,
			CreationTimestamp: asStr(meta["creationTimestamp"]),
		})
	}
	for _, sc := range scMap {
		pulse.StorageByClass = append(pulse.StorageByClass, *sc)
	}
	sort.Slice(pulse.StorageByClass, func(i, j int) bool {
		return pulse.StorageByClass[i].Name < pulse.StorageByClass[j].Name
	})

	// Counts for miscellaneous objects
	pulse.Counts.NamespacesTotal = len(nsItems)
	if pulse.Counts.NamespacesTotal == 0 {
		pulse.Counts.NamespacesTotal = len(nsStatsMap)
	}
	pulse.Counts.ConfigMapsTotal = len(cmItems)
	pulse.Counts.SecretsTotal = len(secItems)
	pulse.Counts.NetworkPoliciesTotal = len(npItems)
	pulse.Counts.HpasTotal = len(hpaItems)
	pulse.Counts.CrdsTotal = len(crdItems)

	for _, nsStat := range nsStatsMap {
		pulse.NamespaceStats = append(pulse.NamespaceStats, *nsStat)
	}
	sort.Slice(pulse.NamespaceStats, func(i, j int) bool {
		if pulse.NamespaceStats[i].PodsTotal != pulse.NamespaceStats[j].PodsTotal {
			return pulse.NamespaceStats[i].PodsTotal > pulse.NamespaceStats[j].PodsTotal
		}
		return pulse.NamespaceStats[i].Name < pulse.NamespaceStats[j].Name
	})

	// Process Events
	for _, ev := range evItems {
		item := parseK3sEvent(ev)
		if item.Type == "Warning" {
			pulse.Counts.WarningEventsCount++
		} else {
			pulse.Counts.NormalEventsCount++
		}
		pulse.RecentEvents = append(pulse.RecentEvents, item)
	}
	sort.Slice(pulse.RecentEvents, func(i, j int) bool {
		return pulse.RecentEvents[i].LastTimestamp > pulse.RecentEvents[j].LastTimestamp
	})
	if len(pulse.RecentEvents) > 100 {
		pulse.RecentEvents = pulse.RecentEvents[:100]
	}

	// Build Interactive Topology Graph (Ingress -> Service -> Workload -> Pod -> Node / PVC)
	pulse.Topology = buildClusterTopology(
		nodesItems,
		podsItems,
		deployItems,
		stsItems,
		dsItems,
		jobItems,
		svcItems,
		ingItems,
		pvcItems,
		rsToDeploy,
		epTargetPodUIDs,
	)

	return pulse, nil
}

func buildClusterTopology(
	nodesItems, podsItems, deployItems, stsItems, dsItems, jobItems, svcItems, ingItems, pvcItems []map[string]any,
	rsToDeploy map[string]string,
	epTargetPodUIDs map[string][]string,
) K3sTopologyGraph {
	graph := K3sTopologyGraph{
		Nodes: []K3sTopologyNode{},
		Edges: []K3sTopologyEdge{},
	}
	nodeIDExists := make(map[string]bool)
	edgeIDExists := make(map[string]bool)

	addNode := func(n K3sTopologyNode) {
		if !nodeIDExists[n.ID] {
			nodeIDExists[n.ID] = true
			graph.Nodes = append(graph.Nodes, n)
		}
	}
	addEdge := func(source, target, relation, label string) {
		if !nodeIDExists[source] || !nodeIDExists[target] {
			return
		}
		id := source + "->" + target + ":" + relation
		if !edgeIDExists[id] {
			edgeIDExists[id] = true
			graph.Edges = append(graph.Edges, K3sTopologyEdge{
				ID:       id,
				Source:   source,
				Target:   target,
				Relation: relation,
				Label:    label,
			})
		}
	}

	// 1. Cluster Nodes
	for _, n := range nodesItems {
		meta := asMap(n["metadata"])
		spec := asMap(n["spec"])
		status := asMap(n["status"])
		name := asStr(meta["name"])
		nStat := "NotReady"
		for _, cAny := range asSlice(status["conditions"]) {
			c := asMap(cAny)
			if asStr(c["type"]) == "Ready" && asStr(c["status"]) == "True" {
				nStat = "Ready"
			}
		}
		unsched := asBool(spec["unschedulable"])
		var ip string
		for _, aAny := range asSlice(status["addresses"]) {
			a := asMap(aAny)
			if asStr(a["type"]) == "InternalIP" {
				ip = asStr(a["address"])
			}
		}
		addNode(K3sTopologyNode{
			ID:         "node/" + name,
			Kind:       "Node",
			Resource:   "nodes",
			Name:       name,
			Status:     nStat,
			StatusTone: statusToneForNode(nStat, unsched),
			Subtitle:   ip,
		})
	}

	// 2. PVCs
	for _, pvc := range pvcItems {
		meta := asMap(pvc["metadata"])
		spec := asMap(pvc["spec"])
		status := asMap(pvc["status"])
		ns := asStr(meta["namespace"])
		name := asStr(meta["name"])
		phase := asStr(status["phase"])
		capStr := getStr(status, "capacity", "storage")
		if capStr == "" {
			capStr = getStr(spec, "resources", "requests", "storage")
		}
		tone := "warn"
		if phase == "Bound" {
			tone = "ok"
		} else if phase == "Lost" {
			tone = "err"
		}
		addNode(K3sTopologyNode{
			ID:         "pvc/" + ns + "/" + name,
			Kind:       "PVC",
			Resource:   "persistentvolumeclaims",
			Name:       name,
			Namespace:  ns,
			Status:     phase,
			StatusTone: tone,
			Subtitle:   strings.TrimSpace(capStr + " • " + asStr(spec["storageClassName"])),
		})
	}

	// 3. Workloads (Deployment, StatefulSet, DaemonSet, Job)
	addWorkloadNodes := func(items []map[string]any, kind, resource string) {
		for _, w := range items {
			meta := asMap(w["metadata"])
			spec := asMap(w["spec"])
			status := asMap(w["status"])
			ns := asStr(meta["namespace"])
			name := asStr(meta["name"])
			var desired, ready int
			switch kind {
			case "Deployment", "StatefulSet":
				desired = asInt(spec["replicas"])
				ready = asInt(status["readyReplicas"])
			case "DaemonSet":
				desired = asInt(status["desiredNumberScheduled"])
				ready = asInt(status["numberReady"])
			case "Job":
				desired = 1
				if asInt(status["succeeded"]) > 0 {
					ready = 1
				}
			}
			tone := "ok"
			if kind == "Job" {
				if asInt(status["failed"]) > 0 {
					tone = "err"
				} else if asInt(status["succeeded"]) == 0 {
					tone = "warn"
				}
			} else if ready < desired {
				if ready == 0 {
					tone = "err"
				} else {
					tone = "warn"
				}
			}
			addNode(K3sTopologyNode{
				ID:         strings.ToLower(kind) + "/" + ns + "/" + name,
				Kind:       kind,
				Resource:   resource,
				Name:       name,
				Namespace:  ns,
				Status:     fmt.Sprintf("%d/%d", ready, desired),
				StatusTone: tone,
				Subtitle:   fmt.Sprintf("%s • %d/%d ready", kind, ready, desired),
			})
		}
	}
	addWorkloadNodes(deployItems, "Deployment", "deployments")
	addWorkloadNodes(stsItems, "StatefulSet", "statefulsets")
	addWorkloadNodes(dsItems, "DaemonSet", "daemonsets")
	addWorkloadNodes(jobItems, "Job", "jobs")

	// 4. Pods (plus edges from Workload->Pod, Pod->Node, Pod->PVC)
	podUIDToNodeID := make(map[string]string)
	type podRef struct {
		id     string
		ns     string
		labels map[string]string
	}
	var allPods []podRef

	for _, pod := range podsItems {
		meta := asMap(pod["metadata"])
		spec := asMap(pod["spec"])
		ns := asStr(meta["namespace"])
		name := asStr(meta["name"])
		uid := asStr(meta["uid"])
		nodeName := asStr(spec["nodeName"])
		labels := asStrMap(meta["labels"])
		derived := derivePodDetails(pod)

		podNodeID := "pod/" + ns + "/" + name
		if uid != "" {
			podUIDToNodeID[uid] = podNodeID
		}
		allPods = append(allPods, podRef{id: podNodeID, ns: ns, labels: labels})

		metaMap := map[string]string{
			"restarts": strconv.Itoa(derived.restarts),
			"podIP":    getStr(pod, "status", "podIP"),
		}
		addNode(K3sTopologyNode{
			ID:             podNodeID,
			Kind:           "Pod",
			Resource:       "pods",
			Name:           name,
			Namespace:      ns,
			Status:         derived.reason,
			StatusTone:     derived.tone,
			Subtitle:       fmt.Sprintf("%d/%d • R:%d", derived.readyCount, derived.totalCount, derived.restarts),
			ParentNodeName: nodeName,
			Meta:           metaMap,
		})

		if nodeName != "" {
			addEdge(podNodeID, "node/"+nodeName, "pod-to-node", "scheduled")
		}

		// Owner references
		for _, oAny := range asSlice(meta["ownerReferences"]) {
			o := asMap(oAny)
			oKind := asStr(o["kind"])
			oName := asStr(o["name"])
			switch oKind {
			case "ReplicaSet":
				if deployName, ok := rsToDeploy[ns+"/"+oName]; ok {
					addEdge("deployment/"+ns+"/"+deployName, podNodeID, "workload-to-pod", "manages")
				}
			case "StatefulSet":
				addEdge("statefulset/"+ns+"/"+oName, podNodeID, "workload-to-pod", "manages")
			case "DaemonSet":
				addEdge("daemonset/"+ns+"/"+oName, podNodeID, "workload-to-pod", "manages")
			case "Job":
				addEdge("job/"+ns+"/"+oName, podNodeID, "workload-to-pod", "runs")
			}
		}

		// PVCs
		for _, vAny := range asSlice(spec["volumes"]) {
			v := asMap(vAny)
			if claim := getStr(v, "persistentVolumeClaim", "claimName"); claim != "" {
				addEdge(podNodeID, "pvc/"+ns+"/"+claim, "pod-to-pvc", "mounts")
			}
		}
	}

	// 5. Services (plus edges Service->Pod)
	for _, svc := range svcItems {
		meta := asMap(svc["metadata"])
		spec := asMap(svc["spec"])
		ns := asStr(meta["namespace"])
		name := asStr(meta["name"])
		svcType := asStr(spec["type"])
		if svcType == "" {
			svcType = "ClusterIP"
		}
		svcID := "service/" + ns + "/" + name
		ports := formatPortsList(asSlice(spec["ports"]))
		sub := svcType
		if len(ports) > 0 {
			sub += " • " + strings.Join(ports, ",")
		}
		addNode(K3sTopologyNode{
			ID:         svcID,
			Kind:       "Service",
			Resource:   "services",
			Name:       name,
			Namespace:  ns,
			Status:     svcType,
			StatusTone: "info",
			Subtitle:   sub,
		})

		// Connect Service -> Pods via selector or Endpoints targetRef
		selector := asStrMap(spec["selector"])
		linkedViaEP := false
		for _, uid := range epTargetPodUIDs[ns+"/"+name] {
			if pID, ok := podUIDToNodeID[uid]; ok {
				addEdge(svcID, pID, "service-to-pod", "routes")
				linkedViaEP = true
			}
		}
		if !linkedViaEP && len(selector) > 0 {
			for _, p := range allPods {
				if p.ns != ns || len(p.labels) == 0 {
					continue
				}
				match := true
				for sk, sv := range selector {
					if p.labels[sk] != sv {
						match = false
						break
					}
				}
				if match {
					addEdge(svcID, p.id, "service-to-pod", "selects")
				}
			}
		}
	}

	// 6. Ingresses (plus edges Ingress->Service)
	for _, ing := range ingItems {
		meta := asMap(ing["metadata"])
		ns := asStr(meta["namespace"])
		name := asStr(meta["name"])
		class, hosts, _, hasTLS, backends := extractIngressDetails(ing)
		ingID := "ingress/" + ns + "/" + name
		sub := strings.Join(hosts, ", ")
		if hasTLS {
			if sub != "" {
				sub = "TLS • " + sub
			} else {
				sub = "TLS"
			}
		}
		if class != "" && sub == "" {
			sub = class
		}
		addNode(K3sTopologyNode{
			ID:         ingID,
			Kind:       "Ingress",
			Resource:   "ingresses",
			Name:       name,
			Namespace:  ns,
			Status:     map[bool]string{true: "TLS", false: "HTTP"}[hasTLS],
			StatusTone: "info",
			Subtitle:   sub,
		})
		for _, svcName := range backends {
			addEdge(ingID, "service/"+ns+"/"+svcName, "ingress-to-service", "forwards")
		}
	}

	return graph
}

func parseK3sEvent(ev map[string]any) K3sEventItem {
	inv := asMap(ev["involvedObject"])
	src := asMap(ev["source"])
	ts := asStr(ev["lastTimestamp"])
	if ts == "" {
		ts = asStr(ev["eventTime"])
	}
	if ts == "" {
		ts = getStr(ev, "metadata", "creationTimestamp")
	}
	cnt := asInt(ev["count"])
	if cnt <= 0 {
		cnt = 1
	}
	return K3sEventItem{
		Type:          asStr(ev["type"]),
		Reason:        asStr(ev["reason"]),
		Namespace:     getStr(ev, "metadata", "namespace"),
		InvolvedKind:  asStr(inv["kind"]),
		InvolvedName:  asStr(inv["name"]),
		Message:       asStr(ev["message"]),
		Count:         cnt,
		LastTimestamp: ts,
		Source:        asStr(src["component"]),
	}
}

// --- API Resource & Namespace Discovery ---

func parseAPIResourcesTable(raw string) []K3sAPIResource {
	var out []K3sAPIResource
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "NAME ") {
			continue
		}
		// Match bracketed verbs if `-o wide` was used
		var verbs []string
		left := line
		if idx := strings.Index(line, "["); idx >= 0 {
			right := strings.LastIndex(line, "]")
			if right > idx {
				vRaw := line[idx+1 : right]
				for _, vf := range strings.Fields(vRaw) {
					vf = strings.Trim(vf, ",")
					if vf != "" {
						verbs = append(verbs, vf)
					}
				}
				left = strings.TrimSpace(line[:idx])
			}
		}
		fields := strings.Fields(left)
		// Expected without shortnames: NAME APIVERSION NAMESPACED KIND (4 fields)
		// With shortnames: NAME SHORTNAMES APIVERSION NAMESPACED KIND (5 fields)
		if len(fields) < 4 {
			continue
		}
		var name, shortStr, apiVer, nsStr, kind string
		if len(fields) >= 5 && (fields[3] == "true" || fields[3] == "false") {
			name, shortStr, apiVer, nsStr, kind = fields[0], fields[1], fields[2], fields[3], fields[4]
		} else if len(fields) >= 4 && (fields[2] == "true" || fields[2] == "false") {
			name, apiVer, nsStr, kind = fields[0], fields[1], fields[2], fields[3]
		} else {
			continue
		}
		var shorts []string
		if shortStr != "" && shortStr != "<none>" {
			for _, sn := range strings.Split(shortStr, ",") {
				sn = strings.TrimSpace(sn)
				if sn != "" {
					shorts = append(shorts, sn)
				}
			}
		}
		out = append(out, K3sAPIResource{
			Name:       name,
			ShortNames: shorts,
			ApiVersion: apiVer,
			Namespaced: nsStr == "true",
			Kind:       kind,
			Verbs:      verbs,
		})
	}
	return out
}

func (m *K3sManager) ListAPIResources(ctx context.Context) ([]K3sAPIResource, error) {
	cCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, errOut, _, err := runKubectlLimited(cCtx, k8sMaxTextBytes, nil, "api-resources", "--no-headers", "-o", "wide")
	if err != nil {
		// Fallback without -o wide in case older kubectl differs
		out2, errOut2, _, err2 := runKubectlLimited(cCtx, k8sMaxTextBytes, nil, "api-resources", "--no-headers")
		if err2 != nil {
			msg := strings.TrimSpace(string(errOut2))
			if msg == "" {
				msg = strings.TrimSpace(string(errOut))
			}
			if msg == "" {
				msg = err2.Error()
			}
			return nil, fmt.Errorf("kubectl api-resources failed: %s", msg)
		}
		out = out2
	}
	return parseAPIResourcesTable(string(out)), nil
}

func (m *K3sManager) ListNamespaces(ctx context.Context) ([]K3sNamespaceSummary, error) {
	cCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var (
		nsOut, podsOut []byte
		nsErrOut       []byte
		nsErr          error
	)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		nsOut, nsErrOut, _, nsErr = runKubectlLimited(cCtx, k8sMaxListBytes, nil, "get", "namespaces", "-o", "json")
	}()
	go func() {
		defer wg.Done()
		podsOut, _, _, _ = runKubectlLimited(cCtx, k8sMaxListBytes, nil, "get", "pods", "-A", "-o", "json")
	}()
	wg.Wait()

	if nsErr != nil {
		msg := strings.TrimSpace(string(nsErrOut))
		if msg == "" {
			msg = nsErr.Error()
		}
		return nil, fmt.Errorf("kubectl get namespaces failed: %s", msg)
	}

	var nsDoc struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(nsOut, &nsDoc); err != nil {
		return nil, fmt.Errorf("parsing namespaces json: %w", err)
	}

	podCounts := make(map[string]int)
	if len(podsOut) > 0 {
		var pDoc struct {
			Items []struct {
				Metadata struct {
					Namespace string `json:"namespace"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if err := json.Unmarshal(podsOut, &pDoc); err == nil {
			for _, p := range pDoc.Items {
				podCounts[p.Metadata.Namespace]++
			}
		}
	}

	out := make([]K3sNamespaceSummary, 0, len(nsDoc.Items))
	for _, n := range nsDoc.Items {
		meta := asMap(n["metadata"])
		name := asStr(meta["name"])
		st := getStr(n, "status", "phase")
		if st == "" {
			st = "Active"
		}
		out = append(out, K3sNamespaceSummary{
			Name:              name,
			Status:            st,
			CreationTimestamp: asStr(meta["creationTimestamp"]),
			Labels:            asStrMap(meta["labels"]),
			PodCount:          podCounts[name],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// --- Universal Resource Listing ---

func (m *K3sManager) ListResources(ctx context.Context, resource, namespace, labelSelector string) (*K3sResourceListResponse, error) {
	resource = strings.TrimSpace(resource)
	namespace = strings.TrimSpace(namespace)
	labelSelector = strings.TrimSpace(labelSelector)

	if !validK8sResourceArg(resource) {
		return nil, fmt.Errorf("invalid kubernetes resource type %q", resource)
	}
	if !validK8sNamespaceArg(namespace) {
		return nil, fmt.Errorf("invalid kubernetes namespace %q", namespace)
	}
	if !validK8sLabelSelector(labelSelector) {
		return nil, fmt.Errorf("invalid label selector %q", labelSelector)
	}

	cCtx, cancel := context.WithTimeout(ctx, 14*time.Second)
	defer cancel()

	namespaced := resolveResourceScopeNamespaced(cCtx, resource)
	args := []string{"get", resource}
	effectiveNS := namespace
	if namespaced {
		if namespace == "" || namespace == "_all" {
			args = append(args, "-A")
			effectiveNS = "_all"
		} else {
			args = append(args, "-n", namespace)
		}
	} else {
		effectiveNS = ""
	}
	if labelSelector != "" {
		args = append(args, "-l", labelSelector)
	}
	args = append(args, "-o", "json")

	normRes := strings.ToLower(resource)
	wantPodTop := normRes == "pod" || normRes == "pods" || normRes == "po"
	wantNodeTop := normRes == "node" || normRes == "nodes" || normRes == "no"

	var (
		out, errOut []byte
		runErr      error
		topMap      map[string]podUsageMetric
	)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		out, errOut, _, runErr = runKubectlLimited(cCtx, k8sMaxListBytes, nil, args...)
	}()
	if wantPodTop || wantNodeTop {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tArgs := []string{"top"}
			if wantPodTop {
				tArgs = append(tArgs, "pods")
				if effectiveNS == "_all" {
					tArgs = append(tArgs, "-A")
				} else if effectiveNS != "" {
					tArgs = append(tArgs, "-n", effectiveNS)
				}
			} else {
				tArgs = append(tArgs, "nodes")
			}
			tArgs = append(tArgs, "--no-headers")
			if tOut, _, _, tErr := runKubectlLimited(cCtx, k8sMaxTextBytes, nil, tArgs...); tErr == nil {
				if wantPodTop {
					topMap = parseTopPodsOutput(string(tOut))
				} else {
					topMap = parseTopNodesOutput(string(tOut))
				}
			}
		}()
	}
	wg.Wait()

	if runErr != nil {
		msg := strings.TrimSpace(string(errOut))
		if msg == "" {
			msg = runErr.Error()
		}
		return &K3sResourceListResponse{
			Resource:   resource,
			Namespace:  effectiveNS,
			Namespaced: namespaced,
			Items:      []K3sResourceItem{},
			Count:      0,
			Error:      msg,
		}, fmt.Errorf("kubectl get %s failed: %s", resource, msg)
	}

	var rawDoc map[string]any
	if err := json.Unmarshal(out, &rawDoc); err != nil {
		return nil, fmt.Errorf("parsing kubectl get %s json: %w", resource, err)
	}

	rawItems := asSlice(rawDoc["items"])
	items := make([]K3sResourceItem, 0, len(rawItems))
	for _, itAny := range rawItems {
		it := asMap(itAny)
		if it == nil {
			continue
		}
		items = append(items, normalizeK3sResourceItem(it, topMap))
	}

	return &K3sResourceListResponse{
		Resource:   resource,
		Namespace:  effectiveNS,
		Namespaced: namespaced,
		Items:      items,
		Count:      len(items),
	}, nil
}

func normalizeK3sResourceItem(it map[string]any, topMap map[string]podUsageMetric) K3sResourceItem {
	meta := asMap(it["metadata"])
	spec := asMap(it["spec"])
	status := asMap(it["status"])

	kind := asStr(it["kind"])
	apiVer := asStr(it["apiVersion"])
	name := asStr(meta["name"])
	ns := asStr(meta["namespace"])
	uid := asStr(meta["uid"])
	created := asStr(meta["creationTimestamp"])
	labels := asStrMap(meta["labels"])

	resStatus := "Active"
	tone := "ok"
	summary := make(map[string]any)

	switch kind {
	case "Pod":
		derived := derivePodDetails(it)
		resStatus = derived.reason
		tone = derived.tone
		summary["ready"] = fmt.Sprintf("%d/%d", derived.readyCount, derived.totalCount)
		summary["readyCount"] = derived.readyCount
		summary["totalCount"] = derived.totalCount
		summary["restarts"] = derived.restarts
		summary["podIP"] = asStr(status["podIP"])
		summary["nodeName"] = asStr(spec["nodeName"])
		summary["qosClass"] = asStr(status["qosClass"])
		summary["containers"] = derived.containers
		summary["hostUsers"] = spec["hostUsers"]
		if tm, ok := topMap[ns+"/"+name]; ok {
			summary["cpuMillis"] = tm.cpuMillis
			summary["memBytes"] = tm.memBytes
		}

	case "Deployment":
		desired := asInt(spec["replicas"])
		ready := asInt(status["readyReplicas"])
		updated := asInt(status["updatedReplicas"])
		avail := asInt(status["availableReplicas"])
		resStatus = fmt.Sprintf("%d/%d", ready, desired)
		if desired == 0 || ready >= desired {
			tone = "ok"
		} else if ready > 0 {
			tone = "warn"
		} else {
			tone = "err"
		}
		summary["ready"] = resStatus
		summary["readyCount"] = ready
		summary["desired"] = desired
		summary["upToDate"] = updated
		summary["available"] = avail
		summary["images"] = extractContainerImages(spec)
		summary["strategy"] = getStr(spec, "strategy", "type")

	case "StatefulSet":
		desired := asInt(spec["replicas"])
		ready := asInt(status["readyReplicas"])
		resStatus = fmt.Sprintf("%d/%d", ready, desired)
		if desired == 0 || ready >= desired {
			tone = "ok"
		} else if ready > 0 {
			tone = "warn"
		} else {
			tone = "err"
		}
		summary["ready"] = resStatus
		summary["readyCount"] = ready
		summary["desired"] = desired
		summary["serviceName"] = asStr(spec["serviceName"])
		summary["images"] = extractContainerImages(spec)

	case "DaemonSet":
		desired := asInt(status["desiredNumberScheduled"])
		ready := asInt(status["numberReady"])
		avail := asInt(status["numberAvailable"])
		resStatus = fmt.Sprintf("%d/%d", ready, desired)
		if desired == 0 || ready >= desired {
			tone = "ok"
		} else if ready > 0 {
			tone = "warn"
		} else {
			tone = "err"
		}
		summary["ready"] = resStatus
		summary["readyCount"] = ready
		summary["desired"] = desired
		summary["available"] = avail
		summary["images"] = extractContainerImages(spec)

	case "ReplicaSet":
		desired := asInt(spec["replicas"])
		ready := asInt(status["readyReplicas"])
		resStatus = fmt.Sprintf("%d/%d", ready, desired)
		if desired == 0 || ready >= desired {
			tone = "ok"
		} else {
			tone = "warn"
		}
		summary["ready"] = resStatus
		summary["desired"] = desired
		summary["readyCount"] = ready
		summary["images"] = extractContainerImages(spec)

	case "Job":
		comp := asInt(spec["completions"])
		if comp == 0 {
			comp = 1
		}
		succ := asInt(status["succeeded"])
		failed := asInt(status["failed"])
		active := asInt(status["active"])
		switch {
		case failed > 0 && succ < comp:
			resStatus = "Failed"
			tone = "err"
		case succ >= comp:
			resStatus = "Completed"
			tone = "info"
		case active > 0:
			resStatus = "Running"
			tone = "ok"
		default:
			resStatus = "Pending"
			tone = "warn"
		}
		summary["completions"] = fmt.Sprintf("%d/%d", succ, comp)
		summary["active"] = active
		summary["failed"] = failed
		summary["images"] = extractContainerImages(spec)

	case "CronJob":
		suspended := asBool(spec["suspend"])
		activeCount := len(asSlice(status["active"]))
		resStatus = map[bool]string{true: "Suspended", false: "Scheduled"}[suspended]
		tone = map[bool]string{true: "warn", false: "ok"}[suspended]
		summary["schedule"] = asStr(spec["schedule"])
		summary["suspend"] = suspended
		summary["active"] = activeCount
		summary["lastScheduleTime"] = asStr(status["lastScheduleTime"])

	case "Service":
		svcType := asStr(spec["type"])
		if svcType == "" {
			svcType = "ClusterIP"
		}
		resStatus = svcType
		tone = "info"
		var extIPs []string
		extIPs = append(extIPs, asStrSlice(spec["externalIPs"])...)
		for _, ingAny := range asSlice(getPath(status, "loadBalancer", "ingress")) {
			ing := asMap(ingAny)
			if ip := asStr(ing["ip"]); ip != "" {
				extIPs = append(extIPs, ip)
			} else if hn := asStr(ing["hostname"]); hn != "" {
				extIPs = append(extIPs, hn)
			}
		}
		summary["type"] = svcType
		summary["clusterIP"] = asStr(spec["clusterIP"])
		summary["externalIP"] = strings.Join(extIPs, ",")
		summary["ports"] = formatPortsList(asSlice(spec["ports"]))
		summary["selector"] = asStrMap(spec["selector"])

	case "Ingress":
		class, hosts, addr, hasTLS, backends := extractIngressDetails(it)
		resStatus = map[bool]string{true: "TLS", false: "HTTP"}[hasTLS]
		tone = "info"
		summary["class"] = class
		summary["hosts"] = hosts
		summary["address"] = addr
		summary["tls"] = hasTLS
		summary["backends"] = backends

	case "Node":
		nodeStat := "NotReady"
		for _, cAny := range asSlice(status["conditions"]) {
			c := asMap(cAny)
			if asStr(c["type"]) == "Ready" && asStr(c["status"]) == "True" {
				nodeStat = "Ready"
			}
		}
		unsched := asBool(spec["unschedulable"])
		var roles []string
		for k := range labels {
			if strings.HasPrefix(k, "node-role.kubernetes.io/") {
				roles = append(roles, strings.TrimPrefix(k, "node-role.kubernetes.io/"))
			}
		}
		sort.Strings(roles)
		roleStr := "worker"
		if len(roles) > 0 {
			roleStr = strings.Join(roles, ",")
		}
		var internalIP string
		for _, aAny := range asSlice(status["addresses"]) {
			a := asMap(aAny)
			if asStr(a["type"]) == "InternalIP" {
				internalIP = asStr(a["address"])
			}
		}
		resStatus = nodeStat
		if unsched {
			resStatus += " (Cordoned)"
		}
		tone = statusToneForNode(nodeStat, unsched)
		summary["roles"] = roleStr
		summary["internalIp"] = internalIP
		summary["version"] = getStr(status, "nodeInfo", "kubeletVersion")
		summary["unschedulable"] = unsched
		summary["osImage"] = getStr(status, "nodeInfo", "osImage")
		summary["taintsCount"] = len(asSlice(spec["taints"]))
		if tm, ok := topMap[name]; ok {
			summary["cpuMillis"] = tm.cpuMillis
			summary["memBytes"] = tm.memBytes
		}

	case "Namespace":
		phase := asStr(status["phase"])
		if phase == "" {
			phase = "Active"
		}
		resStatus = phase
		if phase == "Active" {
			tone = "ok"
		} else {
			tone = "warn"
		}

	case "PersistentVolumeClaim":
		phase := asStr(status["phase"])
		if phase == "" {
			phase = "Pending"
		}
		resStatus = phase
		if phase == "Bound" {
			tone = "ok"
		} else if phase == "Pending" {
			tone = "warn"
		} else {
			tone = "err"
		}
		capStr := getStr(status, "capacity", "storage")
		if capStr == "" {
			capStr = getStr(spec, "resources", "requests", "storage")
		}
		summary["volume"] = asStr(spec["volumeName"])
		summary["capacity"] = capStr
		summary["accessModes"] = asStrSlice(spec["accessModes"])
		summary["storageClass"] = asStr(spec["storageClassName"])

	case "PersistentVolume":
		phase := asStr(status["phase"])
		resStatus = phase
		if phase == "Bound" || phase == "Available" {
			tone = "ok"
		} else if phase == "Released" {
			tone = "warn"
		} else {
			tone = "err"
		}
		summary["capacity"] = getStr(spec, "capacity", "storage")
		summary["accessModes"] = asStrSlice(spec["accessModes"])
		summary["reclaimPolicy"] = asStr(spec["persistentVolumeReclaimPolicy"])
		summary["storageClass"] = asStr(spec["storageClassName"])
		if cr := asMap(spec["claimRef"]); cr != nil {
			summary["claim"] = asStr(cr["namespace"]) + "/" + asStr(cr["name"])
		}

	case "StorageClass":
		ann := asStrMap(meta["annotations"])
		isDef := ann["storageclass.kubernetes.io/is-default-class"] == "true" || ann["storageclass.beta.kubernetes.io/is-default-class"] == "true"
		resStatus = map[bool]string{true: "Default", false: "Available"}[isDef]
		tone = map[bool]string{true: "ok", false: "info"}[isDef]
		summary["provisioner"] = asStr(it["provisioner"])
		summary["reclaimPolicy"] = asStr(it["reclaimPolicy"])
		summary["volumeBindingMode"] = asStr(it["volumeBindingMode"])
		summary["isDefault"] = isDef

	case "ConfigMap":
		dataMap := asMap(it["data"])
		binMap := asMap(it["binaryData"])
		keys := make([]string, 0, len(dataMap)+len(binMap))
		for k := range dataMap {
			keys = append(keys, k)
		}
		for k := range binMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		resStatus = fmt.Sprintf("%d keys", len(keys))
		tone = "info"
		summary["dataCount"] = len(keys)
		summary["dataKeys"] = keys

	case "Secret":
		// NEVER expose secret data values in ListResources!
		dataMap := asMap(it["data"])
		strDataMap := asMap(it["stringData"])
		keys := make([]string, 0, len(dataMap)+len(strDataMap))
		for k := range dataMap {
			keys = append(keys, k)
		}
		for k := range strDataMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sType := asStr(it["type"])
		if sType == "" {
			sType = "Opaque"
		}
		resStatus = fmt.Sprintf("%d keys", len(keys))
		tone = "info"
		summary["type"] = sType
		summary["dataCount"] = len(keys)
		summary["dataKeys"] = keys

	case "Event":
		ev := parseK3sEvent(it)
		resStatus = ev.Type
		if ev.Type == "Warning" {
			tone = "warn"
		} else {
			tone = "info"
		}
		summary["reason"] = ev.Reason
		summary["object"] = ev.InvolvedKind + "/" + ev.InvolvedName
		summary["involvedKind"] = ev.InvolvedKind
		summary["involvedName"] = ev.InvolvedName
		summary["count"] = ev.Count
		summary["message"] = ev.Message
		summary["lastSeen"] = ev.LastTimestamp

	case "CustomResourceDefinition":
		grp := asStr(spec["group"])
		scope := asStr(spec["scope"])
		crdKind := getStr(spec, "names", "kind")
		plural := getStr(spec, "names", "plural")
		resStatus = scope
		tone = "info"
		summary["group"] = grp
		summary["scope"] = scope
		summary["crdKind"] = crdKind
		summary["plural"] = plural

	case "Endpoints":
		var addrs []string
		for _, subAny := range asSlice(it["subsets"]) {
			sub := asMap(subAny)
			for _, aAny := range asSlice(sub["addresses"]) {
				if ip := getStr(asMap(aAny), "ip"); ip != "" {
					addrs = append(addrs, ip)
				}
			}
		}
		resStatus = fmt.Sprintf("%d ready", len(addrs))
		if len(addrs) > 0 {
			tone = "ok"
		} else {
			tone = "warn"
		}
		summary["endpoints"] = addrs

	case "HorizontalPodAutoscaler":
		minR := asInt(spec["minReplicas"])
		maxR := asInt(spec["maxReplicas"])
		curR := asInt(status["currentReplicas"])
		desR := asInt(status["desiredReplicas"])
		resStatus = fmt.Sprintf("%d/%d", curR, maxR)
		tone = "ok"
		summary["reference"] = fmt.Sprintf("%s/%s", getStr(spec, "scaleTargetRef", "kind"), getStr(spec, "scaleTargetRef", "name"))
		summary["minReplicas"] = minR
		summary["maxReplicas"] = maxR
		summary["currentReplicas"] = curR
		summary["desiredReplicas"] = desR

	default:
		if phase := asStr(status["phase"]); phase != "" {
			resStatus = phase
		} else if conds := asSlice(status["conditions"]); len(conds) > 0 {
			last := asMap(conds[len(conds)-1])
			cType := asStr(last["type"])
			cStat := asStr(last["status"])
			resStatus = fmt.Sprintf("%s=%s", cType, cStat)
			if cStat == "True" {
				tone = "ok"
			} else if cStat == "False" {
				tone = "warn"
			}
		}
	}

	return K3sResourceItem{
		UID:               uid,
		Name:              name,
		Namespace:         ns,
		Kind:              kind,
		ApiVersion:        apiVer,
		CreationTimestamp: created,
		Status:            resStatus,
		StatusTone:        tone,
		Labels:            labels,
		OwnerRef:          extractOwnerRefSummary(meta),
		Summary:           summary,
	}
}

// --- Secret Redaction & Resource Inspection ---

const redactedSecretPlaceholder = "<REDACTED — Admin press [x] to decode>"

func redactSecretMap(obj map[string]any) {
	if obj == nil {
		return
	}
	for _, field := range []string{"data", "stringData"} {
		if m := asMap(obj[field]); m != nil {
			masked := make(map[string]any, len(m))
			for k := range m {
				masked[k] = redactedSecretPlaceholder
			}
			obj[field] = masked
		}
	}
	if meta := asMap(obj["metadata"]); meta != nil {
		if ann := asMap(meta["annotations"]); ann != nil {
			if _, ok := ann["kubectl.kubernetes.io/last-applied-configuration"]; ok {
				ann["kubectl.kubernetes.io/last-applied-configuration"] = "<REDACTED — applied secret manifest hidden>"
			}
		}
	}
}

func redactSecretYaml(rawYaml string) string {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(rawYaml), &root); err != nil || len(root.Content) == 0 {
		return "# Unable to safely parse Secret YAML for redaction; content omitted.\n"
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return "# Unable to safely redact Secret YAML; content omitted.\n"
	}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		kNode, vNode := doc.Content[i], doc.Content[i+1]
		if (kNode.Value == "data" || kNode.Value == "stringData") && vNode.Kind == yaml.MappingNode {
			for j := 0; j+1 < len(vNode.Content); j += 2 {
				vNode.Content[j+1] = &yaml.Node{
					Kind:  yaml.ScalarNode,
					Tag:   "!!str",
					Value: redactedSecretPlaceholder,
				}
			}
		} else if kNode.Value == "metadata" && vNode.Kind == yaml.MappingNode {
			for j := 0; j+1 < len(vNode.Content); j += 2 {
				mk, mv := vNode.Content[j], vNode.Content[j+1]
				if mk.Value == "annotations" && mv.Kind == yaml.MappingNode {
					for a := 0; a+1 < len(mv.Content); a += 2 {
						if mv.Content[a].Value == "kubectl.kubernetes.io/last-applied-configuration" {
							mv.Content[a+1] = &yaml.Node{
								Kind:  yaml.ScalarNode,
								Tag:   "!!str",
								Value: "<REDACTED — applied secret manifest hidden>",
							}
						}
					}
				}
			}
		}
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return "# Secret redaction encode failed.\n"
	}
	_ = enc.Close()
	return out.String()
}

func decodeSecretValues(obj map[string]any) map[string]string {
	out := make(map[string]string)
	if dataM := asMap(obj["data"]); dataM != nil {
		for k, v := range dataM {
			rawB64 := asStr(v)
			decoded, err := base64.StdEncoding.DecodeString(rawB64)
			if err != nil {
				out[k] = rawB64
				continue
			}
			if utf8.Valid(decoded) && !bytes.ContainsRune(decoded, '\x00') {
				out[k] = string(decoded)
			} else {
				out[k] = fmt.Sprintf("<binary: %d bytes>", len(decoded))
			}
		}
	}
	if strM := asMap(obj["stringData"]); strM != nil {
		for k, v := range strM {
			out[k] = asStr(v)
		}
	}
	return out
}

func (m *K3sManager) InspectResource(ctx context.Context, resource, namespace, name string, decodeSecret bool) (*K3sResourceInspectResponse, error) {
	resource = strings.TrimSpace(resource)
	namespace = strings.TrimSpace(namespace)
	name = strings.TrimSpace(name)

	if !validK8sResourceArg(resource) {
		return nil, fmt.Errorf("invalid kubernetes resource type %q", resource)
	}
	if !validK8sObjectName(name) {
		return nil, fmt.Errorf("invalid kubernetes object name %q", name)
	}
	if !validK8sNamespaceArg(namespace) || namespace == "_all" {
		return nil, fmt.Errorf("invalid kubernetes namespace %q", namespace)
	}

	cCtx, cancel := context.WithTimeout(ctx, 14*time.Second)
	defer cancel()

	namespaced := resolveResourceScopeNamespaced(cCtx, resource)
	baseArgs := []string{resource, name}
	effectiveNS := ""
	if namespaced {
		if namespace == "" {
			namespace = "default"
		}
		effectiveNS = namespace
		baseArgs = append(baseArgs, "-n", namespace)
	}

	var (
		jsonOut, jsonErrOut []byte
		yamlOut, descOut    []byte
		evOut               []byte
		jsonErr             error
	)
	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		args := append([]string{"get"}, baseArgs...)
		args = append(args, "-o", "json")
		jsonOut, jsonErrOut, _, jsonErr = runKubectlLimited(cCtx, k8sMaxListBytes, nil, args...)
	}()
	go func() {
		defer wg.Done()
		args := append([]string{"get"}, baseArgs...)
		args = append(args, "-o", "yaml")
		yamlOut, _, _, _ = runKubectlLimited(cCtx, k8sMaxListBytes, nil, args...)
	}()
	go func() {
		defer wg.Done()
		args := append([]string{"describe"}, baseArgs...)
		descOut, _, _, _ = runKubectlLimited(cCtx, k8sMaxTextBytes, nil, args...)
	}()
	go func() {
		defer wg.Done()
		evArgs := []string{"get", "events"}
		if effectiveNS != "" {
			evArgs = append(evArgs, "-n", effectiveNS)
		} else {
			evArgs = append(evArgs, "-A")
		}
		evArgs = append(evArgs, "--field-selector", "involvedObject.name="+name, "-o", "json")
		evOut, _, _, _ = runKubectlLimited(cCtx, k8sMaxListBytes, nil, evArgs...)
	}()
	wg.Wait()

	if jsonErr != nil {
		msg := strings.TrimSpace(string(jsonErrOut))
		if msg == "" {
			msg = jsonErr.Error()
		}
		return nil, fmt.Errorf("kubectl get %s %s failed: %s", resource, name, msg)
	}

	var obj map[string]any
	if err := json.Unmarshal(jsonOut, &obj); err != nil {
		return nil, fmt.Errorf("parsing object json: %w", err)
	}

	kind := asStr(obj["kind"])
	apiVer := asStr(obj["apiVersion"])
	meta := asMap(obj["metadata"])
	if metaNS := asStr(meta["namespace"]); metaNS != "" {
		effectiveNS = metaNS
	}

	yamlText := string(yamlOut)
	var decodedSecret map[string]string
	secretRedacted := false

	if kind == "Secret" {
		if decodeSecret {
			decodedSecret = decodeSecretValues(obj)
		} else {
			redactSecretMap(obj)
			yamlText = redactSecretYaml(yamlText)
			secretRedacted = true
		}
	}

	var events []K3sEventItem
	if len(evOut) > 0 {
		var evDoc struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(evOut, &evDoc); err == nil {
			for _, ev := range evDoc.Items {
				events = append(events, parseK3sEvent(ev))
			}
			sort.Slice(events, func(i, j int) bool {
				return events[i].LastTimestamp > events[j].LastTimestamp
			})
		}
	}

	related := computeRelatedResources(cCtx, obj, effectiveNS, name)

	return &K3sResourceInspectResponse{
		Resource:          resource,
		Kind:              kind,
		ApiVersion:        apiVer,
		Name:              name,
		Namespace:         effectiveNS,
		Object:            obj,
		Yaml:              yamlText,
		Describe:          string(descOut),
		Events:            events,
		Related:           related,
		DecodedSecretData: decodedSecret,
		SecretRedacted:    secretRedacted,
	}, nil
}

func computeRelatedResources(ctx context.Context, obj map[string]any, ns, name string) []K3sRelatedResource {
	var related []K3sRelatedResource
	seen := make(map[string]bool)
	addRel := func(r K3sRelatedResource) {
		key := fmt.Sprintf("%s/%s/%s/%s", r.Relation, r.Resource, r.Namespace, r.Name)
		if r.Name == "" || seen[key] {
			return
		}
		seen[key] = true
		related = append(related, r)
	}

	meta := asMap(obj["metadata"])
	spec := asMap(obj["spec"])
	kind := asStr(obj["kind"])

	// Owner references
	for _, oAny := range asSlice(meta["ownerReferences"]) {
		o := asMap(oAny)
		oKind := asStr(o["kind"])
		oName := asStr(o["name"])
		addRel(K3sRelatedResource{
			Relation:  "Owner",
			Kind:      oKind,
			Resource:  pluralResourceForKind(oKind),
			Name:      oName,
			Namespace: ns,
		})
	}

	switch kind {
	case "Pod":
		if nodeName := asStr(spec["nodeName"]); nodeName != "" {
			addRel(K3sRelatedResource{
				Relation: "Scheduled On",
				Kind:     "Node",
				Resource: "nodes",
				Name:     nodeName,
			})
		}
		if sa := asStr(spec["serviceAccountName"]); sa != "" {
			addRel(K3sRelatedResource{
				Relation:  "ServiceAccount",
				Kind:      "ServiceAccount",
				Resource:  "serviceaccounts",
				Name:      sa,
				Namespace: ns,
			})
		}
		for _, vAny := range asSlice(spec["volumes"]) {
			v := asMap(vAny)
			if pvcName := getStr(v, "persistentVolumeClaim", "claimName"); pvcName != "" {
				addRel(K3sRelatedResource{
					Relation:  "Mounts PVC",
					Kind:      "PersistentVolumeClaim",
					Resource:  "persistentvolumeclaims",
					Name:      pvcName,
					Namespace: ns,
				})
			}
			if cmName := getStr(v, "configMap", "name"); cmName != "" {
				addRel(K3sRelatedResource{
					Relation:  "Mounts ConfigMap",
					Kind:      "ConfigMap",
					Resource:  "configmaps",
					Name:      cmName,
					Namespace: ns,
				})
			}
			if secName := getStr(v, "secret", "secretName"); secName != "" {
				addRel(K3sRelatedResource{
					Relation:  "Mounts Secret",
					Kind:      "Secret",
					Resource:  "secrets",
					Name:      secName,
					Namespace: ns,
				})
			}
		}

	case "Service":
		if selector := asStrMap(spec["selector"]); len(selector) > 0 {
			var parts []string
			for k, v := range selector {
				parts = append(parts, k+"="+v)
			}
			sort.Strings(parts)
			selStr := strings.Join(parts, ",")
			if validK8sLabelSelector(selStr) {
				if pOut, _, _, err := runKubectlLimited(ctx, k8sMaxListBytes, nil, "get", "pods", "-n", ns, "-l", selStr, "-o", "json"); err == nil {
					var pDoc struct {
						Items []map[string]any `json:"items"`
					}
					if json.Unmarshal(pOut, &pDoc) == nil {
						for _, p := range pDoc.Items {
							d := derivePodDetails(p)
							addRel(K3sRelatedResource{
								Relation:   "Backend Pod",
								Kind:       "Pod",
								Resource:   "pods",
								Name:       getStr(p, "metadata", "name"),
								Namespace:  ns,
								Status:     d.reason,
								StatusTone: d.tone,
							})
						}
					}
				}
			}
		}
		addRel(K3sRelatedResource{
			Relation:  "Endpoints",
			Kind:      "Endpoints",
			Resource:  "endpoints",
			Name:      name,
			Namespace: ns,
		})

	case "Ingress":
		_, _, _, _, backends := extractIngressDetails(obj)
		for _, svcName := range backends {
			addRel(K3sRelatedResource{
				Relation:  "Backend Service",
				Kind:      "Service",
				Resource:  "services",
				Name:      svcName,
				Namespace: ns,
			})
		}
		for _, tlsAny := range asSlice(spec["tls"]) {
			if secName := getStr(asMap(tlsAny), "secretName"); secName != "" {
				addRel(K3sRelatedResource{
					Relation:  "TLS Secret",
					Kind:      "Secret",
					Resource:  "secrets",
					Name:      secName,
					Namespace: ns,
				})
			}
		}

	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job":
		matchLabels := asStrMap(getPath(spec, "selector", "matchLabels"))
		var parts []string
		for k, v := range matchLabels {
			parts = append(parts, k+"="+v)
		}
		if kind == "Job" && len(parts) == 0 {
			parts = append(parts, "job-name="+name)
		}
		sort.Strings(parts)
		if len(parts) > 0 {
			selStr := strings.Join(parts, ",")
			if validK8sLabelSelector(selStr) {
				if pOut, _, _, err := runKubectlLimited(ctx, k8sMaxListBytes, nil, "get", "pods", "-n", ns, "-l", selStr, "-o", "json"); err == nil {
					var pDoc struct {
						Items []map[string]any `json:"items"`
					}
					if json.Unmarshal(pOut, &pDoc) == nil {
						for _, p := range pDoc.Items {
							d := derivePodDetails(p)
							addRel(K3sRelatedResource{
								Relation:   "Managed Pod",
								Kind:       "Pod",
								Resource:   "pods",
								Name:       getStr(p, "metadata", "name"),
								Namespace:  ns,
								Status:     d.reason,
								StatusTone: d.tone,
							})
						}
					}
				}
			}
		}

	case "Node":
		if pOut, _, _, err := runKubectlLimited(ctx, k8sMaxListBytes, nil, "get", "pods", "-A", "--field-selector", "spec.nodeName="+name, "-o", "json"); err == nil {
			var pDoc struct {
				Items []map[string]any `json:"items"`
			}
			if json.Unmarshal(pOut, &pDoc) == nil {
				for idx, p := range pDoc.Items {
					if idx >= 50 {
						break
					}
					d := derivePodDetails(p)
					addRel(K3sRelatedResource{
						Relation:   "Scheduled Pod",
						Kind:       "Pod",
						Resource:   "pods",
						Name:       getStr(p, "metadata", "name"),
						Namespace:  getStr(p, "metadata", "namespace"),
						Status:     d.reason,
						StatusTone: d.tone,
					})
				}
			}
		}

	case "PersistentVolumeClaim":
		if volName := asStr(spec["volumeName"]); volName != "" {
			addRel(K3sRelatedResource{
				Relation: "Bound PV",
				Kind:     "PersistentVolume",
				Resource: "persistentvolumes",
				Name:     volName,
			})
		}
		if scName := asStr(spec["storageClassName"]); scName != "" {
			addRel(K3sRelatedResource{
				Relation: "StorageClass",
				Kind:     "StorageClass",
				Resource: "storageclasses",
				Name:     scName,
			})
		}
	}

	return related
}

// --- Pod & Workload Logs ---

func buildKubectlLogsArgs(req K3sLogsRequest, follow bool) ([]string, error) {
	ns := strings.TrimSpace(req.Namespace)
	if ns == "" {
		ns = "default"
	}
	if !validK8sNamespaceArg(ns) || ns == "_all" {
		return nil, fmt.Errorf("invalid namespace %q", req.Namespace)
	}
	name := strings.TrimSpace(req.Name)
	if !validK8sObjectName(name) {
		return nil, fmt.Errorf("invalid pod or workload name %q", req.Name)
	}
	container := strings.TrimSpace(req.Container)
	if !validK8sContainerName(container) {
		return nil, fmt.Errorf("invalid container name %q", req.Container)
	}

	target := name
	resNorm := strings.ToLower(strings.TrimSpace(req.Resource))
	switch resNorm {
	case "", "pod", "pods", "po":
		target = name
	case "deployment", "deployments", "deploy":
		target = "deployment/" + name
	case "statefulset", "statefulsets", "sts":
		target = "statefulset/" + name
	case "daemonset", "daemonsets", "ds":
		target = "daemonset/" + name
	case "job", "jobs":
		target = "job/" + name
	default:
		return nil, fmt.Errorf("logs unsupported for resource type %q", req.Resource)
	}

	tail := req.Tail
	if tail <= 0 {
		tail = 300
	}
	if tail > 5000 {
		tail = 5000
	}

	args := []string{"logs", "-n", ns, target, "--tail=" + strconv.Itoa(tail)}
	if container != "" {
		args = append(args, "-c", container)
	}
	if req.Previous {
		args = append(args, "--previous")
	}
	if req.Timestamps {
		args = append(args, "--timestamps")
	}
	if req.SinceSeconds > 0 {
		sec := req.SinceSeconds
		if sec > 604800 {
			sec = 604800
		}
		args = append(args, "--since="+strconv.Itoa(sec)+"s")
	}
	if follow {
		args = append(args, "-f")
	}
	return args, nil
}

func (m *K3sManager) GetPodLogs(ctx context.Context, req K3sLogsRequest) (*K3sLogsResponse, error) {
	args, err := buildKubectlLogsArgs(req, false)
	if err != nil {
		return nil, err
	}
	cCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	out, errOut, truncated, runErr := runKubectlLimited(cCtx, k8sMaxTextBytes, nil, args...)
	if runErr != nil {
		msg := strings.TrimSpace(string(errOut))
		if msg == "" {
			msg = runErr.Error()
		}
		return nil, fmt.Errorf("kubectl logs failed: %s", msg)
	}
	text := string(out)
	linesCount := 0
	if len(text) > 0 {
		linesCount = strings.Count(strings.TrimRight(text, "\n"), "\n") + 1
	}
	return &K3sLogsResponse{
		Logs:       text,
		LinesCount: linesCount,
		Truncated:  truncated,
		Container:  req.Container,
		Previous:   req.Previous,
	}, nil
}

func (m *K3sManager) StreamPodLogsSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}
	q := r.URL.Query()
	tail, _ := strconv.Atoi(q.Get("tail"))
	since, _ := strconv.Atoi(q.Get("sinceSeconds"))
	req := K3sLogsRequest{
		Namespace:    q.Get("namespace"),
		Name:         q.Get("name"),
		Resource:     q.Get("resource"),
		Container:    q.Get("container"),
		Tail:         tail,
		Previous:     q.Get("previous") == "true" || q.Get("previous") == "1",
		Timestamps:   q.Get("timestamps") == "true" || q.Get("timestamps") == "1",
		SinceSeconds: since,
	}
	args, err := buildKubectlLogsArgs(req, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	bin, baseArgs, env, binErr := resolveKubectlBinary()
	if binErr != nil {
		http.Error(w, binErr.Error(), http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	sendSSE := func(event string, payload any) {
		b, _ := json.Marshal(payload)
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		flusher.Flush()
	}

	ctx := r.Context()
	fullArgs := append(append([]string{}, baseArgs...), args...)
	cmd := exec.CommandContext(ctx, bin, fullArgs...)
	cmd.Env = env

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		sendSSE("error", map[string]string{"error": err.Error()})
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		sendSSE("error", map[string]string{"error": err.Error()})
		return
	}
	if err := cmd.Start(); err != nil {
		sendSSE("error", map[string]string{"error": err.Error()})
		return
	}

	type streamLine struct {
		stream string
		line   string
	}
	lineCh := make(chan streamLine, 128)
	var pipeWG sync.WaitGroup
	scanPipe := func(r io.Reader, streamName string) {
		defer pipeWG.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 256*1024)
		for sc.Scan() {
			select {
			case lineCh <- streamLine{stream: streamName, line: sc.Text()}:
			case <-ctx.Done():
				return
			}
		}
	}

	pipeWG.Add(2)
	go scanPipe(stdoutPipe, "stdout")
	go scanPipe(stderrPipe, "stderr")
	go func() {
		pipeWG.Wait()
		close(lineCh)
	}()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = cmd.Wait()
			return
		case <-ticker.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case item, open := <-lineCh:
			if !open {
				waitErr := cmd.Wait()
				if waitErr != nil && !errors.Is(ctx.Err(), context.Canceled) {
					sendSSE("done", map[string]string{"status": "closed", "error": waitErr.Error()})
				} else {
					sendSSE("done", map[string]string{"status": "eof"})
				}
				return
			}
			sendSSE("log", map[string]string{
				"stream": item.stream,
				"line":   item.line,
			})
		}
	}
}

// --- Admin K9s Operations ---

func validateScaleTargetResource(res string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(res)) {
	case "deployment", "deployments", "deploy":
		return "deployment", true
	case "statefulset", "statefulsets", "sts":
		return "statefulset", true
	case "replicaset", "replicasets", "rs":
		return "replicaset", true
	default:
		return "", false
	}
}

func validateRolloutTargetResource(res string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(res)) {
	case "deployment", "deployments", "deploy":
		return "deployment", true
	case "statefulset", "statefulsets", "sts":
		return "statefulset", true
	case "daemonset", "daemonsets", "ds":
		return "daemonset", true
	default:
		return "", false
	}
}

func validateYAMLDocuments(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("yaml payload is empty")
	}
	if len(raw) > k8sMaxYamlBytes {
		return fmt.Errorf("yaml payload exceeds 1 MiB limit")
	}
	dec := yaml.NewDecoder(strings.NewReader(raw))
	docCount := 0
	for {
		var doc any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid YAML: %w", err)
		}
		if doc != nil {
			docCount++
		}
	}
	if docCount == 0 {
		return fmt.Errorf("no YAML documents found in payload")
	}
	return nil
}

func (m *K3sManager) ExecuteK3sAction(ctx context.Context, req K3sActionRequest) (*K3sActionResponse, error) {
	action := strings.ToLower(strings.TrimSpace(req.Action))
	resource := strings.TrimSpace(req.Resource)
	ns := strings.TrimSpace(req.Namespace)
	name := strings.TrimSpace(req.Name)

	runCmd := func(timeout time.Duration, stdin io.Reader, args ...string) (*K3sActionResponse, error) {
		cCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		start := time.Now()
		out, errOut, _, runErr := runKubectlLimited(cCtx, k8sMaxTextBytes, stdin, args...)
		lat := time.Since(start).Milliseconds()
		combined := strings.TrimSpace(string(out))
		if errStr := strings.TrimSpace(string(errOut)); errStr != "" {
			if combined != "" {
				combined += "\n" + errStr
			} else {
				combined = errStr
			}
		}
		if runErr != nil {
			exitCode := 1
			var exitErr *exec.ExitError
			if errors.As(runErr, &exitErr) {
				exitCode = exitErr.ExitCode()
			}
			msg := combined
			if msg == "" {
				msg = runErr.Error()
			}
			return &K3sActionResponse{
				Success:   false,
				Message:   msg,
				Output:    combined,
				ExitCode:  exitCode,
				LatencyMs: lat,
			}, nil
		}
		return &K3sActionResponse{
			Success:   true,
			Message:   combined,
			Output:    combined,
			ExitCode:  0,
			LatencyMs: lat,
		}, nil
	}

	switch action {
	case "delete":
		if !validK8sResourceArg(resource) {
			return nil, fmt.Errorf("invalid resource type %q", req.Resource)
		}
		if !validK8sObjectName(name) {
			return nil, fmt.Errorf("invalid object name %q", req.Name)
		}
		if !validK8sNamespaceArg(ns) || ns == "_all" {
			return nil, fmt.Errorf("invalid namespace %q", req.Namespace)
		}
		namespaced := resolveResourceScopeNamespaced(ctx, resource)
		args := []string{"delete", resource, name}
		if namespaced {
			if ns == "" {
				ns = "default"
			}
			args = append(args, "-n", ns)
		}
		if req.Force {
			args = append(args, "--force", "--grace-period=0")
		}
		args = append(args, "--wait=false")
		resp, err := runCmd(25*time.Second, nil, args...)
		if err == nil && resp.Success && resp.Message == "" {
			resp.Message = fmt.Sprintf("Deleted %s/%s", resource, name)
		}
		return resp, err

	case "scale":
		kindTarget, ok := validateScaleTargetResource(resource)
		if !ok {
			return nil, fmt.Errorf("scale requires deployment, statefulset, or replicaset (got %q)", req.Resource)
		}
		if !validK8sObjectName(name) {
			return nil, fmt.Errorf("invalid object name %q", req.Name)
		}
		if ns == "" {
			ns = "default"
		}
		if !validK8sNamespaceArg(ns) || ns == "_all" {
			return nil, fmt.Errorf("invalid namespace %q", req.Namespace)
		}
		if req.Replicas == nil || *req.Replicas < 0 || *req.Replicas > 200 {
			return nil, fmt.Errorf("replicas must be between 0 and 200")
		}
		resp, err := runCmd(20*time.Second, nil, "scale", kindTarget+"/"+name, "-n", ns, "--replicas="+strconv.Itoa(*req.Replicas))
		if err == nil && resp.Success && resp.Message == "" {
			resp.Message = fmt.Sprintf("Scaled %s/%s to %d replicas", kindTarget, name, *req.Replicas)
		}
		return resp, err

	case "rollout-restart", "rollout-undo":
		kindTarget, ok := validateRolloutTargetResource(resource)
		if !ok {
			return nil, fmt.Errorf("%s requires deployment, statefulset, or daemonset (got %q)", action, req.Resource)
		}
		if !validK8sObjectName(name) {
			return nil, fmt.Errorf("invalid object name %q", req.Name)
		}
		if ns == "" {
			ns = "default"
		}
		if !validK8sNamespaceArg(ns) || ns == "_all" {
			return nil, fmt.Errorf("invalid namespace %q", req.Namespace)
		}
		subcmd := "restart"
		if action == "rollout-undo" {
			subcmd = "undo"
		}
		return runCmd(20*time.Second, nil, "rollout", subcmd, kindTarget+"/"+name, "-n", ns)

	case "cordon", "uncordon":
		if !validK8sNodeName(name) {
			return nil, fmt.Errorf("invalid node name %q", req.Name)
		}
		return runCmd(20*time.Second, nil, action, name)

	case "drain":
		if !validK8sNodeName(name) {
			return nil, fmt.Errorf("invalid node name %q", req.Name)
		}
		return runCmd(90*time.Second, nil, "drain", name, "--ignore-daemonsets", "--delete-emptydir-data", "--force", "--timeout=60s")

	case "trigger-cronjob":
		if !validK8sObjectName(name) {
			return nil, fmt.Errorf("invalid cronjob name %q", req.Name)
		}
		if ns == "" {
			ns = "default"
		}
		if !validK8sNamespaceArg(ns) || ns == "_all" {
			return nil, fmt.Errorf("invalid namespace %q", req.Namespace)
		}
		jobName := fmt.Sprintf("%s-manual-%d", name, time.Now().Unix())
		if len(jobName) > 63 {
			jobName = jobName[len(jobName)-63:]
			jobName = strings.TrimLeft(jobName, "-")
		}
		return runCmd(20*time.Second, nil, "create", "job", "--from=cronjob/"+name, jobName, "-n", ns)

	case "suspend-cronjob":
		if !validK8sObjectName(name) {
			return nil, fmt.Errorf("invalid cronjob name %q", req.Name)
		}
		if ns == "" {
			ns = "default"
		}
		if !validK8sNamespaceArg(ns) || ns == "_all" {
			return nil, fmt.Errorf("invalid namespace %q", req.Namespace)
		}
		susp := true
		if req.Suspend != nil {
			susp = *req.Suspend
		}
		patch := fmt.Sprintf(`{"spec":{"suspend":%t}}`, susp)
		return runCmd(20*time.Second, nil, "patch", "cronjob", name, "-n", ns, "--type=merge", "-p", patch)

	case "apply-yaml":
		if err := validateYAMLDocuments(req.Yaml); err != nil {
			return nil, err
		}
		args := []string{"apply", "-f", "-"}
		if req.DryRun {
			args = append(args, "--dry-run=server")
		}
		return runCmd(25*time.Second, strings.NewReader(req.Yaml), args...)

	case "exec":
		if !validK8sObjectName(name) {
			return nil, fmt.Errorf("invalid pod name %q", req.Name)
		}
		if ns == "" {
			ns = "default"
		}
		if !validK8sNamespaceArg(ns) || ns == "_all" {
			return nil, fmt.Errorf("invalid namespace %q", req.Namespace)
		}
		container := strings.TrimSpace(req.Container)
		if !validK8sContainerName(container) {
			return nil, fmt.Errorf("invalid container name %q", req.Container)
		}
		if strings.TrimSpace(req.Command) == "" || len(req.Command) > 4096 {
			return nil, fmt.Errorf("exec command must be between 1 and 4096 characters")
		}
		args := []string{"exec", "-n", ns, name}
		if container != "" {
			args = append(args, "-c", container)
		}
		// Run inside the container via explicit argv (never via a host shell)
		args = append(args, "--", "/bin/sh", "-c", req.Command)
		return runCmd(30*time.Second, nil, args...)

	default:
		return nil, fmt.Errorf("unsupported K3s action %q", req.Action)
	}
}
