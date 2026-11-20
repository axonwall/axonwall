package engine

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseK8sQuantities(t *testing.T) {
	if got := parseK8sCPU("250m"); got != 250 {
		t.Errorf("parseK8sCPU(250m) = %d, want 250", got)
	}
	if got := parseK8sCPU("4"); got != 4000 {
		t.Errorf("parseK8sCPU(4) = %d, want 4000", got)
	}
	if got := parseK8sCPU("0.5"); got != 500 {
		t.Errorf("parseK8sCPU(0.5) = %d, want 500", got)
	}
	if got := parseK8sCPU("500000000n"); got != 500 {
		t.Errorf("parseK8sCPU(500000000n) = %d, want 500", got)
	}
	if got := parseK8sCPU("2000u"); got != 2 {
		t.Errorf("parseK8sCPU(2000u) = %d, want 2", got)
	}

	if got := parseK8sMemory("1Gi"); got != 1024*1024*1024 {
		t.Errorf("parseK8sMemory(1Gi) = %d, want %d", got, 1024*1024*1024)
	}
	if got := parseK8sMemory("512Mi"); got != 512*1024*1024 {
		t.Errorf("parseK8sMemory(512Mi) = %d, want %d", got, 512*1024*1024)
	}
	if got := parseK8sMemory("2048Ki"); got != 2048*1024 {
		t.Errorf("parseK8sMemory(2048Ki) = %d, want %d", got, 2048*1024)
	}
	if got := parseK8sMemory("500M"); got != 500_000_000 {
		t.Errorf("parseK8sMemory(500M) = %d, want 500000000", got)
	}
}

func TestValidateK8sExplorerInputsRejectsInjection(t *testing.T) {
	badResources := []string{"", "-rf", "--all-namespaces", "pods;id", "../secrets", "pods/exec"}
	for _, r := range badResources {
		if validK8sResourceArg(r) {
			t.Errorf("expected resource %q to be rejected", r)
		}
	}
	goodResources := []string{"pods", "po", "svc", "applications.argoproj.io", "persistentvolumeclaims"}
	for _, r := range goodResources {
		if !validK8sResourceArg(r) {
			t.Errorf("expected resource %q to be valid", r)
		}
	}

	badNames := []string{"", "-flag", "../etc", "foo/bar", "foo;id"}
	for _, n := range badNames {
		if validK8sObjectName(n) {
			t.Errorf("expected object name %q to be rejected", n)
		}
	}
	goodNames := []string{"minio-0", "system:kube-scheduler", "cert-manager.io"}
	for _, n := range goodNames {
		if !validK8sObjectName(n) {
			t.Errorf("expected object name %q to be valid", n)
		}
	}

	if validK8sLabelSelector("-n kube-system") || validK8sLabelSelector("app=foo;rm") {
		t.Errorf("expected dangerous label selectors to be rejected")
	}
	if !validK8sLabelSelector("app.kubernetes.io/name in (minio,grafana),env!=dev") {
		t.Errorf("expected valid set-based label selector to pass")
	}

	mgr := NewK3sManager()
	repNeg := -1
	if _, err := mgr.ExecuteK3sAction(context.Background(), K3sActionRequest{
		Action: "scale", Resource: "deployments", Namespace: "default", Name: "app", Replicas: &repNeg,
	}); err == nil {
		t.Errorf("expected negative replica scale to fail validation")
	}
	if _, err := mgr.ExecuteK3sAction(context.Background(), K3sActionRequest{
		Action: "apply-yaml", Yaml: ":\n\t::bad: [yaml",
	}); err == nil {
		t.Errorf("expected invalid YAML apply to fail validation")
	}
}

func setupFakeKubectlExplorerEnv(t *testing.T) (fixturesDir, logFile string) {
	t.Helper()
	dir := t.TempDir()
	fixturesDir = filepath.Join(dir, "fixtures")
	binDir := filepath.Join(dir, "bin")
	logFile = filepath.Join(dir, "kubectl-invocations.log")
	if err := os.MkdirAll(fixturesDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}

	writeFix := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(fixturesDir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	writeFix("nodes.json", `{"items": [
		{
			"metadata": {"name": "axon-node-1", "labels": {"node-role.kubernetes.io/control-plane": "true", "node-role.kubernetes.io/master": "true"}, "creationTimestamp": "2026-11-10T00:00:00Z"},
			"spec": {"unschedulable": false},
			"status": {
				"conditions": [{"type": "Ready", "status": "True"}],
				"addresses": [{"type": "InternalIP", "address": "10.80.0.10"}],
				"capacity": {"cpu": "8", "memory": "16Gi", "pods": "110"},
				"allocatable": {"cpu": "7800m", "memory": "15Gi", "pods": "110"},
				"nodeInfo": {"kubeletVersion": "v1.32.3+k3s1", "osImage": "Debian GNU/Linux 13", "kernelVersion": "6.12.15-axonwall", "containerRuntimeVersion": "containerd://2.0.0"}
			}
		}
	]}`)

	writeFix("pods.json", `{"items": [
		{
			"metadata": {
				"name": "web-7f8d9-abc", "namespace": "apps", "uid": "pod-uid-1",
				"labels": {"app": "web"}, "creationTimestamp": "2026-11-18T12:00:00Z",
				"ownerReferences": [{"kind": "ReplicaSet", "name": "web-7f8d9"}]
			},
			"spec": {
				"nodeName": "axon-node-1",
				"serviceAccountName": "web-sa",
				"hostUsers": false,
				"containers": [{
					"name": "web", "image": "nginx:1.27",
					"resources": {"requests": {"cpu": "250m", "memory": "256Mi"}, "limits": {"cpu": "1", "memory": "512Mi"}}
				}],
				"volumes": [
					{"name": "data", "persistentVolumeClaim": {"claimName": "web-pvc"}},
					{"name": "creds", "secret": {"secretName": "web-secret"}}
				]
			},
			"status": {
				"phase": "Running", "podIP": "10.42.0.15",
				"containerStatuses": [{"name": "web", "ready": true, "restartCount": 2}]
			}
		}
	]}`)

	writeFix("deployments.json", `{"items": [
		{
			"metadata": {"name": "web", "namespace": "apps", "creationTimestamp": "2026-11-18T11:00:00Z"},
			"spec": {"replicas": 1, "selector": {"matchLabels": {"app": "web"}}, "template": {"spec": {"containers": [{"name": "web", "image": "nginx:1.27"}]}}},
			"status": {"readyReplicas": 1, "availableReplicas": 1}
		}
	]}`)

	writeFix("replicasets.json", `{"items": [
		{
			"metadata": {"name": "web-7f8d9", "namespace": "apps", "ownerReferences": [{"kind": "Deployment", "name": "web"}]},
			"spec": {"replicas": 1}, "status": {"readyReplicas": 1}
		}
	]}`)

	writeFix("services.json", `{"items": [
		{
			"metadata": {"name": "web-svc", "namespace": "apps", "creationTimestamp": "2026-11-18T11:00:00Z"},
			"spec": {"type": "ClusterIP", "clusterIP": "10.43.10.20", "selector": {"app": "web"}, "ports": [{"port": 80, "targetPort": 8080, "protocol": "TCP"}]},
			"status": {}
		}
	]}`)

	writeFix("ingresses.json", `{"items": [
		{
			"metadata": {"name": "web-ing", "namespace": "apps", "creationTimestamp": "2026-11-18T11:00:00Z"},
			"spec": {
				"ingressClassName": "traefik",
				"tls": [{"hosts": ["web.axonwall.lan"], "secretName": "web-tls"}],
				"rules": [{"host": "web.axonwall.lan", "http": {"paths": [{"path": "/", "pathType": "Prefix", "backend": {"service": {"name": "web-svc", "port": {"number": 80}}}}]}}]
			},
			"status": {"loadBalancer": {"ingress": [{"ip": "10.80.0.10"}]}}
		}
	]}`)

	writeFix("endpoints.json", `{"items": [
		{"metadata": {"name": "web-svc", "namespace": "apps"}, "subsets": [{"addresses": [{"ip": "10.42.0.15", "targetRef": {"uid": "pod-uid-1"}}]}]}
	]}`)

	writeFix("pvc.json", `{"items": [
		{
			"metadata": {"name": "web-pvc", "namespace": "apps", "creationTimestamp": "2026-11-18T10:00:00Z"},
			"spec": {"storageClassName": "axonwall-replicated-ha", "volumeName": "pvc-vol-1", "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "20Gi"}}},
			"status": {"phase": "Bound", "capacity": {"storage": "20Gi"}}
		}
	]}`)

	writeFix("storageclass.json", `{"items": [
		{"metadata": {"name": "axonwall-replicated-ha", "annotations": {"storageclass.kubernetes.io/is-default-class": "true"}}, "provisioner": "io.openebs.csi-mayastor"}
	]}`)

	writeFix("namespaces.json", `{"items": [
		{"metadata": {"name": "apps", "creationTimestamp": "2026-11-10T00:00:00Z"}, "status": {"phase": "Active"}}
	]}`)

	writeFix("events.json", `{"items": [
		{"type": "Normal", "reason": "Started", "metadata": {"namespace": "apps"}, "involvedObject": {"kind": "Pod", "name": "web-7f8d9-abc"}, "message": "Started container web", "count": 1, "lastTimestamp": "2026-11-19T00:00:00Z", "source": {"component": "kubelet"}}
	]}`)

	b64Pass := base64.StdEncoding.EncodeToString([]byte("super-secret-token-42"))
	writeFix("secrets.json", `{"items": [
		{
			"kind": "Secret", "apiVersion": "v1", "type": "Opaque",
			"metadata": {"name": "web-secret", "namespace": "apps", "uid": "sec-1", "creationTimestamp": "2026-11-18T00:00:00Z"},
			"data": {"API_TOKEN": "`+b64Pass+`"}
		}
	]}`)

	writeFix("secret_one.json", `{
		"kind": "Secret", "apiVersion": "v1", "type": "Opaque",
		"metadata": {
			"name": "web-secret", "namespace": "apps", "uid": "sec-1",
			"annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{\"data\":{\"API_TOKEN\":\"`+b64Pass+`\"}}"}
		},
		"data": {"API_TOKEN": "`+b64Pass+`"}
	}`)

	writeFix("secret_one.yaml", "apiVersion: v1\nkind: Secret\nmetadata:\n  name: web-secret\n  namespace: apps\n  annotations:\n    kubectl.kubernetes.io/last-applied-configuration: secret-json-here\ndata:\n  API_TOKEN: "+b64Pass+"\ntype: Opaque\n")

	writeFix("api_resources.txt", "pods                              po           v1                                true         Pod                              create delete get list watch\nservices                          svc          v1                                true         Service                          create delete get list\ncertificates                      cert,certs   cert-manager.io/v1                true         Certificate                      create delete get list\nclusterissuers                                 cert-manager.io/v1                false        ClusterIssuer                    create delete get list\n")

	kubectlScript := `#!/bin/sh
echo "$*" >> "` + logFile + `"
cmd="$1"
case "$cmd" in
  api-resources)
    cat "` + fixturesDir + `/api_resources.txt"
    exit 0
    ;;
  top)
    if [ "$2" = "nodes" ]; then
      echo "axon-node-1   310m   4%   2048Mi   13%"
    else
      echo "apps   web-7f8d9-abc   120m   192Mi"
    fi
    exit 0
    ;;
  get)
    res="$2"
    all_args="$*"
    case "$res" in
      nodes|node) cat "` + fixturesDir + `/nodes.json";;
      pods|pod) cat "` + fixturesDir + `/pods.json";;
      deployments|deployment) cat "` + fixturesDir + `/deployments.json";;
      replicasets|replicaset) cat "` + fixturesDir + `/replicasets.json";;
      services|service) cat "` + fixturesDir + `/services.json";;
      ingresses|ingress) cat "` + fixturesDir + `/ingresses.json";;
      endpoints) cat "` + fixturesDir + `/endpoints.json";;
      pvc|persistentvolumeclaims) cat "` + fixturesDir + `/pvc.json";;
      storageclass|storageclasses) cat "` + fixturesDir + `/storageclass.json";;
      namespaces|namespace) cat "` + fixturesDir + `/namespaces.json";;
      events|event) cat "` + fixturesDir + `/events.json";;
      secrets|secret)
        if echo "$all_args" | grep -q "web-secret"; then
          if echo "$all_args" | grep -q " -o yaml"; then
            cat "` + fixturesDir + `/secret_one.yaml"
          else
            cat "` + fixturesDir + `/secret_one.json"
          fi
        else
          cat "` + fixturesDir + `/secrets.json"
        fi
        ;;
      *)
        echo '{"items":[]}'
        ;;
    esac
    exit 0
    ;;
  describe)
    echo "Name: web-secret"
    echo "Data"
    echo "===="
    echo "API_TOKEN: 21 bytes"
    exit 0
    ;;
  logs)
    echo "2026-11-19T00:00:00Z INFO server listening on :8080"
    exit 0
    ;;
  scale|rollout|cordon|uncordon|delete|apply|exec|create|patch|drain)
    echo "action $cmd executed: $*"
    exit 0
    ;;
esac
echo "unexpected command $*" >&2
exit 1
`
	if err := os.WriteFile(filepath.Join(binDir, "kubectl"), []byte(kubectlScript), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	return fixturesDir, logFile
}

func TestK3sExplorerPulseAndTopology(t *testing.T) {
	setupFakeKubectlExplorerEnv(t)
	mgr := NewK3sManager()

	pulse, err := mgr.GetClusterPulse(context.Background())
	if err != nil {
		t.Fatalf("GetClusterPulse returned error: %v", err)
	}
	if !pulse.Available || !pulse.MetricsAvailable {
		t.Fatalf("expected pulse.Available=true and MetricsAvailable=true, got %v/%v (%s)", pulse.Available, pulse.MetricsAvailable, pulse.Error)
	}
	if pulse.Counts.NodesReady != 1 || pulse.Counts.PodsRunning != 1 || pulse.Counts.TotalRestarts != 2 {
		t.Errorf("unexpected pulse counts: %+v", pulse.Counts)
	}
	if len(pulse.Nodes) != 1 || pulse.Nodes[0].CpuRequestsMillis != 250 || pulse.Nodes[0].CpuUsageMillis == nil || *pulse.Nodes[0].CpuUsageMillis != 310 {
		t.Errorf("unexpected node pulse telemetry: %+v", pulse.Nodes)
	}
	if len(pulse.StorageByClass) != 1 || pulse.StorageByClass[0].TotalBytes != 20*1024*1024*1024 {
		t.Errorf("unexpected storageByClass: %+v", pulse.StorageByClass)
	}

	// Verify topology edges across all 5 layers: Ingress -> Service -> Pod, Deployment -> Pod, Pod -> Node, Pod -> PVC
	edgeRelations := make(map[string]bool)
	for _, e := range pulse.Topology.Edges {
		edgeRelations[e.Source+"|"+e.Target+"|"+e.Relation] = true
	}
	expectedEdges := []string{
		"ingress/apps/web-ing|service/apps/web-svc|ingress-to-service",
		"service/apps/web-svc|pod/apps/web-7f8d9-abc|service-to-pod",
		"deployment/apps/web|pod/apps/web-7f8d9-abc|workload-to-pod",
		"pod/apps/web-7f8d9-abc|node/axon-node-1|pod-to-node",
		"pod/apps/web-7f8d9-abc|pvc/apps/web-pvc|pod-to-pvc",
	}
	for _, exp := range expectedEdges {
		if !edgeRelations[exp] {
			t.Errorf("missing expected topology edge %s; got edges=%+v", exp, pulse.Topology.Edges)
		}
	}
}

func TestK3sExplorerSecretRedactionAndDecode(t *testing.T) {
	setupFakeKubectlExplorerEnv(t)
	mgr := NewK3sManager()

	// ListResources must NEVER include secret values
	listResp, err := mgr.ListResources(context.Background(), "secrets", "apps", "")
	if err != nil || len(listResp.Items) != 1 {
		t.Fatalf("ListResources(secrets) failed: err=%v, resp=%+v", err, listResp)
	}
	if listResp.Items[0].Summary["dataCount"] != 1 {
		t.Errorf("expected dataCount=1, got %v", listResp.Items[0].Summary["dataCount"])
	}

	// InspectResource with decodeSecret=false MUST redact JSON, YAML, and last-applied annotation
	redacted, err := mgr.InspectResource(context.Background(), "secrets", "apps", "web-secret", false)
	if err != nil {
		t.Fatalf("InspectResource(decode=false) failed: %v", err)
	}
	if !redacted.SecretRedacted || len(redacted.DecodedSecretData) != 0 {
		t.Errorf("expected SecretRedacted=true and no DecodedSecretData")
	}
	if strings.Contains(redacted.Yaml, "c3VwZXItc2VjcmV0") || strings.Contains(redacted.Yaml, "secret-json-here") {
		t.Errorf("Secret YAML still contained unredacted data or last-applied annotation: %s", redacted.Yaml)
	}

	// InspectResource with decodeSecret=true MUST decode UTF-8 value cleanly
	decoded, err := mgr.InspectResource(context.Background(), "secrets", "apps", "web-secret", true)
	if err != nil {
		t.Fatalf("InspectResource(decode=true) failed: %v", err)
	}
	if decoded.DecodedSecretData["API_TOKEN"] != "super-secret-token-42" {
		t.Errorf("expected decoded API_TOKEN='super-secret-token-42', got %q", decoded.DecodedSecretData["API_TOKEN"])
	}
}

func TestK3sExplorerActionsLogsAndDiscovery(t *testing.T) {
	_, logFile := setupFakeKubectlExplorerEnv(t)
	mgr := NewK3sManager()

	apis, err := mgr.ListAPIResources(context.Background())
	if err != nil || len(apis) != 4 {
		t.Fatalf("ListAPIResources failed: err=%v, count=%d", err, len(apis))
	}
	if apis[2].Name != "certificates" || len(apis[2].ShortNames) != 2 || !apis[2].Namespaced {
		t.Errorf("unexpected parsed CRD entry: %+v", apis[2])
	}
	if apis[3].Namespaced != false {
		t.Errorf("expected clusterissuers Namespaced=false")
	}

	logsResp, err := mgr.GetPodLogs(context.Background(), K3sLogsRequest{
		Namespace: "apps", Resource: "deployments", Name: "web", Tail: 100,
	})
	if err != nil || logsResp.LinesCount != 1 {
		t.Fatalf("GetPodLogs failed: err=%v, resp=%+v", err, logsResp)
	}

	reps := 3
	actResp, err := mgr.ExecuteK3sAction(context.Background(), K3sActionRequest{
		Action: "scale", Resource: "deployments", Namespace: "apps", Name: "web", Replicas: &reps,
	})
	if err != nil || !actResp.Success {
		t.Fatalf("scale failed: err=%v, resp=%+v", err, actResp)
	}

	dryResp, err := mgr.ExecuteK3sAction(context.Background(), K3sActionRequest{
		Action: "apply-yaml", DryRun: true, Yaml: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\n",
	})
	if err != nil || !dryResp.Success {
		t.Fatalf("apply-yaml dry-run failed: err=%v, resp=%+v", err, dryResp)
	}

	logBytes, _ := os.ReadFile(logFile)
	if !strings.Contains(string(logBytes), "scale deployment/web -n apps --replicas=3") {
		t.Errorf("expected scale invocation in log, got:\n%s", string(logBytes))
	}
	if !strings.Contains(string(logBytes), "apply -f - --dry-run=server") {
		t.Errorf("expected dry-run apply invocation in log, got:\n%s", string(logBytes))
	}
}

func TestK3sExplorerPulseFailsClosedWhenUnreachable(t *testing.T) {
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "kubectl"), []byte("#!/bin/sh\necho 'connection refused' >&2\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	mgr := NewK3sManager()
	pulse, err := mgr.GetClusterPulse(context.Background())
	if err != nil {
		t.Fatalf("expected fail-closed struct without fatal error, got %v", err)
	}
	if pulse.Available {
		t.Errorf("expected Available=false when kubectl fails")
	}
	if !strings.Contains(pulse.Error, "connection refused") {
		t.Errorf("expected connection refused in pulse.Error, got %q", pulse.Error)
	}
}
