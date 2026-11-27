package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const topologyMaskedPlaceholder = "********"

var lldpdConfPath = "/etc/lldpd.d/axonwall.conf"

type TopologyPortSpecPayload struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	SpeedMbps  int    `json:"speedMbps,omitempty"`
	MTU        int    `json:"mtu,omitempty"`
	VlanIds    []int  `json:"vlanIds"`
	SubnetCidr string `json:"subnetCidr,omitempty"`
	Planned    bool   `json:"planned"`
}

type TopologyLldpConfigPayload struct {
	Enabled           bool     `json:"enabled"`
	ExcludeWan        bool     `json:"excludeWan"`
	Interfaces        []string `json:"interfaces"`
	SystemDescription string   `json:"systemDescription,omitempty"`
}

type TopologyPollingConfigPayload struct {
	LocalIntervalSec int  `json:"localIntervalSec"`
	PeerIntervalSec  int  `json:"peerIntervalSec"`
	PauseWhenHidden  bool `json:"pauseWhenHidden"`
}

type TopologyPeerHostPayload struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Role          string `json:"role"`
	APIURL        string `json:"apiUrl"`
	APIToken      string `json:"apiToken,omitempty"`
	TLSCaCert     string `json:"tlsCaCert,omitempty"`
	TLSCertSha256 string `json:"tlsCertSha256,omitempty"`
	UseHaMtls     bool   `json:"useHaMtls"`
	Enabled       bool   `json:"enabled"`
	Site          string `json:"site,omitempty"`
	Rack          string `json:"rack,omitempty"`
}

type TopologyConfigPayload struct {
	Enabled       bool                         `json:"enabled"`
	LLDP          TopologyLldpConfigPayload    `json:"lldp"`
	Polling       TopologyPollingConfigPayload `json:"polling"`
	Peers         []TopologyPeerHostPayload    `json:"peers"`
	Nodes         []json.RawMessage            `json:"nodes"`
	Cables        []json.RawMessage            `json:"cables"`
	Scenarios     []json.RawMessage            `json:"scenarios"`
	ActiveScenario string                      `json:"activeScenarioId,omitempty"`
}

type TopologyCompiledLldpPayload struct {
	Enabled               bool     `json:"enabled"`
	AllowedInterfaces     []string `json:"allowedInterfaces"`
	ExcludedWanInterfaces []string `json:"excludedWanInterfaces"`
	ConfContent           string   `json:"confContent"`
}

type TopologyRuntimeBundle struct {
	Enabled bool                        `json:"enabled"`
	Config  TopologyConfigPayload       `json:"config"`
	LLDP    TopologyCompiledLldpPayload `json:"lldp"`
}

type HostNicLLDPNeighbor struct {
	ChassisName string `json:"chassisName"`
	PortID      string `json:"portId"`
	PortDescr   string `json:"portDescr,omitempty"`
}

type HostNicProbe struct {
	HostID        string                `json:"hostId"`
	Device        string                `json:"device"`
	Name          string                `json:"name,omitempty"`
	Role          string                `json:"role,omitempty"`
	AdminUp       bool                  `json:"adminUp"`
	CarrierUp     bool                  `json:"carrierUp"`
	SpeedMbps     int                   `json:"speedMbps,omitempty"`
	MTU           int                   `json:"mtu,omitempty"`
	MAC           string                `json:"mac,omitempty"`
	IPv4Addresses []string              `json:"ipv4Addresses,omitempty"`
	DomAlarm      bool                  `json:"domAlarm,omitempty"`
	RxErrors      int64                 `json:"rxErrors,omitempty"`
	TxErrors      int64                 `json:"txErrors,omitempty"`
	LLDPNeighbors []HostNicLLDPNeighbor `json:"lldpNeighbors,omitempty"`
}

type HostTunnelProbe struct {
	HostID          string `json:"hostId"`
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	Up              bool   `json:"up"`
	HandshakeAgeSec int64  `json:"handshakeAgeSec,omitempty"`
	PeerEndpoint    string `json:"peerEndpoint,omitempty"`
}

type K3sProbeNode struct {
	Name          string `json:"name"`
	Status        string `json:"status"`
	Roles         string `json:"roles,omitempty"`
	InternalIP    string `json:"internalIp,omitempty"`
	Unschedulable bool   `json:"unschedulable,omitempty"`
}

type K3sProbeBackendService struct {
	Name string `json:"name"`
	Port int    `json:"port,omitempty"`
}

type K3sProbeIngress struct {
	Name            string                    `json:"name"`
	Namespace       string                    `json:"namespace"`
	Hosts           []string                  `json:"hosts,omitempty"`
	BackendServices []K3sProbeBackendService  `json:"backendServices"`
	TLSSecretNames  []string                  `json:"tlsSecretNames,omitempty"`
	Kind            string                    `json:"kind"` // Ingress | IngressRoute | HTTPRoute
}

type K3sProbeService struct {
	Name           string            `json:"name"`
	Namespace      string            `json:"namespace"`
	Type           string            `json:"type,omitempty"`
	ClusterIP      string            `json:"clusterIp,omitempty"`
	Ports          []int             `json:"ports,omitempty"`
	ReadyEndpoints int               `json:"readyEndpoints"`
	Selector       map[string]string `json:"selector,omitempty"`
}

type K3sProbeWorkload struct {
	Kind            string            `json:"kind"`
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	ReadyReplicas   int               `json:"readyReplicas"`
	DesiredReplicas int               `json:"desiredReplicas"`
	Selector        map[string]string `json:"selector,omitempty"`
}

type K3sProbePVC struct {
	Name         string `json:"name"`
	Namespace    string `json:"namespace"`
	StorageClass string `json:"storageClass,omitempty"`
	Capacity     string `json:"capacity,omitempty"`
	Bound        bool   `json:"bound"`
}

type K3sProbeNetworkPolicy struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type K3sResourceProbeSnapshot struct {
	Available       bool                    `json:"available"`
	Nodes           []K3sProbeNode          `json:"nodes"`
	Ingresses       []K3sProbeIngress       `json:"ingresses"`
	Services        []K3sProbeService       `json:"services"`
	Workloads       []K3sProbeWorkload      `json:"workloads"`
	PVCs            []K3sProbePVC           `json:"pvcs"`
	NetworkPolicies []K3sProbeNetworkPolicy `json:"networkPolicies"`
}

type LocalTopologyProbe struct {
	Timestamp     string                    `json:"timestamp"`
	LocalHostID   string                    `json:"localHostId"`
	NICs          []HostNicProbe            `json:"nics"`
	Tunnels       []HostTunnelProbe         `json:"tunnels"`
	Transceivers  []OpticalModule           `json:"transceivers"`
	VMs           []VMStatus                `json:"vms"`
	Containers    []ContainerStatus         `json:"containers"`
	K3s           *K3sResourceProbeSnapshot `json:"k3s,omitempty"`
}

type PeerHostProbeResult struct {
	PeerID    string            `json:"peerId"`
	Name      string            `json:"name"`
	Role      string            `json:"role"`
	Reachable bool              `json:"reachable"`
	AuthError string            `json:"authError,omitempty"`
	Error     string            `json:"error,omitempty"`
	NICs      []HostNicProbe    `json:"nics"`
	Tunnels   []HostTunnelProbe `json:"tunnels"`
}

type TopologyFabricSnapshot struct {
	Timestamp string                    `json:"timestamp"`
	Local     *LocalTopologyProbe       `json:"local"`
	Peers     []PeerHostProbeResult     `json:"peers"`
	LibreNMS  *LibreNMSTopologySnapshot `json:"librenms,omitempty"`
	NetBox    *NetBoxInventorySnapshot  `json:"netbox,omitempty"`
	NetFlow   *NetFlowTopologyOverlay   `json:"netflow,omitempty"`
	Config    *TopologyConfigPayload    `json:"config,omitempty"`
}

type TopologyK3sEdit struct {
	Kind         string   `json:"kind"`
	Name         string   `json:"name"`
	Namespace    string   `json:"namespace,omitempty"`
	ManifestYAML string   `json:"manifestYaml,omitempty"`
	ScaleReplicas *int    `json:"scaleReplicas,omitempty"`
	NodeRoles    []string `json:"nodeRoles,omitempty"`
}

type TopologyPeerEdit struct {
	PeerID   string          `json:"peerId"`
	Name     string          `json:"name,omitempty"`
	State    json.RawMessage `json:"state,omitempty"`
	Patch    json.RawMessage `json:"patch,omitempty"`
	Hostname string          `json:"hostname,omitempty"`
}

type TopologyApplyRequest struct {
	DryRun                bool               `json:"dryRun"`
	ConfirmTimeoutSeconds int                `json:"confirmTimeoutSeconds"`
	K3sEdits              []TopologyK3sEdit  `json:"k3sEdits,omitempty"`
	PeerEdits             []TopologyPeerEdit `json:"peerEdits,omitempty"`
	HasLocalChanges       bool               `json:"hasLocalChanges,omitempty"`
	AutoConfirmPeers      bool               `json:"autoConfirmPeers,omitempty"`
}

type TopologyApplyTargetResult struct {
	Phase      int    `json:"phase"`
	TargetType string `json:"targetType"` // "k3s" | "peer" | "local"
	TargetID   string `json:"targetId"`
	Success    bool   `json:"success"`
	RolledBack bool   `json:"rolledBack,omitempty"`
	Message    string `json:"message,omitempty"`
	Error      string `json:"error,omitempty"`
}

type TopologyApplyResult struct {
	Success               bool                        `json:"success"`
	DryRun                bool                        `json:"dryRun"`
	Timestamp             string                      `json:"timestamp"`
	ConfirmTimeoutSeconds int                         `json:"confirmTimeoutSeconds"`
	RolledBackAny         bool                        `json:"rolledBackAny"`
	Results               []TopologyApplyTargetResult `json:"results"`
	Error                 string                      `json:"error,omitempty"`
}

type TopologyManager struct {
	mu              sync.Mutex
	configDir       string
	k3sManager      *K3sManager
	virtManager     *VirtManager
	hardwareManager *HardwareManager
	netboxManager   *NetBoxManager
	librenmsManager *LibreNMSManager
	netflowManager  *NetFlowManager
	sysfsNetDir     string
	kubectlRunner   func(ctx context.Context, args ...string) ([]byte, error)
	lldpRunner      func(ctx context.Context) ([]byte, error)
	wgRunner        func(ctx context.Context) ([]byte, error)
	svcRunner          func(ctx context.Context, action string) error
	haTlsLoader        func() (*tls.Config, error)
	allowLoopbackPeers bool
}

// SetAllowLoopbackForTest enables or disables loopback peer connections for unit tests.
func (m *TopologyManager) SetAllowLoopbackForTest(allow bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowLoopbackPeers = allow
}

func NewTopologyManager(
	configDir string,
	k3sManager *K3sManager,
	virtManager *VirtManager,
	hardwareManager *HardwareManager,
	netboxManager *NetBoxManager,
	librenmsManager *LibreNMSManager,
) *TopologyManager {
	return &TopologyManager{
		configDir:       configDir,
		k3sManager:      k3sManager,
		virtManager:     virtManager,
		hardwareManager: hardwareManager,
		netboxManager:   netboxManager,
		librenmsManager: librenmsManager,
		sysfsNetDir:     "/sys/class/net",
		haTlsLoader:     LoadHAPKITLSConfig,
	}
}

func (m *TopologyManager) SetNetFlowManager(nf *NetFlowManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.netflowManager = nf
}

func (m *TopologyManager) ApplyConfig(rawJSON []byte) error {
	var bundle TopologyRuntimeBundle
	if err := json.Unmarshal(rawJSON, &bundle); err != nil {
		return fmt.Errorf("invalid topology runtime bundle json: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(m.configDir, 0750); err != nil {
		return fmt.Errorf("failed to create topology config dir %q: %w", m.configDir, err)
	}

	// Persist peer API tokens strictly in 0600 peers-secrets.json
	secretsPath := filepath.Join(m.configDir, "peers-secrets.json")
	existingSecrets := map[string]string{}
	if rawSec, err := os.ReadFile(secretsPath); err == nil {
		_ = json.Unmarshal(rawSec, &existingSecrets)
	}
	nextSecrets := map[string]string{}
	sanitized := bundle
	sanitized.Config.Peers = make([]TopologyPeerHostPayload, 0, len(bundle.Config.Peers))
	for _, p := range bundle.Config.Peers {
		tok := strings.TrimSpace(p.APIToken)
		if tok == topologyMaskedPlaceholder || tok == "" {
			if prev, ok := existingSecrets[p.ID]; ok {
				tok = prev
			} else {
				tok = ""
			}
		}
		if tok != "" {
			nextSecrets[p.ID] = tok
		}
		p.APIToken = ""
		sanitized.Config.Peers = append(sanitized.Config.Peers, p)
	}

	if secBytes, err := json.MarshalIndent(nextSecrets, "", "  "); err == nil {
		if err := writeFilesAtomic([]atomicFileWrite{
			{path: secretsPath, content: string(secBytes) + "\n", perm: 0600},
		}); err != nil {
			return fmt.Errorf("failed to write topology peer secrets: %w", err)
		}
	}

	cfgBytes, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize sanitized topology config: %w", err)
	}
	if err := writeFilesAtomic([]atomicFileWrite{
		{path: filepath.Join(m.configDir, "config.json"), content: string(cfgBytes) + "\n", perm: 0600},
	}); err != nil {
		return err
	}

	// Enforce WAN exclusion on lldpd config at daemon boundary too
	if bundle.Enabled && bundle.Config.LLDP.Enabled && bundle.LLDP.Enabled {
		conf := bundle.LLDP.ConfContent
		if strings.TrimSpace(conf) == "" {
			conf = "# Auto-generated by Axonwall Topology Studio\nconfigure system interface pattern !wan*,*\n"
		}
		if !strings.Contains(conf, "!wan*") {
			conf = "configure system interface pattern !wan*\n" + conf
		}
		if err := os.MkdirAll(filepath.Dir(lldpdConfPath), 0755); err == nil {
			if err := writeFilesAtomic([]atomicFileWrite{
				{path: lldpdConfPath, content: conf, perm: 0644},
			}); err != nil {
				return fmt.Errorf("failed to write lldpd config %q: %w", lldpdConfPath, err)
			}
		}
		if m.svcRunner != nil {
			_ = m.svcRunner(context.Background(), "restart")
		} else if bin, lookErr := exec.LookPath("lldpd"); lookErr == nil && bin != "" {
			_ = exec.Command("systemctl", "reload-or-restart", "lldpd").Run()
		}
	} else {
		_ = removeFileIfExists(lldpdConfPath)
		if m.svcRunner != nil && !bundle.Enabled {
			_ = m.svcRunner(context.Background(), "stop")
		}
	}

	return nil
}

func (m *TopologyManager) loadBundleAndPeerTokens() (*TopologyRuntimeBundle, map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var bundle TopologyRuntimeBundle
	if raw, err := os.ReadFile(filepath.Join(m.configDir, "config.json")); err == nil {
		_ = json.Unmarshal(raw, &bundle)
	}
	tokens := map[string]string{}
	if rawSec, err := os.ReadFile(filepath.Join(m.configDir, "peers-secrets.json")); err == nil {
		_ = json.Unmarshal(rawSec, &tokens)
	}
	return &bundle, tokens
}

func readSysfsInt(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	return n
}

func readSysfsInt64(path string) int64 {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	return n
}

func (m *TopologyManager) readLLDPNeighbors(ctx context.Context) map[string][]HostNicLLDPNeighbor {
	outMap := map[string][]HostNicLLDPNeighbor{}
	var raw []byte
	var err error
	if m.lldpRunner != nil {
		raw, err = m.lldpRunner(ctx)
	} else if bin, lookErr := exec.LookPath("lldpctl"); lookErr == nil && bin != "" {
		cCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		raw, err = exec.CommandContext(cCtx, bin, "-f", "json").Output()
	} else {
		return outMap
	}
	if err != nil || len(raw) == 0 {
		return outMap
	}

	var parsed struct {
		LLDP struct {
			Interface []map[string]any `json:"interface"`
		} `json:"lldp"`
	}
	if json.Unmarshal(raw, &parsed) != nil {
		return outMap
	}
	for _, entry := range parsed.LLDP.Interface {
		for ifName, val := range entry {
			ifMap, ok := val.(map[string]any)
			if !ok {
				continue
			}
			chassisName := ""
			if ch, ok := ifMap["chassis"].(map[string]any); ok {
				for k, cv := range ch {
					if cObj, ok := cv.(map[string]any); ok {
						if name, ok := cObj["name"].(map[string]any); ok {
							chassisName, _ = name["value"].(string)
						}
						if chassisName == "" {
							chassisName = k
						}
						break
					}
					if k == "name" {
						chassisName, _ = cv.(string)
					}
				}
			}
			portID := ""
			portDescr := ""
			if pObj, ok := ifMap["port"].(map[string]any); ok {
				if idObj, ok := pObj["id"].(map[string]any); ok {
					portID, _ = idObj["value"].(string)
				}
				if dStr, ok := pObj["descr"].(string); ok {
					portDescr = dStr
				}
			}
			if chassisName != "" || portID != "" {
				outMap[ifName] = append(outMap[ifName], HostNicLLDPNeighbor{
					ChassisName: chassisName,
					PortID:      portID,
					PortDescr:   portDescr,
				})
			}
		}
	}
	return outMap
}

func (m *TopologyManager) readWireGuardTunnels(ctx context.Context, hostID string) []HostTunnelProbe {
	var tunnels []HostTunnelProbe
	var raw []byte
	var err error
	if m.wgRunner != nil {
		raw, err = m.wgRunner(ctx)
	} else if bin, lookErr := exec.LookPath("wg"); lookErr == nil && bin != "" {
		cCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		raw, err = exec.CommandContext(cCtx, bin, "show", "all", "dump").Output()
	} else {
		return tunnels
	}
	if err != nil || len(raw) == 0 {
		return tunnels
	}
	now := time.Now().Unix()
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) >= 8 { // peer line: iface, pubkey, psk, endpoint, allowedips, latest_handshake, rx, tx
			hs, _ := strconv.ParseInt(fields[5], 10, 64)
			var age int64
			up := false
			if hs > 0 {
				age = now - hs
				up = age >= 0 && age <= 180
			}
			tunnels = append(tunnels, HostTunnelProbe{
				HostID:          hostID,
				Name:            fields[0],
				Kind:            "wireguard",
				Up:              up,
				HandshakeAgeSec: age,
				PeerEndpoint:    fields[3],
			})
		}
	}
	return tunnels
}

func (m *TopologyManager) inspectK3sTopology(ctx context.Context) *K3sResourceProbeSnapshot {
	if m.k3sManager == nil {
		return nil
	}
	st := m.k3sManager.GetStatus()
	if !st.Enabled {
		return nil
	}
	snap := &K3sResourceProbeSnapshot{
		Available:       st.Running,
		Nodes:           []K3sProbeNode{},
		Ingresses:       []K3sProbeIngress{},
		Services:        []K3sProbeService{},
		Workloads:       []K3sProbeWorkload{},
		PVCs:            []K3sProbePVC{},
		NetworkPolicies: []K3sProbeNetworkPolicy{},
	}
	for _, n := range st.Nodes {
		snap.Nodes = append(snap.Nodes, K3sProbeNode{
			Name:          n.Name,
			Status:        n.Status,
			Roles:         n.Roles,
			InternalIP:    n.InternalIp,
			Unschedulable: n.Unschedulable,
		})
	}
	if !st.Running && m.kubectlRunner == nil {
		return snap
	}

	runK := func(args ...string) ([]byte, error) {
		kCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		return runPluginKubectl(kCtx, m.kubectlRunner, args...)
	}

	// Endpoints readiness count per namespace/name
	endpointReadyCount := map[string]int{}
	if epRaw, err := runK("get", "endpoints", "-A", "-o", "json"); err == nil {
		var epDoc struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
				Subsets []struct {
					Addresses []any `json:"addresses"`
				} `json:"subsets"`
			} `json:"items"`
		}
		if json.Unmarshal(epRaw, &epDoc) == nil {
			for _, ep := range epDoc.Items {
				cnt := 0
				for _, sub := range ep.Subsets {
					cnt += len(sub.Addresses)
				}
				endpointReadyCount[ep.Metadata.Namespace+"/"+ep.Metadata.Name] = cnt
			}
		}
	}

	// Services
	if svcRaw, err := runK("get", "services", "-A", "-o", "json"); err == nil {
		var svcDoc struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
				Spec struct {
					Type      string            `json:"type"`
					ClusterIP string            `json:"clusterIP"`
					Selector  map[string]string `json:"selector"`
					Ports     []struct {
						Port int `json:"port"`
					} `json:"ports"`
				} `json:"spec"`
			} `json:"items"`
		}
		if json.Unmarshal(svcRaw, &svcDoc) == nil {
			snap.Available = true
			for _, s := range svcDoc.Items {
				var ports []int
				for _, p := range s.Spec.Ports {
					if p.Port > 0 {
						ports = append(ports, p.Port)
					}
				}
				key := s.Metadata.Namespace + "/" + s.Metadata.Name
				snap.Services = append(snap.Services, K3sProbeService{
					Name:           s.Metadata.Name,
					Namespace:      s.Metadata.Namespace,
					Type:           s.Spec.Type,
					ClusterIP:      s.Spec.ClusterIP,
					Ports:          ports,
					ReadyEndpoints: endpointReadyCount[key],
					Selector:       s.Spec.Selector,
				})
			}
		}
	}

	// Standard Ingresses
	if ingRaw, err := runK("get", "ingress", "-A", "-o", "json"); err == nil {
		var ingDoc struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
				Spec struct {
					TLS []struct {
						SecretName string `json:"secretName"`
					} `json:"tls"`
					Rules []struct {
						Host string `json:"host"`
						HTTP struct {
							Paths []struct {
								Backend struct {
									Service struct {
										Name string `json:"name"`
										Port struct {
											Number int `json:"number"`
										} `json:"port"`
									} `json:"service"`
								} `json:"backend"`
							} `json:"paths"`
						} `json:"http"`
					} `json:"rules"`
				} `json:"spec"`
			} `json:"items"`
		}
		if json.Unmarshal(ingRaw, &ingDoc) == nil {
			for _, ing := range ingDoc.Items {
				var hosts []string
				var backends []K3sProbeBackendService
				var tlsSecs []string
				for _, t := range ing.Spec.TLS {
					if t.SecretName != "" {
						tlsSecs = append(tlsSecs, t.SecretName)
					}
				}
				for _, r := range ing.Spec.Rules {
					if r.Host != "" {
						hosts = append(hosts, r.Host)
					}
					for _, p := range r.HTTP.Paths {
						if p.Backend.Service.Name != "" {
							backends = append(backends, K3sProbeBackendService{
								Name: p.Backend.Service.Name,
								Port: p.Backend.Service.Port.Number,
							})
						}
					}
				}
				snap.Ingresses = append(snap.Ingresses, K3sProbeIngress{
					Kind:            "Ingress",
					Name:            ing.Metadata.Name,
					Namespace:       ing.Metadata.Namespace,
					Hosts:           hosts,
					BackendServices: backends,
					TLSSecretNames:  tlsSecs,
				})
			}
		}
	}

	// Workloads (Deployments + StatefulSets)
	for _, resKind := range []struct{ arg, label string }{{"deployments", "Deployment"}, {"statefulsets", "StatefulSet"}} {
		if wlRaw, err := runK("get", resKind.arg, "-A", "-o", "json"); err == nil {
			var wlDoc struct {
				Items []struct {
					Metadata struct {
						Name      string `json:"name"`
						Namespace string `json:"namespace"`
					} `json:"metadata"`
					Spec struct {
						Replicas int `json:"replicas"`
						Selector struct {
							MatchLabels map[string]string `json:"matchLabels"`
						} `json:"selector"`
					} `json:"spec"`
					Status struct {
						ReadyReplicas int `json:"readyReplicas"`
					} `json:"status"`
				} `json:"items"`
			}
			if json.Unmarshal(wlRaw, &wlDoc) == nil {
				for _, w := range wlDoc.Items {
					snap.Workloads = append(snap.Workloads, K3sProbeWorkload{
						Kind:            resKind.label,
						Name:            w.Metadata.Name,
						Namespace:       w.Metadata.Namespace,
						ReadyReplicas:   w.Status.ReadyReplicas,
						DesiredReplicas: w.Spec.Replicas,
						Selector:        w.Spec.Selector.MatchLabels,
					})
				}
			}
		}
	}

	// PVCs
	if pvcRaw, err := runK("get", "pvc", "-A", "-o", "json"); err == nil {
		var pvcDoc struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
				Spec struct {
					StorageClassName string `json:"storageClassName"`
				} `json:"spec"`
				Status struct {
					Phase    string            `json:"phase"`
					Capacity map[string]string `json:"capacity"`
				} `json:"status"`
			} `json:"items"`
		}
		if json.Unmarshal(pvcRaw, &pvcDoc) == nil {
			for _, p := range pvcDoc.Items {
				snap.PVCs = append(snap.PVCs, K3sProbePVC{
					Name:         p.Metadata.Name,
					Namespace:    p.Metadata.Namespace,
					StorageClass: p.Spec.StorageClassName,
					Capacity:     p.Status.Capacity["storage"],
					Bound:        strings.EqualFold(p.Status.Phase, "Bound"),
				})
			}
		}
	}

	// NetworkPolicies
	if npRaw, err := runK("get", "networkpolicies", "-A", "-o", "json"); err == nil {
		var npDoc struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if json.Unmarshal(npRaw, &npDoc) == nil {
			for _, n := range npDoc.Items {
				snap.NetworkPolicies = append(snap.NetworkPolicies, K3sProbeNetworkPolicy{
					Kind:      "NetworkPolicy",
					Name:      n.Metadata.Name,
					Namespace: n.Metadata.Namespace,
				})
			}
		}
	}

	// CRD auto-discovery: Traefik IngressRoute, Gateway API HTTPRoute, CiliumNetworkPolicy
	if irRaw, err := runK("get", "ingressroutes.traefik.io", "-A", "-o", "json"); err == nil {
		var irDoc struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
				Spec struct {
					Routes []struct {
						Match    string `json:"match"`
						Services []struct {
							Name string `json:"name"`
							Port int    `json:"port"`
						} `json:"services"`
					} `json:"routes"`
				} `json:"spec"`
			} `json:"items"`
		}
		if json.Unmarshal(irRaw, &irDoc) == nil {
			for _, ir := range irDoc.Items {
				var hosts []string
				var backends []K3sProbeBackendService
				for _, rt := range ir.Spec.Routes {
					if rt.Match != "" {
						hosts = append(hosts, rt.Match)
					}
					for _, s := range rt.Services {
						if s.Name != "" {
							backends = append(backends, K3sProbeBackendService{Name: s.Name, Port: s.Port})
						}
					}
				}
				snap.Ingresses = append(snap.Ingresses, K3sProbeIngress{
					Kind:            "IngressRoute",
					Name:            ir.Metadata.Name,
					Namespace:       ir.Metadata.Namespace,
					Hosts:           hosts,
					BackendServices: backends,
				})
			}
		}
	}

	if hrRaw, err := runK("get", "httproutes.gateway.networking.k8s.io", "-A", "-o", "json"); err == nil {
		var hrDoc struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
				Spec struct {
					Hostnames []string `json:"hostnames"`
					Rules     []struct {
						BackendRefs []struct {
							Name string `json:"name"`
							Port int    `json:"port"`
						} `json:"backendRefs"`
					} `json:"rules"`
				} `json:"spec"`
			} `json:"items"`
		}
		if json.Unmarshal(hrRaw, &hrDoc) == nil {
			for _, hr := range hrDoc.Items {
				var backends []K3sProbeBackendService
				for _, rule := range hr.Spec.Rules {
					for _, b := range rule.BackendRefs {
						if b.Name != "" {
							backends = append(backends, K3sProbeBackendService{Name: b.Name, Port: b.Port})
						}
					}
				}
				snap.Ingresses = append(snap.Ingresses, K3sProbeIngress{
					Kind:            "HTTPRoute",
					Name:            hr.Metadata.Name,
					Namespace:       hr.Metadata.Namespace,
					Hosts:           hr.Spec.Hostnames,
					BackendServices: backends,
				})
			}
		}
	}

	if cnpRaw, err := runK("get", "ciliumnetworkpolicies.cilium.io", "-A", "-o", "json"); err == nil {
		var cnpDoc struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if json.Unmarshal(cnpRaw, &cnpDoc) == nil {
			for _, cnp := range cnpDoc.Items {
				snap.NetworkPolicies = append(snap.NetworkPolicies, K3sProbeNetworkPolicy{
					Kind:      "CiliumNetworkPolicy",
					Name:      cnp.Metadata.Name,
					Namespace: cnp.Metadata.Namespace,
				})
			}
		}
	}

	return snap
}

func (m *TopologyManager) ProbeLocal(ctx context.Context) *LocalTopologyProbe {
	hostname, _ := os.Hostname()
	if strings.TrimSpace(hostname) == "" {
		hostname = "axonwall-local"
	}
	probe := &LocalTopologyProbe{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		LocalHostID:  hostname,
		NICs:         []HostNicProbe{},
		Tunnels:      m.readWireGuardTunnels(ctx, hostname),
		Transceivers: []OpticalModule{},
		VMs:          []VMStatus{},
		Containers:   []ContainerStatus{},
		K3s:          m.inspectK3sTopology(ctx),
	}

	domAlarmByIf := map[string]bool{}
	if m.hardwareManager != nil {
		if telem, err := m.hardwareManager.CollectTelemetry(); err == nil && telem != nil {
			probe.Transceivers = telem.Transceivers
			for _, opt := range telem.Transceivers {
				stLower := strings.ToLower(strings.TrimSpace(opt.Status))
				if stLower != "" && stLower != "ok" && stLower != "normal" && stLower != "healthy" {
					domAlarmByIf[opt.Interface] = true
				}
			}
		}
	}

	if m.virtManager != nil {
		probe.VMs = m.virtManager.ListVMs()
		probe.Containers = m.virtManager.ListContainers()
	}

	lldpNeighbors := m.readLLDPNeighbors(ctx)
	sysNet := m.sysfsNetDir
	if sysNet == "" {
		sysNet = "/sys/class/net"
	}

	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			if (ifc.Flags & net.FlagLoopback) != 0 {
				continue
			}
			adminUp := (ifc.Flags & net.FlagUp) != 0
			carrierPath := filepath.Join(sysNet, ifc.Name, "carrier")
			carrierUp := adminUp
			if raw, cErr := os.ReadFile(carrierPath); cErr == nil {
				carrierUp = strings.TrimSpace(string(raw)) == "1"
			}
			speed := readSysfsInt(filepath.Join(sysNet, ifc.Name, "speed"))
			if speed < 0 {
				speed = 0
			}
			rxErr := readSysfsInt64(filepath.Join(sysNet, ifc.Name, "statistics", "rx_errors"))
			txErr := readSysfsInt64(filepath.Join(sysNet, ifc.Name, "statistics", "tx_errors"))
			var ips []string
			if addrs, aErr := ifc.Addrs(); aErr == nil {
				for _, addr := range addrs {
					s := addr.String()
					if !strings.HasPrefix(s, "127.") && !strings.HasPrefix(s, "fe80:") {
						ips = append(ips, s)
					}
				}
			}
			probe.NICs = append(probe.NICs, HostNicProbe{
				HostID:        hostname,
				Device:        ifc.Name,
				Name:          ifc.Name,
				AdminUp:       adminUp,
				CarrierUp:     carrierUp,
				SpeedMbps:     speed,
				MTU:           ifc.MTU,
				MAC:           ifc.HardwareAddr.String(),
				IPv4Addresses: ips,
				DomAlarm:      domAlarmByIf[ifc.Name],
				RxErrors:      rxErr,
				TxErrors:      txErr,
				LLDPNeighbors: lldpNeighbors[ifc.Name],
			})
		}
	}

	return probe
}

func (m *TopologyManager) BuildPeerHTTPClient(peer TopologyPeerHostPayload) (*http.Client, error) {
	return m.buildPeerHTTPClient(peer)
}

func (m *TopologyManager) ListEnabledPeersWithTokens() ([]TopologyPeerHostPayload, map[string]string) {
	bundle, tokens := m.loadBundleAndPeerTokens()
	var peers []TopologyPeerHostPayload
	for _, p := range bundle.Config.Peers {
		if p.Enabled {
			peers = append(peers, p)
		}
	}
	return peers, tokens
}

func (m *TopologyManager) buildPeerHTTPClient(peer TopologyPeerHostPayload) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if peer.UseHaMtls && m.haTlsLoader != nil {
		haCfg, err := m.haTlsLoader()
		if err != nil {
			return nil, fmt.Errorf("HA mTLS config unavailable: %w", err)
		}
		tlsCfg = haCfg
	} else if strings.TrimSpace(peer.TLSCaCert) != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(peer.TLSCaCert)) {
			return nil, fmt.Errorf("invalid peer TLS CA certificate PEM")
		}
		tlsCfg.RootCAs = pool
	} else if pin := strings.TrimSpace(peer.TLSCertSha256); pin != "" {
		normPin := strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(strings.ToLower(pin), "sha256:"), ":", ""))
		// Strict pinned fingerprint check: disable default hostname CA chain ONLY while verifying exact leaf SHA-256
		tlsCfg.InsecureSkipVerify = true // #nosec G402 -- verified immediately by explicit SHA-256 certificate pin below
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("peer presented no TLS certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			if got != normPin {
				return fmt.Errorf("peer TLS certificate SHA-256 mismatch (got %s, expected %s)", got, normPin)
			}
			return nil
		}
	}
	m.mu.Lock()
	allowLoopback := m.allowLoopbackPeers
	m.mu.Unlock()
	client, _ := newSafeHTTPClient(SafeHTTPClientOptions{
		Timeout:         5 * time.Second,
		AllowLoopback:   allowLoopback,
		TLSClientConfig: tlsCfg,
	})
	return client, nil
}

func (m *TopologyManager) ProbeFabric(ctx context.Context) *TopologyFabricSnapshot {
	bundle, peerTokens := m.loadBundleAndPeerTokens()
	snap := &TopologyFabricSnapshot{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Peers:     make([]PeerHostProbeResult, 0, len(bundle.Config.Peers)),
		Config:    &bundle.Config,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		snap.Local = m.ProbeLocal(ctx)
	}()

	if m.librenmsManager != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snap.LibreNMS = m.librenmsManager.GetTopologySnapshot(ctx)
		}()
	}

	if m.netboxManager != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snap.NetBox = m.netboxManager.ExportInventory(ctx)
		}()
	}

	m.mu.Lock()
	nfm := m.netflowManager
	m.mu.Unlock()
	if nfm != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snap.NetFlow = nfm.GetTopologyOverlay()
		}()
	}

	peerResults := make([]PeerHostProbeResult, len(bundle.Config.Peers))
	for i, peer := range bundle.Config.Peers {
		if !peer.Enabled {
			peerResults[i] = PeerHostProbeResult{
				PeerID:    peer.ID,
				Name:      peer.Name,
				Role:      peer.Role,
				Reachable: false,
				Error:     "Disabled in topology.yaml",
				NICs:      []HostNicProbe{},
				Tunnels:   []HostTunnelProbe{},
			}
			continue
		}
		wg.Add(1)
		go func(idx int, p TopologyPeerHostPayload) {
			defer wg.Done()
			res := PeerHostProbeResult{
				PeerID:  p.ID,
				Name:    p.Name,
				Role:    p.Role,
				NICs:    []HostNicProbe{},
				Tunnels: []HostTunnelProbe{},
			}
			validURL, urlErr := validatePluginHTTPURL(p.APIURL, "peer "+p.Name)
			if urlErr != nil {
				res.Error = urlErr.Error()
				peerResults[idx] = res
				return
			}
			client, cliErr := m.buildPeerHTTPClient(p)
			if cliErr != nil {
				res.Error = cliErr.Error()
				peerResults[idx] = res
				return
			}
			pCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(pCtx, http.MethodGet, validURL+"/api/v1/topology/probe", nil)
			if err != nil {
				res.Error = err.Error()
				peerResults[idx] = res
				return
			}
			if tok := peerTokens[p.ID]; tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			resp, err := client.Do(req)
			if err != nil {
				res.Error = err.Error()
				peerResults[idx] = res
				return
			}
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				res.AuthError = fmt.Sprintf("HTTP %d unauthorized probing %s", resp.StatusCode, p.Name)
				peerResults[idx] = res
				return
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				res.Error = fmt.Sprintf("HTTP %d from %s", resp.StatusCode, p.Name)
				peerResults[idx] = res
				return
			}
			var envelope struct {
				Data *LocalTopologyProbe `json:"data"`
			}
			if json.Unmarshal(bodyBytes, &envelope) == nil && envelope.Data != nil {
				res.Reachable = true
				res.NICs = envelope.Data.NICs
				res.Tunnels = envelope.Data.Tunnels
			} else {
				var direct LocalTopologyProbe
				if json.Unmarshal(bodyBytes, &direct) == nil && direct.LocalHostID != "" {
					res.Reachable = true
					res.NICs = direct.NICs
					res.Tunnels = direct.Tunnels
				} else {
					res.Error = "Unexpected probe response shape"
				}
			}
			peerResults[idx] = res
		}(i, peer)
	}

	wg.Wait()
	snap.Peers = peerResults
	return snap
}

func parseJSONObject(raw json.RawMessage) (map[string]any, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("expected JSON object")
	}
	var obj map[string]any
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, fmt.Errorf("expected non-null JSON object")
	}
	return obj, nil
}

func deepMergeJSONMaps(base, patch map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(patch))
	for k, v := range base {
		out[k] = v
	}
	for k, pv := range patch {
		if pv == nil {
			delete(out, k)
			continue
		}
		if patchSub, ok := pv.(map[string]any); ok {
			if baseSub, ok2 := out[k].(map[string]any); ok2 {
				out[k] = deepMergeJSONMaps(baseSub, patchSub)
				continue
			}
		}
		out[k] = pv
	}
	return out
}

func validatePeerEdit(pEdit TopologyPeerEdit) (isTargeted bool, err error) {
	hasState := len(bytes.TrimSpace(pEdit.State)) > 0
	hasPatch := len(bytes.TrimSpace(pEdit.Patch)) > 0
	hostname := strings.TrimSpace(pEdit.Hostname)
	hasHostname := hostname != ""

	if !hasState && !hasPatch && !hasHostname {
		return false, fmt.Errorf("peer edit for %q must specify state, patch, or hostname", pEdit.PeerID)
	}
	if hasState && (hasPatch || hasHostname) {
		return false, fmt.Errorf("peer edit for %q cannot combine full state overwrite with targeted patch/hostname", pEdit.PeerID)
	}
	if hasState {
		if _, err := parseJSONObject(pEdit.State); err != nil {
			return false, fmt.Errorf("invalid state JSON for peer %q: %w", pEdit.PeerID, err)
		}
		return false, nil
	}
	if hasPatch {
		if _, err := parseJSONObject(pEdit.Patch); err != nil {
			return true, fmt.Errorf("invalid patch JSON for peer %q: %w", pEdit.PeerID, err)
		}
	}
	if hasHostname {
		if len(hostname) > 253 || strings.ContainsAny(hostname, " \t\r\n/\\") {
			return true, fmt.Errorf("invalid target hostname %q for peer %q", hostname, pEdit.PeerID)
		}
	}
	return true, nil
}

// ApplyFabricPlan executes preflight dry-run validation, Phase 2 K3s & peer applies, and rollback on failure.
func (m *TopologyManager) ApplyFabricPlan(
	ctx context.Context,
	req *TopologyApplyRequest,
	localApplyFn func(context.Context, int) error,
) (*TopologyApplyResult, error) {
	if req == nil {
		req = &TopologyApplyRequest{}
	}
	timeout := req.ConfirmTimeoutSeconds
	if timeout < 10 {
		timeout = 120
	}
	if timeout > 3600 {
		timeout = 3600
	}

	bundle, peerTokens := m.loadBundleAndPeerTokens()
	peerMap := map[string]TopologyPeerHostPayload{}
	for _, p := range bundle.Config.Peers {
		peerMap[p.ID] = p
	}

	res := &TopologyApplyResult{
		Success:               true,
		DryRun:                req.DryRun,
		Timestamp:             time.Now().UTC().Format(time.RFC3339),
		ConfirmTimeoutSeconds: timeout,
		Results:               []TopologyApplyTargetResult{},
	}

	// Phase 1: Dry-run validation across all targets
	for _, kEdit := range req.K3sEdits {
		if kEdit.ManifestYAML != "" {
			if err := validateK3sManifest(kEdit.ManifestYAML); err != nil {
				res.Success = false
				res.Error = err.Error()
				res.Results = append(res.Results, TopologyApplyTargetResult{
					Phase:      1,
					TargetType: "k3s",
					TargetID:   kEdit.Name,
					Success:    false,
					Error:      err.Error(),
				})
				return res, err
			}
			if m.k3sManager != nil && (req.DryRun || m.kubectlRunner != nil) {
				if dryResp, dErr := m.k3sManager.ExecuteK3sAction(ctx, K3sActionRequest{
					Action: "apply-yaml",
					Yaml:   kEdit.ManifestYAML,
					DryRun: true,
				}); dErr != nil || (dryResp != nil && !dryResp.Success) {
					msg := ""
					if dErr != nil {
						msg = dErr.Error()
					} else if dryResp != nil {
						msg = dryResp.Message
					}
					res.Success = false
					res.Error = msg
					res.Results = append(res.Results, TopologyApplyTargetResult{
						Phase:      1,
						TargetType: "k3s",
						TargetID:   kEdit.Name,
						Success:    false,
						Error:      msg,
					})
					return res, fmt.Errorf("K3s dry-run failed for %s: %s", kEdit.Name, msg)
				}
			}
		}
		res.Results = append(res.Results, TopologyApplyTargetResult{
			Phase:      1,
			TargetType: "k3s",
			TargetID:   kEdit.Name,
			Success:    true,
			Message:    "Validated K3s mutation",
		})
	}

	for _, pEdit := range req.PeerEdits {
		peer, ok := peerMap[pEdit.PeerID]
		if !ok {
			err := fmt.Errorf("unknown peer host %q", pEdit.PeerID)
			res.Success = false
			res.Error = err.Error()
			return res, err
		}
		if _, editErr := validatePeerEdit(pEdit); editErr != nil {
			res.Success = false
			res.Error = editErr.Error()
			return res, editErr
		}
		if _, urlErr := validatePluginHTTPURL(peer.APIURL, "peer "+peer.Name); urlErr != nil {
			res.Success = false
			res.Error = urlErr.Error()
			return res, urlErr
		}
		if _, cliErr := m.buildPeerHTTPClient(peer); cliErr != nil {
			res.Success = false
			res.Error = cliErr.Error()
			return res, cliErr
		}
		res.Results = append(res.Results, TopologyApplyTargetResult{
			Phase:      1,
			TargetType: "peer",
			TargetID:   pEdit.PeerID,
			Success:    true,
			Message:    "Preflight validated peer TLS, endpoint & edit payload",
		})
	}

	if req.HasLocalChanges {
		res.Results = append(res.Results, TopologyApplyTargetResult{
			Phase:      1,
			TargetType: "local",
			TargetID:   "local-appliance",
			Success:    true,
			Message:    "Local DesiredState validated",
		})
	}

	if req.DryRun {
		return res, nil
	}

	// Track applied peers so failures trigger rollback
	type appliedPeerHandle struct {
		peer  TopologyPeerHostPayload
		token string
	}
	var appliedPeers []appliedPeerHandle

	rollbackAppliedPeers := func() {
		for _, ap := range appliedPeers {
			client, err := m.buildPeerHTTPClient(ap.peer)
			if err != nil {
				continue
			}
			validURL, _ := validatePluginHTTPURL(ap.peer.APIURL, ap.peer.Name)
			rbReq, err := http.NewRequestWithContext(ctx, http.MethodPost, validURL+"/api/v1/rollback", bytes.NewReader([]byte("{}")))
			if err != nil {
				continue
			}
			rbReq.Header.Set("Content-Type", "application/json")
			if ap.token != "" {
				rbReq.Header.Set("Authorization", "Bearer "+ap.token)
			}
			if rbResp, rbErr := client.Do(rbReq); rbErr == nil {
				_ = rbResp.Body.Close()
				res.RolledBackAny = true
			}
		}
	}

	// Phase 2: K3s & Remote Peer Hosts
	for _, kEdit := range req.K3sEdits {
		if m.k3sManager == nil {
			continue
		}
		if kEdit.ManifestYAML != "" {
			resp, err := m.k3sManager.ExecuteK3sAction(ctx, K3sActionRequest{
				Action: "apply-yaml",
				Yaml:   kEdit.ManifestYAML,
			})
			if err != nil || (resp != nil && !resp.Success) {
				rollbackAppliedPeers()
				msg := ""
				if err != nil {
					msg = err.Error()
				} else if resp != nil {
					msg = resp.Message
				}
				res.Success = false
				res.Error = msg
				res.Results = append(res.Results, TopologyApplyTargetResult{
					Phase:      2,
					TargetType: "k3s",
					TargetID:   kEdit.Name,
					Success:    false,
					Error:      msg,
				})
				return res, fmt.Errorf("K3s apply failed for %s: %s", kEdit.Name, msg)
			}
		} else if kEdit.ScaleReplicas != nil {
			resp, err := m.k3sManager.ExecuteK3sAction(ctx, K3sActionRequest{
				Action:    "scale",
				Resource:  strings.ToLower(kEdit.Kind),
				Name:      kEdit.Name,
				Namespace: kEdit.Namespace,
				Replicas:  kEdit.ScaleReplicas,
			})
			if err != nil || (resp != nil && !resp.Success) {
				rollbackAppliedPeers()
				msg := fmt.Sprintf("%v", err)
				if resp != nil && resp.Message != "" {
					msg = resp.Message
				}
				res.Success = false
				res.Error = msg
				return res, fmt.Errorf("K3s scale failed for %s: %s", kEdit.Name, msg)
			}
		} else if len(kEdit.NodeRoles) > 0 && strings.EqualFold(kEdit.Kind, "Node") {
			if _, err := m.k3sManager.UpdateNodeScheduling(K3sNodeUpdateRequest{
				NodeName: kEdit.Name,
				Roles:    kEdit.NodeRoles,
			}); err != nil {
				rollbackAppliedPeers()
				res.Success = false
				res.Error = err.Error()
				return res, err
			}
		}
		res.Results = append(res.Results, TopologyApplyTargetResult{
			Phase:      2,
			TargetType: "k3s",
			TargetID:   kEdit.Name,
			Success:    true,
			Message:    "Applied K3s edit",
		})
	}

	for _, pEdit := range req.PeerEdits {
		peer := peerMap[pEdit.PeerID]
		validURL, _ := validatePluginHTTPURL(peer.APIURL, peer.Name)
		client, _ := m.buildPeerHTTPClient(peer)
		tok := peerTokens[peer.ID]

		isTargeted, _ := validatePeerEdit(pEdit)
		var statePayload json.RawMessage
		if isTargeted {
			stateReq, err := http.NewRequestWithContext(ctx, http.MethodGet, validURL+"/api/v1/state", nil)
			if err != nil {
				rollbackAppliedPeers()
				res.Success = false
				res.Error = err.Error()
				return res, err
			}
			if tok != "" {
				stateReq.Header.Set("Authorization", "Bearer "+tok)
			}
			stateResp, err := client.Do(stateReq)
			if err != nil || stateResp.StatusCode < 200 || stateResp.StatusCode >= 300 {
				if stateResp != nil {
					_ = stateResp.Body.Close()
				}
				rollbackAppliedPeers()
				msg := ""
				if err != nil {
					msg = err.Error()
				} else {
					msg = fmt.Sprintf("peer %s /api/v1/state returned HTTP %d", peer.Name, stateResp.StatusCode)
				}
				res.Success = false
				res.Error = msg
				res.Results = append(res.Results, TopologyApplyTargetResult{
					Phase:      2,
					TargetType: "peer",
					TargetID:   peer.ID,
					Success:    false,
					Error:      msg,
				})
				return res, fmt.Errorf("peer state fetch failed (%s): %s", peer.Name, msg)
			}
			rawState, readErr := io.ReadAll(io.LimitReader(stateResp.Body, 8<<20))
			_ = stateResp.Body.Close()
			if readErr != nil {
				rollbackAppliedPeers()
				res.Success = false
				res.Error = readErr.Error()
				return res, readErr
			}
			baseObj, parseErr := parseJSONObject(rawState)
			if parseErr != nil {
				rollbackAppliedPeers()
				msg := fmt.Sprintf("invalid peer %s /api/v1/state JSON: %v", peer.Name, parseErr)
				res.Success = false
				res.Error = msg
				return res, fmt.Errorf("%s", msg)
			}
			patchObj := map[string]any{}
			if len(bytes.TrimSpace(pEdit.Patch)) > 0 {
				patchObj, _ = parseJSONObject(pEdit.Patch)
			}
			if h := strings.TrimSpace(pEdit.Hostname); h != "" {
				patchObj = deepMergeJSONMaps(patchObj, map[string]any{
					"system": map[string]any{"hostname": h},
				})
			}
			merged := deepMergeJSONMaps(baseObj, patchObj)
			mergedBytes, mErr := json.Marshal(merged)
			if mErr != nil {
				rollbackAppliedPeers()
				res.Success = false
				res.Error = mErr.Error()
				return res, mErr
			}
			statePayload = json.RawMessage(mergedBytes)
		} else {
			statePayload = pEdit.State
		}

		bodyBytes, _ := json.Marshal(map[string]any{
			"confirmTimeoutSeconds": timeout,
			"state":                 statePayload,
		})
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, validURL+"/api/v1/apply", bytes.NewReader(bodyBytes))
		if err != nil {
			rollbackAppliedPeers()
			res.Success = false
			res.Error = err.Error()
			return res, err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		if tok != "" {
			httpReq.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := client.Do(httpReq)
		if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if resp != nil {
				_ = resp.Body.Close()
			}
			rollbackAppliedPeers()
			msg := ""
			if err != nil {
				msg = err.Error()
			} else {
				msg = fmt.Sprintf("peer %s returned HTTP %d", peer.Name, resp.StatusCode)
			}
			res.Success = false
			res.Error = msg
			res.Results = append(res.Results, TopologyApplyTargetResult{
				Phase:      2,
				TargetType: "peer",
				TargetID:   peer.ID,
				Success:    false,
				Error:      msg,
			})
			return res, fmt.Errorf("peer apply failed (%s): %s", peer.Name, msg)
		}
		_ = resp.Body.Close()
		appliedPeers = append(appliedPeers, appliedPeerHandle{peer: peer, token: tok})
		applyKind := "full state"
		if isTargeted {
			applyKind = "targeted update"
		}
		res.Results = append(res.Results, TopologyApplyTargetResult{
			Phase:      2,
			TargetType: "peer",
			TargetID:   peer.ID,
			Success:    true,
			Message:    fmt.Sprintf("Applied %s on peer %s (confirm timer %ds)", applyKind, peer.Name, timeout),
		})
	}

	// Phase 3: Local Edge Firewall apply last + peer confirm
	if req.HasLocalChanges && localApplyFn != nil {
		if err := localApplyFn(ctx, timeout); err != nil {
			rollbackAppliedPeers()
			res.Success = false
			res.Error = err.Error()
			res.Results = append(res.Results, TopologyApplyTargetResult{
				Phase:      3,
				TargetType: "local",
				TargetID:   "local-appliance",
				Success:    false,
				Error:      err.Error(),
			})
			return res, err
		}
		res.Results = append(res.Results, TopologyApplyTargetResult{
			Phase:      3,
			TargetType: "local",
			TargetID:   "local-appliance",
			Success:    true,
			Message:    fmt.Sprintf("Local firewall applied with %ds rollback guard", timeout),
		})
	}

	// Auto-confirm applied peers ONLY when:
	// - Phase 3 ran in-process and succeeded (HasLocalChanges && localApplyFn != nil), OR
	// - HasLocalChanges is false AND AutoConfirmPeers was explicitly requested.
	// When HasLocalChanges is false without explicit AutoConfirmPeers, peers
	// retain their Commit-Confirm rollback timer so remote full-state overwrites
	// or unverified updates cannot silently cause permanent lockout.
	shouldAutoConfirm := (req.HasLocalChanges && localApplyFn != nil) || (!req.HasLocalChanges && req.AutoConfirmPeers)
	if shouldAutoConfirm {
		for _, ap := range appliedPeers {
			client, err := m.buildPeerHTTPClient(ap.peer)
			if err != nil {
				continue
			}
			validURL, _ := validatePluginHTTPURL(ap.peer.APIURL, ap.peer.Name)
			cReq, err := http.NewRequestWithContext(ctx, http.MethodPost, validURL+"/api/v1/confirm", bytes.NewReader([]byte("{}")))
			if err != nil {
				continue
			}
			cReq.Header.Set("Content-Type", "application/json")
			if ap.token != "" {
				cReq.Header.Set("Authorization", "Bearer "+ap.token)
			}
			if cResp, cErr := client.Do(cReq); cErr == nil {
				_ = cResp.Body.Close()
			}
		}
	}

	slog.Info("Completed phased Topology Studio fabric apply", "targets", len(res.Results))
	return res, nil
}
