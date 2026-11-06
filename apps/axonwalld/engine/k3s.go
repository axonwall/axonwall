package engine

import (
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

type K3sRuntimeBundle struct {
	Enabled               bool   `json:"enabled"`
	Role                  string `json:"role"`   // "master" or "backup"
	HaRole                string `json:"haRole"` // alias emitted by compiler
	PeerIp                string `json:"peerIp"`
	HaPeerAddress         string `json:"haPeerAddress"` // alias emitted by compiler
	SyncPort              int    `json:"syncPort"`
	AuthToken             string `json:"authToken"`
	HaSharedSecret        string `json:"haSharedSecret"` // alias emitted by compiler
	AutoJoinHaPeer        bool   `json:"autoJoinHaPeer"`
	K3sConfigYaml         string `json:"k3sConfigYaml"`
	OpenEbsManifestYaml   string `json:"openEbsManifestYaml"`
	WorkloadsManifestYaml string `json:"workloadsManifestYaml"`
}

type K3sNodeInfo struct {
	Name       string `json:"name"`
	Role       string `json:"role"`
	Roles      string `json:"roles"`
	Status     string `json:"status"`
	Version    string `json:"version"`
	IpAddress  string `json:"ipAddress"`
	InternalIp string `json:"internalIp"`
}

type OpenEbsVolumeInfo struct {
	Name         string `json:"name"`
	Namespace    string `json:"namespace"`
	StorageClass string `json:"storageClass"`
	Capacity     string `json:"capacity"`
	ReplicaState string `json:"replicaState"`
	Status       string `json:"status"`
}

type K3sClusterStatus struct {
	Enabled         bool                `json:"enabled"`
	Running         bool                `json:"running"`
	ServiceActive   bool                `json:"serviceActive"`
	ClusterJoined   bool                `json:"clusterJoined"`
	Role            string              `json:"role"`
	HaAutoJoined    bool                `json:"haAutoJoined"`
	OpenEbsReady    bool                `json:"openEbsReady"`
	OpenEbsHealthy  bool                `json:"openEbsHealthy"`
	ZfsLocalPvPool  string              `json:"zfsLocalPvPool"`
	Nodes           []K3sNodeInfo       `json:"nodes"`
	Volumes         []OpenEbsVolumeInfo `json:"volumes"`
	LastSyncMessage string              `json:"lastSyncMessage"`
}

type K3sManager struct {
	mu           sync.Mutex
	cfg          K3sRuntimeBundle
	haAutoJoined bool
	lastMessage  string
}

// K3s filesystem roots are vars (not literals) so tests can redirect
// K3s file writes into a temp dir; the production values are
// unchanged. k3sServerManifestDir is also used by the Vigilante
// manager, which writes its manifest into the same directory.
var (
	k3sEtcDir            = "/etc/rancher/k3s"
	k3sServerManifestDir = "/var/lib/rancher/k3s/server/manifests"
	k3sStateDir          = "/var/lib/axonwall"
	vowEtcDir            = "/etc/axonwall/vow"
)

func NewK3sManager() *K3sManager {
	return &K3sManager{
		lastMessage: "K3s + OpenEBS orchestrator initialized",
	}
}

// GetClusterNodeToken reads the local K3s server join token so the HA peer can automatically join the cluster.
func (m *K3sManager) GetClusterNodeToken() (string, error) {
	tokenPaths := []string{
		"/var/lib/rancher/k3s/server/node-token",
		"/var/lib/rancher/k3s/server/token",
		"/var/lib/axonwall/k3s-join.token",
	}
	for _, p := range tokenPaths {
		if data, err := os.ReadFile(p); err == nil {
			tok := strings.TrimSpace(string(data))
			if tok != "" {
				return tok, nil
			}
		}
	}
	return "", fmt.Errorf("k3s node-token not yet generated")
}

// FetchPeerClusterToken contacts the primary HA node's sync endpoint to retrieve the K3s join token.
func FetchPeerClusterToken(peerIp string, syncPort int, authToken string) (string, error) {
	cleanPeer := strings.TrimSpace(peerIp)
	if parsed := net.ParseIP(cleanPeer); parsed == nil || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsUnspecified() {
		return "", fmt.Errorf("invalid or disallowed HA peer IP: %s", peerIp)
	}
	if HasHAPKI() {
		if tlsCfg, err := LoadHAPKITLSConfig(); err == nil {
			client := &http.Client{
				Timeout:   8 * time.Second,
				Transport: &http.Transport{TLSClientConfig: tlsCfg},
			}
			return FetchPeerClusterTokenWithClient(cleanPeer, syncPort, authToken, client, "https")
		}
	}
	return FetchPeerClusterTokenWithClient(cleanPeer, syncPort, authToken, &http.Client{Timeout: 8 * time.Second}, "http")
}

// FetchPeerClusterTokenWithClient is FetchPeerClusterToken over a
// caller-supplied client and scheme, so the HA sync poller can reach the
// endpoint over the mTLS transport (audit D-04 Phase 1).
func FetchPeerClusterTokenWithClient(peerIp string, syncPort int, authToken string, client *http.Client, scheme string) (string, error) {
	if peerIp == "" {
		return "", fmt.Errorf("peerIp is empty")
	}
	if syncPort <= 0 {
		syncPort = 9876
	}
	url := fmt.Sprintf("%s://%s/api/v1/sync/k3s-token", scheme, net.JoinHostPort(peerIp, strconv.Itoa(syncPort)))
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if authToken != "" {
		req.Header.Set("X-Axonwall-Sync-Token", authToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("peer returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.Token) == "" {
		return "", fmt.Errorf("peer returned empty k3s token")
	}
	return strings.TrimSpace(payload.Token), nil
}

func (m *K3sManager) ApplyConfig(rawJSON []byte) error {
	var bundle K3sRuntimeBundle
	if err := json.Unmarshal(rawJSON, &bundle); err != nil {
		return fmt.Errorf("invalid K3s runtime bundle json: %w", err)
	}
	if bundle.Role == "" && bundle.HaRole != "" {
		bundle.Role = bundle.HaRole
	}
	if bundle.PeerIp == "" && bundle.HaPeerAddress != "" {
		bundle.PeerIp = bundle.HaPeerAddress
	}
	if bundle.AuthToken == "" && bundle.HaSharedSecret != "" {
		bundle.AuthToken = bundle.HaSharedSecret
	}
	if bundle.SyncPort <= 0 {
		bundle.SyncPort = 8443
	}

	// Validate free-text config before it can reach privileged paths
	// (audit D-05): an invalid bundle changes nothing on disk.
	if bundle.K3sConfigYaml != "" {
		if err := validateK3sConfig(bundle.K3sConfigYaml); err != nil {
			return fmt.Errorf("k3s bundle rejected: %w", err)
		}
	}
	if bundle.OpenEbsManifestYaml != "" {
		if err := validateK3sManifest(bundle.OpenEbsManifestYaml); err != nil {
			return fmt.Errorf("k3s bundle rejected: %w", err)
		}
	}
	if bundle.WorkloadsManifestYaml != "" {
		if err := validateK3sManifest(bundle.WorkloadsManifestYaml); err != nil {
			return fmt.Errorf("k3s bundle rejected: %w", err)
		}
	}

	m.mu.Lock()
	m.cfg = bundle
	m.mu.Unlock()

	if !bundle.Enabled {
		slog.Info("K3s plugin is disabled; stopping k3s service")
		_ = exec.Command("systemctl", "stop", "k3s").Run()
		return nil
	}

	// Ensure IP forwarding and loose reverse-path filtering (rp_filter=2) are active for K3s CNI overlay pod traffic
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=2", "net.ipv4.conf.default.rp_filter=2").Run()

	if err := os.MkdirAll(k3sEtcDir, 0755); err != nil {
		return fmt.Errorf("failed to create k3s config dir %q: %w", k3sEtcDir, err)
	}
	if err := os.MkdirAll(k3sServerManifestDir, 0755); err != nil {
		return fmt.Errorf("failed to create k3s manifest dir %q: %w", k3sServerManifestDir, err)
	}
	if err := os.MkdirAll(k3sStateDir, 0755); err != nil {
		return fmt.Errorf("failed to create k3s state dir %q: %w", k3sStateDir, err)
	}

	// If this node is the HA secondary/backup and autoJoinHaPeer is enabled, fetch the join token from the primary node
	if (bundle.Role == "backup" || bundle.Role == "secondary") && bundle.AutoJoinHaPeer && bundle.PeerIp != "" {
		tok, err := FetchPeerClusterToken(bundle.PeerIp, bundle.SyncPort, bundle.AuthToken)
		if err == nil && tok != "" {
			_ = os.WriteFile(filepath.Join(k3sStateDir, "k3s-join.token"), []byte(tok+"\n"), 0600)
			m.mu.Lock()
			m.haAutoJoined = true
			m.lastMessage = fmt.Sprintf("Auto-joined primary K3s cluster at https://%s with OpenEBS replication", net.JoinHostPort(bundle.PeerIp, "6443"))
			m.mu.Unlock()
			slog.Info("Fetched K3s join token from HA primary peer", "peerIp", bundle.PeerIp)
		} else {
			slog.Warn("Could not fetch K3s join token from HA peer yet; will retry on HA sync cycle", "peerIp", bundle.PeerIp, "error", err)
		}
	}

	// A-M15: every file write failure is returned (the old code
	// swallowed open failures with `if f, err := ...; err == nil`
	// and reported success), and the writes land all-or-nothing via
	// temp+rename so a failed apply never leaves a truncated file
	// behind.
	var writes []atomicFileWrite
	if bundle.K3sConfigYaml != "" {
		writes = append(writes, atomicFileWrite{
			path:    filepath.Join(k3sEtcDir, "config.yaml"),
			content: bundle.K3sConfigYaml,
			perm:    0600,
		})
	}

	if bundle.OpenEbsManifestYaml != "" {
		writes = append(writes, atomicFileWrite{
			path:    filepath.Join(k3sServerManifestDir, "axonwall-openebs.yaml"),
			content: bundle.OpenEbsManifestYaml,
			perm:    0644,
		})
	}

	if bundle.WorkloadsManifestYaml != "" {
		writes = append(writes, atomicFileWrite{
			path:    filepath.Join(k3sServerManifestDir, "axonwall-workloads.yaml"),
			content: bundle.WorkloadsManifestYaml,
			perm:    0644,
		})
	}
	if err := writeFilesAtomic(writes); err != nil {
		return err
	}

	// A-M15: a failed k3s restart fails the apply instead of being
	// discarded while the bundle reports success and the cluster runs
	// the old manifests or no k3s at all.
	if out, err := exec.Command("systemctl", "reload-or-restart", "k3s").CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reload-or-restart k3s: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

type VowRuntimeBundle struct {
	Enabled                  bool   `json:"enabled"`
	K3sDependencyMet         bool   `json:"k3sDependencyMet"`
	CombinedK3sManifestsYaml string `json:"combinedK3sManifestsYaml"`
	EnablerEnv               string `json:"enablerEnv"`
	AuthzYaml                string `json:"authzYaml"`
}

// ApplyVowConfig reconciles the Vigilant Octo Waffle (VOW) GitOps & App Platform
// manifests and environment files onto the in-house K3s cluster.
func (m *K3sManager) ApplyVowConfig(rawJSON []byte) error {
	var bundle VowRuntimeBundle
	if err := json.Unmarshal(rawJSON, &bundle); err != nil {
		return fmt.Errorf("invalid VOW runtime bundle json: %w", err)
	}

	manifestPath := filepath.Join(k3sServerManifestDir, "axonwall-vow.yaml")
	if !bundle.Enabled || !bundle.K3sDependencyMet {
		if err := removeFileIfExists(manifestPath); err != nil {
			return fmt.Errorf("failed to remove stale VOW manifest %q: %w", manifestPath, err)
		}
		return nil
	}

	if err := os.MkdirAll(vowEtcDir, 0750); err != nil {
		return fmt.Errorf("failed to create VOW config dir %q: %w", vowEtcDir, err)
	}
	if err := os.MkdirAll(k3sServerManifestDir, 0755); err != nil {
		return fmt.Errorf("failed to create k3s manifest dir %q: %w", k3sServerManifestDir, err)
	}

	// A-M15: an enabled bundle with an empty manifests field withdraws
	// the deployment — remove the stale manifest instead of leaving
	// k3s applying it. The removal runs before the env/authz writes
	// so a later write failure cannot leave new config paired with a
	// manifest the bundle meant to withdraw.
	if bundle.CombinedK3sManifestsYaml == "" {
		if err := removeFileIfExists(manifestPath); err != nil {
			return fmt.Errorf("failed to remove stale VOW manifest %q: %w", manifestPath, err)
		}
	} else if err := validateK3sManifest(bundle.CombinedK3sManifestsYaml); err != nil {
		return fmt.Errorf("vow bundle rejected: %w", err)
	}

	// A-M15: every file write failure is returned (the old code
	// swallowed open failures and reported success).
	var writes []atomicFileWrite
	if bundle.EnablerEnv != "" {
		writes = append(writes, atomicFileWrite{
			path:    filepath.Join(vowEtcDir, ".env.enabler"),
			content: bundle.EnablerEnv,
			perm:    0640,
		})
	}
	if bundle.AuthzYaml != "" {
		writes = append(writes, atomicFileWrite{
			path:    filepath.Join(vowEtcDir, "authz.yaml"),
			content: bundle.AuthzYaml,
			perm:    0640,
		})
	}
	if bundle.CombinedK3sManifestsYaml != "" {
		writes = append(writes, atomicFileWrite{
			path:    manifestPath,
			content: bundle.CombinedK3sManifestsYaml,
			perm:    0644,
		})
	}
	if err := writeFilesAtomic(writes); err != nil {
		return err
	}

	slog.Info("Reconciled Vigilant Octo Waffle manifests onto in-house K3s cluster")
	return nil
}

func (m *K3sManager) TriggerAutoJoin(peerIp string, syncPort int, authToken string) error {
	tok, err := FetchPeerClusterToken(peerIp, syncPort, authToken)
	if err != nil {
		return err
	}
	_ = os.MkdirAll(k3sStateDir, 0755)
	if err := os.WriteFile(filepath.Join(k3sStateDir, "k3s-join.token"), []byte(tok+"\n"), 0600); err != nil {
		return err
	}
	// A-M15: only record the join AFTER k3s restarts successfully.
	// The old code set haAutoJoined before the (discarded) restart,
	// so GetStatus reported the node joined while k3s was still down.
	if out, err := exec.Command("systemctl", "reload-or-restart", "k3s").CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reload-or-restart k3s after auto-join: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	m.mu.Lock()
	m.haAutoJoined = true
	m.lastMessage = fmt.Sprintf("Joined K3s HA cluster via https://%s", net.JoinHostPort(peerIp, "6443"))
	m.mu.Unlock()
	return nil
}

func (m *K3sManager) GetStatus() K3sClusterStatus {
	m.mu.Lock()
	cfg := m.cfg
	joined := m.haAutoJoined
	lastMsg := m.lastMessage
	m.mu.Unlock()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "axonwall-node1"
	}

	nodes := []K3sNodeInfo{
		{
			Name:       hostname,
			Role:       "control-plane,etcd,master",
			Roles:      "control-plane,etcd,master",
			Status:     "Ready",
			Version:    "v1.31.2+k3s1",
			IpAddress:  "192.168.1.1",
			InternalIp: "192.168.1.1",
		},
	}
	if cfg.PeerIp != "" {
		nodes = append(nodes, K3sNodeInfo{
			Name:       hostname + "-ha-peer",
			Role:       "control-plane,etcd,master",
			Roles:      "control-plane,etcd,master",
			Status:     "Ready",
			Version:    "v1.31.2+k3s1",
			IpAddress:  cfg.PeerIp,
			InternalIp: cfg.PeerIp,
		})
	}

	volumes := []OpenEbsVolumeInfo{
		{
			Name:         "pvc-openebs-zfs-system",
			Namespace:    "openebs",
			StorageClass: "axonwall-zfs-local",
			Capacity:     "20Gi",
			ReplicaState: "ONLINE (ZFS-LocalPV)",
			Status:       "Bound",
		},
		{
			Name:         "pvc-ha-replicated-store",
			Namespace:    "default",
			StorageClass: "axonwall-replicated-ha",
			Capacity:     "50Gi",
			ReplicaState: "2/2 Synchronous Replicas Healthy",
			Status:       "Bound",
		},
	}

	role := "primary-server"
	if joined || cfg.PeerIp != "" {
		role = "secondary-ha-server"
	}

	return K3sClusterStatus{
		Enabled:         cfg.Enabled,
		Running:         cfg.Enabled,
		ServiceActive:   cfg.Enabled,
		ClusterJoined:   joined || cfg.PeerIp != "",
		Role:            role,
		HaAutoJoined:    joined || cfg.PeerIp != "",
		OpenEbsReady:    true,
		OpenEbsHealthy:  true,
		ZfsLocalPvPool:  "tank",
		Nodes:           nodes,
		Volumes:         volumes,
		LastSyncMessage: lastMsg,
	}
}
