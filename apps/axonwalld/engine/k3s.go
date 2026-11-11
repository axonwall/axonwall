package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
	CniPlugin             string `json:"cniPlugin,omitempty"`
	HaTopology            string `json:"haTopology,omitempty"`
	ZfsLocalPvPool        string `json:"zfsLocalPvPool"`
	ReplicatedPool        string `json:"replicatedPool"`
	K3sConfigYaml         string `json:"k3sConfigYaml"`
	OpenEbsManifestYaml   string `json:"openEbsManifestYaml"`
	WorkloadsManifestYaml string `json:"workloadsManifestYaml"`
	CiliumManifestYaml    string `json:"ciliumManifestYaml,omitempty"`
	ServiceLbManifestYaml string `json:"serviceLbManifestYaml,omitempty"`
}

type K3sEtcdSnapshotInfo struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	SizeBytes int64  `json:"sizeBytes"`
	CreatedAt string `json:"createdAt"`
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
	CniPlugin       string              `json:"cniPlugin,omitempty"`
	HaTopology      string              `json:"haTopology,omitempty"`
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

// SetK3sPathsForTest redirects K3s and VOW filesystem roots for testing.
// Returns a cleanup function that restores the prior values.
func SetK3sPathsForTest(etcDir, manifestDir, stateDir, vowDir string) func() {
	origE, origM, origS, origV := k3sEtcDir, k3sServerManifestDir, k3sStateDir, vowEtcDir
	k3sEtcDir, k3sServerManifestDir, k3sStateDir, vowEtcDir = etcDir, manifestDir, stateDir, vowDir
	return func() {
		k3sEtcDir, k3sServerManifestDir, k3sStateDir, vowEtcDir = origE, origM, origS, origV
	}
}

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
	if bundle.CiliumManifestYaml != "" {
		if err := validateK3sManifest(bundle.CiliumManifestYaml); err != nil {
			return fmt.Errorf("k3s cilium manifest rejected: %w", err)
		}
	}
	if bundle.ServiceLbManifestYaml != "" {
		if err := validateK3sManifest(bundle.ServiceLbManifestYaml); err != nil {
			return fmt.Errorf("k3s servicelb manifest rejected: %w", err)
		}
	}

	m.mu.Lock()
	m.cfg = bundle
	m.mu.Unlock()

	if !bundle.Enabled {
		slog.Info("K3s plugin is disabled; stopping k3s service")
		_ = removeFileIfExists(filepath.Join(k3sEtcDir, "config.yaml"))
		_ = exec.Command("systemctl", "stop", "k3s").Run()
		return nil
	}

	// On real appliances (when not redirected by SetK3sPathsForTest),
	// ensure /etc/systemd/system/k3s.service exists if /lib/systemd/system/k3s.service
	// was not yet installed by the .deb package, and ensure the OpenEBS backing ZFS dataset exists.
	if k3sEtcDir == "/etc/rancher/k3s" {
		ensureK3sServiceUnit()
		ensureOpenEbsZfsDataset(bundle.ReplicatedPool)
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
			if existingTok, rErr := os.ReadFile(filepath.Join(k3sStateDir, "k3s-join.token")); rErr == nil && strings.TrimSpace(string(existingTok)) != "" {
				m.mu.Lock()
				m.haAutoJoined = true
				m.lastMessage = fmt.Sprintf("Using cached K3s join token for HA primary https://%s", net.JoinHostPort(bundle.PeerIp, "6443"))
				m.mu.Unlock()
			} else {
				slog.Warn("Could not fetch K3s join token from HA peer yet; will retry on HA sync cycle", "peerIp", bundle.PeerIp, "error", err)
			}
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
	if bundle.CiliumManifestYaml != "" {
		writes = append(writes, atomicFileWrite{
			path:    filepath.Join(k3sServerManifestDir, "axonwall-cilium.yaml"),
			content: bundle.CiliumManifestYaml,
			perm:    0644,
		})
	} else {
		_ = removeFileIfExists(filepath.Join(k3sServerManifestDir, "axonwall-cilium.yaml"))
	}
	if bundle.ServiceLbManifestYaml != "" {
		writes = append(writes, atomicFileWrite{
			path:    filepath.Join(k3sServerManifestDir, "axonwall-servicelb.yaml"),
			content: bundle.ServiceLbManifestYaml,
			perm:    0644,
		})
	} else {
		_ = removeFileIfExists(filepath.Join(k3sServerManifestDir, "axonwall-servicelb.yaml"))
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

	// Ensure /etc/rancher/k3s/k3s.yaml is accessible by admin operators in group axonwall-api
	ensureKubeconfigPermissions()

	return nil
}

func ensureKubeconfigPermissions() {
	kubeconfigPath := filepath.Join(k3sEtcDir, "k3s.yaml")
	if _, err := os.Stat(kubeconfigPath); err == nil {
		_ = exec.Command("chown", ":axonwall-api", kubeconfigPath).Run()
		_ = os.Chmod(kubeconfigPath, 0640)
	}
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

	// A-H2 (round 2): this used to fabricate a healthy 2-node cluster
	// with bound volumes out of constants, even with k3s stopped or
	// never installed. Probe reality instead and report unknown/down
	// when the probes fail: a peer IP in config is not evidence of a
	// joined cluster, and no probe means no nodes and no volumes.
	serviceActive := isSystemdServiceActive("k3s")
	var nodes []K3sNodeInfo
	var volumes []OpenEbsVolumeInfo
	running := false
	openEbsReady := false
	openEbsHealthy := false
	if serviceActive {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if probed, err := probeK3sNodes(ctx); err == nil {
			nodes = probed
			running = true
			volumes = probeK3sPVCs(ctx)
			openEbsReady, openEbsHealthy = probeOpenEBSHealth(ctx)
		} else {
			// The service is up but the API does not answer: the
			// cluster is not running as far as anyone can tell.
			lastMsg = fmt.Sprintf("k3s service is active but kubectl get nodes failed: %v", err)
		}
	}

	// ClusterJoined is the latched join only: a peer IP in config never
	// proves a join (the token fetch may have failed, and ApplyConfig
	// only warns about that).
	role := "primary-server"
	if joined {
		role = "secondary-ha-server"
	}

	cniPlugin := cfg.CniPlugin
	if cniPlugin == "" {
		cniPlugin = "flannel"
	}
	haTopo := cfg.HaTopology
	if haTopo == "" {
		haTopo = "embedded-etcd"
	}

	return K3sClusterStatus{
		Enabled:         cfg.Enabled,
		Running:         running,
		ServiceActive:   serviceActive,
		ClusterJoined:   joined,
		Role:            role,
		CniPlugin:       cniPlugin,
		HaTopology:      haTopo,
		HaAutoJoined:    joined,
		OpenEbsReady:    openEbsReady,
		OpenEbsHealthy:  openEbsHealthy,
		ZfsLocalPvPool:  "tank",
		Nodes:           nodes,
		Volumes:         volumes,
		LastSyncMessage: lastMsg,
	}
}

var k3sEtcdSnapshotDir = "/var/lib/rancher/k3s/server/db/snapshots"

// ListEtcdSnapshots inspects local K3s embedded etcd snapshots on disk.
func (m *K3sManager) ListEtcdSnapshots() []K3sEtcdSnapshotInfo {
	entries, err := os.ReadDir(k3sEtcdSnapshotDir)
	if err != nil {
		return []K3sEtcdSnapshotInfo{}
	}
	var out []K3sEtcdSnapshotInfo
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		out = append(out, K3sEtcdSnapshotInfo{
			Name:      entry.Name(),
			Path:      filepath.Join(k3sEtcdSnapshotDir, entry.Name()),
			SizeBytes: info.Size(),
			CreatedAt: info.ModTime().UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// SaveEtcdSnapshot triggers an immediate K3s embedded etcd snapshot via `k3s etcd-snapshot save`.
func (m *K3sManager) SaveEtcdSnapshot(name string) (string, error) {
	safeName := strings.TrimSpace(name)
	if safeName == "" {
		safeName = fmt.Sprintf("axonwall-etcd-%s", time.Now().UTC().Format("20060102-150405"))
	}
	for _, r := range safeName {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return "", fmt.Errorf("invalid etcd snapshot name %q", name)
		}
	}
	if strings.HasPrefix(safeName, "-") || strings.HasPrefix(safeName, ".") {
		return "", fmt.Errorf("invalid etcd snapshot name %q", name)
	}
	k3sBin, err := exec.LookPath("k3s")
	if err != nil {
		return "", fmt.Errorf("k3s binary not found on system")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, k3sBin, "etcd-snapshot", "save", "--name", safeName).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("k3s etcd-snapshot save failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return safeName, nil
}

// RestoreEtcdSnapshot restores the embedded etcd cluster from a local snapshot inside k3sEtcdSnapshotDir.
func (m *K3sManager) RestoreEtcdSnapshot(snapshotName string) error {
	base := filepath.Base(strings.TrimSpace(snapshotName))
	if base == "" || base == "." || base == ".." || strings.HasPrefix(base, "-") {
		return fmt.Errorf("invalid etcd snapshot filename %q", snapshotName)
	}
	fullPath := filepath.Join(k3sEtcdSnapshotDir, base)
	info, err := os.Lstat(fullPath)
	if err != nil || info.IsDir() || (info.Mode()&os.ModeSymlink) != 0 {
		return fmt.Errorf("etcd snapshot %q not found or invalid", base)
	}
	k3sBin, err := exec.LookPath("k3s")
	if err != nil {
		return fmt.Errorf("k3s binary not found on system")
	}
	_ = exec.Command("systemctl", "stop", "k3s").Run()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, k3sBin, "server", "--cluster-reset", "--cluster-reset-restore-path="+fullPath).CombinedOutput()
	if err != nil {
		_ = exec.Command("systemctl", "start", "k3s").Run()
		return fmt.Errorf("k3s cluster-reset restore failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	if startOut, startErr := exec.Command("systemctl", "start", "k3s").CombinedOutput(); startErr != nil {
		return fmt.Errorf("etcd restored, but failed to restart k3s: %s (%w)", strings.TrimSpace(string(startOut)), startErr)
	}
	return nil
}

const defaultK3sServiceUnit = `[Unit]
Description=Lightweight Kubernetes (Axonwall In-House K3s Engine)
Documentation=https://k3s.io
Wants=network-online.target
After=network-online.target
ConditionPathExists=/etc/rancher/k3s/config.yaml

[Install]
WantedBy=multi-user.target

[Service]
Type=exec
EnvironmentFile=-/etc/default/%N
EnvironmentFile=-/etc/sysconfig/%N
EnvironmentFile=-/etc/systemd/system/k3s.service.env
KillMode=process
Delegate=yes
User=root
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s
ExecStartPre=-/usr/sbin/modprobe br_netfilter
ExecStartPre=-/usr/sbin/modprobe overlay
ExecStart=/usr/local/bin/k3s server --prefer-bundled-bin
`

func ensureK3sServiceUnit() {
	if _, err := os.Stat("/etc/systemd/system/k3s.service"); err == nil {
		return
	}
	if _, err := os.Stat("/lib/systemd/system/k3s.service"); err == nil {
		return
	}
	if err := os.WriteFile("/etc/systemd/system/k3s.service", []byte(defaultK3sServiceUnit), 0644); err != nil {
		slog.Warn("Could not write /etc/systemd/system/k3s.service", "error", err)
		return
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = exec.Command("systemctl", "enable", "k3s.service").Run()
}

func ensureOpenEbsZfsDataset(replicatedPool string) {
	ds := strings.TrimSpace(replicatedPool)
	if ds == "" || !validZfsPath(ds, true) || !strings.Contains(ds, "/") {
		return
	}
	if _, err := exec.LookPath("zfs"); err != nil {
		return
	}
	poolName := strings.SplitN(ds, "/", 2)[0]
	if err := exec.Command("zpool", "list", "-H", poolName).Run(); err != nil {
		return
	}
	if err := exec.Command("zfs", "list", "-H", ds).Run(); err != nil {
		_ = exec.Command("zfs", "create", "-p", "-o", "compression=lz4", ds).Run()
	}
	_ = exec.Command("zfs", "mount", "-O", ds).Run()
}

// LoadSavedConfig restores the in-memory K3sRuntimeBundle and HA auto-join latch at daemon startup.
func (m *K3sManager) LoadSavedConfig(rawJSON []byte) {
	var bundle K3sRuntimeBundle
	if err := json.Unmarshal(rawJSON, &bundle); err != nil {
		return
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
	m.mu.Lock()
	m.cfg = bundle
	if (bundle.Role == "backup" || bundle.Role == "secondary") && bundle.AutoJoinHaPeer {
		if existingTok, err := os.ReadFile(filepath.Join(k3sStateDir, "k3s-join.token")); err == nil && strings.TrimSpace(string(existingTok)) != "" {
			m.haAutoJoined = true
			m.lastMessage = fmt.Sprintf("Auto-joined primary K3s cluster at https://%s with OpenEBS replication", net.JoinHostPort(bundle.PeerIp, "6443"))
		}
	}
	m.mu.Unlock()
}

// IsEnabled reports whether the K3s plugin is currently enabled in configuration.
func (m *K3sManager) IsEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Enabled
}

// MarkHaAutoJoined records that the HA backup poller retrieved the peer token and joined the cluster.
func (m *K3sManager) MarkHaAutoJoined(peerIp string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.haAutoJoined = true
	m.lastMessage = fmt.Sprintf("Auto-joined primary K3s cluster at https://%s with OpenEBS replication", net.JoinHostPort(peerIp, "6443"))
}

// isSystemdServiceActive reports whether a systemd unit is active.
// A missing systemctl binary or any error means "not active".
func isSystemdServiceActive(unit string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run() == nil
}

// runKubectlJSON runs `kubectl get <args...> -o json`, preferring plain
// kubectl (with the k3s kubeconfig when present) and falling back to
// `k3s kubectl`, which finds its own config.
func runKubectlJSON(ctx context.Context, args ...string) ([]byte, error) {
	fullArgs := append([]string{"get"}, args...)
	fullArgs = append(fullArgs, "-o", "json")
	if out, err := runKubectlCmd(ctx, "kubectl", fullArgs); err == nil {
		return out, nil
	}
	return runKubectlCmd(ctx, "k3s", append([]string{"kubectl"}, fullArgs...))
}

func runKubectlCmd(ctx context.Context, name string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if name == "kubectl" {
		if _, err := os.Stat("/etc/rancher/k3s/k3s.yaml"); err == nil {
			cmd.Env = append(os.Environ(), "KUBECONFIG=/etc/rancher/k3s/k3s.yaml")
		}
	}
	return cmd.Output()
}

type kubectlNodeList struct {
	Items []struct {
		Metadata struct {
			Name   string            `json:"name"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
		Status struct {
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
			NodeInfo struct {
				KubeletVersion string `json:"kubeletVersion"`
			} `json:"nodeInfo"`
			Addresses []struct {
				Type    string `json:"type"`
				Address string `json:"address"`
			} `json:"addresses"`
		} `json:"status"`
	} `json:"items"`
}

// probeK3sNodes returns the nodes the Kubernetes API actually reports.
func probeK3sNodes(ctx context.Context) ([]K3sNodeInfo, error) {
	out, err := runKubectlJSON(ctx, "nodes")
	if err != nil {
		return nil, err
	}
	var list kubectlNodeList
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("parsing kubectl get nodes output: %w", err)
	}
	nodes := make([]K3sNodeInfo, 0, len(list.Items))
	for _, item := range list.Items {
		status := "NotReady"
		for _, c := range item.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				status = "Ready"
			}
		}
		var roles []string
		for label := range item.Metadata.Labels {
			if strings.HasPrefix(label, "node-role.kubernetes.io/") {
				roles = append(roles, strings.TrimPrefix(label, "node-role.kubernetes.io/"))
			}
		}
		role := "worker"
		if len(roles) > 0 {
			sort.Strings(roles)
			role = strings.Join(roles, ",")
		}
		var internalIP string
		for _, a := range item.Status.Addresses {
			if a.Type == "InternalIP" {
				internalIP = a.Address
			}
		}
		nodes = append(nodes, K3sNodeInfo{
			Name:       item.Metadata.Name,
			Role:       role,
			Roles:      role,
			Status:     status,
			Version:    item.Status.NodeInfo.KubeletVersion,
			IpAddress:  internalIP,
			InternalIp: internalIP,
		})
	}
	return nodes, nil
}

type kubectlPVCList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			StorageClassName string `json:"storageClassName"`
		} `json:"spec"`
		Status struct {
			Phase    string `json:"phase"`
			Capacity struct {
				Storage string `json:"storage"`
			} `json:"capacity"`
		} `json:"status"`
	} `json:"items"`
}

// probeK3sPVCs returns the persistent volume claims the API reports, or
// nil when the probe fails — never invented volumes.
func probeK3sPVCs(ctx context.Context) []OpenEbsVolumeInfo {
	out, err := runKubectlJSON(ctx, "pvc", "-A")
	if err != nil {
		return nil
	}
	var list kubectlPVCList
	if err := json.Unmarshal(out, &list); err != nil {
		return nil
	}
	volumes := make([]OpenEbsVolumeInfo, 0, len(list.Items))
	for _, item := range list.Items {
		volumes = append(volumes, OpenEbsVolumeInfo{
			Name:         item.Metadata.Name,
			Namespace:    item.Metadata.Namespace,
			StorageClass: item.Spec.StorageClassName,
			Capacity:     item.Status.Capacity.Storage,
			Status:       item.Status.Phase,
		})
	}
	return volumes
}

type kubectlPodList struct {
	Items []struct {
		Status struct {
			Phase             string `json:"phase"`
			ContainerStatuses []struct {
				Ready bool `json:"ready"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

// probeOpenEBSHealth reports whether the OpenEBS pods are all running
// with ready containers, or when using the embedded ZFS/Replicated StorageClasses
// without separate pods in -n openebs, whether both axonwall-zfs-local and
// axonwall-replicated-ha StorageClasses are provisioned in the cluster.
func probeOpenEBSHealth(ctx context.Context) (ready, healthy bool) {
	out, err := runKubectlJSON(ctx, "pods", "-n", "openebs")
	if err == nil {
		var list kubectlPodList
		if err := json.Unmarshal(out, &list); err == nil && len(list.Items) > 0 {
			for _, item := range list.Items {
				if item.Status.Phase != "Running" {
					return false, false
				}
				for _, c := range item.Status.ContainerStatuses {
					if !c.Ready {
						return false, false
					}
				}
			}
			return true, true
		}
	}
	scOut, scErr := runKubectlJSON(ctx, "storageclass")
	if scErr != nil {
		return false, false
	}
	var scList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(scOut, &scList); err != nil || len(scList.Items) == 0 {
		return false, false
	}
	hasZfsLocal := false
	hasReplicated := false
	for _, sc := range scList.Items {
		if sc.Metadata.Name == "axonwall-zfs-local" {
			hasZfsLocal = true
		}
		if sc.Metadata.Name == "axonwall-replicated-ha" {
			hasReplicated = true
		}
	}
	if hasZfsLocal && hasReplicated {
		return true, true
	}
	return false, false
}
