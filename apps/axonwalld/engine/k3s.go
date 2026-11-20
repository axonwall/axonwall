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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
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

type K3sNodeTaint struct {
	Key    string `json:"key"`
	Value  string `json:"value,omitempty"`
	Effect string `json:"effect"`
}

type K3sNodeUpdateRequest struct {
	NodeName      string            `json:"nodeName"`
	Roles         []string          `json:"roles"`        // adjustable roles: "edge", "worker", "storage"
	CustomLabels  map[string]string `json:"customLabels"` // optional user/addon labels
	RemoveLabels  []string          `json:"removeLabels"` // optional user/addon label keys to delete
	Taints        []K3sNodeTaint    `json:"taints"`       // desired operator-managed taints
	Unschedulable *bool             `json:"unschedulable,omitempty"`
}

type K3sNodeInfo struct {
	Name          string            `json:"name"`
	Role          string            `json:"role"`
	Roles         string            `json:"roles"`
	Status        string            `json:"status"`
	Version       string            `json:"version"`
	IpAddress     string            `json:"ipAddress"`
	InternalIp    string            `json:"internalIp"`
	Unschedulable bool              `json:"unschedulable,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Taints        []K3sNodeTaint    `json:"taints,omitempty"`
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

	k3sEditionMarkerPath = "/etc/axonwall/.k3s-edition"
	k3sAgentServicePaths = []string{
		"/etc/systemd/system/k3s-agent.service",
		"/lib/systemd/system/k3s-agent.service",
		"/usr/lib/systemd/system/k3s-agent.service",
	}
	k3sTrustedZfsOperatorManifestPaths = []string{
		"/usr/share/axonwall/k3s/zfs-operator.yaml",
		"/usr/share/axonwall/k3s-storage/zfs-operator.yaml",
	}
)

// k3sJoinedMarkerPath is the durable proof that a secondary node
// completed a join. It is written only after k3s restarts
// successfully with a peer token in place (A-H2, round 3), so a
// daemon restart can tell a completed join apart from a token file
// that was written before a join was ever attempted. The token file
// alone is NOT proof: it is written before the join runs.
func k3sJoinedMarkerPath() string {
	return filepath.Join(k3sStateDir, "k3s-joined")
}

// writeK3sJoinedMarker records a completed join durably. A failure
// is logged, not fatal: the in-memory latch still reflects the join
// that just happened, but it will not survive a daemon restart.
func writeK3sJoinedMarker() {
	if err := os.WriteFile(k3sJoinedMarkerPath(), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0600); err != nil {
		slog.Warn("Failed to persist K3s HA join marker; join will not survive a daemon restart", "error", err)
	}
}

// recordHaJoinedLocked latches the join (caller holds m.mu) and
// persists the marker. It must only be called AFTER k3s has
// restarted successfully with the token in place.
func (m *K3sManager) recordHaJoinedLocked(peerIp string) {
	m.haAutoJoined = true
	m.lastMessage = fmt.Sprintf("Auto-joined primary K3s cluster at https://%s with OpenEBS replication", net.JoinHostPort(peerIp, "6443"))
	writeK3sJoinedMarker()
}

// clearHaJoinedLocked drops the latch and the marker (caller holds
// m.mu), e.g. when k3s is disabled or the node stops being a
// secondary.
func (m *K3sManager) clearHaJoinedLocked() {
	m.haAutoJoined = false
	_ = os.Remove(k3sJoinedMarkerPath())
}

// RestartK3sAfterTokenFetch reload-or-restarts the k3s unit the
// manager is configured for. The HA backup poller uses it to restart
// AFTER fetching a join token, so the join latch is only set once
// the restart succeeds (A-H2, round 3).
func (m *K3sManager) RestartK3sAfterTokenFetch() error {
	m.mu.Lock()
	unit := resolveK3sSystemdUnit(m.cfg.K3sConfigYaml)
	m.mu.Unlock()
	if out, err := exec.Command("systemctl", "--no-ask-password", "reload-or-restart", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reload-or-restart %s after retrieving K3s join token: %v (%s)", unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

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
		_ = exec.Command("systemctl", "--no-ask-password", "stop", "k3s").Run()
		if hasK3sAgentServiceUnit() || isK3sEditionAgent() {
			_ = exec.Command("systemctl", "--no-ask-password", "stop", "k3s-agent").Run()
		}
		// A-H2 (round 3): a disabled cluster must not keep
		// reporting ClusterJoined. The latch used to survive the
		// disable path untouched.
		m.mu.Lock()
		m.clearHaJoinedLocked()
		m.lastMessage = "K3s plugin is disabled"
		m.mu.Unlock()
		return nil
	}

	k3sServiceUnit := resolveK3sSystemdUnit(bundle.K3sConfigYaml)

	// On real appliances (when not redirected by SetK3sPathsForTest),
	// ensure /etc/systemd/system/k3s.service exists if /lib/systemd/system/k3s.service
	// was not yet installed by the .deb package, and ensure the OpenEBS backing ZFS dataset exists.
	if k3sEtcDir == "/etc/rancher/k3s" {
		if k3sServiceUnit == "k3s" {
			ensureK3sServiceUnit()
		}
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
	// A-H2 (round 3): fetching (or reusing a cached) token only
	// stages the join. The latch is set at the end of this function,
	// AFTER the k3s reload-or-restart below succeeds — a token in
	// hand is not a completed join, and a stale cached token from a
	// previous failed join must not re-latch "joined" while the peer
	// is unreachable.
	tokenFetched := false
	if (bundle.Role == "backup" || bundle.Role == "secondary") && bundle.AutoJoinHaPeer && bundle.PeerIp != "" {
		tok, err := FetchPeerClusterToken(bundle.PeerIp, bundle.SyncPort, bundle.AuthToken)
		if err == nil && tok != "" {
			if wErr := os.WriteFile(filepath.Join(k3sStateDir, "k3s-join.token"), []byte(tok+"\n"), 0600); wErr != nil {
				slog.Warn("Fetched K3s join token from HA primary peer but failed to persist it", "peerIp", bundle.PeerIp, "error", wErr)
			} else {
				tokenFetched = true
			}
			slog.Info("Fetched K3s join token from HA primary peer", "peerIp", bundle.PeerIp)
		} else {
			if existingTok, rErr := os.ReadFile(filepath.Join(k3sStateDir, "k3s-join.token")); rErr == nil && strings.TrimSpace(string(existingTok)) != "" {
				slog.Warn("Could not fetch K3s join token from HA peer; a cached token exists and will be used for the restart, but the node is not latched as joined until that restart succeeds", "peerIp", bundle.PeerIp, "error", err)
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
		if opContent, ok := readTrustedLocalZfsOperatorManifest(); ok {
			writes = append(writes, atomicFileWrite{
				path:    filepath.Join(k3sServerManifestDir, "00-openebs-zfs-operator.yaml"),
				content: opContent,
				perm:    0600,
			})
		}
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
	} else {
		_ = removeFileIfExists(filepath.Join(k3sServerManifestDir, "axonwall-workloads.yaml"))
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
	if out, err := exec.Command("systemctl", "--no-ask-password", "reload-or-restart", k3sServiceUnit).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reload-or-restart %s: %v (%s)", k3sServiceUnit, err, strings.TrimSpace(string(out)))
	}

	// A-H2 (round 3): only NOW — after the restart with the join
	// token in place succeeded — is the node joined. A fresh fetch
	// this apply (tokenFetched) or a cached token that survived a
	// successful restart both qualify; a restart that never ran (or
	// failed above) never latches.
	if (bundle.Role == "backup" || bundle.Role == "secondary") && bundle.AutoJoinHaPeer {
		if tok, rErr := os.ReadFile(filepath.Join(k3sStateDir, "k3s-join.token")); rErr == nil && strings.TrimSpace(string(tok)) != "" {
			m.mu.Lock()
			m.recordHaJoinedLocked(bundle.PeerIp)
			m.mu.Unlock()
		} else if tokenFetched {
			// Defensive: the token was fetched but its file vanished
			// between fetch and restart; do not latch on a token
			// that is no longer on disk.
			slog.Warn("K3s join token fetched this apply is no longer on disk after restart; not latching as joined", "peerIp", bundle.PeerIp)
		}
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
	m.mu.Lock()
	curConfigYaml := m.cfg.K3sConfigYaml
	m.mu.Unlock()
	k3sUnit := resolveK3sSystemdUnit(curConfigYaml)
	if out, err := exec.Command("systemctl", "--no-ask-password", "reload-or-restart", k3sUnit).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reload-or-restart %s after auto-join: %v (%s)", k3sUnit, err, strings.TrimSpace(string(out)))
	}
	m.mu.Lock()
	m.haAutoJoined = true
	m.lastMessage = fmt.Sprintf("Joined K3s HA cluster via https://%s", net.JoinHostPort(peerIp, "6443"))
	m.mu.Unlock()
	// A-H2 (round 3): persist the completed join so a daemon restart
	// can restore the latch from proof, not from token possession.
	writeK3sJoinedMarker()
	return nil
}

func readTrustedLocalZfsOperatorManifest() (string, bool) {
	for _, candidate := range k3sTrustedZfsOperatorManifestPaths {
		info, err := os.Lstat(candidate)
		if err != nil || info.IsDir() || (info.Mode()&os.ModeSymlink) != 0 {
			continue
		}
		data, err := os.ReadFile(candidate)
		if err == nil && len(strings.TrimSpace(string(data))) > 0 {
			return string(data), true
		}
	}
	return "", false
}

func isK3sEditionAgent() bool {
	data, err := os.ReadFile(k3sEditionMarkerPath)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "K3S_ROLE" {
			val := strings.Trim(strings.TrimSpace(v), `"'`)
			if val == "agent" {
				return true
			}
		}
	}
	return false
}

func hasK3sAgentServiceUnit() bool {
	for _, p := range k3sAgentServicePaths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func k3sConfigIsAgentJoin(k3sConfigYaml string) bool {
	if strings.TrimSpace(k3sConfigYaml) == "" {
		return false
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(k3sConfigYaml), &doc); err != nil {
		return false
	}
	srvVal, hasServer := doc["server"]
	if !hasServer {
		return false
	}
	srvStr, ok := srvVal.(string)
	if !ok || strings.TrimSpace(srvStr) == "" {
		return false
	}
	_, hasClusterCIDR := doc["cluster-cidr"]
	return !hasClusterCIDR
}

func resolveK3sSystemdUnit(k3sConfigYaml string) string {
	if isK3sEditionAgent() {
		return "k3s-agent"
	}
	if k3sConfigIsAgentJoin(k3sConfigYaml) && hasK3sAgentServiceUnit() {
		return "k3s-agent"
	}
	return "k3s"
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
	k3sUnit := resolveK3sSystemdUnit(cfg.K3sConfigYaml)
	serviceActive := isSystemdServiceActive(k3sUnit)
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

	// ClusterJoined is the latched join only, and the latch is now
	// set exclusively after a k3s restart with the token in place
	// succeeds (ApplyConfig / TriggerAutoJoin / HA poller) or
	// restored from the durable join marker at startup
	// (LoadSavedConfig). A peer IP in config, a token file on disk,
	// or a fetched-but-unrestarted token never proves a join
	// (A-H2, round 3).
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

	// A-L4 (round 3; also fixed on main by fc576368): GetStatus
	// hardcoded the ZFS local PV pool to "tank" even though the
	// bundle carries a configurable ZfsLocalPvPool. Report the
	// configured value; "tank" remains only the default when
	// nothing is configured. Main's version (with TrimSpace) is
	// kept as the dedupe.
	zfsPool := strings.TrimSpace(cfg.ZfsLocalPvPool)
	if zfsPool == "" {
		zfsPool = "tank"
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
		ZfsLocalPvPool:  zfsPool,
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
	// A-M9: the stop used to be discarded (`_ =`), so the cluster
	// reset ran against a possibly still-running etcd when the stop
	// failed (stuck/masked unit, systemctl error). Fail before the
	// reset instead. The unit is resolved the same way as the rest
	// of this file, so k3s-agent editions stop the right unit.
	// Main's --no-ask-password flag (a648c351) is kept on the stop.
	m.mu.Lock()
	configYaml := m.cfg.K3sConfigYaml
	m.mu.Unlock()
	k3sUnit := resolveK3sSystemdUnit(configYaml)
	if out, err := exec.Command("systemctl", "--no-ask-password", "stop", k3sUnit).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop %s before etcd cluster reset: %s (%w)", k3sUnit, strings.TrimSpace(string(out)), err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, k3sBin, "server", "--cluster-reset", "--cluster-reset-restore-path="+fullPath).CombinedOutput()
	if err != nil {
		_ = exec.Command("systemctl", "--no-ask-password", "start", k3sUnit).Run()
		return fmt.Errorf("k3s cluster-reset restore failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	if startOut, startErr := exec.Command("systemctl", "--no-ask-password", "start", k3sUnit).CombinedOutput(); startErr != nil {
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
	_ = exec.Command("systemctl", "--no-ask-password", "daemon-reload").Run()
	_ = exec.Command("systemctl", "--no-ask-password", "enable", "k3s.service").Run()
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
		// A-H2 (round 3): a token file on disk is not proof of a
		// join — it is written BEFORE the join is attempted. Only
		// the marker, written after a successful k3s restart with
		// the token in place, restores the latch across a restart.
		if _, err := os.Stat(k3sJoinedMarkerPath()); err == nil {
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
// Callers must only invoke it AFTER the k3s reload-or-restart that
// follows the token fetch succeeds (see RestartK3sAfterTokenFetch):
// calling it on token possession alone reintroduces the A-H2 latch
// lie. It persists the join marker so the latch survives a restart.
func (m *K3sManager) MarkHaAutoJoined(peerIp string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recordHaJoinedLocked(peerIp)
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

type kubectlNodeItem struct {
	Metadata struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		Unschedulable bool           `json:"unschedulable"`
		Taints        []K3sNodeTaint `json:"taints"`
	} `json:"spec"`
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
}

type kubectlNodeList struct {
	Items []kubectlNodeItem `json:"items"`
}

func parseK3sNodeItem(item kubectlNodeItem) K3sNodeInfo {
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
	var labelsCopy map[string]string
	if len(item.Metadata.Labels) > 0 {
		labelsCopy = make(map[string]string, len(item.Metadata.Labels))
		for k, v := range item.Metadata.Labels {
			labelsCopy[k] = v
		}
	}
	taintsCopy := make([]K3sNodeTaint, len(item.Spec.Taints))
	copy(taintsCopy, item.Spec.Taints)

	return K3sNodeInfo{
		Name:          item.Metadata.Name,
		Role:          role,
		Roles:         role,
		Status:        status,
		Version:       item.Status.NodeInfo.KubeletVersion,
		IpAddress:     internalIP,
		InternalIp:    internalIP,
		Unschedulable: item.Spec.Unschedulable,
		Labels:        labelsCopy,
		Taints:        taintsCopy,
	}
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
		nodes = append(nodes, parseK3sNodeItem(item))
	}
	return nodes, nil
}

var (
	k8sSubdomainRegex  = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	k8sLabelNameRegex  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$`)
	k8sLabelValueRegex = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?)?$`)
)

func validK8sNodeName(name string) bool {
	return len(name) > 0 && len(name) <= 253 && k8sSubdomainRegex.MatchString(name)
}

func validK8sLabelOrTaintKey(key string) bool {
	if key == "" {
		return false
	}
	parts := strings.Split(key, "/")
	if len(parts) > 2 {
		return false
	}
	if len(parts) == 2 {
		prefix, name := parts[0], parts[1]
		if len(prefix) == 0 || len(prefix) > 253 || !k8sSubdomainRegex.MatchString(prefix) {
			return false
		}
		return k8sLabelNameRegex.MatchString(name)
	}
	return k8sLabelNameRegex.MatchString(parts[0])
}

func validK8sLabelOrTaintValue(val string) bool {
	return k8sLabelValueRegex.MatchString(val)
}

func validK8sTaintEffect(eff string) bool {
	return eff == "NoSchedule" || eff == "PreferNoSchedule" || eff == "NoExecute"
}

func isSystemManagedConditionTaintKey(key string) bool {
	switch key {
	case "node.kubernetes.io/not-ready",
		"node.kubernetes.io/unreachable",
		"node.kubernetes.io/disk-pressure",
		"node.kubernetes.io/memory-pressure",
		"node.kubernetes.io/pid-pressure",
		"node.kubernetes.io/network-unavailable",
		"node.kubernetes.io/unschedulable",
		"node.cloudprovider.kubernetes.io/uninitialized":
		return true
	default:
		return false
	}
}

func isProtectedSystemLabelKey(key string) bool {
	if strings.HasPrefix(key, "kubernetes.io/") ||
		strings.HasPrefix(key, "beta.kubernetes.io/") ||
		strings.HasPrefix(key, "node.kubernetes.io/") ||
		strings.HasPrefix(key, "k3s.io/") {
		return true
	}
	switch key {
	case "node-role.kubernetes.io/control-plane",
		"node-role.kubernetes.io/master",
		"node-role.kubernetes.io/etcd",
		"node-role.kubernetes.io/edge",
		"node-role.kubernetes.io/worker",
		"node-role.kubernetes.io/storage",
		"axonwall.io/role":
		return true
	}
	return false
}

func buildNodeSchedulingMergePatch(existingLabels map[string]string, existingTaints []K3sNodeTaint, req K3sNodeUpdateRequest) ([]byte, error) {
	if !validK8sNodeName(req.NodeName) {
		return nil, fmt.Errorf("invalid kubernetes node name %q", req.NodeName)
	}

	selectedRoles := make(map[string]bool)
	for _, r := range req.Roles {
		norm := strings.ToLower(strings.TrimSpace(r))
		if norm == "" {
			continue
		}
		if norm != "edge" && norm != "worker" && norm != "storage" {
			return nil, fmt.Errorf("unsupported adjustable role %q: expected edge, worker, or storage", r)
		}
		selectedRoles[norm] = true
	}

	labelsPatch := make(map[string]any)
	if selectedRoles["edge"] {
		labelsPatch["node-role.kubernetes.io/edge"] = "true"
		labelsPatch["axonwall.io/role"] = "edge"
	} else {
		labelsPatch["node-role.kubernetes.io/edge"] = nil
		if existingLabels["axonwall.io/role"] == "edge" && !selectedRoles["storage"] {
			labelsPatch["axonwall.io/role"] = nil
		}
	}

	if selectedRoles["worker"] {
		labelsPatch["node-role.kubernetes.io/worker"] = "worker"
	} else {
		labelsPatch["node-role.kubernetes.io/worker"] = nil
	}

	if selectedRoles["storage"] {
		labelsPatch["node-role.kubernetes.io/storage"] = "storage"
		if !selectedRoles["edge"] {
			labelsPatch["axonwall.io/role"] = "k3s-storage"
		}
	} else {
		labelsPatch["node-role.kubernetes.io/storage"] = nil
		if existingLabels["axonwall.io/role"] == "k3s-storage" && !selectedRoles["edge"] {
			labelsPatch["axonwall.io/role"] = nil
		}
	}

	for _, rk := range req.RemoveLabels {
		if !validK8sLabelOrTaintKey(rk) {
			return nil, fmt.Errorf("invalid label key to remove %q", rk)
		}
		if isProtectedSystemLabelKey(rk) {
			return nil, fmt.Errorf("cannot remove protected system label %q", rk)
		}
		labelsPatch[rk] = nil
	}

	for k, v := range req.CustomLabels {
		if !validK8sLabelOrTaintKey(k) {
			return nil, fmt.Errorf("invalid custom label key %q", k)
		}
		if isProtectedSystemLabelKey(k) {
			return nil, fmt.Errorf("cannot modify protected system label %q", k)
		}
		if !validK8sLabelOrTaintValue(v) {
			return nil, fmt.Errorf("invalid label value %q for key %q", v, k)
		}
		labelsPatch[k] = v
	}

	mergedTaints := make([]K3sNodeTaint, 0, len(existingTaints)+len(req.Taints))
	seenTaints := make(map[string]bool)
	for _, t := range existingTaints {
		if !isSystemManagedConditionTaintKey(t.Key) {
			continue
		}
		if t.Key == "node.kubernetes.io/unschedulable" && req.Unschedulable != nil && !*req.Unschedulable {
			continue
		}
		dedupeKey := t.Key + "=" + t.Effect
		if !seenTaints[dedupeKey] {
			seenTaints[dedupeKey] = true
			mergedTaints = append(mergedTaints, t)
		}
	}

	for _, t := range req.Taints {
		if isSystemManagedConditionTaintKey(t.Key) {
			continue
		}
		if !validK8sLabelOrTaintKey(t.Key) {
			return nil, fmt.Errorf("invalid taint key %q", t.Key)
		}
		if !validK8sLabelOrTaintValue(t.Value) {
			return nil, fmt.Errorf("invalid taint value %q for key %q", t.Value, t.Key)
		}
		if !validK8sTaintEffect(t.Effect) {
			return nil, fmt.Errorf("invalid taint effect %q for key %q", t.Effect, t.Key)
		}
		dedupeKey := t.Key + "=" + t.Effect
		if !seenTaints[dedupeKey] {
			seenTaints[dedupeKey] = true
			mergedTaints = append(mergedTaints, K3sNodeTaint{
				Key:    t.Key,
				Value:  t.Value,
				Effect: t.Effect,
			})
		}
	}

	specPatch := map[string]any{
		"taints": mergedTaints,
	}
	if req.Unschedulable != nil {
		specPatch["unschedulable"] = *req.Unschedulable
	}

	return json.Marshal(map[string]any{
		"metadata": map[string]any{
			"labels": labelsPatch,
		},
		"spec": specPatch,
	})
}

func runKubectlPatch(ctx context.Context, nodeName, patchJSON string) ([]byte, error) {
	if _, err := exec.LookPath("kubectl"); err == nil {
		cmd := exec.CommandContext(ctx, "kubectl", "patch", "node", nodeName, "--type=merge", "-p", patchJSON)
		if _, statErr := os.Stat("/etc/rancher/k3s/k3s.yaml"); statErr == nil {
			cmd.Env = append(os.Environ(), "KUBECONFIG=/etc/rancher/k3s/k3s.yaml")
		}
		if out, runErr := cmd.CombinedOutput(); runErr == nil {
			return out, nil
		}
	}
	return exec.CommandContext(ctx, "k3s", "kubectl", "patch", "node", nodeName, "--type=merge", "-p", patchJSON).CombinedOutput()
}

// UpdateNodeScheduling atomically applies adjustable roles, labels, taints, and cordon state to a K3s node.
func (m *K3sManager) UpdateNodeScheduling(req K3sNodeUpdateRequest) (*K3sNodeInfo, error) {
	if !validK8sNodeName(req.NodeName) {
		return nil, fmt.Errorf("invalid kubernetes node name %q", req.NodeName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	rawNode, err := runKubectlJSON(ctx, "node", req.NodeName)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect node %q: %w", req.NodeName, err)
	}
	var current kubectlNodeItem
	if err := json.Unmarshal(rawNode, &current); err != nil {
		return nil, fmt.Errorf("failed to parse node %q JSON: %w", req.NodeName, err)
	}

	patchBytes, err := buildNodeSchedulingMergePatch(current.Metadata.Labels, current.Spec.Taints, req)
	if err != nil {
		return nil, err
	}

	if out, err := runKubectlPatch(ctx, req.NodeName, string(patchBytes)); err != nil {
		return nil, fmt.Errorf("kubectl patch node %q failed: %s (%w)", req.NodeName, strings.TrimSpace(string(out)), err)
	}

	updatedRaw, err := runKubectlJSON(ctx, "node", req.NodeName)
	if err != nil {
		return nil, fmt.Errorf("node %q patched, but re-read failed: %w", req.NodeName, err)
	}
	var updated kubectlNodeItem
	if err := json.Unmarshal(updatedRaw, &updated); err != nil {
		return nil, fmt.Errorf("failed to parse updated node %q JSON: %w", req.NodeName, err)
	}
	info := parseK3sNodeItem(updated)
	return &info, nil
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
