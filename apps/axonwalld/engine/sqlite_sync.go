package engine

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SqliteSyncConfig struct {
	Enabled              bool     `json:"enabled"`
	NodeRole             string   `json:"nodeRole"` // "master" or "backup"
	Mode                 string   `json:"mode"`     // "direct_stream" or "litestream"
	Databases            []string `json:"databases"`
	SyncIntervalSeconds  int      `json:"syncIntervalSeconds"`
	ListenPort           int      `json:"listenPort"`
	PeerAddress          string   `json:"peerAddress"`
	PeerPort             int      `json:"peerPort"`
	AuthToken            string   `json:"authToken"`
	LocalAddress         string   `json:"localAddress"`
	AutoPromoteHeadscale bool     `json:"autoPromoteHeadscale"`
	CheckpointOnSync     bool     `json:"checkpointOnSync"`
}

type DatabaseStatus struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Sha256  string `json:"sha256"`
	ModTime int64  `json:"modTime"`
}

type SyncStatusResponse struct {
	NodeRole  string           `json:"nodeRole"`
	Timestamp int64            `json:"timestamp"`
	Databases []DatabaseStatus `json:"databases"`
}

type SqliteSyncManager struct {
	mu            sync.Mutex
	cfg           SqliteSyncConfig
	server        *http.Server
	stopPoller    chan struct{}
	pollerRunning bool
	litestreamCmd *exec.Cmd
	k3sManager    *K3sManager
}

func NewSqliteSyncManager() *SqliteSyncManager {
	return &SqliteSyncManager{
		stopPoller: make(chan struct{}),
	}
}

func (m *SqliteSyncManager) SetK3sManager(km *K3sManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.k3sManager = km
}

func (m *SqliteSyncManager) ApplyConfig(cfg SqliteSyncConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	slog.Info("Applying SQLite Sync Configuration",
		"enabled", cfg.Enabled,
		"role", cfg.NodeRole,
		"mode", cfg.Mode,
		"databases", cfg.Databases,
	)

	// Stop existing services
	m.stopInternal()

	m.cfg = cfg
	if !cfg.Enabled {
		slog.Info("SQLite Sync is disabled.")
		return nil
	}

	if cfg.Mode == "litestream" {
		if cfg.NodeRole == "master" {
			return m.startLitestream()
		}
		return nil
	}

	if cfg.NodeRole == "master" {
		return m.startMasterServer()
	} else {
		return m.startBackupPoller()
	}
}

func (m *SqliteSyncManager) OnStateChange(state string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cfg.Enabled {
		return
	}

	slog.Info("HA State transition notification received in SqliteSyncManager", "state", state)

	if state == "MASTER" {
		m.cfg.NodeRole = "master"
		m.stopInternal()

		// Run SQLite checkpoint before taking over
		for _, db := range m.cfg.Databases {
			if _, err := os.Stat(db); err == nil {
				_ = exec.Command("sqlite3", db, "PRAGMA wal_checkpoint(TRUNCATE);").Run()
			}
		}

		if m.cfg.AutoPromoteHeadscale {
			slog.Info("Promoting local Headscale service to Active Master...")
			if _, err := exec.LookPath("systemctl"); err == nil {
				_ = exec.Command("systemctl", "try-reload-or-restart", "headscale").Run()
			} else if _, err := exec.LookPath("rc-service"); err == nil {
				_ = exec.Command("rc-service", "--ifexists", "headscale", "restart").Run()
			}
		}

		if m.cfg.Mode == "litestream" {
			if err := m.startLitestream(); err != nil {
				slog.Error("Failed to start litestream on transition to MASTER", "error", err)
			}
		} else {
			if err := m.startMasterServer(); err != nil {
				slog.Error("Failed to start master sync server on transition to MASTER", "error", err)
			}
		}
	} else if state == "BACKUP" || state == "FAULT" {
		m.cfg.NodeRole = "backup"
		m.stopInternal()

		if m.cfg.AutoPromoteHeadscale {
			slog.Info("Demoting local node to Standby: stopping Headscale to prevent split-brain writes...")
			if _, err := exec.LookPath("systemctl"); err == nil {
				_ = exec.Command("systemctl", "stop", "headscale").Run()
			} else if _, err := exec.LookPath("rc-service"); err == nil {
				_ = exec.Command("rc-service", "--ifexists", "headscale", "stop").Run()
			}
		}

		if m.cfg.Mode != "litestream" {
			if err := m.startBackupPoller(); err != nil {
				slog.Error("Failed to start backup poller on transition to BACKUP", "error", err)
			}
		}
	}
}

// authorized reports whether a sync request carries the configured shared
// token. It fails closed: when no auth token is configured, every request
// is rejected. The sync endpoints serve the headscale database, appliance
// state, ZFS send streams and the K3s join token, so an unset token must
// never silently mean "no authentication".
func (m *SqliteSyncManager) authorized(r *http.Request) bool {
	m.mu.Lock()
	authToken := m.cfg.AuthToken
	m.mu.Unlock()
	if authToken == "" {
		return false
	}
	provided := r.Header.Get("X-Axonwall-Sync-Token")
	return subtle.ConstantTimeCompare([]byte(provided), []byte(authToken)) == 1
}

func (m *SqliteSyncManager) startMasterServer() error {
	listenAddr := fmt.Sprintf("0.0.0.0:%d", m.cfg.ListenPort)
	if m.cfg.LocalAddress != "" && m.cfg.LocalAddress != "0.0.0.0" {
		listenAddr = fmt.Sprintf("%s:%d", m.cfg.LocalAddress, m.cfg.ListenPort)
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/sync/status", m.handleStatus)
	mux.HandleFunc("/api/v1/sync/db", m.handleDownloadDb)
	mux.HandleFunc("/api/v1/sync/state", m.handleDownloadState)
	mux.HandleFunc("/api/v1/sync/zfs", m.handleZfsSendStream)
	mux.HandleFunc("/api/v1/sync/k3s-token", m.handleK3sToken)

	m.server = &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 300 * time.Second,
	}

	if m.cfg.AuthToken == "" {
		slog.Error("HA sync master server has NO auth token configured: every sync request will be rejected (fail-closed) until sqliteSync.authToken is set")
	}

	// NOTE: plain HTTP on purpose. The peer-side clients (pollAndSync,
	// FetchPeerClusterToken) dial http://; enabling TLS here without a
	// matching client (scheme + CA pinning) silently breaks replication.
	// Transport encryption for HA sync must be added on both ends at once.
	slog.Info("Starting Unified HA Sync Master HTTP Server (SQLite + State + ZFS + K3s)", "addr", listenAddr)
	srv := m.server
	go func() {
		// The HA sync interface address may not be assigned yet at boot;
		// keep retrying the bind instead of giving up on the first error.
		for {
			err := srv.ListenAndServe()
			if err == nil || err == http.ErrServerClosed {
				return
			}
			slog.Error("SQLite Sync server error; retrying in 5s", "addr", listenAddr, "error", err)
			time.Sleep(5 * time.Second)
		}
	}()

	return nil
}

func (m *SqliteSyncManager) handleStatus(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	nodeRole := m.cfg.NodeRole
	databases := append([]string(nil), m.cfg.Databases...)
	m.mu.Unlock()

	if !m.authorized(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var dbStatuses []DatabaseStatus
	for _, dbPath := range databases {
		info, err := os.Stat(dbPath)
		if err != nil {
			continue
		}

		hashStr := computeFileSha256(dbPath)
		dbStatuses = append(dbStatuses, DatabaseStatus{
			Path:    dbPath,
			Size:    info.Size(),
			Sha256:  hashStr,
			ModTime: info.ModTime().Unix(),
		})
	}

	resp := SyncStatusResponse{
		NodeRole:  nodeRole,
		Timestamp: time.Now().Unix(),
		Databases: dbStatuses,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (m *SqliteSyncManager) handleDownloadDb(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	databases := append([]string(nil), m.cfg.Databases...)
	m.mu.Unlock()

	if !m.authorized(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	targetPath := r.URL.Query().Get("path")
	if targetPath == "" {
		http.Error(w, "Missing path parameter", http.StatusBadRequest)
		return
	}

	// Verify requested path is in configured allowed databases
	allowed := false
	for _, p := range databases {
		if p == targetPath {
			allowed = true
			break
		}
	}
	if !allowed {
		http.Error(w, "Access to requested database path denied", http.StatusForbidden)
		return
	}

	if _, err := os.Stat(targetPath); err != nil {
		http.Error(w, "Database file not found", http.StatusNotFound)
		return
	}

	// Create a safe, point-in-time online backup using SQLite backup API or vacuum into
	tmpBackup := fmt.Sprintf("%s.snap.%d", targetPath, time.Now().UnixNano())
	defer os.Remove(tmpBackup)

	// Attempt sqlite3 online backup command
	// The sqlite3 dot-command argument is a single-quoted string literal;
	// escape embedded quotes by doubling (audit D-S04) so a configured DB
	// path containing ' cannot break out into further dot-commands.
	backupCmd := exec.Command("sqlite3", targetPath, fmt.Sprintf(".backup '%s'", strings.ReplaceAll(tmpBackup, "'", "''")))
	if err := backupCmd.Run(); err != nil {
		// Fallback: Checkpoint and copy file
		_ = exec.Command("sqlite3", targetPath, "PRAGMA wal_checkpoint(PASSIVE);").Run()
		if copyErr := copyFile(targetPath, tmpBackup); copyErr != nil {
			http.Error(w, fmt.Sprintf("Failed to generate database snapshot: %v", copyErr), http.StatusInternalServerError)
			return
		}
	}

	checksum := computeFileSha256(tmpBackup)
	w.Header().Set("Content-Type", "application/x-sqlite3")
	w.Header().Set("X-Checksum-SHA256", checksum)

	f, err := os.Open(tmpBackup)
	if err != nil {
		http.Error(w, "Failed to read snapshot", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	_, _ = io.Copy(w, f)
}

func (m *SqliteSyncManager) startBackupPoller() error {
	m.stopPoller = make(chan struct{})
	m.pollerRunning = true

	interval := m.cfg.SyncIntervalSeconds
	if interval < 1 {
		interval = 5
	}

	slog.Info("Starting SQLite Sync Backup Poller", "intervalSeconds", interval, "peer", m.cfg.PeerAddress)

	stopCh := m.stopPoller
	go func() {
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		// Run an immediate sync on startup
		m.pollAndSync()

		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				m.pollAndSync()
			}
		}
	}()

	return nil
}

func (m *SqliteSyncManager) pollAndSync() {
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()

	if cfg.PeerAddress == "" {
		return
	}

	peerPort := cfg.PeerPort
	if peerPort == 0 {
		peerPort = cfg.ListenPort
	}

	statusUrl := fmt.Sprintf("http://%s/api/v1/sync/status", net.JoinHostPort(cfg.PeerAddress, strconv.Itoa(peerPort)))
	req, err := http.NewRequest("GET", statusUrl, nil)
	if err != nil {
		return
	}
	if cfg.AuthToken != "" {
		req.Header.Set("X-Axonwall-Sync-Token", cfg.AuthToken)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		slog.Debug("Peer sync status check unreachable", "url", statusUrl, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("Peer sync status check non-200", "statusCode", resp.StatusCode)
		return
	}

	var statusResp SyncStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		slog.Warn("Failed to parse peer sync status response", "error", err)
		return
	}

	// Compare peer databases against local copies
	for _, peerDb := range statusResp.Databases {
		localSha := computeFileSha256(peerDb.Path)
		if localSha != peerDb.Sha256 {
			slog.Info("Database update detected on peer. Synchronizing...",
				"database", peerDb.Path,
				"peerSha256", peerDb.Sha256,
				"localSha256", localSha,
			)

			if err := m.fetchAndApplyDb(peerDb.Path, peerPort); err != nil {
				slog.Error("Failed to synchronize database from peer", "path", peerDb.Path, "error", err)
			} else {
				slog.Info("Successfully synchronized database from peer", "path", peerDb.Path)
			}
		}
	}

	// Synchronize non-K3s appliance state (/var/lib/axonwall/state.json & Samba passdb.tdb)
	m.syncApplianceStateFromPeer(peerPort)

	// Automatically fetch K3s cluster join token if not yet present on backup node
	if _, err := os.Stat("/var/lib/axonwall/k3s-join.token"); err != nil {
		if tok, err := FetchPeerClusterToken(cfg.PeerAddress, peerPort, cfg.AuthToken); err == nil && tok != "" {
			_ = os.MkdirAll("/var/lib/axonwall", 0755)
			_ = os.WriteFile("/var/lib/axonwall/k3s-join.token", []byte(tok+"\n"), 0600)
			slog.Info("HA Backup Poller: Automatically retrieved K3s cluster join token from primary peer")
			_ = exec.Command("systemctl", "reload-or-restart", "k3s").Run()
		}
	}
}

func (m *SqliteSyncManager) handleDownloadState(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	statePath := "/etc/axonwall/state.json"
	data, err := os.ReadFile(statePath)
	if err != nil {
		statePath = "/var/lib/axonwall/state.json"
		data, err = os.ReadFile(statePath)
		if err != nil {
			http.Error(w, "state.json not found", http.StatusNotFound)
			return
		}
	}

	sum := sha256.Sum256(data)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Checksum-SHA256", hex.EncodeToString(sum[:]))
	_, _ = w.Write(data)
}

func validZfsSnapshotName(name string) bool {
	if name == "" || strings.HasPrefix(name, "-") || strings.Contains(name, "..") {
		return false
	}
	parts := strings.Split(name, "@")
	if len(parts) != 2 {
		return false
	}
	return validZfsPath(parts[0], true) && validZfsPath(parts[1], false)
}

func (m *SqliteSyncManager) handleZfsSendStream(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	dataset := r.URL.Query().Get("dataset")
	fromSnap := r.URL.Query().Get("from")
	if !validZfsPath(dataset, true) {
		http.Error(w, "Invalid dataset parameter", http.StatusBadRequest)
		return
	}
	if fromSnap != "" && !validZfsSnapshotName(fromSnap) {
		http.Error(w, "Invalid from snapshot parameter", http.StatusBadRequest)
		return
	}

	snapTag := fmt.Sprintf("ha-sync-%d", time.Now().UTC().UnixNano())
	targetSnap := fmt.Sprintf("%s@%s", dataset, snapTag)

	if out, err := exec.Command("zfs", "snapshot", targetSnap).CombinedOutput(); err != nil {
		http.Error(w, fmt.Sprintf("zfs snapshot failed: %s", string(out)), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Zfs-Snapshot", targetSnap)

	var sendArgs []string
	if fromSnap != "" {
		sendArgs = []string{"send", "-w", "-I", fromSnap, targetSnap}
	} else {
		sendArgs = []string{"send", "-w", targetSnap}
	}

	cmd := exec.Command("zfs", sendArgs...)
	cmd.Stdout = w
	if err := cmd.Run(); err != nil {
		slog.Warn("zfs send stream finished with error", "dataset", dataset, "error", err)
	}
}

func (m *SqliteSyncManager) handleK3sToken(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	m.mu.Lock()
	km := m.k3sManager
	m.mu.Unlock()
	if km == nil {
		km = NewK3sManager()
	}
	tok, err := km.GetClusterNodeToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token": tok,
	})
}

func (m *SqliteSyncManager) syncApplianceStateFromPeer(peerPort int) {
	m.mu.Lock()
	peerAddr := m.cfg.PeerAddress
	authToken := m.cfg.AuthToken
	m.mu.Unlock()

	if peerAddr == "" {
		return
	}

	stateUrl := fmt.Sprintf("http://%s/api/v1/sync/state", net.JoinHostPort(peerAddr, strconv.Itoa(peerPort)))
	req, err := http.NewRequest(http.MethodGet, stateUrl, nil)
	if err != nil {
		return
	}
	if authToken != "" {
		req.Header.Set("X-Axonwall-Sync-Token", authToken)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	peerSha := resp.Header.Get("X-Checksum-SHA256")
	localPath := "/etc/axonwall/state.json"
	if _, err := os.Stat(localPath); err != nil {
		if _, errVar := os.Stat("/var/lib/axonwall/state.json"); errVar == nil {
			localPath = "/var/lib/axonwall/state.json"
		}
	}
	localSha := computeFileSha256(localPath)
	replicaPath := localPath + ".ha-replica"
	replicaSha := computeFileSha256(replicaPath)
	if peerSha != "" && (peerSha == localSha || peerSha == replicaSha) {
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil || len(body) == 0 {
		return
	}
	actualSum := sha256.Sum256(body)
	actualSha := hex.EncodeToString(actualSum[:])
	if peerSha != "" && actualSha != peerSha {
		slog.Warn("Peer state checksum mismatch, skipping sync", "peerSha", peerSha, "actualSha", actualSha)
		return
	}
	_ = os.MkdirAll(filepath.Dir(localPath), 0755)
	_ = os.WriteFile(replicaPath, body, 0600)
}

func (m *SqliteSyncManager) fetchAndApplyDb(dbPath string, peerPort int) error {
	m.mu.Lock()
	peerAddr := m.cfg.PeerAddress
	authToken := m.cfg.AuthToken
	allowedDbs := append([]string(nil), m.cfg.Databases...)
	m.mu.Unlock()

	// Verify target dbPath is within local allowlist (cfg.Databases) and resides strictly within /var/lib/axonwall/
	cleanDbPath := filepath.Clean(dbPath)
	isAllowed := false
	for _, p := range allowedDbs {
		if filepath.Clean(p) == cleanDbPath {
			isAllowed = true
			break
		}
	}
	if !isAllowed || !strings.HasPrefix(cleanDbPath, "/var/lib/axonwall/") {
		return fmt.Errorf("refusing to apply database to unallowed or unsafe path: %s", cleanDbPath)
	}
	dbPath = cleanDbPath

	downloadUrl := fmt.Sprintf("http://%s/api/v1/sync/db?path=%s", net.JoinHostPort(peerAddr, strconv.Itoa(peerPort)), url.QueryEscape(dbPath))
	req, err := http.NewRequest("GET", downloadUrl, nil)
	if err != nil {
		return err
	}
	if authToken != "" {
		req.Header.Set("X-Axonwall-Sync-Token", authToken)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned error %d", resp.StatusCode)
	}

	expectedSha := resp.Header.Get("X-Checksum-SHA256")

	// Ensure destination directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create db directory: %w", err)
	}

	tmpFile := fmt.Sprintf("%s.tmp.%d", dbPath, time.Now().UnixNano())
	out, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return fmt.Errorf("failed to create temp db file: %w", err)
	}

	hasher := sha256.New()
	writer := io.MultiWriter(out, hasher)

	if _, err := io.Copy(writer, resp.Body); err != nil {
		out.Close()
		os.Remove(tmpFile)
		return fmt.Errorf("failed to stream db payload: %w", err)
	}
	out.Close()

	actualSha := hex.EncodeToString(hasher.Sum(nil))
	if expectedSha != "" && actualSha != expectedSha {
		os.Remove(tmpFile)
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedSha, actualSha)
	}

	// Remove any existing WAL or SHM files when replacing primary database file
	_ = os.Remove(dbPath + "-wal")
	_ = os.Remove(dbPath + "-shm")

	// Atomically replace database
	if err := os.Rename(tmpFile, dbPath); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to rename temp file to %s: %w", dbPath, err)
	}

	return nil
}

func (m *SqliteSyncManager) startLitestream() error {
	configPath := "/etc/litestream.yml"
	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("litestream config %s does not exist: %w", configPath, err)
	}

	cmd := exec.Command("litestream", "replicate", "-config", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		slog.Warn("Failed to start litestream daemon (binary may not be installed)", "error", err)
		return err
	}

	m.litestreamCmd = cmd
	slog.Info("Litestream SQLite replication daemon started successfully")
	return nil
}

func (m *SqliteSyncManager) stopInternal() {
	if m.server != nil {
		_ = m.server.Close()
		m.server = nil
	}

	if m.pollerRunning {
		close(m.stopPoller)
		m.pollerRunning = false
	}

	if m.litestreamCmd != nil && m.litestreamCmd.Process != nil {
		_ = m.litestreamCmd.Process.Kill()
		_ = m.litestreamCmd.Wait()
		m.litestreamCmd = nil
	}
}

func (m *SqliteSyncManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopInternal()
}

func computeFileSha256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
