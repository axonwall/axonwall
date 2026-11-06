package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
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
	"syscall"
	"time"
)

type SqliteSyncConfig struct {
	Enabled               bool     `json:"enabled"`
	NodeRole              string   `json:"nodeRole"` // "master" or "backup"
	Mode                  string   `json:"mode"`     // "direct_stream" or "litestream"
	Databases             []string `json:"databases"`
	SyncIntervalSeconds   int      `json:"syncIntervalSeconds"`
	ListenPort            int      `json:"listenPort"`
	PeerAddress           string   `json:"peerAddress"`
	PeerPort              int      `json:"peerPort"`
	AuthToken             string   `json:"authToken"`
	Transport             string   `json:"transport"`             // "token-http" = legacy shared token over HTTP; "" or "mtls" = HA PKI mutual TLS (D-04 P1; default since P4)
	RequireSignedPayloads bool     `json:"requireSignedPayloads"` // reject unsigned /db and /state payloads from the peer (D-04 P2)
	LocalAddress          string   `json:"localAddress"`
	AutoPromoteHeadscale  bool     `json:"autoPromoteHeadscale"`
	CheckpointOnSync      bool     `json:"checkpointOnSync"`
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
	Transport string           `json:"transport"`
	Databases []DatabaseStatus `json:"databases"`
	// SignsPayloads advertises that this node signs its /db and /state
	// payloads (audit D-04 Phase 4b). Peers require signatures from a
	// node that advertises signing, which lets enforcement distinguish
	// a current master from a pre-signing one. Absent (false) in
	// responses from pre-P4b builds.
	SignsPayloads bool `json:"signsPayloads"`
}

// masterServerRetryDelay is the pause between bind retries of the HA
// sync master server (A-M7). Package variable so tests can shorten it.
var masterServerRetryDelay = 5 * time.Second

type SqliteSyncManager struct {
	mu                 sync.Mutex
	cfg                SqliteSyncConfig
	server             *http.Server
	serverGen          uint64 // generation of the running master server; stop/replace bumps it so a stale retry loop retires (A-M7)
	stopPoller         chan struct{}
	pollerRunning      bool
	pollerDone         chan struct{} // closed by the poller goroutine on exit; waited on by ApplyConfig/OnStateChange/Stop
	pollerCancel       context.CancelFunc
	litestreamCmd      *exec.Cmd
	k3sManager         *K3sManager
	effectiveTransport string // transport the master server is actually serving ("token-http" or "mtls")
	peerSignsPayloads  bool   // capability from the peer's latest sync status (D-04 P4b); set by the poller each round before any payload fetch
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
	slog.Info("Applying SQLite Sync Configuration",
		"enabled", cfg.Enabled,
		"role", cfg.NodeRole,
		"mode", cfg.Mode,
		"databases", cfg.Databases,
	)

	// Stop existing services, then JOIN the old poller before starting
	// anything new. The wait runs without
	// holding m.mu: the winding-down poller still needs m.mu for its
	// snapshots, so waiting under the lock would deadlock.
	m.mu.Lock()
	m.stopInternal()
	done := m.pollerDone
	m.cfg = cfg
	m.mu.Unlock()
	if done != nil {
		<-done
	}

	m.mu.Lock()
	defer m.mu.Unlock()
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
	// A-H3: stop the backup poller and JOIN it before starting the
	// master server. Previously stopInternal only closed the stop
	// channel, so a pollAndSync already in flight (status check, DB
	// download up to 60s) ran to completion and could rename a peer
	// database over the live one — and drop its WAL — after this node
	// had already started serving as master. The join waits without
	// holding m.mu (the poller needs m.mu while winding down), and
	// pollAndSync itself is stop/context-aware so the join cannot wait
	// out a hung download: cancelling the poller context aborts the
	// in-flight HTTP requests. The invariant this buys: every poller
	// database apply happens-before the master server starts, so no
	// apply can land after MASTER takeover.
	m.mu.Lock()
	enabled := m.cfg.Enabled
	m.stopInternal()
	done := m.pollerDone
	databases := append([]string(nil), m.cfg.Databases...)
	mode := m.cfg.Mode
	autoPromote := m.cfg.AutoPromoteHeadscale
	m.mu.Unlock()
	if done != nil {
		<-done
	}

	if !enabled {
		return
	}

	slog.Info("HA State transition notification received in SqliteSyncManager", "state", state)

	if state == "MASTER" {
		m.mu.Lock()
		m.cfg.NodeRole = "master"
		m.mu.Unlock()

		// Run SQLite checkpoint before taking over
		for _, db := range databases {
			if _, err := os.Stat(db); err == nil {
				_ = exec.Command("sqlite3", db, "PRAGMA wal_checkpoint(TRUNCATE);").Run()
			}
		}

		// A-M8: promote the verified peer state replica to the live
		// path now that the databases are checkpointed, before the
		// master server starts serving. The old code downloaded,
		// checksummed, and signature-verified peer state.json on
		// every poll and then never read it back, so a failover
		// served the new master's own stale state instead of the
		// peer's latest. A promotion failure is logged, not fatal:
		// refusing takeover entirely would leave no master at all,
		// which is worse than serving the local state.
		for _, livePath := range []string{"/etc/axonwall/state.json", "/var/lib/axonwall/state.json"} {
			promoted, err := promoteStateReplicaFile(livePath, livePath+".ha-replica")
			if err != nil {
				slog.Warn("HA sync: failed to promote verified peer state replica", "live", livePath, "error", err)
			} else if promoted {
				slog.Info("HA sync: promoted verified peer state replica to live state", "live", livePath)
			}
		}

		if autoPromote {
			slog.Info("Promoting local Headscale service to Active Master...")
			if _, err := exec.LookPath("systemctl"); err == nil {
				_ = exec.Command("systemctl", "try-reload-or-restart", "headscale").Run()
			}
		}

		m.mu.Lock()
		defer m.mu.Unlock()
		if mode == "litestream" {
			if err := m.startLitestream(); err != nil {
				slog.Error("Failed to start litestream on transition to MASTER", "error", err)
			}
		} else {
			if err := m.startMasterServer(); err != nil {
				slog.Error("Failed to start master sync server on transition to MASTER", "error", err)
			}
		}
	} else if state == "BACKUP" || state == "FAULT" {
		m.mu.Lock()
		m.cfg.NodeRole = "backup"
		m.mu.Unlock()

		if autoPromote {
			slog.Info("Demoting local node to Standby: stopping Headscale to prevent split-brain writes...")
			if _, err := exec.LookPath("systemctl"); err == nil {
				_ = exec.Command("systemctl", "stop", "headscale").Run()
			}
		}

		if mode != "litestream" {
			m.mu.Lock()
			defer m.mu.Unlock()
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

// syncMux builds the sync endpoint set shared by the plain and mTLS
// listeners (and by tests).
func (m *SqliteSyncManager) syncMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/sync/status", m.handleStatus)
	mux.HandleFunc("/api/v1/sync/db", m.handleDownloadDb)
	mux.HandleFunc("/api/v1/sync/state", m.handleDownloadState)
	mux.HandleFunc("/api/v1/sync/zfs", m.handleZfsSendStream)
	mux.HandleFunc("/api/v1/sync/k3s-token", m.handleK3sToken)
	mux.HandleFunc("/api/v1/sync/pki-enroll", m.handlePkiEnroll)
	return mux
}

// SyncTrustStatus is the operator-facing view of the HA sync trust state
// (audit D-04 Phase 3), served by the daemon's agent API at
// /v1/ha/sync-trust and rendered on the HA settings page.
type SyncTrustStatus struct {
	NodeRole              string `json:"nodeRole"`
	TransportConfigured   string `json:"transportConfigured"`
	TransportEffective    string `json:"transportEffective"`
	RequireSignedPayloads bool   `json:"requireSignedPayloads"`
	PKIEnrolled           bool   `json:"pkiEnrolled"`
	NodeCertFingerprint   string `json:"nodeCertFingerprint,omitempty"`
	CACertFingerprint     string `json:"caCertFingerprint,omitempty"`
	NodeCertSubject       string `json:"nodeCertSubject,omitempty"`
	NodeCertExpiresAt     string `json:"nodeCertExpiresAt,omitempty"`
}

// buildSyncTrustStatus assembles the trust status from the sync config,
// the transport actually in effect, and the pair's certificates (nil when
// the node has not enrolled). Both pair members share one CA and one node
// certificate, so the fingerprints shown are the pair's identity: the two
// nodes should display identical values.
// resolvedTransport maps a configured transport value onto the product
// default (audit D-04 Phase 4): only an explicit "token-http" selects the
// legacy shared-token transport; "mtls" and the empty value (configs
// written before the field existed, or by hand) both mean mTLS.
func resolvedTransport(configured string) string {
	if configured == "token-http" {
		return "token-http"
	}
	return "mtls"
}

func buildSyncTrustStatus(cfg SqliteSyncConfig, effectiveTransport string, caCert, nodeCert *x509.Certificate) SyncTrustStatus {
	configured := resolvedTransport(cfg.Transport)
	if effectiveTransport != "mtls" && effectiveTransport != "token-http" {
		effectiveTransport = configured
	}
	st := SyncTrustStatus{
		NodeRole:              cfg.NodeRole,
		TransportConfigured:   configured,
		TransportEffective:    effectiveTransport,
		RequireSignedPayloads: cfg.RequireSignedPayloads,
	}
	if caCert != nil && nodeCert != nil {
		st.PKIEnrolled = true
		st.NodeCertFingerprint = certFingerprintSHA256(nodeCert)
		st.CACertFingerprint = certFingerprintSHA256(caCert)
		st.NodeCertSubject = nodeCert.Subject.CommonName
		st.NodeCertExpiresAt = nodeCert.NotAfter.UTC().Format(time.RFC3339)
	}
	return st
}

// TrustStatus reports this node's HA sync trust state.
func (m *SqliteSyncManager) TrustStatus() SyncTrustStatus {
	m.mu.Lock()
	cfg := m.cfg
	effective := m.effectiveTransport
	m.mu.Unlock()

	caCert, _ := loadHACACert()
	nodeCert, _ := loadHANodeCert()
	if cfg.NodeRole != "master" {
		// A backup has no master server; its effective transport is what
		// the poller can resolve: mTLS only once PKI material exists.
		if resolvedTransport(cfg.Transport) == "mtls" && nodeCert != nil {
			effective = "mtls"
		} else {
			effective = "token-http"
		}
	}
	return buildSyncTrustStatus(cfg, effective, caCert, nodeCert)
}

// mtlsRequested reports whether the configuration resolves to the HA
// PKI mutual-TLS transport (audit D-04 Phases 1+4): everything except an
// explicit "token-http" opt-out.
func (m *SqliteSyncManager) mtlsRequested() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return resolvedTransport(m.cfg.Transport) == "mtls"
}

// verifyPeerPayload applies the payload-signature policy (audit D-04
// Phase 2, capability gate Phase 4b) to one downloaded payload. digest
// is the SHA-256 the receiver computed over the received bytes (already
// cross-checked against the peer's declared checksum by the caller). A
// signature that is present but invalid is always refused. A missing
// signature is refused when requireSignedPayloads is configured, or
// when the peer advertised payload signing in its sync status — the
// advertisement is what distinguishes a current master (whose unsigned
// payload means stripping or misconfiguration) from a pre-signing one
// (whose unsigned payloads are still applied, with a warning).
func (m *SqliteSyncManager) verifyPeerPayload(what string, digest []byte, sigHeader string) error {
	m.mu.Lock()
	require := m.cfg.RequireSignedPayloads
	peerSigns := m.peerSignsPayloads
	m.mu.Unlock()

	if sigHeader == "" {
		if require {
			return fmt.Errorf("%s: peer did not sign the payload and requireSignedPayloads is set; refusing to apply", what)
		}
		if peerSigns {
			return fmt.Errorf("%s: peer advertises payload signing but did not sign the payload; refusing to apply", what)
		}
		slog.Warn("HA sync payload is unsigned; applying because the peer does not advertise signing and requireSignedPayloads is off", "payload", what)
		return nil
	}
	if !haVerifyPayloadSignature(digest, sigHeader) {
		return fmt.Errorf("%s: payload signature verification FAILED; refusing to apply", what)
	}
	return nil
}

// peerClient returns the HTTP client and URL scheme the backup poller
// should use for peer data endpoints. When mTLS is requested AND the HA
// PKI material is present, the client presents the node certificate and
// verifies the peer against the shared HA CA. Otherwise it falls back to
// the plain token-authenticated client: a not-yet-enrolled node has no
// certificate to present, and enrollment itself (always plain HTTP) is
// how it gets one. The k3s-token and state/db fetchers use this client;
// enrollment never does.
func (m *SqliteSyncManager) peerClient(timeout time.Duration) (*http.Client, string) {
	if m.mtlsRequested() {
		if tlsCfg, err := LoadHAPKITLSConfig(); err == nil {
			return &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}}, "https"
		}
	}
	return &http.Client{Timeout: timeout}, "http"
}

func (m *SqliteSyncManager) startMasterServer() error {
	listenAddr := fmt.Sprintf("0.0.0.0:%d", m.cfg.ListenPort)
	if m.cfg.LocalAddress != "" && m.cfg.LocalAddress != "0.0.0.0" {
		listenAddr = fmt.Sprintf("%s:%d", m.cfg.LocalAddress, m.cfg.ListenPort)
	}

	m.server = &http.Server{
		Addr:         listenAddr,
		Handler:      m.syncMux(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 300 * time.Second,
	}

	if m.cfg.AuthToken == "" {
		slog.Error("HA sync master server has NO auth token configured: every sync request will be rejected (fail-closed) until sqliteSync.authToken is set")
	}

	// D-04 Phase 1: serve mutual TLS when the operator selected the mtls
	// transport AND HA PKI material exists. Enrollment is the bootstrap
	// that creates that material, so an mtls request on a never-enrolled
	// node falls back to token-http with a loud error instead of serving
	// nothing at all; the effective transport is reported in /status so
	// the state is observable, and flips to mtls on the next config apply
	// once the pair has enrolled.
	serveTLS := false
	if resolvedTransport(m.cfg.Transport) == "mtls" {
		if tlsCfg, err := LoadHAPKITLSConfig(); err == nil {
			m.server.TLSConfig = tlsCfg
			serveTLS = true
		} else {
			slog.Error("HA sync transport 'mtls' requested but HA PKI material is unavailable; serving token-http until the pair has enrolled (check /api/v1/sync/status transport field)", "error", err)
		}
	}
	// Callers (ApplyConfig, OnStateChange) hold m.mu.
	if serveTLS {
		m.effectiveTransport = "mtls"
	} else {
		m.effectiveTransport = "token-http"
	}

	slog.Info("Starting Unified HA Sync Master Server (SQLite + State + ZFS + K3s + Identity PKI)", "addr", listenAddr, "transport", m.effectiveTransport)
	// A-M7: this server object belongs to exactly one generation.
	// stopInternal bumps serverGen, so a retry loop whose server was
	// stopped (node demoted to BACKUP, HA disabled, config replaced)
	// can never bind later and serve the sync database from a node
	// that is no longer master. The old code only exited on
	// ErrServerClosed, and Close on a never-listening server was a
	// no-op, so the loop resurrected the stopped server on retry.
	// Callers hold m.mu here (ApplyConfig, OnStateChange), so the
	// bump is safe.
	m.serverGen++
	gen := m.serverGen
	srv := m.server
	go func() {
		// The HA sync interface address may not be assigned yet at boot;
		// keep retrying the bind instead of giving up on the first error.
		for {
			m.mu.Lock()
			retired := gen != m.serverGen
			m.mu.Unlock()
			if retired {
				slog.Info("SQLite Sync master server retry loop retiring: server was stopped or replaced", "addr", listenAddr)
				return
			}
			var err error
			if serveTLS {
				err = srv.ListenAndServeTLS("", "")
			} else {
				err = srv.ListenAndServe()
			}
			if err == nil || err == http.ErrServerClosed {
				return
			}
			slog.Error("SQLite Sync server error; retrying", "addr", listenAddr, "error", err, "retryDelay", masterServerRetryDelay)
			time.Sleep(masterServerRetryDelay)
		}
	}()

	return nil
}

func (m *SqliteSyncManager) handlePkiEnroll(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	peerIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if r.Method == http.MethodPost {
		var csrReq HAPKICSRRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&csrReq); err != nil || csrReq.CSRPEM == "" {
			http.Error(w, "Invalid CSR enrollment request", http.StatusBadRequest)
			return
		}
		extraIPs := append([]string{}, csrReq.ExtraIPs...)
		if peerIP != "" {
			extraIPs = append(extraIPs, peerIP)
		}
		csrResp, err := SignHAPKICSR([]byte(csrReq.CSRPEM), extraIPs)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to sign HA PKI CSR: %v", err), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(csrResp)
		return
	}
	bundle, err := ExportHAPKIBundle(peerIP)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to export HA PKI bundle: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(bundle)
}

// EnrollPKIFromPeer generates a local HA node CSR, submits it to the primary peer's
// /api/v1/sync/pki-enroll endpoint, and installs the returned certificates and LDAP secret.
func EnrollPKIFromPeer(peerAddr string, peerPort int, authToken string) (*HAPKICSRResponse, error) {
	csrPEM, err := GenerateHAPKICSR(nil)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(HAPKICSRRequest{CSRPEM: string(csrPEM)})
	if err != nil {
		return nil, err
	}
	enrollUrl := fmt.Sprintf("http://%s/api/v1/sync/pki-enroll", net.JoinHostPort(peerAddr, strconv.Itoa(peerPort)))
	req, err := http.NewRequest(http.MethodPost, enrollUrl, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("X-Axonwall-Sync-Token", authToken)
	}
	plainClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := plainClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pki-enroll returned status %d", resp.StatusCode)
	}
	var csrResp HAPKICSRResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&csrResp); err != nil {
		return nil, err
	}
	if err := InstallHAPKICSRResponse(&csrResp); err != nil {
		return nil, err
	}
	return &csrResp, nil
}

func (m *SqliteSyncManager) handleStatus(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	nodeRole := m.cfg.NodeRole
	transport := m.effectiveTransport
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
		NodeRole:      nodeRole,
		Timestamp:     time.Now().Unix(),
		Transport:     transport,
		Databases:     dbStatuses,
		SignsPayloads: haPayloadSigningAvailable(),
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
	// D-04 Phase 2: sign the payload digest with the HA node key when the
	// pair has enrolled. Unenrolled pairs serve unsigned; the receiver's
	// requireSignedPayloads policy decides whether that is acceptable.
	if digestBytes, err := hex.DecodeString(checksum); err == nil {
		if sig, err := haSignPayloadDigest(digestBytes); err == nil {
			w.Header().Set("X-Axonwall-Payload-Signature", sig)
		}
	}

	f, err := os.Open(tmpBackup)
	if err != nil {
		http.Error(w, "Failed to read snapshot", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	_, _ = io.Copy(w, f)
}

// pollerStopped reports whether the poller generation that owns stopCh
// has been stopped. Every apply step in pollAndSync checks it first.
func pollerStopped(stopCh <-chan struct{}) bool {
	select {
	case <-stopCh:
		return true
	default:
		return false
	}
}

func (m *SqliteSyncManager) startBackupPoller() error {
	m.stopPoller = make(chan struct{})
	pollerCtx, cancel := context.WithCancel(context.Background())
	m.pollerCancel = cancel
	m.pollerDone = make(chan struct{})
	m.pollerRunning = true

	interval := m.cfg.SyncIntervalSeconds
	if interval < 1 {
		interval = 5
	}

	slog.Info("Starting SQLite Sync Backup Poller", "intervalSeconds", interval, "peer", m.cfg.PeerAddress)

	stopCh := m.stopPoller
	done := m.pollerDone
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		// Run an immediate sync on startup
		m.pollAndSync(stopCh, pollerCtx)

		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				m.pollAndSync(stopCh, pollerCtx)
			}
		}
	}()

	return nil
}

func (m *SqliteSyncManager) pollAndSync(stopCh <-chan struct{}, pollerCtx context.Context) {
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

	client, scheme := m.peerClient(10 * time.Second)
	statusUrl := fmt.Sprintf("%s://%s/api/v1/sync/status", scheme, net.JoinHostPort(cfg.PeerAddress, strconv.Itoa(peerPort)))
	req, err := http.NewRequestWithContext(pollerCtx, "GET", statusUrl, nil)
	if err != nil {
		return
	}
	if cfg.AuthToken != "" {
		req.Header.Set("X-Axonwall-Sync-Token", cfg.AuthToken)
	}

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

	// D-04 Phase 4b: record the peer's advertised signing capability
	// for this round; verifyPeerPayload requires signatures from a
	// peer that advertises them. Set before any payload fetch below.
	m.mu.Lock()
	m.peerSignsPayloads = statusResp.SignsPayloads
	m.mu.Unlock()

	// Compare peer databases against local copies. Each apply step is
	// gated on the poller still being current: once this node stops
	// being a backup, no step below may write anything.
	for _, peerDb := range statusResp.Databases {
		if pollerStopped(stopCh) {
			return
		}
		localSha := computeFileSha256(peerDb.Path)
		if localSha != peerDb.Sha256 {
			slog.Info("Database update detected on peer. Synchronizing...",
				"database", peerDb.Path,
				"peerSha256", peerDb.Sha256,
				"localSha256", localSha,
			)

			dbClient, _ := m.peerClient(60 * time.Second)
			if err := m.fetchAndApplyDb(peerDb.Path, peerPort, dbClient, scheme, stopCh, pollerCtx); err != nil {
				slog.Error("Failed to synchronize database from peer", "path", peerDb.Path, "error", err)
			} else {
				slog.Info("Successfully synchronized database from peer", "path", peerDb.Path)
			}
		}
	}

	if pollerStopped(stopCh) {
		return
	}

	// Synchronize non-K3s appliance state (/var/lib/axonwall/state.json & Samba passdb.tdb)
	m.syncApplianceStateFromPeer(peerPort, client, scheme, stopCh, pollerCtx)

	if pollerStopped(stopCh) {
		return
	}

	// Automatically enroll HA PKI + OpenLDAP multi-provider syncrepl secret if not yet enrolled.
	// Enrollment is the PKI bootstrap and ALWAYS uses plain HTTP + the
	// shared token, even when the mtls transport is selected: a node that
	// has no certificate yet cannot present one.
	if _, err := os.Stat(HAPKICACertPath); os.IsNotExist(err) {
		if csrResp, err := EnrollPKIFromPeer(cfg.PeerAddress, peerPort, cfg.AuthToken); err == nil && csrResp != nil {
			slog.Info("HA Backup Poller: Enrolled HA PKI via CSR & LDAP replication credentials from primary peer")
			_, _ = EnsureOpenLDAPBootstrapped(csrResp.LDAPBaseDN, 2, DefaultPasswordPolicyConfig())
			_ = ConfigureMultiProviderSyncrepl(2, cfg.PeerAddress, csrResp.LDAPBaseDN)
		}
	}

	if pollerStopped(stopCh) {
		return
	}

	// Automatically fetch K3s cluster join token if not yet present on backup node
	if _, err := os.Stat("/var/lib/axonwall/k3s-join.token"); err != nil {
		if tok, err := FetchPeerClusterTokenWithClient(cfg.PeerAddress, peerPort, cfg.AuthToken, client, scheme); err == nil && tok != "" {
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
	// D-04 Phase 2: see handleDownloadDb.
	if sig, err := haSignPayloadDigest(sum[:]); err == nil {
		w.Header().Set("X-Axonwall-Payload-Signature", sig)
	}
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
	if fromSnap != "" && (!validZfsSnapshotName(fromSnap) || !strings.HasPrefix(fromSnap, dataset+"@")) {
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

// promoteStateReplicaFile atomically replaces the live appliance state
// file with the verified peer replica written by the backup poller
// (A-M8). The replica was checksum- and signature-verified when it
// was downloaded, but it is re-checked here for non-empty valid JSON
// so a torn local file can never become the live state. The swap is
// a rename within the live file's directory, so readers never observe
// a half-written state.json; the live file's mode and ownership are
// preserved. A missing replica is not an error — it only means the
// poller never fetched peer state — and the replica file itself is
// kept as the backup copy.
func promoteStateReplicaFile(livePath, replicaPath string) (bool, error) {
	data, err := os.ReadFile(replicaPath)
	if err != nil {
		return false, nil
	}
	if len(data) == 0 || !json.Valid(data) {
		return false, fmt.Errorf("peer state replica %s is empty or not valid JSON; refusing to promote", replicaPath)
	}
	dir := filepath.Dir(livePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(dir, ".state-promote-*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if fi, err := os.Stat(livePath); err == nil {
		_ = tmp.Chmod(fi.Mode().Perm())
	} else {
		_ = tmp.Chmod(0600)
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	preserveFileOwnership(tmpName, livePath)
	if err := os.Rename(tmpName, livePath); err != nil {
		return false, err
	}
	return true, nil
}

func (m *SqliteSyncManager) syncApplianceStateFromPeer(peerPort int, client *http.Client, scheme string, stopCh <-chan struct{}, pollerCtx context.Context) {
	m.mu.Lock()
	peerAddr := m.cfg.PeerAddress
	authToken := m.cfg.AuthToken
	m.mu.Unlock()

	if peerAddr == "" {
		return
	}

	stateUrl := fmt.Sprintf("%s://%s/api/v1/sync/state", scheme, net.JoinHostPort(peerAddr, strconv.Itoa(peerPort)))
	req, err := http.NewRequestWithContext(pollerCtx, http.MethodGet, stateUrl, nil)
	if err != nil {
		return
	}
	if authToken != "" {
		req.Header.Set("X-Axonwall-Sync-Token", authToken)
	}

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
	// D-04 Phase 2: verify the payload signature before the replica is
	// written; an unverifiable payload changes nothing on this node.
	if err := m.verifyPeerPayload("appliance state", actualSum[:], resp.Header.Get("X-Axonwall-Payload-Signature")); err != nil {
		slog.Warn("Peer state signature check failed, skipping sync", "error", err)
		return
	}
	if pollerStopped(stopCh) {
		return
	}
	_ = os.MkdirAll(filepath.Dir(localPath), 0755)
	_ = os.WriteFile(replicaPath, body, 0600)
}

// preserveFileOwnership best-effort chowns newPath to the owner of the
// file at targetPath — or, when the target does not exist yet, to the
// owner of its directory. The sync daemon runs as root, so a database
// it applies would otherwise land root-owned and the service that owns
// it (headscale runs as its own user since the B-12 follow-up split)
// would lose write access to its own database after the first sync.
// Failures are logged, not fatal — but loudly, for that reason.
func preserveFileOwnership(newPath, targetPath string) {
	stat, err := os.Lstat(targetPath)
	if err == nil && (stat.Mode()&os.ModeSymlink) != 0 {
		return
	}
	if err != nil {
		stat, err = os.Lstat(filepath.Dir(targetPath))
		if err != nil || (stat.Mode()&os.ModeSymlink) != 0 {
			return
		}
	}
	sys, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	if err := os.Lchown(newPath, int(sys.Uid), int(sys.Gid)); err != nil {
		slog.Warn("HA sync: could not preserve ownership on applied database", "path", targetPath, "error", err)
	}
}

func (m *SqliteSyncManager) fetchAndApplyDb(dbPath string, peerPort int, client *http.Client, scheme string, stopCh <-chan struct{}, pollerCtx context.Context) error {
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
	if info, lerr := os.Lstat(dbPath); lerr == nil && (info.Mode()&os.ModeSymlink) != 0 {
		return fmt.Errorf("refusing to overwrite symlink database path: %s", dbPath)
	}

	downloadUrl := fmt.Sprintf("%s://%s/api/v1/sync/db?path=%s", scheme, net.JoinHostPort(peerAddr, strconv.Itoa(peerPort)), url.QueryEscape(dbPath))
	req, err := http.NewRequestWithContext(pollerCtx, "GET", downloadUrl, nil)
	if err != nil {
		return err
	}
	if authToken != "" {
		req.Header.Set("X-Axonwall-Sync-Token", authToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned error %d", resp.StatusCode)
	}

	expectedSha := strings.TrimSpace(resp.Header.Get("X-Checksum-SHA256"))
	if expectedSha == "" {
		return fmt.Errorf("server response missing required X-Checksum-SHA256 header")
	}

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

	if _, err := io.Copy(writer, io.LimitReader(resp.Body, 256*1024*1024)); err != nil {
		out.Close()
		os.Remove(tmpFile)
		return fmt.Errorf("failed to stream db payload: %w", err)
	}
	out.Close()

	actualSha := hex.EncodeToString(hasher.Sum(nil))
	if actualSha != expectedSha {
		os.Remove(tmpFile)
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedSha, actualSha)
	}

	// D-04 Phase 2: verify the payload signature before the downloaded
	// database is allowed to replace the local one.
	if err := m.verifyPeerPayload("database "+dbPath, hasher.Sum(nil), resp.Header.Get("X-Axonwall-Payload-Signature")); err != nil {
		os.Remove(tmpFile)
		return err
	}

	// A-H3: final stop gate before the destructive step. The caller
	// (OnStateChange/ApplyConfig) joins the poller before starting the
	// master server, so any rename that happens here still
	// happens-before MASTER takeover; this gate additionally aborts
	// promptly instead of renaming a database this node no longer
	// wants as a backup.
	if pollerStopped(stopCh) {
		os.Remove(tmpFile)
		return fmt.Errorf("sync stopped before applying database %s", dbPath)
	}

	// A-M17: validate the downloaded bytes are a usable SQLite database
	// before they replace the live one. The checksum only proves the
	// bytes arrived as the peer sent them; the peer's own fallback serves
	// a raw copy of a live DB when `.backup` fails, so a torn copy can
	// arrive with a valid checksum and signature.
	if err := validateSqliteDbFile(tmpFile); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("downloaded database %s failed validation: %w", dbPath, err)
	}

	// A-M17: keep a backup of the database being replaced, so a bad
	// apply can be undone. The previous .bak (if any) is overwritten.
	if _, err := os.Stat(dbPath); err == nil {
		if err := copyFile(dbPath, dbPath+".bak"); err != nil {
			slog.Warn("HA sync: failed to back up replaced database", "db", dbPath, "error", err)
		}
	}

	// A-M17: pause the local consumer while its database file is
	// replaced underneath it. With autoPromoteHeadscale off, headscale
	// keeps the DB open while its WAL is deleted and the file replaced,
	// corrupting the local daemon or killing it at next access. Only a
	// service that is actually active is stopped, and it is restarted
	// on every exit path below.
	headscaleWasActive := false
	if strings.Contains(filepath.Base(dbPath), "headscale") {
		headscaleWasActive = stopServiceIfActive("headscale")
	}
	if headscaleWasActive {
		defer func() {
			if err := exec.Command("systemctl", "start", "headscale").Run(); err != nil {
				slog.Error("HA sync: FAILED to restart headscale after database replace; service is down", "error", err)
			}
		}()
	}

	// Keep the replaced database's ownership on the downloaded copy
	// (see preserveFileOwnership) before it becomes the live file.
	preserveFileOwnership(tmpFile, dbPath)

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

// validateSqliteDbFile checks a downloaded database file is a usable
// SQLite database: the 16-byte header magic, plus a full
// `PRAGMA integrity_check` when the sqlite3 CLI is available. A torn or
// non-SQLite payload must never replace the live database (A-M17).
func validateSqliteDbFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var magic [16]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return fmt.Errorf("cannot read SQLite header: %w", err)
	}
	if string(magic[:]) != "SQLite format 3\x00" {
		return fmt.Errorf("not a SQLite database (bad header magic)")
	}
	if _, err := exec.LookPath("sqlite3"); err != nil {
		slog.Warn("HA sync: sqlite3 CLI not found; skipping PRAGMA integrity_check, header magic only", "path", path)
		return nil
	}
	out, err := exec.Command("sqlite3", path, "PRAGMA integrity_check;").CombinedOutput()
	if err != nil {
		return fmt.Errorf("PRAGMA integrity_check failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	if strings.TrimSpace(string(out)) != "ok" {
		return fmt.Errorf("PRAGMA integrity_check reported corruption: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// stopServiceIfActive stops a systemd service only if it is currently
// active, reporting whether it stopped one (so the caller can restart
// exactly what it stopped). It returns false when systemctl is absent,
// the service is not active, or the stop fails (A-M17).
func stopServiceIfActive(unit string) bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	if err := exec.Command("systemctl", "is-active", "--quiet", unit).Run(); err != nil {
		return false
	}
	if err := exec.Command("systemctl", "stop", unit).Run(); err != nil {
		slog.Warn("HA sync: failed to stop service before database replace", "service", unit, "error", err)
		return false
	}
	return true
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

// stopInternal initiates shutdown of the master server, the backup
// poller and litestream. Callers hold m.mu. It deliberately does NOT
// wait for the poller goroutine: the goroutine needs m.mu while it
// winds down, so joining here would deadlock. Callers that must not
// proceed until the poller has exited (ApplyConfig, OnStateChange,
// Stop) capture m.pollerDone, release m.mu, and wait on it — the join
// that A-H3 requires, placed where it cannot deadlock.
func (m *SqliteSyncManager) stopInternal() {
	// A-M7: retire the master server object. Bumping the generation
	// makes the old retry loop exit after its sleep instead of
	// binding on a later retry; Close alone cannot do that, because
	// Close on a server that never started listening is a no-op.
	m.serverGen++
	if m.server != nil {
		_ = m.server.Close()
		m.server = nil
	}

	if m.pollerRunning {
		close(m.stopPoller)
		if m.pollerCancel != nil {
			// Aborts in-flight poller HTTP requests (status check,
			// DB download) so the join below is prompt, not 60s.
			m.pollerCancel()
			m.pollerCancel = nil
		}
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
	m.stopInternal()
	done := m.pollerDone
	m.mu.Unlock()
	if done != nil {
		<-done
	}
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
