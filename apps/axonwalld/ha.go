package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/axonwall/axonwall/apps/axonwalld/engine"
)

// keepalivedConfPath and conntrackdConfPath are the generated daemon
// configs. Package variables (not constants) so tests can redirect
// them into temp dirs; the production values are unchanged.
var (
	keepalivedConfPath    = "/etc/keepalived/keepalived.conf"
	conntrackdConfPath    = "/etc/conntrackd/conntrackd.conf"
	haEnsurePKICertsFn    = engine.EnsureHAPKICerts
	haEnrollPKIFromPeerFn = engine.EnrollPKIFromPeer
	haConfigureSyncreplFn = engine.ConfigureMultiProviderSyncrepl
)

type VRRPInstanceConfig struct {
	Name         string   `json:"name"`
	Vrid         int      `json:"vrid"`
	Interface    string   `json:"interface"`
	Priority     int      `json:"priority"`
	VirtualIps   []string `json:"virtualIps"`
	AuthPassword string   `json:"authPassword"`
}

type ConntrackSyncConfig struct {
	Enabled         bool     `json:"enabled"`
	Interface       string   `json:"interface"`
	Protocol        string   `json:"protocol"`
	PeerAddress     string   `json:"peerAddress"`
	Port            int      `json:"port"`
	MulticastGroup  string   `json:"multicastGroup,omitempty"`
	BufferSize      int      `json:"bufferSize,omitempty"`
	FilterIgnoreIps []string `json:"filterIgnoreIps,omitempty"`
	Mode            string   `json:"mode,omitempty"`
}

type HAConfig struct {
	Enabled       bool                    `json:"enabled"`
	Role          string                  `json:"role"`     // "master" or "secondary" / "backup"
	NodeRole      string                  `json:"nodeRole"` // "master" or "backup"
	Vrid          int                     `json:"vrid"`
	SyncInterface string                  `json:"syncInterface"`
	PeerIp        string                  `json:"peerIp"`
	PeerAddress   string                  `json:"peerAddress"`
	SyncPassword  string                  `json:"syncPassword"`
	VRRPInstances []VRRPInstanceConfig    `json:"vrrpInstances"`
	ConntrackSync ConntrackSyncConfig     `json:"conntrackSync"`
	SqliteSync    engine.SqliteSyncConfig `json:"sqliteSync"`
}

type haNotifyItem struct {
	state string
	done  chan struct{}
}

type HAEngine struct {
	mu               sync.Mutex
	applyMu          sync.Mutex
	transitionMu     sync.Mutex
	config           HAConfig
	sqliteSync       *engine.SqliteSyncManager
	nasManager       *engine.NasManager
	directoryManager *engine.DirectoryManager
	pluginManager    *engine.PluginManager
	listener         net.Listener
	sockPath         string
	notifyCh         chan haNotifyItem
	workerStop       chan struct{}
	workerDone       chan struct{}
}

func NewHAEngine(nasMgr *engine.NasManager) *HAEngine {
	syncMgr := engine.NewSqliteSyncManager()
	syncMgr.SetNasManager(nasMgr)
	return &HAEngine{
		sqliteSync: syncMgr,
		nasManager: nasMgr,
		sockPath:   "/run/axonwall/ha.sock",
	}
}

func (e *HAEngine) SetK3sManager(km *engine.K3sManager) {
	if e.sqliteSync != nil {
		e.sqliteSync.SetK3sManager(km)
	}
}

func (e *HAEngine) SetDirectoryManager(dm *engine.DirectoryManager) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.directoryManager = dm
}

func (e *HAEngine) SetPluginManager(pm *engine.PluginManager) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pluginManager = pm
}

func formatLdapsPeerURI(peerIP string) string {
	if strings.TrimSpace(peerIP) == "" {
		return ""
	}
	return "ldaps://" + net.JoinHostPort(strings.TrimSpace(peerIP), "636")
}

func isSlapdActive() bool {
	if exec.Command("systemctl", "is-active", "--quiet", "slapd").Run() == nil {
		return true
	}
	return exec.Command("pgrep", "-x", "slapd").Run() == nil
}

var haIsSlapdActiveFn = isSlapdActive

func (e *HAEngine) isLDAPConfiguredForSync() bool {
	e.mu.Lock()
	dm := e.directoryManager
	pm := e.pluginManager
	e.mu.Unlock()

	if pm != nil {
		if !pm.IsPluginEnabled("directory-ldap") {
			return false
		}
		_, replErr := os.Stat(engine.LDAPReplPassFile)
		return haIsSlapdActiveFn() || replErr == nil
	}
	if dm == nil {
		return false
	}
	_, replErr := os.Stat(engine.LDAPReplPassFile)
	return haIsSlapdActiveFn() && replErr == nil
}

func (e *HAEngine) StartSocketListener() error {
	e.mu.Lock()
	oldListener := e.listener
	oldStop := e.workerStop
	oldDone := e.workerDone
	e.listener = nil
	e.workerStop = nil
	e.workerDone = nil
	e.notifyCh = nil
	sockPath := e.sockPath
	e.mu.Unlock()

	if oldListener != nil {
		_ = oldListener.Close()
	}
	if oldStop != nil {
		close(oldStop)
		if oldDone != nil {
			<-oldDone
		}
	}

	_ = os.MkdirAll(filepath.Dir(sockPath), 0755)
	_ = os.Remove(sockPath)

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("failed to listen on ha socket %s: %w", sockPath, err)
	}
	_ = os.Chown(sockPath, 0, 0)
	_ = os.Chmod(sockPath, 0600)

	notifyCh := make(chan haNotifyItem, 64)
	workerStop := make(chan struct{})
	workerDone := make(chan struct{})

	e.mu.Lock()
	e.listener = l
	e.notifyCh = notifyCh
	e.workerStop = workerStop
	e.workerDone = workerDone
	e.mu.Unlock()

	go e.runNotifyWorker(notifyCh, workerStop, workerDone)

	slog.Info("HA Engine state transition socket listening", "path", sockPath)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go e.handleNotificationConn(conn, notifyCh, workerStop)
		}
	}()

	return nil
}

func (e *HAEngine) runNotifyWorker(notifyCh <-chan haNotifyItem, stopCh <-chan struct{}, doneCh chan<- struct{}) {
	defer close(doneCh)
	for {
		select {
		case <-stopCh:
			return
		case item := <-notifyCh:
			e.OnTransition(item.state)
			close(item.done)
		}
	}
}

// haExpectedPeerUID restricts HA notify socket callers to UID 0 (root) in production;
// overridden strictly in unit tests running unprivileged.
var haExpectedPeerUID uint32

func (e *HAEngine) handleNotificationConn(conn net.Conn, notifyCh chan<- haNotifyItem, stopCh <-chan struct{}) {
	defer conn.Close()

	// Verify peer credentials: only expected UID (root UID 0 in production) is allowed to send transitions
	if uconn, ok := conn.(*net.UnixConn); ok {
		raw, err := uconn.SyscallConn()
		if err != nil {
			slog.Warn("Rejecting HA socket connection: failed to access raw conn", "error", err)
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Write([]byte("ERR: unauthorized\n"))
			return
		}
		var credErr error
		authorized := false
		expectedUID := haExpectedPeerUID
		if ctrlErr := raw.Control(func(fd uintptr) {
			ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
			if err != nil {
				credErr = err
				return
			}
			if ucred.Uid != expectedUID {
				credErr = fmt.Errorf("unauthorized caller uid %d, expected %d", ucred.Uid, expectedUID)
				return
			}
			authorized = true
		}); ctrlErr != nil && credErr == nil {
			credErr = ctrlErr
		}
		if credErr != nil || !authorized {
			slog.Warn("Rejecting HA socket connection from unauthorized peer", "error", credErr)
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Write([]byte("ERR: unauthorized\n"))
			return
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	scanner := bufio.NewScanner(io.LimitReader(conn, 4096))
	if scanner.Scan() {
		state := strings.ToUpper(strings.TrimSpace(scanner.Text()))
		if state == "MASTER" || state == "BACKUP" || state == "FAULT" {
			slog.Info("Received HA state transition from notify socket", "state", state)
			item := haNotifyItem{state: state, done: make(chan struct{})}
			select {
			case notifyCh <- item:
			case <-stopCh:
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.Write([]byte("ERR: shutting down\n"))
				return
			}
			select {
			case <-item.done:
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.Write([]byte("OK\n"))
			case <-stopCh:
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.Write([]byte("ERR: shutting down\n"))
			}
		} else {
			slog.Warn("Ignoring unrecognized state transition", "state", state)
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Write([]byte("ERR: invalid state\n"))
		}
	}
}

func (e *HAEngine) OnTransition(state string) {
	e.transitionMu.Lock()
	defer e.transitionMu.Unlock()

	e.mu.Lock()
	cfg := e.config
	dm := e.directoryManager
	e.mu.Unlock()

	slog.Info("HAEngine handling transition", "state", state)
	if state == "BACKUP" || state == "FAULT" {
		if err := engine.SetEdgeWanPortGate("tap-edge-wan", false); err != nil {
			slog.Debug("HA WAN port gate disable skipped or failed", "error", err)
		}
	} else if state == "MASTER" {
		if err := engine.SetEdgeWanPortGate("tap-edge-wan", true); err != nil {
			slog.Debug("HA WAN port gate enable skipped or failed", "error", err)
		}
	}

	if cfg.Enabled && cfg.ConntrackSync.Enabled {
		if _, err := exec.LookPath("conntrackd"); err == nil {
			ctCtx, ctCancel := context.WithTimeout(context.Background(), 5*time.Second)
			if state == "MASTER" {
				for _, arg := range []string{"-c", "-f", "-R"} {
					if err := exec.CommandContext(ctCtx, "conntrackd", arg).Run(); err != nil {
						slog.Debug("conntrackd master transition skipped or failed", "flag", arg, "error", err)
					}
				}
			} else if state == "BACKUP" || state == "FAULT" {
				for _, arg := range []string{"-t", "-n"} {
					if err := exec.CommandContext(ctCtx, "conntrackd", arg).Run(); err != nil {
						slog.Debug("conntrackd backup transition skipped or failed", "flag", arg, "error", err)
					}
				}
			}
			ctCancel()
		}
	}

	e.sqliteSync.OnStateChange(state)
	if dm != nil {
		serverID := 1
		if strings.ToLower(cfg.Role) == "secondary" || strings.ToLower(cfg.Role) == "backup" {
			serverID = 2
		}
		peerURI := formatLdapsPeerURI(cfg.PeerIp)
		dm.SetHAState(cfg.Enabled, state, serverID, peerURI)
	}
	if e.nasManager != nil {
		if state == "MASTER" {
			e.nasManager.PromoteFailoverMaster()
		} else if state == "BACKUP" || state == "FAULT" {
			e.nasManager.DemoteFailoverBackup()
		}
	}
}

// SyncTrustStatus reports the HA sync trust state (PKI enrollment,
// transports, payload-signing policy) for the agent API (D-04 Phase 3).
func (e *HAEngine) SyncTrustStatus() engine.SyncTrustStatus {
	if e.sqliteSync == nil {
		return engine.SyncTrustStatus{}
	}
	return e.sqliteSync.TrustStatus()
}

func (e *HAEngine) Apply(cfg HAConfig) error {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	if !cfg.Enabled {
		e.mu.Lock()
		e.config = cfg
		dm := e.directoryManager
		e.mu.Unlock()

		slog.Info("High Availability is disabled. Stopping Keepalived, Conntrackd, and SQLite sync.")
		_, _ = stopSystemService("keepalived")
		_, _ = stopSystemService("conntrackd")
		e.sqliteSync.Stop()
		if dm != nil {
			dm.SetHAState(false, "MASTER", 1, "")
		}
		return nil
	}

	slog.Info("Applying High Availability (HA) Configuration", "role", cfg.Role, "nodeRole", cfg.NodeRole, "vrid", cfg.Vrid)

	// Normalize Role / NodeRole
	role := strings.ToLower(cfg.Role)
	if role == "" {
		role = strings.ToLower(cfg.NodeRole)
	}
	if role == "" {
		role = "master"
	}
	cfg.Role = role

	// Normalize PeerIp / PeerAddress
	if cfg.PeerIp == "" && cfg.PeerAddress != "" {
		cfg.PeerIp = cfg.PeerAddress
	}
	if cfg.ConntrackSync.PeerAddress == "" && cfg.PeerIp != "" {
		cfg.ConntrackSync.PeerAddress = cfg.PeerIp
	}
	if cfg.ConntrackSync.Interface == "" && cfg.SyncInterface != "" {
		cfg.ConntrackSync.Interface = cfg.SyncInterface
	}

	devMap := loadInterfaceDeviceMap()
	// M4: a configured interface that resolves to nothing (a
	// placeholder name like "auto", or a logical name whose mapping
	// was deleted/disabled) used to be stored back as "" and then
	// silently replaced by "eth0" in the generators — VRRP and
	// conntrackd bound to the wrong interface while Apply returned
	// nil. Only an UNSET interface may fall back to eth0; a
	// set-but-unresolvable one fails the apply instead.
	if cfg.SyncInterface != "" {
		if resolved := resolveInterfaceDevice(cfg.SyncInterface, devMap); resolved == "" {
			return fmt.Errorf("HA sync interface %q does not resolve to a network device", cfg.SyncInterface)
		} else {
			cfg.SyncInterface = resolved
		}
	}
	if cfg.ConntrackSync.Interface != "" {
		if resolved := resolveInterfaceDevice(cfg.ConntrackSync.Interface, devMap); resolved == "" {
			return fmt.Errorf("HA conntrack sync interface %q does not resolve to a network device", cfg.ConntrackSync.Interface)
		} else {
			cfg.ConntrackSync.Interface = resolved
		}
	}
	for i := range cfg.VRRPInstances {
		if cfg.VRRPInstances[i].Interface != "" {
			if resolved := resolveInterfaceDevice(cfg.VRRPInstances[i].Interface, devMap); resolved == "" {
				return fmt.Errorf("HA VRRP instance %d interface %q does not resolve to a network device", i, cfg.VRRPInstances[i].Interface)
			} else {
				cfg.VRRPInstances[i].Interface = resolved
			}
		}
	}

	for _, field := range []string{cfg.SyncInterface, cfg.PeerIp, cfg.SyncPassword, cfg.ConntrackSync.Interface, cfg.ConntrackSync.PeerAddress} {
		if strings.ContainsAny(field, "\n\r\"'{};#! \t") {
			return fmt.Errorf("invalid characters in HA configuration: %q", field)
		}
	}
	if cfg.PeerIp != "" && net.ParseIP(cfg.PeerIp) == nil {
		return fmt.Errorf("invalid HA peer IP address: %q", cfg.PeerIp)
	}
	if cfg.ConntrackSync.PeerAddress != "" && net.ParseIP(cfg.ConntrackSync.PeerAddress) == nil {
		return fmt.Errorf("invalid conntrack sync peer IP address: %q", cfg.ConntrackSync.PeerAddress)
	}

	if err := e.generateKeepalived(cfg); err != nil {
		return fmt.Errorf("keepalived: %w", err)
	}

	if cfg.ConntrackSync.Enabled {
		if err := e.generateConntrackd(cfg); err != nil {
			return fmt.Errorf("conntrackd: %w", err)
		}
	}

	e.mu.Lock()
	e.config = cfg
	dm := e.directoryManager
	e.mu.Unlock()

	// A-M3: HA component failures are returned, not merely logged.
	// ApplyBundle fails the bundle on this error instead of entering
	// pending-confirm and promoting a configuration whose VRRP,
	// syncrepl, or sync daemon never actually applied.
	var applyErrs []error

	slog.Info("Restarting HA services (Keepalived & Conntrackd)")
	if out, err := reloadOrRestartService("keepalived"); err != nil {
		slog.Warn("Failed to reload keepalived", "error", err, "output", string(out))
		applyErrs = append(applyErrs, fmt.Errorf("keepalived reload: %w (output: %s)", err, strings.TrimSpace(string(out))))
	}

	if cfg.ConntrackSync.Enabled {
		if out, err := reloadOrRestartService("conntrackd"); err != nil {
			slog.Warn("Failed to reload conntrackd", "error", err, "output", string(out))
			applyErrs = append(applyErrs, fmt.Errorf("conntrackd reload: %w (output: %s)", err, strings.TrimSpace(string(out))))
		}
	} else {
		_, _ = stopSystemService("conntrackd")
	}

	// Configure Chrony NTP peering with HA peer to keep CSN clocks strictly synchronized
	if cfg.PeerIp != "" {
		chronyDir := "/etc/chrony/conf.d"
		if _, err := os.Stat(chronyDir); os.IsNotExist(err) {
			if st, err2 := os.Stat("/etc/chrony.d"); err2 == nil && st.IsDir() {
				chronyDir = "/etc/chrony.d"
			}
		}
		_ = os.MkdirAll(chronyDir, 0755)
		chronyPeerConf := fmt.Sprintf("# Managed by Axonwall HA Engine\npeer %s iburst\nallow %s\n", cfg.PeerIp, cfg.PeerIp)
		_ = os.WriteFile(filepath.Join(chronyDir, "axonwall-ha.conf"), []byte(chronyPeerConf), 0644)
		_, _ = reloadOrRestartService("chrony")
	}

	// Configure OpenLDAP Multi-Provider syncrepl over mTLS (ldaps://<peerIp>:636)
	serverID := 1
	haState := "MASTER"
	if cfg.Role == "secondary" || cfg.Role == "backup" {
		serverID = 2
		haState = "BACKUP"
	}
	peerURI := formatLdapsPeerURI(cfg.PeerIp)
	if dm != nil {
		dm.SetHAState(true, haState, serverID, peerURI)
	}
	if cfg.PeerIp != "" {
		localSyncIP := resolveInterfaceIPForPeer(cfg.SyncInterface, cfg.PeerIp)
		if serverID == 1 {
			if err := haEnsurePKICertsFn("axonwall-ha", localSyncIP, cfg.PeerIp); err != nil {
				slog.Warn("Failed to ensure HA PKI certificates", "error", err)
				applyErrs = append(applyErrs, fmt.Errorf("ha pki certs: %w", err))
			}
		} else {
			peerPort := cfg.SqliteSync.PeerPort
			if peerPort <= 0 {
				peerPort = cfg.SqliteSync.ListenPort
			}
			if peerPort <= 0 {
				peerPort = 9876
			}
			authToken := cfg.SqliteSync.AuthToken
			if authToken == "" {
				if cfg.SyncPassword != "" {
					authToken = cfg.SyncPassword
				} else if len(cfg.VRRPInstances) > 0 && cfg.VRRPInstances[0].AuthPassword != "" {
					authToken = cfg.VRRPInstances[0].AuthPassword
				}
			}
			if _, err := os.Stat(engine.HAPKIPeerCertPath); os.IsNotExist(err) {
				if _, enrollErr := haEnrollPKIFromPeerFn(cfg.PeerIp, peerPort, authToken); enrollErr != nil {
					slog.Warn("Initial HA PKI enrollment from peer deferred (backup poller will retry)", "peer", cfg.PeerIp, "error", enrollErr)
				} else {
					slog.Info("Enrolled HA PKI from primary peer during HA apply", "peer", cfg.PeerIp)
				}
			}
		}
		if e.isLDAPConfiguredForSync() {
			baseDN, _, _ := engine.ResolveOrCreateBaseDN("axonwall.local")
			if serverID == 1 || engine.HasHAPKI() {
				if err := haConfigureSyncreplFn(serverID, cfg.PeerIp, baseDN); err != nil {
					slog.Warn("Failed to configure OpenLDAP multi-provider syncrepl", "error", err)
					applyErrs = append(applyErrs, fmt.Errorf("syncrepl: %w", err))
				}
			}
		} else {
			slog.Debug("Skipping OpenLDAP syncrepl configuration: OpenLDAP directory sync is not enabled/configured")
		}
	}

	// Apply Distributed SQLite Sync
	if cfg.SqliteSync.Enabled {
		if cfg.SqliteSync.NodeRole == "" {
			if cfg.Role == "master" || cfg.Role == "primary" {
				cfg.SqliteSync.NodeRole = "master"
			} else {
				cfg.SqliteSync.NodeRole = "backup"
			}
		}
		if cfg.SqliteSync.PeerAddress == "" && cfg.PeerIp != "" {
			cfg.SqliteSync.PeerAddress = cfg.PeerIp
		}
		if cfg.SqliteSync.AuthToken == "" {
			if cfg.SyncPassword != "" {
				cfg.SqliteSync.AuthToken = cfg.SyncPassword
			} else if len(cfg.VRRPInstances) > 0 && cfg.VRRPInstances[0].AuthPassword != "" {
				cfg.SqliteSync.AuthToken = cfg.VRRPInstances[0].AuthPassword
			}
		}
		if err := e.sqliteSync.ApplyConfig(cfg.SqliteSync); err != nil {
			slog.Error("Failed to apply SQLite sync config", "error", err)
			applyErrs = append(applyErrs, fmt.Errorf("sqlite sync: %w", err))
		}
	} else {
		e.sqliteSync.Stop()
	}

	// The chrony NTP peering reload above stays best-effort: a stale
	// NTP peer does not invalidate the HA configuration itself.
	if len(applyErrs) > 0 {
		return errors.Join(applyErrs...)
	}
	return nil
}

func (e *HAEngine) ApplyFromJSON(content []byte) error {
	var cfg HAConfig
	if err := json.Unmarshal(content, &cfg); err != nil {
		return fmt.Errorf("failed to parse HA config json: %w", err)
	}
	return e.Apply(cfg)
}

func (e *HAEngine) generateKeepalived(cfg HAConfig) error {
	state := "MASTER"
	defaultPriority := 100
	if cfg.Role == "secondary" || cfg.Role == "backup" {
		state = "BACKUP"
		defaultPriority = 50
	}

	instances := cfg.VRRPInstances
	if len(instances) == 0 {
		vrid := cfg.Vrid
		if vrid == 0 {
			vrid = 1
		}
		iface := cfg.SyncInterface
		if iface == "" {
			iface = "eth0"
		}
		instances = []VRRPInstanceConfig{
			{
				Name:         "VI_1",
				Vrid:         vrid,
				Interface:    iface,
				Priority:     defaultPriority,
				VirtualIps:   []string{"10.0.99.1/24"},
				AuthPassword: cfg.SyncPassword,
			},
		}
	}

	var conf strings.Builder
	conf.WriteString(`global_defs {
    router_id AXONWALL_HA_NODE
    script_user root
    enable_script_security
}

`)

	sanitizeRe := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	usedNames := make(map[string]bool, len(instances))
	var groupInstances []string
	for i, inst := range instances {
		instName := sanitizeRe.ReplaceAllString(strings.TrimSpace(inst.Name), "_")
		if strings.Trim(instName, "_") == "" {
			instName = fmt.Sprintf("VI_%d", i+1)
		}
		base := instName
		suffix := 2
		for usedNames[instName] {
			instName = fmt.Sprintf("%s_%d", base, suffix)
			suffix++
		}
		usedNames[instName] = true
		groupInstances = append(groupInstances, instName)
	}

	conf.WriteString("vrrp_sync_group VG1 {\n    group {\n")
	for _, name := range groupInstances {
		conf.WriteString(fmt.Sprintf("        %s\n", name))
	}
	conf.WriteString(`    }
    notify_master "/usr/local/bin/axonwall-ha-notify MASTER"
    notify_backup "/usr/local/bin/axonwall-ha-notify BACKUP"
    notify_fault  "/usr/local/bin/axonwall-ha-notify FAULT"
}

`)

	validKeepalivedDevRe := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,14}$`)
	for i, inst := range instances {
		instName := groupInstances[i]
		iface := inst.Interface
		if iface == "" {
			iface = cfg.SyncInterface
		}
		if iface == "" {
			iface = "eth0"
		}
		vrid := inst.Vrid
		if vrid == 0 {
			vrid = cfg.Vrid
		}
		if vrid == 0 {
			vrid = i + 1
		}
		if vrid < 1 || vrid > 255 {
			return fmt.Errorf("invalid VRRP instance %s virtual_router_id %d: must be between 1 and 255", instName, vrid)
		}
		prio := inst.Priority
		if prio == 0 {
			prio = defaultPriority
		} else {
			if prio < 1 || prio > 255 {
				return fmt.Errorf("invalid VRRP instance %s priority %d: must be between 1 and 255", instName, prio)
			}
			if cfg.Role == "secondary" || cfg.Role == "backup" {
				if prio >= 100 {
					prio = 50
				}
			}
		}
		pass := inst.AuthPassword
		if pass == "" {
			pass = cfg.SyncPassword
		}
		if strings.ContainsAny(iface+pass, "\n\r\"'{};#! \t") {
			return fmt.Errorf("invalid characters in VRRP instance %s", instName)
		}

		vips := inst.VirtualIps
		if len(vips) == 0 {
			vips = []string{"10.0.99.1/24"}
		}

		authBlock := ""
		if pass != "" {
			authBlock = fmt.Sprintf(`
    authentication {
        auth_type PASS
        auth_pass %s
    }
`, pass)
		}

		conf.WriteString(fmt.Sprintf(`vrrp_instance %s {
    state %s
    interface %s
    virtual_router_id %d
    priority %d
    advert_int 1
%s`, instName, state, iface, vrid, prio, authBlock))

		var vipLines []string
		for _, vip := range vips {
			vip = strings.TrimSpace(vip)
			if vip == "" || strings.ContainsAny(vip, "\n\r\"'{};#") {
				continue
			}
			fields := strings.Fields(vip)
			if len(fields) == 0 {
				continue
			}
			addrToken := fields[0]
			if _, _, err := net.ParseCIDR(addrToken); err != nil && net.ParseIP(addrToken) == nil {
				continue
			}
			targetDev := iface
			if len(fields) == 3 && fields[1] == "dev" && validKeepalivedDevRe.MatchString(fields[2]) && !strings.Contains(fields[2], "..") {
				targetDev = fields[2]
			} else if len(fields) != 1 {
				continue
			}
			vipLines = append(vipLines, fmt.Sprintf("        %s dev %s\n", addrToken, targetDev))
		}
		if len(vipLines) > 0 {
			conf.WriteString("\n    virtual_ipaddress {\n")
			for _, line := range vipLines {
				conf.WriteString(line)
			}
			conf.WriteString("    }\n")
		}

		conf.WriteString("}\n\n")
	}

	if err := os.MkdirAll(filepath.Dir(keepalivedConfPath), 0755); err != nil {
		return err
	}

	f, err := os.OpenFile(keepalivedConfPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("failed to open keepalived.conf safely: %w", err)
	}
	defer f.Close()
	_, err = f.WriteString(conf.String())
	return err
}

func resolveInterfaceIP(ifaceName string, wantV6 bool) string {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if wantV6 {
			if ip.To4() == nil && !ip.IsLinkLocalUnicast() {
				return ip.String()
			}
		} else if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

func resolveInterfaceIPv4(ifaceName string) string {
	return resolveInterfaceIP(ifaceName, false)
}

func resolveInterfaceIPForPeer(ifaceName, peerIP string) string {
	parsed := net.ParseIP(strings.TrimSpace(peerIP))
	if parsed != nil && parsed.To4() == nil {
		if v6 := resolveInterfaceIP(ifaceName, true); v6 != "" {
			return v6
		}
	}
	return resolveInterfaceIP(ifaceName, false)
}

func (e *HAEngine) generateConntrackd(cfg HAConfig) error {
	syncIface := cfg.ConntrackSync.Interface
	if syncIface == "" {
		syncIface = cfg.SyncInterface
	}
	if syncIface == "" {
		syncIface = "eth0"
	}
	peerIp := cfg.ConntrackSync.PeerAddress
	if peerIp == "" {
		peerIp = cfg.PeerIp
	}

	for _, field := range []string{syncIface, peerIp, cfg.ConntrackSync.Protocol, cfg.ConntrackSync.Mode, cfg.ConntrackSync.MulticastGroup} {
		if strings.ContainsAny(field, "\n\r\"'{};#! \t") {
			return fmt.Errorf("invalid characters in conntrackd configuration: %q", field)
		}
	}
	if peerIp != "" && net.ParseIP(peerIp) == nil {
		return fmt.Errorf("invalid conntrackd peer address: %q", peerIp)
	}
	if cfg.ConntrackSync.MulticastGroup != "" && net.ParseIP(cfg.ConntrackSync.MulticastGroup) == nil {
		return fmt.Errorf("invalid conntrackd multicast group: %q", cfg.ConntrackSync.MulticastGroup)
	}

	port := cfg.ConntrackSync.Port
	if port == 0 {
		port = 3780
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid conntrackd port %d: must be between 1 and 65535", port)
	}
	bufSize := cfg.ConntrackSync.BufferSize
	if bufSize <= 0 {
		bufSize = 1249280
	}

	proto := strings.ToLower(strings.TrimSpace(cfg.ConntrackSync.Protocol))
	mode := strings.ToLower(strings.TrimSpace(cfg.ConntrackSync.Mode))
	transportBlock := ""

	switch {
	case proto == "udp" || proto == "tcp" || (proto == "" && (mode == "unicast" || (mode != "multicast" && peerIp != ""))):
		if peerIp == "" {
			return fmt.Errorf("conntrackd unicast transport requires peer address")
		}
		blockName := "UDP"
		if proto == "tcp" {
			blockName = "TCP"
		}
		parsedPeer := net.ParseIP(peerIp)
		isV6 := parsedPeer != nil && parsedPeer.To4() == nil
		localIP := resolveInterfaceIP(syncIface, isV6)
		var addrLines strings.Builder
		if isV6 {
			if localIP != "" {
				addrLines.WriteString(fmt.Sprintf("        IPv6_address %s\n", localIP))
			}
			addrLines.WriteString(fmt.Sprintf("        IPv6_Destination_Address %s\n", peerIp))
		} else {
			if localIP != "" {
				addrLines.WriteString(fmt.Sprintf("        IPv4_address %s\n", localIP))
			}
			addrLines.WriteString(fmt.Sprintf("        IPv4_Destination_Address %s\n", peerIp))
		}
		transportBlock = fmt.Sprintf(`    %s {
%s        Port %d
        Interface %s
        SndSocketBuffer %d
        RcvSocketBuffer %d
        Checksum on
    }`, blockName, addrLines.String(), port, syncIface, bufSize, bufSize)
	case proto == "multicast" || proto == "":
		mcastAddr := strings.TrimSpace(cfg.ConntrackSync.MulticastGroup)
		if mcastAddr == "" {
			mcastAddr = "225.0.0.50"
		}
		parsedMcast := net.ParseIP(mcastAddr)
		isV6 := parsedMcast != nil && parsedMcast.To4() == nil
		localIP := resolveInterfaceIP(syncIface, isV6)
		var mcastLines strings.Builder
		if isV6 {
			mcastLines.WriteString(fmt.Sprintf("        IPv6_address %s\n", mcastAddr))
			if localIP != "" {
				mcastLines.WriteString(fmt.Sprintf("        IPv6_interface %s\n", localIP))
			}
		} else {
			mcastLines.WriteString(fmt.Sprintf("        IPv4_address %s\n", mcastAddr))
			if localIP != "" {
				mcastLines.WriteString(fmt.Sprintf("        IPv4_interface %s\n", localIP))
			}
		}
		transportBlock = fmt.Sprintf(`    Multicast {
%s        Interface %s
        SndSocketBuffer %d
        RcvSocketBuffer %d
        Checksum on
    }`, mcastLines.String(), syncIface, bufSize, bufSize)
	default:
		return fmt.Errorf("unsupported conntrackd protocol %q", cfg.ConntrackSync.Protocol)
	}

	ignoreEntries := []string{
		"            IPv4_address 127.0.0.1",
		"            IPv6_address ::1",
	}
	for _, ipStr := range cfg.ConntrackSync.FilterIgnoreIps {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" || strings.ContainsAny(ipStr, "\n\r\"'{};#! \t") {
			continue
		}
		if ipStr == "127.0.0.1" || ipStr == "::1" {
			continue
		}
		var parsed net.IP
		if ip, _, err := net.ParseCIDR(ipStr); err == nil {
			parsed = ip
		} else {
			parsed = net.ParseIP(ipStr)
		}
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			ignoreEntries = append(ignoreEntries, fmt.Sprintf("            IPv4_address %s", ipStr))
		} else {
			ignoreEntries = append(ignoreEntries, fmt.Sprintf("            IPv6_address %s", ipStr))
		}
	}

	conf := fmt.Sprintf(`Sync {
    Mode FTFW {
        DisableExternalCache Off
        CommitTimeout 1800
        PurgeTimeout 5
    }
    
%s
}

General {
    HashSize 32768
    HashLimit 131072
    LogFile on
    Syslog on
    LockFile /var/lock/conntrack.lock
    UNIX {
        Path /var/run/conntrackd.ctl
        Backlog 20
    }
    NetlinkBufferSize 2097152
    NetlinkBufferSizeMaxGrowth 8388608
    Filter From Userspace {
        Protocol Accept {
            TCP
            UDP
            ICMP
        }
        Address Ignore {
%s
        }
    }
}
`, transportBlock, strings.Join(ignoreEntries, "\n"))

	if err := os.MkdirAll(filepath.Dir(conntrackdConfPath), 0755); err != nil {
		return err
	}

	f, err := os.OpenFile(conntrackdConfPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("failed to open conntrackd.conf safely: %w", err)
	}
	defer f.Close()
	_, err = f.Write([]byte(conf))
	return err
}

func (e *HAEngine) Stop() {
	e.mu.Lock()
	l := e.listener
	sockPath := e.sockPath
	stopCh := e.workerStop
	doneCh := e.workerDone
	e.listener = nil
	e.notifyCh = nil
	e.workerStop = nil
	e.workerDone = nil
	e.mu.Unlock()

	if l != nil {
		_ = l.Close()
		_ = os.Remove(sockPath)
	}
	if stopCh != nil {
		close(stopCh)
		if doneCh != nil {
			<-doneCh
		}
	}
	e.sqliteSync.Stop()
}

func sendHANotification(state string) error {
	conn, err := net.DialTimeout("unix", "/run/axonwall/ha.sock", 3*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to axonwalld ha socket: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintf(conn, "%s\n", state); err != nil {
		return fmt.Errorf("failed to send notification: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		reply := scanner.Text()
		if strings.HasPrefix(reply, "OK") {
			return nil
		}
		return fmt.Errorf("server reply: %s", reply)
	}
	// L7: a dropped connection (no reply) used to return nil, so the
	// keepalived notify path exited 0 and the MASTER/BACKUP/FAULT
	// transition was treated as delivered while the daemon never ran
	// OnTransition. A missing reply is a delivery failure.
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("no reply from axonwalld ha socket: %w", err)
	}
	return fmt.Errorf("no reply from axonwalld ha socket: connection closed without a reply")
}
