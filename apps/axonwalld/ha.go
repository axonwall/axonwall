package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/axonwall/axonwall/apps/axonwalld/engine"
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
	Enabled     bool   `json:"enabled"`
	Interface   string `json:"interface"`
	Protocol    string `json:"protocol"`
	PeerAddress string `json:"peerAddress"`
	Port        int    `json:"port"`
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

type HAEngine struct {
	mu               sync.Mutex
	config           HAConfig
	sqliteSync       *engine.SqliteSyncManager
	nasManager       *engine.NasManager
	directoryManager *engine.DirectoryManager
	listener         net.Listener
	sockPath         string
}

func NewHAEngine(nasMgr *engine.NasManager) *HAEngine {
	return &HAEngine{
		sqliteSync: engine.NewSqliteSyncManager(),
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

func (e *HAEngine) StartSocketListener() error {
	_ = os.MkdirAll(filepath.Dir(e.sockPath), 0755)
	_ = os.Remove(e.sockPath)

	l, err := net.Listen("unix", e.sockPath)
	if err != nil {
		return fmt.Errorf("failed to listen on ha socket %s: %w", e.sockPath, err)
	}
	_ = os.Chown(e.sockPath, 0, 0)
	_ = os.Chmod(e.sockPath, 0600)
	e.listener = l

	slog.Info("HA Engine state transition socket listening", "path", e.sockPath)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go e.handleNotificationConn(conn)
		}
	}()

	return nil
}

func (e *HAEngine) handleNotificationConn(conn net.Conn) {
	defer conn.Close()

	// Verify peer credentials: only root (UID 0) is allowed to send transitions
	if uconn, ok := conn.(*net.UnixConn); ok {
		raw, err := uconn.SyscallConn()
		if err != nil {
			slog.Warn("Rejecting HA socket connection: failed to access raw conn", "error", err)
			_, _ = conn.Write([]byte("ERR: unauthorized\n"))
			return
		}
		var credErr error
		authorized := false
		if ctrlErr := raw.Control(func(fd uintptr) {
			ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
			if err != nil {
				credErr = err
				return
			}
			if ucred.Uid != 0 {
				credErr = fmt.Errorf("unauthorized caller uid %d, expected 0", ucred.Uid)
				return
			}
			authorized = true
		}); ctrlErr != nil && credErr == nil {
			credErr = ctrlErr
		}
		if credErr != nil || !authorized {
			slog.Warn("Rejecting HA socket connection from unauthorized peer", "error", credErr)
			_, _ = conn.Write([]byte("ERR: unauthorized\n"))
			return
		}
	}

	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		state := strings.ToUpper(strings.TrimSpace(scanner.Text()))
		if state == "MASTER" || state == "BACKUP" || state == "FAULT" {
			slog.Info("Received HA state transition from notify socket", "state", state)
			e.OnTransition(state)
			_, _ = conn.Write([]byte("OK\n"))
		} else {
			slog.Warn("Ignoring unrecognized state transition", "state", state)
			_, _ = conn.Write([]byte("ERR: invalid state\n"))
		}
	}
}

func (e *HAEngine) OnTransition(state string) {
	e.mu.Lock()
	defer e.mu.Unlock()

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

	e.sqliteSync.OnStateChange(state)
	if e.directoryManager != nil {
		serverID := 1
		if strings.ToLower(e.config.Role) == "secondary" || strings.ToLower(e.config.Role) == "backup" {
			serverID = 2
		}
		peerURI := ""
		if e.config.PeerIp != "" {
			peerURI = fmt.Sprintf("ldaps://%s:636", e.config.PeerIp)
		}
		e.directoryManager.SetHAState(e.config.Enabled, state, serverID, peerURI)
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
	e.mu.Lock()
	defer e.mu.Unlock()

	if !cfg.Enabled {
		e.config = cfg
		slog.Info("High Availability is disabled. Stopping Keepalived, Conntrackd, and SQLite sync.")
		_, _ = stopSystemService("keepalived")
		_, _ = stopSystemService("conntrackd")
		e.sqliteSync.Stop()
		if e.directoryManager != nil {
			e.directoryManager.SetHAState(false, "MASTER", 1, "")
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

	for _, field := range []string{cfg.SyncInterface, cfg.PeerIp, cfg.SyncPassword, cfg.ConntrackSync.Interface, cfg.ConntrackSync.PeerAddress} {
		if strings.ContainsAny(field, "\n\r\"'{};#") {
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

	if err := e.generateConntrackd(cfg); err != nil {
		return fmt.Errorf("conntrackd: %w", err)
	}

	e.config = cfg

	slog.Info("Restarting HA services (Keepalived & Conntrackd)")
	if out, err := reloadOrRestartService("keepalived"); err != nil {
		slog.Warn("Failed to reload keepalived", "error", err, "output", string(out))
	}

	if out, err := reloadOrRestartService("conntrackd"); err != nil {
		slog.Warn("Failed to reload conntrackd", "error", err, "output", string(out))
	}

	// Configure Chrony NTP peering with HA peer to keep CSN clocks strictly synchronized
	if cfg.PeerIp != "" {
		_ = os.MkdirAll("/etc/chrony/conf.d", 0755)
		chronyPeerConf := fmt.Sprintf("# Managed by Axonwall HA Engine\npeer %s iburst\nallow %s\n", cfg.PeerIp, cfg.PeerIp)
		_ = os.WriteFile("/etc/chrony/conf.d/axonwall-ha.conf", []byte(chronyPeerConf), 0644)
		_, _ = reloadOrRestartService("chrony")
	}

	// Configure OpenLDAP Multi-Provider syncrepl over mTLS (ldaps://<peerIp>:636)
	serverID := 1
	haState := "MASTER"
	if cfg.Role == "secondary" || cfg.Role == "backup" {
		serverID = 2
		haState = "BACKUP"
	}
	peerURI := ""
	if cfg.PeerIp != "" {
		peerURI = fmt.Sprintf("ldaps://%s:636", cfg.PeerIp)
	}
	if e.directoryManager != nil {
		e.directoryManager.SetHAState(true, haState, serverID, peerURI)
	}
	if cfg.PeerIp != "" {
		baseDN, _, _ := engine.ResolveOrCreateBaseDN("axonwall.local")
		if err := engine.ConfigureMultiProviderSyncrepl(serverID, cfg.PeerIp, baseDN); err != nil {
			slog.Warn("Failed to configure OpenLDAP multi-provider syncrepl", "error", err)
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
		if err := e.sqliteSync.ApplyConfig(cfg.SqliteSync); err != nil {
			slog.Error("Failed to apply SQLite sync config", "error", err)
		}
	} else {
		e.sqliteSync.Stop()
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
		if vrid <= 0 {
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

	var groupInstances []string
	for i, inst := range instances {
		instName := inst.Name
		if instName == "" {
			instName = fmt.Sprintf("VI_%d", i+1)
		}
		instName = regexp.MustCompile(`[^a-zA-Z0-9_]`).ReplaceAllString(instName, "_")
		groupInstances = append(groupInstances, instName)
	}

	conf.WriteString("vrrp_sync_group VG1 {\n    group {\n")
	for _, name := range groupInstances {
		conf.WriteString(fmt.Sprintf("        %s\n", name))
	}
	conf.WriteString("    }\n}\n\n")

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
		if vrid <= 0 {
			vrid = cfg.Vrid
		}
		if vrid <= 0 {
			vrid = i + 1
		}
		prio := inst.Priority
		if prio <= 0 {
			prio = defaultPriority
		} else if cfg.Role == "secondary" || cfg.Role == "backup" {
			if prio >= 100 {
				prio = 50
			}
		}
		pass := inst.AuthPassword
		if pass == "" {
			pass = cfg.SyncPassword
		}
		if strings.ContainsAny(iface+pass, "\n\r\"'{};#") {
			return fmt.Errorf("invalid characters in VRRP instance %s", instName)
		}

		vips := inst.VirtualIps
		if len(vips) == 0 {
			vips = []string{"10.0.99.1/24"}
		}

		conf.WriteString(fmt.Sprintf(`vrrp_instance %s {
    state %s
    interface %s
    virtual_router_id %d
    priority %d
    advert_int 1
    
    authentication {
        auth_type PASS
        auth_pass %s
    }

    virtual_ipaddress {
`, instName, state, iface, vrid, prio, pass))

		for _, vip := range vips {
			vip = strings.TrimSpace(vip)
			if vip == "" || strings.ContainsAny(vip, "\n\r\"'{};#") {
				continue
			}
			if strings.Contains(vip, " ") {
				conf.WriteString(fmt.Sprintf("        %s\n", vip))
			} else {
				conf.WriteString(fmt.Sprintf("        %s dev %s\n", vip, iface))
			}
		}

		conf.WriteString(fmt.Sprintf(`    }

    notify_master "/bin/sh -c '/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf -c; /usr/local/bin/axonwall-ha-notify MASTER'"
    notify_backup "/bin/sh -c '/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf -f; /usr/local/bin/axonwall-ha-notify BACKUP'"
    notify_fault  "/bin/sh -c '/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf -t; /usr/local/bin/axonwall-ha-notify FAULT'"
}

`))
	}

	if err := os.MkdirAll("/etc/keepalived", 0755); err != nil {
		return err
	}

	f, err := os.OpenFile("/etc/keepalived/keepalived.conf", os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("failed to open keepalived.conf safely: %w", err)
	}
	defer f.Close()
	_, err = f.WriteString(conf.String())
	return err
}

func resolveInterfaceIPv4(ifaceName string) string {
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
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
			return ip.To4().String()
		}
	}
	return ""
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

	for _, field := range []string{syncIface, peerIp} {
		if strings.ContainsAny(field, "\n\r\"'{};# \t") {
			return fmt.Errorf("invalid characters in conntrackd configuration: %q", field)
		}
	}

	localIP := resolveInterfaceIPv4(syncIface)
	if localIP == "" {
		localIP = peerIp
	}

	conf := fmt.Sprintf(`Sync {
    Mode FTFW {
        DisableExternalCache Off
        CommitTimeout 1800
        PurgeTimeout 5
    }
    
    Multicast {
        IPv4_address 225.0.0.50
        IPv4_interface %s
        Interface %s
        SndSocketBuffer 1249280
        RcvSocketBuffer 1249280
        Checksum on
    }
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
            IPv4_address 127.0.0.1
        }
    }
}
`, localIP, syncIface)

	if err := os.MkdirAll("/etc/conntrackd", 0755); err != nil {
		return err
	}

	f, err := os.OpenFile("/etc/conntrackd/conntrackd.conf", os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("failed to open conntrackd.conf safely: %w", err)
	}
	defer f.Close()
	_, err = f.Write([]byte(conf))
	return err
}

func (e *HAEngine) Stop() {
	if e.listener != nil {
		_ = e.listener.Close()
		_ = os.Remove(e.sockPath)
	}
	e.sqliteSync.Stop()
}

func sendHANotification(state string) error {
	conn, err := net.DialTimeout("unix", "/run/axonwall/ha.sock", 3*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to axonwalld ha socket: %w", err)
	}
	defer conn.Close()

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
	return nil
}
