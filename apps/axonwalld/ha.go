package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/axonwall/monorepo/apps/axonwalld/engine"
)

type HAConfig struct {
	Enabled       bool                    `json:"enabled"`
	Role          string                  `json:"role"` // "master" or "secondary" / "backup"
	Vrid          int                     `json:"vrid"`
	SyncInterface string                  `json:"syncInterface"`
	PeerIp        string                  `json:"peerIp"`
	SyncPassword  string                  `json:"syncPassword"`
	SqliteSync    engine.SqliteSyncConfig `json:"sqliteSync"`
}

type HAEngine struct {
	mu         sync.Mutex
	config     HAConfig
	sqliteSync *engine.SqliteSyncManager
	nasManager *engine.NasManager
	listener   net.Listener
	sockPath   string
}

func NewHAEngine(nasMgr *engine.NasManager) *HAEngine {
	return &HAEngine{
		sqliteSync: engine.NewSqliteSyncManager(),
		nasManager: nasMgr,
		sockPath:   "/run/axonwall/ha.sock",
	}
}

func (e *HAEngine) StartSocketListener() error {
	_ = os.MkdirAll(filepath.Dir(e.sockPath), 0755)
	_ = os.Remove(e.sockPath)

	l, err := net.Listen("unix", e.sockPath)
	if err != nil {
		return fmt.Errorf("failed to listen on ha socket %s: %w", e.sockPath, err)
	}
	_ = os.Chmod(e.sockPath, 0660)
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
	e.sqliteSync.OnStateChange(state)
	if e.nasManager != nil {
		if state == "MASTER" {
			e.nasManager.PromoteFailoverMaster()
		} else if state == "BACKUP" || state == "FAULT" {
			e.nasManager.DemoteFailoverBackup()
		}
	}
}

func (e *HAEngine) Apply(cfg HAConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.config = cfg

	if !cfg.Enabled {
		slog.Info("High Availability is disabled. Stopping Keepalived, Conntrackd, and SQLite sync.")
		_, _ = stopSystemService("keepalived")
		_, _ = stopSystemService("conntrackd")
		e.sqliteSync.Stop()
		return nil
	}

	slog.Info("Applying High Availability (HA) Configuration", "role", cfg.Role, "vrid", cfg.Vrid)

	for _, field := range []string{cfg.SyncInterface, cfg.PeerIp, cfg.SyncPassword} {
		if strings.ContainsAny(field, "\n\r\"'{}") {
			return fmt.Errorf("invalid characters in HA configuration")
		}
	}

	if err := e.generateKeepalived(cfg); err != nil {
		return fmt.Errorf("keepalived: %w", err)
	}

	if err := e.generateConntrackd(cfg); err != nil {
		return fmt.Errorf("conntrackd: %w", err)
	}

	slog.Info("Restarting HA services (Keepalived & Conntrackd)")
	if out, err := reloadOrRestartService("keepalived"); err != nil {
		slog.Warn("Failed to reload keepalived", "error", err, "output", string(out))
	}

	if out, err := reloadOrRestartService("conntrackd"); err != nil {
		slog.Warn("Failed to reload conntrackd", "error", err, "output", string(out))
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
	for _, field := range []string{cfg.SyncInterface, cfg.PeerIp, cfg.SyncPassword} {
		if strings.ContainsAny(field, "\n\r\"'{}") {
			return fmt.Errorf("invalid characters in keepalived configuration")
		}
	}

	state := "MASTER"
	priority := 100
	if cfg.Role == "secondary" || cfg.Role == "backup" {
		state = "BACKUP"
		priority = 50
	}

	conf := fmt.Sprintf(`global_defs {
    router_id AXONWALL_HA_NODE
    script_user root
    enable_script_security
}

vrrp_sync_group VG1 {
    group {
        VI_1
    }
}

vrrp_instance VI_1 {
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
        10.0.99.1/24 dev %s
    }

    notify_master "/bin/sh -c '/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf -c; /usr/local/bin/axonwall-ha-notify MASTER'"
    notify_backup "/bin/sh -c '/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf -f; /usr/local/bin/axonwall-ha-notify BACKUP'"
    notify_fault  "/bin/sh -c '/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf -t; /usr/local/bin/axonwall-ha-notify FAULT'"
}
`, state, cfg.SyncInterface, cfg.Vrid, priority, cfg.SyncPassword, cfg.SyncInterface)

	if err := os.MkdirAll("/etc/keepalived", 0755); err != nil {
		return err
	}

	f, err := os.OpenFile("/etc/keepalived/keepalived.conf", os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("failed to open keepalived.conf safely: %w", err)
	}
	defer f.Close()
	_, err = f.Write([]byte(conf))
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
	for _, field := range []string{cfg.SyncInterface, cfg.PeerIp, cfg.SyncPassword} {
		if strings.ContainsAny(field, "\n\r\"'{}") {
			return fmt.Errorf("invalid characters in conntrackd configuration")
		}
	}

	localIP := resolveInterfaceIPv4(cfg.SyncInterface)
	if localIP == "" {
		localIP = cfg.PeerIp
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
`, localIP, cfg.SyncInterface)

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
