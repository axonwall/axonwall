package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

type HAConfig struct {
	Enabled       bool
	Role          string
	Vrid          int
	SyncInterface string
	PeerIp        string
	SyncPassword  string
}

type HAEngine struct {
	config HAConfig
}

func NewHAEngine() *HAEngine {
	return &HAEngine{}
}

func (e *HAEngine) Apply(cfg HAConfig) error {
	e.config = cfg

	if !cfg.Enabled {
		slog.Info("High Availability is disabled. Stopping Keepalived and Conntrackd.")
		exec.Command("systemctl", "stop", "keepalived").Run()
		exec.Command("systemctl", "stop", "conntrackd").Run()
		return nil
	}

	slog.Info("Applying High Availability (HA) Configuration", "role", cfg.Role, "vrid", cfg.Vrid)

	if err := e.generateKeepalived(cfg); err != nil {
		return fmt.Errorf("keepalived: %w", err)
	}

	if err := e.generateConntrackd(cfg); err != nil {
		return fmt.Errorf("conntrackd: %w", err)
	}

	slog.Info("Restarting HA services (Keepalived & Conntrackd)")
	if out, err := exec.Command("systemctl", "try-reload-or-restart", "keepalived").CombinedOutput(); err != nil {
		slog.Warn("Failed to reload keepalived", "error", err, "output", string(out))
	}

	if out, err := exec.Command("systemctl", "try-reload-or-restart", "conntrackd").CombinedOutput(); err != nil {
		slog.Warn("Failed to reload conntrackd", "error", err, "output", string(out))
	}

	return nil
}

func (e *HAEngine) generateKeepalived(cfg HAConfig) error {
	state := "MASTER"
	priority := 100
	if cfg.Role == "secondary" {
		state = "BACKUP"
		priority = 50
	}

	conf := fmt.Sprintf(`global_defs {
    router_id AXONWALL_HA_NODE
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

    # Virtual IPs would be dynamically populated here based on DesiredState
    virtual_ipaddress {
        10.0.99.1/24 dev %s
    }
}
`, state, cfg.SyncInterface, cfg.Vrid, priority, cfg.SyncPassword, cfg.SyncInterface)

	if err := os.MkdirAll("/etc/keepalived", 0755); err != nil {
		return err
	}
	
	f, err := os.OpenFile("/etc/keepalived/keepalived.conf", os.O_WRONLY|os.O_CREATE|os.O_TRUNC|0x20000, 0600) // O_NOFOLLOW = 0x20000 on Linux
	if err != nil {
		return fmt.Errorf("failed to open keepalived.conf safely: %w", err)
	}
	defer f.Close()
	_, err = f.Write([]byte(conf))
	return err
}

func (e *HAEngine) generateConntrackd(cfg HAConfig) error {
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
`, cfg.PeerIp, cfg.SyncInterface)

	if err := os.MkdirAll("/etc/conntrackd", 0755); err != nil {
		return err
	}
	
	f, err := os.OpenFile("/etc/conntrackd/conntrackd.conf", os.O_WRONLY|os.O_CREATE|os.O_TRUNC|0x20000, 0600)
	if err != nil {
		return fmt.Errorf("failed to open conntrackd.conf safely: %w", err)
	}
	defer f.Close()
	_, err = f.Write([]byte(conf))
	return err
}
