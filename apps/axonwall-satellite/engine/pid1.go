package engine

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// EdgeInterfaceSpec represents a boot-time or hub-pushed network interface configuration.
type EdgeInterfaceSpec struct {
	Name        string `json:"name"`                  // e.g. "wan", "lan", "mgmt"
	Device      string `json:"device"`                // e.g. "eth0", "eth1"
	Address     string `json:"address,omitempty"`     // CIDR e.g. "10.0.0.1/24" or "dhcp"
	Gateway     string `json:"gateway,omitempty"`     // IP e.g. "203.0.113.1"
	IPv6Mode    string `json:"ipv6Mode,omitempty"`    // "disabled", "auto", "static", "delegated", "ula-only"
	IPv6Address string `json:"ipv6Address,omitempty"` // IPv6 CIDR e.g. "fd00::1/64"
	MTU         int    `json:"mtu,omitempty"`         // e.g. 1500 or 9000
	Enabled     bool   `json:"enabled"`
}

// EdgeRouteSpec represents a static route pushed to the super-slim edge NGFW.
type EdgeRouteSpec struct {
	Destination string `json:"destination"` // CIDR e.g. "10.20.0.0/16" or "default"
	Gateway     string `json:"gateway"`     // Next-hop IP
	Device      string `json:"device,omitempty"`
}

// EdgeBootConfig holds configuration extracted from /proc/cmdline and/or Cloud-Init datasources.
type EdgeBootConfig struct {
	HubURL            string              `json:"hubUrl,omitempty"`
	SatelliteID       string              `json:"satelliteId,omitempty"`
	Hostname          string              `json:"hostname,omitempty"`
	ZtpToken          string              `json:"ztpToken,omitempty"`
	SkuProfile        string              `json:"skuProfile,omitempty"`
	UkiSlot           string              `json:"ukiSlot,omitempty"`
	WatchdogSec       int                 `json:"watchdogSec,omitempty"`
	InsecureBootstrap bool                `json:"insecureBootstrap,omitempty"`
	CloudInitSource   string              `json:"cloudInitSource,omitempty"`
	Interfaces        []EdgeInterfaceSpec `json:"interfaces,omitempty"`
	Routes            []EdgeRouteSpec     `json:"routes,omitempty"`
}

// DefaultHardenedSysctls defines the kernel network and security parameters enforced on the edge NGFW.
// IP forwarding is intentionally NOT enabled here: it stays off (fail-closed) until a
// nftables ruleset has been successfully loaded — see EnableForwarding.
var DefaultHardenedSysctls = map[string]string{
	"net/ipv4/ip_forward":                   "0",
	"net/ipv6/conf/all/forwarding":          "0",
	"net/ipv4/tcp_syncookies":               "1",
	"net/ipv4/conf/all/rp_filter":           "1",
	"net/ipv4/conf/default/rp_filter":       "1",
	"net/ipv4/conf/all/accept_redirects":    "0",
	"net/ipv4/conf/all/send_redirects":      "0",
	"net/ipv4/conf/all/accept_source_route": "0",
	"net/ipv6/conf/all/accept_redirects":    "0",
	"net/ipv6/conf/all/accept_source_route": "0",
	"net/netfilter/nf_conntrack_max":        "524288",
	"kernel/kptr_restrict":                  "2",
	"kernel/dmesg_restrict":                 "1",
	"kernel/unprivileged_bpf_disabled":      "1",
}

// IsPID1 returns true if the current process is running as the Linux init process (PID 1).
func IsPID1() bool {
	return os.Getpid() == 1
}

// ParseKernelCmdline parses a Linux /proc/cmdline string for axonwall.* boot parameters.
// Supported parameters:
//   - axonwall.hub=wss://10.0.0.2:2966/ws/satellite
//   - axonwall.id=edge-ngfw-01
//   - axonwall.token=ztp_axon_...
//   - axonwall.sku=sku-x86-intel-n100-i226
//   - axonwall.slot=A
//   - axonwall.wan=eth0:203.0.113.2/24:203.0.113.1
//   - axonwall.lan=eth1:10.0.0.1/24
//   - axonwall.mgmt=eth2:192.168.100.1/24
func ParseKernelCmdline(cmdline string) EdgeBootConfig {
	cfg := EdgeBootConfig{
		SkuProfile: "generic-edge",
		UkiSlot:    "A",
	}

	tokens := strings.Fields(strings.TrimSpace(cmdline))
	for _, tok := range tokens {
		parts := strings.SplitN(tok, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if val == "" {
			continue
		}

		switch key {
		case "axonwall.hub":
			cfg.HubURL = val
		case "axonwall.id":
			cfg.SatelliteID = val
		case "axonwall.token":
			cfg.ZtpToken = val
		case "axonwall.sku":
			cfg.SkuProfile = val
		case "axonwall.slot":
			cfg.UkiSlot = val
		case "axonwall.insecure_bootstrap":
			cfg.InsecureBootstrap = (val == "1" || strings.EqualFold(val, "true"))
		case "axonwall.wan", "axonwall.lan", "axonwall.mgmt":
			role := strings.TrimPrefix(key, "axonwall.")
			if spec, ok := parseInterfaceBootArg(role, val); ok {
				cfg.Interfaces = append(cfg.Interfaces, spec)
			}
		}
	}

	return cfg
}

// parseInterfaceBootArg parses "<dev>:<cidr|dhcp>[:<gateway>]" into an EdgeInterfaceSpec.
func parseInterfaceBootArg(role, arg string) (EdgeInterfaceSpec, bool) {
	segments := strings.Split(arg, ":")
	if len(segments) < 2 {
		return EdgeInterfaceSpec{}, false
	}
	dev := strings.TrimSpace(segments[0])
	addr := strings.TrimSpace(segments[1])
	gw := ""
	if len(segments) >= 3 {
		gw = strings.TrimSpace(segments[2])
	}

	if !validRadioRegex.MatchString(dev) || strings.HasPrefix(dev, "-") || strings.Contains(dev, "..") {
		return EdgeInterfaceSpec{}, false
	}

	if !strings.EqualFold(addr, "dhcp") {
		if _, _, err := net.ParseCIDR(addr); err != nil {
			return EdgeInterfaceSpec{}, false
		}
	}

	if gw != "" && net.ParseIP(gw) == nil {
		return EdgeInterfaceSpec{}, false
	}

	return EdgeInterfaceSpec{
		Name:    role,
		Device:  dev,
		Address: addr,
		Gateway: gw,
		MTU:     1500,
		Enabled: true,
	}, true
}

// ApplyHardenedSysctls writes kernel sysctl values directly to <procSysRoot>/<key>
// so no external /sbin/sysctl binary is needed on the super-slim edge NGFW.
func ApplyHardenedSysctls(procSysRoot string) int {
	if procSysRoot == "" {
		procSysRoot = "/proc/sys"
	}
	applied := 0
	for relPath, val := range DefaultHardenedSysctls {
		fullPath := filepath.Join(procSysRoot, filepath.FromSlash(relPath))
		if err := os.WriteFile(fullPath, []byte(val+"\n"), 0644); err == nil {
			applied++
		}
	}
	return applied
}

// BuildEmergencyLockdownNft generates a fail-closed baseline nftables ruleset loaded at PID 1 boot
// before WAN interfaces come up. It drops unsolicited inbound traffic while permitting loopback,
// established flows, ICMPv6 neighbor discovery, and outbound control-plane communication to the Hub.
func BuildEmergencyLockdownNft(hubURL string) string {
	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# Axonwall Edge NGFW PID 1 Fail-Closed Bootstrap Lockdown\n")
	b.WriteString("flush ruleset\n\n")
	b.WriteString("table inet axonwall {\n")
	b.WriteString("  set blocked_ips {\n    type ipv4_addr;\n    flags interval;\n  }\n")
	b.WriteString("  set blocked_ips6 {\n    type ipv6_addr;\n    flags interval;\n  }\n")
	b.WriteString("  set blocked_macs {\n    type ether_addr;\n  }\n\n")
	b.WriteString("  chain input {\n")
	b.WriteString("    type filter hook input priority filter; policy drop;\n")
	b.WriteString("    ip saddr @blocked_ips drop\n")
	b.WriteString("    ip6 saddr @blocked_ips6 drop\n")
	b.WriteString("    ether saddr @blocked_macs drop\n")
	b.WriteString("    ct state established,related accept\n")
	b.WriteString("    ct state invalid drop\n")
	b.WriteString("    iif \"lo\" accept\n")
	b.WriteString("    meta l4proto ipv6-icmp accept\n")

	if u, err := url.Parse(hubURL); err == nil && u.Hostname() != "" {
		if ip := net.ParseIP(u.Hostname()); ip != nil {
			if ip.To4() != nil {
				b.WriteString(fmt.Sprintf("    ip saddr %s accept comment \"allow-axonwall-hub\"\n", ip.String()))
			} else {
				b.WriteString(fmt.Sprintf("    ip6 saddr %s accept comment \"allow-axonwall-hub\"\n", ip.String()))
			}
		}
	}

	b.WriteString("  }\n\n")
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority filter; policy drop;\n")
	b.WriteString("    ct state established,related accept\n")
	b.WriteString("    ct state invalid drop\n")
	b.WriteString("  }\n\n")
	b.WriteString("  chain output {\n")
	b.WriteString("    type filter hook output priority filter; policy accept;\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String()
}

// BootstrapPID1 initializes the Linux userland environment when axonwall-satellite runs as /init (PID 1).
func BootstrapPID1() (EdgeBootConfig, error) {
	slog.Info("Bootstrapping Axonwall Super-Slim Edge NGFW as PID 1 (/init)...")

	// 1. Mount core virtual filesystems required by the Linux kernel and network stack
	mounts := []struct {
		source string
		target string
		fstype string
		flags  uintptr
		data   string
		mode   os.FileMode
	}{
		{"proc", "/proc", "proc", syscall.MS_NOSUID | syscall.MS_NOEXEC | syscall.MS_NODEV, "", 0555},
		{"sysfs", "/sys", "sysfs", syscall.MS_NOSUID | syscall.MS_NOEXEC | syscall.MS_NODEV, "", 0555},
		{"devtmpfs", "/dev", "devtmpfs", syscall.MS_NOSUID, "mode=0755", 0755},
		{"devpts", "/dev/pts", "devpts", syscall.MS_NOSUID | syscall.MS_NOEXEC, "gid=5,mode=0620", 0755},
		{"tmpfs", "/run", "tmpfs", syscall.MS_NOSUID | syscall.MS_NODEV, "mode=0755,size=64m", 0755},
		{"tmpfs", "/tmp", "tmpfs", syscall.MS_NOSUID | syscall.MS_NODEV, "mode=1777,size=128m", 0777},
		{"bpf", "/sys/fs/bpf", "bpf", syscall.MS_NOSUID | syscall.MS_NOEXEC | syscall.MS_NODEV, "mode=0700", 0700},
	}

	for _, m := range mounts {
		_ = os.MkdirAll(m.target, m.mode)
		if err := syscall.Mount(m.source, m.target, m.fstype, m.flags, m.data); err != nil {
			// Ignore EBUSY if already mounted by kernel devtmpfs
			slog.Debug("Virtual filesystem mount note", "target", m.target, "fstype", m.fstype, "note", err)
		}
	}

	// Ensure runtime state directories exist in RAM
	for _, dir := range []string{"/etc/axonwall/certs", "/etc/wireguard", "/var/run"} {
		_ = os.MkdirAll(dir, 0700)
	}

	// 2. Set hostname
	_ = syscall.Sethostname([]byte("axonwall-edge"))

	// 3. Apply hardened kernel sysctls directly to /proc/sys
	appliedSysctls := ApplyHardenedSysctls("/proc/sys")
	slog.Info("Applied hardened kernel sysctls", "count", appliedSysctls)

	// 4. Parse /proc/cmdline for UKI boot arguments
	var bootCfg EdgeBootConfig
	if cmdlineBytes, err := os.ReadFile("/proc/cmdline"); err == nil {
		bootCfg = ParseKernelCmdline(string(cmdlineBytes))
		slog.Info("Parsed kernel command line", "sku", bootCfg.SkuProfile, "slot", bootCfg.UkiSlot, "interfaces", len(bootCfg.Interfaces))
	}

	// 5. Probe local Cloud-Init datasources (NoCloud cidata / ConfigDrive config-2 / QEMU fw_cfg)
	if ciPayload, ok := DiscoverLocalCloudInit(); ok {
		bootCfg.CloudInitSource = ciPayload.Datasource
		if err := MergeCloudInitIntoBootConfig(&bootCfg, ciPayload, "/"); err != nil {
			slog.Warn("Cloud-Init local seed merge warning", "source", ciPayload.Datasource, "error", err)
		} else {
			slog.Info("Applied autonomous Cloud-Init seed configuration", "source", ciPayload.Datasource, "id", bootCfg.SatelliteID, "interfaces", len(bootCfg.Interfaces))
		}
		if bootCfg.Hostname != "" {
			_ = syscall.Sethostname([]byte(bootCfg.Hostname))
		} else if bootCfg.SatelliteID != "" {
			_ = syscall.Sethostname([]byte(bootCfg.SatelliteID))
		}
	}

	// 6. Zombie reaping: Go's os/exec already waits on every child it spawns.
	// A global Wait4(-1) reaper would race exec.Cmd.Wait and make successful
	// `nft -f` invocations return ECHILD errors, so it is intentionally not started.

	return bootCfg, nil
}

// SetForwarding toggles kernel IPv4/IPv6 forwarding. Callers must only enable
// forwarding after a filtering ruleset has been successfully applied.
func SetForwarding(procSysRoot string, enabled bool) error {
	if procSysRoot == "" {
		procSysRoot = "/proc/sys"
	}
	val := []byte("0\n")
	if enabled {
		val = []byte("1\n")
	}
	if err := os.WriteFile(filepath.Join(procSysRoot, "net", "ipv4", "ip_forward"), val, 0644); err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(procSysRoot, "net", "ipv6", "conf", "all", "forwarding"), val, 0644)
	return nil
}

// HaltForever is used instead of os.Exit when running as PID 1: if init exits,
// the kernel panics ("Attempted to kill init!"). It logs and blocks forever so the
// hardware watchdog / operator can intervene without a kernel panic.
func HaltForever(reason string) {
	slog.Error("PID 1 halted; refusing to exit to avoid kernel panic", "reason", reason)
	select {}
}
