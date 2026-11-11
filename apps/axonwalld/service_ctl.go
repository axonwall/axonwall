package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// serviceCommandTimeout bounds every systemctl/service invocation made
// on behalf of bundle/API callers (A-M2). A hung unit must delay one
// operation, never wedge the agent API forever. Package variable so
// tests can shorten it.
var serviceCommandTimeout = 90 * time.Second

// managedServices is the allowlist of units the daemon may reload,
// restart, or stop on behalf of bundle/API callers (audit D-S03). Before
// this list existed, any name surviving a "/" check reached systemctl as
// argv, so a name like "--all" was parsed as a systemctl OPTION and any
// unit on the box could be bounced by a socket caller.
var managedServices = map[string]bool{
	"suricata": true, "crowdsec": true, "crowdsec-firewall-bouncer": true,
	"kea-dhcp4-server": true, "kea-dhcp6-server": true, "kea-dhcp-ddns-server": true,
	"radvd": true, "avahi-daemon": true, "miniupnpd": true,
	"unbound": true, "frr": true, "caddy": true, "headscale": true,
	"keepalived": true, "conntrackd": true, "nftables": true,
	"ssh": true, "sshd": true,
	"slapd": true, "sssd": true, "chrony": true,
	"wg-quick@wg0": true, "rosenpass": true,
	"haproxy": true, "freeradius": true,
	"openvpn": true, "openvpn@server": true,
	"strongswan": true, "strongswan-starter": true,
	"smbd": true, "nmbd": true, "wsdd": true, "minio": true,
	"nfs-server": true, "nfs-kernel-server": true, "tgt": true, "rtslib-fb-targetctl": true,
	"k3s": true, "libvirtd": true, "nut-server": true, "nut-monitor": true, "nut-client": true, "snmpd": true,
	"tailscaled": true, "ntopng": true, "eluvix": true,
	"clamav-freshclam": true, "clamav-daemon": true, "vector": true,
}

func isSafeInstanceToken(tok string) bool {
	if tok == "" || len(tok) > 32 {
		return false
	}
	for _, r := range tok {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func validServiceName(svc string) bool {
	unit := strings.TrimSuffix(svc, ".service")
	if managedServices[unit] {
		return true
	}
	if strings.HasPrefix(unit, "wg-quick@") && isSafeInstanceToken(strings.TrimPrefix(unit, "wg-quick@")) {
		return true
	}
	if strings.HasPrefix(unit, "openvpn@") && isSafeInstanceToken(strings.TrimPrefix(unit, "openvpn@")) {
		return true
	}
	if strings.HasPrefix(unit, "openvpn-server@") && isSafeInstanceToken(strings.TrimPrefix(unit, "openvpn-server@")) {
		return true
	}
	return false
}

func keaHasActiveInterfaces() bool {
	raw, err := os.ReadFile("/etc/kea/kea-dhcp4.conf")
	if err != nil {
		return false
	}
	var parsed struct {
		Dhcp4 struct {
			InterfacesConfig struct {
				Interfaces []string `json:"interfaces"`
			} `json:"interfaces-config"`
		} `json:"Dhcp4"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return false
	}
	return len(parsed.Dhcp4.InterfacesConfig.Interfaces) > 0
}

func keaHasActiveInterfaces6() bool {
	raw, err := os.ReadFile("/etc/kea/kea-dhcp6.conf")
	if err != nil {
		return false
	}
	var parsed struct {
		Dhcp6 struct {
			InterfacesConfig struct {
				Interfaces []string `json:"interfaces"`
			} `json:"interfaces-config"`
		} `json:"Dhcp6"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return false
	}
	return len(parsed.Dhcp6.InterfacesConfig.Interfaces) > 0
}

func reloadOrRestartService(svc string) ([]byte, error) {
	if !validServiceName(svc) {
		return nil, fmt.Errorf("service %q is not in the managed-services allowlist", svc)
	}
	unit := strings.TrimSuffix(svc, ".service")
	if unit == "kea-dhcp4-server" && !keaHasActiveInterfaces() {
		return stopSystemService(svc)
	}
	if unit == "kea-dhcp6-server" && !keaHasActiveInterfaces6() {
		return stopSystemService(svc)
	}
	ctx, cancel := context.WithTimeout(context.Background(), serviceCommandTimeout)
	defer cancel()
	if _, err := exec.LookPath("systemctl"); err == nil {
		return exec.CommandContext(ctx, "systemctl", "reload-or-restart", svc).CombinedOutput()
	}
	return exec.CommandContext(ctx, "service", unit, "restart").CombinedOutput()
}

func stopSystemService(svc string) ([]byte, error) {
	if !validServiceName(svc) {
		return nil, fmt.Errorf("service %q is not in the managed-services allowlist", svc)
	}
	ctx, cancel := context.WithTimeout(context.Background(), serviceCommandTimeout)
	defer cancel()
	if _, err := exec.LookPath("systemctl"); err == nil {
		return exec.CommandContext(ctx, "systemctl", "stop", svc).CombinedOutput()
	}
	return exec.CommandContext(ctx, "service", strings.TrimSuffix(svc, ".service"), "stop").CombinedOutput()
}

// dhcpPidFilesForDev lists the pidfiles a DHCP client for one device
// writes. The daemon-global dhcpcd pidfiles are deliberately NOT in
// this list (M5): a dhcpcd daemon managing any interface at all used
// to make every later DHCP WAN look "already running", so the second
// WAN never got a client.
func dhcpPidFilesForDev(dev string) []string {
	return []string{
		"/var/run/dhclient." + dev + ".pid",
		"/var/run/dhcpcd/" + dev + ".pid",
		"/var/run/dhcpcd/" + dev + "-4.pid",
		"/var/run/dhcpcd-" + dev + ".pid",
		"/var/run/dhcpcd-" + dev + "-4.pid",
		"/run/dhcpcd/" + dev + ".pid",
		"/run/dhcpcd/" + dev + "-4.pid",
		"/run/dhcpcd-" + dev + ".pid",
		"/run/dhcpcd-" + dev + "-4.pid",
		"/var/run/udhcpc." + dev + ".pid",
		"/run/udhcpc." + dev + ".pid",
	}
}

// pidBelongsToDhcpClient reports whether pid is a live process whose
// command line names a DHCP client. A pidfile whose pid was recycled
// by an unrelated process must not count as a running client (M5).
// When the command line cannot be read, liveness (signal 0) alone is
// the verdict, matching the old behaviour.
func pidBelongsToDhcpClient(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return false
	}
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return true
	}
	return strings.Contains(strings.ToLower(string(cmdline)), "dhcp")
}

// dhcpClientRunningForDev reports whether a DHCP client started by
// the system is already alive for dev, based on the clients'
// per-device pidfiles. It is split out from dhcpClientRunning so
// tests can point it at temp pidfiles.
func dhcpClientRunningForDev(dev string, pidFiles []string) bool {
	for _, pidFile := range pidFiles {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 0 {
			continue
		}
		if pidBelongsToDhcpClient(pid) {
			return true
		}
	}
	return false
}

// dhcpClientRunning reports whether a DHCP client started by the system
// networking path (ifup/dhcpcd, dhclient, udhcpc, or an earlier boot-apply) is
// already alive for dev, based on the clients' per-device pidfiles.
// A running dhcpcd daemon for ANOTHER device does not count: dhcpcd
// is asked to manage a new device with `dhcpcd -4 <dev>` even when
// the daemon already exists (M5).
func dhcpClientRunning(dev string) bool {
	return dhcpClientRunningForDev(dev, dhcpPidFilesForDev(dev))
}

func triggerDhcpClient(dev string, roles ...string) {
	if dev == "" {
		return
	}
	role := "wan"
	if len(roles) > 0 && roles[0] != "" {
		role = strings.ToLower(strings.TrimSpace(roles[0]))
	}
	if dhcpClientRunning(dev) {
		log.Printf("[Agent] DHCP client already running on %s; not starting another", dev)
		return
	}
	go func() {
		if dhcpcdPath, err := exec.LookPath("dhcpcd"); err == nil {
			if role != "wan" {
				_ = exec.Command(dhcpcdPath, "-4", "-G", "-C", "resolv.conf", dev).Run()
			} else {
				_ = exec.Command(dhcpcdPath, "-4", dev).Run()
			}
		} else if dhclientPath, err := exec.LookPath("dhclient"); err == nil {
			_ = exec.Command(dhclientPath, "-1", "-v", dev).Run()
		}
		// After DHCP client negotiates lease, re-reconcile static routes
		if err := ReconcileStaticRoutes(); err != nil {
			log.Printf("[Agent] Post-DHCP static route reconciliation: %v", err)
		}
	}()
}

func releaseDhcpLease(dev string) {
	if dev == "" {
		return
	}
	if dhcpcdPath, err := exec.LookPath("dhcpcd"); err == nil {
		_ = exec.Command(dhcpcdPath, "-k", dev).Run()
		_ = exec.Command(dhcpcdPath, "-x", dev).Run()
	}
	if dhclientPath, err := exec.LookPath("dhclient"); err == nil {
		_ = exec.Command(dhclientPath, "-r", dev).Run()
	}
}
