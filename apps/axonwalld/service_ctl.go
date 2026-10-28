package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// managedServices is the allowlist of units the daemon may reload,
// restart, or stop on behalf of bundle/API callers (audit D-S03). Before
// this list existed, any name surviving a "/" check reached systemctl as
// argv, so a name like "--all" was parsed as a systemctl OPTION and any
// unit on the box could be bounced by a socket caller.
var managedServices = map[string]bool{
	"suricata": true, "crowdsec": true, "crowdsec-firewall-bouncer": true,
	"kea-dhcp4-server": true, "kea-dhcp-ddns-server": true,
	"unbound": true, "frr": true, "caddy": true, "headscale": true,
	"keepalived": true, "conntrackd": true, "nftables": true,
	"ssh": true, "sshd": true,
	"slapd": true, "sssd": true, "chrony": true,
	"wg-quick@wg0": true, "rosenpass": true,
	"haproxy": true, "freeradius": true,
	"openvpn": true, "openvpn@server": true,
	"strongswan": true, "strongswan-starter": true,
	"smbd": true, "nmbd": true, "nfs-server": true, "nfs-kernel-server": true, "tgt": true,
	"k3s": true, "libvirtd": true, "nut-server": true, "nut-monitor": true, "snmpd": true,
}

func validServiceName(svc string) bool {
	return managedServices[strings.TrimSuffix(svc, ".service")]
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

func reloadOrRestartService(svc string) ([]byte, error) {
	if !validServiceName(svc) {
		return nil, fmt.Errorf("service %q is not in the managed-services allowlist", svc)
	}
	unit := strings.TrimSuffix(svc, ".service")
	if unit == "kea-dhcp4-server" && !keaHasActiveInterfaces() {
		return stopSystemService(svc)
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		return exec.Command("systemctl", "reload-or-restart", svc).CombinedOutput()
	}
	return exec.Command("service", unit, "restart").CombinedOutput()
}

func stopSystemService(svc string) ([]byte, error) {
	if !validServiceName(svc) {
		return nil, fmt.Errorf("service %q is not in the managed-services allowlist", svc)
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		return exec.Command("systemctl", "stop", svc).CombinedOutput()
	}
	return exec.Command("service", strings.TrimSuffix(svc, ".service"), "stop").CombinedOutput()
}

// dhcpClientRunning reports whether a DHCP client started by the system
// networking path (ifup/dhcpcd, dhclient, udhcpc, or an earlier boot-apply) is
// already alive for dev, based on the clients' pidfiles.
func dhcpClientRunning(dev string) bool {
	pidFiles := []string{
		"/var/run/dhclient." + dev + ".pid",
		"/var/run/dhcpcd/" + dev + ".pid",
		"/var/run/dhcpcd/" + dev + "-4.pid",
		"/var/run/dhcpcd-" + dev + ".pid",
		"/var/run/dhcpcd-" + dev + "-4.pid",
		"/run/dhcpcd/" + dev + ".pid",
		"/run/dhcpcd/" + dev + "-4.pid",
		"/run/dhcpcd-" + dev + ".pid",
		"/run/dhcpcd-" + dev + "-4.pid",
		"/var/run/dhcpcd/pid",
		"/run/dhcpcd/pid",
		"/var/run/dhcpcd.pid",
		"/run/dhcpcd.pid",
		"/var/run/udhcpc." + dev + ".pid",
		"/run/udhcpc." + dev + ".pid",
	}
	for _, pidFile := range pidFiles {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 0 {
			continue
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		if err := proc.Signal(syscall.Signal(0)); err == nil {
			return true
		}
	}
	return false
}

func triggerDhcpClient(dev string) {
	if dev == "" {
		return
	}
	if dhcpClientRunning(dev) {
		log.Printf("[Agent] DHCP client already running on %s; not starting another", dev)
		return
	}
	go func() {
		if dhcpcdPath, err := exec.LookPath("dhcpcd"); err == nil {
			_ = exec.Command(dhcpcdPath, "-4", dev).Run()
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
