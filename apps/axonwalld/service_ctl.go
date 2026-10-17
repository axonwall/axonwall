package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

func normalizeOpenRCService(svc string) string {
	s := strings.TrimSuffix(svc, ".service")
	if s == "kea-dhcp4-server" {
		if _, err := exec.LookPath("rc-service"); err == nil {
			if exec.Command("rc-service", "--exists", "kea-dhcp4").Run() == nil {
				return "kea-dhcp4"
			}
		}
	}
	if s == "ssh" {
		if _, err := exec.LookPath("rc-service"); err == nil {
			if exec.Command("rc-service", "--exists", "sshd").Run() == nil {
				return "sshd"
			}
		}
	}
	return s
}

// managedServices is the allowlist of units the daemon may reload,
// restart, or stop on behalf of bundle/API callers (audit D-S03). Before
// this list existed, any name surviving a "/" check reached systemctl as
// argv, so a name like "--all" was parsed as a systemctl OPTION and any
// unit on the box could be bounced by a socket caller. The compiler only
// ever requests suricata and crowdsec-firewall-bouncer; the rest are the
// daemons whose configuration this daemon writes or supervises.
var managedServices = map[string]bool{
	"suricata": true, "crowdsec": true, "crowdsec-firewall-bouncer": true,
	"kea-dhcp4-server": true, "kea-dhcp-ddns-server": true,
	"unbound": true, "frr": true, "caddy": true, "headscale": true,
	"keepalived": true, "conntrackd": true, "nftables": true,
	"ssh": true, "sshd": true,
}

func validServiceName(svc string) bool {
	return managedServices[strings.TrimSuffix(svc, ".service")]
}

func reloadOrRestartService(svc string) ([]byte, error) {
	if !validServiceName(svc) {
		return nil, fmt.Errorf("service %q is not in the managed-services allowlist", svc)
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		return exec.Command("systemctl", "try-reload-or-restart", svc).CombinedOutput()
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		name := normalizeOpenRCService(svc)
		return exec.Command("rc-service", "--ifexists", name, "restart").CombinedOutput()
	}
	return exec.Command("service", strings.TrimSuffix(svc, ".service"), "restart").CombinedOutput()
}

func stopSystemService(svc string) ([]byte, error) {
	if !validServiceName(svc) {
		return nil, fmt.Errorf("service %q is not in the managed-services allowlist", svc)
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		return exec.Command("systemctl", "stop", svc).CombinedOutput()
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		name := normalizeOpenRCService(svc)
		return exec.Command("rc-service", "--ifexists", name, "stop").CombinedOutput()
	}
	return exec.Command("service", strings.TrimSuffix(svc, ".service"), "stop").CombinedOutput()
}

// dhcpClientRunning reports whether a DHCP client started by the system
// networking path (ifup/dhcpcd, ifup/udhcpc, or an earlier boot-apply) is
// already alive for dev, based on the clients' pidfiles. Starting a second
// client on the same interface is destructive: a fresh udhcpc runs its
// deconfig script first, which flushes the IPv4 addresses the running
// client just configured, and the two clients then fight over the lease.
func dhcpClientRunning(dev string) bool {
	pidFiles := []string{
		"/var/run/udhcpc." + dev + ".pid",
		"/var/run/dhcpcd/" + dev + ".pid",
		"/var/run/dhcpcd-" + dev + ".pid",
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
		// Prefer udhcpc if present (Alpine default)
		if udhcpcPath, err := exec.LookPath("udhcpc"); err == nil {
			pidFile := "/var/run/udhcpc." + dev + ".pid"
			_ = exec.Command(udhcpcPath, "-b", "-i", dev, "-p", pidFile).Run()
			return
		}
		// Fallback to dhclient (Debian default)
		if dhclientPath, err := exec.LookPath("dhclient"); err == nil {
			_ = exec.Command(dhclientPath, "-1", "-v", dev).Run()
			return
		}
	}()
}

func releaseDhcpLease(dev string) {
	if dev == "" {
		return
	}
	if dhclientPath, err := exec.LookPath("dhclient"); err == nil {
		_ = exec.Command(dhclientPath, "-r", dev).Run()
	}
	// Signal the recorded pid directly. The previous implementation
	// interpolated dev into a root `sh -c` string (audit D-S01 note);
	// the pidfile is written by triggerDhcpClient, so no shell and no
	// pkill pattern are needed.
	pidFile := "/var/run/udhcpc." + dev + ".pid"
	if data, err := os.ReadFile(pidFile); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			if proc, err := os.FindProcess(pid); err == nil {
				_ = proc.Signal(syscall.SIGTERM)
			}
		}
	}
}
