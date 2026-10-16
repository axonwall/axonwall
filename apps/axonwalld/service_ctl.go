package main

import (
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
	return s
}

func reloadOrRestartService(svc string) ([]byte, error) {
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
	pidFile := "/var/run/udhcpc." + dev + ".pid"
	_ = exec.Command("sh", "-c", "kill $(cat "+pidFile+" 2>/dev/null) 2>/dev/null || pkill -f 'udhcpc.*"+dev+"' 2>/dev/null").Run()
}
