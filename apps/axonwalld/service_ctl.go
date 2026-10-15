package main

import (
	"os/exec"
	"strings"
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

func triggerDhcpClient(dev string) {
	if dev == "" {
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
