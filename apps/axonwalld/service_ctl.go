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
