package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installFakeSystemctl prepends a directory containing a fake `systemctl`
// to PATH. The fake logs its arguments and exits with the given status.
func installFakeSystemctl(t *testing.T, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "systemctl-args.log")
	script := "#!/bin/sh\n" +
		"echo \"$@\" >> \"" + logPath + "\"\n" +
		"exit " + string(rune('0'+exitCode)) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0755); err != nil {
		t.Fatalf("Failed to write fake systemctl: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return logPath
}

// A-M29: starting a service must reload, enable, start, and verify it is
// active — writing the unit file alone is not starting the daemon.
func TestBatch7_StartAndVerifyService(t *testing.T) {
	logPath := installFakeSystemctl(t, 0)
	if err := startAndVerifyService("rosenpass"); err != nil {
		t.Fatalf("startAndVerifyService with working systemctl: %v", err)
	}
	argsLog, _ := os.ReadFile(logPath)
	log := string(argsLog)
	for _, want := range []string{"daemon-reload", "enable --now rosenpass.service", "is-active --quiet rosenpass"} {
		if !strings.Contains(log, want) {
			t.Fatalf("expected systemctl %q in log, got %q", want, log)
		}
	}
}

func TestBatch7_StartAndVerifyServiceFailsClosed(t *testing.T) {
	installFakeSystemctl(t, 1)
	if err := startAndVerifyService("rosenpass"); err == nil {
		t.Fatal("startAndVerifyService with a failing systemctl returned nil, want error")
	}

	// No systemctl at all: the daemon cannot be started, so report that
	// instead of claiming it is verified.
	t.Setenv("PATH", t.TempDir())
	if err := startAndVerifyService("rosenpass"); err == nil {
		t.Fatal("startAndVerifyService without systemctl returned nil, want error")
	} else if !strings.Contains(err.Error(), "systemd not available") {
		t.Fatalf("startAndVerifyService without systemctl: %v, want a systemd-not-available error", err)
	}
}
