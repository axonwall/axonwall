package engine

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestEtckeeperManagerExecution(t *testing.T) {
	tempDir := t.TempDir()
	mgr := NewEtckeeperManager(tempDir)
	mgr.debounceTime = 10 * time.Millisecond

	// Mock execCmd to simulate etckeeper and git without altering host system
	historyMock := "1111222233334444555566667777888899990000|admin|2026-10-19T07:00:00Z|Updated /etc/axonwall/firewall.yaml\n"

	mgr.execCmd = func(name string, args ...string) *exec.Cmd {
		if name == "which" {
			return exec.Command("true")
		}
		if name == "etckeeper" {
			return exec.Command("true")
		}
		if name == "git" {
			for i, a := range args {
				if a == "status" {
					return exec.Command("echo", "")
				}
				if a == "log" {
					if i+1 < len(args) && args[i+1] == "-1" {
						return exec.Command("echo", "1111222233334444555566667777888899990000|Updated /etc/axonwall/firewall.yaml|2026-10-19T07:00:00Z")
					}
					return exec.Command("echo", historyMock)
				}
				if a == "diff" {
					return exec.Command("echo", "diff --git a/axonwall/firewall.yaml b/axonwall/firewall.yaml")
				}
			}
		}
		return exec.Command("true")
	}

	if !mgr.IsInstalled() {
		t.Fatalf("expected IsInstalled to return true")
	}

	if err := mgr.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if err := mgr.Commit("Test commit", "admin"); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	status := mgr.GetStatus()
	if !status.Installed {
		t.Errorf("expected status.Installed true")
	}

	history, err := mgr.GetHistory(10)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected 1 history item, got %d", len(history))
	}
	if history[0].Author != "admin" {
		t.Errorf("expected author 'admin', got %s", history[0].Author)
	}
	if !strings.Contains(history[0].Subject, "Updated /etc/axonwall/firewall.yaml") {
		t.Errorf("expected subject to contain updated yaml, got %s", history[0].Subject)
	}

	diff, err := mgr.GetDiff("")
	if err != nil {
		t.Fatalf("GetDiff failed: %v", err)
	}
	if !strings.Contains(diff, "diff --git") {
		t.Errorf("expected diff to contain 'diff --git', got: %s", diff)
	}
}
