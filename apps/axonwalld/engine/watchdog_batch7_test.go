package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// E4 regression (Batch 7): deleting the fallback Boot Environment
// must be refused. The fallback BE is the rollback pointer the ZBM
// watchdog hook follows on a failed boot; destroying it would leave
// org.axonwall:fallback_be pointing at a destroyed dataset. The
// guard reads the property live from ZFS, not from cached status.

func newBatch7ZbmEngine(t *testing.T) *WatchdogEngine {
	t.Helper()
	tempDir := t.TempDir()
	grubenvPath := filepath.Join(tempDir, "grubenv")
	cmdlinePath := filepath.Join(tempDir, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz zfs=zroot/ROOT/axonwall-0.11.30 root=zfs:zroot/ROOT/axonwall-0.11.30 ro quiet"), 0644); err != nil {
		t.Fatalf("failed to write mock cmdline: %v", err)
	}
	engine := NewWatchdogEngineCustom(grubenvPath, cmdlinePath)
	engine.readInstalledVer = func() string { return "0.11.30" }
	// One standby BE, neither running nor staged for next boot, so
	// the only thing that may refuse the delete is the E4 guard.
	engine.status.BootEnvironments = []ZfsBootEnvironment{
		{Dataset: "zroot/ROOT/axonwall-0.11.29", Name: "axonwall-0.11.29"},
	}
	return engine
}

func TestBatch7DeleteFallbackBootEnvironmentRefused(t *testing.T) {
	engine := newBatch7ZbmEngine(t)
	destroyCalled := false
	engine.runZfsCmd = func(args ...string) ([]byte, error) {
		cmdStr := strings.Join(args, " ")
		if strings.HasPrefix(cmdStr, "get") && strings.Contains(cmdStr, "org.axonwall:fallback_be") {
			return []byte("zroot/ROOT/axonwall-0.11.29\n"), nil
		}
		if strings.HasPrefix(cmdStr, "destroy") {
			destroyCalled = true
		}
		return []byte("ok"), nil
	}

	err := engine.DeleteBootEnvironment("axonwall-0.11.29")
	if err == nil {
		t.Fatalf("deleting the fallback BE must fail, got nil error")
	}
	if !strings.Contains(err.Error(), "fallback") {
		t.Errorf("refusal must name the fallback pointer, got: %v", err)
	}
	if destroyCalled {
		t.Errorf("zfs destroy must not run when the delete is refused")
	}
}

func TestBatch7DeleteNonFallbackBootEnvironmentAllowed(t *testing.T) {
	engine := newBatch7ZbmEngine(t)
	destroyCalled := false
	engine.runZfsCmd = func(args ...string) ([]byte, error) {
		cmdStr := strings.Join(args, " ")
		if strings.HasPrefix(cmdStr, "get") && strings.Contains(cmdStr, "org.axonwall:fallback_be") {
			// The fallback is a different BE.
			return []byte("zroot/ROOT/axonwall-0.11.30\n"), nil
		}
		if strings.HasPrefix(cmdStr, "destroy") {
			destroyCalled = true
		}
		return []byte("ok"), nil
	}

	if err := engine.DeleteBootEnvironment("axonwall-0.11.29"); err != nil {
		t.Fatalf("deleting a non-fallback BE must succeed, got: %v", err)
	}
	if !destroyCalled {
		t.Errorf("zfs destroy must run for a non-fallback BE")
	}
}

func TestBatch7DeleteBootEnvironmentUnsetFallbackAllowed(t *testing.T) {
	engine := newBatch7ZbmEngine(t)
	destroyCalled := false
	engine.runZfsCmd = func(args ...string) ([]byte, error) {
		cmdStr := strings.Join(args, " ")
		if strings.HasPrefix(cmdStr, "get") && strings.Contains(cmdStr, "org.axonwall:fallback_be") {
			// zfs get reports an unset user property as "-".
			return []byte("-\n"), nil
		}
		if strings.HasPrefix(cmdStr, "destroy") {
			destroyCalled = true
		}
		return []byte("ok"), nil
	}

	if err := engine.DeleteBootEnvironment("axonwall-0.11.29"); err != nil {
		t.Fatalf("deleting a BE with no fallback set must succeed, got: %v", err)
	}
	if !destroyCalled {
		t.Errorf("zfs destroy must run when no fallback is set")
	}
}
