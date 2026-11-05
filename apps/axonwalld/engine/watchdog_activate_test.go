package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeZxCommands answers zfs/zpool get/set calls from an in-memory property
// table and records every set, failing sets listed in failSets.
type fakeZxCommands struct {
	sets     []string
	props    map[string]string
	failSets map[string]bool
}

func (f *fakeZxCommands) run(args ...string) ([]byte, error) {
	cmd := strings.Join(args, " ")
	if strings.HasPrefix(cmd, "get ") {
		prop := args[len(args)-2]
		if v, ok := f.props[prop]; ok {
			return []byte(v + "\n"), nil
		}
		return nil, fmt.Errorf("property %s not found", prop)
	}
	if strings.HasPrefix(cmd, "set ") {
		kv := args[1]
		if f.failSets[kv] {
			return nil, fmt.Errorf("simulated set failure for %s", kv)
		}
		if eq := strings.Index(kv, "="); eq >= 0 {
			f.props[kv[:eq]] = kv[eq+1:]
		}
		f.sets = append(f.sets, cmd)
		return []byte("ok"), nil
	}
	return []byte("ok"), nil
}

func (f *fakeZxCommands) hasSet(want string) bool {
	for _, s := range f.sets {
		if s == want {
			return true
		}
	}
	return false
}

func newZbmActivateTestEngine(t *testing.T, zfsFake, zpoolFake *fakeZxCommands) *WatchdogEngine {
	t.Helper()
	tempDir := t.TempDir()
	grubenvPath := filepath.Join(tempDir, "grubenv")
	cmdlinePath := filepath.Join(tempDir, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz zfs=zroot/ROOT/axonwall-0.11.30 root=zfs:zroot/ROOT/axonwall-0.11.30 ro quiet"), 0644); err != nil {
		t.Fatalf("Failed to write mock cmdline: %v", err)
	}
	engine := NewWatchdogEngineCustom(grubenvPath, cmdlinePath)
	engine.runZfsCmd = zfsFake.run
	engine.runZpoolCmd = zpoolFake.run
	return engine
}

// E3: a watchdog property-set failure during activation must fail the
// activation (not report success) and roll the arming back.
func TestWatchdogActivateBootEnvironmentPartialFailure(t *testing.T) {
	zfsFake := &fakeZxCommands{
		props: map[string]string{
			"org.axonwall:active_be": "zroot/ROOT/axonwall-0.11.30",
			"org.axonwall:bootcount": "2",
			"org.axonwall:bootlimit": "5",
		},
		failSets: map[string]bool{"org.axonwall:bootcount=0": true},
	}
	zpoolFake := &fakeZxCommands{
		props: map[string]string{"bootfs": "zroot/ROOT/axonwall-0.11.30"},
	}
	engine := newZbmActivateTestEngine(t, zfsFake, zpoolFake)
	engine.status.BootCount = 7
	engine.status.HealthVerified = true
	engine.status.BootEnvironments = []ZfsBootEnvironment{
		{Dataset: "zroot/ROOT/axonwall-0.11.30"},
		{Dataset: "zroot/ROOT/axonwall-0.11.31"},
	}

	err := engine.ActivateBootEnvironment("axonwall-0.11.31")
	if err == nil {
		t.Fatalf("Expected ActivateBootEnvironment to fail when bootcount reset fails; got nil (pre-fix success lie)")
	}
	if !strings.Contains(err.Error(), "bootcount") {
		t.Errorf("Expected error to name the failed bootcount set, got: %v", err)
	}
	// Arming stopped at the first failure: the bootlimit arming set (to 3)
	// must never have been attempted.
	if zfsFake.hasSet("set org.axonwall:bootlimit=3 zroot/ROOT") {
		t.Errorf("Arming continued past the bootcount failure; bootlimit set was attempted")
	}
	// Rollback restored every previously read value.
	if !zpoolFake.hasSet("set bootfs=zroot/ROOT/axonwall-0.11.30 zroot") {
		t.Errorf("Expected bootfs rollback to the previous BE; sets: %v", zpoolFake.sets)
	}
	if !zfsFake.hasSet("set org.axonwall:active_be=zroot/ROOT/axonwall-0.11.30 zroot/ROOT") {
		t.Errorf("Expected active_be rollback to the previous BE; sets: %v", zfsFake.sets)
	}
	if !zfsFake.hasSet("set org.axonwall:bootcount=2 zroot/ROOT") {
		t.Errorf("Expected bootcount rollback to 2; sets: %v", zfsFake.sets)
	}
	if !zfsFake.hasSet("set org.axonwall:bootlimit=5 zroot/ROOT") {
		t.Errorf("Expected bootlimit rollback to 5; sets: %v", zfsFake.sets)
	}
	// In-memory status must not reflect a successful activation.
	if engine.status.BootCount != 7 {
		t.Errorf("Expected BootCount to stay 7 after failed activation, got %d", engine.status.BootCount)
	}
	if !engine.status.HealthVerified {
		t.Errorf("Expected HealthVerified to stay true after failed activation")
	}
	for _, be := range engine.status.BootEnvironments {
		if be.ActiveNext {
			t.Errorf("Expected no ActiveNext flag after failed activation, but %s is marked ActiveNext", be.Dataset)
		}
	}
}

// E3 happy path: a fully successful arming still activates.
func TestWatchdogActivateBootEnvironmentSuccess(t *testing.T) {
	zfsFake := &fakeZxCommands{
		props: map[string]string{
			"org.axonwall:active_be": "zroot/ROOT/axonwall-0.11.30",
			"org.axonwall:bootcount": "2",
			"org.axonwall:bootlimit": "5",
		},
	}
	zpoolFake := &fakeZxCommands{
		props: map[string]string{"bootfs": "zroot/ROOT/axonwall-0.11.30"},
	}
	engine := newZbmActivateTestEngine(t, zfsFake, zpoolFake)
	engine.status.BootEnvironments = []ZfsBootEnvironment{
		{Dataset: "zroot/ROOT/axonwall-0.11.30"},
		{Dataset: "zroot/ROOT/axonwall-0.11.31"},
	}

	if err := engine.ActivateBootEnvironment("axonwall-0.11.31"); err != nil {
		t.Fatalf("ActivateBootEnvironment failed: %v", err)
	}
	if !zpoolFake.hasSet("set bootfs=zroot/ROOT/axonwall-0.11.31 zroot") {
		t.Errorf("Expected bootfs set to the new BE; sets: %v", zpoolFake.sets)
	}
	if !zfsFake.hasSet("set org.axonwall:active_be=zroot/ROOT/axonwall-0.11.31 zroot/ROOT") {
		t.Errorf("Expected active_be set to the new BE; sets: %v", zfsFake.sets)
	}
	if !zfsFake.hasSet("set org.axonwall:bootcount=0 zroot/ROOT") {
		t.Errorf("Expected bootcount reset; sets: %v", zfsFake.sets)
	}
	if !zfsFake.hasSet("set org.axonwall:bootlimit=3 zroot/ROOT") {
		t.Errorf("Expected bootlimit set; sets: %v", zfsFake.sets)
	}
	if engine.status.BootCount != 0 || engine.status.BootLimit != 3 || engine.status.HealthVerified {
		t.Errorf("Expected status BootCount 0, BootLimit 3, HealthVerified false; got %d, %d, %v",
			engine.status.BootCount, engine.status.BootLimit, engine.status.HealthVerified)
	}
	for _, be := range engine.status.BootEnvironments {
		want := be.Dataset == "zroot/ROOT/axonwall-0.11.31"
		if be.ActiveNext != want {
			t.Errorf("Expected ActiveNext=%v for %s, got %v", want, be.Dataset, be.ActiveNext)
		}
	}
}
