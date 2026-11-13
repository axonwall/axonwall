package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Batch 9 (round-3 bug-hunt fix): ZBM watchdog findings E-H1, E-H2,
// E-M4, E-L1, E-L2.
//
// batch9Zfs answers zfs/zpool queries from a fixed BE table, records
// every set, and can fail a chosen set assignment (to model a failed
// bootcount commit). It is deliberately independent of
// batch16ListZfs: the E-H1/E-H2 cases need failure injection and a
// controllable bootfs value.
type batch9Zfs struct {
	sets       []string
	props      map[string]string
	bootfs     string
	bootfsErr  error
	listOutput string
	// failSet is matched as a substring of the joined set command
	// (e.g. "set org.axonwall:bootcount=0"); matching sets fail.
	failSet string
}

func (f *batch9Zfs) runZfs(args ...string) ([]byte, error) {
	cmd := strings.Join(args, " ")
	if strings.HasPrefix(cmd, "list") && strings.Contains(cmd, "filesystem") {
		return []byte(f.listOutput), nil
	}
	if strings.HasPrefix(cmd, "list") && strings.Contains(cmd, "snapshot") {
		return []byte(""), nil
	}
	if strings.HasPrefix(cmd, "get ") {
		prop := args[len(args)-2]
		if v, ok := f.props[prop]; ok {
			return []byte(v + "\n"), nil
		}
		return nil, fmt.Errorf("property %s not found", prop)
	}
	if strings.HasPrefix(cmd, "set ") {
		if f.failSet != "" && strings.Contains(cmd, f.failSet) {
			return nil, fmt.Errorf("simulated set failure for %q", cmd)
		}
		kv := args[1]
		if eq := strings.Index(kv, "="); eq >= 0 {
			f.props[kv[:eq]] = kv[eq+1:]
		}
		f.sets = append(f.sets, cmd)
		return []byte("ok"), nil
	}
	return []byte("ok"), nil
}

func (f *batch9Zfs) runZpool(args ...string) ([]byte, error) {
	cmd := strings.Join(args, " ")
	if strings.HasPrefix(cmd, "get ") && strings.Contains(cmd, "bootfs") {
		if f.bootfsErr != nil {
			return nil, f.bootfsErr
		}
		return []byte(f.bootfs + "\n"), nil
	}
	if strings.HasPrefix(cmd, "set ") {
		f.sets = append(f.sets, "zpool "+cmd)
		return []byte("ok"), nil
	}
	return []byte("ok"), nil
}

func (f *batch9Zfs) hasSet(want string) bool {
	for _, s := range f.sets {
		if strings.HasPrefix(s, want) {
			return true
		}
	}
	return false
}

func batch9PassingChecks(e *WatchdogEngine) {
	e.checkInterfaces = func() HealthCheckResult {
		return HealthCheckResult{Name: "ifaces", Status: CheckStatusPass}
	}
	e.checkNftables = func() HealthCheckResult {
		return HealthCheckResult{Name: "nft", Status: CheckStatusPass}
	}
	e.checkControlPlane = func() HealthCheckResult {
		return HealthCheckResult{Name: "cp", Status: CheckStatusPass}
	}
}

func batch9Engine(t *testing.T, runningVer string) (*WatchdogEngine, string) {
	t.Helper()
	tempDir := t.TempDir()
	cmdlinePath := filepath.Join(tempDir, "cmdline")
	cmdline := fmt.Sprintf("BOOT_IMAGE=/vmlinuz zfs=zroot/ROOT/axonwall-%s root=zfs:zroot/ROOT/axonwall-%s ro quiet", runningVer, runningVer)
	if err := os.WriteFile(cmdlinePath, []byte(cmdline), 0644); err != nil {
		t.Fatalf("Failed to write mock cmdline: %v", err)
	}
	engine := NewWatchdogEngineCustom(filepath.Join(tempDir, "grubenv"), cmdlinePath)
	engine.readInstalledVer = func() string { return runningVer }
	engine.status.InstallMode = "zbm"
	engine.status.ActiveRootDevice = "zroot/ROOT/axonwall-" + runningVer
	return engine, tempDir
}

const batch9ListTwoBEs = "zroot/ROOT/axonwall-0.11.61\t1.4G\tTue Nov  3 09:16 2026\n" +
	"zroot/ROOT/axonwall-0.11.62\t1.7G\tSat Nov  7 21:43 2026\n"

// --- E-H1: verification must not disarm a staged update ---------------

func TestBatch9VerificationLeavesStagedBootfsAlone(t *testing.T) {
	engine, _ := batch9Engine(t, "0.11.62")
	zx := &batch9Zfs{
		props: map[string]string{
			"org.axonwall:bootcount": "1",
			"org.axonwall:bootlimit": "3",
		},
		// A staged update: bootfs names the not-yet-booted 9.9.9 BE
		// (present in the list), running BE is still 0.11.62.
		bootfs: "zroot/ROOT/axonwall-9.9.9",
		listOutput: batch9ListTwoBEs +
			"zroot/ROOT/axonwall-9.9.9\t1.8G\tSun Nov  8 10:00 2026\n",
	}
	engine.runZfsCmd = zx.runZfs
	engine.runZpoolCmd = zx.runZpool
	batch9PassingChecks(engine)

	// Twice: a fresh process (first verification) and a later
	// on-demand verification must both leave the staging alone.
	engine.runVerificationSequence()
	engine.runVerificationSequence()

	if zx.hasSet("zpool set bootfs=zroot/ROOT/axonwall-0.11.62") {
		t.Errorf("Verification disarmed the staged update; sets: %v", zx.sets)
	}
	if zx.hasSet("set org.axonwall:active_be=zroot/ROOT/axonwall-0.11.62") {
		t.Errorf("Verification overwrote active_be for a staged update; sets: %v", zx.sets)
	}
}

func TestBatch9VerificationRepairsDanglingOrUnsetBootfs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		bootfs string
	}{
		{"dangling dataset", "zroot/ROOT/axonwall-0.11.99"},
		{"unset", "-"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, _ := batch9Engine(t, "0.11.62")
			zx := &batch9Zfs{
				props: map[string]string{
					"org.axonwall:bootcount": "1",
					"org.axonwall:bootlimit": "3",
				},
				bootfs:     tc.bootfs,
				listOutput: batch9ListTwoBEs,
			}
			engine.runZfsCmd = zx.runZfs
			engine.runZpoolCmd = zx.runZpool
			batch9PassingChecks(engine)
			engine.runVerificationSequence()
			if !zx.hasSet("zpool set bootfs=zroot/ROOT/axonwall-0.11.62 zroot") {
				t.Errorf("Expected verification to repair bootfs %q to the running BE; sets: %v", tc.bootfs, zx.sets)
			}
			if !zx.hasSet("set org.axonwall:active_be=zroot/ROOT/axonwall-0.11.62 zroot/ROOT") {
				t.Errorf("Expected verification to repair active_be to the running BE; sets: %v", zx.sets)
			}
		})
	}
}

func TestBatch9FailedCommitDoesNotAdvanceFallbackOrSync(t *testing.T) {
	engine, _ := batch9Engine(t, "0.11.62")
	zx := &batch9Zfs{
		props: map[string]string{
			"org.axonwall:bootcount": "1",
			"org.axonwall:bootlimit": "3",
		},
		bootfs:     "-",
		listOutput: batch9ListTwoBEs,
		// The bootcount=0 commit fails: the healthy state is not
		// committed, so neither the fallback pointer nor bootfs may
		// advance to the running BE.
		failSet: "set org.axonwall:bootcount=0",
	}
	engine.runZfsCmd = zx.runZfs
	engine.runZpoolCmd = zx.runZpool
	batch9PassingChecks(engine)
	engine.runVerificationSequence()
	if zx.hasSet("set org.axonwall:fallback_be=") {
		t.Errorf("Failed commit must not advance fallback_be; sets: %v", zx.sets)
	}
	if zx.hasSet("zpool set bootfs=") {
		t.Errorf("Failed commit must not sync bootfs; sets: %v", zx.sets)
	}
	if engine.status.HealthVerified {
		t.Errorf("HealthVerified must stay false when the commit fails")
	}
}

// --- E-H2: rollback must arm a BE other than the running one ---------

func TestBatch9RollbackArmsStandbyNotRunningFallback(t *testing.T) {
	engine, _ := batch9Engine(t, "0.11.62")
	zx := &batch9Zfs{
		props: map[string]string{
			// The running BE already passed verification once, so the
			// fallback pointer names the running (bad) BE.
			"org.axonwall:fallback_be": "zroot/ROOT/axonwall-0.11.62",
			"org.axonwall:active_be":  "zroot/ROOT/axonwall-0.11.62",
			"org.axonwall:bootcount":  "0",
			"org.axonwall:bootlimit":  "3",
		},
		// 0.11.61 is armed for next boot in this mock list (the
		// standby); the running BE is 0.11.62. Note the sandbox's
		// /proc/mounts never marks a BE ActiveNow, so the test models
		// the standby via ActiveNext, as the batch-16 tests do.
		bootfs:     "zroot/ROOT/axonwall-0.11.61",
		listOutput: batch9ListTwoBEs,
	}
	engine.runZfsCmd = zx.runZfs
	engine.runZpoolCmd = zx.runZpool
	if err := engine.TriggerRollback(); err != nil {
		t.Fatalf("TriggerRollback failed: %v", err)
	}
	if !zx.hasSet("set org.axonwall:active_be=zroot/ROOT/axonwall-0.11.61") {
		t.Errorf("Rollback must arm the standby BE, not the running fallback; sets: %v", zx.sets)
	}
	if zx.hasSet("set org.axonwall:active_be=zroot/ROOT/axonwall-0.11.62") {
		t.Errorf("Rollback re-armed the running BE (no-op rollback); sets: %v", zx.sets)
	}
}

func TestBatch9RollbackFailsWhenNoOtherBEExists(t *testing.T) {
	engine, _ := batch9Engine(t, "0.11.62")
	zx := &batch9Zfs{
		props: map[string]string{
			"org.axonwall:fallback_be": "zroot/ROOT/axonwall-0.11.62",
			"org.axonwall:active_be":  "zroot/ROOT/axonwall-0.11.62",
			"org.axonwall:bootcount":  "0",
			"org.axonwall:bootlimit":  "3",
		},
		bootfs:     "zroot/ROOT/axonwall-0.11.62",
		listOutput: "",
	}
	engine.runZfsCmd = zx.runZfs
	engine.runZpoolCmd = zx.runZpool
	if err := engine.TriggerRollback(); err == nil {
		t.Fatalf("TriggerRollback with no other BE must fail loudly, got nil; sets: %v", zx.sets)
	}
	if zx.hasSet("zpool set bootfs=") {
		t.Errorf("Failed rollback must not touch bootfs; sets: %v", zx.sets)
	}
}

func TestBatch9RollbackIgnoresDanglingFallbackPointer(t *testing.T) {
	engine, _ := batch9Engine(t, "0.11.62")
	zx := &batch9Zfs{
		props: map[string]string{
			// fallback_be names a BE that was deleted since it was
			// recorded; the standby 0.11.61 must win over it.
			"org.axonwall:fallback_be": "zroot/ROOT/axonwall-0.11.60",
			"org.axonwall:active_be":  "zroot/ROOT/axonwall-0.11.62",
			"org.axonwall:bootcount":  "0",
			"org.axonwall:bootlimit":  "3",
		},
		bootfs:     "zroot/ROOT/axonwall-0.11.61",
		listOutput: batch9ListTwoBEs,
	}
	engine.runZfsCmd = zx.runZfs
	engine.runZpoolCmd = zx.runZpool
	if err := engine.TriggerRollback(); err != nil {
		t.Fatalf("TriggerRollback failed: %v", err)
	}
	if !zx.hasSet("set org.axonwall:active_be=zroot/ROOT/axonwall-0.11.61") {
		t.Errorf("Rollback must arm the live standby, not the dangling fallback pointer; sets: %v", zx.sets)
	}
}

// --- E-M4: ActivateSlot("A") refreshes the list, never arms "A" ------

func TestBatch9ActivateSlotARefreshesStaleCache(t *testing.T) {
	engine, _ := batch9Engine(t, "0.11.62")
	zx := &batch9Zfs{
		props: map[string]string{
			"org.axonwall:active_be": "zroot/ROOT/axonwall-0.11.62",
			"org.axonwall:bootcount": "0",
			"org.axonwall:bootlimit": "3",
		},
		bootfs:     "zroot/ROOT/axonwall-0.11.62",
		listOutput: batch9ListTwoBEs,
	}
	engine.runZfsCmd = zx.runZfs
	engine.runZpoolCmd = zx.runZpool
	// Stale cache: the daemon last saw only the oldest standby, with
	// no ActiveNow entry at all. A correct implementation refreshes
	// the list and arms the running BE for slot A.
	engine.status.BootEnvironments = []ZfsBootEnvironment{
		{Name: "axonwall-0.11.61", Dataset: "zroot/ROOT/axonwall-0.11.61"},
	}
	if err := engine.ActivateSlot("A"); err != nil {
		t.Fatalf("ActivateSlot(A) failed: %v", err)
	}
	if !zx.hasSet("set org.axonwall:active_be=zroot/ROOT/axonwall-0.11.62") {
		t.Errorf("ActivateSlot(A) must arm the running BE; sets: %v", zx.sets)
	}
	if zx.hasSet("zpool set bootfs=zroot/ROOT/A") {
		t.Errorf("ActivateSlot(A) armed the literal BE name \"A\"; sets: %v", zx.sets)
	}
}

func TestBatch9ActivateSlotARefusesWithNoActiveBE(t *testing.T) {
	engine, _ := batch9Engine(t, "0.11.62")
	zx := &batch9Zfs{
		props: map[string]string{
			"org.axonwall:active_be": "zroot/ROOT/axonwall-0.11.62",
			"org.axonwall:bootcount": "0",
			"org.axonwall:bootlimit": "3",
		},
		bootfs:     "zroot/ROOT/axonwall-0.11.62",
		listOutput: "",
	}
	engine.runZfsCmd = zx.runZfs
	engine.runZpoolCmd = zx.runZpool
	engine.status.ActiveRootDevice = ""
	if err := engine.ActivateSlot("A"); err == nil {
		t.Fatalf("ActivateSlot(A) with no active BE in the list must fail, got nil; sets: %v", zx.sets)
	}
	if zx.hasSet("zpool set bootfs=") {
		t.Errorf("Refused ActivateSlot(A) must not touch bootfs; sets: %v", zx.sets)
	}
}

// --- E-L1: GetStatus must not report a deleted standby's version -----

func TestBatch9GetStatusClearsDeletedStandbyVersion(t *testing.T) {
	engine, tempDir := batch9Engine(t, "0.11.62")
	// slot_versions.json still names the deleted standby 0.11.60.
	svPath := filepath.Join(tempDir, "slot_versions.json")
	if err := os.WriteFile(svPath, []byte("{\n  \"slotA\": \"0.11.62\",\n  \"slotB\": \"0.11.60\",\n  \"updatedAt\": \"2026-11-12T00:00:00Z\"\n}\n"), 0644); err != nil {
		t.Fatalf("Failed to write mock slot_versions.json: %v", err)
	}
	zx := &batch9Zfs{
		props: map[string]string{},
		// Nothing armed for next boot, so no BE is ActiveNext and the
		// stale file value is the only thing naming 0.11.60.
		bootfs:     "-",
		listOutput: batch9ListTwoBEs,
	}
	engine.runZfsCmd = zx.runZfs
	engine.runZpoolCmd = zx.runZpool
	// Re-run detection against the mock so the status is seeded from
	// the file, then ask for status the way the API does.
	engine.detectInitialState()
	status := engine.GetStatus()
	if status.SlotBVersion == "0.11.60" {
		t.Errorf("GetStatus still reports the deleted standby BE's version 0.11.60")
	}
	if status.SlotBVersion != "0.11.61" && status.SlotBVersion != "Standby BE" {
		t.Errorf("GetStatus SlotBVersion = %q, want the live standby 0.11.61 or \"Standby BE\"", status.SlotBVersion)
	}
}

// --- E-L2: snapshot must fail when no active BE can be resolved ------

func TestBatch9CreateSnapshotFailsWithNoActiveBE(t *testing.T) {
	engine, _ := batch9Engine(t, "0.11.62")
	zx := &batch9Zfs{
		props:      map[string]string{},
		bootfs:     "zroot/ROOT/axonwall-0.11.62",
		listOutput: batch9ListTwoBEs,
	}
	engine.runZfsCmd = zx.runZfs
	engine.runZpoolCmd = zx.runZpool
	// The sandbox's /proc/mounts never marks a BE ActiveNow, which is
	// exactly the no-active-BE shape (rescue-media boot): the call
	// must fail instead of snapshotting the first BE in list order.
	if _, err := engine.CreateBootEnvironmentSnapshot("", "manual-test"); err == nil {
		t.Fatalf("CreateBootEnvironmentSnapshot with no active BE must fail, got nil")
	}
}
