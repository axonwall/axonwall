package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Batch 16 (round-2 bug-hunt fix): updater-low findings E2-9, E2-10,
// E2-11, E2-12 and D2-L1. D2-L2 (CI size guard) is covered by the
// workflow check, not by Go tests.

// --- E2-10: standby selection -------------------------------------------

func TestBatch16SelectStandbyBE(t *testing.T) {
	be := func(name, created string, now, next bool) ZfsBootEnvironment {
		return ZfsBootEnvironment{
			Name: name, Dataset: "zroot/ROOT/" + name,
			ActiveNow: now, ActiveNext: next, CreatedAt: created,
		}
	}
	cases := []struct {
		name string
		bes  []ZfsBootEnvironment
		want string // "" means nil
	}{
		{
			name: "armed BE wins over newer by creation",
			bes: []ZfsBootEnvironment{
				be("axonwall-0.11.31", "Mon Nov  2 09:00 2026", false, false),
				be("axonwall-0.11.30", "Sun Nov  1 16:12 2026", false, true),
			},
			want: "axonwall-0.11.30",
		},
		{
			name: "newest by creation when none armed",
			bes: []ZfsBootEnvironment{
				be("axonwall-0.11.28", "Sun Oct 25 10:00 2026", false, false),
				be("axonwall-0.11.30", "Sun Nov  1 16:12 2026", false, false),
				be("axonwall-0.11.29", "Tue Oct 27 10:05 2026", false, false),
			},
			want: "axonwall-0.11.30",
		},
		{
			name: "active BE is skipped even when newest",
			bes: []ZfsBootEnvironment{
				be("axonwall-0.11.30", "Sun Nov  1 16:12 2026", true, false),
				be("axonwall-0.11.29", "Tue Oct 27 10:05 2026", false, false),
			},
			want: "axonwall-0.11.29",
		},
		{
			name: "unparseable creation falls back to last in list order",
			bes: []ZfsBootEnvironment{
				be("axonwall-0.11.28", "garbage", false, false),
				be("axonwall-0.11.29", "also garbage", false, false),
			},
			want: "axonwall-0.11.29",
		},
		{
			name: "no standby returns nil",
			bes: []ZfsBootEnvironment{
				be("axonwall-0.11.30", "Sun Nov  1 16:12 2026", true, true),
			},
			want: "",
		},
		{
			name: "empty list returns nil",
			bes:  nil,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := selectStandbyBE(tc.bes)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("Expected nil, got %s", got.Name)
				}
				return
			}
			if got == nil {
				t.Fatalf("Expected %s, got nil", tc.want)
			}
			if got.Name != tc.want {
				t.Errorf("Expected %s, got %s", tc.want, got.Name)
			}
		})
	}
}

// --- E2-11: rootfsB token matching --------------------------------------

func TestBatch16DetectRunningSlotRootfsB(t *testing.T) {
	cases := []struct {
		name    string
		cmdline string
		want    string
		wantOK  bool
	}{
		// The reported bug: rootfsB=0 (firstboot: slot A) was read as B.
		{"rootfsB=0 with slot=A reads A", "BOOT_IMAGE=/vmlinuz rootfsB=0 slot=A ro quiet", "A", true},
		{"rootfsB=0 alone reads A", "BOOT_IMAGE=/vmlinuz rootfsB=0 ro quiet", "A", true},
		{"rootfsB=1 reads B", "BOOT_IMAGE=/vmlinuz rootfsB=1 ro quiet", "B", true},
		// Exact tokens only: rootfsB=10 is neither =1 nor =0.
		{"rootfsB=10 matches neither", "BOOT_IMAGE=/vmlinuz rootfsB=10 ro quiet", "", false},
		// Explicit slot=B still wins when the tokens disagree
		// (B branch is checked first, as before).
		{"slot=B wins over rootfsB=0", "BOOT_IMAGE=/vmlinuz rootfsB=0 slot=B ro quiet", "B", true},
		{"no marker", "BOOT_IMAGE=/vmlinuz ro quiet", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "cmdline")
			if err := os.WriteFile(p, []byte(tc.cmdline), 0644); err != nil {
				t.Fatalf("Failed to write mock cmdline: %v", err)
			}
			got, ok := detectRunningSlotFromCmdline(p)
			if ok != tc.wantOK || got != tc.want {
				t.Errorf("detectRunningSlotFromCmdline(%q) = (%q, %v), want (%q, %v)",
					tc.cmdline, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// --- E2-12: snapshot source must be a BE ---------------------------------

type batch16RecordingZfs struct {
	calls []string
}

func (f *batch16RecordingZfs) run(args ...string) ([]byte, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	return []byte("ok"), nil
}

func (f *batch16RecordingZfs) saw(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func TestBatch16SnapshotOpsRejectNonBESnapshots(t *testing.T) {
	tempDir := t.TempDir()
	engine := NewWatchdogEngineCustom(
		filepath.Join(tempDir, "grubenv"),
		filepath.Join(tempDir, "cmdline"),
	)
	zfsFake := &batch16RecordingZfs{}
	engine.runZfsCmd = zfsFake.run

	// A data-dataset snapshot must be refused before any zfs call.
	if _, err := engine.CloneSnapshotToBootEnvironment("zroot/tank@backup", "axonwall-9.9.9"); err == nil {
		t.Errorf("Clone of zroot/tank@backup: expected error, got nil")
	} else if !strings.Contains(err.Error(), "not a Boot Environment snapshot") {
		t.Errorf("Clone of zroot/tank@backup: unexpected error %v", err)
	}
	if zfsFake.saw("clone ") {
		t.Errorf("Clone of zroot/tank@backup: zfs clone must not have run")
	}
	if err := engine.RollbackBootEnvironmentSnapshot("zroot/tank@backup"); err == nil {
		t.Errorf("Rollback of zroot/tank@backup: expected error, got nil")
	}
	if zfsFake.saw("rollback ") {
		t.Errorf("Rollback of zroot/tank@backup: zfs rollback must not have run")
	}
	if err := engine.DeleteBootEnvironmentSnapshot("zroot/tank@backup"); err == nil {
		t.Errorf("Delete of zroot/tank@backup: expected error, got nil")
	}
	if zfsFake.saw("destroy ") {
		t.Errorf("Delete of zroot/tank@backup: zfs destroy must not have run")
	}

	// A snapshot reference with no '@' is not a snapshot at all.
	if _, err := engine.CloneSnapshotToBootEnvironment("axonwall-0.11.30", "axonwall-9.9.9"); err == nil || !strings.Contains(err.Error(), "'@label'") {
		t.Errorf("Clone without @label: expected '@label' error, got %v", err)
	}

	// Positive controls: BE snapshots (full and bare names) still work.
	if _, err := engine.CloneSnapshotToBootEnvironment("zroot/ROOT/axonwall-0.11.30@pre-update", "axonwall-9.9.9"); err != nil {
		t.Errorf("Clone of BE snapshot: unexpected error %v", err)
	}
	if !zfsFake.saw("clone ") {
		t.Errorf("Clone of BE snapshot: expected zfs clone to run")
	}
	if _, err := engine.CloneSnapshotToBootEnvironment("axonwall-0.11.30@pre-update", "axonwall-9.9.8"); err != nil {
		t.Errorf("Clone of bare BE snapshot name: unexpected error %v", err)
	}
}

// --- E2-10: ActivateSlot("B") refreshes and prefers armed/newest ------

// batch16ListZfs answers zfs/zpool queries from a fixed BE table and
// records every set, like fakeZxCommands but with a controllable
// `zfs list` response.
type batch16ListZfs struct {
	sets       []string
	props      map[string]string
	bootfs     string
	listOutput string
}

func (f *batch16ListZfs) runZfs(args ...string) ([]byte, error) {
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
		kv := args[1]
		if eq := strings.Index(kv, "="); eq >= 0 {
			f.props[kv[:eq]] = kv[eq+1:]
		}
		f.sets = append(f.sets, cmd)
		return []byte("ok"), nil
	}
	return []byte("ok"), nil
}

func (f *batch16ListZfs) runZpool(args ...string) ([]byte, error) {
	cmd := strings.Join(args, " ")
	if strings.HasPrefix(cmd, "get ") && strings.Contains(cmd, "bootfs") {
		return []byte(f.bootfs + "\n"), nil
	}
	if strings.HasPrefix(cmd, "set ") {
		f.sets = append(f.sets, "zpool "+cmd)
		return []byte("ok"), nil
	}
	return []byte("ok"), nil
}

func (f *batch16ListZfs) hasSet(want string) bool {
	// Recorded sets carry the trailing dataset argument
	// ("set org.axonwall:active_be=<ds> zroot/ROOT"), so match on
	// the set assignment itself, not the whole command line.
	for _, s := range f.sets {
		if strings.HasPrefix(s, want) {
			return true
		}
	}
	return false
}

func TestBatch16ActivateSlotBPrefersArmedOverOldest(t *testing.T) {
	tempDir := t.TempDir()
	cmdlinePath := filepath.Join(tempDir, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz zfs=zroot/ROOT/axonwall-0.11.30 root=zfs:zroot/ROOT/axonwall-0.11.30 ro quiet"), 0644); err != nil {
		t.Fatalf("Failed to write mock cmdline: %v", err)
	}
	engine := NewWatchdogEngineCustom(filepath.Join(tempDir, "grubenv"), cmdlinePath)
	engine.readInstalledVer = func() string { return "0.11.30" }

	zx := &batch16ListZfs{
		props: map[string]string{
			"org.axonwall:active_be": "zroot/ROOT/axonwall-0.11.30",
			"org.axonwall:bootcount": "2",
			"org.axonwall:bootlimit": "3",
		},
		// The staged update (0.11.31) is already armed for next boot.
		bootfs: "zroot/ROOT/axonwall-0.11.31",
		// Dataset-name order: the oldest standby sorts first — the
		// pre-fix code armed it. The armed/newest is last.
		listOutput: "zroot/ROOT/axonwall-0.11.28\t1.2G\tSun Oct 25 10:00 2026\n" +
			"zroot/ROOT/axonwall-0.11.30\t1.4G\tSun Nov  1 16:12 2026\n" +
			"zroot/ROOT/axonwall-0.11.31\t1.4G\tMon Nov  2 09:00 2026\n",
	}
	engine.runZfsCmd = zx.runZfs
	engine.runZpoolCmd = zx.runZpool

	// Stale cache: the daemon last saw only the oldest standby.
	// A correct implementation refreshes the list before choosing.
	engine.status.BootEnvironments = []ZfsBootEnvironment{
		{Name: "axonwall-0.11.28", Dataset: "zroot/ROOT/axonwall-0.11.28"},
	}

	if err := engine.ActivateSlot("B"); err != nil {
		t.Fatalf("ActivateSlot(B) failed: %v", err)
	}
	if !zx.hasSet("set org.axonwall:active_be=zroot/ROOT/axonwall-0.11.31") {
		t.Errorf("ActivateSlot(B) armed the wrong BE; sets were %v", zx.sets)
	}
	if zx.hasSet("set org.axonwall:active_be=zroot/ROOT/axonwall-0.11.28") {
		t.Errorf("ActivateSlot(B) armed the oldest standby (pre-fix behaviour)")
	}
}

func TestBatch16ActivateSlotBNewestWhenNoneArmed(t *testing.T) {
	tempDir := t.TempDir()
	cmdlinePath := filepath.Join(tempDir, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz zfs=zroot/ROOT/axonwall-0.11.30 root=zfs:zroot/ROOT/axonwall-0.11.30 ro quiet"), 0644); err != nil {
		t.Fatalf("Failed to write mock cmdline: %v", err)
	}
	engine := NewWatchdogEngineCustom(filepath.Join(tempDir, "grubenv"), cmdlinePath)
	engine.readInstalledVer = func() string { return "0.11.30" }

	zx := &batch16ListZfs{
		props: map[string]string{
			"org.axonwall:active_be": "zroot/ROOT/axonwall-0.11.30",
			"org.axonwall:bootcount": "2",
			"org.axonwall:bootlimit": "3",
		},
		// No bootfs target: nothing is staged for next boot. (On a
		// real box bootfs would name the running BE, which is also
		// ActiveNow and therefore skipped; this sandbox's /proc/mounts
		// never matches a BE dataset, so an empty bootfs is what
		// models "nothing staged" here.)
		bootfs: "",
		listOutput: "zroot/ROOT/axonwall-0.11.28\t1.2G\tSun Oct 25 10:00 2026\n" +
			"zroot/ROOT/axonwall-0.11.30\t1.4G\tSun Nov  1 16:12 2026\n" +
			"zroot/ROOT/axonwall-0.11.31\t1.4G\tMon Nov  2 09:00 2026\n",
	}
	engine.runZfsCmd = zx.runZfs
	engine.runZpoolCmd = zx.runZpool
	engine.status.BootEnvironments = nil

	if err := engine.ActivateSlot("B"); err != nil {
		t.Fatalf("ActivateSlot(B) failed: %v", err)
	}
	if !zx.hasSet("set org.axonwall:active_be=zroot/ROOT/axonwall-0.11.31") {
		t.Errorf("ActivateSlot(B) with nothing armed should pick the newest standby; sets were %v", zx.sets)
	}
}

// --- E2-9: pool health/topology unknown when the reads fail -------------

func TestBatch16PoolHealthUnknownWhenReadsFail(t *testing.T) {
	tempDir := t.TempDir()
	cmdlinePath := filepath.Join(tempDir, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz zfs=zroot/ROOT/axonwall-0.11.30 root=zfs:zroot/ROOT/axonwall-0.11.30 ro quiet"), 0644); err != nil {
		t.Fatalf("Failed to write mock cmdline: %v", err)
	}
	engine := NewWatchdogEngineCustom(filepath.Join(tempDir, "grubenv"), cmdlinePath)
	engine.readInstalledVer = func() string { return "0.11.30" }

	// Every ZFS/ZPOOL read fails: no topology property, no pool
	// health, no BE list.
	engine.runZfsCmd = func(args ...string) ([]byte, error) {
		return nil, fmt.Errorf("simulated zfs failure")
	}
	engine.runZpoolCmd = func(args ...string) ([]byte, error) {
		return nil, fmt.Errorf("simulated zpool failure")
	}

	engine.detectInitialState()
	status := engine.GetStatus()

	if status.InstallMode != "zbm" {
		t.Fatalf("Expected InstallMode 'zbm', got %q", status.InstallMode)
	}
	if status.ZbmPoolHealth != "" {
		t.Errorf("Expected ZbmPoolHealth '' (unknown), got %q", status.ZbmPoolHealth)
	}
	if status.ZbmPoolTopology != "" {
		t.Errorf("Expected ZbmPoolTopology '' (unknown), got %q", status.ZbmPoolTopology)
	}
	// E2-9: no guessed root device. ActiveRootDevice comes from the
	// mounts-derived detection (the real root device in this sandbox),
	// never from the removed "zroot/ROOT/axonwall-<version>" guess.
	if status.ActiveRootDevice == "zroot/ROOT/axonwall-0.11.30" {
		t.Errorf("ActiveRootDevice must not be the guessed dataset, got %q", status.ActiveRootDevice)
	}
	if len(status.BootEnvironments) != 0 {
		t.Errorf("Expected no Boot Environments, got %d", len(status.BootEnvironments))
	}
}

// --- D2-L1: grubenv mirror uses the target file's env -------------------
// The mirror branch itself needs a mounted slot-A device and cannot run
// in this sandbox; what is unit-testable is the refactor it depends on:
// readGrubEnvAtPath reads the file it is given, not the engine's own.

func TestBatch16ReadGrubEnvAtPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "grubenv-a")
	if err := os.WriteFile(target, []byte("# GRUB Environment Block\nactive_slot=A\nbootcount=2\n"), 0644); err != nil {
		t.Fatalf("Failed to write mock grubenv: %v", err)
	}
	env := readGrubEnvAtPath(target)
	if env["active_slot"] != "A" || env["bootcount"] != "2" {
		t.Errorf("readGrubEnvAtPath returned %v, want active_slot=A bootcount=2", env)
	}
	if env := readGrubEnvAtPath(filepath.Join(dir, "missing")); len(env) != 0 {
		t.Errorf("readGrubEnvAtPath of a missing file should return an empty map, got %v", env)
	}
}

func TestZbmInitialVerificationSyncsBootfsWithoutClobberingSubsequentStage(t *testing.T) {
	tempDir := t.TempDir()
	cmdlinePath := filepath.Join(tempDir, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz zfs=zroot/ROOT/axonwall-0.11.62 root=zfs:zroot/ROOT/axonwall-0.11.62 ro quiet"), 0644); err != nil {
		t.Fatalf("Failed to write mock cmdline: %v", err)
	}
	engine := NewWatchdogEngineCustom(filepath.Join(tempDir, "grubenv"), cmdlinePath)
	engine.readInstalledVer = func() string { return "0.11.62" }

	zx := &batch16ListZfs{
		props: map[string]string{
			"org.axonwall:active_be": "zroot/ROOT/axonwall-0.11.57",
			"org.axonwall:bootcount": "1",
			"org.axonwall:bootlimit": "3",
			"origin":                 "zroot/ROOT/axonwall-0.11.57@pre-update-v0.11.62",
		},
		bootfs: "zroot/ROOT/axonwall-0.11.57",
		listOutput: "zroot/ROOT/axonwall-0.11.57\t1.4G\tTue Nov  3 09:16 2026\n" +
			"zroot/ROOT/axonwall-0.11.62\t1.7G\tSat Nov  7 21:43 2026\n" +
			"zroot/ROOT/axonwall-0.11.63.tmp\t10M\tSat Nov  7 21:44 2026\n",
	}
	engine.runZfsCmd = zx.runZfs
	engine.runZpoolCmd = zx.runZpool
	engine.checkInterfaces = func() HealthCheckResult {
		return HealthCheckResult{Name: "ifaces", Status: CheckStatusPass}
	}
	engine.checkNftables = func() HealthCheckResult {
		return HealthCheckResult{Name: "nft", Status: CheckStatusPass}
	}
	engine.checkControlPlane = func() HealthCheckResult {
		return HealthCheckResult{Name: "cp", Status: CheckStatusPass}
	}

	// Ensure .tmp dataset is filtered out from BE listing
	bes := engine.listBootEnvironmentsLocked()
	for _, be := range bes {
		if strings.HasSuffix(be.Name, ".tmp") {
			t.Errorf("Expected .tmp dataset to be excluded from BootEnvironments, got %s", be.Name)
		}
	}

	engine.status.InstallMode = "zbm"
	engine.status.ActiveRootDevice = "zroot/ROOT/axonwall-0.11.62"
	engine.runVerificationSequence()

	if !zx.hasSet("zpool set bootfs=zroot/ROOT/axonwall-0.11.62 zroot") {
		t.Errorf("Expected initial boot verification to sync bootfs to active BE; sets: %v", zx.sets)
	}
	if !zx.hasSet("set org.axonwall:active_be=zroot/ROOT/axonwall-0.11.62 zroot/ROOT") {
		t.Errorf("Expected initial boot verification to sync org.axonwall:active_be to active BE; sets: %v", zx.sets)
	}

	// Now simulate staging a new BE and running on-demand verification before reboot:
	// bootSyncDone must prevent clobbering the newly staged bootfs.
	zx.sets = nil
	engine.runVerificationSequence()
	if zx.hasSet("zpool set bootfs=zroot/ROOT/axonwall-0.11.62 zroot") {
		t.Errorf("Subsequent on-demand verification must not clobber bootfs; sets: %v", zx.sets)
	}
}
