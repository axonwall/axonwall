package engine

import (
	"fmt"
	"strings"
	"testing"
)

// Batch 5 (round-4 fix run, slice E): R4-E-M1 is a shell-script fix
// covered by the namespace simulation in results-batch5.md, not by Go
// tests. R4-E-M2, R4-E-L2 are covered here; R4-E-L1 is a shell-script
// fix (best-effort cleanup on the ZBM unmount-failure path) with no
// Go surface.

// batch5FakeZfs models a ZFS pool for the round-4 batch-5 tests: a set
// of existing datasets, a property table, and an optional canned
// recursive `zfs list` output for listBootEnvironmentsLocked. One
// instance serves both the zfs and zpool runners (the two commands
// take the same get/set/list shapes this batch exercises). Unlike
// fakeZxCommands, a single-dataset `zfs list` here answers from the
// datasets set — which is exactly what the R4-E-M2 existence check
// depends on.
type batch5FakeZfs struct {
	datasets   map[string]bool
	props      map[string]string
	listOutput string
	failList   bool // recursive `zfs list` fails (listBootEnvironmentsLocked falls back to the cached list)
	sets       []string
	failSets   map[string]bool
}

func (f *batch5FakeZfs) run(args ...string) ([]byte, error) {
	cmd := strings.Join(args, " ")
	switch args[0] {
	case "get":
		prop := args[len(args)-2]
		if v, ok := f.props[prop]; ok {
			return []byte(v + "\n"), nil
		}
		return nil, fmt.Errorf("property %s not found", prop)
	case "set":
		kv := args[1]
		if f.failSets[kv] {
			return nil, fmt.Errorf("simulated set failure for %s", kv)
		}
		if eq := strings.Index(kv, "="); eq >= 0 {
			f.props[kv[:eq]] = kv[eq+1:]
		}
		f.sets = append(f.sets, cmd)
		return []byte("ok"), nil
	case "list":
		if strings.Contains(cmd, "snapshot") {
			return []byte(""), nil
		}
		if strings.Contains(cmd, "-r") {
			if f.failList {
				return nil, fmt.Errorf("simulated zfs list failure")
			}
			return []byte(f.listOutput), nil
		}
		// Single-dataset existence probe (R4-E-M2): `zfs list -H
		// -o name <dataset>` succeeds only when the dataset exists.
		ds := args[len(args)-1]
		if f.datasets[ds] {
			return []byte(ds + "\n"), nil
		}
		return []byte(fmt.Sprintf("cannot open '%s': dataset does not exist\n", ds)), fmt.Errorf("dataset does not exist")
	}
	return []byte("ok"), nil
}

func (f *batch5FakeZfs) hasSet(want string) bool {
	for _, s := range f.sets {
		if s == want {
			return true
		}
	}
	return false
}

func batch5Be(name, created string, now, next bool) ZfsBootEnvironment {
	return ZfsBootEnvironment{
		Name: name, Dataset: "zroot/ROOT/" + name,
		ActiveNow: now, ActiveNext: next, CreatedAt: created,
	}
}

// R4-E-M2: activating a syntactically valid BE whose dataset does not
// exist must refuse BEFORE any `zpool set bootfs` — OpenZFS validates
// bootfs only syntactically (bootfs_name_valid checks name syntax and
// same-pool prefix; it never opens the dataset), so without this check
// the daemon would arm an unbootable next boot and report success.
func TestBatch5ActivateRefusesDanglingBootEnvironment(t *testing.T) {
	zx := &batch5FakeZfs{
		datasets: map[string]bool{"zroot/ROOT/axonwall-0.11.30": true},
		props: map[string]string{
			"bootfs":                   "zroot/ROOT/axonwall-0.11.30",
			"org.axonwall:active_be":   "zroot/ROOT/axonwall-0.11.30",
			"org.axonwall:bootcount":   "0",
			"org.axonwall:bootlimit":   "3",
			"org.axonwall:fallback_be": "zroot/ROOT/axonwall-0.11.30",
		},
	}
	engine := newZbmActivateTestEngine(t, &fakeZxCommands{props: zx.props}, &fakeZxCommands{props: zx.props})
	// Drive both runners through the one existence-modeling fake.
	engine.runZfsCmd = zx.run
	engine.runZpoolCmd = zx.run

	err := engine.ActivateBootEnvironment("axonwall-0.11.31")
	if err == nil {
		t.Fatal("expected activation to fail for a nonexistent BE dataset")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected the error to say the dataset does not exist, got: %v", err)
	}
	if zx.hasSet("set bootfs=zroot/ROOT/axonwall-0.11.31 zroot") {
		t.Fatal("bootfs must never be set to a dataset that does not exist")
	}
}

// R4-E-M2 (positive control): activating a BE whose dataset exists
// still succeeds and arms it exactly as before.
func TestBatch5ActivateSucceedsForExistingBootEnvironment(t *testing.T) {
	zx := &batch5FakeZfs{
		datasets: map[string]bool{
			"zroot/ROOT/axonwall-0.11.30": true,
			"zroot/ROOT/axonwall-0.11.31": true,
		},
		props: map[string]string{
			"bootfs":                 "zroot/ROOT/axonwall-0.11.30",
			"org.axonwall:active_be": "zroot/ROOT/axonwall-0.11.30",
			"org.axonwall:bootcount": "0",
			"org.axonwall:bootlimit": "3",
		},
	}
	engine := newZbmActivateTestEngine(t, &fakeZxCommands{props: zx.props}, &fakeZxCommands{props: zx.props})
	engine.runZfsCmd = zx.run
	engine.runZpoolCmd = zx.run

	if err := engine.ActivateBootEnvironment("axonwall-0.11.31"); err != nil {
		t.Fatalf("ActivateBootEnvironment failed for an existing BE: %v", err)
	}
	if !zx.hasSet("set bootfs=zroot/ROOT/axonwall-0.11.31 zroot") {
		t.Fatalf("expected bootfs to be set to the existing BE; sets: %v", zx.sets)
	}
}

// R4-E-L2: the rollback selector never picks a staged (ActiveNext),
// untested BE, even when it is the newest standby.
func TestBatch5SelectRollbackBE(t *testing.T) {
	cases := []struct {
		name string
		bes  []ZfsBootEnvironment
		want string // "" means nil
	}{
		{
			name: "staged newest is skipped for the last verified-good standby",
			bes: []ZfsBootEnvironment{
				batch5Be("axonwall-0.12.2", "Mon Jan 12 10:00 2026", true, false),
				batch5Be("axonwall-0.12.3", "Mon Jan 19 10:00 2026", false, true),
				batch5Be("axonwall-0.12.1", "Mon Jan  5 10:00 2026", false, false),
			},
			want: "axonwall-0.12.1",
		},
		{
			name: "newest non-staged wins when the staged BE is newest",
			bes: []ZfsBootEnvironment{
				batch5Be("axonwall-0.12.1", "Mon Jan  5 10:00 2026", false, false),
				batch5Be("axonwall-0.12.2", "Mon Jan 12 10:00 2026", false, false),
				batch5Be("axonwall-0.12.3", "Mon Jan 19 10:00 2026", false, true),
			},
			want: "axonwall-0.12.2",
		},
		{
			name: "only a staged standby returns nil (fail loudly, do not arm it)",
			bes: []ZfsBootEnvironment{
				batch5Be("axonwall-0.12.2", "Mon Jan 12 10:00 2026", true, false),
				batch5Be("axonwall-0.12.3", "Mon Jan 19 10:00 2026", false, true),
			},
			want: "",
		},
		{
			name: "unparseable creation falls back to last non-staged in list order",
			bes: []ZfsBootEnvironment{
				batch5Be("axonwall-0.12.3", "garbage", false, true),
				batch5Be("axonwall-0.12.1", "also garbage", false, false),
				batch5Be("axonwall-0.12.2", "still garbage", false, false),
			},
			want: "axonwall-0.12.2",
		},
		{
			name: "empty list returns nil",
			bes:  nil,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := selectRollbackBE(tc.bes)
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

// R4-E-L2 (contrast): the shared slot selector still prefers the
// staged BE — that is the documented ActivateSlot("B") semantic, and
// this batch deliberately leaves it alone. The rollback path must not
// share it.
func TestBatch5SelectStandbyBEStillPrefersStaged(t *testing.T) {
	bes := []ZfsBootEnvironment{
		batch5Be("axonwall-0.12.2", "Mon Jan 12 10:00 2026", true, false),
		batch5Be("axonwall-0.12.3", "Mon Jan 19 10:00 2026", false, true),
		batch5Be("axonwall-0.12.1", "Mon Jan  5 10:00 2026", false, false),
	}
	if got := selectStandbyBE(bes); got == nil || got.Name != "axonwall-0.12.3" {
		t.Fatalf("selectStandbyBE must still prefer the staged BE for slot B, got %+v", got)
	}
	if got := selectRollbackBE(bes); got == nil || got.Name != "axonwall-0.12.1" {
		t.Fatalf("selectRollbackBE must skip the staged BE, got %+v", got)
	}
}

func batch5RollbackEngine(t *testing.T, zx *batch5FakeZfs, bes []ZfsBootEnvironment) *WatchdogEngine {
	t.Helper()
	engine := newZbmActivateTestEngine(t, &fakeZxCommands{props: zx.props}, &fakeZxCommands{props: zx.props})
	engine.runZfsCmd = zx.run
	engine.runZpoolCmd = zx.run
	engine.status.InstallMode = "zbm"
	engine.status.BootEnvironments = bes
	return engine
}

// R4-E-L2 (end to end): with fallback_be unset and a staged BE
// present, TriggerRollback arms the last verified-good standby — not
// the staged BE, not the running BE.
func TestBatch5TriggerRollbackSkipsStagedBE(t *testing.T) {
	zx := &batch5FakeZfs{
		datasets: map[string]bool{
			"zroot/ROOT/axonwall-0.12.1": true,
			"zroot/ROOT/axonwall-0.12.2": true,
			"zroot/ROOT/axonwall-0.12.3": true,
		},
		props: map[string]string{
			"bootfs":                   "zroot/ROOT/axonwall-0.12.3",
			"org.axonwall:fallback_be": "-",
			"org.axonwall:active_be":   "zroot/ROOT/axonwall-0.12.2",
			"org.axonwall:bootcount":   "0",
			"org.axonwall:bootlimit":   "3",
		},
		// The recursive list fails so listBootEnvironmentsLocked
		// returns the cached list with exact ActiveNow/ActiveNext
		// flags: /proc/mounts in this sandbox never marks a BE
		// ActiveNow, so a live listing cannot express "running" here.
		failList: true,
	}
	bes := []ZfsBootEnvironment{
		batch5Be("axonwall-0.12.2", "Mon Jan 12 10:00 2026", true, false),
		batch5Be("axonwall-0.12.3", "Mon Jan 19 10:00 2026", false, true),
		batch5Be("axonwall-0.12.1", "Mon Jan  5 10:00 2026", false, false),
	}
	engine := batch5RollbackEngine(t, zx, bes)

	if err := engine.TriggerRollback(); err != nil {
		t.Fatalf("TriggerRollback failed: %v", err)
	}
	if !zx.hasSet("set bootfs=zroot/ROOT/axonwall-0.12.1 zroot") {
		t.Fatalf("rollback must arm the last verified-good standby (0.12.1); sets: %v", zx.sets)
	}
	if zx.hasSet("set bootfs=zroot/ROOT/axonwall-0.12.3 zroot") {
		t.Fatal("rollback must never arm the staged, untested BE (0.12.3)")
	}
	if zx.hasSet("set bootfs=zroot/ROOT/axonwall-0.12.2 zroot") {
		t.Fatal("rollback must not arm the running BE (0.12.2)")
	}
}

// R4-E-L2 (fail loud): with fallback_be unset and only a staged BE
// available, rollback fails instead of arming the staged BE.
func TestBatch5TriggerRollbackFailsWhenOnlyStagedExists(t *testing.T) {
	zx := &batch5FakeZfs{
		datasets: map[string]bool{
			"zroot/ROOT/axonwall-0.12.2": true,
			"zroot/ROOT/axonwall-0.12.3": true,
		},
		props: map[string]string{
			"bootfs":                   "zroot/ROOT/axonwall-0.12.3",
			"org.axonwall:fallback_be": "-",
			"org.axonwall:active_be":   "zroot/ROOT/axonwall-0.12.2",
			"org.axonwall:bootcount":   "0",
			"org.axonwall:bootlimit":   "3",
		},
		failList: true,
	}
	bes := []ZfsBootEnvironment{
		batch5Be("axonwall-0.12.2", "Mon Jan 12 10:00 2026", true, false),
		batch5Be("axonwall-0.12.3", "Mon Jan 19 10:00 2026", false, true),
	}
	engine := batch5RollbackEngine(t, zx, bes)

	err := engine.TriggerRollback()
	if err == nil {
		t.Fatal("expected rollback to fail when only a staged BE exists")
	}
	if !strings.Contains(err.Error(), "verified-good") {
		t.Fatalf("expected the error to say no verified-good fallback exists, got: %v", err)
	}
	if zx.hasSet("set bootfs=zroot/ROOT/axonwall-0.12.3 zroot") {
		t.Fatal("rollback must never arm the staged BE, even when it is the only standby")
	}
}
