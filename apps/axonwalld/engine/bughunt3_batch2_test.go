package engine

// Round-3 bug-hunt batch 2 tests (A-M5..A-M10, A-L1..A-L5).
// Every test reproduces the finding against the pre-fix behaviour first
// (documented in the test body) and asserts the fixed behaviour.
// Live-box / live-daemon / live-ZFS behaviour is NOT verified here:
// where the real tool is absent from the sandbox (zfs, targetctl),
// a fake binary on PATH emulates the tool's documented interface
// contract — OpenZFS `zfs change-key` prompting twice is documented
// in the zfs-change-key(8) man page and in the upstream rotation
// guides, and `targetctl restore` exiting non-zero on a bad config
// is its normal failure mode.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func bughunt3WriteFakeBin(t *testing.T, dir, name, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
}

// A-M5: a failing `targetctl restore` must fail the NAS apply instead
// of being swallowed while the bundle is stored as live config.
func TestBughunt3Batch2_NasApplyLioRestoreFailure(t *testing.T) {
	dir := t.TempDir()
	bughunt3WriteFakeBin(t, dir, "targetctl", "#!/bin/sh\necho 'targetctl: failed to restore: invalid saveconfig' >&2\nexit 1\n")
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	defer os.Remove("/etc/rtslib-fb-target/saveconfig.json")

	mgr := NewNasManager()
	err := mgr.ApplyConfig([]byte(`{"enabled":true,"lioSaveconfigJson":"{\"version\":1}"}`))
	if err == nil {
		t.Fatal("ApplyConfig must fail when targetctl restore fails")
	}
	if !strings.Contains(err.Error(), "targetctl restore failed") {
		t.Fatalf("expected a targetctl restore error, got: %v", err)
	}
}

// A-M5: a failing MinIO reload must fail the NAS apply.
func TestBughunt3Batch2_NasApplyMinioReloadFailure(t *testing.T) {
	dir := t.TempDir()
	bughunt3WriteFakeBin(t, dir, "systemctl", `#!/bin/sh
if [ "$1" = "is-active" ]; then exit 0; fi
if [ "$1" = "reload-or-restart" ]; then echo 'Failed to reload minio.service' >&2; exit 1; fi
exit 0
`)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	defer os.Remove("/etc/default/minio")

	mgr := NewNasManager()
	err := mgr.ApplyConfig([]byte(`{"enabled":true,"s3EnvConf":"MINIO_ROOT_USER=axw\n"}`))
	if err == nil {
		t.Fatal("ApplyConfig must fail when the minio reload fails")
	}
	if !strings.Contains(err.Error(), "failed to reload-or-restart minio") {
		t.Fatalf("expected a minio reload error, got: %v", err)
	}
}

// A-M7: a failing follow-up `zfs mount` after a successful load-key
// must fail the unlock instead of reporting success.
func TestBughunt3Batch2_DatasetKeyMountFailure(t *testing.T) {
	dir := t.TempDir()
	bughunt3WriteFakeBin(t, dir, "zfs", `#!/bin/sh
if [ "$1" = "load-key" ]; then exit 0; fi
if [ "$1" = "mount" ]; then echo "cannot mount 'tank/data': mountpoint does not exist" >&2; exit 1; fi
exit 0
`)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	mgr := NewNasManager()
	if err := mgr.DatasetKeyAction("tank/data", "load-key", "correct-horse-battery"); err == nil {
		t.Fatal("load-key must fail when the follow-up zfs mount fails")
	} else if !strings.Contains(err.Error(), "zfs mount") {
		t.Fatalf("expected a zfs mount error, got: %v", err)
	}
}

// A-M7 (tolerance): a dataset that is already mounted is accessible,
// so the "already mounted" mount error is not a failure.
func TestBughunt3Batch2_DatasetKeyMountAlreadyMounted(t *testing.T) {
	dir := t.TempDir()
	bughunt3WriteFakeBin(t, dir, "zfs", `#!/bin/sh
if [ "$1" = "load-key" ]; then exit 0; fi
if [ "$1" = "mount" ]; then echo "cannot mount 'tank/data': filesystem already mounted" >&2; exit 1; fi
exit 0
`)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	mgr := NewNasManager()
	if err := mgr.DatasetKeyAction("tank/data", "load-key", "correct-horse-battery"); err != nil {
		t.Fatalf("load-key must succeed when the dataset is already mounted, got: %v", err)
	}
}

// A-M10: `zfs change-key -o keylocation=prompt -o keyformat=passphrase`
// prompts for the new passphrase TWICE. The fake zfs below emulates
// that documented contract: it reads two lines from stdin and fails
// when the second prompt hits EOF (the pre-fix single-line stdin) or
// when the two lines differ. No real zfs exists in this sandbox, so
// the live-ZFS run is still unverified; this proves the daemon now
// supplies what the tool's interface requires.
func TestBughunt3Batch2_DatasetKeyChangeKeyTwoPrompts(t *testing.T) {
	dir := t.TempDir()
	bughunt3WriteFakeBin(t, dir, "zfs", `#!/bin/sh
if [ "$1" = "change-key" ]; then
  IFS= read -r first || { echo 'cannot change key: failed to read passphrase' >&2; exit 1; }
  IFS= read -r second || { echo 'cannot change key: failed to read passphrase confirmation' >&2; exit 1; }
  if [ "$first" != "$second" ]; then echo 'passphrases do not match' >&2; exit 1; fi
  echo "$first" > "$FAKE_ZFS_SEEN"
  echo "$second" >> "$FAKE_ZFS_SEEN"
  exit 0
fi
exit 0
`)
	seen := filepath.Join(dir, "seen-passphrases")
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("FAKE_ZFS_SEEN", seen)

	mgr := NewNasManager()
	if err := mgr.DatasetKeyAction("tank/data", "change-key", "correct-horse-battery"); err != nil {
		t.Fatalf("change-key must succeed when both prompts are answered, got: %v", err)
	}
	lines, err := os.ReadFile(seen)
	if err != nil {
		t.Fatalf("fake zfs did not record the passphrases: %v", err)
	}
	if got := strings.TrimSpace(string(lines)); got != "correct-horse-battery\ncorrect-horse-battery" {
		t.Fatalf("expected the new passphrase supplied twice, got: %q", got)
	}
}

// A-M8: an unrecognised direction must fail before rclone runs —
// it used to fall through to a destructive `rclone sync` push.
func TestBughunt3Batch2_CloudSyncInvalidDirection(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "rclone-invoked")
	bughunt3WriteFakeBin(t, dir, "rclone", "#!/bin/sh\ntouch "+marker+"\nexit 0\n")
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	for _, bad := range []string{"", "download", "Push ", "pullx"} {
		mgr := &NasManager{cfg: NasRuntimeBundle{CloudSyncTasks: []CloudSyncTaskSpec{
			{Name: "t1", Direction: bad, Dataset: "tank/data", RemoteBucket: "bucket"},
		}}}
		// "Push " normalises to the valid direction "push", so it is
		// not in the invalid set; skip it here (covered below).
		if strings.TrimSpace(bad) == "Push" {
			continue
		}
		if _, err := mgr.RunCloudSyncTask("t1"); err == nil {
			t.Fatalf("direction %q must be rejected", bad)
		} else if !strings.Contains(err.Error(), "invalid direction") {
			t.Fatalf("direction %q: expected an invalid-direction error, got: %v", bad, err)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("rclone must not be invoked for an invalid direction")
	}
}

// A-M8: the two documented directions still run, in the right order.
func TestBughunt3Batch2_CloudSyncDirections(t *testing.T) {
	for _, tc := range []struct {
		direction string
		wantFirst string // first path argument after "sync"
	}{
		{"push", "/mnt/tank/data"},
		{"Push", "/mnt/tank/data"},
		{"pull", ":s3:bucket"},
	} {
		dir := t.TempDir()
		argsFile := filepath.Join(dir, "rclone-args")
		bughunt3WriteFakeBin(t, dir, "rclone", "#!/bin/sh\nprintf '%s\\n' \"$@\" > "+argsFile+"\nexit 0\n")
		t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

		mgr := &NasManager{cfg: NasRuntimeBundle{CloudSyncTasks: []CloudSyncTaskSpec{
			{Name: "t1", Direction: tc.direction, Dataset: "tank/data", RemoteBucket: "bucket"},
		}}}
		if _, err := mgr.RunCloudSyncTask("t1"); err != nil {
			t.Fatalf("direction %q must run, got: %v", tc.direction, err)
		}
		raw, err := os.ReadFile(argsFile)
		if err != nil {
			t.Fatalf("direction %q: fake rclone was not invoked: %v", tc.direction, err)
		}
		args := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(args) < 3 || args[0] != "sync" || args[1] != tc.wantFirst {
			t.Fatalf("direction %q: unexpected rclone args %v, want first arg %q after sync", tc.direction, args, tc.wantFirst)
		}
	}
}

// A-M9: a failing `systemctl stop k3s` must fail the restore before
// the cluster reset runs against a possibly live etcd.
func TestBughunt3Batch2_RestoreEtcdSnapshotStopFailure(t *testing.T) {
	dir := t.TempDir()
	snapDir := t.TempDir()
	origSnapDir := k3sEtcdSnapshotDir
	k3sEtcdSnapshotDir = snapDir
	defer func() { k3sEtcdSnapshotDir = origSnapDir }()
	if err := os.WriteFile(filepath.Join(snapDir, "snap.db"), []byte("fake"), 0600); err != nil {
		t.Fatal(err)
	}
	bughunt3WriteFakeBin(t, dir, "k3s", "#!/bin/sh\necho 'k3s should not run after a failed stop' >&2\nexit 1\n")
	bughunt3WriteFakeBin(t, dir, "systemctl", `#!/bin/sh
if [ "$1" = "stop" ]; then echo 'Failed to stop k3s.service' >&2; exit 1; fi
exit 0
`)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	mgr := NewK3sManager()
	if err := mgr.RestoreEtcdSnapshot("snap.db"); err == nil {
		t.Fatal("restore must fail when stopping k3s fails")
	} else if !strings.Contains(err.Error(), "failed to stop") {
		t.Fatalf("expected a stop error, got: %v", err)
	}
}

// A-M9 (success path): stop + reset + start all succeeding restores.
func TestBughunt3Batch2_RestoreEtcdSnapshotSuccess(t *testing.T) {
	dir := t.TempDir()
	snapDir := t.TempDir()
	origSnapDir := k3sEtcdSnapshotDir
	k3sEtcdSnapshotDir = snapDir
	defer func() { k3sEtcdSnapshotDir = origSnapDir }()
	if err := os.WriteFile(filepath.Join(snapDir, "snap.db"), []byte("fake"), 0600); err != nil {
		t.Fatal(err)
	}
	bughunt3WriteFakeBin(t, dir, "k3s", "#!/bin/sh\nexit 0\n")
	bughunt3WriteFakeBin(t, dir, "systemctl", "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	mgr := NewK3sManager()
	if err := mgr.RestoreEtcdSnapshot("snap.db"); err != nil {
		t.Fatalf("restore must succeed when stop/reset/start succeed, got: %v", err)
	}
}

// A-L1: a failed upsert save must not leave the new profile live in
// memory, and a failed delete save must not leave it deleted from
// memory. The save is forced to fail by pointing the profiles path
// under a regular file, so MkdirAll fails.
func TestBughunt3Batch2_BpfTokenProfileSaveRollback(t *testing.T) {
	origPath := BpfTokenProfilesPath
	defer func() { BpfTokenProfilesPath = origPath }()

	goodDir := t.TempDir()
	BpfTokenProfilesPath = filepath.Join(goodDir, "profiles.json")
	mgr := NewBpfTokenManager()
	prof := BpfTokenDelegationProfile{
		ID:         "vm-101-net",
		TargetKind: "standalone",
		TargetRef:  "vm-101",
		Preset:     "network-dataplane",
		Enabled:    true,
	}
	if _, err := mgr.UpsertProfile(prof); err != nil {
		t.Fatalf("setup upsert failed: %v", err)
	}

	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	BpfTokenProfilesPath = filepath.Join(blocker, "profiles.json")

	// Failed upsert of a NEW profile: memory must not gain it.
	if _, err := mgr.UpsertProfile(BpfTokenDelegationProfile{
		ID:         "vm-102-net",
		TargetKind: "standalone",
		TargetRef:  "vm-102",
		Preset:     "network-dataplane",
		Enabled:    true,
	}); err == nil {
		t.Fatal("upsert must fail when the profiles file cannot be saved")
	}
	if _, ok := mgr.GetProfile("vm-102-net"); ok {
		t.Fatal("failed upsert left the new profile live in memory")
	}

	// Failed upsert of an EXISTING profile: memory must keep the old one.
	if _, err := mgr.UpsertProfile(BpfTokenDelegationProfile{
		ID:         "vm-101-net",
		TargetKind: "standalone",
		TargetRef:  "vm-101",
		Preset:     "network-dataplane",
		Enabled:    false,
	}); err == nil {
		t.Fatal("upsert must fail when the profiles file cannot be saved")
	}
	if got, ok := mgr.GetProfile("vm-101-net"); !ok || !got.Enabled {
		t.Fatalf("failed upsert overwrote the in-memory profile: %+v (ok=%v)", got, ok)
	}

	// Failed delete: memory must keep the profile.
	if err := mgr.DeleteProfile("vm-101-net"); err == nil {
		t.Fatal("delete must fail when the profiles file cannot be saved")
	}
	if _, ok := mgr.GetProfile("vm-101-net"); !ok {
		t.Fatal("failed delete removed the profile from memory while disk still holds it")
	}
}

// A-L2: an out-of-range SYN-flood limit from the environment must not
// be recorded as the enforced limit.
func TestBughunt3Batch2_SynFloodEnvLimitValidated(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want uint64
	}{
		{"5", 0},        // below the 20 pps minimum: ignored, limiter disabled
		{"19", 0},       // below the 20 pps minimum: ignored
		{"20", 20},      // minimum: accepted
		{"100", 100},    // in range: accepted
		{"10000001", 0}, // above the maximum: ignored
		{"bogus", 0},    // unparsable: ignored
	} {
		t.Setenv("AXONWALL_XDP_SYN_FLOOD_PPS", tc.env)
		mgr := NewEBPFManager()
		if got := mgr.synFloodLimitPps.Load(); got != tc.want {
			t.Fatalf("env %q: SynFloodLimitPps = %d, want %d", tc.env, got, tc.want)
		}
	}
	// The API setter still enforces the same bounds.
	mgr := NewEBPFManager()
	if err := mgr.SetSynFloodLimitPps(5); err == nil {
		t.Fatal("SetSynFloodLimitPps(5) must be rejected")
	}
}

// A-L3: VM rows in eBPF telemetry must surface a BPF-token profile
// targeting the VM, like LXC rows already did.
func TestBughunt3Batch2_VirtEbpfTelemetryVmBpfToken(t *testing.T) {
	origPath := BpfTokenProfilesPath
	BpfTokenProfilesPath = filepath.Join(t.TempDir(), "bpf-token-profiles.json")
	defer func() { BpfTokenProfilesPath = origPath }()

	if _, err := GetDefaultBpfTokenManager().UpsertProfile(BpfTokenDelegationProfile{
		ID:         "vm-101-net",
		TargetKind: "standalone",
		TargetRef:  "vm-101",
		Preset:     "network-dataplane",
		Enabled:    true,
	}); err != nil {
		t.Fatalf("setup profile upsert failed: %v", err)
	}

	virt := &VirtManager{vmSpecs: map[int]CompiledVmSpec{
		101: {VMID: 101, Name: "test-vm"},
	}}
	tel := virt.GetEbpfTelemetry()
	var row *VirtWorkloadEbpfSummary
	for i := range tel.Workloads {
		if tel.Workloads[i].Kind == "vm" && tel.Workloads[i].ID == 101 {
			row = &tel.Workloads[i]
		}
	}
	if row == nil {
		t.Fatal("expected a VM telemetry row for VM 101")
	}
	if !row.BpfTokenEnabled || row.BpfTokenProfileID != "vm-101-net" || row.BpfTokenPreset != "network-dataplane" {
		t.Fatalf("VM row must surface the vm-101 profile, got %+v", *row)
	}
}

// A-L4: GetStatus must report the configured ZFS local PV pool.
func TestBughunt3Batch2_K3sGetStatusPvPool(t *testing.T) {
	mgr := &K3sManager{cfg: K3sRuntimeBundle{ZfsLocalPvPool: "dozer"}}
	if got := mgr.GetStatus().ZfsLocalPvPool; got != "dozer" {
		t.Fatalf("ZfsLocalPvPool = %q, want %q", got, "dozer")
	}
	mgr = &K3sManager{cfg: K3sRuntimeBundle{}}
	if got := mgr.GetStatus().ZfsLocalPvPool; got != "tank" {
		t.Fatalf("unconfigured ZfsLocalPvPool = %q, want default %q", got, "tank")
	}
}

// A-L5: a pool with no config entry reports "unknown" topology,
// not an invented "mirror".
func TestBughunt3Batch2_ListPoolsUnknownTopology(t *testing.T) {
	dir := t.TempDir()
	bughunt3WriteFakeBin(t, dir, "zpool", "#!/bin/sh\nprintf 'tank\\t107374182400\\t1073741824\\t106300440576\\t0%%\\t1%%\\tONLINE\\n'\n")
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	mgr := &NasManager{cfg: NasRuntimeBundle{}}
	pools := mgr.ListPools()
	if len(pools) != 1 {
		t.Fatalf("expected 1 pool, got %d", len(pools))
	}
	if pools[0].Topology != "unknown" {
		t.Fatalf("unconfigured pool topology = %q, want %q", pools[0].Topology, "unknown")
	}

	mgr = &NasManager{cfg: NasRuntimeBundle{Pools: []ZfsPoolSpec{
		{Name: "tank", Topology: "raidz1"},
	}}}
	pools = mgr.ListPools()
	if len(pools) != 1 || pools[0].Topology != "raidz1" {
		t.Fatalf("configured pool topology = %q, want %q", pools[0].Topology, "raidz1")
	}
}

// A-M6: tc/ip cleanup failures must be reported, not discarded.
// The fake tc fails every delete; the fake ip distinguishes the
// "already gone" case (nil) from a real failure (error).
func TestBughunt3Batch2_CleanupKernelArtifacts(t *testing.T) {
	mgr := &McpTrafficManager{}

	// Shape lease on a live interface (lo) with tc failing: error.
	dir := t.TempDir()
	bughunt3WriteFakeBin(t, dir, "tc", "#!/bin/sh\necho 'RTNETLINK answers: Operation not permitted' >&2\nexit 1\n")
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	shape := &McpTacticalLease{
		ID: "lease-shape", Kind: "shape", ClassID: 501, FwMark: 0x1f4,
		Parameters: map[string]interface{}{"interface": "lo"},
	}
	if err := mgr.cleanupKernelArtifactsForLease(shape); err == nil {
		t.Fatal("shape cleanup must fail when tc deletes fail")
	} else if !strings.Contains(err.Error(), "tc filter del") {
		t.Fatalf("expected a tc filter error, got: %v", err)
	}

	// Same tc, but reporting "already gone": not a failure.
	bughunt3WriteFakeBin(t, dir, "tc", "#!/bin/sh\necho 'RTNETLINK answers: No such file or directory' >&2\nexit 1\n")
	if err := mgr.cleanupKernelArtifactsForLease(shape); err != nil {
		t.Fatalf("tc delete of an already-gone object must not fail, got: %v", err)
	}

	// Shape lease on an interface that no longer exists: the qdisc
	// went with the device, so there is nothing to delete — and tc
	// must not even be invoked. The fake tc fails if called.
	bughunt3WriteFakeBin(t, dir, "tc", "#!/bin/sh\necho 'tc must not be called for a gone interface' >&2\nexit 1\n")
	stale := &McpTacticalLease{
		ID: "lease-stale", Kind: "shape", ClassID: 502, FwMark: 0x1f5,
		Parameters: map[string]interface{}{"interface": "eth9-gone"},
	}
	if err := mgr.cleanupKernelArtifactsForLease(stale); err != nil {
		t.Fatalf("cleanup for a removed interface must succeed, got: %v", err)
	}

	// Blackhole route delete failing for real: error.
	bughunt3WriteFakeBin(t, dir, "ip", "#!/bin/sh\necho 'RTNETLINK answers: Operation not permitted' >&2\nexit 1\n")
	blackhole := &McpTacticalLease{
		ID: "lease-bh", Kind: "blackhole", NormalizedTarget: "203.0.113.7",
		Parameters: map[string]interface{}{"mode": "route_blackhole"},
	}
	if err := mgr.cleanupKernelArtifactsForLease(blackhole); err == nil {
		t.Fatal("blackhole cleanup must fail when ip route del fails")
	}

	// Blackhole route already gone: not a failure.
	bughunt3WriteFakeBin(t, dir, "ip", "#!/bin/sh\necho 'RTNETLINK answers: No such process' >&2\nexit 1\n")
	if err := mgr.cleanupKernelArtifactsForLease(blackhole); err != nil {
		t.Fatalf("ip route del of an already-gone route must not fail, got: %v", err)
	}
}

// A-M6: a RevertLease whose tc cleanup fails must return an error
// (so the API caller is told enforcement may persist) and queue the
// lease for janitor retry — instead of returning success with the
// record gone and the shaping orphaned.
func TestBughunt3Batch2_RevertLeaseCleanupFailure(t *testing.T) {
	dir := t.TempDir()
	bughunt3WriteFakeBin(t, dir, "nft", "#!/bin/sh\nexit 0\n")
	bughunt3WriteFakeBin(t, dir, "tc", "#!/bin/sh\necho 'RTNETLINK answers: Operation not permitted' >&2\nexit 1\n")
	bughunt3WriteFakeBin(t, dir, "ip", "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	origState := mcpStateFilePath
	mcpStateFilePath = filepath.Join(t.TempDir(), "mcp-state.json")
	defer func() { mcpStateFilePath = origState }()

	lease := &McpTacticalLease{
		ID: "lease-revert", Kind: "shape", ClassID: 501, FwMark: 0x1f4,
		ExpiresAt:  time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Parameters: map[string]interface{}{"interface": "lo"},
	}
	mgr := &McpTrafficManager{
		leases:           map[string]*McpTacticalLease{lease.ID: lease},
		reservedClassIDs: map[int]struct{}{},
	}
	_, err := mgr.RevertLease(lease.ID)
	if err == nil {
		t.Fatal("RevertLease must fail when the tc cleanup fails")
	}
	if !errors.Is(err, ErrMcpKernelCleanupFailed) {
		t.Fatalf("expected ErrMcpKernelCleanupFailed, got: %v", err)
	}
	if _, ok := mgr.leases[lease.ID]; ok {
		t.Fatal("reverted lease record must be gone")
	}
	if len(mgr.pendingCleanup) != 1 || mgr.pendingCleanup[0].ID != lease.ID {
		t.Fatalf("failed cleanup must be queued for janitor retry, pending=%v", mgr.pendingCleanup)
	}
}

// A-M6: FlushAllLeases reports the cleanup failure too.
func TestBughunt3Batch2_FlushAllLeasesCleanupFailure(t *testing.T) {
	dir := t.TempDir()
	bughunt3WriteFakeBin(t, dir, "nft", "#!/bin/sh\nexit 0\n")
	bughunt3WriteFakeBin(t, dir, "tc", "#!/bin/sh\necho 'RTNETLINK answers: Operation not permitted' >&2\nexit 1\n")
	bughunt3WriteFakeBin(t, dir, "ip", "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	origState := mcpStateFilePath
	mcpStateFilePath = filepath.Join(t.TempDir(), "mcp-state.json")
	defer func() { mcpStateFilePath = origState }()

	lease := &McpTacticalLease{
		ID: "lease-flush", Kind: "shape", ClassID: 501, FwMark: 0x1f4,
		ExpiresAt:  time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Parameters: map[string]interface{}{"interface": "lo"},
	}
	mgr := &McpTrafficManager{
		leases:           map[string]*McpTacticalLease{lease.ID: lease},
		reservedClassIDs: map[int]struct{}{},
	}
	cleared, err := mgr.FlushAllLeases()
	if err == nil {
		t.Fatal("FlushAllLeases must fail when the tc cleanup fails")
	}
	if !errors.Is(err, ErrMcpKernelCleanupFailed) {
		t.Fatalf("expected ErrMcpKernelCleanupFailed, got: %v", err)
	}
	if cleared != 1 {
		t.Fatalf("cleared = %d, want 1", cleared)
	}
	if len(mgr.pendingCleanup) != 1 {
		t.Fatalf("failed cleanup must be queued for janitor retry, pending=%v", mgr.pendingCleanup)
	}
}

// A-M6: the janitor retry drains a queued cleanup once tc works,
// and keeps it queued while tc still fails.
func TestBughunt3Batch2_RetryPendingCleanups(t *testing.T) {
	dir := t.TempDir()
	bughunt3WriteFakeBin(t, dir, "tc", "#!/bin/sh\necho 'RTNETLINK answers: Operation not permitted' >&2\nexit 1\n")
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	lease := &McpTacticalLease{
		ID: "lease-retry", Kind: "shape", ClassID: 501, FwMark: 0x1f4,
		Parameters: map[string]interface{}{"interface": "lo"},
	}
	mgr := &McpTrafficManager{reservedClassIDs: map[int]struct{}{}}
	mgr.queuePendingCleanup(lease)
	mgr.retryPendingCleanups()
	if len(mgr.pendingCleanup) != 1 {
		t.Fatalf("cleanup that still fails must stay queued, pending=%v", mgr.pendingCleanup)
	}

	bughunt3WriteFakeBin(t, dir, "tc", "#!/bin/sh\nexit 0\n")
	mgr.retryPendingCleanups()
	if len(mgr.pendingCleanup) != 0 {
		t.Fatalf("cleanup that now succeeds must leave the queue, pending=%v", mgr.pendingCleanup)
	}
}
