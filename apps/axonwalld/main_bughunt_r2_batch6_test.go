package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/axonwall/axonwall/apps/axonwalld/engine"
	pb "github.com/axonwall/axonwall/apps/axonwalld/gen/agent/v1"
)

// Round-2 batch 6 (daemon mediums) regression tests.
//
// The ApplyBundle tests run the real ApplyBundle with fake `nft`, `ip`,
// and `systemctl` binaries on PATH so no kernel or systemd state is
// touched. PATH is process-global, so these tests must not run in
// parallel with each other (they do not call t.Parallel).

// r2BlockingSystemctl returns a fake systemctl script that touches
// startedPath on its first invocation and then blocks until
// releasePath appears. It lets a test park ApplyBundle inside the
// reload window (or a subsystem apply) and probe the API from another
// goroutine while the apply is in flight.
func r2BlockingSystemctl(t *testing.T, startedPath, releasePath string) string {
	t.Helper()
	return "#!/bin/sh\n" +
		"touch \"" + startedPath + "\"\n" +
		"while [ ! -f \"" + releasePath + "\" ]; do sleep 0.05; done\n" +
		"exit 0\n"
}

// r2WaitForFile polls until path exists or the deadline passes.
func r2WaitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

// M1: a Confirm arriving while an ApplyBundle is in its reload window
// must fail fast ("apply in progress") instead of acting on the
// previous bundle's pending state, and GetStatus must stay responsive
// (it only takes s.mu, which the reload window releases). After the
// apply finishes, the confirm for its own job id succeeds.
func TestR2Batch6ConfirmFailsFastDuringApply(t *testing.T) {
	dir := t.TempDir()
	started := filepath.Join(dir, "systemctl-started")
	release := filepath.Join(dir, "systemctl-release")
	batch4FakePath(t, r2BlockingSystemctl(t, started, release))
	s := batch4TestServer(t)
	batch4StopTimer(t, s)
	// Never leave the apply goroutine parked if the test fails early.
	t.Cleanup(func() { _ = os.WriteFile(release, []byte("go"), 0644) })

	applyDone := make(chan *pb.ApplyBundleResponse, 1)
	applyErr := make(chan error, 1)
	go func() {
		resp, err := s.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
			JobId:                 "r2-m1-first",
			NftScript:             batch4NftScript,
			ConfirmTimeoutSeconds: 60,
			ReloadServices:        []string{"suricata"},
		})
		if err != nil {
			applyErr <- err
			return
		}
		applyDone <- resp
	}()

	// The fake systemctl is only invoked in the reload window.
	r2WaitForFile(t, started, 10*time.Second)

	resp, err := s.Confirm(context.Background(), &pb.ConfirmRequest{JobId: "r2-m1-first"})
	if err != nil {
		t.Fatalf("Confirm failed: %v", err)
	}
	if resp.Success {
		t.Fatal("Confirm during an in-flight apply succeeded; expected a fail-fast 'apply in progress' failure")
	}
	if !strings.Contains(resp.Message, "apply in progress") {
		t.Fatalf("Confirm failure did not name the in-flight apply, got: %s", resp.Message)
	}

	// GetStatus takes only s.mu, which the reload window releases:
	// it must answer while the apply is still parked.
	statusDone := make(chan error, 1)
	go func() {
		_, err := s.GetStatus(context.Background(), &pb.GetStatusRequest{})
		statusDone <- err
	}()
	select {
	case err := <-statusDone:
		if err != nil {
			t.Fatalf("GetStatus failed during an in-flight apply: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("GetStatus did not return while an apply was parked in its reload window")
	}

	if err := os.WriteFile(release, []byte("go"), 0644); err != nil {
		t.Fatalf("failed to release the fake systemctl: %v", err)
	}
	select {
	case err := <-applyErr:
		t.Fatalf("ApplyBundle failed: %v", err)
	case applyResp := <-applyDone:
		if !applyResp.Success {
			t.Fatalf("ApplyBundle reported failure: %s", applyResp.Message)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ApplyBundle did not return after the fake systemctl was released")
	}

	resp, err = s.Confirm(context.Background(), &pb.ConfirmRequest{JobId: "r2-m1-first"})
	if err != nil {
		t.Fatalf("Confirm failed: %v", err)
	}
	if !resp.Success {
		t.Fatalf("Confirm after the apply completed failed: %s", resp.Message)
	}
}

// M1: two concurrent ApplyBundles must serialise. Pre-fix, the second
// apply ran its full apply (including arming its own timer and pending
// state) while the first was still in its reload window; the first
// then stopped the second's timer and overwrote the pending state, so
// the second bundle could neither be confirmed nor auto-rolled-back.
// With applyMu, the second apply does no work at all until the first
// returns, and the pending state afterwards is the second job's.
func TestR2Batch6ConcurrentAppliesSerialise(t *testing.T) {
	dir := t.TempDir()
	started := filepath.Join(dir, "systemctl-started")
	release := filepath.Join(dir, "systemctl-release")
	batch4FakePath(t, r2BlockingSystemctl(t, started, release))
	s := batch4TestServer(t)
	batch4StopTimer(t, s)
	t.Cleanup(func() { _ = os.WriteFile(release, []byte("go"), 0644) })

	fileA := filepath.Join(dir, "a.txt")
	fileB := filepath.Join(dir, "b.txt")

	runApply := func(jobID, path string) (<-chan *pb.ApplyBundleResponse, <-chan error) {
		done := make(chan *pb.ApplyBundleResponse, 1)
		errCh := make(chan error, 1)
		go func() {
			resp, err := s.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
				JobId:                 jobID,
				NftScript:             batch4NftScript,
				ConfirmTimeoutSeconds: 60,
				ReloadServices:        []string{"suricata"},
				Files: []*pb.BundleFile{
					{Path: path, Content: jobID},
				},
			})
			if err != nil {
				errCh <- err
				return
			}
			done <- resp
		}()
		return done, errCh
	}

	doneA, errA := runApply("r2-m1-job-a", fileA)
	// Park A in its reload window.
	r2WaitForFile(t, started, 10*time.Second)

	doneB, errB := runApply("r2-m1-job-b", fileB)
	// B must not have done any work while A is parked: it is blocked
	// on applyMu before validation, file writes, or the nft apply.
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(fileB); !os.IsNotExist(err) {
		t.Fatalf("second ApplyBundle wrote its bundle file while the first apply was still in flight; applies are not serialised")
	}
	select {
	case <-doneB:
		t.Fatal("second ApplyBundle returned while the first apply was still in flight; applies are not serialised")
	case <-errB:
		t.Fatal("second ApplyBundle errored while the first apply was still in flight; applies are not serialised")
	default:
	}

	if err := os.WriteFile(release, []byte("go"), 0644); err != nil {
		t.Fatalf("failed to release the fake systemctl: %v", err)
	}
	for name, ch := range map[string]struct {
		done <-chan *pb.ApplyBundleResponse
		err  <-chan error
	}{
		"A": {doneA, errA},
		"B": {doneB, errB},
	} {
		done, errCh := ch.done, ch.err
		select {
		case err := <-errCh:
			t.Fatalf("ApplyBundle %s failed: %v", name, err)
		case resp := <-done:
			if !resp.Success {
				t.Fatalf("ApplyBundle %s reported failure: %s", name, resp.Message)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("ApplyBundle %s did not return after release", name)
		}
	}

	// Both applies ran sequentially, so the pending state is B's job
	// and only B's job confirms.
	s.mu.Lock()
	pendingJob := s.pendingJobID
	s.mu.Unlock()
	if pendingJob != "r2-m1-job-b" {
		t.Fatalf("pending job is %q, want %q (the second, sequential apply)", pendingJob, "r2-m1-job-b")
	}
	resp, err := s.Confirm(context.Background(), &pb.ConfirmRequest{JobId: "r2-m1-job-a"})
	if err != nil {
		t.Fatalf("Confirm failed: %v", err)
	}
	if resp.Success {
		t.Fatal("stale job A confirmed after job B superseded it; expected a mismatch failure")
	}
	resp, err = s.Confirm(context.Background(), &pb.ConfirmRequest{JobId: "r2-m1-job-b"})
	if err != nil {
		t.Fatalf("Confirm failed: %v", err)
	}
	if !resp.Success {
		t.Fatalf("Confirm for the pending job B failed: %s", resp.Message)
	}
}

// M2: a stale auto-rollback timer callback must not roll back a newer
// bundle. Pre-fix, triggerAutoRollback checked only pendingConfirm, so
// a callback for job A that started before bundle B went pending
// (Timer.Stop cannot stop an already-running callback) rolled back B
// the moment B finished applying.
func TestR2Batch6StaleRollbackTimerIsIgnored(t *testing.T) {
	batch4FakePath(t, "#!/bin/sh\nexit 0\n")
	s := batch4TestServer(t)
	batch4StopTimer(t, s)
	s.lastGoodScript = batch4NftScript

	s.mu.Lock()
	s.pendingConfirm = true
	s.pendingJobID = "r2-m2-job-b"
	s.rollbackGen = 2
	s.mu.Unlock()

	// Wrong job id, right generation: must not roll back.
	s.triggerAutoRollback("r2-m2-job-a", 2)
	s.mu.Lock()
	stillPending := s.pendingConfirm
	s.mu.Unlock()
	if !stillPending {
		t.Fatal("stale timer callback for job A rolled back the pending job B")
	}

	// Right job id, wrong generation: must not roll back.
	s.triggerAutoRollback("r2-m2-job-b", 1)
	s.mu.Lock()
	stillPending = s.pendingConfirm
	s.mu.Unlock()
	if !stillPending {
		t.Fatal("stale timer callback from an old generation rolled back the pending job B")
	}

	// Matching job id and generation: this is the live callback, and
	// it must roll back.
	s.triggerAutoRollback("r2-m2-job-b", 2)
	s.mu.Lock()
	stillPending = s.pendingConfirm
	s.mu.Unlock()
	if stillPending {
		t.Fatal("matching timer callback did not roll back the pending job B")
	}
}

// M2: a timer callback that fires while an apply is in progress must
// defer (re-arm) instead of rolling back underneath the apply. The
// re-armed callback carries the original job id and generation, so it
// becomes a no-op if the apply armed a newer pending bundle.
func TestR2Batch6RollbackTimerDefersDuringApply(t *testing.T) {
	batch4FakePath(t, "#!/bin/sh\nexit 0\n")
	s := batch4TestServer(t)
	batch4StopTimer(t, s)
	s.lastGoodScript = batch4NftScript

	s.mu.Lock()
	s.pendingConfirm = true
	s.pendingJobID = "r2-m2-job-b"
	s.rollbackGen = 2
	s.applyInProgress = true
	s.mu.Unlock()

	s.triggerAutoRollback("r2-m2-job-b", 2)

	s.mu.Lock()
	stillPending := s.pendingConfirm
	rearmed := s.rollbackTimer != nil
	s.applyInProgress = false
	s.mu.Unlock()
	if !stillPending {
		t.Fatal("timer callback rolled back a bundle while an apply was in progress")
	}
	if !rearmed {
		t.Fatal("timer callback did not re-arm itself while an apply was in progress; the rollback safety net was dropped")
	}
}

// M3: the pending-confirm record round-trips through disk, and a
// missing/corrupt record loads as "no pending bundle".
func TestR2Batch6PendingStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	state := pendingConfirmState{JobID: "r2-m3-job", DeadlineUnix: time.Now().Add(time.Hour).Unix(), ActiveHash: "abc123"}
	if err := writePendingConfirmState(dir, state, batch4NftScript); err != nil {
		t.Fatalf("writePendingConfirmState failed: %v", err)
	}
	got, candidate, ok := loadPendingConfirmState(dir)
	if !ok {
		t.Fatal("loadPendingConfirmState did not find the record just written")
	}
	if got != state {
		t.Fatalf("loaded state %+v, want %+v", got, state)
	}
	if candidate != batch4NftScript {
		t.Fatalf("loaded candidate %q, want the written script", candidate)
	}
	if pendingConfirmIsLive(dir) != true {
		t.Fatal("pendingConfirmIsLive should be true before the deadline")
	}

	clearPendingConfirmFiles(dir)
	if _, _, ok := loadPendingConfirmState(dir); ok {
		t.Fatal("loadPendingConfirmState found a record after clearPendingConfirmFiles")
	}

	// A corrupt record loads as "no pending bundle" (the startup
	// path then rolls back rather than trusting it).
	if err := os.WriteFile(pendingConfirmStatePath(dir), []byte("{not json"), 0600); err != nil {
		t.Fatalf("failed to write corrupt record: %v", err)
	}
	if _, _, ok := loadPendingConfirmState(dir); ok {
		t.Fatal("corrupt pending-confirm record loaded as valid")
	}
}

// r2RedirectLkgDirs points the LKG snapshot/restore trees at temp
// dirs so NewAgentServer tests never touch /etc/axonwall.
func r2RedirectLkgDirs(t *testing.T, liveDir string) {
	t.Helper()
	origSrc, origDst := lkgConfigSrcDirs, lkgConfigDstDirs
	lkgConfigSrcDirs = []string{liveDir}
	lkgConfigDstDirs = []string{liveDir}
	t.Cleanup(func() { lkgConfigSrcDirs, lkgConfigDstDirs = origSrc, origDst })
}

// M3: a restart with a still-live pending confirm restores the
// pending state (job, deadline, candidate, timer) and does NOT
// snapshot the live (unconfirmed) config as last-known-good.
func TestR2Batch6StartupRestoresLivePending(t *testing.T) {
	bundleDir := t.TempDir()
	liveDir := t.TempDir()
	r2RedirectLkgDirs(t, liveDir)

	lkgScript := "table inet axonwall {\n chain input {\n  type filter hook input priority 0;\n }\n}\n"
	if err := os.WriteFile(filepath.Join(bundleDir, "last-known-good.nft"), []byte(lkgScript), 0600); err != nil {
		t.Fatalf("failed to write LKG script: %v", err)
	}
	deadline := time.Now().Add(time.Hour)
	if err := writePendingConfirmState(bundleDir, pendingConfirmState{
		JobID:        "r2-m3-live",
		DeadlineUnix: deadline.Unix(),
		ActiveHash:   "candidate-hash",
	}, batch4NftScript); err != nil {
		t.Fatalf("failed to write pending state: %v", err)
	}

	s := NewAgentServer(bundleDir, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	batch4StopTimer(t, s)
	t.Cleanup(func() { _ = os.Remove("/run/axonwall/commit-confirm.pending") })

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.pendingConfirm {
		t.Fatal("startup did not restore the pending confirmation")
	}
	if s.pendingJobID != "r2-m3-live" {
		t.Fatalf("pending job is %q, want %q", s.pendingJobID, "r2-m3-live")
	}
	if s.candidateScript != batch4NftScript {
		t.Fatal("startup did not restore the candidate script")
	}
	if s.activeHash != "candidate-hash" {
		t.Fatalf("active hash is %q, want the pending bundle's hash", s.activeHash)
	}
	if s.rollbackTimer == nil {
		t.Fatal("startup did not re-arm the auto-rollback timer")
	}
	if s.lastGoodScript != lkgScript {
		t.Fatal("startup overwrote the confirmed last-known-good script")
	}
	if _, err := os.Stat(filepath.Join(bundleDir, "lkg-config")); !os.IsNotExist(err) {
		t.Fatal("startup snapshotted the live (unconfirmed) config as last-known-good")
	}
}

// M3: a restart after the pending deadline rolls back to
// last-known-good (config files restored, LKG ruleset applied) and
// clears the pending record.
func TestR2Batch6StartupRollsBackExpiredPending(t *testing.T) {
	batch4FakePath(t, "#!/bin/sh\nexit 0\n")
	bundleDir := t.TempDir()
	liveDir := t.TempDir()
	r2RedirectLkgDirs(t, liveDir)

	lkgScript := "table inet axonwall {\n chain input {\n  type filter hook input priority 0;\n }\n}\n"
	if err := os.WriteFile(filepath.Join(bundleDir, "last-known-good.nft"), []byte(lkgScript), 0600); err != nil {
		t.Fatalf("failed to write LKG script: %v", err)
	}
	// The confirmed LKG config snapshot…
	if err := os.MkdirAll(filepath.Join(bundleDir, "lkg-config"), 0700); err != nil {
		t.Fatalf("failed to create lkg-config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "lkg-config", "routing.yaml"), []byte("routes: []\n"), 0600); err != nil {
		t.Fatalf("failed to write LKG routing.yaml: %v", err)
	}
	// …while the live tree holds the unconfirmed bundle's file.
	if err := os.WriteFile(filepath.Join(liveDir, "routing.yaml"), []byte("routes:\n  - network: 10.99.0.0/24\n    gateway: 10.99.0.1\n"), 0600); err != nil {
		t.Fatalf("failed to write live routing.yaml: %v", err)
	}
	deadline := time.Now().Add(-time.Hour)
	if err := writePendingConfirmState(bundleDir, pendingConfirmState{
		JobID:        "r2-m3-expired",
		DeadlineUnix: deadline.Unix(),
		ActiveHash:   "candidate-hash",
	}, batch4NftScript); err != nil {
		t.Fatalf("failed to write pending state: %v", err)
	}

	s := NewAgentServer(bundleDir, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	batch4StopTimer(t, s)
	t.Cleanup(func() { _ = os.Remove("/run/axonwall/commit-confirm.pending") })

	s.mu.Lock()
	pending := s.pendingConfirm
	timer := s.rollbackTimer
	s.mu.Unlock()
	if pending {
		t.Fatal("startup kept an expired pending confirmation")
	}
	if timer != nil {
		t.Fatal("startup armed a timer for an expired pending confirmation")
	}
	if _, err := os.Stat(pendingConfirmStatePath(bundleDir)); !os.IsNotExist(err) {
		t.Fatal("startup did not clear the expired pending-confirm record")
	}
	data, err := os.ReadFile(filepath.Join(liveDir, "routing.yaml"))
	if err != nil {
		t.Fatalf("failed to read live routing.yaml: %v", err)
	}
	if string(data) != "routes: []\n" {
		t.Fatalf("live routing.yaml was not restored to LKG, got: %s", string(data))
	}
}

// M3: with a pending confirm and no confirmed LKG at all, startup
// must NOT adopt the live kernel ruleset as last-known-good.
func TestR2Batch6StartupDoesNotAdoptLiveRulesetWhenPending(t *testing.T) {
	dir := t.TempDir()
	nftLog := filepath.Join(dir, "nft-args.log")
	script := "#!/bin/sh\n" +
		"echo \"$@\" >> \"" + nftLog + "\"\n" +
		"if [ \"$1\" = \"list\" ]; then echo \"table inet axonwall { chain input { type filter hook input priority 0; } }\"; fi\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0755); err != nil {
		t.Fatalf("failed to write fake nft: %v", err)
	}
	origPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir+":"+origPath); err != nil {
		t.Fatalf("failed to set PATH: %v", err)
	}
	t.Cleanup(func() { _ = os.Setenv("PATH", origPath) })

	bundleDir := t.TempDir()
	if err := writePendingConfirmState(bundleDir, pendingConfirmState{
		JobID:        "r2-m3-nolkg",
		DeadlineUnix: time.Now().Add(time.Hour).Unix(),
		ActiveHash:   "candidate-hash",
	}, batch4NftScript); err != nil {
		t.Fatalf("failed to write pending state: %v", err)
	}

	s := NewAgentServer(bundleDir, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	batch4StopTimer(t, s)
	t.Cleanup(func() { _ = os.Remove("/run/axonwall/commit-confirm.pending") })

	s.mu.Lock()
	lastGood := s.lastGoodScript
	s.mu.Unlock()
	// The file-based fallbacks (/etc/nftables.conf) may still supply a
	// rollback target — that is pre-existing behaviour. What must NOT
	// happen is adopting the LIVE kernel ruleset (the fake nft's
	// `list ruleset` output) as last-known-good.
	if lastGood == "table inet axonwall { chain input { type filter hook input priority 0; } }" {
		t.Fatal("startup adopted the live ruleset as last-known-good while a confirm was pending")
	}
	if etcData, err := os.ReadFile("/etc/nftables.conf"); err == nil && len(etcData) > 0 {
		if lastGood != string(etcData) {
			t.Fatalf("startup loaded last-known-good from somewhere other than the file fallback while a confirm was pending")
		}
	} else if lastGood != "" {
		t.Fatal("startup adopted a last-known-good script from somewhere other than the file fallback while a confirm was pending")
	}
	if _, err := os.Stat(filepath.Join(bundleDir, "last-known-good.nft")); !os.IsNotExist(err) {
		t.Fatal("startup wrote the live ruleset to last-known-good.nft while a confirm was pending")
	}
	if argsLog, err := os.ReadFile(nftLog); err == nil && strings.Contains(string(argsLog), "list ruleset") {
		t.Fatal("startup ran `nft list ruleset` to adopt the live ruleset while a confirm was pending")
	}
}

// M3: a successful ApplyBundle persists the pending-confirm record,
// and Confirm removes it.
func TestR2Batch6ApplyPersistsPendingState(t *testing.T) {
	batch4FakePath(t, "#!/bin/sh\nexit 0\n")
	s := batch4TestServer(t)
	batch4StopTimer(t, s)

	resp, err := s.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
		JobId:                 "r2-m3-apply",
		NftScript:             batch4NftScript,
		ConfirmTimeoutSeconds: 60,
	})
	if err != nil {
		t.Fatalf("ApplyBundle failed: %v", err)
	}
	if !resp.Success {
		t.Fatalf("ApplyBundle reported failure: %s", resp.Message)
	}
	state, candidate, ok := loadPendingConfirmState(s.bundleDir)
	if !ok {
		t.Fatal("ApplyBundle did not persist the pending-confirm record")
	}
	if state.JobID != "r2-m3-apply" {
		t.Fatalf("persisted job is %q, want %q", state.JobID, "r2-m3-apply")
	}
	if candidate != batch4NftScript {
		t.Fatal("persisted candidate script does not match the applied script")
	}
	if state.DeadlineUnix != resp.ConfirmDeadlineUnix {
		t.Fatalf("persisted deadline %d, want the reported deadline %d", state.DeadlineUnix, resp.ConfirmDeadlineUnix)
	}

	confirmResp, err := s.Confirm(context.Background(), &pb.ConfirmRequest{JobId: "r2-m3-apply"})
	if err != nil {
		t.Fatalf("Confirm failed: %v", err)
	}
	if !confirmResp.Success {
		t.Fatalf("Confirm failed: %s", confirmResp.Message)
	}
	if _, _, ok := loadPendingConfirmState(s.bundleDir); ok {
		t.Fatal("Confirm did not clear the persisted pending-confirm record")
	}
}

// M4: a configured HA interface that resolves to nothing (placeholder
// name, or a logical name whose mapping was deleted/disabled) must
// fail the apply instead of silently falling back to eth0.
func TestR2Batch6HAUnresolvableInterfaceFailsApply(t *testing.T) {
	cases := []struct {
		name string
		cfg  HAConfig
		want string
	}{
		{"sync auto", HAConfig{Enabled: true, Role: "master", SyncInterface: "auto"}, "sync interface"},
		{"sync none", HAConfig{Enabled: true, Role: "master", SyncInterface: "none"}, "sync interface"},
		{"sync unassigned", HAConfig{Enabled: true, Role: "master", SyncInterface: "unassigned"}, "sync interface"},
		{"conntrack auto", HAConfig{Enabled: true, Role: "master", ConntrackSync: ConntrackSyncConfig{Interface: "auto"}}, "conntrack sync interface"},
		{"vrrp disabled", HAConfig{Enabled: true, Role: "master", VRRPInstances: []VRRPInstanceConfig{{Interface: "disabled"}}}, "VRRP instance"},
		{"vrrp name with no valid device spelling", HAConfig{Enabled: true, Role: "master", VRRPInstances: []VRRPInstanceConfig{{Interface: "wan 1"}}}, "VRRP instance"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewHAEngine(nil)
			err := e.Apply(tc.cfg)
			if err == nil {
				t.Fatalf("Apply with an unresolvable interface succeeded; expected an error naming the %s", tc.want)
			}
			if !strings.Contains(err.Error(), "does not resolve to a network device") {
				t.Fatalf("Apply error did not name the unresolvable interface, got: %v", err)
			}
		})
	}
}

// M4 guard: an UNSET interface still falls back to the long-standing
// eth0 default, and a regex-valid but not-yet-present device name
// still passes through (it fails loudly at reload time, as before).
func TestR2Batch6HAUnsetInterfaceKeepsEth0Default(t *testing.T) {
	batch4FakePath(t, "#!/bin/sh\nexit 0\n")
	dir := t.TempDir()
	origKeepalived, origConntrackd := keepalivedConfPath, conntrackdConfPath
	keepalivedConfPath = filepath.Join(dir, "keepalived.conf")
	conntrackdConfPath = filepath.Join(dir, "conntrackd.conf")
	t.Cleanup(func() { keepalivedConfPath, conntrackdConfPath = origKeepalived, origConntrackd })

	e := NewHAEngine(nil)
	if err := e.Apply(HAConfig{Enabled: true, Role: "master"}); err != nil {
		t.Fatalf("Apply with an unset interface failed: %v", err)
	}
	conf, err := os.ReadFile(keepalivedConfPath)
	if err != nil {
		t.Fatalf("failed to read generated keepalived.conf: %v", err)
	}
	if !strings.Contains(string(conf), "eth0") {
		t.Fatalf("generated keepalived.conf does not use the eth0 default for an unset interface:\n%s", string(conf))
	}

	// A regex-valid name that is not a live device passes through
	// unchanged (no M4 error); it is the reload's job to fail loudly.
	e2 := NewHAEngine(nil)
	if err := e2.Apply(HAConfig{Enabled: true, Role: "master", SyncInterface: "eth99"}); err != nil {
		t.Fatalf("Apply with a regex-valid device name failed: %v", err)
	}
	conf, err = os.ReadFile(keepalivedConfPath)
	if err != nil {
		t.Fatalf("failed to read generated keepalived.conf: %v", err)
	}
	if !strings.Contains(string(conf), "eth99") {
		t.Fatalf("generated keepalived.conf does not carry the configured device name:\n%s", string(conf))
	}
}

// M5: the per-device pidfile list must not contain the daemon-global
// dhcpcd pidfiles — a daemon managing any interface must not make
// every other DHCP interface look "already running".
func TestR2Batch6DhcpCheckIgnoresGlobalPidfiles(t *testing.T) {
	for _, global := range []string{
		"/var/run/dhcpcd/pid", "/run/dhcpcd/pid",
		"/var/run/dhcpcd.pid", "/run/dhcpcd.pid",
	} {
		for _, p := range dhcpPidFilesForDev("eth1") {
			if p == global {
				t.Fatalf("per-device pidfile list contains global pidfile %s", global)
			}
		}
	}
	if got := len(dhcpPidFilesForDev("eth1")); got == 0 {
		t.Fatal("per-device pidfile list is empty")
	}
}

// M5: a live process whose cmdline names a DHCP client counts; a
// pid recycled by an unrelated process, a dead pid, and garbage
// pidfile content do not.
func TestR2Batch6DhcpClientRunningForDev(t *testing.T) {
	dir := t.TempDir()

	// A process whose argv[0] is a DHCP client binary.
	dhcpProc := exec.Command("sleep", "30")
	dhcpProc.Args[0] = "dhcpcd"
	if err := dhcpProc.Start(); err != nil {
		t.Fatalf("failed to start dhcpcd-argv process: %v", err)
	}
	t.Cleanup(func() { _ = dhcpProc.Process.Kill() })

	// A process whose argv[0] is unrelated (the pid-recycling case).
	otherProc := exec.Command("sleep", "30")
	if err := otherProc.Start(); err != nil {
		t.Fatalf("failed to start unrelated process: %v", err)
	}
	t.Cleanup(func() { _ = otherProc.Process.Kill() })

	writePid := func(name string, pid int) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(strconv.Itoa(pid)+"\n"), 0644); err != nil {
			t.Fatalf("failed to write pidfile: %v", err)
		}
		return p
	}

	dhcpPidFile := writePid("dhcpcd-eth1.pid", dhcpProc.Process.Pid)
	if !dhcpClientRunningForDev("eth1", []string{dhcpPidFile}) {
		t.Fatal("live dhcpcd process behind a per-device pidfile was not recognised as a running client")
	}

	otherPidFile := writePid("dhcpcd-eth2.pid", otherProc.Process.Pid)
	if dhcpClientRunningForDev("eth2", []string{otherPidFile}) {
		t.Fatal("unrelated process holding a pidfile pid was mistaken for a running DHCP client")
	}

	deadPidFile := writePid("dhcpcd-eth3.pid", 999999)
	if dhcpClientRunningForDev("eth3", []string{deadPidFile}) {
		t.Fatal("dead pid in a pidfile was mistaken for a running DHCP client")
	}

	garbage := filepath.Join(dir, "garbage.pid")
	if err := os.WriteFile(garbage, []byte("not-a-pid\n"), 0644); err != nil {
		t.Fatalf("failed to write garbage pidfile: %v", err)
	}
	if dhcpClientRunningForDev("eth4", []string{garbage}) {
		t.Fatal("garbage pidfile content was mistaken for a running DHCP client")
	}

	if dhcpClientRunningForDev("eth5", []string{filepath.Join(dir, "missing.pid")}) {
		t.Fatal("missing pidfile was mistaken for a running DHCP client")
	}
}

// M6: the default route comes from the first static WAN gateway that
// accepts it — a failed first gateway must not block the second — and
// the apply fails loudly when no gateway yields a route.
func TestR2Batch6StaticDefaultRouteTriesEachGateway(t *testing.T) {
	orig := ipRouteReplaceDefault
	t.Cleanup(func() { ipRouteReplaceDefault = orig })

	var attempted []string
	ipRouteReplaceDefault = func(gateway, dev string) error {
		attempted = append(attempted, gateway+"@"+dev)
		if gateway == "10.0.0.1" {
			return fmt.Errorf("network unreachable")
		}
		return nil
	}

	if err := installStaticDefaultRoute([]staticWanGateway{
		{gateway: "10.0.0.1", device: "eth0"},
		{gateway: "10.0.0.2", device: "eth1"},
	}); err != nil {
		t.Fatalf("installStaticDefaultRoute failed after the second gateway accepted the route: %v", err)
	}
	if len(attempted) != 2 || attempted[0] != "10.0.0.1@eth0" || attempted[1] != "10.0.0.2@eth1" {
		t.Fatalf("gateways attempted in order %v, want [10.0.0.1@eth0 10.0.0.2@eth1]", attempted)
	}
}

// M6: when no static WAN gateway yields a default route, the error
// is returned (so the apply fails loudly) instead of being discarded
// with the route marked as set.
func TestR2Batch6StaticDefaultRouteFailsWhenNoneWork(t *testing.T) {
	orig := ipRouteReplaceDefault
	t.Cleanup(func() { ipRouteReplaceDefault = orig })

	var attempted []string
	ipRouteReplaceDefault = func(gateway, dev string) error {
		attempted = append(attempted, gateway+"@"+dev)
		return fmt.Errorf("network unreachable")
	}

	err := installStaticDefaultRoute([]staticWanGateway{
		{gateway: "10.0.0.1", device: "eth0"},
		{gateway: "10.0.0.2", device: "eth1"},
	})
	if err == nil {
		t.Fatal("installStaticDefaultRoute succeeded when every gateway failed")
	}
	if len(attempted) != 2 {
		t.Fatalf("only %d gateways attempted, want both tried before failing: %v", len(attempted), attempted)
	}
	if err := installStaticDefaultRoute(nil); err != nil {
		t.Fatalf("installStaticDefaultRoute with no gateways failed: %v", err)
	}
}

// r2Batch6FakePathWithSysctl installs fake nft/ip/systemctl/sysctl
// binaries; systemctl runs the given script, the others exit 0. K3s
// ApplyConfig shells out to sysctl and systemctl, so both must be
// faked for the subsystem-apply tests to touch no real system state.
func r2Batch6FakePathWithSysctl(t *testing.T, systemctlScript string) {
	t.Helper()
	dir := t.TempDir()
	for name, script := range map[string]string{
		"nft":       "#!/bin/sh\nexit 0\n",
		"ip":        "#!/bin/sh\nexit 0\n",
		"sysctl":    "#!/bin/sh\nexit 0\n",
		"systemctl": systemctlScript,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0755); err != nil {
			t.Fatalf("failed to write fake %s: %v", name, err)
		}
	}
	orig := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir+":"+orig); err != nil {
		t.Fatalf("failed to set PATH: %v", err)
	}
	t.Cleanup(func() { _ = os.Setenv("PATH", orig) })
}

// r2Batch6K3sFootprint isolates K3s file paths into a temp directory
// so tests don't require root permissions to write to /etc/rancher/k3s.
func r2Batch6K3sFootprint(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	etcDir := filepath.Join(dir, "etc-k3s")
	manifestDir := filepath.Join(dir, "manifests")
	stateDir := filepath.Join(dir, "state")
	vowDir := filepath.Join(dir, "vow")
	cleanup := engine.SetK3sPathsForTest(etcDir, manifestDir, stateDir, vowDir)
	t.Cleanup(cleanup)
}

func r2Batch6K3sApplyRequest(t *testing.T) *pb.ApplyBundleRequest {
	t.Helper()
	k3sPath := filepath.Join(t.TempDir(), "k3s_config.json")
	return &pb.ApplyBundleRequest{
		JobId:                 "r2-m14-subsystem",
		NftScript:             batch4NftScript,
		ConfirmTimeoutSeconds: 60,
		Files: []*pb.BundleFile{
			{Path: k3sPath, Content: `{"enabled": true, "k3sConfigYaml": "node-name: test-node\n"}`},
		},
	}
}

// M14: GetStatus (and Confirm's fail-fast path) must stay responsive
// while ApplyBundle is parked inside a subsystem apply. Pre-fix the
// subsystem loop ran under s.mu, so a hung subsystem wedged the whole
// API; the K3s apply parks on `systemctl reload-or-restart k3s` here.
func TestR2Batch6GetStatusAnswersDuringSubsystemApply(t *testing.T) {
	dir := t.TempDir()
	started := filepath.Join(dir, "systemctl-started")
	release := filepath.Join(dir, "systemctl-release")
	r2Batch6FakePathWithSysctl(t, r2BlockingSystemctl(t, started, release))
	r2Batch6K3sFootprint(t)
	s := batch4TestServer(t)
	s.k3sManager = engine.NewK3sManager()
	batch4StopTimer(t, s)
	// Never leave the apply goroutine parked if the test fails early.
	t.Cleanup(func() { _ = os.WriteFile(release, []byte("go"), 0644) })

	applyDone := make(chan *pb.ApplyBundleResponse, 1)
	applyErr := make(chan error, 1)
	go func() {
		resp, err := s.ApplyBundle(context.Background(), r2Batch6K3sApplyRequest(t))
		if err != nil {
			applyErr <- err
			return
		}
		applyDone <- resp
	}()

	// The fake systemctl is only invoked by the K3s subsystem apply.
	r2WaitForFile(t, started, 10*time.Second)

	// GetStatus takes only s.mu, which the subsystem window releases:
	// it must answer while the apply is still parked.
	statusDone := make(chan error, 1)
	go func() {
		_, err := s.GetStatus(context.Background(), &pb.GetStatusRequest{})
		statusDone <- err
	}()
	select {
	case err := <-statusDone:
		if err != nil {
			t.Fatalf("GetStatus failed during an in-flight subsystem apply: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("GetStatus did not return while an apply was parked in its subsystem phase")
	}

	// Confirm during the park fails fast (apply in progress) instead
	// of blocking behind the hung subsystem.
	resp, err := s.Confirm(context.Background(), &pb.ConfirmRequest{JobId: "r2-m14-subsystem"})
	if err != nil {
		t.Fatalf("Confirm failed: %v", err)
	}
	if resp.Success {
		t.Fatal("Confirm during an in-flight subsystem apply succeeded; expected a fail-fast 'apply in progress' failure")
	}
	if !strings.Contains(resp.Message, "apply in progress") {
		t.Fatalf("Confirm failure did not name the in-flight apply, got: %s", resp.Message)
	}

	if err := os.WriteFile(release, []byte("go"), 0644); err != nil {
		t.Fatalf("failed to release the fake systemctl: %v", err)
	}
	select {
	case err := <-applyErr:
		t.Fatalf("ApplyBundle failed: %v", err)
	case applyResp := <-applyDone:
		if !applyResp.Success {
			t.Fatalf("ApplyBundle reported failure: %s", applyResp.Message)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ApplyBundle did not return after the fake systemctl was released")
	}

	resp, err = s.Confirm(context.Background(), &pb.ConfirmRequest{JobId: "r2-m14-subsystem"})
	if err != nil {
		t.Fatalf("Confirm failed: %v", err)
	}
	if !resp.Success {
		t.Fatalf("Confirm after the apply completed failed: %s", resp.Message)
	}
}

// M14: a subsystem apply that never returns must fail the bundle
// after subsystemApplyTimeout (and roll back) instead of wedging the
// apply — and the API — forever.
func TestR2Batch6SubsystemApplyTimeoutFailsBundle(t *testing.T) {
	origTimeout := subsystemApplyTimeout
	subsystemApplyTimeout = 300 * time.Millisecond
	defer func() { subsystemApplyTimeout = origTimeout }()

	dir := t.TempDir()
	started := filepath.Join(dir, "systemctl-started")
	release := filepath.Join(dir, "systemctl-release")
	r2Batch6FakePathWithSysctl(t, r2BlockingSystemctl(t, started, release))
	r2Batch6K3sFootprint(t)
	s := batch4TestServer(t)
	s.k3sManager = engine.NewK3sManager()
	batch4StopTimer(t, s)
	// Release the parked orphan once the test is done, so its late
	// completion is logged and the goroutine exits.
	t.Cleanup(func() { _ = os.WriteFile(release, []byte("go"), 0644) })

	applyDone := make(chan *pb.ApplyBundleResponse, 1)
	applyErr := make(chan error, 1)
	go func() {
		resp, err := s.ApplyBundle(context.Background(), r2Batch6K3sApplyRequest(t))
		if err != nil {
			applyErr <- err
			return
		}
		applyDone <- resp
	}()

	// The fake systemctl is only invoked by the K3s subsystem apply.
	r2WaitForFile(t, started, 10*time.Second)

	select {
	case err := <-applyErr:
		t.Fatalf("ApplyBundle returned a transport error instead of a timeout failure: %v", err)
	case applyResp := <-applyDone:
		if applyResp.Success {
			t.Fatal("ApplyBundle succeeded despite the subsystem apply hanging past its timeout")
		}
		if !strings.Contains(applyResp.Message, "timed out") {
			t.Fatalf("ApplyBundle failure did not name the timeout, got: %s", applyResp.Message)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("ApplyBundle did not return after the subsystem apply timeout")
	}

	// The API is responsive again once the timed-out apply returns.
	statusDone := make(chan error, 1)
	go func() {
		_, err := s.GetStatus(context.Background(), &pb.GetStatusRequest{})
		statusDone <- err
	}()
	select {
	case err := <-statusDone:
		if err != nil {
			t.Fatalf("GetStatus failed after the timed-out apply: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("GetStatus did not return after the subsystem apply timeout")
	}
}
