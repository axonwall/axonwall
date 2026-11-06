package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
