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

// Batch 4 (daemon/satellite races and state) regression tests.
//
// The ApplyBundle tests run the real ApplyBundle with fake `nft`,
// `ip`, and `systemctl` binaries on PATH so no kernel or systemd state
// is touched. PATH is process-global, so these tests must not run in
// parallel with each other (they do not call t.Parallel).

const batch4NftScript = "table inet axonwall {\n chain input {\n type filter hook input priority 0;\n }\n}\n"

// batch4FakePath installs fake nft/ip/systemctl binaries and returns a
// cleanup that restores PATH. The fakes exit 0 and print nothing
// unless a test overrides one of them.
func batch4FakePath(t *testing.T, systemctlScript string) {
	t.Helper()
	dir := t.TempDir()
	for name, script := range map[string]string{
		"nft":       "#!/bin/sh\nexit 0\n",
		"ip":        "#!/bin/sh\nexit 0\n",
		"systemctl": systemctlScript,
	} {
		if script == "" {
			continue
		}
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

// batch4TestServer returns an AgentServer wired for ApplyBundle tests
// with the owned-routes tracking file redirected to a temp dir.
func batch4TestServer(t *testing.T) *AgentServer {
	t.Helper()
	origOwned := staticRoutesOwnedPath
	staticRoutesOwnedPath = filepath.Join(t.TempDir(), "owned.json")
	t.Cleanup(func() { staticRoutesOwnedPath = origOwned })
	return &AgentServer{
		bundleDir:   t.TempDir(),
		sdwanProber: NewSDWanProber(),
		startTime:   time.Now(),
	}
}

func batch4StopTimer(t *testing.T, s *AgentServer) {
	t.Helper()
	t.Cleanup(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.rollbackTimer != nil {
			s.rollbackTimer.Stop()
			s.rollbackTimer = nil
		}
	})
	// The successful-apply path also writes the commit-confirm marker
	// under /run/axonwall; remove it so test runs leave no trace.
	t.Cleanup(func() { _ = os.Remove("/run/axonwall/commit-confirm.pending") })
}

// A-H2 regression: validation of every file happens before any file
// is written. Pre-fix, the good file was written and then the bundle
// failed on the disallowed file, leaving a half-applied bundle.
func TestBatch4ApplyBundleValidatesAllFilesBeforeWriting(t *testing.T) {
	batch4FakePath(t, "#!/bin/sh\nexit 0\n")
	s := batch4TestServer(t)
	batch4StopTimer(t, s)

	goodPath := filepath.Join(t.TempDir(), "good.txt")
	req := &pb.ApplyBundleRequest{
		JobId:                 "batch4-h2",
		NftScript:             batch4NftScript,
		ConfirmTimeoutSeconds: 60,
		Files: []*pb.BundleFile{
			{Path: goodPath, Content: "good"},
			{Path: "/etc/passwd", Content: "pwned"},
		},
	}
	if _, err := s.ApplyBundle(context.Background(), req); err == nil {
		t.Fatalf("expected ApplyBundle to reject the disallowed file")
	}
	if _, err := os.Stat(goodPath); !os.IsNotExist(err) {
		t.Fatalf("good file must not exist when a later file fails validation, stat err: %v", err)
	}
}

// A-M3 regression: a subsystem apply failure fails the bundle instead
// of being logged and then confirmed into last-known-good. Pre-fix,
// the invalid SD-WAN config was only warned about and the bundle
// reported success.
func TestBatch4ApplyBundleSubsystemFailureFailsBundle(t *testing.T) {
	batch4FakePath(t, "#!/bin/sh\nexit 0\n")
	s := batch4TestServer(t)
	batch4StopTimer(t, s)

	sdwanPath := filepath.Join(t.TempDir(), "sdwan_config.json")
	req := &pb.ApplyBundleRequest{
		JobId:                 "batch4-m3",
		NftScript:             batch4NftScript,
		ConfirmTimeoutSeconds: 60,
		Files: []*pb.BundleFile{
			{Path: sdwanPath, Content: "this is not json{"},
		},
	}
	resp, err := s.ApplyBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("expected a failure response, not a transport error: %v", err)
	}
	if resp.Success {
		t.Fatalf("expected bundle failure on SD-WAN apply error, got success: %s", resp.Message)
	}
	if !strings.Contains(resp.Message, "SD-WAN") {
		t.Fatalf("expected the failure to name the SD-WAN subsystem, got: %s", resp.Message)
	}
	if s.pendingConfirm {
		t.Fatalf("a failed bundle must not enter pending-confirm")
	}
}

// A-M1 regression: when rollback itself fails, the failed candidate
// must not survive as pending state. Pre-fix, executeRollback
// returned before clearing pendingConfirm/candidateScript, so a
// later Confirm for the previous job's ID promoted the failed
// candidate to last-known-good.
func TestBatch4ExecuteRollbackFailureClearsPending(t *testing.T) {
	s := &AgentServer{
		bundleDir:       t.TempDir(),
		pendingConfirm:  true,
		pendingJobID:    "job-A",
		candidateScript: "bad-candidate-script",
	}
	// No lastGoodScript and no last-known-good.nft in the temp
	// bundle dir, so the rollback has nothing to roll back to and
	// must fail.
	if err := s.executeRollback("test"); err == nil {
		t.Fatalf("expected executeRollback to fail with no LKG available")
	}
	if s.pendingConfirm {
		t.Fatalf("rollback failure must clear pendingConfirm")
	}
	if s.pendingJobID != "" {
		t.Fatalf("rollback failure must clear pendingJobID, got %q", s.pendingJobID)
	}
	if s.candidateScript != "" {
		t.Fatalf("rollback failure must clear candidateScript, got %q", s.candidateScript)
	}
}

// A-M2 regression: a service reload must not hold AgentServer.mu.
// ApplyBundle runs with a fake systemctl that sleeps 3s; GetStatus
// must return well before the reload finishes. Pre-fix, GetStatus
// blocked on s.mu for the whole reload.
func TestBatch4ApplyBundleDoesNotHoldLockAcrossReloads(t *testing.T) {
	batch4FakePath(t, "#!/bin/sh\nsleep 3\n")
	s := batch4TestServer(t)
	batch4StopTimer(t, s)

	done := make(chan error, 1)
	go func() {
		_, err := s.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
			JobId:                 "batch4-m2",
			NftScript:             batch4NftScript,
			ConfirmTimeoutSeconds: 3600,
			ReloadServices:        []string{"suricata"},
		})
		done <- err
	}()

	// Give ApplyBundle time to reach the reload loop (all earlier
	// steps run against instant fakes).
	time.Sleep(500 * time.Millisecond)
	start := time.Now()
	if _, err := s.GetStatus(context.Background(), &pb.GetStatusRequest{}); err != nil {
		t.Fatalf("GetStatus during a service reload failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("GetStatus blocked %.1fs on a service reload; s.mu must not be held across reloads", elapsed.Seconds())
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ApplyBundle failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("ApplyBundle did not return after the fake reload finished")
	}
}

// A-M2 regression: service reloads are bounded by a timeout. The fake
// systemctl sleeps 5s while the timeout is shortened to 100ms, so the
// call must fail fast. Pre-fix there was no timeout at all and the
// call returned success after the full sleep. The fake uses exec so
// the timeout kills the sleeper itself rather than a shell whose
// sleep grandchild would hold the output pipes open past the kill.
func TestBatch4ServiceReloadTimeout(t *testing.T) {
	batch4FakePath(t, "#!/bin/sh\nexec sleep 5\n")
	orig := serviceCommandTimeout
	serviceCommandTimeout = 100 * time.Millisecond
	defer func() { serviceCommandTimeout = orig }()

	start := time.Now()
	_, err := reloadOrRestartService("suricata")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected a timeout error from a hanging service reload")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("service reload took %.1fs despite a 100ms timeout", elapsed.Seconds())
	}
}
