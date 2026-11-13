package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/axonwall/axonwall/apps/axonwalld/gen/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Round-3 bug-hunt fix batch 3 (controller MCP/fleet/TUI) regression
// tests: B-M1. A second ApplyBundle while a first bundle is still
// pending confirmation used to silently stop the first bundle's
// rollback timer, overwrite pendingJobID, and arm its own timer —
// so the first caller's confirm was refused with a job mismatch and
// the kernel could end up with neither rule while disk held both.
// The daemon now rejects the overlapping apply with
// FailedPrecondition naming the pending job.
//
// These tests run the real ApplyBundle with fake `nft`, `ip`, and
// `systemctl` binaries on PATH (the batch-4 helpers), so no kernel
// or systemd state is touched.

func bughunt3Apply(t *testing.T, s *AgentServer, jobID, filePath string) *pb.ApplyBundleResponse {
	t.Helper()
	resp, err := s.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
		JobId:                 jobID,
		NftScript:             batch4NftScript,
		ConfirmTimeoutSeconds: 60,
		Files: []*pb.BundleFile{
			{Path: filePath, Content: jobID},
		},
	})
	if err != nil {
		t.Fatalf("ApplyBundle(%s): unexpected error: %v", jobID, err)
	}
	if resp == nil || !resp.Success {
		t.Fatalf("ApplyBundle(%s): expected success, got %+v", jobID, resp)
	}
	return resp
}

func TestBughunt3OverlappingApplyRejected(t *testing.T) {
	batch4FakePath(t, "#!/bin/sh\nexit 0\n")
	s := batch4TestServer(t)
	batch4StopTimer(t, s)

	dir := t.TempDir()
	bughunt3Apply(t, s, "bughunt3-m1-job-a", filepath.Join(dir, "a.txt"))

	// The first bundle is pending confirmation: a second apply for a
	// different job must fail, not silently supersede it.
	_, err := s.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
		JobId:                 "bughunt3-m1-job-b",
		NftScript:             batch4NftScript,
		ConfirmTimeoutSeconds: 60,
		Files: []*pb.BundleFile{
			{Path: filepath.Join(dir, "b.txt"), Content: "bughunt3-m1-job-b"},
		},
	})
	if err == nil {
		t.Fatalf("second ApplyBundle while job A is pending: expected an error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("second ApplyBundle error is not a gRPC status: %v", err)
	}
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("second ApplyBundle error code = %v, want FailedPrecondition (%v)", st.Code(), err)
	}
	if !strings.Contains(st.Message(), "bughunt3-m1-job-a") {
		t.Fatalf("second ApplyBundle error %q does not name the pending job", st.Message())
	}
	// The rejected apply wrote nothing.
	if _, err := os.Stat(filepath.Join(dir, "b.txt")); !os.IsNotExist(err) {
		t.Fatalf("rejected second apply wrote its bundle file")
	}

	// The first job is still pending and confirmable under its own id.
	confirmResp, err := s.Confirm(context.Background(), &pb.ConfirmRequest{JobId: "bughunt3-m1-job-a"})
	if err != nil {
		t.Fatalf("Confirm(job A): unexpected error: %v", err)
	}
	if confirmResp == nil || !confirmResp.Success {
		t.Fatalf("Confirm(job A): expected success, got %+v", confirmResp)
	}

	// With the slot clear, a new apply works again.
	bughunt3Apply(t, s, "bughunt3-m1-job-b", filepath.Join(dir, "b.txt"))
}

func TestBughunt3SameJobReapplyRejectedWhilePending(t *testing.T) {
	batch4FakePath(t, "#!/bin/sh\nexit 0\n")
	s := batch4TestServer(t)
	batch4StopTimer(t, s)

	dir := t.TempDir()
	bughunt3Apply(t, s, "bughunt3-m1-job-a", filepath.Join(dir, "a.txt"))

	// A retry of the same job id is rejected too: that job is
	// already pending and confirmable under its own id.
	_, err := s.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
		JobId:                 "bughunt3-m1-job-a",
		NftScript:             batch4NftScript,
		ConfirmTimeoutSeconds: 60,
	})
	if err == nil {
		t.Fatalf("re-apply of the pending job: expected an error, got nil")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.FailedPrecondition {
		t.Fatalf("re-apply of the pending job: error = %v, want FailedPrecondition", err)
	}

	// The pending job is still confirmable.
	confirmResp, err := s.Confirm(context.Background(), &pb.ConfirmRequest{JobId: "bughunt3-m1-job-a"})
	if err != nil {
		t.Fatalf("Confirm(job A): unexpected error: %v", err)
	}
	if confirmResp == nil || !confirmResp.Success {
		t.Fatalf("Confirm(job A): expected success, got %+v", confirmResp)
	}
}

func TestBughunt3ApplyAfterRollbackTimerFires(t *testing.T) {
	batch4FakePath(t, "#!/bin/sh\nexit 0\n")
	s := batch4TestServer(t)
	// No batch4StopTimer here: this test wants the real timer.
	t.Cleanup(func() { _ = os.Remove("/run/axonwall/commit-confirm.pending") })

	dir := t.TempDir()
	// A 10 s confirm window (the daemon clamps the minimum to 10 s).
	resp, err := s.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
		JobId:                 "bughunt3-m1-job-a",
		NftScript:             batch4NftScript,
		ConfirmTimeoutSeconds: 10,
		Files: []*pb.BundleFile{
			{Path: filepath.Join(dir, "a.txt"), Content: "bughunt3-m1-job-a"},
		},
	})
	if err != nil || resp == nil || !resp.Success {
		t.Fatalf("ApplyBundle(job A): err=%v resp=%+v", err, resp)
	}

	// Still pending immediately: overlapping apply rejected.
	if _, err := s.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
		JobId:                 "bughunt3-m1-job-b",
		NftScript:             batch4NftScript,
		ConfirmTimeoutSeconds: 10,
	}); err == nil {
		t.Fatalf("overlapping apply while job A is pending: expected an error, got nil")
	}

	// After the deadline the auto-rollback clears the slot, and a
	// new apply is accepted again.
	deadline := time.Now().Add(20 * time.Second)
	for {
		s.mu.Lock()
		pending := s.pendingConfirm
		s.mu.Unlock()
		if !pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending confirmation was not cleared by the auto-rollback after 20s")
		}
		time.Sleep(100 * time.Millisecond)
	}
	bughunt3Apply(t, s, "bughunt3-m1-job-b", filepath.Join(dir, "b.txt"))
}
