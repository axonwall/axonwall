package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/axonwall/axonwall/apps/axonwalld/gen/agent/v1"
)

// Batch 9 (round-2 daemon lows) regression tests.

// L4: Confirm must not report success when the last-known-good
// persist fails. Pre-fix, the WriteFile error was discarded and the
// "Persisted last-known-good" log line was emitted regardless, so a
// restart silently loaded the previous LKG as the rollback target.
func TestBatch9ConfirmFailsWhenLkgPersistFails(t *testing.T) {
	batch4FakePath(t, "#!/bin/sh\nexit 0\n")
	s := batch4TestServer(t)
	batch4StopTimer(t, s)

	if _, err := s.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
		JobId:                 "batch9-l4",
		NftScript:             batch4NftScript,
		ConfirmTimeoutSeconds: 60,
	}); err != nil {
		t.Fatalf("ApplyBundle failed: %v", err)
	}

	// Point the bundle dir at a path that cannot be created: a
	// regular file where a directory is expected, so MkdirAll fails
	// even for root.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a dir"), 0644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	s.bundleDir = filepath.Join(blocker, "bundles")

	resp, err := s.Confirm(context.Background(), &pb.ConfirmRequest{JobId: "batch9-l4"})
	if err != nil {
		t.Fatalf("Confirm failed: %v", err)
	}
	if resp.Success {
		t.Fatal("Confirm reported success while the last-known-good persist failed")
	}
	if !strings.Contains(resp.Message, "last-known-good") {
		t.Fatalf("expected the failure to name last-known-good, got: %s", resp.Message)
	}
}
