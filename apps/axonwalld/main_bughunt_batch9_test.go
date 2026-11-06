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
func TestBatch9ConfirmFailsWhenLkgPersistFails(t *testing.T) {	batch4FakePath(t, "#!/bin/sh\nexit 0\n")
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

// L5: mirrorBundleFile must write the mirror copy and must report
// failures instead of discarding them. Pre-fix, the mirror write
// ignored open/write/chmod/close errors, so a bundle could be live
// in /etc while its A/B mirror was stale or missing.
func TestBatch9MirrorBundleFile(t *testing.T) {
	dir := t.TempDir()
	mirrorPath := filepath.Join(dir, "etc-axonwall", "routing.yaml")
	if err := mirrorBundleFile(mirrorPath, 0660, []byte("routes: []\n"), false); err != nil {
		t.Fatalf("mirrorBundleFile failed: %v", err)
	}
	data, err := os.ReadFile(mirrorPath)
	if err != nil || string(data) != "routes: []\n" {
		t.Fatalf("mirror content = %q, err = %v", string(data), err)
	}

	// A mirror write under a regular file must fail loudly, not
	// silently pretend the mirror is up to date.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a dir"), 0644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if err := mirrorBundleFile(filepath.Join(blocker, "x.yaml"), 0660, []byte("x"), false); err == nil {
		t.Fatal("mirrorBundleFile under a non-directory must fail")
	}

	// A symlinked mirror entry is left alone, never followed.
	target := filepath.Join(dir, "target.yaml")
	if err := os.WriteFile(target, []byte("original"), 0644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := mirrorBundleFile(link, 0660, []byte("evil"), false); err != nil {
		t.Fatalf("mirrorBundleFile on a symlink must skip quietly, got: %v", err)
	}
	if data, _ := os.ReadFile(target); string(data) != "original" {
		t.Fatalf("symlinked mirror entry was followed; target = %q", string(data))
	}
}

// L6: a bundle naming a service that cannot be reloaded must say so
// in its response. Pre-fix, reloadBundleServices discarded every
// result, so a typo'd or non-allowlisted unit reported full bundle
// success while the service kept running its old config.
func TestBatch9ApplyBundleWarnsOnFailedServiceReload(t *testing.T) {
	batch4FakePath(t, "#!/bin/sh\nexit 0\n")
	s := batch4TestServer(t)
	batch4StopTimer(t, s)

	resp, err := s.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
		JobId:                 "batch9-l6",
		NftScript:             batch4NftScript,
		ConfirmTimeoutSeconds: 60,
		ReloadServices:        []string{"not-a-managed-service", "/tmp/evil.service"},
	})
	if err != nil {
		t.Fatalf("ApplyBundle failed: %v", err)
	}
	if !resp.Success {
		t.Fatalf("ApplyBundle reported failure: %s", resp.Message)
	}
	if !strings.Contains(resp.Message, "not-a-managed-service") {
		t.Fatalf("expected the response to name the unloadable service, got: %s", resp.Message)
	}
	if !strings.Contains(resp.Message, "evil.service") {
		t.Fatalf("expected the response to name the rejected service, got: %s", resp.Message)
	}
}
