package main

import (
	"context"
	"testing"
	"time"

	pb "github.com/axonwall/axonwall/apps/axonwalld/gen/agent/v1"
)

// C26 (daemon side) regression: ApplyBundle must clamp the confirm
// timeout to 10-3600s instead of trusting the caller's value. Pre-fix,
// a negative value (which arrives as a huge uint32 through the proto)
// left a ruleset effectively unconfirmed forever, and a small/zero
// value could arm an immediate auto-rollback.
func TestBatch6ApplyBundleClampsConfirmTimeout(t *testing.T) {
	cases := []struct {
		name       string
		timeoutSec uint32
		wantMin    int64
		wantMax    int64
	}{
		{"zero defaults to 120", 0, 115, 125},
		{"small clamps up to 10", 5, 8, 13},
		{"huge clamps down to 3600", 99999, 3595, 3605},
		{"wrapped negative clamps down to 3600", 4294967291, 3595, 3605},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			batch4FakePath(t, "#!/bin/sh\nexit 0\n")
			s := batch4TestServer(t)
			batch4StopTimer(t, s)

			before := time.Now().Unix()
			resp, err := s.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
				JobId:                 "batch6-c26",
				NftScript:             batch4NftScript,
				ConfirmTimeoutSeconds: tc.timeoutSec,
			})
			if err != nil {
				t.Fatalf("ApplyBundle failed: %v", err)
			}
			if !resp.Success {
				t.Fatalf("ApplyBundle reported failure: %s", resp.Message)
			}
			delta := resp.ConfirmDeadlineUnix - before
			if delta < tc.wantMin || delta > tc.wantMax {
				t.Fatalf("confirm deadline is %ds out, expected %d-%ds", delta, tc.wantMin, tc.wantMax)
			}
		})
	}
}

// C10/C11 (daemon side) regression: the literal job id "confirm" (and
// an empty id) must not confirm whatever bundle happens to be pending.
// Pre-fix, both were exempt from the mismatch check, so a stale
// confirm promoted an unreviewed bundle to last-known-good.
func TestBatch6ConfirmRequiresExactJobID(t *testing.T) {
	batch4FakePath(t, "#!/bin/sh\nexit 0\n")
	s := batch4TestServer(t)
	batch4StopTimer(t, s)

	if _, err := s.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
		JobId:                 "batch6-job-1",
		NftScript:             batch4NftScript,
		ConfirmTimeoutSeconds: 60,
	}); err != nil {
		t.Fatalf("ApplyBundle failed: %v", err)
	}

	// Literal "confirm" must not confirm job batch6-job-1.
	resp, err := s.Confirm(context.Background(), &pb.ConfirmRequest{JobId: "confirm"})
	if err != nil {
		t.Fatalf("Confirm failed: %v", err)
	}
	if resp.Success {
		t.Fatal("literal job id 'confirm' confirmed the pending bundle; expected a mismatch failure")
	}

	// An empty id must not confirm it either, and the bundle must
	// still be pending afterwards.
	resp, err = s.Confirm(context.Background(), &pb.ConfirmRequest{JobId: ""})
	if err != nil {
		t.Fatalf("Confirm failed: %v", err)
	}
	if resp.Success {
		t.Fatal("empty job id confirmed the pending bundle; expected a mismatch failure")
	}

	// The exact pending job id confirms.
	resp, err = s.Confirm(context.Background(), &pb.ConfirmRequest{JobId: "batch6-job-1"})
	if err != nil {
		t.Fatalf("Confirm failed: %v", err)
	}
	if !resp.Success {
		t.Fatalf("exact job id failed to confirm: %s", resp.Message)
	}
}
