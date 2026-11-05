package main

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A-M12 regression (mutex): concurrent ReconcileStaticRoutes calls must
// serialise instead of interleaving apply/prune against kernel state.
// With no routing config on disk every call fails fast at load; the
// assertion is that all callers complete (no deadlock, no panic) under
// the package-level mutex.
func TestBatch6ReconcileStaticRoutesConcurrent(t *testing.T) {
	// Keep the owned-routes bookkeeping off the real path, as the
	// Batch 4 harness does: a reconcile records its installed set.
	origOwned := staticRoutesOwnedPath
	staticRoutesOwnedPath = filepath.Join(t.TempDir(), "owned.json")
	t.Cleanup(func() { staticRoutesOwnedPath = origOwned })

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ReconcileStaticRoutes()
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent ReconcileStaticRoutes calls did not complete")
	}
}

// A-M12 regression (single-flight): scheduling a second post-boot
// verifier cancels the first, so the first contributes no further
// reconcile rounds. Pre-fix, every apply spawned another goroutine
// and the earlier one's prune could delete a newer route.
func TestBatch6PostBootVerificationSingleFlight(t *testing.T) {
	origDelays := postBootVerificationDelays
	origReconcile := postBootReconcileStaticRoutes
	postBootVerificationDelays = []time.Duration{30 * time.Millisecond, 30 * time.Millisecond}
	var calls atomic.Int32
	postBootReconcileStaticRoutes = func() error {
		calls.Add(1)
		return nil
	}
	t.Cleanup(func() {
		postBootVerificationMu.Lock()
		if postBootVerificationCancel != nil {
			postBootVerificationCancel()
			postBootVerificationCancel = nil
		}
		postBootVerificationMu.Unlock()
		postBootVerificationDelays = origDelays
		postBootReconcileStaticRoutes = origReconcile
	})

	schedulePostBootVerification(nil)
	time.Sleep(10 * time.Millisecond)
	schedulePostBootVerification(nil)
	// Second verifier's two rounds land at ~40ms and ~70ms; the first
	// verifier's 30ms round must never fire.
	time.Sleep(200 * time.Millisecond)
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected exactly 2 reconcile rounds from the second verifier, got %d", got)
	}
}
