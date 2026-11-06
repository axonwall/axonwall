package engine

import (
	"testing"
	"time"
)

// A-M23: Stop() must return promptly when Start() failed before launching
// the monitor goroutine — pre-fix it blocked forever on doneChan and the
// daemon never shut down (systemd had to SIGKILL it). It also must not
// block when Start() was never called at all.
func TestBatch7_EBPFStopAfterFailedStartReturns(t *testing.T) {
	mgr := NewEBPFManager()
	// Start fails in this environment (no BPF objects / BPF fs); if it
	// ever succeeds, Stop must still return promptly via stopChan.
	_ = mgr.Start(nil)
	assertStopReturns(t, mgr)
}

func TestBatch7_EBPFStopWithoutStartReturns(t *testing.T) {
	assertStopReturns(t, NewEBPFManager())
}

func assertStopReturns(t *testing.T, mgr *EBPFManager) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		mgr.Stop()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return within 5s (deadlock on doneChan)")
	}
}
