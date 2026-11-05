package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Mock-traffic removal regression: when tcpdump is missing, RunCapture
// and the packet SSE stream must return an error, not fabricated
// flows. Pre-fix, RunCapture returned a CaptureResult built from
// hardcoded sample flows (plus a dummy "MOCK_PCAP_FILE_HEADER" file)
// and the SSE stream served invented packets forever.
func TestBatch6RunCaptureErrorsWithoutTcpdump(t *testing.T) {
	// PATH without tcpdump (and without anything else the capture
	// path could mistake for it).
	dir := t.TempDir()
	t.Setenv("PATH", dir)

	mgr := NewPacketCaptureManager()
	_, err := mgr.RunCapture(context.Background(), "lo", "", 5)
	if err == nil {
		t.Fatal("expected RunCapture to fail without tcpdump; got a (mock) successful result")
	}
	if !strings.Contains(err.Error(), "tcpdump") {
		t.Fatalf("expected a tcpdump error, got: %v", err)
	}
}

func TestBatch6PacketStreamErrorsWithoutTcpdump(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)

	mgr := NewPacketStreamManager(NewPacketCaptureManager())
	// Bound the request context: pre-fix, the handler fell through
	// to an unbounded mock stream that never returns, so without a
	// deadline the pre-fix run of this test hangs instead of failing.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/v1/events/packets?interface=lo", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		mgr.HandleStreamSSE(rec, req)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("handler did not return within 5s without tcpdump (pre-fix mock stream never ends)")
	}

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without tcpdump, got %d with body %q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "event: packet") {
		t.Fatal("stream served packet events without tcpdump")
	}
	if strings.Contains(rec.Body.String(), "192.168.1.105") {
		t.Fatal("stream served the old fabricated sample flows")
	}
}
