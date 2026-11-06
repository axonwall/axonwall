package engine

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A-M19: a failed tcpdump run must surface an SSE error event instead of
// ending the stream silently (which looked like a live, idle interface).
func TestBatch7_PacketStreamReportsTcpdumpFailure(t *testing.T) {
	binDir := t.TempDir()
	fake := filepath.Join(binDir, "tcpdump")
	script := "#!/bin/sh\necho 'tcpdump: nonexistent0: No such device exists' >&2\nexit 1\n"
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	mgr := NewPacketStreamManager(NewPacketCaptureManager())
	req := httptest.NewRequest(http.MethodGet, "/v1/packets/stream?interface=eth0", nil)
	rec := httptest.NewRecorder()
	mgr.HandleStreamSSE(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "event: error") {
		t.Fatalf("expected an SSE error event for a failed tcpdump run, got body %q", body)
	}
	if !strings.Contains(body, "No such device exists") {
		t.Fatalf("expected tcpdump stderr in the error event, got body %q", body)
	}
}
