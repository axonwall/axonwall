package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installFakeConntrack prepends a directory containing a fake `conntrack`
// executable to PATH. The fake drains its arguments and runs the given
// shell body, so tests can simulate kill success, no-match, and failure
// without the real binary.
func installFakeConntrack(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "conntrack"), []byte(script), 0755); err != nil {
		t.Fatalf("Failed to write fake conntrack: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

func killReq() McpBlackholeReq {
	req := blackholeReq()
	req.KillActiveConnections = true
	return req
}

// A-M22: the conntrack kill runs after the drop rule lands, and a failed
// kill is recorded on the lease instead of silently discarded — while the
// lease itself still succeeds (the drop rule is enforcing).
func TestBatch7_BlackholeRecordsFailedConntrackKill(t *testing.T) {
	installFakeNft(t, 0)
	installFakeConntrack(t, "echo 'conntrack: No such file or directory' >&2\nexit 1")
	mgr := newTestTrafficManager(t)

	lease, err := mgr.BlackholeTraffic(killReq())
	if err != nil {
		t.Fatalf("BlackholeTraffic failed with working nft: %v", err)
	}
	got, _ := lease.Parameters["conntrackKill"].(string)
	if !strings.HasPrefix(got, "failed:") {
		t.Fatalf("conntrackKill = %q, want a recorded failure (pre-fix it was silently discarded)", got)
	}
	if got := len(mgr.ListLeases()); got != 1 {
		t.Fatalf("Expected 1 listed lease, got %d", got)
	}
}

// A-M22: a conntrack run with no matching entries (exit 1, no output)
// means there was nothing to kill, not a failure.
func TestBatch7_BlackholeConntrackNoMatchIsOk(t *testing.T) {
	installFakeNft(t, 0)
	installFakeConntrack(t, "exit 1")
	mgr := newTestTrafficManager(t)

	lease, err := mgr.BlackholeTraffic(killReq())
	if err != nil {
		t.Fatalf("BlackholeTraffic failed with working nft: %v", err)
	}
	got, _ := lease.Parameters["conntrackKill"].(string)
	if got != "ok" {
		t.Fatalf("conntrackKill = %q, want \"ok\" for a no-match kill", got)
	}
}

// A-M22: a missing conntrack binary is a failed kill, recorded as such.
func TestBatch7_KillConntrackEntriesWithoutBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := killConntrackEntries("198.51.100.20"); err == nil {
		t.Fatal("killConntrackEntries without a conntrack binary returned nil, want error")
	}
}
