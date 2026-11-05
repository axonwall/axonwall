package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// installFakeNft prepends a directory containing a fake `nft` executable to
// PATH and returns the path of the file the fake appends its arguments to.
// The fake drains stdin, logs its argv, and exits with the given status, so
// tests do not depend on the sandbox's real nft binary or kernel.
func installFakeNft(t *testing.T, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "nft-args.log")
	script := "#!/bin/sh\n" +
		"echo \"$@\" >> \"" + logPath + "\"\n" +
		"cat > /dev/null\n" +
		"exit " + string(rune('0'+exitCode)) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0755); err != nil {
		t.Fatalf("Failed to write fake nft: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return logPath
}

func newTestTrafficManager(t *testing.T) *McpTrafficManager {
	t.Helper()
	// Keep persisted lease state inside the test temp dir.
	orig := mcpStateFilePath
	mcpStateFilePath = filepath.Join(t.TempDir(), "mcp-tactical-state.json")
	t.Cleanup(func() { mcpStateFilePath = orig })
	return &McpTrafficManager{
		leases:           make(map[string]*McpTacticalLease),
		reservedClassIDs: make(map[int]struct{}),
		stopTicker:       make(chan struct{}),
	}
}

func blackholeReq() McpBlackholeReq {
	return McpBlackholeReq{
		Target:           "198.51.100.20",
		Mode:             "nft_drop",
		Direction:        "both",
		Protocol:         "any",
		TTLSeconds:       3600,
		CallerIP:         "10.42.1.25",
		MaxIPv4PrefixLen: 24,
		MaxIPv6PrefixLen: 64,
		KeyID:            "test-key",
		KeyName:          "test-agent",
	}
}

// A-M13: when the nftables apply fails, lease creation must fail and the
// lease must not be stored, persisted, or listed as active.
func TestMcpBlackholeCreationFailsWhenNftApplyFails(t *testing.T) {
	logPath := installFakeNft(t, 1)
	mgr := newTestTrafficManager(t)

	lease, err := mgr.BlackholeTraffic(blackholeReq())
	if err == nil {
		t.Fatalf("Expected BlackholeTraffic to fail when nft fails; got lease %+v (pre-fix success lie)", lease)
	}
	if lease != nil {
		t.Errorf("Expected nil lease on nft failure, got %+v", lease)
	}
	if got := len(mgr.leases); got != 0 {
		t.Errorf("Expected no stored leases after nft failure, got %d", got)
	}
	if got := len(mgr.ListLeases()); got != 0 {
		t.Errorf("Expected no listed leases after nft failure, got %d", got)
	}
	if data, rerr := os.ReadFile(mcpStateFilePath); rerr == nil {
		if strings.Contains(string(data), "198.51.100.20") {
			t.Errorf("Failed lease was persisted to state file: %s", string(data))
		}
	}
	// The failed run must still have validated the replacement table
	// before applying it (check invocation precedes any apply invocation).
	argsLog, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimSpace(string(argsLog)), "\n")
	if len(lines) < 1 || lines[0] != "-c -f -" {
		t.Errorf("Expected first nft invocation to be the check (-c -f -), got log: %q", string(argsLog))
	}
}

// A-M13 happy path: when nft succeeds, the lease is created and listed.
func TestMcpBlackholeCreationSucceedsWhenNftSucceeds(t *testing.T) {
	logPath := installFakeNft(t, 0)
	mgr := newTestTrafficManager(t)

	lease, err := mgr.BlackholeTraffic(blackholeReq())
	if err != nil {
		t.Fatalf("BlackholeTraffic failed with working nft: %v", err)
	}
	if lease == nil || !strings.HasPrefix(lease.ID, "mcp_lease_") {
		t.Fatalf("Expected a lease with an mcp_lease_ id, got %+v", lease)
	}
	if got := len(mgr.ListLeases()); got != 1 {
		t.Fatalf("Expected 1 listed lease, got %d", got)
	}
	argsLog, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimSpace(string(argsLog)), "\n")
	if len(lines) < 2 || lines[0] != "-c -f -" || lines[1] != "-f -" {
		t.Errorf("Expected nft check then apply invocations, got log: %q", string(argsLog))
	}
}

// A-M13: revert must report failure when the kernel rebuild fails.
func TestMcpRevertFailsWhenNftApplyFails(t *testing.T) {
	installFakeNft(t, 1)
	mgr := newTestTrafficManager(t)
	now := time.Now().UTC()
	mgr.leases["mcp_lease_test"] = &McpTacticalLease{
		ID:               "mcp_lease_test",
		Kind:             "blackhole",
		CreatedAt:        now.Format(time.RFC3339),
		ExpiresAt:        now.Add(time.Hour).Format(time.RFC3339),
		NormalizedTarget: "198.51.100.20",
		Parameters:       map[string]interface{}{"mode": "nft_drop", "direction": "both"},
	}

	_, err := mgr.RevertLease("mcp_lease_test")
	if err == nil {
		t.Fatalf("Expected RevertLease to fail when nft fails; got nil (pre-fix success lie)")
	}
}

// A-M13: flush must report failure (with the cleared count) when the
// kernel rebuild fails, not success with a cleared count.
func TestMcpFlushFailsWhenNftApplyFails(t *testing.T) {
	installFakeNft(t, 1)
	mgr := newTestTrafficManager(t)
	now := time.Now().UTC()
	for _, id := range []string{"mcp_lease_a", "mcp_lease_b"} {
		mgr.leases[id] = &McpTacticalLease{
			ID:               id,
			Kind:             "blackhole",
			CreatedAt:        now.Format(time.RFC3339),
			ExpiresAt:        now.Add(time.Hour).Format(time.RFC3339),
			NormalizedTarget: "198.51.100.20",
			Parameters:       map[string]interface{}{"mode": "nft_drop", "direction": "both"},
		}
	}

	cleared, err := mgr.FlushAllLeases()
	if err == nil {
		t.Fatalf("Expected FlushAllLeases to fail when nft fails; got nil (pre-fix success lie)")
	}
	if cleared != 2 {
		t.Errorf("Expected cleared count 2 alongside the error, got %d", cleared)
	}
}
