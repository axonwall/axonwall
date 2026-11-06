package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// installFakeTc prepends a directory containing a fake `tc`
// executable to PATH so shape-lease tests never touch the sandbox's
// real qdiscs. The fake drains its arguments and exits 0.
func installFakeTc(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"echo \"$@\" >> \"" + filepath.Join(dir, "tc-args.log") + "\"\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "tc"), []byte(script), 0755); err != nil {
		t.Fatalf("Failed to write fake tc: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

func shapeReq() McpShapeReq {
	return McpShapeReq{
		Target:           "198.51.100.20",
		Interface:        "eth0",
		Direction:        "both",
		RateKbps:         1000,
		CeilKbps:         2000,
		TTLSeconds:       3600,
		CallerIP:         "10.42.1.25",
		MaxIPv4PrefixLen: 24,
		MaxIPv6PrefixLen: 64,
		KeyID:            "test-key",
		KeyName:          "test-agent",
	}
}

// M7: creation must reject an unrecognised direction instead of
// storing a lease the kernel enforces nothing for.
func TestR2Batch6LeaseCreationRejectsBadDirection(t *testing.T) {
	installFakeNft(t, 0)
	installFakeTc(t)
	mgr := newTestTrafficManager(t)

	bad := blackholeReq()
	bad.Direction = "in"
	if _, err := mgr.BlackholeTraffic(bad); err == nil {
		t.Fatal("BlackholeTraffic accepted direction \"in\"; expected a validation error")
	}
	if got := len(mgr.leases); got != 0 {
		t.Fatalf("rejected blackhole was stored anyway (%d leases)", got)
	}

	badShape := shapeReq()
	badShape.Direction = "sideways"
	if _, err := mgr.ShapeTraffic(badShape); err == nil {
		t.Fatal("ShapeTraffic accepted direction \"sideways\"; expected a validation error")
	}
	if got := len(mgr.leases); got != 0 {
		t.Fatalf("rejected shape lease was stored anyway (%d leases)", got)
	}

	// Every recognised direction still creates a lease.
	for _, dir := range []string{"both", "inbound", "outbound"} {
		req := blackholeReq()
		req.Direction = dir
		if _, err := mgr.BlackholeTraffic(req); err != nil {
			t.Fatalf("BlackholeTraffic rejected valid direction %q: %v", dir, err)
		}
	}
	for _, dir := range []string{"both", "ingress", "inbound", "egress", "outbound"} {
		req := shapeReq()
		req.Direction = dir
		if _, err := mgr.ShapeTraffic(req); err != nil {
			t.Fatalf("ShapeTraffic rejected valid direction %q: %v", dir, err)
		}
	}
}

// M7 (defence in depth): a lease persisted before the fix with an
// unrecognised direction must fail the reconcile instead of silently
// emitting no rule — and the nft apply must not run for it.
func TestR2Batch6ReconcileRejectsBadDirection(t *testing.T) {
	logPath := installFakeNft(t, 0)
	mgr := newTestTrafficManager(t)
	now := time.Now().UTC()
	mgr.leases["mcp_lease_bad"] = &McpTacticalLease{
		ID:               "mcp_lease_bad",
		Kind:             "blackhole",
		CreatedAt:        now.Format(time.RFC3339),
		ExpiresAt:        now.Add(time.Hour).Format(time.RFC3339),
		NormalizedTarget: "198.51.100.20",
		Parameters:       map[string]interface{}{"mode": "nft_drop", "direction": "in"},
	}

	if err := mgr.ReconcileKernelState(); err == nil {
		t.Fatal("ReconcileKernelState succeeded with a bad-direction lease; expected an error instead of an empty rule set")
	}
	if argsLog, err := os.ReadFile(logPath); err == nil && strings.TrimSpace(string(argsLog)) != "" {
		t.Fatalf("reconcile ran nft for a bad-direction lease: %q", string(argsLog))
	}

	// The bad lease stays removable: reverting it reconciles the set
	// without it, so the revert must succeed.
	if _, err := mgr.RevertLease("mcp_lease_bad"); err != nil {
		t.Fatalf("RevertLease of a bad-direction lease failed: %v", err)
	}
	if got := len(mgr.leases); got != 0 {
		t.Fatalf("bad-direction lease was not removed by the revert (%d leases)", got)
	}
}

// M8: a failed rebuild must keep the record — the lease stays listed
// and revertable instead of vanishing while the kernel may still
// enforce it.
func TestR2Batch6RevertKeepsLeaseWhenRebuildFails(t *testing.T) {
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

	if _, err := mgr.RevertLease("mcp_lease_test"); err == nil {
		t.Fatal("RevertLease succeeded when the kernel rebuild failed")
	}
	if got := len(mgr.ListLeases()); got != 1 {
		t.Fatalf("failed revert removed the lease from the listing (%d listed, want 1)", got)
	}
	if _, ok := mgr.leases["mcp_lease_test"]; !ok {
		t.Fatal("failed revert deleted the lease record")
	}
}

// M8: the happy paths still remove the record once the rebuild lands.
func TestR2Batch6RevertAndFlushRemoveLeasesOnSuccess(t *testing.T) {
	installFakeNft(t, 0)
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

	lease, err := mgr.RevertLease("mcp_lease_a")
	if err != nil {
		t.Fatalf("RevertLease failed with working nft: %v", err)
	}
	if lease == nil || lease.ID != "mcp_lease_a" {
		t.Fatalf("RevertLease returned wrong lease: %+v", lease)
	}
	if got := len(mgr.ListLeases()); got != 1 {
		t.Fatalf("expected 1 lease after revert, got %d", got)
	}

	cleared, err := mgr.FlushAllLeases()
	if err != nil {
		t.Fatalf("FlushAllLeases failed with working nft: %v", err)
	}
	if cleared != 1 {
		t.Fatalf("FlushAllLeases cleared %d, want 1", cleared)
	}
	if got := len(mgr.ListLeases()); got != 0 {
		t.Fatalf("expected 0 leases after flush, got %d", got)
	}
}

// M9: a janitor reconcile failure must stay sticky (dirty) and be
// retried on the next tick — the next tick finds no expired leases
// left, so without a retry the expired leases could stay enforced
// indefinitely.
func TestR2Batch6JanitorRetriesFailedReconcile(t *testing.T) {
	installFakeNft(t, 1)
	mgr := newTestTrafficManager(t)
	now := time.Now().UTC()
	mgr.leases["mcp_lease_expired"] = &McpTacticalLease{
		ID:               "mcp_lease_expired",
		Kind:             "blackhole",
		CreatedAt:        now.Add(-2 * time.Hour).Format(time.RFC3339),
		ExpiresAt:        now.Add(-time.Hour).Format(time.RFC3339),
		NormalizedTarget: "198.51.100.20",
		Parameters:       map[string]interface{}{"mode": "nft_drop", "direction": "both"},
	}

	mgr.purgeExpiredLeases()
	if got := len(mgr.ListLeases()); got != 0 {
		t.Fatalf("expired lease was not purged (%d listed)", got)
	}
	if !mgr.ReconcileDirty() {
		t.Fatal("failed janitor rebuild did not mark the manager dirty; the failure would never be retried")
	}

	// The nft binary recovers; the next tick — with nothing left to
	// expire — must retry the rebuild and clear the dirty flag.
	installFakeNft(t, 0)
	mgr.purgeExpiredLeases()
	if mgr.ReconcileDirty() {
		t.Fatal("dirty flag was not cleared after the retry rebuild succeeded")
	}
}

// M9: a failed startup reconcile marks the manager dirty so the
// janitor retries it, instead of listing reloaded leases as active
// with a stale kernel table.
func TestR2Batch6StartupReconcileFailureMarksDirty(t *testing.T) {
	installFakeNft(t, 1)
	orig := mcpStateFilePath
	mcpStateFilePath = filepath.Join(t.TempDir(), "mcp-tactical-state.json")
	t.Cleanup(func() { mcpStateFilePath = orig })

	mgr := NewMcpTrafficManager()
	defer close(mgr.stopTicker)
	if !mgr.ReconcileDirty() {
		t.Fatal("failed startup rebuild did not mark the manager dirty")
	}
}
