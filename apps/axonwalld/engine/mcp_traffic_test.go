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

// installFakeBinary prepends a directory containing a fake executable of the
// given name to PATH and returns the path of the file the fake appends its
// arguments to. The fake exits with the given status, so tests do not depend
// on the sandbox's real tc/ip binaries or kernel.
func installFakeBinary(t *testing.T, name string, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, name+"-args.log")
	script := "#!/bin/sh\n" +
		"echo \"$@\" >> \"" + logPath + "\"\n" +
		"exit " + string(rune('0'+exitCode)) + "\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0755); err != nil {
		t.Fatalf("Failed to write fake %s: %v", name, err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return logPath
}

func shapeReq() McpShapeReq {
	return McpShapeReq{
		Target:           "198.51.100.20",
		Interface:        "lo",
		Direction:        "both",
		RateKbps:         1024,
		CeilKbps:         2048,
		TTLSeconds:       3600,
		CallerIP:         "10.42.1.25",
		MaxIPv4PrefixLen: 24,
		MaxIPv6PrefixLen: 64,
		KeyID:            "test-key",
		KeyName:          "test-agent",
	}
}

func redirectReq() McpRedirectReq {
	return McpRedirectReq{
		Source:            "198.51.100.30",
		TargetDestination: "198.51.100.99",
		RedirectType:      "policy_route",
		Protocol:          "tcp",
		TTLSeconds:        3600,
		CallerIP:          "10.42.1.25",
		MaxIPv4PrefixLen:  24,
		MaxIPv6PrefixLen:  64,
		KeyID:             "test-key",
		KeyName:           "test-agent",
	}
}

// A-H3: when a tc command fails, shape-lease creation must fail and the
// lease must not be stored, persisted, or listed as active.
func TestMcpShapeCreationFailsWhenTcFails(t *testing.T) {
	installFakeNft(t, 0)
	tcLog := installFakeBinary(t, "tc", 1)
	mgr := newTestTrafficManager(t)

	lease, err := mgr.ShapeTraffic(shapeReq())
	if err == nil {
		t.Fatalf("expected ShapeTraffic to fail when tc fails, got lease %+v", lease)
	}
	if len(mgr.leases) != 0 {
		t.Fatalf("expected no stored lease after tc failure, got %d", len(mgr.leases))
	}
	if _, statErr := os.Stat(tcLog); statErr != nil {
		t.Fatalf("expected tc to be invoked, no log at %s: %v", tcLog, statErr)
	}
}

// A-H3: the success path still stores the lease when tc and nft succeed.
func TestMcpShapeCreationSucceedsWhenTcSucceeds(t *testing.T) {
	installFakeNft(t, 0)
	tcLog := installFakeBinary(t, "tc", 0)
	mgr := newTestTrafficManager(t)

	lease, err := mgr.ShapeTraffic(shapeReq())
	if err != nil {
		t.Fatalf("ShapeTraffic failed with working tc: %v", err)
	}
	if lease == nil || lease.Kind != "shape" {
		t.Fatalf("expected a shape lease, got %+v", lease)
	}
	if len(mgr.leases) != 1 {
		t.Fatalf("expected 1 stored lease, got %d", len(mgr.leases))
	}
	if _, statErr := os.Stat(tcLog); statErr != nil {
		t.Fatalf("expected tc to be invoked, no log at %s: %v", tcLog, statErr)
	}
}

// A-H3: a shape lease for an interface that does not resolve to a live
// device must fail before any tc command runs.
func TestMcpShapeRejectsUnknownInterface(t *testing.T) {
	installFakeNft(t, 0)
	tcLog := installFakeBinary(t, "tc", 0)
	mgr := newTestTrafficManager(t)

	req := shapeReq()
	req.Interface = "nonexistent99"
	if _, err := mgr.ShapeTraffic(req); err == nil {
		t.Fatalf("expected ShapeTraffic to fail for an unresolvable interface")
	}
	if _, statErr := os.Stat(tcLog); statErr == nil {
		t.Fatalf("expected tc NOT to be invoked for an unresolvable interface")
	}
}

// A-H3: unvalidated shape parameters that make `tc netem` fail must be
// rejected up front instead of producing a lease that shapes nothing.
func TestMcpShapeRejectsInvalidNetemParams(t *testing.T) {
	mgr := newTestTrafficManager(t)

	req := shapeReq()
	req.PacketLossPercent = 101
	if _, err := mgr.ShapeTraffic(req); err == nil {
		t.Errorf("expected ShapeTraffic to reject packetLossPercent > 100")
	}
	req = shapeReq()
	req.LatencyMs = 100
	req.JitterMs = 200
	if _, err := mgr.ShapeTraffic(req); err == nil {
		t.Errorf("expected ShapeTraffic to reject jitterMs > latencyMs")
	}
}

// A-H3: when an ip command fails, policy-route redirect creation must fail
// and the lease must not be stored.
func TestMcpRedirectPolicyRouteFailsWhenIpFails(t *testing.T) {
	installFakeNft(t, 0)
	installFakeBinary(t, "ip", 1)
	mgr := newTestTrafficManager(t)

	lease, err := mgr.RedirectTraffic(redirectReq())
	if err == nil {
		t.Fatalf("expected RedirectTraffic to fail when ip fails, got lease %+v", lease)
	}
	if len(mgr.leases) != 0 {
		t.Fatalf("expected no stored lease after ip failure, got %d", len(mgr.leases))
	}
}

// A-H3: the success path still stores the lease when ip and nft succeed.
func TestMcpRedirectPolicyRouteSucceedsWhenIpSucceeds(t *testing.T) {
	installFakeNft(t, 0)
	installFakeBinary(t, "ip", 0)
	mgr := newTestTrafficManager(t)

	lease, err := mgr.RedirectTraffic(redirectReq())
	if err != nil {
		t.Fatalf("RedirectTraffic failed with working ip: %v", err)
	}
	if lease == nil || lease.Kind != "redirect" {
		t.Fatalf("expected a redirect lease, got %+v", lease)
	}
	if len(mgr.leases) != 1 {
		t.Fatalf("expected 1 stored lease, got %d", len(mgr.leases))
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
	// M8: the record must survive a failed rebuild — the lease stays
	// listed and revertable instead of vanishing while the kernel may
	// still enforce it.
	if got := len(mgr.ListLeases()); got != 1 {
		t.Errorf("Expected the lease to still be listed after a failed revert, got %d listed", got)
	}
}

// A-M13: flush must report failure when the kernel rebuild fails.
// M8: on failure nothing is cleared — the records are kept so the
// leases stay listed and revertable instead of vanishing while the
// kernel may still enforce them.
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
	if cleared != 0 {
		t.Errorf("Expected cleared count 0 alongside the error (nothing was cleared), got %d", cleared)
	}
	if got := len(mgr.ListLeases()); got != 2 {
		t.Errorf("Expected both leases to still be listed after a failed flush, got %d", got)
	}
}
