package engine

import (
	"testing"
)

// A-M10 regression: a rollback with no last-known-good configuration
// must return an error, not success. Pre-fix, Rollback logged a
// warning and returned nil, so the watchdog reported no error while
// the box stayed on the bad ruleset.
func TestBatch4RollbackWithoutLKGReturnsError(t *testing.T) {
	e := &NftablesEngine{}
	if err := e.Rollback(); err == nil {
		t.Fatalf("expected Rollback to fail with no last-known-good configuration")
	}
}

// A-M10: the emergency fallback is installed only when no baseline
// or confirmed ruleset exists, and never overwrites one.
func TestBatch4SetEmergencyFallback(t *testing.T) {
	empty := &NftablesEngine{}
	empty.SetEmergencyFallback(BuildEmergencyLockdownNft("wss://10.0.0.2:2966/ws/satellite"))
	if empty.lastKnownGood == "" {
		t.Fatalf("fallback must be installed when no LKG exists")
	}

	confirmed := &NftablesEngine{lastKnownGood: "confirmed-ruleset"}
	confirmed.SetEmergencyFallback(BuildEmergencyLockdownNft("wss://10.0.0.2:2966/ws/satellite"))
	if confirmed.lastKnownGood != "confirmed-ruleset" {
		t.Fatalf("fallback must not overwrite an existing LKG, got %q", confirmed.lastKnownGood)
	}
}

// A-M11 regression: a failed Promote must return an error and must
// not record the node as active. Pre-fix, Promote discarded every
// kernel error and returned nil with role "active", so the hub
// believed a node held the gateway VIP when the VIP assignment had
// silently failed.
func TestBatch4PromoteFailureKeepsRole(t *testing.T) {
	netEngine := NewEdgeNetworkEngine()
	ha := NewEdgeHAEngine("hosted", "standby")
	err := ha.Promote(netEngine, EdgeHATransitionPayload{
		WanDevice: "nonexistent-dev-xyz",
		LanDevice: "nonexistent-dev-xyz",
		LanVipV4:  "10.0.0.1/24",
	})
	if err == nil {
		t.Fatalf("expected Promote to fail on a missing device")
	}
	if ha.Role() != "standby" {
		t.Fatalf("failed Promote must not change the role, got %q", ha.Role())
	}
}

// A-M11 regression: a failed Demote must return an error and must
// not record the node as standby while its VIP may still be live.
// Pre-fix, Demote discarded every kernel error and returned nil
// with role "standby".
func TestBatch4DemoteFailureKeepsRole(t *testing.T) {
	netEngine := NewEdgeNetworkEngine()
	ha := NewEdgeHAEngine("hosted", "active")
	err := ha.Demote(netEngine, EdgeHATransitionPayload{
		WanDevice: "nonexistent-dev-xyz",
		LanDevice: "nonexistent-dev-xyz",
		LanVipV4:  "10.0.0.1/24",
	})
	if err == nil {
		t.Fatalf("expected Demote to fail on a missing device")
	}
	if ha.Role() != "active" {
		t.Fatalf("failed Demote must not change the role, got %q", ha.Role())
	}
}
