package engine

import (
	"testing"
)

// Round-2 batch 6 (daemon mediums) regression tests for A-M11
// (UnblockIP).

// M11: a failed nft delete is an error and the IP stays listed as
// blocked — the kernel block can survive while the UI says unblocked.
// Pre-fix UnblockIP always returned nil and dropped the map entry.
func TestR2Batch6UnblockIPKeepsRecordWhenNftFails(t *testing.T) {
	installFakeNft(t, 0)
	vm := NewVigilanteManager(t.TempDir())
	if err := vm.BlockIP("192.0.2.100", 3600); err != nil {
		t.Fatalf("BlockIP failed with working nft: %v", err)
	}
	if got := len(vm.ListBlockedIPs()); got != 1 {
		t.Fatalf("expected 1 blocked IP, got %d", got)
	}

	// The nft delete now fails: UnblockIP must report it and keep the
	// record instead of claiming the IP is free.
	installFakeNft(t, 1)
	if err := vm.UnblockIP("192.0.2.100"); err == nil {
		t.Fatal("UnblockIP succeeded when the nft delete failed; expected an error")
	}
	if got := len(vm.ListBlockedIPs()); got != 1 {
		t.Fatalf("failed unblock dropped the record anyway (%d listed, want 1)", got)
	}

	// Once nft works again the unblock lands and the record is gone.
	installFakeNft(t, 0)
	if err := vm.UnblockIP("192.0.2.100"); err != nil {
		t.Fatalf("UnblockIP failed with working nft: %v", err)
	}
	if got := len(vm.ListBlockedIPs()); got != 0 {
		t.Fatalf("expected 0 blocked IPs after unblock, got %d", got)
	}
}

// M11: unblocking an IP that was never blocked still reports the nft
// failure instead of silently returning nil.
func TestR2Batch6UnblockIPUnknownIPReportsNftFailure(t *testing.T) {
	installFakeNft(t, 1)
	vm := NewVigilanteManager(t.TempDir())
	if err := vm.UnblockIP("198.51.100.99"); err == nil {
		t.Fatal("UnblockIP succeeded for an unknown IP when the nft delete failed; expected an error")
	}
}
