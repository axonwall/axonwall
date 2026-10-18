package engine

import (
	"testing"
	"time"
)

func TestValidateIPOrCIDR(t *testing.T) {
	validCases := []struct {
		input  string
		family string
	}{
		{"192.0.2.1", "ipv4"},
		{"10.0.0.0/8", "ipv4"},
		{"198.51.100.42/32", "ipv4"},
		{"2001:db8::1", "ipv6"},
		{"2001:db8::/32", "ipv6"},
		{"::1", "ipv6"},
	}

	for _, tc := range validCases {
		clean, family, err := ValidateIPOrCIDR(tc.input)
		if err != nil {
			t.Errorf("ValidateIPOrCIDR(%q) failed: %v", tc.input, err)
		}
		if clean != tc.input {
			t.Errorf("ValidateIPOrCIDR(%q) clean = %q, want %q", tc.input, clean, tc.input)
		}
		if family != tc.family {
			t.Errorf("ValidateIPOrCIDR(%q) family = %q, want %q", tc.input, family, tc.family)
		}
	}

	invalidCases := []string{
		"",
		"   ",
		"192.0.2.1; rm -rf /",
		"10.0.0.1 && cat /etc/passwd",
		"192.168.1.1`whoami`",
		"192.168.1.1$(id)",
		"not-an-ip",
		"999.999.999.999",
		"192.168.1.1/33",
		"2001:db8:::1",
		"1.2.3.4|nc 1.2.3.4 4444",
		"1.2.3.4\n1.2.3.5",
	}

	for _, input := range invalidCases {
		if _, _, err := ValidateIPOrCIDR(input); err == nil {
			t.Errorf("ValidateIPOrCIDR(%q) should have failed but succeeded", input)
		}
	}
}

func TestVigilanteManagerBlockedIPs(t *testing.T) {
	vm := NewVigilanteManager(t.TempDir())

	// Test BlockIP validation
	err := vm.BlockIP("192.0.2.100", 3600)
	// Even if nft command fails in unit test environment (no root/no nftables), in-memory map records the block
	if err != nil {
		t.Fatalf("BlockIP failed: %v", err)
	}

	blocked := vm.ListBlockedIPs()
	if len(blocked) != 1 {
		t.Fatalf("ListBlockedIPs() returned %d items, want 1", len(blocked))
	}
	if blocked[0].IP != "192.0.2.100" || blocked[0].Family != "ipv4" {
		t.Errorf("Unexpected blocked record: %+v", blocked[0])
	}

	// Test unblock
	err = vm.UnblockIP("192.0.2.100")
	if err != nil {
		t.Fatalf("UnblockIP failed: %v", err)
	}

	blockedAfter := vm.ListBlockedIPs()
	if len(blockedAfter) != 0 {
		t.Fatalf("ListBlockedIPs() returned %d items after unblock, want 0", len(blockedAfter))
	}
}

func TestVigilanteManagerExpiration(t *testing.T) {
	vm := NewVigilanteManager(t.TempDir())

	vm.mu.Lock()
	vm.blockedIPs["198.51.100.5"] = BlockedIPRecord{
		IP:        "198.51.100.5",
		Family:    "ipv4",
		BlockedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
	}
	vm.blockedIPs["203.0.113.10"] = BlockedIPRecord{
		IP:        "203.0.113.10",
		Family:    "ipv4",
		BlockedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour), // Active
	}
	vm.mu.Unlock()

	active := vm.ListBlockedIPs()
	if len(active) != 1 {
		t.Fatalf("ListBlockedIPs() returned %d active items, want 1", len(active))
	}
	if active[0].IP != "203.0.113.10" {
		t.Errorf("Unexpected active IP: %s", active[0].IP)
	}
}

func TestValidateEvidenceVaultInputs(t *testing.T) {
	vm := NewVigilanteManager(t.TempDir())

	// Malicious pool or dataset name
	if err := vm.ProvisionEvidenceVault("tank; rm -rf /", "evidence"); err == nil {
		t.Errorf("ProvisionEvidenceVault should reject command injection in pool name")
	}

	// Malicious incident ID
	if _, err := vm.CreateIncidentSnapshot("tank", "evidence", "inc-01; echo pwned"); err == nil {
		t.Errorf("CreateIncidentSnapshot should reject command injection in incident ID")
	}

	// Traversal
	if err := vm.ProvisionEvidenceVault("../etc", "evidence"); err == nil {
		t.Errorf("ProvisionEvidenceVault should reject directory traversal in pool name")
	}
}
