package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHardenDelegatedWAN(t *testing.T) {
	tmpProc := t.TempDir()

	err := hardenDelegatedWANWithRoots(tmpProc, false, "eth0", "br-wan")
	if err != nil {
		t.Fatalf("unexpected error from hardenDelegatedWANWithRoots: %v", err)
	}

	for _, dev := range []string{"eth0", "br-wan"} {
		checks := []struct {
			relPath string
			want    string
		}{
			{filepath.Join("ipv6", "conf", dev, "disable_ipv6"), "1"},
			{filepath.Join("ipv6", "conf", dev, "accept_ra"), "0"},
			{filepath.Join("ipv4", "conf", dev, "arp_ignore"), "8"},
		}
		for _, c := range checks {
			data, err := os.ReadFile(filepath.Join(tmpProc, c.relPath))
			if err != nil {
				t.Fatalf("failed reading %s: %v", c.relPath, err)
			}
			got := strings.TrimSpace(string(data))
			if got != c.want {
				t.Errorf("sysctl %s = %q, want %q", c.relPath, got, c.want)
			}
		}
	}
}

func TestHardenDelegatedWANValidation(t *testing.T) {
	tmpProc := t.TempDir()

	if err := hardenDelegatedWANWithRoots(tmpProc, false); err == nil {
		t.Errorf("expected error when no devices passed")
	}

	invalidDevs := []string{
		"",
		"-eth0",
		"../eth0",
		"eth0;rm -rf /",
		"this-interface-name-is-way-too-long",
	}
	for _, bad := range invalidDevs {
		if err := hardenDelegatedWANWithRoots(tmpProc, false, bad); err == nil {
			t.Errorf("expected validation error for device %q, got nil", bad)
		}
	}
}

func TestBuildWanBridgeHostIsolationNft(t *testing.T) {
	nft := BuildWanBridgeHostIsolationNft("br-wan")
	if !strings.Contains(nft, "table bridge axonwall_wan") {
		t.Errorf("expected table bridge axonwall_wan, got:\n%s", nft)
	}
	if !strings.Contains(nft, "type filter hook output priority 0; policy accept;") {
		t.Errorf("expected bridge output hook, got:\n%s", nft)
	}
	if !strings.Contains(nft, `oifname "br-wan" drop comment "prevent-host-l3-leak-on-wan-bridge"`) {
		t.Errorf("expected oifname br-wan drop rule, got:\n%s", nft)
	}

	// Invalid bridge name falls back safely to "br-wan"
	nftFallback := BuildWanBridgeHostIsolationNft("../bad;name")
	if !strings.Contains(nftFallback, `oifname "br-wan" drop`) {
		t.Errorf("expected fallback to br-wan for invalid bridge name, got:\n%s", nftFallback)
	}
}

func TestValidateBridgeSpec(t *testing.T) {
	valid := BridgeSpec{
		Name:             "br-wan",
		Members:          []string{"eth0", "bond0.4000"},
		VlanFiltering:    false,
		DisableNetfilter: true,
		IsolateHostStack: true,
	}
	if err := ValidateBridgeSpec(valid); err != nil {
		t.Fatalf("expected valid spec to pass, got: %v", err)
	}

	validLan := BridgeSpec{
		Name:             "br-lan",
		Members:          []string{"eth1", "eth2"},
		VlanFiltering:    true,
		DisableNetfilter: true,
		AddressCIDR:      "10.0.0.2/24",
	}
	if err := ValidateBridgeSpec(validLan); err != nil {
		t.Fatalf("expected valid LAN bridge spec to pass, got: %v", err)
	}

	invalidSpecs := []BridgeSpec{
		{Name: "", Members: []string{"eth0"}},
		{Name: "-br0", Members: []string{"eth0"}},
		{Name: "br-wan", Members: []string{"eth0", "../bad"}},
		{Name: "br-lan", Members: []string{"eth1"}, AddressCIDR: "not-a-cidr"},
	}
	for i, s := range invalidSpecs {
		if err := ValidateBridgeSpec(s); err == nil {
			t.Errorf("case %d: expected error for invalid BridgeSpec %+v", i, s)
		}
	}
}

func TestPortGateAndTapValidation(t *testing.T) {
	if err := SetEdgeWanPortGate("../bad", false); err == nil {
		t.Errorf("expected error for invalid tapDev in SetEdgeWanPortGate")
	}
	if err := AttachTapToBridge("../bad", "br-wan", 0); err == nil {
		t.Errorf("expected error for invalid tapDev in AttachTapToBridge")
	}
	if err := AttachTapToBridge("tap-edge-wan", "../bad", 0); err == nil {
		t.Errorf("expected error for invalid bridgeName in AttachTapToBridge")
	}
	if err := AttachTapToBridge("tap-edge-wan", "br-wan", 5000); err == nil {
		t.Errorf("expected error for out-of-range vlanTag in AttachTapToBridge")
	}
}
