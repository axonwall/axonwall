package engine

import (
	"testing"
)

// Round-2 batch 8 (daemon-med-3) regression tests.

// A-M35: "eth0:dhcp:<gateway>" was rejected outright (the else-if branch
// was dead code), so the whole interface spec was dropped. A bare IP
// with a gateway ("eth0:10.0.0.1:10.0.0.254", no prefix) was dropped
// the same way.
func TestBatch8ParseInterfaceBootArgDHCPGateway(t *testing.T) {
	cases := []struct {
		arg     string
		wantOK  bool
		wantAdr string
		wantGw  string
	}{
		{"eth0:dhcp:10.0.0.1", true, "dhcp", "10.0.0.1"},
		{"eth0:DHCP:10.0.0.1", true, "dhcp", "10.0.0.1"},
		{"eth0:10.0.0.1:10.0.0.254", true, "10.0.0.1/24", "10.0.0.254"},
		{"eth0:dhcp", true, "dhcp", ""},
		{"eth0:10.0.0.2/24:10.0.0.1", true, "10.0.0.2/24", "10.0.0.1"},
		{"eth0:fd00::1/64:fd00::ffff", true, "fd00::1/64", "fd00::ffff"},
		{"eth0:dhcp:not-an-ip", false, "", ""},
		{"eth0:10.0.0.1:not-an-ip", false, "", ""},
	}
	for _, tc := range cases {
		spec, ok := parseInterfaceBootArg("wan", tc.arg)
		if ok != tc.wantOK {
			t.Fatalf("parseInterfaceBootArg(%q): ok=%v, want %v", tc.arg, ok, tc.wantOK)
		}
		if !tc.wantOK {
			continue
		}
		if spec.Address != tc.wantAdr || spec.Gateway != tc.wantGw {
			t.Fatalf("parseInterfaceBootArg(%q): got address=%q gateway=%q, want %q/%q",
				tc.arg, spec.Address, spec.Gateway, tc.wantAdr, tc.wantGw)
		}
	}
}
