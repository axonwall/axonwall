package engine

// Round-2 bug-hunt fix batch 10 (daemon-low-2) regression tests:
// A-L33..A-L41 (satellite side). A-L38 (the SYNC_NFTABLES ack) and
// A-L41 (the netlink table replace) need a live box / kernel
// netlink and are not unit-testable here; they were verified by
// build + vet and code review, and still need live-box verification.

import (
	"bytes"
	"strings"
	"testing"
)

// A-L33: a set with type and flags on one line must record the bare
// key type and the interval flag.
func TestBatch10NftSetCombinedTypeFlags(t *testing.T) {
	script := "table inet axonwall {\n  set blocked_ips {\n    type ipv4_addr; flags interval;\n  }\n  chain input {\n    type filter hook input priority filter; policy drop;\n  }\n}"
	b, err := CompileNftScriptToNetlinkBatch(script)
	if err != nil {
		t.Fatalf("CompileNftScriptToNetlinkBatch failed: %v", err)
	}
	if len(b.Sets) != 1 {
		t.Fatalf("expected 1 set, got %d", len(b.Sets))
	}
	if b.Sets[0].KeyType != "ipv4_addr" {
		t.Fatalf("KeyType = %q, want \"ipv4_addr\"", b.Sets[0].KeyType)
	}
	if b.Sets[0].KeyLen != 4 {
		t.Fatalf("KeyLen = %d, want 4", b.Sets[0].KeyLen)
	}
	if !b.Sets[0].Interval {
		t.Fatalf("Interval = false for \"type ipv4_addr; flags interval;\"")
	}
}

// A-L33: the separate-lines form must keep working.
func TestBatch10NftSetSeparateTypeFlags(t *testing.T) {
	script := "table inet axonwall {\n  set blocked_ips {\n    type ipv4_addr;\n    flags interval;\n  }\n  chain input {\n    type filter hook input priority filter; policy drop;\n  }\n}"
	b, err := CompileNftScriptToNetlinkBatch(script)
	if err != nil {
		t.Fatalf("CompileNftScriptToNetlinkBatch failed: %v", err)
	}
	if len(b.Sets) != 1 || b.Sets[0].KeyType != "ipv4_addr" || !b.Sets[0].Interval {
		t.Fatalf("separate-lines set parsed as %+v, want KeyType=ipv4_addr Interval=true", b.Sets)
	}
}

// A-L34: a flow_offload rule referencing a flowtable the batch does
// not define must fail compilation, not be silently dropped.
func TestBatch10NftRejectsMissingFlowtable(t *testing.T) {
	for _, rule := range []string{
		"meta l4proto { tcp, udp } ct state established flow add @fastpath",
		"meta l4proto { tcp, udp } ct state established flow offload @fastpath",
	} {
		script := "table inet axonwall {\n  chain forward {\n    type filter hook forward priority filter; policy drop;\n    " + rule + "\n  }\n}"
		if _, err := CompileNftScriptToNetlinkBatch(script); err == nil {
			t.Fatalf("CompileNftScriptToNetlinkBatch(%q) succeeded, want an error naming the missing flowtable", rule)
		} else if !strings.Contains(err.Error(), "fastpath") {
			t.Fatalf("CompileNftScriptToNetlinkBatch(%q) error %v does not name the missing flowtable", rule, err)
		}
	}
}

// A-L35: "limit rate over 100/second" must compile to the same limit
// expression as "limit rate 100/second" — not to the old silent
// 10/second default — and an explicit burst must be honoured.
func TestBatch10NftLimitRateOver(t *testing.T) {
	compileLimit := func(rateLine string) [][]byte {
		script := "table inet axonwall {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    " + rateLine + " drop\n  }\n}"
		b, err := CompileNftScriptToNetlinkBatch(script)
		if err != nil {
			t.Fatalf("CompileNftScriptToNetlinkBatch(%q) failed: %v", rateLine, err)
		}
		if len(b.Rules) != 1 {
			t.Fatalf("expected 1 rule for %q, got %d", rateLine, len(b.Rules))
		}
		return b.Rules[0].Expressions
	}
	concat := func(exprs [][]byte) []byte {
		var out []byte
		for _, e := range exprs {
			out = append(out, e...)
		}
		return out
	}

	over100 := concat(compileLimit("limit rate over 100/second"))
	plain100 := concat(compileLimit("limit rate 100/second"))
	if !bytes.Equal(over100, plain100) {
		t.Fatalf("\"limit rate over 100/second\" compiled differently from \"limit rate 100/second\"")
	}
	plain10 := concat(compileLimit("limit rate 10/second"))
	if bytes.Equal(over100, plain10) {
		t.Fatalf("\"limit rate over 100/second\" compiled to the same limit as \"limit rate 10/second\" (the old silent default)")
	}
	over100Burst20 := concat(compileLimit("limit rate over 100/second burst 20"))
	plain100Burst20 := concat(compileLimit("limit rate 100/second burst 20"))
	if !bytes.Equal(over100Burst20, plain100Burst20) {
		t.Fatalf("\"limit rate over 100/second burst 20\" compiled differently from \"limit rate 100/second burst 20\"")
	}
	if bytes.Equal(over100Burst20, plain100) {
		t.Fatalf("an explicit \"burst 20\" compiled identically to the default burst")
	}
	if _, err := CompileNftScriptToNetlinkBatch("table inet axonwall {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    limit rate over banana/second drop\n  }\n}"); err == nil {
		t.Fatalf("an unparseable limit rate compiled without an error")
	}
}

// A-L36: ConfigureInterface must surface MTU, IPv6-mode, and
// IPv6-address failures instead of acking them as configured.
func TestBatch10ConfigureInterfaceErrors(t *testing.T) {
	eng := &EdgeNetworkEngine{SysClassNetDir: "/sys/class/net"}
	cases := []struct {
		name string
		spec EdgeInterfaceSpec
		want string
	}{
		{
			"MTU",
			EdgeInterfaceSpec{Name: "wan", Device: "eth99missing", MTU: 1500, Enabled: true},
			"MTU",
		},
		{
			"IPv6Mode",
			EdgeInterfaceSpec{Name: "wan", Device: "eth99missing", IPv6Mode: "auto", Enabled: true},
			"IPv6 mode",
		},
		{
			"IPv6Address",
			EdgeInterfaceSpec{Name: "wan", Device: "eth99missing", IPv6Address: "fd00::1/64", Enabled: true},
			"IPv6 address",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := eng.ConfigureInterface(tc.spec)
			if err == nil {
				t.Fatalf("ConfigureInterface(%+v) returned nil, want an error mentioning %s", tc.spec, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ConfigureInterface error %v does not mention %q", err, tc.want)
			}
		})
	}
}

// A-L37: a JSON user-data seed must honour numeric scalars and
// interfaces/routes lists, like the YAML path does.
func TestBatch10CloudInitJSONNumbersAndLists(t *testing.T) {
	cfg := &EdgeBootConfig{}
	raw := `{"axonwall": {"hub": "https://hub.example:2966", "token": "tok", "watchdog_sec": 60, ` +
		`"interfaces": [{"name": "wan", "device": "eth0", "address": "10.0.0.2/24", "gateway": "10.0.0.1"}, ` +
		`{"name": "lan", "device": "eth1", "address": "10.1.0.1/24"}], ` +
		`"routes": [{"destination": "10.20.0.0/16", "gateway": "10.0.0.1", "device": "eth0"}]}}`
	if err := applyCloudInitJSON(cfg, raw, t.TempDir()); err != nil {
		t.Fatalf("applyCloudInitJSON failed: %v", err)
	}
	if cfg.HubURL != "https://hub.example:2966" {
		t.Fatalf("HubURL = %q, want https://hub.example:2966", cfg.HubURL)
	}
	if cfg.ZtpToken != "tok" {
		t.Fatalf("ZtpToken = %q, want tok", cfg.ZtpToken)
	}
	if cfg.WatchdogSec != 60 {
		t.Fatalf("WatchdogSec = %d, want 60 (numeric scalars were dropped)", cfg.WatchdogSec)
	}
	if len(cfg.Interfaces) != 2 {
		t.Fatalf("Interfaces = %d, want 2 (JSON interface lists were dropped)", len(cfg.Interfaces))
	}
	if cfg.Interfaces[0].Device != "eth0" || cfg.Interfaces[0].Address != "10.0.0.2/24" || cfg.Interfaces[0].Gateway != "10.0.0.1" {
		t.Fatalf("Interfaces[0] = %+v, want wan eth0 10.0.0.2/24 gw 10.0.0.1", cfg.Interfaces[0])
	}
	if cfg.Interfaces[1].Device != "eth1" || cfg.Interfaces[1].Address != "10.1.0.1/24" {
		t.Fatalf("Interfaces[1] = %+v, want lan eth1 10.1.0.1/24", cfg.Interfaces[1])
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("Routes = %d, want 1 (JSON route lists were dropped)", len(cfg.Routes))
	}
	if cfg.Routes[0].Destination != "10.20.0.0/16" || cfg.Routes[0].Gateway != "10.0.0.1" || cfg.Routes[0].Device != "eth0" {
		t.Fatalf("Routes[0] = %+v, want 10.20.0.0/16 via 10.0.0.1 dev eth0", cfg.Routes[0])
	}
}

// A-L39: an empty TunnelIP must be rejected, not configured as an
// unnumbered mesh interface that reports success.
func TestBatch10ConfigureMeshRejectsEmptyTunnelIP(t *testing.T) {
	wg := NewWireGuardEngine()
	err := wg.ConfigureMesh(WireGuardConfig{
		InterfaceName: "wg-axon0",
		ListenPort:    51820,
		PrivateKey:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	})
	if err == nil {
		t.Fatalf("ConfigureMesh with an empty TunnelIP returned nil")
	}
	if !strings.Contains(err.Error(), "tunnel") {
		t.Fatalf("ConfigureMesh error %v does not mention the tunnel IP", err)
	}
}

// A-L40: subnet IDs must be placed in bits [ones, 64) for every
// prefix width, and IDs that do not fit must be rejected instead of
// silently truncated.
//
// NOTE on the report's /60 expectation: bits 60-63 are the LOW
// nibble of byte 7, so /60 subnet 5 correctly carves ...:5::, not
// ...:50:: (that would put subnet bits at 56-59, which are prefix
// bits for a /60). The /52 placement below is the real bug the
// report verified.
func TestBatch10CarveSubnet64PrefixWidths(t *testing.T) {
	cases := []struct {
		prefix string
		subnet uint16
		host   uint16
		want   string
	}{
		{"2001:db8:abcd::/48", 0x123, 1, "2001:db8:abcd:123::1/64"},
		{"2001:db8:abcd::/52", 0x123, 1, "2001:db8:abcd:123::1/64"},
		{"2001:db8:abcd:1200::/56", 0x34, 0, "2001:db8:abcd:1234::/64"},
		{"2001:db8:abcd:1230::/60", 5, 0, "2001:db8:abcd:1235::/64"},
		{"2001:db8:abcd::/48", 0, 0, "2001:db8:abcd::/64"},
	}
	for _, tc := range cases {
		got, err := CarveSubnet64(tc.prefix, tc.subnet, tc.host)
		if err != nil {
			t.Fatalf("CarveSubnet64(%s, %#x, %d) failed: %v", tc.prefix, tc.subnet, tc.host, err)
		}
		if got != tc.want {
			t.Errorf("CarveSubnet64(%s, %#x, %d) = %s, want %s", tc.prefix, tc.subnet, tc.host, got, tc.want)
		}
	}
	overflow := []struct {
		prefix string
		subnet uint16
	}{
		{"2001:db8:abcd:1230::/60", 16},
		{"2001:db8:abcd::/52", 0x1000},
		{"2001:db8:abcd:1200::/56", 256},
	}
	for _, tc := range overflow {
		if got, err := CarveSubnet64(tc.prefix, tc.subnet, 0); err == nil {
			t.Errorf("CarveSubnet64(%s, %#x, 0) = %s, want an error (ID does not fit)", tc.prefix, tc.subnet, got)
		}
	}
}
