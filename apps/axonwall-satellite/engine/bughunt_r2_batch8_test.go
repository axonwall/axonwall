package engine

import (
	"strings"
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

// Round-2 batch 8 (daemon-med-3) regression tests: nft compiler
// (A-M36/M37/M38).

// decodeExprName returns the nft expression name ("payload", "cmp",
// "bitwise", "reject", ...) encoded in one serialized expression, and
// the nested data attributes that follow it.
func decodeExprName(expr []byte) (string, [][]byte) {
	if len(expr) < 4 {
		return "", nil
	}
	// Outer attr: NLA_F_NESTED | NFTA_LIST_ELEM; payload is the children.
	payload := expr[4:]
	var name string
	var data [][]byte
	for len(payload) >= 4 {
		attrLen := int(binaryLittleEndianUint16(payload[0:2]))
		attrType := binaryLittleEndianUint16(payload[2:4]) & 0x3fff
		if attrLen < 4 || attrLen > len(payload) {
			break
		}
		body := payload[4:attrLen]
		switch attrType {
		case 1: // NFTA_EXPR_NAME
			name = strings.TrimRight(string(body), "\x00")
		case 2: // NFTA_EXPR_DATA (nested attrs)
			for len(body) >= 4 {
				dLen := int(binaryLittleEndianUint16(body[0:2]))
				if dLen < 4 || dLen > len(body) {
					break
				}
				data = append(data, body[:dLen])
				body = body[(dLen+3)&^3:]
			}
		}
		payload = payload[(attrLen+3)&^3:]
	}
	return name, data
}

func binaryLittleEndianUint16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}

// exprNames returns the expression names of a compiled rule, in order.
func exprNames(rule NftRuleSpec) []string {
	names := make([]string, 0, len(rule.Expressions))
	for _, e := range rule.Expressions {
		n, _ := decodeExprName(e)
		names = append(names, n)
	}
	return names
}

// payloadLoadOffset extracts the NFTA_PAYLOAD_OFFSET of the first payload
// expression in a rule (0 when there is none).
func payloadLoadOffset(rule NftRuleSpec) (uint32, bool) {
	for _, e := range rule.Expressions {
		name, data := decodeExprName(e)
		if name != "payload" {
			continue
		}
		for _, attr := range data {
			if len(attr) < 8 {
				continue
			}
			attrType := binaryLittleEndianUint16(attr[2:4]) & 0x3fff
			if attrType == 3 { // NFTA_PAYLOAD_OFFSET
				return uint32(attr[4])<<24 | uint32(attr[5])<<16 | uint32(attr[6])<<8 | uint32(attr[7]), true
			}
		}
	}
	return 0, false
}

func compileNftRules(t *testing.T, script string) *NftCompiledBatch {
	t.Helper()
	batch, err := CompileNftScriptToNetlinkBatch(script)
	if err != nil {
		t.Fatalf("CompileNftScriptToNetlinkBatch failed: %v", err)
	}
	return batch
}

func nftScriptWithRules(rules ...string) string {
	s := "table inet axonwall {\n  chain input {\n    type filter hook input priority filter; policy drop;\n"
	for _, r := range rules {
		s += "    " + r + "\n"
	}
	return s + "  }\n}\n"
}

// A-M37: "ether daddr" compiled to a source-MAC match (offset 6); it
// must load the destination MAC at LL-header offset 0.
func TestBatch8EtherDaddrOffset(t *testing.T) {
	batch := compileNftRules(t, nftScriptWithRules(
		"ether daddr aa:bb:cc:dd:ee:ff drop",
		"ether saddr aa:bb:cc:dd:ee:ff drop",
	))
	if len(batch.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(batch.Rules))
	}
	if off, ok := payloadLoadOffset(batch.Rules[0]); !ok || off != 0 {
		t.Fatalf("ether daddr: payload offset = %d (present=%v), want 0", off, ok)
	}
	if off, ok := payloadLoadOffset(batch.Rules[1]); !ok || off != 6 {
		t.Fatalf("ether saddr: payload offset = %d (present=%v), want 6", off, ok)
	}
}

// A-M38: chain priorities other than srcnat/dstnat flattened to 0.
func TestBatch8ChainPriorityParsing(t *testing.T) {
	cases := []struct {
		header string
		want   int32
	}{
		{"type nat hook prerouting priority -100; policy accept;", -100},
		{"type filter hook prerouting priority -150; policy accept;", -150},
		{"type filter hook input priority 50; policy accept;", 50},
		{"type filter hook input priority raw; policy accept;", -300},
		{"type filter hook input priority mangle; policy accept;", -150},
		{"type filter hook input priority dstnat; policy accept;", -100},
		{"type filter hook input priority filter; policy accept;", 0},
		{"type filter hook input priority security; policy accept;", 50},
		{"type filter hook input priority srcnat; policy accept;", 100},
		{"type filter hook input priority out; policy accept;", 100},
	}
	for _, tc := range cases {
		script := "table inet axonwall {\n  chain c {\n    " + tc.header + "\n    accept\n  }\n}\n"
		batch := compileNftRules(t, script)
		if len(batch.Chains) != 1 {
			t.Fatalf("%q: expected 1 chain, got %d", tc.header, len(batch.Chains))
		}
		if batch.Chains[0].Priority != tc.want {
			t.Fatalf("%q: priority = %d, want %d", tc.header, batch.Chains[0].Priority, tc.want)
		}
	}
}

// A-M36: the five shapes that used to fail the whole batch must now
// compile: bare log, reject, CIDR match, port set, proto set.
func TestBatch8NftCompilerCommonConstructs(t *testing.T) {
	batch := compileNftRules(t, nftScriptWithRules(
		"ip saddr 10.0.0.1 log drop",
		"ip saddr 10.0.0.1 log level warn drop",
		"ip saddr 10.0.0.1 reject",
		"ip saddr 10.0.0.1 reject with tcp reset",
		"ip saddr 10.0.0.0/24 drop",
		"ip6 saddr fd00::/64 drop",
		"tcp dport { 80, 443 } accept",
		"meta l4proto { tcp, udp } accept",
		"ip saddr 10.0.0.1 return",
		"ip saddr 10.0.0.1 jump mychain",
	))
	// 2 log + 2 reject + 2 CIDR + 2 port-set + 2 proto-set + return + jump = 12
	if len(batch.Rules) != 12 {
		t.Fatalf("expected 12 compiled rules, got %d", len(batch.Rules))
	}
	// The CIDR rule must contain a masked compare (bitwise expr).
	foundBitwise := false
	for _, n := range exprNames(batch.Rules[4]) {
		if n == "bitwise" {
			foundBitwise = true
		}
	}
	if !foundBitwise {
		t.Fatalf("CIDR rule has no bitwise expression: %v", exprNames(batch.Rules[4]))
	}
	// The reject rules must contain a reject expression.
	for _, idx := range []int{2, 3} {
		found := false
		for _, n := range exprNames(batch.Rules[idx]) {
			if n == "reject" {
				found = true
			}
		}
		if !found {
			t.Fatalf("reject rule %d has no reject expression: %v", idx, exprNames(batch.Rules[idx]))
		}
	}
}

// A-M36: the flowtable-offload l4proto set keeps its existing single-rule
// shape (the match is skipped for offload), so the lockdown script's rule
// count does not change.
func TestBatch8NftFlowOffloadSetNotExpanded(t *testing.T) {
	batch := compileNftRules(t, nftScriptWithRules(
		"meta l4proto { tcp, udp } ct state established flow add @fastpath",
	))
	if len(batch.Rules) != 1 {
		t.Fatalf("expected 1 flow-offload rule, got %d", len(batch.Rules))
	}
}
