package engine

// Round-2 bug-hunt fix batch 10 (daemon-low-2) regression tests:
// A-L33..A-L41 (satellite side). A-L38 (the SYNC_NFTABLES ack) and
// A-L41 (the netlink table replace) need a live box / kernel
// netlink and are not unit-testable here; they were verified by
// build + vet and code review, and still need live-box verification.

import (
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
