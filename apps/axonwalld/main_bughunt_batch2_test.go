package main

import (
	"reflect"
	"testing"
)

// A-M16 regression: staleStaticAddrs must return only the stale global
// addresses on a WAN device — never a keepalived VRRP VIP (a secondary
// address) and never the target address itself. Pre-fix, the caller ran
// `ip addr flush`, which deleted VIPs along with the stale address.
func TestStaleStaticAddrsKeepsVipsAndTarget(t *testing.T) {
	addrShow := `2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet 203.0.113.10/24 brd 203.0.113.255 scope global eth0
    inet 203.0.113.99/24 brd 203.0.113.255 scope global secondary eth0
    inet 169.254.1.2/16 scope link eth0
    inet 192.0.2.5/24 brd 192.0.2.255 scope global eth0
    inet6 fe80::1/64 scope link
`
	got := staleStaticAddrs(addrShow, "203.0.113.20/24")
	// 203.0.113.10 and 192.0.2.5 are stale globals; the VIP
	// (203.0.113.99, secondary) and the link-local address survive.
	want := []string{"203.0.113.10/24", "192.0.2.5/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("staleStaticAddrs = %v, want %v", got, want)
	}
}

func TestStaleStaticAddrsRemovesDifferingPrefixOnSameIP(t *testing.T) {
	addrShow := `    inet 203.0.113.20/24 brd 203.0.113.255 scope global eth0
    inet 203.0.113.20/25 brd 203.0.113.127 scope global eth0
    inet 203.0.113.30/24 brd 203.0.113.255 scope global eth0
`
	// Linux netlink keys addresses by (local, prefixlen): changing prefix
	// length on the same IP requires removing the old prefix rather than
	// leaving dual prefixes bound on the interface.
	got := staleStaticAddrs(addrShow, "203.0.113.20/24")
	want := []string{"203.0.113.20/25", "203.0.113.30/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("staleStaticAddrs = %v, want %v", got, want)
	}

	// Bare IP target without a prefix still preserves any matching IP prefix.
	gotBare := staleStaticAddrs(addrShow, "203.0.113.20")
	wantBare := []string{"203.0.113.30/24"}
	if !reflect.DeepEqual(gotBare, wantBare) {
		t.Fatalf("staleStaticAddrs(bare) = %v, want %v", gotBare, wantBare)
	}
}

func TestStaleStaticAddrsEmpty(t *testing.T) {
	if got := staleStaticAddrs("", "203.0.113.20/24"); len(got) != 0 {
		t.Fatalf("empty addr output must yield no stale addresses, got %v", got)
	}
	if got := staleStaticAddrs("    inet 203.0.113.99/24 scope global secondary eth0\n", "203.0.113.20/24"); len(got) != 0 {
		t.Fatalf("a device holding only a VIP must yield no stale addresses, got %v", got)
	}
}
