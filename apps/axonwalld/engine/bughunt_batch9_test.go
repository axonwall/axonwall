package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Batch 9 (round-2 daemon lows) regression tests.

// batch9FakeTcpdump installs a fake tcpdump on PATH that prints
// stdoutText and exits with exitCode.
func batch9FakeTcpdump(t *testing.T, stdoutText, exitCode string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s' '" + stdoutText + "'\nexit " + exitCode + "\n"
	if err := os.WriteFile(filepath.Join(dir, "tcpdump"), []byte(script), 0755); err != nil {
		t.Fatalf("write fake tcpdump: %v", err)
	}
	orig := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir+":"+orig); err != nil {
		t.Fatalf("set PATH: %v", err)
	}
	t.Cleanup(func() { _ = os.Setenv("PATH", orig) })
}

// L11: a failed tcpdump run must return an error, not "success, 0
// packets". Pre-fix, CapturePacketSample discarded tcpdump's error
// and stderr — the same lie A-M15 fixed in RunCapture.
func TestBatch9CapturePacketSampleReturnsErrorOnFailedTcpdump(t *testing.T) {
	batch9FakeTcpdump(t, "", "1")
	mgr := &McpTrafficManager{}
	if _, err := mgr.CapturePacketSample("eth0", "", "", "", 0, 20, 5); err == nil {
		t.Fatal("expected an error from a failed tcpdump run")
	}
}

// L11: a successful tcpdump run still parses packets.
func TestBatch9CapturePacketSampleParsesPackets(t *testing.T) {
	batch9FakeTcpdump(t, "1700000000.123456 IP 10.0.0.1.1234 > 10.0.0.2.80: Flags [S], seq 1\n", "0")
	mgr := &McpTrafficManager{}
	packets, err := mgr.CapturePacketSample("eth0", "", "", "", 0, 20, 5)
	if err != nil {
		t.Fatalf("CapturePacketSample failed: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	if packets[0].SrcIP != "10.0.0.1" || packets[0].DstIP != "10.0.0.2" {
		t.Fatalf("unexpected packet: %+v", packets[0])
	}
}

// L11: tcpdump missing entirely is an error, not an empty sample.
func TestBatch9CapturePacketSampleErrorsWithoutTcpdump(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	mgr := &McpTrafficManager{}
	if _, err := mgr.CapturePacketSample("eth0", "", "", "", 0, 20, 5); err == nil {
		t.Fatal("expected an error without tcpdump")
	} else if !strings.Contains(err.Error(), "tcpdump") {
		t.Fatalf("expected a tcpdump error, got: %v", err)
	}
}

// L12: snapshot/scrub must fail when the ZFS tooling is absent.
// Pre-fix, both returned success on a box without zfs/zpool — the
// caller was told a snapshot was created / a scrub ran when nothing
// happened.
func TestBatch9NasSnapshotScrubErrorWithoutZfs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	mgr := NewNasManager()
	if _, err := mgr.CreateSnapshot("tank/data", "test"); err == nil {
		t.Fatal("CreateSnapshot must fail without zfs installed")
	}
	if err := mgr.ScrubPool("tank"); err == nil {
		t.Fatal("ScrubPool must fail without zpool installed")
	}
}

// L13: the pcap parser must count IPv6 and ARP packets. Pre-fix,
// both regexes matched only "IP " lines, so IP6 and ARP packets
// were dropped without a trace and PacketCount understated the
// capture.
func TestBatch9ParseTcpdumpLineIPv6AndARP(t *testing.T) {
	pkt, ok := parseTcpdumpLine("1700000000.123456 IP6 2001:db8::1.54321 > 2001:db8::2.443: Flags [S], seq 1", 1)
	if !ok {
		t.Fatal("IP6 port line must parse")
	}
	if pkt.SrcIP != "2001:db8::1" || pkt.DstIP != "2001:db8::2" || pkt.SrcPort != "54321" || pkt.DstPort != "443" {
		t.Fatalf("unexpected IP6 packet: %+v", pkt)
	}
	if pkt.Protocol != "TLS/HTTPS" {
		t.Fatalf("expected TLS/HTTPS for port 443, got %q", pkt.Protocol)
	}

	pkt, ok = parseTcpdumpLine("1700000000.123456 IP6 2001:db8::1 > 2001:db8::2: ICMP6, echo request, seq 1", 2)
	if !ok {
		t.Fatal("IP6 generic line must parse")
	}
	if pkt.Protocol != "ICMPv6" {
		t.Fatalf("expected ICMPv6, got %q", pkt.Protocol)
	}

	pkt, ok = parseTcpdumpLine("1700000000.123456 ARP, Request who-has 192.168.1.1 tell 192.168.1.2, length 28", 3)
	if !ok {
		t.Fatal("ARP line must parse")
	}
	if pkt.Protocol != "ARP" {
		t.Fatalf("expected ARP, got %q", pkt.Protocol)
	}
	if !strings.Contains(pkt.Info, "who-has 192.168.1.1") {
		t.Fatalf("unexpected ARP info: %q", pkt.Info)
	}

	// IPv4 behaviour is unchanged.
	pkt, ok = parseTcpdumpLine("1700000000.123456 IP 10.0.0.1.1234 > 10.0.0.2.80: Flags [S], seq 1", 4)
	if !ok || pkt.Protocol != "HTTP" {
		t.Fatalf("IPv4 line must still parse as HTTP, got ok=%v pkt=%+v", ok, pkt)
	}
	if _, ok := parseTcpdumpLine("reading from file test.pcap, link-type EN10MB", 5); ok {
		t.Fatal("tcpdump banner lines must not parse as packets")
	}
}
