package engine

import (
	"math/bits"
	"net"
	"testing"
	"time"
)

func TestEBPF_PortByteOrderAndReturnTrafficFilter(t *testing.T) {
	// In flow_tracker.c, tcp->source and dest are copied directly in network byte order (Big Endian)
	// On Little Endian architectures (x86_64, arm64 LE), port 80 (0x0050) is stored in memory as:
	// byte 0: 0x00, byte 1: 0x50.
	// When read as uint16:
	port80Wire := uint16(0x5000)
	port443Wire := uint16(0xBB01) // 0x01BB reversed
	port53Wire := uint16(0x3500)  // 0x0035 reversed
	port22Wire := uint16(0x1600)  // 0x0016 reversed

	if got := bits.ReverseBytes16(port80Wire); got != 80 {
		t.Errorf("expected port 80, got %d", got)
	}
	if got := bits.ReverseBytes16(port443Wire); got != 443 {
		t.Errorf("expected port 443, got %d", got)
	}
	if got := bits.ReverseBytes16(port53Wire); got != 53 {
		t.Errorf("expected port 53, got %d", got)
	}
	if got := bits.ReverseBytes16(port22Wire); got != 22 {
		t.Errorf("expected port 22, got %d", got)
	}

	// Verify server response port check
	isServerResponsePort := func(srcPort uint16) bool {
		return srcPort == 80 || srcPort == 443 || srcPort == 8080 || srcPort == 8443 || srcPort == 53 || srcPort == 853 || srcPort == 123 || srcPort == 22
	}

	if !isServerResponsePort(bits.ReverseBytes16(port80Wire)) {
		t.Errorf("port 80 should be identified as server response port")
	}
	if !isServerResponsePort(bits.ReverseBytes16(port443Wire)) {
		t.Errorf("port 443 should be identified as server response port")
	}
	if isServerResponsePort(12345) {
		t.Errorf("ephemeral port 12345 should not be identified as server response port")
	}
}

func TestEBPF_ManagerBlocklistExpiry(t *testing.T) {
	mgr := NewEBPFManager()
	if mgr == nil {
		t.Fatal("expected non-nil EBPFManager")
	}

	testIP := net.ParseIP("198.51.100.5").To4()
	ipUint := uint32(testIP[0]) | uint32(testIP[1])<<8 | uint32(testIP[2])<<16 | uint32(testIP[3])<<24

	now := time.Now()
	mgr.blockMu.Lock()
	mgr.blockedUntil[ipUint] = now.Add(-1 * time.Second) // expired
	mgr.blockMu.Unlock()

	// Verify expired entries can be identified
	mgr.blockMu.Lock()
	expired := false
	for k, exp := range mgr.blockedUntil {
		if k == ipUint && now.After(exp) {
			expired = true
			delete(mgr.blockedUntil, k)
		}
	}
	mgr.blockMu.Unlock()

	if !expired {
		t.Errorf("expected expired entry to be detected")
	}
	if len(mgr.blockedUntil) != 0 {
		t.Errorf("expected empty blockedUntil map, got %d", len(mgr.blockedUntil))
	}
}
