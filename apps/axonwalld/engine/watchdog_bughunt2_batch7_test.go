package engine

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newBatch7WatchdogEngine(t *testing.T) *WatchdogEngine {
	t.Helper()
	tempDir := t.TempDir()
	grubenvPath := filepath.Join(tempDir, "grubenv")
	cmdlinePath := filepath.Join(tempDir, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz ro quiet"), 0644); err != nil {
		t.Fatal(err)
	}
	return NewWatchdogEngineCustom(grubenvPath, cmdlinePath)
}

// A-M20: the interface health check must require at least one up
// non-loopback interface. Loopback alone used to pass with N=1 and the
// watchdog then committed bootcount=0 for a network-dead box.
func TestBatch7_VerifyInterfacesRequiresNonLoopback(t *testing.T) {
	engine := newBatch7WatchdogEngine(t)
	res := engine.verifyInterfaces()

	// The verdict must agree with the live interface list: PASS only
	// when a non-loopback interface is up.
	nonLoopbackUp := 0
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if (iface.Flags&net.FlagUp) != 0 && (iface.Flags&net.FlagLoopback) == 0 {
			nonLoopbackUp++
		}
	}
	if nonLoopbackUp == 0 && res.Status != CheckStatusFail {
		t.Fatalf("verifyInterfaces passed with no non-loopback interface up: %+v", res)
	}
	if nonLoopbackUp > 0 && res.Status != CheckStatusPass {
		t.Fatalf("verifyInterfaces failed with %d non-loopback interface(s) up: %+v", nonLoopbackUp, res)
	}
	// The detail must describe the non-loopback count, never the old
	// loopback-inclusive total.
	if !strings.Contains(res.Detail, "non-loopback") {
		t.Fatalf("verifyInterfaces detail does not count non-loopback interfaces: %q", res.Detail)
	}
}
