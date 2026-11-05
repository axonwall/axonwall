package engine

import (
	"encoding/binary"
	"net"
	"os/exec"
	"syscall"
	"testing"
)

// A-L2 / A-L3 regression (Batch 7): the satellite used to report
// success for network changes that never happened — ConfigureInterface
// swallowed a failed `ip` fallback, and AddRoute silently dropped a
// route device that did not resolve, installing the route with no
// device binding.
//
// A-L2 discriminates end-to-end in this sandbox (pre-fix it logs
// success and returns nil). A-L3 does not discriminate end-to-end
// here: the sandbox lacks CAP_NET_ADMIN, so a real route add fails
// with EPERM before the binding question is reached, and the `ip`
// fallback then fails on the unknown device — pre-fix AddRoute also
// errors, just for the wrong reason. On a real box (where netlink
// works) pre-fix AddRoute installs the route with no binding and
// returns nil. The discriminating A-L3 regression test is therefore
// at the message-builder level, following the Batch 6 A-L1
// precedent: buildRouteNetlinkMessage must refuse an unresolvable
// device and must bind a resolvable one (RTA_OIF carrying its
// ifindex). A rejected real ruleset still needs live-box
// verification.

func TestBatch7ConfigureInterfaceFailsWhenBothAddPathsFail(t *testing.T) {
	e := &EdgeNetworkEngine{SysClassNetDir: t.TempDir()}
	err := e.ConfigureInterface(EdgeInterfaceSpec{
		Name:    "lan",
		Device:  "eth99missing",
		Address: "10.0.0.5/24",
		Enabled: true,
	})
	if err == nil {
		t.Fatal("configuring an address on a nonexistent device must fail when both netlink and the ip fallback fail")
	}
}

func TestBatch7AddRouteFailsForUnknownDevice(t *testing.T) {
	e := NewEdgeNetworkEngine()
	// 203.0.113.0/24 is TEST-NET-3 documentation space; the cleanup
	// is belt-and-braces for a pre-fix run on a box where netlink
	// works (there the route would install without a binding).
	t.Cleanup(func() {
		_ = exec.Command("ip", "route", "del", "203.0.113.0/24", "via", "127.0.0.1").Run()
	})
	err := e.AddRoute(EdgeRouteSpec{
		Destination: "203.0.113.0/24",
		Gateway:     "127.0.0.1",
		Device:      "eth99missing",
	})
	if err == nil {
		t.Fatal("a route naming a nonexistent device must fail, not install without a device binding")
	}
}

// routeMessageOIF scans a serialized RTM_NEWROUTE message for the
// RTA_OIF attribute and returns its ifindex and whether it was
// present. Netlink attributes are 4-byte aligned: length (2),
// type (2), payload, padded to 4.
func routeMessageOIF(t *testing.T, msg []byte) (uint32, bool) {
	t.Helper()
	if len(msg) < 28 {
		t.Fatalf("route message too short: %d bytes", len(msg))
	}
	off := 28
	for off+4 <= len(msg) {
		attrLen := int(binary.NativeEndian.Uint16(msg[off : off+2]))
		attrType := binary.NativeEndian.Uint16(msg[off+2 : off+4])
		if attrLen < 4 || off+attrLen > len(msg) {
			t.Fatalf("malformed route attribute at offset %d (len %d)", off, attrLen)
		}
		if attrType == syscall.RTA_OIF {
			if attrLen != 8 {
				t.Fatalf("RTA_OIF attribute has unexpected length %d", attrLen)
			}
			return binary.NativeEndian.Uint32(msg[off+4 : off+8]), true
		}
		off += (attrLen + 3) &^ 3
	}
	return 0, false
}

func TestBatch7RouteMessageRejectsUnknownDevice(t *testing.T) {
	if _, err := buildRouteNetlinkMessage(EdgeRouteSpec{
		Destination: "203.0.113.0/24",
		Gateway:     "127.0.0.1",
		Device:      "eth99missing",
	}); err == nil {
		t.Fatal("building a route message for a nonexistent device must fail, not emit a message with no device binding")
	}
}

func TestBatch7RouteMessageBindsExistingDevice(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("loopback interface must exist for this test: %v", err)
	}
	msg, err := buildRouteNetlinkMessage(EdgeRouteSpec{
		Destination: "203.0.113.0/24",
		Gateway:     "127.0.0.1",
		Device:      "lo",
	})
	if err != nil {
		t.Fatalf("building a route message for an existing device must succeed: %v", err)
	}
	oif, ok := routeMessageOIF(t, msg)
	if !ok {
		t.Fatal("route message for device lo carries no RTA_OIF attribute")
	}
	if int(oif) != lo.Index {
		t.Fatalf("RTA_OIF is %d, want loopback ifindex %d", oif, lo.Index)
	}
}

func TestBatch7RouteMessageWithoutDeviceHasNoOIF(t *testing.T) {
	msg, err := buildRouteNetlinkMessage(EdgeRouteSpec{
		Destination: "203.0.113.0/24",
		Gateway:     "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("building a device-less route message must succeed: %v", err)
	}
	if oif, ok := routeMessageOIF(t, msg); ok {
		t.Fatalf("device-less route message must not carry RTA_OIF, got %d", oif)
	}
}
