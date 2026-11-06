package engine

import (
	"encoding/binary"
	"syscall"
	"testing"
)

// B2-M7: routes removed from DesiredState are deleted from the
// satellite kernel via RTM_DELROUTE instead of lingering forever.
// These pin the delete-message builder: message type, flags (no
// CREATE/REPLACE — a delete must never create), and the device
// rule (a missing device is tolerated for a delete, unlike an
// add, because the route is gone with its device).
func TestBatch2RouteDeleteMessageTypeAndFlags(t *testing.T) {
	msg, err := buildRouteDeleteNetlinkMessage(EdgeRouteSpec{
		Destination: "203.0.113.0/24",
		Gateway:     "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("building a route delete message must succeed: %v", err)
	}
	msgType := binary.NativeEndian.Uint16(msg[4:6])
	if msgType != uint16(syscall.RTM_DELROUTE) {
		t.Fatalf("delete message type is %d, want RTM_DELROUTE (%d)", msgType, syscall.RTM_DELROUTE)
	}
	flags := binary.NativeEndian.Uint16(msg[6:8])
	want := uint16(syscall.NLM_F_REQUEST | syscall.NLM_F_ACK)
	if flags != want {
		t.Fatalf("delete message flags are %#x, want %#x (REQUEST|ACK, no CREATE/REPLACE)", flags, want)
	}
}

func TestBatch2RouteDeleteMessageToleratesMissingDevice(t *testing.T) {
	msg, err := buildRouteDeleteNetlinkMessage(EdgeRouteSpec{
		Destination: "203.0.113.0/24",
		Gateway:     "127.0.0.1",
		Device:      "eth99missing",
	})
	if err != nil {
		t.Fatalf("a delete for a missing device must succeed (the route is gone with it): %v", err)
	}
	if oif, ok := routeMessageOIF(t, msg); ok {
		t.Fatalf("delete message for a missing device must not carry RTA_OIF, got %d", oif)
	}
}

func TestBatch2RouteAddMessageUnchanged(t *testing.T) {
	// The shared builder must not have changed the add path:
	// RTM_NEWROUTE with CREATE|REPLACE|ACK, and a missing device
	// still fails (A-L3).
	msg, err := buildRouteNetlinkMessage(EdgeRouteSpec{
		Destination: "203.0.113.0/24",
		Gateway:     "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("building a route add message must succeed: %v", err)
	}
	if msgType := binary.NativeEndian.Uint16(msg[4:6]); msgType != uint16(syscall.RTM_NEWROUTE) {
		t.Fatalf("add message type is %d, want RTM_NEWROUTE (%d)", msgType, syscall.RTM_NEWROUTE)
	}
	flags := binary.NativeEndian.Uint16(msg[6:8])
	want := uint16(syscall.NLM_F_REQUEST | syscall.NLM_F_CREATE | syscall.NLM_F_REPLACE | syscall.NLM_F_ACK)
	if flags != want {
		t.Fatalf("add message flags are %#x, want %#x", flags, want)
	}
	if _, err := buildRouteNetlinkMessage(EdgeRouteSpec{
		Destination: "203.0.113.0/24",
		Gateway:     "127.0.0.1",
		Device:      "eth99missing",
	}); err == nil {
		t.Fatal("building an add message for a nonexistent device must still fail")
	}
}
