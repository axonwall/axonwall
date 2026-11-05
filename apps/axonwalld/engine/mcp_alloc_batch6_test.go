package engine

import (
	"fmt"
	"testing"
)

// A-L5 regression: tc class / policy-routing table IDs must be the
// lowest free ID by scanning live leases, never a blind wrap. Pre-fix,
// the shared counter wrapped 9000 -> 500 without an in-use check, so
// a new lease could reuse a live lease's ID and reverting either one
// deleted both leases' enforcement.
func TestBatch6AllocLowestFreeID(t *testing.T) {
	mgr := newTestTrafficManager(t)
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	mgr.leases["a"] = &McpTacticalLease{ID: "a", ClassID: 500}
	mgr.leases["b"] = &McpTacticalLease{ID: "b", ClassID: 501}
	mgr.leases["c"] = &McpTacticalLease{ID: "c", ClassID: 503}

	id, err := mgr.allocClassIDLocked()
	if err != nil {
		t.Fatalf("alloc failed: %v", err)
	}
	if id != 502 {
		t.Fatalf("expected lowest free ID 502, got %d", id)
	}
	// The first allocation is reserved: a second allocation must not
	// hand out the same ID before the first lease is inserted.
	id2, err := mgr.allocClassIDLocked()
	if err != nil {
		t.Fatalf("second alloc failed: %v", err)
	}
	if id2 != 504 {
		t.Fatalf("expected second allocation 504 (502 reserved), got %d", id2)
	}
	// Inserting the first lease releases its reservation, and the ID
	// is then covered by the leases map, not handed out again.
	mgr.leases["d"] = &McpTacticalLease{ID: "d", ClassID: 502}
	mgr.releaseClassIDLocked(502)
	id3, err := mgr.allocClassIDLocked()
	if err != nil {
		t.Fatalf("third alloc failed: %v", err)
	}
	if id3 != 505 {
		t.Fatalf("expected third allocation 505, got %d", id3)
	}
}

func TestBatch6AllocExhaustedPoolErrors(t *testing.T) {
	mgr := newTestTrafficManager(t)
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	for id := mcpClassIDMin; id <= mcpClassIDMax; id++ {
		key := fmt.Sprintf("lease-%d", id)
		mgr.leases[key] = &McpTacticalLease{ID: key, ClassID: id}
	}
	if _, err := mgr.allocClassIDLocked(); err == nil {
		t.Fatal("expected an error when the whole ID pool is in use, got a reusable ID")
	}
}

func TestBatch6AllocSkipsReservedIDs(t *testing.T) {
	mgr := newTestTrafficManager(t)
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	// Simulate a lease deleted but still in kernel cleanup: its ID
	// stays reserved and must not be recycled yet.
	mgr.reserveClassIDLocked(500)
	id, err := mgr.allocClassIDLocked()
	if err != nil {
		t.Fatalf("alloc failed: %v", err)
	}
	if id != 501 {
		t.Fatalf("expected allocation to skip reserved ID 500, got %d", id)
	}
	mgr.releaseClassIDLocked(500)
	id2, err := mgr.allocClassIDLocked()
	if err != nil {
		t.Fatalf("alloc after release failed: %v", err)
	}
	if id2 != 500 {
		t.Fatalf("expected released ID 500 to be allocatable again, got %d", id2)
	}
}
