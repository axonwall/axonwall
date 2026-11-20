package engine

// Round-3 bug-hunt fix batch 3 (controller MCP/fleet/TUI) regression
// tests: B-H1 (satellite side). Fleet-propagated MCP blackholes used
// to be permanent on satellites — the BLOCK_TARGET envelope carried
// no TTL, BlockTarget inserted set elements with no expiry, and no
// UNBLOCK_TARGET path existed at all. The satellite now records a
// TTL-bounded expiry per block (persisted across restarts), removes
// the element when the TTL lapses, and supports UNBLOCK_TARGET.
//
// These tests run without a kernel nftables table: a fake `nft`
// binary on PATH answers every invocation with exit 0 and records
// its arguments, and the netlink insert path fails fast (no table)
// and falls through to that fake binary.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// bughunt3FakeNft installs a fake `nft` binary that exits 0 for every
// invocation and appends its argv (one line per call) to logPath.
// It returns a cleanup that restores PATH.
func bughunt3FakeNft(t *testing.T, logPath string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\necho \"$@\" >> \"$NFT_LOG\"\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake nft: %v", err)
	}
	t.Setenv("NFT_LOG", logPath)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

func bughunt3FleetEngine(t *testing.T) *NftablesEngine {
	t.Helper()
	e := NewNftablesEngine()
	e.fleetBlocksPath = filepath.Join(t.TempDir(), "fleet-blocks.json")
	return e
}

// bughunt3StopFleetTimers stops every armed expiry timer so a test
// never leaks a goroutine that fires after the test ends.
func bughunt3StopFleetTimers(t *testing.T, e *NftablesEngine) {
	t.Helper()
	t.Cleanup(func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		for _, entry := range e.fleetBlocks {
			if entry.timer != nil {
				entry.timer.Stop()
			}
		}
	})
}

func bughunt3ReadFleetState(t *testing.T, path string) []fleetBlockEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fleet state: %v", err)
	}
	var entries []fleetBlockEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("parse fleet state %q: %v", string(data), err)
	}
	return entries
}

func TestBughunt3BlockTargetPayloadCarriesTtl(t *testing.T) {
	// The payload type lives in package main (not importable here),
	// so this pins the wire contract the hub sends and the satellite
	// parses: an old hub sends no ttlSeconds (0, permanent as
	// before) and a new hub sends one.
	var envelope struct {
		Target     string `json:"target"`
		IsMac      bool   `json:"isMac"`
		TtlSeconds int    `json:"ttlSeconds,omitempty"`
	}
	if err := json.Unmarshal([]byte(`{"target":"198.51.100.7","isMac":false,"ttlSeconds":3600}`), &envelope); err != nil {
		t.Fatalf("unmarshal block payload: %v", err)
	}
	if envelope.TtlSeconds != 3600 {
		t.Fatalf("ttlSeconds = %d, want 3600", envelope.TtlSeconds)
	}
	var oldEnvelope struct {
		TtlSeconds int `json:"ttlSeconds,omitempty"`
	}
	if err := json.Unmarshal([]byte(`{"target":"198.51.100.7","isMac":false}`), &oldEnvelope); err != nil {
		t.Fatalf("unmarshal old block payload: %v", err)
	}
	if oldEnvelope.TtlSeconds != 0 {
		t.Fatalf("old envelope ttlSeconds = %d, want 0 (permanent, as before)", oldEnvelope.TtlSeconds)
	}
}

func TestBughunt3NormalizeBlockTarget(t *testing.T) {
	cases := []struct {
		target  string
		isMac   bool
		wantSet string
	}{
		{"198.51.100.7", false, "blocked_ips"},
		{"2001:db8::1", false, "blocked_ips6"},
		{"198.51.100.0/24", false, "blocked_ips"},
		{"2001:db8::/32", false, "blocked_ips6"},
		{"02:00:00:00:00:05", true, "blocked_macs"},
	}
	for _, tc := range cases {
		got, setName, err := normalizeBlockTarget(tc.target, tc.isMac)
		if err != nil {
			t.Errorf("normalizeBlockTarget(%q, %v): unexpected error: %v", tc.target, tc.isMac, err)
			continue
		}
		if setName != tc.wantSet {
			t.Errorf("normalizeBlockTarget(%q, %v): set = %q, want %q", tc.target, tc.isMac, setName, tc.wantSet)
		}
		if got == "" {
			t.Errorf("normalizeBlockTarget(%q, %v): empty normalized target", tc.target, tc.isMac)
		}
	}
	for _, bad := range []string{"not-an-ip", "198.51.100.7/33", "999.1.1.1"} {
		if _, _, err := normalizeBlockTarget(bad, false); err == nil {
			t.Errorf("normalizeBlockTarget(%q, false): expected error, got nil", bad)
		}
	}
	if _, _, err := normalizeBlockTarget("not-a-mac", true); err == nil {
		t.Errorf("normalizeBlockTarget(not-a-mac, true): expected error, got nil")
	}
}

func TestBughunt3FleetBlockExpiryFiresAndPersists(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "nft.log")
	bughunt3FakeNft(t, logPath)
	e := bughunt3FleetEngine(t)
	bughunt3StopFleetTimers(t, e)

	// B-H1: a block with a 1 s TTL is recorded, persisted, and its
	// element is deleted when the TTL lapses.
	e.mu.Lock()
	e.recordFleetBlockLocked("blocked_ips", "198.51.100.7", false, 1)
	e.mu.Unlock()

	entries := bughunt3ReadFleetState(t, e.fleetBlocksPath)
	if len(entries) != 1 || entries[0].Target != "198.51.100.7" {
		t.Fatalf("persisted fleet blocks = %+v, want one entry for 198.51.100.7", entries)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		e.mu.Lock()
		_, stillThere := e.fleetBlocks[fleetBlockKey("blocked_ips", "198.51.100.7")]
		e.mu.Unlock()
		if !stillThere {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fleet block was not removed after its TTL lapsed (still in map after 5s)")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := bughunt3ReadFleetState(t, e.fleetBlocksPath); len(got) != 0 {
		t.Fatalf("persisted fleet blocks after expiry = %+v, want none", got)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake nft log: %v", err)
	}
	if !strings.Contains(string(logged), "delete element inet axonwall blocked_ips { 198.51.100.7 }") {
		t.Fatalf("fake nft log = %q, want a delete element call for 198.51.100.7", string(logged))
	}
}

func TestBughunt3UnblockTargetRemovesBlock(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "nft.log")
	bughunt3FakeNft(t, logPath)
	e := bughunt3FleetEngine(t)
	bughunt3StopFleetTimers(t, e)

	e.mu.Lock()
	e.recordFleetBlockLocked("blocked_ips", "198.51.100.7", false, 3600)
	e.mu.Unlock()

	if err := e.UnblockTarget("198.51.100.7", false); err != nil {
		t.Fatalf("UnblockTarget: unexpected error: %v", err)
	}
	e.mu.Lock()
	_, stillThere := e.fleetBlocks[fleetBlockKey("blocked_ips", "198.51.100.7")]
	e.mu.Unlock()
	if stillThere {
		t.Fatalf("fleet block still tracked after UnblockTarget")
	}
	if got := bughunt3ReadFleetState(t, e.fleetBlocksPath); len(got) != 0 {
		t.Fatalf("persisted fleet blocks after unblock = %+v, want none", got)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake nft log: %v", err)
	}
	if !strings.Contains(string(logged), "delete element inet axonwall blocked_ips { 198.51.100.7 }") {
		t.Fatalf("fake nft log = %q, want a delete element call for 198.51.100.7", string(logged))
	}

	// Idempotent: unblocking a target that is not blocked succeeds.
	if err := e.UnblockTarget("198.51.100.7", false); err != nil {
		t.Fatalf("second UnblockTarget: unexpected error: %v", err)
	}
	// Invalid target: rejected before any kernel call.
	if err := e.UnblockTarget("not-an-ip", false); err == nil {
		t.Fatalf("UnblockTarget(not-an-ip): expected error, got nil")
	}
}

func TestBughunt3PermanentReblockCancelsExpiry(t *testing.T) {
	e := bughunt3FleetEngine(t)
	bughunt3StopFleetTimers(t, e)

	e.mu.Lock()
	e.recordFleetBlockLocked("blocked_ips", "198.51.100.7", false, 3600)
	e.recordFleetBlockLocked("blocked_ips", "198.51.100.7", false, 0)
	_, stillThere := e.fleetBlocks[fleetBlockKey("blocked_ips", "198.51.100.7")]
	e.mu.Unlock()
	if stillThere {
		t.Fatalf("permanent re-block left the expiry entry in place")
	}
	if got := bughunt3ReadFleetState(t, e.fleetBlocksPath); len(got) != 0 {
		t.Fatalf("persisted fleet blocks after permanent re-block = %+v, want none", got)
	}
}

func TestBughunt3RestoreFleetBlocks(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "nft.log")
	bughunt3FakeNft(t, logPath)
	e := bughunt3FleetEngine(t)
	bughunt3StopFleetTimers(t, e)

	// One unexpired block (re-inserted, timer re-armed) and one
	// already-expired block (removed, dropped).
	now := time.Now()
	persisted := []fleetBlockEntry{
		{Target: "198.51.100.7", IsMac: false, SetName: "blocked_ips", ExpiresAt: now.Add(time.Hour)},
		{Target: "198.51.100.8", IsMac: false, SetName: "blocked_ips", ExpiresAt: now.Add(-time.Hour)},
	}
	data, err := json.Marshal(persisted)
	if err != nil {
		t.Fatalf("marshal persisted blocks: %v", err)
	}
	if err := os.WriteFile(e.fleetBlocksPath, data, 0o600); err != nil {
		t.Fatalf("write persisted blocks: %v", err)
	}

	e.RestoreFleetBlocks()

	e.mu.Lock()
	_, live := e.fleetBlocks[fleetBlockKey("blocked_ips", "198.51.100.7")]
	_, expired := e.fleetBlocks[fleetBlockKey("blocked_ips", "198.51.100.8")]
	e.mu.Unlock()
	if !live {
		t.Fatalf("unexpired persisted block was not restored")
	}
	if expired {
		t.Fatalf("already-expired persisted block was kept")
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake nft log: %v", err)
	}
	// The unexpired block is re-inserted (add element) and the
	// expired one is deleted.
	if !strings.Contains(string(logged), "add element inet axonwall blocked_ips { 198.51.100.7 }") {
		t.Fatalf("fake nft log = %q, want an add element call re-inserting 198.51.100.7", string(logged))
	}
	if !strings.Contains(string(logged), "delete element inet axonwall blocked_ips { 198.51.100.8 }") {
		t.Fatalf("fake nft log = %q, want a delete element call removing expired 198.51.100.8", string(logged))
	}
}
