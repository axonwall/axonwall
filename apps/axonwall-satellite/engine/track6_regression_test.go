package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTrack6_CloudInitTabIndentedBlockScalarNoPanic(t *testing.T) {
	root := t.TempDir()
	cfg := &EdgeBootConfig{}
	// Under 4-space `content: |`, 3 tabs have visual indent 6 (> 4) but byte length 4 before 'X'.
	// Previously rawLine[stripLen:] panicked with slice bounds out of range [6:4].
	raw := "#cloud-config\n" +
		"write_files:\n" +
		"  - path: /etc/axonwall/tabtest.conf\n" +
		"    content: |\n" +
		"\t\t\tX\n" +
		"\t\t\tline2\n" +
		"    \t\tmixed\n" +
		"axonwall:\n" +
		"  ca_cert: |\n" +
		"\t\tA\n" +
		"\t\tB\n"

	if err := ApplyCloudInitUserData(cfg, raw, root); err != nil {
		t.Fatalf("ApplyCloudInitUserData with tab-indented block scalars failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "etc", "axonwall", "tabtest.conf"))
	if err != nil {
		t.Fatalf("expected tabtest.conf written: %v", err)
	}
	if string(got) != "X\nline2\n\tmixed\n" {
		t.Fatalf("unexpected write_files content: %q", string(got))
	}
	if s := stripLeadingColumns("     \tstraddle", 6); s != " straddle" {
		t.Fatalf("stripLeadingColumns straddle = %q, want %q", s, " straddle")
	}
	caGot, err := os.ReadFile(filepath.Join(root, "etc", "axonwall", "certs", "ca.crt"))
	if err != nil {
		t.Fatalf("expected ca.crt written: %v", err)
	}
	if string(caGot) != "A\nB\n" {
		t.Fatalf("unexpected ca.crt content: %q", string(caGot))
	}
}

func TestTrack6_RollbackNoPreFlushAndRestoresFleetBlocks(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "nft.log")
	bughunt3FakeNft(t, logPath)
	e := bughunt3FleetEngine(t)
	bughunt3StopFleetTimers(t, e)

	// Record an active in-memory/persisted TTL-bounded fleet block.
	if err := e.BlockTarget("198.51.100.77", false, 300); err != nil {
		t.Fatalf("BlockTarget: %v", err)
	}
	// Clear log after initial BlockTarget so we observe only Rollback actions.
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatalf("clear log: %v", err)
	}

	e.mu.Lock()
	e.lastKnownGood = "# fallback ruleset\n"
	e.mu.Unlock()

	if err := e.Rollback(); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	logStr := string(logged)
	if strings.Contains(logStr, "delete table") {
		t.Fatalf("Rollback must not pre-flush table before atomic replace; got nft calls: %q", logStr)
	}
	if !strings.Contains(logStr, "-f ") {
		t.Fatalf("expected Rollback to apply lastKnownGood ruleset; got nft calls: %q", logStr)
	}
	if !strings.Contains(logStr, "add element inet axonwall blocked_ips { 198.51.100.77 }") {
		t.Fatalf("expected Rollback to restore active fleet blocks; got nft calls: %q", logStr)
	}

	// Verify failed Rollback never flushes table either.
	failDir := t.TempDir()
	failLog := filepath.Join(failDir, "fail.log")
	failScript := "#!/bin/sh\necho \"$@\" >> \"$NFT_FAIL_LOG\"\nexit 1\n"
	if err := os.WriteFile(filepath.Join(failDir, "nft"), []byte(failScript), 0o755); err != nil {
		t.Fatalf("write failing nft: %v", err)
	}
	t.Setenv("NFT_FAIL_LOG", failLog)
	t.Setenv("PATH", failDir+":"+os.Getenv("PATH"))

	e.mu.Lock()
	e.fleetBlocks[fleetBlockKey("blocked_ips", "198.51.100.77")].ExpiresAt = time.Now().Add(5 * time.Minute)
	e.mu.Unlock()
	if err := e.Rollback(); err == nil {
		t.Fatalf("expected Rollback to fail when apply fails")
	}
	failLogged, _ := os.ReadFile(failLog)
	if strings.Contains(string(failLogged), "delete table") {
		t.Fatalf("failed Rollback must not delete table: %q", string(failLogged))
	}
}
