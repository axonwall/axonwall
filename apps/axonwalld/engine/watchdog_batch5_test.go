package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// E9 regression: after arming slot B (in-memory ActiveSlot moved to B
// before any reboot), GetStatus must NOT overwrite the staged slot
// B's version with the running version. The running slot comes from
// the kernel cmdline (slot=A here), not from in-memory state.
func TestBatch5GetStatusKeepsStagedSlotVersion(t *testing.T) {
	tempDir := t.TempDir()
	grubenvPath := filepath.Join(tempDir, "grubenv")
	cmdlinePath := filepath.Join(tempDir, "cmdline")
	// The box is still running slot A; slot B is only staged.
	if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz root=LABEL=axon_root_a ro quiet slot=A"), 0644); err != nil {
		t.Fatalf("failed to write mock cmdline: %v", err)
	}
	engine := NewWatchdogEngineCustom(grubenvPath, cmdlinePath)
	engine.readInstalledVer = func() string { return "1.0.0" }
	// Stage the versions through the engine's primary slot-versions
	// file: loadSlotVersions also falls back to the host's
	// /etc/axonwall/slot_versions.json, so a test that only sets
	// in-memory state would be polluted by whatever the host has.
	if err := os.WriteFile(filepath.Join(tempDir, "slot_versions.json"), []byte(`{"slotA": "1.0.0", "slotB": "2.0.0"}`), 0644); err != nil {
		t.Fatalf("failed to write mock slot versions: %v", err)
	}
	// Simulate the post-ActivateSlot("B") state: in-memory slot moved
	// to B, staged version recorded, but no reboot has happened.
	engine.status.InstallMode = "ab"
	engine.status.ActiveSlot = "B"
	engine.status.InactiveSlot = "A"
	engine.status.SlotAVersion = "1.0.0"
	engine.status.SlotBVersion = "2.0.0"

	status := engine.GetStatus()

	if status.SlotBVersion != "2.0.0" {
		t.Errorf("staged slot B version was overwritten: got %q, want %q (running version)", status.SlotBVersion, "2.0.0")
	}
	if status.SlotAVersion != "1.0.0" {
		t.Errorf("running slot A version wrong: got %q, want %q", status.SlotAVersion, "1.0.0")
	}
	if status.OsVersion != "Axonwall OS v1.0.0" {
		t.Errorf("OsVersion should track the running slot A: got %q", status.OsVersion)
	}
}

// The cmdline helper itself: B markers win for B, A markers for A,
// and an unmarked/unreadable cmdline reports "unknown" so callers
// fall back to in-memory state instead of trusting a default.
func TestBatch5DetectRunningSlotFromCmdline(t *testing.T) {
	tempDir := t.TempDir()
	n := 0
	mk := func(content string) string {
		n++
		p := filepath.Join(tempDir, "cmdline-test-"+string(rune('a'+n)))
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write mock cmdline: %v", err)
		}
		return p
	}
	if slot, ok := detectRunningSlotFromCmdline(mk("BOOT_IMAGE=/vmlinuz root=LABEL=axon_root_b ro quiet slot=B")); !ok || slot != "B" {
		t.Errorf("slot=B cmdline: got (%q, %v), want (B, true)", slot, ok)
	}
	if slot, ok := detectRunningSlotFromCmdline(mk("BOOT_IMAGE=/vmlinuz root=LABEL=axon_root_a ro quiet slot=A")); !ok || slot != "A" {
		t.Errorf("slot=A cmdline: got (%q, %v), want (A, true)", slot, ok)
	}
	if slot, ok := detectRunningSlotFromCmdline(mk("BOOT_IMAGE=/vmlinuz ro quiet")); ok || slot != "" {
		t.Errorf("unmarked cmdline: got (%q, %v), want (\"\", false)", slot, ok)
	}
	if slot, ok := detectRunningSlotFromCmdline(filepath.Join(tempDir, "missing")); ok || slot != "" {
		t.Errorf("missing cmdline: got (%q, %v), want (\"\", false)", slot, ok)
	}
}
