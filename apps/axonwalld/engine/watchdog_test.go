package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWatchdogDetectionAndVerification(t *testing.T) {
	tempDir := t.TempDir()
	grubenvPath := filepath.Join(tempDir, "grubenv")
	cmdlinePath := filepath.Join(tempDir, "cmdline")

	// 1. Setup mock cmdline with Slot B
	if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz root=LABEL=axon_root_b ro quiet slot=B"), 0644); err != nil {
		t.Fatalf("Failed to write mock cmdline: %v", err)
	}

	// 2. Setup mock grubenv with bootcount=1, bootlimit=3
	mockGrubenv := "# GRUB Environment Block\nactive_slot=B\nbootcount=1\nbootlimit=3\n"
	for len(mockGrubenv) < 1024 {
		mockGrubenv += "#"
	}
	if err := os.WriteFile(grubenvPath, []byte(mockGrubenv), 0644); err != nil {
		t.Fatalf("Failed to write mock grubenv: %v", err)
	}

	engine := NewWatchdogEngineCustom(grubenvPath, cmdlinePath)
	// The production probes inspect the live host (interfaces, the nft
	// ruleset, the control-plane socket) and cannot pass off-appliance;
	// stub them so this test exercises the verification-sequence logic.
	passCheck := func(name string) func() HealthCheckResult {
		return func() HealthCheckResult {
			return HealthCheckResult{Name: name, Status: CheckStatusPass, Detail: "stubbed"}
		}
	}
	engine.checkInterfaces = passCheck("Network Interface Initialization")
	engine.checkNftables = passCheck("Atomic nftables kernel baseline")
	engine.checkControlPlane = passCheck("Control plane and management quorum")
	status := engine.GetStatus()

	if status.ActiveSlot != "B" {
		t.Errorf("Expected ActiveSlot B, got %s", status.ActiveSlot)
	}
	if status.InactiveSlot != "A" {
		t.Errorf("Expected InactiveSlot A, got %s", status.InactiveSlot)
	}
	if status.BootCount != 1 {
		t.Errorf("Expected BootCount 1, got %d", status.BootCount)
	}
	if status.BootLimit != 3 {
		t.Errorf("Expected BootLimit 3, got %d", status.BootLimit)
	}

	// 3. Test verification sequence
	engine.runVerificationSequence()
	verifiedStatus := engine.GetStatus()

	if len(verifiedStatus.Checks) != 3 {
		t.Errorf("Expected 3 health checks, got %d", len(verifiedStatus.Checks))
	}
	if !verifiedStatus.HealthVerified {
		t.Errorf("Expected HealthVerified to be true, got false")
	}
	if verifiedStatus.BootCount != 0 {
		t.Errorf("Expected BootCount to be reset to 0, got %d", verifiedStatus.BootCount)
	}

	// 4. Test ActivateSlot to A
	if err := engine.ActivateSlot("A"); err != nil {
		t.Fatalf("ActivateSlot failed: %v", err)
	}

	envVars := engine.readGrubEnvInternal()
	if envVars["active_slot"] != "A" {
		t.Errorf("Expected active_slot in grubenv to be A, got %s", envVars["active_slot"])
	}
	if envVars["bootcount"] != "0" {
		t.Errorf("Expected bootcount in grubenv to be 0, got %s", envVars["bootcount"])
	}

	// 5. Test TriggerRollback
	if err := engine.TriggerRollback(); err != nil {
		t.Fatalf("TriggerRollback failed: %v", err)
	}
}

func TestWatchdogSlotVersionUpdate(t *testing.T) {
	tempDir := t.TempDir()
	grubenvPath := filepath.Join(tempDir, "grubenv")
	cmdlinePath := filepath.Join(tempDir, "cmdline")

	// Setup mock cmdline with Slot A active
	if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz root=LABEL=axon_root_a ro quiet slot=A"), 0644); err != nil {
		t.Fatalf("Failed to write mock cmdline: %v", err)
	}

	mockGrubenv := "# GRUB Environment Block\nactive_slot=A\nbootcount=0\nbootlimit=3\n"
	for len(mockGrubenv) < 1024 {
		mockGrubenv += "#"
	}
	if err := os.WriteFile(grubenvPath, []byte(mockGrubenv), 0644); err != nil {
		t.Fatalf("Failed to write mock grubenv: %v", err)
	}

	engine := NewWatchdogEngineCustom(grubenvPath, cmdlinePath)
	stubUpdater := filepath.Join(tempDir, "axonwall-update")
	if err := os.WriteFile(stubUpdater, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("Failed to write stub updater: %v", err)
	}
	engine.updaterPaths = []string{stubUpdater}
	status := engine.GetStatus()

	if status.ActiveSlot != "A" {
		t.Fatalf("Expected ActiveSlot A, got %s", status.ActiveSlot)
	}
	initialSlotA := status.SlotAVersion
	initialSlotB := status.SlotBVersion

	// Apply firmware update to standby Slot B with version "0.6.0"
	msg, err := engine.ApplyFirmwareUpdate("B", "0.6.0")
	if err != nil {
		t.Fatalf("ApplyFirmwareUpdate failed: %v", err)
	}
	if msg == "" {
		t.Errorf("Expected non-empty success message")
	}

	updatedStatus := engine.GetStatus()
	if updatedStatus.SlotBVersion != "0.6.0" {
		t.Errorf("Expected SlotBVersion 0.6.0, got %s", updatedStatus.SlotBVersion)
	}
	if updatedStatus.SlotAVersion != initialSlotA {
		t.Errorf("Expected SlotAVersion %s to remain unchanged, got %s", initialSlotA, updatedStatus.SlotAVersion)
	}

	// Verify persistence: Instantiate a new WatchdogEngine pointing to same temp directory
	engine2 := NewWatchdogEngineCustom(grubenvPath, cmdlinePath)
	status2 := engine2.GetStatus()
	if status2.SlotBVersion != "0.6.0" {
		t.Errorf("Expected persisted SlotBVersion 0.6.0 on new engine instance, got %s", status2.SlotBVersion)
	}
	_ = initialSlotB
}

// ApplyFirmwareUpdate must not claim success -- or arm the target slot --
// when the updater fails or is missing entirely (regression test for the
// previous behavior of logging a "warning" and reporting a flash that
// never happened).
func TestWatchdogApplyFirmwareUpdateHonestFailure(t *testing.T) {
	setup := func(t *testing.T) (*WatchdogEngine, string) {
		tempDir := t.TempDir()
		grubenvPath := filepath.Join(tempDir, "grubenv")
		cmdlinePath := filepath.Join(tempDir, "cmdline")
		if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz root=LABEL=axon_root_a ro quiet slot=A"), 0644); err != nil {
			t.Fatalf("write cmdline: %v", err)
		}
		mockGrubenv := "# GRUB Environment Block\nactive_slot=A\nbootcount=0\nbootlimit=3\n"
		for len(mockGrubenv) < 1024 {
			mockGrubenv += "#"
		}
		if err := os.WriteFile(grubenvPath, []byte(mockGrubenv), 0644); err != nil {
			t.Fatalf("write grubenv: %v", err)
		}
		return NewWatchdogEngineCustom(grubenvPath, cmdlinePath), grubenvPath
	}

	// Updater present but exits non-zero.
	engine, grubenvPath := setup(t)
	failUpdater := filepath.Join(t.TempDir(), "axonwall-update")
	if err := os.WriteFile(failUpdater, []byte("#!/bin/sh\necho boom >&2\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	engine.updaterPaths = []string{failUpdater}
	slotBBefore := engine.GetStatus().SlotBVersion
	if _, err := engine.ApplyFirmwareUpdate("B", "0.6.0"); err == nil {
		t.Error("failing updater: expected error, got success")
	}
	if got := engine.GetStatus().SlotBVersion; got != slotBBefore {
		t.Errorf("failing updater: SlotBVersion changed %q -> %q despite the failed flash", slotBBefore, got)
	}
	if env := engine.readGrubEnvInternal(); env["active_slot"] != "A" {
		t.Errorf("failing updater: grubenv active_slot armed to %q despite the failed flash", env["active_slot"])
	}
	_ = grubenvPath

	// Updater missing entirely.
	engine2, _ := setup(t)
	engine2.updaterPaths = []string{filepath.Join(t.TempDir(), "does-not-exist")}
	if _, err := engine2.ApplyFirmwareUpdate("B", "0.6.0"); err == nil {
		t.Error("missing updater: expected error, got success")
	}
}

func TestWatchdogAccurateSlotVersionsPreserved(t *testing.T) {
	tempDir := t.TempDir()
	grubenvPath := filepath.Join(tempDir, "grubenv")
	cmdlinePath := filepath.Join(tempDir, "cmdline")
	slotVersionsPath := filepath.Join(tempDir, "slot_versions.json")

	// 1. Initial boot on Slot A
	if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz root=LABEL=axon_root_a ro quiet slot=A"), 0644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	mockGrubenv := "# GRUB Environment Block\nactive_slot=A\nbootcount=0\nbootlimit=3\n"
	for len(mockGrubenv) < 1024 {
		mockGrubenv += "#"
	}
	if err := os.WriteFile(grubenvPath, []byte(mockGrubenv), 0644); err != nil {
		t.Fatalf("write grubenv: %v", err)
	}

	engine := NewWatchdogEngineCustom(grubenvPath, cmdlinePath)
	engine.slotVersionsPath = slotVersionsPath
	engine.readInstalledVer = func() string { return "0.8.12" }
	stubUpdater := filepath.Join(tempDir, "axonwall-update")
	if err := os.WriteFile(stubUpdater, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write stub updater: %v", err)
	}
	engine.updaterPaths = []string{stubUpdater}

	mockDisk := map[string]string{
		"A": "0.8.12",
		"B": "0.8.12",
	}
	engine.readSlotDiskVersion = func(slot string) string {
		return mockDisk[slot]
	}

	// Update slot B to 0.8.13
	if _, err := engine.ApplyFirmwareUpdate("B", "0.8.13"); err != nil {
		t.Fatalf("ApplyFirmwareUpdate failed: %v", err)
	}
	mockDisk["B"] = "0.8.13"

	status := engine.GetStatus()
	if status.SlotBVersion != "0.8.13" {
		t.Errorf("Expected Slot B version 0.8.13, got %s", status.SlotBVersion)
	}

	// 2. Now simulate reboot into Slot B
	if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz root=LABEL=axon_root_b ro quiet slot=B"), 0644); err != nil {
		t.Fatalf("write rebooted cmdline: %v", err)
	}
	engineRebooted := NewWatchdogEngineCustom(grubenvPath, cmdlinePath)
	engineRebooted.slotVersionsPath = slotVersionsPath
	engineRebooted.readInstalledVer = func() string { return "0.8.13" }
	engineRebooted.readSlotDiskVersion = func(slot string) string {
		if slot == "A" {
			return "0.8.12"
		}
		return "0.8.13"
	}

	statusRebooted := engineRebooted.GetStatus()
	if statusRebooted.ActiveSlot != "B" {
		t.Errorf("Expected ActiveSlot B, got %s", statusRebooted.ActiveSlot)
	}
	if statusRebooted.SlotBVersion != "0.8.13" {
		t.Errorf("Expected Slot B to be 0.8.13, got %s", statusRebooted.SlotBVersion)
	}
}

func TestWatchdogSelfHealsDuplicateSlotVersions(t *testing.T) {
	tempDir := t.TempDir()
	grubenvPath := filepath.Join(tempDir, "grubenv")
	cmdlinePath := filepath.Join(tempDir, "cmdline")
	slotVersionsPath := filepath.Join(tempDir, "slot_versions.json")

	// Corrupted state: both slots are set to 0.8.13
	corrupted := `{"slotA": "0.8.13", "slotB": "0.8.13"}`
	if err := os.WriteFile(slotVersionsPath, []byte(corrupted), 0644); err != nil {
		t.Fatalf("write corrupted slot_versions: %v", err)
	}

	// Boot on Slot B
	if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz root=LABEL=axon_root_b ro quiet slot=B"), 0644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	mockGrubenv := "# GRUB Environment Block\nactive_slot=B\nbootcount=0\nbootlimit=3\n"
	for len(mockGrubenv) < 1024 {
		mockGrubenv += "#"
	}
	if err := os.WriteFile(grubenvPath, []byte(mockGrubenv), 0644); err != nil {
		t.Fatalf("write grubenv: %v", err)
	}

	engine := NewWatchdogEngineCustom(grubenvPath, cmdlinePath)
	engine.slotVersionsPath = slotVersionsPath
	engine.readInstalledVer = func() string { return "0.8.13" }
	// Mock inactive slot A disk inspection returning the real prior version
	engine.readSlotDiskVersion = func(slot string) string {
		if slot == "A" {
			return "0.8.12"
		}
		return "0.8.13"
	}

	status := engine.GetStatus()
	if status.ActiveSlot != "B" {
		t.Errorf("Expected ActiveSlot B, got %s", status.ActiveSlot)
	}
	if status.SlotBVersion != "0.8.13" {
		t.Errorf("Expected Active Slot B to be 0.8.13, got %s", status.SlotBVersion)
	}
	if status.SlotAVersion != "0.8.12" {
		t.Errorf("Expected Inactive Slot A to be self-healed to 0.8.12, got %s", status.SlotAVersion)
	}

	// Verify persisted file was corrected
	a, b := engine.loadSlotVersions()
	if a != "0.8.12" {
		t.Errorf("Expected persisted Slot A to be 0.8.12, got %s", a)
	}
	if b != "0.8.13" {
		t.Errorf("Expected persisted Slot B to be 0.8.13, got %s", b)
	}
}

