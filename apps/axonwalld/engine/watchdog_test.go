package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestWatchdogZbmDetectionAndOperations(t *testing.T) {
	tempDir := t.TempDir()
	grubenvPath := filepath.Join(tempDir, "grubenv")
	cmdlinePath := filepath.Join(tempDir, "cmdline")

	// 1. Setup mock cmdline with ZBM root-on-zfs
	if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz zfs=zroot/ROOT/axonwall-0.11.30 root=zfs:zroot/ROOT/axonwall-0.11.30 ro quiet"), 0644); err != nil {
		t.Fatalf("Failed to write mock cmdline: %v", err)
	}

	engine := NewWatchdogEngineCustom(grubenvPath, cmdlinePath)
	engine.readInstalledVer = func() string { return "0.11.30" }

	// Track ZFS/Zpool command invocations
	var executedCommands [][]string
	engine.runZfsCmd = func(args ...string) ([]byte, error) {
		executedCommands = append(executedCommands, append([]string{"zfs"}, args...))
		cmdStr := strings.Join(args, " ")
		if strings.HasPrefix(cmdStr, "list") && strings.Contains(cmdStr, "filesystem") {
			out := "zroot/ROOT\t10G\tThu Oct 28 10:00 2026\n" +
				"zroot/ROOT/axonwall-0.11.30\t5G\tThu Oct 28 10:05 2026\n" +
				"zroot/ROOT/axonwall-0.11.29\t4G\tWed Oct 27 10:05 2026\n"
			return []byte(out), nil
		}
		if strings.HasPrefix(cmdStr, "list") && strings.Contains(cmdStr, "snapshot") {
			out := "zroot/ROOT/axonwall-0.11.30@snap1\nzroot/ROOT/axonwall-0.11.30@snap2\n"
			return []byte(out), nil
		}
		if strings.HasPrefix(cmdStr, "get") && strings.Contains(cmdStr, "org.axonwall:topology") {
			return []byte("raidz2\n"), nil
		}
		if strings.HasPrefix(cmdStr, "get") && strings.Contains(cmdStr, "org.axonwall:bootcount") {
			return []byte("1\n"), nil
		}
		if strings.HasPrefix(cmdStr, "get") && strings.Contains(cmdStr, "org.axonwall:bootlimit") {
			return []byte("3\n"), nil
		}
		if strings.HasPrefix(cmdStr, "get") && strings.Contains(cmdStr, "origin") {
			return []byte("zroot/ROOT/axonwall-0.11.29@pre-upgrade\n"), nil
		}
		if strings.HasPrefix(cmdStr, "get") && strings.Contains(cmdStr, "org.axonwall:fallback_be") {
			// E4: the fallback is the last verified active BE
			// (runVerificationSequence sets it to the active root
			// device), not the standby BE step 6 deletes — a
			// standby BE that is the fallback can no longer be
			// deleted, so the fixture must not name it here. The
			// refusal itself is covered by
			// TestBatch7DeleteFallbackBootEnvironmentRefused.
			return []byte("zroot/ROOT/axonwall-0.11.30\n"), nil
		}
		return []byte("ok"), nil
	}

	engine.runZpoolCmd = func(args ...string) ([]byte, error) {
		executedCommands = append(executedCommands, append([]string{"zpool"}, args...))
		cmdStr := strings.Join(args, " ")
		if strings.HasPrefix(cmdStr, "get") && strings.Contains(cmdStr, "bootfs") {
			return []byte("zroot/ROOT/axonwall-0.11.30\n"), nil
		}
		if strings.HasPrefix(cmdStr, "list") && strings.Contains(cmdStr, "health") {
			return []byte("ONLINE\n"), nil
		}
		return []byte("ok"), nil
	}

	// Re-run detection with mocked ZFS commands
	engine.detectInitialState()
	status := engine.GetStatus()

	if status.InstallMode != "zbm" {
		t.Fatalf("Expected InstallMode 'zbm', got %q", status.InstallMode)
	}
	if status.ZbmPoolName != "zroot" {
		t.Errorf("Expected ZbmPoolName 'zroot', got %q", status.ZbmPoolName)
	}
	if status.ZbmPoolTopology != "raidz2" {
		t.Errorf("Expected ZbmPoolTopology 'raidz2', got %q", status.ZbmPoolTopology)
	}
	if status.ZbmPoolHealth != "ONLINE" {
		t.Errorf("Expected ZbmPoolHealth 'ONLINE', got %q", status.ZbmPoolHealth)
	}
	if status.BootCount != 1 {
		t.Errorf("Expected BootCount 1, got %d", status.BootCount)
	}
	if len(status.BootEnvironments) != 2 {
		t.Fatalf("Expected 2 Boot Environments, got %d", len(status.BootEnvironments))
	}

	be0 := status.BootEnvironments[0]
	if be0.Name != "axonwall-0.11.30" {
		t.Errorf("Expected BE[0] name 'axonwall-0.11.30', got %q", be0.Name)
	}
	if be0.Version != "0.11.30" {
		t.Errorf("Expected BE[0] version '0.11.30', got %q", be0.Version)
	}
	if !be0.ActiveNext {
		t.Errorf("Expected BE[0] ActiveNext to be true")
	}
	if len(be0.Snapshots) != 2 {
		t.Errorf("Expected 2 snapshots for BE[0], got %d", len(be0.Snapshots))
	}

	// 2. Test Snapshot Creation
	snap, err := engine.CreateBootEnvironmentSnapshot("axonwall-0.11.30", "test-manual")
	if err != nil {
		t.Fatalf("CreateBootEnvironmentSnapshot failed: %v", err)
	}
	if snap != "zroot/ROOT/axonwall-0.11.30@test-manual" {
		t.Errorf("Unexpected snapshot name: %s", snap)
	}

	// 3. Test Snapshot Cloning to New BE
	cloned, err := engine.CloneSnapshotToBootEnvironment(snap, "axonwall-0.11.31")
	if err != nil {
		t.Fatalf("CloneSnapshotToBootEnvironment failed: %v", err)
	}
	if cloned != "zroot/ROOT/axonwall-0.11.31" {
		t.Errorf("Unexpected cloned dataset: %s", cloned)
	}

	// 4. Test BE Activation
	if err := engine.ActivateBootEnvironment("axonwall-0.11.31"); err != nil {
		t.Fatalf("ActivateBootEnvironment failed: %v", err)
	}

	// 5. Test BE Deletion Guard
	be0.ActiveNow = true
	engine.status.BootEnvironments[0].ActiveNow = true
	if err := engine.DeleteBootEnvironment("axonwall-0.11.30"); err == nil {
		t.Errorf("Expected error deleting currently running BE, got nil")
	}

	// 6. Test Successful Deletion of Inactive BE
	if err := engine.DeleteBootEnvironment("axonwall-0.11.29"); err != nil {
		t.Fatalf("DeleteBootEnvironment for standby BE failed: %v", err)
	}

	// 7. Test Verification Sequence promoting clone and resetting bootcount
	engine.checkInterfaces = func() HealthCheckResult {
		return HealthCheckResult{Name: "ifaces", Status: CheckStatusPass}
	}
	engine.checkNftables = func() HealthCheckResult {
		return HealthCheckResult{Name: "nft", Status: CheckStatusPass}
	}
	engine.checkControlPlane = func() HealthCheckResult {
		return HealthCheckResult{Name: "cp", Status: CheckStatusPass}
	}
	engine.status.ActiveRootDevice = "zroot/ROOT/axonwall-0.11.30"
	engine.runVerificationSequence()

	vStatus := engine.GetStatus()
	if !vStatus.HealthVerified {
		t.Errorf("Expected HealthVerified to be true")
	}
	if vStatus.BootCount != 0 {
		t.Errorf("Expected BootCount reset to 0, got %d", vStatus.BootCount)
	}

	// Verify promote was issued for clone
	promoted := false
	for _, cmd := range executedCommands {
		if len(cmd) >= 3 && cmd[0] == "zfs" && cmd[1] == "promote" && cmd[2] == "zroot/ROOT/axonwall-0.11.30" {
			promoted = true
			break
		}
	}
	if !promoted {
		t.Errorf("Expected 'zfs promote zroot/ROOT/axonwall-0.11.30' to have been called")
	}

	// 8. Test Rollback to fallback BE
	if err := engine.TriggerRollback(); err != nil {
		t.Fatalf("TriggerRollback failed in ZBM mode: %v", err)
	}

	// 9. Test ApplyFirmwareUpdate with mock updater
	mockUpdater := filepath.Join(tempDir, "axonwall-update")
	updaterScript := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(mockUpdater, []byte(updaterScript), 0755); err != nil {
		t.Fatalf("write mock updater: %v", err)
	}
	engine.updaterPaths = []string{mockUpdater}

	msg, err := engine.ApplyFirmwareUpdate("B", "0.12.0")
	if err != nil {
		t.Fatalf("ApplyFirmwareUpdate failed: %v", err)
	}
	if !strings.Contains(msg, "ZFS Boot Environment") {
		t.Errorf("Expected update success message mentioning ZFS Boot Environment, got %q", msg)
	}
}

func TestBtrfsSnapperModeAndSnapshots(t *testing.T) {
	tempDir := t.TempDir()
	grubEnvPath := filepath.Join(tempDir, "grubenv")
	cmdlinePath := filepath.Join(tempDir, "cmdline")
	snapsDir := filepath.Join(tempDir, "snapshots")

	if err := os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/@/boot/vmlinuz root=LABEL=axon_btrfs rootflags=subvol=@ ro rootfstype=btrfs quiet\n"), 0644); err != nil {
		t.Fatalf("write mock cmdline: %v", err)
	}
	if detected := detectInstallModeCustom(cmdlinePath); detected != "btrfs" {
		t.Fatalf("expected detectInstallModeCustom='btrfs', got %q", detected)
	}

	// Build bootable snapshot #1 XML + boot dir and non-bootable #2 XML
	snap1Boot := filepath.Join(snapsDir, "1", "snapshot", "boot")
	if err := os.MkdirAll(snap1Boot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snap1Boot, "vmlinuz"), []byte("vmlinuz"), 0644); err != nil {
		t.Fatal(err)
	}
	xml1 := `<?xml version="1.0"?><snapshot><type>single</type><num>1</num><date>2026-11-21 08:00:00</date><cleanup>number</cleanup><description>Axonwall Factory Initial</description><userdata><key>important</key><value>yes</value></userdata></snapshot>`
	if err := os.WriteFile(filepath.Join(snapsDir, "1", "info.xml"), []byte(xml1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(snapsDir, "2"), 0755); err != nil {
		t.Fatal(err)
	}
	xml2 := `<?xml version="1.0"?><snapshot><type>pre</type><num>2</num><date>2026-11-21 09:00:00</date><cleanup>number</cleanup><description>Pre-update, Axonwall v0.12.5</description></snapshot>`
	if err := os.WriteFile(filepath.Join(snapsDir, "2", "info.xml"), []byte(xml2), 0644); err != nil {
		t.Fatal(err)
	}

	we := NewWatchdogEngineCustom(grubEnvPath, cmdlinePath)
	we.snapshotsDir = snapsDir
	we.readInstalledVer = func() string { return "0.12.4" }
	var calls [][]string

	// First test XML fallback when snapper CLI errors
	we.runSnapperCmd = func(args ...string) ([]byte, error) {
		calls = append(calls, append([]string{"snapper"}, args...))
		return nil, fmt.Errorf("snapper dbus down")
	}
	we.runBtrfsCmd = func(args ...string) ([]byte, error) {
		calls = append(calls, append([]string{"btrfs"}, args...))
		return []byte("Data, RAID1: total=10.00GiB, used=4.00GiB\n"), nil
	}
	we.runBtrfsGrubCmd = func(args ...string) ([]byte, error) {
		calls = append(calls, append([]string{"axonwall-btrfs-grub"}, args...))
		if len(args) > 0 && args[0] == "create-snapshot" {
			return []byte("3\n"), nil
		}
		if len(args) > 0 && args[0] == "rollback" {
			return []byte("Promoted Snapshot #" + args[1] + " to @\n"), nil
		}
		return []byte("ok\n"), nil
	}

	snapsXML, err := we.ListBtrfsSnapshots()
	if err != nil {
		t.Fatalf("ListBtrfsSnapshots XML fallback failed: %v", err)
	}
	if len(snapsXML) != 2 || snapsXML[0].ID != 2 || snapsXML[1].ID != 1 {
		t.Fatalf("expected [2,1] sorted desc from XML fallback, got %+v", snapsXML)
	}
	if !snapsXML[1].Bootable || !snapsXML[1].Important {
		t.Errorf("expected snapshot #1 to be Bootable=true and Important=true, got %+v", snapsXML[1])
	}

	// Now test snapper --csvout parsing (including commas inside quoted description)
	we.runSnapperCmd = func(args ...string) ([]byte, error) {
		calls = append(calls, append([]string{"snapper"}, args...))
		if len(args) >= 4 && args[2] == "--csvout" {
			return []byte("number,type,pre-number,date,cleanup,description,userdata\n0,single,,,,current,\n2,pre,,2026-11-21 09:00:00,number,\"Pre-update, v0.12.5\",important=yes\n1,single,,2026-11-21 08:00:00,number,Factory Initial,important=yes\n"), nil
		}
		if len(args) >= 3 && args[2] == "create" {
			return []byte("3\n"), nil
		}
		return []byte("ok"), nil
	}
	we.detectInitialState()
	st := we.GetStatus()
	if st.InstallMode != "btrfs" {
		t.Fatalf("expected InstallMode='btrfs', got %q", st.InstallMode)
	}
	if st.BtrfsTopology != "raid1" {
		t.Errorf("expected BtrfsTopology='raid1', got %q", st.BtrfsTopology)
	}
	if len(st.BtrfsSnapshots) != 2 || st.BtrfsSnapshots[0].Description != "Pre-update, v0.12.5" {
		t.Errorf("unexpected parsed CSV snapshots: %+v", st.BtrfsSnapshots)
	}

	if err := we.ActivateSlot("B"); err == nil {
		t.Fatalf("expected ActivateSlot in btrfs mode to return actionable error")
	}
	if err := we.TriggerRollback(); err == nil {
		t.Fatalf("expected TriggerRollback in btrfs mode to return actionable error")
	}

	createdID, err := we.CreateBtrfsSnapshot("Manual checkpoint\nnewline", true)
	if err != nil || createdID != 3 {
		t.Fatalf("CreateBtrfsSnapshot failed: id=%d err=%v", createdID, err)
	}
	if err := we.DeleteBtrfsSnapshot(0); err == nil {
		t.Fatalf("expected DeleteBtrfsSnapshot(0) to fail")
	}
	if err := we.DeleteBtrfsSnapshot(2); err != nil {
		t.Fatalf("DeleteBtrfsSnapshot(2) failed: %v", err)
	}
	rbMsg, err := we.RollbackBtrfsSnapshot(1)
	if err != nil || !strings.Contains(rbMsg, "#1") {
		t.Fatalf("RollbackBtrfsSnapshot(1) failed: msg=%q err=%v", rbMsg, err)
	}

	// Verify ApplyFirmwareUpdate passes --btrfs --version 0.12.5
	argsOut := filepath.Join(tempDir, "updater-args.txt")
	mockUpdater := filepath.Join(tempDir, "axonwall-update")
	script := "#!/bin/sh\necho \"$@\" > '" + argsOut + "'\n"
	if err := os.WriteFile(mockUpdater, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	we.updaterPaths = []string{mockUpdater}
	updMsg, err := we.ApplyFirmwareUpdate("B", "0.12.5")
	if err != nil {
		t.Fatalf("ApplyFirmwareUpdate btrfs failed: %v", err)
	}
	if !strings.Contains(updMsg, "Snapper") {
		t.Errorf("expected Snapper in update message, got %q", updMsg)
	}
	gotArgs, _ := os.ReadFile(argsOut)
	if !strings.Contains(string(gotArgs), "--btrfs --version 0.12.5") {
		t.Errorf("expected updater args '--btrfs --version 0.12.5', got %q", string(gotArgs))
	}
}


