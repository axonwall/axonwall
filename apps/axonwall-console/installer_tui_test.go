package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFilterCandidateDisks(t *testing.T) {
	input := []DiskDevice{
		{Name: "loop0", Path: "/dev/loop0", SizeMB: 8192},
		{Name: "sr0", Path: "/dev/sr0", SizeMB: 4096},
		{Name: "zram0", Path: "/dev/zram0", SizeMB: 4096},
		{Name: "sda", Path: "/dev/sda", SizeMB: 1024},                 // too small (<2 GiB)
		{Name: "sdb", Path: "/dev/sdb", SizeMB: 16384, Mounted: true}, // mounted live USB
		{Name: "nvme1n1", Path: "/dev/nvme1n1", SizeMB: 65536},
		{Name: "nvme0n1", Path: "/dev/nvme0n1", SizeMB: 65536},
	}

	got := FilterCandidateDisks(input)
	if len(got) != 2 {
		t.Fatalf("expected 2 candidate disks, got %d", len(got))
	}
	if got[0].Path != "/dev/nvme0n1" || got[1].Path != "/dev/nvme1n1" {
		t.Errorf("unexpected disk order: %+v", got)
	}
}

func TestComputePartitionLayout(t *testing.T) {
	cfg := DefaultInstallerConfig()
	cfg.InstallMode = "ab"
	cfg.SlotMB = 4096
	cfg.ZfsAllocMode = "remainder"
	cfg.LogsEnabled = true
	cfg.LogsGB = 8

	// 64 GiB (65536 MiB) disk
	layout := ComputePartitionLayout(65536, cfg)
	if layout.EfiMB != 260 {
		t.Errorf("expected EfiMB=260, got %d", layout.EfiMB)
	}
	if layout.SlotAMB != 4096 || layout.SlotBMB != 4096 {
		t.Errorf("expected SlotA/SlotB=4096, got %d/%d", layout.SlotAMB, layout.SlotBMB)
	}
	if layout.LogsMB != 8192 {
		t.Errorf("expected LogsMB=8192, got %d", layout.LogsMB)
	}
	if layout.DataMB != 8192 {
		t.Errorf("expected DataMB=8192 in remainder mode, got %d", layout.DataMB)
	}
	if layout.ZfsMB <= 0 {
		t.Errorf("expected positive ZfsMB on 64 GiB disk, got %d", layout.ZfsMB)
	}

	// Rolling mode should have SlotBMB == 0
	cfg.InstallMode = "rolling"
	rollingLayout := ComputePartitionLayout(65536, cfg)
	if rollingLayout.SlotBMB != 0 {
		t.Errorf("expected SlotBMB=0 in rolling mode, got %d", rollingLayout.SlotBMB)
	}
}

func TestRenderPartitionBarAndFormatConfig(t *testing.T) {
	cfg := DefaultInstallerConfig()
	cfg.Edition = "vault"
	cfg.SystemDisks = []string{"/dev/nvme0n1", "/dev/nvme1n1"}
	cfg.LuksEnabled = true
	cfg.LuksTPM2 = true
	cfg.LuksPassphrase = "s3cr3t'pass"
	cfg.LogsEnabled = true

	layout := ComputePartitionLayout(65536, cfg)
	bar := RenderPartitionBar(layout, cfg, 60)
	if !strings.Contains(bar, "Slot A") || !strings.Contains(bar, "Slot B") || !strings.Contains(bar, "Data[LUKS2]") {
		t.Errorf("RenderPartitionBar missing expected labels: %s", bar)
	}

	serialized := FormatInstallerConfig(cfg)
	if !strings.Contains(serialized, "INSTALL_EDITION='vault'") {
		t.Errorf("expected INSTALL_EDITION='vault' in serialized config:\n%s", serialized)
	}
	if !strings.Contains(serialized, "SYSTEM_DISKS='/dev/nvme0n1 /dev/nvme1n1'") {
		t.Errorf("unexpected SYSTEM_DISKS in serialized config:\n%s", serialized)
	}
	if !strings.Contains(serialized, "LUKS_ENABLED=1") || !strings.Contains(serialized, "LUKS_TPM2=1") {
		t.Errorf("expected LUKS_ENABLED=1 and LUKS_TPM2=1 in serialized config:\n%s", serialized)
	}
	if !strings.Contains(serialized, "LUKS_PASSPHRASE='s3cr3t'\"'\"'pass'") {
		t.Errorf("expected properly shell-escaped single quote in LUKS_PASSPHRASE:\n%s", serialized)
	}
	if !strings.Contains(serialized, "KEEP_PARTITIONS=0") {
		t.Errorf("expected KEEP_PARTITIONS=0 by default in serialized config:\n%s", serialized)
	}

	cfg.KeepPartitions = true
	serializedKeep := FormatInstallerConfig(cfg)
	if !strings.Contains(serializedKeep, "KEEP_PARTITIONS=1") {
		t.Errorf("expected KEEP_PARTITIONS=1 when KeepPartitions=true:\n%s", serializedKeep)
	}
}

func TestAutoAssignDiskRolesAndAccelerators(t *testing.T) {
	// Scenario: 2x 32 GB system disks + 2x 1 TB data disks + 1x 64 GB SLOG + 1x 256 GB L2ARC
	disks := []DiskDevice{
		{Name: "sda", Path: "/dev/sda", SizeMB: 32768, SizeGB: 32.0},
		{Name: "sdb", Path: "/dev/sdb", SizeMB: 32768, SizeGB: 32.0},
		{Name: "sdc", Path: "/dev/sdc", SizeMB: 1048576, SizeGB: 1024.0},
		{Name: "sdd", Path: "/dev/sdd", SizeMB: 1048576, SizeGB: 1024.0},
		{Name: "nvme0n1", Path: "/dev/nvme0n1", SizeMB: 65536, SizeGB: 64.0},
		{Name: "nvme1n1", Path: "/dev/nvme1n1", SizeMB: 262144, SizeGB: 256.0},
	}

	tiered := AutoAssignDiskRoles(disks)
	if tiered[0].Role != "system" || tiered[1].Role != "system" {
		t.Fatalf("expected 2x 32GB disks to be auto-assigned 'system', got %s, %s", tiered[0].Role, tiered[1].Role)
	}
	if tiered[2].Role != "zfs-data" || tiered[3].Role != "zfs-data" {
		t.Fatalf("expected 2x 1TB disks to be auto-assigned 'zfs-data', got %s, %s", tiered[2].Role, tiered[3].Role)
	}

	// User assigns nvme0n1 as SLOG and nvme1n1 as L2ARC
	setDiskRole(&tiered[4], "zfs-slog")
	setDiskRole(&tiered[5], "zfs-l2arc")

	cfg := DefaultInstallerConfig()
	cfg.InstallMode = "zbm"
	primaryMB := syncDiskRolesAndConfig(tiered, &cfg)
	if primaryMB != 32768 {
		t.Errorf("expected primaryMB=32768, got %d", primaryMB)
	}
	if strings.Join(cfg.SystemDisks, " ") != "/dev/sda /dev/sdb" {
		t.Errorf("unexpected SystemDisks: %v", cfg.SystemDisks)
	}
	if strings.Join(cfg.ZfsExtraDisks, " ") != "/dev/sdc /dev/sdd" {
		t.Errorf("unexpected ZfsExtraDisks: %v", cfg.ZfsExtraDisks)
	}
	if strings.Join(cfg.ZfsSlogDisks, " ") != "/dev/nvme0n1" {
		t.Errorf("unexpected ZfsSlogDisks: %v", cfg.ZfsSlogDisks)
	}
	if strings.Join(cfg.ZfsL2arcDisks, " ") != "/dev/nvme1n1" {
		t.Errorf("unexpected ZfsL2arcDisks: %v", cfg.ZfsL2arcDisks)
	}

	layout := ComputePartitionLayout(primaryMB, cfg)
	if layout.SlotAMB != 0 || layout.SlotBMB != 0 || layout.DataMB != 0 {
		t.Errorf("expected pure ZBM layout to have zero ext4 slot/data partitions, got %+v", layout)
	}
	if layout.EfiMB != 512 {
		t.Errorf("expected EfiMB=512 in zbm mode, got %d", layout.EfiMB)
	}
	bar := RenderPartitionBar(layout, cfg, 64)
	if !strings.Contains(bar, "ZBM-EFI") || !strings.Contains(bar, "ZFS:zroot") {
		t.Errorf("expected ZBM-EFI and ZFS:zroot in zbm partition bar, got: %s", bar)
	}

	serialized := FormatInstallerConfig(cfg)
	if !strings.Contains(serialized, "ZFS_EXTRA_DISKS='/dev/sdc /dev/sdd'") {
		t.Errorf("missing ZFS_EXTRA_DISKS in serialized config:\n%s", serialized)
	}
	if !strings.Contains(serialized, "ZFS_SLOG_DISKS='/dev/nvme0n1'") {
		t.Errorf("missing ZFS_SLOG_DISKS in serialized config:\n%s", serialized)
	}
	if !strings.Contains(serialized, "ZFS_L2ARC_DISKS='/dev/nvme1n1'") {
		t.Errorf("missing ZFS_L2ARC_DISKS in serialized config:\n%s", serialized)
	}
}

func TestEvaluateHardwareProfile(t *testing.T) {
	// 1. Two homogeneous disks -> auto-evaluated RAID-1 / ZFS Mirror across both disks
	twoDisks := []DiskDevice{
		{Name: "nvme0n1", Path: "/dev/nvme0n1", SizeMB: 131072, SizeGB: 128.0},
		{Name: "nvme1n1", Path: "/dev/nvme1n1", SizeMB: 131072, SizeGB: 128.0},
	}
	cfg := DefaultInstallerConfig()
	_, eval := EvaluateHardwareProfile(twoDisks, &cfg)
	if len(cfg.SystemDisks) != 2 {
		t.Fatalf("expected 2 homogeneous disks to auto-assign as mirrored system disks, got %v", cfg.SystemDisks)
	}
	if !strings.Contains(eval.SystemDiskSummary, "Mirrored") && !strings.Contains(eval.SystemDiskSummary, "RAID-1") {
		t.Errorf("expected SystemDiskSummary to report mirrored/RAID-1, got %s", eval.SystemDiskSummary)
	}
	if cfg.SlotMB != 8192 {
		t.Errorf("expected 128 GiB disk to auto-evaluate SlotMB=8192, got %d", cfg.SlotMB)
	}

	// 2. Three homogeneous disks -> first 2 mirrored as system, 3rd as ZFS data
	threeDisks := []DiskDevice{
		{Name: "sda", Path: "/dev/sda", SizeMB: 65536, SizeGB: 64.0},
		{Name: "sdb", Path: "/dev/sdb", SizeMB: 65536, SizeGB: 64.0},
		{Name: "sdc", Path: "/dev/sdc", SizeMB: 65536, SizeGB: 64.0},
	}
	cfg3 := DefaultInstallerConfig()
	_, eval3 := EvaluateHardwareProfile(threeDisks, &cfg3)
	if len(cfg3.SystemDisks) != 2 || len(cfg3.ZfsExtraDisks) != 1 {
		t.Fatalf("expected 2 system disks + 1 zfs-data disk, got sys=%v zfs=%v", cfg3.SystemDisks, cfg3.ZfsExtraDisks)
	}
	if eval3.ZfsPoolSummary == "" {
		t.Errorf("expected non-empty ZfsPoolSummary")
	}
}

func TestSaveInstallerDiagnosticsBundle(t *testing.T) {
	cfg := DefaultInstallerConfig()
	disks := []DiskDevice{
		{Name: "nvme0n1", Path: "/dev/nvme0n1", SizeMB: 65536, SizeGB: 64.0},
	}
	_, eval := EvaluateHardwareProfile(disks, &cfg)
	rawLines := []string{
		"[PHASE:1/8] Partitioning target disk(s)...",
		"[+] Created GPT partition table on /dev/nvme0n1",
	}

	tmpDir := t.TempDir()
	customOut := tmpDir + "/custom-diag.log"
	savedPaths, err := SaveInstallerDiagnosticsBundle(customOut, cfg, eval, rawLines)
	if err != nil {
		t.Fatalf("expected SaveInstallerDiagnosticsBundle to succeed, got err=%v", err)
	}
	if len(savedPaths) == 0 {
		t.Fatalf("expected at least one saved path")
	}

	bundle := FormatInstallerDiagnosticsBundle(cfg, eval, rawLines)
	if !strings.Contains(bundle, "AXONWALL NEXT-GEN INSTALLER — DIAGNOSTICS & LOG BUNDLE") {
		t.Errorf("expected header in diagnostics bundle")
	}
	if !strings.Contains(bundle, "CAPTURED SERVICE & SYSTEM ERRORS") {
		t.Errorf("expected captured service errors section in diagnostics bundle")
	}
	if !strings.Contains(bundle, "CLOUD-INIT & INTERCEPTED CONSOLE OUTPUT") {
		t.Errorf("expected cloud-init & intercepted console output section in diagnostics bundle")
	}
	if !strings.Contains(bundle, "[PHASE:1/8] Partitioning target disk(s)...") && !strings.Contains(bundle, "INSTALLER EXECUTION LOG") {
		t.Errorf("expected installer execution log section in diagnostics bundle")
	}

	// Verify HTTP log shipping endpoint
	var receivedBody string
	var receivedHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		receivedHost = r.Header.Get("X-Axonwall-Hostname")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := ShipInstallerDiagnosticsBundle(srv.URL, cfg, eval, rawLines)
	if err != nil {
		t.Fatalf("expected ShipInstallerDiagnosticsBundle to succeed via HTTP, got err=%v", err)
	}
	if !strings.Contains(res, "HTTP POST") {
		t.Errorf("expected HTTP POST confirmation, got %s", res)
	}
	if receivedHost != cfg.Hostname {
		t.Errorf("expected X-Axonwall-Hostname=%s, got %s", cfg.Hostname, receivedHost)
	}
	if !strings.Contains(receivedBody, "CLOUD-INIT & INTERCEPTED CONSOLE OUTPUT") {
		t.Errorf("expected shipped payload to include cloud-init & console section")
	}
}
