package main

import (
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
}
