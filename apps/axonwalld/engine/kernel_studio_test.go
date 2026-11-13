package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSuggestMarchFromFlags(t *testing.T) {
	if got := SuggestMarchFromFlags("aarch64", []string{"asimd"}); got != "armv8-a" {
		t.Fatalf("expected armv8-a, got %s", got)
	}
	if got := SuggestMarchFromFlags("x86_64", []string{"avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl"}); got != "x86-64-v4" {
		t.Fatalf("expected x86-64-v4, got %s", got)
	}
	if got := SuggestMarchFromFlags("x86_64", []string{"avx2", "bmi1", "bmi2", "fma"}); got != "x86-64-v3" {
		t.Fatalf("expected x86-64-v3, got %s", got)
	}
	if got := SuggestMarchFromFlags("x86_64", []string{"sse4_2", "popcnt", "ssse3"}); got != "x86-64-v2" {
		t.Fatalf("expected x86-64-v2, got %s", got)
	}
	if got := SuggestMarchFromFlags("x86_64", []string{"sse2"}); got != "x86-64" {
		t.Fatalf("expected x86-64, got %s", got)
	}
}

func TestKernelStudioFixtureDiscoveryAndConfigParsing(t *testing.T) {
	tmp := t.TempDir()
	procRoot := filepath.Join(tmp, "proc")
	sysRoot := filepath.Join(tmp, "sys")
	bootRoot := filepath.Join(tmp, "boot")
	modRoot := filepath.Join(tmp, "modules")
	workRoot := filepath.Join(tmp, "work")

	for _, d := range []string{
		procRoot,
		filepath.Join(sysRoot, "bus", "pci", "devices", "0000:01:00.0"),
		filepath.Join(sysRoot, "bus", "pci", "drivers", "igc"),
		filepath.Join(sysRoot, "module", "igc"),
		filepath.Join(sysRoot, "class", "block", "nvme0n1", "device"),
		filepath.Join(sysRoot, "class", "net", "enp1s0", "device"),
		filepath.Join(sysRoot, "kernel", "iommu_groups", "1"),
		filepath.Join(sysRoot, "firmware", "efi"),
		filepath.Join(sysRoot, "class", "tpm", "tpmrm0"),
		filepath.Join(sysRoot, "class", "watchdog", "watchdog0"),
		bootRoot,
		filepath.Join(modRoot, "6.12.15-test", "kernel", "drivers", "net"),
		filepath.Join(modRoot, "6.12.15-test", "kernel", "fs"),
		workRoot,
	} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	_ = os.WriteFile(filepath.Join(procRoot, "cpuinfo"), []byte("processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Xeon E-2388G\nflags\t\t: sse4_2 popcnt ssse3 avx2 bmi1 bmi2 fma aes\nprocessor\t: 1\n"), 0644)
	_ = os.WriteFile(filepath.Join(procRoot, "modules"), []byte("igc 184320 0 - Live 0x0\nnvme 61440 2 nvme_core, Live 0x0\nzfs 4128768 5 spl, Live 0x0\n"), 0644)

	pciDev := filepath.Join(sysRoot, "bus", "pci", "devices", "0000:01:00.0")
	_ = os.WriteFile(filepath.Join(pciDev, "vendor"), []byte("0x8086\n"), 0644)
	_ = os.WriteFile(filepath.Join(pciDev, "device"), []byte("0x125c\n"), 0644)
	_ = os.WriteFile(filepath.Join(pciDev, "class"), []byte("0x020000\n"), 0644)
	_ = os.Symlink(filepath.Join(sysRoot, "bus", "pci", "drivers", "igc"), filepath.Join(pciDev, "driver"))
	_ = os.Symlink(filepath.Join(sysRoot, "module", "igc"), filepath.Join(sysRoot, "bus", "pci", "drivers", "igc", "module"))

	blkDir := filepath.Join(sysRoot, "class", "block", "nvme0n1")
	_ = os.WriteFile(filepath.Join(blkDir, "size"), []byte("2048\n"), 0644)
	_ = os.WriteFile(filepath.Join(blkDir, "device", "model"), []byte("Micron 7450 PRO\n"), 0644)

	netDir := filepath.Join(sysRoot, "class", "net", "enp1s0")
	_ = os.WriteFile(filepath.Join(netDir, "address"), []byte("00:11:22:33:44:55\n"), 0644)
	_ = os.WriteFile(filepath.Join(netDir, "operstate"), []byte("up\n"), 0644)
	_ = os.WriteFile(filepath.Join(netDir, "speed"), []byte("2500\n"), 0644)
	_ = os.Symlink(filepath.Join(sysRoot, "bus", "pci", "drivers", "igc"), filepath.Join(netDir, "device", "driver"))

	_ = os.WriteFile(filepath.Join(sysRoot, "class", "watchdog", "watchdog0", "identity"), []byte("iTCO_wdt\n"), 0644)
	_ = os.WriteFile(filepath.Join(modRoot, "6.12.15-test", "kernel", "drivers", "net", "igc.ko.zst"), []byte("stub"), 0644)
	_ = os.WriteFile(filepath.Join(modRoot, "6.12.15-test", "kernel", "fs", "ext4.ko.xz"), []byte("stub"), 0644)
	_ = os.WriteFile(filepath.Join(bootRoot, "config-6.12.15-test"), []byte("CONFIG_USER_NS=y\n# CONFIG_TRIM_UNUSED_KSYMS is not set\nCONFIG_NF_TABLES=m\n"), 0644)

	mgr := &KernelStudioManager{
		procRoot:    procRoot,
		sysRoot:     sysRoot,
		bootRoot:    bootRoot,
		modulesRoot: modRoot,
		workRoot:    workRoot,
	}

	vendor, model, cores, flags := mgr.parseCpuInfo()
	if vendor != "GenuineIntel" || model != "Xeon E-2388G" || cores != 2 {
		t.Fatalf("unexpected CPU info: vendor=%s model=%s cores=%d", vendor, model, cores)
	}
	if march := SuggestMarchFromFlags("x86_64", flags); march != "x86-64-v3" {
		t.Fatalf("expected x86-64-v3, got %s", march)
	}

	mods := mgr.parseLoadedModules()
	if len(mods) != 3 || mods[0].Name != "igc" {
		t.Fatalf("unexpected modules: %+v", mods)
	}

	pcis := mgr.scanPciDevices()
	if len(pcis) != 1 || pcis[0].Driver != "igc" || pcis[0].Module != "igc" {
		t.Fatalf("unexpected pci devices: %+v", pcis)
	}

	blks := mgr.scanStorageControllers()
	if len(blks) != 1 || blks[0].Kind != "nvme" || blks[0].SizeBytes != 2048*512 {
		t.Fatalf("unexpected storage controllers: %+v", blks)
	}

	nets := mgr.scanNetworkInterfaces()
	if len(nets) != 1 || nets[0].Driver != "igc" || nets[0].SpeedMbps != 2500 {
		t.Fatalf("unexpected network interfaces: %+v", nets)
	}

	if cnt := mgr.countAvailableModules("6.12.15-test"); cnt != 2 {
		t.Fatalf("expected 2 compressed modules, got %d", cnt)
	}

	cfg, src := mgr.readRunningKernelConfig("6.12.15-test")
	if src == "" || cfg["CONFIG_USER_NS"] != "y" || cfg["CONFIG_TRIM_UNUSED_KSYMS"] != "n" || cfg["CONFIG_NF_TABLES"] != "m" {
		t.Fatalf("unexpected kernel config map: src=%s cfg=%+v", src, cfg)
	}
}

func TestValidateKconfigFragmentAndBuildAndInstallSafety(t *testing.T) {
	valid := "# Axonwall Hardware Fragment\nCONFIG_IGC=y\n# CONFIG_SOUND is not set\nCONFIG_LSM=\"landlock,lockdown,bpf\"\n"
	if err := ValidateKconfigFragment(valid); err != nil {
		t.Fatalf("expected valid fragment to pass: %v", err)
	}

	for _, bad := range []string{
		"CONFIG_IGC=y; rm -rf /",
		"$(whoami)",
		"CONFIG_CMDLINE=\"foo;id\"",
	} {
		if err := ValidateKconfigFragment(bad); err == nil {
			t.Fatalf("expected malicious line %q to fail validation", bad)
		}
	}

	// Find repo packaging/kernel/build-kernel.sh relative to engine/
	scriptPath, err := filepath.Abs("../../../packaging/kernel/build-kernel.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Skipf("build-kernel.sh not present at %s", scriptPath)
	}

	workRoot := t.TempDir()
	mgr := &KernelStudioManager{
		procRoot:                "/proc",
		sysRoot:                 "/sys",
		bootRoot:                "/boot",
		modulesRoot:             "/lib/modules",
		workRoot:                workRoot,
		builderScriptCandidates: []string{scriptPath},
	}
	taskMgr := NewTaskManager()

	upid, _, err := mgr.StartBuild(taskMgr, KernelBuildRequest{
		Mode:                 "stripped",
		ConfigOnly:           true,
		KernelVersion:        "6.12.15",
		Arch:                 "amd64",
		MarchTarget:          "x86-64-v3",
		Capabilities:         []string{"k3s", "zfs", "nftables", "ebpf"},
		LockdownTier:         "integrity",
		EnableRootlessUserNs: true,
		DisableIa32Emulation: true,
		EnableProcKcore:      true,
		HardwareFragment:     "CONFIG_IGC=y\nCONFIG_BLK_DEV_NVME=y\n",
	}, "test@axonwall")
	if err != nil {
		t.Fatalf("StartBuild failed: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rec, err := taskMgr.GetTask(upid)
		if err == nil && rec.Status != "running" {
			if rec.Status != "stopped" {
				t.Fatalf("expected stopped task, got %s (%s)", rec.Status, rec.ExitStatus)
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	artifacts := mgr.listArtifacts()
	if len(artifacts) < 2 {
		t.Fatalf("expected config and manifest artifacts, got %+v", artifacts)
	}

	// Ensure path traversal / malformed filenames are rejected on InstallArtifactSafely
	for _, badName := range []string{"../evil.deb", "arbitrary-pkg.deb", "linux-image-6.12.deb;id"} {
		if _, _, _, err := mgr.InstallArtifactSafely(taskMgr, nil, badName, "test@axonwall"); err == nil {
			t.Fatalf("expected InstallArtifactSafely to reject %q", badName)
		}
	}
}
