package engine

// Round-2 bug-hunt fix batch 10 (daemon-low-2) regression tests:
// A-L21..A-L32. Tests that need live daemons, LDAP, or systemd (the
// full slapd bootstrap, the plugin LDAP integration against a real
// directory) are covered by the unit seams below, not by live
// services; see the batch report for the live-box items.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A-L21: a second Start() while the manager is running must be
// refused, not spawn a second monitorFlows that panics closing the
// same doneChan twice.
func TestBatch10EBPFDoubleStartRefused(t *testing.T) {
	mgr := NewEBPFManager()
	mgr.mu.Lock()
	mgr.running = true
	mgr.mu.Unlock()

	err := mgr.Start(nil)
	if err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("second Start() = %v, want \"already started\" error", err)
	}

	// Stop on a never-started manager must not panic or hang.
	mgr.mu.Lock()
	mgr.running = false
	mgr.mu.Unlock()
	mgr.Stop()
}

// A-L21: a failed Start() must clear the running flag so a later
// Start() can retry instead of being refused forever.
func TestBatch10EBPFStartFailureClearsRunning(t *testing.T) {
	mgr := NewEBPFManager()
	err := mgr.Start([]string{"lo"})
	if err == nil {
		// The sandbox can load eBPF after all: a second Start must
		// still be refused, and Stop must clean up.
		t.Cleanup(func() { mgr.Stop() })
		if err2 := mgr.Start([]string{"lo"}); err2 == nil || !strings.Contains(err2.Error(), "already started") {
			t.Fatalf("second Start() after successful Start = %v, want \"already started\" error", err2)
		}
		return
	}
	mgr.mu.Lock()
	running := mgr.running
	mgr.mu.Unlock()
	if running {
		t.Fatalf("failed Start() left running=true (err: %v)", err)
	}
}

// A-L22: a second concurrent StartVM for the same VM must be refused
// while the first start task is still running.
func TestBatch10VirtDoubleStartVMRefused(t *testing.T) {
	oldPath := VirtSpecsPath
	VirtSpecsPath = filepath.Join(t.TempDir(), "virt-specs.json")
	defer func() { VirtSpecsPath = oldPath }()

	mgr := NewVirtManager(NewTaskManager(), nil)

	// Deterministic pin: a flagged VMID is refused outright.
	mgr.startMu.Lock()
	if mgr.startingVMs == nil {
		mgr.startingVMs = make(map[int]bool)
	}
	mgr.startingVMs[101] = true
	mgr.startMu.Unlock()
	if _, err := mgr.StartVM(101, "root@axonwall"); err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("StartVM on flagged VMID = %v, want \"already in progress\" error", err)
	}
	mgr.startMu.Lock()
	delete(mgr.startingVMs, 101)
	mgr.startMu.Unlock()

	// Live pin: two sequential starts; the first task is still
	// running (it has to fail through QEMU provisioning first), so
	// the second must hit the guard, not launch a second QEMU.
	upid, err := mgr.StartVM(102, "root@axonwall")
	if err != nil {
		t.Fatalf("first StartVM(102) failed: %v", err)
	}
	if upid == "" {
		t.Fatalf("first StartVM(102) returned an empty UPID")
	}
	if _, err := mgr.StartVM(102, "root@axonwall"); err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("second StartVM(102) = %v, want \"already in progress\" error", err)
	}
}

// A-L24: without hwmon sensors the telemetry must be empty, not
// hardcoded fake temperatures, fans, and optics.
func TestBatch10CollectTelemetryHasNoMockFallback(t *testing.T) {
	if entries, err := os.ReadDir("/sys/class/hwmon"); err == nil && len(entries) > 0 {
		t.Skip("host has real hwmon sensors; the mock-fallback path is not exercised here")
	}
	telem, err := NewHardwareManager().CollectTelemetry()
	if err != nil {
		t.Fatalf("CollectTelemetry failed: %v", err)
	}
	if len(telem.Temperatures) != 0 {
		t.Fatalf("expected no temperatures without hwmon, got %+v", telem.Temperatures)
	}
	if telem.CPUTempC != 0 {
		t.Fatalf("expected CPUTempC 0 without hwmon, got %v", telem.CPUTempC)
	}
	if len(telem.Fans) != 0 {
		t.Fatalf("expected no fans without hwmon, got %+v", telem.Fans)
	}
	if len(telem.Transceivers) != 0 {
		t.Fatalf("expected no transceivers without optics, got %+v", telem.Transceivers)
	}
}

// A-L25: unreadable posture inputs must be reported as unknown with
// empty values, not substituted with secure-looking defaults; and the
// audit no longer claims a hidden-module check ran (the
// HiddenModules field was removed).
func TestBatch10RootkitPostureUnknownNotFabricated(t *testing.T) {
	posture := InspectKernelPosture()
	checkUnknown := func(path, field string, get func() string) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if got := get(); got != "" {
				t.Errorf("expected empty %s when %s is unreadable, got %q", field, path, got)
			}
			found := false
			for _, f := range posture.UnknownFields {
				if f == field {
					found = true
				}
			}
			if !found {
				t.Errorf("expected %q in UnknownFields %v", field, posture.UnknownFields)
			}
		}
	}
	checkUnknown("/sys/kernel/security/lsm", "kernel.security.lsm", func() string {
		return strings.Join(posture.ActiveLsms, ",")
	})
	checkUnknown("/proc/sys/kernel/unprivileged_bpf_disabled", "kernel.unprivileged_bpf_disabled", func() string {
		return posture.UnprivilegedBpfDisabled
	})
	checkUnknown("/proc/sys/net/core/bpf_jit_harden", "net.core.bpf_jit_harden", func() string {
		return posture.BpfJitHarden
	})

	audit := RunHostRootkitAudit()
	if audit.Timestamp == "" {
		t.Fatalf("expected a non-empty audit timestamp")
	}
}

// A-L26: an installed-but-never-initialised etckeeper repo must not
// report Clean=true.
func TestBatch10EtckeeperUninitializedIsNotClean(t *testing.T) {
	mgr := NewEtckeeperManager(t.TempDir())
	mgr.execCmd = func(name string, args ...string) *exec.Cmd {
		if name == "which" {
			return exec.Command("true")
		}
		return exec.Command("true")
	}
	status := mgr.GetStatus()
	if !status.Installed {
		t.Fatalf("expected Installed=true with a mocked etckeeper binary")
	}
	if status.Initialized {
		t.Fatalf("expected Initialized=false with no .git in the tracked dir")
	}
	if status.Clean {
		t.Fatalf("uninitialized etckeeper repo reported Clean=true")
	}
}

// A-L26: a failed git status must not report Clean=true either.
func TestBatch10EtckeeperFailedGitStatusIsNotClean(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	mgr := NewEtckeeperManager(dir)
	mgr.execCmd = func(name string, args ...string) *exec.Cmd {
		if name == "which" {
			return exec.Command("true")
		}
		if name == "git" {
			return exec.Command("false")
		}
		return exec.Command("true")
	}
	status := mgr.GetStatus()
	if !status.Initialized {
		t.Fatalf("expected Initialized=true with a .git dir present")
	}
	if status.Clean {
		t.Fatalf("failed git status reported Clean=true")
	}
}

// A-L27: both state.json copies must be merged; a peer IP that only
// exists in the second copy must still be protected.
func TestBatch10DiscoverProtectedPostureMergesBothStateFiles(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "state1.json")
	second := filepath.Join(dir, "state2.json")
	if err := os.WriteFile(first, []byte(`{"ha": {"peerIp": "10.0.0.11"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte(`{"ha": {"peerIp": "10.0.0.12"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	old := protectedPostureStatePaths
	protectedPostureStatePaths = []string{first, second}
	defer func() { protectedPostureStatePaths = old }()

	posture := DiscoverProtectedPosture()
	has := func(ip string) bool {
		for _, g := range posture.GatewayAndHaIPs {
			if g == ip {
				return true
			}
		}
		return false
	}
	if !has("10.0.0.11") || !has("10.0.0.12") {
		t.Fatalf("expected both HA peer IPs protected, got %v", posture.GatewayAndHaIPs)
	}
}

// A-L28: a port with trailing junk ("80abc") must be rejected, not
// silently parsed as 80.
func TestBatch10ValidateRedirectDestinationRejectsTrailingJunkPort(t *testing.T) {
	for _, dest := range []string{"10.0.0.5:8080x", "10.0.0.5:80abc"} {
		if _, _, _, _, err := ValidateRedirectDestination(dest); err == nil {
			t.Fatalf("ValidateRedirectDestination(%q) succeeded, want an error", dest)
		}
	}
	host, port, _, norm, err := ValidateRedirectDestination("10.0.0.5:8080")
	if err != nil {
		t.Fatalf("ValidateRedirectDestination(10.0.0.5:8080) failed: %v", err)
	}
	if host != "10.0.0.5" || port != 8080 || norm != "10.0.0.5:8080" {
		t.Fatalf("ValidateRedirectDestination(10.0.0.5:8080) = (%q, %d, %q), want (10.0.0.5, 8080, 10.0.0.5:8080)", host, port, norm)
	}
}

// A-L29: an unreadable PCI sysfs tree must be an error, not an empty
// device list.
func TestBatch10DiscoverPciDevicesErrorsWhenSysfsUnreadable(t *testing.T) {
	mgr := &VFIOManager{sysfsRoot: filepath.Join(t.TempDir(), "nosuchsys")}
	if _, err := mgr.DiscoverPciDevices(); err == nil {
		t.Fatalf("DiscoverPciDevices with unreadable sysfs returned nil error")
	}
}

// A-L29: UnbindVfio must report an error when the device is still
// bound to vfio-pci after the unbind writes.
func TestBatch10UnbindVfioReportsStillBound(t *testing.T) {
	root := t.TempDir()
	bdf := "0000:00:01.0"
	devDir := filepath.Join(root, "bus", "pci", "devices", bdf)
	if err := os.MkdirAll(devDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "bus", "pci", "drivers", "vfio-pci"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(root, "bus", "pci", "drivers", "vfio-pci", "unbind"),
		filepath.Join(root, "bus", "pci", "rescan"),
		filepath.Join(devDir, "driver_override"),
	} {
		if err := os.WriteFile(p, []byte{}, 0644); err != nil {
			t.Fatal(err)
		}
	}
	// The writes succeed but the driver symlink never moves: the
	// device is still bound, so UnbindVfio must fail.
	if err := os.Symlink(filepath.Join(root, "bus", "pci", "drivers", "vfio-pci"), filepath.Join(devDir, "driver")); err != nil {
		t.Fatal(err)
	}
	mgr := &VFIOManager{sysfsRoot: root}
	if err := mgr.UnbindVfio(bdf); err == nil {
		t.Fatalf("UnbindVfio returned nil while the device is still bound to vfio-pci")
	}
}

// A-L29: a device bound to another driver is already released.
func TestBatch10UnbindVfioAlreadyUnboundSucceeds(t *testing.T) {
	root := t.TempDir()
	bdf := "0000:00:01.0"
	devDir := filepath.Join(root, "bus", "pci", "devices", bdf)
	if err := os.MkdirAll(devDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "bus", "pci", "drivers", "vfio-pci"), 0755); err != nil {
		t.Fatal(err)
	}
	otherDriver := filepath.Join(root, "bus", "pci", "drivers", "virtio-pci")
	if err := os.MkdirAll(otherDriver, 0755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(root, "bus", "pci", "drivers", "vfio-pci", "unbind"),
		filepath.Join(root, "bus", "pci", "rescan"),
		filepath.Join(devDir, "driver_override"),
	} {
		if err := os.WriteFile(p, []byte{}, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(otherDriver, filepath.Join(devDir, "driver")); err != nil {
		t.Fatal(err)
	}
	mgr := &VFIOManager{sysfsRoot: root}
	if err := mgr.UnbindVfio(bdf); err != nil {
		t.Fatalf("UnbindVfio on a device bound to another driver failed: %v", err)
	}
}
