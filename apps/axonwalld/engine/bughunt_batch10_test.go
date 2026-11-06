package engine

// Round-2 bug-hunt fix batch 10 (daemon-low-2) regression tests:
// A-L21..A-L32. Tests that need live daemons, LDAP, or systemd (the
// full slapd bootstrap, the plugin LDAP integration against a real
// directory) are covered by the unit seams below, not by live
// services; see the batch report for the live-box items.

import (
	"os"
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
