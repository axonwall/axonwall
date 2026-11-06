package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestVirtManager(t *testing.T) *VirtManager {
	t.Helper()
	oldPath := VirtSpecsPath
	VirtSpecsPath = filepath.Join(t.TempDir(), "virt-specs.json")
	t.Cleanup(func() { VirtSpecsPath = oldPath })
	return NewVirtManager(NewTaskManager(), NewNasManager())
}

// A-M26: RegisterVMSpec must surface invalid specs instead of silently
// dropping them while the register API reports success.
func TestBatch7_RegisterVMSpecRejectsInvalidSpecs(t *testing.T) {
	virtMgr := newTestVirtManager(t)

	cases := []struct {
		name string
		spec CompiledVmSpec
	}{
		{"unsupported binary", CompiledVmSpec{VMID: 201, Name: "bad-bin", Binary: "qemu-system-riscv64"}},
		{"disallowed qemu arg", CompiledVmSpec{VMID: 202, Name: "bad-arg", Binary: "qemu-system-x86_64", Args: []string{"-gdb", "tcp::1234"}}},
		{"invalid pool name", CompiledVmSpec{VMID: 203, Name: "bad-pool", Binary: "qemu-system-x86_64", Disks: []VmDisk{{Name: "disk0", Pool: "tank;rm", SizeGb: 10}}}},
		{"invalid zvol path", CompiledVmSpec{VMID: 204, Name: "bad-zvol", Binary: "qemu-system-x86_64", Disks: []VmDisk{{Name: "disk0", Zvol: "tank/vm;evil"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := virtMgr.RegisterVMSpec(tc.spec); err == nil {
				t.Fatalf("RegisterVMSpec(%s) returned nil error, want rejection", tc.name)
			}
		})
	}

	if got := len(virtMgr.ListVMs()); got != 0 {
		t.Fatalf("expected 0 registered VMs after rejected specs, got %d", got)
	}

	// A valid spec still registers.
	if err := virtMgr.RegisterVMSpec(CompiledVmSpec{VMID: 205, Name: "good", Binary: "qemu-system-x86_64"}); err != nil {
		t.Fatalf("RegisterVMSpec valid spec: %v", err)
	}
	if got := len(virtMgr.ListVMs()); got != 1 {
		t.Fatalf("expected 1 registered VM, got %d", got)
	}
}

// A-M26 / C-D1: StartVM must refuse an unregistered VMID instead of
// booting a generic diskless fallback VM.
func TestBatch7_StartVMRefusesUnregisteredVM(t *testing.T) {
	virtMgr := newTestVirtManager(t)
	if _, err := virtMgr.StartVM(999, "test@batch7"); err == nil {
		t.Fatal("StartVM unregistered VMID returned nil error, want refusal")
	}
}

// A-M24: a multi-disk VM backup must cover every disk, not just disk-0.
func TestBatch7_BackupDatasetsForTarget(t *testing.T) {
	virtMgr := newTestVirtManager(t)
	if err := virtMgr.RegisterVMSpec(CompiledVmSpec{
		VMID: 300, Name: "multi", Binary: "qemu-system-x86_64",
		Disks: []VmDisk{
			{Name: "disk0", Pool: "tank", SizeGb: 10},
			{Name: "disk1", Pool: "tank", SizeGb: 20},
			{Name: "disk2", Pool: "fast", Zvol: "fast/vms/custom-disk", SizeGb: 5},
		},
	}); err != nil {
		t.Fatalf("RegisterVMSpec: %v", err)
	}

	got := virtMgr.backupDatasetsForTarget("vm", 300, "tank")
	want := []string{"tank/vms/vm-300-disk-0", "tank/vms/vm-300-disk-1", "fast/vms/custom-disk"}
	if len(got) != len(want) {
		t.Fatalf("multi-disk datasets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dataset %d = %q, want %q", i, got[i], want[i])
		}
	}

	// Unregistered VM and LXC keep the historical single disk-0 dataset.
	got = virtMgr.backupDatasetsForTarget("vm", 301, "tank")
	if len(got) != 1 || got[0] != "tank/vms/vm-301-disk-0" {
		t.Fatalf("unregistered VM datasets = %v, want [tank/vms/vm-301-disk-0]", got)
	}
	got = virtMgr.backupDatasetsForTarget("lxc", 400, "tank")
	if len(got) != 1 || got[0] != "tank/lxc/subvol-400-disk-0" {
		t.Fatalf("LXC datasets = %v, want [tank/lxc/subvol-400-disk-0]", got)
	}
}

// A-M25: StartVM must fail when QEMU died and the QMP socket never
// appeared, instead of warning and reporting task success.
func TestBatch7_WaitForQmpSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "vm-999.sock")
	pidFile := filepath.Join(dir, "vm-999.pid")

	// No socket at all: must fail after the timeout.
	if err := waitForQmpSocket(sock, pidFile, 250*time.Millisecond); err == nil {
		t.Fatal("waitForQmpSocket with no socket returned nil, want error")
	}

	// Socket present but the pid from the pidfile is dead: must fail
	// (a stale socket from a previous run must not count as live).
	if err := os.WriteFile(sock, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidFile, []byte("999999\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := waitForQmpSocket(sock, pidFile, 100*time.Millisecond); err == nil {
		t.Fatal("waitForQmpSocket with dead pid returned nil, want error")
	}

	// Socket present and the pid is alive (our own pid): must succeed.
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if err := waitForQmpSocket(sock, pidFile, 100*time.Millisecond); err != nil {
		t.Fatalf("waitForQmpSocket with live pid: %v", err)
	}

	// Socket present and no pidfile yet (pidfile race): must succeed.
	if err := os.Remove(pidFile); err != nil {
		t.Fatal(err)
	}
	if err := waitForQmpSocket(sock, pidFile, 100*time.Millisecond); err != nil {
		t.Fatalf("waitForQmpSocket with no pidfile: %v", err)
	}
}
