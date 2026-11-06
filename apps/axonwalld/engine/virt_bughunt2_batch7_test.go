package engine

import (
	"path/filepath"
	"testing"
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
