package engine

import (
	"strings"
	"testing"
	"time"
)

func TestTaskManagerUPIDAndExecution(t *testing.T) {
	mgr := NewTaskManager()

	upid := mgr.GenerateUPID("qmstart", "101", "root@axonwall")
	if !strings.HasPrefix(upid, "UPID:") {
		t.Fatalf("expected upid to start with UPID:, got: %s", upid)
	}
	if !strings.Contains(upid, ":qmstart:101:root@axonwall:") {
		t.Fatalf("expected upid to contain components, got: %s", upid)
	}

	taskUpid := mgr.StartTask("qmstart", "101", "root@axonwall", func(logger func(format string, args ...any)) error {
		logger("Booting VM 101...")
		logger("Disks attached.")
		return nil
	})

	var task *TaskRecord
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		task, err = mgr.GetTask(taskUpid)
		if err == nil && task.Status != "running" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err != nil {
		t.Fatalf("failed to get task: %v", err)
	}
	if task.Status != "stopped" || task.ExitStatus != "OK" {
		t.Fatalf("expected task stopped with OK, got status: %s, exit: %s", task.Status, task.ExitStatus)
	}

	lines, done, err := mgr.GetTaskLog(taskUpid, 1)
	if err != nil {
		t.Fatalf("failed to get task log: %v", err)
	}
	if !done {
		t.Fatalf("expected task to be done")
	}
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 log lines, got: %d", len(lines))
	}
}

func TestVirtManagerRegistrationAndListing(t *testing.T) {
	taskMgr := NewTaskManager()
	nasMgr := NewNasManager()
	virtMgr := NewVirtManager(taskMgr, nasMgr)

	virtMgr.RegisterVMSpec(CompiledVmSpec{
		VMID:     105,
		Name:     "database-vm",
		Binary:   "qemu-system-x86_64",
		Cores:    4,
		MemoryMb: 8192,
		Args:     []string{"-name", "database-vm"},
		Disks: []VmDisk{
			{Name: "disk0", Pool: "tank", SizeGb: 100},
		},
	})

	vms := virtMgr.ListVMs()
	if len(vms) != 1 {
		t.Fatalf("expected 1 VM, got %d", len(vms))
	}
	if vms[0].VMID != 105 || vms[0].Name != "database-vm" {
		t.Fatalf("unexpected VM info: %+v", vms[0])
	}
	if vms[0].Status != "stopped" {
		t.Fatalf("expected stopped VM in test environment, got: %s", vms[0].Status)
	}

	virtMgr.RegisterCTSpec(CompiledCtSpec{
		CTID:     205,
		Hostname: "redis-ct",
		Cores:    2,
		MemoryMb: 2048,
	})

	cts := virtMgr.ListContainers()
	if len(cts) != 1 {
		t.Fatalf("expected 1 container, got %d", len(cts))
	}
	if cts[0].CTID != 205 || cts[0].Name != "redis-ct" {
		t.Fatalf("unexpected CT info: %+v", cts[0])
	}
}

func TestVFIOManagerValidation(t *testing.T) {
	vfioMgr := NewVFIOManager()

	err := vfioMgr.BindVfio("invalid-bdf")
	if err == nil {
		t.Fatalf("expected error on invalid BDF")
	}

	err = vfioMgr.ConfigureSriov("0000:99:99.9", 4)
	if err == nil {
		t.Fatalf("expected error on invalid BDF")
	}

	// Scanning should not panic even if hardware has no PCI/IOMMU
	devices, err := vfioMgr.DiscoverPciDevices()
	if err != nil {
		t.Fatalf("discover devices error: %v", err)
	}
	t.Logf("discovered %d PCI devices in test env", len(devices))
}
