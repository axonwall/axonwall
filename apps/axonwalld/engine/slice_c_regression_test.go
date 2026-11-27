package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncFlushingSSERecorder struct {
	mu      sync.Mutex
	header  http.Header
	buf     bytes.Buffer
	flushed chan struct{}
}

func newSyncFlushingSSERecorder() *syncFlushingSSERecorder {
	return &syncFlushingSSERecorder{
		header:  make(http.Header),
		flushed: make(chan struct{}, 64),
	}
}

func (r *syncFlushingSSERecorder) Header() http.Header { return r.header }
func (r *syncFlushingSSERecorder) WriteHeader(int)     {}
func (r *syncFlushingSSERecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(p)
}
func (r *syncFlushingSSERecorder) Flush() {
	select {
	case r.flushed <- struct{}{}:
	default:
	}
}
func (r *syncFlushingSSERecorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

func TestSliceC_VirtAllowlistsAtomicityRestoreAndStopGuard(t *testing.T) {
	// 1. Strict QEMU allowlist checks dotted keys, drivers, mem-path, chardev, duplicate fw_cfg file=.
	validCompiledArgs := []string{
		"-name", "edge-gw",
		"-enable-kvm",
		"-machine", "q35,accel=kvm,smm=on",
		"-cpu", "host",
		"-smp", "4,sockets=1,cores=4,threads=1",
		"-m", "4096",
		"-pidfile", "/run/axonwall/pids/vm-100.pid",
		"-global", "driver=cfi.pflash01,property=secure,value=on",
		"-drive", "if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
		"-drive", "if=none,id=drive0,format=raw,file=/dev/zvol/tank/vms/vm-100-disk-0",
		"-kernel", "/usr/lib/axonwall/edge/slot-a/axonwall-edge.efi",
		"-append", "console=ttyS0,root=/dev/vda1,rw",
		"-chardev", "socket,id=qmp0,path=/run/axonwall/qmp/vm-100.sock,server=on,wait=off",
		"-mon", "chardev=qmp0,mode=control",
		"-fw_cfg", "name=opt/org.axonwall/user-data,file=/run/axonwall/edge/user-data",
		"-object", "memory-backend-memfd,id=mem,size=4096M,share=on",
		"-numa", "node,memdev=mem",
		"-netdev", "tap,id=net0,ifname=tap100i0,script=no,downscript=no",
		"-device", "virtio-net-pci,netdev=net0,mac=52:54:00:00:64:00",
		"-vga", "std",
	}
	if err := validateSafeQemuArgs(validCompiledArgs); err != nil {
		t.Fatalf("expected valid compiled QEMU args to pass, got: %v", err)
	}

	rejectedArgCases := []struct {
		name string
		args []string
	}{
		{"dotted_file_filename", []string{"-drive", "file.driver=file,file.filename=/etc/shadow"}},
		{"backing_file_filename", []string{"-drive", "file=/dev/zvol/tank/vms/vm-1-disk-0,backing.file.filename=/etc/shadow"}},
		{"disallowed_drive_driver", []string{"-drive", "file.driver=nbd,file.filename=/mnt/tank/img.raw"}},
		{"disallowed_blockdev_flag", []string{"-blockdev", "driver=file,filename=/etc/shadow,node-name=evil"}},
		{"disallowed_object_mem_path", []string{"-object", "memory-backend-file,id=m0,size=1G,mem-path=/etc/shadow"}},
		{"disallowed_chardev_pipe", []string{"-chardev", "pipe,id=p0,path=/run/axonwall/qmp/p"}},
		{"disallowed_chardev_path", []string{"-chardev", "socket,id=c0,path=/tmp/evil.sock"}},
		{"duplicate_fw_cfg_file", []string{"-fw_cfg", "name=opt/a,file=/run/axonwall/fwcfg/a,file=/run/axonwall/fwcfg/b"}},
		{"duplicate_fw_cfg_evil_second", []string{"-fw_cfg", "name=opt/a,file=/run/axonwall/fwcfg/a,file=/etc/shadow"}},
		{"disallowed_romfile", []string{"-device", "virtio-net-pci,romfile=/tmp/evil.rom"}},
	}
	for _, tc := range rejectedArgCases {
		if err := validateSafeQemuArgs(tc.args); err == nil {
			t.Fatalf("expected validateSafeQemuArgs(%s) to reject %v", tc.name, tc.args)
		}
	}

	// 2. Strict LXC allowlist.
	validLxc := strings.Join([]string{
		"# Axonwall compiled LXC config",
		"lxc.uts.name = gw-ct",
		"lxc.arch = amd64",
		"lxc.rootfs.path = zfs:tank/lxc/subvol-200-disk-0",
		"lxc.include = /usr/share/lxc/config/common.conf",
		"lxc.init.cmd = /sbin/init",
		"lxc.cgroup2.memory.max = 2147483648",
		"lxc.net.0.type = veth",
		"lxc.net.0.link = br0",
		"lxc.mount.entry = bpffs sys/fs/bpf bpf defaults 0 0",
		"lxc.idmap = u 0 100000 65536",
	}, "\n")
	if err := validateLxcConfig(validLxc); err != nil {
		t.Fatalf("expected valid LXC config to pass, got: %v", err)
	}
	for _, badLxc := range []string{
		"lxc.mount.fstab = /tmp/evil.fstab",
		"lxc.cgroup2.devices.allow = a",
		"lxc.apparmor.profile = unconfined",
		"lxc.namespace.share.net = 1",
		"lxc.environment = LD_PRELOAD=/tmp/evil.so",
		"not_a_key_value_line",
	} {
		if err := validateLxcConfig(badLxc); err == nil {
			t.Fatalf("expected validateLxcConfig to reject %q", badLxc)
		}
	}

	// 3. ApplyVirtBundleJSON must validate ALL VMs & CTs atomically before persisting/mutating.
	oldSpecsPath := VirtSpecsPath
	VirtSpecsPath = filepath.Join(t.TempDir(), "virt-specs.json")
	t.Cleanup(func() { VirtSpecsPath = oldSpecsPath })

	tm := NewTaskManager()
	nm := NewNasManager()
	vm := NewVirtManager(tm, nm)
	if err := vm.RegisterVMSpec(CompiledVmSpec{
		VMID:   100,
		Name:   "existing",
		Binary: "qemu-system-x86_64",
	}); err != nil {
		t.Fatalf("seed RegisterVMSpec: %v", err)
	}
	beforeDisk, _ := os.ReadFile(VirtSpecsPath)

	badBundle := []byte(`{
		"defaultPool": "fastpool",
		"vms": [{"vmid": 101, "name": "new-valid", "qemuBinary": "qemu-system-x86_64", "args": ["-name", "new-valid"]}],
		"containers": [{"ctid": 201, "name": "evil-ct", "lxcConfig": "lxc.cgroup2.devices.allow = a\n"}]
	}`)
	if err := vm.ApplyVirtBundleJSON(badBundle); err == nil {
		t.Fatalf("expected ApplyVirtBundleJSON with invalid CT to return error")
	}
	if vm.getDefaultPool() != "tank" {
		t.Fatalf("expected failed ApplyVirtBundleJSON not to mutate defaultPool, got %q", vm.getDefaultPool())
	}
	vm.mu.RLock()
	_, has100 := vm.vmSpecs[100]
	_, has101 := vm.vmSpecs[101]
	vm.mu.RUnlock()
	if !has100 || has101 {
		t.Fatalf("expected vmSpecs untouched on atomic failure (has100=%v has101=%v)", has100, has101)
	}
	afterDisk, _ := os.ReadFile(VirtSpecsPath)
	if string(afterDisk) != string(beforeDisk) {
		t.Fatalf("expected persisted specs file unchanged on bundle rejection")
	}

	// 4. RestoreBackup preserves -disk-<N> suffix on VM backups.
	oldMntRoot := virtMntRoot
	virtMntRoot = t.TempDir()
	t.Cleanup(func() { virtMntRoot = oldMntRoot })

	pool := "tank"
	backupDir := filepath.Join(virtMntRoot, pool, "backups")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		t.Fatal(err)
	}
	archiveName := "axonwall-backup-vm-100-20261126-120000-000000001-disk-1.vma.zst"
	archivePath := filepath.Join(backupDir, archiveName)
	if err := os.WriteFile(archivePath, []byte("stub"), 0600); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	zstdLog := filepath.Join(binDir, "zfs.args")
	_ = os.WriteFile(filepath.Join(binDir, "zstd"), []byte("#!/bin/sh\nexit 0\n"), 0755)
	_ = os.WriteFile(filepath.Join(binDir, "zfs"), []byte("#!/bin/sh\necho \"$@\" > "+zstdLog+"\nexit 0\n"), 0755)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	upid, rErr := vm.RestoreBackup(archiveName, "vm", 100, pool, "root@axonwall")
	if rErr != nil {
		t.Fatalf("RestoreBackup failed: %v", rErr)
	}
	rec := bughunt3WaitTask(t, tm, upid)
	if rec.Status != "stopped" || rec.ExitStatus != "OK" {
		t.Fatalf("RestoreBackup task failed: status=%s exit=%s", rec.Status, rec.ExitStatus)
	}
	gotZfs, _ := os.ReadFile(zstdLog)
	if !strings.Contains(string(gotZfs), "tank/vms/vm-100-disk-1") {
		t.Fatalf("expected RestoreBackup to target disk-1 dataset, got zfs args %q", string(gotZfs))
	}

	// 5. StopVM must verify /proc/<pid>/cmdline before signaling pidfile PID.
	oldProc := procRootDir
	fakeProc := t.TempDir()
	procRootDir = fakeProc
	t.Cleanup(func() { procRootDir = oldProc })

	oldPidDir := virtPidDir
	virtPidDir = t.TempDir()
	t.Cleanup(func() { virtPidDir = oldPidDir })

	myPid := os.Getpid()
	if err := os.MkdirAll(filepath.Join(fakeProc, strconv.Itoa(myPid)), 0755); err != nil {
		t.Fatal(err)
	}
	// Write non-QEMU cmdline for our own PID: if StopVM blindly killed it, this test process would die!
	_ = os.WriteFile(filepath.Join(fakeProc, strconv.Itoa(myPid), "cmdline"), []byte("/usr/sbin/sshd\x00-D\x00"), 0644)
	pidFile := filepath.Join(virtPidDir, "vm-998.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(myPid)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	upid, sErr := vm.StopVM(998, true, "root@axonwall")
	if sErr != nil {
		t.Fatalf("StopVM failed: %v", sErr)
	}
	_ = bughunt3WaitTask(t, tm, upid)
	if _, statErr := os.Stat(pidFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected StopVM to remove stale pidfile %s", pidFile)
	}
}

func TestSliceC_WatchdogGuardsZbmFallbackAndBtrfsSnapshot(t *testing.T) {
	// 1. Host/rolling modes block grubenv writes, ActivateSlot, TriggerRollback, ApplyFirmwareUpdate.
	for _, mode := range []string{"host", "rolling"} {
		grubPath := filepath.Join(t.TempDir(), "grubenv")
		cmdlinePath := filepath.Join(t.TempDir(), "cmdline")
		if mode == "host" {
			_ = os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz root=UUID=1234 ro\n"), 0644)
		} else {
			_ = os.WriteFile(cmdlinePath, []byte("BOOT_IMAGE=/vmlinuz axon_rolling=1 ro\n"), 0644)
		}
		we := NewWatchdogEngineCustom(grubPath, cmdlinePath)
		we.mu.Lock()
		we.status.InstallMode = mode
		we.mu.Unlock()

		if err := we.writeGrubEnvKey("active_slot", "B"); err == nil {
			t.Fatalf("expected writeGrubEnvKey rejected in %s mode", mode)
		}
		if err := we.ActivateSlot("B"); err == nil {
			t.Fatalf("expected ActivateSlot rejected in %s mode", mode)
		}
		if err := we.TriggerRollback(); err == nil {
			t.Fatalf("expected TriggerRollback rejected in %s mode", mode)
		}
		if _, err := we.ApplyFirmwareUpdate("B", "0.16.3"); err == nil {
			t.Fatalf("expected ApplyFirmwareUpdate rejected in %s mode", mode)
		}
	}

	// 2. detectRunningSlotFromCmdline handles both rootfsB=1/rootfsA=0 and LABEL=axon_root_b.
	cmdB1 := filepath.Join(t.TempDir(), "cmdline-b1")
	_ = os.WriteFile(cmdB1, []byte("BOOT_IMAGE=/vmlinuz rootfsA=0 rootfsB=1 slot=B\n"), 0644)
	if slot, ok := detectRunningSlotFromCmdline(cmdB1); !ok || slot != "B" {
		t.Fatalf("expected slot B from rootfsB=1, got (%q, %v)", slot, ok)
	}
	cmdB2 := filepath.Join(t.TempDir(), "cmdline-b2")
	_ = os.WriteFile(cmdB2, []byte("BOOT_IMAGE=/vmlinuz root=LABEL=axon_root_b ro\n"), 0644)
	if slot, ok := detectRunningSlotFromCmdline(cmdB2); !ok || slot != "B" {
		t.Fatalf("expected slot B from axon_root_b, got (%q, %v)", slot, ok)
	}

	// 3. ZBM TriggerRollback prefers valid non-running fallback_be over newer standby BE.
	grubPath := filepath.Join(t.TempDir(), "grubenv")
	_ = os.WriteFile(grubPath, []byte("# GRUB Environment Block\nfallback_be=zroot/ROOT/axonwall-0.15.9\n"), 0600)
	cmdZbm := filepath.Join(t.TempDir(), "cmdline-zbm")
	_ = os.WriteFile(cmdZbm, []byte("zfs=zroot/ROOT/axonwall-0.16.2 ro\n"), 0644)
	we := NewWatchdogEngineCustom(grubPath, cmdZbm)
	var activated string
	we.runZpoolCmd = func(args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "set" {
			activated = args[1]
		}
		return []byte{}, nil
	}
	we.runZfsCmd = func(args ...string) ([]byte, error) {
		return []byte{}, nil
	}
	we.mu.Lock()
	we.status.InstallMode = "zbm"
	we.status.ZbmPoolName = "zroot"
	we.status.ActiveRootDevice = "zroot/ROOT/axonwall-0.16.2"
	we.status.BootEnvironments = []ZfsBootEnvironment{
		{Name: "axonwall-0.16.2", Dataset: "zroot/ROOT/axonwall-0.16.2", ActiveNow: true},
		{Name: "axonwall-0.16.1", Dataset: "zroot/ROOT/axonwall-0.16.1", ActiveNow: false},
		{Name: "axonwall-0.15.9", Dataset: "zroot/ROOT/axonwall-0.15.9", ActiveNow: false},
	}
	we.mu.Unlock()
	if err := we.TriggerRollback(); err != nil {
		t.Fatalf("TriggerRollback ZBM failed: %v", err)
	}
	if activated != "bootfs=zroot/ROOT/axonwall-0.15.9" {
		t.Fatalf("expected fallback_be axonwall-0.15.9 activated first, got %q", activated)
	}

	// 4. Btrfs selectBtrfsRollbackSnapshotID prefers latest "pre" (or PreNum) snapshot over single.
	snaps := []BtrfsSnapperSnapshot{
		{ID: 1, Type: "single", Bootable: true},
		{ID: 5, Type: "pre", Bootable: true},
		{ID: 6, Type: "post", PreNum: 5, Bootable: true},
		{ID: 9, Type: "single", Bootable: true},
	}
	if got := selectBtrfsRollbackSnapshotID(snaps); got != 5 {
		t.Fatalf("expected latest pre snapshot ID 5, got %d", got)
	}
	snapsPostOnly := []BtrfsSnapperSnapshot{
		{ID: 2, Type: "single", Bootable: true},
		{ID: 4, Type: "post", PreNum: 3, Bootable: true},
	}
	if got := selectBtrfsRollbackSnapshotID(snapsPostOnly); got != 3 {
		t.Fatalf("expected PreNum snapshot ID 3 fallback, got %d", got)
	}
}

func TestSliceC_McpTrafficClassIdIpv6ConntrackAndSinkhole(t *testing.T) {
	dir := t.TempDir()
	conntrackArgs := filepath.Join(dir, "conntrack.args")
	bughunt3WriteFakeBin(t, dir, "nft", "#!/bin/sh\nexit 0\n")
	bughunt3WriteFakeBin(t, dir, "tc", "#!/bin/sh\necho 'RTNETLINK answers: Operation not permitted' >&2\nexit 1\n")
	bughunt3WriteFakeBin(t, dir, "ip", "#!/bin/sh\nexit 0\n")
	bughunt3WriteFakeBin(t, dir, "conntrack", "#!/bin/sh\necho \"$@\" > "+conntrackArgs+"\nexit 0\n")
	bughunt3WriteFakeBin(t, dir, "unbound-control", "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	origState := mcpStateFilePath
	mcpStateFilePath = filepath.Join(t.TempDir(), "mcp-state.json")
	t.Cleanup(func() { mcpStateFilePath = origState })

	origSink := unboundMcpSinkholePath
	unboundMcpSinkholePath = filepath.Join(t.TempDir(), "unbound.conf.d", "mcp-sinkhole.conf")
	t.Cleanup(func() { unboundMcpSinkholePath = origSink })

	// 1. ClassID remains reserved during pendingCleanup until retryPendingCleanups succeeds.
	lease := &McpTacticalLease{
		ID:         "lease-cls",
		Kind:       "shape",
		ClassID:    500,
		FwMark:     0x1f4,
		ExpiresAt:  time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Parameters: map[string]any{"interface": "lo"},
	}
	mgr := &McpTrafficManager{
		leases:           map[string]*McpTacticalLease{lease.ID: lease},
		reservedClassIDs: map[int]struct{}{},
	}
	if _, err := mgr.RevertLease(lease.ID); !errors.Is(err, ErrMcpKernelCleanupFailed) {
		t.Fatalf("expected ErrMcpKernelCleanupFailed, got %v", err)
	}
	mgr.mu.Lock()
	nextWhilePending, allocErr := mgr.allocClassIDLocked()
	mgr.releaseClassIDLocked(nextWhilePending)
	mgr.mu.Unlock()
	if allocErr != nil {
		t.Fatalf("allocClassIDLocked while pending failed: %v", allocErr)
	}
	if nextWhilePending == 500 {
		t.Fatalf("expected ClassID 500 to stay reserved while pendingCleanup holds lease, got %d", nextWhilePending)
	}
	bughunt3WriteFakeBin(t, dir, "tc", "#!/bin/sh\nexit 0\n")
	mgr.retryPendingCleanups()
	mgr.mu.Lock()
	nextAfterCleanup, allocErr2 := mgr.allocClassIDLocked()
	mgr.mu.Unlock()
	if allocErr2 != nil {
		t.Fatalf("allocClassIDLocked after cleanup failed: %v", allocErr2)
	}
	if nextAfterCleanup != 500 {
		t.Fatalf("expected ClassID 500 released after retryPendingCleanups succeeded, got %d", nextAfterCleanup)
	}

	// 2. killConntrackEntries passes -f ipv6 for IPv6 targets.
	if err := killConntrackEntries("2001:db8::1"); err != nil {
		t.Fatalf("killConntrackEntries IPv6 failed: %v", err)
	}
	ctOut, _ := os.ReadFile(conntrackArgs)
	if !strings.Contains(string(ctOut), "-f ipv6") || !strings.Contains(string(ctOut), "2001:db8::1") {
		t.Fatalf("expected -f ipv6 in conntrack args, got %q", string(ctOut))
	}

	// 3. SinkholeDNS canonicalizes IPv4-mapped IPv6 sinkIP (::ffff:10.0.0.55 -> 10.0.0.55).
	if _, err := mgr.SinkholeDNS(McpDnsSinkholeReq{
		Domain:     "malware.example.test",
		SinkholeIP: "::ffff:10.0.0.55",
		TTLSeconds: 60,
		KeyID:      "k1",
		KeyName:    "test",
	}); err != nil {
		t.Fatalf("SinkholeDNS failed: %v", err)
	}
	sinkConf, _ := os.ReadFile(unboundMcpSinkholePath)
	if !strings.Contains(string(sinkConf), `"malware.example.test. 60 IN A 10.0.0.55"`) {
		t.Fatalf("expected canonical IPv4 local-data A record in sinkhole conf, got:\n%s", string(sinkConf))
	}
}

func TestSliceC_PacketStreamAndAndSingleWait(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "tcpdump.args")
	script := "#!/bin/sh\n" +
		"i=1\n" +
		"rm -f " + argsFile + "\n" +
		"for a in \"$@\"; do printf '[%s]\\n' \"$a\" >> " + argsFile + "; done\n" +
		"echo '1700000000.000000 IP 192.0.2.10.12345 > 198.51.100.20.443: tcp 0'\n"
	if err := os.WriteFile(filepath.Join(dir, "tcpdump"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	mgr := NewPacketStreamManager(NewPacketCaptureManager())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stream?interface=lo&srcIp=192.0.2.10&dstIp=198.51.100.20&port=443&protocol=tcp", nil).WithContext(ctx)
	rec := newSyncFlushingSSERecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		mgr.HandleStreamSSE(rec, req)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("HandleStreamSSE timed out")
	}

	gotArgs, _ := os.ReadFile(argsFile)
	wantClause := "[src host 192.0.2.10 and dst host 198.51.100.20 and port 443 and tcp]"
	if !strings.Contains(string(gotArgs), wantClause) {
		t.Fatalf("expected single BPF expression %s, got args:\n%s", wantClause, string(gotArgs))
	}
	if !strings.Contains(rec.String(), "event: packet") {
		t.Fatalf("expected streamed SSE packet event, got:\n%s", rec.String())
	}
}

func TestSliceC_VfioNegativeSriovResetErrAndBindRollback(t *testing.T) {
	root := t.TempDir()
	bdf := "0000:02:00.0"
	devDir := filepath.Join(root, "bus", "pci", "devices", bdf)
	vfioDir := filepath.Join(root, "bus", "pci", "drivers", "vfio-pci")
	if err := os.MkdirAll(devDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(vfioDir, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(devDir, "driver_override"), []byte(""), 0644)
	_ = os.WriteFile(filepath.Join(devDir, "sriov_totalvfs"), []byte("4\n"), 0644)
	_ = os.WriteFile(filepath.Join(devDir, "sriov_numvfs"), []byte("2\n"), 0444) // read-only triggers reset write failure
	_ = os.WriteFile(filepath.Join(vfioDir, "bind"), []byte(""), 0444)         // read-only triggers bind failure
	_ = os.WriteFile(filepath.Join(root, "bus", "pci", "rescan"), []byte("0"), 0644)

	mgr := &VFIOManager{sysfsRoot: root}

	// 1. Negative numVfs must fail.
	if err := mgr.ConfigureSriov(bdf, -1); err == nil {
		t.Fatalf("expected ConfigureSriov(-1) to fail")
	}
	// 2. Read-only sriov_numvfs reset write error must propagate.
	if err := mgr.ConfigureSriov(bdf, 2); err == nil {
		t.Fatalf("expected ConfigureSriov reset write error to propagate")
	}
	// 3. BindVfio failure clears driver_override and pokes rescan.
	if err := mgr.BindVfio(bdf); err == nil {
		t.Fatalf("expected BindVfio against read-only bind file to fail")
	}
	overrideVal, _ := os.ReadFile(filepath.Join(devDir, "driver_override"))
	if strings.TrimSpace(string(overrideVal)) != "" {
		t.Fatalf("expected driver_override cleared after bind failure, got %q", string(overrideVal))
	}
	rescanVal, _ := os.ReadFile(filepath.Join(root, "bus", "pci", "rescan"))
	if string(rescanVal) != "1" {
		t.Fatalf("expected pci rescan triggered after bind failure, got %q", string(rescanVal))
	}
}

func TestSliceC_VigilanteAtomicNormalizePruneAndRotation(t *testing.T) {
	// 1. writeFilesAtomic removes staged temp files on subsequent failure.
	tmpDir := t.TempDir()
	goodTarget := filepath.Join(tmpDir, "first.conf")
	badTarget := filepath.Join(tmpDir, "missing-dir", "second.conf")
	if err := writeFilesAtomic([]atomicFileWrite{
		{path: goodTarget, content: "ok\n", perm: 0600},
		{path: badTarget, content: "fail\n", perm: 0600},
	}); err == nil {
		t.Fatalf("expected writeFilesAtomic to fail when second dir is missing")
	}
	entries, _ := os.ReadDir(tmpDir)
	if len(entries) != 0 {
		t.Fatalf("expected failed writeFilesAtomic to clean all temp files in %s, found %d", tmpDir, len(entries))
	}

	// 2. BlockIP normalizes ::ffff: IPv4-mapped address and prunes expired blockedIPs.
	binDir := t.TempDir()
	nftLog := filepath.Join(binDir, "nft.args")
	_ = os.WriteFile(filepath.Join(binDir, "nft"), []byte("#!/bin/sh\necho \"$@\" > "+nftLog+"\nexit 0\n"), 0755)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	vm := NewVigilanteManager(t.TempDir())
	vm.mu.Lock()
	vm.blockedIPs["203.0.113.5"] = BlockedIPRecord{
		IP:        "203.0.113.5",
		Family:    "ipv4",
		BlockedAt: time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
	}
	vm.mu.Unlock()

	if err := vm.BlockIP("::ffff:198.51.100.77", 60); err != nil {
		t.Fatalf("BlockIP failed: %v", err)
	}
	gotNft, _ := os.ReadFile(nftLog)
	if !strings.Contains(string(gotNft), "vigilante_soar_blocklist_v4") || !strings.Contains(string(gotNft), "198.51.100.77") {
		t.Fatalf("expected ::ffff: normalized to v4 blocklist & IP, got %q", string(gotNft))
	}
	active := vm.ListBlockedIPs()
	if len(active) != 1 || active[0].IP != "198.51.100.77" || active[0].Family != "ipv4" {
		t.Fatalf("expected expired pruned and only 198.51.100.77 active, got %+v", active)
	}

	// 3. StreamLiveTelemetry retries missing eve.json, reads from start when it appears,
	//    and seeks to io.SeekStart on rotation.
	logDir := t.TempDir()
	evePath := filepath.Join(logDir, "eve.json")
	vm.telemetryLog = evePath

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vigilante/stream", nil).WithContext(ctx)
	rec := newSyncFlushingSSERecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		vm.StreamLiveTelemetry(rec, req)
	}()

	time.Sleep(150 * time.Millisecond)
	_ = os.WriteFile(evePath, []byte(`{"src_ip":"192.0.2.1","dest_ip":"198.51.100.1","alert":{"signature":"INIT_SIG","severity":1}}`+"\n"), 0644)

	waitForSSE := func(needle string) bool {
		deadline := time.Now().Add(2500 * time.Millisecond)
		for time.Now().Before(deadline) {
			if strings.Contains(rec.String(), needle) {
				return true
			}
			time.Sleep(30 * time.Millisecond)
		}
		return false
	}
	if !waitForSSE("INIT_SIG") {
		cancel()
		<-done
		t.Fatalf("expected initial late-created eve.json alert INIT_SIG, got:\n%s", rec.String())
	}

	rotatedNew := filepath.Join(logDir, "eve.json.new")
	_ = os.WriteFile(rotatedNew, []byte(`{"src_ip":"192.0.2.2","dest_ip":"198.51.100.2","alert":{"signature":"ROTATED_SIG","severity":2}}`+"\n"), 0644)
	if err := os.Rename(rotatedNew, evePath); err != nil {
		t.Fatal(err)
	}
	if !waitForSSE("ROTATED_SIG") {
		cancel()
		<-done
		t.Fatalf("expected rotated eve.json alert ROTATED_SIG via io.SeekStart, got:\n%s", rec.String())
	}
	cancel()
	<-done
}

func TestSliceC_NoVncOriginAndControlFrameLimits(t *testing.T) {
	tlsReq := httptest.NewRequest(http.MethodGet, "https://gw.local/ws", nil)
	tlsReq.Host = "gw.local"
	tlsReq.TLS = &tls.ConnectionState{}

	if !validateConsoleOrigin("https://GW.LOCAL", tlsReq) {
		t.Fatalf("expected matching HTTPS origin to succeed")
	}
	for _, badOrigin := range []string{
		"http://gw.local",
		"https://gw.local:8443",
		"https://gw.local.evil.com",
		"null",
		"https://evil.example",
	} {
		if validateConsoleOrigin(badOrigin, tlsReq) {
			t.Fatalf("expected origin %q to be rejected for %s", badOrigin, tlsReq.Host)
		}
	}

	// RFC 6455 control frames must reject >125-byte payloads or fragmented frames.
	oversized := bytes.Repeat([]byte("P"), 126)
	if err := writeWSFrame(io.Discard, oversized, 0x9); err == nil {
		t.Fatalf("expected writeWSFrame to reject 126-byte Ping")
	}
	if err := writeWSFrame(io.Discard, oversized, 0xA); err == nil {
		t.Fatalf("expected writeWSFrame to reject 126-byte Pong")
	}

	// Craft incoming masked/unmasked 126-byte Ping wire frame and verify readWSFrame rejects it.
	var wire bytes.Buffer
	wire.Write([]byte{0x89, 126, 0x00, 126})
	wire.Write(oversized)
	if _, _, _, err := readWSFrame(&wire); err == nil {
		t.Fatalf("expected readWSFrame to reject 126-byte Ping frame")
	}

	// Fragmented Ping (FIN=0, opcode=0x9).
	fragPing := bytes.NewReader([]byte{0x09, 0x01, 'a'})
	if _, _, _, err := readWSFrame(fragPing); err == nil {
		t.Fatalf("expected readWSFrame to reject fragmented Ping frame")
	}
}

func TestSliceC_NasAndZfsSpecialSmallBlocks(t *testing.T) {
	basePool := ZfsPoolSpec{
		Name:        "tank",
		Topology:    "mirror",
		DataDisks:   []string{"/dev/sda", "/dev/sdb"},
		Compression: "lz4",
	}
	for _, good := range []string{"", "0", "16K", "64K", "1M"} {
		p := basePool
		p.SpecialSmallBlocks = good
		if err := ValidateZfsPoolSpec(p); err != nil {
			t.Fatalf("expected SpecialSmallBlocks=%q valid in ValidateZfsPoolSpec: %v", good, err)
		}
		if err := ValidateInstallZfsPoolSpec(p); err != nil {
			t.Fatalf("expected SpecialSmallBlocks=%q valid in ValidateInstallZfsPoolSpec: %v", good, err)
		}
	}
	for _, bad := range []string{"16k", "999G", "-o evil=1", "16K;id"} {
		p := basePool
		p.SpecialSmallBlocks = bad
		if err := ValidateZfsPoolSpec(p); err == nil {
			t.Fatalf("expected SpecialSmallBlocks=%q rejected in ValidateZfsPoolSpec", bad)
		}
		if err := ValidateInstallZfsPoolSpec(p); err == nil {
			t.Fatalf("expected SpecialSmallBlocks=%q rejected in ValidateInstallZfsPoolSpec", bad)
		}
	}
}

func TestSliceC_TopologyConfirmGuardAndTargetedPatch(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	var appliedState map[string]any
	peerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/state":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"hostname": "old-peer",
				"dns":      map[string]any{"upstream": "1.1.1.1"},
			})
		case "/api/v1/apply":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			appliedState = body
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case "/api/v1/confirm":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer peerSrv.Close()

	cfgDir := t.TempDir()
	tm := NewTopologyManager(cfgDir, nil, nil, nil, nil, nil)
	tm.SetAllowLoopbackForTest(true)
	tm.svcRunner = func(context.Context, string) error { return nil }
	rawCfg, _ := json.Marshal(TopologyRuntimeBundle{
		Enabled: true,
		Config: TopologyConfigPayload{
			Enabled: true,
			Peers: []TopologyPeerHostPayload{
				{ID: "peer-1", Name: "Peer 1", Role: "edge", APIURL: peerSrv.URL, Enabled: true},
			},
		},
	})
	if err := tm.ApplyConfig(rawCfg); err != nil {
		t.Fatalf("ApplyConfig failed: %v", err)
	}

	ctx := context.Background()

	// 1. Targeted Patch/Hostname merges with existing peer state, and HasLocalChanges=false
	//    does NOT auto-confirm peer without AutoConfirmPeers=true.
	res, err := tm.ApplyFabricPlan(ctx, &TopologyApplyRequest{
		HasLocalChanges: false,
		PeerEdits: []TopologyPeerEdit{
			{
				PeerID:   "peer-1",
				Hostname: "new-edge",
				Patch:    json.RawMessage(`{"mtu":1500}`),
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("ApplyFabricPlan targeted edit failed: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected ApplyFabricPlan success, got %+v", res)
	}
	mu.Lock()
	gotCalls := append([]string(nil), calls...)
	gotState := appliedState
	calls = nil
	mu.Unlock()

	if len(gotCalls) != 2 || gotCalls[0] != "GET /api/v1/state" || gotCalls[1] != "POST /api/v1/apply" {
		t.Fatalf("expected GET state + POST apply without auto-confirm, got %v", gotCalls)
	}
	stateMap, _ := gotState["state"].(map[string]any)
	sysMap, _ := stateMap["system"].(map[string]any)
	if stateMap == nil || sysMap["hostname"] != "new-edge" || stateMap["mtu"] != float64(1500) {
		t.Fatalf("expected merged system.hostname & mtu under apply payload state, got %v", gotState)
	}
	if _, ok := stateMap["dns"]; !ok {
		t.Fatalf("expected existing peer fields preserved during patch merge, got %v", gotState)
	}

	// 2. Explicit AutoConfirmPeers=true triggers POST /api/v1/confirm when HasLocalChanges=false.
	_, err = tm.ApplyFabricPlan(ctx, &TopologyApplyRequest{
		HasLocalChanges:  false,
		AutoConfirmPeers: true,
		PeerEdits: []TopologyPeerEdit{
			{PeerID: "peer-1", State: json.RawMessage(`{"hostname":"explicit-confirm"}`)},
		},
	}, nil)
	if err != nil {
		t.Fatalf("ApplyFabricPlan AutoConfirmPeers failed: %v", err)
	}
	mu.Lock()
	gotConfirmCalls := strings.Join(calls, ",")
	mu.Unlock()
	if !strings.Contains(gotConfirmCalls, "POST /api/v1/confirm") {
		t.Fatalf("expected POST /api/v1/confirm when AutoConfirmPeers=true, got %s", gotConfirmCalls)
	}
}
