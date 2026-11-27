package engine

import (
	"fmt"
	"os"
	"path/filepath"
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
	oldPath := VirtSpecsPath
	VirtSpecsPath = filepath.Join(t.TempDir(), "virt-specs.json")
	defer func() { VirtSpecsPath = oldPath }()

	taskMgr := NewTaskManager()
	nasMgr := NewNasManager()
	virtMgr := NewVirtManager(taskMgr, nasMgr)

	if err := virtMgr.RegisterVMSpec(CompiledVmSpec{
		VMID:      105,
		Name:      "database-vm",
		Binary:    "qemu-system-x86_64",
		Cores:     4,
		MemoryMb:  8192,
		Autostart: true,
		Bridges:   map[string]string{"tap105i0": "br-lan"},
		FwCfg:     map[string]string{"/run/axonwall/fwcfg/test": "secret"},
		Args:      []string{"-name", "database-vm", "-netdev", "tap,id=net0,ifname=tap105i0,script=no"},
		Disks: []VmDisk{
			{Name: "disk0", Pool: "tank", SizeGb: 100},
		},
	}); err != nil {
		t.Fatalf("RegisterVMSpec valid spec: %v", err)
	}

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

	// Verify persistence across VirtManager reloads
	virtMgr2 := NewVirtManager(taskMgr, nasMgr)
	vms2 := virtMgr2.ListVMs()
	if len(vms2) != 1 || vms2[0].VMID != 105 {
		t.Fatalf("expected persisted VM 105 after reload, got: %+v", vms2)
	}

	virtMgr2.UnregisterVMSpec(105)
	if len(virtMgr2.ListVMs()) != 0 {
		t.Fatalf("expected 0 VMs after UnregisterVMSpec")
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

func TestVirtHelpers(t *testing.T) {
	args := []string{
		"-name", "edge",
		"-netdev", "tap,id=wan,ifname=tap-edge-wan,script=no,downscript=no",
		"-netdev", "tap,id=lan,ifname=tap-edge-lan,script=no,downscript=no",
	}
	taps := extractTapDevicesFromArgs(args)
	if len(taps) != 2 || taps[0] != "tap-edge-wan" || taps[1] != "tap-edge-lan" {
		t.Fatalf("unexpected taps extracted: %v", taps)
	}

	withDaemon := ensureDaemonizeArg(args)
	if withDaemon[len(withDaemon)-1] != "-daemonize" {
		t.Fatalf("expected -daemonize appended, got: %v", withDaemon)
	}
	again := ensureDaemonizeArg(withDaemon)
	if len(again) != len(withDaemon) {
		t.Fatalf("expected -daemonize not to be duplicated")
	}

	tmpFwFile := filepath.Join("/run/axonwall/fwcfg", "unit-test-userdata")
	defer os.Remove(tmpFwFile)
	if err := writeFwCfgFiles(map[string]string{tmpFwFile: "#cloud-config\n"}); err == nil {
		info, statErr := os.Stat(tmpFwFile)
		if statErr != nil {
			t.Fatalf("expected fw_cfg file to exist: %v", statErr)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 permissions on fw_cfg file, got %o", info.Mode().Perm())
		}
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

func TestVirtQemuSocketAndMemPathHardening(t *testing.T) {
	badSockets := []string{
		"/run/axonwall/ha.sock",
		"/run/axonwall/caddy-admin.sock",
		"/run/axonwall/agent-api.sock",
		"/run/axonwall/qmp/evil.sock",
		"/run/axonwall/qmp/sub/vm-100.sock",
		"/run/axonwall/pids/vm-100.pid",
		"/tmp/vm-100.sock",
	}
	for _, s := range badSockets {
		if isAllowedQemuSocketPath(s) {
			t.Fatalf("expected socket path %q to be rejected", s)
		}
	}

	goodSockets := []string{
		"/run/axonwall/qmp/vm-100.sock",
		"/run/axonwall/serial/vm-100.sock",
		"/run/axonwall/virtiofs/vm-100-data.sock",
		"/run/axonwall/tpm/vm-100.sock",
		"/run/axonwall/swtpm/vm-100.sock",
	}
	for _, s := range goodSockets {
		if !isAllowedQemuSocketPathForVM(s, 100, "") {
			t.Fatalf("expected socket path %q to be allowed for VM 100", s)
		}
		if isAllowedQemuSocketPathForVM(s, 200, "") {
			t.Fatalf("expected cross-VM socket path %q to be rejected for VM 200", s)
		}
	}

	// Cross-VM socket, -qmp, -serial, -vnc, -pidfile rejected when validated for VM 100.
	crossVMArgs := [][]string{
		{"-chardev", "socket,id=c0,path=/run/axonwall/qmp/vm-200.sock,server=on,wait=off"},
		{"-qmp", "unix:/run/axonwall/qmp/vm-200.sock,server,nowait"},
		{"-serial", "unix:/run/axonwall/serial/vm-200.sock,server,nowait"},
		{"-vnc", "unix:/run/axonwall/vnc/vm-200.sock"},
		{"-pidfile", "/run/axonwall/pids/vm-200.pid"},
	}
	for _, args := range crossVMArgs {
		if err := validateSafeQemuArgsForVM(args, 100); err == nil {
			t.Fatalf("expected cross-VM args %v to fail for VM 100", args)
		}
	}

	// mem-path must reject /run/axonwall/* and allow only /dev/hugepages/.
	if isAllowedQemuMemPath("/run/axonwall/ha.sock") || isAllowedQemuMemPath("/run/axonwall/mem") {
		t.Fatal("expected /run/axonwall/* mem-path to be rejected")
	}
	if !isAllowedQemuMemPath("/dev/hugepages/vm-100") {
		t.Fatal("expected /dev/hugepages/vm-100 mem-path to be allowed")
	}
}

func TestVirtDriveAndLxcPathSymlinkHardening(t *testing.T) {
	badDrives := []string{
		"/var/lib/axonwall/secrets/ha-pki/ca.key",
		"/var/lib/axonwall/core-k3s/token",
		"/var/lib/axonwall/state.json",
		"/var/lib/axonwall/virt-specs.json",
		"/var/lib/axonwall/ldap/data/data.mdb",
		"/run/axonwall/ha.sock",
	}
	for _, d := range badDrives {
		if isAllowedQemuDrivePath(d) {
			t.Fatalf("expected drive path %q to be rejected", d)
		}
		if err := validateSafeQemuArgs([]string{"-drive", "file=" + d + ",format=raw"}); err == nil {
			t.Fatalf("expected -drive %s to be rejected", d)
		}
	}
	for _, good := range []string{
		"/var/lib/axonwall/vms/vm-100.qcow2",
		"/var/lib/axonwall/isos/debian.iso",
		"/mnt/tank/vm-100.raw",
		"/dev/zvol/tank/vms/vm-100-disk-0",
	} {
		if !isAllowedQemuDrivePath(good) {
			t.Fatalf("expected drive path %q to be allowed", good)
		}
	}

	// LXC rootfs and mount entries cannot target /var/lib/axonwall/{secrets,core-k3s,state.json}.
	badLxc := []string{
		"lxc.rootfs.path = dir:/var/lib/axonwall/secrets",
		"lxc.rootfs.path = dir:/var/lib/axonwall/core-k3s",
		"lxc.rootfs.path = /var/lib/axonwall/state.json",
		"lxc.mount.entry = /var/lib/axonwall/secrets secrets none ro,bind,create=dir 0 0",
		"lxc.mount.entry = /var/lib/axonwall/state.json state.json none ro,bind 0 0",
		"lxc.mount.entry = /var/lib/axonwall/core-k3s k3s none rw,bind 0 0",
	}
	for _, cfg := range badLxc {
		if err := validateLxcConfig(cfg); err == nil {
			t.Fatalf("expected LXC config %q to be rejected", cfg)
		}
	}
	goodLxc := strings.Join([]string{
		"lxc.rootfs.path = dir:/var/lib/axonwall/vms/ct-201",
		"lxc.mount.entry = /var/lib/axonwall/isos isos none ro,bind,create=dir 0 0",
		"lxc.mount.entry = /mnt/tank/data data none rw,bind,create=dir 0 0",
	}, "\n")
	if err := validateLxcConfig(goodLxc); err != nil {
		t.Fatalf("expected valid LXC config to pass, got: %v", err)
	}

	// virtiofsd sh.HostPath must resolve symlinks before checking under virtMntRoot.
	tmpRoot := t.TempDir()
	mntDir := filepath.Join(tmpRoot, "mnt")
	outsideDir := filepath.Join(tmpRoot, "secrets")
	realShare := filepath.Join(mntDir, "tank", "share")
	if err := os.MkdirAll(realShare, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0755); err != nil {
		t.Fatal(err)
	}
	symEscape := filepath.Join(mntDir, "escape")
	if err := os.Symlink(outsideDir, symEscape); err != nil {
		t.Fatal(err)
	}
	oldMnt := virtMntRoot
	virtMntRoot = mntDir
	t.Cleanup(func() { virtMntRoot = oldMnt })

	resolved, err := resolveSafeVirtioFsHostPath(realShare)
	if err != nil {
		t.Fatalf("expected valid virtiofs share to pass, got: %v", err)
	}
	if resolved != realShare {
		t.Fatalf("expected resolved path %q, got %q", realShare, resolved)
	}
	if _, err := resolveSafeVirtioFsHostPath(symEscape); err == nil {
		t.Fatal("expected symlink escaping virtMntRoot to be rejected")
	}
	if _, err := validateAndNormalizeVMSpec(CompiledVmSpec{
		VMID:           100,
		Name:           "vfs-escape",
		Binary:         "qemu-system-x86_64",
		VirtioFsShares: []VirtioFsShareSpec{{Tag: "esc", HostPath: symEscape}},
	}); err == nil {
		t.Fatal("expected validateAndNormalizeVMSpec to reject symlink virtiofs escape")
	}
}

func TestVirtLxcBpffsDelegateAllowlist(t *testing.T) {
	valid := "lxc.mount.entry = bpffs sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,create=dir,delegate_cmds=prog_load:map_create:btf_load,delegate_progs=xdp:sched_cls:sched_act:socket_filter:cgroup_skb:cgroup_sock_addr:sk_skb:sk_msg,delegate_maps=array:hash,delegate_attachs=xdp:tcx_ingress 0 0\n"
	if err := validateLxcConfig(valid); err != nil {
		t.Fatalf("expected valid safe networking bpffs config to pass, got: %v", err)
	}

	rejected := []string{
		"lxc.mount.entry = bpffs sys/fs/bpf bpf delegate_progs=kprobe 0 0",
		"lxc.mount.entry = bpffs sys/fs/bpf bpf delegate_progs=lsm 0 0",
		"lxc.mount.entry = bpffs sys/fs/bpf bpf delegate_progs=tracing 0 0",
		"lxc.mount.entry = bpffs sys/fs/bpf bpf delegate_progs=any 0 0",
		"lxc.mount.entry = bpffs sys/fs/bpf bpf delegate_cmds=any 0 0",
		"lxc.mount.entry = bpffs sys/fs/bpf bpf delegate_cmds=* 0 0",
		"lxc.mount.entry = bpffs sys/fs/bpf bpf delegate_progs= 0 0",
		"lxc.mount.entry = bpffs sys/fs/bpf bpf rw,suid 0 0",
		"lxc.mount.entry = bpffs sys/fs/bpf bpf evil_opt=1 0 0",
		"lxc.mount.entry = /tmp/bpffs custom/bpf bpf defaults 0 0",
	}
	for _, cfg := range rejected {
		if err := validateLxcConfig(cfg); err == nil {
			t.Fatalf("expected bpffs config %q to be rejected", cfg)
		}
	}
}

func TestVirtLiveMigrateVMTargetValidation(t *testing.T) {
	oldStatePaths := virtPeerStatePaths
	oldTopoPaths := virtTopologyConfigPaths
	oldSpecs := VirtSpecsPath
	tmp := t.TempDir()
	VirtSpecsPath = filepath.Join(tmp, "virt-specs.json")
	virtPeerStatePaths = nil
	virtTopologyConfigPaths = nil
	t.Cleanup(func() {
		virtPeerStatePaths = oldStatePaths
		virtTopologyConfigPaths = oldTopoPaths
		VirtSpecsPath = oldSpecs
	})

	vm := NewVirtManager(NewTaskManager(), NewNasManager())

	// Unconfigured peers: reject public/IMDS/loopback/unspecified IPs.
	for _, badIP := range []string{"8.8.8.8", "1.1.1.1", "192.0.2.1", "169.254.169.254", "127.0.0.1", "0.0.0.0", "fe80::1", "::1"} {
		if _, err := vm.LiveMigrateVM(101, badIP, "admin"); err == nil {
			t.Fatalf("expected unconfigured LiveMigrateVM(%q) to fail", badIP)
		}
	}
	// Private RFC1918 peer passes IP validation when unconfigured (fails on missing QMP socket).
	if _, err := vm.LiveMigrateVM(101, "10.10.0.5", "admin"); err == nil || !strings.Contains(err.Error(), "QMP socket") {
		t.Fatalf("expected private IP to pass target validation and fail on missing QMP socket, got: %v", err)
	}

	// Configured HA/topology peers: enforce strict allowlist membership.
	statePath := filepath.Join(tmp, "state.json")
	topoPath := filepath.Join(tmp, "topo.json")
	if err := os.WriteFile(statePath, []byte(`{"ha":{"peerIp":"10.80.0.2"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(topoPath, []byte(`{"config":{"peers":[{"enabled":true,"apiUrl":"https://10.20.0.50:2966"}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	virtPeerStatePaths = []string{statePath}
	virtTopologyConfigPaths = []string{topoPath}

	for _, unauthIP := range []string{"10.10.0.5", "10.80.0.99", "8.8.8.8", "192.0.2.1"} {
		err := func() error {
			_, e := vm.LiveMigrateVM(101, unauthIP, "admin")
			return e
		}()
		if err == nil || !strings.Contains(err.Error(), "not an authorized HA or topology peer") {
			t.Fatalf("expected unconfigured peer %q to be rejected against HA/topology allowlist, got: %v", unauthIP, err)
		}
	}
	for _, okIP := range []string{"10.80.0.2", "10.20.0.50"} {
		_, err := vm.LiveMigrateVM(101, okIP, "admin")
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("VM %d is not running", 101)) {
			t.Fatalf("expected configured peer %q to pass allowlist and fail on missing QMP socket, got: %v", okIP, err)
		}
	}
}
