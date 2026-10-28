package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type VMStatus struct {
	VMID          int    `json:"vmid"`
	Name          string `json:"name"`
	Status        string `json:"status"` // "running", "stopped", "paused"
	PID           int    `json:"pid"`
	Cores         int    `json:"cores"`
	MemoryMb      int    `json:"memoryMb"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
	QmpSocket     string `json:"qmpSocket"`
	VncSocket     string `json:"vncSocket"`
	SerialSocket  string `json:"serialSocket"`
	AgentRunning  bool   `json:"agentRunning"`
}

type ContainerStatus struct {
	CTID          int    `json:"ctid"`
	Name          string `json:"name"`
	Status        string `json:"status"` // "running", "stopped"
	PID           int    `json:"pid"`
	Cores         int    `json:"cores"`
	MemoryMb      int    `json:"memoryMb"`
	IPAddress     string `json:"ipAddress"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
}

type ISOInfo struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	SizeBytes int64  `json:"sizeBytes"`
	Pool      string `json:"pool"`
}

type BackupRecord struct {
	ID          string `json:"id"`
	VMID        int    `json:"vmid"`
	Type        string `json:"type"` // "vm" or "lxc"
	Name        string `json:"name"`
	Timestamp   int64  `json:"timestamp"`
	SizeBytes   int64  `json:"sizeBytes"`
	Format      string `json:"format"`
	Destination string `json:"destination"`
	Path        string `json:"path"`
}

type VirtManager struct {
	mu           sync.RWMutex
	taskMgr      *TaskManager
	nasMgr       *NasManager
	vmSpecs      map[int]CompiledVmSpec
	ctSpecs      map[int]CompiledCtSpec
	vmStartTimes map[int]int64
	defaultPool  string
}

type CompiledVmSpec struct {
	VMID      int      `json:"vmid"`
	Name      string   `json:"name"`
	Binary    string   `json:"binary"`
	Args      []string `json:"args"`
	Disks     []VmDisk `json:"disks"`
	Cores     int      `json:"cores"`
	MemoryMb  int      `json:"memoryMb"`
	CloudInit *CloudInitSpec
}

type VmDisk struct {
	Name   string `json:"name"`
	Pool   string `json:"pool"`
	SizeGb int    `json:"sizeGb"`
	Zvol   string `json:"zvol"`
}

type CloudInitSpec struct {
	User          string   `json:"user"`
	Password      string   `json:"password"`
	SshKeys       []string `json:"sshKeys"`
	IpConfig      string   `json:"ipConfig"`
	Gateway       string   `json:"gateway"`
	Nameservers   []string `json:"nameservers"`
	CustomPayload string   `json:"customPayload"`
}

type CompiledCtSpec struct {
	CTID       int      `json:"ctid"`
	Hostname   string   `json:"hostname"`
	Cores      int      `json:"cores"`
	MemoryMb   int      `json:"memoryMb"`
	ConfigPath string   `json:"configPath"`
	RootfsPath string   `json:"rootfsPath"`
	Features   []string `json:"features"`
}

func NewVirtManager(taskMgr *TaskManager, nasMgr *NasManager) *VirtManager {
	_ = os.MkdirAll("/run/axonwall/qmp", 0755)
	_ = os.MkdirAll("/run/axonwall/vnc", 0755)
	_ = os.MkdirAll("/run/axonwall/serial", 0755)
	_ = os.MkdirAll("/run/axonwall/pids", 0755)
	_ = os.MkdirAll("/run/axonwall/qga", 0755)
	_ = os.MkdirAll("/run/axonwall/lxc", 0755)
	_ = os.MkdirAll("/var/lib/axonwall/nvram", 0755)
	_ = os.MkdirAll("/var/lib/axonwall/cloudinit", 0755)
	_ = os.MkdirAll("/var/lib/axonwall/isos", 0755)
	_ = os.MkdirAll("/var/lib/axonwall/backups", 0755)

	return &VirtManager{
		taskMgr:      taskMgr,
		nasMgr:       nasMgr,
		vmSpecs:      make(map[int]CompiledVmSpec),
		ctSpecs:      make(map[int]CompiledCtSpec),
		vmStartTimes: make(map[int]int64),
		defaultPool:  "tank",
	}
}

// RegisterVMSpec stores or updates the compiled specification for a VM
func (m *VirtManager) RegisterVMSpec(spec CompiledVmSpec) {
	switch spec.Binary {
	case "", "qemu-system-x86_64", "/usr/bin/qemu-system-x86_64":
		spec.Binary = "/usr/bin/qemu-system-x86_64"
	case "qemu-system-aarch64", "/usr/bin/qemu-system-aarch64":
		spec.Binary = "/usr/bin/qemu-system-aarch64"
	default:
		return
	}
	for _, disk := range spec.Disks {
		if disk.Pool != "" && !validZfsPoolName(disk.Pool) {
			return
		}
		if disk.Zvol != "" && !validZfsPath(disk.Zvol, true) {
			return
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vmSpecs[spec.VMID] = spec
}

// RegisterCTSpec stores or updates the compiled specification for an LXC container
func (m *VirtManager) RegisterCTSpec(spec CompiledCtSpec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ctSpecs[spec.CTID] = spec
}

func isPidRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil
}

func readPidFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return pid
}

// SendQMPCommand sends a JSON-RPC command over QMP Unix domain socket
func SendQMPCommand(socketPath string, command string, args map[string]any) (map[string]any, error) {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("qmp socket connect failed: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	buf := make([]byte, 4096)
	// Read initial QMP greeting banner
	_, _ = conn.Read(buf)

	// Send qmp_capabilities handshake
	handshake := []byte(`{"execute":"qmp_capabilities"}` + "\n")
	if _, err := conn.Write(handshake); err != nil {
		return nil, fmt.Errorf("qmp handshake write failed: %v", err)
	}
	// Read handshake response
	_, _ = conn.Read(buf)

	reqObj := map[string]any{
		"execute": command,
	}
	if args != nil {
		reqObj["arguments"] = args
	}
	reqData, _ := json.Marshal(reqObj)
	reqData = append(reqData, '\n')

	if _, err := conn.Write(reqData); err != nil {
		return nil, fmt.Errorf("qmp command write failed: %v", err)
	}

	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("qmp command read failed: %v", err)
	}

	var resp map[string]any
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		return map[string]any{"raw": string(buf[:n])}, nil
	}
	return resp, nil
}

// StartVM provisions required ZVOLs, Cloud-Init ISO, and launches QEMU process
func (m *VirtManager) StartVM(vmid int, user string) (string, error) {
	m.mu.Lock()
	spec, exists := m.vmSpecs[vmid]
	m.mu.Unlock()

	if !exists {
		// Provide a default fallback spec if not yet parsed from yaml
		spec = CompiledVmSpec{
			VMID:     vmid,
			Name:     fmt.Sprintf("vm-%d", vmid),
			Binary:   "qemu-system-x86_64",
			Cores:    2,
			MemoryMb: 2048,
			Args: []string{
				"-name", fmt.Sprintf("vm-%d,process=axonwall-vm-%d", vmid, vmid),
				"-enable-kvm",
				"-machine", "q35,accel=kvm",
				"-cpu", "host",
				"-smp", "2",
				"-m", "2048",
				"-pidfile", fmt.Sprintf("/run/axonwall/pids/vm-%d.pid", vmid),
				"-chardev", fmt.Sprintf("socket,id=qmp,path=/run/axonwall/qmp/vm-%d.sock,server=on,wait=off", vmid),
				"-mon", "chardev=qmp,mode=control",
				"-chardev", fmt.Sprintf("socket,id=serial0,path=/run/axonwall/serial/vm-%d.sock,server=on,wait=off", vmid),
				"-serial", "chardev:serial0",
				"-vnc", fmt.Sprintf("unix:/run/axonwall/vnc/vm-%d.sock", vmid),
				"-vga", "std",
				"-daemonize",
			},
		}
	}

	pidFile := fmt.Sprintf("/run/axonwall/pids/vm-%d.pid", vmid)
	if pid := readPidFile(pidFile); pid > 0 && isPidRunning(pid) {
		return "", fmt.Errorf("VM %d is already running (PID %d)", vmid, pid)
	}

	upid := m.taskMgr.StartTask("qmstart", strconv.Itoa(vmid), user, func(logger func(format string, args ...any)) error {
		logger("Starting VM %d (%s)...", vmid, spec.Name)

		// 1. Ensure ZVOL disks exist
		for idx, disk := range spec.Disks {
			pool := disk.Pool
			if pool == "" {
				pool = m.defaultPool
			}
			if !validZfsPoolName(pool) {
				return fmt.Errorf("invalid ZFS pool name: %s", pool)
			}
			zvolName := disk.Zvol
			if zvolName == "" {
				zvolName = fmt.Sprintf("%s/vms/vm-%d-disk-%d", pool, vmid, idx)
			}
			if !validZfsPath(zvolName, true) {
				return fmt.Errorf("invalid ZFS zvol path: %s", zvolName)
			}
			devPath := fmt.Sprintf("/dev/zvol/%s", zvolName)

			if _, err := os.Stat(devPath); os.IsNotExist(err) {
				sizeGb := disk.SizeGb
				if sizeGb <= 0 {
					sizeGb = 32
				}
				logger("Provisioning ZVOL disk %s (%d GB)...", zvolName, sizeGb)
				cmd := exec.Command("zfs", "create", "-p", "-V", fmt.Sprintf("%dG", sizeGb),
					"-o", "compression=lz4", "-o", "volblocksize=16k", zvolName)
				if out, err := cmd.CombinedOutput(); err != nil {
					logger("Failed to create ZVOL %s: %s", zvolName, string(out))
					return fmt.Errorf("zvol creation failed: %v", err)
				}
				logger("ZVOL %s created successfully.", zvolName)
			}
		}

		// 2. Prepare Cloud-Init ISO if configured
		if spec.CloudInit != nil {
			_ = os.MkdirAll("/run/axonwall", 0750)
			ciDir := fmt.Sprintf("/run/axonwall/ci-vm-%d", vmid)
			_ = os.MkdirAll(ciDir, 0700)
			defer os.RemoveAll(ciDir)

			metaYaml := fmt.Sprintf("instance-id: vm-%d\nlocal-hostname: %s\n", vmid, spec.Name)
			_ = os.WriteFile(filepath.Join(ciDir, "meta-data"), []byte(metaYaml), 0644)

			userYaml := fmt.Sprintf("#cloud-config\nhostname: %s\nmanage_etc_hosts: true\nusers:\n  - name: %s\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n",
				spec.Name, spec.CloudInit.User)
			if spec.CloudInit.Password != "" {
				userYaml += fmt.Sprintf("    plain_text_passwd: %s\n    lock_passwd: false\n", spec.CloudInit.Password)
			}
			if len(spec.CloudInit.SshKeys) > 0 {
				userYaml += "    ssh_authorized_keys:\n"
				for _, k := range spec.CloudInit.SshKeys {
					userYaml += fmt.Sprintf("      - %s\n", strings.TrimSpace(k))
				}
			}
			_ = os.WriteFile(filepath.Join(ciDir, "user-data"), []byte(userYaml), 0644)

			netYaml := "version: 2\nethernets:\n  eth0:\n    dhcp4: true\n"
			if spec.CloudInit.IpConfig != "dhcp" && spec.CloudInit.IpConfig != "" {
				netYaml = fmt.Sprintf("version: 2\nethernets:\n  eth0:\n    dhcp4: false\n    addresses: [%s]\n", spec.CloudInit.IpConfig)
				if spec.CloudInit.Gateway != "" {
					netYaml += fmt.Sprintf("    gateway4: %s\n", spec.CloudInit.Gateway)
				}
			}
			_ = os.WriteFile(filepath.Join(ciDir, "network-config"), []byte(netYaml), 0644)

			isoPath := fmt.Sprintf("/var/lib/axonwall/cloudinit/vm-%d-cidata.iso", vmid)
			logger("Generating Cloud-Init NoCloud ISO %s...", isoPath)
			cmdIso := exec.Command("genisoimage", "-output", isoPath, "-volid", "cidata", "-joliet", "-rock",
				filepath.Join(ciDir, "meta-data"), filepath.Join(ciDir, "user-data"), filepath.Join(ciDir, "network-config"))
			if out, err := cmdIso.CombinedOutput(); err != nil {
				// Fallback to xorriso
				cmdXorriso := exec.Command("xorriso", "-as", "mkisofs", "-output", isoPath, "-volid", "cidata", "-joliet", "-rock",
					filepath.Join(ciDir, "meta-data"), filepath.Join(ciDir, "user-data"), filepath.Join(ciDir, "network-config"))
				if outX, errX := cmdXorriso.CombinedOutput(); errX != nil {
					logger("Warning: ISO generator unavailable (genisoimage/xorriso): %s / %s", string(out), string(outX))
				}
			}
		}

		// 3. Clear stale sockets
		_ = os.Remove(fmt.Sprintf("/run/axonwall/qmp/vm-%d.sock", vmid))
		_ = os.Remove(fmt.Sprintf("/run/axonwall/vnc/vm-%d.sock", vmid))
		_ = os.Remove(fmt.Sprintf("/run/axonwall/serial/vm-%d.sock", vmid))
		_ = os.Remove(pidFile)

		// 4. Launch QEMU daemon
		binary := spec.Binary
		switch binary {
		case "", "qemu-system-x86_64", "/usr/bin/qemu-system-x86_64":
			binary = "/usr/bin/qemu-system-x86_64"
		case "qemu-system-aarch64", "/usr/bin/qemu-system-aarch64":
			binary = "/usr/bin/qemu-system-aarch64"
		default:
			return fmt.Errorf("disallowed QEMU binary: %s", binary)
		}

		logger("Executing %s with %d arguments...", binary, len(spec.Args))
		cmd := exec.Command(binary, spec.Args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger("QEMU launch error: %s (%v)", string(out), err)
			return fmt.Errorf("qemu failed: %s (%v)", string(out), err)
		}

		// Wait briefly and verify QMP socket
		qmpSock := fmt.Sprintf("/run/axonwall/qmp/vm-%d.sock", vmid)
		ready := false
		for i := 0; i < 20; i++ {
			time.Sleep(100 * time.Millisecond)
			if _, err := os.Stat(qmpSock); err == nil {
				ready = true
				break
			}
		}

		if ready {
			logger("VM %d launched successfully. QMP & VNC sockets online.", vmid)
			m.mu.Lock()
			m.vmStartTimes[vmid] = time.Now().Unix()
			m.mu.Unlock()
			return nil
		}

		logger("Warning: VM %d process started but QMP socket not detected yet.", vmid)
		return nil
	})

	return upid, nil
}

// StopVM initiates graceful shutdown via QMP or immediate termination
func (m *VirtManager) StopVM(vmid int, force bool, user string) (string, error) {
	qmpSock := fmt.Sprintf("/run/axonwall/qmp/vm-%d.sock", vmid)
	pidFile := fmt.Sprintf("/run/axonwall/pids/vm-%d.pid", vmid)
	pid := readPidFile(pidFile)

	upid := m.taskMgr.StartTask("qmstop", strconv.Itoa(vmid), user, func(logger func(format string, args ...any)) error {
		if force {
			logger("Force terminating VM %d (PID %d)...", vmid, pid)
			_, _ = SendQMPCommand(qmpSock, "quit", nil)
			if pid > 0 {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
			_ = os.Remove(pidFile)
			_ = os.Remove(qmpSock)
			logger("VM %d force killed.", vmid)
			return nil
		}

		logger("Sending ACPI powerdown to VM %d...", vmid)
		if _, err := SendQMPCommand(qmpSock, "system_powerdown", nil); err != nil {
			logger("QMP powerdown failed: %v. Falling back to SIGTERM...", err)
			if pid > 0 {
				_ = syscall.Kill(pid, syscall.SIGTERM)
			}
		}

		// Wait up to 10 seconds for clean exit
		for i := 0; i < 20; i++ {
			time.Sleep(500 * time.Millisecond)
			if pid > 0 && !isPidRunning(pid) {
				logger("VM %d shut down cleanly.", vmid)
				_ = os.Remove(pidFile)
				_ = os.Remove(qmpSock)
				return nil
			}
		}

		logger("VM %d still running after 10s. Issuing force quit...", vmid)
		_, _ = SendQMPCommand(qmpSock, "quit", nil)
		if pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		_ = os.Remove(pidFile)
		_ = os.Remove(qmpSock)
		logger("VM %d stopped.", vmid)
		return nil
	})

	return upid, nil
}

// ResetVM issues hardware reset via QMP
func (m *VirtManager) ResetVM(vmid int) error {
	qmpSock := fmt.Sprintf("/run/axonwall/qmp/vm-%d.sock", vmid)
	_, err := SendQMPCommand(qmpSock, "system_reset", nil)
	return err
}

// PauseVM suspends VM execution via QMP
func (m *VirtManager) PauseVM(vmid int) error {
	qmpSock := fmt.Sprintf("/run/axonwall/qmp/vm-%d.sock", vmid)
	_, err := SendQMPCommand(qmpSock, "stop", nil)
	return err
}

// ResumeVM resumes suspended VM execution via QMP
func (m *VirtManager) ResumeVM(vmid int) error {
	qmpSock := fmt.Sprintf("/run/axonwall/qmp/vm-%d.sock", vmid)
	_, err := SendQMPCommand(qmpSock, "cont", nil)
	return err
}

// ListVMs reports live status for all configured/running VMs
func (m *VirtManager) ListVMs() []VMStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []VMStatus

	for vmid, spec := range m.vmSpecs {
		pidFile := fmt.Sprintf("/run/axonwall/pids/vm-%d.pid", vmid)
		pid := readPidFile(pidFile)
		running := pid > 0 && isPidRunning(pid)

		status := "stopped"
		uptime := int64(0)
		if running {
			status = "running"
			if startTime, ok := m.vmStartTimes[vmid]; ok {
				uptime = time.Now().Unix() - startTime
			}
		}

		qmpSock := fmt.Sprintf("/run/axonwall/qmp/vm-%d.sock", vmid)
		vncSock := fmt.Sprintf("/run/axonwall/vnc/vm-%d.sock", vmid)
		serialSock := fmt.Sprintf("/run/axonwall/serial/vm-%d.sock", vmid)
		qgaSock := fmt.Sprintf("/run/axonwall/qga/vm-%d.sock", vmid)

		agentRunning := false
		if _, err := os.Stat(qgaSock); err == nil {
			agentRunning = true
		}

		result = append(result, VMStatus{
			VMID:          vmid,
			Name:          spec.Name,
			Status:        status,
			PID:           pid,
			Cores:         spec.Cores,
			MemoryMb:      spec.MemoryMb,
			UptimeSeconds: uptime,
			QmpSocket:     qmpSock,
			VncSocket:     vncSock,
			SerialSocket:  serialSock,
			AgentRunning:  agentRunning,
		})
	}

	return result
}

// StartContainer launches an LXC system container
func (m *VirtManager) StartContainer(ctid int, user string) (string, error) {
	upid := m.taskMgr.StartTask("pctstart", strconv.Itoa(ctid), user, func(logger func(format string, args ...any)) error {
		logger("Starting LXC Container %d...", ctid)
		cmd := exec.Command("lxc-start", "-n", strconv.Itoa(ctid), "-d")
		if out, err := cmd.CombinedOutput(); err != nil {
			logger("lxc-start error: %s (%v)", string(out), err)
			return fmt.Errorf("lxc-start failed: %s", string(out))
		}
		logger("LXC Container %d started successfully.", ctid)
		return nil
	})
	return upid, nil
}

// StopContainer shuts down or kills an LXC system container
func (m *VirtManager) StopContainer(ctid int, force bool, user string) (string, error) {
	upid := m.taskMgr.StartTask("pctstop", strconv.Itoa(ctid), user, func(logger func(format string, args ...any)) error {
		args := []string{"-n", strconv.Itoa(ctid)}
		if force {
			args = append(args, "-k")
			logger("Killing LXC Container %d...", ctid)
		} else {
			logger("Stopping LXC Container %d...", ctid)
		}
		cmd := exec.Command("lxc-stop", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger("lxc-stop error: %s (%v)", string(out), err)
			return fmt.Errorf("lxc-stop failed: %s", string(out))
		}
		logger("LXC Container %d stopped.", ctid)
		return nil
	})
	return upid, nil
}

// ListContainers reports live status for all LXC containers
func (m *VirtManager) ListContainers() []ContainerStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []ContainerStatus

	for ctid, spec := range m.ctSpecs {
		status := "stopped"
		pid := 0
		ip := ""

		// Check if lxc-info reports running
		if out, err := exec.Command("lxc-info", "-n", strconv.Itoa(ctid), "-s", "-p", "-i").CombinedOutput(); err == nil {
			outStr := string(out)
			if strings.Contains(outStr, "RUNNING") {
				status = "running"
			}
			for _, line := range strings.Split(outStr, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "PID:") {
					pidStr := strings.TrimSpace(strings.TrimPrefix(line, "PID:"))
					pid, _ = strconv.Atoi(pidStr)
				}
				if strings.HasPrefix(line, "IP:") {
					ip = strings.TrimSpace(strings.TrimPrefix(line, "IP:"))
				}
			}
		}

		result = append(result, ContainerStatus{
			CTID:      ctid,
			Name:      spec.Hostname,
			Status:    status,
			PID:       pid,
			Cores:     spec.Cores,
			MemoryMb:  spec.MemoryMb,
			IPAddress: ip,
		})
	}

	return result
}

// ListISOs lists available ISO images in pools
func (m *VirtManager) ListISOs(pool string) []ISOInfo {
	if pool == "" {
		pool = m.defaultPool
	}
	if !validZfsPoolName(pool) {
		return []ISOInfo{}
	}

	dirs := []string{
		fmt.Sprintf("/mnt/%s/isos", pool),
		"/var/lib/axonwall/isos",
	}

	var result []ISOInfo
	seen := make(map[string]bool)

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".iso") && !strings.HasSuffix(entry.Name(), ".img")) {
				continue
			}
			if seen[entry.Name()] {
				continue
			}
			seen[entry.Name()] = true

			fullPath := filepath.Join(dir, entry.Name())
			info, _ := entry.Info()
			size := int64(0)
			if info != nil {
				size = info.Size()
			}

			result = append(result, ISOInfo{
				Name:      entry.Name(),
				Path:      fullPath,
				SizeBytes: size,
				Pool:      pool,
			})
		}
	}

	return result
}

// DeleteISO safely deletes an ISO or disk image from the specified storage pool.
func (m *VirtManager) DeleteISO(pool, filename string) error {
	if pool == "" {
		pool = m.defaultPool
	}
	if !validZfsPoolName(pool) {
		return fmt.Errorf("invalid ZFS pool name: %s", pool)
	}
	safeName := filepath.Base(strings.TrimSpace(filename))
	if safeName == "" || safeName == "." || safeName == ".." || (!strings.HasSuffix(safeName, ".iso") && !strings.HasSuffix(safeName, ".img")) {
		return fmt.Errorf("invalid ISO filename: %s", filename)
	}
	for _, dir := range []string{fmt.Sprintf("/mnt/%s/isos", pool), "/var/lib/axonwall/isos"} {
		candidate := filepath.Join(dir, safeName)
		if info, err := os.Lstat(candidate); err == nil && !info.IsDir() {
			return os.Remove(candidate)
		}
	}
	return fmt.Errorf("ISO %s not found in pool %s", safeName, pool)
}

// DownloadISO streams an ISO from a URL into the storage pool
func (m *VirtManager) DownloadISO(rawURL, filename, pool, expectedSha256, user string) (string, error) {
	if pool == "" {
		pool = m.defaultPool
	}
	if !validZfsPoolName(pool) {
		return "", fmt.Errorf("invalid ZFS pool name: %s", pool)
	}
	parsedURL, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		return "", fmt.Errorf("invalid ISO download URL: must be http or https")
	}
	hostOnly := parsedURL.Hostname()
	if strings.EqualFold(hostOnly, "localhost") {
		return "", fmt.Errorf("disallowed loopback ISO download host")
	}
	if ip := net.ParseIP(hostOnly); ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return "", fmt.Errorf("disallowed loopback or link-local ISO download IP: %s", hostOnly)
		}
	}

	targetDir := fmt.Sprintf("/mnt/%s/isos", pool)
	_ = os.MkdirAll(targetDir, 0755)

	safeName := filepath.Base(filename)
	if !strings.HasSuffix(safeName, ".iso") && !strings.HasSuffix(safeName, ".img") {
		safeName += ".iso"
	}
	destPath := filepath.Join(targetDir, safeName)

	upid := m.taskMgr.StartTask("isodownload", safeName, user, func(logger func(format string, args ...any)) error {
		logger("Downloading ISO from %s to %s...", rawURL, destPath)

		client := &http.Client{Timeout: 30 * time.Minute}
		resp, err := client.Get(rawURL)
		if err != nil {
			logger("HTTP request error: %v", err)
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			logger("HTTP error: %s", resp.Status)
			return fmt.Errorf("http error: %s", resp.Status)
		}

		outFile, err := os.Create(destPath + ".tmp")
		if err != nil {
			logger("File creation error: %v", err)
			return err
		}
		defer outFile.Close()

		hasher := sha256.New()
		writer := io.MultiWriter(outFile, hasher)

		totalBytes := resp.ContentLength
		buf := make([]byte, 65536)
		var downloaded int64
		lastLog := time.Now()
		limitedBody := io.LimitReader(resp.Body, 16*1024*1024*1024)

		for {
			n, rErr := limitedBody.Read(buf)
			if n > 0 {
				_, wErr := writer.Write(buf[:n])
				if wErr != nil {
					return wErr
				}
				downloaded += int64(n)
			}
			if time.Since(lastLog) > 3*time.Second {
				lastLog = time.Now()
				if totalBytes > 0 {
					pct := float64(downloaded) / float64(totalBytes) * 100
					logger("Downloaded %.1f MB / %.1f MB (%.1f%%)", float64(downloaded)/(1024*1024), float64(totalBytes)/(1024*1024), pct)
				} else {
					logger("Downloaded %.1f MB", float64(downloaded)/(1024*1024))
				}
			}
			if rErr != nil {
				if rErr == io.EOF {
					break
				}
				return rErr
			}
		}

		_ = outFile.Close()

		calculatedSha := hex.EncodeToString(hasher.Sum(nil))
		logger("Download complete. SHA256: %s", calculatedSha)

		if expectedSha256 != "" && !strings.EqualFold(calculatedSha, expectedSha256) {
			_ = os.Remove(destPath + ".tmp")
			logger("SHA256 verification failed! Expected %s, got %s", expectedSha256, calculatedSha)
			return fmt.Errorf("sha256 mismatch")
		}

		if err := os.Rename(destPath+".tmp", destPath); err != nil {
			return err
		}
		logger("ISO saved to %s", destPath)
		return nil
	})

	return upid, nil
}

// RunBackup creates a snapshot and exports a deduplicated compressed archive
func (m *VirtManager) RunBackup(targetType string, targetID int, pool string, destType string, user string) (string, error) {
	if pool == "" {
		pool = m.defaultPool
	}
	if !validZfsPoolName(pool) {
		return "", fmt.Errorf("invalid ZFS pool name: %s", pool)
	}
	if targetType != "vm" && targetType != "lxc" {
		return "", fmt.Errorf("invalid backup target type '%s': must be 'vm' or 'lxc'", targetType)
	}
	ts := time.Now().Format("20060102-150405")
	snapName := fmt.Sprintf("backup-%s", ts)

	upid := m.taskMgr.StartTask("vzdump", fmt.Sprintf("%s-%d", targetType, targetID), user, func(logger func(format string, args ...any)) error {
		logger("Initiating backup of %s %d to %s...", targetType, targetID, destType)

		backupDir := fmt.Sprintf("/mnt/%s/backups", pool)
		_ = os.MkdirAll(backupDir, 0755)
		archiveName := fmt.Sprintf("axonwall-backup-%s-%d-%s.vma.zst", targetType, targetID, ts)
		archivePath := filepath.Join(backupDir, archiveName)

		if targetType == "vm" {
			dataset := fmt.Sprintf("%s/vms/vm-%d-disk-0", pool, targetID)
			snapFull := fmt.Sprintf("%s@%s", dataset, snapName)

			logger("Creating ZFS snapshot %s...", snapFull)
			cmdSnap := exec.Command("zfs", "snapshot", snapFull)
			if out, err := cmdSnap.CombinedOutput(); err != nil {
				logger("Snapshot error: %s (%v)", string(out), err)
				return fmt.Errorf("snapshot failed: %s", string(out))
			}

			logger("Streaming snapshot to compressed archive %s...", archivePath)
			sendCmd := fmt.Sprintf("set -o pipefail; zfs send %s | zstd -3 > %s", snapFull, archivePath)
			cmdStream := exec.Command("/bin/bash", "-c", sendCmd)
			if out, err := cmdStream.CombinedOutput(); err != nil {
				logger("Stream error: %s (%v)", string(out), err)
				return fmt.Errorf("stream failed: %s", string(out))
			}
		} else {
			dataset := fmt.Sprintf("%s/lxc/subvol-%d-disk-0", pool, targetID)
			snapFull := fmt.Sprintf("%s@%s", dataset, snapName)

			logger("Creating ZFS snapshot %s...", snapFull)
			cmdSnap := exec.Command("zfs", "snapshot", snapFull)
			if out, err := cmdSnap.CombinedOutput(); err != nil {
				logger("Snapshot error: %s (%v)", string(out), err)
				return fmt.Errorf("snapshot failed: %s", string(out))
			}

			logger("Streaming container snapshot to archive %s...", archivePath)
			sendCmd := fmt.Sprintf("set -o pipefail; zfs send %s | zstd -3 > %s", snapFull, archivePath)
			cmdStream := exec.Command("/bin/bash", "-c", sendCmd)
			if out, err := cmdStream.CombinedOutput(); err != nil {
				logger("Stream error: %s (%v)", string(out), err)
				return fmt.Errorf("stream failed: %s", string(out))
			}
		}

		logger("Backup completed successfully: %s", archivePath)
		return nil
	})

	return upid, nil
}

// ListBackups scans for existing backup archives in pools
func (m *VirtManager) ListBackups(pool string) []BackupRecord {
	if pool == "" {
		pool = m.defaultPool
	}
	if !validZfsPoolName(pool) {
		return []BackupRecord{}
	}
	backupDir := fmt.Sprintf("/mnt/%s/backups", pool)
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return []BackupRecord{}
	}

	var result []BackupRecord
	for _, entry := range entries {
		if entry.IsDir() || !strings.Contains(entry.Name(), "axonwall-backup-") {
			continue
		}
		info, _ := entry.Info()
		size := int64(0)
		modTime := time.Now().Unix()
		if info != nil {
			size = info.Size()
			modTime = info.ModTime().Unix()
		}

		// Format: axonwall-backup-<type>-<id>-<ts>.vma.zst
		parts := strings.Split(entry.Name(), "-")
		tType := "vm"
		vmid := 0
		if len(parts) >= 4 {
			tType = parts[2]
			vmid, _ = strconv.Atoi(parts[3])
		}

		result = append(result, BackupRecord{
			ID:          entry.Name(),
			VMID:        vmid,
			Type:        tType,
			Name:        entry.Name(),
			Timestamp:   modTime,
			SizeBytes:   size,
			Format:      "vma.zst",
			Destination: "local-zfs",
			Path:        filepath.Join(backupDir, entry.Name()),
		})
	}

	return result
}
