package engine

import (
	"bufio"
	"context"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// VirtSpecsPath is the persistent file storing compiled VM specifications across daemon restarts.
var VirtSpecsPath = "/var/lib/axonwall/virt-specs.json"

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
	// startMu guards startingVMs: the set of VMIDs whose StartVM
	// task is still running. The already-running pid check in
	// StartVM races a concurrent start (both pass before either
	// QEMU writes its pidfile), so two concurrent starts could
	// launch two QEMU processes for the same VM (round-2 A-L22).
	// The flag is held from the pid check until the start task
	// finishes, covering provisioning, socket cleanup, and launch.
	startMu     sync.Mutex
	startingVMs map[int]bool
}

type VirtioFsShareSpec struct {
	Tag      string `json:"tag"`
	HostPath string `json:"hostPath"`
	ReadOnly bool   `json:"readOnly,omitempty"`
}

type QgaInterfaceInfo struct {
	Name        string   `json:"name"`
	HardwareMac string   `json:"hardwareMac,omitempty"`
	IPAddresses []string `json:"ipAddresses"`
}

type CompiledVmNicSpec struct {
	Bridge   string `json:"bridge"`
	VlanTag  int    `json:"vlanTag,omitempty"`
	TapName  string `json:"tapName"`
}

type CompiledFwCfgFileSpec struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type CompiledVmSpec struct {
	VMID           int                     `json:"vmid"`
	Name           string                  `json:"name"`
	Binary         string                  `json:"binary"`
	QemuBinary     string                  `json:"qemuBinary,omitempty"`
	Args           []string                `json:"args"`
	Disks          []VmDisk                `json:"disks"`
	Nics           []CompiledVmNicSpec     `json:"nics,omitempty"`
	FwCfgFiles     []CompiledFwCfgFileSpec `json:"fwCfgFiles,omitempty"`
	Cores          int                     `json:"cores"`
	MemoryMb       int                     `json:"memoryMb"`
	Tpm2           bool                    `json:"tpm2,omitempty"`
	IsTemplate     bool                    `json:"isTemplate,omitempty"`
	VirtioFsShares []VirtioFsShareSpec     `json:"virtioFsShares,omitempty"`
	VlanTags       map[string]int          `json:"vlanTags,omitempty"`
	LibvirtXml     string                  `json:"libvirtXml,omitempty"`
	CloudInit      *CloudInitSpec          `json:"cloudInit,omitempty"`
	Autostart      bool                    `json:"autostart,omitempty"`
	Bridges        map[string]string       `json:"bridges,omitempty"`
	FwCfg          map[string]string       `json:"fwCfg,omitempty"`
}

// VMSpec is an alias for CompiledVmSpec.
type VMSpec = CompiledVmSpec

type VmDisk struct {
	Name         string `json:"name"`
	ID           string `json:"id,omitempty"`
	Pool         string `json:"pool"`
	SizeGb       int    `json:"sizeGb"`
	Zvol         string `json:"zvol"`
	ResolvedZvol string `json:"resolvedZvol,omitempty"`
}

type CloudInitSpec struct {
	User          string   `json:"user"`
	Password      string   `json:"password"`
	SshKeys       []string `json:"sshKeys"`
	IpConfig      string   `json:"ipConfig"`
	Gateway       string   `json:"gateway"`
	Nameservers   []string `json:"nameservers"`
	CustomPayload string   `json:"customPayload"`
	UserData      string   `json:"userData,omitempty"`
	MetaData      string   `json:"metaData,omitempty"`
	NetworkConfig string   `json:"networkConfig,omitempty"`
}

type CompiledCtSpec struct {
	CTID         int      `json:"ctid"`
	Name         string   `json:"name,omitempty"`
	Hostname     string   `json:"hostname"`
	Cores        int      `json:"cores"`
	MemoryMb     int      `json:"memoryMb"`
	RootfsPool   string   `json:"rootfsPool,omitempty"`
	RootfsSizeGb int      `json:"rootfsSizeGb,omitempty"`
	LxcConfig    string   `json:"lxcConfig,omitempty"`
	ConfigPath   string   `json:"configPath"`
	RootfsPath   string   `json:"rootfsPath"`
	Features     []string `json:"features"`
}

func NewVirtManager(taskMgr *TaskManager, nasMgr *NasManager) *VirtManager {
	_ = os.MkdirAll("/run/axonwall/qmp", 0755)
	_ = os.MkdirAll("/run/axonwall/vnc", 0755)
	_ = os.MkdirAll("/run/axonwall/serial", 0755)
	_ = os.MkdirAll("/run/axonwall/pids", 0755)
	_ = os.MkdirAll("/run/axonwall/qga", 0755)
	_ = os.MkdirAll("/run/axonwall/lxc", 0755)
	_ = os.MkdirAll("/run/axonwall/fwcfg", 0700)
	_ = os.MkdirAll("/var/lib/axonwall/nvram", 0755)
	_ = os.MkdirAll("/var/lib/axonwall/cloudinit", 0755)
	_ = os.MkdirAll("/var/lib/axonwall/isos", 0755)
	_ = os.MkdirAll("/var/lib/axonwall/backups", 0755)

	m := &VirtManager{
		taskMgr:      taskMgr,
		nasMgr:       nasMgr,
		vmSpecs:      make(map[int]CompiledVmSpec),
		ctSpecs:      make(map[int]CompiledCtSpec),
		vmStartTimes: make(map[int]int64),
		defaultPool:  "tank",
		startingVMs:  make(map[int]bool),
	}
	m.loadPersistedSpecs()
	return m
}

func (m *VirtManager) savePersistedSpecsLocked() {
	if VirtSpecsPath == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(VirtSpecsPath), 0755)
	data, err := json.MarshalIndent(m.vmSpecs, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(VirtSpecsPath, data, 0600)
}

func (m *VirtManager) loadPersistedSpecs() {
	if VirtSpecsPath == "" {
		return
	}
	data, err := os.ReadFile(VirtSpecsPath)
	if err != nil || len(data) == 0 {
		return
	}
	var loaded map[int]CompiledVmSpec
	if err := json.Unmarshal(data, &loaded); err == nil && loaded != nil {
		m.mu.Lock()
		for id, spec := range loaded {
			m.vmSpecs[id] = spec
		}
		m.mu.Unlock()
		return
	}
	var list []CompiledVmSpec
	if err := json.Unmarshal(data, &list); err == nil {
		m.mu.Lock()
		for _, spec := range list {
			m.vmSpecs[spec.VMID] = spec
		}
		m.mu.Unlock()
	}
}

func validateSafeQemuArgs(args []string) error {
	disallowedFlags := map[string]bool{
		"-gdb": true, "-s": true, "-plugin": true, "-virtfs": true, "-fsdev": true,
		"-D": true, "-loadvm": true, "-incoming": true,
		"-chroot": true, "-run-with": true, "-semihosting-config": true,
	}
	for i := 0; i < len(args); i++ {
		trimmed := strings.TrimSpace(args[i])
		if disallowedFlags[trimmed] {
			return fmt.Errorf("disallowed QEMU flag: %s", trimmed)
		}
		if trimmed == "-pidfile" {
			if i+1 >= len(args) {
				return fmt.Errorf("disallowed bare QEMU -pidfile flag")
			}
			pf := filepath.Clean(strings.TrimSpace(args[i+1]))
			if !strings.HasPrefix(pf, "/run/axonwall/pids/vm-") || !strings.HasSuffix(pf, ".pid") {
				return fmt.Errorf("disallowed QEMU -pidfile path: %s", pf)
			}
			i++
			continue
		}
		if trimmed == "-fw_cfg" {
			if i+1 >= len(args) {
				return fmt.Errorf("disallowed bare QEMU -fw_cfg flag")
			}
			fwSpec := strings.TrimSpace(args[i+1])
			hasSafeFile := false
			for _, part := range strings.Split(fwSpec, ",") {
				if strings.HasPrefix(part, "file=") {
					fp := filepath.Clean(strings.TrimPrefix(part, "file="))
					if (strings.HasPrefix(fp, "/var/lib/axonwall/") || strings.HasPrefix(fp, "/run/axonwall/")) && !strings.Contains(fp, "..") {
						hasSafeFile = true
					}
				}
			}
			if !hasSafeFile {
				return fmt.Errorf("disallowed QEMU -fw_cfg target: %s", fwSpec)
			}
			i++
			continue
		}
		for _, part := range strings.Split(trimmed, ",") {
			if strings.HasPrefix(part, "script=") && part != "script=no" {
				return fmt.Errorf("disallowed QEMU netdev script parameter: %s", part)
			}
			if strings.HasPrefix(part, "downscript=") && part != "downscript=no" {
				return fmt.Errorf("disallowed QEMU netdev downscript parameter: %s", part)
			}
		}
	}
	return nil
}

// ApplyVirtBundleJSON reconciles `/etc/axonwall/managed/virt_config.json` into VirtManager.
func (m *VirtManager) ApplyVirtBundleJSON(rawJSON []byte) error {
	var payload struct {
		Enabled           bool             `json:"enabled"`
		DefaultPool       string           `json:"defaultPool"`
		VMs               []CompiledVmSpec `json:"vms"`
		Containers        []CompiledCtSpec `json:"containers"`
		LibvirtDomainsXml map[string]string `json:"libvirtDomainsXml"`
	}
	if err := json.Unmarshal(rawJSON, &payload); err != nil {
		return fmt.Errorf("invalid virt_config.json: %w", err)
	}
	if payload.DefaultPool != "" && validZfsPoolName(payload.DefaultPool) {
		m.mu.Lock()
		m.defaultPool = payload.DefaultPool
		m.mu.Unlock()
	}
	for _, vm := range payload.VMs {
		if vm.Binary == "" && vm.QemuBinary != "" {
			vm.Binary = vm.QemuBinary
		}
		for i := range vm.Disks {
			if vm.Disks[i].Name == "" && vm.Disks[i].ID != "" {
				vm.Disks[i].Name = vm.Disks[i].ID
			}
			if vm.Disks[i].Zvol == "" && vm.Disks[i].ResolvedZvol != "" {
				vm.Disks[i].Zvol = vm.Disks[i].ResolvedZvol
			}
		}
		if len(vm.Nics) > 0 {
			if vm.Bridges == nil {
				vm.Bridges = make(map[string]string)
			}
			if vm.VlanTags == nil {
				vm.VlanTags = make(map[string]int)
			}
			for idx, nic := range vm.Nics {
				tap := nic.TapName
				if tap == "" {
					tap = fmt.Sprintf("tap%di%d", vm.VMID, idx)
				}
				if nic.Bridge != "" {
					vm.Bridges[tap] = nic.Bridge
				}
				if nic.VlanTag > 0 {
					vm.VlanTags[tap] = nic.VlanTag
				}
			}
		}
		if len(vm.FwCfgFiles) > 0 {
			if vm.FwCfg == nil {
				vm.FwCfg = make(map[string]string)
			}
			for _, f := range vm.FwCfgFiles {
				if f.Path != "" {
					vm.FwCfg[f.Path] = f.Content
				}
			}
		}
		if vm.LibvirtXml == "" && payload.LibvirtDomainsXml != nil {
			if xmlStr, ok := payload.LibvirtDomainsXml[strconv.Itoa(vm.VMID)]; ok {
				vm.LibvirtXml = xmlStr
			}
		}
		if err := m.RegisterVMSpec(vm); err != nil {
			return fmt.Errorf("VM %d spec rejected: %w", vm.VMID, err)
		}
	}
	for _, ct := range payload.Containers {
		if ct.Hostname == "" && ct.Name != "" {
			ct.Hostname = ct.Name
		}
		m.RegisterCTSpec(ct)
	}
	return nil
}

// RegisterVMSpec stores or updates the compiled specification for a VM and persists to disk.
// It returns an error instead of silently dropping an invalid spec: a
// dropped spec used to be reported as a successful register, and the VM
// then booted with a generic diskless fallback spec (A-M26 / C-D1).
func (m *VirtManager) RegisterVMSpec(spec CompiledVmSpec) error {
	switch spec.Binary {
	case "", "qemu-system-x86_64", "/usr/bin/qemu-system-x86_64":
		spec.Binary = "/usr/bin/qemu-system-x86_64"
	case "qemu-system-aarch64", "/usr/bin/qemu-system-aarch64":
		spec.Binary = "/usr/bin/qemu-system-aarch64"
	default:
		return fmt.Errorf("unsupported QEMU binary %q", spec.Binary)
	}
	if err := validateSafeQemuArgs(spec.Args); err != nil {
		return err
	}
	for _, disk := range spec.Disks {
		if disk.Pool != "" && !validZfsPoolName(disk.Pool) {
			return fmt.Errorf("invalid ZFS pool name %q for disk %q", disk.Pool, disk.Name)
		}
		if disk.Zvol != "" && !validZfsPath(disk.Zvol, true) {
			return fmt.Errorf("invalid ZFS zvol path %q for disk %q", disk.Zvol, disk.Name)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vmSpecs[spec.VMID] = spec
	m.savePersistedSpecsLocked()
	return nil
}

// UnregisterVMSpec removes a VM specification and updates persisted state.
func (m *VirtManager) UnregisterVMSpec(vmid int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.vmSpecs, vmid)
	m.savePersistedSpecsLocked()
}

// AutostartAll starts all registered VMs with Autostart: true, booting any "edge" VM first.
func (m *VirtManager) AutostartAll() {
	m.mu.RLock()
	var specs []CompiledVmSpec
	for _, s := range m.vmSpecs {
		if s.Autostart {
			specs = append(specs, s)
		}
	}
	m.mu.RUnlock()

	isEdge := func(s CompiledVmSpec) bool {
		nameLower := strings.ToLower(s.Name)
		return nameLower == "edge" || strings.HasPrefix(nameLower, "edge-") || strings.Contains(nameLower, "edge")
	}

	sort.Slice(specs, func(i, j int) bool {
		ei := isEdge(specs[i])
		ej := isEdge(specs[j])
		if ei != ej {
			return ei
		}
		return specs[i].VMID < specs[j].VMID
	})

	for _, s := range specs {
		_, _ = m.StartVM(s.VMID, "system@autostart")
	}
}

func extractTapDevicesFromArgs(args []string) []string {
	var taps []string
	seen := make(map[string]bool)
	for _, arg := range args {
		for _, part := range strings.Split(arg, ",") {
			if strings.HasPrefix(part, "ifname=") {
				tap := strings.TrimSpace(strings.TrimPrefix(part, "ifname="))
				if tap != "" && ValidNetdevName(tap) && !seen[tap] {
					seen[tap] = true
					taps = append(taps, tap)
				}
			}
		}
	}
	return taps
}

func ensureDaemonizeArg(args []string) []string {
	for _, a := range args {
		if a == "-daemonize" {
			return args
		}
	}
	out := make([]string, len(args), len(args)+1)
	copy(out, args)
	return append(out, "-daemonize")
}

func ensurePidFileArg(args []string, pidFile string) []string {
	for _, a := range args {
		if a == "-pidfile" {
			return args
		}
	}
	out := make([]string, len(args), len(args)+2)
	copy(out, args)
	return append(out, "-pidfile", pidFile)
}

func ensureOvmfNvram(vmid int, args []string) {
	needsNvram := false
	nvramPath := fmt.Sprintf("/var/lib/axonwall/nvram/vm-%d.fd", vmid)
	for _, a := range args {
		if strings.Contains(a, "/var/lib/axonwall/nvram/") || strings.Contains(a, "OVMF") {
			needsNvram = true
			for _, part := range strings.Split(a, ",") {
				if strings.HasPrefix(part, "file=/var/lib/axonwall/nvram/") {
					p := strings.TrimPrefix(part, "file=")
					if filepath.Clean(p) == p {
						nvramPath = p
					}
				}
			}
		}
	}
	if !needsNvram {
		return
	}
	if _, err := os.Stat(nvramPath); err == nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(nvramPath), 0755)
	for _, src := range []string{"/usr/share/OVMF/OVMF_VARS_4M.fd", "/usr/share/OVMF/OVMF_VARS.fd"} {
		if data, err := os.ReadFile(src); err == nil && len(data) > 0 {
			_ = os.WriteFile(nvramPath, data, 0600)
			return
		}
	}
}

func sanitizeCloudInitScalar(s string) string {
	cleaned := strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(strings.TrimSpace(s))
	return strconv.Quote(cleaned)
}

func writeFwCfgFiles(fwCfg map[string]string) error {
	for rawPath, content := range fwCfg {
		cleanPath := filepath.Clean(strings.TrimSpace(rawPath))
		if !strings.HasPrefix(cleanPath, "/run/axonwall/") && !strings.HasPrefix(cleanPath, "/var/lib/axonwall/cloudinit/") {
			return fmt.Errorf("fw_cfg file path %q is outside permitted directories (/run/axonwall/, /var/lib/axonwall/cloudinit/)", cleanPath)
		}
		if err := os.MkdirAll(filepath.Dir(cleanPath), 0700); err != nil {
			return fmt.Errorf("failed to create fw_cfg directory for %s: %w", cleanPath, err)
		}
		if err := os.WriteFile(cleanPath, []byte(content), 0600); err != nil {
			return fmt.Errorf("failed to write fw_cfg file %s: %w", cleanPath, err)
		}
	}
	return nil
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

// waitForQmpSocket polls for the QMP socket QEMU creates after daemonizing
// and verifies the QEMU pid from the pidfile is still alive. With
// -daemonize the parent exits 0 once the child forks, so post-fork failures
// (socket bind conflicts, pidfile failure) are invisible to the launch
// command's exit code and this wait is the only liveness check (A-M25).
func waitForQmpSocket(qmpSock, pidFile string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(qmpSock); err == nil {
			if pid := readPidFile(pidFile); pid > 0 && !isPidRunning(pid) {
				return fmt.Errorf("QMP socket %s appeared but QEMU pid %d from %s is no longer running", qmpSock, pid, pidFile)
			}
			return nil
		}
		if time.Now().After(deadline) {
			if pid := readPidFile(pidFile); pid > 0 && !isPidRunning(pid) {
				return fmt.Errorf("QMP socket %s did not appear within %s and QEMU pid %d from %s is no longer running; QEMU died after daemonizing", qmpSock, timeout, pid, pidFile)
			}
			return fmt.Errorf("QMP socket %s did not appear within %s; QEMU may have died after daemonizing", qmpSock, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// SendQMPCommand sends a JSON-RPC command over QMP Unix domain socket
func SendQMPCommand(socketPath string, command string, args map[string]any) (map[string]any, error) {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("qmp socket connect failed: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	reader := bufio.NewReader(conn)

	// Read initial QMP greeting banner line
	_, _ = reader.ReadString('\n')

	// Send qmp_capabilities handshake
	handshake := []byte(`{"execute":"qmp_capabilities"}` + "\n")
	if _, err := conn.Write(handshake); err != nil {
		return nil, fmt.Errorf("qmp handshake write failed: %v", err)
	}
	// Read handshake response, skipping any asynchronous QMP event lines
	for i := 0; i < 8; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		var msg map[string]any
		if json.Unmarshal([]byte(line), &msg) == nil {
			if _, isEvent := msg["event"]; isEvent {
				continue
			}
		}
		break
	}

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

	for i := 0; i < 16; i++ {
		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			return nil, fmt.Errorf("qmp command read failed: %v", err)
		}
		var resp map[string]any
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			return map[string]any{"raw": strings.TrimSpace(line)}, nil
		}
		if _, isEvent := resp["event"]; isEvent {
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("qmp command read exceeded event limit")
}

// StartVM provisions required ZVOLs, Cloud-Init ISO, and launches QEMU process
func (m *VirtManager) StartVM(vmid int, user string) (string, error) {
	m.mu.Lock()
	spec, exists := m.vmSpecs[vmid]
	m.mu.Unlock()

	pidFile := fmt.Sprintf("/run/axonwall/pids/vm-%d.pid", vmid)

	// A-L22: claim the start before the pid check — and before the
	// spec check below, so a second StartVM for a VM whose start is
	// already in flight is refused as "already in progress" even
	// though the spec lookup would fail first. The task below runs
	// asynchronously, so without this flag a second concurrent
	// StartVM would pass the pid check (no pidfile yet) and launch
	// a second QEMU for the same VM.
	m.startMu.Lock()
	if m.startingVMs == nil {
		m.startingVMs = make(map[int]bool)
	}
	if m.startingVMs[vmid] {
		m.startMu.Unlock()
		return "", fmt.Errorf("VM %d start already in progress", vmid)
	}
	m.startingVMs[vmid] = true
	m.startMu.Unlock()
	clearStarting := func() {
		m.startMu.Lock()
		delete(m.startingVMs, vmid)
		m.startMu.Unlock()
	}

	if !exists {
		// A-M26 / C-D1: refuse to boot a VM with no registered spec.
		// The old code invented a generic 2 vCPU / 2048 MB diskless,
		// NIC-less QEMU spec here, so a failed or skipped register
		// silently booted a VM the operator never configured (and
		// which ListVMs never showed, since it only lists configured
		// VMs). Callers must register a spec first; a failed register
		// now returns an error instead of success.
		clearStarting()
		return "", fmt.Errorf("VM %d has no registered spec; refusing to boot a generic fallback VM (register a spec first)", vmid)
	}

	if pid := readPidFile(pidFile); pid > 0 && isPidRunning(pid) {
		clearStarting()
		return "", fmt.Errorf("VM %d is already running (PID %d)", vmid, pid)
	}

	upid := m.taskMgr.StartTask("qmstart", strconv.Itoa(vmid), user, func(logger func(format string, args ...any)) error {
		// Release the claim when the start task finishes (success
		// or failure) so a later retry is not blocked forever.
		defer clearStarting()
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

			metaYaml := spec.CloudInit.MetaData
			if metaYaml == "" {
				metaYaml = fmt.Sprintf("instance-id: vm-%d\nlocal-hostname: %s\n", vmid, sanitizeCloudInitScalar(spec.Name))
			}
			_ = os.WriteFile(filepath.Join(ciDir, "meta-data"), []byte(metaYaml), 0644)

			var userYaml string
			if spec.CloudInit.UserData != "" {
				userYaml = spec.CloudInit.UserData
			} else {
				ciUser := spec.CloudInit.User
				if strings.TrimSpace(ciUser) == "" {
					ciUser = "axonwall"
				}
				userYaml = fmt.Sprintf("#cloud-config\nhostname: %s\nmanage_etc_hosts: true\nusers:\n  - name: %s\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n",
					sanitizeCloudInitScalar(spec.Name), sanitizeCloudInitScalar(ciUser))
				if spec.CloudInit.Password != "" {
					userYaml += fmt.Sprintf("    plain_text_passwd: %s\n    lock_passwd: false\n", sanitizeCloudInitScalar(spec.CloudInit.Password))
				}
				if len(spec.CloudInit.SshKeys) > 0 {
					userYaml += "    ssh_authorized_keys:\n"
					for _, k := range spec.CloudInit.SshKeys {
						if trimmedKey := strings.TrimSpace(k); trimmedKey != "" {
							userYaml += fmt.Sprintf("      - %s\n", sanitizeCloudInitScalar(trimmedKey))
						}
					}
				}
				if spec.CloudInit.CustomPayload != "" {
					userYaml += "\n" + spec.CloudInit.CustomPayload + "\n"
				}
			}
			_ = os.WriteFile(filepath.Join(ciDir, "user-data"), []byte(userYaml), 0644)

			netYaml := spec.CloudInit.NetworkConfig
			if netYaml == "" {
				netYaml = "version: 2\nethernets:\n  eth0:\n    dhcp4: true\n"
				if spec.CloudInit.IpConfig != "dhcp" && spec.CloudInit.IpConfig != "" {
					netYaml = fmt.Sprintf("version: 2\nethernets:\n  eth0:\n    dhcp4: false\n    addresses: [%s]\n", sanitizeCloudInitScalar(spec.CloudInit.IpConfig))
					if spec.CloudInit.Gateway != "" {
						netYaml += fmt.Sprintf("    gateway4: %s\n", sanitizeCloudInitScalar(spec.CloudInit.Gateway))
					}
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

		// 2b. Write fw_cfg files if present (with 0600 permissions)
		if len(spec.FwCfg) > 0 {
			if err := writeFwCfgFiles(spec.FwCfg); err != nil {
				logger("Failed to write fw_cfg files: %v", err)
				return err
			}
		}

		// 2c. Initialize OVMF NVRAM if needed
		ensureOvmfNvram(vmid, spec.Args)

		// 2d. Spawn swtpm emulator daemon if TPM 2.0 is enabled on the VM
		hasTpmArg := spec.Tpm2
		for _, a := range spec.Args {
			if strings.Contains(a, "swtpm/vm-") {
				hasTpmArg = true
				break
			}
		}
		if hasTpmArg {
			if swtpmBin, lookErr := exec.LookPath("swtpm"); lookErr == nil {
				tpmStateDir := fmt.Sprintf("/var/lib/axonwall/tpm/vm-%d", vmid)
				tpmSock := fmt.Sprintf("/run/axonwall/swtpm/vm-%d.sock", vmid)
				_ = os.MkdirAll(tpmStateDir, 0700)
				_ = os.MkdirAll("/run/axonwall/swtpm", 0755)
				_ = os.Remove(tpmSock)
				_ = exec.Command(swtpmBin, "socket", "--tpm2", "--tpmstate", "dir="+tpmStateDir,
					"--ctrl", "type=unixio,path="+tpmSock, "--daemon").Run()
			}
		}

		// 2e. Spawn virtiofsd helper daemons for ZFS host dataset VirtioFS shares
		if len(spec.VirtioFsShares) > 0 {
			if vfsBin, lookErr := exec.LookPath("virtiofsd"); lookErr == nil {
				_ = os.MkdirAll("/run/axonwall/virtiofs", 0755)
				for _, sh := range spec.VirtioFsShares {
					cleanHost := filepath.Clean(strings.TrimSpace(sh.HostPath))
					if !underMnt(cleanHost) {
						return fmt.Errorf("virtiofs hostPath %q must reside under /mnt", cleanHost)
					}
					safeTag := strings.Map(func(r rune) rune {
						if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
							return r
						}
						return '_'
					}, sh.Tag)
					vfsSock := fmt.Sprintf("/run/axonwall/virtiofs/vm-%d-%s.sock", vmid, safeTag)
					_ = os.Remove(vfsSock)
					vfsCmd := exec.Command(vfsBin, "--socket-path="+vfsSock, "--shared-dir="+cleanHost, "--sandbox=namespace")
					_ = vfsCmd.Start()
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

		if err := validateSafeQemuArgs(spec.Args); err != nil {
			return err
		}
		qemuArgs := ensurePidFileArg(ensureDaemonizeArg(spec.Args), pidFile)
		logger("Executing %s with %d arguments...", binary, len(qemuArgs))
		cmd := exec.Command(binary, qemuArgs...)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger("QEMU launch error: %s (%v)", string(out), err)
			return fmt.Errorf("qemu failed: %s (%v)", string(out), err)
		}

		// 4b. Attach TAP interfaces to their target host bridges
		for _, tapDev := range extractTapDevicesFromArgs(qemuArgs) {
			bridgeName := ""
			if spec.Bridges != nil {
				bridgeName = strings.TrimSpace(spec.Bridges[tapDev])
			}
			if bridgeName == "" {
				if strings.Contains(tapDev, "wan") {
					bridgeName = "br-wan"
				} else {
					bridgeName = "br-lan"
				}
			}
			vlanTag := 0
			if spec.VlanTags != nil {
				vlanTag = spec.VlanTags[tapDev]
			}
			if err := AttachTapToBridge(tapDev, bridgeName, vlanTag); err != nil {
				// Fallback to br0 if br-lan does not exist yet
				if bridgeName == "br-lan" {
					_ = AttachTapToBridge(tapDev, "br0", vlanTag)
				} else {
					logger("Warning: failed to attach tap %s to bridge %s: %v", tapDev, bridgeName, err)
				}
			} else {
				logger("Attached tap %s to bridge %s (VLAN %d).", tapDev, bridgeName, vlanTag)
			}
		}

		// Wait briefly and verify QMP socket
		qmpSock := fmt.Sprintf("/run/axonwall/qmp/vm-%d.sock", vmid)
		// A-M25: a missing QMP socket means QEMU died after
		// daemonizing (the parent exits 0 once the child forks), so
		// this must fail the start task instead of warning and
		// reporting success.
		if err := waitForQmpSocket(qmpSock, pidFile, 2*time.Second); err != nil {
			logger("VM %d failed to start: %v", vmid, err)
			return err
		}
		logger("VM %d launched successfully. QMP & VNC sockets online.", vmid)
		m.mu.Lock()
		m.vmStartTimes[vmid] = time.Now().Unix()
		m.mu.Unlock()
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

// StartContainer launches an LXC system container (provisioning ZFS rootfs & /var/lib/lxc/<ctid>/config if needed)
func (m *VirtManager) StartContainer(ctid int, user string) (string, error) {
	m.mu.RLock()
	spec, hasSpec := m.ctSpecs[ctid]
	defaultPool := m.defaultPool
	m.mu.RUnlock()

	upid := m.taskMgr.StartTask("pctstart", strconv.Itoa(ctid), user, func(logger func(format string, args ...any)) error {
		logger("Starting LXC Container %d...", ctid)
		if hasSpec {
			pool := spec.RootfsPool
			if pool == "" {
				pool = defaultPool
			}
			if validZfsPoolName(pool) {
				ds := fmt.Sprintf("%s/lxc/subvol-%d-disk-0", pool, ctid)
				if _, lookErr := exec.LookPath("zfs"); lookErr == nil {
					if exec.Command("zfs", "list", "-H", ds).Run() != nil {
						_ = exec.Command("zfs", "create", "-p", "-o", "compression=lz4", ds).Run()
					}
				}
			}
			if spec.LxcConfig != "" {
				ctDir := fmt.Sprintf("/var/lib/lxc/%d", ctid)
				_ = os.MkdirAll(ctDir, 0750)
				_ = os.WriteFile(filepath.Join(ctDir, "config"), []byte(spec.LxcConfig), 0640)
			}
		}
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
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsMulticast() || ip.IsUnspecified() {
			return "", fmt.Errorf("disallowed loopback, private, or link-local ISO download IP: %s", hostOnly)
		}
	}

	targetDir := fmt.Sprintf("/mnt/%s/isos", pool)
	_ = os.MkdirAll(targetDir, 0755)

	safeName := filepath.Base(strings.TrimSpace(filename))
	if safeName == "" || safeName == "." || safeName == ".." || strings.HasPrefix(safeName, ".") || strings.HasPrefix(safeName, "-") {
		return "", fmt.Errorf("invalid ISO filename: %s", filename)
	}
	if !strings.HasSuffix(safeName, ".iso") && !strings.HasSuffix(safeName, ".img") {
		safeName += ".iso"
	}
	for _, r := range safeName {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return "", fmt.Errorf("invalid characters in ISO filename: %s", filename)
		}
	}
	if strings.Contains(safeName, "..") {
		return "", fmt.Errorf("invalid ISO filename: %s", filename)
	}
	destPath := filepath.Join(targetDir, safeName)

	upid := m.taskMgr.StartTask("isodownload", safeName, user, func(logger func(format string, args ...any)) error {
		logger("Downloading ISO from %s to %s...", rawURL, destPath)

		dialer := &net.Dialer{Timeout: 15 * time.Second}
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				h, p, splitErr := net.SplitHostPort(addr)
				if splitErr != nil {
					return nil, splitErr
				}
				ips, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, h)
				if lookupErr != nil || len(ips) == 0 {
					return nil, fmt.Errorf("failed to resolve host %s: %v", h, lookupErr)
				}
				for _, ipAddr := range ips {
					ip := ipAddr.IP
					if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsMulticast() || ip.IsUnspecified() {
						return nil, fmt.Errorf("disallowed resolved target IP %s for %s", ip.String(), h)
					}
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), p))
			},
		}
		client := &http.Client{
			Timeout:   30 * time.Minute,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
					return fmt.Errorf("disallowed redirect scheme: %s", req.URL.Scheme)
				}
				rh := req.URL.Hostname()
				if strings.EqualFold(rh, "localhost") {
					return fmt.Errorf("disallowed redirect to localhost")
				}
				if rip := net.ParseIP(rh); rip != nil {
					if rip.IsLoopback() || rip.IsLinkLocalUnicast() || rip.IsLinkLocalMulticast() || rip.IsPrivate() || rip.IsMulticast() || rip.IsUnspecified() {
						return fmt.Errorf("disallowed redirect target IP: %s", rh)
					}
				}
				return nil
			},
		}
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

		tmpPath := destPath + ".tmp"
		if fi, lerr := os.Lstat(tmpPath); lerr == nil {
			if (fi.Mode() & os.ModeSymlink) != 0 {
				return fmt.Errorf("refusing symlink temporary path: %s", tmpPath)
			}
			_ = os.Remove(tmpPath)
		}
		outFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
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

		if fi, lerr := os.Lstat(destPath); lerr == nil {
			if (fi.Mode() & os.ModeSymlink) != 0 {
				_ = os.Remove(destPath + ".tmp")
				return fmt.Errorf("refusing symlink destination path: %s", destPath)
			}
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
	// A-M24: snapshot and archive names carry a nanosecond suffix so two
	// backups of the same target in the same second can no longer collide
	// (the old second-granularity snapshot name made the second backup
	// fail, and the archive name would have been overwritten).
	stamp := fmt.Sprintf("%s-%09d", time.Now().Format("20060102-150405"), time.Now().Nanosecond())
	snapName := fmt.Sprintf("backup-%s", stamp)

	upid := m.taskMgr.StartTask("vzdump", fmt.Sprintf("%s-%d", targetType, targetID), user, func(logger func(format string, args ...any)) error {
		logger("Initiating backup of %s %d to %s...", targetType, targetID, destType)

		backupDir := fmt.Sprintf("/mnt/%s/backups", pool)
		_ = os.MkdirAll(backupDir, 0700)
		_ = os.Chmod(backupDir, 0700)

		// A-M24: back up every disk, not just disk-0. A multi-disk VM
		// used to report "Backup completed successfully" while only
		// disk-0 was snapshotted and streamed; a restore would
		// silently lose every other disk.
		datasets := m.backupDatasetsForTarget(targetType, targetID, pool)
		var archives []string
		for idx, dataset := range datasets {
			archiveName := fmt.Sprintf("axonwall-backup-%s-%d-%s.vma.zst", targetType, targetID, stamp)
			if len(datasets) > 1 {
				archiveName = fmt.Sprintf("axonwall-backup-%s-%d-%s-disk-%d.vma.zst", targetType, targetID, stamp, idx)
			}
			archivePath := filepath.Join(backupDir, archiveName)
			if fi, lerr := os.Lstat(archivePath); lerr == nil {
				if (fi.Mode() & os.ModeSymlink) != 0 {
					return fmt.Errorf("refusing symlink archive path: %s", archivePath)
				}
			}
			if err := backupDataset(dataset, snapName, archivePath, logger); err != nil {
				return err
			}
			archives = append(archives, archivePath)
		}

		logger("Backup completed successfully: %s", strings.Join(archives, ", "))
		return nil
	})

	return upid, nil
}

// backupDatasetsForTarget returns the ZFS datasets a backup must cover. A
// registered VM backs up every disk in its spec (same naming StartVM
// provisions them under); an unregistered VM, or an LXC container (which
// has a single rootfs dataset), falls back to the historical disk-0
// dataset (A-M24).
func (m *VirtManager) backupDatasetsForTarget(targetType string, targetID int, pool string) []string {
	if targetType == "vm" {
		m.mu.RLock()
		spec, ok := m.vmSpecs[targetID]
		m.mu.RUnlock()
		if ok && len(spec.Disks) > 0 {
			datasets := make([]string, 0, len(spec.Disks))
			for idx, disk := range spec.Disks {
				zvolName := disk.Zvol
				if zvolName == "" {
					p := disk.Pool
					if p == "" {
						p = pool
					}
					zvolName = fmt.Sprintf("%s/vms/vm-%d-disk-%d", p, targetID, idx)
				}
				datasets = append(datasets, zvolName)
			}
			return datasets
		}
		return []string{fmt.Sprintf("%s/vms/vm-%d-disk-0", pool, targetID)}
	}
	return []string{fmt.Sprintf("%s/lxc/subvol-%d-disk-0", pool, targetID)}
}

// backupDataset snapshots one ZFS dataset and streams it to a compressed
// archive. On stream failure the partial archive is removed and the
// snapshot destroyed, so a failed backup leaves neither a bogus archive
// for ListBackups to list nor a stray snapshot (A-M24).
func backupDataset(dataset, snapName, archivePath string, logger func(format string, args ...any)) error {
	snapFull := fmt.Sprintf("%s@%s", dataset, snapName)

	logger("Creating ZFS snapshot %s...", snapFull)
	if out, err := exec.Command("zfs", "snapshot", snapFull).CombinedOutput(); err != nil {
		logger("Snapshot error: %s (%v)", string(out), err)
		return fmt.Errorf("snapshot failed: %s", string(out))
	}

	logger("Streaming snapshot to compressed archive %s...", archivePath)
	cmdStream := exec.Command("/bin/bash", "-c", `umask 0077; set -o pipefail; zfs send "$1" | zstd -3 > "$2"`, "_", snapFull, archivePath)
	if out, err := cmdStream.CombinedOutput(); err != nil {
		logger("Stream error: %s (%v)", string(out), err)
		_ = os.Remove(archivePath)
		_ = exec.Command("zfs", "destroy", snapFull).Run()
		return fmt.Errorf("stream failed: %s", string(out))
	}
	_ = os.Chmod(archivePath, 0600)
	return nil
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

// SendQGACommand executes a QEMU Guest Agent JSON-RPC command over /run/axonwall/qga/vm-<vmid>.sock.
func SendQGACommand(vmid int, command string, args map[string]any) (map[string]any, error) {
	sockPath := fmt.Sprintf("/run/axonwall/qga/vm-%d.sock", vmid)
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("qga socket connect failed for VM %d: %w", vmid, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	reqObj := map[string]any{"execute": command}
	if args != nil {
		reqObj["arguments"] = args
	}
	reqBytes, _ := json.Marshal(reqObj)
	reqBytes = append(reqBytes, '\n')
	if _, err := conn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("qga write failed: %w", err)
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return nil, fmt.Errorf("qga read failed: %w", err)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return nil, fmt.Errorf("invalid qga JSON response: %w", err)
	}
	return resp, nil
}

// QueryQgaInterfaces queries guest IPv4/IPv6 addresses and MACs via QEMU Guest Agent.
func (m *VirtManager) QueryQgaInterfaces(vmid int) ([]QgaInterfaceInfo, error) {
	resp, err := SendQGACommand(vmid, "guest-network-get-interfaces", nil)
	if err != nil {
		return nil, err
	}
	rawRet, ok := resp["return"].([]any)
	if !ok {
		return []QgaInterfaceInfo{}, nil
	}
	var out []QgaInterfaceInfo
	for _, item := range rawRet {
		ifMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := ifMap["name"].(string)
		mac, _ := ifMap["hardware-address"].(string)
		var ips []string
		if addrList, ok := ifMap["ip-addresses"].([]any); ok {
			for _, a := range addrList {
				if am, ok := a.(map[string]any); ok {
					ipStr, _ := am["ip-address"].(string)
					if ipStr != "" && ipStr != "127.0.0.1" && ipStr != "::1" {
						ips = append(ips, ipStr)
					}
				}
			}
		}
		out = append(out, QgaInterfaceInfo{
			Name:        name,
			HardwareMac: mac,
			IPAddresses: ips,
		})
	}
	return out, nil
}

// QgaFsFreeze freezes guest filesystems via QEMU Guest Agent before ZFS snapshotting.
func (m *VirtManager) QgaFsFreeze(vmid int) error {
	_, err := SendQGACommand(vmid, "guest-fsfreeze-freeze", nil)
	return err
}

// QgaFsThaw thaws guest filesystems via QEMU Guest Agent after ZFS snapshotting.
func (m *VirtManager) QgaFsThaw(vmid int) error {
	_, err := SendQGACommand(vmid, "guest-fsfreeze-thaw", nil)
	return err
}

// CreateWorkloadSnapshot creates atomic ZFS snapshots across all disks of a VM or LXC container
// (performing QGA guest-fsfreeze-freeze / thaw automatically if the guest agent socket is live).
func (m *VirtManager) CreateWorkloadSnapshot(targetType string, targetID int, label string) ([]string, error) {
	if targetType != "vm" && targetType != "lxc" {
		return nil, fmt.Errorf("targetType must be vm or lxc")
	}
	cleanLabel := strings.TrimSpace(label)
	if cleanLabel == "" {
		cleanLabel = fmt.Sprintf("snap-%s", time.Now().UTC().Format("20060102-150405"))
	}
	if !validZfsPath(cleanLabel, false) {
		return nil, fmt.Errorf("invalid snapshot label %q", label)
	}
	if _, err := exec.LookPath("zfs"); err != nil {
		return nil, fmt.Errorf("zfs is not installed on this system")
	}

	froze := false
	if targetType == "vm" {
		if m.QgaFsFreeze(targetID) == nil {
			froze = true
		}
	}
	defer func() {
		if froze {
			_ = m.QgaFsThaw(targetID)
		}
	}()

	datasets := m.backupDatasetsForTarget(targetType, targetID, m.defaultPool)
	var created []string
	for _, ds := range datasets {
		snapFull := fmt.Sprintf("%s@%s", ds, cleanLabel)
		if out, err := exec.Command("zfs", "snapshot", snapFull).CombinedOutput(); err != nil {
			return created, fmt.Errorf("zfs snapshot %s failed: %s (%w)", snapFull, strings.TrimSpace(string(out)), err)
		}
		created = append(created, snapFull)
	}
	return created, nil
}

// RollbackWorkloadSnapshot rolls back all ZFS disks/subvols of a VM or LXC container to a snapshot label.
func (m *VirtManager) RollbackWorkloadSnapshot(targetType string, targetID int, label string) error {
	if targetType != "vm" && targetType != "lxc" {
		return fmt.Errorf("targetType must be vm or lxc")
	}
	cleanLabel := strings.TrimSpace(label)
	if !validZfsPath(cleanLabel, false) {
		return fmt.Errorf("invalid snapshot label %q", label)
	}
	if _, err := exec.LookPath("zfs"); err != nil {
		return fmt.Errorf("zfs is not installed on this system")
	}
	datasets := m.backupDatasetsForTarget(targetType, targetID, m.defaultPool)
	for _, ds := range datasets {
		snapFull := fmt.Sprintf("%s@%s", ds, cleanLabel)
		if out, err := exec.Command("zfs", "rollback", "-r", snapFull).CombinedOutput(); err != nil {
			return fmt.Errorf("zfs rollback %s failed: %s (%w)", snapFull, strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}

// ListWorkloadSnapshots returns ZFS snapshots belonging to a specific VM or LXC container.
func (m *VirtManager) ListWorkloadSnapshots(targetType string, targetID int) []ZfsSnapshotInfo {
	if m.nasMgr == nil {
		return []ZfsSnapshotInfo{}
	}
	datasets := m.backupDatasetsForTarget(targetType, targetID, m.defaultPool)
	dsSet := make(map[string]bool, len(datasets))
	for _, d := range datasets {
		dsSet[d] = true
	}
	all := m.nasMgr.ListSnapshots()
	var filtered []ZfsSnapshotInfo
	for _, s := range all {
		if dsSet[s.Dataset] {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// CloneVM creates either an instant Zero-Copy ZFS Linked Clone (`zfs clone`) or an independent
// Full Clone (`zfs send | zfs receive`) from a registered VM or Template.
func (m *VirtManager) CloneVM(sourceVMID, newVMID int, newName string, linked bool) (CompiledVmSpec, error) {
	if newVMID < 100 || newVMID > 999999 {
		return CompiledVmSpec{}, fmt.Errorf("newVMID must be between 100 and 999999")
	}
	m.mu.RLock()
	srcSpec, exists := m.vmSpecs[sourceVMID]
	_, targetExists := m.vmSpecs[newVMID]
	defaultPool := m.defaultPool
	m.mu.RUnlock()

	if !exists {
		return CompiledVmSpec{}, fmt.Errorf("source VM %d is not registered", sourceVMID)
	}
	if targetExists {
		return CompiledVmSpec{}, fmt.Errorf("target VMID %d already exists", newVMID)
	}
	cleanName := strings.TrimSpace(newName)
	if cleanName == "" {
		cleanName = fmt.Sprintf("%s-clone-%d", srcSpec.Name, newVMID)
	}

	clonedDisks := make([]VmDisk, 0, len(srcSpec.Disks))
	_, hasZfs := exec.LookPath("zfs")
	stamp := time.Now().UTC().Format("20060102150405")

	for idx, d := range srcSpec.Disks {
		pool := d.Pool
		if pool == "" {
			pool = defaultPool
		}
		srcZvol := d.Zvol
		if srcZvol == "" {
			srcZvol = fmt.Sprintf("%s/vms/vm-%d-disk-%d", pool, sourceVMID, idx)
		}
		dstZvol := fmt.Sprintf("%s/vms/vm-%d-disk-%d", pool, newVMID, idx)
		if hasZfs == nil && exec.Command("zfs", "list", "-H", srcZvol).Run() == nil {
			snap := fmt.Sprintf("%s@clone-%d-%s", srcZvol, newVMID, stamp)
			if out, err := exec.Command("zfs", "snapshot", snap).CombinedOutput(); err != nil {
				return CompiledVmSpec{}, fmt.Errorf("snapshot for clone failed: %s (%w)", strings.TrimSpace(string(out)), err)
			}
			if linked {
				if out, err := exec.Command("zfs", "clone", snap, dstZvol).CombinedOutput(); err != nil {
					return CompiledVmSpec{}, fmt.Errorf("zfs linked clone failed: %s (%w)", strings.TrimSpace(string(out)), err)
				}
			} else {
				cmdFull := exec.Command("/bin/bash", "-c", `set -o pipefail; zfs send "$1" | zfs receive -F "$2"`, "_", snap, dstZvol)
				if out, err := cmdFull.CombinedOutput(); err != nil {
					return CompiledVmSpec{}, fmt.Errorf("zfs full clone failed: %s (%w)", strings.TrimSpace(string(out)), err)
				}
			}
		}
		clonedDisks = append(clonedDisks, VmDisk{
			Name:   d.Name,
			Pool:   pool,
			SizeGb: d.SizeGb,
			Zvol:   dstZvol,
		})
	}

	// Rewrite VMID-specific paths in QEMU args
	oldPrefix := fmt.Sprintf("vm-%d", sourceVMID)
	newPrefix := fmt.Sprintf("vm-%d", newVMID)
	oldTapPrefix := fmt.Sprintf("tap%di", sourceVMID)
	newTapPrefix := fmt.Sprintf("tap%di", newVMID)
	newArgs := make([]string, len(srcSpec.Args))
	for i, a := range srcSpec.Args {
		replaced := strings.ReplaceAll(a, oldPrefix, newPrefix)
		replaced = strings.ReplaceAll(replaced, oldTapPrefix, newTapPrefix)
		newArgs[i] = replaced
	}

	clonedSpec := srcSpec
	clonedSpec.VMID = newVMID
	clonedSpec.Name = cleanName
	clonedSpec.IsTemplate = false
	clonedSpec.Args = newArgs
	clonedSpec.Disks = clonedDisks

	if err := m.RegisterVMSpec(clonedSpec); err != nil {
		return CompiledVmSpec{}, err
	}
	return clonedSpec, nil
}

// RestoreBackup streams a compressed `.vma.zst` ZFS archive back into the target VM or LXC dataset.
func (m *VirtManager) RestoreBackup(archiveName string, targetType string, targetID int, pool string, user string) (string, error) {
	if pool == "" {
		pool = m.defaultPool
	}
	if !validZfsPoolName(pool) {
		return "", fmt.Errorf("invalid ZFS pool name %q", pool)
	}
	if targetType != "vm" && targetType != "lxc" {
		return "", fmt.Errorf("targetType must be vm or lxc")
	}
	safeArchive := filepath.Base(strings.TrimSpace(archiveName))
	if safeArchive == "" || !strings.HasPrefix(safeArchive, "axonwall-backup-") || !strings.HasSuffix(safeArchive, ".vma.zst") {
		return "", fmt.Errorf("invalid backup archive filename %q", archiveName)
	}
	archivePath := filepath.Join(fmt.Sprintf("/mnt/%s/backups", pool), safeArchive)
	info, err := os.Lstat(archivePath)
	if err != nil || info.IsDir() || (info.Mode()&os.ModeSymlink) != 0 {
		return "", fmt.Errorf("backup archive %q not found in pool %s", safeArchive, pool)
	}

	targetDataset := fmt.Sprintf("%s/vms/vm-%d-disk-0", pool, targetID)
	if targetType == "lxc" {
		targetDataset = fmt.Sprintf("%s/lxc/subvol-%d-disk-0", pool, targetID)
	}

	upid := m.taskMgr.StartTask("qmrestore", fmt.Sprintf("%s-%d", targetType, targetID), user, func(logger func(format string, args ...any)) error {
		logger("Restoring %s %d from %s -> %s...", targetType, targetID, archivePath, targetDataset)
		cmd := exec.Command("/bin/bash", "-c", `set -o pipefail; zstd -dc "$1" | zfs receive -F "$2"`, "_", archivePath, targetDataset)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger("Restore failed: %s (%v)", string(out), err)
			return fmt.Errorf("restore failed: %s", strings.TrimSpace(string(out)))
		}
		logger("Restore completed successfully into %s.", targetDataset)
		return nil
	})
	return upid, nil
}

// PruneBackupsGFS prunes older backup archives in a pool, retaining the newest keepLast archives.
func (m *VirtManager) PruneBackupsGFS(pool string, keepLast int) ([]string, error) {
	if keepLast < 1 {
		return nil, fmt.Errorf("keepLast must be >= 1")
	}
	records := m.ListBackups(pool)
	if len(records) <= keepLast {
		return []string{}, nil
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Timestamp > records[j].Timestamp })
	var deleted []string
	for _, old := range records[keepLast:] {
		if info, err := os.Lstat(old.Path); err == nil && !info.IsDir() && (info.Mode()&os.ModeSymlink) == 0 {
			if os.Remove(old.Path) == nil {
				deleted = append(deleted, old.Name)
			}
		}
	}
	return deleted, nil
}

// LiveMigrateVM orchestrates QMP RAM live migration to a peer Axonwall hypervisor node.
func (m *VirtManager) LiveMigrateVM(vmid int, targetPeerIP string, user string) (string, error) {
	cleanIP := strings.TrimSpace(targetPeerIP)
	parsed := net.ParseIP(cleanIP)
	if parsed == nil || parsed.IsLoopback() || parsed.IsUnspecified() {
		return "", fmt.Errorf("invalid target peer IP %q for live migration", targetPeerIP)
	}
	qmpSock := fmt.Sprintf("/run/axonwall/qmp/vm-%d.sock", vmid)
	if _, err := os.Stat(qmpSock); err != nil {
		return "", fmt.Errorf("VM %d is not running (QMP socket %s missing)", vmid, qmpSock)
	}

	migPort := 49152 + (vmid % 1000)
	migURI := fmt.Sprintf("tcp:%s", net.JoinHostPort(cleanIP, strconv.Itoa(migPort)))

	upid := m.taskMgr.StartTask("qmigrate", strconv.Itoa(vmid), user, func(logger func(format string, args ...any)) error {
		logger("Initiating live QMP RAM migration for VM %d -> %s...", vmid, migURI)
		resp, err := SendQMPCommand(qmpSock, "migrate", map[string]any{"uri": migURI})
		if err != nil {
			logger("QMP migrate error: %v", err)
			return err
		}
		if qmpErr, hasErr := resp["error"]; hasErr {
			return fmt.Errorf("QMP migrate rejected: %v", qmpErr)
		}
		logger("QMP live migration stream started toward %s.", migURI)
		return nil
	})
	return upid, nil
}

// ExportLibvirtXML returns standard `<domain type='kvm'>` Libvirt XML for a registered VM.
func (m *VirtManager) ExportLibvirtXML(vmid int) (string, error) {
	m.mu.RLock()
	spec, ok := m.vmSpecs[vmid]
	defaultPool := m.defaultPool
	m.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("VM %d is not registered", vmid)
	}
	if strings.TrimSpace(spec.LibvirtXml) != "" {
		return spec.LibvirtXml, nil
	}
	memKiB := spec.MemoryMb * 1024
	if memKiB <= 0 {
		memKiB = 2097152
	}
	cores := spec.Cores
	if cores <= 0 {
		cores = 2
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<domain type='kvm'>\n  <name>%s</name>\n  <memory unit='KiB'>%d</memory>\n  <vcpu placement='static'>%d</vcpu>\n  <os>\n    <type arch='x86_64' machine='pc-q35-8.2'>hvm</type>\n  </os>\n  <cpu mode='host-passthrough'/>\n  <devices>\n    <emulator>%s</emulator>\n",
		spec.Name, memKiB, cores, spec.Binary)
	for idx, d := range spec.Disks {
		pool := d.Pool
		if pool == "" {
			pool = defaultPool
		}
		zvol := d.Zvol
		if zvol == "" {
			zvol = fmt.Sprintf("%s/vms/vm-%d-disk-%d", pool, vmid, idx)
		}
		devLetter := string(rune('a' + (idx % 26)))
		fmt.Fprintf(&b, "    <disk type='block' device='disk'>\n      <driver name='qemu' type='raw' cache='none'/>\n      <source dev='/dev/zvol/%s'/>\n      <target dev='vd%s' bus='virtio'/>\n    </disk>\n", zvol, devLetter)
	}
	fmt.Fprintf(&b, "    <graphics type='vnc' socket='/run/axonwall/vnc/vm-%d.sock'/>\n  </devices>\n</domain>\n", vmid)
	return b.String(), nil
}
