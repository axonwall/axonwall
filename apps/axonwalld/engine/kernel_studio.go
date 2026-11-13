package engine

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type KernelPciDevice struct {
	BDF               string `json:"bdf"`
	VendorID          string `json:"vendorId"`
	DeviceID          string `json:"deviceId"`
	DeviceClass       string `json:"deviceClass"`
	DeviceName        string `json:"deviceName"`
	Driver            string `json:"driver"`
	Module            string `json:"module,omitempty"`
	IommuGroup        int    `json:"iommuGroup,omitempty"`
	SubsystemVendorID string `json:"subsystemVendorId,omitempty"`
	SubsystemDeviceID string `json:"subsystemDeviceId,omitempty"`
}

type KernelStorageController struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Driver    string `json:"driver"`
	Model     string `json:"model,omitempty"`
	Transport string `json:"transport,omitempty"`
	SizeBytes uint64 `json:"sizeBytes,omitempty"`
}

type KernelNetworkInterface struct {
	Name      string `json:"name"`
	Driver    string `json:"driver"`
	MAC       string `json:"mac,omitempty"`
	Operstate string `json:"operstate,omitempty"`
	SpeedMbps int    `json:"speedMbps,omitempty"`
	BusPath   string `json:"busPath,omitempty"`
}

type KernelLoadedModule struct {
	Name      string   `json:"name"`
	SizeBytes uint64   `json:"sizeBytes"`
	RefCount  int      `json:"refCount"`
	UsedBy    []string `json:"usedBy"`
}

type KernelBuildToolchain struct {
	Ready             bool     `json:"ready"`
	MissingTools      []string `json:"missingTools"`
	AvailableTools    []string `json:"availableTools"`
	BuilderScriptPath string   `json:"builderScriptPath,omitempty"`
	FreeBytes         uint64   `json:"freeBytes"`
}

type KernelBuiltArtifact struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"` // "image-deb", "headers-deb", "config", "manifest"
	SizeBytes int64  `json:"sizeBytes"`
	Sha256    string `json:"sha256,omitempty"`
	CreatedAt string `json:"createdAt"`
}

type KernelDetectedHardware struct {
	Hostname             string                    `json:"hostname"`
	KernelRelease        string                    `json:"kernelRelease"`
	Arch                 string                    `json:"arch"`
	CpuVendor            string                    `json:"cpuVendor"`
	CpuModel             string                    `json:"cpuModel"`
	CpuCores             int                       `json:"cpuCores"`
	CpuFlags             []string                  `json:"cpuFlags"`
	SuggestedMarch       string                    `json:"suggestedMarch"`
	VirtVendor           string                    `json:"virtVendor,omitempty"`
	EfiBooted            bool                      `json:"efiBooted"`
	SecureBootEnabled    bool                      `json:"secureBootEnabled"`
	IommuActive          bool                      `json:"iommuActive"`
	IommuGroupsCount     int                       `json:"iommuGroupsCount"`
	TpmDevices           []string                  `json:"tpmDevices"`
	WatchdogDrivers      []string                  `json:"watchdogDrivers"`
	PciDevices           []KernelPciDevice         `json:"pciDevices"`
	StorageControllers   []KernelStorageController `json:"storageControllers"`
	NetworkInterfaces    []KernelNetworkInterface  `json:"networkInterfaces"`
	LoadedModules        []KernelLoadedModule      `json:"loadedModules"`
	HostAvailableModules int                       `json:"hostAvailableModules"`
}

type KernelStudioPosture struct {
	KernelPostureStatus
	UserNsCloneAllowed bool `json:"userNsCloneAllowed"`
}

type KernelTaskProgress struct {
	Task    *TaskRecord `json:"task"`
	LogTail []string    `json:"logTail"`
}

type KernelStudioState struct {
	Hardware      KernelDetectedHardware `json:"hardware"`
	RunningConfig map[string]string      `json:"runningConfig"`
	ConfigSource  string                 `json:"configSource"`
	Posture       KernelStudioPosture    `json:"posture"`
	Toolchain     KernelBuildToolchain   `json:"toolchain"`
	Artifacts     []KernelBuiltArtifact  `json:"artifacts"`
	InstallMode   string                 `json:"installMode,omitempty"`
	TaskProgress  *KernelTaskProgress    `json:"taskProgress,omitempty"`
}

type KernelBuildRequest struct {
	Mode                 string   `json:"mode"`
	ConfigOnly           bool     `json:"configOnly"`
	KernelVersion        string   `json:"kernelVersion"`
	Arch                 string   `json:"arch"`
	MarchTarget          string   `json:"marchTarget"`
	Capabilities         []string `json:"capabilities"`
	LockdownTier         string   `json:"lockdownTier"`
	EnableRootlessUserNs bool     `json:"enableRootlessUserNs"`
	DisableIa32Emulation bool     `json:"disableIa32Emulation"`
	EnforceModuleSig     bool     `json:"enforceModuleSig"`
	EnableProcKcore      bool     `json:"enableProcKcore"`
	HardwareFragment     string   `json:"hardwareFragment"`
}

type KernelStudioManager struct {
	mu                      sync.RWMutex
	procRoot                string
	sysRoot                 string
	bootRoot                string
	modulesRoot             string
	workRoot                string
	builderScriptCandidates []string
}

func NewKernelStudioManager() *KernelStudioManager {
	return &KernelStudioManager{
		procRoot:    "/proc",
		sysRoot:     "/sys",
		bootRoot:    "/boot",
		modulesRoot: "/lib/modules",
		workRoot:    "/var/lib/axonwall/kernel-builds",
		builderScriptCandidates: []string{
			"/usr/share/axonwall/kernel-builder/build-kernel.sh",
			"packaging/kernel/build-kernel.sh",
			"../../packaging/kernel/build-kernel.sh",
		},
	}
}

var (
	kernelVersionRe    = regexp.MustCompile(`^6\.[0-9]+\.[0-9]+$`)
	kconfigSetLineRe   = regexp.MustCompile(`^CONFIG_[A-Z0-9_]{2,64}=(y|m|n|"[a-zA-Z0-9_,.-]*")$`)
	kconfigUnsetLineRe = regexp.MustCompile(`^# CONFIG_[A-Z0-9_]{2,64} is not set$`)
	kconfigCommentRe   = regexp.MustCompile(`^#[ a-zA-Z0-9._:,/()=+-]*$`)
	artifactDebRe      = regexp.MustCompile(`^linux-image-[a-zA-Z0-9._+-]+\.deb$`)
)

var allowedKernelCapabilities = map[string]bool{
	"k3s":       true,
	"zfs":       true,
	"nftables":  true,
	"ebpf":      true,
	"kvm":       true,
	"ipsec":     true,
	"usb":       true,
	"iscsi_nfs": true,
}

var allowedMarchTargets = map[string]bool{
	"x86-64":    true,
	"x86-64-v2": true,
	"x86-64-v3": true,
	"x86-64-v4": true,
	"native":    true,
	"armv8-a":   true,
}

func ValidateKconfigFragment(fragment string) error {
	scanner := bufio.NewScanner(strings.NewReader(fragment))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if kconfigSetLineRe.MatchString(line) || kconfigUnsetLineRe.MatchString(line) || kconfigCommentRe.MatchString(line) {
			continue
		}
		return fmt.Errorf("disallowed line %d in kernel fragment: %q", lineNum, line)
	}
	return scanner.Err()
}

func SuggestMarchFromFlags(arch string, flags []string) string {
	if arch == "aarch64" || arch == "arm64" {
		return "armv8-a"
	}
	flagSet := make(map[string]bool, len(flags))
	for _, f := range flags {
		flagSet[f] = true
	}
	if flagSet["avx512f"] && flagSet["avx512bw"] && flagSet["avx512cd"] && flagSet["avx512dq"] && flagSet["avx512vl"] {
		return "x86-64-v4"
	}
	if flagSet["avx2"] && flagSet["bmi1"] && flagSet["bmi2"] && flagSet["fma"] {
		return "x86-64-v3"
	}
	if flagSet["sse4_2"] && flagSet["popcnt"] && flagSet["ssse3"] {
		return "x86-64-v2"
	}
	return "x86-64"
}

func (m *KernelStudioManager) parseCpuInfo() (vendor, model string, cores int, flags []string) {
	data, err := os.ReadFile(filepath.Join(m.procRoot, "cpuinfo"))
	if err != nil {
		return "Unknown", "Unknown CPU", runtime.NumCPU(), []string{}
	}
	flagSet := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "processor":
			cores++
		case "vendor_id":
			if vendor == "" {
				vendor = val
			}
		case "model name", "Model":
			if model == "" {
				model = val
			}
		case "flags", "Features":
			if len(flags) == 0 {
				for _, f := range strings.Fields(val) {
					if !flagSet[f] {
						flagSet[f] = true
						flags = append(flags, f)
					}
				}
			}
		}
	}
	if cores == 0 {
		cores = runtime.NumCPU()
	}
	if vendor == "" {
		vendor = "Unknown"
	}
	if model == "" {
		model = "Unknown CPU"
	}
	if flags == nil {
		flags = []string{}
	}
	return vendor, model, cores, flags
}

func (m *KernelStudioManager) parseLoadedModules() []KernelLoadedModule {
	data, err := os.ReadFile(filepath.Join(m.procRoot, "modules"))
	if err != nil {
		return []KernelLoadedModule{}
	}
	var out []KernelLoadedModule
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		sizeBytes, _ := strconv.ParseUint(fields[1], 10, 64)
		refCount, _ := strconv.Atoi(fields[2])
		usedBy := []string{}
		if len(fields) >= 4 && fields[3] != "-" {
			for _, dep := range strings.Split(strings.TrimRight(fields[3], ","), ",") {
				dep = strings.TrimSpace(dep)
				if dep != "" {
					usedBy = append(usedBy, dep)
				}
			}
		}
		out = append(out, KernelLoadedModule{
			Name:      fields[0],
			SizeBytes: sizeBytes,
			RefCount:  refCount,
			UsedBy:    usedBy,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func (m *KernelStudioManager) scanPciDevices() []KernelPciDevice {
	pciRoot := filepath.Join(m.sysRoot, "bus", "pci", "devices")
	entries, err := os.ReadDir(pciRoot)
	if err != nil {
		return []KernelPciDevice{}
	}

	lspciMap := make(map[string]string)
	if m.sysRoot == "/sys" {
		if out, err := exec.Command("lspci", "-D").CombinedOutput(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				parts := strings.SplitN(line, " ", 2)
				if len(parts) == 2 {
					lspciMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	var devices []KernelPciDevice
	for _, entry := range entries {
		bdf := entry.Name()
		if !bdfRegex.MatchString(bdf) {
			continue
		}
		devDir := filepath.Join(pciRoot, bdf)
		vendor := strings.TrimPrefix(readSysfsTrim(filepath.Join(devDir, "vendor")), "0x")
		device := strings.TrimPrefix(readSysfsTrim(filepath.Join(devDir, "device")), "0x")
		class := strings.TrimPrefix(readSysfsTrim(filepath.Join(devDir, "class")), "0x")
		subVendor := strings.TrimPrefix(readSysfsTrim(filepath.Join(devDir, "subsystem_vendor")), "0x")
		subDevice := strings.TrimPrefix(readSysfsTrim(filepath.Join(devDir, "subsystem_device")), "0x")

		driver := "none"
		mod := ""
		if dl, err := os.Readlink(filepath.Join(devDir, "driver")); err == nil {
			driver = filepath.Base(dl)
			if ml, err := os.Readlink(filepath.Join(devDir, "driver", "module")); err == nil {
				mod = filepath.Base(ml)
			}
		}
		iommuGroup := -1
		if il, err := os.Readlink(filepath.Join(devDir, "iommu_group")); err == nil {
			if g, err := strconv.Atoi(filepath.Base(il)); err == nil {
				iommuGroup = g
			}
		}
		devName := lspciMap[bdf]
		if devName == "" {
			devName = fmt.Sprintf("PCI [%s:%s] Class %s", vendor, device, class)
		}
		item := KernelPciDevice{
			BDF:               bdf,
			VendorID:          vendor,
			DeviceID:          device,
			DeviceClass:       class,
			DeviceName:        devName,
			Driver:            driver,
			Module:            mod,
			SubsystemVendorID: subVendor,
			SubsystemDeviceID: subDevice,
		}
		if iommuGroup >= 0 {
			item.IommuGroup = iommuGroup
		}
		devices = append(devices, item)
	}
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].BDF < devices[j].BDF
	})
	return devices
}

func (m *KernelStudioManager) scanStorageControllers() []KernelStorageController {
	blkRoot := filepath.Join(m.sysRoot, "class", "block")
	entries, err := os.ReadDir(blkRoot)
	if err != nil {
		return []KernelStorageController{}
	}
	var out []KernelStorageController
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "zd") {
			continue
		}
		devDir := filepath.Join(blkRoot, name)
		// Skip partitions (only whole block devices)
		if _, err := os.Stat(filepath.Join(devDir, "partition")); err == nil {
			continue
		}
		driver := "unknown"
		if dl, err := os.Readlink(filepath.Join(devDir, "device", "driver")); err == nil {
			driver = filepath.Base(dl)
		} else if strings.HasPrefix(name, "nvme") {
			driver = "nvme"
		} else if strings.HasPrefix(name, "vd") {
			driver = "virtio_blk"
		}
		model := readSysfsTrim(filepath.Join(devDir, "device", "model"))
		sectorsStr := readSysfsTrim(filepath.Join(devDir, "size"))
		sectors, _ := strconv.ParseUint(sectorsStr, 10, 64)
		kind := "disk"
		if strings.HasPrefix(name, "nvme") {
			kind = "nvme"
		} else if strings.HasPrefix(name, "vd") {
			kind = "virtio"
		} else if strings.HasPrefix(name, "md") {
			kind = "mdraid"
			driver = "md_mod"
		}
		out = append(out, KernelStorageController{
			Name:      name,
			Kind:      kind,
			Driver:    driver,
			Model:     model,
			SizeBytes: sectors * 512,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func (m *KernelStudioManager) scanNetworkInterfaces() []KernelNetworkInterface {
	netRoot := filepath.Join(m.sysRoot, "class", "net")
	entries, err := os.ReadDir(netRoot)
	if err != nil {
		return []KernelNetworkInterface{}
	}
	var out []KernelNetworkInterface
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "flannel") || strings.HasPrefix(name, "cni") {
			continue
		}
		ifaceDir := filepath.Join(netRoot, name)
		driver := "virtual"
		if dl, err := os.Readlink(filepath.Join(ifaceDir, "device", "driver")); err == nil {
			driver = filepath.Base(dl)
		}
		mac := readSysfsTrim(filepath.Join(ifaceDir, "address"))
		operstate := readSysfsTrim(filepath.Join(ifaceDir, "operstate"))
		speedMbps := 0
		if s := readSysfsTrim(filepath.Join(ifaceDir, "speed")); s != "" {
			if parsed, err := strconv.Atoi(s); err == nil && parsed > 0 {
				speedMbps = parsed
			}
		}
		out = append(out, KernelNetworkInterface{
			Name:      name,
			Driver:    driver,
			MAC:       mac,
			Operstate: operstate,
			SpeedMbps: speedMbps,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func (m *KernelStudioManager) countAvailableModules(release string) int {
	if release == "" {
		return 0
	}
	dir := filepath.Join(m.modulesRoot, release)
	if _, err := os.Stat(dir); err != nil {
		return 0
	}
	count := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, ".ko") || strings.HasSuffix(name, ".ko.zst") || strings.HasSuffix(name, ".ko.xz") || strings.HasSuffix(name, ".ko.gz") {
			count++
		}
		return nil
	})
	return count
}

func ParseKernelConfigText(text string) map[string]string {
	out := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "# CONFIG_") && strings.HasSuffix(line, " is not set") {
			sym := strings.TrimSuffix(strings.TrimPrefix(line, "# "), " is not set")
			out[sym] = "n"
			continue
		}
		if strings.HasPrefix(line, "CONFIG_") {
			if idx := strings.IndexByte(line, '='); idx > 0 {
				sym := line[:idx]
				val := strings.Trim(line[idx+1:], `"`)
				out[sym] = val
			}
		}
	}
	return out
}

func (m *KernelStudioManager) readRunningKernelConfig(release string) (map[string]string, string) {
	procCfgGz := filepath.Join(m.procRoot, "config.gz")
	if f, err := os.Open(procCfgGz); err == nil {
		defer f.Close()
		if gz, err := gzip.NewReader(f); err == nil {
			defer gz.Close()
			if raw, err := io.ReadAll(io.LimitReader(gz, 2*1024*1024)); err == nil {
				return ParseKernelConfigText(string(raw)), procCfgGz
			}
		}
	}
	if release != "" {
		bootCfg := filepath.Join(m.bootRoot, "config-"+release)
		if raw, err := os.ReadFile(bootCfg); err == nil {
			return ParseKernelConfigText(string(raw)), bootCfg
		}
	}
	return map[string]string{}, ""
}

func (m *KernelStudioManager) resolveBuilderScript() string {
	for _, candidate := range m.builderScriptCandidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			if abs, err := filepath.Abs(candidate); err == nil {
				return abs
			}
			return candidate
		}
	}
	return ""
}

func (m *KernelStudioManager) inspectToolchain() KernelBuildToolchain {
	required := []string{"gcc", "make", "flex", "bison", "bc", "pahole", "dpkg-deb"}
	var missing, available []string
	for _, tool := range required {
		if _, err := exec.LookPath(tool); err == nil {
			available = append(available, tool)
		} else {
			missing = append(missing, tool)
		}
	}

	var freeBytes uint64
	checkDir := m.workRoot
	for checkDir != "/" {
		if _, err := os.Stat(checkDir); err == nil {
			break
		}
		checkDir = filepath.Dir(checkDir)
	}
	var st unix.Statfs_t
	if err := unix.Statfs(checkDir, &st); err == nil {
		freeBytes = st.Bavail * uint64(st.Bsize)
	}

	scriptPath := m.resolveBuilderScript()
	ready := len(missing) == 0 && scriptPath != ""
	if missing == nil {
		missing = []string{}
	}
	if available == nil {
		available = []string{}
	}
	return KernelBuildToolchain{
		Ready:             ready,
		MissingTools:      missing,
		AvailableTools:    available,
		BuilderScriptPath: scriptPath,
		FreeBytes:         freeBytes,
	}
}

func (m *KernelStudioManager) listArtifacts() []KernelBuiltArtifact {
	outDir := filepath.Join(m.workRoot, "output")
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return []KernelBuiltArtifact{}
	}
	var artifacts []KernelBuiltArtifact
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".sha256") {
			continue
		}
		kind := ""
		switch {
		case strings.HasPrefix(name, "linux-image-") && strings.HasSuffix(name, ".deb"):
			kind = "image-deb"
		case strings.HasPrefix(name, "linux-headers-") && strings.HasSuffix(name, ".deb"):
			kind = "headers-deb"
		case strings.HasSuffix(name, ".config"):
			kind = "config"
		case name == "build-manifest.json":
			kind = "manifest"
		default:
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		sha := ""
		if shaBytes, err := os.ReadFile(filepath.Join(outDir, name+".sha256")); err == nil {
			fields := strings.Fields(string(shaBytes))
			if len(fields) > 0 {
				sha = fields[0]
			}
		}
		artifacts = append(artifacts, KernelBuiltArtifact{
			Name:      name,
			Kind:      kind,
			SizeBytes: info.Size(),
			Sha256:    sha,
			CreatedAt: info.ModTime().UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].CreatedAt > artifacts[j].CreatedAt
	})
	return artifacts
}

func (m *KernelStudioManager) InspectStudioState(watchdog *WatchdogEngine, taskMgr *TaskManager, upid string) KernelStudioState {
	hostname, _ := os.Hostname()
	var uts unix.Utsname
	release := ""
	arch := runtime.GOARCH
	if err := unix.Uname(&uts); err == nil {
		release = cBytesToString(uts.Release[:])
		arch = cBytesToString(uts.Machine[:])
	}

	vendor, model, cores, flags := m.parseCpuInfo()
	suggestedMarch := SuggestMarchFromFlags(arch, flags)

	virtVendor := readSysfsTrim(filepath.Join(m.sysRoot, "class", "dmi", "id", "sys_vendor"))
	if virtVendor == "" {
		virtVendor = readSysfsTrim(filepath.Join(m.sysRoot, "hypervisor", "type"))
	}

	_, efiErr := os.Stat(filepath.Join(m.sysRoot, "firmware", "efi"))
	efiBooted := efiErr == nil

	secureBoot := false
	if sbMatches, _ := filepath.Glob(filepath.Join(m.sysRoot, "firmware", "efi", "efivars", "SecureBoot-*")); len(sbMatches) > 0 {
		if raw, err := os.ReadFile(sbMatches[0]); err == nil && len(raw) >= 5 && raw[4] == 1 {
			secureBoot = true
		}
	}

	iommuGroups, _ := filepath.Glob(filepath.Join(m.sysRoot, "kernel", "iommu_groups", "*"))
	tpmEntries, _ := filepath.Glob(filepath.Join(m.sysRoot, "class", "tpm", "*"))
	var tpms []string
	for _, p := range tpmEntries {
		tpms = append(tpms, filepath.Base(p))
	}
	if tpms == nil {
		tpms = []string{}
	}

	wdtEntries, _ := filepath.Glob(filepath.Join(m.sysRoot, "class", "watchdog", "*"))
	var watchdogs []string
	for _, p := range wdtEntries {
		idPath := filepath.Join(p, "identity")
		id := readSysfsTrim(idPath)
		if id == "" {
			id = filepath.Base(p)
		}
		watchdogs = append(watchdogs, id)
	}
	if watchdogs == nil {
		watchdogs = []string{}
	}

	hw := KernelDetectedHardware{
		Hostname:             hostname,
		KernelRelease:        release,
		Arch:                 arch,
		CpuVendor:            vendor,
		CpuModel:             model,
		CpuCores:             cores,
		CpuFlags:             flags,
		SuggestedMarch:       suggestedMarch,
		VirtVendor:           virtVendor,
		EfiBooted:            efiBooted,
		SecureBootEnabled:    secureBoot,
		IommuActive:          len(iommuGroups) > 0,
		IommuGroupsCount:     len(iommuGroups),
		TpmDevices:           tpms,
		WatchdogDrivers:      watchdogs,
		PciDevices:           m.scanPciDevices(),
		StorageControllers:   m.scanStorageControllers(),
		NetworkInterfaces:    m.scanNetworkInterfaces(),
		LoadedModules:        m.parseLoadedModules(),
		HostAvailableModules: m.countAvailableModules(release),
	}

	runningCfg, cfgSource := m.readRunningKernelConfig(release)
	posture := KernelStudioPosture{
		KernelPostureStatus: InspectKernelPosture(),
		UserNsCloneAllowed:  ProbeBpfTokenCapabilities().UserNsCloneAllowed,
	}

	installMode := ""
	if watchdog != nil {
		installMode = watchdog.GetStatus().InstallMode
	}

	var progress *KernelTaskProgress
	if upid != "" && taskMgr != nil {
		if rec, err := taskMgr.GetTask(upid); err == nil {
			tail := readLogTailLines(rec.LogFile, 120)
			progress = &KernelTaskProgress{
				Task:    rec,
				LogTail: tail,
			}
		}
	}

	return KernelStudioState{
		Hardware:      hw,
		RunningConfig: runningCfg,
		ConfigSource:  cfgSource,
		Posture:       posture,
		Toolchain:     m.inspectToolchain(),
		Artifacts:     m.listArtifacts(),
		InstallMode:   installMode,
		TaskProgress:  progress,
	}
}

func readLogTailLines(path string, maxLines int) []string {
	if path == "" {
		return []string{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{}
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines
}

func (m *KernelStudioManager) StartBuild(taskMgr *TaskManager, req KernelBuildRequest, user string) (string, string, error) {
	if taskMgr == nil {
		return "", "", fmt.Errorf("task manager unavailable")
	}

	mode := req.Mode
	if req.ConfigOnly {
		mode = "config-only"
	} else if mode != "universal" && mode != "stripped" && mode != "config-only" {
		return "", "", fmt.Errorf("invalid build mode %q (expected universal, stripped, or config-only)", req.Mode)
	}

	kver := strings.TrimSpace(req.KernelVersion)
	if kver == "" {
		kver = "6.12.15"
	}
	if !kernelVersionRe.MatchString(kver) {
		return "", "", fmt.Errorf("invalid kernel version %q (expected 6.x.y)", kver)
	}

	arch := strings.TrimSpace(req.Arch)
	if arch == "" {
		arch = "amd64"
	}
	if arch != "amd64" && arch != "arm64" {
		return "", "", fmt.Errorf("invalid target arch %q", arch)
	}

	lockdown := strings.TrimSpace(req.LockdownTier)
	if lockdown == "" {
		lockdown = "integrity"
	}
	if lockdown != "integrity" && lockdown != "confidentiality" {
		return "", "", fmt.Errorf("invalid lockdown tier %q", lockdown)
	}

	march := strings.TrimSpace(req.MarchTarget)
	if march == "" {
		march = "x86-64"
	}
	if !allowedMarchTargets[march] {
		return "", "", fmt.Errorf("invalid march target %q", march)
	}

	if len(req.Capabilities) == 0 {
		return "", "", fmt.Errorf("at least one kernel capability pack must be enabled")
	}
	var cleanCaps []string
	for _, capName := range req.Capabilities {
		trimmed := strings.TrimSpace(capName)
		if !allowedKernelCapabilities[trimmed] {
			return "", "", fmt.Errorf("disallowed kernel capability %q", capName)
		}
		cleanCaps = append(cleanCaps, trimmed)
	}

	if req.HardwareFragment != "" {
		if err := ValidateKconfigFragment(req.HardwareFragment); err != nil {
			return "", "", err
		}
	}

	scriptPath := m.resolveBuilderScript()
	if scriptPath == "" {
		return "", "", fmt.Errorf("kernel builder script not found on host")
	}

	buildID := fmt.Sprintf("kbuild-%s-%s", mode, time.Now().UTC().Format("20060102-150405"))
	jobDir := filepath.Join(m.workRoot, buildID)
	outDir := filepath.Join(m.workRoot, "output")
	if err := os.MkdirAll(jobDir, 0750); err != nil {
		return "", "", fmt.Errorf("creating build job directory: %w", err)
	}
	if err := os.MkdirAll(outDir, 0750); err != nil {
		return "", "", fmt.Errorf("creating build output directory: %w", err)
	}

	args := []string{
		"--mode", mode,
		"--kernel-version", kver,
		"--arch", arch,
		"--march", march,
		"--capabilities", strings.Join(cleanCaps, ","),
		"--lockdown", lockdown,
		"--output-dir", outDir,
	}

	if req.HardwareFragment != "" {
		fragPath := filepath.Join(jobDir, "hardware.fragment.config")
		if err := os.WriteFile(fragPath, []byte(req.HardwareFragment), 0640); err != nil {
			return "", "", fmt.Errorf("writing hardware fragment: %w", err)
		}
		args = append(args, "--hardware-fragment", fragPath)
	}

	if mode == "stripped" {
		if mods, err := os.ReadFile(filepath.Join(m.procRoot, "modules")); err == nil && len(mods) > 0 {
			lsmodPath := filepath.Join(jobDir, "host.lsmod")
			if err := os.WriteFile(lsmodPath, mods, 0640); err == nil {
				args = append(args, "--lsmod-file", lsmodPath)
			}
		}
	}

	if req.DisableIa32Emulation {
		args = append(args, "--disable-ia32")
	}
	if !req.EnableRootlessUserNs {
		args = append(args, "--no-userns")
	}
	if req.EnforceModuleSig {
		args = append(args, "--force-module-sig")
	}
	if !req.EnableProcKcore {
		args = append(args, "--disable-kcore")
	}

	upid := taskMgr.StartTask("kernelbuild", buildID, user, func(logfn func(format string, a ...any)) error {
		logfn("Starting %s (%s) with args: %s", scriptPath, buildID, strings.Join(args, " "))
		cmd := exec.Command(scriptPath, args...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		cmd.Stderr = cmd.Stdout
		if err := cmd.Start(); err != nil {
			return err
		}
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			logfn("%s", scanner.Text())
		}
		return cmd.Wait()
	})

	return upid, buildID, nil
}

func (m *KernelStudioManager) InstallArtifactSafely(taskMgr *TaskManager, watchdog *WatchdogEngine, artifactName, user string) (string, string, string, error) {
	if taskMgr == nil {
		return "", "", "", fmt.Errorf("task manager unavailable")
	}
	cleanName := filepath.Base(strings.TrimSpace(artifactName))
	if cleanName != strings.TrimSpace(artifactName) || !artifactDebRe.MatchString(cleanName) {
		return "", "", "", fmt.Errorf("invalid kernel package filename %q", artifactName)
	}

	outDir := filepath.Join(m.workRoot, "output")
	debPath := filepath.Join(outDir, cleanName)
	if rel, err := filepath.Rel(outDir, debPath); err != nil || rel != cleanName {
		return "", "", "", fmt.Errorf("invalid artifact path")
	}
	if _, err := os.Stat(debPath); err != nil {
		return "", "", "", fmt.Errorf("kernel artifact not found: %s", cleanName)
	}

	// Verify optional .sha256 sidecar if present
	if shaBytes, err := os.ReadFile(debPath + ".sha256"); err == nil {
		fields := strings.Fields(string(shaBytes))
		if len(fields) > 0 {
			f, openErr := os.Open(debPath)
			if openErr != nil {
				return "", "", "", openErr
			}
			h := sha256.New()
			_, copyErr := io.Copy(h, f)
			_ = f.Close()
			if copyErr != nil {
				return "", "", "", copyErr
			}
			actualSha := hex.EncodeToString(h.Sum(nil))
			if !strings.EqualFold(actualSha, fields[0]) {
				return "", "", "", fmt.Errorf("checksum mismatch for %s", cleanName)
			}
		}
	}

	installMode := "rolling"
	activeBE := ""
	if watchdog != nil {
		st := watchdog.GetStatus()
		if st.InstallMode != "" {
			installMode = st.InstallMode
		}
		for _, be := range st.BootEnvironments {
			if be.ActiveNow {
				activeBE = be.Name
				break
			}
		}
	}

	var safetyNote string
	if installMode == "zbm" {
		safetyNote = "Clones a standby ZFS Boot Environment before installing the custom kernel so active root stays untouched for ZFSBootMenu rollback."
	} else {
		safetyNote = "Installs custom kernel alongside running Debian kernel and arms one-shot grub-reboot when available; previous kernel remains default fallback."
	}

	upid := taskMgr.StartTask("kernelinstall", cleanName, user, func(logfn func(format string, a ...any)) error {
		logfn("Staging custom kernel package %s (mode=%s)", cleanName, installMode)
		if installMode == "zbm" && watchdog != nil && activeBE != "" {
			snapLabel := "pre-kernel-" + time.Now().UTC().Format("20060102-150405")
			fullSnap, err := watchdog.CreateBootEnvironmentSnapshot(activeBE, snapLabel)
			if err != nil {
				return fmt.Errorf("creating ZFS BE snapshot before kernel install: %w", err)
			}
			logfn("Created pre-install ZFS snapshot: %s", fullSnap)
			newBeName := "axonwall-kcustom-" + time.Now().UTC().Format("20060102-150405")
			dataset, err := watchdog.CloneSnapshotToBootEnvironment(fullSnap, newBeName)
			if err != nil {
				return fmt.Errorf("cloning ZFS BE for kernel install: %w", err)
			}
			logfn("Cloned standby ZFS Boot Environment: %s (%s)", newBeName, dataset)

			mntDir, err := os.MkdirTemp("", "axonwall-be-mnt.")
			if err != nil {
				return err
			}
			defer os.RemoveAll(mntDir)

			if out, err := exec.Command("mount", "-t", "zfs", dataset, mntDir).CombinedOutput(); err != nil {
				return fmt.Errorf("mounting cloned ZFS BE %s: %v (%s)", dataset, err, strings.TrimSpace(string(out)))
			}
			defer func() {
				_ = exec.Command("umount", mntDir).Run()
			}()

			tmpDeb := filepath.Join(mntDir, "tmp", cleanName)
			if raw, err := os.ReadFile(debPath); err != nil {
				return err
			} else if err := os.WriteFile(tmpDeb, raw, 0644); err != nil {
				return err
			}
			defer os.Remove(tmpDeb)

			if out, err := exec.Command("chroot", mntDir, "dpkg", "-i", "/tmp/"+cleanName).CombinedOutput(); err != nil {
				return fmt.Errorf("installing %s inside ZFS BE %s: %v (%s)", cleanName, newBeName, err, strings.TrimSpace(string(out)))
			}
			logfn("Installed %s inside standby ZFS Boot Environment %s", cleanName, newBeName)
			return nil
		}

		// Standard A/B or rolling Debian root: install side-by-side (dpkg -i never removes running kernel)
		if out, err := exec.Command("dpkg", "-i", debPath).CombinedOutput(); err != nil {
			return fmt.Errorf("dpkg -i %s failed: %v (%s)", cleanName, err, strings.TrimSpace(string(out)))
		}
		logfn("Installed %s alongside running kernel.", cleanName)
		if _, err := exec.LookPath("update-grub"); err == nil {
			if out, err := exec.Command("update-grub").CombinedOutput(); err != nil {
				logfn("Warning: update-grub returned error: %v (%s)", err, strings.TrimSpace(string(out)))
			} else {
				logfn("Updated GRUB menu entries.")
			}
		}
		return nil
	})

	return upid, installMode, safetyNote, nil
}
