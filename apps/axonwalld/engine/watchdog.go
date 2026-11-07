package engine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type CheckStatus string

const (
	CheckStatusPass CheckStatus = "PASS"
	CheckStatusFail CheckStatus = "FAIL"
	CheckStatusWarn CheckStatus = "WARN"
)

// HealthCheckResult reports the outcome of a system health verification test.
type HealthCheckResult struct {
	Name       string      `json:"name"`
	Status     CheckStatus `json:"status"`
	Detail     string      `json:"detail"`
	DurationMs int64       `json:"durationMs"`
}

// ZfsSnapshotDetail provides rich telemetry for an individual OpenZFS snapshot.
type ZfsSnapshotDetail struct {
	Name      string `json:"name"`      // e.g. "factory-initial"
	FullName  string `json:"fullName"`  // e.g. "zroot/ROOT/axonwall-0.11.52@factory-initial"
	Dataset   string `json:"dataset"`   // e.g. "zroot/ROOT/axonwall-0.11.52"
	BeName    string `json:"beName"`    // e.g. "axonwall-0.11.52"
	UsedSize  string `json:"usedSize"`  // e.g. "142M"
	ReferSize string `json:"referSize"` // e.g. "1.41G"
	CreatedAt string `json:"createdAt"` // e.g. "Sun Nov  1 16:12 2026"
}

// ZfsBootEnvironment represents an OpenZFS Boot Environment managed by ZFSBootMenu v3.1.x.
type ZfsBootEnvironment struct {
	Name            string              `json:"name"`       // e.g. "axonwall-0.11.30"
	Dataset         string              `json:"dataset"`    // e.g. "zroot/ROOT/axonwall-0.11.30"
	ActiveNow       bool                `json:"activeNow"`  // Currently mounted on /
	ActiveNext      bool                `json:"activeNext"` // Staged in zpool bootfs for next reboot
	Version         string              `json:"version"`
	UsedSize        string              `json:"usedSize"`
	CreatedAt       string              `json:"createdAt"`
	Snapshots       []string            `json:"snapshots"`
	SnapshotDetails []ZfsSnapshotDetail `json:"snapshotDetails,omitempty"`
}

// PartitionStatus details the state of the A/B dual-root, Rolling single-root, or ZFSBootMenu system and boot watchdog.
type PartitionStatus struct {
	InstallMode      string               `json:"installMode"`      // "ab", "rolling", or "zbm"
	ActiveSlot       string               `json:"activeSlot"`       // "A" or "B" (or "ZBM")
	InactiveSlot     string               `json:"inactiveSlot"`     // "B" or "A"
	ActiveRootDevice string               `json:"activeRootDevice"` // e.g. "/dev/sda2" or "zroot/ROOT/axonwall-0.11.30"
	BootCount        int                  `json:"bootCount"`        // Current boot attempt count
	BootLimit        int                  `json:"bootLimit"`        // Maximum attempts before fallback
	HealthVerified   bool                 `json:"healthVerified"`   // True once quorum passes and bootcount is cleared
	LastVerifiedAt   time.Time            `json:"lastVerifiedAt"`   // Time verification finished
	KernelVersion    string               `json:"kernelVersion"`    // Linux kernel release
	OsVersion        string               `json:"osVersion"`        // OS release string
	SlotAVersion     string               `json:"slotAVersion"`     // Installed OS version on Slot A / Active BE
	SlotBVersion     string               `json:"slotBVersion"`     // Installed OS version on Slot B / Standby BE
	Checks           []HealthCheckResult  `json:"checks"`
	ZbmPoolName      string               `json:"zbmPoolName,omitempty"`
	ZbmPoolTopology  string               `json:"zbmPoolTopology,omitempty"`
	ZbmPoolHealth    string               `json:"zbmPoolHealth,omitempty"`
	BootEnvironments []ZfsBootEnvironment `json:"bootEnvironments,omitempty"`
}

type PersistedSlotVersions struct {
	SlotA     string `json:"slotA"`
	SlotB     string `json:"slotB"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

// WatchdogEngine manages A/B partition verification, GRUB boot-counting, and automated recovery.
type WatchdogEngine struct {
	mu               sync.RWMutex
	grubenvPath      string
	cmdlinePath      string
	slotVersionsPath string
	status           PartitionStatus
	stopChan         chan struct{}
	bootSyncDone     bool

	// Injectable for tests; production values are set by the constructor.
	updaterPaths        []string
	checkInterfaces     func() HealthCheckResult
	checkNftables       func() HealthCheckResult
	checkControlPlane   func() HealthCheckResult
	readSlotDiskVersion func(slot string) string
	readInstalledVer    func() string
	runZfsCmd           func(args ...string) ([]byte, error)
	runZpoolCmd         func(args ...string) ([]byte, error)
}

// NewWatchdogEngine initializes the A/B system watchdog engine with default paths.
func NewWatchdogEngine() *WatchdogEngine {
	return NewWatchdogEngineCustom("/boot/grub/grubenv", "/proc/cmdline")
}

// NewWatchdogEngineCustom allows injecting custom paths for unit tests and container environments.
func NewWatchdogEngineCustom(grubenvPath string, cmdlinePath string) *WatchdogEngine {
	slotVersionsPath := filepath.Join(filepath.Dir(grubenvPath), "slot_versions.json")
	if grubenvPath == "/boot/grub/grubenv" {
		slotVersionsPath = "/var/lib/axonwall/slot_versions.json"
	}
	we := &WatchdogEngine{
		grubenvPath:      grubenvPath,
		cmdlinePath:      cmdlinePath,
		slotVersionsPath: slotVersionsPath,
		stopChan:         make(chan struct{}),
		updaterPaths:     []string{"/usr/local/bin/axonwall-update", "/usr/sbin/axonwall-update"},
	}
	we.checkInterfaces = we.verifyInterfaces
	we.checkNftables = we.verifyNftables
	we.checkControlPlane = we.verifyControlPlane
	we.readSlotDiskVersion = we.readSlotVersionFromDiskReal
	we.readInstalledVer = readInstalledVersion
	we.runZfsCmd = func(args ...string) ([]byte, error) {
		return exec.Command("zfs", args...).CombinedOutput()
	}
	we.runZpoolCmd = func(args ...string) ([]byte, error) {
		return exec.Command("zpool", args...).CombinedOutput()
	}
	we.detectInitialState()
	return we
}

func (we *WatchdogEngine) getInstalledVersion() string {
	if we.readInstalledVer != nil {
		return we.readInstalledVer()
	}
	return readInstalledVersion()
}

func (we *WatchdogEngine) getSlotVersionsPath() string {
	if we.slotVersionsPath != "" {
		return we.slotVersionsPath
	}
	return "/var/lib/axonwall/slot_versions.json"
}

func (we *WatchdogEngine) loadSlotVersions() (string, string) {
	primaryPath := we.getSlotVersionsPath()
	for _, p := range []string{primaryPath, "/etc/axonwall/slot_versions.json"} {
		if data, err := os.ReadFile(p); err == nil {
			var psv PersistedSlotVersions
			if err := json.Unmarshal(data, &psv); err == nil {
				return strings.TrimSpace(psv.SlotA), strings.TrimSpace(psv.SlotB)
			}
		}
	}
	return "", ""
}

func (we *WatchdogEngine) saveSlotVersionsLocked() {
	psv := PersistedSlotVersions{
		SlotA:     we.status.SlotAVersion,
		SlotB:     we.status.SlotBVersion,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(psv, "", "  ")
	if err != nil {
		return
	}
	primaryPath := we.getSlotVersionsPath()
	paths := []string{primaryPath}
	if primaryPath != "/etc/axonwall/slot_versions.json" {
		paths = append(paths, "/etc/axonwall/slot_versions.json")
	}
	for _, p := range paths {
		_ = os.MkdirAll(filepath.Dir(p), 0755)
		_ = os.WriteFile(p, data, 0644)
	}
}

func resolveLabelDevice(label string) string {
	byLabel := "/dev/disk/by-label/" + label
	if _, err := os.Stat(byLabel); err == nil {
		return byLabel
	}
	if out, err := exec.Command("findfs", "LABEL="+label).Output(); err == nil {
		if dev := strings.TrimSpace(string(out)); dev != "" {
			return dev
		}
	}
	if out, err := exec.Command("blkid", "-L", label).Output(); err == nil {
		if dev := strings.TrimSpace(string(out)); dev != "" {
			return dev
		}
	}
	return byLabel
}

func detectActiveSlotFromSystem(cmdlinePath string) (string, string) {
	activeSlot := "A"
	rootDevice := resolveLabelDevice("axon_root_a")

	// 1. Inspect kernel cmdline if accessible
	if cmdlineBytes, err := os.ReadFile(cmdlinePath); err == nil {
		cmdline := string(cmdlineBytes)
		// E2-11: rootfsB/rootfsA are matched as exact tokens, never
		// bare substrings — firstboot treats rootfsB=0 as slot A
		// (rootfsB=1 is B), and a bare Contains read rootfsB=0 as B.
		if strings.Contains(cmdline, "axon_root_b") || cmdlineHasToken(cmdline, "rootfsB=1") || cmdlineHasToken(cmdline, "rootfsA=0") || strings.Contains(cmdline, "slot=B") {
			return "B", resolveLabelDevice("axon_root_b")
		} else if strings.Contains(cmdline, "axon_root_a") || cmdlineHasToken(cmdline, "rootfsB=0") || cmdlineHasToken(cmdline, "rootfsA=1") || strings.Contains(cmdline, "slot=A") {
			return "A", resolveLabelDevice("axon_root_a")
		}
	}

	// 2. Fallback: inspect /proc/mounts to find root filesystem device
	if mountsData, err := os.ReadFile("/proc/mounts"); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(mountsData))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 && fields[1] == "/" {
				dev := fields[0]
				if out, err := exec.Command("blkid", "-s", "LABEL", "-o", "value", dev).Output(); err == nil {
					lbl := strings.TrimSpace(string(out))
					if lbl == "axon_root_b" {
						return "B", dev
					} else if lbl == "axon_root_a" {
						return "A", dev
					}
				}
				rootDevice = dev
				break
			}
		}
	}

	return activeSlot, rootDevice
}

func findMountPointForDevice(dev string) string {
	mountsData, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(bytes.NewReader(mountsData))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			mDev := fields[0]
			mMount := fields[1]
			if mMount == "/" {
				continue
			}
			if mDev == dev {
				return mMount
			}
			if realDev, err := filepath.EvalSymlinks(dev); err == nil && realDev != "" && mDev == realDev {
				return mMount
			}
			if realMDev, err := filepath.EvalSymlinks(mDev); err == nil && realMDev != "" && realMDev == dev {
				return mMount
			}
		}
	}
	return ""
}

func readVersionFromDirectory(dir string) string {
	for _, sub := range []string{"etc/axonwall/version", "opt/axonwall/apps/axonwall/package.json", "opt/axonwall/package.json"} {
		fpath := filepath.Join(dir, sub)
		if data, err := os.ReadFile(fpath); err == nil {
			trimmed := strings.TrimSpace(string(data))
			if strings.HasPrefix(trimmed, "{") {
				var pkg struct {
					Version string `json:"version"`
				}
				if err := json.Unmarshal(data, &pkg); err == nil && strings.TrimSpace(pkg.Version) != "" {
					return strings.TrimSpace(pkg.Version)
				}
				if idx := strings.Index(trimmed, `"version":`); idx != -1 {
					s := trimmed[idx+10:]
					s = strings.TrimSpace(strings.Trim(strings.Split(s, ",")[0], ` "`+"\n\r\t}"))
					if s != "" {
						return s
					}
				}
			} else if trimmed != "" {
				lines := strings.Split(trimmed, "\n")
				if len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
					return strings.TrimSpace(lines[0])
				}
			}
		}
	}
	return ""
}

func (we *WatchdogEngine) readSlotVersionFromDiskReal(slot string) string {
	slotUpper := strings.ToUpper(strings.TrimSpace(slot))
	label := "axon_root_a"
	if slotUpper == "B" {
		label = "axon_root_b"
	}

	dev := resolveLabelDevice(label)
	if dev == "" {
		return ""
	}
	if _, err := os.Stat(dev); err != nil {
		return ""
	}

	// 1. Check if device is already mounted somewhere other than /
	mountDir := findMountPointForDevice(dev)
	if mountDir != "" {
		if v := readVersionFromDirectory(mountDir); v != "" {
			return v
		}
	}

	// 2. Temporarily mount read-only
	_ = os.MkdirAll("/run/axonwall", 0750)
	tmpDir, err := os.MkdirTemp("/run/axonwall", "axon_slot_check_*")
	if err != nil {
		tmpDir, err = os.MkdirTemp("", "axon_slot_check_*")
		if err != nil {
			return ""
		}
	}
	defer os.Remove(tmpDir)

	// Try mounting with ro,noload (prevent ext4 journal replay modifications)
	mountCmd := exec.Command("mount", "-o", "ro,noload", dev, tmpDir)
	if err := mountCmd.Run(); err != nil {
		mountCmd = exec.Command("mount", "-o", "ro", dev, tmpDir)
		if err := mountCmd.Run(); err != nil {
			return ""
		}
	}
	defer func() {
		_ = exec.Command("umount", "-l", tmpDir).Run()
	}()

	return readVersionFromDirectory(tmpDir)
}

var (
	zbmIdentifierRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
	zbmSnapshotRegex   = regexp.MustCompile(`^([a-zA-Z0-9._/-]+@)?[a-zA-Z0-9._-]+$`)
)

// cmdlineHasToken reports whether cmdline carries token as a whole
// whitespace-delimited word. E2-11: bare strings.Contains matching
// mistook "rootfsB=0" (firstboot: slot A) for slot B.
func cmdlineHasToken(cmdline, token string) bool {
	for _, field := range strings.Fields(cmdline) {
		if field == token {
			return true
		}
	}
	return false
}

// detectRunningSlotFromCmdline reports which slot the running kernel
// actually booted from, based only on the kernel cmdline. The second
// return is false when the cmdline is unreadable or carries no slot
// marker, so callers can fall back to in-memory state instead of
// trusting detectActiveSlotFromSystem's default-A. (E9: the in-memory
// ActiveSlot is updated by ActivateSlot BEFORE any reboot, so after
// arming it names the staged slot, not the running one.)
func detectRunningSlotFromCmdline(cmdlinePath string) (string, bool) {
	cmdlineBytes, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return "", false
	}
	cmdline := string(cmdlineBytes)
	// E2-11: exact-token matches only (see cmdlineHasToken).
	if strings.Contains(cmdline, "axon_root_b") || cmdlineHasToken(cmdline, "rootfsB=1") || cmdlineHasToken(cmdline, "rootfsA=0") || strings.Contains(cmdline, "slot=B") {
		return "B", true
	}
	if strings.Contains(cmdline, "axon_root_a") || cmdlineHasToken(cmdline, "rootfsB=0") || cmdlineHasToken(cmdline, "rootfsA=1") || strings.Contains(cmdline, "slot=A") {
		return "A", true
	}
	return "", false
}

func detectInstallModeCustom(cmdlinePath string) string {
	for _, p := range []string{"/etc/axonwall/install-mode", "/var/lib/axonwall/install-mode"} {
		if data, err := os.ReadFile(p); err == nil {
			content := strings.ToLower(strings.TrimSpace(string(data)))
			if strings.Contains(content, "zbm") || strings.Contains(content, "zfsbootmenu") {
				return "zbm"
			}
			if strings.Contains(content, "rolling") {
				return "rolling"
			}
			if strings.Contains(content, "ab") {
				return "ab"
			}
		}
	}
	if cmdlineBytes, err := os.ReadFile(cmdlinePath); err == nil {
		cmdline := string(cmdlineBytes)
		if strings.Contains(cmdline, "zfs=") || strings.Contains(cmdline, "zroot/ROOT") || strings.Contains(cmdline, "boot=zfs") {
			return "zbm"
		}
		if strings.Contains(cmdline, "rolling") {
			return "rolling"
		}
	}
	if mountsData, err := os.ReadFile("/proc/mounts"); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(mountsData))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 3 && fields[1] == "/" {
				if fields[2] == "zfs" || strings.Contains(fields[0], "zroot/ROOT") {
					return "zbm"
				}
				break
			}
		}
	}
	return "ab"
}

func detectInstallMode() string {
	return detectInstallModeCustom("/proc/cmdline")
}

func (we *WatchdogEngine) detectInitialState() {
	we.mu.Lock()
	defer we.mu.Unlock()

	installMode := detectInstallModeCustom(we.cmdlinePath)
	activeSlot, rootDevice := detectActiveSlotFromSystem(we.cmdlinePath)
	inactiveSlot := "B"
	if activeSlot == "B" {
		inactiveSlot = "A"
	}
	if installMode == "rolling" {
		activeSlot = "A"
		inactiveSlot = "A"
	} else if installMode == "zbm" {
		activeSlot = "A"
		inactiveSlot = "B"
	}

	// 2. Read boot-counting parameters
	bootCount := 1
	bootLimit := 3
	if installMode == "zbm" {
		if bcOut, err := we.runZfsCmd("get", "-H", "-o", "value", "org.axonwall:bootcount", "zroot/ROOT"); err == nil {
			val := strings.TrimSpace(string(bcOut))
			var c int
			if n, pErr := fmt.Sscanf(val, "%d", &c); pErr == nil && n == 1 {
				bootCount = c
			}
		}
		if blOut, err := we.runZfsCmd("get", "-H", "-o", "value", "org.axonwall:bootlimit", "zroot/ROOT"); err == nil {
			val := strings.TrimSpace(string(blOut))
			var l int
			if n, pErr := fmt.Sscanf(val, "%d", &l); pErr == nil && n == 1 {
				bootLimit = l
			}
		}
	} else {
		grubEnv := we.readGrubEnvInternal()
		if val, ok := grubEnv["bootcount"]; ok {
			fmt.Sscanf(val, "%d", &bootCount)
		}
		if val, ok := grubEnv["bootlimit"]; ok {
			fmt.Sscanf(val, "%d", &bootLimit)
		}
	}

	// 3. Detect Kernel and OS versions
	kernelVer := "unknown"
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err == nil {
		var buf []byte
		for _, b := range uname.Release {
			if b == 0 {
				break
			}
			buf = append(buf, byte(b))
		}
		if len(buf) > 0 {
			kernelVer = strings.TrimSpace(string(buf))
		}
	}

	appVer := we.getInstalledVersion()
	slotAVer, slotBVer := we.loadSlotVersions()

	readDisk := we.readSlotDiskVersion
	if readDisk == nil {
		readDisk = we.readSlotVersionFromDiskReal
	}

	var zbmPoolName, zbmPoolTopology, zbmPoolHealth string
	var bootEnvironments []ZfsBootEnvironment

	if installMode == "rolling" {
		slotAVer = appVer
		slotBVer = "Rolling (Single-Root)"
	} else if installMode == "zbm" {
		zbmPoolName = "zroot"
		// E2-9: topology/health deliberately stay empty when the
		// reads below fail — they are omitempty, so the UI renders
		// them unknown instead of a fabricated ONLINE/mirror.
		// (Previously they defaulted to "mirror"/"ONLINE" before
		// the reads, and the defaults survived a read failure.)

		if topOut, err := we.runZfsCmd("get", "-H", "-o", "value", "org.axonwall:topology", "zroot/ROOT"); err == nil {
			top := strings.TrimSpace(string(topOut))
			if top != "" && top != "-" {
				zbmPoolTopology = top
			}
		}
		if hlthOut, err := we.runZpoolCmd("list", "-H", "-o", "health", "zroot"); err == nil {
			hlth := strings.TrimSpace(string(hlthOut))
			if hlth != "" {
				zbmPoolHealth = hlth
			}
		}

		bootEnvironments = we.listBootEnvironmentsLocked()
		slotAVer = appVer
		slotBVer = "Standby BE"
		for _, be := range bootEnvironments {
			if be.ActiveNow {
				rootDevice = be.Dataset
				slotAVer = be.Version
			} else if slotBVer == "Standby BE" || slotBVer == "" {
				slotBVer = be.Version
			}
		}
		// E2-9: no guessed root device — when the BE list is empty
		// (zfs list failed, no cache) ActiveRootDevice stays ""
		// instead of naming a dataset that may not exist.
	} else if activeSlot == "A" {
		slotAVer = appVer
		if slotBVer == "" || slotBVer == slotAVer {
			if diskVer := readDisk("B"); diskVer != "" {
				slotBVer = diskVer
			}
		}
		if slotBVer == "" {
			slotBVer = "Standby"
		}
	} else if activeSlot == "B" {
		slotBVer = appVer
		if slotAVer == "" || slotAVer == slotBVer {
			if diskVer := readDisk("A"); diskVer != "" {
				slotAVer = diskVer
			}
		}
		if slotAVer == "" {
			slotAVer = "Standby"
		}
	}

	activeVer := slotAVer
	if activeSlot == "B" && installMode != "zbm" {
		activeVer = slotBVer
	}
	osVer := fmt.Sprintf("Axonwall OS v%s", activeVer)
	if installMode == "rolling" {
		osVer = fmt.Sprintf("Axonwall OS v%s (Rolling)", activeVer)
	} else if installMode == "zbm" {
		osVer = fmt.Sprintf("Axonwall OS v%s (Root-on-ZFS)", activeVer)
	}

	we.status = PartitionStatus{
		InstallMode:      installMode,
		ActiveSlot:       activeSlot,
		InactiveSlot:     inactiveSlot,
		ActiveRootDevice: rootDevice,
		BootCount:        bootCount,
		BootLimit:        bootLimit,
		HealthVerified:   false,
		KernelVersion:    kernelVer,
		OsVersion:        osVer,
		SlotAVersion:     slotAVer,
		SlotBVersion:     slotBVer,
		Checks:           []HealthCheckResult{},
		ZbmPoolName:      zbmPoolName,
		ZbmPoolTopology:  zbmPoolTopology,
		ZbmPoolHealth:    zbmPoolHealth,
		BootEnvironments: bootEnvironments,
	}
	we.saveSlotVersionsLocked()
}

func readInstalledVersion() string {
	appVer := "0.11.62"
	for _, vpath := range []string{"/etc/axonwall/version", "/opt/axonwall/apps/axonwall/package.json", "/opt/axonwall/package.json", "./package.json", "../package.json"} {
		if data, err := os.ReadFile(vpath); err == nil {
			trimmed := strings.TrimSpace(string(data))
			if strings.HasPrefix(trimmed, "{") {
				var pkg struct {
					Version string `json:"version"`
				}
				if err := json.Unmarshal(data, &pkg); err == nil && strings.TrimSpace(pkg.Version) != "" {
					appVer = strings.TrimSpace(pkg.Version)
					break
				}
				if idx := strings.Index(trimmed, `"version":`); idx != -1 {
					sub := trimmed[idx+10:]
					sub = strings.TrimSpace(strings.Trim(strings.Split(sub, ",")[0], ` "`+"\n\r\t}"))
					if sub != "" {
						appVer = sub
						break
					}
				}
			} else if trimmed != "" {
				lines := strings.Split(trimmed, "\n")
				if len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
					appVer = strings.TrimSpace(lines[0])
					break
				}
			}
		}
	}
	return appVer
}

// Start begins the health verification loop.
func (we *WatchdogEngine) Start() {
	log.Println("[Watchdog] Starting A/B system partition health verification...")
	go we.runVerificationSequence()
}

// RunVerification triggers the health quorum check on demand.
func (we *WatchdogEngine) RunVerification() PartitionStatus {
	we.runVerificationSequence()
	return we.GetStatus()
}

// Stop shuts down background watchdog routines.
func (we *WatchdogEngine) Stop() {
	we.mu.Lock()
	defer we.mu.Unlock()
	select {
	case <-we.stopChan:
		// Already closed
	default:
		close(we.stopChan)
	}
}

// GetStatus returns a snapshot of partition health and GRUB variables.
func (we *WatchdogEngine) GetStatus() PartitionStatus {
	we.mu.Lock()
	defer we.mu.Unlock()

	if we.status.InstallMode == "" {
		we.status.InstallMode = detectInstallMode()
	}

	slotAVer, slotBVer := we.loadSlotVersions()
	if slotAVer != "" {
		we.status.SlotAVersion = slotAVer
	}
	if slotBVer != "" {
		we.status.SlotBVersion = slotBVer
	}

	appVer := we.getInstalledVersion()
	if we.status.InstallMode == "rolling" {
		we.status.ActiveSlot = "A"
		we.status.InactiveSlot = "A"
		we.status.SlotAVersion = appVer
		we.status.SlotBVersion = "Rolling (Single-Root)"
		we.status.OsVersion = fmt.Sprintf("Axonwall OS v%s (Rolling)", appVer)
		return we.status
	} else if we.status.InstallMode == "zbm" {
		we.status.ActiveSlot = "A"
		we.status.InactiveSlot = "B"
		bes := we.listBootEnvironmentsLocked()
		if len(bes) > 0 {
			we.status.BootEnvironments = bes
			for _, be := range bes {
				if be.ActiveNow {
					we.status.ActiveRootDevice = be.Dataset
					we.status.SlotAVersion = be.Version
				} else if be.ActiveNext && be.Version != "" {
					// E2-6: the BE armed for next boot is the standby
					// slot's version. loadSlotVersions above filled
					// SlotBVersion with the running version (the
					// updater writes slotB = running), so the old
					// "Standby BE"/"" guard below never fired and both
					// slots reported the running version after arming.
					we.status.SlotBVersion = be.Version
				} else if we.status.SlotBVersion == "Standby BE" || we.status.SlotBVersion == "" {
					we.status.SlotBVersion = be.Version
				}
			}
		}
		if we.status.SlotAVersion == "" {
			we.status.SlotAVersion = appVer
		}
		if we.status.SlotBVersion == "" {
			we.status.SlotBVersion = "Standby BE"
		}
		we.status.OsVersion = fmt.Sprintf("Axonwall OS v%s (Root-on-ZFS)", we.status.SlotAVersion)
		return we.status
	}

	readDisk := we.readSlotDiskVersion
	if readDisk == nil {
		readDisk = we.readSlotVersionFromDiskReal
	}

	// E9: the running slot is derived from the kernel cmdline, not
	// from in-memory ActiveSlot (which ActivateSlot already moved to
	// the staged slot before any reboot). Using ActiveSlot here used
	// to overwrite the staged slot's version with the running version,
	// so after arming both slots reported the running version.
	runningSlot := we.status.ActiveSlot
	if slot, ok := detectRunningSlotFromCmdline(we.cmdlinePath); ok {
		runningSlot = slot
	}

	if runningSlot == "A" {
		we.status.SlotAVersion = appVer
		if we.status.SlotBVersion == "" || we.status.SlotBVersion == "Standby" || we.status.SlotBVersion == "Unknown" || we.status.SlotBVersion == we.status.SlotAVersion {
			readDisk := we.readSlotDiskVersion
			if readDisk == nil {
				readDisk = we.readSlotVersionFromDiskReal
			}
			if diskVer := readDisk("B"); diskVer != "" && diskVer != we.status.SlotBVersion {
				we.status.SlotBVersion = diskVer
				we.saveSlotVersionsLocked()
			}
		}
	} else if runningSlot == "B" {
		we.status.SlotBVersion = appVer
		if we.status.SlotAVersion == "" || we.status.SlotAVersion == "Standby" || we.status.SlotAVersion == "Unknown" || we.status.SlotAVersion == we.status.SlotBVersion {
			readDisk := we.readSlotDiskVersion
			if readDisk == nil {
				readDisk = we.readSlotVersionFromDiskReal
			}
			if diskVer := readDisk("A"); diskVer != "" && diskVer != we.status.SlotAVersion {
				we.status.SlotAVersion = diskVer
				we.saveSlotVersionsLocked()
			}
		}
	}

	activeVer := we.status.SlotAVersion
	if runningSlot == "B" {
		activeVer = we.status.SlotBVersion
	}
	if activeVer != "" {
		we.status.OsVersion = fmt.Sprintf("Axonwall OS v%s", activeVer)
	}
	return we.status
}

func (we *WatchdogEngine) listBootEnvironmentsLocked() []ZfsBootEnvironment {
	if we.runZfsCmd == nil {
		return we.status.BootEnvironments
	}

	// 1. Get next boot dataset from bootfs
	nextBootDataset := ""
	if we.runZpoolCmd != nil {
		if out, err := we.runZpoolCmd("get", "-H", "-o", "value", "bootfs", "zroot"); err == nil {
			nextBootDataset = strings.TrimSpace(string(out))
		}
	}

	// 2. Get active now dataset from /proc/mounts
	nowDataset := ""
	if mountsData, err := os.ReadFile("/proc/mounts"); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(mountsData))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 && fields[1] == "/" {
				nowDataset = fields[0]
				break
			}
		}
	}

	// 3. Query filesystems under zroot/ROOT
	out, err := we.runZfsCmd("list", "-H", "-o", "name,used,creation", "-t", "filesystem", "-r", "zroot/ROOT")
	if err != nil {
		if len(we.status.BootEnvironments) > 0 {
			return we.status.BootEnvironments
		}
		return nil
	}

	// 4. Query all snapshots under zroot/ROOT
	snapMap := make(map[string][]string)
	snapDetailMap := make(map[string][]ZfsSnapshotDetail)
	if snapOut, snapErr := we.runZfsCmd("list", "-H", "-o", "name,used,refer,creation", "-t", "snapshot", "-r", "zroot/ROOT"); snapErr == nil {
		snapScanner := bufio.NewScanner(bytes.NewReader(snapOut))
		for snapScanner.Scan() {
			snapLine := strings.TrimSpace(snapScanner.Text())
			if snapLine == "" {
				continue
			}
			fields := strings.Split(snapLine, "\t")
			fullSnap := strings.TrimSpace(fields[0])
			var usedSize, referSize, createdAt string
			if len(fields) >= 4 {
				usedSize = strings.TrimSpace(fields[1])
				referSize = strings.TrimSpace(fields[2])
				createdAt = strings.TrimSpace(strings.Join(fields[3:], " "))
			}
			parts := strings.SplitN(fullSnap, "@", 2)
			if len(parts) == 2 {
				ds := parts[0]
				sName := parts[1]
				snapMap[ds] = append(snapMap[ds], sName)
				snapDetailMap[ds] = append(snapDetailMap[ds], ZfsSnapshotDetail{
					Name:      sName,
					FullName:  fullSnap,
					Dataset:   ds,
					BeName:    strings.TrimPrefix(ds, "zroot/ROOT/"),
					UsedSize:  usedSize,
					ReferSize: referSize,
					CreatedAt: createdAt,
				})
			}
		}
	}

	var results []ZfsBootEnvironment
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			fields = strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
		}
		dsName := strings.TrimSpace(fields[0])
		if dsName == "zroot/ROOT" || !strings.HasPrefix(dsName, "zroot/ROOT/") {
			continue
		}
		beName := strings.TrimPrefix(dsName, "zroot/ROOT/")
		if strings.HasSuffix(beName, ".tmp") {
			continue
		}
		usedSize := strings.TrimSpace(fields[1])
		createdAt := strings.TrimSpace(strings.Join(fields[2:], " "))

		isActiveNow := (dsName == nowDataset)
		isActiveNext := (dsName == nextBootDataset)
		if !isActiveNow && len(results) == 0 && nowDataset == "" {
			isActiveNow = true
		}

		ver := strings.TrimPrefix(beName, "axonwall-")
		ver = strings.TrimPrefix(ver, "v")

		be := ZfsBootEnvironment{
			Name:            beName,
			Dataset:         dsName,
			ActiveNow:       isActiveNow,
			ActiveNext:      isActiveNext,
			Version:         ver,
			UsedSize:        usedSize,
			CreatedAt:       createdAt,
			Snapshots:       snapMap[dsName],
			SnapshotDetails: snapDetailMap[dsName],
		}
		results = append(results, be)
	}

	if len(results) == 0 && len(we.status.BootEnvironments) > 0 {
		return we.status.BootEnvironments
	}
	return results
}

// ListBootEnvironments returns all OpenZFS boot environments.
func (we *WatchdogEngine) ListBootEnvironments() ([]ZfsBootEnvironment, error) {
	we.mu.Lock()
	defer we.mu.Unlock()
	bes := we.listBootEnvironmentsLocked()
	we.status.BootEnvironments = bes
	return bes, nil
}

// CreateBootEnvironmentSnapshot creates a point-in-time ZFS snapshot on a Boot Environment dataset.
func (we *WatchdogEngine) CreateBootEnvironmentSnapshot(beName, label string) (string, error) {
	beName = strings.TrimSpace(beName)
	beName = strings.TrimPrefix(beName, "zroot/ROOT/")
	if beName == "" || beName == "axonwall-active" {
		// E2-7 (same staleness shape as DeleteBootEnvironment):
		// resolve the active BE from a freshly listed set, so a
		// script-side arming since the last refresh does not send
		// the snapshot to the previously-active BE.
		we.mu.Lock()
		we.status.BootEnvironments = we.listBootEnvironmentsLocked()
		for _, be := range we.status.BootEnvironments {
			if be.ActiveNow {
				beName = be.Name
				break
			}
		}
		if beName == "" && len(we.status.BootEnvironments) > 0 {
			beName = we.status.BootEnvironments[0].Name
		}
		we.mu.Unlock()
	}
	label = strings.TrimSpace(label)
	label = strings.ReplaceAll(label, " ", "-")
	if label == "" {
		label = fmt.Sprintf("manual-%s", time.Now().UTC().Format("20060102-150405"))
	}
	if !zbmIdentifierRegex.MatchString(beName) {
		return "", fmt.Errorf("invalid boot environment name: %q", beName)
	}
	if !zbmIdentifierRegex.MatchString(label) {
		return "", fmt.Errorf("invalid snapshot label: %q (use letters, numbers, hyphens, underscores, or periods)", label)
	}
	fullSnap := fmt.Sprintf("zroot/ROOT/%s@%s", beName, label)
	out, err := we.runZfsCmd("snapshot", fullSnap)
	if err != nil {
		return "", fmt.Errorf("zfs snapshot failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	log.Printf("[Watchdog/ZBM] Created Boot Environment snapshot: %s", fullSnap)

	we.mu.Lock()
	we.status.BootEnvironments = we.listBootEnvironmentsLocked()
	we.mu.Unlock()

	return fullSnap, nil
}

// zbmRequireRootSnapshot rejects a normalised snapshot reference whose
// dataset is not a Boot Environment under zroot/ROOT. E2-12: the
// snapshot argument was accepted if it merely matched
// zbmSnapshotRegex, so a data-dataset snapshot (e.g.
// zroot/tank@backup) could be cloned into a BE — or rolled back or
// destroyed — through the BE-scoped API, producing an unbootable BE
// or destroying data outside the BE tree.
func zbmRequireRootSnapshot(fullSnap string) error {
	ds, _, _ := strings.Cut(fullSnap, "@")
	if !strings.HasPrefix(ds, "zroot/ROOT/") {
		return fmt.Errorf("snapshot %q is not a Boot Environment snapshot under zroot/ROOT", fullSnap)
	}
	return nil
}

// DeleteBootEnvironmentSnapshot destroys an existing ZFS snapshot on a Boot Environment dataset.
func (we *WatchdogEngine) DeleteBootEnvironmentSnapshot(snapshot string) error {
	snapshot = strings.TrimSpace(snapshot)
	if !zbmSnapshotRegex.MatchString(snapshot) {
		return fmt.Errorf("invalid snapshot name: %q", snapshot)
	}
	fullSnap := snapshot
	if !strings.HasPrefix(fullSnap, "zroot/ROOT/") && !strings.Contains(fullSnap, "/") {
		fullSnap = "zroot/ROOT/" + fullSnap
	} else if !strings.HasPrefix(fullSnap, "zroot/") {
		fullSnap = "zroot/ROOT/" + strings.TrimPrefix(fullSnap, "/")
	}
	if !strings.Contains(fullSnap, "@") {
		return fmt.Errorf("snapshot identifier must include '@label': %q", snapshot)
	}
	if err := zbmRequireRootSnapshot(fullSnap); err != nil {
		return err
	}

	out, err := we.runZfsCmd("destroy", fullSnap)
	if err != nil {
		return fmt.Errorf("zfs destroy snapshot failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	log.Printf("[Watchdog/ZBM] Destroyed Boot Environment snapshot: %s", fullSnap)

	we.mu.Lock()
	we.status.BootEnvironments = we.listBootEnvironmentsLocked()
	we.mu.Unlock()

	return nil
}

// RollbackBootEnvironmentSnapshot rolls a Boot Environment dataset back to a point-in-time snapshot.
func (we *WatchdogEngine) RollbackBootEnvironmentSnapshot(snapshot string) error {
	snapshot = strings.TrimSpace(snapshot)
	if !zbmSnapshotRegex.MatchString(snapshot) {
		return fmt.Errorf("invalid snapshot name: %q", snapshot)
	}
	fullSnap := snapshot
	if !strings.HasPrefix(fullSnap, "zroot/ROOT/") && !strings.Contains(fullSnap, "/") {
		fullSnap = "zroot/ROOT/" + fullSnap
	} else if !strings.HasPrefix(fullSnap, "zroot/") {
		fullSnap = "zroot/ROOT/" + strings.TrimPrefix(fullSnap, "/")
	}
	if !strings.Contains(fullSnap, "@") {
		return fmt.Errorf("snapshot identifier must include '@label': %q", snapshot)
	}
	if err := zbmRequireRootSnapshot(fullSnap); err != nil {
		return err
	}

	out, err := we.runZfsCmd("rollback", "-r", fullSnap)
	if err != nil {
		return fmt.Errorf("zfs rollback failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	log.Printf("[Watchdog/ZBM] Rolled back Boot Environment to snapshot: %s", fullSnap)

	we.mu.Lock()
	we.status.BootEnvironments = we.listBootEnvironmentsLocked()
	we.mu.Unlock()

	return nil
}

// CloneSnapshotToBootEnvironment clones an existing snapshot into a new standalone Boot Environment.
func (we *WatchdogEngine) CloneSnapshotToBootEnvironment(snapshot, newBeName string) (string, error) {
	snapshot = strings.TrimSpace(snapshot)
	newBeName = strings.TrimSpace(newBeName)
	if !zbmIdentifierRegex.MatchString(newBeName) {
		return "", fmt.Errorf("invalid target boot environment name: %q", newBeName)
	}
	if !zbmSnapshotRegex.MatchString(snapshot) {
		return "", fmt.Errorf("invalid snapshot name: %q", snapshot)
	}
	fullSnap := snapshot
	if !strings.HasPrefix(fullSnap, "zroot/ROOT/") && !strings.Contains(fullSnap, "/") {
		fullSnap = "zroot/ROOT/" + fullSnap
	} else if !strings.HasPrefix(fullSnap, "zroot/") {
		fullSnap = "zroot/ROOT/" + strings.TrimPrefix(fullSnap, "/")
	}
	if !strings.Contains(fullSnap, "@") {
		return "", fmt.Errorf("snapshot identifier must include '@label': %q", snapshot)
	}
	if err := zbmRequireRootSnapshot(fullSnap); err != nil {
		return "", err
	}

	targetDataset := "zroot/ROOT/" + newBeName
	out, err := we.runZfsCmd("clone", "-o", "canmount=noauto", "-o", "mountpoint=/", fullSnap, targetDataset)
	if err != nil {
		return "", fmt.Errorf("zfs clone failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	log.Printf("[Watchdog/ZBM] Cloned snapshot %s to new Boot Environment: %s", fullSnap, targetDataset)

	we.mu.Lock()
	we.status.BootEnvironments = we.listBootEnvironmentsLocked()
	we.mu.Unlock()

	return targetDataset, nil
}

// ActivateBootEnvironment sets the targeted Boot Environment as the active bootfs for next reboot.
// E3: the watchdog property sets are part of the arming, not best-effort
// decoration. If any of them fails, the previous bootfs is restored and an
// error is returned, so activation is atomic or reported failed — never a
// success with bootfs and the watchdog's view of active/fallback disagreeing.
func (we *WatchdogEngine) ActivateBootEnvironment(beName string) error {
	beName = strings.TrimSpace(beName)
	if !zbmIdentifierRegex.MatchString(beName) {
		return fmt.Errorf("invalid boot environment name: %q", beName)
	}
	targetDataset := "zroot/ROOT/" + beName
	prevBootfs := ""
	prevBootfsRead := false
	if out, err := we.runZpoolCmd("get", "-H", "-o", "value", "bootfs", "zroot"); err == nil {
		prevBootfs = strings.TrimSpace(string(out))
		prevBootfsRead = true
	}
	prevActiveBe := ""
	if out, err := we.runZfsCmd("get", "-H", "-o", "value", "org.axonwall:active_be", "zroot/ROOT"); err == nil {
		prevActiveBe = strings.TrimSpace(string(out))
	}
	prevBootcount := ""
	if out, err := we.runZfsCmd("get", "-H", "-o", "value", "org.axonwall:bootcount", "zroot/ROOT"); err == nil {
		prevBootcount = strings.TrimSpace(string(out))
	}
	prevBootlimit := ""
	if out, err := we.runZfsCmd("get", "-H", "-o", "value", "org.axonwall:bootlimit", "zroot/ROOT"); err == nil {
		prevBootlimit = strings.TrimSpace(string(out))
	}
	// L14 (E3 residual): if the current bootfs cannot be read, the
	// rollback below cannot restore it — a later arming failure
	// would leave bootfs pointed at the new target while
	// active_be/bootcount/bootlimit roll back to their previous
	// values, and the watchdog's view of the staged BE would
	// disagree with bootfs. Refuse to arm rather than create that
	// split state. An empty value is NOT an unreadable one: it
	// means no bootfs was set (zpool reports that as "-"; the
	// batch-16 mock reports it as "") — a known state, and the
	// rollback below clears bootfs again for it.
	if !prevBootfsRead {
		return fmt.Errorf("cannot determine current bootfs; refusing to activate %q: zpool get bootfs failed", beName)
	}

	out, err := we.runZpoolCmd("set", "bootfs="+targetDataset, "zroot")
	if err != nil {
		return fmt.Errorf("zpool set bootfs failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	armErr := ""
	if out, err := we.runZfsCmd("set", "org.axonwall:active_be="+targetDataset, "zroot/ROOT"); err != nil {
		armErr = fmt.Sprintf("failed to set org.axonwall:active_be: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if armErr == "" {
		if out, err := we.runZfsCmd("set", "org.axonwall:bootcount=0", "zroot/ROOT"); err != nil {
			armErr = fmt.Sprintf("failed to reset org.axonwall:bootcount: %v (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	if armErr == "" {
		if out, err := we.runZfsCmd("set", "org.axonwall:bootlimit=3", "zroot/ROOT"); err != nil {
			armErr = fmt.Sprintf("failed to set org.axonwall:bootlimit: %v (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	if armErr != "" {
		// Roll the arming back to the previously read values so a failed
		// activation leaves bootfs and the watchdog properties consistent.
		if prevBootfs != "" && prevBootfs != "-" && prevBootfs != targetDataset {
			if _, rerr := we.runZpoolCmd("set", "bootfs="+prevBootfs, "zroot"); rerr != nil {
				log.Printf("[Watchdog/ZBM] Warning: Failed to roll back bootfs to %s after arming failure: %v", prevBootfs, rerr)
			}
		} else if prevBootfs == "-" || prevBootfs == "" {
			// L14: no bootfs was set before, so clear it again
			// instead of leaving it pointed at the failed target.
			// ("-" is zpool's report for unset; "" is the batch-16
			// mock's.)
			if _, rerr := we.runZpoolCmd("set", "bootfs=", "zroot"); rerr != nil {
				log.Printf("[Watchdog/ZBM] Warning: Failed to clear bootfs after arming failure: %v", rerr)
			}
		}
		if prevActiveBe != "" && prevActiveBe != "-" {
			if _, rerr := we.runZfsCmd("set", "org.axonwall:active_be="+prevActiveBe, "zroot/ROOT"); rerr != nil {
				log.Printf("[Watchdog/ZBM] Warning: Failed to roll back org.axonwall:active_be to %s after arming failure: %v", prevActiveBe, rerr)
			}
		} else {
			_, _ = we.runZfsCmd("inherit", "org.axonwall:active_be", "zroot/ROOT")
		}
		if prevBootcount != "" && prevBootcount != "-" {
			if _, rerr := we.runZfsCmd("set", "org.axonwall:bootcount="+prevBootcount, "zroot/ROOT"); rerr != nil {
				log.Printf("[Watchdog/ZBM] Warning: Failed to roll back org.axonwall:bootcount to %s after arming failure: %v", prevBootcount, rerr)
			}
		} else {
			_, _ = we.runZfsCmd("inherit", "org.axonwall:bootcount", "zroot/ROOT")
		}
		if prevBootlimit != "" && prevBootlimit != "-" {
			if _, rerr := we.runZfsCmd("set", "org.axonwall:bootlimit="+prevBootlimit, "zroot/ROOT"); rerr != nil {
				log.Printf("[Watchdog/ZBM] Warning: Failed to roll back org.axonwall:bootlimit to %s after arming failure: %v", prevBootlimit, rerr)
			}
		} else {
			_, _ = we.runZfsCmd("inherit", "org.axonwall:bootlimit", "zroot/ROOT")
		}
		return fmt.Errorf("boot environment arming failed (%s); arming rolled back to its previous values", armErr)
	}

	we.mu.Lock()
	we.status.BootCount = 0
	we.status.BootLimit = 3
	we.status.HealthVerified = false
	for i := range we.status.BootEnvironments {
		we.status.BootEnvironments[i].ActiveNext = (we.status.BootEnvironments[i].Dataset == targetDataset)
	}
	we.mu.Unlock()

	log.Printf("[Watchdog/ZBM] Successfully activated Boot Environment %s for next boot.", targetDataset)
	return nil
}

// DeleteBootEnvironment deletes a standby Boot Environment.
func (we *WatchdogEngine) DeleteBootEnvironment(beName string) error {
	beName = strings.TrimSpace(beName)
	if !zbmIdentifierRegex.MatchString(beName) {
		return fmt.Errorf("invalid boot environment name: %q", beName)
	}
	targetDataset := "zroot/ROOT/" + beName

	// E4: refuse to delete the fallback Boot Environment. The
	// org.axonwall:fallback_be property is the rollback pointer the
	// ZBM watchdog hook follows on a failed boot; destroying the BE
	// it names would leave it pointing at a destroyed dataset and
	// consume the one autonomous fallback. The property is read live
	// from ZFS here, not from cached status, so a fallback armed
	// since the last status refresh is still protected. An unreadable
	// property (unset, or a non-ZBM box) means "no fallback set" and
	// does not block the delete; the destroy itself still fails if
	// the dataset does not exist. This guard deliberately does not
	// depend on what ZFSBootMenu does with a missing bootfs target
	// (inferred, not observed on hardware): it only prevents the
	// pointer from being poisoned in the first place.
	if we.runZfsCmd != nil {
		if out, err := we.runZfsCmd("get", "-H", "-o", "value", "org.axonwall:fallback_be", "zroot/ROOT"); err == nil {
			fallback := strings.TrimSpace(string(out))
			if fallback != "" && fallback != "-" && (fallback == targetDataset || fallback == beName) {
				return fmt.Errorf("cannot delete Boot Environment %s: it is the fallback Boot Environment (org.axonwall:fallback_be=%s); activate another BE as fallback first", beName, fallback)
			}
		} else {
			log.Printf("[Watchdog/ZBM] Warning: could not read org.axonwall:fallback_be before deleting %s: %v", beName, err)
		}
	}

	// E2-7: the ActiveNow/ActiveNext guard must read the live BE
	// list, not the cache. Script-side arming (axonwall-update
	// --zbm) changes bootfs/active_be without telling the daemon,
	// so a BE armed since the last status refresh could otherwise
	// be deleted out from under the next boot. Same live-read
	// discipline as the E4 fallback guard above.
	we.mu.Lock()
	we.status.BootEnvironments = we.listBootEnvironmentsLocked()
	for _, be := range we.status.BootEnvironments {
		if be.Dataset == targetDataset {
			if be.ActiveNow {
				we.mu.Unlock()
				return fmt.Errorf("cannot delete currently running Boot Environment (%s)", beName)
			}
			if be.ActiveNext {
				we.mu.Unlock()
				return fmt.Errorf("cannot delete Boot Environment staged for next boot (%s); activate another BE first", beName)
			}
		}
	}
	we.mu.Unlock()

	out, err := we.runZfsCmd("destroy", "-r", targetDataset)
	if err != nil {
		return fmt.Errorf("zfs destroy failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	log.Printf("[Watchdog/ZBM] Destroyed Boot Environment: %s", targetDataset)

	we.mu.Lock()
	updated := make([]ZfsBootEnvironment, 0, len(we.status.BootEnvironments))
	for _, be := range we.status.BootEnvironments {
		if be.Dataset != targetDataset {
			updated = append(updated, be)
		}
	}
	we.status.BootEnvironments = updated
	we.mu.Unlock()

	return nil
}

// runVerificationSequence executes the three-step health quorum tests.
func (we *WatchdogEngine) runVerificationSequence() {
	time.Sleep(1 * time.Second) // Initial grace period for systemd services

	checks := make([]HealthCheckResult, 0, 3)
	allPassed := true

	// Check 1: Network interfaces initialization
	t1 := time.Now()
	ifacesCheck := we.checkInterfaces()
	ifacesCheck.DurationMs = time.Since(t1).Milliseconds()
	checks = append(checks, ifacesCheck)
	if ifacesCheck.Status == CheckStatusFail {
		allPassed = false
	}

	// Check 2: Atomic nftables kernel baseline check
	t2 := time.Now()
	nftCheck := we.checkNftables()
	nftCheck.DurationMs = time.Since(t2).Milliseconds()
	checks = append(checks, nftCheck)
	if nftCheck.Status == CheckStatusFail {
		allPassed = false
	}

	// Check 3: Control plane and management quorum
	t3 := time.Now()
	cpCheck := we.checkControlPlane()
	cpCheck.DurationMs = time.Since(t3).Milliseconds()
	checks = append(checks, cpCheck)
	if cpCheck.Status == CheckStatusFail {
		allPassed = false
	}

	we.mu.Lock()
	we.status.Checks = checks
	we.status.LastVerifiedAt = time.Now()

	if allPassed {
		// L15: the healthy state is only committed to memory after
		// the on-disk commit succeeds. The old code set
		// HealthVerified/BootCount first and only logged a commit
		// failure, so the status API reported a permanently-healthy
		// slot while the on-disk bootcount still counted up toward
		// fallback — and the next boot followed the disk, not the
		// in-memory flag.
		commitOK := false
		if we.status.InstallMode == "zbm" {
			if _, err := we.runZfsCmd("set", "org.axonwall:bootcount=0", "zroot/ROOT"); err != nil {
				log.Printf("[Watchdog] ERROR: Failed to commit bootcount=0 to zroot/ROOT: %v; slot is NOT marked healthy", err)
			} else {
				commitOK = true
				log.Printf("[Watchdog] Committed bootcount=0 to zroot/ROOT. Boot Environment is marked permanently healthy.")
			}
			activeBe := we.status.ActiveRootDevice
			if strings.HasPrefix(activeBe, "zroot/ROOT/") {
				if originOut, err := we.runZfsCmd("get", "-H", "-o", "value", "origin", activeBe); err == nil {
					origin := strings.TrimSpace(string(originOut))
					if origin != "" && origin != "-" {
						log.Printf("[Watchdog] Active Boot Environment %s is a clone of %s; promoting to independent dataset...", activeBe, origin)
						if promOut, promErr := we.runZfsCmd("promote", activeBe); promErr != nil {
							log.Printf("[Watchdog] Warning: Failed to promote %s: %v (%s)", activeBe, promErr, string(promOut))
						} else {
							log.Printf("[Watchdog] Successfully promoted %s.", activeBe)
						}
					}
				}
				_, _ = we.runZfsCmd("set", "org.axonwall:fallback_be="+activeBe, "zroot/ROOT")
				if commitOK && !we.bootSyncDone {
					_, _ = we.runZpoolCmd("set", "bootfs="+activeBe, "zroot")
					_, _ = we.runZfsCmd("set", "org.axonwall:active_be="+activeBe, "zroot/ROOT")
					we.bootSyncDone = true
				}
			}
		} else {
			// Reset bootcount in GRUB environment
			if err := we.writeGrubEnvKey("bootcount", "0"); err != nil {
				log.Printf("[Watchdog] ERROR: Failed to commit bootcount to grubenv: %v; slot is NOT marked healthy", err)
			} else {
				commitOK = true
				log.Printf("[Watchdog] Committed bootcount=0 to %s. Partition is marked permanently healthy.", we.grubenvPath)
			}
		}
		if commitOK {
			we.status.HealthVerified = true
			we.status.BootCount = 0
			log.Printf("[Watchdog] SUCCESS: All health verification checks passed for Slot %s (mode=%s).", we.status.ActiveSlot, we.status.InstallMode)
		} else {
			we.status.HealthVerified = false
			log.Printf("[Watchdog] FAILED: Health verification checks passed for Slot %s but the healthy state could not be committed to disk; bootcount is %d/%d.", we.status.ActiveSlot, we.status.BootCount, we.status.BootLimit)
		}
	} else {
		we.status.HealthVerified = false
		log.Printf("[Watchdog] FAILED: Health verification failed for Slot %s! Bootcount is %d/%d.",
			we.status.ActiveSlot, we.status.BootCount, we.status.BootLimit)
	}
	we.mu.Unlock()
}

func (we *WatchdogEngine) verifyInterfaces() HealthCheckResult {
	ifaces, err := net.Interfaces()
	if err != nil {
		return HealthCheckResult{
			Name:   "Network Interface Initialization",
			Status: CheckStatusFail,
			Detail: fmt.Sprintf("Failed to enumerate network interfaces: %v", err),
		}
	}

	hasLoopback := false
	nonLoopbackUp := 0
	for _, iface := range ifaces {
		// A-M17 (slice E note): loopback must exist AND be up; the
		// old check counted a merely-present loopback as healthy.
		if (iface.Flags&net.FlagLoopback) != 0 && (iface.Flags&net.FlagUp) != 0 {
			hasLoopback = true
		}
		// A-M20: loopback alone must not pass the check. A box with
		// every physical NIC down used to pass with N=1 (loopback
		// counted in the total) and the watchdog then committed
		// bootcount=0, disarming the A/B fallback for a network-dead
		// box.
		if (iface.Flags&net.FlagUp) != 0 && (iface.Flags&net.FlagLoopback) == 0 {
			nonLoopbackUp++
		}
	}

	if !hasLoopback {
		return HealthCheckResult{
			Name:   "Network Interface Initialization",
			Status: CheckStatusFail,
			Detail: "Loopback interface (lo) is missing or down",
		}
	}

	if nonLoopbackUp == 0 {
		return HealthCheckResult{
			Name:   "Network Interface Initialization",
			Status: CheckStatusFail,
			Detail: "No non-loopback network interface is up; loopback alone cannot carry traffic",
		}
	}

	return HealthCheckResult{
		Name:   "Network Interface Initialization",
		Status: CheckStatusPass,
		Detail: fmt.Sprintf("Detected %d operational non-loopback network interface(s) with active loopback.", nonLoopbackUp),
	}
}

func (we *WatchdogEngine) verifyNftables() HealthCheckResult {
	// 1. Verify nft binary exists and executes
	cmd := exec.Command("nft", "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// A-M17: a missing nft binary is a FAIL, not a pass. The old
		// code scored it as a simulated pass, so
		// runVerificationSequence committed bootcount=0 and marked
		// the slot permanently healthy on an image whose firewall
		// tooling was absent — disarming exactly the A/B fallback
		// that exists to catch a broken firewall image.
		return HealthCheckResult{
			Name:   "Kernel nftables Atomic Baseline",
			Status: CheckStatusFail,
			Detail: fmt.Sprintf("nft binary is missing or not executable: %v", err),
		}
	}

	// In non-root user testing environments (e.g. CI / dev build), netlink socket checks fail with EPERM.
	if os.Geteuid() != 0 {
		return HealthCheckResult{
			Name:   "Kernel nftables Atomic Baseline",
			Status: CheckStatusPass,
			Detail: fmt.Sprintf("nftables binary verified (%s). Netlink check bypassed in non-root environment.", strings.TrimSpace(string(out))),
		}
	}

	// 2. Validate standard baseline ruleset syntax when running as root.
	// nftables requires newlines or semicolons after chain blocks.
	testScript := "table inet axonwall_watchdog_test {\n\tchain test_chain {\n\t\ttype filter hook input priority 0;\n\t}\n}\ndelete table inet axonwall_watchdog_test\n"

	cCheck := exec.Command("nft", "-c", "-f", "-")
	cCheck.Stdin = strings.NewReader(testScript)
	if cOut, cErr := cCheck.CombinedOutput(); cErr != nil {
		// Fallback to temp file if stdin '-' is not supported on older nftables versions
		tmpFile, err := os.CreateTemp("", "watchdog-nft-*.nft")
		if err == nil {
			defer os.Remove(tmpFile.Name())
			tmpFile.WriteString(testScript)
			tmpFile.Close()

			fCheck := exec.Command("nft", "-c", "-f", tmpFile.Name())
			if fOut, fErr := fCheck.CombinedOutput(); fErr != nil {
				return HealthCheckResult{
					Name:   "Kernel nftables Atomic Baseline",
					Status: CheckStatusFail,
					Detail: fmt.Sprintf("nftables kernel compiler check failed: %s", string(fOut)),
				}
			}
		} else {
			return HealthCheckResult{
				Name:   "Kernel nftables Atomic Baseline",
				Status: CheckStatusFail,
				Detail: fmt.Sprintf("nftables kernel compiler check failed: %s", string(cOut)),
			}
		}
	}

	return HealthCheckResult{
		Name:   "Kernel nftables Atomic Baseline",
		Status: CheckStatusPass,
		Detail: fmt.Sprintf("Kernel nftables verified: %s", strings.TrimSpace(string(out))),
	}
}

func (we *WatchdogEngine) verifyControlPlane() HealthCheckResult {
	// A-M17: the old check only created /run/axonwall and then
	// claimed "daemon sockets responsive" without touching any
	// socket or service. Probe something real instead: a connect to
	// any of the daemon's own Unix sockets proves a listener is
	// behind it (connecting to a bound Unix listener succeeds even
	// before the server's accept loop starts, so this is safe to run
	// during early-boot verification), and a systemctl is-active
	// check covers a daemon whose sockets are not yet bound.
	// Nothing responsive means FAIL — the slot must not be marked
	// healthy on an unverified control plane.
	runDir := "/run/axonwall"
	if os.Geteuid() != 0 {
		runDir = filepath.Join(os.TempDir(), "axonwall-run")
	}
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return HealthCheckResult{
			Name:   "Control Plane Quorum",
			Status: CheckStatusFail,
			Detail: fmt.Sprintf("Cannot create runtime run directory: %v", err),
		}
	}

	for _, sockPath := range []string{
		"/run/axonwall/agent-api.sock",
		"/run/axonwall/agent.sock",
		"/run/axonwall/ha.sock",
	} {
		conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
		if err == nil {
			_ = conn.Close()
			return HealthCheckResult{
				Name:   "Control Plane Quorum",
				Status: CheckStatusPass,
				Detail: fmt.Sprintf("Control plane socket responsive: %s", sockPath),
			}
		}
	}

	if _, err := exec.LookPath("systemctl"); err == nil {
		if out, err := exec.Command("systemctl", "is-active", "axonwalld").CombinedOutput(); err == nil && strings.TrimSpace(string(out)) == "active" {
			return HealthCheckResult{
				Name:   "Control Plane Quorum",
				Status: CheckStatusPass,
				Detail: "Control plane service axonwalld is active.",
			}
		}
	}

	return HealthCheckResult{
		Name:   "Control Plane Quorum",
		Status: CheckStatusFail,
		Detail: "No control plane socket responded (agent-api.sock, agent.sock, ha.sock) and axonwalld is not active",
	}
}

// selectStandbyBE picks the Boot Environment a slot-letter or rollback
// caller should arm when no explicit BE is named. E2-10: taking the
// first non-active entry of the cached list armed the alphabetically
// first standby — usually the oldest version — once several standbys
// existed. Prefer the BE already armed for next boot, else the newest
// by creation time; fall back to the last standby in dataset-name
// order when no creation time parses. Returns nil when no standby
// exists. Callers must refresh the list first (the cache is stale
// after script-side arming).
func selectStandbyBE(bes []ZfsBootEnvironment) *ZfsBootEnvironment {
	var newest *ZfsBootEnvironment
	var newestTime time.Time
	var last *ZfsBootEnvironment
	for i := range bes {
		be := &bes[i]
		if be.ActiveNow {
			continue
		}
		if be.ActiveNext {
			return be
		}
		last = be
		if t, err := time.Parse("Mon Jan _2 15:04 2006", be.CreatedAt); err == nil {
			if newest == nil || t.After(newestTime) {
				newest, newestTime = be, t
			}
		}
	}
	if newest != nil {
		return newest
	}
	return last
}

// TriggerRollback manually switches the target boot slot to the alternate partition or fallback BE and reboots.
func (we *WatchdogEngine) TriggerRollback() error {
	we.mu.Lock()
	defer we.mu.Unlock()

	mode := we.status.InstallMode
	if mode == "" {
		mode = detectInstallModeCustom(we.cmdlinePath)
	}

	if mode == "rolling" {
		return fmt.Errorf("A/B partition rollback is not available on Rolling Single-Root installations")
	}

	if mode == "zbm" {
		fallbackOut, err := we.runZfsCmd("get", "-H", "-o", "value", "org.axonwall:fallback_be", "zroot/ROOT")
		fallbackBe := ""
		if err == nil {
			fallbackBe = strings.TrimSpace(string(fallbackOut))
		}
		if fallbackBe == "" || fallbackBe == "-" {
			// E2-10: refresh the list (script-side arming never
			// tells the daemon) and prefer the armed/newest standby
			// instead of the first non-active cached entry.
			we.status.BootEnvironments = we.listBootEnvironmentsLocked()
			if be := selectStandbyBE(we.status.BootEnvironments); be != nil {
				fallbackBe = be.Dataset
			}
		}
		if fallbackBe == "" || fallbackBe == "-" {
			return fmt.Errorf("no fallback Boot Environment available for rollback")
		}
		beName := strings.TrimPrefix(fallbackBe, "zroot/ROOT/")
		we.mu.Unlock()
		err = we.ActivateBootEnvironment(beName)
		we.mu.Lock()
		return err
	}

	targetSlot := we.status.InactiveSlot
	log.Printf("[Watchdog] Triggering safe manual rollback to Slot %s...", targetSlot)

	// A-M21: write bootcount BEFORE active_slot, so a bootcount failure
	// cannot leave the boot target already flipped with stale boot
	// accounting. The old order (active_slot first) booted the target
	// slot with the previous bootcount on the next boot.
	if err := we.writeGrubEnvKey("bootcount", "0"); err != nil {
		return fmt.Errorf("failed to reset bootcount in grubenv: %w", err)
	}
	if err := we.writeGrubEnvKey("active_slot", targetSlot); err != nil {
		return fmt.Errorf("failed to set active_slot in grubenv: %w", err)
	}

	oldActive := we.status.ActiveSlot
	we.status.ActiveSlot = targetSlot
	we.status.InactiveSlot = oldActive
	we.status.HealthVerified = false

	return nil
}

// ActivateSlot sets a specific slot or Boot Environment for the next boot.
func (we *WatchdogEngine) ActivateSlot(targetSlot string) error {
	we.mu.Lock()
	defer we.mu.Unlock()

	mode := we.status.InstallMode
	if mode == "" {
		mode = detectInstallModeCustom(we.cmdlinePath)
	}

	if mode == "rolling" {
		return fmt.Errorf("A/B partition slot switching is not available on Rolling Single-Root installations")
	}

	if mode == "zbm" {
		targetBE := strings.TrimSpace(targetSlot)
		if strings.EqualFold(targetBE, "A") {
			for _, be := range we.status.BootEnvironments {
				if be.ActiveNow {
					targetBE = be.Name
					break
				}
			}
		} else if strings.EqualFold(targetBE, "B") {
			// E2-10: refresh the list (script-side arming never
			// tells the daemon) and prefer the armed/newest standby
			// instead of the first non-active cached entry.
			we.status.BootEnvironments = we.listBootEnvironmentsLocked()
			if be := selectStandbyBE(we.status.BootEnvironments); be != nil {
				targetBE = be.Name
			} else {
				return fmt.Errorf("no standby Boot Environment available for slot B")
			}
		}
		we.mu.Unlock()
		err := we.ActivateBootEnvironment(targetBE)
		we.mu.Lock()
		return err
	}

	targetSlot = strings.ToUpper(strings.TrimSpace(targetSlot))
	if targetSlot != "A" && targetSlot != "B" {
		return fmt.Errorf("invalid partition slot: %s (must be A or B)", targetSlot)
	}

	// A-M21: write bootcount BEFORE active_slot (see TriggerRollback):
	// a bootcount failure must not leave the boot target flipped.
	if err := we.writeGrubEnvKey("bootcount", "0"); err != nil {
		return fmt.Errorf("failed to reset bootcount: %w", err)
	}
	if err := we.writeGrubEnvKey("active_slot", targetSlot); err != nil {
		return fmt.Errorf("failed to set active_slot: %w", err)
	}

	inactiveSlot := "B"
	if targetSlot == "B" {
		inactiveSlot = "A"
	}
	we.status.ActiveSlot = targetSlot
	we.status.InactiveSlot = inactiveSlot
	we.status.BootCount = 0
	we.status.HealthVerified = false

	return nil
}

// ApplyFirmwareUpdate executes the privileged firmware updater for a target slot and version,
// updates bootloader variables, and records the new version on the target slot or Boot Environment.
func (we *WatchdogEngine) ApplyFirmwareUpdate(targetSlot, targetVersion string) (string, error) {
	we.mu.RLock()
	currMode := we.status.InstallMode
	we.mu.RUnlock()
	isZbm := currMode == "zbm" || detectInstallModeCustom(we.cmdlinePath) == "zbm"
	isRolling := currMode == "rolling" || detectInstallModeCustom(we.cmdlinePath) == "rolling"
	targetSlot = strings.ToUpper(strings.TrimSpace(targetSlot))
	if isRolling {
		targetSlot = "A"
	} else if isZbm {
		targetSlot = "B"
	} else if targetSlot != "A" && targetSlot != "B" {
		targetSlot = "B"
	}
	targetVersion = strings.TrimSpace(strings.TrimPrefix(targetVersion, "v"))
	if targetVersion == "" {
		targetVersion = we.getInstalledVersion()
	}
	// Sanitize version string to prevent any shell/argument injection
	for _, r := range targetVersion {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '.' || r == '-' || r == '_') {
			return "", fmt.Errorf("invalid target version format")
		}
	}

	updaterFound := false
	for _, up := range we.updaterPaths {
		if _, err := os.Stat(up); err != nil {
			continue
		}
		updaterFound = true
		var cmd *exec.Cmd
		if isZbm {
			cmd = exec.Command(up, "--zbm", "--version", targetVersion)
		} else if isRolling {
			cmd = exec.Command(up, "--rolling", "--version", targetVersion)
		} else {
			cmd = exec.Command(up, "--slot", targetSlot, "--version", targetVersion)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("axonwall-update failed for slot %s (v%s): %v: %s", targetSlot, targetVersion, err, strings.TrimSpace(string(out)))
		}
		log.Printf("[Watchdog] axonwall-update completed for Slot %s (v%s, rolling=%v, zbm=%v)", targetSlot, targetVersion, isRolling, isZbm)
		break
	}
	if !updaterFound {
		return "", fmt.Errorf("axonwall-update binary not found (looked in %s); slot %s was NOT flashed", strings.Join(we.updaterPaths, ", "), targetSlot)
	}

	we.mu.Lock()
	defer we.mu.Unlock()

	if isRolling {
		we.status.InstallMode = "rolling"
		we.status.SlotAVersion = targetVersion
		we.status.SlotBVersion = "Rolling (Single-Root)"
		we.saveSlotVersionsLocked()
		if err := os.MkdirAll("/etc/axonwall", 0770); err == nil {
			_ = os.WriteFile("/etc/axonwall/version", []byte(targetVersion+"\n"), 0644)
		}
		we.status.OsVersion = fmt.Sprintf("Axonwall OS v%s (Rolling)", targetVersion)
		return fmt.Sprintf("Axonwall v%s successfully updated in-place on Rolling Root (/). Services are reloading.", targetVersion), nil
	}

	if isZbm {
		we.status.InstallMode = "zbm"
		we.status.SlotBVersion = targetVersion
		we.status.BootCount = 0
		we.status.BootLimit = 3
		we.status.BootEnvironments = we.listBootEnvironmentsLocked()
		we.saveSlotVersionsLocked()
		return fmt.Sprintf("Firmware v%s successfully staged to new ZFS Boot Environment (axonwall-%s)! Watchdog bootcount armed (bootlimit=3). Reboot when ready.", targetVersion, targetVersion), nil
	}

	// A-M21: write bootcount/bootlimit BEFORE active_slot (see
	// TriggerRollback): a later write failure must not leave the boot
	// target flipped with stale boot accounting.
	if err := we.writeGrubEnvKey("bootcount", "0"); err != nil {
		return "", fmt.Errorf("failed to reset bootcount in grubenv: %w", err)
	}
	if err := we.writeGrubEnvKey("bootlimit", "3"); err != nil {
		return "", fmt.Errorf("failed to set bootlimit in grubenv: %w", err)
	}
	if err := we.writeGrubEnvKey("active_slot", targetSlot); err != nil {
		return "", fmt.Errorf("failed to set active_slot in grubenv: %w", err)
	}

	currentRunningVer := readInstalledVersion()
	if targetSlot == "A" {
		we.status.SlotAVersion = targetVersion
		if we.status.ActiveSlot == "B" {
			we.status.SlotBVersion = currentRunningVer
		}
	} else {
		we.status.SlotBVersion = targetVersion
		if we.status.ActiveSlot == "A" {
			we.status.SlotAVersion = currentRunningVer
		}
	}

	we.saveSlotVersionsLocked()

	// If updating the active slot directly, update /etc/axonwall/version immediately
	if targetSlot == we.status.ActiveSlot {
		if err := os.MkdirAll("/etc/axonwall", 0770); err == nil {
			_ = os.WriteFile("/etc/axonwall/version", []byte(targetVersion+"\n"), 0644)
		}
		we.status.OsVersion = fmt.Sprintf("Axonwall OS v%s", targetVersion)
	}
	we.status.BootCount = 0
	we.status.BootLimit = 3

	return fmt.Sprintf("Firmware v%s successfully prepared and flashed to Slot %s! Watchdog bootcount armed (bootlimit=3). Reboot when ready.", targetVersion, targetSlot), nil
}

// readGrubEnvInternal parses GRUB key=value pairs from the environment block.
func (we *WatchdogEngine) readGrubEnvInternal() map[string]string {
	return readGrubEnvAtPath(we.grubenvPath)
}

// readGrubEnvAtPath parses GRUB key=value pairs from the environment
// block at envPath.
func readGrubEnvAtPath(envPath string) map[string]string {
	res := make(map[string]string)
	data, err := os.ReadFile(envPath)
	if err != nil {
		return res
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			res[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return res
}

// writeGrubEnvKey updates or appends a key in the grubenv file.
func (we *WatchdogEngine) writeGrubEnvKey(key, value string) error {
	err := writeGrubEnvKeyAtPath(we.grubenvPath, we.readGrubEnvInternal(), key, value)
	if err != nil {
		return err
	}

	// When booted into Slot B on a dual-root disk where GRUB's $prefix lives on Slot A (axon_root_a),
	// mirror grubenv updates to axon_root_a's /boot/grub/grubenv as well.
	// E2-4: on B the mirror IS the arming — GRUB never reads B's
	// grubenv — so a mirror failure is a write failure, not a
	// best-effort side effect. Return it like the primary error so
	// ActivateSlot/TriggerRollback report "not armed" instead of
	// claiming a slot switch the next boot will ignore. The mirror
	// only applies to the real grubenv path; tests and non-A/B
	// layouts keep the old return-early behaviour.
	if we.grubenvPath != "/boot/grub/grubenv" {
		return nil
	}
	cmdlineBytes, cErr := os.ReadFile(we.cmdlinePath)
	if cErr != nil || !strings.Contains(string(cmdlineBytes), "axon_root_b") {
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("cannot mirror grubenv to Slot A: daemon is not running as root (euid %d), so the GRUB-visible grubenv was not updated", os.Geteuid())
	}
	slotADev := resolveLabelDevice("axon_root_a")
	info, statErr := os.Stat(slotADev)
	if statErr != nil || (info.Mode()&os.ModeDevice) == 0 {
		return fmt.Errorf("cannot mirror grubenv to Slot A: device %s is not a block device: %v", slotADev, statErr)
	}
	mntDir := "/run/axonwall/grubsync-a"
	if mErr := os.MkdirAll(mntDir, 0700); mErr != nil {
		return fmt.Errorf("cannot mirror grubenv to Slot A: cannot create mount point %s: %w", mntDir, mErr)
	}
	if mErr := exec.Command("mount", slotADev, mntDir).Run(); mErr != nil {
		_ = os.Remove(mntDir)
		return fmt.Errorf("cannot mirror grubenv to Slot A: mount %s failed: %w", slotADev, mErr)
	}
	targetEnv := filepath.Join(mntDir, "boot", "grub", "grubenv")
	// D2-L1: base the mirror write on the TARGET file's own env, not
	// the booted slot's — the direct-write fallback serialises the
	// whole base map, and the booted slot's map still carries
	// clone-time values (e.g. active_slot=A) that would flip the next
	// boot back to A.
	mirrorErr := writeGrubEnvKeyAtPath(targetEnv, readGrubEnvAtPath(targetEnv), key, value)
	if uErr := exec.Command("umount", mntDir).Run(); uErr != nil {
		// The mirror write already landed; a stuck mount is loud
		// but does not change what GRUB will boot.
		log.Printf("[Watchdog] Warning: failed to unmount Slot A grubenv mirror %s: %v", mntDir, uErr)
	}
	_ = os.Remove(mntDir)
	if mirrorErr != nil {
		return fmt.Errorf("cannot mirror grubenv to Slot A: %w", mirrorErr)
	}
	return nil
}

func writeGrubEnvKeyAtPath(envPath string, currentEnv map[string]string, key, value string) error {
	// 1. If grub-editenv is installed on system, use it for standard atomic editing
	if _, err := exec.LookPath("grub-editenv"); err == nil {
		_ = os.MkdirAll(filepath.Dir(envPath), 0755)
		if _, sErr := os.Stat(envPath); os.IsNotExist(sErr) {
			_ = exec.Command("grub-editenv", envPath, "create").Run()
		}
		cmd := exec.Command("grub-editenv", envPath, "set", fmt.Sprintf("%s=%s", key, value))
		if out, err := cmd.CombinedOutput(); err == nil {
			return nil
		} else {
			log.Printf("[Watchdog] grub-editenv failed (%v: %s), falling back to direct write", err, string(out))
		}
	}

	// 2. Direct format writing: Standard 1024-byte GRUB environment block
	env := make(map[string]string, len(currentEnv)+1)
	for k, v := range currentEnv {
		env[k] = v
	}
	env[key] = value

	// A-L4: the block is fixed at 1024 bytes, and the old code sliced
	// the serialised content to 1024, silently dropping keys in Go
	// map iteration order — the just-set key itself could be the one
	// truncated, while the caller was told the write succeeded.
	// Serialise in sorted key order (deterministic) and fail closed
	// instead of persisting a partial block: a caller that cannot set
	// active_slot/bootcount must report failure, not boot with a
	// grubenv that silently lost the key it just set.
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteString("# GRUB Environment Block\n")
	for _, k := range keys {
		buf.WriteString(fmt.Sprintf("%s=%s\n", k, env[k]))
	}

	if buf.Len() > 1024 {
		return fmt.Errorf("grubenv content (%d bytes) exceeds the 1024-byte GRUB environment block; refusing to truncate keys (set %q, %d keys total)", buf.Len(), key, len(keys))
	}

	// Pad with '#' up to 1024 bytes
	for buf.Len() < 1024 {
		buf.WriteByte('#')
	}

	// Ensure parent dir exists
	_ = os.MkdirAll(filepath.Dir(envPath), 0755)
	return os.WriteFile(envPath, buf.Bytes(), 0644)
}
