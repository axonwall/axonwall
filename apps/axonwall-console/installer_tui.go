package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Additional ANSI styling constants for the Next-Gen TUI Installer
const (
	colorEmerald   = "\033[38;5;48m"
	colorBrightCya = "\033[38;5;51m"
	colorMagenta   = "\033[35m"
	colorBgEmerald = "\033[48;5;23m"
	colorBgDark    = "\033[48;5;235m"
)

// DiskDevice represents a candidate block storage device discovered on the host.
type DiskDevice struct {
	Name       string // e.g. "nvme0n1", "vda", "sda"
	Path       string // e.g. "/dev/nvme0n1"
	Model      string
	Transport  string // "NVMe", "VirtIO", "SATA/SAS"
	SizeBytes  uint64
	SizeMB     int
	SizeGB     float64
	Removable  bool
	Mounted    bool
	Role       string // "system", "zfs-data", "zfs-slog", "zfs-l2arc", "zfs-spare", "none"
	SystemDisk bool
	ZfsExtra   bool
}

// InstallerConfig holds all user choices for the Next-Gen Appliance Installer.
type InstallerConfig struct {
	Edition        string   // "axonwall", "vault", or "k3s-storage"
	OSFamily       string   // "debian" or "alpine"
	InstallMode    string   // "ab", "zbm", "rolling"
	SlotMB         int      // 2048, 4096, 8192, 16384
	RootFSType     string   // "ext4" or "xfs"
	DataFSType     string   // "ext4" or "xfs"
	SystemDisks    []string // e.g. ["/dev/nvme0n1", "/dev/nvme1n1"]
	ZfsAllocMode   string   // "remainder", "split", "custom", "none"
	CustomZfsGB    int      // custom GB when ZfsAllocMode == "custom"
	ZfsExtraDisks  []string // dedicated whole disks for ZFS Data VDEVs
	ZfsSlogDisks   []string // dedicated whole disks for ZFS Separate Intent Log (ZIL / SLOG)
	ZfsL2arcDisks  []string // dedicated whole disks for ZFS Level 2 ARC (L2ARC read cache)
	ZfsSpareDisks  []string // dedicated whole disks for ZFS Hot Spares
	ZfsTopology    string   // "auto", "stripe", "mirror", "raidz1", "raidz2", "raidz3"
	LogsEnabled    bool     // dedicated /var/log partition (axon_logs)
	LogsGB         int      // size of /var/log in GB (default 8)
	LogsFSType     string   // "xfs" or "ext4"
	LuksEnabled    bool     // LUKS2 AES-XTS-512 encryption on /var/lib/axonwall
	LuksTPM2       bool     // hardware TPM 2.0 PCR 0+2+7 auto-unlock
	LuksPassphrase string   // passphrase for LUKS2 volume
	Hostname       string   // appliance hostname
	AdminUser      string   // default "admin"
	AdminPassword  string   // plaintext or scrypt hash for installed appliance
	KeepPartitions bool     // preserve pre-partitioned disk layout created in root shell
	K3sRole        string   // "server" (default) or "agent"
	K3sServerURL   string   // control plane URL (e.g. https://10.0.0.1:6443) when K3sRole == "agent" or HA join
	K3sJoinToken   string   // cluster join token
	ZfsArcMaxMB    int      // 0 = auto-tuned from host RAM
}

// ComputeDefaultZfsArcMaxMB returns the recommended OpenZFS ARC memory cap in MiB for the given total host RAM.
func ComputeDefaultZfsArcMaxMB(ramMB int) int {
	switch {
	case ramMB <= 2048:
		return 384
	case ramMB <= 4096:
		return 512
	case ramMB <= 8192:
		return 1024
	default:
		return ramMB / 4
	}
}

// PartitionLayout represents the computed MiB sizes for visual preview and execution.
type PartitionLayout struct {
	TotalMB int
	EfiMB   int
	SlotAMB int
	SlotBMB int
	LogsMB  int
	DataMB  int
	ZfsMB   int
}

// DefaultInstallerConfig returns the recommended factory defaults for the current runtime.
func DefaultInstallerConfig() InstallerConfig {
	edition := "axonwall"
	hostname := "axonwall"
	k3sRole := "server"
	if _, err := os.Stat("/etc/axonwall/.k3s-edition"); err == nil {
		edition = "k3s-storage"
		hostname = "axonwall-storage"
	} else if _, err := os.Stat("/etc/axonwall/.vault-edition"); err == nil {
		edition = "vault"
		hostname = "axonwall-vault"
	}
	if data, err := os.ReadFile("/proc/cmdline"); err == nil {
		cmd := string(data)
		if edition == "axonwall" {
			if strings.Contains(cmd, "axonwall_edition=k3s-storage") || strings.Contains(cmd, "axonwall.edition=k3s-storage") {
				edition = "k3s-storage"
				hostname = "axonwall-storage"
			} else if strings.Contains(cmd, "axonwall_edition=vault") || strings.Contains(cmd, "axonwall.edition=vault") {
				edition = "vault"
				hostname = "axonwall-vault"
			}
		}
		if strings.Contains(cmd, "axonwall.k3s_role=agent") || strings.Contains(cmd, "axonwall_k3s_role=agent") {
			k3sRole = "agent"
		}
	}
	osFamily := "debian"
	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		osFamily = "alpine"
	}
	tpmPresent := hasTPM2Device()
	adminPass := ""
	if _, err := os.Stat("/etc/axonwall/.password_changed"); err == nil {
		if u, p := getAdminCredentials(); strings.HasPrefix(p, "scrypt$") {
			_ = u
			adminPass = p
		}
	}
	return InstallerConfig{
		Edition:       edition,
		OSFamily:      osFamily,
		InstallMode:   "ab",
		SlotMB:        4096,
		RootFSType:    "ext4",
		DataFSType:    "ext4",
		ZfsAllocMode:  "remainder",
		CustomZfsGB:   16,
		ZfsTopology:   "auto",
		LogsEnabled:   false,
		LogsGB:        8,
		LogsFSType:    "xfs",
		LuksEnabled:   false,
		LuksTPM2:      tpmPresent,
		Hostname:      hostname,
		AdminUser:     "admin",
		AdminPassword: adminPass,
		K3sRole:       k3sRole,
		ZfsArcMaxMB:   0,
	}
}

// cycleEdition cycles cfg.Edition through "axonwall" -> "vault" -> "k3s-storage" -> "axonwall",
// updating cfg.Hostname when empty or matching one of the factory default hostnames.
func cycleEdition(cfg *InstallerConfig) {
	if cfg == nil {
		return
	}
	isDefaultHostname := cfg.Hostname == "" ||
		cfg.Hostname == "axonwall" ||
		cfg.Hostname == "axonwall-vault" ||
		cfg.Hostname == "axonwall-storage"
	switch cfg.Edition {
	case "vault":
		cfg.Edition = "k3s-storage"
		if isDefaultHostname {
			cfg.Hostname = "axonwall-storage"
		}
		if cfg.K3sRole == "" {
			cfg.K3sRole = "server"
		}
	case "k3s-storage":
		cfg.Edition = "axonwall"
		if isDefaultHostname {
			cfg.Hostname = "axonwall"
		}
	default:
		cfg.Edition = "vault"
		if isDefaultHostname {
			cfg.Hostname = "axonwall-vault"
		}
	}
}

func isPartitionOfDisk(partPath, diskPath string) bool {
	if diskPath == "" || !strings.HasPrefix(partPath, diskPath) {
		return false
	}
	rem := partPath[len(diskPath):]
	if rem == "" {
		return false
	}
	lastChar := diskPath[len(diskPath)-1]
	if lastChar >= '0' && lastChar <= '9' {
		if rem[0] != 'p' || len(rem) < 2 {
			return false
		}
		rem = rem[1:]
	}
	for i := 0; i < len(rem); i++ {
		if rem[i] < '0' || rem[i] > '9' {
			return false
		}
	}
	return true
}

func diskHasPrecreatedAxonwallPartitions(diskPath string) bool {
	if diskPath == "" {
		return false
	}
	for _, dir := range []string{"/dev/disk/by-label", "/dev/disk/by-partlabel"} {
		for _, lbl := range []string{"axon_root_a", "axon_root", "AXON_EFI", "axon_data", "axon_zfs_1", "axon_zfs"} {
			if target, err := filepath.EvalSymlinks(filepath.Join(dir, lbl)); err == nil {
				if target == diskPath || isPartitionOfDisk(target, diskPath) {
					return true
				}
			}
		}
	}
	return false
}

func isNetworkExplicitlyConfigured() bool {
	if _, err := os.Stat("/etc/axonwall/.interfaces_configured"); err == nil {
		return true
	}
	if _, err := os.Stat("/var/lib/axonwall/etc-axonwall/.interfaces_configured"); err == nil {
		return true
	}
	return false
}

func formatPreInstallNetworkSummary() string {
	if !isNetworkExplicitlyConfigured() {
		return "Auto-Detect on Firstboot (Use CLI [2]/[3] to customize)"
	}
	cfg := readCurrentNetworkConfig()
	var parts []string
	if cfg.WanDevice != "" {
		wanDesc := cfg.WanMode
		if cfg.WanMode == "static" && cfg.WanIP != "" {
			wanDesc = cfg.WanIP
		}
		parts = append(parts, fmt.Sprintf("WAN=%s (%s)", cfg.WanDevice, wanDesc))
	}
	if cfg.LanDevice != "" {
		lanDesc := cfg.LanMode
		if cfg.LanMode == "static" && cfg.LanIP != "" {
			lanDesc = cfg.LanIP
		}
		parts = append(parts, fmt.Sprintf("LAN=%s (%s)", cfg.LanDevice, lanDesc))
	}
	if cfg.Opt1Device != "" {
		opt1Desc := cfg.Opt1Mode
		if cfg.Opt1Mode == "static" && cfg.Opt1IP != "" {
			opt1Desc = cfg.Opt1IP
		}
		parts = append(parts, fmt.Sprintf("OPT1=%s (%s)", cfg.Opt1Device, opt1Desc))
	}
	if cfg.Opt2Device != "" {
		opt2Desc := cfg.Opt2Mode
		if cfg.Opt2Mode == "static" && cfg.Opt2IP != "" {
			opt2Desc = cfg.Opt2IP
		}
		parts = append(parts, fmt.Sprintf("OPT2=%s (%s)", cfg.Opt2Device, opt2Desc))
	}
	if len(parts) == 0 {
		return "Auto-Detect on Firstboot (Use CLI [2]/[3] to customize)"
	}
	return strings.Join(parts, ", ")
}

func hasTPM2Device() bool {
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		return true
	}
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		return true
	}
	return false
}

func hasUEFIFirmware() bool {
	_, err := os.Stat("/sys/firmware/efi")
	return err == nil
}

func detectCloudInitSeed() string {
	candidates := []string{
		"/var/lib/partman/cloud-config.yaml",
		"/var/lib/cloud/seed/nocloud-net/user-data",
		"/etc/axonwall/cloud-config.yaml",
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.Size() > 0 {
			return c
		}
	}
	return ""
}

// DiscoverDisks scans /sys/block and returns candidate block storage devices.
func DiscoverDisks() []DiskDevice {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil
	}
	mountsBytes, _ := os.ReadFile("/proc/mounts")
	mountsStr := string(mountsBytes)

	var raw []DiskDevice
	for _, entry := range entries {
		name := entry.Name()
		devPath := "/dev/" + name
		sysPath := filepath.Join("/sys/block", name)

		sizeStr, err := os.ReadFile(filepath.Join(sysPath, "size"))
		if err != nil {
			continue
		}
		sectors, err := strconv.ParseUint(strings.TrimSpace(string(sizeStr)), 10, 64)
		if err != nil {
			continue
		}
		sizeBytes := sectors * 512
		sizeMB := int(sizeBytes / (1024 * 1024))
		sizeGB := float64(sizeBytes) / (1024.0 * 1024.0 * 1024.0)

		remStr, _ := os.ReadFile(filepath.Join(sysPath, "removable"))
		removable := strings.TrimSpace(string(remStr)) == "1"

		modelBytes, _ := os.ReadFile(filepath.Join(sysPath, "device/model"))
		model := strings.TrimSpace(string(modelBytes))
		if model == "" {
			if strings.HasPrefix(name, "vd") {
				model = "VirtIO Block Disk"
			} else if strings.HasPrefix(name, "nvme") {
				model = "NVMe Solid State Drive"
			} else {
				model = "Block Storage Device"
			}
		}

		transport := "SATA/SAS"
		if strings.HasPrefix(name, "nvme") {
			transport = "NVMe"
		} else if strings.HasPrefix(name, "vd") {
			transport = "VirtIO"
		} else if strings.HasPrefix(name, "mmcblk") {
			transport = "eMMC"
		}

		mounted := false
		for _, line := range strings.Split(mountsStr, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				mDev := fields[0]
				if mDev == devPath || isPartitionOfDisk(mDev, devPath) {
					mounted = true
					break
				}
			}
		}

		raw = append(raw, DiskDevice{
			Name:      name,
			Path:      devPath,
			Model:     model,
			Transport: transport,
			SizeBytes: sizeBytes,
			SizeMB:    sizeMB,
			SizeGB:    sizeGB,
			Removable: removable,
			Mounted:   mounted,
		})
	}

	return FilterCandidateDisks(raw)
}

// FilterCandidateDisks filters out pseudo-devices, optical drives, tiny disks (<2 GiB), and mounted live media.
func FilterCandidateDisks(devices []DiskDevice) []DiskDevice {
	var filtered []DiskDevice
	for _, d := range devices {
		if strings.HasPrefix(d.Name, "loop") ||
			strings.HasPrefix(d.Name, "ram") ||
			strings.HasPrefix(d.Name, "sr") ||
			strings.HasPrefix(d.Name, "fd") ||
			strings.HasPrefix(d.Name, "dm-") ||
			strings.HasPrefix(d.Name, "md") ||
			strings.HasPrefix(d.Name, "zd") ||
			strings.HasPrefix(d.Name, "zram") {
			continue
		}
		if d.SizeMB < 2048 {
			continue
		}
		if d.Mounted {
			continue
		}
		if d.Role == "" {
			if d.SystemDisk {
				d.Role = "system"
			} else if d.ZfsExtra {
				d.Role = "zfs-data"
			} else {
				d.Role = "none"
			}
		}
		filtered = append(filtered, d)
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Path < filtered[j].Path
	})
	return filtered
}

// setDiskRole sets a DiskDevice's Role and keeps legacy boolean flags in sync.
func setDiskRole(d *DiskDevice, role string) {
	switch role {
	case "system", "zfs-data", "zfs-slog", "zfs-l2arc", "zfs-spare", "none":
		d.Role = role
	default:
		d.Role = "none"
	}
	d.SystemDisk = d.Role == "system"
	d.ZfsExtra = d.Role == "zfs-data"
}

// cycleDiskRole cycles a disk through all supported appliance storage roles.
func cycleDiskRole(d *DiskDevice) {
	order := []string{"system", "zfs-data", "zfs-slog", "zfs-l2arc", "zfs-spare", "none"}
	cur := d.Role
	if cur == "" {
		if d.SystemDisk {
			cur = "system"
		} else if d.ZfsExtra {
			cur = "zfs-data"
		} else {
			cur = "none"
		}
	}
	for i, r := range order {
		if r == cur {
			setDiskRole(d, order[(i+1)%len(order)])
			return
		}
	}
	setDiskRole(d, "system")
}

// formatDiskRoleBadge returns an ANSI-colored fixed-width badge for a disk's assigned role.
func formatDiskRoleBadge(d DiskDevice) string {
	role := d.Role
	if role == "" {
		if d.SystemDisk {
			role = "system"
		} else if d.ZfsExtra {
			role = "zfs-data"
		} else {
			role = "none"
		}
	}
	switch role {
	case "system":
		return colorEmerald + colorBold + "[OS SYSTEM]" + colorReset
	case "zfs-data":
		return colorGreen + colorBold + "[ZFS DATA ]" + colorReset
	case "zfs-slog":
		return colorYellow + colorBold + "[ZFS SLOG ]" + colorReset
	case "zfs-l2arc":
		return colorBrightCya + colorBold + "[ZFS L2ARC]" + colorReset
	case "zfs-spare":
		return colorMagenta + colorBold + "[ZFS SPARE]" + colorReset
	default:
		return colorDim + "[ UNUSED  ]" + colorReset
	}
}

// HardwareEvaluation encapsulates the self-evaluated hardware profile and recommended storage/boot decisions.
type HardwareEvaluation struct {
	TotalRAMMB        int
	FirmwareMode      string
	HasTPM2           bool
	DiskCount         int
	SystemDiskSummary string
	ZfsPoolSummary    string
	SlotSizingNote    string
	EvaluationNotes   []string
}

func detectTotalRAMMB() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 4096
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.Atoi(fields[1]); err == nil && kb > 0 {
					return kb / 1024
				}
			}
		}
	}
	return 4096
}

// AutoAssignDiskRoles automatically assigns roles based on disk capacity tiers.
// For heterogeneous servers (e.g. 2x 32 GB boot disks + 2x 1 TB data disks), the smallest
// tier (1-2 disks) is assigned as "system" (OS RAID-1 Mirror) and the larger capacity tier
// is assigned as "zfs-data" (Dedicated OpenZFS storage pool).
// For homogeneous 2-disk systems, both disks are mirrored as "system".
// For homogeneous 3+ disk systems, the first 2 disks are mirrored as "system" and remaining disks become "zfs-data".
func AutoAssignDiskRoles(disks []DiskDevice) []DiskDevice {
	if len(disks) == 0 {
		return disks
	}
	out := make([]DiskDevice, len(disks))
	copy(out, disks)
	for i := range out {
		setDiskRole(&out[i], "none")
	}

	minMB := out[0].SizeMB
	for _, d := range out {
		if d.SizeMB > 0 && d.SizeMB < minMB {
			minMB = d.SizeMB
		}
	}
	if minMB <= 0 {
		setDiskRole(&out[0], "system")
		return out
	}

	var smallIdxs []int
	var largeIdxs []int
	for i, d := range out {
		if d.SizeMB <= (minMB*125)/100 {
			smallIdxs = append(smallIdxs, i)
		} else if d.SizeMB >= (minMB*150)/100 {
			largeIdxs = append(largeIdxs, i)
		}
	}

	// Heterogeneous storage layout (e.g. 2x 32GB OS + 2x 1TB Data)
	if len(smallIdxs) >= 1 && len(smallIdxs) <= 2 && len(largeIdxs) >= 1 {
		for _, idx := range smallIdxs {
			setDiskRole(&out[idx], "system")
		}
		// Find largest capacity tier among largeIdxs for primary ZFS Data pool
		maxMB := 0
		for _, idx := range largeIdxs {
			if out[idx].SizeMB > maxMB {
				maxMB = out[idx].SizeMB
			}
		}
		for _, idx := range largeIdxs {
			if out[idx].SizeMB >= (maxMB*80)/100 {
				setDiskRole(&out[idx], "zfs-data")
			}
		}
		return out
	}

	// Homogeneous disks: evaluate optimal redundancy automatically
	if len(out) == 1 {
		setDiskRole(&out[0], "system")
	} else if len(out) == 2 && len(smallIdxs) == 2 {
		// 2 identical disks -> automatic RAID-1 system mirror
		setDiskRole(&out[0], "system")
		setDiskRole(&out[1], "system")
	} else if len(out) >= 3 && len(smallIdxs) >= 3 {
		// 3+ identical disks -> mirror first 2 for OS, assign remaining to ZFS Data pool
		setDiskRole(&out[0], "system")
		setDiskRole(&out[1], "system")
		for i := 2; i < len(out); i++ {
			setDiskRole(&out[i], "zfs-data")
		}
	} else {
		setDiskRole(&out[0], "system")
	}
	return out
}

type HardwareEvalResult = HardwareEvaluation

func recommendedSlotGBForDiskMB(primaryMB int) int {
	switch {
	case primaryMB < 24576: // < 24 GB
		return 2
	case primaryMB < 65536: // 24 - 64 GB
		return 4
	case primaryMB < 204800: // 64 - 200 GB
		return 8
	default: // >= 200 GB
		return 16
	}
}

func normalizeSlotMBForMode(cfg *InstallerConfig, recommendedSlotGB int, primaryMB ...int) {
	if cfg == nil {
		return
	}
	diskMB := 65536
	if len(primaryMB) > 0 && primaryMB[0] > 0 {
		diskMB = primaryMB[0]
	}
	switch cfg.InstallMode {
	case "zbm":
		cfg.SlotMB = 0
	case "rolling":
		minRollingMB := 8192
		if cfg.Edition == "k3s-storage" && diskMB < 32768 {
			minRollingMB = 4096
		}
		if cfg.SlotMB < minRollingMB {
			cfg.SlotMB = minRollingMB
		}
	default: // "ab"
		if cfg.SlotMB < 2048 {
			slotMB := recommendedSlotGB * 1024
			if slotMB < 2048 {
				slotMB = 4096
			}
			cfg.SlotMB = slotMB
		}
	}
}

// RefreshHardwareEval updates the HardwareEvaluation summary from the current disks and cfg
// without overwriting user-configured disk roles, SlotMB, LuksTPM2, or ZfsAllocMode.
func RefreshHardwareEval(disks []DiskDevice, cfg *InstallerConfig) HardwareEvaluation {
	primaryMB := syncDiskRolesAndConfig(disks, cfg)

	ramMB := detectTotalRAMMB()
	fwMode := "Legacy BIOS"
	if hasUEFIFirmware() {
		fwMode = "UEFI"
	}
	tpm := hasTPM2Device()

	if cfg.ZfsAllocMode == "" {
		if len(cfg.ZfsExtraDisks) > 0 && cfg.InstallMode != "zbm" {
			cfg.ZfsAllocMode = "none"
		} else {
			cfg.ZfsAllocMode = "remainder"
		}
	}
	if cfg.ZfsTopology == "" {
		cfg.ZfsTopology = "auto"
	}

	resolvedTopo := cfg.ZfsTopology
	if resolvedTopo == "" || resolvedTopo == "auto" {
		vdevCount := len(cfg.ZfsExtraDisks)
		if vdevCount == 0 {
			vdevCount = len(cfg.SystemDisks)
		}
		resolvedTopo = "stripe"
		switch {
		case vdevCount == 2:
			resolvedTopo = "mirror"
		case vdevCount >= 3 && vdevCount <= 4:
			resolvedTopo = "raidz1"
		case vdevCount >= 5:
			resolvedTopo = "raidz2"
		}
	}

	sysSummary := "No target disk detected"
	if len(cfg.SystemDisks) == 1 {
		sysSummary = fmt.Sprintf("Single Disk (%s — %.1f GB)", cfg.SystemDisks[0], float64(primaryMB)/1024.0)
	} else if len(cfg.SystemDisks) >= 2 {
		if cfg.InstallMode == "zbm" {
			sysSummary = fmt.Sprintf("ZFS Mirror across %d Disks (%s)", len(cfg.SystemDisks), strings.Join(cfg.SystemDisks, ", "))
		} else {
			sysSummary = fmt.Sprintf("RAID-1 Mirror across %d Disks (%s)", len(cfg.SystemDisks), strings.Join(cfg.SystemDisks, ", "))
		}
	}

	layout := ComputePartitionLayout(primaryMB, *cfg)
	zfsSummary := "Unified on System Disk"
	if cfg.InstallMode == "zbm" {
		if len(cfg.ZfsExtraDisks) > 0 {
			zfsSummary = fmt.Sprintf("zroot (%s) + Dedicated 'tank' (%s on %s)",
				strings.ToUpper(resolvedTopo), strings.ToUpper(resolvedTopo), strings.Join(cfg.ZfsExtraDisks, ", "))
		} else {
			zfsSummary = fmt.Sprintf("All-in-ZFS 'zroot' Pool (%.1f GB, %s, lz4)",
				float64(layout.ZfsMB)/1024.0, strings.ToUpper(resolvedTopo))
		}
	} else {
		if len(cfg.ZfsExtraDisks) > 0 {
			zfsSummary = fmt.Sprintf("Dedicated 'tank' Pool (%s across %s)",
				strings.ToUpper(resolvedTopo), strings.Join(cfg.ZfsExtraDisks, ", "))
		} else if layout.ZfsMB > 0 {
			zfsSummary = fmt.Sprintf("Pool 'tank' on System Disk (%.1f GB, %s)",
				float64(layout.ZfsMB)/1024.0, strings.ToUpper(resolvedTopo))
		} else {
			zfsSummary = "100% OS & Persistent Data (No ZFS partition)"
		}
	}

	slotNote := fmt.Sprintf("%d GB per A/B Slot (%s)", cfg.SlotMB/1024, cfg.RootFSType)
	if cfg.InstallMode == "zbm" {
		slotNote = "ZFS Boot Environments (Copy-on-Write Snapshots, No GRUB)"
	} else if cfg.InstallMode == "rolling" {
		slotNote = fmt.Sprintf("Single Root Partition (%s)", cfg.RootFSType)
	}

	var notes []string
	notes = append(notes, fmt.Sprintf("Evaluated %d storage device(s), %d MB RAM, %s firmware", len(disks), ramMB, fwMode))
	if len(cfg.SystemDisks) >= 2 {
		notes = append(notes, fmt.Sprintf("Auto-configured %d-disk OS redundancy (%s)", len(cfg.SystemDisks), strings.Join(cfg.SystemDisks, " + ")))
	}
	if len(cfg.ZfsExtraDisks) > 0 {
		notes = append(notes, fmt.Sprintf("Auto-tiered %d dedicated data disk(s) into OpenZFS pool 'tank' (%s)", len(cfg.ZfsExtraDisks), strings.ToUpper(resolvedTopo)))
	}
	if tpm {
		notes = append(notes, "Hardware TPM 2.0 detected (PCR 0+2+7 auto-unlock ready if LUKS2 enabled)")
	}
	if len(cfg.SystemDisks) > 0 && diskHasPrecreatedAxonwallPartitions(cfg.SystemDisks[0]) {
		notes = append(notes, fmt.Sprintf("Pre-partitioned Axonwall layout detected on %s (press [X] to preserve existing partitions)", cfg.SystemDisks[0]))
	}
	if cfg.Edition == "k3s-storage" {
		effArc := cfg.ZfsArcMaxMB
		if effArc <= 0 {
			effArc = ComputeDefaultZfsArcMaxMB(ramMB)
		}
		roleDesc := "Standalone SQLite Server + OpenEBS ZFS-LocalPV"
		if cfg.K3sRole == "agent" {
			roleDesc = "Cluster Storage Worker Agent"
		}
		notes = append(notes, fmt.Sprintf("K3s Storage Host: %s | OpenZFS ARC Cap: %d MiB", roleDesc, effArc))
	}

	return HardwareEvaluation{
		TotalRAMMB:        ramMB,
		FirmwareMode:      fwMode,
		HasTPM2:           tpm,
		DiskCount:         len(disks),
		SystemDiskSummary: sysSummary,
		ZfsPoolSummary:    zfsSummary,
		SlotSizingNote:    slotNote,
		EvaluationNotes:   notes,
	}
}

// EvaluateHardwareProfile inspects candidate disks, RAM, UEFI/BIOS, and TPM 2.0,
// applies optimal defaults to cfg, and returns a human-readable HardwareEvaluation summary.
func EvaluateHardwareProfile(disks []DiskDevice, cfg *InstallerConfig) ([]DiskDevice, HardwareEvaluation) {
	evaluatedDisks := AutoAssignDiskRoles(disks)
	primaryMB := syncDiskRolesAndConfig(evaluatedDisks, cfg)

	cfg.LuksTPM2 = hasTPM2Device()

	recGB := recommendedSlotGBForDiskMB(primaryMB)
	if cfg.Edition == "k3s-storage" && primaryMB < 102400 && recGB > 4 {
		recGB = 4
	}
	if cfg.InstallMode == "zbm" {
		cfg.SlotMB = 0
	} else {
		cfg.SlotMB = recGB * 1024
		normalizeSlotMBForMode(cfg, recGB, primaryMB)
		if cfg.Edition == "k3s-storage" && primaryMB < 102400 && cfg.InstallMode != "rolling" && cfg.SlotMB > 4096 {
			cfg.SlotMB = 4096
		}
	}

	// Evaluate ZFS allocation and topology
	if len(cfg.ZfsExtraDisks) > 0 && cfg.InstallMode != "zbm" {
		cfg.ZfsAllocMode = "none"
	} else if cfg.Edition == "k3s-storage" && len(cfg.ZfsExtraDisks) == 0 && cfg.InstallMode != "zbm" {
		cfg.ZfsAllocMode = "remainder"
	} else if cfg.ZfsAllocMode == "" {
		cfg.ZfsAllocMode = "remainder"
	}
	if cfg.ZfsTopology == "" || cfg.ZfsTopology == "auto" {
		cfg.ZfsTopology = "auto"
	}
	if cfg.Edition == "k3s-storage" && cfg.K3sRole == "" {
		cfg.K3sRole = "server"
	}

	return evaluatedDisks, RefreshHardwareEval(evaluatedDisks, cfg)
}

// syncDiskRolesAndConfig synchronizes DiskDevice roles into InstallerConfig disk slices.
func syncDiskRolesAndConfig(disks []DiskDevice, cfg *InstallerConfig) (primaryMB int) {
	primaryMB = 32768
	var sysDisks, dataDisks, slogDisks, l2arcDisks, spareDisks []string
	for i := range disks {
		d := &disks[i]
		if d.Role == "" {
			if d.SystemDisk {
				d.Role = "system"
			} else if d.ZfsExtra {
				d.Role = "zfs-data"
			} else {
				d.Role = "none"
			}
		}
		d.SystemDisk = d.Role == "system"
		d.ZfsExtra = d.Role == "zfs-data"

		switch d.Role {
		case "system":
			sysDisks = append(sysDisks, d.Path)
			if len(sysDisks) == 1 && d.SizeMB > 0 {
				primaryMB = d.SizeMB
			}
		case "zfs-data":
			dataDisks = append(dataDisks, d.Path)
		case "zfs-slog":
			slogDisks = append(slogDisks, d.Path)
		case "zfs-l2arc":
			l2arcDisks = append(l2arcDisks, d.Path)
		case "zfs-spare":
			spareDisks = append(spareDisks, d.Path)
		}
	}
	cfg.SystemDisks = sysDisks
	cfg.ZfsExtraDisks = dataDisks
	cfg.ZfsSlogDisks = slogDisks
	cfg.ZfsL2arcDisks = l2arcDisks
	cfg.ZfsSpareDisks = spareDisks
	return primaryMB
}

// ComputePartitionLayout calculates the exact partition sizes in MiB for the given disk capacity and config.
func ComputePartitionLayout(diskMB int, cfg InstallerConfig) PartitionLayout {
	if diskMB <= 0 {
		diskMB = 32768
	}
	if cfg.InstallMode == "zbm" {
		efiMB := 512
		logsMB := 0
		if cfg.LogsEnabled && cfg.LogsGB >= 1 {
			logsMB = cfg.LogsGB * 1024
		}
		remMB := diskMB - efiMB - logsMB - 16
		if remMB < 1024 {
			remMB = 1024
		}
		dataMB := 0
		zfsMB := remMB
		if cfg.LuksEnabled {
			dataMB = 4096
			if remMB > 6144 {
				zfsMB = remMB - dataMB
			} else {
				dataMB = remMB / 2
				zfsMB = remMB - dataMB
			}
		}
		return PartitionLayout{
			TotalMB: diskMB,
			EfiMB:   efiMB,
			SlotAMB: 0,
			SlotBMB: 0,
			LogsMB:  logsMB,
			DataMB:  dataMB,
			ZfsMB:   zfsMB,
		}
	}

	efiMB := 260
	slotAMB := cfg.SlotMB
	if slotAMB < 2048 {
		slotAMB = 4096
	}
	slotBMB := 0
	if cfg.InstallMode == "ab" {
		slotBMB = slotAMB
	}
	logsMB := 0
	if cfg.LogsEnabled && cfg.LogsGB >= 1 {
		logsMB = cfg.LogsGB * 1024
	}

	usedBeforeData := efiMB + slotAMB + slotBMB + logsMB + 16
	remMB := diskMB - usedBeforeData
	if remMB < 1024 {
		remMB = 1024
	}

	dataMB := remMB
	zfsMB := 0

	switch cfg.ZfsAllocMode {
	case "split":
		dataMB = remMB / 2
		zfsMB = remMB - dataMB
	case "custom":
		if cfg.CustomZfsGB >= 1 {
			zfsMB = cfg.CustomZfsGB * 1024
			if zfsMB > remMB-2048 {
				zfsMB = remMB - 2048
			}
			if zfsMB < 0 {
				zfsMB = 0
			}
			dataMB = remMB - zfsMB
		}
	case "none":
		zfsMB = 0
		dataMB = remMB
	default: // "remainder"
		if remMB > 10240 {
			if cfg.Edition == "k3s-storage" {
				dataMB = 4096
			} else {
				dataMB = 8192
			}
			zfsMB = remMB - dataMB
		} else if remMB > 4096 {
			dataMB = 2048
			zfsMB = remMB - dataMB
		} else {
			zfsMB = 0
			dataMB = remMB
		}
	}

	return PartitionLayout{
		TotalMB: diskMB,
		EfiMB:   efiMB,
		SlotAMB: slotAMB,
		SlotBMB: slotBMB,
		LogsMB:  logsMB,
		DataMB:  dataMB,
		ZfsMB:   zfsMB,
	}
}

// RenderPartitionBar returns an ANSI-colored visual bar chart and legend for the partition layout.
func RenderPartitionBar(layout PartitionLayout, cfg InstallerConfig, width int) string {
	if width < 24 {
		width = 60
	}
	total := layout.EfiMB + layout.SlotAMB + layout.SlotBMB + layout.LogsMB + layout.DataMB + layout.ZfsMB
	if total <= 0 {
		total = 1
	}

	type seg struct {
		label string
		mb    int
		color string
		char  string
	}
	segments := []seg{
		{label: func() string {
			if cfg.InstallMode == "zbm" {
				return "ZBM-EFI"
			}
			return "EFI"
		}(), mb: layout.EfiMB, color: colorBlue + colorBold, char: "█"},
	}
	if layout.SlotAMB > 0 {
		slotALabel := "Slot A"
		if cfg.InstallMode == "rolling" {
			slotALabel = "Root OS"
		}
		segments = append(segments, seg{label: slotALabel, mb: layout.SlotAMB, color: colorEmerald + colorBold, char: "█"})
	}
	if layout.SlotBMB > 0 {
		segments = append(segments, seg{label: "Slot B", mb: layout.SlotBMB, color: colorCyan + colorBold, char: "█"})
	}
	if layout.LogsMB > 0 && cfg.InstallMode != "zbm" {
		segments = append(segments, seg{label: "Logs", mb: layout.LogsMB, color: colorYellow + colorBold, char: "█"})
	}
	if layout.DataMB > 0 {
		dataLabel := "Data"
		if cfg.LuksEnabled {
			dataLabel = "Data[LUKS2]"
		}
		segments = append(segments, seg{label: dataLabel, mb: layout.DataMB, color: colorMagenta + colorBold, char: "█"})
	}
	if layout.ZfsMB > 0 {
		poolName := "ZFS:tank"
		if cfg.InstallMode == "zbm" {
			poolName = "ZFS:zroot"
		}
		segments = append(segments, seg{label: poolName, mb: layout.ZfsMB, color: colorGreen + colorBold, char: "█"})
	}

	// Allocate character cells proportionally, guaranteeing at least 2 chars per active segment
	counts := make([]int, len(segments))
	usedCells := 0
	for i, s := range segments {
		c := (s.mb * width) / total
		if c < 2 {
			c = 2
		}
		counts[i] = c
		usedCells += c
	}
	// Adjust segments so total width matches exactly while keeping each segment >= 2
	diff := width - usedCells
	if diff > 0 {
		maxIdx := 0
		for i := range segments {
			if counts[i] > counts[maxIdx] {
				maxIdx = i
			}
		}
		counts[maxIdx] += diff
	} else {
		for diff < 0 {
			maxIdx := -1
			for i := range segments {
				if counts[i] > 2 && (maxIdx == -1 || counts[i] > counts[maxIdx]) {
					maxIdx = i
				}
			}
			if maxIdx == -1 {
				break
			}
			counts[maxIdx]--
			diff++
		}
	}

	var sb strings.Builder
	sb.WriteString("  [")
	for i, s := range segments {
		sb.WriteString(s.color)
		sb.WriteString(strings.Repeat(s.char, counts[i]))
		sb.WriteString(colorReset)
	}
	sb.WriteString("]\n  ")

	for i, s := range segments {
		if i > 0 {
			sb.WriteString("  ")
		}
		sizeStr := fmt.Sprintf("%.1fG", float64(s.mb)/1024.0)
		if s.mb < 1024 {
			sizeStr = fmt.Sprintf("%dM", s.mb)
		}
		sb.WriteString(fmt.Sprintf("%s■%s %s (%s)", s.color, colorReset, s.label, sizeStr))
	}
	return sb.String()
}

// shellQuote safely single-quotes a string for POSIX shell sourcing.
func shellQuote(val string) string {
	return "'" + strings.ReplaceAll(val, "'", "'\"'\"'") + "'"
}

// FormatInstallerConfig serializes InstallerConfig into key=value format for axonwall-install --apply-config.
func FormatInstallerConfig(cfg InstallerConfig) string {
	logsEnabled := 0
	if cfg.LogsEnabled {
		logsEnabled = 1
	}
	luksEnabled := 0
	if cfg.LuksEnabled {
		luksEnabled = 1
	}
	luksTPM2 := 0
	if cfg.LuksTPM2 {
		luksTPM2 = 1
	}
	keepParts := 0
	if cfg.KeepPartitions {
		keepParts = 1
	}

	edition := cfg.Edition
	if edition == "" {
		edition = "axonwall"
	}
	k3sRole := cfg.K3sRole
	if k3sRole == "" {
		k3sRole = "server"
	}

	lines := []string{
		"# Axonwall Next-Gen Installer Configuration",
		fmt.Sprintf("INSTALL_EDITION=%s", shellQuote(edition)),
		fmt.Sprintf("SYSTEM_DISKS=%s", shellQuote(strings.Join(cfg.SystemDisks, " "))),
		fmt.Sprintf("INSTALL_MODE=%s", shellQuote(cfg.InstallMode)),
		fmt.Sprintf("KEEP_PARTITIONS=%d", keepParts),
		fmt.Sprintf("SLOT_MB=%d", cfg.SlotMB),
		fmt.Sprintf("ROOT_FSTYPE=%s", shellQuote(cfg.RootFSType)),
		fmt.Sprintf("DATA_FSTYPE=%s", shellQuote(cfg.DataFSType)),
		fmt.Sprintf("ZFS_ALLOC_MODE=%s", shellQuote(cfg.ZfsAllocMode)),
		fmt.Sprintf("CUSTOM_ZFS_GB=%d", cfg.CustomZfsGB),
		fmt.Sprintf("ZFS_EXTRA_DISKS=%s", shellQuote(strings.Join(cfg.ZfsExtraDisks, " "))),
		fmt.Sprintf("ZFS_SLOG_DISKS=%s", shellQuote(strings.Join(cfg.ZfsSlogDisks, " "))),
		fmt.Sprintf("ZFS_L2ARC_DISKS=%s", shellQuote(strings.Join(cfg.ZfsL2arcDisks, " "))),
		fmt.Sprintf("ZFS_SPARE_DISKS=%s", shellQuote(strings.Join(cfg.ZfsSpareDisks, " "))),
		fmt.Sprintf("ZFS_RAID_TOPOLOGY=%s", shellQuote(cfg.ZfsTopology)),
		fmt.Sprintf("LOGS_ENABLED=%d", logsEnabled),
		fmt.Sprintf("LOGS_GB=%d", cfg.LogsGB),
		fmt.Sprintf("LOGS_FSTYPE=%s", shellQuote(cfg.LogsFSType)),
		fmt.Sprintf("LUKS_ENABLED=%d", luksEnabled),
		fmt.Sprintf("LUKS_TPM2=%d", luksTPM2),
		fmt.Sprintf("LUKS_PASSPHRASE=%s", shellQuote(cfg.LuksPassphrase)),
		fmt.Sprintf("HOSTNAME_OVERRIDE=%s", shellQuote(cfg.Hostname)),
		fmt.Sprintf("ADMIN_USER=%s", shellQuote(cfg.AdminUser)),
		fmt.Sprintf("ADMIN_PASSWORD=%s", shellQuote(cfg.AdminPassword)),
		fmt.Sprintf("K3S_ROLE=%s", shellQuote(k3sRole)),
		fmt.Sprintf("K3S_SERVER_URL=%s", shellQuote(cfg.K3sServerURL)),
		fmt.Sprintf("K3S_JOIN_TOKEN=%s", shellQuote(cfg.K3sJoinToken)),
		fmt.Sprintf("ZFS_ARC_MAX_MB=%d", cfg.ZfsArcMaxMB),
	}
	return strings.Join(lines, "\n") + "\n"
}

// redactDiagnosticsSecrets ensures plaintext passphrases, passwords, and cluster join tokens
// never leak into exported or HTTP-shipped installer diagnostics bundles.
func redactDiagnosticsSecrets(s string, cfg InstallerConfig) string {
	for _, secret := range []string{cfg.AdminPassword, cfg.LuksPassphrase, cfg.K3sJoinToken} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "[REDACTED]")
			s = strings.ReplaceAll(s, shellQuote(secret), "'[REDACTED]'")
		}
	}
	return s
}

// readRawKey reads a single keypress or ANSI arrow escape sequence using non-canonical stty mode.
func readRawKey() string {
	rawCmd := exec.Command("stty", "-icanon", "-echo", "min", "1", "time", "0")
	rawCmd.Stdin = os.Stdin
	_ = rawCmd.Run()
	defer func() {
		saneCmd := exec.Command("stty", "icanon", "echo")
		saneCmd.Stdin = os.Stdin
		_ = saneCmd.Run()
	}()

	buf := make([]byte, 8)
	n, err := os.Stdin.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	s := string(buf[:n])
	switch {
	case s == "\x1b[A" || s == "\x1bOA":
		return "UP"
	case s == "\x1b[B" || s == "\x1bOB":
		return "DOWN"
	case s == "\x1b[C" || s == "\x1bOC":
		return "RIGHT"
	case s == "\x1b[D" || s == "\x1bOD":
		return "LEFT"
	case s == "\x1b[5~":
		return "PGUP"
	case s == "\x1b[6~":
		return "PGDN"
	case s == "\f":
		return "REDRAW"
	case s == "\r" || s == "\n":
		return "ENTER"
	case s == " ":
		return "SPACE"
	case s == "\x1b":
		return "ESC"
	case s == "\x7f" || s == "\b":
		return "BACKSPACE"
	default:
		return strings.ToUpper(strings.TrimSpace(s))
	}
}

var (
	consoleCaptureOnce sync.Once
	consoleMasterPTY   *os.File
)

// openLinuxPTY allocates a master/slave PTY pair using /dev/ptmx and TIOCGPTN/TIOCSPTLCK ioctls.
func openLinuxPTY() (*os.File, *os.File, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	var unlock int32 = 0
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), uintptr(syscall.TIOCSPTLCK), uintptr(unsafe.Pointer(&unlock)))
	if errno != 0 {
		_ = master.Close()
		return nil, nil, errno
	}
	var ptyNum uint32
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), uintptr(syscall.TIOCGPTN), uintptr(unsafe.Pointer(&ptyNum)))
	if errno != 0 {
		_ = master.Close()
		return nil, nil, errno
	}
	slavePath := fmt.Sprintf("/dev/pts/%d", ptyNum)
	slave, err := os.OpenFile(slavePath, os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		_ = master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

// suppressConsoleNoise intercepts all /dev/console writes (including cloud-init,
// background systemd services, udev, and kernel printk) via the Linux TIOCCONS ioctl
// onto a hidden capture PTY, and drains every byte into /var/log/axonwall-console-capture.log.
// This guarantees zero raw garbage output ever bleeds onto /dev/tty1 while the TUI runs.
func suppressConsoleNoise() {
	_ = os.WriteFile("/proc/sys/kernel/printk", []byte("1\t4\t1\t7\n"), 0644)
	_ = exec.Command("dmesg", "-n", "1").Run()
	if os.Geteuid() == 0 {
		// SIGRTMIN+21 (signal 55 on Linux x86_64/arm64) instructs PID 1 (systemd)
		// to disable ShowStatus console output immediately.
		_ = syscall.Kill(1, syscall.Signal(55))
	}

	consoleCaptureOnce.Do(func() {
		if os.Geteuid() != 0 {
			return
		}
		master, slave, err := openLinuxPTY()
		if err != nil {
			// Fallback: redirect /dev/console to /dev/tty12 if PTY allocation is unavailable
			if tty12, tErr := os.OpenFile("/dev/tty12", os.O_RDWR|syscall.O_NOCTTY, 0); tErr == nil {
				_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, tty12.Fd(), uintptr(syscall.TIOCCONS), 0)
				_ = tty12.Close()
			}
			return
		}
		// TIOCCONS redirects all kernel /dev/console and /dev/tty0 output to slave PTY!
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, slave.Fd(), uintptr(syscall.TIOCCONS), 0)
		_ = slave.Close()
		if errno != 0 {
			_ = master.Close()
			return
		}
		consoleMasterPTY = master
		go func() {
			_ = os.MkdirAll("/var/log", 0755)
			logFile, _ := os.OpenFile("/var/log/axonwall-console-capture.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			defer func() {
				if logFile != nil {
					_ = logFile.Close()
				}
			}()
			buf := make([]byte, 4096)
			for {
				n, rErr := master.Read(buf)
				if n > 0 && logFile != nil {
					_, _ = logFile.Write(buf[:n])
				}
				if rErr != nil {
					return
				}
			}
		}()
	})
}

// collectCloudInitAndConsoleCaptureLines returns captured /dev/console output, cloud-init-output.log, and cloud-init.log.
func collectCloudInitAndConsoleCaptureLines() []string {
	var lines []string
	lines = append(lines, "=== Intercepted /dev/console Stream (/var/log/axonwall-console-capture.log) ===")
	if data, err := os.ReadFile("/var/log/axonwall-console-capture.log"); err == nil && len(strings.TrimSpace(string(data))) > 0 {
		raw := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(raw) > 120 {
			raw = raw[len(raw)-120:]
		}
		for _, l := range raw {
			lines = append(lines, "  "+strings.TrimRight(l, "\r"))
		}
	} else {
		lines = append(lines, "  (TIOCCONS interceptor active — no stray /dev/console writes captured yet)")
	}

	lines = append(lines, "")
	lines = append(lines, "=== Cloud-Init Console & Provisioning Output (/var/log/cloud-init-output.log) ===")
	if data, err := os.ReadFile("/var/log/cloud-init-output.log"); err == nil && len(strings.TrimSpace(string(data))) > 0 {
		raw := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(raw) > 150 {
			raw = raw[len(raw)-150:]
		}
		for _, l := range raw {
			lines = append(lines, "  "+strings.TrimRight(l, "\r"))
		}
	} else if jOut, err := exec.Command("journalctl", "-u", "cloud-init-local.service", "-u", "cloud-init.service", "-u", "cloud-config.service", "-u", "cloud-final.service", "-n", "100", "--no-pager", "-o", "short-iso").CombinedOutput(); err == nil && len(strings.TrimSpace(string(jOut))) > 0 {
		for _, l := range strings.Split(strings.TrimRight(string(jOut), "\n"), "\n") {
			lines = append(lines, "  "+l)
		}
	} else {
		lines = append(lines, "  (No cloud-init output recorded in this session)")
	}

	if data, err := os.ReadFile("/var/log/cloud-init.log"); err == nil && len(strings.TrimSpace(string(data))) > 0 {
		lines = append(lines, "")
		lines = append(lines, "=== Cloud-Init Detailed Log Tail (/var/log/cloud-init.log) ===")
		raw := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(raw) > 80 {
			raw = raw[len(raw)-80:]
		}
		for _, l := range raw {
			lines = append(lines, "  "+strings.TrimRight(l, "\r"))
		}
	}
	return lines
}

// ShipInstallerDiagnosticsBundle ships the full diagnostics bundle to an HTTP(S) endpoint,
// syslogserver (UDP/TCP host:port), or SCP target (user@host:/path).
func ShipInstallerDiagnosticsBundle(endpoint string, cfg InstallerConfig, eval HardwareEvaluation, rawLines []string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("no shipping destination specified")
	}
	if strings.HasPrefix(endpoint, "-") {
		return "", fmt.Errorf("invalid shipping destination: %s", endpoint)
	}
	bundle := FormatInstallerDiagnosticsBundle(cfg, eval, rawLines)

	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		client := &http.Client{Timeout: 10 * time.Second}
		req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(bundle))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "text/plain; charset=utf-8")
		req.Header.Set("X-Axonwall-Hostname", cfg.Hostname)
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return "", fmt.Errorf("HTTP %d from %s", resp.StatusCode, endpoint)
		}
		return fmt.Sprintf("HTTP POST %s (%d)", endpoint, resp.StatusCode), nil
	}

	if strings.HasPrefix(endpoint, "syslog://") || strings.HasPrefix(endpoint, "udp://") || strings.HasPrefix(endpoint, "tcp://") {
		proto := "udp"
		addr := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(endpoint, "syslog://"), "udp://"), "tcp://")
		if strings.HasPrefix(endpoint, "tcp://") {
			proto = "tcp"
		}
		host, port, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			host = strings.Trim(addr, "[]")
			port = "514"
		}
		if host == "" || strings.HasPrefix(host, "-") || strings.HasPrefix(port, "-") {
			return "", fmt.Errorf("invalid syslog destination: %s", endpoint)
		}
		cmd := exec.Command("logger", "-n", host, "-P", port, "-t", "axonwall-installer")
		if proto == "tcp" {
			cmd.Args = append(cmd.Args, "-T")
		}
		cmd.Stdin = strings.NewReader(bundle)
		if err := cmd.Run(); err != nil {
			return "", err
		}
		return fmt.Sprintf("Syslog %s://%s", proto, net.JoinHostPort(host, port)), nil
	}

	// Default to SCP if user@host:/path or host:/path format
	saved, err := SaveInstallerDiagnosticsBundle("", cfg, eval, rawLines)
	if err != nil || len(saved) == 0 {
		return "", fmt.Errorf("failed to stage local bundle for SCP: %v", err)
	}
	scpCmd := exec.Command("scp", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=8", "--", saved[0], endpoint)
	if out, err := scpCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("scp failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return fmt.Sprintf("SCP %s", endpoint), nil
}

// countFailedSystemdUnits returns the number of failed systemd units on the system.
func countFailedSystemdUnits() (int, []string) {
	out, err := exec.Command("systemctl", "--failed", "--no-legend", "--no-pager", "--plain").Output()
	if err != nil && len(out) == 0 {
		return 0, nil
	}
	var units []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			units = append(units, fields[0])
		}
	}
	return len(units), units
}

// collectInstallerLogLines returns lines from /var/log/axonwall-install.log combined with in-memory lines.
func collectInstallerLogLines(rawLines []string) []string {
	var lines []string
	if data, err := os.ReadFile("/var/log/axonwall-install.log"); err == nil && len(data) > 0 {
		for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 && len(rawLines) > 0 {
		lines = append(lines, rawLines...)
	}
	if len(lines) == 0 {
		lines = []string{
			"No installation has been executed yet in this session.",
			" Log path: /var/log/axonwall-install.log",
			"",
			" Tip: Switch to Tab [2] to inspect captured background systemd service",
			"      & kernel warnings/errors, or Tab [3] for Hardware & Storage Probe.",
		}
	}
	return lines
}

// collectCapturedServiceAndSystemErrors returns failed systemd units and recent journalctl warning/error entries.
func collectCapturedServiceAndSystemErrors() []string {
	var lines []string
	lines = append(lines, "=== Captured Systemd Failed Units (Suppressed from Console TUI) ===")
	failedCnt, failedUnits := countFailedSystemdUnits()
	if failedCnt == 0 {
		lines = append(lines, "  [✓] No failed systemd units detected.")
	} else {
		lines = append(lines, fmt.Sprintf("  [!] %d failed unit(s) captured off-screen: %s", failedCnt, strings.Join(failedUnits, ", ")))
		if out, err := exec.Command("systemctl", "--failed", "--no-pager", "--plain").CombinedOutput(); err == nil && len(out) > 0 {
			for _, l := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
				lines = append(lines, "  "+l)
			}
		}
		for _, u := range failedUnits {
			lines = append(lines, "")
			lines = append(lines, fmt.Sprintf("--- Unit Status: %s ---", u))
			if uOut, err := exec.Command("systemctl", "status", u, "--no-pager", "-n", "12").CombinedOutput(); len(uOut) > 0 || err != nil {
				for _, l := range strings.Split(strings.TrimRight(string(uOut), "\n"), "\n") {
					lines = append(lines, "  "+l)
				}
			}
		}
	}

	lines = append(lines, "")
	lines = append(lines, "=== Recent System & Service Warnings / Errors (journalctl -p err..warning) ===")
	if jOut, err := exec.Command("journalctl", "-p", "err..warning", "-n", "80", "--no-pager", "-o", "short-iso").CombinedOutput(); err == nil && len(jOut) > 0 {
		for _, l := range strings.Split(strings.TrimRight(string(jOut), "\n"), "\n") {
			lines = append(lines, "  "+l)
		}
	} else if dOut, err := exec.Command("dmesg", "--level=err,warn").CombinedOutput(); err == nil && len(dOut) > 0 {
		for _, l := range strings.Split(strings.TrimRight(string(dOut), "\n"), "\n") {
			lines = append(lines, "  "+l)
		}
	} else {
		lines = append(lines, "  (No warning/error journal entries available)")
	}
	return lines
}

// collectHardwareAndStorageProbeLines returns hardware evaluation and block/ZFS/RAID diagnostics.
func collectHardwareAndStorageProbeLines(cfg InstallerConfig, eval HardwareEvaluation) []string {
	var lines []string
	lines = append(lines, "=== Hardware Self-Evaluation & Selected Installer Profile ===")
	lines = append(lines, fmt.Sprintf("  Appliance Edition : %s (%s)", strings.ToUpper(cfg.Edition), cfg.OSFamily))
	lines = append(lines, fmt.Sprintf("  Install Mode      : %s", strings.ToUpper(cfg.InstallMode)))
	lines = append(lines, fmt.Sprintf("  Firmware & RAM    : %s | %d MB RAM | TPM 2.0: %v", eval.FirmwareMode, eval.TotalRAMMB, eval.HasTPM2))
	lines = append(lines, fmt.Sprintf("  System OS Disks   : %s", eval.SystemDiskSummary))
	lines = append(lines, fmt.Sprintf("  OpenZFS Pool      : %s", eval.ZfsPoolSummary))
	lines = append(lines, fmt.Sprintf("  Slot Sizing       : %s", eval.SlotSizingNote))
	adminPassDiag := "(factory default)"
	if cfg.AdminPassword != "" {
		adminPassDiag = "[REDACTED]"
	}
	luksPassDiag := "(none)"
	if cfg.LuksPassphrase != "" {
		luksPassDiag = "[REDACTED]"
	}
	lines = append(lines, fmt.Sprintf("  Auth & LUKS2      : AdminPass=%s | LUKS2=%v (Passphrase=%s)", adminPassDiag, cfg.LuksEnabled, luksPassDiag))
	if cfg.Edition == "k3s-storage" || cfg.K3sJoinToken != "" || cfg.K3sServerURL != "" {
		role := cfg.K3sRole
		if role == "" {
			role = "server"
		}
		tokDiag := "(none)"
		if cfg.K3sJoinToken != "" {
			tokDiag = "[REDACTED]"
		}
		effArc := cfg.ZfsArcMaxMB
		if effArc <= 0 {
			effArc = ComputeDefaultZfsArcMaxMB(eval.TotalRAMMB)
		}
		lines = append(lines, fmt.Sprintf("  K3s Storage Config: Role=%s | ServerURL=%s | JoinToken=%s | ZfsArcMaxMB=%d", role, cfg.K3sServerURL, tokDiag, effArc))
	}
	for _, note := range eval.EvaluationNotes {
		lines = append(lines, "  • "+note)
	}

	lines = append(lines, "")
	lines = append(lines, "=== Block Storage Devices (lsblk) ===")
	if out, err := exec.Command("lsblk", "-o", "NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT,MODEL").CombinedOutput(); err == nil && len(out) > 0 {
		for _, l := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
			lines = append(lines, "  "+l)
		}
	}

	lines = append(lines, "")
	lines = append(lines, "=== OpenZFS Pools (zpool status) ===")
	if out, err := exec.Command("zpool", "status").CombinedOutput(); err == nil && len(out) > 0 {
		for _, l := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
			lines = append(lines, "  "+l)
		}
	} else {
		lines = append(lines, "  (No active OpenZFS pools imported)")
	}

	lines = append(lines, "")
	lines = append(lines, "=== Linux Software RAID (mdadm /proc/mdstat) ===")
	if data, err := os.ReadFile("/proc/mdstat"); err == nil && len(data) > 0 {
		for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			lines = append(lines, "  "+l)
		}
	} else {
		lines = append(lines, "  (No active mdadm arrays)")
	}
	return lines
}

// FormatInstallerDiagnosticsBundle builds a comprehensive plain-text diagnostic report for saving/exporting.
func FormatInstallerDiagnosticsBundle(cfg InstallerConfig, eval HardwareEvaluation, rawLines []string) string {
	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString(" AXONWALL NEXT-GEN INSTALLER — DIAGNOSTICS & LOG BUNDLE\n")
	sb.WriteString(fmt.Sprintf(" Generated: %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString("================================================================================\n\n")

	sb.WriteString("--- [1] HARDWARE & STORAGE PROBE ---\n")
	for _, l := range collectHardwareAndStorageProbeLines(cfg, eval) {
		sb.WriteString(l + "\n")
	}
	sb.WriteString("\n--- [2] CAPTURED SERVICE & SYSTEM ERRORS ---\n")
	for _, l := range collectCapturedServiceAndSystemErrors() {
		sb.WriteString(l + "\n")
	}
	sb.WriteString("\n--- [3] CLOUD-INIT & INTERCEPTED CONSOLE OUTPUT ---\n")
	for _, l := range collectCloudInitAndConsoleCaptureLines() {
		sb.WriteString(l + "\n")
	}
	sb.WriteString("\n--- [4] INSTALLER EXECUTION LOG ---\n")
	for _, l := range collectInstallerLogLines(rawLines) {
		sb.WriteString(l + "\n")
	}
	return redactDiagnosticsSecrets(sb.String(), cfg)
}

// SaveInstallerDiagnosticsBundle writes the diagnostics bundle to the requested path (and standard fallback paths).
func SaveInstallerDiagnosticsBundle(customPath string, cfg InstallerConfig, eval HardwareEvaluation, rawLines []string) ([]string, error) {
	bundle := FormatInstallerDiagnosticsBundle(cfg, eval, rawLines)
	targets := []string{
		"/var/log/axonwall-installer-diagnostics.log",
		"/root/axonwall-installer-diagnostics.log",
	}
	if st, err := os.Stat("/mnt/slot_a/var/log"); err == nil && st.IsDir() {
		targets = append(targets, "/mnt/slot_a/var/log/axonwall-installer-diagnostics.log")
	}
	customPath = strings.TrimSpace(customPath)
	if customPath != "" {
		if st, err := os.Stat(customPath); err == nil && st.IsDir() {
			customPath = filepath.Join(customPath, "axonwall-installer-diagnostics.log")
		}
		already := false
		for _, t := range targets {
			if t == customPath {
				already = true
				break
			}
		}
		if !already {
			targets = append([]string{customPath}, targets...)
		}
	}

	var saved []string
	var lastErr error
	for _, p := range targets {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			lastErr = err
			continue
		}
		if err := os.WriteFile(p, []byte(bundle), 0600); err != nil {
			lastErr = err
			continue
		}
		saved = append(saved, p)
	}
	if len(saved) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return saved, nil
}

// runInstallerLogsScreen renders the interactive Logs & Diagnostics TUI screen inside the installer.
func runInstallerLogsScreen(cfg InstallerConfig, eval HardwareEvaluation, rawLines []string, reader *bufio.Reader) {
	suppressConsoleNoise()
	activeTab := 1 // 1=Installer Log, 2=Service/System Errors, 3=Cloud-Init & Console Stream, 4=Hardware Probe
	if len(rawLines) == 0 {
		if _, err := os.Stat("/var/log/axonwall-install.log"); err != nil {
			// Default to Captured Service & System Errors or Cloud-Init & Console Stream if install hasn't run yet
			if cnt, _ := countFailedSystemdUnits(); cnt > 0 {
				activeTab = 2
			} else if st, err := os.Stat("/var/log/axonwall-console-capture.log"); err == nil && st.Size() > 0 {
				activeTab = 3
			} else if st, err := os.Stat("/var/log/cloud-init-output.log"); err == nil && st.Size() > 0 {
				activeTab = 3
			}
		}
	}
	scrollOffset := 0
	statusBanner := ""

	for {
		clearScreen()
		accent := colorEmerald
		if cfg.Edition == "vault" || cfg.Edition == "k3s-storage" {
			accent = colorBrightCya
		}
		fmt.Printf("%s%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n", accent, colorBold, colorReset)
		fmt.Printf("%s%s║  📋  AXONWALL INSTALLER — LOGS, CAPTURED CONSOLE & DIAGNOSTICS PANE          ║%s\n", accent, colorBold, colorReset)
		fmt.Printf("%s%s║      Raw cloud-init, service & kernel output is intercepted & preserved here ║%s\n", colorCyan, colorBold, colorReset)
		fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════════════════╝%s\n", accent, colorBold, colorReset)

		failedCnt, _ := countFailedSystemdUnits()
		tab1Label := "[1] Install Log"
		tab2Label := fmt.Sprintf("[2] Service Errors (%d)", failedCnt)
		tab3Label := "[3] Cloud-Init & Console"
		tab4Label := "[4] Hardware Probe"

		renderTab := func(idx int, label string) string {
			if activeTab == idx {
				return accent + colorBold + "● " + label + colorReset
			}
			return colorDim + "  " + label + colorReset
		}
		fmt.Printf(" %s  %s  %s  %s\n", renderTab(1, tab1Label), renderTab(2, tab2Label), renderTab(3, tab3Label), renderTab(4, tab4Label))
		fmt.Println("────────────────────────────────────────────────────────────────────────────────")

		var lines []string
		switch activeTab {
		case 1:
			lines = collectInstallerLogLines(rawLines)
		case 2:
			lines = collectCapturedServiceAndSystemErrors()
		case 3:
			lines = collectCloudInitAndConsoleCaptureLines()
		case 4:
			lines = collectHardwareAndStorageProbeLines(cfg, eval)
		}

		pageSize := 13
		maxScroll := len(lines) - pageSize
		if maxScroll < 0 {
			maxScroll = 0
		}
		if scrollOffset > maxScroll {
			scrollOffset = maxScroll
		}
		if scrollOffset < 0 {
			scrollOffset = 0
		}

		endIdx := scrollOffset + pageSize
		if endIdx > len(lines) {
			endIdx = len(lines)
		}

		for i := scrollOffset; i < endIdx; i++ {
			line := lines[i]
			if runes := []rune(line); len(runes) > 78 {
				line = string(runes[:78])
			}
			lineColor := ""
			lower := strings.ToLower(line)
			switch {
			case strings.Contains(lower, "failed") || strings.Contains(lower, "[!]") || strings.Contains(lower, "error"):
				lineColor = colorRed
			case strings.Contains(lower, "warn"):
				lineColor = colorYellow
			case strings.HasPrefix(strings.TrimSpace(line), "===") || strings.HasPrefix(strings.TrimSpace(line), "---"):
				lineColor = colorCyan + colorBold
			case strings.Contains(line, "[✓]") || strings.Contains(line, "[+]"):
				lineColor = colorGreen
			}
			if lineColor != "" {
				fmt.Printf(" %s%s%s\n", lineColor, line, colorReset)
			} else {
				fmt.Printf(" %s\n", line)
			}
		}
		for i := endIdx - scrollOffset; i < pageSize; i++ {
			fmt.Println()
		}

		fmt.Println("────────────────────────────────────────────────────────────────────────────────")
		if statusBanner != "" {
			fmt.Printf(" %s\n", statusBanner)
		} else {
			fmt.Printf(" %sLines %d–%d of %d%s  (Console Interceptor: %sTIOCCONS ACTIVE%s)\n",
				colorDim, scrollOffset+1, endIdx, len(lines), colorReset, colorEmerald+colorBold, colorReset)
		}
		fmt.Printf(" %sControls:%s [1-4] Tab  [↑/↓/PgUp/PgDn] Scroll  %s[S] Save%s  %s[X] Ship Logs%s  [C] Clear  [B/Esc] Back\n",
			colorDim, colorReset, colorEmerald+colorBold, colorReset, colorCyan+colorBold, colorReset)

		key := readRawKey()
		statusBanner = ""
		switch key {
		case "1":
			activeTab = 1
			scrollOffset = 0
		case "2":
			activeTab = 2
			scrollOffset = 0
		case "3":
			activeTab = 3
			scrollOffset = 0
		case "4":
			activeTab = 4
			scrollOffset = 0
		case "LEFT":
			if activeTab > 1 {
				activeTab--
				scrollOffset = 0
			}
		case "RIGHT":
			if activeTab < 4 {
				activeTab++
				scrollOffset = 0
			}
		case "UP", "K":
			if scrollOffset > 0 {
				scrollOffset--
			}
		case "DOWN", "J":
			if scrollOffset < maxScroll {
				scrollOffset++
			}
		case "PGUP", "U":
			scrollOffset -= pageSize
			if scrollOffset < 0 {
				scrollOffset = 0
			}
		case "PGDN", "D", "SPACE":
			scrollOffset += pageSize
			if scrollOffset > maxScroll {
				scrollOffset = maxScroll
			}
		case "S":
			fmt.Print("\n Save path (Enter for /var/log & /root, or enter custom/USB path): ")
			customPath, _ := reader.ReadString('\n')
			savedPaths, err := SaveInstallerDiagnosticsBundle(customPath, cfg, eval, rawLines)
			if err != nil {
				statusBanner = fmt.Sprintf("%s[!] Failed to save diagnostics: %v%s", colorRed+colorBold, err, colorReset)
			} else {
				statusBanner = fmt.Sprintf("%s[✓] Saved diagnostics to: %s%s", colorEmerald+colorBold, strings.Join(savedPaths, ", "), colorReset)
			}
		case "X":
			fmt.Print("\n Ship logs to (https://url, syslog://host:514, or user@host:/path): ")
			dest, _ := reader.ReadString('\n')
			shippedTo, err := ShipInstallerDiagnosticsBundle(dest, cfg, eval, rawLines)
			if err != nil {
				statusBanner = fmt.Sprintf("%s[!] Log shipping failed: %v%s", colorRed+colorBold, err, colorReset)
			} else {
				statusBanner = fmt.Sprintf("%s[✓] Shipped diagnostics bundle via %s%s", colorEmerald+colorBold, shippedTo, colorReset)
			}
		case "C":
			_ = exec.Command("systemctl", "reset-failed").Run()
			suppressConsoleNoise()
			statusBanner = fmt.Sprintf("%s[✓] Cleared failed systemd unit states and refreshed console capture.%s", colorEmerald+colorBold, colorReset)
		case "R", "REDRAW":
			suppressConsoleNoise()
			statusBanner = fmt.Sprintf("%s[✓] Refreshed logs and console capture.%s", colorCyan+colorBold, colorReset)
		case "B", "ESC", "Q", "BACKSPACE":
			return
		}
	}
}

func renderInstallerBanner(cfg InstallerConfig, step int) {
	clearScreen()
	_, osName, kernel, _, _, memStr := getSystemInfo()
	fwMode := "Legacy BIOS"
	if hasUEFIFirmware() {
		fwMode = "UEFI"
	}
	tpmStr := colorDim + "Not Present" + colorReset
	if hasTPM2Device() {
		tpmStr = colorEmerald + colorBold + "TPM 2.0 Ready" + colorReset
	}

	title := "AXONWALL NEXT-GEN APPLIANCE INSTALLER"
	subtitle := "Enterprise Linux Next-Generation Firewall & SD-WAN Platform"
	accent := colorEmerald
	switch cfg.Edition {
	case "vault":
		title = "AXONWALL VAULT EDITION INSTALLER"
		subtitle = "Hardened Immutable S3 Object-Lock Backup Appliance (SeaweedFS)"
		accent = colorBrightCya
	case "k3s-storage":
		title = "K3S + ZFS STORAGE HOST INSTALLER"
		subtitle = "Barebones K3s + OpenZFS + OpenEBS ZFS-LocalPV Host (NGFW/UI bloat stripped)"
		accent = colorCyan
	}

	versionStr := "v0.11.41"
	if data, err := os.ReadFile("/etc/axonwall/version"); err == nil {
		v := strings.TrimSpace(string(data))
		if v != "" {
			versionStr = "v" + strings.TrimPrefix(v, "v")
		}
	}

	fmt.Printf("%s%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n", accent, colorBold, colorReset)
	fmt.Printf("%s%s║  🛡️  %-54s %15s  ║%s\n", accent, colorBold, title, versionStr, colorReset)
	fmt.Printf("%s%s║      %-70s  ║%s\n", colorCyan, colorBold, subtitle, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════════════════╝%s\n", accent, colorBold, colorReset)

	fmt.Printf(" %sOS:%s %-24s %sKernel:%s %-14s %sRAM:%s %s\n",
		colorDim, colorReset, osName,
		colorDim, colorReset, kernel,
		colorDim, colorReset, memStr)
	fmt.Printf(" %sBoot:%s %-22s %sSecurity:%s %-22s",
		colorDim, colorReset, fwMode,
		colorDim, colorReset, tpmStr)
	if ci := detectCloudInitSeed(); ci != "" {
		fmt.Printf(" %sCloud-Init:%s %sSeed Ready%s", colorDim, colorReset, colorGreen+colorBold, colorReset)
	}
	fmt.Println()

	fmt.Println("────────────────────────────────────────────────────────────────────────────────")
	if step == 0 {
		fmt.Printf(" %s%s[ ⚡ Express Hardware-Evaluated Setup ]%s  %s(Press [C] for Advanced Customization)%s\n",
			accent, colorBold, colorReset, colorDim, colorReset)
	} else {
		steps := []string{
			"1. Edition & Arch",
			"2. Disk Roles & RAID",
			"3. Storage & ZFS",
			"4. Security & Auth",
			"5. Review & Install",
		}
		fmt.Print(" ")
		for i, st := range steps {
			idx := i + 1
			if idx == step {
				fmt.Printf("%s%s[ %s ]%s", accent, colorBold, st, colorReset)
			} else if idx < step {
				fmt.Printf("%s✓ %s%s", colorGreen, st, colorReset)
			} else {
				fmt.Printf("%s  %s%s", colorDim, st, colorReset)
			}
			if i < len(steps)-1 {
				fmt.Printf(" %s──>%s ", colorDim, colorReset)
			}
		}
		fmt.Println()
	}
	fmt.Println("────────────────────────────────────────────────────────────────────────────────")
}

// RunNextGenInstallerTUI launches the interactive multi-step Axonwall Next-Gen Installer TUI.
func RunNextGenInstallerTUI(reader *bufio.Reader) {
	suppressConsoleNoise()
	installerPath := "/usr/local/bin/axonwall-install"
	if _, err := os.Stat(installerPath); err != nil {
		clearScreen()
		fmt.Printf("%s[!] Installer utility '%s' not found on this system.%s\n", colorRed, installerPath, colorReset)
		pause(reader)
		return
	}

	cfg := DefaultInstallerConfig()
	disks, eval := EvaluateHardwareProfile(DiscoverDisks(), &cfg)

	step := 0
	archCursor := 0
	diskCursor := 0
	zfsCursor := 0
	secCursor := 0

	for step >= 0 && step <= 5 {
		suppressConsoleNoise()
		switch step {
		case 0:
			renderInstallerBanner(cfg, 0)
			primaryMB := syncDiskRolesAndConfig(disks, &cfg)
			normalizeSlotMBForMode(&cfg, recommendedSlotGBForDiskMB(primaryMB), primaryMB)
			eval = RefreshHardwareEval(disks, &cfg)
			layout := ComputePartitionLayout(primaryMB, cfg)

			ngfwBadge := colorDim + "( ) Axonwall NGFW & Router" + colorReset
			vaultBadge := colorDim + "( ) Axonwall Vault S3" + colorReset
			k3sBadge := colorDim + "( ) K3s + ZFS Storage Host" + colorReset
			switch cfg.Edition {
			case "vault":
				vaultBadge = colorBrightCya + colorBold + "(●) Axonwall Vault S3" + colorReset
			case "k3s-storage":
				k3sBadge = colorCyan + colorBold + "(●) K3s + ZFS Storage Host" + colorReset
			default:
				ngfwBadge = colorEmerald + colorBold + "(●) Axonwall NGFW & Router" + colorReset
			}
			fmt.Printf(" %s[E] Edition:%s %s  %s  %s\n\n", colorBold, colorReset, ngfwBadge, vaultBadge, k3sBadge)

			fmt.Printf(" %sSelect Installation Architecture (Hardware-Evaluated):%s\n", colorBold, colorReset)
			archOptions := []struct {
				mode  string
				title string
				desc  string
			}{
				{
					mode:  "ab",
					title: "Dual-Root A/B Architecture (Recommended)",
					desc:  "Unbrickable dual OS slots (Slot A + Slot B) with watchdog rollback & persistent data",
				},
				{
					mode:  "zbm",
					title: "ZFSBootMenu Root-on-ZFS (All-in-ZFS zroot)",
					desc:  "Copy-on-write ZFS Boot Environments, atomic snapshots & pure ZFSBootMenu boot",
				},
				{
					mode:  "rolling",
					title: "Rolling Standard Linux (Single-Root)",
					desc:  "Single mutable root partition (axon_root) for compact VMs or standard APT workflow",
				},
			}
			for i, opt := range archOptions {
				selected := cfg.InstallMode == opt.mode
				cursor := "  "
				if i == archCursor {
					cursor = colorEmerald + colorBold + "➜ " + colorReset
				}
				radio := "( )"
				if selected {
					radio = colorEmerald + colorBold + "(●)" + colorReset
				}
				fmt.Printf(" %s%s %s[%d] %s%s\n", cursor, radio, colorBold, i+1, opt.title, colorReset)
				fmt.Printf("        %s%s%s\n", colorDim, opt.desc, colorReset)
			}

			pwSummary := colorYellow + "Factory Default (admin / axonwall — prompted on first web login)" + colorReset
			if cfg.AdminPassword != "" {
				pwSummary = colorEmerald + colorBold + "Custom Password Set (scrypt)" + colorReset
			}
			luksSummary := colorDim + "Disabled (Press [L] to enable LUKS2 AES-XTS-512)" + colorReset
			if cfg.LuksEnabled {
				if cfg.LuksTPM2 && eval.HasTPM2 {
					luksSummary = colorEmerald + colorBold + "Enabled (LUKS2 + Hardware TPM 2.0 Auto-Unlock)" + colorReset
				} else {
					luksSummary = colorEmerald + colorBold + "Enabled (LUKS2 Passphrase)" + colorReset
				}
			}

			fmt.Println("────────────────────────────────────────────────────────────────────────────────")
			fmt.Printf(" %sHardware Self-Evaluation & Recommended Profile:%s\n", colorBold, colorReset)
			if len(disks) == 0 {
				fmt.Printf("   %s[!] No unmounted target storage disks (>= 2 GB) detected. Press [R] to rescan.%s\n", colorRed+colorBold, colorReset)
			} else {
				fmt.Printf("   • %-22s : %s%s%s\n", "Target System Disk(s)", colorEmerald+colorBold, eval.SystemDiskSummary, colorReset)
				fmt.Printf("   • %-22s : %s%s%s\n", "OpenZFS Storage Pool", colorGreen+colorBold, eval.ZfsPoolSummary, colorReset)
				if cfg.KeepPartitions {
					fmt.Printf("   • %-22s : %sKeep Existing Pre-Partitioned Disk Layout [X]%s\n", "Partition Table [X]", colorYellow+colorBold, colorReset)
				} else {
					fmt.Printf("   • %-22s : %s%s%s\n", "Boot & Root Layout", colorCyan+colorBold, eval.SlotSizingNote, colorReset)
				}
				fmt.Printf("   • %-22s : %s%s%s\n", "Network Setup [Q->2/3]", colorCyan, formatPreInstallNetworkSummary(), colorReset)
				if cfg.Edition == "k3s-storage" {
					effArc := cfg.ZfsArcMaxMB
					if effArc <= 0 {
						effArc = ComputeDefaultZfsArcMaxMB(eval.TotalRAMMB)
					}
					roleDesc := "Standalone SQLite Server + OpenEBS ZFS-LocalPV"
					if cfg.K3sRole == "agent" {
						roleDesc = "Cluster Storage Worker Agent"
						if cfg.K3sServerURL != "" {
							roleDesc += " (" + cfg.K3sServerURL + ")"
						}
					}
					fmt.Printf("   • %-22s : %s%s | ARC Cap: %d MiB%s\n", "K3s Role & ARC [K]", colorCyan+colorBold, roleDesc, effArc, colorReset)
				}
				fmt.Printf("   • %-22s : %s\n", "Data Encryption [L]", luksSummary)
				fmt.Printf("   • %-22s : %s\n\n", "Admin Password  [P]", pwSummary)
				fmt.Println(RenderPartitionBar(layout, cfg, 64))
			}

			var allTargetDisks []string
			allTargetDisks = append(allTargetDisks, cfg.SystemDisks...)
			allTargetDisks = append(allTargetDisks, cfg.ZfsExtraDisks...)
			fmt.Println("────────────────────────────────────────────────────────────────────────────────")
			if len(allTargetDisks) > 0 {
				if cfg.KeepPartitions {
					fmt.Printf(" %sReady to install onto pre-partitioned [%s] (preserving existing partition table).%s\n",
						colorYellow, strings.Join(allTargetDisks, ", "), colorReset)
				} else {
					fmt.Printf(" %sReady to install onto [%s] (existing data on target disk(s) will be erased).%s\n",
						colorYellow, strings.Join(allTargetDisks, ", "), colorReset)
				}
			}
			if cfg.Edition == "k3s-storage" {
				fmt.Printf(" %sControls:%s %s[Enter / I] Express Install%s  [E] Ed  [K] K3s Role  [1-3/↑/↓] Arch  [P] Pass  [L] LUKS2  [C] Custom  %s[V] Logs%s  [Q] CLI\n",
					colorDim, colorReset, colorEmerald+colorBold, colorReset, colorCyan+colorBold, colorReset)
			} else {
				fmt.Printf(" %sControls:%s %s[Enter / I] Express Install%s  [E] Ed  [1-3/↑/↓] Arch  [P] Pass  [L] LUKS2  [X] KeepParts  [C] Custom  %s[V] Logs%s  [Q] CLI\n",
					colorDim, colorReset, colorEmerald+colorBold, colorReset, colorCyan+colorBold, colorReset)
			}

			key := readRawKey()
			switch key {
			case "UP":
				if archCursor > 0 {
					archCursor--
					cfg.InstallMode = archOptions[archCursor].mode
					normalizeSlotMBForMode(&cfg, recommendedSlotGBForDiskMB(primaryMB), primaryMB)
				}
			case "DOWN", "J":
				if archCursor < len(archOptions)-1 {
					archCursor++
					cfg.InstallMode = archOptions[archCursor].mode
					normalizeSlotMBForMode(&cfg, recommendedSlotGBForDiskMB(primaryMB), primaryMB)
				}
			case "1", "2", "3":
				idx, _ := strconv.Atoi(key)
				archCursor = idx - 1
				cfg.InstallMode = archOptions[archCursor].mode
				normalizeSlotMBForMode(&cfg, recommendedSlotGBForDiskMB(primaryMB), primaryMB)
			case "SPACE":
				cfg.InstallMode = archOptions[archCursor].mode
				normalizeSlotMBForMode(&cfg, recommendedSlotGBForDiskMB(primaryMB), primaryMB)
			case "E":
				cycleEdition(&cfg)
				disks, eval = EvaluateHardwareProfile(disks, &cfg)
			case "K":
				if cfg.Edition == "k3s-storage" {
					if cfg.K3sRole == "agent" {
						cfg.K3sRole = "server"
					} else {
						cfg.K3sRole = "agent"
						if cfg.K3sServerURL == "" {
							fmt.Print("\n Enter K3s Control-Plane URL (e.g. https://10.0.0.1:6443): ")
							urlLine, _ := reader.ReadString('\n')
							urlLine = strings.TrimSpace(urlLine)
							if urlLine != "" && !strings.ContainsAny(urlLine, " \t\n\r\"'") {
								cfg.K3sServerURL = urlLine
							}
							if tok, err := readPassword(reader, " Enter K3s Cluster Join Token (masked): "); err == nil && tok != "" {
								cfg.K3sJoinToken = tok
							}
						}
					}
				} else if archCursor > 0 {
					archCursor--
					cfg.InstallMode = archOptions[archCursor].mode
					normalizeSlotMBForMode(&cfg, recommendedSlotGBForDiskMB(primaryMB), primaryMB)
				}
			case "X":
				cfg.KeepPartitions = !cfg.KeepPartitions
			case "P":
				pw1, _ := readPassword(reader, "\n Enter new Administrator & Root password (min 8 chars, or empty for default): ")
				if pw1 == "" {
					cfg.AdminPassword = ""
				} else if len(pw1) < 8 {
					fmt.Printf(" %s[!] Password must be at least 8 characters.%s\n", colorRed, colorReset)
					time.Sleep(1200 * time.Millisecond)
				} else {
					pw2, _ := readPassword(reader, " Confirm new Administrator & Root password: ")
					if pw1 == pw2 {
						cfg.AdminPassword = pw1
					} else {
						fmt.Printf(" %s[!] Passwords did not match.%s\n", colorRed, colorReset)
						time.Sleep(1200 * time.Millisecond)
					}
				}
			case "L":
				cfg.LuksEnabled = !cfg.LuksEnabled
				if cfg.LuksEnabled && cfg.LuksPassphrase == "" {
					pw1, _ := readPassword(reader, "\n Enter LUKS2 encryption passphrase: ")
					if pw1 != "" {
						pw2, _ := readPassword(reader, " Confirm LUKS2 encryption passphrase: ")
						if pw1 == pw2 {
							cfg.LuksPassphrase = pw1
						} else {
							fmt.Printf(" %s[!] Passphrases did not match. Disabling LUKS2.%s\n", colorRed, colorReset)
							cfg.LuksEnabled = false
							time.Sleep(1200 * time.Millisecond)
						}
					} else {
						cfg.LuksEnabled = false
					}
				}
			case "R":
				disks, eval = EvaluateHardwareProfile(DiscoverDisks(), &cfg)
			case "V":
				runInstallerLogsScreen(cfg, eval, nil, reader)
			case "C":
				step = 1
			case "I", "ENTER":
				if len(cfg.SystemDisks) > 0 {
					executeLiveInstallation(cfg, eval, installerPath, reader)
					return
				}
			case "Q", "ESC":
				return
			}

		case 1:
			renderInstallerBanner(cfg, 1)
			primaryMB := syncDiskRolesAndConfig(disks, &cfg)
			normalizeSlotMBForMode(&cfg, recommendedSlotGBForDiskMB(primaryMB), primaryMB)
			ngfwBadge := colorDim + "( ) Axonwall NGFW & Router" + colorReset
			vaultBadge := colorDim + "( ) Axonwall Vault S3" + colorReset
			k3sBadge := colorDim + "( ) K3s + ZFS Storage Host" + colorReset
			editionDesc := "Full NGFW, SD-WAN, WireGuard/Headscale, IDS/IPS, BGP/OSPF, Web UI & Controller"
			switch cfg.Edition {
			case "vault":
				vaultBadge = colorBrightCya + colorBold + "(●) Axonwall Vault S3" + colorReset
				editionDesc = "Immutable S3 Object-Lock Backup Appliance (SeaweedFS; firewall stack stripped)"
			case "k3s-storage":
				k3sBadge = colorCyan + colorBold + "(●) K3s + ZFS Storage Host" + colorReset
				editionDesc = "Barebones K3s + OpenZFS + OpenEBS ZFS-LocalPV Host (NGFW/UI bloat stripped)"
			default:
				ngfwBadge = colorEmerald + colorBold + "(●) Axonwall NGFW & Router" + colorReset
			}
			fmt.Printf(" %s[E] Edition:%s %s  %s  %s\n", colorBold, colorReset, ngfwBadge, vaultBadge, k3sBadge)
			fmt.Printf("     %s%s%s\n", colorDim, editionDesc, colorReset)
			fmt.Println("────────────────────────────────────────────────────────────────────────────────")
			fmt.Printf(" %sSelect Appliance Storage & Boot Architecture:%s\n\n", colorBold, colorReset)

			archOptions := []struct {
				mode  string
				title string
				desc  string
			}{
				{
					mode:  "ab",
					title: "Dual-Root A/B Architecture (Recommended)",
					desc:  "Unbrickable dual OS slots (Slot A + Slot B) with hardware watchdog rollback & persistent /var/lib/axonwall",
				},
				{
					mode:  "zbm",
					title: "ZFSBootMenu Root-on-ZFS (All-in-ZFS zroot)",
					desc:  "Copy-on-write ZFS Boot Environments, atomic pre-upgrade snapshots & 100% OpenZFS root pool boot",
				},
				{
					mode:  "rolling",
					title: "Rolling Standard Linux (Single-Root)",
					desc:  "Single root partition (axon_root) for compact virtual machines or cloud hypervisors",
				},
			}

			for i, opt := range archOptions {
				selected := cfg.InstallMode == opt.mode
				cursor := "  "
				if i == archCursor {
					cursor = colorEmerald + colorBold + "➜ " + colorReset
				}
				radio := "( )"
				if selected {
					radio = colorEmerald + colorBold + "(●)" + colorReset
				}
				fmt.Printf(" %s%s %s[%d] %s%s\n", cursor, radio, colorBold, i+1, opt.title, colorReset)
				fmt.Printf("        %s%s%s\n\n", colorDim, opt.desc, colorReset)
			}

			slotGB := cfg.SlotMB / 1024
			fmt.Println("────────────────────────────────────────────────────────────────────────────────")
			if cfg.InstallMode == "zbm" {
				fmt.Printf(" %sFilesystem Architecture:%s %s100%% OpenZFS (zroot Boot Environments + Datasets, lz4)%s\n",
					colorBold, colorReset, colorEmerald+colorBold, colorReset)
			} else {
				fmt.Printf(" %s[S] Root Slot Size:%s %s%d GB%s    %s[F] Root/Data Filesystem:%s %s%s%s\n",
					colorBold, colorReset, colorCyan+colorBold, slotGB, colorReset,
					colorBold, colorReset, colorCyan+colorBold, strings.ToUpper(cfg.RootFSType), colorReset)
			}
			fmt.Println("────────────────────────────────────────────────────────────────────────────────")
			if cfg.InstallMode == "zbm" {
				fmt.Printf(" %sControls:%s [E] Edition  [↑/↓] Move  [Space/1-3] Arch  [V] Logs  [B] Express  [Enter] Next  [Q] Cancel\n", colorDim, colorReset)
			} else {
				fmt.Printf(" %sControls:%s [E] Edition  [↑/↓] Move  [Space/1-3] Arch  [S] Slot Size  [F] ext4/xfs  [V] Logs  [B] Express  [Enter] Next\n", colorDim, colorReset)
			}

			key := readRawKey()
			switch key {
			case "V":
				runInstallerLogsScreen(cfg, eval, nil, reader)
			case "E":
				cycleEdition(&cfg)
				disks, eval = EvaluateHardwareProfile(disks, &cfg)
			case "UP", "K":
				if archCursor > 0 {
					archCursor--
				}
			case "DOWN", "J":
				if archCursor < len(archOptions)-1 {
					archCursor++
				}
			case "1", "2", "3":
				idx, _ := strconv.Atoi(key)
				archCursor = idx - 1
				cfg.InstallMode = archOptions[archCursor].mode
				normalizeSlotMBForMode(&cfg, recommendedSlotGBForDiskMB(primaryMB), primaryMB)
			case "SPACE":
				cfg.InstallMode = archOptions[archCursor].mode
				normalizeSlotMBForMode(&cfg, recommendedSlotGBForDiskMB(primaryMB), primaryMB)
			case "S":
				if cfg.InstallMode == "rolling" {
					if cfg.Edition == "k3s-storage" && primaryMB < 32768 {
						switch cfg.SlotMB {
						case 4096:
							cfg.SlotMB = 8192
						case 8192:
							cfg.SlotMB = 16384
						default:
							cfg.SlotMB = 4096
						}
					} else if cfg.SlotMB == 8192 {
						cfg.SlotMB = 16384
					} else {
						cfg.SlotMB = 8192
					}
				} else if cfg.InstallMode != "zbm" {
					switch cfg.SlotMB {
					case 2048:
						cfg.SlotMB = 4096
					case 4096:
						cfg.SlotMB = 8192
					case 8192:
						cfg.SlotMB = 16384
					default:
						cfg.SlotMB = 2048
					}
				}
			case "F":
				if cfg.InstallMode != "zbm" {
					if cfg.RootFSType == "ext4" {
						cfg.RootFSType = "xfs"
						cfg.DataFSType = "xfs"
					} else {
						cfg.RootFSType = "ext4"
						cfg.DataFSType = "ext4"
					}
				}
			case "B", "BACKSPACE", "LEFT":
				step = 0
			case "ENTER", "RIGHT":
				cfg.InstallMode = archOptions[archCursor].mode
				normalizeSlotMBForMode(&cfg, recommendedSlotGBForDiskMB(primaryMB), primaryMB)
				step = 2
			case "Q", "ESC":
				return
			}

		case 2:
			renderInstallerBanner(cfg, 2)
			primaryMB := syncDiskRolesAndConfig(disks, &cfg)

			fmt.Printf(" %sAssign Storage Disk Roles (System Boot, Dedicated ZFS Pool, SLOG & L2ARC):%s\n", colorBold, colorReset)
			fmt.Printf(" %sExample: Assign 2x 32GB disks as [OS SYSTEM] RAID-1, 2x 1TB disks as [ZFS DATA], plus optional [ZFS SLOG] & [ZFS L2ARC].%s\n\n", colorDim, colorReset)

			if len(disks) == 0 {
				fmt.Printf(" %s[!] No unmounted target storage disks (>= 2 GB) detected.%s\n", colorRed+colorBold, colorReset)
				fmt.Printf("     Press [R] to rescan block devices, [W] for Shell Wizard, or [B] to go back.\n")
			} else {
				for i, d := range disks {
					cursor := "  "
					if i == diskCursor {
						cursor = colorEmerald + colorBold + "➜ " + colorReset
					}
					badge := formatDiskRoleBadge(d)
					remTag := ""
					if d.Removable {
						remTag = colorYellow + " [Removable]" + colorReset
					}
					fmt.Printf(" %s%s  %s%-12s%s  %8.1f GB  %-8s  %s%s\n",
						cursor, badge, colorBold, d.Path, colorReset, d.SizeGB, d.Transport, d.Model, remTag)
				}
			}

			raidSummary := colorYellow + "None selected (assign at least 1 disk as [OS SYSTEM])" + colorReset
			if len(cfg.SystemDisks) == 1 {
				if cfg.InstallMode == "zbm" {
					raidSummary = fmt.Sprintf("%sSingle-Disk ZFS Root Pool zroot (%s)%s", colorCyan+colorBold, cfg.SystemDisks[0], colorReset)
				} else {
					raidSummary = fmt.Sprintf("%sSingle System Disk (%s)%s", colorCyan+colorBold, cfg.SystemDisks[0], colorReset)
				}
			} else if len(cfg.SystemDisks) >= 2 {
				if cfg.InstallMode == "zbm" {
					raidSummary = fmt.Sprintf("%sMirrored ZFS Root Pool zroot across %d disks (%s)%s", colorEmerald+colorBold, len(cfg.SystemDisks), strings.Join(cfg.SystemDisks, ", "), colorReset)
				} else {
					raidSummary = fmt.Sprintf("%smdadm RAID-1 System Mirror across %d disks (%s)%s", colorEmerald+colorBold, len(cfg.SystemDisks), strings.Join(cfg.SystemDisks, ", "), colorReset)
				}
			}

			zfsDataSummary := colorDim + "No dedicated data disks (uses System Disk ZFS partition if enabled)" + colorReset
			if len(cfg.ZfsExtraDisks) > 0 {
				zfsDataSummary = fmt.Sprintf("%s%d Dedicated Data VDEV(s) for pool 'tank' (%s)%s",
					colorGreen+colorBold, len(cfg.ZfsExtraDisks), strings.Join(cfg.ZfsExtraDisks, ", "), colorReset)
			}

			slogStr := "None"
			if len(cfg.ZfsSlogDisks) == 1 {
				slogStr = cfg.ZfsSlogDisks[0]
			} else if len(cfg.ZfsSlogDisks) >= 2 {
				slogStr = "Mirror(" + strings.Join(cfg.ZfsSlogDisks, ",") + ")"
			}
			l2arcStr := "None"
			if len(cfg.ZfsL2arcDisks) > 0 {
				l2arcStr = strings.Join(cfg.ZfsL2arcDisks, ",")
			}
			spareStr := "None"
			if len(cfg.ZfsSpareDisks) > 0 {
				spareStr = strings.Join(cfg.ZfsSpareDisks, ",")
			}

			fmt.Println("\n────────────────────────────────────────────────────────────────────────────────")
			fmt.Printf(" %sSystem Boot OS :%s %s\n", colorBold, colorReset, raidSummary)
			fmt.Printf(" %sZFS Data Pool  :%s %s\n", colorBold, colorReset, zfsDataSummary)
			fmt.Printf(" %sZFS Accel/Spare:%s %sSLOG (ZIL):%s %-16s %sL2ARC (Cache):%s %-16s %sSpare:%s %s\n",
				colorBold, colorReset,
				colorYellow+colorBold, colorReset, slogStr,
				colorBrightCya+colorBold, colorReset, l2arcStr,
				colorMagenta+colorBold, colorReset, spareStr)
			if len(cfg.SystemDisks) > 0 {
				layout := ComputePartitionLayout(primaryMB, cfg)
				fmt.Println(RenderPartitionBar(layout, cfg, 64))
			}
			fmt.Println("────────────────────────────────────────────────────────────────────────────────")
			fmt.Printf(" %sRole Keys:%s [Space] Cycle Role  [S] System OS  [D] ZFS Data  [G] ZFS SLOG  [C] ZFS L2ARC  [H] Hot Spare  [U] Unused\n", colorDim, colorReset)
			fmt.Printf(" %sNavigation:%s [↑/↓] Move  [A] Auto-Tier  [X] Keep Existing Partitions (%v)  [R] Rescan  [V] Logs  [B] Back  [Enter] Next\n", colorDim, colorReset, cfg.KeepPartitions)

			key := readRawKey()
			switch key {
			case "V":
				runInstallerLogsScreen(cfg, eval, nil, reader)
			case "X":
				cfg.KeepPartitions = !cfg.KeepPartitions
			case "UP", "K":
				if diskCursor > 0 {
					diskCursor--
				}
			case "DOWN", "J":
				if diskCursor < len(disks)-1 {
					diskCursor++
				}
			case "SPACE":
				if len(disks) > 0 && diskCursor < len(disks) {
					cycleDiskRole(&disks[diskCursor])
				}
			case "S":
				if len(disks) > 0 && diskCursor < len(disks) {
					if disks[diskCursor].Role == "system" {
						setDiskRole(&disks[diskCursor], "none")
					} else {
						setDiskRole(&disks[diskCursor], "system")
					}
				}
			case "D":
				if len(disks) > 0 && diskCursor < len(disks) {
					if disks[diskCursor].Role == "zfs-data" {
						setDiskRole(&disks[diskCursor], "none")
					} else {
						setDiskRole(&disks[diskCursor], "zfs-data")
					}
				}
			case "G":
				if len(disks) > 0 && diskCursor < len(disks) {
					if disks[diskCursor].Role == "zfs-slog" {
						setDiskRole(&disks[diskCursor], "none")
					} else {
						setDiskRole(&disks[diskCursor], "zfs-slog")
					}
				}
			case "C":
				if len(disks) > 0 && diskCursor < len(disks) {
					if disks[diskCursor].Role == "zfs-l2arc" {
						setDiskRole(&disks[diskCursor], "none")
					} else {
						setDiskRole(&disks[diskCursor], "zfs-l2arc")
					}
				}
			case "H":
				if len(disks) > 0 && diskCursor < len(disks) {
					if disks[diskCursor].Role == "zfs-spare" {
						setDiskRole(&disks[diskCursor], "none")
					} else {
						setDiskRole(&disks[diskCursor], "zfs-spare")
					}
				}
			case "U":
				if len(disks) > 0 && diskCursor < len(disks) {
					setDiskRole(&disks[diskCursor], "none")
				}
			case "A":
				disks = AutoAssignDiskRoles(disks)
				// If all disks are homogeneous and user pressed [A], mirror first 2 as system and rest as zfs-data
				sysCount := 0
				dataCount := 0
				for _, d := range disks {
					if d.Role == "system" {
						sysCount++
					} else if d.Role == "zfs-data" {
						dataCount++
					}
				}
				if sysCount == 1 && dataCount == 0 && len(disks) >= 2 {
					setDiskRole(&disks[0], "system")
					setDiskRole(&disks[1], "system")
					for i := 2; i < len(disks); i++ {
						setDiskRole(&disks[i], "zfs-data")
					}
				}
			case "1", "2", "3", "4", "5", "6", "7", "8", "9":
				idx, _ := strconv.Atoi(key)
				if idx >= 1 && idx <= len(disks) {
					diskCursor = idx - 1
					cycleDiskRole(&disks[diskCursor])
				}
			case "R":
				disks = AutoAssignDiskRoles(DiscoverDisks())
				diskCursor = 0
			case "W":
				clearScreen()
				cmd := exec.Command("/bin/sh", installerPath, "--shell-wizard")
				cmd.Stdin = os.Stdin
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				_ = cmd.Run()
				pause(reader)
				return
			case "B", "BACKSPACE", "LEFT":
				step = 1
			case "ENTER", "RIGHT":
				syncDiskRolesAndConfig(disks, &cfg)
				if len(cfg.SystemDisks) > 0 {
					// If dedicated ZFS Data disks are assigned in A/B or Rolling mode, default System Disk to 100% OS & System Data
					if len(cfg.ZfsExtraDisks) > 0 && cfg.InstallMode != "zbm" {
						cfg.ZfsAllocMode = "none"
						zfsCursor = 3
					}
					step = 3
				}
			case "Q", "ESC":
				return
			}

		case 3:
			renderInstallerBanner(cfg, 3)
			primaryMB := syncDiskRolesAndConfig(disks, &cfg)
			layout := ComputePartitionLayout(primaryMB, cfg)

			logsStatus := colorDim + "Disabled (Unified on Root)" + colorReset
			if cfg.LogsEnabled {
				logsStatus = fmt.Sprintf("%sEnabled (%d GB %s axon_logs)%s", colorYellow+colorBold, cfg.LogsGB, strings.ToUpper(cfg.LogsFSType), colorReset)
			}

			slogDesc := colorDim + "None (Internal Pool ZIL)" + colorReset
			if len(cfg.ZfsSlogDisks) == 1 {
				slogDesc = fmt.Sprintf("%sDedicated SLOG Device (%s)%s", colorYellow+colorBold, cfg.ZfsSlogDisks[0], colorReset)
			} else if len(cfg.ZfsSlogDisks) >= 2 {
				slogDesc = fmt.Sprintf("%sMirrored SLOG VDEV (%s)%s", colorYellow+colorBold, strings.Join(cfg.ZfsSlogDisks, ", "), colorReset)
			}

			l2arcDesc := colorDim + "None (RAM ARC Only)" + colorReset
			if len(cfg.ZfsL2arcDisks) > 0 {
				l2arcDesc = fmt.Sprintf("%sDedicated L2ARC Cache (%s)%s", colorBrightCya+colorBold, strings.Join(cfg.ZfsL2arcDisks, ", "), colorReset)
			}

			spareDesc := colorDim + "None" + colorReset
			if len(cfg.ZfsSpareDisks) > 0 {
				spareDesc = fmt.Sprintf("%sHot Spare (%s)%s", colorMagenta+colorBold, strings.Join(cfg.ZfsSpareDisks, ", "), colorReset)
			}

			if cfg.InstallMode == "zbm" {
				// All-in-ZFS (ZFSBootMenu Root-on-ZFS) — no ext4/ZFS split prompts needed!
				fmt.Printf(" %sAll-in-ZFS Storage Architecture (ZFSBootMenu Root-on-ZFS):%s\n\n", colorBold, colorReset)
				fmt.Println(RenderPartitionBar(layout, cfg, 64))
				fmt.Println()

				zrootTopo := "Single-Disk VDEV"
				if len(cfg.SystemDisks) >= 2 {
					zrootTopo = fmt.Sprintf("RAID-1 Mirror (%d System Disks)", len(cfg.SystemDisks))
				}
				fmt.Printf(" %s%s[●] System Root Pool (zroot):%s 100%% of remaining space on [%s] (%s)\n",
					colorEmerald, colorBold, colorReset, strings.Join(cfg.SystemDisks, ", "), zrootTopo)
				fmt.Printf("     %sDatasets: zroot/ROOT/axonwall (Boot Environment) + zroot/var/lib/axonwall (lz4)%s\n\n", colorDim, colorReset)

				if len(cfg.ZfsExtraDisks) > 0 {
					fmt.Printf(" %s%s[●] Dedicated Storage Pool (tank):%s %d Whole-Disk Data VDEV(s) [%s] mounted at /mnt/tank\n",
						colorGreen, colorBold, colorReset, len(cfg.ZfsExtraDisks), strings.Join(cfg.ZfsExtraDisks, ", "))
					fmt.Printf("     %sDatasets: tank/axonwall, tank/backups, tank/pcap, tank/logs (Topology: %s)%s\n",
						colorDim, strings.ToUpper(cfg.ZfsTopology), colorReset)
				} else {
					fmt.Printf(" %s[i] Dedicated Storage Pool (tank):%s None — all datasets reside inside unified 'zroot' pool.\n",
						colorCyan+colorBold, colorReset)
					fmt.Printf("     %sTip: Press [D] to assign dedicated [ZFS DATA], [ZFS SLOG], or [ZFS L2ARC] disks in Step 2.%s\n",
						colorDim, colorReset)
				}

				fmt.Println("────────────────────────────────────────────────────────────────────────────────")
				fmt.Printf(" %s[T] OpenZFS Pool Topology   :%s %s%s%s\n", colorBold, colorReset, colorCyan+colorBold, strings.ToUpper(cfg.ZfsTopology), colorReset)
				fmt.Printf(" %s[L] Dedicated /var/log Part :%s %s\n", colorBold, colorReset, logsStatus)
				fmt.Printf(" %s    SLOG (Separate ZIL Log) :%s %s\n", colorBold, colorReset, slogDesc)
				fmt.Printf(" %s    L2ARC (Read Cache)      :%s %s\n", colorBold, colorReset, l2arcDesc)
				fmt.Printf(" %s    Hot Spare Devices       :%s %s\n", colorBold, colorReset, spareDesc)
				fmt.Println("────────────────────────────────────────────────────────────────────────────────")
				fmt.Printf(" %sControls:%s [T] Cycle Topology  [L] Toggle /var/log  [D] Edit Disk Roles  [V] Logs  [B] Back  [Enter] Next\n", colorDim, colorReset)

				key := readRawKey()
				switch key {
				case "V":
					runInstallerLogsScreen(cfg, eval, nil, reader)
				case "L":
					cfg.LogsEnabled = !cfg.LogsEnabled
				case "T":
					topos := []string{"auto", "mirror", "raidz1", "raidz2", "raidz3", "stripe"}
					for i, t := range topos {
						if cfg.ZfsTopology == t {
							cfg.ZfsTopology = topos[(i+1)%len(topos)]
							break
						}
					}
				case "D", "B", "BACKSPACE", "LEFT":
					step = 2
				case "ENTER", "RIGHT":
					step = 4
				case "Q", "ESC":
					return
				}
			} else {
				// Dual-Root A/B or Rolling Single-Root
				fmt.Printf(" %sConfigure System Disk Partition Layout & OpenZFS Pool (tank):%s\n\n", colorBold, colorReset)
				fmt.Println(RenderPartitionBar(layout, cfg, 64))
				fmt.Println()

				noneTitle := "No OpenZFS Partition on System Disk (100% OS & System Data)"
				if len(cfg.ZfsExtraDisks) > 0 {
					noneTitle = fmt.Sprintf("Dedicated ZFS Disks Only — Keep System Disk 100%% OS & Data (Pool 'tank' on %s)", strings.Join(cfg.ZfsExtraDisks, ", "))
				}

				remDataGB := 8
				if cfg.Edition == "k3s-storage" {
					remDataGB = 4
				}
				zfsModes := []struct {
					mode  string
					title string
				}{
					{"remainder", fmt.Sprintf("Reserve Remaining System Disk Space for OpenZFS (%d GB System Data + Remainder ZFS)", remDataGB)},
					{"split", "Split Remaining System Disk Space 50/50 between System Data & OpenZFS"},
					{"custom", fmt.Sprintf("Custom OpenZFS Partition Size on System Disk (%d GB)", cfg.CustomZfsGB)},
					{"none", noneTitle},
				}

				for i, zm := range zfsModes {
					cursor := "  "
					if i == zfsCursor {
						cursor = colorEmerald + colorBold + "➜ " + colorReset
					}
					radio := "( )"
					if cfg.ZfsAllocMode == zm.mode {
						radio = colorEmerald + colorBold + "(●)" + colorReset
					}
					fmt.Printf(" %s%s [%d] %s\n", cursor, radio, i+1, zm.title)
				}

				var dataVdevParts []string
				if layout.ZfsMB > 0 {
					dataVdevParts = append(dataVdevParts, fmt.Sprintf("System Disk ZFS Partition (%d GB)", layout.ZfsMB/1024))
				}
				if len(cfg.ZfsExtraDisks) > 0 {
					dataVdevParts = append(dataVdevParts, fmt.Sprintf("Dedicated Disks [%s]", strings.Join(cfg.ZfsExtraDisks, ", ")))
				}
				dataVdevSummary := colorDim + "Disabled (No ZFS Data VDEVs selected)" + colorReset
				if len(dataVdevParts) > 0 {
					dataVdevSummary = colorGreen + colorBold + strings.Join(dataVdevParts, " + ") + colorReset
				}

				fmt.Println("────────────────────────────────────────────────────────────────────────────────")
				fmt.Printf(" %sOpenZFS Pool 'tank' Data VDEVs:%s %s\n", colorBold, colorReset, dataVdevSummary)
				fmt.Printf(" %s[T] OpenZFS Pool Topology     :%s %s%s%s\n", colorBold, colorReset, colorCyan+colorBold, strings.ToUpper(cfg.ZfsTopology), colorReset)
				fmt.Printf(" %s[L] Dedicated /var/log Part   :%s %s\n", colorBold, colorReset, logsStatus)
				fmt.Printf(" %s    SLOG (Separate ZIL Log)   :%s %s\n", colorBold, colorReset, slogDesc)
				fmt.Printf(" %s    L2ARC (Read Cache)        :%s %s\n", colorBold, colorReset, l2arcDesc)
				fmt.Printf(" %s    Hot Spare Devices         :%s %s\n", colorBold, colorReset, spareDesc)
				fmt.Println("────────────────────────────────────────────────────────────────────────────────")
				fmt.Printf(" %sControls:%s [↑/↓] Move  [Space/1-4] Select  [C] Custom GB  [T] Topology  [L] /var/log  [V] Logs  [B] Back  [Enter] Next\n", colorDim, colorReset)

				key := readRawKey()
				switch key {
				case "V":
					runInstallerLogsScreen(cfg, eval, nil, reader)
				case "UP", "K":
					if zfsCursor > 0 {
						zfsCursor--
					}
				case "DOWN", "J":
					if zfsCursor < len(zfsModes)-1 {
						zfsCursor++
					}
				case "1", "2", "3", "4":
					idx, _ := strconv.Atoi(key)
					zfsCursor = idx - 1
					cfg.ZfsAllocMode = zfsModes[zfsCursor].mode
				case "SPACE":
					cfg.ZfsAllocMode = zfsModes[zfsCursor].mode
				case "C":
					cfg.ZfsAllocMode = "custom"
					zfsCursor = 2
					fmt.Print("\n Enter custom OpenZFS size in GB [16]: ")
					line, _ := reader.ReadString('\n')
					if val, err := strconv.Atoi(strings.TrimSpace(line)); err == nil && val >= 1 {
						cfg.CustomZfsGB = val
					}
				case "L":
					cfg.LogsEnabled = !cfg.LogsEnabled
				case "T":
					topos := []string{"auto", "mirror", "raidz1", "raidz2", "raidz3", "stripe"}
					for i, t := range topos {
						if cfg.ZfsTopology == t {
							cfg.ZfsTopology = topos[(i+1)%len(topos)]
							break
						}
					}
				case "D", "B", "BACKSPACE", "LEFT":
					step = 2
				case "ENTER", "RIGHT":
					step = 4
				case "Q", "ESC":
					return
				}
			}

		case 4:
			renderInstallerBanner(cfg, 4)
			fmt.Printf(" %sConfigure Cryptographic Security & Appliance Identity:%s\n\n", colorBold, colorReset)

			luksBadge := colorDim + "[ ] Disabled (Standard Unencrypted Persistent Data)" + colorReset
			if cfg.LuksEnabled {
				luksBadge = colorEmerald + colorBold + "[✓] Enabled — LUKS2 AES-XTS-512 on /var/lib/axonwall (axon_data)" + colorReset
			}

			tpmBadge := colorDim + "[ ] Disabled (Passphrase prompt on console at boot)" + colorReset
			if cfg.LuksTPM2 {
				if hasTPM2Device() {
					tpmBadge = colorEmerald + colorBold + "[✓] Enabled — Hardware TPM 2.0 (PCRs 0+2+7) Automatic Unlock" + colorReset
				} else {
					tpmBadge = colorYellow + "[✓] Requested (Warning: No /dev/tpmrm0 detected on host)" + colorReset
				}
			}

			pwStatus := colorYellow + "Default (admin / axonwall — forced change on first web login)" + colorReset
			if cfg.AdminPassword != "" {
				pwStatus = colorEmerald + colorBold + "Custom Administrator Password Configured (scrypt)" + colorReset
			}

			type secMenuItem struct {
				title string
				val   string
			}
			secItems := []secMenuItem{
				{"[1] LUKS2 Persistent Data Encryption", luksBadge},
				{"[2] Hardware TPM 2.0 PCR Binding", tpmBadge},
				{"[3] Appliance Hostname", colorCyan + colorBold + cfg.Hostname + colorReset},
				{"[4] Administrator & Root Password", pwStatus},
			}
			if cfg.Edition == "k3s-storage" {
				roleBadge := colorEmerald + colorBold + "server (Standalone SQLite + OpenEBS ZFS-LocalPV)" + colorReset
				if cfg.K3sRole == "agent" {
					roleBadge = colorBrightCya + colorBold + "agent (Cluster Storage Worker Node)" + colorReset
				}
				srvURLBadge := colorDim + "(none — standalone server)" + colorReset
				if cfg.K3sServerURL != "" {
					srvURLBadge = colorCyan + colorBold + cfg.K3sServerURL + colorReset
				}
				tokBadge := colorDim + "(not set — auto-generated on server)" + colorReset
				if cfg.K3sJoinToken != "" {
					tokBadge = colorEmerald + colorBold + "Configured [REDACTED]" + colorReset
				}
				autoArc := ComputeDefaultZfsArcMaxMB(eval.TotalRAMMB)
				arcBadge := fmt.Sprintf("%sAuto (%d MiB)%s", colorCyan+colorBold, autoArc, colorReset)
				if cfg.ZfsArcMaxMB > 0 {
					arcBadge = fmt.Sprintf("%s%d MiB (Custom)%s", colorEmerald+colorBold, cfg.ZfsArcMaxMB, colorReset)
				}
				secItems = append(secItems,
					secMenuItem{"[5] K3s Node Role", roleBadge},
					secMenuItem{"[6] K3s Control-Plane URL", srvURLBadge},
					secMenuItem{"[7] K3s Cluster Join Token", tokBadge},
					secMenuItem{"[8] ZFS ARC Memory Cap", arcBadge},
				)
			}
			if secCursor >= len(secItems) {
				secCursor = len(secItems) - 1
			}

			spacing := "\n"
			if len(secItems) > 4 {
				spacing = ""
			}
			for i, item := range secItems {
				cursor := "  "
				if i == secCursor {
					cursor = colorEmerald + colorBold + "➜ " + colorReset
				}
				fmt.Printf(" %s%-38s : %s\n%s", cursor, colorBold+item.title+colorReset, item.val, spacing)
			}

			fmt.Println("────────────────────────────────────────────────────────────────────────────────")
			maxKeyHint := "1-4"
			if len(secItems) > 4 {
				maxKeyHint = "1-8"
			}
			fmt.Printf(" %sControls:%s [↑/↓] Move  [Space/%s] Toggle/Edit  [V] Logs & Diagnostics  [B] Back  [Enter] Review & Install\n", colorDim, colorReset, maxKeyHint)

			key := readRawKey()
			switch key {
			case "V":
				runInstallerLogsScreen(cfg, eval, nil, reader)
			case "UP", "K":
				if secCursor > 0 {
					secCursor--
				}
			case "DOWN", "J":
				if secCursor < len(secItems)-1 {
					secCursor++
				}
			case "1", "2", "3", "4", "5", "6", "7", "8", "SPACE":
				if key != "SPACE" {
					idx, _ := strconv.Atoi(key)
					if idx < 1 || idx > len(secItems) {
						continue
					}
					secCursor = idx - 1
				}
				switch secCursor {
				case 0:
					cfg.LuksEnabled = !cfg.LuksEnabled
					if cfg.LuksEnabled && cfg.LuksPassphrase == "" {
						pw1, _ := readPassword(reader, "\n Enter LUKS2 encryption passphrase: ")
						if pw1 != "" {
							pw2, _ := readPassword(reader, " Confirm LUKS2 encryption passphrase: ")
							if pw1 == pw2 {
								cfg.LuksPassphrase = pw1
							} else {
								fmt.Printf(" %s[!] Passphrases did not match. Disabling LUKS2.%s\n", colorRed, colorReset)
								cfg.LuksEnabled = false
								time.Sleep(1200 * time.Millisecond)
							}
						} else {
							cfg.LuksEnabled = false
						}
					}
				case 1:
					cfg.LuksTPM2 = !cfg.LuksTPM2
				case 2:
					fmt.Printf("\n Enter Appliance Hostname [%s]: ", cfg.Hostname)
					line, _ := reader.ReadString('\n')
					line = strings.TrimSpace(line)
					if line != "" && !strings.ContainsAny(line, " \t/\\;\"'") {
						cfg.Hostname = line
					}
				case 3:
					pw1, _ := readPassword(reader, "\n Enter new Administrator & Root password (min 8 chars, or empty for default): ")
					if pw1 == "" {
						cfg.AdminPassword = ""
					} else if len(pw1) < 8 {
						fmt.Printf(" %s[!] Password must be at least 8 characters.%s\n", colorRed, colorReset)
						time.Sleep(1200 * time.Millisecond)
					} else {
						pw2, _ := readPassword(reader, " Confirm new Administrator & Root password: ")
						if pw1 == pw2 {
							cfg.AdminPassword = pw1
						} else {
							fmt.Printf(" %s[!] Passwords did not match.%s\n", colorRed, colorReset)
							time.Sleep(1200 * time.Millisecond)
						}
					}
				case 4:
					if cfg.K3sRole == "agent" {
						cfg.K3sRole = "server"
					} else {
						cfg.K3sRole = "agent"
					}
				case 5:
					fmt.Printf("\n Enter K3s Control-Plane URL (e.g. https://10.0.0.1:6443, empty to clear) [%s]: ", cfg.K3sServerURL)
					line, _ := reader.ReadString('\n')
					line = strings.TrimSpace(line)
					if line == "" {
						cfg.K3sServerURL = ""
					} else if !strings.ContainsAny(line, " \t\n\r\"'") {
						cfg.K3sServerURL = line
					}
				case 6:
					tok, _ := readPassword(reader, "\n Enter K3s Cluster Join Token (empty to clear): ")
					cfg.K3sJoinToken = tok
				case 7:
					autoArc := ComputeDefaultZfsArcMaxMB(eval.TotalRAMMB)
					fmt.Printf("\n Enter OpenZFS ARC Memory Cap in MiB (0 for Auto = %d MiB) [%d]: ", autoArc, cfg.ZfsArcMaxMB)
					line, _ := reader.ReadString('\n')
					line = strings.TrimSpace(line)
					if line != "" {
						if val, err := strconv.Atoi(line); err == nil && val >= 0 {
							cfg.ZfsArcMaxMB = val
						}
					}
				}
			case "B", "BACKSPACE", "LEFT":
				step = 3
			case "ENTER", "RIGHT":
				step = 5
			case "Q", "ESC":
				return
			}

		case 5:
			renderInstallerBanner(cfg, 5)
			primaryMB := syncDiskRolesAndConfig(disks, &cfg)
			layout := ComputePartitionLayout(primaryMB, cfg)

			raidMode := "Single Disk"
			if len(cfg.SystemDisks) >= 2 {
				raidMode = fmt.Sprintf("RAID-1 Mirror (%d Disks)", len(cfg.SystemDisks))
			}

			luksSummary := "Disabled"
			if cfg.LuksEnabled {
				if cfg.LuksTPM2 {
					luksSummary = "LUKS2 AES-XTS-512 + Hardware TPM 2.0 (PCRs 0+2+7)"
				} else {
					luksSummary = "LUKS2 AES-XTS-512 (Passphrase)"
				}
			}

			archSummary := fmt.Sprintf("%s (Slot=%d GB, FS=%s)", strings.ToUpper(cfg.InstallMode), cfg.SlotMB/1024, cfg.RootFSType)
			if cfg.InstallMode == "zbm" {
				archSummary = "ZBM All-in-ZFS Root (zroot Boot Environments, lz4)"
			}

			zfsSummary := fmt.Sprintf("SysAlloc=%s, Topology=%s, DataDisks=%v", cfg.ZfsAllocMode, strings.ToUpper(cfg.ZfsTopology), cfg.ZfsExtraDisks)
			if cfg.InstallMode == "zbm" {
				if len(cfg.ZfsExtraDisks) > 0 {
					zfsSummary = fmt.Sprintf("zroot on System Disks + Dedicated 'tank' (%s) on %v", strings.ToUpper(cfg.ZfsTopology), cfg.ZfsExtraDisks)
				} else {
					zfsSummary = fmt.Sprintf("Unified 'zroot' Pool (100%% System Disks, Topology=%s)", strings.ToUpper(cfg.ZfsTopology))
				}
			}

			fmt.Printf(" %sInstallation Summary — Ready to Image Target Storage:%s\n\n", colorBold, colorReset)
			fmt.Printf("   • %-24s : %s%s (%s)%s\n", "Appliance Edition", colorEmerald+colorBold, strings.ToUpper(cfg.Edition), cfg.OSFamily, colorReset)
			fmt.Printf("   • %-24s : %s%s%s\n", "Architecture", colorCyan+colorBold, archSummary, colorReset)
			fmt.Printf("   • %-24s : %s%s — %s%s\n", "System OS Disk(s)", colorBold, raidMode, strings.Join(cfg.SystemDisks, ", "), colorReset)
			fmt.Printf("   • %-24s : %s%s%s\n", "OpenZFS Storage Pool", colorGreen+colorBold, zfsSummary, colorReset)
			if len(cfg.ZfsSlogDisks) > 0 || len(cfg.ZfsL2arcDisks) > 0 || len(cfg.ZfsSpareDisks) > 0 {
				fmt.Printf("   • %-24s : %sSLOG=%v  L2ARC=%v  Spare=%v%s\n", "OpenZFS Accelerators", colorYellow+colorBold, cfg.ZfsSlogDisks, cfg.ZfsL2arcDisks, cfg.ZfsSpareDisks, colorReset)
			}
			if cfg.Edition == "k3s-storage" {
				k3sRole := cfg.K3sRole
				if k3sRole == "" {
					k3sRole = "server"
				}
				roleDisp := "server (Standalone SQLite + OpenEBS ZFS-LocalPV)"
				if k3sRole == "agent" {
					roleDisp = "agent (Cluster Storage Worker Node)"
				}
				fmt.Printf("   • %-24s : %s%s%s\n", "K3s Node Role", colorCyan+colorBold, roleDisp, colorReset)
				if cfg.K3sServerURL != "" {
					fmt.Printf("   • %-24s : %s%s%s\n", "K3s Control-Plane URL", colorCyan+colorBold, cfg.K3sServerURL, colorReset)
				}
				effArc := cfg.ZfsArcMaxMB
				arcNote := fmt.Sprintf("%d MiB (Custom)", effArc)
				if effArc <= 0 {
					effArc = ComputeDefaultZfsArcMaxMB(eval.TotalRAMMB)
					arcNote = fmt.Sprintf("Auto (%d MiB)", effArc)
				}
				fmt.Printf("   • %-24s : %s%s%s\n", "OpenZFS ARC Memory Cap", colorGreen+colorBold, arcNote, colorReset)
			}
			fmt.Printf("   • %-24s : %s%s%s\n", "Data Volume Encryption", colorMagenta+colorBold, luksSummary, colorReset)
			fmt.Printf("   • %-24s : %s%s%s\n", "Network Interfaces", colorCyan+colorBold, formatPreInstallNetworkSummary(), colorReset)
			if cfg.KeepPartitions {
				fmt.Printf("   • %-24s : %sKeep Existing Pre-Partitioned Disk Layout%s\n", "Partition Table Mode", colorYellow+colorBold, colorReset)
			}
			fmt.Printf("   • %-24s : %s%s%s\n\n", "Appliance Hostname", colorBold, cfg.Hostname, colorReset)

			fmt.Println(RenderPartitionBar(layout, cfg, 64))
			var allTargetDisks []string
			allTargetDisks = append(allTargetDisks, cfg.SystemDisks...)
			allTargetDisks = append(allTargetDisks, cfg.ZfsExtraDisks...)
			allTargetDisks = append(allTargetDisks, cfg.ZfsSlogDisks...)
			allTargetDisks = append(allTargetDisks, cfg.ZfsL2arcDisks...)
			allTargetDisks = append(allTargetDisks, cfg.ZfsSpareDisks...)

			fmt.Println("\n────────────────────────────────────────────────────────────────────────────────")
			if cfg.KeepPartitions {
				fmt.Printf(" %sNOTE: Existing partition table on [%s] will be PRESERVED (formatting target filesystems only).%s\n",
					colorYellow+colorBold, strings.Join(allTargetDisks, ", "), colorReset)
			} else {
				fmt.Printf(" %s⚠️  WARNING: ALL EXISTING DATA ON [%s] WILL BE PERMANENTLY ERASED!%s\n",
					colorRed+colorBold, strings.Join(allTargetDisks, ", "), colorReset)
			}
			fmt.Println("────────────────────────────────────────────────────────────────────────────────")
			fmt.Printf(" %sControls:%s [I / Enter] Begin Installation Now   [V] Logs & Diagnostics   [B] Back   [W] Shell Wizard   [Q] Cancel\n", colorDim, colorReset)

			key := readRawKey()
			switch key {
			case "V":
				runInstallerLogsScreen(cfg, eval, nil, reader)
			case "B", "BACKSPACE", "LEFT":
				step = 4
			case "W":
				clearScreen()
				cmd := exec.Command("/bin/sh", installerPath, "--shell-wizard")
				cmd.Stdin = os.Stdin
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				_ = cmd.Run()
				pause(reader)
				return
			case "I", "ENTER":
				executeLiveInstallation(cfg, eval, installerPath, reader)
				return
			case "Q", "ESC":
				return
			}
		}
	}
}

// executeLiveInstallation writes the config file, runs axonwall-install, and renders the live progress dashboard.
func executeLiveInstallation(cfg InstallerConfig, eval HardwareEvaluation, installerPath string, reader *bufio.Reader) {
	suppressConsoleNoise()
	runDir := "/run/axonwall"
	if err := os.MkdirAll(runDir, 0700); err != nil {
		runDir = os.TempDir()
	}
	tmpFile, err := os.CreateTemp(runDir, "axonwall-install-*.conf")
	if err != nil {
		fmt.Printf("\n%s[!] Failed to create installer configuration file: %v%s\n", colorRed, err, colorReset)
		pause(reader)
		return
	}
	cfgPath := tmpFile.Name()
	_ = tmpFile.Chmod(0600)
	content := FormatInstallerConfig(cfg)
	if _, err := tmpFile.WriteString(content); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(cfgPath)
		fmt.Printf("\n%s[!] Failed to write installer configuration: %v%s\n", colorRed, err, colorReset)
		pause(reader)
		return
	}
	_ = tmpFile.Close()
	defer func() {
		_ = os.Remove(cfgPath)
	}()

	phases := []string{
		"Partitioning target disk(s) (GPT + BIOS Boot + UEFI ESP)",
		"Formatting filesystems, assembling RAID-1 & LUKS2 encryption",
		"Direct-imaging pristine Axonwall OS SquashFS to Slot A",
		"Configuring fstab, crypttab, TPM 2.0, Cloud-Init & credentials",
		"Cloning Slot A into Standby Slot B & recording slot metadata",
		"Installing BIOS & UEFI GRUB2 bootloaders",
		"Bootstrapping OpenZFS storage pool (tank)",
		"Finalizing installation & flushing storage caches",
	}
	if cfg.InstallMode == "zbm" {
		phases = []string{
			"Partitioning target disk(s) (GPT + ZFSBootMenu ESP + OpenZFS zroot)",
			"Formatting ZBM ESP & creating OpenZFS Root Pool (zroot)",
			"Direct-imaging pristine Axonwall OS into ZFS Boot Environment",
			"Configuring fstab, hostid, TPM 2.0, Cloud-Init & credentials",
			"Recording Boot Environment & watchdog metadata",
			"Installing ZFSBootMenu (UEFI UKI & Legacy BIOS Syslinux — No GRUB)",
			"Configuring OpenZFS storage datasets & factory snapshot",
			"Finalizing installation & exporting ZFS pools",
		}
	}

	currentPhase := 1
	totalPhases := len(phases)
	var milestoneLines []string
	var allRawLines []string
	startTime := time.Now()
	logFilePath := "/var/log/axonwall-install.log"

	drawProgress := func(statusMsg string, finished bool, failed bool) {
		clearScreen()
		hdrColor := colorEmerald
		hdrTitle := "⚡ AXONWALL NEXT-GEN DIRECT-IMAGING INSTALLER — LIVE PROGRESS              "
		if failed {
			hdrColor = colorRed
			hdrTitle = "✗  AXONWALL INSTALLER — INSTALLATION FAILED (DO NOT BOOT TARGET DISK)      "
		}
		fmt.Printf("%s%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n", hdrColor, colorBold, colorReset)
		fmt.Printf("%s%s║  %s║%s\n", hdrColor, colorBold, hdrTitle, colorReset)
		fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════════════════╝%s\n\n", hdrColor, colorBold, colorReset)

		pct := ((currentPhase - 1) * 100) / totalPhases
		if finished && !failed {
			pct = 100
		}
		barWidth := 52
		filled := (pct * barWidth) / 100
		if filled > barWidth {
			filled = barWidth
		}
		barColor := colorEmerald
		statusColor := colorCyan
		if failed {
			barColor = colorRed
			statusColor = colorRed
		}
		bar := barColor + colorBold + strings.Repeat("█", filled) + colorReset + colorDim + strings.Repeat("░", barWidth-filled) + colorReset
		elapsed := time.Since(startTime).Round(time.Second)

		fmt.Printf("  Progress: [%s] %s%3d%%%s  (%s)\n", bar, colorBold, pct, colorReset, elapsed)
		fmt.Printf("  Status  : %s%s%s\n\n", statusColor+colorBold, statusMsg, colorReset)

		fmt.Println("  Installation Phases:")
		for i, p := range phases {
			idx := i + 1
			if (finished && !failed) || idx < currentPhase {
				fmt.Printf("    %s[✓]%s %s\n", colorGreen+colorBold, colorReset, p)
			} else if idx == currentPhase {
				if failed {
					fmt.Printf("    %s[✗] %s%s\n", colorRed+colorBold, p, colorReset)
				} else {
					fmt.Printf("    %s[➜] %s%s\n", colorEmerald+colorBold, p, colorReset)
				}
			} else {
				fmt.Printf("    %s[ ] %s%s\n", colorDim, p, colorReset)
			}
		}

		fmt.Println("\n────────────────────────────────────────────────────────────────────────────────")
		if failed {
			fmt.Printf("  %sDiagnostic Output (see %s for full details):%s\n", colorRed+colorBold, logFilePath, colorReset)
			startIdx := 0
			if len(allRawLines) > 10 {
				startIdx = len(allRawLines) - 10
			}
			for _, l := range allRawLines[startIdx:] {
				fmt.Printf("   %s%s%s\n", colorRed, l, colorReset)
			}
		} else {
			fmt.Printf("  %sRecent Activity%s %s(verbose command output encapsulated in %s):%s\n",
				colorBold, colorReset, colorDim, logFilePath, colorReset)
			startIdx := 0
			if len(milestoneLines) > 6 {
				startIdx = len(milestoneLines) - 6
			}
			for _, l := range milestoneLines[startIdx:] {
				fmt.Printf("   %s%s%s\n", colorDim, l, colorReset)
			}
		}
		fmt.Println("────────────────────────────────────────────────────────────────────────────────")
	}

	drawProgress("Starting installation backend...", false, false)

	cmd := exec.Command("/bin/sh", installerPath, "--apply-config", cfgPath)
	cmd.Env = append(os.Environ(), "AXONWALL_INSTALL_BACKEND=1")
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("%s[!] Failed to attach stdout pipe: %v%s\n", colorRed, err, colorReset)
		pause(reader)
		return
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		fmt.Printf("%s[!] Failed to start installer: %v%s\n", colorRed, err, colorReset)
		pause(reader)
		return
	}

	scanner := bufio.NewScanner(stdoutPipe)
	statusMsg := phases[0]
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		allRawLines = append(allRawLines, line)
		if strings.HasPrefix(line, "[PHASE:") {
			// Format: [PHASE:3/8] Message...
			closeIdx := strings.Index(line, "]")
			if closeIdx > 7 {
				ratio := line[7:closeIdx]
				parts := strings.SplitN(ratio, "/", 2)
				if len(parts) == 2 {
					if pNum, err := strconv.Atoi(parts[0]); err == nil && pNum >= 1 && pNum <= totalPhases {
						currentPhase = pNum
					}
				}
				statusMsg = strings.TrimSpace(line[closeIdx+1:])
			}
			drawProgress(statusMsg, false, false)
		} else if strings.HasPrefix(line, "[+]") || strings.HasPrefix(line, "[!]") || strings.HasPrefix(line, "[✓]") {
			milestoneLines = append(milestoneLines, line)
			drawProgress(statusMsg, false, false)
		}
	}

	err = cmd.Wait()
	if err != nil {
		failureMsg := fmt.Sprintf("Installation failed: %v", err)
		for {
			suppressConsoleNoise()
			drawProgress(failureMsg, true, true)
			fmt.Printf("\n  Press %s[V]%s to view/save full Logs & Diagnostics, or %s[Enter / Q]%s to return to Console: ",
				colorCyan+colorBold, colorReset, colorBold, colorReset)
			key := readRawKey()
			if key == "V" {
				runInstallerLogsScreen(cfg, eval, allRawLines, reader)
				continue
			}
			return
		}
	}

	for {
		suppressConsoleNoise()
		drawProgress("Installation completed! Remove installation media and reboot.", true, false)
		fmt.Printf("\n  %s[✓] Axonwall OS has been installed to %s.%s\n", colorGreen+colorBold, strings.Join(cfg.SystemDisks, ", "), colorReset)
		fmt.Printf("  Press %s[R]%s to reboot now, %s[V]%s to view/save Logs & Diagnostics, or %s[Enter]%s for Console: ",
			colorEmerald+colorBold, colorReset, colorCyan+colorBold, colorReset, colorBold, colorReset)

		key := readRawKey()
		if key == "V" {
			runInstallerLogsScreen(cfg, eval, allRawLines, reader)
			continue
		}
		if key == "R" {
			fmt.Println("\n  Rebooting appliance...")
			_ = exec.Command("systemctl", "reboot").Run()
			_ = exec.Command("/sbin/reboot").Run()
			_ = exec.Command("reboot").Run()
			for {
				time.Sleep(1 * time.Second)
			}
		}
		return
	}
}

// RunUnattendedInstall executes zero-touch Cloud-Init installation and streams progress to stdout.
func RunUnattendedInstall() error {
	_ = os.MkdirAll("/run", 0755)
	if lockFile, err := os.OpenFile("/run/axonwall-unattended.lock", os.O_CREATE|os.O_RDWR, 0600); err == nil {
		defer lockFile.Close()
		if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			// Another console instance (e.g. tty1 vs ttyS0) is already executing the unattended installer
			for {
				time.Sleep(5 * time.Second)
			}
		}
	}
	cmd := exec.Command("/bin/sh", "/usr/local/bin/axonwall-install", "--unattended")
	cmd.Env = append(os.Environ(), "AXONWALL_INSTALL_BACKEND=1")
	cmd.Stdin = os.Stdin
	cmd.Stdout = io.Writer(os.Stdout)
	cmd.Stderr = io.Writer(os.Stderr)
	return cmd.Run()
}
