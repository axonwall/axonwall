package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
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
	Edition        string   // "axonwall" or "vault"
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
	if _, err := os.Stat("/etc/axonwall/.vault-edition"); err == nil {
		edition = "vault"
		hostname = "axonwall-vault"
	} else if data, err := os.ReadFile("/proc/cmdline"); err == nil {
		cmd := string(data)
		if strings.Contains(cmd, "axonwall_edition=vault") || strings.Contains(cmd, "axonwall.edition=vault") {
			edition = "vault"
			hostname = "axonwall-vault"
		}
	}
	osFamily := "debian"
	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		osFamily = "alpine"
	}
	tpmPresent := hasTPM2Device()
	return InstallerConfig{
		Edition:      edition,
		OSFamily:     osFamily,
		InstallMode:  "ab",
		SlotMB:       4096,
		RootFSType:   "ext4",
		DataFSType:   "ext4",
		ZfsAllocMode: "remainder",
		CustomZfsGB:  16,
		ZfsTopology:  "auto",
		LogsEnabled:  false,
		LogsGB:       8,
		LogsFSType:   "xfs",
		LuksEnabled:  false,
		LuksTPM2:     tpmPresent,
		Hostname:     hostname,
		AdminUser:    "admin",
	}
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
				if mDev == devPath {
					mounted = true
					break
				}
				if strings.HasPrefix(mDev, devPath) {
					rem := mDev[len(devPath):]
					if len(rem) > 0 && ((rem[0] >= '0' && rem[0] <= '9') || (rem[0] == 'p' && len(rem) > 1 && rem[1] >= '0' && rem[1] <= '9')) {
						mounted = true
						break
					}
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

// AutoAssignDiskRoles automatically assigns roles based on disk capacity tiers.
// For heterogeneous servers (e.g. 2x 32 GB boot disks + 2x 1 TB data disks), the smallest
// tier (1-2 disks) is assigned as "system" (OS RAID-1 Mirror) and the larger capacity tier
// is assigned as "zfs-data" (Dedicated OpenZFS storage pool).
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

	// Homogeneous disks: default first disk (or pair if 2+ identical disks) to system
	setDiskRole(&out[0], "system")
	return out
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

	if cfg.InstallMode == "zbm" {
		dataMB = 4096
		if remMB > 6144 {
			zfsMB = remMB - dataMB
		} else {
			dataMB = remMB / 2
			zfsMB = remMB - dataMB
		}
	} else {
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
				dataMB = 8192
				zfsMB = remMB - dataMB
			} else if remMB > 4096 {
				dataMB = 2048
				zfsMB = remMB - dataMB
			} else {
				zfsMB = 0
				dataMB = remMB
			}
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
	slotALabel := "Slot A"
	if cfg.InstallMode == "zbm" {
		slotALabel = "ZBM-Boot"
	} else if cfg.InstallMode == "rolling" {
		slotALabel = "Root OS"
	}
	segments := []seg{
		{label: "EFI", mb: layout.EfiMB, color: colorBlue + colorBold, char: "█"},
		{label: slotALabel, mb: layout.SlotAMB, color: colorEmerald + colorBold, char: "█"},
	}
	if layout.SlotBMB > 0 {
		segments = append(segments, seg{label: "Slot B", mb: layout.SlotBMB, color: colorCyan + colorBold, char: "█"})
	}
	if layout.LogsMB > 0 {
		segments = append(segments, seg{label: "Logs", mb: layout.LogsMB, color: colorYellow + colorBold, char: "█"})
	}
	dataLabel := "Data"
	if cfg.InstallMode == "zbm" {
		dataLabel = "Aux/Boot"
		if cfg.LuksEnabled {
			dataLabel = "Aux[LUKS2]"
		}
	} else if cfg.LuksEnabled {
		dataLabel = "Data[LUKS2]"
	}
	segments = append(segments, seg{label: dataLabel, mb: layout.DataMB, color: colorMagenta + colorBold, char: "█"})
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
	// Adjust largest segment so total width matches exactly
	maxIdx := 0
	for i := range segments {
		if counts[i] > counts[maxIdx] {
			maxIdx = i
		}
	}
	diff := width - usedCells
	if counts[maxIdx]+diff >= 2 {
		counts[maxIdx] += diff
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

	edition := cfg.Edition
	if edition == "" {
		edition = "axonwall"
	}

	lines := []string{
		"# Axonwall Next-Gen Installer Configuration",
		fmt.Sprintf("INSTALL_EDITION=%s", shellQuote(edition)),
		fmt.Sprintf("SYSTEM_DISKS=%s", shellQuote(strings.Join(cfg.SystemDisks, " "))),
		fmt.Sprintf("INSTALL_MODE=%s", shellQuote(cfg.InstallMode)),
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
	}
	return strings.Join(lines, "\n") + "\n"
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
	case s == "\x1b[A" || s == "\x1bOA" || s == "k" || s == "K":
		return "UP"
	case s == "\x1b[B" || s == "\x1bOB" || s == "j" || s == "J":
		return "DOWN"
	case s == "\x1b[C" || s == "\x1bOC":
		return "RIGHT"
	case s == "\x1b[D" || s == "\x1bOD":
		return "LEFT"
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
	if cfg.Edition == "vault" {
		title = "AXONWALL VAULT EDITION INSTALLER"
		subtitle = "Hardened Immutable S3 Object-Lock Backup Appliance (SeaweedFS)"
		accent = colorBrightCya
	}

	versionStr := "v0.11.38"
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

	steps := []string{
		"1. Edition & Arch",
		"2. Disk Roles & RAID",
		"3. Storage & ZFS",
		"4. Security & Auth",
		"5. Review & Install",
	}
	fmt.Println("────────────────────────────────────────────────────────────────────────────────")
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
	fmt.Println("\n────────────────────────────────────────────────────────────────────────────────")
}

// RunNextGenInstallerTUI launches the interactive multi-step Axonwall Next-Gen Installer TUI.
func RunNextGenInstallerTUI(reader *bufio.Reader) {
	installerPath := "/usr/local/bin/axonwall-install"
	if _, err := os.Stat(installerPath); err != nil {
		clearScreen()
		fmt.Printf("%s[!] Installer utility '%s' not found on this system.%s\n", colorRed, installerPath, colorReset)
		pause(reader)
		return
	}

	cfg := DefaultInstallerConfig()
	disks := AutoAssignDiskRoles(DiscoverDisks())
	syncDiskRolesAndConfig(disks, &cfg)
	if len(cfg.ZfsExtraDisks) > 0 && cfg.InstallMode != "zbm" {
		cfg.ZfsAllocMode = "none"
	}

	step := 1
	archCursor := 0
	diskCursor := 0
	zfsCursor := 0
	secCursor := 0

	for step >= 1 && step <= 5 {
		switch step {
		case 1:
			renderInstallerBanner(cfg, 1)
			ngfwBadge := colorDim + "( ) Axonwall NGFW & Router" + colorReset
			vaultBadge := colorDim + "( ) Axonwall Vault S3 Storage" + colorReset
			editionDesc := "Full NGFW, SD-WAN, WireGuard/Headscale, IDS/IPS, BGP/OSPF, Web UI & Controller"
			if cfg.Edition == "vault" {
				vaultBadge = colorBrightCya + colorBold + "(●) Axonwall Vault S3 Storage" + colorReset
				editionDesc = "Immutable S3 Object-Lock Backup Appliance (SeaweedFS; firewall stack stripped)"
			} else {
				ngfwBadge = colorEmerald + colorBold + "(●) Axonwall NGFW & Router" + colorReset
			}
			fmt.Printf(" %s[E] Appliance Edition:%s  %s    %s\n", colorBold, colorReset, ngfwBadge, vaultBadge)
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
				fmt.Printf(" %sControls:%s [E] Edition  [↑/↓] Move  [Space/1-3] Arch  [Enter] Next  [Q] Cancel\n", colorDim, colorReset)
			} else {
				fmt.Printf(" %sControls:%s [E] Edition  [↑/↓] Move  [Space/1-3] Arch  [S] Slot Size  [F] ext4/xfs  [Enter] Next  [Q] Cancel\n", colorDim, colorReset)
			}

			key := readRawKey()
			switch key {
			case "E":
				if cfg.Edition == "vault" {
					cfg.Edition = "axonwall"
					if cfg.Hostname == "" || cfg.Hostname == "axonwall-vault" {
						cfg.Hostname = "axonwall"
					}
				} else {
					cfg.Edition = "vault"
					if cfg.Hostname == "" || cfg.Hostname == "axonwall" {
						cfg.Hostname = "axonwall-vault"
					}
				}
			case "UP":
				if archCursor > 0 {
					archCursor--
				}
			case "DOWN":
				if archCursor < len(archOptions)-1 {
					archCursor++
				}
			case "1", "2", "3":
				idx, _ := strconv.Atoi(key)
				archCursor = idx - 1
				cfg.InstallMode = archOptions[archCursor].mode
			case "SPACE":
				cfg.InstallMode = archOptions[archCursor].mode
			case "S":
				if cfg.InstallMode == "rolling" {
					if cfg.SlotMB == 8192 {
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
			case "ENTER", "RIGHT":
				cfg.InstallMode = archOptions[archCursor].mode
				if cfg.InstallMode != "ab" && cfg.SlotMB < 8192 {
					cfg.SlotMB = 8192
				}
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
			fmt.Printf(" %sNavigation:%s [↑/↓] Move  [A] Auto-Tier by Size  [R] Rescan  [B] Back  [Enter] Next\n", colorDim, colorReset)

			key := readRawKey()
			switch key {
			case "UP":
				if diskCursor > 0 {
					diskCursor--
				}
			case "DOWN":
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
				cmd := exec.Command("/bin/sh", installerPath, "--wizard")
				cmd.Stdin = os.Stdin
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				_ = cmd.Run()
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
				fmt.Printf(" %sControls:%s [T] Cycle Topology  [L] Toggle /var/log  [D] Edit Disk Roles (Data/SLOG/L2ARC)  [B] Back  [Enter] Next\n", colorDim, colorReset)

				key := readRawKey()
				switch key {
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

				zfsModes := []struct {
					mode  string
					title string
				}{
					{"remainder", "Reserve Remaining System Disk Space for OpenZFS (8 GB System Data + Remainder ZFS)"},
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
				fmt.Printf(" %sControls:%s [↑/↓] Move  [Space/1-4] Select  [C] Custom GB  [T] Topology  [L] /var/log  [D] Disk Roles  [B] Back  [Enter] Next\n", colorDim, colorReset)

				key := readRawKey()
				switch key {
				case "UP":
					if zfsCursor > 0 {
						zfsCursor--
					}
				case "DOWN":
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

			secItems := []struct {
				title string
				val   string
			}{
				{"[1] LUKS2 Persistent Data Encryption", luksBadge},
				{"[2] Hardware TPM 2.0 PCR Binding", tpmBadge},
				{"[3] Appliance Hostname", colorCyan + colorBold + cfg.Hostname + colorReset},
				{"[4] Administrator & Root Password", pwStatus},
			}

			for i, item := range secItems {
				cursor := "  "
				if i == secCursor {
					cursor = colorEmerald + colorBold + "➜ " + colorReset
				}
				fmt.Printf(" %s%-38s : %s\n\n", cursor, colorBold+item.title+colorReset, item.val)
			}

			fmt.Println("────────────────────────────────────────────────────────────────────────────────")
			fmt.Printf(" %sControls:%s [↑/↓] Move  [Space/1-4] Toggle/Edit  [B] Back  [Enter] Review & Install\n", colorDim, colorReset)

			key := readRawKey()
			switch key {
			case "UP":
				if secCursor > 0 {
					secCursor--
				}
			case "DOWN":
				if secCursor < len(secItems)-1 {
					secCursor++
				}
			case "1", "2", "3", "4", "SPACE":
				if key != "SPACE" {
					idx, _ := strconv.Atoi(key)
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
			fmt.Printf("   • %-24s : %s%s%s\n", "Data Volume Encryption", colorMagenta+colorBold, luksSummary, colorReset)
			fmt.Printf("   • %-24s : %s%s%s\n\n", "Appliance Hostname", colorBold, cfg.Hostname, colorReset)

			fmt.Println(RenderPartitionBar(layout, cfg, 64))
			var allTargetDisks []string
			allTargetDisks = append(allTargetDisks, cfg.SystemDisks...)
			allTargetDisks = append(allTargetDisks, cfg.ZfsExtraDisks...)
			allTargetDisks = append(allTargetDisks, cfg.ZfsSlogDisks...)
			allTargetDisks = append(allTargetDisks, cfg.ZfsL2arcDisks...)
			allTargetDisks = append(allTargetDisks, cfg.ZfsSpareDisks...)

			fmt.Println("\n────────────────────────────────────────────────────────────────────────────────")
			fmt.Printf(" %s⚠️  WARNING: ALL EXISTING DATA ON [%s] WILL BE PERMANENTLY ERASED!%s\n",
				colorRed+colorBold, strings.Join(allTargetDisks, ", "), colorReset)
			fmt.Println("────────────────────────────────────────────────────────────────────────────────")
			fmt.Printf(" %sControls:%s [I / Enter] Begin Installation Now   [B] Back   [W] Shell Wizard   [Q] Cancel\n", colorDim, colorReset)

			key := readRawKey()
			switch key {
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
				executeLiveInstallation(cfg, installerPath, reader)
				return
			case "Q", "ESC":
				return
			}
		}
	}
}

// executeLiveInstallation writes the config file, runs axonwall-install, and renders the live progress dashboard.
func executeLiveInstallation(cfg InstallerConfig, installerPath string, reader *bufio.Reader) {
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
		"Installing BIOS & UEFI GRUB2 / ZFSBootMenu bootloaders",
		"Bootstrapping OpenZFS storage pool (tank / zroot)",
		"Finalizing installation & flushing storage caches",
	}

	currentPhase := 1
	totalPhases := len(phases)
	var logLines []string
	startTime := time.Now()

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
		fmt.Printf("  %sLive Installer Log:%s\n", colorBold, colorReset)
		startIdx := 0
		if len(logLines) > 8 {
			startIdx = len(logLines) - 8
		}
		for _, l := range logLines[startIdx:] {
			fmt.Printf("   %s%s%s\n", colorDim, l, colorReset)
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
		} else {
			logLines = append(logLines, line)
		}
		drawProgress(statusMsg, false, false)
	}

	err = cmd.Wait()
	if err != nil {
		drawProgress(fmt.Sprintf("Installation failed: %v", err), true, true)
		pause(reader)
		return
	}

	drawProgress("Installation completed! Remove installation media and reboot.", true, false)
	fmt.Printf("\n  %s[✓] Axonwall OS has been installed to %s.%s\n", colorGreen+colorBold, strings.Join(cfg.SystemDisks, ", "), colorReset)
	fmt.Printf("  Press %s[R]%s to reboot appliance now, or %s[Enter]%s to return to Console: ", colorEmerald+colorBold, colorReset, colorBold, colorReset)

	key := readRawKey()
	if key == "R" {
		fmt.Println("\n  Rebooting appliance...")
		_ = exec.Command("systemctl", "reboot").Run()
		_ = exec.Command("/sbin/reboot").Run()
		_ = exec.Command("reboot").Run()
		for {
			time.Sleep(1 * time.Second)
		}
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
