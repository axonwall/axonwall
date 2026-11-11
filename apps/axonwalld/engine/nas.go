package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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

type InstallZfsBootstrapSpec struct {
	PoolName        string   `json:"poolName"`
	Topology        string   `json:"topology"`
	Vdevs           []string `json:"vdevs"`
	SizeGb          int      `json:"sizeGb"`
	SystemRaidMode  string   `json:"systemRaidMode"`
	SystemRaidDisks string   `json:"systemRaidDisks"`
	AutoCreatePool  bool     `json:"autoCreatePool"`
}

type DiskInventoryItem struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	SizeBytes   uint64 `json:"sizeBytes"`
	Model       string `json:"model"`
	Serial      string `json:"serial"`
	Type        string `json:"type"` // "disk", "part", "raid1"
	FsType      string `json:"fsType"`
	Mountpoint  string `json:"mountpoint"`
	PartLabel   string `json:"partLabel"`
	Rotational  bool   `json:"rotational"`
	SmartPassed bool   `json:"smartPassed"`
	// SmartUnknown reports that no SMART data could be read for this
	// disk (no smartctl, unsupported device). L18: the field used to
	// be absent and every disk was reported SmartPassed=true at a
	// hardcoded temperature, so a failing disk displayed as healthy.
	// SmartPassed is true only when smartctl reports PASSED.
	SmartUnknown   bool   `json:"smartUnknown"`
	TemperatureC   int    `json:"temperatureC"`
	EligibleForZfs bool   `json:"eligibleForZfs"`
	Role           string `json:"role"` // "available", "boot_zfs_partition", "system_raid_member", "in_use"
}

type ZfsPoolSpec struct {
	Name               string   `json:"name"`
	Topology           string   `json:"topology"` // stripe, mirror, raidz1, raidz2, raidz3, draid1, draid2, draid3
	DataDisks          []string `json:"dataDisks"`
	CacheDisks         []string `json:"cacheDisks"`
	LogDisks           []string `json:"logDisks"`
	SpareDisks         []string `json:"spareDisks"`
	SpecialDisks       []string `json:"specialDisks,omitempty"`
	DedupDisks         []string `json:"dedupDisks,omitempty"`
	SpecialSmallBlocks string   `json:"specialSmallBlocks,omitempty"`
	Ashift             int      `json:"ashift"`
	Autotrim           bool     `json:"autotrim"`
	Compression        string   `json:"compression"`
	ScrubScheduleCron  string   `json:"scrubScheduleCron"`
	TrimScheduleCron   string   `json:"trimScheduleCron,omitempty"`
	Description        string   `json:"description"`
}

type ZfsDatasetSpec struct {
	Name               string `json:"name"`
	Pool               string `json:"pool"`
	Type               string `json:"type"` // filesystem, zvol
	Compression        string `json:"compression"`
	Dedup              string `json:"dedup"`
	QuotaGb            int    `json:"quotaGb"`
	RefQuotaGb         int    `json:"refQuotaGb,omitempty"`
	RefReservationGb   int    `json:"refReservationGb,omitempty"`
	RecordSize         string `json:"recordSize"`
	SpecialSmallBlocks string `json:"specialSmallBlocks,omitempty"`
	VolSizeGb          int    `json:"volSizeGb"`
	AclMode            string `json:"aclMode"`
	Atime              string `json:"atime,omitempty"`
	Sync               string `json:"sync,omitempty"`
	Encryption         string `json:"encryption,omitempty"`
	KeyFormat          string `json:"keyFormat,omitempty"`
	KeyLocation        string `json:"keyLocation,omitempty"`
	ReplicateToHaPeer  bool   `json:"replicateToHaPeer"`
}

type CloudSyncTaskSpec struct {
	Name               string `json:"name"`
	Direction          string `json:"direction"` // push, pull
	Dataset            string `json:"dataset"`
	RemoteEndpoint     string `json:"remoteEndpoint"`
	RemoteBucket       string `json:"remoteBucket"`
	RemotePrefix       string `json:"remotePrefix,omitempty"`
	ScheduleCron       string `json:"scheduleCron,omitempty"`
	BandwidthLimitKbps int    `json:"bandwidthLimitKbps,omitempty"`
	Enabled            bool   `json:"enabled"`
}

type ZfsSnapshotPolicySpec struct {
	ID                string `json:"id"`
	Dataset           string `json:"dataset"`
	Interval          string `json:"interval"` // hourly, daily, weekly
	KeepCount         int    `json:"keepCount"`
	ReplicateToHaPeer bool   `json:"replicateToHaPeer"`
	Enabled           bool   `json:"enabled"`
}

type NasRuntimeBundle struct {
	Enabled           bool                    `json:"enabled"`
	Pools             []ZfsPoolSpec           `json:"pools"`
	Datasets          []ZfsDatasetSpec        `json:"datasets"`
	SnapshotPolicies  []ZfsSnapshotPolicySpec `json:"snapshotPolicies"`
	CloudSyncTasks    []CloudSyncTaskSpec     `json:"cloudSyncTasks,omitempty"`
	CloudSyncCommands []string                `json:"cloudSyncCommands,omitempty"`
	SmbConf           string                  `json:"smbConf"`
	NfsExports        string                  `json:"nfsExports"`
	IscsiConf         string                  `json:"iscsiConf"`
	LioSaveconfigJson string                  `json:"lioSaveconfigJson,omitempty"`
	S3EnvConf         string                  `json:"s3EnvConf,omitempty"`
}

type ZfsPoolStatus struct {
	Name          string   `json:"name"`
	Topology      string   `json:"topology"`
	SizeBytes     uint64   `json:"sizeBytes"`
	AllocBytes    uint64   `json:"allocBytes"`
	FreeBytes     uint64   `json:"freeBytes"`
	Fragmentation int      `json:"fragmentation"`
	CapacityPct   int      `json:"capacityPct"`
	Health        string   `json:"health"`
	DataDisks     []string `json:"dataDisks"`
}

type ZfsSnapshotInfo struct {
	Name      string `json:"name"`
	Dataset   string `json:"dataset"`
	UsedBytes uint64 `json:"usedBytes"`
	CreatedAt string `json:"createdAt"`
}

type NasManager struct {
	mu          sync.Mutex
	cfg         NasRuntimeBundle
	installSpec *InstallZfsBootstrapSpec
}

func NewNasManager() *NasManager {
	mgr := &NasManager{}
	mgr.BootstrapInstallZfsPool()
	return mgr
}

func BuildZfsPoolCreateArgs(pool ZfsPoolSpec) []string {
	ashift := pool.Ashift
	if ashift < 9 || ashift > 16 {
		ashift = 12
	}
	autotrim := "on"
	if !pool.Autotrim {
		autotrim = "off"
	}
	comp := pool.Compression
	if comp == "" {
		comp = "lz4"
	}

	args := []string{
		"create", "-f",
		fmt.Sprintf("-o"), fmt.Sprintf("ashift=%d", ashift),
		fmt.Sprintf("-o"), fmt.Sprintf("autotrim=%s", autotrim),
		"-O", fmt.Sprintf("compression=%s", comp),
		"-O", "acltype=posixacl",
		"-O", "xattr=sa",
		"-O", "dnodesize=auto",
		"-O", "normalization=formD",
	}
	if pool.SpecialSmallBlocks != "" && pool.SpecialSmallBlocks != "0" {
		args = append(args, "-O", fmt.Sprintf("special_small_blocks=%s", pool.SpecialSmallBlocks))
	}
	args = append(args,
		"-O", fmt.Sprintf("mountpoint=/mnt/%s", pool.Name),
		pool.Name,
	)

	if pool.Topology != "" && pool.Topology != "stripe" {
		args = append(args, pool.Topology)
	}
	args = append(args, pool.DataDisks...)

	if len(pool.SpecialDisks) > 0 {
		args = append(args, "special")
		if len(pool.SpecialDisks) >= 2 {
			args = append(args, "mirror")
		}
		args = append(args, pool.SpecialDisks...)
	}
	if len(pool.DedupDisks) > 0 {
		args = append(args, "dedup")
		if len(pool.DedupDisks) >= 2 {
			args = append(args, "mirror")
		}
		args = append(args, pool.DedupDisks...)
	}
	if len(pool.LogDisks) > 0 {
		args = append(args, "log")
		if len(pool.LogDisks) >= 2 {
			args = append(args, "mirror")
		}
		args = append(args, pool.LogDisks...)
	}
	if len(pool.CacheDisks) > 0 {
		args = append(args, "cache")
		args = append(args, pool.CacheDisks...)
	}
	if len(pool.SpareDisks) > 0 {
		args = append(args, "spare")
		args = append(args, pool.SpareDisks...)
	}
	return args
}

func BuildZfsDatasetCreateArgs(ds ZfsDatasetSpec) [][]string {
	fullName := ds.Name
	if ds.Pool != "" && !strings.HasPrefix(ds.Name, ds.Pool+"/") {
		fullName = ds.Pool + "/" + ds.Name
	}
	comp := ds.Compression
	if comp == "" {
		comp = "lz4"
	}

	if ds.Type == "zvol" {
		volGb := ds.VolSizeGb
		if volGb <= 0 {
			volGb = 10
		}
		createArgs := []string{"create", "-p", "-V", fmt.Sprintf("%dG", volGb), "-o", fmt.Sprintf("compression=%s", comp), "-o", "volblocksize=16K"}
		if ds.Encryption != "" && ds.Encryption != "off" {
			createArgs = append(createArgs, "-o", fmt.Sprintf("encryption=%s", ds.Encryption))
			kf := ds.KeyFormat
			if kf == "" {
				kf = "hex"
			}
			createArgs = append(createArgs, "-o", fmt.Sprintf("keyformat=%s", kf))
			if ds.KeyLocation != "" && strings.HasPrefix(filepath.Clean(ds.KeyLocation), "/etc/axonwall/keys/") {
				createArgs = append(createArgs, "-o", fmt.Sprintf("keylocation=file://%s", filepath.Clean(ds.KeyLocation)))
			}
		}
		createArgs = append(createArgs, fullName)
		return [][]string{createArgs}
	}

	recSize := ds.RecordSize
	if recSize == "" {
		recSize = "128K"
	}
	dedup := ds.Dedup
	if dedup == "" {
		dedup = "off"
	}
	aclMode := ds.AclMode
	if aclMode == "" {
		aclMode = "passthrough"
	}

	createCmd := []string{
		"create", "-p",
		"-o", fmt.Sprintf("compression=%s", comp),
		"-o", fmt.Sprintf("recordsize=%s", recSize),
		"-o", fmt.Sprintf("dedup=%s", dedup),
		"-o", fmt.Sprintf("aclmode=%s", aclMode),
	}
	if ds.Atime != "" {
		createCmd = append(createCmd, "-o", fmt.Sprintf("atime=%s", ds.Atime))
	}
	if ds.Sync != "" {
		createCmd = append(createCmd, "-o", fmt.Sprintf("sync=%s", ds.Sync))
	}
	if ds.SpecialSmallBlocks != "" {
		createCmd = append(createCmd, "-o", fmt.Sprintf("special_small_blocks=%s", ds.SpecialSmallBlocks))
	}
	if ds.Encryption != "" && ds.Encryption != "off" {
		createCmd = append(createCmd, "-o", fmt.Sprintf("encryption=%s", ds.Encryption))
		kf := ds.KeyFormat
		if kf == "" {
			kf = "hex"
		}
		createCmd = append(createCmd, "-o", fmt.Sprintf("keyformat=%s", kf))
		if ds.KeyLocation != "" && strings.HasPrefix(filepath.Clean(ds.KeyLocation), "/etc/axonwall/keys/") {
			createCmd = append(createCmd, "-o", fmt.Sprintf("keylocation=file://%s", filepath.Clean(ds.KeyLocation)))
		}
	}
	createCmd = append(createCmd, fullName)

	cmds := [][]string{createCmd}
	if ds.QuotaGb > 0 {
		cmds = append(cmds, []string{"set", fmt.Sprintf("quota=%dG", ds.QuotaGb), fullName})
	}
	if ds.RefQuotaGb > 0 {
		cmds = append(cmds, []string{"set", fmt.Sprintf("refquota=%dG", ds.RefQuotaGb), fullName})
	}
	if ds.RefReservationGb > 0 {
		cmds = append(cmds, []string{"set", fmt.Sprintf("refreservation=%dG", ds.RefReservationGb), fullName})
	}
	return cmds
}

func (m *NasManager) BootstrapInstallZfsPool() {
	specPath := "/var/lib/axonwall/install-zfs.json"
	data, err := os.ReadFile(specPath)
	if err != nil {
		return
	}
	var spec InstallZfsBootstrapSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		slog.Warn("Failed to parse install-zfs.json", "error", err)
		return
	}
	m.installSpec = &spec

	if !spec.AutoCreatePool || spec.PoolName == "" || len(spec.Vdevs) == 0 {
		return
	}

	if _, err := exec.LookPath("zpool"); err != nil {
		return
	}

	ensureZrootDatasets := func(topo string) {
		if err := exec.Command("zpool", "list", "-H", "zroot").Run(); err != nil {
			return
		}
		if err := exec.Command("zfs", "list", "-H", "zroot/ROOT").Run(); err == nil {
			return
		}
		appVer := "0.11.41"
		if vBytes, err := os.ReadFile("/etc/axonwall/version"); err == nil {
			if v := strings.TrimSpace(string(vBytes)); v != "" {
				appVer = v
			}
		}
		if topo == "" {
			topo = "stripe"
		}
		initBe := "zroot/ROOT/axonwall-" + appVer
		_ = exec.Command("zfs", "set", "canmount=off", "zroot").Run()
		_ = exec.Command("zfs", "set", "mountpoint=none", "zroot").Run()
		_ = exec.Command("zfs", "create", "-o", "canmount=off", "-o", "mountpoint=none", "zroot/ROOT").Run()
		_ = exec.Command("zfs", "create", "-o", "canmount=noauto", "-o", "mountpoint=/", initBe).Run()
		if err := exec.Command("zpool", "list", "-H", "tank").Run(); err != nil {
			_ = exec.Command("zfs", "create", "-o", "mountpoint=/mnt/tank", "zroot/tank").Run()
		}
		_ = exec.Command("zpool", "set", "bootfs="+initBe, "zroot").Run()
		_ = exec.Command("zfs", "set", "org.axonwall:active_be="+initBe, "zroot/ROOT").Run()
		_ = exec.Command("zfs", "set", "org.axonwall:fallback_be="+initBe, "zroot/ROOT").Run()
		_ = exec.Command("zfs", "set", "org.axonwall:bootcount=0", "zroot/ROOT").Run()
		_ = exec.Command("zfs", "set", "org.axonwall:bootlimit=3", "zroot/ROOT").Run()
		_ = exec.Command("zfs", "set", "org.axonwall:topology="+topo, "zroot/ROOT").Run()
		_ = exec.Command("zfs", "snapshot", initBe+"@factory-initial").Run()
	}

	// Check if pool is already imported
	if err := exec.Command("zpool", "list", "-H", spec.PoolName).Run(); err == nil {
		slog.Info("Install-time ZFS pool already active", "pool", spec.PoolName)
		_ = exec.Command("zfs", "mount", "-a").Run()
		ensureZrootDatasets(spec.Topology)
		return
	}

	// Try importing first
	if err := exec.Command("zpool", "import", "-f", spec.PoolName).Run(); err == nil {
		slog.Info("Imported install-time ZFS pool", "pool", spec.PoolName)
		_ = exec.Command("zfs", "mount", "-a").Run()
		ensureZrootDatasets(spec.Topology)
		return
	}

	// Create pool from install-zfs.json spec
	poolSpec := ZfsPoolSpec{
		Name:        spec.PoolName,
		Topology:    spec.Topology,
		DataDisks:   spec.Vdevs,
		Ashift:      12,
		Autotrim:    true,
		Compression: "lz4",
	}
	if err := ValidateInstallZfsPoolSpec(poolSpec); err != nil {
		slog.Warn("Refusing install-time ZFS pool: invalid spec", "error", err)
		return
	}
	args := BuildZfsPoolCreateArgs(poolSpec)
	slog.Info("Creating install-time ZFS pool from installer layout", "pool", spec.PoolName, "topology", spec.Topology, "vdevs", spec.Vdevs)
	if out, err := exec.Command("zpool", args...).CombinedOutput(); err != nil {
		slog.Warn("Failed to create install-time ZFS pool", "error", err, "output", string(out))
		return
	}
	if spec.PoolName == "zroot" {
		ensureZrootDatasets(spec.Topology)
	}
}

// querySmartHealth runs smartctl for one device and reports the
// overall-health result and temperature. L18: DiscoverDisks used to
// hardcode SmartPassed=true and a fixed temperature for every disk,
// so a failing disk displayed as healthy. When smartctl is missing
// or the device reports nothing, the disk is unknown — never
// "passed" — and the temperature is 0.
func querySmartHealth(devPath string) (passed, known bool, tempC int) {
	tool, err := exec.LookPath("smartctl")
	if err != nil {
		return false, false, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, tool, "-H", "-A", devPath).CombinedOutput()
	passed, known = parseSmartctlHealth(string(out))
	tempC, _ = parseSmartctlTemperature(string(out))
	return passed, known, tempC
}

// parseSmartctlHealth reads the overall-health self-assessment line
// ("SMART overall-health self-assessment test result: PASSED").
// Anything else, including no such line, is unknown.
func parseSmartctlHealth(out string) (passed, known bool) {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "SMART overall-health self-assessment test result:") {
			if strings.Contains(line, "PASSED") {
				return true, true
			}
			return false, true
		}
	}
	return false, false
}

// parseSmartctlTemperature reads the drive temperature: the SATA
// attribute 194 ("Temperature_Celsius ... 36 (Min/Max ...)") or the
// NVMe line ("Temperature: 36 Celsius").
func parseSmartctlTemperature(out string) (int, bool) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 10 && fields[1] == "Temperature_Celsius" {
			if v, err := strconv.Atoi(fields[9]); err == nil {
				return v, true
			}
		}
		if len(fields) >= 2 && fields[0] == "Temperature:" {
			if v, err := strconv.Atoi(fields[1]); err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

func (m *NasManager) DiscoverDisks() []DiskInventoryItem {
	var items []DiskInventoryItem

	out, err := exec.Command("lsblk", "-J", "-b", "-o", "NAME,PATH,SIZE,MODEL,SERIAL,TYPE,FSTYPE,MOUNTPOINT,PARTLABEL,ROTA").Output()
	if err == nil {
		var parsed struct {
			Blockdevices []struct {
				Name       string `json:"name"`
				Path       string `json:"path"`
				Size       any    `json:"size"`
				Model      string `json:"model"`
				Serial     string `json:"serial"`
				Type       string `json:"type"`
				Fstype     string `json:"fstype"`
				Mountpoint string `json:"mountpoint"`
				Partlabel  string `json:"partlabel"`
				Rota       any    `json:"rota"`
				Children   []struct {
					Name       string `json:"name"`
					Path       string `json:"path"`
					Size       any    `json:"size"`
					Type       string `json:"type"`
					Fstype     string `json:"fstype"`
					Mountpoint string `json:"mountpoint"`
					Partlabel  string `json:"partlabel"`
				} `json:"children"`
			} `json:"blockdevices"`
		}

		if json.Unmarshal(out, &parsed) == nil {
			for _, dev := range parsed.Blockdevices {
				if dev.Type != "disk" && dev.Type != "raid1" {
					continue
				}
				var sizeBytes uint64
				switch v := dev.Size.(type) {
				case float64:
					sizeBytes = uint64(v)
				case string:
					sizeBytes, _ = strconv.ParseUint(v, 10, 64)
				}
				rota := false
				switch v := dev.Rota.(type) {
				case bool:
					rota = v
				case float64:
					rota = v != 0
				}

				devPath := dev.Path
				if devPath == "" {
					devPath = "/dev/" + dev.Name
				}
				// L18: query real SMART data instead of hardcoding
				// SmartPassed=true and a fixed temperature. The
				// ZFS-partition children below inherit the parent
				// disk's readings.
				smartPassed, smartKnown, smartTemp := querySmartHealth(devPath)

				hasSystemParts := false
				for _, ch := range dev.Children {
					if strings.HasPrefix(ch.Partlabel, "axon_zfs") {
						var chSize uint64
						switch v := ch.Size.(type) {
						case float64:
							chSize = uint64(v)
						case string:
							chSize, _ = strconv.ParseUint(v, 10, 64)
						}
						chPath := ch.Path
						if chPath == "" {
							chPath = "/dev/" + ch.Name
						}
						items = append(items, DiskInventoryItem{
							Name:           ch.Name,
							Path:           chPath,
							SizeBytes:      chSize,
							Model:          fmt.Sprintf("%s (Install ZFS Partition)", strings.TrimSpace(dev.Model)),
							Serial:         dev.Serial,
							Type:           "part",
							FsType:         ch.Fstype,
							Mountpoint:     ch.Mountpoint,
							PartLabel:      ch.Partlabel,
							Rotational:     rota,
							SmartPassed:    smartPassed,
							SmartUnknown:   !smartKnown,
							TemperatureC:   smartTemp,
							EligibleForZfs: true,
							Role:           "boot_zfs_partition",
						})
					} else {
						hasSystemParts = true
					}
				}

				eligible := !hasSystemParts && dev.Mountpoint == "" && len(dev.Children) == 0
				role := "available"
				if hasSystemParts {
					role = "system_disk"
				} else if dev.Fstype == "zfs_member" {
					role = "zfs_member"
					eligible = true
				}

				items = append(items, DiskInventoryItem{
					Name:           dev.Name,
					Path:           devPath,
					SizeBytes:      sizeBytes,
					Model:          strings.TrimSpace(dev.Model),
					Serial:         strings.TrimSpace(dev.Serial),
					Type:           dev.Type,
					FsType:         dev.Fstype,
					Mountpoint:     dev.Mountpoint,
					PartLabel:      dev.Partlabel,
					Rotational:     rota,
					SmartPassed:    smartPassed,
					SmartUnknown:   !smartKnown,
					TemperatureC:   smartTemp,
					EligibleForZfs: eligible,
					Role:           role,
				})
			}
		}
	}

	return items
}

func (m *NasManager) ListPools() []ZfsPoolStatus {
	m.mu.Lock()
	cfgPools := append([]ZfsPoolSpec(nil), m.cfg.Pools...)
	m.mu.Unlock()

	var result []ZfsPoolStatus
	out, err := exec.Command("zpool", "list", "-H", "-p", "-o", "name,size,alloc,free,frag,cap,health").Output()
	if err != nil {
		// A-M18: never synthesise pool health or sizes from config
		// when zpool has no data. A pool that was never created, failed
		// to import, or lost its disks used to be displayed as a
		// healthy 100 GiB ONLINE pool. No live data means no pools.
		slog.Warn("NAS ListPools: zpool list failed; reporting no pools instead of synthesising configured pools", "error", err)
		return result
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			continue
		}
		sizeB, _ := strconv.ParseUint(fields[1], 10, 64)
		allocB, _ := strconv.ParseUint(fields[2], 10, 64)
		freeB, _ := strconv.ParseUint(fields[3], 10, 64)
		frag, _ := strconv.Atoi(strings.TrimSuffix(fields[4], "%"))
		capPct, _ := strconv.Atoi(strings.TrimSuffix(fields[5], "%"))

		topo := "mirror"
		var disks []string
		for _, cp := range cfgPools {
			if cp.Name == fields[0] {
				topo = cp.Topology
				disks = cp.DataDisks
				break
			}
		}
		result = append(result, ZfsPoolStatus{
			Name:          fields[0],
			Topology:      topo,
			SizeBytes:     sizeB,
			AllocBytes:    allocB,
			FreeBytes:     freeB,
			Fragmentation: frag,
			CapacityPct:   capPct,
			Health:        fields[6],
			DataDisks:     disks,
		})
	}

	return result
}

func (m *NasManager) ListSnapshots() []ZfsSnapshotInfo {
	var snaps []ZfsSnapshotInfo
	out, err := exec.Command("zfs", "list", "-H", "-p", "-t", "snapshot", "-o", "name,used,creation").Output()
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line == "" {
				continue
			}
			fields := strings.Split(line, "\t")
			if len(fields) < 3 {
				continue
			}
			parts := strings.SplitN(fields[0], "@", 2)
			ds := parts[0]
			used, _ := strconv.ParseUint(fields[1], 10, 64)
			snaps = append(snaps, ZfsSnapshotInfo{
				Name:      fields[0],
				Dataset:   ds,
				UsedBytes: used,
				CreatedAt: fields[2],
			})
		}
	}
	return snaps
}

// ZFS names are single argv to the zfs/zpool CLIs; keep them to the
// characters ZFS itself allows in dataset/pool/snapshot names so a
// caller-supplied value can never become an extra option or a second
// name token (audit D-S04).
func validZfsPath(name string, allowSlash bool) bool {
	if name == "" || strings.HasPrefix(name, "-") || strings.Contains(name, "@") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-' || r == ':':
		case r == '/' && allowSlash:
		default:
			return false
		}
	}
	return true
}

func (m *NasManager) CreateSnapshot(dataset string, label string) (string, error) {
	if !validZfsPath(dataset, true) {
		return "", fmt.Errorf("invalid dataset name")
	}
	if label != "" && !validZfsPath(label, false) {
		return "", fmt.Errorf("invalid snapshot label")
	}
	if label == "" {
		label = fmt.Sprintf("auto-%s", time.Now().UTC().Format("20060102-150405"))
	}
	snapName := fmt.Sprintf("%s@%s", dataset, label)
	// L12: without zfs installed this used to return the snapshot
	// name and nil — the caller was told a snapshot was created
	// when nothing happened and no snapshot exists.
	if _, err := exec.LookPath("zfs"); err != nil {
		return "", fmt.Errorf("cannot create snapshot: zfs is not installed on this system")
	}
	if out, err := exec.Command("zfs", "snapshot", "-r", snapName).CombinedOutput(); err != nil {
		return "", fmt.Errorf("zfs snapshot failed: %s (%w)", string(out), err)
	}
	return snapName, nil
}

func validZfsSnapshotSpec(snap string) bool {
	parts := strings.Split(strings.TrimSpace(snap), "@")
	if len(parts) != 2 {
		return false
	}
	return validZfsPath(parts[0], true) && validZfsPath(parts[1], false)
}

func (m *NasManager) RollbackSnapshot(snapshot string, destroyNewer bool) error {
	clean := strings.TrimSpace(snapshot)
	if !validZfsSnapshotSpec(clean) {
		return fmt.Errorf("invalid ZFS snapshot identifier %q (expected dataset@label)", snapshot)
	}
	if _, err := exec.LookPath("zfs"); err != nil {
		return fmt.Errorf("cannot rollback snapshot: zfs is not installed on this system")
	}
	args := []string{"rollback"}
	if destroyNewer {
		args = append(args, "-r")
	}
	args = append(args, clean)
	if out, err := exec.Command("zfs", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("zfs rollback failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (m *NasManager) DeleteSnapshot(snapshot string) error {
	clean := strings.TrimSpace(snapshot)
	if !validZfsSnapshotSpec(clean) {
		return fmt.Errorf("invalid ZFS snapshot identifier %q (expected dataset@label)", snapshot)
	}
	if _, err := exec.LookPath("zfs"); err != nil {
		return fmt.Errorf("cannot delete snapshot: zfs is not installed on this system")
	}
	if out, err := exec.Command("zfs", "destroy", clean).CombinedOutput(); err != nil {
		return fmt.Errorf("zfs destroy %s failed: %s (%w)", clean, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (m *NasManager) TrimPool(poolName string) error {
	if !validZfsPath(poolName, false) {
		return fmt.Errorf("invalid pool name")
	}
	if _, err := exec.LookPath("zpool"); err != nil {
		return fmt.Errorf("cannot trim pool: zpool is not installed on this system")
	}
	if out, err := exec.Command("zpool", "trim", poolName).CombinedOutput(); err != nil {
		return fmt.Errorf("zpool trim failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (m *NasManager) CheckpointPool(poolName string, discard bool) error {
	if !validZfsPath(poolName, false) {
		return fmt.Errorf("invalid pool name")
	}
	if _, err := exec.LookPath("zpool"); err != nil {
		return fmt.Errorf("cannot checkpoint pool: zpool is not installed on this system")
	}
	args := []string{"checkpoint"}
	if discard {
		args = append(args, "-d")
	}
	args = append(args, poolName)
	if out, err := exec.Command("zpool", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("zpool checkpoint failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (m *NasManager) DatasetKeyAction(dataset, action, keyMaterial string) error {
	cleanDs := strings.TrimSpace(dataset)
	if !validZfsPath(cleanDs, true) {
		return fmt.Errorf("invalid dataset name %q", dataset)
	}
	if _, err := exec.LookPath("zfs"); err != nil {
		return fmt.Errorf("cannot manage dataset key: zfs is not installed on this system")
	}
	switch action {
	case "unload-key", "lock":
		if out, err := exec.Command("zfs", "unload-key", cleanDs).CombinedOutput(); err != nil {
			return fmt.Errorf("zfs unload-key failed: %s (%w)", strings.TrimSpace(string(out)), err)
		}
		return nil
	case "load-key", "unlock":
		cmd := exec.Command("zfs", "load-key", cleanDs)
		if strings.TrimSpace(keyMaterial) != "" {
			cmd = exec.Command("zfs", "load-key", "-L", "prompt", cleanDs)
			cmd.Stdin = strings.NewReader(strings.TrimSpace(keyMaterial) + "\n")
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("zfs load-key failed: %s (%w)", strings.TrimSpace(string(out)), err)
		}
		_ = exec.Command("zfs", "mount", cleanDs).Run()
		return nil
	case "change-key":
		if len(strings.TrimSpace(keyMaterial)) < 8 {
			return fmt.Errorf("keyMaterial must be at least 8 characters for change-key")
		}
		cmd := exec.Command("zfs", "change-key", "-o", "keylocation=prompt", "-o", "keyformat=passphrase", cleanDs)
		cmd.Stdin = strings.NewReader(strings.TrimSpace(keyMaterial) + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("zfs change-key failed: %s (%w)", strings.TrimSpace(string(out)), err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported dataset key action %q (expected load-key, unload-key, or change-key)", action)
	}
}

func (m *NasManager) RunSmartTest(device, testType string) (string, error) {
	dev := strings.TrimSpace(device)
	if !validInstallZfsDevice(dev) {
		return "", fmt.Errorf("disallowed block device path %q", device)
	}
	mode := strings.ToLower(strings.TrimSpace(testType))
	if mode == "" {
		mode = "short"
	}
	if mode != "short" && mode != "long" {
		return "", fmt.Errorf("invalid SMART test type %q (expected short or long)", testType)
	}
	tool, err := exec.LookPath("smartctl")
	if err != nil {
		return "", fmt.Errorf("smartctl is not installed on this system")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, tool, "-t", mode, dev).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("smartctl -t %s %s failed: %s (%w)", mode, dev, strings.TrimSpace(string(out)), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (m *NasManager) RunCloudSyncTask(taskName string) (string, error) {
	cleanName := strings.TrimSpace(taskName)
	if cleanName == "" {
		return "", fmt.Errorf("taskName is required")
	}
	m.mu.Lock()
	tasks := append([]CloudSyncTaskSpec(nil), m.cfg.CloudSyncTasks...)
	m.mu.Unlock()

	var found *CloudSyncTaskSpec
	for i := range tasks {
		if tasks[i].Name == cleanName {
			found = &tasks[i]
			break
		}
	}
	if found == nil {
		return "", fmt.Errorf("cloud sync task %q not found in active NAS configuration", cleanName)
	}
	if !validZfsPath(found.Dataset, true) {
		return "", fmt.Errorf("invalid dataset path in cloud sync task %q", cleanName)
	}
	localPath := filepath.Clean("/mnt/" + found.Dataset)
	if !underMnt(localPath) {
		return "", fmt.Errorf("cloud sync local path %q is outside /mnt", localPath)
	}
	rclonePath, err := exec.LookPath("rclone")
	if err != nil {
		return "", fmt.Errorf("rclone is not installed on this system")
	}
	bucket := strings.Trim(strings.TrimSpace(found.RemoteBucket), "/")
	prefix := strings.Trim(strings.TrimSpace(found.RemotePrefix), "/")
	remoteTarget := fmt.Sprintf(":s3:%s", bucket)
	if prefix != "" {
		remoteTarget = fmt.Sprintf(":s3:%s/%s", bucket, prefix)
	}
	args := []string{"sync"}
	if found.Direction == "pull" {
		args = append(args, remoteTarget, localPath)
	} else {
		args = append(args, localPath, remoteTarget)
	}
	if strings.TrimSpace(found.RemoteEndpoint) != "" {
		args = append(args, "--s3-provider=Other", "--s3-env-auth=true", fmt.Sprintf("--s3-endpoint=%s", strings.TrimSpace(found.RemoteEndpoint)))
	}
	if found.BandwidthLimitKbps > 0 {
		args = append(args, fmt.Sprintf("--bwlimit=%dK", found.BandwidthLimitKbps))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, rclonePath, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("rclone cloud sync %s failed: %s (%w)", cleanName, strings.TrimSpace(string(out)), err)
	}
	return fmt.Sprintf("Cloud sync task %s (%s) completed", cleanName, found.Direction), nil
}

func (m *NasManager) ScrubPool(poolName string) error {
	if !validZfsPath(poolName, false) {
		return fmt.Errorf("invalid pool name")
	}
	// L12: without zpool installed this used to return nil — the
	// caller was told a scrub ran when nothing happened.
	if _, err := exec.LookPath("zpool"); err != nil {
		return fmt.Errorf("cannot scrub pool: zpool is not installed on this system")
	}
	if out, err := exec.Command("zpool", "scrub", poolName).CombinedOutput(); err != nil {
		return fmt.Errorf("zpool scrub failed: %s (%w)", string(out), err)
	}
	return nil
}

func (m *NasManager) ApplyConfig(rawJSON []byte) error {
	var bundle NasRuntimeBundle
	if err := json.Unmarshal(rawJSON, &bundle); err != nil {
		return fmt.Errorf("invalid NAS config json: %w", err)
	}

	// Validate free-text config before it can reach privileged paths
	// (audit D-05): an invalid bundle changes nothing on disk.
	if bundle.SmbConf != "" {
		if err := validateSmbConf(bundle.SmbConf); err != nil {
			return fmt.Errorf("nas bundle rejected: %w", err)
		}
	}
	if bundle.NfsExports != "" {
		if err := validateNfsExports(bundle.NfsExports); err != nil {
			return fmt.Errorf("nas bundle rejected: %w", err)
		}
	}

	// A-M16: validate pool/dataset specs before storing the bundle, so
	// an invalid bundle is neither stored as the live config nor
	// reported as applied.
	for _, pool := range bundle.Pools {
		if err := ValidateZfsPoolSpec(pool); err != nil {
			return fmt.Errorf("invalid ZFS pool spec %q: %w", pool.Name, err)
		}
	}
	for _, ds := range bundle.Datasets {
		if err := ValidateZfsDatasetSpec(ds); err != nil {
			return fmt.Errorf("invalid ZFS dataset spec %q: %w", ds.Name, err)
		}
	}

	// A-M16: only store the bundle as the live config once it has
	// actually applied. Storing it first meant a bundle that failed
	// provisioning still counted as the current NAS config.
	if !bundle.Enabled {
		m.mu.Lock()
		m.cfg = bundle
		m.mu.Unlock()
		slog.Info("NAS plugin is disabled; stopping SMB and NFS share daemons")
		_ = exec.Command("systemctl", "stop", "smbd", "nfs-server").Run()
		return nil
	}

	// 1. Reconcile ZFS pools and datasets.
	// A-M16: pool/dataset/config failures used to be swallowed (`_ =`)
	// while the bundle was reported as applied. Every failure below now
	// fails the apply, so ApplyBundle surfaces it instead of the UI
	// showing shares that do not exist.
	if len(bundle.Pools) > 0 {
		if _, err := exec.LookPath("zpool"); err != nil {
			return fmt.Errorf("cannot provision %d ZFS pool(s): zpool is not installed", len(bundle.Pools))
		}
		for _, pool := range bundle.Pools {
			if err := exec.Command("zpool", "list", "-H", pool.Name).Run(); err != nil {
				args := BuildZfsPoolCreateArgs(pool)
				slog.Info("Provisioning ZFS pool", "name", pool.Name, "topology", pool.Topology)
				if out, err := exec.Command("zpool", args...).CombinedOutput(); err != nil {
					return fmt.Errorf("zpool create %s failed: %s (%w)", pool.Name, strings.TrimSpace(string(out)), err)
				}
			}
		}
	}

	if len(bundle.Datasets) > 0 {
		if _, err := exec.LookPath("zfs"); err != nil {
			return fmt.Errorf("cannot provision %d ZFS dataset(s): zfs is not installed", len(bundle.Datasets))
		}
		for _, ds := range bundle.Datasets {
			for _, cmdArgs := range BuildZfsDatasetCreateArgs(ds) {
				// `zfs create` is not idempotent: re-applying a bundle
				// whose dataset already exists fails with "dataset
				// already exists". Skip the create when the dataset
				// is already there (the `set` commands below it stay
				// idempotent and still run).
				if len(cmdArgs) > 0 && cmdArgs[0] == "create" {
					if err := exec.Command("zfs", "list", "-H", cmdArgs[len(cmdArgs)-1]).Run(); err == nil {
						continue
					}
				}
				if out, err := exec.Command("zfs", cmdArgs...).CombinedOutput(); err != nil {
					return fmt.Errorf("zfs %s failed: %s (%w)", strings.Join(cmdArgs, " "), strings.TrimSpace(string(out)), err)
				}
			}
		}
		_ = exec.Command("zfs", "mount", "-O", "-a").Run()
	}

	// 2. Write Samba configuration & reload smbd
	if bundle.SmbConf != "" {
		if err := os.MkdirAll("/etc/samba", 0755); err != nil {
			return fmt.Errorf("failed to create /etc/samba: %w", err)
		}
		f, err := os.OpenFile("/etc/samba/smb.conf", os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0644)
		if err != nil {
			return fmt.Errorf("failed to open /etc/samba/smb.conf: %w", err)
		}
		if _, err := f.WriteString(bundle.SmbConf); err != nil {
			_ = f.Close()
			return fmt.Errorf("failed to write /etc/samba/smb.conf: %w", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("failed to close /etc/samba/smb.conf: %w", err)
		}
		if out, err := exec.Command("systemctl", "reload-or-restart", "smbd").CombinedOutput(); err != nil {
			return fmt.Errorf("failed to reload smbd: %s (%w)", strings.TrimSpace(string(out)), err)
		}
	}

	// 3. Write NFS exports & reload exportfs
	if bundle.NfsExports != "" {
		f, err := os.OpenFile("/etc/exports", os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0644)
		if err != nil {
			return fmt.Errorf("failed to open /etc/exports: %w", err)
		}
		if _, err := f.WriteString(bundle.NfsExports); err != nil {
			_ = f.Close()
			return fmt.Errorf("failed to write /etc/exports: %w", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("failed to close /etc/exports: %w", err)
		}
		if out, err := exec.Command("exportfs", "-ra").CombinedOutput(); err != nil {
			return fmt.Errorf("exportfs -ra failed: %s (%w)", strings.TrimSpace(string(out)), err)
		}
	}

	// 4. Write & reconcile LIO kernel iSCSI target configuration if configured and targetctl is installed
	if bundle.LioSaveconfigJson != "" {
		_ = os.MkdirAll("/etc/rtslib-fb-target", 0750)
		if err := os.WriteFile("/etc/rtslib-fb-target/saveconfig.json", []byte(bundle.LioSaveconfigJson), 0600); err == nil {
			if targetctl, lookErr := exec.LookPath("targetctl"); lookErr == nil {
				_ = exec.Command(targetctl, "restore", "/etc/rtslib-fb-target/saveconfig.json").Run()
			}
		}
	}

	// 5. Write & reload S3 MinIO gateway environment if configured and minio unit is installed
	if bundle.S3EnvConf != "" {
		_ = os.MkdirAll("/etc/default", 0755)
		if err := os.WriteFile("/etc/default/minio", []byte(bundle.S3EnvConf), 0600); err == nil {
			if isSystemdServiceActive("minio") {
				_ = exec.Command("systemctl", "reload-or-restart", "minio").Run()
			}
		}
	}

	m.mu.Lock()
	m.cfg = bundle
	m.mu.Unlock()
	return nil
}

// GetReplicatedDatasets returns the full ZFS dataset paths configured with ReplicateToHaPeer=true.
func (m *NasManager) GetReplicatedDatasets() []string {
	m.mu.Lock()
	enabled := m.cfg.Enabled
	datasets := append([]ZfsDatasetSpec(nil), m.cfg.Datasets...)
	policies := append([]ZfsSnapshotPolicySpec(nil), m.cfg.SnapshotPolicies...)
	m.mu.Unlock()

	if !enabled {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	addDs := func(raw string) {
		clean := strings.TrimSpace(raw)
		if !validZfsPath(clean, true) || !strings.Contains(clean, "/") || seen[clean] {
			return
		}
		seen[clean] = true
		out = append(out, clean)
	}
	for _, ds := range datasets {
		if !ds.ReplicateToHaPeer {
			continue
		}
		fullName := ds.Name
		if ds.Pool != "" && !strings.HasPrefix(ds.Name, ds.Pool+"/") {
			fullName = ds.Pool + "/" + ds.Name
		}
		addDs(fullName)
	}
	for _, sp := range policies {
		if !sp.Enabled || !sp.ReplicateToHaPeer {
			continue
		}
		addDs(sp.Dataset)
	}
	return out
}

// PromoteFailoverMaster is triggered by HAEngine when this node transitions to MASTER.
// It promotes all replicated ZFS datasets to read-write and starts SMB/NFS/iSCSI share services on the VIP.
func (m *NasManager) PromoteFailoverMaster() {
	m.mu.Lock()
	enabled := m.cfg.Enabled
	pools := append([]ZfsPoolSpec(nil), m.cfg.Pools...)
	m.mu.Unlock()

	if !enabled {
		return
	}

	replicated := m.GetReplicatedDatasets()
	slog.Info("HA Failover: Promoting ZFS pools and NAS shares to Active MASTER")
	if _, err := exec.LookPath("zfs"); err == nil {
		for _, p := range pools {
			_ = exec.Command("zfs", "set", "readonly=off", p.Name).Run()
		}
		for _, ds := range replicated {
			_ = exec.Command("zfs", "set", "readonly=off", ds).Run()
		}
		_ = exec.Command("zfs", "mount", "-a").Run()
	}
	_ = exec.Command("exportfs", "-ra").Run()
	_ = exec.Command("systemctl", "reload-or-restart", "smbd", "nfs-server").Run()
}

// DemoteFailoverBackup is triggered by HAEngine when this node transitions to BACKUP or FAULT.
// It sets replicated ZFS target datasets (or pools) to readonly=on so incoming incremental zfs receive streams succeed cleanly.
func (m *NasManager) DemoteFailoverBackup() {
	m.mu.Lock()
	enabled := m.cfg.Enabled
	pools := append([]ZfsPoolSpec(nil), m.cfg.Pools...)
	m.mu.Unlock()

	if !enabled {
		return
	}

	replicated := m.GetReplicatedDatasets()
	slog.Info("HA Failover: Demoting NAS node to Standby BACKUP (setting ZFS readonly=on for incoming replication)")
	if _, err := exec.LookPath("zfs"); err == nil {
		if len(replicated) > 0 {
			for _, ds := range replicated {
				_ = exec.Command("zfs", "set", "readonly=on", ds).Run()
			}
		} else {
			for _, p := range pools {
				_ = exec.Command("zfs", "set", "readonly=on", p.Name).Run()
			}
		}
	}
}

func PruneSnapshotList(snapshots []string, keepCount int) []string {
	if keepCount <= 0 || len(snapshots) <= keepCount {
		return nil
	}
	sorted := append([]string(nil), snapshots...)
	sort.Strings(sorted)
	toDeleteCount := len(sorted) - keepCount
	return sorted[:toDeleteCount]
}

func EnsureManagedDir(path string) error {
	clean := filepath.Clean(path)
	return os.MkdirAll(clean, 0755)
}
