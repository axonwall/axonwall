package engine

import (
	"bufio"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type ZfsArcTelemetry struct {
	Available          bool    `json:"available"`
	Hits               uint64  `json:"hits"`
	Misses             uint64  `json:"misses"`
	HitRatioPct        float64 `json:"hitRatioPct"`
	DemandDataHits     uint64  `json:"demandDataHits"`
	DemandMetadataHits uint64  `json:"demandMetadataHits"`
	SizeBytes          uint64  `json:"sizeBytes"`
	TargetMaxBytes     uint64  `json:"targetMaxBytes"`
	MinSizeBytes       uint64  `json:"minSizeBytes"`
	L2Hits             uint64  `json:"l2Hits"`
	L2Misses           uint64  `json:"l2Misses"`
	L2SizeBytes        uint64  `json:"l2SizeBytes"`
}

type ZfsZilTelemetry struct {
	Available            bool   `json:"available"`
	CommitCount          uint64 `json:"commitCount"`
	CommitWriterCount    uint64 `json:"commitWriterCount"`
	ItxCount             uint64 `json:"itxCount"`
	ItxMetaslabNormalCnt uint64 `json:"itxMetaslabNormalCount"`
	ItxMetaslabSlogCnt   uint64 `json:"itxMetaslabSlogCount"`
	SlogBytesWritten     uint64 `json:"slogBytesWritten"`
}

type ZfsPoolIoKstat struct {
	Pool             string `json:"pool"`
	NReadBytes       uint64 `json:"nreadBytes"`
	NWrittenBytes    uint64 `json:"nwrittenBytes"`
	Reads            uint64 `json:"reads"`
	Writes           uint64 `json:"writes"`
	WaitQueueDepth   uint64 `json:"waitQueueDepth"`
	ActiveQueueDepth uint64 `json:"activeQueueDepth"`
}

type NasShareDaemonTelemetry struct {
	SmbActive        bool `json:"smbActive"`
	NfsActive        bool `json:"nfsActive"`
	IscsiActive      bool `json:"iscsiActive"`
	ActiveSmbClients int  `json:"activeSmbClients"`
	NfsExportCount   int  `json:"nfsExportCount"`
}

type NasDeepTelemetry struct {
	Timestamp   string                  `json:"timestamp"`
	Pools       []ZfsPoolStatus         `json:"pools"`
	Snapshots   []ZfsSnapshotInfo       `json:"snapshots"`
	Arc         ZfsArcTelemetry         `json:"arc"`
	Zil         ZfsZilTelemetry         `json:"zil"`
	PoolIoStats []ZfsPoolIoKstat        `json:"poolIoStats"`
	ShareStatus NasShareDaemonTelemetry `json:"shareStatus"`
}

// ParseZfsKstatKeyValues parses a standard OpenZFS /proc/spl/kstat/zfs/<file>
// table ("name type data" rows) into a uint64 map.
func ParseZfsKstatKeyValues(raw string) map[string]uint64 {
	out := make(map[string]uint64)
	sc := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || lineNum <= 2 {
			// First two lines of SPL kstats are header metadata + "name type data"
			if strings.HasPrefix(line, "name") || strings.Count(line, " ") > 4 {
				continue
			}
		}
		fields := strings.Fields(line)
		if len(fields) == 3 {
			if val, err := strconv.ParseUint(fields[2], 10, 64); err == nil {
				out[fields[0]] = val
			}
		}
	}
	return out
}

// ParseZfsArcstats extracts ARC & L2ARC hit ratios and memory pressure metrics.
func ParseZfsArcstats(raw string) ZfsArcTelemetry {
	kv := ParseZfsKstatKeyValues(raw)
	if len(kv) == 0 {
		return ZfsArcTelemetry{Available: false}
	}
	hits := kv["hits"]
	misses := kv["misses"]
	total := hits + misses
	ratio := 0.0
	if total > 0 {
		ratio = math.Round((float64(hits)/float64(total))*10000) / 100
	}
	return ZfsArcTelemetry{
		Available:          true,
		Hits:               hits,
		Misses:             misses,
		HitRatioPct:        ratio,
		DemandDataHits:     kv["demand_data_hits"],
		DemandMetadataHits: kv["demand_metadata_hits"],
		SizeBytes:          kv["size"],
		TargetMaxBytes:     kv["c_max"],
		MinSizeBytes:       kv["c_min"],
		L2Hits:             kv["l2_hits"],
		L2Misses:           kv["l2_misses"],
		L2SizeBytes:        kv["l2_size"],
	}
}

// ParseZfsZilStats extracts ZFS Intent Log (ZIL) and NVMe SLOG synchronous commit counters.
func ParseZfsZilStats(raw string) ZfsZilTelemetry {
	kv := ParseZfsKstatKeyValues(raw)
	if len(kv) == 0 {
		return ZfsZilTelemetry{Available: false}
	}
	return ZfsZilTelemetry{
		Available:            true,
		CommitCount:          kv["zil_commit_count"],
		CommitWriterCount:    kv["zil_commit_writer_count"],
		ItxCount:             kv["zil_itx_count"],
		ItxMetaslabNormalCnt: kv["zil_itx_metaslab_normal_count"],
		ItxMetaslabSlogCnt:   kv["zil_itx_metaslab_slog_count"],
		SlogBytesWritten:     kv["zil_itx_metaslab_slog_bytes"],
	}
}

// ParseZfsPoolIoKstat parses /proc/spl/kstat/zfs/<pool>/io tabular ZIO queue counters.
func ParseZfsPoolIoKstat(poolName, raw string) (ZfsPoolIoKstat, bool) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) < 3 {
		return ZfsPoolIoKstat{}, false
	}
	// Last non-empty line holds: nread nwritten reads writes wtime wlentime wupdate rtime rlentime rupdate wcnt rcnt
	dataLine := strings.TrimSpace(lines[len(lines)-1])
	fields := strings.Fields(dataLine)
	if len(fields) < 12 {
		return ZfsPoolIoKstat{}, false
	}
	nread, err1 := strconv.ParseUint(fields[0], 10, 64)
	nwritten, err2 := strconv.ParseUint(fields[1], 10, 64)
	reads, err3 := strconv.ParseUint(fields[2], 10, 64)
	writes, err4 := strconv.ParseUint(fields[3], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return ZfsPoolIoKstat{}, false
	}
	wcnt, _ := strconv.ParseUint(fields[10], 10, 64)
	rcnt, _ := strconv.ParseUint(fields[11], 10, 64)
	return ZfsPoolIoKstat{
		Pool:             poolName,
		NReadBytes:       nread,
		NWrittenBytes:    nwritten,
		Reads:            reads,
		Writes:           writes,
		WaitQueueDepth:   wcnt,
		ActiveQueueDepth: rcnt,
	}, true
}

func (m *NasManager) GetDeepTelemetry() NasDeepTelemetry {
	pools := m.ListPools()
	snaps := m.ListSnapshots()

	var arc ZfsArcTelemetry
	if b, err := os.ReadFile("/proc/spl/kstat/zfs/arcstats"); err == nil {
		arc = ParseZfsArcstats(string(b))
	}

	var zil ZfsZilTelemetry
	if b, err := os.ReadFile("/proc/spl/kstat/zfs/zil"); err == nil {
		zil = ParseZfsZilStats(string(b))
	}

	var poolStats []ZfsPoolIoKstat
	for _, p := range pools {
		ioPath := filepath.Join("/proc/spl/kstat/zfs", p.Name, "io")
		if b, err := os.ReadFile(ioPath); err == nil {
			if st, ok := ParseZfsPoolIoKstat(p.Name, string(b)); ok {
				poolStats = append(poolStats, st)
			}
		}
	}

	smbActive := exec.Command("systemctl", "is-active", "--quiet", "smbd").Run() == nil
	nfsActive := exec.Command("systemctl", "is-active", "--quiet", "nfs-server").Run() == nil
	iscsiActive := exec.Command("systemctl", "is-active", "--quiet", "rtslib-fb-targetctl").Run() == nil ||
		exec.Command("systemctl", "is-active", "--quiet", "tgt").Run() == nil

	nfsExports := 0
	if expBytes, err := os.ReadFile("/etc/exports"); err == nil {
		for _, line := range strings.Split(string(expBytes), "\n") {
			t := strings.TrimSpace(line)
			if t != "" && !strings.HasPrefix(t, "#") {
				nfsExports++
			}
		}
	}

	smbClients := 0
	if smbActive {
		if out, err := exec.Command("smbstatus", "-b", "-n").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				f := strings.Fields(line)
				if len(f) >= 4 {
					if _, pErr := strconv.Atoi(f[0]); pErr == nil {
						smbClients++
					}
				}
			}
		}
	}

	return NasDeepTelemetry{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Pools:       pools,
		Snapshots:   snaps,
		Arc:         arc,
		Zil:         zil,
		PoolIoStats: poolStats,
		ShareStatus: NasShareDaemonTelemetry{
			SmbActive:        smbActive,
			NfsActive:        nfsActive,
			IscsiActive:      iscsiActive,
			ActiveSmbClients: smbClients,
			NfsExportCount:   nfsExports,
		},
	}
}
