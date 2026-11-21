package engine

import (
	"bufio"
	"errors"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	maxKernelBpfProgEnum = 512
	maxKernelBpfMapEnum  = 1024
)

type BpfProgramInventoryItem struct {
	ID              uint32 `json:"id"`
	Type            string `json:"type"`
	Name            string `json:"name"`
	Tag             string `json:"tag"`
	JitedBytes      uint32 `json:"jitedBytes"`
	TranslatedBytes int    `json:"translatedBytes"`
	VerifiedInsns   uint32 `json:"verifiedInsns"`
	MemlockBytes    uint64 `json:"memlockBytes"`
	MapCount        int    `json:"mapCount"`
	HasBTF          bool   `json:"hasBtf"`
	CreatedByUID    uint32 `json:"createdByUid"`
	RunCount        uint64 `json:"runCount"`
	RunTimeNs       int64  `json:"runTimeNs"`
	RecursionMisses uint64 `json:"recursionMisses"`
}

type BpfMapInventoryItem struct {
	ID           uint32 `json:"id"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	KeySize      uint32 `json:"keySize"`
	ValueSize    uint32 `json:"valueSize"`
	MaxEntries   uint32 `json:"maxEntries"`
	MemlockBytes uint64 `json:"memlockBytes"`
	Frozen       bool   `json:"frozen"`
	HasBTF       bool   `json:"hasBtf"`
}

type BpfTypeAggregate struct {
	Type           string `json:"type"`
	Count          int    `json:"count"`
	TotalBytes     uint64 `json:"totalBytes"`
	TotalRunTimeNs int64  `json:"totalRunTimeNs"`
	TotalRunCount  uint64 `json:"totalRunCount"`
}

type KernelBpfInventory struct {
	Timestamp             string                    `json:"timestamp"`
	Available             bool                      `json:"available"`
	Error                 string                    `json:"error,omitempty"`
	StatsEnabled          bool                      `json:"statsEnabled"`
	TotalPrograms         int                       `json:"totalPrograms"`
	TotalMaps             int                       `json:"totalMaps"`
	TotalJitedBytes       uint64                    `json:"totalJitedBytes"`
	TotalProgMemlockBytes uint64                    `json:"totalProgMemlockBytes"`
	TotalMapMemlockBytes  uint64                    `json:"totalMapMemlockBytes"`
	ProgramsByType        []BpfTypeAggregate        `json:"programsByType"`
	MapsByType            []BpfTypeAggregate        `json:"mapsByType"`
	Programs              []BpfProgramInventoryItem `json:"programs"`
	Maps                  []BpfMapInventoryItem     `json:"maps"`
}

type KernelTcpSnmpTelemetry struct {
	Available          bool    `json:"available"`
	InSegs             uint64  `json:"inSegs"`
	OutSegs            uint64  `json:"outSegs"`
	RetransSegs        uint64  `json:"retransSegs"`
	RetransmitRatioPct float64 `json:"retransmitRatioPct"`
	CurrEstab          uint64  `json:"currEstab"`
	AttemptFails       uint64  `json:"attemptFails"`
	EstabResets        uint64  `json:"estabResets"`
	InErrs             uint64  `json:"inErrs"`
	OutRsts            uint64  `json:"outRsts"`
}

type KernelUdpSnmpTelemetry struct {
	Available    bool   `json:"available"`
	InDatagrams  uint64 `json:"inDatagrams"`
	OutDatagrams uint64 `json:"outDatagrams"`
	NoPorts      uint64 `json:"noPorts"`
	InErrors     uint64 `json:"inErrors"`
	RcvbufErrors uint64 `json:"rcvbufErrors"`
	SndbufErrors uint64 `json:"sndbufErrors"`
}

type KernelCgroupThrottleTelemetry struct {
	Available        bool    `json:"available"`
	SourcePath       string  `json:"sourcePath,omitempty"`
	NrPeriods        uint64  `json:"nrPeriods"`
	NrThrottled      uint64  `json:"nrThrottled"`
	ThrottledUsec    uint64  `json:"throttledUsec"`
	ThrottleRatioPct float64 `json:"throttleRatioPct"`
}

type KernelMemoryPressureTelemetry struct {
	Available       bool    `json:"available"`
	OomKillCount    uint64  `json:"oomKillCount"`
	MajorPageFaults uint64  `json:"majorPageFaults"`
	AllocStalls     uint64  `json:"allocStalls"`
	PsiSomeAvg10    float64 `json:"psiSomeAvg10"`
	PsiFullAvg10    float64 `json:"psiFullAvg10"`
	PsiAvailable    bool    `json:"psiAvailable"`
}

type KernelRcaTelemetry struct {
	Timestamp string                         `json:"timestamp"`
	Tcp       KernelTcpSnmpTelemetry         `json:"tcp"`
	Udp       KernelUdpSnmpTelemetry         `json:"udp"`
	CgroupCpu KernelCgroupThrottleTelemetry  `json:"cgroupCpu"`
	Memory    KernelMemoryPressureTelemetry `json:"memory"`
}

func inspectBpfProgram(id ebpf.ProgramID) (BpfProgramInventoryItem, bool) {
	prog, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return BpfProgramInventoryItem{}, false
	}
	defer prog.Close()

	info, err := prog.Info()
	if err != nil || info == nil {
		return BpfProgramInventoryItem{}, false
	}

	resolvedID := uint32(id)
	if infoID, ok := info.ID(); ok {
		resolvedID = uint32(infoID)
	}
	jitedBytes, _ := info.JitedSize()
	translatedBytes, _ := info.TranslatedSize()
	verifiedInsns, _ := info.VerifiedInstructions()
	memlockBytes, _ := info.Memlock()
	mapIDs, _ := info.MapIDs()
	btfID, hasBtf := info.BTFID()
	createdUID, _ := info.CreatedByUID()

	name := strings.TrimSpace(info.Name)
	if name == "" {
		name = "prog_" + strconv.FormatUint(uint64(resolvedID), 10)
	}

	item := BpfProgramInventoryItem{
		ID:              resolvedID,
		Type:            info.Type.String(),
		Name:            name,
		Tag:             info.Tag,
		JitedBytes:      jitedBytes,
		TranslatedBytes: translatedBytes,
		VerifiedInsns:   verifiedInsns,
		MemlockBytes:    memlockBytes,
		MapCount:        len(mapIDs),
		HasBTF:          hasBtf && btfID > 0,
		CreatedByUID:    createdUID,
	}

	if stats, err := prog.Stats(); err == nil && stats != nil {
		item.RunCount = stats.RunCount
		item.RunTimeNs = stats.Runtime.Nanoseconds()
		item.RecursionMisses = stats.RecursionMisses
	}

	return item, true
}

func inspectBpfMap(id ebpf.MapID) (BpfMapInventoryItem, bool) {
	m, err := ebpf.NewMapFromID(id)
	if err != nil {
		return BpfMapInventoryItem{}, false
	}
	defer m.Close()

	info, err := m.Info()
	if err != nil || info == nil {
		return BpfMapInventoryItem{}, false
	}

	resolvedID := uint32(id)
	if infoID, ok := info.ID(); ok {
		resolvedID = uint32(infoID)
	}
	memlockBytes, _ := info.Memlock()
	btfID, hasBtf := info.BTFID()

	name := strings.TrimSpace(info.Name)
	if name == "" {
		name = "map_" + strconv.FormatUint(uint64(resolvedID), 10)
	}

	return BpfMapInventoryItem{
		ID:           resolvedID,
		Type:         info.Type.String(),
		Name:         name,
		KeySize:      info.KeySize,
		ValueSize:    info.ValueSize,
		MaxEntries:   info.MaxEntries,
		MemlockBytes: memlockBytes,
		Frozen:       info.Frozen(),
		HasBTF:       hasBtf && btfID > 0,
	}, true
}

func summarizeBpfInventory(progs []BpfProgramInventoryItem, maps []BpfMapInventoryItem) (
	totalJited uint64,
	totalProgMemlock uint64,
	totalMapMemlock uint64,
	progsByType []BpfTypeAggregate,
	mapsByType []BpfTypeAggregate,
) {
	progsByType = []BpfTypeAggregate{}
	mapsByType = []BpfTypeAggregate{}

	progAggMap := make(map[string]*BpfTypeAggregate)
	for _, p := range progs {
		totalJited += uint64(p.JitedBytes)
		totalProgMemlock += p.MemlockBytes
		agg, ok := progAggMap[p.Type]
		if !ok {
			agg = &BpfTypeAggregate{Type: p.Type}
			progAggMap[p.Type] = agg
		}
		agg.Count++
		agg.TotalBytes += uint64(p.JitedBytes)
		agg.TotalRunTimeNs += p.RunTimeNs
		agg.TotalRunCount += p.RunCount
	}
	for _, agg := range progAggMap {
		progsByType = append(progsByType, *agg)
	}
	sort.Slice(progsByType, func(i, j int) bool {
		if progsByType[i].Count != progsByType[j].Count {
			return progsByType[i].Count > progsByType[j].Count
		}
		return progsByType[i].Type < progsByType[j].Type
	})

	mapAggMap := make(map[string]*BpfTypeAggregate)
	for _, m := range maps {
		totalMapMemlock += m.MemlockBytes
		agg, ok := mapAggMap[m.Type]
		if !ok {
			agg = &BpfTypeAggregate{Type: m.Type}
			mapAggMap[m.Type] = agg
		}
		agg.Count++
		agg.TotalBytes += m.MemlockBytes
	}
	for _, agg := range mapAggMap {
		mapsByType = append(mapsByType, *agg)
	}
	sort.Slice(mapsByType, func(i, j int) bool {
		if mapsByType[i].TotalBytes != mapsByType[j].TotalBytes {
			return mapsByType[i].TotalBytes > mapsByType[j].TotalBytes
		}
		if mapsByType[i].Count != mapsByType[j].Count {
			return mapsByType[i].Count > mapsByType[j].Count
		}
		return mapsByType[i].Type < mapsByType[j].Type
	})

	return totalJited, totalProgMemlock, totalMapMemlock, progsByType, mapsByType
}

// CollectKernelBpfInventory enumerates all loaded kernel eBPF programs and maps via
// sys_bpf GET_NEXT_ID / GET_FD_BY_ID without requiring bpftool subprocesses.
func CollectKernelBpfInventory() KernelBpfInventory {
	inv := KernelBpfInventory{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		ProgramsByType: []BpfTypeAggregate{},
		MapsByType:     []BpfTypeAggregate{},
		Programs:       []BpfProgramInventoryItem{},
		Maps:           []BpfMapInventoryItem{},
	}

	if raw, err := os.ReadFile("/proc/sys/kernel/bpf_stats_enabled"); err == nil {
		inv.StatsEnabled = strings.TrimSpace(string(raw)) == "1"
	}

	var progs []BpfProgramInventoryItem
	var lastProgID ebpf.ProgramID
	for count := 0; count < maxKernelBpfProgEnum; count++ {
		nextID, err := ebpf.ProgramGetNextID(lastProgID)
		if err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) || errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
				inv.Available = false
				inv.Error = "Insufficient privilege (CAP_BPF) to enumerate host BPF programs"
				return inv
			}
			inv.Available = false
			inv.Error = err.Error()
			return inv
		}
		lastProgID = nextID
		if item, ok := inspectBpfProgram(nextID); ok {
			if item.RunCount > 0 || item.RunTimeNs > 0 {
				inv.StatsEnabled = true
			}
			progs = append(progs, item)
		}
	}

	var maps []BpfMapInventoryItem
	var lastMapID ebpf.MapID
	for count := 0; count < maxKernelBpfMapEnum; count++ {
		nextID, err := ebpf.MapGetNextID(lastMapID)
		if err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) || errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
				inv.Available = false
				inv.Error = "Insufficient privilege (CAP_BPF) to enumerate host BPF maps"
				return inv
			}
			break
		}
		lastMapID = nextID
		if item, ok := inspectBpfMap(nextID); ok {
			maps = append(maps, item)
		}
	}

	sort.Slice(progs, func(i, j int) bool {
		if progs[i].RunTimeNs != progs[j].RunTimeNs {
			return progs[i].RunTimeNs > progs[j].RunTimeNs
		}
		if progs[i].JitedBytes != progs[j].JitedBytes {
			return progs[i].JitedBytes > progs[j].JitedBytes
		}
		return progs[i].ID < progs[j].ID
	})
	sort.Slice(maps, func(i, j int) bool {
		if maps[i].MemlockBytes != maps[j].MemlockBytes {
			return maps[i].MemlockBytes > maps[j].MemlockBytes
		}
		if maps[i].MaxEntries != maps[j].MaxEntries {
			return maps[i].MaxEntries > maps[j].MaxEntries
		}
		return maps[i].ID < maps[j].ID
	})

	totalJited, totalProgMemlock, totalMapMemlock, progsByType, mapsByType := summarizeBpfInventory(progs, maps)
	inv.Available = true
	inv.TotalPrograms = len(progs)
	inv.TotalMaps = len(maps)
	inv.TotalJitedBytes = totalJited
	inv.TotalProgMemlockBytes = totalProgMemlock
	inv.TotalMapMemlockBytes = totalMapMemlock
	inv.ProgramsByType = progsByType
	inv.MapsByType = mapsByType
	if progs != nil {
		inv.Programs = progs
	}
	if maps != nil {
		inv.Maps = maps
	}
	return inv
}

func parseProcNetSnmpSection(headers, values []string) map[string]uint64 {
	out := make(map[string]uint64)
	n := len(headers)
	if len(values) < n {
		n = len(values)
	}
	for i := 1; i < n; i++ {
		if v, err := strconv.ParseUint(values[i], 10, 64); err == nil {
			out[headers[i]] = v
		}
	}
	return out
}

// ParseProcNetSnmp extracts kernel TCP and UDP SNMP counters from /proc/net/snmp content.
func ParseProcNetSnmp(raw string) (KernelTcpSnmpTelemetry, KernelUdpSnmpTelemetry) {
	var tcp KernelTcpSnmpTelemetry
	var udp KernelUdpSnmpTelemetry

	var pendingPrefix string
	var pendingHeaders []string
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		fields := strings.Fields(strings.TrimSpace(sc.Text()))
		if len(fields) < 2 {
			pendingPrefix = ""
			pendingHeaders = nil
			continue
		}
		prefix := fields[0]
		if pendingPrefix != "" && prefix == pendingPrefix {
			kv := parseProcNetSnmpSection(pendingHeaders, fields)
			switch prefix {
			case "Tcp:":
				tcp.Available = true
				tcp.InSegs = kv["InSegs"]
				tcp.OutSegs = kv["OutSegs"]
				tcp.RetransSegs = kv["RetransSegs"]
				tcp.CurrEstab = kv["CurrEstab"]
				tcp.AttemptFails = kv["AttemptFails"]
				tcp.EstabResets = kv["EstabResets"]
				tcp.InErrs = kv["InErrs"]
				tcp.OutRsts = kv["OutRsts"]
				if tcp.OutSegs > 0 {
					tcp.RetransmitRatioPct = math.Round((float64(tcp.RetransSegs)/float64(tcp.OutSegs))*100000) / 1000
				}
			case "Udp:":
				udp.Available = true
				udp.InDatagrams = kv["InDatagrams"]
				udp.OutDatagrams = kv["OutDatagrams"]
				udp.NoPorts = kv["NoPorts"]
				udp.InErrors = kv["InErrors"]
				udp.RcvbufErrors = kv["RcvbufErrors"]
				udp.SndbufErrors = kv["SndbufErrors"]
			}
			pendingPrefix = ""
			pendingHeaders = nil
			continue
		}

		if prefix == "Tcp:" || prefix == "Udp:" {
			pendingPrefix = prefix
			pendingHeaders = fields
		} else {
			pendingPrefix = ""
			pendingHeaders = nil
		}
	}

	return tcp, udp
}

// ParseCgroupCpuStat parses cgroup v2 cpu.stat throttling metrics.
func ParseCgroupCpuStat(raw, sourcePath string) KernelCgroupThrottleTelemetry {
	out := KernelCgroupThrottleTelemetry{SourcePath: sourcePath}
	found := false
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		fields := strings.Fields(strings.TrimSpace(sc.Text()))
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "nr_periods":
			out.NrPeriods = v
			found = true
		case "nr_throttled":
			out.NrThrottled = v
			found = true
		case "throttled_usec":
			out.ThrottledUsec = v
			found = true
		}
	}
	if !found {
		return KernelCgroupThrottleTelemetry{}
	}
	out.Available = true
	if out.NrPeriods > 0 {
		out.ThrottleRatioPct = math.Round((float64(out.NrThrottled)/float64(out.NrPeriods))*10000) / 100
	}
	return out
}

// ParseProcVmstatAndPsi parses /proc/vmstat and optional /proc/pressure/memory telemetry.
func ParseProcVmstatAndPsi(vmstatRaw, psiRaw string) KernelMemoryPressureTelemetry {
	var out KernelMemoryPressureTelemetry
	sc := bufio.NewScanner(strings.NewReader(vmstatRaw))
	for sc.Scan() {
		fields := strings.Fields(strings.TrimSpace(sc.Text()))
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "oom_kill":
			out.OomKillCount = v
			out.Available = true
		case "pgmajfault":
			out.MajorPageFaults = v
			out.Available = true
		case "allocstall", "allocstall_dma", "allocstall_dma32", "allocstall_normal", "allocstall_movable":
			out.AllocStalls += v
			out.Available = true
		}
	}

	if strings.TrimSpace(psiRaw) != "" {
		psiSc := bufio.NewScanner(strings.NewReader(psiRaw))
		for psiSc.Scan() {
			line := strings.TrimSpace(psiSc.Text())
			if !strings.HasPrefix(line, "some ") && !strings.HasPrefix(line, "full ") {
				continue
			}
			for _, tok := range strings.Fields(line)[1:] {
				if strings.HasPrefix(tok, "avg10=") {
					val, err := strconv.ParseFloat(strings.TrimPrefix(tok, "avg10="), 64)
					if err == nil {
						out.PsiAvailable = true
						if strings.HasPrefix(line, "some ") {
							out.PsiSomeAvg10 = val
						} else {
							out.PsiFullAvg10 = val
						}
					}
				}
			}
		}
	}
	return out
}

// CollectKernelRcaTelemetry gathers real Linux kernel SNMP, cgroup v2 CPU throttling,
// and VM/PSI memory pressure telemetry for automated RCA checks.
func CollectKernelRcaTelemetry() KernelRcaTelemetry {
	out := KernelRcaTelemetry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if snmpBytes, err := os.ReadFile("/proc/net/snmp"); err == nil {
		out.Tcp, out.Udp = ParseProcNetSnmp(string(snmpBytes))
	}

	for _, cgPath := range []string{
		"/sys/fs/cgroup/kubepods.slice/cpu.stat",
		"/sys/fs/cgroup/system.slice/cpu.stat",
		"/sys/fs/cgroup/cpu.stat",
	} {
		if b, err := os.ReadFile(cgPath); err == nil {
			parsed := ParseCgroupCpuStat(string(b), cgPath)
			if parsed.Available {
				out.CgroupCpu = parsed
				if parsed.NrPeriods > 0 {
					break
				}
			}
		}
	}

	var vmstatRaw, psiRaw string
	if b, err := os.ReadFile("/proc/vmstat"); err == nil {
		vmstatRaw = string(b)
	}
	if b, err := os.ReadFile("/proc/pressure/memory"); err == nil {
		psiRaw = string(b)
	}
	out.Memory = ParseProcVmstatAndPsi(vmstatRaw, psiRaw)

	return out
}
