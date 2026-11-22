package engine

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	maxKernelBpfProgEnum = 512
	maxKernelBpfMapEnum  = 1024
	maxKernelBpfLinkEnum = 512
	maxProcNetSocketRows = 65536
)

type BpfProgramInventoryItem struct {
	ID              uint32   `json:"id"`
	Type            string   `json:"type"`
	Name            string   `json:"name"`
	Tag             string   `json:"tag"`
	JitedBytes      uint32   `json:"jitedBytes"`
	TranslatedBytes int      `json:"translatedBytes"`
	VerifiedInsns   uint32   `json:"verifiedInsns"`
	MemlockBytes    uint64   `json:"memlockBytes"`
	MapCount        int      `json:"mapCount"`
	MapIDs          []uint32 `json:"mapIds"`
	HasBTF          bool     `json:"hasBtf"`
	CreatedByUID    uint32   `json:"createdByUid"`
	RunCount        uint64   `json:"runCount"`
	RunTimeNs       int64    `json:"runTimeNs"`
	RecursionMisses uint64   `json:"recursionMisses"`
}

type BpfLinkInventoryItem struct {
	ID           uint32 `json:"id"`
	Type         string `json:"type"`
	ProgramID    uint32 `json:"programId"`
	AttachDetail string `json:"attachDetail,omitempty"`
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
	TotalLinks            int                       `json:"totalLinks"`
	TotalJitedBytes       uint64                    `json:"totalJitedBytes"`
	TotalProgMemlockBytes uint64                    `json:"totalProgMemlockBytes"`
	TotalMapMemlockBytes  uint64                    `json:"totalMapMemlockBytes"`
	ProgramsByType        []BpfTypeAggregate        `json:"programsByType"`
	MapsByType            []BpfTypeAggregate        `json:"mapsByType"`
	Programs              []BpfProgramInventoryItem `json:"programs"`
	Maps                  []BpfMapInventoryItem     `json:"maps"`
	Links                 []BpfLinkInventoryItem    `json:"links"`
}

type SoftnetCpuStat struct {
	Cpu            int    `json:"cpu"`
	Processed      uint64 `json:"processed"`
	Dropped        uint64 `json:"dropped"`
	TimeSqueeze    uint64 `json:"timeSqueeze"`
	CpuCollision   uint64 `json:"cpuCollision"`
	ReceivedRps    uint64 `json:"receivedRps"`
	FlowLimitCount uint64 `json:"flowLimitCount"`
}

type KernelSoftnetTelemetry struct {
	Timestamp           string           `json:"timestamp"`
	Available           bool             `json:"available"`
	CpuCount            int              `json:"cpuCount"`
	TotalProcessed      uint64           `json:"totalProcessed"`
	TotalDropped        uint64           `json:"totalDropped"`
	TotalTimeSqueeze    uint64           `json:"totalTimeSqueeze"`
	TotalCpuCollision   uint64           `json:"totalCpuCollision"`
	TotalReceivedRps    uint64           `json:"totalReceivedRps"`
	TotalFlowLimitCount uint64           `json:"totalFlowLimitCount"`
	PerCpu              []SoftnetCpuStat `json:"perCpu"`
}

type KernelListeningPort struct {
	Protocol    string `json:"protocol"`
	Port        uint16 `json:"port"`
	Service     string `json:"service"`
	Ipv4Sockets int    `json:"ipv4Sockets"`
	Ipv6Sockets int    `json:"ipv6Sockets"`
	TotalCount  int    `json:"totalCount"`
}

type KernelSocketTelemetry struct {
	Timestamp       string                `json:"timestamp"`
	Available       bool                  `json:"available"`
	TotalTcpSockets int                   `json:"totalTcpSockets"`
	Ipv4TcpSockets  int                   `json:"ipv4TcpSockets"`
	Ipv6TcpSockets  int                   `json:"ipv6TcpSockets"`
	TotalUdpSockets int                   `json:"totalUdpSockets"`
	Ipv4UdpSockets  int                   `json:"ipv4UdpSockets"`
	Ipv6UdpSockets  int                   `json:"ipv6UdpSockets"`
	TcpStates       map[string]int        `json:"tcpStates"`
	ListeningPorts  []KernelListeningPort `json:"listeningPorts"`
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
	rawMapIDs, _ := info.MapIDs()
	mapIDs := make([]uint32, 0, len(rawMapIDs))
	for _, mid := range rawMapIDs {
		mapIDs = append(mapIDs, uint32(mid))
	}
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
		MapIDs:          mapIDs,
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

type bpfGetNextIDAttr struct {
	StartID   uint32
	NextID    uint32
	OpenFlags uint32
}

func bpfLinkGetNextID(startID link.ID) (link.ID, error) {
	attr := bpfGetNextIDAttr{StartID: uint32(startID)}
	_, _, errno := unix.Syscall(
		unix.SYS_BPF,
		uintptr(unix.BPF_LINK_GET_NEXT_ID),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return 0, errno
	}
	return link.ID(attr.NextID), nil
}

func formatBpfLinkType(t link.Type) string {
	switch t {
	case link.RawTracepointType:
		return "raw_tracepoint"
	case link.TracingType:
		return "tracing"
	case link.CgroupType:
		return "cgroup"
	case link.IterType:
		return "iter"
	case link.NetNsType:
		return "netns"
	case link.XDPType:
		return "xdp"
	case link.PerfEventType:
		return "perf_event"
	case link.KprobeMultiType:
		return "kprobe_multi"
	case link.TCXType:
		return "tcx"
	case link.UprobeMultiType:
		return "uprobe_multi"
	case link.NetfilterType:
		return "netfilter"
	case link.NetkitType:
		return "netkit"
	case link.StructOpsType:
		return "struct_ops"
	case link.UnspecifiedType:
		return "unspecified"
	default:
		return "type_" + strconv.FormatUint(uint64(t), 10)
	}
}

func formatIfaceAttach(prefix string, ifindex uint32) string {
	if ifindex > 0 {
		if iface, err := net.InterfaceByIndex(int(ifindex)); err == nil && iface != nil && iface.Name != "" {
			return prefix + ":" + iface.Name
		}
	}
	return fmt.Sprintf("%s:ifindex#%d", prefix, ifindex)
}

func inspectBpfLink(id link.ID) (BpfLinkInventoryItem, bool) {
	l, err := link.NewFromID(id)
	if err != nil {
		return BpfLinkInventoryItem{}, false
	}
	defer l.Close()

	info, err := l.Info()
	if err != nil || info == nil {
		return BpfLinkInventoryItem{}, false
	}

	resolvedID := uint32(id)
	if info.ID > 0 {
		resolvedID = uint32(info.ID)
	}

	detail := ""
	switch {
	case info.XDP() != nil:
		detail = formatIfaceAttach("xdp", info.XDP().Ifindex)
	case info.TCX() != nil:
		tcx := info.TCX()
		detail = formatIfaceAttach("tcx", tcx.Ifindex) + " (" + tcx.AttachType.String() + ")"
	case info.Netkit() != nil:
		nk := info.Netkit()
		detail = formatIfaceAttach("netkit", nk.Ifindex) + " (" + nk.AttachType.String() + ")"
	case info.Cgroup() != nil:
		cg := info.Cgroup()
		detail = fmt.Sprintf("cgroup:#%d (%s)", cg.CgroupId, cg.AttachType.String())
	case info.Tracing() != nil:
		tr := info.Tracing()
		detail = fmt.Sprintf("%s (btf#%d)", tr.AttachType.String(), tr.TargetBtfId)
	case info.RawTracepoint() != nil && info.RawTracepoint().Name != "":
		detail = "raw_tp:" + info.RawTracepoint().Name
	case info.Netfilter() != nil:
		nf := info.Netfilter()
		detail = fmt.Sprintf("netfilter:pf=%d hook=%d prio=%d", nf.ProtocolFamily, nf.Hook, nf.Priority)
	case info.PerfEvent() != nil:
		pe := info.PerfEvent()
		if kp := pe.Kprobe(); kp != nil && kp.Function != "" {
			detail = "kprobe:" + kp.Function
		} else if tp := pe.Tracepoint(); tp != nil && tp.Tracepoint != "" {
			detail = "tp:" + tp.Tracepoint
		} else if up := pe.Uprobe(); up != nil && up.File != "" {
			detail = "uprobe:" + up.File
		}
	}

	return BpfLinkInventoryItem{
		ID:           resolvedID,
		Type:         formatBpfLinkType(info.Type),
		ProgramID:    uint32(info.Program),
		AttachDetail: detail,
	}, true
}

// SetKernelBpfStatsEnabled toggles /proc/sys/kernel/bpf_stats_enabled so per-program
// runCount and runTimeNs telemetry can be activated or disabled on demand.
func SetKernelBpfStatsEnabled(enabled bool) error {
	val := "0\n"
	if enabled {
		val = "1\n"
	}
	return os.WriteFile("/proc/sys/kernel/bpf_stats_enabled", []byte(val), 0o644)
}

// CollectKernelBpfInventory enumerates all loaded kernel eBPF programs, maps, and links via
// sys_bpf GET_NEXT_ID / GET_FD_BY_ID without requiring bpftool subprocesses.
func CollectKernelBpfInventory() KernelBpfInventory {
	inv := KernelBpfInventory{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		ProgramsByType: []BpfTypeAggregate{},
		MapsByType:     []BpfTypeAggregate{},
		Programs:       []BpfProgramInventoryItem{},
		Maps:           []BpfMapInventoryItem{},
		Links:          []BpfLinkInventoryItem{},
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

	var links []BpfLinkInventoryItem
	var lastLinkID link.ID
	for count := 0; count < maxKernelBpfLinkEnum; count++ {
		nextID, err := bpfLinkGetNextID(lastLinkID)
		if err != nil {
			if errors.Is(err, unix.ENOENT) ||
				errors.Is(err, unix.EINVAL) ||
				errors.Is(err, unix.ENOSYS) ||
				errors.Is(err, unix.EPERM) ||
				errors.Is(err, unix.EACCES) ||
				errors.Is(err, os.ErrNotExist) {
				break
			}
			break
		}
		lastLinkID = nextID
		if item, ok := inspectBpfLink(nextID); ok {
			links = append(links, item)
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
	sort.Slice(links, func(i, j int) bool {
		if links[i].ProgramID != links[j].ProgramID {
			return links[i].ProgramID < links[j].ProgramID
		}
		return links[i].ID < links[j].ID
	})

	totalJited, totalProgMemlock, totalMapMemlock, progsByType, mapsByType := summarizeBpfInventory(progs, maps)
	inv.Available = true
	inv.TotalPrograms = len(progs)
	inv.TotalMaps = len(maps)
	inv.TotalLinks = len(links)
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
	if links != nil {
		inv.Links = links
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

// ParseProcNetSoftnetStat parses /proc/net/softnet_stat hex rows into per-CPU SoftIRQ/NAPI telemetry.
func ParseProcNetSoftnetStat(raw string) KernelSoftnetTelemetry {
	out := KernelSoftnetTelemetry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		PerCpu:    []SoftnetCpuStat{},
	}

	var perCpu []SoftnetCpuStat
	sc := bufio.NewScanner(strings.NewReader(raw))
	idx := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		parseHexCol := func(pos int) uint64 {
			if pos >= len(fields) {
				return 0
			}
			v, err := strconv.ParseUint(fields[pos], 16, 64)
			if err != nil {
				return 0
			}
			return v
		}

		cpuIdx := idx
		if len(fields) >= 13 {
			if parsedCpu, err := strconv.ParseUint(fields[12], 16, 32); err == nil {
				cpuIdx = int(parsedCpu)
			}
		}

		stat := SoftnetCpuStat{
			Cpu:            cpuIdx,
			Processed:      parseHexCol(0),
			Dropped:        parseHexCol(1),
			TimeSqueeze:    parseHexCol(2),
			CpuCollision:   parseHexCol(8),
			ReceivedRps:    parseHexCol(9),
			FlowLimitCount: parseHexCol(10),
		}

		perCpu = append(perCpu, stat)
		out.TotalProcessed += stat.Processed
		out.TotalDropped += stat.Dropped
		out.TotalTimeSqueeze += stat.TimeSqueeze
		out.TotalCpuCollision += stat.CpuCollision
		out.TotalReceivedRps += stat.ReceivedRps
		out.TotalFlowLimitCount += stat.FlowLimitCount
		idx++
	}

	sort.Slice(perCpu, func(i, j int) bool {
		return perCpu[i].Cpu < perCpu[j].Cpu
	})

	if len(perCpu) > 0 {
		out.Available = true
		out.CpuCount = len(perCpu)
		out.PerCpu = perCpu
	}
	return out
}

// CollectSoftnetTelemetry reads /proc/net/softnet_stat for real per-CPU NAPI Ring-0 pressure metrics.
func CollectSoftnetTelemetry() KernelSoftnetTelemetry {
	raw, err := os.ReadFile("/proc/net/softnet_stat")
	if err != nil {
		return KernelSoftnetTelemetry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			PerCpu:    []SoftnetCpuStat{},
		}
	}
	return ParseProcNetSoftnetStat(string(raw))
}

var linuxTcpStateNames = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

func parseProcSocketAddrPort(addrPort string) (uint16, bool) {
	colon := strings.LastIndexByte(addrPort, ':')
	if colon < 0 || colon+1 >= len(addrPort) {
		return 0, false
	}
	p, err := strconv.ParseUint(addrPort[colon+1:], 16, 16)
	if err != nil {
		return 0, false
	}
	return uint16(p), true
}

type listenPortAggKey struct {
	protocol string
	port     uint16
}

// ParseProcNetSockets parses /proc/net/{tcp,tcp6,udp,udp6} contents into TCP state
// distribution counts and deduplicated listening TCP/UDP socket endpoints.
func ParseProcNetSockets(tcp4Raw, tcp6Raw, udp4Raw, udp6Raw string) KernelSocketTelemetry {
	tcpStates := map[string]int{
		"ESTABLISHED": 0,
		"SYN_SENT":    0,
		"SYN_RECV":    0,
		"FIN_WAIT1":   0,
		"FIN_WAIT2":   0,
		"TIME_WAIT":   0,
		"CLOSE":       0,
		"CLOSE_WAIT":  0,
		"LAST_ACK":    0,
		"LISTEN":      0,
		"CLOSING":     0,
	}

	out := KernelSocketTelemetry{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		TcpStates:      tcpStates,
		ListeningPorts: []KernelListeningPort{},
	}

	listeners := make(map[listenPortAggKey]*KernelListeningPort)
	recordListener := func(protocol string, protoNum uint8, port uint16, isV6 bool) {
		if port == 0 {
			return
		}
		k := listenPortAggKey{protocol: protocol, port: port}
		entry, ok := listeners[k]
		if !ok {
			entry = &KernelListeningPort{
				Protocol: protocol,
				Port:     port,
				Service:  serviceNameForPort(port, protoNum),
			}
			listeners[k] = entry
		}
		if isV6 {
			entry.Ipv6Sockets++
		} else {
			entry.Ipv4Sockets++
		}
		entry.TotalCount++
	}

	scanTable := func(raw string, isTcp bool, isV6 bool) int {
		if strings.TrimSpace(raw) == "" {
			return 0
		}
		count := 0
		sc := bufio.NewScanner(strings.NewReader(raw))
		first := true
		for sc.Scan() {
			if count >= maxProcNetSocketRows {
				break
			}
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			if first {
				first = false
				if strings.Contains(line, "local_address") {
					continue
				}
			}
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			localPort, okLocal := parseProcSocketAddrPort(fields[1])
			remPort, okRem := parseProcSocketAddrPort(fields[2])
			stateCode := strings.ToUpper(fields[3])
			count++
			out.Available = true

			if isTcp {
				if stateName, exists := linuxTcpStateNames[stateCode]; exists {
					out.TcpStates[stateName]++
				}
				if stateCode == "0A" && okLocal {
					recordListener("TCP", 6, localPort, isV6)
				}
			} else if stateCode == "07" && okLocal && (!okRem || remPort == 0) {
				recordListener("UDP", 17, localPort, isV6)
			}
		}
		return count
	}

	out.Ipv4TcpSockets = scanTable(tcp4Raw, true, false)
	out.Ipv6TcpSockets = scanTable(tcp6Raw, true, true)
	out.TotalTcpSockets = out.Ipv4TcpSockets + out.Ipv6TcpSockets

	out.Ipv4UdpSockets = scanTable(udp4Raw, false, false)
	out.Ipv6UdpSockets = scanTable(udp6Raw, false, true)
	out.TotalUdpSockets = out.Ipv4UdpSockets + out.Ipv6UdpSockets

	for _, entry := range listeners {
		out.ListeningPorts = append(out.ListeningPorts, *entry)
	}
	sort.Slice(out.ListeningPorts, func(i, j int) bool {
		if out.ListeningPorts[i].Port != out.ListeningPorts[j].Port {
			return out.ListeningPorts[i].Port < out.ListeningPorts[j].Port
		}
		return out.ListeningPorts[i].Protocol < out.ListeningPorts[j].Protocol
	})

	return out
}

// CollectKernelSocketTelemetry reads /proc/net/{tcp,tcp6,udp,udp6} for real TCP state
// distribution and listening port inventory.
func CollectKernelSocketTelemetry() KernelSocketTelemetry {
	readOpt := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		return string(b)
	}
	return ParseProcNetSockets(
		readOpt("/proc/net/tcp"),
		readOpt("/proc/net/tcp6"),
		readOpt("/proc/net/udp"),
		readOpt("/proc/net/udp6"),
	)
}
