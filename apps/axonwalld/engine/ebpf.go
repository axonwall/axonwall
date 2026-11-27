package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/bits"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/axonwall/axonwall/apps/axonwalld/ebpf"
)

const (
	XdpReasonAutoDdos       uint32 = 1
	XdpReasonMcpTactical    uint32 = 2
	XdpReasonSoarQuarantine uint32 = 3
	XdpReasonLpmCidrDrop    uint32 = 4
)

type XdpVerdictTelemetry struct {
	RxPackets     uint64 `json:"rxPackets"`
	RxBytes       uint64 `json:"rxBytes"`
	XdpPass       uint64 `json:"xdpPass"`
	XdpDrop       uint64 `json:"xdpDrop"`
	Ipv4Packets   uint64 `json:"ipv4Packets"`
	Ipv6Packets   uint64 `json:"ipv6Packets"`
	VlanPackets   uint64 `json:"vlanPackets"`
	TcpSynPackets uint64 `json:"tcpSynPackets"`
	LpmCidrDrops  uint64 `json:"lpmCidrDrops"`
	SynFloodDrops uint64 `json:"synFloodDrops"`
}

type XdpFlowSnapshotEntry struct {
	Family         int    `json:"family"`
	SrcIP          string `json:"srcIp"`
	DstIP          string `json:"dstIp"`
	SrcPort        uint16 `json:"srcPort"`
	DstPort        uint16 `json:"dstPort"`
	VlanID         uint16 `json:"vlanId"`
	IngressIfIndex uint32 `json:"ingressIfIndex,omitempty"`
	Protocol       uint8  `json:"protocol"`
	ProtoName      string `json:"protoName"`
	Packets        uint64 `json:"packets"`
	Bytes          uint64 `json:"bytes"`
	SynPackets     uint64 `json:"synPackets"`
	RstPackets     uint64 `json:"rstPackets"`
	TcpFlags       string `json:"tcpFlags,omitempty"`
	AgeMs          int64  `json:"ageMs"`
}

type XdpBlockSnapshotEntry struct {
	IP          string `json:"ip"`
	Family      int    `json:"family"`
	IsCidr      bool   `json:"isCidr,omitempty"`
	DropPackets uint64 `json:"dropPackets"`
	DropBytes   uint64 `json:"dropBytes"`
	ReasonCode  uint32 `json:"reasonCode"`
	Reason      string `json:"reason"`
	ExpiresAt   string `json:"expiresAt,omitempty"`
}

type XdpPerCpuTelemetry struct {
	Cpu           int    `json:"cpu"`
	RxPackets     uint64 `json:"rxPackets"`
	RxBytes       uint64 `json:"rxBytes"`
	XdpPass       uint64 `json:"xdpPass"`
	XdpDrop       uint64 `json:"xdpDrop"`
	Ipv4Packets   uint64 `json:"ipv4Packets"`
	Ipv6Packets   uint64 `json:"ipv6Packets"`
	VlanPackets   uint64 `json:"vlanPackets"`
	TcpSynPackets uint64 `json:"tcpSynPackets"`
	LpmCidrDrops  uint64 `json:"lpmCidrDrops"`
	SynFloodDrops uint64 `json:"synFloodDrops"`
}

type XdpProtocolSummary struct {
	Protocol  uint8  `json:"protocol"`
	ProtoName string `json:"protoName"`
	Flows     int    `json:"flows"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
}

type XdpPortSummary struct {
	Port       uint16 `json:"port"`
	Service    string `json:"service"`
	Protocol   uint8  `json:"protocol"`
	ProtoName  string `json:"protoName"`
	Flows      int    `json:"flows"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	SynPackets uint64 `json:"synPackets"`
	RstPackets uint64 `json:"rstPackets"`
}

type XdpVlanSummary struct {
	VlanID  uint16 `json:"vlanId"`
	Flows   int    `json:"flows"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type XdpSynMeterEntry struct {
	IP             string `json:"ip"`
	Family         int    `json:"family"`
	SynCount       uint64 `json:"synCount"`
	DroppedPackets uint64 `json:"droppedPackets"`
	WindowAgeMs    int64  `json:"windowAgeMs"`
}

type EbpfDataplaneSnapshot struct {
	Running            bool                    `json:"running"`
	AttachedInterfaces []string                `json:"attachedInterfaces"`
	ClickHouseEnabled  bool                    `json:"clickHouseEnabled"`
	SynFloodLimitPps   uint64                  `json:"synFloodLimitPps"`
	Stats              XdpVerdictTelemetry     `json:"stats"`
	PerCpuStats        []XdpPerCpuTelemetry    `json:"perCpuStats"`
	TotalFlowCount     int                     `json:"totalFlowCount"`
	TotalFlowCountV4   int                     `json:"totalFlowCountV4"`
	TotalFlowCountV6   int                     `json:"totalFlowCountV6"`
	ProtocolBreakdown  []XdpProtocolSummary    `json:"protocolBreakdown"`
	TopPorts           []XdpPortSummary        `json:"topPorts"`
	VlanBreakdown      []XdpVlanSummary        `json:"vlanBreakdown"`
	SynRateMeters      []XdpSynMeterEntry      `json:"synRateMeters"`
	TopFlows           []XdpFlowSnapshotEntry  `json:"topFlows"`
	ActiveBlocks       []XdpBlockSnapshotEntry `json:"activeBlocks"`
	Timestamp          string                  `json:"timestamp"`
}

type xdpBlockMeta struct {
	expiresAt time.Time
	reason    string
}

type EBPFManager struct {
	objsMu           sync.RWMutex
	objs             ebpf.FlowTrackerObjects
	links            []link.Link
	attachedIfaces   []string
	ch               driver.Conn
	stopChan         chan struct{}
	doneChan         chan struct{}
	// monitorStarted records whether monitorFlows() was actually launched.
	monitorStarted   atomic.Bool
	synFloodLimitPps atomic.Uint64
	prevPackets      map[ebpf.FlowTrackerFlowKey]uint64
	prevBytes        map[ebpf.FlowTrackerFlowKey]uint64
	prevPackets6     map[ebpf.FlowTrackerFlow6Key]uint64
	blockedUntil     map[uint32]time.Time
	blockMetaV4      map[uint32]xdpBlockMeta
	blockMetaV6      map[[16]uint8]xdpBlockMeta
	cidrMetaV4       map[ebpf.FlowTrackerLpmV4Key]xdpBlockMeta
	cidrMetaV6       map[ebpf.FlowTrackerLpmV6Key]xdpBlockMeta
	blockMu          sync.Mutex
	mu               sync.Mutex
	running          bool
}

var (
	defaultEbpfMgrMu sync.RWMutex
	defaultEbpfMgr   *EBPFManager
)

func NewEBPFManager() *EBPFManager {
	mgr := &EBPFManager{
		stopChan:     make(chan struct{}),
		doneChan:     make(chan struct{}),
		prevPackets:  make(map[ebpf.FlowTrackerFlowKey]uint64),
		prevBytes:    make(map[ebpf.FlowTrackerFlowKey]uint64),
		prevPackets6: make(map[ebpf.FlowTrackerFlow6Key]uint64),
		blockedUntil: make(map[uint32]time.Time),
		blockMetaV4:  make(map[uint32]xdpBlockMeta),
		blockMetaV6:  make(map[[16]uint8]xdpBlockMeta),
		cidrMetaV4:   make(map[ebpf.FlowTrackerLpmV4Key]xdpBlockMeta),
		cidrMetaV6:   make(map[ebpf.FlowTrackerLpmV6Key]xdpBlockMeta),
	}
	if rawSyn := strings.TrimSpace(os.Getenv("AXONWALL_XDP_SYN_FLOOD_PPS")); rawSyn != "" {
		if parsed, err := strconv.ParseUint(rawSyn, 10, 64); err == nil && parsed > 0 {
			// A-L2: the env value used to be stored with no range
			// check, while SetSynFloodLimitPps rejects anything
			// below 20 pps — so Start's (discarded) call left the
			// atomic holding a limit the kernel never got, and the
			// snapshot reported it as enforced. Validate here, at
			// the same bounds the setter enforces, and ignore an
			// out-of-range value (limiter stays disabled) instead
			// of recording a phantom limit.
			if parsed < 20 || parsed > 10_000_000 {
				log.Printf("Warning: AXONWALL_XDP_SYN_FLOOD_PPS=%d is outside the supported range (20-10000000 pps); ignoring it, SYN-flood limiter disabled", parsed)
			} else {
				mgr.synFloodLimitPps.Store(parsed)
			}
		}
	}
	defaultEbpfMgrMu.Lock()
	defaultEbpfMgr = mgr
	defaultEbpfMgrMu.Unlock()
	return mgr
}

func GetDefaultEBPFManager() *EBPFManager {
	defaultEbpfMgrMu.RLock()
	defer defaultEbpfMgrMu.RUnlock()
	return defaultEbpfMgr
}

func ktimeMonotonicNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

func ipv4Uint32FromBytes(ip4 net.IP) uint32 {
	return uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
}

func ipv4FromUint32(v uint32) net.IP {
	ip := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		ip[i] = byte(v >> (i * 8))
	}
	return ip
}

func formatTcpFlags(flags uint8) string {
	if flags == 0 {
		return ""
	}
	var parts []string
	if flags&0x02 != 0 {
		parts = append(parts, "SYN")
	}
	if flags&0x10 != 0 {
		parts = append(parts, "ACK")
	}
	if flags&0x01 != 0 {
		parts = append(parts, "FIN")
	}
	if flags&0x04 != 0 {
		parts = append(parts, "RST")
	}
	if flags&0x08 != 0 {
		parts = append(parts, "PSH")
	}
	if flags&0x20 != 0 {
		parts = append(parts, "URG")
	}
	return strings.Join(parts, "|")
}

func protocolName(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 58:
		return "ICMPv6"
	default:
		return strconv.Itoa(int(proto))
	}
}

func xdpReasonLabel(code uint32, custom string) string {
	if custom != "" {
		return custom
	}
	switch code {
	case XdpReasonAutoDdos:
		return "Volumetric XDP Auto-DDoS Mitigation"
	case XdpReasonMcpTactical:
		return "MCP Autonomous AI Tactical XDP Drop"
	case XdpReasonSoarQuarantine:
		return "Vigilante SOAR XDP Quarantine"
	case XdpReasonLpmCidrDrop:
		return "XDP LPM CIDR Subnet Drop"
	default:
		return "XDP Hardware/Driver Drop"
	}
}

func (m *EBPFManager) initClickHouse() error {
	chAddr := os.Getenv("CLICKHOUSE_ADDR")
	if chAddr == "" {
		chAddr = "127.0.0.1:9000"
	}
	chUser := os.Getenv("CLICKHOUSE_USER")
	if chUser == "" {
		chUser = "admin"
	}
	chPass := strings.TrimSpace(os.Getenv("CLICKHOUSE_PASSWORD"))
	if chPass == "" {
		return fmt.Errorf("CLICKHOUSE_PASSWORD is unset; skipping ClickHouse export")
	}
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{chAddr},
		Auth: clickhouse.Auth{
			Database: "axonwall",
			Username: chUser,
			Password: chPass,
		},
		MaxOpenConns:    5,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
	})
	if err != nil {
		return err
	}

	ctx := context.Background()
	query := `
	CREATE TABLE IF NOT EXISTS flows (
		timestamp DateTime,
		src_ip IPv4,
		dst_ip IPv4,
		protocol UInt8,
		packets UInt64,
		bytes UInt64
	) ENGINE = MergeTree()
	ORDER BY (timestamp, src_ip, dst_ip)
	`
	if err := conn.Exec(ctx, query); err != nil {
		_ = conn.Close()
		return err
	}

	m.mu.Lock()
	m.ch = conn
	m.mu.Unlock()
	return nil
}

func (m *EBPFManager) Start(interfaces []string) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("eBPF manager already started")
	}
	m.running = true
	m.mu.Unlock()
	closeCH := func() {
		m.mu.Lock()
		ch := m.ch
		m.ch = nil
		m.mu.Unlock()
		if ch != nil {
			_ = ch.Close()
		}
	}
	clearRunning := func() {
		m.mu.Lock()
		m.running = false
		m.stopChan = nil
		m.doneChan = nil
		m.attachedIfaces = nil
		m.mu.Unlock()
	}

	if os.Getenv("AXONWALL_LEGACY_EBPF_CLICKHOUSE") == "1" {
		if err := m.initClickHouse(); err != nil {
			log.Printf("Warning: failed to init ClickHouse: %v. Historical forensics will be disabled.", err)
		}
	}

	m.objsMu.Lock()
	err := ebpf.LoadFlowTrackerObjects(&m.objs, nil)
	m.objsMu.Unlock()
	if err != nil {
		closeCH()
		clearRunning()
		return fmt.Errorf("loading objects: %w", err)
	}

	if initSyn := m.synFloodLimitPps.Load(); initSyn > 0 {
		// A-L2: this error used to be discarded, which is what let
		// an unapplied limit linger in the atomic and be reported
		// as enforced. The constructor now validates the env value
		// against the same bounds, so this should not fire on range
		// — but a kernel-map failure here must still be visible.
		if err := m.SetSynFloodLimitPps(initSyn); err != nil {
			log.Printf("Warning: could not apply initial SYN-flood limit %d pps: %v", initSyn, err)
		}
	}

	var attached []string
	var links []link.Link
	seenIf := make(map[string]bool)
	m.objsMu.RLock()
	xdpProg := m.objs.XdpFlowTracker
	for _, rawIf := range interfaces {
		iface := strings.TrimSpace(rawIf)
		if iface == "" || iface == "lo" || seenIf[iface] {
			continue
		}
		seenIf[iface] = true
		ifaceObj, err := net.InterfaceByName(iface)
		if err != nil {
			log.Printf("Warning: interface %s not found, skipping eBPF attachment", iface)
			continue
		}

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   xdpProg,
			Interface: ifaceObj.Index,
		})
		if err != nil {
			log.Printf("Warning: could not attach XDP to %s: %v", iface, err)
			continue
		}
		links = append(links, l)
		attached = append(attached, iface)
	}
	m.objsMu.RUnlock()

	// A-H3 (round 3): Start used to return nil with zero interfaces
	// attached, leaving running=true while the kernel enforced
	// nothing — and AddXdpBlock then recorded blocks as active.
	// A manager with no XDP program attached enforces nothing, so
	// fail loudly instead of reporting a live dataplane.
	if len(attached) == 0 {
		for _, l := range links {
			_ = l.Close()
		}
		m.objsMu.Lock()
		_ = m.objs.Close()
		m.objs = ebpf.FlowTrackerObjects{}
		m.objsMu.Unlock()
		closeCH()
		clearRunning()
		return fmt.Errorf("eBPF XDP attach failed on all %d interface(s): no XDP program attached, dataplane not enforced", len(interfaces))
	}

	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	m.mu.Lock()
	m.links = links
	m.attachedIfaces = attached
	m.stopChan = stopCh
	m.doneChan = doneCh
	m.monitorStarted.Store(true)
	m.mu.Unlock()

	go m.monitorFlows(stopCh, doneCh)

	return nil
}

// SetSynFloodLimitPps configures the Ring-0 XDP TCP SYN-flood per-source PPS rate limiter (0 disables).
func (m *EBPFManager) SetSynFloodLimitPps(maxSynPps uint64) error {
	if m == nil {
		return errors.New("eBPF manager is not initialized")
	}
	if maxSynPps > 0 && maxSynPps < 20 {
		return fmt.Errorf("maxSynPps %d is below safety minimum (20 pps; pass 0 to disable)", maxSynPps)
	}
	if maxSynPps > 10_000_000 {
		return fmt.Errorf("maxSynPps %d exceeds maximum supported limit (10,000,000)", maxSynPps)
	}
	m.synFloodLimitPps.Store(maxSynPps)
	m.objsMu.RLock()
	defer m.objsMu.RUnlock()
	if m.objs.SynFloodCfgMap != nil {
		enabled := uint32(0)
		if maxSynPps > 0 {
			enabled = 1
		}
		cfg := ebpf.FlowTrackerSynFloodCfg{
			MaxSynPps: maxSynPps,
			Enabled:   enabled,
		}
		if err := m.objs.SynFloodCfgMap.Put(uint32(0), cfg); err != nil {
			return fmt.Errorf("failed to update XDP syn_flood_cfg_map: %w", err)
		}
	}
	return nil
}

func (m *EBPFManager) monitorFlows(stopCh, doneCh chan struct{}) {
	defer func() {
		if doneCh != nil {
			close(doneCh)
		}
	}()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			m.sweepFlowsOnce()
		}
	}
}

func (m *EBPFManager) sweepFlowsOnce() {
	m.objsMu.RLock()
	defer m.objsMu.RUnlock()
	if m.objs.FlowMap == nil {
		return
	}

	m.mu.Lock()
	ch := m.ch
	m.mu.Unlock()

	var batch driver.Batch
	if ch != nil {
		ctx := context.Background()
		var err error
		batch, err = ch.PrepareBatch(ctx, "INSERT INTO flows (timestamp, src_ip, dst_ip, protocol, packets, bytes)")
		if err != nil {
			log.Printf("ClickHouse prepare batch error: %v", err)
			batch = nil
		}
	}

	now := time.Now()
	nowKtime := ktimeMonotonicNs()
	count := 0

	// 1. Process cooldown expirations on IPv4/IPv6 host & LPM CIDR XDP blocklists
	m.blockMu.Lock()
	if m.objs.BlocklistMap != nil {
		for ipUint, expiry := range m.blockedUntil {
			if now.After(expiry) {
				_ = m.objs.BlocklistMap.Delete(ipUint)
				delete(m.blockedUntil, ipUint)
				delete(m.blockMetaV4, ipUint)
				log.Printf("XDP Mitigation: Cooldown expired for IP %s. Removed from XDP blocklist", ipv4FromUint32(ipUint).String())
			}
		}
	}
	if m.objs.Blocklist6Map != nil {
		for ip6Arr, meta := range m.blockMetaV6 {
			if !meta.expiresAt.IsZero() && now.After(meta.expiresAt) {
				_ = m.objs.Blocklist6Map.Delete(ebpf.FlowTrackerIpv6AddrKey{Addr: ip6Arr})
				delete(m.blockMetaV6, ip6Arr)
				log.Printf("XDP Mitigation: Cooldown expired for IPv6 %s. Removed from XDP blocklist", net.IP(ip6Arr[:]).String())
			}
		}
	}
	for lpm4, meta := range m.cidrMetaV4 {
		if !meta.expiresAt.IsZero() && now.After(meta.expiresAt) {
			if m.objs.CidrBlock4Map != nil {
				_ = m.objs.CidrBlock4Map.Delete(lpm4)
			}
			delete(m.cidrMetaV4, lpm4)
		}
	}
	for lpm6, meta := range m.cidrMetaV6 {
		if !meta.expiresAt.IsZero() && now.After(meta.expiresAt) {
			if m.objs.CidrBlock6Map != nil {
				_ = m.objs.CidrBlock6Map.Delete(lpm6)
			}
			delete(m.cidrMetaV6, lpm6)
		}
	}
	m.blockMu.Unlock()

	ddosEnabled := os.Getenv("AXONWALL_DDOS_MITIGATION_ENABLED") != "false"
	ddosThreshold := uint64(500000) // 50,000 packets/sec
	if val := os.Getenv("AXONWALL_DDOS_THRESHOLD_10S"); val != "" {
		if parsed, err := strconv.ParseUint(val, 10, 64); err == nil && parsed > 0 {
			ddosThreshold = parsed
		}
	}
	ddosCooldown := 60 * time.Second
	if val := os.Getenv("AXONWALL_DDOS_COOLDOWN_SECONDS"); val != "" {
		if sec, err := strconv.Atoi(val); err == nil && sec > 0 {
			ddosCooldown = time.Duration(sec) * time.Second
		}
	}

	iter := m.objs.FlowMap.Iterate()
	var key ebpf.FlowTrackerFlowKey
	var val ebpf.FlowTrackerFlowVal
	var keysToDelete []ebpf.FlowTrackerFlowKey
	nextPrev := make(map[ebpf.FlowTrackerFlowKey]uint64)
	nextPrevBytes := make(map[ebpf.FlowTrackerFlowKey]uint64)

	for iter.Next(&key, &val) {
		srcIP := ipv4FromUint32(key.SrcIp)
		dstIP := ipv4FromUint32(key.DstIp)
		srcPort := bits.ReverseBytes16(key.SrcPort)
		dstPort := bits.ReverseBytes16(key.DstPort)

		deltaPackets := val.Packets
		if prev, ok := m.prevPackets[key]; ok && val.Packets >= prev {
			deltaPackets = val.Packets - prev
		}
		deltaBytes := val.Bytes
		if prevB, ok := m.prevBytes[key]; ok && val.Bytes >= prevB {
			deltaBytes = val.Bytes - prevB
		}
		nextPrev[key] = val.Packets
		nextPrevBytes[key] = val.Bytes

		isServerResponsePort := srcPort == 80 || srcPort == 443 || srcPort == 8080 || srcPort == 8443 || srcPort == 53 || srcPort == 853 || srcPort == 123 || srcPort == 22
		isReturnTraffic := isServerResponsePort || (dstPort >= 1024 && srcPort < 1024)

		if ddosEnabled && !isReturnTraffic && deltaPackets > ddosThreshold {
			if _, _, _, err := ValidateTargetSafety(srcIP.String(), "", 0, 24, 64); err == nil {
				log.Printf("DDoS Mitigation: Volumetric threshold exceeded (%d packets/10s on port %d -> %d). Blocking IP %s via XDP for %v cooldown", deltaPackets, srcPort, dstPort, srcIP.String(), ddosCooldown)
				if m.objs.BlocklistMap != nil {
					expTime := now.Add(ddosCooldown)
					expNs := uint64(0)
					if nowKtime > 0 {
						expNs = nowKtime + uint64(ddosCooldown.Nanoseconds())
					}
					blkVal := ebpf.FlowTrackerXdpBlockVal{
						ExpiresNs:  expNs,
						ReasonCode: XdpReasonAutoDdos,
						Active:     1,
					}
					m.blockMu.Lock()
					_ = m.objs.BlocklistMap.Put(key.SrcIp, blkVal)
					m.blockedUntil[key.SrcIp] = expTime
					m.blockMetaV4[key.SrcIp] = xdpBlockMeta{
						expiresAt: expTime,
						reason:    "Volumetric XDP Auto-DDoS Mitigation",
					}
					m.blockMu.Unlock()
				}
			}
		}
		if batch != nil {
			err := batch.Append(
				now,
				srcIP.String(),
				dstIP.String(),
				key.Protocol,
				deltaPackets,
				deltaBytes,
			)
			if err == nil {
				count++
			}
		}

		if nowKtime == 0 || val.LastSeenNs == 0 || (nowKtime > val.LastSeenNs && nowKtime-val.LastSeenNs > uint64(30*time.Second)) {
			keysToDelete = append(keysToDelete, key)
		}
	}

	for i := range keysToDelete {
		if err := m.objs.FlowMap.Delete(&keysToDelete[i]); err == nil {
			delete(nextPrev, keysToDelete[i])
			delete(nextPrevBytes, keysToDelete[i])
		}
	}
	m.prevPackets = nextPrev
	m.prevBytes = nextPrevBytes

	// Sweep IPv6 LRU flows for volumetric DDoS mitigation & idle eviction
	if m.objs.Flow6Map != nil {
		iter6 := m.objs.Flow6Map.Iterate()
		var k6 ebpf.FlowTrackerFlow6Key
		var v6 ebpf.FlowTrackerFlowVal
		var keys6ToDelete []ebpf.FlowTrackerFlow6Key
		nextPrev6 := make(map[ebpf.FlowTrackerFlow6Key]uint64)

		for iter6.Next(&k6, &v6) {
			srcIP6 := net.IP(k6.SrcIp6[:])
			srcPort := bits.ReverseBytes16(k6.SrcPort)
			dstPort := bits.ReverseBytes16(k6.DstPort)

			deltaPackets := v6.Packets
			if prev, ok := m.prevPackets6[k6]; ok && v6.Packets >= prev {
				deltaPackets = v6.Packets - prev
			}
			nextPrev6[k6] = v6.Packets

			isServerResponsePort := srcPort == 80 || srcPort == 443 || srcPort == 8080 || srcPort == 8443 || srcPort == 53 || srcPort == 853 || srcPort == 123 || srcPort == 22
			isReturnTraffic := isServerResponsePort || (dstPort >= 1024 && srcPort < 1024)

			if ddosEnabled && !isReturnTraffic && deltaPackets > ddosThreshold {
				if _, _, _, err := ValidateTargetSafety(srcIP6.String(), "", 0, 24, 64); err == nil && m.objs.Blocklist6Map != nil {
					expTime := now.Add(ddosCooldown)
					expNs := uint64(0)
					if nowKtime > 0 {
						expNs = nowKtime + uint64(ddosCooldown.Nanoseconds())
					}
					blkVal := ebpf.FlowTrackerXdpBlockVal{
						ExpiresNs:  expNs,
						ReasonCode: XdpReasonAutoDdos,
						Active:     1,
					}
					m.blockMu.Lock()
					_ = m.objs.Blocklist6Map.Put(ebpf.FlowTrackerIpv6AddrKey{Addr: k6.SrcIp6}, blkVal)
					m.blockMetaV6[k6.SrcIp6] = xdpBlockMeta{
						expiresAt: expTime,
						reason:    "Volumetric IPv6 XDP Auto-DDoS Mitigation",
					}
					m.blockMu.Unlock()
				}
			}

			if nowKtime == 0 || v6.LastSeenNs == 0 || (nowKtime > v6.LastSeenNs && nowKtime-v6.LastSeenNs > uint64(30*time.Second)) {
				keys6ToDelete = append(keys6ToDelete, k6)
			}
		}
		for i := range keys6ToDelete {
			if err := m.objs.Flow6Map.Delete(&keys6ToDelete[i]); err == nil {
				delete(nextPrev6, keys6ToDelete[i])
			}
		}
		m.prevPackets6 = nextPrev6
	} else {
		m.prevPackets6 = make(map[ebpf.FlowTrackerFlow6Key]uint64)
	}

	if batch != nil {
		if count > 0 {
			if err := batch.Send(); err != nil {
				log.Printf("ClickHouse send batch error: %v", err)
			} else {
				log.Printf("Exported %d flow records to ClickHouse", count)
			}
		} else {
			_ = batch.Abort()
		}
	}
}

// requireXdpEnforcing reports whether a block added right now would
// actually be dropped by the kernel: the manager must be started with
// at least one XDP program attached. Callers check this BEFORE taking
// blockMu: GetDataplaneSnapshot takes mu then blockMu, so taking them
// in the opposite order here could deadlock against a concurrent
// snapshot.
func (m *EBPFManager) requireXdpEnforcing() error {
	m.mu.Lock()
	running := m.running
	attached := len(m.attachedIfaces) > 0
	m.mu.Unlock()
	if !running || !attached {
		return errors.New("XDP dataplane is not enforcing: eBPF manager is not running with an attached interface; refusing to record a block the kernel would not drop")
	}
	return nil
}

// AddXdpBlock inserts a single IPv4/IPv6 host address OR an IPv4 (/8../32) / IPv6 (/16../128) CIDR
// subnet into the Ring-0 NIC driver XDP blocklist / LPM Trie map with blast-radius validation.
func (m *EBPFManager) AddXdpBlock(ipOrCidr string, ttlSeconds int, reasonCode uint32, reasonText string) error {
	if m == nil {
		return errors.New("eBPF manager is not initialized")
	}
	raw := strings.TrimSpace(ipOrCidr)
	if raw == "" {
		return errors.New("empty IP or CIDR for XDP blocklist")
	}
	if ttlSeconds < 10 {
		ttlSeconds = 10
	}
	if ttlSeconds > 604800 {
		ttlSeconds = 604800
	}

	now := time.Now()
	expAt := now.Add(time.Duration(ttlSeconds) * time.Second)
	nowKtime := ktimeMonotonicNs()
	expNs := uint64(0)
	if nowKtime > 0 {
		expNs = nowKtime + uint64(ttlSeconds)*1_000_000_000
	}

	// Check if input is a CIDR subnet prefix
	if strings.Contains(raw, "/") {
		ip, ipNet, err := net.ParseCIDR(raw)
		if err != nil || ip == nil || ipNet == nil {
			return fmt.Errorf("invalid CIDR %q for XDP LPM blocklist", ipOrCidr)
		}
		ones, bitsLen := ipNet.Mask.Size()
		if _, _, _, err := ValidateTargetSafety(ipNet.String(), "", 0, 8, 16); err != nil {
			return fmt.Errorf("XDP CIDR safety guard rejected %q: %w", ipNet.String(), err)
		}
		// Host /32 or /128 routes through exact host map
		if (bitsLen == 32 && ones == 32) || (bitsLen == 128 && ones == 128) {
			raw = ip.String()
		} else {
			if reasonCode == 0 {
				reasonCode = XdpReasonLpmCidrDrop
			}
			blkVal := ebpf.FlowTrackerXdpBlockVal{
				ExpiresNs:  expNs,
				ReasonCode: reasonCode,
				Active:     1,
			}
			// A-H3 (round 3): a nil map used to mean "record the
			// userspace metadata and return nil", so the block was
			// listed as active while the kernel dropped nothing.
			// A block that cannot be written to the kernel map is
			// not a block: fail loudly and record nothing.
			if err := m.requireXdpEnforcing(); err != nil {
				return err
			}
			m.objsMu.RLock()
			defer m.objsMu.RUnlock()
			m.blockMu.Lock()
			defer m.blockMu.Unlock()

			if ip4 := ipNet.IP.To4(); ip4 != nil && bitsLen == 32 {
				lpmKey := ebpf.FlowTrackerLpmV4Key{
					Prefixlen: uint32(ones),
					Addr:      ipv4Uint32FromBytes(ip4),
				}
				if m.objs.CidrBlock4Map == nil {
					return fmt.Errorf("XDP cidr_block4_map is not loaded: eBPF dataplane not enforcing; block %q not recorded", raw)
				}
				if err := m.objs.CidrBlock4Map.Put(lpmKey, blkVal); err != nil {
					return fmt.Errorf("failed to insert IPv4 CIDR into XDP cidr_block4_map: %w", err)
				}
				m.cidrMetaV4[lpmKey] = xdpBlockMeta{expiresAt: expAt, reason: reasonText}
				return nil
			}

			ip6 := ipNet.IP.To16()
			if ip6 == nil {
				return fmt.Errorf("unsupported CIDR %q", ipOrCidr)
			}
			var addrArr [16]uint8
			copy(addrArr[:], ip6)
			lpmKey6 := ebpf.FlowTrackerLpmV6Key{
				Prefixlen: uint32(ones),
				Addr:      addrArr,
			}
			if m.objs.CidrBlock6Map == nil {
				return fmt.Errorf("XDP cidr_block6_map is not loaded: eBPF dataplane not enforcing; block %q not recorded", raw)
			}
			if err := m.objs.CidrBlock6Map.Put(lpmKey6, blkVal); err != nil {
				return fmt.Errorf("failed to insert IPv6 CIDR into XDP cidr_block6_map: %w", err)
			}
			m.cidrMetaV6[lpmKey6] = xdpBlockMeta{expiresAt: expAt, reason: reasonText}
			return nil
		}
	}

	parsed := net.ParseIP(raw)
	if parsed == nil {
		return fmt.Errorf("invalid IP address %q for XDP blocklist", ipOrCidr)
	}
	if _, _, _, err := ValidateTargetSafety(raw, "", 0, 32, 128); err != nil {
		return fmt.Errorf("XDP safety guard rejected target %q: %w", raw, err)
	}
	if reasonCode == 0 {
		reasonCode = XdpReasonMcpTactical
	}

	blkVal := ebpf.FlowTrackerXdpBlockVal{
		ExpiresNs:  expNs,
		ReasonCode: reasonCode,
		Active:     1,
	}

	// A-H3 (round 3): see the CIDR branches above — never record
	// userspace metadata for a block the kernel map did not accept.
	if err := m.requireXdpEnforcing(); err != nil {
		return err
	}
	m.objsMu.RLock()
	defer m.objsMu.RUnlock()
	m.blockMu.Lock()
	defer m.blockMu.Unlock()

	if ip4 := parsed.To4(); ip4 != nil {
		k := ipv4Uint32FromBytes(ip4)
		if m.objs.BlocklistMap == nil {
			return fmt.Errorf("XDP blocklist_map is not loaded: eBPF dataplane not enforcing; block %q not recorded", raw)
		}
		if err := m.objs.BlocklistMap.Put(k, blkVal); err != nil {
			return fmt.Errorf("failed to insert IPv4 into XDP blocklist_map: %w", err)
		}
		m.blockedUntil[k] = expAt
		m.blockMetaV4[k] = xdpBlockMeta{expiresAt: expAt, reason: reasonText}
		return nil
	}

	ip6 := parsed.To16()
	if ip6 == nil {
		return fmt.Errorf("unsupported IP address %q", ipOrCidr)
	}
	var addrArr [16]uint8
	copy(addrArr[:], ip6)
	if m.objs.Blocklist6Map == nil {
		return fmt.Errorf("XDP blocklist6_map is not loaded: eBPF dataplane not enforcing; block %q not recorded", raw)
	}
	if err := m.objs.Blocklist6Map.Put(ebpf.FlowTrackerIpv6AddrKey{Addr: addrArr}, blkVal); err != nil {
		return fmt.Errorf("failed to insert IPv6 into XDP blocklist6_map: %w", err)
	}
	m.blockMetaV6[addrArr] = xdpBlockMeta{expiresAt: expAt, reason: reasonText}
	return nil
}

// RemoveXdpBlock removes a single IPv4/IPv6 address or CIDR subnet from the XDP blocklist maps.
func (m *EBPFManager) RemoveXdpBlock(ipOrCidr string) error {
	if m == nil {
		return errors.New("eBPF manager is not initialized")
	}
	raw := strings.TrimSpace(ipOrCidr)
	if strings.Contains(raw, "/") {
		ip, ipNet, err := net.ParseCIDR(raw)
		if err != nil || ip == nil || ipNet == nil {
			return fmt.Errorf("invalid CIDR %q", ipOrCidr)
		}
		ones, bitsLen := ipNet.Mask.Size()
		if (bitsLen == 32 && ones == 32) || (bitsLen == 128 && ones == 128) {
			raw = ip.String()
		} else {
			m.objsMu.RLock()
			defer m.objsMu.RUnlock()
			m.blockMu.Lock()
			defer m.blockMu.Unlock()
			if ip4 := ipNet.IP.To4(); ip4 != nil && bitsLen == 32 {
				lpmKey := ebpf.FlowTrackerLpmV4Key{
					Prefixlen: uint32(ones),
					Addr:      ipv4Uint32FromBytes(ip4),
				}
				if m.objs.CidrBlock4Map != nil {
					_ = m.objs.CidrBlock4Map.Delete(lpmKey)
				}
				delete(m.cidrMetaV4, lpmKey)
				return nil
			}
			ip6 := ipNet.IP.To16()
			var addrArr [16]uint8
			copy(addrArr[:], ip6)
			lpmKey6 := ebpf.FlowTrackerLpmV6Key{
				Prefixlen: uint32(ones),
				Addr:      addrArr,
			}
			if m.objs.CidrBlock6Map != nil {
				_ = m.objs.CidrBlock6Map.Delete(lpmKey6)
			}
			delete(m.cidrMetaV6, lpmKey6)
			return nil
		}
	}

	parsed := net.ParseIP(raw)
	if parsed == nil {
		return fmt.Errorf("invalid IP address %q", ipOrCidr)
	}

	m.objsMu.RLock()
	defer m.objsMu.RUnlock()
	m.blockMu.Lock()
	defer m.blockMu.Unlock()

	if ip4 := parsed.To4(); ip4 != nil {
		k := ipv4Uint32FromBytes(ip4)
		if m.objs.BlocklistMap != nil {
			_ = m.objs.BlocklistMap.Delete(k)
		}
		delete(m.blockedUntil, k)
		delete(m.blockMetaV4, k)
		return nil
	}

	ip6 := parsed.To16()
	var addrArr [16]uint8
	copy(addrArr[:], ip6)
	if m.objs.Blocklist6Map != nil {
		_ = m.objs.Blocklist6Map.Delete(ebpf.FlowTrackerIpv6AddrKey{Addr: addrArr})
	}
	delete(m.blockMetaV6, addrArr)
	return nil
}

// GetDataplaneSnapshot reads per-CPU XDP verdict counters, dual-stack IPv4/IPv6
// + VLAN flows, and active host + LPM CIDR XDP drop statistics directly from kernel BPF maps.
func (m *EBPFManager) GetDataplaneSnapshot(maxFlows int) EbpfDataplaneSnapshot {
	if maxFlows <= 0 || maxFlows > 500 {
		maxFlows = 50
	}
	snap := EbpfDataplaneSnapshot{
		AttachedInterfaces: []string{},
		PerCpuStats:        []XdpPerCpuTelemetry{},
		ProtocolBreakdown:  []XdpProtocolSummary{},
		TopPorts:           []XdpPortSummary{},
		VlanBreakdown:      []XdpVlanSummary{},
		SynRateMeters:      []XdpSynMeterEntry{},
		TopFlows:           []XdpFlowSnapshotEntry{},
		ActiveBlocks:       []XdpBlockSnapshotEntry{},
		Timestamp:          time.Now().UTC().Format(time.RFC3339),
	}
	if m == nil {
		return snap
	}

	m.mu.Lock()
	snap.Running = m.running
	snap.AttachedInterfaces = append([]string(nil), m.attachedIfaces...)
	snap.ClickHouseEnabled = m.ch != nil
	m.mu.Unlock()
	snap.SynFloodLimitPps = m.synFloodLimitPps.Load()

	nowKtime := ktimeMonotonicNs()

	m.objsMu.RLock()
	defer m.objsMu.RUnlock()

	// 1. Sum per-CPU XDP stats and capture per-core distribution
	if m.objs.XdpStatsMap != nil {
		var perCpu []ebpf.FlowTrackerXdpDatastats
		if err := m.objs.XdpStatsMap.Lookup(uint32(0), &perCpu); err == nil {
			snap.PerCpuStats = make([]XdpPerCpuTelemetry, 0, len(perCpu))
			for cpuIdx, cpuStat := range perCpu {
				snap.Stats.RxPackets += cpuStat.RxPackets
				snap.Stats.RxBytes += cpuStat.RxBytes
				snap.Stats.XdpPass += cpuStat.XdpPass
				snap.Stats.XdpDrop += cpuStat.XdpDrop
				snap.Stats.Ipv4Packets += cpuStat.Ipv4Packets
				snap.Stats.Ipv6Packets += cpuStat.Ipv6Packets
				snap.Stats.VlanPackets += cpuStat.VlanPackets
				snap.Stats.TcpSynPackets += cpuStat.TcpSynPackets
				snap.Stats.LpmCidrDrops += cpuStat.LpmCidrDrops
				snap.Stats.SynFloodDrops += cpuStat.SynFloodDrops
				snap.PerCpuStats = append(snap.PerCpuStats, XdpPerCpuTelemetry{
					Cpu:           cpuIdx,
					RxPackets:     cpuStat.RxPackets,
					RxBytes:       cpuStat.RxBytes,
					XdpPass:       cpuStat.XdpPass,
					XdpDrop:       cpuStat.XdpDrop,
					Ipv4Packets:   cpuStat.Ipv4Packets,
					Ipv6Packets:   cpuStat.Ipv6Packets,
					VlanPackets:   cpuStat.VlanPackets,
					TcpSynPackets: cpuStat.TcpSynPackets,
					LpmCidrDrops:  cpuStat.LpmCidrDrops,
					SynFloodDrops: cpuStat.SynFloodDrops,
				})
			}
		}
	}

	// 2. Collect IPv4 & IPv6 LRU flows
	flows, v4Count, v6Count := m.collectFlowEntriesLocked(nowKtime)
	snap.TotalFlowCountV4 = v4Count
	snap.TotalFlowCountV6 = v6Count
	snap.TotalFlowCount = snap.TotalFlowCountV4 + snap.TotalFlowCountV6
	snap.ProtocolBreakdown, snap.TopPorts, snap.VlanBreakdown = summarizeXdpFlows(flows)
	sort.Slice(flows, func(i, j int) bool { return flows[i].Bytes > flows[j].Bytes })
	if len(flows) > maxFlows {
		flows = flows[:maxFlows]
	}
	if len(flows) > 0 {
		snap.TopFlows = flows
	}

	// 2b. Collect live TCP SYN rate-meter entries from IPv4/IPv6 SYN maps
	var synMeters []XdpSynMeterEntry
	if m.objs.SynMeter4Map != nil {
		iterSyn4 := m.objs.SynMeter4Map.Iterate()
		var ipUint uint32
		var mv ebpf.FlowTrackerSynMeterVal
		for iterSyn4.Next(&ipUint, &mv) {
			if mv.SynCount == 0 && mv.DroppedPackets == 0 {
				continue
			}
			ageMs := int64(0)
			if nowKtime > 0 && mv.WindowStartNs > 0 && nowKtime >= mv.WindowStartNs {
				ageMs = int64((nowKtime - mv.WindowStartNs) / 1_000_000)
			}
			synMeters = append(synMeters, XdpSynMeterEntry{
				IP:             ipv4FromUint32(ipUint).String(),
				Family:         4,
				SynCount:       mv.SynCount,
				DroppedPackets: mv.DroppedPackets,
				WindowAgeMs:    ageMs,
			})
		}
	}
	if m.objs.SynMeter6Map != nil {
		iterSyn6 := m.objs.SynMeter6Map.Iterate()
		var k6 ebpf.FlowTrackerIpv6AddrKey
		var mv ebpf.FlowTrackerSynMeterVal
		for iterSyn6.Next(&k6, &mv) {
			if mv.SynCount == 0 && mv.DroppedPackets == 0 {
				continue
			}
			ageMs := int64(0)
			if nowKtime > 0 && mv.WindowStartNs > 0 && nowKtime >= mv.WindowStartNs {
				ageMs = int64((nowKtime - mv.WindowStartNs) / 1_000_000)
			}
			synMeters = append(synMeters, XdpSynMeterEntry{
				IP:             net.IP(k6.Addr[:]).String(),
				Family:         6,
				SynCount:       mv.SynCount,
				DroppedPackets: mv.DroppedPackets,
				WindowAgeMs:    ageMs,
			})
		}
	}
	if len(synMeters) > 0 {
		sort.Slice(synMeters, func(i, j int) bool {
			if synMeters[i].DroppedPackets != synMeters[j].DroppedPackets {
				return synMeters[i].DroppedPackets > synMeters[j].DroppedPackets
			}
			return synMeters[i].SynCount > synMeters[j].SynCount
		})
		if len(synMeters) > 25 {
			synMeters = synMeters[:25]
		}
		snap.SynRateMeters = synMeters
	}

	// 3. Collect active XDP host & LPM CIDR blocklist entries
	m.blockMu.Lock()
	seenV4 := make(map[uint32]bool)
	if m.objs.BlocklistMap != nil {
		iter := m.objs.BlocklistMap.Iterate()
		var ipUint uint32
		var bv ebpf.FlowTrackerXdpBlockVal
		for iter.Next(&ipUint, &bv) {
			if bv.Active == 0 {
				continue
			}
			seenV4[ipUint] = true
			meta := m.blockMetaV4[ipUint]
			expStr := ""
			if !meta.expiresAt.IsZero() {
				expStr = meta.expiresAt.UTC().Format(time.RFC3339)
			} else if exp, ok := m.blockedUntil[ipUint]; ok {
				expStr = exp.UTC().Format(time.RFC3339)
			}
			snap.ActiveBlocks = append(snap.ActiveBlocks, XdpBlockSnapshotEntry{
				IP:          ipv4FromUint32(ipUint).String(),
				Family:      4,
				DropPackets: bv.DropPackets,
				DropBytes:   bv.DropBytes,
				ReasonCode:  bv.ReasonCode,
				Reason:      xdpReasonLabel(bv.ReasonCode, meta.reason),
				ExpiresAt:   expStr,
			})
		}
	}
	// A-H3: the metadata-only fallbacks below list a block as active
	// even when its kernel map is not loaded, i.e. when nothing is
	// enforced. Each fallback is gated on its map being loaded; with
	// the AddXdpBlock fix no such metadata can be created, and this
	// keeps a stale entry from ever being reported as active again.
	for ipUint, exp := range m.blockedUntil {
		if m.objs.BlocklistMap == nil || seenV4[ipUint] || time.Now().After(exp) {
			continue
		}
		meta := m.blockMetaV4[ipUint]
		snap.ActiveBlocks = append(snap.ActiveBlocks, XdpBlockSnapshotEntry{
			IP:         ipv4FromUint32(ipUint).String(),
			Family:     4,
			ReasonCode: XdpReasonMcpTactical,
			Reason:     xdpReasonLabel(XdpReasonMcpTactical, meta.reason),
			ExpiresAt:  exp.UTC().Format(time.RFC3339),
		})
	}
	seenV6 := make(map[[16]uint8]bool)
	if m.objs.Blocklist6Map != nil {
		iter6 := m.objs.Blocklist6Map.Iterate()
		var k6 ebpf.FlowTrackerIpv6AddrKey
		var bv ebpf.FlowTrackerXdpBlockVal
		for iter6.Next(&k6, &bv) {
			if bv.Active == 0 {
				continue
			}
			seenV6[k6.Addr] = true
			meta := m.blockMetaV6[k6.Addr]
			expStr := ""
			if !meta.expiresAt.IsZero() {
				expStr = meta.expiresAt.UTC().Format(time.RFC3339)
			}
			snap.ActiveBlocks = append(snap.ActiveBlocks, XdpBlockSnapshotEntry{
				IP:          net.IP(k6.Addr[:]).String(),
				Family:      6,
				DropPackets: bv.DropPackets,
				DropBytes:   bv.DropBytes,
				ReasonCode:  bv.ReasonCode,
				Reason:      xdpReasonLabel(bv.ReasonCode, meta.reason),
				ExpiresAt:   expStr,
			})
		}
	}
	for addrArr, meta := range m.blockMetaV6 {
		if m.objs.Blocklist6Map == nil || seenV6[addrArr] || (!meta.expiresAt.IsZero() && time.Now().After(meta.expiresAt)) {
			continue
		}
		snap.ActiveBlocks = append(snap.ActiveBlocks, XdpBlockSnapshotEntry{
			IP:         net.IP(addrArr[:]).String(),
			Family:     6,
			ReasonCode: XdpReasonMcpTactical,
			Reason:     xdpReasonLabel(XdpReasonMcpTactical, meta.reason),
			ExpiresAt:  meta.expiresAt.UTC().Format(time.RFC3339),
		})
	}

	// LPM CIDR entries (IPv4 & IPv6)
	for lpm4, meta := range m.cidrMetaV4 {
		if m.objs.CidrBlock4Map == nil || (!meta.expiresAt.IsZero() && time.Now().After(meta.expiresAt)) {
			continue
		}
		var dropPkts, dropBytes uint64
		reasonCode := XdpReasonLpmCidrDrop
		if m.objs.CidrBlock4Map != nil {
			var bv ebpf.FlowTrackerXdpBlockVal
			if err := m.objs.CidrBlock4Map.Lookup(lpm4, &bv); err == nil {
				dropPkts = bv.DropPackets
				dropBytes = bv.DropBytes
				if bv.ReasonCode != 0 {
					reasonCode = bv.ReasonCode
				}
			}
		}
		snap.ActiveBlocks = append(snap.ActiveBlocks, XdpBlockSnapshotEntry{
			IP:          fmt.Sprintf("%s/%d", ipv4FromUint32(lpm4.Addr).String(), lpm4.Prefixlen),
			Family:      4,
			IsCidr:      true,
			DropPackets: dropPkts,
			DropBytes:   dropBytes,
			ReasonCode:  reasonCode,
			Reason:      xdpReasonLabel(reasonCode, meta.reason),
			ExpiresAt:   meta.expiresAt.UTC().Format(time.RFC3339),
		})
	}
	for lpm6, meta := range m.cidrMetaV6 {
		if m.objs.CidrBlock6Map == nil || (!meta.expiresAt.IsZero() && time.Now().After(meta.expiresAt)) {
			continue
		}
		var dropPkts, dropBytes uint64
		reasonCode := XdpReasonLpmCidrDrop
		if m.objs.CidrBlock6Map != nil {
			var bv ebpf.FlowTrackerXdpBlockVal
			if err := m.objs.CidrBlock6Map.Lookup(lpm6, &bv); err == nil {
				dropPkts = bv.DropPackets
				dropBytes = bv.DropBytes
				if bv.ReasonCode != 0 {
					reasonCode = bv.ReasonCode
				}
			}
		}
		snap.ActiveBlocks = append(snap.ActiveBlocks, XdpBlockSnapshotEntry{
			IP:          fmt.Sprintf("%s/%d", net.IP(lpm6.Addr[:]).String(), lpm6.Prefixlen),
			Family:      6,
			IsCidr:      true,
			DropPackets: dropPkts,
			DropBytes:   dropBytes,
			ReasonCode:  reasonCode,
			Reason:      xdpReasonLabel(reasonCode, meta.reason),
			ExpiresAt:   meta.expiresAt.UTC().Format(time.RFC3339),
		})
	}
	m.blockMu.Unlock()

	return snap
}

func (m *EBPFManager) collectFlowEntries(nowKtime uint64) ([]XdpFlowSnapshotEntry, int, int) {
	m.objsMu.RLock()
	defer m.objsMu.RUnlock()
	return m.collectFlowEntriesLocked(nowKtime)
}

func (m *EBPFManager) collectFlowEntriesLocked(nowKtime uint64) ([]XdpFlowSnapshotEntry, int, int) {
	var flows []XdpFlowSnapshotEntry
	var v4Count, v6Count int
	if m.objs.FlowMap != nil {
		iter := m.objs.FlowMap.Iterate()
		var k ebpf.FlowTrackerFlowKey
		var v ebpf.FlowTrackerFlowVal
		for iter.Next(&k, &v) {
			v4Count++
			ageMs := int64(0)
			if nowKtime > 0 && v.LastSeenNs > 0 && nowKtime >= v.LastSeenNs {
				ageMs = int64((nowKtime - v.LastSeenNs) / 1_000_000)
			}
			flows = append(flows, XdpFlowSnapshotEntry{
				Family:         4,
				SrcIP:          ipv4FromUint32(k.SrcIp).String(),
				DstIP:          ipv4FromUint32(k.DstIp).String(),
				SrcPort:        bits.ReverseBytes16(k.SrcPort),
				DstPort:        bits.ReverseBytes16(k.DstPort),
				VlanID:         k.VlanId,
				IngressIfIndex: k.IngressIfindex,
				Protocol:       k.Protocol,
				ProtoName:      protocolName(k.Protocol),
				Packets:        v.Packets,
				Bytes:          v.Bytes,
				SynPackets:     v.SynPackets,
				RstPackets:     v.RstPackets,
				TcpFlags:       formatTcpFlags(v.TcpFlags),
				AgeMs:          ageMs,
			})
		}
	}
	if m.objs.Flow6Map != nil {
		iter6 := m.objs.Flow6Map.Iterate()
		var k6 ebpf.FlowTrackerFlow6Key
		var v6 ebpf.FlowTrackerFlowVal
		for iter6.Next(&k6, &v6) {
			v6Count++
			ageMs := int64(0)
			if nowKtime > 0 && v6.LastSeenNs > 0 && nowKtime >= v6.LastSeenNs {
				ageMs = int64((nowKtime - v6.LastSeenNs) / 1_000_000)
			}
			flows = append(flows, XdpFlowSnapshotEntry{
				Family:         6,
				SrcIP:          net.IP(k6.SrcIp6[:]).String(),
				DstIP:          net.IP(k6.DstIp6[:]).String(),
				SrcPort:        bits.ReverseBytes16(k6.SrcPort),
				DstPort:        bits.ReverseBytes16(k6.DstPort),
				VlanID:         k6.VlanId,
				IngressIfIndex: k6.IngressIfindex,
				Protocol:       k6.Protocol,
				ProtoName:      protocolName(k6.Protocol),
				Packets:        v6.Packets,
				Bytes:          v6.Bytes,
				SynPackets:     v6.SynPackets,
				RstPackets:     v6.RstPackets,
				TcpFlags:       formatTcpFlags(v6.TcpFlags),
				AgeMs:          ageMs,
			})
		}
	}
	return flows, v4Count, v6Count
}

// GetAllFlowCounters returns up to maxFlows (clamped to [1, 16384]) active eBPF flow
// entries without the 50-flow UI cap used by GetDataplaneSnapshot.
func (m *EBPFManager) GetAllFlowCounters(maxFlows int) []XdpFlowSnapshotEntry {
	if m == nil {
		return nil
	}
	if maxFlows <= 0 {
		maxFlows = 16384
	}
	if maxFlows > 16384 {
		maxFlows = 16384
	}
	flows, _, _ := m.collectFlowEntries(ktimeMonotonicNs())
	if len(flows) > maxFlows {
		sort.Slice(flows, func(i, j int) bool { return flows[i].Bytes > flows[j].Bytes })
		flows = flows[:maxFlows]
	}
	return flows
}

func (m *EBPFManager) Stop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	wasRunning := m.running
	stopChan := m.stopChan
	doneChan := m.doneChan
	monitorStarted := m.monitorStarted.Load()
	m.running = false
	m.stopChan = nil
	m.doneChan = nil
	m.attachedIfaces = nil
	m.monitorStarted.Store(false)
	links := m.links
	m.links = nil
	ch := m.ch
	m.ch = nil
	m.mu.Unlock()

	if wasRunning && stopChan != nil {
		close(stopChan)
		if doneChan != nil && monitorStarted {
			<-doneChan
		}
	}
	for _, l := range links {
		if l != nil {
			_ = l.Close()
		}
	}
	m.objsMu.Lock()
	m.blockMu.Lock()
	_ = m.objs.Close()
	m.objs = ebpf.FlowTrackerObjects{}
	m.blockMu.Unlock()
	m.objsMu.Unlock()
	if ch != nil {
		_ = ch.Close()
	}
}

// ClearBlocklist purges all currently active XDP host & LPM CIDR blocks from the eBPF maps.
func (m *EBPFManager) ClearBlocklist() {
	m.objsMu.RLock()
	defer m.objsMu.RUnlock()
	m.blockMu.Lock()
	defer m.blockMu.Unlock()
	cleared := 0
	if m.objs.BlocklistMap != nil {
		iter := m.objs.BlocklistMap.Iterate()
		var ipUint uint32
		var val ebpf.FlowTrackerXdpBlockVal
		var keysToDelete []uint32
		for iter.Next(&ipUint, &val) {
			keysToDelete = append(keysToDelete, ipUint)
		}
		for _, k := range keysToDelete {
			_ = m.objs.BlocklistMap.Delete(k)
			cleared++
		}
	}
	if m.objs.Blocklist6Map != nil {
		iter6 := m.objs.Blocklist6Map.Iterate()
		var k6 ebpf.FlowTrackerIpv6AddrKey
		var val ebpf.FlowTrackerXdpBlockVal
		var keys6 []ebpf.FlowTrackerIpv6AddrKey
		for iter6.Next(&k6, &val) {
			keys6 = append(keys6, k6)
		}
		for _, k := range keys6 {
			_ = m.objs.Blocklist6Map.Delete(k)
			cleared++
		}
	}
	if m.objs.CidrBlock4Map != nil {
		for lpm4 := range m.cidrMetaV4 {
			_ = m.objs.CidrBlock4Map.Delete(lpm4)
			cleared++
		}
	}
	if m.objs.CidrBlock6Map != nil {
		for lpm6 := range m.cidrMetaV6 {
			_ = m.objs.CidrBlock6Map.Delete(lpm6)
			cleared++
		}
	}
	m.blockedUntil = make(map[uint32]time.Time)
	m.blockMetaV4 = make(map[uint32]xdpBlockMeta)
	m.blockMetaV6 = make(map[[16]uint8]xdpBlockMeta)
	m.cidrMetaV4 = make(map[ebpf.FlowTrackerLpmV4Key]xdpBlockMeta)
	m.cidrMetaV6 = make(map[ebpf.FlowTrackerLpmV6Key]xdpBlockMeta)
	if cleared > 0 {
		log.Printf("XDP Mitigation: Cleared %d entries from XDP blocklist maps", cleared)
	}
}

func serviceNameForPort(port uint16, proto uint8) string {
	switch port {
	case 22:
		return "SSH"
	case 53:
		return "DNS"
	case 67, 68:
		return "DHCP"
	case 80:
		return "HTTP"
	case 123:
		return "NTP"
	case 179:
		return "BGP"
	case 443:
		if proto == 17 {
			return "QUIC/HTTP3"
		}
		return "HTTPS"
	case 500, 4500:
		return "IPsec/IKE"
	case 2049:
		return "NFS"
	case 2379, 2380:
		return "etcd"
	case 2966:
		return "Axonwall UI"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 4444:
		return "Canary/Trap"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	case 6443:
		return "K3s API"
	case 8080, 8443:
		return "HTTP-Alt"
	case 8472:
		return "Flannel VXLAN"
	case 9000:
		return "ClickHouse"
	case 9092:
		return "Kafka"
	case 51820:
		return "WireGuard"
	default:
		return ""
	}
}

type portAggKey struct {
	port  uint16
	proto uint8
}

func summarizeXdpFlows(flows []XdpFlowSnapshotEntry) ([]XdpProtocolSummary, []XdpPortSummary, []XdpVlanSummary) {
	protos := []XdpProtocolSummary{}
	topPorts := []XdpPortSummary{}
	vlans := []XdpVlanSummary{}
	if len(flows) == 0 {
		return protos, topPorts, vlans
	}

	protoMap := make(map[uint8]*XdpProtocolSummary)
	portMap := make(map[portAggKey]*XdpPortSummary)
	vlanMap := make(map[uint16]*XdpVlanSummary)

	for _, f := range flows {
		pName := f.ProtoName
		if pName == "" {
			pName = protocolName(f.Protocol)
		}
		ps, ok := protoMap[f.Protocol]
		if !ok {
			ps = &XdpProtocolSummary{Protocol: f.Protocol, ProtoName: pName}
			protoMap[f.Protocol] = ps
		}
		ps.Flows++
		ps.Packets += f.Packets
		ps.Bytes += f.Bytes

		if f.DstPort > 0 {
			pk := portAggKey{port: f.DstPort, proto: f.Protocol}
			pt, ok := portMap[pk]
			if !ok {
				pt = &XdpPortSummary{
					Port:      f.DstPort,
					Service:   serviceNameForPort(f.DstPort, f.Protocol),
					Protocol:  f.Protocol,
					ProtoName: pName,
				}
				portMap[pk] = pt
			}
			pt.Flows++
			pt.Packets += f.Packets
			pt.Bytes += f.Bytes
			pt.SynPackets += f.SynPackets
			pt.RstPackets += f.RstPackets
		}

		vl, ok := vlanMap[f.VlanID]
		if !ok {
			vl = &XdpVlanSummary{VlanID: f.VlanID}
			vlanMap[f.VlanID] = vl
		}
		vl.Flows++
		vl.Packets += f.Packets
		vl.Bytes += f.Bytes
	}

	for _, ps := range protoMap {
		protos = append(protos, *ps)
	}
	sort.Slice(protos, func(i, j int) bool {
		if protos[i].Bytes != protos[j].Bytes {
			return protos[i].Bytes > protos[j].Bytes
		}
		return protos[i].Protocol < protos[j].Protocol
	})

	for _, pt := range portMap {
		topPorts = append(topPorts, *pt)
	}
	sort.Slice(topPorts, func(i, j int) bool {
		if topPorts[i].Bytes != topPorts[j].Bytes {
			return topPorts[i].Bytes > topPorts[j].Bytes
		}
		return topPorts[i].Port < topPorts[j].Port
	})
	if len(topPorts) > 12 {
		topPorts = topPorts[:12]
	}

	for _, vl := range vlanMap {
		vlans = append(vlans, *vl)
	}
	sort.Slice(vlans, func(i, j int) bool {
		if vlans[i].Bytes != vlans[j].Bytes {
			return vlans[i].Bytes > vlans[j].Bytes
		}
		return vlans[i].VlanID < vlans[j].VlanID
	})
	if len(vlans) > 16 {
		vlans = vlans[:16]
	}

	return protos, topPorts, vlans
}
