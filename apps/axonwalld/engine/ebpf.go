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
	Family     int    `json:"family"`
	SrcIP      string `json:"srcIp"`
	DstIP      string `json:"dstIp"`
	SrcPort    uint16 `json:"srcPort"`
	DstPort    uint16 `json:"dstPort"`
	VlanID     uint16 `json:"vlanId"`
	Protocol   uint8  `json:"protocol"`
	ProtoName  string `json:"protoName"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	SynPackets uint64 `json:"synPackets"`
	RstPackets uint64 `json:"rstPackets"`
	TcpFlags   string `json:"tcpFlags,omitempty"`
	AgeMs      int64  `json:"ageMs"`
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

type EbpfDataplaneSnapshot struct {
	Running            bool                    `json:"running"`
	AttachedInterfaces []string                `json:"attachedInterfaces"`
	ClickHouseEnabled  bool                    `json:"clickHouseEnabled"`
	SynFloodLimitPps   uint64                  `json:"synFloodLimitPps"`
	Stats              XdpVerdictTelemetry     `json:"stats"`
	TopFlows           []XdpFlowSnapshotEntry  `json:"topFlows"`
	ActiveBlocks       []XdpBlockSnapshotEntry `json:"activeBlocks"`
	Timestamp          string                  `json:"timestamp"`
}

type xdpBlockMeta struct {
	expiresAt time.Time
	reason    string
}

type EBPFManager struct {
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
		prevPackets6: make(map[ebpf.FlowTrackerFlow6Key]uint64),
		blockedUntil: make(map[uint32]time.Time),
		blockMetaV4:  make(map[uint32]xdpBlockMeta),
		blockMetaV6:  make(map[[16]uint8]xdpBlockMeta),
		cidrMetaV4:   make(map[ebpf.FlowTrackerLpmV4Key]xdpBlockMeta),
		cidrMetaV6:   make(map[ebpf.FlowTrackerLpmV6Key]xdpBlockMeta),
	}
	if rawSyn := strings.TrimSpace(os.Getenv("AXONWALL_XDP_SYN_FLOOD_PPS")); rawSyn != "" {
		if parsed, err := strconv.ParseUint(rawSyn, 10, 64); err == nil && parsed > 0 {
			mgr.synFloodLimitPps.Store(parsed)
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
	chPass := os.Getenv("CLICKHOUSE_PASSWORD")
	if chPass == "" {
		chPass = "axonwallclickhouse"
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
		return err
	}

	m.ch = conn
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
	clearRunning := func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}

	if err := m.initClickHouse(); err != nil {
		log.Printf("Warning: failed to init ClickHouse: %v. Historical forensics will be disabled.", err)
	}

	if err := ebpf.LoadFlowTrackerObjects(&m.objs, nil); err != nil {
		clearRunning()
		return fmt.Errorf("loading objects: %w", err)
	}

	if initSyn := m.synFloodLimitPps.Load(); initSyn > 0 {
		_ = m.SetSynFloodLimitPps(initSyn)
	}

	var attached []string
	seenIf := make(map[string]bool)
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
			Program:   m.objs.XdpFlowTracker,
			Interface: ifaceObj.Index,
		})
		if err != nil {
			log.Printf("Warning: could not attach XDP to %s: %v", iface, err)
			continue
		}
		m.links = append(m.links, l)
		attached = append(attached, iface)
	}

	m.mu.Lock()
	m.attachedIfaces = attached
	if m.stopChan == nil {
		m.stopChan = make(chan struct{})
	}
	if m.doneChan == nil {
		m.doneChan = make(chan struct{})
	}
	m.mu.Unlock()

	m.monitorStarted.Store(true)
	go m.monitorFlows()

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

func (m *EBPFManager) monitorFlows() {
	defer func() {
		if m.doneChan != nil {
			close(m.doneChan)
		}
	}()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			if m.objs.FlowMap == nil {
				continue
			}

			var batch driver.Batch
			if m.ch != nil {
				ctx := context.Background()
				var err error
				batch, err = m.ch.PrepareBatch(ctx, "INSERT INTO flows (timestamp, src_ip, dst_ip, protocol, packets, bytes)")
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

			for iter.Next(&key, &val) {
				srcIP := ipv4FromUint32(key.SrcIp)
				dstIP := ipv4FromUint32(key.DstIp)
				srcPort := bits.ReverseBytes16(key.SrcPort)
				dstPort := bits.ReverseBytes16(key.DstPort)

				deltaPackets := val.Packets
				if prev, ok := m.prevPackets[key]; ok && val.Packets >= prev {
					deltaPackets = val.Packets - prev
				}
				m.prevPackets[key] = val.Packets

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
						val.Bytes,
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
					delete(m.prevPackets, keysToDelete[i])
				}
			}

			// Sweep IPv6 LRU flows for volumetric DDoS mitigation & idle eviction
			if m.objs.Flow6Map != nil {
				iter6 := m.objs.Flow6Map.Iterate()
				var k6 ebpf.FlowTrackerFlow6Key
				var v6 ebpf.FlowTrackerFlowVal
				var keys6ToDelete []ebpf.FlowTrackerFlow6Key

				for iter6.Next(&k6, &v6) {
					srcIP6 := net.IP(k6.SrcIp6[:])
					srcPort := bits.ReverseBytes16(k6.SrcPort)
					dstPort := bits.ReverseBytes16(k6.DstPort)

					deltaPackets := v6.Packets
					if prev, ok := m.prevPackets6[k6]; ok && v6.Packets >= prev {
						deltaPackets = v6.Packets - prev
					}
					m.prevPackets6[k6] = v6.Packets

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
						delete(m.prevPackets6, keys6ToDelete[i])
					}
				}
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
	}
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
			m.blockMu.Lock()
			defer m.blockMu.Unlock()

			if ip4 := ipNet.IP.To4(); ip4 != nil && bitsLen == 32 {
				lpmKey := ebpf.FlowTrackerLpmV4Key{
					Prefixlen: uint32(ones),
					Addr:      ipv4Uint32FromBytes(ip4),
				}
				if m.objs.CidrBlock4Map != nil {
					if err := m.objs.CidrBlock4Map.Put(lpmKey, blkVal); err != nil {
						return fmt.Errorf("failed to insert IPv4 CIDR into XDP cidr_block4_map: %w", err)
					}
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
			if m.objs.CidrBlock6Map != nil {
				if err := m.objs.CidrBlock6Map.Put(lpmKey6, blkVal); err != nil {
					return fmt.Errorf("failed to insert IPv6 CIDR into XDP cidr_block6_map: %w", err)
				}
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

	m.blockMu.Lock()
	defer m.blockMu.Unlock()

	if ip4 := parsed.To4(); ip4 != nil {
		k := ipv4Uint32FromBytes(ip4)
		if m.objs.BlocklistMap != nil {
			if err := m.objs.BlocklistMap.Put(k, blkVal); err != nil {
				return fmt.Errorf("failed to insert IPv4 into XDP blocklist_map: %w", err)
			}
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
	if m.objs.Blocklist6Map != nil {
		if err := m.objs.Blocklist6Map.Put(ebpf.FlowTrackerIpv6AddrKey{Addr: addrArr}, blkVal); err != nil {
			return fmt.Errorf("failed to insert IPv6 into XDP blocklist6_map: %w", err)
		}
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

	// 1. Sum per-CPU XDP stats
	if m.objs.XdpStatsMap != nil {
		var perCpu []ebpf.FlowTrackerXdpDatastats
		if err := m.objs.XdpStatsMap.Lookup(uint32(0), &perCpu); err == nil {
			for _, cpuStat := range perCpu {
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
			}
		}
	}

	// 2. Collect IPv4 & IPv6 LRU flows
	var flows []XdpFlowSnapshotEntry
	if m.objs.FlowMap != nil {
		iter := m.objs.FlowMap.Iterate()
		var k ebpf.FlowTrackerFlowKey
		var v ebpf.FlowTrackerFlowVal
		for iter.Next(&k, &v) {
			ageMs := int64(0)
			if nowKtime > 0 && v.LastSeenNs > 0 && nowKtime >= v.LastSeenNs {
				ageMs = int64((nowKtime - v.LastSeenNs) / 1_000_000)
			}
			flows = append(flows, XdpFlowSnapshotEntry{
				Family:     4,
				SrcIP:      ipv4FromUint32(k.SrcIp).String(),
				DstIP:      ipv4FromUint32(k.DstIp).String(),
				SrcPort:    bits.ReverseBytes16(k.SrcPort),
				DstPort:    bits.ReverseBytes16(k.DstPort),
				VlanID:     k.VlanId,
				Protocol:   k.Protocol,
				ProtoName:  protocolName(k.Protocol),
				Packets:    v.Packets,
				Bytes:      v.Bytes,
				SynPackets: v.SynPackets,
				RstPackets: v.RstPackets,
				TcpFlags:   formatTcpFlags(v.TcpFlags),
				AgeMs:      ageMs,
			})
		}
	}
	if m.objs.Flow6Map != nil {
		iter6 := m.objs.Flow6Map.Iterate()
		var k6 ebpf.FlowTrackerFlow6Key
		var v6 ebpf.FlowTrackerFlowVal
		for iter6.Next(&k6, &v6) {
			ageMs := int64(0)
			if nowKtime > 0 && v6.LastSeenNs > 0 && nowKtime >= v6.LastSeenNs {
				ageMs = int64((nowKtime - v6.LastSeenNs) / 1_000_000)
			}
			flows = append(flows, XdpFlowSnapshotEntry{
				Family:     6,
				SrcIP:      net.IP(k6.SrcIp6[:]).String(),
				DstIP:      net.IP(k6.DstIp6[:]).String(),
				SrcPort:    bits.ReverseBytes16(k6.SrcPort),
				DstPort:    bits.ReverseBytes16(k6.DstPort),
				VlanID:     k6.VlanId,
				Protocol:   k6.Protocol,
				ProtoName:  protocolName(k6.Protocol),
				Packets:    v6.Packets,
				Bytes:      v6.Bytes,
				SynPackets: v6.SynPackets,
				RstPackets: v6.RstPackets,
				TcpFlags:   formatTcpFlags(v6.TcpFlags),
				AgeMs:      ageMs,
			})
		}
	}
	sort.Slice(flows, func(i, j int) bool { return flows[i].Bytes > flows[j].Bytes })
	if len(flows) > maxFlows {
		flows = flows[:maxFlows]
	}
	if len(flows) > 0 {
		snap.TopFlows = flows
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
	for ipUint, exp := range m.blockedUntil {
		if seenV4[ipUint] || time.Now().After(exp) {
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
		if seenV6[addrArr] || (!meta.expiresAt.IsZero() && time.Now().After(meta.expiresAt)) {
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
		if !meta.expiresAt.IsZero() && time.Now().After(meta.expiresAt) {
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
		if !meta.expiresAt.IsZero() && time.Now().After(meta.expiresAt) {
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

func (m *EBPFManager) Stop() {
	m.mu.Lock()
	wasRunning := m.running
	stopChan := m.stopChan
	doneChan := m.doneChan
	m.mu.Unlock()

	if wasRunning && stopChan != nil {
		close(stopChan)
		if doneChan != nil && m.monitorStarted.Load() {
			<-doneChan
			m.monitorStarted.Store(false)
		}
		m.mu.Lock()
		m.stopChan = nil
		m.doneChan = nil
		m.running = false
		m.attachedIfaces = nil
		m.mu.Unlock()
	}
	for _, l := range m.links {
		l.Close()
	}
	m.links = nil
	m.objs.Close()
	if m.ch != nil {
		_ = m.ch.Close()
	}
}

// ClearBlocklist purges all currently active XDP host & LPM CIDR blocks from the eBPF maps.
func (m *EBPFManager) ClearBlocklist() {
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
