package engine

import (
	"context"
	"fmt"
	"log"
	"math/bits"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/cilium/ebpf/link"

	"github.com/axonwall/axonwall/apps/axonwalld/ebpf"
)

type EBPFManager struct {
	objs         ebpf.FlowTrackerObjects
	links        []link.Link
	ch           driver.Conn
	stopChan     chan struct{}
	doneChan     chan struct{}
	// monitorStarted records whether monitorFlows() was actually launched.
	// Start() returns early on object-load failure before `go
	// m.monitorFlows()`, so doneChan is never closed; Stop() must not
	// wait on it in that case (A-M23).
	monitorStarted atomic.Bool
	prevPackets  map[ebpf.FlowTrackerFlowKey]uint64
	blockedUntil map[uint32]time.Time
	blockMu      sync.Mutex
}

func NewEBPFManager() *EBPFManager {
	return &EBPFManager{
		stopChan:     make(chan struct{}),
		doneChan:     make(chan struct{}),
		prevPackets:  make(map[ebpf.FlowTrackerFlowKey]uint64),
		blockedUntil: make(map[uint32]time.Time),
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

	// Create table if not exists
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
	if err := m.initClickHouse(); err != nil {
		log.Printf("Warning: failed to init ClickHouse: %v. Historical forensics will be disabled.", err)
	}

	// Load pre-compiled programs into the kernel.
	if err := ebpf.LoadFlowTrackerObjects(&m.objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}

	for _, iface := range interfaces {
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
	}

	// A-M23: mark the monitor as started before launching it, so Stop()
	// only waits on doneChan when a goroutine will actually close it.
	m.monitorStarted.Store(true)
	go m.monitorFlows()

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

			iter := m.objs.FlowMap.Iterate()
			var key ebpf.FlowTrackerFlowKey
			var val ebpf.FlowTrackerFlowVal
			var keysToDelete []ebpf.FlowTrackerFlowKey

			now := time.Now()
			count := 0

			// 1. Process cooldown expirations on blocklist
			if m.objs.BlocklistMap != nil {
				m.blockMu.Lock()
				for ipUint, expiry := range m.blockedUntil {
					if now.After(expiry) {
						_ = m.objs.BlocklistMap.Delete(ipUint)
						delete(m.blockedUntil, ipUint)
						ip := make(net.IP, 4)
						for i := 0; i < 4; i++ {
							ip[i] = byte(ipUint >> (i * 8))
						}
						log.Printf("DDoS Mitigation: Cooldown expired for IP %s. Removed from XDP blocklist", ip.String())
					}
				}
				m.blockMu.Unlock()
			}

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

			for iter.Next(&key, &val) {
				// Convert uint32 to net.IP
				srcIP := make(net.IP, 4)
				for i := 0; i < 4; i++ {
					srcIP[i] = byte(key.SrcIp >> (i * 8))
				}
				dstIP := make(net.IP, 4)
				for i := 0; i < 4; i++ {
					dstIP[i] = byte(key.DstIp >> (i * 8))
				}

				// Network byte order to host byte order:
				srcPort := bits.ReverseBytes16(key.SrcPort)
				dstPort := bits.ReverseBytes16(key.DstPort)

				deltaPackets := val.Packets
				if prev, ok := m.prevPackets[key]; ok && val.Packets >= prev {
					deltaPackets = val.Packets - prev
				}
				m.prevPackets[key] = val.Packets

				// Filter out response/download traffic:
				// Never block legitimate response traffic from standard server ports:
				// 80 (HTTP), 443 (HTTPS), 8080/8443 (Alt-HTTP/S), 53 (DNS), 853 (DoT), 123 (NTP), 22 (SSH)
				isServerResponsePort := srcPort == 80 || srcPort == 443 || srcPort == 8080 || srcPort == 8443 || srcPort == 53 || srcPort == 853 || srcPort == 123 || srcPort == 22
				isReturnTraffic := isServerResponsePort || (dstPort >= 1024 && srcPort < 1024)

				if ddosEnabled && !isReturnTraffic && deltaPackets > ddosThreshold {
					if _, _, _, err := ValidateTargetSafety(srcIP.String(), "", 0, 24, 64); err == nil {
						log.Printf("DDoS Mitigation: Volumetric threshold exceeded (%d packets/10s on port %d -> %d). Blocking IP %s via XDP for %v cooldown", deltaPackets, srcPort, dstPort, srcIP.String(), ddosCooldown)
						if m.objs.BlocklistMap != nil {
							m.blockMu.Lock()
							_ = m.objs.BlocklistMap.Put(key.SrcIp, uint8(1))
							m.blockedUntil[key.SrcIp] = now.Add(ddosCooldown)
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

				keysToDelete = append(keysToDelete, key)
			}

			for i := range keysToDelete {
				if err := m.objs.FlowMap.Delete(&keysToDelete[i]); err == nil {
					delete(m.prevPackets, keysToDelete[i])
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

func (m *EBPFManager) Stop() {
	if m.stopChan != nil {
		close(m.stopChan)
		m.stopChan = nil
		// A-M23: only wait for the monitor goroutine when one actually
		// started. Start() returns early on object-load failure before
		// `go m.monitorFlows()`, so doneChan is never closed and an
		// unconditional wait deadlocks daemon shutdown (systemd must
		// SIGKILL it). Same when Start() was never called at all.
		if m.monitorStarted.Load() && m.doneChan != nil {
			<-m.doneChan
		}
	}
	for _, l := range m.links {
		l.Close()
	}
	m.objs.Close()
	if m.ch != nil {
		_ = m.ch.Close()
	}
}

// ClearBlocklist purges all currently active XDP blocks from the eBPF blocklist map.
func (m *EBPFManager) ClearBlocklist() {
	m.blockMu.Lock()
	defer m.blockMu.Unlock()
	if m.objs.BlocklistMap == nil {
		return
	}
	iter := m.objs.BlocklistMap.Iterate()
	var ipUint uint32
	var val uint8
	var keysToDelete []uint32
	for iter.Next(&ipUint, &val) {
		keysToDelete = append(keysToDelete, ipUint)
	}
	for _, k := range keysToDelete {
		_ = m.objs.BlocklistMap.Delete(k)
	}
	m.blockedUntil = make(map[uint32]time.Time)
	if len(keysToDelete) > 0 {
		log.Printf("DDoS Mitigation: Cleared %d entries from XDP blocklist", len(keysToDelete))
	}
}
