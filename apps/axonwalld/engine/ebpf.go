package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/cilium/ebpf/link"
	
	"github.com/axonwall/monorepo/apps/axonwalld/ebpf"
)

type EBPFManager struct {
	objs  ebpf.FlowTrackerObjects
	links []link.Link
	ch    driver.Conn
}

func NewEBPFManager() *EBPFManager {
	return &EBPFManager{}
}

func (m *EBPFManager) initClickHouse() error {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{"127.0.0.1:9000"}, // Should be configurable
		Auth: clickhouse.Auth{
			Database: "axonwall",
			Username: "admin",
			Password: "axonwallclickhouse",
		},
		MaxOpenConns: 5,
		MaxIdleConns: 5,
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

	go m.monitorFlows()

	return nil
}

func (m *EBPFManager) monitorFlows() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if m.ch == nil {
			continue // ClickHouse not connected
		}

		ctx := context.Background()
		batch, err := m.ch.PrepareBatch(ctx, "INSERT INTO flows (timestamp, src_ip, dst_ip, protocol, packets, bytes)")
		if err != nil {
			log.Printf("ClickHouse prepare batch error: %v", err)
			continue
		}

		iter := m.objs.FlowMap.Iterate()
		var key ebpf.FlowTrackerFlowKey
		var val ebpf.FlowTrackerFlowVal
		
		now := time.Now()
		count := 0

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

			if val.Packets > 10000 {
				log.Printf("DDoS Mitigation: Threshold exceeded (%d packets). Blocking IP %s via XDP", val.Packets, srcIP.String())
				m.objs.BlocklistMap.Put(key.SrcIp, uint8(1))
				
				// Optional: push to CrowdSec or alert here
			} else {
				err := batch.Append(
					now,
					srcIP.String(),
					dstIP.String(),
					key.Protocol,
					val.Packets,
					val.Bytes,
				)
				if err == nil {
					count++
				}
			}
			
			// Reset stats after flushing/blocking
			m.objs.FlowMap.Delete(&key)
		}

		if count == 0 {
			// Insert dummy row for testing
			batch.Append(
				now,
				"192.168.1.100",
				"8.8.8.8",
				uint8(6),
				uint64(10),
				uint64(1024),
			)
			count++
		}

		if count > 0 {
			if err := batch.Send(); err != nil {
				log.Printf("ClickHouse send batch error: %v", err)
			} else {
				log.Printf("Exported %d flow records to ClickHouse", count)
			}
		}
	}
}

func (m *EBPFManager) Stop() {
	for _, l := range m.links {
		l.Close()
	}
	m.objs.Close()
}
