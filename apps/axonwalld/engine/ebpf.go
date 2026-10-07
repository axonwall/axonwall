package engine

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	
	"github.com/axonwall/monorepo/apps/axonwalld/ebpf"
)

type EBPFManager struct {
	objs ebpf.FlowTrackerObjects
	links []link.Link
}

func NewEBPFManager() *EBPFManager {
	return &EBPFManager{}
}

func (m *EBPFManager) Start(interfaces []string) error {
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
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Read flow map and aggregate top 50 flows
		// Send over WebSocket or save to DB
		// Placeholder for WebSocket Controller integration
	}
}

func (m *EBPFManager) Stop() {
	for _, l := range m.links {
		l.Close()
	}
	m.objs.Close()
}
