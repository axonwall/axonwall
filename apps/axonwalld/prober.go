package main

import (
	"context"
	"log/slog"
	"os/exec"
	"sync"
	"time"
)

type GatewayTarget struct {
	Name      string
	IP        string
	Interface string
	Tier      int
}

type SDWanProber struct {
	gateways []GatewayTarget
	mu       sync.Mutex
	active   map[string]bool
}

func NewSDWanProber(targets []GatewayTarget) *SDWanProber {
	return &SDWanProber{
		gateways: targets,
		active:   make(map[string]bool),
	}
}

// Start probing the gateways in the background
func (p *SDWanProber) Start(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.probeAll()
		}
	}
}

func (p *SDWanProber) probeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, gw := range p.gateways {
		// Basic ICMP ping with a 2-second timeout, sending 3 packets
		cmd := exec.Command("ping", "-c", "3", "-W", "2", "-I", gw.Interface, gw.IP)
		err := cmd.Run()

		wasActive := p.active[gw.Name]
		isActive := err == nil

		if isActive && !wasActive {
			slog.Info("SD-WAN Prober: Gateway came ONLINE", "gateway", gw.Name, "interface", gw.Interface, "tier", gw.Tier)
			p.active[gw.Name] = true
			p.triggerFailover()
		} else if !isActive && wasActive {
			slog.Warn("SD-WAN Prober: Gateway went OFFLINE (packet loss)", "gateway", gw.Name, "interface", gw.Interface, "tier", gw.Tier)
			p.active[gw.Name] = false
			p.triggerFailover()
		}
	}
}

// Re-evaluates routing table based on active gateways
func (p *SDWanProber) triggerFailover() {
	slog.Info("SD-WAN Prober: Re-calculating multi-path default routes...")

	// Find highest active tier (lower number is higher priority)
	bestTier := 999
	var bestGateways []GatewayTarget

	for _, gw := range p.gateways {
		if p.active[gw.Name] {
			if gw.Tier < bestTier {
				bestTier = gw.Tier
				bestGateways = []GatewayTarget{gw}
			} else if gw.Tier == bestTier {
				bestGateways = append(bestGateways, gw)
			}
		}
	}

	if len(bestGateways) == 0 {
		slog.Error("SD-WAN Prober: ALL GATEWAYS OFFLINE. No internet connectivity.")
		return
	}

	// Build the multipath route command
	// Example: ip route replace default nexthop via 192.168.1.1 dev eth0 weight 1 nexthop via 10.0.0.1 dev eth2 weight 1
	args := []string{"route", "replace", "default"}
	for _, gw := range bestGateways {
		args = append(args, "nexthop", "via", gw.IP, "dev", gw.Interface, "weight", "1")
	}

	cmd := exec.Command("ip", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Error("SD-WAN Prober: Failed to update default route", "error", err, "output", string(out))
	} else {
		slog.Info("SD-WAN Prober: Default route updated successfully", "tier", bestTier, "active_links", len(bestGateways))
	}
}
