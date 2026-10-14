package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"time"
)

var validGwIfaceRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

type GatewayTarget struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Interface   string `json:"interface"`
	GatewayIP   string `json:"gatewayIp"`
	MonitorIP   string `json:"monitorIp,omitempty"`
	Weight      int    `json:"weight"`
	IsDefault   bool   `json:"isDefault"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
}

type GatewayGroupMember struct {
	GatewayName string `json:"gatewayName"`
	Tier        int    `json:"tier"`
	Weight      int    `json:"weight"`
}

type GatewayGroup struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Trigger     string               `json:"trigger"`
	Members     []GatewayGroupMember `json:"members"`
	Description string               `json:"description,omitempty"`
}

type SDWanConfig struct {
	Enabled       bool            `json:"enabled"`
	Gateways      []GatewayTarget `json:"gateways"`
	GatewayGroups []GatewayGroup  `json:"gatewayGroups"`
}

type SDWanProber struct {
	config *SDWanConfig
	mu     sync.Mutex
	active map[string]bool
	cancel context.CancelFunc
}

func NewSDWanProber() *SDWanProber {
	return &SDWanProber{
		active: make(map[string]bool),
	}
}

func (p *SDWanProber) ReloadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			p.stop()
			return nil
		}
		return err
	}

	var config SDWanConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	p.mu.Lock()
	p.config = &config
	p.active = make(map[string]bool)
	p.mu.Unlock()

	if !config.Enabled || len(config.Gateways) == 0 {
		p.stop()
		return nil
	}

	p.restart()
	return nil
}

func (p *SDWanProber) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
}

func (p *SDWanProber) restart() {
	p.stop()

	p.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.mu.Unlock()

	go p.run(ctx)
}

func (p *SDWanProber) run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Initial probe
	p.probeAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.probeAll(ctx)
		}
	}
}

func (p *SDWanProber) probeAll(ctx context.Context) {
	p.mu.Lock()
	if p.config == nil || !p.config.Enabled {
		p.mu.Unlock()
		return
	}
	gateways := p.config.Gateways
	groups := p.config.GatewayGroups
	p.mu.Unlock()

	stateChanged := false

	for _, gw := range gateways {
		if !gw.Enabled {
			continue
		}

		targetIP := gw.MonitorIP
		if targetIP == "" {
			targetIP = gw.GatewayIP
		}
		if targetIP == "" || net.ParseIP(targetIP) == nil {
			continue
		}
		if !validGwIfaceRegex.MatchString(gw.Interface) {
			continue
		}

		// Basic ICMP ping with a 1-second timeout, sending 2 packets
		cmd := exec.CommandContext(ctx, "ping", "-c", "2", "-W", "1", "-I", gw.Interface, targetIP)
		err := cmd.Run()
		if ctx.Err() != nil {
			return
		}

		p.mu.Lock()
		wasActive := p.active[gw.Name]
		isActive := err == nil

		if isActive && !wasActive {
			slog.Info("SD-WAN Prober: Gateway came ONLINE", "gateway", gw.Name, "interface", gw.Interface)
			p.active[gw.Name] = true
			stateChanged = true
		} else if !isActive && wasActive {
			slog.Warn("SD-WAN Prober: Gateway went OFFLINE (packet loss)", "gateway", gw.Name, "interface", gw.Interface)
			p.active[gw.Name] = false
			stateChanged = true
		}
		p.mu.Unlock()
	}

	if stateChanged {
		p.triggerFailover(gateways, groups)
	}
}

// Re-evaluates routing table based on active gateways
func (p *SDWanProber) triggerFailover(gateways []GatewayTarget, groups []GatewayGroup) {
	slog.Info("SD-WAN Prober: Re-calculating multi-path default routes...")

	p.mu.Lock()
	defer p.mu.Unlock()

	// If GatewayGroups exist, use them. Otherwise, fallback to gateways with IsDefault=true
	var activeTargets []GatewayTarget

	if len(groups) > 0 {
		// Just evaluate the first group for now (usually the default LoadBalance group)
		group := groups[0]

		bestTier := 999

		// Find the best tier that has at least one active gateway
		for _, member := range group.Members {
			if p.active[member.GatewayName] {
				if member.Tier < bestTier {
					bestTier = member.Tier
				}
			}
		}

		if bestTier == 999 {
			slog.Error("SD-WAN Prober: ALL GATEWAYS IN GROUP OFFLINE. No internet connectivity.")
			return
		}

		// Collect all active gateways in the best tier
		for _, member := range group.Members {
			if member.Tier == bestTier && p.active[member.GatewayName] {
				for _, gw := range gateways {
					if gw.Name == member.GatewayName {
						gwCopy := gw
						if member.Weight > 0 {
							gwCopy.Weight = member.Weight
						}
						activeTargets = append(activeTargets, gwCopy)
					}
				}
			}
		}
	} else {
		// Fallback to gateways marked as default
		for _, gw := range gateways {
			if gw.IsDefault && p.active[gw.Name] {
				activeTargets = append(activeTargets, gw)
			}
		}
	}

	if len(activeTargets) == 0 {
		slog.Error("SD-WAN Prober: No active default gateways available.")
		return
	}

	// Build the multipath route command
	// Example: ip route replace default nexthop via 192.168.1.1 dev eth0 weight 1 nexthop via 10.0.0.1 dev eth2 weight 1
	args := []string{"route", "replace", "default"}
	for _, gw := range activeTargets {
		if net.ParseIP(gw.GatewayIP) == nil || !validGwIfaceRegex.MatchString(gw.Interface) {
			continue
		}
		weight := gw.Weight
		weightStr := "1"
		if weight > 0 {
			weightStr = strconv.Itoa(weight)
		}
		args = append(args, "nexthop", "via", gw.GatewayIP, "dev", gw.Interface, "weight", weightStr)
	}

	if len(args) == 3 {
		slog.Error("SD-WAN Prober: No valid IP/interface targets for default route")
		return
	}

	cmd := exec.Command("ip", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Error("SD-WAN Prober: Failed to update default route", "error", err, "output", string(out))
	} else {
		slog.Info("SD-WAN Prober: Default route updated successfully", "active_links", len(activeTargets))
	}
}
