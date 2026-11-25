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
	"strings"
	"sync"
	"time"

	"github.com/axonwall/axonwall/apps/axonwalld/engine"
)

var validGwIfaceRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,14}$`)

func isValidGwIface(dev string) bool {
	return validGwIfaceRegex.MatchString(dev) && !strings.Contains(dev, "..")
}

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
	Enabled       *bool           `json:"enabled,omitempty"`
	Gateways      []GatewayTarget `json:"gateways"`
	GatewayGroups []GatewayGroup  `json:"gatewayGroups"`
}

func (c *SDWanConfig) isEnabled() bool {
	if c == nil || len(c.Gateways) == 0 {
		return false
	}
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

type SDWanProber struct {
	config *SDWanConfig
	mu     sync.Mutex
	active map[string]bool
	cancel context.CancelFunc
	// generation is bumped by ReloadConfig every time the config
	// changes. triggerFailover snapshots it with the active map and
	// re-checks it just before the `ip route` exec: a reload that
	// lands mid-failover must abort the stale exec instead of
	// installing a default route via a gateway the new config
	// removed (L3). The restart() join waits for the old loop to
	// exit — i.e. for the stale exec to LAND first — so the check
	// before the exec is the only place the race can be caught.
	generation uint64
	// wg tracks the run goroutine so restart waits for the old loop to
	// exit before starting a new one (A-M6). Without the join, the old
	// loop could still be inside triggerFailover (an unbounded `ip route`
	// exec with no context) while the new loop probes and fails over
	// from its own snapshot, and last-writer-wins on the default route.
	wg sync.WaitGroup
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
			// The config is gone: any in-flight failover
			// computed from it is stale, so bump the
			// generation before stopping the loop.
			p.mu.Lock()
			p.generation++
			p.mu.Unlock()
			p.stop()
			// A-M6, same join as restart: a disabled prober must not
			// leave a stale loop that can still move the default route.
			p.wg.Wait()
			return nil
		}
		return err
	}

	var config SDWanConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	// A-M4: seed the active map from the previous config instead of
	// resetting it to empty. A gateway that was up before the reload
	// and is down on the first post-reload probe must produce a
	// true→false transition so triggerFailover runs; with a reset map
	// it produced false→false and the dead gateway kept the default
	// route. Entries for gateways no longer configured are dropped.
	p.mu.Lock()
	prevActive := p.active
	p.config = &config
	p.generation++
	kept := make(map[string]bool)
	for _, gw := range config.Gateways {
		if was, ok := prevActive[gw.Name]; ok {
			kept[gw.Name] = was
		}
	}
	p.active = kept
	p.mu.Unlock()

	if !config.isEnabled() {
		p.stop()
		p.wg.Wait()
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
	// A-M6: wait for the old run goroutine to exit before starting a
	// new one. The wait is deliberately outside p.mu: the old loop's
	// exit path takes no lock, and probeAll's post-cancel path returns
	// before re-acquiring it, so this cannot deadlock with a probe
	// that is mid-flight. A hung `ip route` exec in the old loop's
	// triggerFailover delays the new loop rather than racing it.
	p.wg.Wait()

	p.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.mu.Unlock()

	p.wg.Add(1)
	go p.run(ctx)
}

func (p *SDWanProber) run(ctx context.Context) {
	defer p.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Initial probe
	p.probeAll(ctx)
	if ctx.Err() != nil {
		return
	}

	// A-M4: evaluate failover unconditionally after the first
	// post-reload probe cycle, even if no gateway changed state in
	// that cycle. triggerFailover is a no-op when no gateway is
	// active, so this cannot move the route to a dead gateway; it
	// only guarantees the route reflects the fresh probe results
	// rather than the pre-reload winner.
	p.evaluateFailover()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.probeAll(ctx)
		}
	}
}

// evaluateFailover re-calculates the default route from the current
// active map and config snapshot, regardless of whether the last
// probe cycle observed a transition.
func (p *SDWanProber) evaluateFailover() {
	p.mu.Lock()
	if !p.config.isEnabled() {
		p.mu.Unlock()
		return
	}
	gateways := p.config.Gateways
	groups := p.config.GatewayGroups
	p.mu.Unlock()

	p.triggerFailover(gateways, groups)
}

// markGatewayOffline records a gateway that could not be probed at
// all as offline (A-M5). It is called from every skip branch of
// probeAll, including a disabled gateway: a gateway that cannot be
// probed must not remain a failover target.
func (p *SDWanProber) markGatewayOffline(name string, stateChanged *bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active[name] {
		p.active[name] = false
		*stateChanged = true
	}
}

func (p *SDWanProber) probeAll(ctx context.Context) {
	p.mu.Lock()
	if !p.config.isEnabled() {
		p.mu.Unlock()
		return
	}
	gateways := p.config.Gateways
	groups := p.config.GatewayGroups
	p.mu.Unlock()

	devMap := loadInterfaceDeviceMap()
	stateChanged := false

	for _, gw := range gateways {
		if !gw.Enabled {
			// A-M5: a disabled gateway stops being a failover
			// target instead of lingering as active=true.
			p.markGatewayOffline(gw.Name, &stateChanged)
			continue
		}

		targetIP := gw.MonitorIP
		if targetIP == "" {
			targetIP = gw.GatewayIP
		}
		if targetIP == "" || net.ParseIP(targetIP) == nil {
			// A-M5: "cannot probe" is offline, not "still up".
			// Without this, a gateway whose interface was renamed
			// or removed stayed active=true forever and the
			// default route kept pointing at a dead device.
			p.markGatewayOffline(gw.Name, &stateChanged)
			continue
		}
		resolvedDev := resolveInterfaceDevice(gw.Interface, devMap)
		if !isValidGwIface(resolvedDev) {
			// A-M5: same treatment for an unresolvable device.
			p.markGatewayOffline(gw.Name, &stateChanged)
			continue
		}

		// Basic ICMP ping with a 1-second timeout, sending 2 packets
		pingArgs := []string{"-c", "2", "-W", "1", "-I", resolvedDev, targetIP}
		if ip := net.ParseIP(targetIP); ip != nil && ip.To4() == nil {
			pingArgs = append([]string{"-6"}, pingArgs...)
		}
		cmd := exec.CommandContext(ctx, "ping", pingArgs...)
		err := cmd.Run()
		if ctx.Err() != nil {
			return
		}

		p.mu.Lock()
		wasActive := p.active[gw.Name]
		isActive := err == nil

		if isActive && !wasActive {
			slog.Info("SD-WAN Prober: Gateway came ONLINE", "gateway", gw.Name, "interface", gw.Interface, "device", resolvedDev)
			p.active[gw.Name] = true
			stateChanged = true
		} else if !isActive && wasActive {
			slog.Warn("SD-WAN Prober: Gateway went OFFLINE (packet loss)", "gateway", gw.Name, "interface", gw.Interface, "device", resolvedDev)
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
	activeSnapshot := make(map[string]bool, len(p.active))
	for k, v := range p.active {
		activeSnapshot[k] = v
	}
	gen := p.generation
	p.mu.Unlock()

	devMap := loadInterfaceDeviceMap()

	// If GatewayGroups exist, use them. Otherwise, fallback to gateways with IsDefault=true
	var activeTargets []GatewayTarget

	if len(groups) > 0 {
		// Just evaluate the first group for now (usually the default LoadBalance group)
		group := groups[0]

		bestTier := 999

		// Find the best tier that has at least one active gateway
		for _, member := range group.Members {
			if activeSnapshot[member.GatewayName] {
				if member.Tier < bestTier {
					bestTier = member.Tier
				}
			}
		}

		if bestTier == 999 {
			slog.Error("SD-WAN Prober: ALL GATEWAYS IN GROUP OFFLINE. No internet connectivity.")
			p.withdrawStaleDefaultRoute()
			return
		}

		// Collect all active gateways in the best tier
		for _, member := range group.Members {
			if member.Tier == bestTier && activeSnapshot[member.GatewayName] {
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
			if gw.IsDefault && activeSnapshot[gw.Name] {
				activeTargets = append(activeTargets, gw)
			}
		}
	}

	if len(activeTargets) == 0 {
		slog.Error("SD-WAN Prober: No active default gateways available.")
		p.withdrawStaleDefaultRoute()
		return
	}

	// Build multipath route commands separated by address family.
	args4 := []string{"route", "replace", "default"}
	args6 := []string{"-6", "route", "replace", "default"}
	for _, gw := range activeTargets {
		resolvedDev := resolveInterfaceDevice(gw.Interface, devMap)
		gwIP := net.ParseIP(gw.GatewayIP)
		if gwIP == nil || !isValidGwIface(resolvedDev) {
			continue
		}
		weight := gw.Weight
		weightStr := "1"
		if weight > 0 {
			weightStr = strconv.Itoa(weight)
		}
		if gwIP.To4() != nil {
			args4 = append(args4, "nexthop", "via", gw.GatewayIP, "dev", resolvedDev, "weight", weightStr)
		} else {
			args6 = append(args6, "nexthop", "via", gw.GatewayIP, "dev", resolvedDev, "weight", weightStr)
		}
	}

	if len(args4) == 3 && len(args6) == 4 {
		slog.Error("SD-WAN Prober: No valid IP/interface targets for default route")
		p.withdrawStaleDefaultRoute()
		return
	}

	// L3: re-validate the snapshot before the exec.
	p.mu.Lock()
	stale := p.generation != gen
	p.mu.Unlock()
	if stale {
		slog.Warn("SD-WAN Prober: Config reloaded mid-failover; aborting stale default-route update")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if len(args4) > 3 {
		cmd := exec.CommandContext(ctx, "ip", args4...)
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Error("SD-WAN Prober: Failed to update IPv4 default route", "error", err, "output", string(out))
		} else {
			slog.Info("SD-WAN Prober: IPv4 default route updated successfully", "active_links", len(activeTargets))
		}
	}
	if len(args6) > 4 {
		cmd := exec.CommandContext(ctx, "ip", args6...)
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Error("SD-WAN Prober: Failed to update IPv6 default route", "error", err, "output", string(out))
		} else {
			slog.Info("SD-WAN Prober: IPv6 default route updated successfully", "active_links", len(activeTargets))
		}
	}
}

// withdrawStaleDefaultRoute deletes the kernel default route when it
// points at a gateway the CURRENT config no longer contains (L3).
// In host or dev mode, never delete the workstation's default route.
func (p *SDWanProber) withdrawStaleDefaultRoute() {
	if currentRuntimeMode != engine.ModeAppliance {
		return
	}
	p.mu.Lock()
	configured := make(map[string]bool)
	if p.config != nil {
		for _, gw := range p.config.Gateways {
			if gw.GatewayIP != "" {
				configured[gw.GatewayIP] = true
			}
		}
	}
	p.mu.Unlock()

	for _, family := range []struct {
		showArgs []string
		delArgs  []string
	}{
		{[]string{"route", "show", "default"}, []string{"route", "del", "default"}},
		{[]string{"-6", "route", "show", "default"}, []string{"-6", "route", "del", "default"}},
	} {
		out, err := exec.Command("ip", family.showArgs...).CombinedOutput()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var vias []string
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "via" && i+1 < len(fields) {
					vias = append(vias, fields[i+1])
				}
			}
			if len(vias) == 1 && !configured[vias[0]] {
				slog.Warn("SD-WAN Prober: Withdrawing stale default route via unconfigured gateway", "gateway", vias[0])
				if delOut, err := exec.Command("ip", family.delArgs...).CombinedOutput(); err != nil {
					slog.Error("SD-WAN Prober: Failed to withdraw stale default route", "error", err, "output", string(delOut))
				}
			}
			break
		}
	}
}
