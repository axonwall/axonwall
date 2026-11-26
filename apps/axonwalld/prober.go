package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
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
	config        *SDWanConfig
	mu            sync.Mutex
	reloadMu      sync.Mutex
	active        map[string]bool
	stats         map[string]engine.GatewayProbeStats
	ownedDefaults map[string]bool
	cancel        context.CancelFunc
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
		active:        make(map[string]bool),
		stats:         make(map[string]engine.GatewayProbeStats),
		ownedDefaults: make(map[string]bool),
	}
}

func (p *SDWanProber) ReloadConfig(path string) error {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// The config is gone: any in-flight failover
			// computed from it is stale, so bump the
			// generation before stopping the loop.
			p.mu.Lock()
			p.generation++
			p.mu.Unlock()
			p.stopLocked()
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
		p.stopLocked()
		p.wg.Wait()
		return nil
	}

	p.restartLocked()
	return nil
}

func (p *SDWanProber) stopLocked() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
}

func (p *SDWanProber) stop() {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()
	p.stopLocked()
	p.wg.Wait()
}

func (p *SDWanProber) restart() {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()
	p.restartLocked()
}

func (p *SDWanProber) restartLocked() {
	p.stopLocked()
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

var (
	pingLossRegex = regexp.MustCompile(`(\d+(?:\.\d+)?)%\s*packet loss`)
	pingRttRegex  = regexp.MustCompile(`(?:rtt|round-trip)\s+min/avg/max(?:/(?:mdev|stddev))?\s*=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)(?:/([0-9.]+))?\s*ms`)
)

// ParsePingOutput extracts average RTT (ms), jitter (ms), and packet loss (%) from
// iputils or BusyBox ping output.
func ParsePingOutput(out string) (rttMs, jitterMs, lossPct float64) {
	if m := pingLossRegex.FindStringSubmatch(out); len(m) >= 2 {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil {
			lossPct = v
		}
	} else {
		lossPct = 100
	}
	if m := pingRttRegex.FindStringSubmatch(out); len(m) >= 4 {
		minV, _ := strconv.ParseFloat(m[1], 64)
		avgV, _ := strconv.ParseFloat(m[2], 64)
		maxV, _ := strconv.ParseFloat(m[3], 64)
		rttMs = avgV
		if len(m) >= 5 && m[4] != "" {
			jitterMs, _ = strconv.ParseFloat(m[4], 64)
		} else if maxV >= minV {
			jitterMs = (maxV - minV) / 2.0
		}
	}
	return rttMs, jitterMs, lossPct
}

// Snapshot returns the most recent probe statistics for all tracked gateways.
func (p *SDWanProber) Snapshot() []engine.GatewayProbeStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.stats) == 0 {
		return nil
	}
	out := make([]engine.GatewayProbeStats, 0, len(p.stats))
	for _, st := range p.stats {
		out = append(out, st)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Name < out[j-1].Name; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// markGatewayOffline records a gateway that could not be probed at
// all as offline (A-M5). It is called from every skip branch of
// probeAll, including a disabled gateway: a gateway that cannot be
// probed must not remain a failover target.
func (p *SDWanProber) markGatewayOffline(name string, stateChanged *bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stats == nil {
		p.stats = make(map[string]engine.GatewayProbeStats)
	}
	st := p.stats[name]
	st.Name = name
	st.Up = false
	st.PacketLossPct = 100
	st.LastProbeUnix = time.Now().Unix()
	p.stats[name] = st
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
		outBytes, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			return
		}
		rttMs, jitterMs, lossPct := ParsePingOutput(string(outBytes))
		if err != nil && lossPct == 0 {
			lossPct = 100
		}

		p.mu.Lock()
		if p.stats == nil {
			p.stats = make(map[string]engine.GatewayProbeStats)
		}
		wasActive := p.active[gw.Name]
		isActive := err == nil
		p.stats[gw.Name] = engine.GatewayProbeStats{
			Name:          gw.Name,
			Interface:     gw.Interface,
			MonitorIP:     targetIP,
			Up:            isActive,
			RttMs:         rttMs,
			JitterMs:      jitterMs,
			PacketLossPct: lossPct,
			LastProbeUnix: time.Now().Unix(),
		}

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
	var hops4, hops6 []string
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
		hopKey := gw.GatewayIP + "@" + resolvedDev
		if gwIP.To4() != nil {
			args4 = append(args4, "nexthop", "via", gw.GatewayIP, "dev", resolvedDev, "weight", weightStr)
			hops4 = append(hops4, hopKey)
		} else {
			args6 = append(args6, "nexthop", "via", gw.GatewayIP, "dev", resolvedDev, "weight", weightStr)
			hops6 = append(hops6, hopKey)
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
			p.recordOwnedDefault("4", hops4)
			slog.Info("SD-WAN Prober: IPv4 default route updated successfully", "active_links", len(activeTargets))
		}
	}
	if len(args6) > 4 {
		cmd := exec.CommandContext(ctx, "ip", args6...)
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Error("SD-WAN Prober: Failed to update IPv6 default route", "error", err, "output", string(out))
		} else {
			p.recordOwnedDefault("6", hops6)
			slog.Info("SD-WAN Prober: IPv6 default route updated successfully", "active_links", len(activeTargets))
		}
	}
}

func proberDefaultRouteKey(family string, hops []string) string {
	sorted := append([]string(nil), hops...)
	sort.Strings(sorted)
	return family + ":" + strings.Join(sorted, "|")
}

func (p *SDWanProber) recordOwnedDefault(family string, hops []string) {
	if len(hops) == 0 {
		return
	}
	key := proberDefaultRouteKey(family, hops)
	prefix := family + ":"
	p.mu.Lock()
	if p.ownedDefaults == nil {
		p.ownedDefaults = make(map[string]bool)
	}
	for existing := range p.ownedDefaults {
		if strings.HasPrefix(existing, prefix) {
			delete(p.ownedDefaults, existing)
		}
	}
	p.ownedDefaults[key] = true
	p.mu.Unlock()
}

// withdrawStaleDefaultRoute deletes kernel default routes that were
// installed by SDWanProber when any gateway in the route (including
// multipath ECMP nexthops) is no longer present in the current config.
// Unowned routes (such as DHCP WAN defaults or static operator routes)
// are never deleted. In host or dev mode, never mutate default routes.
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
	owned := make(map[string]bool, len(p.ownedDefaults))
	for k, v := range p.ownedDefaults {
		if v {
			owned[k] = true
		}
	}
	p.mu.Unlock()

	if len(owned) == 0 {
		return
	}

	for _, family := range []struct {
		id       string
		showArgs []string
		delBase  []string
	}{
		{"4", []string{"-j", "-4", "route", "show", "default"}, []string{"route", "del", "default"}},
		{"6", []string{"-j", "-6", "route", "show", "default"}, []string{"-6", "route", "del", "default"}},
	} {
		out, err := exec.Command("ip", family.showArgs...).CombinedOutput()
		if err != nil {
			continue
		}
		var entries []ipRouteShowEntry
		if err := json.Unmarshal(bytesTrimSpace(out), &entries); err != nil {
			continue
		}
		for _, r := range entries {
			if r.Protocol == "dhcp" {
				continue
			}
			var hops []string
			var gateways []string
			delArgs := append([]string(nil), family.delBase...)
			if len(r.Nexthops) > 0 {
				for _, nh := range r.Nexthops {
					if nh.Gateway == "" || nh.Dev == "" {
						continue
					}
					hops = append(hops, nh.Gateway+"@"+nh.Dev)
					gateways = append(gateways, nh.Gateway)
					delArgs = append(delArgs, "nexthop", "via", nh.Gateway, "dev", nh.Dev)
					if nh.Weight > 0 {
						delArgs = append(delArgs, "weight", strconv.Itoa(nh.Weight))
					}
				}
			} else if r.Gateway != "" && r.Dev != "" {
				hops = append(hops, r.Gateway+"@"+r.Dev)
				gateways = append(gateways, r.Gateway)
				delArgs = append(delArgs, "via", r.Gateway, "dev", r.Dev)
			}
			if r.Metric > 0 {
				delArgs = append(delArgs, "metric", strconv.Itoa(r.Metric))
			}
			if len(hops) == 0 {
				continue
			}
			routeKey := proberDefaultRouteKey(family.id, hops)
			if !owned[routeKey] {
				continue
			}
			stale := false
			for _, gwIP := range gateways {
				if !configured[gwIP] {
					stale = true
					break
				}
			}
			if !stale {
				continue
			}
			slog.Warn("SD-WAN Prober: Withdrawing owned stale default route", "family", family.id, "gateways", gateways)
			if delOut, err := exec.Command("ip", delArgs...).CombinedOutput(); err != nil {
				slog.Error("SD-WAN Prober: Failed to withdraw stale default route", "error", err, "output", string(delOut))
			} else {
				p.mu.Lock()
				delete(p.ownedDefaults, routeKey)
				p.mu.Unlock()
			}
		}
	}
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
