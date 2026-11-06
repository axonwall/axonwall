package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

var validNetdevRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

type StaticRouteConfig struct {
	ID          string `yaml:"id" json:"id,omitempty"`
	Network     string `yaml:"network" json:"network"`
	Gateway     string `yaml:"gateway" json:"gateway"`
	Interface   string `yaml:"interface" json:"interface,omitempty"`
	Description string `yaml:"description" json:"description,omitempty"`
	Enabled     *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

func (r StaticRouteConfig) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

type RoutingDomainConfig struct {
	Routes        []StaticRouteConfig `yaml:"routes" json:"routes"`
	Gateways      []GatewayTarget     `yaml:"gateways" json:"gateways,omitempty"`
	GatewayGroups []GatewayGroup      `yaml:"gatewayGroups" json:"gatewayGroups,omitempty"`
}

type InterfacesConfigYaml struct {
	Interfaces []struct {
		Name    string `yaml:"name" json:"name"`
		Device  string `yaml:"device" json:"device"`
		Enabled *bool  `yaml:"enabled" json:"enabled"`
	} `yaml:"interfaces" json:"interfaces"`
}

// LoadRoutingConfigFromBytes parses static route definitions from raw YAML or JSON bytes.
func LoadRoutingConfigFromBytes(data []byte) (*RoutingDomainConfig, error) {
	var yamlCfg RoutingDomainConfig
	yamlErr := yaml.Unmarshal(data, &yamlCfg)
	if yamlErr == nil && yamlCfg.Routes != nil {
		return &yamlCfg, nil
	}
	var jsonCfg RoutingDomainConfig
	jsonErr := json.Unmarshal(data, &jsonCfg)
	if jsonErr == nil && jsonCfg.Routes != nil {
		return &jsonCfg, nil
	}
	// A-H1: a file that parses under neither encoding is corrupt, not
	// "zero routes". The old code returned an empty config with a nil
	// error here, so ReconcileStaticRoutes pruned every kernel static
	// route after a typo or a truncated bundle write. A file that
	// parses cleanly but simply defines no routes still yields the
	// empty config below, unchanged.
	if yamlErr != nil && jsonErr != nil {
		return nil, fmt.Errorf("routing config is neither valid YAML nor valid JSON (yaml: %v; json: %v)", yamlErr, jsonErr)
	}
	return &RoutingDomainConfig{Routes: []StaticRouteConfig{}}, nil
}

// LoadRoutingConfig reads the static route definitions from routing.yaml or state.json.
func LoadRoutingConfig() (*RoutingDomainConfig, error) {
	candidatePaths := []string{
		"/etc/axonwall/routing.yaml",
		"/var/lib/axonwall/etc-axonwall/routing.yaml",
		"/etc/axonwall/state.json",
		"/var/lib/axonwall/state.json",
	}

	for _, path := range candidatePaths {
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			continue
		}

		// A-H1: fail closed on a corrupt candidate instead of falling
		// through to a stale mirror and eventually an empty desired
		// set that would prune every static route. A bundle write
		// mirrors /etc/axonwall/*.yaml to /var/lib, so the mirror
		// carries the same corruption and is no safety net here.
		cfg, err := LoadRoutingConfigFromBytes(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", path, err)
		}
		if cfg.Routes != nil {
			return cfg, nil
		}
	}

	return &RoutingDomainConfig{Routes: []StaticRouteConfig{}}, nil
}

func isPlaceholderNetdev(dev string) bool {
	switch strings.ToLower(strings.TrimSpace(dev)) {
	case "", "none", "-", "<none>", "unassigned", "disabled", "null", "auto":
		return true
	}
	return false
}

// loadInterfaceDeviceMap builds a mapping from logical interface names (wan, lan, opt1, etc.)
// to system kernel net devices (e.g. ens19, ens18, eth0, etc.).
func loadInterfaceDeviceMap() map[string]string {
	devMap := make(map[string]string)

	// 1. Read /etc/axonwall/interfaces.conf
	for _, confPath := range []string{"/etc/axonwall/interfaces.conf", "/var/lib/axonwall/etc-axonwall/interfaces.conf"} {
		if data, err := os.ReadFile(confPath); err == nil {
			rawKv := make(map[string]string)
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				k := strings.TrimSpace(parts[0])
				v := strings.TrimSpace(parts[1])
				rawKv[k] = v
			}
			for k, v := range rawKv {
				if isPlaceholderNetdev(v) {
					continue
				}
				switch k {
				case "WAN_INTERFACE":
					devMap["wan"] = v
				case "LAN_INTERFACE":
					devMap["lan"] = v
				case "OPT1_INTERFACE":
					devMap["opt1"] = v
				case "OPT2_INTERFACE":
					devMap["opt2"] = v
				default:
					if strings.HasPrefix(k, "IFACE_") && strings.HasSuffix(k, "_DEVICE") {
						rawKey := strings.TrimSuffix(strings.TrimPrefix(k, "IFACE_"), "_DEVICE")
						name := strings.TrimSpace(rawKv["IFACE_"+rawKey+"_NAME"])
						if name == "" {
							name = strings.ToLower(rawKey)
						}
						if name != "" {
							devMap[strings.ToLower(name)] = v
						}
					}
				}
			}
			break
		}
	}

	// 2. Read /etc/axonwall/interfaces.yaml if present
	for _, path := range []string{"/etc/axonwall/interfaces.yaml", "/var/lib/axonwall/etc-axonwall/interfaces.yaml"} {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			var ifCfg InterfacesConfigYaml
			if err := yaml.Unmarshal(data, &ifCfg); err == nil {
				for _, iface := range ifCfg.Interfaces {
					name := strings.ToLower(strings.TrimSpace(iface.Name))
					if name == "" {
						continue
					}
					if (iface.Enabled != nil && !*iface.Enabled) || isPlaceholderNetdev(iface.Device) {
						delete(devMap, name)
						continue
					}
					devMap[name] = iface.Device
				}
			}
			break
		}
	}

	// 3. Read /etc/axonwall/state.json if present (overrides stale interfaces.conf entries)
	for _, path := range []string{"/etc/axonwall/state.json", "/var/lib/axonwall/state.json"} {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			var state struct {
				Interfaces []struct {
					Name    string `json:"name"`
					Device  string `json:"device"`
					Enabled *bool  `json:"enabled"`
				} `json:"interfaces"`
			}
			if err := json.Unmarshal(data, &state); err == nil {
				for _, iface := range state.Interfaces {
					name := strings.ToLower(strings.TrimSpace(iface.Name))
					if name == "" {
						continue
					}
					if (iface.Enabled != nil && !*iface.Enabled) || isPlaceholderNetdev(iface.Device) {
						delete(devMap, name)
						continue
					}
					devMap[name] = iface.Device
				}
			}
			break
		}
	}

	return devMap
}

// resolveInterfaceDevice resolves an interface string (e.g. "lan" or "ens18") to an actual net device.
func resolveInterfaceDevice(ifaceName string, devMap map[string]string) string {
	ifaceName = strings.TrimSpace(ifaceName)
	if isPlaceholderNetdev(ifaceName) {
		return ""
	}

	// Direct match if device exists in OS
	if _, err := net.InterfaceByName(ifaceName); err == nil {
		return ifaceName
	}

	// Check logical name mapping
	lower := strings.ToLower(ifaceName)
	if mapped, ok := devMap[lower]; ok && !isPlaceholderNetdev(mapped) {
		if _, err := net.InterfaceByName(mapped); err == nil {
			return mapped
		}
		if validNetdevRegex.MatchString(mapped) {
			return mapped
		}
	}

	if validNetdevRegex.MatchString(ifaceName) {
		return ifaceName
	}
	return ""
}

// ReconcileStaticRoutes synchronizes the Linux kernel routing table with static routes
// defined in /etc/axonwall/routing.yaml or state.json.
// reconcileStaticRoutesMu serialises all static-route reconciliations
// (A-M12). Reconcile reads config, applies routes, then prunes against
// shared kernel state; two concurrent runs with different config
// snapshots could interleave apply/prune so the older run's prune
// deletes a route the newer config just installed.
var reconcileStaticRoutesMu sync.Mutex

func ReconcileStaticRoutes() error {
	reconcileStaticRoutesMu.Lock()
	defer reconcileStaticRoutesMu.Unlock()
	return reconcileStaticRoutesLocked()
}

func reconcileStaticRoutesLocked() error {
	cfg, err := LoadRoutingConfig()
	if err != nil {
		return fmt.Errorf("failed to load static routes: %w", err)
	}

	devMap := loadInterfaceDeviceMap()
	desiredRoutes := make(map[string]StaticRouteConfig)

	appliedCount := 0
	for _, r := range cfg.Routes {
		r.Network = strings.TrimSpace(r.Network)
		r.Gateway = strings.TrimSpace(r.Gateway)

		if r.Network == "" || r.Gateway == "" {
			continue
		}

		// Normalize single host IP to CIDR
		if !strings.Contains(r.Network, "/") {
			if ip := net.ParseIP(r.Network); ip != nil {
				if ip.To4() != nil {
					r.Network += "/32"
				} else {
					r.Network += "/128"
				}
			}
		}

		// Validate and canonicalize CIDR and Gateway IP
		_, ipNet, errCIDR := net.ParseCIDR(r.Network)
		ipGW := net.ParseIP(r.Gateway)
		if errCIDR != nil || ipGW == nil {
			log.Printf("[Agent] Warning: Skipping invalid static route destination=%q gateway=%q", r.Network, r.Gateway)
			continue
		}
		r.Network = ipNet.String()

		dev := resolveInterfaceDevice(r.Interface, devMap)

		family := "-4"
		if strings.Contains(r.Network, ":") || ipGW.To4() == nil {
			family = "-6"
		}

		if r.IsEnabled() {
			desiredRoutes[r.Network] = r
			if strings.HasSuffix(r.Network, "/32") {
				desiredRoutes[strings.TrimSuffix(r.Network, "/32")] = r
			} else if strings.HasSuffix(r.Network, "/128") {
				desiredRoutes[strings.TrimSuffix(r.Network, "/128")] = r
			}

			args := []string{family, "route", "replace", r.Network, "via", r.Gateway}
			if dev != "" {
				args = append(args, "dev", dev, "onlink")
			}
			args = append(args, "proto", "static")

			cmd := exec.Command("ip", args...)
			if out, err := cmd.CombinedOutput(); err != nil {
				// If adding with onlink failed, retry without onlink as fallback
				if dev != "" {
					fallbackArgs := []string{family, "route", "replace", r.Network, "via", r.Gateway, "dev", dev, "proto", "static"}
					if fbOut, fbErr := exec.Command("ip", fallbackArgs...).CombinedOutput(); fbErr == nil {
						appliedCount++
						log.Printf("[Agent] Applied static route: %s via %s (dev=%s)", r.Network, r.Gateway, dev)
						continue
					} else {
						log.Printf("[Agent] Failed to apply static route %s via %s: %s", r.Network, r.Gateway, strings.TrimSpace(string(fbOut)))
						continue
					}
				}
				log.Printf("[Agent] Failed to apply static route %s via %s: %s", r.Network, r.Gateway, strings.TrimSpace(string(out)))
			} else {
				appliedCount++
				log.Printf("[Agent] Applied static route: %s via %s (dev=%s, onlink)", r.Network, r.Gateway, dev)
			}
		} else {
			// If explicitly disabled, remove from kernel if present with proto static
			args := []string{family, "route", "del", r.Network, "proto", "static"}
			_ = exec.Command("ip", args...).Run()
		}
	}

	// A-H1: prune only routes this reconciler owns (destinations it
	// installed on an earlier run). A foreign proto-static route — one
	// added by DHCP, keepalived, or an operator's `ip route` — is
	// never this reconciler's to delete, and a config that failed to
	// load never reaches this point (LoadRoutingConfig errors above).
	ownedRoutes := loadOwnedStaticRoutes()
	pruned4, retained4 := pruneObsoleteRoutes("-4", desiredRoutes, ownedRoutes)
	pruned6, retained6 := pruneObsoleteRoutes("-6", desiredRoutes, ownedRoutes)
	prunedCount := pruned4 + pruned6
	// Record this run's installed destinations (plus any owned routes whose
	// deletion failed this cycle) as the owned set for the next reconcile.
	mergedOwned := make(map[string]StaticRouteConfig, len(desiredRoutes)+len(retained4)+len(retained6))
	for k, v := range desiredRoutes {
		mergedOwned[k] = v
	}
	for _, r := range retained4 {
		mergedOwned[r] = StaticRouteConfig{Network: r}
	}
	for _, r := range retained6 {
		mergedOwned[r] = StaticRouteConfig{Network: r}
	}
	saveOwnedStaticRoutes(mergedOwned)

	log.Printf("[Agent] Static routes reconciliation complete: %d active, %d pruned", appliedCount, prunedCount)
	return nil
}

// staticRoutesOwnedPath records the destinations the reconciler last
// installed, so pruning only ever removes routes it owns (A-H1). The
// path is a variable so tests can redirect it.
var staticRoutesOwnedPath = "/var/lib/axonwall/applied-static-routes.json"

func loadOwnedStaticRoutes() map[string]bool {
	owned := make(map[string]bool)
	data, err := os.ReadFile(staticRoutesOwnedPath)
	if err != nil || len(data) == 0 {
		return owned
	}
	var dests []string
	if err := json.Unmarshal(data, &dests); err != nil {
		return owned
	}
	for _, d := range dests {
		if d != "" {
			owned[d] = true
		}
	}
	return owned
}

func saveOwnedStaticRoutes(desired map[string]StaticRouteConfig) {
	dests := make([]string, 0, len(desired))
	for d := range desired {
		dests = append(dests, d)
	}
	data, err := json.Marshal(dests)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(staticRoutesOwnedPath), 0755)
	_ = os.WriteFile(staticRoutesOwnedPath, data, 0600)
}

// shouldPruneStaticRoute reports whether a kernel proto-static route
// may be deleted: it must be absent from the desired set (including
// the host-suffix forms the reconciler records) and present in the
// owned set from a previous reconcile. The default route is never
// pruned here; it is managed separately.
func shouldPruneStaticRoute(dest string, desired map[string]StaticRouteConfig, owned map[string]bool) bool {
	if dest == "default" {
		return false
	}
	if _, ok := desired[dest]; ok {
		return false
	}
	if !strings.Contains(dest, "/") {
		if strings.Contains(dest, ":") {
			if _, ok := desired[dest+"/128"]; ok {
				return false
			}
		} else {
			if _, ok := desired[dest+"/32"]; ok {
				return false
			}
		}
	}
	// Owned check mirrors the desired check, including host-suffix forms.
	if owned[dest] {
		return true
	}
	if !strings.Contains(dest, "/") {
		if strings.Contains(dest, ":") {
			return owned[dest+"/128"]
		}
		return owned[dest+"/32"]
	}
	return false
}

func pruneObsoleteRoutes(family string, desired map[string]StaticRouteConfig, owned map[string]bool) (int, []string) {
	out, err := exec.Command("ip", family, "route", "show", "proto", "static").CombinedOutput()
	if err != nil {
		var retained []string
		for d := range owned {
			isV6 := strings.Contains(d, ":")
			if (family == "-6" && isV6) || (family == "-4" && !isV6) {
				retained = append(retained, d)
			}
		}
		return 0, retained
	}

	pruned := 0
	var retained []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		dest := fields[0]
		if !shouldPruneStaticRoute(dest, desired, owned) {
			continue
		}

		log.Printf("[Agent] Pruning obsolete static route: %s (%s)", dest, family)
		delCmd := exec.Command("ip", family, "route", "del", dest, "proto", "static")
		if err := delCmd.Run(); err == nil {
			pruned++
		} else {
			retained = append(retained, dest)
		}
	}
	return pruned, retained
}
