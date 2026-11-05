package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A-M4 regression: a config reload must not reset the SD-WAN active
// map. Pre-fix, ReloadConfig replaced the map with an empty one, so a
// gateway that was up before the reload and down on the first
// post-reload probe produced no transition and the dead gateway kept
// the default route. The reloads here use enabled:false so no probe
// goroutine is started.
func TestBatch4ProberReloadPreservesActive(t *testing.T) {
	p := NewSDWanProber()
	p.config = &SDWanConfig{
		Gateways: []GatewayTarget{
			{Name: "WAN1", Interface: "eth0", GatewayIP: "192.0.2.1", Enabled: true},
			{Name: "WAN2", Interface: "eth1", GatewayIP: "198.51.100.1", Enabled: true},
		},
	}
	p.active = map[string]bool{"WAN1": true, "WAN2": false}

	writeCfg := func(gateways []GatewayTarget) string {
		t.Helper()
		disabled := false
		data, err := json.Marshal(SDWanConfig{Enabled: &disabled, Gateways: gateways})
		if err != nil {
			t.Fatalf("marshal config: %v", err)
		}
		path := filepath.Join(t.TempDir(), "sdwan.json")
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		return path
	}

	if err := p.ReloadConfig(writeCfg([]GatewayTarget{
		{Name: "WAN1", Interface: "eth0", GatewayIP: "192.0.2.1", Enabled: true},
		{Name: "WAN2", Interface: "eth1", GatewayIP: "198.51.100.1", Enabled: true},
	})); err != nil {
		t.Fatalf("ReloadConfig failed: %v", err)
	}
	if !p.active["WAN1"] {
		t.Fatalf("reload must preserve the previously active WAN1, got active=%v", p.active)
	}
	if p.active["WAN2"] {
		t.Fatalf("reload must preserve the previously inactive WAN2, got active=%v", p.active)
	}

	// Entries for gateways removed from the config are dropped.
	if err := p.ReloadConfig(writeCfg([]GatewayTarget{
		{Name: "WAN1", Interface: "eth0", GatewayIP: "192.0.2.1", Enabled: true},
	})); err != nil {
		t.Fatalf("ReloadConfig failed: %v", err)
	}
	if _, ok := p.active["WAN2"]; ok {
		t.Fatalf("reload must drop entries for removed gateways, got active=%v", p.active)
	}
	if !p.active["WAN1"] {
		t.Fatalf("reload must keep WAN1 across the second reload, got active=%v", p.active)
	}
}

// A-M5 regression: a gateway that stops being probeable must be
// marked offline instead of lingering as active=true. Pre-fix, every
// skip branch returned before the map update, so a renamed/removed
// interface or a disabled gateway kept the default route forever.
func TestBatch4ProberSkipMarksOffline(t *testing.T) {
	p := NewSDWanProber()
	p.config = &SDWanConfig{
		Gateways: []GatewayTarget{
			// Empty interface: unresolvable, hits the skip branch.
			{Name: "GW1", Interface: "", GatewayIP: "192.0.2.1", IsDefault: true, Enabled: true},
			// Disabled gateway: also a skip branch.
			{Name: "GW2", Interface: "eth1", GatewayIP: "198.51.100.1", Enabled: false},
		},
	}
	p.active = map[string]bool{"GW1": true, "GW2": true}

	// triggerFailover runs (both gateways transitioned) but finds no
	// active target, so it returns before invoking `ip`.
	p.probeAll(context.Background())

	if p.active["GW1"] {
		t.Fatalf("unprobeable gateway GW1 must be marked offline, got active=%v", p.active)
	}
	if p.active["GW2"] {
		t.Fatalf("disabled gateway GW2 must be marked offline, got active=%v", p.active)
	}
}
