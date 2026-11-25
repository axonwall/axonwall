package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBugHunt4_ConsoleCanonicalStateAndMinimalDHCP(t *testing.T) {
	// C-H12(b): Minimal edition defaults LanDHCP to false when interfaces.conf is absent/unset
	minimalCfg := readCurrentNetworkConfigForEdition("minimal", filepath.Join(t.TempDir(), "missing.conf"))
	if minimalCfg.LanDHCP {
		t.Fatalf("expected Minimal edition to default LanDHCP=false")
	}
	fullCfg := readCurrentNetworkConfigForEdition("axonwall", filepath.Join(t.TempDir(), "missing.conf"))
	if !fullCfg.LanDHCP {
		t.Fatalf("expected Axonwall edition to default LanDHCP=true")
	}

	// C-H12(a): Canonical /var/lib/axonwall/state.json must win over stale /etc/axonwall/state.json
	root := t.TempDir()
	etcDir := filepath.Join(root, "etc")
	varDir := filepath.Join(root, "var")
	_ = os.MkdirAll(etcDir, 0755)
	_ = os.MkdirAll(varDir, 0755)

	staleEtc := `{"version":1,"system":{"hostname":"stale-etc"}}`
	freshVar := `{"version":1,"system":{"hostname":"fresh-canonical"},"dhcp":{"enabled":false,"subnets":[]}}`
	_ = os.WriteFile(filepath.Join(etcDir, "state.json"), []byte(staleEtc), 0660)
	_ = os.WriteFile(filepath.Join(varDir, "state.json"), []byte(freshVar), 0660)

	minimalCfg.LanMode = "static"
	minimalCfg.LanIP = "192.168.10.1/24"
	updateStateJSONWithPaths(minimalCfg, etcDir, varDir, filepath.Join(root, "state.json.lock"))

	updatedBytes, err := os.ReadFile(filepath.Join(varDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var updated map[string]any
	if err := json.Unmarshal(updatedBytes, &updated); err != nil {
		t.Fatal(err)
	}
	sysMap := updated["system"].(map[string]any)
	if sysMap["hostname"] != "fresh-canonical" {
		t.Fatalf("expected canonical hostname 'fresh-canonical' preserved over stale /etc copy, got %v", sysMap["hostname"])
	}
	dhcpMap := updated["dhcp"].(map[string]any)
	if dhcpMap["enabled"] != false {
		t.Fatalf("expected Minimal dhcp.enabled to stay false, got %v", dhcpMap["enabled"])
	}
}

func TestBugHunt4_DefaultInstallerConfigRespectsExplicitAxonwallEdition(t *testing.T) {
	dir := t.TempDir()
	edFile := filepath.Join(dir, "edition")
	cmdline := filepath.Join(dir, "cmdline")

	_ = os.WriteFile(edFile, []byte("axonwall\n"), 0644)
	_ = os.WriteFile(cmdline, []byte("quiet axonwall_edition=minimal boot=live\n"), 0644)
	cfg := defaultInstallerConfigFrom(edFile, dir, cmdline)
	if cfg.Edition != "axonwall" {
		t.Fatalf("expected explicit edition file 'axonwall' to ignore cmdline minimal override, got %q", cfg.Edition)
	}

	// Missing edition file + false substring in cmdline must not trigger minimal; exact token triggers
	_ = os.Remove(edFile)
	_ = os.WriteFile(cmdline, []byte("foo=axonwall.edition=minimalx"), 0644)
	cfgSub := defaultInstallerConfigFrom(edFile, dir, cmdline)
	if cfgSub.Edition != "axonwall" {
		t.Fatalf("expected substring 'minimalx' not to trigger minimal, got %q", cfgSub.Edition)
	}
	_ = os.WriteFile(cmdline, []byte("quiet axonwall.edition=minimal"), 0644)
	cfgExact := defaultInstallerConfigFrom(edFile, dir, cmdline)
	if cfgExact.Edition != "minimal" {
		t.Fatalf("expected exact cmdline token to set minimal, got %q", cfgExact.Edition)
	}
}

func TestBugHunt4_ValidatePartitionLayoutFitRejectsOverflow(t *testing.T) {
	cfg := InstallerConfig{
		InstallMode: "ab",
		SlotMB:      8192,
		LogsEnabled: true,
		LogsGB:      8,
	}
	if err := ValidatePartitionLayoutFit(16384, cfg); err == nil {
		t.Fatalf("expected 16 GiB disk with 2x8GiB A/B + 8GiB logs to fail fit validation")
	}
	if err := ValidatePartitionLayoutFit(32768, cfg); err != nil {
		t.Fatalf("expected 32 GiB disk to fit, got %v", err)
	}
}

func TestUpdateStateJSONPrunesCollidingExtraInterfaces(t *testing.T) {
	root := t.TempDir()
	etcDir := filepath.Join(root, "etc")
	varDir := filepath.Join(root, "var")
	_ = os.MkdirAll(etcDir, 0755)
	_ = os.MkdirAll(varDir, 0755)

	// Seed 8-NIC state (wan..opt6 on enp3s0..enp10s0, mixed ordering).
	seed := map[string]any{
		"version": 1,
		"system":  map[string]any{"hostname": "ckpt"},
		"interfaces": []map[string]any{
			{"name": "wan", "role": "wan", "device": "enp3s0", "type": "dhcp", "enabled": true},
			{"name": "lan", "role": "lan", "device": "enp4s0", "type": "static", "ipv4Address": "192.168.1.1/24", "enabled": true},
			{"name": "opt1", "role": "lan", "device": "enp5s0", "type": "dhcp", "enabled": true},
			{"name": "opt2", "role": "lan", "device": "enp6s0", "type": "dhcp", "enabled": true},
			{"name": "opt3", "role": "lan", "device": "enp7s0", "type": "dhcp", "enabled": true},
			{"name": "opt4", "role": "lan", "device": "enp8s0", "type": "dhcp", "enabled": true},
			{"name": "opt5", "role": "lan", "device": "enp9s0", "type": "dhcp", "enabled": true},
			{"name": "opt6", "role": "lan", "device": "enp10s0", "type": "dhcp", "enabled": true},
		},
	}
	raw, _ := json.Marshal(seed)
	_ = os.WriteFile(filepath.Join(varDir, "state.json"), raw, 0660)

	// Reassign top row ports 1-4 (enp3s0, enp5s0, enp7s0, enp9s0) as wan/lan/opt1/opt2.
	// Previously opt3 (enp7s0) and opt5 (enp9s0) stayed in state.json colliding with opt1 and opt2!
	cfg := NetworkConfig{
		WanDevice:  "enp3s0",
		WanMode:    "dhcp",
		LanDevice:  "enp5s0",
		LanMode:    "static",
		LanIP:      "10.60.0.1/24",
		LanDHCP:    true,
		Opt1Device: "enp7s0",
		Opt1Mode:   "dhcp",
		Opt2Device: "enp9s0",
		Opt2Mode:   "dhcp",
	}
	updateStateJSONWithPaths(cfg, etcDir, varDir, filepath.Join(root, "state.json.lock"))

	updatedBytes, err := os.ReadFile(filepath.Join(varDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var updated struct {
		Interfaces []struct {
			Name   string `json:"name"`
			Device string `json:"device"`
		} `json:"interfaces"`
	}
	if err := json.Unmarshal(updatedBytes, &updated); err != nil {
		t.Fatal(err)
	}

	devOwners := make(map[string][]string)
	for _, ifc := range updated.Interfaces {
		devOwners[ifc.Device] = append(devOwners[ifc.Device], ifc.Name)
	}
	for dev, owners := range devOwners {
		if len(owners) > 1 {
			t.Fatalf("device %s bound to multiple logical interfaces after console reassignment: %v", dev, owners)
		}
	}
	for _, unexpected := range []string{"opt3", "opt5"} {
		for _, ifc := range updated.Interfaces {
			if ifc.Name == unexpected {
				t.Fatalf("expected colliding stale extra interface %s to be pruned, still present: %+v", unexpected, updated.Interfaces)
			}
		}
	}
	if len(devOwners["enp8s0"]) != 1 || devOwners["enp8s0"][0] != "opt4" || len(devOwners["enp10s0"]) != 1 || devOwners["enp10s0"][0] != "opt6" {
		t.Fatalf("expected non-colliding opt4 (enp8s0) and opt6 (enp10s0) preserved, got %v", devOwners)
	}
}
