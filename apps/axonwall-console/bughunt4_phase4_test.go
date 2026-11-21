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
