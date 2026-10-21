package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRoutingConfig(t *testing.T) {
	tmpDir := t.TempDir()
	origDir := "/etc/axonwall"
	defer func() {
		// restore if any mock paths were used
	}()

	yamlContent := `
gateways:
  - name: WAN_GW
    interface: wan
    gatewayIp: 192.168.1.1
    isDefault: true
    enabled: true
routes:
  - network: 10.79.0.0/24
    gateway: 10.80.0.1
    interface: lan
    description: Branch Office
    enabled: true
  - network: 172.16.50.0/24
    gateway: 10.80.0.254
    interface: opt1
    description: DMZ Route
    enabled: false
  - network: 192.168.100.0/24
    gateway: 10.80.0.2
    interface: lan
    description: Implicitly enabled route
`
	yamlPath := filepath.Join(tmpDir, "routing.yaml")
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("failed to write test routing.yaml: %v", err)
	}

	data, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("failed to read test routing.yaml: %v", err)
	}

	cfg, err := LoadRoutingConfigFromBytes(data)
	if err != nil {
		t.Fatalf("LoadRoutingConfigFromBytes failed: %v", err)
	}

	if len(cfg.Routes) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(cfg.Routes))
	}

	r1 := cfg.Routes[0]
	if r1.Network != "10.79.0.0/24" || r1.Gateway != "10.80.0.1" || r1.Interface != "lan" || !r1.IsEnabled() {
		t.Errorf("unexpected route 1: %+v", r1)
	}

	r2 := cfg.Routes[1]
	if r2.Network != "172.16.50.0/24" || r2.Gateway != "10.80.0.254" || r2.IsEnabled() {
		t.Errorf("unexpected route 2: %+v", r2)
	}

	r3 := cfg.Routes[2]
	if r3.Network != "192.168.100.0/24" || r3.Gateway != "10.80.0.2" || !r3.IsEnabled() {
		t.Errorf("unexpected route 3: %+v", r3)
	}
	_ = origDir
}

func TestResolveInterfaceDevice(t *testing.T) {
	devMap := map[string]string{
		"wan":  "ens19",
		"lan":  "ens18",
		"opt1": "eth2",
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"auto", ""},
		{"AUTO", ""},
		{"lan", "ens18"},
		{"LAN", "ens18"},
		{"wan", "ens19"},
		{"opt1", "eth2"},
		{"custom_dev0", "custom_dev0"},
		{"invalid;dev", ""},
	}

	for _, tt := range tests {
		actual := resolveInterfaceDevice(tt.input, devMap)
		if actual != tt.expected {
			t.Errorf("resolveInterfaceDevice(%q) = %q; expected %q", tt.input, actual, tt.expected)
		}
	}
}
