package main

import (
	"errors"
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

// A-H1 regression: a routing file that parses under neither YAML nor
// JSON is corrupt, not "zero routes". Pre-fix this returned a nil
// error with an empty route list, and ReconcileStaticRoutes then
// pruned every kernel static route.
func TestLoadRoutingConfigFromBytesCorruptReturnsError(t *testing.T) {
	corrupt := "routes: [unclosed\n\tbad: : : {\n"
	if _, err := LoadRoutingConfigFromBytes([]byte(corrupt)); err == nil {
		t.Fatalf("expected an error for corrupt routing config, got nil")
	}
}

// A-M13 (A-H1 residual): a file that parses cleanly but carries no
// `routes` key is a wrong-schema document, not "zero routes" —
// accepting it used to let the reconciler prune every owned route
// (a typo'd top-level key, a `gateways:`-only document, an
// interfaces.yaml written to routing.yaml). The round-1 A-H1 guard
// below blessed this case; round-2 M13 overturns it. Only an
// explicitly empty document (or `routes: []`) is "zero routes".
func TestLoadRoutingConfigFromBytesValidNoRoutes(t *testing.T) {
	gatewaysOnly := "gateways:\n  - name: WAN_GW\n    interface: wan\n    gatewayIp: 192.168.1.1\n"
	if _, err := LoadRoutingConfigFromBytes([]byte(gatewaysOnly)); !errors.Is(err, errNoRoutesKey) {
		t.Fatalf("expected errNoRoutesKey for a gateways-only routing document, got: %v", err)
	}
}

// A-H1 regression: pruning is limited to routes this reconciler owns.
// A foreign proto-static route (not in the desired set and never
// installed by a previous reconcile) must survive, while an owned
// route that left the desired set is pruned.
func TestShouldPruneStaticRoute(t *testing.T) {
	desired := map[string]StaticRouteConfig{
		"10.0.0.0/24": {Network: "10.0.0.0/24", Gateway: "10.0.0.1"},
		"10.3.0.5/32": {Network: "10.3.0.5/32", Gateway: "10.0.0.1"},
	}
	owned := map[string]bool{
		"10.1.0.0/24": true,
		"10.4.0.5/32": true,
	}
	cases := []struct {
		dest string
		want bool
	}{
		{"10.0.0.0/24", false}, // still desired
		{"10.3.0.5", false},    // desired via its /32 form
		{"10.1.0.0/24", true},  // owned, no longer desired
		{"10.4.0.5", true},     // owned via its /32 form, no longer desired
		{"10.9.0.0/24", false}, // foreign: never owned, must survive
		{"default", false},     // managed separately, never pruned here
	}
	for _, tc := range cases {
		if got := shouldPruneStaticRoute(tc.dest, desired, owned); got != tc.want {
			t.Errorf("shouldPruneStaticRoute(%q) = %v, want %v", tc.dest, got, tc.want)
		}
	}
}

// A-H1: the owned-set round-trips through its backing file.
func TestOwnedStaticRoutesRoundTrip(t *testing.T) {
	orig := staticRoutesOwnedPath
	staticRoutesOwnedPath = filepath.Join(t.TempDir(), "owned.json")
	defer func() { staticRoutesOwnedPath = orig }()

	desired := map[string]StaticRouteConfig{
		"10.0.0.0/24": {Network: "10.0.0.0/24", Gateway: "10.0.0.1"},
		"10.2.0.0/24": {Network: "10.2.0.0/24", Gateway: "10.0.0.1"},
	}
	saveOwnedStaticRoutes(desired)
	owned := loadOwnedStaticRoutes()
	if !owned["10.0.0.0/24"] || !owned["10.2.0.0/24"] || len(owned) != 2 {
		t.Fatalf("owned set round-trip failed, got %v", owned)
	}
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
