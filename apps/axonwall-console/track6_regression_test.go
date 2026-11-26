package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTrack6_BuildLiveInstallCommandPassesConfirmations(t *testing.T) {
	// Ensure inherited env vars cannot leak stale confirmations when false.
	t.Setenv("ALLOW_WIPE_EXISTING", "1")
	t.Setenv("AXONWALL_REINSTALL_CONFIRMED", "1")

	unconfirmed := buildLiveInstallCommand("/usr/local/bin/axonwall-install", "/tmp/cfg.conf", false, false)
	if slices.Contains(unconfirmed.Args, "--force-wipe") {
		t.Fatalf("did not expect --force-wipe when overwriteConfirmed=false: %v", unconfirmed.Args)
	}
	for _, kv := range unconfirmed.Env {
		if strings.HasPrefix(kv, "ALLOW_WIPE_EXISTING=") || strings.HasPrefix(kv, "AXONWALL_REINSTALL_CONFIRMED=") {
			t.Fatalf("unexpected confirmation env leaked when unconfirmed: %s", kv)
		}
	}
	if !slices.Contains(unconfirmed.Env, "AXONWALL_INSTALL_BACKEND=1") {
		t.Fatalf("expected AXONWALL_INSTALL_BACKEND=1 in env")
	}

	confirmed := buildLiveInstallCommand("/usr/local/bin/axonwall-install", "/tmp/cfg.conf", true, true)
	if !slices.Contains(confirmed.Args, "--force-wipe") {
		t.Fatalf("expected --force-wipe in args when overwriteConfirmed=true: %v", confirmed.Args)
	}
	if !slices.Contains(confirmed.Env, "ALLOW_WIPE_EXISTING=1") {
		t.Fatalf("expected ALLOW_WIPE_EXISTING=1 in env")
	}
	if !slices.Contains(confirmed.Env, "AXONWALL_REINSTALL_CONFIRMED=1") {
		t.Fatalf("expected AXONWALL_REINSTALL_CONFIRMED=1 in env")
	}
	if !slices.Contains(confirmed.Env, "AXONWALL_INSTALL_BACKEND=1") {
		t.Fatalf("expected AXONWALL_INSTALL_BACKEND=1 in env")
	}
}

func TestTrack6_UpdateStateJSONPreservesAntiLockoutAndEnablesDhcp(t *testing.T) {
	root := t.TempDir()
	etcDir := filepath.Join(root, "etc")
	varDir := filepath.Join(root, "var")
	_ = os.MkdirAll(etcDir, 0755)
	_ = os.MkdirAll(varDir, 0755)

	seed := map[string]any{
		"version": 1,
		"dhcp": map[string]any{
			"enabled": false,
			"subnets": []any{},
		},
		"system": map[string]any{
			"hostname": "fw1",
			"antiLockout": map[string]any{
				"enabled":    true,
				"interface":  "lan",
				"interfaces": []string{"lan"},
				"ports":      []int{2222, 2966},
			},
		},
	}
	raw, _ := json.Marshal(seed)
	_ = os.WriteFile(filepath.Join(varDir, "state.json"), raw, 0660)

	// Configure WAN, LAN (with authoritative DHCP), OPT1, OPT2.
	// Anti-lockout must preserve ["lan"] and [2222, 2966] rather than reopening opt1/opt2 or resetting ports;
	// dhcp.enabled must flip from false -> true because LanDHCP is enabled.
	cfg := NetworkConfig{
		WanDevice:  "eth0",
		WanMode:    "dhcp",
		LanDevice:  "eth1",
		LanMode:    "static",
		LanIP:      "192.168.10.1/24",
		LanDHCP:    true,
		Opt1Device: "eth2",
		Opt1Mode:   "dhcp",
		Opt2Device: "eth3",
		Opt2Mode:   "dhcp",
	}
	updateStateJSONWithPaths(cfg, etcDir, varDir, filepath.Join(root, "state.json.lock"))

	updatedBytes, err := os.ReadFile(filepath.Join(varDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var updated map[string]any
	if err := json.Unmarshal(updatedBytes, &updated); err != nil {
		t.Fatal(err)
	}

	dhcpMap := updated["dhcp"].(map[string]any)
	if dhcpMap["enabled"] != true {
		t.Fatalf("expected dhcp.enabled=true when Authoritative DHCP enabled on LAN, got %v", dhcpMap["enabled"])
	}
	subnets := dhcpMap["subnets"].([]any)
	if len(subnets) != 1 {
		t.Fatalf("expected 1 DHCP subnet created, got %d", len(subnets))
	}

	alMap := updated["system"].(map[string]any)["antiLockout"].(map[string]any)
	alIfaces := alMap["interfaces"].([]any)
	if len(alIfaces) != 1 || alIfaces[0] != "lan" {
		t.Fatalf("expected antiLockout.interfaces preserved as [lan], got %v", alIfaces)
	}
	alPorts := alMap["ports"].([]any)
	if len(alPorts) != 2 || int(alPorts[0].(float64)) != 2222 || int(alPorts[1].(float64)) != 2966 {
		t.Fatalf("expected custom antiLockout.ports [2222, 2966] preserved, got %v", alPorts)
	}

	// Verify pruning when an antiLockout interface (opt1) is removed from NetworkConfig.
	alMap["interfaces"] = []string{"lan", "opt1"}
	reseeded, _ := json.Marshal(updated)
	_ = os.WriteFile(filepath.Join(varDir, "state.json"), reseeded, 0660)
	cfg.Opt1Device = ""
	updateStateJSONWithPaths(cfg, etcDir, varDir, filepath.Join(root, "state.json.lock"))
	updatedBytes2, _ := os.ReadFile(filepath.Join(varDir, "state.json"))
	var updated2 map[string]any
	_ = json.Unmarshal(updatedBytes2, &updated2)
	alIfaces2 := updated2["system"].(map[string]any)["antiLockout"].(map[string]any)["interfaces"].([]any)
	if len(alIfaces2) != 1 || alIfaces2[0] != "lan" {
		t.Fatalf("expected removed opt1 pruned from antiLockout.interfaces, got %v", alIfaces2)
	}
}

func TestTrack6_WriteSystemYamlAntiLockoutPreservesTopLevelKeys(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "system.yaml")
	// Hand-edited system.yaml without antiLockout key and with 4-space indentation + sibling plugins/mcp/observability.
	initial := strings.Join([]string{
		"# custom header",
		"system:",
		"    hostname: custom-gw",
		"    sshPort: 2222",
		"plugins:",
		"    fleet-controller: true",
		"mcp:",
		"    enabled: true",
		"observability:",
		"    victoriaMetrics:",
		"        url: http://10.0.0.5:8428",
	}, "\n") + "\n"
	if err := os.WriteFile(yamlPath, []byte(initial), 0660); err != nil {
		t.Fatal(err)
	}

	writeSystemYamlAntiLockoutToPaths([]string{yamlPath}, []string{"lan", "opt1"}, []int{2222, 2966}, true)

	outBytes, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := yaml.Unmarshal(outBytes, &parsed); err != nil {
		t.Fatalf("updated system.yaml is invalid YAML: %v\n%s", err, string(outBytes))
	}
	if parsed["plugins"] == nil || parsed["mcp"] == nil || parsed["observability"] == nil {
		t.Fatalf("sibling top-level sections were wiped: %+v", parsed)
	}
	sys := parsed["system"].(map[string]any)
	if sys["hostname"] != "custom-gw" || sys["sshPort"] != 2222 {
		t.Fatalf("existing system fields were wiped: %+v", sys)
	}
	al := sys["antiLockout"].(map[string]any)
	if al["interface"] != "lan" {
		t.Fatalf("unexpected antiLockout.interface: %+v", al)
	}
	ifaces := al["interfaces"].([]any)
	if len(ifaces) != 2 || ifaces[0] != "lan" || ifaces[1] != "opt1" {
		t.Fatalf("unexpected antiLockout.interfaces: %v", ifaces)
	}
	ports := al["ports"].([]any)
	if len(ports) != 2 || ports[0] != 2222 || ports[1] != 2966 {
		t.Fatalf("unexpected antiLockout.ports: %v", ports)
	}
}

func TestTrack6_SaveAntiLockoutSelectionUsesLockAndAtomicWrite(t *testing.T) {
	root := t.TempDir()
	etcDir := filepath.Join(root, "etc")
	varDir := filepath.Join(root, "var")
	_ = os.MkdirAll(etcDir, 0755)
	_ = os.MkdirAll(varDir, 0755)
	lockPath := filepath.Join(root, "state.json.lock")

	seed := map[string]any{
		"version": 1,
		"system": map[string]any{
			"antiLockout": map[string]any{
				"enabled":    true,
				"interface":  "lan",
				"interfaces": []string{"lan", "opt1"},
				"ports":      []int{22, 2966},
			},
		},
	}
	raw, _ := json.Marshal(seed)
	_ = os.WriteFile(filepath.Join(varDir, "state.json"), raw, 0660)

	// Test atomic write does not leave temp files and rejects symlinks.
	symTarget := filepath.Join(root, "victim.txt")
	_ = os.WriteFile(symTarget, []byte("keep"), 0600)
	symPath := filepath.Join(etcDir, "symlinked.conf")
	_ = os.Symlink(symTarget, symPath)
	writeSharedConfigFile(symPath, []byte("pwned"), 0600)
	gotVictim, _ := os.ReadFile(symTarget)
	if string(gotVictim) != "keep" {
		t.Fatalf("writeSharedConfigFile followed symlink!")
	}

	ports, err := saveAntiLockoutSelectionWithPaths(etcDir, varDir, lockPath, []string{"lan"})
	if err != nil {
		t.Fatalf("saveAntiLockoutSelectionWithPaths failed: %v", err)
	}
	if len(ports) != 2 || ports[0] != 22 || ports[1] != 2966 {
		t.Fatalf("expected preserved ports [22, 2966], got %v", ports)
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("expected lock file to be released after save")
	}
	entries, _ := os.ReadDir(varDir)
	for _, ent := range entries {
		if strings.Contains(ent.Name(), ".tmp-") {
			t.Fatalf("unexpected temp file left behind: %s", ent.Name())
		}
	}
}

func TestTrack6_ReconcileAntiLockoutNftPrunesDisallowedRules(t *testing.T) {
	dir := t.TempDir()
	nftLog := filepath.Join(dir, "nft.log")
	fakeNft := `#!/bin/sh
echo "$@" >> "$NFT_LOG"
if [ "$1" = "-a" ] && [ "$2" = "list" ]; then
  echo 'table inet axonwall {'
  echo '  chain input {'
  echo '    iifname "eth1" tcp dport { 22, 2966 } accept comment "anti-lockout-lan" # handle 11'
  echo '    iifname "eth2" tcp dport { 22, 2966 } accept comment "anti-lockout-opt1" # handle 12'
  echo '  }'
  echo '}'
  exit 0
fi
if [ "$1" = "list" ]; then
  echo '    iifname "eth1" tcp dport { 22, 2966 } accept comment "anti-lockout-lan"'
  exit 0
fi
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(fakeNft), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NFT_LOG", nftLog)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	cfg := NetworkConfig{
		WanDevice:  "eth0",
		LanDevice:  "eth1",
		Opt1Device: "eth2",
	}
	// Only "lan" is permitted; opt1 rule (handle 12) must be deleted and opt1 must NOT be re-inserted.
	reconcileConsoleAntiLockoutNftWithConfig(cfg, nil, []string{"lan"}, []int{22, 2966}, true)

	logged, err := os.ReadFile(nftLog)
	if err != nil {
		t.Fatal(err)
	}
	logStr := string(logged)
	if !strings.Contains(logStr, "delete rule inet axonwall input handle 12") {
		t.Fatalf("expected stale opt1 anti-lockout rule handle 12 deleted; nft log:\n%s", logStr)
	}
	if strings.Contains(logStr, "insert rule inet axonwall input iifname eth2") {
		t.Fatalf("disallowed opt1 must NOT have anti-lockout rule inserted; nft log:\n%s", logStr)
	}
}
