package main

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSecH06_ValidateExtraInterfaceRejectsInjectionAndInvalidFields(t *testing.T) {
	validStatic := map[string]interface{}{
		"name":        "opt3",
		"role":        "lan",
		"device":      "enp7s0",
		"type":        "static",
		"enabled":     true,
		"dhcpServer":  true,
		"ipv4Address": "10.30.0.1/24",
		"ipv4Gateway": "10.30.0.254",
		"mtu":         float64(9000),
		"description": "DMZ Network",
	}
	v, reason, ok := validateExtraInterface(validStatic)
	if !ok {
		t.Fatalf("expected valid static extra interface to pass, got reason: %s", reason)
	}
	if v.Name != "opt3" || v.Role != "lan" || v.Device != "enp7s0" || v.Type != "static" ||
		v.IPv4Address != "10.30.0.1/24" || v.IPv4IP != "10.30.0.1" || v.IPv4Netmask != "255.255.255.0" ||
		v.IPv4Gateway != "10.30.0.254" || v.MTU != 9000 {
		t.Fatalf("unexpected validated struct: %+v", v)
	}

	validWanDelegated := map[string]interface{}{
		"name":    "wan_2-bak",
		"role":    "wan-delegated",
		"device":  "enp8s0.100",
		"type":    "dhcp",
		"enabled": true,
	}
	if _, reason, ok := validateExtraInterface(validWanDelegated); !ok {
		t.Fatalf("expected valid wan-delegated dhcp entry with VLAN device to pass, got: %s", reason)
	}

	invalidCases := []struct {
		name  string
		entry map[string]interface{}
	}{
		{
			name:  "name newline pre-up smuggling",
			entry: map[string]interface{}{"name": "opt3\n    pre-up /tmp/pwn", "role": "lan", "device": "eth4", "type": "dhcp", "enabled": true},
		},
		{
			name:  "name quote and semicolon injection",
			entry: map[string]interface{}{"name": `opt3"; id; #`, "role": "lan", "device": "eth4", "type": "dhcp", "enabled": true},
		},
		{
			name:  "name braces and space",
			entry: map[string]interface{}{"name": "opt3 { bad }", "role": "lan", "device": "eth4", "type": "dhcp", "enabled": true},
		},
		{
			name:  "name uppercase rejected",
			entry: map[string]interface{}{"name": "OPT3", "role": "lan", "device": "eth4", "type": "dhcp", "enabled": true},
		},
		{
			name:  "name exceeds 15 chars",
			entry: map[string]interface{}{"name": "abcdefghijklmnop", "role": "lan", "device": "eth4", "type": "dhcp", "enabled": true},
		},
		{
			name:  "role newline post-up smuggling",
			entry: map[string]interface{}{"name": "opt3", "role": "lan\npost-up /bin/sh", "device": "eth4", "type": "dhcp", "enabled": true},
		},
		{
			name:  "role quotes and braces",
			entry: map[string]interface{}{"name": "opt3", "role": `lan" # {}`, "device": "eth4", "type": "dhcp", "enabled": true},
		},
		{
			name:  "role explicit empty string",
			entry: map[string]interface{}{"name": "opt3", "role": "", "device": "eth4", "type": "dhcp", "enabled": true},
		},
		{
			name:  "type manual rejected",
			entry: map[string]interface{}{"name": "opt3", "role": "lan", "device": "eth4", "type": "manual", "enabled": true},
		},
		{
			name:  "type newline up smuggling",
			entry: map[string]interface{}{"name": "opt3", "role": "lan", "device": "eth4", "type": "dhcp\n    up /tmp/pwn", "enabled": true},
		},
		{
			name:  "type empty string rejected",
			entry: map[string]interface{}{"name": "opt3", "role": "lan", "device": "eth4", "type": "", "enabled": true},
		},
		{
			name:  "device newline injection",
			entry: map[string]interface{}{"name": "opt3", "role": "lan", "device": "eth4\n    pre-up id", "type": "dhcp", "enabled": true},
		},
		{
			name:  "device trailing newline",
			entry: map[string]interface{}{"name": "opt3", "role": "lan", "device": "eth4\n", "type": "dhcp", "enabled": true},
		},
		{
			name:  "device path traversal",
			entry: map[string]interface{}{"name": "opt3", "role": "lan", "device": "../eth4", "type": "dhcp", "enabled": true},
		},
		{
			name:  "ipv4Address newline post-up smuggling",
			entry: map[string]interface{}{"name": "opt3", "role": "lan", "device": "eth4", "type": "static", "ipv4Address": "10.0.3.1/24\n    post-up /tmp/pwn", "enabled": true},
		},
		{
			name:  "ipv4Address trailing whitespace",
			entry: map[string]interface{}{"name": "opt3", "role": "lan", "device": "eth4", "type": "static", "ipv4Address": "10.0.3.1/24 ", "enabled": true},
		},
		{
			name:  "ipv4Address bare IP without CIDR",
			entry: map[string]interface{}{"name": "opt3", "role": "lan", "device": "eth4", "type": "static", "ipv4Address": "10.0.3.1", "enabled": true},
		},
		{
			name:  "ipv4Address non-CIDR garbage",
			entry: map[string]interface{}{"name": "opt3", "role": "lan", "device": "eth4", "type": "static", "ipv4Address": "not-a-cidr", "enabled": true},
		},
		{
			name:  "ipv4Address IPv6 rejected",
			entry: map[string]interface{}{"name": "opt3", "role": "lan", "device": "eth4", "type": "static", "ipv4Address": "2001:db8::1/64", "enabled": true},
		},
		{
			name:  "ipv4Gateway newline injection",
			entry: map[string]interface{}{"name": "opt3", "role": "wan", "device": "eth4", "type": "static", "ipv4Address": "198.51.100.2/24", "ipv4Gateway": "198.51.100.1\n    up /tmp/pwn", "enabled": true},
		},
		{
			name:  "ipv4Gateway control char",
			entry: map[string]interface{}{"name": "opt3", "role": "wan", "device": "eth4", "type": "static", "ipv4Address": "198.51.100.2/24", "ipv4Gateway": "198.51.100.1\x00", "enabled": true},
		},
		{
			name:  "ipv4Gateway invalid IP",
			entry: map[string]interface{}{"name": "opt3", "role": "wan", "device": "eth4", "type": "static", "ipv4Address": "198.51.100.2/24", "ipv4Gateway": "999.999.999.999", "enabled": true},
		},
		{
			name:  "ipv4Gateway IPv4-mapped IPv6 rejected",
			entry: map[string]interface{}{"name": "opt3", "role": "wan", "device": "eth4", "type": "static", "ipv4Address": "198.51.100.2/24", "ipv4Gateway": "::ffff:198.51.100.1", "enabled": true},
		},
		{
			name:  "mtu string yaml smuggling",
			entry: map[string]interface{}{"name": "opt3", "role": "lan", "device": "eth4", "type": "dhcp", "mtu": "1500\n  - name: pwned", "enabled": true},
		},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := validateExtraInterface(tc.entry); ok {
				t.Fatalf("expected invalid extra interface %s to be rejected: %+v", tc.name, tc.entry)
			}
		})
	}
}

func TestSecH06_PersistNetworkInterfacesDropsPoisonedExtraIfacesWithWarning(t *testing.T) {
	root := t.TempDir()
	etcDir := filepath.Join(root, "etc", "axonwall")
	varDir := filepath.Join(root, "var", "lib", "axonwall")
	netIfacesPath := filepath.Join(root, "etc", "network", "interfaces")
	lockdownPath := filepath.Join(root, "usr", "share", "axonwall", "lockdown.nft")
	_ = os.MkdirAll(etcDir, 0o755)
	_ = os.MkdirAll(varDir, 0o755)
	_ = os.MkdirAll(filepath.Dir(lockdownPath), 0o755)

	initialNft := `table inet axonwall {
    set wan_interfaces {
        type ifname
        elements = { "wan0" }
    }
}
`
	if err := os.WriteFile(lockdownPath, []byte(initialNft), 0o644); err != nil {
		t.Fatal(err)
	}

	// Fake nft binary capturing every invocation so we can prove no poisoned tokens reach nft args.
	binDir := filepath.Join(root, "bin")
	_ = os.MkdirAll(binDir, 0o755)
	nftLog := filepath.Join(root, "nft.log")
	fakeNft := "#!/bin/sh\necho \"$@\" >> \"$NFT_LOG\"\nexit 0\n"
	if err := os.WriteFile(filepath.Join(binDir, "nft"), []byte(fakeNft), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NFT_LOG", nftLog)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	// Seed state.json simulating Tier-2 axonwall-api tampering alongside one legitimate opt3 interface.
	seed := map[string]any{
		"version": 1,
		"system": map[string]any{
			"antiLockout": map[string]any{
				"enabled":    true,
				"interface":  "lan",
				"interfaces": []string{"lan", "opt3"},
				"ports":      []int{22, 2966},
			},
		},
		"interfaces": []map[string]any{
			{"name": "wan", "role": "wan", "device": "eth0", "type": "dhcp", "enabled": true},
			{"name": "lan", "role": "lan", "device": "eth1", "type": "static", "ipv4Address": "192.168.1.1/24", "enabled": true},
			{"name": "opt3", "role": "lan", "device": "eth2", "type": "static", "ipv4Address": "10.3.0.1/24", "enabled": true, "description": `OPT3: "Valid" # link`},
			{"name": "evil1\npre-up /tmp/pwn", "role": "lan", "device": "eth3", "type": "dhcp", "enabled": true},
			{"name": "evil2", "role": "lan\" ; accept", "device": "eth4", "type": "dhcp", "enabled": true},
			{"name": "evil3", "role": "lan", "device": "eth5", "type": "manual", "enabled": true},
			{"name": "evil4", "role": "lan", "device": "eth6", "type": "static", "ipv4Address": "10.4.0.1/24\n    post-up /tmp/pwn2", "enabled": true},
			{"name": "evil5", "role": "wan", "device": "eth7", "type": "static", "ipv4Address": "198.51.100.5/24", "ipv4Gateway": "198.51.100.1\nup /tmp/pwn3", "enabled": true},
		},
	}
	raw, _ := json.Marshal(seed)
	if err := os.WriteFile(filepath.Join(varDir, "state.json"), raw, 0o660); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)

	cfg := NetworkConfig{
		WanDevice: "eth0",
		WanMode:   "dhcp",
		LanDevice: "eth1",
		LanMode:   "static",
		LanIP:     "192.168.1.1/24",
		LanDHCP:   true,
	}
	paths := networkPersistPaths{
		etcDir:                etcDir,
		varDir:                varDir,
		lockPath:              filepath.Join(root, "state.json.lock"),
		networkInterfacesPath: netIfacesPath,
		legacyIfacesDropin:    filepath.Join(root, "etc", "network", "interfaces.d", "axonwall"),
		lockdownNftPath:       lockdownPath,
	}
	persistNetworkInterfacesWithPaths(cfg, paths)

	// 1. Warning log emitted for dropped entries
	warnLogs := logBuf.String()
	for _, needle := range []string{"evil1", "evil2", "evil3", "evil4", "evil5"} {
		if !strings.Contains(warnLogs, needle) {
			t.Errorf("expected warning log for dropped interface %s; got:\n%s", needle, warnLogs)
		}
	}

	// 2. Check /etc/network/interfaces, interfaces.conf, interfaces.yaml, and nft log
	for _, path := range []string{
		netIfacesPath,
		filepath.Join(etcDir, "interfaces.conf"),
		filepath.Join(varDir, "etc-axonwall", "interfaces.conf"),
		filepath.Join(etcDir, "interfaces.yaml"),
		filepath.Join(varDir, "etc-axonwall", "interfaces.yaml"),
		nftLog,
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read %s: %v", path, err)
		}
		text := string(data)
		for _, forbidden := range []string{"evil1", "evil2", "evil3", "evil4", "evil5", "pre-up", "post-up", "/tmp/pwn", "manual", "eth3", "eth4", "eth5", "eth6", "eth7"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("file %s unexpectedly contained poisoned token %q:\n%s", path, forbidden, text)
			}
		}
		if !strings.Contains(text, "eth2") {
			t.Fatalf("file %s missing valid opt3 device eth2:\n%s", path, text)
		}
	}

	// 3. Direct call to reconcileConsoleAntiLockoutNftWithPaths must also independently drop poisoned extraIfaces
	logBuf.Reset()
	_ = os.WriteFile(nftLog, nil, 0o644)
	poisonedDirect := []map[string]interface{}{
		{"name": `bad"quote`, "role": "lan", "device": "eth9", "type": "dhcp", "enabled": true},
		{"name": "badip", "role": "wan", "device": "eth8", "type": "static", "ipv4Address": "1.2.3.4/24\npost-up id", "enabled": true},
		{"name": "opt4", "role": "lan", "device": "eth10", "type": "dhcp", "enabled": true},
	}
	reconcileConsoleAntiLockoutNftWithPaths(cfg, poisonedDirect, []string{"lan", "opt4", `bad"quote`}, []int{22, 2966}, true, lockdownPath)
	directNftBytes, _ := os.ReadFile(nftLog)
	directNftText := string(directNftBytes)
	for _, forbidden := range []string{"bad", "quote", "eth9", "eth8", "post-up"} {
		if strings.Contains(directNftText, forbidden) {
			t.Fatalf("direct reconcile passed poisoned token %q to nft:\n%s", forbidden, directNftText)
		}
	}
	if !strings.Contains(directNftText, "eth10") {
		t.Fatalf("direct reconcile dropped valid opt4 device eth10:\n%s", directNftText)
	}
	if !strings.Contains(logBuf.String(), "bad") {
		t.Fatalf("expected warning log from direct reconcileConsoleAntiLockoutNftWithPaths, got: %s", logBuf.String())
	}

	// 4. Direct call to writePersistedNetworkFiles (bypassing updateStateJSONWithPaths) must also drop poisoned extraIfaces
	logBuf.Reset()
	_ = os.WriteFile(nftLog, nil, 0o644)
	directExtras := []map[string]interface{}{
		{"name": "opt5\n    pre-up /tmp/pwn_direct", "role": "lan", "device": "eth11", "type": "dhcp", "enabled": true},
		{"name": "opt6", "role": "lan", "device": "eth12", "type": "static", "ipv4Address": "10.6.0.1/24", "enabled": true},
	}
	writePersistedNetworkFiles(cfg, directExtras, paths)
	netIfacesBytes, _ := os.ReadFile(netIfacesPath)
	confBytes, _ := os.ReadFile(filepath.Join(etcDir, "interfaces.conf"))
	if strings.Contains(string(netIfacesBytes), "pwn_direct") || strings.Contains(string(netIfacesBytes), "eth11") {
		t.Fatalf("writePersistedNetworkFiles wrote poisoned interface to /etc/network/interfaces:\n%s", string(netIfacesBytes))
	}
	if strings.Contains(string(confBytes), "pwn_direct") || strings.Contains(string(confBytes), "eth11") {
		t.Fatalf("writePersistedNetworkFiles wrote poisoned interface to interfaces.conf:\n%s", string(confBytes))
	}
	if !strings.Contains(string(netIfacesBytes), "eth12") || !strings.Contains(string(confBytes), "eth12") {
		t.Fatalf("writePersistedNetworkFiles dropped valid opt6 eth12")
	}
	if !strings.Contains(logBuf.String(), "opt5") {
		t.Fatalf("expected warning log from writePersistedNetworkFiles, got: %s", logBuf.String())
	}
}

func TestSecH06_MarshalInterfacesYamlWithYamlV3(t *testing.T) {
	cfg := NetworkConfig{
		WanDevice:  "eth0",
		WanMode:    "static",
		WanIP:      "203.0.113.10/24",
		WanGateway: "203.0.113.1",
		LanDevice:  "eth1",
		LanMode:    "static",
		LanIP:      "192.168.1.1/24",
		LanDHCP:    true,
	}
	validExtras, _ := filterAndValidateExtraInterfaces([]map[string]interface{}{
		{
			"name":        "opt3",
			"role":        "lan",
			"device":      "eth2",
			"type":        "static",
			"enabled":     true,
			"dhcpServer":  false,
			"ipv4Address": "10.20.0.1/24",
			"mtu":         float64(9000),
			"description": "DMZ: \"Guest\" # test\n  - name: spoofed_yaml_item",
		},
	})
	if len(validExtras) != 1 {
		t.Fatalf("expected 1 valid extra interface, got %d", len(validExtras))
	}

	existingYaml := `# existing header
interfaces:
  - name: wan
    device: eth0
vlans:
  - name: vlan10
    parent: eth1
    tag: 10
bridges: []
bonds: []
virtualIps: []
vrfs: []
`
	entries := buildInterfacesYamlEntries(cfg, validExtras, map[string]map[string]interface{}{
		"lan": {"mtu": float64(9000)},
	})
	out, err := marshalInterfacesYaml(entries, []byte(existingYaml))
	if err != nil {
		t.Fatalf("marshalInterfacesYaml failed: %v", err)
	}

	// Must parse cleanly back into YAML without injecting a fake interface entry from description
	var parsed struct {
		Interfaces []yamlInterfaceConfigEntry `yaml:"interfaces"`
		Vlans      []map[string]any           `yaml:"vlans"`
		Bridges    []any                      `yaml:"bridges"`
		Bonds      []any                      `yaml:"bonds"`
		VirtualIps []any                      `yaml:"virtualIps"`
		Vrfs       []any                      `yaml:"vrfs"`
	}
	if err := yaml.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("marshaled YAML failed to unmarshal: %v\n%s", err, string(out))
	}
	if len(parsed.Interfaces) != 3 {
		t.Fatalf("expected exactly 3 interfaces (wan, lan, opt3; no spoofed entry), got %d:\n%s", len(parsed.Interfaces), string(out))
	}
	if parsed.Interfaces[1].MTU != 9000 {
		t.Errorf("expected lan MTU 9000 preserved, got %d", parsed.Interfaces[1].MTU)
	}
	if parsed.Interfaces[2].Name != "opt3" || parsed.Interfaces[2].Description != "DMZ: \"Guest\" # test\n  - name: spoofed_yaml_item" {
		t.Errorf("unexpected opt3 entry after YAML round-trip: %+v", parsed.Interfaces[2])
	}
	if len(parsed.Vlans) != 1 || parsed.Vlans[0]["name"] != "vlan10" {
		t.Errorf("expected existing vlans section preserved, got %+v", parsed.Vlans)
	}

	// When no existing YAML exists, default vlans/bridges/laggs empty lists are generated
	freshOut, err := marshalInterfacesYaml(entries, nil)
	if err != nil {
		t.Fatalf("fresh marshalInterfacesYaml failed: %v", err)
	}
	var freshParsed map[string]any
	if err := yaml.Unmarshal(freshOut, &freshParsed); err != nil {
		t.Fatalf("fresh YAML invalid: %v\n%s", err, string(freshOut))
	}
	for _, k := range []string{"interfaces", "vlans", "bridges", "laggs"} {
		if _, exists := freshParsed[k]; !exists {
			t.Errorf("expected key %q in fresh interfaces.yaml:\n%s", k, string(freshOut))
		}
	}
}

func TestSecM06_LockdownNftPreservesWanInterfacesWhenLanCarrierDownAndOnlyUpdatesWanSet(t *testing.T) {
	dir := t.TempDir()
	lockdownPath := filepath.Join(dir, "lockdown.nft")
	nftLog := filepath.Join(dir, "nft.log")
	fakeNft := "#!/bin/sh\necho \"$@\" >> \"$NFT_LOG\"\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(fakeNft), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NFT_LOG", nftLog)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	// Include multiple sets with `elements = { ... }` plus a commented-out set wan_interfaces
	// so we prove ONLY the real `set wan_interfaces` block is rewritten.
	originalNft := `#!/usr/sbin/nft -f
table inet axonwall {
    set blocked_ips {
        type ipv4_addr
        elements = { 192.0.2.10, 198.51.100.20 }
    }

    # set wan_interfaces { elements = { "commented_out" } }
    set wan_interfaces {
        type ifname
        elements = { "wan0" }
    }

    set trusted_ports {
        type inet_service
        elements = { 22, 2966 }
    }

    chain input {
        type filter hook input priority filter; policy drop;
        iifname @wan_interfaces tcp dport { 22, 80, 443, 2966, 3000, 9876 } drop
    }
}
`
	if err := os.WriteFile(lockdownPath, []byte(originalNft), 0o644); err != nil {
		t.Fatal(err)
	}

	// Non-existent / carrier-down internal interfaces (enp4s0, enp5s0 do not exist in /sys/class/net)
	cfg := NetworkConfig{
		WanDevice: "enp3s0",
		LanDevice: "enp4s0",
	}
	extraIfaces := []map[string]interface{}{
		{"name": "wan2", "role": "wan", "device": "enp6s0", "type": "dhcp", "enabled": true},
		{"name": "opt3", "role": "lan", "device": "enp5s0", "type": "dhcp", "enabled": true},
	}

	reconcileConsoleAntiLockoutNftWithPaths(cfg, extraIfaces, []string{"lan"}, []int{22, 2966}, true, lockdownPath)

	updatedBytes, err := os.ReadFile(lockdownPath)
	if err != nil {
		t.Fatal(err)
	}
	updated := string(updatedBytes)

	if !strings.Contains(updated, `elements = { "wan0", "enp3s0", "enp6s0" }`) {
		t.Fatalf("expected wan_interfaces to include wan0, enp3s0, enp6s0 even with LAN carrier down; got:\n%s", updated)
	}
	if !strings.Contains(updated, "elements = { 192.0.2.10, 198.51.100.20 }") {
		t.Fatalf("blocked_ips elements were clobbered! got:\n%s", updated)
	}
	if !strings.Contains(updated, "elements = { 22, 2966 }") {
		t.Fatalf("trusted_ports elements were clobbered! got:\n%s", updated)
	}
	if !strings.Contains(updated, `# set wan_interfaces { elements = { "commented_out" } }`) {
		t.Fatalf("commented set wan_interfaces was modified! got:\n%s", updated)
	}
}

func TestSecM06_UpdateLockdownWanInterfacesEdgeCases(t *testing.T) {
	// Single-line set wan_interfaces alongside another set
	singleLine := "set other { elements = { 1.1.1.1 } }\nset wan_interfaces { elements = { \"wan0\" } }\n"
	got, ok := updateLockdownWanInterfaces(singleLine, []string{`"wan0"`, `"eth0"`})
	if !ok {
		t.Fatalf("expected updateLockdownWanInterfaces to match single-line set")
	}
	want := "set other { elements = { 1.1.1.1 } }\nset wan_interfaces { elements = { \"wan0\", \"eth0\" } }\n"
	if got != want {
		t.Fatalf("unexpected single-line output:\ngot:  %q\nwant: %q", got, want)
	}

	// Set without existing elements line
	noElems := "table inet axonwall {\n    set wan_interfaces {\n        type ifname\n    }\n}\n"
	gotNoElems, ok := updateLockdownWanInterfaces(noElems, []string{`"wan0"`, `"eth0"`})
	if !ok || !strings.Contains(gotNoElems, `elements = { "wan0", "eth0" }`) {
		t.Fatalf("expected elements inserted into wan_interfaces without prior elements, got:\n%s", gotNoElems)
	}

	// Set name prefix collision (wan_interfaces_v2 must NOT match)
	prefixOnly := "set wan_interfaces_v2 { elements = { \"wan0\" } }\n"
	if _, ok := updateLockdownWanInterfaces(prefixOnly, []string{`"wan0"`, `"eth0"`}); ok {
		t.Fatalf("expected set wan_interfaces_v2 not to match wan_interfaces")
	}
}
