package engine

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBugHuntV012NftNetlinkFixes(t *testing.T) {
	script := `table inet axonwall {
  flowtable fastpath {
    hook ingress priority 0;
    devices = { "eth0", "eth1" };
    flags offload;
  }
  chain syn_flood {
    limit rate 25/second accept
    drop
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    oifname != "eth0" jump syn_flood
    iifname "eth0" limit rate 10/second log prefix "axonwall-rule:wan-drop: " drop comment "log-and-drop-wan"
  }
}`
	batch, err := CompileNftScriptToNetlinkBatch(script)
	if err != nil {
		t.Fatalf("CompileNftScriptToNetlinkBatch failed: %v", err)
	}
	if len(batch.Chains) != 2 {
		t.Fatalf("expected 2 chains, got %d", len(batch.Chains))
	}

	// 1. Helper chain (syn_flood) must not carry hook or policy attributes in netlink messages.
	var foundHelperChain, foundFlowtableOffload bool
	for _, msg := range batch.RawMsgs {
		if len(msg) < 20 {
			continue
		}
		msgType := binary.NativeEndian.Uint16(msg[4:6]) & 0x00ff
		if msgType == nftMsgNewChain && bytes.Contains(msg, []byte("syn_flood\x00")) {
			foundHelperChain = true
			// Parse TLVs starting after nfgenmsg (byte 20)
			attrs := parseTopLevelNetlinkAttrs(msg[20:])
			if _, hasHook := attrs[nftaChainHook]; hasHook {
				t.Fatalf("helper chain syn_flood unexpectedly contains NFTA_CHAIN_HOOK")
			}
			if _, hasPolicy := attrs[nftaChainPolicy]; hasPolicy {
				t.Fatalf("helper chain syn_flood unexpectedly contains NFTA_CHAIN_POLICY")
			}
		}
		if msgType == nftMsgNewFlowtable && bytes.Contains(msg, []byte("fastpath\x00")) {
			attrs := parseTopLevelNetlinkAttrs(msg[20:])
			flagsRaw, hasFlags := attrs[nftaFlowtableFlags]
			if hasFlags && len(flagsRaw) == 4 && binary.BigEndian.Uint32(flagsRaw) == 0x2 {
				foundFlowtableOffload = true
			}
		}
	}
	if !foundHelperChain {
		t.Fatalf("did not find serialized syn_flood helper chain netlink message")
	}
	if !foundFlowtableOffload {
		t.Fatalf("expected flowtable fastpath message to carry NFTA_FLOWTABLE_FLAGS=0x2")
	}

	// 2. oifname != "eth0" rule must encode NFT_CMP_NEQ (op = 1), not NFT_CMP_EQ (op = 0).
	var foundNeqRule, foundLogRule bool
	for _, r := range batch.Rules {
		if strings.Contains(r.RawLine, "oifname != ") {
			foundNeqRule = true
			joined := bytes.Join(r.Expressions, nil)
			if !bytes.Contains(joined, nlAttrU32BE(nftaCmpOp, nftCmpNeq)) {
				t.Fatalf("expected oifname != rule to encode nftCmpNeq (op=1)")
			}
		}
		// 3. log prefix must appear AFTER iifname and limit, BEFORE drop (never hoisted to exprs[0]).
		if strings.Contains(r.RawLine, `log prefix "axonwall-rule:wan-drop: "`) {
			foundLogRule = true
			if len(r.Expressions) < 4 {
				t.Fatalf("expected at least 4 expressions in log rule, got %d", len(r.Expressions))
			}
			if bytes.Contains(r.Expressions[0], []byte("log\x00")) {
				t.Fatalf("log expression was hoisted to index 0 before iifname/limit match predicates")
			}
			if !bytes.Contains(r.Expressions[len(r.Expressions)-2], []byte("log\x00")) {
				t.Fatalf("expected log expression immediately before terminal verdict drop")
			}
		}
	}
	if !foundNeqRule || !foundLogRule {
		t.Fatalf("missing compiled test rules (neq=%v log=%v)", foundNeqRule, foundLogRule)
	}

	// 4. Atomic batch wire wraps DELTABLE inside a single BATCH_BEGIN .. BATCH_END transaction.
	wire := buildAtomicReplaceNetlinkWire(batch)
	var batchBegins, batchEnds, delTables int
	off := 0
	for off+16 <= len(wire) {
		l := int(binary.NativeEndian.Uint32(wire[off : off+4]))
		if l < 16 || off+l > len(wire) {
			t.Fatalf("corrupt netlink header length %d at offset %d", l, off)
		}
		typ := binary.NativeEndian.Uint16(wire[off+4 : off+6])
		switch typ {
		case nfnlMsgBatchBegin:
			batchBegins++
		case nfnlMsgBatchEnd:
			batchEnds++
		case nftMsgType(nftMsgDelTable):
			delTables++
		}
		off += (l + 3) & ^3
	}
	if batchBegins != 1 || batchEnds != 1 || delTables != 1 {
		t.Fatalf("expected 1 BATCH_BEGIN, 1 DELTABLE, 1 BATCH_END in atomic wire; got begin=%d del=%d end=%d", batchBegins, delTables, batchEnds)
	}
}

func parseTopLevelNetlinkAttrs(b []byte) map[uint16][]byte {
	out := make(map[uint16][]byte)
	off := 0
	for off+4 <= len(b) {
		l := int(binary.NativeEndian.Uint16(b[off : off+2]))
		typ := binary.NativeEndian.Uint16(b[off+2 : off+4]) & 0x3fff
		if l < 4 || off+l > len(b) {
			break
		}
		out[typ] = b[off+4 : off+l]
		off += (l + 3) & ^3
	}
	return out
}

func TestBugHuntV012CloudInitBlockScalarDualStackAndHostname(t *testing.T) {
	tmpRoot := t.TempDir()
	userData := `#cloud-config
axonwall:
  hub: wss://hub.example.com:2966/ws/satellite
  token: tok-123
  ca_cert: |
      -----BEGIN CERTIFICATE-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
      -----END CERTIFICATE-----
write_files:
  - path: /etc/axonwall/test.conf
    permissions: "0600"
    content: |
     # 1-space relative indent
     FOO=bar
`
	metaData := "instance-id: iid-1\nlocal-hostname: edge-branch-01\n"
	netCfg := `network:
  version: 2
  ethernets:
    eth0:
      addresses: [203.0.113.10/24, 2001:db8:1::10/64]
      gateway4: 203.0.113.1
      gateway6: 2001:db8:1::1
`
	var cfg EdgeBootConfig
	if err := MergeCloudInitIntoBootConfig(&cfg, CloudInitPayload{
		Datasource:    "imds:test",
		UserData:      userData,
		MetaData:      metaData,
		NetworkConfig: netCfg,
	}, tmpRoot); err != nil {
		t.Fatalf("MergeCloudInitIntoBootConfig failed: %v", err)
	}

	if cfg.Hostname != "edge-branch-01" {
		t.Fatalf("expected metaData local-hostname to populate cfg.Hostname, got %q", cfg.Hostname)
	}
	caRaw, err := os.ReadFile(filepath.Join(tmpRoot, "etc/axonwall/certs/ca.crt"))
	if err != nil {
		t.Fatalf("failed reading ca.crt: %v", err)
	}
	if !strings.HasPrefix(string(caRaw), "-----BEGIN CERTIFICATE-----\n") {
		t.Fatalf("expected 6-space PEM block scalar dedented to column 0, got %q", string(caRaw))
	}
	wfRaw, err := os.ReadFile(filepath.Join(tmpRoot, "etc/axonwall/test.conf"))
	if err != nil {
		t.Fatalf("failed reading test.conf: %v", err)
	}
	if !strings.HasPrefix(string(wfRaw), "# 1-space relative indent\nFOO=bar\n") {
		t.Fatalf("expected 1-space block scalar preserved cleanly, got %q", string(wfRaw))
	}

	if len(cfg.Interfaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(cfg.Interfaces))
	}
	if cfg.Interfaces[0].Address != "203.0.113.10/24" || cfg.Interfaces[0].IPv6Address != "2001:db8:1::10/64" {
		t.Fatalf("expected dual-stack IPv4+IPv6 preserved from netplan v2 addresses, got v4=%q v6=%q",
			cfg.Interfaces[0].Address, cfg.Interfaces[0].IPv6Address)
	}
}

func TestBugHuntV012StandbySyncFencingVlanWifiDhcp(t *testing.T) {
	// 1. Standby SYNC_INTERFACES fencing keeps WAN admin-down and strips shared LAN VIPs.
	ha := NewEdgeHAEngine("hosted", "standby")
	ha.mu.Lock()
	ha.lastWanDev = "eth0"
	ha.lastLanDev = "eth1"
	ha.lastVipV4 = "10.10.0.1/24"
	ha.lastVipV6 = "fd00:10::1/64"
	ha.mu.Unlock()

	wanSpec, wanApply := ha.PrepareSyncedInterface(EdgeInterfaceSpec{
		Name: "wan", Device: "eth0", Address: "dhcp", Enabled: true,
	})
	if !wanApply || wanSpec.Enabled {
		t.Fatalf("expected standby WAN spec to suppress Enabled (apply=%v enabled=%v)", wanApply, wanSpec.Enabled)
	}
	vipSpec, vipApply := ha.PrepareSyncedInterface(EdgeInterfaceSpec{
		Name: "lan-vip4", Device: "eth1", Address: "10.10.0.1/24", Enabled: true,
	})
	if vipApply || vipSpec.Address != "" {
		t.Fatalf("expected standby lan-vip4 spec to be stripped and skipped, got apply=%v spec=%+v", vipApply, vipSpec)
	}
	lanSpec, lanApply := ha.PrepareSyncedInterface(EdgeInterfaceSpec{
		Name: "lan", Device: "eth1", Address: "10.10.0.1/24", IPv6Address: "fd00:10::1/64", Enabled: true,
	})
	if !lanApply || lanSpec.Address != "" || lanSpec.IPv6Address != "" {
		t.Fatalf("expected standby primary lan spec to strip VIPs but stay configurable, got apply=%v spec=%+v", lanApply, lanSpec)
	}

	// 2. VLAN name parser & RTM_NEWLINK frame sanity
	parent, vid, ok := parseVlanDeviceName("eth1.40")
	if !ok || parent != "eth1" || vid != 40 {
		t.Fatalf("parseVlanDeviceName(eth1.40) = (%q, %d, %v)", parent, vid, ok)
	}
	vlanMsg := buildCreateVlanLinkNetlinkMessage(2, "eth1.40", 40)
	if !bytes.Contains(vlanMsg, []byte("eth1.40\x00")) || !bytes.Contains(vlanMsg, []byte("vlan\x00")) {
		t.Fatalf("expected RTM_NEWLINK VLAN message to contain eth1.40 and vlan info kind")
	}

	// 3. DHCPv4 Option 6 DNS parsing & 0.0.0.0 yiaddr rejection
	pkt := make([]byte, 300)
	pkt[0] = bootpReply
	binary.BigEndian.PutUint32(pkt[4:8], 0x11223344)
	copy(pkt[16:20], []byte{192, 0, 2, 50})
	binary.BigEndian.PutUint32(pkt[236:240], dhcpMagicCookie)
	opts := []byte{
		dhcpOptMsgType, 1, dhcpMsgOffer,
		dhcpOptDNS, 8, 1, 1, 1, 1, 9, 9, 9, 9,
		dhcpOptEnd,
	}
	copy(pkt[240:], opts)
	_, lease, err := ParseDHCPv4Packet(pkt, 0x11223344)
	if err != nil {
		t.Fatalf("ParseDHCPv4Packet failed: %v", err)
	}
	if len(lease.DNS) != 2 || lease.DNS[0] != "1.1.1.1" || lease.DNS[1] != "9.9.9.9" {
		t.Fatalf("expected Option 6 DNS [1.1.1.1 9.9.9.9], got %v", lease.DNS)
	}
	// Reject 0.0.0.0 yiaddr
	copy(pkt[16:20], net.IPv4zero.To4())
	if _, _, err := ParseDHCPv4Packet(pkt, 0x11223344); err == nil {
		t.Fatalf("expected ParseDHCPv4Packet to reject unspecified yiaddr 0.0.0.0")
	}

	// 4. Wi-Fi 5GHz template renders hw_mode=a + ieee80211ac=1 + defaulted MobilityDomain
	tmpWifi := t.TempDir()
	we := &WiFiEngine{ConfigDir: tmpWifi}
	_ = we.Configure(WiFiConfig{
		Radio:       "wlan0",
		SSID:        "axon-5g",
		Channel:     36,
		Security:    SecurityWPA2PSK,
		Password:    "supersecretpass",
		Enabled:     true,
		FastRoaming: FastRoamingConfig{Enabled: true},
	})
	confBytes, err := os.ReadFile(filepath.Join(tmpWifi, "hostapd-wlan0.conf"))
	if err != nil {
		t.Fatalf("expected hostapd-wlan0.conf written: %v", err)
	}
	confStr := string(confBytes)
	if !strings.Contains(confStr, "hw_mode=a\n") || !strings.Contains(confStr, "ieee80211ac=1\n") || !strings.Contains(confStr, "mobility_domain=4f57\n") {
		t.Fatalf("unexpected 5GHz hostapd config:\n%s", confStr)
	}
}

// R4-A-L3: with an unknown LAN device (node never went through a
// Promote/Demote transition, lastLanDev == ""), a non-LAN interface
// must NOT be treated as LAN — the old `lanDev == "" || dev ==
// lanDev` stripped the VIP from every non-WAN interface. And a
// dropped lan-vip interface must surface as an error from
// ApplySyncedInterface, not nil, so the hub's SYNC ack cannot claim
// success for an interface that was never applied.
func TestBugHuntV012StandbyFencingUnknownLanDev(t *testing.T) {
	ha := NewEdgeHAEngine("hosted", "standby")
	ha.mu.Lock()
	ha.lastWanDev = ""
	ha.lastLanDev = ""
	ha.lastVipV4 = "10.10.0.1/24"
	ha.lastVipV6 = "fd00:10::1/64"
	ha.mu.Unlock()

	// A non-LAN interface carrying the VIP address keeps it: it is
	// not the LAN device, and only an explicit device match (or the
	// lan-vip name) marks an interface as LAN.
	mgmtSpec, mgmtApply := ha.PrepareSyncedInterface(EdgeInterfaceSpec{
		Name: "mgmt", Device: "eth2", Address: "10.10.0.1/24", Enabled: true,
	})
	if !mgmtApply || mgmtSpec.Address != "10.10.0.1/24" {
		t.Fatalf("unknown lanDev must not strip a non-LAN interface's address, got apply=%v spec=%+v", mgmtApply, mgmtSpec)
	}

	// The lan-vip name itself is the backstop: Promote creates the
	// VIP interfaces as lan-vip4/lan-vip6, so a lan-vip-named
	// interface is fenced even when the device name differs.
	vipSpec, vipApply := ha.PrepareSyncedInterface(EdgeInterfaceSpec{
		Name: "lan-vip4", Device: "eth9", Address: "10.10.0.1/24", Enabled: true,
	})
	if vipApply || vipSpec.Address != "" {
		t.Fatalf("lan-vip-named interface on an unknown device must be stripped and skipped, got apply=%v spec=%+v", vipApply, vipSpec)
	}

	// The dropped interface is an error, not silent success (the
	// net engine is never reached on the skip path, so nil is safe
	// here).
	if err := ha.ApplySyncedInterface(nil, EdgeInterfaceSpec{
		Name: "lan-vip4", Device: "eth9", Address: "10.10.0.1/24", Enabled: true,
	}); err == nil {
		t.Fatal("ApplySyncedInterface must return an error for a fencing-dropped lan-vip interface, got nil")
	}
}
