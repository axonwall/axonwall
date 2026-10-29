package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseKernelCmdline(t *testing.T) {
	cmdline := "console=ttyS0,115200 quiet axonwall.hub=wss://10.0.0.2:2966/ws/satellite axonwall.id=edge-n100-01 axonwall.token=ztp_axon_abc123 axonwall.sku=sku-x86-intel-n100-i226 axonwall.slot=B axonwall.wan=eth0:203.0.113.2/24:203.0.113.1 axonwall.lan=eth1:10.0.0.1/24"
	cfg := ParseKernelCmdline(cmdline)

	if cfg.HubURL != "wss://10.0.0.2:2966/ws/satellite" {
		t.Fatalf("expected HubURL wss://10.0.0.2:2966/ws/satellite, got %q", cfg.HubURL)
	}
	if cfg.SatelliteID != "edge-n100-01" {
		t.Fatalf("expected SatelliteID edge-n100-01, got %q", cfg.SatelliteID)
	}
	if cfg.ZtpToken != "ztp_axon_abc123" {
		t.Fatalf("expected ZtpToken ztp_axon_abc123, got %q", cfg.ZtpToken)
	}
	if cfg.SkuProfile != "sku-x86-intel-n100-i226" {
		t.Fatalf("expected SkuProfile sku-x86-intel-n100-i226, got %q", cfg.SkuProfile)
	}
	if cfg.UkiSlot != "B" {
		t.Fatalf("expected UkiSlot B, got %q", cfg.UkiSlot)
	}
	if len(cfg.Interfaces) != 2 {
		t.Fatalf("expected 2 parsed interfaces, got %d", len(cfg.Interfaces))
	}
	if cfg.Interfaces[0].Name != "wan" || cfg.Interfaces[0].Device != "eth0" || cfg.Interfaces[0].Address != "203.0.113.2/24" || cfg.Interfaces[0].Gateway != "203.0.113.1" {
		t.Fatalf("unexpected WAN interface spec: %+v", cfg.Interfaces[0])
	}
	if cfg.Interfaces[1].Name != "lan" || cfg.Interfaces[1].Device != "eth1" || cfg.Interfaces[1].Address != "10.0.0.1/24" {
		t.Fatalf("unexpected LAN interface spec: %+v", cfg.Interfaces[1])
	}
}

func TestApplyHardenedSysctls(t *testing.T) {
	tmp := t.TempDir()
	for relPath := range DefaultHardenedSysctls {
		full := filepath.Join(tmp, filepath.FromSlash(relPath))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}
	}

	applied := ApplyHardenedSysctls(tmp)
	if applied != len(DefaultHardenedSysctls) {
		t.Fatalf("expected %d sysctls applied, got %d", len(DefaultHardenedSysctls), applied)
	}

	ipForward, err := os.ReadFile(filepath.Join(tmp, "net/ipv4/ip_forward"))
	if err != nil || strings.TrimSpace(string(ipForward)) != "0" {
		t.Fatalf("expected fail-closed net/ipv4/ip_forward=0 before ruleset load, got %q (err=%v)", string(ipForward), err)
	}

	if err := SetForwarding(tmp, true); err != nil {
		t.Fatalf("SetForwarding(true) failed: %v", err)
	}
	ipForward, _ = os.ReadFile(filepath.Join(tmp, "net/ipv4/ip_forward"))
	if strings.TrimSpace(string(ipForward)) != "1" {
		t.Fatalf("expected net/ipv4/ip_forward=1 after SetForwarding(true), got %q", string(ipForward))
	}
}

func TestBuildEmergencyLockdownNft(t *testing.T) {
	script := BuildEmergencyLockdownNft("wss://10.0.0.2:2966/ws/satellite")
	if !strings.Contains(script, "policy drop;") {
		t.Fatalf("expected fail-closed policy drop in emergency lockdown script")
	}
	if !strings.Contains(script, "ip saddr 10.0.0.2 accept comment \"allow-axonwall-hub\"") {
		t.Fatalf("expected Hub IP allow rule in emergency lockdown script, got:\n%s", script)
	}
}

func TestValidateInterfaceAndRouteSpecs(t *testing.T) {
	validIface := EdgeInterfaceSpec{
		Name:    "wan",
		Device:  "eth0",
		Address: "203.0.113.2/24",
		Gateway: "203.0.113.1",
		MTU:     1500,
		Enabled: true,
	}
	if err := ValidateInterfaceSpec(validIface); err != nil {
		t.Fatalf("expected valid interface spec, got error: %v", err)
	}

	badIface := EdgeInterfaceSpec{
		Name:   "wan",
		Device: "../eth0",
	}
	if err := ValidateInterfaceSpec(badIface); err == nil {
		t.Fatalf("expected error for invalid interface device '../eth0'")
	}

	validRoute := EdgeRouteSpec{
		Destination: "10.20.0.0/16",
		Gateway:     "10.0.0.254",
		Device:      "eth1",
	}
	if err := ValidateRouteSpec(validRoute); err != nil {
		t.Fatalf("expected valid route spec, got error: %v", err)
	}

	badRoute := EdgeRouteSpec{
		Destination: "not-a-cidr",
		Gateway:     "10.0.0.254",
	}
	if err := ValidateRouteSpec(badRoute); err == nil {
		t.Fatalf("expected error for invalid route CIDR")
	}
}

func TestParseConntrackFlowsAndKmsgFirewallLog(t *testing.T) {
	sampleConntrack := strings.Join([]string{
		"ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.50 dst=93.184.216.34 sport=54321 dport=443 packets=140 bytes=90000 src=93.184.216.34 dst=203.0.113.2 sport=443 dport=54321 packets=200 bytes=210000 [ASSURED] [OFFLOAD] mark=0 zone=0 use=2",
		"ipv4     2 udp      17 29 src=10.0.0.12 dst=1.1.1.1 sport=61022 dport=53 packets=2 bytes=140 src=1.1.1.1 dst=203.0.113.2 sport=53 dport=61022 packets=2 bytes=320 mark=0 use=1",
	}, "\n")

	flows := ParseConntrackFlows(sampleConntrack, 10)
	if len(flows) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(flows))
	}
	if flows[0].Protocol != "tcp" || flows[0].SrcIP != "10.0.0.50" || flows[0].DstPort != 443 || !flows[0].Offloaded || flows[0].Bytes != 300000 {
		t.Fatalf("unexpected top flow record: %+v", flows[0])
	}

	kmsgLine := "6,1420,58291042,-;axonwall-rule:wan-ssh-drop: IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=198.51.100.77 DST=203.0.113.2 LEN=60 PROTO=TCP SPT=49122 DPT=22 SYN"
	fwLog, ok := ParseKmsgFirewallLog(kmsgLine)
	if !ok {
		t.Fatalf("expected kmsg firewall log line to parse")
	}
	if fwLog.RuleID != "wan-ssh-drop" || fwLog.InIface != "eth0" || fwLog.SrcIP != "198.51.100.77" || fwLog.DstPort != 22 || fwLog.Protocol != "tcp" {
		t.Fatalf("unexpected parsed firewall log: %+v", fwLog)
	}
}

func TestCompileNftScriptToNetlinkBatch(t *testing.T) {
	// 1. Test PID 1 Emergency Lockdown script compilation
	lockdown := BuildEmergencyLockdownNft("wss://10.0.0.2:2966/ws/satellite")
	b1, err := CompileNftScriptToNetlinkBatch(lockdown)
	if err != nil {
		t.Fatalf("CompileNftScriptToNetlinkBatch(lockdown) failed: %v", err)
	}
	if b1.TableName != "axonwall" || len(b1.Sets) != 3 || len(b1.Chains) != 3 || len(b1.RawMsgs) < 10 {
		t.Fatalf("unexpected lockdown batch summary: table=%q sets=%d chains=%d msgs=%d", b1.TableName, len(b1.Sets), len(b1.Chains), len(b1.RawMsgs))
	}

	// 2. Test full Super-Slim Edge NGFW UKI ruleset (flowtable, WAN log-and-drop, LAN->WAN, masquerade)
	edgeScript := `#!/usr/sbin/nft -f
flush ruleset
table inet axonwall {
  set blocked_ips {
    type ipv4_addr;
    flags interval;
  }
  set blocked_ips6 {
    type ipv6_addr;
    flags interval;
  }
  set blocked_macs {
    type ether_addr;
  }
  flowtable fastpath {
    hook ingress priority 0;
    devices = { "eth0", "eth1" };
  }
  chain input {
    type filter hook input priority filter; policy drop;
    ip saddr @blocked_ips drop comment "ai-micro-segmentation"
    ip6 saddr @blocked_ips6 drop comment "ai-micro-segmentation"
    ether saddr @blocked_macs drop comment "ai-micro-segmentation"
    ct state established,related accept
    ct state invalid drop
    iif "lo" accept
    meta l4proto ipv6-icmp accept comment "allow-icmpv6-nd"
    iifname "eth1" accept comment "allow-lan-control-plane"
    udp dport 51820 accept comment "allow-wireguard"
    iifname "wg-axon0" accept comment "allow-wg-mesh-traffic"
    udp dport 41641 accept comment "headscale-mesh"
    iifname "tailscale0" accept comment "allow-tailscale-mesh-traffic"
    iifname "eth0" limit rate 10/second log prefix "axonwall-rule:wan-drop: " drop comment "log-and-drop-wan-input"
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    ip saddr @blocked_ips drop comment "ai-micro-segmentation"
    ip daddr @blocked_ips drop comment "ai-micro-segmentation"
    ip6 saddr @blocked_ips6 drop comment "ai-micro-segmentation"
    ip6 daddr @blocked_ips6 drop comment "ai-micro-segmentation"
    ether saddr @blocked_macs drop comment "ai-micro-segmentation"
    meta l4proto { tcp, udp } ct state established flow add @fastpath comment "wire-speed-flowtable-offload"
    ct state established,related accept
    ct state invalid drop
    iifname "eth1" oifname "eth0" accept comment "allow-lan-to-wan"
    iifname "wg-axon0" accept
    iifname "tailscale0" accept
  }
  chain output {
    type filter hook output priority filter; policy accept;
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "eth0" masquerade comment "edge-ngfw-wan-masquerade"
  }
}`

	b2, err := CompileNftScriptToNetlinkBatch(edgeScript)
	if err != nil {
		t.Fatalf("CompileNftScriptToNetlinkBatch(edgeScript) failed: %v", err)
	}
	if len(b2.Flowtables) != 1 || b2.Flowtables[0].Name != "fastpath" || len(b2.Flowtables[0].Devices) != 2 {
		t.Fatalf("expected 1 flowtable fastpath with 2 devices, got %+v", b2.Flowtables)
	}
	if len(b2.Chains) != 4 {
		t.Fatalf("expected 4 chains (input, forward, output, postrouting), got %d", len(b2.Chains))
	}
	if len(b2.Rules) != 25 {
		t.Fatalf("expected 25 compiled rules, got %d", len(b2.Rules))
	}
}

func TestBuildWireGuardSetDeviceAttrs(t *testing.T) {
	priv := base64.StdEncoding.EncodeToString(make([]byte, 32))
	pub := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))

	cfg := WireGuardConfig{
		InterfaceName: "wg-axon0",
		TunnelIP:      "10.99.0.2/24",
		ListenPort:    51820,
		PrivateKey:    priv,
		Peers: []WireGuardPeer{
			{
				PublicKey:    pub,
				Endpoint:     "203.0.113.10:51820",
				AllowedIPs:   "10.99.0.0/24, 10.0.0.0/16",
				KeepAliveSec: 25,
			},
		},
	}

	attrs, err := BuildWireGuardSetDeviceAttrs(cfg)
	if err != nil {
		t.Fatalf("BuildWireGuardSetDeviceAttrs failed: %v", err)
	}
	if len(attrs) < 64 {
		t.Fatalf("expected serialized WG_CMD_SET_DEVICE attributes >= 64 bytes, got %d", len(attrs))
	}
}

func TestDHCPv4PacketRoundtrip(t *testing.T) {
	mac, _ := net.ParseMAC("02:42:ac:11:00:02")
	xid := uint32(0xdeadbeef)

	discover := BuildDHCPv4Packet(dhcpMsgDiscover, xid, mac, nil, nil)
	if len(discover) != 300 {
		t.Fatalf("expected 300-byte DHCPDISCOVER packet, got %d", len(discover))
	}

	// Construct a synthetic DHCPOFFER reply for 203.0.113.42/24 via 203.0.113.1
	reply := make([]byte, 300)
	reply[0] = bootpReply
	binary.BigEndian.PutUint32(reply[4:8], xid)
	copy(reply[16:20], net.IPv4(203, 0, 113, 42).To4())
	binary.BigEndian.PutUint32(reply[236:240], dhcpMagicCookie)
	opt := 240
	// MsgType = Offer (2)
	reply[opt], reply[opt+1], reply[opt+2] = dhcpOptMsgType, 1, dhcpMsgOffer
	opt += 3
	// Subnet Mask = 255.255.255.0
	reply[opt], reply[opt+1] = dhcpOptSubnetMask, 4
	copy(reply[opt+2:opt+6], []byte{255, 255, 255, 0})
	opt += 6
	// Router = 203.0.113.1
	reply[opt], reply[opt+1] = dhcpOptRouter, 4
	copy(reply[opt+2:opt+6], []byte{203, 0, 113, 1})
	opt += 6
	reply[opt] = dhcpOptEnd

	msgType, lease, err := ParseDHCPv4Packet(reply, xid)
	if err != nil {
		t.Fatalf("ParseDHCPv4Packet failed: %v", err)
	}
	if msgType != dhcpMsgOffer || lease.CIDR != "203.0.113.42/24" || lease.Gateway != "203.0.113.1" {
		t.Fatalf("unexpected parsed DHCP lease: msgType=%d lease=%+v", msgType, lease)
	}
}

func TestCloudInitUserDataAndCerts(t *testing.T) {
	tmpRoot := t.TempDir()
	envB64 := base64.StdEncoding.EncodeToString([]byte("AXONWALL_SLOT=B\nAXONWALL_WATCHDOG=90\n"))

	userData := `#cloud-config
hostname: edge-proxmox-01
axonwall:
  hub: wss://hub.axonwall.internal:2966/ws/satellite
  token: ztp_axon_cloudinit_999
  sku: sku-vm-virtio
  ca_cert: |
    -----BEGIN CERTIFICATE-----
    MIIB+TCCAWACCQCAxonwallTestCA==
    -----END CERTIFICATE-----
  interfaces:
    - name: wan
      device: eth0
      address: 198.51.100.10/24
      gateway: 198.51.100.1
    - name: lan
      device: eth1
      address: 10.50.0.1/24
  routes:
    - destination: 10.60.0.0/16
      gateway: 10.50.0.254
      device: eth1
write_files:
  - path: /etc/axonwall/edge.env
    encoding: b64
    permissions: '0600'
    content: ` + envB64 + `
`

	bootCfg := ParseKernelCmdline("quiet axonwall.sku=sku-vm-virtio")
	err := MergeCloudInitIntoBootConfig(&bootCfg, CloudInitPayload{
		Datasource: "nocloud",
		UserData:   userData,
		MetaData:   "instance-id: i-proxmox-99\nlocal-hostname: edge-proxmox-01\n",
	}, tmpRoot)
	if err != nil {
		t.Fatalf("MergeCloudInitIntoBootConfig failed: %v", err)
	}

	if bootCfg.HubURL != "wss://hub.axonwall.internal:2966/ws/satellite" {
		t.Fatalf("unexpected HubURL: %q", bootCfg.HubURL)
	}
	if bootCfg.SatelliteID != "edge-proxmox-01" {
		t.Fatalf("unexpected SatelliteID: %q", bootCfg.SatelliteID)
	}
	if bootCfg.ZtpToken != "ztp_axon_cloudinit_999" {
		t.Fatalf("unexpected ZtpToken: %q", bootCfg.ZtpToken)
	}
	if bootCfg.UkiSlot != "B" || bootCfg.WatchdogSec != 90 {
		t.Fatalf("expected write_files edge.env to set UkiSlot=B and WatchdogSec=90, got slot=%q watchdog=%d", bootCfg.UkiSlot, bootCfg.WatchdogSec)
	}
	if len(bootCfg.Interfaces) != 2 || bootCfg.Interfaces[0].Address != "198.51.100.10/24" || bootCfg.Interfaces[1].Address != "10.50.0.1/24" {
		t.Fatalf("unexpected interfaces: %+v", bootCfg.Interfaces)
	}
	if len(bootCfg.Routes) != 1 || bootCfg.Routes[0].Destination != "10.60.0.0/16" {
		t.Fatalf("unexpected routes: %+v", bootCfg.Routes)
	}

	caBytes, err := os.ReadFile(filepath.Join(tmpRoot, "etc", "axonwall", "certs", "ca.crt"))
	if err != nil || !strings.Contains(string(caBytes), "BEGIN CERTIFICATE") {
		t.Fatalf("expected ca.crt to be written by cloud-init, got err=%v content=%q", err, string(caBytes))
	}
}

func TestCloudInitNetworkConfigV1AndV2(t *testing.T) {
	v1 := `version: 1
config:
  - type: physical
    name: eth0
    subnets:
      - type: static
        address: 203.0.113.5
        netmask: 255.255.255.0
        gateway: 203.0.113.1
  - type: physical
    name: eth1
    subnets:
      - type: dhcp
`
	ifacesV1, _ := ParseCloudInitNetworkConfig(v1)
	if len(ifacesV1) != 2 || ifacesV1[0].Address != "203.0.113.5/24" || ifacesV1[0].Gateway != "203.0.113.1" || ifacesV1[1].Address != "dhcp" {
		t.Fatalf("unexpected v1 network-config interfaces: %+v", ifacesV1)
	}

	v2 := `version: 2
ethernets:
  eth0:
    dhcp4: true
  eth1:
    addresses:
      - 10.99.0.1/24
`
	ifacesV2, _ := ParseCloudInitNetworkConfig(v2)
	if len(ifacesV2) != 2 || ifacesV2[0].Address != "dhcp" || ifacesV2[1].Address != "10.99.0.1/24" {
		t.Fatalf("unexpected v2 network-config interfaces: %+v", ifacesV2)
	}
}

func TestCloudInitIMDSFetchEC2v2(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/api/token":
			if r.Method == http.MethodPut {
				_, _ = w.Write([]byte("imds-v2-session-token"))
				return
			}
		case "/latest/user-data":
			if r.Header.Get("X-aws-ec2-metadata-token") == "imds-v2-session-token" {
				_, _ = w.Write([]byte("#cloud-config\naxonwall:\n  hub: wss://10.0.0.2:2966/ws/satellite\n  token: ztp_axon_imds_ec2\n"))
				return
			}
		case "/latest/meta-data/instance-id":
			_, _ = w.Write([]byte("i-0123456789abcdef0"))
			return
		case "/latest/meta-data/local-hostname":
			_, _ = w.Write([]byte("edge-ec2-us-east-1a"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	payload, ok := FetchIMDSCloudInit(context.Background(), srv.URL)
	if !ok || payload.Datasource != "imds-ec2" {
		t.Fatalf("expected FetchIMDSCloudInit to succeed with imds-ec2, got ok=%v payload=%+v", ok, payload)
	}

	bootCfg := EdgeBootConfig{SkuProfile: "sku-vm-virtio"}
	if err := MergeCloudInitIntoBootConfig(&bootCfg, payload, t.TempDir()); err != nil {
		t.Fatalf("MergeCloudInitIntoBootConfig(IMDS) failed: %v", err)
	}
	if bootCfg.SatelliteID != "edge-ec2-us-east-1a" || bootCfg.ZtpToken != "ztp_axon_imds_ec2" {
		t.Fatalf("unexpected merged IMDS config: %+v", bootCfg)
	}
}

func TestIPv6ModeAndDHCPv6AndRA(t *testing.T) {
	tmpSys := t.TempDir()

	// 1. Verify "disabled" shuts off kernel IPv6 on the interface
	if err := ApplyInterfaceIPv6Mode(tmpSys, "eth1", "disabled"); err != nil {
		t.Fatalf("ApplyInterfaceIPv6Mode(disabled) failed: %v", err)
	}
	disVal, _ := os.ReadFile(filepath.Join(tmpSys, "net", "ipv6", "conf", "eth1", "disable_ipv6"))
	if strings.TrimSpace(string(disVal)) != "1" {
		t.Fatalf("expected disable_ipv6=1, got %q", string(disVal))
	}

	// 2. Verify "auto" enables accept_ra=2 (router-safe SLAAC)
	if err := ApplyInterfaceIPv6Mode(tmpSys, "eth0", "auto"); err != nil {
		t.Fatalf("ApplyInterfaceIPv6Mode(auto) failed: %v", err)
	}
	raVal, _ := os.ReadFile(filepath.Join(tmpSys, "net", "ipv6", "conf", "eth0", "accept_ra"))
	if strings.TrimSpace(string(raVal)) != "2" {
		t.Fatalf("expected accept_ra=2 for WAN auto mode, got %q", string(raVal))
	}

	// 3. Deterministic ULA & /64 Subnet Carving
	ula := DeriveDeterministicULA("edge-home-01")
	if !strings.HasPrefix(ula, "fd") || !strings.HasSuffix(ula, "::/48") {
		t.Fatalf("unexpected ULA format: %q", ula)
	}
	carved, err := CarveSubnet64("2001:db8:abcd::/56", 0x10, 1)
	if err != nil || carved != "2001:db8:abcd:10::1/64" {
		t.Fatalf("expected carved subnet 2001:db8:abcd:10::1/64, got %q (err=%v)", carved, err)
	}

	// 4. DHCPv6 IA_NA + IA_PD Solicit & Reply roundtrip
	mac, _ := net.ParseMAC("52:54:00:12:34:56")
	duid := BuildDUIDLL(mac)
	txID := [3]byte{0x12, 0x34, 0x56}
	solicit := BuildDHCPv6Packet(dhcpv6MsgSolicit, txID, duid, nil, 56)
	if len(solicit) < 40 {
		t.Fatalf("unexpectedly short DHCPv6 Solicit packet: %d bytes", len(solicit))
	}

	// Construct synthetic DHCPv6 Reply (7) with IA_PD 2001:db8:cafe::/56
	var reply []byte
	reply = append(reply, dhcpv6MsgReply, txID[0], txID[1], txID[2])
	reply = appendDHCPv6Opt(reply, dhcpv6OptServerID, []byte{0, 3, 0, 1, 1, 2, 3, 4, 5, 6})
	iapfx := make([]byte, 25)
	binary.BigEndian.PutUint32(iapfx[0:4], 3600)
	binary.BigEndian.PutUint32(iapfx[4:8], 7200)
	iapfx[8] = 56
	copy(iapfx[9:25], net.ParseIP("2001:db8:cafe::").To16())
	iapd := make([]byte, 12)
	binary.BigEndian.PutUint32(iapd[0:4], 2)
	iapd = appendDHCPv6Opt(iapd, dhcpv6OptIAPrefix, iapfx)
	reply = appendDHCPv6Opt(reply, dhcpv6OptIAPD, iapd)

	msgType, v6Lease, err := ParseDHCPv6Packet(reply, txID)
	if err != nil || msgType != dhcpv6MsgReply || v6Lease.DelegatedPrefix != "2001:db8:cafe::/56" {
		t.Fatalf("unexpected DHCPv6 parsed lease: msgType=%d lease=%+v err=%v", msgType, v6Lease, err)
	}

	// 5. Router Advertisement ICMPv6 packet builder
	raPkt, err := BuildRouterAdvertisementICMPv6([]string{"2001:db8:cafe:1::/64", "fd00:1234:5678:1::/64"}, "fd00:1234:5678:1::2", 1500, 1800)
	if err != nil || len(raPkt) != 16+32+32+24+8 {
		t.Fatalf("unexpected RA packet: len=%d err=%v", len(raPkt), err)
	}
}

func TestCompileNftNetlinkIPv6DisableAndDNAT(t *testing.T) {
	script := `table inet axonwall {
  flowtable fastpath {
    hook ingress priority 0;
    devices = { "eth0", "eth1" };
    flags offload;
  }
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "eth0" tcp dport 443 dnat ip to 10.0.0.2:443 comment "port-forward-https"
  }
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "eth1.40" meta nfproto ipv6 drop comment "ipv6-disabled-iot"
    icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, echo-request, nd-neighbor-solicit, nd-neighbor-advert } accept comment "rfc4890-icmpv6"
  }
}`
	batch, err := CompileNftScriptToNetlinkBatch(script)
	if err != nil {
		t.Fatalf("CompileNftScriptToNetlinkBatch failed: %v", err)
	}
	if len(batch.Flowtables) != 1 || !batch.Flowtables[0].HwOffload {
		t.Fatalf("expected flowtable with HwOffload=true, got %+v", batch.Flowtables)
	}
	if len(batch.Rules) != 3 {
		t.Fatalf("expected 3 compiled rules (dnat, ipv6 drop, icmpv6 accept), got %d", len(batch.Rules))
	}
}
