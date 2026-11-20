package engine

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBugHuntV012_NetdevSchemaAndLogicalResolution(t *testing.T) {
	raw := []byte(`{
		"vlans": [
			{ "parentInterface": "eth1", "vlanInterface": "vlan10", "tag": 10, "mtu": 1500 }
		],
		"bonds": [
			{ "name": "bond0", "mode": "802.3ad", "members": ["eth2", "eth3"] }
		],
		"bridges": [
			{ "name": "br-lan", "vlanFiltering": true, "members": [{ "interface": "eth1" }] }
		],
		"virtualIps": [
			{ "ip": "192.0.2.50", "subnetBits": 24, "interface": "wan" },
			{ "ip": "2001:db8::50", "subnetBits": 64, "interface": "lan" }
		]
	}`)

	var cfg NetdevConfigBundle
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal NetdevConfigBundle: %v", err)
	}
	if len(cfg.Vlans) != 1 || cfg.Vlans[0].EffectiveParent() != "eth1" || cfg.Vlans[0].EffectiveVlanInterface() != "vlan10" {
		t.Fatalf("unexpected VLAN parse: %+v", cfg.Vlans)
	}
	if len(cfg.Bonds) != 1 || len(cfg.Bonds[0].EffectiveMembers()) != 2 || cfg.Bonds[0].EffectiveMembers()[0] != "eth2" {
		t.Fatalf("unexpected Bond parse: %+v", cfg.Bonds)
	}
	if len(cfg.Bridges) != 1 || len(cfg.Bridges[0].Members) != 1 || cfg.Bridges[0].Members[0].EffectiveDevice() != "eth1" {
		t.Fatalf("unexpected Bridge parse: %+v", cfg.Bridges)
	}
	if got := formatVirtualIpCIDR(cfg.VirtualIps[0]); got != "192.0.2.50/24" {
		t.Fatalf("IPv4 VIP CIDR = %q, want 192.0.2.50/24", got)
	}
	if got := formatVirtualIpCIDR(cfg.VirtualIps[1]); got != "2001:db8::50/64" {
		t.Fatalf("IPv6 VIP CIDR = %q, want 2001:db8::50/64", got)
	}

	tmpEtc := t.TempDir()
	oldEtc := AxonwallEtcDir
	AxonwallEtcDir = tmpEtc
	defer func() { AxonwallEtcDir = oldEtc }()
	if err := os.WriteFile(filepath.Join(tmpEtc, "interfaces.conf"), []byte("WAN_INTERFACE=enp1s0\nLAN_INTERFACE=enp2s0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if dev := resolveLogicalInterfaceDev("wan"); dev != "enp1s0" {
		t.Fatalf("resolveLogicalInterfaceDev(wan) = %q, want enp1s0", dev)
	}
	if dev := resolveLogicalInterfaceDev("lan"); dev != "enp2s0" {
		t.Fatalf("resolveLogicalInterfaceDev(lan) = %q, want enp2s0", dev)
	}
}

func TestBugHuntV012_EpisodeAnonymizationScrubsIPv6ReasoningAndSNI(t *testing.T) {
	anon, err := NewCryptoPanAnonymizer("bughunt-test-salt", "")
	if err != nil {
		t.Fatalf("NewCryptoPanAnonymizer: %v", err)
	}
	ep := ThreatEpisode{
		ID:                 "ep-v6-sni-1",
		LabelTier:          "gold_malicious",
		ReviewStatus:       "pinned_gold",
		SrcIP:              "2001:db8:10::5",
		DstIP:              "198.51.100.44",
		SrcPort:            44444,
		DstPort:            443,
		ProtoName:          "TCP",
		SNI:                "secret-c2.corp.internal",
		CausalDsl:          "FLOW src=2001:db8:10::5 -> 198.51.100.44 sni=secret-c2.corp.internal",
		ReasoningTrace:     "Host 2001:db8:10::5 beaconed to secret-c2.corp.internal at 198.51.100.44",
		RecommendedMcpTool: `sinkhole_dns({"domain":"secret-c2.corp.internal","src":"2001:db8:10::5"})`,
	}
	sft := episodeToSftExample(ep, anon)
	joined := sft.Messages[1].Content + "\n" + sft.Messages[2].Content
	for _, secret := range []string{"2001:db8:10::5", "198.51.100.44", "secret-c2.corp.internal"} {
		if strings.Contains(joined, secret) {
			t.Fatalf("unredacted secret %q leaked in SFT example:\n%s", secret, joined)
		}
	}
	if !strings.Contains(joined, ".anon.axonwall") {
		t.Fatalf("expected hashed .anon.axonwall SNI replacement in SFT output:\n%s", joined)
	}
}

func TestBugHuntV012_CorruptParquetFooterNoPanic(t *testing.T) {
	// Craft a Parquet-shaped buffer with a huge Thrift binary/string length and deep/garbage header
	var buf bytes.Buffer
	buf.WriteString("PAR1")
	// Compact protocol binary field (id=6 CreatedBy delta=6 -> 0x68), huge varint length 0xFFFFFFFF0F
	footer := []byte{0x68, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00}
	buf.Write(footer)
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(footer)))
	buf.Write(lenBuf[:])
	buf.WriteString("PAR1")

	if _, err := ReadThreatParquetMetadata(buf.Bytes()); err == nil {
		t.Fatalf("expected error parsing corrupt Parquet footer with oversized length")
	}

	// Oversized list count in schema field (field 2, list type 9 -> 0x29, count=0xFF varint)
	var buf2 bytes.Buffer
	buf2.WriteString("PAR1")
	footer2 := []byte{0x29, 0xfc, 0xff, 0xff, 0xff, 0x0f, 0x00}
	buf2.Write(footer2)
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(footer2)))
	buf2.Write(lenBuf[:])
	buf2.WriteString("PAR1")

	if _, err := ReadThreatParquetMetadata(buf2.Bytes()); err == nil {
		t.Fatalf("expected error parsing corrupt Parquet footer with huge list count")
	}
}

func TestBugHuntV012_ManifestUserNsBpffsTokensAndHelmValues(t *testing.T) {
	validUserNs := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: xdp-guard
spec:
  template:
    spec:
      hostUsers: false
      containers:
        - name: guard
          image: ghcr.io/axonwall/guard:v1
          securityContext:
            capabilities:
              drop: ["ALL"]
              add: ["BPF", "NET_ADMIN"]
      volumes:
        - name: bpf-token
          hostPath:
            path: /run/axonwall/bpffs-tokens/xdp-guard
            type: Directory
---
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: vigilante-soc
spec:
  repo: https://charts.vigilante.local
  chart: vigilante-soc
  values:
    kind: ServiceAccount
`
	if err := validateK3sManifest(validUserNs); err != nil {
		t.Fatalf("valid UserNS bpffs-tokens Deployment + HelmChart rejected: %v", err)
	}

	badEtcHostPath := `apiVersion: v1
kind: Pod
metadata:
  name: bad
spec:
  hostUsers: false
  containers:
    - name: c
      image: alpine
  volumes:
    - name: etc
      hostPath:
        path: /etc
`
	if err := validateK3sManifest(badEtcHostPath); err == nil {
		t.Fatalf("expected /etc hostPath with hostUsers: false to still be rejected")
	}

	badNoUserNs := `apiVersion: v1
kind: Pod
metadata:
  name: bad-nouserns
spec:
  containers:
    - name: c
      image: alpine
      securityContext:
        capabilities:
          drop: ["ALL"]
          add: ["BPF"]
  volumes:
    - name: tok
      hostPath:
        path: /run/axonwall/bpffs-tokens/xdp-guard
`
	if err := validateK3sManifest(badNoUserNs); err == nil {
		t.Fatalf("expected bpffs-tokens hostPath without hostUsers: false to be rejected")
	}
}

func TestBugHuntV012_CloneVmMacsBridgesAndTokenBoundary(t *testing.T) {
	// A-M2 (round 3, merged): CloneVM fails closed without zfs, so
	// the rewrite assertions below need a working zfs on PATH.
	// (The fake exits 0 for list/snapshot/send/receive alike.)
	bughunt3FakeZfs(t, "exit 0\n")
	virtMgr := newTestVirtManager(t)
	if err := virtMgr.RegisterVMSpec(CompiledVmSpec{
		VMID:     100,
		Name:     "app-vm",
		Binary:   "qemu-system-x86_64",
		Cores:    2,
		MemoryMb: 2048,
		Bridges:  map[string]string{"tap100i0": "br-lan"},
		VlanTags: map[string]int{"tap100i0": 20},
		Args: []string{
			"-name", "vm-100",
			"-qmp", "unix:/run/axonwall/qmp/vm-100.sock,server,nowait",
			"-netdev", "tap,id=net0,ifname=tap100i0,script=no",
			"-device", "virtio-net-pci,netdev=net0,mac=52:54:00:aa:bb:cc",
			"-drive", "file=/dev/zvol/tank/vms/vm-1000-extra-disk-0",
		},
		Disks: []VmDisk{{Name: "disk0", Pool: "tank", SizeGb: 32}},
	}); err != nil {
		t.Fatalf("RegisterVMSpec: %v", err)
	}

	cloned, err := virtMgr.CloneVM(100, 101, "app-vm-clone", false)
	if err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	if cloned.Bridges["tap101i0"] != "br-lan" || cloned.Bridges["tap100i0"] != "" {
		t.Fatalf("expected re-keyed Bridges map for tap101i0, got: %+v", cloned.Bridges)
	}
	if cloned.VlanTags["tap101i0"] != 20 || cloned.VlanTags["tap100i0"] != 0 {
		t.Fatalf("expected re-keyed VlanTags map for tap101i0, got: %+v", cloned.VlanTags)
	}
	joinedArgs := strings.Join(cloned.Args, " ")
	if strings.Contains(joinedArgs, "52:54:00:aa:bb:cc") {
		t.Fatalf("cloned VM reused source MAC address: %s", joinedArgs)
	}
	if !strings.Contains(joinedArgs, "ifname=tap101i0") {
		t.Fatalf("cloned VM did not rewrite tap100i0 -> tap101i0: %s", joinedArgs)
	}
	if !strings.Contains(joinedArgs, "vm-1000-extra-disk-0") {
		t.Fatalf("CloneVM corrupted unrelated vm-1000 reference: %s", joinedArgs)
	}
}
