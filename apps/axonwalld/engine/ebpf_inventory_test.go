package engine

import (
	"testing"

	"github.com/cilium/ebpf/link"
)

func TestSummarizeXdpFlows(t *testing.T) {
	flows := []XdpFlowSnapshotEntry{
		{Family: 4, SrcIP: "10.0.0.10", DstIP: "10.0.0.1", SrcPort: 51000, DstPort: 443, VlanID: 0, Protocol: 6, ProtoName: "TCP", Packets: 120, Bytes: 180000, SynPackets: 2, RstPackets: 0},
		{Family: 4, SrcIP: "10.0.0.11", DstIP: "10.0.0.1", SrcPort: 51001, DstPort: 443, VlanID: 10, Protocol: 6, ProtoName: "TCP", Packets: 80, Bytes: 20000, SynPackets: 1, RstPackets: 1},
		{Family: 6, SrcIP: "fd00::10", DstIP: "fd00::1", SrcPort: 54000, DstPort: 53, VlanID: 10, Protocol: 17, ProtoName: "UDP", Packets: 40, Bytes: 4000},
		{Family: 4, SrcIP: "198.51.100.2", DstIP: "10.0.0.1", SrcPort: 0, DstPort: 0, VlanID: 0, Protocol: 1, ProtoName: "ICMP", Packets: 5, Bytes: 420},
	}

	protos, ports, vlans := summarizeXdpFlows(flows)
	if len(protos) != 3 {
		t.Fatalf("expected 3 protocols, got %d (%+v)", len(protos), protos)
	}
	if protos[0].ProtoName != "TCP" || protos[0].Bytes != 200000 || protos[0].Flows != 2 {
		t.Fatalf("unexpected top protocol summary: %+v", protos[0])
	}
	if len(ports) != 2 {
		t.Fatalf("expected 2 destination port summaries (excluding port 0), got %d", len(ports))
	}
	if ports[0].Port != 443 || ports[0].Service != "HTTPS" || ports[0].SynPackets != 3 || ports[0].RstPackets != 1 {
		t.Fatalf("unexpected top port summary: %+v", ports[0])
	}
	if ports[1].Port != 53 || ports[1].Service != "DNS" {
		t.Fatalf("unexpected second port summary: %+v", ports[1])
	}
	if len(vlans) != 2 || vlans[0].VlanID != 0 || vlans[1].VlanID != 10 || vlans[1].Bytes != 24000 {
		t.Fatalf("unexpected vlan breakdown: %+v", vlans)
	}
}

func TestSummarizeBpfInventory(t *testing.T) {
	progs := []BpfProgramInventoryItem{
		{ID: 1, Type: "XDP", Name: "xdp_flow_track", JitedBytes: 4096, MemlockBytes: 8192, RunTimeNs: 9000, RunCount: 100},
		{ID: 2, Type: "XDP", Name: "xdp_aux", JitedBytes: 1024, MemlockBytes: 4096, RunTimeNs: 1000, RunCount: 20},
		{ID: 3, Type: "LSM", Name: "restrict_bpf", JitedBytes: 2048, MemlockBytes: 4096, RunTimeNs: 500, RunCount: 5},
	}
	maps := []BpfMapInventoryItem{
		{ID: 10, Type: "LRUHash", Name: "flow_map", MemlockBytes: 1048576},
		{ID: 11, Type: "RingBuf", Name: "events", MemlockBytes: 262144},
		{ID: 12, Type: "LRUHash", Name: "flow6_map", MemlockBytes: 524288},
	}

	totalJited, progMem, mapMem, pByType, mByType := summarizeBpfInventory(progs, maps)
	if totalJited != 7168 || progMem != 16384 || mapMem != 1835008 {
		t.Fatalf("unexpected inventory totals: jited=%d progMem=%d mapMem=%d", totalJited, progMem, mapMem)
	}
	if len(pByType) != 2 || pByType[0].Type != "XDP" || pByType[0].Count != 2 || pByType[0].TotalRunTimeNs != 10000 {
		t.Fatalf("unexpected programsByType: %+v", pByType)
	}
	if len(mByType) != 2 || mByType[0].Type != "LRUHash" || mByType[0].TotalBytes != 1572864 {
		t.Fatalf("unexpected mapsByType: %+v", mByType)
	}
}

func TestParseKernelRcaParsers(t *testing.T) {
	snmpSample := `Ip: Forwarding DefaultTTL InReceives
Ip: 1 64 1000
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 200 120000 -1 500 200 4 2 18 50000 40000 10 1 3 0
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti
Udp: 9000 5 2 8500 1 0 0 0
`
	tcp, udp := ParseProcNetSnmp(snmpSample)
	if !tcp.Available || tcp.OutSegs != 40000 || tcp.RetransSegs != 10 || tcp.CurrEstab != 18 {
		t.Fatalf("unexpected parsed TCP SNMP: %+v", tcp)
	}
	if tcp.RetransmitRatioPct != 0.025 {
		t.Fatalf("expected RetransmitRatioPct=0.025, got %v", tcp.RetransmitRatioPct)
	}
	if !udp.Available || udp.InDatagrams != 9000 || udp.InErrors != 2 || udp.RcvbufErrors != 1 {
		t.Fatalf("unexpected parsed UDP SNMP: %+v", udp)
	}

	cg := ParseCgroupCpuStat("usage_usec 123456\nnr_periods 2000\nnr_throttled 50\nthrottled_usec 90000\n", "/sys/fs/cgroup/kubepods.slice/cpu.stat")
	if !cg.Available || cg.NrPeriods != 2000 || cg.NrThrottled != 50 || cg.ThrottleRatioPct != 2.5 {
		t.Fatalf("unexpected parsed cgroup cpu.stat: %+v", cg)
	}

	mem := ParseProcVmstatAndPsi("pgfault 1000\npgmajfault 12\noom_kill 1\nallocstall_normal 4\nallocstall_movable 3\n", "some avg10=1.25 avg60=0.40 avg300=0.10 total=999\nfull avg10=0.50 avg60=0.10 avg300=0.02 total=100\n")
	if !mem.Available || mem.OomKillCount != 1 || mem.MajorPageFaults != 12 || mem.AllocStalls != 7 {
		t.Fatalf("unexpected parsed vmstat: %+v", mem)
	}
	if !mem.PsiAvailable || mem.PsiSomeAvg10 != 1.25 || mem.PsiFullAvg10 != 0.50 {
		t.Fatalf("unexpected parsed PSI: %+v", mem)
	}

	emptyTcp, emptyUdp := ParseProcNetSnmp("")
	if emptyTcp.Available || emptyUdp.Available {
		t.Fatalf("expected empty snmp input to produce Available=false")
	}
}

func TestGetDataplaneSnapshotNonNilSlicesWhenUnattached(t *testing.T) {
	mgr := NewEBPFManager()
	snap := mgr.GetDataplaneSnapshot(50)
	if snap.PerCpuStats == nil || snap.ProtocolBreakdown == nil || snap.TopPorts == nil || snap.VlanBreakdown == nil || snap.SynRateMeters == nil || snap.TopFlows == nil || snap.ActiveBlocks == nil {
		t.Fatalf("expected all slices in EbpfDataplaneSnapshot to be non-nil: %+v", snap)
	}
}

func TestParseProcNetSoftnetStat(t *testing.T) {
	raw := `
001179be 00000004 00000002 00000000 00000000 00000000 00000000 00000000 00000001 0000000a 00000003 00000000 00000000 00000000 00000000
00000100 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000002
00000020 00000001 00000005
`
	res := ParseProcNetSoftnetStat(raw)
	if !res.Available || res.CpuCount != 3 || len(res.PerCpu) != 3 {
		t.Fatalf("expected 3 parsed CPUs, got %+v", res)
	}
	if res.PerCpu[0].Cpu != 0 || res.PerCpu[0].Processed != 0x001179be || res.PerCpu[0].Dropped != 4 || res.PerCpu[0].TimeSqueeze != 2 || res.PerCpu[0].CpuCollision != 1 || res.PerCpu[0].ReceivedRps != 10 || res.PerCpu[0].FlowLimitCount != 3 {
		t.Fatalf("unexpected cpu 0 softnet entry: %+v", res.PerCpu[0])
	}
	// Row 1 explicitly encodes cpu index 2 via column 12; row 2 has short columns and falls back to index 2 -> sorted tie preserves both.
	if res.TotalDropped != 5 || res.TotalTimeSqueeze != 7 || res.TotalCpuCollision != 1 || res.TotalReceivedRps != 10 || res.TotalFlowLimitCount != 3 {
		t.Fatalf("unexpected softnet aggregates: %+v", res)
	}

	empty := ParseProcNetSoftnetStat("")
	if empty.Available || empty.CpuCount != 0 || empty.PerCpu == nil {
		t.Fatalf("expected empty softnet telemetry to remain unavailable with non-nil PerCpu: %+v", empty)
	}
}

func TestParseProcNetSockets(t *testing.T) {
	tcp4 := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 100
   1: 0100007F:0B96 0A000002:C350 01 00000000:00000000 00:00000000 00000000     0        0 101
   2: 00000000:01BB 0A000003:C351 03 00000000:00000000 00:00000000 00000000     0        0 102
   3: 00000000:0016 0A000004:C352 06 00000000:00000000 00:00000000 00000000     0        0 103
   4: 00000000:0016 0A000005:C353 08 00000000:00000000 00:00000000 00000000     0        0 104
`
	tcp6 := `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A
`
	udp4 := `  sl  local_address rem_address   st
   0: 00000000:01BB 00000000:0000 07
   1: 0100007F:9999 0A000002:0035 01
`
	udp6 := `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 07
`

	res := ParseProcNetSockets(tcp4, tcp6, udp4, udp6)
	if !res.Available || res.Ipv4TcpSockets != 5 || res.Ipv6TcpSockets != 1 || res.TotalTcpSockets != 6 {
		t.Fatalf("unexpected TCP socket totals: %+v", res)
	}
	if res.Ipv4UdpSockets != 2 || res.Ipv6UdpSockets != 1 || res.TotalUdpSockets != 3 {
		t.Fatalf("unexpected UDP socket totals: %+v", res)
	}
	if res.TcpStates["LISTEN"] != 2 || res.TcpStates["ESTABLISHED"] != 1 || res.TcpStates["SYN_RECV"] != 1 || res.TcpStates["TIME_WAIT"] != 1 || res.TcpStates["CLOSE_WAIT"] != 1 {
		t.Fatalf("unexpected TCP state breakdown: %+v", res.TcpStates)
	}
	// Expected listening ports sorted by port asc: UDP:53 (DNS), TCP:443 (HTTPS), UDP:443 (QUIC/HTTP3)
	if len(res.ListeningPorts) != 3 {
		t.Fatalf("expected 3 listening ports, got %+v", res.ListeningPorts)
	}
	if res.ListeningPorts[0].Protocol != "UDP" || res.ListeningPorts[0].Port != 53 || res.ListeningPorts[0].Service != "DNS" || res.ListeningPorts[0].Ipv6Sockets != 1 {
		t.Fatalf("unexpected first listening port: %+v", res.ListeningPorts[0])
	}
	if res.ListeningPorts[1].Protocol != "TCP" || res.ListeningPorts[1].Port != 443 || res.ListeningPorts[1].Ipv4Sockets != 1 || res.ListeningPorts[1].Ipv6Sockets != 1 || res.ListeningPorts[1].TotalCount != 2 {
		t.Fatalf("unexpected TCP 443 listening entry: %+v", res.ListeningPorts[1])
	}
	if res.ListeningPorts[2].Protocol != "UDP" || res.ListeningPorts[2].Port != 443 || res.ListeningPorts[2].Service != "QUIC/HTTP3" {
		t.Fatalf("unexpected UDP 443 listening entry: %+v", res.ListeningPorts[2])
	}
}

func TestFormatBpfLinkType(t *testing.T) {
	cases := map[link.Type]string{
		link.XDPType:           "xdp",
		link.TCXType:           "tcx",
		link.CgroupType:        "cgroup",
		link.TracingType:       "tracing",
		link.RawTracepointType: "raw_tracepoint",
		link.PerfEventType:     "perf_event",
		link.NetfilterType:     "netfilter",
		link.Type(999):         "type_999",
	}
	for in, want := range cases {
		if got := formatBpfLinkType(in); got != want {
			t.Fatalf("formatBpfLinkType(%v) = %q, want %q", in, got, want)
		}
	}
}
