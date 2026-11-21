package engine

import (
	"testing"
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
