package engine

import (
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNetFlowDecodersAndEncodersRoundTrip(t *testing.T) {
	dec := NewFlowDecoder()
	now := time.Now()
	sample := []FlowRecord{
		{
			FlowStartMs: now.Add(-2 * time.Second).UnixMilli(),
			TimestampMs: now.UnixMilli(),
			SrcIP:       "10.80.0.10",
			DstIP:       "1.1.1.1",
			SrcPort:     51234,
			DstPort:     443,
			Protocol:    6,
			TCPFlags:    0x12,
			InIfIndex:   2,
			OutIfIndex:  1,
			VlanID:      10,
			Bytes:       128000,
			Packets:     96,
		},
	}

	// 1. IPFIX RFC 7011 round-trip
	ipfixPkt := EncodeIPFIXPacket(42, 1, true, sample)
	ver, flows, _, err := dec.DecodePacket("10.80.0.1", ipfixPkt, now)
	if err != nil || ver != "ipfix" || len(flows) != 1 {
		t.Fatalf("IPFIX round-trip failed: ver=%q len=%d err=%v", ver, len(flows), err)
	}
	if flows[0].SrcIP != "10.80.0.10" || flows[0].DstIP != "1.1.1.1" || flows[0].DstPort != 443 || flows[0].VlanID != 10 {
		t.Fatalf("IPFIX decoded fields mismatch: %+v", flows[0])
	}

	// 2. NetFlow v9 RFC 3954 round-trip
	nf9Pkt := EncodeNetFlowV9Packet(7, 1, true, sample)
	ver9, flows9, _, err := dec.DecodePacket("10.80.0.2", nf9Pkt, now)
	if err != nil || ver9 != "netflow9" || len(flows9) != 1 {
		t.Fatalf("NetFlow v9 round-trip failed: ver=%q len=%d err=%v", ver9, len(flows9), err)
	}
	if flows9[0].Bytes != 128000 || flows9[0].Packets != 96 {
		t.Fatalf("NetFlow v9 decoded counters mismatch: %+v", flows9[0])
	}

	// 3. NetFlow v5 decode
	nf5Pkt := encodeSyntheticNetFlowV5(sample)
	ver5, flows5, _, err := dec.DecodePacket("10.80.0.3", nf5Pkt, now)
	if err != nil || ver5 != "netflow5" || len(flows5) != 1 {
		t.Fatalf("NetFlow v5 decode failed: ver=%q len=%d err=%v", ver5, len(flows5), err)
	}

	// 4. sFlow v5 Flow Sample + Raw Ethernet/IPv4/TCP decode
	sfPkt := encodeSyntheticSFlowV5(sample)
	verS, flowsS, _, err := dec.DecodePacket("10.80.0.4", sfPkt, now)
	if err != nil || verS != "sflow5" || len(flowsS) != 1 {
		t.Fatalf("sFlow v5 decode failed: ver=%q len=%d err=%v", verS, len(flowsS), err)
	}
	if flowsS[0].SamplingRate != 100 || flowsS[0].DstPort != 443 {
		t.Fatalf("sFlow v5 sampling/port mismatch: %+v", flowsS[0])
	}

	if len(dec.GetTemplates()) < 2 {
		t.Fatalf("expected >= 2 cached templates (IPFIX + v9), got %d", len(dec.GetTemplates()))
	}
}

func TestIPFIXEnterpriseAndVariableLengthDecode(t *testing.T) {
	dec := NewFlowDecoder()
	// Build IPFIX packet with Enterprise IE 1 (ent=65001, varLen=0xffff) + DstPort (7+4=11? IE 11, len=2)
	// Template Set: id=258, count=2:
	//   field 1: 0x8001 (ent bit + 1), len=0xFFFF, entID=65001 (8 bytes)
	//   field 2: 11 (dstPort), len=2 (4 bytes)
	buf := make([]byte, 16)
	binary.BigEndian.PutUint16(buf[0:2], 10)
	binary.BigEndian.PutUint32(buf[12:16], 11)

	tmplSet := []byte{
		0, 2, 0, 20, // SetID=2, Len=20
		1, 2, 0, 2, // TemplateID=258, FieldCount=2
		0x80, 1, 0xFF, 0xFF, 0, 0, 0xFD, 0xE9, // Enterprise IE 1 (65001) var-len
		0, 11, 0, 2, // IE 11 (dstPort) len 2
	}
	ns := "kube-system"
	// Data Set: SetID=258, len = 4 + 1 + len(ns) + 2 = 18 -> 20 with padding? Wait 4+1+11+2 = 18 -> no padding needed in varLen loop
	dataSet := []byte{1, 2, 0, byte(4 + 1 + len(ns) + 2), byte(len(ns))}
	dataSet = append(dataSet, []byte(ns)...)
	dataSet = append(dataSet, 0x01, 0xBB) // port 443

	pkt := append(buf, tmplSet...)
	pkt = append(pkt, dataSet...)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))

	ver, flows, _, err := dec.DecodePacket("10.80.0.10", pkt, time.Now())
	if err != nil || ver != "ipfix" || len(flows) != 1 {
		t.Fatalf("IPFIX enterprise var-len decode failed: ver=%q len=%d err=%v", ver, len(flows), err)
	}
	if flows[0].K3sNamespace != "kube-system" || flows[0].DstPort != 443 {
		t.Fatalf("unexpected decoded enterprise flow: %+v", flows[0])
	}
}

func TestFlowStoreZstdChunkingFQLAndAlertingEndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	sinkConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen mock replicator sink: %v", err)
	}
	defer sinkConn.Close()
	sinkPort := sinkConn.LocalAddr().(*net.UDPAddr).Port

	mgr := NewNetFlowManager(t.TempDir(), nil, nil, nil, nil, nil)
	bundle := &NetFlowRuntimeBundle{
		Enabled: true,
		Config: NetFlowConfigPayload{
			Enabled: true,
			Replicator: NetFlowReplicatorPayload{
				Enabled: true,
				Targets: []NetFlowReplicatorTargetPayload{
					{ID: "siem", Name: "Mock SIEM", Enabled: true, DestinationHost: "127.0.0.1", DestinationPort: sinkPort},
				},
			},
			Storage: NetFlowStoragePayload{
				Mode:             "local",
				DataDir:          tmpDir,
				RetentionHours:   24,
				MaxDiskMB:        512,
				HotRingSize:      1000,
				FlushIntervalSec: 10,
				Compression:      "zstd",
			},
			Enrichment: NetFlowEnrichmentPayload{
				GeoIPAsn:         true,
				ThreatIntelMatch: true,
				InternalCidrs:    []string{"10.0.0.0/8"},
			},
			Alerting: NetFlowAlertingPayload{
				Enabled: true,
				Rules: []NetFlowAlertRulePayload{
					{ID: "r-scan", Name: "Scan", Enabled: true, Kind: "port_scan", Severity: "high", Threshold: 3, WindowSec: 60, CooldownSec: 300, Actions: []string{"alert_log"}},
					{ID: "r-ioc", Name: "Threat IOC", Enabled: true, Kind: "threat_ioc", Severity: "critical", Threshold: 1, WindowSec: 60, CooldownSec: 300, Actions: []string{"alert_log"}},
				},
			},
		},
		ThreatCidrs: []NetFlowThreatEntry{{Alias: "threat_c2", Entry: "198.51.100.0/24"}},
	}

	mgr.mu.Lock()
	mgr.bundle = bundle
	mgr.mu.Unlock()
	mgr.enricher.UpdateBundle(bundle)
	mgr.store.Configure(bundle.Config.Storage)

	// Simulate packet ingestion (triggers decode, enrichment, store, replicator, and alert rules)
	now := time.Now()
	var scanFlows []FlowRecord
	for p := uint16(80); p <= 83; p++ {
		scanFlows = append(scanFlows, FlowRecord{
			FlowStartMs: now.Add(-2 * time.Second).UnixMilli(),
			TimestampMs: now.UnixMilli(),
			SrcIP:       "10.80.0.55",
			DstIP:       "198.51.100.77",
			SrcPort:     50000 + p,
			DstPort:     p,
			Protocol:    6,
			Bytes:       150000,
			Packets:     100,
		})
	}
	pkt := EncodeIPFIXPacket(1, 1, true, scanFlows)
	rt := &listenerRuntime{cfg: NetFlowListenerPayload{ID: "test", Protocol: "auto"}}
	mgr.processPacket(rt, "10.80.0.1", pkt)

	// Verify replicator received raw packet
	_ = sinkConn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	n, _, err := sinkConn.ReadFromUDP(buf)
	if err != nil || n != len(pkt) {
		t.Fatalf("expected replicated packet of %d bytes, got %d (err=%v)", len(pkt), n, err)
	}

	// Verify alerts fired for both port_scan (4 ports >= 3) and threat_ioc (198.51.100.77)
	alerts := mgr.ListAlerts()
	if len(alerts) < 2 {
		t.Fatalf("expected >= 2 alerts (port_scan + threat_ioc), got %d: %+v", len(alerts), alerts)
	}

	// Flush zstd chunks to disk, reload store from manifest, and verify FQL queries
	if err := mgr.store.Flush(); err != nil {
		t.Fatalf("store flush failed: %v", err)
	}
	reloaded := NewFlowStore(bundle.Config.Storage)
	res := reloaded.Query(FlowQueryRequest{
		RangeMinutes: 10,
		FQL:          `src=10.80.0.0/24 and (dst_port=80 or dst_port=81) and threat="threat_c2" and bytes>10KB`,
	})
	if res.FQLError != "" {
		t.Fatalf("unexpected FQL error: %s", res.FQLError)
	}
	if res.TotalMatchedFlows != 2 {
		t.Fatalf("expected 2 flows matching FQL on reloaded zstd store, got %d", res.TotalMatchedFlows)
	}
}

func TestNetFlowHTTPClientsHardening(t *testing.T) {
	var targetHits int
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetSrv.URL+"/redirected", http.StatusFound)
	}))
	defer redirSrv.Close()

	mgr := NewNetFlowManager(t.TempDir(), nil, nil, nil, nil, nil)
	metaClient, err := mgr.getMetadataHTTPClient(&NetFlowRuntimeBundle{}, targetSrv.URL)
	if err != nil {
		t.Fatalf("getMetadataHTTPClient: %v", err)
	}
	if _, err := metaClient.Get(targetSrv.URL); err == nil {
		t.Fatal("expected metadata HTTP client to block loopback by default")
	}
	if _, err := metaClient.Get("http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Fatal("expected metadata HTTP client to block IMDS")
	}

	mgr.SetAllowLoopbackHTTPForTest(true)
	metaLoopbackClient, err := mgr.getMetadataHTTPClient(&NetFlowRuntimeBundle{}, redirSrv.URL)
	if err != nil {
		t.Fatalf("getMetadataHTTPClient loopback: %v", err)
	}
	resp, err := metaLoopbackClient.Get(redirSrv.URL)
	if err != nil {
		t.Fatalf("expected unfollowed 302 from metadata client, got: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || targetHits != 0 {
		t.Fatalf("expected metadata client not to follow redirect (status=%d, targetHits=%d)", resp.StatusCode, targetHits)
	}

	if err := postAlertWebhookWithClient(targetSrv.URL, NetFlowAlertRulePayload{ID: "r1"}, "1.2.3.4", "test", nil); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected alert webhook default client to block loopback, got: %v", err)
	}
	if err := postNetflowReportWebhookWithClient(targetSrv.URL, NetFlowReportResponse{}, nil); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected report webhook default client to block loopback, got: %v", err)
	}
	if err := postAlertWebhookWithClient(redirSrv.URL, NetFlowAlertRulePayload{ID: "r1"}, "1.2.3.4", "test", metaLoopbackClient); err != nil {
		t.Fatalf("expected non-followed 302 on alert webhook, got: %v", err)
	}
	if targetHits != 0 {
		t.Fatalf("expected redirect target never reached by alert webhook, got %d hits", targetHits)
	}
}
