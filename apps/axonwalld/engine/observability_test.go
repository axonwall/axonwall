package engine

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/snappy"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestComputeTargetFlowDeltasNoDropRegression(t *testing.T) {
	mgr := NewNetFlowManager(t.TempDir(), nil, nil, nil, nil, nil)
	baseFlow := FlowRecord{
		SrcIP:     "10.0.1.10",
		DstIP:     "1.1.1.1",
		SrcPort:   51000,
		DstPort:   443,
		Protocol:  6,
		InIfIndex: 2,
	}
	ifMap := map[uint32]string{2: "eth0", 3: "eth1"}

	// Fast 5s target polls at 1000, 2000, 3000 cumulative bytes -> must sum to 3000 with 0% loss
	var fastTotal uint64
	for _, cum := range []uint64{1000, 2000, 3000} {
		f := baseFlow
		f.Bytes = cum
		f.Packets = cum / 100
		eth1Skip := FlowRecord{
			SrcIP:     "10.0.2.10",
			DstIP:     "8.8.8.8",
			SrcPort:   52000,
			DstPort:   53,
			Protocol:  17,
			InIfIndex: 3,
			Bytes:     9999,
			Packets:   99,
		}
		deltas := mgr.computeTargetFlowDeltas("fast-5s", []FlowRecord{f, eth1Skip}, []string{"eth0"}, 4, ifMap)
		if len(deltas) != 1 {
			t.Fatalf("expected 1 filtered delta for eth0, got %d", len(deltas))
		}
		if deltas[0].SamplingRate != 4 {
			t.Fatalf("expected samplingRate=4, got %d", deltas[0].SamplingRate)
		}
		if deltas[0].Bytes != 1000 {
			t.Fatalf("expected delta 1000 on fast target, got %d", deltas[0].Bytes)
		}
		fastTotal += deltas[0].Bytes
	}
	if fastTotal != 3000 {
		t.Fatalf("expected fast-5s cumulative deltas to equal 3000, got %d", fastTotal)
	}

	// Independent 15s target polls later at 3000 -> must still receive full 3000 bytes
	fSlow := baseFlow
	fSlow.Bytes = 3000
	fSlow.Packets = 30
	slowDeltas := mgr.computeTargetFlowDeltas("slow-15s", []FlowRecord{fSlow}, nil, 0, ifMap)
	if len(slowDeltas) != 1 || slowDeltas[0].Bytes != 3000 {
		t.Fatalf("expected slow-15s independent delta 3000, got %+v", slowDeltas)
	}
}

func TestGetAllFlowCountersCap(t *testing.T) {
	var nilMgr *EBPFManager
	if got := nilMgr.GetAllFlowCounters(100); got != nil {
		t.Fatalf("expected nil from nil EBPFManager, got %v", got)
	}
	mgr := NewEBPFManager()
	if got := mgr.GetAllFlowCounters(0); len(got) != 0 {
		t.Fatalf("expected empty slice when unattached, got %d", len(got))
	}
	if got := mgr.GetAllFlowCounters(65536); len(got) != 0 {
		t.Fatalf("expected empty slice when unattached with max cap, got %d", len(got))
	}
}

func TestIPFIXOptionsPacketRoundTripAndRemoteMetadata(t *testing.T) {
	now := time.Now().UTC()
	dec := NewFlowDecoder()

	optPkt := EncodeIPFIXOptionsPacket(42, 1, "edge-cp1", "checkpoint1", []NetFlowRemoteIface{
		{IfIndex: 9, Name: "eth0", Description: "WAN"},
	})
	ver, optFlows, ifCounters, err := dec.DecodePacket("10.8.0.2", optPkt, now)
	if err != nil {
		t.Fatalf("DecodePacket(options) failed: %v", err)
	}
	if ver != "ipfix" || len(optFlows) != 0 {
		t.Fatalf("unexpected options decode result: ver=%s flows=%d ifCounters=%d", ver, len(optFlows), len(ifCounters))
	}

	dataPkt := EncodeIPFIXPacket(42, 2, true, []FlowRecord{
		{
			TimestampMs: now.UnixMilli(),
			FlowStartMs: now.Add(-5 * time.Second).UnixMilli(),
			SrcIP:       "192.168.10.50",
			DstIP:       "1.1.1.1",
			SrcPort:     54321,
			DstPort:     443,
			Protocol:    6,
			InIfIndex:   9,
			Bytes:       1500,
			Packets:     10,
		},
	})
	ver, flows, _, err := dec.DecodePacket("10.8.0.2", dataPkt, now)
	if err != nil {
		t.Fatalf("DecodePacket(data) failed: %v", err)
	}
	if ver != "ipfix" || len(flows) != 1 {
		t.Fatalf("expected 1 decoded IPFIX flow, got ver=%s len=%d", ver, len(flows))
	}
	if flows[0].HostID != "edge-cp1" || flows[0].HostName != "checkpoint1" {
		t.Fatalf("expected decoded node identity edge-cp1/checkpoint1, got %q/%q", flows[0].HostID, flows[0].HostName)
	}

	enricher := NewFlowEnricher(nil, nil, nil)
	enricher.ApplyRemoteNodeMetadata(RemoteNodeMetadataPayload{
		NodeID:     "edge-cp1",
		Hostname:   "checkpoint1",
		ExporterIP: "10.8.0.2",
		Interfaces: []NetFlowRemoteIface{{IfIndex: 11, Name: "wg0"}},
		StaticHosts: []NetFlowStaticHostEntry{
			{IP: "192.168.10.50", Hostname: "workstation.lan", Source: "static"},
		},
		DhcpLeases: []NetFlowRemoteLease{
			{IP: "192.168.10.60", Hostname: "phone.lan"},
		},
	})

	if got := enricher.lookupIfNameForNode("edge-cp1", "10.8.0.2", 11); got != "wg0" {
		t.Fatalf("expected remote ifName wg0, got %q", got)
	}
	if got := enricher.resolveHostForNode("edge-cp1", "192.168.10.50", false); got != "workstation.lan" {
		t.Fatalf("expected remote static host workstation.lan, got %q", got)
	}
	if got := enricher.resolveHostForNode("edge-cp1", "192.168.10.60", false); got != "phone.lan" {
		t.Fatalf("expected remote dhcp lease phone.lan, got %q", got)
	}
}

func TestEncodePrometheusRemoteWriteAndSnappy(t *testing.T) {
	raw := EncodePrometheusRemoteWrite([]PromMetricSample{
		{
			Name:        "axonwall_up",
			Labels:      []PromLabel{{Name: "node_id", Value: "edge-1"}},
			Value:       1,
			TimestampMs: 1700000000000,
		},
	})
	if len(raw) == 0 {
		t.Fatal("expected non-empty prometheus WriteRequest bytes")
	}
	compressed := snappy.Encode(nil, raw)
	decompressed, err := snappy.Decode(nil, compressed)
	if err != nil {
		t.Fatalf("snappy.Decode failed: %v", err)
	}
	if !bytes.Equal(raw, decompressed) {
		t.Fatal("snappy round-trip byte mismatch")
	}

	num, typ, n := protowire.ConsumeField(decompressed)
	if n < 0 {
		t.Fatalf("invalid protobuf wire encoding: %v", protowire.ParseError(n))
	}
	if num != 1 || typ != protowire.BytesType {
		t.Fatalf("expected outer TimeSeries field (1, BytesType), got (%d, %v)", num, typ)
	}
}

func TestTelemetryQueueRingBufferAndDiskSpool(t *testing.T) {
	// 1. RAM ring buffer drop-oldest when disk spool is disabled (1 MiB limit)
	ramQ := NewTelemetryQueue("test-ram", 1, false, t.TempDir(), 16)
	for i := byte(1); i <= 4; i++ {
		item := bytes.Repeat([]byte{i}, 400*1024)
		ramQ.Push(item)
	}
	if ramQ.DroppedCount() == 0 {
		t.Fatal("expected oldest RAM items to be dropped when exceeding 1 MiB limit")
	}
	ramStats := ramQ.Stats()
	if ramStats.QueuedBytes > 1024*1024 {
		t.Fatalf("expected queued RAM <= 1 MiB, got %d", ramStats.QueuedBytes)
	}
	batch := ramQ.PopBatch(10)
	if len(batch) == 0 || batch[len(batch)-1][0] != 4 {
		t.Fatalf("expected newest item (tag=4) retained in ring buffer, got len=%d", len(batch))
	}

	// 2. Zstd disk spool spill & FIFO replay before RAM items
	diskQ := NewTelemetryQueue("test-disk", 1, true, t.TempDir(), 16)
	for i := byte(1); i <= 3; i++ {
		item := bytes.Repeat([]byte{i}, 450*1024)
		diskQ.Push(item)
	}
	if diskQ.DroppedCount() != 0 {
		t.Fatalf("expected 0 dropped when disk spool absorbs overflow, got %d", diskQ.DroppedCount())
	}
	diskStats := diskQ.Stats()
	if diskStats.DiskSpoolBytes == 0 {
		t.Fatal("expected non-zero zstd disk spool bytes after RAM overflow")
	}
	replayed := diskQ.PopBatch(10)
	if len(replayed) == 0 || replayed[0][0] != 1 {
		t.Fatalf("expected earliest spooled item (tag=1) replayed first, got len=%d", len(replayed))
	}
}

func TestParseNflogAndRateLimiter(t *testing.T) {
	// Build minimal IPv4 TCP SYN payload (20B IP + 8B TCP)
	ipPkt := make([]byte, 28)
	ipPkt[0] = 0x45 // IPv4, IHL=20B
	ipPkt[9] = 6    // TCP
	copy(ipPkt[12:16], []byte{192, 168, 10, 10})
	copy(ipPkt[16:20], []byte{93, 184, 216, 34})
	binary.BigEndian.PutUint16(ipPkt[20:22], 51234)
	binary.BigEndian.PutUint16(ipPkt[22:24], 443)

	buildAttr := func(attrType uint16, val []byte) []byte {
		padded := ((4 + len(val)) + 3) &^ 3
		buf := make([]byte, padded)
		binary.LittleEndian.PutUint16(buf[0:2], uint16(4+len(val)))
		binary.LittleEndian.PutUint16(buf[2:4], attrType)
		copy(buf[4:], val)
		return buf
	}

	var attrs []byte
	attrs = append(attrs, buildAttr(nfulaPrefix, []byte("axonwall-rule:r1234567: \x00"))...)
	indev := make([]byte, 4)
	binary.BigEndian.PutUint32(indev, 3)
	attrs = append(attrs, buildAttr(nfulaIfindexIndev, indev)...)
	attrs = append(attrs, buildAttr(nfulaPayload, ipPkt)...)

	msgLen := 20 + len(attrs)
	msg := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint16(msg[4:6], uint16((nfnlSubsysUlog<<8)|nfulnlMsgPacket))
	binary.BigEndian.PutUint16(msg[18:20], 0) // group 0
	copy(msg[20:], attrs)

	rules := map[string]ObservabilityRuleMeta{
		"r1234567": {ID: "rule-uuid-123", Description: "Block Bad", Action: "drop", Interface: "wan"},
	}
	entries := ParseNflogNetlinkMessages(msg, "edge-cp1", "checkpoint1", rules, map[uint32]string{3: "eth0"})
	if len(entries) != 1 {
		t.Fatalf("expected 1 parsed NFLOG entry, got %d", len(entries))
	}
	e := entries[0]
	if e.RuleID != "rule-uuid-123" || e.Action != "drop" || e.Interface != "eth0" || e.SrcIP != "192.168.10.10" || e.DstPort != 443 || e.Protocol != "TCP" {
		t.Fatalf("unexpected parsed NFLOG entry: %+v", e)
	}

	lim := newTokenBucketLimiter(5)
	for i := 0; i < 5; i++ {
		if !lim.Allow() {
			t.Fatalf("expected token %d of 5 to be allowed", i+1)
		}
	}
	if lim.Allow() {
		t.Fatal("expected 6th burst call to be rate-limited")
	}
}

func TestEncodeVictoriaLogsGzipNDJSON(t *testing.T) {
	in := []StructuredLogEntry{
		{Time: "2026-11-25T12:00:00Z", Msg: "rule dropped packet", NodeID: "edge-1", Hostname: "cp1", Source: "nflog", Level: "warn"},
		{Time: "2026-11-25T12:00:01Z", Msg: "dhcp lease ack", NodeID: "edge-1", Hostname: "cp1", Source: "kea", Level: "info"},
	}
	gzBytes, err := EncodeVictoriaLogsGzipNDJSON(in)
	if err != nil {
		t.Fatalf("EncodeVictoriaLogsGzipNDJSON failed: %v", err)
	}
	r, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		t.Fatalf("gzip.NewReader failed: %v", err)
	}
	raw, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatalf("io.ReadAll failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d (%q)", len(lines), string(raw))
	}
	var decoded StructuredLogEntry
	if err := json.Unmarshal([]byte(lines[0]), &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if decoded.Source != "nflog" || decoded.NodeID != "edge-1" {
		t.Fatalf("unexpected decoded log entry: %+v", decoded)
	}
}

func TestHandleRemoteMitigateAntiLockout(t *testing.T) {
	mgr := NewObservabilityManager(nil, nil, nil, nil, nil)
	if _, err := mgr.HandleRemoteMitigate(RemoteMitigateRequest{TargetIP: "203.0.113.50"}); err == nil {
		t.Fatal("expected mitigation to be rejected when unconfigured/disabled")
	}

	cfg := `{
		"nodeId": "edge-1",
		"hostname": "cp1",
		"enabled": false,
		"activeMitigation": {
			"acceptRemoteBlocks": true,
			"maxTtlSec": 600,
			"protectedCidrs": ["10.8.0.0/24", "192.168.10.0/24"]
		}
	}`
	if err := mgr.ApplyConfig([]byte(cfg)); err != nil {
		t.Fatalf("ApplyConfig failed: %v", err)
	}

	for _, tc := range []struct {
		ip      string
		wantErr string
	}{
		{"not-an-ip", "invalid targetIp"},
		{"127.0.0.1", "protected"},
		{"10.8.0.5", "protectedCidr"},
		{"192.168.10.3", "protectedCidr"},
		{"203.0.113.50", "XDP engine unavailable"},
	} {
		_, err := mgr.HandleRemoteMitigate(RemoteMitigateRequest{TargetIP: tc.ip, TTLSec: 120})
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("ip=%s: expected error containing %q, got %v", tc.ip, tc.wantErr, err)
		}
	}
}

func TestParseRuntimeModeCollector(t *testing.T) {
	m, err := ParseRuntimeMode("collector", false, true)
	if err != nil || m != ModeCollector {
		t.Fatalf("expected ModeCollector from explicit flag, got (%v, %v)", m, err)
	}
	t.Setenv("AXONWALL_COLLECTOR_ONLY", "1")
	m2, err := ParseRuntimeMode("auto", false, true)
	if err != nil || m2 != ModeCollector {
		t.Fatalf("expected ModeCollector from AXONWALL_COLLECTOR_ONLY=1, got (%v, %v)", m2, err)
	}
}
