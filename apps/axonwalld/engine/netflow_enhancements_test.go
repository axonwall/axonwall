package engine

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func buildTestMMDB(cityMode bool) []byte {
	var data bytes.Buffer
	encodeStr := func(b *bytes.Buffer, s string) {
		n := len(s)
		if n < 29 {
			b.WriteByte(byte((2 << 5) | n))
		} else {
			b.WriteByte(byte((2 << 5) | 29))
			b.WriteByte(byte(n - 29))
		}
		b.WriteString(s)
	}
	encodeUint32 := func(b *bytes.Buffer, v uint32) {
		var tmp [4]byte
		binary.BigEndian.PutUint32(tmp[:], v)
		b.WriteByte(byte((6 << 5) | 4))
		b.Write(tmp[:])
	}
	encodeUint16 := func(b *bytes.Buffer, v uint16) {
		var tmp [2]byte
		binary.BigEndian.PutUint16(tmp[:], v)
		b.WriteByte(byte((5 << 5) | 2))
		b.Write(tmp[:])
	}
	encodeDouble := func(b *bytes.Buffer, v float64) {
		var tmp [8]byte
		binary.BigEndian.PutUint64(tmp[:], math.Float64bits(v))
		b.WriteByte(byte((3 << 5) | 8))
		b.Write(tmp[:])
	}
	encodeMapHdr := func(b *bytes.Buffer, count int) {
		b.WriteByte(byte((7 << 5) | count))
	}

	// Record A (at data offset 0): bit0 == 0 (e.g. 1.1.1.1)
	offA := data.Len()
	if cityMode {
		encodeMapHdr(&data, 3)
		encodeStr(&data, "country")
		encodeMapHdr(&data, 1)
		encodeStr(&data, "iso_code")
		encodeStr(&data, "AU")

		encodeStr(&data, "city")
		encodeMapHdr(&data, 1)
		encodeStr(&data, "names")
		encodeMapHdr(&data, 1)
		encodeStr(&data, "en")
		encodeStr(&data, "Sydney")

		encodeStr(&data, "location")
		encodeMapHdr(&data, 2)
		encodeStr(&data, "latitude")
		encodeDouble(&data, -33.8688)
		encodeStr(&data, "longitude")
		encodeDouble(&data, 151.2093)
	} else {
		encodeMapHdr(&data, 2)
		encodeStr(&data, "autonomous_system_number")
		encodeUint32(&data, 13335)
		encodeStr(&data, "autonomous_system_organization")
		encodeStr(&data, "Cloudflare Inc")
	}

	// Record B (bit0 == 1, e.g. 198.51.100.1)
	offB := data.Len()
	if cityMode {
		encodeMapHdr(&data, 2)
		encodeStr(&data, "country")
		encodeMapHdr(&data, 1)
		encodeStr(&data, "iso_code")
		encodeStr(&data, "DE")

		encodeStr(&data, "city")
		encodeMapHdr(&data, 1)
		encodeStr(&data, "names")
		encodeMapHdr(&data, 1)
		encodeStr(&data, "en")
		encodeStr(&data, "Frankfurt")
	} else {
		encodeMapHdr(&data, 2)
		encodeStr(&data, "autonomous_system_number")
		encodeUint32(&data, 24940)
		encodeStr(&data, "autonomous_system_organization")
		encodeStr(&data, "Hetzner Online")
	}

	const nodeCount = 1
	// 24-bit record size: node 0 left -> 1 + 16 + offA, right -> 1 + 16 + offB
	recA := uint32(nodeCount + 16 + offA)
	recB := uint32(nodeCount + 16 + offB)
	tree := []byte{
		byte(recA >> 16), byte(recA >> 8), byte(recA),
		byte(recB >> 16), byte(recB >> 8), byte(recB),
	}

	var out bytes.Buffer
	out.Write(tree)
	out.Write(make([]byte, 16))
	out.Write(data.Bytes())
	out.Write(mmdbMetadataMarker)

	encodeMapHdr(&out, 4)
	encodeStr(&out, "node_count")
	encodeUint32(&out, nodeCount)
	encodeStr(&out, "record_size")
	encodeUint16(&out, 24)
	encodeStr(&out, "ip_version")
	encodeUint16(&out, 4)
	encodeStr(&out, "database_type")
	if cityMode {
		encodeStr(&out, "GeoLite2-City")
	} else {
		encodeStr(&out, "GeoLite2-ASN")
	}
	return out.Bytes()
}

func TestMMDBReaderCityAndASNAndHTTPUpdate(t *testing.T) {
	cityBytes := buildTestMMDB(true)
	asnBytes := buildTestMMDB(false)

	cityReader, err := OpenMMDBBytes(cityBytes)
	if err != nil {
		t.Fatalf("OpenMMDBBytes(city) failed: %v", err)
	}
	iso, city, lat, lon, ok := cityReader.LookupCity(netip.MustParseAddr("1.1.1.1"))
	if !ok || iso != "AU" || city != "Sydney" || math.Abs(lat-(-33.8688)) > 0.01 || math.Abs(lon-151.2093) > 0.01 {
		t.Fatalf("unexpected City lookup: ok=%v iso=%q city=%q lat=%v lon=%v", ok, iso, city, lat, lon)
	}
	iso2, city2, _, _, ok2 := cityReader.LookupCity(netip.MustParseAddr("198.51.100.1"))
	if !ok2 || iso2 != "DE" || city2 != "Frankfurt" {
		t.Fatalf("unexpected right-branch City lookup: ok=%v iso=%q city=%q", ok2, iso2, city2)
	}

	asnReader, err := OpenMMDBBytes(asnBytes)
	if err != nil {
		t.Fatalf("OpenMMDBBytes(asn) failed: %v", err)
	}
	asn, org, okA := asnReader.LookupASN(netip.MustParseAddr("1.1.1.1"))
	if !okA || asn != 13335 || org != "Cloudflare Inc" {
		t.Fatalf("unexpected ASN lookup: ok=%v asn=%d org=%q", okA, asn, org)
	}

	// Test HTTPS atomic updater (rejects http://, private IPs, and unsafe destination paths; accepts valid TLS reload + preserves on corrupt payload)
	serveCorrupt := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveCorrupt {
			_, _ = w.Write([]byte("not-a-valid-mmdb-file"))
			return
		}
		if strings.Contains(r.URL.Path, "asn") {
			_, _ = w.Write(asnBytes)
		} else {
			_, _ = w.Write(cityBytes)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	cityPath := filepath.Join(dir, "City.mmdb")
	asnPath := filepath.Join(dir, "ASN.mmdb")
	gm := NewGeoIPManager()
	// 1. Default strict enforcement checks
	if err := gm.UpdateFromURLs(context.Background(), "http://example.com/city.mmdb", "", "/var/lib/axonwall/geoip/City.mmdb", ""); err == nil {
		t.Fatalf("expected UpdateFromURLs to reject plain http:// scheme")
	}
	if err := gm.UpdateFromURLs(context.Background(), srv.URL+"/city.mmdb", "", "/var/lib/axonwall/geoip/City.mmdb", ""); err == nil {
		t.Fatalf("expected UpdateFromURLs default client to reject loopback IP")
	}
	if err := gm.UpdateFromURLs(context.Background(), "https://93.184.216.34/city.mmdb", "", cityPath, ""); err == nil {
		t.Fatalf("expected UpdateFromURLs default confinement to reject path outside /var/lib/axonwall")
	}

	// 2. Test-scoped TLS client & temp dir confinement check atomic valid reload + corrupt preservation
	gm.httpClient = srv.Client()
	gm.allowedBaseDirs = []string{dir}
	if err := gm.UpdateFromURLs(context.Background(), srv.URL+"/city.mmdb", srv.URL+"/asn.mmdb", cityPath, asnPath); err != nil {
		t.Fatalf("UpdateFromURLs valid payload failed: %v", err)
	}
	cLoaded, aLoaded, _ := gm.Status()
	if !cLoaded || !aLoaded {
		t.Fatalf("expected both City and ASN loaded after HTTP update, got city=%v asn=%v", cLoaded, aLoaded)
	}

	// IPv4-mapped IPv6 address must unmap cleanly in LookupCity
	if iso6, _, _, _, ok6 := gm.LookupCity(netip.MustParseAddr("::ffff:1.1.1.1")); !ok6 || iso6 != "AU" {
		t.Fatalf("expected ::ffff:1.1.1.1 unmapped lookup to resolve AU, got iso=%q ok=%v", iso6, ok6)
	}

	// Corrupt download must fail AND preserve previous valid readers
	serveCorrupt = true
	if err := gm.UpdateFromURLs(context.Background(), srv.URL+"/city.mmdb", "", cityPath, asnPath); err == nil {
		t.Fatalf("expected error for corrupt MMDB download")
	}
	if isoCheck, _, _, _, okCheck := gm.LookupCity(netip.MustParseAddr("1.1.1.1")); !okCheck || isoCheck != "AU" {
		t.Fatalf("expected existing City reader preserved after corrupt download")
	}
}

func TestFRRBgpJSONAndConntrackNAT(t *testing.T) {
	bgpJSON := []byte(`{
		"routes": {
			"1.1.1.0/24": [{"valid": true, "bestpath": true, "path": "64512 13335", "nexthops": [{"ip": "192.0.2.1"}]}],
			"1.1.0.0/16": [{"valid": true, "bestpath": true, "path": "64512 3356", "nexthops": [{"ip": "192.0.2.2"}]}]
		}
	}`)
	routes := ParseFRRBgpJSON(bgpJSON)
	if len(routes) != 2 || routes[0].Prefix.Bits() != 24 || routes[0].PeerAs != 64512 || len(routes[0].AsPath) != 2 {
		t.Fatalf("unexpected ParseFRRBgpJSON output (LPM / AsPath): %+v", routes)
	}

	// Test conntrack SNAT line parsing
	snatLine := "ipv4 2 tcp 6 431999 ESTABLISHED src=10.80.0.25 dst=1.1.1.1 sport=51234 dport=443 packets=18 bytes=12400 src=1.1.1.1 dst=203.0.113.10 sport=443 dport=61001 [ASSURED] mark=0"
	rec, hasNat, natInfo, ok := parseConntrackLine(snatLine, time.Now())
	if !ok || !hasNat {
		t.Fatalf("expected SNAT conntrack parse success, got ok=%v hasNat=%v", ok, hasNat)
	}
	if rec.PostNatSrcIP != "203.0.113.10" || rec.PostNatSrcPort != 61001 {
		t.Fatalf("expected PostNatSrc 203.0.113.10:61001, got %s:%d", rec.PostNatSrcIP, rec.PostNatSrcPort)
	}

	// Verify FlowEnricher combines BGP + conntrack NAT + static K3s pod map
	enr := NewFlowEnricher(nil, nil, nil)
	enr.mu.Lock()
	enr.cfg = NetFlowEnrichmentPayload{
		FrrBgpLookup:            true,
		NatConntrackCorrelation: true,
		K3sPodServiceTagging:    true,
		GeoIPAsn:                true,
	}
	enr.bgpRoutes = routes
	enr.k3sIPMap["10.42.0.15"] = k3sWorkloadInfo{Namespace: "prod", PodName: "api-7f8d9", Workload: "api"}
	enr.mu.Unlock()
	natKey := "6|10.42.0.15|55000|1.1.1.1|443"
	enr.UpdateConntrackNAT(map[string]natTupleInfo{natKey: natInfo})

	f := FlowRecord{
		SrcIP: "10.42.0.15", DstIP: "1.1.1.1", SrcPort: 55000, DstPort: 443, Protocol: 6,
	}
	enr.Enrich(&f)
	if f.PeerAs != 64512 || f.BgpNextHop != "192.0.2.1" {
		t.Fatalf("expected BGP enrichment (PeerAs=64512), got PeerAs=%d NextHop=%s", f.PeerAs, f.BgpNextHop)
	}
	if f.K3sNamespace != "prod" || f.K3sPodName != "api-7f8d9" {
		t.Fatalf("expected K3s pod attribution, got ns=%q pod=%q", f.K3sNamespace, f.K3sPodName)
	}
	if f.PostNatSrcIP != "203.0.113.10" || f.PostNatSrcPort != 61001 {
		t.Fatalf("expected NAT enrichment via UpdateConntrackNAT, got %+v", f)
	}
}

func TestClickHouseSQLCompilerAndSafety(t *testing.T) {
	ast, err := ParseFQL(`src=10.80.0.0/24 and (dst_port=443 or city~Chicago) and peer_as=13335 and not threat="'; DROP TABLE netflow_flows;--"`)
	if err != nil {
		t.Fatalf("ParseFQL failed: %v", err)
	}
	whereSQL, args, err := CompileFQLToClickHouseSQL(ast)
	if err != nil {
		t.Fatalf("CompileFQLToClickHouseSQL failed: %v", err)
	}
	if strings.Contains(whereSQL, "DROP TABLE") || strings.Contains(whereSQL, "10.80.0.0/24") {
		t.Fatalf("user values leaked directly into compiled SQL: %s", whereSQL)
	}
	if !strings.Contains(whereSQL, "isIPAddressInRange(src_ip, ?)") || !strings.Contains(whereSQL, "peer_as = ?") {
		t.Fatalf("unexpected compiled ClickHouse WHERE SQL: %s", whereSQL)
	}
	if len(args) != 6 {
		t.Fatalf("expected 6 positional bind args, got %d (%v)", len(args), args)
	}

	// Verify IPv6 CIDR uses isIPv6String
	ast6, err := ParseFQL(`src=2001:db8::/32`)
	if err != nil {
		t.Fatalf("ParseFQL IPv6 failed: %v", err)
	}
	sql6, args6, err := CompileFQLToClickHouseSQL(ast6)
	if err != nil || !strings.Contains(sql6, "isIPv6String(src_ip)") || len(args6) != 1 {
		t.Fatalf("unexpected IPv6 SQL compilation: sql=%q args=%v err=%v", sql6, args6, err)
	}
}

func TestRollupPersistenceAndQuery(t *testing.T) {
	dir := t.TempDir()
	fs := NewFlowStore(NetFlowStoragePayload{
		Mode:           "local",
		DataDir:        dir,
		RetentionHours: 48,
		HotRingSize:    1000,
		Compression:    "zstd",
	})
	// Ingest historical flow >8h ago so compactRollupsLocked promotes to 5m bucket & survives Flush without hotRing overlap
	ts8h := time.Now().Add(-8 * time.Hour).UnixMilli()
	fs.Ingest([]FlowRecord{
		{
			ID: "r-old-1", TimestampMs: ts8h, SrcIP: "10.80.0.10", DstIP: "1.1.1.1",
			Protocol: 6, ProtocolName: "TCP", AppName: "HTTPS", ExporterIP: "10.80.0.1",
			InIfName: "eth1", SrcCountry: "LAN", DstCountry: "US", Bytes: 2_000_000, Packets: 1500,
		},
	})
	if err := fs.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// Reload fresh store from same DataDir (simulate daemon restart with empty hotRing & deleted chunks)
	fs.mu.Lock()
	for _, c := range fs.chunks {
		_ = os.Remove(c.Path)
	}
	_ = os.Remove(fs.manifestPathLocked())
	fs.mu.Unlock()

	reloaded := NewFlowStore(NetFlowStoragePayload{
		Mode:           "local",
		DataDir:        dir,
		RetentionHours: 48,
		HotRingSize:    1000,
		Compression:    "zstd",
	})
	res := reloaded.Query(FlowQueryRequest{StartMs: ts8h - 3600_000, EndMs: ts8h + 3600_000})
	if res.Engine != "local-rollups" || res.TotalBytes != 2_000_000 || len(res.Timeseries) == 0 {
		t.Fatalf("expected persisted rollup query result, got engine=%q totalBytes=%d tsLen=%d", res.Engine, res.TotalBytes, len(res.Timeseries))
	}
}

func TestBidirectionalSessionStitchingAndHeatmaps(t *testing.T) {
	nowMs := time.Now().UnixMilli()
	flows := []FlowRecord{
		// Symmetric HTTPS flow
		{
			TimestampMs: nowMs - 2000, FlowStartMs: nowMs - 4000,
			SrcIP: "10.80.0.20", DstIP: "1.1.1.1", SrcPort: 50000, DstPort: 443,
			Protocol: 6, ProtocolName: "TCP", TCPFlags: 0x02,
			SrcCountry: "LAN", DstCountry: "US", SrcLat: 39.8, SrcLon: -98.5, DstLat: 37.7, DstLon: -97.8,
			Bytes: 1500, Packets: 5, RttMs: 12.5, Retransmits: 1,
		},
		{
			TimestampMs: nowMs - 1000, FlowStartMs: nowMs - 3900,
			SrcIP: "1.1.1.1", DstIP: "10.80.0.20", SrcPort: 443, DstPort: 50000,
			Protocol: 6, ProtocolName: "TCP", TCPFlags: 0x12,
			Bytes: 45000, Packets: 32, RttMs: 14.5,
		},
		// Unanswered SYN scan flow
		{
			TimestampMs: nowMs - 500, FlowStartMs: nowMs - 500,
			SrcIP: "198.51.100.9", DstIP: "10.80.0.20", SrcPort: 61111, DstPort: 22,
			Protocol: 6, ProtocolName: "TCP", TCPFlags: 0x02, ThreatMatch: "blocklist",
			Bytes: 64, Packets: 1,
		},
	}

	sessions := StitchBidirectionalSessions(flows, 120_000)
	if len(sessions) != 2 {
		t.Fatalf("expected 2 stitched sessions, got %d", len(sessions))
	}
	var httpsSess, synSess FlowSessionRecord
	for _, s := range sessions {
		if s.ResponderPort == 443 {
			httpsSess = s
		} else {
			synSess = s
		}
	}
	if httpsSess.BytesFwd != 1500 || httpsSess.BytesRev != 45000 || httpsSess.UnansweredSyn {
		t.Fatalf("unexpected HTTPS stitched session: %+v", httpsSess)
	}
	if httpsSess.AsymmetryRatio < 0.9 || httpsSess.TotalRetransmits != 1 || math.Abs(httpsSess.AvgRttMs-13.5) > 0.1 {
		t.Fatalf("unexpected asymmetry/NPM stats on HTTPS session: %+v", httpsSess)
	}
	if !synSess.UnansweredSyn || synSess.PacketsRev != 0 {
		t.Fatalf("expected UnansweredSyn=true on scan session: %+v", synSess)
	}

	topSrc := []FlowTopEntry{{Key: "1.1.1.1"}, {Key: "10.80.0.20"}, {Key: "198.51.100.9"}}
	topDst := []FlowTopEntry{{Key: "1.1.1.1"}, {Key: "10.80.0.20"}}
	hm := BuildHostHeatmap(flows, topSrc, topDst)
	if hm == nil || hm.MaxValue != 45000 {
		t.Fatalf("unexpected HostHeatmap: %+v", hm)
	}
	arcs := BuildGeoArcs(flows)
	if len(arcs) != 1 || arcs[0].SrcCountry != "LAN" || arcs[0].DstCountry != "US" {
		t.Fatalf("unexpected GeoArcs: %+v", arcs)
	}
}

func TestPercentileReportAndRenderers(t *testing.T) {
	samples := make([]float64, 20)
	for i := 0; i < 20; i++ {
		samples[i] = float64((i + 1) * 100)
	}
	p95, p99, peak, avg := Compute95thPercentile(samples)
	if p95 != 1900 || p99 != 2000 || peak != 2000 || avg != 1050 {
		t.Fatalf("unexpected percentile math: p95=%v p99=%v peak=%v avg=%v", p95, p99, peak, avg)
	}

	fs := NewFlowStore(NetFlowStoragePayload{Mode: "local", DataDir: t.TempDir(), HotRingSize: 200})
	nowMs := time.Now().UnixMilli()
	fs.Ingest([]FlowRecord{
		{ID: "p1", TimestampMs: nowMs - 600_000, InIfName: "eth0", ExporterIP: "10.80.0.1", Bytes: 3_000_000, Packets: 2000},
		{ID: "p2", TimestampMs: nowMs, InIfName: "eth0", ExporterIP: "10.80.0.1", Bytes: 30_000_000, Packets: 20000},
	})
	rep := GeneratePercentileReport(fs, NetFlowReportRequest{RangeDays: 1, GroupBy: "interface", Format: "markdown"})
	if len(rep.Rows) != 1 || rep.Rows[0].GroupKey != "eth0" || !strings.Contains(rep.Rendered, "| eth0 |") {
		t.Fatalf("unexpected markdown percentile report: %+v", rep)
	}
	csvOut := RenderReportCSV(&rep)
	if !strings.Contains(csvOut, "Group,P95_Bps") || !strings.Contains(csvOut, "eth0,") {
		t.Fatalf("unexpected CSV output: %s", csvOut)
	}
}

func TestBaselineEWMAZScoreAndFirstSeenPair(t *testing.T) {
	dir := t.TempDir()
	be := NewBaselineEngine(dir)
	ts := time.Date(2026, 11, 23, 14, 0, 0, 0, time.UTC)

	// Cold warmup < 12 samples must not trigger warmedUp=true
	for i := 0; i < baselineWarmupSamples; i++ {
		_, _, warmed := be.ObserveAndScore("10.80.0.50", ts, 10_000_000+float64((i%3)*200_000), 1000)
		if warmed {
			t.Fatalf("expected warmedUp=false during warmup iteration %d", i)
		}
	}
	// Normal observation should stay well below Z=3.5
	zBps, _, warmed := be.ObserveAndScore("10.80.0.50", ts, 10_100_000, 1005)
	if !warmed || zBps >= 3.5 {
		t.Fatalf("expected normal traffic z<3.5 after warmup, got warmed=%v z=%.2f", warmed, zBps)
	}
	// 100x spike must exceed Z=3.5
	zSpike, _, warmedSpike := be.ObserveAndScore("10.80.0.50", ts, 1_000_000_000, 90000)
	if !warmedSpike || zSpike < 3.5 {
		t.Fatalf("expected spike detection Z>=3.5, got warmed=%v z=%.2f", warmedSpike, zSpike)
	}

	if !be.CheckPair("10.80.0.0/24->AS13335", ts.Unix()) {
		t.Fatalf("expected CheckPair true on first sighting")
	}
	if be.CheckPair("10.80.0.0/24->AS13335", ts.Unix()+5) {
		t.Fatalf("expected CheckPair false on repeat sighting")
	}

	if err := be.Save(""); err != nil {
		t.Fatalf("BaselineEngine.Save failed: %v", err)
	}
	reloaded := NewBaselineEngine(dir)
	if reloaded.Count() != 1 || reloaded.CheckPair("10.80.0.0/24->AS13335", ts.Unix()+10) {
		t.Fatalf("expected persisted baseline entities and seenPairs after reload")
	}
}

func generateTestCAPair(t *testing.T, dir string) (caPath, srvCertPath, srvKeyPath, cliCertPath, cliKeyPath string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "axonwall-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create test CA: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPath = filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0644)

	signLeaf := func(prefix string, serial int64, ku x509.ExtKeyUsage) (string, string) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: prefix},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{ku},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		if err != nil {
			t.Fatalf("sign %s leaf: %v", prefix, err)
		}
		kDER, _ := x509.MarshalECPrivateKey(k)
		cPath := filepath.Join(dir, prefix+".crt")
		kPath := filepath.Join(dir, prefix+".key")
		_ = os.WriteFile(cPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
		_ = os.WriteFile(kPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kDER}), 0600)
		return cPath, kPath
	}

	srvCertPath, srvKeyPath = signLeaf("server", 2, x509.ExtKeyUsageServerAuth)
	cliCertPath, cliKeyPath = signLeaf("client", 3, x509.ExtKeyUsageClientAuth)
	return
}

func TestNetFlowDualStackIPv6IPFIXAndTLS13MTLS(t *testing.T) {
	// 1. Dual-stack IPv4 NAT + IPv6 (Template 257) + PEN 62999 RTT/retransmits wire round-trip
	dec := NewFlowDecoder()
	now := time.Now()
	mixed := []FlowRecord{
		{
			FlowStartMs: now.Add(-time.Second).UnixMilli(), TimestampMs: now.UnixMilli(),
			SrcIP: "10.80.0.15", DstIP: "1.1.1.1", SrcPort: 50123, DstPort: 443, Protocol: 6,
			PostNatSrcIP: "203.0.113.5", PostNatSrcPort: 62001, Bytes: 4096, Packets: 10,
			RttMs: 8.25, Retransmits: 2,
		},
		{
			FlowStartMs: now.Add(-time.Second).UnixMilli(), TimestampMs: now.UnixMilli(),
			SrcIP: "2001:db8::1", DstIP: "2001:db8::2", SrcPort: 44444, DstPort: 8443, Protocol: 17,
			Bytes: 8192, Packets: 16, RttMs: 15.5, Retransmits: 0,
		},
	}
	pkt := EncodeIPFIXPacket(99, 1, true, mixed)
	ver, decoded, _, err := dec.DecodePacket("127.0.0.1", pkt, now)
	if err != nil || ver != "ipfix" || len(decoded) != 2 {
		t.Fatalf("dual-stack IPFIX decode failed: ver=%q len=%d err=%v", ver, len(decoded), err)
	}
	if decoded[0].PostNatSrcIP != "203.0.113.5" || decoded[0].Retransmits != 2 || math.Abs(decoded[0].RttMs-8.25) > 0.01 {
		t.Fatalf("IPv4 NAT/NPM decode mismatch: %+v", decoded[0])
	}
	if decoded[1].SrcIP != "2001:db8::1" || decoded[1].DstIP != "2001:db8::2" || math.Abs(decoded[1].RttMs-15.5) > 0.01 {
		t.Fatalf("IPv6 Template 257 decode mismatch: %+v", decoded[1])
	}

	// 2. TLS 1.3 mTLS listener <-> client end-to-end delivery + untrusted cert rejection
	certDir := t.TempDir()
	caPath, srvCert, srvKey, cliCert, cliKey := generateTestCAPair(t, certDir)

	// Pick free port
	lnProbe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alloc ephemeral port: %v", err)
	}
	port := lnProbe.Addr().(*net.TCPAddr).Port
	_ = lnProbe.Close()

	mgr := NewNetFlowManager(t.TempDir(), nil, nil, nil, nil, nil)
	bundle := NetFlowRuntimeBundle{
		Enabled:       true,
		LocalHostname: "test-tls-host",
		Config: NetFlowConfigPayload{
			Enabled: true,
			Listeners: []NetFlowListenerPayload{
				{
					ID:          "tls-listener",
					Name:        "TLS 1.3 IPFIX",
					Enabled:     true,
					Protocol:    "ipfix",
					Transport:   "tls",
					BindAddress: "127.0.0.1",
					Port:        port,
					Workers:     1,
					TLS: &NetFlowTlsConfigPayload{
						UseHaPki:          false,
						RequireClientCert: true,
						CAPath:            caPath,
						CertPath:          srvCert,
						KeyPath:           srvKey,
					},
				},
			},
			Storage: NetFlowStoragePayload{Mode: "local", DataDir: t.TempDir(), HotRingSize: 500},
		},
	}
	rawCfg, _ := json.Marshal(bundle)
	if err := mgr.ApplyConfig(rawCfg); err != nil {
		t.Fatalf("ApplyConfig TLS listener failed: %v", err)
	}
	defer mgr.Stop()

	// Valid mTLS client sends IPFIX packet
	err = sendFlowDatagram("tls", "127.0.0.1", port, &NetFlowTlsConfigPayload{
		UseHaPki: false, CAPath: caPath, CertPath: cliCert, KeyPath: cliKey,
	}, pkt)
	if err != nil {
		t.Fatalf("valid mTLS sendFlowDatagram failed: %v", err)
	}

	// Wait briefly for serveTCP goroutine to process packet
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mgr.GetStatus().FlowsIngested >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st := mgr.GetStatus(); st.FlowsIngested < 2 {
		t.Fatalf("expected >= 2 ingested flows over TLS 1.3 mTLS, got %d (lastErr=%q)", st.FlowsIngested, st.LastError)
	}

	// Untrusted client cert signed by rogue CA must be rejected
	rogueDir := t.TempDir()
	_, _, _, rogueCert, rogueKey := generateTestCAPair(t, rogueDir)
	if err := sendFlowDatagram("tls", "127.0.0.1", port, &NetFlowTlsConfigPayload{
		UseHaPki: false, CAPath: caPath, CertPath: rogueCert, KeyPath: rogueKey,
	}, pkt); err == nil {
		// In TLS 1.3, handshake failure may surface on first Write or immediate server close; verify no extra flows arrive
		time.Sleep(80 * time.Millisecond)
		if mgr.GetStatus().FlowsIngested > 2 {
			t.Fatalf("rogue client certificate bypassed mTLS server verification")
		}
	}
}

func TestNetFlowFederationAndPrometheusMetrics(t *testing.T) {
	// Mock peer returning 1 remote flow
	peerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/netflow/query" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"data": FlowQueryResponse{
				Timestamp:         time.Now().UTC().Format(time.RFC3339),
				TotalMatchedFlows: 1,
				TotalBytes:        99000,
				Flows: []FlowRecord{
					{
						ID:           "remote-1",
						TimestampMs:  time.Now().UnixMilli(),
						Version:      "ipfix",
						ExporterIP:   "10.80.0.213",
						SrcIP:        "10.99.0.5",
						DstIP:        "8.8.8.8",
						DstPort:      53,
						Protocol:     17,
						ProtocolName: "UDP",
						Bytes:        99000,
						Packets:      100,
					},
				},
			},
		})
	}))
	defer peerSrv.Close()

	// Initialize TopologyManager with mock peer + 1 unreachable peer
	topoDir := t.TempDir()
	topoMgr := NewTopologyManager(topoDir, nil, nil, nil, nil, nil)
	topoBundle := TopologyRuntimeBundle{
		Enabled: true,
		Config: TopologyConfigPayload{
			Enabled: true,
			Peers: []TopologyPeerHostPayload{
				{ID: "peer-1", Name: "suburban-hello", Role: "edge", APIURL: peerSrv.URL, Enabled: true},
				{ID: "peer-down", Name: "offline-peer", Role: "edge", APIURL: "http://127.0.0.1:1", Enabled: true},
			},
		},
	}
	rawTopo, _ := json.Marshal(topoBundle)
	_ = os.WriteFile(filepath.Join(topoDir, "config.json"), rawTopo, 0600)

	mgr := NewNetFlowManager(t.TempDir(), nil, nil, nil, nil, nil)
	mgr.SetTopologyManager(topoMgr)
	mgr.store = NewFlowStore(NetFlowStoragePayload{Mode: "local", DataDir: t.TempDir(), HotRingSize: 200})
	mgr.bundle = &NetFlowRuntimeBundle{
		Enabled:       true,
		LocalHostname: "klaxon",
	}
	_, _ = mgr.InjectTestBurst("ipfix", 2)

	res := mgr.QueryFlows(FlowQueryRequest{RangeMinutes: 60, Scope: "fleet", Limit: 50})
	if res.Engine != "federated" {
		t.Fatalf("expected federated engine, got %q", res.Engine)
	}
	if len(res.PeerErrors) != 1 || res.PeerErrors[0].PeerID != "peer-down" {
		t.Fatalf("expected 1 PeerError for peer-down, got %+v", res.PeerErrors)
	}
	foundRemote := false
	for _, f := range res.Flows {
		if f.HostName == "suburban-hello" && f.Bytes == 99000 {
			foundRemote = true
		}
	}
	if !foundRemote {
		t.Fatalf("expected remote flow tagged with HostName=suburban-hello in federated result")
	}

	var promBuf bytes.Buffer
	mgr.WritePrometheusMetrics(&promBuf)
	prom := promBuf.String()
	for _, needle := range []string{
		"axonwall_netflow_collector_up",
		"axonwall_netflow_flows_ingested_total",
		"axonwall_netflow_bytes_ingested_total",
		"axonwall_netflow_exporter_flows_total",
	} {
		if !strings.Contains(prom, needle) {
			t.Fatalf("missing metric %q in Prometheus output:\n%s", needle, prom)
		}
	}
}

func TestIPFIXTemplateWithdrawalPartialAndOverflowSafety(t *testing.T) {
	dec := NewFlowDecoder()
	sample := []FlowRecord{{
		TimestampMs: time.Now().UnixMilli(),
		SrcIP:       "10.80.0.10",
		DstIP:       "1.1.1.1",
		SrcPort:     1234,
		DstPort:     443,
		Protocol:    6,
		Bytes:       500,
		Packets:     5,
	}}
	pkt := EncodeIPFIXPacket(10, 1, true, sample)
	if _, flows, _, err := dec.DecodePacket("10.80.0.1", pkt, time.Now()); err != nil || len(flows) != 1 {
		t.Fatalf("seed IPFIX packet failed: err=%v len=%d", err, len(flows))
	}
	if len(dec.GetTemplates()) != 1 {
		t.Fatalf("expected 1 cached template, got %d", len(dec.GetTemplates()))
	}

	// Bogus fieldCount=65535 on 8-byte template body must NOT panic/alloc huge slice or cache template
	badBody := []byte{1, 1, 0xFF, 0xFF, 0, 8, 0, 4}
	dec.parseIPFIXTemplates("10.80.0.9", 10, badBody, false, time.Now())
	if len(dec.GetTemplates()) != 1 {
		t.Fatalf("bogus oversized fieldCount must be rejected, got templates=%d", len(dec.GetTemplates()))
	}

	// Partial enterprise field truncated before 4-byte enterprise ID must be discarded
	partialBody := []byte{1, 2, 0, 1, 0x80, 1, 0, 4}
	dec.parseIPFIXTemplates("10.80.0.9", 10, partialBody, false, time.Now())
	if len(dec.GetTemplates()) != 1 {
		t.Fatalf("partial truncated template must be discarded, got templates=%d", len(dec.GetTemplates()))
	}

	// RFC 7011 template withdrawal (fieldCount=0) removes matching template
	tid := dec.GetTemplates()[0].TemplateID
	withdrawBody := make([]byte, 4)
	binary.BigEndian.PutUint16(withdrawBody[0:2], tid)
	binary.BigEndian.PutUint16(withdrawBody[2:4], 0)
	dec.parseIPFIXTemplates("10.80.0.1", 10, withdrawBody, false, time.Now())
	if len(dec.GetTemplates()) != 0 {
		t.Fatalf("expected template withdrawal to delete template %d, got %d remaining", tid, len(dec.GetTemplates()))
	}
}

func TestMMDBNodeCountOverflowRejected(t *testing.T) {
	// Construct tiny payload with forged huge node_count causing uint64 multiplication overflow if unchecked
	var meta bytes.Buffer
	meta.WriteByte((7 << 5) | 2) // map of 2 entries
	writeStr := func(s string) {
		meta.WriteByte(byte((2 << 5) | len(s)))
		meta.WriteString(s)
	}
	writeStr("node_count")
	meta.WriteByte((6 << 5) | 8) // uint64 (8 bytes)
	_ = binary.Write(&meta, binary.BigEndian, uint64(0x4000000000000001))
	writeStr("record_size")
	meta.WriteByte((5 << 5) | 1) // uint16 (1 byte)
	meta.WriteByte(24)

	raw := append([]byte{0, 0, 0, 0}, mmdbMetadataMarker...)
	raw = append(raw, meta.Bytes()...)
	if _, err := OpenMMDBBytes(raw); err == nil {
		t.Fatalf("expected OpenMMDBBytes to reject overflowing node_count")
	}
}

func TestFQLCompositeNotEqualSemanticsAndCHSQL(t *testing.T) {
	rec := FlowRecord{
		SrcIP: "10.0.0.1", DstIP: "8.8.8.8",
		InIfName: "eth0", OutIfName: "wan0",
		SrcAsn: 64512, DstAsn: 15169,
		SrcCountry: "LAN", DstCountry: "US",
		SrcCity: "Local", DstCity: "Chicago",
		SrcHost: "gw", DstHost: "dns", HostName: "axon-1",
	}
	for _, expr := range []string{
		"ip!=8.8.8.8",
		"if!=wan0",
		"asn!=15169",
		"country!=US",
		"city!=Chicago",
		"host!=axon-1",
	} {
		ast, err := ParseFQL(expr)
		if err != nil {
			t.Fatalf("ParseFQL(%q) error: %v", expr, err)
		}
		if ast.Eval(&rec) {
			t.Fatalf("expected local Eval(%q) to return false when one side matches excluded value", expr)
		}
		sqlStr, _, sqlErr := CompileFQLToClickHouseSQL(ast)
		if sqlErr != nil {
			t.Fatalf("CompileFQLToClickHouseSQL(%q) error: %v", expr, sqlErr)
		}
		if !strings.Contains(sqlStr, " AND ") || strings.Contains(sqlStr, " OR ") {
			t.Fatalf("expected composite != SQL for %q to join predicates with AND, got %q", expr, sqlStr)
		}
	}
}

func TestFlowEnricherStopAndEnrichSafe(t *testing.T) {
	enr := NewFlowEnricher(nil, nil, nil)
	enr.Stop()
	// Idempotent Stop and non-panicking Enrich after Stop
	enr.Stop()
	f := FlowRecord{SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Protocol: 6}
	enr.Enrich(&f)
}
