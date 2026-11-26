package engine

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/klauspost/compress/zstd"
)

type chunkManifestEntry struct {
	Path     string `json:"path"`
	MinTsMs  int64  `json:"minTsMs"`
	MaxTsMs  int64  `json:"maxTsMs"`
	Count    int    `json:"count"`
	Bytes    uint64 `json:"bytes"`
	FileSize int64  `json:"fileSize"`
}

type rollupBucket struct {
	TimestampMs int64             `json:"timestampMs"`
	Bytes       uint64            `json:"bytes"`
	Packets     uint64            `json:"packets"`
	Flows       int               `json:"flows"`
	ByProto     map[string]uint64 `json:"byProto,omitempty"`
	ByExporter  map[string]uint64 `json:"byExporter,omitempty"`
	ByInterface map[string]uint64 `json:"byInterface,omitempty"`
	ByApp       map[string]uint64 `json:"byApp,omitempty"`
	ByCountry   map[string]uint64 `json:"byCountry,omitempty"`
	ByDirection map[string]uint64 `json:"byDirection,omitempty"`
}

type persistedRollupsFile struct {
	Rollups1m map[int64]*rollupBucket `json:"rollups1m"`
	Rollups5m map[int64]*rollupBucket `json:"rollups5m"`
	Rollups1h map[int64]*rollupBucket `json:"rollups1h"`
}

type FlowStore struct {
	mu           sync.RWMutex
	cfg          NetFlowStoragePayload
	hotRing      []FlowRecord
	hotHead      int
	hotCount     int
	pendingFlush []FlowRecord
	pendingCH    []FlowRecord
	chunks       []chunkManifestEntry
	rollups1m    map[int64]*rollupBucket
	rollups5m    map[int64]*rollupBucket
	rollups1h    map[int64]*rollupBucket
	chGen        uint64
	chConn       driver.Conn
	chConnected  bool
	chTableFQN   string
}

const maxFlowStorePending = 100000

func capFlowQueue(q []FlowRecord, max int) []FlowRecord {
	if max <= 0 || len(q) <= max {
		return q
	}
	drop := len(q) - max
	trimmed := make([]FlowRecord, max)
	copy(trimmed, q[drop:])
	return trimmed
}

func NewFlowStore(initial NetFlowStoragePayload) *FlowStore {
	if initial.HotRingSize <= 0 {
		initial.HotRingSize = 50000
	}
	if initial.DataDir == "" {
		initial.DataDir = "/var/lib/axonwall/netflow"
	}
	if initial.Compression == "" {
		initial.Compression = "zstd"
	}
	if initial.Mode == "" {
		initial.Mode = "local"
	}
	fs := &FlowStore{
		cfg:       initial,
		hotRing:   make([]FlowRecord, initial.HotRingSize),
		rollups1m: make(map[int64]*rollupBucket),
		rollups5m: make(map[int64]*rollupBucket),
		rollups1h: make(map[int64]*rollupBucket),
	}
	fs.loadManifest()
	return fs
}

func (s *FlowStore) Configure(cfg NetFlowStoragePayload) {
	if cfg.HotRingSize < 100 {
		cfg.HotRingSize = 50000
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "/var/lib/axonwall/netflow"
	}
	if cfg.Compression == "" {
		cfg.Compression = "zstd"
	}
	if cfg.Mode == "" {
		cfg.Mode = "local"
	}
	s.mu.Lock()
	resize := cfg.HotRingSize != cap(s.hotRing)
	dirChanged := cfg.DataDir != s.cfg.DataDir
	s.cfg = cfg
	if resize {
		existing := s.snapshotHotLocked()
		s.hotRing = make([]FlowRecord, cfg.HotRingSize)
		s.hotHead = 0
		s.hotCount = 0
		for _, rec := range existing {
			s.pushHotLocked(rec)
		}
	}
	s.chGen++
	chGen := s.chGen
	if s.chConn != nil && (!cfg.ClickHouse.Enabled || cfg.Mode == "local") {
		_ = s.chConn.Close()
		s.chConn = nil
		s.chConnected = false
		s.chTableFQN = ""
	}
	s.mu.Unlock()

	if dirChanged {
		s.loadManifest()
	}
	if cfg.ClickHouse.Enabled && (cfg.Mode == "clickhouse" || cfg.Mode == "hybrid") {
		go s.initClickHouse(cfg.ClickHouse, chGen)
	}
}

func (s *FlowStore) initClickHouse(ch NetFlowClickHousePayload, gen uint64) {
	addr := strings.TrimSpace(ch.URL)
	proto := clickhouse.Native
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		proto = clickhouse.HTTP
		if u, err := url.Parse(addr); err == nil && u.Host != "" {
			addr = u.Host
		}
	}
	if addr == "" {
		addr = "127.0.0.1:8123"
		proto = clickhouse.HTTP
	}
	db := ch.Database
	if db == "" {
		db = "axonwall"
	}
	tbl := ch.Table
	if tbl == "" {
		tbl = "netflow_flows"
	}
	dbSafe := sanitizeClickHouseIdentWithDefault(db, "axonwall")
	tableSafe := sanitizeClickHouseIdentWithDefault(tbl, "netflow_flows")
	password := ch.Password
	if password == "" {
		password = os.Getenv("CLICKHOUSE_PASSWORD")
	}
	ttlDays := ch.TTLDays
	if ttlDays <= 0 {
		ttlDays = 30
	}

	if dbSafe != "default" {
		if bootConn, bootErr := clickhouse.Open(&clickhouse.Options{
			Addr:     []string{addr},
			Protocol: proto,
			Auth: clickhouse.Auth{
				Database: "default",
				Username: ch.Username,
				Password: password,
			},
			DialTimeout: 3 * time.Second,
			MaxOpenConns: 1,
		}); bootErr == nil {
			bCtx, bCancel := context.WithTimeout(context.Background(), 4*time.Second)
			if bootConn.Ping(bCtx) == nil {
				_ = bootConn.Exec(bCtx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", dbSafe))
			}
			bCancel()
			_ = bootConn.Close()
		}
	}

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr:     []string{addr},
		Protocol: proto,
		Auth: clickhouse.Auth{
			Database: dbSafe,
			Username: ch.Username,
			Password: password,
		},
		DialTimeout: 3 * time.Second,
		MaxOpenConns: 4,
		MaxIdleConns: 2,
	})
	if err != nil {
		log.Printf("[NetFlow] ClickHouse open warning (%s): %v", addr, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		_ = conn.Close()
		log.Printf("[NetFlow] ClickHouse ping warning (%s): %v", addr, err)
		return
	}
	if err := conn.Exec(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", dbSafe)); err != nil {
		_ = conn.Close()
		log.Printf("[NetFlow] ClickHouse database init warning (%s): %v", dbSafe, err)
		return
	}
	ddl := fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s.%s (
		timestamp DateTime64(3),
		version LowCardinality(String),
		exporter_ip String,
		node_id LowCardinality(String),
		node_name LowCardinality(String),
		src_ip String,
		dst_ip String,
		src_port UInt16,
		dst_port UInt16,
		protocol UInt8,
		app_name LowCardinality(String),
		direction LowCardinality(String),
		in_if_name LowCardinality(String),
		out_if_name LowCardinality(String),
		vlan_id UInt16,
		bytes UInt64,
		packets UInt64,
		bps Float64,
		src_country LowCardinality(String),
		dst_country LowCardinality(String),
		threat_match String,
		src_asn UInt32,
		dst_asn UInt32,
		src_city LowCardinality(String),
		dst_city LowCardinality(String),
		peer_as UInt32,
		post_nat_src_ip String,
		post_nat_dst_ip String,
		post_nat_src_port UInt16,
		post_nat_dst_port UInt16,
		tcp_flags UInt8,
		k3s_namespace LowCardinality(String),
		k3s_workload String,
		rtt_ms Float64,
		retransmits UInt32
	) ENGINE = MergeTree()
	ORDER BY (timestamp, src_ip, dst_ip, dst_port)
	TTL toDateTime(timestamp) + INTERVAL %d DAY
	`, dbSafe, tableSafe, ttlDays)
	if err := conn.Exec(ctx, ddl); err != nil {
		_ = conn.Close()
		log.Printf("[NetFlow] ClickHouse schema init warning: %v", err)
		return
	}
	for _, colDef := range []string{
		"node_id LowCardinality(String)", "node_name LowCardinality(String)",
		"src_asn UInt32", "dst_asn UInt32",
		"src_city LowCardinality(String)", "dst_city LowCardinality(String)",
		"peer_as UInt32",
		"post_nat_src_ip String", "post_nat_dst_ip String",
		"post_nat_src_port UInt16", "post_nat_dst_port UInt16",
		"tcp_flags UInt8",
		"k3s_namespace LowCardinality(String)", "k3s_workload String",
		"rtt_ms Float64", "retransmits UInt32",
	} {
		_ = conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s.%s ADD COLUMN IF NOT EXISTS %s", dbSafe, tableSafe, colDef))
	}

	s.mu.Lock()
	if s.chGen != gen {
		s.mu.Unlock()
		_ = conn.Close()
		return
	}
	if s.chConn != nil {
		_ = s.chConn.Close()
	}
	s.chConn = conn
	s.chConnected = true
	s.chTableFQN = fmt.Sprintf("%s.%s", dbSafe, tableSafe)
	s.mu.Unlock()
}

func sanitizeClickHouseIdentWithDefault(s, fallback string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return fallback
	}
	return b.String()
}

func sanitizeClickHouseIdent(s string) string {
	return sanitizeClickHouseIdentWithDefault(s, "netflow_flows")
}

func (s *FlowStore) Ingest(flows []FlowRecord) {
	if len(flows) == 0 {
		return
	}
	s.mu.Lock()
	for _, f := range flows {
		if f.TimestampMs <= 0 {
			f.TimestampMs = time.Now().UnixMilli()
		}
		if f.Timestamp == "" {
			f.Timestamp = time.UnixMilli(f.TimestampMs).UTC().Format(time.RFC3339Nano)
		}
		s.pushHotLocked(f)
		if s.cfg.Mode != "clickhouse" {
			s.pendingFlush = capFlowQueue(append(s.pendingFlush, f), maxFlowStorePending)
		}
		if s.chConnected && s.chConn != nil && (s.cfg.Mode == "clickhouse" || s.cfg.Mode == "hybrid") {
			s.pendingCH = capFlowQueue(append(s.pendingCH, f), maxFlowStorePending)
		}
		bucketMs := (f.TimestampMs / 60000) * 60000
		rb := s.rollups1m[bucketMs]
		if rb == nil {
			rb = newRollupBucket(bucketMs)
			s.rollups1m[bucketMs] = rb
		}
		accumulateIntoRollup(rb, &f)
	}
	s.compactRollupsLocked()
	s.mu.Unlock()
}

func newRollupBucket(tsMs int64) *rollupBucket {
	return &rollupBucket{
		TimestampMs: tsMs,
		ByProto:     make(map[string]uint64),
		ByExporter:  make(map[string]uint64),
		ByInterface: make(map[string]uint64),
		ByApp:       make(map[string]uint64),
		ByCountry:   make(map[string]uint64),
		ByDirection: make(map[string]uint64),
	}
}

func accumulateIntoRollup(rb *rollupBucket, f *FlowRecord) {
	rb.Bytes += f.Bytes
	rb.Packets += f.Packets
	rb.Flows++
	if rb.ByProto == nil {
		rb.ByProto = make(map[string]uint64)
	}
	if rb.ByExporter == nil {
		rb.ByExporter = make(map[string]uint64)
	}
	if rb.ByInterface == nil {
		rb.ByInterface = make(map[string]uint64)
	}
	if rb.ByApp == nil {
		rb.ByApp = make(map[string]uint64)
	}
	if rb.ByCountry == nil {
		rb.ByCountry = make(map[string]uint64)
	}
	if rb.ByDirection == nil {
		rb.ByDirection = make(map[string]uint64)
	}
	rb.ByProto[firstNonEmpty(f.ProtocolName, "OTHER")] += f.Bytes
	rb.ByExporter[firstNonEmpty(f.ExporterName, f.ExporterIP)] += f.Bytes
	if ifn := firstNonEmpty(f.InIfName, f.OutIfName); ifn != "" {
		rb.ByInterface[ifn] += f.Bytes
	}
	rb.ByApp[firstNonEmpty(f.AppName, f.ProtocolName)] += f.Bytes
	if c := firstNonEmpty(f.DstCountry, f.SrcCountry); c != "" {
		rb.ByCountry[c] += f.Bytes
	}
	if f.Direction != "" {
		rb.ByDirection[f.Direction] += f.Bytes
	}
}

func mergeRollupBucket(dst, src *rollupBucket) {
	dst.Bytes += src.Bytes
	dst.Packets += src.Packets
	dst.Flows += src.Flows
	mergeMap := func(d *map[string]uint64, s map[string]uint64) {
		if len(s) == 0 {
			return
		}
		if *d == nil {
			*d = make(map[string]uint64)
		}
		for k, v := range s {
			(*d)[k] += v
		}
	}
	mergeMap(&dst.ByProto, src.ByProto)
	mergeMap(&dst.ByExporter, src.ByExporter)
	mergeMap(&dst.ByInterface, src.ByInterface)
	mergeMap(&dst.ByApp, src.ByApp)
	mergeMap(&dst.ByCountry, src.ByCountry)
	mergeMap(&dst.ByDirection, src.ByDirection)
}

func (s *FlowStore) compactRollupsLocked() {
	nowMs := time.Now().UnixMilli()
	retHours := s.cfg.RetentionHours
	if retHours <= 0 {
		retHours = 168
	}
	cutoff1m := nowMs - 6*3600*1000
	cutoff5m := nowMs - 48*3600*1000
	cutoffRetention := nowMs - int64(retHours)*3600*1000

	for k, rb := range s.rollups1m {
		if k < cutoff1m {
			b5 := (k / 300_000) * 300_000
			dst := s.rollups5m[b5]
			if dst == nil {
				dst = newRollupBucket(b5)
				s.rollups5m[b5] = dst
			}
			mergeRollupBucket(dst, rb)
			delete(s.rollups1m, k)
		}
	}
	for k, rb := range s.rollups5m {
		if k < cutoff5m {
			b1h := (k / 3_600_000) * 3_600_000
			dst := s.rollups1h[b1h]
			if dst == nil {
				dst = newRollupBucket(b1h)
				s.rollups1h[b1h] = dst
			}
			mergeRollupBucket(dst, rb)
			delete(s.rollups5m, k)
		}
	}
	for _, m := range []map[int64]*rollupBucket{s.rollups1m, s.rollups5m, s.rollups1h} {
		for k := range m {
			if k < cutoffRetention {
				delete(m, k)
			}
		}
	}
}

func (s *FlowStore) saveRollupsLocked() {
	if s.cfg.DataDir == "" {
		return
	}
	dir := filepath.Join(s.cfg.DataDir, "rollups")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return
	}
	target := filepath.Join(dir, "rollups.json.zst")
	tmp := target + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return
	}
	zw, zerr := zstd.NewWriter(f)
	if zerr != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return
	}
	doc := persistedRollupsFile{
		Rollups1m: s.rollups1m,
		Rollups5m: s.rollups5m,
		Rollups1h: s.rollups1h,
	}
	encErr := json.NewEncoder(zw).Encode(doc)
	closeZErr := zw.Close()
	closeFErr := f.Close()
	if encErr != nil || closeZErr != nil || closeFErr != nil {
		_ = os.Remove(tmp)
		return
	}
	_ = os.Rename(tmp, target)
}

func (s *FlowStore) loadRollupsLocked() {
	if s.cfg.DataDir == "" {
		return
	}
	target := filepath.Join(s.cfg.DataDir, "rollups", "rollups.json.zst")
	f, err := os.Open(target)
	if err != nil {
		return
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		return
	}
	defer zr.Close()
	var doc persistedRollupsFile
	if err := json.NewDecoder(zr).Decode(&doc); err != nil {
		return
	}
	if doc.Rollups1m != nil {
		s.rollups1m = doc.Rollups1m
	}
	if doc.Rollups5m != nil {
		s.rollups5m = doc.Rollups5m
	}
	if doc.Rollups1h != nil {
		s.rollups1h = doc.Rollups1h
	}
}

func (s *FlowStore) pushHotLocked(f FlowRecord) {
	if len(s.hotRing) == 0 {
		return
	}
	s.hotRing[s.hotHead] = f
	s.hotHead = (s.hotHead + 1) % len(s.hotRing)
	if s.hotCount < len(s.hotRing) {
		s.hotCount++
	}
}

func (s *FlowStore) snapshotHotLocked() []FlowRecord {
	if s.hotCount == 0 {
		return nil
	}
	out := make([]FlowRecord, 0, s.hotCount)
	start := (s.hotHead - s.hotCount + len(s.hotRing)) % len(s.hotRing)
	for i := 0; i < s.hotCount; i++ {
		out = append(out, s.hotRing[(start+i)%len(s.hotRing)])
	}
	return out
}

func (s *FlowStore) Stats() (hotCount, hotCap, chunksCount int, diskMB float64, mode string, chConnected bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var totalSize int64
	for _, c := range s.chunks {
		totalSize += c.FileSize
	}
	return s.hotCount, len(s.hotRing), len(s.chunks), float64(totalSize) / (1024 * 1024), s.cfg.Mode, s.chConnected
}

// Flush persists pending local flows to compressed chunk files and flushes any pending ClickHouse batch.
func (s *FlowStore) Flush() error {
	s.mu.Lock()
	toWrite := s.pendingFlush
	s.pendingFlush = nil
	toCH := s.pendingCH
	s.pendingCH = nil
	cfg := s.cfg
	chConn := s.chConn
	chConnected := s.chConnected
	chTable := s.chTableFQN
	s.mu.Unlock()

	var firstErr error
	if len(toWrite) > 0 && cfg.DataDir != "" && cfg.Mode != "clickhouse" {
		if entry, err := s.writeChunkFile(cfg, toWrite); err != nil {
			firstErr = err
			s.mu.Lock()
			s.pendingFlush = capFlowQueue(append(toWrite, s.pendingFlush...), maxFlowStorePending)
			s.mu.Unlock()
		} else {
			s.mu.Lock()
			s.chunks = append(s.chunks, entry)
			s.pruneChunksLocked()
			_ = s.saveManifestLocked()
			s.mu.Unlock()
		}
	}

	if len(toCH) > 0 && chConnected && chConn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		batch, err := chConn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
			timestamp, version, exporter_ip, node_id, node_name, src_ip, dst_ip, src_port, dst_port,
			protocol, app_name, direction, in_if_name, out_if_name, vlan_id,
			bytes, packets, bps, src_country, dst_country, threat_match,
			src_asn, dst_asn, src_city, dst_city, peer_as,
			post_nat_src_ip, post_nat_dst_ip, post_nat_src_port, post_nat_dst_port,
			tcp_flags, k3s_namespace, k3s_workload, rtt_ms, retransmits
		)`, chTable))
		var chErr error
		if err != nil {
			chErr = err
		} else {
			for _, f := range toCH {
				nodeID := f.HostID
				if nodeID == "" {
					nodeID = f.ExporterIP
				}
				if appErr := batch.Append(
					time.UnixMilli(f.TimestampMs),
					f.Version,
					f.ExporterIP,
					nodeID,
					f.HostName,
					f.SrcIP,
					f.DstIP,
					f.SrcPort,
					f.DstPort,
					f.Protocol,
					f.AppName,
					f.Direction,
					f.InIfName,
					f.OutIfName,
					f.VlanID,
					f.Bytes,
					f.Packets,
					f.Bps,
					f.SrcCountry,
					f.DstCountry,
					f.ThreatMatch,
					f.SrcAsn,
					f.DstAsn,
					f.SrcCity,
					f.DstCity,
					f.PeerAs,
					f.PostNatSrcIP,
					f.PostNatDstIP,
					f.PostNatSrcPort,
					f.PostNatDstPort,
					f.TCPFlags,
					f.K3sNamespace,
					f.K3sWorkload,
					f.RttMs,
					f.Retransmits,
				); appErr != nil && chErr == nil {
					chErr = appErr
				}
			}
			if chErr == nil {
				if sendErr := batch.Send(); sendErr != nil {
					chErr = sendErr
				}
			} else {
				_ = batch.Abort()
			}
		}
		cancel()
		if chErr != nil {
			if firstErr == nil {
				firstErr = chErr
			}
			s.mu.Lock()
			if s.chConnected && s.chConn != nil {
				s.pendingCH = capFlowQueue(append(toCH, s.pendingCH...), maxFlowStorePending)
			}
			s.mu.Unlock()
		}
	}

	s.mu.Lock()
	s.compactRollupsLocked()
	s.saveRollupsLocked()
	s.mu.Unlock()

	return firstErr
}

func (s *FlowStore) writeChunkFile(cfg NetFlowStoragePayload, records []FlowRecord) (chunkManifestEntry, error) {
	minTs := records[0].TimestampMs
	maxTs := records[0].TimestampMs
	var totalBytes uint64
	for _, r := range records {
		if r.TimestampMs < minTs {
			minTs = r.TimestampMs
		}
		if r.TimestampMs > maxTs {
			maxTs = r.TimestampMs
		}
		totalBytes += r.Bytes
	}

	dayDir := filepath.Join(cfg.DataDir, "chunks", time.UnixMilli(minTs).UTC().Format("2006-01-02"))
	if err := os.MkdirAll(dayDir, 0750); err != nil {
		return chunkManifestEntry{}, err
	}
	ext := "jsonl"
	if cfg.Compression == "zstd" {
		ext = "nfl.zst"
	} else if cfg.Compression == "gzip" {
		ext = "nfl.gz"
	}
	chunkPath := filepath.Join(dayDir, fmt.Sprintf("chunk-%d-%d.%s", minTs, time.Now().UnixNano()%100000, ext))
	tmpPath := chunkPath + ".tmp"

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return chunkManifestEntry{}, err
	}

	var w io.WriteCloser
	switch cfg.Compression {
	case "zstd":
		zw, zerr := zstd.NewWriter(f)
		if zerr != nil {
			_ = f.Close()
			return chunkManifestEntry{}, zerr
		}
		w = zw
	case "gzip":
		w = gzip.NewWriter(f)
	default:
		w = nopWriteCloser{f}
	}

	bw := bufio.NewWriterSize(w, 32*1024)
	enc := json.NewEncoder(bw)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			_ = bw.Flush()
			_ = w.Close()
			_ = f.Close()
			_ = os.Remove(tmpPath)
			return chunkManifestEntry{}, err
		}
	}
	if err := bw.Flush(); err != nil {
		_ = w.Close()
		_ = f.Close()
		return chunkManifestEntry{}, err
	}
	if cfg.Compression != "none" {
		if err := w.Close(); err != nil {
			_ = f.Close()
			return chunkManifestEntry{}, err
		}
	}
	if err := f.Close(); err != nil {
		return chunkManifestEntry{}, err
	}
	if err := os.Rename(tmpPath, chunkPath); err != nil {
		return chunkManifestEntry{}, err
	}
	st, _ := os.Stat(chunkPath)
	var fSize int64
	if st != nil {
		fSize = st.Size()
	}
	return chunkManifestEntry{
		Path:     chunkPath,
		MinTsMs:  minTs,
		MaxTsMs:  maxTs,
		Count:    len(records),
		Bytes:    totalBytes,
		FileSize: fSize,
	}, nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func (s *FlowStore) readChunkFile(entry chunkManifestEntry) ([]FlowRecord, error) {
	f, err := os.Open(entry.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(entry.Path, ".zst") {
		zr, err := zstd.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	} else if strings.HasSuffix(entry.Path, ".gz") {
		gr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		r = gr
	}

	out := make([]FlowRecord, 0, entry.Count)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec FlowRecord
		if err := json.Unmarshal([]byte(line), &rec); err == nil {
			out = append(out, rec)
		}
	}
	return out, sc.Err()
}

func (s *FlowStore) pruneChunksLocked() {
	if s.cfg.RetentionHours > 0 {
		cutoffMs := time.Now().Add(-time.Duration(s.cfg.RetentionHours) * time.Hour).UnixMilli()
		kept := s.chunks[:0]
		for _, c := range s.chunks {
			if c.MaxTsMs < cutoffMs {
				_ = os.Remove(c.Path)
			} else {
				kept = append(kept, c)
			}
		}
		s.chunks = kept
	}
	if s.cfg.MaxDiskMB > 0 {
		maxBytes := int64(s.cfg.MaxDiskMB) * 1024 * 1024
		var total int64
		for _, c := range s.chunks {
			total += c.FileSize
		}
		for total > maxBytes && len(s.chunks) > 1 {
			oldest := s.chunks[0]
			s.chunks = s.chunks[1:]
			total -= oldest.FileSize
			_ = os.Remove(oldest.Path)
		}
	}
}

func (s *FlowStore) manifestPathLocked() string {
	return filepath.Join(s.cfg.DataDir, "index.json")
}

func (s *FlowStore) saveManifestLocked() error {
	if s.cfg.DataDir == "" {
		return nil
	}
	_ = os.MkdirAll(s.cfg.DataDir, 0750)
	data, err := json.Marshal(s.chunks)
	if err != nil {
		return err
	}
	tmp := s.manifestPathLocked() + ".tmp"
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, s.manifestPathLocked())
}

func (s *FlowStore) loadManifest() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadRollupsLocked()
	if s.cfg.DataDir == "" {
		return
	}
	data, err := os.ReadFile(s.manifestPathLocked())
	if err != nil {
		return
	}
	var loaded []chunkManifestEntry
	if err := json.Unmarshal(data, &loaded); err != nil {
		return
	}
	existing := loaded[:0]
	for _, c := range loaded {
		if _, err := os.Stat(c.Path); err == nil {
			existing = append(existing, c)
		}
	}
	s.chunks = existing
}

// CollectFlowsInRange scans hot ring and matching compressed chunks for analytics/reports.
func (s *FlowStore) CollectFlowsInRange(startMs, endMs int64, maxChunks int) []FlowRecord {
	if maxChunks <= 0 {
		maxChunks = 64
	}
	s.mu.RLock()
	hot := s.snapshotHotLocked()
	var matchingChunks []chunkManifestEntry
	for _, c := range s.chunks {
		if c.MaxTsMs >= startMs && c.MinTsMs <= endMs {
			matchingChunks = append(matchingChunks, c)
		}
	}
	s.mu.RUnlock()

	seen := make(map[string]struct{}, len(hot))
	out := make([]FlowRecord, 0, len(hot))
	addRec := func(r FlowRecord) {
		if r.TimestampMs < startMs || r.TimestampMs > endMs {
			return
		}
		if r.ID != "" {
			if _, ok := seen[r.ID]; ok {
				return
			}
			seen[r.ID] = struct{}{}
		}
		out = append(out, r)
	}
	for _, r := range hot {
		addRec(r)
	}
	startIdx := 0
	if len(matchingChunks) > maxChunks {
		startIdx = len(matchingChunks) - maxChunks
	}
	for _, ch := range matchingChunks[startIdx:] {
		if recs, err := s.readChunkFile(ch); err == nil {
			for _, r := range recs {
				addRec(r)
			}
		}
	}
	return out
}

func (s *FlowStore) Query(req FlowQueryRequest) FlowQueryResponse {
	nowMs := time.Now().UnixMilli()
	endMs := req.EndMs
	if endMs <= 0 {
		endMs = nowMs
	}
	startMs := req.StartMs
	if startMs <= 0 {
		mins := req.RangeMinutes
		if mins <= 0 {
			mins = 60
		}
		startMs = endMs - int64(mins)*60*1000
	}
	if req.Limit <= 0 || req.Limit > 1000 {
		req.Limit = 200
	}

	var fqlAst fqlNode
	if strings.TrimSpace(req.FQL) != "" {
		parsed, err := ParseFQL(req.FQL)
		if err != nil {
			return FlowQueryResponse{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				FQLError:  err.Error(),
			}
		}
		fqlAst = parsed
	}

	s.mu.RLock()
	hot := s.snapshotHotLocked()
	var matchingChunks []chunkManifestEntry
	for _, c := range s.chunks {
		if c.MaxTsMs >= startMs && c.MinTsMs <= endMs {
			matchingChunks = append(matchingChunks, c)
		}
	}
	cfgMode := s.cfg.Mode
	chReady := s.chConnected && s.chConn != nil
	s.mu.RUnlock()

	oldestHotMs := nowMs
	for _, r := range hot {
		if r.TimestampMs < oldestHotMs {
			oldestHotMs = r.TimestampMs
		}
	}

	if chReady && (cfgMode == "clickhouse" || (cfgMode == "hybrid" && (startMs < oldestHotMs || len(hot) == 0))) {
		if chResp, ok := s.queryClickHouse(req, fqlAst, startMs, endMs); ok {
			return chResp
		}
	}

	seenID := make(map[string]struct{}, len(hot))
	matched := make([]FlowRecord, 0, len(hot))
	appendIfMatch := func(r FlowRecord) {
		if r.TimestampMs < startMs || r.TimestampMs > endMs {
			return
		}
		if fqlAst != nil && !fqlAst.Eval(&r) {
			return
		}
		if r.ID != "" {
			if _, ok := seenID[r.ID]; ok {
				return
			}
			seenID[r.ID] = struct{}{}
		}
		matched = append(matched, r)
	}

	for _, r := range hot {
		appendIfMatch(r)
	}
	engineName := "local-ring"
	if startMs < oldestHotMs || len(hot) == 0 {
		startIdx := 0
		if len(matchingChunks) > 64 {
			startIdx = len(matchingChunks) - 64
		}
		if len(matchingChunks[startIdx:]) > 0 {
			engineName = "local-chunks"
		}
		for _, ch := range matchingChunks[startIdx:] {
			if recs, err := s.readChunkFile(ch); err == nil {
				for _, r := range recs {
					appendIfMatch(r)
				}
			}
		}
	}

	if len(matched) == 0 && strings.TrimSpace(req.FQL) == "" {
		if rollupResp, ok := s.queryRollupsResponse(req, startMs, endMs); ok {
			return rollupResp
		}
	}

	resp := buildFlowQueryResponse(matched, startMs, endMs, req)
	resp.Engine = engineName
	return resp
}

// ListDistinctNodes aggregates unique node_id / exporter_ip identities across the hot ring and ClickHouse.
func (s *FlowStore) ListDistinctNodes() []NetFlowNodeSummary {
	byKey := make(map[string]*NetFlowNodeSummary)

	s.mu.RLock()
	for i := range s.hotRing {
		r := &s.hotRing[i]
		nid := r.HostID
		if nid == "" {
			nid = r.ExporterIP
		}
		if nid == "" {
			continue
		}
		cur := byKey[nid]
		if cur == nil {
			cur = &NetFlowNodeSummary{
				NodeID:     nid,
				NodeName:   r.HostName,
				ExporterIP: r.ExporterIP,
			}
			byKey[nid] = cur
		}
		if cur.NodeName == "" && r.HostName != "" {
			cur.NodeName = r.HostName
		}
		if cur.ExporterIP == "" && r.ExporterIP != "" {
			cur.ExporterIP = r.ExporterIP
		}
		cur.FlowsCount++
		if r.TimestampMs > cur.LastSeenMs {
			cur.LastSeenMs = r.TimestampMs
		}
	}
	conn := s.chConn
	connected := s.chConnected
	tableFQN := s.chTableFQN
	s.mu.RUnlock()

	if connected && conn != nil && tableFQN != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		rows, err := conn.Query(ctx, fmt.Sprintf(`
			SELECT
				if(node_id != '', node_id, exporter_ip) AS nid,
				anyIf(node_name, node_name != '') AS nname,
				anyIf(exporter_ip, exporter_ip != '') AS exp_ip,
				count() AS cnt,
				max(timestamp) AS last_ts
			FROM %s
			GROUP BY nid
			ORDER BY last_ts DESC
			LIMIT 200
		`, tableFQN))
		if err == nil {
			for rows.Next() {
				var nid, nname, expIP string
				var cnt uint64
				var lastTs time.Time
				if rows.Scan(&nid, &nname, &expIP, &cnt, &lastTs) == nil && nid != "" {
					cur := byKey[nid]
					if cur == nil {
						cur = &NetFlowNodeSummary{NodeID: nid}
						byKey[nid] = cur
					}
					if cur.NodeName == "" {
						cur.NodeName = nname
					}
					if cur.ExporterIP == "" {
						cur.ExporterIP = expIP
					}
					if cnt > cur.FlowsCount {
						cur.FlowsCount = cnt
					}
					if ms := lastTs.UnixMilli(); ms > cur.LastSeenMs {
						cur.LastSeenMs = ms
					}
				}
			}
			rows.Close()
		}
		cancel()
	}

	out := make([]NetFlowNodeSummary, 0, len(byKey))
	for _, v := range byKey {
		if v.NodeName == "" {
			v.NodeName = v.NodeID
		}
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeenMs != out[j].LastSeenMs {
			return out[i].LastSeenMs > out[j].LastSeenMs
		}
		return out[i].NodeID < out[j].NodeID
	})
	return out
}

func (s *FlowStore) queryRollupsResponse(req FlowQueryRequest, startMs, endMs int64) (FlowQueryResponse, bool) {
	s.mu.RLock()
	spanMs := endMs - startMs
	stepMs := int64(60_000)
	if spanMs >= 48*3600*1000 {
		stepMs = 3_600_000
	} else if spanMs >= 6*3600*1000 {
		stepMs = 300_000
	}

	mergedMap := make(map[int64]*rollupBucket)
	addTier := func(src map[int64]*rollupBucket) {
		for ts, rb := range src {
			if ts < startMs || ts > endMs {
				continue
			}
			bTs := (ts / stepMs) * stepMs
			dst := mergedMap[bTs]
			if dst == nil {
				dst = newRollupBucket(bTs)
				mergedMap[bTs] = dst
			}
			mergeRollupBucket(dst, rb)
		}
	}
	addTier(s.rollups1m)
	addTier(s.rollups5m)
	addTier(s.rollups1h)
	s.mu.RUnlock()

	if len(mergedMap) == 0 {
		return FlowQueryResponse{}, false
	}
	buckets := make([]*rollupBucket, 0, len(mergedMap))
	for _, rb := range mergedMap {
		buckets = append(buckets, rb)
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].TimestampMs < buckets[j].TimestampMs })
	bucketSec := float64(stepMs) / 1000.0

	resp := FlowQueryResponse{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Engine:     "local-rollups",
		Flows:      []FlowRecord{},
		Timeseries: make([]FlowTimeseriesPoint, 0, len(buckets)),
	}
	protoTotals := make(map[string]uint64)
	expTotals := make(map[string]uint64)
	appTotals := make(map[string]uint64)
	countryTotals := make(map[string]uint64)
	ifTotals := make(map[string]uint64)

	for _, b := range buckets {
		resp.TotalBytes += b.Bytes
		resp.TotalPackets += b.Packets
		resp.TotalMatchedFlows += b.Flows
		series := make(map[string]float64)
		for k, v := range b.ByProto {
			series[k] = float64(v*8) / bucketSec
			protoTotals[k] += v
		}
		for k, v := range b.ByExporter {
			expTotals[k] += v
		}
		for k, v := range b.ByApp {
			appTotals[k] += v
		}
		for k, v := range b.ByCountry {
			countryTotals[k] += v
		}
		for k, v := range b.ByInterface {
			ifTotals[k] += v
		}
		resp.Timeseries = append(resp.Timeseries, FlowTimeseriesPoint{
			TimestampMs: b.TimestampMs,
			TimeLabel:   time.UnixMilli(b.TimestampMs).Local().Format("01-02 15:04"),
			TotalBytes:  b.Bytes,
			TotalPkts:   b.Packets,
			FlowsCount:  b.Flows,
			Bps:         float64(b.Bytes*8) / bucketSec,
			Pps:         float64(b.Packets) / bucketSec,
			Series:      series,
		})
	}
	durSec := float64(spanMs) / 1000.0
	if durSec < 1 {
		durSec = 1
	}
	resp.AvgBps = float64(resp.TotalBytes*8) / durSec
	rankMap := func(m map[string]uint64, limit int) []FlowTopEntry {
		out := make([]FlowTopEntry, 0, len(m))
		for k, v := range m {
			out = append(out, FlowTopEntry{Key: k, Label: k, Bytes: v, Bps: float64(v*8) / durSec})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
		if len(out) > limit {
			out = out[:limit]
		}
		return out
	}
	resp.TopProtocols = rankMap(protoTotals, 10)
	resp.TopExporters = rankMap(expTotals, 10)
	resp.TopApps = rankMap(appTotals, 15)
	resp.TopCountries = rankMap(countryTotals, 10)
	resp.TopInterfaces = rankMap(ifTotals, 12)
	for i := 0; i < len(resp.TopProtocols) && i < 6; i++ {
		resp.SeriesKeys = append(resp.SeriesKeys, resp.TopProtocols[i].Key)
	}
	_ = req
	return resp, true
}

func buildFlowQueryResponse(matched []FlowRecord, startMs, endMs int64, req FlowQueryRequest) FlowQueryResponse {
	resp := FlowQueryResponse{
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		TotalMatchedFlows: len(matched),
	}

	srcMap := make(map[string]*FlowTopEntry)
	dstMap := make(map[string]*FlowTopEntry)
	appMap := make(map[string]*FlowTopEntry)
	protoMap := make(map[string]*FlowTopEntry)
	countryMap := make(map[string]*FlowTopEntry)
	asnMap := make(map[string]*FlowTopEntry)
	expMap := make(map[string]*FlowTopEntry)
	ifMap := make(map[string]*FlowTopEntry)
	vlanMap := make(map[string]*FlowTopEntry)
	convMap := make(map[string]*FlowConversationEntry)
	sankeySrcApp := make(map[string]uint64)
	sankeyAppDst := make(map[string]uint64)
	srcSet := make(map[string]struct{})
	dstSet := make(map[string]struct{})

	spanMs := endMs - startMs
	if spanMs <= 0 {
		spanMs = 60_000
	}
	bucketMs := spanMs / 40
	if bucketMs < 10_000 {
		bucketMs = 10_000
	}
	bucketMap := make(map[int64]*FlowTimeseriesPoint)
	groupTotals := make(map[string]uint64)

	groupBy := strings.ToLower(strings.TrimSpace(req.GroupBy))
	if groupBy == "" {
		groupBy = "protocol"
	}

	for _, f := range matched {
		resp.TotalBytes += f.Bytes
		resp.TotalPackets += f.Packets
		if f.SrcIP != "" {
			srcSet[f.SrcIP] = struct{}{}
		}
		if f.DstIP != "" {
			dstSet[f.DstIP] = struct{}{}
		}

		addTopEntry(srcMap, f.SrcIP, f.SrcHost, f.SrcOrg, &f)
		addTopEntry(dstMap, f.DstIP, f.DstHost, f.DstCountry, &f)
		appKey := f.AppName
		if appKey == "" {
			appKey = f.ProtocolName
		}
		addTopEntry(appMap, appKey, appKey, f.ProtocolName, &f)
		addTopEntry(protoMap, f.ProtocolName, f.ProtocolName, "", &f)

		country := f.DstCountry
		if country == "" || country == "LAN" {
			country = f.SrcCountry
		}
		if country != "" {
			addTopEntry(countryMap, country, country, "", &f)
		}
		org := f.DstOrg
		if org == "" || org == "Private / Internal" {
			org = f.SrcOrg
		}
		if org != "" {
			addTopEntry(asnMap, org, org, "", &f)
		}
		addTopEntry(expMap, f.ExporterIP, f.ExporterName, f.Version, &f)
		if ifName := firstNonEmpty(f.InIfName, f.OutIfName); ifName != "" {
			addTopEntry(ifMap, ifName, ifName, f.ExporterIP, &f)
		}
		if f.VlanID > 0 {
			vk := fmt.Sprintf("VLAN %d", f.VlanID)
			addTopEntry(vlanMap, vk, vk, "", &f)
		}

		cKey := fmt.Sprintf("%s|%s|%d|%s", f.SrcIP, f.DstIP, f.DstPort, f.ProtocolName)
		ce := convMap[cKey]
		if ce == nil {
			ce = &FlowConversationEntry{
				SrcIP:        f.SrcIP,
				SrcHost:      f.SrcHost,
				DstIP:        f.DstIP,
				DstHost:      f.DstHost,
				DstPort:      f.DstPort,
				ProtocolName: f.ProtocolName,
				AppName:      appKey,
				Direction:    f.Direction,
				ThreatMatch:  f.ThreatMatch,
			}
			convMap[cKey] = ce
		}
		ce.Bytes += f.Bytes
		ce.Packets += f.Packets
		ce.Flows++
		if f.ThreatMatch != "" && ce.ThreatMatch == "" {
			ce.ThreatMatch = f.ThreatMatch
		}

		srcLabel := f.SrcIP
		if f.SrcHost != "" {
			srcLabel = f.SrcHost
		}
		dstLabel := f.DstIP
		if f.DstHost != "" {
			dstLabel = f.DstHost
		}
		sankeySrcApp[srcLabel+"→"+appKey] += f.Bytes
		sankeyAppDst[appKey+"→"+dstLabel] += f.Bytes

		bTs := (f.TimestampMs / bucketMs) * bucketMs
		pt := bucketMap[bTs]
		if pt == nil {
			pt = &FlowTimeseriesPoint{
				TimestampMs: bTs,
				TimeLabel:   time.UnixMilli(bTs).Local().Format("15:04:05"),
				Series:      make(map[string]float64),
			}
			bucketMap[bTs] = pt
		}
		pt.TotalBytes += f.Bytes
		pt.TotalPkts += f.Packets
		pt.FlowsCount++
		gKey := extractGroupKey(&f, groupBy)
		pt.Series[gKey] += float64(f.Bytes*8) / (float64(bucketMs) / 1000.0)
		groupTotals[gKey] += f.Bytes
	}

	durSec := float64(spanMs) / 1000.0
	if durSec < 1 {
		durSec = 1
	}
	resp.AvgBps = float64(resp.TotalBytes*8) / durSec
	resp.UniqueSources = len(srcSet)
	resp.UniqueDests = len(dstSet)

	// Top 5 series keys for clean stacked AreaChart
	seriesRank := make([]struct {
		k string
		b uint64
	}, 0, len(groupTotals))
	for k, b := range groupTotals {
		seriesRank = append(seriesRank, struct {
			k string
			b uint64
		}{k: k, b: b})
	}
	sort.Slice(seriesRank, func(i, j int) bool { return seriesRank[i].b > seriesRank[j].b })
	for i := 0; i < len(seriesRank) && i < 6; i++ {
		resp.SeriesKeys = append(resp.SeriesKeys, seriesRank[i].k)
	}

	bKeys := make([]int64, 0, len(bucketMap))
	for k := range bucketMap {
		bKeys = append(bKeys, k)
	}
	sort.Slice(bKeys, func(i, j int) bool { return bKeys[i] < bKeys[j] })
	bSec := float64(bucketMs) / 1000.0
	for _, k := range bKeys {
		pt := bucketMap[k]
		pt.Bps = float64(pt.TotalBytes*8) / bSec
		pt.Pps = float64(pt.TotalPkts) / bSec
		resp.Timeseries = append(resp.Timeseries, *pt)
	}

	resp.TopSources = rankTopEntries(srcMap, durSec, 15)
	resp.TopDestinations = rankTopEntries(dstMap, durSec, 15)
	resp.TopApps = rankTopEntries(appMap, durSec, 15)
	resp.TopProtocols = rankTopEntries(protoMap, durSec, 10)
	resp.TopCountries = rankTopEntries(countryMap, durSec, 10)
	resp.TopASNs = rankTopEntries(asnMap, durSec, 10)
	resp.TopExporters = rankTopEntries(expMap, durSec, 10)
	resp.TopInterfaces = rankTopEntries(ifMap, durSec, 12)
	resp.TopVLANs = rankTopEntries(vlanMap, durSec, 10)

	convs := make([]FlowConversationEntry, 0, len(convMap))
	for _, c := range convMap {
		c.Bps = float64(c.Bytes*8) / durSec
		convs = append(convs, *c)
	}
	sort.Slice(convs, func(i, j int) bool { return convs[i].Bytes > convs[j].Bytes })
	if len(convs) > 25 {
		convs = convs[:25]
	}
	resp.TopConversations = convs
	resp.SankeyLinks = buildSankeyLinks(sankeySrcApp, sankeyAppDst)
	resp.HostHeatmap = BuildHostHeatmap(matched, resp.TopSources, resp.TopDestinations)
	resp.PortTimeHeatmap = BuildPortTimeHeatmap(matched, resp.Timeseries, startMs, bucketMs)
	resp.GeoArcs = BuildGeoArcs(matched)
	if req.Biflow {
		resp.Sessions = StitchBidirectionalSessions(matched, 120_000)
	}

	switch strings.ToLower(req.SortBy) {
	case "bytes":
		sort.Slice(matched, func(i, j int) bool { return matched[i].Bytes > matched[j].Bytes })
	case "packets":
		sort.Slice(matched, func(i, j int) bool { return matched[i].Packets > matched[j].Packets })
	case "bps":
		sort.Slice(matched, func(i, j int) bool { return matched[i].Bps > matched[j].Bps })
	default:
		sort.Slice(matched, func(i, j int) bool { return matched[i].TimestampMs > matched[j].TimestampMs })
	}

	off := req.Offset
	if off < 0 {
		off = 0
	}
	if off >= len(matched) {
		resp.Flows = []FlowRecord{}
	} else {
		endIdx := off + req.Limit
		if endIdx > len(matched) {
			endIdx = len(matched)
		}
		resp.Flows = matched[off:endIdx]
	}
	return resp
}

func addTopEntry(m map[string]*FlowTopEntry, key, label, meta string, f *FlowRecord) {
	if key == "" {
		return
	}
	e := m[key]
	if e == nil {
		e = &FlowTopEntry{Key: key, Label: label, Meta: meta}
		m[key] = e
	}
	if label != "" && e.Label == "" {
		e.Label = label
	}
	e.Bytes += f.Bytes
	e.Packets += f.Packets
	e.Flows++
}

func rankTopEntries(m map[string]*FlowTopEntry, durSec float64, limit int) []FlowTopEntry {
	out := make([]FlowTopEntry, 0, len(m))
	for _, e := range m {
		e.Bps = float64(e.Bytes*8) / durSec
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func buildSankeyLinks(srcApp, appDst map[string]uint64) []FlowSankeyLink {
	links := make([]FlowSankeyLink, 0, 24)
	addRanked := func(m map[string]uint64, stage string, limit int) {
		type kv struct {
			k string
			v uint64
		}
		var list []kv
		for k, v := range m {
			list = append(list, kv{k: k, v: v})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
		for i := 0; i < len(list) && i < limit; i++ {
			parts := strings.SplitN(list[i].k, "→", 2)
			if len(parts) == 2 {
				links = append(links, FlowSankeyLink{
					Source: parts[0],
					Target: parts[1],
					Bytes:  list[i].v,
					Stage:  stage,
				})
			}
		}
	}
	addRanked(srcApp, "src-to-app", 10)
	addRanked(appDst, "app-to-dst", 10)
	return links
}

func extractGroupKey(f *FlowRecord, groupBy string) string {
	switch groupBy {
	case "app":
		return firstNonEmpty(f.AppName, f.ProtocolName)
	case "direction":
		return firstNonEmpty(f.Direction, "unknown")
	case "src":
		return firstNonEmpty(f.SrcHost, f.SrcIP)
	case "dst":
		return firstNonEmpty(f.DstHost, f.DstIP)
	case "exporter":
		return firstNonEmpty(f.ExporterName, f.ExporterIP)
	case "vlan":
		if f.VlanID > 0 {
			return fmt.Sprintf("VLAN %d", f.VlanID)
		}
		return "Untagged"
	default:
		return firstNonEmpty(f.ProtocolName, "OTHER")
	}
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// --- Flow Query Language (FQL) Recursive-Descent Parser & Evaluator ---

type fqlNode interface {
	Eval(f *FlowRecord) bool
}

type fqlAnd struct{ left, right fqlNode }
type fqlOr struct{ left, right fqlNode }
type fqlNot struct{ inner fqlNode }

func (n fqlAnd) Eval(f *FlowRecord) bool { return n.left.Eval(f) && n.right.Eval(f) }
func (n fqlOr) Eval(f *FlowRecord) bool  { return n.left.Eval(f) || n.right.Eval(f) }
func (n fqlNot) Eval(f *FlowRecord) bool { return !n.inner.Eval(f) }

type fqlPred struct {
	field string
	op    string
	raw   string
	num   float64
	isNum bool
	cidr  netip.Prefix
	isNet bool
}

func ParseFQL(raw string) (fqlNode, error) {
	toks, err := tokenizeFQL(raw)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, nil
	}
	p := &fqlParser{toks: toks}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.toks) {
		return nil, fmt.Errorf("unexpected token %q in FQL expression", p.toks[p.pos])
	}
	return node, nil
}

func tokenizeFQL(raw string) ([]string, error) {
	var toks []string
	i := 0
	for i < len(raw) {
		ch := raw[i]
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			i++
			continue
		}
		if ch == '(' || ch == ')' || ch == '=' || ch == '>' || ch == '<' || ch == '~' {
			if (ch == '>' || ch == '<') && i+1 < len(raw) && raw[i+1] == '=' {
				toks = append(toks, raw[i:i+2])
				i += 2
				continue
			}
			toks = append(toks, string(ch))
			i++
			continue
		}
		if ch == '!' {
			if i+1 < len(raw) && raw[i+1] == '=' {
				toks = append(toks, "!=")
				i += 2
				continue
			}
			toks = append(toks, "not")
			i++
			continue
		}
		if (ch == '&' && i+1 < len(raw) && raw[i+1] == '&') || (ch == '|' && i+1 < len(raw) && raw[i+1] == '|') {
			toks = append(toks, raw[i:i+2])
			i += 2
			continue
		}
		if ch == '"' || ch == '\'' {
			q := ch
			j := i + 1
			for j < len(raw) && raw[j] != q {
				j++
			}
			if j >= len(raw) {
				return nil, errors.New("unterminated quoted string in FQL")
			}
			toks = append(toks, raw[i+1:j])
			i = j + 1
			continue
		}
		j := i
		for j < len(raw) {
			c := raw[j]
			if c == ' ' || c == '\t' || c == '\n' || c == '(' || c == ')' || c == '=' || c == '>' || c == '<' || c == '~' || c == '!' || c == '&' || c == '|' {
				break
			}
			j++
		}
		toks = append(toks, raw[i:j])
		i = j
	}
	return toks, nil
}

type fqlParser struct {
	toks []string
	pos  int
}

func (p *fqlParser) peek() string {
	if p.pos >= len(p.toks) {
		return ""
	}
	return p.toks[p.pos]
}

func (p *fqlParser) parseOr() (fqlNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		tok := strings.ToLower(p.peek())
		if tok == "or" || tok == "||" {
			p.pos++
			right, err := p.parseAnd()
			if err != nil {
				return nil, err
			}
			left = fqlOr{left: left, right: right}
		} else {
			break
		}
	}
	return left, nil
}

func (p *fqlParser) parseAnd() (fqlNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		tok := strings.ToLower(p.peek())
		if tok == "and" || tok == "&&" {
			p.pos++
			right, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			left = fqlAnd{left: left, right: right}
		} else {
			break
		}
	}
	return left, nil
}

func (p *fqlParser) parseUnary() (fqlNode, error) {
	if strings.EqualFold(p.peek(), "not") {
		p.pos++
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return fqlNot{inner: inner}, nil
	}
	return p.parsePrimary()
}

func (p *fqlParser) parsePrimary() (fqlNode, error) {
	if p.peek() == "(" {
		p.pos++
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, errors.New("expected closing ')' in FQL")
		}
		p.pos++
		return node, nil
	}
	if p.pos >= len(p.toks) {
		return nil, errors.New("unexpected end of FQL expression")
	}
	field := p.toks[p.pos]
	p.pos++
	op := p.peek()
	if op == "=" || op == "!=" || op == ">" || op == ">=" || op == "<" || op == "<=" || op == "~" {
		p.pos++
		if p.pos >= len(p.toks) {
			return nil, fmt.Errorf("missing value after %s %s", field, op)
		}
		val := p.toks[p.pos]
		p.pos++
		return compilePred(strings.ToLower(field), op, val), nil
	}
	// Bare keyword fallback matches IP/app/host
	return compilePred("_any", "~", field), nil
}

func compilePred(field, op, raw string) fqlPred {
	pr := fqlPred{field: field, op: op, raw: raw}
	if num, ok := parseHumanNumber(raw); ok {
		pr.num = num
		pr.isNum = true
	}
	if p, err := netip.ParsePrefix(strings.TrimSpace(raw)); err == nil {
		pr.cidr = p
		pr.isNet = true
	}
	return pr
}

func parseHumanNumber(raw string) (float64, bool) {
	s := strings.TrimSpace(strings.ToUpper(raw))
	mult := 1.0
	for suffix, m := range map[string]float64{
		"GBPS": 1e9, "MBPS": 1e6, "KBPS": 1e3,
		"GB": 1024 * 1024 * 1024, "MB": 1024 * 1024, "KB": 1024,
		"G": 1e9, "M": 1e6, "K": 1e3,
	} {
		if strings.HasSuffix(s, suffix) {
			s = strings.TrimSpace(strings.TrimSuffix(s, suffix))
			mult = m
			break
		}
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v * mult, true
}

func (p fqlPred) Eval(f *FlowRecord) bool {
	if p.field == "_any" {
		q := strings.ToLower(p.raw)
		return strings.Contains(strings.ToLower(f.SrcIP), q) ||
			strings.Contains(strings.ToLower(f.DstIP), q) ||
			strings.Contains(strings.ToLower(f.SrcHost), q) ||
			strings.Contains(strings.ToLower(f.DstHost), q) ||
			strings.Contains(strings.ToLower(f.AppName), q) ||
			strings.Contains(strings.ToLower(f.ProtocolName), q) ||
			strings.Contains(strings.ToLower(f.SrcCity), q) ||
			strings.Contains(strings.ToLower(f.DstCity), q) ||
			strings.Contains(strings.ToLower(f.K3sPodName), q) ||
			strings.Contains(strings.ToLower(f.ThreatMatch), q)
	}

	switch p.field {
	case "ip":
		if p.op == "!=" {
			return matchIPField(f.SrcIP, p) && matchIPField(f.DstIP, p)
		}
		return matchIPField(f.SrcIP, p) || matchIPField(f.DstIP, p)
	case "src", "src_ip":
		return matchIPField(f.SrcIP, p)
	case "dst", "dst_ip":
		return matchIPField(f.DstIP, p)
	case "post_nat_src":
		return matchIPField(f.PostNatSrcIP, p)
	case "post_nat_dst":
		return matchIPField(f.PostNatDstIP, p)
	case "exporter", "exporter_ip":
		return matchIPField(f.ExporterIP, p)
	case "host":
		if p.op == "!=" {
			return matchStrField(f.SrcHost, p) && matchStrField(f.DstHost, p) && matchStrField(f.HostName, p)
		}
		return matchStrField(f.SrcHost, p) || matchStrField(f.DstHost, p) || matchStrField(f.HostName, p)
	case "host_id", "node", "node_id":
		if p.op == "!=" {
			return matchStrField(f.HostID, p) && matchStrField(f.HostName, p) && matchIPField(f.ExporterIP, p)
		}
		return matchStrField(f.HostID, p) || matchStrField(f.HostName, p) || matchIPField(f.ExporterIP, p)
	case "src_port":
		return matchNumField(float64(f.SrcPort), p)
	case "dst_port":
		return matchNumField(float64(f.DstPort), p)
	case "post_nat_sport":
		return matchNumField(float64(f.PostNatSrcPort), p)
	case "post_nat_dport":
		return matchNumField(float64(f.PostNatDstPort), p)
	case "port":
		if p.op == "!=" {
			return matchNumField(float64(f.SrcPort), p) && matchNumField(float64(f.DstPort), p)
		}
		return matchNumField(float64(f.SrcPort), p) || matchNumField(float64(f.DstPort), p)
	case "proto", "protocol":
		return matchStrField(f.ProtocolName, p) || (p.isNum && matchNumField(float64(f.Protocol), p))
	case "app":
		return matchStrField(f.AppName, p)
	case "in_if":
		return matchStrField(f.InIfName, p) || matchNumField(float64(f.InIfIndex), p)
	case "out_if":
		return matchStrField(f.OutIfName, p) || matchNumField(float64(f.OutIfIndex), p)
	case "if":
		if p.op == "!=" {
			return matchStrField(f.InIfName, p) && matchStrField(f.OutIfName, p)
		}
		return matchStrField(f.InIfName, p) || matchStrField(f.OutIfName, p)
	case "vlan":
		return matchNumField(float64(f.VlanID), p)
	case "bytes":
		return matchNumField(float64(f.Bytes), p)
	case "packets", "pkts":
		return matchNumField(float64(f.Packets), p)
	case "bps":
		return matchNumField(f.Bps, p)
	case "pps":
		return matchNumField(f.Pps, p)
	case "asn":
		if p.op == "!=" {
			if p.isNum {
				return matchNumField(float64(f.SrcAsn), p) && matchNumField(float64(f.DstAsn), p)
			}
			return matchStrField(f.SrcOrg, p) && matchStrField(f.DstOrg, p)
		}
		return matchNumField(float64(f.SrcAsn), p) || matchNumField(float64(f.DstAsn), p) || matchStrField(f.SrcOrg, p) || matchStrField(f.DstOrg, p)
	case "peer_as":
		return matchNumField(float64(f.PeerAs), p)
	case "as_path":
		for _, a := range f.AsPath {
			if matchNumField(float64(a), p) {
				return true
			}
		}
		return false
	case "country":
		if p.op == "!=" {
			return matchStrField(f.SrcCountry, p) && matchStrField(f.DstCountry, p)
		}
		return matchStrField(f.SrcCountry, p) || matchStrField(f.DstCountry, p)
	case "city":
		if p.op == "!=" {
			return matchStrField(f.SrcCity, p) && matchStrField(f.DstCity, p)
		}
		return matchStrField(f.SrcCity, p) || matchStrField(f.DstCity, p)
	case "direction", "dir":
		return matchStrField(f.Direction, p)
	case "tcp_flags", "flags":
		return matchStrField(f.TCPFlagsStr, p) || (p.isNum && matchNumField(float64(f.TCPFlags), p))
	case "tos":
		return matchNumField(float64(f.ToS), p)
	case "dscp":
		return matchNumField(float64(f.DSCP), p)
	case "threat":
		return matchStrField(f.ThreatMatch, p)
	case "k3s_ns":
		return matchStrField(f.K3sNamespace, p)
	case "k3s_workload":
		return matchStrField(f.K3sWorkload, p)
	case "k3s_pod":
		return matchStrField(f.K3sPodName, p) || matchStrField(f.K3sWorkload, p) || matchStrField(f.K3sServiceName, p)
	case "rtt_ms":
		return matchNumField(f.RttMs, p)
	case "retransmits":
		return matchNumField(float64(f.Retransmits), p)
	case "version":
		return matchStrField(f.Version, p)
	}
	return false
}

func matchIPField(val string, p fqlPred) bool {
	if p.isNet {
		addr, err := netip.ParseAddr(val)
		in := err == nil && p.cidr.Contains(addr)
		if p.op == "!=" {
			return !in
		}
		return in
	}
	return matchStrField(val, p)
}

func matchStrField(val string, p fqlPred) bool {
	lv := strings.ToLower(val)
	lr := strings.ToLower(p.raw)
	switch p.op {
	case "=":
		return lv == lr
	case "!=":
		return lv != lr
	case "~":
		return strings.Contains(lv, lr)
	default:
		return lv == lr
	}
}

func matchNumField(val float64, p fqlPred) bool {
	if !p.isNum {
		return false
	}
	switch p.op {
	case "=":
		return val == p.num
	case "!=":
		return val != p.num
	case ">":
		return val > p.num
	case ">=":
		return val >= p.num
	case "<":
		return val < p.num
	case "<=":
		return val <= p.num
	default:
		return false
	}
}
