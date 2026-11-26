package engine

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type LogShipper struct {
	mu            sync.RWMutex
	cfg           *ObservabilityRuntimeBundle
	running       bool
	stopCh        chan struct{}
	stopCtx       context.Context
	stopCancel    context.CancelFunc
	wg            sync.WaitGroup
	httpClient    *http.Client
	httpTransport *http.Transport
	httpClientErr error
	nextRetryAt   time.Time
	retryBackoff  time.Duration
	queue         *TelemetryQueue
	nflog         *NflogReader
	eventCh       chan StructuredLogEntry
	lastPushAt    atomic.Int64
	lastErr       atomic.Value
}

func NewLogShipper() *LogShipper {
	s := &LogShipper{
		queue:   NewTelemetryQueue("logs-victorialogs", 24, false, "/var/lib/axonwall/telemetry-spool", 256),
		eventCh: make(chan StructuredLogEntry, 4096),
	}
	s.nflog = NewNflogReader(s.Enqueue)
	return s
}

func (s *LogShipper) Enqueue(entry StructuredLogEntry) {
	select {
	case s.eventCh <- entry:
	default:
		// Channel full under extreme burst: drop newest inline or push direct compressed chunk
	}
}

func (s *LogShipper) QueueStats() TelemetryQueueStats {
	return s.queue.Stats()
}

func (s *LogShipper) Status() (TelemetryQueueStats, int64, string) {
	errStr, _ := s.lastErr.Load().(string)
	return s.queue.Stats(), s.lastPushAt.Load(), errStr
}

func (s *LogShipper) ApplyConfig(b *ObservabilityRuntimeBundle) {
	s.Stop()
	if b == nil {
		return
	}
	targetURL := b.Offload.ResolvedVictoriaLogsURLOrDefault()
	client, tr, clientErr := buildObservabilityHTTPClient(b, targetURL)
	s.mu.Lock()
	if s.httpTransport != nil {
		s.httpTransport.CloseIdleConnections()
	}
	s.cfg = b
	s.httpClient = client
	s.httpTransport = tr
	s.httpClientErr = clientErr
	s.nextRetryAt = time.Time{}
	s.retryBackoff = 0
	s.mu.Unlock()
	s.queue.Configure(
		b.Offload.Buffer.MaxMemoryMB,
		b.Offload.Buffer.DiskSpoolEnabled,
		b.Offload.Buffer.DiskSpoolDir,
		b.Offload.Buffer.DiskSpoolMaxMB,
	)

	if !b.Offload.Enabled || !b.Offload.Logs.Enabled || targetURL == "" {
		return
	}
	s.Start()
}

func (s *LogShipper) Start() {
	s.mu.Lock()
	if s.running || s.cfg == nil {
		s.mu.Unlock()
		return
	}
	cfg := s.cfg
	stopCh := make(chan struct{})
	stopCtx, stopCancel := context.WithCancel(context.Background())
	s.stopCh = stopCh
	s.stopCtx = stopCtx
	s.stopCancel = stopCancel
	s.running = true
	s.mu.Unlock()

	nodeID := strings.TrimSpace(cfg.NodeID)
	hostname := strings.TrimSpace(cfg.Hostname)
	if nodeID == "" {
		nodeID = firstNonEmpty(hostname, "axonwall")
	}

	if cfg.Offload.Logs.Nflog.Enabled {
		s.nflog.Start(
			uint16(cfg.Offload.Logs.Nflog.Group),
			cfg.Offload.Logs.Nflog.RateLimitPerSec,
			nodeID,
			hostname,
			cfg.FirewallRules,
		)
	}
	if cfg.Offload.Logs.Suricata.Enabled {
		s.wg.Add(1)
		go s.tailFileLoop(stopCh, "/var/log/suricata/eve.json", "suricata", nodeID, hostname, parseSuricataLine)
	}
	if cfg.Offload.Logs.CrowdSec.Enabled {
		s.wg.Add(1)
		go s.tailFileLoop(stopCh, "/var/log/crowdsec.log", "crowdsec", nodeID, hostname, nil)
	}
	if cfg.Offload.Logs.KeaDhcp.Enabled {
		s.wg.Add(1)
		go s.tailFileLoop(stopCh, "/var/log/axonwall/kea-dhcp4.log", "kea", nodeID, hostname, nil)
	}
	if cfg.Offload.Logs.Journald.Enabled || cfg.Offload.Logs.UnboundDns.Enabled {
		s.wg.Add(1)
		go s.journaldLoop(stopCh, cfg, nodeID, hostname)
	}

	s.wg.Add(1)
	go s.batchAndFlushLoop(stopCh, stopCtx, cfg)
}

func (s *LogShipper) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	stopCh := s.stopCh
	stopCancel := s.stopCancel
	s.running = false
	s.mu.Unlock()

	s.nflog.Stop()
	if stopCancel != nil {
		stopCancel()
	}
	close(stopCh)
	s.wg.Wait()
	s.mu.Lock()
	if s.httpTransport != nil {
		s.httpTransport.CloseIdleConnections()
	}
	s.mu.Unlock()
}

func (s *LogShipper) batchAndFlushLoop(stopCh chan struct{}, stopCtx context.Context, cfg *ObservabilityRuntimeBundle) {
	defer s.wg.Done()
	flushSec := cfg.Offload.Logs.FlushIntervalSec
	if flushSec < 1 {
		flushSec = 5
	}
	maxBatch := cfg.Offload.Logs.BatchSize
	if maxBatch <= 0 {
		maxBatch = 256
	}
	tk := time.NewTicker(time.Duration(flushSec) * time.Second)
	defer tk.Stop()

	batch := make([]StructuredLogEntry, 0, maxBatch)
	flush := func() {
		if len(batch) > 0 {
			if gz, err := EncodeVictoriaLogsGzipNDJSON(batch); err == nil && len(gz) > 0 {
				s.queue.Push(gz)
			}
			batch = batch[:0]
		}
		s.flushQueue(stopCtx, cfg)
	}

	for {
		select {
		case <-stopCh:
			flush()
			return
		case ent := <-s.eventCh:
			batch = append(batch, ent)
			if len(batch) >= maxBatch {
				flush()
			}
		case <-tk.C:
			flush()
		}
	}
}

func (s *LogShipper) recordRetryableFailure(errMsg string) {
	s.mu.Lock()
	if s.retryBackoff <= 0 {
		s.retryBackoff = 2 * time.Second
	} else {
		s.retryBackoff *= 2
		if s.retryBackoff > 60*time.Second {
			s.retryBackoff = 60 * time.Second
		}
	}
	s.nextRetryAt = time.Now().Add(s.retryBackoff)
	s.mu.Unlock()
	s.lastErr.Store(errMsg)
}

func (s *LogShipper) resetRetryBackoff() {
	s.mu.Lock()
	s.retryBackoff = 0
	s.nextRetryAt = time.Time{}
	s.mu.Unlock()
}

func (s *LogShipper) flushQueue(parentCtx context.Context, cfg *ObservabilityRuntimeBundle) {
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	if parentCtx.Err() != nil {
		return
	}
	targetURL := cfg.Offload.ResolvedVictoriaLogsURLOrDefault()
	if targetURL == "" {
		return
	}

	s.mu.RLock()
	client := s.httpClient
	clientErr := s.httpClientErr
	nextRetry := s.nextRetryAt
	s.mu.RUnlock()

	if !nextRetry.IsZero() && time.Now().Before(nextRetry) {
		return
	}
	if clientErr != nil {
		s.lastErr.Store(clientErr.Error())
		return
	}
	if client == nil {
		var tr *http.Transport
		client, tr, clientErr = buildObservabilityHTTPClient(cfg, targetURL)
		if clientErr != nil {
			s.lastErr.Store(clientErr.Error())
			return
		}
		s.mu.Lock()
		if s.httpClient == nil {
			s.httpClient = client
			s.httpTransport = tr
		} else {
			if tr != nil {
				tr.CloseIdleConnections()
			}
			client = s.httpClient
		}
		s.mu.Unlock()
	}

	batches := s.queue.PeekBatch(8)
	if len(batches) == 0 {
		return
	}
	token := strings.TrimSpace(cfg.Offload.IngestToken)
	if token == "" {
		token = strings.TrimSpace(cfg.VictoriaLogs.BearerToken)
	}

	for _, gzBody := range batches {
		if parentCtx.Err() != nil {
			return
		}
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(gzBody))
		if err != nil {
			cancel()
			s.recordRetryableFailure(err.Error())
			return
		}
		req.Header.Set("Content-Type", "application/stream+json")
		req.Header.Set("Content-Encoding", "gzip")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			s.recordRetryableFailure(err.Error())
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		cancel()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			s.queue.AckBatch(1)
			s.queue.MarkSent(1)
			s.resetRetryBackoff()
			s.lastPushAt.Store(time.Now().UnixMilli())
			s.lastErr.Store("")
			continue
		}
		if resp.StatusCode >= 400 && resp.StatusCode < 500 &&
			resp.StatusCode != http.StatusRequestTimeout &&
			resp.StatusCode != http.StatusTooManyRequests {
			s.queue.AckBatch(1)
			s.queue.MarkDropped(1)
			s.lastErr.Store(fmt.Sprintf("HTTP %d from VictoriaLogs ingest (dropped non-retryable batch)", resp.StatusCode))
			continue
		}
		s.recordRetryableFailure(fmt.Sprintf("HTTP %d from VictoriaLogs ingest", resp.StatusCode))
		return
	}
}

// EncodeVictoriaLogsGzipNDJSON marshals StructuredLogEntries into gzip-compressed NDJSON
// compatible with VictoriaLogs `/insert/jsonline`.
func EncodeVictoriaLogsGzipNDJSON(entries []StructuredLogEntry) ([]byte, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	for _, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		_, _ = gz.Write(b)
		_, _ = gz.Write([]byte{'\n'})
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *LogShipper) tailFileLoop(
	stopCh chan struct{},
	path string,
	source string,
	nodeID string,
	hostname string,
	parser func(line, nodeID, hostname string) (StructuredLogEntry, bool),
) {
	defer s.wg.Done()
	var offset int64
	var lastInode uint64
	seekEndOnOpen := true

	tk := time.NewTicker(1 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-tk.C:
			st, err := os.Stat(path)
			if err != nil {
				continue
			}
			var curInode uint64
			if statT, ok := st.Sys().(*syscall.Stat_t); ok {
				curInode = statT.Ino
			}
			if curInode != lastInode {
				lastInode = curInode
				if seekEndOnOpen {
					offset = st.Size()
					seekEndOnOpen = false
					continue
				}
				offset = 0
			} else if st.Size() < offset {
				offset = 0 // file rotated/truncated
			}
			if st.Size() == offset {
				continue
			}
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				_ = f.Close()
				continue
			}
			r := bufio.NewReaderSize(f, 64*1024)
			for {
				line, rerr := r.ReadString('\n')
				if len(line) > 0 && strings.HasSuffix(line, "\n") {
					offset += int64(len(line))
					trimmed := strings.TrimSpace(line)
					if trimmed != "" {
						if parser != nil {
							if ent, ok := parser(trimmed, nodeID, hostname); ok {
								s.Enqueue(ent)
							}
						} else {
							s.Enqueue(StructuredLogEntry{
								Time:     time.Now().UTC().Format(time.RFC3339Nano),
								Msg:      trimmed,
								NodeID:   nodeID,
								Hostname: hostname,
								Source:   source,
								Level:    inferLogLevel(trimmed),
							})
						}
					}
				}
				if rerr != nil {
					break
				}
			}
			_ = f.Close()
		}
	}
}

func parseSuricataLine(line, nodeID, hostname string) (StructuredLogEntry, bool) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return StructuredLogEntry{}, false
	}
	evType, _ := raw["event_type"].(string)
	if evType == "" {
		evType = "eve"
	}
	srcIP, _ := raw["src_ip"].(string)
	dstIP, _ := raw["dest_ip"].(string)
	proto, _ := raw["proto"].(string)
	ts, _ := raw["timestamp"].(string)
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339Nano)
	}
	msg := fmt.Sprintf("Suricata %s %s %s -> %s", evType, proto, srcIP, dstIP)
	level := "info"
	if alertObj, ok := raw["alert"].(map[string]any); ok {
		sig, _ := alertObj["signature"].(string)
		level = "warn"
		msg = fmt.Sprintf("Suricata ALERT [%s] %s -> %s (%s)", sig, srcIP, dstIP, proto)
	}
	var dPort uint16
	if p, ok := raw["dest_port"].(float64); ok && p > 0 {
		dPort = uint16(p)
	}
	return StructuredLogEntry{
		Time:     ts,
		Msg:      msg,
		NodeID:   nodeID,
		Hostname: hostname,
		Source:   "suricata",
		Level:    level,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		DstPort:  dPort,
		Protocol: proto,
	}, true
}

func buildJournalctlArgs(cfg *ObservabilityRuntimeBundle) []string {
	args := []string{"-f", "-o", "json", "-n", "0"}
	if cfg == nil {
		return args
	}
	hasExplicitUnits := false
	hasUnbound := false
	if cfg.Offload.Logs.Journald.Enabled {
		for _, u := range cfg.Offload.Logs.Journald.Units {
			if u = strings.TrimSpace(u); u != "" {
				args = append(args, "-u", u)
				hasExplicitUnits = true
				if u == "unbound" || u == "unbound.service" {
					hasUnbound = true
				}
			}
		}
	}
	if cfg.Offload.Logs.UnboundDns.Enabled && !hasUnbound {
		if !cfg.Offload.Logs.Journald.Enabled || hasExplicitUnits {
			args = append(args, "-u", "unbound")
		}
	}
	return args
}

func (s *LogShipper) journaldLoop(stopCh chan struct{}, cfg *ObservabilityRuntimeBundle, nodeID, hostname string) {
	defer s.wg.Done()
	jPath, err := exec.LookPath("journalctl")
	if err != nil {
		return
	}
	for {
		select {
		case <-stopCh:
			return
		default:
		}
		ctx, cancel := context.WithCancel(context.Background())
		args := buildJournalctlArgs(cfg)

		cmd := exec.CommandContext(ctx, jPath, args...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			cancel()
			return
		}
		if err := cmd.Start(); err != nil {
			cancel()
			log.Printf("[Observability] journalctl shipper warning: %v", err)
			return
		}

		doneWait := make(chan struct{})
		go func() {
			select {
			case <-stopCh:
				cancel()
			case <-doneWait:
			}
		}()

		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 512*1024)
		for sc.Scan() {
			var j map[string]any
			if json.Unmarshal(sc.Bytes(), &j) != nil {
				continue
			}
			msg, _ := j["MESSAGE"].(string)
			unit, _ := j["_SYSTEMD_UNIT"].(string)
			if msg == "" {
				continue
			}
			isUnbound := strings.Contains(unit, "unbound") || strings.Contains(strings.ToLower(msg), "info:") && strings.Contains(msg, " IN ")
			if isUnbound && !cfg.Offload.Logs.UnboundDns.Enabled {
				continue
			}
			if !isUnbound && !cfg.Offload.Logs.Journald.Enabled {
				continue
			}
			src := "journald"
			if isUnbound {
				src = "unbound"
			}
			ent := StructuredLogEntry{
				Time:     time.Now().UTC().Format(time.RFC3339Nano),
				Msg:      msg,
				NodeID:   nodeID,
				Hostname: hostname,
				Source:   src,
				Level:    inferLogLevel(msg),
				Fields:   map[string]any{"unit": unit},
			}
			if usStr, ok := j["__REALTIME_TIMESTAMP"].(string); ok {
				var us int64
				if _, err := fmt.Sscanf(usStr, "%d", &us); err == nil && us > 0 {
					ent.Time = time.Unix(us/1_000_000, (us%1_000_000)*1000).UTC().Format(time.RFC3339Nano)
				}
			}
			s.Enqueue(ent)
		}
		_ = cmd.Wait()
		close(doneWait)
		cancel()

		select {
		case <-stopCh:
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func inferLogLevel(msg string) string {
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "crit") || strings.Contains(low, "fatal") || strings.Contains(low, "panic"):
		return "error"
	case strings.Contains(low, "err"):
		return "error"
	case strings.Contains(low, "warn") || strings.Contains(low, "drop") || strings.Contains(low, "block"):
		return "warn"
	default:
		return "info"
	}
}
