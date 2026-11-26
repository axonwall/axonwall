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
	mu          sync.RWMutex
	cfg         *ObservabilityRuntimeBundle
	running     bool
	stopCh      chan struct{}
	wg          sync.WaitGroup
	queue       *TelemetryQueue
	nflog       *NflogReader
	eventCh     chan StructuredLogEntry
	lastPushAt  atomic.Int64
	lastErr     atomic.Value
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
	s.mu.Lock()
	s.cfg = b
	s.mu.Unlock()
	s.queue.Configure(
		b.Offload.Buffer.MaxMemoryMB,
		b.Offload.Buffer.DiskSpoolEnabled,
		b.Offload.Buffer.DiskSpoolDir,
		b.Offload.Buffer.DiskSpoolMaxMB,
	)

	if !b.Offload.Enabled || !b.Offload.Logs.Enabled || b.Offload.ResolvedVictoriaLogsURLOrDefault() == "" {
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
	s.stopCh = stopCh
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
	go s.batchAndFlushLoop(stopCh, cfg)
}

func (s *LogShipper) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	stopCh := s.stopCh
	s.running = false
	s.mu.Unlock()

	s.nflog.Stop()
	close(stopCh)
	s.wg.Wait()
}

func (s *LogShipper) batchAndFlushLoop(stopCh chan struct{}, cfg *ObservabilityRuntimeBundle) {
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
		s.flushQueue(cfg)
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

func (s *LogShipper) flushQueue(cfg *ObservabilityRuntimeBundle) {
	targetURL := cfg.Offload.ResolvedVictoriaLogsURLOrDefault()
	if targetURL == "" {
		return
	}
	batches := s.queue.PopBatch(8)
	if len(batches) == 0 {
		return
	}
	client := &http.Client{Timeout: 6 * time.Second}
	if strings.HasPrefix(targetURL, "https://") {
		if tlsCfg, err := buildTLSConfigFromBundleParams(
			cfg.Offload.UseHaMtls,
			cfg.Offload.TLSCACert,
			"", "", "",
			cfg.Offload.TLSInsecureSkipVerify,
			false,
			false,
		); err == nil {
			client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
		}
	}
	token := strings.TrimSpace(cfg.Offload.IngestToken)
	if token == "" {
		token = strings.TrimSpace(cfg.VictoriaLogs.BearerToken)
	}

	for idx, gzBody := range batches {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(gzBody))
		if err != nil {
			cancel()
			s.queue.RequeueFront(batches[idx:])
			s.lastErr.Store(err.Error())
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
			s.queue.RequeueFront(batches[idx:])
			s.lastErr.Store(err.Error())
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			s.queue.RequeueFront(batches[idx:])
			s.lastErr.Store(fmt.Sprintf("HTTP %d from VictoriaLogs ingest", resp.StatusCode))
			return
		}
		s.queue.MarkSent(1)
		s.lastPushAt.Store(time.Now().UnixMilli())
		s.lastErr.Store("")
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
				if len(line) > 0 {
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
		args := []string{"-f", "-o", "json", "-n", "0"}
		if cfg.Offload.Logs.Journald.Enabled {
			for _, u := range cfg.Offload.Logs.Journald.Units {
				if u = strings.TrimSpace(u); u != "" {
					args = append(args, "-u", u)
				}
			}
		} else if cfg.Offload.Logs.UnboundDns.Enabled {
			args = append(args, "-u", "unbound")
		}

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
