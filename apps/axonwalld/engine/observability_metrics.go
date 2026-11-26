package engine

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/snappy"
	"google.golang.org/protobuf/encoding/protowire"
)

type GatewayProbeStats struct {
	Name          string  `json:"name"`
	Interface     string  `json:"interface"`
	MonitorIP     string  `json:"monitorIp"`
	Up            bool    `json:"up"`
	RttMs         float64 `json:"rttMs"`
	JitterMs      float64 `json:"jitterMs"`
	PacketLossPct float64 `json:"packetLossPct"`
	LastProbeUnix int64   `json:"lastProbeUnix"`
}

type PromLabel struct {
	Name  string
	Value string
}

type PromMetricSample struct {
	Name        string
	Labels      []PromLabel
	Value       float64
	TimestampMs int64
}

type MetricsShipper struct {
	mu            sync.RWMutex
	cfg           *ObservabilityRuntimeBundle
	running       bool
	stopCh        chan struct{}
	wg            sync.WaitGroup
	httpSrv       *http.Server
	httpClient    *http.Client
	httpTransport *http.Transport
	httpClientErr error
	queue         *TelemetryQueue
	ebpf          *EBPFManager
	hardware      *HardwareManager
	nas           *NasManager
	sdwanFn       func() []GatewayProbeStats
	extraStatsFn  func() []TelemetryQueueStats

	prevCpuTotal uint64
	prevCpuIdle  uint64
	hasPrevCpu   bool

	lastSamplesMu sync.RWMutex
	lastSamples   []PromMetricSample
	lastPushAt    atomic.Int64
	lastErr       atomic.Value
}

func NewMetricsShipper(
	ebpf *EBPFManager,
	hardware *HardwareManager,
	nas *NasManager,
	sdwanFn func() []GatewayProbeStats,
) *MetricsShipper {
	return &MetricsShipper{
		queue:    NewTelemetryQueue("metrics-remote-write", 24, false, "/var/lib/axonwall/telemetry-spool", 256),
		ebpf:     ebpf,
		hardware: hardware,
		nas:      nas,
		sdwanFn:  sdwanFn,
	}
}

func (m *MetricsShipper) SetExtraQueueStatsProvider(fn func() []TelemetryQueueStats) {
	m.mu.Lock()
	m.extraStatsFn = fn
	m.mu.Unlock()
}

func (m *MetricsShipper) ApplyConfig(b *ObservabilityRuntimeBundle) {
	m.Stop()
	if b == nil {
		return
	}
	targetURL := b.Offload.ResolvedRemoteWriteUrlOrDefault()
	client, tr, clientErr := buildObservabilityHTTPClient(b, targetURL)
	m.mu.Lock()
	if m.httpTransport != nil {
		m.httpTransport.CloseIdleConnections()
	}
	m.cfg = b
	m.httpClient = client
	m.httpTransport = tr
	m.httpClientErr = clientErr
	m.mu.Unlock()
	m.queue.Configure(
		b.Offload.Buffer.MaxMemoryMB,
		b.Offload.Buffer.DiskSpoolEnabled,
		b.Offload.Buffer.DiskSpoolDir,
		b.Offload.Buffer.DiskSpoolMaxMB,
	)

	shouldRun := (b.Offload.Enabled && b.Offload.Metrics.Enabled && targetURL != "") ||
		b.Offload.Metrics.ExposeScrape
	if !shouldRun {
		return
	}
	m.Start()
}

func (m *MetricsShipper) Start() {
	m.mu.Lock()
	if m.running || m.cfg == nil {
		m.mu.Unlock()
		return
	}
	cfg := m.cfg
	stopCh := make(chan struct{})
	m.stopCh = stopCh
	m.running = true
	m.mu.Unlock()

	if cfg.Offload.Metrics.ExposeScrape {
		bind := strings.TrimSpace(cfg.Offload.Metrics.ScrapeBind)
		if bind == "" {
			bind = "127.0.0.1"
		}
		port := cfg.Offload.Metrics.ScrapePort
		if port <= 0 {
			port = 9100
		}
		addr := net.JoinHostPort(bind, strconv.Itoa(port))
		mux := http.NewServeMux()
		scrapeToken := strings.TrimSpace(cfg.Offload.Metrics.ScrapeToken)
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			if scrapeToken != "" {
				auth := strings.TrimSpace(r.Header.Get("Authorization"))
				if auth != "Bearer "+scrapeToken {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			m.WritePrometheusMetrics(w)
		})
		srv := &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 3 * time.Second,
		}
		m.mu.Lock()
		m.httpSrv = srv
		m.mu.Unlock()
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[Observability] Metrics scrape listener (%s) warning: %v", addr, err)
			}
		}()
	}

	m.wg.Add(1)
	go m.collectLoop(stopCh)
}

func (m *MetricsShipper) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	stopCh := m.stopCh
	srv := m.httpSrv
	m.httpSrv = nil
	m.running = false
	m.mu.Unlock()

	close(stopCh)
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
	}
	m.wg.Wait()
	m.mu.Lock()
	if m.httpTransport != nil {
		m.httpTransport.CloseIdleConnections()
	}
	m.mu.Unlock()
}

func (m *MetricsShipper) collectLoop(stopCh chan struct{}) {
	defer m.wg.Done()
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()
	if cfg == nil {
		return
	}
	intervalSec := cfg.Offload.Metrics.IntervalSec
	if intervalSec < 5 {
		intervalSec = 15
	}
	// Initial sample so cached scrape output is warm immediately
	m.tickOnce(cfg)

	tk := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-tk.C:
			m.mu.RLock()
			cur := m.cfg
			m.mu.RUnlock()
			if cur != nil {
				m.tickOnce(cur)
			}
		}
	}
}

func (m *MetricsShipper) tickOnce(cfg *ObservabilityRuntimeBundle) {
	samples := m.collectAllSamples(cfg)
	m.lastSamplesMu.Lock()
	m.lastSamples = samples
	m.lastSamplesMu.Unlock()

	if cfg.Offload.Enabled && cfg.Offload.Metrics.Enabled && cfg.Offload.ResolvedRemoteWriteUrlOrDefault() != "" && len(samples) > 0 {
		rawPb := EncodePrometheusRemoteWrite(samples)
		compressed := snappy.Encode(nil, rawPb)
		m.queue.Push(compressed)
		m.flushQueue(cfg)
	}
}

func (m *MetricsShipper) flushQueue(cfg *ObservabilityRuntimeBundle) {
	targetURL := cfg.Offload.ResolvedRemoteWriteUrlOrDefault()
	if targetURL == "" {
		return
	}
	m.mu.RLock()
	client := m.httpClient
	clientErr := m.httpClientErr
	m.mu.RUnlock()
	if clientErr != nil {
		m.lastErr.Store(clientErr.Error())
		return
	}
	if client == nil {
		var tr *http.Transport
		client, tr, clientErr = buildObservabilityHTTPClient(cfg, targetURL)
		if clientErr != nil {
			m.lastErr.Store(clientErr.Error())
			return
		}
		m.mu.Lock()
		if m.httpClient == nil {
			m.httpClient = client
			m.httpTransport = tr
		} else {
			if tr != nil {
				tr.CloseIdleConnections()
			}
			client = m.httpClient
		}
		m.mu.Unlock()
	}

	batches := m.queue.PeekBatch(8)
	if len(batches) == 0 {
		return
	}
	token := strings.TrimSpace(cfg.Offload.IngestToken)
	if token == "" {
		token = strings.TrimSpace(cfg.VictoriaMetrics.BearerToken)
	}

	for _, body := range batches {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
		if err != nil {
			cancel()
			m.lastErr.Store(err.Error())
			return
		}
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.Header.Set("Content-Encoding", "snappy")
		req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			m.lastErr.Store(err.Error())
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			m.lastErr.Store(fmt.Sprintf("HTTP %d from VictoriaMetrics remote-write", resp.StatusCode))
			return
		}
		m.queue.AckBatch(1)
		m.queue.MarkSent(1)
		m.lastPushAt.Store(time.Now().UnixMilli())
		m.lastErr.Store("")
	}
}

func buildObservabilityHTTPClient(cfg *ObservabilityRuntimeBundle, targetURL string) (*http.Client, *http.Transport, error) {
	tr := &http.Transport{}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(targetURL)), "https://") {
		tlsCfg, err := buildTLSConfigFromBundleParams(
			cfg.Offload.UseHaMtls,
			cfg.Offload.TLSCACert,
			"", "", "",
			cfg.Offload.TLSInsecureSkipVerify,
			false,
			false,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("TLS config error for %s: %w", targetURL, err)
		}
		tr.TLSClientConfig = tlsCfg
	}
	return &http.Client{Timeout: 6 * time.Second, Transport: tr}, tr, nil
}

func (m *MetricsShipper) collectAllSamples(cfg *ObservabilityRuntimeBundle) []PromMetricSample {
	nowMs := time.Now().UnixMilli()
	nodeID := strings.TrimSpace(cfg.NodeID)
	hostname := strings.TrimSpace(cfg.Hostname)
	if nodeID == "" {
		nodeID = firstNonEmpty(hostname, "axonwall")
	}
	if hostname == "" {
		hostname = nodeID
	}

	var out []PromMetricSample
	add := func(name string, val float64, extra ...PromLabel) {
		if math.IsNaN(val) || math.IsInf(val, 0) {
			return
		}
		labels := make([]PromLabel, 0, 2+len(extra))
		labels = append(labels, PromLabel{Name: "node_id", Value: nodeID})
		labels = append(labels, PromLabel{Name: "hostname", Value: hostname})
		labels = append(labels, extra...)
		out = append(out, PromMetricSample{
			Name:        name,
			Labels:      labels,
			Value:       val,
			TimestampMs: nowMs,
		})
	}

	// 0. Host/agent liveness
	add("axonwall_up", 1)

	// 1. CPU & Load
	if cpuPct, ok := m.sampleCPUPercent(); ok {
		add("axonwall_host_cpu_usage_percent", cpuPct)
	}
	if l1, l5, l15, ok := readLoadAvg(); ok {
		add("axonwall_host_load", l1, PromLabel{Name: "period", Value: "1m"})
		add("axonwall_host_load", l5, PromLabel{Name: "period", Value: "5m"})
		add("axonwall_host_load", l15, PromLabel{Name: "period", Value: "15m"})
	}

	// 2. Memory
	if totalB, availB, usedB, ok := readMemInfoBytes(); ok {
		add("axonwall_host_memory_total_bytes", float64(totalB))
		add("axonwall_host_memory_available_bytes", float64(availB))
		add("axonwall_host_memory_used_bytes", float64(usedB))
	}

	// 3. Interfaces (/proc/net/dev + role mapping + operstate)
	roleByDev := make(map[string]string, len(cfg.Interfaces))
	for _, ifc := range cfg.Interfaces {
		if ifc.Device != "" {
			roleByDev[ifc.Device] = ifc.Role
		}
	}
	for _, nic := range readProcNetDevCounters() {
		if nic.Name == "lo" {
			continue
		}
		role := roleByDev[nic.Name]
		if role == "" {
			role = "other"
		}
		upVal := 0.0
		if stateB, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/operstate", nic.Name)); err == nil {
			st := strings.TrimSpace(string(stateB))
			if st == "up" || st == "unknown" {
				upVal = 1.0
			}
		}
		add("axonwall_interface_up", upVal, PromLabel{Name: "interface", Value: nic.Name}, PromLabel{Name: "role", Value: role})
		add("axonwall_interface_rx_bytes_total", float64(nic.RxBytes), PromLabel{Name: "interface", Value: nic.Name}, PromLabel{Name: "role", Value: role})
		add("axonwall_interface_tx_bytes_total", float64(nic.TxBytes), PromLabel{Name: "interface", Value: nic.Name}, PromLabel{Name: "role", Value: role})
		add("axonwall_interface_rx_packets_total", float64(nic.RxPackets), PromLabel{Name: "interface", Value: nic.Name}, PromLabel{Name: "role", Value: role})
		add("axonwall_interface_tx_packets_total", float64(nic.TxPackets), PromLabel{Name: "interface", Value: nic.Name}, PromLabel{Name: "role", Value: role})
		add("axonwall_interface_rx_errors_total", float64(nic.RxErrors), PromLabel{Name: "interface", Value: nic.Name}, PromLabel{Name: "role", Value: role})
		add("axonwall_interface_tx_errors_total", float64(nic.TxErrors), PromLabel{Name: "interface", Value: nic.Name}, PromLabel{Name: "role", Value: role})
		add("axonwall_interface_rx_drops_total", float64(nic.RxDrops), PromLabel{Name: "interface", Value: nic.Name}, PromLabel{Name: "role", Value: role})
		add("axonwall_interface_tx_drops_total", float64(nic.TxDrops), PromLabel{Name: "interface", Value: nic.Name}, PromLabel{Name: "role", Value: role})
	}

	// 4. Conntrack
	if cur, ok := readSingleUint64File("/proc/sys/net/netfilter/nf_conntrack_count"); ok {
		add("axonwall_conntrack_entries", float64(cur))
	}
	if maxC, ok := readSingleUint64File("/proc/sys/net/netfilter/nf_conntrack_max"); ok {
		add("axonwall_conntrack_max", float64(maxC))
	}

	// 5. XDP verdict counters
	if m.ebpf != nil {
		snap := m.ebpf.GetDataplaneSnapshot(1)
		if snap.Running {
			add("axonwall_xdp_pass_total", float64(snap.Stats.XdpPass))
			add("axonwall_xdp_drop_total", float64(snap.Stats.XdpDrop))
			add("axonwall_xdp_syn_flood_drops_total", float64(snap.Stats.SynFloodDrops))
			add("axonwall_xdp_lpm_cidr_drops_total", float64(snap.Stats.LpmCidrDrops))
		}
	}

	// 6. SD-WAN gateway RTT, jitter, packet loss
	if m.sdwanFn != nil {
		for _, gw := range m.sdwanFn() {
			upV := 0.0
			if gw.Up {
				upV = 1.0
			}
			lbls := []PromLabel{
				{Name: "gateway", Value: gw.Name},
				{Name: "interface", Value: gw.Interface},
				{Name: "monitor_ip", Value: gw.MonitorIP},
			}
			add("axonwall_sdwan_gateway_up", upV, lbls...)
			add("axonwall_sdwan_gateway_rtt_ms", gw.RttMs, lbls...)
			add("axonwall_sdwan_gateway_jitter_ms", gw.JitterMs, lbls...)
			add("axonwall_sdwan_gateway_packet_loss_percent", gw.PacketLossPct, lbls...)
		}
	}

	// 7. Hardware sensors & fans
	if m.hardware != nil {
		if hw, err := m.hardware.CollectTelemetry(); err == nil && hw != nil {
			for _, t := range hw.Temperatures {
				add("axonwall_hardware_temp_celsius", t.Value, PromLabel{Name: "sensor", Value: t.Label})
			}
			for _, fan := range hw.Fans {
				add("axonwall_hardware_fan_rpm", float64(fan.RPM), PromLabel{Name: "sensor", Value: fan.Label})
			}
		}
	}

	// 8. ZFS ARC & pools (when ZFS kernel module loaded)
	if arcBytes, err := os.ReadFile("/proc/spl/kstat/zfs/arcstats"); err == nil {
		arc := ParseZfsArcstats(string(arcBytes))
		if arc.Available {
			add("axonwall_zfs_arc_size_bytes", float64(arc.SizeBytes))
		}
		if m.nas != nil {
			for _, p := range m.nas.ListPools() {
				healthVal := 1.0
				if strings.ToUpper(p.Health) != "ONLINE" {
					healthVal = 0.0
				}
				add("axonwall_zfs_pool_health", healthVal, PromLabel{Name: "pool", Value: p.Name})
			}
		}
	}

	// 9. Telemetry shipper queue stats
	allStats := []TelemetryQueueStats{m.queue.Stats()}
	m.mu.RLock()
	extraFn := m.extraStatsFn
	m.mu.RUnlock()
	if extraFn != nil {
		allStats = append(allStats, extraFn()...)
	}
	for _, st := range allStats {
		add("axonwall_telemetry_shipper_queued_bytes", float64(st.QueuedBytes+st.DiskSpoolBytes), PromLabel{Name: "stream", Value: st.Name})
		add("axonwall_telemetry_shipper_dropped_total", float64(st.DroppedTotal), PromLabel{Name: "stream", Value: st.Name})
		add("axonwall_telemetry_shipper_sent_total", float64(st.SentTotal), PromLabel{Name: "stream", Value: st.Name})
	}

	return out
}

func (m *MetricsShipper) WritePrometheusMetrics(w io.Writer) {
	m.lastSamplesMu.RLock()
	samples := make([]PromMetricSample, len(m.lastSamples))
	copy(samples, m.lastSamples)
	m.lastSamplesMu.RUnlock()

	if len(samples) == 0 {
		m.mu.RLock()
		cfg := m.cfg
		m.mu.RUnlock()
		if cfg != nil {
			samples = m.collectAllSamples(cfg)
		}
	}

	sort.Slice(samples, func(i, j int) bool {
		if samples[i].Name != samples[j].Name {
			return samples[i].Name < samples[j].Name
		}
		return len(samples[i].Labels) < len(samples[j].Labels)
	})

	lastMetric := ""
	for _, s := range samples {
		if s.Name != lastMetric {
			fmt.Fprintf(w, "# TYPE %s gauge\n", s.Name)
			lastMetric = s.Name
		}
		if len(s.Labels) == 0 {
			fmt.Fprintf(w, "%s %g\n", s.Name, s.Value)
			continue
		}
		var lb strings.Builder
		lb.WriteByte('{')
		for idx, l := range s.Labels {
			if idx > 0 {
				lb.WriteByte(',')
			}
			lb.WriteString(l.Name)
			lb.WriteString(`="`)
			lb.WriteString(escapePromLabelVal(l.Value))
			lb.WriteByte('"')
		}
		lb.WriteByte('}')
		fmt.Fprintf(w, "%s%s %g\n", s.Name, lb.String(), s.Value)
	}
}

func (m *MetricsShipper) Status() (TelemetryQueueStats, int64, string) {
	errStr, _ := m.lastErr.Load().(string)
	return m.queue.Stats(), m.lastPushAt.Load(), errStr
}

// EncodePrometheusRemoteWrite encodes PromMetricSamples into a Prometheus WriteRequest protobuf.
func EncodePrometheusRemoteWrite(samples []PromMetricSample) []byte {
	var out []byte
	for _, s := range samples {
		labels := make([]PromLabel, 0, len(s.Labels)+1)
		labels = append(labels, PromLabel{Name: "__name__", Value: s.Name})
		labels = append(labels, s.Labels...)
		sort.Slice(labels, func(i, j int) bool { return labels[i].Name < labels[j].Name })

		var tsBuf []byte
		for _, l := range labels {
			var lb []byte
			lb = protowire.AppendTag(lb, 1, protowire.BytesType)
			lb = protowire.AppendString(lb, l.Name)
			lb = protowire.AppendTag(lb, 2, protowire.BytesType)
			lb = protowire.AppendString(lb, l.Value)
			tsBuf = protowire.AppendTag(tsBuf, 1, protowire.BytesType)
			tsBuf = protowire.AppendBytes(tsBuf, lb)
		}

		var sb []byte
		sb = protowire.AppendTag(sb, 1, protowire.Fixed64Type)
		sb = protowire.AppendFixed64(sb, math.Float64bits(s.Value))
		sb = protowire.AppendTag(sb, 2, protowire.VarintType)
		sb = protowire.AppendVarint(sb, uint64(s.TimestampMs))
		tsBuf = protowire.AppendTag(tsBuf, 2, protowire.BytesType)
		tsBuf = protowire.AppendBytes(tsBuf, sb)

		out = protowire.AppendTag(out, 1, protowire.BytesType)
		out = protowire.AppendBytes(out, tsBuf)
	}
	return out
}

func (m *MetricsShipper) sampleCPUPercent() (float64, bool) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, false
	}
	line := strings.SplitN(string(b), "\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, false
	}
	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			continue
		}
		total += v
		if i == 4 || i == 5 { // idle + iowait
			idle += v
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.hasPrevCpu {
		m.prevCpuTotal = total
		m.prevCpuIdle = idle
		m.hasPrevCpu = true
		return 0, false
	}
	if total <= m.prevCpuTotal || idle < m.prevCpuIdle {
		m.prevCpuTotal = total
		m.prevCpuIdle = idle
		return 0, false
	}
	dTotal := total - m.prevCpuTotal
	dIdle := idle - m.prevCpuIdle
	m.prevCpuTotal = total
	m.prevCpuIdle = idle
	if dIdle > dTotal {
		return 0, false
	}
	return (float64(dTotal-dIdle) / float64(dTotal)) * 100.0, true
}

func readLoadAvg() (float64, float64, float64, bool) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, false
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return 0, 0, 0, false
	}
	l1, e1 := strconv.ParseFloat(fields[0], 64)
	l5, e5 := strconv.ParseFloat(fields[1], 64)
	l15, e15 := strconv.ParseFloat(fields[2], 64)
	if e1 != nil || e5 != nil || e15 != nil {
		return 0, 0, 0, false
	}
	return l1, l5, l15, true
}

func readMemInfoBytes() (total, avail, used uint64, ok bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = kb * 1024
		case "MemAvailable:":
			avail = kb * 1024
		}
	}
	if total == 0 {
		return 0, 0, 0, false
	}
	if avail <= total {
		used = total - avail
	}
	return total, avail, used, true
}

type procNetDevEntry struct {
	Name      string
	RxBytes   uint64
	RxPackets uint64
	RxErrors  uint64
	RxDrops   uint64
	TxBytes   uint64
	TxPackets uint64
	TxErrors  uint64
	TxDrops   uint64
}

func readProcNetDevCounters() []procNetDevEntry {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []procNetDevEntry
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		if lineNo <= 2 {
			continue
		}
		line := strings.TrimSpace(sc.Text())
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 12 {
			continue
		}
		p := func(idx int) uint64 {
			v, _ := strconv.ParseUint(fields[idx], 10, 64)
			return v
		}
		out = append(out, procNetDevEntry{
			Name:      name,
			RxBytes:   p(0),
			RxPackets: p(1),
			RxErrors:  p(2),
			RxDrops:   p(3),
			TxBytes:   p(8),
			TxPackets: p(9),
			TxErrors:  p(10),
			TxDrops:   p(11),
		})
	}
	return out
}

func readSingleUint64File(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func escapePromLabelVal(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
