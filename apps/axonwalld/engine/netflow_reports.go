package engine

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Compute95thPercentile calculates nearest-rank 95th and 99th percentiles across bps samples.
func Compute95thPercentile(bpsSamples []float64) (p95, p99, peak, avg float64) {
	if len(bpsSamples) == 0 {
		return 0, 0, 0, 0
	}
	s := make([]float64, len(bpsSamples))
	copy(s, bpsSamples)
	sort.Float64s(s)

	var sum float64
	for _, v := range s {
		sum += v
	}
	avg = sum / float64(len(s))
	peak = s[len(s)-1]

	idx95 := int(math.Ceil(0.95*float64(len(s)))) - 1
	if idx95 < 0 {
		idx95 = 0
	}
	if idx95 >= len(s) {
		idx95 = len(s) - 1
	}
	p95 = s[idx95]

	idx99 := int(math.Ceil(0.99*float64(len(s)))) - 1
	if idx99 < 0 {
		idx99 = 0
	}
	if idx99 >= len(s) {
		idx99 = len(s) - 1
	}
	p99 = s[idx99]
	return p95, p99, peak, avg
}

// GeneratePercentileReport computes telecom-style 95th-percentile utilization over 5-minute buckets.
func GeneratePercentileReport(store *FlowStore, req NetFlowReportRequest) NetFlowReportResponse {
	days := req.RangeDays
	if days <= 0 || days > 90 {
		days = 7
	}
	groupBy := strings.ToLower(strings.TrimSpace(req.GroupBy))
	if groupBy == "" {
		groupBy = "interface"
	}
	const bucketSec = 300
	const bucketMs int64 = bucketSec * 1000

	endMs := time.Now().UnixMilli()
	startMs := endMs - int64(days)*24*3600*1000

	qRes := store.Query(FlowQueryRequest{
		StartMs: startMs,
		EndMs:   endMs,
		Limit:   1000,
	})
	flows := store.CollectFlowsInRange(startMs, endMs, 64)
	if len(flows) == 0 {
		flows = qRes.Flows
	}

	type grpAgg struct {
		buckets map[int64]uint64
		bytes   uint64
		flows   int
	}
	groups := make(map[string]*grpAgg)
	for _, f := range flows {
		key := reportGroupKey(&f, groupBy)
		g := groups[key]
		if g == nil {
			g = &grpAgg{buckets: make(map[int64]uint64)}
			groups[key] = g
		}
		bTs := (f.TimestampMs / bucketMs) * bucketMs
		g.buckets[bTs] += f.Bytes
		g.bytes += f.Bytes
		g.flows++
	}

	rows := make([]NetFlowPercentileRow, 0, len(groups))
	for key, g := range groups {
		samples := make([]float64, 0, len(g.buckets))
		for _, bytesInBucket := range g.buckets {
			samples = append(samples, float64(bytesInBucket*8)/float64(bucketSec))
		}
		p95, p99, peak, avg := Compute95thPercentile(samples)
		rows = append(rows, NetFlowPercentileRow{
			GroupKey:    key,
			P95Bps:      math.Round(p95*100) / 100,
			P99Bps:      math.Round(p99*100) / 100,
			PeakBps:     math.Round(peak*100) / 100,
			AvgBps:      math.Round(avg*100) / 100,
			TotalBytes:  g.bytes,
			TotalFlows:  g.flows,
			SampleCount: len(samples),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].P95Bps > rows[j].P95Bps })
	if len(rows) > 100 {
		rows = rows[:100]
	}

	rep := NetFlowReportResponse{
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		RangeDays:     days,
		StartMs:       startMs,
		EndMs:         endMs,
		GroupBy:       groupBy,
		BucketSeconds: bucketSec,
		Rows:          rows,
	}

	switch strings.ToLower(strings.TrimSpace(req.Format)) {
	case "csv":
		rep.Rendered = RenderReportCSV(&rep)
	case "markdown", "md":
		rep.Rendered = RenderReportMarkdown(&rep)
	case "json":
		raw, _ := json.MarshalIndent(&rep, "", "  ")
		rep.Rendered = string(raw)
	}
	return rep
}

func reportGroupKey(f *FlowRecord, groupBy string) string {
	switch groupBy {
	case "exporter":
		return firstNonEmpty(f.ExporterName, f.ExporterIP)
	case "vlan":
		if f.VlanID > 0 {
			return fmt.Sprintf("VLAN %d", f.VlanID)
		}
		return "Untagged"
	case "subnet":
		if addr, err := netip.ParseAddr(f.SrcIP); err == nil {
			bits := 24
			if addr.Is6() {
				bits = 64
			}
			return netip.PrefixFrom(addr, bits).Masked().String()
		}
		return f.SrcIP
	default:
		return firstNonEmpty(firstNonEmpty(f.InIfName, f.OutIfName), firstNonEmpty(f.ExporterName, f.ExporterIP))
	}
}

func RenderReportCSV(rep *NetFlowReportResponse) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"Group", "P95_Bps", "P99_Bps", "Peak_Bps", "Avg_Bps", "Total_Bytes", "Total_Flows", "5m_Samples"})
	for _, r := range rep.Rows {
		_ = w.Write([]string{
			r.GroupKey,
			strconv.FormatFloat(r.P95Bps, 'f', 2, 64),
			strconv.FormatFloat(r.P99Bps, 'f', 2, 64),
			strconv.FormatFloat(r.PeakBps, 'f', 2, 64),
			strconv.FormatFloat(r.AvgBps, 'f', 2, 64),
			strconv.FormatUint(r.TotalBytes, 10),
			strconv.Itoa(r.TotalFlows),
			strconv.Itoa(r.SampleCount),
		})
	}
	w.Flush()
	return buf.String()
}

func RenderReportMarkdown(rep *NetFlowReportResponse) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Axonwall NetFlow 95th-Percentile Bandwidth Report\n\n"))
	b.WriteString(fmt.Sprintf("- **Generated:** %s\n", rep.GeneratedAt))
	b.WriteString(fmt.Sprintf("- **Window:** Last %d day(s) (5-minute buckets)\n", rep.RangeDays))
	b.WriteString(fmt.Sprintf("- **Grouped By:** `%s`\n\n", rep.GroupBy))
	b.WriteString("| Group | 95th Pct | 99th Pct | Peak | Average | Total Bytes | Flows |\n")
	b.WriteString("| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n")
	for _, r := range rep.Rows {
		b.WriteString(fmt.Sprintf(
			"| %s | %s | %s | %s | %s | %d | %d |\n",
			r.GroupKey,
			formatReportBps(r.P95Bps),
			formatReportBps(r.P99Bps),
			formatReportBps(r.PeakBps),
			formatReportBps(r.AvgBps),
			r.TotalBytes,
			r.TotalFlows,
		))
	}
	return b.String()
}

func formatReportBps(bps float64) string {
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gbps", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.2f Mbps", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.1f Kbps", bps/1e3)
	default:
		return fmt.Sprintf("%.0f bps", bps)
	}
}

// GetReport computes a read-only 95th-percentile report without writing snapshots or webhooks.
func (m *NetFlowManager) GetReport(req NetFlowReportRequest) NetFlowReportResponse {
	if req.Format == "" {
		req.Format = "json"
	}
	rep := GeneratePercentileReport(m.store, req)
	m.mu.RLock()
	bundle := m.bundle
	m.mu.RUnlock()
	dataDir := "/var/lib/axonwall/netflow"
	if bundle != nil && bundle.Config.Storage.DataDir != "" {
		dataDir = bundle.Config.Storage.DataDir
	}
	rep.SavedSnapshots = listSavedReportSnapshots(filepath.Join(dataDir, "reports"))
	return rep
}

func (m *NetFlowManager) GenerateAndSaveReport(req NetFlowReportRequest) (NetFlowReportResponse, string, error) {
	if req.Format == "" {
		req.Format = "markdown"
	}
	rep := GeneratePercentileReport(m.store, req)

	m.mu.RLock()
	bundle := m.bundle
	m.mu.RUnlock()

	dataDir := "/var/lib/axonwall/netflow"
	retention := 30
	webhook := ""
	if bundle != nil {
		if bundle.Config.Storage.DataDir != "" {
			dataDir = bundle.Config.Storage.DataDir
		}
		if bundle.Config.Reporting.RetentionCount > 0 {
			retention = bundle.Config.Reporting.RetentionCount
		}
		webhook = bundle.Config.Reporting.WebhookURL
	}

	ext := "md"
	if req.Format == "csv" {
		ext = "csv"
	} else if req.Format == "json" {
		ext = "json"
	}

	reportsDir := filepath.Join(dataDir, "reports")
	var savedPath string
	if err := os.MkdirAll(reportsDir, 0750); err == nil {
		filename := fmt.Sprintf("netflow-p95-%s.%s", time.Now().UTC().Format("20060102-150405"), ext)
		savedPath = filepath.Join(reportsDir, filename)
		_ = os.WriteFile(savedPath, []byte(rep.Rendered), 0640)
		pruneOldReportSnapshots(reportsDir, retention)
	}
	rep.SavedSnapshots = listSavedReportSnapshots(reportsDir)

	if strings.HasPrefix(webhook, "http://") || strings.HasPrefix(webhook, "https://") {
		go func(u string, r NetFlowReportResponse) {
			client, tr := newSafeHTTPClient(SafeHTTPClientOptions{Timeout: 5 * time.Second})
			defer tr.CloseIdleConnections()
			postNetflowReportWebhookWithClient(u, r, client)
		}(webhook, rep)
	}
	return rep, savedPath, nil
}

func postNetflowReportWebhookWithClient(u string, r NetFlowReportResponse, client *http.Client) error {
	payload, _ := json.Marshal(map[string]any{
		"source": "axonwall-netflow-report",
		"report": r,
	})
	reqHTTP, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	reqHTTP.Header.Set("Content-Type", "application/json")
	if client == nil {
		var tr *http.Transport
		client, tr = newSafeHTTPClient(SafeHTTPClientOptions{Timeout: 5 * time.Second})
		defer tr.CloseIdleConnections()
	}
	resp, err := client.Do(reqHTTP)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func listSavedReportSnapshots(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if len(names) > 25 {
		names = names[:25]
	}
	return names
}

func pruneOldReportSnapshots(dir string, keep int) {
	if keep <= 0 {
		keep = 30
	}
	names := listSavedReportSnapshots(dir)
	for i := keep; i < len(names); i++ {
		_ = os.Remove(filepath.Join(dir, names[i]))
	}
}

func (m *NetFlowManager) reportingLoop(stopCh chan struct{}) {
	defer m.wg.Done()
	tk := time.NewTicker(10 * time.Minute)
	defer tk.Stop()
	var lastRun time.Time

	for {
		select {
		case <-stopCh:
			return
		case now := <-tk.C:
			m.mu.RLock()
			bundle := m.bundle
			m.mu.RUnlock()
			if bundle == nil || !bundle.Enabled || !bundle.Config.Reporting.Enabled {
				continue
			}
			interval := time.Duration(maxInt(1, bundle.Config.Reporting.IntervalHours)) * time.Hour
			if !lastRun.IsZero() && now.Sub(lastRun) < interval {
				continue
			}
			lastRun = now
			_, _, _ = m.GenerateAndSaveReport(NetFlowReportRequest{
				RangeDays: bundle.Config.Reporting.RangeDays,
				GroupBy:   bundle.Config.Reporting.GroupBy,
				Format:    bundle.Config.Reporting.Format,
			})
		}
	}
}
