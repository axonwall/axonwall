package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
)

type ObservabilityRuleMeta struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Interface   string `json:"interface"`
}

type ObservabilityOffloadConfigPayload struct {
	Enabled               bool                     `json:"enabled"`
	NodeID                string                   `json:"nodeId,omitempty"`
	HubURL                string                   `json:"hubUrl,omitempty"`
	CollectorHost         string                   `json:"collectorHost,omitempty"`
	CollectorPort         int                      `json:"collectorPort"`
	IPFIXTransport        string                   `json:"ipfixTransport"`
	IngestToken           string                   `json:"ingestToken,omitempty"`
	UseHaMtls             bool                     `json:"useHaMtls"`
	TLSCACert             string                   `json:"tlsCaCert,omitempty"`
	TLSInsecureSkipVerify bool                     `json:"tlsInsecureSkipVerify"`
	ResolvedRemoteWriteURL string                  `json:"resolvedRemoteWriteUrl"`
	ResolvedVictoriaLogsURL string                 `json:"resolvedVictoriaLogsUrl"`
	Metrics struct {
		Enabled        bool   `json:"enabled"`
		RemoteWriteURL string `json:"remoteWriteUrl,omitempty"`
		IntervalSec    int    `json:"intervalSec"`
		ExposeScrape   bool   `json:"exposeScrape"`
		ScrapeBind     string `json:"scrapeBind"`
		ScrapePort     int    `json:"scrapePort"`
		ScrapeToken    string `json:"scrapeToken,omitempty"`
	} `json:"metrics"`
	Logs struct {
		Enabled          bool   `json:"enabled"`
		VictoriaLogsURL  string `json:"victoriaLogsUrl,omitempty"`
		FlushIntervalSec int    `json:"flushIntervalSec"`
		BatchSize        int    `json:"batchSize"`
		Nflog            struct {
			Enabled         bool `json:"enabled"`
			Group           int  `json:"group"`
			RateLimitPerSec int  `json:"rateLimitPerSec"`
		} `json:"nflog"`
		Journald struct {
			Enabled bool     `json:"enabled"`
			Units   []string `json:"units"`
		} `json:"journald"`
		Suricata struct {
			Enabled bool `json:"enabled"`
		} `json:"suricata"`
		CrowdSec struct {
			Enabled bool `json:"enabled"`
		} `json:"crowdsec"`
		KeaDhcp struct {
			Enabled bool `json:"enabled"`
		} `json:"keaDhcp"`
		UnboundDns struct {
			Enabled bool `json:"enabled"`
		} `json:"unboundDns"`
	} `json:"logs"`
	Buffer TelemetryBufferPayload `json:"buffer"`
	ActiveMitigation struct {
		AcceptRemoteBlocks bool     `json:"acceptRemoteBlocks"`
		MaxTtlSec          int      `json:"maxTtlSec"`
		ProtectedCidrs     []string `json:"protectedCidrs"`
	} `json:"activeMitigation"`
}

func (o ObservabilityOffloadConfigPayload) ResolvedRemoteWriteUrlOrDefault() string {
	if strings.TrimSpace(o.ResolvedRemoteWriteURL) != "" {
		return strings.TrimSpace(o.ResolvedRemoteWriteURL)
	}
	if strings.TrimSpace(o.Metrics.RemoteWriteURL) != "" {
		return strings.TrimSpace(o.Metrics.RemoteWriteURL)
	}
	if strings.TrimSpace(o.HubURL) != "" {
		return strings.TrimRight(strings.TrimSpace(o.HubURL), "/") + "/vm/api/v1/write"
	}
	return ""
}

func (o ObservabilityOffloadConfigPayload) ResolvedVictoriaLogsURLOrDefault() string {
	if strings.TrimSpace(o.ResolvedVictoriaLogsURL) != "" {
		return strings.TrimSpace(o.ResolvedVictoriaLogsURL)
	}
	if strings.TrimSpace(o.Logs.VictoriaLogsURL) != "" {
		return strings.TrimSpace(o.Logs.VictoriaLogsURL)
	}
	if strings.TrimSpace(o.HubURL) != "" {
		return strings.TrimRight(strings.TrimSpace(o.HubURL), "/") + "/vl/insert/jsonline"
	}
	return ""
}

type ObservabilityBackendEndpoint struct {
	Enabled     bool   `json:"enabled"`
	URL         string `json:"url"`
	BearerToken string `json:"bearerToken,omitempty"`
}

type ObservabilityRuntimeBundle struct {
	NodeID          string                              `json:"nodeId"`
	Hostname        string                              `json:"hostname"`
	Enabled         bool                                `json:"enabled"`
	Offload         ObservabilityOffloadConfigPayload   `json:"offload"`
	VictoriaMetrics ObservabilityBackendEndpoint        `json:"victoriaMetrics"`
	VictoriaLogs    ObservabilityBackendEndpoint        `json:"victoriaLogs"`
	ClickHouse      NetFlowClickHousePayload            `json:"clickhouse"`
	ActiveMitigation struct {
		AcceptRemoteBlocks bool     `json:"acceptRemoteBlocks"`
		MaxTtlSec          int      `json:"maxTtlSec"`
		ProtectedCidrs     []string `json:"protectedCidrs"`
	} `json:"activeMitigation"`
	Interfaces    []NetFlowInterfaceHint           `json:"interfaces"`
	FirewallRules map[string]ObservabilityRuleMeta `json:"firewallRules"`
}

type ObservabilityStatusSnapshot struct {
	Enabled           bool                  `json:"enabled"`
	OffloadEnabled    bool                  `json:"offloadEnabled"`
	NodeID            string                `json:"nodeId"`
	Hostname          string                `json:"hostname"`
	MetricsURL        string                `json:"metricsUrl,omitempty"`
	LogsURL           string                `json:"logsUrl,omitempty"`
	MetricsQueue      TelemetryQueueStats   `json:"metricsQueue"`
	LogsQueue         TelemetryQueueStats   `json:"logsQueue"`
	NetFlowQueue      TelemetryQueueStats   `json:"netflowQueue"`
	MetricsLastPushMs int64                 `json:"metricsLastPushMs,omitempty"`
	LogsLastPushMs    int64                 `json:"logsLastPushMs,omitempty"`
	MetricsLastError  string                `json:"metricsLastError,omitempty"`
	LogsLastError     string                `json:"logsLastError,omitempty"`
	AcceptsMitigation bool                  `json:"acceptsMitigation"`
}

type RemoteMitigateRequest struct {
	TargetIP string `json:"targetIp"`
	TTLSec   int    `json:"ttlSec"`
	Reason   string `json:"reason"`
}

type RemoteMitigateResponse struct {
	Accepted bool   `json:"accepted"`
	TargetIP string `json:"targetIp"`
	TTLSec   int    `json:"ttlSec"`
	Message  string `json:"message,omitempty"`
}

type ObservabilityManager struct {
	mu      sync.RWMutex
	bundle  *ObservabilityRuntimeBundle
	ebpf    *EBPFManager
	netflow *NetFlowManager
	metrics *MetricsShipper
	logs    *LogShipper
}

func NewObservabilityManager(
	ebpf *EBPFManager,
	hardware *HardwareManager,
	nas *NasManager,
	netflow *NetFlowManager,
	sdwanFn func() []GatewayProbeStats,
) *ObservabilityManager {
	m := &ObservabilityManager{
		ebpf:    ebpf,
		netflow: netflow,
		metrics: NewMetricsShipper(ebpf, hardware, nas, sdwanFn),
		logs:    NewLogShipper(),
	}
	m.metrics.SetExtraQueueStatsProvider(func() []TelemetryQueueStats {
		var extra []TelemetryQueueStats
		extra = append(extra, m.logs.QueueStats())
		if m.netflow != nil && m.netflow.exportQueue != nil {
			extra = append(extra, m.netflow.exportQueue.Stats())
		}
		return extra
	})
	return m
}

func (m *ObservabilityManager) ApplyConfig(rawJSON []byte) error {
	var b ObservabilityRuntimeBundle
	if err := json.Unmarshal(rawJSON, &b); err != nil {
		return fmt.Errorf("invalid observability_config.json: %w", err)
	}
	m.mu.Lock()
	m.bundle = &b
	m.mu.Unlock()

	m.metrics.ApplyConfig(&b)
	m.logs.ApplyConfig(&b)
	return nil
}

func (m *ObservabilityManager) LoadFromFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return m.ApplyConfig(raw)
}

func (m *ObservabilityManager) Stop() {
	m.metrics.Stop()
	m.logs.Stop()
}

func (m *ObservabilityManager) WritePrometheusMetrics(w io.Writer) {
	m.metrics.WritePrometheusMetrics(w)
}

func (m *ObservabilityManager) GetStatus() ObservabilityStatusSnapshot {
	m.mu.RLock()
	b := m.bundle
	m.mu.RUnlock()

	mq, mPush, mErr := m.metrics.Status()
	lq, lPush, lErr := m.logs.Status()
	var nfq TelemetryQueueStats
	if m.netflow != nil && m.netflow.exportQueue != nil {
		nfq = m.netflow.exportQueue.Stats()
	}

	snap := ObservabilityStatusSnapshot{
		MetricsQueue:      mq,
		LogsQueue:         lq,
		NetFlowQueue:      nfq,
		MetricsLastPushMs: mPush,
		LogsLastPushMs:    lPush,
		MetricsLastError:  mErr,
		LogsLastError:     lErr,
	}
	if b != nil {
		snap.Enabled = b.Enabled
		snap.OffloadEnabled = b.Offload.Enabled
		snap.NodeID = b.NodeID
		snap.Hostname = b.Hostname
		snap.MetricsURL = b.Offload.ResolvedRemoteWriteUrlOrDefault()
		snap.LogsURL = b.Offload.ResolvedVictoriaLogsURLOrDefault()
		snap.AcceptsMitigation = b.ActiveMitigation.AcceptRemoteBlocks
	}
	return snap
}

// HandleRemoteMitigate validates opt-in remote mitigation policy and protected management/WG
// CIDRs before invoking kernel XDP blocking on this node.
func (m *ObservabilityManager) HandleRemoteMitigate(req RemoteMitigateRequest) (RemoteMitigateResponse, error) {
	m.mu.RLock()
	b := m.bundle
	m.mu.RUnlock()

	if b == nil || !b.ActiveMitigation.AcceptRemoteBlocks {
		return RemoteMitigateResponse{Accepted: false}, errors.New("remote edge mitigation is disabled on this node")
	}
	ipStr := strings.TrimSpace(req.TargetIP)
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return RemoteMitigateResponse{Accepted: false}, fmt.Errorf("invalid targetIp %q", ipStr)
	}
	if addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
		return RemoteMitigateResponse{Accepted: false}, fmt.Errorf("targetIp %s is protected", ipStr)
	}

	// Enforce configured anti-lockout protected CIDRs
	for _, rawCidr := range b.ActiveMitigation.ProtectedCidrs {
		c := strings.TrimSpace(rawCidr)
		if c == "" {
			continue
		}
		if p, perr := netip.ParsePrefix(c); perr == nil && p.Contains(addr) {
			return RemoteMitigateResponse{Accepted: false}, fmt.Errorf("targetIp %s is inside protectedCidr %s", ipStr, c)
		}
	}
	// Never allow blocking any local interface subnet (including wg0 / mgmt)
	if ifAddrs, err := net.InterfaceAddrs(); err == nil {
		for _, ia := range ifAddrs {
			if p, perr := netip.ParsePrefix(ia.String()); perr == nil && p.Contains(addr) {
				return RemoteMitigateResponse{Accepted: false}, fmt.Errorf("targetIp %s falls within local interface subnet %s", ipStr, p.String())
			}
		}
	}

	ttl := req.TTLSec
	if ttl < 60 {
		ttl = 300
	}
	maxTtl := b.ActiveMitigation.MaxTtlSec
	if maxTtl <= 0 {
		maxTtl = 3600
	}
	if ttl > maxTtl {
		ttl = maxTtl
	}

	if m.ebpf == nil {
		return RemoteMitigateResponse{Accepted: false}, errors.New("XDP engine unavailable on this node")
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "Remote Analytics Hub mitigation"
	}
	if err := m.ebpf.AddXdpBlock(ipStr, ttl, XdpReasonSoarQuarantine, reason); err != nil {
		return RemoteMitigateResponse{Accepted: false}, err
	}
	return RemoteMitigateResponse{
		Accepted: true,
		TargetIP: ipStr,
		TTLSec:   ttl,
		Message:  fmt.Sprintf("XDP blocked %s for %ds", ipStr, ttl),
	}, nil
}
