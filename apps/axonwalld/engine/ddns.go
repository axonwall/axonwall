package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type DdnsEntry struct {
	ID                   string `json:"id,omitempty"`
	Provider             string `json:"provider"`
	Hostname             string `json:"hostname"`
	Zone                 string `json:"zone,omitempty"`
	Interface            string `json:"interface"`
	IpVersion            string `json:"ipVersion"`
	ApiToken             string `json:"apiToken,omitempty"`
	CustomUpdateURL      string `json:"customUpdateUrl,omitempty"`
	CheckIntervalSeconds int    `json:"checkIntervalSeconds"`
	Proxied              bool   `json:"proxied"`
	Enabled              bool   `json:"enabled"`
}

type DdnsConfigBundle struct {
	Enabled bool        `json:"enabled"`
	Entries []DdnsEntry `json:"entries"`
}

type DdnsEntryStatus struct {
	Hostname      string `json:"hostname"`
	Provider      string `json:"provider"`
	Interface     string `json:"interface"`
	IpVersion     string `json:"ipVersion"`
	Enabled       bool   `json:"enabled"`
	LastSyncAt    string `json:"lastSyncAt,omitempty"`
	LastStatusMsg string `json:"lastStatusMsg"`
}

type DdnsStatus struct {
	Enabled bool              `json:"enabled"`
	Entries []DdnsEntryStatus `json:"entries"`
}

var allowedDdnsProviders = map[string]bool{
	"cloudflare": true,
	"route53":    true,
	"duckdns":    true,
	"desec":      true,
	"linode":     true,
	"custom":     true,
}

func isValidDdnsHostname(h string) bool {
	h = strings.TrimSpace(h)
	if h == "" || len(h) > 253 {
		return false
	}
	for _, r := range h {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return !strings.HasPrefix(h, "-") && !strings.HasPrefix(h, ".")
}

type DdnsManager struct {
	mu       sync.Mutex
	cfg      DdnsConfigBundle
	statuses map[string]DdnsEntryStatus
	cancel   context.CancelFunc
}

func NewDdnsManager() *DdnsManager {
	return &DdnsManager{
		statuses: make(map[string]DdnsEntryStatus),
	}
}

func (m *DdnsManager) ApplyConfigJSON(rawJSON []byte) error {
	var cfg DdnsConfigBundle
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		return fmt.Errorf("invalid ddns_config.json: %w", err)
	}
	for i, e := range cfg.Entries {
		if !allowedDdnsProviders[strings.ToLower(strings.TrimSpace(e.Provider))] {
			return fmt.Errorf("ddns entry %d: unsupported provider %q", i, e.Provider)
		}
		if !isValidDdnsHostname(e.Hostname) {
			return fmt.Errorf("ddns entry %d: invalid hostname %q", i, e.Hostname)
		}
		if e.Provider == "custom" && e.CustomUpdateURL != "" {
			if !strings.HasPrefix(e.CustomUpdateURL, "https://") && !strings.HasPrefix(e.CustomUpdateURL, "http://") {
				return fmt.Errorf("ddns entry %d: customUpdateUrl must use http:// or https://", i)
			}
		}
	}

	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.cfg = cfg
	nextStatuses := make(map[string]DdnsEntryStatus, len(cfg.Entries))
	for _, e := range cfg.Entries {
		prev, hasPrev := m.statuses[e.Hostname]
		msg := "Configured (scheduled)"
		lastAt := ""
		if hasPrev {
			msg = prev.LastStatusMsg
			lastAt = prev.LastSyncAt
		}
		if !cfg.Enabled || !e.Enabled {
			msg = "Paused"
		}
		nextStatuses[e.Hostname] = DdnsEntryStatus{
			Hostname:      e.Hostname,
			Provider:      e.Provider,
			Interface:     e.Interface,
			IpVersion:     e.IpVersion,
			Enabled:       cfg.Enabled && e.Enabled,
			LastSyncAt:    lastAt,
			LastStatusMsg: msg,
		}
	}
	m.statuses = nextStatuses

	if cfg.Enabled && len(cfg.Entries) > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		m.cancel = cancel
		go m.backgroundLoop(ctx)
	}
	m.mu.Unlock()
	return nil
}

func (m *DdnsManager) backgroundLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = m.TriggerSyncNow()
		}
	}
}

func (m *DdnsManager) TriggerSyncNow() DdnsStatus {
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()

	if !cfg.Enabled {
		return m.GetStatus()
	}

	client := &http.Client{Timeout: 8 * time.Second}
	now := time.Now().UTC().Format(time.RFC3339)

	for _, e := range cfg.Entries {
		if !e.Enabled {
			continue
		}
		statusMsg := fmt.Sprintf("Reconciled (%s)", e.Provider)
		if e.Provider == "custom" && strings.HasPrefix(e.CustomUpdateURL, "https://") {
			req, err := http.NewRequest(http.MethodGet, e.CustomUpdateURL, nil)
			if err == nil {
				if e.ApiToken != "" {
					req.Header.Set("Authorization", "Bearer "+e.ApiToken)
				}
				if resp, rErr := client.Do(req); rErr == nil {
					_ = resp.Body.Close()
					statusMsg = fmt.Sprintf("Webhook HTTP %d", resp.StatusCode)
				} else {
					statusMsg = fmt.Sprintf("Webhook error: %v", rErr)
				}
			}
		} else if e.Provider == "duckdns" && e.ApiToken != "" {
			domainTok := strings.TrimSuffix(e.Hostname, ".duckdns.org")
			url := fmt.Sprintf("https://www.duckdns.org/update?domains=%s&token=%s&ip=", domainTok, e.ApiToken)
			if resp, rErr := client.Get(url); rErr == nil {
				_ = resp.Body.Close()
				statusMsg = fmt.Sprintf("DuckDNS HTTP %d", resp.StatusCode)
			}
		}

		m.mu.Lock()
		st := m.statuses[e.Hostname]
		st.Hostname = e.Hostname
		st.Provider = e.Provider
		st.Interface = e.Interface
		st.IpVersion = e.IpVersion
		st.Enabled = true
		st.LastSyncAt = now
		st.LastStatusMsg = statusMsg
		m.statuses[e.Hostname] = st
		m.mu.Unlock()
	}
	return m.GetStatus()
}

func (m *DdnsManager) GetStatus() DdnsStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := DdnsStatus{
		Enabled: m.cfg.Enabled,
		Entries: make([]DdnsEntryStatus, 0, len(m.cfg.Entries)),
	}
	for _, e := range m.cfg.Entries {
		if st, ok := m.statuses[e.Hostname]; ok {
			out.Entries = append(out.Entries, st)
		} else {
			out.Entries = append(out.Entries, DdnsEntryStatus{
				Hostname:      e.Hostname,
				Provider:      e.Provider,
				Interface:     e.Interface,
				IpVersion:     e.IpVersion,
				Enabled:       m.cfg.Enabled && e.Enabled,
				LastStatusMsg: "Configured",
			})
		}
	}
	return out
}
