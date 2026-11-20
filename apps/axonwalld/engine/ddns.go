package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	ID            string `json:"id,omitempty"`
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

// Providers with a real client in this daemon. The rest are reported
// as not-implemented on every sync attempt — never "Reconciled"
// (A-H1, round 3).
var ddnsImplementedProviders = map[string]bool{
	"cloudflare": true,
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

// ddnsStatusKey identifies one entry's status row. Statuses used to
// be keyed by hostname alone, so two entries for the same hostname
// (different provider/interface) collapsed into one row and silently
// overwrote each other (A-H1, round 3).
func ddnsStatusKey(e DdnsEntry) string {
	if id := strings.TrimSpace(e.ID); id != "" {
		return "id:" + id
	}
	return strings.ToLower(strings.TrimSpace(e.Hostname)) + "|" +
		strings.ToLower(strings.TrimSpace(e.Provider)) + "|" +
		strings.TrimSpace(e.Interface) + "|" +
		strings.TrimSpace(e.IpVersion)
}

type DdnsManager struct {
	mu       sync.Mutex
	cfg      DdnsConfigBundle
	statuses map[string]DdnsEntryStatus
	lastSync map[string]time.Time
	cancel   context.CancelFunc

	httpClient     *http.Client
	duckdnsBaseURL string
	cloudflareBase string
	desecBaseURL   string
	linodeBaseURL  string
}

func NewDdnsManager() *DdnsManager {
	return &DdnsManager{
		statuses:       make(map[string]DdnsEntryStatus),
		lastSync:       make(map[string]time.Time),
		httpClient:     &http.Client{Timeout: 8 * time.Second},
		duckdnsBaseURL: "https://www.duckdns.org",
		cloudflareBase: "https://api.cloudflare.com/client/v4",
		desecBaseURL:   "https://desec.io/api/v1",
		linodeBaseURL:  "https://api.linode.com/v4",
	}
}

func (m *DdnsManager) httpDo(req *http.Request) (*http.Response, error) {
	c := m.httpClient
	if c == nil {
		c = &http.Client{Timeout: 8 * time.Second}
	}
	return c.Do(req)
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
		key := ddnsStatusKey(e)
		prev, hasPrev := m.statuses[key]
		msg := "Configured (scheduled)"
		lastAt := ""
		if hasPrev {
			msg = prev.LastStatusMsg
			lastAt = prev.LastSyncAt
		}
		if !cfg.Enabled || !e.Enabled {
			msg = "Paused"
		}
		nextStatuses[key] = DdnsEntryStatus{
			ID:            strings.TrimSpace(e.ID),
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
	// A-H1: the loop used to tick at a hardcoded 5 minutes for every
	// entry while CheckIntervalSeconds was never read. Tick often and
	// let syncDueEntries honour each entry's own interval.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.syncDueEntries()
		}
	}
}

// ddnsInterval returns the per-entry check interval, defaulting to 5
// minutes when unset or invalid.
func ddnsInterval(e DdnsEntry) time.Duration {
	if e.CheckIntervalSeconds <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(e.CheckIntervalSeconds) * time.Second
}

// syncDueEntries syncs only the enabled entries whose own interval
// has elapsed since their last successful sync.
func (m *DdnsManager) syncDueEntries() {
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()
	if !cfg.Enabled {
		return
	}
	now := time.Now()
	for _, e := range cfg.Entries {
		if !e.Enabled {
			continue
		}
		m.mu.Lock()
		last, ok := m.lastSync[ddnsStatusKey(e)]
		m.mu.Unlock()
		if ok && now.Sub(last) < ddnsInterval(e) {
			continue
		}
		m.syncOne(e, now)
	}
}

func (m *DdnsManager) TriggerSyncNow() DdnsStatus {
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()

	if !cfg.Enabled {
		return m.GetStatus()
	}

	now := time.Now()
	for _, e := range cfg.Entries {
		if !e.Enabled {
			continue
		}
		// A manual sync forces every enabled entry, regardless of
		// its interval; the background loop honours intervals.
		m.syncOne(e, now)
	}
	return m.GetStatus()
}

// syncOne attempts a single entry's update and records the outcome.
// LastSyncAt advances only on a real success: the old code stamped
// "Reconciled (<provider>)" with a fresh timestamp for providers
// that were never contacted at all (A-H1, round 3).
func (m *DdnsManager) syncOne(e DdnsEntry, now time.Time) {
	msg, ok := m.syncEntry(e)
	key := ddnsStatusKey(e)
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.statuses[key]
	st.ID = strings.TrimSpace(e.ID)
	st.Hostname = e.Hostname
	st.Provider = e.Provider
	st.Interface = e.Interface
	st.IpVersion = e.IpVersion
	st.Enabled = true
	if ok {
		st.LastSyncAt = now.UTC().Format(time.RFC3339)
		if m.lastSync == nil {
			m.lastSync = make(map[string]time.Time)
		}
		m.lastSync[key] = now
	}
	st.LastStatusMsg = msg
	m.statuses[key] = st
}

// syncEntry performs the provider update. It returns the status
// message and whether the provider record was actually updated.
func (m *DdnsManager) syncEntry(e DdnsEntry) (string, bool) {
	provider := strings.ToLower(strings.TrimSpace(e.Provider))
	if !ddnsImplementedProviders[provider] {
		return fmt.Sprintf("Not implemented: provider %q has no DDNS client in this daemon; record not updated", provider), false
	}
	switch provider {
	case "custom":
		return m.syncCustom(e)
	case "duckdns":
		return m.syncDuckDNS(e)
	case "cloudflare":
		return m.syncCloudflare(e)
	case "desec":
		return m.syncDesec(e)
	case "linode":
		return m.syncLinode(e)
	default:
		return fmt.Sprintf("Not implemented: provider %q has no DDNS client in this daemon; record not updated", provider), false
	}
}

func (m *DdnsManager) syncCustom(e DdnsEntry) (string, bool) {
	// A-H1: the webhook used to fire only for https:// while
	// validation also allowed http://, so an http:// custom URL was
	// silently never called yet reported "Reconciled (custom)".
	if strings.TrimSpace(e.CustomUpdateURL) == "" {
		return "Custom update URL not configured; webhook not called", false
	}
	req, err := http.NewRequest(http.MethodGet, e.CustomUpdateURL, nil)
	if err != nil {
		return fmt.Sprintf("Webhook error: %v", err), false
	}
	if e.ApiToken != "" {
		req.Header.Set("Authorization", "Bearer "+e.ApiToken)
	}
	resp, err := m.httpDo(req)
	if err != nil {
		return fmt.Sprintf("Webhook error: %v", err), false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Sprintf("Webhook HTTP %d (not 2xx); update not confirmed", resp.StatusCode), false
	}
	return fmt.Sprintf("Webhook HTTP %d", resp.StatusCode), true
}

func (m *DdnsManager) syncDuckDNS(e DdnsEntry) (string, bool) {
	if strings.TrimSpace(e.ApiToken) == "" {
		return "DuckDNS API token not configured; record not updated", false
	}
	// A-H1: the update URL used to be built with an empty ip=, so
	// DuckDNS never received an address. Resolve the interface's
	// current IP first; without one, fail instead of calling.
	ip, err := ddnsInterfaceIP(e.Interface, e.IpVersion)
	if err != nil {
		return fmt.Sprintf("DuckDNS error: %v; record not updated", err), false
	}
	domainTok := strings.TrimSuffix(e.Hostname, ".duckdns.org")
	base := m.duckdnsBaseURL
	if base == "" {
		base = "https://www.duckdns.org"
	}
	u := fmt.Sprintf("%s/update?domains=%s&token=%s&ip=%s",
		strings.TrimSuffix(base, "/"), url.QueryEscape(domainTok), url.QueryEscape(e.ApiToken), url.QueryEscape(ip))
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return fmt.Sprintf("DuckDNS error: %v", err), false
	}
	resp, err := m.httpDo(req)
	if err != nil {
		return fmt.Sprintf("DuckDNS error: %v", err), false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "OK" {
		return fmt.Sprintf("DuckDNS rejected update (HTTP %d: %s); record not updated", resp.StatusCode, strings.TrimSpace(string(body))), false
	}
	return fmt.Sprintf("DuckDNS OK (%s -> %s)", e.Hostname, ip), true
}

func (m *DdnsManager) syncCloudflare(e DdnsEntry) (string, bool) {
	if strings.TrimSpace(e.ApiToken) == "" {
		return "Cloudflare API token not configured; record not updated", false
	}
	if strings.TrimSpace(e.Zone) == "" {
		return "Cloudflare zone ID not configured (zone field); record not updated", false
	}
	ip, err := ddnsInterfaceIP(e.Interface, e.IpVersion)
	if err != nil {
		return fmt.Sprintf("Cloudflare error: %v; record not updated", err), false
	}
	recType := "A"
	if ddnsWantsIPv6(e.IpVersion) {
		recType = "AAAA"
	}
	base := m.cloudflareBase
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	base = strings.TrimSuffix(base, "/")
	zoneID := url.PathEscape(strings.TrimSpace(e.Zone))

	listURL := fmt.Sprintf("%s/zones/%s/dns_records?name=%s&type=%s&per_page=1",
		base, zoneID, url.QueryEscape(e.Hostname), recType)
	req, err := http.NewRequest(http.MethodGet, listURL, nil)
	if err != nil {
		return fmt.Sprintf("Cloudflare error: %v", err), false
	}
	req.Header.Set("Authorization", "Bearer "+e.ApiToken)
	resp, err := m.httpDo(req)
	if err != nil {
		return fmt.Sprintf("Cloudflare error: %v", err), false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("Cloudflare error: list records HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))), false
	}
	var list struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return fmt.Sprintf("Cloudflare error: unreadable list response: %v", err), false
	}
	if !list.Success {
		return fmt.Sprintf("Cloudflare error: %s", cloudflareErrText(list.Errors)), false
	}

	payload, _ := json.Marshal(map[string]any{
		"type":    recType,
		"name":    e.Hostname,
		"content": ip,
		"proxied": e.Proxied,
		"ttl":     1,
	})
	var method, updateURL string
	if len(list.Result) > 0 {
		method = http.MethodPut
		updateURL = fmt.Sprintf("%s/zones/%s/dns_records/%s", base, zoneID, url.PathEscape(list.Result[0].ID))
	} else {
		method = http.MethodPost
		updateURL = fmt.Sprintf("%s/zones/%s/dns_records", base, zoneID)
	}
	req, err = http.NewRequest(method, updateURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Sprintf("Cloudflare error: %v", err), false
	}
	req.Header.Set("Authorization", "Bearer "+e.ApiToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err = m.httpDo(req)
	if err != nil {
		return fmt.Sprintf("Cloudflare error: %v", err), false
	}
	body, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("Cloudflare error: update HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))), false
	}
	var upd struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &upd); err != nil {
		return fmt.Sprintf("Cloudflare error: unreadable update response: %v", err), false
	}
	if !upd.Success {
		return fmt.Sprintf("Cloudflare error: %s", cloudflareErrText(upd.Errors)), false
	}
	return fmt.Sprintf("Cloudflare updated %s -> %s", e.Hostname, ip), true
}

func cloudflareErrText(errs []struct {
	Message string `json:"message"`
}) string {
	if len(errs) == 0 {
		return "unknown error"
	}
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		msgs = append(msgs, e.Message)
	}
	return strings.Join(msgs, "; ")
}

func (m *DdnsManager) syncDesec(e DdnsEntry) (string, bool) {
	if strings.TrimSpace(e.ApiToken) == "" {
		return "deSEC API token not configured; record not updated", false
	}
	ip, err := ddnsInterfaceIP(e.Interface, e.IpVersion)
	if err != nil {
		return fmt.Sprintf("deSEC error: %v; record not updated", err), false
	}
	recType := "A"
	if ddnsWantsIPv6(e.IpVersion) {
		recType = "AAAA"
	}
	domain, subname, ok := ddnsSplitHostname(e.Hostname)
	if !ok {
		return fmt.Sprintf("deSEC error: hostname %q has no parent domain; record not updated", e.Hostname), false
	}
	base := m.desecBaseURL
	if base == "" {
		base = "https://desec.io/api/v1"
	}
	base = strings.TrimSuffix(base, "/")
	updateURL := fmt.Sprintf("%s/domains/%s/rrsets/%s/%s/", base, url.PathEscape(domain), url.PathEscape(subname), recType)
	payload, _ := json.Marshal([]map[string]any{{
		"subname": subname,
		"type":    recType,
		"ttl":     3600,
		"records": []string{ip},
	}})
	req, err := http.NewRequest(http.MethodPut, updateURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Sprintf("deSEC error: %v", err), false
	}
	req.Header.Set("Authorization", "Token "+e.ApiToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.httpDo(req)
	if err != nil {
		return fmt.Sprintf("deSEC error: %v", err), false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Sprintf("deSEC error: update HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))), false
	}
	return fmt.Sprintf("deSEC updated %s -> %s", e.Hostname, ip), true
}

func (m *DdnsManager) syncLinode(e DdnsEntry) (string, bool) {
	if strings.TrimSpace(e.ApiToken) == "" {
		return "Linode API token not configured; record not updated", false
	}
	// Linode's API addresses domains by numeric ID; the zone field
	// carries it. A domain name here cannot be resolved to an ID
	// without an extra list call that would guess among matches, so
	// fail loudly instead of updating the wrong domain.
	domainID := strings.TrimSpace(e.Zone)
	if domainID == "" {
		return "Linode domain ID not configured (zone field must hold the numeric Linode domain ID); record not updated", false
	}
	for _, r := range domainID {
		if r < '0' || r > '9' {
			return "Linode zone field must hold the numeric Linode domain ID; record not updated", false
		}
	}
	ip, err := ddnsInterfaceIP(e.Interface, e.IpVersion)
	if err != nil {
		return fmt.Sprintf("Linode error: %v; record not updated", err), false
	}
	recType := "A"
	if ddnsWantsIPv6(e.IpVersion) {
		recType = "AAAA"
	}
	_, subname, ok := ddnsSplitHostname(e.Hostname)
	if !ok {
		return fmt.Sprintf("Linode error: hostname %q has no parent domain; record not updated", e.Hostname), false
	}
	base := m.linodeBaseURL
	if base == "" {
		base = "https://api.linode.com/v4"
	}
	base = strings.TrimSuffix(base, "/")

	listURL := fmt.Sprintf("%s/domains/%s/records?type=%s&name=%s", base, domainID, recType, url.QueryEscape(subname))
	req, err := http.NewRequest(http.MethodGet, listURL, nil)
	if err != nil {
		return fmt.Sprintf("Linode error: %v", err), false
	}
	req.Header.Set("Authorization", "Bearer "+e.ApiToken)
	resp, err := m.httpDo(req)
	if err != nil {
		return fmt.Sprintf("Linode error: %v", err), false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("Linode error: list records HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))), false
	}
	var list struct {
		Data []struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return fmt.Sprintf("Linode error: unreadable list response: %v", err), false
	}
	payload, _ := json.Marshal(map[string]any{
		"type":   recType,
		"name":   subname,
		"target": ip,
	})
	var method, updateURL string
	if len(list.Data) > 0 {
		method = http.MethodPut
		updateURL = fmt.Sprintf("%s/domains/%s/records/%d", base, domainID, list.Data[0].ID)
	} else {
		method = http.MethodPost
		updateURL = fmt.Sprintf("%s/domains/%s/records", base, domainID)
	}
	req, err = http.NewRequest(method, updateURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Sprintf("Linode error: %v", err), false
	}
	req.Header.Set("Authorization", "Bearer "+e.ApiToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err = m.httpDo(req)
	if err != nil {
		return fmt.Sprintf("Linode error: %v", err), false
	}
	body, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Sprintf("Linode error: update HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))), false
	}
	return fmt.Sprintf("Linode updated %s -> %s", e.Hostname, ip), true
}

// ddnsSplitHostname splits "host.example.com" into ("example.com",
// "host"). A bare domain ("example.com") yields subname "" (apex).
func ddnsSplitHostname(hostname string) (domain, subname string, ok bool) {
	parts := strings.Split(strings.TrimSuffix(strings.TrimSpace(hostname), "."), ".")
	if len(parts) < 2 {
		return "", "", false
	}
	return strings.Join(parts[1:], "."), parts[0], true
}

func ddnsWantsIPv6(ipVersion string) bool {
	v := strings.ToLower(strings.TrimSpace(ipVersion))
	return v == "6" || v == "v6" || v == "ipv6"
}

// ddnsInterfaceIP returns the interface's current address of the
// requested family (IPv4 unless the entry asks for v6). With no
// interface named, it takes the first global unicast address of that
// family on any interface. Loopback and link-local addresses are
// never DDNS answers.
func ddnsInterfaceIP(iface, ipVersion string) (string, error) {
	want6 := ddnsWantsIPv6(ipVersion)
	family := "IPv4"
	if want6 {
		family = "IPv6"
	}
	pick := func(addrs []net.Addr) (string, bool) {
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			if want6 {
				if ip.To4() != nil || ip.To16() == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
					continue
				}
				return ip.String(), true
			}
			ip4 := ip.To4()
			if ip4 == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			return ip4.String(), true
		}
		return "", false
	}
	if strings.TrimSpace(iface) != "" {
		ifObj, err := net.InterfaceByName(strings.TrimSpace(iface))
		if err != nil {
			return "", fmt.Errorf("no %s address: interface %q not found", family, iface)
		}
		addrs, err := ifObj.Addrs()
		if err != nil {
			return "", fmt.Errorf("no %s address: cannot list addresses of interface %q: %w", family, iface, err)
		}
		if ip, ok := pick(addrs); ok {
			return ip, nil
		}
		return "", fmt.Errorf("no %s address on interface %q", family, iface)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("no %s address: cannot list interfaces: %w", family, err)
	}
	for _, ifObj := range ifaces {
		addrs, err := ifObj.Addrs()
		if err != nil {
			continue
		}
		if ip, ok := pick(addrs); ok {
			return ip, nil
		}
	}
	return "", fmt.Errorf("no %s address on any interface", family)
}

func (m *DdnsManager) GetStatus() DdnsStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := DdnsStatus{
		Enabled: m.cfg.Enabled,
		Entries: make([]DdnsEntryStatus, 0, len(m.cfg.Entries)),
	}
	for _, e := range m.cfg.Entries {
		if st, ok := m.statuses[ddnsStatusKey(e)]; ok {
			out.Entries = append(out.Entries, st)
		} else {
			out.Entries = append(out.Entries, DdnsEntryStatus{
				ID:            strings.TrimSpace(e.ID),
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
