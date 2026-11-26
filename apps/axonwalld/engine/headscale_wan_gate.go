package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// HeadscaleWanConfig mirrors /etc/axonwall/managed/headscale_wan_config.json.
type HeadscaleWanConfig struct {
	Enabled              bool   `json:"enabled"`
	BindPort             int    `json:"bindPort"`
	Hostname             string `json:"hostname"`
	AutoWindow           bool   `json:"autoWindow"`
	RequirePin           bool   `json:"requirePin"`
	PortKnockingEnabled  bool   `json:"portKnockingEnabled"`
	KnockProtocol        string `json:"knockProtocol"`
	KnockSequence        []int  `json:"knockSequence"`
	KnockStepTimeoutSec  int    `json:"knockStepTimeoutSec"`
	KnockOpenDurationSec int    `json:"knockOpenDurationSec"`
}

// HeadscaleWanStatus describes live WAN invite gate and port-knocking state.
type HeadscaleWanStatus struct {
	Enabled             bool     `json:"enabled"`
	AutoWindow          bool     `json:"autoWindow"`
	BindPort            int      `json:"bindPort"`
	Hostname            string   `json:"hostname"`
	WindowOpen          bool     `json:"windowOpen"`
	Reason              string   `json:"reason"` // disabled | always_open | pending_invites | manual_arm | closed
	PendingCount        int      `json:"pendingCount"`
	PendingExpiresAt    string   `json:"pendingExpiresAt,omitempty"`
	ManualExpiresAt     string   `json:"manualExpiresAt,omitempty"`
	EffectiveExpiresAt  string   `json:"effectiveExpiresAt,omitempty"`
	PortKnockingEnabled bool     `json:"portKnockingEnabled"`
	KnockProtocol       string   `json:"knockProtocol,omitempty"`
	KnockSequence       []int    `json:"knockSequence,omitempty"`
	KnockedIPs          []string `json:"knockedIPs"`
	LastSyncError       string   `json:"lastSyncError,omitempty"`
	DryRun              bool     `json:"dryRun"`
}

type storedHeadscaleInvite struct {
	Status    string `json:"status"`
	ExpiresAt string `json:"expiresAt"`
}

// HeadscaleWanGateManager reconciles dynamic nftables invite window sets
// (headscale_wan_window_ports) against active pending invites and admin arming.
type HeadscaleWanGateManager struct {
	mu          sync.Mutex
	invitesPath string
	dryRun      bool
	cfg         HeadscaleWanConfig

	manualUntil   time.Time
	windowOpen    bool
	lastSyncError string

	nowFn        func() time.Time
	nftApplyFn   func(stdin string) error
	nftListSetFn func(setName string) ([]string, error)

	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewHeadscaleWanGateManager constructs a gate manager watching stateDir/headscale-invites.json.
func NewHeadscaleWanGateManager(stateDir string, dryRun bool) *HeadscaleWanGateManager {
	if strings.TrimSpace(stateDir) == "" {
		stateDir = "/var/lib/axonwall"
	}
	m := &HeadscaleWanGateManager{
		invitesPath: filepath.Join(stateDir, "headscale-invites.json"),
		dryRun:      dryRun,
		nowFn:       time.Now,
		stopCh:      make(chan struct{}),
	}
	m.nftApplyFn = defaultNftBatchApply
	m.nftListSetFn = defaultNftListSetIPs
	return m
}

func (m *HeadscaleWanGateManager) effectiveInvitesPath() string {
	if override := strings.TrimSpace(os.Getenv("AXONWALL_HEADSCALE_INVITES_PATH")); override != "" {
		return override
	}
	return m.invitesPath
}

func defaultNftBatchApply(stdin string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft apply failed: %s (%w)", strings.TrimSpace(out.String()), err)
	}
	return nil
}

func defaultNftListSetIPs(setName string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-j", "list", "set", "inet", "axonwall", setName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft list set %s: %s (%w)", setName, strings.TrimSpace(string(out)), err)
	}
	return ParseNftSetIPsJSON(out)
}

// ParseNftSetIPsJSON extracts element IP strings from `nft -j list set` JSON output.
func ParseNftSetIPsJSON(raw []byte) ([]string, error) {
	var parsed struct {
		Nftables []struct {
			Set *struct {
				Elem json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var ips []string
	addIP := func(val string) {
		clean := strings.TrimSpace(val)
		if clean == "" {
			return
		}
		if _, ok := seen[clean]; !ok {
			seen[clean] = struct{}{}
			ips = append(ips, clean)
		}
	}
	for _, entry := range parsed.Nftables {
		if entry.Set == nil || len(entry.Set.Elem) == 0 {
			continue
		}
		var rawElems []json.RawMessage
		if err := json.Unmarshal(entry.Set.Elem, &rawElems); err != nil {
			continue
		}
		for _, item := range rawElems {
			var strVal string
			if err := json.Unmarshal(item, &strVal); err == nil {
				addIP(strVal)
				continue
			}
			var elemObj struct {
				Elem struct {
					Val json.RawMessage `json:"val"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(item, &elemObj); err == nil && len(elemObj.Elem.Val) > 0 {
				if err := json.Unmarshal(elemObj.Elem.Val, &strVal); err == nil {
					addIP(strVal)
					continue
				}
				var prefixObj struct {
					Prefix struct {
						Addr string `json:"addr"`
						Len  int    `json:"len"`
					} `json:"prefix"`
				}
				if err := json.Unmarshal(elemObj.Elem.Val, &prefixObj); err == nil && prefixObj.Prefix.Addr != "" {
					addIP(fmt.Sprintf("%s/%d", prefixObj.Prefix.Addr, prefixObj.Prefix.Len))
				}
			}
		}
	}
	sort.Strings(ips)
	return ips, nil
}

// ApplyConfig stores updated compiled config; actual nft elements are reconciled afterwards.
func (m *HeadscaleWanGateManager) ApplyConfig(raw []byte) error {
	var cfg HeadscaleWanConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("invalid headscale_wan_config.json: %w", err)
	}
	if cfg.Enabled && (cfg.BindPort < 1 || cfg.BindPort > 65535) {
		cfg.BindPort = 8443
	}
	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()
	return nil
}

func (m *HeadscaleWanGateManager) readPendingInviteSummary(now time.Time) (int, time.Time) {
	raw, err := os.ReadFile(m.effectiveInvitesPath())
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return 0, time.Time{}
	}
	var records []storedHeadscaleInvite
	if err := json.Unmarshal(raw, &records); err != nil {
		return 0, time.Time{}
	}
	count := 0
	var maxExp time.Time
	for _, rec := range records {
		if rec.Status != "pending" {
			continue
		}
		exp, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(rec.ExpiresAt))
		if err != nil {
			exp, err = time.Parse(time.RFC3339, strings.TrimSpace(rec.ExpiresAt))
		}
		if err != nil || !exp.After(now) {
			continue
		}
		count++
		if exp.After(maxExp) {
			maxExp = exp
		}
	}
	return count, maxExp
}

// Reconcile syncs the live nftables headscale_wan_window_ports set with pending invites & manual arms.
func (m *HeadscaleWanGateManager) Reconcile() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reconcileLocked()
}

func isNftMissingSetError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "No such file or directory") || strings.Contains(msg, "does not exist")
}

func (m *HeadscaleWanGateManager) reconcileLocked() error {
	now := m.nowFn().UTC()
	cfg := m.cfg

	if m.manualUntil.IsZero() || !m.manualUntil.After(now) {
		m.manualUntil = time.Time{}
	}

	_, pendingUntil := m.readPendingInviteSummary(now)

	if !cfg.Enabled || cfg.BindPort < 1 || cfg.BindPort > 65535 {
		wasOpen := m.windowOpen
		m.windowOpen = false
		m.lastSyncError = ""
		if !m.dryRun && wasOpen {
			if err := m.nftApplyFn("flush set inet axonwall headscale_wan_window_ports\n"); err != nil && !isNftMissingSetError(err) {
				m.lastSyncError = err.Error()
				return err
			}
		}
		return nil
	}

	if !cfg.AutoWindow {
		m.windowOpen = true
		m.lastSyncError = ""
		return nil
	}

	effectiveUntil := pendingUntil
	if m.manualUntil.After(effectiveUntil) {
		effectiveUntil = m.manualUntil
	}

	if effectiveUntil.After(now) {
		ttlSec := int(math.Ceil(effectiveUntil.Sub(now).Seconds()))
		if ttlSec < 1 {
			ttlSec = 1
		}
		if ttlSec > 604800 {
			ttlSec = 604800
		}
		script := fmt.Sprintf(
			"flush set inet axonwall headscale_wan_window_ports\nadd element inet axonwall headscale_wan_window_ports { %d timeout %ds }\n",
			cfg.BindPort,
			ttlSec,
		)
		if !m.dryRun {
			if err := m.nftApplyFn(script); err != nil {
				m.lastSyncError = err.Error()
				return err
			}
		}
		m.windowOpen = true
		m.lastSyncError = ""
		return nil
	}

	if !m.dryRun {
		if err := m.nftApplyFn("flush set inet axonwall headscale_wan_window_ports\n"); err != nil {
			if !isNftMissingSetError(err) {
				m.lastSyncError = err.Error()
				return err
			}
		}
	}
	m.windowOpen = false
	m.lastSyncError = ""
	return nil
}

// SyncFromInvites immediately reconciles and returns the updated gate status.
func (m *HeadscaleWanGateManager) SyncFromInvites() HeadscaleWanStatus {
	_ = m.Reconcile()
	return m.Status()
}

// ArmManual temporarily opens the WAN invite window (durationSec <= 0 closes manual arm).
func (m *HeadscaleWanGateManager) ArmManual(durationSec int) (HeadscaleWanStatus, error) {
	m.mu.Lock()
	now := m.nowFn().UTC()
	if durationSec <= 0 {
		m.manualUntil = time.Time{}
	} else {
		if durationSec < 60 {
			durationSec = 60
		}
		if durationSec > 86400 {
			durationSec = 86400
		}
		m.manualUntil = now.Add(time.Duration(durationSec) * time.Second)
	}
	err := m.reconcileLocked()
	m.mu.Unlock()
	return m.Status(), err
}

// Status returns the current WAN invite window status and any active knocked-in IPs.
func (m *HeadscaleWanGateManager) Status() HeadscaleWanStatus {
	m.mu.Lock()
	now := m.nowFn().UTC()
	cfg := m.cfg
	manualUntil := m.manualUntil
	if !manualUntil.IsZero() && !manualUntil.After(now) {
		manualUntil = time.Time{}
		m.manualUntil = time.Time{}
	}
	pendingCount, pendingUntil := m.readPendingInviteSummary(now)
	windowOpen := m.windowOpen
	lastErr := m.lastSyncError
	dryRun := m.dryRun
	listSetFn := m.nftListSetFn
	m.mu.Unlock()

	effectiveUntil := pendingUntil
	if manualUntil.After(effectiveUntil) {
		effectiveUntil = manualUntil
	}

	reason := "closed"
	if !cfg.Enabled {
		reason = "disabled"
		windowOpen = false
	} else if !cfg.AutoWindow {
		reason = "always_open"
		windowOpen = true
	} else if !effectiveUntil.IsZero() && effectiveUntil.After(now) {
		if !manualUntil.IsZero() && (pendingUntil.IsZero() || manualUntil.After(pendingUntil)) {
			reason = "manual_arm"
		} else {
			reason = "pending_invites"
		}
	}

	seqCopy := make([]int, len(cfg.KnockSequence))
	copy(seqCopy, cfg.KnockSequence)

	knockedIPs := []string{}
	if cfg.Enabled && cfg.PortKnockingEnabled && !dryRun && listSetFn != nil {
		seen := make(map[string]struct{})
		for _, setName := range []string{"headscale_knock_allow_v4", "headscale_knock_allow_v6"} {
			if ips, err := listSetFn(setName); err == nil {
				for _, ip := range ips {
					if _, ok := seen[ip]; !ok {
						seen[ip] = struct{}{}
						knockedIPs = append(knockedIPs, ip)
					}
				}
			}
		}
		sort.Strings(knockedIPs)
	}

	st := HeadscaleWanStatus{
		Enabled:             cfg.Enabled,
		AutoWindow:          cfg.AutoWindow,
		BindPort:            cfg.BindPort,
		Hostname:            cfg.Hostname,
		WindowOpen:          windowOpen,
		Reason:              reason,
		PendingCount:        pendingCount,
		PortKnockingEnabled: cfg.PortKnockingEnabled,
		KnockProtocol:       cfg.KnockProtocol,
		KnockSequence:       seqCopy,
		KnockedIPs:          knockedIPs,
		LastSyncError:       lastErr,
		DryRun:              dryRun,
	}
	if !pendingUntil.IsZero() {
		st.PendingExpiresAt = pendingUntil.UTC().Format(time.RFC3339)
	}
	if !manualUntil.IsZero() {
		st.ManualExpiresAt = manualUntil.UTC().Format(time.RFC3339)
	}
	if !effectiveUntil.IsZero() {
		st.EffectiveExpiresAt = effectiveUntil.UTC().Format(time.RFC3339)
	}
	return st
}

// Start launches a background 15-second expiry reconciliation loop.
func (m *HeadscaleWanGateManager) Start() {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		_ = m.Reconcile()
		for {
			select {
			case <-ticker.C:
				if err := m.Reconcile(); err != nil {
					log.Printf("[HeadscaleWanGate] Periodic reconcile error: %v", err)
				}
			case <-m.stopCh:
				return
			}
		}
	}()
}

// Stop terminates the background reconciliation loop cleanly.
func (m *HeadscaleWanGateManager) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
}
