package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHeadscaleWanGateLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	invitesPath := filepath.Join(tmpDir, "headscale-invites.json")
	mgr := NewHeadscaleWanGateManager(tmpDir, false)

	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	mgr.nowFn = func() time.Time { return now }

	var appliedScripts []string
	mgr.nftApplyFn = func(stdin string) error {
		appliedScripts = append(appliedScripts, stdin)
		return nil
	}
	mgr.nftListSetFn = func(setName string) ([]string, error) {
		if setName == "headscale_knock_allow_v4" {
			return []string{"198.51.100.42"}, nil
		}
		return []string{"2001:db8::99"}, nil
	}

	cfgBytes, _ := json.Marshal(HeadscaleWanConfig{
		Enabled:              true,
		BindPort:             8443,
		Hostname:             "join.example.com",
		AutoWindow:           true,
		PortKnockingEnabled:  true,
		KnockProtocol:        "udp",
		KnockSequence:        []int{41821, 52913, 38477},
		KnockStepTimeoutSec:  15,
		KnockOpenDurationSec: 900,
	})
	if err := mgr.ApplyConfig(cfgBytes); err != nil {
		t.Fatalf("ApplyConfig failed: %v", err)
	}

	// 1. No invites => closed & flushed
	st := mgr.SyncFromInvites()
	if st.WindowOpen || st.Reason != "closed" || st.PendingCount != 0 {
		t.Fatalf("expected closed with 0 invites, got %+v", st)
	}
	if len(appliedScripts) == 0 || !strings.Contains(appliedScripts[len(appliedScripts)-1], "flush set inet axonwall headscale_wan_window_ports") {
		t.Fatalf("expected flush script, got %v", appliedScripts)
	}

	// 2. Write one valid pending invite (+1h) and one expired invite
	invites := []map[string]any{
		{"status": "pending", "expiresAt": now.Add(1 * time.Hour).Format(time.RFC3339)},
		{"status": "pending", "expiresAt": now.Add(-5 * time.Minute).Format(time.RFC3339)},
		{"status": "redeemed", "expiresAt": now.Add(24 * time.Hour).Format(time.RFC3339)},
	}
	rawInvites, _ := json.Marshal(invites)
	if err := os.WriteFile(invitesPath, rawInvites, 0600); err != nil {
		t.Fatalf("write invites: %v", err)
	}

	st = mgr.SyncFromInvites()
	if !st.WindowOpen || st.Reason != "pending_invites" || st.PendingCount != 1 {
		t.Fatalf("expected open pending_invites(1), got %+v", st)
	}
	lastScript := appliedScripts[len(appliedScripts)-1]
	if !strings.Contains(lastScript, "add element inet axonwall headscale_wan_window_ports { 8443 timeout 3600s }") {
		t.Fatalf("unexpected nft add script: %s", lastScript)
	}
	if len(st.KnockedIPs) != 2 || st.KnockedIPs[0] != "198.51.100.42" || st.KnockedIPs[1] != "2001:db8::99" {
		t.Fatalf("expected knocked IPs from v4+v6 sets, got %v", st.KnockedIPs)
	}

	// 3. Redeem last invite => immediate close
	invites[0]["status"] = "redeemed"
	rawInvites, _ = json.Marshal(invites)
	_ = os.WriteFile(invitesPath, rawInvites, 0600)

	st = mgr.SyncFromInvites()
	if st.WindowOpen || st.Reason != "closed" {
		t.Fatalf("expected closed after redeem, got %+v", st)
	}
	lastScript = appliedScripts[len(appliedScripts)-1]
	if strings.Contains(lastScript, "add element") {
		t.Fatalf("did not expect add element after last invite redeemed: %s", lastScript)
	}

	// 4. Manual arm for 1800s and close early
	st, err := mgr.ArmManual(1800)
	if err != nil {
		t.Fatalf("ArmManual failed: %v", err)
	}
	if !st.WindowOpen || st.Reason != "manual_arm" {
		t.Fatalf("expected manual_arm open, got %+v", st)
	}
	if !strings.Contains(appliedScripts[len(appliedScripts)-1], "add element inet axonwall headscale_wan_window_ports { 8443 timeout 1800s }") {
		t.Fatalf("unexpected manual arm nft script: %s", appliedScripts[len(appliedScripts)-1])
	}

	st, err = mgr.ArmManual(0)
	if err != nil {
		t.Fatalf("ArmManual(0) failed: %v", err)
	}
	if st.WindowOpen || st.Reason != "closed" {
		t.Fatalf("expected closed after ArmManual(0), got %+v", st)
	}

	// 5. AutoWindow false => always_open
	alwaysOpenBytes, _ := json.Marshal(HeadscaleWanConfig{
		Enabled:    true,
		BindPort:   8443,
		Hostname:   "join.example.com",
		AutoWindow: false,
	})
	_ = mgr.ApplyConfig(alwaysOpenBytes)
	st = mgr.SyncFromInvites()
	if !st.WindowOpen || st.Reason != "always_open" {
		t.Fatalf("expected always_open, got %+v", st)
	}

	// 6. Disabled config => disabled & flushed
	disabledBytes, _ := json.Marshal(HeadscaleWanConfig{Enabled: false, BindPort: 8443, AutoWindow: true})
	_ = mgr.ApplyConfig(disabledBytes)
	st = mgr.SyncFromInvites()
	if st.WindowOpen || st.Reason != "disabled" {
		t.Fatalf("expected disabled, got %+v", st)
	}
}

func TestParseNftSetIPsJSON(t *testing.T) {
	sample := []byte(`{
	  "nftables": [
	    {"metainfo": {"version": "1.1.7"}},
	    {"set": {
	      "family": "inet",
	      "name": "headscale_knock_allow_v4",
	      "type": "ipv4_addr",
	      "elem": [
	        {"elem": {"val": "203.0.113.10", "timeout": 900, "expires": 842}},
	        "198.51.100.7"
	      ]
	    }}
	  ]
	}`)
	ips, err := ParseNftSetIPsJSON(sample)
	if err != nil {
		t.Fatalf("ParseNftSetIPsJSON failed: %v", err)
	}
	if len(ips) != 2 || ips[0] != "198.51.100.7" || ips[1] != "203.0.113.10" {
		t.Fatalf("unexpected parsed IPs: %v", ips)
	}
}
