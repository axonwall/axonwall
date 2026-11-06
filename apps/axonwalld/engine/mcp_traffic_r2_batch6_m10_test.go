package engine

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Round-2 batch 6 (daemon mediums) regression tests for A-M10: DNS
// sinkhole reconcile failures must fail the lease instead of leaving
// it listed as active while DNS still resolves.

// installFakeUnboundControl prepends a directory containing a fake
// `unbound-control` executable to PATH and returns the path of the
// file the fake appends its invocations to. The fake exits with the
// given status, so tests do not depend on the sandbox's Unbound.
func installFakeUnboundControl(t *testing.T, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "unbound-control-args.log")
	script := "#!/bin/sh\n" +
		"echo \"$@\" >> \"" + logPath + "\"\n" +
		"exit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "unbound-control"), []byte(script), 0755); err != nil {
		t.Fatalf("Failed to write fake unbound-control: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return logPath
}

// redirectSinkholePath points the sinkhole config at a temp file and
// returns its path.
func redirectSinkholePath(t *testing.T) string {
	t.Helper()
	orig := unboundMcpSinkholePath
	path := filepath.Join(t.TempDir(), "unbound.conf.d", "mcp-sinkhole.conf")
	unboundMcpSinkholePath = path
	t.Cleanup(func() { unboundMcpSinkholePath = orig })
	return path
}

func sinkholeLease(domain string) *McpTacticalLease {
	now := time.Now().UTC()
	return &McpTacticalLease{
		ID:               "mcp_lease_sink",
		Kind:             "dns_sinkhole",
		CreatedAt:        now.Format(time.RFC3339),
		ExpiresAt:        now.Add(time.Hour).Format(time.RFC3339),
		NormalizedTarget: domain,
		Parameters: map[string]interface{}{
			"domain":            domain,
			"sinkholeIp":        "0.0.0.0",
			"includeSubdomains": false,
		},
	}
}

// M10: a working reload writes the sinkhole config and reloads Unbound.
func TestR2Batch6SinkholeReconcileWritesConfigAndReloads(t *testing.T) {
	logPath := installFakeUnboundControl(t, 0)
	cfgPath := redirectSinkholePath(t)
	mgr := newTestTrafficManager(t)

	if err := mgr.reconcileDnsSinkholes([]*McpTacticalLease{sinkholeLease("evil.example.com")}); err != nil {
		t.Fatalf("reconcileDnsSinkholes failed with working unbound-control: %v", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("sinkhole config was not written: %v", err)
	}
	if !strings.Contains(string(data), `local-zone: "evil.example.com." transparent`) ||
		!strings.Contains(string(data), `local-data: "evil.example.com. 60 IN A 0.0.0.0"`) {
		t.Fatalf("sinkhole config missing the expected zone/data lines: %q", string(data))
	}
	args, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(args), "reload") {
		t.Fatalf("unbound-control reload was not invoked, log: %q (err %v)", string(args), err)
	}
}

// M10: a failed reload is an error, not a silent success.
func TestR2Batch6SinkholeReconcileReloadFailureReturnsError(t *testing.T) {
	installFakeUnboundControl(t, 1)
	cfgPath := redirectSinkholePath(t)
	mgr := newTestTrafficManager(t)

	err := mgr.reconcileDnsSinkholes([]*McpTacticalLease{sinkholeLease("evil.example.com")})
	if err == nil {
		t.Fatal("reconcileDnsSinkholes succeeded when unbound-control reload failed")
	}
	if !strings.Contains(err.Error(), "reload") {
		t.Fatalf("error did not name the reload failure: %v", err)
	}
	// The config write itself still landed; only the reload failed.
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("sinkhole config was not written before the reload failure: %v", err)
	}
}

// M10: with no sinkhole leases and no sinkhole file on disk there is
// nothing to reconcile — Unbound is not even invoked, so an unrelated
// lease create does not fail just because Unbound is down.
func TestR2Batch6SinkholeReconcileNoLeasesSkipsReload(t *testing.T) {
	logPath := installFakeUnboundControl(t, 1)
	redirectSinkholePath(t)
	mgr := newTestTrafficManager(t)

	if err := mgr.reconcileDnsSinkholes(nil); err != nil {
		t.Fatalf("reconcileDnsSinkholes with no sinkhole leases failed: %v", err)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatal("unbound-control was invoked with nothing to reconcile")
	}
}

// M10: a stale sinkhole file with no active sinkhole leases is removed
// and Unbound reloaded so it stops serving the withdrawn sinkhole.
func TestR2Batch6SinkholeReconcileRemovesStaleConfig(t *testing.T) {
	logPath := installFakeUnboundControl(t, 0)
	cfgPath := redirectSinkholePath(t)
	mgr := newTestTrafficManager(t)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		t.Fatalf("failed to create sinkhole dir: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte("stale\n"), 0644); err != nil {
		t.Fatalf("failed to write stale sinkhole config: %v", err)
	}

	if err := mgr.reconcileDnsSinkholes(nil); err != nil {
		t.Fatalf("reconcileDnsSinkholes failed removing a stale config: %v", err)
	}
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Fatal("stale sinkhole config was not removed")
	}
	args, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(args), "reload") {
		t.Fatalf("unbound-control reload was not invoked after removing the stale config, log: %q (err %v)", string(args), err)
	}
}

// M10: when the stale-config removal succeeds but the reload fails,
// the failure is still reported (Unbound keeps serving the old config
// in memory until a reload lands).
func TestR2Batch6SinkholeReconcileStaleRemoveReloadFailure(t *testing.T) {
	installFakeUnboundControl(t, 1)
	cfgPath := redirectSinkholePath(t)
	mgr := newTestTrafficManager(t)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		t.Fatalf("failed to create sinkhole dir: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte("stale\n"), 0644); err != nil {
		t.Fatalf("failed to write stale sinkhole config: %v", err)
	}

	if err := mgr.reconcileDnsSinkholes(nil); err == nil {
		t.Fatal("reconcileDnsSinkholes succeeded when the post-removal reload failed")
	}
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Fatal("stale sinkhole config was not removed before the reload attempt")
	}
}

// M10: end to end — creating a sinkhole lease fails closed when the
// reload fails, and the lease is not stored, persisted, or listed.
func TestR2Batch6SinkholeCreationFailsWhenReloadFails(t *testing.T) {
	installFakeNft(t, 0)
	installFakeUnboundControl(t, 1)
	redirectSinkholePath(t)
	mgr := newTestTrafficManager(t)

	req := McpDnsSinkholeReq{
		Domain:     "evil.example.com",
		SinkholeIP: "0.0.0.0",
		TTLSeconds: 3600,
		KeyID:      "test-key",
		KeyName:    "test-agent",
	}
	if _, err := mgr.SinkholeDNS(req); err == nil {
		t.Fatal("SinkholeDNS succeeded when unbound-control reload failed; expected a fail-closed error")
	}
	if got := len(mgr.leases); got != 0 {
		t.Fatalf("failed sinkhole lease was stored anyway (%d leases)", got)
	}
	if got := len(mgr.ListLeases()); got != 0 {
		t.Fatalf("failed sinkhole lease is listed as active (%d leases)", got)
	}
}

// M10: the happy path still creates the lease when the reload lands.
func TestR2Batch6SinkholeCreationSucceedsWhenReloadSucceeds(t *testing.T) {
	installFakeNft(t, 0)
	installFakeUnboundControl(t, 0)
	cfgPath := redirectSinkholePath(t)
	mgr := newTestTrafficManager(t)

	req := McpDnsSinkholeReq{
		Domain:     "evil.example.com",
		SinkholeIP: "0.0.0.0",
		TTLSeconds: 3600,
		KeyID:      "test-key",
		KeyName:    "test-agent",
	}
	lease, err := mgr.SinkholeDNS(req)
	if err != nil {
		t.Fatalf("SinkholeDNS failed with working nft and unbound-control: %v", err)
	}
	if lease == nil || lease.Kind != "dns_sinkhole" {
		t.Fatalf("SinkholeDNS returned wrong lease: %+v", lease)
	}
	if got := len(mgr.ListLeases()); got != 1 {
		t.Fatalf("expected 1 listed lease, got %d", got)
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("sinkhole config was not written: %v", err)
	}
}
