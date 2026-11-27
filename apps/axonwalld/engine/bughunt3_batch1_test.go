package engine

// Round-3 bug-hunt fix regressions, batch 1 (Go daemons):
// A-H1 DDNS, A-H2 k3s join latch, A-H3 XDP blocks, A-H4 netdev bundle,
// A-M1 QGA errors, A-M2 CloneVM, A-M3 snapshot cleanup, A-M4 live migration.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------- A-H3

func TestBughunt3_XdpBlockWithoutEbpf(t *testing.T) {
	// The hunt's repro: unstarted manager, AddXdpBlock must now
	// error and the snapshot must list nothing as active.
	mgr := NewEBPFManager()
	defer mgr.Stop()

	for _, target := range []string{
		"198.51.100.99",
		"2001:db8::1",
		"198.51.100.0/24",
		"2001:db8:c0de::/48",
	} {
		if err := mgr.AddXdpBlock(target, 3600, XdpReasonMcpTactical, "hunt repro"); err == nil {
			t.Fatalf("expected AddXdpBlock(%s) on an unstarted manager to fail, got nil", target)
		}
	}
	snap := mgr.GetDataplaneSnapshot(10)
	if snap.Running {
		t.Fatalf("expected Running=false for an unstarted manager")
	}
	if len(snap.AttachedInterfaces) != 0 {
		t.Fatalf("expected no attached interfaces, got %v", snap.AttachedInterfaces)
	}
	if len(snap.ActiveBlocks) != 0 {
		t.Fatalf("expected 0 active blocks, got %d (%+v)", len(snap.ActiveBlocks), snap.ActiveBlocks)
	}
}

func TestBughunt3_XdpStartWithNoInterfacesFails(t *testing.T) {
	mgr := NewEBPFManager()
	defer mgr.Stop()
	if err := mgr.Start(nil); err == nil {
		t.Fatalf("expected Start(nil) to fail, got nil")
	}
	if err := mgr.Start([]string{"does-not-exist-xyz"}); err == nil {
		t.Fatalf("expected Start with only unknown interfaces to fail, got nil")
	}
	// A failed Start must leave the manager non-enforcing.
	if err := mgr.AddXdpBlock("198.51.100.99", 3600, XdpReasonMcpTactical, "after failed start"); err == nil {
		t.Fatalf("expected AddXdpBlock after a failed Start to fail, got nil")
	}
}

// ---------------------------------------------------------------- A-H1

func bughunt3DdnsManager(t *testing.T, rawJSON string) *DdnsManager {
	t.Helper()
	mgr := NewDdnsManager()
	mgr.SetAllowLoopbackForTest(true)
	if err := mgr.ApplyConfigJSON([]byte(rawJSON)); err != nil {
		t.Fatalf("ApplyConfigJSON failed: %v", err)
	}
	return mgr
}

func TestBughunt3_DdnsUnimplementedProvidersNeverReconciled(t *testing.T) {
	mgr := bughunt3DdnsManager(t, `{"enabled": true, "entries": [
		{"provider": "route53", "hostname": "host.example.com", "interface": "", "ipVersion": "4", "apiToken": "tok", "enabled": true},
		{"provider": "linode", "hostname": "host.example.com", "interface": "", "ipVersion": "4", "apiToken": "tok", "enabled": true},
		{"provider": "cloudflare", "hostname": "host.example.com", "interface": "", "ipVersion": "4", "enabled": true}
	]}`)
	st := mgr.TriggerSyncNow()
	if len(st.Entries) != 3 {
		t.Fatalf("expected 3 status entries, got %d", len(st.Entries))
	}
	for _, e := range st.Entries {
		if strings.Contains(e.LastStatusMsg, "Reconciled") {
			t.Fatalf("entry %s still reports Reconciled: %q", e.Provider, e.LastStatusMsg)
		}
		if !strings.Contains(e.LastStatusMsg, "Not implemented") && !strings.Contains(e.LastStatusMsg, "not configured") {
			t.Fatalf("entry %s: expected an honest not-implemented/not-configured message, got %q", e.Provider, e.LastStatusMsg)
		}
		if e.LastSyncAt != "" {
			t.Fatalf("entry %s: LastSyncAt must stay empty when nothing was updated, got %q", e.Provider, e.LastSyncAt)
		}
	}
}

func TestBughunt3_DdnsDuckDNSUsesInterfaceIP(t *testing.T) {
	var gotIP, gotDomains string
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		gotIP = r.URL.Query().Get("ip")
		gotDomains = r.URL.Query().Get("domains")
		if r.URL.Query().Get("token") != "tok123" {
			t.Errorf("expected token tok123, got %q", r.URL.Query().Get("token"))
		}
		_, _ = w.Write([]byte("OK"))
	}))
	defer srv.Close()

	mgr := NewDdnsManager()
	mgr.SetAllowLoopbackForTest(true)
	mgr.duckdnsBaseURL = srv.URL
	if err := mgr.ApplyConfigJSON([]byte(`{"enabled": true, "entries": [
		{"provider": "duckdns", "hostname": "myhost.duckdns.org", "interface": "", "ipVersion": "4", "apiToken": "tok123", "enabled": true}
	]}`)); err != nil {
		t.Fatalf("ApplyConfigJSON failed: %v", err)
	}
	st := mgr.TriggerSyncNow()
	if calls != 1 {
		t.Fatalf("expected exactly 1 DuckDNS call, got %d", calls)
	}
	if gotIP == "" {
		t.Fatalf("DuckDNS was called with an empty ip= (the A-H1 bug)")
	}
	if gotIP == "127.0.0.1" {
		t.Fatalf("DuckDNS was called with loopback ip=127.0.0.1; expected a global address")
	}
	if gotDomains != "myhost" {
		t.Fatalf("expected domains=myhost, got %q", gotDomains)
	}
	if len(st.Entries) != 1 || !strings.Contains(st.Entries[0].LastStatusMsg, "DuckDNS OK") {
		t.Fatalf("expected DuckDNS OK status, got %+v", st.Entries)
	}
	if st.Entries[0].LastSyncAt == "" {
		t.Fatalf("expected LastSyncAt to be set after a successful update")
	}
}

func TestBughunt3_DdnsDuckDNSNoIPFailsWithoutCalling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("DuckDNS must not be called when the interface has no usable IP")
		_, _ = w.Write([]byte("OK"))
	}))
	defer srv.Close()

	mgr := NewDdnsManager()
	mgr.SetAllowLoopbackForTest(true)
	mgr.duckdnsBaseURL = srv.URL
	if err := mgr.ApplyConfigJSON([]byte(`{"enabled": true, "entries": [
		{"provider": "duckdns", "hostname": "myhost.duckdns.org", "interface": "lo", "ipVersion": "4", "apiToken": "tok123", "enabled": true}
	]}`)); err != nil {
		t.Fatalf("ApplyConfigJSON failed: %v", err)
	}
	st := mgr.TriggerSyncNow()
	if len(st.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(st.Entries))
	}
	if !strings.Contains(st.Entries[0].LastStatusMsg, "no IPv4 address on interface") {
		t.Fatalf("expected a no-address failure message, got %q", st.Entries[0].LastStatusMsg)
	}
	if st.Entries[0].LastSyncAt != "" {
		t.Fatalf("LastSyncAt must stay empty on failure, got %q", st.Entries[0].LastSyncAt)
	}
}

func TestBughunt3_DdnsCustomHttpURLFires(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mgr := bughunt3DdnsManager(t, fmt.Sprintf(`{"enabled": true, "entries": [
		{"provider": "custom", "hostname": "host.example.com", "customUpdateUrl": %q, "enabled": true}
	]}`, srv.URL+"/update"))
	st := mgr.TriggerSyncNow()
	if calls != 1 {
		t.Fatalf("expected the http:// custom webhook to fire once, got %d calls", calls)
	}
	if !strings.Contains(st.Entries[0].LastStatusMsg, "Webhook HTTP 200") {
		t.Fatalf("expected Webhook HTTP 200, got %q", st.Entries[0].LastStatusMsg)
	}
}

func TestBughunt3_DdnsCloudflareUpdate(t *testing.T) {
	var gotContent, gotName string
	var putCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"success": true, "result": [{"id": "rec1"}]}`))
			return
		}
		if r.Method == http.MethodPut {
			putCalled = true
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotContent, _ = body["content"].(string)
			gotName, _ = body["name"].(string)
			_, _ = w.Write([]byte(`{"success": true, "result": {}}`))
			return
		}
		t.Errorf("unexpected Cloudflare call %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	mgr := NewDdnsManager()
	mgr.SetAllowLoopbackForTest(true)
	mgr.cloudflareBase = srv.URL
	if err := mgr.ApplyConfigJSON([]byte(`{"enabled": true, "entries": [
		{"provider": "cloudflare", "hostname": "host.example.com", "zone": "zone123", "interface": "", "ipVersion": "4", "apiToken": "tok", "enabled": true}
	]}`)); err != nil {
		t.Fatalf("ApplyConfigJSON failed: %v", err)
	}
	st := mgr.TriggerSyncNow()
	if !putCalled {
		t.Fatalf("expected Cloudflare record update (PUT) to be called")
	}
	if gotContent == "" || gotName != "host.example.com" {
		t.Fatalf("unexpected Cloudflare update: content=%q name=%q", gotContent, gotName)
	}
	if !strings.Contains(st.Entries[0].LastStatusMsg, "Cloudflare updated") {
		t.Fatalf("expected Cloudflare updated status, got %q", st.Entries[0].LastStatusMsg)
	}
}

func TestBughunt3_DdnsSameHostnameTwoProviders(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv2.Close()

	mgr := bughunt3DdnsManager(t, fmt.Sprintf(`{"enabled": true, "entries": [
		{"provider": "custom", "hostname": "host.example.com", "interface": "host0", "customUpdateUrl": %q, "enabled": true},
		{"provider": "custom", "hostname": "host.example.com", "interface": "", "customUpdateUrl": %q, "enabled": true}
	]}`, srv1.URL+"/one", srv2.URL+"/two"))
	st := mgr.TriggerSyncNow()
	if len(st.Entries) != 2 {
		t.Fatalf("expected 2 status rows for 2 entries sharing a hostname, got %d", len(st.Entries))
	}
	for _, e := range st.Entries {
		if !strings.Contains(e.LastStatusMsg, "Webhook HTTP 200") {
			t.Fatalf("expected both entries to report their own webhook result, got %q", e.LastStatusMsg)
		}
	}
}

func TestBughunt3_DdnsIntervalHonoured(t *testing.T) {
	if ddnsInterval(DdnsEntry{}) != 5*time.Minute {
		t.Fatalf("expected unset interval to default to 5m, got %v", ddnsInterval(DdnsEntry{}))
	}
	if ddnsInterval(DdnsEntry{CheckIntervalSeconds: 60}) != time.Minute {
		t.Fatalf("expected 60s interval, got %v", ddnsInterval(DdnsEntry{CheckIntervalSeconds: 60}))
	}

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mgr := NewDdnsManager()
	mgr.SetAllowLoopbackForTest(true)
	if err := mgr.ApplyConfigJSON([]byte(fmt.Sprintf(`{"enabled": true, "entries": [
		{"provider": "custom", "hostname": "host.example.com", "customUpdateUrl": %q, "checkIntervalSeconds": 3600, "enabled": true}
	]}`, srv.URL+"/update"))); err != nil {
		t.Fatalf("ApplyConfigJSON failed: %v", err)
	}
	// Just synced: the due-check must not fire again.
	mgr.mu.Lock()
	mgr.lastSync[ddnsStatusKey(mgr.cfg.Entries[0])] = time.Now()
	mgr.mu.Unlock()
	mgr.syncDueEntries()
	if calls != 0 {
		t.Fatalf("expected 0 calls while the per-entry interval has not elapsed, got %d", calls)
	}
	// Interval elapsed: the due-check must fire.
	mgr.mu.Lock()
	mgr.lastSync[ddnsStatusKey(mgr.cfg.Entries[0])] = time.Now().Add(-2 * time.Hour)
	mgr.mu.Unlock()
	mgr.syncDueEntries()
	if calls != 1 {
		t.Fatalf("expected 1 call after the interval elapsed, got %d", calls)
	}
}

// ---------------------------------------------------------------- A-H2

func bughunt3K3sTestDirs(t *testing.T) func() {
	t.Helper()
	etc := t.TempDir()
	man := t.TempDir()
	state := t.TempDir()
	vow := t.TempDir()
	return SetK3sPathsForTest(etc, man, state, vow)
}

func TestBughunt3_K3sJoinLatchNeedsMarker(t *testing.T) {
	restore := bughunt3K3sTestDirs(t)
	defer restore()
	stateDir := k3sStateDir

	// A stale token file with no marker: a daemon restart must NOT
	// resurrect "joined" for a join that never completed.
	if err := os.WriteFile(filepath.Join(stateDir, "k3s-join.token"), []byte("stale-token\n"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	mgr := NewK3sManager()
	mgr.LoadSavedConfig([]byte(`{"enabled": true, "role": "backup", "autoJoinHaPeer": true, "peerIp": "192.0.2.1"}`))
	if mgr.GetStatus().ClusterJoined {
		t.Fatalf("LoadSavedConfig latched joined from a token file alone (the A-H2 bug)")
	}

	// With the marker (written only after a successful restart),
	// the latch is restored.
	if err := os.WriteFile(filepath.Join(stateDir, "k3s-joined"), []byte("2026-11-12T00:00:00Z\n"), 0600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	mgr2 := NewK3sManager()
	mgr2.LoadSavedConfig([]byte(`{"enabled": true, "role": "backup", "autoJoinHaPeer": true, "peerIp": "192.0.2.1"}`))
	if !mgr2.GetStatus().ClusterJoined {
		t.Fatalf("expected marker-backed join to restore the latch")
	}

	// MarkHaAutoJoined persists the marker.
	mgr3 := NewK3sManager()
	_ = os.Remove(filepath.Join(stateDir, "k3s-joined"))
	mgr3.MarkHaAutoJoined("192.0.2.1")
	if !mgr3.GetStatus().ClusterJoined {
		t.Fatalf("expected MarkHaAutoJoined to latch")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "k3s-joined")); err != nil {
		t.Fatalf("expected MarkHaAutoJoined to write the join marker: %v", err)
	}
}

func TestBughunt3_K3sDisableClearsJoin(t *testing.T) {
	restore := bughunt3K3sTestDirs(t)
	defer restore()
	mgr := NewK3sManager()
	mgr.MarkHaAutoJoined("192.0.2.1")
	if !mgr.GetStatus().ClusterJoined {
		t.Fatalf("setup: expected latch before disable")
	}
	if err := mgr.ApplyConfig([]byte(`{"enabled": false}`)); err != nil {
		t.Fatalf("ApplyConfig disabled failed: %v", err)
	}
	if mgr.GetStatus().ClusterJoined {
		t.Fatalf("disabled cluster still reports ClusterJoined (the A-H2 bug)")
	}
	if _, err := os.Stat(filepath.Join(k3sStateDir, "k3s-joined")); !os.IsNotExist(err) {
		t.Fatalf("expected the join marker to be removed on disable, stat err=%v", err)
	}
}

func TestBughunt3_K3sStaleTokenDoesNotLatchOnApply(t *testing.T) {
	restore := bughunt3K3sTestDirs(t)
	defer restore()
	// Peer is unreachable (TEST-NET-1) and only a stale token exists.
	if err := os.WriteFile(filepath.Join(k3sStateDir, "k3s-join.token"), []byte("stale-token\n"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	mgr := NewK3sManager()
	// Apply fails at the k3s restart in this sandbox (no systemd
	// unit), which is the point: no restart success, no latch.
	_ = mgr.ApplyConfig([]byte(`{"enabled": true, "role": "backup", "autoJoinHaPeer": true, "peerIp": "192.0.2.1", "syncPort": 9876}`))
	if mgr.GetStatus().ClusterJoined {
		t.Fatalf("ApplyConfig latched joined from a stale cached token while the peer was unreachable (the A-H2 bug)")
	}
	if _, err := os.Stat(filepath.Join(k3sStateDir, "k3s-joined")); !os.IsNotExist(err) {
		t.Fatalf("expected no join marker after a failed apply, stat err=%v", err)
	}
}

// ---------------------------------------------------------------- A-H4

func TestBughunt3_NetdevBundleRejectsInvalidBondMode(t *testing.T) {
	err := ApplyNetdevBundleJSON([]byte(`{"bonds": [{"name": "bond0", "mode": "turbo", "slaves": ["eth0"]}]}`), jsonUnmarshalForTest)
	if err == nil || !strings.Contains(err.Error(), "invalid bond mode") {
		t.Fatalf("expected invalid-bond-mode error, got %v", err)
	}
}

func TestBughunt3_NetdevBundleMissingIpFails(t *testing.T) {
	// No `ip` binary on PATH: the bundle used to "apply" with
	// nothing done and return nil.
	t.Setenv("PATH", t.TempDir())
	err := ApplyNetdevBundleJSON([]byte(`{"vlans": [{"parent": "eth0", "tag": 10}]}`), jsonUnmarshalForTest)
	if err == nil || !strings.Contains(err.Error(), "ip command not found") {
		t.Fatalf("expected missing-ip error, got %v", err)
	}
}

func TestBughunt3_NetdevBundleMissingVlanParent(t *testing.T) {
	err := ApplyNetdevBundleJSON([]byte(`{"vlans": [{"parent": "eth9", "tag": 10}]}`), jsonUnmarshalForTest)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected missing-parent error, got %v", err)
	}
}

func TestBughunt3_NetdevBundleBadVip(t *testing.T) {
	err := ApplyNetdevBundleJSON([]byte(`{"virtualIps": [{"ip": "not-an-ip", "interface": "eth0"}]}`), jsonUnmarshalForTest)
	if err == nil || !strings.Contains(err.Error(), "invalid virtual IP") {
		t.Fatalf("expected invalid-VIP error, got %v", err)
	}
}

func jsonUnmarshalForTest(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// ---------------------------------------------------------------- A-M1

// bughunt3FakeQga serves canned QGA replies on the VM's agent socket.
func bughunt3FakeQga(t *testing.T, vmid int, reply func(cmd string) string) {
	t.Helper()
	oldQgaDir := virtQgaSocketDir
	virtQgaSocketDir = t.TempDir()
	t.Cleanup(func() { virtQgaSocketDir = oldQgaDir })
	sockPath := filepath.Join(virtQgaSocketDir, fmt.Sprintf("vm-%d.sock", vmid))
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen qga socket: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				line, _ := reader.ReadString('\n')
				var req map[string]any
				_ = json.Unmarshal([]byte(line), &req)
				cmd, _ := req["execute"].(string)
				_, _ = fmt.Fprintln(c, reply(cmd))
			}(conn)
		}
	}()
}

func TestBughunt3_QgaGuestErrorSurfaced(t *testing.T) {
	bughunt3FakeQga(t, 999, func(cmd string) string {
		return `{"error": {"class": "GenericError", "desc": "guest-fsfreeze-freeze is not enabled"}}`
	})
	vm := NewVirtManager(NewTaskManager(), NewNasManager())

	if _, err := SendQGACommand(999, "guest-fsfreeze-freeze", nil); err == nil {
		t.Fatalf("expected SendQGACommand to surface the guest error reply, got nil")
	} else if !IsQgaGuestError(err) {
		t.Fatalf("expected a QgaGuestError, got %T: %v", err, err)
	}
	if err := vm.QgaFsFreeze(999); err == nil {
		t.Fatalf("expected QgaFsFreeze to fail when the guest rejects the freeze, got nil")
	}
	if _, err := vm.QueryQgaInterfaces(999); err == nil {
		t.Fatalf("expected QueryQgaInterfaces to fail for an erroring agent, got nil (the old code reported available:true with [])")
	}
}

func TestBughunt3_QgaSuccessStillWorks(t *testing.T) {
	bughunt3FakeQga(t, 998, func(cmd string) string {
		switch cmd {
		case "guest-network-get-interfaces":
			return `{"return": [{"name": "eth0", "hardware-address": "aa:bb:cc:dd:ee:ff", "ip-addresses": [{"ip-address": "10.0.0.5"}]}]}`
		default:
			return `{"return": {}}`
		}
	})
	vm := NewVirtManager(NewTaskManager(), NewNasManager())
	if err := vm.QgaFsFreeze(998); err != nil {
		t.Fatalf("expected QgaFsFreeze to succeed on a good reply, got %v", err)
	}
	ifaces, err := vm.QueryQgaInterfaces(998)
	if err != nil {
		t.Fatalf("expected QueryQgaInterfaces to succeed, got %v", err)
	}
	if len(ifaces) != 1 || len(ifaces[0].IPAddresses) != 1 || ifaces[0].IPAddresses[0] != "10.0.0.5" {
		t.Fatalf("unexpected interfaces: %+v", ifaces)
	}
}

// ------------------------------------------------------- A-M2 / A-M3

func bughunt3FakeZfs(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "zfs.log")
	scriptPath := filepath.Join(dir, "zfs")
	full := "#!/bin/sh\nLOG=\"" + logPath + "\"\n" + script
	if err := os.WriteFile(scriptPath, []byte(full), 0755); err != nil {
		t.Fatalf("write fake zfs: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return logPath
}

func bughunt3ZfsLog(t *testing.T, logPath string) string {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		return ""
	}
	return string(data)
}

func bughunt3VirtManager(t *testing.T) (*VirtManager, *TaskManager) {
	t.Helper()
	oldPath := VirtSpecsPath
	VirtSpecsPath = filepath.Join(t.TempDir(), "virt-specs.json")
	t.Cleanup(func() { VirtSpecsPath = oldPath })
	tm := NewTaskManager()
	vm := NewVirtManager(tm, NewNasManager())
	vm.SetAllowedMigrationPeers([]string{"192.0.2.1"})
	return vm, tm
}

func TestBughunt3_CloneVMSourceZvolMissingFails(t *testing.T) {
	// Fake zfs: `list` fails for the source zvol (pool not imported
	// / disk never provisioned). The clone must fail, not register
	// a VM whose disks were never copied.
	logPath := bughunt3FakeZfs(t, "echo \"$@\" >> \"$LOG\"\ncase \"$1\" in list) exit 1;; *) exit 0;; esac\n")
	vm, _ := bughunt3VirtManager(t)
	if err := vm.RegisterVMSpec(CompiledVmSpec{
		VMID: 100, Name: "src",
		Disks: []VmDisk{{Name: "root", Pool: "tank", SizeGb: 10, Zvol: "tank/vms/vm-100-disk-0"}},
	}); err != nil {
		t.Fatalf("RegisterVMSpec failed: %v", err)
	}
	if _, err := vm.CloneVM(100, 200, "clone", true); err == nil {
		t.Fatalf("expected CloneVM to fail when the source zvol is absent, got nil")
	}
	if got := bughunt3ZfsLog(t, logPath); strings.Contains(got, "clone") {
		t.Fatalf("no clone should have been attempted, log: %s", got)
	}
}

func TestBughunt3_CloneVMFakeZfsCopiesDisks(t *testing.T) {
	logPath := bughunt3FakeZfs(t, "echo \"$@\" >> \"$LOG\"\nexit 0\n")
	vm, _ := bughunt3VirtManager(t)
	if err := vm.RegisterVMSpec(CompiledVmSpec{
		VMID: 100, Name: "src",
		Disks: []VmDisk{{Name: "root", Pool: "tank", SizeGb: 10, Zvol: "tank/vms/vm-100-disk-0"}},
	}); err != nil {
		t.Fatalf("RegisterVMSpec failed: %v", err)
	}
	cloned, err := vm.CloneVM(100, 200, "clone", true)
	if err != nil {
		t.Fatalf("expected CloneVM to succeed with a working zfs, got %v", err)
	}
	if len(cloned.Disks) != 1 || cloned.Disks[0].Zvol != "tank/vms/vm-200-disk-0" {
		t.Fatalf("unexpected cloned disks: %+v", cloned.Disks)
	}
	log := bughunt3ZfsLog(t, logPath)
	if !strings.Contains(log, "snapshot tank/vms/vm-100-disk-0@clone-200-") {
		t.Fatalf("expected a snapshot of the source zvol, log: %s", log)
	}
	if !strings.Contains(log, "clone tank/vms/vm-100-disk-0@clone-200-") || !strings.Contains(log, "tank/vms/vm-200-disk-0") {
		t.Fatalf("expected a linked clone into the destination zvol, log: %s", log)
	}
}

func TestBughunt3_SnapshotPartialFailureCleansUp(t *testing.T) {
	// Fake zfs: snapshot succeeds for disk-0, fails for disk-1;
	// destroy always succeeds and is logged.
	logPath := bughunt3FakeZfs(t, "echo \"$@\" >> \"$LOG\"\ncase \"$1\" in snapshot) case \"$2\" in *disk-1*) exit 1;; esac;; esac\nexit 0\n")
	vm, _ := bughunt3VirtManager(t)
	if err := vm.RegisterVMSpec(CompiledVmSpec{
		VMID: 100, Name: "src",
		Disks: []VmDisk{
			{Name: "root", Pool: "tank", SizeGb: 10, Zvol: "tank/vms/vm-100-disk-0"},
			{Name: "data", Pool: "tank", SizeGb: 10, Zvol: "tank/vms/vm-100-disk-1"},
		},
	}); err != nil {
		t.Fatalf("RegisterVMSpec failed: %v", err)
	}
	created, err := vm.CreateWorkloadSnapshot("vm", 100, "testlabel")
	if err == nil {
		t.Fatalf("expected CreateWorkloadSnapshot to fail when disk-1 snapshot fails, got nil (created=%v)", created)
	}
	if len(created) != 0 {
		t.Fatalf("expected no snapshots to remain after cleanup, got %v", created)
	}
	log := bughunt3ZfsLog(t, logPath)
	if !strings.Contains(log, "destroy tank/vms/vm-100-disk-0@testlabel") {
		t.Fatalf("expected the already-created disk-0 snapshot to be destroyed, log: %s", log)
	}
}

// ---------------------------------------------------------------- A-M4

// bughunt3FakeQmp serves canned QMP replies on the VM's QMP socket.
// statuses are returned in order for successive query-migrate calls.
// It returns an accessor for the number of query-migrate calls seen.
func bughunt3FakeQmp(t *testing.T, vmid int, statuses []string) func() int {
	t.Helper()
	oldQmpDir := virtQmpSocketDir
	virtQmpSocketDir = t.TempDir()
	t.Cleanup(func() { virtQmpSocketDir = oldQmpDir })
	sockPath := filepath.Join(virtQmpSocketDir, fmt.Sprintf("vm-%d.sock", vmid))
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen qmp socket: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})
	var mu sync.Mutex
	queryCount := 0
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// QMP greeting, then handshake, then one command.
				_, _ = fmt.Fprintln(c, `{"QMP": {"version": {"qemu": {"micro": 0, "minor": 0, "major": 8}, "package": "test"}}}`)
				reader := bufio.NewReader(c)
				if _, err := reader.ReadString('\n'); err != nil { // handshake
					return
				}
				_, _ = fmt.Fprintln(c, `{"return": {}}`)
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				var req map[string]any
				_ = json.Unmarshal([]byte(line), &req)
				cmd, _ := req["execute"].(string)
				switch cmd {
				case "migrate":
					_, _ = fmt.Fprintln(c, `{"return": {}}`)
				case "query-migrate":
					mu.Lock()
					idx := queryCount
					queryCount++
					mu.Unlock()
					status := "active"
					if idx < len(statuses) {
						status = statuses[idx]
					} else if len(statuses) > 0 {
						status = statuses[len(statuses)-1]
					}
					_, _ = fmt.Fprintf(c, "{\"return\": {\"status\": %q}}\n", status)
				default:
					_, _ = fmt.Fprintln(c, `{"return": {}}`)
				}
			}(conn)
		}
	}()
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		return queryCount
	}
}

func bughunt3WaitTask(t *testing.T, tm *TaskManager, upid string) *TaskRecord {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		rec, err := tm.GetTask(upid)
		if err != nil {
			t.Fatalf("GetTask failed: %v", err)
		}
		if rec.Status != "running" {
			return rec
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("task %s still running after 15s", upid)
	return nil
}

func TestBughunt3_LiveMigratePollsToCompletion(t *testing.T) {
	oldInterval, oldTimeout := liveMigratePollInterval, liveMigrateTimeout
	liveMigratePollInterval = 10 * time.Millisecond
	liveMigrateTimeout = 30 * time.Second
	defer func() {
		liveMigratePollInterval, liveMigrateTimeout = oldInterval, oldTimeout
	}()

	queries := bughunt3FakeQmp(t, 101, []string{"active", "completed"})
	vm, tm := bughunt3VirtManager(t)
	upid, err := vm.LiveMigrateVM(101, "192.0.2.1", "root@axonwall")
	if err != nil {
		t.Fatalf("LiveMigrateVM failed: %v", err)
	}
	rec := bughunt3WaitTask(t, tm, upid)
	if rec.Status != "stopped" || rec.ExitStatus != "OK" {
		t.Fatalf("expected migration task to complete OK, got status=%s exit=%s", rec.Status, rec.ExitStatus)
	}
	if queries() == 0 {
		t.Fatalf("expected query-migrate to be polled at least once; the task returned without observing completion")
	}
}

func TestBughunt3_LiveMigrateFailedMigrationFailsTask(t *testing.T) {
	oldInterval, oldTimeout := liveMigratePollInterval, liveMigrateTimeout
	liveMigratePollInterval = 10 * time.Millisecond
	liveMigrateTimeout = 30 * time.Second
	defer func() {
		liveMigratePollInterval, liveMigrateTimeout = oldInterval, oldTimeout
	}()

	bughunt3FakeQmp(t, 101, []string{"active", "failed"})
	vm, tm := bughunt3VirtManager(t)
	upid, err := vm.LiveMigrateVM(101, "192.0.2.1", "root@axonwall")
	if err != nil {
		t.Fatalf("LiveMigrateVM failed: %v", err)
	}
	rec := bughunt3WaitTask(t, tm, upid)
	if rec.Status != "failed" {
		t.Fatalf("expected a failed migration to fail the task, got status=%s exit=%s (the A-M4 bug: task showed success)", rec.Status, rec.ExitStatus)
	}
}

func TestBughunt3_LiveMigrateQmpErrorFailsAndReleasesPort(t *testing.T) {
	oldQmpDir := virtQmpSocketDir
	virtQmpSocketDir = t.TempDir()
	t.Cleanup(func() { virtQmpSocketDir = oldQmpDir })
	sockPath := filepath.Join(virtQmpSocketDir, "vm-102.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen qmp socket: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = fmt.Fprintln(c, `{"QMP": {"version": {"qemu": {"micro": 0, "minor": 0, "major": 8}, "package": "test"}}}`)
				reader := bufio.NewReader(c)
				if _, err := reader.ReadString('\n'); err != nil {
					return
				}
				_, _ = fmt.Fprintln(c, `{"return": {}}`)
				_, _ = reader.ReadString('\n')
				_, _ = fmt.Fprintln(c, `{"error": {"class": "GenericError", "desc": "connection refused"}}`)
			}(conn)
		}
	}()

	vm, tm := bughunt3VirtManager(t)
	upid, err := vm.LiveMigrateVM(102, "192.0.2.1", "root@axonwall")
	if err != nil {
		t.Fatalf("expected LiveMigrateVM to launch migration task without destructive pre-probe, got error: %v", err)
	}
	rec := bughunt3WaitTask(t, tm, upid)
	if rec.Status != "failed" {
		t.Fatalf("expected QMP migrate rejection to fail task, got status=%s exit=%s", rec.Status, rec.ExitStatus)
	}
	vm.migMu.Lock()
	remaining := len(vm.migPorts)
	vm.migMu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected migration port to be released after QMP failure, got %d remaining", remaining)
	}
}

func TestBughunt3_MigrationPortAllocation(t *testing.T) {
	vm, _ := bughunt3VirtManager(t)
	p1, err := vm.allocateMigrationPort(101)
	if err != nil {
		t.Fatalf("allocateMigrationPort failed: %v", err)
	}
	p2, err := vm.allocateMigrationPort(101)
	if err != nil {
		t.Fatalf("second allocateMigrationPort failed: %v", err)
	}
	if p1 == p2 {
		t.Fatalf("two concurrent migrations got the same port %d (the A-M4 collision)", p1)
	}
	// Same VMID 1000 apart used to collide (49152 + vmid%1000).
	p3, err := vm.allocateMigrationPort(1101)
	if err != nil {
		t.Fatalf("allocateMigrationPort(1101) failed: %v", err)
	}
	if p3 == p1 || p3 == p2 {
		t.Fatalf("VMIDs differing by 1000 collided on port %d", p3)
	}
	vm.releaseMigrationPort(p1)
	p4, err := vm.allocateMigrationPort(101)
	if err != nil {
		t.Fatalf("allocate after release failed: %v", err)
	}
	if p4 != p1 {
		t.Fatalf("expected released port %d to be reusable, got %d", p1, p4)
	}
	vm.releaseMigrationPort(p2)
	vm.releaseMigrationPort(p3)
	vm.releaseMigrationPort(p4)
}
