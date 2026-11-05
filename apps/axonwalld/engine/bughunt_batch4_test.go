package engine

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A-M7 invariant: the master server retry loop must retire when the
// server is stopped. The test binds the target port with a scratch
// listener so the first bind fails, stops the manager, frees the
// port, and then checks that nothing starts serving on it.
//
// Honest scope note: this test passes on pre-fix code too, and the
// hunt report's literal trigger could not be reproduced — two
// experiments against this toolchain (go1.26) show that
// stopInternal's Close() already retires the loop, because
// http.Server.Close marks the server closed even when it never
// listened, so the next ListenAndServe returns ErrServerClosed
// without binding. The generation gate is therefore hardening, not
// a live-bug fix: it makes retirement explicit and independent of
// http.Server Close semantics, and it covers a replace-without-close
// that no current caller performs. The test pins the invariant
// (nothing serves after stop) rather than a pre-fix failure, and
// the poll window runs past the pre-fix 5s retry sleep so a
// resurrecting loop would still be caught.
func TestBatch4MasterServerRetryLoopRetiresOnStop(t *testing.T) {
	origDelay := masterServerRetryDelay
	masterServerRetryDelay = 50 * time.Millisecond
	defer func() { masterServerRetryDelay = origDelay }()

	occupier, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := occupier.Addr().(*net.TCPAddr).Port

	started := time.Now()
	m := NewSqliteSyncManager()
	m.mu.Lock()
	m.cfg = SqliteSyncConfig{ListenPort: port, LocalAddress: "127.0.0.1", AuthToken: "test-token"}
	if err := m.startMasterServer(); err != nil {
		m.mu.Unlock()
		t.Fatalf("startMasterServer failed: %v", err)
	}
	m.mu.Unlock()

	// Let the retry loop attempt (and fail) at least once, then stop
	// the manager and free the port.
	time.Sleep(150 * time.Millisecond)
	m.Stop()
	_ = occupier.Close()

	// Poll until 7s after start: past the pre-fix 5s retry sleep, so
	// a non-retiring loop has time to resurrect and be caught.
	for time.Since(started) < 7*time.Second {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("stopped master server retry loop bound the freed port; it must retire on stop")
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// A-M8 regression: the verified peer replica promotes to the live
// state path atomically, and a corrupt replica is never promoted.
func TestBatch4PromoteStateReplicaFile(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "state.json")
	replica := live + ".ha-replica"
	if err := os.WriteFile(live, []byte(`{"old":true}`), 0660); err != nil {
		t.Fatalf("write live: %v", err)
	}
	if err := os.WriteFile(replica, []byte(`{"new":true}`), 0600); err != nil {
		t.Fatalf("write replica: %v", err)
	}
	promoted, err := promoteStateReplicaFile(live, replica)
	if err != nil || !promoted {
		t.Fatalf("expected promotion, got promoted=%v err=%v", promoted, err)
	}
	data, _ := os.ReadFile(live)
	if string(data) != `{"new":true}` {
		t.Fatalf("live state was not replaced by the replica: %s", data)
	}

	// A missing replica is a no-op, not an error.
	if promoted, err := promoteStateReplicaFile(filepath.Join(dir, "absent.json"), filepath.Join(dir, "absent.json.ha-replica")); err != nil || promoted {
		t.Fatalf("missing replica must be a no-op, got promoted=%v err=%v", promoted, err)
	}

	// A corrupt replica must never become the live state.
	if err := os.WriteFile(replica, []byte(`{"torn":`), 0600); err != nil {
		t.Fatalf("write corrupt replica: %v", err)
	}
	if _, err := promoteStateReplicaFile(live, replica); err == nil {
		t.Fatalf("expected an error promoting a corrupt replica")
	}
	data, _ = os.ReadFile(live)
	if string(data) != `{"new":true}` {
		t.Fatalf("corrupt replica must not touch live state: %s", data)
	}
}

// A-M14 regression: GetTask/ListTasks return copies, not the live
// record. Pre-fix, mutating a returned record mutated the store (and
// concurrent reads raced the task goroutine's writes).
func TestBatch4GetTaskReturnsCopy(t *testing.T) {
	mgr := NewTaskManager()
	upid := mgr.StartTask("qmstart", "101", "root@axonwall", func(logger func(format string, args ...any)) error {
		return nil
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		task, err := mgr.GetTask(upid)
		if err != nil {
			t.Fatalf("GetTask failed: %v", err)
		}
		if task.Status != "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("task did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}

	got, err := mgr.GetTask(upid)
	if err != nil {
		t.Fatalf("GetTask failed: %v", err)
	}
	got.Status = "tampered"
	again, err := mgr.GetTask(upid)
	if err != nil {
		t.Fatalf("GetTask failed: %v", err)
	}
	if again.Status == "tampered" {
		t.Fatalf("GetTask returned the live record: mutating it mutated the store")
	}

	listed := mgr.ListTasks(10)
	if len(listed) == 0 {
		t.Fatalf("ListTasks returned nothing")
	}
	listed[0].Status = "tampered"
	againList := mgr.ListTasks(10)
	if againList[0].Status == "tampered" {
		t.Fatalf("ListTasks returned live records: mutating one mutated the store")
	}
}

// batch4FakeTcpdump installs a fake tcpdump on PATH. The script
// creates the -w output file (so parsePcap finds it) and exits with
// the given code.
func batch4FakeTcpdump(t *testing.T, exitCode string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nprev=\"\"\nfor a in \"$@\"; do\n  if [ \"$prev\" = \"-w\" ]; then touch \"$a\"; fi\n  prev=\"$a\"\ndone\nexit " + exitCode + "\n"
	if err := os.WriteFile(filepath.Join(dir, "tcpdump"), []byte(script), 0755); err != nil {
		t.Fatalf("write fake tcpdump: %v", err)
	}
	orig := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir+":"+orig); err != nil {
		t.Fatalf("set PATH: %v", err)
	}
	t.Cleanup(func() { _ = os.Setenv("PATH", orig) })
}

// A-M15 regression: a failed tcpdump run must return an error, not
// "success, 0 packets". Pre-fix, the run error was discarded.
func TestBatch4RunCaptureReturnsErrorOnFailedTcpdump(t *testing.T) {
	batch4FakeTcpdump(t, "1")
	mgr := &PacketCaptureManager{captureDir: t.TempDir()}
	if _, err := mgr.RunCapture(t.Context(), "eth0", "", 10); err == nil {
		t.Fatalf("expected an error from a failed tcpdump run")
	}
}

// A-M15 regression: capture IDs must be unique per capture, not per
// second. Pre-fix, two captures in the same second shared a filename.
func TestBatch4RunCaptureIDsUnique(t *testing.T) {
	batch4FakeTcpdump(t, "0")
	mgr := &PacketCaptureManager{captureDir: t.TempDir()}
	first, err := mgr.RunCapture(t.Context(), "eth0", "", 10)
	if err != nil {
		t.Fatalf("first capture failed: %v", err)
	}
	second, err := mgr.RunCapture(t.Context(), "eth0", "", 10)
	if err != nil {
		t.Fatalf("second capture failed: %v", err)
	}
	if first.ID == second.ID {
		t.Fatalf("capture IDs must be unique, both were %q", first.ID)
	}
	if !strings.HasPrefix(first.ID, "pcap-") || !strings.HasSuffix(first.PcapPath, ".pcap") {
		t.Fatalf("unexpected capture ID/path: %q %q", first.ID, first.PcapPath)
	}
}

// A-M17 regression: a missing nft binary fails health verification
// instead of passing as a simulated success. Pre-fix, the missing
// tool path returned CheckStatusPass and the slot was marked
// permanently healthy.
func TestBatch4VerifyNftablesMissingBinaryFails(t *testing.T) {
	dir := t.TempDir()
	orig := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir); err != nil {
		t.Fatalf("set PATH: %v", err)
	}
	defer func() { _ = os.Setenv("PATH", orig) }()

	we := &WatchdogEngine{}
	if got := we.verifyNftables(); got.Status != CheckStatusFail {
		t.Fatalf("missing nft binary must FAIL verification, got %s (%s)", got.Status, got.Detail)
	}
}

// A-M17 regression: the control-plane check must fail when no daemon
// socket or service responds. Pre-fix it passed merely because
// /run/axonwall could be created. (This test runs in an environment
// with no axonwalld sockets and no systemd axonwalld unit.)
func TestBatch4VerifyControlPlaneFailsWithNothingResponsive(t *testing.T) {
	for _, sock := range []string{"/run/axonwall/agent-api.sock", "/run/axonwall/agent.sock", "/run/axonwall/ha.sock"} {
		if _, err := os.Stat(sock); err == nil {
			t.Skipf("control-plane socket %s exists in this environment; cannot test the nothing-responsive path", sock)
		}
	}
	we := &WatchdogEngine{}
	if got := we.verifyControlPlane(); got.Status != CheckStatusFail {
		t.Fatalf("control-plane check with nothing responsive must FAIL, got %s (%s)", got.Status, got.Detail)
	}
}

// A-M17 guard: a listening control-plane socket still passes.
func TestBatch4VerifyControlPlanePassesWithSocket(t *testing.T) {
	if err := os.MkdirAll("/run/axonwall", 0755); err != nil {
		t.Skipf("cannot create /run/axonwall: %v", err)
	}
	ln, err := net.Listen("unix", "/run/axonwall/agent-api.sock")
	if err != nil {
		t.Skipf("cannot listen on test socket: %v", err)
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove("/run/axonwall/agent-api.sock")
	}()
	we := &WatchdogEngine{}
	if got := we.verifyControlPlane(); got.Status != CheckStatusPass {
		t.Fatalf("control-plane check with a listening socket must PASS, got %s (%s)", got.Status, got.Detail)
	}
}

// A-M18 regression: when HA is enabled, only MASTER may mutate the
// identity directory. Pre-fix, only BACKUP was blocked, so a FAULT
// node accepted writes while the real master also did.
func TestBatch4CheckWritePermittedAllowlist(t *testing.T) {
	cases := []struct {
		enabled bool
		role    string
		allowed bool
	}{
		{true, "MASTER", true},
		{true, "BACKUP", false},
		{true, "FAULT", false},
		{true, "", false},
		{false, "FAULT", true},
		{false, "", true},
	}
	for _, tc := range cases {
		d := &DirectoryManager{haEnabled: tc.enabled, haRole: tc.role}
		err := d.checkWritePermitted()
		if tc.allowed && err != nil {
			t.Errorf("haEnabled=%v role=%q: writes must be allowed, got %v", tc.enabled, tc.role, err)
		}
		if !tc.allowed && err == nil {
			t.Errorf("haEnabled=%v role=%q: writes must be blocked", tc.enabled, tc.role)
		}
	}
}
