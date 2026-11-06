package engine

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Batch 9 (round-2 daemon lows) regression tests.

// batch9FakeTcpdump installs a fake tcpdump on PATH that prints
// stdoutText and exits with exitCode.
func batch9FakeTcpdump(t *testing.T, stdoutText, exitCode string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s' '" + stdoutText + "'\nexit " + exitCode + "\n"
	if err := os.WriteFile(filepath.Join(dir, "tcpdump"), []byte(script), 0755); err != nil {
		t.Fatalf("write fake tcpdump: %v", err)
	}
	orig := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir+":"+orig); err != nil {
		t.Fatalf("set PATH: %v", err)
	}
	t.Cleanup(func() { _ = os.Setenv("PATH", orig) })
}

// L11: a failed tcpdump run must return an error, not "success, 0
// packets". Pre-fix, CapturePacketSample discarded tcpdump's error
// and stderr — the same lie A-M15 fixed in RunCapture.
func TestBatch9CapturePacketSampleReturnsErrorOnFailedTcpdump(t *testing.T) {
	batch9FakeTcpdump(t, "", "1")
	mgr := &McpTrafficManager{}
	if _, err := mgr.CapturePacketSample("eth0", "", "", "", 0, 20, 5); err == nil {
		t.Fatal("expected an error from a failed tcpdump run")
	}
}

// L11: a successful tcpdump run still parses packets.
func TestBatch9CapturePacketSampleParsesPackets(t *testing.T) {
	batch9FakeTcpdump(t, "1700000000.123456 IP 10.0.0.1.1234 > 10.0.0.2.80: Flags [S], seq 1\n", "0")
	mgr := &McpTrafficManager{}
	packets, err := mgr.CapturePacketSample("eth0", "", "", "", 0, 20, 5)
	if err != nil {
		t.Fatalf("CapturePacketSample failed: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	if packets[0].SrcIP != "10.0.0.1" || packets[0].DstIP != "10.0.0.2" {
		t.Fatalf("unexpected packet: %+v", packets[0])
	}
}

// L11: tcpdump missing entirely is an error, not an empty sample.
func TestBatch9CapturePacketSampleErrorsWithoutTcpdump(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	mgr := &McpTrafficManager{}
	if _, err := mgr.CapturePacketSample("eth0", "", "", "", 0, 20, 5); err == nil {
		t.Fatal("expected an error without tcpdump")
	} else if !strings.Contains(err.Error(), "tcpdump") {
		t.Fatalf("expected a tcpdump error, got: %v", err)
	}
}

// L12: snapshot/scrub must fail when the ZFS tooling is absent.
// Pre-fix, both returned success on a box without zfs/zpool — the
// caller was told a snapshot was created / a scrub ran when nothing
// happened.
func TestBatch9NasSnapshotScrubErrorWithoutZfs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	mgr := NewNasManager()
	if _, err := mgr.CreateSnapshot("tank/data", "test"); err == nil {
		t.Fatal("CreateSnapshot must fail without zfs installed")
	}
	if err := mgr.ScrubPool("tank"); err == nil {
		t.Fatal("ScrubPool must fail without zpool installed")
	}
}

// L13: the pcap parser must count IPv6 and ARP packets. Pre-fix,
// both regexes matched only "IP " lines, so IP6 and ARP packets
// were dropped without a trace and PacketCount understated the
// capture.
func TestBatch9ParseTcpdumpLineIPv6AndARP(t *testing.T) {
	pkt, ok := parseTcpdumpLine("1700000000.123456 IP6 2001:db8::1.54321 > 2001:db8::2.443: Flags [S], seq 1", 1)
	if !ok {
		t.Fatal("IP6 port line must parse")
	}
	if pkt.SrcIP != "2001:db8::1" || pkt.DstIP != "2001:db8::2" || pkt.SrcPort != "54321" || pkt.DstPort != "443" {
		t.Fatalf("unexpected IP6 packet: %+v", pkt)
	}
	if pkt.Protocol != "TLS/HTTPS" {
		t.Fatalf("expected TLS/HTTPS for port 443, got %q", pkt.Protocol)
	}

	pkt, ok = parseTcpdumpLine("1700000000.123456 IP6 2001:db8::1 > 2001:db8::2: ICMP6, echo request, seq 1", 2)
	if !ok {
		t.Fatal("IP6 generic line must parse")
	}
	if pkt.Protocol != "ICMPv6" {
		t.Fatalf("expected ICMPv6, got %q", pkt.Protocol)
	}

	pkt, ok = parseTcpdumpLine("1700000000.123456 ARP, Request who-has 192.168.1.1 tell 192.168.1.2, length 28", 3)
	if !ok {
		t.Fatal("ARP line must parse")
	}
	if pkt.Protocol != "ARP" {
		t.Fatalf("expected ARP, got %q", pkt.Protocol)
	}
	if !strings.Contains(pkt.Info, "who-has 192.168.1.1") {
		t.Fatalf("unexpected ARP info: %q", pkt.Info)
	}

	// IPv4 behaviour is unchanged.
	pkt, ok = parseTcpdumpLine("1700000000.123456 IP 10.0.0.1.1234 > 10.0.0.2.80: Flags [S], seq 1", 4)
	if !ok || pkt.Protocol != "HTTP" {
		t.Fatalf("IPv4 line must still parse as HTTP, got ok=%v pkt=%+v", ok, pkt)
	}
	if _, ok := parseTcpdumpLine("reading from file test.pcap, link-type EN10MB", 5); ok {
		t.Fatal("tcpdump banner lines must not parse as packets")
	}
}

// L14 (E3 residual): activation with an unreadable previous bootfs
// must refuse to arm. Pre-fix, the bootfs set already succeeded and
// a later arming failure left bootfs pointed at the new target while
// the other properties rolled back.
func TestBatch9ActivateRefusesWithUnreadableBootfs(t *testing.T) {
	zfsFake := &fakeZxCommands{
		props: map[string]string{
			"org.axonwall:active_be": "zroot/ROOT/axonwall-0.11.30",
			"org.axonwall:bootcount": "2",
			"org.axonwall:bootlimit": "5",
		},
	}
	// No "bootfs" prop: the zpool get fails.
	zpoolFake := &fakeZxCommands{props: map[string]string{}}
	engine := newZbmActivateTestEngine(t, zfsFake, zpoolFake)

	if err := engine.ActivateBootEnvironment("axonwall-0.11.31"); err == nil {
		t.Fatal("expected activation to fail with an unreadable bootfs")
	} else if !strings.Contains(err.Error(), "bootfs") {
		t.Fatalf("expected the error to name bootfs, got: %v", err)
	}
	if zpoolFake.hasSet("set bootfs=zroot/ROOT/axonwall-0.11.31 zroot") {
		t.Fatal("bootfs must never be set when the previous value is unknown")
	}
}

// L14: when the previous bootfs was "-" (none set), a failed arming
// must clear bootfs again instead of leaving it on the failed target.
func TestBatch9ActivateClearsBootfsWhenPreviousWasNone(t *testing.T) {
	zfsFake := &fakeZxCommands{
		props: map[string]string{
			"org.axonwall:active_be": "zroot/ROOT/axonwall-0.11.30",
			"org.axonwall:bootcount": "2",
			"org.axonwall:bootlimit": "5",
		},
		failSets: map[string]bool{"org.axonwall:active_be=zroot/ROOT/axonwall-0.11.31": true},
	}
	zpoolFake := &fakeZxCommands{
		props: map[string]string{"bootfs": "-"},
	}
	engine := newZbmActivateTestEngine(t, zfsFake, zpoolFake)

	if err := engine.ActivateBootEnvironment("axonwall-0.11.31"); err == nil {
		t.Fatal("expected activation to fail when the active_be set fails")
	}
	if !zpoolFake.hasSet("set bootfs= zroot") {
		t.Fatalf("expected bootfs to be cleared on rollback when the previous value was none; sets: %v", zpoolFake.sets)
	}
}

// L15: verification must not mark the slot healthy in memory when
// the bootcount commit to disk fails. Pre-fix, HealthVerified and
// BootCount=0 were set before the zfs/grubenv commit and both
// failures were only logged, so the status API reported a
// permanently-healthy slot while the on-disk bootcount still counted
// up toward fallback.
func TestBatch9VerificationDoesNotMarkHealthyOnCommitFailure(t *testing.T) {
	zfsFake := &fakeZxCommands{
		props:    map[string]string{},
		failSets: map[string]bool{"org.axonwall:bootcount=0": true},
	}
	zpoolFake := &fakeZxCommands{props: map[string]string{}}
	engine := newZbmActivateTestEngine(t, zfsFake, zpoolFake)
	passCheck := func(name string) func() HealthCheckResult {
		return func() HealthCheckResult {
			return HealthCheckResult{Name: name, Status: CheckStatusPass, Detail: "stubbed"}
		}
	}
	engine.checkInterfaces = passCheck("Network Interface Initialization")
	engine.checkNftables = passCheck("Atomic nftables kernel baseline")
	engine.checkControlPlane = passCheck("Control plane and management quorum")
	engine.status.InstallMode = "zbm"
	engine.status.ActiveRootDevice = "zroot/ROOT/axonwall-0.11.30"
	engine.status.BootCount = 2
	engine.status.BootLimit = 3

	engine.runVerificationSequence()

	status := engine.GetStatus()
	if status.HealthVerified {
		t.Fatal("slot must not be marked healthy when the bootcount commit fails")
	}
	if status.BootCount != 2 {
		t.Fatalf("BootCount must stay 2 when the commit fails, got %d", status.BootCount)
	}
}

// L15 (positive control): when the commit succeeds, the slot is
// marked healthy exactly as before.
func TestBatch9VerificationMarksHealthyOnCommitSuccess(t *testing.T) {
	zfsFake := &fakeZxCommands{props: map[string]string{}}
	zpoolFake := &fakeZxCommands{props: map[string]string{}}
	engine := newZbmActivateTestEngine(t, zfsFake, zpoolFake)
	passCheck := func(name string) func() HealthCheckResult {
		return func() HealthCheckResult {
			return HealthCheckResult{Name: name, Status: CheckStatusPass, Detail: "stubbed"}
		}
	}
	engine.checkInterfaces = passCheck("Network Interface Initialization")
	engine.checkNftables = passCheck("Atomic nftables kernel baseline")
	engine.checkControlPlane = passCheck("Control plane and management quorum")
	engine.status.InstallMode = "zbm"
	engine.status.ActiveRootDevice = "zroot/ROOT/axonwall-0.11.30"
	engine.status.BootCount = 2
	engine.status.BootLimit = 3

	engine.runVerificationSequence()

	status := engine.GetStatus()
	if !status.HealthVerified {
		t.Fatal("slot must be marked healthy when the bootcount commit succeeds")
	}
	if status.BootCount != 0 {
		t.Fatalf("BootCount must reset to 0 on a committed verification, got %d", status.BootCount)
	}
}

// L16: the telemetry stream must notice eve.json rotation and
// truncation. Pre-fix, it read forever from a dead fd after a
// rotation, sending nothing and reporting nothing.
func TestBatch9TelemetryFileRotated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	content := strings.Repeat("x", 100) + "\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write eve.json: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open eve.json: %v", err)
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		t.Fatalf("seek: %v", err)
	}
	consumed := telemetryConsumedOffset(f, reader)

	// No change: neither rotated nor truncated.
	if rotated, truncated := telemetryFileRotated(f, path, consumed); rotated || truncated {
		t.Fatalf("unchanged file reported rotated=%v truncated=%v", rotated, truncated)
	}

	// Rotation: rename away and create a new file at the path.
	if err := os.Rename(path, filepath.Join(dir, "eve.json.1")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := os.WriteFile(path, []byte("new\n"), 0644); err != nil {
		t.Fatalf("write new eve.json: %v", err)
	}
	if rotated, _ := telemetryFileRotated(f, path, consumed); !rotated {
		t.Fatal("renamed file must report rotated")
	}

	// Truncation: same inode, shrunk below the consumed offset.
	path2 := filepath.Join(dir, "eve2.json")
	if err := os.WriteFile(path2, []byte(strings.Repeat("y", 100)+"\n"), 0644); err != nil {
		t.Fatalf("write eve2.json: %v", err)
	}
	f2, err := os.Open(path2)
	if err != nil {
		t.Fatalf("open eve2.json: %v", err)
	}
	defer f2.Close()
	reader2 := bufio.NewReader(f2)
	if _, err := f2.Seek(0, io.SeekEnd); err != nil {
		t.Fatalf("seek: %v", err)
	}
	consumed2 := telemetryConsumedOffset(f2, reader2)
	if err := os.Truncate(path2, 10); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, truncated := telemetryFileRotated(f2, path2, consumed2); !truncated {
		t.Fatal("shrunk file must report truncated")
	}
}

// batch9SSEWriter is a thread-safe http.ResponseWriter + Flusher for
// streaming-handler tests.
type batch9SSEWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	header http.Header
	code   int
}

func (w *batch9SSEWriter) Header() http.Header { return w.header }
func (w *batch9SSEWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}
func (w *batch9SSEWriter) WriteHeader(code int) { w.code = code }
func (w *batch9SSEWriter) Flush()               {}
func (w *batch9SSEWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// L16: a live telemetry stream must keep delivering alerts after
// eve.json is rotated.
func TestBatch9TelemetryStreamReopensAfterRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(logPath, []byte{}, 0644); err != nil {
		t.Fatalf("write eve.json: %v", err)
	}
	vm := NewVigilanteManager(dir)
	vm.telemetryLog = logPath

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/v1/events/telemetry", nil).WithContext(ctx)
	rec := &batch9SSEWriter{header: http.Header{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		vm.StreamLiveTelemetry(rec, req)
	}()
	waitFor := func(want string) bool {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if strings.Contains(rec.String(), want) {
				return true
			}
			time.Sleep(50 * time.Millisecond)
		}
		return false
	}
	alert := func(sig string) string {
		return `{"timestamp":"2026-11-06T00:00:00Z","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","alert":{"signature":"` + sig + `","severity":2}}` + "\n"
	}

	// The stream seeks to end on open, so the first alert must be
	// appended after the handler starts.
	time.Sleep(300 * time.Millisecond)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open eve.json: %v", err)
	}
	if _, err := f.WriteString(alert("test one")); err != nil {
		t.Fatalf("write alert: %v", err)
	}
	_ = f.Close()
	if !waitFor("test one") {
		t.Fatal("first alert never streamed")
	}

	// Rotate to a fresh empty file, let the stream notice and
	// reopen (it seeks to the new end), then append the second alert.
	if err := os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := os.WriteFile(logPath, []byte{}, 0644); err != nil {
		t.Fatalf("write new eve.json: %v", err)
	}
	time.Sleep(1 * time.Second)
	f, err = os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open new eve.json: %v", err)
	}
	if _, err := f.WriteString(alert("test two")); err != nil {
		t.Fatalf("write alert: %v", err)
	}
	_ = f.Close()
	if !waitFor("test two") {
		cancel()
		<-done
		t.Fatal("no alert streamed after rotation; the stream died on the rotated fd")
	}
	cancel()
	<-done
}

// L17: GetTaskLog must not silently truncate at a >64 KiB log line.
// Pre-fix, the default scanner token limit stopped the scan and the
// error was never checked, so every line after the long one was
// permanently lost while the task appeared to stream normally.
func TestBatch9GetTaskLogReadsLongLines(t *testing.T) {
	mgr := NewTaskManager()
	longLine := strings.Repeat("x", 100*1024)
	upid := mgr.StartTask("test", "1", "root@axonwall", func(logger func(format string, args ...any)) error {
		logger("before")
		logger(longLine)
		logger("after")
		return nil
	})
	var task *TaskRecord
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		task, err = mgr.GetTask(upid)
		if err == nil && task.Status != "running" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("failed to get task: %v", err)
	}
	lines, done, err := mgr.GetTaskLog(upid, 1)
	if err != nil {
		t.Fatalf("GetTaskLog failed: %v", err)
	}
	if !done {
		t.Fatal("expected task to be done")
	}
	// TASK STARTED line + before + long line + after + TASK COMPLETED.
	if len(lines) != 5 {
		t.Fatalf("expected 5 log lines, got %d", len(lines))
	}
	if !strings.Contains(lines[2], longLine) {
		t.Fatal("long log line was not returned intact")
	}
	if !strings.Contains(lines[3], "after") {
		t.Fatalf("line after the long line was lost, got %q", lines[3])
	}
}

// L18: SMART status must come from smartctl, not hardcoded values.
// Pre-fix, every disk was reported SmartPassed=true at 34/36 °C.
func TestBatch9ParseSmartctlHealth(t *testing.T) {
	passed, known := parseSmartctlHealth("SMART overall-health self-assessment test result: PASSED\n")
	if !known || !passed {
		t.Fatalf("PASSED line must parse as passed+known, got passed=%v known=%v", passed, known)
	}
	passed, known = parseSmartctlHealth("SMART overall-health self-assessment test result: FAILED\n")
	if !known || passed {
		t.Fatalf("FAILED line must parse as failed+known, got passed=%v known=%v", passed, known)
	}
	if _, known := parseSmartctlHealth("no smart data here\n"); known {
		t.Fatal("output without a health line must parse as unknown")
	}
}

func TestBatch9ParseSmartctlTemperature(t *testing.T) {
	sata := "ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE\n194 Temperature_Celsius     0x0022   100   100   000    Old_age   Always       -       36 (Min/Max 20/45)\n"
	if temp, ok := parseSmartctlTemperature(sata); !ok || temp != 36 {
		t.Fatalf("SATA temperature must parse as 36, got %d ok=%v", temp, ok)
	}
	nvme := "Temperature:                        42 Celsius\n"
	if temp, ok := parseSmartctlTemperature(nvme); !ok || temp != 42 {
		t.Fatalf("NVMe temperature must parse as 42, got %d ok=%v", temp, ok)
	}
	if _, ok := parseSmartctlTemperature("no temperature here\n"); ok {
		t.Fatal("output without a temperature must parse as unknown")
	}
}

func TestBatch9QuerySmartHealthUnknownWithoutSmartctl(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	passed, known, temp := querySmartHealth("/dev/sda")
	if known || passed || temp != 0 {
		t.Fatalf("without smartctl, health must be unknown: passed=%v known=%v temp=%d", passed, known, temp)
	}
}
