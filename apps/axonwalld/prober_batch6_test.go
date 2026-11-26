package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/axonwall/axonwall/apps/axonwalld/engine"
)

// A-M6 regression: restart must wait for the old run goroutine to exit
// before starting a new one. Pre-fix, restart returned immediately while
// the old loop was still inside triggerFailover (an unbounded `ip route`
// exec), so two failover evaluations raced on the default route.
//
// The test uses fake `ping` (instant success) and fake `ip` (2s sleep)
// binaries on PATH so no kernel or network state is touched. It starts
// the prober, waits until the first triggerFailover's `ip` invocation
// has begun, then reloads: post-fix the reload blocks until the old
// loop has finished both of its `ip` invocations; pre-fix it returns
// in milliseconds.
func TestBatch6ProberRestartWaitsForOldLoop(t *testing.T) {
	dir := t.TempDir()
	ipLog := filepath.Join(dir, "ip.log")
	for name, script := range map[string]string{
		"ping": "#!/bin/sh\nexit 0\n",
		"ip":   "#!/bin/sh\necho \"$@\" >> " + ipLog + "\nsleep 2\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0755); err != nil {
			t.Fatalf("failed to write fake %s: %v", name, err)
		}
	}
	origPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir+":"+origPath); err != nil {
		t.Fatalf("failed to set PATH: %v", err)
	}

	p := NewSDWanProber()
	defer func() {
		p.stop()
		p.wg.Wait()
		_ = os.Setenv("PATH", origPath)
	}()

	cfg1 := filepath.Join(dir, "sdwan1.json")
	cfg2 := filepath.Join(dir, "sdwan2.json")
	cfgBody := func(name string) string {
		return `{"gateways":[{"name":"` + name + `","interface":"lo","gatewayIp":"127.0.0.1","weight":1,"isDefault":true,"enabled":true}]}`
	}
	if err := os.WriteFile(cfg1, []byte(cfgBody("gw1")), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg2, []byte(cfgBody("gw2")), 0644); err != nil {
		t.Fatal(err)
	}

	if err := p.ReloadConfig(cfg1); err != nil {
		t.Fatalf("first ReloadConfig failed: %v", err)
	}

	// Wait until the old loop is provably inside triggerFailover.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if data, err := os.ReadFile(ipLog); err == nil && len(data) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the first `ip` invocation")
		}
		time.Sleep(50 * time.Millisecond)
	}

	start := time.Now()
	if err := p.ReloadConfig(cfg2); err != nil {
		t.Fatalf("second ReloadConfig failed: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 1*time.Second {
		t.Fatalf("restart returned after %v; expected it to wait for the old loop's in-flight `ip` invocations (>= 1s)", elapsed)
	}

	p.mu.Lock()
	got := ""
	if p.config != nil && len(p.config.Gateways) > 0 {
		got = p.config.Gateways[0].Name
	}
	p.mu.Unlock()
	if got != "gw2" {
		t.Fatalf("expected reloaded config gw2, got %q", got)
	}
}

func TestParsePingOutputAndSnapshot(t *testing.T) {
	iputilsOut := "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n--- 1.1.1.1 ping statistics ---\n2 packets transmitted, 2 received, 0% packet loss, time 1001ms\nrtt min/avg/max/mdev = 10.0/15.5/21.0/3.25 ms\n"
	rtt, jitter, loss := ParsePingOutput(iputilsOut)
	if rtt != 15.5 || jitter != 3.25 || loss != 0 {
		t.Fatalf("iputils parse mismatch: got rtt=%v jitter=%v loss=%v", rtt, jitter, loss)
	}

	busyboxOut := "PING 8.8.8.8 (8.8.8.8): 56 data bytes\n--- 8.8.8.8 ping statistics ---\n2 packets transmitted, 1 packets received, 50% packet loss\nround-trip min/avg/max = 12.0/14.0/18.0 ms\n"
	rtt, jitter, loss = ParsePingOutput(busyboxOut)
	if rtt != 14.0 || jitter != 3.0 || loss != 50 {
		t.Fatalf("busybox parse mismatch: got rtt=%v jitter=%v loss=%v", rtt, jitter, loss)
	}

	rtt, jitter, loss = ParsePingOutput("")
	if loss != 100 || rtt != 0 || jitter != 0 {
		t.Fatalf("empty output parse mismatch: got rtt=%v jitter=%v loss=%v", rtt, jitter, loss)
	}

	p := NewSDWanProber()
	stateChanged := false
	p.mu.Lock()
	p.stats["wan2"] = engine.GatewayProbeStats{Name: "wan2", Up: true, RttMs: 9.2}
	p.active["wan1"] = true
	p.mu.Unlock()
	p.markGatewayOffline("wan1", &stateChanged)
	if !stateChanged {
		t.Fatalf("expected markGatewayOffline to set stateChanged=true for active gateway")
	}
	snap := p.Snapshot()
	if len(snap) != 2 || snap[0].Name != "wan1" || snap[1].Name != "wan2" {
		t.Fatalf("expected sorted snapshot for [wan1 wan2], got %+v", snap)
	}
	if snap[0].Up || snap[0].PacketLossPct != 100 {
		t.Fatalf("expected wan1 marked offline with 100%% loss, got %+v", snap[0])
	}
}
