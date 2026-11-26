package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/axonwall/axonwall/apps/axonwalld/gen/agent/v1"
	"github.com/axonwall/axonwall/apps/axonwalld/engine"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestBugfixGroup1_SingleNicLanDhcpNoNoGatewayFlag(t *testing.T) {
	dir := t.TempDir()
	etcDir := filepath.Join(dir, "etc")
	stateDir := filepath.Join(dir, "state")
	binDir := filepath.Join(dir, "bin")
	for _, d := range []string{etcDir, stateDir, binDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("AXONWALL_ETC_DIR", etcDir)
	t.Setenv("AXONWALL_STATE_DIR", stateDir)
	origOwned := staticRoutesOwnedPath
	staticRoutesOwnedPath = filepath.Join(dir, "owned-routes.json")
	t.Cleanup(func() { staticRoutesOwnedPath = origOwned })

	dhcpLog := filepath.Join(dir, "dhcpcd.log")
	for name, script := range map[string]string{
		"dhcpcd": "#!/bin/sh\necho \"$@\" >> " + dhcpLog + "\nexit 0\n",
		"ip": "#!/bin/sh\n" +
			"if [ \"$1\" = \"-4\" ] && [ \"$2\" = \"addr\" ]; then echo \"\"; exit 0; fi\n" +
			"exit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	prevMode := currentRuntimeMode
	currentRuntimeMode = engine.ModeAppliance
	t.Cleanup(func() {
		currentRuntimeMode = prevMode
		cancelPostBootVerification()
		dhcpLaunchMu.Lock()
		delete(dhcpRecentLaunch, "enp5s0")
		delete(dhcpRecentLaunch, "enp3s0")
		dhcpLaunchMu.Unlock()
	})

	// Single-NIC LAN-only DHCP node (!hasWan): must NOT pass -G or -C resolv.conf.
	if err := os.WriteFile(filepath.Join(etcDir, "interfaces.conf"), []byte("LAN_INTERFACE=enp5s0\nLAN_MODE=dhcp\n"), 0664); err != nil {
		t.Fatal(err)
	}
	if err := applyBootInterfaces(); err != nil {
		t.Fatalf("single-NIC LAN DHCP applyBootInterfaces failed: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(dhcpLog); err == nil && strings.Contains(string(b), "enp5s0") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancelPostBootVerification()
	logged, _ := os.ReadFile(dhcpLog)
	if !strings.Contains(string(logged), "-4 enp5s0") {
		t.Fatalf("expected single-NIC LAN DHCP to launch dhcpcd -4 enp5s0, got: %q", string(logged))
	}
	if strings.Contains(string(logged), "-G") || strings.Contains(string(logged), "resolv.conf") {
		t.Fatalf("single-NIC LAN DHCP must NOT receive -G or -C resolv.conf, got: %q", string(logged))
	}

	// Transition to dual-NIC WAN + LAN DHCP (hasWan): LAN must rebind with -G -C resolv.conf!
	_ = os.WriteFile(dhcpLog, nil, 0644)
	dualConf := "WAN_INTERFACE=enp3s0\nWAN_MODE=dhcp\nLAN_INTERFACE=enp5s0\nLAN_MODE=dhcp\n"
	if err := os.WriteFile(filepath.Join(etcDir, "interfaces.conf"), []byte(dualConf), 0664); err != nil {
		t.Fatal(err)
	}
	if err := applyBootInterfaces(); err != nil {
		t.Fatalf("dual-NIC DHCP applyBootInterfaces failed: %v", err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(dhcpLog); err == nil &&
			strings.Contains(string(b), "-4 enp3s0") &&
			strings.Contains(string(b), "-4 -G -C resolv.conf enp5s0") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancelPostBootVerification()
	logged, _ = os.ReadFile(dhcpLog)
	if !strings.Contains(string(logged), "-4 -G -C resolv.conf enp5s0") {
		t.Fatalf("expected dual-NIC LAN DHCP to transition to -4 -G -C resolv.conf enp5s0, got: %q", string(logged))
	}
	if !strings.Contains(string(logged), "-4 enp3s0") {
		t.Fatalf("expected dual-NIC WAN DHCP to run -4 enp3s0, got: %q", string(logged))
	}
}

func TestBugfixGroup1_SingleNicStaticLanGatewayAndDhcpHelpers(t *testing.T) {
	// 1. Legacy LAN_IPV4_GATEWAY parsing + conditional default route when !hasWan vs hasWan.
	dir := t.TempDir()
	etcDir := filepath.Join(dir, "etc")
	stateDir := filepath.Join(dir, "state")
	binDir := filepath.Join(dir, "bin")
	for _, d := range []string{etcDir, stateDir, binDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("AXONWALL_ETC_DIR", etcDir)
	t.Setenv("AXONWALL_STATE_DIR", stateDir)
	origOwned := staticRoutesOwnedPath
	staticRoutesOwnedPath = filepath.Join(dir, "owned-routes.json")
	t.Cleanup(func() { staticRoutesOwnedPath = origOwned })

	if err := os.WriteFile(filepath.Join(binDir, "ip"), []byte("#!/bin/sh\necho \"inet 10.60.0.10/24 brd 10.60.0.255 scope global enp5s0\"\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	var routeCalls []string
	origReplace := ipRouteReplaceDefault
	ipRouteReplaceDefault = func(gw, dev string) error {
		routeCalls = append(routeCalls, gw+"@"+dev)
		return nil
	}
	t.Cleanup(func() { ipRouteReplaceDefault = origReplace })

	prevMode := currentRuntimeMode
	currentRuntimeMode = engine.ModeAppliance
	t.Cleanup(func() {
		currentRuntimeMode = prevMode
		cancelPostBootVerification()
	})

	if err := os.WriteFile(filepath.Join(etcDir, "interfaces.conf"), []byte("LAN_INTERFACE=enp5s0\nLAN_MODE=static\nLAN_IPV4_ADDRESS=10.60.0.10/24\nLAN_IPV4_GATEWAY=10.60.0.1\n"), 0664); err != nil {
		t.Fatal(err)
	}
	if err := applyBootInterfaces(); err != nil {
		t.Fatalf("static single-NIC LAN apply failed: %v", err)
	}
	if len(routeCalls) != 1 || routeCalls[0] != "10.60.0.1@enp5s0" {
		t.Fatalf("expected single-NIC static LAN gateway default route [10.60.0.1@enp5s0], got %v", routeCalls)
	}

	// When WAN exists, LAN gateway is NOT installed as default route.
	routeCalls = nil
	if err := os.WriteFile(filepath.Join(etcDir, "interfaces.conf"), []byte("WAN_INTERFACE=enp3s0\nWAN_MODE=dhcp\nLAN_INTERFACE=enp5s0\nLAN_MODE=static\nLAN_IPV4_ADDRESS=10.60.0.10/24\nLAN_IPV4_GATEWAY=10.60.0.1\n"), 0664); err != nil {
		t.Fatal(err)
	}
	_ = applyBootInterfaces()
	cancelPostBootVerification()
	for _, rc := range routeCalls {
		if rc == "10.60.0.1@enp5s0" {
			t.Fatalf("LAN gateway must not become default route when WAN is configured, got %v", routeCalls)
		}
	}

	// 2. /proc/<pid>/cmdline -G detection + inferRollbackDhcpPolicy default-route ownership.
	procRoot := filepath.Join(dir, "proc")
	pidDir := filepath.Join(procRoot, fmt.Sprintf("%d", os.Getpid()))
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatal(err)
	}
	origProc := dhcpProcRoot
	dhcpProcRoot = procRoot
	t.Cleanup(func() { dhcpProcRoot = origProc })

	pidFile := filepath.Join(dir, "dhcpcd-enp5s0.pid")
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("dhcpcd\x00-4\x00-G\x00-C\x00resolv.conf\x00enp5s0\x00"), 0644)
	if !dhcpClientNeedsRebindForPidFiles("enp5s0", "lan", true, []string{pidFile}) {
		t.Fatal("expected dhcpClientNeedsRebind=true when running dhcpcd has -G but allowDefaultRoute=true")
	}
	if dhcpClientNeedsRebindForPidFiles("enp5s0", "lan", false, []string{pidFile}) {
		t.Fatal("expected dhcpClientNeedsRebind=false when running dhcpcd matches -G and allowDefaultRoute=false")
	}

	// 3. Rollback policy infers WAN / allowDefaultRoute when snap.Role is empty and device owns default route.
	role, allow := inferRollbackDhcpPolicy(
		LiveNetIfaceSnapshot{Device: "enp3s0", Role: ""},
		map[string]string{},
		true,
		[]LiveDefaultRoute{{Device: "enp3s0", Gateway: "203.0.113.1"}},
	)
	if role != "wan" || !allow {
		t.Fatalf("expected inferred (wan, true) for default-route owner, got (%q, %v)", role, allow)
	}
	role2, allow2 := inferRollbackDhcpPolicy(
		LiveNetIfaceSnapshot{Device: "enp5s0", Role: ""},
		map[string]string{},
		true,
		[]LiveDefaultRoute{{Device: "enp3s0", Gateway: "203.0.113.1"}},
	)
	if role2 != "lan" || allow2 {
		t.Fatalf("expected inferred (lan, false) for non-default-route NIC when WAN exists, got (%q, %v)", role2, allow2)
	}

	// 4. dhclient fallback passes -pf /run/dhclient.<dev>.pid AND stopDhcpClient cancels in-flight launch cleanly.
	dhclientDir := filepath.Join(dir, "dhclient-bin")
	if err := os.MkdirAll(dhclientDir, 0755); err != nil {
		t.Fatal(err)
	}
	dhclientLog := filepath.Join(dir, "dhclient.log")
	dhclientStarted := filepath.Join(dir, "dhclient.started")
	dhclientScript := "#!/bin/sh\necho \"$@\" >> " + dhclientLog + "\ntouch " + dhclientStarted + "\nsleep 30\n"
	if err := os.WriteFile(filepath.Join(dhclientDir, "dhclient"), []byte(dhclientScript), 0755); err != nil {
		t.Fatal(err)
	}
	// Replace PATH without dhcpcd so dhclient fallback triggers.
	t.Setenv("PATH", dhclientDir+":/bin:/usr/bin")
	if _, lpErr := execLookPath("dhcpcd"); lpErr == nil {
		t.Log("host has real dhcpcd on /bin:/usr/bin; skipping dhclient-only fallback assertion")
	} else {
		startDhcpClientProcess("enp8s0", "wan", true)
		dl := time.Now().Add(2 * time.Second)
		for time.Now().Before(dl) {
			if _, err := os.Stat(dhclientStarted); err == nil {
				break
			}
			time.Sleep(15 * time.Millisecond)
		}
		stopDhcpClient("enp8s0")
		argsOut, _ := os.ReadFile(dhclientLog)
		if !strings.Contains(string(argsOut), "-pf /run/dhclient.enp8s0.pid enp8s0") {
			t.Fatalf("dhclient fallback missing -pf /run/dhclient.<dev>.pid: %q", string(argsOut))
		}
	}
}

func TestBugfixGroup2_FallbackLkgScoping(t *testing.T) {
	if isSafeLkgNftScript("/etc/nftables.conf", []byte("flush ruleset\ntable inet axonwall {\n}\n")) {
		t.Fatal("expected /etc/nftables.conf with flush ruleset to be rejected")
	}
	if isSafeLkgNftScript("/etc/nftables.conf", []byte("table inet filter {\n}\n")) {
		t.Fatal("expected /etc/nftables.conf omitting table inet axonwall to be rejected")
	}
	if !isSafeLkgNftScript("/etc/nftables.conf", []byte("table inet axonwall {\n chain input { }\n}\n")) {
		t.Fatal("expected /etc/nftables.conf with table inet axonwall and without flush ruleset to be accepted")
	}

	dir := t.TempDir()
	nftLog := filepath.Join(dir, "nft.log")
	nftScript := "#!/bin/sh\necho \"$@\" >> " + nftLog + "\necho \"table inet axonwall {\n  chain input { type filter hook input priority 0; }\n}\"\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(nftScript), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	lkgFile := filepath.Join(dir, "bundle", "last-known-good.nft")
	gotScript, gotHash, ok := captureLiveAxonwallLkgNft(lkgFile)
	if !ok || gotHash == "" {
		t.Fatal("expected captureLiveAxonwallLkgNft to succeed")
	}
	if strings.Contains(gotScript, "flush ruleset") {
		t.Fatalf("captured LKG script must not contain flush ruleset:\n%s", gotScript)
	}
	if !strings.HasPrefix(gotScript, "table inet axonwall {}\nflush table inet axonwall\n") {
		t.Fatalf("captured LKG script missing table-scoped header:\n%s", gotScript)
	}
	logged, _ := os.ReadFile(nftLog)
	if !strings.Contains(string(logged), "list table inet axonwall") || strings.Contains(string(logged), "list ruleset") {
		t.Fatalf("expected `nft list table inet axonwall`, got: %q", string(logged))
	}
}

func TestBugfixGroup3_HAEngineNonLdapKeepalivedConntrackdAndFIFO(t *testing.T) {
	dir := t.TempDir()
	origK := keepalivedConfPath
	origC := conntrackdConfPath
	origEnsure := haEnsurePKICertsFn
	origSyncrepl := haConfigureSyncreplFn
	origSlapd := haIsSlapdActiveFn
	keepalivedConfPath = filepath.Join(dir, "keepalived.conf")
	conntrackdConfPath = filepath.Join(dir, "conntrackd.conf")
	t.Cleanup(func() {
		keepalivedConfPath = origK
		conntrackdConfPath = origC
		haEnsurePKICertsFn = origEnsure
		haConfigureSyncreplFn = origSyncrepl
		haIsSlapdActiveFn = origSlapd
	})

	svcLog := filepath.Join(dir, "systemctl.log")
	fakeSysctl := "#!/bin/sh\necho \"$@\" >> " + svcLog + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(fakeSysctl), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	// 1. Default non-LDAP appliance must NOT invoke ConfigureMultiProviderSyncrepl;
	// EnsureHAPKICerts error MUST propagate.
	syncreplCalls := 0
	haConfigureSyncreplFn = func(serverID int, peerIP, baseDN string) error {
		syncreplCalls++
		return errors.New("slapd unavailable")
	}
	haIsSlapdActiveFn = func() bool { return false }
	haEnsurePKICertsFn = func(cn, localIP, peerIP string) error { return nil }

	e := NewHAEngine(nil)
	pm := engine.NewPluginManager(t.TempDir())
	e.SetPluginManager(pm)

	cfg := HAConfig{
		Enabled:       true,
		Role:          "master",
		PeerIp:        "fd00:10::2",
		SyncInterface: "lo",
		VRRPInstances: []VRRPInstanceConfig{
			{Name: "VI-1", Vrid: 51, Interface: "lo", Priority: 150},
			{Name: "VI_1", Vrid: 52, Interface: "lo", Priority: 140},
		},
		ConntrackSync: ConntrackSyncConfig{Enabled: false},
	}
	if err := e.Apply(cfg); err != nil {
		t.Fatalf("HA Apply on non-LDAP appliance should succeed, got: %v", err)
	}
	if syncreplCalls != 0 {
		t.Fatalf("expected 0 ConfigureMultiProviderSyncrepl calls on non-LDAP appliance, got %d", syncreplCalls)
	}
	sysLog, _ := os.ReadFile(svcLog)
	if !strings.Contains(string(sysLog), "stop conntrackd") {
		t.Fatalf("expected conntrackd stopped when ConntrackSync.Enabled=false, log:\n%s", string(sysLog))
	}

	// Keepalived checks: empty authentication omitted, deduplicated names VI_1 & VI_1_2.
	kConfBytes, err := os.ReadFile(keepalivedConfPath)
	if err != nil {
		t.Fatal(err)
	}
	kConf := string(kConfBytes)
	if strings.Contains(kConf, "authentication {") || strings.Contains(kConf, "auth_pass") {
		t.Fatalf("expected empty auth_pass/authentication omitted in keepalived.conf:\n%s", kConf)
	}
	if !strings.Contains(kConf, "vrrp_instance VI_1 ") || !strings.Contains(kConf, "vrrp_instance VI_1_2 ") {
		t.Fatalf("expected deduplicated VRRP instance names VI_1 & VI_1_2 in keepalived.conf:\n%s", kConf)
	}

	// EnsureHAPKICerts error is checked & returned.
	haEnsurePKICertsFn = func(cn, localIP, peerIP string) error { return errors.New("pki cert boom") }
	if err := e.Apply(cfg); err == nil || !strings.Contains(err.Error(), "ha pki certs") {
		t.Fatalf("expected EnsureHAPKICerts error propagation, got: %v", err)
	}

	// formatLdapsPeerURI IPv6 host formatting.
	if got := formatLdapsPeerURI("fd00:10::2"); got != "ldaps://[fd00:10::2]:636" {
		t.Fatalf("formatLdapsPeerURI IPv6 = %q, want ldaps://[fd00:10::2]:636", got)
	}

	// VRID and priority range validation.
	if err := e.generateKeepalived(HAConfig{
		Enabled:       true,
		VRRPInstances: []VRRPInstanceConfig{{Name: "BAD", Vrid: 256, Interface: "lo", Priority: 100}},
	}); err == nil {
		t.Fatal("expected keepalived validation error for vrid 256")
	}
	if err := e.generateKeepalived(HAConfig{
		Enabled:       true,
		VRRPInstances: []VRRPInstanceConfig{{Name: "BAD", Vrid: 10, Interface: "lo", Priority: -1}},
	}); err == nil {
		t.Fatal("expected keepalived validation error for priority -1")
	}

	// Conntrackd UDP/TCP unicast & IPv6 Multicast emission.
	if err := e.generateConntrackd(HAConfig{
		Enabled:       true,
		SyncInterface: "lo",
		ConntrackSync: ConntrackSyncConfig{Enabled: true, Protocol: "tcp", PeerAddress: "fd00:20::2", Port: 4780},
	}); err != nil {
		t.Fatalf("generateConntrackd TCP IPv6 failed: %v", err)
	}
	cOut, _ := os.ReadFile(conntrackdConfPath)
	if !strings.Contains(string(cOut), "TCP {") || !strings.Contains(string(cOut), "IPv6_Destination_Address fd00:20::2") || !strings.Contains(string(cOut), "Port 4780") {
		t.Fatalf("unexpected TCP IPv6 conntrackd.conf:\n%s", string(cOut))
	}

	if err := e.generateConntrackd(HAConfig{
		Enabled:       true,
		SyncInterface: "lo",
		ConntrackSync: ConntrackSyncConfig{Enabled: true, Protocol: "udp", PeerAddress: "10.0.99.2", Port: 3781},
	}); err != nil {
		t.Fatalf("generateConntrackd UDP IPv4 failed: %v", err)
	}
	cOut, _ = os.ReadFile(conntrackdConfPath)
	if !strings.Contains(string(cOut), "UDP {") || !strings.Contains(string(cOut), "IPv4_Destination_Address 10.0.99.2") || !strings.Contains(string(cOut), "Port 3781") {
		t.Fatalf("unexpected UDP IPv4 conntrackd.conf:\n%s", string(cOut))
	}

	// FIFO worker sequential ordering via HA notify socket + lock-safe Stop().
	e2 := NewHAEngine(nil)
	e2.sockPath = filepath.Join(dir, "ha-fifo.sock")
	if err := e2.StartSocketListener(); err != nil {
		t.Fatalf("StartSocketListener: %v", err)
	}
	if os.Getuid() != 0 {
		// Default haExpectedPeerUID=0 rejects non-root callers cleanly.
		c, err := net.Dial("unix", e2.sockPath)
		if err != nil {
			t.Fatalf("dial ha.sock: %v", err)
		}
		_, _ = fmt.Fprintln(c, "BACKUP")
		buf := make([]byte, 32)
		n, _ := c.Read(buf)
		_ = c.Close()
		if !strings.Contains(string(buf[:n]), "ERR: unauthorized") {
			t.Fatalf("expected non-root caller rejected by default, got %q", string(buf[:n]))
		}
		origPeerUID := haExpectedPeerUID
		haExpectedPeerUID = uint32(os.Getuid())
		t.Cleanup(func() { haExpectedPeerUID = origPeerUID })
	}
	var mu sync.Mutex
	var states []string
	// Verify back-to-back socket messages complete sequentially in strict FIFO order.
	for _, st := range []string{"BACKUP", "MASTER"} {
		conn, err := net.Dial("unix", e2.sockPath)
		if err != nil {
			t.Fatalf("dial ha.sock: %v", err)
		}
		_, _ = fmt.Fprintf(conn, "%s\n", st)
		buf := make([]byte, 32)
		n, _ := conn.Read(buf)
		_ = conn.Close()
		mu.Lock()
		states = append(states, st+":"+strings.TrimSpace(string(buf[:n])))
		mu.Unlock()
	}
	e2.Stop()
	if strings.Join(states, ",") != "BACKUP:OK,MASTER:OK" {
		t.Fatalf("unexpected HA socket replies: %v", states)
	}
}

func TestBugfixGroup4_BootAntiLockoutRollbackOrderingSyncAndWireGuard(t *testing.T) {
	// 1. reconcileBootAntiLockoutNft: skip when hasLkg==true; insert ONLY primary lan after anchor when false.
	dir := t.TempDir()
	etcDir := filepath.Join(dir, "etc")
	stateDir := filepath.Join(dir, "state")
	binDir := filepath.Join(dir, "bin")
	wgDir := filepath.Join(dir, "wireguard")
	for _, d := range []string{etcDir, stateDir, binDir, wgDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("AXONWALL_ETC_DIR", etcDir)
	t.Setenv("AXONWALL_STATE_DIR", stateDir)

	origLockdown := bootLockdownNftPath
	bootLockdownNftPath = filepath.Join(dir, "lockdown.nft")
	_ = os.WriteFile(bootLockdownNftPath, []byte("set wan_interfaces { elements = { \"wan0\" } }\n"), 0644)
	t.Cleanup(func() { bootLockdownNftPath = origLockdown })

	nftLog := filepath.Join(dir, "nft.log")
	nftFake := "#!/bin/sh\necho \"$@\" >> " + nftLog + "\n" +
		"if [ \"$1\" = \"-a\" ]; then\n" +
		"  echo '  ip saddr @blocked_ips drop # handle 12'\n" +
		"  echo '  ct state invalid drop # handle 19'\n" +
		"fi\nexit 0\n"
	if err := os.WriteFile(filepath.Join(binDir, "nft"), []byte(nftFake), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	_ = os.WriteFile(filepath.Join(etcDir, "interfaces.conf"), []byte("WAN_INTERFACE=eth0\nLAN_INTERFACE=eth1\nOPT1_INTERFACE=eth2\n"), 0664)
	reconcileBootAntiLockoutNft(true)
	if out, _ := os.ReadFile(nftLog); len(out) > 0 {
		t.Fatalf("expected reconcileBootAntiLockoutNft(true) to skip anti-lockout injection, got: %s", string(out))
	}

	reconcileBootAntiLockoutNft(false)
	outBytes, _ := os.ReadFile(nftLog)
	out := string(outBytes)
	if !strings.Contains(out, "add rule inet axonwall input position 19 iifname eth1") {
		t.Fatalf("expected primary lan eth1 added after handle 19, got:\n%s", out)
	}
	if strings.Contains(out, "eth2") {
		t.Fatalf("reconcileBootAntiLockoutNft(false) must only add primary lan, not eth2:\n%s", out)
	}

	// 2. WireGuard live syncconf vs restart on ListenPort change.
	origWgDir := wireguardConfDir
	wireguardConfDir = wgDir
	t.Cleanup(func() { wireguardConfDir = origWgDir })
	_ = os.WriteFile(filepath.Join(wgDir, "wg0.conf"), []byte("[Interface]\nAddress = 10.99.0.1/24\nListenPort = 51820\n[Peer]\nPublicKey = abc=\n"), 0600)

	wgLog := filepath.Join(dir, "wg.log")
	for name, body := range map[string]string{
		"wg": "#!/bin/sh\necho \"wg $@\" >> " + wgLog + "\nif [ \"$1\" = \"show\" ]; then echo 51820; fi\nexit 0\n",
		"wg-quick": "#!/bin/sh\necho \"wg-quick $@\" >> " + wgLog + "\necho \"[Peer]\nPublicKey = abc=\"\nexit 0\n",
		"ip": "#!/bin/sh\necho '[{\"ifname\":\"wg0\",\"addr_info\":[{\"family\":\"inet\",\"local\":\"10.99.0.1\",\"prefixlen\":24,\"scope\":\"global\"}]}]'\n",
		"systemctl": "#!/bin/sh\necho \"systemctl $@\" >> " + wgLog + "\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := reloadOrRestartService("wg-quick@wg0"); err != nil {
		t.Fatalf("wg-quick@wg0 syncconf failed: %v", err)
	}
	wgOut, _ := os.ReadFile(wgLog)
	if !strings.Contains(string(wgOut), "wg syncconf wg0") || strings.Contains(string(wgOut), "reload-or-restart") {
		t.Fatalf("expected live wg0 peer update to use wg syncconf without unit restart, log:\n%s", string(wgOut))
	}

	// Changing ListenPort in wg0.conf forces systemd reload-or-restart fallback.
	_ = os.WriteFile(wgLog, nil, 0644)
	_ = os.WriteFile(filepath.Join(wgDir, "wg0.conf"), []byte("[Interface]\nAddress = 10.99.0.1/24\nListenPort = 51821\n"), 0600)
	if _, err := reloadOrRestartService("wg-quick@wg0"); err != nil {
		t.Fatalf("wg-quick@wg0 restart fallback failed: %v", err)
	}
	wgOut, _ = os.ReadFile(wgLog)
	if !strings.Contains(string(wgOut), "reload-or-restart wg-quick@wg0") {
		t.Fatalf("expected ListenPort change to restart wg-quick@wg0, log:\n%s", string(wgOut))
	}

	// 3. restoreExternalBundleFiles stops added units BEFORE deleting added config files.
	bundleDir := filepath.Join(dir, "bundle")
	stopLog := filepath.Join(dir, "stop.log")
	_ = os.WriteFile(filepath.Join(binDir, "systemctl"), []byte("#!/bin/sh\necho \"systemctl $@\" >> "+stopLog+"\nexit 0\n"), 0755)
	_ = saveExternalBundleMeta(bundleDir, ExternalBundleMeta{
		Files: []ExternalFileEntry{
			{Path: "/etc/wireguard/wg-noexist0.conf", Existed: false},
			{Path: "/etc/openvpn/server/site-does-not-exist.conf", Existed: false},
			{Path: "/etc/rosenpass/config.toml", Existed: false},
			{Path: "/etc/radvd.conf", Existed: false},
		},
		ReloadServices: []string{"wg-quick@wg-noexist0", "unbound"},
	})
	prevMode := currentRuntimeMode
	currentRuntimeMode = engine.ModeAppliance
	t.Cleanup(func() { currentRuntimeMode = prevMode })
	rem, ok := restoreExternalBundleFiles(bundleDir)
	if !ok {
		t.Fatal("restoreExternalBundleFiles failed")
	}
	stopOut, _ := os.ReadFile(stopLog)
	for _, unit := range []string{"wg-quick@wg-noexist0", "openvpn-server@site-does-not-exist", "rosenpass", "radvd"} {
		if !strings.Contains(string(stopOut), "stop "+unit) {
			t.Fatalf("expected restoreExternalBundleFiles to stop %s, log:\n%s", unit, string(stopOut))
		}
	}
	if len(rem) != 1 || rem[0] != "unbound" {
		t.Fatalf("expected stopped unit filtered from remaining ReloadServices, got %v", rem)
	}

	// 4. syncPersistentYamlConfigs syncs managed/*.json (0600) and credential/env files symmetrically.
	_ = os.MkdirAll(filepath.Join(etcDir, "managed"), 0755)
	_ = os.WriteFile(filepath.Join(etcDir, "managed", "ddns_config.json"), []byte(`{"enabled":false}`), 0600)
	_ = os.WriteFile(filepath.Join(etcDir, "axonwall.env"), []byte("SECRET=1\n"), 0600)
	_ = os.WriteFile(filepath.Join(etcDir, "slapd.seed"), []byte("pw"), 0600)
	_ = os.WriteFile(filepath.Join(etcDir, "agent.token"), []byte("tok"), 0600)
	syncPersistentYamlConfigs()
	for _, f := range []string{
		filepath.Join(stateDir, "etc-axonwall", "managed", "ddns_config.json"),
		filepath.Join(stateDir, "etc-axonwall", "axonwall.env"),
		filepath.Join(stateDir, "etc-axonwall", "slapd.seed"),
		filepath.Join(stateDir, "etc-axonwall", "agent.token"),
	} {
		fi, statErr := os.Lstat(f)
		if statErr != nil {
			t.Fatalf("expected %s synced to state mirror: %v", f, statErr)
		}
		if fi.Mode().Perm()&0o177 != 0 && filepath.Base(f) != "agent.token" {
			t.Fatalf("expected strict 0600 on %s, got %o", f, fi.Mode().Perm())
		}
	}

	// 5. restoreLiveNetSnapshot enables promote_secondaries=1, runs Phase B before Phase A, re-reads routes before Phase C.
	h := setupNetRollbackHarness(t, fakeKernelState{
		Interfaces: []ipAddrShowEntry{{
			Ifname: "enp5s0",
			Flags:  []string{"BROADCAST", "MULTICAST", "UP"},
			AddrInfo: []struct {
				Family    string `json:"family"`
				Local     string `json:"local"`
				Prefixlen int    `json:"prefixlen"`
				Scope     string `json:"scope"`
				Dynamic   bool   `json:"dynamic"`
				Secondary bool   `json:"secondary"`
			}{{Family: "inet", Local: "10.60.0.1", Prefixlen: 24, Scope: "global"}},
		}},
	})
	procConfDir := filepath.Join(h.root, "proc-conf")
	_ = os.MkdirAll(filepath.Join(procConfDir, "enp5s0"), 0755)
	_ = os.WriteFile(filepath.Join(procConfDir, "enp5s0", "promote_secondaries"), []byte("0\n"), 0644)
	origProcConf := procSysNetIPv4ConfRoot
	procSysNetIPv4ConfRoot = procConfDir
	t.Cleanup(func() { procSysNetIPv4ConfRoot = origProcConf })

	captureLiveNetSnapshot(h.bundleDir)
	// Simulate candidate swapping IP from 10.60.0.1/24 to 10.99.0.1/24.
	mut := h.readKernelState(t)
	mut.Interfaces[0].AddrInfo[0].Local = "10.99.0.1"
	mutBytes, _ := json.MarshalIndent(mut, "", "  ")
	_ = os.WriteFile(h.netStateFile, mutBytes, 0600)

	if !restoreLiveNetSnapshot(h.bundleDir) {
		t.Fatal("restoreLiveNetSnapshot failed")
	}
	promVal, _ := os.ReadFile(filepath.Join(procConfDir, "enp5s0", "promote_secondaries"))
	if strings.TrimSpace(string(promVal)) != "1" {
		t.Fatalf("expected promote_secondaries=1, got %q", string(promVal))
	}
	cmdLog := h.readCmdLog(t)
	repIdx := strings.Index(cmdLog, "ip addr replace 10.60.0.1/24 dev enp5s0")
	delIdx := strings.Index(cmdLog, "ip addr del 10.99.0.1/24 dev enp5s0")
	if repIdx < 0 || delIdx < 0 || repIdx > delIdx {
		t.Fatalf("expected Phase B (ip addr replace) BEFORE Phase A (ip addr del), log:\n%s", cmdLog)
	}

	// 6. reapplyRestoredSubsystemsImpl disables absent subsystems on ENOENT + restartNgfwDaemonsIfEnabled reads managed/firewall_config.json.
	subEtc := t.TempDir()
	t.Setenv("AXONWALL_ETC_DIR", subEtc)
	_ = os.MkdirAll(filepath.Join(subEtc, "managed"), 0755)
	_ = os.WriteFile(filepath.Join(subEtc, "managed", "firewall_config.json"), []byte(`{"enabled":true}`), 0600)

	haEngine := NewHAEngine(nil)
	haEngine.config = HAConfig{Enabled: true}
	ddnsMgr := engine.NewDdnsManager()
	iapMgr := engine.NewIAPManager()
	hwgMgr := engine.NewHeadscaleWanGateManager(t.TempDir(), true)
	srv := &AgentServer{
		haEngine:                haEngine,
		ddnsManager:             ddnsMgr,
		iapManager:              iapMgr,
		headscaleWanGateManager: hwgMgr,
	}
	if err := srv.reapplyRestoredSubsystemsImpl(false); err != nil {
		t.Fatalf("reapplyRestoredSubsystemsImpl failed on disabled absent configs: %v", err)
	}
	if err := srv.restartNgfwDaemonsIfEnabled(); err != nil {
		t.Fatalf("restartNgfwDaemonsIfEnabled failed with managed/firewall_config.json: %v", err)
	}
	restartLog := h.readCmdLog(t)
	if !strings.Contains(restartLog, "systemctl --no-ask-password start") {
		t.Fatalf("expected managed/firewall_config.json to trigger NGFW daemon start, log:\n%s", restartLog)
	}
}

func TestBugfixGroup6_ValidationDiagnosticsProberRoutesAndHTTP(t *testing.T) {
	// 1. validateBundleFiles rejects /tmp/, rejects symlink parent via O_DIRECTORY|O_NOFOLLOW, strips execute bits.
	if _, err := validateBundleFiles([]*pb.BundleFile{{Path: "/tmp/evil.conf", Content: "x"}}); err == nil {
		t.Fatal("expected validateBundleFiles to reject /tmp/ path")
	} else if st, ok := status.FromError(err); !ok || st.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for /tmp/, got %v", err)
	}

	symDir := t.TempDir()
	realSub := filepath.Join(symDir, "real")
	_ = os.MkdirAll(realSub, 0755)
	linkSub := filepath.Join(symDir, "linked")
	_ = os.Symlink(realSub, linkSub)
	allowTestBundlePrefix(t, symDir)
	if _, err := validateBundleFiles([]*pb.BundleFile{{Path: filepath.Join(linkSub, "test.conf"), Content: "x"}}); err == nil {
		t.Fatal("expected validateBundleFiles to reject symlink parent directory")
	}

	goodFile := filepath.Join(realSub, "cfg.conf")
	vfs, err := validateBundleFiles([]*pb.BundleFile{{Path: goodFile, Content: "x", FileMode: 0o4777}})
	if err != nil {
		t.Fatalf("validateBundleFiles valid file failed: %v", err)
	}
	if vfs[0].mode != 0o644 {
		t.Fatalf("expected mode 0o644 (execute & world-write stripped), got %o", vfs[0].mode)
	}

	// 2. ExecuteDiagnostic clamps zero/out-of-range count and port cleanly.
	binDir := t.TempDir()
	pingArgs := filepath.Join(binDir, "ping.args")
	_ = os.WriteFile(filepath.Join(binDir, "ping"), []byte("#!/bin/sh\necho \"$@\" > "+pingArgs+"\nexit 0\n"), 0755)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	diagSrv := &AgentServer{}
	_, err = diagSrv.ExecuteDiagnostic(context.Background(), &pb.DiagnosticRequest{
		Type:   pb.DiagnosticType_DIAGNOSTIC_TYPE_PING,
		Target: "127.0.0.1",
		Count:  0,
	})
	if err != nil {
		t.Fatalf("ExecuteDiagnostic zero count failed: %v", err)
	}
	pArgs, _ := os.ReadFile(pingArgs)
	if !strings.Contains(string(pArgs), "-c 3 ") {
		t.Fatalf("expected zero count clamped to -c 3, got: %q", string(pArgs))
	}
	_, err = diagSrv.ExecuteDiagnostic(context.Background(), &pb.DiagnosticRequest{
		Type:   pb.DiagnosticType_DIAGNOSTIC_TYPE_PING,
		Target: "127.0.0.1",
		Count:  99,
	})
	if err != nil {
		t.Fatalf("ExecuteDiagnostic over-limit count failed: %v", err)
	}
	pArgs, _ = os.ReadFile(pingArgs)
	if !strings.Contains(string(pArgs), "-c 3 ") {
		t.Fatalf("expected >10 count clamped to -c 3, got: %q", string(pArgs))
	}

	// Port probe with zero/over-65535 port clamps to 80.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	portResp, pErr := diagSrv.ExecuteDiagnostic(ctx, &pb.DiagnosticRequest{
		Type:   pb.DiagnosticType_DIAGNOSTIC_TYPE_PORT_PROBE,
		Target: "127.0.0.1",
		Port:   0,
	})
	if pErr != nil {
		t.Fatalf("ExecuteDiagnostic zero port error: %v", pErr)
	}
	if !strings.Contains(portResp.Output, ":80") {
		t.Fatalf("expected zero port clamped to port 80, got: %s", portResp.Output)
	}
	portResp, pErr = diagSrv.ExecuteDiagnostic(ctx, &pb.DiagnosticRequest{
		Type:   pb.DiagnosticType_DIAGNOSTIC_TYPE_PORT_PROBE,
		Target: "127.0.0.1",
		Port:   70000,
	})
	if pErr != nil {
		t.Fatalf("ExecuteDiagnostic >65535 port error: %v", pErr)
	}
	if !strings.Contains(portResp.Output, ":80") {
		t.Fatalf("expected >65535 port clamped to port 80, got: %s", portResp.Output)
	}

	// 3. SDWanProber: ip -j multipath withdrawal only removes owned routes and preserves DHCP WAN defaults.
	prevMode := currentRuntimeMode
	currentRuntimeMode = engine.ModeAppliance
	t.Cleanup(func() { currentRuntimeMode = prevMode })

	routeStateFile := filepath.Join(binDir, "ip-routes.json")
	ipDelLog := filepath.Join(binDir, "ip-del.log")
	routesJSON := `[{"dst":"default","protocol":"static","nexthops":[{"gateway":"192.0.2.1","dev":"eth0","weight":1},{"gateway":"198.51.100.1","dev":"eth1","weight":1}]},{"dst":"default","gateway":"10.0.2.2","dev":"eth2","protocol":"dhcp"}]`
	_ = os.WriteFile(routeStateFile, []byte(routesJSON), 0644)
	_ = os.WriteFile(filepath.Join(binDir, "ip"), []byte("#!/bin/sh\nif [ \"$1\" = \"-j\" ] && [ \"$2\" = \"-4\" ]; then cat "+routeStateFile+"; exit 0; fi\nif [ \"$1\" = \"-j\" ] && [ \"$2\" = \"-6\" ]; then echo '[]'; exit 0; fi\nif [ \"$1\" = \"route\" ] && [ \"$2\" = \"del\" ]; then echo \"$@\" >> "+ipDelLog+"; exit 0; fi\nexit 0\n"), 0755)

	prober := NewSDWanProber()
	prober.config = &SDWanConfig{Gateways: []GatewayTarget{{GatewayIP: "192.0.2.1"}}} // 198.51.100.1 removed
	prober.recordOwnedDefault("4", []string{"192.0.2.1@eth0", "198.51.100.1@eth1"})
	prober.withdrawStaleDefaultRoute()
	delLog, _ := os.ReadFile(ipDelLog)
	if !strings.Contains(string(delLog), "route del default nexthop via 192.0.2.1 dev eth0") {
		t.Fatalf("expected owned stale multipath route deleted, got: %q", string(delLog))
	}
	if strings.Contains(string(delLog), "10.0.2.2") {
		t.Fatalf("DHCP default route 10.0.2.2 must NOT be deleted, got: %q", string(delLog))
	}

	// 4. loadInterfaceDeviceMap skips state.json when interfaces.yaml loaded, and prefers /var/lib/axonwall/state.json.
	origConfPaths := interfaceConfCandidatePaths
	origYamlPaths := interfaceYamlCandidatePaths
	origStatePaths := stateJsonCandidatePaths
	t.Cleanup(func() {
		interfaceConfCandidatePaths = origConfPaths
		interfaceYamlCandidatePaths = origYamlPaths
		stateJsonCandidatePaths = origStatePaths
	})
	yamlDir := t.TempDir()
	interfaceConfCandidatePaths = nil
	interfaceYamlCandidatePaths = []string{filepath.Join(yamlDir, "interfaces.yaml")}
	varState := filepath.Join(yamlDir, "var-state.json")
	etcState := filepath.Join(yamlDir, "etc-state.json")
	stateJsonCandidatePaths = []string{varState, etcState}

	_ = os.WriteFile(filepath.Join(yamlDir, "interfaces.yaml"), []byte("interfaces:\n  - name: wan\n    device: eth9\n    enabled: true\n"), 0600)
	_ = os.WriteFile(varState, []byte(`{"interfaces":[{"name":"wan","device":"wrong_var","enabled":true}]}`), 0600)
	devMap := loadInterfaceDeviceMap()
	if devMap["wan"] != "eth9" {
		t.Fatalf("expected interfaces.yaml to suppress state.json override, got %v", devMap)
	}

	interfaceYamlCandidatePaths = []string{filepath.Join(yamlDir, "missing.yaml")}
	_ = os.WriteFile(varState, []byte(`{"interfaces":[{"name":"wan","device":"eth_var","enabled":true}]}`), 0600)
	_ = os.WriteFile(etcState, []byte(`{"interfaces":[{"name":"wan","device":"eth_etc","enabled":true}]}`), 0600)
	devMap = loadInterfaceDeviceMap()
	if devMap["wan"] != "eth_var" {
		t.Fatalf("expected /var/lib state.json preferred over /etc state.json, got %v", devMap)
	}

	// 5. reconcileStaticRoutesLocked skips unowned disabled routes & treats "No such process" as success.
	origOwned := staticRoutesOwnedPath
	origRoutingPaths := routingCandidatePaths
	staticRoutesOwnedPath = filepath.Join(binDir, "owned-static.json")
	routingYaml := filepath.Join(yamlDir, "routing.yaml")
	_ = os.WriteFile(routingYaml, []byte("routes:\n  - network: 10.10.0.0/24\n    gateway: 192.0.2.1\n    enabled: false\n  - network: 10.20.0.0/24\n    gateway: 192.0.2.1\n    enabled: false\n"), 0600)
	routingCandidatePaths = []string{routingYaml}
	t.Cleanup(func() {
		staticRoutesOwnedPath = origOwned
		routingCandidatePaths = origRoutingPaths
	})
	saveOwnedStaticRoutes(map[string]StaticRouteConfig{"10.10.0.0/24": {Network: "10.10.0.0/24"}})
	routeDelLog := filepath.Join(binDir, "route-del.log")
	_ = os.WriteFile(filepath.Join(binDir, "ip"), []byte("#!/bin/sh\necho \"$@\" >> "+routeDelLog+"\nif [ \"$2\" = \"route\" ] && [ \"$3\" = \"del\" ]; then echo 'RTNETLINK answers: No such process' >&2; exit 2; fi\nexit 0\n"), 0755)
	err = reconcileStaticRoutesLocked()
	if err != nil {
		t.Fatalf("reconcileStaticRoutesLocked failed: %v", err)
	}
	rLog, _ := os.ReadFile(routeDelLog)
	if strings.Contains(string(rLog), "10.20.0.0/24") {
		t.Fatalf("must not delete unowned disabled route 10.20.0.0/24, got:\n%s", string(rLog))
	}
	if ownedAfter := loadOwnedStaticRoutes(); ownedAfter["10.10.0.0/24"] {
		t.Fatalf("No such process should drop route from owned set, got %v", ownedAfter)
	}

	// 6. HTTP hygiene: Confirm/Rollback 400 on malformed JSON, Headscale sync 500 on error, MaxBytesReader limit.
	srv := batch4TestServer(t)
	rec := httptest.NewRecorder()
	handleAgentConfirmHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/confirm", strings.NewReader("{bad json")), srv)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("/v1/confirm malformed JSON status = %d, want 400", rec.Code)
	}
	rec = httptest.NewRecorder()
	handleAgentRollbackHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/rollback", strings.NewReader("{bad json")), srv)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("/v1/rollback malformed JSON status = %d, want 400", rec.Code)
	}

	// Empty body confirm returns 200 JSON (not 400).
	rec = httptest.NewRecorder()
	handleAgentConfirmHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/confirm", nil), srv)
	if rec.Code != http.StatusOK {
		t.Fatalf("/v1/confirm empty body status = %d, want 200", rec.Code)
	}

	// Headscale sync HTTP returns 500 when SyncFromInvites returns error.
	hsState := t.TempDir()
	_ = os.WriteFile(filepath.Join(binDir, "nft"), []byte("#!/bin/sh\necho 'Error: Operation not permitted' >&2\nexit 1\n"), 0755)
	hwg := engine.NewHeadscaleWanGateManager(hsState, false)
	cfgBytes, _ := json.Marshal(map[string]any{"enabled": true, "autoWindow": true, "bindPort": 8443})
	_ = hwg.ApplyConfig(cfgBytes)
	rec = httptest.NewRecorder()
	handleHeadscaleWanSyncHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/vpn/headscale/wan-window/sync", nil), hwg)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("/v1/vpn/headscale/wan-window/sync error status = %d, want 500 (body=%s)", rec.Code, rec.Body.String())
	}

	// httpMaxBodyMiddleware bounds non-/v1/apply POST bodies to 4 MiB.
	var readErr error
	handler := httpMaxBodyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	oversized := bytes.Repeat([]byte("A"), int(defaultMaxHTTPBodyBytes)+128)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/diagnostic", bytes.NewReader(oversized)))
	if rec.Code != http.StatusRequestEntityTooLarge || readErr == nil {
		t.Fatalf("expected oversized POST blocked by httpMaxBodyMiddleware, got status=%d err=%v", rec.Code, readErr)
	}
}

func boolPtr(b bool) *bool { return &b }

func execLookPath(bin string) (string, error) {
	return filepath.EvalSymlinks(bin)
}
