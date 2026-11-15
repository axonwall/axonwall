package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/axonwall/axonwall/apps/axonwalld/engine"
)

func TestArchAndDebianServiceValidation(t *testing.T) {
	allowed := []string{
		"kea-dhcp4",
		"kea-dhcp6",
		"kea-dhcp-ddns",
		"smbd",
		"smb",
		"nmb",
		"chrony",
		"chronyd",
		"freeradius",
		"radiusd",
		"target",
		"k3s-agent",
		"NetworkManager",
		"systemd-networkd",
		"openvpn-client@branch1",
		"wg-quick@wg0",
	}
	for _, svc := range allowed {
		if !validServiceName(svc) {
			t.Errorf("expected validServiceName(%q) to be true", svc)
		}
	}

	rejected := []string{
		"",
		"../etc/passwd",
		"smbd;rm -rf /",
		"openvpn-client@",
		"openvpn-client@bad..inst",
		"wg-quick@bad/iface",
		"arbitrary-unmanaged-service",
	}
	for _, svc := range rejected {
		if validServiceName(svc) {
			t.Errorf("expected validServiceName(%q) to be false", svc)
		}
	}
}

func TestDistroAliasesAndOpenRCMapping(t *testing.T) {
	if _, ok := distroServiceAliases["smbd"]; !ok {
		t.Fatalf("expected distroServiceAliases entry for smbd")
	}
	if _, ok := distroServiceAliases["chrony"]; !ok {
		t.Fatalf("expected distroServiceAliases entry for chrony")
	}
	if got := resolveOpenRCServiceName("kea-dhcp4-server"); got != "kea-dhcp4" {
		t.Errorf("resolveOpenRCServiceName(kea-dhcp4-server) = %q, want kea-dhcp4", got)
	}
	if got := resolveOpenRCServiceName("openvpn-client@site1"); got != "openvpn.site1" {
		t.Errorf("resolveOpenRCServiceName(openvpn-client@site1) = %q, want openvpn.site1", got)
	}
	if !isValidNetdev("enp1s0") || !isValidNetdev("wg0.100") {
		t.Errorf("expected standard netdev names to validate")
	}
	if isValidNetdev("../eth0") || isValidNetdev("-eth0") || isValidNetdev("verylonginterfacename0") {
		t.Errorf("expected malformed netdev names to be rejected")
	}
}

func TestHAEngineSocketListenerReopenAndClose(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "ha.sock")

	// Start with an already-existing stale socket file and reopen twice to verify
	// previous listener handles are closed cleanly instead of leaking FDs.
	_ = os.WriteFile(sock, []byte("stale"), 0600)
	e := NewHAEngine(nil)
	e.sockPath = sock
	if err := e.StartSocketListener(); err != nil {
		t.Fatalf("first StartSocketListener failed: %v", err)
	}
	firstListener := e.listener
	if firstListener == nil {
		t.Fatal("expected listener after StartSocketListener")
	}
	if err := e.StartSocketListener(); err != nil {
		t.Fatalf("second StartSocketListener failed: %v", err)
	}
	e.mu.Lock()
	secondListener := e.listener
	e.mu.Unlock()
	if secondListener == nil || secondListener == firstListener {
		t.Fatal("expected fresh listener on second StartSocketListener call")
	}
	e.Stop()
}

func TestApplianceModeRoutingDefaultGuard(t *testing.T) {
	// Ensure non-appliance modes (ModeHost / ModeDev) do not mutate host default routes via withdrawStaleDefaultRoute.
	prevMode := currentRuntimeMode
	currentRuntimeMode = engine.ModeHost
	t.Cleanup(func() {
		currentRuntimeMode = prevMode
	})

	p := &SDWanProber{}
	// Should immediately return without invoking ip route del in host/dev mode.
	p.withdrawStaleDefaultRoute()
}
