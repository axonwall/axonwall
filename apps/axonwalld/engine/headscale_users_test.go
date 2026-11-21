package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveApplianceRoleAndVpnUserMapping(t *testing.T) {
	if got := ResolveApplianceRole([]string{"axonwall-vpn"}, "alice"); got != "vpn_user" {
		t.Fatalf("expected vpn_user for axonwall-vpn, got %q", got)
	}
	if got := ResolveApplianceRole([]string{"axonwall-vpn", "axonwall-readonly"}, "alice"); got != "readonly" {
		t.Fatalf("expected readonly precedence over axonwall-vpn, got %q", got)
	}
	if got := ResolveApplianceRole([]string{"axonwall-operator", "axonwall-vpn"}, "alice"); got != "operator" {
		t.Fatalf("expected operator precedence over axonwall-vpn, got %q", got)
	}
	if got := ResolveApplianceRole([]string{"axonwall-admin", "axonwall-vpn"}, "alice"); got != "admin" {
		t.Fatalf("expected admin precedence over axonwall-vpn, got %q", got)
	}
	if got := ResolveApplianceRole([]string{"users"}, "alice"); got != "os_only" {
		t.Fatalf("expected os_only fallback, got %q", got)
	}

	groups := RoleToGroups("vpn_user")
	if len(groups) != 1 || groups[0] != "axonwall-vpn" {
		t.Fatalf("unexpected RoleToGroups(vpn_user): %#v", groups)
	}
	if sh := DefaultShellForRole("vpn_user"); sh != "/usr/sbin/nologin" {
		t.Fatalf("expected /usr/sbin/nologin for vpn_user, got %q", sh)
	}
}

func TestSyncHeadscaleConfigNonDestructiveAndValidated(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	initial := `---
server_url: http://127.0.0.1:8080
listen_addr: 127.0.0.1:8080
noise:
  private_key_path: /var/lib/axonwall/headscale/noise_private.key
derp:
  server:
    enabled: true
    region_id: 999
database:
  type: sqlite
  sqlite:
    path: /var/lib/axonwall/headscale/db.sqlite
dns:
  magic_dns: true
  base_domain: tailnet.axonwall.local
  nameservers:
    global:
      - 1.1.1.1
unix_socket: /run/headscale/headscale.sock
`
	if err := os.WriteFile(cfgPath, []byte(initial), 0640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	changed, err := SyncHeadscaleConfig(cfgPath, "https://vpn.example.com/", "mesh.example.net")
	if err != nil {
		t.Fatalf("SyncHeadscaleConfig failed: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true on first update")
	}

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(raw)
	if !strings.Contains(content, "server_url: https://vpn.example.com\n") {
		t.Fatalf("expected updated server_url, got:\n%s", content)
	}
	if !strings.Contains(content, "  base_domain: mesh.example.net\n") {
		t.Fatalf("expected updated base_domain, got:\n%s", content)
	}
	for _, preserved := range []string{
		"listen_addr: 127.0.0.1:8080",
		"private_key_path: /var/lib/axonwall/headscale/noise_private.key",
		"region_id: 999",
		"path: /var/lib/axonwall/headscale/db.sqlite",
		"unix_socket: /run/headscale/headscale.sock",
	} {
		if !strings.Contains(content, preserved) {
			t.Fatalf("expected preserved line %q, got:\n%s", preserved, content)
		}
	}

	changedAgain, err := SyncHeadscaleConfig(cfgPath, "https://vpn.example.com", "mesh.example.net")
	if err != nil {
		t.Fatalf("second SyncHeadscaleConfig failed: %v", err)
	}
	if changedAgain {
		t.Fatalf("expected changed=false on identical second sync")
	}

	// Reject malicious / invalid values without touching file
	badInputs := []struct {
		url    string
		domain string
	}{
		{"javascript://alert(1)", ""},
		{"file:///etc/passwd", ""},
		{"https://vpn.example.com\ninjected: true", ""},
		{"", "bad\ninjected: yes"},
		{"", "invalid domain!"},
		{"not-a-url", ""},
	}
	for _, tc := range badInputs {
		if _, err := SyncHeadscaleConfig(cfgPath, tc.url, tc.domain); err == nil {
			t.Fatalf("expected error for url=%q domain=%q", tc.url, tc.domain)
		}
	}
}

func TestChangeOwnPasswordValidation(t *testing.T) {
	dm := NewDirectoryManager(NewUserManager(nil), nil)
	if err := dm.ChangeOwnPassword("root", "oldpass1234", "newpass123456"); err == nil {
		t.Fatalf("expected root self-service password change rejection")
	}
	if err := dm.ChangeOwnPassword("bad user!", "oldpass1234", "newpass123456"); err == nil {
		t.Fatalf("expected invalid username rejection")
	}
	if err := dm.ChangeOwnPassword("alice", "", "newpass123456"); err == nil {
		t.Fatalf("expected empty currentPassword rejection")
	}
	if err := dm.ChangeOwnPassword("alice", "oldpass1234", "short"); err == nil {
		t.Fatalf("expected too-short password rejection")
	}
	if err := dm.ChangeOwnPassword("alice", "oldpass1234", "oldpass1234"); err == nil {
		t.Fatalf("expected unchanged password rejection")
	}
	if err := dm.ChangeOwnPassword("alice", "oldpass1234", "valid\ninjected"); err == nil {
		t.Fatalf("expected newline control character rejection")
	}
}
