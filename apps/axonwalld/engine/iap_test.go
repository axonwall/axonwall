package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIAPUpstreamValidation(t *testing.T) {
	m := NewIAPManager()

	badConfigs := []struct {
		name     string
		pubHost  string
		upstream string
	}{
		{"unix_scheme", "app.local", "unix//run/axonwall/ha.sock"},
		{"unix_in_http_host", "app.local", "http://unix//run/axonwall/ha.sock"},
		{"empty_host", "app.local", "http:///run/axonwall/caddy-admin.sock"},
		{"file_scheme", "app.local", "file:///etc/passwd"},
		{"h2c_scheme", "app.local", "h2c://10.0.0.5:8080"},
		{"empty_upstream", "app.local", ""},
		{"control_sock_ref", "app.local", "http://10.0.0.5/run/axonwall/agent-api.sock"},
		{"embedded_creds", "app.local", "http://user:pass@10.0.0.5:8080"},
		{"path_in_upstream", "app.local", "http://10.0.0.5:8080/admin"},
		{"query_in_upstream", "app.local", "http://10.0.0.5:8080?x=1"},
		{"caddy_injection", "app.local", "http://10.0.0.5:8080\nreverse_proxy / evil"},
		{"bad_public_host", "app.local { }", "http://10.0.0.5:8080"},
	}

	for _, tc := range badConfigs {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ZeroTrustConfig{
				Enabled: true,
				Apps: []ZeroTrustApp{{
					ID:               "app1",
					Name:             "App 1",
					PublicHostname:   tc.pubHost,
					InternalUpstream: tc.upstream,
					Enabled:          true,
				}},
			}
			raw, _ := json.Marshal(cfg)
			if err := m.ApplyConfig(raw); err == nil {
				t.Fatalf("expected ApplyConfig to reject %s (%q -> %q)", tc.name, tc.pubHost, tc.upstream)
			}
			caddyfile := m.generateCaddyfile(cfg)
			if strings.Contains(caddyfile, "reverse_proxy") {
				t.Fatalf("generateCaddyfile emitted rejected upstream %q:\n%s", tc.upstream, caddyfile)
			}
		})
	}

	validCfg := ZeroTrustConfig{
		Enabled: true,
		Apps: []ZeroTrustApp{
			{
				ID:               "grafana",
				Name:             "Grafana",
				PublicHostname:   "grafana.internal",
				InternalUpstream: "http://10.0.0.5:3000",
				AllowedRoles:     []string{"admin"},
				Enabled:          true,
			},
			{
				ID:               "vault",
				Name:             "Vault",
				PublicHostname:   "vault.internal:8443",
				InternalUpstream: "https://10.0.0.6:8443",
				AllowedRoles:     []string{"operator"},
				Enabled:          true,
			},
		},
	}
	for _, app := range validCfg.Apps {
		if err := validateZeroTrustApp(app); err != nil {
			t.Fatalf("expected valid app %+v to pass, got: %v", app, err)
		}
	}
	caddyfile := m.generateCaddyfile(validCfg)
	if !strings.Contains(caddyfile, "reverse_proxy http://10.0.0.5:3000") || !strings.Contains(caddyfile, "reverse_proxy https://10.0.0.6:8443") {
		t.Fatalf("expected valid upstreams in generated Caddyfile:\n%s", caddyfile)
	}
}

func TestIAPCaddyAdminSocketPermissions(t *testing.T) {
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(tmp, "run")
	if err := os.MkdirAll(runDir, 0750); err != nil {
		t.Fatal(err)
	}

	origPid := caddyPidFile
	origSock := caddyAdminSocket
	origConf := iapCaddyfilePath
	origRun := iapRunDir
	caddyPidFile = filepath.Join(runDir, "caddy.pid")
	caddyAdminSocket = filepath.Join(runDir, "caddy-admin.sock")
	iapCaddyfilePath = filepath.Join(tmp, "Caddyfile")
	iapRunDir = runDir
	t.Cleanup(func() {
		caddyPidFile = origPid
		caddyAdminSocket = origSock
		iapCaddyfilePath = origConf
		iapRunDir = origRun
	})

	// Fake caddy creates the admin socket with overly broad 0777 permissions and stays alive.
	fakeCaddy := filepath.Join(binDir, "caddy")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"run\" ]; then\n" +
		"  umask 000\n" +
		"  touch \"" + caddyAdminSocket + "\"\n" +
		"  chmod 0777 \"" + caddyAdminSocket + "\"\n" +
		"  sleep 30\n" +
		"  exit 0\n" +
		"fi\n" +
		"exit 0\n"
	if err := os.WriteFile(fakeCaddy, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	m := NewIAPManager()
	t.Cleanup(m.Stop)

	raw, _ := json.Marshal(ZeroTrustConfig{
		Enabled: true,
		Apps: []ZeroTrustApp{{
			ID:               "app1",
			PublicHostname:   "app.axonwall.local",
			InternalUpstream: "http://10.0.0.5:8080",
			Enabled:          true,
		}},
	})
	if err := m.ApplyConfig(raw); err != nil {
		t.Fatalf("ApplyConfig with fake caddy failed: %v", err)
	}
	info, err := os.Stat(caddyAdminSocket)
	if err != nil {
		t.Fatalf("stat caddyAdminSocket: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected caddy-admin.sock mode 0600, got %04o", info.Mode().Perm())
	}

	// Simulate socket mode drift before reload; ReloadCaddy must re-enforce 0600.
	if err := os.Chmod(caddyAdminSocket, 0666); err != nil {
		t.Fatal(err)
	}
	if err := m.ReloadCaddy(iapCaddyfilePath); err != nil {
		t.Fatalf("ReloadCaddy failed: %v", err)
	}
	info2, err := os.Stat(caddyAdminSocket)
	if err != nil {
		t.Fatalf("stat after reload: %v", err)
	}
	if info2.Mode().Perm() != 0600 {
		t.Fatalf("expected caddy-admin.sock mode 0600 after reload, got %04o", info2.Mode().Perm())
	}
}
