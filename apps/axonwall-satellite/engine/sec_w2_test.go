package engine

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecH05_ParseKernelCmdlineIMDSFlagAndShouldProbeIMDS(t *testing.T) {
	cases := []struct {
		name    string
		cmdline string
		want    bool
	}{
		{
			name:    "neither hub nor token probes IMDS",
			cmdline: "quiet console=ttyS0",
			want:    true,
		},
		{
			name:    "hub only skips IMDS without axonwall.imds=1",
			cmdline: "axonwall.hub=wss://hub.example:2966/ws/satellite",
			want:    false,
		},
		{
			name:    "token only skips IMDS without axonwall.imds=1",
			cmdline: "axonwall.token=ztp_secret_123",
			want:    false,
		},
		{
			name:    "both hub and token skip IMDS without axonwall.imds=1",
			cmdline: "axonwall.hub=wss://hub.example:2966/ws/satellite axonwall.token=ztp_secret_123",
			want:    false,
		},
		{
			name:    "hub with axonwall.imds=1 enables IMDS",
			cmdline: "axonwall.hub=wss://hub.example:2966/ws/satellite axonwall.imds=1",
			want:    true,
		},
		{
			name:    "token with axonwall.imds=true enables IMDS",
			cmdline: "axonwall.token=ztp_secret_123 axonwall.imds=true",
			want:    true,
		},
		{
			name:    "explicit axonwall.imds=0 disables IMDS even when hub and token empty",
			cmdline: "axonwall.imds=0",
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ParseKernelCmdline(tc.cmdline)
			if got := ShouldProbeIMDS(cfg); got != tc.want {
				t.Fatalf("ShouldProbeIMDS(ParseKernelCmdline(%q)) = %v, want %v (cfg=%+v)", tc.cmdline, got, tc.want, cfg)
			}
		})
	}
}

func TestSecH05_BuildEmergencyLockdownAllowsDHCPv4AndCompiles(t *testing.T) {
	script := BuildEmergencyLockdownNft("wss://10.0.0.2:2966/ws/satellite")
	if !strings.Contains(script, "udp sport 67 udp dport 68 accept") {
		t.Fatalf("expected emergency lockdown script to permit DHCPv4 replies, got:\n%s", script)
	}
	batch, err := CompileNftScriptToNetlinkBatch(script)
	if err != nil {
		t.Fatalf("CompileNftScriptToNetlinkBatch(emergency lockdown) failed: %v", err)
	}
	if len(batch.Chains) != 3 {
		t.Fatalf("expected 3 chains, got %d", len(batch.Chains))
	}
}

func TestSecH05_FetchIMDSCloudInitRejectsRedirects(t *testing.T) {
	redirectHits := 0
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectHits++
		_, _ = w.Write([]byte("#cloud-config\naxonwall:\n  hub: wss://evil.example/ws/satellite\n  token: hijacked\n"))
	}))
	defer redirectTarget.Close()

	// Redirecting IMDS responder across OpenStack, EC2 token, EC2 user-data, GCP, and Azure.
	imdsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL+r.URL.Path, http.StatusFound)
	}))
	defer imdsSrv.Close()

	if payload, ok := FetchIMDSCloudInit(context.Background(), imdsSrv.URL); ok {
		t.Fatalf("expected FetchIMDSCloudInit to refuse 302 redirects, got ok=true payload=%+v", payload)
	}
	if redirectHits != 0 {
		t.Fatalf("expected redirect target to receive 0 requests, got %d", redirectHits)
	}

	// Also verify EC2 IMDSv2 token PUT passes token endpoint redirect check (no token sent to target).
	ec2DataSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/api/token":
			http.Redirect(w, r, redirectTarget.URL+"/steal-token", http.StatusTemporaryRedirect)
		case "/latest/user-data":
			http.Redirect(w, r, redirectTarget.URL+"/evil-userdata", http.StatusMovedPermanently)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ec2DataSrv.Close()

	if payload, ok := FetchIMDSCloudInit(context.Background(), ec2DataSrv.URL); ok {
		t.Fatalf("expected FetchIMDSCloudInit to refuse EC2 301/307 redirects, got ok=true payload=%+v", payload)
	}
	if redirectHits != 0 {
		t.Fatalf("expected redirect target to receive 0 requests on EC2 redirects, got %d", redirectHits)
	}
}

func TestSecH05_IMDSCannotOverwriteCmdlineCertsFirewallOrEnableInsecure(t *testing.T) {
	root := t.TempDir()
	certDir := filepath.Join(root, "etc", "axonwall", "certs")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bakedCA := "-----BEGIN CERTIFICATE-----\nBAKED-IN-TRUSTED-CA\n-----END CERTIFICATE-----\n"
	caPath := filepath.Join(certDir, "ca.crt")
	if err := os.WriteFile(caPath, []byte(bakedCA), 0o600); err != nil {
		t.Fatal(err)
	}
	bakedNft := "table inet axonwall {\n  chain forward {\n    type filter hook forward priority filter; policy drop;\n  }\n}\n"
	nftPath := filepath.Join(root, "etc", "nftables.conf")
	if err := os.WriteFile(nftPath, []byte(bakedNft), 0o600); err != nil {
		t.Fatal(err)
	}

	// Case 1: YAML IMDS payload attempting full hijack (fields, inline ca_cert, write_files ca.crt/env/nftables.conf)
	cfg := ParseKernelCmdline("axonwall.hub=wss://trusted.hub:2966/ws/satellite axonwall.token=ztp_trusted axonwall.id=edge-trusted-01 axonwall.imds=1")
	yamlUserData := `#cloud-config
hostname: attacker-host
axonwall:
  hub: wss://attacker.hub:2966/ws/satellite
  token: ztp_attacker
  id: attacker-id
  insecure_bootstrap: true
  ca_cert: |
    -----BEGIN CERTIFICATE-----
    ATTACKER-CA
    -----END CERTIFICATE-----
write_files:
  - path: /etc/axonwall/certs/../certs/ca.crt
    content: |
      ATTACKER-WRITE-FILES-CA
  - path: /etc/nftables.conf
    content: |
      table inet axonwall { chain forward { type filter hook forward priority filter; policy accept; } }
  - path: /etc/axonwall/edge.env
    content: |
      AXONWALL_HUB=wss://attacker-env.hub:2966/ws/satellite
      AXONWALL_TOKEN=ztp_attacker_env
      AXONWALL_ID=attacker-env-id
      AXONWALL_INSECURE_BOOTSTRAP=1
`
	err := MergeCloudInitIntoBootConfig(&cfg, CloudInitPayload{
		Datasource: "imds-ec2",
		UserData:   yamlUserData,
		MetaData:   "instance-id: i-attacker\nlocal-hostname: attacker-meta-host\n",
	}, root)
	if err != nil {
		t.Fatalf("MergeCloudInitIntoBootConfig failed unexpectedly: %v", err)
	}
	if cfg.HubURL != "wss://trusted.hub:2966/ws/satellite" {
		t.Fatalf("IMDS overwrote HubURL: got %q", cfg.HubURL)
	}
	if cfg.ZtpToken != "ztp_trusted" {
		t.Fatalf("IMDS overwrote ZtpToken: got %q", cfg.ZtpToken)
	}
	if cfg.SatelliteID != "edge-trusted-01" {
		t.Fatalf("IMDS overwrote SatelliteID: got %q", cfg.SatelliteID)
	}
	if cfg.InsecureBootstrap {
		t.Fatalf("IMDS enabled InsecureBootstrap")
	}
	gotCA, err := os.ReadFile(caPath)
	if err != nil || string(gotCA) != bakedCA {
		t.Fatalf("IMDS overwrote baked-in ca.crt: got %q (err=%v)", string(gotCA), err)
	}
	gotNft, err := os.ReadFile(nftPath)
	if err != nil || string(gotNft) != bakedNft {
		t.Fatalf("IMDS overwrote baked-in nftables.conf: got %q (err=%v)", string(gotNft), err)
	}

	// Case 2: JSON IMDS payload with empty Hub/Token/ID cannot set InsecureBootstrap, ca.crt, or nftables.conf
	cfgEmpty := EdgeBootConfig{}
	jsonUserData := `{"hub": "wss://ok.hub:2966/ws/satellite", "token": "ztp_ok", "id": "edge-json-01", "insecure_bootstrap": true, "ca_cert": "ATTACKER-JSON-CA", "write_files": [{"path": "/etc/axonwall/certs/ca.crt", "content": "ATTACKER-JSON-WF-CA"}, {"path": "/etc/nftables.conf", "content": "flush ruleset"}]}`
	if err := MergeCloudInitIntoBootConfig(&cfgEmpty, CloudInitPayload{
		Datasource: "imds-openstack",
		UserData:   jsonUserData,
	}, root); err != nil {
		t.Fatalf("MergeCloudInitIntoBootConfig(JSON) failed: %v", err)
	}
	if cfgEmpty.InsecureBootstrap {
		t.Fatalf("JSON IMDS enabled InsecureBootstrap")
	}
	gotCA, _ = os.ReadFile(caPath)
	if string(gotCA) != bakedCA {
		t.Fatalf("JSON IMDS overwrote baked-in ca.crt: got %q", string(gotCA))
	}
	gotNft, _ = os.ReadFile(nftPath)
	if string(gotNft) != bakedNft {
		t.Fatalf("JSON IMDS overwrote baked-in nftables.conf: got %q", string(gotNft))
	}

	// Case 3: Absent /etc/nftables.conf still cannot be created by IMDS
	freshRoot := t.TempDir()
	cfgFresh := EdgeBootConfig{}
	if err := MergeCloudInitIntoBootConfig(&cfgFresh, CloudInitPayload{
		Datasource: "imds-gcp",
		UserData:   "#cloud-config\nwrite_files:\n  - path: /etc/nftables.conf\n    content: |\n      table inet axonwall { chain forward { type filter hook forward priority filter; policy accept; } }\n",
	}, freshRoot); err != nil {
		t.Fatalf("MergeCloudInitIntoBootConfig(freshRoot) failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(freshRoot, "etc", "nftables.conf")); !os.IsNotExist(err) {
		t.Fatalf("expected IMDS write to /etc/nftables.conf to be rejected even when absent")
	}

	// Case 4: Local NoCloud datasource still works normally (regression check)
	localCfg := ParseKernelCmdline("")
	localUserData := "#cloud-config\naxonwall:\n  hub: wss://local.hub:2966/ws/satellite\n  token: ztp_local\n  insecure_bootstrap: true\n  ca_cert: |\n    LOCAL-CA\nwrite_files:\n  - path: /etc/nftables.conf\n    content: |\n      table inet axonwall {\n        chain forward {\n          type filter hook forward priority filter; policy drop;\n        }\n      }\n"
	if err := MergeCloudInitIntoBootConfig(&localCfg, CloudInitPayload{
		Datasource: "nocloud:/dev/vdb",
		UserData:   localUserData,
	}, freshRoot); err != nil {
		t.Fatalf("local nocloud MergeCloudInitIntoBootConfig failed: %v", err)
	}
	if !localCfg.InsecureBootstrap || localCfg.HubURL != "wss://local.hub:2966/ws/satellite" {
		t.Fatalf("expected local nocloud to keep configuring hub and insecure_bootstrap, got %+v", localCfg)
	}
	if _, err := os.Stat(filepath.Join(freshRoot, "etc", "nftables.conf")); err != nil {
		t.Fatalf("expected local nocloud /etc/nftables.conf write to succeed: %v", err)
	}
}

func TestSecM07_RejectsUnknownSelectorsInsteadOfSilentMiscompile(t *testing.T) {
	badRules := []string{
		"ip protocol tcp drop",
		"ip ttl 64 drop",
		"ip bogus 10.0.0.1 drop",
		"ip6 nexthdr tcp drop",
		"ip6 hoplimit 1 drop",
		"ip6 bogus ::1 drop",
		"tcp flags syn drop",
		"tcp window 1024 drop",
		"tcp doff 5 drop",
		"udp length 64 drop",
		"udp checksum 1234 drop",
		"meta nfproto arp drop",
		"meta nfproto bridge drop",
		"meta nfproto netdev drop",
		"meta nfproto bogus drop",
	}

	for _, rule := range badRules {
		script := "table inet axonwall {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    " + rule + "\n  }\n}\n"
		if _, err := CompileNftScriptToNetlinkBatch(script); err == nil {
			t.Errorf("CompileNftScriptToNetlinkBatch(%q) succeeded, want explicit error instead of silent miscompilation", rule)
		}
	}

	// Valid selectors must keep working with exact offsets and proto constants.
	goodScript := `table inet axonwall {
  chain input {
    type filter hook input priority filter; policy drop;
    ip saddr 10.0.0.1 drop
    ip daddr 10.0.0.2 drop
    ip6 saddr fd00::1 drop
    ip6 daddr fd00::2 drop
    tcp sport 12345 accept
    tcp dport 443 accept
    udp sport 5353 accept
    udp dport 53 accept
    meta nfproto ipv4 accept
    meta nfproto ipv6 drop
  }
}`
	batch, err := CompileNftScriptToNetlinkBatch(goodScript)
	if err != nil {
		t.Fatalf("valid selectors script failed: %v", err)
	}
	if len(batch.Rules) != 10 {
		t.Fatalf("expected 10 compiled rules, got %d", len(batch.Rules))
	}

	// Verify exact payload offsets: ip saddr=12, ip daddr=16, ip6 saddr=8, ip6 daddr=24, sport=0, dport=2.
	wantOffsets := []uint32{12, 16, 8, 24, 0, 2, 0, 2}
	for idx, wantOff := range wantOffsets {
		off, ok := payloadLoadOffset(batch.Rules[idx])
		if !ok || off != wantOff {
			t.Errorf("rule %d (%q): payload offset = %d (ok=%v), want %d", idx, batch.Rules[idx].RawLine, off, ok, wantOff)
		}
	}
}

func TestSecM07_BraceTrackingRejectsNonInetMultiTableAndTrailingBlocks(t *testing.T) {
	badScripts := []struct {
		name   string
		script string
	}{
		{
			name:   "non-inet ip table",
			script: "table ip nat {\n  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n    oifname \"eth0\" masquerade\n  }\n}\n",
		},
		{
			name:   "non-inet ip6 table",
			script: "table ip6 filter {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    iif \"lo\" accept\n  }\n}\n",
		},
		{
			name:   "implicit ip family table",
			script: "table filter {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    iif \"lo\" accept\n  }\n}\n",
		},
		{
			name: "multi-table inet and ip",
			script: `table inet axonwall {
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
  }
}
table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "eth0" masquerade
  }
}`,
		},
		{
			name: "multi-table two inet tables",
			script: `table inet axonwall {
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
  }
}
table inet extra {
  chain forward {
    type filter hook forward priority filter; policy accept;
    accept
  }
}`,
		},
		{
			name: "chain leaking after table closes",
			script: `table inet axonwall {
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
  }
}
chain leaked {
  type filter hook forward priority filter; policy accept;
  accept
}`,
		},
		{
			name:   "unterminated table",
			script: "table inet axonwall {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    iif \"lo\" accept\n  }\n",
		},
		{
			name:   "extra closing brace",
			script: "table inet axonwall {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    iif \"lo\" accept\n  }\n}\n}\n",
		},
		{
			name:   "unsupported table-level map block",
			script: "table inet axonwall {\n  map ports {\n    type inet_service : verdict;\n  }\n  chain input {\n    type filter hook input priority filter; policy drop;\n    iif \"lo\" accept\n  }\n}\n",
		},
	}

	for _, tc := range badScripts {
		t.Run(tc.name, func(t *testing.T) {
			if b, err := CompileNftScriptToNetlinkBatch(tc.script); err == nil {
				t.Fatalf("expected CompileNftScriptToNetlinkBatch to fail for %s, but succeeded with table=%q chains=%d", tc.name, b.TableName, len(b.Chains))
			}
		})
	}

	// Verify quoted braces/hashes in comments and inline comments do not corrupt brace tracking.
	validWithComments := `table inet axonwall { # main table
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept comment "allow { lo # 1 }" # inline comment
  } # end chain
} # end table`
	batch, err := CompileNftScriptToNetlinkBatch(validWithComments)
	if err != nil {
		t.Fatalf("expected valid script with quoted braces and inline comments to compile, got %v", err)
	}
	if batch.TableName != "axonwall" || len(batch.Chains) != 1 || len(batch.Rules) != 1 {
		t.Fatalf("unexpected compiled batch: %+v", batch)
	}

	// Verify applyScriptInternal triggers nft -f fallback when pure-Go compiler rejects multi-table script,
	// and fails closed when no nft binary is present on PATH.
	multiTable := badScripts[3].script
	logPath := filepath.Join(t.TempDir(), "nft-fallback.log")
	bughunt3FakeNft(t, logPath)
	if err := applyScriptInternal(multiTable); err != nil {
		t.Fatalf("expected applyScriptInternal to fall back to nft -f on multi-table script, got %v", err)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(logged), "-f ") {
		t.Fatalf("expected fake nft -f invocation on fallback, got %q (err=%v)", string(logged), err)
	}

	t.Setenv("PATH", t.TempDir())
	if err := applyScriptInternal(multiTable); err == nil {
		t.Fatalf("expected fail-closed error when compiler rejects multi-table script and nft binary is absent")
	}
	_ = binary.LittleEndian
}
