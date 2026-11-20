package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchPluginPackagesAndRootkitScannerSlot(t *testing.T) {
	defs := GetExtensionPluginDefinitions()
	if len(defs) == 0 {
		t.Fatal("expected extension plugin definitions")
	}
	for _, d := range defs {
		if d.ArchPackages == nil {
			t.Errorf("plugin %q missing ArchPackages mapping", d.ID)
		}
		if len(d.DebianPackages) > 0 {
			pkgs := packagesForOS("arch", d)
			if len(pkgs) == 0 {
				t.Errorf("packagesForOS(arch, %q) returned empty slice", d.ID)
			}
		}
	}

	scanners := ListInstalledRootkitScanners()
	if len(scanners) != 12 {
		t.Fatalf("expected 12 rootkit scanner slots, got %d", len(scanners))
	}
	if DetectOSFamily() == "arch" {
		foundPacman := false
		for _, s := range scanners {
			if s.ID == "pacman-qk" {
				foundPacman = true
			}
		}
		if !foundPacman {
			t.Fatalf("expected pacman-qk integrity scanner slot on Arch host, got %+v", scanners)
		}
	}
}

func TestRoleToGroupsWheelVsSudoAndPrimaryGroupLookup(t *testing.T) {
	tmp := t.TempDir()
	archGroup := filepath.Join(tmp, "group-arch")
	_ = os.WriteFile(archGroup, []byte("root:x:0:\nwheel:x:998:alice\n"), 0644)

	groups := roleToGroupsFromFile("admin", archGroup)
	hasWheel := false
	hasSudo := false
	for _, g := range groups {
		if g == "wheel" {
			hasWheel = true
		}
		if g == "sudo" {
			hasSudo = true
		}
	}
	if !hasWheel || hasSudo {
		t.Fatalf("expected [axonwall-admin, wheel] on Arch group file, got %v", groups)
	}

	debGroup := filepath.Join(tmp, "group-deb")
	_ = os.WriteFile(debGroup, []byte("root:x:0:\nsudo:x:27:alice\nadm:x:4:\n"), 0644)
	debGroups := roleToGroupsFromFile("admin", debGroup)
	hasSudo = false
	for _, g := range debGroups {
		if g == "sudo" {
			hasSudo = true
		}
	}
	if !hasSudo {
		t.Fatalf("expected sudo in Debian role groups, got %v", debGroups)
	}

	passwd := filepath.Join(tmp, "passwd")
	_ = os.WriteFile(passwd, []byte("alice:x:1000:998:Alice:/home/alice:/bin/bash\n"), 0644)
	um := NewCustomUserManager(passwd, archGroup, filepath.Join(tmp, "shadow"), nil)
	if pg := um.lookupPrimaryGroup("alice", map[int]string{998: "wheel"}); pg != "wheel" {
		t.Fatalf("expected primary group 'wheel', got %q", pg)
	}
}

func TestConfigureNSSwitchPreservesArchModulesAndComments(t *testing.T) {
	in := "# Arch NSS config\npasswd: files systemd\ngroup: files [SUCCESS=merge] systemd\nshadow: files systemd\nhosts: mymachines resolve [!UNAVAIL=return] files myhostname dns\n"
	out, changed := configureNSSwitchContent(in)
	if !changed {
		t.Fatal("expected configureNSSwitchContent to add sss")
	}
	if !strings.Contains(out, "# Arch NSS config") {
		t.Errorf("lost comment in nsswitch: %s", out)
	}
	if !strings.Contains(out, "passwd: files systemd sss") {
		t.Errorf("expected systemd preserved + sss appended in passwd: %s", out)
	}
	if !strings.Contains(out, "group: files [SUCCESS=merge] systemd sss") {
		t.Errorf("expected [SUCCESS=merge] systemd preserved in group: %s", out)
	}
	if !strings.Contains(out, "mymachines resolve") {
		t.Errorf("expected hosts line untouched: %s", out)
	}

	// Second call must be idempotent
	out2, changed2 := configureNSSwitchContent(out)
	if changed2 || out2 != out {
		t.Fatalf("expected second configureNSSwitchContent to be a no-op, got changed=%v", changed2)
	}
}

func TestSyncLocalNSSMirrorPreservesPreExistingLocalAccounts(t *testing.T) {
	tmp := t.TempDir()
	prevPasswd, prevGroup, prevShadow, prevState := etcPasswdPath, etcGroupPath, etcShadowPath, mirroredNSSStatePath
	etcPasswdPath = filepath.Join(tmp, "passwd")
	etcGroupPath = filepath.Join(tmp, "group")
	etcShadowPath = filepath.Join(tmp, "shadow")
	mirroredNSSStatePath = filepath.Join(tmp, "mirrored-nss.json")
	t.Cleanup(func() {
		etcPasswdPath = prevPasswd
		etcGroupPath = prevGroup
		etcShadowPath = prevShadow
		mirroredNSSStatePath = prevState
	})

	_ = os.WriteFile(etcPasswdPath, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"localdev:x:15000:15000:Local Non-LDAP Account:/home/localdev:/bin/bash\n"+
			"stale-ldap:x:10050:10050:Stale Operator [axonwall-ldap]:/home/stale-ldap:/bin/bash\n",
	), 0644)
	_ = os.WriteFile(etcGroupPath, []byte(
		"root:x:0:\n"+
			"localgrp:x:15000:localdev\n",
	), 0644)
	_ = os.WriteFile(etcShadowPath, []byte(
		"root:*:19723:0:99999:7:::\n"+
			"localdev:*:19723:0:99999:7:::\n"+
			"stale-ldap:*:19723:0:99999:7:::\n",
	), 0640)

	dm := &DirectoryManager{}
	dm.applyLocalNSSMirror("",
		[]LocalUser{{Username: "alice", UID: 10001, GID: 10001, Comment: "Alice", HomeDir: "/home/alice", Shell: "/bin/bash"}},
		[]LocalGroup{{Name: "alice", GID: 10001, Members: []string{"alice"}}},
	)

	pw, _ := os.ReadFile(etcPasswdPath)
	pwStr := string(pw)
	if !strings.Contains(pwStr, "localdev:x:15000:15000:") {
		t.Fatalf("BUG-05 regression: pre-existing local user UID 15000 was deleted!\n%s", pwStr)
	}
	if strings.Contains(pwStr, "stale-ldap:") {
		t.Fatalf("expected tracked [axonwall-ldap] stale user to be removed:\n%s", pwStr)
	}
	if !strings.Contains(pwStr, "alice:x:10001:10001:Alice [axonwall-ldap]:/home/alice:/bin/bash") {
		t.Fatalf("expected mirrored LDAP user alice with tag:\n%s", pwStr)
	}

	gr, _ := os.ReadFile(etcGroupPath)
	if !strings.Contains(string(gr), "localgrp:x:15000:localdev") {
		t.Fatalf("BUG-05 regression: pre-existing local group GID 15000 was deleted!\n%s", string(gr))
	}
}

func TestPluginLDAPIntegrationValidationAndCloudSyncValidation(t *testing.T) {
	dm := &DirectoryManager{baseDN: "dc=axonwall,dc=local"}
	if _, err := dm.EnsurePluginLDAPIntegration("../../etc/passwd", PluginLDAPSpec{}); err == nil {
		t.Fatal("expected path traversal pluginID to be rejected")
	}
	if _, err := dm.EnsurePluginLDAPIntegration("good-plugin", PluginLDAPSpec{ServiceAccountCN: "cn=evil,dc=x"}); err == nil {
		t.Fatal("expected DN injection in ServiceAccountCN to be rejected")
	}

	nm := &NasManager{
		cfg: NasRuntimeBundle{
			CloudSyncTasks: []CloudSyncTaskSpec{
				{Name: "badbucket", Dataset: "tank/data", RemoteBucket: "-o=evil", RemoteEndpoint: "https://s3.example.com", Direction: "push"},
				{Name: "badscheme", Dataset: "tank/data", RemoteBucket: "mybucket123", RemoteEndpoint: "file:///etc/passwd", Direction: "push"},
			},
		},
	}
	if _, err := nm.RunCloudSyncTask("badbucket"); err == nil {
		t.Fatal("expected invalid S3 bucket name to be rejected")
	}
	if _, err := nm.RunCloudSyncTask("badscheme"); err == nil {
		t.Fatal("expected non-http(s) S3 endpoint to be rejected")
	}
}

func TestSqliteSyncZfsAllowlistAndMcpRedirectOriginalDst(t *testing.T) {
	nm := &NasManager{
		cfg: NasRuntimeBundle{
			Datasets: []ZfsDatasetSpec{
				{Pool: "tank", Name: "shared", ReplicateToHaPeer: true},
			},
		},
	}
	m := NewSqliteSyncManager()
	m.cfg = SqliteSyncConfig{Enabled: true, NodeRole: "master", AuthToken: "s3cret"}
	m.SetNasManager(nm)

	for _, ds := range []string{"zroot/ROOT/default", "tank/unlisted"} {
		q := url.Values{}
		q.Set("dataset", ds)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sync/zfs?"+q.Encode(), nil)
		req.Header.Set("X-Axonwall-Sync-Token", "s3cret")
		rec := httptest.NewRecorder()
		m.handleZfsSendStream(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("dataset %q: got HTTP %d, want 403 Forbidden", ds, rec.Code)
		}
	}

	// MCP RedirectTraffic validates OriginalDstIP (BUG-06)
	mcpMgr := &McpTrafficManager{}
	_, err := mcpMgr.RedirectTraffic(McpRedirectReq{
		Source:            "198.51.100.10",
		OriginalDstIP:     "not-an-ip\nflush ruleset",
		TargetDestination: "192.0.2.50:2222",
	})
	if err == nil {
		t.Fatal("expected RedirectTraffic to reject invalid originalDstIp")
	}

	// Kernel studio 7.x + Arch pkg regex & Virt RestoreBackup targetID guard
	if !kernelVersionRe.MatchString("7.2.15-1-omarchy") || !kernelVersionRe.MatchString("6.12.15") {
		t.Fatal("expected kernelVersionRe to accept 7.2.15-1-omarchy and 6.12.15")
	}
	if !artifactDebRe.MatchString("linux-axonwall-7.2.15-x86_64.pkg.tar.zst") || !artifactDebRe.MatchString("linux-image-6.12.15_1_amd64.deb") {
		t.Fatal("expected artifactDebRe to match both Arch .pkg.tar.zst and Debian .deb artifacts")
	}
	vm := &VirtManager{defaultPool: "tank"}
	if _, err := vm.RestoreBackup("axonwall-backup-test.vma.zst", "vm", 0, "tank", "admin"); err == nil {
		t.Fatal("expected RestoreBackup to reject non-positive targetID")
	}

	// PacketStream SSE must not emit wildcard Access-Control-Allow-Origin (BUG-08)
	psm := NewPacketStreamManager(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sseReq := httptest.NewRequest(http.MethodGet, "/api/v1/packet-stream?interface=lo", nil).WithContext(ctx)
	sseRec := httptest.NewRecorder()
	psm.HandleStreamSSE(sseRec, sseReq)
	if acao := sseRec.Header().Get("Access-Control-Allow-Origin"); acao != "" {
		t.Fatalf("expected no Access-Control-Allow-Origin header on packet stream SSE, got %q", acao)
	}
}
