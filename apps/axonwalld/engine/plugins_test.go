package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPluginManager_ListPlugins(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "axonwall-plugins-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	pm := NewPluginManager(tmpDir)
	plugins := pm.ListPlugins()

	if len(plugins) == 0 {
		t.Fatalf("expected at least 1 plugin definition, got 0")
	}

	foundWorkstation := false
	foundNastyMap := false
	foundVow := false
	foundEluvix := false
	foundNetbox := false
	for _, p := range plugins {
		if p.ID == "cli-workstation" {
			foundWorkstation = true
			if len(p.RequiredBinaries) == 0 {
				t.Errorf("cli-workstation missing required binaries metadata")
			}
			if p.DefaultEnabled {
				t.Errorf("expected cli-workstation to have DefaultEnabled=false (Lean Core opt-in)")
			}
			if p.Enabled {
				t.Errorf("expected cli-workstation to be Enabled=false by default")
			}
		}
		if p.ID == "cli-diagnostics-nastymap" {
			foundNastyMap = true
		}
		if p.ID == "vigilant-octo-waffle" {
			foundVow = true
			if len(p.Dependencies) != 1 || p.Dependencies[0] != "core-k3s" {
				t.Errorf("expected vigilant-octo-waffle to have Dependencies=[core-k3s], got %v", p.Dependencies)
			}
		}
		if p.ID == "eluvix" {
			foundEluvix = true
		}
		if p.ID == "netbox" {
			foundNetbox = true
			if len(p.Dependencies) != 1 || p.Dependencies[0] != "core-k3s" {
				t.Errorf("expected netbox to have Dependencies=[core-k3s], got %v", p.Dependencies)
			}
			if p.LdapIntegration == nil || p.LdapIntegration.ServiceAccountCN != "svc-netbox" {
				t.Errorf("expected netbox OpenLDAP ServiceAccountCN=svc-netbox, got %+v", p.LdapIntegration)
			}
			if p.LdapIntegration == nil || len(p.LdapIntegration.Groups) != 3 {
				t.Errorf("expected 3 LDAP groups on netbox plugin, got %+v", p.LdapIntegration)
			}
		}
	}

	if !foundWorkstation {
		t.Errorf("expected cli-workstation plugin in definitions")
	}
	if !foundNastyMap {
		t.Errorf("expected cli-diagnostics-nastymap plugin in definitions")
	}
	if !foundVow {
		t.Errorf("expected vigilant-octo-waffle plugin in definitions")
	}
	if !foundEluvix {
		t.Errorf("expected eluvix plugin in definitions")
	}
	if !foundNetbox {
		t.Errorf("expected netbox plugin in definitions")
	}
}

func TestPluginManager_ReconfigureWorkstation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "axonwall-plugins-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	pm := NewPluginManager(tmpDir)
	resp := pm.ReconfigurePlugin("cli-workstation")
	if !resp.Success {
		t.Errorf("expected reconfigure success, got %v: %s", resp.Success, resp.Message)
	}

	// Verify starship.toml was generated
	if _, err := os.Stat("/etc/axonwall/starship.toml"); err != nil && os.Geteuid() == 0 {
		t.Errorf("expected /etc/axonwall/starship.toml to be created: %v", err)
	}
}

func TestPluginManager_UnknownPlugin(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "axonwall-plugins-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	pm := NewPluginManager(tmpDir)
	resp := pm.InstallPlugin("invalid-nonexistent-plugin-12345")
	if resp.Success {
		t.Errorf("expected failure on unknown plugin ID, got success")
	}
}

func TestPluginManager_StatePersistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "axonwall-plugins-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	pm := NewPluginManager(tmpDir)
	pm.installedMap["custom-test-plugin"] = "2026-10-21T12:00:00Z"
	pm.saveState()

	// Verify file exists
	statePath := filepath.Join(tmpDir, "plugins.json")
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state file was not created: %v", err)
	}

	// Create new manager from same dir
	pm2 := NewPluginManager(tmpDir)
	if pm2.installedMap["custom-test-plugin"] != "2026-10-21T12:00:00Z" {
		t.Errorf("failed to reload persisted plugin state")
	}
}

func TestPluginManager_NonBlockingListDuringAction(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "axonwall-plugins-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	pm := NewPluginManager(tmpDir)

	// Simulate an in-progress package manager action holding actionMu
	pm.actionMu.Lock()

	done := make(chan bool, 1)
	go func() {
		// ListPlugins should not be blocked by actionMu
		_ = pm.ListPlugins()
		done <- true
	}()

	select {
	case <-done:
		// success: ListPlugins returned without deadlock
	case <-time.After(2 * time.Second):
		t.Fatalf("ListPlugins was blocked by package action lock!")
	}

	pm.actionMu.Unlock()
}

// R4-A-M4: the ebpf-threat-harvester toggle must actually start the
// harvester — it used to only MkdirAll + flip state, reporting
// enabled while nothing ran. Without a wired harvester manager, and
// when the harvester cannot start (dev mode without BPF), the toggle
// fails closed and the plugin stays disabled.
func TestPluginManager_HarvesterToggleWired(t *testing.T) {
	t.Setenv("AXONWALL_RUNTIME_MODE", "dev")
	tmpDir := t.TempDir()
	pm := NewPluginManager(tmpDir)

	resp := pm.ReconfigurePlugin("ebpf-threat-harvester")
	if resp.Success {
		t.Fatalf("ReconfigurePlugin without a wired harvester must fail closed, got success: %+v", resp)
	}
	if pm.IsPluginEnabled("ebpf-threat-harvester") {
		t.Fatalf("plugin must not be enabled after a failed reconfigure")
	}

	mgr := NewThreatHarvesterManager(nil, nil, nil, nil)
	cfg := DefaultThreatHarvesterConfig()
	cfg.SpoolDir = t.TempDir()
	if err := mgr.UpdateConfig(cfg); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}
	pm.SetThreatHarvesterManager(mgr)
	resp = pm.ReconfigurePlugin("ebpf-threat-harvester")
	if resp.Success {
		t.Fatalf("ReconfigurePlugin in dev mode without BPF must fail honestly, got success: %+v", resp)
	}
	if pm.IsPluginEnabled("ebpf-threat-harvester") {
		t.Fatalf("plugin must not be enabled when the harvester cannot start")
	}

	resp = pm.DisablePlugin("ebpf-threat-harvester")
	if !resp.Success {
		t.Fatalf("DisablePlugin should succeed, got: %+v", resp)
	}
	if pm.IsPluginEnabled("ebpf-threat-harvester") {
		t.Fatalf("plugin must be disabled after DisablePlugin")
	}
}

func TestPluginManager_MinimalOnDemandHelpers(t *testing.T) {
	def, ok := findExtensionPluginDefinition("cli-workstation")
	if !ok {
		t.Fatalf("cli-workstation definition missing")
	}
	for _, unexpected := range []string{"kubectl", "helm"} {
		for _, rb := range def.RequiredBinaries {
			if rb == unexpected {
				t.Fatalf("cli-workstation RequiredBinaries should not include %q (minimal installs work without K3s): %v", unexpected, def.RequiredBinaries)
			}
		}
	}

	if pkgs := coreRoleOSPackages("debian", "core-firewall"); len(pkgs) == 0 {
		t.Fatalf("coreRoleOSPackages(debian, core-firewall) should return OS packages")
	}
	if pkgs := coreRoleOSPackages("debian", "core-k3s"); len(pkgs) == 0 {
		t.Fatalf("coreRoleOSPackages(debian, core-k3s) should return OS packages")
	}
	if pkgs := coreRoleOSPackages("alpine", "core-nas"); len(pkgs) == 0 {
		t.Fatalf("coreRoleOSPackages(alpine, core-nas) should return OS packages")
	}
	if pkgs := coreRoleOSPackages("arch", "core-virt"); len(pkgs) == 0 {
		t.Fatalf("coreRoleOSPackages(arch, core-virt) should return OS packages")
	}

	emptyAptDir := t.TempDir()
	if !aptListsNeedUpdate(emptyAptDir) {
		t.Fatalf("empty apt lists dir should report update needed")
	}
	if !aptListsNeedUpdate(filepath.Join(emptyAptDir, "nonexistent")) {
		t.Fatalf("missing apt lists dir should report update needed")
	}
	_ = os.WriteFile(filepath.Join(emptyAptDir, "lock"), nil, 0644)
	if !aptListsNeedUpdate(emptyAptDir) {
		t.Fatalf("apt lists dir without *_Packages should report update needed")
	}
	_ = os.WriteFile(filepath.Join(emptyAptDir, "deb.debian.org_debian_dists_trixie_main_binary-amd64_Packages"), []byte("Package: nftables\n"), 0644)
	if aptListsNeedUpdate(emptyAptDir) {
		t.Fatalf("apt lists dir with *_Packages should not require update")
	}

	rootMinimalMarker := t.TempDir()
	_ = os.MkdirAll(filepath.Join(rootMinimalMarker, "etc/axonwall"), 0755)
	if isMinimalEditionRoot(rootMinimalMarker) {
		t.Fatalf("root without edition file or .minimal-edition must not report minimal")
	}
	_ = os.WriteFile(filepath.Join(rootMinimalMarker, "etc/axonwall/edition"), []byte("minimal\n"), 0644)
	if !isMinimalEditionRoot(rootMinimalMarker) {
		t.Fatalf("root with edition=minimal must report minimal")
	}
	_ = os.WriteFile(filepath.Join(rootMinimalMarker, "etc/axonwall/edition"), []byte("axonwall\n"), 0644)
	_ = os.WriteFile(filepath.Join(rootMinimalMarker, "etc/axonwall/.minimal-edition"), nil, 0644)
	if !isMinimalEditionRoot(rootMinimalMarker) {
		t.Fatalf("root with .minimal-edition marker must report minimal")
	}
}

func TestLibreNmsPluginDefinitionAndLifecycle(t *testing.T) {
	def, ok := findExtensionPluginDefinition("librenms")
	if !ok {
		t.Fatalf("librenms extension plugin definition missing")
	}
	if len(def.Dependencies) != 1 || def.Dependencies[0] != "core-k3s" {
		t.Fatalf("librenms must depend on core-k3s, got: %v", def.Dependencies)
	}
	if len(def.SystemdUnits) != 0 {
		t.Fatalf("librenms must not list host systemd units (disabling must never stop k3s.service), got: %v", def.SystemdUnits)
	}
	if def.LdapIntegration == nil || def.LdapIntegration.ServiceAccountCN != "svc-librenms" {
		t.Fatalf("librenms LDAP integration missing svc-librenms, got: %+v", def.LdapIntegration)
	}

	tmpDir := t.TempDir()
	origManifestDir := k3sServerManifestDir
	manifestTmp := filepath.Join(tmpDir, "manifests")
	k3sServerManifestDir = manifestTmp
	t.Cleanup(func() { k3sServerManifestDir = origManifestDir })

	pm := NewPluginManager(filepath.Join(tmpDir, "plugins"))
	resp := pm.ReconfigurePlugin("librenms")
	if !resp.Success {
		t.Fatalf("ReconfigurePlugin(librenms) failed: %+v", resp)
	}
	_ = os.MkdirAll(manifestTmp, 0755)
	manifestPath := filepath.Join(manifestTmp, "axonwall-librenms.yaml")
	_ = os.WriteFile(manifestPath, []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: librenms\n"), 0600)

	dis := pm.DisablePlugin("librenms")
	if !dis.Success {
		t.Fatalf("DisablePlugin(librenms) failed: %+v", dis)
	}
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Fatalf("DisablePlugin(librenms) should remove %s", manifestPath)
	}
}

func TestAiCopilotPluginDefinitionAndToggle(t *testing.T) {
	def, ok := findExtensionPluginDefinition("ai-copilot")
	if !ok {
		t.Fatalf("ai-copilot extension plugin definition missing")
	}
	if def.DefaultEnabled {
		t.Fatalf("ai-copilot must default to disabled (opt-in)")
	}
	if len(def.SystemdUnits) != 0 || len(def.RequiredBinaries) != 0 {
		t.Fatalf("ai-copilot should have no host systemd units or OS binaries, got units=%v bins=%v", def.SystemdUnits, def.RequiredBinaries)
	}

	tmpDir := t.TempDir()
	pm := NewPluginManager(filepath.Join(tmpDir, "plugins"))

	findStatus := func() (PluginStatus, bool) {
		for _, p := range pm.ListPlugins() {
			if p.ID == "ai-copilot" {
				return p, true
			}
		}
		return PluginStatus{}, false
	}

	initial, found := findStatus()
	if !found {
		t.Fatalf("ai-copilot missing from ListPlugins()")
	}
	if initial.Enabled || !initial.Bundled {
		t.Fatalf("expected initial ai-copilot state disabled & bundled, got enabled=%v installed=%v bundled=%v", initial.Enabled, initial.Installed, initial.Bundled)
	}

	en := pm.EnablePlugin("ai-copilot")
	if !en.Success {
		t.Fatalf("EnablePlugin(ai-copilot) failed: %+v", en)
	}
	afterEnable, _ := findStatus()
	if !afterEnable.Enabled || !afterEnable.Installed {
		t.Fatalf("expected enabled & installed after EnablePlugin(ai-copilot), got enabled=%v installed=%v", afterEnable.Enabled, afterEnable.Installed)
	}

	dis := pm.DisablePlugin("ai-copilot")
	if !dis.Success {
		t.Fatalf("DisablePlugin(ai-copilot) failed: %+v", dis)
	}
	afterDisable, _ := findStatus()
	if afterDisable.Enabled {
		t.Fatalf("expected disabled after DisablePlugin(ai-copilot)")
	}
}

func buildSyntheticDocsTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%s): %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("Write(%s): %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func writeTestRSAPubkeyPEM(t *testing.T, dir string, priv *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubPath := filepath.Join(dir, "release-signing.pub")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(pubPath, pemBytes, 0644); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}
	return pubPath
}

func TestDocsPortalPluginLifecycleAndVerification(t *testing.T) {
	def, ok := findExtensionPluginDefinition("docs-portal")
	if !ok {
		t.Fatalf("docs-portal extension plugin definition missing")
	}
	if def.DefaultEnabled {
		t.Fatalf("docs-portal must default to disabled (on-demand install)")
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tarBytes := buildSyntheticDocsTarGz(t, map[string]string{
		"docs/index.html":              "<html><body>Axonwall Docs</body></html>",
		"docs/architecture/index.html": "<html><body>Architecture</body></html>",
		"_next/static/css/app.css":     "body{color:#fff}",
		"manifest.json":                `{"id":"docs-portal","version":"0.15.1","guides":2}`,
	})
	tarSum := sha256.Sum256(tarBytes)
	shaContent := []byte(fmt.Sprintf("%s  axonwall-docs-latest.tar.gz\n", hex.EncodeToString(tarSum[:])))
	shaDigest := sha256.Sum256(shaContent)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, shaDigest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/axonwall-docs-latest.tar.gz":
			_, _ = w.Write(tarBytes)
		case "/axonwall-docs-latest.tar.gz.sha256":
			_, _ = w.Write(shaContent)
		case "/axonwall-docs-latest.tar.gz.sha256.sig":
			_, _ = w.Write(sigBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	pubPath := writeTestRSAPubkeyPEM(t, tmpDir, privKey)
	pm := NewPluginManager(filepath.Join(tmpDir, "plugins"))
	pm.docsBundleBaseURL = srv.URL
	pm.releaseKeyPaths = []string{pubPath}

	findStatus := func() PluginStatus {
		for _, p := range pm.ListPlugins() {
			if p.ID == "docs-portal" {
				return p
			}
		}
		t.Fatalf("docs-portal missing from ListPlugins()")
		return PluginStatus{}
	}

	initial := findStatus()
	if initial.Installed || initial.Bundled || initial.Enabled {
		t.Fatalf("expected initial docs-portal not installed/not bundled/disabled, got %+v", initial)
	}

	if enableBefore := pm.EnablePlugin("docs-portal"); enableBefore.Success {
		t.Fatalf("EnablePlugin(docs-portal) must fail closed before installation")
	}

	inst := pm.InstallPlugin("docs-portal")
	if !inst.Success {
		t.Fatalf("InstallPlugin(docs-portal) failed: %+v", inst)
	}

	afterInstall := findStatus()
	if !afterInstall.Installed || afterInstall.Bundled || !afterInstall.Enabled {
		t.Fatalf("expected Installed=true Bundled=false Enabled=true after install, got %+v", afterInstall)
	}
	indexPath := filepath.Join(tmpDir, "plugins", "docs-portal", "site", "docs", "index.html")
	if _, err := os.Stat(indexPath); err != nil {
		t.Fatalf("expected extracted docs entrypoint %s: %v", indexPath, err)
	}

	dis := pm.DisablePlugin("docs-portal")
	if !dis.Success {
		t.Fatalf("DisablePlugin(docs-portal) failed: %+v", dis)
	}
	afterDisable := findStatus()
	if !afterDisable.Installed || afterDisable.Enabled {
		t.Fatalf("expected Installed=true Enabled=false after disable, got %+v", afterDisable)
	}

	en := pm.EnablePlugin("docs-portal")
	if !en.Success {
		t.Fatalf("EnablePlugin(docs-portal) failed after install: %+v", en)
	}
	if !findStatus().Enabled {
		t.Fatalf("expected Enabled=true after re-enable")
	}

	uninst := pm.UninstallPlugin("docs-portal")
	if !uninst.Success {
		t.Fatalf("UninstallPlugin(docs-portal) failed: %+v", uninst)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "plugins", "docs-portal")); !os.IsNotExist(err) {
		t.Fatalf("expected docs-portal storage directory removed on uninstall")
	}
	afterUninstall := findStatus()
	if afterUninstall.Installed || afterUninstall.Bundled || afterUninstall.Enabled {
		t.Fatalf("expected Installed=false Bundled=false Enabled=false after uninstall, got %+v", afterUninstall)
	}
}

func TestDocsPortalRejectsTamperedHashSignatureAndTarSlip(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(other): %v", err)
	}

	validTar := buildSyntheticDocsTarGz(t, map[string]string{
		"docs/index.html": "<html><body>Ok</body></html>",
	})

	t.Run("tampered_sha256", func(t *testing.T) {
		badSHA := []byte("0000000000000000000000000000000000000000000000000000000000000000  axonwall-docs-latest.tar.gz\n")
		d := sha256.Sum256(badSHA)
		sig, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, d[:])

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/axonwall-docs-latest.tar.gz":
				_, _ = w.Write(validTar)
			case "/axonwall-docs-latest.tar.gz.sha256":
				_, _ = w.Write(badSHA)
			case "/axonwall-docs-latest.tar.gz.sha256.sig":
				_, _ = w.Write(sig)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		tmpDir := t.TempDir()
		pubPath := writeTestRSAPubkeyPEM(t, tmpDir, privKey)
		pm := NewPluginManager(filepath.Join(tmpDir, "plugins"))
		pm.docsBundleBaseURL = srv.URL
		pm.releaseKeyPaths = []string{pubPath}

		if res := pm.InstallPlugin("docs-portal"); res.Success {
			t.Fatalf("expected InstallPlugin to fail on sha256 mismatch")
		}
		if pm.isDocsBundleInstalled() {
			t.Fatalf("docs bundle must not be marked installed after sha256 failure")
		}
	})

	t.Run("untrusted_signature", func(t *testing.T) {
		sum := sha256.Sum256(validTar)
		shaBytes := []byte(fmt.Sprintf("%s  axonwall-docs-latest.tar.gz\n", hex.EncodeToString(sum[:])))
		d := sha256.Sum256(shaBytes)
		badSig, _ := rsa.SignPKCS1v15(rand.Reader, otherKey, crypto.SHA256, d[:])

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/axonwall-docs-latest.tar.gz":
				_, _ = w.Write(validTar)
			case "/axonwall-docs-latest.tar.gz.sha256":
				_, _ = w.Write(shaBytes)
			case "/axonwall-docs-latest.tar.gz.sha256.sig":
				_, _ = w.Write(badSig)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		tmpDir := t.TempDir()
		pubPath := writeTestRSAPubkeyPEM(t, tmpDir, privKey)
		pm := NewPluginManager(filepath.Join(tmpDir, "plugins"))
		pm.docsBundleBaseURL = srv.URL
		pm.releaseKeyPaths = []string{pubPath}

		if res := pm.InstallPlugin("docs-portal"); res.Success {
			t.Fatalf("expected InstallPlugin to fail on invalid signature")
		}
		if pm.isDocsBundleInstalled() {
			t.Fatalf("docs bundle must not be installed on invalid signature")
		}
	})

	t.Run("tar_slip_rejected", func(t *testing.T) {
		slipTar := buildSyntheticDocsTarGz(t, map[string]string{
			"docs/index.html": "<html><body>Ok</body></html>",
			"../escape.html":  "pwned",
		})
		sum := sha256.Sum256(slipTar)
		shaBytes := []byte(fmt.Sprintf("%s  axonwall-docs-latest.tar.gz\n", hex.EncodeToString(sum[:])))
		d := sha256.Sum256(shaBytes)
		sig, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, d[:])

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/axonwall-docs-latest.tar.gz":
				_, _ = w.Write(slipTar)
			case "/axonwall-docs-latest.tar.gz.sha256":
				_, _ = w.Write(shaBytes)
			case "/axonwall-docs-latest.tar.gz.sha256.sig":
				_, _ = w.Write(sig)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		tmpDir := t.TempDir()
		pubPath := writeTestRSAPubkeyPEM(t, tmpDir, privKey)
		pm := NewPluginManager(filepath.Join(tmpDir, "plugins"))
		pm.docsBundleBaseURL = srv.URL
		pm.releaseKeyPaths = []string{pubPath}

		if res := pm.InstallPlugin("docs-portal"); res.Success {
			t.Fatalf("expected InstallPlugin to reject tar-slip archive")
		}
		if _, err := os.Stat(filepath.Join(tmpDir, "plugins", "docs-portal", "escape.html")); !os.IsNotExist(err) {
			t.Fatalf("tar-slip file escaped staging directory")
		}
	})
}

func TestLeanCorePluginDefinitionsAndUpgradePreservation(t *testing.T) {
	expectedNewIDs := []string{
		"coroot-ebpf-apm",
		"suricata-ids",
		"crowdsec-bouncer",
		"frr-routing",
		"openvpn",
		"ipsec-strongswan",
		"captive-portal",
		"tls-decryption",
		"identity-aware-proxy",
		"directory-ldap",
		"enterprise-sso",
		"firewall-importer",
		"mcp-ai-control",
		"custom-kernel-studio",
		"high-availability",
		"fleet-controller",
		"etckeeper-audit",
		"web-terminal",
		"packet-diagnostics",
	}
	for _, id := range expectedNewIDs {
		def, ok := findExtensionPluginDefinition(id)
		if !ok {
			t.Fatalf("missing extension plugin definition %q", id)
		}
		if def.DefaultEnabled {
			t.Fatalf("plugin %q must default disabled on Lean Core", id)
		}
	}
	for _, id := range []string{"cli-workstation", "host-malware-rootkit"} {
		def, ok := findExtensionPluginDefinition(id)
		if !ok || def.DefaultEnabled {
			t.Fatalf("plugin %q must have DefaultEnabled=false", id)
		}
	}

	if pkgs := coreRoleOSPackages("debian", "core-firewall"); len(pkgs) != 4 {
		t.Fatalf("expected slimmed 4 OS packages for core-firewall debian, got %v", pkgs)
	}

	t.Run("fresh_install_skips_preservation", func(t *testing.T) {
		root := t.TempDir()
		etcDir := filepath.Join(root, "etc-axonwall")
		etcRoot := filepath.Join(root, "etc")
		stateDir := filepath.Join(root, "state")
		_ = os.MkdirAll(etcDir, 0755)
		_ = os.MkdirAll(etcRoot, 0755)
		_ = os.WriteFile(filepath.Join(etcDir, ".firstboot"), []byte("1\n"), 0644)
		_ = os.WriteFile(filepath.Join(etcDir, "slapd.seed"), []byte("seed"), 0600)

		pm := NewPluginManager(stateDir)
		preserved := pm.runUpgradePreservationFromPaths(upgradeProbePaths{
			etcDir:      etcDir,
			etcRoot:     etcRoot,
			baseDataDir: stateDir,
		})
		if len(preserved) != 0 {
			t.Fatalf("fresh install with .firstboot must not auto-preserve plugins, got %v", preserved)
		}
		if pm.IsPluginEnabled("directory-ldap") {
			t.Fatalf("directory-ldap must stay disabled on fresh install")
		}
	})

	t.Run("upgrade_preserves_existing_disk_artifacts", func(t *testing.T) {
		root := t.TempDir()
		etcDir := filepath.Join(root, "etc-axonwall")
		etcRoot := filepath.Join(root, "etc")
		stateDir := filepath.Join(root, "state")
		_ = os.MkdirAll(etcDir, 0755)
		_ = os.MkdirAll(filepath.Join(etcRoot, ".git"), 0755)
		_ = os.MkdirAll(filepath.Join(stateDir, "cli-workstation"), 0755)
		_ = os.WriteFile(filepath.Join(etcDir, "slapd.seed"), []byte("seed"), 0600)
		_ = os.WriteFile(filepath.Join(etcDir, "mcp-keys.json"), []byte(`[{"id":"k1"}]`), 0600)

		pm := NewPluginManager(stateDir)
		preserved := pm.runUpgradePreservationFromPaths(upgradeProbePaths{
			etcDir:      etcDir,
			etcRoot:     etcRoot,
			baseDataDir: stateDir,
			isSystemdUnitReady: func(unit string) bool {
				return unit == "suricata.service" || unit == "frr.service"
			},
		})
		if len(preserved) < 6 {
			t.Fatalf("expected 6+ preserved plugins, got %v", preserved)
		}
		for _, want := range []string{"directory-ldap", "etckeeper-audit", "mcp-ai-control", "cli-workstation", "suricata-ids", "frr-routing"} {
			if !pm.IsPluginEnabled(want) {
				t.Fatalf("expected %q to be preserved across upgrade", want)
			}
		}

		// Verify DesiredState (state.json) was synchronized with preserved plugins and identity.ldapEnabled
		stateBytes, readErr := os.ReadFile(filepath.Join(stateDir, "state.json"))
		if readErr != nil {
			t.Fatalf("expected synced state.json after upgrade preservation: %v", readErr)
		}
		var synced struct {
			Identity struct {
				LDAPEnabled bool `json:"ldapEnabled"`
			} `json:"identity"`
			Plugins []struct {
				ID      string `json:"id"`
				Enabled bool   `json:"enabled"`
			} `json:"plugins"`
		}
		if err := json.Unmarshal(stateBytes, &synced); err != nil {
			t.Fatalf("unmarshal synced state.json: %v", err)
		}
		if !synced.Identity.LDAPEnabled {
			t.Fatalf("expected synced identity.ldapEnabled=true when directory-ldap preserved")
		}
		syncedMap := make(map[string]bool)
		for _, p := range synced.Plugins {
			syncedMap[p.ID] = p.Enabled
		}
		for _, want := range []string{"directory-ldap", "etckeeper-audit", "cli-workstation"} {
			if !syncedMap[want] {
				t.Fatalf("expected %q enabled in synced state.json plugins list, got %+v", want, synced.Plugins)
			}
		}

		// Operator can disable permanently on next boot; marker prevents re-enabling.
		if dis := pm.DisablePlugin("mcp-ai-control"); !dis.Success {
			t.Fatalf("DisablePlugin(mcp-ai-control): %+v", dis)
		}
		pm2 := NewPluginManager(stateDir)
		secondPass := pm2.runUpgradePreservationFromPaths(upgradeProbePaths{
			etcDir:      etcDir,
			etcRoot:     etcRoot,
			baseDataDir: stateDir,
		})
		if len(secondPass) != 0 {
			t.Fatalf("expected second upgrade probe to no-op after marker, got %v", secondPass)
		}
		if pm2.IsPluginEnabled("mcp-ai-control") {
			t.Fatalf("expected operator disable of mcp-ai-control to stay persistent")
		}
	})
}

func TestResolveDirectoryBootstrapParams(t *testing.T) {
	dir := t.TempDir()
	pm := NewPluginManager(dir)

	domain, sid := pm.resolveDirectoryBootstrapParams()
	if domain != "axonwall.local" || sid != 1 {
		// On hosts with /etc/axonwall/state.json only check fallback when no test file in dir
		_ = os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"system":{"domain":"corp.example.net"},"ha":{"role":"backup"}}`), 0600)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"system":{"domain":"corp.example.net"},"ha":{"role":"backup"}}`), 0600); err != nil {
		t.Fatalf("write state.json: %v", err)
	}
	domain, sid = pm.resolveDirectoryBootstrapParams()
	if domain != "corp.example.net" || sid != 2 {
		t.Fatalf("expected domain=corp.example.net serverID=2, got domain=%q sid=%d", domain, sid)
	}
}

func TestOfflinePluginCacheManifestVerificationAndResolution(t *testing.T) {
	writeArchiveAndSum := func(t *testing.T, dir, name string, content []byte) offlineCacheManifestFile {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), content, 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		sum := sha256.Sum256(content)
		return offlineCacheManifestFile{
			Filename: name,
			SHA256:   hex.EncodeToString(sum[:]),
		}
	}

	t.Run("valid manifest resolves selective closure and excludes unrelated cached packs", func(t *testing.T) {
		cacheRoot := t.TempDir()
		debDir := filepath.Join(cacheRoot, "debian")
		if err := os.MkdirAll(debDir, 0755); err != nil {
			t.Fatal(err)
		}
		f1 := writeArchiveAndSum(t, debDir, "suricata_7.0.0_amd64.deb", []byte("deb-suricata"))
		f1.Package = "suricata"
		f1.Depends = []string{"libhtp2"}
		f2 := writeArchiveAndSum(t, debDir, "libhtp2_0.5.48_amd64.deb", []byte("deb-libhtp2"))
		f2.Package = "libhtp2"
		fUnrelated := writeArchiveAndSum(t, debDir, "frr_10.0_amd64.deb", []byte("deb-frr"))
		fUnrelated.Package = "frr"
		manifestBytes, _ := json.Marshal(offlineCacheManifest{
			OSFamily: "debian",
			Version:  "0.16.0",
			Files:    []offlineCacheManifestFile{f2, f1, fUnrelated},
		})
		if err := os.WriteFile(filepath.Join(debDir, "manifest.json"), manifestBytes, 0644); err != nil {
			t.Fatal(err)
		}

		paths, ok, err := verifyAndCollectOfflinePackages(cacheRoot, "debian", []string{"suricata"})
		if err != nil || !ok {
			t.Fatalf("expected valid cache resolution, got ok=%v err=%v", ok, err)
		}
		if len(paths) != 2 || filepath.Base(paths[0]) != "libhtp2_0.5.48_amd64.deb" || filepath.Base(paths[1]) != "suricata_7.0.0_amd64.deb" {
			t.Fatalf("expected selective closure excluding frr, got: %v", paths)
		}

		// Partial cache missing required package 'crowdsec' returns ok=false, err=nil
		paths, ok, err = verifyAndCollectOfflinePackages(cacheRoot, "debian", []string{"suricata", "crowdsec"})
		if err != nil || ok || len(paths) != 0 {
			t.Fatalf("expected partial cache miss (ok=false err=nil), got ok=%v err=%v paths=%v", ok, err, paths)
		}
	})

	t.Run("alpine matching avoids foo-dev false positive", func(t *testing.T) {
		cacheRoot := t.TempDir()
		apkDir := filepath.Join(cacheRoot, "alpine")
		if err := os.MkdirAll(apkDir, 0755); err != nil {
			t.Fatal(err)
		}
		fDev := writeArchiveAndSum(t, apkDir, "foo-dev-1.2.3-r0.apk", []byte("apk-dev"))
		manifestBytes, _ := json.Marshal(offlineCacheManifest{
			OSFamily: "alpine",
			Version:  "0.16.0",
			Files:    []offlineCacheManifestFile{fDev},
		})
		if err := os.WriteFile(filepath.Join(apkDir, "manifest.json"), manifestBytes, 0644); err != nil {
			t.Fatal(err)
		}
		_, ok, err := verifyAndCollectOfflinePackages(cacheRoot, "alpine", []string{"foo"})
		if err != nil || ok {
			t.Fatalf("expected foo-dev NOT to satisfy foo, got ok=%v err=%v", ok, err)
		}

		fReal := writeArchiveAndSum(t, apkDir, "foo-1.2.3-r0.apk", []byte("apk-foo"))
		manifestBytes, _ = json.Marshal(offlineCacheManifest{
			OSFamily: "alpine",
			Version:  "0.16.0",
			Files:    []offlineCacheManifestFile{fDev, fReal},
		})
		if err := os.WriteFile(filepath.Join(apkDir, "manifest.json"), manifestBytes, 0644); err != nil {
			t.Fatal(err)
		}
		paths, ok, err := verifyAndCollectOfflinePackages(cacheRoot, "alpine", []string{"foo"})
		if err != nil || !ok || len(paths) != 1 || filepath.Base(paths[0]) != "foo-1.2.3-r0.apk" {
			t.Fatalf("expected only foo-1.2.3-r0.apk, got ok=%v err=%v paths=%v", ok, err, paths)
		}
	})

	t.Run("tampered sha256, empty manifest, and symlink fail closed", func(t *testing.T) {
		cacheRoot := t.TempDir()
		debDir := filepath.Join(cacheRoot, "debian")
		if err := os.MkdirAll(debDir, 0755); err != nil {
			t.Fatal(err)
		}
		emptyManifest, _ := json.Marshal(offlineCacheManifest{OSFamily: "debian", Version: "0.16.0", Files: []offlineCacheManifestFile{}})
		if err := os.WriteFile(filepath.Join(debDir, "manifest.json"), emptyManifest, 0644); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := verifyAndCollectOfflinePackages(cacheRoot, "debian", []string{"frr"}); err == nil || ok {
			t.Fatalf("expected empty manifest.files to fail closed, got ok=%v err=%v", ok, err)
		}

		outsideFile := filepath.Join(cacheRoot, "outside.deb")
		_ = os.WriteFile(outsideFile, []byte("secret"), 0644)
		linkPath := filepath.Join(debDir, "frr_10.0_amd64.deb")
		if err := os.Symlink(outsideFile, linkPath); err == nil {
			sum := sha256.Sum256([]byte("secret"))
			symManifest, _ := json.Marshal(offlineCacheManifest{
				OSFamily: "debian",
				Version:  "0.16.0",
				Files:    []offlineCacheManifestFile{{Filename: "frr_10.0_amd64.deb", SHA256: hex.EncodeToString(sum[:])}},
			})
			_ = os.WriteFile(filepath.Join(debDir, "manifest.json"), symManifest, 0644)
			if _, ok, err := verifyAndCollectOfflinePackages(cacheRoot, "debian", []string{"frr"}); err == nil || ok {
				t.Fatalf("expected symlink archive to fail closed, got ok=%v err=%v", ok, err)
			}
			_ = os.Remove(linkPath)
		}

		f := writeArchiveAndSum(t, debDir, "frr_10.0_amd64.deb", []byte("original"))
		manifestBytes, _ := json.Marshal(offlineCacheManifest{
			OSFamily: "debian",
			Version:  "0.16.0",
			Files:    []offlineCacheManifestFile{f},
		})
		if err := os.WriteFile(filepath.Join(debDir, "manifest.json"), manifestBytes, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(debDir, "frr_10.0_amd64.deb"), []byte("tampered"), 0644); err != nil {
			t.Fatal(err)
		}
		_, ok, err := verifyAndCollectOfflinePackages(cacheRoot, "debian", []string{"frr"})
		if err == nil || ok {
			t.Fatalf("expected fail-closed sha256 error, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("path traversal filename in manifest fails closed", func(t *testing.T) {
		cacheRoot := t.TempDir()
		debDir := filepath.Join(cacheRoot, "debian")
		if err := os.MkdirAll(debDir, 0755); err != nil {
			t.Fatal(err)
		}
		manifestBytes, _ := json.Marshal(offlineCacheManifest{
			OSFamily: "debian",
			Version:  "0.16.0",
			Files: []offlineCacheManifestFile{{
				Filename: "../evil_1.0.deb",
				SHA256:   strings.Repeat("a", 64),
			}},
		})
		if err := os.WriteFile(filepath.Join(debDir, "manifest.json"), manifestBytes, 0644); err != nil {
			t.Fatal(err)
		}
		_, ok, err := verifyAndCollectOfflinePackages(cacheRoot, "debian", []string{"evil"})
		if err == nil || ok {
			t.Fatalf("expected path traversal rejection, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("missing cache dir returns false without error", func(t *testing.T) {
		paths, ok, err := verifyAndCollectOfflinePackages(t.TempDir(), "debian", []string{"suricata"})
		if err != nil || ok || len(paths) != 0 {
			t.Fatalf("expected missing cache dir to return (nil, false, nil), got ok=%v err=%v", ok, err)
		}
	})
}

func TestUninstallSkipsProtectedAndSharedPackages(t *testing.T) {
	dir := t.TempDir()
	pm := NewPluginManager(dir)
	pm.osFamily = "debian"

	// rosenpass declares wireguard-tools; must never remove wireguard-tools!
	rem, skipped := pm.filterSafeUninstallPackages("rosenpass", []string{"wireguard-tools"})
	if len(rem) != 0 || len(skipped) != 1 || skipped[0] != "wireguard-tools" {
		t.Fatalf("expected wireguard-tools skipped on rosenpass uninstall, got rem=%v skipped=%v", rem, skipped)
	}

	// Simulate host-malware-rootkit enabled, then uninstalling coroot-ebpf-apm must skip shared linux-perf
	pm.mu.Lock()
	pm.installedMap["host-malware-rootkit"] = time.Now().UTC().Format(time.RFC3339)
	pm.mu.Unlock()
	rem, skipped = pm.filterSafeUninstallPackages("coroot-ebpf-apm", []string{"bpftool", "linux-perf"})
	if len(rem) != 0 || len(skipped) != 2 {
		t.Fatalf("expected shared bpftool & linux-perf skipped, got rem=%v skipped=%v", rem, skipped)
	}
}

func buildTestOpenPGPV4KeyPacket(payload []byte) ([]byte, string) {
	body := append([]byte{4, 0, 0, 0, 1, 1}, payload...)
	var pkt []byte
	pkt = append(pkt, 0x80|0x40|6)
	if len(body) < 192 {
		pkt = append(pkt, byte(len(body)))
	} else {
		n := len(body) - 192
		pkt = append(pkt, byte((n>>8)+192), byte(n&0xff))
	}
	pkt = append(pkt, body...)

	h := sha1.New()
	h.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
	h.Write(body)
	return pkt, strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

func TestTailscaleAptRepoHardening(t *testing.T) {
	// 1. Validate Debian codename strictly (^[a-z0-9-]+$).
	for _, badCodename := range []string{
		"trixie;id",
		"../bookworm",
		"Bookworm",
		"trixie main",
		"trixie$(whoami)",
		"trixie/sid",
	} {
		osRel := filepath.Join(t.TempDir(), "os-release")
		_ = os.WriteFile(osRel, []byte("VERSION_CODENAME=\""+badCodename+"\"\n"), 0644)
		if _, err := readValidatedDebianCodename(osRel); err == nil {
			t.Fatalf("expected codename %q to be rejected", badCodename)
		}
	}

	validPkt, validFP := buildTestOpenPGPV4KeyPacket([]byte("tailscale-test-key-material-01"))
	roguePkt, _ := buildTestOpenPGPV4KeyPacket([]byte("rogue-extra-key-material-02"))
	validSum := sha256.Sum256(validPkt)
	validSHA := hex.EncodeToString(validSum[:])

	var listEndpointCalled bool
	var keyringMode string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".tailscale-keyring.list") {
			listEndpointCalled = true
			_, _ = w.Write([]byte("deb [trusted=yes] https://evil.example/repo evil main\n"))
			return
		}
		switch keyringMode {
		case "corrupt":
			_, _ = w.Write([]byte("not-an-openpgp-keyring"))
		case "rogue_appended":
			_, _ = w.Write(append(append([]byte{}, validPkt...), roguePkt...))
		case "wrong_key":
			_, _ = w.Write(roguePkt)
		default:
			_, _ = w.Write(validPkt)
		}
	}))
	defer srv.Close()

	osRel := filepath.Join(t.TempDir(), "os-release")
	_ = os.WriteFile(osRel, []byte("ID=debian\nVERSION_CODENAME=bookworm\n"), 0644)

	// 2. Reject corrupt keyring, wrong fingerprint, or appended rogue key.
	for _, mode := range []string{"corrupt", "wrong_key", "rogue_appended"} {
		keyringMode = mode
		tmp := t.TempDir()
		err := prepareTailscaleAptRepoWithOptions(tailscaleRepoOptions{
			osReleasePath:     osRel,
			baseURL:           srv.URL,
			repoBaseURL:       "https://pkgs.tailscale.com/stable/debian",
			keyringPath:       filepath.Join(tmp, "tailscale-archive-keyring.gpg"),
			listPath:          filepath.Join(tmp, "tailscale.list"),
			pinnedFingerprint: validFP,
			httpClient:        srv.Client(),
			skipAptUpdate:     true,
		})
		if err == nil {
			t.Fatalf("mode %s: expected verification error, got nil", mode)
		}
		if _, statErr := os.Stat(filepath.Join(tmp, "tailscale-archive-keyring.gpg")); !os.IsNotExist(statErr) {
			t.Fatalf("mode %s: keyring file must not be written on verification failure", mode)
		}
	}

	// 3. Reject non-HTTPS base URL.
	tmpHTTP := t.TempDir()
	if err := prepareTailscaleAptRepoWithOptions(tailscaleRepoOptions{
		osReleasePath:     osRel,
		baseURL:           "http://pkgs.tailscale.com/stable/debian",
		keyringPath:       filepath.Join(tmpHTTP, "keyring.gpg"),
		listPath:          filepath.Join(tmpHTTP, "tailscale.list"),
		pinnedFingerprint: validFP,
		skipAptUpdate:     true,
	}); err == nil {
		t.Fatal("expected plain http:// Tailscale keyring URL to be rejected")
	}

	// 4. Valid pinned keyring writes keyring + locally generated sources.list without touching remote .list.
	keyringMode = "valid"
	tmpOK := t.TempDir()
	krPath := filepath.Join(tmpOK, "tailscale-archive-keyring.gpg")
	listPath := filepath.Join(tmpOK, "tailscale.list")
	if err := prepareTailscaleAptRepoWithOptions(tailscaleRepoOptions{
		osReleasePath:     osRel,
		baseURL:           srv.URL,
		repoBaseURL:       "https://pkgs.tailscale.com/stable/debian",
		keyringPath:       krPath,
		listPath:          listPath,
		pinnedFingerprint: validFP,
		pinnedSHA256s:     []string{validSHA},
		httpClient:        srv.Client(),
		skipAptUpdate:     true,
	}); err != nil {
		t.Fatalf("expected valid pinned keyring install to succeed, got: %v", err)
	}
	if listEndpointCalled {
		t.Fatal("remote .tailscale-keyring.list endpoint must never be fetched or trusted")
	}
	listBytes, err := os.ReadFile(listPath)
	if err != nil {
		t.Fatal(err)
	}
	wantLine := fmt.Sprintf("deb [signed-by=%s] https://pkgs.tailscale.com/stable/debian bookworm main\n", krPath)
	if string(listBytes) != wantLine {
		t.Fatalf("unexpected generated tailscale.list:\n got: %q\nwant: %q", string(listBytes), wantLine)
	}

	// 5. Cross-check OpenPGP v4 fingerprint parser against real gpg --export if gpg is installed.
	if gpgBin, lookErr := exec.LookPath("gpg"); lookErr == nil {
		gpgHome := filepath.Join(t.TempDir(), "gnupg")
		if err := os.MkdirAll(gpgHome, 0700); err != nil {
			t.Fatal(err)
		}
		batch := "Key-Type: RSA\nKey-Length: 2048\nName-Real: Axonwall Test\nName-Email: test@axonwall.local\n%no-protection\n%commit\n"
		genCmd := exec.Command(gpgBin, "--homedir", gpgHome, "--batch", "--gen-key")
		genCmd.Stdin = strings.NewReader(batch)
		if out, genErr := genCmd.CombinedOutput(); genErr == nil {
			fpOut, fpErr := exec.Command(gpgBin, "--homedir", gpgHome, "--batch", "--with-colons", "--list-keys").Output()
			expBytes, expErr := exec.Command(gpgBin, "--homedir", gpgHome, "--batch", "--export").Output()
			if fpErr == nil && expErr == nil && len(expBytes) > 0 {
				var gpgFP string
				for _, line := range strings.Split(string(fpOut), "\n") {
					if strings.HasPrefix(line, "fpr:") {
						parts := strings.Split(line, ":")
						if len(parts) > 9 && parts[9] != "" {
							gpgFP = parts[9]
							break
						}
					}
				}
				if gpgFP != "" {
					parsedFPs, parseErr := parseOpenPGPPublicKeyFingerprints(expBytes)
					if parseErr != nil || len(parsedFPs) != 1 || parsedFPs[0] != gpgFP {
						t.Fatalf("OpenPGP fingerprint mismatch against gpg: parsed=%v err=%v want=%s", parsedFPs, parseErr, gpgFP)
					}
				}
			}
		} else {
			t.Logf("skipping real gpg cross-check (gpg --gen-key failed in sandbox: %s)", string(out))
		}
	}
}
