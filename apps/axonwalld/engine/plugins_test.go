package engine

import (
	"os"
	"path/filepath"
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
			if !p.DefaultEnabled {
				t.Errorf("expected cli-workstation to have DefaultEnabled=true")
			}
			if !p.Enabled {
				t.Errorf("expected cli-workstation to be Enabled=true by default")
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
