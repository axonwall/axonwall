package engine

import (
	"os"
	"path/filepath"
	"testing"
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
