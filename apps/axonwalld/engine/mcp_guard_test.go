package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsMcpSubsystemEnabled(t *testing.T) {
	// Clean env
	os.Unsetenv("AXONWALL_DISABLE_MCP")
	os.Unsetenv("AXONWALL_MCP_ENABLED")
	os.Unsetenv("AXONWALL_MCP_SETTINGS_PATH")
	defer func() {
		os.Unsetenv("AXONWALL_DISABLE_MCP")
		os.Unsetenv("AXONWALL_MCP_ENABLED")
		os.Unsetenv("AXONWALL_MCP_SETTINGS_PATH")
	}()

	tmpDir := t.TempDir()
	nonExistentSettings := filepath.Join(tmpDir, "nonexistent.json")
	os.Setenv("AXONWALL_MCP_SETTINGS_PATH", nonExistentSettings)

	// 1. Disabled by default
	enabled, reason := IsMcpSubsystemEnabled()
	if enabled {
		t.Fatalf("expected MCP subsystem to be disabled by default, got enabled")
	}
	if reason == "" {
		t.Fatalf("expected non-empty reason when disabled by default")
	}

	// 2. Explicitly enabled via AXONWALL_MCP_ENABLED=true
	os.Setenv("AXONWALL_MCP_ENABLED", "true")
	enabled, _ = IsMcpSubsystemEnabled()
	if !enabled {
		t.Fatalf("expected MCP subsystem to be enabled when AXONWALL_MCP_ENABLED=true")
	}

	// 3. Explicitly enabled via AXONWALL_MCP_ENABLED=1
	os.Setenv("AXONWALL_MCP_ENABLED", "1")
	enabled, _ = IsMcpSubsystemEnabled()
	if !enabled {
		t.Fatalf("expected MCP subsystem to be enabled when AXONWALL_MCP_ENABLED=1")
	}

	// 4. Explicitly disabled via AXONWALL_MCP_ENABLED=false
	os.Setenv("AXONWALL_MCP_ENABLED", "false")
	enabled, _ = IsMcpSubsystemEnabled()
	if enabled {
		t.Fatalf("expected MCP subsystem to be disabled when AXONWALL_MCP_ENABLED=false")
	}
	os.Unsetenv("AXONWALL_MCP_ENABLED")

	// 5. Explicitly disabled via AXONWALL_DISABLE_MCP=1
	os.Setenv("AXONWALL_DISABLE_MCP", "1")
	enabled, _ = IsMcpSubsystemEnabled()
	if enabled {
		t.Fatalf("expected MCP subsystem to be disabled when AXONWALL_DISABLE_MCP=1")
	}
	os.Unsetenv("AXONWALL_DISABLE_MCP")

	// 6. Explicitly enabled via persistent configuration file
	settingsPath := filepath.Join(tmpDir, "mcp-settings.json")
	os.Setenv("AXONWALL_MCP_SETTINGS_PATH", settingsPath)

	if err := os.WriteFile(settingsPath, []byte(`{"enabled": true}`), 0600); err != nil {
		t.Fatalf("failed to write settings file: %v", err)
	}
	enabled, _ = IsMcpSubsystemEnabled()
	if !enabled {
		t.Fatalf("expected MCP subsystem to be enabled via settings file")
	}

	// 7. Explicitly disabled via persistent configuration file
	if err := os.WriteFile(settingsPath, []byte(`{"enabled": false, "disabledReason": "Custom lockdown"}`), 0600); err != nil {
		t.Fatalf("failed to write settings file: %v", err)
	}
	enabled, reason = IsMcpSubsystemEnabled()
	if enabled {
		t.Fatalf("expected MCP subsystem to be disabled via settings file")
	}
	if reason != "Custom lockdown" {
		t.Fatalf("expected reason 'Custom lockdown', got '%s'", reason)
	}
}
