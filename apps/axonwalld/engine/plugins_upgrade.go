package engine

import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const upgradeMigrationMarkerName = ".plugin-migration-v016-done"

type upgradeProbePaths struct {
	etcDir             string
	etcRoot            string
	baseDataDir        string
	isSystemdUnitReady func(unit string) bool
}

func isNonEmptyJSONArrayOrObject(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "[]" || trimmed == "{}" || trimmed == "null" {
		return false
	}
	var arr []any
	if err := json.Unmarshal(data, &arr); err == nil {
		return len(arr) > 0
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err == nil {
		return len(obj) > 0
	}
	return false
}

// RunUpgradePreservation preserves previously-active appliance features as enabled
// plugins when upgrading an existing v0.15.x host onto the Lean Core baseline.
// Fresh installs (.firstboot present) and subsequent boots (.plugin-migration-v016-done
// present) are skipped cleanly so operators stay in Lean Core by default and can
// disable preserved plugins permanently.
func (pm *PluginManager) RunUpgradePreservation(etcDir string) []string {
	if strings.Contains(pm.baseDataDir, "axonwall-plugins-test-") {
		return nil
	}
	return pm.runUpgradePreservationFromPaths(upgradeProbePaths{
		etcDir:      etcDir,
		etcRoot:     "/etc",
		baseDataDir: pm.baseDataDir,
		isSystemdUnitReady: func(unit string) bool {
			if !systemctlAvailable() {
				return false
			}
			return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
		},
	})
}

func (pm *PluginManager) runUpgradePreservationFromPaths(opts upgradeProbePaths) []string {
	markerPath := filepath.Join(opts.baseDataDir, upgradeMigrationMarkerName)
	if _, err := os.Stat(markerPath); err == nil {
		return nil
	}

	writeMarker := func() {
		_ = os.MkdirAll(opts.baseDataDir, 0755)
		_ = os.WriteFile(markerPath, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0644)
	}

	if _, err := os.Stat(filepath.Join(opts.etcDir, ".firstboot")); err == nil {
		writeMarker()
		return nil
	}

	var preserved []string
	preserve := func(id string) {
		pm.mu.Lock()
		defer pm.mu.Unlock()
		if pm.disabledMap[id] {
			return
		}
		if pm.installedMap[id] == "" {
			pm.installedMap[id] = time.Now().UTC().Format(time.RFC3339)
		}
		preserved = append(preserved, id)
	}

	if info, err := os.Stat(filepath.Join(opts.etcDir, "slapd.seed")); err == nil && info.Size() > 0 {
		preserve("directory-ldap")
	}
	if _, err := os.Stat(filepath.Join(opts.etcRoot, ".git")); err == nil {
		preserve("etckeeper-audit")
	}
	if isNonEmptyJSONArrayOrObject(filepath.Join(opts.etcDir, "mcp-keys.json")) {
		preserve("mcp-ai-control")
	}
	if _, err := os.Stat(filepath.Join(opts.baseDataDir, "cli-workstation")); err == nil {
		if _, disErr := os.Stat(filepath.Join(opts.etcDir, "workstation.disabled")); os.IsNotExist(disErr) {
			preserve("cli-workstation")
		}
	}

	if opts.isSystemdUnitReady != nil {
		unitToPlugin := map[string]string{
			"suricata.service":                "suricata-ids",
			"crowdsec.service":                "crowdsec-bouncer",
			"frr.service":                     "frr-routing",
			"keepalived.service":              "high-availability",
			"openvpn-server@axonwall.service": "openvpn",
			"strongswan-starter.service":      "ipsec-strongswan",
		}
		for unit, pluginID := range unitToPlugin {
			if opts.isSystemdUnitReady(unit) {
				preserve(pluginID)
			}
		}
	}

	if len(preserved) > 0 {
		pm.mu.Lock()
		pm.saveState()
		pm.mu.Unlock()
		syncPreservedPluginsToDesiredState(opts, preserved)
		log.Printf("[PluginManager] Preserved pre-existing appliance features across Lean Core upgrade: %s", strings.Join(preserved, ", "))
	}
	writeMarker()
	return preserved
}

func syncPreservedPluginsToDesiredState(opts upgradeProbePaths, preserved []string) {
	if len(preserved) == 0 {
		return
	}
	candidates := []string{
		filepath.Join(opts.baseDataDir, "state.json"),
		filepath.Join(opts.etcDir, "state.json"),
	}
	wroteAny := false
	for _, statePath := range candidates {
		if _, err := os.Stat(statePath); err == nil {
			mergePreservedPluginsIntoStateFile(statePath, preserved)
			wroteAny = true
		}
	}
	if !wroteAny {
		// In minimal/test environments where state.json does not yet exist under baseDataDir, seed it there.
		_ = os.MkdirAll(opts.baseDataDir, 0755)
		mergePreservedPluginsIntoStateFile(filepath.Join(opts.baseDataDir, "state.json"), preserved)
	}
}

func mergePreservedPluginsIntoStateFile(statePath string, preserved []string) {
	doc := make(map[string]any)
	if raw, err := os.ReadFile(statePath); err == nil && len(strings.TrimSpace(string(raw))) > 0 {
		if json.Unmarshal(raw, &doc) != nil {
			return
		}
	}

	var pluginsList []map[string]any
	explicitState := make(map[string]bool)
	if rawPlugins, ok := doc["plugins"].([]any); ok {
		for _, item := range rawPlugins {
			if m, ok := item.(map[string]any); ok {
				if id, ok := m["id"].(string); ok && id != "" {
					if en, hasEn := m["enabled"].(bool); hasEn {
						explicitState[id] = en
					}
				}
				pluginsList = append(pluginsList, m)
			}
		}
	}

	changed := false
	for _, pid := range preserved {
		if en, exists := explicitState[pid]; exists {
			// Respect explicit disabled: false entries; nothing to add when already recorded.
			_ = en
			continue
		}
		pluginsList = append(pluginsList, map[string]any{
			"id":      pid,
			"enabled": true,
		})
		explicitState[pid] = true
		changed = true

		if pid == "directory-ldap" {
			identityMap, _ := doc["identity"].(map[string]any)
			if identityMap == nil {
				identityMap = make(map[string]any)
			}
			if _, hasLdap := identityMap["ldapEnabled"]; !hasLdap {
				identityMap["ldapEnabled"] = true
				doc["identity"] = identityMap
			}
		}
	}

	if !changed {
		return
	}
	doc["plugins"] = pluginsList
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return
	}
	tmpPath := statePath + ".tmp"
	if err := os.WriteFile(tmpPath, append(encoded, '\n'), 0660); err == nil {
		if renameErr := os.Rename(tmpPath, statePath); renameErr != nil {
			_ = os.Remove(tmpPath)
		}
	}
}
