package engine

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type ZeroTrustApp struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	PublicHostname   string   `json:"publicHostname"`
	InternalUpstream string   `json:"internalUpstream"`
	AllowedRoles     []string `json:"allowedRoles"`
	Enabled          bool     `json:"enabled"`
	Description      string   `json:"description"`
}

type ZeroTrustConfig struct {
	Enabled bool           `json:"enabled"`
	Apps    []ZeroTrustApp `json:"apps"`
}

type IAPManager struct {
	cmd *exec.Cmd
}

func NewIAPManager() *IAPManager {
	return &IAPManager{}
}

func (m *IAPManager) ApplyConfig(configJSON []byte) error {
	var config ZeroTrustConfig
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return fmt.Errorf("failed to unmarshal ZeroTrustConfig: %w", err)
	}

	if !config.Enabled {
		m.Stop()
		return nil
	}

	for _, app := range config.Apps {
		if !app.Enabled {
			continue
		}
		if strings.ContainsAny(app.PublicHostname, "\n\r{};") || strings.ContainsAny(app.InternalUpstream, "\n\r{};") {
			return fmt.Errorf("invalid characters in zero trust app hostname or upstream")
		}
	}

	caddyfileContent := m.generateCaddyfile(config)

	caddyfilePath := "/etc/axonwall/Caddyfile"
	if err := os.MkdirAll(filepath.Dir(caddyfilePath), 0755); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}
	_ = os.MkdirAll("/run/axonwall", 0755)

	if err := os.WriteFile(caddyfilePath, []byte(caddyfileContent), 0644); err != nil {
		return fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	return m.ReloadCaddy(caddyfilePath)
}

func (m *IAPManager) generateCaddyfile(config ZeroTrustConfig) string {
	var out string

	out += "{\n"
	out += "\tadmin unix//run/axonwall/caddy-admin.sock\n"
	out += "}\n\n"

	for _, app := range config.Apps {
		if !app.Enabled {
			continue
		}
		if strings.ContainsAny(app.PublicHostname, "\n\r{};") || strings.ContainsAny(app.InternalUpstream, "\n\r{};") {
			continue
		}

		out += fmt.Sprintf("%s {\n", app.PublicHostname)
		out += fmt.Sprintf("\tforward_auth http://localhost:3000 {\n")
		out += fmt.Sprintf("\t\turi /api/auth/gateway\n")
		out += fmt.Sprintf("\t\tcopy_headers X-Remote-User X-Remote-Roles\n")
		out += fmt.Sprintf("\t}\n")
		out += fmt.Sprintf("\treverse_proxy %s\n", app.InternalUpstream)
		out += "}\n\n"
	}

	return out
}

func (m *IAPManager) ReloadCaddy(configPath string) error {
	// If it's not running, start it
	if m.cmd == nil || m.cmd.Process == nil {
		m.cmd = exec.Command("caddy", "run", "--config", configPath, "--adapter", "caddyfile")
		m.cmd.Stdout = os.Stdout
		m.cmd.Stderr = os.Stderr

		if err := m.cmd.Start(); err != nil {
			log.Printf("Warning: Failed to start Caddy (IAP): %v", err)
			return err
		}
		log.Printf("Started Caddy IAP proxy on port 443")
		return nil
	}

	// If running, reload via unix admin socket; fallback to process restart if reload fails
	reloadCmd := exec.Command("caddy", "reload", "--config", configPath, "--adapter", "caddyfile", "--address", "unix//run/axonwall/caddy-admin.sock")
	if out, err := reloadCmd.CombinedOutput(); err != nil {
		log.Printf("Warning: caddy reload failed (%v: %s), restarting process", err, string(out))
		m.Stop()
		m.cmd = exec.Command("caddy", "run", "--config", configPath, "--adapter", "caddyfile")
		m.cmd.Stdout = os.Stdout
		m.cmd.Stderr = os.Stderr
		if startErr := m.cmd.Start(); startErr != nil {
			return fmt.Errorf("failed to restart caddy: %v", startErr)
		}
		log.Printf("Restarted Caddy IAP proxy on port 443")
		return nil
	}
	log.Printf("Reloaded Caddy IAP configuration")
	return nil
}

func (m *IAPManager) Stop() {
	if m.cmd != nil && m.cmd.Process != nil {
		m.cmd.Process.Kill()
		m.cmd.Wait()
		m.cmd = nil
		log.Printf("Stopped Caddy IAP proxy")
	}
}
