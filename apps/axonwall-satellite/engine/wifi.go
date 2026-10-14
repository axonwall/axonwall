package engine

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

var validRadioRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

type WiFiSecurity string

const (
	SecurityWPA2PSK        WiFiSecurity = "wpa2-psk"
	SecurityWPA3SAE        WiFiSecurity = "wpa3-sae"
	SecurityWPA3Enterprise WiFiSecurity = "wpa3-enterprise"
	SecurityOpen           WiFiSecurity = "open"
)

type FastRoamingConfig struct {
	Enabled        bool   `json:"enabled"`
	MobilityDomain string `json:"mobilityDomain,omitempty"`
}

type WiFiConfig struct {
	Radio       string            `json:"radio"`
	SSID        string            `json:"ssid"`
	Channel     int               `json:"channel"`
	Security    WiFiSecurity      `json:"security"`
	Password    string            `json:"password,omitempty"`
	Enabled     bool              `json:"enabled"`
	FastRoaming FastRoamingConfig `json:"fastRoaming,omitempty"`
}

type WiFiEngine struct {
	ConfigDir string
}

func NewWiFiEngine() *WiFiEngine {
	// Typically /etc/hostapd/ or similar
	dir := "/etc/axonwall/wifi"
	_ = os.MkdirAll(dir, 0755)
	return &WiFiEngine{
		ConfigDir: dir,
	}
}

// DetectRadios uses `iw dev` to find physical wireless interfaces
func (e *WiFiEngine) DetectRadios() ([]string, error) {
	cmd := exec.Command("iw", "dev")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run iw dev: %v (output: %s)", err, out)
	}

	// Very simple parser for `iw dev` output to extract Interface names
	var radios []string
	lines := bytes.Split(out, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("Interface ")) {
			parts := bytes.Split(line, []byte(" "))
			if len(parts) >= 2 {
				radios = append(radios, string(parts[1]))
			}
		}
	}
	return radios, nil
}

// hostapdTemplate is a minimal template for hostapd configuration
const hostapdTemplate = `
interface={{.Radio}}
driver=nl80211
ssid={{.SSID}}
hw_mode=g
channel={{.Channel}}
ieee80211n=1
wmm_enabled=1

{{if .FastRoaming.Enabled}}
# 802.11r Fast BSS Transition
ieee80211r=1
mobility_domain={{.FastRoaming.MobilityDomain}}
ft_over_ds=1
ft_psk_generate_local=1
{{end}}

{{if eq .Security "wpa2-psk"}}
wpa=2
wpa_passphrase={{.Password}}
{{if .FastRoaming.Enabled}}wpa_key_mgmt=WPA-PSK FT-PSK{{else}}wpa_key_mgmt=WPA-PSK{{end}}
rsn_pairwise=CCMP
{{end}}

{{if eq .Security "wpa3-sae"}}
wpa=2
wpa_passphrase={{.Password}}
{{if .FastRoaming.Enabled}}wpa_key_mgmt=SAE FT-SAE{{else}}wpa_key_mgmt=SAE{{end}}
rsn_pairwise=CCMP
ieee80211w=2
{{end}}

{{if eq .Security "wpa3-enterprise"}}
wpa=2
ieee80211x=1
{{if .FastRoaming.Enabled}}wpa_key_mgmt=WPA-EAP-SUITE-B-192 FT-EAP{{else}}wpa_key_mgmt=WPA-EAP-SUITE-B-192 WPA-EAP{{end}}
rsn_pairwise=CCMP
ieee80211w=2
{{end}}

{{if eq .Security "open"}}
# Open network, no WPA
{{end}}
`

// Configure provisions the SSID on the given radio
func (e *WiFiEngine) Configure(cfg WiFiConfig) error {
	if !validRadioRegex.MatchString(cfg.Radio) || strings.Contains(cfg.Radio, "..") || strings.HasPrefix(cfg.Radio, "-") {
		return fmt.Errorf("invalid radio interface name: %s", cfg.Radio)
	}
	for _, field := range []string{cfg.SSID, cfg.Password, cfg.FastRoaming.MobilityDomain} {
		if strings.ContainsAny(field, "\n\r") {
			return fmt.Errorf("invalid wifi configuration: newlines are not allowed")
		}
	}

	if !cfg.Enabled {
		return e.Teardown(cfg.Radio)
	}

	tmpl, err := template.New("hostapd").Parse(hostapdTemplate)
	if err != nil {
		return err
	}

	// Default channel if not specified
	if cfg.Channel == 0 {
		cfg.Channel = 1
	}

	confPath := filepath.Join(e.ConfigDir, fmt.Sprintf("hostapd-%s.conf", cfg.Radio))

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cfg); err != nil {
		return err
	}

	if err := os.WriteFile(confPath, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write hostapd config: %v", err)
	}

	// Restart or start hostapd for this interface
	slog.Info("Restarting hostapd service for radio", "radio", cfg.Radio)
	cmd := exec.Command("systemctl", "restart", fmt.Sprintf("hostapd@%s", cfg.Radio))
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("Failed to restart hostapd via systemd, trying direct execution", "error", err, "output", string(out))
		// Fallback for non-systemd environments (like OpenWrt)
		exec.Command("pkill", "-f", fmt.Sprintf("hostapd %s", confPath)).Run()

		startCmd := exec.Command("hostapd", "-B", confPath)
		if startOut, startErr := startCmd.CombinedOutput(); startErr != nil {
			return fmt.Errorf("failed to start hostapd: %v (output: %s)", startErr, startOut)
		}
	}

	return nil
}

// Teardown stops hostapd for the radio
func (e *WiFiEngine) Teardown(radio string) error {
	if !validRadioRegex.MatchString(radio) || strings.Contains(radio, "..") || strings.HasPrefix(radio, "-") {
		return fmt.Errorf("invalid radio interface name: %s", radio)
	}
	confPath := filepath.Join(e.ConfigDir, fmt.Sprintf("hostapd-%s.conf", radio))

	cmd := exec.Command("systemctl", "stop", fmt.Sprintf("hostapd@%s", radio))
	if err := cmd.Run(); err != nil {
		exec.Command("pkill", "-f", fmt.Sprintf("hostapd %s", confPath)).Run()
	}

	_ = os.Remove(confPath)
	return nil
}
