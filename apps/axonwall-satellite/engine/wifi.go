package engine

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"
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
hw_mode={{.HwMode}}
channel={{.Channel}}
ieee80211n=1
{{if .Is5GHz}}ieee80211ac=1
{{end}}{{if .Is6GHz}}ieee80211ax=1
{{end}}wmm_enabled=1

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

// wifiBandForChannel classifies a WiFi channel into its band and
// validates it against the legal channel sets. R4-A-L5: the old code
// classified every channel > 14 as 5 GHz and never validated the
// channel at all, so a 6 GHz channel (e.g. 37) was configured as a
// 5 GHz channel and an out-of-range channel (e.g. 200) was written
// into hostapd.conf unchecked.
//
// Band overlap: 6 GHz channels 1, 5, 9, 13 overlap the 2.4 GHz set
// 1-14, and 149/153/157/161/165 exist in both the 5 GHz and 6 GHz
// sets. From a channel number alone the only deterministic reading
// is priority 2.4 GHz > 5 GHz > 6 GHz; selecting an overlapping
// channel explicitly for 6 GHz needs a Band field on WiFiConfig,
// which is not part of this fix.
func wifiBandForChannel(ch int) (band string, err error) {
	if ch >= 1 && ch <= 14 {
		return "2.4GHz", nil
	}
	if valid5GHzChannel[ch] {
		return "5GHz", nil
	}
	if ch >= 1 && ch <= 233 && (ch-1)%4 == 0 {
		return "6GHz", nil
	}
	return "", fmt.Errorf("invalid WiFi channel %d: legal channels are 2.4 GHz 1-14, 5 GHz %v, and 6 GHz 1-233 step 4 (1, 5, 9, ...)", ch, sorted5GHzChannels())
}

// valid5GHzChannel is the legal UNII channel set (20 MHz base
// channels, including the DFS and U-NII-3 ranges).
var valid5GHzChannel = map[int]bool{
	32: true, 34: true, 36: true, 38: true, 40: true, 42: true,
	44: true, 46: true, 48: true, 52: true, 56: true, 60: true,
	64: true, 100: true, 104: true, 108: true, 112: true, 116: true,
	120: true, 124: true, 128: true, 132: true, 136: true, 140: true,
	144: true, 149: true, 153: true, 157: true, 161: true, 165: true,
	169: true, 173: true, 177: true,
}

func sorted5GHzChannels() []int {
	out := make([]int, 0, len(valid5GHzChannel))
	for ch := range valid5GHzChannel {
		out = append(out, ch)
	}
	sort.Ints(out)
	return out
}

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

	// Default channel and derived 802.11 band parameters
	if cfg.Channel == 0 {
		cfg.Channel = 1
	}
	if cfg.FastRoaming.Enabled && strings.TrimSpace(cfg.FastRoaming.MobilityDomain) == "" {
		cfg.FastRoaming.MobilityDomain = "4f57"
	}

	// R4-A-L5: validate the channel and classify the band from the
	// channel number — a 6 GHz channel is not a 5 GHz channel, and
	// an out-of-range channel must not reach hostapd.conf.
	band, err := wifiBandForChannel(cfg.Channel)
	if err != nil {
		return err
	}

	confPath := filepath.Join(e.ConfigDir, fmt.Sprintf("hostapd-%s.conf", cfg.Radio))

	buf, err := renderHostapdConfig(cfg, band)
	if err != nil {
		return err
	}

	if err := os.WriteFile(confPath, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write hostapd config: %v", err)
	}

	// Restart or start hostapd for this interface
	slog.Info("Restarting hostapd service for radio", "radio", cfg.Radio)
	cmd := exec.Command("systemctl", "--no-ask-password", "restart", fmt.Sprintf("hostapd@%s", cfg.Radio))
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("Failed to restart hostapd via systemd, trying direct execution", "error", err, "output", string(out))
		// Fallback for non-systemd environments (like OpenWrt)
		// A-M39 (round 2): the old pattern "hostapd <confPath>"
		// could never match the daemon this code itself starts
		// ("hostapd -B <confPath>"), so the stale hostapd survived
		// every re-configure. Match the real argv, with the path
		// regex-quoted, and wait for the old daemon to die before
		// starting the new one (otherwise the new hostapd fails to
		// bind the radio while the old config stays live).
		_ = exec.Command("pkill", "-f", hostapdPattern(confPath)).Run()
		if !waitHostapdGone(confPath, 5*time.Second) {
			return fmt.Errorf("previous hostapd for radio %s is still running; refusing to start a second instance", cfg.Radio)
		}

		startCmd := exec.Command("hostapd", "-B", confPath)
		if startOut, startErr := startCmd.CombinedOutput(); startErr != nil {
			return fmt.Errorf("failed to start hostapd: %v (output: %s)", startErr, startOut)
		}
	}

	return nil
}

// renderHostapdConfig renders the hostapd.conf body for cfg on the
// given band ("2.4GHz", "5GHz", "6GHz"). Extracted from Configure so
// the band classification and template output are unit-testable
// without running systemctl/hostapd.
func renderHostapdConfig(cfg WiFiConfig, band string) (bytes.Buffer, error) {
	var buf bytes.Buffer
	tmpl, err := template.New("hostapd").Parse(hostapdTemplate)
	if err != nil {
		return buf, err
	}
	tplData := struct {
		WiFiConfig
		HwMode string
		Is5GHz bool
		Is6GHz bool
	}{
		WiFiConfig: cfg,
		HwMode:     "g",
		Is5GHz:     band == "5GHz",
		Is6GHz:     band == "6GHz",
	}
	if band == "5GHz" || band == "6GHz" {
		tplData.HwMode = "a"
	}
	if err := tmpl.Execute(&buf, tplData); err != nil {
		return buf, err
	}
	return buf, nil
}

// hostapdPattern matches the exact argv this code starts hostapd with
// ("hostapd -B <confPath>") for pkill/pgrep -f.
func hostapdPattern(confPath string) string {
	return fmt.Sprintf("hostapd -B %s", regexp.QuoteMeta(confPath))
}

// waitHostapdGone polls until no hostapd with this config is running, or
// the deadline passes. Teardown must not report success while the AP
// keeps broadcasting (A-M39).
func waitHostapdGone(confPath string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if exec.Command("pgrep", "-f", hostapdPattern(confPath)).Run() != nil {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Teardown stops hostapd for the radio
func (e *WiFiEngine) Teardown(radio string) error {
	if !validRadioRegex.MatchString(radio) || strings.Contains(radio, "..") || strings.HasPrefix(radio, "-") {
		return fmt.Errorf("invalid radio interface name: %s", radio)
	}
	confPath := filepath.Join(e.ConfigDir, fmt.Sprintf("hostapd-%s.conf", radio))

	cmd := exec.Command("systemctl", "--no-ask-password", "stop", fmt.Sprintf("hostapd@%s", radio))
	if err := cmd.Run(); err != nil {
		_ = exec.Command("pkill", "-f", hostapdPattern(confPath)).Run()
	}

	// A-M39 (round 2): Teardown used to remove the config and return
	// nil while the AP kept broadcasting. Verify the process is
	// actually gone before reporting success.
	if !waitHostapdGone(confPath, 5*time.Second) {
		return fmt.Errorf("hostapd for radio %s is still running after stop; AP may still be broadcasting", radio)
	}

	_ = os.Remove(confPath)
	return nil
}
