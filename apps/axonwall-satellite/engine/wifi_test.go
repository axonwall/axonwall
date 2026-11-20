package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R4-A-L5: WiFi channels are validated against the legal 2.4/5/6 GHz
// sets and classified from the channel number — the old code treated
// every channel > 14 as 5 GHz and never validated at all, so a 6 GHz
// channel was configured as 5 GHz and an out-of-range channel was
// written into hostapd.conf unchecked.
func TestWifiBandForChannel(t *testing.T) {
	for _, tc := range []struct {
		ch   int
		want string
	}{
		{1, "2.4GHz"},
		{6, "2.4GHz"},
		{14, "2.4GHz"},
		{36, "5GHz"},
		{100, "5GHz"},
		{149, "5GHz"},
		{177, "5GHz"},
		{37, "6GHz"},
		{33, "6GHz"},
		{101, "6GHz"},
		{233, "6GHz"},
	} {
		band, err := wifiBandForChannel(tc.ch)
		if err != nil {
			t.Errorf("channel %d: unexpected error: %v", tc.ch, err)
			continue
		}
		if band != tc.want {
			t.Errorf("channel %d: expected band %s, got %s", tc.ch, tc.want, band)
		}
	}
	// Overlapping channels classify by priority 2.4 GHz > 5 GHz >
	// 6 GHz from the channel number alone (see wifiBandForChannel).
	if band, _ := wifiBandForChannel(5); band != "2.4GHz" {
		t.Errorf("channel 5 overlaps 2.4/6 GHz and must classify 2.4GHz, got %s", band)
	}
	for _, bad := range []int{0, -1, 15, 16, 31, 200, 234, 1000} {
		if _, err := wifiBandForChannel(bad); err == nil {
			t.Errorf("channel %d should be rejected as out of range", bad)
		}
	}
}

func TestRenderHostapdConfigBand(t *testing.T) {
	cfg := WiFiConfig{Radio: "wlan0", SSID: "test", Channel: 37, Security: SecurityWPA2PSK, Password: "secret123", Enabled: true}

	six, err := renderHostapdConfig(cfg, "6GHz")
	if err != nil {
		t.Fatalf("renderHostapdConfig 6GHz failed: %v", err)
	}
	if !strings.Contains(six.String(), "hw_mode=a") || !strings.Contains(six.String(), "ieee80211ax=1") {
		t.Errorf("6 GHz config must use hw_mode=a and ieee80211ax=1:\n%s", six.String())
	}
	if strings.Contains(six.String(), "ieee80211ac=1") {
		t.Errorf("6 GHz config must not enable 802.11ac:\n%s", six.String())
	}
	if !strings.Contains(six.String(), "channel=37") {
		t.Errorf("6 GHz config must carry channel=37:\n%s", six.String())
	}

	five, err := renderHostapdConfig(cfg, "5GHz")
	if err != nil {
		t.Fatalf("renderHostapdConfig 5GHz failed: %v", err)
	}
	if !strings.Contains(five.String(), "hw_mode=a") || !strings.Contains(five.String(), "ieee80211ac=1") {
		t.Errorf("5 GHz config must use hw_mode=a and ieee80211ac=1:\n%s", five.String())
	}
	if strings.Contains(five.String(), "ieee80211ax=1") {
		t.Errorf("5 GHz config must not enable 802.11ax:\n%s", five.String())
	}

	two, err := renderHostapdConfig(cfg, "2.4GHz")
	if err != nil {
		t.Fatalf("renderHostapdConfig 2.4GHz failed: %v", err)
	}
	if !strings.Contains(two.String(), "hw_mode=g") {
		t.Errorf("2.4 GHz config must use hw_mode=g:\n%s", two.String())
	}
}

// Configure must reject an out-of-range channel before writing any
// hostapd.conf or touching the system.
func TestWiFiConfigureRejectsInvalidChannel(t *testing.T) {
	e := &WiFiEngine{ConfigDir: t.TempDir()}
	err := e.Configure(WiFiConfig{Radio: "wlan0", SSID: "test", Channel: 200, Security: SecurityWPA2PSK, Password: "secret123", Enabled: true})
	if err == nil {
		t.Fatal("Configure must reject channel 200")
	}
	if entries, _ := os.ReadDir(e.ConfigDir); len(entries) != 0 {
		t.Fatalf("invalid channel must not write hostapd.conf, found %v in %s", entries, e.ConfigDir)
	}
	confPath := filepath.Join(e.ConfigDir, "hostapd-wlan0.conf")
	if _, statErr := os.Stat(confPath); statErr == nil {
		t.Fatalf("invalid channel must not write %s", confPath)
	}
}
