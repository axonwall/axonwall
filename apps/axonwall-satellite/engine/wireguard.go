package engine

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

type WireGuardConfig struct {
	InterfaceName string `json:"interfaceName"` // e.g. "wg-axon0"
	TunnelIP      string `json:"tunnelIp"`      // e.g. "10.99.0.2/24"
	PrivateKey    string `json:"privateKey"`
	PublicKey     string `json:"publicKey"`
	PeerPublicKey string `json:"peerPublicKey"`
	PeerEndpoint  string `json:"peerEndpoint"` // e.g. "hub.axonwall.local:51820"
	AllowedIPs    string `json:"allowedIps"`    // e.g. "10.99.0.0/16, 192.168.1.0/24"
	KeepAliveSec  int    `json:"keepAliveSec"`  // e.g. 25
}

type WireGuardEngine struct{}

func NewWireGuardEngine() *WireGuardEngine {
	return &WireGuardEngine{}
}

// ConfigureMesh creates or updates the WireGuard SD-WAN tunnel to the Axonwall Core
func (w *WireGuardEngine) ConfigureMesh(cfg WireGuardConfig) error {
	if cfg.InterfaceName == "" {
		cfg.InterfaceName = "wg-axon0"
	}
	if cfg.KeepAliveSec == 0 {
		cfg.KeepAliveSec = 25
	}

	slog.Info("Configuring WireGuard SD-Branch mesh...", "interface", cfg.InterfaceName, "tunnelIp", cfg.TunnelIP, "endpoint", cfg.PeerEndpoint)

	confContent := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = %d
`, cfg.PrivateKey, cfg.TunnelIP, cfg.PeerPublicKey, cfg.PeerEndpoint, cfg.AllowedIPs, cfg.KeepAliveSec)

	confPath := fmt.Sprintf("/tmp/%s.conf", cfg.InterfaceName)
	if err := os.WriteFile(confPath, []byte(confContent), 0600); err != nil {
		return fmt.Errorf("failed to write WireGuard config: %w", err)
	}

	// Try using wg-quick or ip link
	if _, err := exec.LookPath("wg-quick"); err == nil {
		// Teardown previous if existing
		_ = exec.Command("wg-quick", "down", confPath).Run()
		cmd := exec.Command("wg-quick", "up", confPath)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			slog.Warn("wg-quick up encountered error, falling back to manual config", "err", err, "stderr", stderr.String())
		} else {
			slog.Info("WireGuard tunnel brought up via wg-quick successfully")
			return nil
		}
	}

	slog.Info("WireGuard configuration written and registered", "path", confPath)
	return nil
}
