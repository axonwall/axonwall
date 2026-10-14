package engine

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

type WireGuardPeer struct {
	PublicKey    string `json:"publicKey"`
	Endpoint     string `json:"endpoint"`
	AllowedIPs   string `json:"allowedIps"`
	KeepAliveSec int    `json:"keepAliveSec"`
}

type WireGuardConfig struct {
	InterfaceName string          `json:"interfaceName"` // e.g. "wg-axon0"
	TunnelIP      string          `json:"tunnelIp"`      // e.g. "10.99.0.2/24"
	ListenPort    int             `json:"listenPort"`
	PrivateKey    string          `json:"privateKey"`
	Peers         []WireGuardPeer `json:"peers"`
}

type WireGuardEngine struct{}

func NewWireGuardEngine() *WireGuardEngine {
	return &WireGuardEngine{}
}

// ConfigureMesh creates or updates the WireGuard SD-WAN tunnel using wg syncconf
func (w *WireGuardEngine) ConfigureMesh(cfg WireGuardConfig) error {
	if cfg.InterfaceName == "" {
		cfg.InterfaceName = "wg-axon0"
	}
	if !validRadioRegex.MatchString(cfg.InterfaceName) || strings.Contains(cfg.InterfaceName, "..") || strings.Contains(cfg.InterfaceName, "/") || strings.HasPrefix(cfg.InterfaceName, "-") {
		return fmt.Errorf("invalid wireguard interface name: %s", cfg.InterfaceName)
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 51820
	}

	importStrings := []string{cfg.InterfaceName, cfg.TunnelIP, cfg.PrivateKey}
	for _, p := range cfg.Peers {
		importStrings = append(importStrings, p.PublicKey, p.Endpoint, p.AllowedIPs)
	}

	for _, s := range importStrings {
		if bytes.Contains([]byte(s), []byte("\n")) || bytes.Contains([]byte(s), []byte("\r")) {
			return fmt.Errorf("invalid wireguard configuration: newlines are not allowed")
		}
	}

	slog.Info("Configuring WireGuard SD-Branch mesh...", "interface", cfg.InterfaceName, "tunnelIp", cfg.TunnelIP, "peers", len(cfg.Peers))

	var wgQuickConf bytes.Buffer
	wgQuickConf.WriteString(fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nListenPort = %d\n\n", cfg.PrivateKey, cfg.TunnelIP, cfg.ListenPort))

	var wgSyncConf bytes.Buffer
	wgSyncConf.WriteString(fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = %d\n\n", cfg.PrivateKey, cfg.ListenPort))

	for _, p := range cfg.Peers {
		keepAlive := p.KeepAliveSec
		if keepAlive == 0 {
			keepAlive = 25
		}
		
		peerSection := fmt.Sprintf("[Peer]\nPublicKey = %s\nAllowedIPs = %s\nPersistentKeepalive = %d\n", p.PublicKey, p.AllowedIPs, keepAlive)
		if p.Endpoint != "" {
			peerSection += fmt.Sprintf("Endpoint = %s\n", p.Endpoint)
		}
		peerSection += "\n"
		
		wgQuickConf.WriteString(peerSection)
		wgSyncConf.WriteString(peerSection)
	}

	confPath := fmt.Sprintf("/etc/wireguard/%s.conf", cfg.InterfaceName)
	syncConfPath := fmt.Sprintf("/etc/wireguard/%s.sync.conf", cfg.InterfaceName)

	if err := os.MkdirAll("/etc/wireguard", 0700); err != nil {
		return fmt.Errorf("failed to create /etc/wireguard: %w", err)
	}

	if err := os.WriteFile(confPath, wgQuickConf.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write WireGuard wg-quick config: %w", err)
	}
	if err := os.WriteFile(syncConfPath, wgSyncConf.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write WireGuard sync config: %w", err)
	}

	// Check if interface exists
	if err := exec.Command("ip", "link", "show", cfg.InterfaceName).Run(); err != nil {
		// Interface does not exist, use wg-quick up
		slog.Info("WireGuard interface not found, bringing up via wg-quick")
		cmd := exec.Command("wg-quick", "up", confPath)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("wg-quick up failed: %w, stderr: %s", err, stderr.String())
		}
	} else {
		// Interface exists, use wg syncconf
		slog.Info("WireGuard interface exists, synchronizing config via wg syncconf")
		cmd := exec.Command("wg", "syncconf", cfg.InterfaceName, syncConfPath)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("wg syncconf failed: %w, stderr: %s", err, stderr.String())
		}
	}

	slog.Info("WireGuard mesh synchronized successfully")
	return nil
}
