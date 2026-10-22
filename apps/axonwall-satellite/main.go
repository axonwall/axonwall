package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/axonwall/axonwall_monorepo/apps/axonwall-satellite/engine"
	"github.com/gorilla/websocket"
)

var (
	coreURL           = flag.String("core", "wss://axonwall.local:2966/ws/satellite", "URL of the Axonwall Core Hub")
	token             = flag.String("token", "", "Zero-Touch Provisioning (ZTP) Token")
	satID             = flag.String("id", "", "Satellite Hardware ID (MAC or Serial)")
	watchdogTimeout   = flag.Int("watchdog", 60, "Watchdog timeout in seconds before rolling back nftables")
	insecureBootstrap = flag.Bool("insecure-bootstrap", false, "INSECURE, provisioning only: skip hub TLS verification when no CA certificate is provisioned. Anyone able to intercept the connection can impersonate the hub, receive the ZTP token, and push arbitrary firewall/WireGuard commands that execute as root.")
)

type EnvelopeMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type NftablesSyncPayload struct {
	Script string `json:"script"`
}

type HeadscaleSyncPayload struct {
	ServerURL string `json:"serverUrl"`
	AuthKey   string `json:"authKey"`
}

type SyncWiFiPayload struct {
	Configs []engine.WiFiConfig `json:"configs"`
}

type BlockTargetPayload struct {
	Target string `json:"target"`
	IsMac  bool   `json:"isMac"`
}

type TelemetryReportPayload struct {
	SatelliteID string                  `json:"satelliteId"`
	Metrics     engine.SatelliteMetrics `json:"metrics"`
}

func main() {
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	slog.Info("Starting Axonwall Satellite Agent", "version", "0.11.8", "id", *satID)

	if *satID == "" || *token == "" {
		slog.Error("Missing required ZTP parameters. Must provide -id and -token.")
		os.Exit(1)
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	certPath := "/etc/axonwall/certs/satellite.crt"
	keyPath := "/etc/axonwall/certs/satellite.key"

	// The hub connection carries the fleet ZTP token and receives
	// nftables/WireGuard commands that execute as root, so hub TLS is
	// verified in every mode by default. When the appliance CA has been
	// provisioned at /etc/axonwall/certs/ca.crt it is pinned as the root
	// pool; otherwise the system roots are used. Skipping verification
	// requires the explicit -insecure-bootstrap opt-in and is intended
	// only for first-boot provisioning on a trusted network: nothing in
	// the ZTP flow installs the client certificate automatically, so
	// the old unconditional bootstrap mode was effectively permanent.
	caCertPool, _ := x509.SystemCertPool()
	if caCert, err := os.ReadFile("/etc/axonwall/certs/ca.crt"); err == nil && len(caCert) > 0 {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(caCert) {
			caCertPool = pool
			slog.Info("Pinning hub TLS verification to the appliance CA", "path", "/etc/axonwall/certs/ca.crt")
		}
	}

	tlsConfig := &tls.Config{RootCAs: caCertPool}
	if _, err := os.Stat(certPath); err == nil {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			slog.Error("Failed to load mTLS certificates", "error", err)
			os.Exit(1)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		slog.Info("Running in secure mTLS mode")
	} else if *insecureBootstrap {
		tlsConfig.RootCAs = nil
		tlsConfig.InsecureSkipVerify = true // explicit operator opt-in, see flag help
		slog.Warn("Running in INSECURE ZTP bootstrap mode: hub TLS is NOT verified (-insecure-bootstrap). A network attacker can impersonate the hub, capture the ZTP token, and push arbitrary firewall/WireGuard configuration.")
	} else {
		slog.Info("Running with verified hub TLS (ZTP token auth; no client certificate provisioned)")
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		HandshakeTimeout: 10 * time.Second,
	}

	u, err := url.Parse(*coreURL)
	if err != nil {
		slog.Error("Invalid core URL", "error", err)
		os.Exit(1)
	}

	headers := make(map[string][]string)
	headers["X-Axonwall-Satellite-ID"] = []string{*satID}
	headers["X-Axonwall-ZTP-Token"] = []string{*token}

	nftEngine := engine.NewNftablesEngine()
	wgEngine := engine.NewWireGuardEngine()
	wifiEngine := engine.NewWiFiEngine()

	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second

	for {
		select {
		case <-interrupt:
			slog.Info("Interrupt received, shutting down satellite...")
			return
		default:
		}

		slog.Info("Connecting to Axonwall Core Hub...", "url", u.String())
		c, _, err := dialer.Dial(u.String(), headers)
		if err != nil {
			slog.Warn("Failed to connect to core hub, retrying...", "error", err, "backoff", backoff)
			select {
			case <-interrupt:
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// Connected successfully: reset backoff
		backoff = 2 * time.Second
		slog.Info("Connected to Axonwall Core Hub. Engines initialized.")

		done := make(chan struct{})
		var lastHeardUnix atomic.Int64
		lastHeardUnix.Store(time.Now().Unix())

		var writeMu sync.Mutex
		writeWS := func(messageType int, data []byte) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			return c.WriteMessage(messageType, data)
		}

		c.SetPongHandler(func(appData string) error {
			lastHeardUnix.Store(time.Now().Unix())
			return nil
		})

		// Watchdog routine: triggers rollback if connectivity to Core is lost
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					elapsed := time.Now().Unix() - lastHeardUnix.Load()
					if elapsed > int64(*watchdogTimeout) {
						slog.Warn("Watchdog triggered: no heartbeat from Core Hub!", "elapsedSeconds", elapsed, "timeout", *watchdogTimeout)
						if err := nftEngine.Rollback(); err != nil {
							slog.Error("Watchdog rollback error", "error", err)
						}
						// Reset lastHeard to prevent continuous rollbacks
						lastHeardUnix.Store(time.Now().Unix())
					}
				}
			}
		}()

		// Incoming message processing loop
		go func() {
			defer close(done)
			for {
				_, rawMsg, err := c.ReadMessage()
				if err != nil {
					slog.Error("Disconnected from Core Hub", "error", err)
					return
				}

				lastHeardUnix.Store(time.Now().Unix())

				var env EnvelopeMessage
				if err := json.Unmarshal(rawMsg, &env); err != nil {
					slog.Error("Malformed envelope received", "error", err)
					continue
				}

				switch env.Type {
				case "SYNC_NFTABLES":
					var p NftablesSyncPayload
					if err := json.Unmarshal(env.Payload, &p); err == nil && p.Script != "" {
						slog.Info("Applying updated nftables ruleset from Core Hub...")
						if err := nftEngine.Apply(p.Script); err != nil {
							slog.Error("Failed to apply nftables script", "error", err)
						} else {
							slog.Info("nftables ruleset applied successfully")
						}
					}

				case "SYNC_WIREGUARD":
					var wgCfg engine.WireGuardConfig
					if err := json.Unmarshal(env.Payload, &wgCfg); err == nil {
						slog.Info("Applying WireGuard mesh tunnel configuration...")
						if err := wgEngine.ConfigureMesh(wgCfg); err != nil {
							slog.Error("Failed to configure WireGuard mesh", "error", err)
						}
					}

				case "SYNC_WIFI":
					var wfCfg SyncWiFiPayload
					if err := json.Unmarshal(env.Payload, &wfCfg); err == nil {
						slog.Info("Applying Wi-Fi radio configurations...")
						for _, c := range wfCfg.Configs {
							if err := wifiEngine.Configure(c); err != nil {
								slog.Error("Failed to configure Wi-Fi radio", "radio", c.Radio, "error", err)
							} else {
								slog.Info("Wi-Fi configured successfully", "radio", c.Radio, "ssid", c.SSID)
							}
						}
					}

				case "SYNC_HEADSCALE":
					var hsCfg HeadscaleSyncPayload
					if err := json.Unmarshal(env.Payload, &hsCfg); err == nil && hsCfg.AuthKey != "" {
						slog.Info("Enrolling in Headscale mesh via tailscaled...", "serverUrl", hsCfg.ServerURL)
						cmd := exec.Command("tailscale", "up", "--login-server="+hsCfg.ServerURL, "--authkey="+hsCfg.AuthKey, "--reset")
						out, err := cmd.CombinedOutput()
						if err != nil {
							slog.Error("Failed to join Headscale mesh", "error", err, "output", string(out))
						} else {
							slog.Info("Successfully joined Headscale mesh!")
						}
					}

				case "BLOCK_TARGET":
					var bp BlockTargetPayload
					if err := json.Unmarshal(env.Payload, &bp); err == nil && bp.Target != "" {
						slog.Info("Received AI Copilot block request...", "target", bp.Target)
						if err := nftEngine.BlockTarget(bp.Target, bp.IsMac); err != nil {
							slog.Error("Failed to apply micro-segmentation block", "error", err)
						}
					}

				case "PING":
					// Heartbeat ack from Hub
					lastHeardUnix.Store(time.Now().Unix())

				default:
					slog.Debug("Unhandled message type", "type", env.Type)
				}
			}
		}()

		// Telemetry & Keepalive loop
		telemetryTicker := time.NewTicker(15 * time.Second)

		sessionActive := true
		for sessionActive {
			select {
			case <-done:
				slog.Warn("Core connection closed. Entering autonomous edge mode and scheduling reconnect...")
				sessionActive = false

			case <-telemetryTicker.C:
				// 1. Send Ping
				_ = writeWS(websocket.PingMessage, []byte{})

				// 2. Gather kernel telemetry and push to Core
				metrics := engine.CollectMetrics()
				report := TelemetryReportPayload{
					SatelliteID: *satID,
					Metrics:     metrics,
				}

				payloadBytes, err := json.Marshal(report)
				if err == nil {
					msg := EnvelopeMessage{
						Type:    "TELEMETRY_REPORT",
						Payload: payloadBytes,
					}
					if msgBytes, err := json.Marshal(msg); err == nil {
						_ = writeWS(websocket.TextMessage, msgBytes)
					}
				}

			case <-interrupt:
				slog.Info("Interrupt received, cleanly disconnecting satellite...")
				_ = writeWS(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "agent stopping"))
				select {
				case <-done:
				case <-time.After(time.Second):
				}
				_ = c.Close()
				telemetryTicker.Stop()
				return
			}
		}

		telemetryTicker.Stop()
		_ = c.Close()
		select {
		case <-interrupt:
			return
		case <-time.After(3 * time.Second):
		}
	}
}
