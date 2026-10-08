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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/axonwall/axonwall_monorepo/apps/axonwall-satellite/engine"
)

var (
	coreURL         = flag.String("core", "wss://axonwall.local:8443/ws/satellite", "URL of the Axonwall Core Hub")
	token           = flag.String("token", "", "Zero-Touch Provisioning (ZTP) Token")
	satID           = flag.String("id", "", "Satellite Hardware ID (MAC or Serial)")
	watchdogTimeout = flag.Int("watchdog", 60, "Watchdog timeout in seconds before rolling back nftables")
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

type TelemetryReportPayload struct {
	SatelliteID string                  `json:"satelliteId"`
	Metrics     engine.SatelliteMetrics `json:"metrics"`
}

func main() {
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	slog.Info("Starting Axonwall Satellite Agent", "version", "0.2.0", "id", *satID)

	if *satID == "" || *token == "" {
		slog.Error("Missing required ZTP parameters. Must provide -id and -token.")
		os.Exit(1)
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	certPath := "/etc/axonwall/certs/satellite.crt"
	keyPath := "/etc/axonwall/certs/satellite.key"

	var tlsConfig *tls.Config
	if _, err := os.Stat(certPath); err == nil {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			slog.Error("Failed to load mTLS certificates", "error", err)
			os.Exit(1)
		}
		
		// Note: Requires "crypto/x509" import
		// We will rely on system pool or manual verification if preferred, but let's assume we skip verify
		// if CA is not cleanly set up, or better, we set ServerName
		caCertPool := x509.NewCertPool()
		caCert, err := os.ReadFile("/etc/axonwall/certs/ca.crt")
		if err == nil {
			caCertPool.AppendCertsFromPEM(caCert)
		}
		
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
			InsecureSkipVerify: false,
		}
		slog.Info("Running in secure mTLS mode")
	} else {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true, // For bootstrap; mTLS cert installed post-ZTP
		}
		slog.Warn("Running in ZTP Bootstrap mode with InsecureSkipVerify")
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

	slog.Info("Connecting to Axonwall Core Hub...", "url", u.String())

	c, _, err := dialer.Dial(u.String(), headers)
	if err != nil {
		slog.Error("Failed to connect to core hub", "error", err)
		os.Exit(1)
	}
	defer c.Close()

	nftEngine := engine.NewNftablesEngine()
	wgEngine := engine.NewWireGuardEngine()

	slog.Info("Connected to Axonwall Core Hub. Engines initialized.")

	done := make(chan struct{})
	var lastHeardUnix atomic.Int64
	lastHeardUnix.Store(time.Now().Unix())

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
	defer telemetryTicker.Stop()

	for {
		select {
		case <-done:
			slog.Warn("Core connection closed. Satellite entering autonomous edge mode.")
			return

		case <-telemetryTicker.C:
			// 1. Send Ping
			_ = c.WriteMessage(websocket.PingMessage, []byte{})

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
					_ = c.WriteMessage(websocket.TextMessage, msgBytes)
				}
			}

		case <-interrupt:
			slog.Info("Interrupt received, cleanly disconnecting satellite...")
			_ = c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "agent stopping"))
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}
