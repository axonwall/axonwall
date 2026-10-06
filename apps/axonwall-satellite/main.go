package main

import (
	"crypto/tls"
	"flag"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

var (
	coreURL   = flag.String("core", "wss://axonwall.local:8443/ws/satellite", "URL of the Axonwall Core Hub")
	token     = flag.String("token", "", "Zero-Touch Provisioning (ZTP) Token")
	satID     = flag.String("id", "", "Satellite Hardware ID (MAC or Serial)")
)

func main() {
	flag.Parse()

	// Initialize structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	slog.Info("Starting Axonwall Satellite Agent", "version", "0.1.0", "id", *satID)

	if *satID == "" || *token == "" {
		slog.Error("Missing required ZTP parameters. Must provide -id and -token.")
		os.Exit(1)
	}

	// Setup graceful shutdown
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	// In a real mTLS scenario, we would load the client cert here.
	// For ZTP initial enrollment, we skip verification or use a pinned CA.
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // TODO: Replace with pinned CA for ZTP
		},
		HandshakeTimeout: 10 * time.Second,
	}

	u, err := url.Parse(*coreURL)
	if err != nil {
		slog.Error("Invalid core URL", "error", err)
		os.Exit(1)
	}

	// Add ZTP headers
	headers := make(map[string][]string)
	headers["X-Axonwall-Satellite-ID"] = []string{*satID}
	headers["X-Axonwall-ZTP-Token"] = []string{*token}

	slog.Info("Connecting to Axonwall Core...", "url", u.String())

	c, _, err := dialer.Dial(u.String(), headers)
	if err != nil {
		slog.Error("Failed to connect to core", "error", err)
		os.Exit(1)
	}
	defer c.Close()

	slog.Info("Successfully connected to Axonwall Core. Awaiting config...")

	done := make(chan struct{})

	// Read loop (receiving DesiredState configs)
	go func() {
		defer close(done)
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				slog.Error("Read error from core", "error", err)
				return
			}
			slog.Info("Received configuration payload", "size", len(message))
			// TODO: Parse desired state, apply via nftables / iproute2
		}
	}()

	// Main event loop
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			slog.Warn("Core disconnected. Satellite entering autonomous mode.")
			return
		case <-ticker.C:
			// Send heartbeat telemetry
			err := c.WriteMessage(websocket.PingMessage, []byte{})
			if err != nil {
				slog.Error("Failed to send heartbeat", "error", err)
				return
			}
		case <-interrupt:
			slog.Info("Interrupt received, shutting down satellite...")
			
			// Cleanly close the connection by sending a close message
			err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				slog.Error("Error closing connection", "error", err)
				return
			}
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}
