package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
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
	pid1Mode          = flag.Bool("pid1", false, "Force Super-Slim Edge NGFW PID 1 (/init) bootstrap mode")
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

type SyncInterfacesPayload struct {
	Interfaces []engine.EdgeInterfaceSpec `json:"interfaces"`
}

type SyncRoutesPayload struct {
	Routes []engine.EdgeRouteSpec `json:"routes"`
}

type BlockTargetPayload struct {
	Target string `json:"target"`
	IsMac  bool   `json:"isMac"`
}

type TelemetryReportPayload struct {
	SatelliteID string                  `json:"satelliteId"`
	Metrics     engine.SatelliteMetrics `json:"metrics"`
}

// exitOrHalt exits normally, except as PID 1 where exiting would panic the kernel.
func exitOrHalt(code int) {
	if engine.IsPID1() {
		engine.HaltForever("fatal error (exit code " + strconv.Itoa(code) + ")")
	}
	os.Exit(code)
}

func main() {
	flag.Parse()

	// As PID 1, returning from main panics the kernel ("Attempted to kill init!").
	defer func() {
		if engine.IsPID1() {
			engine.HaltForever("main returned")
		}
	}()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	netEngine := engine.NewEdgeNetworkEngine()
	nftEngine := engine.NewNftablesEngine()
	wgEngine := engine.NewWireGuardEngine()
	wifiEngine := engine.NewWiFiEngine()
	flowStreamer := engine.NewEdgeFlowStreamer()

	// Super-Slim Edge NGFW PID 1 (/init) bootstrap
	var bootCfg engine.EdgeBootConfig
	if engine.IsPID1() || *pid1Mode {
		var err error
		bootCfg, err = engine.BootstrapPID1()
		if err != nil {
			slog.Error("PID 1 bootstrap error", "error", err)
		}
		_ = netEngine.BringUpLoopback()

		// If neither /proc/cmdline nor local Cloud-Init cidata specified interfaces,
		// automatically discover the primary NIC (e.g. eth0) and acquire a DHCPv4 lease
		// so the appliance can reach Cloud IMDS (169.254.169.254) and the Axonwall Hub.
		if len(bootCfg.Interfaces) == 0 {
			if primaryNIC := engine.DiscoverPrimaryNIC("/sys/class/net"); primaryNIC != "" {
				slog.Info("No static boot interfaces specified; auto-configuring primary NIC via DHCPv4", "device", primaryNIC)
				bootCfg.Interfaces = append(bootCfg.Interfaces, engine.EdgeInterfaceSpec{
					Name:    "wan",
					Device:  primaryNIC,
					Address: "dhcp",
					MTU:     1500,
					Enabled: true,
				})
			}
		}

		for _, iface := range bootCfg.Interfaces {
			if err := netEngine.ConfigureInterface(iface); err != nil {
				slog.Warn("Boot interface config warning", "device", iface.Device, "error", err)
			}
		}
		for _, rt := range bootCfg.Routes {
			if err := netEngine.AddRoute(rt); err != nil {
				slog.Warn("Boot route config warning", "destination", rt.Destination, "error", err)
			}
		}

		// If local Cloud-Init seed was not present (or did not supply a ZTP token),
		// probe Cloud IMDS HTTP metadata (OpenStack, AWS IMDSv2/v1, GCP, Azure) at 169.254.169.254.
		if bootCfg.CloudInitSource == "" || bootCfg.ZtpToken == "" {
			imdsCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if imdsPayload, ok := engine.FetchIMDSCloudInit(imdsCtx, "http://169.254.169.254"); ok {
				bootCfg.CloudInitSource = imdsPayload.Datasource
				if err := engine.MergeCloudInitIntoBootConfig(&bootCfg, imdsPayload, "/"); err != nil {
					slog.Warn("Cloud-Init IMDS merge warning", "source", imdsPayload.Datasource, "error", err)
				} else {
					slog.Info("Applied autonomous Cloud-Init IMDS configuration", "source", imdsPayload.Datasource, "id", bootCfg.SatelliteID)
					for _, iface := range bootCfg.Interfaces {
						_ = netEngine.ConfigureInterface(iface)
					}
					for _, rt := range bootCfg.Routes {
						_ = netEngine.AddRoute(rt)
					}
				}
			}
			cancel()
		}
	} else if cmdlineBytes, err := os.ReadFile("/proc/cmdline"); err == nil {
		bootCfg = engine.ParseKernelCmdline(string(cmdlineBytes))
	}

	// Apply /proc/cmdline & Cloud-Init parameters when CLI flags were not explicitly set
	if bootCfg.HubURL != "" && *coreURL == "wss://axonwall.local:2966/ws/satellite" {
		*coreURL = bootCfg.HubURL
	}
	if *satID == "" && bootCfg.SatelliteID != "" {
		*satID = bootCfg.SatelliteID
	}
	if *token == "" && bootCfg.ZtpToken != "" {
		*token = bootCfg.ZtpToken
	}
	if bootCfg.WatchdogSec > 0 && *watchdogTimeout == 60 {
		*watchdogTimeout = bootCfg.WatchdogSec
	}
	if !*insecureBootstrap && bootCfg.InsecureBootstrap {
		*insecureBootstrap = true
	}

	// Fallback hardware SatelliteID derived from primary NIC MAC if not explicitly provided
	if *satID == "" {
		if primaryNIC := engine.DiscoverPrimaryNIC("/sys/class/net"); primaryNIC != "" {
			if macBytes, err := os.ReadFile(filepath.Join("/sys/class/net", primaryNIC, "address")); err == nil {
				macClean := strings.ReplaceAll(strings.TrimSpace(string(macBytes)), ":", "")
				if macClean != "" && macClean != "000000000000" {
					*satID = "edge-" + macClean
					slog.Info("Derived deterministic SatelliteID from primary NIC MAC", "id", *satID, "device", primaryNIC)
				}
			}
		}
	}

	if engine.IsPID1() || *pid1Mode {
		// Load Cloud-Init baseline router ruleset (/etc/nftables.conf) if provisioned,
		// falling back to the fail-closed emergency lockdown ruleset before connecting to Hub.
		// Forwarding stays disabled (fail-closed) unless a filtering ruleset loads.
		initialScript := engine.BuildEmergencyLockdownNft(*coreURL)
		if ciNftBytes, err := os.ReadFile("/etc/nftables.conf"); err == nil && strings.Contains(string(ciNftBytes), "chain forward") {
			initialScript = string(ciNftBytes)
			slog.Info("Loading Cloud-Init baseline router nftables ruleset from /etc/nftables.conf")
		}
		if err := nftEngine.Apply(initialScript); err != nil {
			slog.Error("Initial nftables ruleset failed; keeping IP forwarding disabled", "error", err)
			_ = engine.SetForwarding("", false)
		} else {
			nftEngine.Confirm()
			if err := engine.SetForwarding("", true); err != nil {
				slog.Warn("Failed to enable IP forwarding", "error", err)
			}
		}
	}

	slog.Info("Starting Axonwall Satellite / Edge NGFW Agent", "version", "0.11.32", "id", *satID, "pid1", engine.IsPID1() || *pid1Mode)

	if *satID == "" || *token == "" {
		slog.Error("Missing required ZTP parameters. Must provide -id and -token (or axonwall.id / axonwall.token on kernel cmdline).")
		if engine.IsPID1() {
			engine.HaltForever("missing ZTP parameters")
		}
		exitOrHalt(1)
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	kmsgStop := make(chan struct{})
	defer close(kmsgStop)
	flowStreamer.StartKmsgReader(kmsgStop)
	engine.StartHardwareWatchdog(kmsgStop)
	haEngine := engine.NewEdgeHAEngine("hosted", "active")

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
			exitOrHalt(1)
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
		exitOrHalt(1)
	}

	headers := make(map[string][]string)
	headers["X-Axonwall-Satellite-ID"] = []string{*satID}
	headers["X-Axonwall-ZTP-Token"] = []string{*token}

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
							_ = engine.SetForwarding("", true)
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

				case "SYNC_INTERFACES":
					var ifPayload SyncInterfacesPayload
					if err := json.Unmarshal(env.Payload, &ifPayload); err == nil {
						slog.Info("Applying edge network interface configurations...", "count", len(ifPayload.Interfaces))
						for _, iface := range ifPayload.Interfaces {
							if err := netEngine.ConfigureInterface(iface); err != nil {
								slog.Error("Failed to configure edge interface", "device", iface.Device, "error", err)
							}
						}
					}

				case "SYNC_ROUTES":
					var rtPayload SyncRoutesPayload
					if err := json.Unmarshal(env.Payload, &rtPayload); err == nil {
						slog.Info("Applying edge kernel routes...", "count", len(rtPayload.Routes))
						for _, rt := range rtPayload.Routes {
							if err := netEngine.AddRoute(rt); err != nil {
								slog.Error("Failed to add edge route", "destination", rt.Destination, "error", err)
							}
						}
					}

				case "CONFIRM_CONFIG", "CONFIRM_NFTABLES":
					nftEngine.Confirm()
					slog.Info("Confirmed active nftables ruleset as last-known-good")

				case "SYNC_HEADSCALE":
					var hsCfg HeadscaleSyncPayload
					if err := json.Unmarshal(env.Payload, &hsCfg); err == nil && hsCfg.AuthKey != "" {
						hsURL := strings.TrimSpace(hsCfg.ServerURL)
						hsKey := strings.TrimSpace(hsCfg.AuthKey)
						parsedHS, urlErr := url.Parse(hsURL)
						if urlErr != nil || (parsedHS.Scheme != "http" && parsedHS.Scheme != "https") || parsedHS.Host == "" ||
							strings.HasPrefix(hsURL, "-") || strings.ContainsAny(hsURL, " \t\r\n") ||
							strings.HasPrefix(hsKey, "-") || strings.ContainsAny(hsKey, " \t\r\n") {
							slog.Error("Rejected invalid Headscale serverUrl or authKey")
							continue
						}
						slog.Info("Enrolling in Headscale mesh via tailscaled...", "serverUrl", hsURL)
						cmd := exec.Command("tailscale", "up", "--login-server="+hsURL, "--authkey="+hsKey, "--reset")
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

				case "PROMOTE":
					var hp engine.EdgeHATransitionPayload
					_ = json.Unmarshal(env.Payload, &hp)
					if err := haEngine.Promote(netEngine, hp); err != nil {
						slog.Error("Failed to promote Edge NGFW to active", "error", err)
					}

				case "DEMOTE":
					var hp engine.EdgeHATransitionPayload
					_ = json.Unmarshal(env.Payload, &hp)
					if err := haEngine.Demote(netEngine, hp); err != nil {
						slog.Error("Failed to demote Edge NGFW to standby", "error", err)
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

				// 3. Stream stateless conntrack flows & firewall logs to Core Hub (zero local storage)
				flowBatch := flowStreamer.DrainBatch(*satID, 50)
				if len(flowBatch.Flows) > 0 || len(flowBatch.FirewallLogs) > 0 {
					if batchBytes, err := json.Marshal(flowBatch); err == nil {
						flowMsg := EnvelopeMessage{
							Type:    "EDGE_FLOW_BATCH",
							Payload: batchBytes,
						}
						if msgBytes, err := json.Marshal(flowMsg); err == nil {
							_ = writeWS(websocket.TextMessage, msgBytes)
						}
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
