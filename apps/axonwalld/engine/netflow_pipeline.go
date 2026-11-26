package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type listenerRuntime struct {
	cfg           NetFlowListenerPayload
	listening     atomic.Bool
	pktsReceived  atomic.Uint64
	decodeErrs    atomic.Uint64
	droppedUnkT   atomic.Uint64
	lastErrMu     sync.Mutex
	lastError     string
	udpConn       net.PacketConn
	udpConns      []net.PacketConn
	tcpListener   net.Listener
	allowedCidrs  []netip.Prefix
	stopCh        chan struct{}
}

type exporterCounterState struct {
	bytes   uint64
	packets uint64
}

type exporterTracker struct {
	ip          string
	lastSeenMs  int64
	versions    map[string]bool
	packets     uint64
	flows       uint64
	bytes       uint64
	winStartMs  int64
	winFlows    uint64
	winBytes    uint64
	fps         float64
	bps         float64
	interfaces  map[uint32]ExporterInterfaceCounter
}

type alertWindowTrack struct {
	windowStartMs int64
	bytesByIP     map[string]uint64
	pktsByIP      map[string]uint64
	synByIP       map[string]uint64
	portsByIP     map[string]map[uint16]struct{}
	dstsByIP      map[string]map[string]struct{}
	egressByIP    map[string]uint64
	flowsByPair   map[string]int
}

type NetFlowManager struct {
	mu           sync.RWMutex
	baseDir      string
	bundle       *NetFlowRuntimeBundle
	running      bool
	stopCh       chan struct{}
	wg           sync.WaitGroup

	ebpf      *EBPFManager
	vigilante *VigilanteManager
	k3s       *K3sManager
	netbox    *NetBoxManager
	librenms  *LibreNMSManager
	topology  *TopologyManager

	decoder   *FlowDecoder
	enricher  *FlowEnricher
	store     *FlowStore
	baselines *BaselineEngine
	spoofWarn atomic.Bool

	listeners  []*listenerRuntime
	exporters  map[string]*exporterTracker
	exportersMu sync.RWMutex

	selfPrevByTarget map[string]map[string]exporterCounterState
	selfSeq          atomic.Uint32
	selfLastTmpl     map[string]time.Time
	targetConnsMu    sync.Mutex
	targetConns      map[string]net.Conn
	inboundMu        sync.Mutex
	inboundClosed    bool
	inboundConns     map[net.Conn]struct{}
	metaMu           sync.Mutex
	metaClient       *http.Client
	metaTransport    *http.Transport
	metaClientKey    string
	exportQueue      *TelemetryQueue

	replMu    sync.RWMutex
	replConns map[string]*net.UDPConn
	replRate  map[string]*replRateBucket

	alertMu       sync.Mutex
	alerts        []FlowAlertEvent
	alertCooldown map[string]int64 // ruleID|culpritIP -> unixMs
	alertWindows  map[string]*alertWindowTrack

	sseMu   sync.Mutex
	sseSubs map[chan FlowRecord]struct{}

	totalPktsRecv    atomic.Uint64
	totalFlowsIngest atomic.Uint64
	totalBytesIngest atomic.Uint64
	totalReplicated  atomic.Uint64
	totalSelfExport  atomic.Uint64
	totalDecodeErrs  atomic.Uint64
	lastErr          atomic.Value
}

type replRateBucket struct {
	secStart int64
	count    int
}

func NewNetFlowManager(
	baseDir string,
	ebpf *EBPFManager,
	vigilante *VigilanteManager,
	k3s *K3sManager,
	netbox *NetBoxManager,
	librenms *LibreNMSManager,
) *NetFlowManager {
	if baseDir == "" {
		baseDir = "/etc/axonwall/netflow"
	}
	return &NetFlowManager{
		baseDir:       baseDir,
		ebpf:          ebpf,
		vigilante:     vigilante,
		k3s:           k3s,
		netbox:        netbox,
		librenms:      librenms,
		decoder:       NewFlowDecoder(),
		enricher:      NewFlowEnricher(k3s, netbox, librenms),
		store:         NewFlowStore(NetFlowStoragePayload{}),
		baselines:        NewBaselineEngine("/var/lib/axonwall/netflow"),
		exporters:        make(map[string]*exporterTracker),
		selfPrevByTarget: make(map[string]map[string]exporterCounterState),
		selfLastTmpl:     make(map[string]time.Time),
		targetConns:      make(map[string]net.Conn),
		inboundConns:     make(map[net.Conn]struct{}),
		exportQueue:      NewTelemetryQueue("netflow-export", 24, false, "/var/lib/axonwall/telemetry-spool", 256),
		replConns:        make(map[string]*net.UDPConn),
		replRate:      make(map[string]*replRateBucket),
		alertCooldown: make(map[string]int64),
		alertWindows:  make(map[string]*alertWindowTrack),
		sseSubs:       make(map[chan FlowRecord]struct{}),
	}
}

func (m *NetFlowManager) SetTopologyManager(tm *TopologyManager) {
	m.mu.Lock()
	m.topology = tm
	m.mu.Unlock()
}

func (m *NetFlowManager) ApplyConfig(rawJSON []byte) error {
	var bundle NetFlowRuntimeBundle
	if err := json.Unmarshal(rawJSON, &bundle); err != nil {
		return fmt.Errorf("invalid netflow_config.json bundle: %w", err)
	}

	m.mu.Lock()
	prev := m.bundle
	if prev != nil {
		if bundle.Config.Storage.ClickHouse.Password == netflowMaskedPlaceholder {
			bundle.Config.Storage.ClickHouse.Password = prev.Config.Storage.ClickHouse.Password
		}
		if bundle.Config.Reporting.WebhookURL == netflowMaskedPlaceholder {
			bundle.Config.Reporting.WebhookURL = prev.Config.Reporting.WebhookURL
		}
		if bundle.Config.Enrichment.GeoIPCityDownloadURL == netflowMaskedPlaceholder {
			bundle.Config.Enrichment.GeoIPCityDownloadURL = prev.Config.Enrichment.GeoIPCityDownloadURL
		}
		if bundle.Config.Enrichment.GeoIPAsnDownloadURL == netflowMaskedPlaceholder {
			bundle.Config.Enrichment.GeoIPAsnDownloadURL = prev.Config.Enrichment.GeoIPAsnDownloadURL
		}
		prevWh := make(map[string]string)
		for _, r := range prev.Config.Alerting.Rules {
			if r.ID != "" && r.WebhookURL != "" {
				prevWh[r.ID] = r.WebhookURL
			}
		}
		for i := range bundle.Config.Alerting.Rules {
			if bundle.Config.Alerting.Rules[i].WebhookURL == netflowMaskedPlaceholder {
				bundle.Config.Alerting.Rules[i].WebhookURL = prevWh[bundle.Config.Alerting.Rules[i].ID]
			}
		}
	}
	m.bundle = &bundle
	m.mu.Unlock()

	if m.baseDir != "" {
		_ = os.MkdirAll(m.baseDir, 0750)
		_ = os.WriteFile(filepath.Join(m.baseDir, "runtime_bundle.json"), rawJSON, 0600)
	}

	m.Stop()
	bufMB := bundle.Buffer.MaxMemoryMB
	if bufMB <= 0 {
		bufMB = 24
	}
	m.exportQueue.Configure(bufMB, bundle.Buffer.DiskSpoolEnabled, bundle.Buffer.DiskSpoolDir, bundle.Buffer.DiskSpoolMaxMB)
	if !isExporterOnlyMode(&bundle) {
		m.enricher.UpdateBundle(&bundle)
		m.store.Configure(bundle.Config.Storage)
		m.baselines.SetDataDir(bundle.Config.Storage.DataDir)
	}

	if !bundle.Enabled {
		return nil
	}
	return m.Start()
}

func isExporterOnlyMode(b *NetFlowRuntimeBundle) bool {
	if b == nil {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(b.Mode))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(b.Config.Mode))
	}
	return mode == "exporter"
}

const netflowMaskedPlaceholder = "********"

func (m *NetFlowManager) SetEnabled(enabled bool) error {
	m.mu.Lock()
	if m.bundle == nil {
		m.bundle = &NetFlowRuntimeBundle{
			Enabled: enabled,
			Config: NetFlowConfigPayload{
				Enabled: enabled,
				Listeners: []NetFlowListenerPayload{
					{
						ID:                 "default-auto-2055",
						Name:               "Primary Multi-Protocol",
						Enabled:            true,
						Protocol:           "auto",
						Transport:          "udp",
						BindAddress:        "0.0.0.0",
						Port:               2055,
						SocketRecvBufferKB: 8192,
						Workers:            2,
					},
				},
				Storage: NetFlowStoragePayload{
					Mode:             "local",
					DataDir:          "/var/lib/axonwall/netflow",
					RetentionHours:   168,
					MaxDiskMB:        4096,
					HotRingSize:      50000,
					FlushIntervalSec: 15,
					Compression:      "zstd",
				},
			},
		}
	} else {
		m.bundle.Enabled = enabled
		m.bundle.Config.Enabled = enabled
	}
	b := m.bundle
	m.mu.Unlock()

	m.Stop()
	if !enabled {
		return nil
	}
	if !isExporterOnlyMode(b) {
		m.enricher.UpdateBundle(b)
		m.store.Configure(b.Config.Storage)
	}
	return m.Start()
}

func (m *NetFlowManager) Start() error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	if m.bundle == nil || !m.bundle.Enabled {
		m.mu.Unlock()
		return nil
	}
	bundle := m.bundle
	cfg := bundle.Config
	exporterOnly := isExporterOnlyMode(bundle)
	stopCh := make(chan struct{})
	m.stopCh = stopCh
	m.running = true
	m.listeners = nil
	m.mu.Unlock()

	m.inboundMu.Lock()
	m.inboundClosed = false
	if m.inboundConns == nil {
		m.inboundConns = make(map[net.Conn]struct{})
	}
	m.inboundMu.Unlock()

	if exporterOnly {
		// Edge exporter-only mode: zero listeners, zero local ClickHouse/chunk/baseline/enrichment overhead
		m.wg.Add(2)
		go m.selfExportLoop(stopCh)
		go m.metadataSyncLoop(stopCh)
		return nil
	}

	for _, lCfg := range cfg.Listeners {
		if !lCfg.Enabled {
			continue
		}
		rt := m.startListener(lCfg, stopCh)
		m.mu.Lock()
		m.listeners = append(m.listeners, rt)
		m.mu.Unlock()
	}

	// Background loops: storage flusher, external cache refresher, self-exporter, scheduled reporter, metadata sync
	m.wg.Add(5)
	go m.flushLoop(stopCh, cfg.Storage.FlushIntervalSec)
	go m.enrichmentLoop(stopCh)
	go m.selfExportLoop(stopCh)
	go m.reportingLoop(stopCh)
	go m.metadataSyncLoop(stopCh)

	return nil
}

func (m *NetFlowManager) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	stopCh := m.stopCh
	listeners := m.listeners
	m.listeners = nil
	m.running = false
	m.mu.Unlock()

	close(stopCh)
	for _, l := range listeners {
		if l.udpConn != nil {
			_ = l.udpConn.Close()
		}
		for _, uc := range l.udpConns {
			_ = uc.Close()
		}
		if l.tcpListener != nil {
			_ = l.tcpListener.Close()
		}
	}
	m.replMu.Lock()
	for k, c := range m.replConns {
		_ = c.Close()
		delete(m.replConns, k)
	}
	m.replMu.Unlock()
	m.closeAllTargetConns()
	m.closeAllInboundConns()
	m.closeMetaHTTPClient()

	m.wg.Wait()
	m.mu.RLock()
	exporterOnly := isExporterOnlyMode(m.bundle)
	m.mu.RUnlock()
	if !exporterOnly {
		_ = m.store.Flush()
		_ = m.baselines.Save("")
	}
}

func (m *NetFlowManager) closeAllTargetConns() {
	m.targetConnsMu.Lock()
	defer m.targetConnsMu.Unlock()
	for k, c := range m.targetConns {
		_ = c.Close()
		delete(m.targetConns, k)
	}
}

func buildTLSConfigFromBundleParams(useHaPki bool, caCertOrPath, certPath, keyPath, serverName string, insecureSkipVerify, requireClientCert, isServer bool) (*tls.Config, error) {
	var cfg *tls.Config
	var err error
	if useHaPki || (certPath == "" && caCertOrPath == "") {
		cfg, err = LoadHAPKITLSConfig()
	} else if strings.Contains(caCertOrPath, "BEGIN CERTIFICATE") {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caCertOrPath)) {
			return nil, errors.New("invalid inline TLS CA PEM")
		}
		cfg = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
		if certPath != "" && keyPath != "" {
			if cert, cerr := tls.LoadX509KeyPair(certPath, keyPath); cerr == nil {
				cfg.Certificates = []tls.Certificate{cert}
			}
		}
	} else {
		cfg, err = LoadHAPKITLSConfigFromPaths(caCertOrPath, certPath, keyPath)
	}
	if err != nil {
		if insecureSkipVerify && !isServer {
			return &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true, //nolint:gosec
				ServerName:         serverName,
			}, nil
		}
		return nil, err
	}
	cloned := cfg.Clone()
	cloned.MinVersion = tls.VersionTLS13
	if serverName != "" {
		cloned.ServerName = serverName
	}
	if insecureSkipVerify && !isServer {
		cloned.InsecureSkipVerify = true //nolint:gosec
	}
	if isServer {
		if !requireClientCert {
			cloned.ClientAuth = tls.VerifyClientCertIfGiven
		} else {
			cloned.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	return cloned, nil
}

func buildNetFlowTLSConfig(tlsCfg *NetFlowTlsConfigPayload, isServer bool) (*tls.Config, error) {
	if tlsCfg == nil {
		return buildTLSConfigFromBundleParams(true, "", "", "", "", false, true, isServer)
	}
	return buildTLSConfigFromBundleParams(
		tlsCfg.UseHaPki,
		tlsCfg.CAPath,
		tlsCfg.CertPath,
		tlsCfg.KeyPath,
		tlsCfg.ServerName,
		tlsCfg.InsecureSkipVerify,
		tlsCfg.RequireClientCert,
		isServer,
	)
}

func (m *NetFlowManager) startListener(cfg NetFlowListenerPayload, stopCh chan struct{}) *listenerRuntime {
	rt := &listenerRuntime{
		cfg:    cfg,
		stopCh: stopCh,
	}
	for _, cidr := range cfg.AllowedExporters {
		raw := strings.TrimSpace(cidr)
		if !strings.Contains(raw, "/") {
			if addr, err := netip.ParseAddr(raw); err == nil {
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				rt.allowedCidrs = append(rt.allowedCidrs, netip.PrefixFrom(addr, bits))
			}
		} else if p, err := netip.ParsePrefix(raw); err == nil {
			rt.allowedCidrs = append(rt.allowedCidrs, p)
		}
	}

	addr := net.JoinHostPort(cfg.BindAddress, strconv.Itoa(cfg.Port))
	if cfg.Transport == "tcp" || cfg.Transport == "tls" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			rt.setErr(err.Error())
			m.lastErr.Store(err.Error())
			return rt
		}
		if cfg.Transport == "tls" {
			tlsConf, terr := buildNetFlowTLSConfig(cfg.TLS, true)
			if terr != nil {
				_ = ln.Close()
				rt.setErr("TLS 1.3 mTLS init failed: " + terr.Error())
				m.lastErr.Store(terr.Error())
				return rt
			}
			ln = tls.NewListener(ln, tlsConf)
		}
		rt.tcpListener = ln
		rt.listening.Store(true)
		m.wg.Add(1)
		go m.serveTCP(rt)
		return rt
	}

	workers := cfg.Workers
	if workers <= 0 {
		workers = 2
	}
	if workers > 16 {
		workers = 16
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			_ = c.Control(func(fd uintptr) {
				if workers > 1 {
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				}
				if cfg.SocketRecvBufferKB > 0 {
					_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, cfg.SocketRecvBufferKB*1024)
				}
			})
			return nil
		},
	}
	for w := 0; w < workers; w++ {
		pc, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			if len(rt.udpConns) > 0 {
				// SO_REUSEPORT unsupported on secondary socket: share first socket across remaining workers
				break
			}
			rt.setErr(err.Error())
			m.lastErr.Store(err.Error())
			return rt
		}
		rt.udpConns = append(rt.udpConns, pc)
	}
	rt.udpConn = rt.udpConns[0]
	rt.listening.Store(true)

	for w := 0; w < workers; w++ {
		conn := rt.udpConns[w%len(rt.udpConns)]
		m.wg.Add(1)
		go m.serveUDP(rt, conn)
	}
	return rt
}

func (rt *listenerRuntime) setErr(msg string) {
	rt.lastErrMu.Lock()
	rt.lastError = msg
	rt.lastErrMu.Unlock()
}

func (rt *listenerRuntime) exporterAllowed(ip string) bool {
	if len(rt.allowedCidrs) == 0 {
		return true
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range rt.allowedCidrs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (m *NetFlowManager) serveUDP(rt *listenerRuntime, conn net.PacketConn) {
	defer m.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-rt.stopCh:
				return
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				rt.setErr(err.Error())
				return
			}
		}
		if n <= 0 || remote == nil {
			continue
		}
		exporterIP := extractRemoteIP(remote.String())
		if !rt.exporterAllowed(exporterIP) {
			continue
		}
		pktCopy := make([]byte, n)
		copy(pktCopy, buf[:n])
		m.processPacket(rt, exporterIP, pktCopy)
	}
}

func (m *NetFlowManager) registerInboundConn(c net.Conn) bool {
	m.inboundMu.Lock()
	defer m.inboundMu.Unlock()
	if m.inboundClosed {
		return false
	}
	if m.inboundConns == nil {
		m.inboundConns = make(map[net.Conn]struct{})
	}
	m.inboundConns[c] = struct{}{}
	return true
}

func (m *NetFlowManager) unregisterInboundConn(c net.Conn) {
	m.inboundMu.Lock()
	delete(m.inboundConns, c)
	m.inboundMu.Unlock()
}

func (m *NetFlowManager) closeAllInboundConns() {
	m.inboundMu.Lock()
	m.inboundClosed = true
	conns := make([]net.Conn, 0, len(m.inboundConns))
	for c := range m.inboundConns {
		conns = append(conns, c)
	}
	m.inboundConns = make(map[net.Conn]struct{})
	m.inboundMu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (m *NetFlowManager) serveTCP(rt *listenerRuntime) {
	defer m.wg.Done()
	for {
		conn, err := rt.tcpListener.Accept()
		if err != nil {
			select {
			case <-rt.stopCh:
				return
			default:
				rt.setErr(err.Error())
				return
			}
		}
		exporterIP := extractRemoteIP(conn.RemoteAddr().String())
		if !rt.exporterAllowed(exporterIP) {
			_ = conn.Close()
			continue
		}
		if !m.registerInboundConn(conn) {
			_ = conn.Close()
			return
		}
		m.wg.Add(1)
		go func(c net.Conn, exp string) {
			defer m.wg.Done()
			defer m.unregisterInboundConn(c)
			defer c.Close()
			hdr := make([]byte, 4)
			for {
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Minute))
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				ver := binary.BigEndian.Uint16(hdr[0:2])
				msgLen := int(binary.BigEndian.Uint16(hdr[2:4]))
				// For IPFIX over TCP bytes[2:4] is total message length (>=16); read remaining
				if ver == 10 && msgLen >= 16 && msgLen <= 65535 {
					pkt := make([]byte, msgLen)
					copy(pkt[:4], hdr)
					if _, err := io.ReadFull(c, pkt[4:]); err != nil {
						return
					}
					m.processPacket(rt, exp, pkt)
					continue
				}
				// Fallback newline/frame read
				_ = hdr
				return
			}
		}(conn, exporterIP)
	}
}

func (m *NetFlowManager) processPacket(rt *listenerRuntime, exporterIP string, raw []byte) {
	now := time.Now()
	rt.pktsReceived.Add(1)
	m.totalPktsRecv.Add(1)

	ver, flows, counters, err := m.decoder.DecodePacket(exporterIP, raw, now)
	if err != nil {
		rt.decodeErrs.Add(1)
		m.totalDecodeErrs.Add(1)
		rt.setErr(err.Error())
		return
	}

	if rt.cfg.Protocol != "auto" && rt.cfg.Protocol != "" {
		if rt.cfg.Protocol == "ipfix" && ver != "ipfix" {
			return
		}
		if rt.cfg.Protocol == "sflow" && ver != "sflow5" {
			return
		}
		if rt.cfg.Protocol == "netflow" && ver != "netflow5" && ver != "netflow9" {
			return
		}
	}

	// Fan-out raw datagram replication before mutating records
	m.replicateDatagram(exporterIP, ver, raw)

	m.mu.RLock()
	bundle := m.bundle
	m.mu.RUnlock()

	var expProfile *NetFlowExporterProfilePayload
	if bundle != nil {
		for i := range bundle.Config.ExporterProfiles {
			if bundle.Config.ExporterProfiles[i].IP == exporterIP {
				expProfile = &bundle.Config.ExporterProfiles[i]
				break
			}
		}
	}

	if expProfile != nil && !expProfile.Enabled {
		return
	}

	var totalBytes uint64
	for i := range flows {
		if expProfile != nil {
			flows[i].ExporterName = expProfile.Name
			if expProfile.SamplingRateOverride > 1 && flows[i].SamplingRate <= 1 {
				flows[i].Bytes *= uint64(expProfile.SamplingRateOverride)
				flows[i].Packets *= uint64(expProfile.SamplingRateOverride)
				flows[i].SamplingRate = uint32(expProfile.SamplingRateOverride)
			}
		}
		m.enricher.Enrich(&flows[i])
		totalBytes += flows[i].Bytes
	}

	m.recordExporterActivity(exporterIP, expProfile, ver, len(flows), totalBytes, counters)

	if len(flows) > 0 {
		m.totalFlowsIngest.Add(uint64(len(flows)))
		m.totalBytesIngest.Add(totalBytes)
		m.store.Ingest(flows)
		m.broadcastSSE(flows)
		m.evaluateAlerts(flows)
	}
}

func (m *NetFlowManager) recordExporterActivity(
	exporterIP string,
	profile *NetFlowExporterProfilePayload,
	ver string,
	flowCount int,
	bytes uint64,
	counters []ExporterInterfaceCounter,
) {
	nowMs := time.Now().UnixMilli()
	m.exportersMu.Lock()
	defer m.exportersMu.Unlock()

	tr := m.exporters[exporterIP]
	if tr == nil {
		name := exporterIP
		vendor := "other"
		site := ""
		if profile != nil {
			name = profile.Name
			vendor = profile.Vendor
			site = profile.Site
		} else if exporterIP == "127.0.0.1" || exporterIP == "::1" {
			name = "Local Axonwall Appliance"
			vendor = "axonwall"
		}
		if len(m.exporters) >= 1024 {
			var oldestIP string
			var oldestSeen int64
			first := true
			for ip, cur := range m.exporters {
				if first || cur.lastSeenMs < oldestSeen {
					oldestIP = ip
					oldestSeen = cur.lastSeenMs
					first = false
				}
			}
			if !first {
				delete(m.exporters, oldestIP)
			}
		}
		tr = &exporterTracker{
			ip:         exporterIP,
			versions:   make(map[string]bool),
			winStartMs: nowMs,
			interfaces: make(map[uint32]ExporterInterfaceCounter),
		}
		m.exporters[exporterIP] = tr
		_ = name
		_ = vendor
		_ = site
	}
	tr.lastSeenMs = nowMs
	tr.versions[ver] = true
	tr.packets++
	tr.flows += uint64(flowCount)
	tr.bytes += bytes
	tr.winFlows += uint64(flowCount)
	tr.winBytes += bytes

	elapsed := float64(nowMs-tr.winStartMs) / 1000.0
	if elapsed >= 5.0 {
		tr.fps = float64(tr.winFlows) / elapsed
		tr.bps = float64(tr.winBytes*8) / elapsed
		if elapsed >= 30.0 {
			tr.winStartMs = nowMs
			tr.winFlows = 0
			tr.winBytes = 0
		}
	}
	for _, c := range counters {
		tr.interfaces[c.IfIndex] = c
	}
}

func (m *NetFlowManager) replicateDatagram(exporterIP, ver string, raw []byte) {
	m.mu.RLock()
	bundle := m.bundle
	m.mu.RUnlock()
	if bundle == nil || !bundle.Config.Replicator.Enabled || len(bundle.Config.Replicator.Targets) == 0 {
		return
	}

	nowSec := time.Now().Unix()
	for _, tgt := range bundle.Config.Replicator.Targets {
		if !tgt.Enabled || tgt.DestinationHost == "" || tgt.DestinationPort <= 0 {
			continue
		}
		if len(tgt.FilterExporters) > 0 {
			ok := false
			for _, fexp := range tgt.FilterExporters {
				if strings.TrimSpace(fexp) == exporterIP {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		if len(tgt.FilterProtocols) > 0 {
			ok := false
			for _, fp := range tgt.FilterProtocols {
				if fp == ver {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		if tgt.RateLimitPps > 0 {
			m.replMu.Lock()
			rb := m.replRate[tgt.ID]
			if rb == nil || rb.secStart != nowSec {
				rb = &replRateBucket{secStart: nowSec}
				m.replRate[tgt.ID] = rb
			}
			allowed := rb.count < tgt.RateLimitPps
			if allowed {
				rb.count++
			}
			m.replMu.Unlock()
			if !allowed {
				continue
			}
		}

		if tgt.SpoofSourceIP {
			if err := sendSpoofedUDP(exporterIP, tgt.DestinationHost, tgt.DestinationPort, raw); err == nil {
				m.totalReplicated.Add(1)
				continue
			} else if !m.spoofWarn.Swap(true) {
				log.Printf("[NetFlow] Raw-socket source spoof unavailable (%v); falling back to standard UDP replication", err)
			}
		}

		m.replMu.RLock()
		conn := m.replConns[tgt.ID]
		m.replMu.RUnlock()
		if conn == nil {
			rAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(tgt.DestinationHost, strconv.Itoa(tgt.DestinationPort)))
			if err != nil {
				continue
			}
			c, err := net.DialUDP("udp", nil, rAddr)
			if err != nil {
				continue
			}
			m.replMu.Lock()
			m.replConns[tgt.ID] = c
			m.replMu.Unlock()
			conn = c
		}
		if _, err := conn.Write(raw); err == nil {
			m.totalReplicated.Add(1)
		}
	}
}

func sendSpoofedUDP(srcIPStr, dstHost string, dstPort int, payload []byte) error {
	srcIP := net.ParseIP(srcIPStr).To4()
	if srcIP == nil {
		return errors.New("source spoof requires IPv4 exporter address")
	}
	ips, err := net.LookupIP(dstHost)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("resolving replicator target %s: %w", dstHost, err)
	}
	var dstIP net.IP
	for _, cand := range ips {
		if v4 := cand.To4(); v4 != nil {
			dstIP = v4
			break
		}
	}
	if dstIP == nil {
		return errors.New("replicator destination has no IPv4 address")
	}
	totalLen := 20 + 8 + len(payload)
	if totalLen > 65535 {
		return errors.New("spoofed UDP packet too large")
	}
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], uint16(time.Now().UnixNano()&0xFFFF))
	pkt[8] = 64
	pkt[9] = 17 // UDP
	copy(pkt[12:16], srcIP)
	copy(pkt[16:20], dstIP)
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))

	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:2], uint16(dstPort))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return err
	}
	var sa4 unix.SockaddrInet4
	sa4.Port = dstPort
	copy(sa4.Addr[:], dstIP)
	return unix.Sendto(fd, pkt, 0, &sa4)
}

func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (m *NetFlowManager) flushLoop(stopCh chan struct{}, flushSec int) {
	defer m.wg.Done()
	if flushSec < 5 {
		flushSec = 15
	}
	tk := time.NewTicker(time.Duration(flushSec) * time.Second)
	defer tk.Stop()
	lastBaselineSave := time.Now()
	for {
		select {
		case <-stopCh:
			return
		case <-tk.C:
			if err := m.store.Flush(); err != nil {
				log.Printf("[NetFlow] Storage flush warning: %v", err)
			}
			m.evaluateSilentExporters()
			if time.Since(lastBaselineSave) >= 5*time.Minute {
				lastBaselineSave = time.Now()
				_ = m.baselines.Save("")
			}
		}
	}
}

func (m *NetFlowManager) evaluateSilentExporters() {
	m.mu.RLock()
	bundle := m.bundle
	m.mu.RUnlock()
	if bundle == nil || !bundle.Enabled || !bundle.Config.Alerting.Enabled {
		return
	}

	nowMs := time.Now().UnixMilli()
	m.exportersMu.RLock()
	lastSeenMap := make(map[string]int64, len(m.exporters))
	for ip, tr := range m.exporters {
		lastSeenMap[ip] = tr.lastSeenMs
	}
	m.exportersMu.RUnlock()

	m.alertMu.Lock()
	defer m.alertMu.Unlock()
	for _, rule := range bundle.Config.Alerting.Rules {
		if !rule.Enabled || rule.Kind != "exporter_silent" {
			continue
		}
		silenceMs := int64(maxInt(30, rule.WindowSec)) * 1000
		for _, prof := range bundle.Config.ExporterProfiles {
			if !prof.Enabled || prof.IP == "" {
				continue
			}
			lastMs, seen := lastSeenMap[prof.IP]
			if seen && nowMs-lastMs >= silenceMs {
				m.triggerRuleAlertLocked(
					rule,
					prof.IP,
					prof.IP,
					float64((nowMs-lastMs)/1000),
					fmt.Sprintf("Configured exporter %s (%s) silent for %ds", prof.Name, prof.IP, (nowMs-lastMs)/1000),
					nowMs,
				)
			}
		}
	}
}

func (m *NetFlowManager) enrichmentLoop(stopCh chan struct{}) {
	defer m.wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	m.enricher.RefreshExternalCaches(ctx)
	cancel()

	tk := time.NewTicker(60 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-tk.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			m.enricher.RefreshExternalCaches(ctx)
			cancel()
		}
	}
}

func (m *NetFlowManager) selfExportLoop(stopCh chan struct{}) {
	defer m.wg.Done()
	tk := time.NewTicker(5 * time.Second)
	defer tk.Stop()
	lastTargetExport := make(map[string]time.Time)

	for {
		select {
		case <-stopCh:
			return
		case now := <-tk.C:
			m.mu.RLock()
			bundle := m.bundle
			m.mu.RUnlock()
			if bundle == nil || !bundle.Enabled || !bundle.Config.SelfExport.Enabled {
				continue
			}

			// First drain any buffered unsent packets for enabled targets when collector recovers
			m.drainQueuedExportPackets(bundle)

			rawFlows := m.sampleRawLocalFlows()
			if len(rawFlows) == 0 {
				continue
			}
			localIfaces, ifNameByIdx := collectLocalInterfaceSnapshot(bundle)
			nodeID := strings.TrimSpace(bundle.NodeID)
			if nodeID == "" {
				nodeID = strings.TrimSpace(bundle.Config.NodeID)
			}
			if nodeID == "" {
				nodeID = bundle.LocalHostname
			}

			for _, tgt := range bundle.Config.SelfExport.Targets {
				if !tgt.Enabled || tgt.Host == "" || tgt.Port <= 0 {
					continue
				}
				activeSec := maxInt(5, tgt.ActiveTimeoutSec)
				if activeSec > 300 {
					activeSec = 300
				}
				minInterval := time.Duration(activeSec) * time.Second
				if last, ok := lastTargetExport[tgt.ID]; ok && now.Sub(last) < minInterval {
					continue
				}
				lastTargetExport[tgt.ID] = now

				// Compute per-target deltas so longer-interval targets never drop intermediate ticks
				deltaFlows := m.computeTargetFlowDeltas(tgt.ID, rawFlows, tgt.Interfaces, tgt.SamplingRate, ifNameByIdx)
				if len(deltaFlows) == 0 {
					continue
				}

				lastTmpl := m.selfLastTmpl[tgt.ID]
				refreshInterval := time.Duration(maxInt(30, tgt.TemplateRefreshSec)) * time.Second
				includeTmpl := lastTmpl.IsZero() || now.Sub(lastTmpl) >= refreshInterval

				domainID := tgt.ObservationDomainID
				if domainID == 0 {
					domainID = 1
				}

				tmplSentOK := true
				if includeTmpl && tgt.Version != "netflow9" {
					optSeq := m.selfSeq.Add(1)
					optPkt := EncodeIPFIXOptionsPacket(domainID, optSeq, nodeID, bundle.LocalHostname, localIfaces)
					if err := m.sendTargetDatagram(tgt, optPkt); err != nil {
						m.enqueueExportPacket(tgt.ID, optPkt)
						tmplSentOK = false
					}
				}

				// Chunk flows into <= 20 per MTU-safe UDP datagram
				dataTmplOK := false
				for start := 0; start < len(deltaFlows); start += 20 {
					end := start + 20
					if end > len(deltaFlows) {
						end = len(deltaFlows)
					}
					batch := deltaFlows[start:end]
					batchCount := uint32(len(batch))
					seq := m.selfSeq.Add(batchCount) - batchCount + 1
					var pkt []byte
					if tgt.Version == "netflow9" {
						pkt = EncodeNetFlowV9Packet(domainID, seq, includeTmpl && start == 0, batch)
					} else {
						pkt = EncodeIPFIXPacket(domainID, seq, includeTmpl && start == 0, batch)
					}
					if err := m.sendTargetDatagram(tgt, pkt); err == nil {
						m.totalSelfExport.Add(uint64(len(batch)))
						m.exportQueue.MarkSent(uint64(len(batch)))
						if includeTmpl && start == 0 {
							dataTmplOK = true
						}
					} else {
						m.enqueueExportPacket(tgt.ID, pkt)
						if includeTmpl && start == 0 {
							tmplSentOK = false
						}
					}
				}
				if includeTmpl && tmplSentOK && (len(deltaFlows) == 0 || dataTmplOK) {
					m.selfLastTmpl[tgt.ID] = now
				}
			}
		}
	}
}

func (m *NetFlowManager) enqueueExportPacket(targetID string, pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	idBytes := []byte(targetID)
	if len(idBytes) > 250 {
		idBytes = idBytes[:250]
	}
	framed := make([]byte, 0, 1+len(idBytes)+len(pkt))
	framed = append(framed, byte(len(idBytes)))
	framed = append(framed, idBytes...)
	framed = append(framed, pkt...)
	m.exportQueue.Push(framed)
}

func (m *NetFlowManager) drainQueuedExportPackets(bundle *NetFlowRuntimeBundle) {
	targetsByID := make(map[string]NetFlowSelfExportTargetPayload, len(bundle.Config.SelfExport.Targets))
	for _, t := range bundle.Config.SelfExport.Targets {
		if t.Enabled && t.Host != "" && t.Port > 0 {
			targetsByID[t.ID] = t
		}
	}
	batch := m.exportQueue.PopBatch(32)
	if len(batch) == 0 {
		return
	}
	var failed [][]byte
	for idx, item := range batch {
		if len(item) < 2 {
			continue
		}
		idLen := int(item[0])
		if 1+idLen >= len(item) {
			continue
		}
		tid := string(item[1 : 1+idLen])
		pkt := item[1+idLen:]
		tgt, ok := targetsByID[tid]
		if !ok {
			continue
		}
		if err := m.sendTargetDatagram(tgt, pkt); err != nil {
			failed = batch[idx:]
			break
		}
		m.exportQueue.MarkSent(1)
	}
	if len(failed) > 0 {
		m.exportQueue.RequeueFront(failed)
	}
}

// sendTargetDatagram reuses a persistent TCP/TLS connection per target when transport is tcp or tls.
func (m *NetFlowManager) sendTargetDatagram(tgt NetFlowSelfExportTargetPayload, pkt []byte) error {
	transport := strings.ToLower(strings.TrimSpace(tgt.Transport))
	if transport == "" {
		transport = "udp"
	}
	addr := net.JoinHostPort(tgt.Host, strconv.Itoa(tgt.Port))
	if transport == "udp" {
		conn, err := net.DialTimeout("udp", addr, 1500*time.Millisecond)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Write(pkt)
		return err
	}

	poolKey := fmt.Sprintf("%s|%s|%s", tgt.ID, transport, addr)
	m.targetConnsMu.Lock()
	conn := m.targetConns[poolKey]
	m.targetConnsMu.Unlock()

	writeOnce := func(c net.Conn) error {
		_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, err := c.Write(pkt)
		return err
	}

	if conn != nil {
		if err := writeOnce(conn); err == nil {
			return nil
		}
		_ = conn.Close()
		m.targetConnsMu.Lock()
		if m.targetConns[poolKey] == conn {
			delete(m.targetConns, poolKey)
		}
		m.targetConnsMu.Unlock()
	}

	var newConn net.Conn
	var err error
	if transport == "tls" {
		conf, cerr := buildNetFlowTLSConfig(tgt.TLS, false)
		if cerr != nil {
			return cerr
		}
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		newConn, err = tls.DialWithDialer(dialer, "tcp", addr, conf)
	} else {
		newConn, err = net.DialTimeout("tcp", addr, 3*time.Second)
	}
	if err != nil {
		return err
	}
	if err := writeOnce(newConn); err != nil {
		_ = newConn.Close()
		return err
	}
	m.targetConnsMu.Lock()
	if old := m.targetConns[poolKey]; old != nil {
		_ = old.Close()
	}
	m.targetConns[poolKey] = newConn
	m.targetConnsMu.Unlock()
	return nil
}

func sendFlowDatagram(transport, host string, port int, tlsCfg *NetFlowTlsConfigPayload, pkt []byte) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if transport == "tls" {
		conf, err := buildNetFlowTLSConfig(tlsCfg, false)
		if err != nil {
			return err
		}
		dialer := &net.Dialer{Timeout: 2 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Write(pkt)
		return err
	}
	network := "udp"
	if transport == "tcp" {
		network = "tcp"
	}
	conn, err := net.DialTimeout(network, addr, 1500*time.Millisecond)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write(pkt)
	return err
}

func (m *NetFlowManager) sampleRawLocalFlows() []FlowRecord {
	now := time.Now()
	current := make(map[string]FlowRecord)
	tcpDiag := readTCPDiagMetrics()

	if m.ebpf != nil {
		counters := m.ebpf.GetAllFlowCounters(16384)
		for _, ef := range counters {
			if ef.SrcIP == "" || ef.DstIP == "" {
				continue
			}
			inIdx := ef.IngressIfIndex
			if inIdx == 0 {
				inIdx = 1
			}
			key := fmt.Sprintf("%d|%s|%d|%s|%d|%d", ef.Protocol, ef.SrcIP, ef.SrcPort, ef.DstIP, ef.DstPort, inIdx)
			rec := FlowRecord{
				FlowStartMs: now.Add(-5 * time.Second).UnixMilli(),
				TimestampMs: now.UnixMilli(),
				SrcIP:       ef.SrcIP,
				DstIP:       ef.DstIP,
				SrcPort:     ef.SrcPort,
				DstPort:     ef.DstPort,
				Protocol:    ef.Protocol,
				VlanID:      ef.VlanID,
				Bytes:       ef.Bytes,
				Packets:     ef.Packets,
				InIfIndex:   inIdx,
			}
			if dm, ok := tcpDiag[fmt.Sprintf("%s|%d|%s|%d", ef.SrcIP, ef.SrcPort, ef.DstIP, ef.DstPort)]; ok {
				rec.RttMs = dm.RttMs
				rec.Retransmits = dm.Retransmits
			}
			current[key] = rec
		}
	}

	conntrackRecs, natIdx := readConntrackDeltasAndNAT()
	if len(natIdx) > 0 {
		m.enricher.UpdateConntrackNAT(natIdx)
	}
	for _, cf := range conntrackRecs {
		fiveKey := fmt.Sprintf("%d|%s|%d|%s|%d", cf.Protocol, cf.SrcIP, cf.SrcPort, cf.DstIP, cf.DstPort)
		matchedExisting := false
		for ck, ex := range current {
			if strings.HasPrefix(ck, fiveKey+"|") {
				if ex.PostNatSrcIP == "" {
					ex.PostNatSrcIP = cf.PostNatSrcIP
					ex.PostNatSrcPort = cf.PostNatSrcPort
					ex.PostNatDstIP = cf.PostNatDstIP
					ex.PostNatDstPort = cf.PostNatDstPort
					current[ck] = ex
				}
				matchedExisting = true
			}
		}
		if !matchedExisting && len(current) < 16384 {
			if dm, ok := tcpDiag[fmt.Sprintf("%s|%d|%s|%d", cf.SrcIP, cf.SrcPort, cf.DstIP, cf.DstPort)]; ok {
				cf.RttMs = dm.RttMs
				cf.Retransmits = dm.Retransmits
			}
			current[fiveKey+"|1"] = cf
		}
	}

	out := make([]FlowRecord, 0, len(current))
	for _, rec := range current {
		out = append(out, rec)
	}
	return out
}

// computeTargetFlowDeltas tracks cumulative counters independently per targetID so different
// activeTimeoutSec intervals never discard intermediate ticks.
func (m *NetFlowManager) computeTargetFlowDeltas(
	targetID string,
	raw []FlowRecord,
	targetIfaces []string,
	samplingRate int,
	ifNameByIdx map[uint32]string,
) []FlowRecord {
	var allowedIfaceSet map[string]bool
	if len(targetIfaces) > 0 {
		allowedIfaceSet = make(map[string]bool, len(targetIfaces))
		for _, ifc := range targetIfaces {
			if s := strings.TrimSpace(ifc); s != "" {
				allowedIfaceSet[s] = true
			}
		}
	}

	m.mu.Lock()
	prevMap := m.selfPrevByTarget[targetID]
	if prevMap == nil {
		prevMap = make(map[string]exporterCounterState)
	}
	nextPrev := make(map[string]exporterCounterState, len(raw))
	deltas := make([]FlowRecord, 0, len(raw))

	for i, f := range raw {
		if len(allowedIfaceSet) > 0 {
			inName := ifNameByIdx[f.InIfIndex]
			if !allowedIfaceSet[inName] && !allowedIfaceSet[strconv.FormatUint(uint64(f.InIfIndex), 10)] {
				continue
			}
		}
		key := fmt.Sprintf("%d|%s|%d|%s|%d|%d", f.Protocol, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.InIfIndex)
		prev := prevMap[key]
		var dBytes, dPkts uint64
		if f.Bytes >= prev.bytes {
			dBytes = f.Bytes - prev.bytes
		} else {
			dBytes = f.Bytes
		}
		if f.Packets >= prev.packets {
			dPkts = f.Packets - prev.packets
		} else {
			dPkts = f.Packets
		}
		nextPrev[key] = exporterCounterState{bytes: f.Bytes, packets: f.Packets}
		if dBytes > 0 || dPkts > 0 {
			if samplingRate > 1 {
				if i%samplingRate != 0 {
					continue
				}
				f.SamplingRate = uint32(samplingRate)
			}
			f.Bytes = dBytes
			f.Packets = dPkts
			deltas = append(deltas, f)
		}
	}
	m.selfPrevByTarget[targetID] = nextPrev
	m.mu.Unlock()
	return deltas
}

func collectLocalInterfaceSnapshot(bundle *NetFlowRuntimeBundle) ([]NetFlowRemoteIface, map[uint32]string) {
	hintByDev := make(map[string]NetFlowInterfaceHint)
	if bundle != nil {
		for _, h := range bundle.LocalInterfaces {
			hintByDev[h.Device] = h
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, map[uint32]string{}
	}
	out := make([]NetFlowRemoteIface, 0, len(ifaces))
	nameByIdx := make(map[uint32]string, len(ifaces))
	for _, ifc := range ifaces {
		if ifc.Index <= 0 {
			continue
		}
		idx := uint32(ifc.Index)
		nameByIdx[idx] = ifc.Name
		desc := ifc.Name
		ipv4 := ""
		if h, ok := hintByDev[ifc.Name]; ok {
			if h.Name != "" {
				desc = h.Name
			}
			ipv4 = h.IPv4Address
		}
		out = append(out, NetFlowRemoteIface{
			IfIndex:     idx,
			Name:        ifc.Name,
			Description: desc,
			MacAddress:  ifc.HardwareAddr.String(),
			IPv4Address: ipv4,
		})
	}
	return out, nameByIdx
}

func (m *NetFlowManager) metadataSyncLoop(stopCh chan struct{}) {
	defer m.wg.Done()
	tk := time.NewTicker(15 * time.Second)
	defer tk.Stop()
	var lastSync time.Time

	for {
		select {
		case <-stopCh:
			return
		case now := <-tk.C:
			m.mu.RLock()
			bundle := m.bundle
			m.mu.RUnlock()
			if bundle == nil || !bundle.Enabled || bundle.Config.SelfExport.MetadataSync == nil || !bundle.Config.SelfExport.MetadataSync.Enabled {
				continue
			}
			syncCfg := bundle.Config.SelfExport.MetadataSync
			targetURL := strings.TrimSpace(syncCfg.TargetURL)
			if targetURL == "" && bundle.HubURL != "" {
				targetURL = strings.TrimRight(bundle.HubURL, "/") + "/api/v1/netflow/metadata-sync"
			}
			if targetURL == "" {
				continue
			}
			interval := time.Duration(maxInt(15, syncCfg.IntervalSec)) * time.Second
			if !lastSync.IsZero() && now.Sub(lastSync) < interval {
				continue
			}
			lastSync = now
			m.pushMetadataSyncOnce(bundle, syncCfg, targetURL)
		}
	}
}

func (m *NetFlowManager) closeMetaHTTPClient() {
	m.metaMu.Lock()
	tr := m.metaTransport
	m.metaClient = nil
	m.metaTransport = nil
	m.metaClientKey = ""
	m.metaMu.Unlock()
	if tr != nil {
		tr.CloseIdleConnections()
	}
}

func (m *NetFlowManager) getMetadataHTTPClient(bundle *NetFlowRuntimeBundle, targetURL string) (*http.Client, error) {
	useTLS := strings.HasPrefix(targetURL, "https://")
	key := "http"
	if useTLS {
		key = fmt.Sprintf("https|%v|%s|%v", bundle.UseHaMtls, bundle.TLSCACert, bundle.TLSInsecureSkipVerify)
	}
	m.metaMu.Lock()
	if m.metaClient != nil && m.metaClientKey == key {
		c := m.metaClient
		m.metaMu.Unlock()
		return c, nil
	}
	oldTr := m.metaTransport
	m.metaMu.Unlock()

	if oldTr != nil {
		oldTr.CloseIdleConnections()
	}

	var tr *http.Transport
	if useTLS {
		tlsConf, terr := buildTLSConfigFromBundleParams(bundle.UseHaMtls, bundle.TLSCACert, "", "", "", bundle.TLSInsecureSkipVerify, false, false)
		if terr != nil {
			return nil, terr
		}
		tr = &http.Transport{
			TLSClientConfig: tlsConf,
			MaxIdleConns:    4,
			IdleConnTimeout: 60 * time.Second,
		}
	} else {
		tr = &http.Transport{
			MaxIdleConns:    4,
			IdleConnTimeout: 60 * time.Second,
		}
	}
	c := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}

	m.metaMu.Lock()
	if m.metaClient != nil && m.metaClientKey == key {
		existing := m.metaClient
		m.metaMu.Unlock()
		tr.CloseIdleConnections()
		return existing, nil
	}
	m.metaClient = c
	m.metaTransport = tr
	m.metaClientKey = key
	m.metaMu.Unlock()
	return c, nil
}

func (m *NetFlowManager) pushMetadataSyncOnce(bundle *NetFlowRuntimeBundle, syncCfg *NetFlowMetadataSyncPayload, targetURL string) {
	ifaces, _ := collectLocalInterfaceSnapshot(bundle)
	leasesList := readActiveKeaLeases("/var/lib/kea/kea-leases4.csv")
	leases := make([]NetFlowRemoteLease, 0, len(leasesList))
	for _, l := range leasesList {
		ip := strings.Split(l.Address, "/")[0]
		if ip != "" && l.Description != "" {
			leases = append(leases, NetFlowRemoteLease{IP: ip, Hostname: l.Description})
		}
	}
	nodeID := strings.TrimSpace(bundle.NodeID)
	if nodeID == "" {
		nodeID = bundle.LocalHostname
	}
	payload := RemoteNodeMetadataPayload{
		NodeID:      nodeID,
		Hostname:    bundle.LocalHostname,
		Interfaces:  ifaces,
		StaticHosts: bundle.StaticHostMap,
		DhcpLeases:  leases,
		TimestampMs: time.Now().UnixMilli(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	client, err := m.getMetadataHTTPClient(bundle, targetURL)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	tok := strings.TrimSpace(syncCfg.APIToken)
	if tok == "" {
		tok = strings.TrimSpace(bundle.IngestToken)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := client.Do(req)
	if err == nil && resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

// ApplyRemoteNodeMetadata registers remote interface mappings and DHCP/DNS hostnames pushed from an edge node.
func (m *NetFlowManager) ApplyRemoteNodeMetadata(p RemoteNodeMetadataPayload) {
	m.enricher.ApplyRemoteNodeMetadata(p)
}

// IngestExternalBatch ingests flow records bridged from external/satellite sources through enrichment, storage, and alerting.
func (m *NetFlowManager) IngestExternalBatch(nodeID, hostname, exporterIP string, flows []FlowRecord) int {
	if len(flows) == 0 {
		return 0
	}
	var totalBytes uint64
	nowMs := time.Now().UnixMilli()
	for i := range flows {
		if flows[i].HostID == "" {
			flows[i].HostID = nodeID
		}
		if flows[i].HostName == "" {
			flows[i].HostName = hostname
		}
		if flows[i].ExporterIP == "" {
			flows[i].ExporterIP = exporterIP
		}
		if flows[i].TimestampMs <= 0 {
			flows[i].TimestampMs = nowMs
			flows[i].Timestamp = time.UnixMilli(nowMs).UTC().Format(time.RFC3339Nano)
		}
		if flows[i].Version == "" {
			flows[i].Version = "ipfix"
		}
		m.enricher.Enrich(&flows[i])
		totalBytes += flows[i].Bytes
	}
	m.recordExporterActivity(firstNonEmpty(exporterIP, nodeID), nil, flows[0].Version, len(flows), totalBytes, nil)
	m.totalFlowsIngest.Add(uint64(len(flows)))
	m.totalBytesIngest.Add(totalBytes)
	m.store.Ingest(flows)
	m.broadcastSSE(flows)
	m.evaluateAlerts(flows)
	return len(flows)
}

// ListNodes returns distinct edge/host identities observed in flows.
func (m *NetFlowManager) ListNodes() []NetFlowNodeSummary {
	return m.store.ListDistinctNodes()
}

func readConntrackDeltasAndNAT() ([]FlowRecord, map[string]natTupleInfo) {
	f, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	now := time.Now()
	var out []FlowRecord
	natIdx := make(map[string]natTupleInfo)
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(out) < 16384 {
		if rec, hasNat, nt, ok := parseConntrackLine(sc.Text(), now); ok {
			if hasNat {
				k := fmt.Sprintf("%d|%s|%d|%s|%d", rec.Protocol, rec.SrcIP, rec.SrcPort, rec.DstIP, rec.DstPort)
				natIdx[k] = nt
			}
			if rec.Bytes > 0 || rec.Packets > 0 {
				out = append(out, rec)
			}
		}
	}
	return out, natIdx
}

// parseConntrackLine parses an /proc/net/nf_conntrack line including original & reply NAT tuples.
func parseConntrackLine(line string, now time.Time) (rec FlowRecord, hasNat bool, nat natTupleInfo, ok bool) {
	fields := strings.Fields(line)
	var proto uint8
	var origSrc, origDst, repSrc, repDst string
	var origSport, origDport, repSport, repDport uint16
	var pkts, bytes uint64
	srcSeen, dstSeen, sportSeen, dportSeen := 0, 0, 0, 0

	for _, tok := range fields {
		switch {
		case tok == "tcp":
			proto = 6
		case tok == "udp":
			proto = 17
		case tok == "icmp":
			proto = 1
		case strings.HasPrefix(tok, "src="):
			val := strings.TrimPrefix(tok, "src=")
			if srcSeen == 0 {
				origSrc = val
			} else if srcSeen == 1 {
				repSrc = val
			}
			srcSeen++
		case strings.HasPrefix(tok, "dst="):
			val := strings.TrimPrefix(tok, "dst=")
			if dstSeen == 0 {
				origDst = val
			} else if dstSeen == 1 {
				repDst = val
			}
			dstSeen++
		case strings.HasPrefix(tok, "sport="):
			v, _ := strconv.Atoi(strings.TrimPrefix(tok, "sport="))
			if sportSeen == 0 {
				origSport = uint16(v)
			} else if sportSeen == 1 {
				repSport = uint16(v)
			}
			sportSeen++
		case strings.HasPrefix(tok, "dport="):
			v, _ := strconv.Atoi(strings.TrimPrefix(tok, "dport="))
			if dportSeen == 0 {
				origDport = uint16(v)
			} else if dportSeen == 1 {
				repDport = uint16(v)
			}
			dportSeen++
		case strings.HasPrefix(tok, "packets="):
			v, _ := strconv.ParseUint(strings.TrimPrefix(tok, "packets="), 10, 64)
			pkts += v
		case strings.HasPrefix(tok, "bytes="):
			v, _ := strconv.ParseUint(strings.TrimPrefix(tok, "bytes="), 10, 64)
			bytes += v
		}
	}
	if origSrc == "" || origDst == "" {
		return FlowRecord{}, false, natTupleInfo{}, false
	}

	// SNAT: reply dst/dport differs from orig src/sport
	if repDst != "" && (repDst != origSrc || repDport != origSport) {
		nat.PostSrcIP = repDst
		nat.PostSrcPort = repDport
		hasNat = true
	}
	// DNAT: reply src/sport differs from orig dst/dport
	if repSrc != "" && (repSrc != origDst || repSport != origDport) {
		nat.PostDstIP = repSrc
		nat.PostDstPort = repSport
		hasNat = true
	}

	return FlowRecord{
		FlowStartMs:    now.Add(-5 * time.Second).UnixMilli(),
		TimestampMs:    now.UnixMilli(),
		SrcIP:          origSrc,
		DstIP:          origDst,
		SrcPort:        origSport,
		DstPort:        origDport,
		Protocol:       proto,
		PostNatSrcIP:   nat.PostSrcIP,
		PostNatSrcPort: nat.PostSrcPort,
		PostNatDstIP:   nat.PostDstIP,
		PostNatDstPort: nat.PostDstPort,
		Bytes:          bytes,
		Packets:        pkts,
	}, hasNat, nat, true
}

// --- Real-Time Anomaly & Alert Engine ---

func (m *NetFlowManager) evaluateAlerts(flows []FlowRecord) {
	m.mu.RLock()
	bundle := m.bundle
	m.mu.RUnlock()
	if bundle == nil || !bundle.Config.Alerting.Enabled || len(bundle.Config.Alerting.Rules) == 0 {
		return
	}

	nowMs := time.Now().UnixMilli()
	m.alertMu.Lock()
	defer m.alertMu.Unlock()

	for _, rule := range bundle.Config.Alerting.Rules {
		if !rule.Enabled {
			continue
		}
		var fqlNode fqlNode
		if strings.TrimSpace(rule.FQLFilter) != "" {
			if ast, err := ParseFQL(rule.FQLFilter); err == nil {
				fqlNode = ast
			}
		}

		winMs := int64(maxInt(10, rule.WindowSec)) * 1000
		tr := m.alertWindows[rule.ID]
		if tr == nil || nowMs-tr.windowStartMs > winMs {
			tr = &alertWindowTrack{
				windowStartMs: nowMs,
				bytesByIP:     make(map[string]uint64),
				pktsByIP:      make(map[string]uint64),
				synByIP:       make(map[string]uint64),
				portsByIP:     make(map[string]map[uint16]struct{}),
				dstsByIP:      make(map[string]map[string]struct{}),
				egressByIP:    make(map[string]uint64),
				flowsByPair:   make(map[string]int),
			}
			m.alertWindows[rule.ID] = tr
		}

		for i := range flows {
			f := &flows[i]
			if fqlNode != nil && !fqlNode.Eval(f) {
				continue
			}
			tr.bytesByIP[f.SrcIP] += f.Bytes
			tr.pktsByIP[f.SrcIP] += f.Packets
			if f.TCPFlags&0x02 != 0 && f.TCPFlags&0x10 == 0 {
				tr.synByIP[f.SrcIP] += f.Packets
			}
			pm := tr.portsByIP[f.SrcIP]
			if pm == nil {
				pm = make(map[uint16]struct{})
				tr.portsByIP[f.SrcIP] = pm
			}
			if f.DstPort > 0 {
				pm[f.DstPort] = struct{}{}
			}
			dm := tr.dstsByIP[f.SrcIP]
			if dm == nil {
				dm = make(map[string]struct{})
				tr.dstsByIP[f.SrcIP] = dm
			}
			if f.DstIP != "" {
				dm[f.DstIP] = struct{}{}
			}
			if f.Direction == "egress" {
				tr.egressByIP[f.SrcIP] += f.Bytes
			}
			tr.flowsByPair[f.SrcIP+"|"+f.DstIP]++

			if rule.Kind == "threat_ioc" && f.ThreatMatch != "" {
				m.triggerRuleAlertLocked(rule, f.SrcIP, f.ExporterIP, 1, fmt.Sprintf("Threat IOC match (%s) between %s and %s", f.ThreatMatch, f.SrcIP, f.DstIP), nowMs)
			}
			if rule.Kind == "custom_fql" && fqlNode != nil && tr.flowsByPair[f.SrcIP+"|"+f.DstIP] >= maxInt(1, int(rule.Threshold)) {
				m.triggerRuleAlertLocked(rule, f.SrcIP, f.ExporterIP, float64(tr.flowsByPair[f.SrcIP+"|"+f.DstIP]), fmt.Sprintf("Custom FQL alert matched for %s -> %s", f.SrcIP, f.DstIP), nowMs)
			}
		}

		winSec := float64(maxInt(10, rule.WindowSec))
		switch rule.Kind {
		case "volumetric_bps":
			for ip, b := range tr.bytesByIP {
				bps := float64(b*8) / winSec
				if rule.Threshold > 0 && bps >= rule.Threshold {
					m.triggerRuleAlertLocked(rule, ip, "", bps, fmt.Sprintf("Volumetric traffic from %s reached %.1f Mbps", ip, bps/1e6), nowMs)
				}
			}
		case "volumetric_pps":
			for ip, pk := range tr.pktsByIP {
				pps := float64(pk) / winSec
				if rule.Threshold > 0 && pps >= rule.Threshold {
					m.triggerRuleAlertLocked(rule, ip, "", pps, fmt.Sprintf("Packet flood from %s reached %.0f pps", ip, pps), nowMs)
				}
			}
		case "syn_flood":
			for ip, sy := range tr.synByIP {
				pps := float64(sy) / winSec
				if rule.Threshold > 0 && pps >= rule.Threshold {
					m.triggerRuleAlertLocked(rule, ip, "", pps, fmt.Sprintf("SYN flood suspected from %s (%.0f SYN/s)", ip, pps), nowMs)
				}
			}
		case "port_scan":
			for ip, pm := range tr.portsByIP {
				if rule.Threshold > 0 && float64(len(pm)) >= rule.Threshold {
					m.triggerRuleAlertLocked(rule, ip, "", float64(len(pm)), fmt.Sprintf("Port scan detected from %s (%d unique destination ports)", ip, len(pm)), nowMs)
				}
			}
		case "host_sweep":
			for ip, dm := range tr.dstsByIP {
				if rule.Threshold > 0 && float64(len(dm)) >= rule.Threshold {
					m.triggerRuleAlertLocked(rule, ip, "", float64(len(dm)), fmt.Sprintf("Host sweep detected from %s (%d unique destination hosts)", ip, len(dm)), nowMs)
				}
			}
		case "exfiltration":
			for ip, eb := range tr.egressByIP {
				if rule.Threshold > 0 && float64(eb) >= rule.Threshold {
					m.triggerRuleAlertLocked(rule, ip, "", float64(eb), fmt.Sprintf("Large egress transfer from %s (%d MB in %ds)", ip, eb/(1024*1024), rule.WindowSec), nowMs)
				}
			}
		case "c2_beacon":
			for pair, cnt := range tr.flowsByPair {
				if rule.Threshold > 0 && float64(cnt) >= rule.Threshold {
					parts := strings.SplitN(pair, "|", 2)
					m.triggerRuleAlertLocked(rule, parts[0], "", float64(cnt), fmt.Sprintf("Periodic C2 beaconing pattern %s (%d connections in %ds)", pair, cnt, rule.WindowSec), nowMs)
				}
			}
		case "baseline_zscore":
			zLimit := rule.Threshold
			if zLimit <= 0 {
				zLimit = 3.5
			}
			nowT := time.UnixMilli(nowMs)
			for ip, b := range tr.bytesByIP {
				bps := float64(b*8) / winSec
				pps := float64(tr.pktsByIP[ip]) / winSec
				zBps, zPps, warmed := m.baselines.ObserveAndScore(ip, nowT, bps, pps)
				if !warmed {
					continue
				}
				zMax := zBps
				if zPps > zMax {
					zMax = zPps
				}
				if zMax >= zLimit {
					m.triggerRuleAlertLocked(rule, ip, "", zMax, fmt.Sprintf("Adaptive baseline spike on %s (Z=%.2f, %.1f Mbps)", ip, zMax, bps/1e6), nowMs)
				}
			}
		case "first_seen_pair":
			nowSec := nowMs / 1000
			for i := range flows {
				f := &flows[i]
				if f.Bytes < uint64(rule.Threshold) {
					continue
				}
				if sAddr, err := netip.ParseAddr(f.SrcIP); err == nil {
					bits := 24
					if sAddr.Is6() {
						bits = 64
					}
					srcSub := netip.PrefixFrom(sAddr, bits).Masked().String()
					dstKey := f.DstIP
					if f.DstAsn > 0 {
						dstKey = fmt.Sprintf("AS%d", f.DstAsn)
					} else if dAddr, derr := netip.ParseAddr(f.DstIP); derr == nil && (dAddr.IsPrivate() || dAddr.IsLoopback()) {
						dstKey = netip.PrefixFrom(dAddr, bits).Masked().String()
					}
					pairKey := srcSub + "->" + dstKey
					if m.baselines.CheckPair(pairKey, nowSec) {
						m.triggerRuleAlertLocked(rule, f.SrcIP, f.ExporterIP, float64(f.Bytes), fmt.Sprintf("First-seen traffic pair %s (%d bytes to %s)", pairKey, f.Bytes, f.DstIP), nowMs)
					}
				}
			}
		}
	}
}

func (m *NetFlowManager) triggerRuleAlertLocked(rule NetFlowAlertRulePayload, culpritIP, exporterIP string, metricVal float64, summary string, nowMs int64) {
	cdKey := rule.ID + "|" + culpritIP
	cdMs := int64(maxInt(30, rule.CooldownSec)) * 1000
	if expMs, ok := m.alertCooldown[cdKey]; ok && nowMs < expMs {
		return
	}
	for k, expMs := range m.alertCooldown {
		if nowMs >= expMs {
			delete(m.alertCooldown, k)
		}
	}
	if len(m.alertCooldown) >= 4096 {
		var oldestKey string
		var oldestExp int64
		first := true
		for k, expMs := range m.alertCooldown {
			if first || expMs < oldestExp {
				oldestKey = k
				oldestExp = expMs
				first = false
			}
		}
		if !first {
			delete(m.alertCooldown, oldestKey)
		}
	}
	m.alertCooldown[cdKey] = nowMs + cdMs

	actionsTaken := []string{"alert_log"}
	ttl := rule.XdpBlockTTLSec
	if ttl < 60 {
		ttl = 900
	}
	for _, act := range rule.Actions {
		switch act {
		case "webhook":
			if strings.HasPrefix(rule.WebhookURL, "http://") || strings.HasPrefix(rule.WebhookURL, "https://") {
				actionsTaken = append(actionsTaken, "webhook_queued")
				u := rule.WebhookURL
				go postAlertWebhook(u, rule, culpritIP, summary)
			}
		case "vigilante_soar":
			if rule.RemoteEdgeMitigation && exporterIP != "" && exporterIP != "127.0.0.1" && exporterIP != "::1" && m.topology != nil {
				actionsTaken = append(actionsTaken, "remote_soar_queued")
				go m.dispatchRemoteEdgeMitigation(exporterIP, culpritIP, ttl, "NetFlow SOAR: "+rule.Name)
			} else if m.vigilante != nil && culpritIP != "" {
				if err := m.vigilante.BlockIP(culpritIP, ttl); err == nil {
					actionsTaken = append(actionsTaken, "vigilante_soar_blocked")
				} else {
					actionsTaken = append(actionsTaken, fmt.Sprintf("vigilante_soar_err:%v", err))
				}
			}
		case "xdp_block":
			if rule.RemoteEdgeMitigation && exporterIP != "" && exporterIP != "127.0.0.1" && exporterIP != "::1" && m.topology != nil {
				actionsTaken = append(actionsTaken, "remote_xdp_queued")
				go m.dispatchRemoteEdgeMitigation(exporterIP, culpritIP, ttl, "NetFlow anomaly: "+rule.Name)
			} else if m.ebpf != nil && culpritIP != "" {
				if err := m.ebpf.AddXdpBlock(culpritIP, ttl, XdpReasonSoarQuarantine, "NetFlow anomaly: "+rule.Name); err == nil {
					actionsTaken = append(actionsTaken, "xdp_blocked")
				} else {
					actionsTaken = append(actionsTaken, fmt.Sprintf("xdp_block_err:%v", err))
				}
			}
		}
	}

	evt := FlowAlertEvent{
		ID:           fmt.Sprintf("nfa-%d-%s", nowMs, rule.ID),
		Timestamp:    time.UnixMilli(nowMs).UTC().Format(time.RFC3339),
		RuleID:       rule.ID,
		RuleName:     rule.Name,
		Kind:         rule.Kind,
		Severity:     rule.Severity,
		CulpritIP:    culpritIP,
		ExporterIP:   exporterIP,
		MetricValue:  metricVal,
		Threshold:    rule.Threshold,
		Summary:      summary,
		ActionsTaken: actionsTaken,
	}
	m.alerts = append([]FlowAlertEvent{evt}, m.alerts...)
	if len(m.alerts) > 500 {
		m.alerts = m.alerts[:500]
	}
}

func postAlertWebhook(webhookURL string, rule NetFlowAlertRulePayload, culpritIP, summary string) {
	payload, _ := json.Marshal(map[string]any{
		"source":    "axonwall-netflow-collector",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"ruleId":    rule.ID,
		"ruleName":  rule.Name,
		"severity":  rule.Severity,
		"culpritIp": culpritIP,
		"summary":   summary,
	})
	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

func (m *NetFlowManager) dispatchRemoteEdgeMitigation(exporterIP, culpritIP string, ttlSec int, reason string) {
	m.mu.RLock()
	tm := m.topology
	m.mu.RUnlock()
	if tm == nil || culpritIP == "" || exporterIP == "" {
		return
	}
	expAddr, expParseErr := netip.ParseAddr(strings.TrimSpace(exporterIP))
	if expParseErr == nil {
		expAddr = expAddr.Unmap()
	}
	peers, peerTokens := tm.ListEnabledPeersWithTokens()
	for _, p := range peers {
		validURL, err := validatePluginHTTPURL(p.APIURL, "peer "+p.Name)
		if err != nil {
			continue
		}
		parsedURL, perr := url.Parse(validURL)
		if perr != nil {
			continue
		}
		apiHost := strings.TrimSpace(parsedURL.Hostname())
		hostMatch := false
		if apiAddr, aerr := netip.ParseAddr(apiHost); aerr == nil && expParseErr == nil {
			hostMatch = apiAddr.Unmap() == expAddr
		} else if apiHost != "" {
			hostMatch = strings.EqualFold(apiHost, strings.TrimSpace(exporterIP))
		}
		if !hostMatch && p.ID != exporterIP && p.Name != exporterIP {
			continue
		}
		client, cerr := tm.BuildPeerHTTPClient(p)
		if cerr != nil {
			continue
		}
		payload, _ := json.Marshal(map[string]any{
			"targetIp": culpritIP,
			"ttlSec":   ttlSec,
			"reason":   reason,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(validURL, "/")+"/api/v1/observability/mitigate", bytes.NewReader(payload))
		if rerr != nil {
			cancel()
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if tok := peerTokens[p.ID]; tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, derr := client.Do(req)
		if derr == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		cancel()
		return
	}
}

// --- Public API / Query / Stream / Status Methods ---

func (m *NetFlowManager) GetStatus() NetFlowStatusSnapshot {
	m.mu.RLock()
	bundle := m.bundle
	running := m.running
	ls := make([]*listenerRuntime, len(m.listeners))
	copy(ls, m.listeners)
	m.mu.RUnlock()

	lStatus := make([]NetFlowListenerStatus, 0, len(ls))
	for _, rt := range ls {
		rt.lastErrMu.Lock()
		le := rt.lastError
		rt.lastErrMu.Unlock()
		lStatus = append(lStatus, NetFlowListenerStatus{
			ID:              rt.cfg.ID,
			Name:            rt.cfg.Name,
			Protocol:        rt.cfg.Protocol,
			Transport:       rt.cfg.Transport,
			Address:         net.JoinHostPort(rt.cfg.BindAddress, strconv.Itoa(rt.cfg.Port)),
			Listening:       rt.listening.Load(),
			PacketsReceived: rt.pktsReceived.Load(),
			DecodeErrors:    rt.decodeErrs.Load(),
			DroppedUnknownT: rt.droppedUnkT.Load(),
			LastError:       le,
		})
	}

	m.exportersMu.RLock()
	expCount := len(m.exporters)
	m.exportersMu.RUnlock()

	m.alertMu.Lock()
	activeAlerts := 0
	for _, a := range m.alerts {
		if !a.Acknowledged {
			activeAlerts++
		}
	}
	m.alertMu.Unlock()

	hotCnt, hotCap, chunkCnt, diskMB, mode, chConn := m.store.Stats()
	cityLoaded, asnLoaded, geoUpdatedAt, bgpPrefixes, k3sWorkloads := m.enricher.RuntimeStats()
	lastErrStr, _ := m.lastErr.Load().(string)

	return NetFlowStatusSnapshot{
		Enabled:             bundle != nil && bundle.Enabled,
		Running:             running,
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
		Listeners:           lStatus,
		PacketsReceived:     m.totalPktsRecv.Load(),
		FlowsIngested:       m.totalFlowsIngest.Load(),
		BytesIngested:       m.totalBytesIngest.Load(),
		ReplicatedPackets:   m.totalReplicated.Load(),
		SelfExportedFlows:   m.totalSelfExport.Load(),
		DecodeErrors:        m.totalDecodeErrs.Load(),
		HotRingCount:        hotCnt,
		HotRingCapacity:     hotCap,
		DiskChunksCount:     chunkCnt,
		DiskUsageMB:         diskMB,
		StorageMode:         mode,
		ClickHouseConnected: chConn,
		ExportersCount:      expCount,
		TemplatesCount:      len(m.decoder.GetTemplates()),
		ActiveAlertsCount:   activeAlerts,
		GeoIPCityLoaded:     cityLoaded,
		GeoIPAsnLoaded:      asnLoaded,
		GeoIPUpdatedAt:      geoUpdatedAt,
		BaselineEntities:    m.baselines.Count(),
		BgpPrefixes:         bgpPrefixes,
		K3sWorkloads:        k3sWorkloads,
		LastError:           lastErrStr,
	}
}

func (m *NetFlowManager) GetBaselines(limit int) []BaselineSummaryEntry {
	return m.baselines.Snapshot(limit)
}

func (m *NetFlowManager) ResetBaselines() error {
	return m.baselines.Reset()
}

func (m *NetFlowManager) TriggerGeoIPUpdate(ctx context.Context) error {
	return m.enricher.TriggerGeoIPUpdate(ctx)
}

func (m *NetFlowManager) GetExporters() []ExporterRuntimeStats {
	m.mu.RLock()
	bundle := m.bundle
	m.mu.RUnlock()

	profileByIP := make(map[string]NetFlowExporterProfilePayload)
	if bundle != nil {
		for _, p := range bundle.Config.ExporterProfiles {
			profileByIP[p.IP] = p
		}
	}

	templates := m.decoder.GetTemplates()
	tmplCountByIP := make(map[string]int)
	for _, t := range templates {
		tmplCountByIP[t.ExporterIP]++
	}

	nowMs := time.Now().UnixMilli()
	m.exportersMu.RLock()
	defer m.exportersMu.RUnlock()

	seen := make(map[string]bool)
	out := make([]ExporterRuntimeStats, 0, len(m.exporters)+len(profileByIP))

	for ip, tr := range m.exporters {
		seen[ip] = true
		p, hasP := profileByIP[ip]
		name := ip
		vendor := "other"
		site := ""
		if hasP {
			name = p.Name
			vendor = p.Vendor
			site = p.Site
		} else if ip == "127.0.0.1" || ip == "::1" {
			name = "Local Axonwall Appliance"
			vendor = "axonwall"
		}
		var vers []string
		for v := range tr.versions {
			vers = append(vers, v)
		}
		sort.Strings(vers)

		ageSec := (nowMs - tr.lastSeenMs) / 1000
		status := "green"
		if ageSec > 180 {
			status = "red"
		} else if ageSec > 60 {
			status = "yellow"
		}
		if hasP && p.ExpectedFpsMin > 0 && tr.fps < p.ExpectedFpsMin {
			status = "yellow"
		}

		var ifaces []ExporterInterfaceCounter
		for _, c := range tr.interfaces {
			ifaces = append(ifaces, c)
		}
		sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].IfIndex < ifaces[j].IfIndex })

		samp := m.decoder.GetExporterSampling(ip)
		if hasP && p.SamplingRateOverride > 1 {
			samp = uint32(p.SamplingRateOverride)
		}

		out = append(out, ExporterRuntimeStats{
			ExporterIP:      ip,
			Name:            name,
			Vendor:          vendor,
			Site:            site,
			LastSeen:        time.UnixMilli(tr.lastSeenMs).UTC().Format(time.RFC3339),
			LastSeenUnixMs:  tr.lastSeenMs,
			Status:          status,
			Versions:        vers,
			PacketsReceived: tr.packets,
			FlowsReceived:   tr.flows,
			BytesAccounted:  tr.bytes,
			SamplingRate:    samp,
			TemplatesCount:  tmplCountByIP[ip],
			FpsEstimate:     tr.fps,
			BpsEstimate:     tr.bps,
			Interfaces:      ifaces,
		})
	}

	// Include configured profiles that haven't reported yet as red
	for ip, p := range profileByIP {
		if seen[ip] {
			continue
		}
		out = append(out, ExporterRuntimeStats{
			ExporterIP: ip,
			Name:       p.Name,
			Vendor:     p.Vendor,
			Site:       p.Site,
			Status:     "red",
			Versions:   []string{},
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].BytesAccounted > out[j].BytesAccounted })
	return out
}

func (m *NetFlowManager) GetTemplates() []TemplateCacheEntry {
	return m.decoder.GetTemplates()
}

func (m *NetFlowManager) ListAlerts() []FlowAlertEvent {
	m.alertMu.Lock()
	defer m.alertMu.Unlock()
	out := make([]FlowAlertEvent, len(m.alerts))
	copy(out, m.alerts)
	return out
}

func (m *NetFlowManager) AckAlert(id string) bool {
	m.alertMu.Lock()
	defer m.alertMu.Unlock()
	for i := range m.alerts {
		if m.alerts[i].ID == id || id == "all" {
			m.alerts[i].Acknowledged = true
			if id != "all" {
				return true
			}
		}
	}
	return id == "all"
}

func (m *NetFlowManager) GetTopologyOverlay() *NetFlowTopologyOverlay {
	m.mu.RLock()
	bundle := m.bundle
	m.mu.RUnlock()
	if bundle == nil || !bundle.Enabled || !bundle.Config.TopologyOverlay.Enabled {
		return nil
	}
	winSec := bundle.Config.TopologyOverlay.WindowSec
	if winSec < 10 {
		winSec = 60
	}
	nowMs := time.Now().UnixMilli()
	res := m.store.Query(FlowQueryRequest{
		StartMs: nowMs - int64(winSec)*1000,
		EndMs:   nowMs,
		Limit:   1000,
	})
	type ifKey struct{ exp, dev string }
	agg := make(map[ifKey]*NetFlowTopologyInterfaceRate)
	for _, f := range res.Flows {
		dev := firstNonEmpty(f.OutIfName, f.InIfName)
		if dev == "" {
			continue
		}
		k := ifKey{exp: f.ExporterIP, dev: dev}
		ent := agg[k]
		if ent == nil {
			ent = &NetFlowTopologyInterfaceRate{ExporterIP: f.ExporterIP, Device: dev}
			agg[k] = ent
		}
		if f.InIfName != "" {
			ent.RxBps += float64(f.Bytes*8) / float64(winSec)
		}
		if f.OutIfName != "" {
			ent.TxBps += float64(f.Bytes*8) / float64(winSec)
		}
		if f.InIfName == "" && f.OutIfName == "" {
			ent.RxBps += float64(f.Bytes*8) / float64(winSec)
		}
		ent.Flows++
	}
	rates := make([]NetFlowTopologyInterfaceRate, 0, len(agg))
	for _, v := range agg {
		rates = append(rates, *v)
	}
	return &NetFlowTopologyOverlay{
		Available:  true,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		WindowSec:  winSec,
		TotalBps:   res.AvgBps,
		TotalFlows: res.TotalMatchedFlows,
		Interfaces: rates,
	}
}

// InjectTestBurst transmits real wire-encoded NetFlow/IPFIX/sFlow test packets to verify pipeline end-to-end.
func (m *NetFlowManager) InjectTestBurst(proto string, count int) (int, error) {
	if count <= 0 || count > 200 {
		count = 12
	}
	sampleFlows := make([]FlowRecord, 0, count)
	now := time.Now()
	dstChoices := []struct {
		ip   string
		port uint16
	}{
		{"1.1.1.1", 443},
		{"8.8.8.8", 53},
		{"104.16.132.229", 443},
		{"52.94.236.248", 8443},
		{"10.80.0.200", 22},
		{"10.43.0.10", 6443},
	}
	for i := 0; i < count; i++ {
		d := dstChoices[i%len(dstChoices)]
		p := uint8(6)
		if d.port == 53 {
			p = 17
		}
		sampleFlows = append(sampleFlows, FlowRecord{
			FlowStartMs: now.Add(-4 * time.Second).UnixMilli(),
			TimestampMs: now.UnixMilli(),
			SrcIP:       fmt.Sprintf("10.80.0.%d", 20+(i%6)),
			DstIP:       d.ip,
			SrcPort:     uint16(40000 + i),
			DstPort:     d.port,
			Protocol:    p,
			TCPFlags:    0x12,
			InIfIndex:   2,
			OutIfIndex:  1,
			VlanID:      uint16((i % 2) * 10),
			Bytes:       uint64(64_000 * (1 + i%5)),
			Packets:     uint64(48 * (1 + i%4)),
		})
	}

	var pkt []byte
	switch strings.ToLower(proto) {
	case "netflow9", "v9":
		pkt = EncodeNetFlowV9Packet(99, m.selfSeq.Add(1), true, sampleFlows)
	case "netflow5", "v5":
		pkt = encodeSyntheticNetFlowV5(sampleFlows)
	case "sflow", "sflow5":
		pkt = encodeSyntheticSFlowV5(sampleFlows)
	default:
		pkt = EncodeIPFIXPacket(1, m.selfSeq.Add(1), true, sampleFlows)
	}

	m.mu.RLock()
	var targetPort int
	for _, l := range m.listeners {
		if l.listening.Load() && l.cfg.Transport == "udp" {
			targetPort = l.cfg.Port
			break
		}
	}
	m.mu.RUnlock()

	if targetPort > 0 {
		if err := sendFlowDatagram("udp", "127.0.0.1", targetPort, nil, pkt); err == nil {
			return len(sampleFlows), nil
		}
	}

	// Fallback direct decode+ingest if collector listener isn't bound on UDP yet
	rt := &listenerRuntime{cfg: NetFlowListenerPayload{ID: "synthetic", Protocol: "auto"}}
	m.processPacket(rt, "127.0.0.1", pkt)
	return len(sampleFlows), nil
}

func encodeSyntheticNetFlowV5(flows []FlowRecord) []byte {
	const hdrLen = 24
	const recLen = 48
	buf := make([]byte, hdrLen+len(flows)*recLen)
	binary.BigEndian.PutUint16(buf[0:2], 5)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(flows)))
	binary.BigEndian.PutUint32(buf[4:8], 60000)
	binary.BigEndian.PutUint32(buf[8:12], uint32(time.Now().Unix()))
	for i, f := range flows {
		r := buf[hdrLen+i*recLen : hdrLen+(i+1)*recLen]
		copy(r[0:4], net.ParseIP(f.SrcIP).To4())
		copy(r[4:8], net.ParseIP(f.DstIP).To4())
		binary.BigEndian.PutUint16(r[12:14], uint16(f.InIfIndex))
		binary.BigEndian.PutUint16(r[14:16], uint16(f.OutIfIndex))
		binary.BigEndian.PutUint32(r[16:20], uint32(f.Packets))
		binary.BigEndian.PutUint32(r[20:24], uint32(f.Bytes))
		binary.BigEndian.PutUint32(r[24:28], 55000)
		binary.BigEndian.PutUint32(r[28:32], 60000)
		binary.BigEndian.PutUint16(r[32:34], f.SrcPort)
		binary.BigEndian.PutUint16(r[34:36], f.DstPort)
		r[37] = f.TCPFlags
		r[38] = f.Protocol
	}
	return buf
}

func encodeSyntheticSFlowV5(flows []FlowRecord) []byte {
	// sFlow v5 header (IPv4 agent) + 1 flow sample for first flow
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(5))       // version
	_ = binary.Write(&buf, binary.BigEndian, uint32(1))       // IPv4 agent
	buf.Write(net.ParseIP("127.0.0.1").To4())                 // agent IP
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))       // sub-agent
	_ = binary.Write(&buf, binary.BigEndian, uint32(1))       // seq
	_ = binary.Write(&buf, binary.BigEndian, uint32(1000))    // uptime
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(flows)))

	for idx, f := range flows {
		// Ethernet (14B) + IPv4 (20B) + TCP/UDP (20B) = 54B
		eth := make([]byte, 54)
		eth[12] = 0x08
		eth[13] = 0x00
		eth[14] = 0x45
		eth[23] = f.Protocol
		copy(eth[26:30], net.ParseIP(f.SrcIP).To4())
		copy(eth[30:34], net.ParseIP(f.DstIP).To4())
		binary.BigEndian.PutUint16(eth[34:36], f.SrcPort)
		binary.BigEndian.PutUint16(eth[36:38], f.DstPort)
		eth[47] = f.TCPFlags

		// Raw Packet Header record: 16B header + 54B padded to 56B (4B aligned) = 72B record body + 8B record header = 80B
		recBodyLen := 16 + len(eth)
		sampleBodyLen := 32 + 8 + recBodyLen
		_ = binary.Write(&buf, binary.BigEndian, uint32(1))                   // flow sample
		_ = binary.Write(&buf, binary.BigEndian, uint32(sampleBodyLen))
		_ = binary.Write(&buf, binary.BigEndian, uint32(idx+1))               // sample seq
		_ = binary.Write(&buf, binary.BigEndian, uint32(1))                   // source id
		_ = binary.Write(&buf, binary.BigEndian, uint32(100))                 // sampling rate 1:100
		_ = binary.Write(&buf, binary.BigEndian, uint32(1000))                // sample pool
		_ = binary.Write(&buf, binary.BigEndian, uint32(0))                   // drops
		_ = binary.Write(&buf, binary.BigEndian, f.InIfIndex)                 // input
		_ = binary.Write(&buf, binary.BigEndian, f.OutIfIndex)                // output
		_ = binary.Write(&buf, binary.BigEndian, uint32(1))                   // num records
		_ = binary.Write(&buf, binary.BigEndian, uint32(1))                   // raw packet header fmt
		_ = binary.Write(&buf, binary.BigEndian, uint32(recBodyLen))
		_ = binary.Write(&buf, binary.BigEndian, uint32(1))                   // eth
		_ = binary.Write(&buf, binary.BigEndian, uint32(1280))                // wire frame len
		_ = binary.Write(&buf, binary.BigEndian, uint32(0))                   // stripped
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(eth)))            // pkt len
		buf.Write(eth)
	}
	return buf.Bytes()
}

// --- Live SSE Broker ---

func (m *NetFlowManager) broadcastSSE(flows []FlowRecord) {
	m.sseMu.Lock()
	if len(m.sseSubs) == 0 {
		m.sseMu.Unlock()
		return
	}
	subs := make([]chan FlowRecord, 0, len(m.sseSubs))
	for ch := range m.sseSubs {
		subs = append(subs, ch)
	}
	m.sseMu.Unlock()

	for _, f := range flows {
		for _, ch := range subs {
			select {
			case ch <- f:
			default:
			}
		}
	}
}

func (m *NetFlowManager) StreamSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	fqlRaw := strings.TrimSpace(r.URL.Query().Get("fql"))
	var fqlAst fqlNode
	if fqlRaw != "" {
		parsed, err := ParseFQL(fqlRaw)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid FQL filter: %v", err), http.StatusBadRequest)
			return
		}
		fqlAst = parsed
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan FlowRecord, 256)
	m.sseMu.Lock()
	m.sseSubs[ch] = struct{}{}
	m.sseMu.Unlock()
	defer func() {
		m.sseMu.Lock()
		delete(m.sseSubs, ch)
		m.sseMu.Unlock()
	}()

	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()

	_, _ = w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepAlive.C:
			_, _ = w.Write([]byte(": keepalive\n\n"))
			flusher.Flush()
		case flow := <-ch:
			if fqlAst != nil && !fqlAst.Eval(&flow) {
				continue
			}
			b, err := json.Marshal(flow)
			if err != nil {
				continue
			}
			_, _ = w.Write([]byte("event: flow\ndata: "))
			_, _ = w.Write(b)
			_, _ = w.Write([]byte("\n\n"))
			flusher.Flush()
		}
	}
}

func extractRemoteIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return strings.Trim(host, "[]")
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var _ = errors.New
