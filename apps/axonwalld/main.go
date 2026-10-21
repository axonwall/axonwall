package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/axonwall/monorepo/apps/axonwalld/engine"
	pb "github.com/axonwall/monorepo/apps/axonwalld/gen/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type AgentServer struct {
	pb.UnimplementedAgentServiceServer
	mu              sync.Mutex
	bundleDir       string
	activeHash      string
	lastGoodHash    string
	lastGoodScript  string
	candidateScript string
	pendingConfirm  bool
	confirmDeadline time.Time
	rollbackTimer   *time.Timer
	nodeId          string
	startTime       time.Time
	iapManager      *engine.IAPManager
	haEngine        *HAEngine
	sdwanProber     *SDWanProber
	pcapManager     *engine.PacketCaptureManager
	watchdog        *engine.WatchdogEngine
	nasManager       *engine.NasManager
	k3sManager       *engine.K3sManager
	vigilanteManager *engine.VigilanteManager
	etckeeperManager *engine.EtckeeperManager
	directoryManager *engine.DirectoryManager
}

func snapshotLkgConfig(bundleDir string) {
	lkgConfigDir := filepath.Join(bundleDir, "lkg-config")
	if err := os.MkdirAll(lkgConfigDir, 0700); err != nil {
		return
	}

	srcDirs := []string{"/etc/axonwall", "/var/lib/axonwall/etc-axonwall"}
	for _, srcDir := range srcDirs {
		entries, err := os.ReadDir(srcDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".json") || name == "interfaces.conf" {
				srcPath := filepath.Join(srcDir, name)
				dstPath := filepath.Join(lkgConfigDir, name)
				if data, err := os.ReadFile(srcPath); err == nil && len(data) > 0 {
					_ = os.WriteFile(dstPath, data, 0600)
				}
			}
		}
	}
}

func restoreLkgConfig(bundleDir string) {
	lkgConfigDir := filepath.Join(bundleDir, "lkg-config")
	entries, err := os.ReadDir(lkgConfigDir)
	if err != nil {
		return
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		srcPath := filepath.Join(lkgConfigDir, name)
		data, err := os.ReadFile(srcPath)
		if err != nil || len(data) == 0 {
			continue
		}

		targetDirs := []string{"/etc/axonwall", "/var/lib/axonwall/etc-axonwall"}
		for _, dir := range targetDirs {
			_ = os.MkdirAll(dir, 0755)
			_ = os.WriteFile(filepath.Join(dir, name), data, 0644)
		}
	}
}

func NewAgentServer(bundleDir string, iapManager *engine.IAPManager, haEngine *HAEngine, sdwanProber *SDWanProber, pcapManager *engine.PacketCaptureManager, watchdog *engine.WatchdogEngine, nasManager *engine.NasManager, k3sManager *engine.K3sManager, vigilanteManager *engine.VigilanteManager, etckeeperManager *engine.EtckeeperManager, directoryManager *engine.DirectoryManager) *AgentServer {
	hostname, _ := os.Hostname()

	initHash := ""
	lastGoodScript := ""
	for _, checkPath := range []string{filepath.Join(bundleDir, "last-known-good.nft"), "/etc/axonwall/last-known-good.nft", "/etc/nftables.conf"} {
		if data, err := os.ReadFile(checkPath); err == nil && len(data) > 0 {
			h := sha256.Sum256(data)
			initHash = hex.EncodeToString(h[:])
			lastGoodScript = string(data)
			break
		}
	}
	if lastGoodScript == "" {
		if out, err := exec.Command("nft", "list", "ruleset").CombinedOutput(); err == nil && len(out) > 0 {
			h := sha256.Sum256(out)
			initHash = hex.EncodeToString(h[:])
			lastGoodScript = string(out)
			if err := os.MkdirAll(bundleDir, 0700); err == nil {
				_ = os.WriteFile(filepath.Join(bundleDir, "last-known-good.nft"), out, 0600)
			}
		}
	}

	snapshotLkgConfig(bundleDir)

	return &AgentServer{
		bundleDir:        bundleDir,
		activeHash:       initHash,
		lastGoodHash:     initHash,
		lastGoodScript:   lastGoodScript,
		nodeId:           fmt.Sprintf("axonwall-%s", hostname),
		startTime:        time.Now(),
		iapManager:       iapManager,
		haEngine:         haEngine,
		sdwanProber:      sdwanProber,
		pcapManager:      pcapManager,
		watchdog:         watchdog,
		nasManager:       nasManager,
		k3sManager:       k3sManager,
		vigilanteManager: vigilanteManager,
		etckeeperManager: etckeeperManager,
		directoryManager: directoryManager,
	}
}

func (s *AgentServer) ApplyBundle(ctx context.Context, req *pb.ApplyBundleRequest) (*pb.ApplyBundleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Printf("[Agent] Received ApplyBundle request (hash: %s, timeout: %ds)", req.BundleHash, req.ConfirmTimeoutSeconds)

	if req.NftScript == "" {
		return nil, status.Error(codes.InvalidArgument, "nft_script cannot be empty")
	}

	// 1. Dry run syntax check using `nft -c -f`
	tmpFile, err := os.CreateTemp("", "axonwall-candidate-*.nft")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create temp candidate file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(req.NftScript); err != nil {
		_ = tmpFile.Close()
		return nil, status.Errorf(codes.Internal, "failed to write candidate script: %v", err)
	}
	_ = tmpFile.Close()

	validateCmd := exec.Command("nft", "-c", "-f", tmpFile.Name())
	if out, err := validateCmd.CombinedOutput(); err != nil {
		log.Printf("[Agent] nft validation error: %s", string(out))
		return &pb.ApplyBundleResponse{
			Success: false,
			Message: fmt.Sprintf("nftables syntax validation failed: %s", string(out)),
		}, nil
	}

	// Snapshot verified configuration before writing candidate changes
	if !s.pendingConfirm {
		snapshotLkgConfig(s.bundleDir)
	}

	// 2. Write optional bundle configuration files (e.g. kea, unbound, suricata, crowdsec)
	allowedPrefixes := []string{
		"/etc/axonwall/",
		"/tmp/",
		"/etc/network/",
		"/etc/suricata/",
		"/etc/crowdsec/",
		"/etc/kea/",
		"/etc/unbound/",
		"/etc/frr/",
		"/etc/wireguard/",
		"/etc/swanctl/",
		"/etc/haproxy/",
		"/etc/freeradius/",
	}
	for _, f := range req.Files {
		// Enforce safety: paths must reside within allowed system config locations or /tmp/
		cleanPath := filepath.Clean(f.Path)
		allowed := false
		for _, prefix := range allowedPrefixes {
			if strings.HasPrefix(cleanPath, prefix) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, status.Errorf(codes.PermissionDenied, "disallowed destination file path: %s", cleanPath)
		}
		// Reject symlinked intermediate directories (audit D-S02): the
		// prefix check and O_NOFOLLOW leaf open do not stop a planted
		// symlink one level up from redirecting the write outside the
		// allowed tree.
		for _, prefix := range allowedPrefixes {
			if strings.HasPrefix(cleanPath, prefix) {
				rel, _ := filepath.Rel(strings.TrimSuffix(prefix, "/"), filepath.Dir(cleanPath))
				cur := strings.TrimSuffix(prefix, "/")
				unsafe := false
				if rel != "." {
					for _, part := range strings.Split(rel, string(filepath.Separator)) {
						cur = filepath.Join(cur, part)
						if fi, err := os.Lstat(cur); err == nil && fi.Mode()&os.ModeSymlink != 0 {
							unsafe = true
							break
						}
					}
				}
				if unsafe {
					return nil, status.Errorf(codes.PermissionDenied, "destination path traverses a symlink: %s", cleanPath)
				}
			}
		}
		if err := os.MkdirAll(filepath.Dir(cleanPath), 0755); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create directories for %s: %v", cleanPath, err)
		}
		// Sanitize the caller-chosen mode (audit D-S02): plain permission
		// bits only (drops setuid/setgid/sticky), and never group- or
		// world-writable under the config tree.
		mode := os.FileMode(f.FileMode).Perm()
		if mode == 0 {
			if strings.HasPrefix(cleanPath, "/etc/axonwall/") && (strings.HasSuffix(cleanPath, ".json") || strings.HasSuffix(cleanPath, ".yaml") || strings.HasSuffix(cleanPath, ".yml")) {
				mode = 0600
			} else {
				mode = 0644
			}
		}
		mode &^= 0o022

		// Use syscall.O_NOFOLLOW to prevent symlink TOCTOU attacks
		file, err := os.OpenFile(cleanPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, mode)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to open file %s: %v", cleanPath, err)
		}
		if _, err := file.Write([]byte(f.Content)); err != nil {
			file.Close()
			return nil, status.Errorf(codes.Internal, "failed to write file %s: %v", cleanPath, err)
		}
		_ = file.Chmod(mode)
		file.Close()

		// Mirror /etc/axonwall/*.yaml (and conf.d/*.yaml) to /var/lib/axonwall/etc-axonwall/ for A/B rootfs persistence
		if strings.HasPrefix(cleanPath, "/etc/axonwall/") && (strings.HasSuffix(cleanPath, ".yaml") || strings.HasSuffix(cleanPath, ".yml")) {
			relPath := strings.TrimPrefix(cleanPath, "/etc/axonwall/")
			persistPath := filepath.Join("/var/lib/axonwall/etc-axonwall", relPath)
			_ = os.MkdirAll(filepath.Dir(persistPath), 0755)
			_ = os.WriteFile(persistPath, []byte(f.Content), mode)
		}

		if filepath.Base(cleanPath) == "zero_trust_apps.json" {
			log.Printf("[Agent] Applying Zero Trust IAP configuration")
			if err := s.iapManager.ApplyConfig([]byte(f.Content)); err != nil {
				log.Printf("[Agent] Warning: Failed to apply IAP config: %v", err)
			}
		}

		if filepath.Base(cleanPath) == "sdwan_config.json" {
			log.Printf("[Agent] Applying SD-WAN Gateway routing configuration")
			if err := s.sdwanProber.ReloadConfig(cleanPath); err != nil {
				log.Printf("[Agent] Warning: Failed to apply SD-WAN config: %v", err)
			}
		}

		if filepath.Base(cleanPath) == "ha_config.json" {
			log.Printf("[Agent] Applying High Availability & SQLite Sync configuration")
			if err := s.haEngine.ApplyFromJSON([]byte(f.Content)); err != nil {
				log.Printf("[Agent] Warning: Failed to apply HA config: %v", err)
			}
		}

		if filepath.Base(cleanPath) == "nas_config.json" && s.nasManager != nil {
			log.Printf("[Agent] Applying OpenZFS Storage & NAS Share configuration")
			if err := s.nasManager.ApplyConfig([]byte(f.Content)); err != nil {
				log.Printf("[Agent] Warning: Failed to apply NAS config: %v", err)
			}
		}

		if filepath.Base(cleanPath) == "k3s_config.json" && s.k3sManager != nil {
			log.Printf("[Agent] Applying K3s & OpenEBS cluster configuration")
			if err := s.k3sManager.ApplyConfig([]byte(f.Content)); err != nil {
				log.Printf("[Agent] Warning: Failed to apply K3s config: %v", err)
			}
		}

		if filepath.Base(cleanPath) == "vigilante_config.json" && s.vigilanteManager != nil {
			log.Printf("[Agent] Applying Vigilante Cyber Defense configuration")
		}
	}

	// Reconcile static routes whenever a bundle is applied
	if err := ReconcileStaticRoutes(); err != nil {
		log.Printf("[Agent] Warning: Static routes reconciliation: %v", err)
	}

	if s.etckeeperManager != nil && len(req.Files) > 0 {
		commitMsg := fmt.Sprintf("Axonwall configuration bundle applied (%s)", req.BundleHash)
		s.etckeeperManager.ScheduleCommit(commitMsg, "axonwall")
	}

	// 3. Backup current script for rollback
	s.candidateScript = req.NftScript

	// 4. Apply ruleset atomically
	applyCmd := exec.Command("nft", "-f", tmpFile.Name())
	if out, err := applyCmd.CombinedOutput(); err != nil {
		log.Printf("[Agent] Failed to apply nftables ruleset: %s", string(out))
		return &pb.ApplyBundleResponse{
			Success: false,
			Message: fmt.Sprintf("failed to execute atomic nft application: %s", string(out)),
		}, nil
	}

	if req.BundleHash != "" {
		s.activeHash = req.BundleHash
	} else {
		h := sha256.Sum256([]byte(req.NftScript))
		s.activeHash = hex.EncodeToString(h[:])
	}

	// 5. Reload any changed systemd units requested
	for _, svc := range req.ReloadServices {
		// Validate service name to prevent loading arbitrary unit files via path (e.g., /tmp/pwn.service)
		if strings.Contains(svc, "/") || strings.Contains(svc, "\\") || strings.HasPrefix(svc, ".") {
			log.Printf("[Agent] Rejected malformed/malicious service reload request: %s", svc)
			continue
		}
		log.Printf("[Agent] Reloading system service: %s", svc)
		_, _ = reloadOrRestartService(svc)
	}

	// 6. Setup Commit-Confirm deadline
	timeoutSec := req.ConfirmTimeoutSeconds
	if timeoutSec == 0 {
		timeoutSec = 120
	}

	if s.rollbackTimer != nil {
		s.rollbackTimer.Stop()
	}

	s.pendingConfirm = true
	s.confirmDeadline = time.Now().Add(time.Duration(timeoutSec) * time.Second)
	_ = os.MkdirAll("/run/axonwall", 0755)
	_ = os.WriteFile("/run/axonwall/commit-confirm.pending", []byte(fmt.Sprintf("COMMIT-CONFIRM (%ds)", timeoutSec)), 0644)

	s.rollbackTimer = time.AfterFunc(time.Duration(timeoutSec)*time.Second, func() {
		s.triggerAutoRollback(req.JobId)
	})

	log.Printf("[Agent] Configuration applied successfully. Pending confirmation for job %s (deadline: %v)", req.JobId, s.confirmDeadline)

	return &pb.ApplyBundleResponse{
		Success:             true,
		Message:             "Configuration applied. Pending confirmation before timeout.",
		ConfirmDeadlineUnix: s.confirmDeadline.Unix(),
	}, nil
}

func (s *AgentServer) executeRollback(reason string) error {
	if s.lastGoodScript == "" {
		lkgPath := filepath.Join(s.bundleDir, "last-known-good.nft")
		if data, err := os.ReadFile(lkgPath); err == nil && len(data) > 0 {
			s.lastGoodScript = string(data)
		} else {
			return fmt.Errorf("no previous last-known-good configuration available for rollback")
		}
	}

	if s.lastGoodScript != "" {
		tmpFile, err := os.CreateTemp("", "axonwall-rollback-*.nft")
		if err != nil {
			return fmt.Errorf("failed to create rollback temp file: %w", err)
		}
		_ = tmpFile.Close()
		defer os.Remove(tmpFile.Name())

		if err := os.WriteFile(tmpFile.Name(), []byte(s.lastGoodScript), 0644); err != nil {
			return fmt.Errorf("failed to write rollback script: %w", err)
		}

		cmd := exec.Command("nft", "-f", tmpFile.Name())
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[Agent] ERROR applying rollback ruleset: %s", string(out))
			return fmt.Errorf("failed to execute rollback nftables application: %s", string(out))
		}

		if s.lastGoodHash != "" {
			s.activeHash = s.lastGoodHash
		} else {
			h := sha256.Sum256([]byte(s.lastGoodScript))
			s.activeHash = hex.EncodeToString(h[:])
		}
	}

	// Restore LKG configuration files & state
	restoreLkgConfig(s.bundleDir)

	// Reconcile static routes with the restored configuration
	if err := ReconcileStaticRoutes(); err != nil {
		log.Printf("[Agent] Rollback: static routes reconciliation: %v", err)
	}

	s.pendingConfirm = false
	s.candidateScript = ""
	_ = os.Remove("/run/axonwall/commit-confirm.pending")
	log.Printf("[Agent] Successfully rolled back to last known good configuration (reason: %s).", reason)
	return nil
}

func (s *AgentServer) triggerAutoRollback(jobId string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.pendingConfirm {
		return
	}

	log.Printf("[Agent] WARNING: Commit-confirm deadline expired for job %s! Initiating automatic rollback.", jobId)
	if err := s.executeRollback(fmt.Sprintf("commit-confirm timeout for job %s", jobId)); err != nil {
		log.Printf("[Agent] Automatic rollback failed: %v", err)
	}
}

func (s *AgentServer) Confirm(ctx context.Context, req *pb.ConfirmRequest) (*pb.ConfirmResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Printf("[Agent] Received Confirm request for job %s", req.JobId)

	if s.rollbackTimer != nil {
		s.rollbackTimer.Stop()
		s.rollbackTimer = nil
	}

	s.pendingConfirm = false
	_ = os.Remove("/run/axonwall/commit-confirm.pending")
	if s.candidateScript != "" {
		s.lastGoodScript = s.candidateScript
		if s.activeHash == "" {
			h := sha256.Sum256([]byte(s.lastGoodScript))
			s.activeHash = hex.EncodeToString(h[:])
		}
		s.lastGoodHash = s.activeHash
	}

	// Save to bundle directory
	if err := os.MkdirAll(s.bundleDir, 0700); err == nil {
		lkgPath := filepath.Join(s.bundleDir, "last-known-good.nft")
		_ = os.WriteFile(lkgPath, []byte(s.lastGoodScript), 0600)
		log.Printf("[Agent] Persisted last-known-good configuration to %s", lkgPath)
	}

	// Snapshot confirmed YAML configuration to LKG
	snapshotLkgConfig(s.bundleDir)

	return &pb.ConfirmResponse{
		Success: true,
		Message: "Configuration confirmed and promoted to last-known-good.",
	}, nil
}

func (s *AgentServer) Rollback(ctx context.Context, req *pb.RollbackRequest) (*pb.RollbackResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Printf("[Agent] Manual Rollback requested: %s", req.Reason)

	if s.rollbackTimer != nil {
		s.rollbackTimer.Stop()
		s.rollbackTimer = nil
	}

	if err := s.executeRollback(req.Reason); err != nil {
		return &pb.RollbackResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.RollbackResponse{
		Success: true,
		Message: "Successfully rolled back to last known good configuration.",
	}, nil
}

func (s *AgentServer) GetStatus(ctx context.Context, req *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	uptime := uint64(time.Since(s.startTime).Seconds())

	// Gather network interfaces state
	var ifStates []*pb.InterfaceState
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			isUp := (iface.Flags & net.FlagUp) != 0
			var addrs []string
			if ifAddrs, err := iface.Addrs(); err == nil {
				for _, a := range ifAddrs {
					addrs = append(addrs, a.String())
				}
			}

			ifStates = append(ifStates, &pb.InterfaceState{
				Name:        iface.Name,
				Device:      iface.Name,
				IsUp:        isUp,
				IpAddresses: addrs,
			})
		}
	}

	var deadlineUnix int64 = 0
	if s.pendingConfirm {
		deadlineUnix = s.confirmDeadline.Unix()
	}

	ver := "0.2.9"
	if data, err := os.ReadFile("/etc/axonwall/version"); err == nil {
		if v := strings.TrimSpace(strings.Split(string(data), "\n")[0]); v != "" {
			ver = v
		}
	}

	return &pb.GetStatusResponse{
		NodeId:              s.nodeId,
		Version:             ver,
		UptimeSeconds:       uptime,
		ActiveBundleHash:    s.activeHash,
		PendingConfirm:      s.pendingConfirm,
		ConfirmDeadlineUnix: deadlineUnix,
		Interfaces:          ifStates,
	}, nil
}

func (s *AgentServer) ExecuteDiagnostic(ctx context.Context, req *pb.DiagnosticRequest) (*pb.DiagnosticResponse, error) {
	log.Printf("[Agent] Executing diagnostic %v on target %s", req.Type, req.Target)

	// Safe argument sanitation
	target := strings.TrimSpace(req.Target)
	if target == "" && int32(req.Type) != 5 {
		return nil, status.Error(codes.InvalidArgument, "target cannot be empty")
	}

	start := time.Now()

	// Special handling for Packet Capture diagnostic (Type 5 or target prefixed with pcap:)
	if int32(req.Type) == 5 || strings.HasPrefix(target, "pcap:") {
		filter := strings.TrimPrefix(target, "pcap:")
		if filter == "all" || filter == "any" {
			filter = ""
		}
		// Validate BPF filter against shell command injection
		if strings.ContainsAny(filter, ";|&$`\n\r<>(){}") {
			return nil, status.Error(codes.InvalidArgument, "invalid characters in packet capture filter")
		}
		captureCount := int(req.Count)
		if captureCount <= 0 || captureCount > 500 {
			captureCount = 50
		}
		iface := req.Interface
		if iface == "" {
			iface = "any"
		}
		res, err := s.pcapManager.RunCapture(ctx, iface, filter, captureCount)
		latency := time.Since(start).Milliseconds()
		if err != nil {
			return &pb.DiagnosticResponse{
				Success:   false,
				Output:    fmt.Sprintf("Packet capture failed: %v", err),
				LatencyMs: latency,
			}, nil
		}
		data, _ := json.Marshal(res)
		return &pb.DiagnosticResponse{
			Success:   true,
			Output:    string(data),
			LatencyMs: latency,
		}, nil
	}

	// Validate target to prevent flag injection (starts with '-') or command injection
	// Only allow valid hostnames or IP addresses.
	if strings.HasPrefix(target, "-") || strings.ContainsAny(target, ";&|\\$*{}[]()<>\"'") {
		return nil, status.Error(codes.InvalidArgument, "invalid target formatting")
	}

	count := req.Count
	if count == 0 || count > 10 {
		count = 3
	}

	var cmd *exec.Cmd

	switch req.Type {
	case pb.DiagnosticType_DIAGNOSTIC_TYPE_PING:
		cmd = exec.CommandContext(ctx, "ping", "-c", fmt.Sprintf("%d", count), "-W", "2", target)
	case pb.DiagnosticType_DIAGNOSTIC_TYPE_TRACEROUTE:
		cmd = exec.CommandContext(ctx, "traceroute", "-m", "15", "-w", "2", target)
	case pb.DiagnosticType_DIAGNOSTIC_TYPE_DNS_LOOKUP:
		cmd = exec.CommandContext(ctx, "host", "-W", "2", target)
	case pb.DiagnosticType_DIAGNOSTIC_TYPE_PORT_PROBE:
		port := req.Port
		if port == 0 || port > 65535 {
			port = 80
		}
		// Probe TCP port directly using net.DialTimeout
		d := net.Dialer{Timeout: 3 * time.Second}
		addr := net.JoinHostPort(target, strconv.Itoa(int(port)))
		conn, err := d.DialContext(ctx, "tcp", addr)
		latency := time.Since(start).Milliseconds()
		if err != nil {
			return &pb.DiagnosticResponse{
				Success:   false,
				Output:    fmt.Sprintf("Failed to connect to %s: %v", addr, err),
				LatencyMs: latency,
			}, nil
		}
		conn.Close()
		return &pb.DiagnosticResponse{
			Success:   true,
			Output:    fmt.Sprintf("Port %d on %s is OPEN (connected in %dms)", port, target, latency),
			LatencyMs: latency,
		}, nil
	default:
		return nil, status.Error(codes.InvalidArgument, "unsupported diagnostic type")
	}

	out, err := cmd.CombinedOutput()
	latency := time.Since(start).Milliseconds()

	return &pb.DiagnosticResponse{
		Success:   err == nil,
		Output:    string(out),
		LatencyMs: latency,
	}, nil
}

func applyBootInterfaces() {
	confPath := "/etc/axonwall/interfaces.conf"
	data, err := os.ReadFile(confPath)
	if err != nil {
		return
	}

	config := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		config[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	// Validate the file's values before they reach `ip` argv or
	// /etc/resolv.conf (audit D-S10): interface names follow the same
	// shape the packet-capture path enforces, DNS servers and the
	// gateway must be real IPs, static addresses must parse.
	validDev := func(dev string) string {
		if dev == "" || strings.HasPrefix(dev, "-") {
			return ""
		}
		for _, r := range dev {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
				return ""
			}
		}
		return dev
	}
	validIP := func(ip string) string {
		if net.ParseIP(ip) == nil {
			return ""
		}
		return ip
	}
	validCIDR := func(cidr string) string {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			if net.ParseIP(cidr) == nil {
				return ""
			}
		}
		return cidr
	}

	wanDev := validDev(config["WAN_INTERFACE"])
	wanMode := config["WAN_MODE"]
	wanIP := validCIDR(config["WAN_IPV4_ADDRESS"])
	wanGw := validIP(config["WAN_IPV4_GATEWAY"])
	wanDNS1 := validIP(config["WAN_DNS1"])
	wanDNS2 := validIP(config["WAN_DNS2"])

	lanDev := validDev(config["LAN_INTERFACE"])
	lanIP := validCIDR(config["LAN_IPV4_ADDRESS"])

	opt1Dev := validDev(config["OPT1_INTERFACE"])
	opt1Mode := config["OPT1_MODE"]
	opt1IP := validCIDR(config["OPT1_IPV4_ADDRESS"])

	opt2Dev := validDev(config["OPT2_INTERFACE"])
	opt2Mode := config["OPT2_MODE"]
	opt2IP := validCIDR(config["OPT2_IPV4_ADDRESS"])

	// 1. WAN configuration
	if wanDev != "" {
		_ = exec.Command("ip", "link", "set", wanDev, "up").Run()
		if wanMode == "static" && wanIP != "" {
			log.Printf("[Agent] Boot-apply: configuring static IP %s on WAN (%s)", wanIP, wanDev)
			// Check if IP is already configured
			out, _ := exec.Command("ip", "-4", "addr", "show", "dev", wanDev).CombinedOutput()
			if !strings.Contains(string(out), strings.Split(wanIP, "/")[0]) {
				_ = exec.Command("ip", "addr", "flush", "dev", wanDev).Run()
				if addOut, err := exec.Command("ip", "addr", "add", wanIP, "dev", wanDev).CombinedOutput(); err != nil {
					log.Printf("[Agent] Boot-apply: failed to assign WAN IP %s: %s", wanIP, string(addOut))
				}
			}
			if wanGw != "" {
				_ = exec.Command("ip", "route", "replace", "default", "via", wanGw, "dev", wanDev).Run()
			}
			if wanDNS1 != "" || wanDNS2 != "" {
				if rData, rErr := os.ReadFile("/etc/resolv.conf"); rErr != nil || len(strings.TrimSpace(string(rData))) == 0 {
					var resolv strings.Builder
					resolv.WriteString("# Generated by Axonwall\n")
					if wanDNS1 != "" {
						resolv.WriteString(fmt.Sprintf("nameserver %s\n", wanDNS1))
					}
					if wanDNS2 != "" {
						resolv.WriteString(fmt.Sprintf("nameserver %s\n", wanDNS2))
					}
					_ = os.WriteFile("/etc/resolv.conf", []byte(resolv.String()), 0644)
				}
			}
		} else if wanMode == "dhcp" {
			out, _ := exec.Command("ip", "-4", "addr", "show", "dev", wanDev).CombinedOutput()
			if !strings.Contains(string(out), "inet ") {
				log.Printf("[Agent] Boot-apply: starting DHCP client on WAN (%s)", wanDev)
				triggerDhcpClient(wanDev)
			}
		}
	}

	// 2. LAN configuration
	if lanDev != "" {
		_ = exec.Command("ip", "link", "set", lanDev, "up").Run()
		targetLanIP := lanIP
		if targetLanIP == "" {
			targetLanIP = "192.168.1.1/24"
		}
		out, _ := exec.Command("ip", "-4", "addr", "show", "dev", lanDev).CombinedOutput()
		if !strings.Contains(string(out), strings.Split(targetLanIP, "/")[0]) {
			log.Printf("[Agent] Boot-apply: assigning static IP %s to LAN (%s)", targetLanIP, lanDev)
			_ = exec.Command("ip", "addr", "add", targetLanIP, "dev", lanDev).Run()
		}
	}

	// 3. OPT1 configuration
	if opt1Dev != "" {
		_ = exec.Command("ip", "link", "set", opt1Dev, "up").Run()
		if opt1Mode == "static" && opt1IP != "" {
			out, _ := exec.Command("ip", "-4", "addr", "show", "dev", opt1Dev).CombinedOutput()
			if !strings.Contains(string(out), strings.Split(opt1IP, "/")[0]) {
				_ = exec.Command("ip", "addr", "add", opt1IP, "dev", opt1Dev).Run()
			}
		} else if opt1Mode == "dhcp" {
			out, _ := exec.Command("ip", "-4", "addr", "show", "dev", opt1Dev).CombinedOutput()
			if !strings.Contains(string(out), "inet ") {
				log.Printf("[Agent] Boot-apply: starting DHCP client on OPT1 (%s)", opt1Dev)
				triggerDhcpClient(opt1Dev)
			}
		}
	}

	// 4. OPT2 configuration
	if opt2Dev != "" {
		_ = exec.Command("ip", "link", "set", opt2Dev, "up").Run()
		if opt2Mode == "static" && opt2IP != "" {
			out, _ := exec.Command("ip", "-4", "addr", "show", "dev", opt2Dev).CombinedOutput()
			if !strings.Contains(string(out), strings.Split(opt2IP, "/")[0]) {
				_ = exec.Command("ip", "addr", "add", opt2IP, "dev", opt2Dev).Run()
			}
		} else if opt2Mode == "dhcp" {
			out, _ := exec.Command("ip", "-4", "addr", "show", "dev", opt2Dev).CombinedOutput()
			if !strings.Contains(string(out), "inet ") {
				log.Printf("[Agent] Boot-apply: starting DHCP client on OPT2 (%s)", opt2Dev)
				triggerDhcpClient(opt2Dev)
			}
		}
	}

	// 5. Static routes configuration
	if err := ReconcileStaticRoutes(); err != nil {
		log.Printf("[Agent] Boot-apply: static routes reconciliation: %v", err)
	}
}

func reconcileBootAntiLockoutNft(hasLkgBundle bool) {
	data, err := os.ReadFile("/etc/axonwall/interfaces.conf")
	if err != nil {
		return
	}
	config := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		config[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	validDev := func(dev string) string {
		if dev == "" || strings.HasPrefix(dev, "-") {
			return ""
		}
		for _, r := range dev {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
				return ""
			}
		}
		return dev
	}

	wanDev := validDev(config["WAN_INTERFACE"])
	lanDev := validDev(config["LAN_INTERFACE"])
	opt1Dev := validDev(config["OPT1_INTERFACE"])
	opt2Dev := validDev(config["OPT2_INTERFACE"])

	internalHasLink := false
	for _, dev := range []string{lanDev, opt1Dev, opt2Dev} {
		if dev == "" {
			continue
		}
		if cData, cErr := os.ReadFile(filepath.Join("/sys/class/net", dev, "carrier")); cErr == nil && strings.TrimSpace(string(cData)) == "1" {
			internalHasLink = true
			break
		}
	}

	// Update /usr/share/axonwall/lockdown.nft so wan_interfaces matches actual topology
	lockdownPath := "/usr/share/axonwall/lockdown.nft"
	if lData, lErr := os.ReadFile(lockdownPath); lErr == nil {
		content := string(lData)
		newElements := `elements = { "wan0" }`
		if internalHasLink && wanDev != "" && wanDev != "wan0" && wanDev != lanDev && wanDev != opt1Dev && wanDev != opt2Dev {
			newElements = fmt.Sprintf(`elements = { "wan0", %q }`, wanDev)
		}
		var updatedLines []string
		for _, line := range strings.Split(content, "\n") {
			if strings.Contains(line, "elements = {") {
				indent := line[:strings.Index(line, "elements")]
				updatedLines = append(updatedLines, indent+newElements)
			} else {
				updatedLines = append(updatedLines, line)
			}
		}
		_ = os.WriteFile(lockdownPath, []byte(strings.Join(updatedLines, "\n")), 0644)
		if !hasLkgBundle {
			_ = exec.Command("nft", "-f", lockdownPath).Run()
		}
	}

	// Ensure configured internal interfaces (LAN, OPT1, OPT2) are permitted for anti-lockout in inet axonwall input
	currentRulesOut, _ := exec.Command("nft", "list", "chain", "inet", "axonwall", "input").CombinedOutput()
	currentRules := string(currentRulesOut)
	for _, entry := range []struct {
		role string
		dev  string
	}{
		{"lan", lanDev},
		{"opt1", opt1Dev},
		{"opt2", opt2Dev},
	} {
		if entry.dev == "" || entry.dev == wanDev {
			continue
		}
		if !strings.Contains(currentRules, fmt.Sprintf(`iifname %q tcp dport`, entry.dev)) {
			_ = exec.Command(
				"nft", "insert", "rule", "inet", "axonwall", "input",
				"iifname", entry.dev,
				"tcp", "dport", "{ 22, 80, 443, 2966, 3000 }",
				"accept", "comment", fmt.Sprintf("\"anti-lockout-%s\"", entry.role),
			).Run()
		}
	}
}

func syncFile(srcPath, dstPath string, perm os.FileMode) {
	srcInfo, err1 := os.Stat(srcPath)
	if err1 != nil {
		return
	}
	dstInfo, err2 := os.Stat(dstPath)
	if err2 != nil || srcInfo.ModTime().After(dstInfo.ModTime()) {
		if data, err := os.ReadFile(srcPath); err == nil {
			_ = os.WriteFile(dstPath, data, perm)
		}
	}
}

func syncPersistentYamlConfigs() {
	srcDir := "/var/lib/axonwall/etc-axonwall"
	dstDir := "/etc/axonwall"
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return
	}
	_ = os.MkdirAll(dstDir, 0755)
	_ = os.MkdirAll(filepath.Join(dstDir, "conf.d"), 0755)

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			if name == "conf.d" {
				confEntries, err := os.ReadDir(filepath.Join(srcDir, "conf.d"))
				if err == nil {
					for _, ce := range confEntries {
						if ce.IsDir() {
							continue
						}
						cName := ce.Name()
						if strings.HasSuffix(cName, ".yaml") || strings.HasSuffix(cName, ".yml") {
							syncFile(filepath.Join(srcDir, "conf.d", cName), filepath.Join(dstDir, "conf.d", cName), 0600)
						}
					}
				}
			}
			continue
		}

		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			syncFile(filepath.Join(srcDir, name), filepath.Join(dstDir, name), 0600)
		}
	}

	// Also ensure administrative credentials and controller configs are synced
	syncFile(filepath.Join(srcDir, "admin.env"), filepath.Join(dstDir, "admin.env"), 0600)
	syncFile(filepath.Join(srcDir, "controller.env"), filepath.Join(dstDir, "controller.env"), 0600)
}

func main() {
	notifyState := flag.String("notify", "", "Send state change notification to running axonwalld HA engine (MASTER/BACKUP/FAULT)")
	socketPath := flag.String("socket", "/run/axonwall/agent.sock", "Path to agent Unix socket")
	bundleDir := flag.String("bundle-dir", "/var/lib/axonwall/bundles", "Directory for storing last-known-good bundles")
	bootApply := flag.Bool("boot-apply", false, "Apply last-known-good configuration immediately on boot")
	flag.Parse()

	if *notifyState != "" {
		if err := sendHANotification(*notifyState); err != nil {
			log.Fatalf("Failed to send HA notification: %v", err)
		}
		log.Printf("Successfully notified axonwalld of HA state: %s", *notifyState)
		os.Exit(0)
	}

	log.Printf("Starting Axonwall Privileged Agent (axonwalld)")
	syncPersistentYamlConfigs()

	// If boot-apply is requested, load last-known-good configuration and ensure network interfaces are configured
	if *bootApply {
		applyBootInterfaces()

		lkgPath := filepath.Join(*bundleDir, "last-known-good.nft")
		hasLkg := false
		if _, err := os.Stat(lkgPath); err == nil {
			log.Printf("[Agent] Early-boot: applying last-known-good bundle from %s", lkgPath)
			cmd := exec.Command("nft", "-f", lkgPath)
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("[Agent] Failed to apply boot bundle: %s", string(out))
			} else {
				log.Printf("[Agent] Boot bundle applied successfully.")
				hasLkg = true
			}
		}
		reconcileBootAntiLockoutNft(hasLkg)
		if err := ReconcileStaticRoutes(); err != nil {
			log.Printf("[Agent] Early-boot: static routes reconciliation: %v", err)
		}
	}

	// Ensure directory for socket exists
	sockDir := filepath.Dir(*socketPath)
	if err := os.MkdirAll(sockDir, 0770); err != nil {
		log.Fatalf("Failed to create socket directory %s: %v", sockDir, err)
	}
	chownSocketToAPIGroup(sockDir, 0770)
	_ = os.Remove(*socketPath)

	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("Failed to listen on unix socket %s: %v", *socketPath, err)
	}
	defer os.Remove(*socketPath)

	// Socket permissions: 0660 root:axonwall-api so control plane group can access
	chownSocketToAPIGroup(*socketPath, 0660)

	// Agent API authentication: every gRPC call and every HTTP REST
	// call must carry the per-install agent token (see agent_auth.go).
	agentToken, agentTokenSource := resolveAgentToken()
	log.Printf("[Agent] Agent API token authentication enabled (source: %s)", agentTokenSource)

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(agentTokenUnaryInterceptor(agentToken)),
		grpc.StreamInterceptor(agentTokenStreamInterceptor(agentToken)),
	)

	iapManager := engine.NewIAPManager()
	nasManager := engine.NewNasManager()
	k3sManager := engine.NewK3sManager()
	haEngine := NewHAEngine(nasManager)
	haEngine.SetK3sManager(k3sManager)
	if err := haEngine.StartSocketListener(); err != nil {
		log.Printf("[Agent] Warning: Failed to start HA socket listener: %v", err)
	}

	sdwanProber := NewSDWanProber()
	pcapManager := engine.NewPacketCaptureManager()
	packetStreamMgr := engine.NewPacketStreamManager(pcapManager)
	hardwareMgr := engine.NewHardwareManager()
	terminalMgr := engine.NewTerminalManager()
	taskManager := engine.NewTaskManager()
	virtManager := engine.NewVirtManager(taskManager, nasManager)
	vfioManager := engine.NewVFIOManager()
	consoleProxy := engine.NewConsoleProxy()
	watchdog := engine.NewWatchdogEngine()
	watchdog.Start()
	vigilanteManager := engine.NewVigilanteManager("/var/lib/axonwall/vigilante")
	etckeeperManager := engine.NewEtckeeperManager("/etc")
	if etckeeperManager.IsInstalled() {
		_ = etckeeperManager.Init()
	}
	userManager := engine.NewUserManager(etckeeperManager)
	directoryManager := engine.NewDirectoryManager(userManager, etckeeperManager)
	pluginManager := engine.NewPluginManager("/var/lib/axonwall")
	haEngine.SetDirectoryManager(directoryManager)

	go func() {
		if err := directoryManager.Bootstrap("axonwall.local", 1); err != nil {
			log.Printf("[Directory] Warning during initial OpenLDAP bootstrap: %v", err)
		}
	}()

	agentServer := NewAgentServer(*bundleDir, iapManager, haEngine, sdwanProber, pcapManager, watchdog, nasManager, k3sManager, vigilanteManager, etckeeperManager, directoryManager)
	pb.RegisterAgentServiceServer(grpcServer, agentServer)

	// Start eBPF Manager
	ebpfManager := engine.NewEBPFManager()
	if err := ebpfManager.Start([]string{"eth0", "lo"}); err != nil {
		log.Printf("[Agent] Warning: Failed to start eBPF manager: %v", err)
	}

	// Start HTTP REST listener over Unix socket for local UI and management tooling
	apiSocketPath := filepath.Join(sockDir, "agent-api.sock")
	_ = os.Remove(apiSocketPath)
	apiListener, err := net.Listen("unix", apiSocketPath)
	var apiServer *http.Server
	if err != nil {
		log.Printf("[Agent] Warning: Failed to listen on API unix socket %s: %v", apiSocketPath, err)
	} else {
		chownSocketToAPIGroup(apiSocketPath, 0660)
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
			resp, err := agentServer.GetStatus(r.Context(), &pb.GetStatusRequest{})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/v1/apply", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, fmt.Sprintf("failed to read body: %v", err), http.StatusBadRequest)
				return
			}
			var req pb.ApplyBundleRequest
			unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
			if err := unmarshaler.Unmarshal(bodyBytes, &req); err != nil {
				if errJson := json.Unmarshal(bodyBytes, &req); errJson != nil {
					http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
					return
				}
			}
			var rawPayload struct {
				Files []struct {
					Path     string `json:"path"`
					FileMode uint32 `json:"fileMode"`
				} `json:"files"`
			}
			if err := json.Unmarshal(bodyBytes, &rawPayload); err == nil && len(rawPayload.Files) > 0 {
				for i, rawF := range rawPayload.Files {
					if i < len(req.Files) && req.Files[i].FileMode == 0 && rawF.FileMode != 0 {
						req.Files[i].FileMode = rawF.FileMode
					}
				}
			}
			resp, err := agentServer.ApplyBundle(r.Context(), &req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/v1/routes/reconcile", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if err := ReconcileStaticRoutes(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Static routes reconciled successfully"})
		})
		mux.HandleFunc("/v1/confirm", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req pb.ConfirmRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			resp, err := agentServer.Confirm(r.Context(), &req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/v1/rollback", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req pb.RollbackRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			resp, err := agentServer.Rollback(r.Context(), &req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/v1/diagnostic", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req pb.DiagnosticRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
				return
			}
			resp, err := agentServer.ExecuteDiagnostic(r.Context(), &req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/v1/system/partitions", func(w http.ResponseWriter, r *http.Request) {
			status := watchdog.GetStatus()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(status)
		})
		mux.HandleFunc("/v1/system/slot/activate", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				Slot string `json:"slot"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
				return
			}
			if err := watchdog.ActivateSlot(req.Slot); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"message": fmt.Sprintf("Slot %s armed as active slot for next boot", req.Slot),
			})
		})
		mux.HandleFunc("/v1/system/health/verify", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			status := watchdog.RunVerification()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(status)
		})
		mux.HandleFunc("/v1/system/update", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				Slot    string `json:"slot"`
				Version string `json:"version"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
				return
			}
			msg, err := watchdog.ApplyFirmwareUpdate(req.Slot, req.Version)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": false,
					"message": err.Error(),
				})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":    true,
				"message":    msg,
				"targetSlot": strings.ToUpper(strings.TrimSpace(req.Slot)),
				"newVersion": strings.TrimSpace(strings.TrimPrefix(req.Version, "v")),
			})
		})
		mux.HandleFunc("/v1/system/power", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				Action string `json:"action"` // "reboot" | "poweroff" | "shutdown"
				Slot   string `json:"slot"`   // optional "A" | "B"
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
				return
			}
			action := strings.ToLower(strings.TrimSpace(req.Action))
			if action != "reboot" && action != "poweroff" && action != "shutdown" {
				http.Error(w, "invalid power action, must be 'reboot' or 'poweroff'", http.StatusBadRequest)
				return
			}

			targetSlot := strings.ToUpper(strings.TrimSpace(req.Slot))
			if targetSlot == "A" || targetSlot == "B" {
				if err := watchdog.ActivateSlot(targetSlot); err != nil {
					http.Error(w, fmt.Sprintf("failed to activate target slot %s: %v", targetSlot, err), http.StatusBadRequest)
					return
				}
				log.Printf("[Agent] Armed Slot %s in bootloader before reboot", targetSlot)
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"message": fmt.Sprintf("System %s command accepted. Performing clean shutdown...", action),
				"action":  action,
				"slot":    targetSlot,
			})

			go func() {
				time.Sleep(500 * time.Millisecond)
				if action == "reboot" {
					log.Printf("[Agent] System reboot initiated via API")
					_ = exec.Command("systemctl", "reboot").Run()
					_ = exec.Command("/sbin/reboot").Run()
					_ = exec.Command("reboot").Run()
				} else {
					log.Printf("[Agent] System poweroff initiated via API")
					_ = exec.Command("systemctl", "poweroff").Run()
					_ = exec.Command("/sbin/poweroff").Run()
					_ = exec.Command("poweroff").Run()
					_ = exec.Command("/sbin/halt", "-p").Run()
					_ = exec.Command("halt", "-p").Run()
				}
			}()
		})
		mux.HandleFunc("/v1/events/packets", packetStreamMgr.HandleStreamSSE)
		mux.HandleFunc("/v1/system/telemetry/hardware", func(w http.ResponseWriter, r *http.Request) {
			telem, err := hardwareMgr.CollectTelemetry()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(telem)
		})
		mux.HandleFunc("/v1/terminal/exec", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req engine.TerminalExecRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
				return
			}
			resp, err := terminalMgr.Execute(r.Context(), req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/v1/nas/disks", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"disks": nasManager.DiscoverDisks(),
			})
		})
		mux.HandleFunc("/v1/nas/pools", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pools": nasManager.ListPools(),
			})
		})
		mux.HandleFunc("/v1/nas/snapshots", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				var req struct {
					Dataset string `json:"dataset"`
					Label   string `json:"label"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				snap, err := nasManager.CreateSnapshot(req.Dataset, req.Label)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success":  true,
					"snapshot": snap,
				})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"snapshots": nasManager.ListSnapshots(),
			})
		})
		mux.HandleFunc("/v1/nas/scrub", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				Pool string `json:"pool"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := nasManager.ScrubPool(req.Pool); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"message": fmt.Sprintf("Started ZFS scrub on pool %s", req.Pool),
			})
		})
		mux.HandleFunc("/v1/k3s/status", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(k3sManager.GetStatus())
		})
		mux.HandleFunc("/v1/k3s/join", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				PeerIp    string `json:"peerIp"`
				SyncPort  int    `json:"syncPort"`
				AuthToken string `json:"authToken"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := k3sManager.TriggerAutoJoin(req.PeerIp, req.SyncPort, req.AuthToken); err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"message": fmt.Sprintf("Auto-joined K3s cluster at %s", net.JoinHostPort(req.PeerIp, "6443")),
			})
		})

		// Virt / Hypervisor APIs
		mux.HandleFunc("/v1/virt/vms", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				var req struct {
					Action string                 `json:"action"` // "start", "stop", "reset", "pause", "resume", "register"
					VMID   int                    `json:"vmid"`
					Force  bool                   `json:"force"`
					Spec   *engine.CompiledVmSpec `json:"spec,omitempty"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				if req.Action == "register" && req.Spec != nil {
					virtManager.RegisterVMSpec(*req.Spec)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
					return
				}
				user := "root@axonwall"
				switch req.Action {
				case "start":
					upid, err := virtManager.StartVM(req.VMID, user)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "upid": upid})
				case "stop":
					upid, err := virtManager.StopVM(req.VMID, req.Force, user)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "upid": upid})
				case "reset":
					if err := virtManager.ResetVM(req.VMID); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
				case "pause":
					if err := virtManager.PauseVM(req.VMID); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
				case "resume":
					if err := virtManager.ResumeVM(req.VMID); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
				default:
					http.Error(w, "Unknown VM action: "+req.Action, http.StatusBadRequest)
				}
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"vms": virtManager.ListVMs(),
			})
		})

		mux.HandleFunc("/v1/virt/containers", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				var req struct {
					Action string                 `json:"action"` // "start", "stop", "register"
					CTID   int                    `json:"ctid"`
					Force  bool                   `json:"force"`
					Spec   *engine.CompiledCtSpec `json:"spec,omitempty"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				if req.Action == "register" && req.Spec != nil {
					virtManager.RegisterCTSpec(*req.Spec)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
					return
				}
				user := "root@axonwall"
				switch req.Action {
				case "start":
					upid, err := virtManager.StartContainer(req.CTID, user)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "upid": upid})
				case "stop":
					upid, err := virtManager.StopContainer(req.CTID, req.Force, user)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "upid": upid})
				default:
					http.Error(w, "Unknown container action: "+req.Action, http.StatusBadRequest)
				}
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"containers": virtManager.ListContainers(),
			})
		})

		mux.HandleFunc("/v1/virt/pci", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				var req struct {
					Action string `json:"action"` // "bind", "unbind", "sriov"
					BDF    string `json:"bdf"`
					NumVfs int    `json:"numVfs"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				switch req.Action {
				case "bind":
					if err := vfioManager.BindVfio(req.BDF); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
				case "unbind":
					if err := vfioManager.UnbindVfio(req.BDF); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
				case "sriov":
					if err := vfioManager.ConfigureSriov(req.BDF, req.NumVfs); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
				default:
					http.Error(w, "Unknown PCI action: "+req.Action, http.StatusBadRequest)
				}
				return
			}
			devices, err := vfioManager.DiscoverPciDevices()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": devices})
		})

		mux.HandleFunc("/v1/virt/isos", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				var req struct {
					URL      string `json:"url"`
					Filename string `json:"filename"`
					Pool     string `json:"pool"`
					Sha256   string `json:"sha256"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				user := "root@axonwall"
				upid, err := virtManager.DownloadISO(req.URL, req.Filename, req.Pool, req.Sha256, user)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "upid": upid})
				return
			}
			pool := r.URL.Query().Get("pool")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"isos": virtManager.ListISOs(pool),
			})
		})

		mux.HandleFunc("/v1/virt/backups", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				var req struct {
					TargetType string `json:"targetType"` // "vm" or "lxc"
					TargetID   int    `json:"targetId"`
					Pool       string `json:"pool"`
					DestType   string `json:"destType"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				user := "root@axonwall"
				upid, err := virtManager.RunBackup(req.TargetType, req.TargetID, req.Pool, req.DestType, user)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "upid": upid})
				return
			}
			pool := r.URL.Query().Get("pool")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"backups": virtManager.ListBackups(pool),
			})
		})

		mux.HandleFunc("/v1/virt/console/ws", consoleProxy.ServeHTTP)

		mux.HandleFunc("/v1/tasks", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tasks": taskManager.ListTasks(50),
			})
		})

		mux.HandleFunc("/v1/tasks/log", taskManager.HandleStreamTaskLogSSE)

		// Vigilante Cyber Defense / SOAR APIs
		mux.HandleFunc("/v1/vigilante/soar/block-ip", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				IP         string `json:"ip"`
				TimeoutSec int    `json:"timeoutSec"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
				return
			}
			if err := vigilanteManager.BlockIP(req.IP, req.TimeoutSec); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"message": fmt.Sprintf("Successfully quarantined and blocked IP %s", req.IP),
			})
		})

		mux.HandleFunc("/v1/vigilante/soar/unblock-ip", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				IP string `json:"ip"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
				return
			}
			if err := vigilanteManager.UnblockIP(req.IP); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"message": fmt.Sprintf("Successfully unblocked IP %s", req.IP),
			})
		})

		mux.HandleFunc("/v1/vigilante/soar/blocked-ips", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"blockedIPs": vigilanteManager.ListBlockedIPs(),
			})
		})

		mux.HandleFunc("/v1/vigilante/vault/provision", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				Pool    string `json:"pool"`
				Dataset string `json:"dataset"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
				return
			}
			if err := vigilanteManager.ProvisionEvidenceVault(req.Pool, req.Dataset); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"message": "Vigilante evidence vault provisioned successfully",
			})
		})

		mux.HandleFunc("/v1/vigilante/vault/snapshot", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				Pool       string `json:"pool"`
				Dataset    string `json:"dataset"`
				IncidentID string `json:"incidentId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
				return
			}
			snap, err := vigilanteManager.CreateIncidentSnapshot(req.Pool, req.Dataset, req.IncidentID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":  true,
				"snapshot": snap,
			})
		})

		mux.HandleFunc("/v1/vigilante/telemetry/stream", vigilanteManager.StreamLiveTelemetry)

		// Etckeeper /etc change tracking APIs
		mux.HandleFunc("/v1/system/etckeeper/status", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(etckeeperManager.GetStatus())
		})

		mux.HandleFunc("/v1/system/etckeeper/commit", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				Message string `json:"message"`
				Author  string `json:"author"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
				return
			}
			if err := etckeeperManager.Commit(req.Message, req.Author); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"message": "Committed /etc changes to etckeeper successfully",
			})
		})

		mux.HandleFunc("/v1/system/etckeeper/history", func(w http.ResponseWriter, r *http.Request) {
			history, err := etckeeperManager.GetHistory(25)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"history": history,
			})
		})

		mux.HandleFunc("/v1/system/etckeeper/diff", func(w http.ResponseWriter, r *http.Request) {
			commitHash := r.URL.Query().Get("commit")
			diff, err := etckeeperManager.GetDiff(commitHash)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"diff": diff,
			})
		})

		// OpenLDAP Identity Directory & POSIX Group Management APIs
		writeDirError := func(w http.ResponseWriter, msg string, code int) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": false,
				"error":   msg,
				"message": msg,
			})
		}

		mux.HandleFunc("/v1/system/users", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				users, err := directoryManager.ListUsers()
				if err != nil {
					writeDirError(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"users": users})
			case http.MethodPost:
				var req engine.CreateUserRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					writeDirError(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
					return
				}
				if err := directoryManager.CreateUser(req); err != nil {
					writeDirError(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": true,
					"message": fmt.Sprintf("Created directory user %s successfully", req.Username),
				})
			default:
				writeDirError(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		mux.HandleFunc("/v1/system/users/auth", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				writeDirError(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req engine.AuthUserRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeDirError(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
				return
			}
			resp := directoryManager.Authenticate(req)
			w.Header().Set("Content-Type", "application/json")
			if !resp.Success {
				w.WriteHeader(http.StatusUnauthorized)
			}
			_ = json.NewEncoder(w).Encode(resp)
		})

		mux.HandleFunc("/v1/system/users/", func(w http.ResponseWriter, r *http.Request) {
			username := strings.TrimPrefix(r.URL.Path, "/v1/system/users/")
			username = strings.TrimSpace(username)
			if username == "" {
				writeDirError(w, "Username required in path", http.StatusBadRequest)
				return
			}

			switch r.Method {
			case http.MethodPut:
				var req engine.UpdateUserRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					writeDirError(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
					return
				}
				if err := directoryManager.UpdateUser(username, req); err != nil {
					writeDirError(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": true,
					"message": fmt.Sprintf("Updated directory user %s successfully", username),
				})
			case http.MethodDelete:
				removeHome := r.URL.Query().Get("removeHome") == "true"
				if err := directoryManager.DeleteUser(username, removeHome); err != nil {
					writeDirError(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": true,
					"message": fmt.Sprintf("Deleted directory user %s successfully", username),
				})
			default:
				writeDirError(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		mux.HandleFunc("/v1/system/groups", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				groups, err := directoryManager.ListGroups()
				if err != nil {
					writeDirError(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"groups": groups})
			case http.MethodPost:
				var req struct {
					Name string `json:"name"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					writeDirError(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
					return
				}
				if _, err := directoryManager.EnsureLDAPGroupExists(req.Name, 0); err != nil {
					writeDirError(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": true,
					"message": fmt.Sprintf("Directory group %s ensured successfully", req.Name),
				})
			default:
				writeDirError(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		mux.HandleFunc("/v1/system/directory/status", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(directoryManager.GetStatus())
		})

		mux.HandleFunc("/v1/system/directory/policy", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut && r.Method != http.MethodPost {
				writeDirError(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var policy engine.PasswordPolicyConfig
			if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
				writeDirError(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
				return
			}
			if err := directoryManager.UpdatePasswordPolicy(policy); err != nil {
				writeDirError(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"message": "OpenLDAP password policy updated successfully",
				"policy":  policy,
			})
		})

		mux.HandleFunc("/v1/system/directory/migrate", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				writeDirError(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			migrated, err := directoryManager.MigrateLocalHumanUsers()
			if err != nil {
				writeDirError(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":  true,
				"migrated": migrated,
				"message":  fmt.Sprintf("Migrated %d local human account(s) into OpenLDAP", len(migrated)),
			})
		})

		// Extension Plugins Lifecycle & Management APIs
		mux.HandleFunc("/v1/system/plugins", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"plugins":  pluginManager.ListPlugins(),
				"osFamily": engine.DetectOSFamily(),
			})
		})

		mux.HandleFunc("/v1/system/plugins/action", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req engine.PluginActionRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
				return
			}
			var resp engine.PluginActionResponse
			switch req.Action {
			case "install":
				resp = pluginManager.InstallPlugin(req.PluginID)
			case "uninstall", "remove":
				resp = pluginManager.UninstallPlugin(req.PluginID)
			case "reconfigure", "re-sync":
				resp = pluginManager.ReconfigurePlugin(req.PluginID)
			default:
				resp = engine.PluginActionResponse{
					Success: false,
					Message: fmt.Sprintf("Unsupported action '%s'", req.Action),
				}
			}
			w.Header().Set("Content-Type", "application/json")
			if !resp.Success {
				w.WriteHeader(http.StatusBadRequest)
			}
			_ = json.NewEncoder(w).Encode(resp)
		})

		apiServer = &http.Server{Handler: agentTokenHTTPMiddleware(agentToken, mux)}
		go func() {
			log.Printf("[Agent] Listening on REST Unix socket: %s", apiSocketPath)
			if err := apiServer.Serve(apiListener); err != nil && err != http.ErrServerClosed {
				log.Printf("[Agent] REST Unix socket server stopped: %v", err)
			}
		}()
	}

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("[Agent] Shutting down agent daemon...")
		if apiServer != nil {
			_ = apiServer.Close()
			_ = os.Remove(apiSocketPath)
		}
		watchdog.Stop()
		iapManager.Stop()
		haEngine.Stop()
		sdwanProber.stop()
		ebpfManager.Stop()
		etckeeperManager.Close()
		grpcServer.GracefulStop()
		_ = os.Remove(*socketPath)
		os.Exit(0)
	}()

	log.Printf("[Agent] Listening on gRPC Unix socket: %s", *socketPath)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("gRPC server failed: %v", err)
	}
}
