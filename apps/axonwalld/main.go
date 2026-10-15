package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
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
}

func NewAgentServer(bundleDir string, iapManager *engine.IAPManager, haEngine *HAEngine, sdwanProber *SDWanProber, pcapManager *engine.PacketCaptureManager, watchdog *engine.WatchdogEngine) *AgentServer {
	hostname, _ := os.Hostname()

	initHash := ""
	lastGoodScript := ""
	for _, checkPath := range []string{"/etc/nftables.conf", filepath.Join(bundleDir, "last-known-good.nft")} {
		if data, err := os.ReadFile(checkPath); err == nil && len(data) > 0 {
			h := sha256.Sum256(data)
			initHash = hex.EncodeToString(h[:])
			lastGoodScript = string(data)
			break
		}
	}

	return &AgentServer{
		bundleDir:      bundleDir,
		activeHash:     initHash,
		lastGoodHash:   initHash,
		lastGoodScript: lastGoodScript,
		nodeId:         fmt.Sprintf("axonwall-%s", hostname),
		startTime:      time.Now(),
		iapManager:     iapManager,
		haEngine:       haEngine,
		sdwanProber:    sdwanProber,
		pcapManager:    pcapManager,
		watchdog:       watchdog,
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

	// 2. Write optional bundle configuration files (e.g. kea, unbound)
	for _, f := range req.Files {
		// Enforce safety: paths must reside within /etc/axonwall/ or /tmp/
		cleanPath := filepath.Clean(f.Path)
		if !strings.HasPrefix(cleanPath, "/etc/axonwall/") && !strings.HasPrefix(cleanPath, "/tmp/") {
			return nil, status.Errorf(codes.PermissionDenied, "disallowed destination file path: %s", cleanPath)
		}
		if err := os.MkdirAll(filepath.Dir(cleanPath), 0755); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create directories for %s: %v", cleanPath, err)
		}
		mode := os.FileMode(f.FileMode)
		if mode == 0 {
			mode = 0644
		}
		
		// Use syscall.O_NOFOLLOW to prevent symlink TOCTOU attacks
		file, err := os.OpenFile(cleanPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, mode)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to open file %s: %v", cleanPath, err)
		}
		if _, err := file.Write([]byte(f.Content)); err != nil {
			file.Close()
			return nil, status.Errorf(codes.Internal, "failed to write file %s: %v", cleanPath, err)
		}
		file.Close()

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

func (s *AgentServer) triggerAutoRollback(jobId string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.pendingConfirm {
		return
	}

	log.Printf("[Agent] WARNING: Commit-confirm deadline expired for job %s! Initiating automatic rollback.", jobId)

	if s.lastGoodScript == "" {
		lkgPath := filepath.Join(s.bundleDir, "last-known-good.nft")
		if data, err := os.ReadFile(lkgPath); err == nil {
			s.lastGoodScript = string(data)
		}
	}

	if s.lastGoodScript != "" {
		tmpFile, err := os.CreateTemp("", "axonwall-rollback-*.nft")
		if err == nil {
			_ = tmpFile.Close()
			_ = os.WriteFile(tmpFile.Name(), []byte(s.lastGoodScript), 0644)
			cmd := exec.Command("nft", "-f", tmpFile.Name())
			out, err := cmd.CombinedOutput()
			os.Remove(tmpFile.Name())
			if err != nil {
				log.Printf("[Agent] ERROR applying rollback ruleset: %s", string(out))
			} else {
				if s.lastGoodHash != "" {
					s.activeHash = s.lastGoodHash
				} else {
					h := sha256.Sum256([]byte(s.lastGoodScript))
					s.activeHash = hex.EncodeToString(h[:])
				}
				log.Printf("[Agent] Successfully rolled back to last known good ruleset.")
			}
		}
	}

	s.pendingConfirm = false
	s.candidateScript = ""
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

	if s.lastGoodScript == "" {
		// Attempt to load from disk
		lkgPath := filepath.Join(s.bundleDir, "last-known-good.nft")
		data, err := os.ReadFile(lkgPath)
		if err == nil {
			s.lastGoodScript = string(data)
		} else {
			return &pb.RollbackResponse{
				Success: false,
				Message: "No previous last-known-good configuration available for rollback",
			}, nil
		}
	}

	tmpFile, err := os.CreateTemp("", "axonwall-rollback-*.nft")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create rollback temp file: %v", err)
	}
	_ = tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	if err := os.WriteFile(tmpFile.Name(), []byte(s.lastGoodScript), 0644); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to write rollback script: %v", err)
	}

	cmd := exec.Command("nft", "-f", tmpFile.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		return &pb.RollbackResponse{
			Success: false,
			Message: fmt.Sprintf("failed to execute rollback nftables application: %s", string(out)),
		}, nil
	}

	if s.lastGoodHash != "" {
		s.activeHash = s.lastGoodHash
	} else {
		h := sha256.Sum256([]byte(s.lastGoodScript))
		s.activeHash = hex.EncodeToString(h[:])
	}
	s.pendingConfirm = false
	s.candidateScript = ""

	return &pb.RollbackResponse{
		Success: true,
		Message: "Successfully rolled back to last known good ruleset.",
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

	return &pb.GetStatusResponse{
		NodeId:              s.nodeId,
		Version:             "0.2.8",
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

	// If boot-apply is requested, load last-known-good
	if *bootApply {
		lkgPath := filepath.Join(*bundleDir, "last-known-good.nft")
		if _, err := os.Stat(lkgPath); err == nil {
			log.Printf("[Agent] Early-boot: applying last-known-good bundle from %s", lkgPath)
			cmd := exec.Command("nft", "-f", lkgPath)
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("[Agent] Failed to apply boot bundle: %s", string(out))
			} else {
				log.Printf("[Agent] Boot bundle applied successfully.")
			}
		}
	}

	// Ensure directory for socket exists
	sockDir := filepath.Dir(*socketPath)
	if err := os.MkdirAll(sockDir, 0755); err != nil {
		log.Fatalf("Failed to create socket directory %s: %v", sockDir, err)
	}
	_ = os.Remove(*socketPath)

	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("Failed to listen on unix socket %s: %v", *socketPath, err)
	}
	defer os.Remove(*socketPath)

	// Socket permissions: 0660 so control plane group can access
	_ = os.Chmod(*socketPath, 0660)

	grpcServer := grpc.NewServer()
	
	iapManager := engine.NewIAPManager()
	haEngine := NewHAEngine()
	if err := haEngine.StartSocketListener(); err != nil {
		log.Printf("[Agent] Warning: Failed to start HA socket listener: %v", err)
	}

	sdwanProber := NewSDWanProber()
	pcapManager := engine.NewPacketCaptureManager()
	packetStreamMgr := engine.NewPacketStreamManager(pcapManager)
	hardwareMgr := engine.NewHardwareManager()
	terminalMgr := engine.NewTerminalManager()
	watchdog := engine.NewWatchdogEngine()
	watchdog.Start()

	agentServer := NewAgentServer(*bundleDir, iapManager, haEngine, sdwanProber, pcapManager, watchdog)
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
		_ = os.Chmod(apiSocketPath, 0660)
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
			var req pb.ApplyBundleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
				return
			}
			resp, err := agentServer.ApplyBundle(r.Context(), &req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
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
		apiServer = &http.Server{Handler: mux}
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
		grpcServer.GracefulStop()
		_ = os.Remove(*socketPath)
		os.Exit(0)
	}()

	log.Printf("[Agent] Listening on gRPC Unix socket: %s", *socketPath)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("gRPC server failed: %v", err)
	}
}
