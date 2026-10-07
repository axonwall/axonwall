package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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
	lastGoodScript  string
	candidateScript string
	pendingConfirm  bool
	confirmDeadline time.Time
	rollbackTimer   *time.Timer
	nodeId          string
	startTime       time.Time
}

func NewAgentServer(bundleDir string) *AgentServer {
	hostname, _ := os.Hostname()
	return &AgentServer{
		bundleDir: bundleDir,
		nodeId:    fmt.Sprintf("axonwall-%s", hostname),
		startTime: time.Now(),
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
		return nil, status.Errorf(codes.Internal, "failed to write candidate script: %v", err)
	}
	tmpFile.Close()

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

	// 5. Reload any changed systemd units requested
	for _, svc := range req.ReloadServices {
		// Validate service name to prevent loading arbitrary unit files via path (e.g., /tmp/pwn.service)
		if strings.Contains(svc, "/") || strings.Contains(svc, "\\") || strings.HasPrefix(svc, ".") {
			log.Printf("[Agent] Rejected malformed/malicious service reload request: %s", svc)
			continue
		}
		log.Printf("[Agent] Reloading system service: %s", svc)
		_ = exec.Command("systemctl", "try-reload-or-restart", svc).Run()
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
		Success:              true,
		Message:              "Configuration applied. Pending confirmation before timeout.",
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

	if s.lastGoodScript != "" {
		tmpFile, err := os.CreateTemp("", "axonwall-rollback-*.nft")
		if err == nil {
			_ = os.WriteFile(tmpFile.Name(), []byte(s.lastGoodScript), 0644)
			cmd := exec.Command("nft", "-f", tmpFile.Name())
			out, err := cmd.CombinedOutput()
			os.Remove(tmpFile.Name())
			if err != nil {
				log.Printf("[Agent] ERROR applying rollback ruleset: %s", string(out))
			} else {
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
	s.lastGoodScript = s.candidateScript

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
		Version:             "0.1.0",
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
	if target == "" {
		return nil, status.Error(codes.InvalidArgument, "target cannot be empty")
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
	start := time.Now()

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
		conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", target, port))
		latency := time.Since(start).Milliseconds()
		if err != nil {
			return &pb.DiagnosticResponse{
				Success:   false,
				Output:    fmt.Sprintf("Failed to connect to %s:%d: %v", target, port, err),
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
	socketPath := flag.String("socket", "/run/axonwall/agent.sock", "Path to agent Unix socket")
	bundleDir := flag.String("bundle-dir", "/var/lib/axonwall/bundles", "Directory for storing last-known-good bundles")
	bootApply := flag.Bool("boot-apply", false, "Apply last-known-good configuration immediately on boot")
	flag.Parse()

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
	agentServer := NewAgentServer(*bundleDir)
	pb.RegisterAgentServiceServer(grpcServer, agentServer)

	// Start eBPF Manager
	ebpfManager := engine.NewEBPFManager()
	if err := ebpfManager.Start([]string{"eth0", "lo"}); err != nil {
		log.Printf("[Agent] Warning: Failed to start eBPF manager: %v", err)
	}

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("[Agent] Shutting down agent daemon...")
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
