package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/axonwall/axonwall/apps/axonwalld/engine"
	pb "github.com/axonwall/axonwall/apps/axonwalld/gen/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/yaml.v3"
)

type AgentServer struct {
	pb.UnimplementedAgentServiceServer
	mu sync.Mutex
	// applyMu serialises whole ApplyBundle calls (M1). The A-M2 fix
	// releases s.mu around service reloads so a hung reload cannot
	// wedge the API — but nothing serialised two applies across that
	// window, so a second apply could arm its own timer and pending
	// state while the first was still reloading, disarming the first
	// bundle's auto-rollback and leaving it unconfirmable. A second
	// ApplyBundle now waits on applyMu; GetStatus/Confirm/Rollback
	// only take s.mu, so they stay live during an apply (Confirm and
	// Rollback fail fast while one is in progress — see
	// applyInProgress — instead of acting on state mid-apply).
	applyMu sync.Mutex
	// applyInProgress is set under s.mu for the whole of ApplyBundle
	// (including the windows where s.mu itself is released) so
	// Confirm, Rollback, and the auto-rollback timer can tell an
	// apply is running without taking applyMu.
	applyInProgress  bool
	bundleDir        string
	activeHash       string
	lastGoodHash     string
	lastGoodScript   string
	candidateScript  string
	pendingConfirm   bool
	pendingJobID     string
	confirmDeadline  time.Time
	rollbackTimer    *time.Timer
	// rollbackGen counts every arming of the auto-rollback timer (M2).
	// The timer callback captures the generation it was armed with
	// and refuses to roll back unless it still matches: Timer.Stop
	// cannot stop a callback that already started, so without this a
	// stale callback could fire into a newer bundle's apply window
	// and roll back the wrong bundle.
	rollbackGen      uint64
	nodeId           string
	startTime        time.Time
	iapManager       *engine.IAPManager
	haEngine         *HAEngine
	sdwanProber      *SDWanProber
	pcapManager      *engine.PacketCaptureManager
	watchdog         *engine.WatchdogEngine
	nasManager       *engine.NasManager
	k3sManager       *engine.K3sManager
	vigilanteManager *engine.VigilanteManager
	etckeeperManager *engine.EtckeeperManager
	directoryManager *engine.DirectoryManager
}

// lkgConfigSrcDirs and lkgConfigDstDirs are the config trees the
// last-known-good snapshot is copied from / restored to. Package
// variables (not constants) so tests can redirect them into temp
// dirs; the production values are unchanged.
var lkgConfigSrcDirs = []string{"/var/lib/axonwall/etc-axonwall", "/etc/axonwall"}
var lkgConfigDstDirs = []string{"/etc/axonwall", "/var/lib/axonwall/etc-axonwall"}

func snapshotLkgConfig(bundleDir string) {
	lkgConfigDir := filepath.Join(bundleDir, "lkg-config")
	if err := os.MkdirAll(lkgConfigDir, 0700); err != nil {
		return
	}

	// Read fallback dir first so live /etc/axonwall files take precedence
	srcDirs := lkgConfigSrcDirs
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

func resolveAxonwallApiGid() int {
	if grp, err := user.LookupGroup("axonwall-api"); err == nil {
		if gid, err := strconv.Atoi(grp.Gid); err == nil {
			return gid
		}
	}
	return -1
}

func ensureSharedConfigPerm(path string, mode os.FileMode) {
	fi, err := os.Lstat(path)
	if err != nil || (fi.Mode()&os.ModeSymlink) != 0 {
		return
	}
	_ = os.Chmod(path, mode)
	if gid := resolveAxonwallApiGid(); gid >= 0 {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			_ = os.Lchown(path, int(st.Uid), gid)
		} else {
			_ = os.Lchown(path, -1, gid)
		}
	}
}

func normalizeConfigTreePermissions() {
	gid := resolveAxonwallApiGid()
	dirs := []string{
		"/etc/axonwall",
		"/etc/axonwall/conf.d",
		"/etc/axonwall/managed",
		"/var/lib/axonwall",
		"/var/lib/axonwall/etc-axonwall",
		"/var/lib/axonwall/etc-axonwall/conf.d",
		"/var/lib/axonwall/etc-axonwall/managed",
		"/var/lib/axonwall/captures",
		"/var/lib/axonwall/backups",
		"/var/lib/axonwall/gitops",
	}
	for _, d := range dirs {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			if gid >= 0 {
				_ = os.Chown(d, -1, gid)
			}
			_ = os.Chmod(d, 0775|os.ModeSetgid)
		}
	}

	for _, dir := range []string{"/etc/axonwall", "/var/lib/axonwall/etc-axonwall"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			fullPath := filepath.Join(dir, name)
			if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") ||
				name == "state.json" || name == "admin.env" || name == "mfa.env" ||
				name == "mcp-keys.json" || name == "mcp-settings.json" {
				ensureSharedConfigPerm(fullPath, 0660)
			} else if name == "controller.env" {
				ensureSharedConfigPerm(fullPath, 0640)
			} else if name == "interfaces.conf" || name == "slot_versions.json" {
				ensureSharedConfigPerm(fullPath, 0664)
			}
		}
	}

	for _, sharedVarFile := range []string{
		"/var/lib/axonwall/state.json",
		"/var/lib/axonwall/mcp-keys.json",
		"/var/lib/axonwall/mcp-settings.json",
		"/var/lib/axonwall/mcp-audit.jsonl",
		"/var/lib/axonwall/session-epoch",
		"/var/lib/axonwall/revoked-jtis",
		"/var/lib/axonwall/users.json",
		"/var/lib/axonwall/backups.json",
	} {
		if _, err := os.Stat(sharedVarFile); err == nil {
			ensureSharedConfigPerm(sharedVarFile, 0660)
		}
	}
	for _, readableVarFile := range []string{
		"/var/lib/axonwall/slot_versions.json",
		"/var/lib/axonwall/.password_changed",
	} {
		if _, err := os.Stat(readableVarFile); err == nil {
			ensureSharedConfigPerm(readableVarFile, 0664)
		}
	}
}

// restoreLkgConfig restores the last-known-good config snapshot over
// the live config trees. It reports whether it restored at least one
// file, so callers can tell "nothing to restore" apart from a
// successful restore (M3).
func restoreLkgConfig(bundleDir string) bool {
	lkgConfigDir := filepath.Join(bundleDir, "lkg-config")
	entries, err := os.ReadDir(lkgConfigDir)
	if err != nil {
		return false
	}

	restored := false
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "admin.env" || name == "axonwall.env" || name == "agent.token" || name == "controller.env" || name == "mfa.env" || name == "slapd.seed" {
			continue
		}
		srcPath := filepath.Join(lkgConfigDir, name)
		if fi, lerr := os.Lstat(srcPath); lerr != nil || (fi.Mode()&os.ModeSymlink) != 0 {
			continue
		}
		data, err := os.ReadFile(srcPath)
		if err != nil || len(data) == 0 {
			continue
		}

		mode := os.FileMode(0660)
		if name == "interfaces.conf" {
			mode = 0664
		}

		targetDirs := lkgConfigDstDirs
		for _, dir := range targetDirs {
			_ = os.MkdirAll(dir, 0775)
			dst := filepath.Join(dir, name)
			if fi, lerr := os.Lstat(dst); lerr == nil && (fi.Mode()&os.ModeSymlink) != 0 {
				continue
			}
			if err := os.WriteFile(dst, data, mode); err == nil {
				ensureSharedConfigPerm(dst, mode)
				restored = true
			}
		}
		if name == "state.json" {
			if fi, lerr := os.Lstat("/var/lib/axonwall/state.json"); lerr != nil || (fi.Mode()&os.ModeSymlink) == 0 {
				if err := os.WriteFile("/var/lib/axonwall/state.json", data, 0660); err == nil {
					ensureSharedConfigPerm("/var/lib/axonwall/state.json", 0660)
					restored = true
				}
			}
		}
	}
	return restored
}

func NewAgentServer(bundleDir string, iapManager *engine.IAPManager, haEngine *HAEngine, sdwanProber *SDWanProber, pcapManager *engine.PacketCaptureManager, watchdog *engine.WatchdogEngine, nasManager *engine.NasManager, k3sManager *engine.K3sManager, vigilanteManager *engine.VigilanteManager, etckeeperManager *engine.EtckeeperManager, directoryManager *engine.DirectoryManager) *AgentServer {
	hostname, _ := os.Hostname()

	// M3: a pending-confirm record from a previous run means the live
	// config/ruleset is an UNCONFIRMED bundle. It must never be
	// adopted as last-known-good below, and the startup LKG snapshot
	// must not copy it over the confirmed snapshot.
	pendingExists := false
	if _, err := os.Stat(pendingConfirmStatePath(bundleDir)); err == nil {
		pendingExists = true
	}

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
	if lastGoodScript == "" && !pendingExists {
		if out, err := exec.Command("nft", "list", "ruleset").CombinedOutput(); err == nil && len(out) > 0 {
			scriptStr := string(out)
			if !strings.HasPrefix(strings.TrimSpace(scriptStr), "flush ruleset") {
				scriptStr = "flush ruleset\n" + scriptStr
			}
			scriptBytes := []byte(scriptStr)
			h := sha256.Sum256(scriptBytes)
			initHash = hex.EncodeToString(h[:])
			lastGoodScript = scriptStr
			if err := os.MkdirAll(bundleDir, 0700); err == nil {
				_ = os.WriteFile(filepath.Join(bundleDir, "last-known-good.nft"), scriptBytes, 0600)
			}
		}
	}

	s := &AgentServer{
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

	if pendingExists {
		s.handlePendingConfirmAtStartup(bundleDir)
	} else {
		snapshotLkgConfig(bundleDir)
	}

	return s
}

// handlePendingConfirmAtStartup reconciles a pending-confirm record
// left by a previous run (M3). If the deadline is still in the
// future, the pending state is restored (with the timer re-armed from
// the remaining time) so the operator can still confirm it; the
// startup LKG snapshot is skipped so the unconfirmed bundle is not
// promoted. If the deadline already passed (or the record is
// corrupt), the daemon rolls back to last-known-good before doing
// anything else.
func (s *AgentServer) handlePendingConfirmAtStartup(bundleDir string) {
	state, candidate, ok := loadPendingConfirmState(bundleDir)
	if !ok {
		log.Printf("[Agent] WARNING: pending-confirm record in %s is corrupt or incomplete; rolling back to last-known-good", bundleDir)
		s.rollbackPendingAtStartup(bundleDir)
		return
	}
	remaining := time.Until(time.Unix(state.DeadlineUnix, 0))
	if remaining <= 0 {
		log.Printf("[Agent] WARNING: previous run exited with unconfirmed bundle (job %s, deadline %s); rolling back to last-known-good", state.JobID, time.Unix(state.DeadlineUnix, 0).Format(time.RFC3339))
		s.rollbackPendingAtStartup(bundleDir)
		return
	}

	// Deadline still in the future: restore the pending state.
	s.pendingConfirm = true
	s.pendingJobID = state.JobID
	s.confirmDeadline = time.Unix(state.DeadlineUnix, 0)
	s.candidateScript = candidate
	if state.ActiveHash != "" {
		s.activeHash = state.ActiveHash
	}
	s.rollbackGen++
	gen := s.rollbackGen
	s.rollbackTimer = time.AfterFunc(remaining, func() {
		s.triggerAutoRollback(state.JobID, gen)
	})
	_ = os.MkdirAll("/run/axonwall", 0755)
	_ = os.WriteFile("/run/axonwall/commit-confirm.pending", []byte(fmt.Sprintf("COMMIT-CONFIRM (restored, %ds remaining)", int(remaining.Seconds()))), 0644)
	log.Printf("[Agent] WARNING: restored pending confirmation for job %s from previous run (deadline %s, %ds remaining); confirm it or it will roll back automatically", state.JobID, s.confirmDeadline.Format(time.RFC3339), int(remaining.Seconds()))
	// NOTE: no snapshotLkgConfig here — the live files are the
	// unconfirmed bundle's; snapshotting them would promote it.
}

// rollbackPendingAtStartup restores the last-known-good config files
// and ruleset after a previous run exited with an unconfirmed bundle
// (M3). When no confirmed LKG exists at all there is nothing to roll
// back to: the unconfirmed bundle stays live, but it is NOT adopted
// as LKG and the live files are NOT snapshotted as LKG.
func (s *AgentServer) rollbackPendingAtStartup(bundleDir string) {
	restored := restoreLkgConfig(bundleDir)
	if s.lastGoodScript != "" {
		if err := applyNftScriptString(s.lastGoodScript); err != nil {
			log.Printf("[Agent] WARNING: startup rollback could not apply last-known-good ruleset: %v", err)
		} else {
			log.Printf("[Agent] Startup rollback applied last-known-good ruleset")
			if s.lastGoodHash != "" {
				s.activeHash = s.lastGoodHash
			}
		}
	}
	if restored {
		// The restored files are the confirmed LKG config; snapshot
		// them so the lkg-config dir matches what is live now.
		snapshotLkgConfig(bundleDir)
	} else {
		if s.lastGoodScript == "" {
			log.Printf("[Agent] WARNING: no last-known-good configuration exists to roll back to; the unconfirmed bundle from the previous run stays live but is NOT promoted to last-known-good")
		} else {
			log.Printf("[Agent] WARNING: no last-known-good config snapshot exists to restore; config files left as-is while the ruleset was rolled back")
		}
	}
	clearPendingConfirmFiles(bundleDir)
	_ = os.Remove("/run/axonwall/commit-confirm.pending")
}

// Timeouts bounding the slow external commands ApplyBundle runs (A-M2).
// A hung nftables load or service reload must delay an apply, never
// wedge the agent API forever. Package variables so tests can shorten
// them; production values are deliberately generous because nft -f on
// a large ruleset and a slow unit reload are legitimate slow paths.
var nftValidateTimeout = 60 * time.Second
var nftApplyTimeout = 120 * time.Second

// autoRollbackDeferDelay is how long a commit-confirm timer callback
// waits before retrying when it fires while an apply is in progress
// (M2). A variable so tests can shrink it.
var autoRollbackDeferDelay = 10 * time.Second

// validatedBundleFile is one bundle file after all path, symlink, and
// mode checks have passed, before anything is written (A-H2).
type validatedBundleFile struct {
	file                *pb.BundleFile
	cleanPath           string
	mode                os.FileMode
	isSharedAxonwallCfg bool
}

// validateBundleFiles checks every file in a bundle — allowed prefix,
// protected credential/PKI paths, leaf and intermediate symlinks, and
// the sanitized mode — without writing anything. ApplyBundle runs
// this before the write loop so a bundle that fails validation leaves
// no half-written files behind (A-H2: the old loop validated and
// wrote file by file, so a disallowed later file left earlier files
// and their subsystem side effects live).
func validateBundleFiles(files []*pb.BundleFile) ([]validatedBundleFile, error) {
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
		"/etc/rosenpass/",
		"/etc/swanctl/",
		"/etc/haproxy/",
		"/etc/freeradius/",
		"/etc/snmp/",
		"/etc/nut/",
	}
	out := make([]validatedBundleFile, 0, len(files))
	for _, f := range files {
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
		if cleanPath == "/etc/axonwall/admin.env" ||
			cleanPath == "/etc/axonwall/axonwall.env" ||
			cleanPath == "/etc/axonwall/agent.token" ||
			cleanPath == "/etc/axonwall/controller.env" ||
			cleanPath == "/etc/axonwall/mfa.env" ||
			cleanPath == "/etc/axonwall/slapd.seed" ||
			cleanPath == "/etc/axonwall/pki" ||
			strings.HasPrefix(cleanPath, "/etc/axonwall/pki/") {
			return nil, status.Errorf(codes.PermissionDenied, "protected credential or PKI file cannot be overwritten via bundle: %s", cleanPath)
		}
		if fi, lerr := os.Lstat(cleanPath); lerr == nil && (fi.Mode()&os.ModeSymlink) != 0 {
			return nil, status.Errorf(codes.PermissionDenied, "destination path is a symlink: %s", cleanPath)
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
		// Sanitize the caller-chosen mode (audit D-S02): plain permission
		// bits only (drops setuid/setgid/sticky), and never world-writable.
		// Shared config files under /etc/axonwall (*.yaml, *.yml, state.json, interfaces.conf)
		// must remain group-readable and group-writable (0660 / 0664) for group axonwall-api
		// so axonwall-ui and axonwall-controller can read and update them across reboots.
		isSharedAxonwallCfg := strings.HasPrefix(cleanPath, "/etc/axonwall/") &&
			(strings.HasSuffix(cleanPath, ".yaml") || strings.HasSuffix(cleanPath, ".yml") || filepath.Base(cleanPath) == "state.json" || filepath.Base(cleanPath) == "interfaces.conf")
		mode := os.FileMode(f.FileMode).Perm()
		if isSharedAxonwallCfg {
			if filepath.Base(cleanPath) == "interfaces.conf" {
				mode = 0664
			} else {
				mode = 0660
			}
			mode &^= 0o002
		} else {
			if mode == 0 {
				if strings.HasPrefix(cleanPath, "/etc/axonwall/") && strings.HasSuffix(cleanPath, ".json") {
					mode = 0600
				} else {
					mode = 0644
				}
			}
			mode &^= 0o022
		}
		out = append(out, validatedBundleFile{file: f, cleanPath: cleanPath, mode: mode, isSharedAxonwallCfg: isSharedAxonwallCfg})
	}
	return out, nil
}

// reloadBundleServices reloads the requested units. It touches no
// AgentServer state, so ApplyBundle calls it without holding s.mu
// (A-M2): a hung unit reload must not wedge GetStatus, Confirm, or
// the auto-rollback timer behind the agent lock. A Confirm arriving
// in this window is premature — ApplyBundle has not returned success
// yet — and the commit-confirm timer is not armed until after the
// reloads, so releasing the lock here changes no committed state.
// (M1: Confirm now fails fast while an apply is in progress, and a
// second ApplyBundle waits on applyMu, so nothing can act on the
// half-applied state from this window.)
func reloadBundleServices(services []string) {
	for _, svc := range services {
		// Validate service name to prevent loading arbitrary unit files via path (e.g., /tmp/pwn.service)
		if strings.Contains(svc, "/") || strings.Contains(svc, "\\") || strings.HasPrefix(svc, ".") {
			log.Printf("[Agent] Rejected malformed/malicious service reload request: %s", svc)
			continue
		}
		log.Printf("[Agent] Reloading system service: %s", svc)
		_, _ = reloadOrRestartService(svc)
	}
}

func (s *AgentServer) ApplyBundle(ctx context.Context, req *pb.ApplyBundleRequest) (*pb.ApplyBundleResponse, error) {
	// M1: serialise whole applies. A second ApplyBundle waits here
	// instead of interleaving with the first across the lock-release
	// windows below and corrupting its pending-confirm state.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	s.mu.Lock()
	s.applyInProgress = true
	// Registered before the deferred s.mu.Unlock below, so it runs
	// after the lock is released at return: clear the flag under the
	// lock, then let the deferred applyMu unlock run.
	defer func() {
		s.mu.Lock()
		s.applyInProgress = false
		s.mu.Unlock()
	}()
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

	// A-M2: bound the validation exec; an nft binary that hangs must
	// not wedge the agent API behind s.mu forever.
	validateCtx, validateCancel := context.WithTimeout(context.Background(), nftValidateTimeout)
	defer validateCancel()
	validateCmd := exec.CommandContext(validateCtx, "nft", "-c", "-f", tmpFile.Name())
	if out, err := validateCmd.CombinedOutput(); err != nil {
		log.Printf("[Agent] nft validation error: %s", string(out))
		return &pb.ApplyBundleResponse{
			Success: false,
			Message: fmt.Sprintf("nftables syntax validation failed: %s", string(out)),
		}, nil
	}

	// A-H2: validate every file before writing any of them.
	validatedFiles, err := validateBundleFiles(req.Files)
	if err != nil {
		return nil, err
	}

	// Snapshot verified configuration before writing candidate changes
	if !s.pendingConfirm {
		snapshotLkgConfig(s.bundleDir)
	}

	// 2. Write the already-validated bundle configuration files (e.g.
	// kea, unbound, suricata, crowdsec). Paths, symlinks, and modes
	// were checked for every file up front by validateBundleFiles, so
	// a failure here can only come from the writes themselves — and
	// any such failure rolls back instead of leaving a half-applied
	// bundle behind (A-H2).
	var subsystemErr error
	for _, vf := range validatedFiles {
		f := vf.file
		cleanPath := vf.cleanPath
		mode := vf.mode
		isSharedAxonwallCfg := vf.isSharedAxonwallCfg
		if err := os.MkdirAll(filepath.Dir(cleanPath), 0755); err != nil {
			log.Printf("[Agent] Failed to create directories for %s: %v; rolling back", cleanPath, err)
			_ = s.executeRollback("bundle file write failed")
			return nil, status.Errorf(codes.Internal, "failed to create directories for %s: %v", cleanPath, err)
		}

		// Use syscall.O_NOFOLLOW to prevent symlink TOCTOU attacks
		file, err := os.OpenFile(cleanPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, mode)
		if err != nil {
			log.Printf("[Agent] Failed to open file %s: %v; rolling back", cleanPath, err)
			_ = s.executeRollback("bundle file write failed")
			return nil, status.Errorf(codes.Internal, "failed to open file %s: %v", cleanPath, err)
		}
		if _, err := file.Write([]byte(f.Content)); err != nil {
			file.Close()
			log.Printf("[Agent] Failed to write file %s: %v; rolling back", cleanPath, err)
			_ = s.executeRollback("bundle file write failed")
			return nil, status.Errorf(codes.Internal, "failed to write file %s: %v", cleanPath, err)
		}
		_ = file.Chmod(mode)
		file.Close()
		if isSharedAxonwallCfg {
			ensureSharedConfigPerm(cleanPath, mode)
		}

		// Mirror /etc/axonwall/*.yaml, *.json, and interfaces.conf to /var/lib/axonwall/etc-axonwall/ for A/B rootfs persistence
		if strings.HasPrefix(cleanPath, "/etc/axonwall/") &&
			(strings.HasSuffix(cleanPath, ".yaml") || strings.HasSuffix(cleanPath, ".yml") || strings.HasSuffix(cleanPath, ".json") || filepath.Base(cleanPath) == "interfaces.conf") {
			relPath := strings.TrimPrefix(cleanPath, "/etc/axonwall/")
			persistPath := filepath.Join("/var/lib/axonwall/etc-axonwall", relPath)
			_ = os.MkdirAll(filepath.Dir(persistPath), 0775)
			if fi, lerr := os.Lstat(persistPath); lerr != nil || (fi.Mode()&os.ModeSymlink) == 0 {
				if pf, perr := os.OpenFile(persistPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, mode); perr == nil {
					_, _ = pf.Write([]byte(f.Content))
					_ = pf.Chmod(mode)
					_ = pf.Close()
				}
				if isSharedAxonwallCfg {
					ensureSharedConfigPerm(persistPath, mode)
				}
			}
			if filepath.Base(cleanPath) == "state.json" {
				varStatePath := "/var/lib/axonwall/state.json"
				if fi, lerr := os.Lstat(varStatePath); lerr != nil || (fi.Mode()&os.ModeSymlink) == 0 {
					if sf, serr := os.OpenFile(varStatePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0660); serr == nil {
						_, _ = sf.Write([]byte(f.Content))
						_ = sf.Chmod(0660)
						_ = sf.Close()
					}
					ensureSharedConfigPerm(varStatePath, 0660)
				}
			}
		}

		if filepath.Base(cleanPath) == "firewall_config.json" {
			var fwCfg struct {
				Enabled bool `json:"enabled"`
			}
			if err := json.Unmarshal([]byte(f.Content), &fwCfg); err == nil && !fwCfg.Enabled {
				log.Printf("[Agent] Core-Firewall plugin is disabled (Host Mode); stopping NGFW-only daemons")
				stopCtx, stopCancel := context.WithTimeout(context.Background(), serviceCommandTimeout)
				_ = exec.CommandContext(stopCtx, "systemctl", "stop", "kea-dhcp4-server", "suricata", "frr", "conntrackd", "crowdsec-firewall-bouncer").Run()
				stopCancel()
			}
		}

		// A-M3: a subsystem apply failure fails the bundle instead of
		// being logged and then confirmed into last-known-good. The
		// first failure stops the loop (fewer half-applied side
		// effects) and the bundle is rolled back below.
		if filepath.Base(cleanPath) == "zero_trust_apps.json" {
			log.Printf("[Agent] Applying Zero Trust IAP configuration")
			if err := s.iapManager.ApplyConfig([]byte(f.Content)); err != nil {
				subsystemErr = fmt.Errorf("IAP config: %w", err)
				break
			}
		}

		if filepath.Base(cleanPath) == "sdwan_config.json" {
			log.Printf("[Agent] Applying SD-WAN Gateway routing configuration")
			if err := s.sdwanProber.ReloadConfig(cleanPath); err != nil {
				subsystemErr = fmt.Errorf("SD-WAN config: %w", err)
				break
			}
		}

		if filepath.Base(cleanPath) == "ha_config.json" {
			log.Printf("[Agent] Applying High Availability & SQLite Sync configuration")
			if err := s.haEngine.ApplyFromJSON([]byte(f.Content)); err != nil {
				subsystemErr = fmt.Errorf("HA config: %w", err)
				break
			}
		}

		if filepath.Base(cleanPath) == "nas_config.json" && s.nasManager != nil {
			log.Printf("[Agent] Applying OpenZFS Storage & NAS Share configuration")
			if err := s.nasManager.ApplyConfig([]byte(f.Content)); err != nil {
				subsystemErr = fmt.Errorf("NAS config: %w", err)
				break
			}
		}

		if filepath.Base(cleanPath) == "k3s_config.json" && s.k3sManager != nil {
			log.Printf("[Agent] Applying K3s & OpenEBS cluster configuration")
			if err := s.k3sManager.ApplyConfig([]byte(f.Content)); err != nil {
				subsystemErr = fmt.Errorf("K3s config: %w", err)
				break
			}
		}

		if filepath.Base(cleanPath) == "vigilante_config.json" && s.vigilanteManager != nil {
			log.Printf("[Agent] Applying Vigilante Cyber Defense configuration & K3s manifests")
			if err := s.vigilanteManager.ApplyConfig([]byte(f.Content)); err != nil {
				subsystemErr = fmt.Errorf("Vigilante config: %w", err)
				break
			}
		}

		if filepath.Base(cleanPath) == "vow_config.json" && s.k3sManager != nil {
			log.Printf("[Agent] Applying Vigilant Octo Waffle (VOW) K3s GitOps configuration")
			if err := s.k3sManager.ApplyVowConfig([]byte(f.Content)); err != nil {
				subsystemErr = fmt.Errorf("VOW config: %w", err)
				break
			}
		}
	}

	// A-M3: report the subsystem failure and roll back instead of
	// entering pending-confirm with a half-applied bundle.
	if subsystemErr != nil {
		log.Printf("[Agent] Subsystem apply failed (%v); rolling back", subsystemErr)
		if rbErr := s.executeRollback("subsystem apply failed"); rbErr != nil {
			log.Printf("[Agent] Rollback after subsystem failure also failed: %v", rbErr)
		}
		return &pb.ApplyBundleResponse{
			Success: false,
			Message: fmt.Sprintf("subsystem apply failed: %v", subsystemErr),
		}, nil
	}

	// Reconcile physical/logical interfaces and static routes whenever a bundle is applied
	// A-M16: a failed static address assignment fails the apply (with
	// rollback, like the nft failure below) instead of being logged
	// while the WAN is left address-less.
	if err := applyBootInterfaces(); err != nil {
		log.Printf("[Agent] Failed to apply boot interfaces: %v; rolling back", err)
		_ = s.executeRollback("interface apply failed")
		return &pb.ApplyBundleResponse{
			Success: false,
			Message: fmt.Sprintf("failed to apply interfaces: %v", err),
		}, nil
	}
	if err := ReconcileStaticRoutes(); err != nil {
		log.Printf("[Agent] Warning: Static routes reconciliation: %v", err)
	}

	if s.etckeeperManager != nil && len(req.Files) > 0 {
		commitMsg := fmt.Sprintf("Axonwall configuration bundle applied (%s)", req.BundleHash)
		s.etckeeperManager.ScheduleCommit(commitMsg, "axonwall")
	}

	// 3. Backup current script for rollback
	s.candidateScript = req.NftScript

	// 4. Apply ruleset atomically (bounded by A-M2's timeout).
	applyCtx, applyCancel := context.WithTimeout(context.Background(), nftApplyTimeout)
	defer applyCancel()
	applyCmd := exec.CommandContext(applyCtx, "nft", "-f", tmpFile.Name())
	if out, err := applyCmd.CombinedOutput(); err != nil {
		log.Printf("[Agent] Failed to apply nftables ruleset: %s; rolling back config files and services", string(out))
		if rbErr := s.executeRollback("nftables apply failed"); rbErr != nil {
			log.Printf("[Agent] Rollback after nftables apply failure also failed: %v", rbErr)
		}
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

	// 5. Reload any changed systemd units requested. A-M2: this runs
	// without holding s.mu (see reloadBundleServices); the deferred
	// unlock at the top of ApplyBundle releases the re-acquired lock.
	s.mu.Unlock()
	reloadBundleServices(req.ReloadServices)
	s.mu.Lock()

	// 6. Setup Commit-Confirm deadline
	// C26 (daemon side): the UI now validates/clamps this value, but
	// the daemon must not trust it. Out-of-range values previously
	// passed through verbatim: a negative timeout armed a deadline
	// in the past (immediate auto-rollback racing the confirm), and
	// a huge timeout left a ruleset effectively unconfirmed forever.
	// Clamp to 10-3600s, defaulting an absent value to 120s.
	timeoutSec := req.ConfirmTimeoutSeconds
	if timeoutSec == 0 {
		timeoutSec = 120
	}
	if timeoutSec < 10 {
		timeoutSec = 10
	}
	if timeoutSec > 3600 {
		timeoutSec = 3600
	}

	if s.rollbackTimer != nil {
		s.rollbackTimer.Stop()
	}

	s.pendingConfirm = true
	s.pendingJobID = req.JobId
	s.confirmDeadline = time.Now().Add(time.Duration(timeoutSec) * time.Second)
	_ = os.MkdirAll("/run/axonwall", 0755)
	_ = os.WriteFile("/run/axonwall/commit-confirm.pending", []byte(fmt.Sprintf("COMMIT-CONFIRM (%ds)", timeoutSec)), 0644)

	// M2: the callback captures the generation it was armed with.
	// A stale callback (already running when a newer bundle armed
	// its own timer) must not roll back the newer bundle.
	s.rollbackGen++
	rollbackGen := s.rollbackGen
	s.rollbackTimer = time.AfterFunc(time.Duration(timeoutSec)*time.Second, func() {
		s.triggerAutoRollback(req.JobId, rollbackGen)
	})

	// M3: persist the pending-confirm state (job, deadline, candidate
	// script) so a daemon restart neither promotes the unconfirmed
	// bundle to last-known-good nor loses the chance to confirm or
	// roll it back. A persist failure is loud but does not fail the
	// apply: the in-memory state is still correct for this run.
	if err := writePendingConfirmState(s.bundleDir, pendingConfirmState{
		JobID:        req.JobId,
		DeadlineUnix: s.confirmDeadline.Unix(),
		ActiveHash:   s.activeHash,
	}, s.candidateScript); err != nil {
		log.Printf("[Agent] WARNING: failed to persist pending-confirm state: %v (a restart will roll back to last-known-good)", err)
	}

	log.Printf("[Agent] Configuration applied successfully. Pending confirmation for job %s (deadline: %v)", req.JobId, s.confirmDeadline)

	return &pb.ApplyBundleResponse{
		Success:             true,
		Message:             "Configuration applied. Pending confirmation before timeout.",
		ConfirmDeadlineUnix: s.confirmDeadline.Unix(),
	}, nil
}

// clearPendingLocked drops the pending-confirm state. Callers hold
// s.mu. It is used on every rollback path, success or failure: a
// failed rollback must never leave a failed candidate confirmable
// (A-M1 — the old code returned before clearing on rollback failure,
// so a later Confirm for the previous job's ID promoted the failed
// candidate script to last-known-good).
func (s *AgentServer) clearPendingLocked() {
	if s.rollbackTimer != nil {
		s.rollbackTimer.Stop()
		s.rollbackTimer = nil
	}
	s.pendingConfirm = false
	s.pendingJobID = ""
	s.candidateScript = ""
	_ = os.Remove("/run/axonwall/commit-confirm.pending")
	// M3: drop the persisted pending-confirm record too, so a later
	// restart does not try to confirm or roll back a bundle that
	// already finished.
	clearPendingConfirmFiles(s.bundleDir)
}

// pendingConfirmState is the on-disk record of an unconfirmed bundle
// (M3). Pending-confirm state used to live only in memory plus the
// /run marker file, which nothing read at startup — so a daemon
// restart silently promoted an unconfirmed bundle to last-known-good
// (NewAgentServer snapshotted the live files as LKG, and adopted the
// live ruleset as the LKG script when no LKG file existed yet). The
// record lives in the bundle dir (persistent, unlike /run) next to
// last-known-good.nft; the candidate script is stored alongside it
// so a restarted daemon can still confirm or roll back the pending
// bundle.
type pendingConfirmState struct {
	JobID        string `json:"jobId"`
	DeadlineUnix int64  `json:"deadlineUnix"`
	ActiveHash   string `json:"activeHash"`
}

func pendingConfirmStatePath(bundleDir string) string {
	return filepath.Join(bundleDir, "pending-confirm.json")
}

func pendingCandidatePath(bundleDir string) string {
	return filepath.Join(bundleDir, "candidate.nft")
}

// writePendingConfirmState persists a pending-confirm record and its
// candidate script. A failure to persist is reported but must not
// fail the apply itself: the in-memory state is still correct for
// this run, and the startup path treats a missing record as "roll
// back to last-known-good".
func writePendingConfirmState(bundleDir string, state pendingConfirmState, candidateScript string) error {
	if err := os.MkdirAll(bundleDir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.WriteFile(pendingConfirmStatePath(bundleDir), data, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(pendingCandidatePath(bundleDir), []byte(candidateScript), 0600); err != nil {
		_ = os.Remove(pendingConfirmStatePath(bundleDir))
		return err
	}
	return nil
}

// loadPendingConfirmState reads a persisted pending-confirm record.
// It reports ok=false when no confirm was pending or the record is
// unusable (missing/corrupt state or candidate); callers treat that
// as "no live pending bundle" and roll back if a record exists.
func loadPendingConfirmState(bundleDir string) (pendingConfirmState, string, bool) {
	var state pendingConfirmState
	data, err := os.ReadFile(pendingConfirmStatePath(bundleDir))
	if err != nil || len(data) == 0 {
		return state, "", false
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, "", false
	}
	candidate, err := os.ReadFile(pendingCandidatePath(bundleDir))
	if err != nil || len(candidate) == 0 {
		return state, "", false
	}
	return state, string(candidate), true
}

// pendingConfirmIsLive reports whether a previous run left a pending
// confirm whose deadline is still in the future.
func pendingConfirmIsLive(bundleDir string) bool {
	state, _, ok := loadPendingConfirmState(bundleDir)
	if !ok {
		return false
	}
	return time.Now().Unix() < state.DeadlineUnix
}

func clearPendingConfirmFiles(bundleDir string) {
	_ = os.Remove(pendingConfirmStatePath(bundleDir))
	_ = os.Remove(pendingCandidatePath(bundleDir))
}

// applyNftScriptString applies an nftables script via a temp file,
// bounded by nftApplyTimeout like the apply/rollback execs (A-M2).
func applyNftScriptString(script string) error {
	tmpFile, err := os.CreateTemp("", "axonwall-script-*.nft")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	_ = tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	if err := os.WriteFile(tmpFile.Name(), []byte(script), 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), nftApplyTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", tmpFile.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *AgentServer) executeRollback(reason string) error {
	if s.lastGoodScript == "" {
		lkgPath := filepath.Join(s.bundleDir, "last-known-good.nft")
		if data, err := os.ReadFile(lkgPath); err == nil && len(data) > 0 {
			s.lastGoodScript = string(data)
		} else {
			// A-M1: no rollback target means the pending candidate
			// must die here, not linger for a later Confirm.
			s.clearPendingLocked()
			return fmt.Errorf("no previous last-known-good configuration available for rollback")
		}
	}

	if s.lastGoodScript != "" {
		if err := applyNftScriptString(s.lastGoodScript); err != nil {
			log.Printf("[Agent] ERROR applying rollback ruleset: %v", err)
			s.clearPendingLocked()
			return fmt.Errorf("failed to execute rollback nftables application: %w", err)
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

	// Re-apply restored physical/logical interfaces and reconcile static routes
	// A-M16: a rollback must not itself fail because one interface
	// re-apply failed; log and continue restoring the rest.
	if err := applyBootInterfaces(); err != nil {
		log.Printf("[Agent] Rollback: boot interfaces re-apply failed: %v", err)
	}
	if err := ReconcileStaticRoutes(); err != nil {
		log.Printf("[Agent] Rollback: static routes reconciliation: %v", err)
	}

	s.clearPendingLocked()
	log.Printf("[Agent] Successfully rolled back to last known good configuration (reason: %s).", reason)
	return nil
}

func (s *AgentServer) triggerAutoRollback(jobId string, gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.pendingConfirm {
		return
	}

	// M2: the callback only rolls back the bundle it was armed for.
	// Timer.Stop cannot stop a callback that already started, so a
	// stale callback can acquire the lock after a newer bundle went
	// pending; without the job-id and generation checks it would
	// roll back the newer bundle.
	if jobId != s.pendingJobID || gen != s.rollbackGen {
		return
	}

	// M2/M1: an apply in progress owns the config files and the
	// kernel state right now; rolling back underneath it would
	// restore LKG files under the new bundle's writes. Defer the
	// rollback instead of dropping it: the re-armed callback
	// re-checks the job id and generation, so it becomes a no-op
	// if the apply armed a newer pending bundle in the meantime.
	if s.applyInProgress {
		log.Printf("[Agent] WARNING: Commit-confirm deadline expired for job %s, but a configuration apply is in progress; deferring automatic rollback.", jobId)
		s.rollbackTimer = time.AfterFunc(autoRollbackDeferDelay, func() {
			s.triggerAutoRollback(jobId, gen)
		})
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

	// M1: a confirm arriving while an apply is in progress is
	// premature — the pending state it would act on belongs to the
	// previous bundle, while the new bundle's files are already on
	// disk. Fail fast instead of confirming (and snapshotting) a
	// half-applied state; the caller retries after the apply returns.
	if s.applyInProgress {
		return &pb.ConfirmResponse{
			Success: false,
			Message: "Configuration apply in progress; retry the confirm after it completes.",
		}, nil
	}

	if !s.pendingConfirm {
		return &pb.ConfirmResponse{
			Success: false,
			Message: "No pending configuration to confirm (already confirmed or rolled back).",
		}, nil
	}
	// C10/C11 (daemon side): the literal job id "confirm" used to be
	// exempt from the mismatch check, so a stale confirm — sent for
	// a job that is no longer pending, or with no job known at all —
	// confirmed whatever bundle happened to be pending, promoting a
	// ruleset the operator never reviewed. The UI now sends real job
	// ids, and axonwallctl resolves the pending id before confirming,
	// so the daemon requires an exact match: the confirm must name
	// the pending job (including both sides being empty for applies
	// submitted without a job id). Anything else is a mismatch.
	if req.JobId != s.pendingJobID {
		return &pb.ConfirmResponse{
			Success: false,
			Message: fmt.Sprintf("Job ID mismatch for pending confirmation: expected %s, got %s", s.pendingJobID, req.JobId),
		}, nil
	}

	if s.rollbackTimer != nil {
		s.rollbackTimer.Stop()
		s.rollbackTimer = nil
	}

	s.pendingConfirm = false
	s.pendingJobID = ""
	_ = os.Remove("/run/axonwall/commit-confirm.pending")
	// M3: drop the persisted pending-confirm record too.
	clearPendingConfirmFiles(s.bundleDir)
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

	// M1: same premature-action guard as Confirm — rolling back
	// while an apply is mid-flight would restore LKG files under
	// the new bundle's writes. Fail fast; the caller retries after
	// the apply returns.
	if s.applyInProgress {
		return &pb.RollbackResponse{
			Success: false,
			Message: "Configuration apply in progress; retry the rollback after it completes.",
		}, nil
	}

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

func sanitizeEtcNetworkInterfaces() {
	_ = os.Remove("/etc/network/interfaces.d/axonwall")
	ifData, err := os.ReadFile("/etc/network/interfaces")
	if err != nil {
		return
	}
	content := string(ifData)
	if !strings.Contains(content, "auto none") && !strings.Contains(content, "iface none") {
		return
	}
	var cleaned []string
	skipStanza := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "auto none" {
			continue
		}
		if strings.HasPrefix(trimmed, "iface none ") {
			skipStanza = true
			continue
		}
		if skipStanza {
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				continue
			}
			skipStanza = false
		}
		cleaned = append(cleaned, line)
	}
	_ = os.WriteFile("/etc/network/interfaces", []byte(strings.Join(cleaned, "\n")), 0644)
}

type bootIfaceSpec struct {
	Name    string
	Role    string // "wan" or "lan"
	Device  string
	Mode    string // "dhcp" or "static"
	IPv4    string
	Gateway string
}

func loadAllBootInterfaces(config map[string]string) []bootIfaceSpec {
	validDev := func(dev string) string {
		if dev == "" || strings.HasPrefix(dev, "-") || isPlaceholderNetdev(dev) {
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
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			return ""
		}
		if _, _, err := net.ParseCIDR(cidr); err == nil {
			return cidr
		}
		if ip := net.ParseIP(cidr); ip != nil {
			if ip.To4() != nil {
				return cidr + "/24"
			}
			return cidr + "/64"
		}
		return ""
	}

	byName := make(map[string]bootIfaceSpec)
	var order []string
	upsert := func(s bootIfaceSpec) {
		if s.Name == "" || s.Device == "" {
			return
		}
		s.Name = strings.ToLower(s.Name)
		s.Role = strings.ToLower(strings.TrimSpace(s.Role))
		if s.Role != "wan" && s.Role != "lan" && s.Role != "wan-delegated" {
			if strings.HasPrefix(s.Name, "wan") {
				s.Role = "wan"
			} else {
				s.Role = "lan"
			}
		}
		if s.Mode != "static" && s.Mode != "dhcp" {
			if s.Name == "lan" {
				s.Mode = "static"
			} else {
				s.Mode = "dhcp"
			}
		}
		if _, exists := byName[s.Name]; !exists {
			order = append(order, s.Name)
		}
		byName[s.Name] = s
	}
	remove := func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return
		}
		delete(byName, name)
	}

	// 1. Legacy 4-slot keys in interfaces.conf
	if d := validDev(config["WAN_INTERFACE"]); d != "" {
		wanRole := strings.ToLower(strings.TrimSpace(config["WAN_ROLE"]))
		if wanRole == "" {
			wanRole = "wan"
		}
		upsert(bootIfaceSpec{
			Name:    "wan",
			Role:    wanRole,
			Device:  d,
			Mode:    config["WAN_MODE"],
			IPv4:    validCIDR(config["WAN_IPV4_ADDRESS"]),
			Gateway: validIP(config["WAN_IPV4_GATEWAY"]),
		})
	}
	if d := validDev(config["LAN_INTERFACE"]); d != "" {
		lanMode := config["LAN_MODE"]
		if lanMode == "" {
			lanMode = "static"
		}
		lanIP := validCIDR(config["LAN_IPV4_ADDRESS"])
		if lanIP == "" && lanMode == "static" {
			lanIP = "192.168.1.1/24"
		}
		upsert(bootIfaceSpec{
			Name:   "lan",
			Role:   "lan",
			Device: d,
			Mode:   lanMode,
			IPv4:   lanIP,
		})
	}
	if d := validDev(config["OPT1_INTERFACE"]); d != "" {
		upsert(bootIfaceSpec{
			Name:   "opt1",
			Role:   "lan",
			Device: d,
			Mode:   config["OPT1_MODE"],
			IPv4:   validCIDR(config["OPT1_IPV4_ADDRESS"]),
		})
	}
	if d := validDev(config["OPT2_INTERFACE"]); d != "" {
		upsert(bootIfaceSpec{
			Name:   "opt2",
			Role:   "lan",
			Device: d,
			Mode:   config["OPT2_MODE"],
			IPv4:   validCIDR(config["OPT2_IPV4_ADDRESS"]),
		})
	}

	// 2. N-interface keys (IFACE_<NAME>_DEVICE, etc.) in interfaces.conf (sorted for deterministic order)
	var confKeys []string
	for k := range config {
		confKeys = append(confKeys, k)
	}
	sort.Strings(confKeys)
	for _, k := range confKeys {
		v := config[k]
		if strings.HasPrefix(k, "IFACE_") && strings.HasSuffix(k, "_DEVICE") {
			rawName := strings.TrimSuffix(strings.TrimPrefix(k, "IFACE_"), "_DEVICE")
			if rawName == "" {
				continue
			}
			prefix := "IFACE_" + rawName
			logicalName := strings.TrimSpace(config[prefix+"_NAME"])
			if logicalName == "" {
				logicalName = strings.ToLower(rawName)
			}
			dev := validDev(v)
			if dev == "" {
				remove(logicalName)
				continue
			}
			upsert(bootIfaceSpec{
				Name:    logicalName,
				Role:    strings.ToLower(config[prefix+"_ROLE"]),
				Device:  dev,
				Mode:    strings.ToLower(config[prefix+"_MODE"]),
				IPv4:    validCIDR(config[prefix+"_IPV4_ADDRESS"]),
				Gateway: validIP(config[prefix+"_IPV4_GATEWAY"]),
			})
		}
	}

	// 3. Merge interfaces from /etc/axonwall/interfaces.yaml or /var/lib/axonwall/etc-axonwall/interfaces.yaml
	confStat, errConfStat := os.Stat("/etc/axonwall/interfaces.conf")
	for _, yamlPath := range []string{"/etc/axonwall/interfaces.yaml", "/var/lib/axonwall/etc-axonwall/interfaces.yaml"} {
		yamlStat, errYamlStat := os.Stat(yamlPath)
		raw, err := os.ReadFile(yamlPath)
		if err != nil || len(raw) == 0 {
			continue
		}
		var parsed struct {
			Interfaces []struct {
				Name        string `yaml:"name"`
				Role        string `yaml:"role"`
				Device      string `yaml:"device"`
				Type        string `yaml:"type"`
				IPv4Mode    string `yaml:"ipv4Mode"`
				Enabled     *bool  `yaml:"enabled"`
				IPv4Address string `yaml:"ipv4Address"`
				IPv4Gateway string `yaml:"ipv4Gateway"`
			} `yaml:"interfaces"`
		}
		if yaml.Unmarshal(raw, &parsed) == nil && len(parsed.Interfaces) > 0 {
			// If interfaces.yaml was modified more recently than interfaces.conf, treat interfaces.yaml
			// as authoritative and prune any stale interfaces from interfaces.conf that were deleted.
			if errYamlStat == nil && (errConfStat != nil || yamlStat.ModTime().After(confStat.ModTime().Add(2*time.Second))) {
				presentInYaml := make(map[string]bool)
				for _, yIface := range parsed.Interfaces {
					presentInYaml[strings.ToLower(strings.TrimSpace(yIface.Name))] = true
				}
				for existingName := range byName {
					if !presentInYaml[existingName] {
						remove(existingName)
					}
				}
			}
			for _, yIface := range parsed.Interfaces {
				if yIface.Enabled != nil && !*yIface.Enabled {
					remove(yIface.Name)
					continue
				}
				dev := validDev(yIface.Device)
				if dev == "" {
					remove(yIface.Name)
					continue
				}
				mode := yIface.Type
				if mode == "" {
					mode = yIface.IPv4Mode
				}
				upsert(bootIfaceSpec{
					Name:    yIface.Name,
					Role:    yIface.Role,
					Device:  dev,
					Mode:    mode,
					IPv4:    validCIDR(yIface.IPv4Address),
					Gateway: validIP(yIface.IPv4Gateway),
				})
			}
			break
		}
	}

	// 4. Also merge interfaces from /etc/axonwall/state.json or /var/lib/axonwall/state.json
	for _, statePath := range []string{"/etc/axonwall/state.json", "/var/lib/axonwall/state.json"} {
		raw, err := os.ReadFile(statePath)
		if err != nil {
			continue
		}
		var parsed struct {
			Interfaces []struct {
				Name        string `json:"name"`
				Role        string `json:"role"`
				Device      string `json:"device"`
				Type        string `json:"type"`
				Enabled     *bool  `json:"enabled"`
				IPv4Address string `json:"ipv4Address"`
				IPv4Gateway string `json:"ipv4Gateway"`
			} `json:"interfaces"`
		}
		if json.Unmarshal(raw, &parsed) == nil && len(parsed.Interfaces) > 0 {
			for _, stIface := range parsed.Interfaces {
				if stIface.Enabled != nil && !*stIface.Enabled {
					remove(stIface.Name)
					continue
				}
				dev := validDev(stIface.Device)
				if dev == "" {
					remove(stIface.Name)
					continue
				}
				upsert(bootIfaceSpec{
					Name:    stIface.Name,
					Role:    stIface.Role,
					Device:  dev,
					Mode:    stIface.Type,
					IPv4:    validCIDR(stIface.IPv4Address),
					Gateway: validIP(stIface.IPv4Gateway),
				})
			}
			break
		}
	}

	seenDev := make(map[string]bool)
	var specs []bootIfaceSpec
	for _, name := range order {
		s, ok := byName[name]
		if !ok || seenDev[s.Device] {
			continue
		}
		seenDev[s.Device] = true
		specs = append(specs, s)
	}
	return specs
}

// staleStaticAddrs parses `ip -4 addr show dev <device>` output and
// returns the global (non-secondary, non-link-local) addresses that are
// not the target address. A-M16: the old code ran `ip addr flush` on
// every WAN bundle apply, deleting keepalived VRRP VIPs (which live on
// the device as secondary addresses) along with the stale static
// address it meant to remove. Secondary addresses are therefore never
// returned here, so a VIP survives an unrelated bundle apply.
func staleStaticAddrs(addrShowOut string, targetCIDR string) []string {
	targetIP := strings.Split(targetCIDR, "/")[0]
	var stale []string
	for _, line := range strings.Split(addrShowOut, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "inet ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addr := fields[1]
		ip := strings.Split(addr, "/")[0]
		if addr == targetCIDR || ip == targetIP {
			continue
		}
		// Keepalived VIPs are secondary addresses; link-local
		// addresses are not stale statics either.
		if strings.Contains(line, " secondary") || strings.Contains(line, " scope link") {
			continue
		}
		if net.ParseIP(ip) == nil {
			continue
		}
		stale = append(stale, addr)
	}
	return stale
}

// staticWanGateway is one static WAN's default-route candidate.
type staticWanGateway struct {
	gateway string
	device  string
}

// ipRouteReplaceDefault installs the default route via one gateway.
// A variable so tests can simulate failing/succeeding gateways
// without touching kernel routes.
var ipRouteReplaceDefault = func(gateway, dev string) error {
	return exec.Command("ip", "route", "replace", "default", "via", gateway, "dev", dev).Run()
}

// installStaticDefaultRoute tries each static WAN gateway in order
// until one installs (M6). Pre-fix, the first attempt's error was
// discarded and the route was marked set regardless, so a second
// configured WAN gateway was never tried and the box could end up
// with no default route while a reachable gateway was configured.
func installStaticDefaultRoute(gateways []staticWanGateway) error {
	var lastErr error
	for _, gw := range gateways {
		if err := ipRouteReplaceDefault(gw.gateway, gw.device); err != nil {
			lastErr = err
			log.Printf("[Agent] Boot-apply: failed to install default route via %s on %s: %v", gw.gateway, gw.device, err)
			continue
		}
		return nil
	}
	if lastErr == nil {
		return nil
	}
	return fmt.Errorf("no static WAN gateway yielded a default route (last error: %w)", lastErr)
}

func applyBootInterfaces() error {
	sanitizeEtcNetworkInterfaces()

	config := make(map[string]string)
	if data, err := os.ReadFile("/etc/axonwall/interfaces.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			config[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	specs := loadAllBootInterfaces(config)
	if len(specs) == 0 {
		return nil
	}

	validIP := func(ip string) string {
		if net.ParseIP(ip) == nil {
			return ""
		}
		return ip
	}
	wanDNS1 := validIP(config["WAN_DNS1"])
	wanDNS2 := validIP(config["WAN_DNS2"])

	// Ensure fast DNS failover (1s timeout instead of 5s glibc default) and fallback resolvers
	_ = os.WriteFile("/etc/resolv.conf.head", []byte("options timeout:1 attempts:2\n"), 0644)
	{
		var tail strings.Builder
		if wanDNS1 != "" {
			tail.WriteString(fmt.Sprintf("nameserver %s\n", wanDNS1))
		} else {
			tail.WriteString("nameserver 1.1.1.1\n")
		}
		if wanDNS2 != "" {
			tail.WriteString(fmt.Sprintf("nameserver %s\n", wanDNS2))
		} else {
			tail.WriteString("nameserver 8.8.8.8\n")
		}
		_ = os.WriteFile("/etc/resolv.conf.tail", []byte(tail.String()), 0644)
	}
	if rData, rErr := os.ReadFile("/etc/resolv.conf"); rErr == nil && len(rData) > 0 && !strings.Contains(string(rData), "options timeout:") {
		_ = os.WriteFile("/etc/resolv.conf", []byte("options timeout:1 attempts:2\n"+string(rData)), 0644)
	}

	var dhcpSpecs []bootIfaceSpec
	// M6: static WAN gateways are collected during the loop and the
	// default route is installed afterwards by
	// installStaticDefaultRoute, which tries each in turn.
	var staticGateways []staticWanGateway
	// A-M16: the first static-WAN address failure is returned to the
	// caller (ApplyBundle fails the apply) instead of being logged
	// while the WAN is left address-less after a flush.
	var firstIfaceErr error

	for _, spec := range specs {
		if spec.Role == "wan-delegated" {
			log.Printf("[Agent] Boot-apply: delegating WAN device %s (%s) to br-wan (host L3 disabled)", spec.Device, spec.Name)
			if err := engine.HardenDelegatedWAN(spec.Device, "br-wan"); err != nil {
				log.Printf("[Agent] Boot-apply: warning hardening delegated WAN %s: %v", spec.Device, err)
			}
			if err := engine.EnsureBridge(engine.BridgeSpec{
				Name:             "br-wan",
				Members:          []string{spec.Device},
				DisableNetfilter: true,
				IsolateHostStack: true,
			}); err != nil {
				log.Printf("[Agent] Boot-apply: warning ensuring br-wan for %s: %v", spec.Device, err)
			}
			continue
		}

		_ = exec.Command("ip", "link", "set", spec.Device, "up").Run()
		if spec.Mode == "static" && spec.IPv4 != "" {
			out, _ := exec.Command("ip", "-4", "addr", "show", "dev", spec.Device).CombinedOutput()
			ipOnly := strings.Split(spec.IPv4, "/")[0]
			if !strings.Contains(string(out), "inet "+spec.IPv4) && !strings.Contains(string(out), "inet "+ipOnly+"/") {
				log.Printf("[Agent] Boot-apply: configuring static IP %s on %s (%s, role=%s)", spec.IPv4, spec.Name, spec.Device, spec.Role)
				if spec.Role == "wan" {
					// A-M16: never flush the device — that deletes
					// HA VIPs and secondary addresses. Delete only
					// the specific stale global addresses, then use
					// `ip addr replace` (add-or-replace just this
					// address) for the target.
					for _, stale := range staleStaticAddrs(string(out), spec.IPv4) {
						if delOut, err := exec.Command("ip", "addr", "del", stale, "dev", spec.Device).CombinedOutput(); err != nil {
							log.Printf("[Agent] Boot-apply: warning: failed to remove stale address %s on %s: %s", stale, spec.Device, string(delOut))
						}
					}
				}
				if addOut, err := exec.Command("ip", "addr", "replace", spec.IPv4, "dev", spec.Device).CombinedOutput(); err != nil {
					log.Printf("[Agent] Boot-apply: failed to assign IP %s on %s: %s", spec.IPv4, spec.Device, string(addOut))
					if firstIfaceErr == nil {
						firstIfaceErr = fmt.Errorf("failed to assign IP %s on %s: %s", spec.IPv4, spec.Device, string(addOut))
					}
				}
			}
			if spec.Gateway != "" && spec.Role == "wan" {
				staticGateways = append(staticGateways, staticWanGateway{gateway: spec.Gateway, device: spec.Device})
			}
			if spec.Role == "wan" && (wanDNS1 != "" || wanDNS2 != "") {
				if rData, rErr := os.ReadFile("/etc/resolv.conf"); rErr != nil || len(strings.TrimSpace(string(rData))) == 0 {
					var resolv strings.Builder
					resolv.WriteString("# Generated by Axonwall\noptions timeout:1 attempts:2\n")
					if wanDNS1 != "" {
						resolv.WriteString(fmt.Sprintf("nameserver %s\n", wanDNS1))
					}
					if wanDNS2 != "" {
						resolv.WriteString(fmt.Sprintf("nameserver %s\n", wanDNS2))
					}
					_ = os.WriteFile("/etc/resolv.conf", []byte(resolv.String()), 0644)
				}
			}
		} else if spec.Mode == "dhcp" {
			dhcpSpecs = append(dhcpSpecs, spec)
			out, _ := exec.Command("ip", "-4", "addr", "show", "dev", spec.Device).CombinedOutput()
			if !strings.Contains(string(out), "inet ") {
				log.Printf("[Agent] Boot-apply: starting DHCP client on %s (%s, role=%s)", spec.Name, spec.Device, spec.Role)
				triggerDhcpClient(spec.Device, spec.Role)
			}
		}
	}

	// M6: install the default route from the first static WAN gateway
	// that accepts it. If no WAN yields one, the apply fails loudly
	// instead of reporting success with no default route.
	if len(staticGateways) > 0 {
		if err := installStaticDefaultRoute(staticGateways); err != nil {
			log.Printf("[Agent] Boot-apply: %v", err)
			if firstIfaceErr == nil {
				firstIfaceErr = err
			}
		}
	}

	// Static routes configuration
	if err := ReconcileStaticRoutes(); err != nil {
		log.Printf("[Agent] Boot-apply: static routes reconciliation: %v", err)
	}

	// Post-boot DHCP & static route verification once networking.service settles
	if len(dhcpSpecs) > 0 {
		schedulePostBootVerification(dhcpSpecs)
	}

	return firstIfaceErr
}

// postBootVerificationDelays are the waits before each post-boot DHCP /
// static-route verification round. A variable (not constants) so tests
// can shrink them; production values are unchanged (8s, 20s).
var postBootVerificationDelays = []time.Duration{8 * time.Second, 20 * time.Second}

// postBootReconcileStaticRoutes is the reconcile step run by the
// post-boot verifier. A variable so tests can observe invocations
// without touching kernel routes; production always calls
// ReconcileStaticRoutes.
var postBootReconcileStaticRoutes = ReconcileStaticRoutes

var postBootVerificationMu sync.Mutex
var postBootVerificationCancel context.CancelFunc

// schedulePostBootVerification starts the post-boot DHCP/static-route
// verification goroutine, cancelling any previous one (A-M12). Every
// bundle apply that touches a DHCP interface used to spawn another
// goroutine, so an earlier goroutine's prune phase could delete a
// route the newer config just installed; now at most one verifier
// runs, and it is cancelled by the next apply.
func schedulePostBootVerification(ifSpecs []bootIfaceSpec) {
	postBootVerificationMu.Lock()
	if postBootVerificationCancel != nil {
		postBootVerificationCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	postBootVerificationCancel = cancel
	postBootVerificationMu.Unlock()
	go runPostBootVerification(ctx, ifSpecs)
}

func runPostBootVerification(ctx context.Context, ifSpecs []bootIfaceSpec) {
	for _, delay := range postBootVerificationDelays {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		for _, sp := range ifSpecs {
			if ctx.Err() != nil {
				return
			}
			out, _ := exec.Command("ip", "-4", "addr", "show", "dev", sp.Device).CombinedOutput()
			if !dhcpClientRunning(sp.Device) || !strings.Contains(string(out), "inet ") {
				log.Printf("[Agent] Post-boot check: ensuring DHCP client is active on %s", sp.Device)
				triggerDhcpClient(sp.Device, sp.Role)
			}
		}
		if ctx.Err() != nil {
			return
		}
		_ = postBootReconcileStaticRoutes()
	}
}

func reconcileBootAntiLockoutNft(hasLkgBundle bool) {
	config := make(map[string]string)
	if data, err := os.ReadFile("/etc/axonwall/interfaces.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			config[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	specs := loadAllBootInterfaces(config)
	if len(specs) == 0 {
		return
	}

	var wanDevs []string
	wanDevSet := make(map[string]bool)
	var lanSpecs []bootIfaceSpec
	internalHasLink := false

	for _, s := range specs {
		if s.Role == "wan-delegated" {
			wanDevSet[s.Device] = true
			continue
		}
		if s.Role == "wan" {
			wanDevs = append(wanDevs, s.Device)
			wanDevSet[s.Device] = true
		} else {
			lanSpecs = append(lanSpecs, s)
			if cData, cErr := os.ReadFile(filepath.Join("/sys/class/net", s.Device, "carrier")); cErr == nil && strings.TrimSpace(string(cData)) == "1" {
				internalHasLink = true
			}
		}
	}

	// Update /usr/share/axonwall/lockdown.nft so wan_interfaces matches actual multi-WAN topology
	lockdownPath := "/usr/share/axonwall/lockdown.nft"
	if lData, lErr := os.ReadFile(lockdownPath); lErr == nil {
		content := string(lData)
		elems := []string{`"wan0"`}
		if internalHasLink {
			for _, wd := range wanDevs {
				if wd != "" && wd != "wan0" {
					elems = append(elems, fmt.Sprintf("%q", wd))
				}
			}
		}
		newElements := fmt.Sprintf("elements = { %s }", strings.Join(elems, ", "))
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

	// Ensure all configured LAN interfaces are permitted for anti-lockout in inet axonwall input
	currentRulesOut, _ := exec.Command("nft", "list", "chain", "inet", "axonwall", "input").CombinedOutput()
	currentRules := string(currentRulesOut)
	for _, entry := range lanSpecs {
		if entry.Device == "" || wanDevSet[entry.Device] {
			continue
		}
		if !strings.Contains(currentRules, fmt.Sprintf(`iifname %q tcp dport`, entry.Device)) {
			_ = exec.Command(
				"nft", "insert", "rule", "inet", "axonwall", "input",
				"iifname", entry.Device,
				"tcp", "dport", "{ 22, 80, 443, 2966, 3000 }",
				"accept", "comment", fmt.Sprintf("\"anti-lockout-%s\"", entry.Name),
			).Run()
		}
	}
}

func syncFile(srcPath, dstPath string, perm os.FileMode) {
	base := filepath.Base(srcPath)
	if base == "admin.env" || base == "axonwall.env" || base == "agent.token" || base == "controller.env" || base == "mfa.env" || base == "slapd.seed" {
		return
	}
	srcInfo, err1 := os.Lstat(srcPath)
	if err1 != nil || (srcInfo.Mode()&os.ModeSymlink) != 0 {
		return
	}
	dstInfo, err2 := os.Lstat(dstPath)
	if err2 == nil && (dstInfo.Mode()&os.ModeSymlink) != 0 {
		return
	}
	if err2 != nil || srcInfo.ModTime().After(dstInfo.ModTime()) {
		if data, err := os.ReadFile(srcPath); err == nil {
			_ = os.WriteFile(dstPath, data, perm)
			ensureSharedConfigPerm(dstPath, perm)
		}
	} else if dstInfo.ModTime().After(srcInfo.ModTime()) {
		// Also sync newer /etc/axonwall edits back to /var/lib/axonwall/etc-axonwall
		if data, err := os.ReadFile(dstPath); err == nil {
			_ = os.WriteFile(srcPath, data, perm)
			ensureSharedConfigPerm(srcPath, perm)
		}
	}
}

func syncPersistentYamlConfigs() {
	srcDir := "/var/lib/axonwall/etc-axonwall"
	dstDir := "/etc/axonwall"
	_ = os.MkdirAll(srcDir, 0775)
	_ = os.MkdirAll(dstDir, 0775)
	_ = os.MkdirAll(filepath.Join(dstDir, "conf.d"), 0775)
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		normalizeConfigTreePermissions()
		return
	}

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
							syncFile(filepath.Join(srcDir, "conf.d", cName), filepath.Join(dstDir, "conf.d", cName), 0660)
						}
					}
				}
			}
			continue
		}

		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") || name == "state.json" {
			syncFile(filepath.Join(srcDir, name), filepath.Join(dstDir, name), 0660)
		}
	}

	// Also ensure administrative credentials, MFA secrets, MCP configs, controller configs, and interface assignments are synced
	syncFile(filepath.Join(srcDir, "admin.env"), filepath.Join(dstDir, "admin.env"), 0660)
	syncFile(filepath.Join(srcDir, "mfa.env"), filepath.Join(dstDir, "mfa.env"), 0660)
	syncFile(filepath.Join(srcDir, "mcp-keys.json"), filepath.Join(dstDir, "mcp-keys.json"), 0660)
	syncFile(filepath.Join(srcDir, "mcp-settings.json"), filepath.Join(dstDir, "mcp-settings.json"), 0660)
	syncFile(filepath.Join(srcDir, "controller.env"), filepath.Join(dstDir, "controller.env"), 0640)
	syncFile(filepath.Join(srcDir, "interfaces.conf"), filepath.Join(dstDir, "interfaces.conf"), 0664)
	normalizeConfigTreePermissions()
}

func ensureStandardPath() {
	required := []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}
	current := filepath.SplitList(os.Getenv("PATH"))
	seen := make(map[string]bool, len(current))
	for _, p := range current {
		if p != "" {
			seen[p] = true
		}
	}
	for _, req := range required {
		if !seen[req] {
			current = append(current, req)
		}
	}
	_ = os.Setenv("PATH", strings.Join(current, string(os.PathListSeparator)))
}

func main() {
	ensureStandardPath()
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
		// A-M16: log a failed interface apply at boot; boot itself
		// must not abort on one interface (the post-boot checks and
		// later bundle applies still run).
		if err := applyBootInterfaces(); err != nil {
			log.Printf("[Agent] Boot-apply: boot interfaces failed: %v", err)
		}

		lkgPath := filepath.Join(*bundleDir, "last-known-good.nft")
		hasLkg := false
		if pendingConfirmIsLive(*bundleDir) {
			// M3: a confirm is still pending from the previous run
			// with time left on its deadline. The live ruleset is
			// that unconfirmed bundle; applying LKG here would roll
			// it back underneath the restored pending state (see
			// NewAgentServer), so leave the kernel alone.
			log.Printf("[Agent] Early-boot: a configuration confirm is still pending from the previous run; skipping last-known-good apply so the pending bundle stays live until its deadline")
		} else if _, err := os.Stat(lkgPath); err == nil {
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
		if keaHasActiveInterfaces() {
			_, _ = reloadOrRestartService("kea-dhcp4-server")
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
	go virtManager.AutostartAll()
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
	pluginManager.SetDirectoryManager(directoryManager)
	mcpTrafficManager := engine.NewMcpTrafficManager()
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
	if err := ebpfManager.Start([]string{"eth0"}); err != nil {
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
			agentServer.mu.Lock()
			currentPendingJobID := agentServer.pendingJobID
			agentServer.mu.Unlock()
			statusMap := map[string]interface{}{
				"node_id":               resp.NodeId,
				"version":               resp.Version,
				"uptime_seconds":        resp.UptimeSeconds,
				"active_bundle_hash":    resp.ActiveBundleHash,
				"pending_confirm":       resp.PendingConfirm,
				"pendingConfirm":        resp.PendingConfirm,
				"confirm_deadline_unix": resp.ConfirmDeadlineUnix,
				"confirmDeadlineUnix":   resp.ConfirmDeadlineUnix,
				"pending_job_id":        currentPendingJobID,
				"pendingJobId":          currentPendingJobID,
				"interfaces":            resp.Interfaces,
			}
			_ = json.NewEncoder(w).Encode(statusMap)
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
		mux.HandleFunc("/v1/system/zbm", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				bes, err := watchdog.ListBootEnvironments()
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success":          true,
					"bootEnvironments": bes,
					"status":           watchdog.GetStatus(),
				})
				return
			}
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				Action    string `json:"action"` // "list", "snapshot", "clone", "activate", "delete"
				BeName    string `json:"beName,omitempty"`
				Label     string `json:"label,omitempty"`
				Snapshot  string `json:"snapshot,omitempty"`
				NewBeName string `json:"newBeName,omitempty"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
				return
			}
			action := strings.ToLower(strings.TrimSpace(req.Action))
			switch action {
			case "list":
				bes, err := watchdog.ListBootEnvironments()
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success":          true,
					"bootEnvironments": bes,
				})
			case "snapshot":
				snap, err := watchdog.CreateBootEnvironmentSnapshot(req.BeName, req.Label)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				var clonedDataset string
				if strings.TrimSpace(req.NewBeName) != "" {
					target, cloneErr := watchdog.CloneSnapshotToBootEnvironment(snap, req.NewBeName)
					if cloneErr != nil {
						http.Error(w, fmt.Sprintf("Created snapshot %s, but cloning to BE failed: %v", snap, cloneErr), http.StatusBadRequest)
						return
					}
					clonedDataset = target
				}
				bes, _ := watchdog.ListBootEnvironments()
				w.Header().Set("Content-Type", "application/json")
				msg := fmt.Sprintf("Created snapshot %s", snap)
				if clonedDataset != "" {
					msg = fmt.Sprintf("Created snapshot %s and cloned to Boot Environment %s", snap, clonedDataset)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success":          true,
					"message":          msg,
					"snapshot":         snap,
					"dataset":          clonedDataset,
					"bootEnvironments": bes,
				})
			case "delete-snapshot":
				if err := watchdog.DeleteBootEnvironmentSnapshot(req.Snapshot); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				bes, _ := watchdog.ListBootEnvironments()
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success":          true,
					"message":          fmt.Sprintf("Deleted snapshot %s", req.Snapshot),
					"bootEnvironments": bes,
				})
			case "rollback-snapshot":
				if err := watchdog.RollbackBootEnvironmentSnapshot(req.Snapshot); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				bes, _ := watchdog.ListBootEnvironments()
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success":          true,
					"message":          fmt.Sprintf("Rolled back to snapshot %s", req.Snapshot),
					"bootEnvironments": bes,
				})
			case "clone":
				target, err := watchdog.CloneSnapshotToBootEnvironment(req.Snapshot, req.NewBeName)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				bes, _ := watchdog.ListBootEnvironments()
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success":          true,
					"message":          fmt.Sprintf("Cloned snapshot %s to Boot Environment %s", req.Snapshot, target),
					"dataset":          target,
					"bootEnvironments": bes,
				})
			case "activate":
				if err := watchdog.ActivateBootEnvironment(req.BeName); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				bes, _ := watchdog.ListBootEnvironments()
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success":          true,
					"message":          fmt.Sprintf("Boot Environment %s armed for next boot", req.BeName),
					"bootEnvironments": bes,
				})
			case "delete":
				if err := watchdog.DeleteBootEnvironment(req.BeName); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				bes, _ := watchdog.ListBootEnvironments()
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success":          true,
					"message":          fmt.Sprintf("Boot Environment %s deleted", req.BeName),
					"bootEnvironments": bes,
				})
			default:
				http.Error(w, fmt.Sprintf("unknown action: %s", action), http.StatusBadRequest)
			}
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
		mux.HandleFunc("/v1/ha/sync-trust", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if haEngine == nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"pkiEnrolled": false})
				return
			}
			_ = json.NewEncoder(w).Encode(haEngine.SyncTrustStatus())
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
				if req.Action == "unregister" {
					virtManager.UnregisterVMSpec(req.VMID)
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
			if r.Method == http.MethodDelete {
				pool := r.URL.Query().Get("pool")
				filename := r.URL.Query().Get("filename")
				if filename == "" {
					var req struct {
						Pool     string `json:"pool"`
						Filename string `json:"filename"`
					}
					_ = json.NewDecoder(r.Body).Decode(&req)
					if pool == "" {
						pool = req.Pool
					}
					filename = req.Filename
				}
				if err := virtManager.DeleteISO(pool, filename); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
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
			case "enable":
				resp = pluginManager.EnablePlugin(req.PluginID)
			case "disable":
				resp = pluginManager.DisablePlugin(req.PluginID)
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

		// =====================================================================
		// Security AI / VigilSOC MCP Tactical Traffic Control & Forensics APIs
		// =====================================================================
		writeMcpJSON := func(w http.ResponseWriter, status int, payload any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(payload)
		}

		checkMcpEnabled := func(w http.ResponseWriter) bool {
			if enabled, reason := engine.IsMcpSubsystemEnabled(); !enabled {
				writeMcpJSON(w, http.StatusServiceUnavailable, map[string]any{
					"success": false,
					"error":   reason,
				})
				return false
			}
			return true
		}

		mux.HandleFunc("/v1/mcp/posture", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				writeMcpJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "error": "Method not allowed"})
				return
			}
			if !checkMcpEnabled(w) {
				return
			}
			writeMcpJSON(w, http.StatusOK, map[string]any{
				"success": true,
				"posture": engine.DiscoverProtectedPosture(),
				"leases":  mcpTrafficManager.ListLeases(),
				// M9: a failed kernel rebuild leaves enforcement
				// stale; say so instead of listing leases as if
				// they were enforced.
				"reconcileDirty": mcpTrafficManager.ReconcileDirty(),
			})
		})

		mux.HandleFunc("/v1/mcp/leases", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				writeMcpJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "error": "Method not allowed"})
				return
			}
			if !checkMcpEnabled(w) {
				return
			}
			writeMcpJSON(w, http.StatusOK, map[string]any{
				"success": true,
				"leases":  mcpTrafficManager.ListLeases(),
				// M9: see the posture endpoint above.
				"reconcileDirty": mcpTrafficManager.ReconcileDirty(),
			})
		})

		mux.HandleFunc("/v1/mcp/blackhole", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				writeMcpJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "error": "Method not allowed"})
				return
			}
			if !checkMcpEnabled(w) {
				return
			}
			var req engine.McpBlackholeReq
			if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
				writeMcpJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": fmt.Sprintf("invalid json: %v", err)})
				return
			}
			lease, err := mcpTrafficManager.BlackholeTraffic(req)
			if err != nil {
				writeMcpJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
				return
			}
			writeMcpJSON(w, http.StatusOK, map[string]any{"success": true, "lease": lease})
		})

		mux.HandleFunc("/v1/mcp/shape", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				writeMcpJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "error": "Method not allowed"})
				return
			}
			if !checkMcpEnabled(w) {
				return
			}
			var req engine.McpShapeReq
			if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
				writeMcpJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": fmt.Sprintf("invalid json: %v", err)})
				return
			}
			lease, err := mcpTrafficManager.ShapeTraffic(req)
			if err != nil {
				writeMcpJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
				return
			}
			writeMcpJSON(w, http.StatusOK, map[string]any{"success": true, "lease": lease})
		})

		mux.HandleFunc("/v1/mcp/redirect", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				writeMcpJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "error": "Method not allowed"})
				return
			}
			if !checkMcpEnabled(w) {
				return
			}
			var req engine.McpRedirectReq
			if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
				writeMcpJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": fmt.Sprintf("invalid json: %v", err)})
				return
			}
			lease, err := mcpTrafficManager.RedirectTraffic(req)
			if err != nil {
				writeMcpJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
				return
			}
			writeMcpJSON(w, http.StatusOK, map[string]any{"success": true, "lease": lease})
		})

		mux.HandleFunc("/v1/mcp/sinkhole-dns", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				writeMcpJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "error": "Method not allowed"})
				return
			}
			if !checkMcpEnabled(w) {
				return
			}
			var req engine.McpDnsSinkholeReq
			if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
				writeMcpJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": fmt.Sprintf("invalid json: %v", err)})
				return
			}
			lease, err := mcpTrafficManager.SinkholeDNS(req)
			if err != nil {
				writeMcpJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
				return
			}
			writeMcpJSON(w, http.StatusOK, map[string]any{"success": true, "lease": lease})
		})

		mux.HandleFunc("/v1/mcp/revert", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				writeMcpJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "error": "Method not allowed"})
				return
			}
			if !checkMcpEnabled(w) {
				return
			}
			var req struct {
				LeaseID string `json:"leaseId"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil || req.LeaseID == "" {
				writeMcpJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "leaseId is required"})
				return
			}
			lease, err := mcpTrafficManager.RevertLease(req.LeaseID)
			if err != nil {
				writeMcpJSON(w, http.StatusNotFound, map[string]any{"success": false, "error": err.Error()})
				return
			}
			writeMcpJSON(w, http.StatusOK, map[string]any{"success": true, "revertedLease": lease})
		})

		mux.HandleFunc("/v1/mcp/flush", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				writeMcpJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "error": "Method not allowed"})
				return
			}
			if !checkMcpEnabled(w) {
				return
			}
			cleared, flushErr := mcpTrafficManager.FlushAllLeases()
			if flushErr != nil {
				writeMcpJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": flushErr.Error(), "clearedCount": cleared})
				return
			}
			writeMcpJSON(w, http.StatusOK, map[string]any{"success": true, "clearedCount": cleared})
		})

		mux.HandleFunc("/v1/mcp/flows", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				writeMcpJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "error": "Method not allowed"})
				return
			}
			if !checkMcpEnabled(w) {
				return
			}
			q := r.URL.Query()
			port, _ := strconv.Atoi(q.Get("port"))
			minBytes, _ := strconv.ParseUint(q.Get("minBytes"), 10, 64)
			limit, _ := strconv.Atoi(q.Get("limit"))
			flows := mcpTrafficManager.QueryActiveFlows(
				q.Get("srcIp"),
				q.Get("dstIp"),
				q.Get("protocol"),
				q.Get("state"),
				port,
				minBytes,
				limit,
			)
			writeMcpJSON(w, http.StatusOK, map[string]any{"success": true, "flows": flows})
		})

		mux.HandleFunc("/v1/mcp/host-context", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				writeMcpJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "error": "Method not allowed"})
				return
			}
			if !checkMcpEnabled(w) {
				return
			}
			ip := r.URL.Query().Get("ip")
			ctxData, err := mcpTrafficManager.InspectHostContext(ip)
			if err != nil {
				writeMcpJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
				return
			}
			writeMcpJSON(w, http.StatusOK, map[string]any{"success": true, "context": ctxData})
		})

		mux.HandleFunc("/v1/mcp/pcap-sample", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				writeMcpJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "error": "Method not allowed"})
				return
			}
			if !checkMcpEnabled(w) {
				return
			}
			var req struct {
				Interface       string `json:"interface"`
				SrcIP           string `json:"srcIp"`
				DstIP           string `json:"dstIp"`
				Protocol        string `json:"protocol"`
				Port            int    `json:"port"`
				MaxPackets      int    `json:"maxPackets"`
				DurationSeconds int    `json:"durationSeconds"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
				writeMcpJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": fmt.Sprintf("invalid json: %v", err)})
				return
			}
			packets, err := mcpTrafficManager.CapturePacketSample(
				req.Interface,
				req.SrcIP,
				req.DstIP,
				req.Protocol,
				req.Port,
				req.MaxPackets,
				req.DurationSeconds,
			)
			if err != nil {
				writeMcpJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
				return
			}
			writeMcpJSON(w, http.StatusOK, map[string]any{"success": true, "packets": packets})
		})

		// =====================================================================
		// Rosenpass Post-Quantum Hybrid Dual-KEM (Classic McEliece + ML-KEM) APIs
		// =====================================================================
		mux.HandleFunc("/v1/vpn/rosenpass/status", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			wgDev := r.URL.Query().Get("wgDevice")
			if wgDev == "" {
				wgDev = "wg0"
			}
			st := engine.GetRosenpassStatus(engine.DefaultRosenpassDir, wgDev)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(st)
		})

		mux.HandleFunc("/v1/vpn/rosenpass/keygen", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				Force bool `json:"force"`
			}
			_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req)
			if err := engine.ProvisionRosenpassEnvironment(engine.DefaultRosenpassDir); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
				return
			}
			shaHex, sizeBytes, err := engine.GenerateRosenpassKeypair(engine.DefaultRosenpassDir, req.Force)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":       true,
				"publicKeyPath": "/etc/rosenpass/pq.pk",
				"sizeBytes":     sizeBytes,
				"sha256":        shaHex,
			})
		})

		mux.HandleFunc("/v1/vpn/rosenpass/pubkey", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			pkPath := filepath.Join(engine.DefaultRosenpassDir, "pq.pk")
			data, err := os.ReadFile(pkPath)
			if err != nil || len(data) == 0 {
				// Auto-provision if missing
				if _, _, genErr := engine.GenerateRosenpassKeypair(engine.DefaultRosenpassDir, false); genErr == nil {
					data, err = os.ReadFile(pkPath)
				}
			}
			if err != nil {
				http.Error(w, fmt.Sprintf("public key not found: %v", err), http.StatusNotFound)
				return
			}
			sum := sha256.Sum256(data)
			shaHex := hex.EncodeToString(sum[:])
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":         true,
				"publicKeyBase64": base64.StdEncoding.EncodeToString(data),
				"sizeBytes":       len(data),
				"sha256":          shaHex,
			})
		})

		mux.HandleFunc("/v1/vpn/rosenpass/peer-pubkey", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				PeerName        string `json:"peerName"`
				PublicKeyBase64 string `json:"publicKeyBase64"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 2*1024*1024)).Decode(&req); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": fmt.Sprintf("invalid json: %v", err)})
				return
			}
			rawKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PublicKeyBase64))
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "invalid base64 publicKeyBase64 payload"})
				return
			}
			savedPath, shaHex, sizeBytes, err := engine.SaveRosenpassPeerPublicKey(engine.DefaultRosenpassDir, req.PeerName, rawKey)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":   true,
				"path":      savedPath,
				"sha256":    shaHex,
				"sizeBytes": sizeBytes,
			})
		})

		// =====================================================================
		// Host Malware, Rootkit & Ghost-in-the-Ring Kernel Telemetry APIs
		// =====================================================================
		mux.HandleFunc("/v1/security/rootkit/status", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			audit := engine.RunHostRootkitAudit()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(audit)
		})

		mux.HandleFunc("/v1/security/rootkit/scan", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			audit := engine.RunHostRootkitAudit()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(audit)
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
