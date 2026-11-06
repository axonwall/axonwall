package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type VigilanteCompiledBundle struct {
	K3sDependencyMet bool   `json:"k3sDependencyMet"`
	NftablesRuleset  string `json:"nftablesRuleset"`
	UnboundOverrides string `json:"unboundOverrides"`
	K3sManifests     string `json:"k3sManifests"`
	ConfigYaml       string `json:"configYaml"`
	LdapEnv          string `json:"ldapEnv"`
}

type VigilanteRuntimeBundle struct {
	Enabled        bool                     `json:"enabled"`
	K3sEnabled     bool                     `json:"k3sEnabled"`
	CompiledBundle *VigilanteCompiledBundle `json:"compiledBundle,omitempty"`
}

var (
	validPoolDatasetRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$`)
	validIncidentIDRegex  = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
)

// vigilanteEtcDir is a var (not a literal) so tests can redirect the
// ldap.env write; the production value is unchanged.
var vigilanteEtcDir = "/etc/axonwall/vigilante"

// removeFileIfExists removes path, tolerating an already-absent file.
// Any other failure is returned: a stale manifest that could not be
// removed must not be silently left live (A-M12, A-M15).
func removeFileIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// atomicFileWrite is one file in an all-or-nothing multi-file write
// (A-M12, A-M15).
type atomicFileWrite struct {
	path    string
	content string
	perm    os.FileMode
}

// writeFileAtomic writes a single file via temp+rename.
func writeFileAtomic(w atomicFileWrite) error {
	return writeFilesAtomic([]atomicFileWrite{w})
}

// writeFilesAtomic writes every file via a temp file in its own
// directory followed by a rename, so a failed write never leaves a
// truncated file behind — and if a later file fails, the ones already
// renamed are rolled back to their previous content (or removed, if
// they did not exist before), so a failed apply leaves the previous
// on-disk state instead of a mix of new and old files (A-M12). A
// pre-existing symlink at a destination is refused instead of
// replaced, preserving the O_NOFOLLOW intent of the old direct
// opens. All temp files are staged before any rename happens, so a
// failure while staging changes nothing on disk.
func writeFilesAtomic(writes []atomicFileWrite) error {
	type staged struct {
		write   atomicFileWrite
		tmpPath string
		existed bool
		prior   []byte
	}
	var stagedList []staged
	cleanup := func() {
		for _, s := range stagedList {
			_ = os.Remove(s.tmpPath)
		}
	}
	for _, w := range writes {
		if fi, err := os.Lstat(w.path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			cleanup()
			return fmt.Errorf("refusing to write %q: destination is a symlink", w.path)
		}
		prior, err := os.ReadFile(w.path)
		existed := err == nil
		tmp, err := os.CreateTemp(filepath.Dir(w.path), ".axonwall-tmp-*")
		if err != nil {
			cleanup()
			return fmt.Errorf("failed to create temp file for %q: %w", w.path, err)
		}
		if _, err := tmp.WriteString(w.content); err != nil {
			_ = tmp.Close()
			cleanup()
			return fmt.Errorf("failed to write %q: %w", w.path, err)
		}
		if err := tmp.Close(); err != nil {
			cleanup()
			return fmt.Errorf("failed to close %q: %w", w.path, err)
		}
		if err := os.Chmod(tmp.Name(), w.perm); err != nil {
			cleanup()
			return fmt.Errorf("failed to set permissions on %q: %w", w.path, err)
		}
		stagedList = append(stagedList, staged{write: w, tmpPath: tmp.Name(), existed: existed, prior: prior})
	}
	var renamed []staged
	for _, s := range stagedList {
		if err := os.Rename(s.tmpPath, s.write.path); err != nil {
			for _, r := range renamed {
				if r.existed {
					_ = os.WriteFile(r.write.path, r.prior, r.write.perm)
				} else {
					_ = os.Remove(r.write.path)
				}
			}
			cleanup()
			return fmt.Errorf("failed to install %q: %w", s.write.path, err)
		}
		renamed = append(renamed, s)
	}
	return nil
}

type BlockedIPRecord struct {
	IP        string    `json:"ip"`
	Family    string    `json:"family"`
	BlockedAt time.Time `json:"blockedAt"`
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
}

type VigilanteManager struct {
	mu           sync.RWMutex
	blockedIPs   map[string]BlockedIPRecord
	evidenceRoot string
	telemetryLog string
}

func NewVigilanteManager(evidenceRoot string) *VigilanteManager {
	if evidenceRoot == "" {
		evidenceRoot = "/var/lib/axonwall/vigilante"
	}
	return &VigilanteManager{
		blockedIPs:   make(map[string]BlockedIPRecord),
		evidenceRoot: evidenceRoot,
		telemetryLog: "/var/log/suricata/eve.json",
	}
}

// ValidateIPOrCIDR ensures input is a strictly valid IPv4/IPv6 address or CIDR without command injection
func ValidateIPOrCIDR(raw string) (string, string, error) {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return "", "", fmt.Errorf("ip or cidr cannot be empty")
	}

	// Reject whitespace or shell characters
	if strings.ContainsAny(clean, " \t\r\n;&|`$<>(){}[]\\") {
		return "", "", fmt.Errorf("invalid characters in ip or cidr: %q", raw)
	}

	if strings.Contains(clean, "/") {
		ip, _, err := net.ParseCIDR(clean)
		if err != nil {
			return "", "", fmt.Errorf("malformed cidr: %w", err)
		}
		if ip.To4() != nil {
			return clean, "ipv4", nil
		}
		return clean, "ipv6", nil
	}

	ip := net.ParseIP(clean)
	if ip == nil {
		return "", "", fmt.Errorf("malformed ip address: %q", clean)
	}

	if ip.To4() != nil {
		return clean, "ipv4", nil
	}
	return clean, "ipv6", nil
}

// BlockIP adds an offending IP address into the live nftables SOAR set
func (vm *VigilanteManager) BlockIP(rawIP string, timeoutSec int) error {
	cleanIP, family, err := ValidateIPOrCIDR(rawIP)
	if err != nil {
		return err
	}
	if _, _, _, err := ValidateTargetSafety(cleanIP, "", 0, 24, 64); err != nil {
		return err
	}

	if timeoutSec <= 0 {
		timeoutSec = 86400 // Default 24 hours
	}

	setName := "vigilante_soar_blocklist_v4"
	if family == "ipv6" {
		setName = "vigilante_soar_blocklist_v6"
	}

	// Execute nft element add with timeout
	// Example: nft add element inet axonwall vigilante_soar_blocklist_v4 { 198.51.100.200 timeout 86400s }
	elementSpec := fmt.Sprintf("{ %s timeout %ds }", cleanIP, timeoutSec)
	cmd := exec.Command("nft", "add", "element", "inet", "axonwall", setName, elementSpec)
	if out, err := cmd.CombinedOutput(); err != nil {
		// L20: the error used to be returned only when running as
		// root; as non-root the IP was recorded in blockedIPs and
		// returned nil while the kernel never got the element.
		// A block the kernel never got must not be recorded.
		return fmt.Errorf("failed to add IP %s to nftables SOAR blocklist: %s (%w)", cleanIP, string(out), err)
	}

	vm.mu.Lock()
	now := time.Now().UTC()
	vm.blockedIPs[cleanIP] = BlockedIPRecord{
		IP:        cleanIP,
		Family:    family,
		BlockedAt: now,
		ExpiresAt: now.Add(time.Duration(timeoutSec) * time.Second),
	}
	vm.mu.Unlock()

	log.Printf("[VigilanteManager] SOAR successfully blocked %s (family: %s, timeout: %ds)", cleanIP, family, timeoutSec)
	return nil
}

// UnblockIP removes an IP from the live nftables SOAR set
func (vm *VigilanteManager) UnblockIP(rawIP string) error {
	cleanIP, family, err := ValidateIPOrCIDR(rawIP)
	if err != nil {
		return err
	}

	setName := "vigilante_soar_blocklist_v4"
	if family == "ipv6" {
		setName = "vigilante_soar_blocklist_v6"
	}

	elementSpec := fmt.Sprintf("{ %s }", cleanIP)
	cmd := exec.Command("nft", "delete", "element", "inet", "axonwall", setName, elementSpec)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[VigilanteManager] nft delete element warning: %v, out: %s", err, string(out))
		// A-M11: mirror BlockIP — as root a failed kernel delete
		// is an error and the map entry stays, so ListBlockedIPs
		// never reports an IP unblocked while the kernel may still
		// drop its traffic. As non-root the nft call is
		// best-effort (the sandbox/CI case), as in BlockIP.
		if os.Geteuid() == 0 {
			return fmt.Errorf("failed to remove IP %s from nftables SOAR blocklist: %s (%w)", cleanIP, string(out), err)
		}
	}

	vm.mu.Lock()
	delete(vm.blockedIPs, cleanIP)
	vm.mu.Unlock()

	log.Printf("[VigilanteManager] SOAR unblocked %s", cleanIP)
	return nil
}

// ListBlockedIPs returns the list of currently active SOAR IP containments
func (vm *VigilanteManager) ListBlockedIPs() []BlockedIPRecord {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	now := time.Now().UTC()
	res := make([]BlockedIPRecord, 0, len(vm.blockedIPs))
	for _, rec := range vm.blockedIPs {
		if rec.ExpiresAt.IsZero() || rec.ExpiresAt.After(now) {
			res = append(res, rec)
		}
	}
	return res
}

// ProvisionEvidenceVault initializes a compressed ZFS dataset and folder hierarchy.
// (The old docstring promised an *encrypted* dataset, but the create
// command never set any encryption property — there is no ZFS encryption
// key infrastructure in this codebase — so the claim is dropped rather
// than left as a lie. See A-M44.)
func (vm *VigilanteManager) ProvisionEvidenceVault(pool, dataset string) error {
	if pool == "" {
		pool = "tank"
	}
	if dataset == "" {
		dataset = "vigilante-evidence"
	}

	fullSpec := fmt.Sprintf("%s/%s", pool, dataset)
	if !validPoolDatasetRegex.MatchString(fullSpec) {
		return fmt.Errorf("invalid pool or dataset name: %q", fullSpec)
	}

	// Create ZFS dataset with zstd compression if zfs is available
	cmd := exec.Command("zfs", "create", "-p", "-o", "compression=zstd", fullSpec)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[VigilanteManager] zfs create failed for %s (may already exist): %v, out: %s", fullSpec, err, string(out))
	}

	// A-M44 (round 2): the old code only logged a zfs create failure,
	// then fell back to the evidence root on / when the mountpoint did
	// not exist — so on a box without zfs (or with a failed create)
	// the caller reported "provisioned successfully" while no dataset
	// existed and evidence landed unencrypted on the root filesystem.
	// The dataset must be confirmed to exist, and the mountpoint must
	// actually be the dataset's mount — never a fallback onto /.
	if !zfsDatasetExists(fullSpec) {
		return fmt.Errorf("evidence vault dataset %s does not exist (zfs create failed)", fullSpec)
	}
	mountDir, err := zfsDatasetMountpoint(fullSpec)
	if err != nil {
		return fmt.Errorf("evidence vault dataset %s has no usable mountpoint: %w", fullSpec, err)
	}
	if !isMountpoint(mountDir) {
		// The dataset exists but is not mounted; try to mount it once.
		_ = exec.Command("zfs", "mount", fullSpec).Run()
		if !isMountpoint(mountDir) {
			return fmt.Errorf("evidence vault dataset %s is not mounted at %s", fullSpec, mountDir)
		}
	}

	subdirs := []string{
		"evidence",
		"datalake",
		"nmaps",
		"oobscans",
		"cti",
		"canary",
		"carved",
		"purpleteam",
		"ledger",
		"wasm",
		"values",
	}

	for _, sub := range subdirs {
		dir := filepath.Join(mountDir, sub)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create evidence vault dir %q: %w", dir, err)
		}
	}

	log.Printf("[VigilanteManager] Evidence vault provisioned at %s", mountDir)
	return nil
}

// zfsDatasetExists reports whether a ZFS dataset exists (via "zfs list").
// When the zfs binary is absent the command fails, so a box without zfs
// correctly reports no dataset (A-M44).
func zfsDatasetExists(spec string) bool {
	return exec.Command("zfs", "list", "-H", "-o", "name", spec).Run() == nil
}

// zfsDatasetMountpoint returns the configured mountpoint of a ZFS
// dataset. "none" and "legacy" are not usable mountpoints.
func zfsDatasetMountpoint(spec string) (string, error) {
	out, err := exec.Command("zfs", "get", "-H", "-o", "value", "mountpoint", spec).Output()
	if err != nil {
		return "", err
	}
	mp := strings.TrimSpace(string(out))
	if mp == "" || mp == "none" || mp == "legacy" {
		return "", fmt.Errorf("dataset mountpoint is %q", mp)
	}
	return mp, nil
}

// isMountpoint reports whether dir is an active mount point, by scanning
// /proc/mounts. A directory that merely exists (e.g. a stale empty dir
// where a dataset should be mounted) is not a mountpoint.
func isMountpoint(dir string) bool {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && unescapeMountField(fields[1]) == dir {
			return true
		}
	}
	return false
}

// unescapeMountField reverses the octal escaping /proc/mounts applies to
// mount paths (space -> \040, tab -> \011, newline -> \012, backslash ->
// \134).
func unescapeMountField(s string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(s)
}

// CreateIncidentSnapshot creates an immutable ZFS snapshot of the evidence vault for legal chain-of-custody
func (vm *VigilanteManager) CreateIncidentSnapshot(pool, dataset, incidentID string) (string, error) {
	if pool == "" {
		pool = "tank"
	}
	if dataset == "" {
		dataset = "vigilante-evidence"
	}
	targetDataset := fmt.Sprintf("%s/%s", pool, dataset)
	if !validPoolDatasetRegex.MatchString(targetDataset) {
		return "", fmt.Errorf("invalid pool or dataset name: %q", targetDataset)
	}
	if !validIncidentIDRegex.MatchString(incidentID) {
		return "", fmt.Errorf("invalid incident id: %q", incidentID)
	}

	fullSpec := fmt.Sprintf("%s@incident-%s", targetDataset, incidentID)
	cmd := exec.Command("zfs", "snapshot", fullSpec)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("zfs snapshot failed: %s (%w)", string(out), err)
	}

	log.Printf("[VigilanteManager] Created immutable incident snapshot: %s", fullSpec)
	return fullSpec, nil
}

// ApplyConfig reconciles the Vigilante runtime config.yaml, OpenLDAP SSO environment,
// and in-house K3s manifests (/var/lib/rancher/k3s/server/manifests/axonwall-vigilante.yaml).
func (vm *VigilanteManager) ApplyConfig(rawJSON []byte) error {
	var bundle VigilanteRuntimeBundle
	if err := json.Unmarshal(rawJSON, &bundle); err != nil {
		return fmt.Errorf("invalid vigilante runtime bundle json: %w", err)
	}

	manifestPath := filepath.Join(k3sServerManifestDir, "axonwall-vigilante.yaml")
	if !bundle.Enabled {
		if err := removeFileIfExists(manifestPath); err != nil {
			return fmt.Errorf("failed to remove stale vigilante manifest %q: %w", manifestPath, err)
		}
		return nil
	}

	// A-M12: validate the K3s manifest BEFORE writing anything. The
	// old code wrote config.yaml and ldap.env first and only then
	// validated, so a validation failure left new config on disk
	// paired with the stale manifest — and executeRollback restores
	// only the nft script, so the mixed state persisted until the
	// next successful bundle apply.
	if bundle.CompiledBundle != nil && (bundle.K3sEnabled || bundle.CompiledBundle.K3sDependencyMet) && bundle.CompiledBundle.K3sManifests != "" {
		if err := validateK3sManifest(bundle.CompiledBundle.K3sManifests); err != nil {
			return fmt.Errorf("vigilante K3s manifest failed security validation: %w", err)
		}
	}

	if err := os.MkdirAll(vm.evidenceRoot, 0750); err != nil {
		return fmt.Errorf("failed to create evidence root %q: %w", vm.evidenceRoot, err)
	}
	if err := os.MkdirAll(vigilanteEtcDir, 0750); err != nil {
		return fmt.Errorf("failed to create vigilante config dir %q: %w", vigilanteEtcDir, err)
	}

	if bundle.CompiledBundle != nil {
		// An empty manifests field withdraws the deployment: remove
		// the stale manifest BEFORE writing the new config files, so
		// a later write failure cannot leave new config paired with
		// a manifest the bundle meant to withdraw.
		if (bundle.K3sEnabled || bundle.CompiledBundle.K3sDependencyMet) && bundle.CompiledBundle.K3sManifests == "" {
			if err := removeFileIfExists(manifestPath); err != nil {
				return fmt.Errorf("failed to remove stale vigilante manifest %q: %w", manifestPath, err)
			}
		}
		var writes []atomicFileWrite
		if bundle.CompiledBundle.ConfigYaml != "" {
			writes = append(writes, atomicFileWrite{
				path:    filepath.Join(vm.evidenceRoot, "config.yaml"),
				content: bundle.CompiledBundle.ConfigYaml,
				perm:    0640,
			})
		}
		if bundle.CompiledBundle.LdapEnv != "" {
			writes = append(writes, atomicFileWrite{
				path:    filepath.Join(vigilanteEtcDir, "ldap.env"),
				content: bundle.CompiledBundle.LdapEnv,
				perm:    0640,
			})
		}
		if (bundle.K3sEnabled || bundle.CompiledBundle.K3sDependencyMet) && bundle.CompiledBundle.K3sManifests != "" {
			if err := os.MkdirAll(k3sServerManifestDir, 0755); err != nil {
				return fmt.Errorf("failed to create k3s manifest dir %q: %w", k3sServerManifestDir, err)
			}
			writes = append(writes, atomicFileWrite{
				path:    manifestPath,
				content: bundle.CompiledBundle.K3sManifests,
				perm:    0644,
			})
		}
		// A-M12: every write failure is returned (the old code
		// swallowed open failures and reported "Reconciled"), and
		// the writes land all-or-nothing via temp+rename.
		if err := writeFilesAtomic(writes); err != nil {
			return err
		}
	} else {
		if err := removeFileIfExists(manifestPath); err != nil {
			return fmt.Errorf("failed to remove stale vigilante manifest %q: %w", manifestPath, err)
		}
	}

	log.Printf("[VigilanteManager] Reconciled Vigilante runtime configuration and in-house K3s manifests")
	return nil
}

// StreamLiveTelemetry handles SSE streaming of live security alerts
// telemetryConsumedOffset returns how many bytes of the open file
// have been consumed through reader (the fd offset minus bytes the
// bufio reader has buffered but not yet delivered).
func telemetryConsumedOffset(f *os.File, reader *bufio.Reader) int64 {
	off, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0
	}
	return off - int64(reader.Buffered())
}

// telemetryFileRotated reports whether the file at path is no longer
// the file openFile points at (rotated away), or has shrunk below
// the offset already consumed (truncated in place). Either way the
// open fd will return EOF forever. A stat failure (file deleted but
// not yet recreated) reports neither: the caller keeps polling.
func telemetryFileRotated(openFile *os.File, path string, consumed int64) (rotated bool, truncated bool) {
	openInfo, err := openFile.Stat()
	if err != nil {
		return false, false
	}
	pathInfo, err := os.Stat(path)
	if err != nil {
		return false, false
	}
	if openStat, ok := openInfo.Sys().(*syscall.Stat_t); ok {
		if pathStat, ok := pathInfo.Sys().(*syscall.Stat_t); ok {
			if openStat.Ino != pathStat.Ino || openStat.Dev != pathStat.Dev {
				return true, false
			}
		}
	}
	if pathInfo.Size() < consumed {
		return false, true
	}
	return false, false
}

func (vm *VigilanteManager) StreamLiveTelemetry(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	logFile, err := os.Open(vm.telemetryLog)
	if err != nil {
		// If suricata eve.json is missing (e.g. fresh boot), emit heartbeat
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case t := <-ticker.C:
				sample := map[string]any{
					"source":    "axonwall-sensor",
					"severity":  "INFO",
					"rule":      "HEARTBEAT",
					"message":   "Vigilante sensor online. Listening on interfaces...",
					"time":      t.Format(time.RFC3339),
					"timestamp": t.UnixMilli(),
				}
				data, _ := json.Marshal(sample)
				_, _ = fmt.Fprintf(w, "event: telemetry\ndata: %s\n\n", data)
				flusher.Flush()
			}
		}
	}
	defer logFile.Close()

	// Seek to end of file to stream only new alerts
	_, _ = logFile.Seek(0, os.SEEK_END)
	reader := bufio.NewReader(logFile)
	var pendingLine string

	for {
		select {
		case <-r.Context().Done():
			return
		default:
			chunk, err := reader.ReadString('\n')
			if len(chunk) > 0 {
				pendingLine += chunk
			}
			if err == nil {
				line := strings.TrimSpace(pendingLine)
				pendingLine = ""
				if line != "" {
					var raw map[string]any
					if jsonErr := json.Unmarshal([]byte(line), &raw); jsonErr == nil {
						// Normalize suricata eve format
						event := map[string]any{
							"source":    "suricata",
							"severity":  "MEDIUM",
							"rule":      "Network Signature Alert",
							"message":   line,
							"time":      time.Now().Format(time.RFC3339),
							"timestamp": time.Now().UnixMilli(),
						}
						if alert, ok := raw["alert"].(map[string]any); ok {
							if sig, ok := alert["signature"].(string); ok {
								event["rule"] = sig
							}
							if sev, ok := alert["severity"].(float64); ok {
								if sev == 1 {
									event["severity"] = "CRITICAL"
								} else if sev == 2 {
									event["severity"] = "HIGH"
								}
							}
						}
						if src, ok := raw["src_ip"].(string); ok {
							event["srcIp"] = src
						}
						if dest, ok := raw["dest_ip"].(string); ok {
							event["destIp"] = dest
						}
						data, _ := json.Marshal(event)
						_, _ = fmt.Fprintf(w, "event: telemetry\ndata: %s\n\n", data)
						flusher.Flush()
					}
				}
			} else {
				// L16: eve.json may have been rotated (replaced)
				// or truncated while the stream is open. The open
				// fd then points at a deleted inode (or past EOF)
				// and ReadString returns EOF forever; detect that
				// and reopen instead of spinning silently on the
				// dead fd while the operator watches a live stream
				// that will never deliver another alert.
				if rotated, truncated := telemetryFileRotated(logFile, vm.telemetryLog, telemetryConsumedOffset(logFile, reader)); rotated || truncated {
					if rotated {
						if reopened, err := os.Open(vm.telemetryLog); err == nil {
							_ = logFile.Close()
							logFile = reopened
							_, _ = logFile.Seek(0, io.SeekEnd)
							reader = bufio.NewReader(logFile)
							pendingLine = ""
							log.Printf("[VigilanteManager] Telemetry log rotated; reopened %s", vm.telemetryLog)
						}
						// If the new file is not there yet, keep
						// polling the old fd (EOF) and retry.
					} else {
						// Same inode, shrunk in place
						// (copytruncate): everything in the file
						// now is new content, so rewind to the
						// start instead of the (stale) end.
						_, _ = logFile.Seek(0, io.SeekStart)
						reader = bufio.NewReader(logFile)
						pendingLine = ""
						log.Printf("[VigilanteManager] Telemetry log truncated; rewound %s", vm.telemetryLog)
					}
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
	}
}
