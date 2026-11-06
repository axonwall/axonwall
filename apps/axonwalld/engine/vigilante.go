package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
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
		log.Printf("[VigilanteManager] nft add element warning: %v, out: %s", err, string(out))
		if os.Geteuid() == 0 {
			return fmt.Errorf("failed to add IP %s to nftables SOAR blocklist: %s (%w)", cleanIP, string(out), err)
		}
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

	manifestPath := filepath.Join("/var/lib/rancher/k3s/server/manifests", "axonwall-vigilante.yaml")
	if !bundle.Enabled {
		_ = os.Remove(manifestPath)
		return nil
	}

	_ = os.MkdirAll(vm.evidenceRoot, 0750)
	_ = os.MkdirAll("/etc/axonwall/vigilante", 0750)

	if bundle.CompiledBundle != nil {
		if bundle.CompiledBundle.ConfigYaml != "" {
			cfgPath := filepath.Join(vm.evidenceRoot, "config.yaml")
			if f, err := os.OpenFile(cfgPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0640); err == nil {
				_, _ = f.WriteString(bundle.CompiledBundle.ConfigYaml)
				_ = f.Close()
			}
		}
		if bundle.CompiledBundle.LdapEnv != "" {
			envPath := "/etc/axonwall/vigilante/ldap.env"
			if f, err := os.OpenFile(envPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0640); err == nil {
				_, _ = f.WriteString(bundle.CompiledBundle.LdapEnv)
				_ = f.Close()
			}
		}
		if (bundle.K3sEnabled || bundle.CompiledBundle.K3sDependencyMet) && bundle.CompiledBundle.K3sManifests != "" {
			if err := validateK3sManifest(bundle.CompiledBundle.K3sManifests); err != nil {
				return fmt.Errorf("vigilante K3s manifest failed security validation: %w", err)
			}
			_ = os.MkdirAll("/var/lib/rancher/k3s/server/manifests", 0755)
			if f, err := os.OpenFile(manifestPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0644); err == nil {
				_, _ = f.WriteString(bundle.CompiledBundle.K3sManifests)
				_ = f.Close()
			}
		} else {
			_ = os.Remove(manifestPath)
		}
	} else {
		_ = os.Remove(manifestPath)
	}

	log.Printf("[VigilanteManager] Reconciled Vigilante runtime configuration and in-house K3s manifests")
	return nil
}

// StreamLiveTelemetry handles SSE streaming of live security alerts
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
				time.Sleep(200 * time.Millisecond)
			}
		}
	}
}
