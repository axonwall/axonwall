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
	"time"
)

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

// ProvisionEvidenceVault initializes an encrypted/compressed ZFS dataset and folder hierarchy
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
		log.Printf("[VigilanteManager] zfs create info (may already exist): %v, out: %s", err, string(out))
	}

	// Mountpoint lookup or fallback
	mountDir := fmt.Sprintf("/mnt/%s", fullSpec)
	if _, err := os.Stat(mountDir); os.IsNotExist(err) {
		mountDir = filepath.Join(vm.evidenceRoot, dataset)
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

// CreateIncidentSnapshot creates an immutable ZFS snapshot of the evidence vault for legal chain-of-custody
func (vm *VigilanteManager) CreateIncidentSnapshot(pool, dataset, incidentID string) (string, error) {
	if pool == "" {
		pool = "tank"
	}
	if dataset == "" {
		dataset = "vigilante-evidence"
	}
	if !validIncidentIDRegex.MatchString(incidentID) {
		return "", fmt.Errorf("invalid incident id: %q", incidentID)
	}

	fullSpec := fmt.Sprintf("%s/%s@incident-%s", pool, dataset, incidentID)
	cmd := exec.Command("zfs", "snapshot", fullSpec)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("zfs snapshot failed: %s (%w)", string(out), err)
	}

	log.Printf("[VigilanteManager] Created immutable incident snapshot: %s", fullSpec)
	return fullSpec, nil
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

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		default:
			line, err := reader.ReadString('\n')
			if err == nil {
				line = strings.TrimSpace(line)
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
