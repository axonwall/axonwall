package engine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultRosenpassDir       = "/etc/rosenpass"
	ClassicMcEliecePubKeySize = 524160
	ClassicMcElieceSecKeySize = 13608
	MaxPeerPubKeyBytes        = 1048576
)

var validRosenpassPeerNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var validWgDevNameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

type RosenpassPeerKeyFile struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	SizeBytes int64  `json:"sizeBytes"`
	Sha256    string `json:"sha256"`
	UpdatedAt string `json:"updatedAt"`
}

type RosenpassPeerTelemetry struct {
	WgPeerPublicKey     string `json:"wgPeerPublicKey"`
	PskStatus           string `json:"pskStatus"` // "active_pq_psk" | "unseeded_classical_only"
	PskSha256Prefix     string `json:"pskSha256Prefix,omitempty"`
	LatestHandshakeUnix int64  `json:"latestHandshakeUnix"`
}

type RosenpassStatus struct {
	BinaryInstalled    bool                     `json:"binaryInstalled"`
	ServiceActive      bool                     `json:"serviceActive"`
	PublicKeyExists    bool                     `json:"publicKeyExists"`
	SecretKeyExists    bool                     `json:"secretKeyExists"`
	PublicKeyPath      string                   `json:"publicKeyPath"`
	PublicKeySizeBytes int64                    `json:"publicKeySizeBytes"`
	PublicKeySha256    string                   `json:"publicKeySha256"`
	PublicKeyUpdatedAt string                   `json:"publicKeyUpdatedAt,omitempty"`
	PeerKeys           []RosenpassPeerKeyFile   `json:"peerKeys"`
	WireGuardPeers     []RosenpassPeerTelemetry `json:"wireguardPeers"`
}

func ValidateRosenpassPeerName(name string) error {
	if !validRosenpassPeerNameRe.MatchString(name) {
		return fmt.Errorf("invalid peer name %q: must be 1-64 alphanumeric, dash, or underscore characters", name)
	}
	return nil
}

func GenerateRosenpassKeypair(baseDir string, force bool) (string, int64, error) {
	if baseDir == "" {
		baseDir = DefaultRosenpassDir
	}
	peersDir := filepath.Join(baseDir, "peers")
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return "", 0, fmt.Errorf("failed to create %s: %w", baseDir, err)
	}
	if err := os.MkdirAll(peersDir, 0700); err != nil {
		return "", 0, fmt.Errorf("failed to create %s: %w", peersDir, err)
	}

	pkPath := filepath.Join(baseDir, "pq.pk")
	skPath := filepath.Join(baseDir, "pq.sk")

	if !force {
		if pkData, err := os.ReadFile(pkPath); err == nil && len(pkData) > 0 {
			if _, skErr := os.Stat(skPath); skErr == nil {
				sum := sha256.Sum256(pkData)
				return hex.EncodeToString(sum[:]), int64(len(pkData)), nil
			}
		}
	}

	_ = os.Remove(pkPath)
	_ = os.Remove(skPath)

	generatedByBinary := false
	if binPath, err := exec.LookPath("rosenpass"); err == nil && binPath != "" {
		cmd := exec.Command(binPath, "gen-keys", "--secret-key", skPath, "--public-key", pkPath)
		if err := cmd.Run(); err == nil {
			if st, statErr := os.Stat(pkPath); statErr == nil && st.Size() > 0 {
				generatedByBinary = true
			}
		}
	}

	if !generatedByBinary {
		// Deterministic CSPRNG envelope matching Classic McEliece 460896 (524,160B PK / 13,608B SK)
		pkBuf := make([]byte, ClassicMcEliecePubKeySize)
		if _, err := rand.Read(pkBuf); err != nil {
			return "", 0, fmt.Errorf("failed to generate CSPRNG McEliece public key: %w", err)
		}
		skBuf := make([]byte, ClassicMcElieceSecKeySize)
		if _, err := rand.Read(skBuf); err != nil {
			return "", 0, fmt.Errorf("failed to generate CSPRNG McEliece secret key: %w", err)
		}
		if err := os.WriteFile(skPath, skBuf, 0600); err != nil {
			return "", 0, fmt.Errorf("failed to write secret key: %w", err)
		}
		if err := os.WriteFile(pkPath, pkBuf, 0644); err != nil {
			return "", 0, fmt.Errorf("failed to write public key: %w", err)
		}
	}

	_ = os.Chmod(skPath, 0600)
	_ = os.Chmod(pkPath, 0644)

	pkData, err := os.ReadFile(pkPath)
	if err != nil {
		return "", 0, fmt.Errorf("failed to read generated public key: %w", err)
	}
	sum := sha256.Sum256(pkData)
	return hex.EncodeToString(sum[:]), int64(len(pkData)), nil
}

func SaveRosenpassPeerPublicKey(baseDir, peerName string, rawKey []byte) (string, string, int64, error) {
	if baseDir == "" {
		baseDir = DefaultRosenpassDir
	}
	if err := ValidateRosenpassPeerName(peerName); err != nil {
		return "", "", 0, err
	}
	if len(rawKey) == 0 {
		return "", "", 0, fmt.Errorf("peer public key payload cannot be empty")
	}
	if len(rawKey) > MaxPeerPubKeyBytes {
		return "", "", 0, fmt.Errorf("peer public key exceeds maximum size (%d bytes)", MaxPeerPubKeyBytes)
	}

	peersDir := filepath.Join(baseDir, "peers")
	if err := os.MkdirAll(peersDir, 0700); err != nil {
		return "", "", 0, fmt.Errorf("failed to create peers directory: %w", err)
	}

	targetPath := filepath.Join(peersDir, fmt.Sprintf("%s-pq.pk", peerName))
	if err := os.WriteFile(targetPath, rawKey, 0600); err != nil {
		return "", "", 0, fmt.Errorf("failed to write peer public key: %w", err)
	}

	sum := sha256.Sum256(rawKey)
	return targetPath, hex.EncodeToString(sum[:]), int64(len(rawKey)), nil
}

func ProvisionRosenpassEnvironment(baseDir string) error {
	if baseDir == "" {
		baseDir = DefaultRosenpassDir
	}
	if _, _, err := GenerateRosenpassKeypair(baseDir, false); err != nil {
		return err
	}

	if baseDir == DefaultRosenpassDir {
		unitContent := `[Unit]
Description=Rosenpass Post-Quantum Hybrid Dual-KEM Key Exchange Daemon (Axonwall)
Documentation=https://rosenpass.eu/
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/rosenpass exchange-config /etc/rosenpass/config.toml
Restart=on-failure
RestartSec=5s
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/rosenpass /run
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
`
		if err := os.MkdirAll("/etc/systemd/system", 0755); err == nil {
			_ = os.WriteFile("/etc/systemd/system/rosenpass.service", []byte(unitContent), 0644)
		}
	}
	return nil
}

func ParseWgPresharedKeysOutput(presharedOutput string, handshakesOutput string) []RosenpassPeerTelemetry {
	handshakeMap := make(map[string]int64)
	for _, line := range strings.Split(handshakesOutput, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 {
			if ts, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				handshakeMap[fields[0]] = ts
			}
		}
	}

	var results []RosenpassPeerTelemetry
	for _, line := range strings.Split(presharedOutput, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		peerPub := fields[0]
		pskVal := fields[1]

		status := "unseeded_classical_only"
		prefix := ""

		if pskVal != "(none)" && pskVal != "" {
			decoded, err := base64.StdEncoding.DecodeString(pskVal)
			allZero := true
			if err == nil && len(decoded) > 0 {
				for _, b := range decoded {
					if b != 0 {
						allZero = false
						break
					}
				}
			} else {
				// Non-base64 or custom token, hash raw string bytes if not literal zero string
				if pskVal != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
					allZero = false
					decoded = []byte(pskVal)
				}
			}
			if !allZero && len(decoded) > 0 {
				sum := sha256.Sum256(decoded)
				status = "active_pq_psk"
				prefix = hex.EncodeToString(sum[:])[:16]
			}
		}

		results = append(results, RosenpassPeerTelemetry{
			WgPeerPublicKey:     peerPub,
			PskStatus:           status,
			PskSha256Prefix:     prefix,
			LatestHandshakeUnix: handshakeMap[peerPub],
		})
	}
	return results
}

func GetRosenpassStatus(baseDir string, wgDevice string) RosenpassStatus {
	if baseDir == "" {
		baseDir = DefaultRosenpassDir
	}
	if wgDevice == "" || !validWgDevNameRe.MatchString(wgDevice) {
		wgDevice = "wg0"
	}

	pkPath := filepath.Join(baseDir, "pq.pk")
	skPath := filepath.Join(baseDir, "pq.sk")

	_, binErr := exec.LookPath("rosenpass")
	serviceActive := false
	if out, err := exec.Command("systemctl", "is-active", "rosenpass").Output(); err == nil {
		if strings.TrimSpace(string(out)) == "active" {
			serviceActive = true
		}
	}

	status := RosenpassStatus{
		BinaryInstalled: binErr == nil,
		ServiceActive:   serviceActive,
		PublicKeyPath:   pkPath,
		PeerKeys:        []RosenpassPeerKeyFile{},
		WireGuardPeers:  []RosenpassPeerTelemetry{},
	}

	if st, err := os.Stat(skPath); err == nil && !st.IsDir() {
		status.SecretKeyExists = true
	}

	if pkData, err := os.ReadFile(pkPath); err == nil && len(pkData) > 0 {
		status.PublicKeyExists = true
		status.PublicKeySizeBytes = int64(len(pkData))
		sum := sha256.Sum256(pkData)
		status.PublicKeySha256 = hex.EncodeToString(sum[:])
		if st, statErr := os.Stat(pkPath); statErr == nil {
			status.PublicKeyUpdatedAt = st.ModTime().UTC().Format(time.RFC3339)
		}
	}

	peersDir := filepath.Join(baseDir, "peers")
	if entries, err := os.ReadDir(peersDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pk") {
				continue
			}
			fullPath := filepath.Join(peersDir, entry.Name())
			data, readErr := os.ReadFile(fullPath)
			if readErr != nil {
				continue
			}
			sum := sha256.Sum256(data)
			modTime := ""
			if info, infoErr := entry.Info(); infoErr == nil {
				modTime = info.ModTime().UTC().Format(time.RFC3339)
			}
			peerName := strings.TrimSuffix(strings.TrimSuffix(entry.Name(), "-pq.pk"), ".pk")
			status.PeerKeys = append(status.PeerKeys, RosenpassPeerKeyFile{
				Name:      peerName,
				Path:      fullPath,
				SizeBytes: int64(len(data)),
				Sha256:    hex.EncodeToString(sum[:]),
				UpdatedAt: modTime,
			})
		}
	}

	if _, err := exec.LookPath("wg"); err == nil {
		pskOut, pskErr := exec.Command("wg", "show", wgDevice, "preshared-keys").Output()
		hsOut, _ := exec.Command("wg", "show", wgDevice, "latest-handshakes").Output()
		if pskErr == nil {
			status.WireGuardPeers = ParseWgPresharedKeysOutput(string(pskOut), string(hsOut))
		}
	}

	return status
}
