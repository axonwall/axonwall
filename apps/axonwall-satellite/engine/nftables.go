package engine

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
)

type NftablesEngine struct {
	mu            sync.Mutex
	lastKnownGood string
	currentScript string
}

func NewNftablesEngine() *NftablesEngine {
	baseline := ""
	if data, err := os.ReadFile("/etc/nftables.conf"); err == nil && len(data) > 0 {
		baseline = string(data)
	}
	return &NftablesEngine{
		lastKnownGood: baseline,
		currentScript: baseline,
	}
}

// Apply compiles and atomically loads the nftables script.
func (e *NftablesEngine) Apply(scriptContent string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	tmp, err := os.CreateTemp("", "axonwall-sat-apply-*.nft")
	if err != nil {
		return fmt.Errorf("failed to create temporary nft script: %w", err)
	}
	tmpFile := tmp.Name()
	defer os.Remove(tmpFile)

	if _, err := tmp.Write([]byte(scriptContent)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write temporary nft script: %w", err)
	}
	_ = tmp.Close()

	// Execute nft -f <tmpFile>
	cmd := exec.Command("nft", "-f", tmpFile)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft -f failed: %w (stderr: %s)", err, stderr.String())
	}

	slog.Info("Successfully applied nftables ruleset.")

	// If it succeeds, update currentScript and lastKnownGood
	if e.currentScript != "" {
		e.lastKnownGood = e.currentScript
	} else if e.lastKnownGood == "" {
		e.lastKnownGood = scriptContent
	}
	e.currentScript = scriptContent

	return nil
}

// Rollback restores the last known good configuration
func (e *NftablesEngine) Rollback() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.lastKnownGood == "" {
		slog.Warn("No previous known good configuration to rollback to.")
		return nil
	}

	slog.Info("Initiating nftables rollback...")

	tmp, err := os.CreateTemp("", "axonwall-sat-rollback-*.nft")
	if err != nil {
		return fmt.Errorf("failed to create rollback script: %w", err)
	}
	tmpFile := tmp.Name()
	defer os.Remove(tmpFile)

	if _, err := tmp.Write([]byte(e.lastKnownGood)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write rollback script: %w", err)
	}
	_ = tmp.Close()

	cmd := exec.Command("nft", "-f", tmpFile)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft rollback failed: %w (stderr: %s)", err, stderr.String())
	}

	slog.Info("Successfully rolled back nftables ruleset.")
	e.currentScript = e.lastKnownGood

	return nil
}

// Flush clears all Axonwall tables
func (e *NftablesEngine) Flush() error {
	cmd := exec.Command("nft", "delete", "table", "inet", "axonwall")
	if err := cmd.Run(); err != nil {
		// Ignore error, table might not exist
		return nil
	}
	return nil
}

// BlockTarget adds an IP or MAC address to the blocked dynamic sets
func (e *NftablesEngine) BlockTarget(target string, isMac bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	target = strings.TrimSpace(target)
	var setName string
	if isMac {
		hw, err := net.ParseMAC(target)
		if err != nil {
			return fmt.Errorf("invalid MAC address target %q: %w", target, err)
		}
		target = hw.String()
		setName = "blocked_macs"
	} else {
		if ip := net.ParseIP(target); ip != nil {
			target = ip.String()
			if ip.To4() == nil {
				setName = "blocked_ips6"
			} else {
				setName = "blocked_ips"
			}
		} else if _, ipNet, err := net.ParseCIDR(target); err == nil && ipNet != nil {
			target = ipNet.String()
			if ipNet.IP.To4() == nil {
				setName = "blocked_ips6"
			} else {
				setName = "blocked_ips"
			}
		} else {
			return fmt.Errorf("invalid IP or CIDR target %q", target)
		}
	}

	cmd := exec.Command("nft", "add", "element", "inet", "axonwall", setName, "{", target, "}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add element %s to set %s: %w (stderr: %s)", target, setName, err, stderr.String())
	}

	slog.Info("Micro-segmentation active: target blocked", "target", target, "set", setName)
	return nil
}
