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
	return &NftablesEngine{}
}

// Apply compiles and atomically loads the nftables script.
func (e *NftablesEngine) Apply(scriptContent string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	tmpFile := "/tmp/axonwall-satellite-rules.nft"

	// Create a temp file to hold the script
	if err := os.WriteFile(tmpFile, []byte(scriptContent), 0600); err != nil {
		return fmt.Errorf("failed to write temporary nft script: %w", err)
	}
	defer os.Remove(tmpFile)

	// Execute nft -f /tmp/axonwall-satellite-rules.nft
	cmd := exec.Command("nft", "-f", tmpFile)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft -f failed: %w (stderr: %s)", err, stderr.String())
	}

	slog.Info("Successfully applied nftables ruleset.")

	// If it succeeds, update currentScript
	if e.currentScript != "" {
		e.lastKnownGood = e.currentScript
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

	tmpFile := "/tmp/axonwall-satellite-rollback.nft"
	if err := os.WriteFile(tmpFile, []byte(e.lastKnownGood), 0600); err != nil {
		return fmt.Errorf("failed to write rollback script: %w", err)
	}
	defer os.Remove(tmpFile)

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
		} else if _, ipNet, err := net.ParseCIDR(target); err == nil && ipNet != nil {
			target = ipNet.String()
		} else {
			return fmt.Errorf("invalid IP or CIDR target %q", target)
		}
		setName = "blocked_ips"
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
