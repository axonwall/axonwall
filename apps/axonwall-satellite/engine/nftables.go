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

// applyScriptInternal loads the nftables ruleset into the Linux kernel.
// It uses the pure-Go NETLINK_NETFILTER batch compiler by default (requiring zero
// /usr/sbin/nft binary in the Super-Slim Edge NGFW UKI), and falls back to `nft -f`
// only if an external `nft` binary is installed and native Netlink is unavailable.
func applyScriptInternal(scriptContent string) error {
	batch, compileErr := CompileNftScriptToNetlinkBatch(scriptContent)
	if compileErr == nil {
		if nlErr := ApplyNftBatchNetlink(batch); nlErr == nil {
			slog.Info("Applied nftables ruleset via native NETLINK_NETFILTER", "table", batch.TableName, "chains", len(batch.Chains), "rules", len(batch.Rules))
			return nil
		} else {
			slog.Debug("Native NETLINK_NETFILTER apply note, checking nft binary fallback", "note", nlErr)
		}
	}

	nftBin, lookErr := exec.LookPath("nft")
	if lookErr != nil {
		if compileErr != nil {
			return fmt.Errorf("native nftables compiler failed (%w) and no nft binary found", compileErr)
		}
		return fmt.Errorf("native NETLINK_NETFILTER apply failed and no nft binary present in initramfs")
	}

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

	cmd := exec.Command(nftBin, "-f", tmpFile)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft -f failed: %w (stderr: %s)", err, stderr.String())
	}
	return nil
}

// Apply compiles and atomically loads the nftables script into the kernel.
func (e *NftablesEngine) Apply(scriptContent string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := applyScriptInternal(scriptContent); err != nil {
		return err
	}

	slog.Info("Successfully applied nftables ruleset.")

	// Keep lastKnownGood untouched until Confirm() is called (unless no baseline existed at all)
	if e.lastKnownGood == "" {
		e.lastKnownGood = scriptContent
	}
	e.currentScript = scriptContent

	return nil
}

// Confirm promotes the currently applied ruleset to lastKnownGood.
func (e *NftablesEngine) Confirm() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.currentScript != "" {
		e.lastKnownGood = e.currentScript
	}
}

// Rollback restores the last known good configuration.
func (e *NftablesEngine) Rollback() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.lastKnownGood == "" {
		slog.Warn("No previous known good configuration to rollback to.")
		return nil
	}

	slog.Info("Initiating nftables rollback...")
	_ = e.Flush()

	if err := applyScriptInternal(e.lastKnownGood); err != nil {
		return fmt.Errorf("nft rollback failed: %w", err)
	}

	slog.Info("Successfully rolled back nftables ruleset.")
	e.currentScript = e.lastKnownGood

	return nil
}

// Flush clears all Axonwall tables via native NETLINK_NETFILTER (with nft binary fallback).
func (e *NftablesEngine) Flush() error {
	if err := DeleteTableNetlink("axonwall"); err == nil {
		return nil
	}
	if nftBin, err := exec.LookPath("nft"); err == nil {
		_ = exec.Command(nftBin, "delete", "table", "inet", "axonwall").Run()
	}
	return nil
}

// BlockTarget adds an IP or MAC address to the blocked dynamic sets via native NETLINK_NETFILTER.
func (e *NftablesEngine) BlockTarget(target string, isMac bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	target = strings.TrimSpace(target)
	var setName string
	var keyBytes []byte

	if isMac {
		hw, err := net.ParseMAC(target)
		if err != nil {
			return fmt.Errorf("invalid MAC address target %q: %w", target, err)
		}
		target = hw.String()
		setName = "blocked_macs"
		keyBytes = []byte(hw)
	} else {
		if ip := net.ParseIP(target); ip != nil {
			target = ip.String()
			if ip4 := ip.To4(); ip4 != nil {
				setName = "blocked_ips"
				keyBytes = []byte(ip4)
			} else {
				setName = "blocked_ips6"
				keyBytes = []byte(ip.To16())
			}
		} else if _, ipNet, err := net.ParseCIDR(target); err == nil && ipNet != nil {
			target = ipNet.String()
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				setName = "blocked_ips"
				keyBytes = []byte(ip4)
			} else {
				setName = "blocked_ips6"
				keyBytes = []byte(ipNet.IP.To16())
			}
		} else {
			return fmt.Errorf("invalid IP or CIDR target %q", target)
		}
	}

	if err := AddSetElementNetlink("axonwall", setName, keyBytes); err == nil {
		slog.Info("Micro-segmentation active: target blocked via NETLINK_NETFILTER", "target", target, "set", setName)
		return nil
	}

	nftBin, lookErr := exec.LookPath("nft")
	if lookErr != nil {
		return fmt.Errorf("NETLINK_NETFILTER set element insert failed for %s (%s) and no nft binary installed", target, setName)
	}

	cmd := exec.Command(nftBin, "add", "element", "inet", "axonwall", setName, "{", target, "}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add element %s to set %s: %w (stderr: %s)", target, setName, err, stderr.String())
	}

	slog.Info("Micro-segmentation active: target blocked", "target", target, "set", setName)
	return nil
}
