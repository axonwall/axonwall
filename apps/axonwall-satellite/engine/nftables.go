package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type NftablesEngine struct {
	mu            sync.Mutex
	lastKnownGood string
	currentScript string
	// B-H1 (round 3): fleet blocks with a hub-supplied TTL, so a
	// block whose hub lease expired (or was reverted/flushed) does
	// not live on the satellite forever. Keyed by
	// setName + "\x00" + normalized target. Entries are persisted
	// to fleetBlocksPath so a satellite process restart neither
	// loses the expiry nor leaves a block with no record: on
	// startup RestoreFleetBlocks re-arms the timers (and re-inserts
	// elements lost with the kernel table).
	fleetBlocks     map[string]*fleetBlockEntry
	fleetBlocksPath string
}

// fleetBlockEntry is one TTL-bounded fleet block. The timer is
// in-memory only; ExpiresAt is what is persisted.
type fleetBlockEntry struct {
	Target    string      `json:"target"`
	IsMac     bool        `json:"isMac"`
	SetName   string      `json:"setName"`
	ExpiresAt time.Time   `json:"expiresAt"`
	timer     *time.Timer `json:"-"`
}

// fleetBlockStatePath is where TTL-bounded fleet blocks are
// persisted across satellite restarts.
const fleetBlockStatePath = "/var/lib/axonwall/fleet-blocks.json"

// fleetBlockRetryDelay is how long after a failed expiry delete the
// satellite retries: a failed delete must not silently leave the
// block in the kernel with no record.
const fleetBlockRetryDelay = 5 * time.Minute

func NewNftablesEngine() *NftablesEngine {
	baseline := ""
	if data, err := os.ReadFile("/etc/nftables.conf"); err == nil && len(data) > 0 {
		baseline = string(data)
	}
	return &NftablesEngine{
		lastKnownGood:   baseline,
		currentScript:   baseline,
		fleetBlocks:     make(map[string]*fleetBlockEntry),
		fleetBlocksPath: fleetBlockStatePath,
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

	// A-M10: lastKnownGood changes ONLY on Confirm (or an explicit
	// emergency fallback installed by main). The old code promoted
	// the first hub-pushed script to lastKnownGood when no baseline
	// existed, so a watchdog rollback restored the very script it
	// was meant to escape — on a fresh edge box with no baseline,
	// a bad first ruleset that dropped the hub connection could
	// never be escaped.
	e.currentScript = scriptContent

	return nil
}

// SetEmergencyFallback installs a fail-closed fallback ruleset as the
// rollback target, but only when no baseline or confirmed ruleset
// exists yet. It never overwrites a real baseline or a confirmed
// ruleset, and it never promotes an unconfirmed hub-pushed script.
func (e *NftablesEngine) SetEmergencyFallback(script string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lastKnownGood == "" && script != "" {
		e.lastKnownGood = script
	}
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
		// A-M10: a rollback with nothing to roll back to is an
		// error, not a success. The old code logged a warning and
		// returned nil, so the watchdog logged no error while the
		// box stayed on the bad ruleset.
		return fmt.Errorf("no last-known-good configuration available for rollback")
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
// B-H1 (round 3): ttlSeconds bounds the block. When > 0 the satellite
// records the expiry and removes the element when it lapses, so the
// block ends with the hub lease instead of living forever; 0 or
// negative means no expiry (an explicit permanent block, as before).
func (e *NftablesEngine) BlockTarget(target string, isMac bool, ttlSeconds int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.blockTargetLocked(target, isMac, ttlSeconds)
}

// blockTargetLocked is BlockTarget with the lock already held, so
// RestoreFleetBlocks can re-insert persisted blocks under the same
// lock.
func (e *NftablesEngine) blockTargetLocked(target string, isMac bool, ttlSeconds int) error {
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
			var startBytes []byte
			var maskBytes []byte
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				setName = "blocked_ips"
				startBytes = []byte(ip4)
				maskBytes = []byte(ipNet.Mask)
			} else {
				setName = "blocked_ips6"
				startBytes = []byte(ipNet.IP.To16())
				maskBytes = []byte(ipNet.Mask)
			}
			if len(startBytes) == len(maskBytes) {
				bcast := make([]byte, len(startBytes))
				for i := range startBytes {
					bcast[i] = startBytes[i] | ^maskBytes[i]
				}
				if endBytes, ok := incrementIPBytes(bcast); ok {
					if err := AddIntervalSetElementNetlink("axonwall", setName, startBytes, endBytes); err == nil {
						slog.Info("Micro-segmentation active: CIDR target blocked via NETLINK_NETFILTER", "target", target, "set", setName)
						e.recordFleetBlockLocked(setName, target, isMac, ttlSeconds)
						return nil
					}
				}
			}
			keyBytes = nil
		} else {
			return fmt.Errorf("invalid IP or CIDR target %q", target)
		}
	}

	if len(keyBytes) > 0 {
		if err := AddSetElementNetlink("axonwall", setName, keyBytes); err == nil {
			slog.Info("Micro-segmentation active: target blocked via NETLINK_NETFILTER", "target", target, "set", setName)
			e.recordFleetBlockLocked(setName, target, isMac, ttlSeconds)
			return nil
		}
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
	e.recordFleetBlockLocked(setName, target, isMac, ttlSeconds)
	return nil
}

// fleetBlockKey identifies one fleet block in the expiry map.
func fleetBlockKey(setName, target string) string {
	return setName + "\x00" + target
}

// recordFleetBlockLocked records (or clears) the expiry for a block
// that was just inserted into the kernel. Callers hold e.mu. A
// re-block with ttlSeconds <= 0 cancels any pending expiry for that
// target: the newest instruction wins, so an explicit permanent
// re-block does not later expire out from under the operator.
func (e *NftablesEngine) recordFleetBlockLocked(setName, target string, isMac bool, ttlSeconds int) {
	if e.fleetBlocks == nil {
		e.fleetBlocks = make(map[string]*fleetBlockEntry)
	}
	key := fleetBlockKey(setName, target)
	if old, ok := e.fleetBlocks[key]; ok && old.timer != nil {
		old.timer.Stop()
	}
	if ttlSeconds <= 0 {
		delete(e.fleetBlocks, key)
		e.persistFleetBlocksLocked()
		return
	}
	entry := &fleetBlockEntry{
		Target:    target,
		IsMac:     isMac,
		SetName:   setName,
		ExpiresAt: time.Now().Add(time.Duration(ttlSeconds) * time.Second),
	}
	e.fleetBlocks[key] = entry
	e.armFleetBlockExpiryLocked(key, entry)
	e.persistFleetBlocksLocked()
	slog.Info("Fleet block expiry scheduled", "target", target, "set", setName, "ttlSeconds", ttlSeconds, "expiresAt", entry.ExpiresAt.Format(time.RFC3339))
}

// armFleetBlockExpiryLocked arms the timer that removes a block when
// its TTL lapses. Callers hold e.mu.
func (e *NftablesEngine) armFleetBlockExpiryLocked(key string, entry *fleetBlockEntry) {
	var t *time.Timer
	t = time.AfterFunc(time.Until(entry.ExpiresAt), func() { e.expireFleetBlock(key, t) })
	entry.timer = t
}

// expireFleetBlock removes a fleet block whose TTL has lapsed. It
// runs on the timer goroutine, so it takes e.mu itself. A stale
// timer (superseded by a re-block, or cancelled by an explicit
// unblock) is a no-op. A failed kernel delete is NOT dropped: the
// entry is re-armed for a retry, so a transient nft failure cannot
// silently leave the block enforced with no record.
func (e *NftablesEngine) expireFleetBlock(key string, t *time.Timer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	entry, ok := e.fleetBlocks[key]
	if !ok || entry.timer != t {
		return
	}
	if err := e.unblockTargetLocked(entry); err != nil {
		slog.Error("Fleet block expiry: failed to remove expired block from kernel; retrying", "target", entry.Target, "set", entry.SetName, "error", err)
		entry.ExpiresAt = time.Now().Add(fleetBlockRetryDelay)
		e.armFleetBlockExpiryLocked(key, entry)
		e.persistFleetBlocksLocked()
		return
	}
	slog.Info("Fleet block expired and removed", "target", entry.Target, "set", entry.SetName)
	delete(e.fleetBlocks, key)
	e.persistFleetBlocksLocked()
}

// UnblockTarget removes an IP, CIDR, or MAC address from the blocked
// dynamic sets and cancels any pending expiry for it. It is the
// fleet-unblock path (B-H1, round 3): the hub sends UNBLOCK_TARGET
// when a lease is reverted or flushed, and the expiry timer calls it
// when a TTL lapses. Removing a target that is not blocked is a
// success, so a duplicate or already-expired unblock is idempotent.
func (e *NftablesEngine) UnblockTarget(target string, isMac bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	normTarget, setName, err := normalizeBlockTarget(target, isMac)
	if err != nil {
		return err
	}
	key := fleetBlockKey(setName, normTarget)
	// Keep the old entry until the kernel delete succeeds: if the
	// delete fails, the block is still enforced, so the entry (and
	// its expiry timer) must survive for a retry instead of the
	// block becoming an orphan with no record.
	old, hadOld := e.fleetBlocks[key]
	if hadOld && old.timer != nil {
		old.timer.Stop()
	}
	delete(e.fleetBlocks, key)
	entry := &fleetBlockEntry{Target: normTarget, IsMac: isMac, SetName: setName}
	if err := e.unblockTargetLocked(entry); err != nil {
		if hadOld {
			e.fleetBlocks[key] = old
			if old.ExpiresAt.After(time.Now()) {
				e.armFleetBlockExpiryLocked(key, old)
			}
		}
		e.persistFleetBlocksLocked()
		return err
	}
	e.persistFleetBlocksLocked()
	slog.Info("Micro-segmentation inactive: target unblocked", "target", normTarget, "set", setName)
	return nil
}

// unblockTargetLocked deletes one set element via the nft CLI.
// Callers hold e.mu. The netlink layer in this package has no set
// element delete yet, and the CLI form handles interval sets
// (singleton IPs inserted as [ip, ip+1), CIDRs as [start, end)) as
// well as plain MAC sets.
func (e *NftablesEngine) unblockTargetLocked(entry *fleetBlockEntry) error {
	nftBin, lookErr := exec.LookPath("nft")
	if lookErr != nil {
		return fmt.Errorf("no nft binary installed to remove element %s from set %s", entry.Target, entry.SetName)
	}
	cmd := exec.Command(nftBin, "delete", "element", "inet", "axonwall", entry.SetName, "{", entry.Target, "}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Idempotent delete: the element is already gone.
		if strings.Contains(stderr.String(), "No such file or directory") {
			return nil
		}
		return fmt.Errorf("failed to delete element %s from set %s: %w (stderr: %s)", entry.Target, entry.SetName, err, stderr.String())
	}
	return nil
}

// normalizeBlockTarget validates a block/unblock target and returns
// its canonical form and the set it lives in. It mirrors the
// normalization in blockTargetLocked (which also needs the key
// bytes for the netlink insert, so it keeps its own inline parse).
func normalizeBlockTarget(target string, isMac bool) (normTarget, setName string, err error) {
	target = strings.TrimSpace(target)
	if isMac {
		hw, err := net.ParseMAC(target)
		if err != nil {
			return "", "", fmt.Errorf("invalid MAC address target %q: %w", target, err)
		}
		return hw.String(), "blocked_macs", nil
	}
	if ip := net.ParseIP(target); ip != nil {
		target = ip.String()
		if ip.To4() != nil {
			return target, "blocked_ips", nil
		}
		return target, "blocked_ips6", nil
	}
	if _, ipNet, err := net.ParseCIDR(target); err == nil && ipNet != nil {
		target = ipNet.String()
		if ipNet.IP.To4() != nil {
			return target, "blocked_ips", nil
		}
		return target, "blocked_ips6", nil
	}
	return "", "", fmt.Errorf("invalid IP or CIDR target %q", target)
}

// persistFleetBlocksLocked writes the TTL-bounded fleet blocks to
// disk (best effort — a persist failure is logged, not fatal: the
// in-memory timers still enforce the expiry for this process
// lifetime). Callers hold e.mu.
func (e *NftablesEngine) persistFleetBlocksLocked() {
	if e.fleetBlocksPath == "" {
		return
	}
	entries := make([]fleetBlockEntry, 0, len(e.fleetBlocks))
	for _, entry := range e.fleetBlocks {
		entries = append(entries, *entry)
	}
	data, err := json.Marshal(entries)
	if err != nil {
		slog.Warn("Failed to marshal fleet block state", "error", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(e.fleetBlocksPath), 0o755); err != nil {
		slog.Warn("Failed to create fleet block state directory", "error", err)
		return
	}
	tmp := e.fleetBlocksPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		slog.Warn("Failed to write fleet block state", "error", err)
		return
	}
	if err := os.Rename(tmp, e.fleetBlocksPath); err != nil {
		slog.Warn("Failed to persist fleet block state", "error", err)
	}
}

// loadFleetBlocks reads the persisted TTL-bounded fleet blocks. A
// missing or corrupt file means no blocks (logged, not fatal).
func (e *NftablesEngine) loadFleetBlocks() []fleetBlockEntry {
	data, err := os.ReadFile(e.fleetBlocksPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("Failed to read fleet block state", "error", err)
		}
		return nil
	}
	var entries []fleetBlockEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		slog.Warn("Failed to parse fleet block state; ignoring persisted blocks", "error", err)
		return nil
	}
	return entries
}

// RestoreFleetBlocks re-arms the expiry timers for TTL-bounded fleet
// blocks persisted across a satellite restart, and re-inserts any
// whose kernel element was lost with the table (a reboot wipes the
// kernel sets while /var/lib survives). Already-expired entries are
// removed from the kernel best-effort and dropped. It runs after a
// ruleset Apply, when the axonwall table exists; a re-insert that
// still fails keeps its entry and timer, so the next Apply's restore
// retries it instead of silently dropping a live block.
func (e *NftablesEngine) RestoreFleetBlocks() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fleetBlocks == nil {
		e.fleetBlocks = make(map[string]*fleetBlockEntry)
	}
	for _, persisted := range e.loadFleetBlocks() {
		entry := persisted
		key := fleetBlockKey(entry.SetName, entry.Target)
		if !entry.ExpiresAt.After(time.Now()) {
			if err := e.unblockTargetLocked(&entry); err != nil {
				slog.Warn("Failed to remove already-expired persisted fleet block", "target", entry.Target, "set", entry.SetName, "error", err)
			} else {
				slog.Info("Removed already-expired persisted fleet block", "target", entry.Target, "set", entry.SetName)
			}
			continue
		}
		if err := e.blockTargetLocked(entry.Target, entry.IsMac, int(time.Until(entry.ExpiresAt)/time.Second)); err != nil {
			slog.Warn("Failed to re-insert persisted fleet block; keeping its expiry timer for the next restore", "target", entry.Target, "set", entry.SetName, "error", err)
			kept := entry
			if old, ok := e.fleetBlocks[key]; ok && old.timer != nil {
				old.timer.Stop()
			}
			e.fleetBlocks[key] = &kept
			e.armFleetBlockExpiryLocked(key, &kept)
			continue
		}
		// blockTargetLocked recorded the block with the remaining
		// TTL, so the timer is already armed; nothing more to do.
		slog.Info("Restored persisted fleet block", "target", entry.Target, "set", entry.SetName, "expiresAt", entry.ExpiresAt.Format(time.RFC3339))
	}
	e.persistFleetBlocksLocked()
}
