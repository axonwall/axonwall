package engine

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
)

const defaultTelemetrySpoolDir = "/var/lib/axonwall/telemetry-spool"

type TelemetryQueueStats struct {
	Name           string `json:"name"`
	QueuedItems    int    `json:"queuedItems"`
	QueuedBytes    int64  `json:"queuedBytes"`
	DiskSpoolBytes int64  `json:"diskSpoolBytes"`
	DroppedTotal   uint64 `json:"droppedTotal"`
	SentTotal      uint64 `json:"sentTotal"`
}

// TelemetryQueue provides a bounded in-RAM drop-oldest ring buffer with an
// optional bounded zstd-compressed disk spool directory for extended hub outages.
type TelemetryQueue struct {
	mu               sync.Mutex
	name             string
	maxMemBytes      int64
	curMemBytes      int64
	memItems         [][]byte
	diskEnabled      bool
	diskDir          string
	diskMaxBytes     int64
	seq              uint64
	lastSpoolTs      int64
	diskReplayFile   string
	diskReplayItems  [][]byte
	diskReplayOffset int
	dropped          atomic.Uint64
	sent             atomic.Uint64
}

func sanitizeTelemetryQueueName(name string) string {
	clean := filepath.Base(strings.TrimSpace(name))
	if clean == "" || clean == "." || clean == ".." {
		return "default"
	}
	return clean
}

func confineTelemetrySpoolDir(dir string) (string, error) {
	trimmed := strings.TrimSpace(dir)
	if trimmed == "" {
		return defaultTelemetrySpoolDir, nil
	}
	if !filepath.IsAbs(trimmed) {
		return "", fmt.Errorf("diskSpoolDir %q must be an absolute path", trimmed)
	}
	for _, seg := range strings.Split(filepath.ToSlash(trimmed), "/") {
		if seg == ".." {
			return "", fmt.Errorf("diskSpoolDir %q must not contain '..'", trimmed)
		}
	}
	resolved, err := resolveEvalSymlinksWithTail(trimmed)
	if err != nil {
		return "", fmt.Errorf("diskSpoolDir %q resolution failed: %w", trimmed, err)
	}
	if !strings.HasPrefix(resolved, "/var/lib/axonwall/") &&
		!strings.HasPrefix(resolved, "/run/axonwall/") &&
		resolved != "/var/lib/axonwall" &&
		resolved != "/run/axonwall" {
		return "", fmt.Errorf("diskSpoolDir %q must reside under /var/lib/axonwall/ or /run/axonwall/", trimmed)
	}
	return resolved, nil
}

func NewTelemetryQueue(name string, maxMemoryMB int, diskSpoolEnabled bool, diskSpoolDir string, diskSpoolMaxMB int) *TelemetryQueue {
	if maxMemoryMB <= 0 {
		maxMemoryMB = 24
	}
	if diskSpoolMaxMB <= 0 {
		diskSpoolMaxMB = 256
	}
	safeName := sanitizeTelemetryQueueName(name)
	baseDir := strings.TrimSpace(diskSpoolDir)
	if baseDir == "" {
		baseDir = defaultTelemetrySpoolDir
	} else {
		clean := filepath.Clean(baseDir)
		tmpRoot := filepath.Clean(os.TempDir())
		if resolved, err := confineTelemetrySpoolDir(clean); err == nil {
			baseDir = resolved
		} else if tmpRoot != "" && (strings.HasPrefix(clean, tmpRoot+"/") || clean == tmpRoot) {
			baseDir = clean
		} else {
			log.Printf("[Observability] Warning: unsafe diskSpoolDir %q rejected in NewTelemetryQueue; disabling disk spool", diskSpoolDir)
			baseDir = defaultTelemetrySpoolDir
			diskSpoolEnabled = false
		}
	}
	subDir := filepath.Join(baseDir, safeName)
	if diskSpoolEnabled {
		_ = os.MkdirAll(subDir, 0o750)
	}
	return &TelemetryQueue{
		name:         safeName,
		maxMemBytes:  int64(maxMemoryMB) * 1024 * 1024,
		diskEnabled:  diskSpoolEnabled,
		diskDir:      subDir,
		diskMaxBytes: int64(diskSpoolMaxMB) * 1024 * 1024,
	}
}

func (q *TelemetryQueue) Configure(maxMemoryMB int, diskSpoolEnabled bool, diskSpoolDir string, diskSpoolMaxMB int) {
	if maxMemoryMB <= 0 {
		maxMemoryMB = 24
	}
	if diskSpoolMaxMB <= 0 {
		diskSpoolMaxMB = 256
	}
	confinedDir, err := confineTelemetrySpoolDir(diskSpoolDir)
	if err != nil {
		log.Printf("[Observability] Warning: unsafe diskSpoolDir %q rejected (%v); disabling disk spool", diskSpoolDir, err)
		confinedDir = defaultTelemetrySpoolDir
		diskSpoolEnabled = false
	}
	subDir := filepath.Join(confinedDir, q.name)
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.diskDir != subDir || !diskSpoolEnabled {
		q.diskReplayFile = ""
		q.diskReplayItems = nil
		q.diskReplayOffset = 0
	}
	q.maxMemBytes = int64(maxMemoryMB) * 1024 * 1024
	q.diskEnabled = diskSpoolEnabled
	q.diskDir = subDir
	q.diskMaxBytes = int64(diskSpoolMaxMB) * 1024 * 1024
	if diskSpoolEnabled {
		_ = os.MkdirAll(subDir, 0o750)
	}
	q.enforceLimitsLocked()
}

func (q *TelemetryQueue) Push(payload []byte) {
	if len(payload) == 0 {
		return
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)

	q.mu.Lock()
	defer q.mu.Unlock()
	if int64(len(cp)) > q.maxMemBytes {
		if !q.diskEnabled {
			q.dropped.Add(1)
			return
		}
		// Flush older RAM items to disk first so FIFO order is preserved
		if len(q.memItems) > 0 {
			if q.writeDiskSpoolLocked(q.memItems) {
				for i := range q.memItems {
					q.memItems[i] = nil
				}
				q.memItems = nil
				q.curMemBytes = 0
			} else {
				for i := range q.memItems {
					q.memItems[i] = nil
					q.dropped.Add(1)
				}
				q.memItems = nil
				q.curMemBytes = 0
			}
		}
		if !q.writeDiskSpoolLocked([][]byte{cp}) {
			q.dropped.Add(1)
		}
		return
	}
	q.memItems = append(q.memItems, cp)
	q.curMemBytes += int64(len(cp))
	q.enforceLimitsLocked()
}

// RequeueFront restores unsent batches at the front of the queue (respecting limits).
func (q *TelemetryQueue) RequeueFront(items [][]byte) {
	if len(items) == 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	var added int64
	cleaned := make([][]byte, 0, len(items))
	for _, it := range items {
		if len(it) == 0 {
			continue
		}
		cp := make([]byte, len(it))
		copy(cp, it)
		cleaned = append(cleaned, cp)
		added += int64(len(cp))
	}
	if len(cleaned) == 0 {
		return
	}
	q.memItems = append(cleaned, q.memItems...)
	q.curMemBytes += added
	q.enforceLimitsLocked()
}

// PeekBatch returns up to maxItems from disk spool (FIFO) then RAM without removing
// disk spool chunks or RAM items until AckBatch is called.
func (q *TelemetryQueue) PeekBatch(maxItems int) [][]byte {
	if maxItems <= 0 {
		maxItems = 1
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.peekBatchLocked(maxItems)
}

// AckBatch removes count acknowledged items from the front of the queue (advancing
// the disk spool cursor and deleting a .zst file only once all its items are acked).
func (q *TelemetryQueue) AckBatch(count int) {
	if count <= 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.ackBatchLocked(count)
}

// PopBatch pops up to maxItems (replaying disk spool FIFO first if present) and acknowledges them.
func (q *TelemetryQueue) PopBatch(maxItems int) [][]byte {
	if maxItems <= 0 {
		maxItems = 1
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.peekBatchLocked(maxItems)
	if len(out) > 0 {
		q.ackBatchLocked(len(out))
	}
	return out
}

func (q *TelemetryQueue) MarkSent(count uint64) {
	q.sent.Add(count)
}

func (q *TelemetryQueue) MarkDropped(count uint64) {
	q.dropped.Add(count)
}

func (q *TelemetryQueue) DroppedCount() uint64 {
	return q.dropped.Load()
}

func (q *TelemetryQueue) Stats() TelemetryQueueStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	var diskBytes int64
	if q.diskEnabled && q.diskDir != "" {
		if entries, err := os.ReadDir(q.diskDir); err == nil {
			for _, ent := range entries {
				if info, err := ent.Info(); err == nil {
					diskBytes += info.Size()
				}
			}
		}
	}
	return TelemetryQueueStats{
		Name:           q.name,
		QueuedItems:    len(q.memItems),
		QueuedBytes:    q.curMemBytes,
		DiskSpoolBytes: diskBytes,
		DroppedTotal:   q.dropped.Load(),
		SentTotal:      q.sent.Load(),
	}
}

func (q *TelemetryQueue) enforceLimitsLocked() {
	if q.curMemBytes <= q.maxMemBytes {
		return
	}
	// Spill oldest items in a loop to bounded zstd disk spool preserving FIFO order
	for q.diskEnabled && q.curMemBytes > q.maxMemBytes && len(q.memItems) > 0 {
		spillCount := len(q.memItems) / 2
		if spillCount < 1 {
			spillCount = 1
		}
		spill := q.memItems[:spillCount]
		if !q.writeDiskSpoolLocked(spill) {
			break
		}
		var spilledBytes int64
		for i := 0; i < spillCount; i++ {
			spilledBytes += int64(len(q.memItems[i]))
			q.memItems[i] = nil
		}
		q.memItems = append([][]byte(nil), q.memItems[spillCount:]...)
		q.curMemBytes -= spilledBytes
		if q.curMemBytes < 0 {
			q.curMemBytes = 0
		}
	}
	// Drop oldest items in RAM cleanly under backpressure
	for q.curMemBytes > q.maxMemBytes && len(q.memItems) > 0 {
		q.curMemBytes -= int64(len(q.memItems[0]))
		q.memItems[0] = nil
		q.memItems = q.memItems[1:]
		q.dropped.Add(1)
	}
	if len(q.memItems) == 0 {
		q.memItems = nil
		q.curMemBytes = 0
	} else if cap(q.memItems) > 64 && len(q.memItems)*2 < cap(q.memItems) {
		q.memItems = append([][]byte(nil), q.memItems...)
	}
}

func decodeDiskSpoolChunk(path string) ([][]byte, error) {
	compressed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	raw, err := dec.DecodeAll(compressed, nil)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	off := 0
	for off+4 <= len(raw) {
		l := int(uint32(raw[off])<<24 | uint32(raw[off+1])<<16 | uint32(raw[off+2])<<8 | uint32(raw[off+3]))
		off += 4
		if l <= 0 || off+l > len(raw) {
			break
		}
		item := make([]byte, l)
		copy(item, raw[off:off+l])
		out = append(out, item)
		off += l
	}
	return out, nil
}

func (q *TelemetryQueue) sortedSpoolFilesLocked() []string {
	if q.diskDir == "" {
		return nil
	}
	entries, err := os.ReadDir(q.diskDir)
	if err != nil {
		return nil
	}
	var names []string
	for _, ent := range entries {
		if !ent.IsDir() && filepath.Ext(ent.Name()) == ".zst" {
			names = append(names, ent.Name())
		}
	}
	sort.Strings(names)
	return names
}

func (q *TelemetryQueue) ensureDiskHeadLocked() bool {
	if q.diskReplayFile != "" && q.diskReplayOffset < len(q.diskReplayItems) {
		return true
	}
	if q.diskReplayFile != "" {
		_ = os.Remove(filepath.Join(q.diskDir, q.diskReplayFile))
		q.diskReplayFile = ""
		q.diskReplayItems = nil
		q.diskReplayOffset = 0
	}
	for _, name := range q.sortedSpoolFilesLocked() {
		path := filepath.Join(q.diskDir, name)
		items, err := decodeDiskSpoolChunk(path)
		if err != nil || len(items) == 0 {
			_ = os.Remove(path)
			continue
		}
		q.diskReplayFile = name
		q.diskReplayItems = items
		q.diskReplayOffset = 0
		return true
	}
	return false
}

func (q *TelemetryQueue) peekBatchLocked(maxItems int) [][]byte {
	var out [][]byte
	if q.diskEnabled {
		if q.ensureDiskHeadLocked() {
			for i := q.diskReplayOffset; i < len(q.diskReplayItems) && len(out) < maxItems; i++ {
				cp := make([]byte, len(q.diskReplayItems[i]))
				copy(cp, q.diskReplayItems[i])
				out = append(out, cp)
			}
			if len(out) < maxItems {
				for _, name := range q.sortedSpoolFilesLocked() {
					if name <= q.diskReplayFile {
						continue
					}
					items, err := decodeDiskSpoolChunk(filepath.Join(q.diskDir, name))
					if err != nil {
						continue
					}
					for _, it := range items {
						if len(out) >= maxItems {
							break
						}
						out = append(out, it)
					}
					if len(out) >= maxItems {
						break
					}
				}
			}
		}
	}
	for i := 0; i < len(q.memItems) && len(out) < maxItems; i++ {
		cp := make([]byte, len(q.memItems[i]))
		copy(cp, q.memItems[i])
		out = append(out, cp)
	}
	return out
}

func (q *TelemetryQueue) ackBatchLocked(count int) {
	for count > 0 && q.diskEnabled {
		if !q.ensureDiskHeadLocked() {
			break
		}
		avail := len(q.diskReplayItems) - q.diskReplayOffset
		if count < avail {
			for i := 0; i < count; i++ {
				q.diskReplayItems[q.diskReplayOffset+i] = nil
			}
			q.diskReplayOffset += count
			count = 0
			break
		}
		count -= avail
		_ = os.Remove(filepath.Join(q.diskDir, q.diskReplayFile))
		q.diskReplayFile = ""
		q.diskReplayItems = nil
		q.diskReplayOffset = 0
	}
	if count > 0 && len(q.memItems) > 0 {
		n := count
		if n > len(q.memItems) {
			n = len(q.memItems)
		}
		var removedBytes int64
		for i := 0; i < n; i++ {
			removedBytes += int64(len(q.memItems[i]))
			q.memItems[i] = nil
		}
		q.memItems = append([][]byte(nil), q.memItems[n:]...)
		q.curMemBytes -= removedBytes
		if q.curMemBytes < 0 {
			q.curMemBytes = 0
		}
		if len(q.memItems) == 0 {
			q.memItems = nil
		}
	}
}

func (q *TelemetryQueue) writeDiskSpoolLocked(items [][]byte) bool {
	if q.diskDir == "" || len(items) == 0 {
		return false
	}
	_ = os.MkdirAll(q.diskDir, 0o750)

	enc, err := zstd.NewWriter(nil)
	if err != nil {
		return false
	}
	defer enc.Close()

	// Length-prefixed binary framing inside zstd chunk
	var raw []byte
	for _, it := range items {
		var hdr [4]byte
		l := uint32(len(it))
		hdr[0] = byte(l >> 24)
		hdr[1] = byte(l >> 16)
		hdr[2] = byte(l >> 8)
		hdr[3] = byte(l)
		raw = append(raw, hdr[:]...)
		raw = append(raw, it...)
	}
	compressed := enc.EncodeAll(raw, nil)
	if int64(len(compressed)) > q.diskMaxBytes {
		return false
	}

	// Enforce diskMaxBytes quota including incoming compressed chunk size, counting items dropped
	if entries, err := os.ReadDir(q.diskDir); err == nil {
		var files []os.DirEntry
		var total int64
		for _, ent := range entries {
			if !ent.IsDir() && filepath.Ext(ent.Name()) == ".zst" {
				if info, ierr := ent.Info(); ierr == nil {
					total += info.Size()
					files = append(files, ent)
				}
			}
		}
		sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })
		for total+int64(len(compressed)) > q.diskMaxBytes && len(files) > 0 {
			old := files[0]
			files = files[1:]
			oldPath := filepath.Join(q.diskDir, old.Name())
			if info, ierr := old.Info(); ierr == nil {
				total -= info.Size()
			}
			var droppedItems uint64
			if old.Name() == q.diskReplayFile {
				if rem := len(q.diskReplayItems) - q.diskReplayOffset; rem > 0 {
					droppedItems = uint64(rem)
				}
				q.diskReplayFile = ""
				q.diskReplayItems = nil
				q.diskReplayOffset = 0
			} else if decoded, derr := decodeDiskSpoolChunk(oldPath); derr == nil && len(decoded) > 0 {
				droppedItems = uint64(len(decoded))
			} else {
				droppedItems = 1
			}
			_ = os.Remove(oldPath)
			q.dropped.Add(droppedItems)
		}
	}

	ts := time.Now().UnixNano()
	if ts <= q.lastSpoolTs {
		ts = q.lastSpoolTs
	}
	q.lastSpoolTs = ts
	q.seq++
	fname := fmt.Sprintf("spool-%020d-%06d.zst", ts, q.seq)
	tmpPath := filepath.Join(q.diskDir, fname+".tmp")
	finalPath := filepath.Join(q.diskDir, fname)
	if err := os.WriteFile(tmpPath, compressed, 0o600); err != nil {
		return false
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return false
	}
	return true
}
