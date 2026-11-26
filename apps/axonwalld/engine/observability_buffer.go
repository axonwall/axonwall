package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
)

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
	mu           sync.Mutex
	name         string
	maxMemBytes  int64
	curMemBytes  int64
	memItems     [][]byte
	diskEnabled  bool
	diskDir      string
	diskMaxBytes int64
	seq          uint64
	dropped      atomic.Uint64
	sent         atomic.Uint64
}

func NewTelemetryQueue(name string, maxMemoryMB int, diskSpoolEnabled bool, diskSpoolDir string, diskSpoolMaxMB int) *TelemetryQueue {
	if maxMemoryMB <= 0 {
		maxMemoryMB = 24
	}
	if diskSpoolMaxMB <= 0 {
		diskSpoolMaxMB = 256
	}
	if diskSpoolDir == "" {
		diskSpoolDir = "/var/lib/axonwall/telemetry-spool"
	}
	subDir := filepath.Join(diskSpoolDir, name)
	if diskSpoolEnabled {
		_ = os.MkdirAll(subDir, 0o750)
	}
	return &TelemetryQueue{
		name:         name,
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
	if diskSpoolDir == "" {
		diskSpoolDir = "/var/lib/axonwall/telemetry-spool"
	}
	subDir := filepath.Join(diskSpoolDir, q.name)
	q.mu.Lock()
	defer q.mu.Unlock()
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
		if !q.diskEnabled || !q.writeDiskSpoolLocked([][]byte{cp}) {
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

// PopBatch pops up to maxItems (replaying disk spool FIFO first if present).
func (q *TelemetryQueue) PopBatch(maxItems int) [][]byte {
	if maxItems <= 0 {
		maxItems = 1
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.diskEnabled {
		if spooled := q.popDiskSpoolLocked(); len(spooled) > 0 {
			return spooled
		}
	}
	if len(q.memItems) == 0 {
		return nil
	}
	n := maxItems
	if n > len(q.memItems) {
		n = len(q.memItems)
	}
	out := make([][]byte, n)
	var removedBytes int64
	for i := 0; i < n; i++ {
		out[i] = q.memItems[i]
		removedBytes += int64(len(out[i]))
	}
	q.memItems = append([][]byte(nil), q.memItems[n:]...)
	q.curMemBytes -= removedBytes
	if q.curMemBytes < 0 {
		q.curMemBytes = 0
	}
	return out
}

func (q *TelemetryQueue) MarkSent(count uint64) {
	q.sent.Add(count)
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
	// First try spilling oldest half of RAM items to bounded zstd disk spool if opted-in
	if q.diskEnabled && len(q.memItems) > 1 {
		spillCount := len(q.memItems) / 2
		if spillCount < 1 {
			spillCount = 1
		}
		spill := q.memItems[:spillCount]
		if q.writeDiskSpoolLocked(spill) {
			var spilledBytes int64
			for _, it := range spill {
				spilledBytes += int64(len(it))
			}
			q.memItems = append([][]byte(nil), q.memItems[spillCount:]...)
			q.curMemBytes -= spilledBytes
			if q.curMemBytes <= q.maxMemBytes {
				return
			}
		}
	}
	// Drop oldest items in RAM cleanly under backpressure
	for q.curMemBytes > q.maxMemBytes && len(q.memItems) > 0 {
		q.curMemBytes -= int64(len(q.memItems[0]))
		q.memItems = q.memItems[1:]
		q.dropped.Add(1)
	}
	if len(q.memItems) == 0 {
		q.curMemBytes = 0
	}
}

func (q *TelemetryQueue) writeDiskSpoolLocked(items [][]byte) bool {
	if q.diskDir == "" || len(items) == 0 {
		return false
	}
	_ = os.MkdirAll(q.diskDir, 0o750)
	// Enforce diskMaxBytes by pruning oldest .zst chunks first
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
		for total >= q.diskMaxBytes && len(files) > 0 {
			old := files[0]
			files = files[1:]
			if info, ierr := old.Info(); ierr == nil {
				total -= info.Size()
			}
			_ = os.Remove(filepath.Join(q.diskDir, old.Name()))
			q.dropped.Add(1)
		}
	}

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
	q.seq++
	fname := fmt.Sprintf("spool-%020d-%06d.zst", time.Now().UnixNano(), q.seq)
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

func (q *TelemetryQueue) popDiskSpoolLocked() [][]byte {
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
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	path := filepath.Join(q.diskDir, names[0])
	compressed, err := os.ReadFile(path)
	_ = os.Remove(path)
	if err != nil {
		return nil
	}
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil
	}
	defer dec.Close()
	raw, err := dec.DecodeAll(compressed, nil)
	if err != nil {
		return nil
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
	return out
}
