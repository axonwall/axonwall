package engine

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	baselineAlpha         = 0.15
	baselineWarmupSamples = 12
	baselineMaxEntities   = 10000
	baselineMaxPairs      = 50000
	baselinePairTTLSec    = 30 * 24 * 3600
)

type BaselineSlot struct {
	Count   int     `json:"count"`
	EwmaBps float64 `json:"ewmaBps"`
	VarBps  float64 `json:"varBps"`
	EwmaPps float64 `json:"ewmaPps"`
	VarPps  float64 `json:"varPps"`
}

type EntityBaseline struct {
	LastSeenSec int64             `json:"lastSeenSec"`
	Slots       [168]BaselineSlot `json:"slots"` // 7 days * 24 hours
}

type BaselineSnapshotFile struct {
	UpdatedAt string                     `json:"updatedAt"`
	Entities  map[string]*EntityBaseline `json:"entities"`
	SeenPairs map[string]int64           `json:"seenPairs"`
}

// BaselineEngine tracks rolling 7-day hour-of-day EWMA/variance models and first-seen pairs.
type BaselineEngine struct {
	mu        sync.Mutex
	path      string
	entities  map[string]*EntityBaseline
	seenPairs map[string]int64
}

func NewBaselineEngine(dataDir string) *BaselineEngine {
	be := &BaselineEngine{
		entities:  make(map[string]*EntityBaseline),
		seenPairs: make(map[string]int64),
	}
	if dataDir != "" {
		be.path = filepath.Join(dataDir, "baselines.json")
		_ = be.Load(be.path)
	}
	return be
}

func (b *BaselineEngine) SetDataDir(dataDir string) {
	if dataDir == "" {
		return
	}
	next := filepath.Join(dataDir, "baselines.json")
	b.mu.Lock()
	changed := next != b.path
	b.path = next
	b.mu.Unlock()
	if changed {
		_ = b.Load(next)
	}
}

func slotIndexForTime(ts time.Time) int {
	u := ts.UTC()
	return int(u.Weekday())*24 + u.Hour()
}

// ObserveAndScore updates the EWMA model and returns the pre-update Z-score when warmed up.
func (b *BaselineEngine) ObserveAndScore(entity string, ts time.Time, bps, pps float64) (zBps, zPps float64, warmedUp bool) {
	if entity == "" {
		return 0, 0, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	eb := b.entities[entity]
	if eb == nil {
		if len(b.entities) >= baselineMaxEntities {
			b.evictOldestEntityLocked()
		}
		eb = &EntityBaseline{}
		b.entities[entity] = eb
	}
	eb.LastSeenSec = ts.Unix()

	slot := &eb.Slots[slotIndexForTime(ts)]
	if slot.Count >= baselineWarmupSamples {
		warmedUp = true
		stdBps := math.Sqrt(math.Max(slot.VarBps, 1e4))
		zBps = (bps - slot.EwmaBps) / stdBps
		stdPps := math.Sqrt(math.Max(slot.VarPps, 4.0))
		zPps = (pps - slot.EwmaPps) / stdPps
	}

	if slot.Count == 0 {
		slot.EwmaBps = bps
		slot.EwmaPps = pps
		slot.VarBps = 0
		slot.VarPps = 0
	} else {
		diffBps := bps - slot.EwmaBps
		incrBps := baselineAlpha * diffBps
		slot.EwmaBps += incrBps
		slot.VarBps = (1-baselineAlpha)*(slot.VarBps + baselineAlpha*diffBps*diffBps)

		diffPps := pps - slot.EwmaPps
		incrPps := baselineAlpha * diffPps
		slot.EwmaPps += incrPps
		slot.VarPps = (1-baselineAlpha)*(slot.VarPps + baselineAlpha*diffPps*diffPps)
	}
	slot.Count++
	return zBps, zPps, warmedUp
}

// CheckPair records a src->dst/ASN pair and returns true the first time it is seen (or after TTL expiry).
func (b *BaselineEngine) CheckPair(pairKey string, nowSec int64) bool {
	if pairKey == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if prev, ok := b.seenPairs[pairKey]; ok && nowSec-prev < baselinePairTTLSec {
		b.seenPairs[pairKey] = nowSec
		return false
	}
	if len(b.seenPairs) >= baselineMaxPairs {
		b.prunePairsLocked(nowSec)
	}
	b.seenPairs[pairKey] = nowSec
	return true
}

func (b *BaselineEngine) evictOldestEntityLocked() {
	var oldestKey string
	var oldestTs int64 = math.MaxInt64
	for k, v := range b.entities {
		if v.LastSeenSec < oldestTs {
			oldestTs = v.LastSeenSec
			oldestKey = k
		}
	}
	if oldestKey != "" {
		delete(b.entities, oldestKey)
	}
}

func (b *BaselineEngine) prunePairsLocked(nowSec int64) {
	for k, ts := range b.seenPairs {
		if nowSec-ts >= baselinePairTTLSec {
			delete(b.seenPairs, k)
		}
	}
	for len(b.seenPairs) >= baselineMaxPairs {
		var oldestK string
		var oldestTs int64 = math.MaxInt64
		n := 0
		for k, ts := range b.seenPairs {
			if ts < oldestTs {
				oldestTs = ts
				oldestK = k
			}
			n++
			if n >= 64 {
				break
			}
		}
		if oldestK != "" {
			delete(b.seenPairs, oldestK)
		} else {
			break
		}
	}
}

func (b *BaselineEngine) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entities)
}

func (b *BaselineEngine) Reset() error {
	b.mu.Lock()
	b.entities = make(map[string]*EntityBaseline)
	b.seenPairs = make(map[string]int64)
	p := b.path
	b.mu.Unlock()
	if p != "" {
		_ = os.Remove(p)
	}
	return nil
}

func (b *BaselineEngine) Snapshot(limit int) []BaselineSummaryEntry {
	if limit <= 0 {
		limit = 50
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now().UTC()
	curSlot := slotIndexForTime(now)
	dow := int(now.Weekday())
	hod := now.Hour()

	var out []BaselineSummaryEntry
	for ent, eb := range b.entities {
		s := eb.Slots[curSlot]
		if s.Count == 0 {
			// Pick highest-sample slot if current hour hasn't accumulated yet.
			for i := range eb.Slots {
				if eb.Slots[i].Count > s.Count {
					s = eb.Slots[i]
				}
			}
		}
		if s.Count == 0 {
			continue
		}
		out = append(out, BaselineSummaryEntry{
			Entity:      ent,
			DayOfWeek:   dow,
			HourOfDay:   hod,
			Samples:     s.Count,
			EwmaBps:     math.Round(s.EwmaBps*100) / 100,
			StddevBps:   math.Round(math.Sqrt(math.Max(0, s.VarBps))*100) / 100,
			EwmaPps:     math.Round(s.EwmaPps*100) / 100,
			StddevPps:   math.Round(math.Sqrt(math.Max(0, s.VarPps))*100) / 100,
			LastSeenSec: eb.LastSeenSec,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EwmaBps > out[j].EwmaBps })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (b *BaselineEngine) Save(path string) error {
	b.mu.Lock()
	if path == "" {
		path = b.path
	}
	if path == "" {
		b.mu.Unlock()
		return nil
	}
	snap := BaselineSnapshotFile{
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Entities:  b.entities,
		SeenPairs: b.seenPairs,
	}
	data, err := json.Marshal(snap)
	b.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (b *BaselineEngine) Load(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var snap BaselineSnapshotFile
	if err := json.Unmarshal(raw, &snap); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if snap.Entities != nil {
		b.entities = snap.Entities
	}
	if snap.SeenPairs != nil {
		b.seenPairs = snap.SeenPairs
	}
	return nil
}
