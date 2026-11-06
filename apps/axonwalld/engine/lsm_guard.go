package engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/axonwall/axonwall/apps/axonwalld/ebpf"
)

const (
	AllowFlagBpfLoad   uint8 = 1 << 0
	AllowFlagAfAlgAead uint8 = 1 << 1

	HookIDSocketBindAead uint32 = 1
	HookIDBpfProgLoad    uint32 = 2
	HookIDUringSqpoll    uint32 = 3

	PolicyIdxEnforceBpfLoad     uint32 = 0
	PolicyIdxEnforceUringSqpoll uint32 = 1
	PolicyIdxEnforceCopyfail    uint32 = 2

	maxRecentLsmEvents = 256
)

type BpfLsmAllowlistEntry struct {
	Path  string `json:"path"`
	Dev   uint64 `json:"dev"`
	Ino   uint64 `json:"ino"`
	Flags uint8  `json:"flags"`
}

type BpfLsmDenialEvent struct {
	Timestamp      string `json:"timestamp"`
	PID            uint32 `json:"pid"`
	UID            uint32 `json:"uid"`
	HookID         uint32 `json:"hookId"`
	Hook           string `json:"hook"`
	Blocked        bool   `json:"blocked"`
	Dev            uint64 `json:"dev"`
	Ino            uint64 `json:"ino"`
	Comm           string `json:"comm"`
	Detail         string `json:"detail"`
	MitreTechnique string `json:"mitreTechnique"`
}

type LsmGuardPolicyConfig struct {
	EnforceBpfLoad        bool
	EnforceUringSqpoll    bool
	EnforceCopyfailAead   bool
	TrustedBpfLoaderPaths []string
	TrustedAfAlgPaths     []string
}

func DefaultLsmGuardPolicyConfig() LsmGuardPolicyConfig {
	return LsmGuardPolicyConfig{
		EnforceBpfLoad:      true,
		EnforceUringSqpoll:  true,
		EnforceCopyfailAead: true,
		TrustedBpfLoaderPaths: []string{
			"/usr/sbin/bpftool",
			"/usr/local/bin/bpftool",
			"/usr/sbin/axonwalld",
			"/usr/local/bin/axonwalld",
		},
		TrustedAfAlgPaths: []string{
			"/sbin/cryptsetup",
			"/usr/sbin/cryptsetup",
		},
	}
}

// KernelDevFromStat converts a userspace stat(2) st_dev value into the Linux
// kernel's internal super_block s_dev encoding: (major << 20) | minor.
func KernelDevFromStat(stDev uint64) uint64 {
	maj := unix.Major(stDev)
	min := unix.Minor(stDev)
	return (uint64(maj) << 20) | uint64(min)
}

// ResolveExecutableID resolves symlinks for path, stats the target file, and
// returns the unspoofable (s_dev, i_ino) pair used by the BPF-LSM allowlist map.
func ResolveExecutableID(path string) (ebpf.LsmGuardLsmExeId, error) {
	if path == "" {
		return ebpf.LsmGuardLsmExeId{}, errors.New("empty executable path")
	}
	resolved := path
	if target, err := filepath.EvalSymlinks(path); err == nil && target != "" {
		resolved = target
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return ebpf.LsmGuardLsmExeId{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return ebpf.LsmGuardLsmExeId{}, fmt.Errorf("unable to extract syscall.Stat_t for %s", resolved)
	}
	return ebpf.LsmGuardLsmExeId{
		Dev: KernelDevFromStat(uint64(st.Dev)),
		Ino: st.Ino,
	}, nil
}

func cBytesToString(b []byte) string {
	if idx := bytes.IndexByte(b, 0); idx >= 0 {
		b = b[:idx]
	}
	return string(b)
}

func HookMetaFromID(hookID uint32) (hookName string, mitre string) {
	switch hookID {
	case HookIDSocketBindAead:
		return "lsm/socket_bind (AF_ALG AEAD / CVE-2026-31431)", "T1068"
	case HookIDBpfProgLoad:
		return "lsm/bpf (BPF_PROG_LOAD)", "T1014"
	case HookIDUringSqpoll:
		return "lsm/uring_sqpoll (IORING_SETUP_SQPOLL)", "T1014"
	default:
		return "lsm/unknown", "T1014"
	}
}

// DecodeLsmEvent parses a 112-byte raw LsmGuardLsmEvent record from the BPF ring buffer.
func DecodeLsmEvent(raw []byte, ts time.Time) (BpfLsmDenialEvent, error) {
	if len(raw) < 112 {
		return BpfLsmDenialEvent{}, fmt.Errorf("short lsm_event record (%d bytes, need 112)", len(raw))
	}
	pid := binary.LittleEndian.Uint32(raw[0:4])
	uid := binary.LittleEndian.Uint32(raw[4:8])
	hookID := binary.LittleEndian.Uint32(raw[8:12])
	blocked := binary.LittleEndian.Uint32(raw[12:16]) != 0
	dev := binary.LittleEndian.Uint64(raw[16:24])
	ino := binary.LittleEndian.Uint64(raw[24:32])
	comm := cBytesToString(raw[32:48])
	detail := cBytesToString(raw[48:112])

	hookName, mitre := HookMetaFromID(hookID)
	return BpfLsmDenialEvent{
		Timestamp:      ts.UTC().Format(time.RFC3339),
		PID:            pid,
		UID:            uid,
		HookID:         hookID,
		Hook:           hookName,
		Blocked:        blocked,
		Dev:            dev,
		Ino:            ino,
		Comm:           comm,
		Detail:         detail,
		MitreTechnique: mitre,
	}, nil
}

type LsmGuardManager struct {
	mu            sync.RWMutex
	objs          ebpf.LsmGuardObjects
	links         []link.Link
	rbReader      *ringbuf.Reader
	attached      bool
	attachedHooks []string
	allowlisted   []BpfLsmAllowlistEntry
	events        []BpfLsmDenialEvent
	stopOnce      sync.Once
	doneChan      chan struct{}
}

var (
	defaultLsmGuardMu  sync.RWMutex
	defaultLsmGuardMgr *LsmGuardManager
)

func NewLsmGuardManager() *LsmGuardManager {
	mgr := &LsmGuardManager{
		doneChan: make(chan struct{}),
	}
	defaultLsmGuardMu.Lock()
	defaultLsmGuardMgr = mgr
	defaultLsmGuardMu.Unlock()
	return mgr
}

func GetDefaultLsmGuardManager() *LsmGuardManager {
	defaultLsmGuardMu.RLock()
	defer defaultLsmGuardMu.RUnlock()
	return defaultLsmGuardMgr
}

func boolToUint32(v bool) uint32 {
	if v {
		return 1
	}
	return 0
}

func (m *LsmGuardManager) Start(cfg LsmGuardPolicyConfig) error {
	posture := InspectKernelPosture()
	if !posture.BpfLsmActive {
		log.Printf("[BPF-LSM] Notice: 'bpf' is not active in /sys/kernel/security/lsm (%v); skipping live LSM trampoline attachment.", posture.ActiveLsms)
		return nil
	}

	if err := ebpf.LoadLsmGuardObjects(&m.objs, nil); err != nil {
		return fmt.Errorf("loading LsmGuard eBPF objects: %w", err)
	}

	// 1. Configure enforcement policy array before attaching hooks
	policies := map[uint32]uint32{
		PolicyIdxEnforceBpfLoad:     boolToUint32(cfg.EnforceBpfLoad),
		PolicyIdxEnforceUringSqpoll: boolToUint32(cfg.EnforceUringSqpoll),
		PolicyIdxEnforceCopyfail:    boolToUint32(cfg.EnforceCopyfailAead),
	}
	for idx, val := range policies {
		if m.objs.PolicyConfig != nil {
			_ = m.objs.PolicyConfig.Put(idx, val)
		}
	}

	// 2. Populate unspoofable (s_dev, i_ino) allowlist before attaching hooks
	//    Always include our own running executable so axonwalld is never locked out.
	flagByID := make(map[ebpf.LsmGuardLsmExeId]uint8)
	pathByID := make(map[ebpf.LsmGuardLsmExeId]string)

	addPathFlag := func(p string, flag uint8) {
		id, err := ResolveExecutableID(p)
		if err != nil {
			return
		}
		flagByID[id] |= flag
		if _, exists := pathByID[id]; !exists {
			pathByID[id] = p
		}
	}

	if selfExe, err := os.Executable(); err == nil && selfExe != "" {
		addPathFlag(selfExe, AllowFlagBpfLoad)
	}
	for _, p := range cfg.TrustedBpfLoaderPaths {
		addPathFlag(p, AllowFlagBpfLoad)
	}
	for _, p := range cfg.TrustedAfAlgPaths {
		addPathFlag(p, AllowFlagAfAlgAead)
	}

	var allowEntries []BpfLsmAllowlistEntry
	for id, flags := range flagByID {
		if m.objs.Allowlist != nil {
			if err := m.objs.Allowlist.Put(id, flags); err != nil {
				log.Printf("[BPF-LSM] Warning: failed to allowlist %s (dev=%d ino=%d): %v", pathByID[id], id.Dev, id.Ino, err)
				continue
			}
		}
		allowEntries = append(allowEntries, BpfLsmAllowlistEntry{
			Path:  pathByID[id],
			Dev:   id.Dev,
			Ino:   id.Ino,
			Flags: flags,
		})
	}

	// 3. Attach BPF-LSM hooks
	hookSpecs := []struct {
		name string
		prog *ebpf.LsmGuardPrograms
		fn   func() (link.Link, error)
	}{
		{
			name: "lsm/socket_bind",
			fn: func() (link.Link, error) {
				return link.AttachLSM(link.LSMOptions{Program: m.objs.CopyfailGuard})
			},
		},
		{
			name: "lsm/bpf",
			fn: func() (link.Link, error) {
				return link.AttachLSM(link.LSMOptions{Program: m.objs.RestrictBpfLoad})
			},
		},
		{
			name: "lsm/uring_sqpoll",
			fn: func() (link.Link, error) {
				return link.AttachLSM(link.LSMOptions{Program: m.objs.BlockUringSqpoll})
			},
		},
	}

	var attachedHooks []string
	for _, hs := range hookSpecs {
		l, err := hs.fn()
		if err != nil {
			log.Printf("[BPF-LSM] Warning: could not attach %s: %v", hs.name, err)
			continue
		}
		m.links = append(m.links, l)
		attachedHooks = append(attachedHooks, hs.name)
	}

	if len(attachedHooks) == 0 {
		_ = m.objs.Close()
		return errors.New("no BPF-LSM hooks could be attached")
	}

	rb, err := ringbuf.NewReader(m.objs.Events)
	if err != nil {
		for _, l := range m.links {
			_ = l.Close()
		}
		_ = m.objs.Close()
		return fmt.Errorf("opening BPF-LSM ringbuf reader: %w", err)
	}
	m.rbReader = rb

	m.mu.Lock()
	m.attached = true
	m.attachedHooks = attachedHooks
	m.allowlisted = allowEntries
	m.mu.Unlock()

	log.Printf("[BPF-LSM] Attached %d in-kernel LSM guards (%v) with %d allowlisted (dev,ino) executables",
		len(attachedHooks), attachedHooks, len(allowEntries))

	go m.pollEvents()
	return nil
}

func (m *LsmGuardManager) pollEvents() {
	defer close(m.doneChan)
	for {
		rec, err := m.rbReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		ev, err := DecodeLsmEvent(rec.RawSample, time.Now())
		if err != nil {
			continue
		}
		m.RecordEvent(ev)
		action := "AUDIT"
		if ev.Blocked {
			action = "DENIED"
		}
		log.Printf("[BPF-LSM] %s: hook=%s pid=%d uid=%d comm=%s dev=%d ino=%d detail=%s",
			action, ev.Hook, ev.PID, ev.UID, ev.Comm, ev.Dev, ev.Ino, ev.Detail)
	}
}

func (m *LsmGuardManager) RecordEvent(ev BpfLsmDenialEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) >= maxRecentLsmEvents {
		m.events = append(m.events[1:], ev)
	} else {
		m.events = append(m.events, ev)
	}
}

func (m *LsmGuardManager) Snapshot() (attached bool, hooks []string, allowlist []BpfLsmAllowlistEntry, events []BpfLsmDenialEvent) {
	if m == nil {
		return false, []string{}, []BpfLsmAllowlistEntry{}, []BpfLsmDenialEvent{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	hooksCopy := append([]string(nil), m.attachedHooks...)
	allowCopy := append([]BpfLsmAllowlistEntry(nil), m.allowlisted...)
	eventsCopy := append([]BpfLsmDenialEvent(nil), m.events...)
	return m.attached, hooksCopy, allowCopy, eventsCopy
}

func (m *LsmGuardManager) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		if m.rbReader != nil {
			_ = m.rbReader.Close()
			<-m.doneChan
		}
		for _, l := range m.links {
			_ = l.Close()
		}
		_ = m.objs.Close()
		m.mu.Lock()
		m.attached = false
		m.attachedHooks = nil
		m.mu.Unlock()
	})
}
