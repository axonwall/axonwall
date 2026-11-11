package engine

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// BpfTokenProfilesPath stores declarative & MCP-managed BPF_TOKEN delegation profiles.
var BpfTokenProfilesPath = "/var/lib/axonwall/bpf-token-profiles.json"

var safeTokenProfileIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,62}$`)

// Exact Linux kernel symbolic tables for bpffs delegation mount options (Linux 6.9+).
var kernelBpfCmdBits = map[string]uint64{
	"map_create":                  1 << 0,
	"map_lookup_elem":             1 << 1,
	"map_update_elem":             1 << 2,
	"map_delete_elem":             1 << 3,
	"map_get_next_key":            1 << 4,
	"prog_load":                   1 << 5,
	"obj_pin":                     1 << 6,
	"obj_get":                     1 << 7,
	"prog_attach":                 1 << 8,
	"prog_detach":                 1 << 9,
	"prog_test_run":               1 << 10,
	"btf_load":                    1 << 18,
	"map_lookup_and_delete_elem":  1 << 21,
	"map_freeze":                  1 << 22,
	"map_lookup_batch":            1 << 24,
	"map_lookup_and_delete_batch": 1 << 25,
	"map_update_batch":            1 << 26,
	"map_delete_batch":            1 << 27,
	"link_create":                 1 << 28,
	"link_update":                 1 << 29,
	"link_detach":                 1 << 34,
	"prog_bind_map":               1 << 35,
	"token_create":                1 << 36,
}

var kernelSafeBpfProgBits = map[string]uint64{
	"socket_filter":    1 << 1,
	"sched_cls":        1 << 3,
	"sched_act":        1 << 4,
	"xdp":              1 << 6,
	"cgroup_skb":       1 << 8,
	"cgroup_sock":      1 << 9,
	"lwt_in":           1 << 10,
	"lwt_out":          1 << 11,
	"lwt_xmit":         1 << 12,
	"sock_ops":         1 << 13,
	"sk_skb":           1 << 14,
	"cgroup_device":    1 << 15,
	"sk_msg":           1 << 17,
	"cgroup_sock_addr": 1 << 18,
	"lwt_seg6local":    1 << 19,
	"sk_reuseport":     1 << 21,
	"flow_dissector":   1 << 22,
	"cgroup_sysctl":    1 << 23,
	"cgroup_sockopt":   1 << 25,
	"sk_lookup":        1 << 30,
	"netfilter":        1 << 32,
}

// ForbiddenBpfProgReasons lists Ring-0 tracing, introspection & kernel-tampering
// BPF program types that MUST NEVER be delegated to unprivileged containers via
// BPF_TOKEN_CREATE because they unlock bpf_probe_read_kernel() across global RAM.
var ForbiddenBpfProgReasons = map[string]string{
	"kprobe":                  "exposes bpf_probe_read_kernel() over arbitrary kernel functions & global host RAM",
	"tracepoint":              "exposes global kernel tracepoints across all host & sibling tenant namespaces",
	"perf_event":              "exposes hardware PMU sampling & global stack trace inspection",
	"raw_tracepoint":          "exposes raw kernel register frames across all host tasks",
	"raw_tracepoint_writable": "permits mutating raw kernel tracepoint buffers",
	"tracing":                 "fentry/fexit/fmod_ret BTF trampolines inspect arbitrary kernel symbols & arguments",
	"struct_ops":              "replaces kernel subsystem function pointer tables (TCP congestion / sched_ext)",
	"ext":                     "freplace dynamically overwrites instructions of existing BPF programs",
	"lsm":                     "attaches Mandatory Access Control hooks capable of DoS-ing host syscalls",
	"syscall":                 "executes privileged kernel bpf_syscall helpers from BPF context",
}

var kernelBpfMapBits = map[string]uint64{
	"hash":                1 << 1,
	"array":               1 << 2,
	"prog_array":          1 << 3,
	"percpu_hash":         1 << 5,
	"percpu_array":        1 << 6,
	"cgroup_array":        1 << 8,
	"lru_hash":            1 << 9,
	"lru_percpu_hash":     1 << 10,
	"lpm_trie":            1 << 11,
	"array_of_maps":       1 << 12,
	"hash_of_maps":        1 << 13,
	"devmap":              1 << 14,
	"sockmap":             1 << 15,
	"cpumap":              1 << 16,
	"xskmap":              1 << 17,
	"sockhash":            1 << 18,
	"cgroup_storage":      1 << 19,
	"queue":               1 << 22,
	"stack":               1 << 23,
	"sk_storage":          1 << 24,
	"devmap_hash":         1 << 25,
	"ringbuf":             1 << 27,
	"inode_storage":       1 << 28,
	"task_storage":        1 << 29,
	"bloom_filter":        1 << 30,
	"user_ringbuf":        1 << 31,
	"cgrp_storage":        1 << 32,
}

var kernelBpfAttachBits = map[string]uint64{
	"cgroup_inet_ingress":      1 << 0,
	"cgroup_inet_egress":       1 << 1,
	"cgroup_inet_sock_create":  1 << 2,
	"cgroup_sock_ops":          1 << 3,
	"sk_skb_stream_parser":     1 << 4,
	"sk_skb_stream_verdict":    1 << 5,
	"cgroup_device":            1 << 6,
	"sk_msg_verdict":           1 << 7,
	"cgroup_inet4_bind":        1 << 8,
	"cgroup_inet6_bind":        1 << 9,
	"cgroup_inet4_connect":     1 << 10,
	"cgroup_inet6_connect":     1 << 11,
	"cgroup_inet4_post_bind":   1 << 12,
	"cgroup_inet6_post_bind":   1 << 13,
	"cgroup_udp4_sendmsg":      1 << 14,
	"cgroup_udp6_sendmsg":      1 << 15,
	"flow_dissector":           1 << 17,
	"cgroup_sysctl":            1 << 18,
	"cgroup_udp4_recvmsg":      1 << 19,
	"cgroup_udp6_recvmsg":      1 << 20,
	"cgroup_getsockopt":        1 << 21,
	"cgroup_setsockopt":        1 << 22,
	"cgroup_inet_sock_release": 1 << 34,
	"xdp":                      1 << 37,
	"sk_lookup":                1 << 36,
	"netfilter":                1 << 45,
	"tcx_ingress":              1 << 46,
	"tcx_egress":               1 << 47,
}

type BpfTokenKernelCapabilities struct {
	KernelRelease           string `json:"kernelRelease"`
	KernelMajor             int    `json:"kernelMajor"`
	KernelMinor             int    `json:"kernelMinor"`
	Kernel69OrNewer         bool   `json:"kernel69OrNewer"`
	BtfHasBpfToken          bool   `json:"btfHasBpfToken"`
	BtfHasLsmTokenCreate    bool   `json:"btfHasLsmTokenCreate"`
	BtfHasLsmTokenCmd       bool   `json:"btfHasLsmTokenCmd"`
	UnprivilegedBpfDisabled string `json:"unprivilegedBpfDisabled"`
	UserNsCloneAllowed      bool   `json:"userNsCloneAllowed"`
	Supported               bool   `json:"supported"`
}

type BpfTokenPresetInfo struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Summary         string `json:"summary"`
	DelegateCmds    string `json:"delegateCmds"`
	DelegateProgs   string `json:"delegateProgs"`
	DelegateMaps    string `json:"delegateMaps"`
	DelegateAttachs string `json:"delegateAttachs"`
	CmdsMaskHex     string `json:"cmdsMaskHex"`
	ProgsMaskHex    string `json:"progsMaskHex"`
	MapsMaskHex     string `json:"mapsMaskHex"`
	AttachsMaskHex  string `json:"attachsMaskHex"`
}

type BpfTokenDelegationProfile struct {
	ID               string `json:"id"`
	TargetKind       string `json:"targetKind"` // "lxc", "k3s-pod", "standalone"
	TargetRef        string `json:"targetRef"`  // e.g., "ct-101" or "vow-system/cilium-agent"
	Preset           string `json:"preset"`     // "socket-observability", "network-dataplane", "cgroup-microsegmentation", "custom"
	Enabled          bool   `json:"enabled"`
	DelegateCmds     string `json:"delegateCmds"`
	DelegateProgs    string `json:"delegateProgs"`
	DelegateMaps     string `json:"delegateMaps"`
	DelegateAttachs  string `json:"delegateAttachs"`
	CmdsMaskHex      string `json:"cmdsMaskHex"`
	ProgsMaskHex     string `json:"progsMaskHex"`
	MapsMaskHex      string `json:"mapsMaskHex"`
	AttachsMaskHex   string `json:"attachsMaskHex"`
	BpffsMountPath   string `json:"bpffsMountPath"`
	AuditViaBpfLsm   bool   `json:"auditViaBpfLsm"`
	Description      string `json:"description,omitempty"`
	UpdatedAt        string `json:"updatedAt"`
	UpdatedBy        string `json:"updatedBy"`
	MountPreviewCmd  string `json:"mountPreviewCmd"`
}

type ActiveBpffsDelegationMount struct {
	MountID         int    `json:"mountId"`
	MountPoint      string `json:"mountPoint"`
	ReadOnly        bool   `json:"readOnly"`
	DelegateCmds    string `json:"delegateCmds,omitempty"`
	DelegateProgs   string `json:"delegateProgs,omitempty"`
	DelegateMaps    string `json:"delegateMaps,omitempty"`
	DelegateAttachs string `json:"delegateAttachs,omitempty"`
	HasDelegation   bool   `json:"hasDelegation"`
}

type BpfTokenManager struct {
	mu       sync.RWMutex
	profiles map[string]BpfTokenDelegationProfile
}

var (
	defaultBpfTokenMgrOnce sync.Once
	defaultBpfTokenMgr     *BpfTokenManager
)

func GetDefaultBpfTokenManager() *BpfTokenManager {
	defaultBpfTokenMgrOnce.Do(func() {
		defaultBpfTokenMgr = NewBpfTokenManager()
	})
	return defaultBpfTokenMgr
}

func NewBpfTokenManager() *BpfTokenManager {
	m := &BpfTokenManager{
		profiles: make(map[string]BpfTokenDelegationProfile),
	}
	m.loadProfiles()
	return m
}

// ProbeBpfTokenCapabilities inspects the running Linux kernel for Linux 6.9+
// BPF_TOKEN_CREATE support, kernel BTF struct bpf_token, and BPF-LSM token hooks.
func ProbeBpfTokenCapabilities() BpfTokenKernelCapabilities {
	var uts unix.Utsname
	rel := ""
	if err := unix.Uname(&uts); err == nil {
		rel = cBytesToString(uts.Release[:])
	}
	maj, min := parseKernelMajorMinor(rel)
	is69 := maj > 6 || (maj == 6 && min >= 9)

	hasTokenStruct := false
	hasLsmCreate := false
	hasLsmCmd := false
	if spec, err := btf.LoadKernelSpec(); err == nil && spec != nil {
		var st *btf.Struct
		if spec.TypeByName("bpf_token", &st) == nil {
			hasTokenStruct = true
		}
		var fnCreate *btf.Func
		if spec.TypeByName("bpf_lsm_bpf_token_create", &fnCreate) == nil {
			hasLsmCreate = true
		}
		var fnCmd *btf.Func
		if spec.TypeByName("bpf_lsm_bpf_token_cmd", &fnCmd) == nil {
			hasLsmCmd = true
		}
	}

	unprivBpf := readSysctlFileTrimmed("/proc/sys/kernel/unprivileged_bpf_disabled", "1")
	unprivUserNs := readSysctlFileTrimmed("/proc/sys/kernel/unprivileged_userns_clone", "1")
	maxUserNs := readSysctlFileTrimmed("/proc/sys/user/max_user_namespaces", "65536")
	userNsOk := unprivUserNs != "0" && maxUserNs != "0"

	return BpfTokenKernelCapabilities{
		KernelRelease:           rel,
		KernelMajor:             maj,
		KernelMinor:             min,
		Kernel69OrNewer:         is69,
		BtfHasBpfToken:          hasTokenStruct,
		BtfHasLsmTokenCreate:    hasLsmCreate,
		BtfHasLsmTokenCmd:       hasLsmCmd,
		UnprivilegedBpfDisabled: unprivBpf,
		UserNsCloneAllowed:      userNsOk,
		Supported:               is69 && hasTokenStruct,
	}
}

func parseKernelMajorMinor(release string) (int, int) {
	parts := strings.Split(strings.TrimSpace(release), ".")
	if len(parts) < 2 {
		return 0, 0
	}
	maj, _ := strconv.Atoi(parts[0])
	minStr := parts[1]
	for i, r := range minStr {
		if r < '0' || r > '9' {
			minStr = minStr[:i]
			break
		}
	}
	min, _ := strconv.Atoi(minStr)
	return maj, min
}

// GetBpfTokenPresets returns Axonwall's security-hardened BPF_TOKEN_CREATE presets.
func GetBpfTokenPresets() []BpfTokenPresetInfo {
	raw := []struct {
		id, name, summary, cmds, progs, maps, attachs string
	}{
		{
			id:      "socket-observability",
			name:    "Socket & DNS Observability (Read-Only Packet Dissection)",
			summary: "Permits unprivileged CLONE_NEWUSER containers to attach socket_filter and cgroup_skb programs with ringbuf/hash telemetry. Zero packet mutation or kernel memory reads.",
			cmds:    "prog_load:map_create:btf_load:map_lookup_elem:map_update_elem:map_delete_elem:map_get_next_key",
			progs:   "socket_filter:cgroup_skb",
			maps:    "array:hash:lru_hash:percpu_array:ringbuf",
			attachs: "cgroup_inet_ingress:cgroup_inet_egress",
		},
		{
			id:      "network-dataplane",
			name:    "XDP & TC Container Network Dataplane (Cilium / Katran / L4 LB)",
			summary: "Permits unprivileged UserNS LXC containers and K3s pods to run line-rate XDP, TCX (sched_cls), and socket load-balancing eBPF programs while strictly blocking kprobe/tracepoint/LSM Ring-0 memory helpers.",
			cmds:    "prog_load:map_create:btf_load:link_create:link_update:link_detach:obj_pin:obj_get:map_lookup_elem:map_update_elem:map_delete_elem:map_get_next_key",
			progs:   "xdp:sched_cls:sched_act:socket_filter:cgroup_skb:cgroup_sock_addr:sk_skb:sk_msg",
			maps:    "array:percpu_array:hash:percpu_hash:lru_hash:lru_percpu_hash:lpm_trie:ringbuf:devmap:sockmap:sockhash",
			attachs: "xdp:tcx_ingress:tcx_egress:cgroup_inet_ingress:cgroup_inet_egress:cgroup_inet4_connect:cgroup_inet6_connect:sk_skb_stream_verdict:sk_msg_verdict",
		},
		{
			id:      "cgroup-microsegmentation",
			name:    "Cgroup v2 Socket & Connect Micro-Segmentation",
			summary: "Permits tenant cgroup L3/L4 socket bind/connect policy enforcement inside unprivileged user namespaces without XDP NIC driver attachment.",
			cmds:    "prog_load:map_create:btf_load:link_create:map_lookup_elem:map_update_elem:map_delete_elem",
			progs:   "cgroup_skb:cgroup_sock:cgroup_sock_addr",
			maps:    "array:hash:lru_hash:lpm_trie:ringbuf",
			attachs: "cgroup_inet_ingress:cgroup_inet_egress:cgroup_inet4_bind:cgroup_inet6_bind:cgroup_inet4_connect:cgroup_inet6_connect",
		},
	}

	out := make([]BpfTokenPresetInfo, 0, len(raw))
	for _, r := range raw {
		cMask, _ := compileSymbolMask(r.cmds, kernelBpfCmdBits, nil, "delegate_cmds")
		pMask, _ := compileSymbolMask(r.progs, kernelSafeBpfProgBits, ForbiddenBpfProgReasons, "delegate_progs")
		mMask, _ := compileSymbolMask(r.maps, kernelBpfMapBits, nil, "delegate_maps")
		aMask, _ := compileSymbolMask(r.attachs, kernelBpfAttachBits, nil, "delegate_attachs")
		out = append(out, BpfTokenPresetInfo{
			ID:              r.id,
			Name:            r.name,
			Summary:         r.summary,
			DelegateCmds:    r.cmds,
			DelegateProgs:   r.progs,
			DelegateMaps:    r.maps,
			DelegateAttachs: r.attachs,
			CmdsMaskHex:     fmt.Sprintf("0x%x", cMask),
			ProgsMaskHex:    fmt.Sprintf("0x%x", pMask),
			MapsMaskHex:     fmt.Sprintf("0x%x", mMask),
			AttachsMaskHex:  fmt.Sprintf("0x%x", aMask),
		})
	}
	return out
}

func compileSymbolMask(
	colonList string,
	allowed map[string]uint64,
	forbiddenReasons map[string]string,
	fieldName string,
) (uint64, error) {
	trimmed := strings.TrimSpace(colonList)
	if trimmed == "" || trimmed == "none" {
		return 0, nil
	}
	if strings.EqualFold(trimmed, "any") || strings.Contains(trimmed, "*") {
		return 0, fmt.Errorf("%s wildcard %q is prohibited: explicit least-privilege bitmasks are required for BPF_TOKEN delegation", fieldName, trimmed)
	}
	var mask uint64
	for _, item := range strings.Split(trimmed, ":") {
		sym := strings.ToLower(strings.TrimSpace(item))
		if sym == "" {
			continue
		}
		if reason, isForbidden := forbiddenReasons[sym]; isForbidden {
			return 0, fmt.Errorf("%s rejects Ring-0 program type %q: %s", fieldName, sym, reason)
		}
		bit, ok := allowed[sym]
		if !ok {
			return 0, fmt.Errorf("unsupported or unsafe %s symbol %q", fieldName, sym)
		}
		mask |= bit
	}
	if mask == 0 {
		return 0, fmt.Errorf("%s resolved to an empty bitmask", fieldName)
	}
	return mask, nil
}

// ValidateAndCompileBpfTokenProfile validates a BPF_TOKEN delegation request,
// resolves preset defaults if preset != "custom", blocks any Ring-0 tracing/LSM
// program types, and computes exact hex bitmasks + mount preview commands.
func ValidateAndCompileBpfTokenProfile(in BpfTokenDelegationProfile) (BpfTokenDelegationProfile, error) {
	id := strings.ToLower(strings.TrimSpace(in.ID))
	if !safeTokenProfileIDRe.MatchString(id) {
		return BpfTokenDelegationProfile{}, fmt.Errorf("invalid profile id %q (must match ^[a-z0-9][a-z0-9._-]{1,62}$)", in.ID)
	}
	in.ID = id

	switch in.TargetKind {
	case "", "standalone":
		in.TargetKind = "standalone"
	case "lxc", "k3s-pod":
	default:
		return BpfTokenDelegationProfile{}, fmt.Errorf("invalid targetKind %q (expected lxc, k3s-pod, or standalone)", in.TargetKind)
	}

	if in.Preset == "" {
		in.Preset = "network-dataplane"
	}

	if in.Preset != "custom" {
		matched := false
		for _, p := range GetBpfTokenPresets() {
			if p.ID == in.Preset {
				in.DelegateCmds = p.DelegateCmds
				in.DelegateProgs = p.DelegateProgs
				in.DelegateMaps = p.DelegateMaps
				in.DelegateAttachs = p.DelegateAttachs
				matched = true
				break
			}
		}
		if !matched {
			return BpfTokenDelegationProfile{}, fmt.Errorf("unknown BPF token preset %q", in.Preset)
		}
	}

	cMask, err := compileSymbolMask(in.DelegateCmds, kernelBpfCmdBits, nil, "delegate_cmds")
	if err != nil {
		return BpfTokenDelegationProfile{}, err
	}
	pMask, err := compileSymbolMask(in.DelegateProgs, kernelSafeBpfProgBits, ForbiddenBpfProgReasons, "delegate_progs")
	if err != nil {
		return BpfTokenDelegationProfile{}, err
	}
	mMask, err := compileSymbolMask(in.DelegateMaps, kernelBpfMapBits, nil, "delegate_maps")
	if err != nil {
		return BpfTokenDelegationProfile{}, err
	}
	aMask, err := compileSymbolMask(in.DelegateAttachs, kernelBpfAttachBits, nil, "delegate_attachs")
	if err != nil {
		return BpfTokenDelegationProfile{}, err
	}

	in.CmdsMaskHex = fmt.Sprintf("0x%x", cMask)
	in.ProgsMaskHex = fmt.Sprintf("0x%x", pMask)
	in.MapsMaskHex = fmt.Sprintf("0x%x", mMask)
	in.AttachsMaskHex = fmt.Sprintf("0x%x", aMask)

	if in.BpffsMountPath == "" {
		in.BpffsMountPath = filepath.Join("/run/axonwall/bpffs-tokens", in.ID)
	} else {
		cleanMount := filepath.Clean(strings.TrimSpace(in.BpffsMountPath))
		if !strings.HasPrefix(cleanMount, "/run/axonwall/bpffs-tokens/") &&
			!strings.HasPrefix(cleanMount, "/mnt/") &&
			!strings.HasPrefix(cleanMount, "/var/lib/lxc/") {
			return BpfTokenDelegationProfile{}, fmt.Errorf("bpffsMountPath %q must reside under /run/axonwall/bpffs-tokens/, /mnt/, or /var/lib/lxc/", cleanMount)
		}
		in.BpffsMountPath = cleanMount
	}

	if in.UpdatedAt == "" {
		in.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if in.UpdatedBy == "" {
		in.UpdatedBy = "admin"
	}

	in.MountPreviewCmd = fmt.Sprintf(
		"mount -t bpf bpffs %s -o delegate_cmds=%s,delegate_progs=%s,delegate_maps=%s,delegate_attachs=%s",
		in.BpffsMountPath,
		in.DelegateCmds,
		in.DelegateProgs,
		in.DelegateMaps,
		in.DelegateAttachs,
	)

	return in, nil
}

func (m *BpfTokenManager) loadProfiles() {
	if BpfTokenProfilesPath == "" {
		return
	}
	raw, err := os.ReadFile(BpfTokenProfilesPath)
	if err != nil || len(raw) == 0 {
		return
	}
	var list []BpfTokenDelegationProfile
	if err := json.Unmarshal(raw, &list); err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range list {
		if compiled, err := ValidateAndCompileBpfTokenProfile(p); err == nil {
			m.profiles[compiled.ID] = compiled
		}
	}
}

func (m *BpfTokenManager) saveProfilesLocked() error {
	if BpfTokenProfilesPath == "" {
		return nil
	}
	list := make([]BpfTokenDelegationProfile, 0, len(m.profiles))
	for _, p := range m.profiles {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(BpfTokenProfilesPath), 0750); err != nil {
		return err
	}
	tmp := BpfTokenProfilesPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, BpfTokenProfilesPath)
}

func (m *BpfTokenManager) UpsertProfile(in BpfTokenDelegationProfile) (BpfTokenDelegationProfile, error) {
	compiled, err := ValidateAndCompileBpfTokenProfile(in)
	if err != nil {
		return BpfTokenDelegationProfile{}, err
	}
	compiled.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	m.mu.Lock()
	m.profiles[compiled.ID] = compiled
	saveErr := m.saveProfilesLocked()
	m.mu.Unlock()
	if saveErr != nil {
		return BpfTokenDelegationProfile{}, saveErr
	}
	return compiled, nil
}

func (m *BpfTokenManager) DeleteProfile(id string) error {
	cleanID := strings.ToLower(strings.TrimSpace(id))
	m.mu.Lock()
	if _, exists := m.profiles[cleanID]; !exists {
		m.mu.Unlock()
		return errors.New("BPF token delegation profile not found")
	}
	delete(m.profiles, cleanID)
	err := m.saveProfilesLocked()
	m.mu.Unlock()
	return err
}

func (m *BpfTokenManager) ListProfiles() []BpfTokenDelegationProfile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]BpfTokenDelegationProfile, 0, len(m.profiles))
	for _, p := range m.profiles {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (m *BpfTokenManager) GetProfile(id string) (BpfTokenDelegationProfile, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.profiles[strings.ToLower(strings.TrimSpace(id))]
	return p, ok
}

// ParseMountInfoBpffs parses Linux /proc/self/mountinfo content to discover
// active bpffs mounts and any configured Linux 6.9+ delegate_* bitmask options.
func ParseMountInfoBpffs(mountInfoContent string) []ActiveBpffsDelegationMount {
	var mounts []ActiveBpffsDelegationMount
	sc := bufio.NewScanner(strings.NewReader(mountInfoContent))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		sepIdx := strings.Index(line, " - ")
		if sepIdx < 0 {
			continue
		}
		leftFields := strings.Fields(line[:sepIdx])
		rightFields := strings.Fields(line[sepIdx+3:])
		if len(leftFields) < 6 || len(rightFields) < 3 {
			continue
		}
		if rightFields[0] != "bpf" {
			continue
		}
		mountID, _ := strconv.Atoi(leftFields[0])
		mountPoint := leftFields[4]
		vfsOpts := leftFields[5]
		superOpts := rightFields[2]

		m := ActiveBpffsDelegationMount{
			MountID:    mountID,
			MountPoint: mountPoint,
			ReadOnly:   strings.HasPrefix(vfsOpts, "ro,") || vfsOpts == "ro",
		}
		for _, opt := range strings.Split(superOpts, ",") {
			kv := strings.SplitN(opt, "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "delegate_cmds":
				m.DelegateCmds = kv[1]
				m.HasDelegation = true
			case "delegate_progs":
				m.DelegateProgs = kv[1]
				m.HasDelegation = true
			case "delegate_maps":
				m.DelegateMaps = kv[1]
				m.HasDelegation = true
			case "delegate_attachs":
				m.DelegateAttachs = kv[1]
				m.HasDelegation = true
			}
		}
		mounts = append(mounts, m)
	}
	return mounts
}

func DiscoverDelegatedBpffsMounts() []ActiveBpffsDelegationMount {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return []ActiveBpffsDelegationMount{}
	}
	return ParseMountInfoBpffs(string(b))
}

// RenderK3sUserNsPodManifest generates a hardened Kubernetes 1.30+ / K3s UserNS
// Pod or DaemonSet YAML manifest using hostUsers: false (CLONE_NEWUSER) and
// LIBBPF_BPF_TOKEN_PATH=/sys/fs/bpf with zero init_user_ns host capabilities.
func RenderK3sUserNsPodManifest(profile BpfTokenDelegationProfile, workloadName, namespace, image, kind string) (string, error) {
	compiled, err := ValidateAndCompileBpfTokenProfile(profile)
	if err != nil {
		return "", err
	}
	sanitizeK8s := func(s, def string) string {
		clean := strings.ToLower(strings.TrimSpace(s))
		if clean == "" {
			return def
		}
		var b strings.Builder
		for _, r := range clean {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
				b.WriteRune(r)
			} else {
				b.WriteRune('-')
			}
		}
		res := strings.Trim(b.String(), "-.")
		if res == "" {
			return def
		}
		return res
	}

	safeName := sanitizeK8s(workloadName, "ebpf-tenant-agent")
	safeNs := sanitizeK8s(namespace, "default")
	safeImg := strings.NewReplacer("\r", "", "\n", "", "\"", "").Replace(strings.TrimSpace(image))
	if safeImg == "" {
		safeImg = "ghcr.io/cilium/cilium:v1.16.4"
	}
	if kind != "DaemonSet" {
		kind = "Pod"
	}

	if kind == "DaemonSet" {
		return fmt.Sprintf(`# Axonwall Hardened K3s BPF_TOKEN_CREATE DaemonSet (Zero Host Root / CLONE_NEWUSER)
# Profile: %s (%s) — Progs: %s (%s)
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: %s
  namespace: %s
  annotations:
    ebpf.axonwall.io/token-profile: "%s"
    ebpf.axonwall.io/delegate-progs: "%s"
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: %s
  template:
    metadata:
      labels:
        app.kubernetes.io/name: %s
    spec:
      hostUsers: false
      automountServiceAccountToken: false
      containers:
        - name: %s
          image: "%s"
          env:
            - name: LIBBPF_BPF_TOKEN_PATH
              value: "/sys/fs/bpf"
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
              add: ["BPF", "NET_ADMIN"]
          volumeMounts:
            - name: delegated-bpffs
              mountPath: /sys/fs/bpf
      volumes:
        - name: delegated-bpffs
          hostPath:
            path: "%s"
            type: Directory
`, compiled.ID, compiled.Preset, compiled.DelegateProgs, compiled.ProgsMaskHex,
			safeName, safeNs, compiled.ID, compiled.DelegateProgs, safeName, safeName, safeName, safeImg, compiled.BpffsMountPath), nil
	}

	return fmt.Sprintf(`# Axonwall Hardened K3s BPF_TOKEN_CREATE UserNS Pod (Zero Host Root / CLONE_NEWUSER)
# Profile: %s (%s) — Progs: %s (%s)
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  annotations:
    ebpf.axonwall.io/token-profile: "%s"
    ebpf.axonwall.io/delegate-cmds: "%s"
    ebpf.axonwall.io/delegate-progs: "%s"
    ebpf.axonwall.io/delegate-maps: "%s"
    ebpf.axonwall.io/delegate-attachs: "%s"
spec:
  hostUsers: false
  automountServiceAccountToken: false
  containers:
    - name: %s
      image: "%s"
      env:
        - name: LIBBPF_BPF_TOKEN_PATH
          value: "/sys/fs/bpf"
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
          add: ["BPF", "NET_ADMIN"]
      volumeMounts:
        - name: delegated-bpffs
          mountPath: /sys/fs/bpf
  volumes:
    - name: delegated-bpffs
      hostPath:
        path: "%s"
        type: Directory
`, compiled.ID, compiled.Preset, compiled.DelegateProgs, compiled.ProgsMaskHex,
		safeName, safeNs, compiled.ID, compiled.DelegateCmds, compiled.DelegateProgs,
		compiled.DelegateMaps, compiled.DelegateAttachs, safeName, safeImg, compiled.BpffsMountPath), nil
}
