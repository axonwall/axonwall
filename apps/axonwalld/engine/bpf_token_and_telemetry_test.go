package engine

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/axonwall/axonwall/apps/axonwalld/ebpf"
)

func TestEmbeddedFlowTrackerDualStackVlanSpec(t *testing.T) {
	spec, err := ebpf.LoadFlowTracker()
	if err != nil {
		t.Fatalf("LoadFlowTracker failed: %v", err)
	}
	wantMaps := []string{"flow_map", "flow6_map", "blocklist_map", "blocklist6_map", "xdp_stats_map"}
	for _, m := range wantMaps {
		if _, ok := spec.Maps[m]; !ok {
			t.Errorf("missing expected XDP map %q in embedded FlowTracker ELF", m)
		}
	}
	if _, ok := spec.Programs["xdp_flow_tracker"]; !ok {
		t.Errorf("missing xdp_flow_tracker program in embedded FlowTracker ELF")
	}
}

func TestEmbeddedLsmGuardTokenHooksAndVerdicts(t *testing.T) {
	spec, err := ebpf.LoadLsmGuard()
	if err != nil {
		t.Fatalf("LoadLsmGuard failed: %v", err)
	}
	for _, prog := range []string{
		"copyfail_guard",
		"restrict_bpf_load",
		"block_uring_sqpoll",
		"guard_bpf_token_create",
		"audit_bpf_token_cmd",
	} {
		if _, ok := spec.Programs[prog]; !ok {
			t.Errorf("missing expected BPF-LSM program %q", prog)
		}
	}

	// Verify allowed BPF_TOKEN_DELEGATED event logs as INFO without tripping COMPROMISED_CRITICAL
	mgr := NewLsmGuardManager()
	defer mgr.Stop()

	rawOk := make([]byte, 112)
	binary.LittleEndian.PutUint32(rawOk[0:4], 10240)
	binary.LittleEndian.PutUint32(rawOk[4:8], 100000)
	binary.LittleEndian.PutUint32(rawOk[8:12], HookIDBpfTokenDelegated)
	binary.LittleEndian.PutUint32(rawOk[12:16], 0)
	copy(rawOk[32:48], "cilium-agent\x00")
	copy(rawOk[48:112], "BPF_TOKEN_CREATE_MINTED\x00")

	evOk, err := DecodeLsmEvent(rawOk, time.Now())
	if err != nil {
		t.Fatalf("DecodeLsmEvent(ok): %v", err)
	}
	if evOk.Blocked {
		t.Fatalf("expected Blocked=false for delegated token audit event")
	}
	mgr.RecordEvent(evOk)
	audit := RunHostRootkitAudit()
	for _, f := range audit.Findings {
		if f.Detector == "bpf-lsm-lockdown" && f.Severity == "CRITICAL" {
			t.Fatalf("expected allowed BPF_TOKEN event to have INFO severity, got CRITICAL: %+v", f)
		}
	}

	// Now record a blocked BPF_TOKEN Ring-0 tracing violation and verify CRITICAL verdict
	rawDeny := make([]byte, 112)
	binary.LittleEndian.PutUint32(rawDeny[0:4], 10241)
	binary.LittleEndian.PutUint32(rawDeny[4:8], 100000)
	binary.LittleEndian.PutUint32(rawDeny[8:12], HookIDBpfTokenBlocked)
	binary.LittleEndian.PutUint32(rawDeny[12:16], 1)
	copy(rawDeny[32:48], "evil-kprobe\x00")
	copy(rawDeny[48:112], "BPF_TOKEN_FORBIDDEN_RING0_PROG\x00")

	evDeny, err := DecodeLsmEvent(rawDeny, time.Now())
	if err != nil {
		t.Fatalf("DecodeLsmEvent(deny): %v", err)
	}
	mgr.RecordEvent(evDeny)
	audit2 := RunHostRootkitAudit()
	if audit2.OverallVerdict != "COMPROMISED_CRITICAL" {
		t.Fatalf("expected COMPROMISED_CRITICAL on blocked BPF_TOKEN Ring-0 violation, got %s", audit2.OverallVerdict)
	}
}

func TestBpfTokenDelegationValidatorAndProfiles(t *testing.T) {
	origPath := BpfTokenProfilesPath
	BpfTokenProfilesPath = filepath.Join(t.TempDir(), "bpf-token-profiles.json")
	defer func() { BpfTokenProfilesPath = origPath }()

	mgr := NewBpfTokenManager()

	// 1. Valid preset compilation
	prof, err := mgr.UpsertProfile(BpfTokenDelegationProfile{
		ID:         "ct-101-net",
		TargetKind: "lxc",
		TargetRef:  "ct-101",
		Preset:     "network-dataplane",
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("UpsertProfile(network-dataplane) failed: %v", err)
	}
	if prof.CmdsMaskHex == "0x0" || prof.ProgsMaskHex == "0x0" {
		t.Fatalf("expected non-zero hex bitmasks, got %+v", prof)
	}
	if !strings.Contains(prof.MountPreviewCmd, "delegate_progs=xdp:sched_cls") {
		t.Fatalf("unexpected mount preview: %s", prof.MountPreviewCmd)
	}

	// 2. Reject every dangerous Ring-0 tracing/LSM program type
	for _, forbidden := range []string{"kprobe", "tracepoint", "raw_tracepoint", "perf_event", "tracing", "lsm", "struct_ops", "ext"} {
		_, err := ValidateAndCompileBpfTokenProfile(BpfTokenDelegationProfile{
			ID:              "bad-" + strings.ReplaceAll(forbidden, "_", "-"),
			Preset:          "custom",
			DelegateCmds:    "prog_load:map_create:btf_load",
			DelegateProgs:   "xdp:" + forbidden,
			DelegateMaps:    "hash:array",
			DelegateAttachs: "xdp",
		})
		if err == nil {
			t.Errorf("expected Ring-0 program type %q to be rejected by BPF_TOKEN validator", forbidden)
		}
	}

	// 3. Reject wildcard 'any'
	if _, err := ValidateAndCompileBpfTokenProfile(BpfTokenDelegationProfile{
		ID:              "wildcard-test",
		Preset:          "custom",
		DelegateCmds:    "any",
		DelegateProgs:   "xdp",
		DelegateMaps:    "hash",
		DelegateAttachs: "xdp",
	}); err == nil {
		t.Errorf("expected delegate_cmds='any' wildcard to be rejected")
	}

	// 4. Render K3s UserNS Pod manifest
	manifest, err := RenderK3sUserNsPodManifest(prof, "cilium-ebpf-worker", "kube-system", "ghcr.io/cilium/cilium:v1.16.4", "DaemonSet")
	if err != nil {
		t.Fatalf("RenderK3sUserNsPodManifest: %v", err)
	}
	if !strings.Contains(manifest, "hostUsers: false") || !strings.Contains(manifest, "LIBBPF_BPF_TOKEN_PATH") || !strings.Contains(manifest, "privileged: false") {
		t.Fatalf("manifest missing required UserNS / BPF_TOKEN security controls:\n%s", manifest)
	}

	// 5. Parse /proc/self/mountinfo bpffs delegation entries
	sampleMountInfo := `32 24 0:27 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime shared:10 - bpf bpf rw,mode=700
914 28 0:98 / /run/axonwall/bpffs-tokens/ct-101-net rw,nosuid,nodev,noexec,relatime - bpf bpffs rw,delegate_cmds=prog_load:map_create:btf_load,delegate_progs=xdp:sched_cls,delegate_maps=hash:array,delegate_attachs=xdp:tcx_ingress
`
	mounts := ParseMountInfoBpffs(sampleMountInfo)
	if len(mounts) != 2 {
		t.Fatalf("expected 2 bpffs mounts, got %d", len(mounts))
	}
	if mounts[0].HasDelegation {
		t.Errorf("host /sys/fs/bpf should not report HasDelegation")
	}
	if !mounts[1].HasDelegation || mounts[1].DelegateProgs != "xdp:sched_cls" {
		t.Errorf("unexpected delegated bpffs parse: %+v", mounts[1])
	}
}

func TestXdpBlockSafetyAndSnapshot(t *testing.T) {
	mgr := NewEBPFManager()
	defer mgr.Stop()

	// Must reject loopback / protected IP
	if err := mgr.AddXdpBlock("127.0.0.1", 60, XdpReasonMcpTactical, "test loopback"); err == nil {
		t.Fatalf("expected AddXdpBlock(127.0.0.1) to be rejected by safety guard")
	}

	// Must accept documentation IPv4 & IPv6 addresses
	if err := mgr.AddXdpBlock("198.51.100.42", 120, XdpReasonMcpTactical, "MCP test IPv4 block"); err != nil {
		t.Fatalf("AddXdpBlock IPv4 failed: %v", err)
	}
	if err := mgr.AddXdpBlock("2001:db8::dead:beef", 120, XdpReasonMcpTactical, "MCP test IPv6 block"); err != nil {
		t.Fatalf("AddXdpBlock IPv6 failed: %v", err)
	}

	snap := mgr.GetDataplaneSnapshot(10)
	if len(snap.ActiveBlocks) != 2 {
		t.Fatalf("expected 2 active XDP blocks in snapshot, got %d (%+v)", len(snap.ActiveBlocks), snap.ActiveBlocks)
	}

	if err := mgr.RemoveXdpBlock("198.51.100.42"); err != nil {
		t.Fatalf("RemoveXdpBlock failed: %v", err)
	}
	snap2 := mgr.GetDataplaneSnapshot(10)
	if len(snap2.ActiveBlocks) != 1 {
		t.Fatalf("expected 1 active XDP block after removal, got %d", len(snap2.ActiveBlocks))
	}
}

func TestZfsArcZilAndPoolIoKstatParsers(t *testing.T) {
	arcRaw := `13 1 0x01 98 31360 5192837123 89123791823
name                            type data
hits                            4    9500
misses                          4    500
demand_data_hits                4    7200
demand_metadata_hits            4    2300
size                            4    8589934592
c_max                           4    17179869184
c_min                           4    1073741824
l2_hits                         4    400
l2_misses                       4    100
l2_size                         4    34359738368
`
	arc := ParseZfsArcstats(arcRaw)
	if !arc.Available || arc.HitRatioPct != 95.0 || arc.SizeBytes != 8589934592 {
		t.Fatalf("unexpected parsed ARC stats: %+v", arc)
	}

	zilRaw := `10 1 0x01 20 1280 12345 67890
name                            type data
zil_commit_count                4    1842
zil_commit_writer_count         4    1610
zil_itx_count                   4    9420
zil_itx_metaslab_normal_count   4    120
zil_itx_metaslab_slog_count     4    1490
zil_itx_metaslab_slog_bytes     4    61030400
`
	zil := ParseZfsZilStats(zilRaw)
	if !zil.Available || zil.ItxMetaslabSlogCnt != 1490 || zil.CommitCount != 1842 {
		t.Fatalf("unexpected parsed ZIL stats: %+v", zil)
	}

	ioRaw := `3 0 0x01 1 80 123456 999999999
nread    nwritten reads    writes   wtime    wlentime wupdate  rtime    rlentime rupdate  wcnt     rcnt
104857600 52428800 4120     2090     0        0        0        0        0        0        2        5
`
	poolIo, ok := ParseZfsPoolIoKstat("tank", ioRaw)
	if !ok || poolIo.Pool != "tank" || poolIo.Reads != 4120 || poolIo.ActiveQueueDepth != 5 {
		t.Fatalf("unexpected parsed Pool IO kstat: ok=%v %+v", ok, poolIo)
	}
}
