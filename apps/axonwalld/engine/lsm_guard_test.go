package engine

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/axonwall/axonwall/apps/axonwalld/ebpf"
)

func TestKernelDevFromStat(t *testing.T) {
	stDev := unix.Mkdev(259, 3)
	got := KernelDevFromStat(stDev)
	want := (uint64(259) << 20) | uint64(3)
	if got != want {
		t.Fatalf("KernelDevFromStat(Mkdev(259,3)) = 0x%x, want 0x%x", got, want)
	}
}

func TestResolveExecutableID(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "trusted-app")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	linkPath := filepath.Join(tmpDir, "trusted-link")
	if err := os.Symlink(binPath, linkPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	idDirect, err := ResolveExecutableID(binPath)
	if err != nil {
		t.Fatalf("ResolveExecutableID(binPath): %v", err)
	}
	idLink, err := ResolveExecutableID(linkPath)
	if err != nil {
		t.Fatalf("ResolveExecutableID(linkPath): %v", err)
	}

	if idDirect.Ino == 0 || idDirect.Dev == 0 {
		t.Fatalf("expected non-zero (dev, ino), got dev=%d ino=%d", idDirect.Dev, idDirect.Ino)
	}
	if idDirect != idLink {
		t.Fatalf("symlink resolution mismatch: direct=%+v link=%+v", idDirect, idLink)
	}
}

func TestEmbeddedLsmGuardCollectionSpec(t *testing.T) {
	spec, err := ebpf.LoadLsmGuard()
	if err != nil {
		t.Fatalf("LoadLsmGuard failed: %v", err)
	}

	wantProgs := []string{"copyfail_guard", "restrict_bpf_load", "block_uring_sqpoll"}
	for _, p := range wantProgs {
		if _, ok := spec.Programs[p]; !ok {
			t.Errorf("missing expected BPF-LSM program %q in embedded ELF", p)
		}
	}

	wantMaps := []string{"allowlist", "policy_config", "events"}
	for _, m := range wantMaps {
		if _, ok := spec.Maps[m]; !ok {
			t.Errorf("missing expected BPF-LSM map %q in embedded ELF", m)
		}
	}
}

func TestDecodeLsmEventAndAuditIntegration(t *testing.T) {
	raw := make([]byte, 112)
	binary.LittleEndian.PutUint32(raw[0:4], 4192)
	binary.LittleEndian.PutUint32(raw[4:8], 1000)
	binary.LittleEndian.PutUint32(raw[8:12], HookIDSocketBindAead)
	binary.LittleEndian.PutUint32(raw[12:16], 1)
	binary.LittleEndian.PutUint64(raw[16:24], (uint64(259)<<20)|2)
	binary.LittleEndian.PutUint64(raw[24:32], 987654)
	copy(raw[32:48], "try-bind\x00")
	copy(raw[48:112], "authencesn(hmac(sha256),cbc(aes))\x00")

	ts := time.Date(2026, 11, 6, 21, 0, 0, 0, time.UTC)
	ev, err := DecodeLsmEvent(raw, ts)
	if err != nil {
		t.Fatalf("DecodeLsmEvent: %v", err)
	}
	if ev.PID != 4192 || ev.UID != 1000 || !ev.Blocked {
		t.Fatalf("unexpected decoded metadata: %+v", ev)
	}
	if ev.Comm != "try-bind" {
		t.Fatalf("unexpected comm %q, want try-bind", ev.Comm)
	}
	if ev.Detail != "authencesn(hmac(sha256),cbc(aes))" {
		t.Fatalf("unexpected detail %q", ev.Detail)
	}
	if ev.MitreTechnique != "T1068" {
		t.Fatalf("unexpected mitre %q, want T1068", ev.MitreTechnique)
	}

	mgr := NewLsmGuardManager()
	defer mgr.Stop()
	mgr.RecordEvent(ev)

	audit := RunHostRootkitAudit()
	if len(audit.BpfLsmDenialEvents) != 1 {
		t.Fatalf("expected 1 BpfLsmDenialEvent in audit, got %d", len(audit.BpfLsmDenialEvents))
	}
	if audit.OverallVerdict != "COMPROMISED_CRITICAL" {
		t.Fatalf("expected verdict COMPROMISED_CRITICAL when LSM denial is recorded, got %s", audit.OverallVerdict)
	}
}
