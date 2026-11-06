package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installFakeIP prepends a directory containing a fake `ip` executable to
// PATH. The fake logs its arguments and exits with the given status.
func installFakeIP(t *testing.T, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "ip-args.log")
	script := "#!/bin/sh\n" +
		"echo \"$@\" >> \"" + logPath + "\"\n" +
		"exit " + string(rune('0'+exitCode)) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(script), 0755); err != nil {
		t.Fatalf("Failed to write fake ip: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return logPath
}

// A-M30: a bridge spec naming a renamed/removed NIC must fail instead of
// reporting a bridge that came up empty.
func TestBatch7_EnsureBridgeRejectsMissingMember(t *testing.T) {
	installFakeIP(t, 0)
	// Fake the sysfs bridge dir so step 2 succeeds without a real bridge.
	oldSysfs := SysfsNetRoot
	tmpSysfs := t.TempDir()
	SysfsNetRoot = tmpSysfs
	t.Cleanup(func() { SysfsNetRoot = oldSysfs })
	bridgeDir := filepath.Join(tmpSysfs, "br-test", "bridge")
	if err := os.MkdirAll(bridgeDir, 0755); err != nil {
		t.Fatal(err)
	}

	err := EnsureBridge(BridgeSpec{Name: "br-test", Members: []string{"ghost0"}})
	if err == nil {
		t.Fatal("EnsureBridge with a nonexistent member returned nil, want error")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("EnsureBridge error = %q, want it to report the missing member", err.Error())
	}
}

// A-M30: hardening must report a failed `ip addr flush` / `link set up`
// instead of silently doing nothing.
func TestBatch7_HardenDelegatedWANReportsIpFailures(t *testing.T) {
	tmpProc := t.TempDir()
	installFakeIP(t, 1)
	if err := hardenDelegatedWANWithRoots(tmpProc, true, "eth0"); err == nil {
		t.Fatal("hardenDelegatedWANWithRoots with a failing ip returned nil, want error")
	}

	installFakeIP(t, 0)
	// The fake ip now succeeds; sysctl writes land in the temp proc root.
	if err := hardenDelegatedWANWithRoots(tmpProc, true, "eth0"); err != nil {
		t.Fatalf("hardenDelegatedWANWithRoots with a working ip: %v", err)
	}
}
