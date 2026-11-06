package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installFakeUsermod prepends a directory containing a fake `usermod`
// executable to PATH. The fake records its arguments and exits with the
// given status, so lock/unlock error handling can be tested without
// touching a real account.
func installFakeUsermod(t *testing.T, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "usermod-args.log")
	script := "#!/bin/sh\n" +
		"echo \"$@\" >> \"" + logPath + "\"\n" +
		"exit " + string(rune('0'+exitCode)) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "usermod"), []byte(script), 0755); err != nil {
		t.Fatalf("Failed to write fake usermod: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return logPath
}

func boolPtr(b bool) *bool { return &b }

// A-M27: a usermod lock failure must be reported, not discarded —
// pre-fix a "locked" local user stayed unlocked while the call returned
// success. The fake usermod shadows the real one, so no real account is
// touched.
func TestBatch7_UserLockFailureIsReported(t *testing.T) {
	installFakeUsermod(t, 1)
	mgr := NewUserManager(nil)
	err := mgr.UpdateUser("root", UpdateUserRequest{PasswordLocked: boolPtr(true)})
	if err == nil {
		t.Fatal("UpdateUser with a failing usermod -L returned nil, want error")
	}
	if !strings.Contains(err.Error(), "failed to lock") {
		t.Fatalf("UpdateUser error = %q, want it to report the lock failure", err.Error())
	}
}

func TestBatch7_UserLockSuccess(t *testing.T) {
	logPath := installFakeUsermod(t, 0)
	mgr := NewUserManager(nil)
	if err := mgr.UpdateUser("root", UpdateUserRequest{PasswordLocked: boolPtr(true)}); err != nil {
		t.Fatalf("UpdateUser with a working usermod -L: %v", err)
	}
	argsLog, _ := os.ReadFile(logPath)
	if !strings.Contains(string(argsLog), "-L root") {
		t.Fatalf("expected fake usermod to be called with '-L root', got log %q", string(argsLog))
	}
}
