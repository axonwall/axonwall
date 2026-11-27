package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSlapdEnsureBaseDirPreservesStickyAndSetgid(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "axonwall-state")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := ensureAxonwallBaseDirPermissions(dir); err != nil {
		t.Fatalf("ensureAxonwallBaseDirPermissions: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mode := info.Mode()
	if mode&os.ModeSetgid == 0 {
		t.Fatalf("expected setgid bit preserved on %s, got mode %v", dir, mode)
	}
	if mode&os.ModeSticky == 0 {
		t.Fatalf("expected sticky bit preserved on %s, got mode %v", dir, mode)
	}
	if mode.Perm() != 0775 {
		t.Fatalf("expected permissions 0775, got %04o", mode.Perm())
	}
}
