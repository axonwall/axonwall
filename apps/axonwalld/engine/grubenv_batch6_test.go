package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A-L4 regression: the GRUB environment block is fixed at 1024 bytes.
// Pre-fix, writeGrubEnvKeyAtPath sliced serialised content to 1024
// bytes in Go map iteration order, silently dropping keys — possibly
// the just-set one — while returning nil. Post-fix, an over-budget
// block errors without writing, and in-budget writes are byte
// deterministic (sorted key order).
func TestBatch6GrubEnvOverflowErrorsWithoutWriting(t *testing.T) {
	// Hide grub-editenv so the direct-write fallback path is taken.
	t.Setenv("PATH", t.TempDir())

	envPath := filepath.Join(t.TempDir(), "grubenv")
	big := make(map[string]string)
	for i := 0; i < 40; i++ {
		big["key"+string(rune('a'+i%26))+strings.Repeat("x", 20)] = strings.Repeat("v", 20)
	}
	if err := writeGrubEnvKeyAtPath(envPath, big, "active_slot", "B"); err == nil {
		t.Fatal("expected an error when the grubenv block would exceed 1024 bytes")
	}
	if _, err := os.Stat(envPath); !os.IsNotExist(err) {
		t.Fatalf("over-budget grubenv must not be written, stat err: %v", err)
	}
}

func TestBatch6GrubEnvWriteIsDeterministic(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	dir := t.TempDir()
	env := map[string]string{"bootcount": "0", "active_slot": "A", "bootlimit": "3"}
	p1 := filepath.Join(dir, "grubenv1")
	p2 := filepath.Join(dir, "grubenv2")
	if err := writeGrubEnvKeyAtPath(p1, env, "active_slot", "B"); err != nil {
		t.Fatalf("in-budget write failed: %v", err)
	}
	if err := writeGrubEnvKeyAtPath(p2, env, "active_slot", "B"); err != nil {
		t.Fatalf("in-budget write failed: %v", err)
	}
	b1, err := os.ReadFile(p1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(p2)
	if err != nil {
		t.Fatal(err)
	}
	if len(b1) != 1024 {
		t.Fatalf("expected a 1024-byte block, got %d", len(b1))
	}
	if string(b1) != string(b2) {
		t.Fatal("two identical grubenv writes produced different bytes (key order must be deterministic)")
	}
	if !strings.Contains(string(b1), "active_slot=B\n") {
		t.Fatalf("written block is missing the just-set key: %q", string(b1))
	}
}
