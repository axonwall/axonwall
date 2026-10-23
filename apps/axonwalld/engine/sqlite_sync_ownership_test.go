package engine

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestPreserveFileOwnership pins the B-12 follow-up behavior the HA
// sync apply relies on: a database downloaded by the root daemon must
// land with the ownership of the file it replaces (or of its
// directory), so the owning service — headscale, running as its own
// user — keeps write access to its database after a sync.
func TestPreserveFileOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to arbitrary ids requires root")
	}
	const uid, gid = 12345, 12345 // unassigned ids; ownership is numeric

	// Some sandboxed mounts refuse chown to non-root ids even for
	// root; a tmpfs scratch tree exercises the real syscalls. Fall
	// back to the default temp dir where /dev/shm is unavailable.
	base := "/dev/shm"
	if _, err := os.Stat(base); err != nil {
		base = ""
	}
	root, err := os.MkdirTemp(base, "preserve-owner")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	tempDir := func() string {
		d, err := os.MkdirTemp(root, "case")
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	ownerOf := func(path string) (int, int) {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		return int(st.Uid), int(st.Gid)
	}
	write := func(path string) {
		if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Existing target: the replacement inherits its ownership.
	dir := tempDir()
	target := filepath.Join(dir, "db.sqlite")
	fresh := filepath.Join(dir, "db.sqlite.tmp")
	write(target)
	write(fresh)
	if err := os.Chown(target, uid, gid); err != nil {
		t.Fatal(err)
	}
	preserveFileOwnership(fresh, target)
	if u, g := ownerOf(fresh); u != uid || g != gid {
		t.Fatalf("replacement should inherit target ownership %d:%d, got %d:%d", uid, gid, u, g)
	}

	// No target yet: the replacement inherits the directory's ownership.
	dir2 := tempDir()
	if err := os.Chown(dir2, uid, gid); err != nil {
		t.Fatal(err)
	}
	fresh2 := filepath.Join(dir2, "db.sqlite.tmp")
	write(fresh2)
	preserveFileOwnership(fresh2, filepath.Join(dir2, "db.sqlite"))
	if u, g := ownerOf(fresh2); u != uid || g != gid {
		t.Fatalf("replacement should inherit directory ownership %d:%d, got %d:%d", uid, gid, u, g)
	}

	// Neither target nor directory: a silent no-op that changes nothing.
	fresh3 := filepath.Join(tempDir(), "db.sqlite.tmp")
	write(fresh3)
	beforeU, beforeG := ownerOf(fresh3)
	preserveFileOwnership(fresh3, filepath.Join(root, "gone", "db.sqlite"))
	if u, g := ownerOf(fresh3); u != beforeU || g != beforeG {
		t.Fatalf("no-op case changed ownership: %d:%d -> %d:%d", beforeU, beforeG, u, g)
	}
}
