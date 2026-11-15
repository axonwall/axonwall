package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteCloudInitFileRejectsSymlinkTraversal(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	cfg := &EdgeBootConfig{}

	// 1. Intermediate directory symlink inside /etc/axonwall -> outside
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "etc", "axonwall")); err != nil {
		t.Fatal(err)
	}
	err := writeCloudInitFile(cfg, CloudInitWriteFile{
		Path:    "/etc/axonwall/escaped.conf",
		Content: "secret=1\n",
	}, root)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("expected intermediate dir symlink error, got %v", err)
	}
	if _, serr := os.Stat(filepath.Join(outside, "escaped.conf")); !os.IsNotExist(serr) {
		t.Fatalf("symlink traversal wrote outside rootDir")
	}

	// 2. Terminal file symlink -> outside file
	root2 := t.TempDir()
	outsideFile := filepath.Join(outside, "victim.conf")
	_ = os.WriteFile(outsideFile, []byte("original"), 0644)
	if err := os.MkdirAll(filepath.Join(root2, "etc", "axonwall"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(root2, "etc", "axonwall", "victim.conf")); err != nil {
		t.Fatal(err)
	}
	err = writeCloudInitFile(cfg, CloudInitWriteFile{
		Path:    "/etc/axonwall/victim.conf",
		Content: "overwritten",
	}, root2)
	if err == nil {
		t.Fatal("expected terminal file symlink write to fail")
	}
	got, _ := os.ReadFile(outsideFile)
	if string(got) != "original" {
		t.Fatalf("expected terminal symlink target unchanged, got %q", string(got))
	}

	// 3. Normal file write succeeds
	if err := writeCloudInitFile(cfg, CloudInitWriteFile{
		Path:        "/etc/axonwall/good.conf",
		Content:     "ok=1\n",
		Permissions: "0600",
	}, root2); err != nil {
		t.Fatalf("expected safe writeCloudInitFile to succeed, got %v", err)
	}
}

func TestSetForwardingChecksIPv6Errors(t *testing.T) {
	// IPv6 directory missing -> succeeds cleanly (IPv6 disabled kernel)
	proc1 := t.TempDir()
	v4 := filepath.Join(proc1, "net", "ipv4", "ip_forward")
	if err := os.MkdirAll(filepath.Dir(v4), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(v4, []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := SetForwarding(proc1, true); err != nil {
		t.Fatalf("expected SetForwarding to succeed when ipv6 proc path does not exist, got %v", err)
	}

	// IPv6 file present as a directory (unwritable regardless of euid) -> error propagated
	proc2 := t.TempDir()
	v4_2 := filepath.Join(proc2, "net", "ipv4", "ip_forward")
	v6_2 := filepath.Join(proc2, "net", "ipv6", "conf", "all", "forwarding")
	_ = os.MkdirAll(filepath.Dir(v4_2), 0755)
	_ = os.WriteFile(v4_2, []byte("0\n"), 0644)
	_ = os.MkdirAll(v6_2, 0755) // directory instead of file -> EISDIR on write even for root
	if err := SetForwarding(proc2, true); err == nil {
		t.Fatal("expected SetForwarding to return error when IPv6 forwarding path exists but fails write")
	}
}
