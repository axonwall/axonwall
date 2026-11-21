package engine

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBugHunt4_ResolveLocalNSSShell(t *testing.T) {
	for _, tc := range []struct {
		req  string
		role string
	}{
		{"/usr/sbin/nologin", "readonly"},
		{"/usr/local/bin/axonwall-opshell", "operator"},
		{"/sbin/nologin", "admin"},
	} {
		got := resolveLocalNSSShell(tc.req, tc.role)
		if got == "/bin/bash" || got == "/bin/ash" || got == "/bin/sh" || got == "/usr/bin/zsh" {
			t.Fatalf("resolveLocalNSSShell(%q, %q) must never upgrade restricted shell to interactive shell %q", tc.req, tc.role, got)
		}
		if tc.req != "/usr/local/bin/axonwall-opshell" && !strings.HasSuffix(got, "nologin") && !strings.HasSuffix(got, "false") {
			t.Fatalf("expected non-login shell for %q, got %q", tc.req, got)
		}
	}
}

func TestBugHunt4_FailingPluginCommandNoShellInjection(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "pwned")
	payload := `$(touch ` + marker + `) ` + "`touch " + marker + "`"
	cmd := failingPluginCommand(payload)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failingPluginCommand to exit non-zero")
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatalf("command injection executed side effect %s", marker)
	}
	if !strings.Contains(string(out), payload) {
		t.Fatalf("expected literal payload in stderr output, got %q", string(out))
	}
}

func TestBugHunt4_BuildSSSDConfigEmitsAllowedShells(t *testing.T) {
	cfg, err := BuildSSSDConfigWithBind("dc=example,dc=com", "", "", "")
	if err != nil {
		t.Fatalf("BuildSSSDConfigWithBind: %v", err)
	}
	for _, want := range []string{"default_shell =", "allowed_shells =", "shell_fallback = /bin/bash"} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("expected %q in SSSD config:\n%s", want, cfg)
		}
	}
}

func TestBugHunt4_VerifyBundledBinariesPinAndSymlink(t *testing.T) {
	pm := newBundledTestPM(t)
	sum := stagePluginFile(t, pm, "rosenpass", "bin/rosenpass", "#!/bin/sh\necho ok\n", 0755)
	def := PluginDefinition{
		ID:               "rosenpass",
		RequiredBinaries: []string{"rosenpass"},
		Binaries: []PluginBundledBinary{
			{Kind: "binary", Name: "rosenpass", SHA256: sum, URL: "https://example.invalid/rp"},
		},
		BinDirs: []string{"bin"},
	}

	// Missing Sources pin must fail closed.
	dir, _ := pm.pluginDir("rosenpass")
	if err := os.WriteFile(bundledRecordPath(dir), []byte(`{"pluginId":"rosenpass","files":[{"path":"bin/rosenpass","sha256":"`+sum+`","entry":"rosenpass","kind":"binary"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := pm.verifyBundledBinaries(def); err == nil {
		t.Fatalf("expected missing Sources pin to fail")
	}

	// Symlink file in plugin dir must fail closed in sha256File.
	target := filepath.Join(t.TempDir(), "outside")
	_ = os.WriteFile(target, []byte("outside"), 0755)
	symPath := filepath.Join(dir, "bin", "symlinked")
	if err := os.Symlink(target, symPath); err != nil {
		t.Fatal(err)
	}
	if _, err := sha256File(symPath); err == nil {
		t.Fatalf("expected sha256File to reject symlink")
	}
}

func TestBugHunt4_BundleValidators(t *testing.T) {
	// HelmChart validation (D-H4)
	if err := validateAllowedHelmChartSpec(map[string]any{
		"repo":         "https://charts.vigilante.local",
		"chart":        "vigilante",
		"chartContent": "H4sI...",
	}); err == nil {
		t.Fatalf("expected chartContent in HelmChart spec to be rejected")
	}
	if err := validateAllowedHelmChartSpec(map[string]any{
		"repo":     "https://helm.cilium.io/",
		"chart":    "cilium",
		"jobImage": "docker.io/library/alpine:latest",
	}); err == nil {
		t.Fatalf("expected jobImage in HelmChart spec to be rejected")
	}
	if err := validateAllowedHelmChartSpec(map[string]any{
		"repo":          "https://helm.cilium.io/",
		"chart":         "cilium",
		"valuesContent": "securityContext:\n  privileged: true\n",
	}); err == nil {
		t.Fatalf("expected privileged: true in HelmChart valuesContent to be rejected")
	}
	if err := validateAllowedHelmChartSpec(map[string]any{
		"repo":          "https://helm.cilium.io/",
		"chart":         "cilium",
		"valuesContent": "extraVolumes:\n  - name: host\n    hostPath:\n      path: /\n",
	}); err == nil {
		t.Fatalf("expected hostPath in HelmChart valuesContent to be rejected")
	}
	if err := validateAllowedHelmChartSpec(map[string]any{
		"repo":          "https://helm.cilium.io/",
		"chart":         "cilium",
		"valuesContent": "k8sServiceHost: 10.0.0.1\n",
	}); err != nil {
		t.Fatalf("expected valid cilium HelmChart valuesContent to pass, got %v", err)
	}
	if err := validateAllowedHelmChartSpec(map[string]any{
		"repo":  "https://untrusted.example.com",
		"chart": "evil",
	}); err == nil {
		t.Fatalf("expected untrusted repo to be rejected")
	}

	// Samba validation (D-H5)
	if err := validateSmbConf("[global]\nwinshook = /tmp/evil.sh\n"); err == nil {
		t.Fatalf("expected winshook in smb.conf to be rejected")
	}
	if err := validateSmbConf("[global]\npreload modules = /tmp/evil.so\n"); err == nil {
		t.Fatalf("expected preload modules in smb.conf to be rejected")
	}

	// LIO / MinIO / QEMU / LXC validation (D-H6)
	if err := validateLioSaveconfigJSON(`{"storage_objects":[{"dev":"/dev/sda"}]}`); err == nil {
		t.Fatalf("expected unsafe LIO backing dev /dev/sda to be rejected")
	}
	if err := validateLioSaveconfigJSON(`{"version":1,"storage_objects":[{"dev":"/dev/zvol/tank/vol0"}]}`); err != nil {
		t.Fatalf("expected valid LIO saveconfig JSON, got %v", err)
	}
	if err := validateMinioEnvConf("MINIO_ROOT_USER=axw\nEVIL_CMD=$(id)\n"); err == nil {
		t.Fatalf("expected shell expansion/unknown key in MinIO env to fail")
	}
	if err := validateMinioEnvConf("MINIO_ROOT_USER=axw\nMINIO_VOLUMES=\"/mnt/s3\"\n"); err != nil {
		t.Fatalf("expected valid MinIO env, got %v", err)
	}
	if err := validateSafeQemuArgs([]string{"-fw_cfg", "name=opt/evil,file=/etc/shadow"}); err == nil {
		t.Fatalf("expected -fw_cfg referencing /etc/shadow to be rejected")
	}
	if err := validateSafeQemuArgs([]string{"-fw_cfg", "name=opt/edge,file=/run/axonwall/edge/boot.json"}); err != nil {
		t.Fatalf("expected /run/axonwall/edge fw_cfg to be permitted, got %v", err)
	}
	if err := validateLxcConfig("lxc.hook.pre-start = /bin/sh\n"); err == nil {
		t.Fatalf("expected lxc hook injection to be rejected")
	}
	if err := validateLxcConfig("lxc.include = /usr/share/lxc/config/common.conf\nlxc.uts.name = web01\n"); err != nil {
		t.Fatalf("expected valid LXC config, got %v", err)
	}
}

func TestBugHunt4_IsPluginEnabledCoreK3s(t *testing.T) {
	pm := newBundledTestPM(t)
	if pm.IsPluginEnabled("core-k3s") {
		t.Fatalf("expected core-k3s disabled before staging")
	}
	stagePluginFile(t, pm, "core-k3s", "bin/k3s", "#!/bin/sh\n", 0755)
	if !pm.IsPluginEnabled("core-k3s") {
		t.Fatalf("expected core-k3s enabled once staged binary exists")
	}
}

func TestBugHunt4_ZshLoaderIdempotentAndOrderCheck(t *testing.T) {
	p := filepath.Join(t.TempDir(), "zshenv")
	if err := syncPluginShellZshLoaderFile(p, []string{"core-k3s"}); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	first, _ := os.ReadFile(p)
	if err := syncPluginShellZshLoaderFile(p, []string{"core-k3s"}); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	second, _ := os.ReadFile(p)
	if string(first) != string(second) {
		t.Fatalf("zsh loader grew across calls:\nfirst=%q\nsecond=%q", string(first), string(second))
	}

	reversed := pluginShellZshLoaderEnd + "\nstuff\n" + pluginShellZshLoaderBegin + "\n"
	if err := os.WriteFile(p, []byte(reversed), 0644); err != nil {
		t.Fatal(err)
	}
	if err := syncPluginShellZshLoaderFile(p, []string{"core-k3s"}); err == nil {
		t.Fatalf("expected reversed zsh markers to error")
	}
}

func TestBugHunt4_UninstallBinDirsOnlyAndExtractPAXGlobalHeader(t *testing.T) {
	// D-M3: BinDirs-only plugin cleanup on uninstall
	pm := newBundledTestPM(t)
	synthDoom := PluginDefinition{
		ID:      "cli-emacs-doom",
		Name:    "Doom Emacs",
		BinDirs: []string{"bin"},
	}
	overridePluginDefsForTest(t, synthDoom)
	stagePluginFile(t, pm, "cli-emacs-doom", "bin/emacs-doom", "#!/bin/sh\n", 0755)
	pm.installedMap["cli-emacs-doom"] = "2026-11-21T00:00:00Z"

	resp := pm.UninstallPlugin("cli-emacs-doom")
	if !resp.Success {
		t.Fatalf("UninstallPlugin failed: %s", resp.Message)
	}
	dir, _ := pm.pluginDir("cli-emacs-doom")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("expected BinDirs-only plugin dir %s to be removed on uninstall", dir)
	}

	// D-L2: extractArchiveTree skips tar.TypeXGlobalHeader ('g')
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	_ = tw.WriteHeader(&tar.Header{Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader, Size: 0})
	payload := []byte("hello")
	_ = tw.WriteHeader(&tar.Header{Name: "bin/hello", Mode: 0755, Size: int64(len(payload)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(payload)
	_ = tw.Close()

	archPath := filepath.Join(t.TempDir(), "test.tar")
	if err := os.WriteFile(archPath, tarBuf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "out")
	if err := extractArchiveTree(archPath, "tar", 0, outDir); err != nil {
		t.Fatalf("extractArchiveTree failed on PAX global header: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "bin", "hello")); err != nil {
		t.Fatalf("expected bin/hello extracted: %v", err)
	}
}

func TestBugHunt4_RedactSecretDescribe(t *testing.T) {
	raw := "Name: my-secret\nAnnotations:  kubectl.kubernetes.io/last-applied-configuration:\n                {\"apiVersion\":\"v1\",\"data\":{\"password\":\"c3VwZXJzZWNyZXQ=\"}}\n              other.io/note: ok\nType: Opaque\n"
	got := redactSecretDescribe(raw)
	if strings.Contains(got, "c3VwZXJzZWNyZXQ") {
		t.Fatalf("expected last-applied secret payload redacted, got:\n%s", got)
	}
	if !strings.Contains(got, "<redacted>") || !strings.Contains(got, "Type: Opaque") {
		t.Fatalf("expected <redacted> placeholder and non-secret fields preserved, got:\n%s", got)
	}
}
