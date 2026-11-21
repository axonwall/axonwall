// Plugin-bundled binaries: negative-control proofs (W5).
//
// Every test here stages FAKE binaries with hashes computed by the
// test itself and serves downloads from an httptest server — no test
// hits the real network or the real Debian/GitHub URLs. A live
// launch of real emacs/k3s/k9s/nvim is NOT runnable in this sandbox
// (none of those binaries exists here); where a launch matters, the
// test runs the generated launcher against a fake binary that echoes
// its argv/environment, and the real-binary launch stays recorded
// as unverified (see TestEmacsLaunchersResolveSharedBinary).
//
// Conventions: test PluginManagers use os.MkdirTemp with the
// "axonwall-plugins-test-*" prefix so NewPluginManager skips its
// /etc/dpkg write; shell-snippet tests point the package-level
// pluginShellProfileDir/pluginShellZshDir at temp dirs so nothing
// touches /etc.
package engine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func newBundledTestPM(t *testing.T) *PluginManager {
	t.Helper()
	dir, err := os.MkdirTemp("", "axonwall-plugins-test-*")
	if err != nil {
		t.Fatalf("create temp baseDataDir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return NewPluginManager(dir)
}

func shOnlyPATH(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	shPath := "/bin/sh"
	if p, err := exec.LookPath("sh"); err == nil && p != "" {
		shPath = p
	}
	if err := os.Symlink(shPath, filepath.Join(binDir, "sh")); err != nil {
		t.Fatalf("symlink sh into temp PATH: %v", err)
	}
	return binDir
}

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// stagePluginFile writes content (mode) at rel under the plugin dir
// and returns the file's sha256, for building bundled.json records.
func stagePluginFile(t *testing.T, pm *PluginManager, pluginID, rel, content string, mode os.FileMode) string {
	t.Helper()
	dir, err := pm.pluginDir(pluginID)
	if err != nil {
		t.Fatalf("pluginDir(%q): %v", pluginID, err)
	}
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(p), err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return sha256HexBytes([]byte(content))
}

func overridePluginDefsForTest(t *testing.T, defs ...PluginDefinition) {
	t.Helper()
	origLookup := lookupPluginDefinition
	origList := listExtensionPluginDefinitions
	overrides := make(map[string]PluginDefinition, len(defs))
	for _, d := range defs {
		overrides[d.ID] = d
	}
	lookupPluginDefinition = func(pluginID string) (PluginDefinition, bool) {
		if d, ok := overrides[pluginID]; ok {
			return d, true
		}
		return origLookup(pluginID)
	}
	listExtensionPluginDefinitions = func() []PluginDefinition {
		base := origList()
		out := make([]PluginDefinition, len(base))
		copy(out, base)
		seen := make(map[string]bool, len(base))
		for i, d := range out {
			seen[d.ID] = true
			if ov, ok := overrides[d.ID]; ok {
				out[i] = ov
			}
		}
		for _, d := range defs {
			if !seen[d.ID] {
				out = append(out, d)
			}
		}
		return out
	}
	t.Cleanup(func() {
		lookupPluginDefinition = origLookup
		listExtensionPluginDefinitions = origList
	})
}

func writeBundledJSON(t *testing.T, pm *PluginManager, pluginID string, recs []bundledBinaryRecord) {
	t.Helper()
	dir, err := pm.pluginDir(pluginID)
	if err != nil {
		t.Fatalf("pluginDir(%q): %v", pluginID, err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	var sources map[string]string
	if def, ok := lookupPluginDefinition(pluginID); ok && len(def.Binaries) > 0 {
		sources = make(map[string]string)
		for _, b := range def.Binaries {
			if b.SHA256 != "" {
				sources[b.Name] = strings.ToLower(strings.TrimSpace(b.SHA256))
			}
		}
	}
	data, err := json.MarshalIndent(bundledBinariesFile{PluginID: pluginID, Sources: sources, Files: recs}, "", "  ")
	if err != nil {
		t.Fatalf("marshal bundled.json: %v", err)
	}
	if err := os.WriteFile(bundledRecordPath(dir), data, 0644); err != nil {
		t.Fatalf("write bundled.json: %v", err)
	}
}

// findListedPlugin returns the ListPlugins status for id, or fails.
func findListedPlugin(t *testing.T, pm *PluginManager, id string) PluginStatus {
	t.Helper()
	for _, p := range pm.ListPlugins() {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("plugin %q not present in ListPlugins", id)
	return PluginStatus{}
}

func containsString(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

// envValue returns the value of key in a KEY=value env list.
func envValue(env []string, key string) (string, bool) {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v, true
		}
	}
	return "", false
}

// overrideSnippetDirs points the shell-snippet directories at temp
// dirs and restores them on cleanup, so no test touches /etc.
func overrideSnippetDirs(t *testing.T) (profileDir, zshDir string) {
	t.Helper()
	oldProfile, oldZsh := pluginShellProfileDir, pluginShellZshDir
	profileDir = t.TempDir()
	zshDir = t.TempDir()
	pluginShellProfileDir, pluginShellZshDir = profileDir, zshDir
	t.Cleanup(func() { pluginShellProfileDir, pluginShellZshDir = oldProfile, oldZsh })
	return profileDir, zshDir
}

func assertShSyntaxOK(t *testing.T, path string) {
	t.Helper()
	if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("sh -n %s failed: %v (output: %s)", path, err, strings.TrimSpace(string(out)))
	}
}

func assertShSyntaxStringOK(t *testing.T, name, content string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	assertShSyntaxOK(t, p)
}

// runFailingPluginCommand runs a command produced by
// CommandForPlugin for an unresolvable/unverified binary and
// asserts it fails with exit 127 and a message mentioning want.
func runFailingPluginCommand(t *testing.T, cmd *exec.Cmd, want string) {
	t.Helper()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failing plugin command to fail, got success (output: %s)", string(out))
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 127 {
		t.Fatalf("expected exit 127, got err %v (output: %s)", err, string(out))
	}
	if !strings.Contains(string(out), want) {
		t.Fatalf("failing command output %q does not mention %q", string(out), want)
	}
}

// ---------------------------------------------------------------------------
// (a) ListPlugins: cli-emacs installed with zero missing binaries when
// its plugin dir holds verified bundled binaries and the system PATH
// has no emacs; missing when the staged tree is absent.
// ---------------------------------------------------------------------------

// stageCliEmacsTree stages a fake-but-verified cli-emacs tree: the
// bin/emacs launcher and the real usr/bin/emacs-nox binary, plus a
// bundled.json whose hashes match the bytes on disk.
func stageCliEmacsTree(t *testing.T, pm *PluginManager) string {
	t.Helper()
	emacsSum := stagePluginFile(t, pm, "cli-emacs", "bin/emacs",
		"#!/bin/sh\necho fake-emacs \"$@\"\n", 0755)
	noxSum := stagePluginFile(t, pm, "cli-emacs", "usr/bin/emacs-nox",
		"#!/bin/sh\necho fake-emacs-nox \"$@\"\n", 0755)
	realDef, ok := findExtensionPluginDefinition("cli-emacs")
	if !ok {
		t.Fatalf("cli-emacs definition not found")
	}
	synth := realDef
	synth.Binaries = []PluginBundledBinary{
		{Kind: "distroPackage", Name: "emacs-nox", SHA256: noxSum, Package: "emacs-nox", Version: "1:30.1+1-6+deb13u1", Arch: "amd64"},
	}
	overridePluginDefsForTest(t, synth)
	writeBundledJSON(t, pm, "cli-emacs", []bundledBinaryRecord{
		{Path: "bin/emacs", SHA256: emacsSum, Entry: "emacs-nox", Kind: "distroPackage"},
		{Path: "usr/bin/emacs-nox", SHA256: noxSum, Entry: "emacs-nox", Kind: "distroPackage"},
	})
	dir, err := pm.pluginDir("cli-emacs")
	if err != nil {
		t.Fatalf("pluginDir(cli-emacs): %v", err)
	}
	return dir
}

func TestListPlugins_CliEmacsBundledInstalledNoSystemEmacs(t *testing.T) {
	// Scrubbed PATH: the empty dir holds no binaries at all, so
	// any emacs the listing finds must come from the plugin dir.
	t.Setenv("PATH", t.TempDir())
	if _, err := exec.LookPath("emacs"); err == nil {
		t.Fatalf("precondition failed: emacs unexpectedly resolvable on scrubbed PATH")
	}

	pm := newBundledTestPM(t)
	stageCliEmacsTree(t, pm)

	def, ok := lookupPluginDefinition("cli-emacs")
	if !ok {
		t.Fatalf("cli-emacs definition not found")
	}
	if err := pm.verifyBundledBinaries(def); err != nil {
		t.Fatalf("staged cli-emacs tree should verify: %v", err)
	}

	st := findListedPlugin(t, pm, "cli-emacs")
	if !st.Installed {
		t.Fatalf("expected cli-emacs Installed=true with verified bundled tree, got false (missing: %v)", st.MissingBinaries)
	}
	if len(st.MissingBinaries) != 0 {
		t.Fatalf("expected zero missing binaries, got %v", st.MissingBinaries)
	}
	if !containsString(st.BundledBinaries, "emacs") || !containsString(st.BundledBinaries, "emacs-nox") {
		t.Fatalf("expected BundledBinaries to list emacs and emacs-nox, got %v", st.BundledBinaries)
	}
}

func TestListPlugins_CliEmacsMissingWithoutStagedTree(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	pm := newBundledTestPM(t)
	// No plugin dir staged at all.
	st := findListedPlugin(t, pm, "cli-emacs")
	if st.Installed {
		t.Fatalf("expected cli-emacs Installed=false with no staged tree")
	}
	if !containsString(st.MissingBinaries, "emacs") || !containsString(st.MissingBinaries, "emacs-nox") {
		t.Fatalf("expected MissingBinaries to list emacs and emacs-nox, got %v", st.MissingBinaries)
	}
	if len(st.BundledBinaries) != 0 {
		t.Fatalf("expected no BundledBinaries without a staged tree, got %v", st.BundledBinaries)
	}
}

// ---------------------------------------------------------------------------
// (b) CommandForPlugin / PluginEnv resolve the bundled emacs; the
// shell snippet lifecycle (enable -> snippet exists, disable ->
// snippet removed) decides what an interactive shell sees.
// ---------------------------------------------------------------------------

func TestCommandForPlugin_CliEmacsBundledEmacs(t *testing.T) {
	// PATH has sh (so the test can run commands) but no emacs.
	t.Setenv("PATH", shOnlyPATH(t))
	if _, err := exec.LookPath("emacs"); err == nil {
		t.Fatalf("precondition failed: emacs unexpectedly on PATH")
	}
	pm := newBundledTestPM(t)
	pluginDir := stageCliEmacsTree(t, pm)

	cmd := pm.CommandForPlugin("cli-emacs", "emacs", "--version")
	if got := cmd.Path; got != filepath.Join(pluginDir, "bin", "emacs") {
		t.Fatalf("CommandForPlugin resolved emacs to %q, want %q", got, filepath.Join(pluginDir, "bin", "emacs"))
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running bundled emacs launcher failed: %v (output: %s)", err, string(out))
	}
	if !strings.Contains(string(out), "fake-emacs") {
		t.Fatalf("bundled emacs did not run: output %q", string(out))
	}

	// PluginEnv: the plugin bin dirs come first on PATH and the
	// ${PLUGIN_DIR} env values expand to the plugin dir.
	env, err := pm.PluginEnv("cli-emacs")
	if err != nil {
		t.Fatalf("PluginEnv: %v", err)
	}
	pathVal, ok := envValue(env, "PATH")
	if !ok {
		t.Fatalf("PluginEnv has no PATH")
	}
	parts := strings.Split(pathVal, string(os.PathListSeparator))
	if len(parts) < 2 || parts[0] != filepath.Join(pluginDir, "bin") || parts[1] != filepath.Join(pluginDir, "usr", "bin") {
		t.Fatalf("PluginEnv PATH should start with bin/ then usr/bin/ of the plugin dir, got %q", pathVal)
	}
	if got, _ := envValue(env, "EMACSDATA"); got != filepath.Join(pluginDir, "usr", "share", "emacs", "30.1", "etc") {
		t.Fatalf("EMACSDATA = %q, want the plugin-dir etc tree", got)
	}
	if got, _ := envValue(env, "LD_LIBRARY_PATH"); got != filepath.Join(pluginDir, "usr", "lib", "x86_64-linux-gnu") {
		t.Fatalf("LD_LIBRARY_PATH = %q, want the plugin-dir lib tree", got)
	}
}

func TestPluginShellSnippetLifecycle_CliEmacs(t *testing.T) {
	profileDir, zshDir := overrideSnippetDirs(t)
	pm := newBundledTestPM(t)
	pluginDir := stageCliEmacsTree(t, pm)
	pm.installedMap["cli-emacs"] = "2026-11-20T00:00:00Z"

	if err := SyncPluginShellPaths(pm, "cli-emacs"); err != nil {
		t.Fatalf("SyncPluginShellPaths (enabled): %v", err)
	}
	profileSnippet := filepath.Join(profileDir, "axonwall-plugin-cli-emacs.sh")
	zshSnippet := filepath.Join(zshDir, "axonwall-plugin-cli-emacs.zsh")
	for _, p := range []string{profileSnippet, zshSnippet} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("expected snippet %s to exist: %v", p, err)
		}
		if !strings.Contains(string(data), filepath.Join(pluginDir, "bin")) {
			t.Fatalf("snippet %s does not mention the plugin bin dir:\n%s", p, string(data))
		}
		assertShSyntaxOK(t, p)
	}
	// The zshenv loader block must source the .zsh snippet.
	zshenv, err := os.ReadFile(filepath.Join(zshDir, "zshenv"))
	if err != nil {
		t.Fatalf("expected zshenv loader to exist: %v", err)
	}
	if !strings.Contains(string(zshenv), "axonwall-plugin-cli-emacs.zsh") {
		t.Fatalf("zshenv loader does not reference the cli-emacs snippet:\n%s", string(zshenv))
	}

	// Live proof: a fresh sh sourcing the profile snippet resolves
	// emacs from the plugin dir, with a PATH that had no emacs.
	emptyDir := t.TempDir()
	// Run again with the scrubbed PATH on the child env.
	cmd := exec.Command("sh", "-c", fmt.Sprintf(". %s; command -v emacs", strconv.Quote(profileSnippet)))
	cmd.Env = []string{"PATH=" + emptyDir, "HOME=" + t.TempDir()}
	resolved, err := cmd.Output()
	if err != nil {
		t.Fatalf("sourcing the snippet did not put emacs on PATH: %v", err)
	}
	if strings.TrimSpace(string(resolved)) != filepath.Join(pluginDir, "bin", "emacs") {
		t.Fatalf("sourced shell resolved emacs to %q, want %q", strings.TrimSpace(string(resolved)), filepath.Join(pluginDir, "bin", "emacs"))
	}

	// Disable: Sync must REMOVE the snippets (disabled plugins
	// contribute no PATH), so an interactive shell no longer sees it.
	pm.disabledMap["cli-emacs"] = true
	if err := SyncPluginShellPaths(pm, "cli-emacs"); err != nil {
		t.Fatalf("SyncPluginShellPaths (disabled): %v", err)
	}
	for _, p := range []string{profileSnippet, zshSnippet} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("expected snippet %s to be removed after disable, stat err: %v", p, err)
		}
	}
	if data, err := os.ReadFile(filepath.Join(zshDir, "zshenv")); err == nil && strings.Contains(string(data), "cli-emacs") {
		t.Fatalf("zshenv loader still references cli-emacs after disable:\n%s", string(data))
	}

	// Explicit removal is idempotent and nil-pm-safe.
	if err := RemovePluginShellPath(nil, "cli-emacs"); err != nil {
		t.Fatalf("RemovePluginShellPath(nil) should succeed on missing snippets: %v", err)
	}
}

// CommandForPlugin does NOT gate on enabled state (observed
// semantic, recorded — not changed): disabling the plugin removes
// the shell snippet, but the daemon still resolves the bundled
// binary through the plugin dir. The snippet is what keeps it out
// of interactive shells.
func TestCommandForPlugin_DoesNotGateOnEnabled(t *testing.T) {
	pm := newBundledTestPM(t)
	pluginDir := stageCliEmacsTree(t, pm)
	pm.installedMap["cli-emacs"] = "2026-11-20T00:00:00Z"
	pm.disabledMap["cli-emacs"] = true
	if pm.IsPluginEnabled("cli-emacs") {
		t.Fatalf("precondition failed: cli-emacs should read disabled")
	}
	cmd := pm.CommandForPlugin("cli-emacs", "emacs")
	if got := cmd.Path; got != filepath.Join(pluginDir, "bin", "emacs") {
		t.Fatalf("disabled plugin still resolves via CommandForPlugin to %q (want %q) — if this ever changes, update the snippet-lifecycle tests that rely on the daemon/snippet split", got, filepath.Join(pluginDir, "bin", "emacs"))
	}
}

// ---------------------------------------------------------------------------
// (c) Tampering fails closed: a flipped byte (or a wrong hash in
// bundled.json) makes verification fail, CommandForPlugin return the
// exit-127 command, and ListPlugins report the binary missing.
// ---------------------------------------------------------------------------

func TestVerifyBundledBinaries_TamperedBinaryFailsClosed(t *testing.T) {
	// PATH has sh (to run the failing command) but no emacs.
	t.Setenv("PATH", shOnlyPATH(t))
	pm := newBundledTestPM(t)
	pluginDir := stageCliEmacsTree(t, pm)
	def, _ := lookupPluginDefinition("cli-emacs")

	// Flip one byte of the staged launcher after install.
	launcher := filepath.Join(pluginDir, "bin", "emacs")
	data, err := os.ReadFile(launcher)
	if err != nil {
		t.Fatalf("read launcher: %v", err)
	}
	data[0] ^= 0x01
	if err := os.WriteFile(launcher, data, 0755); err != nil {
		t.Fatalf("rewrite launcher: %v", err)
	}

	if err := pm.verifyBundledBinaries(def); err == nil {
		t.Fatalf("verify should fail on a tampered bundled binary")
	} else if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("verify error should name the sha256 mismatch, got: %v", err)
	}

	runFailingPluginCommand(t, pm.CommandForPlugin("cli-emacs", "emacs"), "sha256 mismatch")

	st := findListedPlugin(t, pm, "cli-emacs")
	if st.Installed {
		t.Fatalf("tampered cli-emacs must not read installed")
	}
	if !containsString(st.MissingBinaries, "emacs") || !containsString(st.MissingBinaries, "emacs-nox") {
		t.Fatalf("tampered cli-emacs should report emacs and emacs-nox missing, got %v", st.MissingBinaries)
	}
	if len(st.BundledBinaries) != 0 {
		t.Fatalf("tampered cli-emacs must report no verified bundled binaries, got %v", st.BundledBinaries)
	}
}

func TestVerifyBundledBinaries_WrongRecordHashFailsClosed(t *testing.T) {
	pm := newBundledTestPM(t)
	stageCliEmacsTree(t, pm)
	def, _ := lookupPluginDefinition("cli-emacs")

	// Rewrite bundled.json with a wrong hash for one file (the
	// bytes on disk are untouched — the record itself lies).
	writeBundledJSON(t, pm, "cli-emacs", []bundledBinaryRecord{
		{Path: "bin/emacs", SHA256: strings.Repeat("0", 64), Entry: "emacs-nox", Kind: "distroPackage"},
		{Path: "usr/bin/emacs-nox", SHA256: strings.Repeat("0", 64), Entry: "emacs-nox", Kind: "distroPackage"},
	})
	if err := pm.verifyBundledBinaries(def); err == nil {
		t.Fatalf("verify should fail when bundled.json carries a wrong hash")
	} else if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("verify error should name the sha256 mismatch, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// (d) A rosenpass-style archive download with a WRONG sha256 refuses
// to install; the matching hash installs and verifies.
// ---------------------------------------------------------------------------

type tarMember struct {
	name     string
	content  string
	mode     int64
	typeflag byte
	linkname string
}

func buildTarGz(t *testing.T, members []tarMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, m := range members {
		tf := m.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		mode := m.mode
		if mode == 0 {
			mode = 0644
		}
		hdr := &tar.Header{Name: m.name, Mode: mode, Size: int64(len(m.content)), Typeflag: tf, Linkname: m.linkname}
		if tf != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader %s: %v", m.name, err)
		}
		if tf == tar.TypeReg {
			if _, err := tw.Write([]byte(m.content)); err != nil {
				t.Fatalf("tar Write %s: %v", m.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

func buildTar(t *testing.T, members []tarMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range members {
		tf := m.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		mode := m.mode
		if mode == 0 {
			mode = 0644
		}
		hdr := &tar.Header{Name: m.name, Mode: mode, Size: int64(len(m.content)), Typeflag: tf, Linkname: m.linkname}
		if tf != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader %s: %v", m.name, err)
		}
		if tf == tar.TypeReg {
			if _, err := tw.Write([]byte(m.content)); err != nil {
				t.Fatalf("tar Write %s: %v", m.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	return buf.Bytes()
}

// countingServer serves fixed byte payloads per path and counts hits.
type countingServer struct {
	mu         sync.Mutex
	files      map[string][]byte
	hits       int
	hitsByPath map[string]int
}

func (s *countingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits++
	if s.hitsByPath == nil {
		s.hitsByPath = make(map[string]int)
	}
	s.hitsByPath[r.URL.Path]++
	s.mu.Unlock()
	b, ok := s.files[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(b)
}

func (s *countingServer) hitCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

// rosenpassStyleDef is a synthetic plugin with the real rosenpass
// entry's shape (tar archive, PathInArchive bin/rosenpass) but an
// httptest URL, so the download path is exercised without network.
func rosenpassStyleDef(t *testing.T, srv *httptest.Server, sha string) PluginDefinition {
	t.Helper()
	return PluginDefinition{
		ID:               "test-rosenpass",
		RequiredBinaries: []string{"rosenpass"},
		Binaries: []PluginBundledBinary{{
			Kind:          "archive",
			Name:          "rosenpass",
			SHA256:        sha,
			URL:           srv.URL + "/rosenpass.tar",
			Format:        "tar",
			PathInArchive: "bin/rosenpass",
		}},
		BinDirs: []string{"bin"},
	}
}

func TestInstallBundledBinaries_RosenpassStyleArchiveHappyPath(t *testing.T) {
	tarBytes := buildTar(t, []tarMember{
		{name: "bin/rosenpass", content: "#!/bin/sh\necho rosenpass-fake \"$@\"\n", mode: 0755},
		{name: "bin/rp", content: "#!/bin/sh\necho rp-fake\n", mode: 0755},
		{name: "README.md", content: "rosenpass\n"},
	})
	srv := httptest.NewServer(&countingServer{files: map[string][]byte{"/rosenpass.tar": tarBytes}})
	defer srv.Close()

	pm := newBundledTestPM(t)
	def := rosenpassStyleDef(t, srv, sha256HexBytes(tarBytes))
	if err := pm.validateBundledBinaries(def); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := pm.installBundledBinaries(def); err != nil {
		t.Fatalf("install: %v", err)
	}
	pluginDir, _ := pm.pluginDir("test-rosenpass")
	got, err := os.ReadFile(filepath.Join(pluginDir, "bin", "rosenpass"))
	if err != nil {
		t.Fatalf("installed rosenpass binary missing: %v", err)
	}
	if string(got) != "#!/bin/sh\necho rosenpass-fake \"$@\"\n" {
		t.Fatalf("installed rosenpass has unexpected content %q", string(got))
	}
	if info, err := os.Stat(filepath.Join(pluginDir, "bin", "rosenpass")); err != nil || info.Mode().Perm()&0111 == 0 {
		t.Fatalf("installed rosenpass is not executable: %v %v", info, err)
	}
	// Only the declared binary is extracted; the sibling rp script
	// and the README are ignored by single-binary extraction.
	if _, err := os.Stat(filepath.Join(pluginDir, "bin", "rp")); !os.IsNotExist(err) {
		t.Fatalf("single-binary extraction should not have installed bin/rp")
	}
	if _, err := os.Stat(bundledRecordPath(pluginDir)); err != nil {
		t.Fatalf("bundled.json missing after install: %v", err)
	}
	if err := pm.verifyBundledBinaries(def); err != nil {
		t.Fatalf("verify after install: %v", err)
	}
	out, err := exec.Command(filepath.Join(pluginDir, "bin", "rosenpass"), "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("running installed fake rosenpass failed: %v", err)
	}
	if !strings.Contains(string(out), "rosenpass-fake") {
		t.Fatalf("unexpected rosenpass output %q", string(out))
	}
}

func TestInstallBundledBinaries_RosenpassStyleArchiveWrongSHARefuses(t *testing.T) {
	tarBytes := buildTar(t, []tarMember{
		{name: "bin/rosenpass", content: "#!/bin/sh\necho rosenpass-fake\n", mode: 0755},
	})
	srv := httptest.NewServer(&countingServer{files: map[string][]byte{"/rosenpass.tar": tarBytes}})
	defer srv.Close()

	pm := newBundledTestPM(t)
	// Deliberately wrong expected hash: the hash of other bytes.
	def := rosenpassStyleDef(t, srv, sha256HexBytes([]byte("not the tarball")))
	if err := pm.validateBundledBinaries(def); err != nil {
		t.Fatalf("validate should pass on a well-formed (if wrong-hash) def: %v", err)
	}
	err := pm.installBundledBinaries(def)
	if err == nil {
		t.Fatalf("install with a wrong sha256 must fail")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("install error should name the sha256 mismatch, got: %v", err)
	}
	pluginDir, _ := pm.pluginDir("test-rosenpass")
	if _, err := os.Stat(bundledRecordPath(pluginDir)); !os.IsNotExist(err) {
		t.Fatalf("a failed install must not write bundled.json")
	}
	if _, err := os.Stat(filepath.Join(pluginDir, "bin", "rosenpass")); !os.IsNotExist(err) {
		t.Fatalf("a failed install must not leave the binary behind")
	}
	if err := pm.verifyBundledBinaries(def); err == nil {
		t.Fatalf("verify must fail after a refused install")
	}
}

// The real rosenpass definition resolves its bundled binary through
// the daemon path once a verified tree is staged (same staging shape
// as cli-emacs in (a)).
func TestCommandForPlugin_RosenpassBundledBinary(t *testing.T) {
	t.Setenv("PATH", shOnlyPATH(t))
	pm := newBundledTestPM(t)
	sum := stagePluginFile(t, pm, "rosenpass", "bin/rosenpass",
		"#!/bin/sh\necho rosenpass-fake \"$@\"\n", 0755)
	realDef, ok := findExtensionPluginDefinition("rosenpass")
	if !ok {
		t.Fatalf("rosenpass definition not found")
	}
	synth := realDef
	synth.Binaries = []PluginBundledBinary{
		{Kind: "archive", Name: "rosenpass", SHA256: sum, URL: "https://example.invalid/rosenpass.tar.zst", Format: "tar.zst"},
	}
	overridePluginDefsForTest(t, synth)
	writeBundledJSON(t, pm, "rosenpass", []bundledBinaryRecord{
		{Path: "bin/rosenpass", SHA256: sum, Entry: "rosenpass", Kind: "archive"},
	})
	def, _ := lookupPluginDefinition("rosenpass")
	if err := pm.verifyBundledBinaries(def); err != nil {
		t.Fatalf("staged rosenpass tree should verify: %v", err)
	}
	pluginDir, _ := pm.pluginDir("rosenpass")
	cmd := pm.CommandForPlugin("rosenpass", "rosenpass", "gen-keys")
	if cmd.Path != filepath.Join(pluginDir, "bin", "rosenpass") {
		t.Fatalf("CommandForPlugin resolved rosenpass to %q, want %q", cmd.Path, filepath.Join(pluginDir, "bin", "rosenpass"))
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running bundled rosenpass failed: %v", err)
	}
	if !strings.Contains(string(out), "rosenpass-fake") {
		t.Fatalf("unexpected rosenpass output %q", string(out))
	}
}

// ---------------------------------------------------------------------------
// (e) All three emacs plugins at once: definitions coexist, each
// launcher resolves to the SHARED cli-emacs binary with its own
// config, and plain `emacs` is the minimal config. A live launch of
// REAL emacs is NOT runnable here (no emacs binary in the sandbox)
// and stays unverified; what runs here is each generated launcher
// against a fake emacs-nox that echoes argv/environment.
// ---------------------------------------------------------------------------

func extDef(t *testing.T, id string) PluginDefinition {
	t.Helper()
	def, ok := findExtensionPluginDefinition(id)
	if !ok {
		t.Fatalf("extension definition %q not found", id)
	}
	return def
}

func TestEmacsPluginDefinitionsCoexist(t *testing.T) {
	cli := extDef(t, "cli-emacs")
	doom := extDef(t, "cli-emacs-doom")
	spacemacs := extDef(t, "cli-emacs-spacemacs")

	// cli-emacs carries the bundle: 10 distroPackage .debs.
	if len(cli.Binaries) != 10 {
		t.Fatalf("cli-emacs should declare 10 distroPackage entries, got %d", len(cli.Binaries))
	}
	for _, b := range cli.Binaries {
		if b.Kind != "distroPackage" {
			t.Fatalf("cli-emacs entry %q has kind %q, want distroPackage", b.Name, b.Kind)
		}
		if !sha256HexPattern.MatchString(b.SHA256) {
			t.Fatalf("cli-emacs entry %q has a non-hex sha256 %q", b.Name, b.SHA256)
		}
	}
	if got := cli.BinDirs; len(got) != 2 || got[0] != "bin" || got[1] != "usr/bin" {
		t.Fatalf("cli-emacs BinDirs = %v, want [bin usr/bin]", got)
	}

	// Doom/Spacemacs carry NO emacs binary of their own — by
	// design, they share cli-emacs — and both depend on it.
	for _, d := range []PluginDefinition{doom, spacemacs} {
		if len(d.Binaries) != 0 {
			t.Fatalf("%s must declare no Binaries (it shares cli-emacs), got %v", d.ID, d.Binaries)
		}
		if len(d.Dependencies) != 1 || d.Dependencies[0] != "cli-emacs" {
			t.Fatalf("%s Dependencies = %v, want [cli-emacs]", d.ID, d.Dependencies)
		}
		if len(d.BinDirs) != 1 || d.BinDirs[0] != "bin" {
			t.Fatalf("%s BinDirs = %v, want [bin]", d.ID, d.BinDirs)
		}
	}
	if doom.RequiredBinaries == nil || len(doom.RequiredBinaries) != 1 || doom.RequiredBinaries[0] != "emacs-doom" {
		t.Fatalf("doom RequiredBinaries = %v, want [emacs-doom]", doom.RequiredBinaries)
	}
	if len(spacemacs.RequiredBinaries) != 1 || spacemacs.RequiredBinaries[0] != "emacs-spacemacs" {
		t.Fatalf("spacemacs RequiredBinaries = %v, want [emacs-spacemacs]", spacemacs.RequiredBinaries)
	}

	// Every real definition in the repo must pass daemon validation.
	pm := newBundledTestPM(t)
	if pm.osFamily != "debian" {
		t.Skipf("distroPackage validation needs a debian host, this host is %q", pm.osFamily)
	}
	for _, d := range GetExtensionPluginDefinitions() {
		if err := pm.validateBundledBinaries(d); err != nil {
			t.Fatalf("definition %q fails validation: %v", d.ID, err)
		}
	}
	for _, d := range GetCorePluginDefinitions() {
		if err := pm.validateBundledBinaries(d); err != nil {
			t.Fatalf("core definition %q fails validation: %v", d.ID, err)
		}
	}
}

// assertElispBalanced checks paren/bracket/brace balance after
// stripping string literals and ;-comments, so a paren inside a
// string or comment cannot mask (or fake) an imbalance.
func assertElispBalanced(t *testing.T, name, src string) {
	t.Helper()
	var code strings.Builder
	inStr := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		if inStr {
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			continue
		}
		if c == ';' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}
		code.WriteByte(c)
	}
	if inStr {
		t.Fatalf("%s: unterminated string literal", name)
	}
	depths := map[byte]int{'(': 0, '[': 0, '{': 0}
	pairs := map[byte]byte{')': '(', ']': '[', '}': '{'}
	for i := 0; i < code.Len(); i++ {
		c := code.String()[i]
		switch c {
		case '(', '[', '{':
			depths[c]++
		case ')', ']', '}':
			open := pairs[c]
			depths[open]--
			if depths[open] < 0 {
				t.Fatalf("%s: unbalanced %q at code offset %d", name, c, i)
			}
		}
	}
	for open, d := range depths {
		if d != 0 {
			t.Fatalf("%s: unbalanced %q (depth %d at end of file)", name, open, d)
		}
	}
}

func TestEmacsGeneratedConfigParenBalance(t *testing.T) {
	assertElispBalanced(t, "emacsInitEl (minimal)", emacsInitEl)
	assertElispBalanced(t, "doomInitEl", doomInitEl)
	assertElispBalanced(t, "doomConfigEl", doomConfigEl)
	assertElispBalanced(t, "doomPackagesEl", doomPackagesEl)
	assertElispBalanced(t, "spacemacsInitEl", spacemacsInitEl)
}

// W4 launcher check, ported: provisionEmacsPluginFiles writes the
// bin/emacs launcher byte-identical to the emacsLauncherScript
// constant, the minimal init.el byte-identical to emacsInitEl, and
// symlinks the pdmp next to the binary.
func TestProvisionEmacsPluginFiles_LauncherByteIdenticalAndPdmpSymlink(t *testing.T) {
	pm := newBundledTestPM(t)
	// The provision step needs exactly one pdmp under the libexec
	// tree and the extracted binary present.
	stagePluginFile(t, pm, "cli-emacs", "usr/bin/emacs-nox",
		"#!/bin/sh\necho fake-emacs-nox\n", 0755)
	stagePluginFile(t, pm, "cli-emacs",
		"usr/libexec/emacs/30.1/x86_64-linux-gnu/emacs-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.pdmp",
		"fake-pdmp", 0644)
	if err := pm.provisionEmacsPluginFiles(); err != nil {
		t.Fatalf("provisionEmacsPluginFiles: %v", err)
	}
	pluginDir, _ := pm.pluginDir("cli-emacs")
	launcher, err := os.ReadFile(filepath.Join(pluginDir, "bin", "emacs"))
	if err != nil {
		t.Fatalf("read provisioned launcher: %v", err)
	}
	if string(launcher) != emacsLauncherScript {
		t.Fatalf("provisioned bin/emacs differs from the emacsLauncherScript constant")
	}
	initEl, err := os.ReadFile(filepath.Join(pluginDir, "config", "init.el"))
	if err != nil {
		t.Fatalf("read provisioned init.el: %v", err)
	}
	if string(initEl) != emacsInitEl {
		t.Fatalf("provisioned config/init.el differs from the emacsInitEl constant")
	}
	link := filepath.Join(pluginDir, "usr", "bin", "emacs-nox.pdmp")
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("pdmp symlink missing: %v", err)
	}
	want := filepath.Join("..", "libexec", "emacs", "30.1", "x86_64-linux-gnu", "emacs-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.pdmp")
	if target != want {
		t.Fatalf("pdmp symlink target = %q, want %q", target, want)
	}
	if _, err := os.Stat(link); err != nil {
		t.Fatalf("pdmp symlink dangles: %v", err)
	}
	assertShSyntaxOK(t, filepath.Join(pluginDir, "bin", "emacs"))
}

func TestEmacsLaunchersResolveSharedBinary(t *testing.T) {
	// All three launcher texts are valid sh.
	assertShSyntaxStringOK(t, "emacs-launcher.sh", emacsLauncherScript)
	assertShSyntaxStringOK(t, "emacs-doom-launcher.sh", doomLauncherScript())
	assertShSyntaxStringOK(t, "emacs-spacemacs-launcher.sh", spacemacsLauncherScript())

	// Text: Doom/Spacemacs exec the SHARED cli-emacs binary (a
	// sibling plugin dir), never a system emacs; minimal execs its
	// own plugin dir's binary. Each passes its own --init-directory.
	if !strings.Contains(doomLauncherScript(), `BIN="$EMACS_PLUGIN_DIR/usr/bin/emacs-nox"`) {
		t.Fatalf("doom launcher does not exec the shared cli-emacs emacs-nox")
	}
	if !strings.Contains(spacemacsLauncherScript(), `BIN="$EMACS_PLUGIN_DIR/usr/bin/emacs-nox"`) {
		t.Fatalf("spacemacs launcher does not exec the shared cli-emacs emacs-nox")
	}
	if !strings.Contains(emacsLauncherScript, `BIN="$PLUGIN_DIR/usr/bin/emacs-nox"`) {
		t.Fatalf("minimal launcher does not exec its own plugin dir's emacs-nox")
	}
	if !strings.Contains(doomLauncherScript(), `export DOOMDIR="$PLUGIN_DIR/config"`) ||
		!strings.Contains(doomLauncherScript(), `export DOOMLOCALDIR="$PLUGIN_DIR/local"`) ||
		!strings.Contains(doomLauncherScript(), `exec "$BIN" --init-directory "$PLUGIN_DIR/doom"`) {
		t.Fatalf("doom launcher is missing DOOMDIR/DOOMLOCALDIR/--init-directory doom:\n%s", doomLauncherScript())
	}
	if !strings.Contains(spacemacsLauncherScript(), `export SPACEMACSDIR="$PLUGIN_DIR/config"`) ||
		!strings.Contains(spacemacsLauncherScript(), `exec "$BIN" --init-directory "$PLUGIN_DIR/spacemacs"`) {
		t.Fatalf("spacemacs launcher is missing SPACEMACSDIR/--init-directory spacemacs:\n%s", spacemacsLauncherScript())
	}
	if !strings.Contains(emacsLauncherScript, `exec "$BIN" --init-directory "$PLUGIN_DIR/config"`) {
		t.Fatalf("minimal launcher is missing --init-directory config")
	}
	if strings.Contains(emacsLauncherScript, "DOOMDIR") || strings.Contains(emacsLauncherScript, "SPACEMACSDIR") {
		t.Fatalf("minimal launcher must not set Doom/Spacemacs variables")
	}
	// No launcher falls back to a bare system emacs.
	for name, script := range map[string]string{
		"minimal":   emacsLauncherScript,
		"doom":      doomLauncherScript(),
		"spacemacs": spacemacsLauncherScript(),
	} {
		if strings.Contains(script, "exec emacs ") || strings.Contains(script, "exec emacs\n") {
			t.Fatalf("%s launcher falls back to a system emacs", name)
		}
		if !strings.Contains(script, "exit 127") {
			t.Fatalf("%s launcher does not fail loudly (exit 127) when its binary is missing", name)
		}
	}

	// Live launcher run against a FAKE emacs-nox that echoes its
	// argv and environment. This proves launcher resolution and
	// env-passing end to end; launching REAL emacs stays
	// UNVERIFIED here (no emacs binary exists in this sandbox).
	pm := newBundledTestPM(t)
	fakeNox := "#!/bin/sh\n" +
		"echo \"FAKE-NOX ARGS: $*\"\n" +
		"echo \"DOOMDIR=${DOOMDIR-unset}\"\n" +
		"echo \"DOOMLOCALDIR=${DOOMLOCALDIR-unset}\"\n" +
		"echo \"SPACEMACSDIR=${SPACEMACSDIR-unset}\"\n" +
		"echo \"EMACSDATA=${EMACSDATA-unset}\"\n"
	stagePluginFile(t, pm, "cli-emacs", "usr/bin/emacs-nox", fakeNox, 0755)
	stagePluginFile(t, pm, "cli-emacs",
		"usr/libexec/emacs/30.1/x86_64-linux-gnu/emacs-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.pdmp",
		"fake-pdmp", 0644)
	if err := pm.provisionEmacsPluginFiles(); err != nil {
		t.Fatalf("provisionEmacsPluginFiles: %v", err)
	}
	if err := pm.provisionDoomEmacsPluginFiles(); err != nil {
		t.Fatalf("provisionDoomEmacsPluginFiles: %v", err)
	}
	if err := pm.provisionSpacemacsPluginFiles(); err != nil {
		t.Fatalf("provisionSpacemacsPluginFiles: %v", err)
	}
	cliDir, _ := pm.pluginDir("cli-emacs")
	doomDir, _ := pm.pluginDir("cli-emacs-doom")
	spacemacsDir, _ := pm.pluginDir("cli-emacs-spacemacs")
	home := t.TempDir()
	run := func(path string) string {
		t.Helper()
		cmd := exec.Command(path)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("running %s failed: %v (output: %s)", path, err, string(out))
		}
		return string(out)
	}
	minimalOut := run(filepath.Join(cliDir, "bin", "emacs"))
	if !strings.Contains(minimalOut, "--init-directory "+filepath.Join(cliDir, "config")) {
		t.Fatalf("minimal launcher did not pass its own config dir:\n%s", minimalOut)
	}
	if !strings.Contains(minimalOut, "EMACSDATA="+filepath.Join(cliDir, "usr", "share", "emacs", "30.1", "etc")) {
		t.Fatalf("minimal launcher did not set EMACSDATA at the plugin dir:\n%s", minimalOut)
	}
	if !strings.Contains(minimalOut, "DOOMDIR=unset") || !strings.Contains(minimalOut, "SPACEMACSDIR=unset") {
		t.Fatalf("minimal launcher leaked Doom/Spacemacs variables:\n%s", minimalOut)
	}
	doomOut := run(filepath.Join(doomDir, "bin", "emacs-doom"))
	if !strings.Contains(doomOut, "--init-directory "+filepath.Join(doomDir, "doom")) {
		t.Fatalf("doom launcher did not pass its own doom dir:\n%s", doomOut)
	}
	if !strings.Contains(doomOut, "DOOMDIR="+filepath.Join(doomDir, "config")) ||
		!strings.Contains(doomOut, "DOOMLOCALDIR="+filepath.Join(doomDir, "local")) {
		t.Fatalf("doom launcher did not set DOOMDIR/DOOMLOCALDIR:\n%s", doomOut)
	}
	if !strings.Contains(doomOut, "EMACSDATA="+filepath.Join(cliDir, "usr", "share", "emacs", "30.1", "etc")) {
		t.Fatalf("doom launcher did not point EMACSDATA at the SHARED cli-emacs tree:\n%s", doomOut)
	}
	spacemacsOut := run(filepath.Join(spacemacsDir, "bin", "emacs-spacemacs"))
	if !strings.Contains(spacemacsOut, "--init-directory "+filepath.Join(spacemacsDir, "spacemacs")) {
		t.Fatalf("spacemacs launcher did not pass its own spacemacs dir:\n%s", spacemacsOut)
	}
	if !strings.Contains(spacemacsOut, "SPACEMACSDIR="+filepath.Join(spacemacsDir, "config")) {
		t.Fatalf("spacemacs launcher did not set SPACEMACSDIR:\n%s", spacemacsOut)
	}
	if !strings.Contains(spacemacsOut, "EMACSDATA="+filepath.Join(cliDir, "usr", "share", "emacs", "30.1", "etc")) {
		t.Fatalf("spacemacs launcher did not point EMACSDATA at the SHARED cli-emacs tree:\n%s", spacemacsOut)
	}
}

// ---------------------------------------------------------------------------
// (f) Dependency guard, ported from W6's throwaway checks: disabling
// (and uninstalling) cli-emacs while Doom or Spacemacs is enabled
// refuses, naming the dependent; the guard clears once the
// dependent is disabled.
// ---------------------------------------------------------------------------

func TestDependencyGuard_CliEmacsRefusesWhileDoomEnabled(t *testing.T) {
	overrideSnippetDirs(t)
	pm := newBundledTestPM(t)
	pm.installedMap["cli-emacs"] = "2026-11-20T00:00:00Z"
	pm.installedMap["cli-emacs-doom"] = "2026-11-20T00:00:00Z"

	resp := pm.DisablePlugin("cli-emacs")
	if resp.Success {
		t.Fatalf("DisablePlugin(cli-emacs) must refuse while cli-emacs-doom is enabled")
	}
	if !strings.Contains(resp.Message, "cli-emacs-doom") {
		t.Fatalf("refusal must name the dependent, got: %s", resp.Message)
	}
	if !pm.IsPluginEnabled("cli-emacs") {
		t.Fatalf("cli-emacs must stay enabled after the refused disable")
	}

	resp = pm.UninstallPlugin("cli-emacs")
	if resp.Success {
		t.Fatalf("UninstallPlugin(cli-emacs) must refuse while cli-emacs-doom is enabled")
	}
	if !strings.Contains(resp.Message, "cli-emacs-doom") {
		t.Fatalf("uninstall refusal must name the dependent, got: %s", resp.Message)
	}

	// Guard clears once the dependent is disabled.
	resp = pm.DisablePlugin("cli-emacs-doom")
	if !resp.Success {
		t.Fatalf("DisablePlugin(cli-emacs-doom) should succeed: %+v", resp)
	}
	resp = pm.DisablePlugin("cli-emacs")
	if !resp.Success {
		t.Fatalf("DisablePlugin(cli-emacs) should succeed once doom is disabled: %+v", resp)
	}
	if pm.IsPluginEnabled("cli-emacs") {
		t.Fatalf("cli-emacs should be disabled now")
	}
}

func TestDependencyGuard_CliEmacsRefusesWhileSpacemacsEnabled(t *testing.T) {
	overrideSnippetDirs(t)
	pm := newBundledTestPM(t)
	pm.installedMap["cli-emacs"] = "2026-11-20T00:00:00Z"
	pm.installedMap["cli-emacs-spacemacs"] = "2026-11-20T00:00:00Z"

	resp := pm.DisablePlugin("cli-emacs")
	if resp.Success || !strings.Contains(resp.Message, "cli-emacs-spacemacs") {
		t.Fatalf("DisablePlugin(cli-emacs) must refuse naming cli-emacs-spacemacs, got: %+v", resp)
	}
	resp = pm.UninstallPlugin("cli-emacs")
	if resp.Success || !strings.Contains(resp.Message, "cli-emacs-spacemacs") {
		t.Fatalf("UninstallPlugin(cli-emacs) must refuse naming cli-emacs-spacemacs, got: %+v", resp)
	}

	// Disabling the dependent by state alone (not via the toggle)
	// also clears the guard: the guard reads enabled state, not
	// the toggle path.
	pm.disabledMap["cli-emacs-spacemacs"] = true
	if got := pm.enabledDependentsOf("cli-emacs"); len(got) != 0 {
		t.Fatalf("expected no enabled dependents once spacemacs is disabled, got %v", got)
	}
	resp = pm.DisablePlugin("cli-emacs")
	if !resp.Success {
		t.Fatalf("DisablePlugin(cli-emacs) should succeed once spacemacs is disabled: %+v", resp)
	}
	// And the uninstall now succeeds too (no packages to remove
	// for cli-emacs; the plugin dir is removed if present).
	resp = pm.UninstallPlugin("cli-emacs")
	if !resp.Success {
		t.Fatalf("UninstallPlugin(cli-emacs) should succeed once spacemacs is disabled: %+v", resp)
	}
}

// ---------------------------------------------------------------------------
// (g) core-k3s: k3s and k9s resolve from the plugin dir with no k3s/k9s
// on the system PATH; ensureBundledBinaries costs no network when the
// staged tree is healthy and re-downloads when a file is missing or
// mismatched.
// ---------------------------------------------------------------------------

// stageCoreK3sTree stages fake k3s/k9s binaries plus a matching
// bundled.json for the REAL core-k3s definition.
func stageCoreK3sTree(t *testing.T, pm *PluginManager) string {
	t.Helper()
	k3sSum := stagePluginFile(t, pm, "core-k3s", "bin/k3s",
		"#!/bin/sh\necho fake-k3s \"$@\"\n", 0755)
	k9sSum := stagePluginFile(t, pm, "core-k3s", "bin/k9s",
		"#!/bin/sh\necho fake-k9s \"$@\"\n", 0755)
	realDef := GetCorePluginDefinitions()[0]
	synth := realDef
	synth.Binaries = []PluginBundledBinary{
		{Kind: "binary", Name: "k3s", SHA256: k3sSum, URL: "https://example.invalid/k3s"},
		{Kind: "archive", Name: "k9s", SHA256: k9sSum, URL: "https://example.invalid/k9s.tar.gz", Format: "tar.gz"},
	}
	overridePluginDefsForTest(t, synth)
	writeBundledJSON(t, pm, "core-k3s", []bundledBinaryRecord{
		{Path: "bin/k3s", SHA256: k3sSum, Entry: "k3s", Kind: "binary"},
		{Path: "bin/k9s", SHA256: k9sSum, Entry: "k9s", Kind: "archive"},
	})
	dir, err := pm.pluginDir("core-k3s")
	if err != nil {
		t.Fatalf("pluginDir(core-k3s): %v", err)
	}
	return dir
}

func TestCoreK3s_BundledBinariesResolveWithoutSystemBinaries(t *testing.T) {
	t.Setenv("PATH", shOnlyPATH(t))
	for _, bin := range []string{"k3s", "k9s", "kubectl"} {
		if _, err := exec.LookPath(bin); err == nil {
			t.Fatalf("precondition failed: %s unexpectedly on PATH", bin)
		}
	}
	pm := newBundledTestPM(t)
	pluginDir := stageCoreK3sTree(t, pm)
	def, ok := lookupPluginDefinition("core-k3s")
	if !ok || def.ID != "core-k3s" {
		t.Fatalf("core-k3s definition lookup failed: %+v", def)
	}
	if err := pm.ensureBundledBinaries(def); err != nil {
		t.Fatalf("ensureBundledBinaries on a healthy staged tree: %v", err)
	}
	for _, bin := range []string{"k3s", "k9s"} {
		cmd := pm.CommandForPlugin("core-k3s", bin, "version")
		if cmd.Path != filepath.Join(pluginDir, "bin", bin) {
			t.Fatalf("CommandForPlugin(core-k3s, %q) resolved to %q, want the plugin dir", bin, cmd.Path)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("running bundled %s failed: %v", bin, err)
		}
		if !strings.Contains(string(out), "fake-"+bin) {
			t.Fatalf("unexpected %s output %q", bin, string(out))
		}
	}

	// kubectl is the k3s multicall symlink in the plugin bin dir.
	if err := pm.ensureCoreK3sBinSymlinks(); err != nil {
		t.Fatalf("ensureCoreK3sBinSymlinks: %v", err)
	}
	kubectl := filepath.Join(pluginDir, "bin", "kubectl")
	if target, err := os.Readlink(kubectl); err != nil || target != "k3s" {
		t.Fatalf("kubectl symlink = %q (err %v), want target \"k3s\"", target, err)
	}
	if !pm.hasPluginBinaryForPlugin(def, "kubectl") {
		t.Fatalf("hasPluginBinaryForPlugin should find kubectl via the plugin dir")
	}
	cmd := pm.CommandForPlugin("core-k3s", "kubectl", "version")
	if cmd.Path != kubectl {
		t.Fatalf("CommandForPlugin(core-k3s, kubectl) resolved to %q, want %q", cmd.Path, kubectl)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running plugin kubectl failed: %v", err)
	}
	if !strings.Contains(string(out), "fake-k3s") {
		t.Fatalf("plugin kubectl should run the k3s multicall binary, got %q", string(out))
	}
}

func TestEnsureBundledBinaries_NoNetworkWhenHealthyRedownloadsWhenMissing(t *testing.T) {
	k3sBytes := []byte("#!/bin/sh\necho fake-k3s \"$@\"\n")
	k9sBytes := []byte("#!/bin/sh\necho fake-k9s \"$@\"\n")
	k9sTar := buildTarGz(t, []tarMember{{name: "k9s", content: string(k9sBytes), mode: 0755}})
	srvFiles := map[string][]byte{"/k3s": k3sBytes, "/k9s.tar.gz": k9sTar}
	handler := &countingServer{files: srvFiles}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Synthetic core-k3s definition: same plugin id (so the same
	// plugin dir), but httptest URLs instead of the real GitHub ones.
	synth := PluginDefinition{
		ID:               "core-k3s",
		RequiredBinaries: []string{"k3s", "k9s"},
		Binaries: []PluginBundledBinary{
			{Kind: "binary", Name: "k3s", SHA256: sha256HexBytes(k3sBytes), URL: srv.URL + "/k3s"},
			{Kind: "archive", Name: "k9s", SHA256: sha256HexBytes(k9sTar), URL: srv.URL + "/k9s.tar.gz", Format: "tar.gz"},
		},
		BinDirs: []string{"bin"},
	}
	pm := newBundledTestPM(t)
	if err := pm.validateBundledBinaries(synth); err != nil {
		t.Fatalf("validate synthetic core-k3s: %v", err)
	}
	// First ensure installs (2 downloads).
	if err := pm.ensureBundledBinaries(synth); err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	if got := handler.hitCount(); got != 2 {
		t.Fatalf("first ensure should download both entries (2 hits), got %d", got)
	}
	pluginDir, _ := pm.pluginDir("core-k3s")
	if got, _ := os.ReadFile(filepath.Join(pluginDir, "bin", "k3s")); string(got) != string(k3sBytes) {
		t.Fatalf("installed k3s bytes differ from the served bytes")
	}
	// Healthy tree: ensure costs no network at all.
	if err := pm.ensureBundledBinaries(synth); err != nil {
		t.Fatalf("ensure on healthy tree: %v", err)
	}
	if got := handler.hitCount(); got != 2 {
		t.Fatalf("ensure on a healthy tree must not hit the network (still 2 hits), got %d", got)
	}
	// Missing file: ensure re-downloads and restores it.
	if err := os.Remove(filepath.Join(pluginDir, "bin", "k9s")); err != nil {
		t.Fatalf("remove k9s: %v", err)
	}
	if err := pm.ensureBundledBinaries(synth); err != nil {
		t.Fatalf("ensure after deleting k9s: %v", err)
	}
	if got := handler.hitCount(); got != 4 {
		t.Fatalf("ensure after a missing file should re-download both entries (4 hits total), got %d", got)
	}
	if got, _ := os.ReadFile(filepath.Join(pluginDir, "bin", "k9s")); string(got) != string(k9sBytes) {
		t.Fatalf("re-downloaded k9s bytes differ from the served bytes")
	}
	// Mismatched file: flipping a byte also triggers a re-download
	// that restores the verified bytes.
	k3sPath := filepath.Join(pluginDir, "bin", "k3s")
	data, _ := os.ReadFile(k3sPath)
	data[0] ^= 0x01
	if err := os.WriteFile(k3sPath, data, 0755); err != nil {
		t.Fatalf("corrupt k3s: %v", err)
	}
	if err := pm.ensureBundledBinaries(synth); err != nil {
		t.Fatalf("ensure after corrupting k3s: %v", err)
	}
	if got := handler.hitCount(); got != 6 {
		t.Fatalf("ensure after a mismatched file should re-download both entries (6 hits total), got %d", got)
	}
	if got, _ := os.ReadFile(k3sPath); string(got) != string(k3sBytes) {
		t.Fatalf("re-downloaded k3s bytes differ from the served bytes")
	}
	// D-H2: The real core-k3s definition must FAIL closed against a tree
	// staged from synthetic non-pinned hashes (source pin mismatch).
	if err := pm.verifyBundledBinaries(GetCorePluginDefinitions()[0]); err == nil {
		t.Fatalf("real core-k3s definition must fail source pin check against synthetic tree")
	} else if !strings.Contains(err.Error(), "source pin mismatch") {
		t.Fatalf("expected source pin mismatch error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// (h) vi/vim resolve to the bundled nvim (relative symlinks in the
// workstation plugin bin/ dir); disabling the workstation plugin
// removes the shell snippet so all three leave PATH.
// ---------------------------------------------------------------------------

func stageWorkstationNvimTree(t *testing.T, pm *PluginManager) string {
	t.Helper()
	nvimSum := stagePluginFile(t, pm, "cli-workstation", "bin/nvim",
		"#!/bin/sh\necho fake-nvim \"$@\"\n", 0755)
	runtimeSum := stagePluginFile(t, pm, "cli-workstation", "share/nvim/runtime/doc.txt",
		"fake runtime\n", 0644)
	parserSum := stagePluginFile(t, pm, "cli-workstation", "lib/nvim/parser/c.so",
		"fake-parser", 0644)
	if realDef, ok := findExtensionPluginDefinition("cli-workstation"); ok {
		synth := realDef
		synth.Binaries = []PluginBundledBinary{
			{Kind: "archive", Name: "nvim", SHA256: nvimSum, URL: "https://example.invalid/nvim.tar.gz", Format: "tar.gz", OSes: []string{"debian"}},
		}
		overridePluginDefsForTest(t, synth)
	}
	writeBundledJSON(t, pm, "cli-workstation", []bundledBinaryRecord{
		{Path: "bin/nvim", SHA256: nvimSum, Entry: "nvim", Kind: "archive"},
		{Path: "lib/nvim/parser/c.so", SHA256: parserSum, Entry: "nvim", Kind: "archive"},
		{Path: "share/nvim/runtime/doc.txt", SHA256: runtimeSum, Entry: "nvim", Kind: "archive"},
	})
	dir, err := pm.pluginDir("cli-workstation")
	if err != nil {
		t.Fatalf("pluginDir(cli-workstation): %v", err)
	}
	return dir
}

func TestWorkstation_NvimSymlinksResolveViVim(t *testing.T) {
	// Scrubbed PATH: /usr/bin/vi exists on this host, so only a
	// scrubbed PATH proves the plugin dir is what resolves vi/vim.
	t.Setenv("PATH", t.TempDir())
	pm := newBundledTestPM(t)
	pluginDir := stageWorkstationNvimTree(t, pm)
	def, ok := lookupPluginDefinition("cli-workstation")
	if !ok {
		t.Fatalf("cli-workstation definition not found")
	}
	if err := pm.verifyBundledBinaries(def); err != nil {
		t.Fatalf("staged workstation tree should verify: %v", err)
	}
	if err := pm.ensureWorkstationNvimSymlinks(); err != nil {
		t.Fatalf("ensureWorkstationNvimSymlinks: %v", err)
	}
	for _, link := range []string{"vi", "vim"} {
		p := filepath.Join(pluginDir, "bin", link)
		target, err := os.Readlink(p)
		if err != nil {
			t.Fatalf("symlink %s missing: %v", link, err)
		}
		if target != "nvim" {
			t.Fatalf("symlink %s points at %q, want relative target \"nvim\"", link, target)
		}
		// os.Stat follows the symlink: the link resolves to an
		// executable (this is what hasPluginBinaryForPlugin
		// relies on).
		if !isExecutableFile(p) {
			t.Fatalf("symlink %s does not resolve to an executable", link)
		}
		if !pm.hasPluginBinaryForPlugin(def, link) {
			t.Fatalf("hasPluginBinaryForPlugin should find %s via the plugin dir", link)
		}
		cmd := pm.CommandForPlugin("cli-workstation", link, "--version")
		if cmd.Path != p {
			t.Fatalf("CommandForPlugin(cli-workstation, %q) resolved to %q, want %q", link, cmd.Path, p)
		}
	}
	if !pm.hasPluginBinaryForPlugin(def, "nvim") {
		t.Fatalf("hasPluginBinaryForPlugin should find nvim via the plugin dir")
	}
	// Running `vi` through the symlink executes the bundled nvim.
	out, err := exec.Command(filepath.Join(pluginDir, "bin", "vi"), "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("running plugin vi failed: %v", err)
	}
	if !strings.Contains(string(out), "fake-nvim") {
		t.Fatalf("plugin vi should run the bundled nvim, got %q", string(out))
	}
}

func TestPluginShellSnippetLifecycle_Workstation(t *testing.T) {
	profileDir, zshDir := overrideSnippetDirs(t)
	pm := newBundledTestPM(t)
	pluginDir := stageWorkstationNvimTree(t, pm)
	if err := pm.ensureWorkstationNvimSymlinks(); err != nil {
		t.Fatalf("ensureWorkstationNvimSymlinks: %v", err)
	}
	// cli-workstation is enabled by default (no
	// /etc/axonwall/workstation.disabled in this sandbox).
	if !pm.IsPluginEnabled("cli-workstation") {
		t.Fatalf("precondition failed: cli-workstation should read enabled")
	}
	if err := SyncPluginShellPaths(pm, "cli-workstation"); err != nil {
		t.Fatalf("SyncPluginShellPaths (enabled): %v", err)
	}
	profileSnippet := filepath.Join(profileDir, "axonwall-plugin-cli-workstation.sh")
	data, err := os.ReadFile(profileSnippet)
	if err != nil {
		t.Fatalf("expected workstation snippet to exist: %v", err)
	}
	if !strings.Contains(string(data), filepath.Join(pluginDir, "bin")) {
		t.Fatalf("workstation snippet does not mention the plugin bin dir:\n%s", string(data))
	}
	assertShSyntaxOK(t, profileSnippet)

	// Live proof: sourcing the snippet puts vi, vim and nvim on
	// PATH from the plugin dir.
	emptyDir := t.TempDir()
	cmd := exec.Command("sh", "-c", fmt.Sprintf(". %s; command -v vi; command -v vim; command -v nvim", strconv.Quote(profileSnippet)))
	cmd.Env = []string{"PATH=" + emptyDir, "HOME=" + t.TempDir()}
	resolved, err := cmd.Output()
	if err != nil {
		t.Fatalf("sourcing the workstation snippet did not put vi/vim/nvim on PATH: %v", err)
	}
	want := strings.Join([]string{
		filepath.Join(pluginDir, "bin", "vi"),
		filepath.Join(pluginDir, "bin", "vim"),
		filepath.Join(pluginDir, "bin", "nvim"),
	}, "\n") + "\n"
	if string(resolved) != want {
		t.Fatalf("sourced shell resolved vi/vim/nvim to %q, want %q", string(resolved), want)
	}

	// Disable removes the snippet, so all three leave PATH: a
	// fresh shell sourcing what remains finds none of them.
	if err := RemovePluginShellPath(pm, "cli-workstation"); err != nil {
		t.Fatalf("RemovePluginShellPath: %v", err)
	}
	for _, p := range []string{
		profileSnippet,
		filepath.Join(zshDir, "axonwall-plugin-cli-workstation.zsh"),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("expected snippet %s to be removed after disable, stat err: %v", p, err)
		}
	}
	cmd = exec.Command("sh", "-c", "command -v vi || echo NOTFOUND; command -v vim || echo NOTFOUND; command -v nvim || echo NOTFOUND")
	cmd.Env = []string{"PATH=" + emptyDir, "HOME=" + t.TempDir()}
	resolved, err = cmd.Output()
	if err != nil {
		t.Fatalf("post-removal shell check failed: %v", err)
	}
	if string(resolved) != "NOTFOUND\nNOTFOUND\nNOTFOUND\n" {
		t.Fatalf("after snippet removal a fresh shell should find no vi/vim/nvim, got %q", string(resolved))
	}
}

// ---------------------------------------------------------------------------
// Validation unit tests for the schema rules (daemon side — the Go
// struct cannot enforce them, validateBundledBinaries must).
// ---------------------------------------------------------------------------

func TestValidateBundledBinaries(t *testing.T) {
	pm := newBundledTestPM(t)
	if pm.osFamily != "debian" {
		t.Skipf("distroPackage cases need a debian host, this host is %q", pm.osFamily)
	}
	validSHA := strings.Repeat("a", 64)
	archive := func(mutate func(*PluginBundledBinary)) PluginBundledBinary {
		b := PluginBundledBinary{Kind: "archive", Name: "tool", SHA256: validSHA, URL: "https://example.com/tool.tar.gz", Format: "tar.gz"}
		if mutate != nil {
			mutate(&b)
		}
		return b
	}
	binary := func(mutate func(*PluginBundledBinary)) PluginBundledBinary {
		b := PluginBundledBinary{Kind: "binary", Name: "tool", SHA256: validSHA, URL: "https://example.com/tool"}
		if mutate != nil {
			mutate(&b)
		}
		return b
	}
	distro := func(mutate func(*PluginBundledBinary)) PluginBundledBinary {
		b := PluginBundledBinary{Kind: "distroPackage", Name: "tool", SHA256: validSHA, Distro: "debian", Package: "tool", Version: "1.0-1", Arch: "amd64"}
		if mutate != nil {
			mutate(&b)
		}
		return b
	}
	defWith := func(bins []PluginBundledBinary, binDirs []string, env map[string]string) PluginDefinition {
		return PluginDefinition{ID: "test-plugin", Binaries: bins, BinDirs: binDirs, Env: env}
	}
	valid := func(b PluginBundledBinary) PluginDefinition {
		return defWith([]PluginBundledBinary{b}, []string{"bin"}, nil)
	}

	cases := []struct {
		name    string
		def     PluginDefinition
		wantErr string // "" means valid; otherwise a substring of the error
	}{
		{name: "valid archive", def: valid(archive(nil)), wantErr: ""},
		{name: "valid binary", def: valid(binary(nil)), wantErr: ""},
		{name: "valid distroPackage", def: valid(distro(nil)), wantErr: ""},
		{name: "valid distroPackage with source", def: valid(distro(func(b *PluginBundledBinary) { b.Source = "tool-src" })), wantErr: ""},
		{name: "valid tree archive", def: valid(archive(func(b *PluginBundledBinary) {
			b.Extract = "tree"
			b.StripComponents = 1
		})), wantErr: ""},
		{name: "valid oses gate", def: valid(archive(func(b *PluginBundledBinary) { b.OSes = []string{"debian"} })), wantErr: ""},
		{name: "valid uppercase sha256", def: valid(archive(func(b *PluginBundledBinary) { b.SHA256 = strings.Repeat("A", 64) })), wantErr: ""},
		{name: "valid env key", def: defWith([]PluginBundledBinary{archive(nil)}, []string{"bin"}, map[string]string{"EMACSDATA": "${PLUGIN_DIR}/etc"}), wantErr: ""},

		{name: "bad sha256 short", def: valid(archive(func(b *PluginBundledBinary) { b.SHA256 = "abc" })), wantErr: "sha256 must be a 64-char hex digest"},
		{name: "bad sha256 non-hex", def: valid(archive(func(b *PluginBundledBinary) { b.SHA256 = strings.Repeat("z", 64) })), wantErr: "sha256 must be a 64-char hex digest"},
		{name: "SHA256_TODO placeholder rejected", def: valid(archive(func(b *PluginBundledBinary) { b.SHA256 = "SHA256_TODO_tool" })), wantErr: "sha256 must be a 64-char hex digest"},
		{name: "empty name", def: valid(archive(func(b *PluginBundledBinary) { b.Name = "" })), wantErr: "empty name"},
		{name: "name with slash", def: valid(archive(func(b *PluginBundledBinary) { b.Name = "a/b" })), wantErr: "must be a plain file name"},
		{name: "duplicate name", def: defWith([]PluginBundledBinary{archive(nil), binary(func(b *PluginBundledBinary) { b.Name = "tool" })}, []string{"bin"}, nil), wantErr: "duplicate binary name"},
		{name: "unknown kind", def: valid(PluginBundledBinary{Kind: "tarball", Name: "tool", SHA256: validSHA, URL: "https://example.com/tool"}), wantErr: "unknown kind"},
		{name: "archive missing url", def: valid(archive(func(b *PluginBundledBinary) { b.URL = "" })), wantErr: "url is required"},
		{name: "archive ftp url", def: valid(archive(func(b *PluginBundledBinary) { b.URL = "ftp://example.com/tool.tar" })), wantErr: "must be an http(s) URL"},
		{name: "archive with distro fields", def: valid(archive(func(b *PluginBundledBinary) { b.Distro = "debian" })), wantErr: "must be empty for kind archive"},
		{name: "archive bad format", def: valid(archive(func(b *PluginBundledBinary) { b.Format = "rar" })), wantErr: "unsupported format"},
		{name: "archive bad extract", def: valid(archive(func(b *PluginBundledBinary) { b.Extract = "bogus" })), wantErr: "unsupported extract"},
		{name: "tree with pathInArchive rejected", def: valid(archive(func(b *PluginBundledBinary) {
			b.Extract = "tree"
			b.PathInArchive = "bin/tool"
		})), wantErr: "pathInArchive must be empty with extract"},
		{name: "stripComponents without tree rejected", def: valid(archive(func(b *PluginBundledBinary) { b.StripComponents = 1 })), wantErr: "stripComponents is only meaningful with extract"},
		{name: "stripComponents out of range", def: valid(archive(func(b *PluginBundledBinary) {
			b.Extract = "tree"
			b.StripComponents = 9
		})), wantErr: "stripComponents 9 out of range"},
		{name: "pathInArchive with ..", def: valid(archive(func(b *PluginBundledBinary) { b.PathInArchive = "../tool" })), wantErr: "must not contain .."},
		{name: "pathInArchive absolute", def: valid(archive(func(b *PluginBundledBinary) { b.PathInArchive = "/bin/tool" })), wantErr: "must be a relative path"},
		{name: "bad oses name", def: valid(archive(func(b *PluginBundledBinary) { b.OSes = []string{"windows"} })), wantErr: "not a known OS family"},
		{name: "duplicate oses", def: valid(archive(func(b *PluginBundledBinary) { b.OSes = []string{"debian", "debian"} })), wantErr: "duplicate os"},

		{name: "binary with distro fields rejected", def: valid(binary(func(b *PluginBundledBinary) { b.Distro = "debian" })), wantErr: "must be empty for kind binary"},
		{name: "binary with format rejected", def: valid(binary(func(b *PluginBundledBinary) { b.Format = "tar" })), wantErr: "format must be empty for kind binary"},
		{name: "binary with pathInArchive rejected", def: valid(binary(func(b *PluginBundledBinary) { b.PathInArchive = "tool" })), wantErr: "pathInArchive must be empty for kind binary"},
		{name: "binary with extract rejected", def: valid(binary(func(b *PluginBundledBinary) { b.Extract = "tree" })), wantErr: "extract must be empty for kind binary"},
		{name: "binary with stripComponents rejected", def: valid(binary(func(b *PluginBundledBinary) { b.StripComponents = 1 })), wantErr: "stripComponents must be 0 for kind binary"},
		{name: "binary missing url", def: valid(binary(func(b *PluginBundledBinary) { b.URL = "" })), wantErr: "url is required"},

		{name: "distroPackage with url rejected", def: valid(distro(func(b *PluginBundledBinary) { b.URL = "https://example.com/tool.deb" })), wantErr: "url must be empty for kind distroPackage"},
		{name: "distroPackage missing version", def: valid(distro(func(b *PluginBundledBinary) { b.Version = "" })), wantErr: "distro, package, version and arch are all required"},
		{name: "distroPackage non-debian distro", def: valid(distro(func(b *PluginBundledBinary) { b.Distro = "alpine" })), wantErr: "not supported (debian only)"},
		{name: "distroPackage bad package name", def: valid(distro(func(b *PluginBundledBinary) { b.Package = "Bad_Pkg" })), wantErr: "not a valid Debian package name"},
		{name: "distroPackage bad version", def: valid(distro(func(b *PluginBundledBinary) { b.Version = "1.0/x" })), wantErr: "not a valid Debian version"},
		{name: "distroPackage with extract rejected", def: valid(distro(func(b *PluginBundledBinary) { b.Extract = "tree" })), wantErr: "extract must be empty for kind distroPackage"},

		{name: "bad binDir absolute", def: defWith([]PluginBundledBinary{archive(nil)}, []string{"/bin"}, nil), wantErr: "binDir"},
		{name: "bad binDir dotdot", def: defWith([]PluginBundledBinary{archive(nil)}, []string{"../up"}, nil), wantErr: "binDir"},
		{name: "bad binDir empty segment", def: defWith([]PluginBundledBinary{archive(nil)}, []string{"a//b"}, nil), wantErr: "binDir"},
		{name: "bad binDir backslash", def: defWith([]PluginBundledBinary{archive(nil)}, []string{`a\b`}, nil), wantErr: "binDir"},
		{name: "bad binDir empty", def: defWith([]PluginBundledBinary{archive(nil)}, []string{""}, nil), wantErr: "binDir"},
		{name: "bad env key leading digit", def: defWith([]PluginBundledBinary{archive(nil)}, []string{"bin"}, map[string]string{"1BAD": "x"}), wantErr: "not a valid environment variable name"},
		{name: "bad env key dash", def: defWith([]PluginBundledBinary{archive(nil)}, []string{"bin"}, map[string]string{"HAS-DASH": "x"}), wantErr: "not a valid environment variable name"},
		{name: "bad env key empty", def: defWith([]PluginBundledBinary{archive(nil)}, []string{"bin"}, map[string]string{"": "x"}), wantErr: "not a valid environment variable name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := pm.validateBundledBinaries(tc.def)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestStripArchiveComponents(t *testing.T) {
	cases := []struct {
		in    string
		strip int
		want  string
		ok    bool
	}{
		{"nvim-linux-x86_64/bin/nvim", 1, "bin/nvim", true},
		{"nvim-linux-x86_64/bin/nvim", 0, "nvim-linux-x86_64/bin/nvim", true},
		{"nvim-linux-x86_64", 1, "", false},
		{"top/file", 2, "", false},
		{"a/b/c", 2, "c", true},
	}
	for _, tc := range cases {
		got, ok := stripArchiveComponents(tc.in, tc.strip)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("stripArchiveComponents(%q, %d) = (%q, %v), want (%q, %v)", tc.in, tc.strip, got, ok, tc.want, tc.ok)
		}
	}
}

// ---------------------------------------------------------------------------
// Tree-extraction safety (W8's temp checks, ported): symlinks,
// hardlinks, duplicates and strip-dropped files are refused; ".." and
// absolute members can never escape the plugin dir.
// ---------------------------------------------------------------------------

func TestExtractArchiveTree_HappyPathStrip(t *testing.T) {
	pluginDir := t.TempDir()
	tarBytes := buildTarGz(t, []tarMember{
		{name: "nvim-linux-x86_64/bin/nvim", content: "#!/bin/sh\necho fake-nvim\n", mode: 0755},
		{name: "nvim-linux-x86_64/share/nvim/runtime/doc.txt", content: "doc\n"},
		{name: "nvim-linux-x86_64/lib/nvim/parser/c.so", content: "so\n"},
	})
	archivePath := filepath.Join(t.TempDir(), "nvim.tar.gz")
	if err := os.WriteFile(archivePath, tarBytes, 0644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	if err := extractArchiveTree(archivePath, "tar.gz", 1, pluginDir); err != nil {
		t.Fatalf("extractArchiveTree: %v", err)
	}
	for _, rel := range []string{"bin/nvim", "share/nvim/runtime/doc.txt", "lib/nvim/parser/c.so"} {
		if _, err := os.Stat(filepath.Join(pluginDir, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("expected extracted file %s: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(pluginDir, "nvim-linux-x86_64")); !os.IsNotExist(err) {
		t.Fatalf("stripComponents 1 should have removed the top-level dir")
	}
	if info, err := os.Stat(filepath.Join(pluginDir, "bin", "nvim")); err != nil || info.Mode().Perm()&0111 == 0 {
		t.Fatalf("extracted nvim is not executable: %v %v", info, err)
	}
}

func TestExtractArchiveTree_Safety(t *testing.T) {
	writeArchive := func(t *testing.T, members []tarMember) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "a.tar.gz")
		if err := os.WriteFile(p, buildTarGz(t, members), 0644); err != nil {
			t.Fatalf("write archive: %v", err)
		}
		return p
	}
	t.Run("symlink member refused", func(t *testing.T) {
		dir := t.TempDir()
		p := writeArchive(t, []tarMember{
			{name: "pkg/bin/tool", content: "x\n", mode: 0755},
			{name: "pkg/bin/evil", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
		})
		err := extractArchiveTree(p, "tar.gz", 1, dir)
		if err == nil {
			t.Fatalf("symlink member must fail the install")
		}
		if !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("error should say refusing, got: %v", err)
		}
	})
	t.Run("hardlink member refused", func(t *testing.T) {
		dir := t.TempDir()
		p := writeArchive(t, []tarMember{
			{name: "pkg/bin/tool", content: "x\n", mode: 0755},
			{name: "pkg/bin/hard", typeflag: tar.TypeLink, linkname: "pkg/bin/tool"},
		})
		if err := extractArchiveTree(p, "tar.gz", 1, dir); err == nil {
			t.Fatalf("hardlink member must fail the install")
		}
	})
	t.Run("duplicate members after strip refused", func(t *testing.T) {
		dir := t.TempDir()
		p := writeArchive(t, []tarMember{
			{name: "pkg/bin/tool", content: "one\n", mode: 0755},
			{name: "pkg/bin/tool", content: "two\n", mode: 0755},
		})
		if err := extractArchiveTree(p, "tar.gz", 1, dir); err == nil {
			t.Fatalf("two members stripping to the same destination must fail the install")
		}
	})
	t.Run("regular file dropped by strip refused", func(t *testing.T) {
		dir := t.TempDir()
		p := writeArchive(t, []tarMember{
			{name: "pkg", content: "I am the stripped prefix itself\n", mode: 0644},
		})
		err := extractArchiveTree(p, "tar.gz", 1, dir)
		if err == nil {
			t.Fatalf("a regular file the strip would silently drop must fail the install")
		}
		if !strings.Contains(err.Error(), "dropped by stripComponents") {
			t.Fatalf("error should name the strip drop, got: %v", err)
		}
	})
	t.Run("dotdot member refused", func(t *testing.T) {
		dir := t.TempDir()
		parent := filepath.Dir(dir)
		p := writeArchive(t, []tarMember{
			{name: "pkg/../../escape.txt", content: "escaped\n"},
			{name: "pkg/bin/tool", content: "x\n", mode: 0755},
		})
		// A ".." member fails the install outright (safeArchiveName
		// refuses it before cleaning) — it must never be sanitised
		// into the tree at a path the archive never declared.
		err := extractArchiveTree(p, "tar.gz", 0, dir)
		if err == nil {
			t.Fatalf("dotdot member must fail the install")
		}
		if !strings.Contains(err.Error(), "refusing unsafe member") {
			t.Fatalf("error should say refusing unsafe member, got: %v", err)
		}
		if _, err := os.Stat(filepath.Join(parent, "escape.txt")); !os.IsNotExist(err) {
			t.Fatalf("dotdot member escaped the plugin dir")
		}
		if _, err := os.Stat(filepath.Join(dir, "escape.txt")); !os.IsNotExist(err) {
			t.Fatalf("dotdot member must not land inside the plugin dir either")
		}
	})
	t.Run("absolute member refused", func(t *testing.T) {
		dir := t.TempDir()
		p := writeArchive(t, []tarMember{
			{name: "/etc/evil.txt", content: "escaped\n"},
		})
		err := extractArchiveTree(p, "tar.gz", 0, dir)
		if err == nil {
			t.Fatalf("absolute member must fail the install")
		}
		if !strings.Contains(err.Error(), "refusing unsafe member") {
			t.Fatalf("error should say refusing unsafe member, got: %v", err)
		}
		if _, err := os.Stat("/etc/evil.txt"); !os.IsNotExist(err) {
			t.Fatalf("absolute member escaped the plugin dir")
		}
		if _, err := os.Stat(filepath.Join(dir, "etc", "evil.txt")); !os.IsNotExist(err) {
			t.Fatalf("absolute member must not land inside the plugin dir either")
		}
	})
}

func TestExtractArchiveTree_ZipSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: "pkg/bin/evil", Method: zip.Store}
	h.SetMode(os.ModeSymlink | 0777)
	w, err := zw.CreateHeader(h)
	if err != nil {
		t.Fatalf("zip CreateHeader: %v", err)
	}
	_, _ = w.Write([]byte("/etc/passwd"))
	fh, err := zw.Create("pkg/bin/tool")
	if err != nil {
		t.Fatalf("zip Create: %v", err)
	}
	_, _ = io.WriteString(fh, "x\n")
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close: %v", err)
	}
	archivePath := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	if err := extractArchiveTree(archivePath, "zip", 1, dir); err == nil {
		t.Fatalf("zip symlink member must fail the install")
	}
}

// ---------------------------------------------------------------------------
// OS gate: an entry gated away from this host is never downloaded and
// is ignored by verification; a gated-in entry installs normally.
// ---------------------------------------------------------------------------

func TestInstallBundledBinaries_OsesGateSkips(t *testing.T) {
	pm := newBundledTestPM(t)
	if pm.osFamily != "debian" {
		t.Skipf("this test needs a debian host, this host is %q", pm.osFamily)
	}
	tarBytes := buildTar(t, []tarMember{{name: "bin/tool", content: "#!/bin/sh\necho tool\n", mode: 0755}})
	handler := &countingServer{files: map[string][]byte{"/tool.tar": tarBytes}}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	gatedOut := PluginDefinition{
		ID: "test-gated",
		Binaries: []PluginBundledBinary{{
			Kind: "archive", Name: "tool", SHA256: sha256HexBytes(tarBytes),
			URL: srv.URL + "/tool.tar", Format: "tar", PathInArchive: "bin/tool",
			OSes: []string{"alpine"},
		}},
		BinDirs: []string{"bin"},
	}
	if err := pm.validateBundledBinaries(gatedOut); err != nil {
		t.Fatalf("validate gated-out def: %v", err)
	}
	if err := pm.installBundledBinaries(gatedOut); err != nil {
		t.Fatalf("install of a fully gated-out plugin: %v", err)
	}
	if got := handler.hitCount(); got != 0 {
		t.Fatalf("gated-out entry must never be downloaded (0 hits), got %d", got)
	}
	pluginDir, _ := pm.pluginDir("test-gated")
	if _, err := os.Stat(filepath.Join(pluginDir, "bin", "tool")); !os.IsNotExist(err) {
		t.Fatalf("gated-out entry must not be installed")
	}
	// Verification of a fully gated-out plugin is trivially true.
	if err := pm.verifyBundledBinaries(gatedOut); err != nil {
		t.Fatalf("verify of a fully gated-out plugin should pass trivially: %v", err)
	}
	if err := pm.ensureBundledBinaries(gatedOut); err != nil {
		t.Fatalf("ensure of a fully gated-out plugin: %v", err)
	}
	if got := handler.hitCount(); got != 0 {
		t.Fatalf("ensure of a gated-out plugin must not hit the network, got %d hits", got)
	}

	gatedIn := PluginDefinition{
		ID: "test-gated-in",
		Binaries: []PluginBundledBinary{{
			Kind: "archive", Name: "tool", SHA256: sha256HexBytes(tarBytes),
			URL: srv.URL + "/tool.tar", Format: "tar", PathInArchive: "bin/tool",
			OSes: []string{"debian"},
		}},
		BinDirs: []string{"bin"},
	}
	if err := pm.installBundledBinaries(gatedIn); err != nil {
		t.Fatalf("install of a gated-in entry: %v", err)
	}
	if got := handler.hitCount(); got != 1 {
		t.Fatalf("gated-in entry should download exactly once, got %d hits", got)
	}
	inDir, _ := pm.pluginDir("test-gated-in")
	if _, err := os.Stat(filepath.Join(inDir, "bin", "tool")); err != nil {
		t.Fatalf("gated-in entry should be installed: %v", err)
	}
}

// debianPoolURL: the pool path derives from the *source* package
// (libgccjit0 is built from gcc-14) and the epoch is dropped from
// the filename.
func TestDebianPoolURL(t *testing.T) {
	cases := []struct {
		b    PluginBundledBinary
		want string
	}{
		{
			PluginBundledBinary{Name: "emacs-nox", Package: "emacs-nox", Source: "emacs", Version: "1:30.1+1-6+deb13u1", Arch: "amd64"},
			"http://deb.debian.org/debian/pool/main/e/emacs/emacs-nox_30.1+1-6+deb13u1_amd64.deb",
		},
		{
			PluginBundledBinary{Name: "libgccjit0", Package: "libgccjit0", Source: "gcc-14", Version: "14.2.0-19", Arch: "amd64"},
			"http://deb.debian.org/debian/pool/main/g/gcc-14/libgccjit0_14.2.0-19_amd64.deb",
		},
		{
			PluginBundledBinary{Name: "libisl23", Package: "libisl23", Source: "isl", Version: "0.27-1", Arch: "amd64"},
			"http://deb.debian.org/debian/pool/main/i/isl/libisl23_0.27-1_amd64.deb",
		},
		{
			// lib* sources use the "libX" pool directory.
			PluginBundledBinary{Name: "libasound2t64", Package: "libasound2t64", Source: "alsa-lib", Version: "1.2.14-1+deb13u1", Arch: "amd64"},
			"http://deb.debian.org/debian/pool/main/a/alsa-lib/libasound2t64_1.2.14-1+deb13u1_amd64.deb",
		},
		{
			// No Source: the binary package name is the source, so
			// the pool directory is emacs-common (the real
			// cli-emacs entry sets Source "emacs" to get /e/emacs/).
			PluginBundledBinary{Name: "emacs-common", Package: "emacs-common", Version: "1:30.1+1-6+deb13u1", Arch: "all"},
			"http://deb.debian.org/debian/pool/main/e/emacs-common/emacs-common_30.1+1-6+deb13u1_all.deb",
		},
	}
	for _, tc := range cases {
		got, err := debianPoolURL(tc.b)
		if err != nil {
			t.Fatalf("debianPoolURL(%q): %v", tc.b.Name, err)
		}
		if got != tc.want {
			t.Fatalf("debianPoolURL(%q) = %q, want %q", tc.b.Name, got, tc.want)
		}
	}
	if _, err := debianPoolURL(PluginBundledBinary{Name: "bad", Package: "bad", Version: "1:", Arch: "amd64"}); err == nil {
		t.Fatalf("debianPoolURL should fail on a version that is only an epoch")
	}
}
