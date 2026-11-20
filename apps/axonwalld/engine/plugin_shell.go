// Package engine — plugin shell PATH integration (plugin_shell.go).
//
// # DESIGN
//
// A plugin that declares BinDirs (e.g. cli-emacs with BinDirs
// ["usr/bin"]) owns binaries under its per-plugin directory,
// <baseDataDir>/<plugin-id>/. The daemon resolves those binaries
// through PluginEnv/CommandForPlugin (plugins.go), but interactive
// shells need the same directories on PATH. This file is the shell
// side of that: it writes one small snippet per plugin and lets the
// shells source it.
//
// Placement: ONE FILE PER PLUGIN, never a shared file that every
// plugin edits:
//
//   - POSIX sh/bash login shells: /etc/profile.d/axonwall-plugin-<id>.sh
//   - zsh: /etc/zsh/axonwall-plugin-<id>.zsh, sourced from a
//     marker-delimited block this file maintains in /etc/zsh/zshenv
//     (every zsh invocation) and /etc/zsh/zlogin (login shells; see
//     the ZSH section below)
//
// One file per plugin makes add/remove exact: enabling writes the
// file, disabling/uninstalling deletes it, and no plugin's lifecycle
// ever rewrites another plugin's lines. Snippet writes are atomic
// (temp file in the same directory + rename) and idempotent
// (re-running writes the same bytes; the write is skipped entirely
// when the file already has that content).
//
// The snippet itself is POSIX sh (no bashisms: no [[ ]], no arrays,
// no function-local tricks), so the same text is valid in sh, dash,
// bash, and zsh. Every directory is prepended only if it exists
// ([ -d ... ]) and only if it is not already on PATH (a
// case ":$PATH:" match), so repeated sourcing is a no-op and a
// plugin whose tree was never extracted adds nothing.
//
// # ZSH — CONCLUSION AND EVIDENCE
//
// zsh login shells do NOT read /etc/profile or /etc/profile.d, so
// the profile.d snippet alone leaves zsh without the plugin PATH.
// The repo provisions no zsh startup file that would pick it up:
//   - provisionWorkstationConfigs (plugins.go) writes
//     /etc/zsh/axonwall.zsh, /etc/zsh/zshenv, /etc/skel/.zshrc and
//     /root/.zshrc. It writes NO /etc/zsh/zshrc and NO
//     /etc/zsh/zprofile, and grep finds no /etc/profile.d reference
//     anywhere in the repo.
//   - /etc/zsh/axonwall.zsh is sourced by ~/.zshrc (interactive
//     shells only) and hard-resets PATH:
//     `export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`
//     (plugins.go, in the zshConf literal). That reset runs BEFORE
//     the workstation.disabled early-return, so it wipes any PATH
//     added earlier in the same shell — including anything a
//     zshenv snippet added.
//   - /etc/zsh/zshenv is unconditionally OVERWRITTEN by
//     provisionWorkstationConfigs with a single STARSHIP_CONFIG line
//     (plugins.go: `_ = os.WriteFile("/etc/zsh/zshenv", ...)`).
//     Anything this file adds to zshenv is therefore wiped on the
//     next cli-workstation enable/reconfigure, and restored on the
//     next Sync/Rebuild — see the hook spec for the Rebuild call
//     that heals it.
//
// So zsh needs separate handling, implemented here as per-plugin
// .zsh files plus a marker-delimited source block (BEGIN/END
// axonwall-plugin-paths) maintained in BOTH /etc/zsh/zshenv and
// /etc/zsh/zlogin:
//
//   - zshenv is read by EVERY zsh invocation (login, interactive,
//     non-interactive, scripts). It is the only file that covers
//     `zsh -c` and non-interactive use. It runs BEFORE zshrc, so
//     for interactive zsh its PATH addition is later wiped by the
//     axonwall.zsh reset (above) — zshenv alone is NOT enough for
//     interactive zsh.
//   - zlogin is read by LOGIN shells AFTER zshrc, i.e. after the
//     axonwall.zsh reset, so it re-applies the plugin PATH for
//     login interactive zsh — the SSH-login case.
//   - /etc/zsh/zprofile is deliberately NOT used: it runs before
//     zshrc, so the axonwall.zsh reset would wipe it just like
//     zshenv, and it adds nothing zshenv+zlogin do not cover.
//
// The loader block preserves every other line in zshenv/zlogin: it
// replaces only the text between its own BEGIN/END markers (or
// appends the block if absent) and removes the block when no plugin
// snippet remains. If zsh is not installed (/etc/zsh does not
// exist) the whole zsh side is skipped silently — there is no zsh
// to read it — and the profile.d side still applies.
//
// # SOFT-FAIL CONTRACT
//
// SyncPluginShellPaths / RemovePluginShellPath /
// RebuildPluginShellPaths return a descriptive error when a snippet
// directory cannot be written (daemon not running as root, /etc
// read-only, or a test baseDataDir) — but the CALLER MUST treat that
// error as soft-fail: log it and continue, NEVER fail the
// enable/install/disable/uninstall itself. A shell PATH snippet is
// a convenience for interactive shells; the plugin's binaries still
// work through the daemon (PluginEnv/CommandForPlugin), and a
// failed snippet must never turn a successful install into a
// reported failure, nor leave a disabled plugin's snippet behind
// unreported — removal failures are likewise logged, not fatal.
// These functions never panic, never write outside the snippet
// directories (profile.d / /etc/zsh), and never follow a pluginID
// that fails the ^[a-z0-9-]+$ check (see pluginShellIDPattern).
//
// COVERAGE — WHAT IS AND IS NOT COVERED
//
//	Covered:
//	- sh/bash LOGIN shells (ssh login, `bash -l`, console login)
//	  via /etc/profile.d, sourced by /etc/profile on Debian.
//	- zsh non-interactive / `zsh -c` via the zshenv loader block.
//	- zsh LOGIN interactive shells (the SSH-login case) via the
//	  zlogin loader block, which runs after the axonwall.zsh PATH
//	  reset.
//	- Daemon invocations are NOT this file's job: W2's
//	  PluginEnv/CommandForPlugin covers those.
//
//	NOT covered (stated plainly):
//	- bash interactive NON-LOGIN shells: bash reads ~/.bashrc, not
//	  /etc/profile.d. Covering them would need a loader in
//	  /etc/bash.bashrc (Debian, distro-owned) or /etc/skel/.bashrc;
//	  not implemented here.
//	- zsh interactive NON-LOGIN shells (e.g. tmux panes — tmux.conf
//	  sets default-shell /usr/bin/zsh — or `zsh` started from
//	  another shell) while cli-workstation is enabled: no system
//	  zsh file runs after ~/.zshrc, and axonwall.zsh hard-resets
//	  PATH there. The fix belongs in plugins.go, not here: make
//	  /etc/zsh/axonwall.zsh preserve the existing PATH instead of
//	  overwriting it (prepend the system dirs only if missing), or
//	  have it source /etc/zsh/axonwall-plugin-*.zsh at its end.
//	  Until then, non-login interactive zsh does not get plugin
//	  binaries on PATH; login zsh and `zsh -c` do.
//	- non-interactive sh (`sh -c ...`): reads no profile files.
//	- Already-running shells: snippets apply to shells started
//	  after the write; a running shell must re-source or restart.
//	- Plugin Env vars (e.g. cli-emacs EMACSDATA) are NOT exported
//	  to shells by this file — PATH only. Env is daemon-side
//	  (PluginEnv). Exporting Env to shells would mean emitting
//	  `export KEY=value` lines with ${PLUGIN_DIR} expanded; that is
//	  a follow-up, not done here.
//
// # STANDALONE NOTE
//
// This file intentionally duplicates three tiny pieces of
// plugins.go rather than calling them: the plugin-ID pattern
// (pluginIDPattern), the BinDir guard (validBinDir), and the plugin
// directory join (pm.pluginDir). That keeps plugin_shell.go
// compilable against HEAD with no other new code, and independent
// of the parallel daemon-runtime work landing in plugins.go. The
// duplicates are named pluginShell* so they cannot collide; the
// coordinator may unify them onto pm.pluginDir/validBinDir once
// that work is committed, but must not do so silently — the guards
// must stay identical.
//
// # TESTABILITY
//
// pluginShellProfileDir and pluginShellZshDir are package-level
// variables so tests can point them at temp dirs; nothing in this
// file hardcodes /etc/profile.d or /etc/zsh except their default
// values. pluginShellSnippet is pure text — tests can assert on the
// exact snippet without touching /etc.
package engine

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// pluginShellProfileDir is the directory holding one
// axonwall-plugin-<id>.sh file per plugin, sourced by login
// sh/bash via /etc/profile.d. Overridable for tests.
var pluginShellProfileDir = "/etc/profile.d"

// pluginShellZshDir is the directory holding one
// axonwall-plugin-<id>.zsh file per plugin, plus the zshenv and
// zlogin files that source them. Overridable for tests; the zshenv
// and zlogin paths below are derived from it.
var pluginShellZshDir = "/etc/zsh"

const (
	pluginShellFilePrefix = "axonwall-plugin-"
	pluginShellShSuffix   = ".sh"
	pluginShellZshSuffix  = ".zsh"
)

// pluginShellIDPattern is the plugin-ID guard: lowercase letters,
// digits and hyphens only. It intentionally duplicates plugins.go's
// pluginIDPattern (see the STANDALONE NOTE in the header) so this
// file never joins an unvalidated id onto a directory — an id
// containing "/" or ".." must be refused, never cleaned up silently.
var pluginShellIDPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// pluginShellZshLoaderBegin/End delimit the block this file owns
// inside /etc/zsh/zshenv and /etc/zsh/zlogin. Everything outside the
// markers is preserved verbatim.
const (
	pluginShellZshLoaderBegin = "# BEGIN axonwall-plugin-paths (managed by axonwalld; do not edit)"
	pluginShellZshLoaderEnd   = "# END axonwall-plugin-paths"
)

// SyncPluginShellPaths (re)writes the shell PATH snippets for one
// plugin when it is enabled/installed.
//
//   - If the plugin is disabled (pm.IsPluginEnabled reports false),
//     unknown, declares no BinDirs, or declares only invalid
//     BinDirs, the snippets are REMOVED instead of written, so a
//     disabled plugin never contributes PATH entries.
//   - Otherwise one snippet is written per shell family (profile.d
//     for sh/bash login shells, /etc/zsh for zsh — see the header).
//
// SOFT-FAIL: on any write error this returns a descriptive error
// and the caller MUST log it and continue — it must never fail the
// enable/install itself (see the header contract). A nil pm, an
// empty baseDataDir, or an invalid pluginID is also an error.
func SyncPluginShellPaths(pm *PluginManager, pluginID string) error {
	if !validPluginShellID(pluginID) {
		return fmt.Errorf("invalid plugin id %q: must match ^[a-z0-9-]+$", pluginID)
	}
	if pm == nil {
		return errors.New("cannot sync plugin shell PATH: nil PluginManager")
	}
	// Disabled means no snippet: remove any stale one rather than
	// writing PATH entries for a plugin that is off. This also
	// covers the uninstall path if the hook calls Sync after the
	// state change instead of Remove.
	if !pm.IsPluginEnabled(pluginID) {
		return RemovePluginShellPath(pm, pluginID)
	}
	dirs, err := resolvePluginShellBinDirs(pm, pluginID)
	if err != nil {
		return err
	}
	if len(dirs) == 0 {
		// Unknown plugin, or no (valid) BinDirs: nothing to put
		// on PATH; make sure no stale snippet survives.
		return RemovePluginShellPath(pm, pluginID)
	}
	if err := writePluginShellFile(pluginShellProfilePath(pluginID), pluginShellSnippet(pluginID, dirs)); err != nil {
		return fmt.Errorf("write shell PATH snippet for plugin %q in %s: %w", pluginID, pluginShellProfileDir, err)
	}
	if err := syncPluginShellZshSide(pluginID, dirs); err != nil {
		return err
	}
	return nil
}

// RemovePluginShellPath removes the shell PATH snippets for one
// plugin (disable/uninstall). A missing snippet file is not an
// error. pm may be nil — removal needs no manager state — but the
// pluginID is still validated before any path is touched.
// SOFT-FAIL: callers log a returned error and continue.
func RemovePluginShellPath(pm *PluginManager, pluginID string) error {
	// pm is intentionally unused: removal is driven by the id alone
	// so it works even when the plugin is unknown or the manager is
	// gone. Keep the parameter so the lifecycle hooks read
	// symmetrically with SyncPluginShellPaths.
	_ = pm
	if !validPluginShellID(pluginID) {
		return fmt.Errorf("invalid plugin id %q: must match ^[a-z0-9-]+$", pluginID)
	}
	var errs []error
	if err := removeFileIfExists(pluginShellProfilePath(pluginID)); err != nil {
		errs = append(errs, fmt.Errorf("remove shell PATH snippet for plugin %q in %s: %w", pluginID, pluginShellProfileDir, err))
	}
	if err := removeFileIfExists(pluginShellZshPath(pluginID)); err != nil {
		errs = append(errs, fmt.Errorf("remove zsh PATH snippet for plugin %q in %s: %w", pluginID, pluginShellZshDir, err))
	}
	// The zsh loader block must no longer source the removed file.
	if err := refreshPluginShellZshLoaders(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// RebuildPluginShellPaths regenerates snippets for ALL currently
// enabled plugins that declare BinDirs (daemon startup / after
// state changes) and removes snippets for any plugin that is
// disabled or no longer declares BinDirs (stale-snippet cleanup,
// including files for plugin ids that no longer exist at all).
// Errors for individual plugins are collected and joined — one
// unwritable snippet must not stop the rest — and the joined error
// is SOFT-FAIL for the caller (log and continue; see the header).
func RebuildPluginShellPaths(pm *PluginManager) error {
	if pm == nil {
		return errors.New("cannot rebuild plugin shell PATHs: nil PluginManager")
	}
	var errs []error
	wanted := make(map[string]bool)
	for _, def := range GetExtensionPluginDefinitions() {
		if !validPluginShellID(def.ID) || len(def.BinDirs) == 0 {
			continue
		}
		if !pm.IsPluginEnabled(def.ID) {
			continue
		}
		wanted[def.ID] = true
		if err := SyncPluginShellPaths(pm, def.ID); err != nil {
			errs = append(errs, fmt.Errorf("rebuild shell PATH for plugin %q: %w", def.ID, err))
		}
	}
	// Stale-snippet cleanup: any managed file whose plugin is not
	// in the wanted set goes, in both snippet directories. This
	// covers disabled plugins, plugins that dropped their BinDirs,
	// and files left behind for ids that no longer exist.
	for _, dir := range []string{pluginShellProfileDir, pluginShellZshDir} {
		suffix := pluginShellShSuffix
		if dir == pluginShellZshDir {
			suffix = pluginShellZshSuffix
		}
		ids, err := listPluginShellIDs(dir, suffix)
		if err != nil {
			errs = append(errs, fmt.Errorf("list plugin shell snippets in %s: %w", dir, err))
			continue
		}
		for _, id := range ids {
			if wanted[id] {
				continue
			}
			if err := RemovePluginShellPath(pm, id); err != nil {
				errs = append(errs, fmt.Errorf("remove stale shell PATH snippet for plugin %q: %w", id, err))
			}
		}
	}
	// The stale sweep may have removed zsh files directly; make
	// sure the loader blocks reflect what is actually on disk.
	if err := refreshPluginShellZshLoaders(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// pluginShellSnippet returns the exact POSIX sh snippet text for one
// plugin. binDirs must already be ABSOLUTE directories (the caller
// resolves them against the plugin dir); the builder does no path
// resolution, so tests can assert on the text without touching /etc.
// The snippet prepends each directory to PATH only if it exists and
// is not already on PATH. Dirs are emitted in reverse listed order
// so the first-listed dir ends up first on PATH (each prepend puts
// its directory ahead of the previous one).
func pluginShellSnippet(pluginID string, binDirs []string) string {
	return pluginShellSnippetWithNote(pluginID, binDirs,
		"Sourced by login sh/bash via /etc/profile.d (see /etc/profile).")
}

// pluginShellZshSnippet is the zsh counterpart of
// pluginShellSnippet: the same POSIX-compatible body (valid zsh —
// no bashisms), with a header noting it is sourced from the loader
// blocks in /etc/zsh/zshenv and /etc/zsh/zlogin.
func pluginShellZshSnippet(pluginID string, binDirs []string) string {
	return pluginShellSnippetWithNote(pluginID, binDirs,
		"Sourced for zsh from /etc/zsh/zshenv (all invocations) and /etc/zsh/zlogin (login shells).")
}

func pluginShellSnippetWithNote(pluginID string, binDirs []string, sourceNote string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Axonwall plugin %q: bundled-binary PATH entries.\n", pluginID)
	b.WriteString("# Managed by axonwalld (engine/plugin_shell.go). Do not edit by hand:\n")
	b.WriteString("# this file is rewritten on plugin enable/install and removed on\n")
	b.WriteString("# plugin disable/uninstall.\n")
	fmt.Fprintf(&b, "# %s\n", sourceNote)
	b.WriteString("# Each directory is prepended to PATH only if it exists and is not\n")
	b.WriteString("# already on PATH, so sourcing this file repeatedly is a no-op.\n")
	if len(binDirs) == 0 {
		return b.String()
	}
	// Reverse listed order: the first-listed dir must end up first
	// on PATH, and each prepend puts its dir ahead of the previous.
	b.WriteString("for _axonwall_plugin_dir in")
	for i := len(binDirs) - 1; i >= 0; i-- {
		fmt.Fprintf(&b, " %s", shellSingleQuote(binDirs[i]))
	}
	b.WriteString("; do\n")
	b.WriteString("  if [ -d \"$_axonwall_plugin_dir\" ]; then\n")
	b.WriteString("    case \":$PATH:\" in\n")
	b.WriteString("      *\":$_axonwall_plugin_dir:\"*) ;;\n")
	b.WriteString("      *) PATH=\"$_axonwall_plugin_dir${PATH:+:$PATH}\" ;;\n")
	b.WriteString("    esac\n")
	b.WriteString("  fi\n")
	b.WriteString("done\n")
	b.WriteString("unset _axonwall_plugin_dir\n")
	b.WriteString("export PATH\n")
	return b.String()
}

// validPluginShellID reports whether id is a safe plugin id. It
// intentionally duplicates plugins.go's pluginIDPattern (see the
// header STANDALONE NOTE) so this file stands alone.
func validPluginShellID(id string) bool {
	return pluginShellIDPattern.MatchString(id)
}

// validPluginShellBinDir reports whether a BinDirs entry is safe to
// join onto a plugin dir: relative, non-empty, no ".." segment, no
// backslash, no empty segment. It intentionally duplicates
// plugins.go's validBinDir (see the header STANDALONE NOTE); the
// daemon's install-time validation is the authoritative check and
// this is the shell side's second look, so a bad entry is skipped
// here rather than ever reaching a snippet.
func validPluginShellBinDir(dir string) bool {
	if dir == "" || filepath.IsAbs(dir) || strings.Contains(dir, "\\") {
		return false
	}
	for _, seg := range strings.Split(filepath.ToSlash(dir), "/") {
		if seg == ".." || seg == "" {
			return false
		}
	}
	return true
}

// pluginShellDir returns the per-plugin directory,
// <baseDataDir>/<pluginID>/, after validating the id. It mirrors
// pm.pluginDir in plugins.go (see the header STANDALONE NOTE).
func pluginShellDir(pm *PluginManager, pluginID string) (string, error) {
	if !validPluginShellID(pluginID) {
		return "", fmt.Errorf("invalid plugin id %q: must match ^[a-z0-9-]+$", pluginID)
	}
	if pm == nil || pm.baseDataDir == "" {
		return "", errors.New("plugin data directory is not configured (nil PluginManager or empty baseDataDir)")
	}
	return filepath.Join(pm.baseDataDir, pluginID), nil
}

// resolvePluginShellBinDirs returns the plugin's BinDirs as absolute
// paths under its plugin dir, in declared order. Invalid entries
// are skipped with a warning, never written into a snippet; an
// unknown plugin yields an empty slice (and no error) so the caller
// removes any stale snippet for it.
func resolvePluginShellBinDirs(pm *PluginManager, pluginID string) ([]string, error) {
	def, ok := findExtensionPluginDefinition(pluginID)
	if !ok {
		return nil, nil
	}
	if len(def.BinDirs) == 0 {
		return nil, nil
	}
	dir, err := pluginShellDir(pm, pluginID)
	if err != nil {
		return nil, err
	}
	dirs := make([]string, 0, len(def.BinDirs))
	for _, binDir := range def.BinDirs {
		if !validPluginShellBinDir(binDir) {
			log.Printf("[PluginManager] Warning: skipping invalid binDir %q for plugin %s in shell PATH snippet", binDir, pluginID)
			continue
		}
		dirs = append(dirs, filepath.Join(dir, filepath.FromSlash(binDir)))
	}
	return dirs, nil
}

func pluginShellProfilePath(pluginID string) string {
	return filepath.Join(pluginShellProfileDir, pluginShellFilePrefix+pluginID+pluginShellShSuffix)
}

func pluginShellZshPath(pluginID string) string {
	return filepath.Join(pluginShellZshDir, pluginShellFilePrefix+pluginID+pluginShellZshSuffix)
}

func pluginShellZshenvPath() string {
	return filepath.Join(pluginShellZshDir, "zshenv")
}

func pluginShellZloginPath() string {
	return filepath.Join(pluginShellZshDir, "zlogin")
}

// shellSingleQuote quotes s for POSIX sh/zsh as a single-quoted
// word, escaping embedded single quotes. Paths come from
// filepath.Join of a validated id and validated BinDirs, so they
// are normally plain — this is defence in depth (a baseDataDir
// with a space or a quote must not break the snippet).
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// writePluginShellFile writes content to path atomically with mode
// 0644, creating the parent directory if needed. It is a no-op when
// the file already holds exactly content, so re-running a sync does
// not churn mtime. The atomic write itself is vigilante.go's
// writeFileAtomic (temp file in the same directory + rename), which
// additionally REFUSES a pre-existing symlink at the destination
// instead of following it — a symlink planted at a snippet path
// must never redirect a write outside the snippet directory.
func writePluginShellFile(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	if existing, err := os.ReadFile(path); err == nil && string(existing) == content {
		return nil
	}
	if err := writeFileAtomic(atomicFileWrite{path: path, content: content, perm: 0644}); err != nil {
		return err
	}
	return nil
}

// listPluginShellIDs returns the plugin ids of managed snippet
// files in dir with the given suffix, sorted. Files that do not
// match the managed name pattern (or whose id fails validation)
// are ignored, never removed. A missing directory yields an empty
// list, not an error.
func listPluginShellIDs(dir, suffix string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read directory %s: %w", dir, err)
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, pluginShellFilePrefix) || !strings.HasSuffix(name, suffix) {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, pluginShellFilePrefix), suffix)
		if !validPluginShellID(id) {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// syncPluginShellZshSide writes the zsh snippet for one plugin and
// refreshes the zshenv/zlogin loader blocks to match the files on
// disk. If the zsh directory does not exist (zsh not installed)
// the whole zsh side is skipped silently — there is no zsh to read
// it — and the profile.d side written by the caller still applies.
func syncPluginShellZshSide(pluginID string, dirs []string) error {
	if _, err := os.Stat(pluginShellZshDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat zsh directory %s: %w", pluginShellZshDir, err)
	}
	if err := writePluginShellFile(pluginShellZshPath(pluginID), pluginShellZshSnippet(pluginID, dirs)); err != nil {
		return fmt.Errorf("write zsh PATH snippet for plugin %q in %s: %w", pluginID, pluginShellZshDir, err)
	}
	return refreshPluginShellZshLoaders()
}

// refreshPluginShellZshLoaders rebuilds the loader blocks in
// /etc/zsh/zshenv and /etc/zsh/zlogin from the per-plugin .zsh
// files actually present on disk, so the blocks never source a
// file that was removed. Skipped silently when the zsh directory
// does not exist.
func refreshPluginShellZshLoaders() error {
	if _, err := os.Stat(pluginShellZshDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat zsh directory %s: %w", pluginShellZshDir, err)
	}
	ids, err := listPluginShellIDs(pluginShellZshDir, pluginShellZshSuffix)
	if err != nil {
		return err
	}
	var errs []error
	for _, path := range []string{pluginShellZshenvPath(), pluginShellZloginPath()} {
		if err := syncPluginShellZshLoaderFile(path, ids); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// syncPluginShellZshLoaderFile maintains the marker-delimited
// loader block in one zsh startup file (zshenv or zlogin): it
// replaces only the text between the BEGIN/END markers (or appends
// the block when absent) and preserves every other line verbatim.
// With no plugin ids left the block is removed; if that leaves the
// file empty the file itself is removed. A file whose BEGIN marker
// is present without its END marker is left untouched and reported
// as an error rather than rewritten on a guess.
func syncPluginShellZshLoaderFile(path string, ids []string) error {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read zsh startup file %s: %w", path, err)
	}
	content := string(data)
	begin := strings.Index(content, pluginShellZshLoaderBegin)
	end := strings.Index(content, pluginShellZshLoaderEnd)
	if begin >= 0 && end < 0 {
		return fmt.Errorf("zsh startup file %s has a %s marker without its END marker; refusing to rewrite it", path, pluginShellZshLoaderBegin)
	}
	if end >= 0 && begin < 0 {
		return fmt.Errorf("zsh startup file %s has a %s marker without its BEGIN marker; refusing to rewrite it", path, pluginShellZshLoaderEnd)
	}
	var head, tail string
	if begin >= 0 {
		head = content[:begin]
		tail = content[end+len(pluginShellZshLoaderEnd):]
	} else {
		head = content
		tail = ""
	}
	var b strings.Builder
	b.WriteString(head)
	if len(ids) > 0 {
		if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
			b.WriteString("\n")
		}
		b.WriteString(pluginShellZshLoaderBegin + "\n")
		b.WriteString("# zsh reads this file on every invocation; each line sources one\n")
		b.WriteString("# plugin's PATH snippet if it still exists.\n")
		for _, id := range ids {
			fmt.Fprintf(&b, "[ -f %s ] && . %s\n", shellSingleQuote(pluginShellZshPath(id)), shellSingleQuote(pluginShellZshPath(id)))
		}
		b.WriteString(pluginShellZshLoaderEnd + "\n")
	}
	b.WriteString(tail)
	newContent := b.String()
	if strings.TrimSpace(newContent) == "" {
		// Nothing left but our (now removed) block: drop the file
		// rather than leaving an empty startup file behind.
		if err := removeFileIfExists(path); err != nil {
			return err
		}
		return nil
	}
	if err := writePluginShellFile(path, newContent); err != nil {
		return fmt.Errorf("write zsh startup file %s: %w", path, err)
	}
	return nil
}
