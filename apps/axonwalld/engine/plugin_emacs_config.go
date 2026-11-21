package engine

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// cli-emacs install-time files: the bin/emacs launcher and the
// minimal config/init.el. Both are generated locally from the
// constants below (never downloaded), so they are NOT part of
// bundled.json — verify checks bin/emacs exists and is executable,
// but does not hash it. Layout inside the plugin dir:
//
//	<plugindir>/
//	  bin/emacs            launcher (execs usr/bin/emacs-nox)
//	  config/init.el       minimal curated init.el
//	  usr/bin/emacs-nox    the real extracted binary (from the .deb)
//	  usr/bin/emacs-nox.pdmp -> ../libexec/.../emacs-<fp>.pdmp
//	                         (symlink, see below — the pdmp lookup)
//	  usr/lib/x86_64-linux-gnu/  bundled lib .debs (libgccjit0 et al.)
//	  usr/share/emacs/30.1/      the Lisp tree (EMACSDATA = .../etc)
//	  usr/libexec/emacs/30.1/x86_64-linux-gnu/  hexl, rcs2log, pdmp
//
// The launcher resolves the plugin dir from its own path, so the
// plugin dir can move (state-dir override, restore) without
// rewriting it. It passes through all arguments ("$@") and execs
// (does not fork). It sets four environment variables, all
// verified live 2026-11-20 against a real extraction — every one
// is load-bearing, and a relocated Debian emacs-nox does NOT work
// without them (the compiled-in /usr paths do not exist on the
// appliance, and argv[0] relocation does not redirect them):
//
//   EMACSDATA=<plugindir>/usr/share/emacs/30.1/etc — data-directory
//     IS the etc dir (GNU Emacs FAQ); the startup charsets check
//     looks for <EMACSDATA>/charsets. Pointing it at the version
//     dir fails startup ("Emacs will not function correctly without
//     the character map files").
//   EMACSPATH=<plugindir>/usr/libexec/emacs/30.1/x86_64-linux-gnu
//     — the arch-dependent dir (hexl, rcs2log). NOTE: it does NOT
//     redirect the pdmp lookup (verified by strace): the pdmp is
//     only found next to the binary or at the compiled-in libexec
//     path, hence the usr/bin/emacs-nox.pdmp symlink below. Without
//     the pdmp, emacs runs undumped (temacs loadup) and is broken.
//   EMACSLOADPATH=<plugindir>/usr/share/emacs/30.1/lisp:
//     <plugindir>/usr/share/emacs/site-lisp — the dumped load-path
//     still names compiled-in /usr/share/emacs/30.1/lisp, so
//     without this emacs cannot find simple.el or any mode.
//     Startup adds the lisp subdirectories automatically.
//   LD_LIBRARY_PATH=<plugindir>/usr/lib/x86_64-linux-gnu — the
//     loader does not search the bundled lib dir by default. The
//     shell PATH snippets carry PATH only, not Env, so the launcher
//     must set all four itself for interactive shells (daemon
//     invocations get the same values from the plugin Env map).

const emacsPluginID = "cli-emacs"

// emacsBundledBinaryRelPath is the real extracted binary's path
// inside the plugin dir. Verified from the research notes: the
// emacs-nox .deb extracts usr/bin/emacs-nox — there is NO
// usr/bin/emacs (dpkg-deb -x runs no maintainer scripts, so the
// update-alternatives /usr/bin/emacs symlink is never created).
// The bin/emacs launcher execs this file.
const emacsBundledBinaryRelPath = "usr/bin/emacs-nox"

// emacsBundledLibDirRelPath is where the bundled lib .debs land
// (libgccjit0, libisl23, libmpc3, libmpfr6, libasound2t64,
// liblcms2-2) — it must be on LD_LIBRARY_PATH at runtime.
const emacsBundledLibDirRelPath = "usr/lib/x86_64-linux-gnu"

// emacsRelocationEnvScript returns the four shell export lines that
// point a relocated Debian emacs-nox tree at its data and libraries.
// dirExpr is a shell expression expanding to the cli-emacs plugin
// dir — "$PLUGIN_DIR" for the cli-emacs launcher itself,
// "$EMACS_PLUGIN_DIR" for the Doom/Spacemacs launchers, which resolve
// the shared tree from the sibling cli-emacs plugin dir. It is the
// single definition of these four exports: the cli-emacs launcher
// below and both Doom/Spacemacs launchers (plugin_emacs_doom_spacemacs.go)
// are built from it, so the values cannot drift apart silently.
func emacsRelocationEnvScript(dirExpr string) string {
	return fmt.Sprintf(`export EMACSDATA="%[1]s/usr/share/emacs/30.1/etc"
export EMACSPATH="%[1]s/usr/libexec/emacs/30.1/x86_64-linux-gnu"
export EMACSLOADPATH="%[1]s/usr/share/emacs/30.1/lisp:%[1]s/usr/share/emacs/site-lisp"
export LD_LIBRARY_PATH="%[1]s/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
`, dirExpr)
}

var emacsLauncherScript = `#!/bin/sh
# cli-emacs launcher — execs the bundled emacs-nox binary with the
# bundled data tree and libraries. Generated at install time by
# axonwalld (plugin_emacs_config.go); do not edit by hand.
# All four variables are load-bearing (see the header comment in
# plugin_emacs_config.go): EMACSDATA is the etc dir, EMACSPATH the
# libexec dir, EMACSLOADPATH the lisp tree, LD_LIBRARY_PATH the
# bundled libs.
PLUGIN_DIR=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BIN="$PLUGIN_DIR/usr/bin/emacs-nox"
if [ ! -x "$BIN" ]; then
  printf 'cli-emacs: bundled binary %s is missing or not executable\n' "$BIN" >&2
  exit 127
fi
` + emacsRelocationEnvScript("$PLUGIN_DIR") + `exec "$BIN" --init-directory "$PLUGIN_DIR/config" "$@"
`

// emacsInitEl is the minimal curated init.el for editing
// /etc/axonwall files. Built-ins only, zero MELPA packages, no
// network at startup, no package.el refresh — every `require` is
// guarded so a missing feature never breaks startup. Tree-sitter
// modes are guarded by treesit-ready-p with non-ts fallbacks: the
// mode code ships in emacs-common, but trixie ships NO grammar
// .so files (no libtree-sitter-json.so / libtree-sitter-yaml.so
// anywhere), so an unguarded *-ts-mode errors on activation.
// Bundling prebuilt grammar .so files is a follow-up (see research
// notes §4c option 2), not done here.
const emacsInitEl = `;;; init.el --- Minimal Axonwall cli-emacs configuration -*- lexical-binding: t -*-
;;; Commentary:
;; Minimal curated Emacs for editing /etc/axonwall configuration
;; files on the appliance.  Built-in packages only — no MELPA, no
;; network at startup, no package.el refresh.  Every require is
;; guarded so a missing feature never breaks startup.
;;
;; File formats covered (all under /etc/axonwall):
;;   YAML  — firewall.yaml, interfaces.yaml, routing.yaml,
;;           system.yaml, virt.yaml, cloud-config.yaml,
;;           vigilante.yaml (and any *.yaml / *.yml)
;;   .env  — admin.env, axonwall.env, controller.env, mfa.env,
;;           k3s-storage.env (KEY=value, shell-like)
;;   Caddyfile — Caddy v2, brace syntax (conf-mode + font-lock)
;;   JSON  — managed/netdev_config.json, managed/virt_config.json,
;;           state.json, slot_versions.json, firewall_config.json,
;;           */ldap.json
;;   TOML  — starship.toml
;;   Lua   — nvim/init.lua (no built-in lua-mode: prog-mode fallback)
;;; Code:

;; No splash screen, no package.el at startup.
(setq inhibit-startup-screen t)
(setq package-enable-at-startup nil)

;; Byte-compiled only — NO native-comp JIT. Verified live
;; 2026-11-20: JIT-compiling new code fails at the link step
;; ("ld: cannot find crtbeginS.o") because the link needs
;; crtbeginS.o from gcc-14 / libgcc-14-dev, which is not bundled
;; (and bundling a compiler toolchain onto the appliance is out of
;; scope). With JIT left on, the first load of any package without
;; a prebuilt .eln would fail loudly in the same way; with it off,
;; emacs runs byte-compiled and deterministic. The prebuilt .eln
;; files for the preloaded libs still load, and
;; native-comp-available-p still reports t — this only stops
;; *new* JIT compilation.
(when (boundp 'native-comp-jit-compilation)
  (setq native-comp-jit-compilation nil))

;; Which-key: discoverable keybindings (built in since Emacs 30).
(when (require 'which-key nil t)
  (which-key-mode 1))

;; In-buffer completion preview (built in since Emacs 30.1) —
;; the minimal replacement for corfu/company, no MELPA needed.
(when (fboundp 'global-completion-preview-mode)
  (global-completion-preview-mode 1))

;; YAML — firewall.yaml, interfaces.yaml, routing.yaml,
;; system.yaml, virt.yaml, cloud-config.yaml, vigilante.yaml.
;; yaml-ts-mode when a YAML tree-sitter grammar is available,
;; conf-mode otherwise (no grammar .so ships in trixie).
(if (and (fboundp 'treesit-ready-p) (treesit-ready-p 'yaml))
    (add-to-list 'auto-mode-alist '("\\.ya?ml\\'" . yaml-ts-mode))
  (add-to-list 'auto-mode-alist '("\\.ya?ml\\'" . conf-mode)))

;; JSON — managed/*.json, state.json, slot_versions.json,
;; firewall_config.json, */ldap.json.  json-ts-mode when a JSON
;; grammar is available, js-json-mode (built in) otherwise.
(if (and (fboundp 'treesit-ready-p) (treesit-ready-p 'json))
    (add-to-list 'auto-mode-alist '("\\.json\\'" . json-ts-mode))
  (add-to-list 'auto-mode-alist '("\\.json\\'" . js-json-mode)))

;; TOML — starship.toml.  toml-ts-mode when a TOML grammar is
;; available, conf-mode otherwise.
(if (and (fboundp 'treesit-ready-p) (treesit-ready-p 'toml))
    (add-to-list 'auto-mode-alist '("\\.toml\\'" . toml-ts-mode))
  (add-to-list 'auto-mode-alist '("\\.toml\\'" . conf-mode)))

;; .env files — admin.env, axonwall.env, controller.env, mfa.env,
;; k3s-storage.env.  KEY=value, shell-like: sh-mode covers them.
(add-to-list 'auto-mode-alist '("\\.env\\'" . sh-mode))
(add-to-list 'auto-mode-alist '("\\.env\\..+\\'" . sh-mode))

;; Caddyfile — Caddy v2, brace syntax.  conf-mode plus a small
;; font-lock addition for Caddy directives (caddyfile-mode is not
;; vendored: conf-mode covers the file adequately).
(add-to-list 'auto-mode-alist '("Caddyfile\\'" . conf-mode))
(with-eval-after-load 'conf-mode
  (font-lock-add-keywords
   'conf-mode
   '(("\\<\\(handle\\|reverse_proxy\\|tls\\|encode\\|redir\\|file_server\\|respond\\|route\\|import\\|log\\|bind\\|root\\|php_fastcgi\\|basicauth\\|request_body\\|header\\|rewrite\\|templates\\|try_files\\|handle_errors\\|uri\\|abort\\)\\>" . font-lock-keyword-face)
     ("\\<\\(https?://[^ \t\n]+\\)" . font-lock-string-face))))

;; Git — /etc/axonwall is under git (etckeeper).  vc-git is built
;; in; no extra config is needed, just ensure it loads so
;; C-x v v (vc-next-action), C-x v l (vc-print-log) and
;; C-x v = (vc-diff) work.
(when (require 'vc-git nil t)
  nil)

;; Lua — nvim/init.lua.  There is no built-in lua-mode in Emacs
;; core and no Lua grammar is bundled, so fall back to prog-mode
;; (syntax highlighting is limited; indentation is manual).
(add-to-list 'auto-mode-alist '("\\.lua\\'" . prog-mode))

;;; init.el ends here
`

// provisionEmacsPluginFiles writes the cli-emacs launcher and
// minimal init.el into the plugin dir, and symlinks the portable
// dump next to the binary. It runs at install time, after
// installBundledBinaries has extracted the .debs.
//
// The pdmp symlink is required, not cosmetic: emacs looks for its
// dump only (a) next to the binary (<bindir>/emacs-nox.pdmp) or
// (b) at the compiled-in libexec path — verified by strace
// 2026-11-20; EMACSPATH does NOT redirect the lookup. Without the
// dump, emacs runs undumped (temacs loadup) and is broken. The
// dump file name carries a build fingerprint
// (emacs-<sha256>.pdmp), so the code globs for the single match
// under usr/libexec/emacs/30.1/x86_64-linux-gnu/ and fails loudly
// on zero or multiple matches rather than guessing a name.
func (pm *PluginManager) provisionEmacsPluginFiles() error {
	pluginDir, err := pm.pluginDir(emacsPluginID)
	if err != nil {
		return err
	}
	binDir := filepath.Join(pluginDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", binDir, err)
	}
	launcher := filepath.Join(binDir, "emacs")
	if err := os.WriteFile(launcher, []byte(emacsLauncherScript), 0755); err != nil {
		return fmt.Errorf("write %s: %w", launcher, err)
	}
	configDir := filepath.Join(pluginDir, "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", configDir, err)
	}
	initEl := filepath.Join(configDir, "init.el")
	if err := os.WriteFile(initEl, []byte(emacsInitEl), 0644); err != nil {
		return fmt.Errorf("write %s: %w", initEl, err)
	}
	pdmpPattern := filepath.Join(pluginDir, "usr", "libexec", "emacs", "30.1", "x86_64-linux-gnu", "emacs-*.pdmp")
	matches, err := filepath.Glob(pdmpPattern)
	if err != nil {
		return fmt.Errorf("glob bundled emacs dump: %w", err)
	}
	if len(matches) != 1 {
		return fmt.Errorf("expected exactly one bundled emacs dump matching %s, found %d; refusing to install a plugin whose dump cannot be located", pdmpPattern, len(matches))
	}
	link := filepath.Join(pluginDir, "usr", "bin", "emacs-nox.pdmp")
	_ = os.Remove(link)
	if err := os.Symlink(filepath.Join("..", "libexec", "emacs", "30.1", "x86_64-linux-gnu", filepath.Base(matches[0])), link); err != nil {
		return fmt.Errorf("symlink %s: %w", link, err)
	}
	return nil
}

// checkEmacsBundledLibraries runs `ldd` on the extracted
// emacs-nox binary and fails loudly listing any shared library
// reported "not found" — a missing libgccjit.so.0 (or
// libasound/liblcms2) means the binary cannot start at all, and
// the install must fail rather than record a broken plugin. ldd
// runs with LD_LIBRARY_PATH set to the bundled lib dir, because
// that is the runtime environment: without it the bundled libs
// themselves would (correctly, but misleadingly) report as
// missing. If `ldd` itself is absent, this logs a warning and
// continues — a missing ldd must not block the install; the
// failure will surface at first launch instead.
func (pm *PluginManager) checkEmacsBundledLibraries() error {
	lddPath, err := exec.LookPath("ldd")
	if err != nil {
		log.Printf("[Plugins] Warning: ldd is not available; skipping bundled-library check for cli-emacs (a missing shared library will fail at first launch instead)")
		return nil
	}
	pluginDir, err := pm.pluginDir(emacsPluginID)
	if err != nil {
		return err
	}
	binary := filepath.Join(pluginDir, filepath.FromSlash(emacsBundledBinaryRelPath))
	libDir := filepath.Join(pluginDir, filepath.FromSlash(emacsBundledLibDirRelPath))
	cmd := exec.Command(lddPath, binary)
	// Append after the inherited environment: exec dedups with
	// the last value winning, so this overrides any ambient
	// LD_LIBRARY_PATH rather than stacking on it.
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+libDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ldd %s failed: %w (output: %s)", binary, err, strings.TrimSpace(string(out)))
	}
	var missing []string
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "not found") {
			continue
		}
		if fields := strings.Fields(strings.TrimSpace(line)); len(fields) > 0 {
			missing = append(missing, fields[0])
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("bundled emacs binary %s is missing shared libraries: %s; refusing to install a plugin whose binary cannot start (bundle the providing .debs or fix the plugin manifest)", binary, strings.Join(missing, ", "))
	}
	return nil
}
