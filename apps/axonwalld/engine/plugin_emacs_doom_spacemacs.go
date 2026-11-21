package engine

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Doom Emacs (cli-emacs-doom) and Spacemacs (cli-emacs-spacemacs):
// two config distributions sharing the ONE cli-emacs binary
// (Debian emacs-nox 30.1, see plugin_emacs_config.go). Neither
// plugin ships a second copy of the binary or the data tree — each
// adds only its distribution's clone plus its config layer, and a
// bin/ launcher that execs the shared binary with its own
// --init-directory. All three (minimal, Doom, Spacemacs) may be
// installed and enabled at once; the choice is at launch time
// (emacs vs emacs-doom vs emacs-spacemacs).
//
// Layout inside each plugin dir:
//
//	<plugindir>/
//	  bin/emacs-doom | bin/emacs-spacemacs   launcher (this file)
//	  config/                                 DOOMDIR / SPACEMACSDIR
//	    init.el, config.el, packages.el       (Doom)
//	    init.el                               (Spacemacs dotfile)
//	  doom/                                   Doom core clone (Doom only)
//	    bin/doom, early-init.el, lisp/
//	    sources/doom+/                        modules submodule
//	  local/                                  DOOMLOCALDIR (Doom only:
//	                                            straight repos + build
//	                                            dirs + caches + state)
//	  spacemacs/                              Spacemacs clone (Spacemacs
//	                                            only: init.el, core/,
//	                                            layers/; elpa/ + .cache/
//	                                            land here at first start)
//
// Launchers resolve the plugin dir from their own path and the
// shared cli-emacs tree as its sibling, so the state dir can move
// (state-dir override, restore) without rewriting them. No -nw is
// forced in either launcher: the operator chooses terminal vs GUI
// at launch (the appliance is terminal-only in practice, and
// emacs-nox has no GUI).
//
// RECONFIGURE REPAIR GAP (same as cli-emacs): ReconfigurePlugin has
// no case for these plugins, so if a launcher or config file is
// deleted after install, only a reinstall restores it. That is
// recorded here, not papered over with a repair pass.
//
// PINNED UPSTREAM COMMITS. Every hash below was observed by cloning
// the upstream repo on 2026-11-20 (see the W6 report); none was
// invented. Dates are the commit dates.
//
//	Doom core:    doomemacs/core @ eab52d2fe5e58303696e129717553ec5bf031bb0
//	              (2026-11-15, "fix: make kill-current-buffer delete
//	              dedicated windows")
//	Doom modules: doomemacs/modules @ f054be8fcdd2a0446eb8259d76dd4f6f76acc0b7
//	              (2026-11-03, "release: 26.11.0") — this is the commit
//	              the pinned core's gitlink records for sources/doom+
//	              (verified from core's tree), not just modules' HEAD.
//	Spacemacs:    syl20bnr/spacemacs develop @ 1f69b2a854a7a46f709def08412dbd5d6dc073a1
//	              (2026-11-09, "[bootstrap] Fix which-key showing
//	              \"root\" instead of embark-select (M-o SPC)")
//
// Doom pins are REAL pins: every Doom package carries a :pin in its
// module's packages.el, and `doom sync` respects them, so the pinned
// (core + modules) pair determines the package set. Spacemacs pins
// are NOT: Spacemacs has no per-package version pinning — first start
// fetches the latest snapshot of every package from MELPA/GNU ELPA.
// Only the Spacemacs commit itself is pinned; the packages are
// latest-at-install. The vendored-elpa-snapshot approach (build once,
// ship the elpa/ tree with sha256s) is the follow-up that would make
// Spacemacs reproducible; it is NOT done on this branch.

const doomEmacsPluginID = "cli-emacs-doom"
const spacemacsPluginID = "cli-emacs-spacemacs"

const doomCoreRepoURL = "https://github.com/doomemacs/core"
const doomCorePinnedCommit = "eab52d2fe5e58303696e129717553ec5bf031bb0" // 2026-11-15
const doomModulesRepoURL = "https://github.com/doomemacs/modules"
const doomModulesPinnedCommit = "f054be8fcdd2a0446eb8259d76dd4f6f76acc0b7" // 2026-11-03, "release: 26.11.0"

const spacemacsRepoURL = "https://github.com/syl20bnr/spacemacs"
const spacemacsPinnedCommit = "1f69b2a854a7a46f709def08412dbd5d6dc073a1" // 2026-11-09, develop

// doomInitEl is the minimal Doom module set for editing /etc/axonwall
// files (YAML, .env, Caddyfile, JSON, TOML, Lua, shell). Flags are
// deliberately minimal:
//
//   - NO :editor section, i.e. NO evil: the operators are
//     emacs-preferring (the same decision as cli-emacs minimal), and
//     Doom's :config default +bindings provides the C-c leader scheme
//     for non-evil users. Evil is a one-line change
//     ((evil +everywhere) under :editor) if an operator wants it —
//     nearly all Doom documentation is written for evil, so the
//     non-evil path is less documented.
//   - NO +lsp anywhere: language servers come via npm/Node, absent
//     on vault/k3s-storage (NGFW only).
//   - NO :checkers syntax (flycheck): its YAML/JSON checkers need
//     yamllint, js-yaml (node) or ruby — none on the box.
//   - NO :term vterm: needs cmake + libtool to build its C module;
//     eshell (built in) instead.
//   - NO :tools tree-sitter: Emacs 30 has built-in treesit; the Doom
//     module would download prebuilt grammars, which conflicts with
//     the cli-emacs grammar plan (unverified interaction).
//   - :lang data provides csv-mode ONLY at the pinned modules commit
//     (verified 2026-11-20: packages.el lists a single pinned
//     csv-mode, config.el adds nxml-mode) — it does NOT cover TOML,
//     dotenv or YAML. TOML/.env/Caddyfile/Lua are covered by the
//     guards in doomConfigEl, not by a module.
const doomInitEl = `;;; init.el --- Doom Emacs module selection for Axonwall -*- lexical-binding: t; -*-
;;; Commentary:
;; Minimal Doom module set for editing /etc/axonwall configuration
;; files.  No evil (operators are emacs-preferring; see the header
;; comment in plugin_emacs_doom_spacemacs.go), no +lsp, no vterm, no
;; flycheck — none of those have their external tools on the box.
;; Run 'doom sync' after modifying this file.
;;; Code:

(doom! :completion
       (corfu +orderless)   ; in-buffer completion
       vertico              ; minibuffer completion UI
       :ui
       doom                 ; Doom theme; which-key is built into Emacs 30
       hl-todo              ; highlight TODO/FIXME in configs
       :emacs
       dired                ; file browser
       electric             ; smarter indent
       undo                 ; undo-fu
       vc                   ; vc-gutter/diff integration (etckeeper git repo)
       :term
       eshell               ; built-in shell; vterm EXCLUDED (needs cmake/libtool)
       :tools
       magit                ; git porcelain; needs git (present); full clone, see header
       editorconfig         ; EditorConfig; C core absent, elisp fallback
       :os
       tty                  ; terminal-Emacs improvements (we are emacs-nox)
       :lang
       data                 ; config/data formats (csv-mode only at the pinned commit)
       emacs-lisp           ; config editing; near-mandatory in Doom
       json                 ; json-mode; +lsp OFF
       sh                   ; sh-mode for scripts + .env; +lsp OFF
       yaml                 ; yaml-mode; +lsp OFF
       :config
       (default +bindings +smartparens))

;;; init.el ends here
`

// doomConfigEl is $DOOMDIR/config.el: the gaps the module set does
// not cover. YAML/JSON/sh are owned by their modules and are NOT
// overridden here (their modes exist; the tree-sitter guards in the
// cli-emacs minimal only applied because there were no modes at
// all). What this file adds is TOML (built-in toml-ts-mode guarded,
// conf-mode otherwise — no MELPA toml-mode is pinned), .env
// (sh-mode), Caddyfile (conf-mode + font-lock, same keywords as the
// cli-emacs minimal), Lua (prog-mode fallback: no built-in lua-mode)
// and the byte-compiled-only native-comp setting (same crtbeginS.o
// reason as cli-emacs: the .eln link step needs gcc-14 files that
// are not bundled). `doom env` is deliberately NOT run at install:
// on a terminal-only box launched from a shell the env is already
// correct, and where it would write its file was not verified.
const doomConfigEl = `;;; config.el --- Doom Emacs user configuration for Axonwall -*- lexical-binding: t; -*-
;;; Commentary:
;; Fills the gaps the minimal module set leaves: TOML, .env files,
;; Caddyfile, Lua.  YAML/JSON/sh are owned by their Doom modules and
;; are not touched here.  No 'doom env' file is generated (see the
;; header comment in plugin_emacs_doom_spacemacs.go).
;;; Code:

;; Doom theme (doom-one is the default; set explicitly).
(setq doom-theme 'doom-one)

;; Byte-compiled only — NO native-comp JIT. Same reason as cli-emacs
;; (plugin_emacs_config.go): JIT-compiling new code fails at the link
;; step ("ld: cannot find crtbeginS.o") because the link needs
;; crtbeginS.o from gcc-14 / libgcc-14-dev, which is not bundled.
;; Doom already defers native-comp during sync; this stops runtime
;; JIT from hitting the same missing linker.
(when (boundp 'native-comp-jit-compilation)
  (setq native-comp-jit-compilation nil))

;; TOML — starship.toml. toml-ts-mode when a TOML tree-sitter grammar
;; is available, conf-mode otherwise (no grammar .so ships in trixie).
(if (and (fboundp 'treesit-ready-p) (treesit-ready-p 'toml))
    (add-to-list 'auto-mode-alist '("\\.toml\\'" . toml-ts-mode))
  (add-to-list 'auto-mode-alist '("\\.toml\\'" . conf-mode)))

;; .env files — admin.env, axonwall.env, controller.env, mfa.env,
;; k3s-storage.env. KEY=value, shell-like: sh-mode covers them.
(add-to-list 'auto-mode-alist '("\\.env\\'" . sh-mode))
(add-to-list 'auto-mode-alist '("\\.env\\..+\\'" . sh-mode))

;; Caddyfile — Caddy v2, brace syntax. conf-mode plus a small
;; font-lock addition for Caddy directives (same keywords as the
;; cli-emacs minimal; caddyfile-mode is not vendored).
(add-to-list 'auto-mode-alist '("Caddyfile\\'" . conf-mode))
(with-eval-after-load 'conf-mode
  (font-lock-add-keywords
   'conf-mode
   '(("\\<\\(handle\\|reverse_proxy\\|tls\\|encode\\|redir\\|file_server\\|respond\\|route\\|import\\|log\\|bind\\|root\\|php_fastcgi\\|basicauth\\|request_body\\|header\\|rewrite\\|templates\\|try_files\\|handle_errors\\|uri\\|abort\\)\\>" . font-lock-keyword-face)
     ("\\<\\(https?://[^ \t\n]+\\)" . font-lock-string-face))))

;; Lua — nvim/init.lua. There is no built-in lua-mode in Emacs core
;; and no Lua grammar is bundled, so fall back to prog-mode.
(add-to-list 'auto-mode-alist '("\\.lua\\'" . prog-mode))

;;; config.el ends here
`

// doomPackagesEl is $DOOMDIR/packages.el: intentionally empty. Every
// package the minimal module set needs comes from the pinned
// doomemacs/modules tree with its own :pin, and `doom sync` enforces
// those pins. Add a (package! ... :pin "<40-hex>") line here only
// with a real, observed pin hash — never invent one.
const doomPackagesEl = `;; -*- no-byte-compile: t; -*-
;;; packages.el --- Doom Emacs user packages for Axonwall
;;; Commentary:
;; No additional packages: the minimal module set's packages all come
;; from the pinned doomemacs/modules tree with their own :pin values,
;; enforced by 'doom sync'. In particular :lang data at the pinned
;; modules commit provides csv-mode only (plus nxml-mode config) — it
;; does NOT cover TOML, so TOML is handled by the built-in
;; toml-ts-mode guard in config.el rather than by pinning a MELPA
;; toml-mode here.
;;; Code:

;;; packages.el ends here
`

// spacemacsInitEl is the pre-seeded Spacemacs dotfile, written to
// <plugindir>/config/init.el and selected with SPACEMACSDIR. It is
// the attempt at suppressing the first-start wizard: the wizard
// writes the dotfile when none exists, so a pre-existing dotfile
// should skip it — but whether a pre-seeded dotfile FULLY suppresses
// the wizard was NOT verified in this sandbox (no live first start
// is possible here), so that is recorded as unverified, not claimed.
//
// Layer set (minimal, for editing /etc/axonwall files):
//
//   - helm (default completion framework), auto-completion
//     (company), better-defaults, emacs-lisp, git (Magit +
//     companions — verified at the pinned commit; includes forge,
//     which needs a GitHub token and is useless on the appliance
//     but is left installed rather than excluded, untested),
//     version-control (diff-hl fringe diffs for etckeeper-tracked
//     /etc/axonwall), shell with eshell (NEVER vterm: needs
//     cmake/libtool), syntax-checking (flycheck — installed, but
//     its YAML/JSON checkers need yamllint/js-yaml/node, none on
//     the box, so it reports "no checker" for these files),
//     yaml (yaml-mode; verified at the pinned commit: company,
//     flycheck, yaml-mode), json (verified at the pinned commit:
//     company, add-node-modules-path, flycheck, json-mode,
//     json-navigator, json-reformat, json-snatcher, prettier-js,
//     web-beautify).
//   - Editing style 'emacs, NOT vim: the operators are
//     emacs-preferring (same decision as Doom without evil); 'vim
//     would pull the whole evil stack. The wizard's default is vim;
//     pre-seeding the dotfile is what locks 'emacs in.
//   - Distribution 'spacemacs (the default). 'spacemacs-base is an
//     UNVERIFIED slimming option, not the default.
//   - dotspacemacs-excluded-packages trims prettier-js /
//     web-beautify (need Node to format; Node is absent on
//     vault/k3s-storage). The json layer's `:packages' selection
//     syntax was NOT re-verified against current develop, so the
//     trimming is done here (a documented variable, present in the
//     template at the pinned commit) instead of in the layer spec.
//   - Left out: org, markdown, themes-megapack (~100 themes),
//     lsp/dap (need language servers), spell-checking (needs
//     ispell/hunspell/aspell — none on the box), treemacs/neotree,
//     github (needs network + tokens).
//
// PACKAGES ARE LATEST-AT-INSTALL (not pinned): Spacemacs cannot pin
// package versions (upstream issue #6531: "There's no way to do this
// yet. Spacemacs tracks volatile versions of all packages"). First
// start downloads the latest snapshot of every layer package from
// MELPA/GNU ELPA and needs network; two installs at different times
// can differ. dotspacemacs-frozen-packages freezes an
// already-installed package against updates — it does NOT select
// which version gets installed. Do not describe this install as
// pinned. The vendored-elpa-snapshot follow-up (ship a built elpa/
// tree with sha256s) is what would make it reproducible.
const spacemacsInitEl = `;; -*- mode: emacs-lisp; lexical-binding: t -*-
;; .spacemacs (as SPACEMACSDIR/init.el) — pre-seeded Spacemacs dotfile
;; for Axonwall. Generated at install time by axonwalld
;; (plugin_emacs_doom_spacemacs.go); do not edit by hand.
;;
;; Pre-seeding this file is the attempt at suppressing the first-start
;; wizard (see the header comment in plugin_emacs_doom_spacemacs.go):
;; whether it fully suppresses the wizard is UNVERIFIED — no live
;; first start is possible in the sandbox.
;;
;; PACKAGES ARE LATEST-AT-INSTALL, NOT PINNED: Spacemacs has no
;; per-package version pinning. First start downloads the latest
;; snapshot of every layer package from MELPA/GNU ELPA and needs
;; network. The vendored-elpa-snapshot approach is a follow-up, not
;; this branch.

(defun dotspacemacs/layers ()
  "Layer configuration:
This function should only modify configuration layer settings."
  (setq-default
   ;; Base distribution: 'spacemacs (default). 'spacemacs-base is an
   ;; UNVERIFIED slimming option, not the default.
   dotspacemacs-distribution 'spacemacs

   ;; Lazy installation of layers (default 'unused).
   dotspacemacs-enable-lazy-installation 'unused

   ;; List of configuration layers to load.
   dotspacemacs-configuration-layers
   '(helm
     auto-completion
     better-defaults
     emacs-lisp
     git
     (version-control :variables
                      version-control-diff-tool 'diff-hl
                      version-control-global-margin t)
     (shell :variables
            shell-default-shell 'eshell
            shell-default-height 30
            shell-default-position 'bottom)
     syntax-checking
     yaml
     json)

   ;; List of additional packages that will be installed without being
   ;; wrapped in a layer.
   dotspacemacs-additional-packages '()

   ;; A list of packages that cannot be updated.
   dotspacemacs-frozen-packages '()

   ;; A list of packages that will not be installed and loaded.
   ;; prettier-js / web-beautify need Node to format; Node is absent
   ;; on vault/k3s-storage, so they are dead weight there. (Trimming
   ;; is done here rather than with the json layer's ':packages'
   ;; selection, whose syntax was not re-verified on current develop.)
   dotspacemacs-excluded-packages '(prettier-js web-beautify)

   ;; Defines the behaviour of Spacemacs when installing packages.
   ;; 'used-only installs only explicitly used packages.
   dotspacemacs-install-packages 'used-only))

(defun dotspacemacs/init ()
  "Initialization:
This function is called at the very beginning of Spacemacs startup,
before layer configuration.
It should only modify the values of Spacemacs settings."
  (setq-default
   ;; If non-nil, a form that evaluates to a package directory.
   ;; 'emacs-version keeps elpa/ per-Emacs-version (template default;
   ;; set explicitly so a future emacs upgrade does not mix bytecode).
   dotspacemacs-elpa-subdirectory 'emacs-version

   ;; One of 'vim, 'emacs or 'hybrid. 'emacs, NOT vim: the operators
   ;; are emacs-preferring (same decision as Doom without evil); 'vim
   ;; would pull the whole evil stack.
   dotspacemacs-editing-style 'emacs

   ;; Never check for updates at startup (default nil; set explicitly
   ;; so a future default cannot start phoning GitHub on every launch).
   dotspacemacs-check-for-update nil))

(defun dotspacemacs/user-init ()
  "Initialization for user code:
This function is called immediately after dotspacemacs/init, before
layer configuration. It is mostly useful for variables that need to be
set before packages are loaded."
  )

(defun dotspacemacs/user-config ()
  "Configuration for user code:
This function is called at the very end of Spacemacs startup, after
layer configuration. Put your configuration code here, except for
variables that should be set before packages are loaded."
  ;; Byte-compiled only — NO native-comp JIT. Same reason as cli-emacs
  ;; (plugin_emacs_config.go): JIT-compiling new code fails at the link
  ;; step ("ld: cannot find crtbeginS.o") because the link needs
  ;; crtbeginS.o from gcc-14 / libgcc-14-dev, which is not bundled.
  (when (boundp 'native-comp-jit-compilation)
    (setq native-comp-jit-compilation nil))

  ;; .env files — admin.env, axonwall.env, controller.env, mfa.env,
  ;; k3s-storage.env. KEY=value, shell-like: sh-mode covers them.
  (add-to-list 'auto-mode-alist '("\\.env\\'" . sh-mode))
  (add-to-list 'auto-mode-alist '("\\.env\\..+\\'" . sh-mode))

  ;; Caddyfile — Caddy v2, brace syntax. conf-mode plus a small
  ;; font-lock addition for Caddy directives (same keywords as the
  ;; cli-emacs minimal; caddyfile-mode is not vendored).
  (add-to-list 'auto-mode-alist '("Caddyfile\\'" . conf-mode))
  (with-eval-after-load 'conf-mode
    (font-lock-add-keywords
     'conf-mode
     '(("\\<\\(handle\\|reverse_proxy\\|tls\\|encode\\|redir\\|file_server\\|respond\\|route\\|import\\|log\\|bind\\|root\\|php_fastcgi\\|basicauth\\|request_body\\|header\\|rewrite\\|templates\\|try_files\\|handle_errors\\|uri\\|abort\\)\\>" . font-lock-keyword-face)
       ("\\<\\(https?://[^ \t\n]+\\)" . font-lock-string-face))))

  ;; Lua — nvim/init.lua. There is no built-in lua-mode in Emacs core
  ;; and no Lua grammar is bundled, so fall back to prog-mode.
  (add-to-list 'auto-mode-alist '("\\.lua\\'" . prog-mode)))
`

// doomLauncherScript returns the bin/emacs-doom launcher. It execs
// the SHARED cli-emacs binary (resolved as a sibling of this plugin's
// dir, so the state dir can move) with the same four relocation env
// vars as the cli-emacs launcher (from emacsRelocationEnvScript —
// the single definition), plus DOOMDIR + DOOMLOCALDIR and
// --init-directory at this plugin's Doom core clone. DOOMPROFILE is
// unset: with no profile, Doom uses the DOOMLOCALDIR-rooted paths and
// writes nothing under $HOME. No -nw is forced: the operator chooses
// terminal vs GUI at launch. If the shared binary is missing (e.g.
// cli-emacs not installed) it fails loudly with exit 127 — it never
// falls back to a system emacs.
func doomLauncherScript() string {
	return `#!/bin/sh
# cli-emacs-doom launcher — execs the SHARED cli-emacs emacs-nox binary
# with the Doom Emacs distribution. Generated at install time by
# axonwalld (plugin_emacs_doom_spacemacs.go); do not edit by hand.
# No -nw is forced: the operator chooses terminal vs GUI at launch.
PLUGIN_DIR=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
EMACS_PLUGIN_DIR="$(dirname "$PLUGIN_DIR")/cli-emacs"
BIN="$EMACS_PLUGIN_DIR/usr/bin/emacs-nox"
if [ ! -x "$BIN" ]; then
  printf 'cli-emacs-doom: shared cli-emacs binary %s is missing or not executable (is cli-emacs installed?)\n' "$BIN" >&2
  exit 127
fi
` + emacsRelocationEnvScript("$EMACS_PLUGIN_DIR") + `export DOOMDIR="$PLUGIN_DIR/config"
export DOOMLOCALDIR="$PLUGIN_DIR/local"
unset DOOMPROFILE
exec "$BIN" --init-directory "$PLUGIN_DIR/doom" "$@"
`
}

// spacemacsLauncherScript returns the bin/emacs-spacemacs launcher.
// Same shape as the Doom launcher: the shared cli-emacs binary, the
// same four relocation env vars, plus SPACEMACSDIR and
// --init-directory at this plugin's Spacemacs clone. No -nw is
// forced. It fails loudly (exit 127) if the shared binary is missing
// — never a silent fallback to a system emacs — and also if
// ~/.spacemacs exists: that file ALWAYS takes priority over
// SPACEMACSDIR, so a stray one would silently shadow the plugin
// dotfile instead of merely being ignored.
func spacemacsLauncherScript() string {
	return `#!/bin/sh
# cli-emacs-spacemacs launcher — execs the SHARED cli-emacs emacs-nox
# binary with Spacemacs. Generated at install time by axonwalld
# (plugin_emacs_doom_spacemacs.go); do not edit by hand.
# No -nw is forced: the operator chooses terminal vs GUI at launch.
PLUGIN_DIR=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
EMACS_PLUGIN_DIR="$(dirname "$PLUGIN_DIR")/cli-emacs"
BIN="$EMACS_PLUGIN_DIR/usr/bin/emacs-nox"
if [ ! -x "$BIN" ]; then
  printf 'cli-emacs-spacemacs: shared cli-emacs binary %s is missing or not executable (is cli-emacs installed?)\n' "$BIN" >&2
  exit 127
fi
if [ -f "$HOME/.spacemacs" ]; then
  printf 'cli-emacs-spacemacs: %s exists and would silently take priority over SPACEMACSDIR — remove it first\n' "$HOME/.spacemacs" >&2
  exit 127
fi
` + emacsRelocationEnvScript("$EMACS_PLUGIN_DIR") + `export SPACEMACSDIR="$PLUGIN_DIR/config"
exec "$BIN" --init-directory "$PLUGIN_DIR/spacemacs" "$@"
`
}

// provisionDoomEmacsPluginFiles writes the bin/emacs-doom launcher
// and the DOOMDIR config files (init.el, config.el, packages.el).
// The Doom core clone (doom/) is created by installDoomEmacs, not
// here. Like the cli-emacs launcher/config, these files are
// generated locally from repo constants (not downloaded), so they
// are not part of bundled.json — verification checks the launcher
// exists and is executable via RequiredBinaries, but does not hash
// it. Only a reinstall restores a deleted launcher/config (see the
// header comment).
func (pm *PluginManager) provisionDoomEmacsPluginFiles() error {
	pluginDir, err := pm.pluginDir(doomEmacsPluginID)
	if err != nil {
		return err
	}
	binDir := filepath.Join(pluginDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", binDir, err)
	}
	launcher := filepath.Join(binDir, "emacs-doom")
	if err := os.WriteFile(launcher, []byte(doomLauncherScript()), 0755); err != nil {
		return fmt.Errorf("write %s: %w", launcher, err)
	}
	configDir := filepath.Join(pluginDir, "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", configDir, err)
	}
	for name, content := range map[string]string{
		"init.el":     doomInitEl,
		"config.el":   doomConfigEl,
		"packages.el": doomPackagesEl,
	} {
		path := filepath.Join(configDir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}

// provisionSpacemacsPluginFiles writes the bin/emacs-spacemacs
// launcher and the pre-seeded dotfile (config/init.el, selected via
// SPACEMACSDIR). The Spacemacs clone (spacemacs/) is created by
// installSpacemacsEmacs, not here. Same generated-locally caveats
// as provisionDoomEmacsPluginFiles: not part of bundled.json, only
// a reinstall restores a deleted launcher/dotfile.
func (pm *PluginManager) provisionSpacemacsPluginFiles() error {
	pluginDir, err := pm.pluginDir(spacemacsPluginID)
	if err != nil {
		return err
	}
	binDir := filepath.Join(pluginDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", binDir, err)
	}
	launcher := filepath.Join(binDir, "emacs-spacemacs")
	if err := os.WriteFile(launcher, []byte(spacemacsLauncherScript()), 0755); err != nil {
		return fmt.Errorf("write %s: %w", launcher, err)
	}
	configDir := filepath.Join(pluginDir, "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", configDir, err)
	}
	initEl := filepath.Join(configDir, "init.el")
	if err := os.WriteFile(initEl, []byte(spacemacsInitEl), 0644); err != nil {
		return fmt.Errorf("write %s: %w", initEl, err)
	}
	return nil
}

// requireCliEmacsInstalled fails closed unless the shared cli-emacs
// binary exists and is executable. The dependency guard in
// Disable/Uninstall covers disable/uninstall, but install must also
// refuse without its dependency present: a Doom/Spacemacs install
// with no binary to exec would record a plugin whose launcher can
// never run.
func (pm *PluginManager) requireCliEmacsInstalled() error {
	emacsDir, err := pm.pluginDir(emacsPluginID)
	if err != nil {
		return err
	}
	binary := filepath.Join(emacsDir, filepath.FromSlash(emacsBundledBinaryRelPath))
	if !isExecutableFile(binary) {
		return fmt.Errorf("cli-emacs is not installed: shared binary %s is missing or not executable; install cli-emacs first", binary)
	}
	return nil
}

// runGit runs git with stdin closed and GIT_TERMINAL_PROMPT=0, so a
// missing credential or unreachable remote fails fast instead of
// blocking on a prompt. dir is the working directory ("" = no -C).
func runGit(dir string, args ...string) error {
	argv := args
	if dir != "" {
		argv = append([]string{"-C", dir}, args...)
	}
	cmd := exec.Command("git", argv...)
	cmd.Stdin = nil
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %s: %w (output: %s)", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// gitRevParseHead returns the HEAD commit of the repo at dir.
func gitRevParseHead(dir string) (string, error) {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "HEAD")
	cmd.Stdin = nil
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git -C %s rev-parse HEAD: %w", dir, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// gitCloneAtCommit clones url into dir at exactly commit pin (a
// detached HEAD — the normal state for a pinned checkout, as with
// submodules). A shallow clone of HEAD would pin nothing, since HEAD
// moves: instead it fetches exactly the pinned commit (GitHub
// allows fetching a single SHA) and verifies HEAD landed on it,
// failing closed otherwise. Network is required at install time.
func gitCloneAtCommit(url, dir, pin string) error {
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git is required to install this plugin but was not found on PATH: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(dir), err)
	}
	if err := runGit("", "init", dir); err != nil {
		return err
	}
	if err := runGit(dir, "remote", "add", "origin", url); err != nil {
		return err
	}
	if err := runGit(dir, "fetch", "--depth", "1", "origin", pin); err != nil {
		return fmt.Errorf("fetch pinned commit %s from %s: %w", pin, url, err)
	}
	if err := runGit(dir, "checkout", pin); err != nil {
		return err
	}
	head, err := gitRevParseHead(dir)
	if err != nil {
		return err
	}
	if head != pin {
		return fmt.Errorf("checkout of %s landed on %s, want pinned commit %s; refusing to install an unpinned tree", url, head, pin)
	}
	return nil
}

// tailString returns the last n characters of s (the whole string
// when shorter), for capping command output in error messages.
func tailString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// runDoomSync runs `<plugindir>/doom/bin/doom sync` with DOOMDIR and
// DOOMLOCALDIR set to this plugin's dirs, with the shared cli-emacs
// bin dir first on PATH and EMACS pointing at the cli-emacs
// launcher, so bin/doom execs the bundled emacs-nox (never a system
// emacs — there is none on the box, so a wrong resolution fails
// loudly instead). DOOMPROFILE is stripped from the environment:
// with no profile, Doom uses the DOOMLOCALDIR-rooted paths and
// writes nothing under $HOME. stdin is closed: doom sync must run
// non-interactively, and a prompt must fail with EOF rather than
// hang the install. Doom's packages are :pin-pinned in the modules
// tree, so this sync is reproducible from the pinned commits —
// except magit, which breaks on shallow clones and is fetched whole
// (see the header comment). Whether `doom sync` actually runs
// non-interactively in practice was NOT verified in this sandbox
// (no emacs here); that is recorded as unverified, not claimed.
func (pm *PluginManager) runDoomSync() error {
	pluginDir, err := pm.pluginDir(doomEmacsPluginID)
	if err != nil {
		return err
	}
	doomBin := filepath.Join(pluginDir, "doom", "bin", "doom")
	if !isExecutableFile(doomBin) {
		return fmt.Errorf("doom binary %s is missing or not executable; the Doom core clone is incomplete", doomBin)
	}
	emacsDir, err := pm.pluginDir(emacsPluginID)
	if err != nil {
		return err
	}
	emacsBinDir := filepath.Join(emacsDir, "bin")
	env := make([]string, 0, len(os.Environ())+4)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "DOOMPROFILE=") {
			continue
		}
		env = append(env, kv)
	}
	// Appended after the inherited environment: exec dedups with the
	// last value winning, so these override any ambient PATH/EMACS.
	env = append(env,
		"DOOMDIR="+filepath.Join(pluginDir, "config"),
		"DOOMLOCALDIR="+filepath.Join(pluginDir, "local"),
		"EMACS="+filepath.Join(emacsBinDir, "emacs"),
		"PATH="+emacsBinDir+":"+os.Getenv("PATH"),
	)
	cmd := exec.Command(doomBin, "sync")
	cmd.Env = env
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("doom sync failed: %w (output tail: %s)", err, tailString(strings.TrimSpace(string(out)), 4000))
	}
	log.Printf("[Plugins] doom sync succeeded for cli-emacs-doom (%d bytes of output)", len(out))
	return nil
}

// installDoomEmacs performs the Doom install: fail closed without
// cli-emacs; clone doomemacs/core at the pinned commit; populate the
// doomemacs/modules submodule (sources/doom+, the commit the pinned
// core records) and verify it landed on the pinned modules commit;
// write the launcher + DOOMDIR configs; run doom sync. On any
// failure it removes this run's artifacts (doom/, config/, the
// launcher) so a half-installed tree can never be mistaken for
// installed. local/ (the straight package cache) is always kept: it
// holds no install claim and speeds a retry.
func (pm *PluginManager) installDoomEmacs() error {
	if err := pm.requireCliEmacsInstalled(); err != nil {
		return err
	}
	pluginDir, err := pm.pluginDir(doomEmacsPluginID)
	if err != nil {
		return err
	}
	doomDir := filepath.Join(pluginDir, "doom")
	configDir := filepath.Join(pluginDir, "config")
	launcher := filepath.Join(pluginDir, "bin", "emacs-doom")
	// Fresh clone on every install: a previous install's doom/ is
	// removed so the clone lands on exactly the pinned commit.
	// local/ is kept (doom sync reconciles it against the pins).
	if err := os.RemoveAll(doomDir); err != nil {
		return fmt.Errorf("remove previous Doom core clone %s: %w", doomDir, err)
	}
	failed := true
	defer func() {
		if failed {
			_ = os.RemoveAll(doomDir)
			_ = os.RemoveAll(configDir)
			_ = os.Remove(launcher)
		}
	}()
	if err := gitCloneAtCommit(doomCoreRepoURL, doomDir, doomCorePinnedCommit); err != nil {
		return err
	}
	// The modules library ships as a git submodule of core
	// (sources/doom+); a plain clone leaves it empty, so populate it
	// explicitly. It checks out the commit the pinned core records.
	if err := runGit(doomDir, "submodule", "update", "--init", "--depth", "1"); err != nil {
		return fmt.Errorf("populate Doom modules submodule: %w", err)
	}
	modulesDir := filepath.Join(doomDir, "sources", "doom+")
	modulesHead, err := gitRevParseHead(modulesDir)
	if err != nil {
		return fmt.Errorf("verify Doom modules submodule: %w", err)
	}
	if modulesHead != doomModulesPinnedCommit {
		return fmt.Errorf("Doom modules submodule checked out %s, want pinned commit %s; refusing to install an unpinned tree", modulesHead, doomModulesPinnedCommit)
	}
	if err := pm.provisionDoomEmacsPluginFiles(); err != nil {
		return err
	}
	if err := pm.runDoomSync(); err != nil {
		return err
	}
	failed = false
	return nil
}

// installSpacemacsEmacs performs the Spacemacs install: fail closed
// without cli-emacs, and fail closed if ~/.spacemacs exists (it
// ALWAYS takes priority over SPACEMACSDIR, so a stray one would
// silently shadow the plugin dotfile); clone syl20bnr/spacemacs
// develop at the pinned commit; write the launcher + pre-seeded
// dotfile. That is the whole install: there is NO package install
// and NO first start here. Spacemacs downloads its packages from
// MELPA/GNU ELPA on first launch (latest versions, unpinned — see
// the header comment); a live first start is NOT attempted in this
// sandbox and the wizard-suppression pre-seed is unverified. On any
// failure it removes this run's artifacts (spacemacs/, config/,
// the launcher) so a half-installed tree can never be mistaken for
// installed.
func (pm *PluginManager) installSpacemacsEmacs() error {
	if err := pm.requireCliEmacsInstalled(); err != nil {
		return err
	}
	if home, err := os.UserHomeDir(); err == nil {
		if _, err := os.Stat(filepath.Join(home, ".spacemacs")); err == nil {
			return fmt.Errorf("~/.spacemacs exists and would silently take priority over the plugin dotfile (SPACEMACSDIR); remove it before installing cli-emacs-spacemacs")
		}
	}
	pluginDir, err := pm.pluginDir(spacemacsPluginID)
	if err != nil {
		return err
	}
	spacemacsDir := filepath.Join(pluginDir, "spacemacs")
	configDir := filepath.Join(pluginDir, "config")
	launcher := filepath.Join(pluginDir, "bin", "emacs-spacemacs")
	if err := os.RemoveAll(spacemacsDir); err != nil {
		return fmt.Errorf("remove previous Spacemacs clone %s: %w", spacemacsDir, err)
	}
	failed := true
	defer func() {
		if failed {
			_ = os.RemoveAll(spacemacsDir)
			_ = os.RemoveAll(configDir)
			_ = os.Remove(launcher)
		}
	}()
	if err := gitCloneAtCommit(spacemacsRepoURL, spacemacsDir, spacemacsPinnedCommit); err != nil {
		return err
	}
	if err := pm.provisionSpacemacsPluginFiles(); err != nil {
		return err
	}
	failed = false
	return nil
}
