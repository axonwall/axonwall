package engine

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PluginDefinition struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Version          string   `json:"version"`
	Category         string   `json:"category"`
	Description      string   `json:"description"`
	Author           string   `json:"author"`
	DefaultEnabled   bool     `json:"defaultEnabled"`
	Dependencies     []string `json:"dependencies,omitempty"`
	SystemdUnits     []string `json:"systemdUnits"`
	Privileges       []string `json:"privileges"`
	DebianPackages   []string `json:"debianPackages"`
	AlpinePackages   []string `json:"alpinePackages"`
	ArchPackages     []string `json:"archPackages"`
	RequiredBinaries []string `json:"requiredBinaries"`

	// Binaries are binaries shipped with the plugin: downloaded into
	// the plugin's own directory, sha256-verified, and extracted
	// there — never installed into the system. Additive alongside
	// RequiredBinaries, which keeps working as-is. See
	// PluginBundledBinary.
	// BinDirs are plugin-owned directories (relative to the per-plugin
	// directory, e.g. "usr/bin" for a tree extracted from .debs) added
	// to PATH for daemon invocations and interactive shells. Guard
	// rules (enforced by the TS schema; the daemon must enforce them
	// too before use): relative only — no absolute paths, no ".."
	// segments, no empty entries.
	// Env holds extra per-plugin environment variables (e.g. EMACSDATA
	// pointing at a bundled data tree). Keys must be valid env-var
	// names ([A-Za-z_][A-Za-z0-9_]*). Values may reference the plugin's
	// own directory via the ${PLUGIN_DIR} placeholder, expanded by the
	// daemon/shell integration to the per-plugin directory.
	Binaries        []PluginBundledBinary `json:"binaries,omitempty"`
	BinDirs         []string              `json:"binDirs,omitempty"`
	Env             map[string]string     `json:"env,omitempty"`
	LdapIntegration *PluginLDAPSpec       `json:"ldapIntegration,omitempty"`
}

// PluginBundledBinary declares one binary artifact bundled with a
// plugin. Kind discriminates the three source kinds unambiguously:
//
//   - "archive": a downloadable archive. URL is required; Distro /
//     Package / Version / Arch must be empty. Name is the binary the
//     archive provides (e.g. "rosenpass", fetched from
//     https://github.com/rosenpass/rosenpass/releases/download/v0.2.3/rosenpass-x86_64-linux-0.2.3.tar).
//     Format is the container ("tar", "tar.gz"/"tgz", "zip"; default
//     "tar"). PathInArchive is the binary's path inside the archive,
//     relative with no ".."; it defaults to Name. By default an
//     archive entry extracts exactly that one binary into
//     <plugindir>/bin/<name> (Extract "" or "binary"); with
//     Extract "tree" the WHOLE archive is extracted into the plugin
//     dir, preserving member paths (bin/, lib/, share/, ...), after
//     stripping StripComponents leading path components — e.g. the
//     neovim release tarball wraps everything under a single
//     top-level "nvim-linux-x86_64/" dir, so StripComponents 1
//     lands the tree at <plugindir>/bin/nvim,
//     <plugindir>/lib/..., <plugindir>/share/... . Tree extraction
//     follows the same safety rules as single-binary extraction
//     (no symlinks/hardlinks/devices, no absolute or ".." members,
//     no member escaping the plugin dir); a tree member that would
//     be dropped by the strip (a regular file at or above the strip
//     depth) fails the install instead of being silently skipped.
//     PathInArchive must be empty for a tree entry: the strip is
//     the mechanism that selects the tree root, not a member path.
//     OSes, when non-empty, gates the entry to the listed host OS
//     families ("debian", "alpine", "arch" — the DetectOSFamily
//     values): an entry whose OS list does not include this host is
//     SKIPPED at install and ignored by verification, so a
//     Debian-only artifact (a glibc-linked tarball) never fails an
//     Alpine/Arch install. An empty OSes means every OS. A plugin
//     whose every entry is gated out on this host verifies trivially
//     (nothing bundled to check) and its binaries keep resolving
//     from the system packages, which must then still provide them
//     — see cli-workstation: vim/neovim stay in AlpinePackages and
//     ArchPackages for exactly this reason.
//   - "binary": a downloadable raw single file (no archive
//     container). URL is required; Distro / Package / Version /
//     Arch / Format / PathInArchive must be empty. The verified
//     bytes are placed directly at <plugindir>/bin/<name> with
//     mode 0755 (e.g. "k3s", fetched as a bare static binary from
//     its GitHub release).
//   - "distroPackage": a distro package to download and extract
//     (never install). URL must be empty; Distro / Package / Version /
//     Arch are required. Name is the package name (e.g. "emacs-nox");
//     the binaries it contributes are found via BinDirs after
//     extraction. Version is the full version including epoch where
//     the distro uses one (e.g. "1:30.1+1-6"); the daemon derives the
//     file name from Package + Version + Arch (Debian filenames drop
//     the epoch, e.g. "emacs-nox_30.1+1-6_amd64.deb" under
//     pool/main/e/emacs/). Source is the Debian *source* package
//     name, which is usually — but not always — the same as Package:
//     emacs-nox/emacs-bin-common/emacs-common are all built from
//     source "emacs"; libgccjit0 is built from source gcc-14,
//     libisl23 from isl, libmpc3 from mpclib3, libmpfr6 from mpfr4,
//     libasound2t64 / libasound2-data from alsa-lib, liblcms2-2
//     from lcms2. The pool path is derived from Source (default:
//     Package); a distroPackage entry whose binary package comes
//     from a differently-named source MUST set Source or its
//     download URL 404s.
//
// SHA256 is REQUIRED on every entry. It must be a 64-char hex digest,
// except for temporary "SHA256_TODO_<name>" markers used while a hash
// is still being resolved from the upstream index — those MUST be
// replaced with the real digest before install, and the daemon MUST
// fail closed (refuse to download/extract) on any entry whose SHA256
// is still a SHA256_TODO_* marker or is not 64 hex chars. The Go
// struct itself cannot enforce this; the TS PluginManifestSchema
// enforces the shape and the daemon must validate before use.
// Kind is "archive" (URL, Format, PathInArchive set; distro fields
// empty), "binary" (URL set; Format, PathInArchive and distro fields
// empty), or "distroPackage" (Distro, Package, Version, Arch set; URL
// empty).
type PluginBundledBinary struct {
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	SHA256        string `json:"sha256"`
	URL           string `json:"url,omitempty"`
	Format        string `json:"format,omitempty"`
	PathInArchive string `json:"pathInArchive,omitempty"`
	// Extract selects the archive extraction mode: "" or "binary"
	// (default — exactly one member, PathInArchive, into bin/) or
	// "tree" (the whole archive into the plugin dir, after
	// stripping StripComponents leading components). Meaningless
	// for kinds other than "archive" and must be empty there.
	Extract string `json:"extract,omitempty"`
	// StripComponents is the number of leading path components
	// stripped from every member during tree extraction. Only
	// meaningful with Extract "tree" and must be 0 otherwise.
	StripComponents int `json:"stripComponents,omitempty"`
	// OSes gates the entry to the listed host OS families. Empty
	// means every OS. A gated-out entry is skipped at install and
	// ignored by verification (see the type doc above).
	OSes    []string `json:"oses,omitempty"`
	Distro  string   `json:"distro,omitempty"`
	Package string   `json:"package,omitempty"`
	Source  string   `json:"source,omitempty"`
	Version string   `json:"version,omitempty"`
	Arch    string   `json:"arch,omitempty"`
}

// bundledEntryAppliesToOS reports whether a bundled-binary entry
// applies on a host of the given OS family: true when the entry
// carries no OS gate, or when the host's family is listed.
func bundledEntryAppliesToOS(b PluginBundledBinary, osFamily string) bool {
	if len(b.OSes) == 0 {
		return true
	}
	for _, o := range b.OSes {
		if o == osFamily {
			return true
		}
	}
	return false
}

// validOSFamilyName reports whether s is a known host OS family
// value (the DetectOSFamily values).
func validOSFamilyName(s string) bool {
	switch s {
	case "debian", "alpine", "arch":
		return true
	}
	return false
}

type PluginStatus struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Version          string   `json:"version"`
	Category         string   `json:"category"`
	Description      string   `json:"description"`
	Author           string   `json:"author"`
	Enabled          bool     `json:"enabled"`
	DefaultEnabled   bool     `json:"defaultEnabled"`
	Dependencies     []string `json:"dependencies,omitempty"`
	Installed        bool     `json:"installed"`
	Bundled          bool     `json:"bundled"`
	RequiredBinaries []string `json:"requiredBinaries"`
	MissingBinaries  []string `json:"missingBinaries"`
	// BundledBinaries names the bundled binaries that verified
	// present under this plugin's own directory (archive entry
	// names, plus required binaries found under BinDirs for
	// distroPackage entries). Empty when the plugin declares no
	// Binaries, or when verification failed — a failed verification
	// must never be reported as a verified bundled binary.
	BundledBinaries []string        `json:"bundledBinaries,omitempty"`
	Packages        []string        `json:"packages"`
	InstalledAt     string          `json:"installedAt,omitempty"`
	SystemdUnits    []string        `json:"systemdUnits"`
	LdapIntegration *PluginLDAPSpec `json:"ldapIntegration,omitempty"`
}

type PluginActionRequest struct {
	PluginID string `json:"pluginId"`
	Action   string `json:"action"` // "install", "uninstall", "reconfigure", "enable", "disable"
}

type PluginActionResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Output  string `json:"output,omitempty"`
}

type PluginManager struct {
	mu           sync.RWMutex
	actionMu     sync.Mutex
	baseDataDir  string
	stateFile    string
	disabledFile string
	osFamily     string
	dirMgr       *DirectoryManager
	installedMap map[string]string // pluginID -> installedAt
	disabledMap  map[string]bool   // pluginID -> explicitly disabled
	// R4-A-M4: the live ThreatHarvesterManager, wired by the daemon
	// at startup. The ebpf-threat-harvester plugin toggle drives the
	// harvester through this (enable starts it, disable stops it) so
	// the toggle can never report success while nothing runs. Nil
	// when the daemon has not wired one (unit tests, tooling) — the
	// toggle then fails closed instead of claiming success.
	harvester *ThreatHarvesterManager
}

func (pm *PluginManager) SetDirectoryManager(dm *DirectoryManager) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.dirMgr = dm
}

// SetThreatHarvesterManager wires the live harvester manager so the
// ebpf-threat-harvester plugin toggle can start/stop it (R4-A-M4).
func (pm *PluginManager) SetThreatHarvesterManager(thm *ThreatHarvesterManager) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.harvester = thm
}

// harvesterManager returns the wired harvester manager, if any.
func (pm *PluginManager) harvesterManager() *ThreatHarvesterManager {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.harvester
}

// setHarvesterEnabled starts or stops the harvester for the
// ebpf-threat-harvester plugin toggle (R4-A-M4). It fails closed when
// no manager is wired — the toggle must not report success while
// nothing runs — and returns the attach error when enabling fails.
func (pm *PluginManager) setHarvesterEnabled(enabled bool) error {
	thm := pm.harvesterManager()
	if thm == nil {
		verb := "disable"
		if enabled {
			verb = "enable"
		}
		return fmt.Errorf("threat harvester manager is not wired to the plugin manager; cannot %s the ebpf-threat-harvester plugin", verb)
	}
	return thm.SetEnabled(enabled)
}

func GetCoreVigilanteLDAPSpec() PluginLDAPSpec {
	return PluginLDAPSpec{
		EnabledByDefault:           true,
		ServiceAccountCN:           "svc-vigilante",
		InheritApplianceRoleGroups: true,
		EnvPrefix:                  "VIGILANTE_LDAP_",
		Groups: []PluginLdapGroupSpec{
			{
				CN:          "vigilante-admin",
				GIDNumber:   10230,
				Description: "Vigilante SOC & SOAR Administrators",
				Role:        "admin",
			},
			{
				CN:          "vigilante-operator",
				GIDNumber:   10231,
				Description: "Vigilante SOC Analysts, Threat Hunters & Incident Responders",
				Role:        "operator",
			},
			{
				CN:          "vigilante-readonly",
				GIDNumber:   10232,
				Description: "Vigilante SOC Read-Only Auditors & Observers",
				Role:        "readonly",
			},
		},
	}
}

func (pm *PluginManager) ensurePluginLDAP(pluginID string) {
	pm.mu.RLock()
	dm := pm.dirMgr
	pm.mu.RUnlock()
	if dm == nil {
		return
	}
	if pluginID == "core-vigilante" || pluginID == "vigilante" {
		spec := GetCoreVigilanteLDAPSpec()
		if _, err := dm.EnsurePluginLDAPIntegration("core-vigilante", spec); err != nil {
			log.Printf("[Plugins] Warning: failed to ensure LDAP integration for %s: %v", pluginID, err)
		}
		return
	}
	defs := GetExtensionPluginDefinitions()
	for _, d := range defs {
		if d.ID == pluginID && d.LdapIntegration != nil {
			if _, err := dm.EnsurePluginLDAPIntegration(pluginID, *d.LdapIntegration); err != nil {
				log.Printf("[Plugins] Warning: failed to ensure LDAP integration for %s: %v", pluginID, err)
			}
			break
		}
	}
}

// GetCorePluginDefinitions returns the Go-side definitions for the
// core-role plugins that declare bundled binaries. Today that is
// only core-k3s.
//
// WHY A SEPARATE LIST, AND WHY ListPlugins DOES NOT CONSULT IT:
// core roles are NOT extension plugins in the daemon API.
// /v1/system/plugins (main.go) returns ListPlugins(), which iterates
// GetExtensionPluginDefinitions() only, and the console renders the
// core roles from the TS BUILTIN_PLUGINS table plus the capabilities
// (k3sEnabled, ...) — the plugins page even special-cases core-k3s
// by id. Adding core-k3s to ListPlugins would duplicate that card
// and change the API shape for a migration whose scope is where the
// binaries live, so ListPlugins stays extension-only and this list
// is consulted ONLY by the bundled-binary machinery, through
// findPluginDefinition: ensureBundledBinaries /
// verifyBundledBinaries, PluginEnv / CommandForPlugin, and the
// core-k3s Reconfigure branch. That is the whole Go-side home of
// the core-k3s definition: one function, mirroring the TS entry in
// packages/axonwall_lib/src/plugins/index.ts (same version, URLs
// and sha256s — the two must stay in sync).
//
// The entry declares NO distroPackage binaries: k3s and k9s are
// upstream release artifacts (a raw binary and a tarball). The
// DebianPackages/AlpinePackages/ArchPackages lists are the OS
// packages the role needs (curl, iptables, open-iscsi), unchanged
// from the TS entry — they are not bundled binaries.
func GetCorePluginDefinitions() []PluginDefinition {
	return []PluginDefinition{
		{
			// Kubernetes (K3s) & OpenEBS Distributed Storage.
			// Version 1.31.2 is the *plugin's* version (TS
			// BUILTIN_PLUGINS), not the k3s binary version
			// (v1.32.3+k3s1) — do not confuse the two.
			//
			// k3s v1.32.3+k3s1 (kind "binary"): upstream ships it
			// as a bare statically-linked binary; the sha256 is
			// the upstream-published digest from
			// https://github.com/k3s-io/k3s/releases/download/v1.32.3%2Bk3s1/sha256sum-amd64.txt
			// and matches the pin the builders carried before
			// this move. k9s v0.51.0 (kind "archive", tar.gz):
			// sha256 is the upstream-published digest for
			// k9s_Linux_amd64.tar.gz from
			// https://github.com/derailed/k9s/releases/download/v0.51.0/checksums.sha256.
			// The tarball's members sit at the top level
			// (LICENSE, README.md, k9s — no wrapping directory,
			// verified 2026-11-20), so PathInArchive defaults
			// to the binary name "k9s".
			ID:               "core-k3s",
			Name:             "Kubernetes (K3s) & OpenEBS Distributed Storage",
			Version:          "1.31.2",
			Category:         "core_role",
			Description:      "Lightweight multi-node Kubernetes control plane with automatic HA second-node cluster join, OpenEBS ZFS-LocalPV, and synchronous 2-node Replicated Persistent Volumes.",
			Author:           "CNCF / OpenEBS / Axonwall Core",
			DefaultEnabled:   true,
			SystemdUnits:     []string{"k3s.service"},
			Privileges:       []string{"k3s.cluster", "storage.openebs"},
			DebianPackages:   []string{"curl", "iptables", "open-iscsi"},
			AlpinePackages:   []string{"curl", "iptables", "open-iscsi"},
			ArchPackages:     []string{"curl", "iptables-nft", "open-iscsi"},
			RequiredBinaries: []string{"k3s", "k9s"},
			Binaries: []PluginBundledBinary{
				{
					Kind:   "binary",
					Name:   "k3s",
					SHA256: "b19216803650b567bf980888dec39035edaf664339c55bc4462f7a003edbef83",
					URL:    "https://github.com/k3s-io/k3s/releases/download/v1.32.3%2Bk3s1/k3s",
				},
				{
					Kind:   "archive",
					Name:   "k9s",
					SHA256: "c3752ad51a5a4015a113819c4eeb6e55a4d0e4b8e652494797532f6fc8161dd7",
					URL:    "https://github.com/derailed/k9s/releases/download/v0.51.0/k9s_Linux_amd64.tar.gz",
					Format: "tar.gz",
				},
			},
			BinDirs: []string{"bin"},
		},
	}
}

// findPluginDefinition returns the definition for any known plugin
// id — core first, then extension — or false when the id is unknown
// to both lists. The bundled-binary machinery (PluginEnv,
// CommandForPlugin, ensureBundledBinaries) uses this so core-k3s
// resolves through the same path as extension plugins; callers
// that are extension-only by design (ListPlugins, the LDAP loops)
// keep using GetExtensionPluginDefinitions() directly.
func findPluginDefinition(pluginID string) (PluginDefinition, bool) {
	for _, d := range GetCorePluginDefinitions() {
		if d.ID == pluginID {
			return d, true
		}
	}
	return findExtensionPluginDefinition(pluginID)
}

func GetExtensionPluginDefinitions() []PluginDefinition {
	return []PluginDefinition{
		{
			ID:             "cli-workstation",
			Name:           "Modern Operator Shell & Editor (ZSH, Oh My Zsh, Starship, VIM & Neovim Super Configurator)",
			Version:        "1.2.0",
			Category:       "extension",
			Description:    "Enabled by default: first-class shell environment with ZSH, Oh My Zsh (https://ohmyz.sh), Starship cyber-emerald prompt, Neovim Super Configurator (axonwall-config / nui — zero-chrome Lua form TUI with full Vim motions), VIM syntax defaults, Tmux multiplexer, and deep stack autocompletions (kubectl, helm, k3s, zfs/zpool, nftables, wireguard, rosenpass, virsh, lxc, axonwallctl, axonwall-tui, axonwall-config). Can be disabled to minimize attack surface.",
			Author:         "Axonwall Core",
			DefaultEnabled: true,
			Privileges:     []string{"system.users", "system.hardware"},
			// VIM + NEOVIM ARE BUNDLED, NOT SYSTEM-INSTALLED — Debian
			// only (coordinator decisions 1–2, 2026-11-20). vim is
			// DROPPED entirely: vi/vim become symlinks to the
			// bundled nvim in the plugin's bin/ dir (see
			// ensureWorkstationNvimSymlinks), so the vim .deb set
			// (vim + vim-runtime + vim-common + libgpm2 +
			// libsodium23) is not bundled — neovim is already the
			// default editor and vim.basic adds nothing once vi/vim
			// point at nvim. DebianPackages therefore drops "vim"
			// and "neovim" below; AlpinePackages/ArchPackages keep
			// them (old behavior) because the nvim tarball is
			// glibc-linked and cannot run on Alpine (musl), and
			// the archive entry is gated to debian via OSes — on
			// Alpine/Arch it is skipped at install and ignored by
			// verification, and vim/nvim keep resolving from the
			// system packages.
			//
			// CHECKSUM CAVEAT: neovim publishes NO checksum for
			// this tarball (no .sha256, no SHA256SUMS, no hash in
			// the release notes — checked for v0.12.6 and the four
			// releases before it, 2026-11-20). The sha256 below
			// was computed locally from the bytes GitHub served
			// for that asset URL on 2026-11-20 (asset size
			// 11,404,582 bytes; re-verified against the research
			// scratch copy). Do NOT claim it is an official
			// published checksum — it is not published anywhere
			// upstream. If the release asset were ever replaced,
			// the pinned hash fails closed, as intended.
			//
			// TREE, NOT SINGLE BINARY: nvim alone is not a
			// working install — it needs share/nvim/runtime and
			// lib/nvim/parser/*.so from the same tarball (verified
			// live 2026-11-20: bin/nvim needs only libm/libgcc_s/
			// libc, all in the base image, and resolves its
			// runtime relative to its own location). Extract
			// "tree" with StripComponents 1 strips the tarball's
			// single top-level dir ("nvim-linux-x86_64/") so the
			// tree lands at <plugindir>/bin/nvim,
			// <plugindir>/lib/..., <plugindir>/share/... ; the
			// whole tree (2,228 files, ~40 MB extracted) is
			// recorded in bundled.json and re-verified on use.
			// RequiredBinaries keeps listing "vim" and "nvim":
			// both resolve via the plugin-local lookup
			// (hasPluginBinaryForPlugin checks BinDirs with
			// os.Stat, which follows the vi/vim symlinks to the
			// executable nvim), and on Alpine/Arch they resolve
			// from the system PATH as before.
			DebianPackages: []string{
				"zsh",
				"starship",
				"tmux",
				"zsh-autosuggestions",
				"zsh-syntax-highlighting",
				"fzf",
				"zoxide",
				"bat",
				"ripgrep",
				"fd-find",
				"git",
				"kubectl",
			},
			AlpinePackages: []string{
				"zsh",
				"vim",
				"neovim",
				"starship",
				"tmux",
				"zsh-vcs",
				"fzf",
				"zoxide",
				"bat",
				"ripgrep",
				"fd",
				"git",
				"kubectl",
			},
			ArchPackages: []string{
				"zsh",
				"vim",
				"neovim",
				"starship",
				"tmux",
				"zsh-autosuggestions",
				"zsh-syntax-highlighting",
				"fzf",
				"zoxide",
				"bat",
				"ripgrep",
				"fd",
				"git",
				"kubectl",
				"helm",
			},
			RequiredBinaries: []string{"zsh", "vim", "nvim", "starship", "tmux"},
			Binaries: []PluginBundledBinary{
				{
					Kind:            "archive",
					Name:            "nvim",
					SHA256:          "474430d53e6264f6d6dd18db42d6dc9df3a1b56ca9e88a325bbf860e1a811d87",
					URL:             "https://github.com/neovim/neovim/releases/download/v0.12.6/nvim-linux-x86_64.tar.gz",
					Format:          "tar.gz",
					Extract:         "tree",
					StripComponents: 1,
					OSes:            []string{"debian"},
				},
			},
			BinDirs: []string{"bin"},
		},
		{
			// GNU Emacs, bundled — not system-installed. The trixie
			// amd64 .debs are downloaded, sha256-verified, and
			// extracted (dpkg-deb -x layout) into the plugin's own
			// directory; nothing is installed into the system, so
			// DebianPackages/AlpinePackages/ArchPackages are
			// deliberately empty (ArchPackages is an empty slice, not
			// nil, per TestArchPluginPackagesAndRootkitScannerSlot).
			//
			// VERSION DEVIATION (coordinator decision): pinned
			// 1:30.1+1-6+deb13u1, the current trixie security
			// update, NOT the 1:30.1+1-6 named in the original
			// plan — 1:30.1+1-6 is superseded and only available
			// from snapshot.debian.org now. All sha256s below were
			// verified by downloading the .debs and hashing locally
			// against the live trixie Packages index (research
			// notes 2026-11-20).
			//
			// The three emacs .debs alone do NOT run: the extracted
			// binary is usr/bin/emacs-nox (dpkg-deb -x runs no
			// maintainer scripts, so there is no /usr/bin/emacs
			// alternatives symlink — bin/emacs is a launcher
			// written at install time, see provisionEmacsPluginFiles)
			// and it hard-links libgccjit.so.0, libasound.so.2 and
			// liblcms2.so.2, none of which are in the base image.
			// So the bundle also carries libgccjit0 (+ its .so
			// deps libisl23, libmpc3, libmpfr6 — libgmp10,
			// libzstd1 and zlib1g are already in the image),
			// libasound2t64 (+ tiny libasound2-data) and
			// liblcms2-2. The lib .debs' binary packages are built
			// from differently-named source packages, hence the
			// Source field on each (pool path is derived from it).
			// Full bundle: ~35.6 MB download, ~169 MB on disk.
			//
			// emacs-el is deliberately SKIPPED: it is only the
			// .el sources (19.5 MB download / 19.7 MB disk) — the
			// .elc files live in emacs-common itself. Trade-off:
			// describe-function cannot show Lisp sources and user
			// code cannot byte-compile against those sources.
			//
			// Native-comp is UNVERIFIED with just this .so set:
			// libgccjit compiles in-process, but Emacs native-comp
			// also invokes the assembler/linker for the final .eln
			// link step and gcc-14/cc1 is NOT in the base image.
			// A live-box test must byte+natively compile a trivial
			// .el file; if it fails, the fallback is
			// native-comp-jit-compilation nil (byte-compiled only).
			// VERIFIED 2026-11-20 (live extraction + run): JIT
			// compilation of new code FAILS at the link step —
			// "ld: cannot find crtbeginS.o" (a gcc-14 /
			// libgcc-14-dev file, not bundled, and bundling a
			// compiler toolchain onto the appliance is out of
			// scope). The plugin therefore ships byte-compiled
			// only: init.el sets native-comp-jit-compilation to
			// nil, so emacs never attempts a JIT compile (and
			// never shows the ld error); the prebuilt .eln files
			// for the preloaded libs still load, and
			// native-comp-available-p reports t.
			ID:               "cli-emacs",
			Name:             "Emacs Editor (GNU Emacs, no-X) for /etc/axonwall",
			Version:          "0.1.0",
			Category:         "extension",
			Description:      "GNU Emacs (no-X) for editing /etc/axonwall configuration files, bundled with the plugin: the Debian emacs-nox 30.1 tree plus its missing shared libraries are downloaded, checksum-verified, and extracted into the plugin's own directory, and its bin directory is added to PATH for daemon invocations and interactive shells. Nothing is installed into the system.",
			Author:           "Axonwall Core",
			Privileges:       []string{"system.users", "system.config.write"},
			DebianPackages:   []string{},
			AlpinePackages:   []string{},
			ArchPackages:     []string{},
			RequiredBinaries: []string{"emacs", "emacs-nox"},
			Binaries: []PluginBundledBinary{
				{
					Kind:    "distroPackage",
					Name:    "emacs-nox",
					SHA256:  "fee9e5bc5d4c0da716e3e12eee8e1b063bd24a58a6ca6755be2516b377d50364",
					Distro:  "debian",
					Package: "emacs-nox",
					Source:  "emacs",
					Version: "1:30.1+1-6+deb13u1",
					Arch:    "amd64",
				},
				{
					Kind:    "distroPackage",
					Name:    "emacs-bin-common",
					SHA256:  "86ad88ffb8d0024fe22a4b95863918655ecb10523c4bcdd199540da75f67c4db",
					Distro:  "debian",
					Package: "emacs-bin-common",
					Source:  "emacs",
					Version: "1:30.1+1-6+deb13u1",
					Arch:    "amd64",
				},
				{
					Kind:    "distroPackage",
					Name:    "emacs-common",
					SHA256:  "1a20b06410720a432bd6c82a455a919b7083011e02a3c7b46243e65d8582791b",
					Distro:  "debian",
					Package: "emacs-common",
					Source:  "emacs",
					Version: "1:30.1+1-6+deb13u1",
					Arch:    "all",
				},
				{
					Kind:    "distroPackage",
					Name:    "libgccjit0",
					SHA256:  "cab79f341f9b1ee14a03bc6ca1c1ecdb2d52b2a346d1e011c47682e5f45453f9",
					Distro:  "debian",
					Package: "libgccjit0",
					Source:  "gcc-14",
					Version: "14.2.0-19",
					Arch:    "amd64",
				},
				{
					Kind:    "distroPackage",
					Name:    "libisl23",
					SHA256:  "ac8518042e81c00de1effb72bba7e88ac4ecd488f7ea8b9e3ebc63159cb53b35",
					Distro:  "debian",
					Package: "libisl23",
					Source:  "isl",
					Version: "0.27-1",
					Arch:    "amd64",
				},
				{
					Kind:    "distroPackage",
					Name:    "libmpc3",
					SHA256:  "2af0a5c128e03694a41c0b011bd8a958b7297436cdb3a15ddad7866dae8c300b",
					Distro:  "debian",
					Package: "libmpc3",
					Source:  "mpclib3",
					Version: "1.3.1-1+b3",
					Arch:    "amd64",
				},
				{
					Kind:    "distroPackage",
					Name:    "libmpfr6",
					SHA256:  "75dddce11dabc7fc543712c33dc27b7f2ee66a111763eb5eac654d010b42cd92",
					Distro:  "debian",
					Package: "libmpfr6",
					Source:  "mpfr4",
					Version: "4.2.2-1",
					Arch:    "amd64",
				},
				{
					Kind:    "distroPackage",
					Name:    "libasound2t64",
					SHA256:  "5495496142d57e5ad6d581ac5456ec3c87f872c109a2bfb815d154b673eebc67",
					Distro:  "debian",
					Package: "libasound2t64",
					Source:  "alsa-lib",
					Version: "1.2.14-1+deb13u1",
					Arch:    "amd64",
				},
				{
					Kind:    "distroPackage",
					Name:    "libasound2-data",
					SHA256:  "04688afdff3769c0f685541daed7b2f6f0cb946799ddf1d5847ddf11fe245559",
					Distro:  "debian",
					Package: "libasound2-data",
					Source:  "alsa-lib",
					Version: "1.2.14-1+deb13u1",
					Arch:    "all",
				},
				{
					Kind:    "distroPackage",
					Name:    "liblcms2-2",
					SHA256:  "32e53c2002ccea8c60c02779bea0ba49ac132fef702988a30d64af79b6617806",
					Distro:  "debian",
					Package: "liblcms2-2",
					Source:  "lcms2",
					Version: "2.16-2+deb13u2",
					Arch:    "amd64",
				},
			},
			// bin/ first: the bin/emacs launcher (written at
			// install time) wins over the raw usr/bin/emacs-nox
			// for PATH resolution and for RequiredBinaries checks.
			BinDirs: []string{"bin", "usr/bin"},
			Env: map[string]string{
				// EMACSDATA is the *etc* directory, not the
				// version directory: data-directory IS the etc
				// dir (GNU Emacs FAQ), and the startup charsets
				// check looks for <EMACSDATA>/charsets — i.e.
				// <plugindir>/usr/share/emacs/30.1/etc/charsets.
				// Pointing it at the version dir makes that check
				// fail ("Emacs will not function correctly
				// without the character map files"), verified
				// live 2026-11-20.
				"EMACSDATA": "${PLUGIN_DIR}/usr/share/emacs/30.1/etc",
				// EMACSPATH is the arch-dependent (libexec) dir:
				// it silences the "arch-dependent data dir"
				// warning and lets emacs find hexl/rcs2log. It
				// does NOT redirect the pdmp lookup — the pdmp
				// is only found next to the binary or at the
				// compiled-in libexec path, so install time
				// symlinks it to usr/bin/emacs-nox.pdmp (see
				// provisionEmacsPluginFiles).
				"EMACSPATH": "${PLUGIN_DIR}/usr/libexec/emacs/30.1/x86_64-linux-gnu",
				// EMACSLOADPATH is the lisp tree: the dumped
				// load-path still names the compiled-in
				// /usr/share/emacs/30.1/lisp, which does not
				// exist on the appliance, so without this emacs
				// cannot find simple.el or any mode (verified
				// live 2026-11-20). Startup adds the lisp
				// subdirectories (progmodes, textmodes, vc, ...)
				// automatically; only the two top dirs are needed.
				"EMACSLOADPATH": "${PLUGIN_DIR}/usr/share/emacs/30.1/lisp:${PLUGIN_DIR}/usr/share/emacs/site-lisp",
				// The bundled lib .debs extract to
				// <plugindir>/usr/lib/x86_64-linux-gnu/ — the
				// loader does NOT search there by default, so
				// daemon invocations need it on
				// LD_LIBRARY_PATH. The bin/emacs launcher sets
				// the same value for interactive shells (the
				// shell PATH snippets carry PATH only, not Env).
				"LD_LIBRARY_PATH": "${PLUGIN_DIR}/usr/lib/x86_64-linux-gnu",
			},
		},
		{
			// Doom Emacs, sharing the cli-emacs binary — no second
			// copy of the emacs binary/data tree (there is no
			// Binaries entry for emacs here, by design; the
			// bin/emacs-doom launcher execs the sibling cli-emacs
			// plugin's usr/bin/emacs-nox). dependencies:
			// ["cli-emacs"] activates the generic guard in
			// enabledDependentsOf: cli-emacs cannot be disabled
			// or uninstalled while this plugin is enabled. Install
			// also fails closed without cli-emacs present (see
			// installDoomEmacs).
			//
			// PINS (observed by cloning upstream 2026-11-20; see
			// plugin_emacs_doom_spacemacs.go):
			//   doomemacs/core    eab52d2fe5e58303696e129717553ec5bf031bb0 (2026-11-15)
			//   doomemacs/modules f054be8fcdd2a0446eb8259d76dd4f6f76acc0b7 (2026-11-03)
			//   bundled emacs     30.1 (the cli-emacs tree; Doom
			//                       supports 27.1-31.1)
			// Doom pins are real: every package carries a :pin in
			// its module's packages.el and `doom sync` (run at
			// install time) respects them, so the pinned
			// (core + modules) pair determines the package set.
			// The modules library ships as a git submodule of core
			// (sources/doom+); install populates it explicitly
			// and verifies it landed on the pinned commit.
			//
			// DECISIONS: no evil (operators are emacs-preferring;
			// one-line change to add (evil +everywhere)); no +lsp
			// and no vterm (no Node/npm or cmake/libtool on the
			// box); no flycheck (its YAML/JSON checkers need
			// yamllint/js-yaml/node); no -nw forced (the operator
			// chooses). Module set: completion corfu+vertico, ui
			// doom hl-todo, emacs dired electric undo vc, term
			// eshell, tools magit editorconfig, os tty, lang data
			// emacs-lisp json sh yaml, config default+bindings+
			// smartparens. :lang data covers csv-mode only at the
			// pinned modules commit; TOML/.env/Caddyfile/Lua are
			// covered by guards in config.el.
			//
			// UNVERIFIED (recorded, not claimed): that `doom sync`
			// runs non-interactively in practice; `doom doctor`
			// behaviour on Emacs 30.1 at the pinned commit; the
			// magit full-clone handling and download size; the
			// installed straight-tree size; the fd/fdfind name
			// question. A live first launch of emacs-doom on the
			// box is still mandatory.
			//
			// No system packages, no systemd units, no menu entry.
			// Binaries are deliberately absent (see above);
			// BinDirs ["bin"] is the launcher dir, added to PATH
			// for daemon invocations and interactive shells.
			// Reconfigure does not restore a deleted launcher or
			// config — only a reinstall does.
			ID:               "cli-emacs-doom",
			Name:             "Doom Emacs for /etc/axonwall",
			Version:          "0.1.0",
			Category:         "extension",
			Description:      "Doom Emacs for editing /etc/axonwall configuration files, sharing the cli-emacs bundled GNU Emacs 30.1 binary: the Doom core and modules are cloned at pinned commits and packages installed with doom sync at install time. No evil mode (operators are emacs-preferring), no LSP or vterm (no language servers or C toolchain on the box).",
			Author:           "Axonwall Core",
			Dependencies:     []string{"cli-emacs"},
			Privileges:       []string{"system.users", "system.config.write"},
			DebianPackages:   []string{},
			AlpinePackages:   []string{},
			ArchPackages:     []string{},
			RequiredBinaries: []string{"emacs-doom"},
			BinDirs:          []string{"bin"},
		},
		{
			// Spacemacs (develop branch), sharing the cli-emacs
			// binary — no second copy of the emacs binary/data
			// tree (no Binaries entry for emacs here, by design;
			// the bin/emacs-spacemacs launcher execs the sibling
			// cli-emacs plugin's usr/bin/emacs-nox). dependencies:
			// ["cli-emacs"] activates the generic guard in
			// enabledDependentsOf; install also fails closed
			// without cli-emacs present (see
			// installSpacemacsEmacs).
			//
			// PIN (observed by cloning upstream 2026-11-20; see
			// plugin_emacs_doom_spacemacs.go):
			//   syl20bnr/spacemacs develop
			//     1f69b2a854a7a46f709def08412dbd5d6dc073a1 (2026-11-09)
			//   bundled emacs 30.1 (Spacemacs requires 28.2+ with
			//     no stated upper bound; there is NO explicit
			//     upstream "supports Emacs 30.1" statement — a
			//     first-start smoke test on the box is mandatory).
			//
			// LATEST-AT-INSTALL, NOT PINNED: Spacemacs has no
			// per-package version pinning (upstream issue #6531).
			// Only the Spacemacs commit is pinned; first start
			// downloads the latest snapshot of every layer package
			// from MELPA/GNU ELPA and needs network. Do not
			// describe this install as pinned. The
			// vendored-elpa-snapshot follow-up (ship a built elpa/
			// tree with sha256s) is what would make it
			// reproducible; it is NOT done on this branch.
			// Install does NOT attempt a first start or a package
			// install; the pre-seeded dotfile is the attempt at
			// suppressing the first-start wizard, and whether it
			// fully suppresses it is UNVERIFIED.
			//
			// DECISIONS: editing style 'emacs, NOT vim (operators
			// are emacs-preferring; 'vim would pull the evil
			// stack); distribution 'spacemacs (default;
			// 'spacemacs-base is an unverified slimming option);
			// shell layer uses eshell, NEVER vterm (needs
			// cmake/libtool); prettier-js/web-beautify excluded
			// (need Node). Layer set: helm, auto-completion,
			// better-defaults, emacs-lisp, git, version-control,
			// shell (eshell), syntax-checking, yaml, json. No
			// -nw forced (the operator chooses). Install fails
			// closed if ~/.spacemacs exists (it always wins over
			// SPACEMACSDIR).
			//
			// No system packages, no systemd units, no menu entry.
			// Binaries are deliberately absent (see above);
			// BinDirs ["bin"] is the launcher dir. Reconfigure
			// does not restore a deleted launcher or dotfile —
			// only a reinstall does.
			ID:               "cli-emacs-spacemacs",
			Name:             "Spacemacs for /etc/axonwall",
			Version:          "0.1.0",
			Category:         "extension",
			Description:      "Spacemacs (develop branch) for editing /etc/axonwall configuration files, sharing the cli-emacs bundled GNU Emacs 30.1 binary. The Spacemacs core is cloned at a pinned commit; its packages are downloaded from MELPA/GNU ELPA on first start (latest versions — Spacemacs cannot pin package versions), so a first start needs network. Emacs editing style, not vim.",
			Author:           "Axonwall Core",
			Dependencies:     []string{"cli-emacs"},
			Privileges:       []string{"system.users", "system.config.write"},
			DebianPackages:   []string{},
			AlpinePackages:   []string{},
			ArchPackages:     []string{},
			RequiredBinaries: []string{"emacs-spacemacs"},
			BinDirs:          []string{"bin"},
		},
		{
			ID:               "cli-diagnostics-nastymap",
			Name:             "NastyMap & Live CLI Telemetry Suite",
			Version:          "1.0.0",
			Category:         "extension",
			Description:      "Autonomous host discovery and vulnerability auditing with NastyMap & Nmap, plus real-time system/network monitors (btop, htop, iftop, iotop, slurm, sysstat, dnsutils).",
			Author:           "Axonwall Core / NastyMap",
			Privileges:       []string{"system.monitoring", "network.interfaces"},
			DebianPackages:   []string{"nmap", "dnsutils", "net-tools", "btop", "htop", "iftop", "iotop", "slurm", "sysstat"},
			AlpinePackages:   []string{"nmap", "bind-tools", "net-tools", "btop", "htop", "iftop", "iotop", "slurm", "sysstat"},
			ArchPackages:     []string{"nmap", "bind", "net-tools", "btop", "htop", "iftop", "iotop", "sysstat"},
			RequiredBinaries: []string{"nmap", "dig", "netstat", "btop", "htop", "iftop", "iostat", "mpstat"},
		},
		{
			ID:               "haproxy",
			Name:             "HAProxy Load Balancer & Reverse Proxy",
			Version:          "2.8.3",
			Category:         "extension",
			Description:      "High performance TCP/HTTP load balancer, reverse proxy, and SSL/TLS termination with ACME integration.",
			Author:           "HAProxy Technologies / Axonwall Core",
			SystemdUnits:     []string{"haproxy.service"},
			Privileges:       []string{"services.haproxy", "system.certificates"},
			DebianPackages:   []string{"haproxy"},
			AlpinePackages:   []string{"haproxy"},
			ArchPackages:     []string{"haproxy"},
			RequiredBinaries: []string{"haproxy"},
		},
		{
			ID:               "freeradius",
			Name:             "FreeRADIUS AAA Suite",
			Version:          "3.2.3",
			Category:         "extension",
			Description:      "High-performance RADIUS authentication and accounting server integrated with internal OpenLDAP.",
			Author:           "Network RADIUS / Axonwall Core",
			SystemdUnits:     []string{"freeradius.service"},
			Privileges:       []string{"services.freeradius", "system.users"},
			DebianPackages:   []string{"freeradius", "freeradius-ldap"},
			AlpinePackages:   []string{"freeradius"},
			ArchPackages:     []string{"freeradius"},
			RequiredBinaries: []string{"freeradius"},
			LdapIntegration: &PluginLDAPSpec{
				EnabledByDefault:           true,
				ServiceAccountCN:           "svc-freeradius",
				InheritApplianceRoleGroups: true,
				EnvPrefix:                  "FREERADIUS_LDAP_",
				Groups: []PluginLdapGroupSpec{
					{
						CN:          "radius-users",
						GIDNumber:   10210,
						Description: "FreeRADIUS 802.1X and VPN Authenticated Users",
						Role:        "operator",
					},
				},
			},
		},
		{
			ID:               "snmp",
			Name:             "Net-SNMP Daemon & MIBs",
			Version:          "5.9.3",
			Category:         "extension",
			Description:      "SNMPv2c and SNMPv3 monitoring agent with standard MIBs for network management systems.",
			Author:           "Net-SNMP Team / Axonwall Core",
			SystemdUnits:     []string{"snmpd.service"},
			Privileges:       []string{"system.monitoring"},
			DebianPackages:   []string{"snmpd", "snmp"},
			AlpinePackages:   []string{"net-snmp"},
			ArchPackages:     []string{"net-snmp"},
			RequiredBinaries: []string{"snmpd"},
		},
		{
			ID:               "nut-ups",
			Name:             "Network UPS Tools (NUT)",
			Version:          "2.8.0",
			Category:         "extension",
			Description:      "Reliable UPS monitoring and automated graceful shutdown for battery backups over USB and serial.",
			Author:           "NUT Project / Axonwall Core",
			SystemdUnits:     []string{"nut-server.service", "nut-client.service"},
			Privileges:       []string{"system.hardware", "system.power"},
			DebianPackages:   []string{"nut-server", "nut-client"},
			AlpinePackages:   []string{"nut"},
			ArchPackages:     []string{"nut"},
			RequiredBinaries: []string{"upsd"},
		},
		{
			ID:               "headscale",
			Name:             "Headscale Mesh VPN Coordination Server",
			Version:          "0.29.4",
			Category:         "extension",
			Description:      "Self-hosted, open source WireGuard mesh coordination server with MagicDNS, multi-tenant namespaces, and route distribution.",
			Author:           "Juan Font / Axonwall Core",
			SystemdUnits:     []string{"headscale.service"},
			Privileges:       []string{"vpn.admin", "network.interfaces"},
			DebianPackages:   []string{},
			AlpinePackages:   []string{},
			ArchPackages:     []string{},
			RequiredBinaries: []string{"headscale"},
		},
		{
			ID:               "tailscale",
			Name:             "Tailscale Mesh VPN",
			Version:          "1.74.0",
			Category:         "extension",
			Description:      "Zero-config WireGuard mesh VPN for secure fleet connectivity and subnet routing.",
			Author:           "Tailscale Inc. / Axonwall Community",
			SystemdUnits:     []string{"tailscaled.service"},
			Privileges:       []string{"vpn.tailscale", "network.interfaces"},
			DebianPackages:   []string{"tailscale"},
			AlpinePackages:   []string{"tailscale"},
			ArchPackages:     []string{"tailscale"},
			RequiredBinaries: []string{"tailscaled", "tailscale"},
		},
		{
			ID:               "ntopng",
			Name:             "ntopng High-Speed Flow Analysis",
			Version:          "5.6.0",
			Category:         "extension",
			Description:      "Next-generation web-based traffic analysis and flow visibility.",
			Author:           "ntop / Axonwall Community",
			SystemdUnits:     []string{"ntopng.service"},
			Privileges:       []string{"reporting.flows", "system.monitoring"},
			DebianPackages:   []string{"ntopng"},
			AlpinePackages:   []string{"ntopng"},
			ArchPackages:     []string{"ntopng"},
			RequiredBinaries: []string{"ntopng"},
		},
		{
			ID:               "rosenpass",
			Name:             "Rosenpass Post-Quantum WireGuard (McEliece + ML-KEM)",
			Version:          "0.2.3",
			Category:         "extension",
			Description:      "Hybrid Dual-KEM post-quantum key exchange daemon (Classic McEliece 460896 static authentication + ephemeral ML-KEM-512 forward secrecy) that rotates kernel WireGuard pre-shared keys every 120s with fail-closed boot protection.",
			Author:           "Rosenpass Project / Axonwall Core",
			SystemdUnits:     []string{"rosenpass.service"},
			Privileges:       []string{"vpn.admin", "network.interfaces"},
			DebianPackages:   []string{"wireguard-tools"},
			AlpinePackages:   []string{"rosenpass", "wireguard-tools"},
			ArchPackages:     []string{"rosenpass", "wireguard-tools"},
			RequiredBinaries: []string{"rosenpass", "wg"},
			// Bundled (was: unverified `curl | tar` into
			// /usr/local/bin at install time). The v0.2.3 release
			// tarball is now downloaded, sha256-verified, and
			// extracted into the plugin's own directory
			// (<plugindir>/bin/rosenpass); the systemd unit's
			// ExecStart points there, and gen-keys runs the
			// plugin-dir binary (see rosenpass.go). Behaviour
			// change: the binary moves from /usr/local/bin to the
			// plugin dir; same version (0.2.3), same unit
			// semantics. Uninstall removes the legacy
			// /usr/local/bin/rosenpass and /usr/local/bin/rp if
			// present.
			//
			// CHECKSUM CAVEAT: rosenpass publishes NO checksum
			// for this tarball (no .sha256, no SHA256SUMS, no hash
			// in the release notes — verified 2026-11-20). The
			// sha256 below was computed locally from the bytes
			// GitHub served for that asset URL on 2026-11-20
			// (asset size 4,802,560 bytes). Do NOT claim it is an
			// official published checksum — it is not published
			// anywhere upstream. If the release asset were ever
			// replaced, the pinned hash fails closed, as intended.
			//
			// No second entry for `rp`: the tarball also contains
			// bin/rp (a Bourne shell script), but `rp` is used
			// nowhere in the codebase — the only reference was
			// the old curl|tar copy block — so it is not bundled.
			Binaries: []PluginBundledBinary{
				{
					Kind:          "archive",
					Name:          "rosenpass",
					SHA256:        "53158a8c339e3be1a9520b91c33a9e83eab05ea49af346cdb7e6eec522f2318b",
					URL:           "https://github.com/rosenpass/rosenpass/releases/download/v0.2.3/rosenpass-x86_64-linux-0.2.3.tar",
					Format:        "tar",
					PathInArchive: "bin/rosenpass",
				},
			},
			BinDirs: []string{"bin"},
		},
		{
			ID:               "vigilant-octo-waffle",
			Name:             "Vigilant Octo Waffle (K8s GitOps & App Platform)",
			Version:          "1.0.0",
			Category:         "extension",
			Description:      "Cloud-native Kubernetes GitOps & App Platform for K3s with dual ArgoCD + FluxCD runners (automatic Argo-to-Flux synthesis), 45+ curated apps (Harbor, Rancher, Keycloak, OpenBao, Supabase, Kubeflow, Ollama, vLLM, Nextcloud), Waffle Blueprints, local mkcert TLS + Unbound DNS auto-zones, and 33-permission CASL authorization.",
			Author:           "DeployCoop / Axonwall Core",
			Dependencies:     []string{"core-k3s"},
			SystemdUnits:     []string{"k3s.service"},
			Privileges:       []string{"k3s.cluster", "services.vow", "security.certificates", "services.dns"},
			DebianPackages:   []string{"kubectl", "mkcert", "libnss3-tools", "gettext-base", "git", "curl", "jq"},
			AlpinePackages:   []string{"kubectl", "mkcert", "nss-tools", "gettext", "git", "curl", "jq"},
			ArchPackages:     []string{"kubectl", "helm", "mkcert", "nss", "gettext", "git", "curl", "jq"},
			RequiredBinaries: []string{"kubectl", "helm", "mkcert", "git", "envsubst"},
			LdapIntegration: &PluginLDAPSpec{
				EnabledByDefault:           true,
				ServiceAccountCN:           "svc-vow",
				InheritApplianceRoleGroups: true,
				EnvPrefix:                  "VOW_LDAP_",
				Groups: []PluginLdapGroupSpec{
					{
						CN:          "vow-admin",
						GIDNumber:   10220,
						Description: "Vigilant Octo Waffle Platform Administrators",
						Role:        "admin",
					},
					{
						CN:          "vow-operator",
						GIDNumber:   10221,
						Description: "Vigilant Octo Waffle GitOps & Workload Operators",
						Role:        "operator",
					},
					{
						CN:          "vow-readonly",
						GIDNumber:   10222,
						Description: "Vigilant Octo Waffle Read-Only Viewers",
						Role:        "readonly",
					},
				},
			},
		},
		{
			ID:             "host-malware-rootkit",
			Name:           "Host Malware, Rootkit & Ghost-in-the-Ring Kernel Hunter",
			Version:        "1.0.0",
			Category:       "extension",
			DefaultEnabled: true,
			Description:    "Defense-in-depth host malware, rootkit, and Ring-0 implant suite combining classic scanners (rkhunter, chkrootkit, ClamAV, AIDE, Lynis, YARA, unhide, debsums) with Ghost-in-the-Ring telemetry: io_uring SQPOLL/FIXED_FILE implant hunting (Curing/RingReaper), drgn /proc/kcore prog_idr XArray vs sys_bpf diffing for self-hiding eBPF rootkits (TripleCross/Boopkit/Symbiote), Silicon PMU LBR/BRS branch tracing, and preventive BPF_LSM + sysctl kernel lockdown.",
			Author:         "Tekromancy / Axonwall Core",
			SystemdUnits:   []string{"clamav-freshclam.service"},
			Privileges:     []string{"security.forensics", "system.hardware", "system.monitoring"},
			DebianPackages: []string{
				"rkhunter",
				"chkrootkit",
				"clamav",
				"clamav-freshclam",
				"lynis",
				"aide",
				"yara",
				"unhide",
				"debsums",
				"bpftool",
				"bpftrace",
				"python3-drgn",
				"linux-perf",
			},
			AlpinePackages: []string{
				"rkhunter",
				"chkrootkit",
				"clamav",
				"lynis",
				"aide",
				"yara",
				"bpftool",
				"bpftrace",
				"perf",
			},
			ArchPackages: []string{
				"rkhunter",
				"chkrootkit",
				"clamav",
				"lynis",
				"aide",
				"yara",
				"bpf",
				"bpftrace",
				"perf",
			},
			RequiredBinaries: []string{"rkhunter", "chkrootkit", "yara", "unhide", "debsums"},
		},
		{
			ID:               "eluvix",
			Name:             "Eluvix Sovereign AI Router, Enterprise Tokenomics & Prompt/PII Guard",
			Version:          "1.0.0",
			Category:         "extension",
			DefaultEnabled:   false,
			Description:      "Enterprise-wide LLM routing gateway (git@github.com:Eluvixrouter/eluvix.git) delivering up to 85% tokenomics savings via Switchyard cost-complexity routing, sub-2ms Semantic Caching, and DeepSeek MLA FP8 / RDMA KV-cache disaggregation (vLLM NIXL & SGLang Mooncake), paired with inline PromptGuard injection defense, PrivacyGuard PII/secret DLP redaction, confidential TEE attestation, and an 8-harness agent mesh (OpenCode, ACP, TrueForge, OpenHands, Mastra, Letta, A2A, Hermes).",
			Author:           "Eluvix Router / Axonwall Core",
			SystemdUnits:     []string{"eluvix.service"},
			Privileges:       []string{"system.ai", "security.forensics", "services.dns"},
			DebianPackages:   []string{"nodejs", "git", "curl", "jq", "sqlite3"},
			AlpinePackages:   []string{"nodejs", "git", "curl", "jq", "sqlite"},
			ArchPackages:     []string{"nodejs", "git", "curl", "jq", "sqlite"},
			RequiredBinaries: []string{"node", "git"},
			LdapIntegration: &PluginLDAPSpec{
				EnabledByDefault:           true,
				ServiceAccountCN:           "svc-eluvix",
				InheritApplianceRoleGroups: true,
				EnvPrefix:                  "ELUVIX_LDAP_",
				Groups: []PluginLdapGroupSpec{
					{
						CN:          "eluvix-admin",
						GIDNumber:   10200,
						Description: "Eluvix AI Router Full Administrators",
						Role:        "admin",
					},
					{
						CN:          "eluvix-operator",
						GIDNumber:   10201,
						Description: "Eluvix AI Router Operators (Chat & Playground)",
						Role:        "operator",
					},
					{
						CN:          "eluvix-readonly",
						GIDNumber:   10202,
						Description: "Eluvix AI Router Read-Only Auditors",
						Role:        "readonly",
					},
				},
			},
		},
		{
			ID:               "ebpf-threat-harvester",
			Name:             "eBPF Threat-LLM Harvester (Blackbox)",
			Version:          "1.0.0",
			Category:         "extension",
			DefaultEnabled:   false,
			Description:      "Extreme multi-plane CO-RE eBPF flight recorder (tcx ingress/egress, socket_cookie + cgroup_id process/memfd lineage, and guarded TLS uprobes) that correlates Gold honeypot/LSM and Silver IDS/XDP oracles into scrubbed SFT/RLVR Causal Episode JSONL and Apache Parquet datasets for custom Threat Detection LLMs.",
			Author:           "Axonwall Core",
			SystemdUnits:     []string{},
			Privileges:       []string{"security.forensics", "system.monitoring", "system.ai"},
			DebianPackages:   []string{},
			AlpinePackages:   []string{},
			ArchPackages:     []string{},
			RequiredBinaries: []string{},
		},
	}
}

func NewPluginManager(baseDataDir string) *PluginManager {
	statePath := filepath.Join(baseDataDir, "plugins.json")
	disabledPath := filepath.Join(baseDataDir, "plugins-disabled.json")
	pm := &PluginManager{
		baseDataDir:  baseDataDir,
		stateFile:    statePath,
		disabledFile: disabledPath,
		osFamily:     DetectOSFamily(),
		installedMap: make(map[string]string),
		disabledMap:  make(map[string]bool),
	}
	if pm.osFamily == "debian" && os.Geteuid() == 0 && !strings.Contains(baseDataDir, "axonwall-plugins-test-") {
		// Eliminate tens of thousands of fsync / ZIL commit stalls on ZFS filesystems during dpkg package extraction
		_ = os.MkdirAll("/etc/dpkg/dpkg.cfg.d", 0755)
		_ = os.WriteFile("/etc/dpkg/dpkg.cfg.d/force-unsafe-io", []byte("force-unsafe-io\n"), 0644)
	}
	pm.loadState()
	return pm
}

func (pm *PluginManager) loadState() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if data, err := os.ReadFile(pm.stateFile); err == nil {
		var saved map[string]string
		if err := json.Unmarshal(data, &saved); err == nil {
			pm.installedMap = saved
		}
	}
	if data, err := os.ReadFile(pm.disabledFile); err == nil {
		var savedDis map[string]bool
		if err := json.Unmarshal(data, &savedDis); err == nil {
			pm.disabledMap = savedDis
		}
	}
}

func (pm *PluginManager) saveState() {
	_ = os.MkdirAll(filepath.Dir(pm.stateFile), 0755)
	if data, err := json.MarshalIndent(pm.installedMap, "", "  "); err == nil {
		_ = os.WriteFile(pm.stateFile, data, 0644)
	}
	if data, err := json.MarshalIndent(pm.disabledMap, "", "  "); err == nil {
		_ = os.WriteFile(pm.disabledFile, data, 0644)
	}
}

func (pm *PluginManager) IsPluginEnabled(pluginID string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.disabledMap[pluginID] {
		return false
	}
	if pluginID == "cli-workstation" {
		if _, err := os.Stat("/etc/axonwall/workstation.disabled"); err == nil {
			return false
		}
		return true
	}
	if pluginID == "host-malware-rootkit" {
		return true
	}
	if pluginID == "core-k3s" {
		if pm.installedMap[pluginID] != "" {
			return true
		}
		if pluginDir, err := pm.pluginDir("core-k3s"); err == nil {
			if isExecutableFile(filepath.Join(pluginDir, "bin", "k3s")) {
				return true
			}
			if info, statErr := os.Stat(bundledRecordPath(pluginDir)); statErr == nil && !info.IsDir() {
				return true
			}
		}
		return false
	}
	return pm.installedMap[pluginID] != ""
}

func packagesForOS(osFamily string, d PluginDefinition) []string {
	switch osFamily {
	case "alpine":
		return d.AlpinePackages
	case "arch":
		if d.ArchPackages != nil {
			return d.ArchPackages
		}
		return d.DebianPackages
	default:
		return d.DebianPackages
	}
}

func hasPluginBinary(osFamily, bin string) bool {
	if _, err := exec.LookPath(bin); err == nil {
		return true
	}
	if bin == "freeradius" && osFamily != "debian" {
		if _, err := exec.LookPath("radiusd"); err == nil {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Plugin-bundled binaries (daemon runtime)
//
// Layout: every plugin that declares Binaries owns one directory,
// <baseDataDir>/<pluginID>/ ("plugin dir"). distroPackage entries are
// extracted merged into it with `dpkg-deb -x`, so a .deb's usr/bin,
// usr/share/... land directly under the plugin dir. Archive entries
// extract into <plugindir>/bin/, their declared binary landing at
// <plugindir>/bin/<name> unless PathInArchive says otherwise — or,
// with Extract "tree", the whole archive lands in the plugin dir
// after stripping StripComponents leading path components — and
// binary entries are placed there directly.
// BinDirs are relative to the plugin dir (e.g. "usr/bin") and are
// prepended to PATH for daemon invocations of that plugin's commands.
//
// Trust model: nothing under a plugin dir is trusted on the strength
// of having been downloaded once. Install sha256-verifies every
// artifact before extraction and writes bundled.json (one record per
// installed file — for a tree archive entry, every file in the
// tree); every later use re-verifies bundled.json and the
// manifest's expected binaries before exec, and ListPlugins reports
// the plugin uninstalled while verification fails. A plugin whose
// manifest still carries SHA256_TODO_* placeholders can never
// install: validation rejects non-hex digests outright.
// ---------------------------------------------------------------------------

var (
	pluginIDPattern   = regexp.MustCompile(`^[a-z0-9-]+$`)
	sha256HexPattern  = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	envKeyPattern     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	debNamePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	debVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:-]*$`)
	debArchPattern    = regexp.MustCompile(`^[a-z0-9]+$`)
)

// pluginDir returns the per-plugin directory for pluginID. The id is
// validated first: an unvalidated id joined onto baseDataDir would let
// a caller escape the plugins tree ("../..."), so anything outside
// ^[a-z0-9-]+$ is refused, never cleaned up silently.
func (pm *PluginManager) pluginDir(pluginID string) (string, error) {
	if !pluginIDPattern.MatchString(pluginID) {
		return "", fmt.Errorf("invalid plugin id %q: must match ^[a-z0-9-]+$", pluginID)
	}
	return filepath.Join(pm.baseDataDir, pluginID), nil
}

// validBinDir reports whether a BinDirs entry is safe to join onto a
// plugin dir: relative, non-empty, no ".." segment, no backslash
// (a Windows separator smuggled into a Unix path).
func validBinDir(dir string) bool {
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

// validateBundledBinaries checks a plugin definition's Binaries,
// BinDirs and Env and fails closed on the first problem, naming the
// offending entry. It runs at install time, before anything is
// downloaded: a SHA256_TODO_* placeholder, an unknown kind, a
// non-http(s) archive URL, or a distroPackage entry for a distro
// other than this host's all refuse the install rather than
// proceeding with an unverified or wrong-distro artifact.
func (pm *PluginManager) validateBundledBinaries(def PluginDefinition) error {
	seenNames := make(map[string]bool, len(def.Binaries))
	for _, b := range def.Binaries {
		if b.Name == "" {
			return fmt.Errorf("bundled binary entry has an empty name (kind %q)", b.Kind)
		}
		if strings.ContainsAny(b.Name, `/\`) || b.Name == "." || b.Name == ".." {
			return fmt.Errorf("bundled binary %q: name must be a plain file name, not a path", b.Name)
		}
		if seenNames[b.Name] {
			return fmt.Errorf("bundled binary %q: duplicate binary name", b.Name)
		}
		seenNames[b.Name] = true
		// SHA256 must be exactly 64 hex chars. This rejects the
		// SHA256_TODO_* placeholders by construction: an install
		// of a plugin whose hashes are not yet resolved must fail
		// here, never download an unverifiable artifact.
		if !sha256HexPattern.MatchString(b.SHA256) {
			return fmt.Errorf("bundled binary %q: sha256 must be a 64-char hex digest (placeholders are not installable)", b.Name)
		}
		// OS gate: every listed family must be a known one, with
		// no duplicates. An entry gated away from this host is
		// skipped at install, not an error — the gate is checked
		// here only for shape, never for a match against this host.
		seenOSes := make(map[string]bool, len(b.OSes))
		for _, o := range b.OSes {
			if !validOSFamilyName(o) {
				return fmt.Errorf("bundled binary %q: os %q is not a known OS family (want debian, alpine or arch)", b.Name, o)
			}
			if seenOSes[o] {
				return fmt.Errorf("bundled binary %q: duplicate os %q", b.Name, o)
			}
			seenOSes[o] = true
		}
		switch b.Kind {
		case "archive":
			if b.URL == "" {
				return fmt.Errorf("bundled binary %q (archive): url is required", b.Name)
			}
			u, err := url.Parse(b.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("bundled binary %q (archive): url %q must be an http(s) URL", b.Name, b.URL)
			}
			if b.Distro != "" || b.Package != "" || b.Source != "" || b.Version != "" || b.Arch != "" {
				return fmt.Errorf("bundled binary %q (archive): distro/package/source/version/arch must be empty for kind archive", b.Name)
			}
			switch strings.ToLower(strings.TrimSpace(b.Format)) {
			case "", "tar", "tar.gz", "tgz", "zip":
			default:
				return fmt.Errorf("bundled binary %q (archive): unsupported format %q (want tar, tar.gz, tgz or zip)", b.Name, b.Format)
			}
			// Extraction mode: ""/"binary" extracts exactly one
			// member (PathInArchive, default Name) into bin/;
			// "tree" extracts the whole archive into the plugin
			// dir after stripping StripComponents leading path
			// components. A tree entry takes no PathInArchive —
			// the strip selects the tree root — and a strip only
			// makes sense for a tree.
			switch strings.ToLower(strings.TrimSpace(b.Extract)) {
			case "", "binary", "tree":
			default:
				return fmt.Errorf("bundled binary %q (archive): unsupported extract %q (want binary or tree)", b.Name, b.Extract)
			}
			isTree := strings.EqualFold(strings.TrimSpace(b.Extract), "tree")
			if b.StripComponents < 0 || b.StripComponents > 8 {
				return fmt.Errorf("bundled binary %q (archive): stripComponents %d out of range (want 0-8)", b.Name, b.StripComponents)
			}
			if !isTree && b.StripComponents != 0 {
				return fmt.Errorf("bundled binary %q (archive): stripComponents is only meaningful with extract \"tree\"", b.Name)
			}
			if isTree && b.PathInArchive != "" {
				return fmt.Errorf("bundled binary %q (archive): pathInArchive must be empty with extract \"tree\" (the strip selects the tree root)", b.Name)
			}
			if b.PathInArchive != "" {
				if filepath.IsAbs(b.PathInArchive) || strings.Contains(b.PathInArchive, "\\") {
					return fmt.Errorf("bundled binary %q (archive): pathInArchive %q must be a relative path", b.Name, b.PathInArchive)
				}
				for _, seg := range strings.Split(filepath.ToSlash(b.PathInArchive), "/") {
					if seg == ".." {
						return fmt.Errorf("bundled binary %q (archive): pathInArchive %q must not contain ..", b.Name, b.PathInArchive)
					}
				}
			}
		case "binary":
			if b.URL == "" {
				return fmt.Errorf("bundled binary %q (binary): url is required", b.Name)
			}
			u, err := url.Parse(b.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("bundled binary %q (binary): url %q must be an http(s) URL", b.Name, b.URL)
			}
			if b.Distro != "" || b.Package != "" || b.Source != "" || b.Version != "" || b.Arch != "" {
				return fmt.Errorf("bundled binary %q (binary): distro/package/source/version/arch must be empty for kind binary", b.Name)
			}
			if b.Format != "" {
				return fmt.Errorf("bundled binary %q (binary): format must be empty for kind binary (a raw file has no container)", b.Name)
			}
			if b.PathInArchive != "" {
				return fmt.Errorf("bundled binary %q (binary): pathInArchive must be empty for kind binary (a raw file has no member path)", b.Name)
			}
			if b.Extract != "" {
				return fmt.Errorf("bundled binary %q (binary): extract must be empty for kind binary (a raw file has no archive to extract)", b.Name)
			}
			if b.StripComponents != 0 {
				return fmt.Errorf("bundled binary %q (binary): stripComponents must be 0 for kind binary (a raw file has no archive members)", b.Name)
			}
		case "distroPackage":
			if b.URL != "" {
				return fmt.Errorf("bundled binary %q (distroPackage): url must be empty for kind distroPackage", b.Name)
			}
			if b.Distro == "" || b.Package == "" || b.Version == "" || b.Arch == "" {
				return fmt.Errorf("bundled binary %q (distroPackage): distro, package, version and arch are all required", b.Name)
			}
			// Debian-only for now, and only for this host's distro:
			// a non-matching distro is an error at install, not a
			// silent skip — silently skipping would leave the
			// plugin "installed" without the binary it needs.
			if b.Distro != "debian" {
				return fmt.Errorf("bundled binary %q (distroPackage): distro %q is not supported (debian only)", b.Name, b.Distro)
			}
			if pm.osFamily != "debian" {
				return fmt.Errorf("bundled binary %q (distroPackage): host osFamily is %q, not debian; distroPackage entries cannot install here", b.Name, pm.osFamily)
			}
			if !debNamePattern.MatchString(b.Package) {
				return fmt.Errorf("bundled binary %q (distroPackage): package %q is not a valid Debian package name", b.Name, b.Package)
			}
			if b.Source != "" && !debNamePattern.MatchString(b.Source) {
				return fmt.Errorf("bundled binary %q (distroPackage): source %q is not a valid Debian source package name", b.Name, b.Source)
			}
			if !debVersionPattern.MatchString(b.Version) || strings.ContainsAny(b.Version, `/\`) {
				return fmt.Errorf("bundled binary %q (distroPackage): version %q is not a valid Debian version", b.Name, b.Version)
			}
			if !debArchPattern.MatchString(b.Arch) {
				return fmt.Errorf("bundled binary %q (distroPackage): arch %q is not valid", b.Name, b.Arch)
			}
			if b.Extract != "" {
				return fmt.Errorf("bundled binary %q (distroPackage): extract must be empty for kind distroPackage (a .deb extracts as a merged tree by definition)", b.Name)
			}
			if b.StripComponents != 0 {
				return fmt.Errorf("bundled binary %q (distroPackage): stripComponents must be 0 for kind distroPackage", b.Name)
			}
		default:
			return fmt.Errorf("bundled binary %q: unknown kind %q (want archive, binary or distroPackage)", b.Name, b.Kind)
		}
	}
	for _, dir := range def.BinDirs {
		if !validBinDir(dir) {
			return fmt.Errorf("plugin %q: binDir %q must be a non-empty relative path with no .., no backslash and no leading /", def.ID, dir)
		}
	}
	for key := range def.Env {
		if !envKeyPattern.MatchString(key) {
			return fmt.Errorf("plugin %q: env key %q is not a valid environment variable name", def.ID, key)
		}
	}
	return nil
}

// bundledBinaryRecord is one row of <plugindir>/bundled.json: the
// installed file (relative to the plugin dir), the sha256 of the
// bytes actually on disk after extraction, and the manifest entry it
// came from. It is the record verifyBundledBinaries checks on use.
type bundledBinaryRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Entry  string `json:"entry"`
	Kind   string `json:"kind"`
}

type bundledBinariesFile struct {
	PluginID string                `json:"pluginId"`
	Sources  map[string]string     `json:"sources,omitempty"`
	Files    []bundledBinaryRecord `json:"files"`
}

func bundledRecordPath(pluginDir string) string {
	return filepath.Join(pluginDir, "bundled.json")
}

// sha256File returns the lowercase hex sha256 of a regular file's contents.
// Rejects symlinks and special files via Lstat so verification can never follow
// a swapped symlink outside the plugin tree.
func sha256File(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("refusing non-regular file %q", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// downloadVerified fetches rawURL with a timeout, streams it to a
// temp file under tmpDir while hashing, and fails closed unless the
// bytes' sha256 equals wantSHA256. The temp file is returned on
// success; the caller removes it. No shell curl: pure net/http.
func downloadVerified(rawURL, wantSHA256, tmpDir string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(rawURL)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: unexpected HTTP status %s", rawURL, resp.Status)
	}
	tmp, err := os.CreateTemp(tmpDir, "axonwall-plugin-download-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	// Cap the download so a malicious or misconfigured upstream
	// cannot fill the disk: bundled binaries are small artifacts.
	h := sha256.New()
	if _, err := io.Copy(tmp, io.TeeReader(io.LimitReader(resp.Body, 1<<30), h)); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("download %s: %w", rawURL, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("download %s: %w", rawURL, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != strings.ToLower(wantSHA256) {
		os.Remove(tmpPath)
		return "", fmt.Errorf("download %s: sha256 mismatch: got %s, want %s; refusing to use unverified bytes", rawURL, got, wantSHA256)
	}
	return tmpPath, nil
}

// debianPoolURL builds the download URL for a distroPackage entry
// from the Debian pool convention:
//
//	http://deb.debian.org/debian/pool/main/<dir>/<source>/<pkg>_<version-no-epoch>_<arch>.deb
//
// where <dir> is the source package's first letter ("lib" + first
// letter for lib* sources, per the pool layout) and the epoch
// ("1:" in "1:30.1+1-6") is dropped from the filename. The source
// package is b.Source when set, else the binary package name —
// the two differ for the bundled libraries (libgccjit0 is built
// from source gcc-14, libisl23 from isl, libmpc3 from mpclib3,
// libmpfr6 from mpfr4, libasound2t64/libasound2-data from alsa-lib,
// liblcms2-2 from lcms2), and the pool directory is derived from
// the source, not the binary package name.
func debianPoolURL(b PluginBundledBinary) (string, error) {
	source := b.Source
	if source == "" {
		source = b.Package
	}
	if source == "" {
		return "", fmt.Errorf("bundled binary %q: package is empty", b.Name)
	}
	dir := source[:1]
	if strings.HasPrefix(source, "lib") && len(source) >= 4 {
		dir = source[:4]
	}
	ver := b.Version
	if i := strings.Index(ver, ":"); i >= 0 {
		ver = ver[i+1:]
	}
	if ver == "" {
		return "", fmt.Errorf("bundled binary %q: version %q has no version after the epoch", b.Name, b.Version)
	}
	file := fmt.Sprintf("%s_%s_%s.deb", b.Package, ver, b.Arch)
	return fmt.Sprintf("http://deb.debian.org/debian/pool/main/%s/%s/%s", dir, source, file), nil
}

// safeArchiveName cleans an archive member name and rejects anything
// that could escape the destination: absolute paths, ".." segments,
// backslashes, and non-regular entries (symlinks/hardlinks/devices
// are refused, never followed — a crafted archive must not be able
// to plant a symlink pointing outside the plugin dir).
func safeArchiveName(name string) (string, bool) {
	// Refuse BEFORE cleaning: Clean would silently resolve ".."
	// against the archive root (pkg/../../escape.txt -> escape.txt)
	// and strip a leading "/" (/etc/evil.txt -> etc/evil.txt),
	// landing the file somewhere the archive never declared.
	// A crafted member must fail the install, not be sanitised
	// into the tree. Backslashes are refused too: they are never
	// legitimate in a release-tarball member name on this platform.
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return "", false
	}
	for _, seg := range strings.Split(strings.TrimPrefix(name, "./"), "/") {
		if seg == ".." {
			return "", false
		}
	}
	cleaned := filepath.ToSlash(filepath.Clean("/" + strings.TrimPrefix(name, "./")))
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "" || cleaned == "." {
		return "", false
	}
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == ".." {
			return "", false
		}
	}
	return cleaned, true
}

// archiveMemberMatches reports whether archive member name matches
// the declared PathInArchive (default: the binary Name). An exact
// cleaned-path match wins; a bare file name also matches a member
// whose base name is that file, so release tarballs that wrap the
// binary in a top-level directory still resolve.
func archiveMemberMatches(member, want string) bool {
	cleaned, ok := safeArchiveName(member)
	if !ok {
		return false
	}
	if cleaned == want {
		return true
	}
	if !strings.Contains(want, "/") && filepath.Base(cleaned) == want {
		return true
	}
	return false
}

// extractArchiveBinary extracts exactly one file — the declared
// binary — from archivePath into <pluginDir>/bin/<name> and returns
// its relative path. Only that file is written; every other member
// is ignored, and a symlink/hardlink member or a second member
// matching the wanted file fails the install.
func extractArchiveBinary(archivePath, format, want, name, pluginDir string) (string, error) {
	binDir := filepath.Join(pluginDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", err
	}
	dest := filepath.Join(binDir, name)
	relDest := filepath.Join("bin", name)

	writeMember := func(r io.Reader) error {
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.Copy(f, r); err != nil {
			os.Remove(dest)
			return err
		}
		return nil
	}

	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "tar"
	}
	found := false
	switch format {
	case "zip":
		zr, err := zip.OpenReader(archivePath)
		if err != nil {
			return "", fmt.Errorf("extract archive: %w", err)
		}
		defer zr.Close()
		for _, member := range zr.File {
			if member.FileInfo().IsDir() {
				continue
			}
			if member.FileInfo().Mode()&os.ModeSymlink != 0 || !member.FileInfo().Mode().IsRegular() {
				return "", fmt.Errorf("extract archive: refusing non-regular member %q", member.Name)
			}
			if !archiveMemberMatches(member.Name, want) {
				continue
			}
			if found {
				return "", fmt.Errorf("extract archive: multiple members match %q; refusing ambiguous archive", want)
			}
			rc, err := member.Open()
			if err != nil {
				return "", fmt.Errorf("extract archive: %w", err)
			}
			err = writeMember(rc)
			rc.Close()
			if err != nil {
				return "", err
			}
			found = true
		}
	case "tar", "tar.gz", "tgz":
		f, err := os.Open(archivePath)
		if err != nil {
			return "", err
		}
		defer f.Close()
		var tr *tar.Reader
		if format == "tar" {
			tr = tar.NewReader(f)
		} else {
			gz, err := gzip.NewReader(f)
			if err != nil {
				return "", fmt.Errorf("extract archive: %w", err)
			}
			defer gz.Close()
			tr = tar.NewReader(gz)
		}
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", fmt.Errorf("extract archive: %w", err)
			}
			if hdr.Typeflag != tar.TypeReg {
				// Symlinks, hardlinks, devices, dirs: never
				// follow or create them from an untrusted archive.
				if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
					return "", fmt.Errorf("extract archive: refusing link member %q", hdr.Name)
				}
				continue
			}
			if !archiveMemberMatches(hdr.Name, want) {
				continue
			}
			if found {
				return "", fmt.Errorf("extract archive: multiple members match %q; refusing ambiguous archive", want)
			}
			if err := writeMember(tr); err != nil {
				return "", err
			}
			found = true
		}
	default:
		return "", fmt.Errorf("extract archive: unsupported format %q", format)
	}
	if !found {
		return "", fmt.Errorf("extract archive: no member %q found in archive", want)
	}
	if err := os.Chmod(dest, 0755); err != nil {
		return "", err
	}
	return relDest, nil
}

// stripArchiveComponents drops the first strip leading components
// of a cleaned archive member path (e.g. strip 1 turns
// "nvim-linux-x86_64/bin/nvim" into "bin/nvim"). It reports false
// when the member sits at or above the strip depth — the member IS
// (part of) the stripped prefix itself, so there is nothing left to
// place. Callers skip such directories and fail on such regular
// files (a file the strip would silently drop is a manifest/archive
// mismatch, not something to ignore).
func stripArchiveComponents(cleaned string, strip int) (string, bool) {
	if strip <= 0 {
		return cleaned, true
	}
	parts := strings.Split(cleaned, "/")
	if len(parts) <= strip {
		return "", false
	}
	return strings.Join(parts[strip:], "/"), true
}

// extractArchiveTree extracts the WHOLE archive into pluginDir,
// preserving member paths after stripping StripComponents leading
// components (see stripArchiveComponents). It is the extraction
// mode for archives that are a working tree, not a single binary:
// the neovim release tarball is bin/nvim plus the lib/ parsers and
// share/nvim/runtime it needs to run, and extracting nvim alone
// would leave it runtime-less. Every member is written (no
// exclusion list — the whole tree is the install, icons/man
// included: 8 small files in the nvim tarball, not worth a filter
// that could silently drop a file a future release adds under a
// path the filter did not expect). Safety follows
// extractArchiveBinary: a symlink/hardlink/device member anywhere
// in the archive fails the install (never followed or created), an
// absolute or ".." member fails it, a member that would land
// outside pluginDir fails it, and a duplicate member (two members
// stripping to the same destination) fails it. Directories are
// created as needed; regular files are written with O_EXCL and the
// archive's mode (masked to 0755 at most — never setuid/setgid).
// The caller records the extracted files (recordInstalledFiles);
// the named binary's executability is then checked by
// expectedBundledBinaries as for a single-binary entry.
func extractArchiveTree(archivePath, format string, strip int, pluginDir string) error {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "tar"
	}

	writeMember := func(rel string, mode os.FileMode, r io.Reader) error {
		dest := filepath.Join(pluginDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return err
		}
		perm := mode.Perm() & 0755
		if perm == 0 {
			perm = 0644
		}
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, r); err != nil {
			f.Close()
			os.Remove(dest)
			return err
		}
		if err := f.Close(); err != nil {
			os.Remove(dest)
			return err
		}
		return nil
	}

	// One member: clean + strip it, then either skip it (a
	// directory at/below the strip depth), write it (a regular
	// file), or fail the install (a link/device, or a regular file
	// the strip would drop). Returns false when the member is a
	// directory that was skipped.
	placeMember := func(name string, isDir bool, isLink bool, mode os.FileMode, r io.Reader) error {
		cleaned, ok := safeArchiveName(name)
		if !ok {
			return fmt.Errorf("extract archive tree: refusing unsafe member %q", name)
		}
		if isLink {
			return fmt.Errorf("extract archive tree: refusing link member %q", name)
		}
		rel, ok := stripArchiveComponents(cleaned, strip)
		if !ok {
			if isDir {
				return nil
			}
			return fmt.Errorf("extract archive tree: member %q would be dropped by stripComponents %d; refusing to silently drop a file", name, strip)
		}
		if isDir {
			return os.MkdirAll(filepath.Join(pluginDir, filepath.FromSlash(rel)), 0755)
		}
		return writeMember(rel, mode, r)
	}

	switch format {
	case "zip":
		zr, err := zip.OpenReader(archivePath)
		if err != nil {
			return fmt.Errorf("extract archive tree: %w", err)
		}
		defer zr.Close()
		for _, member := range zr.File {
			mode := member.FileInfo().Mode()
			if member.FileInfo().IsDir() {
				if err := placeMember(member.Name, true, false, mode, nil); err != nil {
					return err
				}
				continue
			}
			if mode&os.ModeSymlink != 0 || !mode.IsRegular() {
				return fmt.Errorf("extract archive tree: refusing non-regular member %q", member.Name)
			}
			rc, err := member.Open()
			if err != nil {
				return fmt.Errorf("extract archive tree: %w", err)
			}
			err = placeMember(member.Name, false, false, mode, rc)
			rc.Close()
			if err != nil {
				return err
			}
		}
	case "tar", "tar.gz", "tgz":
		f, err := os.Open(archivePath)
		if err != nil {
			return err
		}
		defer f.Close()
		var tr *tar.Reader
		if format == "tar" {
			tr = tar.NewReader(f)
		} else {
			gz, err := gzip.NewReader(f)
			if err != nil {
				return fmt.Errorf("extract archive tree: %w", err)
			}
			defer gz.Close()
			tr = tar.NewReader(gz)
		}
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("extract archive tree: %w", err)
			}
			switch hdr.Typeflag {
			case tar.TypeXGlobalHeader, tar.TypeXHeader:
				// PAX global/extended metadata headers (e.g. git archive tarballs); ignore safely.
				continue
			case tar.TypeDir:
				if err := placeMember(hdr.Name, true, false, hdr.FileInfo().Mode(), nil); err != nil {
					return err
				}
			case tar.TypeReg:
				if err := placeMember(hdr.Name, false, false, hdr.FileInfo().Mode(), tr); err != nil {
					return err
				}
			default:
				// Symlinks, hardlinks, devices, and anything
				// else non-regular: never follow or create
				// them from an untrusted archive.
				return fmt.Errorf("extract archive tree: refusing non-regular member %q", hdr.Name)
			}
		}
	default:
		return fmt.Errorf("extract archive tree: unsupported format %q", format)
	}
	return nil
}

// recordInstalledFiles walks pluginDir after an entry was extracted
// and records every regular file not yet recorded, attributed to
// that entry, hashing the bytes on disk. It runs per entry, so files
// from an earlier entry are already recorded and the new ones belong
// to the entry just extracted. bundled.json itself is excluded.
func recordInstalledFiles(pluginDir string, entry PluginBundledBinary, seen map[string]bool, records *[]bundledBinaryRecord) error {
	return filepath.WalkDir(pluginDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(pluginDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "bundled.json" || seen[rel] {
			return nil
		}
		sum, err := sha256File(path)
		if err != nil {
			return err
		}
		seen[rel] = true
		*records = append(*records, bundledBinaryRecord{Path: rel, SHA256: sum, Entry: entry.Name, Kind: entry.Kind})
		return nil
	})
}

// installRawBinary places a verified raw download at
// <pluginDir>/bin/<name> with mode 0755 and returns its relative
// path. The temp file's bytes were already sha256-verified by
// downloadVerified; the on-disk hash is recorded by the caller.
func installRawBinary(tmpPath, name, pluginDir string) (string, error) {
	binDir := filepath.Join(pluginDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", err
	}
	dest := filepath.Join(binDir, name)
	src, err := os.Open(tmpPath)
	if err != nil {
		return "", err
	}
	defer src.Close()
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, src); err != nil {
		f.Close()
		os.Remove(dest)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(dest)
		return "", err
	}
	if err := os.Chmod(dest, 0755); err != nil {
		return "", err
	}
	return filepath.Join("bin", name), nil
}

// installBundledBinaries downloads, sha256-verifies and extracts
// every Binaries entry of def into the plugin dir. Archive entries
// land in <plugindir>/bin/ — or, with Extract "tree", the whole
// archive lands in the plugin dir after the strip; binary entries
// are placed in bin/ directly; distroPackage entries are extracted
// merged into the plugin dir with `dpkg-deb -x` (the one shell-out
// allowed here — dpkg-deb itself is the format's extractor, and a
// missing dpkg-deb fails closed). Entries gated away from this host
// by OSes are skipped, never downloaded. On any error the install
// aborts and bundled.json is NOT written, so a half-extracted tree
// can never pass verifyBundledBinaries. Callers must validate first.
func (pm *PluginManager) installBundledBinaries(def PluginDefinition) error {
	if len(def.Binaries) == 0 {
		return nil
	}
	if err := pm.validateBundledBinaries(def); err != nil {
		return err
	}
	pluginDir, err := pm.pluginDir(def.ID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(pluginDir), 0755); err != nil {
		return err
	}
	stagingDir, err := os.MkdirTemp(filepath.Dir(pluginDir), ".staging-"+def.ID+"-*")
	if err != nil {
		return err
	}
	stagingCleaned := false
	defer func() {
		if !stagingCleaned {
			_ = os.RemoveAll(stagingDir)
		}
	}()
	if err := os.Chmod(stagingDir, 0755); err != nil {
		return err
	}
	tmpDir, err := os.MkdirTemp("", "axonwall-plugin-bundled-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	var records []bundledBinaryRecord
	sources := make(map[string]string)
	seen := make(map[string]bool)
	for _, b := range def.Binaries {
		// OS gate: an entry that does not apply on this host is
		// skipped outright — never downloaded, never extracted,
		// never recorded.
		if !bundledEntryAppliesToOS(b, pm.osFamily) {
			continue
		}
		sources[b.Name] = strings.ToLower(strings.TrimSpace(b.SHA256))
		switch b.Kind {
		case "archive":
			tmpPath, err := downloadVerified(b.URL, b.SHA256, tmpDir)
			if err != nil {
				return fmt.Errorf("bundled binary %q: %w", b.Name, err)
			}
			if strings.EqualFold(strings.TrimSpace(b.Extract), "tree") {
				if err := extractArchiveTree(tmpPath, b.Format, b.StripComponents, stagingDir); err != nil {
					os.Remove(tmpPath)
					return fmt.Errorf("bundled binary %q: %w", b.Name, err)
				}
				os.Remove(tmpPath)
				if err := recordInstalledFiles(stagingDir, b, seen, &records); err != nil {
					return fmt.Errorf("bundled binary %q: %w", b.Name, err)
				}
				continue
			}
			want := b.PathInArchive
			if want == "" {
				want = b.Name
			}
			rel, err := extractArchiveBinary(tmpPath, b.Format, want, b.Name, stagingDir)
			os.Remove(tmpPath)
			if err != nil {
				return fmt.Errorf("bundled binary %q: %w", b.Name, err)
			}
			sum, err := sha256File(filepath.Join(stagingDir, rel))
			if err != nil {
				return fmt.Errorf("bundled binary %q: %w", b.Name, err)
			}
			seen[filepath.ToSlash(rel)] = true
			records = append(records, bundledBinaryRecord{Path: filepath.ToSlash(rel), SHA256: sum, Entry: b.Name, Kind: b.Kind})
		case "binary":
			tmpPath, err := downloadVerified(b.URL, b.SHA256, tmpDir)
			if err != nil {
				return fmt.Errorf("bundled binary %q: %w", b.Name, err)
			}
			rel, err := installRawBinary(tmpPath, b.Name, stagingDir)
			os.Remove(tmpPath)
			if err != nil {
				return fmt.Errorf("bundled binary %q: %w", b.Name, err)
			}
			sum, err := sha256File(filepath.Join(stagingDir, rel))
			if err != nil {
				return fmt.Errorf("bundled binary %q: %w", b.Name, err)
			}
			seen[filepath.ToSlash(rel)] = true
			records = append(records, bundledBinaryRecord{Path: filepath.ToSlash(rel), SHA256: sum, Entry: b.Name, Kind: b.Kind})
		case "distroPackage":
			if pm.osFamily != "debian" {
				return fmt.Errorf("bundled binary %q (distroPackage): host osFamily is %q, not debian", b.Name, pm.osFamily)
			}
			dpkgDeb, err := exec.LookPath("dpkg-deb")
			if err != nil {
				return fmt.Errorf("bundled binary %q (distroPackage): dpkg-deb is not available on this host; cannot extract .deb packages", b.Name)
			}
			poolURL, err := debianPoolURL(b)
			if err != nil {
				return fmt.Errorf("bundled binary %q: %w", b.Name, err)
			}
			tmpPath, err := downloadVerified(poolURL, b.SHA256, tmpDir)
			if err != nil {
				return fmt.Errorf("bundled binary %q: %w", b.Name, err)
			}
			cmd := exec.Command(dpkgDeb, "-x", tmpPath, stagingDir)
			if out, err := cmd.CombinedOutput(); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("bundled binary %q: dpkg-deb -x failed: %w (output: %s)", b.Name, err, strings.TrimSpace(string(out)))
			}
			os.Remove(tmpPath)
			if err := recordInstalledFiles(stagingDir, b, seen, &records); err != nil {
				return fmt.Errorf("bundled binary %q: %w", b.Name, err)
			}
		default:
			return fmt.Errorf("bundled binary %q: unknown kind %q", b.Name, b.Kind)
		}
	}

	for _, binDir := range def.BinDirs {
		root := filepath.Join(stagingDir, filepath.FromSlash(binDir))
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			_ = os.Chmod(path, 0755)
			return nil
		})
	}

	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	data, err := json.MarshalIndent(bundledBinariesFile{PluginID: def.ID, Sources: sources, Files: records}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(bundledRecordPath(stagingDir), data, 0644); err != nil {
		return err
	}

	// Atomically promote the verified staging tree into pluginDir so mid-install
	// network/checksum failures preserve any previously working plugin tree.
	var backupDir string
	if _, lerr := os.Lstat(pluginDir); lerr == nil {
		backupDir = pluginDir + ".bak-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		if err := os.Rename(pluginDir, backupDir); err != nil {
			return fmt.Errorf("rotate prior plugin dir %s: %w", pluginDir, err)
		}
	}
	if err := os.Rename(stagingDir, pluginDir); err != nil {
		if backupDir != "" {
			_ = os.Rename(backupDir, pluginDir)
		}
		return fmt.Errorf("promote staged plugin dir %s: %w", pluginDir, err)
	}
	stagingCleaned = true
	if backupDir != "" {
		_ = os.RemoveAll(backupDir)
	}
	return nil
}

// ensureBundledBinaries is the install/ensure path for a plugin
// that declares Binaries: it verifies the tree that is already on
// disk first (the image builders pre-stage core-k3s, so a first
// boot must NOT re-download ~110 MB) and downloads ONLY when a
// file is missing, mismatched, or the verification record is
// absent/corrupt. A verify failure therefore costs a full
// re-download of every entry (installBundledBinaries starts from a
// clean tree — it cannot know which entry went bad), but a healthy
// staged tree costs no network at all. Callers must validate
// first; validation runs here too so a direct caller cannot skip
// it. A plugin with no Binaries is a no-op.
func (pm *PluginManager) ensureBundledBinaries(def PluginDefinition) error {
	if len(def.Binaries) == 0 {
		return nil
	}
	if err := pm.validateBundledBinaries(def); err != nil {
		return err
	}
	if err := pm.verifyBundledBinaries(def); err == nil {
		return nil
	}
	return pm.installBundledBinaries(def)
}

// ensureCoreK3sBinSymlinks creates the k3s multicall symlinks
// (kubectl, crictl, ctr) in the core-k3s plugin bin dir, pointing
// at the staged k3s binary, and removes a dangling legacy
// /usr/local/bin/kubectl symlink left by the pre-migration
// workstation hook (only when it no longer resolves — a symlink
// that still points at a working k3s is left alone, and a real
// standalone kubectl binary there is never touched). The plugin
// bin dir is the only place these symlinks are created now; the
// builders stage the same three at image build time and this is
// the repair path if they are deleted. An existing real file under
// one of the three names is left alone, never overwritten.
func (pm *PluginManager) ensureCoreK3sBinSymlinks() error {
	pluginDir, err := pm.pluginDir("core-k3s")
	if err != nil {
		return err
	}
	k3sBin := filepath.Join(pluginDir, "bin", "k3s")
	if !isExecutableFile(k3sBin) {
		return fmt.Errorf("core-k3s k3s binary %q is missing or not executable; cannot create multicall symlinks", filepath.ToSlash(filepath.Join("core-k3s", "bin", "k3s")))
	}
	for _, link := range []string{"kubectl", "crictl", "ctr"} {
		p := filepath.Join(pluginDir, "bin", link)
		if info, err := os.Lstat(p); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				if target, rerr := os.Readlink(p); rerr == nil && target == "k3s" {
					continue
				}
				_ = os.Remove(p)
			} else {
				continue
			}
		}
		if err := os.Symlink("k3s", p); err != nil {
			return fmt.Errorf("core-k3s: failed to create symlink %q: %w", link, err)
		}
	}
	// Legacy cleanup: the old workstation/VOW install hook created
	// /usr/local/bin/kubectl -> k3s. Uninstall/disable never removed
	// it, so upgraded boxes keep a symlink at the old location that
	// dangles once /usr/local/bin/k3s is gone. Remove it only when
	// it dangles (Stat follows the link and fails); a working
	// symlink and any real file are left alone.
	if info, err := os.Lstat("/usr/local/bin/kubectl"); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if target, rerr := os.Readlink("/usr/local/bin/kubectl"); rerr == nil && (target == "k3s" || strings.HasSuffix(target, "/k3s")) {
			if _, serr := os.Stat("/usr/local/bin/kubectl"); serr != nil {
				_ = os.Remove("/usr/local/bin/kubectl")
			}
		}
	}
	return nil
}

// ensureWorkstationNvimSymlinks creates the vi/vim symlinks in the
// cli-workstation plugin bin dir, pointing at the bundled nvim.
// The links use the RELATIVE target "nvim" (same dir), so the
// plugin dir stays relocatable (state-dir override, restore) and
// the links keep working wherever the dir moves. They live INSIDE
// the plugin dir on purpose — the old kubectl precedent wrote a
// system symlink (/usr/local/bin/kubectl) that uninstall/disable
// never removed; these die with the plugin dir on uninstall
// (UninstallPlugin removes the dir for plugins with Binaries) and
// leave PATH on disable (DisablePlugin removes the shell snippet,
// and the daemon resolves them only through the plugin's BinDirs).
// An existing real file under either name is left alone, never
// overwritten; a stale symlink pointing elsewhere is replaced. The
// bundled nvim must exist and be executable first — on Alpine/Arch
// there is no bundled nvim (the archive entry is Debian-gated), so
// callers must not invoke this there: system vi/vim are the editors
// on those hosts and this helper would fail closed.
func (pm *PluginManager) ensureWorkstationNvimSymlinks() error {
	pluginDir, err := pm.pluginDir("cli-workstation")
	if err != nil {
		return err
	}
	nvimBin := filepath.Join(pluginDir, "bin", "nvim")
	if !isExecutableFile(nvimBin) {
		return fmt.Errorf("cli-workstation bundled nvim %q is missing or not executable; cannot create vi/vim symlinks", filepath.ToSlash(filepath.Join("cli-workstation", "bin", "nvim")))
	}
	for _, link := range []string{"vi", "vim"} {
		p := filepath.Join(pluginDir, "bin", link)
		if info, err := os.Lstat(p); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				if target, rerr := os.Readlink(p); rerr == nil && target == "nvim" {
					continue
				}
				_ = os.Remove(p)
			} else {
				continue
			}
		}
		if err := os.Symlink("nvim", p); err != nil {
			return fmt.Errorf("cli-workstation: failed to create symlink %q: %w", link, err)
		}
	}
	return nil
}

// checkWorkstationNvimLibraries runs `ldd` on the bundled nvim
// binary and fails loudly listing any shared library reported "not
// found" — a missing lib means the binary cannot start at all, and
// the install must fail rather than record a broken plugin. The
// nvim tarball needs only libm/libgcc_s/libc (verified live
// 2026-11-20), all in the base image, so this is expected to pass;
// it is the tripwire if a future neovim release gains a dependency
// the image does not carry. No LD_LIBRARY_PATH is needed: the
// bundled tree carries no .so files outside lib/nvim/parser (loaded
// by nvim itself, not the dynamic loader). If `ldd` itself is
// absent, this logs a warning and continues — a missing ldd must
// not block the install; the failure will surface at first launch
// instead. (Same shape as checkEmacsBundledLibraries.)
func (pm *PluginManager) checkWorkstationNvimLibraries() error {
	lddPath, err := exec.LookPath("ldd")
	if err != nil {
		log.Printf("[Plugins] Warning: ldd is not available; skipping bundled-library check for cli-workstation nvim (a missing shared library will fail at first launch instead)")
		return nil
	}
	pluginDir, err := pm.pluginDir("cli-workstation")
	if err != nil {
		return err
	}
	binary := filepath.Join(pluginDir, "bin", "nvim")
	cmd := exec.Command(lddPath, binary)
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
		return fmt.Errorf("bundled nvim binary %s is missing shared libraries: %s; refusing to install a plugin whose binary cannot start", binary, strings.Join(missing, ", "))
	}
	return nil
}

// expectedBundledBinary returns the on-disk location of the binary a
// manifest entry provides, and whether that location is meaningful
// to check. Archive and binary entries provide
// <plugindir>/bin/<name> directly.
// A distroPackage entry provides no single binary by name — its
// package name (e.g. "emacs-nox") is not a file — so its expected
// binaries are the plugin's RequiredBinaries under its BinDirs
// (for cli-emacs: bin/emacs — the launcher — and usr/bin/emacs-nox,
// the real extracted binary). A required binary counts as expected
// at the FIRST BinDir that holds it: BinDirs are alternatives in
// priority order (bin/ wins over usr/bin/), not every combination —
// a binary present in one BinDir must not fail verification for
// being absent from another. When a required binary is in NO
// BinDir, the path under the first BinDir is returned so the
// failure names a concrete missing location.
func (pm *PluginManager) expectedBundledBinaries(def PluginDefinition) []string {
	pluginDir, err := pm.pluginDir(def.ID)
	if err != nil {
		return nil
	}
	var out []string
	for _, b := range def.Binaries {
		if !bundledEntryAppliesToOS(b, pm.osFamily) {
			continue
		}
		switch b.Kind {
		case "archive", "binary":
			out = append(out, filepath.Join(pluginDir, "bin", b.Name))
		case "distroPackage":
			for _, bin := range def.RequiredBinaries {
				found := ""
				for _, binDir := range def.BinDirs {
					candidate := filepath.Join(pluginDir, filepath.FromSlash(binDir), bin)
					if isExecutableFile(candidate) {
						found = candidate
						break
					}
				}
				if found != "" {
					out = append(out, found)
					continue
				}
				if len(def.BinDirs) > 0 {
					out = append(out, filepath.Join(pluginDir, filepath.FromSlash(def.BinDirs[0]), bin))
				}
			}
		}
	}
	return out
}

// bundledBinariesVerifiedNames lists the bundled binaries that are
// present and executable, for PluginStatus.BundledBinaries: archive
// and binary entry names, plus required binaries found under a
// BinDir for distroPackage entries.
func (pm *PluginManager) bundledBinariesVerifiedNames(def PluginDefinition) []string {
	pluginDir, err := pm.pluginDir(def.ID)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, b := range def.Binaries {
		if !bundledEntryAppliesToOS(b, pm.osFamily) {
			continue
		}
		switch b.Kind {
		case "archive", "binary":
			if isExecutableFile(filepath.Join(pluginDir, "bin", b.Name)) {
				add(b.Name)
			}
		case "distroPackage":
			for _, bin := range def.RequiredBinaries {
				for _, binDir := range def.BinDirs {
					if isExecutableFile(filepath.Join(pluginDir, filepath.FromSlash(binDir), bin)) {
						add(bin)
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0111 != 0
}

// verifyBundledBinaries re-verifies a plugin's bundled binaries
// before use and fails closed on any discrepancy. It re-reads
// <plugindir>/bundled.json and requires every listed file to exist
// with a matching sha256, and requires every manifest entry's
// expected binary to be present and executable at its expected
// location. A missing bundled.json, a missing or tampered file, or
// a missing expected binary is an error — never a warning — so a
// caller can never exec a binary it has not just verified.
func (pm *PluginManager) verifyBundledBinaries(def PluginDefinition) error {
	if len(def.Binaries) == 0 {
		return nil
	}
	// OS gate: a plugin whose every entry is gated away from this
	// host bundles nothing here — there is nothing to verify, and
	// requiring a bundled.json would wrongly fail the install on
	// that host (the plugin's binaries resolve from the system
	// packages instead; see cli-workstation on Alpine/Arch).
	applicable := false
	for _, b := range def.Binaries {
		if bundledEntryAppliesToOS(b, pm.osFamily) {
			applicable = true
			break
		}
	}
	if !applicable {
		return nil
	}
	pluginDir, err := pm.pluginDir(def.ID)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(bundledRecordPath(pluginDir))
	if err != nil {
		return fmt.Errorf("plugin %q: bundled verification record %s is missing or unreadable: %w; refusing to use unverified bundled binaries", def.ID, bundledRecordPath(pluginDir), err)
	}
	var rec bundledBinariesFile
	if err := json.Unmarshal(data, &rec); err != nil {
		return fmt.Errorf("plugin %q: bundled verification record is corrupt: %w", def.ID, err)
	}
	if rec.PluginID != def.ID {
		return fmt.Errorf("plugin %q: bundled verification record pluginId %q does not match %q", def.ID, rec.PluginID, def.ID)
	}
	if len(rec.Files) == 0 {
		return fmt.Errorf("plugin %q: bundled verification record lists no files", def.ID)
	}
	entriesPresent := make(map[string]bool)
	for _, r := range rec.Files {
		if r.Path == "" || filepath.IsAbs(r.Path) || strings.Contains(r.Path, "..") {
			return fmt.Errorf("plugin %q: bundled verification record has unsafe path %q", def.ID, r.Path)
		}
		full := filepath.Join(pluginDir, filepath.FromSlash(r.Path))
		sum, err := sha256File(full)
		if err != nil {
			return fmt.Errorf("plugin %q: bundled file %q is missing or unreadable: %w", def.ID, r.Path, err)
		}
		if sum != strings.ToLower(r.SHA256) {
			return fmt.Errorf("plugin %q: bundled file %q sha256 mismatch: got %s, want %s; refusing to use tampered bundled binaries", def.ID, r.Path, sum, r.SHA256)
		}
		if r.Entry != "" {
			entriesPresent[r.Entry] = true
		}
	}
	for _, b := range def.Binaries {
		if !bundledEntryAppliesToOS(b, pm.osFamily) {
			continue
		}
		wantPin := strings.ToLower(strings.TrimSpace(b.SHA256))
		srcPin, hasSrc := rec.Sources[b.Name]
		if !hasSrc || strings.ToLower(strings.TrimSpace(srcPin)) != wantPin {
			return fmt.Errorf("plugin %q: bundled verification record source pin mismatch for %q (got %q, want %q); refusing stale or unpinned bundled binaries", def.ID, b.Name, srcPin, wantPin)
		}
		if !entriesPresent[b.Name] {
			return fmt.Errorf("plugin %q: bundled verification record lists no files for manifest entry %q", def.ID, b.Name)
		}
		if b.Kind == "binary" {
			onDiskHash, err := sha256File(filepath.Join(pluginDir, "bin", b.Name))
			if err != nil {
				return fmt.Errorf("plugin %q: bundled binary %q is missing or unreadable: %w", def.ID, b.Name, err)
			}
			if onDiskHash != wantPin {
				return fmt.Errorf("plugin %q: bundled binary %q on-disk sha256 %s does not match manifest pin %s", def.ID, b.Name, onDiskHash, wantPin)
			}
		}
	}
	for _, expected := range pm.expectedBundledBinaries(def) {
		if !isExecutableFile(expected) {
			rel, _ := filepath.Rel(pluginDir, expected)
			return fmt.Errorf("plugin %q: expected bundled binary %q is missing or not executable", def.ID, filepath.ToSlash(rel))
		}
	}
	return nil
}

// Package-internal test seams so unit tests staging fake binaries can supply
// synthetic PluginDefinitions matching their test hashes while production code
// strictly enforces findPluginDefinition / GetExtensionPluginDefinitions.
var (
	lookupPluginDefinition         = findPluginDefinition
	listExtensionPluginDefinitions = GetExtensionPluginDefinitions
)

// hasPluginBinaryForPlugin checks the system PATH first (including
// the freeradius/radiusd alias), then the plugin's own BinDirs under
// its plugin dir, for an executable file named bin. A bundled
// binary therefore counts as present without ever being installed
// into the system.
func (pm *PluginManager) hasPluginBinaryForPlugin(def PluginDefinition, bin string) bool {
	if hasPluginBinary(pm.osFamily, bin) {
		return true
	}
	pluginDir, err := pm.pluginDir(def.ID)
	if err != nil {
		return false
	}
	for _, binDir := range def.BinDirs {
		if !validBinDir(binDir) {
			continue
		}
		if isExecutableFile(filepath.Join(pluginDir, filepath.FromSlash(binDir), bin)) {
			return true
		}
	}
	// Archive entries live in <plugindir>/bin/ even when the
	// manifest declares no BinDirs.
	if isExecutableFile(filepath.Join(pluginDir, "bin", bin)) {
		return true
	}
	return false
}

// PluginEnv returns the environment for invoking a plugin's
// commands, as KEY=value strings: the full current environment,
// with PATH rebuilt as the plugin's BinDirs (absolute paths, in
// declared order) prepended to the current PATH, and the plugin's
// Env map overlaid with ${PLUGIN_DIR} expanded to the plugin dir.
// Binaries are resolved through this PATH by CommandForPlugin, so a
// bundled binary shadows any same-named system binary — which is
// the point of bundling it.
func (pm *PluginManager) PluginEnv(pluginID string) ([]string, error) {
	def, ok := lookupPluginDefinition(pluginID)
	if !ok {
		return nil, fmt.Errorf("unknown plugin ID %q", pluginID)
	}
	pluginDir, err := pm.pluginDir(pluginID)
	if err != nil {
		return nil, err
	}
	pathParts := make([]string, 0, len(def.BinDirs)+1)
	for _, binDir := range def.BinDirs {
		if !validBinDir(binDir) {
			continue
		}
		pathParts = append(pathParts, filepath.Join(pluginDir, filepath.FromSlash(binDir)))
	}
	if cur := os.Getenv("PATH"); cur != "" {
		pathParts = append(pathParts, cur)
	}
	env := os.Environ()
	out := make([]string, 0, len(env)+len(def.Env)+1)
	replacedPath := false
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			out = append(out, "PATH="+strings.Join(pathParts, string(os.PathListSeparator)))
			replacedPath = true
			continue
		}
		out = append(out, kv)
	}
	if !replacedPath {
		out = append(out, "PATH="+strings.Join(pathParts, string(os.PathListSeparator)))
	}
	keys := make([]string, 0, len(def.Env))
	for k := range def.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	expanded := make(map[string]string, len(def.Env))
	for _, k := range keys {
		expanded[k] = strings.ReplaceAll(def.Env[k], "${PLUGIN_DIR}", pluginDir)
	}
	for i, kv := range out {
		if k, _, ok := strings.Cut(kv, "="); ok {
			if v, exists := expanded[k]; exists {
				out[i] = k + "=" + v
				delete(expanded, k)
			}
		}
	}
	for _, k := range keys {
		if v, ok := expanded[k]; ok {
			out = append(out, k+"="+v)
		}
	}
	return out, nil
}

// failingPluginCommand returns a command that fails with a
// descriptive error instead of silently running the wrong binary
// (or nothing at all). CommandForPlugin uses it when the binary
// cannot be resolved or the bundled binaries fail verification.
func failingPluginCommand(msg string) *exec.Cmd {
	return exec.Command("sh", "-c", `printf '%s\n' "$1" >&2; exit 127`, "_", msg)
}

// CommandForPlugin builds a command to run a plugin's binary with
// that plugin's environment (see PluginEnv). The binary is resolved
// through the plugin's BinDirs first, then the system PATH, so a
// bundled binary is preferred over a system one of the same name.
// For plugins that declare Binaries, the bundled tree is
// re-verified before exec and any failure yields a command that
// fails descriptively rather than running an unverified binary.
func (pm *PluginManager) CommandForPlugin(pluginID, name string, args ...string) *exec.Cmd {
	def, ok := lookupPluginDefinition(pluginID)
	if !ok {
		return failingPluginCommand(fmt.Sprintf("axonwall: unknown plugin %q", pluginID))
	}
	if name == "" || strings.Contains(name, "..") || filepath.IsAbs(name) {
		return failingPluginCommand(fmt.Sprintf("axonwall: plugin %q: refusing to run binary name %q", pluginID, name))
	}
	if len(def.Binaries) > 0 {
		if err := pm.verifyBundledBinaries(def); err != nil {
			return failingPluginCommand(fmt.Sprintf("axonwall: plugin %q: %v", pluginID, err))
		}
	}
	pluginDir, err := pm.pluginDir(pluginID)
	if err != nil {
		return failingPluginCommand(fmt.Sprintf("axonwall: plugin %q: %v", pluginID, err))
	}
	var resolved string
	if !strings.ContainsRune(name, '/') {
		for _, binDir := range def.BinDirs {
			if !validBinDir(binDir) {
				continue
			}
			candidate := filepath.Join(pluginDir, filepath.FromSlash(binDir), name)
			if isExecutableFile(candidate) {
				resolved = candidate
				break
			}
		}
		if resolved == "" {
			if candidate := filepath.Join(pluginDir, "bin", name); isExecutableFile(candidate) {
				resolved = candidate
			}
		}
	} else {
		// A relative path such as "usr/bin/emacs": resolve it
		// under the plugin dir only, never the system.
		candidate := filepath.Join(pluginDir, filepath.FromSlash(name))
		if isExecutableFile(candidate) {
			resolved = candidate
		}
	}
	if resolved == "" {
		if found, err := exec.LookPath(name); err == nil {
			resolved = found
		}
	}
	if resolved == "" {
		return failingPluginCommand(fmt.Sprintf("axonwall: plugin %q: binary %q not found in plugin directories or system PATH", pluginID, name))
	}
	env, err := pm.PluginEnv(pluginID)
	if err != nil {
		return failingPluginCommand(fmt.Sprintf("axonwall: plugin %q: %v", pluginID, err))
	}
	cmd := exec.Command(resolved, args...)
	cmd.Env = env
	return cmd
}

func (pm *PluginManager) ListPlugins() []PluginStatus {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	defs := listExtensionPluginDefinitions()
	results := make([]PluginStatus, 0, len(defs))

	for _, d := range defs {
		var missing []string
		for _, bin := range d.RequiredBinaries {
			if bin == "debsums" && pm.osFamily != "debian" {
				continue
			}
			if !pm.hasPluginBinaryForPlugin(d, bin) {
				missing = append(missing, bin)
			}
		}

		// Bundled binaries: a plugin whose binaries are all
		// bundled and verified reads as installed with zero
		// missing binaries even when the system has none of them
		// — but only while verification passes. A failed
		// verification counts every required binary as missing
		// and the plugin is not reported installed, so the UI can
		// never show a plugin installed on an unverified tree.
		var bundledBinaries []string
		if len(d.Binaries) > 0 {
			if err := pm.verifyBundledBinaries(d); err != nil {
				for _, bin := range d.RequiredBinaries {
					found := false
					for _, m := range missing {
						if m == bin {
							found = true
							break
						}
					}
					if !found {
						missing = append(missing, bin)
					}
				}
			} else {
				bundledBinaries = pm.bundledBinariesVerifiedNames(d)
			}
		}

		pkgs := packagesForOS(pm.osFamily, d)

		installedAt := pm.installedMap[d.ID]
		installed := len(missing) == 0
		if len(d.RequiredBinaries) == 0 && installedAt != "" {
			installed = true
		}
		bundled := len(missing) == 0 && installedAt == ""

		enabled := d.DefaultEnabled
		if pm.disabledMap[d.ID] {
			enabled = false
		} else if d.ID == "cli-workstation" {
			if _, err := os.Stat("/etc/axonwall/workstation.disabled"); err == nil {
				enabled = false
			}
		} else if installedAt != "" {
			enabled = true
		}

		results = append(results, PluginStatus{
			ID:               d.ID,
			Name:             d.Name,
			Version:          d.Version,
			Category:         d.Category,
			Description:      d.Description,
			Author:           d.Author,
			Enabled:          enabled,
			DefaultEnabled:   d.DefaultEnabled,
			Dependencies:     d.Dependencies,
			Installed:        installed,
			Bundled:          bundled,
			RequiredBinaries: d.RequiredBinaries,
			MissingBinaries:  missing,
			BundledBinaries:  bundledBinaries,
			Packages:         pkgs,
			InstalledAt:      installedAt,
			SystemdUnits:     d.SystemdUnits,
			LdapIntegration:  d.LdapIntegration,
		})
	}
	return results
}

func (pm *PluginManager) EnablePlugin(pluginID string) PluginActionResponse {
	if pluginID == "cli-workstation" {
		_ = os.Remove("/etc/axonwall/workstation.disabled")
		if err := pm.provisionWorkstationConfigs(); err != nil {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to enable workstation shell environment: %v", err),
			}
		}
		pm.mu.Lock()
		delete(pm.disabledMap, pluginID)
		if pm.installedMap[pluginID] == "" {
			pm.installedMap[pluginID] = time.Now().UTC().Format(time.RFC3339)
		}
		pm.saveState()
		pm.mu.Unlock()
		// Shell PATH: provisioning rewrote /etc/zsh/zshenv, which wipes
		// the plugin PATH loader block — rebuild every enabled plugin's
		// snippet so the loader is restored. Soft-fail: the plugin works
		// via the daemon either way; the snippet is only a convenience.
		if err := RebuildPluginShellPaths(pm); err != nil {
			log.Printf("[PluginManager] Warning: failed to rebuild plugin shell PATHs: %v", err)
		}
		return PluginActionResponse{
			Success: true,
			Message: "Enabled Modern Operator Shell & Editor (ZSH + Oh My Zsh + Starship + VIM + Full Stack Completions).",
		}
	}

	// A-M33 (round 2): reconfigure FIRST so unit files the plugin
	// provisions exist before systemd is asked to enable them. The old
	// order ran "systemctl enable --now" before ReconfigurePlugin
	// wrote the unit, so a first enable always failed — silently —
	// for plugins like rosenpass whose unit is written by reconfigure.
	resp := pm.ReconfigurePlugin(pluginID)
	if !resp.Success {
		return resp
	}
	if def, ok := findExtensionPluginDefinition(pluginID); ok {
		if err := enablePluginUnits(def); err != nil {
			// The service is not actually running: record the
			// plugin disabled so ListPlugins does not report it
			// enabled while its service is down.
			pm.mu.Lock()
			pm.disabledMap[pluginID] = true
			pm.saveState()
			pm.mu.Unlock()
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to enable plugin %s: %v", pluginID, err),
			}
		}
	}

	pm.mu.Lock()
	delete(pm.disabledMap, pluginID)
	if pm.installedMap[pluginID] == "" {
		pm.installedMap[pluginID] = time.Now().UTC().Format(time.RFC3339)
	}
	pm.saveState()
	pm.mu.Unlock()
	// Shell PATH (soft-fail: log + continue, never fail the enable —
	// the plugin works via the daemon's PluginEnv either way).
	if err := SyncPluginShellPaths(pm, pluginID); err != nil {
		log.Printf("[PluginManager] Warning: failed to sync shell PATH for plugin %s: %v", pluginID, err)
	}
	return resp
}

func (pm *PluginManager) DisablePlugin(pluginID string) PluginActionResponse {
	// Dependency guard: refuse while any other currently-enabled
	// plugin depends on this one — disabling it would break the
	// dependent. Runs before the cli-workstation special case.
	if dependents := pm.enabledDependentsOf(pluginID); len(dependents) > 0 {
		return PluginActionResponse{
			Success: false,
			Message: fmt.Sprintf("Cannot disable plugin %s: enabled plugin(s) %s depend on it. Disable %s first.", pluginID, strings.Join(dependents, ", "), strings.Join(dependents, ", ")),
		}
	}
	if pluginID == "cli-workstation" {
		_ = os.MkdirAll("/etc/axonwall", 0755)
		_ = os.WriteFile("/etc/axonwall/workstation.disabled", []byte("disabled=true\n"), 0644)
		pm.mu.Lock()
		pm.disabledMap[pluginID] = true
		pm.saveState()
		pm.mu.Unlock()
		// Shell PATH (soft-fail): remove the snippet so the disabled
		// plugin's binaries leave interactive shells too.
		if err := RemovePluginShellPath(pm, pluginID); err != nil {
			log.Printf("[PluginManager] Warning: failed to remove shell PATH for plugin %s: %v", pluginID, err)
		}
		return PluginActionResponse{
			Success: true,
			Message: "Disabled Modern Operator Shell & Editor (attack-surface reduction mode active).",
		}
	}

	// A-M33 (round 2): the old code discarded every "systemctl
	// disable --now" error and reported success while the service
	// kept running. Only record the plugin disabled once its units
	// are actually stopped.
	if def, ok := findExtensionPluginDefinition(pluginID); ok {
		if err := disablePluginUnits(def); err != nil {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to disable plugin %s: %v", pluginID, err),
			}
		}
	}

	// R4-A-M4: disabling the harvester plugin stops the harvester —
	// the toggle must actually stop collection, not just flip state.
	// (SetEnabled(false) detaches the eBPF hooks and cannot fail
	// meaningfully; a wiring error is logged, not fatal, because the
	// plugin is being turned off.)
	if pluginID == "ebpf-threat-harvester" {
		if err := pm.setHarvesterEnabled(false); err != nil {
			log.Printf("[PluginManager] Warning: disabling ebpf-threat-harvester did not stop the harvester: %v", err)
		}
	}

	pm.mu.Lock()
	pm.disabledMap[pluginID] = true
	pm.saveState()
	pm.mu.Unlock()

	// Shell PATH (soft-fail): remove the snippet so the disabled
	// plugin's binaries leave interactive shells too.
	if err := RemovePluginShellPath(pm, pluginID); err != nil {
		log.Printf("[PluginManager] Warning: failed to remove shell PATH for plugin %s: %v", pluginID, err)
	}

	return PluginActionResponse{
		Success: true,
		Message: fmt.Sprintf("Disabled plugin %s.", pluginID),
	}
}

// systemctlAvailable reports whether systemd is present on this host.
func systemctlAvailable() bool {
	_, err := exec.LookPath("systemctl")
	return err == nil
}

// enabledDependentsOf returns the IDs of currently-enabled plugins
// that declare pluginID in their Dependencies (sorted). It is the
// guard for DisablePlugin/UninstallPlugin: a plugin another enabled
// plugin depends on must not be turned off or removed underneath
// it — e.g. once Doom/Spacemacs declare dependencies:
// ["cli-emacs"], cli-emacs cannot be disabled while either is
// enabled. It reads definitions generically; no plugin ID is
// hardcoded here.
func (pm *PluginManager) enabledDependentsOf(pluginID string) []string {
	var out []string
	for _, d := range GetExtensionPluginDefinitions() {
		if d.ID == pluginID {
			continue
		}
		depends := false
		for _, dep := range d.Dependencies {
			if dep == pluginID {
				depends = true
				break
			}
		}
		if !depends {
			continue
		}
		if pm.IsPluginEnabled(d.ID) {
			out = append(out, d.ID)
		}
	}
	sort.Strings(out)
	return out
}

// findExtensionPluginDefinition returns the definition for an extension
// plugin id, if it is a known extension plugin.
func findExtensionPluginDefinition(pluginID string) (PluginDefinition, bool) {
	for _, d := range GetExtensionPluginDefinitions() {
		if d.ID == pluginID {
			return d, true
		}
	}
	return PluginDefinition{}, false
}

// enablePluginUnits runs "systemctl enable --now" for each declared unit
// and verifies each one is actually active afterwards.
//
// A-M33 (round 2): the old code discarded every systemctl error, so
// enabling a plugin whose unit failed to start still reported success
// (and the UI toggle reported success while the service kept running
// or never started). A daemon-reload runs first so units written by
// ReconfigurePlugin are visible to systemd.
func enablePluginUnits(def PluginDefinition) error {
	if !systemctlAvailable() {
		return nil
	}
	_ = exec.Command("systemctl", "--no-ask-password", "daemon-reload").Run()
	for _, unit := range def.SystemdUnits {
		if out, err := exec.Command("systemctl", "--no-ask-password", "enable", "--now", unit).CombinedOutput(); err != nil {
			return fmt.Errorf("failed to enable unit %s: %w (output: %s)", unit, err, strings.TrimSpace(string(out)))
		}
		if err := exec.Command("systemctl", "is-active", "--quiet", unit).Run(); err != nil {
			return fmt.Errorf("unit %s is not active after enable", unit)
		}
	}
	return nil
}

// disablePluginUnits runs "systemctl disable --now" for each declared
// unit and verifies none is still active afterwards. A disable error
// for a unit that is not loaded is tolerated — what matters is that the
// service is actually stopped; a unit still active after the disable
// attempt is a failure.
func disablePluginUnits(def PluginDefinition) error {
	if !systemctlAvailable() {
		return nil
	}
	var errs []error
	for _, unit := range def.SystemdUnits {
		_ = exec.Command("systemctl", "--no-ask-password", "disable", "--now", unit).Run()
		if err := exec.Command("systemctl", "is-active", "--quiet", unit).Run(); err == nil {
			errs = append(errs, fmt.Errorf("unit %s is still active after disable", unit))
		}
	}
	return errors.Join(errs...)
}

// verifyRosenpassUnit checks that the rosenpass systemd unit written by
// ProvisionRosenpassEnvironment is loadable and that the binary its
// ExecStart points at exists. It returns nil when there is no systemd
// on this host (nothing to verify against) so Alpine/OpenRC hosts are
// not failed for lacking systemctl.
func verifyRosenpassUnit() error {
	if !systemctlAvailable() {
		return nil
	}
	unitPath := "/etc/systemd/system/rosenpass.service"
	data, err := os.ReadFile(unitPath)
	if err != nil {
		return fmt.Errorf("rosenpass unit %s is missing: %w", unitPath, err)
	}
	_ = exec.Command("systemctl", "--no-ask-password", "daemon-reload").Run()
	if out, err := exec.Command("systemctl", "cat", "rosenpass.service").CombinedOutput(); err != nil {
		return fmt.Errorf("rosenpass unit does not load: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		bin := strings.Fields(strings.TrimPrefix(line, "ExecStart="))
		if len(bin) == 0 {
			return fmt.Errorf("rosenpass unit has an empty ExecStart")
		}
		if _, err := os.Stat(bin[0]); err != nil {
			return fmt.Errorf("rosenpass ExecStart binary %s does not exist: %w", bin[0], err)
		}
		return nil
	}
	return fmt.Errorf("rosenpass unit has no ExecStart line")
}

const (
	headscalePinnedVersion = "0.29.4"
	headscalePinnedURL     = "https://github.com/juanfont/headscale/releases/download/v0.29.4/headscale_0.29.4_linux_amd64"
	headscalePinnedSHA256  = "212ed0a884c0d3541e094c4bebbe94397df6f4e01bd3d7f059c520cb55e0d757"
)

func aptListsNeedUpdate(aptListsDir string) bool {
	entries, err := os.ReadDir(aptListsDir)
	if err != nil {
		return true
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.Contains(name, "_Packages") {
			return false
		}
	}
	return true
}

func runAptGetUpdate(output *strings.Builder) error {
	cmd := exec.Command("apt-get", "update")
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	if output != nil {
		output.WriteString(string(out))
	}
	return err
}

func isPackageInstalledForOS(osFamily, pkg string) bool {
	switch osFamily {
	case "alpine":
		return exec.Command("apk", "info", "-e", pkg).Run() == nil
	case "arch":
		return exec.Command("pacman", "-Q", pkg).Run() == nil
	default:
		out, err := exec.Command("dpkg-query", "-W", "-f=${Status}\n", pkg).Output()
		return err == nil && strings.Contains(string(out), "install ok installed")
	}
}

func missingPackagesForOS(osFamily string, pkgs []string) []string {
	var missing []string
	for _, pkg := range pkgs {
		if !isPackageInstalledForOS(osFamily, pkg) {
			missing = append(missing, pkg)
		}
	}
	return missing
}

func coreRoleOSPackages(osFamily, pluginID string) []string {
	switch pluginID {
	case "core-firewall":
		switch osFamily {
		case "alpine":
			return []string{"nftables", "suricata", "frr", "kea-dhcp4", "conntrack-tools", "unbound", "wireguard-tools", "strongswan", "openvpn", "keepalived"}
		case "arch":
			return []string{"nftables", "suricata", "frr", "kea", "conntrack-tools", "unbound", "wireguard-tools", "strongswan", "openvpn", "keepalived"}
		default:
			return []string{"nftables", "suricata", "frr", "kea-dhcp4-server", "conntrackd", "unbound", "wireguard-tools", "strongswan", "openvpn", "keepalived"}
		}
	case "core-nas":
		switch osFamily {
		case "alpine":
			return []string{"zfs", "samba", "nfs-utils", "open-iscsi"}
		case "arch":
			return []string{"zfs-utils", "samba", "nfs-utils", "open-iscsi"}
		default:
			return []string{"zfsutils-linux", "samba", "nfs-kernel-server", "open-iscsi"}
		}
	case "core-k3s":
		switch osFamily {
		case "alpine":
			return []string{"curl", "iptables", "open-iscsi"}
		case "arch":
			return []string{"curl", "iptables-nft", "open-iscsi"}
		default:
			return []string{"curl", "iptables", "open-iscsi"}
		}
	case "core-virt":
		switch osFamily {
		case "alpine":
			return []string{"qemu-system-x86_64", "qemu-img", "ovmf", "swtpm", "lxc", "dnsmasq", "xorriso"}
		case "arch":
			return []string{"qemu-full", "edk2-ovmf", "swtpm", "lxc", "dnsmasq", "libisoburn"}
		default:
			return []string{"qemu-system-x86", "qemu-utils", "ovmf", "swtpm", "lxc", "dnsmasq-base", "xorriso", "bridge-utils"}
		}
	default:
		return nil
	}
}

var pluginOptionalPackages = map[string]bool{
	"python3-drgn": true,
	"bpftrace":     true,
	"linux-perf":   true,
	"bpftool":      true,
	"perf":         true,
	"kubectl":      true,
	"starship":     true,
}

func (pm *PluginManager) installOSPackages(pkgs []string, output *strings.Builder) error {
	if len(pkgs) == 0 {
		return nil
	}
	if pm.osFamily == "arch" {
		if _, err := os.Stat("/var/lib/pacman/db.lck"); err == nil {
			return fmt.Errorf("pacman database is locked (/var/lib/pacman/db.lck); another package operation is in progress")
		}
	}

	var corePkgs, optionalPkgs []string
	for _, p := range pkgs {
		if pluginOptionalPackages[p] {
			optionalPkgs = append(optionalPkgs, p)
		} else {
			corePkgs = append(corePkgs, p)
		}
	}

	ranAptUpdate := false
	if pm.osFamily == "debian" && aptListsNeedUpdate("/var/lib/apt/lists") {
		if err := runAptGetUpdate(output); err != nil {
			log.Printf("[PluginManager] Warning: initial apt-get update failed: %v", err)
		}
		ranAptUpdate = true
	}

	runInstall := func(pkgList []string) ([]byte, error) {
		var cmd *exec.Cmd
		switch pm.osFamily {
		case "alpine":
			args := append([]string{"add", "--no-cache"}, pkgList...)
			cmd = exec.Command("apk", args...)
		case "arch":
			args := append([]string{"-Sy", "--needed", "--noconfirm"}, pkgList...)
			cmd = exec.Command("pacman", args...)
		default:
			args := append([]string{"install", "-y", "--no-install-recommends", "-o", "Dpkg::Options::=--force-unsafe-io"}, pkgList...)
			cmd = exec.Command("apt-get", args...)
			cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		}
		return cmd.CombinedOutput()
	}

	if len(corePkgs) > 0 {
		out, err := runInstall(corePkgs)
		if output != nil {
			output.WriteString(string(out))
		}
		if err != nil && pm.osFamily == "debian" && !ranAptUpdate {
			if uerr := runAptGetUpdate(output); uerr == nil {
				out, err = runInstall(corePkgs)
				if output != nil {
					output.WriteString(string(out))
				}
			}
		}
		if err != nil {
			return fmt.Errorf("package installation failed: %w", err)
		}
	}

	for _, optPkg := range optionalPkgs {
		if out, err := runInstall([]string{optPkg}); err != nil {
			log.Printf("[PluginManager] Note: optional package %s not installed via repo: %v (%s)", optPkg, err, string(out))
		} else if output != nil {
			output.WriteString(string(out))
		}
	}
	return nil
}

func systemdUnitInstalledAny(unit string) bool {
	for _, dir := range []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"} {
		if _, err := os.Stat(filepath.Join(dir, unit)); err == nil {
			return true
		}
	}
	return false
}

func ensureCoreK3sSystemdUnit() error {
	if !systemctlAvailable() || systemdUnitInstalledAny("k3s.service") {
		return nil
	}
	unit := `[Unit]
Description=Lightweight Kubernetes (Axonwall In-House K3s Engine)
Documentation=https://k3s.io
Wants=network-online.target
After=network-online.target
ConditionPathExists=/etc/rancher/k3s/config.yaml
ConditionPathExists=!/etc/rancher/k3s/agent-mode
ConditionPathExists=!/etc/axonwall/.vault-edition
ConditionKernelCommandLine=!axonwall_install=1
ConditionKernelCommandLine=!axonwall.install=1
ConditionKernelCommandLine=!axonwall.unattended=1

[Install]
WantedBy=multi-user.target

[Service]
Type=exec
EnvironmentFile=-/etc/default/%N
EnvironmentFile=-/etc/sysconfig/%N
EnvironmentFile=-/etc/systemd/system/k3s.service.env
KillMode=process
Delegate=yes
User=root
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s
ExecStartPre=-/usr/sbin/modprobe br_netfilter
ExecStartPre=-/usr/sbin/modprobe overlay
ExecStart=/var/lib/axonwall/core-k3s/bin/k3s server --prefer-bundled-bin
`
	if err := os.MkdirAll("/etc/systemd/system", 0755); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/systemd/system/k3s.service", []byte(unit), 0644); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "--no-ask-password", "daemon-reload").Run()
	return nil
}

func ensureHeadscaleInstalled(osFamily string, output *strings.Builder) error {
	if _, err := exec.LookPath("headscale"); err != nil {
		tmpDir, err := os.MkdirTemp("", "axonwall-headscale-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpDir)
		tmpPath, err := downloadVerified(headscalePinnedURL, headscalePinnedSHA256, tmpDir)
		if err != nil {
			return err
		}
		if err := os.MkdirAll("/usr/sbin", 0755); err != nil {
			return err
		}
		src, err := os.Open(tmpPath)
		if err != nil {
			return err
		}
		stagePath := "/usr/sbin/.headscale.new"
		dst, err := os.OpenFile(stagePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			src.Close()
			return err
		}
		_, copyErr := io.Copy(dst, src)
		closeErr := dst.Close()
		src.Close()
		if copyErr != nil || closeErr != nil {
			_ = os.Remove(stagePath)
			if copyErr != nil {
				return copyErr
			}
			return closeErr
		}
		if err := os.Chmod(stagePath, 0755); err != nil {
			_ = os.Remove(stagePath)
			return err
		}
		if err := os.Rename(stagePath, "/usr/sbin/headscale"); err != nil {
			_ = os.Remove(stagePath)
			return err
		}
		if output != nil {
			output.WriteString("[+] Installed verified headscale v" + headscalePinnedVersion + " to /usr/sbin/headscale\n")
		}
	}

	if osFamily == "debian" || osFamily == "arch" {
		nologinShell := "/usr/sbin/nologin"
		if _, statErr := os.Stat(nologinShell); statErr != nil {
			nologinShell = "/sbin/nologin"
		}
		if exec.Command("getent", "group", "axonwall-headscale").Run() != nil {
			_ = exec.Command("groupadd", "--system", "axonwall-headscale").Run()
		}
		if exec.Command("getent", "passwd", "axonwall-headscale").Run() != nil {
			_ = exec.Command("useradd", "--system", "--gid", "axonwall-headscale", "--home-dir", "/var/lib/axonwall",
				"--no-create-home", "--shell", nologinShell, "--comment", "Axonwall Headscale Service User", "axonwall-headscale").Run()
		}
	} else if osFamily == "alpine" {
		if exec.Command("getent", "group", "axonwall-headscale").Run() != nil {
			_ = exec.Command("addgroup", "-S", "axonwall-headscale").Run()
		}
		if exec.Command("getent", "passwd", "axonwall-headscale").Run() != nil {
			_ = exec.Command("adduser", "-S", "-D", "-H", "-h", "/var/lib/axonwall", "-s", "/sbin/nologin", "-G", "axonwall-headscale", "axonwall-headscale").Run()
		}
	}

	_ = os.MkdirAll("/var/lib/axonwall/headscale", 0770)
	_ = os.MkdirAll("/run/headscale", 0770)
	_ = os.MkdirAll("/etc/headscale", 0755)
	_ = exec.Command("chown", "-R", "axonwall-headscale:axonwall-headscale", "/var/lib/axonwall/headscale").Run()
	_ = exec.Command("chown", "axonwall-headscale:axonwall-api", "/run/headscale").Run()

	if _, err := os.Stat("/etc/headscale/config.yaml"); os.IsNotExist(err) {
		defaultCfg := `---
server_url: http://127.0.0.1:8080
listen_addr: 127.0.0.1:8080
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: false
noise:
  private_key_path: /var/lib/axonwall/headscale/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
derp:
  server:
    enabled: true
    region_id: 999
    region_code: "headscale"
    region_name: "Headscale Embedded DERP"
    stun_listen_addr: "127.0.0.1:3478"
    private_key_path: /var/lib/axonwall/headscale/derp_server_private.key
  urls: []
  paths: []
  auto_update_enabled: false
  update_frequency: 24h
disable_check_updates: true
node:
  expiry: 0
  ephemeral:
    inactivity_timeout: 30m
database:
  type: sqlite
  sqlite:
    path: /var/lib/axonwall/headscale/db.sqlite
acme_url: https://acme-v02.api.letsencrypt.org/directory
acme_email: ""
tls_letsencrypt_hostname: ""
tls_client_auth_mode: relaxed
tls_letsencrypt_cache_dir: /var/lib/axonwall/headscale/cache
tls_letsencrypt_challenge_type: HTTP-01
tls_letsencrypt_listen: ":http"
tls_cert_path: ""
tls_key_path: ""
log:
  format: text
  level: info
policy:
  mode: file
  path: ""
dns:
  magic_dns: true
  base_domain: tailnet.axonwall.local
  nameservers:
    global:
      - 1.1.1.1
      - 1.0.0.1
  search_domains: []
  extra_records: []
unix_socket: /run/headscale/headscale.sock
unix_socket_permission: "0770"
logtail:
  enabled: false
`
		if err := os.WriteFile("/etc/headscale/config.yaml", []byte(defaultCfg), 0640); err != nil {
			return err
		}
		_ = exec.Command("chown", "root:axonwall-api", "/etc/headscale/config.yaml").Run()
	}

	if systemctlAvailable() && !systemdUnitInstalledAny("headscale.service") {
		unit := `[Unit]
Description=headscale coordination server for Tailscale clients
After=network-online.target axonwall-firstboot.service
Wants=network-online.target
ConditionPathExists=!/etc/axonwall/.vault-edition
ConditionPathExists=!/etc/axonwall/.k3s-edition
ConditionKernelCommandLine=!axonwall_install=1
ConditionKernelCommandLine=!axonwall.install=1
ConditionKernelCommandLine=!axonwall.unattended=1

[Service]
Type=simple
User=axonwall-headscale
Group=axonwall-api
Environment="HEADSCALE_CONFIG=/etc/headscale/config.yaml"
ExecStart=/usr/sbin/headscale serve
Restart=always
RestartSec=5
LimitNOFILE=65536
LimitNPROC=65536

ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
PrivateTmp=yes
RuntimeDirectory=headscale
RuntimeDirectoryMode=0770
ReadWritePaths=-/var/lib/axonwall/headscale -/run/headscale

[Install]
WantedBy=multi-user.target
`
		if err := os.WriteFile("/etc/systemd/system/headscale.service", []byte(unit), 0644); err != nil {
			return err
		}
		_ = exec.Command("systemctl", "--no-ask-password", "daemon-reload").Run()
	}
	return nil
}

func resetMissingZshUsersToBash() {
	if _, err := os.Stat("/usr/bin/zsh"); err == nil {
		return
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		return
	}
	if pwBytes, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, line := range strings.Split(string(pwBytes), "\n") {
			parts := strings.Split(line, ":")
			if len(parts) < 7 || parts[6] != "/usr/bin/zsh" {
				continue
			}
			uid, err := strconv.Atoi(parts[2])
			if err != nil || (uid != 0 && (uid < 1000 || uid >= 60000)) {
				continue
			}
			_ = exec.Command("usermod", "-s", "/bin/bash", parts[0]).Run()
		}
	}
	if uaBytes, err := os.ReadFile("/etc/default/useradd"); err == nil {
		updated := regexp.MustCompile(`(?m)^SHELL=.*$`).ReplaceAllString(string(uaBytes), "SHELL=/bin/bash")
		if updated != string(uaBytes) {
			_ = os.WriteFile("/etc/default/useradd", []byte(updated), 0644)
		}
	}
	if acBytes, err := os.ReadFile("/etc/adduser.conf"); err == nil {
		updated := regexp.MustCompile(`(?m)^DSHELL=.*$`).ReplaceAllString(string(acBytes), "DSHELL=/bin/bash")
		if updated != string(acBytes) {
			_ = os.WriteFile("/etc/adduser.conf", []byte(updated), 0644)
		}
	}
}

func prepareNtopAptRepo() error {
	tmpDir, err := os.MkdirTemp("", "axonwall-ntop-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	if err := os.Chmod(tmpDir, 0700); err != nil {
		return err
	}
	prereqCmd := exec.Command("apt-get", "install", "-y", "--no-install-recommends", "-o", "Dpkg::Options::=--force-unsafe-io", "gnupg", "ca-certificates")
	prereqCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if out, err := prereqCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("install gnupg/ca-certificates failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get("https://packages.ntop.org/apt/ntop.key")
	if err != nil {
		return fmt.Errorf("download ntop GPG key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download ntop GPG key: unexpected HTTP status %s", resp.Status)
	}
	keyPath := filepath.Join(tmpDir, "ntop.key")
	keyFile, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(keyFile, io.LimitReader(resp.Body, 1<<20))
	closeErr := keyFile.Close()
	if copyErr != nil {
		return fmt.Errorf("write ntop GPG key: %w", copyErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.MkdirAll("/usr/share/keyrings", 0755); err != nil {
		return err
	}
	keyringPath := "/usr/share/keyrings/ntop-archive-keyring.gpg"
	stagedKeyring := filepath.Join(tmpDir, "ntop-archive-keyring.gpg")
	if out, err := exec.Command("gpg", "--dearmor", "--batch", "--yes", "-o", stagedKeyring, keyPath).CombinedOutput(); err != nil {
		return fmt.Errorf("dearmor ntop GPG key failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	keyringBytes, err := os.ReadFile(stagedKeyring)
	if err != nil || len(keyringBytes) == 0 {
		return fmt.Errorf("dearmored ntop keyring is empty or unreadable: %v", err)
	}
	if err := os.WriteFile(keyringPath, keyringBytes, 0644); err != nil {
		return err
	}
	repoList := fmt.Sprintf("deb [signed-by=%s] https://packages.ntop.org/apt-stable/trixie/ x64/\ndeb [signed-by=%s] https://packages.ntop.org/apt-stable/trixie/ all/\n", keyringPath, keyringPath)
	if err := os.WriteFile("/etc/apt/sources.list.d/ntop.list", []byte(repoList), 0644); err != nil {
		return err
	}
	updCmd := exec.Command("apt-get", "update")
	updCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if out, err := updCmd.CombinedOutput(); err != nil {
		_ = os.Remove("/etc/apt/sources.list.d/ntop.list")
		return fmt.Errorf("apt-get update for ntop repo failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func isKnownCorePluginID(pluginID string) bool {
	switch pluginID {
	case "core-firewall", "core-nas", "core-k3s", "core-virt", "core-vigilante":
		return true
	}
	_, ok := lookupPluginDefinition(pluginID)
	return ok
}

func (pm *PluginManager) InstallPlugin(pluginID string) PluginActionResponse {
	if strings.HasPrefix(pluginID, "core-") {
		if !isKnownCorePluginID(pluginID) {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Unknown core plugin ID '%s'", pluginID),
			}
		}
		var pkgOut strings.Builder
		if os.Geteuid() == 0 {
			missing := missingPackagesForOS(pm.osFamily, coreRoleOSPackages(pm.osFamily, pluginID))
			if len(missing) > 0 {
				pm.actionMu.Lock()
				err := pm.installOSPackages(missing, &pkgOut)
				pm.actionMu.Unlock()
				if err != nil {
					return PluginActionResponse{
						Success: false,
						Message: fmt.Sprintf("Failed to install core role %s packages: %v", pluginID, err),
						Output:  pkgOut.String(),
					}
				}
			}
		}
		resp := pm.ReconfigurePlugin(pluginID)
		if resp.Success {
			pm.mu.Lock()
			delete(pm.disabledMap, pluginID)
			if pm.installedMap[pluginID] == "" {
				pm.installedMap[pluginID] = time.Now().UTC().Format(time.RFC3339)
			}
			pm.saveState()
			pm.mu.Unlock()
		}
		if pkgOut.Len() > 0 {
			if resp.Output != "" {
				resp.Output = pkgOut.String() + "\n" + resp.Output
			} else {
				resp.Output = pkgOut.String()
			}
		}
		return resp
	}

	pm.actionMu.Lock()
	defer pm.actionMu.Unlock()

	defs := listExtensionPluginDefinitions()
	var target *PluginDefinition
	for i := range defs {
		if defs[i].ID == pluginID {
			target = &defs[i]
			break
		}
	}
	if target == nil {
		return PluginActionResponse{
			Success: false,
			Message: fmt.Sprintf("Unknown plugin ID '%s'", pluginID),
		}
	}

	pkgs := packagesForOS(pm.osFamily, *target)

	var output strings.Builder

	// Upstream repository preparation hooks for plugins not hosted in base Debian repos
	if pm.osFamily == "debian" {
		if pluginID == "tailscale" {
			if _, err := os.Stat("/etc/apt/sources.list.d/tailscale.list"); os.IsNotExist(err) {
				prepCmd := exec.Command("sh", "-c", "codename=$(. /etc/os-release 2>/dev/null && echo \"${VERSION_CODENAME:-trixie}\" || echo trixie); curl -fsSL \"https://pkgs.tailscale.com/stable/debian/${codename}.noarmor.gpg\" | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null && curl -fsSL \"https://pkgs.tailscale.com/stable/debian/${codename}.tailscale-keyring.list\" | tee /etc/apt/sources.list.d/tailscale.list >/dev/null && apt-get update")
				prepCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
				if out, err := prepCmd.CombinedOutput(); err != nil {
					log.Printf("[PluginManager] Warning configuring Tailscale apt repository: %v (%s)", err, string(out))
				}
			}
		} else if pluginID == "ntopng" {
			if _, err := os.Stat("/etc/apt/sources.list.d/ntop.list"); os.IsNotExist(err) {
				if err := prepareNtopAptRepo(); err != nil {
					log.Printf("[PluginManager] Warning configuring ntopng apt repository: %v", err)
				}
			}
		}
	}

	if err := pm.installOSPackages(pkgs, &output); err != nil {
		return PluginActionResponse{
			Success: false,
			Message: err.Error(),
			Output:  output.String(),
		}
	}

	// Bundled binaries: validate then download/verify/extract into
	// the plugin's own directory, before any post-install hook runs.
	// Any failure aborts the install — the plugin is NOT recorded
	// installed and hooks do not run — so a half-bundled plugin can
	// never be reported installed.
	if len(target.Binaries) > 0 {
		if err := pm.validateBundledBinaries(*target); err != nil {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Bundled binary validation failed for plugin %s: %v", pluginID, err),
				Output:  output.String(),
			}
		}
		if err := pm.installBundledBinaries(*target); err != nil {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Bundled binary installation failed for plugin %s: %v", pluginID, err),
				Output:  output.String(),
			}
		}
	}

	// cli-emacs post-install: the bundled tree is extracted, so
	// (1) ldd-check the real binary (usr/bin/emacs-nox) for
	// missing shared libraries, and (2) write the bin/emacs
	// launcher + config/init.el. The ldd check runs first: on
	// failure the plugin tree is removed again so ListPlugins
	// cannot report the plugin installed on a tree whose binary
	// cannot start, and the install fails loudly listing the
	// missing libraries. The launcher/config files are generated
	// locally from repo constants (not downloaded), so they are
	// not part of bundled.json — verify checks bin/emacs exists
	// and is executable, but does not hash it.
	if pluginID == "cli-emacs" {
		failEmacsInstall := func(err error) PluginActionResponse {
			if dir, derr := pm.pluginDir(pluginID); derr == nil {
				_ = os.RemoveAll(dir)
			}
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Bundled emacs post-install failed for plugin %s: %v", pluginID, err),
				Output:  output.String(),
			}
		}
		if err := pm.checkEmacsBundledLibraries(); err != nil {
			return failEmacsInstall(err)
		}
		if err := pm.provisionEmacsPluginFiles(); err != nil {
			return failEmacsInstall(err)
		}
	}

	// Doom / Spacemacs post-install: each shares the cli-emacs
	// binary, so each fails closed without cli-emacs present, then
	// clones its distribution at the pinned commit and writes its
	// launcher + config. Doom additionally runs `doom sync`;
	// Spacemacs does no package install and no first start (its
	// packages are latest-at-install — see
	// plugin_emacs_doom_spacemacs.go). On failure the plugin is NOT
	// recorded installed and the helpers remove their partial
	// artifacts; the failure message names the cause.
	if pluginID == "cli-emacs-doom" {
		if err := pm.installDoomEmacs(); err != nil {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Doom Emacs install failed for plugin %s: %v", pluginID, err),
				Output:  output.String(),
			}
		}
	}
	if pluginID == "cli-emacs-spacemacs" {
		if err := pm.installSpacemacsEmacs(); err != nil {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Spacemacs install failed for plugin %s: %v", pluginID, err),
				Output:  output.String(),
			}
		}
	}

	// Post-install configuration hooks
	if pluginID == "cli-workstation" || pluginID == "vigilant-octo-waffle" {
		// kubectl now comes from the core-k3s plugin's bin dir,
		// not /usr/local/bin: if no kubectl resolves on the
		// system PATH and the staged k3s binary exists, link
		// <plugindir>/bin/kubectl -> k3s (plus crictl/ctr) there.
		// Never writes /usr/local/bin — the old hook created
		// /usr/local/bin/kubectl -> k3s and uninstall/disable
		// never removed it; a dangling copy is now cleaned up
		// by ensureCoreK3sBinSymlinks. A standalone kubectl
		// binary (Debian builders still ship one in
		// /usr/local/bin) satisfies the LookPath check and this
		// stays a no-op, as before.
		if _, err := exec.LookPath("kubectl"); err != nil {
			_ = pm.ensureCoreK3sBinSymlinks()
		}
	}
	if pluginID == "cli-workstation" {
		// Debian-only nvim post-install: the bundled tree is
		// extracted, so (1) ldd-check the real binary (bin/nvim)
		// for missing shared libraries, and (2) create the
		// bin/vi + bin/vim symlinks to it. The ldd check runs
		// first: on failure the plugin tree is removed again so
		// ListPlugins cannot report the plugin installed on a
		// tree whose binary cannot start. On Alpine/Arch there
		// is no bundled nvim (the archive entry is Debian-gated
		// and skipped), so this whole block is a no-op there and
		// vi/vim keep resolving from the system packages. The
		// symlinks are generated locally (not downloaded), so
		// they are not part of bundled.json — verify checks
		// bin/nvim exists and is executable, but does not hash
		// them; hasPluginBinaryForPlugin resolves vim/nvim
		// through them because os.Stat follows a symlink to an
		// executable target (verified by reasoning + the
		// isExecutableFile definition, not by a live launch).
		if pm.osFamily == "debian" {
			failWorkstationNvimInstall := func(err error) PluginActionResponse {
				if dir, derr := pm.pluginDir(pluginID); derr == nil {
					_ = os.RemoveAll(dir)
				}
				return PluginActionResponse{
					Success: false,
					Message: fmt.Sprintf("Bundled nvim post-install failed for plugin %s: %v", pluginID, err),
					Output:  output.String(),
				}
			}
			if err := pm.checkWorkstationNvimLibraries(); err != nil {
				return failWorkstationNvimInstall(err)
			}
			if err := pm.ensureWorkstationNvimSymlinks(); err != nil {
				return failWorkstationNvimInstall(err)
			}
		}
		_ = os.Remove("/etc/axonwall/workstation.disabled")
		pm.mu.Lock()
		delete(pm.disabledMap, pluginID)
		pm.mu.Unlock()
		if err := pm.provisionWorkstationConfigs(); err != nil {
			log.Printf("[PluginManager] Warning provisioning workstation configs: %v", err)
		}
		// On Debian/Alpine, keep /etc/shells and SSSD cache in sync with real zsh presence
		if pm.osFamily == "alpine" {
			if zshPath, err := exec.LookPath("zsh"); err == nil && zshPath != "" {
				_ = os.Remove("/usr/bin/zsh")
				_ = os.Symlink(zshPath, "/usr/bin/zsh")
			}
		}
		if os.Geteuid() == 0 {
			if SyncZshInEtcShells(true) && hasSSSD() {
				_ = restartSSSD()
			}
			InvalidateSSSDCache("")
		}
	}
	if pluginID == "headscale" && os.Geteuid() == 0 {
		if err := ensureHeadscaleInstalled(pm.osFamily, &output); err != nil {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to install Headscale binary/service: %v", err),
				Output:  output.String(),
			}
		}
	}
	if pluginID == "rosenpass" {
		// The rosenpass binary now arrives via the generic
		// bundled-binaries flow above (verified archive extract
		// into <plugindir>/bin/) — the old unverified
		// `curl | tar` into /usr/local/bin is deleted. Only the
		// keypair/unit provisioning remains here.
		if err := ProvisionRosenpassEnvironment(DefaultRosenpassDir); err != nil {
			log.Printf("[PluginManager] Warning provisioning Rosenpass PQ keys: %v", err)
		}
	}
	if pluginID == "vigilant-octo-waffle" {
		_ = os.MkdirAll("/etc/axonwall/vow", 0755)
		_ = os.MkdirAll("/etc/rancher/k3s", 0755)
		_ = os.MkdirAll("/var/lib/rancher/k3s/server/manifests", 0755)
	}
	if pluginID == "eluvix" {
		_ = os.MkdirAll("/etc/axonwall/eluvix", 0755)
	}
	if pluginID == "ebpf-threat-harvester" {
		_ = os.MkdirAll("/var/lib/axonwall/threat-corpus", 0750)
		// R4-A-M4: installing the plugin must actually start the
		// harvester — installing and reporting success while nothing
		// runs is the same lie as the enable toggle. On failure the
		// plugin is left uninstalled (and recorded disabled, like
		// the A-M33 unit-failure path) instead of enabled-but-dead.
		if err := pm.setHarvesterEnabled(true); err != nil {
			pm.mu.Lock()
			pm.disabledMap[pluginID] = true
			pm.saveState()
			pm.mu.Unlock()
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to start the threat harvester for plugin %s: %v", pluginID, err),
			}
		}
	}

	pm.mu.Lock()
	delete(pm.disabledMap, pluginID)
	pm.installedMap[pluginID] = time.Now().UTC().Format(time.RFC3339)
	pm.saveState()
	pm.mu.Unlock()

	// Ensure LDAP integration is provisioned if declared by the plugin
	go pm.ensurePluginLDAP(pluginID)

	// Shell PATH (soft-fail): the bundled dirs exist now and the plugin
	// is recorded installed, so interactive shells can use its binaries.
	if pluginID == "cli-workstation" {
		if err := RebuildPluginShellPaths(pm); err != nil {
			log.Printf("[PluginManager] Warning: failed to rebuild plugin shell PATHs: %v", err)
		}
	} else if err := SyncPluginShellPaths(pm, pluginID); err != nil {
		log.Printf("[PluginManager] Warning: failed to sync shell PATH for plugin %s: %v", pluginID, err)
	}

	return PluginActionResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully installed plugin %s (%s)", target.Name, pluginID),
		Output:  output.String(),
	}
}

func (pm *PluginManager) UninstallPlugin(pluginID string) PluginActionResponse {
	// Dependency guard: refuse while any other currently-enabled
	// plugin depends on this one — uninstalling it would break the
	// dependent. Runs at the top, before the core-role early return.
	if dependents := pm.enabledDependentsOf(pluginID); len(dependents) > 0 {
		return PluginActionResponse{
			Success: false,
			Message: fmt.Sprintf("Cannot uninstall plugin %s: enabled plugin(s) %s depend on it. Disable %s first.", pluginID, strings.Join(dependents, ", "), strings.Join(dependents, ", ")),
		}
	}
	if strings.HasPrefix(pluginID, "core-") {
		pm.mu.Lock()
		pm.disabledMap[pluginID] = true
		delete(pm.installedMap, pluginID)
		pm.saveState()
		pm.mu.Unlock()
		if err := RemovePluginShellPath(pm, pluginID); err != nil {
			log.Printf("[PluginManager] Warning: failed to remove shell PATH for core plugin %s: %v", pluginID, err)
		}
		return PluginActionResponse{
			Success: true,
			Message: fmt.Sprintf("Disabled core role plugin %s.", pluginID),
		}
	}

	pm.actionMu.Lock()
	defer pm.actionMu.Unlock()

	defs := listExtensionPluginDefinitions()
	var target *PluginDefinition
	for i := range defs {
		if defs[i].ID == pluginID {
			target = &defs[i]
			break
		}
	}
	if target == nil {
		return PluginActionResponse{
			Success: false,
			Message: fmt.Sprintf("Unknown plugin ID '%s'", pluginID),
		}
	}

	// A-M33 (round 2): the old code discarded the disable errors, so
	// an uninstall could report success while the service kept
	// running. Refuse to uninstall while its units are still active.
	if err := disablePluginUnits(*target); err != nil {
		return PluginActionResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to stop plugin %s services: %v", pluginID, err),
		}
	}

	pkgs := packagesForOS(pm.osFamily, *target)

	var output strings.Builder

	if pm.osFamily == "arch" && len(pkgs) > 0 {
		if _, err := os.Stat("/var/lib/pacman/db.lck"); err == nil {
			return PluginActionResponse{
				Success: false,
				Message: "Pacman database is locked (/var/lib/pacman/db.lck); another package operation is in progress",
			}
		}
	}

	if len(pkgs) > 0 {
		var cmd *exec.Cmd
		switch pm.osFamily {
		case "alpine":
			args := append([]string{"del"}, pkgs...)
			cmd = exec.Command("apk", args...)
		case "arch":
			args := append([]string{"-Rs", "--noconfirm"}, pkgs...)
			cmd = exec.Command("pacman", args...)
		default:
			args := append([]string{"remove", "-y", "-o", "Dpkg::Options::=--force-unsafe-io"}, pkgs...)
			cmd = exec.Command("apt-get", args...)
			cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		}

		out, err := cmd.CombinedOutput()
		output.WriteString(string(out))
		if err != nil {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Package removal failed: %v", err),
				Output:  output.String(),
			}
		}
	}

	// Bundled binaries: remove the plugin's own directory, but only
	// for plugins that declare Binaries — never delete a directory
	// for a plugin that never had one. The id was validated by
	// pluginDir, so the joined path cannot escape baseDataDir; a
	// symlink at that path is removed as a link, never followed
	// (os.RemoveAll does not follow the root symlink, and the Lstat
	// check makes that explicit). A removal failure is logged, not
	// fatal: the packages are already gone and the plugin record is
	// cleared below either way. Core-role plugins never reach here.
	if len(target.Binaries) > 0 || len(target.BinDirs) > 0 {
		if dir, err := pm.pluginDir(pluginID); err == nil {
			if info, err := os.Lstat(dir); err == nil {
				var rmErr error
				if info.Mode()&os.ModeSymlink != 0 {
					rmErr = os.Remove(dir)
				} else {
					rmErr = os.RemoveAll(dir)
				}
				if rmErr != nil {
					log.Printf("[PluginManager] Warning: failed to remove bundled-binary directory %s for plugin %s: %v", dir, pluginID, rmErr)
				}
			}
		}
	}

	// Post-removal cleanup hooks
	if pluginID == "headscale" {
		if info, err := os.Lstat("/usr/sbin/headscale"); err == nil && !info.IsDir() {
			if rmErr := os.Remove("/usr/sbin/headscale"); rmErr != nil {
				log.Printf("[PluginManager] Warning: failed to remove headscale binary /usr/sbin/headscale: %v", rmErr)
			}
		}
		if _, libErr := os.Stat("/lib/systemd/system/headscale.service"); os.IsNotExist(libErr) {
			if _, usrErr := os.Stat("/usr/lib/systemd/system/headscale.service"); os.IsNotExist(usrErr) {
				if info, err := os.Lstat("/etc/systemd/system/headscale.service"); err == nil && !info.IsDir() {
					if rmErr := os.Remove("/etc/systemd/system/headscale.service"); rmErr == nil && systemctlAvailable() {
						_ = exec.Command("systemctl", "--no-ask-password", "daemon-reload").Run()
					}
				}
			}
		}
	}
	if pluginID == "rosenpass" {
		// Legacy cleanup: before the bundled-binaries migration
		// the rosenpass binary (and `rp`) lived in /usr/local/bin.
		// Remove them on uninstall so a stale copy cannot shadow
		// — or be mistaken for — the plugin-dir binary. Only
		// regular files/symlinks are removed, never directories.
		for _, legacy := range []string{"/usr/local/bin/rosenpass", "/usr/local/bin/rp"} {
			if info, err := os.Lstat(legacy); err == nil && !info.IsDir() {
				if err := os.Remove(legacy); err != nil {
					log.Printf("[PluginManager] Warning: failed to remove legacy rosenpass binary %s: %v", legacy, err)
				}
			}
		}
	}
	if pluginID == "cli-workstation" {
		pm.mu.Lock()
		pm.disabledMap[pluginID] = true
		pm.mu.Unlock()
		_ = os.MkdirAll("/etc/axonwall", 0755)
		_ = os.WriteFile("/etc/axonwall/workstation.disabled", []byte("disabled=true\n"), 0644)
		if pm.osFamily == "alpine" && !isMinimalEditionRoot("/") {
			// Restore a real /bin/bash wrapper if /bin/bash exists (never symlink /bin/ash -> BusyBox argv[0]=zsh applet error)
			_ = os.Remove("/usr/bin/zsh")
			if _, err := os.Stat("/bin/bash"); err == nil {
				_ = os.WriteFile("/usr/bin/zsh", []byte("#!/bin/sh\nexec /bin/bash \"$@\"\n"), 0755)
				SyncZshInEtcShells(true)
			} else if os.Geteuid() == 0 {
				resetMissingZshUsersToBash()
				if SyncZshInEtcShells(false) && hasSSSD() {
					_ = restartSSSD()
				}
				InvalidateSSSDCache("")
			}
		} else if os.Geteuid() == 0 {
			resetMissingZshUsersToBash()
			if SyncZshInEtcShells(false) && hasSSSD() {
				_ = restartSSSD()
			}
			InvalidateSSSDCache("")
		}
	}

	pm.mu.Lock()
	delete(pm.installedMap, pluginID)
	if target.DefaultEnabled {
		pm.disabledMap[pluginID] = true
	}
	pm.saveState()
	pm.mu.Unlock()

	// Shell PATH (soft-fail): remove the snippet — the plugin dir is
	// already gone, so the snippet must not outlive it.
	if err := RemovePluginShellPath(pm, pluginID); err != nil {
		log.Printf("[PluginManager] Warning: failed to remove shell PATH for plugin %s: %v", pluginID, err)
	}

	return PluginActionResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully uninstalled plugin %s (%s)", target.Name, pluginID),
		Output:  output.String(),
	}
}

func (pm *PluginManager) ReconfigurePlugin(pluginID string) PluginActionResponse {
	pm.actionMu.Lock()
	defer pm.actionMu.Unlock()
	if pluginID == "core-k3s" {
		// Core-k3s install/ensure flow. InstallPlugin's core-*
		// branch funnels here, and so does EnablePlugin (via
		// ReconfigurePlugin), so this is the one place the
		// bundled k3s + k9s tree is ensured: the image builders
		// pre-stage it with bundled.json, and
		// ensureBundledBinaries verifies that tree first and
		// downloads only when a file is missing or mismatched —
		// a first boot never re-downloads ~110 MB. The k3s
		// multicall symlinks are (re)created in the plugin bin
		// dir, soft-fail: the units and the daemon resolve k3s
		// directly, and kubectl also resolves via `k3s kubectl`.
		def, ok := lookupPluginDefinition(pluginID)
		if !ok {
			return PluginActionResponse{
				Success: false,
				Message: "core-k3s plugin definition is missing; cannot ensure bundled binaries",
			}
		}
		if err := pm.ensureBundledBinaries(def); err != nil {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to ensure core-k3s bundled binaries: %v", err),
			}
		}
		if err := pm.ensureCoreK3sBinSymlinks(); err != nil {
			log.Printf("[PluginManager] Warning: failed to create core-k3s multicall symlinks: %v", err)
		}
		if os.Geteuid() == 0 {
			if err := ensureCoreK3sSystemdUnit(); err != nil {
				log.Printf("[PluginManager] Warning: failed to provision core-k3s systemd unit: %v", err)
			}
		}
		pm.mu.Lock()
		delete(pm.disabledMap, pluginID)
		if pm.installedMap[pluginID] == "" {
			pm.installedMap[pluginID] = time.Now().UTC().Format(time.RFC3339)
		}
		pm.saveState()
		pm.mu.Unlock()
		// Shell PATH (soft-fail): interactive shells get the core-k3s
		// bin dir too — the shell helpers know core definitions.
		if err := SyncPluginShellPaths(pm, pluginID); err != nil {
			log.Printf("[PluginManager] Warning: failed to sync shell PATH for plugin %s: %v", pluginID, err)
		}
		return PluginActionResponse{
			Success: true,
			Message: "Kubernetes (K3s) & OpenEBS Distributed Storage enabled; bundled k3s and k9s verified in the core-k3s plugin directory.",
		}
	}
	if pluginID == "cli-workstation" {
		_ = os.Remove("/etc/axonwall/workstation.disabled")
		pm.mu.Lock()
		delete(pm.disabledMap, pluginID)
		pm.saveState()
		pm.mu.Unlock()
		// Re-create the bin/vi + bin/vim symlinks if they were
		// deleted (soft-fail, like the core-k3s multicall
		// symlinks in the core-k3s branch above): reconfigure
		// repairs, only a reinstall restores a missing nvim
		// tree. Debian only — on Alpine/Arch there is no bundled
		// nvim and the helper would fail closed.
		if pm.osFamily == "debian" {
			if err := pm.ensureWorkstationNvimSymlinks(); err != nil {
				log.Printf("[PluginManager] Warning: failed to create cli-workstation vi/vim symlinks: %v", err)
			}
		}
		if err := pm.provisionWorkstationConfigs(); err != nil {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to reconfigure workstation: %v", err),
			}
		}
		// Shell PATH: provisioning rewrote /etc/zsh/zshenv, which wipes
		// the plugin PATH loader block — rebuild it (soft-fail).
		if err := RebuildPluginShellPaths(pm); err != nil {
			log.Printf("[PluginManager] Warning: failed to rebuild plugin shell PATHs: %v", err)
		}
		return PluginActionResponse{
			Success: true,
			Message: "Workstation terminal, ZSH, Oh My Zsh (kubectl + stack plugins), Starship, VIM, and Tmux configs re-provisioned successfully.",
		}
	}
	if pluginID == "rosenpass" {
		err := ProvisionRosenpassEnvironment(DefaultRosenpassDir)
		if err != nil && (!errors.Is(err, errNoSupportedInit) || systemctlAvailable()) {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to provision Rosenpass environment: %v", err),
			}
		}
		// A-M33 (round 2): Reconfigure claimed the keypair and unit
		// were "verified" without verifying anything. Verify the
		// unit loads and its ExecStart binary exists before saying
		// so; on a host without systemd there is nothing to verify
		// against and the message says provisioned, not verified.
		if err := verifyRosenpassUnit(); err != nil {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Rosenpass keypair provisioned but systemd unit not verified: %v", err),
			}
		}
		if systemctlAvailable() {
			return PluginActionResponse{
				Success: true,
				Message: "Rosenpass Post-Quantum McEliece 460896 keypair and systemd unit verified.",
			}
		}
		return PluginActionResponse{
			Success: true,
			Message: "Rosenpass Post-Quantum McEliece 460896 keypair and systemd unit provisioned (no systemd on this host; service start not verified).",
		}
	}
	if pluginID == "vigilant-octo-waffle" {
		_ = os.MkdirAll("/etc/axonwall/vow", 0755)
		_ = os.MkdirAll("/etc/rancher/k3s", 0755)
		_ = os.MkdirAll("/var/lib/rancher/k3s/server/manifests", 0755)
		pm.mu.Lock()
		delete(pm.disabledMap, pluginID)
		if pm.installedMap[pluginID] == "" {
			pm.installedMap[pluginID] = time.Now().UTC().Format(time.RFC3339)
		}
		pm.saveState()
		pm.mu.Unlock()
		pm.ensurePluginLDAP(pluginID)
		return PluginActionResponse{
			Success: true,
			Message: "Vigilant Octo Waffle (K8s GitOps & App Platform) enabled; K3s configuration provisioned (Dependency: core-k3s).",
		}
	}
	if pluginID == "core-vigilante" || pluginID == "vigilante" {
		_ = os.MkdirAll("/etc/axonwall/vigilante", 0755)
		_ = os.MkdirAll("/var/lib/axonwall/vigilante", 0755)
		_ = os.MkdirAll("/etc/rancher/k3s", 0755)
		_ = os.MkdirAll("/var/lib/rancher/k3s/server/manifests", 0755)
		pm.ensurePluginLDAP("core-vigilante")
		return PluginActionResponse{
			Success: true,
			Message: "Vigilante Cyber Defense, SOAR & Autonomous SOC OpenLDAP integration and in-house K3s runtime configured (Dependency: core-k3s).",
		}
	}
	if pluginID == "host-malware-rootkit" {
		pm.mu.Lock()
		delete(pm.disabledMap, pluginID)
		if pm.installedMap[pluginID] == "" {
			pm.installedMap[pluginID] = time.Now().UTC().Format(time.RFC3339)
		}
		pm.saveState()
		pm.mu.Unlock()
		return PluginActionResponse{
			Success: true,
			Message: "Host Malware, Rootkit & Ghost-in-the-Ring Kernel Hunter enabled.",
		}
	}
	if pluginID == "eluvix" {
		_ = os.MkdirAll("/etc/axonwall/eluvix", 0755)
		pm.mu.Lock()
		delete(pm.disabledMap, pluginID)
		if pm.installedMap[pluginID] == "" {
			pm.installedMap[pluginID] = time.Now().UTC().Format(time.RFC3339)
		}
		pm.saveState()
		pm.mu.Unlock()
		pm.ensurePluginLDAP(pluginID)
		return PluginActionResponse{
			Success: true,
			Message: "Eluvix Sovereign AI Router, Enterprise Tokenomics & Prompt/PII Guard enabled; configuration provisioned.",
		}
	}
	if pluginID == "ebpf-threat-harvester" {
		_ = os.MkdirAll("/var/lib/axonwall/threat-corpus", 0750)
		// R4-A-M4: enabling the plugin must actually start the
		// harvester (EnablePlugin funnels through here). On failure
		// the plugin stays recorded disabled instead of reporting
		// success while nothing runs.
		if err := pm.setHarvesterEnabled(true); err != nil {
			pm.mu.Lock()
			pm.disabledMap[pluginID] = true
			pm.saveState()
			pm.mu.Unlock()
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to start the threat harvester for plugin %s: %v", pluginID, err),
			}
		}
		pm.mu.Lock()
		delete(pm.disabledMap, pluginID)
		if pm.installedMap[pluginID] == "" {
			pm.installedMap[pluginID] = time.Now().UTC().Format(time.RFC3339)
		}
		pm.saveState()
		pm.mu.Unlock()
		return PluginActionResponse{
			Success: true,
			Message: "eBPF Threat-LLM Harvester (Blackbox) CO-RE telemetry spool configured.",
		}
	}
	pm.ensurePluginLDAP(pluginID)
	return PluginActionResponse{
		Success: true,
		Message: fmt.Sprintf("Plugin %s is already up-to-date.", pluginID),
	}
}

func (pm *PluginManager) provisionWorkstationConfigs() error {
	_ = os.MkdirAll("/etc/axonwall", 0755)
	_ = os.MkdirAll("/etc/zsh", 0755)
	_ = os.MkdirAll("/etc/skel", 0755)
	_ = os.MkdirAll("/etc/vim", 0755)
	_ = os.MkdirAll("/root", 0700)
	_ = os.MkdirAll("/usr/share/oh-my-zsh/lib", 0755)
	_ = os.MkdirAll("/usr/share/oh-my-zsh/custom/plugins", 0755)
	for _, plug := range []string{"kubectl", "helm", "git", "systemd", "sudo", "tmux", "extract", "colored-man-pages", "docker", "axonwall"} {
		_ = os.MkdirAll(filepath.Join("/usr/share/oh-my-zsh/plugins", plug), 0755)
	}

	// 1. /etc/axonwall/starship.toml
	starshipConf := `# ==============================================================================
# Axonwall Appliance — Starship Cross-Shell Prompt Configuration
# Guide: https://starship.rs/guide/ | Location: /etc/axonwall/starship.toml
# ==============================================================================

"$schema" = 'https://starship.rs/config-schema.json'

add_newline = false
command_timeout = 500

format = """
[\\[axonwall\\]](bold #10b981) \
${custom.axonwall_commit}\
$username\
[@](bold #64748b)\
$hostname\
[:](bold #64748b)\
$directory\
$git_branch\
$git_status\
$kubernetes\
$cmd_duration\
$jobs\
$status\
$line_break\
$character"""

right_format = """${custom.axonwall_if}$time"""

[custom.axonwall_commit]
command = "cat /run/axonwall/commit-confirm.pending 2>/dev/null || echo 'COMMIT-CONFIRM ACTIVE'"
when = "test -f /run/axonwall/commit-confirm.pending"
style = "bold #f59e0b"
format = '[⚠ $output — run ` + "`confirm`" + ` ]($style)'
shell = ["/bin/sh", "-c"]

[custom.axonwall_if]
when = "true"
command = "ip route show default 2>/dev/null | awk '{print $5; exit}'"
style = "dimmed #38bdf8"
format = '([\[$output\]]($style) )'
shell = ["/bin/sh", "-c"]

[username]
show_always = true
style_user = "bold #38bdf8"
style_root = "bold #ef4444"
format = "[$user]($style)"

[hostname]
ssh_only = false
style = "bold #f8fafc"
format = "[$hostname]($style)"
trim_at = "."

[directory]
truncation_length = 4
truncate_to_repo = false
style = "bold #06b6d4"
format = "[$path]($style) "

[git_branch]
symbol = "git:"
style = "bold #a855f7"
format = "on [$symbol$branch]($style) "

[git_status]
style = "bold #f59e0b"
format = '([\[$all_status$ahead_behind\]]($style) )'

[kubernetes]
disabled = false
symbol = "☸ "
style = "bold #38bdf8"
format = '[$symbol$context( \($namespace\))]($style) '

[character]
success_symbol = "[❯](bold #10b981)"
error_symbol = "[❯](bold #ef4444)"
vimcmd_symbol = "[❮](bold #38bdf8)"
`
	_ = os.WriteFile("/etc/axonwall/starship.toml", []byte(starshipConf), 0644)

	// 2. Provision Oh My Zsh loader if not already present on disk
	omzLoaderPath := "/usr/share/oh-my-zsh/oh-my-zsh.sh"
	if _, err := os.Stat(omzLoaderPath); os.IsNotExist(err) {
		omzLoader := `# Oh My Zsh (https://ohmyz.sh) — Axonwall System-Wide Distribution Loader
export ZSH="${ZSH:-/usr/share/oh-my-zsh}"
export ZSH_CUSTOM="${ZSH_CUSTOM:-$ZSH/custom}"
export ZSH_CACHE_DIR="${ZSH_CACHE_DIR:-${HOME}/.cache/oh-my-zsh}"
mkdir -p "${ZSH_CACHE_DIR}/completions" 2>/dev/null || true
fpath=("$ZSH/functions" "$ZSH/completions" "${ZSH_CACHE_DIR}/completions" $fpath)
for _omz_plugin in ${plugins[@]}; do
  if [[ -d "$ZSH_CUSTOM/plugins/$_omz_plugin" ]]; then
    fpath=("$ZSH_CUSTOM/plugins/$_omz_plugin" $fpath)
  elif [[ -d "$ZSH/plugins/$_omz_plugin" ]]; then
    fpath=("$ZSH/plugins/$_omz_plugin" $fpath)
  fi
done
unset _omz_plugin
autoload -Uz compinit
compinit -u -d "${ZSH_CACHE_DIR}/.zcompdump-${ZSH_VERSION:-zsh}" 2>/dev/null || compinit -u 2>/dev/null || true
for _omz_lib in "$ZSH"/lib/*.zsh(N); do
  source "$_omz_lib"
done
unset _omz_lib
for _omz_plugin in ${plugins[@]}; do
  if [[ -f "$ZSH_CUSTOM/plugins/$_omz_plugin/$_omz_plugin.plugin.zsh" ]]; then
    source "$ZSH_CUSTOM/plugins/$_omz_plugin/$_omz_plugin.plugin.zsh"
  elif [[ -f "$ZSH/plugins/$_omz_plugin/$_omz_plugin.plugin.zsh" ]]; then
    source "$ZSH/plugins/$_omz_plugin/$_omz_plugin.plugin.zsh"
  fi
done
unset _omz_plugin
`
		_ = os.WriteFile(omzLoaderPath, []byte(omzLoader), 0644)
	}

	// Ensure kubectl Oh My Zsh plugin exists
	kubectlPluginPath := "/usr/share/oh-my-zsh/plugins/kubectl/kubectl.plugin.zsh"
	if _, err := os.Stat(kubectlPluginPath); os.IsNotExist(err) {
		kubectlPlug := `# Oh My Zsh — kubectl plugin
if [[ -z "${KUBECONFIG:-}" ]] && [[ -r /etc/rancher/k3s/k3s.yaml ]]; then
  export KUBECONFIG="/etc/rancher/k3s/k3s.yaml"
fi
if ! (( $+commands[kubectl] )) && (( $+commands[k3s] )); then
  function kubectl() { command k3s kubectl "$@"; }
fi
if (( $+commands[kubectl] )) || (( $+commands[k3s] )); then
  if [[ ! -f "${ZSH_CACHE_DIR}/completions/_kubectl" ]]; then
    kubectl completion zsh 2>/dev/null >| "${ZSH_CACHE_DIR}/completions/_kubectl" &|
  fi
  [[ -s "${ZSH_CACHE_DIR}/completions/_kubectl" ]] && source "${ZSH_CACHE_DIR}/completions/_kubectl" 2>/dev/null
fi
alias k='kubectl'
alias kgp='kubectl get pods'
alias kgpa='kubectl get pods --all-namespaces'
alias kgs='kubectl get svc'
alias kgsa='kubectl get svc --all-namespaces'
alias kgn='kubectl get nodes -o wide'
alias kgd='kubectl get deployment'
alias kgpvc='kubectl get pvc'
alias kdp='kubectl describe pods'
alias kds='kubectl describe svc'
alias kdno='kubectl describe node'
alias kl='kubectl logs'
alias klf='kubectl logs -f'
alias kex='kubectl exec -it'
alias kaf='kubectl apply -f'
alias kdel='kubectl delete'
alias kctx='kubectl config get-contexts'
alias kns='kubectl config set-context --current --namespace'
alias kroll='kubectl rollout restart deployment'
`
		_ = os.WriteFile(kubectlPluginPath, []byte(kubectlPlug), 0644)
	}

	// Ensure helm Oh My Zsh plugin exists
	helmPluginPath := "/usr/share/oh-my-zsh/plugins/helm/helm.plugin.zsh"
	if _, err := os.Stat(helmPluginPath); os.IsNotExist(err) {
		helmPlug := `# Oh My Zsh — helm plugin
if (( $+commands[helm] )); then
  if [[ ! -f "${ZSH_CACHE_DIR}/completions/_helm" ]]; then
    helm completion zsh 2>/dev/null >| "${ZSH_CACHE_DIR}/completions/_helm" &|
  fi
  [[ -s "${ZSH_CACHE_DIR}/completions/_helm" ]] && source "${ZSH_CACHE_DIR}/completions/_helm" 2>/dev/null
  alias h='helm'
  alias hl='helm list'
  alias hla='helm list --all-namespaces'
  alias hi='helm install'
  alias hu='helm upgrade --install'
  alias hd='helm uninstall'
  alias hs='helm status'
  alias hrepo='helm repo'
  alias hse='helm search'
fi
`
		_ = os.WriteFile(helmPluginPath, []byte(helmPlug), 0644)
	}

	// Ensure bat -> batcat and fd -> fdfind symlinks exist on Debian
	_ = os.MkdirAll("/usr/local/bin", 0755)
	if _, err := os.Stat("/usr/bin/batcat"); err == nil {
		if _, err := os.Lstat("/usr/local/bin/bat"); os.IsNotExist(err) {
			_ = os.Symlink("/usr/bin/batcat", "/usr/local/bin/bat")
		}
	}
	if _, err := os.Stat("/usr/bin/fdfind"); err == nil {
		if _, err := os.Lstat("/usr/local/bin/fd"); os.IsNotExist(err) {
			_ = os.Symlink("/usr/bin/fdfind", "/usr/local/bin/fd")
		}
	}

	// 3. /etc/zsh/axonwall.zsh (preserve packaged rich version if already present and non-empty, otherwise write full config)
	zshConf := `# ==============================================================================
# Axonwall Appliance Modern ZSH Configuration (/etc/zsh/axonwall.zsh)
# Powered by Oh My Zsh (https://ohmyz.sh) + Starship + Full Stack Completions
# Sourced by /etc/zsh/zshrc and ~/.zshrc for interactive shell sessions
# ==============================================================================

if [[ -n "${_AXONWALL_ZSH_LOADED:-}" ]]; then
  return 0
fi
export _AXONWALL_ZSH_LOADED=1

export EDITOR="vim"
export VISUAL="vim"
export PAGER="less -FRX"
# Preserve any PATH entries added earlier (e.g. plugin bin dirs from
# /etc/zsh/zshenv): add each system dir only if missing, instead of
# resetting PATH outright. The old hard reset wiped plugin PATH
# entries in non-login interactive zsh (tmux panes, 'zsh' started
# from another shell), which zlogin never heals — only login shells
# were restored. This loop is idempotent and preserves order.
for _d in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do
  case ":$PATH:" in *":$_d:"*) ;; *) PATH="$_d:$PATH";; esac
done
export PATH
unset _d

if [[ -z "${KUBECONFIG:-}" ]] && [[ -r /etc/rancher/k3s/k3s.yaml ]]; then
  export KUBECONFIG="/etc/rancher/k3s/k3s.yaml"
fi

if [[ -f /etc/axonwall/workstation.disabled ]]; then
  PROMPT='%n@%m:%~%# '
  return 0
fi

export STARSHIP_CONFIG="/etc/axonwall/starship.toml"
export STARSHIP_LOG="error"

export ZSH="${ZSH:-/usr/share/oh-my-zsh}"
export ZSH_CUSTOM="${ZSH_CUSTOM:-$ZSH/custom}"
export ZSH_CACHE_DIR="${HOME}/.cache/oh-my-zsh"
DISABLE_AUTO_UPDATE="true"
DISABLE_UPDATE_PROMPT="true"

if [[ -d /usr/share/oh-my-zsh ]] && [[ -n "${HOME:-}" ]] && [[ -d "${HOME}" ]] && [[ ! -e "${HOME}/.oh-my-zsh" ]]; then
  ln -s /usr/share/oh-my-zsh "${HOME}/.oh-my-zsh" 2>/dev/null || true
fi

plugins=(
  git
  kubectl
  helm
  docker
  systemd
  sudo
  tmux
  extract
  colored-man-pages
  axonwall
)

if [[ -f "$ZSH/oh-my-zsh.sh" ]]; then
  source "$ZSH/oh-my-zsh.sh"
fi

HISTFILE="${HOME}/.zsh_history"
HISTSIZE=50000
SAVEHIST=50000
setopt APPEND_HISTORY
setopt SHARE_HISTORY
setopt HIST_IGNORE_DUPS
setopt HIST_IGNORE_SPACE

if [[ -f /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh ]]; then
  ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=242'
  source /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh
elif [[ -f /usr/share/zsh/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh ]]; then
  ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=242'
  source /usr/share/zsh/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh
fi
if [[ -f /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ]]; then
  source /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
elif [[ -f /usr/share/zsh/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ]]; then
  source /usr/share/zsh/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
fi

if command -v starship >/dev/null 2>&1; then
  eval "$(starship init zsh)"
fi

alias tui='axonwall-tui'
alias webtui='axonwall-tui'
alias nastymap='axonwall-tui --tab nastymap'
alias nui='axonwall-config'
alias cfg='axonwall-config'
alias superedit='axonwall-config'
alias console='/usr/sbin/axonwall-console'
alias ctl='axonwallctl'
alias confirm='axonwallctl confirm'
alias rollback='axonwallctl rollback'
alias vi='vim'
if command -v batcat >/dev/null 2>&1 && ! command -v bat >/dev/null 2>&1; then
  alias bat='batcat'
fi
if command -v fdfind >/dev/null 2>&1 && ! command -v fd >/dev/null 2>&1; then
  alias fd='fdfind'
fi
alias ll='ls -lah --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias diff='diff --color=auto'
alias grep='grep --color=auto'
alias ports='ss -tulnp'
alias fw='nft list ruleset'
alias rules='nft list ruleset'
alias routes='ip -c route show'
alias ifaces='ip -brief -c addr'
`
	if existing, err := os.ReadFile("/etc/zsh/axonwall.zsh"); err != nil || !strings.Contains(string(existing), "oh-my-zsh") || strings.Contains(string(existing), `export PATH="/usr/local/sbin:`) {
		_ = os.WriteFile("/etc/zsh/axonwall.zsh", []byte(zshConf), 0644)
	}

	// 4. /etc/zsh/zshenv
	_ = os.WriteFile("/etc/zsh/zshenv", []byte("export STARSHIP_CONFIG=/etc/axonwall/starship.toml\n"), 0644)

	// 5. /etc/skel/.zshrc and /root/.zshrc and /root/.oh-my-zsh
	userZshrc := `# Axonwall ZSH User Profile (Oh My Zsh + Starship + Stack Completions)
[[ -f /etc/zsh/axonwall.zsh ]] && source /etc/zsh/axonwall.zsh
`
	_ = os.WriteFile("/etc/skel/.zshrc", []byte(userZshrc), 0644)
	if _, err := os.Stat("/root/.zshrc"); os.IsNotExist(err) {
		_ = os.WriteFile("/root/.zshrc", []byte(userZshrc), 0640)
	}
	if _, err := os.Lstat("/root/.oh-my-zsh"); os.IsNotExist(err) {
		_ = os.Symlink("/usr/share/oh-my-zsh", "/root/.oh-my-zsh")
	}

	// 6. /etc/vim/vimrc.local
	vimConf := `" Axonwall Appliance Modern VIM Configuration (/etc/vim/vimrc.local)
syntax on
filetype plugin indent on
set nocompatible
set encoding=utf-8
set background=dark
set number
set ruler
set autoindent
set expandtab
set tabstop=2
set shiftwidth=2
set mouse=
set hlsearch
set incsearch
`
	_ = os.WriteFile("/etc/vim/vimrc.local", []byte(vimConf), 0644)

	// 7. /etc/tmux.conf
	tmuxConf := `# Axonwall Appliance Modern tmux Configuration (/etc/tmux.conf)
set -g default-terminal "screen-256color"
set -g default-shell /usr/bin/zsh
set -g history-limit 50000
set -g mouse on
set -g status-interval 5
set -g status-style "bg=#0f172a,fg=#e2e8f0"
set -g status-left "#[fg=#0f172a,bg=#10b981,bold] AXONWALL #[default] "
`
	_ = os.WriteFile("/etc/tmux.conf", []byte(tmuxConf), 0644)

	return nil
}
