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
// plugin. Kind discriminates the two source kinds unambiguously:
//
//   - "archive": a downloadable archive. URL is required; Distro /
//     Package / Version / Arch must be empty. Name is the binary the
//     archive provides (e.g. "rosenpass", fetched from
//     https://github.com/rosenpass/rosenpass/releases/download/v0.2.3/rosenpass-x86_64-linux-0.2.3.tar).
//     Format is the container ("tar", "tar.gz"/"tgz", "zip"; default
//     "tar"). PathInArchive is the binary's path inside the archive,
//     relative with no ".."; it defaults to Name.
//   - "distroPackage": a distro package to download and extract
//     (never install). URL must be empty; Distro / Package / Version /
//     Arch are required. Name is the package name (e.g. "emacs-nox");
//     the binaries it contributes are found via BinDirs after
//     extraction. Version is the full version including epoch where
//     the distro uses one (e.g. "1:30.1+1-6"); the daemon derives the
//     file name from Package + Version + Arch (Debian filenames drop
//     the epoch, e.g. "emacs-nox_30.1+1-6_amd64.deb" under
//     pool/main/e/emacs/).
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
// empty) or "distroPackage" (Distro, Package, Version, Arch set; URL
// empty).
type PluginBundledBinary struct {
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	SHA256        string `json:"sha256"`
	URL           string `json:"url,omitempty"`
	Format        string `json:"format,omitempty"`
	PathInArchive string `json:"pathInArchive,omitempty"`
	Distro        string `json:"distro,omitempty"`
	Package       string `json:"package,omitempty"`
	Version       string `json:"version,omitempty"`
	Arch          string `json:"arch,omitempty"`
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
			DebianPackages: []string{
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
			RequiredBinaries: []string{"zsh", "vim", "nvim", "starship", "tmux", "kubectl", "helm"},
		},
		{
			// GNU Emacs, bundled — not system-installed. The three
			// trixie amd64 .debs are downloaded, sha256-verified, and
			// extracted (dpkg-deb -x layout) into the plugin's own
			// directory; nothing is installed into the system, so
			// DebianPackages/AlpinePackages/ArchPackages are
			// deliberately empty (ArchPackages is an empty slice, not
			// nil, per TestArchPluginPackagesAndRootkitScannerSlot).
			// SHA256 values are SHA256_TODO_* placeholders: a later
			// worker replaces them with the real digests from the
			// Debian Packages index; the daemon must fail closed on
			// them until then. Expected files (epoch dropped from the
			// filename, per Debian convention) under
			// pool/main/e/emacs/:
			//   emacs-nox_30.1+1-6_amd64.deb
			//   emacs-bin-common_30.1+1-6_amd64.deb
			//   emacs-common_30.1+1-6_all.deb
			// UNCERTAIN: live trixie now serves 1:30.1+1-6+deb13u1
			// (security update, same pool path, filenames with the
			// +deb13u1 suffix), not the 1:30.1+1-6 pinned here — the
			// resolving worker must confirm the exact version and
			// hashes against the Packages index before install.
			ID:               "cli-emacs",
			Name:             "Emacs Editor (GNU Emacs, no-X) for /etc/axonwall",
			Version:          "0.1.0",
			Category:         "extension",
			Description:      "GNU Emacs (no-X) for editing /etc/axonwall configuration files, bundled with the plugin: the Debian emacs-nox 30.1 tree is downloaded, checksum-verified, and extracted into the plugin's own directory, and its bin directory is added to PATH for daemon invocations and interactive shells. Nothing is installed into the system.",
			Author:           "Axonwall Core",
			Privileges:       []string{"system.users", "system.config.write"},
			DebianPackages:   []string{},
			AlpinePackages:   []string{},
			ArchPackages:     []string{},
			RequiredBinaries: []string{"emacs"},
			Binaries: []PluginBundledBinary{
				{
					Kind:    "distroPackage",
					Name:    "emacs-nox",
					SHA256:  "SHA256_TODO_emacs-nox",
					Distro:  "debian",
					Package: "emacs-nox",
					Version: "1:30.1+1-6",
					Arch:    "amd64",
				},
				{
					Kind:    "distroPackage",
					Name:    "emacs-bin-common",
					SHA256:  "SHA256_TODO_emacs-bin-common",
					Distro:  "debian",
					Package: "emacs-bin-common",
					Version: "1:30.1+1-6",
					Arch:    "amd64",
				},
				{
					Kind:    "distroPackage",
					Name:    "emacs-common",
					SHA256:  "SHA256_TODO_emacs-common",
					Distro:  "debian",
					Package: "emacs-common",
					Version: "1:30.1+1-6",
					Arch:    "all",
				},
			},
			BinDirs: []string{"usr/bin"},
			Env: map[string]string{
				"EMACSDATA": "${PLUGIN_DIR}/usr/share/emacs/30.1",
			},
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
			Version:          "0.2.2",
			Category:         "extension",
			Description:      "Hybrid Dual-KEM post-quantum key exchange daemon (Classic McEliece 460896 static authentication + ephemeral ML-KEM-512 forward secrecy) that rotates kernel WireGuard pre-shared keys every 120s with fail-closed boot protection.",
			Author:           "Rosenpass Project / Axonwall Core",
			SystemdUnits:     []string{"rosenpass.service"},
			Privileges:       []string{"vpn.admin", "network.interfaces"},
			DebianPackages:   []string{"wireguard-tools"},
			AlpinePackages:   []string{"rosenpass", "wireguard-tools"},
			ArchPackages:     []string{"rosenpass", "wireguard-tools"},
			RequiredBinaries: []string{"rosenpass", "wg"},
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
// <plugindir>/bin/<name> unless PathInArchive says otherwise.
// BinDirs are relative to the plugin dir (e.g. "usr/bin") and are
// prepended to PATH for daemon invocations of that plugin's commands.
//
// Trust model: nothing under a plugin dir is trusted on the strength
// of having been downloaded once. Install sha256-verifies every
// artifact before extraction and writes bundled.json (one record per
// installed file); every later use re-verifies bundled.json and the
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
		switch b.Kind {
		case "archive":
			if b.URL == "" {
				return fmt.Errorf("bundled binary %q (archive): url is required", b.Name)
			}
			u, err := url.Parse(b.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("bundled binary %q (archive): url %q must be an http(s) URL", b.Name, b.URL)
			}
			if b.Distro != "" || b.Package != "" || b.Version != "" || b.Arch != "" {
				return fmt.Errorf("bundled binary %q (archive): distro/package/version/arch must be empty for kind archive", b.Name)
			}
			switch strings.ToLower(strings.TrimSpace(b.Format)) {
			case "", "tar", "tar.gz", "tgz", "zip":
			default:
				return fmt.Errorf("bundled binary %q (archive): unsupported format %q (want tar, tar.gz, tgz or zip)", b.Name, b.Format)
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
			if !debVersionPattern.MatchString(b.Version) || strings.ContainsAny(b.Version, `/\`) {
				return fmt.Errorf("bundled binary %q (distroPackage): version %q is not a valid Debian version", b.Name, b.Version)
			}
			if !debArchPattern.MatchString(b.Arch) {
				return fmt.Errorf("bundled binary %q (distroPackage): arch %q is not valid", b.Name, b.Arch)
			}
		default:
			return fmt.Errorf("bundled binary %q: unknown kind %q (want archive or distroPackage)", b.Name, b.Kind)
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
	Files    []bundledBinaryRecord `json:"files"`
}

func bundledRecordPath(pluginDir string) string {
	return filepath.Join(pluginDir, "bundled.json")
}

// sha256File returns the lowercase hex sha256 of a file's contents.
func sha256File(path string) (string, error) {
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
// ("1:" in "1:30.1+1-6") is dropped from the filename.
//
// LIMITATION: the manifest schema has no source-package field, so
// this assumes source == package name (the source directory is the
// package name). That holds for emacs-nox/emacs-bin-common/
// emacs-common (source package "emacs") and for most binary
// packages, but NOT for packages built from a differently-named
// source (e.g. a binary whose source package differs). Such an
// entry would 404 at download time and fail closed; a source field
// must be added to the schema before those packages can be bundled.
func debianPoolURL(b PluginBundledBinary) (string, error) {
	source := b.Package // see LIMITATION above: source == package name
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

// installBundledBinaries downloads, sha256-verifies and extracts
// every Binaries entry of def into the plugin dir. Archive entries
// land in <plugindir>/bin/; distroPackage entries are extracted
// merged into the plugin dir with `dpkg-deb -x` (the one shell-out
// allowed here — dpkg-deb itself is the format's extractor, and a
// missing dpkg-deb fails closed). On any error the install aborts
// and bundled.json is NOT written, so a half-extracted tree can
// never pass verifyBundledBinaries. Callers must validate first.
func (pm *PluginManager) installBundledBinaries(def PluginDefinition) error {
	pluginDir, err := pm.pluginDir(def.ID)
	if err != nil {
		return err
	}
	// Start from a clean tree: files left over from a previous
	// version of the plugin must not linger and get recorded as if
	// the new manifest installed them. (A failed install leaves no
	// bundled.json, so the cleaned tree still fails verification.)
	if err := os.RemoveAll(pluginDir); err != nil {
		return err
	}
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return err
	}
	tmpDir, err := os.MkdirTemp("", "axonwall-plugin-bundled-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	var records []bundledBinaryRecord
	seen := make(map[string]bool)
	for _, b := range def.Binaries {
		switch b.Kind {
		case "archive":
			want := b.PathInArchive
			if want == "" {
				want = b.Name
			}
			tmpPath, err := downloadVerified(b.URL, b.SHA256, tmpDir)
			if err != nil {
				return fmt.Errorf("bundled binary %q: %w", b.Name, err)
			}
			rel, err := extractArchiveBinary(tmpPath, b.Format, want, b.Name, pluginDir)
			os.Remove(tmpPath)
			if err != nil {
				return fmt.Errorf("bundled binary %q: %w", b.Name, err)
			}
			sum, err := sha256File(filepath.Join(pluginDir, rel))
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
			// dpkg-deb -x extracts only; nothing is installed
			// into the system and no maintainer scripts run.
			cmd := exec.Command(dpkgDeb, "-x", tmpPath, pluginDir)
			if out, err := cmd.CombinedOutput(); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("bundled binary %q: dpkg-deb -x failed: %w (output: %s)", b.Name, err, strings.TrimSpace(string(out)))
			}
			os.Remove(tmpPath)
			if err := recordInstalledFiles(pluginDir, b, seen, &records); err != nil {
				return fmt.Errorf("bundled binary %q: %w", b.Name, err)
			}
		default:
			return fmt.Errorf("bundled binary %q: unknown kind %q", b.Name, b.Kind)
		}
	}

	// Executable bits on everything under the declared BinDirs:
	// extracted .deb trees carry their own modes, but an archive
	// entry's binary and any helper under a bin dir must be
	// runnable by the daemon without relying on archive modes.
	for _, binDir := range def.BinDirs {
		root := filepath.Join(pluginDir, filepath.FromSlash(binDir))
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			_ = os.Chmod(path, 0755)
			return nil
		})
	}

	// Only now, with every entry extracted and hashed, is the
	// verification record written: a failed install leaves no
	// bundled.json, so verify can never bless a partial tree.
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	data, err := json.MarshalIndent(bundledBinariesFile{PluginID: def.ID, Files: records}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(bundledRecordPath(pluginDir), data, 0644); err != nil {
		return err
	}
	return nil
}

// expectedBundledBinary returns the on-disk location of the binary a
// manifest entry provides, and whether that location is meaningful
// to check. Archive entries provide <plugindir>/bin/<name> directly.
// A distroPackage entry provides no single binary by name — its
// package name (e.g. "emacs-nox") is not a file — so its expected
// binaries are the plugin's RequiredBinaries under its BinDirs
// (for cli-emacs: usr/bin/emacs). That is what verify checks for
// distroPackage entries.
func (pm *PluginManager) expectedBundledBinaries(def PluginDefinition) []string {
	pluginDir, err := pm.pluginDir(def.ID)
	if err != nil {
		return nil
	}
	var out []string
	for _, b := range def.Binaries {
		switch b.Kind {
		case "archive":
			out = append(out, filepath.Join(pluginDir, "bin", b.Name))
		case "distroPackage":
			for _, bin := range def.RequiredBinaries {
				for _, binDir := range def.BinDirs {
					out = append(out, filepath.Join(pluginDir, filepath.FromSlash(binDir), bin))
				}
			}
		}
	}
	return out
}

// bundledBinariesVerifiedNames lists the bundled binaries that are
// present and executable, for PluginStatus.BundledBinaries: archive
// entry names, plus required binaries found under a BinDir for
// distroPackage entries.
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
		switch b.Kind {
		case "archive":
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
	if rec.PluginID != "" && rec.PluginID != def.ID {
		return fmt.Errorf("plugin %q: bundled verification record belongs to plugin %q", def.ID, rec.PluginID)
	}
	if len(rec.Files) == 0 {
		return fmt.Errorf("plugin %q: bundled verification record lists no files", def.ID)
	}
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
	}
	for _, expected := range pm.expectedBundledBinaries(def) {
		if !isExecutableFile(expected) {
			rel, _ := filepath.Rel(pluginDir, expected)
			return fmt.Errorf("plugin %q: expected bundled binary %q is missing or not executable", def.ID, filepath.ToSlash(rel))
		}
	}
	return nil
}

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
	def, ok := findExtensionPluginDefinition(pluginID)
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
	return exec.Command("sh", "-c", "printf '%s\\n' "+strconv.Quote(msg)+" >&2; exit 127")
}

// CommandForPlugin builds a command to run a plugin's binary with
// that plugin's environment (see PluginEnv). The binary is resolved
// through the plugin's BinDirs first, then the system PATH, so a
// bundled binary is preferred over a system one of the same name.
// For plugins that declare Binaries, the bundled tree is
// re-verified before exec and any failure yields a command that
// fails descriptively rather than running an unverified binary.
func (pm *PluginManager) CommandForPlugin(pluginID, name string, args ...string) *exec.Cmd {
	def, ok := findExtensionPluginDefinition(pluginID)
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

	defs := GetExtensionPluginDefinitions()
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

func (pm *PluginManager) InstallPlugin(pluginID string) PluginActionResponse {
	if strings.HasPrefix(pluginID, "core-") {
		pm.mu.Lock()
		delete(pm.disabledMap, pluginID)
		if pm.installedMap[pluginID] == "" {
			pm.installedMap[pluginID] = time.Now().UTC().Format(time.RFC3339)
		}
		pm.saveState()
		pm.mu.Unlock()
		return pm.ReconfigurePlugin(pluginID)
	}

	pm.actionMu.Lock()
	defer pm.actionMu.Unlock()

	defs := GetExtensionPluginDefinitions()
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

	if pm.osFamily == "arch" && len(pkgs) > 0 {
		if _, err := os.Stat("/var/lib/pacman/db.lck"); err == nil {
			return PluginActionResponse{
				Success: false,
				Message: "Pacman database is locked (/var/lib/pacman/db.lck); another package operation is in progress",
			}
		}
	}

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
				prepCmd := exec.Command("sh", "-c", "apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-unsafe-io gnupg curl ca-certificates lsb-release wget && curl -fsSL https://packages.ntop.org/apt/trixie/all/apt-ntop.deb -o /tmp/apt-ntop.deb && (dpkg --force-unsafe-io -i /tmp/apt-ntop.deb || apt-get install -f -y) && apt-get update")
				prepCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
				if out, err := prepCmd.CombinedOutput(); err != nil {
					log.Printf("[PluginManager] Warning configuring ntopng apt repository: %v (%s)", err, string(out))
				}
			}
		}
	}

	if len(pkgs) > 0 {
		var corePkgs, optionalPkgs []string
		optionalSet := map[string]bool{
			"python3-drgn": true,
			"bpftrace":     true,
			"linux-perf":   true,
			"bpftool":      true,
			"perf":         true,
			"kubectl":      true,
			"starship":     true,
		}
		for _, p := range pkgs {
			if optionalSet[p] {
				optionalPkgs = append(optionalPkgs, p)
			} else {
				corePkgs = append(corePkgs, p)
			}
		}

		if len(corePkgs) > 0 {
			var cmd *exec.Cmd
			switch pm.osFamily {
			case "alpine":
				args := append([]string{"add", "--no-cache"}, corePkgs...)
				cmd = exec.Command("apk", args...)
			case "arch":
				args := append([]string{"-Sy", "--needed", "--noconfirm"}, corePkgs...)
				cmd = exec.Command("pacman", args...)
			default:
				args := append([]string{"install", "-y", "--no-install-recommends", "-o", "Dpkg::Options::=--force-unsafe-io"}, corePkgs...)
				cmd = exec.Command("apt-get", args...)
				cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
			}

			out, err := cmd.CombinedOutput()
			output.WriteString(string(out))
			if err != nil {
				return PluginActionResponse{
					Success: false,
					Message: fmt.Sprintf("Package installation failed: %v", err),
					Output:  output.String(),
				}
			}
		}

		for _, optPkg := range optionalPkgs {
			var optCmd *exec.Cmd
			switch pm.osFamily {
			case "alpine":
				optCmd = exec.Command("apk", "add", "--no-cache", optPkg)
			case "arch":
				optCmd = exec.Command("pacman", "-S", "--needed", "--noconfirm", optPkg)
			default:
				optCmd = exec.Command("apt-get", "install", "-y", "--no-install-recommends", "-o", "Dpkg::Options::=--force-unsafe-io", optPkg)
				optCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
			}
			if out, err := optCmd.CombinedOutput(); err != nil {
				log.Printf("[PluginManager] Note: optional package %s not installed via repo: %v (%s)", optPkg, err, string(out))
			} else {
				output.WriteString(string(out))
			}
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

	// Post-install configuration hooks
	if pluginID == "cli-workstation" || pluginID == "vigilant-octo-waffle" {
		if _, err := exec.LookPath("kubectl"); err != nil {
			if k3sPath, kerr := exec.LookPath("k3s"); kerr == nil && k3sPath != "" {
				_ = os.MkdirAll("/usr/local/bin", 0755)
				_ = os.Symlink(k3sPath, "/usr/local/bin/kubectl")
			}
		}
	}
	if pluginID == "cli-workstation" {
		_ = os.Remove("/etc/axonwall/workstation.disabled")
		pm.mu.Lock()
		delete(pm.disabledMap, pluginID)
		pm.mu.Unlock()
		if err := pm.provisionWorkstationConfigs(); err != nil {
			log.Printf("[PluginManager] Warning provisioning workstation configs: %v", err)
		}
		// On Alpine, if real zsh exists, replace any /usr/bin/zsh -> /bin/ash fallback
		if pm.osFamily == "alpine" {
			if zshPath, err := exec.LookPath("zsh"); err == nil && zshPath != "" {
				_ = os.Remove("/usr/bin/zsh")
				_ = os.Symlink(zshPath, "/usr/bin/zsh")
			}
		}
	}
	if pluginID == "rosenpass" {
		if _, err := exec.LookPath("rosenpass"); err != nil {
			dlCmd := exec.Command("sh", "-c", "tmpd=$(mktemp -d) && curl -fsSL https://github.com/rosenpass/rosenpass/releases/download/v0.2.3/rosenpass-x86_64-linux-0.2.3.tar | tar -xf - -C \"$tmpd\" && find \"$tmpd\" -type f \\( -name rosenpass -o -name rp \\) -exec cp -f {} /usr/local/bin/ \\; && chmod 755 /usr/local/bin/rosenpass /usr/local/bin/rp 2>/dev/null; rm -rf \"$tmpd\"")
			if out, err := dlCmd.CombinedOutput(); err != nil {
				log.Printf("[PluginManager] Warning downloading rosenpass release binary: %v (%s)", err, string(out))
			}
		}
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
	if err := SyncPluginShellPaths(pm, pluginID); err != nil {
		log.Printf("[PluginManager] Warning: failed to sync shell PATH for plugin %s: %v", pluginID, err)
	}

	return PluginActionResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully installed plugin %s (%s)", target.Name, pluginID),
		Output:  output.String(),
	}
}

func (pm *PluginManager) UninstallPlugin(pluginID string) PluginActionResponse {
	if strings.HasPrefix(pluginID, "core-") {
		pm.mu.Lock()
		pm.disabledMap[pluginID] = true
		delete(pm.installedMap, pluginID)
		pm.saveState()
		pm.mu.Unlock()
		return PluginActionResponse{
			Success: true,
			Message: fmt.Sprintf("Disabled core role plugin %s.", pluginID),
		}
	}

	pm.actionMu.Lock()
	defer pm.actionMu.Unlock()

	defs := GetExtensionPluginDefinitions()
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
	if len(target.Binaries) > 0 {
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
	if pluginID == "cli-workstation" {
		pm.mu.Lock()
		pm.disabledMap[pluginID] = true
		pm.mu.Unlock()
		_ = os.MkdirAll("/etc/axonwall", 0755)
		_ = os.WriteFile("/etc/axonwall/workstation.disabled", []byte("disabled=true\n"), 0644)
		if pm.osFamily == "alpine" {
			// Restore /usr/bin/zsh -> /bin/ash fallback so OpenLDAP SSO users with loginShell=/usr/bin/zsh can always SSH in!
			_ = os.Remove("/usr/bin/zsh")
			if _, err := os.Stat("/bin/ash"); err == nil {
				_ = os.Symlink("/bin/ash", "/usr/bin/zsh")
			}
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
	if pluginID == "cli-workstation" {
		_ = os.Remove("/etc/axonwall/workstation.disabled")
		pm.mu.Lock()
		delete(pm.disabledMap, pluginID)
		pm.saveState()
		pm.mu.Unlock()
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
		if err := ProvisionRosenpassEnvironment(DefaultRosenpassDir); err != nil {
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
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

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
	if existing, err := os.ReadFile("/etc/zsh/axonwall.zsh"); err != nil || !strings.Contains(string(existing), "oh-my-zsh") {
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
