package engine

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
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
	SystemdUnits     []string `json:"systemdUnits"`
	Privileges       []string `json:"privileges"`
	DebianPackages   []string `json:"debianPackages"`
	AlpinePackages   []string `json:"alpinePackages"`
	RequiredBinaries []string `json:"requiredBinaries"`
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
	Installed        bool     `json:"installed"`
	Bundled          bool     `json:"bundled"`
	RequiredBinaries []string `json:"requiredBinaries"`
	MissingBinaries  []string `json:"missingBinaries"`
	Packages         []string `json:"packages"`
	InstalledAt      string   `json:"installedAt,omitempty"`
	SystemdUnits     []string `json:"systemdUnits"`
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
	baseDataDir  string
	stateFile    string
	disabledFile string
	osFamily     string
	installedMap map[string]string // pluginID -> installedAt
	disabledMap  map[string]bool   // pluginID -> explicitly disabled
}

func DetectOSFamily() string {
	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		return "alpine"
	}
	return "debian"
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
			DebianPackages: []string{
				"zsh",
				"vim",
				"neovim",
				"tmux",
				"zsh-autosuggestions",
				"zsh-syntax-highlighting",
				"fzf",
				"zoxide",
				"bat",
				"ripgrep",
				"fd-find",
				"git",
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
			},
			RequiredBinaries: []string{"zsh", "vim", "starship", "tmux"},
		},
		{
			ID:               "cli-diagnostics-nastymap",
			Name:             "NastyMap & Live CLI Telemetry Suite",
			Version:          "1.0.0",
			Category:         "extension",
			Description:      "Autonomous host discovery and vulnerability auditing with NastyMap & Nmap, plus real-time system/network monitors (btop, htop, iftop, iotop, slurm, sysstat, dnsutils).",
			Author:           "Axonwall Core / NastyMap",
			DebianPackages:   []string{"nmap", "dnsutils", "net-tools", "btop", "htop", "iftop", "iotop", "slurm", "sysstat"},
			AlpinePackages:   []string{"nmap", "bind-tools", "net-tools", "btop", "htop", "iftop", "sysstat"},
			RequiredBinaries: []string{"nmap", "btop", "htop", "iftop"},
		},
		{
			ID:               "haproxy",
			Name:             "HAProxy Load Balancer & Reverse Proxy",
			Version:          "2.8.3",
			Category:         "extension",
			Description:      "High performance TCP/HTTP load balancer, reverse proxy, and SSL/TLS termination with ACME integration.",
			Author:           "HAProxy Technologies / Axonwall Core",
			SystemdUnits:     []string{"haproxy.service"},
			DebianPackages:   []string{"haproxy"},
			AlpinePackages:   []string{"haproxy"},
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
			DebianPackages:   []string{"freeradius", "freeradius-ldap"},
			AlpinePackages:   []string{"freeradius"},
			RequiredBinaries: []string{"freeradius"},
		},
		{
			ID:               "snmp",
			Name:             "Net-SNMP Daemon & MIBs",
			Version:          "5.9.3",
			Category:         "extension",
			Description:      "SNMPv2c and SNMPv3 monitoring agent with standard MIBs for network management systems.",
			Author:           "Net-SNMP Team / Axonwall Core",
			SystemdUnits:     []string{"snmpd.service"},
			DebianPackages:   []string{"snmpd", "snmp"},
			AlpinePackages:   []string{"net-snmp"},
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
			DebianPackages:   []string{"nut-server", "nut-client"},
			AlpinePackages:   []string{"nut"},
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
			DebianPackages:   []string{},
			AlpinePackages:   []string{},
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
			DebianPackages:   []string{"tailscale"},
			AlpinePackages:   []string{"tailscale"},
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
			DebianPackages:   []string{"ntopng"},
			AlpinePackages:   []string{"ntopng"},
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
			DebianPackages:   []string{"rosenpass", "wireguard-tools"},
			AlpinePackages:   []string{"rosenpass", "wireguard-tools"},
			RequiredBinaries: []string{"rosenpass", "wg"},
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
	return pm.installedMap[pluginID] != ""
}

func (pm *PluginManager) ListPlugins() []PluginStatus {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	defs := GetExtensionPluginDefinitions()
	results := make([]PluginStatus, 0, len(defs))

	for _, d := range defs {
		var missing []string
		for _, bin := range d.RequiredBinaries {
			if _, err := exec.LookPath(bin); err != nil {
				missing = append(missing, bin)
			}
		}

		pkgs := d.DebianPackages
		if pm.osFamily == "alpine" {
			pkgs = d.AlpinePackages
		}

		installed := len(missing) == 0
		installedAt := pm.installedMap[d.ID]
		bundled := installed && installedAt == ""

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
			Installed:        installed,
			Bundled:          bundled,
			RequiredBinaries: d.RequiredBinaries,
			MissingBinaries:  missing,
			Packages:         pkgs,
			InstalledAt:      installedAt,
			SystemdUnits:     d.SystemdUnits,
		})
	}
	return results
}

func (pm *PluginManager) EnablePlugin(pluginID string) PluginActionResponse {
	pm.mu.Lock()
	delete(pm.disabledMap, pluginID)
	pm.saveState()
	pm.mu.Unlock()

	if pluginID == "cli-workstation" {
		_ = os.Remove("/etc/axonwall/workstation.disabled")
		if err := pm.provisionWorkstationConfigs(); err != nil {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to enable workstation shell environment: %v", err),
			}
		}
		return PluginActionResponse{
			Success: true,
			Message: "Enabled Modern Operator Shell & Editor (ZSH + Oh My Zsh + Starship + VIM + Full Stack Completions).",
		}
	}

	return pm.ReconfigurePlugin(pluginID)
}

func (pm *PluginManager) DisablePlugin(pluginID string) PluginActionResponse {
	pm.mu.Lock()
	pm.disabledMap[pluginID] = true
	pm.saveState()
	pm.mu.Unlock()

	if pluginID == "cli-workstation" {
		_ = os.MkdirAll("/etc/axonwall", 0755)
		_ = os.WriteFile("/etc/axonwall/workstation.disabled", []byte("disabled=true\n"), 0644)
		return PluginActionResponse{
			Success: true,
			Message: "Disabled Modern Operator Shell & Editor (attack-surface reduction mode active).",
		}
	}

	return PluginActionResponse{
		Success: true,
		Message: fmt.Sprintf("Disabled plugin %s.", pluginID),
	}
}

func (pm *PluginManager) InstallPlugin(pluginID string) PluginActionResponse {
	pm.mu.Lock()
	defer pm.mu.Unlock()

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

	pkgs := target.DebianPackages
	if pm.osFamily == "alpine" {
		pkgs = target.AlpinePackages
	}

	var output strings.Builder
	if len(pkgs) > 0 {
		var cmd *exec.Cmd
		if pm.osFamily == "alpine" {
			args := append([]string{"add", "--no-cache"}, pkgs...)
			cmd = exec.Command("apk", args...)
		} else {
			args := append([]string{"install", "-y", "--no-install-recommends"}, pkgs...)
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

	// Post-install configuration hooks
	if pluginID == "cli-workstation" {
		_ = os.Remove("/etc/axonwall/workstation.disabled")
		delete(pm.disabledMap, pluginID)
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
		if err := ProvisionRosenpassEnvironment(DefaultRosenpassDir); err != nil {
			log.Printf("[PluginManager] Warning provisioning Rosenpass PQ keys: %v", err)
		}
	}

	pm.installedMap[pluginID] = time.Now().UTC().Format(time.RFC3339)
	pm.saveState()

	return PluginActionResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully installed plugin %s (%s)", target.Name, pluginID),
		Output:  output.String(),
	}
}

func (pm *PluginManager) UninstallPlugin(pluginID string) PluginActionResponse {
	pm.mu.Lock()
	defer pm.mu.Unlock()

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

	pkgs := target.DebianPackages
	if pm.osFamily == "alpine" {
		pkgs = target.AlpinePackages
	}

	var output strings.Builder
	if len(pkgs) > 0 {
		var cmd *exec.Cmd
		if pm.osFamily == "alpine" {
			args := append([]string{"del"}, pkgs...)
			cmd = exec.Command("apk", args...)
		} else {
			args := append([]string{"remove", "-y"}, pkgs...)
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

	// Post-removal cleanup hooks
	if pluginID == "cli-workstation" {
		pm.disabledMap[pluginID] = true
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

	delete(pm.installedMap, pluginID)
	pm.saveState()

	return PluginActionResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully uninstalled plugin %s (%s)", target.Name, pluginID),
		Output:  output.String(),
	}
}

func (pm *PluginManager) ReconfigurePlugin(pluginID string) PluginActionResponse {
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
		return PluginActionResponse{
			Success: true,
			Message: "Rosenpass Post-Quantum McEliece 460896 keypair and systemd unit verified.",
		}
	}
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
fi
if [[ -f /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ]]; then
  source /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
fi

if command -v starship >/dev/null 2>&1; then
  eval "$(starship init zsh)"
fi

alias tui='axonwall-tui'
alias webtui='axonwall-tui'
alias nastymap='axonwall-tui --tab nastymap'
alias ctl='axonwallctl'
alias confirm='axonwallctl confirm'
alias rollback='axonwallctl rollback'
alias vi='vim'
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
