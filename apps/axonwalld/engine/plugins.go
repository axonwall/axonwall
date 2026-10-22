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
	Action   string `json:"action"` // "install", "uninstall", "reconfigure"
}

type PluginActionResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Output  string `json:"output,omitempty"`
}

type PluginManager struct {
	mu           sync.RWMutex
	stateFile    string
	osFamily     string
	installedMap map[string]string // pluginID -> installedAt
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
			ID:               "cli-workstation",
			Name:             "Modern Operator Shell & Editor (ZSH, Starship & VIM)",
			Version:          "1.0.0",
			Category:         "extension",
			Description:      "Pre-configured productivity environment with ZSH, Starship cyber-emerald prompt, live Commit-Confirm rollback indicator, VIM syntax defaults, and Tmux terminal multiplexer.",
			Author:           "Axonwall Core",
			DebianPackages:   []string{"zsh", "vim", "tmux"},
			AlpinePackages:   []string{"zsh", "vim", "starship", "tmux"},
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
	}
}

func NewPluginManager(baseDataDir string) *PluginManager {
	statePath := filepath.Join(baseDataDir, "plugins.json")
	pm := &PluginManager{
		stateFile:    statePath,
		osFamily:     DetectOSFamily(),
		installedMap: make(map[string]string),
	}
	pm.loadState()
	return pm
}

func (pm *PluginManager) loadState() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	data, err := os.ReadFile(pm.stateFile)
	if err != nil {
		return
	}
	var saved map[string]string
	if err := json.Unmarshal(data, &saved); err == nil {
		pm.installedMap = saved
	}
}

func (pm *PluginManager) saveState() {
	_ = os.MkdirAll(filepath.Dir(pm.stateFile), 0755)
	if data, err := json.MarshalIndent(pm.installedMap, "", "  "); err == nil {
		_ = os.WriteFile(pm.stateFile, data, 0644)
	}
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

		results = append(results, PluginStatus{
			ID:               d.ID,
			Name:             d.Name,
			Version:          d.Version,
			Category:         d.Category,
			Description:      d.Description,
			Author:           d.Author,
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
	if pluginID == "cli-workstation" && pm.osFamily == "alpine" {
		// Restore /usr/bin/zsh -> /bin/ash fallback so OpenLDAP SSO users with loginShell=/usr/bin/zsh can always SSH in!
		_ = os.Remove("/usr/bin/zsh")
		if _, err := os.Stat("/bin/ash"); err == nil {
			_ = os.Symlink("/bin/ash", "/usr/bin/zsh")
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
		if err := pm.provisionWorkstationConfigs(); err != nil {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to reconfigure workstation: %v", err),
			}
		}
		return PluginActionResponse{
			Success: true,
			Message: "Workstation terminal, ZSH, Starship, and VIM configs re-provisioned successfully.",
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
$character"""

right_format = """$cmd_duration"""

[custom.axonwall_commit]
command = "cat /run/axonwall/commit-confirm.pending 2>/dev/null"
when = "test -s /run/axonwall/commit-confirm.pending"
style = "bold #f59e0b"
format = "[$output]($style) "

[username]
show_always = true
style_user = "bold #38bdf8"
style_root = "bold #ef4444"
format = "[$user]($style)"

[hostname]
ssh_only = false
style = "bold #94a3b8"
format = "[$hostname]($style)"

[directory]
truncation_length = 4
truncate_to_repo = false
style = "bold #06b6d4"
format = "[$path]($style) "

[character]
success_symbol = "[❯](bold #10b981)"
error_symbol = "[❯](bold #ef4444)"
`
	_ = os.WriteFile("/etc/axonwall/starship.toml", []byte(starshipConf), 0644)

	// 2. /etc/zsh/axonwall.zsh
	zshConf := `# ==============================================================================
# Axonwall Appliance Modern ZSH Configuration (/etc/zsh/axonwall.zsh)
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
export STARSHIP_CONFIG="/etc/axonwall/starship.toml"
export STARSHIP_LOG="error"

HISTFILE="${HOME}/.zsh_history"
HISTSIZE=50000
SAVEHIST=50000
setopt APPEND_HISTORY
setopt SHARE_HISTORY
setopt HIST_IGNORE_DUPS
setopt HIST_IGNORE_SPACE

if command -v starship >/dev/null 2>&1; then
  eval "$(starship init zsh)"
fi

alias ll='ls -lah --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias diff='diff --color=auto'
alias grep='grep --color=auto'
alias ports='netstat -tulnp'
alias fw='nft list ruleset'
alias routes='ip route show'
alias ifaces='ip -brief addr'
`
	_ = os.WriteFile("/etc/zsh/axonwall.zsh", []byte(zshConf), 0644)

	// 3. /etc/zsh/zshenv
	_ = os.WriteFile("/etc/zsh/zshenv", []byte("export STARSHIP_CONFIG=/etc/axonwall/starship.toml\n"), 0644)

	// 4. /etc/skel/.zshrc and /root/.zshrc
	userZshrc := `# Axonwall ZSH User Profile
[ -f /etc/zsh/axonwall.zsh ] && source /etc/zsh/axonwall.zsh
`
	_ = os.WriteFile("/etc/skel/.zshrc", []byte(userZshrc), 0644)
	if _, err := os.Stat("/root/.zshrc"); os.IsNotExist(err) {
		_ = os.WriteFile("/root/.zshrc", []byte(userZshrc), 0640)
	}

	// 5. /etc/vim/vimrc.local
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

	// 6. /etc/tmux.conf
	tmuxConf := `# Axonwall Appliance Modern tmux Configuration (/etc/tmux.conf)
set -g default-terminal "screen-256color"
set -g history-limit 50000
set -g mouse on
set -g status-interval 5
set -g status-style "bg=#0f172a,fg=#e2e8f0"
set -g status-left "#[fg=#0f172a,bg=#10b981,bold] AXONWALL #[default] "
`
	_ = os.WriteFile("/etc/tmux.conf", []byte(tmuxConf), 0644)

	return nil
}
