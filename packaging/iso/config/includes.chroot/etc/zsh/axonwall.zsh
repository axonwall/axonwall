# ==============================================================================
# Axonwall Appliance Modern ZSH Configuration (/etc/zsh/axonwall.zsh)
# Sourced by /etc/zsh/zshrc and ~/.zshrc for interactive shell sessions
# ==============================================================================

# Guard against double-sourcing when both /etc/zsh/zshrc and ~/.zshrc source this file
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

# History configuration
HISTFILE="${HOME}/.zsh_history"
HISTSIZE=25000
SAVEHIST=25000
setopt APPEND_HISTORY
setopt INC_APPEND_HISTORY
setopt SHARE_HISTORY
setopt HIST_IGNORE_DUPS
setopt HIST_IGNORE_ALL_DUPS
setopt HIST_IGNORE_SPACE
setopt HIST_REDUCE_BLANKS
setopt AUTO_CD
setopt INTERACTIVE_COMMENTS
setopt PROMPT_SUBST

# Completion system
autoload -Uz compinit
compinit -u -d "${HOME}/.zcompdump" 2>/dev/null || compinit -u 2>/dev/null || true
zstyle ':completion:*' menu select
zstyle ':completion:*' matcher-list 'm:{a-zA-Z}={A-Za-z}' 'r:|[._-]=* r:|=*'
zstyle ':completion:*' list-colors "${(s.:.)LS_COLORS}"

# Keybindings (Emacs/standard navigation + Home/End/Delete/Ctrl-Left/Ctrl-Right)
bindkey -e
bindkey '^[[3~' delete-char
bindkey '^[[H' beginning-of-line
bindkey '^[[F' end-of-line
bindkey '^[[1~' beginning-of-line
bindkey '^[[4~' end-of-line
bindkey '^[[1;5C' forward-word
bindkey '^[[1;5D' backward-word

# Helper to detect primary default interface and subnet for intelligent CLI defaults
_axonwall_default_if() {
  local def_if
  def_if="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
  if [[ -z "$def_if" ]]; then
    def_if="$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -vx 'lo' | head -n 1)"
  fi
  echo "${def_if:-eth0}"
}

_axonwall_lan_cidr() {
  local lan_if cidr
  lan_if="$(grep '^LAN_INTERFACE=' /etc/axonwall/interfaces.conf 2>/dev/null | cut -d= -f2)"
  if [[ -n "$lan_if" ]]; then
    cidr="$(ip -o -4 addr show dev "$lan_if" 2>/dev/null | awk '{print $4; exit}')"
  fi
  if [[ -z "$cidr" ]]; then
    cidr="$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4; exit}')"
  fi
  echo "${cidr:-192.168.1.0/24}"
}

# Custom ZSH Tab Completion for axonwallctl & axonwall-tui
_axonwallctl_completion() {
  local -a subcmds
  subcmds=(
    'status:Show live appliance health, interfaces, and commit-confirm status'
    'validate:Validate syntax and schema of /etc/axonwall/*.yaml'
    'diff:Show pending changes between /etc/axonwall/*.yaml and live state'
    'apply:Compile and apply /etc/axonwall/*.yaml with Commit-Confirm safety'
    'confirm:Confirm active candidate configuration before rollback timer expires'
    'rollback:Immediately revert to Last-Known-Good (LKG) configuration'
    'export:Export running state to declarative /etc/axonwall/*.yaml files'
    'import:Import configuration bundle or legacy config'
    'cloudinit:Reconcile cloud-init (#cloud-config) metadata'
  )
  _describe 'axonwallctl command' subcmds
}
compdef _axonwallctl_completion axonwallctl ctl 2>/dev/null || true

_axonwall_tui_completion() {
  local -a tabs
  tabs=(
    'dashboard:System Telemetry & Gateways Overview'
    'interfaces:Interfaces, VLANs & Bridges'
    'routing:Gateways, Static Routes & FRR BGP/OSPF'
    'firewall:Zone Policies & Lockdown Control'
    'nat:SNAT Masquerade & Port Forwards (DNAT)'
    'services:DHCPv4 (Kea), DNS (Unbound) & HA Sync'
    'vpn:WireGuard & Headscale Mesh'
    'nastymap:NastyMap Interactive Nmap Scanner & Topology'
    'cli-tools:CLI Ops Toolkit (btop, slurm, iftop, iotop, sysstat, dig)'
    'logs:Live System & Daemon Journal Logs'
  )
  _arguments \
    '--tab[Open directly to specific TUI workspace tab]:tab:->tabs' \
    '--help[Show TUI usage help]'
  if [[ "$state" == "tabs" ]]; then
    _describe 'TUI tab' tabs
  fi
}
compdef _axonwall_tui_completion axonwall-tui tui 2>/dev/null || true

# Intelligent Axonwall & CLI Utility Aliases
alias tui='axonwall-tui'
alias webtui='axonwall-tui'
alias nastymap='axonwall-tui --tab nastymap'
alias ctl='axonwallctl'
alias confirm='axonwallctl confirm'
alias rollback='axonwallctl rollback'
alias console='/usr/sbin/axonwall-console'
alias vi='vim'
alias ll='ls -lah --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias grep='grep --color=auto'
alias ip='ip -color=auto'
alias ports='ss -tulnp'
alias routes='ip -c route show'
alias rules='nft list ruleset'
alias arptable='ip -c neigh show'
alias bw='slurm -z -i $(_axonwall_default_if)'
alias ifbw='iftop -nNP -i $(_axonwall_default_if)'
alias iomon='iostat -xz 1'
alias cpumon='mpstat -P ALL 1'
alias diskio='iotop -oPa'
alias quickscan='nmap -T4 -F $(_axonwall_lan_cidr)'
alias servicescan='nmap -sV -T4 $(_axonwall_lan_cidr)'

# Modern CLI tool integrations (bat/batcat, fd/fdfind, fzf, zoxide)
if command -v batcat >/dev/null 2>&1 && ! command -v bat >/dev/null 2>&1; then
  alias bat='batcat --paging=never'
  alias caty='batcat --paging=never -l yaml'
elif command -v bat >/dev/null 2>&1; then
  alias caty='bat --paging=never -l yaml'
fi

if command -v fdfind >/dev/null 2>&1 && ! command -v fd >/dev/null 2>&1; then
  alias fd='fdfind'
fi

# Interactive fzf power-helpers for operators
if command -v fzf >/dev/null 2>&1; then
  [[ -f /usr/share/doc/fzf/examples/key-bindings.zsh ]] && source /usr/share/doc/fzf/examples/key-bindings.zsh
  [[ -f /usr/share/doc/fzf/examples/completion.zsh ]] && source /usr/share/doc/fzf/examples/completion.zsh

  # Fuzzy-pick and edit an /etc/axonwall/*.yaml config file
  fconf() {
    local file
    file="$(find /etc/axonwall -maxdepth 2 -name '*.yaml' 2>/dev/null | sort | fzf --prompt='Edit Axonwall YAML > ' --height=40% --layout=reverse --border)"
    [[ -n "$file" ]] && vim "$file"
  }

  # Fuzzy-search live systemd journal logs
  flog() {
    journalctl -u axonwalld -u axonwall-controller -u axonwall-ui -u slapd -u sssd -n 500 --no-pager 2>/dev/null | fzf --tac --no-sort --prompt='Logs > ' --layout=reverse
  }

  # Fuzzy-search active sockets & listening ports
  fconn() {
    ss -tulnp 2>/dev/null | fzf --header-lines=1 --prompt='Sockets > ' --layout=reverse
  }
fi

if command -v zoxide >/dev/null 2>&1; then
  eval "$(zoxide init zsh 2>/dev/null)" || true
fi

# Load ZSH Autosuggestions & Syntax Highlighting plugins if installed
if [[ -f /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh ]]; then
  ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=242'
  source /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh
fi
if [[ -f /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ]]; then
  source /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
fi

# Initialize Starship Cross-Shell Prompt (https://starship.rs/guide/)
if command -v starship >/dev/null 2>&1; then
  eval "$(starship init zsh)"
else
  # Fallback prompt if starship binary is not present
  _axonwall_fallback_commit() {
    if [[ -f /run/axonwall/commit-confirm.pending ]]; then
      echo "%F{yellow}%B[⚠ COMMIT-CONFIRM PENDING — run 'confirm']%b%f "
    fi
  }
  PROMPT='%F{emerald}%B[axonwall]%b%f $(_axonwall_fallback_commit)%(!.%F{red}%n%f.%F{cyan}%n%f)@%F{white}%m%f:%F{blue}%~%f %(!.#.❯) '
  RPROMPT='%F{242}[$(_axonwall_default_if)]%f'
fi

# Display concise interactive welcome banner on login
if [[ -o interactive ]] && [[ -z "${AXONWALL_BANNER_SHOWN:-}" ]]; then
  export AXONWALL_BANNER_SHOWN=1
  echo "\033[1;32m================================================================================\033[0m"
  echo "\033[1;37m  Axonwall Appliance ZSH + Starship\033[0m — NIC: \033[1;36m$(_axonwall_default_if)\033[0m | Subnet: \033[1;36m$(_axonwall_lan_cidr)\033[0m"
  echo "  • \033[1;33maxonwall-tui\033[0m   : Full Interactive Ink TUI (Web Console + NastyMap + Ops)"
  echo "  • \033[1;33mnastymap\033[0m       : NastyMap Interactive Nmap Scanner & Topology TUI"
  echo "  • \033[1;33maxonwallctl\033[0m    : YAML CLI (\033[36mstatus\033[0m | \033[36mdiff\033[0m | \033[36mapply\033[0m | \033[36mconfirm\033[0m | \033[36mrollback\033[0m)"
  echo "  • \033[1;33mfconf / flog\033[0m   : Fuzzy-edit \033[36m/etc/axonwall/*.yaml\033[0m or search logs (\033[36mfzf\033[0m)"
  echo "  • \033[1;33mbtop / htop\033[0m    : Live telemetry | \033[1;33mbw\033[0m (\033[36mslurm\033[0m) / \033[1;33mifbw\033[0m (\033[36miftop\033[0m) : Live NIC"
  if [[ -f /run/axonwall/commit-confirm.pending ]]; then
    echo "  \033[1;33;41m ⚠ COMMIT-CONFIRM TIMER ACTIVE: Run 'confirm' (or 'axonwallctl confirm') now! \033[0m"
  fi
  echo "\033[1;32m================================================================================\033[0m"
fi
