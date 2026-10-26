# ==============================================================================
# Axonwall Appliance Modern ZSH Configuration (/etc/zsh/axonwall.zsh)
# Powered by Oh My Zsh (https://ohmyz.sh) + Starship + Full Stack Completions
# Sourced by /etc/zsh/zshrc and ~/.zshrc for all interactive ZSH shells
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

# Auto-detect K3s kubeconfig if present so kubectl / helm / k9s work immediately
if [[ -z "${KUBECONFIG:-}" ]] && [[ -r /etc/rancher/k3s/k3s.yaml ]]; then
  export KUBECONFIG="/etc/rancher/k3s/k3s.yaml"
fi

# Respect explicit workstation plugin disablement (attack-surface reduction mode)
if [[ -f /etc/axonwall/workstation.disabled ]]; then
  PROMPT='%n@%m:%~%# '
  return 0
fi

export STARSHIP_CONFIG="/etc/axonwall/starship.toml"
export STARSHIP_LOG="error"

# ==============================================================================
# 1. Oh My Zsh (https://ohmyz.sh) Initialization & Plugins
# ==============================================================================
export ZSH="${ZSH:-/usr/share/oh-my-zsh}"
export ZSH_CUSTOM="${ZSH_CUSTOM:-$ZSH/custom}"
export ZSH_CACHE_DIR="${HOME}/.cache/oh-my-zsh"
DISABLE_AUTO_UPDATE="true"
DISABLE_UPDATE_PROMPT="true"

# Ensure ~/.oh-my-zsh symlink exists for per-user tool compatibility
if [[ -d /usr/share/oh-my-zsh ]] && [[ -n "${HOME:-}" ]] && [[ -d "${HOME}" ]] && [[ ! -e "${HOME}/.oh-my-zsh" ]]; then
  ln -s /usr/share/oh-my-zsh "${HOME}/.oh-my-zsh" 2>/dev/null || true
fi

# Enabled Oh My Zsh plugins across the Axonwall stack
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
else
  # Fallback completion initialization if Oh My Zsh directory is missing
  autoload -Uz compinit
  compinit -u -d "${HOME}/.zcompdump" 2>/dev/null || compinit -u 2>/dev/null || true
  zstyle ':completion:*' menu select
  zstyle ':completion:*' matcher-list 'm:{a-zA-Z}={A-Za-z}' 'r:|[._-]=* r:|=*'
fi

setopt INTERACTIVE_COMMENTS
setopt PROMPT_SUBST

# ==============================================================================
# 2. Intelligent Network & Appliance Helpers
# ==============================================================================
_axonwall_default_if() {
  local def_if
  def_if="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
  if [[ -z "$def_if" ]]; then
    def_if="$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -vx 'lo' | head -n 1)"
  fi
  echo "${def_if:-eth0}"
}

_axonwall_lan_cidr() {
  local lan_if wan_if cidr
  lan_if="$(grep '^LAN_INTERFACE=' /etc/axonwall/interfaces.conf 2>/dev/null | cut -d= -f2)"
  wan_if="$(grep '^WAN_INTERFACE=' /etc/axonwall/interfaces.conf 2>/dev/null | cut -d= -f2)"
  case "${lan_if:l}" in
    none|-|unassigned|\<none\>) lan_if="" ;;
  esac
  if [[ -n "$lan_if" ]]; then
    cidr="$(ip -o -4 addr show dev "$lan_if" 2>/dev/null | awk '{print $4; exit}')"
  fi
  if [[ -z "$cidr" ]]; then
    if [[ -n "$wan_if" ]]; then
      cidr="$(ip -o -4 addr show scope global 2>/dev/null | awk -v w="$wan_if" '$2 != w {print $4; exit}')"
    else
      cidr="$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4; exit}')"
    fi
  fi
  echo "${cidr:-192.168.1.0/24}"
}

# ==============================================================================
# 3. Axonwall Operator Aliases & Modern CLI Integrations
# ==============================================================================
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
alias diff='diff --color=auto'
alias grep='grep --color=auto'
alias ip='ip -color=auto'
alias ports='ss -tulnp'
alias routes='ip -c route show'
alias ifaces='ip -brief -c addr'
alias rules='nft list ruleset'
alias fw='nft list ruleset'
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

  # Fuzzy-search Kubernetes pods across all namespaces
  kpod() {
    local pod_line ns pod
    pod_line="$(kubectl get pods --all-namespaces --no-headers 2>/dev/null | fzf --prompt='K8s Pod > ' --height=40% --layout=reverse --border)"
    if [[ -n "$pod_line" ]]; then
      ns="$(echo "$pod_line" | awk '{print $1}')"
      pod="$(echo "$pod_line" | awk '{print $2}')"
      kubectl describe pod "$pod" -n "$ns"
    fi
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

# ==============================================================================
# 4. Initialize Starship Cross-Shell Prompt (https://starship.rs/guide/)
# ==============================================================================
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

# ==============================================================================
# 5. Interactive Login Banner
# ==============================================================================
if [[ -o interactive ]] && [[ -z "${AXONWALL_BANNER_SHOWN:-}" ]]; then
  export AXONWALL_BANNER_SHOWN=1
  echo "\033[1;32m================================================================================\033[0m"
  echo "\033[1;37m  Axonwall Appliance ZSH + Oh My Zsh + Starship\033[0m — NIC: \033[1;36m$(_axonwall_default_if)\033[0m | Subnet: \033[1;36m$(_axonwall_lan_cidr)\033[0m"
  echo "  • \033[1;33maxonwall-tui\033[0m   : Full Interactive Ink TUI (10-Tab Console + NastyMap + Ops)"
  echo "  • \033[1;33maxonwallctl\033[0m    : YAML CLI (\033[36mstatus\033[0m | \033[36mdiff\033[0m | \033[36mapply\033[0m | \033[36mconfirm\033[0m | \033[36mplugin\033[0m | \033[36mmcp\033[0m)"
  echo "  • \033[1;33mOh My Zsh\033[0m      : \033[36mkubectl\033[0m (\033[36mk\033[0m/\033[36mkgp\033[0m/\033[36mklf\033[0m), \033[36mhelm\033[0m, \033[36mzfs\033[0m/\033[36mzpool\033[0m, \033[36mnft\033[0m, \033[36mwg\033[0m, \033[36mvirsh\033[0m, \033[36msystemd\033[0m, \033[36mgit\033[0m"
  echo "  • \033[1;33mfconf / flog\033[0m   : Fuzzy-edit \033[36m/etc/axonwall/*.yaml\033[0m or search logs (\033[36mfzf\033[0m)"
  if [[ -f /run/axonwall/commit-confirm.pending ]]; then
    echo "  \033[1;33;41m ⚠ COMMIT-CONFIRM TIMER ACTIVE: Run 'confirm' (or 'axonwallctl confirm') now! \033[0m"
  fi
  echo "\033[1;32m================================================================================\033[0m"
fi
