# ==============================================================================
# Oh My Zsh — docker & containerd/CRI (crictl / ctr) plugin
# Container runtime completions and shortcuts for K3s and Docker
# ==============================================================================

if (( $+commands[crictl] )); then
  if [[ ! -f "${ZSH_CACHE_DIR}/completions/_crictl" ]]; then
    crictl completion zsh 2>/dev/null >| "${ZSH_CACHE_DIR}/completions/_crictl" &|
  fi
  [[ -s "${ZSH_CACHE_DIR}/completions/_crictl" ]] && source "${ZSH_CACHE_DIR}/completions/_crictl" 2>/dev/null
fi

alias kpods='crictl pods'
alias kps='crictl ps'
alias kpsa='crictl ps -a'
alias kimg='crictl images'
alias kstats='crictl stats'
alias klogs='crictl logs'
alias dps='docker ps'
alias dpa='docker ps -a'
alias di='docker images'
alias dlogs='docker logs -f'
alias dexec='docker exec -it'
