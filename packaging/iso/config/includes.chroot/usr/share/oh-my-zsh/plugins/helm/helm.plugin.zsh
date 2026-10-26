# ==============================================================================
# Oh My Zsh — helm plugin
# Kubernetes Helm package manager completion & operator aliases
# ==============================================================================

if (( $+commands[helm] )); then
  if [[ ! -f "${ZSH_CACHE_DIR}/completions/_helm" ]]; then
    helm completion zsh 2>/dev/null >| "${ZSH_CACHE_DIR}/completions/_helm" &|
  fi
  [[ -s "${ZSH_CACHE_DIR}/completions/_helm" ]] && source "${ZSH_CACHE_DIR}/completions/_helm" 2>/dev/null
fi

_axonwall_helm_fallback() {
  local -a subcmds
  subcmds=(
    'install:Install a chart'
    'upgrade:Upgrade a release'
    'uninstall:Uninstall a release'
    'list:List releases'
    'status:Display the status of the named release'
    'history:Fetch release history'
    'rollback:Roll back a release to a previous revision'
    'repo:Add, list, remove, update, and index chart repositories'
    'search:Search for a keyword in charts'
    'show:Show information of a chart'
    'template:Locally render templates'
    'lint:Examine a chart for possible issues'
    'package:Package a chart directory into a chart archive'
    'pull:Download a chart from a repository'
  )
  _describe 'helm command' subcmds
}

if ! (( $+functions[__start_helm] )); then
  compdef _axonwall_helm_fallback helm h 2>/dev/null || true
else
  compdef __start_helm h 2>/dev/null || true
fi

alias h='helm'
alias hin='helm install'
alias hup='helm upgrade --install'
alias hun='helm uninstall'
alias hls='helm list'
alias hlsa='helm list --all-namespaces'
alias hst='helm status'
alias hhi='helm history'
alias hrb='helm rollback'
alias hrepo='helm repo'
alias hru='helm repo update'
alias hrl='helm repo list'
alias hse='helm search repo'
