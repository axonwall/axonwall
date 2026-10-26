# ==============================================================================
# Oh My Zsh (https://ohmyz.sh) — Axonwall System-Wide Distribution Loader
# Installed globally at /usr/share/oh-my-zsh for all interactive ZSH shells
# ==============================================================================

export ZSH="${ZSH:-/usr/share/oh-my-zsh}"
export ZSH_CUSTOM="${ZSH_CUSTOM:-$ZSH/custom}"
export ZSH_CACHE_DIR="${ZSH_CACHE_DIR:-${HOME}/.cache/oh-my-zsh}"

mkdir -p "${ZSH_CACHE_DIR}/completions" 2>/dev/null || true

# Add Oh My Zsh functions and completions to fpath
fpath=("$ZSH/functions" "$ZSH/completions" "${ZSH_CACHE_DIR}/completions" $fpath)

# Register enabled plugin directories in fpath before compinit
for _omz_plugin in ${plugins[@]}; do
  if [[ -d "$ZSH_CUSTOM/plugins/$_omz_plugin" ]]; then
    fpath=("$ZSH_CUSTOM/plugins/$_omz_plugin" $fpath)
  elif [[ -d "$ZSH/plugins/$_omz_plugin" ]]; then
    fpath=("$ZSH/plugins/$_omz_plugin" $fpath)
  fi
done
unset _omz_plugin

# Initialize ZSH completion system with per-user dump file
autoload -Uz compinit
compinit -u -d "${ZSH_CACHE_DIR}/.zcompdump-${ZSH_VERSION:-zsh}" 2>/dev/null || compinit -u 2>/dev/null || true

# Source Oh My Zsh core libraries
for _omz_lib in "$ZSH"/lib/*.zsh(N); do
  source "$_omz_lib"
done
unset _omz_lib

# Source all enabled Oh My Zsh plugins
for _omz_plugin in ${plugins[@]}; do
  if [[ -f "$ZSH_CUSTOM/plugins/$_omz_plugin/$_omz_plugin.plugin.zsh" ]]; then
    source "$ZSH_CUSTOM/plugins/$_omz_plugin/$_omz_plugin.plugin.zsh"
  elif [[ -f "$ZSH/plugins/$_omz_plugin/$_omz_plugin.plugin.zsh" ]]; then
    source "$ZSH/plugins/$_omz_plugin/$_omz_plugin.plugin.zsh"
  fi
done
unset _omz_plugin
