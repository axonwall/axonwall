# Oh My Zsh — history.zsh
[[ -z "$HISTFILE" ]] && HISTFILE="${HOME}/.zsh_history"
HISTSIZE=50000
SAVEHIST=50000

setopt extended_history
setopt hist_expire_dups_first
setopt hist_ignore_dups
setopt hist_ignore_all_dups
setopt hist_ignore_space
setopt hist_verify
setopt share_history
setopt append_history
setopt inc_append_history

alias history='omz_history -i'
function omz_history {
  builtin fc -l "$@"
}
