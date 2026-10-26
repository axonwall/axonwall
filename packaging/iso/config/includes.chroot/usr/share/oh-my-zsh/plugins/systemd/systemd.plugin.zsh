# ==============================================================================
# Oh My Zsh — systemd plugin
# Systemd service & journalctl operator shortcuts
# ==============================================================================

alias sc-status='systemctl status'
alias sc-show='systemctl show'
alias sc-start='sudo systemctl start'
alias sc-stop='sudo systemctl stop'
alias sc-restart='sudo systemctl restart'
alias sc-reload='sudo systemctl reload'
alias sc-enable='sudo systemctl enable'
alias sc-disable='sudo systemctl disable'
alias sc-enable-now='sudo systemctl enable --now'
alias sc-disable-now='sudo systemctl disable --now'
alias sc-daemon-reload='sudo systemctl daemon-reload'
alias sc-failed='systemctl --failed'
alias sc-units='systemctl list-unit-files'
alias sc-timers='systemctl list-timers --all'
alias jc='journalctl'
alias jcf='journalctl -f'
alias jcu='journalctl -u'
alias jcb='journalctl -b'
alias jce='journalctl -p err..alert -b'
alias axonlogs='journalctl -u axonwalld -u axonwall-controller -u axonwall-ui -f'
