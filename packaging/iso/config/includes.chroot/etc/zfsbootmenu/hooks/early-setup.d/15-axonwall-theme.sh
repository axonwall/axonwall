#!/bin/bash
# ==============================================================================
# Axonwall ZFSBootMenu Visual Theme & Console Styling Hook
# Located at: /etc/zfsbootmenu/hooks/early-setup.d/15-axonwall-theme.sh
#             /EFI/ZBM/hooks/early-setup.d/15-axonwall-theme.sh (via zbm.hookroot)
# ==============================================================================

# 1. Determine active physical/VGA console terminal (never serial ttyS0)
TERM_DEV="${control_term:-/dev/tty1}"
case "$TERM_DEV" in
  /dev/tty[0-9]*) ;;
  *) TERM_DEV="/dev/tty1" ;;
esac
[ -c "$TERM_DEV" ] || TERM_DEV="/dev/tty0"

# 2. Program Linux virtual console 16-color hardware palette
# Palette: Axonwall Cyberpunk Dark Slate & Emerald (#090e1a / #34d399 / #06b6d4)
if [ -c "$TERM_DEV" ]; then
  # 0=Black(bg), 1=Red, 2=Green, 3=Yellow, 4=Blue, 5=Magenta, 6=Cyan, 7=White(fg)
  # 8=BrBlack, 9=BrRed, A=BrGreen, B=BrYellow, C=BrBlue, D=BrMagenta, E=BrCyan, F=BrWhite
  printf '\033]P0090e1a\033]P1f43f5e\033]P210b981\033]P3f59e0b\033]P40284c7\033]P58b5cf6\033]P606b6d4\033]P7cbd5e1\033]P81e293b\033]P9fb7185\033]PA34d399\033]PBfbbf24\033]PC38bdf8\033]PDa78bfa\033]PE22d3ee\033]PFf8fafc' > "$TERM_DEV" 2>/dev/null || true
  printf '\033[2J\033[H' > "$TERM_DEV" 2>/dev/null || true
fi

# 3. Append 16-color theme rules to ZFSBootMenu's /lib/fzf-defaults.sh
# Preserves all fuzzy_default_options (--ansi, --layout=reverse-list, --tac, keybindings)
for fzf_cfg in /lib/fzf-defaults.sh /usr/lib/fzf-defaults.sh; do
  if [ -f "$fzf_cfg" ] && ! grep -q "AXONWALL_FZF_THEME" "$fzf_cfg" 2>/dev/null; then
    cat << 'FZF_EOF' >> "$fzf_cfg"

# AXONWALL_FZF_THEME
fuzzy_default_options+=(
  "--color=border:cyan,label:bright-cyan,preview-label:bright-green,current-fg:bright-green,selected-fg:bright-cyan,prompt:bright-green,pointer:bright-green,marker:bright-green,header:cyan,info:bright-blue,spinner:bright-green,hl:bright-green,hl+:bright-cyan"
)
export FZF_DEFAULT_OPTS="${fuzzy_default_options[*]}"
FZF_EOF
  fi
done

# 4. If invoked at 15- (before 20-dracut-console-init.sh & 30-console-autosize.sh),
# stage a 90- copy so palette is re-applied after console_init and setfont finish.
if [ "${0##*/}" = "15-axonwall-theme.sh" ] && [ -d /libexec/hooks/early-setup.d ] && [ ! -f /libexec/hooks/early-setup.d/90-axonwall-theme.sh ]; then
  cp -f "$0" /libexec/hooks/early-setup.d/90-axonwall-theme.sh 2>/dev/null || true
  chmod +x /libexec/hooks/early-setup.d/90-axonwall-theme.sh 2>/dev/null || true
fi

exit 0
