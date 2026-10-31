#!/bin/bash
# ==============================================================================
# Axonwall ZFSBootMenu Visual Theme & Console Styling Hook
# Located at: /etc/zfsbootmenu/hooks/early-setup.d/15-axonwall-theme.sh
#             /EFI/ZBM/hooks/early-setup.d/15-axonwall-theme.sh (via zbm.hookroot)
# ==============================================================================

# 1. Determine active console terminal
TERM_DEV="${control_term:-/dev/tty1}"
[ -c "$TERM_DEV" ] || TERM_DEV="/dev/tty0"

# 2. Program Linux virtual console 16-color hardware palette
# Palette: Axonwall Cyberpunk Dark Slate & Emerald (#090e1a / #34d399 / #06b6d4)
# Escape sequence syntax: \033]P<idx><RRGGBB>
if [ -c "$TERM_DEV" ]; then
  # 0=Black(bg), 1=Red, 2=Green, 3=Yellow, 4=Blue, 5=Magenta, 6=Cyan, 7=White(fg)
  # 8=BrBlack, 9=BrRed, A=BrGreen, B=BrYellow, C=BrBlue, D=BrMagenta, E=BrCyan, F=BrWhite
  printf '\033]P0090e1a\033]P1f43f5e\033]P210b981\033]P3f59e0b\033]P40284c7\033]P58b5cf6\033]P606b6d4\033]P7cbd5e1\033]P81e293b\033]P9fb7185\033]PA34d399\033]PBfbbf24\033]PC38bdf8\033]PDa78bfa\033]PE22d3ee\033]PFf8fafc' > "$TERM_DEV" 2>/dev/null || true
  # Clear and home cursor to repaint console buffer with #090e1a
  printf '\033[2J\033[H' > "$TERM_DEV" 2>/dev/null || true
fi

# 3. Configure FZF truecolor environment defaults for ZBM menu interfaces
FZF_AXONWALL_OPTS="--color=bg+:#111c2e,bg:#090e1a,spinner:#34d399,hl:#34d399,fg:#cbd5e1,header:#06b6d4,info:#38bdf8,pointer:#34d399,marker:#34d399,fg+:#f8fafc,prompt:#34d399,hl+:#22d3ee,border:#1e3a47"
export FZF_DEFAULT_OPTS="${FZF_AXONWALL_OPTS}"

# Persist to runtime zfsbootmenu configuration so subshells and subsequent pages inherit colors
if [ -f /etc/zfsbootmenu.conf ] && ! grep -q "FZF_DEFAULT_OPTS" /etc/zfsbootmenu.conf 2>/dev/null; then
  printf '\nexport FZF_DEFAULT_OPTS="%s"\n' "${FZF_AXONWALL_OPTS}" >> /etc/zfsbootmenu.conf 2>/dev/null || true
fi

# 4. Set console font if not already applied by rd.vconsole.font
if [ -x /usr/bin/setfont ]; then
  for font in \
    /usr/share/zfsbootmenu/fonts/ter-v32b.psf \
    /usr/share/zfsbootmenu/fonts/ter-v28b.psf \
    /usr/share/zfsbootmenu/fonts/ter-v24b.psf \
    /usr/share/kbd/consolefonts/Lat2-Terminus16.psfu.gz; do
    if [ -f "$font" ]; then
      setfont "$font" >/dev/null 2>&1 && break
    fi
  done
fi

exit 0
