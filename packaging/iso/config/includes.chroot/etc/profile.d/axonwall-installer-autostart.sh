#!/bin/sh
# Fallback autostart: if a login shell opens directly on tty1 or ttyS0 during Live Installer boot
# (axonwall_install=1), launch the Next-Gen TUI Installer automatically once per TTY.
case "$-" in
  *i*) ;;
  *) return 0 2>/dev/null || exit 0 ;;
esac

if [ -r /proc/cmdline ] && grep -qE '(^|[[:space:]])(axonwall_install=1|axonwall\.install=1)($|[[:space:]])' /proc/cmdline 2>/dev/null; then
  _tty="$(tty 2>/dev/null || true)"
  case "$_tty" in
    /dev/tty1|/dev/ttyS0)
      _stamp="/run/axonwall-autostart-$(basename "$_tty").done"
      if [ ! -f "$_stamp" ] && [ -x /usr/sbin/axonwall-console ]; then
        touch "$_stamp" 2>/dev/null || true
        if [ "$(id -u)" -eq 0 ]; then
          /usr/sbin/axonwall-console
        elif command -v sudo >/dev/null 2>&1; then
          sudo /usr/sbin/axonwall-console
        fi
      fi
      ;;
  esac
fi
