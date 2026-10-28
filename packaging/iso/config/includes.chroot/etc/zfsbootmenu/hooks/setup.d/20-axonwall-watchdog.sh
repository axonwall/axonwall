#!/bin/sh
# ZFSBootMenu v3.1.x Pre-Boot Autonomous Watchdog Hook for Axonwall Root-on-ZFS
# Located at /etc/zfsbootmenu/hooks/setup.d/20-axonwall-watchdog.sh

set -e

POOL="zroot"
PARENT="${POOL}/ROOT"

# Ensure pool is imported read-write
if ! zpool list "$POOL" >/dev/null 2>&1; then
  zpool import -N -o readonly=off "$POOL" 2>/dev/null || exit 0
fi

# Read watchdog properties from zroot/ROOT
ACTIVE_BE="$(zfs get -H -o value org.axonwall:active_be "$PARENT" 2>/dev/null || echo "-")"
FALLBACK_BE="$(zfs get -H -o value org.axonwall:fallback_be "$PARENT" 2>/dev/null || echo "-")"
BOOTCOUNT_RAW="$(zfs get -H -o value org.axonwall:bootcount "$PARENT" 2>/dev/null || echo "0")"
BOOTLIMIT_RAW="$(zfs get -H -o value org.axonwall:bootlimit "$PARENT" 2>/dev/null || echo "3")"

# Clean up raw outputs
[ "$ACTIVE_BE" = "-" ] && ACTIVE_BE=""
[ "$FALLBACK_BE" = "-" ] && FALLBACK_BE=""
BOOTCOUNT=$(echo "$BOOTCOUNT_RAW" | tr -cd '0-9')
[ -z "$BOOTCOUNT" ] && BOOTCOUNT=0
BOOTLIMIT=$(echo "$BOOTLIMIT_RAW" | tr -cd '0-9')
[ -z "$BOOTLIMIT" ] || [ "$BOOTLIMIT" -le 0 ] && BOOTLIMIT=3

# Current pool bootfs
CURRENT_BOOTFS="$(zpool get -H -o value bootfs "$POOL" 2>/dev/null || echo "")"

echo "================================================================================"
echo "[Axonwall ZBM Watchdog] Inspecting Boot Environment health properties..."
echo "  Pool          : ${POOL}"
echo "  Current bootfs: ${CURRENT_BOOTFS:-<not set>}"
echo "  Active BE     : ${ACTIVE_BE:-<none>}"
echo "  Fallback BE   : ${FALLBACK_BE:-<none>}"
echo "  Boot Attempts : ${BOOTCOUNT}/${BOOTLIMIT}"
echo "================================================================================"

# If an upgrade or switch is armed and active_be differs from fallback_be:
if [ -n "$ACTIVE_BE" ] && [ -n "$FALLBACK_BE" ] && [ "$ACTIVE_BE" != "$FALLBACK_BE" ]; then
  if [ "$BOOTCOUNT" -ge "$BOOTLIMIT" ]; then
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "[!] CRITICAL: Boot attempt threshold (${BOOTCOUNT}/${BOOTLIMIT}) exceeded for target BE:"
    echo "    ${ACTIVE_BE}"
    echo "[!] AUTONOMOUS WATCHDOG: Rolling back bootfs to verified fallback BE:"
    echo "    ${FALLBACK_BE}"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"

    zpool set bootfs="${FALLBACK_BE}" "$POOL" 2>/dev/null || true
    zfs set org.axonwall:bootcount=0 "$PARENT" 2>/dev/null || true
    zfs set org.axonwall:active_be="${FALLBACK_BE}" "$PARENT" 2>/dev/null || true
    sleep 3
  else
    NEW_COUNT=$(( BOOTCOUNT + 1 ))
    echo "[+] Unverified Boot Environment detected. Incrementing bootcount: ${BOOTCOUNT} -> ${NEW_COUNT} (limit: ${BOOTLIMIT})"
    zfs set org.axonwall:bootcount="${NEW_COUNT}" "$PARENT" 2>/dev/null || true
  fi
fi

exit 0
