#!/bin/sh
# ZFSBootMenu v3.1.x Pre-Boot Autonomous Watchdog Hook for Axonwall Root-on-ZFS
# Located at /etc/zfsbootmenu/hooks/setup.d/20-axonwall-watchdog.sh

POOL="zroot"
PARENT="${POOL}/ROOT"
GUARD_FILE="${BASE:-/zfsbootmenu}/axonwall_watchdog_done"

[ -e "$GUARD_FILE" ] && exit 0
mkdir -p "${BASE:-/zfsbootmenu}" 2>/dev/null || true
: > "$GUARD_FILE" 2>/dev/null || true

# Ensure pool is imported
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

# If an upgrade or switch is armed and active_be differs from fallback_be:
if [ -n "$ACTIVE_BE" ] && [ -n "$FALLBACK_BE" ] && [ "$ACTIVE_BE" != "$FALLBACK_BE" ]; then
  RO_STATE="$(zpool get -H -o value readonly "$POOL" 2>/dev/null || echo "off")"
  if [ "$RO_STATE" = "on" ]; then
    zpool export "$POOL" 2>/dev/null || true
    zpool import -N -o readonly=off "$POOL" 2>/dev/null || exit 0
  fi

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
    echo "${FALLBACK_BE}" > "${BASE:-/zfsbootmenu}/bootfs" 2>/dev/null || true
    sleep 2
  else
    NEW_COUNT=$(( BOOTCOUNT + 1 ))
    zfs set org.axonwall:bootcount="${NEW_COUNT}" "$PARENT" 2>/dev/null || true
  fi

  if [ "$RO_STATE" = "on" ]; then
    zpool export "$POOL" 2>/dev/null || true
    zpool import -N -o readonly=on "$POOL" 2>/dev/null || true
  fi
fi

exit 0
