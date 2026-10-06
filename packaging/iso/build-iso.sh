#!/usr/bin/env bash
# ==============================================================================
# Axonwall Debian 13 (Trixie) Appliance ISO Builder
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/build"
OUTPUT_DIR="${SCRIPT_DIR}/output"
ISO_NAME="axonwall-debian13-amd64.iso"

echo "=== Axonwall Appliance ISO Builder ==="

if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root (or via sudo / in a root container) to build chroot/ISO."
   echo "    In CI/CD, this executes inside an unprivileged Docker container with CAP_SYS_ADMIN."
fi

mkdir -p "${WORK_DIR}" "${OUTPUT_DIR}"

# 1. Install prerequisites if missing
if ! command -v lb &>/dev/null; then
  echo "[+] Installing live-build & xorriso dependencies..."
  apt-get update && apt-get install -y --no-install-recommends \
    live-build \
    debootstrap \
    xorriso \
    isolinux \
    syslinux-efi \
    grub-pc-bin \
    grub-efi-amd64-bin \
    mtools
fi

cd "${WORK_DIR}"

# 2. Configure live-build for Debian 13 (Trixie)
echo "[+] Configuring live-build for Debian 13 (Trixie)..."
lb config \
  --distribution trixie \
  --architectures amd64 \
  --archive-areas "main contrib non-free non-free-firmware" \
  --binary-images iso-hybrid \
  --bootloader grub-efi \
  --debian-installer live \
  --debian-installer-preseedfile "${SCRIPT_DIR}/config/includes.installer/preseed.cfg" \
  --iso-application "Axonwall Firewall & Router Appliance" \
  --iso-publisher "Axonwall Core Team <ops@axonwall.io>" \
  --iso-volume "AXONWALL_D13" \
  --memtest none \
  --system live

# 3. Copy customized overlays (sysctl, firstboot service, systemd units)
echo "[+] Copying Axonwall system includes & overlays..."
mkdir -p config/includes.chroot
cp -r "${SCRIPT_DIR}/config/includes.chroot/"* config/includes.chroot/

# Copy Debian packaging systemd units
mkdir -p config/includes.chroot/etc/systemd/system/
cp "${SCRIPT_DIR}/../debian/axonwalld.service" config/includes.chroot/etc/systemd/system/ || true
cp "${SCRIPT_DIR}/../debian/axonwall-controller.service" config/includes.chroot/etc/systemd/system/ || true
cp "${SCRIPT_DIR}/../debian/axonwall-ui.service" config/includes.chroot/etc/systemd/system/ || true

# Copy default baseline lockdown ruleset
mkdir -p config/includes.chroot/usr/share/axonwall/
cp "${SCRIPT_DIR}/../debian/lockdown.nft" config/includes.chroot/usr/share/axonwall/ || true

chmod +x config/includes.chroot/usr/local/bin/axonwall-firstboot

# 4. Define package list to install in image
mkdir -p config/package-lists
cat << 'EOF' > config/package-lists/axonwall.list.chroot
linux-image-amd64
linux-headers-amd64
firmware-linux
firmware-misc-nonfree
systemd
systemd-sysv
grub-efi-amd64
nftables
iproute2
wireguard-tools
suricata
kea-dhcp4-server
unbound
frr
strongswan
openvpn
conntrack
conntrackd
keepalived
ethtool
pciutils
tcpdump
curl
wget
jq
ca-certificates
EOF

# 5. Build ISO
echo "[+] Executing lb build..."
lb build

# 6. Move output image
if [[ -f live-image-amd64.hybrid.iso ]]; then
  mv live-image-amd64.hybrid.iso "${OUTPUT_DIR}/${ISO_NAME}"
  echo "=================================================="
  echo "[✓] Successfully built Axonwall Appliance ISO:"
  echo "    ${OUTPUT_DIR}/${ISO_NAME}"
  echo "=================================================="
fi
