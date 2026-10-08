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

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}" "${OUTPUT_DIR}"

# 1. Install prerequisites if missing
if ! command -v lb &>/dev/null; then
  echo "[+] Installing live-build & xorriso dependencies..."
  apt-get update && apt-get install -y --no-install-recommends \
    live-build \
    debootstrap \
    debian-archive-keyring \
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
  --mode debian \
  --distribution trixie \
  --mirror-bootstrap "http://deb.debian.org/debian/" \
  --mirror-chroot "http://deb.debian.org/debian/" \
  --mirror-chroot-security "http://deb.debian.org/debian-security/" \
  --mirror-binary "http://deb.debian.org/debian/" \
  --mirror-binary-security "http://deb.debian.org/debian-security/" \
  --mirror-debian-installer "http://deb.debian.org/debian/" \
  --keyring-packages debian-archive-keyring \
  --architectures amd64 \
  --linux-flavours amd64 \
  --archive-areas "main contrib non-free non-free-firmware" \
  --binary-images iso-hybrid \
  --bootloaders "syslinux,grub-efi" \
  --bootappend-live "boot=live components hostname=axonwall username=axonwall live-config.user-default-groups=sudo,adm,dialout live-config.user-password=axonwall live-config.root-password=axonwall console=tty0 console=ttyS0,115200" \
  --bootappend-install "auto=true priority=critical preseed/file=/cdrom/preseed.cfg" \
  --debian-installer live \
  --debian-installer-distribution trixie \
  --debian-installer-gui false \
  --iso-application "Axonwall Firewall & Router Appliance" \
  --iso-publisher "Axonwall Core Team <ops@axonwall.io>" \
  --iso-volume "AXONWALL_D13" \
  --memtest none \
  --system live

# 3. Copy customized overlays (sysctl, firstboot service, systemd units)
echo "[+] Copying Axonwall system includes & overlays..."
mkdir -p config/includes.chroot
if [[ -d "${SCRIPT_DIR}/config/includes.chroot" ]]; then
  cp -r "${SCRIPT_DIR}/config/includes.chroot/"* config/includes.chroot/
fi

mkdir -p config/includes.installer
if [[ -d "${SCRIPT_DIR}/config/includes.installer" ]]; then
  cp -r "${SCRIPT_DIR}/config/includes.installer/"* config/includes.installer/
fi

# Ensure firstboot marker directory and service enable symlink exist
mkdir -p config/includes.chroot/etc/axonwall/
touch config/includes.chroot/etc/axonwall/.firstboot
mkdir -p config/includes.chroot/etc/systemd/system/multi-user.target.wants/
if [[ -f config/includes.chroot/etc/systemd/system/axonwall-firstboot.service ]]; then
  ln -sf /etc/systemd/system/axonwall-firstboot.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/axonwall-firstboot.service
fi

# Copy Debian packaging systemd units
mkdir -p config/includes.chroot/etc/systemd/system/
cp "${SCRIPT_DIR}/../debian/axonwalld.service" config/includes.chroot/etc/systemd/system/ || true
cp "${SCRIPT_DIR}/../debian/axonwall-controller.service" config/includes.chroot/etc/systemd/system/ || true
cp "${SCRIPT_DIR}/../debian/axonwall-ui.service" config/includes.chroot/etc/systemd/system/ || true
cp "${SCRIPT_DIR}/../debian/headscale.service" config/includes.chroot/etc/systemd/system/ || true
ln -sf /etc/systemd/system/headscale.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/headscale.service

mkdir -p config/includes.chroot/etc/headscale
cp "${SCRIPT_DIR}/../debian/headscale-config.yaml" config/includes.chroot/etc/headscale/config.yaml || true

# Copy default baseline lockdown ruleset
mkdir -p config/includes.chroot/usr/share/axonwall/
cp "${SCRIPT_DIR}/../debian/lockdown.nft" config/includes.chroot/usr/share/axonwall/ || true

if [[ -f config/includes.chroot/usr/local/bin/axonwall-firstboot ]]; then
  chmod +x config/includes.chroot/usr/local/bin/axonwall-firstboot
fi

# Copy compiled daemon binaries if present
mkdir -p config/includes.chroot/usr/sbin/

# Fetch Headscale binary
HEADSCALE_VERSION="0.29.4"
if [[ ! -f config/includes.chroot/usr/sbin/headscale ]]; then
  echo "[+] Fetching Headscale v${HEADSCALE_VERSION}..."
  curl -fsSL -o config/includes.chroot/usr/sbin/headscale "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}/headscale_${HEADSCALE_VERSION}_linux_amd64"
  chmod +x config/includes.chroot/usr/sbin/headscale
fi

if [[ -f "${SCRIPT_DIR}/../../apps/axonwalld/bin/axonwalld" ]]; then
  cp "${SCRIPT_DIR}/../../apps/axonwalld/bin/axonwalld" config/includes.chroot/usr/sbin/
  chmod +x config/includes.chroot/usr/sbin/axonwalld
fi

if [[ -f "${SCRIPT_DIR}/../../apps/axonwall-satellite/bin/axonwall-satellite-amd64" ]]; then
  cp "${SCRIPT_DIR}/../../apps/axonwall-satellite/bin/axonwall-satellite-amd64" config/includes.chroot/usr/sbin/axonwall-satellite
  chmod +x config/includes.chroot/usr/sbin/axonwall-satellite
fi

mkdir -p config/includes.chroot/usr/share/axonwall/satellites/
if [[ -d "${SCRIPT_DIR}/../../apps/axonwall-satellite/bin" ]]; then
  cp -r "${SCRIPT_DIR}/../../apps/axonwall-satellite/bin/"* config/includes.chroot/usr/share/axonwall/satellites/ 2>/dev/null || true
fi

# 4. Define package list to install in image
mkdir -p config/package-lists
cat << 'EOF' > config/package-lists/axonwall.list.chroot
linux-image-amd64
linux-headers-amd64
live-boot
live-boot-initramfs-tools
live-config
live-config-systemd
user-setup
sudo
firmware-linux
firmware-misc-nonfree
systemd
systemd-sysv
grub-pc-bin
grub-efi-amd64-bin
grub-efi-amd64-signed
shim-signed
isolinux
syslinux-common
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
