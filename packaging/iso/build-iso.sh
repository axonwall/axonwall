#!/usr/bin/env bash
# ==============================================================================
# Axonwall Debian 13 (Trixie) Appliance ISO Builder
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${WORK_DIR:-${SCRIPT_DIR}/build}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/output}"
ISO_NAME="axonwall-debian13-amd64.iso"

echo "=== Axonwall Appliance ISO Builder ==="

if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root (or via sudo / in a root container) to build chroot/ISO."
   echo "    In CI/CD, this executes inside an unprivileged Docker container with CAP_SYS_ADMIN."
fi

mkdir -p "${WORK_DIR}" "${OUTPUT_DIR}"
find "${WORK_DIR}" -mindepth 1 -not -path "${WORK_DIR}/cache*" -delete 2>/dev/null || true

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
    syslinux-common \
    grub-pc-bin \
    grub-efi-amd64-bin \
    mtools \
    curl \
    ca-certificates \
    dosfstools
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
  --bootappend-install "auto=true priority=critical preseed/file=/preseed.cfg" \
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

mkdir -p config/includes.binary
if [[ -d "${SCRIPT_DIR}/config/includes.binary" ]]; then
  cp -r "${SCRIPT_DIR}/config/includes.binary/"* config/includes.binary/
fi

# Ensure firstboot marker directory and service enable symlink exist
mkdir -p config/includes.chroot/etc/axonwall/
touch config/includes.chroot/etc/axonwall/.firstboot
mkdir -p config/includes.chroot/etc/systemd/system/multi-user.target.wants/
if [[ -f config/includes.chroot/etc/systemd/system/axonwall-firstboot.service ]]; then
  ln -sf /etc/systemd/system/axonwall-firstboot.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/axonwall-firstboot.service
fi

# Copy Debian packaging systemd units
mkdir -p config/includes.chroot/etc/systemd/system/multi-user.target.wants/
cp "${SCRIPT_DIR}/../debian/axonwalld.service" config/includes.chroot/etc/systemd/system/ || true
ln -sf /etc/systemd/system/axonwalld.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/axonwalld.service
cp "${SCRIPT_DIR}/../debian/axonwall-controller.service" config/includes.chroot/etc/systemd/system/ || true
ln -sf /etc/systemd/system/axonwall-controller.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/axonwall-controller.service
cp "${SCRIPT_DIR}/../debian/axonwall-ui.service" config/includes.chroot/etc/systemd/system/ || true
ln -sf /etc/systemd/system/axonwall-ui.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/axonwall-ui.service
cp "${SCRIPT_DIR}/../debian/axonwall-console.service" config/includes.chroot/etc/systemd/system/ || true
ln -sf /etc/systemd/system/axonwall-console.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/axonwall-console.service
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

if [[ -f config/includes.chroot/usr/local/bin/axonwall-ha-notify ]]; then
  chmod +x config/includes.chroot/usr/local/bin/axonwall-ha-notify
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

# Fetch Litestream binary for distributed SQLite replication
LITESTREAM_VERSION="0.3.13"
if [[ ! -f config/includes.chroot/usr/sbin/litestream ]]; then
  echo "[+] Fetching Litestream v${LITESTREAM_VERSION}..."
  curl -fsSL -o /tmp/litestream.tar.gz "https://github.com/benbjohnson/litestream/releases/download/v${LITESTREAM_VERSION}/litestream-v${LITESTREAM_VERSION}-linux-amd64.tar.gz" || true
  if [[ -f /tmp/litestream.tar.gz ]]; then
    tar -xzf /tmp/litestream.tar.gz -C config/includes.chroot/usr/sbin/ litestream 2>/dev/null || true
    chmod +x config/includes.chroot/usr/sbin/litestream 2>/dev/null || true
    rm -f /tmp/litestream.tar.gz
  fi
fi

if [[ -f "${SCRIPT_DIR}/../../apps/axonwalld/bin/axonwalld" ]]; then
  cp "${SCRIPT_DIR}/../../apps/axonwalld/bin/axonwalld" config/includes.chroot/usr/sbin/
  chmod +x config/includes.chroot/usr/sbin/axonwalld
fi

if [[ -f "${SCRIPT_DIR}/../../apps/axonwall-console/bin/axonwall-console" ]]; then
  cp "${SCRIPT_DIR}/../../apps/axonwall-console/bin/axonwall-console" config/includes.chroot/usr/sbin/
  chmod +x config/includes.chroot/usr/sbin/axonwall-console
fi

if [[ -f "${SCRIPT_DIR}/../../apps/axonwall-satellite/bin/axonwall-satellite-amd64" ]]; then
  cp "${SCRIPT_DIR}/../../apps/axonwall-satellite/bin/axonwall-satellite-amd64" config/includes.chroot/usr/sbin/axonwall-satellite
  chmod +x config/includes.chroot/usr/sbin/axonwall-satellite
fi

mkdir -p config/includes.chroot/usr/share/axonwall/satellites/
if [[ -d "${SCRIPT_DIR}/../../apps/axonwall-satellite/bin" ]]; then
  cp -r "${SCRIPT_DIR}/../../apps/axonwall-satellite/bin/"* config/includes.chroot/usr/share/axonwall/satellites/ 2>/dev/null || true
fi

# Bundle Axonwall Web Console (Next.js standalone) and Controller into /opt/axonwall/
echo "[+] Bundling Axonwall Web Console & Controller into /opt/axonwall..."
mkdir -p config/includes.chroot/opt/axonwall/apps/axonwall
mkdir -p config/includes.chroot/opt/axonwall/apps/axonwall-controller/dist

if [[ -d "${SCRIPT_DIR}/../../apps/axonwall/.next/standalone" ]]; then
  cp -r "${SCRIPT_DIR}/../../apps/axonwall/.next/standalone/"* config/includes.chroot/opt/axonwall/
  mkdir -p config/includes.chroot/opt/axonwall/apps/axonwall/.next/
  mkdir -p config/includes.chroot/opt/axonwall/.next/
  if [[ -d "${SCRIPT_DIR}/../../apps/axonwall/.next/static" ]]; then
    cp -r "${SCRIPT_DIR}/../../apps/axonwall/.next/static" config/includes.chroot/opt/axonwall/apps/axonwall/.next/
    cp -r "${SCRIPT_DIR}/../../apps/axonwall/.next/static" config/includes.chroot/opt/axonwall/.next/
  fi
  if [[ -d "${SCRIPT_DIR}/../../apps/axonwall/public" ]]; then
    cp -r "${SCRIPT_DIR}/../../apps/axonwall/public" config/includes.chroot/opt/axonwall/apps/axonwall/
    cp -r "${SCRIPT_DIR}/../../apps/axonwall/public" config/includes.chroot/opt/axonwall/
  fi
fi

if [[ -f "${SCRIPT_DIR}/../../apps/axonwall-controller/dist/index.js" ]]; then
  cp "${SCRIPT_DIR}/../../apps/axonwall-controller/dist/index.js" config/includes.chroot/opt/axonwall/apps/axonwall-controller/dist/
  cp "${SCRIPT_DIR}/../../apps/axonwall-controller/package.json" config/includes.chroot/opt/axonwall/apps/axonwall-controller/
fi

# NOTE: TLS certificates are intentionally NOT generated here. A key baked into the
# ISO would be identical on every appliance. axonwall-firstboot generates a unique one.
rm -rf config/includes.chroot/etc/axonwall/certs

# Ensure post-base-installer and finish-install hooks in installer are executable
find config/includes.installer/ -type f -name "*.d/*" -exec chmod +x {} + 2>/dev/null || true

# Pre-cache bootloader packages so debian-installer offline installations succeed without network/disc prompts
echo "[+] Pre-caching offline bootloader packages for BIOS & UEFI..."
mkdir -p config/includes.chroot/var/cache/apt/archives/
apt-get update -qq || true
apt-get install -d -y --no-install-recommends \
  grub-pc \
  grub-pc-bin \
  grub2-common \
  grub-common \
  ucf \
  os-prober 2>/dev/null || true
apt-get install -d -y --no-install-recommends \
  grub-efi-amd64 \
  grub-efi-amd64-bin \
  grub-efi-amd64-signed \
  shim-signed \
  shim-helpers-amd64-signed \
  shim-unsigned \
  efibootmgr 2>/dev/null || true
cp /var/cache/apt/archives/*.deb config/includes.chroot/var/cache/apt/archives/ 2>/dev/null || true

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
grub-pc
grub-pc-bin
ucf
os-prober
isolinux
syslinux-common
nftables
iproute2
wireguard-tools
sqlite3
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
nodejs
net-tools
openssl
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
else
  echo "[!] Error: live-image-amd64.hybrid.iso was not generated in $(pwd)"
  exit 1
fi
