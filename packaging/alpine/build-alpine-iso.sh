#!/usr/bin/env bash
# ==============================================================================
# Axonwall Alpine Linux Appliance ISO Builder
# Supports:
#   --profile virt   Ultra-compact Virtual/Cloud Appliance (~135 MB)
#   --profile lts    Bare-Metal & Hardware Appliance with NIC firmware (~165 MB)
#   --minimal        Exclude heavy IDS/routing packages (Suricata/FRR) (~95 MB)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PROFILE="virt"
MINIMAL=1
IN_CONTAINER=0

ARGS=("$@")
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="${2:-virt}"
      shift 2
      ;;
    --minimal)
      MINIMAL=1
      shift
      ;;
    --full)
      MINIMAL=0
      shift
      ;;
    --in-container)
      IN_CONTAINER=1
      shift
      ;;
    *)
      shift
      ;;
  esac
done

# If not running inside Alpine Linux, automatically delegate to alpine:3.21 Docker container
if [[ "$IN_CONTAINER" -eq 0 ]] && [[ ! -f /etc/alpine-release ]]; then
  echo "[+] Host is not Alpine Linux. Launching isolated alpine:3.21 build container..."
  exec docker run --rm \
    -v "${REPO_ROOT}:/repo" \
    -w /repo \
    alpine:3.21 \
    /bin/sh -c "apk add --no-cache bash >/dev/null && exec /bin/bash /repo/packaging/alpine/build-alpine-iso.sh --in-container ${ARGS[*]}"
fi

ALPINE_BRANCH="v3.21"
ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_BRANCH}"
WORK_DIR="/tmp/axonwall-alpine-build"
OUTPUT_DIR="${REPO_ROOT}/packaging/alpine/output"
if [[ "$MINIMAL" -eq 1 ]]; then
  ISO_NAME="axonwall-alpine-${PROFILE}-minimal-amd64.iso"
else
  ISO_NAME="axonwall-alpine-${PROFILE}-amd64.iso"
fi

echo "=== Axonwall Alpine Linux ISO Builder (Profile: ${PROFILE}, Minimal: ${MINIMAL}) ==="

# 1. Install ISO build tools inside Alpine
apk update
apk add --no-cache \
  xorriso \
  syslinux \
  grub \
  grub-bios \
  grub-efi \
  mtools \
  dosfstools \
  squashfs-tools \
  curl \
  tar \
  gzip \
  xz \
  openssl \
  ca-certificates \
  abuild \
  cpio

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}/iso/boot/grub" \
         "${WORK_DIR}/iso/boot/syslinux" \
         "${WORK_DIR}/iso/apks/x86_64" \
         "${WORK_DIR}/ovl" \
         "${OUTPUT_DIR}"

# 2. Fetch official Alpine base ISO for kernel, initramfs, modloop, and EFI boot image
echo "[+] Fetching Alpine ${ALPINE_BRANCH} (${PROFILE}) kernel, initramfs & modloop..."
ALPINE_FLAVOR="${PROFILE}"
if [[ "$PROFILE" == "lts" || "$PROFILE" == "standard" ]]; then
  ALPINE_FLAVOR="standard"
fi
RELEASE_YAML="$(curl -fsSL "${ALPINE_MIRROR}/releases/x86_64/latest-releases.yaml")"
ISO_FILE="$(echo "$RELEASE_YAML" | awk -v flv="alpine-${ALPINE_FLAVOR}-" '$1 == "file:" && $2 ~ flv && $2 ~ "-x86_64.iso" {print $2; exit}')"
if [[ -z "$ISO_FILE" ]]; then
  ISO_FILE="alpine-${ALPINE_FLAVOR}-3.21.8-x86_64.iso"
fi

# Pinned SHA-256 for the stock Alpine base ISOs this build redistributes:
# the kernel, initramfs and modloop are taken from the base ISO verbatim,
# so it is verified before extraction. Values cross-checked against
# Alpine's published release metadata AND a full download (2026-10-16).
# An unpinned base ISO fails the build closed -- bump the pin together
# with the Alpine point release.
case "${ISO_FILE}" in
  alpine-virt-3.21.8-x86_64.iso)
    EXPECTED_ISO_SHA256="478f6629181541a8c24ddcdf4c3f1810cf8deacb47f4e7e2ed367a7b2ef4d80e" ;;
  alpine-standard-3.21.8-x86_64.iso)
    EXPECTED_ISO_SHA256="290e9d0f708f60fcd5adeb08553408a0b9fd267e934633dc787c49657922a25b" ;;
  *)
    echo "[!] ERROR: no pinned SHA-256 for Alpine base ISO '${ISO_FILE}'." >&2
    echo "    Verify the new ISO against Alpine's release metadata and pin" >&2
    echo "    its SHA-256 in build-alpine-iso.sh before building with it." >&2
    exit 1 ;;
esac

curl -fsSL -o "${WORK_DIR}/base.iso" "${ALPINE_MIRROR}/releases/x86_64/${ISO_FILE}"
echo "${EXPECTED_ISO_SHA256}  ${WORK_DIR}/base.iso" | sha256sum -c -
xorriso -osirrox on -indev "${WORK_DIR}/base.iso" -extract / "${WORK_DIR}/iso" 2>/dev/null
chmod -R u+w "${WORK_DIR}/iso"
rm -f "${WORK_DIR}/base.iso"

# 3. Populate offline APK repository with Axonwall runtime & networking packages
# Minimal mode strips all extra shells/editors/CLI diagnostics (zsh, vim, starship,
# tmux, btop, htop, iftop, sysstat, nmap, git, etckeeper, etc.) to keep the ISO
# as small as possible while retaining 100% OpenLDAP + SSO + HA compatibility.
CORE_PKGS=(
  alpine-base
  alpine-conf
  openrc
  busybox
  busybox-openrc
  busybox-mdev-openrc
  kmod
  nftables
  iproute2
  # Interface management + a real DHCP client for the OpenRC networking
  # service (stock Alpine ISOs ship both; kea-dhcp4 below is a DHCP *server*)
  ifupdown-ng
  dhcpcd
  wireguard-tools
  keepalived
  conntrack-tools
  ethtool
  tcpdump
  unbound
  kea-dhcp4
  nodejs
  sqlite
  curl
  jq
  openssl
  ca-certificates
  parted
  mdadm
  sgdisk
  e2fsprogs
  dosfstools
  grub
  grub-bios
  grub-efi
  openssh
  # OpenLDAP SSO Identity Directory, HA Multi-Provider Syncrepl & NTP Clock Sync
  openldap
  openldap-openrc
  openldap-back-mdb
  openldap-overlay-syncprov
  openldap-overlay-ppolicy
  openldap-overlay-unique
  openldap-overlay-accesslog
  openldap-clients
  sudo
  shadow
  chrony
  chrony-openrc
)

if [[ "$MINIMAL" -eq 0 ]]; then
  CORE_PKGS+=(
    frr
    strongswan
    openvpn
    suricata
    zfs
    samba
    nfs-utils
    open-iscsi
    smartmontools
    etckeeper
    git
    nmap
    bind-tools
    net-tools
    htop
    btop
    iftop
    sysstat
    vim
    zsh
    starship
    tmux
  )
fi

if [[ "$PROFILE" == "lts" ]]; then
  CORE_PKGS+=(
    linux-firmware-intel
    linux-firmware-rtl_nic
    linux-firmware-bnx2
    linux-firmware-bnx2x
  )
fi

echo "[+] Resolving and caching ${#CORE_PKGS[@]} packages and transitive dependencies into /apks/x86_64..."
apk fetch --recursive --output "${WORK_DIR}/iso/apks/x86_64" "${CORE_PKGS[@]}"
# Generate RSA keypair and sign APKINDEX so apk verifies it offline.
#
# Trust model for this key (audit C-S4, decided 2026-10-22): the key is
# deliberately ephemeral per build. Its job is intra-image integrity —
# the APKINDEX is signed here and the public half is baked into the
# overlay and the initramfs, so boot-time and runtime apk verify the
# offline repo against the image's own key. No cross-release key
# pinning is promised or needed: an installed appliance never
# apk-installs after imaging, and updates replace whole A/B slots
# verified at the image level (release checksum / release signature).
# Publisher identity across releases belongs to the release-signing
# key; whether a persistent APK key is also warranted will be decided
# together with the release-signing enablement, not here.
echo "[+] Generating Axonwall signing key and indexing APK repository..."
mkdir -p /root/.abuild "${WORK_DIR}/ovl/etc/apk/keys"
abuild-keygen -a -n -q
SIGN_KEY_PUB="$(ls /root/.abuild/*.rsa.pub 2>/dev/null | head -n 1)"
SIGN_KEY_PRIV="$(ls /root/.abuild/*.rsa 2>/dev/null | grep -v '\.pub$' | head -n 1)"
PUBKEY_NAME="$(basename "${SIGN_KEY_PUB}")"

apk index \
  --output "${WORK_DIR}/iso/apks/x86_64/APKINDEX.tar.gz" \
  --rewrite-arch x86_64 \
  --description "Axonwall Appliance Offline Repository" \
  "${WORK_DIR}/iso/apks/x86_64/"*.apk

abuild-sign -k "${SIGN_KEY_PRIV}" -p "${PUBKEY_NAME}" "${WORK_DIR}/iso/apks/x86_64/APKINDEX.tar.gz"

# Ensure .boot_repository exists so initramfs find_boot_repositories locates it
touch "${WORK_DIR}/iso/apks/.boot_repository"

# Copy official Alpine and Axonwall signing public keys into overlay
cp -a /etc/apk/keys/* "${WORK_DIR}/ovl/etc/apk/keys/" 2>/dev/null || true
cp -a "${SIGN_KEY_PUB}" "${WORK_DIR}/ovl/etc/apk/keys/"

# Patch initramfs to trust local offline APK repository and include signing key
echo "[+] Patching initramfs with signing keys and offline repository trust..."
for initrd in "${WORK_DIR}/iso/boot"/initramfs-*; do
  if [[ -f "${initrd}" ]]; then
    INITFS_DIR="${WORK_DIR}/initfs_tmp"
    rm -rf "${INITFS_DIR}"
    mkdir -p "${INITFS_DIR}"
    (
      cd "${INITFS_DIR}"
      gzip -dc "${initrd}" | cpio -idmv >/dev/null 2>&1
      mkdir -p etc/apk/keys
      cp -a /etc/apk/keys/* etc/apk/keys/ 2>/dev/null || true
      cp -a "${SIGN_KEY_PUB}" etc/apk/keys/
      # Signature verification stays ON: the initramfs apk must verify
      # the offline repository. The APKINDEX is signed above with the
      # build's abuild key and its public half was just copied into
      # etc/apk/keys (alongside the stock Alpine keys that sign the
      # fetched packages), so no --allow-untrusted escape hatch is
      # needed. (Audit finding C3: this patch previously added
      # --allow-untrusted to apkflags, defeating the signing entirely.)
      find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "${initrd}.tmp"
    )
    mv "${initrd}.tmp" "${initrd}"
    rm -rf "${INITFS_DIR}"
    echo "    Patched and repacked $(basename "${initrd}")"
  fi
done

# 4. Construct Axonwall APKOVL (Appliance Overlay)
echo "[+] Building axonwall.apkovl.tar.gz overlay..."
OVL="${WORK_DIR}/ovl"

mkdir -p \
  "${OVL}/etc/axonwall" \
  "${OVL}/etc/headscale" \
  "${OVL}/etc/init.d" \
  "${OVL}/etc/runlevels/sysinit" \
  "${OVL}/etc/runlevels/boot" \
  "${OVL}/etc/runlevels/default" \
  "${OVL}/etc/runlevels/shutdown" \
  "${OVL}/etc/ssh/sshd_config.d" \
  "${OVL}/etc/sudoers.d" \
  "${OVL}/etc/sysctl.d" \
  "${OVL}/root" \
  "${OVL}/bin" \
  "${OVL}/sbin" \
  "${OVL}/usr/bin" \
  "${OVL}/usr/lib" \
  "${OVL}/usr/local/bin" \
  "${OVL}/usr/sbin" \
  "${OVL}/usr/share/axonwall/satellites" \
  "${OVL}/opt/axonwall/apps/axonwall" \
  "${OVL}/opt/axonwall/apps/axonwall-controller/dist" \
  "${OVL}/var/lib/axonwall/home" \
  "${OVL}/var/lib/axonwall/ldap/config" \
  "${OVL}/var/lib/axonwall/ldap/data" \
  "${OVL}/var/lib/axonwall/ldap/accesslog" \
  "${OVL}/var/lib/axonwall/ldap/backups" \
  "${OVL}/var/lib/axonwall/secrets/ldap" \
  "${OVL}/var/lib/axonwall/secrets/ha-pki" \
  "${OVL}/var/lib/openldap/run" \
  "${OVL}/var/log/axonwall"

# Ensure basic /bin/busybox and /sbin/init symlink exist in overlay as fail-safe
if [[ -f /bin/busybox ]]; then
  cp /bin/busybox "${OVL}/bin/busybox"
  chmod 755 "${OVL}/bin/busybox"
  ln -sf /bin/busybox "${OVL}/sbin/init"
  ln -sf /bin/busybox "${OVL}/bin/sh"
fi

# Symlink Debian OpenLDAP paths (/etc/ldap, /usr/lib/ldap) to Alpine paths (/etc/openldap, /usr/lib/openldap)
ln -sf /etc/openldap "${OVL}/etc/ldap"
ln -sf /usr/lib/openldap "${OVL}/usr/lib/ldap"

# Write /etc/hostname & /etc/apk/world
echo "axonwall" > "${OVL}/etc/hostname"
touch "${OVL}/etc/axonwall/.firstboot"

printf "%s\n" "${CORE_PKGS[@]}" > "${OVL}/etc/apk/world"

# Copy Alpine overlay files (OpenRC scripts, inittab, shims, installer)
cp -a "${SCRIPT_DIR}/overlay/"* "${OVL}/"
chmod +x "${OVL}/etc/init.d/"* "${OVL}/usr/local/bin/"*

# Copy shared scripts and configs from Debian/ISO packaging
cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/sysctl.d/99-axonwall.conf" "${OVL}/etc/sysctl.d/"
# Alpine's stock sshd is built without PAM, so strip UsePAM from sshd_config.d/axonwall.conf
grep -v '^UsePAM ' "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/ssh/sshd_config.d/axonwall.conf" > "${OVL}/etc/ssh/sshd_config.d/axonwall.conf"
cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/sudoers.d/axonwall" "${OVL}/etc/sudoers.d/axonwall"
chmod 0440 "${OVL}/etc/sudoers.d/axonwall"
cp "${REPO_ROOT}/packaging/debian/headscale-config.yaml" "${OVL}/etc/headscale/config.yaml"
cp "${REPO_ROOT}/packaging/debian/lockdown.nft" "${OVL}/usr/share/axonwall/lockdown.nft"

if [[ "$MINIMAL" -eq 0 ]]; then
  mkdir -p "${OVL}/etc/zsh" "${OVL}/etc/skel" "${OVL}/etc/vim"
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/axonwall/starship.toml" "${OVL}/etc/axonwall/starship.toml"
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zsh/axonwall.zsh" "${OVL}/etc/zsh/axonwall.zsh"
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zsh/zshenv" "${OVL}/etc/zsh/zshenv"
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/skel/.zshrc" "${OVL}/etc/skel/.zshrc"
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/skel/.zshrc" "${OVL}/root/.zshrc"
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/vim/vimrc.local" "${OVL}/etc/vim/vimrc.local"
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/tmux.conf" "${OVL}/etc/tmux.conf"
else
  # On minimal Alpine (no zsh installed), symlink /usr/bin/zsh -> /bin/ash so SSO users
  # replicated with loginShell=/usr/bin/zsh can SSH into minimal Alpine seamlessly.
  ln -sf /bin/ash "${OVL}/usr/bin/zsh"
fi

cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-ha-notify" "${OVL}/usr/local/bin/"
cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-import" "${OVL}/usr/local/bin/"
cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-update" "${OVL}/usr/local/bin/"
cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwallctl" "${OVL}/usr/local/bin/"
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-tui" ]]; then
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-tui" "${OVL}/usr/local/bin/"
fi
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-opshell" ]]; then
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-opshell" "${OVL}/usr/local/bin/"
fi
chmod +x "${OVL}/usr/local/bin/axonwall"*

# Version stamp
VERSION="$(cat "${REPO_ROOT}/VERSION" 2>/dev/null | tr -d '[:space:]' || echo "0.2.2")"
echo "${VERSION}" > "${OVL}/etc/axonwall/version"

# Copy compiled Go daemons (axonwalld, axonwall-console, axonwall-satellite)
if [[ -f "${REPO_ROOT}/apps/axonwalld/bin/axonwalld" ]]; then
  cp "${REPO_ROOT}/apps/axonwalld/bin/axonwalld" "${OVL}/usr/sbin/axonwalld"
  strip "${OVL}/usr/sbin/axonwalld" 2>/dev/null || true
  chmod +x "${OVL}/usr/sbin/axonwalld"
fi

if [[ -f "${REPO_ROOT}/apps/axonwall-console/bin/axonwall-console" ]]; then
  cp "${REPO_ROOT}/apps/axonwall-console/bin/axonwall-console" "${OVL}/usr/sbin/axonwall-console"
  strip "${OVL}/usr/sbin/axonwall-console" 2>/dev/null || true
  chmod +x "${OVL}/usr/sbin/axonwall-console"
fi

if [[ -f "${REPO_ROOT}/apps/axonwall-satellite/bin/axonwall-satellite-amd64" ]]; then
  cp "${REPO_ROOT}/apps/axonwall-satellite/bin/axonwall-satellite-amd64" "${OVL}/usr/sbin/axonwall-satellite"
  strip "${OVL}/usr/sbin/axonwall-satellite" 2>/dev/null || true
  chmod +x "${OVL}/usr/sbin/axonwall-satellite"
  ln -sf /usr/sbin/axonwall-satellite "${OVL}/usr/share/axonwall/satellites/axonwall-satellite-amd64"
fi

HEADSCALE_VERSION="0.29.4"
HEADSCALE_SHA256="212ed0a884c0d3541e094c4bebbe94397df6f4e01bd3d7f059c520cb55e0d757"
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/sbin/headscale" ]]; then
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/sbin/headscale" "${OVL}/usr/sbin/headscale"
  strip "${OVL}/usr/sbin/headscale" 2>/dev/null || true
  chmod +x "${OVL}/usr/sbin/headscale"
elif [[ ! -f "${OVL}/usr/sbin/headscale" ]]; then
  echo "[+] Fetching Headscale v${HEADSCALE_VERSION} for Alpine overlay..."
  curl -fsSL -o "${OVL}/usr/sbin/headscale" "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}/headscale_${HEADSCALE_VERSION}_linux_amd64"
  echo "${HEADSCALE_SHA256}  ${OVL}/usr/sbin/headscale" | sha256sum -c -
  strip "${OVL}/usr/sbin/headscale" 2>/dev/null || true
  chmod +x "${OVL}/usr/sbin/headscale"
fi

# Copy Next.js standalone UI & Controller
if [[ -d "${REPO_ROOT}/apps/axonwall/.next/standalone" ]]; then
  cp -a "${REPO_ROOT}/apps/axonwall/.next/standalone/"* "${OVL}/opt/axonwall/"
  # Strip build-only dependencies and unused glibc native binaries from standalone bundle
  rm -rf \
    "${OVL}/opt/axonwall/node_modules/.pnpm/"@img+sharp* \
    "${OVL}/opt/axonwall/node_modules/.pnpm/"sharp* \
    "${OVL}/opt/axonwall/node_modules/.pnpm/"typescript* \
    "${OVL}/opt/axonwall/node_modules/.pnpm/"caniuse-lite* \
    "${OVL}/opt/axonwall/node_modules/.pnpm/"postcss* \
    "${OVL}/opt/axonwall/node_modules/.pnpm/"next*/node_modules/next/dist/compiled/@vercel/og \
    "${OVL}/opt/axonwall/node_modules/.pnpm/"next*/node_modules/next/dist/compiled/webpack \
    2>/dev/null || true
  find "${OVL}/opt/axonwall" \( -name "*.map" -o -name "*.d.ts" -o -name "*.md" -o -name "LICENSE*" \) -delete 2>/dev/null || true
  # Next's production server loads dist/next-devtools/server/shared.js at
  # startup (via dist/server/patch-error-inspect.js), and shared.js in
  # turn requires dist/compiled/babel/code-frame. The strip list above
  # previously removed both dist/next-devtools and dist/compiled/babel*,
  # which crashed axonwall-ui on boot with "Cannot find module
  # '../next-devtools/server/shared'" (and, once that was restored,
  # "Cannot find module 'next/dist/compiled/babel/code-frame'").
  # Fail the build if the runtime files are missing from the payload.
  for next_dir in "${OVL}/opt/axonwall/node_modules/.pnpm/"next*/node_modules/next; do
    for req in dist/next-devtools/server/shared.js dist/server/patch-error-inspect.js dist/compiled/babel/code-frame.js; do
      if [[ ! -f "${next_dir}/${req}" ]]; then
        echo "[!] ERROR: Next.js runtime file missing from UI payload: ${next_dir}/${req}" >&2
        exit 1
      fi
    done
  done
  mkdir -p "${OVL}/opt/axonwall/apps/axonwall/.next" "${OVL}/opt/axonwall/.next"
  if [[ -d "${REPO_ROOT}/apps/axonwall/.next/static" ]]; then
    cp -a "${REPO_ROOT}/apps/axonwall/.next/static" "${OVL}/opt/axonwall/apps/axonwall/.next/"
  fi
  if [[ -d "${REPO_ROOT}/apps/axonwall/public" ]]; then
    cp -a "${REPO_ROOT}/apps/axonwall/public" "${OVL}/opt/axonwall/apps/axonwall/"
  fi
fi

if [[ -f "${REPO_ROOT}/apps/axonwall-controller/dist/index.js" ]]; then
  cp "${REPO_ROOT}/apps/axonwall-controller/dist/index.js" "${OVL}/opt/axonwall/apps/axonwall-controller/dist/"
  cp "${REPO_ROOT}/apps/axonwall-controller/package.json" "${OVL}/opt/axonwall/apps/axonwall-controller/"
fi
if [[ -f "${REPO_ROOT}/apps/axonwall-controller/dist/axonwallctl.js" ]]; then
  cp "${REPO_ROOT}/apps/axonwall-controller/dist/axonwallctl.js" "${OVL}/opt/axonwall/apps/axonwall-controller/dist/"
fi
if [[ -f "${REPO_ROOT}/apps/axonwall-controller/dist/axonwall-tui.js" ]]; then
  cp "${REPO_ROOT}/apps/axonwall-controller/dist/axonwall-tui.js" "${OVL}/opt/axonwall/apps/axonwall-controller/dist/"
fi

# Configure OpenRC runlevel symlinks
# modloop is required on this diskless image: it mounts the modloop squashfs
# and links /lib/modules into the live system. Stock Alpine adds it via the
# initramfs default runlevel set, but a hand-pinned apkovl like this one
# suppresses those defaults. Without it no kernel module can load after the
# initramfs stage -- notably af_packet, so every DHCPv4 client (dhcpcd and
# udhcpc alike) fails with "socket(AF_PACKET): Address family not supported
# by protocol" and the live system never gets an IPv4 lease.
for svc in devfs dmesg mdev hwdrivers modloop; do
  ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/sysinit/${svc}"
done
for svc in axonwall-network-setup modules sysctl hostname bootmisc syslog networking; do
  ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/boot/${svc}"
done
for svc in chronyd crond slapd sshd headscale axonwall-firstboot axonwalld axonwall-controller axonwall-ui local; do
  ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/default/${svc}"
done
for svc in mount-ro killprocs savecache; do
  ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/shutdown/${svc}"
done

# Pack axonwall.apkovl.tar.gz into ISO root with maximum compression
(cd "${OVL}" && tar -cf - . | gzip -9 > "${WORK_DIR}/iso/axonwall.apkovl.tar.gz")

# 5. Update bootloader configs (SYSLINUX & GRUB EFI) with comprehensive storage drivers, live & install options
STORAGE_MODULES="loop,squashfs,sd-mod,usb-storage,sr_mod,cdrom,isofs,virtio_blk,virtio_scsi,virtio_pci,nvme,ata_piix,ahci"

mkdir -p "${WORK_DIR}/iso/boot/syslinux" "${WORK_DIR}/iso/boot/grub"

cat << SYSLINUX_EOF > "${WORK_DIR}/iso/boot/syslinux/syslinux.cfg"
TIMEOUT 50
PROMPT 1
DEFAULT live

LABEL live
  MENU LABEL Axonwall Appliance (Live Mode)
  KERNEL /boot/vmlinuz-${ALPINE_FLAVOR}
  INITRD /boot/initramfs-${ALPINE_FLAVOR}
  APPEND modules=${STORAGE_MODULES} quiet console=tty0 console=ttyS0,115200

LABEL install
  MENU LABEL Install Axonwall to Storage Disk (A/B + RAID + ZFS)
  KERNEL /boot/vmlinuz-${ALPINE_FLAVOR}
  INITRD /boot/initramfs-${ALPINE_FLAVOR}
  APPEND modules=${STORAGE_MODULES} axonwall_install=1 quiet console=tty0 console=ttyS0,115200
SYSLINUX_EOF

cat << GRUB_EOF > "${WORK_DIR}/iso/boot/grub/grub.cfg"
set default=0
set timeout=5

menuentry "Axonwall Appliance (Live Mode)" {
  linux /boot/vmlinuz-${ALPINE_FLAVOR} modules=${STORAGE_MODULES} quiet console=tty0 console=ttyS0,115200
  initrd /boot/initramfs-${ALPINE_FLAVOR}
}

menuentry "Install Axonwall to Storage Disk (A/B + RAID + ZFS)" {
  linux /boot/vmlinuz-${ALPINE_FLAVOR} modules=${STORAGE_MODULES} axonwall_install=1 quiet console=tty0 console=ttyS0,115200
  initrd /boot/initramfs-${ALPINE_FLAVOR}
}
GRUB_EOF

# 6. Assemble bootable BIOS + UEFI Hybrid ISO
echo "[+] Generating hybrid BIOS/UEFI ISO image: ${ISO_NAME}..."
MBR_BIN="/usr/share/syslinux/isohdpfx.bin"
XORRISO_ARGS=(
  -as mkisofs
  -o "${OUTPUT_DIR}/${ISO_NAME}"
  -V "AXONWALL_ALPINE"
  -A "Axonwall Alpine Firewall & Router Appliance"
  -p "Axonwall Core Team"
  -J -R -l
)

if [[ -f "${MBR_BIN}" ]]; then
  XORRISO_ARGS+=(-isohybrid-mbr "${MBR_BIN}")
fi

if [[ -f "${WORK_DIR}/iso/boot/syslinux/isolinux.bin" ]]; then
  XORRISO_ARGS+=(
    -b boot/syslinux/isolinux.bin
    -c boot/syslinux/boot.cat
    -no-emul-boot
    -boot-load-size 4
    -boot-info-table
  )
fi

if [[ -f "${WORK_DIR}/iso/boot/grub/efi.img" ]]; then
  XORRISO_ARGS+=(
    -eltorito-alt-boot
    -e boot/grub/efi.img
    -no-emul-boot
    -isohybrid-gpt-basdat
  )
fi

XORRISO_ARGS+=("${WORK_DIR}/iso")

xorriso "${XORRISO_ARGS[@]}"

(cd "${OUTPUT_DIR}" && sha256sum "${ISO_NAME}" > "${ISO_NAME}.sha256")
ISO_SIZE="$(du -sh "${OUTPUT_DIR}/${ISO_NAME}" | awk '{print $1}')"

echo "================================================================================"
echo "[✓] Successfully built Axonwall Alpine Appliance ISO!"
echo "    Path : ${OUTPUT_DIR}/${ISO_NAME}"
echo "    Size : ${ISO_SIZE}"
echo "    SHA256: $(cat "${OUTPUT_DIR}/${ISO_NAME}.sha256")"
echo "================================================================================"
