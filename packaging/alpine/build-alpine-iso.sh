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
EDITION="${AXONWALL_EDITION:-axonwall}"
IN_CONTAINER=0

ARGS=("$@")
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="${2:-virt}"
      shift 2
      ;;
    --edition)
      EDITION="${2:-axonwall}"
      shift 2
      ;;
    --edition=*)
      EDITION="${1#*=}"
      shift
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

case "${EDITION}" in
  axonwall|minimal|k3s-storage) ;;
  *)
    echo "[!] Unknown --edition '${EDITION}' (expected axonwall, minimal, or k3s-storage)" >&2
    exit 1
    ;;
esac

# If not running inside Alpine Linux, automatically delegate to alpine:3.21 Docker container
if [[ "$IN_CONTAINER" -eq 0 ]] && [[ ! -f /etc/alpine-release ]]; then
  echo "[+] Host is not Alpine Linux. Launching isolated alpine:3.21 build container..."
  exec docker run --rm \
    -v "${REPO_ROOT}:/repo" \
    -w /repo \
    alpine:3.21 \
    /bin/sh -c 'apk add --no-cache bash >/dev/null && exec /bin/bash /repo/packaging/alpine/build-alpine-iso.sh --in-container "$@"' -- "${ARGS[@]}"
fi

ALPINE_BRANCH="v3.21"
ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_BRANCH}"
WORK_DIR="/tmp/axonwall-alpine-build"
OUTPUT_DIR="${REPO_ROOT}/packaging/alpine/output"
if [[ "${EDITION}" == "k3s-storage" ]]; then
  ISO_NAME="axonwall-k3s-storage-alpine-${PROFILE}-amd64.iso"
elif [[ "${EDITION}" == "minimal" ]]; then
  ISO_NAME="axonwall-minimal-alpine-${PROFILE}-amd64.iso"
elif [[ "$MINIMAL" -eq 1 ]]; then
  ISO_NAME="axonwall-alpine-${PROFILE}-minimal-amd64.iso"
else
  ISO_NAME="axonwall-alpine-${PROFILE}-amd64.iso"
fi

echo "=== Axonwall Alpine Linux ISO Builder (Edition: ${EDITION}, Profile: ${PROFILE}, Minimal: ${MINIMAL}) ==="

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
# ISO flavor name != kernel flavor name: the standard ISO ships the lts
# kernel (vmlinuz-lts / initramfs-lts); only virt matches its kernel
# name. Bootloader entries must use the kernel flavor, or BIOS boot
# fails to find its kernel (the stock efi.img config is untouched, so
# UEFI boot masked this). Verified against the real 3.21.9 standard
# ISO, whose /boot holds vmlinuz-lts, not vmlinuz-standard.
ALPINE_KERNEL_FLAVOR="${ALPINE_FLAVOR}"
if [[ "$ALPINE_FLAVOR" == "standard" ]]; then
  ALPINE_KERNEL_FLAVOR="lts"
fi
ALPINE_ISO_VERSION="${ALPINE_ISO_VERSION:-3.21.8}"
ISO_FILE="alpine-${ALPINE_FLAVOR}-${ALPINE_ISO_VERSION}-x86_64.iso"

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
if [[ "${EDITION}" == "k3s-storage" ]]; then
  # Barebones K3s + OpenZFS + OpenEBS Storage Host package set (no NGFW/UI/LDAP stack)
  CORE_PKGS=(
    alpine-base
    alpine-conf
    openrc
    busybox
    busybox-openrc
    busybox-mdev-openrc
    kmod
    nftables
    nftables-openrc
    iptables
    iproute2
    bridge
    cni-plugins
    ifupdown-ng
    dhcpcd
    wireguard-tools
    conntrack-tools
    ethtool
    tcpdump
    curl
    jq
    openssl
    ca-certificates
    zfs
    "zfs-${ALPINE_KERNEL_FLAVOR}"
    zfs-openrc
    parted
    mdadm
    sgdisk
    e2fsprogs
    btrfs-progs
    dosfstools
    cryptsetup
    rsync
    bash
    syslinux
    efibootmgr
    grub
    grub-bios
    grub-efi
    openssh
    sudo
    shadow
    chrony
    chrony-openrc
  )
elif [[ "${EDITION}" == "minimal" ]]; then
  # Zero-role control plane Minimal edition (control plane + Web UI + local POSIX auth + OpenZFS base)
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
    ifupdown-ng
    dhcpcd
    ethtool
    nodejs
    sqlite
    curl
    jq
    openssl
    ca-certificates
    zfs
    "zfs-${ALPINE_KERNEL_FLAVOR}"
    zfs-openrc
    parted
    mdadm
    sgdisk
    e2fsprogs
    btrfs-progs
    dosfstools
    cryptsetup
    rsync
    bash
    syslinux
    efibootmgr
    grub
    grub-bios
    grub-efi
    openssh
    sudo
    shadow
    chrony
    chrony-openrc
  )
else
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
  conntrack-tools
  ethtool
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
  btrfs-progs
  dosfstools
  cryptsetup
  rsync
  bash
  syslinux
  efibootmgr
  grub
  grub-bios
  grub-efi
  openssh
  sudo
  shadow
  chrony
  chrony-openrc
)

if [[ "$MINIMAL" -eq 0 ]]; then
  CORE_PKGS+=(
    zfs
    "zfs-${ALPINE_KERNEL_FLAVOR}"
    zfs-openrc
    smartmontools
    python3
    less
    binutils
    zstd
    bzip2
    xz
    unzip
  )
fi
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

# Deterministic modes for the state directories created above. Without this
# they inherit the build container's umask: a umask-007 build shipped them
# 0770 root:root, which locked slapd (running as ldap) out of its config
# tree under /var/lib/axonwall and supervise-daemon out of the service log
# directory /var/log/axonwall. Runtime (firstboot / checkpath) re-asserts
# the tighter service modes; the shipped modes only need to guarantee
# traversal until then.
chmod 0755 \
  "${OVL}/var" \
  "${OVL}/var/lib" \
  "${OVL}/var/log" \
  "${OVL}/var/lib/axonwall" \
  "${OVL}/var/lib/axonwall/home" \
  "${OVL}/var/lib/axonwall/ldap" \
  "${OVL}/var/lib/axonwall/ldap/config" \
  "${OVL}/var/lib/axonwall/ldap/data" \
  "${OVL}/var/lib/axonwall/ldap/accesslog" \
  "${OVL}/var/lib/axonwall/ldap/backups" \
  "${OVL}/var/lib/openldap/run" \
  "${OVL}/var/log/axonwall"
chmod 0750 \
  "${OVL}/var/lib/axonwall/secrets" \
  "${OVL}/var/lib/axonwall/secrets/ldap" \
  "${OVL}/var/lib/axonwall/secrets/ha-pki"

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

# Write /etc/hostname & firstboot/edition markers
if [[ "${EDITION}" == "k3s-storage" ]]; then
  echo "axonwall-storage" > "${OVL}/etc/hostname"
  touch "${OVL}/etc/axonwall/.k3s-edition" "${OVL}/etc/axonwall/.k3s-firstboot"
elif [[ "${EDITION}" == "minimal" ]]; then
  echo "axonwall-minimal" > "${OVL}/etc/hostname"
  touch "${OVL}/etc/axonwall/.minimal-edition" "${OVL}/etc/axonwall/.firstboot"
  printf 'disabled=true\n' > "${OVL}/etc/axonwall/workstation.disabled"
  printf '{\n  "core-firewall": true,\n  "core-nas": true,\n  "core-k3s": true,\n  "core-virt": true,\n  "core-vigilante": true,\n  "cli-workstation": true,\n  "host-malware-rootkit": true,\n  "coroot-ebpf-apm": true\n}\n' > "${OVL}/var/lib/axonwall/plugins-disabled.json"
  chmod 0644 "${OVL}/etc/axonwall/workstation.disabled" "${OVL}/var/lib/axonwall/plugins-disabled.json"
else
  echo "axonwall" > "${OVL}/etc/hostname"
  touch "${OVL}/etc/axonwall/.firstboot"
fi
# D-M9 (marker): the canonical edition file for the live installer
# environment. EDITION is validated to axonwall|minimal|k3s-storage above.
printf '%s\n' "${EDITION}" > "${OVL}/etc/axonwall/edition"

printf "%s\n" "${CORE_PKGS[@]}" > "${OVL}/etc/apk/world"

# Copy Alpine overlay files (OpenRC scripts, inittab, shims, installer)
cp -a "${SCRIPT_DIR}/overlay/"* "${OVL}/"
chmod +x "${OVL}/etc/init.d/"* "${OVL}/usr/local/bin/"*

# Alpine's stock sshd is built without PAM, so strip UsePAM from sshd_config.d/axonwall.conf
grep -v '^UsePAM ' "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/ssh/sshd_config.d/axonwall.conf" > "${OVL}/etc/ssh/sshd_config.d/axonwall.conf"
cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/sudoers.d/axonwall" "${OVL}/etc/sudoers.d/axonwall"
chmod 0440 "${OVL}/etc/sudoers.d/axonwall"

if [[ "${EDITION}" == "k3s-storage" ]]; then
  # Strip NGFW-only OpenRC init scripts and stage Barebones K3s + OpenZFS Storage Host configs
  rm -f "${OVL}/etc/init.d/axonwalld" \
        "${OVL}/etc/init.d/axonwall-controller" \
        "${OVL}/etc/init.d/axonwall-ui" \
        "${OVL}/etc/init.d/headscale"
  rmdir "${OVL}/etc/headscale" 2>/dev/null || true
  rm -rf "${OVL}/opt/axonwall"

  mkdir -p "${OVL}/etc/modules-load.d" "${OVL}/usr/share/axonwall/k3s"
  cp "${REPO_ROOT}/packaging/k3s-storage/nftables.conf" "${OVL}/etc/nftables.conf"
  cp "${REPO_ROOT}/packaging/k3s-storage/90-k3s-storage.conf" "${OVL}/etc/sysctl.d/90-k3s-storage.conf"
  cp "${REPO_ROOT}/packaging/k3s-storage/k3s-storage.modules.conf" "${OVL}/etc/modules-load.d/k3s-storage.conf"
  cp "${REPO_ROOT}/packaging/k3s-storage/zfs-operator.yaml" "${OVL}/usr/share/axonwall/k3s/zfs-operator.yaml"
  for _kmod in zfs overlay br_netfilter wireguard nf_conntrack; do
    grep -qxF "$_kmod" "${OVL}/etc/modules" 2>/dev/null || echo "$_kmod" >> "${OVL}/etc/modules"
  done
  for _kbin in axonwall-k3s-firstboot axonwall-k3s-verify axonwall-k3s-status; do
    cp "${REPO_ROOT}/packaging/k3s-storage/${_kbin}" "${OVL}/usr/local/bin/${_kbin}"
    chmod 0755 "${OVL}/usr/local/bin/${_kbin}"
  done
  cat << 'ZSH_SHIM_EOF' > "${OVL}/usr/bin/zsh"
#!/bin/sh
if [ -x /bin/bash ]; then
  exec /bin/bash "$@"
fi
exec /bin/ash "$@"
ZSH_SHIM_EOF
  chmod 0755 "${OVL}/usr/bin/zsh"
elif [[ "${EDITION}" == "minimal" ]]; then
  # Reduced attack surface: strip headscale and k3s-storage payload; keep core control plane + Web UI + OpenLDAP
  rm -f "${OVL}/etc/init.d/headscale" "${OVL}/etc/init.d/k3s" "${OVL}/etc/init.d/k3s-agent" \
        "${OVL}/etc/init.d/axonwall-k3s-verify"
  rmdir "${OVL}/etc/headscale" 2>/dev/null || true
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/sysctl.d/99-axonwall.conf" "${OVL}/etc/sysctl.d/"
  cp "${REPO_ROOT}/packaging/debian/lockdown.nft" "${OVL}/usr/share/axonwall/lockdown.nft"
  if [[ -d "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/axonwall/nvim" ]]; then
    mkdir -p "${OVL}/etc/axonwall/nvim"
    cp -a "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/axonwall/nvim/." "${OVL}/etc/axonwall/nvim/"
  fi
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwallctl" "${OVL}/usr/local/bin/"
  if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-tui" ]]; then
    cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-tui" "${OVL}/usr/local/bin/"
  fi
else
  # Copy shared scripts and configs from Debian/ISO packaging
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/sysctl.d/99-axonwall.conf" "${OVL}/etc/sysctl.d/"
  cp "${REPO_ROOT}/packaging/debian/headscale-config.yaml" "${OVL}/etc/headscale/config.yaml"
  cp "${REPO_ROOT}/packaging/debian/lockdown.nft" "${OVL}/usr/share/axonwall/lockdown.nft"

  # Stage k3s-storage configs & OpenEBS manifest so unified Alpine installs can also deploy k3s-storage
  mkdir -p "${OVL}/usr/share/axonwall/k3s-storage" "${OVL}/usr/share/axonwall/k3s"
  cp "${REPO_ROOT}/packaging/k3s-storage/nftables.conf" \
     "${REPO_ROOT}/packaging/k3s-storage/90-k3s-storage.conf" \
     "${REPO_ROOT}/packaging/k3s-storage/k3s-storage.modules.conf" \
     "${REPO_ROOT}/packaging/k3s-storage/zfs-operator.yaml" \
     "${REPO_ROOT}/packaging/k3s-storage/axonwall-k3s-firstboot" \
     "${REPO_ROOT}/packaging/k3s-storage/axonwall-k3s-verify" \
     "${REPO_ROOT}/packaging/k3s-storage/axonwall-k3s-status" \
     "${OVL}/usr/share/axonwall/k3s-storage/"
  chmod 0755 "${OVL}/usr/share/axonwall/k3s-storage/axonwall-k3s-firstboot" \
             "${OVL}/usr/share/axonwall/k3s-storage/axonwall-k3s-verify" \
             "${OVL}/usr/share/axonwall/k3s-storage/axonwall-k3s-status"
  cp "${REPO_ROOT}/packaging/k3s-storage/zfs-operator.yaml" "${OVL}/usr/share/axonwall/k3s/zfs-operator.yaml"

  if [[ "$MINIMAL" -eq 0 ]]; then
    mkdir -p "${OVL}/etc/zsh" "${OVL}/etc/skel" "${OVL}/etc/vim" "${OVL}/usr/share/oh-my-zsh"
    cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/axonwall/starship.toml" "${OVL}/etc/axonwall/starship.toml"
    cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zsh/axonwall.zsh" "${OVL}/etc/zsh/axonwall.zsh"
    cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zsh/zshenv" "${OVL}/etc/zsh/zshenv"
    cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/skel/.zshrc" "${OVL}/etc/skel/.zshrc"
    cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/skel/.zshrc" "${OVL}/root/.zshrc"
    cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/vim/vimrc.local" "${OVL}/etc/vim/vimrc.local"
    cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/tmux.conf" "${OVL}/etc/tmux.conf"
    if [[ -d "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/share/oh-my-zsh" ]]; then
      cp -a "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/share/oh-my-zsh/." "${OVL}/usr/share/oh-my-zsh/"
    fi
    if [[ -d "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/axonwall/nvim" ]]; then
      mkdir -p "${OVL}/etc/axonwall/nvim"
      cp -a "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/axonwall/nvim/." "${OVL}/etc/axonwall/nvim/"
    fi
  else
    # On minimal-package Alpine (no zsh installed), provide a real wrapper script
    # (never a symlink to /bin/ash -> busybox, which rejects argv[0]=zsh with
    # "zsh: applet not found") so SSO users with loginShell=/usr/bin/zsh work.
    cat << 'ZSH_SHIM_EOF' > "${OVL}/usr/bin/zsh"
#!/bin/sh
if [ -x /bin/bash ]; then
  exec /bin/bash "$@"
fi
exec /bin/ash "$@"
ZSH_SHIM_EOF
    chmod 0755 "${OVL}/usr/bin/zsh"
  fi

  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-ha-notify" "${OVL}/usr/local/bin/"
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-import" "${OVL}/usr/local/bin/"
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwallctl" "${OVL}/usr/local/bin/"
  if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-tui" ]]; then
    cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-tui" "${OVL}/usr/local/bin/"
  fi
fi

cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-update" "${OVL}/usr/local/bin/"
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-btrfs-grub" ]]; then
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-btrfs-grub" "${OVL}/usr/local/bin/"
  chmod 0755 "${OVL}/usr/local/bin/axonwall-btrfs-grub"
fi
# E-M3 (round-3): ship the release-signing trust anchor so an Alpine
# box's first .deb update verifies the detached signature instead of
# falling back to SHA-256 + TLS only. Debian installs get the anchor
# from the ISO chroot and .deb-maintained systems from the package;
# Alpine got neither, so the signature the release workflow produces
# was never checked on the update most likely to carry a waited-for
# fix. Mirror the keyring directory too (E-M2).
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/axonwall/release-signing.pub" ]]; then
  mkdir -p "${OVL}/etc/axonwall"
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/axonwall/release-signing.pub" "${OVL}/etc/axonwall/release-signing.pub"
  chmod 644 "${OVL}/etc/axonwall/release-signing.pub"
fi
if [[ -d "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/axonwall/release-signing.d" ]]; then
  mkdir -p "${OVL}/etc/axonwall/release-signing.d"
  for _keyring_pub in "${REPO_ROOT}"/packaging/iso/config/includes.chroot/etc/axonwall/release-signing.d/*.pub; do
    [[ -f "$_keyring_pub" ]] || continue
    cp "$_keyring_pub" "${OVL}/etc/axonwall/release-signing.d/"
    chmod 644 "${OVL}/etc/axonwall/release-signing.d/$(basename "$_keyring_pub")"
  done
fi
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-config" ]]; then
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-config" "${OVL}/usr/local/bin/"
fi
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-opshell" ]]; then
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-opshell" "${OVL}/usr/local/bin/"
fi
chmod +x "${OVL}/usr/local/bin/axonwall"*

# Version stamp
VERSION="$(cat "${REPO_ROOT}/VERSION" 2>/dev/null | tr -d '[:space:]' || true)"
if [ -z "$VERSION" ]; then
  VERSION="$(grep -m1 '"version"' "${REPO_ROOT}/package.json" 2>/dev/null | sed -E 's/.*"version": *"([^"]+)".*/\1/' || true)"
fi
if [ -z "$VERSION" ]; then
  echo "[-] ERROR: cannot determine release version (VERSION file and package.json both missing or unreadable); refusing to stamp a hardcoded fallback version." >&2
  exit 1
fi
echo "${VERSION}" > "${OVL}/etc/axonwall/version"

# Copy compiled Go daemons (axonwalld, axonwall-console, axonwall-satellite)
# Core payloads are fail-closed, mirroring the console-binary guard in
# build-iso.sh: an image built without its daemon, UI, or controller
# boots "successfully" and is only discovered broken at service start.
if [[ "${EDITION}" == "axonwall" || "${EDITION}" == "minimal" ]]; then
  if [[ -f "${REPO_ROOT}/apps/axonwalld/bin/axonwalld" ]]; then
    cp "${REPO_ROOT}/apps/axonwalld/bin/axonwalld" "${OVL}/usr/sbin/axonwalld"
    strip "${OVL}/usr/sbin/axonwalld" 2>/dev/null || true
    chmod +x "${OVL}/usr/sbin/axonwalld"
  else
    echo "[!] ERROR: apps/axonwalld/bin/axonwalld is missing; cannot build Alpine ISO without the daemon." >&2
    exit 1
  fi
fi

if [[ -f "${REPO_ROOT}/apps/axonwall-console/bin/axonwall-console" ]]; then
  cp "${REPO_ROOT}/apps/axonwall-console/bin/axonwall-console" "${OVL}/usr/sbin/axonwall-console"
  strip "${OVL}/usr/sbin/axonwall-console" 2>/dev/null || true
  chmod +x "${OVL}/usr/sbin/axonwall-console"
else
  echo "[!] ERROR: apps/axonwall-console/bin/axonwall-console is missing; cannot build Alpine ISO without the console TUI." >&2
  exit 1
fi

if [[ "${EDITION}" != "minimal" ]] && [[ -f "${REPO_ROOT}/apps/axonwall-satellite/bin/axonwall-satellite-amd64" ]]; then
  cp "${REPO_ROOT}/apps/axonwall-satellite/bin/axonwall-satellite-amd64" "${OVL}/usr/sbin/axonwall-satellite"
  strip "${OVL}/usr/sbin/axonwall-satellite" 2>/dev/null || true
  chmod +x "${OVL}/usr/sbin/axonwall-satellite"
  if [[ "${EDITION}" == "axonwall" ]]; then
    ln -sf /usr/sbin/axonwall-satellite "${OVL}/usr/share/axonwall/satellites/axonwall-satellite-amd64"
  else
    rmdir "${OVL}/usr/share/axonwall/satellites" 2>/dev/null || true
  fi
elif [[ "${EDITION}" == "axonwall" ]]; then
  echo "[!] ERROR: apps/axonwall-satellite/bin/axonwall-satellite-amd64 is missing; cannot build Alpine ISO without the satellite binary." >&2
  exit 1
else
  rmdir "${OVL}/usr/share/axonwall/satellites" 2>/dev/null || true
fi

# write_core_k3s_bundled_json writes the bundled.json verification
# record next to the pre-staged plugin binaries, in exactly the
# format axonwalld's installBundledBinaries writes (relative path +
# sha256 of the bytes on disk + manifest entry + kind), so the
# daemon's verifyBundledBinaries passes on the staged tree without
# a re-download. $1 = plugin dir. It records whichever of bin/k3s
# and bin/k9s are staged and executable, and fails the build when
# neither is — a plugin dir with no binaries must never ship a
# record blessing an empty tree. Defined here, outside the
# edition branches, because the k9s block below calls it for both
# editions. Note the axonwall edition stages k9s only (k3s is
# k3s-storage-only here, as before this move), so its record lists
# just bin/k9s and the daemon downloads k3s on first core-k3s
# install/reconfigure.
write_core_k3s_bundled_json() {
  local _dir="$1"
  local _k3s_src_sum="${2:-${K3S_SHA256:-}}"
  local _k9s_src_sum="${3:-${K9S_SHA256:-}}"
  local _k3s_sum="" _k9s_sum="" _n=0
  if [[ -x "${_dir}/bin/k3s" ]]; then
    _k3s_sum="$(sha256sum "${_dir}/bin/k3s" | awk '{print $1}')"
    _k3s_src_sum="${_k3s_src_sum:-${_k3s_sum}}"
    _n=$((_n + 1))
  fi
  if [[ -x "${_dir}/bin/k9s" ]]; then
    _k9s_sum="$(sha256sum "${_dir}/bin/k9s" | awk '{print $1}')"
    if [[ -z "${_k9s_src_sum}" ]]; then
      echo "[!] ERROR: core-k3s plugin dir ${_dir} stages bin/k9s without pinned archive checksum K9S_SHA256." >&2
      return 1
    fi
    _n=$((_n + 1))
  fi
  if [[ "${_n}" -eq 0 ]]; then
    echo "[!] ERROR: core-k3s plugin dir ${_dir} has no staged binaries; cannot write bundled.json." >&2
    return 1
  fi
  {
    printf '{\n  "pluginId": "core-k3s",\n  "sources": {\n'
    if [[ -n "${_k3s_sum}" ]]; then
      printf '    "k3s": "%s"' "${_k3s_src_sum}"
      if [[ -n "${_k9s_sum}" ]]; then printf ',\n'; fi
    fi
    if [[ -n "${_k9s_sum}" ]]; then
      printf '    "k9s": "%s"' "${_k9s_src_sum}"
    fi
    printf '\n  },\n  "files": [\n'
    if [[ -n "${_k3s_sum}" ]]; then
      printf '    {\n      "path": "bin/k3s",\n      "sha256": "%s",\n      "entry": "k3s",\n      "kind": "binary"\n    }' "${_k3s_sum}"
      if [[ -n "${_k9s_sum}" ]]; then printf ',\n'; fi
    fi
    if [[ -n "${_k9s_sum}" ]]; then
      printf '    {\n      "path": "bin/k9s",\n      "sha256": "%s",\n      "entry": "k9s",\n      "kind": "archive"\n    }' "${_k9s_sum}"
    fi
    printf '\n  ]\n}\n'
  } > "${_dir}/bundled.json"
  chmod 0644 "${_dir}/bundled.json"
}

if [[ "${EDITION}" == "k3s-storage" ]]; then
  K3S_VERSION="${K3S_VERSION:-v1.32.3+k3s1}"
  K3S_URL_VERSION="${K3S_VERSION//+/%2B}"
  case "${K3S_VERSION}" in
    v1.31.5+k3s1) K3S_SHA256="${K3S_SHA256:-399b87b432ce55013fa81adad572a8e4ecf56e0df97369cf02d4b8a41f039091}" ;;
    v1.32.3+k3s1) K3S_SHA256="${K3S_SHA256:-b19216803650b567bf980888dec39035edaf664339c55bc4462f7a003edbef83}" ;;
    *) K3S_SHA256="${K3S_SHA256:-}" ;;
  esac
  echo "[+] Fetching K3s ${K3S_VERSION} for Alpine k3s-storage overlay..."
  mkdir -p "${OVL}/var/lib/axonwall/core-k3s/bin"
  curl -fsSL -o "${OVL}/var/lib/axonwall/core-k3s/bin/k3s" "https://github.com/k3s-io/k3s/releases/download/${K3S_URL_VERSION}/k3s"
  if [[ -z "${K3S_SHA256}" ]]; then
    K3S_SHA256="$(curl -fsSL "https://github.com/k3s-io/k3s/releases/download/${K3S_URL_VERSION}/sha256sum-amd64.txt" | awk '$2 == "k3s" {print $1; exit}')"
  fi
  if [[ -z "${K3S_SHA256}" ]]; then
    echo "[!] ERROR: Unable to determine SHA-256 checksum for K3s ${K3S_VERSION}" >&2
    exit 1
  fi
  echo "${K3S_SHA256}  ${OVL}/var/lib/axonwall/core-k3s/bin/k3s" | sha256sum -c -
  chmod 0755 "${OVL}/var/lib/axonwall/core-k3s/bin/k3s"
  # k3s multicall symlinks in the plugin bin dir (kubectl, crictl,
  # ctr -> k3s). The daemon recreates them on core-k3s reconfigure
  # if they are ever deleted; nothing is linked into /usr/local/bin.
  ln -sf k3s "${OVL}/var/lib/axonwall/core-k3s/bin/kubectl"
  ln -sf k3s "${OVL}/var/lib/axonwall/core-k3s/bin/crictl"
  ln -sf k3s "${OVL}/var/lib/axonwall/core-k3s/bin/ctr"
elif [[ "${EDITION}" == "axonwall" ]]; then
  HEADSCALE_VERSION="0.29.4"
  HEADSCALE_SHA256="212ed0a884c0d3541e094c4bebbe94397df6f4e01bd3d7f059c520cb55e0d757"
  if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/sbin/headscale" ]]; then
    cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/sbin/headscale" "${OVL}/usr/sbin/headscale"
    strip "${OVL}/usr/sbin/headscale" 2>/dev/null || true
    # headscale serves as the dedicated axonwall-headscale user, so the
    # binary must be world-executable: chmod +x alone preserves whatever
    # mode the source file had (0750 under a restrictive build umask),
    # which supervise-daemon then cannot exec as that user.
    chmod 0755 "${OVL}/usr/sbin/headscale"
  elif [[ ! -f "${OVL}/usr/sbin/headscale" ]]; then
    echo "[+] Fetching Headscale v${HEADSCALE_VERSION} for Alpine overlay..."
    curl -fsSL -o "${OVL}/usr/sbin/headscale" "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}/headscale_${HEADSCALE_VERSION}_linux_amd64"
    echo "${HEADSCALE_SHA256}  ${OVL}/usr/sbin/headscale" | sha256sum -c -
    strip "${OVL}/usr/sbin/headscale" 2>/dev/null || true
    chmod 0755 "${OVL}/usr/sbin/headscale"
  fi
fi

# Bundle statically-linked K9s v0.51.0 binary in k3s-storage Alpine edition
# Staged into the core-k3s plugin dir; standard axonwall downloads k3s/k9s on demand when core-k3s is activated.
if [[ "${EDITION}" == "k3s-storage" ]]; then
  K9S_VERSION="0.51.0"
  K9S_SHA256="c3752ad51a5a4015a113819c4eeb6e55a4d0e4b8e652494797532f6fc8161dd7"
  mkdir -p "${OVL}/var/lib/axonwall/core-k3s/bin"
  echo "[+] Fetching K9s v${K9S_VERSION} for Alpine overlay..."
  K9S_TAR="$(mktemp -t k9s-XXXXXX)"
  curl -fsSL -o "${K9S_TAR}" "https://github.com/derailed/k9s/releases/download/v${K9S_VERSION}/k9s_Linux_amd64.tar.gz"
  echo "${K9S_SHA256}  ${K9S_TAR}" | sha256sum -c -
  tar -xzf "${K9S_TAR}" -C "${OVL}/var/lib/axonwall/core-k3s/bin/" k9s
  chmod 0755 "${OVL}/var/lib/axonwall/core-k3s/bin/k9s"
  rm -f "${K9S_TAR}"
  # Verification record for the staged tree (see the helper above;
  # on the axonwall edition this lists bin/k9s only — k3s is not
  # staged there and the daemon downloads it on first core-k3s
  # install/reconfigure).
  write_core_k3s_bundled_json "${OVL}/var/lib/axonwall/core-k3s" "${K3S_SHA256:-}" "${K9S_SHA256:-}"
fi

# Fetch ZFSBootMenu v3.1.0 Unified Kernel Image (UKI) for Root-on-ZFS installations
ZBM_VERSION="3.1.0"
ZBM_KVER="linux6.12"
ZBM_SHA256="131d55c7b385df8cd319d267b6aa15d97f8c32c94f5149bd906556715fadf4e7"
ZBM_CACHE="${REPO_ROOT}/packaging/iso/build/cache/zfsbootmenu-release-x86_64-v${ZBM_VERSION}-${ZBM_KVER}.EFI"
mkdir -p "${OVL}/usr/lib/zfsbootmenu" "${OVL}/usr/lib/axonwall" "${OVL}/etc/zfsbootmenu/hooks/early-setup.d" "${OVL}/etc/zfsbootmenu/hooks/setup.d" "${OVL}/etc/zfsbootmenu/dracut.conf.d"
RAW_ZBM="/tmp/zbm-raw-${ZBM_VERSION}.efi"
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/lib/zfsbootmenu/vmlinuz.efi" ]]; then
  cp -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/lib/zfsbootmenu/vmlinuz.efi" "${OVL}/usr/lib/zfsbootmenu/vmlinuz.efi"
elif [[ -f "${ZBM_CACHE}" ]]; then
  echo "${ZBM_SHA256}  ${ZBM_CACHE}" | sha256sum -c -
  cp -f "${ZBM_CACHE}" "$RAW_ZBM"
else
  echo "[+] Fetching ZFSBootMenu v${ZBM_VERSION} (${ZBM_KVER}) UKI for Alpine overlay..."
  curl -fsSL -o "$RAW_ZBM" "https://github.com/zbm-dev/zfsbootmenu/releases/download/v${ZBM_VERSION}/zfsbootmenu-release-x86_64-v${ZBM_VERSION}-${ZBM_KVER}.EFI"
  echo "${ZBM_SHA256}  $RAW_ZBM" | sha256sum -c -
fi

if [[ ! -f "${OVL}/usr/lib/zfsbootmenu/vmlinuz.efi" && -f "$RAW_ZBM" ]]; then
  if command -v python3 &>/dev/null && command -v objcopy &>/dev/null && [[ -f "${REPO_ROOT}/packaging/iso/branding/theme-zbm-uki.py" && -f "${REPO_ROOT}/packaging/iso/branding/splash.bmp" ]]; then
    echo "[+] Theming ZFSBootMenu UKI for Alpine overlay..."
    python3 "${REPO_ROOT}/packaging/iso/branding/theme-zbm-uki.py" \
      "$RAW_ZBM" \
      -o "${OVL}/usr/lib/zfsbootmenu/vmlinuz.efi" \
      -s "${REPO_ROOT}/packaging/iso/branding/splash.bmp" \
      --hooks-dir "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zfsbootmenu/hooks"
  else
    cp -f "$RAW_ZBM" "${OVL}/usr/lib/zfsbootmenu/vmlinuz.efi"
  fi
  rm -f "$RAW_ZBM"
fi
chmod 0644 "${OVL}/usr/lib/zfsbootmenu/vmlinuz.efi"

if [[ -f "${REPO_ROOT}/packaging/iso/branding/theme-zbm-uki.py" ]]; then
  cp -f "${REPO_ROOT}/packaging/iso/branding/theme-zbm-uki.py" "${OVL}/usr/lib/axonwall/theme-zbm-uki.py"
  chmod +x "${OVL}/usr/lib/axonwall/theme-zbm-uki.py"
fi
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-zbm-theme" ]]; then
  cp -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-zbm-theme" "${OVL}/usr/local/bin/axonwall-zbm-theme"
  chmod +x "${OVL}/usr/local/bin/axonwall-zbm-theme"
  ln -sf axonwall-zbm-theme "${OVL}/usr/local/bin/generate-zbm"
  ln -sf axonwall-zbm-theme "${OVL}/usr/local/bin/zbm-kcl"
fi
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zfsbootmenu/splash.bmp" ]]; then
  cp -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zfsbootmenu/splash.bmp" "${OVL}/etc/zfsbootmenu/splash.bmp"
fi
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zfsbootmenu/config.yaml" ]]; then
  cp -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zfsbootmenu/config.yaml" "${OVL}/etc/zfsbootmenu/config.yaml"
fi
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zfsbootmenu/dracut.conf.d/colors.conf" ]]; then
  cp -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zfsbootmenu/dracut.conf.d/colors.conf" "${OVL}/etc/zfsbootmenu/dracut.conf.d/colors.conf"
fi
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zfsbootmenu/hooks/early-setup.d/15-axonwall-theme.sh" ]]; then
  cp -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zfsbootmenu/hooks/early-setup.d/15-axonwall-theme.sh" "${OVL}/etc/zfsbootmenu/hooks/early-setup.d/15-axonwall-theme.sh"
  cp -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zfsbootmenu/hooks/early-setup.d/15-axonwall-theme.sh" "${OVL}/etc/zfsbootmenu/hooks/early-setup.d/90-axonwall-theme.sh"
  chmod 0755 "${OVL}/etc/zfsbootmenu/hooks/early-setup.d/15-axonwall-theme.sh" "${OVL}/etc/zfsbootmenu/hooks/early-setup.d/90-axonwall-theme.sh"
fi
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zfsbootmenu/hooks/setup.d/20-axonwall-watchdog.sh" ]]; then
  cp -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/etc/zfsbootmenu/hooks/setup.d/20-axonwall-watchdog.sh" "${OVL}/etc/zfsbootmenu/hooks/setup.d/20-axonwall-watchdog.sh"
  chmod 0755 "${OVL}/etc/zfsbootmenu/hooks/setup.d/20-axonwall-watchdog.sh"
fi

# Copy Next.js standalone UI & Controller (axonwall & minimal editions)
if [[ "${EDITION}" == "axonwall" || "${EDITION}" == "minimal" ]]; then
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
    # startup (via dist/server/patch-error-inspect.js), and in Next.js 16
    # shared.js requires dist/shared/lib/errors/code-frame.js (moved from
    # dist/compiled/babel/code-frame.js in Next 15). Fail the build if any of
    # these runtime files are missing from the payload.
    for next_dir in "${OVL}/opt/axonwall/node_modules/.pnpm/"next*/node_modules/next; do
      for req in dist/next-devtools/server/shared.js dist/server/patch-error-inspect.js dist/shared/lib/errors/code-frame.js; do
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
  else
    echo "[!] ERROR: apps/axonwall/.next/standalone is missing (run the Next.js production build first); cannot build Alpine ISO without the web console." >&2
    exit 1
  fi

  if [[ -f "${REPO_ROOT}/apps/axonwall-controller/dist/index.js" ]]; then
    cp "${REPO_ROOT}/apps/axonwall-controller/dist/index.js" "${OVL}/opt/axonwall/apps/axonwall-controller/dist/"
    cp "${REPO_ROOT}/apps/axonwall-controller/package.json" "${OVL}/opt/axonwall/apps/axonwall-controller/"
  else
    echo "[!] ERROR: apps/axonwall-controller/dist/index.js is missing (run the controller build first); cannot build Alpine ISO without the controller." >&2
    exit 1
  fi
  if [[ -f "${REPO_ROOT}/apps/axonwall-controller/dist/axonwallctl.js" ]]; then
    cp "${REPO_ROOT}/apps/axonwall-controller/dist/axonwallctl.js" "${OVL}/opt/axonwall/apps/axonwall-controller/dist/"
  fi
  if [[ -f "${REPO_ROOT}/apps/axonwall-controller/dist/axonwall-tui.js" ]]; then
    cp "${REPO_ROOT}/apps/axonwall-controller/dist/axonwall-tui.js" "${OVL}/opt/axonwall/apps/axonwall-controller/dist/"
  fi
fi

# Configure OpenRC runlevel symlinks
# modloop is required on this diskless image: it mounts the modloop squashfs
# and links /lib/modules into the live system. Stock Alpine adds it via the
# initramfs default runlevel set, but a hand-pinned apkovl like this one
# suppresses those defaults. Without it no kernel module can load after the
# initramfs stage -- notably af_packet, so every DHCPv4 client (dhcpcd and
# udhcpc alike) fails with "socket(AF_PACKET): Address family not supported
# by protocol" and the live system never gets an IPv4 lease.
if [[ "${EDITION}" == "k3s-storage" ]]; then
  for svc in devfs dmesg mdev hwdrivers modloop cgroups; do
    ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/sysinit/${svc}"
  done
  for svc in axonwall-network-setup modules sysctl hostname bootmisc syslog networking zfs-import zfs-mount; do
    ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/boot/${svc}"
  done
  for svc in chronyd crond sshd nftables axonwall-firstboot k3s k3s-agent axonwall-k3s-verify local; do
    ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/default/${svc}"
  done
elif [[ "${EDITION}" == "minimal" ]]; then
  for svc in devfs dmesg mdev hwdrivers modloop; do
    ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/sysinit/${svc}"
  done
  for svc in axonwall-network-setup modules sysctl hostname bootmisc syslog networking zfs-import zfs-mount; do
    ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/boot/${svc}"
  done
  for svc in chronyd crond sshd axonwall-firstboot axonwalld axonwall-controller axonwall-ui local; do
    ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/default/${svc}"
  done
else
  for svc in devfs dmesg mdev hwdrivers modloop; do
    ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/sysinit/${svc}"
  done
  for svc in axonwall-network-setup modules sysctl hostname bootmisc syslog networking; do
    ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/boot/${svc}"
  done
  for svc in chronyd crond sshd axonwall-firstboot axonwalld axonwall-controller axonwall-ui local; do
    ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/default/${svc}"
  done
fi
for svc in mount-ro killprocs savecache; do
  ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/shutdown/${svc}"
done

# Normalize directory modes across the assembled overlay before packing:
# every directory must stay traversable by the unprivileged service users
# (ldap, the axonwall-api group members, ...). Payload copied with cp -a
# otherwise carries whatever modes the build host produced, which is how
# /var, /var/lib and /usr/lib shipped as 0770 in the v0.11.13 build.
# /root and the secrets tree keep their restrictive modes and are
# re-asserted explicitly after the sweep.
find "${OVL}" -type d \
  ! -path "${OVL}/root" ! -path "${OVL}/root/*" \
  ! -path "${OVL}/var/lib/axonwall/secrets" ! -path "${OVL}/var/lib/axonwall/secrets/*" \
  -exec chmod a+rx {} +
chmod 0700 "${OVL}/root"
chmod 0750 \
  "${OVL}/var/lib/axonwall/secrets" \
  "${OVL}/var/lib/axonwall/secrets/ldap" \
  "${OVL}/var/lib/axonwall/secrets/ha-pki"

# Stage branded splash artwork into overlay before packing apkovl
if [[ -f "${REPO_ROOT}/packaging/iso/branding/splash.png" ]]; then
  mkdir -p "${OVL}/etc/axonwall/branding"
  cp "${REPO_ROOT}/packaging/iso/branding/splash.png" "${OVL}/etc/axonwall/branding/splash.png"
fi

# Pack axonwall.apkovl.tar.gz into ISO root with maximum compression
(cd "${OVL}" && tar -cf - . | gzip -9 > "${WORK_DIR}/iso/axonwall.apkovl.tar.gz")

# 5. Update bootloader configs (SYSLINUX & GRUB EFI) with Axonwall branding, Next-Gen TUI Installer & Live modes
STORAGE_MODULES="loop,squashfs,sd-mod,usb-storage,sr_mod,cdrom,isofs,virtio_blk,virtio_scsi,virtio_pci,nvme,ata_piix,ahci"

if [[ "${EDITION}" == "k3s-storage" ]]; then
  BOOT_MENU_TITLE="Axonwall K3s + OpenZFS Storage Host Boot Menu (Alpine Linux)"
  BOOT_INSTALL_LABEL="^Install Axonwall K3s + ZFS Storage Host — TUI Installer (Recommended)"
  BOOT_GRUB_INSTALL_LABEL="Install Axonwall K3s + ZFS Storage Host — TUI Installer (Recommended)"
  BOOT_LIVE_LABEL="^Live Storage Host Mode (Evaluate K3s + OpenZFS)"
  BOOT_GRUB_LIVE_LABEL="Axonwall K3s Storage Host Live Mode"
  EDITION_KARG="axonwall.edition=k3s-storage "
  ISO_VOL_ID="AXONWALL_K3S_ALP"
  ISO_APP_ID="Axonwall Alpine K3s + ZFS Storage Host"
elif [[ "${EDITION}" == "minimal" ]]; then
  BOOT_MENU_TITLE="Axonwall Minimal Edition Boot Menu (Alpine Linux)"
  BOOT_INSTALL_LABEL="^Install Axonwall Minimal Edition (Reduced Attack Surface)"
  BOOT_GRUB_INSTALL_LABEL="Install Axonwall Minimal Edition (Reduced Attack Surface)"
  BOOT_LIVE_LABEL="^Live Minimal Mode (Web UI on 192.168.1.1:2966)"
  BOOT_GRUB_LIVE_LABEL="Axonwall Minimal Live Mode (Reduced Attack Surface)"
  EDITION_KARG="axonwall.edition=minimal "
  ISO_VOL_ID="AXONWALL_MIN_ALP"
  ISO_APP_ID="Axonwall Alpine Minimal Appliance (Reduced Attack Surface)"
else
  BOOT_MENU_TITLE="Axonwall Next-Gen Appliance Boot Menu (Alpine Linux)"
  BOOT_INSTALL_LABEL="^Install Axonwall OS — Next-Gen Branded TUI Installer (Recommended)"
  BOOT_GRUB_INSTALL_LABEL="Install Axonwall OS — Next-Gen Branded TUI Installer (Recommended)"
  BOOT_LIVE_LABEL="^Live Appliance Mode (Evaluate & Web UI on 192.168.1.1:2966)"
  BOOT_GRUB_LIVE_LABEL="Axonwall Live Appliance Mode (Evaluate & Web UI)"
  EDITION_KARG=""
  ISO_VOL_ID="AXONWALL_ALPINE"
  ISO_APP_ID="Axonwall Alpine Firewall & Router Appliance"
fi

mkdir -p "${WORK_DIR}/iso/boot/syslinux" "${WORK_DIR}/iso/boot/grub/themes/axonwall"
if [[ -f "${REPO_ROOT}/packaging/iso/branding/splash.png" ]]; then
  cp "${REPO_ROOT}/packaging/iso/branding/splash.png" "${WORK_DIR}/iso/boot/syslinux/splash.png"
  cp "${REPO_ROOT}/packaging/iso/branding/splash.png" "${WORK_DIR}/iso/boot/grub/splash.png"
  cp "${REPO_ROOT}/packaging/iso/branding/splash.png" "${WORK_DIR}/iso/boot/grub/themes/axonwall/splash.png"
fi
if [[ -f "${REPO_ROOT}/packaging/iso/config/bootloaders/grub-pc/live-theme/theme.txt" ]]; then
  cp "${REPO_ROOT}/packaging/iso/config/bootloaders/grub-pc/live-theme/theme.txt" "${WORK_DIR}/iso/boot/grub/themes/axonwall/theme.txt"
fi

# Fail closed if the mapped kernel/initramfs are not in the extracted
# base ISO (e.g. Alpine renames a kernel flavor): a bootloader entry
# pointing at a missing file is a BIOS-boot brick, not a warning.
for _boot_file in "vmlinuz-${ALPINE_KERNEL_FLAVOR}" "initramfs-${ALPINE_KERNEL_FLAVOR}"; do
  if [[ ! -f "${WORK_DIR}/iso/boot/${_boot_file}" ]]; then
    echo "[!] ERROR: base ISO '${ISO_FILE}' has no /boot/${_boot_file}; refusing to write bootloader entries that point at a missing kernel." >&2
    exit 1
  fi
done

cat << SYSLINUX_EOF > "${WORK_DIR}/iso/boot/syslinux/syslinux.cfg"
SERIAL 0 9600
UI vesamenu.c32
TIMEOUT 50
PROMPT 0
DEFAULT install

MENU BACKGROUND splash.png
MENU TITLE ${BOOT_MENU_TITLE}
MENU COLOR screen       37;40      #80ffffff #00000000 std
MENU COLOR border       30;44      #4010b981 #00000000 std
MENU COLOR title        1;36;44    #ff34d399 #00000000 std
MENU COLOR sel          7;37;40    #ff06101e #ff10b981 all
MENU COLOR unsel        37;44      #ffe2e8f0 #00000000 std

LABEL install
  MENU LABEL ${BOOT_INSTALL_LABEL}
  MENU DEFAULT
  KERNEL /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR}
  INITRD /boot/initramfs-${ALPINE_KERNEL_FLAVOR}
  APPEND modules=${STORAGE_MODULES} ${EDITION_KARG}axonwall_install=1 quiet console=tty0 console=ttyS0,9600
SYSLINUX_EOF

if [[ "${EDITION}" == "axonwall" ]]; then
  cat << 'SYSLINUX_MINIMAL_EOF' >> "${WORK_DIR}/iso/boot/syslinux/syslinux.cfg"

LABEL install-minimal
  MENU LABEL Install Axonwall ^Minimal Edition (Reduced Attack Surface)
  KERNEL /boot/vmlinuz-virt
  INITRD /boot/initramfs-virt
  APPEND modules=loop,squashfs,sd-mod,usb-storage,sr_mod,cdrom,isofs,virtio_blk,virtio_scsi,virtio_pci,nvme,ata_piix,ahci axonwall_edition=minimal axonwall_install=1 quiet console=tty0 console=ttyS0,9600
SYSLINUX_MINIMAL_EOF
  if [[ -x "${OVL}/usr/share/axonwall/vault/weed" || -x "${OVL}/usr/sbin/weed" ]]; then
    cat << 'SYSLINUX_VAULT_EOF' >> "${WORK_DIR}/iso/boot/syslinux/syslinux.cfg"

LABEL install-vault
  MENU LABEL Install Axonwall ^Vault Edition (Immutable S3 Storage)
  KERNEL /boot/vmlinuz-virt
  INITRD /boot/initramfs-virt
  APPEND modules=loop,squashfs,sd-mod,usb-storage,sr_mod,cdrom,isofs,virtio_blk,virtio_scsi,virtio_pci,nvme,ata_piix,ahci axonwall_edition=vault axonwall_install=1 quiet console=tty0 console=ttyS0,9600
SYSLINUX_VAULT_EOF
  fi
  if [[ -x "${OVL}/var/lib/axonwall/core-k3s/bin/k3s" ]]; then
    cat << 'SYSLINUX_K3S_EOF' >> "${WORK_DIR}/iso/boot/syslinux/syslinux.cfg"

LABEL install-k3s-storage
  MENU LABEL Install Axonwall ^K3s + ZFS Storage Host (Minimal)
  KERNEL /boot/vmlinuz-virt
  INITRD /boot/initramfs-virt
  APPEND modules=loop,squashfs,sd-mod,usb-storage,sr_mod,cdrom,isofs,virtio_blk,virtio_scsi,virtio_pci,nvme,ata_piix,ahci axonwall_edition=k3s-storage axonwall_install=1 quiet console=tty0 console=ttyS0,9600
SYSLINUX_K3S_EOF
  fi
  sed -i "s|/boot/vmlinuz-virt|/boot/vmlinuz-${ALPINE_KERNEL_FLAVOR}|g; s|/boot/initramfs-virt|/boot/initramfs-${ALPINE_KERNEL_FLAVOR}|g; s|modules=loop,[^ ]*|modules=${STORAGE_MODULES}|g" "${WORK_DIR}/iso/boot/syslinux/syslinux.cfg"
fi

cat << SYSLINUX_REST_EOF >> "${WORK_DIR}/iso/boot/syslinux/syslinux.cfg"

LABEL live
  MENU LABEL ${BOOT_LIVE_LABEL}
  KERNEL /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR}
  INITRD /boot/initramfs-${ALPINE_KERNEL_FLAVOR}
  APPEND modules=${STORAGE_MODULES} ${EDITION_KARG}quiet console=tty0 console=ttyS0,9600

LABEL unattended
  MENU LABEL ^Zero-Touch Unattended Install (Cloud-Init / NoCloud Seed)
  KERNEL /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR}
  INITRD /boot/initramfs-${ALPINE_KERNEL_FLAVOR}
  APPEND modules=${STORAGE_MODULES} ${EDITION_KARG}axonwall.unattended=1 quiet console=tty0 console=ttyS0,9600
SYSLINUX_REST_EOF

cat << GRUB_EOF > "${WORK_DIR}/iso/boot/grub/grub.cfg"
set default=0
set timeout=5

insmod all_video
insmod gfxterm
insmod png
insmod gfxmenu
insmod serial
set gfxmode=640x480,800x600,auto

if [ -f /boot/grub/themes/axonwall/theme.txt ]; then
  set theme=/boot/grub/themes/axonwall/theme.txt
  export theme
elif [ -f /boot/grub/splash.png ]; then
  background_image /boot/grub/splash.png
fi

set color_normal=light-gray/black
set color_highlight=light-green/dark-gray
if serial --unit=0 --speed=9600 --word=8 --parity=no --stop=1; then
  terminal_input console serial
  terminal_output gfxterm serial
else
  terminal_output gfxterm
fi

menuentry "${BOOT_GRUB_INSTALL_LABEL}" {
  linux /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR} modules=${STORAGE_MODULES} ${EDITION_KARG}axonwall_install=1 quiet console=tty0 console=ttyS0,9600
  initrd /boot/initramfs-${ALPINE_KERNEL_FLAVOR}
}
GRUB_EOF

if [[ "${EDITION}" == "axonwall" ]]; then
  cat << GRUB_MINIMAL_EOF >> "${WORK_DIR}/iso/boot/grub/grub.cfg"

menuentry "Install Axonwall Minimal Edition (Reduced Attack Surface)" {
  linux /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR} modules=${STORAGE_MODULES} axonwall_edition=minimal axonwall_install=1 quiet console=tty0 console=ttyS0,9600
  initrd /boot/initramfs-${ALPINE_KERNEL_FLAVOR}
}
GRUB_MINIMAL_EOF
  if [[ -x "${OVL}/usr/share/axonwall/vault/weed" || -x "${OVL}/usr/sbin/weed" ]]; then
    cat << GRUB_VAULT_EOF >> "${WORK_DIR}/iso/boot/grub/grub.cfg"

menuentry "Install Axonwall Vault Edition (Immutable S3 Storage)" {
  linux /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR} modules=${STORAGE_MODULES} axonwall_edition=vault axonwall_install=1 quiet console=tty0 console=ttyS0,9600
  initrd /boot/initramfs-${ALPINE_KERNEL_FLAVOR}
}
GRUB_VAULT_EOF
  fi
  if [[ -x "${OVL}/var/lib/axonwall/core-k3s/bin/k3s" ]]; then
    cat << GRUB_K3S_EOF >> "${WORK_DIR}/iso/boot/grub/grub.cfg"

menuentry "Install Axonwall K3s + ZFS Storage Host (Minimal)" {
  linux /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR} modules=${STORAGE_MODULES} axonwall_edition=k3s-storage axonwall_install=1 quiet console=tty0 console=ttyS0,9600
  initrd /boot/initramfs-${ALPINE_KERNEL_FLAVOR}
}
GRUB_K3S_EOF
  fi
fi

cat << GRUB_REST_EOF >> "${WORK_DIR}/iso/boot/grub/grub.cfg"

menuentry "${BOOT_GRUB_LIVE_LABEL}" {
  linux /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR} modules=${STORAGE_MODULES} ${EDITION_KARG}quiet console=tty0 console=ttyS0,9600
  initrd /boot/initramfs-${ALPINE_KERNEL_FLAVOR}
}

menuentry "Zero-Touch Unattended Install (Cloud-Init / NoCloud Seed)" {
  linux /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR} modules=${STORAGE_MODULES} ${EDITION_KARG}axonwall.unattended=1 quiet console=tty0 console=ttyS0,9600
  initrd /boot/initramfs-${ALPINE_KERNEL_FLAVOR}
}
GRUB_REST_EOF

# 6. Assemble bootable BIOS + UEFI Hybrid ISO
echo "[+] Generating hybrid BIOS/UEFI ISO image: ${ISO_NAME}..."
MBR_BIN="/usr/share/syslinux/isohdpfx.bin"
XORRISO_ARGS=(
  -as mkisofs
  -o "${OUTPUT_DIR}/${ISO_NAME}"
  -V "${ISO_VOL_ID}"
  -A "${ISO_APP_ID}"
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
