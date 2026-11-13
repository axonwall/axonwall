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
  axonwall|k3s-storage) ;;
  *)
    echo "[!] Unknown --edition '${EDITION}' (expected axonwall or k3s-storage)" >&2
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
  cryptsetup
  rsync
  bash
  syslinux
  efibootmgr
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
    "zfs-${ALPINE_KERNEL_FLAVOR}"
    zfs-openrc
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
    neovim
    zsh
    python3
    kubectl
    helm
    starship
    tmux
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
else
  echo "axonwall" > "${OVL}/etc/hostname"
  touch "${OVL}/etc/axonwall/.firstboot"
fi

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
  ln -sf /bin/ash "${OVL}/usr/bin/zsh"
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
    # On minimal Alpine (no zsh installed), symlink /usr/bin/zsh -> /bin/ash so SSO users
    # replicated with loginShell=/usr/bin/zsh can SSH into minimal Alpine seamlessly.
    ln -sf /bin/ash "${OVL}/usr/bin/zsh"
  fi

  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-ha-notify" "${OVL}/usr/local/bin/"
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-import" "${OVL}/usr/local/bin/"
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwallctl" "${OVL}/usr/local/bin/"
  if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-tui" ]]; then
    cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-tui" "${OVL}/usr/local/bin/"
  fi
fi

cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-update" "${OVL}/usr/local/bin/"
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-config" ]]; then
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-config" "${OVL}/usr/local/bin/"
fi
if [[ -f "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-opshell" ]]; then
  cp "${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-opshell" "${OVL}/usr/local/bin/"
fi
chmod +x "${OVL}/usr/local/bin/axonwall"*

# Version stamp
VERSION="$(cat "${REPO_ROOT}/VERSION" 2>/dev/null | tr -d '[:space:]' || echo "0.2.2")"
echo "${VERSION}" > "${OVL}/etc/axonwall/version"

# Copy compiled Go daemons (axonwalld, axonwall-console, axonwall-satellite)
# Core payloads are fail-closed, mirroring the console-binary guard in
# build-iso.sh: an image built without its daemon, UI, or controller
# boots "successfully" and is only discovered broken at service start.
if [[ "${EDITION}" == "axonwall" ]]; then
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

if [[ -f "${REPO_ROOT}/apps/axonwall-satellite/bin/axonwall-satellite-amd64" ]]; then
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
fi

if [[ "${EDITION}" == "k3s-storage" ]]; then
  K3S_VERSION="${K3S_VERSION:-v1.31.5+k3s1}"
  K3S_URL_VERSION="${K3S_VERSION//+/%2B}"
  case "${K3S_VERSION}" in
    v1.31.5+k3s1) K3S_SHA256="${K3S_SHA256:-399b87b432ce55013fa81adad572a8e4ecf56e0df97369cf02d4b8a41f039091}" ;;
    v1.32.3+k3s1) K3S_SHA256="${K3S_SHA256:-b19216803650b567bf980888dec39035edaf664339c55bc4462f7a003edbef83}" ;;
    *) K3S_SHA256="${K3S_SHA256:-}" ;;
  esac
  echo "[+] Fetching K3s ${K3S_VERSION} for Alpine k3s-storage overlay..."
  curl -fsSL -o "${OVL}/usr/local/bin/k3s" "https://github.com/k3s-io/k3s/releases/download/${K3S_URL_VERSION}/k3s"
  if [[ -z "${K3S_SHA256}" ]]; then
    K3S_SHA256="$(curl -fsSL "https://github.com/k3s-io/k3s/releases/download/${K3S_URL_VERSION}/sha256sum-amd64.txt" | awk '$2 == "k3s" {print $1; exit}')"
  fi
  if [[ -z "${K3S_SHA256}" ]]; then
    echo "[!] ERROR: Unable to determine SHA-256 checksum for K3s ${K3S_VERSION}" >&2
    exit 1
  fi
  echo "${K3S_SHA256}  ${OVL}/usr/local/bin/k3s" | sha256sum -c -
  chmod 0755 "${OVL}/usr/local/bin/k3s"
  ln -sf k3s "${OVL}/usr/local/bin/kubectl"
  ln -sf k3s "${OVL}/usr/local/bin/crictl"
  ln -sf k3s "${OVL}/usr/local/bin/ctr"
else
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

# Copy Next.js standalone UI & Controller (axonwall NGFW edition only)
if [[ "${EDITION}" == "axonwall" ]]; then
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
  for svc in chronyd crond sshd nftables axonwall-firstboot k3s k3s-agent local; do
    ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/default/${svc}"
  done
else
  for svc in devfs dmesg mdev hwdrivers modloop; do
    ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/sysinit/${svc}"
  done
  for svc in axonwall-network-setup modules sysctl hostname bootmisc syslog networking; do
    ln -sf "/etc/init.d/${svc}" "${OVL}/etc/runlevels/boot/${svc}"
  done
  for svc in chronyd crond sshd headscale axonwall-firstboot axonwalld axonwall-controller axonwall-ui local; do
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
  APPEND modules=${STORAGE_MODULES} ${EDITION_KARG}axonwall_install=1 quiet console=tty0 console=ttyS0,115200
SYSLINUX_EOF

if [[ "${EDITION}" == "axonwall" ]]; then
cat << 'SYSLINUX_EDITIONS_EOF' >> "${WORK_DIR}/iso/boot/syslinux/syslinux.cfg"

LABEL install-vault
  MENU LABEL Install Axonwall ^Vault Edition (Immutable S3 Storage)
  KERNEL /boot/vmlinuz-virt
  INITRD /boot/initramfs-virt
  APPEND modules=loop,squashfs,sd-mod,usb-storage,sr_mod,cdrom,isofs,virtio_blk,virtio_scsi,virtio_pci,nvme,ata_piix,ahci axonwall_edition=vault axonwall_install=1 quiet console=tty0 console=ttyS0,115200

LABEL install-k3s-storage
  MENU LABEL Install Axonwall ^K3s + ZFS Storage Host (Minimal)
  KERNEL /boot/vmlinuz-virt
  INITRD /boot/initramfs-virt
  APPEND modules=loop,squashfs,sd-mod,usb-storage,sr_mod,cdrom,isofs,virtio_blk,virtio_scsi,virtio_pci,nvme,ata_piix,ahci axonwall_edition=k3s-storage axonwall_install=1 quiet console=tty0 console=ttyS0,115200
SYSLINUX_EDITIONS_EOF
sed -i "s|/boot/vmlinuz-virt|/boot/vmlinuz-${ALPINE_KERNEL_FLAVOR}|g; s|/boot/initramfs-virt|/boot/initramfs-${ALPINE_KERNEL_FLAVOR}|g; s|modules=loop,[^ ]*|modules=${STORAGE_MODULES}|g" "${WORK_DIR}/iso/boot/syslinux/syslinux.cfg"
fi

cat << SYSLINUX_REST_EOF >> "${WORK_DIR}/iso/boot/syslinux/syslinux.cfg"

LABEL live
  MENU LABEL ${BOOT_LIVE_LABEL}
  KERNEL /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR}
  INITRD /boot/initramfs-${ALPINE_KERNEL_FLAVOR}
  APPEND modules=${STORAGE_MODULES} ${EDITION_KARG}quiet console=tty0 console=ttyS0,115200

LABEL unattended
  MENU LABEL ^Zero-Touch Unattended Install (Cloud-Init / NoCloud Seed)
  KERNEL /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR}
  INITRD /boot/initramfs-${ALPINE_KERNEL_FLAVOR}
  APPEND modules=${STORAGE_MODULES} ${EDITION_KARG}axonwall.unattended=1 quiet console=tty0 console=ttyS0,115200
SYSLINUX_REST_EOF

cat << GRUB_EOF > "${WORK_DIR}/iso/boot/grub/grub.cfg"
set default=0
set timeout=5

insmod all_video
insmod gfxterm
insmod png
insmod gfxmenu
set gfxmode=640x480,800x600,auto

if [ -f /boot/grub/themes/axonwall/theme.txt ]; then
  set theme=/boot/grub/themes/axonwall/theme.txt
  export theme
elif [ -f /boot/grub/splash.png ]; then
  background_image /boot/grub/splash.png
fi

set color_normal=light-gray/black
set color_highlight=light-green/dark-gray
terminal_output gfxterm

menuentry "${BOOT_GRUB_INSTALL_LABEL}" {
  linux /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR} modules=${STORAGE_MODULES} ${EDITION_KARG}axonwall_install=1 quiet console=tty0 console=ttyS0,115200
  initrd /boot/initramfs-${ALPINE_KERNEL_FLAVOR}
}
GRUB_EOF

if [[ "${EDITION}" == "axonwall" ]]; then
cat << GRUB_EDITIONS_EOF >> "${WORK_DIR}/iso/boot/grub/grub.cfg"

menuentry "Install Axonwall Vault Edition (Immutable S3 Storage)" {
  linux /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR} modules=${STORAGE_MODULES} axonwall_edition=vault axonwall_install=1 quiet console=tty0 console=ttyS0,115200
  initrd /boot/initramfs-${ALPINE_KERNEL_FLAVOR}
}

menuentry "Install Axonwall K3s + ZFS Storage Host (Minimal)" {
  linux /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR} modules=${STORAGE_MODULES} axonwall_edition=k3s-storage axonwall_install=1 quiet console=tty0 console=ttyS0,115200
  initrd /boot/initramfs-${ALPINE_KERNEL_FLAVOR}
}
GRUB_EDITIONS_EOF
fi

cat << GRUB_REST_EOF >> "${WORK_DIR}/iso/boot/grub/grub.cfg"

menuentry "${BOOT_GRUB_LIVE_LABEL}" {
  linux /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR} modules=${STORAGE_MODULES} ${EDITION_KARG}quiet console=tty0 console=ttyS0,115200
  initrd /boot/initramfs-${ALPINE_KERNEL_FLAVOR}
}

menuentry "Zero-Touch Unattended Install (Cloud-Init / NoCloud Seed)" {
  linux /boot/vmlinuz-${ALPINE_KERNEL_FLAVOR} modules=${STORAGE_MODULES} ${EDITION_KARG}axonwall.unattended=1 quiet console=tty0 console=ttyS0,115200
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
