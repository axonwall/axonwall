#!/usr/bin/env bash
# ==============================================================================
# Axonwall Debian 13 (Trixie) Appliance ISO Builder
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${WORK_DIR:-${SCRIPT_DIR}/build}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/output}"

# Appliance flavor: "axonwall" (the firewall, default), "vault"
# (Vault Edition: SeaweedFS immutable-backup appliance), or "k3s-storage"
# (Barebones K3s + OpenZFS + OpenEBS Storage Host; firewall/UI stack absent).
FLAVOR="${AXONWALL_FLAVOR:-axonwall}"
case "${FLAVOR}" in
  axonwall)
    ISO_NAME="axonwall-debian13-amd64.iso"
    ISO_APPLICATION="Axonwall Firewall & Router Appliance"
    ISO_VOLUME="AXONWALL_D13"
    LIVE_HOSTNAME="axonwall"
    ;;
  vault)
    ISO_NAME="axonwall-vault-debian13-amd64.iso"
    ISO_APPLICATION="Axonwall Vault Appliance"
    ISO_VOLUME="AXONWALL_VAULT"
    LIVE_HOSTNAME="axonwall-vault"
    ;;
  k3s-storage)
    ISO_NAME="axonwall-k3s-storage-debian13-amd64.iso"
    ISO_APPLICATION="Axonwall K3s + ZFS Storage Host"
    ISO_VOLUME="AXONWALL_K3S"
    LIVE_HOSTNAME="axonwall-storage"
    ;;
  *)
    echo "[!] Unknown AXONWALL_FLAVOR '${FLAVOR}' (expected axonwall, vault, or k3s-storage)" >&2
    exit 1
    ;;
esac

echo "=== Axonwall Appliance ISO Builder ==="

if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root (or via sudo / in a root container) to build chroot/ISO."
   echo "    In CI/CD, this executes inside an unprivileged Docker container with CAP_SYS_ADMIN."
fi

mkdir -p "${WORK_DIR}" "${OUTPUT_DIR}"
if [[ -d "${WORK_DIR}" ]]; then
  (cd "${WORK_DIR}" && lb clean 2>/dev/null || true)
fi
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
  --mirror-bootstrap "https://deb.debian.org/debian/" \
  --mirror-chroot "https://deb.debian.org/debian/" \
  --mirror-chroot-security "https://deb.debian.org/debian-security/" \
  --mirror-binary "https://deb.debian.org/debian/" \
  --mirror-binary-security "https://deb.debian.org/debian-security/" \
  --mirror-debian-installer "https://deb.debian.org/debian/" \
  --keyring-packages debian-archive-keyring \
  --architectures amd64 \
  --linux-flavours amd64 \
  --archive-areas "main contrib non-free non-free-firmware" \
  --apt-recommends false \
  --firmware-chroot false \
  --firmware-binary false \
  --chroot-squashfs-compression-type xz \
  --binary-images iso-hybrid \
  --bootloaders "syslinux,grub-efi" \
  --bootappend-live "boot=live components quiet splash plymouth.ignore-serial-consoles loglevel=3 systemd.show_status=0 lsm=landlock,lockdown,yama,integrity,apparmor,bpf hostname=${LIVE_HOSTNAME} username=axonwall live-config.user-default-groups=sudo,adm,dialout live-config.nottyautologin console=ttyS0,9600 console=tty0" \
  --bootappend-install "auto=true priority=critical preseed/file=/preseed.cfg" \
  --debian-installer live \
  --debian-installer-distribution trixie \
  --debian-installer-gui false \
  --iso-application "${ISO_APPLICATION}" \
  --iso-publisher "Axonwall Core Team <ops@axonwall.io>" \
  --iso-volume "${ISO_VOLUME}" \
  --memtest none \
  --system live

# 3. Copy customized overlays (sysctl, firstboot service, systemd units, hooks)
echo "[+] Copying Axonwall system includes, overlays & chroot hooks..."
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

mkdir -p config/hooks/live config/hooks/normal
if [[ -d "${SCRIPT_DIR}/config/hooks" ]]; then
  cp -r "${SCRIPT_DIR}/config/hooks/"* config/hooks/
fi
chmod +x config/hooks/live/* config/hooks/normal/* 2>/dev/null || true

# Copy branded GRUB2 & ISOLINUX bootloader templates and splash artwork
mkdir -p config/bootloaders/isolinux config/bootloaders/grub-pc/live-theme config/includes.chroot/etc/axonwall/branding config/includes.chroot/boot/grub/themes/axonwall config/includes.chroot/etc/default/grub.d
if [[ -d "${SCRIPT_DIR}/config/bootloaders" ]]; then
  cp -r "${SCRIPT_DIR}/config/bootloaders/"* config/bootloaders/
fi
SPLASH_SRC="${SCRIPT_DIR}/branding/splash.png"
SPLASH_BMP="${SCRIPT_DIR}/branding/splash.bmp"
if [[ "${FLAVOR}" == "vault" && -f "${SCRIPT_DIR}/branding/splash-vault.png" ]]; then
  SPLASH_SRC="${SCRIPT_DIR}/branding/splash-vault.png"
  SPLASH_BMP="${SCRIPT_DIR}/branding/splash-vault.bmp"
fi
if [[ ( ! -f "${SPLASH_SRC}" || ! -f "${SPLASH_BMP}" ) ]] && command -v python3 &>/dev/null && [[ -f "${SCRIPT_DIR}/branding/generate-splash.py" ]]; then
  python3 "${SCRIPT_DIR}/branding/generate-splash.py" "${SCRIPT_DIR}/branding" || true
fi
if [[ -f "${SPLASH_SRC}" ]]; then
  cp "${SPLASH_SRC}" config/includes.chroot/etc/axonwall/branding/splash.png
  cp "${SPLASH_SRC}" config/includes.chroot/boot/grub/themes/axonwall/splash.png
  cp "${SPLASH_SRC}" config/includes.chroot/boot/grub/splash.png
  cp "${SPLASH_SRC}" config/bootloaders/isolinux/splash.png
  cp "${SPLASH_SRC}" config/bootloaders/grub-pc/live-theme/splash.png
fi
if [[ -f "${SPLASH_BMP}" ]]; then
  mkdir -p config/includes.chroot/etc/axonwall/branding config/includes.chroot/etc/zfsbootmenu
  cp "${SPLASH_BMP}" config/includes.chroot/etc/axonwall/branding/splash.bmp
  cp "${SPLASH_BMP}" config/includes.chroot/etc/zfsbootmenu/splash.bmp
fi
if [[ -f "${SCRIPT_DIR}/config/bootloaders/grub-pc/live-theme/theme.txt" ]]; then
  cp "${SCRIPT_DIR}/config/bootloaders/grub-pc/live-theme/theme.txt" config/includes.chroot/boot/grub/themes/axonwall/theme.txt
  cp "${SCRIPT_DIR}/config/bootloaders/grub-pc/live-theme/theme.txt" config/includes.chroot/etc/axonwall/branding/theme.txt
fi
if [[ -d "${SCRIPT_DIR}/branding/plymouth/axonwall" ]]; then
  mkdir -p config/includes.chroot/usr/share/plymouth/themes/axonwall
  cp -a "${SCRIPT_DIR}/branding/plymouth/axonwall/." config/includes.chroot/usr/share/plymouth/themes/axonwall/
fi

# Stage detect-cloudinit into Live chroot so unattended/live installer can discover NoCloud seeds
if [[ -f "${SCRIPT_DIR}/config/includes.installer/usr/lib/axonwall/detect-cloudinit" ]]; then
  mkdir -p config/includes.chroot/usr/lib/axonwall
  cp "${SCRIPT_DIR}/config/includes.installer/usr/lib/axonwall/detect-cloudinit" config/includes.chroot/usr/lib/axonwall/detect-cloudinit
  chmod +x config/includes.chroot/usr/lib/axonwall/detect-cloudinit
fi

if [[ "${FLAVOR}" == "vault" ]]; then
  echo "[+] Applying Vault Edition overlay (firewall payload removed)..."
  # The firewall stack is ABSENT from a vault image, not disabled:
  # drop its firstboot, CLIs, service drop-ins and leftover config
  # from the copied tree before anything else consumes them.
  rm -f config/includes.chroot/etc/systemd/system/axonwall-firstboot.service \
        config/includes.chroot/usr/local/bin/axonwall-firstboot \
        config/includes.chroot/usr/local/bin/axonwallctl \
        config/includes.chroot/usr/local/bin/axonwall-tui \
        config/includes.chroot/usr/local/bin/axonwall-ha-notify \
        config/includes.chroot/usr/local/bin/axonwall-cloud-init \
        config/includes.chroot/usr/local/bin/axonwall-import \
        config/includes.chroot/etc/headscale/config.yaml
  # No k3s on a vault image, in either location: the chroot tree
  # persists across builds, so a staged core-k3s plugin dir left by
  # an earlier axonwall-flavor build must go, not just the binaries
  # the vault branch never downloads.
  rm -rf config/includes.chroot/var/lib/axonwall/core-k3s
  rm -rf config/includes.chroot/etc/systemd/system/suricata.service.d
  rmdir config/includes.chroot/etc/headscale 2>/dev/null || true
  # Vault markers: .vault-edition tells shared hooks (e.g. the
  # installer's credentials step) to stand down; .vault-firstboot
  # gates the vault firstboot service.
  mkdir -p config/includes.chroot/etc/axonwall/
  touch config/includes.chroot/etc/axonwall/.vault-firstboot
  touch config/includes.chroot/etc/axonwall/.vault-edition
  # Static vault firewall ruleset + vault preseeds.
  cp "${SCRIPT_DIR}/../vault/nftables.conf" config/includes.chroot/etc/nftables.conf
  cp "${SCRIPT_DIR}/../vault/preseed-vault.cfg" config/includes.installer/preseed.cfg
  cp "${SCRIPT_DIR}/../vault/preseed-vault-binary.cfg" config/includes.binary/preseed.cfg
elif [[ "${FLAVOR}" == "k3s-storage" ]]; then
  echo "[+] Applying K3s + ZFS Storage Host overlay (firewall/UI payload removed)..."
  rm -f config/includes.chroot/etc/systemd/system/axonwall-firstboot.service \
        config/includes.chroot/usr/local/bin/axonwall-firstboot \
        config/includes.chroot/usr/local/bin/axonwallctl \
        config/includes.chroot/usr/local/bin/axonwall-tui \
        config/includes.chroot/usr/local/bin/axonwall-ha-notify \
        config/includes.chroot/usr/local/bin/axonwall-cloud-init \
        config/includes.chroot/usr/local/bin/axonwall-import \
        config/includes.chroot/etc/headscale/config.yaml
  rm -rf config/includes.chroot/etc/systemd/system/suricata.service.d
  rmdir config/includes.chroot/etc/headscale 2>/dev/null || true
  mkdir -p config/includes.chroot/etc/axonwall/ \
           config/includes.chroot/etc/sysctl.d/ \
           config/includes.chroot/etc/modules-load.d/ \
           config/includes.chroot/usr/share/axonwall/k3s/
  touch config/includes.chroot/etc/axonwall/.k3s-firstboot
  touch config/includes.chroot/etc/axonwall/.k3s-edition
  cp "${SCRIPT_DIR}/../k3s-storage/nftables.conf" config/includes.chroot/etc/nftables.conf
  cp "${SCRIPT_DIR}/../k3s-storage/90-k3s-storage.conf" config/includes.chroot/etc/sysctl.d/90-k3s-storage.conf
  cp "${SCRIPT_DIR}/../k3s-storage/k3s-storage.modules.conf" config/includes.chroot/etc/modules-load.d/k3s-storage.conf
  cp "${SCRIPT_DIR}/../k3s-storage/zfs-operator.yaml" config/includes.chroot/usr/share/axonwall/k3s/zfs-operator.yaml
  cp "${SCRIPT_DIR}/../k3s-storage/preseed-k3s-storage.cfg" config/includes.installer/preseed.cfg
  cp "${SCRIPT_DIR}/../k3s-storage/preseed-k3s-storage-binary.cfg" config/includes.binary/preseed.cfg
fi

# D-M9 (marker): the canonical edition file for the live installer
# environment (and, via this chroot, for the cloud image and every
# install the TUI/d-i paths perform from this ISO). FLAVOR is the
# builder's edition axis, validated to axonwall|vault|k3s-storage.
printf '%s\n' "${FLAVOR}" > config/includes.chroot/etc/axonwall/edition

# Ensure firstboot marker directory and service enable symlink exist
mkdir -p config/includes.chroot/etc/axonwall/
if [[ "${FLAVOR}" == "axonwall" ]]; then
  touch config/includes.chroot/etc/axonwall/.firstboot
fi
mkdir -p config/includes.chroot/etc/systemd/system/multi-user.target.wants/
if [[ -f config/includes.chroot/etc/systemd/system/axonwall-firstboot.service ]]; then
  ln -sf /etc/systemd/system/axonwall-firstboot.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/axonwall-firstboot.service
fi

# Copy systemd units for the flavor
# R4-D-L1: these are core payloads, not optional ones -- a failed copy
# must fail the build, not ship an ISO with a dangling enable symlink.
# Each copy below is bare (no `|| true`); the enable symlink that
# follows it is only created when its target file actually landed.
mkdir -p config/includes.chroot/etc/systemd/system/multi-user.target.wants/
# Appliance console & Next-Gen TUI Installer unit ships in BOTH flavors
cp "${SCRIPT_DIR}/../debian/axonwall-console.service" config/includes.chroot/etc/systemd/system/
ln -sf /etc/systemd/system/axonwall-console.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/axonwall-console.service
if [[ "${FLAVOR}" == "axonwall" ]]; then
  cp "${SCRIPT_DIR}/../debian/axonwalld.service" config/includes.chroot/etc/systemd/system/
  ln -sf /etc/systemd/system/axonwalld.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/axonwalld.service
  cp "${SCRIPT_DIR}/../debian/axonwall-controller.service" config/includes.chroot/etc/systemd/system/
  ln -sf /etc/systemd/system/axonwall-controller.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/axonwall-controller.service
  cp "${SCRIPT_DIR}/../debian/axonwall-ui.service" config/includes.chroot/etc/systemd/system/
  ln -sf /etc/systemd/system/axonwall-ui.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/axonwall-ui.service
  cp "${SCRIPT_DIR}/../debian/headscale.service" config/includes.chroot/etc/systemd/system/
  ln -sf /etc/systemd/system/headscale.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/headscale.service
  cp "${SCRIPT_DIR}/../debian/k3s.service" config/includes.chroot/etc/systemd/system/
  ln -sf /etc/systemd/system/k3s.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/k3s.service

  mkdir -p config/includes.chroot/etc/headscale
  cp "${SCRIPT_DIR}/../debian/headscale-config.yaml" config/includes.chroot/etc/headscale/config.yaml

  # Copy default baseline lockdown ruleset
  mkdir -p config/includes.chroot/usr/share/axonwall/
  cp "${SCRIPT_DIR}/../debian/lockdown.nft" config/includes.chroot/usr/share/axonwall/
elif [[ "${FLAVOR}" == "k3s-storage" ]]; then
  # K3s + OpenZFS Storage Host units & CLI helpers
  for kunit in k3s.service k3s-agent.service axonwall-k3s-firstboot.service axonwall-k3s-verify.service; do
    cp "${SCRIPT_DIR}/../k3s-storage/${kunit}" "config/includes.chroot/etc/systemd/system/${kunit}"
    ln -sf "/etc/systemd/system/${kunit}" "config/includes.chroot/etc/systemd/system/multi-user.target.wants/${kunit}"
  done
  ln -sf /lib/systemd/system/nftables.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/nftables.service
  mkdir -p config/includes.chroot/usr/local/bin
  for kbin in axonwall-k3s-firstboot axonwall-k3s-verify axonwall-k3s-status; do
    cp "${SCRIPT_DIR}/../k3s-storage/${kbin}" "config/includes.chroot/usr/local/bin/${kbin}"
    chmod +x "config/includes.chroot/usr/local/bin/${kbin}"
  done
else
  # Vault Edition units, tools and identity files.
  cp "${SCRIPT_DIR}/../vault/seaweedfs.service" config/includes.chroot/etc/systemd/system/
  cp "${SCRIPT_DIR}/../vault/axonwall-vault-firstboot.service" config/includes.chroot/etc/systemd/system/
  cp "${SCRIPT_DIR}/../vault/axonwall-vault-provision.service" config/includes.chroot/etc/systemd/system/
  ln -sf /etc/systemd/system/axonwall-vault-firstboot.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/axonwall-vault-firstboot.service
  ln -sf /etc/systemd/system/axonwall-vault-provision.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/axonwall-vault-provision.service
  # seaweedfs is enabled but inert until firstboot writes its identity
  # config: the unit carries ConditionPathExists on that config and is
  # ordered after the firstboot unit.
  ln -sf /etc/systemd/system/seaweedfs.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/seaweedfs.service
  # The stock nftables.service applies /etc/nftables.conf (vault ruleset).
  ln -sf /lib/systemd/system/nftables.service config/includes.chroot/etc/systemd/system/multi-user.target.wants/nftables.service
  mkdir -p config/includes.chroot/usr/lib/sysusers.d config/includes.chroot/usr/lib/tmpfiles.d
  cp "${SCRIPT_DIR}/../vault/axonwall-vault.sysusers" config/includes.chroot/usr/lib/sysusers.d/axonwall-vault.conf
  cp "${SCRIPT_DIR}/../vault/axonwall-vault.tmpfiles" config/includes.chroot/usr/lib/tmpfiles.d/axonwall-vault.conf
  cp "${SCRIPT_DIR}/../vault/axonwall-vault-provision" config/includes.chroot/usr/local/bin/
  cp "${SCRIPT_DIR}/../vault/axonwall-vault-status" config/includes.chroot/usr/local/bin/
  cp "${SCRIPT_DIR}/../vault/axonwall-vault-firstboot" config/includes.chroot/usr/local/bin/
  chmod +x config/includes.chroot/usr/local/bin/axonwall-vault-provision \
           config/includes.chroot/usr/local/bin/axonwall-vault-status \
           config/includes.chroot/usr/local/bin/axonwall-vault-firstboot
fi

# Hub certificate renewal (B-14) ships in BOTH flavors: the vault's S3
# endpoint serves the same CA-issued hub leaf and renews it the same way.
# R4-D-L1: core payloads -- a failed copy fails the build (no `|| true`).
cp "${SCRIPT_DIR}/../debian/axonwall-hub-cert-renew.service" config/includes.chroot/etc/systemd/system/
cp "${SCRIPT_DIR}/../debian/axonwall-hub-cert-renew.timer" config/includes.chroot/etc/systemd/system/
mkdir -p config/includes.chroot/etc/systemd/system/timers.target.wants/
ln -sf /etc/systemd/system/axonwall-hub-cert-renew.timer config/includes.chroot/etc/systemd/system/timers.target.wants/axonwall-hub-cert-renew.timer

if [[ -f config/includes.chroot/usr/local/bin/axonwall-firstboot ]]; then
  chmod +x config/includes.chroot/usr/local/bin/axonwall-firstboot
fi

if [[ -f config/includes.chroot/usr/local/bin/axonwall-ha-notify ]]; then
  chmod +x config/includes.chroot/usr/local/bin/axonwall-ha-notify
fi

if [[ -f config/includes.chroot/usr/local/bin/axonwall-update ]]; then
  chmod +x config/includes.chroot/usr/local/bin/axonwall-update
fi

if [[ -f config/includes.chroot/usr/local/bin/axonwall-opshell ]]; then
  chmod +x config/includes.chroot/usr/local/bin/axonwall-opshell
fi

if [[ -f config/includes.chroot/usr/local/bin/axonwall-config ]]; then
  chmod +x config/includes.chroot/usr/local/bin/axonwall-config
fi

if [[ -f config/includes.chroot/usr/local/bin/axonwall-install ]]; then
  chmod +x config/includes.chroot/usr/local/bin/axonwall-install
fi

if [[ -f config/includes.chroot/usr/local/bin/axonwall-cloud-init ]]; then
  chmod +x config/includes.chroot/usr/local/bin/axonwall-cloud-init
fi

if [[ -f config/includes.chroot/usr/local/bin/axonwall-zbm-theme ]]; then
  chmod +x config/includes.chroot/usr/local/bin/axonwall-zbm-theme
  ln -sf axonwall-zbm-theme config/includes.chroot/usr/local/bin/generate-zbm
  ln -sf axonwall-zbm-theme config/includes.chroot/usr/local/bin/zbm-kcl
fi

for rk_script in axonwall-hunt-rootkits hunt-io-uring-implants.sh hunt-ebpf-rootkits.sh audit_hidden_bpf_prog_idr.py; do
  if [[ -f "config/includes.chroot/usr/local/bin/${rk_script}" ]]; then
    chmod +x "config/includes.chroot/usr/local/bin/${rk_script}"
  fi
done

if [[ -f config/includes.chroot/etc/sudoers.d/axonwall ]]; then
  chmod 0440 config/includes.chroot/etc/sudoers.d/axonwall
fi

chmod +x config/includes.chroot/usr/local/bin/axonwall-import || true

VERSION=$(node -p "require('${SCRIPT_DIR}/../../package.json').version" 2>/dev/null || grep -m1 '"version"' "${SCRIPT_DIR}/../../package.json" 2>/dev/null | sed -E 's/.*"version": *"([^"]+)".*/\1/' || true)
if [ -z "$VERSION" ]; then
  echo "[-] ERROR: cannot determine release version (package.json missing or unreadable); refusing to stamp a hardcoded fallback version." >&2
  exit 1
fi
echo "${VERSION}" > config/includes.chroot/etc/axonwall/version

# Copy compiled daemon binaries if present
mkdir -p config/includes.chroot/usr/sbin/

# Fetch ZFSBootMenu v3.1.0 Unified Kernel Image (UKI) for Root-on-ZFS installations (ships in both flavors)
ZBM_VERSION="3.1.0"
ZBM_KVER="linux6.12"
ZBM_SHA256="131d55c7b385df8cd319d267b6aa15d97f8c32c94f5149bd906556715fadf4e7"
ZBM_CACHE="${WORK_DIR}/cache/zfsbootmenu-release-x86_64-v${ZBM_VERSION}-${ZBM_KVER}.EFI"
mkdir -p "${WORK_DIR}/cache" config/includes.chroot/usr/lib/zfsbootmenu config/includes.chroot/usr/lib/axonwall
if [[ ! -f "${ZBM_CACHE}" ]]; then
  echo "[+] Fetching ZFSBootMenu v${ZBM_VERSION} (${ZBM_KVER}) UKI..."
  curl -fsSL -o "${ZBM_CACHE}" "https://github.com/zbm-dev/zfsbootmenu/releases/download/v${ZBM_VERSION}/zfsbootmenu-release-x86_64-v${ZBM_VERSION}-${ZBM_KVER}.EFI"
fi
echo "${ZBM_SHA256}  ${ZBM_CACHE}" | sha256sum -c -

# Theme ZFSBootMenu UKI with Axonwall splash bitmap, embedded initramfs hooks, and console parameters
if command -v python3 &>/dev/null && command -v objcopy &>/dev/null && [[ -f "${SCRIPT_DIR}/branding/theme-zbm-uki.py" && -f "${SPLASH_BMP}" ]]; then
  echo "[+] Theming ZFSBootMenu UKI (embedding branded .splash section and initramfs hooks)..."
  python3 "${SCRIPT_DIR}/branding/theme-zbm-uki.py" \
    "${ZBM_CACHE}" \
    -o config/includes.chroot/usr/lib/zfsbootmenu/vmlinuz.efi \
    -s "${SPLASH_BMP}"
else
  cp -f "${ZBM_CACHE}" config/includes.chroot/usr/lib/zfsbootmenu/vmlinuz.efi
fi
chmod 0644 config/includes.chroot/usr/lib/zfsbootmenu/vmlinuz.efi

if [[ -f "${SCRIPT_DIR}/branding/theme-zbm-uki.py" ]]; then
  cp -f "${SCRIPT_DIR}/branding/theme-zbm-uki.py" config/includes.chroot/usr/lib/axonwall/theme-zbm-uki.py
  chmod +x config/includes.chroot/usr/lib/axonwall/theme-zbm-uki.py
fi

# Plugin-bundled binaries (core-k3s): k3s + k9s live in the plugin
# dir <root>/var/lib/axonwall/core-k3s/bin/ now, not /usr/local/bin.
# This chroot tree persists in the repo across builds, so drop any
# pre-migration copies at the old location: a stale /usr/local/bin
# binary would otherwise ship alongside the plugin dir, unreferenced
# by every unit/script but still shadowing it on PATH.
rm -f config/includes.chroot/usr/local/bin/k3s config/includes.chroot/usr/local/bin/k9s

# write_core_k3s_bundled_json writes the bundled.json verification
# record next to the pre-staged plugin binaries, in exactly the
# format axonwalld's installBundledBinaries writes (relative path +
# sha256 of the bytes on disk + manifest entry + kind), so the
# daemon's verifyBundledBinaries passes on the staged tree without
# a re-download. $1 = plugin dir. It records whichever of bin/k3s
# and bin/k9s are staged and executable, and fails the build when
# neither is — a plugin dir with no binaries must never ship a
# record blessing an empty tree.
write_core_k3s_bundled_json() {
  local _dir="$1" _k3s_sum="" _k9s_sum="" _n=0
  if [[ -x "${_dir}/bin/k3s" ]]; then
    _k3s_sum="$(sha256sum "${_dir}/bin/k3s" | awk '{print $1}')"
    _n=$((_n + 1))
  fi
  if [[ -x "${_dir}/bin/k9s" ]]; then
    _k9s_sum="$(sha256sum "${_dir}/bin/k9s" | awk '{print $1}')"
    _n=$((_n + 1))
  fi
  if [[ "${_n}" -eq 0 ]]; then
    echo "[!] ERROR: core-k3s plugin dir ${_dir} has no staged binaries; cannot write bundled.json." >&2
    return 1
  fi
  {
    printf '{\n  "pluginId": "core-k3s",\n  "files": [\n'
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

if [[ "${FLAVOR}" == "axonwall" ]]; then
# Fetch Headscale binary
HEADSCALE_VERSION="0.29.4"
# Pinned SHA-256 of the upstream release binary (verified from the
# official GitHub release download, 2026-10-16). Bump with the version.
HEADSCALE_SHA256="212ed0a884c0d3541e094c4bebbe94397df6f4e01bd3d7f059c520cb55e0d757"
if [[ ! -f config/includes.chroot/usr/sbin/headscale ]]; then
  echo "[+] Fetching Headscale v${HEADSCALE_VERSION}..."
  curl -fsSL -o config/includes.chroot/usr/sbin/headscale "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}/headscale_${HEADSCALE_VERSION}_linux_amd64"
  echo "${HEADSCALE_SHA256}  config/includes.chroot/usr/sbin/headscale" | sha256sum -c -
  chmod +x config/includes.chroot/usr/sbin/headscale
fi

# Fetch Litestream binary for distributed SQLite replication
LITESTREAM_VERSION="0.3.13"
# Pinned SHA-256 of the upstream release tarball (verified from the
# official GitHub release download, 2026-10-16). Bump with the version.
# A failed download or checksum mismatch now fails the build (set -e):
# this binary ships in /usr/sbin of every ISO, so silently shipping
# without it -- or with an unverified copy -- is not an option.
LITESTREAM_SHA256="eb75a3de5cab03875cdae9f5f539e6aedadd66607003d9b1e7a9077948818ba0"
if [[ ! -f config/includes.chroot/usr/sbin/litestream ]]; then
  echo "[+] Fetching Litestream v${LITESTREAM_VERSION}..."
  LITE_TAR="$(mktemp -t litestream-XXXXXX.tar.gz)"
  curl -fsSL -o "${LITE_TAR}" "https://github.com/benbjohnson/litestream/releases/download/v${LITESTREAM_VERSION}/litestream-v${LITESTREAM_VERSION}-linux-amd64.tar.gz"
  echo "${LITESTREAM_SHA256}  ${LITE_TAR}" | sha256sum -c -
  tar -xzf "${LITE_TAR}" -C config/includes.chroot/usr/sbin/ litestream
  chmod +x config/includes.chroot/usr/sbin/litestream
  rm -f "${LITE_TAR}"
fi

# Fetch Helm v3 binary for Kubernetes & Cloud-Native package management
HELM_VERSION="3.17.4"
HELM_SHA256="c91e3d7293849eff3b4dc4ea7994c338bcc92f914864d38b5789bab18a1d775d"
mkdir -p config/includes.chroot/usr/local/bin
if [[ ! -f config/includes.chroot/usr/local/bin/helm ]]; then
  echo "[+] Fetching Helm v${HELM_VERSION}..."
  HELM_TAR="$(mktemp -t helm-XXXXXX.tar.gz)"
  curl -fsSL -o "${HELM_TAR}" "https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz"
  echo "${HELM_SHA256}  ${HELM_TAR}" | sha256sum -c -
  tar -xzf "${HELM_TAR}" -C config/includes.chroot/usr/local/bin/ --strip-components=1 linux-amd64/helm
  chmod 0755 config/includes.chroot/usr/local/bin/helm
  rm -f "${HELM_TAR}"
fi

# Fetch kubectl binary for Kubernetes cluster administration
KUBECTL_VERSION="1.32.3"
KUBECTL_SHA256="ab209d0c5134b61486a0486585604a616a5bb2fc07df46d304b3c95817b2d79f"
if [[ ! -f config/includes.chroot/usr/local/bin/kubectl ]]; then
  echo "[+] Fetching kubectl v${KUBECTL_VERSION}..."
  curl -fsSL -o config/includes.chroot/usr/local/bin/kubectl "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
  echo "${KUBECTL_SHA256}  config/includes.chroot/usr/local/bin/kubectl" | sha256sum -c -
  chmod 0755 config/includes.chroot/usr/local/bin/kubectl
fi

# Fetch K3s binary for in-house Kubernetes control plane & worker engine (core-k3s plugin)
# Staged into the plugin dir config/includes.chroot/var/lib/axonwall/core-k3s/bin/,
# not /usr/local/bin. A pre-existing staged binary is kept only if
# its sha256 still matches the pin — a stale file from an earlier
# build is re-downloaded, never packaged unverified.
K3S_VERSION="v1.32.3+k3s1"
K3S_URL_VERSION="v1.32.3%2Bk3s1"
K3S_SHA256="b19216803650b567bf980888dec39035edaf664339c55bc4462f7a003edbef83"
mkdir -p config/includes.chroot/var/lib/axonwall/core-k3s/bin
if [[ -f config/includes.chroot/var/lib/axonwall/core-k3s/bin/k3s ]] && echo "${K3S_SHA256}  config/includes.chroot/var/lib/axonwall/core-k3s/bin/k3s" | sha256sum -c - >/dev/null 2>&1; then
  echo "[+] K3s ${K3S_VERSION} already staged and verified; keeping."
else
  echo "[+] Fetching K3s ${K3S_VERSION}..."
  curl -fsSL -o config/includes.chroot/var/lib/axonwall/core-k3s/bin/k3s "https://github.com/k3s-io/k3s/releases/download/${K3S_URL_VERSION}/k3s"
  echo "${K3S_SHA256}  config/includes.chroot/var/lib/axonwall/core-k3s/bin/k3s" | sha256sum -c -
  chmod 0755 config/includes.chroot/var/lib/axonwall/core-k3s/bin/k3s
fi

# Fetch K9s v0.51.0 interactive Kubernetes terminal UI
# A pre-existing staged k9s is always re-downloaded and re-extracted:
# the pinned sha256 covers the tarball, not the extracted binary, so
# there is no digest a staged binary could be verified against.
K9S_VERSION="0.51.0"
K9S_SHA256="c3752ad51a5a4015a113819c4eeb6e55a4d0e4b8e652494797532f6fc8161dd7"
rm -f config/includes.chroot/var/lib/axonwall/core-k3s/bin/k9s
echo "[+] Fetching K9s v${K9S_VERSION}..."
K9S_TAR="$(mktemp -t k9s-XXXXXX.tar.gz)"
curl -fsSL -o "${K9S_TAR}" "https://github.com/derailed/k9s/releases/download/v${K9S_VERSION}/k9s_Linux_amd64.tar.gz"
echo "${K9S_SHA256}  ${K9S_TAR}" | sha256sum -c -
tar -xzf "${K9S_TAR}" -C config/includes.chroot/var/lib/axonwall/core-k3s/bin/ k9s
chmod 0755 config/includes.chroot/var/lib/axonwall/core-k3s/bin/k9s
rm -f "${K9S_TAR}"

# k3s multicall symlinks in the plugin bin dir (kubectl, crictl,
# ctr -> k3s). The daemon recreates them on core-k3s reconfigure if
# they are ever deleted; nothing is linked into /usr/local/bin.
for _klink in kubectl crictl ctr; do
  ln -sf k3s "config/includes.chroot/var/lib/axonwall/core-k3s/bin/${_klink}"
done
# Verification record for the staged tree (see the helper above).
write_core_k3s_bundled_json config/includes.chroot/var/lib/axonwall/core-k3s

# Stage Vault Edition payload into /usr/share/axonwall/vault/ so the unified
# main ISO can install EITHER Axonwall NGFW OR Axonwall Vault Edition.
mkdir -p config/includes.chroot/usr/share/axonwall/vault
WEED_VERSION="4.48"
WEED_SHA256="4a7d108384d044d95212d1342cdda9533fa55842c1c9b41f606ca3c8a9561124"
if [[ ! -f config/includes.chroot/usr/share/axonwall/vault/weed ]]; then
  echo "[+] Fetching SeaweedFS v${WEED_VERSION} for unified Vault Edition installer support..."
  WEED_TAR="$(mktemp -t seaweedfs-XXXXXX.tar.gz)"
  curl -fsSL -o "${WEED_TAR}" "https://github.com/seaweedfs/seaweedfs/releases/download/${WEED_VERSION}/linux_amd64.tar.gz"
  echo "${WEED_SHA256}  ${WEED_TAR}" | sha256sum -c -
  tar -xzf "${WEED_TAR}" -C config/includes.chroot/usr/share/axonwall/vault/ weed
  chmod +x config/includes.chroot/usr/share/axonwall/vault/weed
  rm -f "${WEED_TAR}"
fi
cp "${SCRIPT_DIR}/../vault/seaweedfs.service" \
   "${SCRIPT_DIR}/../vault/axonwall-vault-firstboot.service" \
   "${SCRIPT_DIR}/../vault/axonwall-vault-provision.service" \
   "${SCRIPT_DIR}/../vault/axonwall-vault.sysusers" \
   "${SCRIPT_DIR}/../vault/axonwall-vault.tmpfiles" \
   "${SCRIPT_DIR}/../vault/axonwall-vault-provision" \
   "${SCRIPT_DIR}/../vault/axonwall-vault-status" \
   "${SCRIPT_DIR}/../vault/axonwall-vault-firstboot" \
   "${SCRIPT_DIR}/../vault/nftables.conf" \
   config/includes.chroot/usr/share/axonwall/vault/
chmod +x config/includes.chroot/usr/share/axonwall/vault/axonwall-vault-provision \
         config/includes.chroot/usr/share/axonwall/vault/axonwall-vault-status \
         config/includes.chroot/usr/share/axonwall/vault/axonwall-vault-firstboot
  if [[ -f "${SCRIPT_DIR}/branding/splash-vault.png" ]]; then
    cp "${SCRIPT_DIR}/branding/splash-vault.png" config/includes.chroot/usr/share/axonwall/vault/splash-vault.png
  fi

  # Stage K3s + ZFS Storage Host payload into /usr/share/axonwall/k3s-storage/
  # and OpenEBS manifest into /usr/share/axonwall/k3s/zfs-operator.yaml so the
  # unified ISO can install axonwall, vault, OR k3s-storage offline.
  mkdir -p config/includes.chroot/usr/share/axonwall/k3s-storage \
           config/includes.chroot/usr/share/axonwall/k3s
  cp "${SCRIPT_DIR}/../k3s-storage/nftables.conf" \
     "${SCRIPT_DIR}/../k3s-storage/90-k3s-storage.conf" \
     "${SCRIPT_DIR}/../k3s-storage/k3s-storage.modules.conf" \
     "${SCRIPT_DIR}/../k3s-storage/k3s.service" \
     "${SCRIPT_DIR}/../k3s-storage/k3s-agent.service" \
     "${SCRIPT_DIR}/../k3s-storage/axonwall-k3s-firstboot.service" \
     "${SCRIPT_DIR}/../k3s-storage/axonwall-k3s-verify.service" \
     "${SCRIPT_DIR}/../k3s-storage/zfs-operator.yaml" \
     "${SCRIPT_DIR}/../k3s-storage/axonwall-k3s-firstboot" \
     "${SCRIPT_DIR}/../k3s-storage/axonwall-k3s-verify" \
     "${SCRIPT_DIR}/../k3s-storage/axonwall-k3s-status" \
     config/includes.chroot/usr/share/axonwall/k3s-storage/
  chmod +x config/includes.chroot/usr/share/axonwall/k3s-storage/axonwall-k3s-firstboot \
           config/includes.chroot/usr/share/axonwall/k3s-storage/axonwall-k3s-verify \
           config/includes.chroot/usr/share/axonwall/k3s-storage/axonwall-k3s-status
  cp "${SCRIPT_DIR}/../k3s-storage/zfs-operator.yaml" config/includes.chroot/usr/share/axonwall/k3s/zfs-operator.yaml
elif [[ "${FLAVOR}" == "k3s-storage" ]]; then
  # Fetch K3s binary for Barebones K3s + OpenZFS Storage Host
  # Staged into the plugin dir, not /usr/local/bin (see the
  # axonwall-flavor block above for the layout). A pre-existing
  # staged binary is kept only if its sha256 still matches the
  # resolved pin.
  K3S_VERSION="${K3S_VERSION:-v1.32.3+k3s1}"
  K3S_URL_VERSION="${K3S_VERSION//+/%2B}"
  case "${K3S_VERSION}" in
    v1.31.5+k3s1) K3S_SHA256="${K3S_SHA256:-399b87b432ce55013fa81adad572a8e4ecf56e0df97369cf02d4b8a41f039091}" ;;
    v1.32.3+k3s1) K3S_SHA256="${K3S_SHA256:-b19216803650b567bf980888dec39035edaf664339c55bc4462f7a003edbef83}" ;;
    *) K3S_SHA256="${K3S_SHA256:-}" ;;
  esac
  mkdir -p config/includes.chroot/var/lib/axonwall/core-k3s/bin
  if [[ -f config/includes.chroot/var/lib/axonwall/core-k3s/bin/k3s ]] && [[ -n "${K3S_SHA256}" ]] && echo "${K3S_SHA256}  config/includes.chroot/var/lib/axonwall/core-k3s/bin/k3s" | sha256sum -c - >/dev/null 2>&1; then
    echo "[+] K3s ${K3S_VERSION} already staged and verified; keeping."
  else
    echo "[+] Fetching K3s ${K3S_VERSION}..."
    curl -fsSL -o config/includes.chroot/var/lib/axonwall/core-k3s/bin/k3s "https://github.com/k3s-io/k3s/releases/download/${K3S_URL_VERSION}/k3s"
    if [[ -z "${K3S_SHA256}" ]]; then
      K3S_SHA256="$(curl -fsSL "https://github.com/k3s-io/k3s/releases/download/${K3S_URL_VERSION}/sha256sum-amd64.txt" | awk '$2 == "k3s" {print $1; exit}')"
    fi
    if [[ -z "${K3S_SHA256}" ]]; then
      echo "[!] ERROR: Unable to determine SHA-256 checksum for K3s ${K3S_VERSION}" >&2
      exit 1
    fi
    echo "${K3S_SHA256}  config/includes.chroot/var/lib/axonwall/core-k3s/bin/k3s" | sha256sum -c -
    chmod 0755 config/includes.chroot/var/lib/axonwall/core-k3s/bin/k3s
  fi
  # A pre-existing staged k9s is always re-downloaded and
  # re-extracted: the pinned sha256 covers the tarball, not the
  # extracted binary, so there is no digest a staged binary could
  # be verified against.
  K9S_VERSION="0.51.0"
  K9S_SHA256="c3752ad51a5a4015a113819c4eeb6e55a4d0e4b8e652494797532f6fc8161dd7"
  rm -f config/includes.chroot/var/lib/axonwall/core-k3s/bin/k9s
  echo "[+] Fetching K9s v${K9S_VERSION}..."
  K9S_TAR="$(mktemp -t k9s-XXXXXX.tar.gz)"
  curl -fsSL -o "${K9S_TAR}" "https://github.com/derailed/k9s/releases/download/v${K9S_VERSION}/k9s_Linux_amd64.tar.gz"
  echo "${K9S_SHA256}  ${K9S_TAR}" | sha256sum -c -
  tar -xzf "${K9S_TAR}" -C config/includes.chroot/var/lib/axonwall/core-k3s/bin/ k9s
  chmod 0755 config/includes.chroot/var/lib/axonwall/core-k3s/bin/k9s
  rm -f "${K9S_TAR}"
  # k3s multicall symlinks in the plugin bin dir (kubectl, crictl,
  # ctr -> k3s). The daemon recreates them on core-k3s reconfigure
  # if they are ever deleted; nothing is linked into /usr/local/bin.
  for _klink in kubectl crictl ctr; do
    ln -sf k3s "config/includes.chroot/var/lib/axonwall/core-k3s/bin/${_klink}"
  done
  # Verification record for the staged tree (see the helper above).
  write_core_k3s_bundled_json config/includes.chroot/var/lib/axonwall/core-k3s
else
# Fetch SeaweedFS binary (Vault Edition storage engine)
WEED_VERSION="4.48"
# Pinned SHA-256 of the upstream release tarball (verified from the
# official GitHub release download, 2026-10-23). Bump with the version.
# NOTE: pin 4.48, not 4.49 -- the 4.49 GitHub release is missing its
# linux binaries. A failed download or checksum mismatch fails the
# build (set -e): this binary IS the vault, so shipping without it --
# or with an unverified copy -- is not an option.
WEED_SHA256="4a7d108384d044d95212d1342cdda9533fa55842c1c9b41f606ca3c8a9561124"
if [[ ! -f config/includes.chroot/usr/sbin/weed ]]; then
  echo "[+] Fetching SeaweedFS v${WEED_VERSION}..."
  WEED_TAR="$(mktemp -t seaweedfs-XXXXXX.tar.gz)"
  curl -fsSL -o "${WEED_TAR}" "https://github.com/seaweedfs/seaweedfs/releases/download/${WEED_VERSION}/linux_amd64.tar.gz"
  echo "${WEED_SHA256}  ${WEED_TAR}" | sha256sum -c -
  tar -xzf "${WEED_TAR}" -C config/includes.chroot/usr/sbin/ weed
  chmod +x config/includes.chroot/usr/sbin/weed
  rm -f "${WEED_TAR}"
fi
fi

if [[ "${FLAVOR}" == "axonwall" ]]; then
  if [[ -f "${SCRIPT_DIR}/../../apps/axonwalld/bin/axonwalld" ]]; then
    cp "${SCRIPT_DIR}/../../apps/axonwalld/bin/axonwalld" config/includes.chroot/usr/sbin/
    chmod +x config/includes.chroot/usr/sbin/axonwalld
  else
    echo "[!] ERROR: apps/axonwalld/bin/axonwalld is missing; cannot build ISO without the daemon." >&2
    exit 1
  fi
fi

if command -v go &>/dev/null; then
  echo "[+] Compiling axonwall-console TUI & Next-Gen Installer..."
  (cd "${SCRIPT_DIR}/../../apps/axonwall-console" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/axonwall-console .)
fi
if [[ -f "${SCRIPT_DIR}/../../apps/axonwall-console/bin/axonwall-console" ]]; then
  cp "${SCRIPT_DIR}/../../apps/axonwall-console/bin/axonwall-console" config/includes.chroot/usr/sbin/
  chmod +x config/includes.chroot/usr/sbin/axonwall-console
else
  echo "[!] ERROR: apps/axonwall-console/bin/axonwall-console is missing; cannot build ISO without Next-Gen Installer TUI." >&2
  exit 1
fi

if [[ "${FLAVOR}" == "axonwall" ]]; then
  if [[ -f "${SCRIPT_DIR}/../../apps/axonwall-satellite/bin/axonwall-satellite-amd64" ]]; then
    cp "${SCRIPT_DIR}/../../apps/axonwall-satellite/bin/axonwall-satellite-amd64" config/includes.chroot/usr/sbin/axonwall-satellite
    chmod +x config/includes.chroot/usr/sbin/axonwall-satellite
  else
    echo "[!] ERROR: apps/axonwall-satellite/bin/axonwall-satellite-amd64 is missing; cannot build ISO without the satellite binary." >&2
    exit 1
  fi
elif [[ "${FLAVOR}" == "k3s-storage" ]]; then
  # Ship axonwall-satellite binary inert on disk for optional future fleet enrollment (no service enabled)
  if [[ -f "${SCRIPT_DIR}/../../apps/axonwall-satellite/bin/axonwall-satellite-amd64" ]]; then
    cp "${SCRIPT_DIR}/../../apps/axonwall-satellite/bin/axonwall-satellite-amd64" config/includes.chroot/usr/sbin/axonwall-satellite
    chmod +x config/includes.chroot/usr/sbin/axonwall-satellite
  fi
fi

if [[ "${FLAVOR}" == "axonwall" ]]; then
mkdir -p config/includes.chroot/usr/share/axonwall/satellites/
if [[ -d "${SCRIPT_DIR}/../../apps/axonwall-satellite/bin" ]]; then
  cp -r "${SCRIPT_DIR}/../../apps/axonwall-satellite/bin/"* config/includes.chroot/usr/share/axonwall/satellites/ 2>/dev/null || true
fi
if [[ -f "${SCRIPT_DIR}/../edge-uki/output/axonwall-edge-sku-vm-virtio.efi" ]]; then
  mkdir -p config/includes.chroot/usr/lib/axonwall/edge/slot-A
  cp "${SCRIPT_DIR}/../edge-uki/output/axonwall-edge-sku-vm-virtio.efi" config/includes.chroot/usr/lib/axonwall/edge/slot-A/axonwall-edge-sku-vm-virtio.efi
  chmod 0644 config/includes.chroot/usr/lib/axonwall/edge/slot-A/axonwall-edge-sku-vm-virtio.efi
fi
fi

if [[ "${FLAVOR}" == "axonwall" ]]; then
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
else
  echo "[!] ERROR: apps/axonwall/.next/standalone is missing (run the Next.js production build first); cannot build ISO without the web console." >&2
  exit 1
fi

if [[ -f "${SCRIPT_DIR}/../../apps/axonwall-controller/dist/index.js" ]]; then
  cp "${SCRIPT_DIR}/../../apps/axonwall-controller/dist/index.js" config/includes.chroot/opt/axonwall/apps/axonwall-controller/dist/
  cp "${SCRIPT_DIR}/../../apps/axonwall-controller/package.json" config/includes.chroot/opt/axonwall/apps/axonwall-controller/
else
  echo "[!] ERROR: apps/axonwall-controller/dist/index.js is missing (run the controller build first); cannot build ISO without the controller." >&2
  exit 1
fi
if [[ -f "${SCRIPT_DIR}/../../apps/axonwall-controller/dist/axonwallctl.js" ]]; then
  cp "${SCRIPT_DIR}/../../apps/axonwall-controller/dist/axonwallctl.js" config/includes.chroot/opt/axonwall/apps/axonwall-controller/dist/
fi
if [[ -f "${SCRIPT_DIR}/../../apps/axonwall-controller/dist/axonwall-tui.js" ]]; then
  cp "${SCRIPT_DIR}/../../apps/axonwall-controller/dist/axonwall-tui.js" config/includes.chroot/opt/axonwall/apps/axonwall-controller/dist/
fi
if [[ -f config/includes.chroot/usr/local/bin/axonwallctl ]]; then
  chmod +x config/includes.chroot/usr/local/bin/axonwallctl
fi
if [[ -f config/includes.chroot/usr/local/bin/axonwall-tui ]]; then
  chmod +x config/includes.chroot/usr/local/bin/axonwall-tui
fi
fi

# NOTE: TLS certificates are intentionally NOT generated here. A key baked into the
# ISO would be identical on every appliance. axonwall-firstboot generates a unique one.
rm -rf config/includes.chroot/etc/axonwall/certs

# Ensure post-base-installer and finish-install hooks in installer are executable
find config/includes.installer/ -type f -path "*.d/*" -exec chmod +x {} + 2>/dev/null || true
chmod +x config/includes.installer/usr/lib/axonwall/* 2>/dev/null || true

# Pre-cache bootloader packages so debian-installer offline installations succeed without network/disc prompts
# R4-D-M5: this block exists so offline d-i installs have GRUB cached. A
# failed apt-get or an empty copy used to be swallowed (`|| true` +
# stderr to /dev/null), so the ISO still printed "[✓] Successfully
# built…" with no cached GRUB packages and the failure only surfaced at
# install time. Fail the build loudly instead, and verify the expected
# bootloader .debs actually landed before continuing.
echo "[+] Pre-caching offline bootloader packages for BIOS & UEFI..."
mkdir -p config/includes.chroot/var/cache/apt/archives/
apt-get update -qq || { echo "[!] ERROR: apt-get update failed; cannot pre-cache offline bootloader packages." >&2; exit 1; }
apt-get install -d -y --no-install-recommends \
  grub-pc \
  grub-pc-bin \
  grub2-common \
  grub-common \
  ucf \
  os-prober || { echo "[!] ERROR: failed to download BIOS bootloader packages (grub-pc set) for the offline pre-cache." >&2; exit 1; }
apt-get install -d -y --no-install-recommends \
  grub-efi-amd64 \
  grub-efi-amd64-bin \
  grub-efi-amd64-signed \
  shim-signed \
  shim-helpers-amd64-signed \
  shim-unsigned \
  efibootmgr || { echo "[!] ERROR: failed to download UEFI bootloader packages (grub-efi-amd64 set) for the offline pre-cache." >&2; exit 1; }
cp /var/cache/apt/archives/*.deb config/includes.chroot/var/cache/apt/archives/ || { echo "[!] ERROR: failed to copy downloaded bootloader .debs into config/includes.chroot/var/cache/apt/archives/." >&2; exit 1; }
for _req_boot_deb in "grub-pc_" "grub-efi-amd64_"; do
  if ! compgen -G "config/includes.chroot/var/cache/apt/archives/${_req_boot_deb}*.deb" >/dev/null; then
    echo "[!] ERROR: expected bootloader package '${_req_boot_deb}*.deb' is missing from config/includes.chroot/var/cache/apt/archives/ -- offline d-i installs would have no GRUB cached." >&2
    exit 1
  fi
done

if [[ "${FLAVOR}" == "axonwall" ]]; then
# Preseed slapd in live-build chroot so package installation does not prompt or create unconfigured DB
mkdir -p config/preseed
cat << 'PRESEED_EOF' > config/preseed/slapd.cfg.chroot
slapd slapd/no_configuration boolean true
PRESEED_EOF
fi

# 4. Define package list to install in image
mkdir -p config/package-lists
if [[ "${FLAVOR}" == "vault" ]]; then
# Vault Edition package set: base OS + storage + admin tooling only.
# The firewall service stack (suricata, kea, unbound, frr, strongswan,
# openvpn, conntrackd, keepalived, wireguard-tools, samba, nfs, iscsi)
# and the LDAP/SSSD stack are absent -- there is nothing to disable.
cat << 'EOF' > config/package-lists/axonwall.list.chroot
linux-image-amd64
live-boot
live-boot-initramfs-tools
live-config
live-config-systemd
user-setup
sudo
firmware-linux-free
firmware-realtek
firmware-atheros
firmware-bnx2
firmware-bnx2x
firmware-iwlwifi
intel-microcode
amd64-microcode
systemd
systemd-sysv
plymouth
plymouth-label
fontconfig
fontconfig-config
fonts-dejavu-core
grub-pc
grub-pc-bin
grub-efi-amd64-bin
efibootmgr
dosfstools
mtools
e2fsprogs
squashfs-tools
ucf
os-prober
isolinux
syslinux
syslinux-common
extlinux
nftables
iproute2
ethtool
pciutils
tcpdump
curl
wget
jq
ca-certificates
net-tools
dnsutils
bind9-host
nmap
kubectl
mkcert
zsh
vim
neovim
less
binutils
zstd
xz-utils
bzip2
unzip
btop
htop
sysstat
iotop
iftop
slurm
starship
zoxide
zsh-autosuggestions
zsh-syntax-highlighting
tmux
fzf
ripgrep
fd-find
bat
mtr-tiny
openssl
kmod
procps
iputils-ping
nano
locales
rsync
python3
mdadm
gdisk
parted
smartmontools
linux-headers-amd64
zfs-dkms
zfsutils-linux
zfs-initramfs
cryptsetup
systemd-cryptsetup
tpm2-tools
xfsprogs
etckeeper
git
openssh-server
openssh-client
libpam-modules
chrony
rkhunter
chkrootkit
yara
unhide
lynis
debsums
bpftool
python3-drgn
linux-perf
EOF
elif [[ "${FLAVOR}" == "k3s-storage" ]]; then
# K3s + OpenZFS Storage Host package set: lean Vault base OS + OpenZFS +
# wireguard-tools + bridge-utils + iptables for K3s Flannel WireGuard & CNI.
cat << 'EOF' > config/package-lists/axonwall.list.chroot
linux-image-amd64
live-boot
live-boot-initramfs-tools
live-config
live-config-systemd
user-setup
sudo
firmware-linux-free
firmware-realtek
firmware-atheros
firmware-bnx2
firmware-bnx2x
firmware-iwlwifi
intel-microcode
amd64-microcode
systemd
systemd-sysv
plymouth
plymouth-label
fontconfig
fontconfig-config
fonts-dejavu-core
grub-pc
grub-pc-bin
grub-efi-amd64-bin
efibootmgr
dosfstools
mtools
e2fsprogs
squashfs-tools
ucf
os-prober
isolinux
syslinux
syslinux-common
extlinux
nftables
iptables
wireguard-tools
bridge-utils
iproute2
ethtool
pciutils
tcpdump
curl
wget
jq
ca-certificates
net-tools
dnsutils
bind9-host
nmap
kubectl
mkcert
zsh
vim
neovim
less
binutils
zstd
xz-utils
bzip2
unzip
btop
htop
sysstat
iotop
iftop
slurm
starship
zoxide
zsh-autosuggestions
zsh-syntax-highlighting
tmux
fzf
ripgrep
fd-find
bat
mtr-tiny
openssl
kmod
procps
iputils-ping
nano
locales
rsync
python3
mdadm
gdisk
parted
smartmontools
linux-headers-amd64
zfs-dkms
zfsutils-linux
zfs-initramfs
cloud-init
cloud-guest-utils
cryptsetup
systemd-cryptsetup
tpm2-tools
xfsprogs
etckeeper
git
openssh-server
openssh-client
libpam-modules
chrony
rkhunter
chkrootkit
yara
unhide
lynis
debsums
bpftool
python3-drgn
linux-perf
EOF
else
cat << 'EOF' > config/package-lists/axonwall.list.chroot
linux-image-amd64
live-boot
live-boot-initramfs-tools
live-config
live-config-systemd
user-setup
sudo
firmware-linux-free
firmware-realtek
firmware-atheros
firmware-bnx2
firmware-bnx2x
firmware-iwlwifi
intel-microcode
amd64-microcode
systemd
systemd-sysv
plymouth
plymouth-label
fontconfig
fontconfig-config
fonts-dejavu-core
grub-pc
grub-pc-bin
grub-efi-amd64-bin
efibootmgr
dosfstools
mtools
e2fsprogs
squashfs-tools
ucf
os-prober
isolinux
syslinux
syslinux-common
extlinux
nftables
iproute2
wireguard-tools
sqlite3
suricata
kea-dhcp4-server
unbound
dns-root-data
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
dnsutils
bind9-host
nmap
kubectl
mkcert
zsh
vim
neovim
less
binutils
zstd
xz-utils
bzip2
unzip
btop
htop
sysstat
iotop
iftop
slurm
starship
zoxide
zsh-autosuggestions
zsh-syntax-highlighting
tmux
fzf
ripgrep
fd-find
bat
mtr-tiny
openssl
kmod
procps
iputils-ping
nano
locales
rsync
python3
mdadm
gdisk
parted
smartmontools
linux-headers-amd64
zfs-dkms
zfsutils-linux
zfs-initramfs
cloud-init
cloud-guest-utils
qemu-system-x86
qemu-utils
ovmf
xorriso
bridge-utils
libvirt-clients
lxc
cryptsetup
systemd-cryptsetup
tpm2-tools
xfsprogs
samba
nfs-kernel-server
open-iscsi
tgt
etckeeper
git
openssh-server
openssh-client
slapd
ldap-utils
sssd-ldap
sssd-tools
libnss-sss
libpam-sss
libpam-modules
chrony
rkhunter
chkrootkit
yara
unhide
lynis
debsums
bpftool
python3-drgn
linux-perf
EOF
fi

# Stage Axonwall Custom Hardened Kernel Builder onto deployed hosts
if [[ "${FLAVOR}" == "axonwall" || "${FLAVOR}" == "k3s-storage" ]]; then
  if [[ -d "${SCRIPT_DIR}/../kernel/fragments" && -f "${SCRIPT_DIR}/../kernel/build-kernel.sh" ]]; then
    echo "[+] Staging Axonwall Hardened Kernel Builder (/usr/share/axonwall/kernel-builder)..."
    mkdir -p config/includes.chroot/usr/share/axonwall/kernel-builder/fragments
    cp "${SCRIPT_DIR}/../kernel/build-kernel.sh" config/includes.chroot/usr/share/axonwall/kernel-builder/build-kernel.sh
    cp "${SCRIPT_DIR}/../kernel/README.md" config/includes.chroot/usr/share/axonwall/kernel-builder/README.md || true
    cp "${SCRIPT_DIR}/../kernel/fragments/"* config/includes.chroot/usr/share/axonwall/kernel-builder/fragments/
    chmod 0755 config/includes.chroot/usr/share/axonwall/kernel-builder/build-kernel.sh
  fi
fi

# Include prebuilt Axonwall custom hardened kernel .deb packages when available
# R4-D-M3: refuse to stage a host-CPU-locked (--march native) kernel .deb.
# build-kernel.sh refuses --march native outright; this is the second line
# of defence for a .deb built by an older builder version, whose manifest
# records "march": "native".
if [[ -f "${SCRIPT_DIR}/../kernel/output/build-manifest.json" ]] && grep -q '"march": "native"' "${SCRIPT_DIR}/../kernel/output/build-manifest.json"; then
  echo "[!] ERROR: packaging/kernel/output/build-manifest.json records \"march\": \"native\" -- the prebuilt kernel .deb is locked to the build host's CPU and must not be staged into the ISO. Rebuild it with a named baseline (e.g. --march x86-64-v3)." >&2
  exit 1
fi
if compgen -G "${SCRIPT_DIR}/../kernel/output/linux-image-*axonwall*.deb" >/dev/null; then
  echo "[+] Installing prebuilt Axonwall custom hardened kernel .deb packages into chroot..."
  mkdir -p config/packages.chroot
  cp "${SCRIPT_DIR}/../kernel/output/linux-image-"*axonwall*.deb config/packages.chroot/
  if compgen -G "${SCRIPT_DIR}/../kernel/output/linux-headers-*axonwall*.deb" >/dev/null; then
    cp "${SCRIPT_DIR}/../kernel/output/linux-headers-"*axonwall*.deb config/packages.chroot/
  fi
fi

# 5. Build ISO
echo "[+] Executing lb build..."
lb build

# 6. Move output image
if [[ -f live-image-amd64.hybrid.iso ]]; then
  mv live-image-amd64.hybrid.iso "${OUTPUT_DIR}/${ISO_NAME}"
  (cd "${OUTPUT_DIR}" && sha256sum "${ISO_NAME}" > "${ISO_NAME}.sha256")
  echo "=================================================="
  echo "[✓] Successfully built Axonwall Appliance ISO:"
  echo "    ${OUTPUT_DIR}/${ISO_NAME}"
  echo "=================================================="
else
  echo "[!] Error: live-image-amd64.hybrid.iso was not generated in $(pwd)"
  exit 1
fi
