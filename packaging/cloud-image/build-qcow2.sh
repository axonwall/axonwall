#!/usr/bin/env bash
# ==============================================================================
# Axonwall Cloud Appliance Image (QCOW2) Builder
# ==============================================================================
# Builds an optimized, compressed QCOW2 virtual appliance image with:
# - GPT hybrid BIOS & UEFI boot support (SeaBIOS + OVMF)
# - Dual-Root A/B unbrickable upgrade layout (Slot A active, Slot B standby;
#   B ships empty and is populated by firstboot -- see the note below)
# - Dynamic auto-expansion of data partition via cloud-guest-utils (growpart)
# - Native cloud-init integration (#cloud-config)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
WORK_DIR="${SCRIPT_DIR}/build"

VERSION=$(node -p "require('${ROOT_DIR}/package.json').version" 2>/dev/null || grep -m1 '"version"' "${ROOT_DIR}/package.json" 2>/dev/null | sed -E 's/.*"version": *"([^"]+)".*/\1/' || true)
if [ -z "$VERSION" ]; then
  echo "[-] ERROR: cannot determine release version (package.json missing or unreadable); refusing to stamp a hardcoded fallback version." >&2
  exit 1
fi
IMAGE_BASE="axonwall-debian13-amd64-cloud"
RAW_IMAGE="${WORK_DIR}/${IMAGE_BASE}.raw"
QCOW2_IMAGE="${OUTPUT_DIR}/${IMAGE_BASE}.qcow2"

echo "================================================================================"
echo "Axonwall Appliance Cloud Image (QCOW2) Builder"
echo "  Version: ${VERSION}"
echo "  Target : ${QCOW2_IMAGE}"
echo "================================================================================"

# Verify root privileges
if [[ $EUID -ne 0 ]]; then
  echo "[!] Error: build-qcow2.sh must be executed as root (or via sudo)." >&2
  exit 1
fi

# Verify required tools
for tool in qemu-img losetup parted mkfs.ext4 mkfs.vfat rsync; do
  if ! command -v "$tool" &>/dev/null; then
    echo "[!] Error: Required tool '$tool' is not installed." >&2
    exit 1
  fi
done

# Check root filesystem source
CHROOT_SRC="${ROOT_DIR}/packaging/iso/build/chroot"
if [[ ! -d "$CHROOT_SRC" ]]; then
  echo "[!] Notice: Live-build chroot (${CHROOT_SRC}) not found."
  echo "    Attempting to build base system via packaging/iso/build-iso.sh..."
  "${ROOT_DIR}/packaging/iso/build-iso.sh"
fi

if [[ ! -d "$CHROOT_SRC" ]]; then
  echo "[!] Error: Cannot find chroot directory at ${CHROOT_SRC}." >&2
  exit 1
fi

TARGET="${WORK_DIR}/mnt"
LOOP_DEV=""

cleanup() {
  set +e
  echo "[*] Cleaning up mounts and loop devices..."
  if [[ -d "${TARGET}" ]]; then
    for submount in run dev/pts dev sys proc boot/efi var/lib/axonwall; do
      if mountpoint -q "${TARGET}/${submount}" 2>/dev/null; then
        umount "${TARGET}/${submount}" 2>/dev/null || umount -l "${TARGET}/${submount}" 2>/dev/null || true
      fi
    done

    if mountpoint -q "${TARGET}" 2>/dev/null; then
      umount "${TARGET}" 2>/dev/null || umount -l "${TARGET}" 2>/dev/null || true
    fi
  fi

  if [[ -n "${LOOP_DEV:-}" && -b "${LOOP_DEV}" ]]; then
    losetup -d "${LOOP_DEV}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# Unmount any leftover mounts and detach stale loops from an interrupted prior run
if [[ -d "${TARGET}" ]]; then
  for submount in run dev/pts dev sys proc boot/efi var/lib/axonwall; do
    if mountpoint -q "${TARGET}/${submount}" 2>/dev/null; then
      umount "${TARGET}/${submount}" || umount -l "${TARGET}/${submount}"
    fi
  done
  if mountpoint -q "${TARGET}" 2>/dev/null; then
    umount "${TARGET}" || umount -l "${TARGET}"
  fi
fi
if [[ -f "${RAW_IMAGE}" ]]; then
  for _stale_loop in $(losetup -j "${RAW_IMAGE}" 2>/dev/null | cut -d: -f1); do
    [[ -n "${_stale_loop}" ]] && losetup -d "${_stale_loop}" 2>/dev/null || true
  done
fi

rm -rf --one-file-system "${WORK_DIR}"
mkdir -p "${WORK_DIR}" "${OUTPUT_DIR}"

# 1. Allocate 16GB sparse raw disk image
echo "[+] Allocating 16GB sparse raw disk image..."
truncate -s 16G "${RAW_IMAGE}"

# 2. Partition disk table (GPT with BIOS boot + EFI + A/B Dual Root + Swap + Data)
echo "[+] Creating GPT partition table with Hybrid BIOS/UEFI + A/B Dual Root layout..."
parted -s "${RAW_IMAGE}" mklabel gpt
# 1: BIOS Boot (1MB - 3MB)
parted -s "${RAW_IMAGE}" mkpart bios_boot 1MiB 4MiB
parted -s "${RAW_IMAGE}" set 1 bios_grub on

# 2: EFI System Partition (4MB - 516MB)
parted -s "${RAW_IMAGE}" mkpart AXON_EFI fat32 4MiB 516MiB
parted -s "${RAW_IMAGE}" set 2 esp on

# 3: Slot A Root (516MB - 6660MB / ~6GB)
parted -s "${RAW_IMAGE}" mkpart axon_root_a ext4 516MiB 6660MiB

# 4: Slot B Standby Root (6660MB - 12804MB / ~6GB)
parted -s "${RAW_IMAGE}" mkpart axon_root_b ext4 6660MiB 12804MiB

# 5: Swap (12804MB - 13828MB / 1GB)
parted -s "${RAW_IMAGE}" mkpart axon_swap linux-swap 12804MiB 13828MiB

# 6: Data /var/lib/axonwall (13828MB - 100% / ~2.5GB sparse default, expandable)
parted -s "${RAW_IMAGE}" mkpart axon_data ext4 13828MiB 100%

# 3. Attach loopback device
echo "[+] Attaching loopback device..."
LOOP_DEV=$(losetup -Pf --show "${RAW_IMAGE}")
echo "    Assigned loop device: ${LOOP_DEV}"

# Wait for kernel to register partition table
partprobe "${LOOP_DEV}" 2>/dev/null || true
udevadm settle 2>/dev/null || sleep 1

PART_BIOS="${LOOP_DEV}p1"
PART_EFI="${LOOP_DEV}p2"
PART_ROOT_A="${LOOP_DEV}p3"
PART_ROOT_B="${LOOP_DEV}p4"
PART_SWAP="${LOOP_DEV}p5"
PART_DATA="${LOOP_DEV}p6"

# 4. Format filesystems with deterministic volume labels
echo "[+] Formatting partitions..."
mkfs.vfat -F 32 -n "AXON_EFI" "${PART_EFI}"
mkfs.ext4 -F -L "axon_root_a" -m 1 "${PART_ROOT_A}"
mkfs.ext4 -F -L "axon_root_b" -m 1 "${PART_ROOT_B}"
mkswap -L "axon_swap" "${PART_SWAP}"
mkfs.ext4 -F -L "axon_data" -m 1 "${PART_DATA}"
udevadm settle 2>/dev/null || true

# 5. Mount target filesystems
mkdir -p "${TARGET}"
mount "${PART_ROOT_A}" "${TARGET}"
mkdir -p "${TARGET}/boot/efi" "${TARGET}/var/lib/axonwall"
mount "${PART_EFI}" "${TARGET}/boot/efi"
mount "${PART_DATA}" "${TARGET}/var/lib/axonwall"

# 6. Populate Slot A rootfs from live-build chroot
echo "[+] Synchronizing base appliance filesystem from live-build chroot..."
rsync -aHAX --exclude='/proc/*' --exclude='/sys/*' --exclude='/dev/*' \
  --exclude='/run/*' --exclude='/tmp/*' --exclude='/boot/efi/*' \
  --exclude='/var/lib/axonwall/*' "${CHROOT_SRC}/" "${TARGET}/"

# Copy Axonwall chroot overrides and configurations
if [[ -d "${ROOT_DIR}/packaging/iso/config/includes.chroot" ]]; then
  echo "[+] Applying Axonwall appliance includes and hooks..."
  cp -r "${ROOT_DIR}/packaging/iso/config/includes.chroot/"* "${TARGET}/" 2>/dev/null || true
fi
if [[ -f "${TARGET}/etc/sudoers.d/axonwall" ]]; then
  chmod 0440 "${TARGET}/etc/sudoers.d/axonwall"
fi

# Ensure critical directories exist
mkdir -p "${TARGET}/dev" "${TARGET}/proc" "${TARGET}/sys" "${TARGET}/run" "${TARGET}/tmp"
chmod 1777 "${TARGET}/tmp"
mkdir -p "${TARGET}/etc/axonwall" "${TARGET}/etc/cloud/cloud.cfg.d" "${TARGET}/etc/ssh/sshd_config.d"

# Record A/B install mode inside both /etc/axonwall and persistent /var/lib/axonwall before cloning Slot B / sanitizing
printf 'ab\n' > "${TARGET}/etc/axonwall/install-mode"
printf 'ab\n' > "${TARGET}/var/lib/axonwall/install-mode"

# Configure /etc/fstab with deterministic label mounts
cat << FSTAB_EOF > "${TARGET}/etc/fstab"
# /etc/fstab: static file system information for Axonwall Appliance
# <file system>        <mount point>       <type>   <options>                        <dump>  <pass>
LABEL=axon_root_a      /                   ext4     defaults,noatime,errors=remount-ro  0       1
LABEL=AXON_EFI         /boot/efi           vfat     umask=0077                       0       2
LABEL=axon_data        /var/lib/axonwall   ext4     defaults,noatime                 0       2
LABEL=axon_swap        none                swap     sw                               0       0
/var/lib/axonwall/home /home               none     bind                             0       0
FSTAB_EOF

# The fstab bind-mounts /var/lib/axonwall/home onto /home, so the source
# must already exist inside the data partition at first boot: a failed
# fstab mount (no nofail) fails local-fs.target and drops the box to
# emergency mode before Debian firstboot (which creates the directory
# far too late) ever runs.
mkdir -p "${TARGET}/var/lib/axonwall/home"

# Set firstboot marker
touch "${TARGET}/etc/axonwall/.firstboot"

# Slot B ships as an empty formatted filesystem (see the note below the
# sanitize step): storing the rootfs twice pushed the image past GitHub's
# 2 GiB release asset limit. Firstboot populates B from the booted slot
# once, then consumes this marker; installer (d-i) images populate B at
# install time and never carry it.
touch "${TARGET}/etc/axonwall/.ab-clone-pending"

# Preserve includes.chroot/etc/cloud/cloud.cfg.d/90_axonwall.cfg when copied;
# only synthesize a fallback 90_axonwall.cfg if absent, and add growpart drop-in for /var/lib/axonwall.
if [[ ! -f "${TARGET}/etc/cloud/cloud.cfg.d/90_axonwall.cfg" ]]; then
  cat << 'CFG_EOF' > "${TARGET}/etc/cloud/cloud.cfg.d/90_axonwall.cfg"
# Axonwall Appliance Cloud-Init Datasource Configuration
datasource_list: [ NoCloud, ConfigDrive, OpenStack, OVF, Ec2, GCE, Azure, None ]

datasource:
  NoCloud:
    fs_label: cidata
  ConfigDrive:
    dsmode: local
CFG_EOF
fi
cat << 'GROW_EOF' > "${TARGET}/etc/cloud/cloud.cfg.d/91_axonwall_growpart.cfg"
# Expand /var/lib/axonwall data partition on cloud disk resize
growpart:
  mode: auto
  devices: ['/var/lib/axonwall']
  ignore_growroot_disabled: false
GROW_EOF

# Ensure cloud-init services are enabled
for svc in cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service; do
  ln -sf "/lib/systemd/system/${svc}" "${TARGET}/etc/systemd/system/multi-user.target.wants/${svc}" 2>/dev/null || true
done

# Ensure axonwall services are enabled (do not enable stock nftables.service which races axonwalld)
for svc in axonwalld.service axonwall-firstboot.service axonwall-controller.service axonwall-ui.service headscale.service ssh.service; do
  if [[ -f "${TARGET}/etc/systemd/system/${svc}" ]]; then
    ln -sf "/etc/systemd/system/${svc}" "${TARGET}/etc/systemd/system/multi-user.target.wants/${svc}" 2>/dev/null || true
  elif [[ -f "${TARGET}/lib/systemd/system/${svc}" || -f "${TARGET}/usr/lib/systemd/system/${svc}" ]]; then
    ln -sf "/lib/systemd/system/${svc}" "${TARGET}/etc/systemd/system/multi-user.target.wants/${svc}" 2>/dev/null || true
  fi
done

# Install GRUB bootloader for both BIOS and UEFI
echo "[+] Installing GRUB bootloader (UEFI + BIOS)..."
mount -t devtmpfs dev "${TARGET}/dev" 2>/dev/null || mount --bind /dev "${TARGET}/dev"
mount --make-rslave "${TARGET}/dev" 2>/dev/null || true
mkdir -p "${TARGET}/dev/pts" "${TARGET}/run"
mount -t devpts devpts "${TARGET}/dev/pts" -o gid=5,mode=620 2>/dev/null || mount --bind /dev/pts "${TARGET}/dev/pts"
mount -t proc proc "${TARGET}/proc" 2>/dev/null || mount --bind /proc "${TARGET}/proc"
mount -t sysfs sys "${TARGET}/sys" 2>/dev/null || mount --bind /sys "${TARGET}/sys"
mount --bind /run "${TARGET}/run"

# Install GRUB for EFI (removable media target ensures boot on all UEFI firmware)
# D-H1: a failed bootloader install must fail the build, never ship an
# unbootable image stamped as success. No `|| true`, no silenced stderr:
# under `set -euo pipefail` a failure aborts here and the EXIT trap cleans up.
chroot "${TARGET}" grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=axonwall --recheck --no-nvram --removable

# Install GRUB for Legacy BIOS
chroot "${TARGET}" grub-install --target=i386-pc --recheck "${LOOP_DEV}"

# Configure GRUB theme & fonts
mkdir -p "${TARGET}/boot/grub/themes/axonwall"
if [[ -f "${TARGET}/usr/share/grub/unicode.pf2" ]]; then
  cp -n "${TARGET}/usr/share/grub/unicode.pf2" "${TARGET}/boot/grub/unicode.pf2" 2>/dev/null || true
  cp -n "${TARGET}/usr/share/grub/unicode.pf2" "${TARGET}/boot/grub/themes/axonwall/unicode.pf2" 2>/dev/null || true
fi

# Configure Axonwall Plymouth boot splash theme
chroot "${TARGET}" /usr/sbin/plymouth-set-default-theme axonwall 2>/dev/null || true

# Update GRUB configuration & initialize deterministic grubenv A/B state
# (D-H1: update-grub fails the build on error -- no || true, no silenced stderr.)
chroot "${TARGET}" update-grub
if [[ ! -f "${TARGET}/boot/grub/grubenv" ]]; then
  chroot "${TARGET}" grub-editenv /boot/grub/grubenv create
fi
chroot "${TARGET}" grub-editenv /boot/grub/grubenv set active_slot=A bootcount=0 bootlimit=3

# Sanitize image before unmounting: ensure unique machine-id and SSH host keys on VM instantiation
echo "[+] Sanitizing appliance image (machine-id, host keys, cloud-init state)..."
: > "${TARGET}/etc/machine-id"
rm -f "${TARGET}/var/lib/dbus/machine-id"
rm -f "${TARGET}/etc/ssh/ssh_host_"*
rm -rf "${TARGET}/var/lib/cloud/data" "${TARGET}/var/lib/cloud/instance" "${TARGET}/var/lib/cloud/instances"
rm -rf "${TARGET}/tmp/"* "${TARGET}/var/tmp/"*

# Unmount target mounts strictly in reverse hierarchical order before qemu-img convert
sync
udevadm settle 2>/dev/null || true

for sub in run dev/pts dev sys proc boot/efi var/lib/axonwall; do
  if mountpoint -q "${TARGET}/${sub}" 2>/dev/null; then
    umount "${TARGET}/${sub}"
  fi
done

if mountpoint -q "${TARGET}" 2>/dev/null; then
  umount "${TARGET}"
fi
losetup -d "${LOOP_DEV}"
LOOP_DEV=""

# 7. Convert sparse raw image to compressed QCOW2
echo "[+] Converting raw disk image to optimized compressed QCOW2..."
qemu-img convert -c -f raw -O qcow2 "${RAW_IMAGE}" "${QCOW2_IMAGE}"
rm -f "${RAW_IMAGE}"

# 8. Compute checksums
(cd "${OUTPUT_DIR}" && sha256sum "$(basename "${QCOW2_IMAGE}")" > "$(basename "${QCOW2_IMAGE}").sha256")

echo "================================================================================"
echo "[✓] Successfully built Axonwall Appliance QCOW2 Image:"
echo "    ${QCOW2_IMAGE}"
echo "    Size: $(du -h "${QCOW2_IMAGE}" | awk '{print $1}')"
echo "================================================================================"
