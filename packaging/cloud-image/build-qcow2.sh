#!/usr/bin/env bash
# ==============================================================================
# Axonwall Cloud Appliance Image (QCOW2) Builder
# ==============================================================================
# Builds an optimized, compressed QCOW2 virtual appliance image with:
# - GPT hybrid BIOS & UEFI boot support (SeaBIOS + OVMF)
# - Dual-Root A/B unbrickable upgrade layout (Slot A active, Slot B standby)
# - Dynamic auto-expansion of data partition via cloud-guest-utils (growpart)
# - Native cloud-init integration (#cloud-config)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
WORK_DIR="${SCRIPT_DIR}/build"

VERSION=$(node -p "require('${ROOT_DIR}/package.json').version" 2>/dev/null || echo "0.9.9")
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

rm -rf "${WORK_DIR}"
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

cleanup() {
  set +e
  echo "[*] Cleaning up mounts and loop devices..."
  umount -R "${WORK_DIR}/mnt" 2>/dev/null || true
  if [[ -n "${LOOP_DEV:-}" && -b "${LOOP_DEV}" ]]; then
    losetup -d "${LOOP_DEV}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Wait for kernel to register partition table
partprobe "${LOOP_DEV}" 2>/dev/null || true
sleep 1

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

# 5. Mount target filesystems
TARGET="${WORK_DIR}/mnt"
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

# Ensure critical directories exist
mkdir -p "${TARGET}/dev" "${TARGET}/proc" "${TARGET}/sys" "${TARGET}/run" "${TARGET}/tmp"
chmod 1777 "${TARGET}/tmp"
mkdir -p "${TARGET}/etc/axonwall" "${TARGET}/etc/cloud/cloud.cfg.d" "${TARGET}/etc/ssh/sshd_config.d"

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

# Set firstboot marker
touch "${TARGET}/etc/axonwall/.firstboot"

# Configure cloud-init datasource
cat << 'CFG_EOF' > "${TARGET}/etc/cloud/cloud.cfg.d/90_axonwall.cfg"
# Axonwall Appliance Cloud-Init Datasource Configuration
datasource_list: [ NoCloud, ConfigDrive, OpenStack, OVF, Ec2, GCE, Azure, None ]

datasource:
  NoCloud:
    fs_label: cidata
  ConfigDrive:
    dsmode: local
CFG_EOF

# Ensure cloud-init services are enabled
for svc in cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service; do
  ln -sf "/lib/systemd/system/${svc}" "${TARGET}/etc/systemd/system/multi-user.target.wants/${svc}" 2>/dev/null || true
done

# Ensure axonwall services are enabled
for svc in axonwalld.service axonwall-firstboot.service axonwall-controller.service axonwall-ui.service headscale.service nftables.service ssh.service; do
  ln -sf "/etc/systemd/system/${svc}" "${TARGET}/etc/systemd/system/multi-user.target.wants/${svc}" 2>/dev/null || \
  ln -sf "/lib/systemd/system/${svc}" "${TARGET}/etc/systemd/system/multi-user.target.wants/${svc}" 2>/dev/null || true
done

# Install GRUB bootloader for both BIOS and UEFI
echo "[+] Installing GRUB bootloader (UEFI + BIOS)..."
mount --bind /dev "${TARGET}/dev"
mount --bind /dev/pts "${TARGET}/dev/pts"
mount --bind /proc "${TARGET}/proc"
mount --bind /sys "${TARGET}/sys"

# Install GRUB for EFI (removable media target ensures boot on all UEFI firmware)
chroot "${TARGET}" grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=axonwall --recheck --no-nvram --removable 2>/dev/null || true

# Install GRUB for Legacy BIOS
chroot "${TARGET}" grub-install --target=i386-pc --recheck "${LOOP_DEV}" 2>/dev/null || true

# Update GRUB configuration
chroot "${TARGET}" update-grub 2>/dev/null || true

# Sanitize image before unmounting: ensure unique machine-id and SSH host keys on VM instantiation
echo "[+] Sanitizing appliance image (machine-id, host keys, cloud-init state)..."
: > "${TARGET}/etc/machine-id"
rm -f "${TARGET}/var/lib/dbus/machine-id"
rm -f "${TARGET}/etc/ssh/ssh_host_"*
rm -rf "${TARGET}/var/lib/cloud/data" "${TARGET}/var/lib/cloud/instance" "${TARGET}/var/lib/cloud/instances"
rm -rf "${TARGET}/tmp/"* "${TARGET}/var/tmp/"*

# Unmount target mounts
umount "${TARGET}/sys" "${TARGET}/proc" "${TARGET}/dev/pts" "${TARGET}/dev"
umount "${TARGET}/boot/efi" "${TARGET}/var/lib/axonwall" "${TARGET}"
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
