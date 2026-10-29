#!/usr/bin/env bash
# ==============================================================================
# Axonwall Super-Slim Edge NGFW — Hardware-SKU Kernel & EFI UKI Builder
# Produces:
#   1. Zero-Shell Static Go PID 1 Initramfs (axonwall-edge-<sku>-initramfs.cpio.gz)
#   2. Merged Monolithic Kernel Config (axonwall-edge-<sku>.kernel.config)
#   3. Single-File UEFI Unified Kernel Image (axonwall-edge-<sku>.efi / BOOTX64.EFI)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PROFILES_DIR="${SCRIPT_DIR}/profiles"
OUTPUT_DIR="${SCRIPT_DIR}/output"

SKU="sku-vm-virtio"
MODE="initramfs-only"
KERNEL_VERSION="6.12.15"
# Pinned upstream kernel.org tarball SHA-256 for Linux 6.12.15 LTS
KERNEL_SHA256="5ff5bd84ea0e22c53437302db5d394d0a92d8b8b1a88ce20d1098298e9f7630a"
EXTRA_CMDLINE=""
HUB_URL="wss://axonwall.local:2966/ws/satellite"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --sku <profile>         Hardware SKU profile name (default: sku-vm-virtio)
                          Available SKUs:
                            - sku-vm-virtio (default — KVM/QEMU/Proxmox/Cloud VirtIO)
                            - sku-x86-intel-n100-i226
                            - sku-x86-enterprise-10g-25g
                            - sku-arm64-router
  --mode <mode>           Build mode: 'initramfs-only' (fast) or 'full-uki' (compiles kernel)
  --hub <wss-url>         Default Axonwall Core Hub WebSocket URL
  --cmdline <args>        Additional kernel command-line arguments baked into UKI
  --list-skus             List available hardware manufacturing SKU profiles
  -h, --help              Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sku)
      SKU="${2:-}"
      shift 2
      ;;
    --mode)
      MODE="${2:-initramfs-only}"
      shift 2
      ;;
    --hub)
      HUB_URL="${2:-}"
      shift 2
      ;;
    --cmdline)
      EXTRA_CMDLINE="${2:-}"
      shift 2
      ;;
    --list-skus)
      for f in "${PROFILES_DIR}"/sku-*.config; do
        basename "${f}" .config
      done
      exit 0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[!] Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

BASE_CONFIG="${PROFILES_DIR}/base-hardened-ngfw.config"
SKU_CONFIG="${PROFILES_DIR}/${SKU}.config"

if [[ ! -f "${BASE_CONFIG}" ]]; then
  echo "[!] ERROR: Missing base kernel config: ${BASE_CONFIG}" >&2
  exit 1
fi
if [[ ! -f "${SKU_CONFIG}" ]]; then
  echo "[!] ERROR: Unknown hardware SKU profile '${SKU}' (expected ${SKU_CONFIG})" >&2
  exit 1
fi

# Extract compiler target metadata from SKU profile header
SKU_ARCH="$(sed -n 's/^# AXONWALL_SKU_ARCH=//p' "${SKU_CONFIG}" | head -n 1 | tr -d '[:space:]')"
SKU_GOAMD64="$(sed -n 's/^# AXONWALL_GOAMD64=//p' "${SKU_CONFIG}" | head -n 1 | tr -d '[:space:]')"
SKU_KCFLAGS="$(sed -n 's/^# AXONWALL_KCFLAGS=//p' "${SKU_CONFIG}" | head -n 1)"
SKU_ARCH="${SKU_ARCH:-amd64}"

mkdir -p "${OUTPUT_DIR}"
WORK_DIR="$(mktemp -d /tmp/axonwall-edge-uki.XXXXXX)"
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "================================================================================"
echo "=== Axonwall Super-Slim Edge NGFW Builder                                    ==="
echo "=== Hardware SKU : ${SKU} (arch=${SKU_ARCH}, GOAMD64=${SKU_GOAMD64:-default})"
echo "=== Build Mode   : ${MODE}"
echo "================================================================================"

# 1. Compile static Go PID 1 binary (CGO_ENABLED=0)
INITRAMFS_ROOT="${WORK_DIR}/initramfs"
mkdir -p \
  "${INITRAMFS_ROOT}/dev" \
  "${INITRAMFS_ROOT}/proc" \
  "${INITRAMFS_ROOT}/sys" \
  "${INITRAMFS_ROOT}/run" \
  "${INITRAMFS_ROOT}/tmp" \
  "${INITRAMFS_ROOT}/sbin" \
  "${INITRAMFS_ROOT}/etc/axonwall/certs" \
  "${INITRAMFS_ROOT}/etc/ssl/certs" \
  "${INITRAMFS_ROOT}/etc/wireguard"

VERSION="$(cat "${REPO_ROOT}/VERSION" 2>/dev/null | tr -d '[:space:]' || echo "0.11.30")"
echo "[+] Compiling static Go PID 1 binary (/init) for ${SKU}..."
(
  cd "${REPO_ROOT}/apps/axonwall-satellite"
  if [[ -n "${SKU_GOAMD64}" ]]; then
    CGO_ENABLED=0 GOOS=linux GOARCH="${SKU_ARCH}" GOAMD64="${SKU_GOAMD64}" \
      go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" \
      -o "${INITRAMFS_ROOT}/init" main.go
  else
    CGO_ENABLED=0 GOOS=linux GOARCH="${SKU_ARCH}" \
      go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" \
      -o "${INITRAMFS_ROOT}/init" main.go
  fi
)
chmod 0755 "${INITRAMFS_ROOT}/init"

# 2. Populate minimal certificates & fail-closed baseline nftables ruleset
if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
  cp /etc/ssl/certs/ca-certificates.crt "${INITRAMFS_ROOT}/etc/ssl/certs/ca-certificates.crt"
fi
if [[ -f "${REPO_ROOT}/packaging/debian/lockdown.nft" ]]; then
  cp "${REPO_ROOT}/packaging/debian/lockdown.nft" "${INITRAMFS_ROOT}/etc/nftables.conf"
fi

cat <<EOF > "${INITRAMFS_ROOT}/etc/axonwall/sku-profile"
SKU=${SKU}
ARCH=${SKU_ARCH}
GOAMD64=${SKU_GOAMD64:-baseline}
VERSION=${VERSION}
EOF

# Verify that NO shell (/bin/sh, /bin/bash, busybox) exists inside the initramfs
if [[ -e "${INITRAMFS_ROOT}/bin/sh" || -e "${INITRAMFS_ROOT}/bin/bash" || -e "${INITRAMFS_ROOT}/bin/busybox" ]]; then
  echo "[!] SECURITY VIOLATION: Shell binary detected inside Super-Slim Edge NGFW initramfs!" >&2
  exit 1
fi

# 3. Pack initramfs cpio.gz archive with root:root ownership
INITRAMFS_OUT="${OUTPUT_DIR}/axonwall-edge-${SKU}-initramfs.cpio.gz"
echo "[+] Packing zero-shell initramfs archive: ${INITRAMFS_OUT}..."
(
  cd "${INITRAMFS_ROOT}"
  find . -print0 | cpio --null -o --format=newc --owner=0:0 2>/dev/null | gzip -9 > "${INITRAMFS_OUT}"
)

# 4. Generate merged monolithic kernel configuration
MERGED_KCONFIG="${OUTPUT_DIR}/axonwall-edge-${SKU}.kernel.config"
DEFAULT_CMDLINE="quiet console=ttyS0,115200 console=tty0 axonwall.sku=${SKU} axonwall.hub=${HUB_URL} ${EXTRA_CMDLINE}"
cat "${BASE_CONFIG}" "${SKU_CONFIG}" > "${MERGED_KCONFIG}"
cat <<EOF >> "${MERGED_KCONFIG}"

# Baked-in UKI Initramfs & Command Line
CONFIG_BLK_DEV_INITRD=y
CONFIG_INITRAMFS_SOURCE="${INITRAMFS_ROOT}"
CONFIG_INITRAMFS_ROOT_UID=0
CONFIG_INITRAMFS_ROOT_GID=0
CONFIG_RD_GZIP=y
CONFIG_INITRAMFS_COMPRESSION_GZIP=y
CONFIG_CMDLINE_BOOL=y
CONFIG_CMDLINE="${DEFAULT_CMDLINE}"
EOF

echo "[✓] Generated merged monolithic kernel config: ${MERGED_KCONFIG}"
sha256sum "${INITRAMFS_OUT}" > "${INITRAMFS_OUT}.sha256"

# Verify critical security invariants in merged config
if ! grep -q "^CONFIG_MODULES=n$" "${MERGED_KCONFIG}"; then
  echo "[!] SECURITY VIOLATION: CONFIG_MODULES=n missing from merged kernel config!" >&2
  exit 1
fi
if ! grep -q "^CONFIG_EFI_STUB=y$" "${MERGED_KCONFIG}"; then
  echo "[!] ERROR: CONFIG_EFI_STUB=y missing from merged kernel config!" >&2
  exit 1
fi

# 5. Optional Full Linux Kernel + Single-File EFI UKI compilation
if [[ "${MODE}" == "full-uki" ]]; then
  CACHE_DIR="${SCRIPT_DIR}/.cache"
  mkdir -p "${CACHE_DIR}"
  TARBALL="${CACHE_DIR}/linux-${KERNEL_VERSION}.tar.xz"
  if [[ ! -f "${TARBALL}" ]]; then
    echo "[+] Downloading Linux ${KERNEL_VERSION} LTS source for full UKI compilation..."
    curl -fsSL -o "${TARBALL}" "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
  fi
  echo "${KERNEL_SHA256}  ${TARBALL}" | sha256sum -c -
  echo "[+] Extracting Linux ${KERNEL_VERSION} source tree..."
  tar -xf "${TARBALL}" -C "${WORK_DIR}"
  KSRC="${WORK_DIR}/linux-${KERNEL_VERSION}"

  echo "[+] Configuring minimalist monolithic kernel for ${SKU} (tinyconfig + SKU fragment)..."
  make -C "${KSRC}" tinyconfig >/dev/null
  KCONFIG_CONFIG="${KSRC}/.config" "${KSRC}/scripts/kconfig/merge_config.sh" -m "${KSRC}/.config" "${MERGED_KCONFIG}" >/dev/null
  make -C "${KSRC}" olddefconfig >/dev/null

  for sym in CONFIG_64BIT=y CONFIG_EFI_STUB=y CONFIG_BLK_DEV_INITRD=y CONFIG_NF_TABLES=y CONFIG_WIREGUARD=y; do
    if ! grep -q "^${sym}$" "${KSRC}/.config"; then
      echo "[!] ERROR: Required kernel symbol ${sym} was dropped after olddefconfig!" >&2
      exit 1
    fi
  done

  echo "[+] Compiling Single-File EFI UKI (bzImage with embedded PID 1 /init) using $(nproc) cores..."
  make -C "${KSRC}" -j"$(nproc)" KCFLAGS="${SKU_KCFLAGS}" bzImage

  UKI_OUT="${OUTPUT_DIR}/axonwall-edge-${SKU}.efi"
  cp "${KSRC}/arch/x86/boot/bzImage" "${UKI_OUT}"
  (cd "${OUTPUT_DIR}" && sha256sum "$(basename "${UKI_OUT}")" > "$(basename "${UKI_OUT}").sha256")
  (cd "${OUTPUT_DIR}" && sha256sum "$(basename "${INITRAMFS_OUT}")" > "$(basename "${INITRAMFS_OUT}").sha256")
  echo "[✓] Built Single-File UEFI Unified Kernel Image: ${UKI_OUT} ($(du -sh "${UKI_OUT}" | awk '{print $1}'))"
fi

INITRAMFS_SIZE="$(du -sh "${INITRAMFS_OUT}" | awk '{print $1}')"
echo "================================================================================"
echo "[✓] Axonwall Super-Slim Edge NGFW Artifacts Ready:"
echo "    Initramfs : ${INITRAMFS_OUT} (${INITRAMFS_SIZE})"
echo "    Kconfig   : ${MERGED_KCONFIG}"
echo "================================================================================"
