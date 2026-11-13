#!/usr/bin/env bash
# ==============================================================================
# Axonwall Hardened Linux Kernel Builder (Universal & Hardware-Stripped)
# ==============================================================================
# Builds either:
#   1. universal   — Debian-13-equivalent broad hardware support + KSPP,
#                    K3s/containers, OpenZFS, nftables, and CO-RE eBPF hardening.
#   2. stripped    — Hardware-locked minimal kernel (`localmodconfig` + host PCI
#                    /NVMe/NIC fragment) stripping unused desktop/legacy drivers.
#   3. config-only — Deterministic Kconfig fragment + sysctl + manifest export
#                    without downloading source or compiling.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FRAGMENTS_DIR="${SCRIPT_DIR}/fragments"
OUTPUT_DIR="${SCRIPT_DIR}/output"

MODE="universal"
KERNEL_VERSION="6.12.15"
# Pinned upstream kernel.org tarball SHA-256 for Linux 6.12.15 LTS
DEFAULT_6_12_15_SHA256="5ff5bd84ea0e22c53437302db5d394d0a92d8b8b1a88ce20d1098298e9f7630a"
KERNEL_SHA256=""
ARCH_ARG="$(uname -m)"
case "${ARCH_ARG}" in
  x86_64|amd64) TARGET_ARCH="amd64" ;;
  aarch64|arm64) TARGET_ARCH="arm64" ;;
  *) TARGET_ARCH="amd64" ;;
esac

CAPABILITIES="k3s,zfs,nftables,ebpf,kvm,ipsec,usb,iscsi_nfs"
LOCKDOWN_TIER="integrity"
MARCH_TARGET=""
LSMOD_FILE=""
HARDWARE_FRAGMENT=""
DISABLE_IA32=0
NO_USERNS=0
FORCE_MODULE_SIG=0
DISABLE_KCORE=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --mode <mode>               Build mode: 'universal' (default), 'stripped', or 'config-only'
  --kernel-version <ver>      Linux kernel version (default: ${KERNEL_VERSION})
  --kernel-sha256 <hex>       Expected SHA-256 of linux-<ver>.tar.xz (required if version != ${KERNEL_VERSION})
  --arch <amd64|arm64>        Target architecture (default: ${TARGET_ARCH})
  --capabilities <csv>        Comma-separated packs (default: ${CAPABILITIES})
                              Valid: k3s, zfs, nftables, ebpf, kvm, ipsec, usb, iscsi_nfs
  --lockdown <tier>           Lockdown LSM mode: 'integrity' (default) or 'confidentiality'
  --march <target>            CPU microarchitecture: x86-64, x86-64-v2, x86-64-v3, x86-64-v4, native, armv8-a
  --lsmod-file <path>         Host lsmod / /proc/modules file for 'make localmodconfig' (stripped mode)
  --hardware-fragment <path>  Optional hardware Kconfig fragment to merge
  --disable-ia32              Disable IA-32 32-bit x86 emulation (CONFIG_IA32_EMULATION=n)
  --no-userns                 Disable unprivileged user namespaces (breaks rootless containers!)
  --force-module-sig          Enforce CONFIG_MODULE_SIG_FORCE=y (requires signed ZFS/OOT kmods)
  --disable-kcore             Disable /proc/kcore exposure (overrides CONFIG_PROC_KCORE=y)
  --output-dir <dir>          Output directory (default: ${OUTPUT_DIR})
  -h, --help                  Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --kernel-version)
      KERNEL_VERSION="${2:-}"
      shift 2
      ;;
    --kernel-sha256)
      KERNEL_SHA256="${2:-}"
      shift 2
      ;;
    --arch)
      TARGET_ARCH="${2:-}"
      shift 2
      ;;
    --capabilities)
      CAPABILITIES="${2:-}"
      shift 2
      ;;
    --lockdown)
      LOCKDOWN_TIER="${2:-}"
      shift 2
      ;;
    --march)
      MARCH_TARGET="${2:-}"
      shift 2
      ;;
    --lsmod-file)
      LSMOD_FILE="${2:-}"
      shift 2
      ;;
    --hardware-fragment)
      HARDWARE_FRAGMENT="${2:-}"
      shift 2
      ;;
    --disable-ia32)
      DISABLE_IA32=1
      shift
      ;;
    --no-userns)
      NO_USERNS=1
      shift
      ;;
    --force-module-sig)
      FORCE_MODULE_SIG=1
      shift
      ;;
    --disable-kcore)
      DISABLE_KCORE=1
      shift
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
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

case "${MODE}" in
  universal|stripped|config-only) ;;
  *)
    echo "[!] Invalid --mode '${MODE}' (expected universal, stripped, or config-only)" >&2
    exit 1
    ;;
esac

if ! [[ "${KERNEL_VERSION}" =~ ^6\.[0-9]+\.[0-9]+$ ]]; then
  echo "[!] Invalid --kernel-version '${KERNEL_VERSION}' (expected 6.x.y)" >&2
  exit 1
fi

if [[ -z "${KERNEL_SHA256}" ]]; then
  if [[ "${KERNEL_VERSION}" == "6.12.15" ]]; then
    KERNEL_SHA256="${DEFAULT_6_12_15_SHA256}"
  elif [[ "${MODE}" != "config-only" ]]; then
    echo "[!] --kernel-sha256 is required when --kernel-version != 6.12.15" >&2
    exit 1
  fi
fi

case "${TARGET_ARCH}" in
  amd64|arm64) ;;
  *)
    echo "[!] Invalid --arch '${TARGET_ARCH}' (expected amd64 or arm64)" >&2
    exit 1
    ;;
esac

case "${LOCKDOWN_TIER}" in
  integrity|confidentiality) ;;
  *)
    echo "[!] Invalid --lockdown '${LOCKDOWN_TIER}' (expected integrity or confidentiality)" >&2
    exit 1
    ;;
esac

if [[ -z "${MARCH_TARGET}" ]]; then
  if [[ "${TARGET_ARCH}" == "arm64" ]]; then
    MARCH_TARGET="armv8-a"
  elif [[ "${MODE}" == "stripped" ]]; then
    MARCH_TARGET="x86-64-v3"
  else
    MARCH_TARGET="x86-64"
  fi
fi

KCFLAGS_VAL=""
case "${MARCH_TARGET}" in
  x86-64)    KCFLAGS_VAL="-O2" ;;
  x86-64-v2) KCFLAGS_VAL="-O2 -march=x86-64-v2" ;;
  x86-64-v3) KCFLAGS_VAL="-O2 -march=x86-64-v3" ;;
  x86-64-v4) KCFLAGS_VAL="-O2 -march=x86-64-v4" ;;
  native)    KCFLAGS_VAL="-O2 -march=native" ;;
  armv8-a)   KCFLAGS_VAL="-O2 -march=armv8-a" ;;
  *)
    echo "[!] Invalid --march '${MARCH_TARGET}'" >&2
    exit 1
    ;;
esac

if [[ -n "${LSMOD_FILE}" && ! -f "${LSMOD_FILE}" ]]; then
  echo "[!] Specified --lsmod-file does not exist: ${LSMOD_FILE}" >&2
  exit 1
fi
if [[ -n "${HARDWARE_FRAGMENT}" && ! -f "${HARDWARE_FRAGMENT}" ]]; then
  echo "[!] Specified --hardware-fragment does not exist: ${HARDWARE_FRAGMENT}" >&2
  exit 1
fi

has_cap() {
  local needle="$1"
  local ifs_save="$IFS"
  IFS=','
  for item in ${CAPABILITIES}; do
    if [[ "${item}" == "${needle}" ]]; then
      IFS="${ifs_save}"
      return 0
    fi
  done
  IFS="${ifs_save}"
  return 1
}

mkdir -p "${OUTPUT_DIR}"
WORK_DIR="$(mktemp -d /tmp/axonwall-kernel-build.XXXXXX)"
trap 'rm -rf "${WORK_DIR}"' EXIT

OVERRIDE_FRAGMENT="${WORK_DIR}/90-cli-overrides.config"
: > "${OVERRIDE_FRAGMENT}"

if [[ "${LOCKDOWN_TIER}" == "confidentiality" ]]; then
  cat >> "${OVERRIDE_FRAGMENT}" <<'EOF'
# CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY is not set
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y
EOF
  if has_cap "ebpf"; then
    echo "[!] WARNING: confidentiality lockdown restricts bpf_probe_read_kernel() & BTF trampolines while eBPF capability is enabled." >&2
  fi
else
  cat >> "${OVERRIDE_FRAGMENT}" <<'EOF'
CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y
# CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY is not set
EOF
fi

if [[ "${DISABLE_IA32}" -eq 1 ]]; then
  echo "# CONFIG_IA32_EMULATION is not set" >> "${OVERRIDE_FRAGMENT}"
fi

if [[ "${NO_USERNS}" -eq 1 ]]; then
  echo "# CONFIG_USER_NS is not set" >> "${OVERRIDE_FRAGMENT}"
  if has_cap "k3s"; then
    echo "[!] WARNING: --no-userns breaks rootless Podman/containerd and K3s user-namespace pods." >&2
  fi
fi

if [[ "${FORCE_MODULE_SIG}" -eq 1 ]]; then
  echo "CONFIG_MODULE_SIG_FORCE=y" >> "${OVERRIDE_FRAGMENT}"
fi

if [[ "${DISABLE_KCORE}" -eq 1 ]]; then
  echo "# CONFIG_PROC_KCORE is not set" >> "${OVERRIDE_FRAGMENT}"
fi

if has_cap "kvm"; then
  cat >> "${OVERRIDE_FRAGMENT}" <<'EOF'
CONFIG_KVM=m
CONFIG_VFIO=m
CONFIG_VFIO_PCI=m
CONFIG_VHOST_NET=m
EOF
else
  cat >> "${OVERRIDE_FRAGMENT}" <<'EOF'
# CONFIG_KVM is not set
# CONFIG_VFIO is not set
EOF
fi

if ! has_cap "ipsec"; then
  cat >> "${OVERRIDE_FRAGMENT}" <<'EOF'
# CONFIG_XFRM_USER is not set
# CONFIG_INET_ESP is not set
EOF
fi

if ! has_cap "usb"; then
  cat >> "${OVERRIDE_FRAGMENT}" <<'EOF'
# CONFIG_USB_STORAGE is not set
# CONFIG_USB_UAS is not set
EOF
fi

if ! has_cap "iscsi_nfs"; then
  cat >> "${OVERRIDE_FRAGMENT}" <<'EOF'
# CONFIG_ISCSI_TCP is not set
# CONFIG_NFSD is not set
# CONFIG_NFS_FS is not set
EOF
fi

# Collect ordered fragments
SELECTED_FRAGMENTS=()
if [[ "${MODE}" != "stripped" || -z "${HARDWARE_FRAGMENT}" ]]; then
  SELECTED_FRAGMENTS+=("${FRAGMENTS_DIR}/00-universal-hardware-base.config")
fi
SELECTED_FRAGMENTS+=("${FRAGMENTS_DIR}/01-kspp-hardening.config")
if has_cap "k3s"; then
  SELECTED_FRAGMENTS+=("${FRAGMENTS_DIR}/02-k3s-containers.config")
fi
if has_cap "zfs"; then
  SELECTED_FRAGMENTS+=("${FRAGMENTS_DIR}/03-storage-zfs.config")
fi
if has_cap "nftables"; then
  SELECTED_FRAGMENTS+=("${FRAGMENTS_DIR}/04-nftables-ngfw.config")
fi
if has_cap "ebpf"; then
  SELECTED_FRAGMENTS+=("${FRAGMENTS_DIR}/05-ebpf-observability.config")
fi
if [[ "${MODE}" == "stripped" ]]; then
  SELECTED_FRAGMENTS+=("${FRAGMENTS_DIR}/06-strip-desktop-bloat.config")
fi
if [[ -n "${HARDWARE_FRAGMENT}" ]]; then
  SELECTED_FRAGMENTS+=("${HARDWARE_FRAGMENT}")
fi
SELECTED_FRAGMENTS+=("${OVERRIDE_FRAGMENT}")

# Deterministically deduplicate CONFIG_* keys (last-wins) so standalone fragments
# are clean and inspectable even in --mode config-only.
MERGED_FRAGMENT_OUT="${OUTPUT_DIR}/axonwall-kernel-${MODE}.fragment.config"
dedup_fragments() {
  local out_file="$1"
  shift
  awk '
    /^[[:space:]]*$/ || /^[[:space:]]*#/ && $0 !~ /^# CONFIG_[A-Za-z0-9_]+ is not set$/ {
      next
    }
    /^# CONFIG_[A-Za-z0-9_]+ is not set$/ {
      key = $2
      if (!(key in seen)) { order[++n] = key; seen[key] = 1 }
      vals[key] = $0
      next
    }
    /^CONFIG_[A-Za-z0-9_]+=/ {
      split($0, parts, "=")
      key = parts[1]
      if (!(key in seen)) { order[++n] = key; seen[key] = 1 }
      vals[key] = $0
      next
    }
    END {
      for (i = 1; i <= n; i++) {
        print vals[order[i]]
      }
    }
  ' "$@" > "${out_file}"
}

{
  echo "# Axonwall Hardened Kernel Fragment (${MODE}, Linux ${KERNEL_VERSION}, ${TARGET_ARCH})"
  echo "# Capabilities: ${CAPABILITIES} | Lockdown: ${LOCKDOWN_TIER} | march: ${MARCH_TARGET}"
  echo ""
  dedup_fragments "${WORK_DIR}/dedup.body" "${SELECTED_FRAGMENTS[@]}"
  cat "${WORK_DIR}/dedup.body"
} > "${MERGED_FRAGMENT_OUT}"

SYSCTL_OUT="${OUTPUT_DIR}/95-axonwall-kernel-hardening.conf"
cp "${FRAGMENTS_DIR}/95-axonwall-kernel-hardening.sysctl.conf" "${SYSCTL_OUT}"
if [[ "${NO_USERNS}" -eq 1 ]]; then
  sed -i 's/^-kernel\.unprivileged_userns_clone = 1$/-kernel.unprivileged_userns_clone = 0/' "${SYSCTL_OUT}"
fi

assert_kconfig_invariants() {
  local cfg="$1"
  local required=(
    "CONFIG_SECURITY_LOCKDOWN_LSM=y"
    "CONFIG_SLAB_FREELIST_HARDENED=y"
  )
  if [[ "${LOCKDOWN_TIER}" == "confidentiality" ]]; then
    required+=("CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y")
  else
    required+=("CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y")
  fi
  if has_cap "ebpf"; then
    required+=("CONFIG_BPF_UNPRIV_DEFAULT_OFF=y" "CONFIG_DEBUG_INFO_BTF=y" "CONFIG_BPF_LSM=y")
  fi
  if has_cap "k3s" && [[ "${NO_USERNS}" -eq 0 ]]; then
    required+=("CONFIG_USER_NS=y" "CONFIG_OVERLAY_FS=y" "CONFIG_CGROUPS=y")
  fi
  if has_cap "nftables"; then
    required+=("CONFIG_NF_TABLES=y" "CONFIG_NFT_FLOW_OFFLOAD=y")
  fi
  for sym in "${required[@]}"; do
    if ! grep -q "^${sym}$" "${cfg}"; then
      echo "[!] KCONFIG INVARIANT FAILED: missing '${sym}' in ${cfg}" >&2
      exit 1
    fi
  done
  if has_cap "zfs"; then
    if grep -q "^CONFIG_TRIM_UNUSED_KSYMS=y$" "${cfg}"; then
      echo "[!] KCONFIG INVARIANT FAILED: CONFIG_TRIM_UNUSED_KSYMS=y breaks external OpenZFS DKMS symbols" >&2
      exit 1
    fi
  fi
}

assert_kconfig_invariants "${MERGED_FRAGMENT_OUT}"

FRAG_SHA256="$(sha256sum "${MERGED_FRAGMENT_OUT}" | awk '{print $1}')"
SYSCTL_SHA256="$(sha256sum "${SYSCTL_OUT}" | awk '{print $1}')"
BUILD_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MANIFEST_OUT="${OUTPUT_DIR}/build-manifest.json"

write_manifest() {
  local deb_json="$1"
  cat > "${MANIFEST_OUT}" <<EOF
{
  "mode": "${MODE}",
  "kernelVersion": "${KERNEL_VERSION}",
  "arch": "${TARGET_ARCH}",
  "capabilities": "${CAPABILITIES}",
  "lockdownTier": "${LOCKDOWN_TIER}",
  "march": "${MARCH_TARGET}",
  "kcflags": "${KCFLAGS_VAL}",
  "builtAt": "${BUILD_TS}",
  "fragmentFile": "$(basename "${MERGED_FRAGMENT_OUT}")",
  "fragmentSha256": "${FRAG_SHA256}",
  "sysctlFile": "$(basename "${SYSCTL_OUT}")",
  "sysctlSha256": "${SYSCTL_SHA256}",
  "packages": ${deb_json}
}
EOF
}

echo "================================================================================"
echo "=== Axonwall Hardened Kernel Builder                                         ==="
echo "=== Mode         : ${MODE} (arch=${TARGET_ARCH}, march=${MARCH_TARGET})"
echo "=== Kernel       : Linux ${KERNEL_VERSION} LTS"
echo "=== Capabilities : ${CAPABILITIES}"
echo "=== Lockdown LSM : ${LOCKDOWN_TIER}"
echo "================================================================================"

if [[ "${MODE}" == "config-only" ]]; then
  write_manifest "[]"
  echo "[✓] Deterministic kernel fragment generated: ${MERGED_FRAGMENT_OUT}"
  echo "[✓] Sysctl hardening profile generated  : ${SYSCTL_OUT}"
  echo "[✓] Manifest generated                  : ${MANIFEST_OUT}"
  exit 0
fi

# Verify host build toolchain before downloading/compiling
MISSING_TOOLS=()
for tool in gcc make flex bison bc pahole dpkg-deb rsync cpio xz zstd openssl tar curl; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    MISSING_TOOLS+=("${tool}")
  fi
done
if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
  echo "[!] Missing kernel build tools: ${MISSING_TOOLS[*]}" >&2
  echo "    Install prerequisites on Debian with:" >&2
  echo "    apt-get update && apt-get install -y build-essential bc flex bison dwarves libssl-dev libelf-dev debhelper dpkg-dev rsync cpio zstd xz-utils" >&2
  exit 1
fi

# Locate or cache Linux kernel source tarball (reuse edge-uki cache if populated)
CACHE_DIR="${SCRIPT_DIR}/.cache"
EDGE_CACHE_TAR="${REPO_ROOT}/packaging/edge-uki/.cache/linux-${KERNEL_VERSION}.tar.xz"
TARBALL="${CACHE_DIR}/linux-${KERNEL_VERSION}.tar.xz"
mkdir -p "${CACHE_DIR}"

if [[ ! -f "${TARBALL}" && -f "${EDGE_CACHE_TAR}" ]]; then
  echo "[+] Reusing cached Linux ${KERNEL_VERSION} tarball from packaging/edge-uki/.cache..."
  cp "${EDGE_CACHE_TAR}" "${TARBALL}"
fi

if [[ ! -f "${TARBALL}" ]]; then
  MAJOR_X="${KERNEL_VERSION%%.*}"
  echo "[+] Downloading Linux ${KERNEL_VERSION} LTS source tarball..."
  curl -fsSL -o "${TARBALL}" "https://cdn.kernel.org/pub/linux/kernel/v${MAJOR_X}.x/linux-${KERNEL_VERSION}.tar.xz"
fi

echo "${KERNEL_SHA256}  ${TARBALL}" | sha256sum -c -
echo "[+] Extracting Linux ${KERNEL_VERSION} source..."
tar -xf "${TARBALL}" -C "${WORK_DIR}"
KSRC="${WORK_DIR}/linux-${KERNEL_VERSION}"

# Seed base .config from running Debian kernel config when available, else defconfig
RUNNING_KVER="$(uname -r)"
KMAKE_ARCH="x86_64"
if [[ "${TARGET_ARCH}" == "arm64" ]]; then
  KMAKE_ARCH="arm64"
fi

if [[ -f "/boot/config-${RUNNING_KVER}" && "${TARGET_ARCH}" == "$(dpkg --print-architecture 2>/dev/null || echo "${TARGET_ARCH}")" ]]; then
  echo "[+] Seeding base config from /boot/config-${RUNNING_KVER}..."
  cp "/boot/config-${RUNNING_KVER}" "${KSRC}/.config"
else
  echo "[+] Generating base ${KMAKE_ARCH} defconfig..."
  make -C "${KSRC}" ARCH="${KMAKE_ARCH}" defconfig >/dev/null
fi

# Clear Debian UEFI certificate paths so bindeb-pkg does not fail looking for debian-uefi-certs.pem
sed -i 's|^CONFIG_SYSTEM_TRUSTED_KEYS=.*|CONFIG_SYSTEM_TRUSTED_KEYS=""|' "${KSRC}/.config"
sed -i 's|^CONFIG_SYSTEM_REVOCATION_KEYS=.*|CONFIG_SYSTEM_REVOCATION_KEYS=""|' "${KSRC}/.config"

if [[ "${MODE}" == "stripped" && -n "${LSMOD_FILE}" ]]; then
  echo "[+] Applying host lsmod strip via make localmodconfig..."
  yes "" | make -C "${KSRC}" ARCH="${KMAKE_ARCH}" LSMOD="${LSMOD_FILE}" localmodconfig >/dev/null
fi

echo "[+] Merging Axonwall hardening & capability fragments..."
KCONFIG_CONFIG="${KSRC}/.config" "${KSRC}/scripts/kconfig/merge_config.sh" -m "${KSRC}/.config" "${MERGED_FRAGMENT_OUT}" >/dev/null
make -C "${KSRC}" ARCH="${KMAKE_ARCH}" olddefconfig >/dev/null

# Re-assert invariants after full kernel dependency resolution
assert_kconfig_invariants "${KSRC}/.config"

LOCALVER="-axonwall-${MODE}"
echo "[+] Compiling Debian kernel packages (${LOCALVER}) with $(nproc) cores..."
make -C "${KSRC}" ARCH="${KMAKE_ARCH}" -j"$(nproc)" \
  KCFLAGS="${KCFLAGS_VAL}" \
  LOCALVERSION="${LOCALVER}" \
  bindeb-pkg

PKG_LIST=()
for deb in "${WORK_DIR}"/linux-*.deb; do
  [[ -e "${deb}" ]] || continue
  base="$(basename "${deb}")"
  cp "${deb}" "${OUTPUT_DIR}/${base}"
  (cd "${OUTPUT_DIR}" && sha256sum "${base}" > "${base}.sha256")
  PKG_LIST+=("\"${base}\"")
done

cp "${KSRC}/.config" "${OUTPUT_DIR}/axonwall-kernel-${MODE}.resolved.config"

DEB_JSON="[]"
if [[ ${#PKG_LIST[@]} -gt 0 ]]; then
  DEB_JSON="[$(IFS=','; echo "${PKG_LIST[*]}")]"
fi
write_manifest "${DEB_JSON}"

echo "================================================================================"
echo "[✓] Built Axonwall Hardened Kernel (${MODE}) in ${OUTPUT_DIR}"
echo "    Manifest : ${MANIFEST_OUT}"
echo "    Sysctl   : ${SYSCTL_OUT}"
echo "================================================================================"
