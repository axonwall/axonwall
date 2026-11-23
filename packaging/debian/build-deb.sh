#!/usr/bin/env bash
# ==============================================================================
# Axonwall Debian Package (.deb) Builder
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORK_DIR="${SCRIPT_DIR}/build"
OUTPUT_DIR="${SCRIPT_DIR}/output"

# Extract version from package.json
VERSION=$(node -p "require('${ROOT_DIR}/package.json').version" 2>/dev/null || echo "0.15.0")
ARCH="amd64"

# D-M9 (round-3): flavor-specific packages. The updater used to fetch the
# NGFW .deb on every box, reintroducing the daemon/UI/controller payload
# the vault and k3s-storage flavors deliberately strip. Josh's decision
# (2026-11-12): flavor-specific package/channel — this script builds
# `axonwall-<edition>_${VERSION}_${ARCH}.deb` for vault and k3s-storage.
# Edition comes from --edition, AXONWALL_EDITION, or AXONWALL_FLAVOR
# (the build-iso.sh name); default axonwall. The payload sections below
# are edition-gated against the ISO builders' strip lists
# (packaging/iso/build-iso.sh, packaging/alpine/build-alpine-iso.sh),
# and a verification guard at the end fails the build if a flavor
# package ever contains NGFW-only payload.
EDITION="${AXONWALL_EDITION:-${AXONWALL_FLAVOR:-axonwall}}"
while [ $# -gt 0 ]; do
  case "$1" in
    --edition)
      EDITION="${2:-axonwall}"
      shift 2
      ;;
    --edition=*)
      EDITION="${1#*=}"
      shift
      ;;
    --help|-h)
      echo "Usage: build-deb.sh [--edition axonwall|minimal|vault|k3s-storage]"
      echo "  Edition may also come from AXONWALL_EDITION or AXONWALL_FLAVOR."
      exit 0
      ;;
    *)
      echo "[!] ERROR: unknown option '$1' (expected --edition or --help)." >&2
      exit 1
      ;;
  esac
done
case "${EDITION}" in
  axonwall|minimal|vault|k3s-storage) ;;
  *)
    echo "[!] ERROR: unknown edition '${EDITION}' (expected axonwall, minimal, vault, or k3s-storage)." >&2
    exit 1
    ;;
esac
if [ "${EDITION}" = "axonwall" ]; then
  PKG_NAME="axonwall_${VERSION}_${ARCH}"
  PKG_DEB_NAME="axonwall"
else
  PKG_NAME="axonwall-${EDITION}_${VERSION}_${ARCH}"
  PKG_DEB_NAME="axonwall-${EDITION}"
fi

echo "================================================================================"
echo "Axonwall Debian Package Builder"
echo "  Package: ${PKG_NAME}.deb"
echo "  Edition: ${EDITION}"
echo "  Version: ${VERSION}"
echo "  Arch   : ${ARCH}"
echo "================================================================================"

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}/DEBIAN" "${OUTPUT_DIR}"

# 1. Generate DEBIAN/control
# D-M9: per-edition metadata. Depends/Recommends are trimmed from the
# NGFW lists against the ISO package lists (build-iso.sh): the vault
# list has no firewall stack (suricata, kea, unbound, frr, strongswan,
# openvpn, conntrackd, keepalived, wireguard-tools, samba, nfs, iscsi)
# and no LDAP/SSSD stack, but keeps ZFS + storage + admin tooling; the
# k3s-storage list is the vault base plus wireguard-tools, iptables and
# bridge-utils for Flannel/CNI. Conflicts is mutual exclusion in both
# directions: a box carries exactly one edition package, so installing
# the wrong edition fails loudly at dpkg instead of file-conflicting.
case "${EDITION}" in
  vault)
    PKG_DEPENDS="nftables (>= 1.1.0), iproute2, openssh-server, openssh-client, libpam-modules, chrony, openssl, curl, wget, jq, ca-certificates, rsync, python3, ethtool, pciutils, tcpdump, kmod, procps, iputils-ping, nano, less, binutils, zstd, xz-utils, bzip2, unzip, zsh, zsh-autosuggestions, zsh-syntax-highlighting, vim, neovim, tmux, fzf, ripgrep, fd-find, bat, mtr-tiny, btop, htop, sysstat, iotop, iftop, slurm, net-tools, dnsutils, bind9-host, nmap, kubectl, mkcert, zfsutils-linux, zfs-initramfs, mdadm, gdisk, parted, smartmontools, xfsprogs, cryptsetup, tpm2-tools, etckeeper, git, rkhunter, chkrootkit, yara, unhide, lynis, debsums, bpftool, python3-drgn, linux-perf"
    PKG_RECOMMENDS="starship, zoxide, plymouth, plymouth-label"
    PKG_CONFLICTS="axonwall, axonwall-minimal, axonwall-k3s-storage"
    PKG_DESC="Axonwall Vault Edition — Immutable S3 Backup Vault"
    PKG_DESC_LONG=$' SeaweedFS-backed immutable backup vault with S3 Object Lock.\n No firewall daemon, web console, or controller — the NGFW payload\n is absent, not disabled.'
    ;;
  k3s-storage)
    PKG_DEPENDS="nftables (>= 1.1.0), iproute2, wireguard-tools, iptables, bridge-utils, openssh-server, openssh-client, libpam-modules, chrony, openssl, curl, wget, jq, ca-certificates, rsync, python3, ethtool, pciutils, tcpdump, kmod, procps, iputils-ping, nano, less, binutils, zstd, xz-utils, bzip2, unzip, zsh, zsh-autosuggestions, zsh-syntax-highlighting, vim, neovim, tmux, fzf, ripgrep, fd-find, bat, mtr-tiny, btop, htop, sysstat, iotop, iftop, slurm, net-tools, dnsutils, bind9-host, nmap, kubectl, mkcert, zfsutils-linux, zfs-initramfs, mdadm, gdisk, parted, smartmontools, xfsprogs, cryptsetup, tpm2-tools, etckeeper, git, rkhunter, chkrootkit, yara, unhide, lynis, debsums, bpftool, python3-drgn, linux-perf"
    PKG_RECOMMENDS="starship, zoxide, plymouth, plymouth-label"
    PKG_CONFLICTS="axonwall, axonwall-minimal, axonwall-vault"
    PKG_DESC="Axonwall K3s-Storage Edition — Barebones K3s + OpenZFS Storage Host"
    PKG_DESC_LONG=$' Lean K3s + OpenZFS + OpenEBS storage host.\n No firewall daemon, web console, or controller — the NGFW payload\n is absent, not disabled.'
    ;;
  minimal)
    PKG_DEPENDS="nftables (>= 1.1.0), iproute2, conntrack, nodejs (>= 20.0.0), openssh-server, openssh-client, slapd, ldap-utils, sssd-ldap, sssd-tools, libnss-sss, libpam-sss, libpam-modules, chrony, openssl, curl, wget, jq, ca-certificates, rsync, python3, sqlite3, ethtool, pciutils, kmod, procps, iputils-ping, nano, less, binutils, zstd, xz-utils, bzip2, unzip"
    PKG_RECOMMENDS="zfsutils-linux, zfs-initramfs, mdadm, gdisk, parted, smartmontools, xfsprogs, cryptsetup, tpm2-tools, cloud-init, cloud-guest-utils, plymouth, plymouth-label"
    PKG_CONFLICTS="axonwall, axonwall-vault, axonwall-k3s-storage"
    PKG_DESC="Axonwall Minimal Edition — Reduced Attack Surface Core Appliance"
    PKG_DESC_LONG=$' Hardened minimal bootable Axonwall host containing only the core\n control plane, Web UI, OpenLDAP/SSSD directory stack, and base OS tooling.\n Roles and plugins can be installed on demand after deployment.'
    ;;
  *)
    PKG_DEPENDS="nftables (>= 1.1.0), iproute2, wireguard-tools, keepalived, conntrack, conntrackd, nodejs (>= 20.0.0), openssh-server, openssh-client, slapd, ldap-utils, sssd-ldap, sssd-tools, libnss-sss, libpam-sss, libpam-modules, chrony, openssl, curl, wget, jq, ca-certificates, rsync, python3, sqlite3, ethtool, pciutils, tcpdump, kmod, procps, iputils-ping, nano, less, binutils, zstd, xz-utils, bzip2, unzip, zsh, zsh-autosuggestions, zsh-syntax-highlighting, vim, neovim, tmux, fzf, ripgrep, fd-find, bat, mtr-tiny, btop, htop, sysstat, iotop, iftop, slurm, net-tools, dnsutils, bind9-host, nmap, kubectl, mkcert"
    PKG_RECOMMENDS="starship, zoxide, unbound, kea-dhcp4-server, frr, suricata, strongswan, openvpn, etckeeper, git, qemu-system-x86, qemu-utils, ovmf, xorriso, bridge-utils, libvirt-clients, lxc, zfsutils-linux, zfs-initramfs, mdadm, gdisk, parted, smartmontools, xfsprogs, cryptsetup, tpm2-tools, samba, nfs-kernel-server, open-iscsi, tgt, cloud-init, cloud-guest-utils, rkhunter, chkrootkit, yara, unhide, lynis, debsums, bpftool, python3-drgn, linux-perf, plymouth, plymouth-label"
    PKG_CONFLICTS="axonwall-minimal, axonwall-vault, axonwall-k3s-storage"
    PKG_DESC="Modern Linux Router & Next-Gen Firewall"
    PKG_DESC_LONG=$' Axonwall replaces legacy BSD/PHP firewalls with a\n modern reactive architecture built on Linux nftables, Next.js, OpenLDAP,\n and a privileged Go daemon with commit-confirm transaction safety.'
    ;;
esac
cat << EOF > "${WORK_DIR}/DEBIAN/control"
Package: ${PKG_DEB_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Axonwall Core Team <ops@axonwall.io>
Depends: ${PKG_DEPENDS}
Recommends: ${PKG_RECOMMENDS}
Conflicts: ${PKG_CONFLICTS}
Homepage: https://axonwall.com
Description: ${PKG_DESC}
${PKG_DESC_LONG}
EOF

# 2. Copy Maintainer scripts
cp "${SCRIPT_DIR}/postinst" "${WORK_DIR}/DEBIAN/postinst"
cp "${SCRIPT_DIR}/prerm" "${WORK_DIR}/DEBIAN/prerm"
cp "${SCRIPT_DIR}/postrm" "${WORK_DIR}/DEBIAN/postrm"
chmod 755 "${WORK_DIR}/DEBIAN/postinst" "${WORK_DIR}/DEBIAN/prerm" "${WORK_DIR}/DEBIAN/postrm"

# 3. Create target directory structure
mkdir -p "${WORK_DIR}/usr/sbin"
mkdir -p "${WORK_DIR}/usr/local/bin"
mkdir -p "${WORK_DIR}/lib/systemd/system"
mkdir -p "${WORK_DIR}/etc/axonwall"
mkdir -p "${WORK_DIR}/etc/sudoers.d"
mkdir -p "${WORK_DIR}/etc/ssh/sshd_config.d"
mkdir -p "${WORK_DIR}/usr/share/axonwall"
mkdir -p "${WORK_DIR}/usr/lib/sysusers.d"
mkdir -p "${WORK_DIR}/usr/lib/tmpfiles.d"
if [[ "${EDITION}" == "axonwall" ]]; then
  mkdir -p "${WORK_DIR}/etc/headscale"
  mkdir -p "${WORK_DIR}/usr/share/axonwall/satellites"
fi
if [[ "${EDITION}" != "minimal" ]]; then
  mkdir -p "${WORK_DIR}/etc/zsh"
  mkdir -p "${WORK_DIR}/etc/skel"
  mkdir -p "${WORK_DIR}/etc/vim"
fi
# D-M9: the /opt/axonwall tree (web console + controller) ships in
# axonwall and minimal only; vault and k3s-storage never ship it.
if [[ "${EDITION}" == "axonwall" || "${EDITION}" == "minimal" ]]; then
  mkdir -p "${WORK_DIR}/opt/axonwall/apps/axonwall"
  mkdir -p "${WORK_DIR}/opt/axonwall/apps/axonwall-controller/dist"
fi

# 4. Copy Binaries
# Core payloads are fail-closed, mirroring the console-binary guard in
# build-iso.sh: a package built without its daemon, UI, or controller
# installs "successfully" and is only discovered broken at service
# start on the target. Optional payloads (satellite bin dir, edge EFI)
# stay conditional below.
# D-M9: the daemon ships in axonwall and minimal (vault and k3s-storage strip it).
if [[ "${EDITION}" == "axonwall" || "${EDITION}" == "minimal" ]]; then
  if [[ -f "${ROOT_DIR}/apps/axonwalld/bin/axonwalld" ]]; then
    cp "${ROOT_DIR}/apps/axonwalld/bin/axonwalld" "${WORK_DIR}/usr/sbin/axonwalld"
    chmod 755 "${WORK_DIR}/usr/sbin/axonwalld"
  else
    echo "[!] ERROR: apps/axonwalld/bin/axonwalld is missing; cannot build deb without the daemon." >&2
    exit 1
  fi
fi

if [[ -f "${ROOT_DIR}/apps/axonwall-console/bin/axonwall-console" ]]; then
  cp "${ROOT_DIR}/apps/axonwall-console/bin/axonwall-console" "${WORK_DIR}/usr/sbin/axonwall-console"
  chmod 755 "${WORK_DIR}/usr/sbin/axonwall-console"
else
  echo "[!] ERROR: apps/axonwall-console/bin/axonwall-console is missing; cannot build deb without the console TUI." >&2
  exit 1
fi

# D-M9: the satellite binary is required for axonwall, shipped inert on
# disk for k3s-storage (mirroring build-iso.sh — no service enabled),
# and absent for vault (build-iso.sh does not ship it there at all).
if [[ "${EDITION}" == "axonwall" ]]; then
  if [[ -f "${ROOT_DIR}/apps/axonwall-satellite/bin/axonwall-satellite-amd64" ]]; then
    cp "${ROOT_DIR}/apps/axonwall-satellite/bin/axonwall-satellite-amd64" "${WORK_DIR}/usr/sbin/axonwall-satellite"
    chmod 755 "${WORK_DIR}/usr/sbin/axonwall-satellite"
  else
    echo "[!] ERROR: apps/axonwall-satellite/bin/axonwall-satellite-amd64 is missing; cannot build deb without the satellite binary." >&2
    exit 1
  fi
elif [[ "${EDITION}" == "k3s-storage" ]]; then
  if [[ -f "${ROOT_DIR}/apps/axonwall-satellite/bin/axonwall-satellite-amd64" ]]; then
    cp "${ROOT_DIR}/apps/axonwall-satellite/bin/axonwall-satellite-amd64" "${WORK_DIR}/usr/sbin/axonwall-satellite"
    chmod 755 "${WORK_DIR}/usr/sbin/axonwall-satellite"
  fi
fi

# Hub TLS certificate rotation tool (audit B-14)
cp "${SCRIPT_DIR}/axonwall-rotate-hub-cert" "${WORK_DIR}/usr/local/bin/axonwall-rotate-hub-cert"
chmod 755 "${WORK_DIR}/usr/local/bin/axonwall-rotate-hub-cert"

# D-M9: the satellites bin dir and the edge UKI are NGFW payload
# (build-iso.sh ships them for the axonwall flavor only; the Alpine
# builder removes the satellites dir for k3s-storage).
if [[ "${EDITION}" == "axonwall" ]]; then
  if [[ -d "${ROOT_DIR}/apps/axonwall-satellite/bin" ]]; then
    cp -r "${ROOT_DIR}/apps/axonwall-satellite/bin/"* "${WORK_DIR}/usr/share/axonwall/satellites/" 2>/dev/null || true
  fi

  if [[ -f "${ROOT_DIR}/packaging/edge-uki/output/axonwall-edge-sku-vm-virtio.efi" ]]; then
    mkdir -p "${WORK_DIR}/usr/lib/axonwall/edge/slot-A"
    cp "${ROOT_DIR}/packaging/edge-uki/output/axonwall-edge-sku-vm-virtio.efi" "${WORK_DIR}/usr/lib/axonwall/edge/slot-A/axonwall-edge-sku-vm-virtio.efi"
    chmod 0644 "${WORK_DIR}/usr/lib/axonwall/edge/slot-A/axonwall-edge-sku-vm-virtio.efi"
  fi
fi

# D-M9: Headscale is NGFW-only (the flavor images strip the mesh
# stack); the download runs for the axonwall edition only.
if [[ "${EDITION}" == "axonwall" ]]; then
# Fetch Headscale binary if absent
HEADSCALE_VERSION="0.29.4"
# Pinned SHA-256 of the upstream release binary (verified from the
# official GitHub release download, 2026-10-16). Bump with the version.
HEADSCALE_SHA256="212ed0a884c0d3541e094c4bebbe94397df6f4e01bd3d7f059c520cb55e0d757"
if [[ ! -f "${WORK_DIR}/usr/sbin/headscale" ]]; then
  echo "[+] Downloading Headscale v${HEADSCALE_VERSION} binary..."
  curl -fsSL -o "${WORK_DIR}/usr/sbin/headscale" "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}/headscale_${HEADSCALE_VERSION}_linux_amd64"
  echo "${HEADSCALE_SHA256}  ${WORK_DIR}/usr/sbin/headscale" | sha256sum -c -
  chmod 755 "${WORK_DIR}/usr/sbin/headscale"
fi
fi

# D-M9: Litestream is NGFW-only (distributed SQLite replication for
# the daemon); the download runs for the axonwall edition only.
if [[ "${EDITION}" == "axonwall" ]]; then
# Fetch Litestream binary if absent
LITESTREAM_VERSION="0.3.13"
# Pinned SHA-256 of the upstream release tarball (verified from the
# official GitHub release download, 2026-10-16). Bump with the version.
# Download/verify failures abort the build (set -e) instead of silently
# shipping a package without -- or with an unverified -- /usr/sbin binary.
LITESTREAM_SHA256="eb75a3de5cab03875cdae9f5f539e6aedadd66607003d9b1e7a9077948818ba0"
if [[ ! -f "${WORK_DIR}/usr/sbin/litestream" ]]; then
  echo "[+] Downloading Litestream v${LITESTREAM_VERSION} binary..."
  LITE_TAR="$(mktemp -t litestream-XXXXXX.tar.gz)"
  curl -fsSL -o "${LITE_TAR}" "https://github.com/benbjohnson/litestream/releases/download/v${LITESTREAM_VERSION}/litestream-v${LITESTREAM_VERSION}-linux-amd64.tar.gz"
  echo "${LITESTREAM_SHA256}  ${LITE_TAR}" | sha256sum -c -
  tar -xzf "${LITE_TAR}" -C "${WORK_DIR}/usr/sbin/" litestream
  chmod 755 "${WORK_DIR}/usr/sbin/litestream"
  rm -f "${LITE_TAR}"
fi
fi

# D-M9: Helm and kubectl are NGFW-only (cluster tooling for the
# firewall's K3s integration); the downloads run for the axonwall
# edition only. The k3s-storage edition gets the k3s binary below, and
# kubectl comes from apt on its ISO image.
if [[ "${EDITION}" == "axonwall" ]]; then
# Fetch Helm v3 binary if absent
HELM_VERSION="3.17.4"
HELM_SHA256="c91e3d7293849eff3b4dc4ea7994c338bcc92f914864d38b5789bab18a1d775d"
if [[ ! -f "${WORK_DIR}/usr/local/bin/helm" ]]; then
  echo "[+] Downloading Helm v${HELM_VERSION} binary..."
  HELM_TAR="$(mktemp -t helm-XXXXXX.tar.gz)"
  curl -fsSL -o "${HELM_TAR}" "https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz"
  echo "${HELM_SHA256}  ${HELM_TAR}" | sha256sum -c -
  tar -xzf "${HELM_TAR}" -C "${WORK_DIR}/usr/local/bin/" --strip-components=1 linux-amd64/helm
  chmod 755 "${WORK_DIR}/usr/local/bin/helm"
  rm -f "${HELM_TAR}"
fi

# Fetch kubectl binary if absent (ensures .deb updates via axonwall-update include kubectl)
KUBECTL_VERSION="1.32.3"
KUBECTL_SHA256="ab209d0c5134b61486a0486585604a616a5bb2fc07df46d304b3c95817b2d79f"
if [[ ! -f "${WORK_DIR}/usr/local/bin/kubectl" ]]; then
  echo "[+] Downloading kubectl v${KUBECTL_VERSION} binary..."
  curl -fsSL -o "${WORK_DIR}/usr/local/bin/kubectl" "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
  echo "${KUBECTL_SHA256}  ${WORK_DIR}/usr/local/bin/kubectl" | sha256sum -c -
  chmod 755 "${WORK_DIR}/usr/local/bin/kubectl"
fi
fi

# D-M9: K3s ships in the axonwall and k3s-storage editions (the
# k3s-storage edition IS the K3s host); it is absent for vault.
#
# Plugin-bundled binaries (core-k3s): k3s + k9s are staged into the
# plugin dir <root>/var/lib/axonwall/core-k3s/bin/ instead of
# /usr/local/bin. Same versions, URLs and pins as before the move.
# write_core_k3s_bundled_json writes the bundled.json verification
# record next to the staged binaries, in exactly the format
# axonwalld's installBundledBinaries writes (relative path + sha256
# of the bytes on disk + manifest entry + kind), so the daemon's
# verifyBundledBinaries passes on the staged tree without a
# re-download. $1 = plugin dir. It records whichever of bin/k3s and
# bin/k9s are staged and executable, and fails the build when
# neither is — a plugin dir with no binaries must never ship a
# record blessing an empty tree.
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

if [[ "${EDITION}" == "axonwall" || "${EDITION}" == "k3s-storage" ]]; then
mkdir -p "${WORK_DIR}/var/lib/axonwall/core-k3s/bin"
# Fetch K3s binary if absent (ensures .deb updates via axonwall-update include k3s)
K3S_VERSION="v1.32.3+k3s1"
K3S_URL_VERSION="v1.32.3%2Bk3s1"
K3S_SHA256="b19216803650b567bf980888dec39035edaf664339c55bc4462f7a003edbef83"
if [[ ! -f "${WORK_DIR}/var/lib/axonwall/core-k3s/bin/k3s" ]]; then
  echo "[+] Downloading K3s ${K3S_VERSION} binary..."
  curl -fsSL -o "${WORK_DIR}/var/lib/axonwall/core-k3s/bin/k3s" "https://github.com/k3s-io/k3s/releases/download/${K3S_URL_VERSION}/k3s"
  echo "${K3S_SHA256}  ${WORK_DIR}/var/lib/axonwall/core-k3s/bin/k3s" | sha256sum -c -
  chmod 755 "${WORK_DIR}/var/lib/axonwall/core-k3s/bin/k3s"
fi
fi

# D-M9: SeaweedFS is the vault's storage engine (pin 4.48, same as
# build-iso.sh — the 4.49 GitHub release is missing its linux binaries).
# It ships in the vault edition only.
if [[ "${EDITION}" == "vault" ]]; then
WEED_VERSION="4.48"
# Pinned SHA-256 of the upstream release tarball (verified from the
# official GitHub release download, 2026-10-23). Bump with the version.
# NOTE: pin 4.48, not 4.49 -- the 4.49 GitHub release is missing its
# linux binaries. A failed download or checksum mismatch fails the
# build (set -e): this binary IS the vault, so shipping without it --
# or with an unverified copy -- is not an option.
WEED_SHA256="4a7d108384d044d95212d1342cdda9533fa55842c1c9b41f606ca3c8a9561124"
if [[ ! -f "${WORK_DIR}/usr/sbin/weed" ]]; then
  echo "[+] Downloading SeaweedFS v${WEED_VERSION} binary..."
  WEED_TAR="$(mktemp -t seaweedfs-XXXXXX.tar.gz)"
  curl -fsSL -o "${WEED_TAR}" "https://github.com/seaweedfs/seaweedfs/releases/download/${WEED_VERSION}/linux_amd64.tar.gz"
  echo "${WEED_SHA256}  ${WEED_TAR}" | sha256sum -c -
  tar -xzf "${WEED_TAR}" -C "${WORK_DIR}/usr/sbin/" weed
  chmod 755 "${WORK_DIR}/usr/sbin/weed"
  rm -f "${WEED_TAR}"
fi
fi

# D-M9: k9s ships only where k3s ships (axonwall + k3s-storage).
# The vault edition has no k3s cluster, so it gets no k9s either:
# before this move the k9s block was not edition-gated and the vault
# .deb shipped a 126 MiB k9s for a cluster that does not exist.
if [[ "${EDITION}" == "axonwall" || "${EDITION}" == "k3s-storage" ]]; then
# Fetch K9s v0.51.0 binary if absent (ensures .deb installs & axonwall-update include k9s CLI)
K9S_VERSION="0.51.0"
K9S_SHA256="c3752ad51a5a4015a113819c4eeb6e55a4d0e4b8e652494797532f6fc8161dd7"
if [[ ! -f "${WORK_DIR}/var/lib/axonwall/core-k3s/bin/k9s" ]]; then
  echo "[+] Downloading K9s v${K9S_VERSION} binary..."
  K9S_TAR="$(mktemp -t k9s-XXXXXX.tar.gz)"
  curl -fsSL -o "${K9S_TAR}" "https://github.com/derailed/k9s/releases/download/v${K9S_VERSION}/k9s_Linux_amd64.tar.gz"
  echo "${K9S_SHA256}  ${K9S_TAR}" | sha256sum -c -
  tar -xzf "${K9S_TAR}" -C "${WORK_DIR}/var/lib/axonwall/core-k3s/bin/" k9s
  chmod 755 "${WORK_DIR}/var/lib/axonwall/core-k3s/bin/k9s"
  rm -f "${K9S_TAR}"
fi
# k3s multicall symlinks in the plugin bin dir (kubectl, crictl,
# ctr -> k3s). The daemon recreates them on core-k3s reconfigure if
# they are ever deleted; nothing is linked into /usr/local/bin.
for _klink in kubectl crictl ctr; do
  ln -sf k3s "${WORK_DIR}/var/lib/axonwall/core-k3s/bin/${_klink}"
done
# Verification record for the staged tree (see the helper above).
write_core_k3s_bundled_json "${WORK_DIR}/var/lib/axonwall/core-k3s" "${K3S_SHA256:-}" "${K9S_SHA256:-}"
fi

# 5. Copy System Scripts & Terminal Configs
CHROOT_SRC="${ROOT_DIR}/packaging/iso/config/includes.chroot"
# D-M9: the script set is edition-gated against build-iso.sh, which
# removes axonwall-firstboot, axonwallctl, axonwall-tui,
# axonwall-ha-notify, axonwall-cloud-init and axonwall-import from the
# flavor trees. axonwall-opshell and axonwall-config ship in all
# editions on main (both builders copy them unconditionally — the
# vault-branch Alpine gate is a branch divergence, not main's rule).
# axonwall-kubeconfig (main, fc576368) is shared too: it lives in
# includes.chroot and neither builder strips it for any flavor.
BIN_SCRIPTS=(
  axonwall-update
  axonwall-opshell
  axonwall-config
  axonwall-install
  axonwall-kubeconfig
  axonwall-zbm-theme
  axonwall-btrfs-grub
)
if [[ "${EDITION}" != "minimal" ]]; then
  BIN_SCRIPTS+=(
    axonwall-hunt-rootkits
    hunt-io-uring-implants.sh
    hunt-ebpf-rootkits.sh
    audit_hidden_bpf_prog_idr.py
  )
fi
if [[ "${EDITION}" == "axonwall" || "${EDITION}" == "minimal" ]]; then
  BIN_SCRIPTS+=(
    axonwall-firstboot
    axonwallctl
    axonwall-tui
    axonwall-cloud-init
  )
fi
if [[ "${EDITION}" == "axonwall" ]]; then
  BIN_SCRIPTS+=(
    axonwall-import
    axonwall-ha-notify
  )
fi
for bin_script in "${BIN_SCRIPTS[@]}"; do
  if [[ -f "${CHROOT_SRC}/usr/local/bin/${bin_script}" ]]; then
    cp "${CHROOT_SRC}/usr/local/bin/${bin_script}" "${WORK_DIR}/usr/local/bin/"
    chmod 755 "${WORK_DIR}/usr/local/bin/${bin_script}"
  else
    # R4-D-M6: fail closed, like the core binaries above. A .deb built
    # without firstboot, the updater, axonwallctl or the installer used to
    # print "[✓] Successfully built" and only be discovered broken on the
    # target. A missing listed script aborts the build instead.
    echo "[!] ERROR: ${CHROOT_SRC}/usr/local/bin/${bin_script} is missing; cannot build deb without ${bin_script}." >&2
    exit 1
  fi
done
# D-M9: flavor tools, mirroring build-iso.sh's flavor units section.
# Fail closed when a flavor tool is missing from the tree — a flavor
# package without its firstboot/provision/verify tools installs
# "successfully" and is only discovered broken at service start.
if [[ "${EDITION}" == "vault" ]]; then
  for vault_bin in axonwall-vault-firstboot axonwall-vault-provision axonwall-vault-status; do
    if [[ -f "${ROOT_DIR}/packaging/vault/${vault_bin}" ]]; then
      cp "${ROOT_DIR}/packaging/vault/${vault_bin}" "${WORK_DIR}/usr/local/bin/"
      chmod 755 "${WORK_DIR}/usr/local/bin/${vault_bin}"
    else
      echo "[!] ERROR: packaging/vault/${vault_bin} is missing; cannot build vault deb without it." >&2
      exit 1
    fi
  done
elif [[ "${EDITION}" == "k3s-storage" ]]; then
  for k3s_bin in axonwall-k3s-firstboot axonwall-k3s-verify axonwall-k3s-status; do
    if [[ -f "${ROOT_DIR}/packaging/k3s-storage/${k3s_bin}" ]]; then
      cp "${ROOT_DIR}/packaging/k3s-storage/${k3s_bin}" "${WORK_DIR}/usr/local/bin/"
      chmod 755 "${WORK_DIR}/usr/local/bin/${k3s_bin}"
    else
      echo "[!] ERROR: packaging/k3s-storage/${k3s_bin} is missing; cannot build k3s-storage deb without it." >&2
      exit 1
    fi
  done
fi
ln -sf axonwall-zbm-theme "${WORK_DIR}/usr/local/bin/generate-zbm"
ln -sf axonwall-zbm-theme "${WORK_DIR}/usr/local/bin/zbm-kcl"

if [[ -f "${ROOT_DIR}/packaging/iso/branding/theme-zbm-uki.py" ]]; then
  mkdir -p "${WORK_DIR}/usr/lib/axonwall"
  cp "${ROOT_DIR}/packaging/iso/branding/theme-zbm-uki.py" "${WORK_DIR}/usr/lib/axonwall/theme-zbm-uki.py"
  chmod 755 "${WORK_DIR}/usr/lib/axonwall/theme-zbm-uki.py"
elif [[ -f "${CHROOT_SRC}/usr/lib/axonwall/theme-zbm-uki.py" ]]; then
  mkdir -p "${WORK_DIR}/usr/lib/axonwall"
  cp "${CHROOT_SRC}/usr/lib/axonwall/theme-zbm-uki.py" "${WORK_DIR}/usr/lib/axonwall/theme-zbm-uki.py"
  chmod 755 "${WORK_DIR}/usr/lib/axonwall/theme-zbm-uki.py"
fi

if [[ "${EDITION}" != "minimal" ]] && [[ -d "${CHROOT_SRC}/etc/axonwall/yara" ]]; then
  mkdir -p "${WORK_DIR}/etc/axonwall/yara"
  cp -a "${CHROOT_SRC}/etc/axonwall/yara/." "${WORK_DIR}/etc/axonwall/yara/"
  chmod -R a+rX "${WORK_DIR}/etc/axonwall/yara"
fi
if [[ -d "${CHROOT_SRC}/etc/axonwall/branding" ]]; then
  mkdir -p "${WORK_DIR}/etc/axonwall/branding"
  cp -a "${CHROOT_SRC}/etc/axonwall/branding/." "${WORK_DIR}/etc/axonwall/branding/"
  chmod -R a+rX "${WORK_DIR}/etc/axonwall/branding"
fi
if [[ -d "${CHROOT_SRC}/etc/zfsbootmenu" ]]; then
  mkdir -p "${WORK_DIR}/etc/zfsbootmenu"
  cp -a "${CHROOT_SRC}/etc/zfsbootmenu/." "${WORK_DIR}/etc/zfsbootmenu/"
  chmod -R a+rX "${WORK_DIR}/etc/zfsbootmenu"
fi
if [[ "${EDITION}" != "minimal" ]] && [[ -f "${CHROOT_SRC}/etc/rkhunter.conf.local" ]]; then
  cp "${CHROOT_SRC}/etc/rkhunter.conf.local" "${WORK_DIR}/etc/rkhunter.conf.local"
  chmod 0644 "${WORK_DIR}/etc/rkhunter.conf.local"
fi
if [[ -f "${CHROOT_SRC}/etc/modprobe.d/axonwall-blacklist.conf" ]]; then
  mkdir -p "${WORK_DIR}/etc/modprobe.d"
  cp "${CHROOT_SRC}/etc/modprobe.d/axonwall-blacklist.conf" "${WORK_DIR}/etc/modprobe.d/axonwall-blacklist.conf"
  chmod 0644 "${WORK_DIR}/etc/modprobe.d/axonwall-blacklist.conf"
fi
if [[ -f "${CHROOT_SRC}/etc/sysctl.d/99-axonwall.conf" ]]; then
  mkdir -p "${WORK_DIR}/etc/sysctl.d"
  cp "${CHROOT_SRC}/etc/sysctl.d/99-axonwall.conf" "${WORK_DIR}/etc/sysctl.d/99-axonwall.conf"
  chmod 0644 "${WORK_DIR}/etc/sysctl.d/99-axonwall.conf"
fi
if [[ -d "${CHROOT_SRC}/etc/axonwall/nvim" ]]; then
  mkdir -p "${WORK_DIR}/etc/axonwall/nvim"
  cp -a "${CHROOT_SRC}/etc/axonwall/nvim/." "${WORK_DIR}/etc/axonwall/nvim/"
  chmod -R a+rX "${WORK_DIR}/etc/axonwall/nvim"
fi
if [[ "${EDITION}" != "minimal" ]] && [[ -f "${CHROOT_SRC}/etc/axonwall/starship.toml" ]]; then
  cp "${CHROOT_SRC}/etc/axonwall/starship.toml" "${WORK_DIR}/etc/axonwall/starship.toml"
  chmod 0644 "${WORK_DIR}/etc/axonwall/starship.toml"
fi
# Release-signing trust anchor: axonwall-update enforces detached
# signatures on downloaded release checksums when this file is
# present (packaging source: includes.chroot/etc/axonwall). Shipping
# it in the .deb as well means .deb-maintained systems enforce too.
# E-M2 (round-3): rotation works through the keyring — a transition
# release signed by the OLD key delivers the NEW anchor (below), and
# the following release can be signed by the new key. See
# release-signing.d/README.md for the full procedure.
if [[ -f "${CHROOT_SRC}/etc/axonwall/release-signing.pub" ]]; then
  cp "${CHROOT_SRC}/etc/axonwall/release-signing.pub" "${WORK_DIR}/etc/axonwall/release-signing.pub"
  chmod 0644 "${WORK_DIR}/etc/axonwall/release-signing.pub"
fi
if [[ -d "${CHROOT_SRC}/etc/axonwall/release-signing.d" ]]; then
  mkdir -p "${WORK_DIR}/etc/axonwall/release-signing.d"
  for _keyring_pub in "${CHROOT_SRC}"/etc/axonwall/release-signing.d/*.pub; do
    [[ -f "$_keyring_pub" ]] || continue
    cp "$_keyring_pub" "${WORK_DIR}/etc/axonwall/release-signing.d/"
    chmod 0644 "${WORK_DIR}/etc/axonwall/release-signing.d/$(basename "$_keyring_pub")"
  done
fi
if [[ "${EDITION}" != "minimal" ]]; then
  if [[ -f "${CHROOT_SRC}/etc/zsh/axonwall.zsh" ]]; then
    cp "${CHROOT_SRC}/etc/zsh/axonwall.zsh" "${WORK_DIR}/etc/zsh/axonwall.zsh"
    chmod 0644 "${WORK_DIR}/etc/zsh/axonwall.zsh"
  fi
  if [[ -f "${CHROOT_SRC}/etc/zsh/zshenv" ]]; then
    cp "${CHROOT_SRC}/etc/zsh/zshenv" "${WORK_DIR}/usr/share/axonwall/zshenv"
    chmod 0644 "${WORK_DIR}/usr/share/axonwall/zshenv"
  fi
  if [[ -f "${CHROOT_SRC}/etc/skel/.zshrc" ]]; then
    cp "${CHROOT_SRC}/etc/skel/.zshrc" "${WORK_DIR}/etc/skel/.zshrc"
    chmod 0644 "${WORK_DIR}/etc/skel/.zshrc"
  fi
  if [[ -d "${CHROOT_SRC}/usr/share/oh-my-zsh" ]]; then
    mkdir -p "${WORK_DIR}/usr/share/oh-my-zsh"
    cp -a "${CHROOT_SRC}/usr/share/oh-my-zsh/." "${WORK_DIR}/usr/share/oh-my-zsh/"
    chmod -R a+rX "${WORK_DIR}/usr/share/oh-my-zsh"
  fi
  if [[ -f "${CHROOT_SRC}/etc/vim/vimrc.local" ]]; then
    cp "${CHROOT_SRC}/etc/vim/vimrc.local" "${WORK_DIR}/etc/vim/vimrc.local"
    chmod 0644 "${WORK_DIR}/etc/vim/vimrc.local"
  fi
  if [[ -f "${CHROOT_SRC}/etc/tmux.conf" ]]; then
    cp "${CHROOT_SRC}/etc/tmux.conf" "${WORK_DIR}/etc/tmux.conf"
    chmod 0644 "${WORK_DIR}/etc/tmux.conf"
  fi
fi
if [[ -f "${CHROOT_SRC}/etc/sudoers.d/axonwall" ]]; then
  cp "${CHROOT_SRC}/etc/sudoers.d/axonwall" "${WORK_DIR}/etc/sudoers.d/axonwall"
  chmod 0440 "${WORK_DIR}/etc/sudoers.d/axonwall"
fi
if [[ -f "${CHROOT_SRC}/etc/ssh/sshd_config.d/axonwall.conf" ]]; then
  cp "${CHROOT_SRC}/etc/ssh/sshd_config.d/axonwall.conf" "${WORK_DIR}/etc/ssh/sshd_config.d/axonwall.conf"
  chmod 0644 "${WORK_DIR}/etc/ssh/sshd_config.d/axonwall.conf"
fi

echo "${VERSION}" > "${WORK_DIR}/etc/axonwall/version"
# D-M9 (marker): the canonical edition file. Every package ships its
# own edition, so the installed system always carries the record the
# updater trusts first. (A regular payload file like `version`, not a
# conffile: the package's edition is authoritative, so an upgrade
# overwrites a hand-edit — same as `version`.)
printf '%s\n' "${EDITION}" > "${WORK_DIR}/etc/axonwall/edition"
# D-M9: the flavor .deb carries its own edition marker, so the package
# is self-describing on the dpkg path (the updater reads the marker
# from the installed root, which the rootfs clone carries).
if [[ "${EDITION}" == "vault" ]]; then
  touch "${WORK_DIR}/etc/axonwall/.vault-edition"
elif [[ "${EDITION}" == "k3s-storage" ]]; then
  touch "${WORK_DIR}/etc/axonwall/.k3s-edition"
elif [[ "${EDITION}" == "minimal" ]]; then
  touch "${WORK_DIR}/etc/axonwall/.minimal-edition"
  printf 'disabled=true\n' > "${WORK_DIR}/etc/axonwall/workstation.disabled"
  chmod 0644 "${WORK_DIR}/etc/axonwall/workstation.disabled"
fi

# 6. Copy Configurations, Rulesets, Systemd, Sysusers
# D-M9: the NGFW baseline ruleset ships in axonwall and minimal; the
# Headscale config is axonwall-only.
if [[ "${EDITION}" == "axonwall" || "${EDITION}" == "minimal" ]]; then
  cp "${SCRIPT_DIR}/lockdown.nft" "${WORK_DIR}/usr/share/axonwall/lockdown.nft"
fi
if [[ "${EDITION}" == "axonwall" ]]; then
  cp "${SCRIPT_DIR}/headscale-config.yaml" "${WORK_DIR}/etc/headscale/config.yaml"
  # The config can carry the OIDC client secret; postinst assigns it to
  # root:axonwall-api on install (all of its readers are group members).
  chmod 0640 "${WORK_DIR}/etc/headscale/config.yaml"
fi
# D-M9: units are edition-gated against build-iso.sh's flavor units
# section. The console unit and the hub-cert-renew pair ship in all
# editions; axonwalld/ui/controller ship in axonwall and minimal;
# headscale/k3s units ship in axonwall only (and k3s-storage uses its own).
cp "${SCRIPT_DIR}/axonwall-console.service" "${WORK_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/axonwall-hub-cert-renew.service" "${WORK_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/axonwall-hub-cert-renew.timer" "${WORK_DIR}/lib/systemd/system/"
if [[ "${EDITION}" == "axonwall" || "${EDITION}" == "minimal" ]]; then
  cp "${SCRIPT_DIR}/axonwalld.service" "${WORK_DIR}/lib/systemd/system/"
  cp "${SCRIPT_DIR}/axonwall-ui.service" "${WORK_DIR}/lib/systemd/system/"
  cp "${SCRIPT_DIR}/axonwall-controller.service" "${WORK_DIR}/lib/systemd/system/"
fi
if [[ "${EDITION}" == "axonwall" ]]; then
  cp "${SCRIPT_DIR}/headscale.service" "${WORK_DIR}/lib/systemd/system/"
  cp "${SCRIPT_DIR}/k3s.service" "${WORK_DIR}/lib/systemd/system/"
elif [[ "${EDITION}" == "vault" ]]; then
  for _unit in seaweedfs.service axonwall-vault-firstboot.service axonwall-vault-provision.service; do
    if [[ -f "${ROOT_DIR}/packaging/vault/${_unit}" ]]; then
      cp "${ROOT_DIR}/packaging/vault/${_unit}" "${WORK_DIR}/lib/systemd/system/"
    else
      echo "[!] ERROR: packaging/vault/${_unit} is missing; cannot build vault deb without it." >&2
      exit 1
    fi
  done
elif [[ "${EDITION}" == "k3s-storage" ]]; then
  for _unit in k3s.service k3s-agent.service axonwall-k3s-firstboot.service axonwall-k3s-verify.service; do
    if [[ -f "${ROOT_DIR}/packaging/k3s-storage/${_unit}" ]]; then
      cp "${ROOT_DIR}/packaging/k3s-storage/${_unit}" "${WORK_DIR}/lib/systemd/system/"
    else
      echo "[!] ERROR: packaging/k3s-storage/${_unit} is missing; cannot build k3s-storage deb without it." >&2
      exit 1
    fi
  done
fi

if [[ -d "${CHROOT_SRC}/usr/share/plymouth/themes/axonwall" ]]; then
  mkdir -p "${WORK_DIR}/usr/share/plymouth/themes/axonwall"
  cp -a "${CHROOT_SRC}/usr/share/plymouth/themes/axonwall/." "${WORK_DIR}/usr/share/plymouth/themes/axonwall/"
  chmod -R a+rX "${WORK_DIR}/usr/share/plymouth/themes/axonwall"
fi
for dropin_dir in plymouth-quit.service.d plymouth-quit-wait.service.d; do
  if [[ -d "${CHROOT_SRC}/etc/systemd/system/${dropin_dir}" ]]; then
    mkdir -p "${WORK_DIR}/lib/systemd/system/${dropin_dir}"
    cp -a "${CHROOT_SRC}/etc/systemd/system/${dropin_dir}/." "${WORK_DIR}/lib/systemd/system/${dropin_dir}/"
    chmod -R a+rX "${WORK_DIR}/lib/systemd/system/${dropin_dir}"
  fi
done

if [[ -f "${CHROOT_SRC}/usr/lib/sysusers.d/axonwall.conf" ]]; then
  if [[ "${EDITION}" == "minimal" ]]; then
    grep -v 'headscale' "${CHROOT_SRC}/usr/lib/sysusers.d/axonwall.conf" > "${WORK_DIR}/usr/lib/sysusers.d/axonwall.conf"
  else
    cp "${CHROOT_SRC}/usr/lib/sysusers.d/axonwall.conf" "${WORK_DIR}/usr/lib/sysusers.d/"
  fi
fi
if [[ -f "${CHROOT_SRC}/usr/lib/tmpfiles.d/axonwall.conf" ]]; then
  if [[ "${EDITION}" == "minimal" ]]; then
    grep -v 'headscale' "${CHROOT_SRC}/usr/lib/tmpfiles.d/axonwall.conf" > "${WORK_DIR}/usr/lib/tmpfiles.d/axonwall.conf"
  else
    cp "${CHROOT_SRC}/usr/lib/tmpfiles.d/axonwall.conf" "${WORK_DIR}/usr/lib/tmpfiles.d/"
  fi
fi
# D-M9: the vault ships its own sysusers/tmpfiles (the axonwall-vault
# user + /var/lib/axonwall/vault), mirroring build-iso.sh.
if [[ "${EDITION}" == "vault" ]]; then
  for _vault_sys in sysusers tmpfiles; do
    if [[ -f "${ROOT_DIR}/packaging/vault/axonwall-vault.${_vault_sys}" ]]; then
      cp "${ROOT_DIR}/packaging/vault/axonwall-vault.${_vault_sys}" "${WORK_DIR}/usr/lib/${_vault_sys}.d/axonwall-vault.conf"
    else
      echo "[!] ERROR: packaging/vault/axonwall-vault.${_vault_sys} is missing; cannot build vault deb without it." >&2
      exit 1
    fi
  done
fi
# D-M9: k3s-storage configs. zfs-operator.yaml is consumed by
# axonwall-k3s-firstboot from /usr/share/axonwall/k3s/; the sysctl and
# modules-load configs are the k3s-storage flavor's (build-iso.sh).
# The flavor nftables.conf is deliberately NOT shipped: the live
# /etc/nftables.conf is carried by the rootfs clone and
# apply_staged_tree does not sync it, so a copy here would have no
# updater-path consumer.
if [[ "${EDITION}" == "k3s-storage" ]]; then
  mkdir -p "${WORK_DIR}/usr/share/axonwall/k3s" "${WORK_DIR}/etc/sysctl.d" "${WORK_DIR}/etc/modules-load.d"
  for _k3s_cfg in "zfs-operator.yaml:usr/share/axonwall/k3s/zfs-operator.yaml" "90-k3s-storage.conf:etc/sysctl.d/90-k3s-storage.conf" "k3s-storage.modules.conf:etc/modules-load.d/k3s-storage.conf"; do
    _src="${_k3s_cfg%%:*}"
    _dst="${_k3s_cfg#*:}"
    if [[ -f "${ROOT_DIR}/packaging/k3s-storage/${_src}" ]]; then
      cp "${ROOT_DIR}/packaging/k3s-storage/${_src}" "${WORK_DIR}/${_dst}"
      chmod 0644 "${WORK_DIR}/${_dst}"
    else
      echo "[!] ERROR: packaging/k3s-storage/${_src} is missing; cannot build k3s-storage deb without it." >&2
      exit 1
    fi
  done
fi

# 7. Bundle Next.js Web Console & Controller
# D-M9: the web console and controller ship in axonwall and minimal;
# vault and k3s-storage deliberately omit /opt/axonwall entirely.
if [[ "${EDITION}" == "axonwall" || "${EDITION}" == "minimal" ]]; then
echo "[+] Bundling Next.js Web Console and Controller..."
if [[ -d "${ROOT_DIR}/apps/axonwall/.next/standalone" ]]; then
  cp -r "${ROOT_DIR}/apps/axonwall/.next/standalone/"* "${WORK_DIR}/opt/axonwall/"
  mkdir -p "${WORK_DIR}/opt/axonwall/apps/axonwall/.next/"
  mkdir -p "${WORK_DIR}/opt/axonwall/.next/"
  if [[ -d "${ROOT_DIR}/apps/axonwall/.next/static" ]]; then
    cp -r "${ROOT_DIR}/apps/axonwall/.next/static" "${WORK_DIR}/opt/axonwall/apps/axonwall/.next/"
    cp -r "${ROOT_DIR}/apps/axonwall/.next/static" "${WORK_DIR}/opt/axonwall/.next/"
  fi
  if [[ -d "${ROOT_DIR}/apps/axonwall/public" ]]; then
    cp -r "${ROOT_DIR}/apps/axonwall/public" "${WORK_DIR}/opt/axonwall/apps/axonwall/"
    cp -r "${ROOT_DIR}/apps/axonwall/public" "${WORK_DIR}/opt/axonwall/"
  fi
else
  echo "[!] ERROR: apps/axonwall/.next/standalone is missing (run the Next.js production build first); cannot build deb without the web console." >&2
  exit 1
fi

if [[ -f "${ROOT_DIR}/apps/axonwall-controller/dist/index.js" ]]; then
  cp "${ROOT_DIR}/apps/axonwall-controller/dist/index.js" "${WORK_DIR}/opt/axonwall/apps/axonwall-controller/dist/"
  cp "${ROOT_DIR}/apps/axonwall-controller/package.json" "${WORK_DIR}/opt/axonwall/apps/axonwall-controller/"
else
  echo "[!] ERROR: apps/axonwall-controller/dist/index.js is missing (run the controller build first); cannot build deb without the controller." >&2
  exit 1
fi
if [[ -f "${ROOT_DIR}/apps/axonwall-controller/dist/axonwallctl.js" ]]; then
  cp "${ROOT_DIR}/apps/axonwall-controller/dist/axonwallctl.js" "${WORK_DIR}/opt/axonwall/apps/axonwall-controller/dist/"
fi
if [[ -f "${ROOT_DIR}/apps/axonwall-controller/dist/axonwall-tui.js" ]]; then
  cp "${ROOT_DIR}/apps/axonwall-controller/dist/axonwall-tui.js" "${WORK_DIR}/opt/axonwall/apps/axonwall-controller/dist/"
fi
fi # EDITION == axonwall|minimal: end of Next.js + controller bundle

# 7b. Declare all packaged /etc files in DEBIAN/conffiles so dpkg preserves operator edits
# D-L7: exclude generated state -- /etc/axonwall/version and
# /etc/axonwall/release-signing.pub are written by the build, not by the
# operator. Listing them as conffiles lets an upgrade with
# --force-confold (as the updater's apt path uses) keep a stale version
# string / stale trust anchor instead of the shipped ones.
# (Main's fc576368 excludes the same two files; the grep -vE form below
# is its equivalent implementation.)
if [[ -d "${WORK_DIR}/etc" ]]; then
  (cd "${WORK_DIR}" && find etc -type f | sed 's|^|/|' | grep -vE '^/etc/axonwall/(version|edition|\.(minimal|vault|k3s)-edition|workstation\.disabled|release-signing\.pub|release-signing\.d/.*)$' | LC_ALL=C sort) > "${WORK_DIR}/DEBIAN/conffiles"
  chmod 0644 "${WORK_DIR}/DEBIAN/conffiles"
fi

# D-M9: build-side guard — a flavor package must never silently be an
# NGFW-equivalent package. The copy sections above are edition-gated;
# this is defense in depth against a future edit re-adding a payload
# unconditionally. Fail the build on any forbidden file in a flavor
# package, and on a flavor package missing its own required payload.
if [[ "${EDITION}" == "vault" || "${EDITION}" == "k3s-storage" ]]; then
  for _ngfw_file in \
    usr/sbin/axonwalld usr/sbin/headscale usr/sbin/litestream \
    usr/local/bin/helm usr/local/bin/kubectl \
    usr/local/bin/axonwallctl usr/local/bin/axonwall-tui \
    usr/local/bin/axonwall-firstboot usr/local/bin/axonwall-import \
    usr/local/bin/axonwall-ha-notify usr/local/bin/axonwall-cloud-init \
    lib/systemd/system/axonwalld.service \
    lib/systemd/system/axonwall-ui.service \
    lib/systemd/system/axonwall-controller.service \
    lib/systemd/system/headscale.service \
    etc/headscale/config.yaml usr/share/axonwall/lockdown.nft; do
    if [[ -e "${WORK_DIR}/${_ngfw_file}" ]]; then
      echo "[!] ERROR: flavor package '${PKG_NAME}' contains NGFW-only payload '${_ngfw_file}'; refusing to build an NGFW-equivalent ${EDITION} package." >&2
      exit 1
    fi
  done
  # Content, not mere existence: the skeleton dirs above are created
  # for the axonwall/minimal editions only, but a future unconditional
  # mkdir must not trip this — only an actual payload file does.
  if [[ -d "${WORK_DIR}/opt/axonwall" ]] && [[ -n "$(find "${WORK_DIR}/opt/axonwall" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
    echo "[!] ERROR: flavor package '${PKG_NAME}' contains /opt/axonwall (web console + controller); refusing to build." >&2
    exit 1
  fi
  if [[ "${EDITION}" == "vault" ]]; then
    [[ -f "${WORK_DIR}/etc/axonwall/.vault-edition" ]] || { echo "[!] ERROR: vault package is missing its .vault-edition marker." >&2; exit 1; }
    [[ -x "${WORK_DIR}/usr/sbin/weed" ]] || { echo "[!] ERROR: vault package is missing the weed binary." >&2; exit 1; }
    [[ -f "${WORK_DIR}/lib/systemd/system/seaweedfs.service" ]] || { echo "[!] ERROR: vault package is missing seaweedfs.service." >&2; exit 1; }
    [[ -f "${WORK_DIR}/lib/systemd/system/axonwall-vault-firstboot.service" ]] || { echo "[!] ERROR: vault package is missing axonwall-vault-firstboot.service." >&2; exit 1; }
    [[ -f "${WORK_DIR}/lib/systemd/system/axonwall-vault-provision.service" ]] || { echo "[!] ERROR: vault package is missing axonwall-vault-provision.service." >&2; exit 1; }
  elif [[ "${EDITION}" == "k3s-storage" ]]; then
    [[ -f "${WORK_DIR}/etc/axonwall/.k3s-edition" ]] || { echo "[!] ERROR: k3s-storage package is missing its .k3s-edition marker." >&2; exit 1; }
    [[ -x "${WORK_DIR}/var/lib/axonwall/core-k3s/bin/k3s" ]] || { echo "[!] ERROR: k3s-storage package is missing the k3s binary." >&2; exit 1; }
    [[ -x "${WORK_DIR}/var/lib/axonwall/core-k3s/bin/k9s" ]] || { echo "[!] ERROR: k3s-storage package is missing the k9s binary." >&2; exit 1; }
    [[ -f "${WORK_DIR}/var/lib/axonwall/core-k3s/bundled.json" ]] || { echo "[!] ERROR: k3s-storage package is missing the core-k3s bundled.json verification record." >&2; exit 1; }
    [[ -f "${WORK_DIR}/lib/systemd/system/k3s.service" ]] || { echo "[!] ERROR: k3s-storage package is missing k3s.service." >&2; exit 1; }
    [[ -f "${WORK_DIR}/lib/systemd/system/k3s-agent.service" ]] || { echo "[!] ERROR: k3s-storage package is missing k3s-agent.service." >&2; exit 1; }
    [[ -f "${WORK_DIR}/usr/share/axonwall/k3s/zfs-operator.yaml" ]] || { echo "[!] ERROR: k3s-storage package is missing zfs-operator.yaml." >&2; exit 1; }
  fi
elif [[ "${EDITION}" == "minimal" ]]; then
  for _min_forbidden in \
    usr/sbin/headscale usr/sbin/litestream usr/sbin/axonwall-satellite \
    usr/local/bin/helm usr/local/bin/kubectl \
    usr/local/bin/axonwall-import usr/local/bin/axonwall-ha-notify \
    usr/local/bin/axonwall-hunt-rootkits usr/local/bin/hunt-io-uring-implants.sh \
    usr/local/bin/hunt-ebpf-rootkits.sh usr/local/bin/audit_hidden_bpf_prog_idr.py \
    lib/systemd/system/headscale.service lib/systemd/system/k3s.service \
    etc/headscale/config.yaml etc/rkhunter.conf.local etc/axonwall/starship.toml \
    etc/zsh/axonwall.zsh usr/share/axonwall/zshenv etc/skel/.zshrc \
    etc/vim/vimrc.local etc/tmux.conf \
    var/lib/axonwall/core-k3s/bin/k3s var/lib/axonwall/core-k3s/bin/k9s \
    usr/share/oh-my-zsh/oh-my-zsh.sh etc/axonwall/yara/ghost_in_the_ring.yar; do
    if [[ -e "${WORK_DIR}/${_min_forbidden}" ]]; then
      echo "[!] ERROR: minimal package '${PKG_NAME}' contains stripped payload '${_min_forbidden}'; refusing to build." >&2
      exit 1
    fi
  done
  for _min_dir in usr/share/axonwall/satellites usr/lib/axonwall/edge; do
    if [[ -d "${WORK_DIR}/${_min_dir}" ]] && [[ -n "$(find "${WORK_DIR}/${_min_dir}" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
      echo "[!] ERROR: minimal package '${PKG_NAME}' contains stripped directory '${_min_dir}'; refusing to build." >&2
      exit 1
    fi
  done
  for _min_req in \
    etc/axonwall/.minimal-edition etc/axonwall/workstation.disabled \
    usr/sbin/axonwalld usr/sbin/axonwall-console \
    opt/axonwall/apps/axonwall-controller/dist/index.js \
    lib/systemd/system/axonwalld.service \
    lib/systemd/system/axonwall-ui.service \
    lib/systemd/system/axonwall-controller.service \
    lib/systemd/system/axonwall-console.service \
    usr/share/axonwall/lockdown.nft; do
    if [[ ! -e "${WORK_DIR}/${_min_req}" ]]; then
      echo "[!] ERROR: minimal package '${PKG_NAME}' is missing required payload '${_min_req}'." >&2
      exit 1
    fi
  done
fi

# D-M9 (marker): every package must ship its canonical edition file
# with exactly its own edition — the updater trusts this file first,
# so a package without it (or with the wrong value) would leave the
# installed box's edition in question.
if [[ "$(tr -d ' \t\r\n' < "${WORK_DIR}/etc/axonwall/edition" 2>/dev/null || true)" != "${EDITION}" ]]; then
  echo "[!] ERROR: package '${PKG_NAME}' is missing /etc/axonwall/edition or it does not contain '${EDITION}'." >&2
  exit 1
fi

# 8. Build Debian Archive via dpkg-deb (or docker fallback if dpkg-deb is absent)
echo "[+] Building deb package: ${PKG_NAME}.deb..."
if command -v dpkg-deb &>/dev/null; then
  dpkg-deb -Zxz --build --root-owner-group "${WORK_DIR}" "${OUTPUT_DIR}/${PKG_NAME}.deb"
elif command -v docker &>/dev/null; then
  echo "[+] Running dpkg-deb inside debian:trixie container..."
  docker run --rm \
    -v "${SCRIPT_DIR}:/workspace" \
    debian:trixie \
    dpkg-deb -Zxz --build --root-owner-group "/workspace/build" "/workspace/output/${PKG_NAME}.deb"
else
  echo "[-] Error: Neither dpkg-deb nor docker is available to build .deb" >&2
  exit 1
fi

(cd "${OUTPUT_DIR}" && sha256sum "${PKG_NAME}.deb" > "${PKG_NAME}.deb.sha256")
echo "================================================================================"
echo "[✓] Successfully built Axonwall Debian Package:"
echo "    ${OUTPUT_DIR}/${PKG_NAME}.deb"
echo "    ${OUTPUT_DIR}/${PKG_NAME}.deb.sha256"
echo "================================================================================"
