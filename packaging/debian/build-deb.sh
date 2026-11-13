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
VERSION=$(node -p "require('${ROOT_DIR}/package.json').version" 2>/dev/null || echo "0.11.68")
ARCH="amd64"
PKG_NAME="axonwall_${VERSION}_${ARCH}"

echo "================================================================================"
echo "Axonwall Debian Package Builder"
echo "  Package: ${PKG_NAME}.deb"
echo "  Version: ${VERSION}"
echo "  Arch   : ${ARCH}"
echo "================================================================================"

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}/DEBIAN" "${OUTPUT_DIR}"

# 1. Generate DEBIAN/control
cat << EOF > "${WORK_DIR}/DEBIAN/control"
Package: axonwall
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Axonwall Core Team <ops@axonwall.io>
Depends: nftables (>= 1.0.0), iproute2, wireguard-tools, keepalived, conntrack, conntrackd, nodejs (>= 20.0.0), openssh-server, openssh-client, slapd, ldap-utils, sssd-ldap, sssd-tools, libnss-sss, libpam-sss, libpam-modules, chrony, openssl, curl, wget, jq, ca-certificates, rsync, python3, sqlite3, ethtool, pciutils, tcpdump, kmod, procps, iputils-ping, nano, less, binutils, zstd, xz-utils, bzip2, unzip, zsh, zsh-autosuggestions, zsh-syntax-highlighting, vim, neovim, tmux, fzf, ripgrep, fd-find, bat, mtr-tiny, btop, htop, sysstat, iotop, iftop, slurm, net-tools, dnsutils, bind9-host, nmap, kubectl, mkcert
Recommends: starship, zoxide, unbound, kea-dhcp4-server, frr, suricata, strongswan, openvpn, etckeeper, git, qemu-system-x86, qemu-utils, ovmf, xorriso, bridge-utils, libvirt-clients, lxc, zfsutils-linux, zfs-initramfs, mdadm, gdisk, parted, smartmontools, xfsprogs, cryptsetup, tpm2-tools, samba, nfs-kernel-server, open-iscsi, tgt, cloud-init, cloud-guest-utils, rkhunter, chkrootkit, yara, unhide, lynis, debsums, bpftool, python3-drgn, linux-perf
Homepage: https://axonwall.com
Description: Modern Linux Router & Next-Gen Firewall
 Axonwall replaces legacy BSD/PHP firewalls with a
 modern reactive architecture built on Linux nftables, Next.js, OpenLDAP,
 and a privileged Go daemon with commit-confirm transaction safety.
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
mkdir -p "${WORK_DIR}/etc/headscale"
mkdir -p "${WORK_DIR}/etc/sudoers.d"
mkdir -p "${WORK_DIR}/etc/ssh/sshd_config.d"
mkdir -p "${WORK_DIR}/etc/zsh"
mkdir -p "${WORK_DIR}/etc/skel"
mkdir -p "${WORK_DIR}/etc/vim"
mkdir -p "${WORK_DIR}/usr/share/axonwall"
mkdir -p "${WORK_DIR}/usr/share/axonwall/satellites"
mkdir -p "${WORK_DIR}/usr/lib/sysusers.d"
mkdir -p "${WORK_DIR}/usr/lib/tmpfiles.d"
mkdir -p "${WORK_DIR}/opt/axonwall/apps/axonwall"
mkdir -p "${WORK_DIR}/opt/axonwall/apps/axonwall-controller/dist"

# 4. Copy Binaries
# Core payloads are fail-closed, mirroring the console-binary guard in
# build-iso.sh: a package built without its daemon, UI, or controller
# installs "successfully" and is only discovered broken at service
# start on the target. Optional payloads (satellite bin dir, edge EFI)
# stay conditional below.
if [[ -f "${ROOT_DIR}/apps/axonwalld/bin/axonwalld" ]]; then
  cp "${ROOT_DIR}/apps/axonwalld/bin/axonwalld" "${WORK_DIR}/usr/sbin/axonwalld"
  chmod 755 "${WORK_DIR}/usr/sbin/axonwalld"
else
  echo "[!] ERROR: apps/axonwalld/bin/axonwalld is missing; cannot build deb without the daemon." >&2
  exit 1
fi

if [[ -f "${ROOT_DIR}/apps/axonwall-console/bin/axonwall-console" ]]; then
  cp "${ROOT_DIR}/apps/axonwall-console/bin/axonwall-console" "${WORK_DIR}/usr/sbin/axonwall-console"
  chmod 755 "${WORK_DIR}/usr/sbin/axonwall-console"
else
  echo "[!] ERROR: apps/axonwall-console/bin/axonwall-console is missing; cannot build deb without the console TUI." >&2
  exit 1
fi

if [[ -f "${ROOT_DIR}/apps/axonwall-satellite/bin/axonwall-satellite-amd64" ]]; then
  cp "${ROOT_DIR}/apps/axonwall-satellite/bin/axonwall-satellite-amd64" "${WORK_DIR}/usr/sbin/axonwall-satellite"
  chmod 755 "${WORK_DIR}/usr/sbin/axonwall-satellite"
else
  echo "[!] ERROR: apps/axonwall-satellite/bin/axonwall-satellite-amd64 is missing; cannot build deb without the satellite binary." >&2
  exit 1
fi

# Hub TLS certificate rotation tool (audit B-14)
cp "${SCRIPT_DIR}/axonwall-rotate-hub-cert" "${WORK_DIR}/usr/local/bin/axonwall-rotate-hub-cert"
chmod 755 "${WORK_DIR}/usr/local/bin/axonwall-rotate-hub-cert"

if [[ -d "${ROOT_DIR}/apps/axonwall-satellite/bin" ]]; then
  cp -r "${ROOT_DIR}/apps/axonwall-satellite/bin/"* "${WORK_DIR}/usr/share/axonwall/satellites/" 2>/dev/null || true
fi

if [[ -f "${ROOT_DIR}/packaging/edge-uki/output/axonwall-edge-sku-vm-virtio.efi" ]]; then
  mkdir -p "${WORK_DIR}/usr/lib/axonwall/edge/slot-A"
  cp "${ROOT_DIR}/packaging/edge-uki/output/axonwall-edge-sku-vm-virtio.efi" "${WORK_DIR}/usr/lib/axonwall/edge/slot-A/axonwall-edge-sku-vm-virtio.efi"
  chmod 0644 "${WORK_DIR}/usr/lib/axonwall/edge/slot-A/axonwall-edge-sku-vm-virtio.efi"
fi

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

# Fetch K3s binary if absent (ensures .deb updates via axonwall-update include k3s)
K3S_VERSION="v1.32.3+k3s1"
K3S_URL_VERSION="v1.32.3%2Bk3s1"
K3S_SHA256="b19216803650b567bf980888dec39035edaf664339c55bc4462f7a003edbef83"
if [[ ! -f "${WORK_DIR}/usr/local/bin/k3s" ]]; then
  echo "[+] Downloading K3s ${K3S_VERSION} binary..."
  curl -fsSL -o "${WORK_DIR}/usr/local/bin/k3s" "https://github.com/k3s-io/k3s/releases/download/${K3S_URL_VERSION}/k3s"
  echo "${K3S_SHA256}  ${WORK_DIR}/usr/local/bin/k3s" | sha256sum -c -
  chmod 755 "${WORK_DIR}/usr/local/bin/k3s"
fi

# 5. Copy System Scripts & Terminal Configs
CHROOT_SRC="${ROOT_DIR}/packaging/iso/config/includes.chroot"
for bin_script in \
  axonwall-firstboot \
  axonwall-import \
  axonwall-ha-notify \
  axonwall-update \
  axonwall-opshell \
  axonwallctl \
  axonwall-tui \
  axonwall-config \
  axonwall-install \
  axonwall-cloud-init \
  axonwall-zbm-theme \
  axonwall-hunt-rootkits \
  hunt-io-uring-implants.sh \
  hunt-ebpf-rootkits.sh \
  audit_hidden_bpf_prog_idr.py
do
  if [[ -f "${CHROOT_SRC}/usr/local/bin/${bin_script}" ]]; then
    cp "${CHROOT_SRC}/usr/local/bin/${bin_script}" "${WORK_DIR}/usr/local/bin/"
    chmod 755 "${WORK_DIR}/usr/local/bin/${bin_script}"
  fi
done
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

if [[ -d "${CHROOT_SRC}/etc/axonwall/yara" ]]; then
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
if [[ -f "${CHROOT_SRC}/etc/rkhunter.conf.local" ]]; then
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
if [[ -f "${CHROOT_SRC}/etc/axonwall/starship.toml" ]]; then
  cp "${CHROOT_SRC}/etc/axonwall/starship.toml" "${WORK_DIR}/etc/axonwall/starship.toml"
  chmod 0644 "${WORK_DIR}/etc/axonwall/starship.toml"
fi
# Release-signing trust anchor: axonwall-update enforces detached
# signatures on downloaded release checksums when this file is
# present (packaging source: includes.chroot/etc/axonwall). Shipping
# it in the .deb as well means .deb-maintained systems enforce too,
# and a future key rotation can deliver the new anchor inside a
# release whose download was verified against the old one.
if [[ -f "${CHROOT_SRC}/etc/axonwall/release-signing.pub" ]]; then
  cp "${CHROOT_SRC}/etc/axonwall/release-signing.pub" "${WORK_DIR}/etc/axonwall/release-signing.pub"
  chmod 0644 "${WORK_DIR}/etc/axonwall/release-signing.pub"
fi
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
if [[ -f "${CHROOT_SRC}/etc/sudoers.d/axonwall" ]]; then
  cp "${CHROOT_SRC}/etc/sudoers.d/axonwall" "${WORK_DIR}/etc/sudoers.d/axonwall"
  chmod 0440 "${WORK_DIR}/etc/sudoers.d/axonwall"
fi
if [[ -f "${CHROOT_SRC}/etc/ssh/sshd_config.d/axonwall.conf" ]]; then
  cp "${CHROOT_SRC}/etc/ssh/sshd_config.d/axonwall.conf" "${WORK_DIR}/etc/ssh/sshd_config.d/axonwall.conf"
  chmod 0644 "${WORK_DIR}/etc/ssh/sshd_config.d/axonwall.conf"
fi

echo "${VERSION}" > "${WORK_DIR}/etc/axonwall/version"

# 6. Copy Configurations, Rulesets, Systemd, Sysusers
cp "${SCRIPT_DIR}/lockdown.nft" "${WORK_DIR}/usr/share/axonwall/lockdown.nft"
cp "${SCRIPT_DIR}/headscale-config.yaml" "${WORK_DIR}/etc/headscale/config.yaml"
# The config can carry the OIDC client secret; postinst assigns it to
# root:axonwall-api on install (all of its readers are group members).
chmod 0640 "${WORK_DIR}/etc/headscale/config.yaml"
cp "${SCRIPT_DIR}/axonwalld.service" "${WORK_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/axonwall-ui.service" "${WORK_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/axonwall-controller.service" "${WORK_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/axonwall-console.service" "${WORK_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/headscale.service" "${WORK_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/k3s.service" "${WORK_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/axonwall-hub-cert-renew.service" "${WORK_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/axonwall-hub-cert-renew.timer" "${WORK_DIR}/lib/systemd/system/"

if [[ -f "${CHROOT_SRC}/usr/lib/sysusers.d/axonwall.conf" ]]; then
  cp "${CHROOT_SRC}/usr/lib/sysusers.d/axonwall.conf" "${WORK_DIR}/usr/lib/sysusers.d/"
fi
if [[ -f "${CHROOT_SRC}/usr/lib/tmpfiles.d/axonwall.conf" ]]; then
  cp "${CHROOT_SRC}/usr/lib/tmpfiles.d/axonwall.conf" "${WORK_DIR}/usr/lib/tmpfiles.d/"
fi

# 7. Bundle Next.js Web Console & Controller
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

# 7b. Declare all packaged /etc files in DEBIAN/conffiles so dpkg preserves operator edits
if [[ -d "${WORK_DIR}/etc" ]]; then
  (cd "${WORK_DIR}" && find etc -type f | sed 's|^|/|' | LC_ALL=C sort) > "${WORK_DIR}/DEBIAN/conffiles"
  chmod 0644 "${WORK_DIR}/DEBIAN/conffiles"
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
