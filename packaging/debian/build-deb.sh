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
VERSION=$(node -p "require('${ROOT_DIR}/package.json').version" 2>/dev/null || echo "0.11.22")
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
Depends: nftables (>= 1.0.0), iproute2, wireguard-tools, keepalived, conntrackd, nodejs (>= 20.0.0), openssh-server, openssh-client, slapd, ldap-utils, sssd-ldap, sssd-tools, libnss-sss, libpam-sss, libpam-modules, chrony, openssl, curl, ca-certificates, rsync, python3, zsh, zsh-autosuggestions, zsh-syntax-highlighting, vim, tmux, fzf, ripgrep, fd-find, bat, mtr-tiny, btop, htop, sysstat, iotop, iftop, slurm, net-tools, dnsutils, nmap
Recommends: starship, zoxide, unbound, kea-dhcp4-server, frr, suricata, strongswan, openvpn, etckeeper, git
Homepage: https://axonwall.com
Description: Modern Linux Router & Next-Gen Firewall
 Axonwall replaces legacy BSD/PHP firewalls (OPNsense/pfSense) with a
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
if [[ -f "${ROOT_DIR}/apps/axonwalld/bin/axonwalld" ]]; then
  cp "${ROOT_DIR}/apps/axonwalld/bin/axonwalld" "${WORK_DIR}/usr/sbin/axonwalld"
  chmod 755 "${WORK_DIR}/usr/sbin/axonwalld"
fi

if [[ -f "${ROOT_DIR}/apps/axonwall-console/bin/axonwall-console" ]]; then
  cp "${ROOT_DIR}/apps/axonwall-console/bin/axonwall-console" "${WORK_DIR}/usr/sbin/axonwall-console"
  chmod 755 "${WORK_DIR}/usr/sbin/axonwall-console"
fi

if [[ -f "${ROOT_DIR}/apps/axonwall-satellite/bin/axonwall-satellite-amd64" ]]; then
  cp "${ROOT_DIR}/apps/axonwall-satellite/bin/axonwall-satellite-amd64" "${WORK_DIR}/usr/sbin/axonwall-satellite"
  chmod 755 "${WORK_DIR}/usr/sbin/axonwall-satellite"
fi

# Hub TLS certificate rotation tool (audit B-14)
cp "${SCRIPT_DIR}/axonwall-rotate-hub-cert" "${WORK_DIR}/usr/local/bin/axonwall-rotate-hub-cert"
chmod 755 "${WORK_DIR}/usr/local/bin/axonwall-rotate-hub-cert"

if [[ -d "${ROOT_DIR}/apps/axonwall-satellite/bin" ]]; then
  cp -r "${ROOT_DIR}/apps/axonwall-satellite/bin/"* "${WORK_DIR}/usr/share/axonwall/satellites/" 2>/dev/null || true
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

# 5. Copy System Scripts & Terminal Configs
CHROOT_SRC="${ROOT_DIR}/packaging/iso/config/includes.chroot"
if [[ -f "${CHROOT_SRC}/usr/local/bin/axonwall-firstboot" ]]; then
  cp "${CHROOT_SRC}/usr/local/bin/axonwall-firstboot" "${WORK_DIR}/usr/local/bin/"
  chmod 755 "${WORK_DIR}/usr/local/bin/axonwall-firstboot"
fi
if [[ -f "${CHROOT_SRC}/usr/local/bin/axonwall-import" ]]; then
  cp "${CHROOT_SRC}/usr/local/bin/axonwall-import" "${WORK_DIR}/usr/local/bin/"
  chmod 755 "${WORK_DIR}/usr/local/bin/axonwall-import"
fi
if [[ -f "${CHROOT_SRC}/usr/local/bin/axonwall-ha-notify" ]]; then
  cp "${CHROOT_SRC}/usr/local/bin/axonwall-ha-notify" "${WORK_DIR}/usr/local/bin/"
  chmod 755 "${WORK_DIR}/usr/local/bin/axonwall-ha-notify"
fi
if [[ -f "${CHROOT_SRC}/usr/local/bin/axonwall-update" ]]; then
  cp "${CHROOT_SRC}/usr/local/bin/axonwall-update" "${WORK_DIR}/usr/local/bin/"
  chmod 755 "${WORK_DIR}/usr/local/bin/axonwall-update"
fi
if [[ -f "${CHROOT_SRC}/usr/local/bin/axonwall-opshell" ]]; then
  cp "${CHROOT_SRC}/usr/local/bin/axonwall-opshell" "${WORK_DIR}/usr/local/bin/"
  chmod 755 "${WORK_DIR}/usr/local/bin/axonwall-opshell"
fi
if [[ -f "${CHROOT_SRC}/usr/local/bin/axonwallctl" ]]; then
  cp "${CHROOT_SRC}/usr/local/bin/axonwallctl" "${WORK_DIR}/usr/local/bin/"
  chmod 755 "${WORK_DIR}/usr/local/bin/axonwallctl"
fi
if [[ -f "${CHROOT_SRC}/usr/local/bin/axonwall-tui" ]]; then
  cp "${CHROOT_SRC}/usr/local/bin/axonwall-tui" "${WORK_DIR}/usr/local/bin/"
  chmod 755 "${WORK_DIR}/usr/local/bin/axonwall-tui"
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
  cp "${CHROOT_SRC}/etc/zsh/zshenv" "${WORK_DIR}/etc/zsh/zshenv"
  chmod 0644 "${WORK_DIR}/etc/zsh/zshenv"
fi
if [[ -f "${CHROOT_SRC}/etc/skel/.zshrc" ]]; then
  cp "${CHROOT_SRC}/etc/skel/.zshrc" "${WORK_DIR}/etc/skel/.zshrc"
  chmod 0644 "${WORK_DIR}/etc/skel/.zshrc"
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
fi

if [[ -f "${ROOT_DIR}/apps/axonwall-controller/dist/index.js" ]]; then
  cp "${ROOT_DIR}/apps/axonwall-controller/dist/index.js" "${WORK_DIR}/opt/axonwall/apps/axonwall-controller/dist/"
  cp "${ROOT_DIR}/apps/axonwall-controller/package.json" "${WORK_DIR}/opt/axonwall/apps/axonwall-controller/"
fi
if [[ -f "${ROOT_DIR}/apps/axonwall-controller/dist/axonwallctl.js" ]]; then
  cp "${ROOT_DIR}/apps/axonwall-controller/dist/axonwallctl.js" "${WORK_DIR}/opt/axonwall/apps/axonwall-controller/dist/"
fi
if [[ -f "${ROOT_DIR}/apps/axonwall-controller/dist/axonwall-tui.js" ]]; then
  cp "${ROOT_DIR}/apps/axonwall-controller/dist/axonwall-tui.js" "${WORK_DIR}/opt/axonwall/apps/axonwall-controller/dist/"
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
