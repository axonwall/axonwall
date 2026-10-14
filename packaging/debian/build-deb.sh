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
VERSION=$(node -p "require('${ROOT_DIR}/package.json').version" 2>/dev/null || echo "0.2.0")
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
Depends: nftables (>= 1.0.0), iproute2, wireguard-tools, keepalived, conntrackd, nodejs (>= 20.0.0), openssl, curl, ca-certificates, rsync, python3
Recommends: unbound, kea-dhcp4-server, frr, suricata, strongswan, openvpn
Homepage: https://axonwall.com
Description: Modern Linux Router & Next-Gen Firewall
 Axonwall replaces legacy BSD/PHP firewalls (OPNsense/pfSense) with a
 modern reactive architecture built on Linux nftables, Next.js, and
 a privileged Go daemon with commit-confirm transaction safety.
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

if [[ -d "${ROOT_DIR}/apps/axonwall-satellite/bin" ]]; then
  cp -r "${ROOT_DIR}/apps/axonwall-satellite/bin/"* "${WORK_DIR}/usr/share/axonwall/satellites/" 2>/dev/null || true
fi

# Fetch Headscale binary if absent
HEADSCALE_VERSION="0.29.4"
if [[ ! -f "${WORK_DIR}/usr/sbin/headscale" ]]; then
  echo "[+] Downloading Headscale v${HEADSCALE_VERSION} binary..."
  curl -fsSL -o "${WORK_DIR}/usr/sbin/headscale" "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}/headscale_${HEADSCALE_VERSION}_linux_amd64" || true
  chmod 755 "${WORK_DIR}/usr/sbin/headscale" 2>/dev/null || true
fi

# Fetch Litestream binary if absent
LITESTREAM_VERSION="0.3.13"
if [[ ! -f "${WORK_DIR}/usr/sbin/litestream" ]]; then
  echo "[+] Downloading Litestream v${LITESTREAM_VERSION} binary..."
  curl -fsSL -o /tmp/litestream.tar.gz "https://github.com/benbjohnson/litestream/releases/download/v${LITESTREAM_VERSION}/litestream-v${LITESTREAM_VERSION}-linux-amd64.tar.gz" || true
  if [[ -f /tmp/litestream.tar.gz ]]; then
    tar -xzf /tmp/litestream.tar.gz -C "${WORK_DIR}/usr/sbin/" litestream 2>/dev/null || true
    chmod 755 "${WORK_DIR}/usr/sbin/litestream" 2>/dev/null || true
    rm -f /tmp/litestream.tar.gz
  fi
fi

# 5. Copy System Scripts
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

echo "${VERSION}" > "${WORK_DIR}/etc/axonwall/version"

# 6. Copy Configurations, Rulesets, Systemd, Sysusers
cp "${SCRIPT_DIR}/lockdown.nft" "${WORK_DIR}/usr/share/axonwall/lockdown.nft"
cp "${SCRIPT_DIR}/headscale-config.yaml" "${WORK_DIR}/etc/headscale/config.yaml"
cp "${SCRIPT_DIR}/axonwalld.service" "${WORK_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/axonwall-ui.service" "${WORK_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/axonwall-controller.service" "${WORK_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/axonwall-console.service" "${WORK_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/headscale.service" "${WORK_DIR}/lib/systemd/system/"

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

# 8. Build Debian Archive via dpkg-deb (or docker fallback if dpkg-deb is absent)
echo "[+] Building deb package: ${PKG_NAME}.deb..."
if command -v dpkg-deb &>/dev/null; then
  dpkg-deb --build --root-owner-group "${WORK_DIR}" "${OUTPUT_DIR}/${PKG_NAME}.deb"
elif command -v docker &>/dev/null; then
  echo "[+] Running dpkg-deb inside debian:trixie container..."
  docker run --rm \
    -v "${SCRIPT_DIR}:/workspace" \
    debian:trixie \
    dpkg-deb --build --root-owner-group "/workspace/build" "/workspace/output/${PKG_NAME}.deb"
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
