#!/usr/bin/env bash
# ==============================================================================
# Axonwall CI & Packaging Preflight Verification
# ==============================================================================
# Catches packaging, shell compatibility, merged-usr, Next.js standalone payload,
# and script-parity regressions locally and early in CI before slow ISO builds.
#
# Usage:
#   ./scripts/ci-preflight.sh                  # Static checks + standalone check if built
#   ./scripts/ci-preflight.sh --require-build  # Fail if .next/standalone is missing
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

REQUIRE_BUILD=false
for arg in "$@"; do
  case "${arg}" in
    --require-build) REQUIRE_BUILD=true ;;
    *)
      echo "Unknown argument: ${arg}" >&2
      exit 2
      ;;
  esac
done

FAIL=0
fail() {
  echo "[!] FAIL: $*" >&2
  FAIL=1
}
pass() {
  echo "[✓] $*"
}

echo "=== Axonwall CI & Packaging Preflight ==="

# ------------------------------------------------------------------------------
# 1. POSIX sh & Bash syntax checks
# ------------------------------------------------------------------------------
SH_SCRIPTS=(
  packaging/iso/config/includes.chroot/usr/local/bin/axonwall-install
  packaging/iso/config/includes.chroot/usr/local/bin/axonwall-update
  packaging/iso/config/includes.chroot/usr/local/bin/axonwallctl
  packaging/k3s-storage/axonwall-k3s-firstboot
  packaging/k3s-storage/axonwall-k3s-verify
  packaging/vault/axonwall-vault-firstboot
  packaging/vault/axonwall-vault-provision
  packaging/vault/axonwall-vault-status
  packaging/debian/postinst
  packaging/alpine/overlay/usr/local/bin/axonwall-firstboot-alpine
)

for s in "${SH_SCRIPTS[@]}"; do
  if ! sh -n "$s"; then
    fail "POSIX sh syntax check failed for $s"
  fi
done

BASH_SCRIPTS=(
  packaging/cloud-image/build-qcow2.sh
  packaging/debian/build-deb.sh
  packaging/iso/build-iso.sh
  packaging/alpine/build-alpine-iso.sh
  packaging/iso/config/includes.chroot/usr/local/bin/axonwall-cloud-init
  scripts/build-docs-bundle.sh
  scripts/build-plugins-bundle.sh
  scripts/ci-preflight.sh
  scripts/release-tagger.sh
)

for b in "${BASH_SCRIPTS[@]}"; do
  if ! bash -n "$b"; then
    fail "bash syntax check failed for $b"
  fi
done
pass "POSIX sh & bash syntax checks"

# ------------------------------------------------------------------------------
# 2. Duplicate script & preseed parity checks
# ------------------------------------------------------------------------------
extract_pkgs() {
  awk '/d-i pkgsel\/include string/{flag=1; next} flag{print; if ($0 !~ /\\$/) exit}' "$1" \
    | sed 's/\\$//; s/^[[:space:]]*//; s/[[:space:]]*$//' | sort
}
extract_services() {
  grep 'systemctl enable' "$1" | sed 's/.*systemctl enable//; s/;.*//' \
    | tr ' ' '\n' | grep -v '^$' | sort
}

if ! diff -u <(extract_pkgs packaging/vault/preseed-vault.cfg) <(extract_pkgs packaging/vault/preseed-vault-binary.cfg); then
  fail "vault preseed package lists differ"
fi
if ! diff -u <(extract_services packaging/vault/preseed-vault.cfg) <(extract_services packaging/vault/preseed-vault-binary.cfg); then
  fail "vault preseed enabled-service lists differ"
fi
if ! diff -u <(extract_pkgs packaging/k3s-storage/preseed-k3s-storage.cfg) <(extract_pkgs packaging/k3s-storage/preseed-k3s-storage-binary.cfg); then
  fail "k3s-storage preseed package lists differ"
fi
if ! diff -u <(extract_services packaging/k3s-storage/preseed-k3s-storage.cfg) <(extract_services packaging/k3s-storage/preseed-k3s-storage-binary.cfg); then
  fail "k3s-storage preseed enabled-service lists differ"
fi
if ! diff -u <(extract_pkgs packaging/iso/config/includes.installer/preseed.cfg) <(extract_pkgs packaging/iso/config/includes.binary/preseed.cfg); then
  fail "NGFW preseed package lists differ"
fi
if ! diff -u <(extract_services packaging/iso/config/includes.installer/preseed.cfg) <(extract_services packaging/iso/config/includes.binary/preseed.cfg); then
  fail "NGFW preseed enabled-service lists differ"
fi
if ! diff -u packaging/iso/config/includes.chroot/usr/local/bin/axonwall-install packaging/alpine/overlay/usr/local/bin/axonwall-install; then
  fail "axonwall-install differs between Debian ISO and Alpine ISO overlays"
fi
if ! diff -u packaging/iso/config/includes.chroot/usr/lib/axonwall/theme-zbm-uki.py packaging/iso/branding/theme-zbm-uki.py; then
  fail "theme-zbm-uki.py differs between includes.chroot and branding"
fi
if ! diff -u packaging/iso/config/includes.chroot/usr/local/bin/axonwall-zbm-theme packaging/alpine/overlay/usr/local/bin/axonwall-zbm-theme; then
  fail "axonwall-zbm-theme differs between Debian ISO and Alpine ISO overlays"
fi
pass "Duplicate script & preseed parity checks"

# ------------------------------------------------------------------------------
# 3. BusyBox mktemp compatibility in Alpine scripts
#    BusyBox mktemp requires templates to end with XXXXXX (no .tar.gz suffix).
# ------------------------------------------------------------------------------
if grep -rnE 'mktemp[^;|\n]*XXXXXX\.[A-Za-z0-9._-]+' packaging/alpine/; then
  fail "BusyBox mktemp rejects suffixes after XXXXXX in packaging/alpine/ (use XXXXXX without extension)"
else
  pass "BusyBox mktemp template compatibility (packaging/alpine/)"
fi

# Also check POSIX sh scripts that may run under BusyBox ash/Alpine
for s in "${SH_SCRIPTS[@]}"; do
  if grep -nE 'mktemp[^;|\n]*XXXXXX\.[A-Za-z0-9._-]+' "$s"; then
    fail "POSIX sh script $s uses mktemp template with suffix after XXXXXX (incompatible with BusyBox mktemp)"
  fi
done

# ------------------------------------------------------------------------------
# 4. Merged-usr safety in cloud-image / chroot overlay copies
#    Debian 13 uses merged-usr (/lib -> usr/lib, /bin -> usr/bin, /sbin -> usr/sbin).
#    `cp -r includes.chroot/* ${TARGET}/` fails with:
#    "cp: cannot overwrite non-directory '.../mnt/lib' with directory"
# ------------------------------------------------------------------------------
if grep -nE 'cp[[:space:]]+-[a-zA-Z]*[rRa][a-zA-Z]*[[:space:]]+.*includes\.chroot/\*' packaging/cloud-image/build-qcow2.sh; then
  fail "packaging/cloud-image/build-qcow2.sh uses cp -r/-a on includes.chroot/* (breaks merged-usr /lib symlink; use rsync -aK)"
fi

if ! grep -qE 'rsync[[:space:]]+-aK.*includes\.chroot/' packaging/cloud-image/build-qcow2.sh; then
  fail "packaging/cloud-image/build-qcow2.sh must use 'rsync -aK' when syncing includes.chroot/ onto merged-usr target"
fi

if command -v rsync >/dev/null 2>&1; then
  TMP_MNT="$(mktemp -d)"
  trap 'rm -rf "${TMP_MNT}"' EXIT
  mkdir -p "${TMP_MNT}/usr/lib" "${TMP_MNT}/usr/bin" "${TMP_MNT}/usr/sbin"
  ln -s usr/lib "${TMP_MNT}/lib"
  ln -s usr/bin "${TMP_MNT}/bin"
  ln -s usr/sbin "${TMP_MNT}/sbin"
  rsync -aK "${REPO_ROOT}/packaging/iso/config/includes.chroot/" "${TMP_MNT}/"
  if [[ ! -L "${TMP_MNT}/lib" ]]; then
    fail "rsync -aK replaced merged-usr /lib symlink"
  elif [[ ! -f "${TMP_MNT}/usr/lib/dhcpcd/dhcpcd-hooks/99-axonwall-routes" ]]; then
    fail "rsync -aK did not copy includes.chroot/lib/* into usr/lib/*"
  else
    pass "Merged-usr rsync -aK smoke test against includes.chroot/"
  fi
  rm -rf "${TMP_MNT}"
  trap - EXIT
fi

# ------------------------------------------------------------------------------
# 5. Debian ISO offline bootloader cache contract
# ------------------------------------------------------------------------------
if grep -q '"grub-pc_"' packaging/iso/build-iso.sh; then
  if ! grep -qE '^[[:space:]]*grub-pc([[:space:]]|\\|$)' packaging/iso/build-iso.sh || \
     ! grep -qE '^[[:space:]]*grub-efi-amd64([[:space:]]|\\|$)' packaging/iso/build-iso.sh; then
    fail "packaging/iso/build-iso.sh validates grub-pc_/grub-efi-amd64_ in offline cache but does not download both packages"
  else
    pass "Debian ISO offline bootloader pre-cache contract (grub-pc + grub-efi-amd64)"
  fi
fi

# ------------------------------------------------------------------------------
# 6. Next.js standalone runtime payload vs Alpine strip/validation check
# ------------------------------------------------------------------------------
STANDALONE_DIR="${REPO_ROOT}/apps/axonwall/.next/standalone"
if [[ -d "${STANDALONE_DIR}" ]]; then
  NEXT_PKG_DIR=""
  for candidate in "${STANDALONE_DIR}/node_modules/.pnpm/"next*/node_modules/next; do
    if [[ -d "${candidate}" ]]; then
      NEXT_PKG_DIR="${candidate}"
      break
    fi
  done

  if [[ -z "${NEXT_PKG_DIR}" ]]; then
    fail "Could not locate Next.js package inside ${STANDALONE_DIR}/node_modules/.pnpm/"
  else
    # Extract the exact required file list from packaging/alpine/build-alpine-iso.sh
    REQ_FILES="$(sed -nE 's/^[[:space:]]*for req in ([^;]+); do/\1/p' packaging/alpine/build-alpine-iso.sh)"
    if [[ -z "${REQ_FILES}" ]]; then
      fail "Could not parse required Next.js runtime files from packaging/alpine/build-alpine-iso.sh"
    else
      for req in ${REQ_FILES}; do
        if [[ ! -f "${NEXT_PKG_DIR}/${req}" ]]; then
          fail "Next.js standalone payload missing required runtime file: ${NEXT_PKG_DIR}/${req}"
        fi
      done
      pass "Next.js standalone runtime payload matches Alpine ISO check (${REQ_FILES})"
    fi
  fi
elif [[ "${REQUIRE_BUILD}" == true ]]; then
  fail "apps/axonwall/.next/standalone not found (--require-build specified); run 'pnpm build' first"
else
  echo "[i] Skipping Next.js standalone payload check (apps/axonwall/.next/standalone not built yet)"
fi

if [[ "${FAIL}" -ne 0 ]]; then
  echo "============================================================" >&2
  echo "[!] CI & Packaging Preflight FAILED" >&2
  echo "============================================================" >&2
  exit 1
fi

# ------------------------------------------------------------------------------
# 7. Lean Core Packaging Diet (zero unintended opt-in bloat in preseed/.deb)
# ------------------------------------------------------------------------------
if grep -qE '(^|[[:space:]])(slapd|sssd-ldap)([[:space:]]|\\|$)' packaging/iso/config/includes.installer/preseed-minimal.cfg; then
  fail "preseed-minimal.cfg must not bundle slapd/sssd-ldap in zero-role minimal edition"
fi
for pcfg in packaging/iso/config/includes.installer/preseed.cfg packaging/iso/config/includes.binary/preseed.cfg; do
  if grep -qE '(^|[[:space:]])(suricata|frr|strongswan|openvpn|keepalived|rkhunter|slapd)([[:space:]]|\\|$)' "$pcfg"; then
    fail "$pcfg must not pre-install opt-in plugin daemons in Lean Core"
  fi
  if grep -qE 'systemctl enable[^;]*headscale' "$pcfg"; then
    fail "$pcfg must not auto-enable headscale.service in Lean Core"
  fi
done
if grep -qE 'PKG_DEPENDS=.*(slapd|sssd-ldap)' packaging/debian/build-deb.sh; then
  fail "packaging/debian/build-deb.sh must not require slapd/sssd-ldap in base or minimal editions"
fi
if grep -qE 'for svc in .*headscale' packaging/cloud-image/build-qcow2.sh || \
   grep -qE 'for svc in .*headscale.*axonwall-firstboot' packaging/alpine/build-alpine-iso.sh; then
  fail "build-qcow2.sh / build-alpine-iso.sh must not auto-enable opt-in headscale service on Lean Core"
fi
for bad_pack in enterprise-identity observability-ai workstation-cli; do
  if grep -qF "${bad_pack}" apps/axonwall-console/installer_tui.go \
     packaging/iso/config/includes.chroot/usr/local/bin/axonwall-install; then
    fail "Obsolete starter pack ID '${bad_pack}' found in installer_tui.go or axonwall-install"
  fi
done
for canon_pack in enterprise-ngfw remote-access-vpn operator-diagnostics ai-observability; do
  if ! grep -qF "${canon_pack}" apps/axonwall-console/installer_tui.go || \
     ! grep -qF "${canon_pack}" packaging/iso/config/includes.chroot/usr/local/bin/axonwall-install; then
    fail "Canonical starter pack ID '${canon_pack}' missing from installer_tui.go or axonwall-install"
  fi
done
pass "Lean Core packaging diet, preseed & starter-pack parity guardrails"

if [[ "${FAIL}" -ne 0 ]]; then
  echo "============================================================" >&2
  echo "[!] CI & Packaging Preflight FAILED" >&2
  echo "============================================================" >&2
  exit 1
fi

echo "============================================================"
echo "[✓] All CI & Packaging Preflight checks passed!"
echo "============================================================"
