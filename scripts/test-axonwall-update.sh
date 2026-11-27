#!/bin/sh
# Non-destructive unit and sandboxed integration tests for axonwall-update
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
UPDATER="${REPO_ROOT}/packaging/iso/config/includes.chroot/usr/local/bin/axonwall-update"

TEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/test-axonwall-update.XXXXXX")"
cleanup() {
  rm -rf "${TEST_TMP}"
}
trap cleanup EXIT INT TERM

PASS_COUNT=0
FAIL_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '[PASS] %s\n' "$1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf '[FAIL] %s\n' "$1" >&2
}

assert_eq() {
  _got="$1"
  _exp="$2"
  _msg="$3"
  if [ "$_got" = "$_exp" ]; then
    pass "$_msg"
  else
    fail "$_msg (got='${_got}', expected='${_exp}')"
  fi
}

echo "=== axonwall-update Hardening Test Suite ==="

# ------------------------------------------------------------------------------
# 1. Syntax & main() structure checks
# ------------------------------------------------------------------------------
if sh -n "$UPDATER"; then
  pass "sh -n syntax check passes"
else
  fail "sh -n syntax check failed"
fi

if command -v dash >/dev/null 2>&1; then
  if dash -n "$UPDATER"; then
    pass "dash -n syntax check passes"
  else
    fail "dash -n syntax check failed"
  fi
else
  printf '[INFO] dash not installed on host; skipped host dash -n\n'
fi

LAST_LINE="$(awk 'NF {last=$0} END {print last}' "$UPDATER")"
assert_eq "$LAST_LINE" 'main "$@"; exit $?' "final line invokes main \"\$@\"; exit \$?"

TOP_CODE_BEFORE_MAIN="$(awk '
  /^main\(\)/ { exit }
  /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
  /^[a-zA-Z_][a-zA-Z0-9_]*\(\)/ { in_fn = 1; next }
  in_fn && /^\}/ { in_fn = 0; next }
  in_fn { next }
  /^set -eu$/ { next }
  { print NR ":" $0 }
' "$UPDATER")"
assert_eq "$TOP_CODE_BEFORE_MAIN" "" "no executable top-level statements before main()"

# ------------------------------------------------------------------------------
# 2. Direct CLI main() checks (non-destructive)
# ------------------------------------------------------------------------------
if sh "$UPDATER" --help | grep -q -- '--allow-downgrade'; then
  pass "--help succeeds and documents --allow-downgrade"
else
  fail "--help missing or omits --allow-downgrade"
fi

if sh "$UPDATER" --bogus-flag >/dev/null 2>&1; then
  fail "unknown CLI option should fail"
else
  pass "unknown CLI option rejected"
fi

for bad_ver in "../foo" "/etc/passwd" "1.2.3;id" "1.2.3 foo" "1.2.3-..1" "1.2.3..4" "" "v"; do
  if sh "$UPDATER" --version "$bad_ver" >/dev/null 2>&1; then
    fail "CLI --version '${bad_ver}' should be rejected"
  else
    pass "CLI --version '${bad_ver}' rejected"
  fi
done

# ------------------------------------------------------------------------------
# 3. Extract helper functions for unit testing
# ------------------------------------------------------------------------------
HELPERS="${TEST_TMP}/helpers.sh"
awk '/^main\(\)/ { exit } { print }' "$UPDATER" > "$HELPERS"

run_helper() {
  sh -c ". '${HELPERS}'; $1"
}

# validate_semver
for ok_v in "0.16.3" "1.2.3" "1.2.3-rc.1" "0.16.3.1" "2.0.0-alpha-1"; do
  if run_helper "validate_semver '${ok_v}'"; then
    pass "validate_semver accepts '${ok_v}'"
  else
    fail "validate_semver rejected valid version '${ok_v}'"
  fi
done

for bad_v in "../foo" "1.2" "1.2.3..4" "1.2.3-..rc1" "1.2.3/4" "1.2.3;id" "1.2.3 bar"; do
  if run_helper "validate_semver '${bad_v}'"; then
    fail "validate_semver accepted invalid version '${bad_v}'"
  else
    pass "validate_semver rejects '${bad_v}'"
  fi
done

if sh -c ". '${HELPERS}'; v=\$(printf '0.16.3\n0.16.4'); validate_semver \"\$v\""; then
  fail "validate_semver accepted multiline version"
else
  pass "validate_semver rejects newline injection"
fi

# semver_compare & check_downgrade
assert_eq "$(run_helper "semver_compare 0.16.2 0.16.3")" "-1" "semver_compare 0.16.2 < 0.16.3"
assert_eq "$(run_helper "semver_compare 0.16.3 0.16.3")" "0" "semver_compare 0.16.3 == 0.16.3"
assert_eq "$(run_helper "semver_compare 0.16.4 0.16.3")" "1" "semver_compare 0.16.4 > 0.16.3"
assert_eq "$(run_helper "semver_compare 0.9.9 0.10.0")" "-1" "semver_compare 0.9.9 < 0.10.0 (numeric)"
assert_eq "$(run_helper "semver_compare 1.0.0-rc.1 1.0.0")" "-1" "semver_compare 1.0.0-rc.1 < 1.0.0"
assert_eq "$(run_helper "semver_compare 1.0.0 1.0.0-rc.1")" "1" "semver_compare 1.0.0 > 1.0.0-rc.1"
assert_eq "$(run_helper "semver_compare 1.0.0-rc.2 1.0.0-rc.10")" "-1" "semver_compare 1.0.0-rc.2 < 1.0.0-rc.10"

if run_helper "check_downgrade 0.16.2 0.16.3 0" 2>/dev/null; then
  fail "check_downgrade should reject 0.16.3 -> 0.16.2 without --allow-downgrade"
else
  pass "check_downgrade rejects 0.16.3 -> 0.16.2"
fi

if run_helper "check_downgrade 0.16.2 0.16.3 1" 2>/dev/null; then
  pass "check_downgrade allows 0.16.3 -> 0.16.2 with --allow-downgrade"
else
  fail "check_downgrade failed with --allow-downgrade=1"
fi

# verify_sha256_manifest
H64="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
SHA_DIR="${TEST_TMP}/sha"
mkdir -p "$SHA_DIR"

printf '%s  %s\n' "$H64" "axonwall_0.16.3_amd64.deb" > "${SHA_DIR}/valid.sha256"
GOT_H="$(run_helper "verify_sha256_manifest '${SHA_DIR}/valid.sha256' 'axonwall_0.16.3_amd64.deb'")"
assert_eq "$GOT_H" "$H64" "verify_sha256_manifest accepts exact 1-line match"

printf '%s  %s\n' "$H64" "axonwall-minimal_0.16.3_amd64.deb" > "${SHA_DIR}/wrong-ed.sha256"
if run_helper "verify_sha256_manifest '${SHA_DIR}/wrong-ed.sha256' 'axonwall_0.16.3_amd64.deb'" >/dev/null 2>&1; then
  fail "verify_sha256_manifest accepted wrong edition filename"
else
  pass "verify_sha256_manifest rejects wrong edition filename"
fi

printf '%s  %s\n' "$H64" "axonwall_0.16.2_amd64.deb" > "${SHA_DIR}/wrong-ver.sha256"
if run_helper "verify_sha256_manifest '${SHA_DIR}/wrong-ver.sha256' 'axonwall_0.16.3_amd64.deb'" >/dev/null 2>&1; then
  fail "verify_sha256_manifest accepted wrong version filename"
else
  pass "verify_sha256_manifest rejects wrong version filename"
fi

printf '%s  %s\n' "$H64" "axonwall-docs-0.16.3.tar.gz" > "${SHA_DIR}/docs.sha256"
if run_helper "verify_sha256_manifest '${SHA_DIR}/docs.sha256' 'axonwall_0.16.3_amd64.deb'" >/dev/null 2>&1; then
  fail "verify_sha256_manifest accepted docs tarball filename"
else
  pass "verify_sha256_manifest rejects docs tarball filename"
fi

printf '%s  %s\n' "$H64" "./axonwall_0.16.3_amd64.deb" > "${SHA_DIR}/slash.sha256"
if run_helper "verify_sha256_manifest '${SHA_DIR}/slash.sha256' 'axonwall_0.16.3_amd64.deb'" >/dev/null 2>&1; then
  fail "verify_sha256_manifest accepted filename with slash"
else
  pass "verify_sha256_manifest rejects filename with slash"
fi

printf '%s  %s\n%s  %s\n' "$H64" "axonwall_0.16.3_amd64.deb" "$H64" "other.deb" > "${SHA_DIR}/multiline.sha256"
if run_helper "verify_sha256_manifest '${SHA_DIR}/multiline.sha256' 'axonwall_0.16.3_amd64.deb'" >/dev/null 2>&1; then
  fail "verify_sha256_manifest accepted multiline .sha256"
else
  pass "verify_sha256_manifest rejects extra lines"
fi

printf '%s  %s\r\n' "$H64" "axonwall_0.16.3_amd64.deb" > "${SHA_DIR}/crlf.sha256"
if run_helper "verify_sha256_manifest '${SHA_DIR}/crlf.sha256' 'axonwall_0.16.3_amd64.deb'" >/dev/null 2>&1; then
  fail "verify_sha256_manifest accepted CRLF"
else
  pass "verify_sha256_manifest rejects CRLF"
fi

printf '%s *%s\n' "$H64" "axonwall_0.16.3_amd64.deb" > "${SHA_DIR}/star.sha256"
if run_helper "verify_sha256_manifest '${SHA_DIR}/star.sha256' 'axonwall_0.16.3_amd64.deb'" >/dev/null 2>&1; then
  fail "verify_sha256_manifest accepted single-space star mode"
else
  pass "verify_sha256_manifest rejects binary * marker"
fi

: > "${SHA_DIR}/empty.sha256"
if run_helper "verify_sha256_manifest '${SHA_DIR}/empty.sha256' 'axonwall_0.16.3_amd64.deb'" >/dev/null 2>&1; then
  fail "verify_sha256_manifest accepted empty file"
else
  pass "verify_sha256_manifest rejects empty file"
fi

printf '%s  %s\0\n' "$H64" "axonwall_0.16.3_amd64.deb" > "${SHA_DIR}/nul.sha256"
if run_helper "verify_sha256_manifest '${SHA_DIR}/nul.sha256' 'axonwall_0.16.3_amd64.deb'" >/dev/null 2>&1; then
  fail "verify_sha256_manifest accepted NUL byte"
else
  pass "verify_sha256_manifest rejects NUL byte"
fi

# sync_static_etc_axonwall (key rotation cleanup)
SRC_ETC="${TEST_TMP}/src_etc"
DST_ETC="${TEST_TMP}/dst_etc"
mkdir -p "${SRC_ETC}/release-signing.d" "${DST_ETC}/release-signing.d"
echo "new-pub" > "${SRC_ETC}/release-signing.d/key-2027.pub"
echo "old-pub" > "${DST_ETC}/release-signing.d/key-2025.pub"
echo "readme" > "${DST_ETC}/release-signing.d/README.md"
run_helper "sync_static_etc_axonwall '${SRC_ETC}' '${DST_ETC}'"
if [ -f "${DST_ETC}/release-signing.d/key-2027.pub" ] && [ ! -e "${DST_ETC}/release-signing.d/key-2025.pub" ] && [ -f "${DST_ETC}/release-signing.d/README.md" ]; then
  pass "sync_static_etc_axonwall removes retired .pub keys and preserves README.md"
else
  fail "sync_static_etc_axonwall key rotation cleanup failed"
fi

# atomic_install_bin
AIB_SRC="${TEST_TMP}/aib_src"
AIB_DST="${TEST_TMP}/aib_dst"
mkdir -p "$AIB_SRC" "$AIB_DST"
printf '#!/bin/sh\necho old\n' > "${AIB_DST}/axonwall-update"
chmod 0755 "${AIB_DST}/axonwall-update"
OLD_INODE="$(stat -c '%i' "${AIB_DST}/axonwall-update")"
printf '#!/bin/sh\necho new\n' > "${AIB_SRC}/axonwall-update"
chmod 0644 "${AIB_SRC}/axonwall-update"
ln -s "axonwall-update" "${AIB_SRC}/axonwall-link"
run_helper "atomic_install_bin '${AIB_SRC}/axonwall-update' '${AIB_DST}' 'axonwall-update'"
run_helper "atomic_install_bin '${AIB_SRC}/axonwall-link' '${AIB_DST}' 'axonwall-link'"
NEW_INODE="$(stat -c '%i' "${AIB_DST}/axonwall-update")"
NEW_MODE="$(stat -c '%a' "${AIB_DST}/axonwall-update")"
if [ "$OLD_INODE" != "$NEW_INODE" ] && [ "$NEW_MODE" = "755" ] && [ -L "${AIB_DST}/axonwall-link" ]; then
  pass "atomic_install_bin allocates new inode, sets 0755, and installs symlinks"
else
  fail "atomic_install_bin check failed (old=${OLD_INODE}, new=${NEW_INODE}, mode=${NEW_MODE})"
fi

# ------------------------------------------------------------------------------
# 4. Fallback extract_deb(): FIFO/block/char rejection + --no-same-permissions
# ------------------------------------------------------------------------------
EXTR_DIR="${TEST_TMP}/extract_test"
mkdir -p "${EXTR_DIR}/bin" "${EXTR_DIR}/payload/usr/local/bin" "${EXTR_DIR}/out_ok" "${EXTR_DIR}/out_fifo" "${EXTR_DIR}/work"

# Hide dpkg-deb by setting a controlled PATH with standard tools except dpkg-deb
for tool in sh dash bash awk grep sed tr wc cat rm mkdir chmod mktemp ar tar gzip find mv cp ln readlink head tail date basename dirname; do
  tpath="$(command -v "$tool" || true)"
  [ -n "$tpath" ] && ln -sf "$tpath" "${EXTR_DIR}/bin/${tool}"
done

# Real valid tarball with 0777 file and relative symlink (test --no-same-permissions under umask 022)
printf '#!/bin/sh\necho hello\n' > "${EXTR_DIR}/payload/usr/local/bin/tool"
chmod 0777 "${EXTR_DIR}/payload/usr/local/bin/tool"
ln -s "tool" "${EXTR_DIR}/payload/usr/local/bin/tool-link"
printf '2.0\n' > "${EXTR_DIR}/debian-binary"
tar -cf "${EXTR_DIR}/data.tar.gz" -z -C "${EXTR_DIR}/payload" .
(cd "${EXTR_DIR}" && ar rcs "${EXTR_DIR}/valid.deb" debian-binary data.tar.gz >/dev/null 2>&1)

if PATH="${EXTR_DIR}/bin" WORK_DIR="${EXTR_DIR}/work" sh -c "umask 022; . '${HELPERS}'; extract_deb '${EXTR_DIR}/valid.deb' '${EXTR_DIR}/out_ok'"; then
  TOOL_MODE="$(stat -c '%a' "${EXTR_DIR}/out_ok/usr/local/bin/tool")"
  if [ "$TOOL_MODE" = "755" ] && [ -L "${EXTR_DIR}/out_ok/usr/local/bin/tool-link" ]; then
    pass "extract_deb fallback extracts valid .deb with --no-same-permissions (0777 -> 0755)"
  else
    fail "extract_deb extracted unexpected mode (${TOOL_MODE}) or missing symlink"
  fi
else
  fail "extract_deb fallback failed on valid .deb"
fi

# Real FIFO ('p') member inside .deb
mkdir -p "${EXTR_DIR}/fifo_payload/tmp_fifo"
mkfifo "${EXTR_DIR}/fifo_payload/tmp_fifo/evil.pipe"
tar -cf "${EXTR_DIR}/fifo_data.tar.gz" -z -C "${EXTR_DIR}/fifo_payload" .
(cd "${EXTR_DIR}" && ar rcs "${EXTR_DIR}/fifo.deb" debian-binary fifo_data.tar.gz >/dev/null 2>&1)
if PATH="${EXTR_DIR}/bin" WORK_DIR="${EXTR_DIR}/work" sh -c ". '${HELPERS}'; extract_deb '${EXTR_DIR}/fifo.deb' '${EXTR_DIR}/out_fifo'" >/dev/null 2>&1; then
  fail "extract_deb should reject FIFO ('p') tar members"
else
  pass "extract_deb rejects FIFO ('p') tar members"
fi

# Spy tar verifying block ('b'), char ('c'), and FIFO ('p') rejection via tar -tvf awk filter,
# as well as verifying --no-same-permissions is passed on extraction.
for ftype_char in b c p; do
  SPY_BIN="${TEST_TMP}/spy_${ftype_char}"
  OUT_SPY="${TEST_TMP}/out_${ftype_char}"
  mkdir -p "$SPY_BIN" "$OUT_SPY"
  cp -a "${EXTR_DIR}/bin/." "$SPY_BIN/"
  rm -f "${SPY_BIN}/tar"
  cat > "${SPY_BIN}/tar" << EOF
#!/bin/sh
case "\$*" in
  *"-tf "*) echo "./dev/evil" ; exit 0 ;;
  *"-tvf "*) echo "${ftype_char}rw-r--r-- root/root 1, 3 2026-11-27 12:00 ./dev/evil" ; exit 0 ;;
  *"--help"*) echo "--no-same-owner --no-same-permissions" ; exit 0 ;;
esac
exit 0
EOF
  chmod 0755 "${SPY_BIN}/tar"
  if PATH="$SPY_BIN" WORK_DIR="${EXTR_DIR}/work" sh -c ". '${HELPERS}'; extract_deb '${EXTR_DIR}/valid.deb' '${OUT_SPY}'" >/dev/null 2>&1; then
    fail "extract_deb should reject '${ftype_char}' tar member"
  else
    pass "extract_deb rejects '${ftype_char}' tar member"
  fi
done

SPY_PERM="${TEST_TMP}/spy_perm"
OUT_PERM="${TEST_TMP}/out_perm"
mkdir -p "$SPY_PERM" "$OUT_PERM"
cp -a "${EXTR_DIR}/bin/." "$SPY_PERM/"
rm -f "${SPY_PERM}/tar"
cat > "${SPY_PERM}/tar" << EOF
#!/bin/sh
case "\$*" in
  *"--help"*) echo "--no-same-owner --no-same-permissions" ; exit 0 ;;
  *"-tf "*) echo "./usr/local/bin/ok" ; exit 0 ;;
  *"-tvf "*) echo "-rwxr-xr-x root/root 10 2026-11-27 12:00 ./usr/local/bin/ok" ; exit 0 ;;
  *"-xf "*) printf '%s\n' "\$*" > "${TEST_TMP}/tar_extract_args" ; exit 0 ;;
esac
exit 0
EOF
chmod 0755 "${SPY_PERM}/tar"
if PATH="$SPY_PERM" WORK_DIR="${EXTR_DIR}/work" sh -c ". '${HELPERS}'; extract_deb '${EXTR_DIR}/valid.deb' '${OUT_PERM}'"; then
  if grep -q -- '--no-same-permissions' "${TEST_TMP}/tar_extract_args"; then
    pass "extract_deb passes --no-same-permissions to tar"
  else
    fail "extract_deb did not pass --no-same-permissions to tar: $(cat "${TEST_TMP}/tar_extract_args")"
  fi
else
  fail "extract_deb failed in --no-same-permissions spy test"
fi

# ------------------------------------------------------------------------------
# 5. End-to-end sandboxed main() tests (signed .deb, curl TLS flags, downgrade,
#    filename mismatch, self-overwrite under /bin/sh & dash)
# ------------------------------------------------------------------------------
SBOX="${TEST_TMP}/sandbox"
mkdir -p "${SBOX}/etc/axonwall/release-signing.d" "${SBOX}/var/lib/axonwall" \
  "${SBOX}/usr/local/bin" "${SBOX}/usr/sbin" "${SBOX}/run" "${SBOX}/opt/axonwall" \
  "${SBOX}/pkg_src/usr/local/bin" "${SBOX}/pkg_src/etc/axonwall/release-signing.d" \
  "${SBOX}/pkg_src/opt/axonwall" "${SBOX}/repo" "${SBOX}/mock_bin"

# Generate test RSA signing keypair
openssl genrsa -out "${TEST_TMP}/signing.key" 2048 >/dev/null 2>&1
openssl rsa -in "${TEST_TMP}/signing.key" -pubout -out "${SBOX}/etc/axonwall/release-signing.pub" >/dev/null 2>&1
echo "axonwall" > "${SBOX}/etc/axonwall/edition"
echo "0.16.3" > "${SBOX}/etc/axonwall/version"
echo "rolling" > "${SBOX}/etc/axonwall/install-mode"
echo "old" > "${SBOX}/etc/axonwall/release-signing.d/retired.pub"
echo "readme" > "${SBOX}/etc/axonwall/release-signing.d/README.md"
echo "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet" > "${SBOX}/proc_cmdline"

# Rewrite root-anchored system paths (not ${var}/... relative subpaths) in a
# sandboxed copy of axonwall-update so main() runs isolated without root.
SBOX_UPDATER="${SBOX}/usr/local/bin/axonwall-update"
sed -E \
  -e "s|([[:space:]\"'])/etc/axonwall|\1${SBOX}/etc/axonwall|g" \
  -e "s|([[:space:]\"'])/var/lib/axonwall|\1${SBOX}/var/lib/axonwall|g" \
  -e "s|([[:space:]\"'])/usr/local/bin|\1${SBOX}/usr/local/bin|g" \
  -e "s|([[:space:]\"'])/usr/sbin|\1${SBOX}/usr/sbin|g" \
  -e "s|([[:space:]\"'])/usr/share/axonwall|\1${SBOX}/usr/share/axonwall|g" \
  -e "s|([[:space:]\"'])/opt/axonwall|\1${SBOX}/opt/axonwall|g" \
  -e "s|/proc/cmdline|${SBOX}/proc_cmdline|g" \
  -e "s|/run/axonwall-update\.XXXXXX|${SBOX}/run/axonwall-update.XXXXXX|g" \
  -e 's|apply_staged_tree "\$\{PKG_STAGE\}" "/"|apply_staged_tree "${PKG_STAGE}" "'"${SBOX}"'"|g' \
  -e 's|ensure_cli_symlinks "/"|ensure_cli_symlinks "'"${SBOX}"'"|g' \
  "$UPDATER" > "$SBOX_UPDATER"
chmod 0755 "$SBOX_UPDATER"

# Create a longer new axonwall-update inside the .deb payload with trailing '&'
# tokens to prove SEC-C04 self-overwrite cannot corrupt the running shell!
cp "$SBOX_UPDATER" "${SBOX}/pkg_src/usr/local/bin/axonwall-update"
awk 'BEGIN { for (i=0; i<300; i++) printf "# padding line %04d & && ;;\n", i }' >> "${SBOX}/pkg_src/usr/local/bin/axonwall-update"
chmod 0755 "${SBOX}/pkg_src/usr/local/bin/axonwall-update"
echo "new-2027" > "${SBOX}/pkg_src/etc/axonwall/release-signing.d/active-2027.pub"
echo "updated" > "${SBOX}/pkg_src/opt/axonwall/MARKER"

# Build signed .deb packages for 0.16.4 (upgrade) and 0.16.2 (downgrade)
build_signed_deb() {
  _ver="$1"
  _name="axonwall_${_ver}_amd64.deb"
  tar -cf "${TEST_TMP}/data.tar.gz" -z -C "${SBOX}/pkg_src" .
  printf '2.0\n' > "${TEST_TMP}/debian-binary"
  rm -f "${SBOX}/repo/${_name}"
  (cd "${TEST_TMP}" && ar rcs "${SBOX}/repo/${_name}" debian-binary data.tar.gz >/dev/null 2>&1)
  (cd "${SBOX}/repo" && sha256sum "${_name}" > "${_name}.sha256")
  openssl dgst -sha256 -sign "${TEST_TMP}/signing.key" -out "${SBOX}/repo/${_name}.sha256.sig" "${SBOX}/repo/${_name}.sha256"
}

build_signed_deb "0.16.4"
build_signed_deb "0.16.2"

# Mock curl that verifies HTTPS flags and serves from ${SBOX}/repo
cat > "${SBOX}/mock_bin/curl" << EOF
#!/bin/sh
printf '%s\n' "\$*" >> "${TEST_TMP}/curl_calls.log"
_has_proto=0
_has_redir=0
_has_tls=0
_out=""
_url=""
while [ \$# -gt 0 ]; do
  case "\$1" in
    --proto) [ "\${2:-}" = "=https" ] && _has_proto=1; shift 2 ;;
    --proto-redir) [ "\${2:-}" = "=https" ] && _has_redir=1; shift 2 ;;
    --tlsv1.2) _has_tls=1; shift ;;
    -o) _out="\${2:-}"; shift 2 ;;
    https://*) _url="\$1"; shift ;;
    -*)
      case "\$1" in
        --connect-timeout|--max-time) shift 2 ;;
        *) shift ;;
      esac
      ;;
    *) shift ;;
  esac
done
if [ "\$_has_proto" != "1" ] || [ "\$_has_redir" != "1" ] || [ "\$_has_tls" != "1" ]; then
  echo "missing TLS/HTTPS enforcement flags" >&2
  exit 22
fi
_fname="\$(basename "\$_url")"
if [ -f "${SBOX}/repo/\${_fname}" ]; then
  cp "${SBOX}/repo/\${_fname}" "\$_out"
  exit 0
fi
exit 22
EOF
chmod 0755 "${SBOX}/mock_bin/curl"
# Provide minimal PATH with mock curl & standard tools (no systemctl/dpkg-deb so fallback paths run)
for tool in sh dash bash awk grep sed tr wc cat rm mkdir chmod mktemp ar tar gzip find mv cp ln readlink head tail date basename dirname sha256sum openssl ls touch rmdir stat; do
  tpath="$(command -v "$tool" || true)"
  [ -n "$tpath" ] && ln -sf "$tpath" "${SBOX}/mock_bin/${tool}"
done

# 5a. Downgrade rejected without --allow-downgrade
if PATH="${SBOX}/mock_bin" sh "$SBOX_UPDATER" --rolling --version 0.16.2 >/dev/null 2>&1; then
  fail "sandboxed main() should reject downgrade 0.16.3 -> 0.16.2"
else
  pass "sandboxed main() rejects downgrade 0.16.3 -> 0.16.2"
fi

# 5b. Wrong-edition signed .sha256 rejected
cp "${SBOX}/repo/axonwall_0.16.4_amd64.deb.sha256" "${TEST_TMP}/saved_0164.sha256"
cp "${SBOX}/repo/axonwall_0.16.4_amd64.deb.sha256.sig" "${TEST_TMP}/saved_0164.sha256.sig"
_h0164="$(awk '{print $1}' "${TEST_TMP}/saved_0164.sha256")"
printf '%s  %s\n' "$_h0164" "axonwall-minimal_0.16.4_amd64.deb" > "${SBOX}/repo/axonwall_0.16.4_amd64.deb.sha256"
openssl dgst -sha256 -sign "${TEST_TMP}/signing.key" -out "${SBOX}/repo/axonwall_0.16.4_amd64.deb.sha256.sig" "${SBOX}/repo/axonwall_0.16.4_amd64.deb.sha256"
if PATH="${SBOX}/mock_bin" sh "$SBOX_UPDATER" --rolling --version 0.16.4 >/dev/null 2>&1; then
  fail "sandboxed main() accepted validly signed .sha256 with wrong edition filename"
else
  pass "sandboxed main() rejects validly signed .sha256 with wrong edition filename"
fi
cp "${TEST_TMP}/saved_0164.sha256" "${SBOX}/repo/axonwall_0.16.4_amd64.deb.sha256"
cp "${TEST_TMP}/saved_0164.sha256.sig" "${SBOX}/repo/axonwall_0.16.4_amd64.deb.sha256.sig"

# 5b2. Wrong-version signed .sha256 rejected
printf '%s  %s\n' "$_h0164" "axonwall_0.16.3_amd64.deb" > "${SBOX}/repo/axonwall_0.16.4_amd64.deb.sha256"
openssl dgst -sha256 -sign "${TEST_TMP}/signing.key" -out "${SBOX}/repo/axonwall_0.16.4_amd64.deb.sha256.sig" "${SBOX}/repo/axonwall_0.16.4_amd64.deb.sha256"
if PATH="${SBOX}/mock_bin" sh "$SBOX_UPDATER" --rolling --version 0.16.4 >/dev/null 2>&1; then
  fail "sandboxed main() accepted validly signed .sha256 with wrong version filename"
else
  pass "sandboxed main() rejects validly signed .sha256 with wrong version filename"
fi
cp "${TEST_TMP}/saved_0164.sha256" "${SBOX}/repo/axonwall_0.16.4_amd64.deb.sha256"
cp "${TEST_TMP}/saved_0164.sha256.sig" "${SBOX}/repo/axonwall_0.16.4_amd64.deb.sha256.sig"

# 5c. Upgrade 0.16.3 -> 0.16.4 with self-overwrite & rotation cleanup
: > "${TEST_TMP}/curl_calls.log"
PRE_INODE="$(stat -c '%i' "$SBOX_UPDATER")"
if PATH="${SBOX}/mock_bin" sh "$SBOX_UPDATER" --rolling --version 0.16.4 >"${TEST_TMP}/sbox_5c.log" 2>&1; then
  POST_INODE="$(stat -c '%i' "$SBOX_UPDATER")"
  VER_NOW="$(cat "${SBOX}/etc/axonwall/version")"
  LEFTOVER_RUN="$(find "${SBOX}/run" -mindepth 1 -maxdepth 1 2>/dev/null || true)"
  if [ "$PRE_INODE" != "$POST_INODE" ] && [ "$VER_NOW" = "0.16.4" ] && \
     [ -z "$LEFTOVER_RUN" ] && \
     [ ! -e "${SBOX}/etc/axonwall/release-signing.d/retired.pub" ] && \
     [ -f "${SBOX}/etc/axonwall/release-signing.d/active-2027.pub" ] && \
     [ -f "${SBOX}/etc/axonwall/release-signing.d/README.md" ] && \
     grep -q -- '--proto =https --proto-redir =https --tlsv1.2' "${TEST_TMP}/curl_calls.log"; then
    pass "sandboxed main() upgrade 0.16.3 -> 0.16.4 (atomic self-overwrite, key rotation, HTTPS curl, WORK_DIR cleanup)"
  else
    fail "sandboxed main() post-upgrade assertions failed (inodes=${PRE_INODE}/${POST_INODE}, ver=${VER_NOW}, leftover=${LEFTOVER_RUN})"
  fi
else
  cat "${TEST_TMP}/sbox_5c.log" >&2 || true
  fail "sandboxed main() upgrade 0.16.3 -> 0.16.4 failed"
fi

# 5d. Downgrade 0.16.4 -> 0.16.2 succeeds with --allow-downgrade
if PATH="${SBOX}/mock_bin" sh "$SBOX_UPDATER" --rolling --version 0.16.2 --allow-downgrade >"${TEST_TMP}/sbox_5d.log" 2>&1; then
  VER_NOW="$(cat "${SBOX}/etc/axonwall/version")"
  assert_eq "$VER_NOW" "0.16.2" "sandboxed main() downgrade succeeds with --allow-downgrade"
else
  cat "${TEST_TMP}/sbox_5d.log" >&2 || true
  fail "sandboxed main() downgrade with --allow-downgrade failed"
fi

echo "=== Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed ==="
[ "$FAIL_COUNT" -eq 0 ]
