#!/usr/bin/env bash
set -euo pipefail

# Build an air-gapped Offline Plugin Cache tarball
# (axonwall-plugins-<os>-<version>.tar.gz + .sha256 + manifest.json)
# dynamically resolving package lists from @axonwall/lib.
# Extract on target hosts under /var/lib/axonwall/plugin-cache/.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OS_FAMILY="debian"
PACKS_ARG=""
PLUGINS_ARG=""
VERSION=""
OUT_DIR="${REPO_ROOT}/dist/plugins-bundle"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --os)
      OS_FAMILY="${2:-}"
      shift 2
      ;;
    --pack)
      PACKS_ARG="${2:-}"
      shift 2
      ;;
    --plugins)
      PLUGINS_ARG="${2:-}"
      shift 2
      ;;
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift 1
      ;;
    -h|--help)
      cat <<'EOF'
Usage: scripts/build-plugins-bundle.sh [options]

Options:
  --os <debian|alpine>      Target OS family (default: debian)
  --pack <all|pack-id,...>  Starter Pack ID(s) to bundle (default: all if --plugins unset)
  --plugins <id1,id2,...>   Additional explicit plugin IDs to bundle
  --version <X.Y.Z>         Bundle version tag (default: package.json version)
  --output-dir <dir>        Output directory (default: dist/plugins-bundle)
  --dry-run                 Resolve plugin/package lists and print plan without downloading
  -h, --help                Show this help text
EOF
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

case "${OS_FAMILY}" in
  debian|alpine) ;;
  *)
    echo "ERROR: unsupported --os '${OS_FAMILY}' (expected debian or alpine)" >&2
    exit 1
    ;;
esac

if [[ -z "${PACKS_ARG}" && -z "${PLUGINS_ARG}" ]]; then
  PACKS_ARG="all"
fi

if [[ -z "${VERSION}" ]]; then
  VERSION="$(node -p "require('${REPO_ROOT}/package.json').version" 2>/dev/null || echo "0.0.0")"
fi
VERSION="${VERSION#v}"

PLUGINS_DIST="${REPO_ROOT}/packages/axonwall_lib/dist/plugins/index.js"
if [[ ! -f "${PLUGINS_DIST}" ]]; then
  echo "ERROR: ${PLUGINS_DIST} not found. Run 'pnpm --filter @axonwall/lib build' first." >&2
  exit 1
fi

RESOLVED_JSON="$(
  node --input-type=module - "${PLUGINS_DIST}" "${OS_FAMILY}" "${PACKS_ARG}" "${PLUGINS_ARG}" <<'NODE'
import { pathToFileURL } from 'node:url';

const [distPath, osFamily, packsArg, pluginsArg] = process.argv.slice(2);
const mod = await import(pathToFileURL(distPath).href);
const { BUILTIN_PLUGINS, PLUGIN_STARTER_PACKS } = mod;

const byId = new Map(BUILTIN_PLUGINS.map((p) => [p.id, p]));
const packsById = new Map(PLUGIN_STARTER_PACKS.map((p) => [p.id, p]));
const selectedIds = new Set();

const addWithDeps = (id) => {
  const clean = id.trim();
  if (!clean) return;
  const m = byId.get(clean);
  if (!m) {
    console.error(`ERROR: unknown plugin ID '${clean}'`);
    process.exit(2);
  }
  if (selectedIds.has(clean)) return;
  selectedIds.add(clean);
  if (Array.isArray(m.dependencies)) {
    for (const dep of m.dependencies) {
      addWithDeps(dep);
    }
  }
};

if (packsArg) {
  for (const tok of packsArg.split(',').map((s) => s.trim()).filter(Boolean)) {
    if (tok === 'all') {
      for (const pack of PLUGIN_STARTER_PACKS) {
        for (const pid of pack.pluginIds) addWithDeps(pid);
      }
    } else {
      const pack = packsById.get(tok);
      if (!pack) {
        console.error(`ERROR: unknown starter pack '${tok}' (available: ${PLUGIN_STARTER_PACKS.map((p) => p.id).join(', ')})`);
        process.exit(2);
      }
      for (const pid of pack.pluginIds) addWithDeps(pid);
    }
  }
}

if (pluginsArg) {
  for (const tok of pluginsArg.split(',').map((s) => s.trim()).filter(Boolean)) {
    addWithDeps(tok);
  }
}

const pkgSet = new Set();
const orderedPlugins = [];
for (const p of BUILTIN_PLUGINS) {
  if (!selectedIds.has(p.id)) continue;
  orderedPlugins.push(p.id);
  const osPkgs = p.packages?.[osFamily] ?? [];
  for (const pkg of osPkgs) {
    pkgSet.add(pkg);
  }
}

console.log(JSON.stringify({
  osFamily,
  plugins: orderedPlugins,
  packages: Array.from(pkgSet),
}));
NODE
)"

PLUGINS_LIST="$(node -e "const d=JSON.parse(process.argv[1]); console.log(d.plugins.join(', '));" "${RESOLVED_JSON}")"
PACKAGES_LINES="$(node -e "const d=JSON.parse(process.argv[1]); console.log(d.packages.join('\n'));" "${RESOLVED_JSON}")"
PKG_COUNT="$(node -e "const d=JSON.parse(process.argv[1]); console.log(d.packages.length);" "${RESOLVED_JSON}")"

ARCHIVE_NAME="axonwall-plugins-${OS_FAMILY}-${VERSION}.tar.gz"
LATEST_NAME="axonwall-plugins-${OS_FAMILY}-latest.tar.gz"
ARCHIVE_PATH="${OUT_DIR}/${ARCHIVE_NAME}"
SHA_PATH="${ARCHIVE_PATH}.sha256"
MANIFEST_PLAN="${OUT_DIR}/${OS_FAMILY}/manifest.json"

echo "[plugins-bundle] OS Family   : ${OS_FAMILY}"
echo "[plugins-bundle] Version     : ${VERSION}"
echo "[plugins-bundle] Plugins     : ${PLUGINS_LIST}"
echo "[plugins-bundle] OS Packages (${PKG_COUNT}):"
if [[ "${PKG_COUNT}" -gt 0 ]]; then
  printf '%s\n' "${PACKAGES_LINES}" | sed 's/^/  - /'
else
  echo "  (none)"
fi
echo "[plugins-bundle] Output      : ${ARCHIVE_PATH}"
echo "[plugins-bundle] Manifest    : ${MANIFEST_PLAN}"
echo "[plugins-bundle] Target Dir  : /var/lib/axonwall/plugin-cache/${OS_FAMILY}/"

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "[plugins-bundle] Dry-run complete (no packages downloaded)."
  exit 0
fi

mapfile -t PKGS_ARRAY < <(printf '%s\n' "${PACKAGES_LINES}" | awk 'NF > 0')
if [[ "${#PKGS_ARRAY[@]}" -eq 0 ]]; then
  echo "ERROR: resolved OS package list is empty for os=${OS_FAMILY}." >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
STAGE_DIR="${WORK}/${OS_FAMILY}"
mkdir -p "${STAGE_DIR}" "${OUT_DIR}"

if [[ "${OS_FAMILY}" == "debian" ]]; then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "ERROR: apt-get is required to build a Debian offline plugin bundle." >&2
    exit 1
  fi
  APT_STATE="${WORK}/apt-state"
  mkdir -p "${APT_STATE}/lists/partial" "${STAGE_DIR}/partial"
  : > "${APT_STATE}/status"
  apt-get update -qq || true
  apt-get install -y --download-only --no-install-recommends \
    -o Dir::State::status="${APT_STATE}/status" \
    -o Dir::Cache::Archives="${STAGE_DIR}" \
    "${PKGS_ARRAY[@]}"
  rm -rf "${STAGE_DIR}/partial" "${STAGE_DIR}/lock"
else
  if ! command -v apk >/dev/null 2>&1; then
    echo "ERROR: apk is required to build an Alpine offline plugin bundle." >&2
    exit 1
  fi
  apk fetch --recursive --output "${STAGE_DIR}" "${PKGS_ARRAY[@]}"
fi

node --input-type=module - "${STAGE_DIR}" "${OS_FAMILY}" "${VERSION}" "${RESOLVED_JSON}" <<'NODE'
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const [stageDir, osFamily, version, resolvedRaw] = process.argv.slice(2);
const resolved = JSON.parse(resolvedRaw);
const ext = osFamily === 'alpine' ? '.apk' : '.deb';
const entries = fs.readdirSync(stageDir).filter((f) => f.endsWith(ext)).sort();

const parseDebDeps = (raw) => {
  if (!raw) return [];
  const deps = new Set();
  for (const altGroup of raw.split(',')) {
    for (const part of altGroup.split('|')) {
      const name = part.trim().split(/[\s(:<=>]/)[0]?.trim();
      if (name) deps.add(name);
    }
  }
  return Array.from(deps);
};

const extractMeta = (filePath, filename) => {
  try {
    if (osFamily === 'debian') {
      const out = execFileSync(
        'dpkg-deb',
        ['-f', filePath, 'Package', 'Provides', 'Depends', 'Pre-Depends'],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
      );
      const fields = {};
      for (const line of out.split('\n')) {
        const idx = line.indexOf(':');
        if (idx > 0) {
          fields[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
        }
      }
      return {
        package: fields.Package || filename.split('_')[0],
        provides: parseDebDeps(fields.Provides),
        depends: Array.from(new Set([...parseDebDeps(fields.Depends), ...parseDebDeps(fields['Pre-Depends'])])),
      };
    }
    const pkgInfo = execFileSync('tar', ['-xOf', filePath, '.PKGINFO'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    let pkgName = '';
    const provides = [];
    const depends = [];
    for (const line of pkgInfo.split('\n')) {
      const eq = line.indexOf('=');
      if (eq <= 0) continue;
      const k = line.slice(0, eq).trim();
      const v = line.slice(eq + 1).trim();
      if (k === 'pkgname') pkgName = v;
      else if (k === 'provides') {
        const n = v.split(/[<=>~]/)[0]?.trim();
        if (n) provides.push(n);
      } else if (k === 'depend') {
        const n = v.split(/[<=>~]/)[0]?.trim();
        if (n && !n.startsWith('!')) depends.push(n);
      }
    }
    return {
      package: pkgName || filename.replace(/-[0-9].*$/, ''),
      provides,
      depends,
    };
  } catch {
    return { package: '', provides: [], depends: [] };
  }
};

const files = entries.map((filename) => {
  const fullPath = path.join(stageDir, filename);
  const data = fs.readFileSync(fullPath);
  const sha256 = crypto.createHash('sha256').update(data).digest('hex');
  const meta = extractMeta(fullPath, filename);
  return {
    filename,
    sha256,
    sizeBytes: data.length,
    ...(meta.package ? { package: meta.package } : {}),
    ...(meta.provides.length > 0 ? { provides: meta.provides } : {}),
    ...(meta.depends.length > 0 ? { depends: meta.depends } : {}),
  };
});

const manifest = {
  osFamily,
  version,
  generatedAt: new Date().toISOString(),
  plugins: resolved.plugins,
  packages: resolved.packages,
  files,
};

fs.writeFileSync(path.join(stageDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');
NODE

tar -C "${WORK}" -czf "${ARCHIVE_PATH}" "${OS_FAMILY}"
cp -f "${ARCHIVE_PATH}" "${OUT_DIR}/${LATEST_NAME}"
(
  cd "${OUT_DIR}"
  sha256sum "${ARCHIVE_NAME}" > "${ARCHIVE_NAME}.sha256"
  sha256sum "${LATEST_NAME}" > "${LATEST_NAME}.sha256"
)

echo "[plugins-bundle] Built ${ARCHIVE_PATH} (SHA-256: $(cut -d' ' -f1 "${SHA_PATH}"))"
