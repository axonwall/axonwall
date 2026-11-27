#!/usr/bin/env bash
set -euo pipefail

# Build the standalone, on-demand Offline Documentation Portal tarball
# (axonwall-docs-<version>.tar.gz + axonwall-docs-latest.tar.gz + .sha256)
# from the axonwall.com submodule in a clean temporary directory without
# ever modifying the axonwall.com git working tree.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION=""
OUT_DIR="${REPO_ROOT}/packaging/docs/output"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      cat <<'EOF'
Usage: scripts/build-docs-bundle.sh [--version <X.Y.Z>] [--output-dir <dir>]

Builds the offline Axonwall documentation bundle tarball (served by the console
under /api/docs-bundle/) into packaging/docs/output/.
EOF
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "${VERSION}" ]]; then
  VERSION="$(node -p "require('${REPO_ROOT}/package.json').version" 2>/dev/null || echo "0.0.0")"
fi
VERSION="${VERSION#v}"

SITE_DIR="${REPO_ROOT}/axonwall.com"
if [[ ! -d "${SITE_DIR}/src/app/docs" ]]; then
  echo "ERROR: axonwall.com submodule documentation source not found at ${SITE_DIR}/src/app/docs" >&2
  exit 1
fi

if [[ ! -d "${SITE_DIR}/node_modules" ]]; then
  echo "[docs-bundle] Installing axonwall.com dependencies..."
  pnpm --dir "${SITE_DIR}" install --frozen-lockfile
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

cp -a "${SITE_DIR}/package.json" "${SITE_DIR}/postcss.config.mjs" "${SITE_DIR}/tsconfig.json" "${WORK}/"
cp -a "${SITE_DIR}/src" "${WORK}/src"
mkdir -p "${WORK}/public"
for asset in favicon.svg logo-icon.svg; do
  if [[ -f "${SITE_DIR}/public/${asset}" ]]; then
    cp -a "${SITE_DIR}/public/${asset}" "${WORK}/public/${asset}"
  fi
done
ln -s "${SITE_DIR}/node_modules" "${WORK}/node_modules"

# Strip marketing-only pages so only /docs/* and shared app shell are built.
rm -rf "${WORK}/src/app/architecture" "${WORK}/src/app/demo" "${WORK}/src/app/releases"

cat > "${WORK}/next.config.mjs" <<'EOF'
/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  basePath: '/api/docs-bundle',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
};

export default nextConfig;
EOF

cat > "${WORK}/src/app/page.tsx" <<'EOF'
import Link from 'next/link';

export default function DocsBundleRootPage() {
  return (
    <main className="min-h-screen bg-[#080c14] text-slate-100 flex items-center justify-center p-8">
      <div className="max-w-md text-center space-y-4">
        <h1 className="text-xl font-bold">Axonwall Offline Documentation</h1>
        <p className="text-sm text-slate-400">Open the documentation portal to browse all guides.</p>
        <Link
          href="/docs/"
          className="inline-flex px-4 py-2 rounded-lg bg-emerald-600 text-white text-sm font-semibold hover:bg-emerald-500 transition"
        >
          Open Documentation
        </Link>
      </div>
    </main>
  );
}
EOF

# Rewrite links in the temporary copy so header/marketing/console links resolve cleanly
# when hosted under /api/docs-bundle/ inside the appliance console.
DOCS_WORK="${WORK}" DOCS_VERSION="${VERSION}" node -e '
const fs = require("node:fs");
const path = require("node:path");

const work = process.env.DOCS_WORK;

const rootLayoutPath = path.join(work, "src/app/layout.tsx");
if (fs.existsSync(rootLayoutPath)) {
  let rootLayout = fs.readFileSync(rootLayoutPath, "utf8");
  rootLayout = rootLayout
    .replaceAll("'\''/favicon.svg'\''", "'\''/api/docs-bundle/favicon.svg'\''")
    .replaceAll("'\''/logo-icon.svg'\''", "'\''/api/docs-bundle/logo-icon.svg'\''")
    .replace(/<html([^>]*)>/, (m, attrs) =>
      attrs.includes("data-theme=") ? m : `<html${attrs} data-theme="axonwall-emerald">`
    )
    .replace(/<script\b[\s\S]*?localStorage[\s\S]*?\/>\s*/g, "")
    .replace(/<script\b[\s\S]*?localStorage[\s\S]*?<\/script>\s*/g, "");
  fs.writeFileSync(rootLayoutPath, rootLayout);
}

const themesLibPath = path.join(work, "src/lib/themes.ts");
if (fs.existsSync(themesLibPath)) {
  let themesLib = fs.readFileSync(themesLibPath, "utf8");
  // Opaque-origin sandboxed iframes throw SecurityError on window.localStorage.
  // Swap localStorage for an in-memory shim so ThemeSwitcher still works per-view without storage access.
  themesLib = `const __sandboxThemeMemoryStore = new Map<string, string>();
const __axonwallSandboxStorage = {
  getItem: (k: string): string | null => __sandboxThemeMemoryStore.get(k) ?? null,
  setItem: (k: string, v: string): void => { __sandboxThemeMemoryStore.set(k, String(v)); },
  removeItem: (k: string): void => { __sandboxThemeMemoryStore.delete(k); },
};
` + themesLib.replace(/\blocalStorage\b/g, "__axonwallSandboxStorage");
  fs.writeFileSync(themesLibPath, themesLib);
}

const docsLayoutPath = path.join(work, "src/app/docs/layout.tsx");
if (fs.existsSync(docsLayoutPath)) {
  let layout = fs.readFileSync(docsLayoutPath, "utf8");
  layout = layout.replace("<Link href=\"/\" className=\"flex items-center gap-3 group\">", "<Link href=\"/docs/\" className=\"flex items-center gap-3 group\">");
  layout = layout.replace(
    `<Link\n            href="/"\n            className="hidden sm:flex items-center gap-1.5 text-slate-400 hover:text-white transition px-2.5 py-1.5 rounded-lg hover:bg-slate-800/50"\n          >\n            <ArrowLeft className="w-3.5 h-3.5" /> Back to Home\n          </Link>`,
    `<a\n            href="https://axonwall.com"\n            target="_blank"\n            rel="noopener noreferrer"\n            className="hidden sm:flex items-center gap-1.5 text-slate-400 hover:text-white transition px-2.5 py-1.5 rounded-lg hover:bg-slate-800/50"\n          >\n            <ExternalLink className="w-3.5 h-3.5" /> axonwall.com\n          </a>`
  );
  layout = layout.replace(
    `<Link\n            href="/architecture"\n            className="hidden sm:inline-block text-slate-400 hover:text-white transition px-2.5 py-1.5 rounded-lg hover:bg-slate-800/50"\n          >\n            Architecture\n          </Link>`,
    `<a\n            href="https://axonwall.com/architecture"\n            target="_blank"\n            rel="noopener noreferrer"\n            className="hidden sm:inline-block text-slate-400 hover:text-white transition px-2.5 py-1.5 rounded-lg hover:bg-slate-800/50"\n          >\n            Architecture\n          </a>`
  );
  layout = layout.replace(
    `<Link\n            href="/releases"\n            className="hidden sm:inline-block text-slate-400 hover:text-white transition px-2.5 py-1.5 rounded-lg hover:bg-slate-800/50"\n          >\n            Releases\n          </Link>`,
    `<a\n            href="https://axonwall.com/releases"\n            target="_blank"\n            rel="noopener noreferrer"\n            className="hidden sm:inline-block text-slate-400 hover:text-white transition px-2.5 py-1.5 rounded-lg hover:bg-slate-800/50"\n          >\n            Releases\n          </a>`
  );
  fs.writeFileSync(docsLayoutPath, layout);
}

const k3sPagePath = path.join(work, "src/app/docs/k3s-kubernetes/page.tsx");
if (fs.existsSync(k3sPagePath)) {
  let k3s = fs.readFileSync(k3sPagePath, "utf8");
  k3s = k3s
    .replaceAll(`href="/docs/installer-raid-zfs#k3s-storage-edition"`, `href="/api/docs-bundle/docs/installer-raid-zfs/#k3s-storage-edition"`)
    .replaceAll(`href="/docs/custom-kernel"`, `href="/api/docs-bundle/docs/custom-kernel/"`)
    .replaceAll(`<a href="/k3s/explorer"`, `<a href="/k3s/explorer" target="_blank" rel="noopener noreferrer"`)
    .replaceAll(`<a href="/k3s/cluster"`, `<a href="/k3s/cluster" target="_blank" rel="noopener noreferrer"`);
  fs.writeFileSync(k3sPagePath, k3s);
}

// Strip any remaining target="_top" attributes across all copied source files so
// links never depend on allow-top-navigation inside the sandboxed docs iframe.
function stripTopTargets(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      stripTopTargets(full);
    } else if (/\.(tsx?|jsx?|html)$/.test(entry.name)) {
      const orig = fs.readFileSync(full, "utf8");
      const next = orig.replace(/\s+target=(["'\''])_top\1/g, "");
      if (next !== orig) {
        fs.writeFileSync(full, next);
      }
    }
  }
}
stripTopTargets(path.join(work, "src"));
'

echo "[docs-bundle] Exporting static offline documentation bundle (v${VERSION})..."
(
  cd "${WORK}"
  NEXT_TELEMETRY_DISABLED=1 ./node_modules/.bin/next build >/dev/null
)

if [[ ! -f "${WORK}/out/docs/index.html" ]]; then
  echo "ERROR: Expected ${WORK}/out/docs/index.html after static export, but it was not produced." >&2
  exit 1
fi

GUIDE_COUNT="$(find "${WORK}/out/docs" -type f -name 'index.html' | wc -l | tr -d ' ')"

mkdir -p "${WORK}/payload"
cp -rL "${WORK}/out/docs" "${WORK}/payload/docs"
cp -rL "${WORK}/out/_next" "${WORK}/payload/_next"
for asset in favicon.svg logo-icon.svg; do
  if [[ -f "${WORK}/out/${asset}" ]]; then
    cp -L "${WORK}/out/${asset}" "${WORK}/payload/${asset}"
  fi
done

BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "${WORK}/payload/manifest.json" <<EOF
{
  "id": "docs-portal",
  "version": "${VERSION}",
  "basePath": "/api/docs-bundle",
  "builtAt": "${BUILT_AT}",
  "guides": ${GUIDE_COUNT}
}
EOF

find "${WORK}/payload" -type d -exec chmod 0755 {} +
find "${WORK}/payload" -type f -exec chmod 0644 {} +

mkdir -p "${OUT_DIR}"
TAR_NAME="axonwall-docs-${VERSION}.tar.gz"
LATEST_NAME="axonwall-docs-latest.tar.gz"

rm -f \
  "${OUT_DIR}/${TAR_NAME}" "${OUT_DIR}/${TAR_NAME}.sha256" "${OUT_DIR}/${TAR_NAME}.sha256.sig" \
  "${OUT_DIR}/${LATEST_NAME}" "${OUT_DIR}/${LATEST_NAME}.sha256" "${OUT_DIR}/${LATEST_NAME}.sha256.sig"

if tar --sort=name --help >/dev/null 2>&1; then
  (cd "${WORK}/payload" && tar --sort=name --owner=0 --group=0 --numeric-owner -czf "${OUT_DIR}/${TAR_NAME}" *)
else
  (cd "${WORK}/payload" && tar -czf "${OUT_DIR}/${TAR_NAME}" *)
fi
cp "${OUT_DIR}/${TAR_NAME}" "${OUT_DIR}/${LATEST_NAME}"
chmod 0644 "${OUT_DIR}/${TAR_NAME}" "${OUT_DIR}/${LATEST_NAME}"

(
  cd "${OUT_DIR}"
  sha256sum "${TAR_NAME}" > "${TAR_NAME}.sha256"
  sha256sum "${LATEST_NAME}" > "${LATEST_NAME}.sha256"
  chmod 0644 "${TAR_NAME}.sha256" "${LATEST_NAME}.sha256"
)

BYTES="$(wc -c < "${OUT_DIR}/${TAR_NAME}" | tr -d ' ')"
SHA="$(awk '{print $1}' "${OUT_DIR}/${TAR_NAME}.sha256")"
echo "[docs-bundle] Built ${OUT_DIR}/${TAR_NAME} (${BYTES} bytes, ${GUIDE_COUNT} guides, sha256=${SHA})"
