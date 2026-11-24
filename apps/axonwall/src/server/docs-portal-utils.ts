import fs from 'node:fs';
import path from 'node:path';
import { getStateDir } from './dev-paths';
export { ONLINE_DOCS_BASE_URL, buildOnlineDocsUrl } from '@/lib/docs-portal-urls';

export interface DocsBundleMeta {
  installed: boolean;
  version: string | null;
  guideCount: number | null;
  builtAt: string | null;
}

export type DocsBundleFileResolution =
  | {
      ok: true;
      filePath: string;
      contentType: string;
      isImmutableAsset: boolean;
    }
  | {
      ok: false;
      status: 400 | 404;
      reason: string;
    };

const MIME_BY_EXT: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
};

export function getDocsBundleSiteDir(stateDir?: string): string {
  return path.join(stateDir ?? getStateDir(), 'docs-portal', 'site');
}

export function readDocsBundleMeta(siteDir: string): DocsBundleMeta {
  const indexPath = path.join(siteDir, 'docs', 'index.html');
  let installed = false;
  try {
    installed = fs.lstatSync(indexPath).isFile();
  } catch {
    installed = false;
  }
  if (!installed) {
    return {
      installed: false,
      version: null,
      guideCount: null,
      builtAt: null,
    };
  }

  let version: string | null = null;
  let guideCount: number | null = null;
  let builtAt: string | null = null;
  try {
    const manifestPath = path.join(siteDir, 'manifest.json');
    if (fs.lstatSync(manifestPath).isFile()) {
      const parsed = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      if (typeof parsed?.version === 'string') version = parsed.version;
      if (typeof parsed?.guides === 'number') guideCount = parsed.guides;
      if (typeof parsed?.builtAt === 'string') builtAt = parsed.builtAt;
    }
  } catch {
    // Metadata manifest is optional; entrypoint presence determines installation.
  }

  return {
    installed: true,
    version,
    guideCount,
    builtAt,
  };
}

function isSafePathSegment(seg: string): boolean {
  if (!seg || seg === '.' || seg === '..' || seg.startsWith('.')) {
    return false;
  }
  if (seg.includes('/') || seg.includes('\\') || seg.includes('\0')) {
    return false;
  }
  for (let i = 0; i < seg.length; i++) {
    const code = seg.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      return false;
    }
  }
  return true;
}

export function resolveDocsBundleFile(
  siteDir: string,
  rawSegments: string[]
): DocsBundleFileResolution {
  const segments =
    rawSegments.length > 0 && rawSegments[rawSegments.length - 1] === ''
      ? rawSegments.slice(0, -1)
      : [...rawSegments];

  for (const seg of segments) {
    if (!isSafePathSegment(seg)) {
      return { ok: false, status: 400, reason: 'Invalid path segment in docs bundle request.' };
    }
  }

  let realRoot: string;
  try {
    realRoot = fs.realpathSync(siteDir);
  } catch {
    return { ok: false, status: 404, reason: 'Offline documentation bundle is not installed.' };
  }

  const effectiveSegments = segments.length === 0 ? ['docs', 'index.html'] : segments;
  const candidate = path.join(realRoot, ...effectiveSegments);
  const candidatesToTry = [candidate];
  if (!path.extname(effectiveSegments[effectiveSegments.length - 1] || '')) {
    candidatesToTry.push(path.join(candidate, 'index.html'));
  }

  for (const fileCandidate of candidatesToTry) {
    try {
      const lstat = fs.lstatSync(fileCandidate);
      if (lstat.isSymbolicLink() || !lstat.isFile()) {
        continue;
      }
      const realFile = fs.realpathSync(fileCandidate);
      if (realFile !== realRoot && !realFile.startsWith(`${realRoot}${path.sep}`)) {
        return { ok: false, status: 400, reason: 'Path escapes docs bundle root.' };
      }
      const ext = path.extname(realFile).toLowerCase();
      const contentType = MIME_BY_EXT[ext] || 'application/octet-stream';
      const isImmutableAsset =
        effectiveSegments[0] === '_next' && effectiveSegments[1] === 'static';
      return {
        ok: true,
        filePath: realFile,
        contentType,
        isImmutableAsset,
      };
    } catch {
      continue;
    }
  }

  return { ok: false, status: 404, reason: 'Requested documentation asset not found.' };
}
