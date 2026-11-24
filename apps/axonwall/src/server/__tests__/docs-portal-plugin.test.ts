import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { DesiredStateSchema } from '@axonwall/lib/schemas';
import type { UserSession } from '@axonwall/lib/rbac';
import {
  buildOnlineDocsUrl,
  getDocsBundleSiteDir,
  readDocsBundleMeta,
  resolveDocsBundleFile,
} from '../docs-portal-utils';

const hoisted = vi.hoisted(() => {
  const adminSession: UserSession = {
    userId: 'admin-1',
    username: 'admin',
    displayName: 'Administrator',
    roles: ['admin'],
    privileges: [],
    passwordChangeRequired: false,
    source: 'local',
    exp: Math.floor(Date.now() / 1000) + 3600,
  };
  return {
    adminSession,
    getSession: vi.fn<() => Promise<UserSession | null>>(async () => adminSession),
    getDesiredStateInternal: vi.fn(async () => DesiredStateSchema.parse({ version: 1 })),
  };
});

vi.mock('../auth', () => ({
  getSession: hoisted.getSession,
}));

vi.mock('../desired-state-internal', () => ({
  getDesiredStateInternal: hoisted.getDesiredStateInternal,
}));

import { GET as docsBundleGet } from '@/app/api/docs-bundle/[[...path]]/route';

function makeTempStateWithBundle(): { tmpStateDir: string; siteDir: string } {
  const tmpStateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-docs-test-'));
  const siteDir = getDocsBundleSiteDir(tmpStateDir);
  fs.mkdirSync(path.join(siteDir, 'docs', 'high-availability'), { recursive: true });
  fs.mkdirSync(path.join(siteDir, '_next', 'static', 'css'), { recursive: true });
  fs.writeFileSync(path.join(siteDir, 'docs', 'index.html'), '<html><body>Docs Index</body></html>');
  fs.writeFileSync(
    path.join(siteDir, 'docs', 'high-availability', 'index.html'),
    '<html><body>HA Guide</body></html>'
  );
  fs.writeFileSync(
    path.join(siteDir, '_next', 'static', 'css', 'app.css'),
    'body { background: #080c14; }'
  );
  fs.writeFileSync(
    path.join(siteDir, 'manifest.json'),
    JSON.stringify({ id: 'docs-portal', version: '0.15.1', guides: 26 })
  );
  return { tmpStateDir, siteDir };
}

describe('Offline Documentation Portal (docs-portal)', () => {
  const tempDirs: string[] = [];
  const origStateDir = process.env.AXONWALL_STATE_DIR;

  beforeEach(() => {
    vi.clearAllMocks();
    hoisted.getSession.mockResolvedValue(hoisted.adminSession);
    hoisted.getDesiredStateInternal.mockResolvedValue(DesiredStateSchema.parse({ version: 1 }));
  });

  afterEach(() => {
    if (origStateDir === undefined) {
      delete process.env.AXONWALL_STATE_DIR;
    } else {
      process.env.AXONWALL_STATE_DIR = origStateDir;
    }
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop();
      if (dir) fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('builds safe fallback URLs pointing to axonwall.com/docs', () => {
    expect(buildOnlineDocsUrl()).toBe('https://axonwall.com/docs');
    expect(buildOnlineDocsUrl(['high-availability'], '#two-host-setup')).toBe(
      'https://axonwall.com/docs/high-availability#two-host-setup'
    );
    expect(buildOnlineDocsUrl(['../etc/passwd', 'architecture'], '#evil<script>')).toBe(
      'https://axonwall.com/docs/architecture'
    );
  });

  it('resolves valid guides and immutable assets while blocking traversal and symlinks', () => {
    const { tmpStateDir, siteDir } = makeTempStateWithBundle();
    tempDirs.push(tmpStateDir);

    const outsideFile = path.join(tmpStateDir, 'secret.txt');
    fs.writeFileSync(outsideFile, 'top-secret');
    fs.symlinkSync(outsideFile, path.join(siteDir, 'docs', 'leak.html'));

    expect(readDocsBundleMeta(siteDir)).toEqual({
      installed: true,
      version: '0.15.1',
      guideCount: 26,
      builtAt: null,
    });

    const rootRes = resolveDocsBundleFile(siteDir, []);
    expect(rootRes.ok).toBe(true);
    if (rootRes.ok) {
      expect(rootRes.filePath).toBe(path.join(fs.realpathSync(siteDir), 'docs', 'index.html'));
      expect(rootRes.contentType).toContain('text/html');
    }

    const dirRes = resolveDocsBundleFile(siteDir, ['docs', 'high-availability', '']);
    expect(dirRes.ok).toBe(true);
    if (dirRes.ok) {
      expect(dirRes.filePath).toBe(
        path.join(fs.realpathSync(siteDir), 'docs', 'high-availability', 'index.html')
      );
    }

    const cssRes = resolveDocsBundleFile(siteDir, ['_next', 'static', 'css', 'app.css']);
    expect(cssRes.ok).toBe(true);
    if (cssRes.ok) {
      expect(cssRes.isImmutableAsset).toBe(true);
      expect(cssRes.contentType).toContain('text/css');
    }

    expect(resolveDocsBundleFile(siteDir, ['docs', '..', '..', 'secret.txt']).ok).toBe(false);
    expect(resolveDocsBundleFile(siteDir, ['.env']).ok).toBe(false);
    expect(resolveDocsBundleFile(siteDir, ['docs\\index.html']).ok).toBe(false);
    expect(resolveDocsBundleFile(siteDir, ['docs', 'leak.html']).ok).toBe(false);
    expect(resolveDocsBundleFile(siteDir, ['docs', 'missing-page']).ok).toBe(false);
  });

  it('GET /api/docs-bundle fails closed when unauthenticated, disabled, or uninstalled, and serves when enabled & installed', async () => {
    const { tmpStateDir } = makeTempStateWithBundle();
    tempDirs.push(tmpStateDir);
    process.env.AXONWALL_STATE_DIR = tmpStateDir;

    const req = new NextRequest('https://localhost/api/docs-bundle/docs/high-availability/');

    // 1. Unauthenticated -> 401
    hoisted.getSession.mockResolvedValueOnce(null);
    const unauth = await docsBundleGet(req, {
      params: Promise.resolve({ path: ['docs', 'high-availability'] }),
    });
    expect(unauth.status).toBe(401);

    // 2. Plugin disabled in DesiredState -> 403 even with bundle on disk
    const disabledRes = await docsBundleGet(req, {
      params: Promise.resolve({ path: ['docs', 'high-availability'] }),
    });
    expect(disabledRes.status).toBe(403);

    // 3. Enabled in DesiredState, installed on disk -> 200 SAMEORIGIN + HTML
    hoisted.getDesiredStateInternal.mockResolvedValue(
      DesiredStateSchema.parse({
        version: 1,
        plugins: [{ id: 'docs-portal', enabled: true }],
      })
    );
    const okRes = await docsBundleGet(req, {
      params: Promise.resolve({ path: ['docs', 'high-availability'] }),
    });
    expect(okRes.status).toBe(200);
    expect(okRes.headers.get('X-Frame-Options')).toBe('SAMEORIGIN');
    expect(okRes.headers.get('Content-Security-Policy')).toContain("connect-src 'none'");
    expect(okRes.headers.get('Content-Security-Policy')).toContain("frame-ancestors 'self'");
    expect(okRes.headers.get('Content-Type')).toContain('text/html');
    expect(await okRes.text()).toContain('HA Guide');

    // 4. Enabled in DesiredState, missing on disk -> 404
    fs.rmSync(path.join(tmpStateDir, 'docs-portal'), { recursive: true, force: true });
    const missingRes = await docsBundleGet(req, {
      params: Promise.resolve({ path: ['docs', 'high-availability'] }),
    });
    expect(missingRes.status).toBe(404);
  });
});
