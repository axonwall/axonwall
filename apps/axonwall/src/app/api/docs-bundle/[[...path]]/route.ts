import fs from 'node:fs';
import { NextRequest, NextResponse } from 'next/server';
import { isPluginEnabled } from '@axonwall/lib/plugins';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { getDesiredStateInternal } from '@/server/desired-state-internal';
import {
  getDocsBundleSiteDir,
  readDocsBundleMeta,
  resolveDocsBundleFile,
} from '@/server/docs-portal-utils';

export const dynamic = 'force-dynamic';

function mapAuthErrorStatus(message: string): number {
  if (message.includes('Unauthorized')) return 401;
  return 403;
}

export async function GET(
  _req: NextRequest,
  context: { params: Promise<{ path?: string[] }> }
) {
  try {
    const session = await getSession();
    assertActionPermitted(session);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unauthorized';
    return NextResponse.json({ error: message }, { status: mapAuthErrorStatus(message) });
  }

  const state = await getDesiredStateInternal();
  if (!isPluginEnabled('docs-portal', state)) {
    return NextResponse.json(
      { error: 'Offline Documentation Portal plugin (docs-portal) is disabled.' },
      { status: 403 }
    );
  }

  const siteDir = getDocsBundleSiteDir();
  const meta = readDocsBundleMeta(siteDir);
  if (!meta.installed) {
    return NextResponse.json(
      { error: 'Offline Documentation Portal bundle is not installed.' },
      { status: 404 }
    );
  }

  const resolvedParams = await context.params;
  const segments = resolvedParams?.path ?? [];
  const res = resolveDocsBundleFile(siteDir, segments);
  if (!res.ok) {
    return NextResponse.json({ error: res.reason }, { status: res.status });
  }

  const buf = fs.readFileSync(res.filePath);
  const cacheControl = res.isImmutableAsset
    ? 'private, max-age=31536000, immutable'
    : res.contentType.startsWith('text/html')
      ? 'private, no-cache'
      : 'private, max-age=3600';

  return new NextResponse(new Uint8Array(buf), {
    status: 200,
    headers: {
      'Content-Type': res.contentType,
      'Content-Security-Policy':
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'none'; form-action 'none'; frame-ancestors 'self'; object-src 'none'; base-uri 'none'; sandbox allow-scripts",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN',
      'Cache-Control': cacheControl,
    },
  });
}
