import { NextResponse } from 'next/server';
import { listPreAuthKeys, createPreAuthKey, expirePreAuthKey } from '../../../../../../server/headscale';
import { getSession } from '../../../../../../server/auth';
import { assertActionPermitted } from '../../../../../../server/auth-guard';
import { checkPluginApiGuard } from '../../../../../../server/plugin-guard';

function mapMeshErrStatus(err: unknown): number {
  if (err instanceof SyntaxError) return 400;
  const msg = err instanceof Error ? err.message : String(err || '');
  if (msg === 'Unauthorized') return 401;
  if (msg.startsWith('Forbidden')) return 403;
  if (/not found/i.test(msg)) return 404;
  if (/invalid|required|cannot start|must be|json/i.test(msg)) return 400;
  return 500;
}

export async function GET(req: Request) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');
    const guard = await checkPluginApiGuard('headscale');
    if (guard) return guard;
    const { searchParams } = new URL(req.url);
    const user = searchParams.get('user') || undefined;
    const keys = await listPreAuthKeys(user);
    return NextResponse.json({ status: 'ok', data: keys });
  } catch (err: any) {
    return NextResponse.json({ status: 'error', error: err?.message || 'Failed to list pre-auth keys' }, { status: mapMeshErrStatus(err) });
  }
}

export async function POST(req: Request) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');
    const guard = await checkPluginApiGuard('headscale');
    if (guard) return guard;
    const body = await req.json();
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return NextResponse.json({ status: 'error', error: 'Invalid JSON request body' }, { status: 400 });
    }
    const { action, user, reusable, ephemeral, expiration, key, keyId } = body;
    
    if (action === 'expire') {
      const keyTarget = key || keyId;
      if (!keyTarget || (typeof keyTarget !== 'string' && typeof keyTarget !== 'number')) {
        return NextResponse.json({ error: 'key or keyId is required' }, { status: 400 });
      }
      await expirePreAuthKey(typeof user === 'string' ? user : '', keyTarget, keyId);
      return NextResponse.json({ status: 'ok' });
    }

    // C21: only an explicit 'create' mints a key. The old fall-through
    // created a 30-day pre-auth key for any unrecognised action, so a
    // typo like 'expir' silently minted a credential instead of
    // expiring one.
    if (action !== 'create') {
      return NextResponse.json(
        { error: `Invalid action '${action}': expected 'create' or 'expire'` },
        { status: 400 }
      );
    }

    // Create new key
    if (typeof user !== 'string' || !user.trim()) {
      return NextResponse.json({ error: 'user is required' }, { status: 400 });
    }
    if (expiration !== undefined && typeof expiration !== 'string') {
      return NextResponse.json({ error: 'Invalid expiration timestamp' }, { status: 400 });
    }
    const newKey = await createPreAuthKey(
      user, 
      !!reusable, 
      !!ephemeral, 
      expiration || new Date(Date.now() + 86400000 * 30).toISOString() // default 30 days
    );
    return NextResponse.json({ status: 'ok', data: newKey });
  } catch (err: any) {
    const message = err instanceof SyntaxError ? 'Invalid JSON request body' : err?.message || 'Pre-auth key operation failed';
    return NextResponse.json({ status: 'error', error: message }, { status: mapMeshErrStatus(err) });
  }
}
