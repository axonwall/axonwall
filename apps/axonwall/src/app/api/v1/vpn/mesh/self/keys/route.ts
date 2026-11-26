import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertMeshSelfServicePermitted } from '@/server/auth-guard';
import {
  assertPreAuthKeyOwnedByUser,
  createPreAuthKey,
  expirePreAuthKey,
  resolveHeadscaleUsername,
} from '@/server/headscale';
import { buildQuickConnectCommand, resolveHeadscaleNetworkInfo } from '@/server/headscale-network';

export async function POST(req: NextRequest) {
  try {
    const session = await getSession();
    assertMeshSelfServicePermitted(session);
    const ownerUser = resolveHeadscaleUsername(session);
    const network = await resolveHeadscaleNetworkInfo(req);
    if (!network.enabled) {
      return NextResponse.json(
        { status: 'error', error: 'Forbidden: Mesh VPN (Headscale) is currently disabled by your administrator' },
        { status: 403 }
      );
    }

    const body = await req.json().catch(() => ({}));
    const action = body?.action;

    if (action === 'expire') {
      const target = body?.keyId ?? body?.key;
      if (target === undefined || target === null || String(target).trim() === '') {
        return NextResponse.json(
          { status: 'error', error: 'keyId or key is required' },
          { status: 400 }
        );
      }

      // Strict IDOR guard: verify the key belongs to the caller's Headscale namespace.
      const owned = await assertPreAuthKeyOwnedByUser(ownerUser, target);
      await expirePreAuthKey(ownerUser, owned.key || String(owned.id), owned.id);
      return NextResponse.json({ status: 'ok' });
    }

    if (action === 'create') {
      if (!network.allowSelfRegistration) {
        return NextResponse.json(
          { status: 'error', error: 'Forbidden: Self-service key creation is disabled by your administrator' },
          { status: 403 }
        );
      }
      const rawHours = Number(body?.expiryHours ?? network.defaultKeyExpiryHours ?? 24);
      const expiryHours = Number.isFinite(rawHours) ? Math.min(720, Math.max(1, Math.round(rawHours))) : 24;
      const reusable = Boolean(body?.reusable);
      const ephemeral = Boolean(body?.ephemeral);
      const expIso = new Date(Date.now() + expiryHours * 3600 * 1000).toISOString();

      const created = await createPreAuthKey(ownerUser, reusable, ephemeral, expIso);
      return NextResponse.json({
        status: 'ok',
        data: {
          ...created,
          serverUrl: network.serverUrl,
          magicDnsDomain: network.magicDnsDomain,
          quickConnectCommand: buildQuickConnectCommand(network.serverUrl, created.key),
        },
      });
    }

    return NextResponse.json(
      { status: 'error', error: `Invalid action '${action}': expected create or expire` },
      { status: 400 }
    );
  } catch (err: any) {
    const msg = err?.message || 'Auth key operation failed';
    const status =
      msg === 'Unauthorized'
        ? 401
        : msg.startsWith('Forbidden')
          ? 403
          : err?.code === 'NOT_FOUND'
            ? 404
            : 400;
    return NextResponse.json({ status: 'error', error: msg }, { status });
  }
}
