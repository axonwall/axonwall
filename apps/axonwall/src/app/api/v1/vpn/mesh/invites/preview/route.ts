import { NextRequest, NextResponse } from 'next/server';
import { callAgentApiDetailed } from '@/server/agent-client';
import { getDesiredStateInternal } from '@/server/desired-state-internal';
import { checkInviteRateLimit, previewHeadscaleInvite } from '@/server/headscale-invites';
import { resolveClientIp, resolveHeadscaleNetworkInfo } from '@/server/headscale-network';
import { checkPluginApiGuard } from '@/server/plugin-guard';

export const dynamic = 'force-dynamic';

const NO_STORE_HEADERS = { 'Cache-Control': 'no-store' };

async function ensureMeshInvitesEnabled(): Promise<NextResponse | null> {
  const pluginGuard = await checkPluginApiGuard('headscale');
  if (pluginGuard) {
    pluginGuard.headers.set('Cache-Control', 'no-store');
    return pluginGuard;
  }
  const state = await getDesiredStateInternal().catch(() => null);
  if (state?.headscale?.enabled !== true) {
    return NextResponse.json(
      { status: 'error', error: 'Forbidden: Mesh VPN (Headscale) is currently disabled' },
      { status: 403, headers: NO_STORE_HEADERS }
    );
  }
  return null;
}

export async function GET() {
  return NextResponse.json(
    { status: 'error', error: 'Method Not Allowed: use POST with JSON body { token }' },
    { status: 405, headers: { Allow: 'POST', 'Cache-Control': 'no-store' } }
  );
}

export async function POST(req: NextRequest) {
  const disabledRes = await ensureMeshInvitesEnabled();
  if (disabledRes) {
    return disabledRes;
  }

  const clientIp = resolveClientIp(req);
  if (!checkInviteRateLimit(clientIp)) {
    return NextResponse.json(
      { status: 'error', error: 'Too many invite lookups. Please wait a few minutes and try again.' },
      { status: 429, headers: NO_STORE_HEADERS }
    );
  }

  const body = await req.json().catch(() => ({}));
  const token = typeof body?.token === 'string' ? body.token.trim() : '';
  let preview: ReturnType<typeof previewHeadscaleInvite>;
  try {
    preview = previewHeadscaleInvite(token);
  } catch (err: any) {
    return NextResponse.json(
      { status: 'error', error: err?.message || 'Invite store unavailable' },
      { status: 503, headers: NO_STORE_HEADERS }
    );
  }
  const network = await resolveHeadscaleNetworkInfo(req);

  let minPasswordLength = 12;
  try {
    const dirStatus = await callAgentApiDetailed<{ passwordPolicy?: { minLength?: number } }>(
      '/v1/system/directory/status',
      'GET',
      undefined,
      2000
    );
    if (dirStatus.kind === 'ok' && typeof dirStatus.data.passwordPolicy?.minLength === 'number') {
      minPasswordLength = Math.max(8, dirStatus.data.passwordPolicy.minLength);
    }
  } catch {}

  if (preview.status !== 'valid' || !preview.invite) {
    return NextResponse.json(
      {
        status: 'ok',
        data: {
          status: preview.status,
          magicDnsDomain: network.magicDnsDomain,
          portalUrl: network.portalUrl,
          minPasswordLength,
        },
      },
      { headers: NO_STORE_HEADERS }
    );
  }

  return NextResponse.json(
    {
      status: 'ok',
      data: {
        status: 'valid',
        username: preview.invite.username,
        displayName: preview.invite.displayName,
        mode: preview.invite.mode,
        expiresAt: preview.invite.expiresAt,
        createStarterKey: preview.invite.createStarterKey,
        requiresPin: Boolean(preview.invite.requiresPin),
        magicDnsDomain: network.magicDnsDomain,
        portalUrl: network.portalUrl,
        minPasswordLength,
      },
    },
    { headers: NO_STORE_HEADERS }
  );
}
