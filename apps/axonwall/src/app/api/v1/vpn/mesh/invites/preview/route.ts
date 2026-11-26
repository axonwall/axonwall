import { NextRequest, NextResponse } from 'next/server';
import { callAgentApiDetailed } from '@/server/agent-client';
import { checkInviteRateLimit, previewHeadscaleInvite } from '@/server/headscale-invites';
import { resolveClientIp, resolveHeadscaleNetworkInfo } from '@/server/headscale-network';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const clientIp = resolveClientIp(req);
  if (!checkInviteRateLimit(clientIp)) {
    return NextResponse.json(
      { status: 'error', error: 'Too many invite lookups. Please wait a few minutes and try again.' },
      { status: 429 }
    );
  }

  const token = req.nextUrl.searchParams.get('token') || '';
  const preview = previewHeadscaleInvite(token);
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
    return NextResponse.json({
      status: 'ok',
      data: {
        status: preview.status,
        magicDnsDomain: network.magicDnsDomain,
        minPasswordLength,
      },
    });
  }

  return NextResponse.json({
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
      minPasswordLength,
    },
  });
}
