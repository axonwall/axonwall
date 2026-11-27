import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { callAgentApiResponse } from '@/server/agent-client';
import { resolveHeadscaleNetworkInfo } from '@/server/headscale-network';
import { checkPluginApiGuard } from '@/server/plugin-guard';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');
    const guard = await checkPluginApiGuard('headscale');
    if (guard) return guard;

    const network = await resolveHeadscaleNetworkInfo(req);
    return NextResponse.json({ status: 'ok', data: network });
  } catch (err: any) {
    const msg = err?.message || 'Failed to read Headscale config';
    const status = msg === 'Unauthorized' ? 401 : msg.startsWith('Forbidden') ? 403 : 500;
    return NextResponse.json(
      { status: 'error', error: msg },
      { status }
    );
  }
}

export async function POST(req: NextRequest) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');
    const guard = await checkPluginApiGuard('headscale');
    if (guard) return guard;

    const body = await req.json().catch(() => ({}));
    const serverUrl = typeof body?.serverUrl === 'string' ? body.serverUrl.trim() : '';
    const magicDnsDomain = typeof body?.magicDnsDomain === 'string' ? body.magicDnsDomain.trim() : '';

    const res = await callAgentApiResponse<{
      success?: boolean;
      changed?: boolean;
      reloaded?: boolean;
      message?: string;
      error?: string;
    }>('/v1/vpn/headscale/sync-config', 'POST', {
      serverUrl,
      magicDnsDomain,
    });

    if (!res) {
      return NextResponse.json(
        { status: 'error', error: 'Daemon unavailable: could not sync /etc/headscale/config.yaml' },
        { status: 503 }
      );
    }
    if (!res.success) {
      return NextResponse.json(
        { status: 'error', error: res.error || res.message || 'Failed to sync Headscale config' },
        { status: 400 }
      );
    }

    return NextResponse.json({ status: 'ok', data: res });
  } catch (err: any) {
    const msg = err?.message || 'Failed to sync Headscale config';
    const status = msg === 'Unauthorized' ? 401 : msg.startsWith('Forbidden') ? 403 : 500;
    return NextResponse.json(
      { status: 'error', error: msg },
      { status }
    );
  }
}
