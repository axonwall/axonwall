import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertMeshSelfServicePermitted } from '@/server/auth-guard';
import { registerMachine, resolveHeadscaleUsername } from '@/server/headscale';
import { resolveHeadscaleNetworkInfo } from '@/server/headscale-network';
import { checkPluginApiGuard } from '@/server/plugin-guard';

export async function POST(req: NextRequest) {
  try {
    const session = await getSession();
    assertMeshSelfServicePermitted(session);
    const pluginGuard = await checkPluginApiGuard('headscale');
    if (pluginGuard) return pluginGuard;
    const ownerUser = resolveHeadscaleUsername(session);

    const network = await resolveHeadscaleNetworkInfo(req);
    if (!network.enabled) {
      return NextResponse.json(
        { status: 'error', error: 'Forbidden: Mesh VPN (Headscale) is currently disabled by your administrator' },
        { status: 403 }
      );
    }
    if (!network.allowSelfRegistration) {
      return NextResponse.json(
        { status: 'error', error: 'Forbidden: Device self-registration is disabled by your administrator' },
        { status: 403 }
      );
    }

    const body = await req.json().catch(() => ({}));
    const rawKey = typeof body?.key === 'string' ? body.key.trim() : '';
    if (!rawKey) {
      return NextResponse.json(
        { status: 'error', error: 'Registration key or auth ID is required' },
        { status: 400 }
      );
    }

    const registered = await registerMachine(ownerUser, rawKey);
    return NextResponse.json({ status: 'ok', data: registered });
  } catch (err: any) {
    const msg = err?.message || 'Device registration failed';
    const status = msg === 'Unauthorized' ? 401 : msg.startsWith('Forbidden') ? 403 : 400;
    return NextResponse.json({ status: 'error', error: msg }, { status });
  }
}
