import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertMeshSelfServicePermitted } from '@/server/auth-guard';
import {
  assertMachineOwnedByUser,
  deleteMachine,
  expireMachine,
  renameMachine,
  resolveHeadscaleUsername,
} from '@/server/headscale';
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

    const body = await req.json().catch(() => ({}));
    const { action, machineId, newName } = body || {};

    if (machineId === undefined || machineId === null || String(machineId).trim() === '') {
      return NextResponse.json({ status: 'error', error: 'machineId is required' }, { status: 400 });
    }

    if (action !== 'rename' && action !== 'expire' && action !== 'delete') {
      return NextResponse.json(
        { status: 'error', error: `Invalid action '${action}': expected rename, expire, or delete` },
        { status: 400 }
      );
    }

    // Strict IDOR guard: verify the machine belongs to the authenticated user's Headscale namespace.
    await assertMachineOwnedByUser(ownerUser, machineId);

    if (action === 'rename') {
      if (typeof newName !== 'string' || !newName.trim()) {
        return NextResponse.json({ status: 'error', error: 'newName is required' }, { status: 400 });
      }
      const m = await renameMachine(machineId, newName.trim());
      return NextResponse.json({ status: 'ok', data: m });
    }

    if (action === 'expire') {
      const m = await expireMachine(machineId);
      return NextResponse.json({ status: 'ok', data: m });
    }

    await deleteMachine(machineId);
    return NextResponse.json({ status: 'ok' });
  } catch (err: any) {
    const msg = err?.message || 'Device operation failed';
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
