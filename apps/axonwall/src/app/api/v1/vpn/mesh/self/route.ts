import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertMeshSelfServicePermitted } from '@/server/auth-guard';
import { getDesiredStateInternal } from '@/server/desired-state-internal';
import { checkPluginApiGuard } from '@/server/plugin-guard';
import {
  ensureUser,
  isHeadscaleSocketReady,
  listMachines,
  listPreAuthKeys,
  resolveHeadscaleUsername,
} from '@/server/headscale';
import { resolveHeadscaleNetworkInfo } from '@/server/headscale-network';

export const dynamic = 'force-dynamic';

function mapAuthStatus(err: unknown): number {
  const msg = err instanceof Error ? err.message : '';
  if (msg === 'Unauthorized') return 401;
  if (msg.startsWith('Forbidden')) return 403;
  return 500;
}

export async function GET(req: NextRequest) {
  try {
    const session = await getSession();
    assertMeshSelfServicePermitted(session);
    const pluginGuard = await checkPluginApiGuard('headscale');
    if (pluginGuard) return pluginGuard;

    const headscaleUser = resolveHeadscaleUsername(session);
    const [network, state] = await Promise.all([
      resolveHeadscaleNetworkInfo(req),
      getDesiredStateInternal().catch(() => null),
    ]);

    const explicitlyDisabled = state?.headscale?.enabled === false;
    const serviceRunning = isHeadscaleSocketReady();

    let devices: Awaited<ReturnType<typeof listMachines>> = [];
    let keys: Array<{
      id: string | number;
      keyPreview: string;
      reusable: boolean;
      ephemeral: boolean;
      used: boolean;
      expired: boolean;
      expiration?: string;
      createdAt?: string;
    }> = [];
    let headscaleError: string | null = null;

    if (serviceRunning && !explicitlyDisabled) {
      try {
        await ensureUser(headscaleUser);
        const [ownedMachines, ownedKeys] = await Promise.all([
          listMachines(headscaleUser),
          listPreAuthKeys(headscaleUser),
        ]);
        devices = ownedMachines;
        keys = ownedKeys.map((k) => ({
          id: k.id,
          keyPreview: k.keyPreview,
          reusable: k.reusable,
          ephemeral: k.ephemeral,
          used: k.used,
          expired: k.expired,
          expiration: k.expiration,
          createdAt: k.createdAt,
        }));
      } catch (err: any) {
        headscaleError = err?.message || 'Unable to contact Headscale control plane';
      }
    } else if (!serviceRunning) {
      headscaleError = 'Headscale service is not currently running on this appliance';
    } else {
      headscaleError = 'Mesh VPN (Headscale) is currently disabled by your administrator';
    }

    const { wanInvite: _omitWanInvite, ...safeNetwork } = network;

    return NextResponse.json({
      status: 'ok',
      data: {
        account: {
          username: session.username,
          displayName: session.displayName || session.username,
          headscaleUser,
          role: session.roles[0] || 'vpn_user',
          source: session.source,
          canChangePassword: session.source === 'local',
        },
        network: {
          ...safeNetwork,
          serviceRunning,
        },
        headscaleError,
        devices,
        keys,
      },
    });
  } catch (err: unknown) {
    const status = mapAuthStatus(err);
    const message = err instanceof Error ? err.message : 'Failed to load self-service VPN account';
    return NextResponse.json({ status: 'error', error: message }, { status });
  }
}
