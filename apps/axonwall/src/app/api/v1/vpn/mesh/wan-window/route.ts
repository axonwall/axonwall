import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { checkPluginApiGuard } from '@/server/plugin-guard';
import { callAgentApiDetailed } from '@/server/agent-client';
import { getActivePendingInviteWindow } from '@/server/headscale-invites';
import { resolveHeadscaleNetworkInfo } from '@/server/headscale-network';

export const dynamic = 'force-dynamic';

export interface HeadscaleWanWindowStatusDto {
  enabled: boolean;
  autoWindow: boolean;
  bindPort: number;
  hostname: string;
  windowOpen: boolean;
  reason: 'disabled' | 'always_open' | 'pending_invites' | 'manual_arm' | 'closed';
  pendingCount: number;
  pendingExpiresAt?: string;
  manualExpiresAt?: string;
  effectiveExpiresAt?: string;
  portKnockingEnabled: boolean;
  knockProtocol?: string;
  knockSequence?: number[];
  knockedIPs: string[];
  lastSyncError?: string;
  dryRun?: boolean;
  daemonAvailable: boolean;
}

function buildFallbackStatus(
  network: Awaited<ReturnType<typeof resolveHeadscaleNetworkInfo>>
): HeadscaleWanWindowStatusDto {
  const localPending = getActivePendingInviteWindow();
  const wan = network.wanInvite;
  const open =
    wan.enabled && (!wan.autoWindow || localPending.pendingCount > 0);
  const reason: HeadscaleWanWindowStatusDto['reason'] = !wan.enabled
    ? 'disabled'
    : !wan.autoWindow
      ? 'always_open'
      : localPending.pendingCount > 0
        ? 'pending_invites'
        : 'closed';
  return {
    enabled: wan.enabled,
    autoWindow: wan.autoWindow,
    bindPort: wan.bindPort,
    hostname: wan.hostname,
    windowOpen: open,
    reason,
    pendingCount: localPending.pendingCount,
    ...(localPending.latestExpiresAt
      ? {
          pendingExpiresAt: localPending.latestExpiresAt,
          effectiveExpiresAt: localPending.latestExpiresAt,
        }
      : {}),
    portKnockingEnabled: wan.portKnocking.enabled,
    knockProtocol: wan.portKnocking.protocol,
    knockSequence: wan.portKnocking.sequence,
    knockedIPs: [],
    daemonAvailable: false,
  };
}

export async function GET(req: NextRequest) {
  const session = await getSession();
  try {
    assertActionPermitted(session, 'admin');
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unauthorized';
    return NextResponse.json({ status: 'error', error: msg }, { status: msg === 'Unauthorized' ? 401 : 403 });
  }
  const guard = await checkPluginApiGuard('headscale');
  if (guard) return guard;

  const network = await resolveHeadscaleNetworkInfo(req);
  const agentRes = await callAgentApiDetailed<{
    success: boolean;
    data?: Omit<HeadscaleWanWindowStatusDto, 'daemonAvailable'>;
  }>('/v1/vpn/headscale/wan-window/status', 'GET', undefined, 2500);

  if (agentRes.kind === 'ok' && agentRes.data?.success && agentRes.data.data) {
    return NextResponse.json({
      status: 'ok',
      data: {
        ...agentRes.data.data,
        knockedIPs: agentRes.data.data.knockedIPs ?? [],
        daemonAvailable: true,
      },
    });
  }

  return NextResponse.json({
    status: 'ok',
    data: buildFallbackStatus(network),
  });
}

export async function POST(req: NextRequest) {
  const session = await getSession();
  try {
    assertActionPermitted(session, 'admin');
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unauthorized';
    return NextResponse.json({ status: 'error', error: msg }, { status: msg === 'Unauthorized' ? 401 : 403 });
  }
  const guard = await checkPluginApiGuard('headscale');
  if (guard) return guard;

  const body = await req.json().catch(() => ({}));
  const action = typeof body?.action === 'string' ? body.action.trim() : 'sync';

  if (action === 'sync') {
    const agentRes = await callAgentApiDetailed<{
      success: boolean;
      data?: Omit<HeadscaleWanWindowStatusDto, 'daemonAvailable'>;
      error?: string;
    }>('/v1/vpn/headscale/wan-window/sync', 'POST', {}, 3000);
    if (agentRes.kind === 'ok' && agentRes.data?.success && agentRes.data.data) {
      return NextResponse.json({
        status: 'ok',
        data: {
          ...agentRes.data.data,
          knockedIPs: agentRes.data.data.knockedIPs ?? [],
          daemonAvailable: true,
        },
      });
    }
    return NextResponse.json(
      { status: 'error', error: 'Daemon unavailable: unable to sync WAN invite window' },
      { status: 503 }
    );
  }

  if (action === 'arm' || action === 'close') {
    const durationSec =
      action === 'close'
        ? 0
        : Math.min(86400, Math.max(60, Math.round(Number(body?.durationSec) || 1800)));
    const agentRes = await callAgentApiDetailed<{
      success: boolean;
      data?: Omit<HeadscaleWanWindowStatusDto, 'daemonAvailable'>;
      error?: string;
    }>('/v1/vpn/headscale/wan-window/arm', 'POST', { durationSec }, 3000);
    if (agentRes.kind === 'ok' && agentRes.data?.success && agentRes.data.data) {
      return NextResponse.json({
        status: 'ok',
        data: {
          ...agentRes.data.data,
          knockedIPs: agentRes.data.data.knockedIPs ?? [],
          daemonAvailable: true,
        },
      });
    }
    return NextResponse.json(
      {
        status: 'error',
        error:
          agentRes.kind === 'http_error'
            ? agentRes.message
            : 'Daemon unavailable: unable to update WAN invite window',
      },
      { status: 503 }
    );
  }

  return NextResponse.json(
    { status: 'error', error: `Unsupported action '${action}'; expected sync, arm, or close` },
    { status: 400 }
  );
}
