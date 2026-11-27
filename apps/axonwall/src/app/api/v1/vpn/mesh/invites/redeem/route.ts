import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { mintSupabaseToken } from '@axonwall/lib/ldap';
import { DEFAULT_ROLES, type UserSession } from '@axonwall/lib/rbac';
import { callAgentApiDetailed, callAgentApiResponse } from '@/server/agent-client';
import { getJwtSecret, SESSION_COOKIE } from '@/server/auth-constants';
import { getDesiredStateInternal } from '@/server/desired-state-internal';
import { createPreAuthKey, ensureUser, isHeadscaleSocketReady } from '@/server/headscale';
import {
  checkInviteRateLimit,
  consumeHeadscaleInvite,
  syncHeadscaleWanWindow,
} from '@/server/headscale-invites';
import {
  buildQuickConnectCommand,
  resolveClientIp,
  resolveHeadscaleNetworkInfo,
} from '@/server/headscale-network';
import { checkPluginApiGuard } from '@/server/plugin-guard';
import { bumpUserSessionEpoch, stampSessionEpoch } from '@/server/session-revocation';

export async function POST(req: NextRequest) {
  const pluginGuard = await checkPluginApiGuard('headscale');
  if (pluginGuard) {
    pluginGuard.headers.set('Cache-Control', 'no-store');
    return pluginGuard;
  }
  const desiredState = await getDesiredStateInternal().catch(() => null);
  if (desiredState?.headscale?.enabled !== true) {
    return NextResponse.json(
      { status: 'error', error: 'Forbidden: Mesh VPN (Headscale) is currently disabled' },
      { status: 403, headers: { 'Cache-Control': 'no-store' } }
    );
  }

  const clientIp = resolveClientIp(req);
  if (!checkInviteRateLimit(clientIp)) {
    return NextResponse.json(
      { status: 'error', error: 'Too many activation attempts. Try again in a few minutes.' },
      { status: 429 }
    );
  }

  try {
    const body = await req.json().catch(() => ({}));
    const token = typeof body?.token === 'string' ? body.token.trim() : '';
    const password = typeof body?.password === 'string' ? body.password : '';
    const confirmPassword = typeof body?.confirmPassword === 'string' ? body.confirmPassword : undefined;
    const pin = typeof body?.pin === 'string' ? body.pin.trim() : '';

    if (!token) {
      return NextResponse.json({ status: 'error', error: 'Invite token is required' }, { status: 400 });
    }
    if (!password) {
      return NextResponse.json({ status: 'error', error: 'Password is required' }, { status: 400 });
    }
    if (confirmPassword !== undefined && password !== confirmPassword) {
      return NextResponse.json(
        { status: 'error', error: 'Password and confirmation do not match' },
        { status: 400 }
      );
    }
    if (/[\r\n\x00]/.test(password)) {
      return NextResponse.json(
        { status: 'error', error: 'Password contains invalid control characters' },
        { status: 400 }
      );
    }

    let minLen = 12;
    try {
      const statusRes = await callAgentApiDetailed<{ passwordPolicy?: { minLength?: number } }>(
        '/v1/system/directory/status',
        'GET',
        undefined,
        2000
      );
      if (statusRes.kind === 'ok' && typeof statusRes.data.passwordPolicy?.minLength === 'number') {
        minLen = Math.max(8, statusRes.data.passwordPolicy.minLength);
      }
    } catch {}

    if (password.length < minLen) {
      return NextResponse.json(
        { status: 'error', error: `Password must be at least ${minLen} characters long` },
        { status: 400 }
      );
    }

    const network = await resolveHeadscaleNetworkInfo(req);

    const { invite, result } = await consumeHeadscaleInvite(
      token,
      async (inv) => {
        const usersRes = await callAgentApiDetailed<{
          users: Array<{ username: string; applianceRole: string }>;
        }>('/v1/system/users', 'GET');
        if (usersRes.kind !== 'ok') {
          const err = new Error('Appliance directory service unavailable');
          (err as any).statusCode = 503;
          throw err;
        }

        const existing = (usersRes.data.users || []).find((u) => u.username === inv.username);
        if (existing) {
          if (existing.applianceRole !== 'vpn_user') {
            const err = new Error(
              `Forbidden: Privileged account '${inv.username}' cannot be modified via VPN invite`
            );
            (err as any).statusCode = 403;
            throw err;
          }
          const updRes = await callAgentApiResponse<{ success?: boolean; message?: string; error?: string }>(
            `/v1/system/users/${encodeURIComponent(inv.username)}`,
            'PUT',
            { password, passwordLocked: false }
          );
          if (!updRes || !updRes.success) {
            throw new Error(updRes?.error || updRes?.message || 'Failed to update account password');
          }
          bumpUserSessionEpoch(inv.username);
        } else {
          if (inv.mode === 'reset') {
            const err = new Error(`Account '${inv.username}' no longer exists`);
            (err as any).statusCode = 404;
            throw err;
          }
          const createRes = await callAgentApiResponse<{ success?: boolean; message?: string; error?: string }>(
            '/v1/system/users',
            'POST',
            {
              username: inv.username,
              comment: inv.displayName || inv.username,
              password,
              shell: '/usr/sbin/nologin',
              applianceRole: 'vpn_user',
            }
          );
          if (!createRes || !createRes.success) {
            throw new Error(createRes?.error || createRes?.message || 'Failed to provision directory account');
          }
        }

        let starterKey: { id: string | number; key: string; expiration?: string } | null = null;
        let headscaleError: string | null = null;
        if (!network.enabled) {
          headscaleError = 'Mesh VPN (Headscale) is currently disabled by your administrator';
        } else if (!isHeadscaleSocketReady()) {
          headscaleError = 'Headscale service is not currently running on this appliance';
        } else {
          try {
            await ensureUser(inv.username);
            if (inv.createStarterKey) {
              const expIso = new Date(
                Date.now() + (network.defaultKeyExpiryHours || 24) * 3600 * 1000
              ).toISOString();
              const created = await createPreAuthKey(inv.username, false, false, expIso);
              starterKey = {
                id: created.id,
                key: created.key,
                expiration: created.expiration,
              };
            }
          } catch (hsErr: any) {
            const msg = hsErr?.message || 'Unable to provision Headscale starter key';
            const err = new Error(`Headscale provisioning failed: ${msg}`);
            (err as any).statusCode = 502;
            throw err;
          }
        }

        return { starterKey, headscaleError };
      },
      { pin }
    );

    await syncHeadscaleWanWindow();

    const roleDef = DEFAULT_ROLES.vpn_user;
    const session: UserSession = {
      userId: `local:${invite.username}`,
      username: invite.username,
      displayName: invite.displayName || invite.username,
      source: 'local',
      roles: ['vpn_user'],
      privileges: Array.from(roleDef.privileges),
      exp: Math.floor(Date.now() / 1000) + 8 * 3600,
    };
    stampSessionEpoch(session);
    const jwt = await mintSupabaseToken(session, getJwtSecret());

    const cookieStore = await cookies();
    cookieStore.set(SESSION_COOKIE, jwt, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production' && process.env.AXONWALL_INSECURE_HTTP !== '1',
      sameSite: 'lax',
      path: '/',
      maxAge: 8 * 3600,
    });

    const redirectTo = '/vpn';

    return NextResponse.json(
      {
        status: 'ok',
        redirectTo,
        portalUrl: network.portalUrl,
        username: invite.username,
        starterKey: result.starterKey,
        headscaleError: result.headscaleError,
        serverUrl: network.serverUrl,
        magicDnsDomain: network.magicDnsDomain,
        quickConnectCommand: buildQuickConnectCommand(network.serverUrl, result.starterKey?.key),
      },
      { headers: { 'Cache-Control': 'no-store' } }
    );
  } catch (err: any) {
    const code = err?.code;
    const status =
      typeof err?.statusCode === 'number'
        ? err.statusCode
        : code === 'CONFLICT'
          ? 409
          : code === 'ALREADY_USED' || code === 'EXPIRED' || code === 'REVOKED'
            ? 410
            : code === 'INVALID_TOKEN'
              ? 404
              : 400;
    return NextResponse.json(
      { status: 'error', error: err?.message || 'Invite activation failed' },
      { status }
    );
  }
}
