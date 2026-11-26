import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { callAgentApiDetailed, callAgentApiResponse } from '@/server/agent-client';
import {
  listUsers,
  ensureUser,
  deleteUser,
  listMachines,
  deleteMachine,
  listPreAuthKeys,
  createPreAuthKey,
  isHeadscaleSocketReady,
} from '@/server/headscale';
import {
  createHeadscaleInvite,
  listHeadscaleInvites,
  revokeHeadscaleInvite,
  syncHeadscaleWanWindow,
  validateInviteUsername,
} from '@/server/headscale-invites';
import {
  buildPortKnockCommands,
  buildQuickConnectCommand,
  generateTemporaryPassword,
  resolveHeadscaleNetworkInfo,
} from '@/server/headscale-network';
import { bumpUserSessionEpoch } from '@/server/session-revocation';

export const dynamic = 'force-dynamic';

interface DirectoryUserSummary {
  username: string;
  comment: string;
  applianceRole: string;
  isSystem: boolean;
  protected: boolean;
  passwordLocked: boolean;
}

async function fetchDirectoryUsers(): Promise<{
  available: boolean;
  users: DirectoryUserSummary[];
  minLength: number;
}> {
  const [usersRes, statusRes] = await Promise.all([
    callAgentApiDetailed<{ users: DirectoryUserSummary[] }>('/v1/system/users', 'GET'),
    callAgentApiDetailed<{ passwordPolicy?: { minLength?: number } }>('/v1/system/directory/status', 'GET'),
  ]);
  const users =
    usersRes.kind === 'ok' && Array.isArray(usersRes.data.users)
      ? usersRes.data.users.filter((u) => !u.isSystem && u.username !== 'root')
      : [];
  const minLength =
    statusRes.kind === 'ok' && typeof statusRes.data.passwordPolicy?.minLength === 'number'
      ? Math.max(8, statusRes.data.passwordPolicy.minLength)
      : 12;
  return {
    available: usersRes.kind === 'ok',
    users,
    minLength,
  };
}

export async function GET(req: NextRequest) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');

    const [network, directory, invites] = await Promise.all([
      resolveHeadscaleNetworkInfo(req),
      fetchDirectoryUsers(),
      Promise.resolve(listHeadscaleInvites()),
    ]);

    let headscaleAvailable = isHeadscaleSocketReady();
    let headscaleError: string | null = null;
    let headscaleUsers: Array<{
      id: string | number;
      name: string;
      createdAt?: string;
      machineCount: number;
      onlineCount: number;
      activeKeyCount: number;
      applianceRole: string | null;
      displayName: string;
      hasDirectoryAccount: boolean;
    }> = [];

    if (headscaleAvailable) {
      try {
        const [hsUsers, machines, keys] = await Promise.all([
          listUsers(),
          listMachines(),
          listPreAuthKeys(),
        ]);
        const dirMap = new Map(directory.users.map((u) => [u.username.toLowerCase(), u]));
        headscaleUsers = hsUsers.map((u) => {
          const ownedMachines = machines.filter((m) => m.user?.name === u.name);
          const ownedKeys = keys.filter(
            (k) => k.user?.name === u.name && !k.expired && (k.reusable || !k.used)
          );
          const dir = dirMap.get(u.name.toLowerCase());
          return {
            id: u.id,
            name: u.name,
            createdAt: u.createdAt,
            machineCount: ownedMachines.length,
            onlineCount: ownedMachines.filter((m) => m.online).length,
            activeKeyCount: ownedKeys.length,
            applianceRole: dir?.applianceRole ?? null,
            displayName: dir?.comment || u.name,
            hasDirectoryAccount: Boolean(dir),
          };
        });
      } catch (err: any) {
        headscaleAvailable = false;
        headscaleError = err?.message || 'Unable to query Headscale daemon';
      }
    } else {
      headscaleError = 'Headscale service is not running';
    }

    const hsNames = new Set(headscaleUsers.map((u) => u.name.toLowerCase()));
    const eligibleExistingUsers = directory.users.filter(
      (u) => !hsNames.has(u.username.toLowerCase())
    );

    return NextResponse.json({
      status: 'ok',
      data: {
        headscaleAvailable,
        headscaleError,
        headscaleUsers,
        directoryUsers: directory.users,
        eligibleExistingUsers,
        directoryAvailable: directory.available,
        passwordPolicy: { minLength: directory.minLength },
        invites,
        network,
      },
    });
  } catch (err: any) {
    return NextResponse.json(
      { status: 'error', error: err?.message || 'Failed to load Mesh VPN people directory' },
      { status: 500 }
    );
  }
}

export async function POST(req: NextRequest) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');

    const body = await req.json().catch(() => ({}));
    const action = body?.action;
    const network = await resolveHeadscaleNetworkInfo(req);

    if (action === 'invite') {
      const username = validateInviteUsername(body?.username);
      const mode = body?.mode === 'reset' ? 'reset' : 'onboard';
      const displayName =
        typeof body?.displayName === 'string' ? body.displayName.trim() : username;
      const createStarterKey = body?.createStarterKey !== false;
      const expiryHours = body?.expiryHours ? Number(body.expiryHours) : 48;
      const requirePin =
        typeof body?.requirePin === 'boolean' ? body.requirePin : network.wanInvite.requirePin;

      const directory = await fetchDirectoryUsers();
      const existingDir = directory.users.find((u) => u.username === username);
      if (mode === 'reset') {
        if (!directory.available) {
          return NextResponse.json(
            { status: 'error', error: 'Daemon unavailable: cannot verify user before issuing reset invite' },
            { status: 503 }
          );
        }
        if (!existingDir) {
          return NextResponse.json(
            { status: 'error', error: `User '${username}' does not exist in directory` },
            { status: 404 }
          );
        }
        if (existingDir.applianceRole !== 'vpn_user') {
          return NextResponse.json(
            {
              status: 'error',
              error: `Cannot issue self-service password reset invite for privileged role '${existingDir.applianceRole}'`,
            },
            { status: 403 }
          );
        }
      } else if (existingDir) {
        if (existingDir.applianceRole === 'vpn_user') {
          return NextResponse.json(
            {
              status: 'error',
              error: `User '${username}' already exists as a VPN Member. Issue a password reset invite or generate an auth key instead.`,
            },
            { status: 409 }
          );
        }
        return NextResponse.json(
          {
            status: 'error',
            error: `User '${username}' already exists in directory (role: ${existingDir.applianceRole}). Enable Mesh VPN on that existing account instead.`,
          },
          { status: 409 }
        );
      }

      const { invite, rawToken, invitePin } = await createHeadscaleInvite({
        username,
        displayName,
        mode,
        createStarterKey,
        requirePin,
        expiryHours,
        createdBy: session.username,
      });

      await syncHeadscaleWanWindow();

      let headscaleProvisioned = false;
      let headscaleWarning: string | undefined;
      if (isHeadscaleSocketReady()) {
        try {
          await ensureUser(username);
          headscaleProvisioned = true;
        } catch (err: any) {
          headscaleWarning = err?.message || 'Headscale namespace could not be pre-created';
        }
      } else {
        headscaleWarning = 'Headscale service is not running yet; namespace will be created when Headscale starts or on first login.';
      }

      const inviteBaseUrl =
        network.wanInvite.enabled && network.wanInvite.baseUrl
          ? network.wanInvite.baseUrl
          : network.portalUrl;
      const inviteUrl = `${inviteBaseUrl}/invite/${rawToken}`;
      const knockCommands =
        network.wanInvite.enabled &&
        network.wanInvite.portKnocking.enabled &&
        network.wanInvite.hostname
          ? buildPortKnockCommands(
              network.wanInvite.hostname,
              network.wanInvite.portKnocking.protocol,
              network.wanInvite.portKnocking.sequence
            )
          : undefined;

      const welcomeLines = [
        `You have been invited to the Axonwall Mesh VPN (${network.magicDnsDomain}).`,
      ];
      let stepNum = 1;
      if (knockCommands) {
        welcomeLines.push(
          `${stepNum++}. Knock the sequence (${network.wanInvite.portKnocking.protocol.toUpperCase()} ports ${network.wanInvite.portKnocking.sequence.join(', ')}) from your terminal first:`,
          knockCommands.unix
        );
      }
      welcomeLines.push(
        `${stepNum++}. Open your activation link (expires ${new Date(invite.expiresAt).toLocaleString()}):`,
        inviteUrl
      );
      if (invitePin) {
        welcomeLines.push(
          `${stepNum++}. Enter the 6-digit verification PIN sent by your administrator over a separate channel and choose a password for username '${username}'.`
        );
      } else {
        welcomeLines.push(`${stepNum++}. Choose a password for username '${username}'.`);
      }
      welcomeLines.push(
        `${stepNum++}. Follow the Tailscale setup command or scan the QR code shown right on the activation page to connect. Once connected, you can visit ${network.portalUrl}/vpn.`
      );
      const welcomeMessage = welcomeLines.join('\n');

      return NextResponse.json({
        status: 'ok',
        data: {
          invite,
          inviteUrl,
          ...(invitePin ? { invitePin } : {}),
          ...(knockCommands ? { knockCommands } : {}),
          headscaleProvisioned,
          headscaleWarning,
          welcomeMessage,
        },
      });
    }

    if (action === 'create_direct') {
      const username = validateInviteUsername(body?.username);
      const displayName =
        typeof body?.displayName === 'string' && body.displayName.trim()
          ? body.displayName.trim()
          : username;
      if (/[\r\n\x00]/.test(displayName)) {
        return NextResponse.json(
          { status: 'error', error: 'Display name contains invalid control characters' },
          { status: 400 }
        );
      }

      const directory = await fetchDirectoryUsers();
      if (!directory.available) {
        return NextResponse.json(
          { status: 'error', error: 'Daemon unavailable: cannot create directory user' },
          { status: 503 }
        );
      }
      if (directory.users.some((u) => u.username === username)) {
        return NextResponse.json(
          { status: 'error', error: `User '${username}' already exists in directory` },
          { status: 409 }
        );
      }

      const generatePass = body?.generatePassword !== false && !body?.password;
      const password = generatePass
        ? generateTemporaryPassword(Math.max(16, directory.minLength))
        : String(body?.password || '');

      if (!password || password.length < directory.minLength) {
        return NextResponse.json(
          { status: 'error', error: `Password must be at least ${directory.minLength} characters` },
          { status: 400 }
        );
      }
      if (/[\r\n\x00]/.test(password)) {
        return NextResponse.json(
          { status: 'error', error: 'Password contains invalid control characters' },
          { status: 400 }
        );
      }

      const createRes = await callAgentApiResponse<{ success?: boolean; message?: string; error?: string }>(
        '/v1/system/users',
        'POST',
        {
          username,
          comment: displayName,
          password,
          shell: '/usr/sbin/nologin',
          applianceRole: 'vpn_user',
        }
      );
      if (!createRes || !createRes.success) {
        return NextResponse.json(
          {
            status: 'error',
            error: createRes?.error || createRes?.message || 'Failed to create directory user',
          },
          { status: 400 }
        );
      }

      let headscaleProvisioned = false;
      let headscaleWarning: string | undefined;
      let starterKey: { id: string | number; key: string; expiration?: string } | null = null;
      const wantStarterKey = body?.createStarterKey !== false;

      if (isHeadscaleSocketReady()) {
        try {
          await ensureUser(username);
          headscaleProvisioned = true;
          if (wantStarterKey) {
            const ttlHours = Math.min(720, Math.max(1, Number(body?.keyExpiryHours) || network.defaultKeyExpiryHours || 24));
            const keyRes = await createPreAuthKey(
              username,
              false,
              false,
              new Date(Date.now() + ttlHours * 3600 * 1000).toISOString()
            );
            starterKey = {
              id: keyRes.id,
              key: keyRes.key,
              expiration: keyRes.expiration,
            };
          }
        } catch (err: any) {
          headscaleWarning = err?.message || 'Failed to provision Headscale namespace/key';
        }
      } else {
        headscaleWarning = 'Headscale service is not running yet; namespace will be initialized on first portal visit.';
      }

      const portalSignInUrl = `${network.portalUrl}/login?username=${encodeURIComponent(username)}`;
      const quickConnectCommand = buildQuickConnectCommand(network.serverUrl, starterKey?.key);
      const welcomeLines = [
        `Axonwall Mesh VPN Account Ready (${network.magicDnsDomain})`,
        `Self-Service Portal: ${portalSignInUrl}`,
        `Username: ${username}`,
        `Temporary Password: ${password}`,
        '',
        'Quick Connect Command:',
        quickConnectCommand,
      ];

      return NextResponse.json({
        status: 'ok',
        data: {
          username,
          displayName,
          password,
          portalUrl: `${network.portalUrl}/vpn`,
          portalSignInUrl,
          serverUrl: network.serverUrl,
          magicDnsDomain: network.magicDnsDomain,
          starterKey,
          quickConnectCommand,
          headscaleProvisioned,
          headscaleWarning,
          welcomeMessage: welcomeLines.join('\n'),
        },
      });
    }

    if (action === 'enable_existing') {
      const username = validateInviteUsername(body?.username);
      const grantPortalRole = body?.grantPortalRole !== false;
      const directory = await fetchDirectoryUsers();
      if (!directory.available) {
        return NextResponse.json(
          { status: 'error', error: 'Daemon unavailable: cannot inspect directory users' },
          { status: 503 }
        );
      }
      const existing = directory.users.find((u) => u.username === username);
      if (!existing) {
        return NextResponse.json(
          { status: 'error', error: `Directory user '${username}' not found` },
          { status: 404 }
        );
      }
      if (grantPortalRole && existing.applianceRole === 'os_only') {
        const updateRes = await callAgentApiResponse<{ success?: boolean; message?: string; error?: string }>(
          `/v1/system/users/${encodeURIComponent(username)}`,
          'PUT',
          { applianceRole: 'vpn_user', shell: '/usr/sbin/nologin' }
        );
        if (!updateRes || !updateRes.success) {
          return NextResponse.json(
            { status: 'error', error: updateRes?.error || updateRes?.message || 'Failed to update user role' },
            { status: 400 }
          );
        }
      }

      let headscaleProvisioned = false;
      if (isHeadscaleSocketReady()) {
        await ensureUser(username);
        headscaleProvisioned = true;
      }

      return NextResponse.json({
        status: 'ok',
        data: {
          username,
          headscaleProvisioned,
          portalUrl: `${network.portalUrl}/vpn`,
        },
      });
    }

    if (action === 'revoke_invite') {
      const inviteId = typeof body?.inviteId === 'string' ? body.inviteId.trim() : '';
      if (!inviteId) {
        return NextResponse.json({ status: 'error', error: 'inviteId is required' }, { status: 400 });
      }
      const invite = revokeHeadscaleInvite(inviteId);
      await syncHeadscaleWanWindow();
      return NextResponse.json({ status: 'ok', data: invite });
    }

    if (action === 'remove_person') {
      const username = validateInviteUsername(body?.username);
      const removeMachines = Boolean(body?.deleteMachines);
      const removeDirectoryUser = Boolean(body?.deleteDirectoryUser);

      if (isHeadscaleSocketReady()) {
        const hsUsers = await listUsers();
        const hsUser = hsUsers.find((u) => u.name === username);
        if (hsUser) {
          const ownedMachines = await listMachines(username);
          if (ownedMachines.length > 0 && !removeMachines) {
            return NextResponse.json(
              {
                status: 'error',
                error: `User '${username}' still owns ${ownedMachines.length} device(s). Confirm deleting their devices or remove devices first.`,
              },
              { status: 409 }
            );
          }
          for (const m of ownedMachines) {
            await deleteMachine(m.id);
          }
          await deleteUser(hsUser.name);
        }
      }

      if (removeDirectoryUser) {
        const directory = await fetchDirectoryUsers();
        if (!directory.available) {
          return NextResponse.json(
            { status: 'error', error: 'Daemon unavailable: cannot delete directory account' },
            { status: 503 }
          );
        }
        const target = directory.users.find((u) => u.username === username);
        if (target) {
          if (target.applianceRole !== 'vpn_user') {
            return NextResponse.json(
              {
                status: 'error',
                error: `Refusing to delete non-VPN directory user '${username}' (role: ${target.applianceRole}) from Mesh VPN panel; manage privileged accounts in System Users.`,
              },
              { status: 403 }
            );
          }
          const delRes = await callAgentApiResponse<{ success?: boolean; message?: string; error?: string }>(
            `/v1/system/users/${encodeURIComponent(username)}?removeHome=false`,
            'DELETE'
          );
          if (!delRes || !delRes.success) {
            return NextResponse.json(
              { status: 'error', error: delRes?.error || delRes?.message || 'Failed to delete directory user' },
              { status: 400 }
            );
          }
        }
      }

      bumpUserSessionEpoch(username);
      return NextResponse.json({ status: 'ok' });
    }

    return NextResponse.json(
      {
        status: 'error',
        error: `Invalid action '${action}': expected invite, create_direct, enable_existing, revoke_invite, or remove_person`,
      },
      { status: 400 }
    );
  } catch (err: any) {
    const msg = err?.message || 'Mesh VPN people operation failed';
    const status =
      msg === 'Unauthorized'
        ? 401
        : msg.startsWith('Forbidden')
          ? 403
          : err?.code === 'NOT_FOUND'
            ? 404
            : 400;
    return NextResponse.json(
      { status: 'error', error: msg },
      { status }
    );
  }
}
