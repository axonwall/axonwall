import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { mintSupabaseToken, verifyToken } from '@axonwall/lib/ldap';
import { DEFAULT_ROLES, type UserSession } from '@axonwall/lib/rbac';
import {
  assertActionPermitted,
  assertMeshSelfServicePermitted,
  isConsoleUser,
  isVpnPortalOnlyUser,
} from '../auth-guard';
import {
  extractRegistrationToken,
  findOwnedMachine,
  findOwnedPreAuthKey,
  resolveHeadscaleUsername,
  type HeadscaleMachineRecord,
  type HeadscalePreAuthKeyRecord,
} from '../headscale';
import {
  MAX_PIN_ATTEMPTS,
  checkInviteRateLimit,
  consumeHeadscaleInvite,
  createHeadscaleInvite,
  getActivePendingInviteWindow,
  listHeadscaleInvites,
  previewHeadscaleInvite,
  resetInviteRateLimitForTests,
  revokeHeadscaleInvite,
  validateInviteUsername,
} from '../headscale-invites';
import { buildPortKnockCommands } from '../headscale-network';

describe('Headscale username normalization & registration token parsing', () => {
  it('preserves safe Linux usernames and hashes external/email identities deterministically', () => {
    expect(resolveHeadscaleUsername('alice')).toBe('alice');
    expect(resolveHeadscaleUsername({ username: 'Bob_Ops-1' })).toBe('bob_ops-1');

    const mappedA = resolveHeadscaleUsername({ username: 'alice@example.com' });
    const mappedB = resolveHeadscaleUsername({ username: 'oidc:alice@example.com' });
    const mappedC = resolveHeadscaleUsername({ username: 'alice@example.com' });

    expect(mappedA).toBe(mappedC);
    expect(mappedA).not.toBe(mappedB);
    expect(mappedA).toMatch(/^[a-z][a-z0-9-]*-[0-9a-f]{8}$/);
    expect(mappedA.length).toBeLessThanOrEqual(31);
  });

  it('extracts Headscale v0.29 auth IDs, legacy node keys, and pasted CLI commands safely', () => {
    expect(extractRegistrationToken('hskey-authreq-0123456789abcdef')).toEqual({
      kind: 'auth_id',
      token: 'hskey-authreq-0123456789abcdef',
    });

    expect(
      extractRegistrationToken(
        'headscale auth register --user alice --auth-id hskey-authreq-z9y8x7w6'
      )
    ).toEqual({
      kind: 'auth_id',
      token: 'hskey-authreq-z9y8x7w6',
    });

    expect(extractRegistrationToken('mkey:abcdef0123456789')).toEqual({
      kind: 'machine_key',
      token: 'mkey:abcdef0123456789',
    });

    expect(
      extractRegistrationToken(
        'headscale nodes register --user alice --key nodekey:998877665544'
      )
    ).toEqual({
      kind: 'machine_key',
      token: 'nodekey:998877665544',
    });

    expect(() => extractRegistrationToken('')).toThrow();
    expect(() => extractRegistrationToken('--user bob')).toThrow();
    expect(() => extractRegistrationToken('headscale auth register --auth-id bad;rm')).toThrow();
    expect(() => extractRegistrationToken('some arbitrary sentence without key')).toThrow();
  });
});

describe('Headscale invite store lifecycle & rate limiting', () => {
  let tmpDir: string;
  let invitesPath: string;
  const origInvitesPath = process.env.AXONWALL_HEADSCALE_INVITES_PATH;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axw-hs-invites-'));
    invitesPath = path.join(tmpDir, 'headscale-invites.json');
    process.env.AXONWALL_HEADSCALE_INVITES_PATH = invitesPath;
  });

  afterEach(() => {
    if (fs.existsSync(invitesPath)) fs.unlinkSync(invitesPath);
    resetInviteRateLimitForTests();
  });

  afterAll(() => {
    if (origInvitesPath === undefined) delete process.env.AXONWALL_HEADSCALE_INVITES_PATH;
    else process.env.AXONWALL_HEADSCALE_INVITES_PATH = origInvitesPath;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('never writes plaintext invite tokens to disk and supports single-use redemption', async () => {
    const { invite, rawToken } = await createHeadscaleInvite({
      username: 'alice',
      displayName: 'Alice Smith',
      mode: 'onboard',
      createStarterKey: true,
      expiryHours: 24,
      createdBy: 'admin',
    });

    const onDiskRaw = fs.readFileSync(invitesPath, 'utf8');
    expect(onDiskRaw).not.toContain(rawToken);
    expect(onDiskRaw).toContain('tokenHash');

    const preview = previewHeadscaleInvite(rawToken);
    expect(preview.status).toBe('valid');
    expect(preview.invite?.id).toBe(invite.id);
    expect(preview.invite?.username).toBe('alice');

    // Failed provisioning must NOT consume the invite
    await expect(
      consumeHeadscaleInvite(rawToken, async () => {
        throw new Error('Password too weak');
      })
    ).rejects.toThrow('Password too weak');

    expect(previewHeadscaleInvite(rawToken).status).toBe('valid');

    // Successful redemption marks it used and prevents replay
    const redeemed = await consumeHeadscaleInvite(rawToken, async (inv) => ({
      provisionedFor: inv.username,
    }));
    expect(redeemed.result.provisionedFor).toBe('alice');
    expect(redeemed.invite.status).toBe('redeemed');
    expect(previewHeadscaleInvite(rawToken).status).toBe('used');

    await expect(consumeHeadscaleInvite(rawToken, async () => 'replay')).rejects.toThrow(
      /already been used/i
    );
  });

  it('prevents concurrent double-redemption and enforces revocation/expiry/validation', async () => {
    expect(() => validateInviteUsername('root')).toThrow();
    expect(() => validateInviteUsername('admin')).toThrow();
    expect(() => validateInviteUsername('1bad')).toThrow();

    const { rawToken } = await createHeadscaleInvite({
      username: 'bob',
      createdBy: 'admin',
    });

    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });

    const p1 = consumeHeadscaleInvite(rawToken, async () => {
      await firstGate;
      return 'first';
    });

    const p2 = consumeHeadscaleInvite(rawToken, async () => 'second');
    await expect(p2).rejects.toThrow(/already in progress/i);

    releaseFirst();
    await expect(p1).resolves.toMatchObject({ result: 'first' });

    const { invite: i2, rawToken: tok2 } = await createHeadscaleInvite({
      username: 'carol',
      createdBy: 'admin',
    });
    revokeHeadscaleInvite(i2.id);
    expect(previewHeadscaleInvite(tok2).status).toBe('revoked');
    await expect(consumeHeadscaleInvite(tok2, async () => 'fail')).rejects.toThrow(/revoked/i);

    // Expired timestamp simulation directly in store file
    const { invite: i3, rawToken: tok3 } = await createHeadscaleInvite({
      username: 'dave',
      createdBy: 'admin',
    });
    const stored = JSON.parse(fs.readFileSync(invitesPath, 'utf8'));
    const rec = stored.find((x: any) => x.id === i3.id);
    rec.expiresAt = new Date(Date.now() - 60_000).toISOString();
    fs.writeFileSync(invitesPath, JSON.stringify(stored));

    expect(previewHeadscaleInvite(tok3).status).toBe('expired');
    await expect(consumeHeadscaleInvite(tok3, async () => 'fail')).rejects.toThrow(/expired/i);

    expect(listHeadscaleInvites().some((x) => x.username === 'dave' && x.effectiveStatus === 'expired')).toBe(
      true
    );
  });

  it('rate-limits repeated invite lookups/redemptions per IP', () => {
    for (let i = 0; i < 20; i++) {
      expect(checkInviteRateLimit('203.0.113.5')).toBe(true);
    }
    expect(checkInviteRateLimit('203.0.113.5')).toBe(false);
    expect(checkInviteRateLimit('203.0.113.6')).toBe(true);
  });

  it('enforces hashed out-of-band 6-digit PINs, auto-revokes after 5 wrong attempts, and computes active window', async () => {
    const { invite: pinInv, rawToken: pinTok, invitePin } = await createHeadscaleInvite({
      username: 'eve',
      requirePin: true,
      expiryHours: 12,
      createdBy: 'admin',
    });
    expect(invitePin).toMatch(/^\d{6}$/);
    expect(pinInv.requiresPin).toBe(true);

    const diskRaw = fs.readFileSync(invitesPath, 'utf8');
    expect(diskRaw).not.toContain(invitePin!);
    expect(diskRaw).toContain('pinHash');

    const preview = previewHeadscaleInvite(pinTok);
    expect(preview.status).toBe('valid');
    expect(preview.invite?.requiresPin).toBe(true);
    expect((preview.invite as any)?.pinHash).toBeUndefined();
    expect((preview.invite as any)?.pinSalt).toBeUndefined();

    // Missing or invalid PIN rejects cleanly without consuming invite on first 4 failures
    await expect(
      consumeHeadscaleInvite(pinTok, async () => 'should-not-run', { pin: '000000' === invitePin ? '111111' : '000000' })
    ).rejects.toMatchObject({ code: 'INVALID_PIN', statusCode: 403 });
    expect(previewHeadscaleInvite(pinTok).status).toBe('valid');

    // Correct PIN succeeds before lockout
    const ok = await consumeHeadscaleInvite(pinTok, async () => 'ok', { pin: invitePin });
    expect(ok.result).toBe('ok');
    expect(previewHeadscaleInvite(pinTok).status).toBe('used');

    // Lockout after MAX_PIN_ATTEMPTS failed attempts
    const { rawToken: lockTok, invitePin: lockPin } = await createHeadscaleInvite({
      username: 'frank',
      requirePin: true,
      expiryHours: 24,
      createdBy: 'admin',
    });
    const badPin = lockPin === '123456' ? '654321' : '123456';
    for (let i = 1; i < MAX_PIN_ATTEMPTS; i++) {
      await expect(
        consumeHeadscaleInvite(lockTok, async () => 'nope', { pin: badPin })
      ).rejects.toMatchObject({ code: 'INVALID_PIN' });
      expect(previewHeadscaleInvite(lockTok).status).toBe('valid');
    }
    await expect(
      consumeHeadscaleInvite(lockTok, async () => 'nope', { pin: badPin })
    ).rejects.toMatchObject({ code: 'REVOKED', statusCode: 410 });
    expect(previewHeadscaleInvite(lockTok).status).toBe('revoked');

    // Window calculation across pending + expired + revoked
    expect(getActivePendingInviteWindow().pendingCount).toBe(0);
    await createHeadscaleInvite({ username: 'grace', expiryHours: 4, createdBy: 'admin' });
    const { invite: hInv } = await createHeadscaleInvite({ username: 'heidi', expiryHours: 48, createdBy: 'admin' });
    const win = getActivePendingInviteWindow();
    expect(win.pendingCount).toBe(2);
    expect(win.latestExpiresAt).toBe(new Date(Date.parse(hInv.expiresAt)).toISOString());
    revokeHeadscaleInvite(hInv.id);
    expect(getActivePendingInviteWindow().pendingCount).toBe(1);
  });

  it('formats sanitized UDP and TCP port-knock helper commands', () => {
    const udp = buildPortKnockCommands('https://join.example.com:8443/invite', 'udp', [41821, 52913, 38477]);
    expect(udp.unix).toContain('nc -u -w 1 join.example.com');
    expect(udp.unix).toContain('41821 52913 38477');
    expect(udp.powershell).toContain('UdpClient');
    expect(udp.powershell).toContain('join.example.com');

    const tcp = buildPortKnockCommands('join.example.com', 'tcp', [20111, 30222]);
    expect(tcp.unix).toContain('nc -z -w 1 join.example.com');
    expect(tcp.unix).toContain('20111 30222');
    expect(tcp.powershell).toContain('TcpClient');
  });
});

describe('Least-privilege RBAC isolation, ownership checks & per-user session revocation', () => {
  let revDir: string;
  const origState = process.env.AXONWALL_STATE_DIR;
  const origEtc = process.env.AXONWALL_ETC_DIR;

  beforeAll(() => {
    revDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axw-rev-'));
    process.env.AXONWALL_STATE_DIR = revDir;
    process.env.AXONWALL_ETC_DIR = revDir;
  });

  afterAll(() => {
    if (origState === undefined) delete process.env.AXONWALL_STATE_DIR;
    else process.env.AXONWALL_STATE_DIR = origState;
    if (origEtc === undefined) delete process.env.AXONWALL_ETC_DIR;
    else process.env.AXONWALL_ETC_DIR = origEtc;
    fs.rmSync(revDir, { recursive: true, force: true });
  });

  it('isolates vpn_user away from console actions while permitting Mesh self-service', () => {
    const vpnSession: UserSession = {
      userId: 'local:alice',
      username: 'alice',
      source: 'local',
      roles: ['vpn_user'],
      privileges: [...DEFAULT_ROLES.vpn_user.privileges],
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
    const readonlySession: UserSession = {
      userId: 'local:auditor',
      username: 'auditor',
      source: 'local',
      roles: ['readonly'],
      privileges: [...DEFAULT_ROLES.readonly.privileges],
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    expect(isConsoleUser(vpnSession)).toBe(false);
    expect(isVpnPortalOnlyUser(vpnSession)).toBe(true);
    expect(isConsoleUser(readonlySession)).toBe(true);
    expect(isVpnPortalOnlyUser(readonlySession)).toBe(false);

    expect(() => assertActionPermitted(vpnSession)).toThrow(/Forbidden/i);
    expect(() => assertActionPermitted(vpnSession, 'readonly')).toThrow(/Forbidden/i);
    expect(() => assertActionPermitted(vpnSession, 'admin')).toThrow(/Forbidden/i);
    expect(() => assertMeshSelfServicePermitted(vpnSession)).not.toThrow();

    expect(() => assertActionPermitted(readonlySession)).not.toThrow();
    expect(() => assertMeshSelfServicePermitted(readonlySession)).not.toThrow();
    expect(() => assertMeshSelfServicePermitted(null)).toThrow(/Unauthorized/);
  });

  it('enforces per-user IDOR isolation on Headscale machines and pre-auth keys', () => {
    const machines: HeadscaleMachineRecord[] = [
      {
        id: 10,
        name: 'alice-laptop',
        ipAddresses: ['100.64.0.10'],
        user: { id: 1, name: 'alice' },
        lastSeen: null,
        online: true,
        routes: [],
        approvedRoutes: [],
        availableRoutes: [],
        expiry: null,
        createdAt: null,
      },
      {
        id: 20,
        name: 'bob-phone',
        ipAddresses: ['100.64.0.20'],
        user: { id: 2, name: 'bob' },
        lastSeen: null,
        online: true,
        routes: [],
        approvedRoutes: [],
        availableRoutes: [],
        expiry: null,
        createdAt: null,
      },
    ];

    const keys: HeadscalePreAuthKeyRecord[] = [
      {
        id: 101,
        key: 'hskey-alice-1',
        keyPreview: 'hskey-al•••ce-1',
        reusable: false,
        ephemeral: false,
        used: false,
        expired: false,
        user: { id: 1, name: 'alice' },
      },
      {
        id: 202,
        key: 'hskey-bob-2',
        keyPreview: 'hskey-bo•••ob-2',
        reusable: false,
        ephemeral: false,
        used: false,
        expired: false,
        user: { id: 2, name: 'bob' },
      },
    ];

    expect(findOwnedMachine(machines, 'alice', 10).name).toBe('alice-laptop');
    expect(() => findOwnedMachine(machines, 'alice', 20)).toThrow(/Machine not found/);
    expect(() => findOwnedMachine(machines, 'alice', 999)).toThrow(/Machine not found/);

    expect(findOwnedPreAuthKey(keys, 'alice', 101).key).toBe('hskey-alice-1');
    expect(() => findOwnedPreAuthKey(keys, 'alice', 202)).toThrow(/Pre-auth key not found/);
    expect(() => findOwnedPreAuthKey(keys, 'alice', 'hskey-bob-2')).toThrow(/Pre-auth key not found/);
  });

  it('revokes only the target user sessions when bumping per-user session epoch', async () => {
    vi.resetModules();
    const rev = await import('../session-revocation');
    const secret = 'test-jwt-secret-must-be-long-enough-123456';

    const aliceSess: UserSession = {
      userId: 'local:alice',
      username: 'alice',
      source: 'local',
      roles: ['vpn_user'],
      privileges: ['vpn.mesh.self'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
    const bobSess: UserSession = {
      userId: 'local:bob',
      username: 'bob',
      source: 'local',
      roles: ['vpn_user'],
      privileges: ['vpn.mesh.self'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    rev.stampSessionEpoch(aliceSess);
    rev.stampSessionEpoch(bobSess);

    const aliceJwt = await mintSupabaseToken(aliceSess, secret);
    const bobJwt = await mintSupabaseToken(bobSess, secret);

    const aliceDecoded = await verifyToken(aliceJwt, secret);
    const bobDecoded = await verifyToken(bobJwt, secret);
    expect(aliceDecoded).not.toBeNull();
    expect(bobDecoded).not.toBeNull();
    expect(rev.isSessionRevoked(aliceDecoded!)).toBe(false);
    expect(rev.isSessionRevoked(bobDecoded!)).toBe(false);

    // Bump only alice
    rev.bumpUserSessionEpoch('alice');
    expect(rev.isSessionRevoked(aliceDecoded!)).toBe(true);
    expect(rev.isSessionRevoked(bobDecoded!)).toBe(false);

    // Fresh token minted after bump stays valid for alice
    const aliceFresh: UserSession = { ...aliceSess };
    rev.stampSessionEpoch(aliceFresh);
    const aliceFreshDecoded = await verifyToken(await mintSupabaseToken(aliceFresh, secret), secret);
    expect(rev.isSessionRevoked(aliceFreshDecoded!)).toBe(false);
  });
});
