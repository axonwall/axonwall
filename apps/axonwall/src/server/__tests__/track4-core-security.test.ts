import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { DesiredStateSchema } from '@axonwall/lib/schemas';
import type { UserSession } from '@axonwall/lib/rbac';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-track4-core-'));
const etcDir = path.join(root, 'etc');
const stateDir = path.join(root, 'var');
const persistDir = path.join(stateDir, 'etc-axonwall');
for (const dir of [etcDir, stateDir, persistDir]) {
  fs.mkdirSync(dir, { recursive: true });
}
process.env.AXONWALL_ETC_DIR = etcDir;
process.env.AXONWALL_STATE_DIR = stateDir;
process.env.AXONWALL_PERSIST_YAML_DIR = persistDir;
process.env.AXONWALL_STATE_JSON_PATH = path.join(stateDir, 'state.json');
process.env.FORCE_PASSWORD_CHANGE = 'false';

const hoisted = vi.hoisted(() => ({
  root: '',
  etcDir: '',
  stateDir: '',
  persistDir: '',
}));
hoisted.root = root;
hoisted.etcDir = etcDir;
hoisted.stateDir = stateDir;
hoisted.persistDir = persistDir;

vi.mock('../agent-client', () => ({
  clearCachedAgentToken: vi.fn(),
  getAgentToken: vi.fn(() => 'test-agent-token'),
  isApplianceRuntime: vi.fn(() => false),
  callAgentApi: vi.fn(async () => null),
  callAgentApiResponse: vi.fn(async () => ({ success: false })),
  callAgentApiDetailed: vi.fn(async () => ({ kind: 'unreachable' })),
}));

import {
  assertActionPermitted,
  assertInteractiveSession,
  assertMeshSelfServicePermitted,
  isConsoleUser,
} from '../auth-guard';
import { performAuthentication } from '../auth-internal';
import { queryDataLakeMetrics } from '../clickhouse';
import {
  invalidateDesiredStateCacheInternal,
  persistDesiredStateToDisk,
} from '../desired-state-internal';
import {
  consumeHeadscaleInvite,
  createHeadscaleInvite,
  listHeadscaleInvites,
} from '../headscale-invites';
import { resolveClientIp } from '../headscale-network';
import { resolvePublicOrigin, roleFromGroups } from '../oidc';
import {
  createServiceToken,
  revokeServiceToken,
  verifyServiceToken,
} from '../service-tokens';
import {
  currentSessionEpoch,
  currentUserSessionEpoch,
  isSessionRevoked,
  revokeTokenJti,
} from '../session-revocation';
import { assertSafeOutboundUrl } from '../ssrf-guard';

afterAll(() => {
  try {
    fs.chmodSync(hoisted.persistDir, 0o755);
  } catch {}
  try {
    fs.chmodSync(hoisted.etcDir, 0o755);
  } catch {}
  fs.rmSync(hoisted.root, { recursive: true, force: true });
});

describe('Track 4 Core Security & Reliability Fixes', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    invalidateDesiredStateCacheInternal();
  });

  describe('service-tokens & auth-guard', () => {
    it('rejects unknown roles, defaults omitted role to readonly, and reconciles revocations across mirrors', () => {
      expect(() =>
        createServiceToken({
          name: 'bad-role',
          role: 'superadmin' as any,
          scopes: ['observability:read'],
        })
      ).toThrow(/Invalid service token role/);

      expect(() =>
        createServiceToken({
          name: 'empty-scopes',
          scopes: ['  ', ''],
        })
      ).toThrow(/At least one non-empty scope/);

      const created = createServiceToken({
        name: 'default-role-token',
        scopes: ['observability:ingest'],
      });
      expect(created.record.role).toBe('readonly');
      expect(verifyServiceToken(created.plaintextToken)?.role).toBe('readonly');

      // Mirror reconciliation: revoke ONLY in the etc mirror and confirm verifyServiceToken treats it as revoked.
      const created2 = createServiceToken({
        name: 'mirror-revoked-token',
        role: 'operator',
        scopes: ['observability:read'],
      });
      const etcPath = path.join(hoisted.etcDir, 'service-tokens.json');
      const etcRecords = JSON.parse(fs.readFileSync(etcPath, 'utf8')) as Array<Record<string, unknown>>;
      const recIdx = etcRecords.findIndex((r) => r.id === created2.record.id);
      expect(recIdx).toBeGreaterThanOrEqual(0);
      etcRecords[recIdx]!.revokedAt = new Date().toISOString();
      fs.writeFileSync(etcPath, JSON.stringify(etcRecords, null, 2), 'utf8');

      expect(verifyServiceToken(created2.plaintextToken)).toBeNull();
      expect(revokeServiceToken(created.record.id)).toBe(true);
      expect(verifyServiceToken(created.plaintextToken)).toBeNull();
    });

    it('fails closed when primary service token store cannot be written', () => {
      fs.chmodSync(hoisted.persistDir, 0o500);
      try {
        expect(() =>
          createServiceToken({
            name: 'fail-closed-primary-dir',
            role: 'readonly',
            scopes: ['observability:read'],
          })
        ).toThrow(/EACCES|primary service token store/);
      } finally {
        fs.chmodSync(hoisted.persistDir, 0o755);
      }

      // Even when the secondary mirror (etcDir) is writable, a failure writing primary store fails closed.
      const blockerPrimary = path.join(hoisted.root, 'primary-eisdir');
      fs.mkdirSync(path.join(blockerPrimary, 'service-tokens.json'), { recursive: true });
      const prevPersist = process.env.AXONWALL_PERSIST_YAML_DIR;
      process.env.AXONWALL_PERSIST_YAML_DIR = blockerPrimary;
      try {
        expect(() =>
          createServiceToken({
            name: 'fail-closed-primary-eisdir',
            role: 'readonly',
            scopes: ['observability:read'],
          })
        ).toThrow(/EISDIR|illegal operation/i);
      } finally {
        process.env.AXONWALL_PERSIST_YAML_DIR = prevPersist;
      }
    });

    it('enforces scoped service-token checks and blocks service tokens from interactive and self-mesh paths', () => {
      const scopedSvc: UserSession = {
        userId: 'svc:metrics',
        username: 'svc:metrics',
        source: 'service_token',
        roles: ['admin'],
        privileges: [],
        scopes: ['observability:read'],
        exp: Math.floor(Date.now() / 1000) + 3600,
      };
      const wildcardSvc: UserSession = {
        ...scopedSvc,
        scopes: ['*'],
      };

      expect(isConsoleUser(scopedSvc)).toBe(false);
      expect(isConsoleUser(wildcardSvc)).toBe(true);

      expect(() => assertInteractiveSession(scopedSvc)).toThrow(/Forbidden/);
      expect(() => assertInteractiveSession(wildcardSvc)).toThrow(/Forbidden/);
      expect(() => assertMeshSelfServicePermitted(scopedSvc)).toThrow(/Forbidden/);
      expect(() => assertMeshSelfServicePermitted(wildcardSvc)).toThrow(/Forbidden/);

      // Omitted requiredScope denies scoped tokens by default.
      expect(() => assertActionPermitted(scopedSvc, 'readonly')).toThrow(/Scoped service token/);
      expect(() => assertActionPermitted(scopedSvc, 'readonly', 'firewall:write')).toThrow(/lacks required scope/);
      expect(() => assertActionPermitted(scopedSvc, 'admin', 'observability:read')).not.toThrow();
      expect(() => assertActionPermitted(wildcardSvc, 'admin')).not.toThrow();
    });
  });

  describe('auth-internal lockout & session revocation', () => {
    it('rejects non-string credentials and does not evict actively locked accounts under map pressure', async () => {
      const badType = await performAuthentication(null as any, { nested: true } as any);
      expect(badType.success).toBe(false);
      expect(badType.error).toContain('Username and password are required');

      const targetUser = 'lockout-victim-track4';
      for (let i = 0; i < 5; i++) {
        await performAuthentication(targetUser, 'wrong-password');
      }
      const lockedImmediately = await performAuthentication(targetUser, 'wrong-password');
      expect(lockedImmediately.error).toContain('Too many failed sign-in attempts');

      // Flood past LOGIN_FAILURE_MAX_ENTRIES (2000) with distinct unlocked accounts.
      for (let i = 0; i < 2010; i++) {
        await performAuthentication(`probe-user-${i}`, 'bad-pass');
      }

      const stillLocked = await performAuthentication(targetUser, 'wrong-password');
      expect(stillLocked.success).toBe(false);
      expect(stillLocked.error).toContain('Too many failed sign-in attempts');
    });

    it('persists revoked jti:exp pairs past 500 entries and prunes only expired entries', () => {
      const nowSec = Math.floor(Date.now() / 1000);
      const keepJti = 'track4-jti-keep-oldest';
      revokeTokenJti(keepJti, nowSec + 7200);

      for (let i = 0; i < 520; i++) {
        revokeTokenJti(`track4-jti-fill-${i}`, nowSec + 3600);
      }

      const epoch = currentSessionEpoch();
      const userEpoch = currentUserSessionEpoch('alice');
      const baseSession: UserSession = {
        userId: 'local:alice',
        username: 'alice',
        source: 'local',
        roles: ['admin'],
        privileges: ['*'],
        exp: nowSec + 7200,
        sessionEpoch: epoch,
        userSessionEpoch: userEpoch,
      };

      expect(isSessionRevoked({ ...baseSession, jti: keepJti })).toBe(true);
      expect(isSessionRevoked({ ...baseSession, jti: 'track4-jti-fill-519' })).toBe(true);
      expect(isSessionRevoked({ ...baseSession, jti: 'track4-jti-never-revoked' })).toBe(false);

      const diskContent = fs.readFileSync(path.join(hoisted.stateDir, 'revoked-jtis'), 'utf8');
      expect(diskContent).toContain(`${keepJti}:${nowSec + 7200}`);
    });
  });

  describe('OIDC fail-closed role mapping & trusted origin resolution', () => {
    it('fails closed on unrecognized IdP groups and honors only explicit/trusted origins', () => {
      expect(roleFromGroups(['employees', 'unknown-group'])).toBeNull();
      expect(roleFromGroups([])).toBeNull();
      expect(roleFromGroups(['axonwall-admins'])).toBe('admin');
      expect(
        roleFromGroups(['netops'], [{ idpGroup: 'netops', role: 'operator' }])
      ).toBe('operator');
      expect(
        roleFromGroups(['other'], [{ idpGroup: 'netops', role: 'operator' }])
      ).toBeNull();

      const hdrs = new Headers({
        'x-forwarded-host': 'evil.attacker.example',
        'x-forwarded-proto': 'https',
        host: '127.0.0.1:3000',
      });
      const prevTrust = process.env.AXONWALL_TRUST_PROXY;
      const prevHosts = process.env.AXONWALL_TRUSTED_HOSTS;
      delete process.env.AXONWALL_TRUST_PROXY;
      delete process.env.AXONWALL_TRUSTED_HOSTS;
      try {
        expect(resolvePublicOrigin(hdrs, 'http://127.0.0.1:3000')).toBe('http://127.0.0.1:3000');

        process.env.AXONWALL_TRUSTED_HOSTS = 'fw.trusted.example:2966';
        expect(resolvePublicOrigin(hdrs, 'http://127.0.0.1:3000')).toBe('http://127.0.0.1:3000');

        const trustedHdrs = new Headers({
          'x-forwarded-host': 'fw.trusted.example:2966',
          'x-forwarded-proto': 'https',
        });
        expect(resolvePublicOrigin(trustedHdrs, 'http://127.0.0.1:3000')).toBe(
          'https://fw.trusted.example:2966'
        );
      } finally {
        if (prevTrust === undefined) delete process.env.AXONWALL_TRUST_PROXY;
        else process.env.AXONWALL_TRUST_PROXY = prevTrust;
        if (prevHosts === undefined) delete process.env.AXONWALL_TRUSTED_HOSTS;
        else process.env.AXONWALL_TRUSTED_HOSTS = prevHosts;
      }
    });
  });

  describe('Headscale invites two-phase locking, corrupt store & client IP', () => {
    it('extracts rightmost X-Forwarded-For entry in resolveClientIp', () => {
      expect(
        resolveClientIp(
          new Request('http://localhost/api/v1/invites/redeem', {
            headers: {
              'x-forwarded-for': '198.51.100.1, 10.0.0.5, 203.0.113.42',
              'x-real-ip': '192.0.2.10',
            },
          })
        )
      ).toBe('203.0.113.42');
      expect(
        resolveClientIp(
          new Request('http://localhost/api/v1/invites/redeem', {
            headers: { 'x-real-ip': '192.0.2.10' },
          })
        )
      ).toBe('192.0.2.10');
    });

    it('reverts redeeming -> pending on failed provisioning so invite is not burned, and fails closed on corrupt JSON', async () => {
      const { invite, rawToken } = await createHeadscaleInvite({
        username: 'retryuser',
        expiryHours: 12,
        createdBy: 'admin',
      });

      await expect(
        consumeHeadscaleInvite(rawToken, async () => {
          // Verify conflict protection while in redeeming state.
          await expect(
            consumeHeadscaleInvite(rawToken, async () => ({ ok: true }))
          ).rejects.toThrow(/already in progress/);
          throw new Error('headscale daemon temporary failure');
        })
      ).rejects.toThrow(/temporary failure/);

      // Because phase 2 reverted redeeming -> pending, retrying succeeds cleanly.
      const redeemed = await consumeHeadscaleInvite(rawToken, async (pub) => {
        expect(pub.id).toBe(invite.id);
        return { key: 'tskey-auth-123' };
      });
      expect(redeemed.invite.status).toBe('redeemed');
      expect(redeemed.result.key).toBe('tskey-auth-123');

      await expect(consumeHeadscaleInvite(rawToken, async () => ({ ok: true }))).rejects.toThrow(
        /already been used/
      );

      // Fail closed if store JSON becomes corrupt.
      const storePath = path.join(hoisted.stateDir, 'headscale-invites.json');
      const validBackup = fs.readFileSync(storePath, 'utf8');
      fs.writeFileSync(storePath, '{corrupt-json', 'utf8');
      try {
        expect(() => listHeadscaleInvites()).toThrow(/corrupt JSON/);
      } finally {
        fs.writeFileSync(storePath, validBackup, 'utf8');
      }
    });
  });

  describe('SSRF protection & atomic desired-state writes', () => {
    it('blocks link-local metadata and disallowed private/scheme targets', async () => {
      await expect(
        assertSafeOutboundUrl('http://169.254.169.254/latest/meta-data/', {
          allowHttp: true,
          allowPrivate: true,
        })
      ).rejects.toThrow(/link-local|prohibited|SSRF/i);

      await expect(
        assertSafeOutboundUrl('http://127.0.0.1:8080/health', {
          allowHttp: true,
          allowPrivate: false,
        })
      ).rejects.toThrow(/private|loopback|prohibited|SSRF/i);

      await expect(
        assertSafeOutboundUrl('http://93.184.216.34/iso', {
          allowHttp: false,
          allowPrivate: false,
        })
      ).rejects.toThrow(/HTTPS|Protocol/i);

      const dl = await queryDataLakeMetrics({
        enabled: true,
        url: 'http://169.254.169.254:8123',
        username: 'admin',
        password: 'secret',
        database: 'axonwall',
      });
      expect(dl.unavailable).toBe(true);
      expect(dl.reason).toMatch(/link-local|prohibited|SSRF/i);
    });

    it('preserves existing desired-state files on disk if an atomic write target fails', () => {
      const initial = DesiredStateSchema.parse({
        version: 1,
        system: { hostname: 'axonwall-atomic-check' },
        interfaces: [{ name: 'wan', device: 'eth0', role: 'wan', type: 'dhcp', enabled: true }],
      });
      persistDesiredStateToDisk(initial);
      const stateJsonPath = process.env.AXONWALL_STATE_JSON_PATH!;
      const beforeJson = fs.readFileSync(stateJsonPath, 'utf8');
      expect(beforeJson).toContain('axonwall-atomic-check');

      const updated = DesiredStateSchema.parse({
        version: 1,
        system: { hostname: 'axonwall-should-not-overwrite' },
        interfaces: [{ name: 'wan', device: 'eth0', role: 'wan', type: 'dhcp', enabled: true }],
      });
      const renameSpy = vi.spyOn(fs, 'renameSync').mockImplementation(() => {
        throw new Error('ENOSPC');
      });
      try {
        expect(() => persistDesiredStateToDisk(updated)).toThrow(/Failed to atomically persist/);
      } finally {
        renameSpy.mockRestore();
      }

      const afterJson = fs.readFileSync(stateJsonPath, 'utf8');
      expect(afterJson).toBe(beforeJson);
      expect(
        fs.readFileSync(path.join(hoisted.persistDir, 'system.yaml'), 'utf8')
      ).toContain('axonwall-atomic-check');
    });
  });
});
