import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { mintSupabaseToken } from '@axonwall/lib/ldap';
import { enablePluginWithDependencies } from '@axonwall/lib/plugins';
import type { UserSession } from '@axonwall/lib/rbac';
import { DesiredStateSchema, type DesiredState } from '@axonwall/lib/schemas';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-wave2-sec-'));
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
process.env.AXONWALL_SERVICE_TOKENS_PATH = path.join(persistDir, 'service-tokens.json');
process.env.AXONWALL_MCP_KEYS_PATH = path.join(stateDir, 'mcp-keys.json');
process.env.AXONWALL_MCP_AUDIT_PATH = path.join(stateDir, 'mcp-audit.jsonl');
process.env.AXONWALL_HEADSCALE_INVITES_PATH = path.join(stateDir, 'headscale-invites.json');
process.env.FORCE_PASSWORD_CHANGE = 'false';
process.env.JWT_SECRET =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

function makeSession(
  role: 'admin' | 'operator' | 'readonly' | 'vpn_user' = 'admin',
  overrides: Partial<UserSession> = {}
): UserSession {
  return {
    userId: `${role}-1`,
    username: role === 'vpn_user' ? 'vpnuser' : role,
    displayName: role.toUpperCase(),
    roles: [role],
    privileges: role === 'admin' ? ['*'] : [],
    passwordChangeRequired: false,
    source: role === 'admin' ? 'local_admin' : 'local',
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...overrides,
  };
}

const hoisted = vi.hoisted(() => {
  const sessionRef: { current: UserSession | null } = { current: null };
  const cookieJar = new Map<string, string>();
  const callAgentApiMock = vi.fn(async () => null as any);
  const callAgentApiResponseMock = vi.fn(async () => ({ success: true, message: 'ok' }) as any);
  const callAgentApiDetailedMock = vi.fn(async () => ({ kind: 'ok', data: { success: true } }) as any);
  const runPipelineMock = vi.fn(async (state: unknown) => ({
    success: true,
    message: 'Applied',
    nftScript: '',
    warnings: [],
    state,
  }));
  const ssrfFetchSpy = vi.fn<(...args: any[]) => Promise<Response>>();
  const assertOutboundSpy = vi.fn<(...args: any[]) => Promise<any>>();
  return {
    root: '',
    sessionRef,
    cookieJar,
    callAgentApiMock,
    callAgentApiResponseMock,
    callAgentApiDetailedMock,
    runPipelineMock,
    ssrfFetchSpy,
    assertOutboundSpy,
  };
});
hoisted.root = root;

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) =>
      hoisted.cookieJar.has(name) ? { name, value: hoisted.cookieJar.get(name)! } : undefined,
    set: (name: string, value: string) => {
      hoisted.cookieJar.set(name, value);
    },
    delete: (name: string) => {
      hoisted.cookieJar.delete(name);
    },
  })),
  headers: vi.fn(async () => new Headers()),
}));

vi.mock('next/navigation', () => ({
  redirect: vi.fn((url: string) => {
    throw new Error(`NEXT_REDIRECT:${url}`);
  }),
}));

vi.mock('../auth', () => ({
  getSession: vi.fn(async () => hoisted.sessionRef.current),
}));

vi.mock('../agent-client', () => ({
  clearCachedAgentToken: vi.fn(),
  getAgentToken: vi.fn(() => 'test-agent-token'),
  isApplianceRuntime: vi.fn(() => false),
  callAgentApi: hoisted.callAgentApiMock,
  callAgentApiResponse: hoisted.callAgentApiResponseMock,
  callAgentApiDetailed: hoisted.callAgentApiDetailedMock,
}));

vi.mock('../apply-state-internal', () => ({
  runDesiredStateApplyPipeline: hoisted.runPipelineMock,
}));

vi.mock('../ssrf-guard', async () => {
  const actual = await vi.importActual<typeof import('../ssrf-guard')>('../ssrf-guard');
  hoisted.ssrfFetchSpy.mockImplementation((...args: any[]) =>
    (actual.ssrfSafeFetch as any)(...args)
  );
  hoisted.assertOutboundSpy.mockImplementation((...args: any[]) =>
    (actual.assertSafeOutboundUrl as any)(...args)
  );
  return {
    ...actual,
    ssrfSafeFetch: (...args: any[]) => hoisted.ssrfFetchSpy(...args),
    assertSafeOutboundUrl: (...args: any[]) => hoisted.assertOutboundSpy(...args),
  };
});

import {
  invalidateDesiredStateCacheInternal,
  persistDesiredStateToDisk,
} from '../desired-state-internal';
import {
  applyDesiredState,
  applySystemFirmwareUpdate,
  createMcpApiKeyAction,
  executeK3sAction,
  executeTerminalCommand,
  exportCloudInitConfigAction,
  getCurrentDesiredState,
  getK3sClusterPulseAction,
  getK3sRuntimeStatus,
  getNasDisksInventory,
  getNetFlowNodesAction,
  getRecentThreatAlerts,
  getRosenpassStatusAction,
  getServiceJournalLogs,
  getThreatHarvesterStatus,
  getUpsStatus,
  poweroffSystemAction,
  rebootSystemAction,
  runDiagnostic,
  runNmapScan,
} from '../agent';
import { saveEtckeeperConfig } from '../gitops';
import { getAttackGraphDataAction, getVigilanteConfigAction } from '../vigilante';
import { getVirtConfigAction, vmPowerAction } from '../virt';
import { getLiveFleetSatellitesAction, triggerFleetSyncAction } from '../fleet';
import { queryDataLakeMetrics } from '../clickhouse';
import { queryVictoriaMetricsRange } from '../observability-clients';
import { assertActionPermitted } from '../auth-guard';
import { performAuthentication, resetLoginFailuresForTests } from '../auth-internal';
import {
  bumpUserSessionEpoch,
  currentUserSessionEpoch,
  isSessionRevoked,
  stampSessionEpoch,
} from '../session-revocation';
import {
  checkInviteRateLimit,
  createHeadscaleInvite,
  listHeadscaleInvites,
  resetInviteRateLimitForTests,
} from '../headscale-invites';
import { resolveHeadscaleUsername } from '../headscale';
import { resolveClientIp } from '../headscale-network';
import { computePkceChallenge, OIDC_STATE_COOKIE, resolvePublicOrigin } from '../oidc';
import { getCaptureFile, runLivePacketCapture } from '../pcap';
import { createPinnedLookup, isDisallowedSsrfIp, ssrfSafeFetch } from '../ssrf-guard';
import { middleware } from '../../middleware';

import { GET as docsBundleGet } from '../../app/api/docs-bundle/[[...path]]/route';
import { GET as gatewayGet } from '../../app/api/auth/gateway/route';
import { POST as loginPost } from '../../app/api/auth/login/route';
import { GET as ssoLoginGet } from '../../app/api/auth/sso/login/route';
import { GET as oidcCallbackGet } from '../../app/api/auth/callback/oidc/route';
import { GET as packetsGet } from '../../app/api/v1/events/packets/route';
import { GET as k3sGet, POST as k3sPost } from '../../app/api/k3s/route';
import { GET as nasGet, POST as nasPost } from '../../app/api/nas/route';
import { GET as meshConfigGet, POST as meshConfigPost } from '../../app/api/v1/vpn/mesh/config/route';
import { GET as meshKeysGet, POST as meshKeysPost } from '../../app/api/v1/vpn/mesh/keys/route';
import { GET as meshMachinesGet, POST as meshMachinesPost } from '../../app/api/v1/vpn/mesh/machines/route';
import { GET as meshPeopleGet, POST as meshPeoplePost } from '../../app/api/v1/vpn/mesh/people/route';
import { GET as meshRoutesGet, POST as meshRoutesPost } from '../../app/api/v1/vpn/mesh/routes/route';
import { GET as meshUsersGet, POST as meshUsersPost } from '../../app/api/v1/vpn/mesh/users/route';
import { GET as meshWanGet, POST as meshWanPost } from '../../app/api/v1/vpn/mesh/wan-window/route';
import { GET as meshSelfGet } from '../../app/api/v1/vpn/mesh/self/route';
import { POST as meshSelfDevicesPost } from '../../app/api/v1/vpn/mesh/self/devices/route';
import { POST as meshSelfKeysPost } from '../../app/api/v1/vpn/mesh/self/keys/route';
import { POST as meshSelfPasswordPost } from '../../app/api/v1/vpn/mesh/self/password/route';
import { POST as meshSelfRegisterPost } from '../../app/api/v1/vpn/mesh/self/register/route';
import {
  GET as invitePreviewGet,
  POST as invitePreviewPost,
} from '../../app/api/v1/vpn/mesh/invites/preview/route';
import { POST as inviteRedeemPost } from '../../app/api/v1/vpn/mesh/invites/redeem/route';

function seedState(build?: (base: DesiredState) => DesiredState): DesiredState {
  const base = DesiredStateSchema.parse({
    version: 1,
    interfaces: [{ name: 'wan', device: 'eth0', role: 'wan', type: 'dhcp', enabled: true }],
  });
  const next = build ? build(base) : base;
  persistDesiredStateToDisk(next);
  invalidateDesiredStateCacheInternal();
  return next;
}

function listenServer(server: http.Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve((server.address() as { port: number }).port);
    });
  });
}

function closeServer(server: http.Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

afterAll(() => {
  fs.rmSync(hoisted.root, { recursive: true, force: true });
});

describe('Wave 2 Web Backend Security Remediations', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    const actualSsrf = await vi.importActual<typeof import('../ssrf-guard')>('../ssrf-guard');
    hoisted.ssrfFetchSpy.mockImplementation((...args: any[]) =>
      (actualSsrf.ssrfSafeFetch as any)(...args)
    );
    hoisted.assertOutboundSpy.mockImplementation((...args: any[]) =>
      (actualSsrf.assertSafeOutboundUrl as any)(...args)
    );
    hoisted.cookieJar.clear();
    hoisted.sessionRef.current = makeSession('admin');
    hoisted.callAgentApiMock.mockResolvedValue(null);
    hoisted.callAgentApiResponseMock.mockResolvedValue({ success: true, message: 'ok' });
    hoisted.callAgentApiDetailedMock.mockResolvedValue({ kind: 'ok', data: { success: true } });
    hoisted.runPipelineMock.mockImplementation(async (state: unknown) => ({
      success: true,
      message: 'Applied',
      nftScript: '',
      warnings: [],
      state,
    }));
    resetLoginFailuresForTests();
    resetInviteRateLimitForTests();
    if (fs.existsSync(process.env.AXONWALL_HEADSCALE_INVITES_PATH!)) {
      fs.unlinkSync(process.env.AXONWALL_HEADSCALE_INVITES_PATH!);
    }
    seedState();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('1. [SEC-H08] DesiredState & ThreatHarvester secret redaction + mask preservation', () => {
    it('redacts k3s.externalDatastoreEndpoint, litestreamAccessKeyId, accessKey fields, and recursive credential URIs while preserving on admin apply', async () => {
      seedState((base) =>
        DesiredStateSchema.parse({
          ...base,
          k3s: {
            enabled: true,
            externalDatastoreEndpoint: 'postgres://k3s:dbpass@pg.internal:5432/k3s',
          },
          ha: {
            enabled: false,
            sqliteSync: {
              litestreamAccessKeyId: 'AKIAIOSFODNN7EXAMPLE',
              litestreamSecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            },
          },
          nas: {
            enabled: true,
            s3: {
              enabled: true,
              accessKey: 'MINIOACCESS123',
              secretKey: 'MINIOSECRET456',
            },
          },
          threatHarvester: {
            enabled: true,
            anonymizationSalt: 'harvester-salt-001',
            teacherLlm: {
              apiKey: 'sk-teacher-secret',
            },
            fleetShipper: {
              accessKey: 'SHIPPERACCESS789',
              secretKey: 'SHIPPERSECRET012',
            },
          },
          wireguard: {
            enabled: true,
            privateKey: 'wg-priv-redact-0123456789abcdef0123456789ab',
          },
            observability: {
            clickhouse: {
              enabled: true,
              url: 'https://clickhouse.internal:8123',
              password: 'ch-secret-password',
            },
            victoriaLogs: {
              enabled: true,
              url: 'https://vluser:vlsecret@logs.internal:9428',
            },
            victoriaMetrics: {
              enabled: true,
              url: 'https://vm.internal:8428?api_key=vm-query-secret',
            },
            alerting: {
              webhookUrl: 'https://hooks.example.com/notify?token=query-secret-value',
            },
          },
          system: {
            ...base.system,
            hostname: 'fw-main',
          },
        })
      );

      hoisted.sessionRef.current = makeSession('operator');
      const opState = (await getCurrentDesiredState()) as any;
      expect(opState.k3s.externalDatastoreEndpoint).toBe('********');
      expect(opState.ha.sqliteSync.litestreamAccessKeyId).toBe('********');
      expect(opState.ha.sqliteSync.litestreamSecretAccessKey).toBe('********');
      expect(opState.nas.s3.accessKey).toBe('********');
      expect(opState.nas.s3.secretKey).toBe('********');
      expect(opState.threatHarvester.fleetShipper.accessKey).toBe('********');
      expect(opState.threatHarvester.fleetShipper.secretKey).toBe('********');
      expect(opState.threatHarvester.teacherLlm.apiKey).toBe('********');
      expect(opState.wireguard.privateKey).toBe('********');
      expect(opState.system.hostname).toBe('fw-main');
      expect(opState.observability.clickhouse.url).toBe('https://clickhouse.internal:8123');
      expect(opState.observability.victoriaLogs.url).toBe('********');
      expect(opState.observability.victoriaMetrics.url).not.toContain('vm-query-secret');
      expect(opState.observability.alerting.webhookUrl).toBe('********');

      // ThreatHarvester status also masks fleetShipper.accessKey (daemon down & daemon live)
      const thDown = await getThreatHarvesterStatus();
      expect(thDown.config.fleetShipper.accessKey).toBe('********');
      expect(thDown.config.fleetShipper.secretKey).toBe('********');

      hoisted.callAgentApiMock.mockResolvedValueOnce({
        daemonDown: false,
        config: {
          anonymizationSalt: 'live-salt',
          teacherLlm: { apiKey: 'live-llm-key' },
          fleetShipper: { accessKey: 'LIVEACCESS', secretKey: 'LIVESECRET' },
        },
        stats: { packetsSeen: 10 },
      });
      const thLive = await getThreatHarvesterStatus();
      expect(thLive.config.fleetShipper.accessKey).toBe('********');
      expect(thLive.config.fleetShipper.secretKey).toBe('********');
      expect(thLive.config.teacherLlm.apiKey).toBe('********');

      // Admin saving back masked '********' placeholders preserves originals on disk
      hoisted.sessionRef.current = makeSession('admin');
      const maskedForApply = DesiredStateSchema.parse({
        ...opState,
        wireguard: undefined,
        observability: {
          ...opState.observability,
          victoriaLogs: { enabled: true, url: 'https://logs.internal:9428' },
          victoriaMetrics: { enabled: true, url: 'https://vm.internal:8428' },
        },
        k3s: { ...opState.k3s, externalDatastoreEndpoint: '********' },
        ha: {
          ...opState.ha,
          sqliteSync: {
            ...opState.ha.sqliteSync,
            litestreamAccessKeyId: '********',
            litestreamSecretAccessKey: '********',
          },
        },
        nas: {
          ...opState.nas,
          s3: { ...opState.nas.s3, accessKey: '********', secretKey: '********' },
        },
        threatHarvester: {
          ...opState.threatHarvester,
          anonymizationSalt: '********',
          teacherLlm: { ...opState.threatHarvester.teacherLlm, apiKey: '********' },
          fleetShipper: {
            ...opState.threatHarvester.fleetShipper,
            accessKey: '********',
            secretKey: '********',
          },
        },
      });
      await applyDesiredState(maskedForApply, 60);
      const passed = hoisted.runPipelineMock.mock.calls.at(-1)?.[0] as DesiredState;
      expect(passed.k3s?.externalDatastoreEndpoint).toBe('postgres://k3s:dbpass@pg.internal:5432/k3s');
      expect(passed.ha?.sqliteSync.litestreamAccessKeyId).toBe('AKIAIOSFODNN7EXAMPLE');
      expect(passed.ha?.sqliteSync.litestreamSecretAccessKey).toBe(
        'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
      );
      expect(passed.nas?.s3?.accessKey).toBe('MINIOACCESS123');
      expect(passed.nas?.s3?.secretKey).toBe('MINIOSECRET456');
      expect(passed.threatHarvester?.fleetShipper.accessKey).toBe('SHIPPERACCESS789');
      expect(passed.threatHarvester?.fleetShipper.secretKey).toBe('SHIPPERSECRET012');
      expect(passed.threatHarvester?.teacherLlm.apiKey).toBe('sk-teacher-secret');
    });
  });

  describe('2. [SEC-H09] Interactive session enforcement & /api/v1/vpn/mesh/people error status codes', () => {
    it('rejects wildcard service_token across all interactive server actions and maps people auth errors cleanly', async () => {
      hoisted.sessionRef.current = makeSession('admin', {
        userId: 'svc:wildcard',
        username: 'svc:wildcard',
        source: 'service_token',
        scopes: ['*'],
      });

      await expect(exportCloudInitConfigAction()).rejects.toThrow(/Forbidden/);
      await expect(executeTerminalCommand('id')).rejects.toThrow(/Forbidden/);
      await expect(
        createMcpApiKeyAction({
          name: 'automation-key',
          agentType: 'custom-ai',
          scopes: ['mcp:k3s:read'],
          allowedSourceCidrs: ['10.0.0.0/8'],
          policyLimits: {},
        })
      ).rejects.toThrow(/Forbidden/);
      await expect(applySystemFirmwareUpdate('B')).rejects.toThrow(/Forbidden/);
      await expect(rebootSystemAction('A')).rejects.toThrow(/Forbidden/);
      await expect(poweroffSystemAction()).rejects.toThrow(/Forbidden/);
      await expect(saveEtckeeperConfig({})).rejects.toThrow(/Forbidden/);

      const peopleGetSvc = await meshPeopleGet(new NextRequest('http://localhost/api/v1/vpn/mesh/people'));
      expect(peopleGetSvc.status).toBe(403);
      const peoplePostSvc = await meshPeoplePost(
        new NextRequest('http://localhost/api/v1/vpn/mesh/people', {
          method: 'POST',
          body: JSON.stringify({ action: 'create', username: 'alice' }),
        })
      );
      expect(peoplePostSvc.status).toBe(403);

      hoisted.sessionRef.current = null;
      const peopleGetUnauth = await meshPeopleGet(
        new NextRequest('http://localhost/api/v1/vpn/mesh/people')
      );
      expect(peopleGetUnauth.status).toBe(401);
      const peoplePostUnauth = await meshPeoplePost(
        new NextRequest('http://localhost/api/v1/vpn/mesh/people', {
          method: 'POST',
          body: JSON.stringify({ action: 'create', username: 'alice' }),
        })
      );
      expect(peoplePostUnauth.status).toBe(401);
    });
  });

  describe('3. [SEC-H10] & [SEC-M15] SSRF pinning, IPv6 transition prefixes, response caps, ClickHouse redirects, and VM span cap', () => {
    it('blocks IPv6 NAT64/6to4/Teredo/SIIT/site-local prefixes and aborts oversized ssrfSafeFetch responses', async () => {
      for (const ip of ['64:ff9b:1::1', '2002:7f00:1::1', '2001:0:4136:e378::1', '::ffff:0:127.0.0.1', '::ffff:0:0:1', 'fec0::1']) {
        expect(isDisallowedSsrfIp(ip, { allowPrivate: true })).toBe(true);
      }

      const bigSrv = http.createServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('A'.repeat(4096));
      });
      const port = await listenServer(bigSrv);
      try {
        await expect(
          ssrfSafeFetch(
            `http://127.0.0.1:${port}/big`,
            { maxResponseBytes: 512, timeoutMs: 2000 },
            { allowHttp: true, allowPrivate: true }
          )
        ).rejects.toThrow(/exceeded maxResponseBytes|maximum size|exceeds/i);
      } finally {
        await closeServer(bigSrv);
      }
    });

    it('pins DNS lookup for http.Agent, blocks HTTP 302 redirects on ClickHouse, guards queryDataLakeMetrics, and caps oversized Fleet payloads', async () => {
      let targetHitCount = 0;
      const redirectTargetSrv = http.createServer((_req, res) => {
        targetHitCount += 1;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"data":[]}');
      });
      const targetPort = await listenServer(redirectTargetSrv);

      const chRedirectSrv = http.createServer((_req, res) => {
        res.writeHead(302, { Location: `http://127.0.0.1:${targetPort}/secret` });
        res.end();
      });
      const chPort = await listenServer(chRedirectSrv);

      const pinnedHitSrv = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ host: req.headers.host || '', ok: true }));
      });
      const pinnedPort = await listenServer(pinnedHitSrv);

      const oversizedFleetSrv = http.createServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        const chunk = 'x'.repeat(1024 * 1024);
        for (let i = 0; i < 11; i++) res.write(chunk);
        res.end();
      });
      const fleetPort = await listenServer(oversizedFleetSrv);
      const prevControllerUrl = process.env.CONTROLLER_URL;
      try {
        // Verify createPinnedLookup steers Node http.request to pinned loopback IP without resolving nonexistent hostname
        const pinnedBody = await new Promise<string>((resolve, reject) => {
          const req = http.request(
            {
              hostname: 'rebind.nonexistent.invalid',
              port: pinnedPort,
              path: '/ping',
              lookup: createPinnedLookup([{ address: '127.0.0.1', family: 4 }]) as any,
            },
            (res) => {
              let data = '';
              res.on('data', (c) => (data += c));
              res.on('end', () => resolve(data));
            }
          );
          req.on('error', reject);
          req.end();
        });
        expect(JSON.parse(pinnedBody).ok).toBe(true);

        // queryDataLakeMetrics rejects unauthenticated callers
        hoisted.sessionRef.current = null;
        await expect(
          queryDataLakeMetrics({
            enabled: true,
            url: `http://127.0.0.1:${chPort}`,
            username: 'default',
            password: 'pw',
            database: 'axonwall',
          })
        ).rejects.toThrow(/Unauthorized|Forbidden/i);

        // ClickHouse refuses HTTP 302 redirect and never hits redirect target
        hoisted.sessionRef.current = makeSession('readonly');
        const chRedirect = await queryDataLakeMetrics({
          enabled: true,
          url: `http://127.0.0.1:${chPort}`,
          username: 'default',
          password: 'pw',
          database: 'axonwall',
        });
        expect(chRedirect.unavailable).toBe(true);
        expect(targetHitCount).toBe(0);

        // Fleet aborts oversized >10 MiB controller payloads
        seedState((s) => enablePluginWithDependencies('fleet-controller', s).state);
        process.env.CONTROLLER_URL = `http://127.0.0.1:${fleetPort}`;
        const fleetRes = await getLiveFleetSatellitesAction();
        expect(fleetRes.reachable).toBe(false);
        expect(fleetRes.error).toMatch(/size limit|exceeded/i);
      } finally {
        if (prevControllerUrl === undefined) delete process.env.CONTROLLER_URL;
        else process.env.CONTROLLER_URL = prevControllerUrl;
        await Promise.all([
          closeServer(redirectTargetSrv),
          closeServer(chRedirectSrv),
          closeServer(pinnedHitSrv),
          closeServer(oversizedFleetSrv),
        ]);
      }
    });

    it('caps queryVictoriaMetricsRange time span to 90 days and sample count to <= 10,000 points', async () => {
      hoisted.ssrfFetchSpy.mockImplementation(async () => {
        return new Response(JSON.stringify({ status: 'success', data: { result: [] } }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      });
      const state = DesiredStateSchema.parse({
        version: 1,
        observability: {
          victoriaMetrics: { enabled: true, url: 'https://vm.internal:8428' },
        },
      });
      const nowSec = 1_800_000_000;
      const twoYearsAgo = nowSec - 730 * 86400;
      await queryVictoriaMetricsRange('up', twoYearsAgo, nowSec, 5, { state });

      expect(hoisted.ssrfFetchSpy).toHaveBeenCalledTimes(1);
      const calledUrl = new URL(hoisted.ssrfFetchSpy.mock.calls[0]![0]);
      const start = Number(calledUrl.searchParams.get('start'));
      const end = Number(calledUrl.searchParams.get('end'));
      const step = Number(calledUrl.searchParams.get('step'));
      expect(end - start).toBeLessThanOrEqual(90 * 86400);
      expect((end - start) / step).toBeLessThanOrEqual(10_000);
    });
  });

  describe('4. [SEC-H11] /api/docs-bundle CSP sandbox', () => {
    it('emits sandbox allow-scripts without allow-same-origin or allow-top-navigation', async () => {
      const siteDir = path.join(stateDir, 'docs-portal', 'site');
      fs.mkdirSync(path.join(siteDir, 'docs'), { recursive: true });
      fs.writeFileSync(path.join(siteDir, 'docs', 'index.html'), '<html><body>Docs</body></html>');

      seedState((s) => enablePluginWithDependencies('docs-portal', s).state);
      const res = await docsBundleGet(new NextRequest('https://localhost/api/docs-bundle/docs/index.html'), {
        params: Promise.resolve({ path: ['docs', 'index.html'] }),
      });
      expect(res.status).toBe(200);
      const csp = res.headers.get('Content-Security-Policy') || '';
      expect(csp).toContain('sandbox allow-scripts');
      expect(csp).toContain("object-src 'none'");
      expect(csp).toContain("base-uri 'none'");
      expect(csp).not.toContain('allow-same-origin');
      expect(csp).not.toContain('allow-top-navigation');
    });
  });

  describe('5. [SEC-M08] Lean Core plugin guards across routes & actions', () => {
    it('fails closed across all Headscale, K3s, NAS, Virt, Vigilante, Fleet, Nmap, NetFlow, Rosenpass, NUT, Suricata, and Gateway endpoints when plugins are disabled', async () => {
      // Base seedState has optional plugins disabled
      const { rawToken } = await createHeadscaleInvite({
        username: 'disabledvpn',
        expiryHours: 12,
        createdBy: 'admin',
      });

      // Invites preview & redeem fail closed 403 BEFORE consuming invite or touching directory
      const prevDisabled = await invitePreviewPost(
        new NextRequest('http://localhost/api/v1/vpn/mesh/invites/preview', {
          method: 'POST',
          body: JSON.stringify({ token: rawToken }),
        })
      );
      expect(prevDisabled.status).toBe(403);

      const redDisabled = await inviteRedeemPost(
        new NextRequest('http://localhost/api/v1/vpn/mesh/invites/redeem', {
          method: 'POST',
          body: JSON.stringify({ token: rawToken, password: 'ValidPassword123!' }),
        })
      );
      expect(redDisabled.status).toBe(403);
      expect(listHeadscaleInvites().find((i) => i.username === 'disabledvpn')?.status).toBe('pending');
      expect(hoisted.callAgentApiDetailedMock).not.toHaveBeenCalled();

      // Even if plugin flag is enabled in list but headscale.enabled === false, invites fail closed
      seedState((s) =>
        DesiredStateSchema.parse({
          ...enablePluginWithDependencies('headscale', s).state,
          headscale: { enabled: false },
        })
      );
      const redFlagOff = await inviteRedeemPost(
        new NextRequest('http://localhost/api/v1/vpn/mesh/invites/redeem', {
          method: 'POST',
          body: JSON.stringify({ token: rawToken, password: 'ValidPassword123!' }),
        })
      );
      expect(redFlagOff.status).toBe(403);

      // Reset to disabled baseline and verify every mesh route fails closed with 403
      seedState();
      const postReq = (url: string, body = {}) =>
        new NextRequest(url, { method: 'POST', body: JSON.stringify(body) });

      for (const res of await Promise.all([
        meshConfigGet(new NextRequest('http://localhost/api/v1/vpn/mesh/config')),
        meshConfigPost(postReq('http://localhost/api/v1/vpn/mesh/config')),
        meshKeysGet(new Request('http://localhost/api/v1/vpn/mesh/keys')),
        meshKeysPost(new Request('http://localhost/api/v1/vpn/mesh/keys', { method: 'POST', body: '{}' })),
        meshMachinesGet(new Request('http://localhost/api/v1/vpn/mesh/machines')),
        meshMachinesPost(
          new Request('http://localhost/api/v1/vpn/mesh/machines', { method: 'POST', body: '{}' })
        ),
        meshPeopleGet(new NextRequest('http://localhost/api/v1/vpn/mesh/people')),
        meshPeoplePost(postReq('http://localhost/api/v1/vpn/mesh/people')),
        meshRoutesGet(new Request('http://localhost/api/v1/vpn/mesh/routes')),
        meshRoutesPost(new Request('http://localhost/api/v1/vpn/mesh/routes', { method: 'POST', body: '{}' })),
        meshUsersGet(),
        meshUsersPost(new Request('http://localhost/api/v1/vpn/mesh/users', { method: 'POST', body: '{}' })),
        meshWanGet(new NextRequest('http://localhost/api/v1/vpn/mesh/wan-window')),
        meshWanPost(postReq('http://localhost/api/v1/vpn/mesh/wan-window')),
        meshSelfGet(new NextRequest('http://localhost/api/v1/vpn/mesh/self')),
        meshSelfDevicesPost(postReq('http://localhost/api/v1/vpn/mesh/self/devices')),
        meshSelfKeysPost(postReq('http://localhost/api/v1/vpn/mesh/self/keys')),
        meshSelfPasswordPost(postReq('http://localhost/api/v1/vpn/mesh/self/password')),
        meshSelfRegisterPost(postReq('http://localhost/api/v1/vpn/mesh/self/register')),
        packetsGet(new NextRequest('http://localhost/api/v1/events/packets')),
        k3sGet(),
        k3sPost(new Request('http://localhost/api/k3s', { method: 'POST', body: '{}' })),
        nasGet(),
        nasPost(new Request('http://localhost/api/nas', { method: 'POST', body: '{}' })),
        gatewayGet(new NextRequest('http://localhost/api/auth/gateway?app_id=a&roles=admin')),
      ])) {
        expect(res.status).toBe(403);
      }

      // Disabled server actions fail closed with Forbidden: Plugin '...'
      await expect(getNetFlowNodesAction()).rejects.toThrow(/Forbidden: Plugin 'netflow-collector'/);
      await expect(getK3sRuntimeStatus()).rejects.toThrow(/Forbidden: Plugin 'core-k3s'/);
      await expect(getK3sClusterPulseAction()).rejects.toThrow(/Forbidden: Plugin 'core-k3s'/);
      await expect(
        executeK3sAction({ resource: 'pods', name: 'p', action: 'delete' })
      ).rejects.toThrow(/Forbidden: Plugin 'core-k3s'/);
      await expect(getNasDisksInventory()).rejects.toThrow(/Forbidden: Plugin 'core-nas'/);
      await expect(getVirtConfigAction()).rejects.toThrow(/Forbidden: Plugin 'core-virt'/);
      await expect(vmPowerAction(101, 'start')).rejects.toThrow(/Forbidden: Plugin 'core-virt'/);
      await expect(getVigilanteConfigAction()).rejects.toThrow(/Forbidden: Plugin 'core-vigilante'/);
      await expect(getAttackGraphDataAction()).rejects.toThrow(/Forbidden: Plugin 'core-vigilante'/);
      await expect(getLiveFleetSatellitesAction()).rejects.toThrow(
        /Forbidden: Plugin 'fleet-controller'/
      );
      await expect(triggerFleetSyncAction()).rejects.toThrow(/Forbidden: Plugin 'fleet-controller'/);
      await expect(
        runNmapScan({ target: '192.168.1.1', profile: 'ping', simulated: true })
      ).rejects.toThrow(/Forbidden: Plugin 'cli-diagnostics-nastymap'/);
      await expect(getRosenpassStatusAction()).rejects.toThrow(/Forbidden: Plugin 'rosenpass'/);
      await expect(getUpsStatus()).rejects.toThrow(/Forbidden: Plugin 'nut-ups'/);
      await expect(getRecentThreatAlerts()).rejects.toThrow(/Forbidden: Plugin 'suricata-ids'/);
    });
  });

  describe('6. [SEC-M09..M14, M18, L05..L09] OIDC, Gateway, Lockout/Caps, ClientIP, Invite Preview, PCAP, and Low Hardening', () => {
    it('enforces OIDC S256 PKCE, email_verified, oidc: namespacing, scheme & alg pinning, azp, and relative redirects', async () => {
      seedState((s) =>
        DesiredStateSchema.parse({
          ...enablePluginWithDependencies('enterprise-sso', s).state,
          sso: {
            enabled: true,
            provider: 'oidc',
            issuerUrl: 'https://idp.example.com/realms/main',
            clientId: 'axonwall-ui',
          },
        })
      );

      // 1. resolvePublicOrigin does NOT trust unconfigured Host header when AXONWALL_TRUST_PROXY / TRUSTED_HOSTS unset
      const prevTrust = process.env.AXONWALL_TRUST_PROXY;
      const prevHosts = process.env.AXONWALL_TRUSTED_HOSTS;
      delete process.env.AXONWALL_TRUST_PROXY;
      delete process.env.AXONWALL_TRUSTED_HOSTS;
      try {
        expect(
          resolvePublicOrigin(
            new Headers({ host: 'spoofed.attacker.com', 'x-forwarded-host': 'evil.attacker.com' }),
            'https://axonwall.local'
          )
        ).toBe('https://axonwall.local');
      } finally {
        if (prevTrust !== undefined) process.env.AXONWALL_TRUST_PROXY = prevTrust;
        if (prevHosts !== undefined) process.env.AXONWALL_TRUSTED_HOSTS = prevHosts;
      }

      // 2. Reject http:// authorization_endpoint when issuer is https://
      hoisted.ssrfFetchSpy.mockImplementation(async () => {
        return new Response(
          JSON.stringify({
            authorization_endpoint: 'http://idp.example.com/auth',
            token_endpoint: 'https://idp.example.com/token',
            jwks_uri: 'https://idp.example.com/jwks',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      });
      const badSchemeRes = await ssoLoginGet(new NextRequest('https://axonwall.local/api/auth/sso/login'));
      expect(badSchemeRes.status).toBe(302);
      expect(badSchemeRes.headers.get('location')).toBe('/login?error=sso_unreachable');

      // 3. Valid discovery -> S256 PKCE + 3-part state cookie; then callback checks email_verified, RS256 alg pinning, azp, and oidc: prefix
      const { publicKey, privateKey } = await generateKeyPair('RS256');
      const jwk = await exportJWK(publicKey);
      jwk.kid = 'k1';
      jwk.alg = 'RS256';
      jwk.use = 'sig';

      // Use a distinct issuerUrl so module-level discoveryCache does not reuse step 2
      seedState((s) =>
        DesiredStateSchema.parse({
          ...enablePluginWithDependencies('enterprise-sso', s).state,
          sso: {
            enabled: true,
            provider: 'oidc',
            issuerUrl: 'https://idp-v2.example.com/realms/main',
            clientId: 'axonwall-ui',
          },
        })
      );

      let nextIdToken = '';
      let lastTokenReqBody = '';
      hoisted.assertOutboundSpy.mockResolvedValue({
        url: new URL('https://idp-v2.example.com'),
        addresses: [{ address: '93.184.216.34', family: 4 }],
      });
      hoisted.ssrfFetchSpy.mockImplementation(async (url: string, init?: RequestInit) => {
        if (url.endsWith('/.well-known/openid-configuration')) {
          return new Response(
            JSON.stringify({
              authorization_endpoint: 'https://idp-v2.example.com/auth',
              token_endpoint: 'https://idp-v2.example.com/token',
              jwks_uri: 'https://idp-v2.example.com/jwks',
            }),
            { status: 200, headers: { 'content-type': 'application/json' } }
          );
        }
        if (url.endsWith('/token')) {
          lastTokenReqBody = String(init?.body || '');
          return new Response(JSON.stringify({ id_token: nextIdToken }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        if (url.endsWith('/jwks')) {
          return new Response(JSON.stringify({ keys: [jwk] }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        return new Response('Not found', { status: 404 });
      });

      const loginRes = await ssoLoginGet(new NextRequest('https://axonwall.local/api/auth/sso/login'));
      expect(loginRes.status).toBe(307);
      const authLoc = new URL(loginRes.headers.get('location')!);
      const state = authLoc.searchParams.get('state')!;
      const nonce = authLoc.searchParams.get('nonce')!;
      const challenge = authLoc.searchParams.get('code_challenge')!;
      expect(authLoc.searchParams.get('code_challenge_method')).toBe('S256');
      const stateCookie = loginRes.cookies.get(OIDC_STATE_COOKIE)?.value || '';
      const cookieParts = stateCookie.split('.');
      expect(cookieParts).toHaveLength(3);
      expect(computePkceChallenge(cookieParts[2]!)).toBe(challenge);

      // Helper to build callback NextRequest carrying the OIDC_STATE_COOKIE
      const callCallback = (cookieVal: string) => {
        const req = new NextRequest(
          `https://axonwall.local/api/auth/callback/oidc?code=code-1&state=${encodeURIComponent(state)}`,
          { headers: { cookie: `${OIDC_STATE_COOKIE}=${cookieVal}` } }
        );
        return oidcCallbackGet(req);
      };

      // Reject unverified email
      nextIdToken = await new SignJWT({
        sub: 'sub-1',
        nonce,
        email: 'admin@example.com',
        email_verified: false,
        groups: ['axonwall-admins'],
      })
        .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
        .setIssuer('https://idp-v2.example.com/realms/main')
        .setAudience('axonwall-ui')
        .setIssuedAt()
        .setExpirationTime('10m')
        .sign(privateKey);

      const unverifiedRes = await callCallback(stateCookie);
      expect(unverifiedRes.status).toBe(302);
      expect(unverifiedRes.headers.get('location')).toBe('/login?error=sso_email_unverified');

      // Reject multi-audience JWT with mismatched azp
      nextIdToken = await new SignJWT({
        sub: 'sub-1',
        nonce,
        email: 'admin@example.com',
        email_verified: true,
        azp: 'some-other-client',
        groups: ['axonwall-admins'],
      })
        .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
        .setIssuer('https://idp-v2.example.com/realms/main')
        .setAudience(['axonwall-ui', 'other-app'])
        .setIssuedAt()
        .setExpirationTime('10m')
        .sign(privateKey);

      const badAzpRes = await callCallback(stateCookie);
      expect(badAzpRes.status).toBe(302);
      expect(badAzpRes.headers.get('location')).toBe('/login?error=sso_failed');

      // Reject HS256 symmetric algorithm confusion token
      nextIdToken = await new SignJWT({
        sub: 'sub-1',
        nonce,
        email: 'admin@example.com',
        email_verified: true,
        groups: ['axonwall-admins'],
      })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuer('https://idp-v2.example.com/realms/main')
        .setAudience('axonwall-ui')
        .setIssuedAt()
        .setExpirationTime('10m')
        .sign(new TextEncoder().encode('fake-hmac-secret'));

      const hs256Res = await callCallback(stateCookie);
      expect(hs256Res.status).toBe(302);
      expect(hs256Res.headers.get('location')).toBe('/login?error=sso_failed');

      // Valid verified RS256 token succeeds with relative redirect & oidc: namespace + PKCE code_verifier
      nextIdToken = await new SignJWT({
        sub: 'sub-admin-1',
        nonce,
        email: 'admin@example.com',
        email_verified: true,
        azp: 'axonwall-ui',
        groups: ['axonwall-admins'],
      })
        .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
        .setIssuer('https://idp-v2.example.com/realms/main')
        .setAudience(['axonwall-ui', 'extra-aud'])
        .setIssuedAt()
        .setExpirationTime('10m')
        .sign(privateKey);

      const okRes = await callCallback(stateCookie);
      expect(okRes.status).toBe(302);
      expect(okRes.headers.get('location')).toBe('/lobby');
      expect(lastTokenReqBody).toContain(`code_verifier=${encodeURIComponent(cookieParts[2]!)}`);

      // Headscale & session-revocation namespace oidc separately from local accounts
      expect(resolveHeadscaleUsername({ username: 'alice', source: 'oidc' })).not.toBe(
        resolveHeadscaleUsername({ username: 'alice', source: 'local' })
      );
      const localSess: UserSession = makeSession('operator', {
        username: 'alice',
        source: 'local',
      });
      const oidcSess: UserSession = makeSession('operator', {
        username: 'alice',
        source: 'oidc',
      });
      stampSessionEpoch(localSess);
      stampSessionEpoch(oidcSess);
      bumpUserSessionEpoch('alice', 'oidc');
      expect(currentUserSessionEpoch('alice', 'oidc')).toBeGreaterThan(
        currentUserSessionEpoch('alice', 'local')
      );
      expect(isSessionRevoked(oidcSess)).toBe(true);
      expect(isSessionRevoked(localSess)).toBe(false);
    });

    it('hardens /api/auth/gateway against X-Forwarded-Host mismatch, missing/disabled app_id, and vpn_user', async () => {
      const appId = '11111111-1111-4111-8111-111111111111';
      seedState((s) =>
        DesiredStateSchema.parse({
          ...enablePluginWithDependencies('identity-aware-proxy', s).state,
          zeroTrust: {
            enabled: true,
            apps: [
              {
                id: appId,
                name: 'Grafana',
                publicHostname: 'grafana.corp.local',
                internalUpstream: 'http://10.0.0.10:3000',
                allowedRoles: ['readonly'],
                enabled: true,
              },
            ],
          },
        })
      );

      // vpn_user rejected
      hoisted.sessionRef.current = makeSession('vpn_user');
      const vpnRes = await gatewayGet(
        new NextRequest(`http://localhost/api/auth/gateway?app_id=${appId}&roles=readonly`, {
          headers: { 'x-forwarded-host': 'grafana.corp.local' },
        })
      );
      expect(vpnRes.status).toBe(403);

      // Unknown app_id rejected EVEN when ?roles=readonly matches session role
      hoisted.sessionRef.current = makeSession('readonly');
      const wrongAppRes = await gatewayGet(
        new NextRequest(
          'http://localhost/api/auth/gateway?app_id=22222222-2222-4222-8222-222222222222&roles=readonly',
          { headers: { 'x-forwarded-host': 'grafana.corp.local' } }
        )
      );
      expect(wrongAppRes.status).toBe(403);

      // Host mismatch rejected
      const wrongHostRes = await gatewayGet(
        new NextRequest(`http://localhost/api/auth/gateway?app_id=${appId}&roles=readonly`, {
          headers: { 'x-forwarded-host': 'evil.corp.local' },
        })
      );
      expect(wrongHostRes.status).toBe(403);

      // Multi-value trailing-dot port X-Forwarded-Host normalized -> 200
      const okRes = await gatewayGet(
        new NextRequest(`http://localhost/api/auth/gateway?app_id=${appId}&roles=readonly`, {
          headers: { 'x-forwarded-host': 'Grafana.corp.local.:443, edge.proxy' },
        })
      );
      expect(okRes.status).toBe(200);
      expect(okRes.headers.get('X-Axonwall-User')).toBe('readonly');
      expect(okRes.headers.get('X-Remote-User')).toBe('readonly');
    });

    it('serializes concurrent logins against LOGIN_MAX_FAILURES and returns 429 fail-closed when lockout/invite maps hit global cap', async () => {
      // Concurrent brute-force against same username locks after 5 attempts
      const results = await Promise.all(
        Array.from({ length: 10 }, () => performAuthentication('race-victim', 'wrong-pass'))
      );
      const lockedCount = results.filter((r) =>
        r.error?.includes('Too many failed sign-in attempts')
      ).length;
      expect(lockedCount).toBeGreaterThanOrEqual(5);

      // Flood loginFailures map to cap (2000) -> 2001st distinct user fails closed with 429
      resetLoginFailuresForTests();
      for (let i = 0; i < 2000; i++) {
        await performAuthentication(`cap-user-${i}`, 'wrong');
      }
      const capHit = await performAuthentication('cap-user-overflow', 'wrong');
      expect(capHit.success).toBe(false);
      expect(capHit.statusCode).toBe(429);

      const login429 = await loginPost(
        new NextRequest('http://localhost/api/auth/login', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ username: 'cap-user-overflow-2', password: 'wrong' }),
        })
      );
      expect(login429.status).toBe(429);

      // Invite rate limit map cap (1000) fails closed (returns false -> 429)
      for (let i = 0; i < 1000; i++) {
        expect(checkInviteRateLimit(`198.51.100.${i % 250}:${i}`)).toBe(true);
      }
      expect(checkInviteRateLimit('203.0.113.99')).toBe(false);

      // resolveClientIp trusts forwarded headers ONLY for loopback peer or AXONWALL_TRUST_PROXY=1
      const req = new NextRequest('http://localhost/api/v1/vpn/mesh/invites/preview', {
        headers: { 'x-forwarded-for': '203.0.113.77', 'x-real-ip': '192.0.2.55' },
      });
      expect(resolveClientIp(req, '198.51.100.9')).toBe('198.51.100.9');
      expect(resolveClientIp(req, '127.0.0.1')).toBe('203.0.113.77');
    });

    it('rejects GET ?token= on invite preview with 405 and supports POST { token } with Cache-Control: no-store', async () => {
      seedState((s) =>
        DesiredStateSchema.parse({
          ...enablePluginWithDependencies('headscale', s).state,
          headscale: { ...s.headscale, enabled: true },
        })
      );
      const { rawToken } = await createHeadscaleInvite({
        username: 'previewuser',
        expiryHours: 12,
        createdBy: 'admin',
      });

      const getRes = await invitePreviewGet();
      expect(getRes.status).toBe(405);
      expect(getRes.headers.get('Allow')).toBe('POST');
      expect(getRes.headers.get('Cache-Control')).toBe('no-store');

      const postRes = await invitePreviewPost(
        new NextRequest('http://localhost/api/v1/vpn/mesh/invites/preview', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ token: rawToken }),
        })
      );
      expect(postRes.status).toBe(200);
      expect(postRes.headers.get('Cache-Control')).toBe('no-store');
      const json = await postRes.json();
      expect(json.data.status).toBe('valid');
      expect(json.data.username).toBe('previewuser');
    });

    it('hardens PCAP capture storage against /tmp and symlinks, and enforces assertActionPermitted in runLivePacketCapture', async () => {
      seedState((s) => enablePluginWithDependencies('packet-diagnostics', s).state);

      // Service token missing packet:capture scope is rejected
      hoisted.sessionRef.current = makeSession('admin', {
        userId: 'svc:ro',
        username: 'svc:ro',
        source: 'service_token',
        scopes: ['observability:read'],
      });
      await expect(runLivePacketCapture({ iface: 'any' })).rejects.toThrow(/Forbidden|Unauthorized/i);

      // Captures reside inside stateDir (never os.tmpdir()/tmp) and reject symlinks
      const capDir = path.join(stateDir, 'captures');
      fs.mkdirSync(capDir, { recursive: true, mode: 0o700 });
      const outside = path.join(root, 'outside-secret.pcap');
      fs.writeFileSync(outside, 'secret-pcap');
      const symlinkPath = path.join(capDir, 'evilcap.pcap');
      fs.symlinkSync(outside, symlinkPath);

      const lookupSym = getCaptureFile('evilcap');
      expect(lookupSym.exists).toBe(false);
      expect(lookupSym.filePath.startsWith(os.tmpdir() + '/axonwall-captures')).toBe(false);

      fs.writeFileSync(path.join(capDir, 'legitcap.pcap'), 'ok');
      const lookupLegit = getCaptureFile('legitcap');
      expect(lookupLegit.exists).toBe(true);
      expect(lookupLegit.filePath).toBe(path.join(fs.realpathSync(capDir), 'legitcap.pcap'));
    });

    it('enforces low-severity hardening across runNmapScan, getServiceJournalLogs, port_probe, assertActionPermitted, and middleware', async () => {
      seedState((s) => enablePluginWithDependencies('cli-diagnostics-nastymap', s).state);

      // Hyphenated IP octet ranges rejected
      const rangeRes = await runNmapScan({
        target: '192.168.1.1-254',
        profile: 'ping',
        simulated: true,
      });
      expect(rangeRes.success).toBe(false);
      expect(rangeRes.error).toMatch(/Invalid scan target/i);

      const rangeMidRes = await runNmapScan({
        target: '10.0-255.0.1',
        profile: 'ping',
        simulated: true,
      });
      expect(rangeMidRes.success).toBe(false);

      // Service journal logs restricted to managed appliance units
      await expect(getServiceJournalLogs('postgresql.service')).rejects.toThrow(/allowlist|Forbidden/i);
      const allowedLogs = await getServiceJournalLogs('axonwalld.service');
      expect(typeof allowedLogs).toBe('string');

      // port_probe blocks loopback, localhost, link-local IMDS, and metadata hosts
      hoisted.sessionRef.current = makeSession('admin', { username: 'diag-probe-tester' });
      for (const blockedTarget of ['127.0.0.1', 'localhost', '169.254.169.254', 'metadata.google.internal']) {
        const probeRes = await runDiagnostic('port_probe', blockedTarget, 80);
        expect(probeRes.success).toBe(false);
        expect(probeRes.output).toMatch(/blocked|disallowed/i);
      }
      hoisted.sessionRef.current = makeSession('admin');

      // assertActionPermitted blocks readonly reads while passwordChangeRequired is true
      const pwdPendingSession = makeSession('readonly', { passwordChangeRequired: true });
      expect(() => assertActionPermitted(pwdPendingSession, 'readonly')).toThrow(
        /Password change required/i
      );

      // Middleware fails closed 503 in production when JWT_SECRET is absent, and blocks non-auth GETs on pwd_change_required
      const mutableEnv = process.env as Record<string, string | undefined>;
      const prevNodeEnv = mutableEnv.NODE_ENV;
      const prevSecret = mutableEnv.JWT_SECRET;
      try {
        mutableEnv.NODE_ENV = 'production';
        delete mutableEnv.JWT_SECRET;
        const noSecretRes = await middleware(new NextRequest('https://localhost/api/v1/apply'));
        expect(noSecretRes.status).toBe(503);

        // Auth routes still reachable when JWT_SECRET missing check runs after /api/auth/ bypass
        const loginNextRes = await middleware(new NextRequest('https://localhost/api/auth/login'));
        expect(loginNextRes.status).toBe(200);

        mutableEnv.JWT_SECRET = prevSecret;
        const pwdToken = await mintSupabaseToken(
          makeSession('admin', { passwordChangeRequired: true }),
          prevSecret!
        );
        const getBlocked = await middleware(
          new NextRequest('https://localhost/api/v1/apply', {
            method: 'GET',
            headers: { cookie: `axonwall_session=${pwdToken}` },
          })
        );
        expect(getBlocked.status).toBe(403);
      } finally {
        mutableEnv.NODE_ENV = prevNodeEnv;
        if (prevSecret === undefined) delete mutableEnv.JWT_SECRET;
        else mutableEnv.JWT_SECRET = prevSecret;
      }
    });
  });
});
