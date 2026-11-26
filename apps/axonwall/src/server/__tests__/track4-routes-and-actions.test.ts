import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { DesiredStateSchema } from '@axonwall/lib/schemas';
import { enablePluginWithDependencies } from '@axonwall/lib/plugins';
import { DEFAULT_ROLES, type UserSession } from '@axonwall/lib/rbac';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-track4-routes-'));
const etcDir = path.join(root, 'etc');
const stateDir = path.join(root, 'var');
const persistDir = path.join(stateDir, 'etc-axonwall');
const gitopsDir = path.join(root, 'gitops');
for (const dir of [etcDir, stateDir, persistDir, gitopsDir]) {
  fs.mkdirSync(dir, { recursive: true });
}
process.env.AXONWALL_ETC_DIR = etcDir;
process.env.AXONWALL_STATE_DIR = stateDir;
process.env.AXONWALL_PERSIST_YAML_DIR = persistDir;
process.env.AXONWALL_STATE_JSON_PATH = path.join(stateDir, 'state.json');
process.env.GITOPS_DIR = gitopsDir;
process.env.FORCE_PASSWORD_CHANGE = 'false';

const hoisted = vi.hoisted(() => {
  const sessionRef: { current: UserSession | null } = { current: null };
  const callAgentApiMock = vi.fn(async () => null as any);
  const callAgentApiResponseMock = vi.fn(async () => ({ success: true, message: 'ok' }) as any);
  const callAgentApiDetailedMock = vi.fn(async () => ({ kind: 'ok', data: { success: true } }) as any);
  const callAgentApiBinaryMock = vi.fn(async () => ({ ok: true, status: 200, buffer: Buffer.from('ok') }) as any);
  const runPipelineMock = vi.fn(async (state: unknown) => ({
    success: true,
    message: 'Applied',
    nftScript: '',
    warnings: [],
    state,
  }));
  const queryVictoriaLogsMock = vi.fn(async (_query?: string) => ({
    configured: true,
    unavailable: false,
    status: 'ok' as const,
    entries: [],
  }));
  const fetchObservabilityNodesMock = vi.fn(async () => []);
  const headscaleState = {
    socketReady: true,
    machines: [{ id: '1', name: 'laptop', ipAddresses: ['100.64.0.2'], online: true }],
    keys: [
      {
        id: 'key-1',
        keyPreview: 'tskey-1',
        reusable: false,
        ephemeral: false,
        used: false,
        expired: false,
      },
    ],
  };

  return {
    root: '',
    etcDir: '',
    stateDir: '',
    persistDir: '',
    sessionRef,
    callAgentApiMock,
    callAgentApiResponseMock,
    callAgentApiDetailedMock,
    callAgentApiBinaryMock,
    runPipelineMock,
    queryVictoriaLogsMock,
    fetchObservabilityNodesMock,
    headscaleState,
  };
});
hoisted.root = root;
hoisted.etcDir = etcDir;
hoisted.stateDir = stateDir;
hoisted.persistDir = persistDir;

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: () => undefined,
    set: vi.fn(),
    delete: vi.fn(),
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
  callAgentApiBinary: hoisted.callAgentApiBinaryMock,
}));

vi.mock('../apply-state-internal', () => ({
  runDesiredStateApplyPipeline: hoisted.runPipelineMock,
}));

vi.mock('../observability-clients', () => ({
  queryVictoriaLogs: hoisted.queryVictoriaLogsMock,
  fetchObservabilityNodes: hoisted.fetchObservabilityNodesMock,
}));

vi.mock('../headscale', () => ({
  ensureUser: vi.fn(async () => {}),
  isHeadscaleSocketReady: vi.fn(() => hoisted.headscaleState.socketReady),
  listMachines: vi.fn(async () => hoisted.headscaleState.machines),
  listPreAuthKeys: vi.fn(async () => hoisted.headscaleState.keys),
  createPreAuthKey: vi.fn(async () => ({ id: 'k-new', key: 'tskey-new', keyPreview: 'tskey-ne...' })),
  expirePreAuthKey: vi.fn(async () => {}),
  assertPreAuthKeyOwnedByUser: vi.fn(async () => ({ id: 'key-1', key: 'tskey-1' })),
  assertMachineOwnedByUser: vi.fn(async () => ({ id: '1', name: 'laptop' })),
  renameMachine: vi.fn(async () => {}),
  expireMachine: vi.fn(async () => {}),
  deleteMachine: vi.fn(async () => {}),
  registerMachine: vi.fn(async () => ({ id: '2', name: 'new-node' })),
  resolveHeadscaleUsername: vi.fn((s: UserSession) => s.username),
  readHeadscaleConfigDefaults: vi.fn(() => ({ serverUrl: '', magicDnsDomain: 'tailnet.axonwall.local' })),
}));

import {
  applyDesiredState,
  getCurrentDesiredState,
  getLibreNmsTopologyAction,
  getReleaseInfo,
  getSystemPartitionsTelemetry,
  getThreatHarvesterStatus,
  runNmapScan,
} from '../agent';
import { invalidateDesiredStateCacheInternal, persistDesiredStateToDisk } from '../desired-state-internal';
import { blockFleetTargetAction, triggerFleetSyncAction } from '../fleet';
import { currentUserSessionEpoch } from '../session-revocation';
import { deleteLocalUser, updateLocalUser } from '../users';
import {
  getAttackGraphDataAction,
  getDeceptionMeshStatusAction,
  getPurpleTeamMatrixAction,
  listSecurityModulesAction,
} from '../vigilante';
import { GET as gatewayGet } from '../../app/api/auth/gateway/route';
import { POST as loginPost } from '../../app/api/auth/login/route';
import { GET as k3sLogsStreamGet } from '../../app/api/k3s/logs/stream/route';
import { POST as applyPost } from '../../app/api/v1/apply/route';
import { POST as metadataSyncPost } from '../../app/api/v1/netflow/metadata-sync/route';
import { GET as netflowMetricsGet } from '../../app/api/v1/netflow/metrics/route';
import { GET as netflowNodesGet } from '../../app/api/v1/netflow/nodes/route';
import { GET as netflowStreamGet } from '../../app/api/v1/netflow/stream/route';
import { POST as netflowTestInjectPost } from '../../app/api/v1/netflow/test-inject/route';
import { GET as logsQueryGet } from '../../app/api/v1/observability/logs/query/route';
import { GET as threatExportGet } from '../../app/api/v1/security/threat-harvester/export/route';
import { POST as librenmsSyncPost } from '../../app/api/v1/services/librenms/sync/route';
import { GET as librenmsTopologyGet } from '../../app/api/v1/services/librenms/topology/route';
import {
  GET as librenmsWebhookGet,
  POST as librenmsWebhookPost,
} from '../../app/api/v1/services/librenms/webhook/route';
import {
  GET as serviceTokensGet,
  POST as serviceTokensPost,
} from '../../app/api/v1/system/service-tokens/route';
import { POST as backupExportPost } from '../../app/api/system/backup/export/route';
import { GET as usersGet } from '../../app/api/system/users/route';
import { POST as selfDevicesPost } from '../../app/api/v1/vpn/mesh/self/devices/route';
import { POST as selfKeysPost } from '../../app/api/v1/vpn/mesh/self/keys/route';
import { POST as selfRegisterPost } from '../../app/api/v1/vpn/mesh/self/register/route';
import { GET as selfMeshGet } from '../../app/api/v1/vpn/mesh/self/route';

function makeSession(
  role: 'admin' | 'operator' | 'readonly' | 'vpn_user',
  overrides: Partial<UserSession> = {}
): UserSession {
  return {
    userId: `${role}-1`,
    username: `${role}-user`,
    displayName: `${role} user`,
    source: 'local',
    roles: [role],
    privileges: [...DEFAULT_ROLES[role].privileges],
    passwordChangeRequired: false,
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...overrides,
  };
}

function seedState(mutator?: (s: ReturnType<typeof DesiredStateSchema.parse>) => any) {
  let state = DesiredStateSchema.parse({
    version: 1,
    interfaces: [{ name: 'wan', device: 'eth0', role: 'wan', type: 'dhcp', enabled: true }],
  });
  if (mutator) {
    state = mutator(state);
  }
  persistDesiredStateToDisk(state);
  invalidateDesiredStateCacheInternal();
  return state;
}

afterAll(() => {
  fs.rmSync(hoisted.root, { recursive: true, force: true });
});

describe('Track 4 API Routes & Server Actions Hardening', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    hoisted.sessionRef.current = makeSession('admin');
    hoisted.headscaleState.socketReady = true;
    seedState();
  });

  describe('Secret redaction, unmasking & RBAC in agent.ts', () => {
    it('redacts portKnocking.sequence, metadataSync.apiToken, anonymizationSalt, and ddns customUpdateUrl for non-admins and preserves on admin apply', async () => {
      seedState((base) => {
        let s = enablePluginWithDependencies('netflow-collector', base).state;
        s = enablePluginWithDependencies('ebpf-threat-harvester', s).state;
        return DesiredStateSchema.parse({
          ...s,
          headscale: {
            ...s.headscale,
            enabled: true,
            wanInvite: {
              enabled: true,
              bindPort: 8443,
              autoWindow: true,
              requirePin: false,
              portKnocking: {
                enabled: true,
                protocol: 'udp',
                sequence: [41001, 42002, 43003],
                stepTimeoutSec: 10,
                openDurationSec: 60,
              },
            },
          },
          netflow: {
            ...s.netflow,
            enabled: true,
            selfExport: {
              enabled: true,
              targets: [],
              metadataSync: {
                enabled: true,
                target: 'netbox',
                apiUrl: 'https://netbox.internal',
                apiToken: 'nf-sync-secret',
              },
            },
          },
          threatHarvester: {
            ...s.threatHarvester,
            enabled: true,
            anonymizationSalt: 'harvester-salt-secret',
          },
          ddns: {
            enabled: true,
            entries: [
              {
                provider: 'custom',
                hostname: 'gw.example.com',
                apiToken: 'ddns-api-secret',
                customUpdateUrl: 'https://ddns.example.com/nic/update?token=supersecret',
              },
            ],
          },
        });
      });

      hoisted.sessionRef.current = makeSession('operator');
      const redacted = await getCurrentDesiredState();
      expect(redacted.headscale?.wanInvite?.portKnocking?.sequence).toEqual([]);
      expect(redacted.netflow?.selfExport?.metadataSync?.apiToken).toBe('********');
      expect(redacted.threatHarvester?.anonymizationSalt).toBe('********');
      expect(redacted.ddns?.entries?.[0]?.apiToken).toBe('********');
      expect(redacted.ddns?.entries?.[0]?.customUpdateUrl).toBe('********');

      hoisted.callAgentApiMock.mockResolvedValueOnce({
        daemonDown: false,
        config: {
          enabled: true,
          anonymizationSalt: 'harvester-salt-secret',
          teacherLlm: { enabled: false, apiKey: 'llm-secret' },
          fleetShipper: { enabled: false, secretKey: 'shipper-secret' },
        },
        bpfAttached: false,
        attachedInterfaces: [],
        activeHooks: [],
        excludedUprobeDaemons: [],
        stats: {
          packetsSeen: 0,
          tier0Events: 0,
          tier1PayloadEvents: 0,
          ringbufDrops: 0,
          darkPortHits: 0,
          memfdAlerts: 0,
          tlsUprobeEvents: 0,
        },
        timestamp: new Date().toISOString(),
      });
      const thStatus = await getThreatHarvesterStatus();
      expect(thStatus.config.anonymizationSalt).toBe('********');
      expect(thStatus.config.teacherLlm?.apiKey).toBe('********');

      // Switch to admin and apply with masked placeholders -> original secrets preserved.
      hoisted.sessionRef.current = makeSession('admin');
      await applyDesiredState(redacted);
      expect(hoisted.runPipelineMock).toHaveBeenCalledTimes(1);
      const passedState = hoisted.runPipelineMock.mock.calls[0]![0] as any;
      expect(passedState.headscale.wanInvite.portKnocking.sequence).toEqual([41001, 42002, 43003]);
      expect(passedState.netflow.selfExport.metadataSync.apiToken).toBe('nf-sync-secret');
      expect(passedState.threatHarvester.anonymizationSalt).toBe('harvester-salt-secret');
      expect(passedState.ddns.entries[0].apiToken).toBe('ddns-api-secret');
      expect(passedState.ddns.entries[0].customUpdateUrl).toBe(
        'https://ddns.example.com/nic/update?token=supersecret'
      );
    });

    it('blocks vpn_user on getReleaseInfo and getSystemPartitionsTelemetry, and reports live Nmap failures explicitly', async () => {
      hoisted.sessionRef.current = makeSession('vpn_user');
      await expect(getReleaseInfo(true)).rejects.toThrow(/Forbidden/);
      await expect(getSystemPartitionsTelemetry()).rejects.toThrow(/Forbidden/);

      hoisted.sessionRef.current = makeSession('admin');
      const prevPath = process.env.PATH;
      process.env.PATH = '';
      try {
        const scanRes = await runNmapScan({ target: '127.0.0.1', profile: 'ping', simulated: false });
        expect(scanRes.success).toBe(false);
        expect(scanRes.mode).toBe('live');
        expect(scanRes.error).toContain('nmap');
      } finally {
        process.env.PATH = prevPath;
      }
    });
  });

  describe('Users session epoch invalidation, Fleet client & Vigilante cleanup', () => {
    it('bumps per-user session epoch when local users are updated or deleted', async () => {
      const before = currentUserSessionEpoch('alice');
      await updateLocalUser('alice', { fullName: 'Alice Updated' } as any);
      const afterUpdate = currentUserSessionEpoch('alice');
      expect(afterUpdate).toBeGreaterThan(before);

      await deleteLocalUser('alice', false);
      const afterDelete = currentUserSessionEpoch('alice');
      expect(afterDelete).toBeGreaterThan(afterUpdate);
    });

    it('uses subdomain vigil and returns no hardcoded compromise fixtures in vigilante', async () => {
      const modules = await listSecurityModulesAction();
      const vigilSoc = modules.find((m) => m.id === 'vigil-soc');
      expect(vigilSoc?.subdomain).toBe('vigil');

      const graph = await getAttackGraphDataAction();
      expect(graph).toEqual({ nodes: [], edges: [], criticalPathsCount: 0 });
      const deception = await getDeceptionMeshStatusAction();
      expect(deception).toEqual({ canaries: [], activeHoneynetsCount: 0, isolatedAttackersCount: 0 });
      const matrix = await getPurpleTeamMatrixAction();
      expect(matrix).toEqual({ techniques: [], coveragePercent: 0, totalSimulations: 0 });
    });

    it('sends empty body on fleet sync, normalizes syncedSatellites, and sets isMac: true for MAC targets', async () => {
      const requests: Array<{ path: string; body: string; contentType?: string }> = [];
      const srv = http.createServer((req, res) => {
        let raw = '';
        req.on('data', (chunk) => {
          raw += chunk;
        });
        req.on('end', () => {
          requests.push({
            path: req.url || '',
            body: raw,
            contentType: req.headers['content-type'],
          });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          if (req.url === '/api/v1/fleet/sync') {
            res.end(JSON.stringify({ syncedSatellites: 3, message: 'Synced 3 satellites' }));
          } else {
            res.end(JSON.stringify({ blockedCount: 2, message: 'Blocked' }));
          }
        });
      });

      await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', () => resolve()));
      const addr = srv.address() as { port: number };
      const prevControllerUrl = process.env.CONTROLLER_URL;
      process.env.CONTROLLER_URL = `http://127.0.0.1:${addr.port}`;
      try {
        const syncRes = await triggerFleetSyncAction();
        expect(syncRes.reachable).toBe(true);
        expect(syncRes.data?.syncedSatellites).toBe(3);
        expect(syncRes.data?.syncedCount).toBe(3);

        const blockRes = await blockFleetTargetAction('aa:bb:cc:dd:ee:ff', 600, 'Quarantine');
        expect(blockRes.reachable).toBe(true);

        expect(requests).toHaveLength(2);
        expect(requests[0]).toEqual({ path: '/api/v1/fleet/sync', body: '', contentType: undefined });
        expect(JSON.parse(requests[1]!.body)).toEqual({
          target: 'aa:bb:cc:dd:ee:ff',
          isMac: true,
          ttlSeconds: 600,
          reason: 'Quarantine',
        });
      } finally {
        if (prevControllerUrl === undefined) delete process.env.CONTROLLER_URL;
        else process.env.CONTROLLER_URL = prevControllerUrl;
        await new Promise<void>((resolve) => srv.close(() => resolve()));
      }
    });
  });

  describe('API route security, validation, rate limits, self-mesh & plugin guards', () => {
    it('blocks scoped and wildcard service tokens from interactive, self-mesh, and gateway routes', async () => {
      hoisted.sessionRef.current = makeSession('admin', {
        userId: 'svc:token1',
        username: 'svc:token1',
        source: 'service_token',
        privileges: ['*'],
        scopes: ['*'],
      });

      const svcListRes = await serviceTokensGet();
      expect(svcListRes.status).toBe(403);

      const svcCreateRes = await serviceTokensPost(
        new NextRequest('http://localhost/api/v1/system/service-tokens', {
          method: 'POST',
          body: JSON.stringify({ name: 'test', scopes: ['observability:read'] }),
        })
      );
      expect(svcCreateRes.status).toBe(403);

      const gwRes = await gatewayGet(new NextRequest('http://localhost/api/auth/gateway'));
      expect(gwRes.status).toBe(403);

      const usersRes = await usersGet();
      expect(usersRes.status).toBe(403);

      const backupRes = await backupExportPost(
        new NextRequest('http://localhost/api/system/backup/export', { method: 'POST' })
      );
      expect(backupRes.status).toBe(403);

      const selfRes = await selfMeshGet(new NextRequest('http://localhost/api/v1/vpn/mesh/self'));
      expect(selfRes.status).toBe(403);
    });

    it('authenticates before JSON/Zod parsing on /api/v1/apply and returns 400 on malformed /api/auth/login input', async () => {
      hoisted.sessionRef.current = null;
      const unauthApplyRes = await applyPost(
        new Request('http://localhost/api/v1/apply', {
          method: 'POST',
          body: '{broken-json',
        })
      );
      expect(unauthApplyRes.status).toBe(401);

      const malformedLoginRes = await loginPost(
        new Request('http://localhost/api/auth/login', {
          method: 'POST',
          body: '{not-json',
        })
      );
      expect(malformedLoginRes.status).toBe(400);

      const badTypesLoginRes = await loginPost(
        new Request('http://localhost/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({ username: ['admin'], password: 42 }),
        })
      );
      expect(badTypesLoginRes.status).toBe(400);
    });

    it('prepends LogsQL metadata filters BEFORE rawQ and wraps head before pipes', async () => {
      const req = new NextRequest(
        'http://localhost/api/v1/observability/logs/query?nodeId=edge-1&source=nflog&level=warn&q=' +
          encodeURIComponent('drop OR allow | stats count()')
      );
      const res = await logsQueryGet(req);
      expect(res.status).toBe(200);
      expect(hoisted.queryVictoriaLogsMock).toHaveBeenCalledTimes(1);
      const passedQuery = hoisted.queryVictoriaLogsMock.mock.calls[0]![0];
      expect(passedQuery).toBe(
        'node_id:"edge-1" source:"nflog" level:"warn" (drop OR allow) | stats count()'
      );
    });

    it('strips wanInvite on /vpn/mesh/self and enforces network.enabled & allowSelfRegistration', async () => {
      hoisted.sessionRef.current = makeSession('vpn_user');

      seedState((s) =>
        DesiredStateSchema.parse({
          ...s,
          headscale: {
            enabled: false,
            allowSelfRegistration: false,
            wanInvite: {
              enabled: true,
              bindPort: 8443,
              autoWindow: true,
              requirePin: false,
              portKnocking: {
                enabled: true,
                protocol: 'udp',
                sequence: [41001, 42002],
                stepTimeoutSec: 10,
                openDurationSec: 60,
              },
            },
          },
        })
      );

      const selfDisabledRes = await selfMeshGet(new NextRequest('http://localhost/api/v1/vpn/mesh/self'));
      expect(selfDisabledRes.status).toBe(200);
      const selfBody = await selfDisabledRes.json();
      expect(selfBody.data.network.wanInvite).toBeUndefined();

      const keyDisabledRes = await selfKeysPost(
        new NextRequest('http://localhost/api/v1/vpn/mesh/self/keys', {
          method: 'POST',
          body: JSON.stringify({ action: 'create' }),
        })
      );
      expect(keyDisabledRes.status).toBe(403);

      const devDisabledRes = await selfDevicesPost(
        new NextRequest('http://localhost/api/v1/vpn/mesh/self/devices', {
          method: 'POST',
          body: JSON.stringify({ action: 'rename', machineId: '1', newName: 'lap2' }),
        })
      );
      expect(devDisabledRes.status).toBe(403);

      const regDisabledRes = await selfRegisterPost(
        new NextRequest('http://localhost/api/v1/vpn/mesh/self/register', {
          method: 'POST',
          body: JSON.stringify({ key: 'nodekey:abc' }),
        })
      );
      expect(regDisabledRes.status).toBe(403);

      // Enable Headscale but keep allowSelfRegistration false.
      seedState((s) =>
        DesiredStateSchema.parse({
          ...s,
          headscale: {
            enabled: true,
            allowSelfRegistration: false,
          },
        })
      );

      const keySelfRegOff = await selfKeysPost(
        new NextRequest('http://localhost/api/v1/vpn/mesh/self/keys', {
          method: 'POST',
          body: JSON.stringify({ action: 'create' }),
        })
      );
      expect(keySelfRegOff.status).toBe(403);

      const regSelfRegOff = await selfRegisterPost(
        new NextRequest('http://localhost/api/v1/vpn/mesh/self/register', {
          method: 'POST',
          body: JSON.stringify({ key: 'nodekey:abc' }),
        })
      );
      expect(regSelfRegOff.status).toBe(403);
    });

    it('enforces checkPluginApiGuard on all 7 newly guarded plugin routes', async () => {
      // Base seedState has optional plugins disabled.
      const thRes = await threatExportGet(
        new NextRequest('http://localhost/api/v1/security/threat-harvester/export')
      );
      expect(thRes.status).toBe(403);

      const nfNodesRes = await netflowNodesGet();
      expect(nfNodesRes.status).toBe(403);

      const nfMetricsRes = await netflowMetricsGet();
      expect(nfMetricsRes.status).toBe(403);

      const nfStreamRes = await netflowStreamGet(new NextRequest('http://localhost/api/v1/netflow/stream'));
      expect(nfStreamRes.status).toBe(403);

      const nfMetaRes = await metadataSyncPost(
        new NextRequest('http://localhost/api/v1/netflow/metadata-sync', {
          method: 'POST',
          body: JSON.stringify({ flows: [] }),
        })
      );
      expect(nfMetaRes.status).toBe(403);

      const lmsWebhookGet = await librenmsWebhookGet();
      expect(lmsWebhookGet.status).toBe(403);

      const lmsWebhookPost = await librenmsWebhookPost(
        new NextRequest('http://localhost/api/v1/services/librenms/webhook', {
          method: 'POST',
          headers: { 'x-axonwall-webhook-secret': 'wh-sec' },
          body: JSON.stringify({ event: 'alert' }),
        })
      );
      expect(lmsWebhookPost.status).toBe(403);

      const k3sRes = await k3sLogsStreamGet(new NextRequest('http://localhost/api/k3s/logs/stream'));
      expect(k3sRes.status).toBe(403);
    });

    it('maps Too Many Requests to HTTP 429 on sync/inject/apply routes and drops endpoint override on topology route', async () => {
      seedState((base) => {
        let s = enablePluginWithDependencies('librenms', base).state;
        s = enablePluginWithDependencies('netflow-collector', s).state;
        return DesiredStateSchema.parse({
          ...s,
          librenms: { enabled: true, endpoint: 'https://librenms.internal' },
        });
      });

      hoisted.callAgentApiDetailedMock.mockResolvedValue({ kind: 'ok', data: { nodes: [], links: [] } });
      await librenmsTopologyGet();
      expect(hoisted.callAgentApiDetailedMock).toHaveBeenCalledWith(
        '/v1/librenms/topology',
        'GET',
        undefined,
        10000
      );
      await expect(getLibreNmsTopologyAction('http://169.254.169.254')).rejects.toThrow(/Forbidden/);

      // Trigger real rate limit on LibreNMS sync (10/min).
      hoisted.sessionRef.current = makeSession('admin', { username: 'rate-limit-librenms' });
      for (let i = 0; i < 10; i++) {
        await librenmsSyncPost(
          new NextRequest('http://localhost/api/v1/services/librenms/sync', {
            method: 'POST',
            body: JSON.stringify({ dryRun: true }),
          })
        );
      }
      const sync429 = await librenmsSyncPost(
        new NextRequest('http://localhost/api/v1/services/librenms/sync', {
          method: 'POST',
          body: JSON.stringify({ dryRun: true }),
        })
      );
      expect(sync429.status).toBe(429);

      // Trigger real rate limit on NetFlow test-inject (15/min).
      hoisted.sessionRef.current = makeSession('admin', { username: 'rate-limit-netflow' });
      for (let i = 0; i < 15; i++) {
        await netflowTestInjectPost(
          new NextRequest('http://localhost/api/v1/netflow/test-inject', {
            method: 'POST',
            body: JSON.stringify({ protocol: 'ipfix', count: 1 }),
          })
        );
      }
      const inject429 = await netflowTestInjectPost(
        new NextRequest('http://localhost/api/v1/netflow/test-inject', {
          method: 'POST',
          body: JSON.stringify({ protocol: 'ipfix', count: 1 }),
        })
      );
      expect(inject429.status).toBe(429);
    });
  });
});
