import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { DesiredStateSchema } from '@axonwall/lib/schemas';
import type { UserSession } from '@axonwall/lib/rbac';

const hoisted = vi.hoisted(() => {
  const mockSessionState: { current: UserSession | null } = {
    current: {
      userId: 'op-1',
      username: 'ops',
      roles: ['operator'],
      privileges: [],
      source: 'local',
      exp: Math.floor(Date.now() / 1000) + 3600,
    },
  };
  return {
    mockSessionState,
    mockRunPipeline: vi.fn(async (state: unknown) => ({
      success: true,
      message: 'ok',
      nftScript: '',
      warnings: [],
      state,
    })),
  };
});

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-obs-redact-'));
const etcDir = path.join(root, 'etc');
const stateDir = path.join(root, 'var');
const persistDir = path.join(stateDir, 'etc-axonwall');
for (const d of [etcDir, stateDir, persistDir]) {
  fs.mkdirSync(d, { recursive: true });
}
process.env.AXONWALL_ETC_DIR = etcDir;
process.env.AXONWALL_STATE_DIR = stateDir;
process.env.AXONWALL_PERSIST_YAML_DIR = persistDir;
process.env.AXONWALL_STATE_JSON_PATH = path.join(stateDir, 'state.json');

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({ get: () => undefined, set: vi.fn(), delete: vi.fn() })),
  headers: vi.fn(async () => new Headers()),
}));

vi.mock('next/navigation', () => ({
  redirect: vi.fn((url: string) => {
    throw new Error(`NEXT_REDIRECT:${url}`);
  }),
}));

vi.mock('../auth', () => ({
  getSession: vi.fn(async () => hoisted.mockSessionState.current),
}));

vi.mock('../apply-state-internal', () => ({
  runDesiredStateApplyPipeline: hoisted.mockRunPipeline,
}));

vi.mock('../agent-client', () => ({
  clearCachedAgentToken: vi.fn(),
  getAgentToken: vi.fn(() => 'test-token'),
  isApplianceRuntime: vi.fn(() => true),
  callAgentApi: vi.fn(async () => null),
  callAgentApiResponse: vi.fn(async () => ({ success: true, message: 'ok' })),
  callAgentApiDetailed: vi.fn(async () => ({ kind: 'unreachable' })),
}));

import * as agentMod from '../agent';
import { invalidateDesiredStateCacheInternal, persistDesiredStateToDisk } from '../desired-state-internal';

afterAll(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

describe('Observability offload & SNMPv3 secret redaction/unmasking', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    hoisted.mockSessionState.current = {
      userId: 'op-1',
      username: 'ops',
      roles: ['operator'],
      privileges: [],
      source: 'local',
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
  });

  it('masks VM/VL bearer tokens, offload tokens, and SNMPv3 passwords and restores on apply', async () => {
    const initial = DesiredStateSchema.parse({
      observability: {
        victoriaMetrics: { enabled: true, url: 'https://hub.internal/vm', bearerToken: 'vm-secret-123' },
        victoriaLogs: { enabled: true, url: 'https://hub.internal/vl', bearerToken: 'vl-secret-456' },
        offload: {
          enabled: true,
          hubUrl: 'https://hub.internal',
          ingestToken: 'axw_svc_edge_ingest_secret',
          metrics: { enabled: true, exposeScrape: true, scrapeToken: 'scrape-secret-789' },
        },
      },
      snmp: {
        enabled: true,
        version: 'v3',
        v3Users: [
          {
            username: 'monv3',
            authProtocol: 'SHA-256',
            authPassword: 'auth-password-secret',
            privProtocol: 'AES',
            privPassword: 'priv-password-secret',
            securityLevel: 'authPriv',
          },
        ],
      },
    });
    invalidateDesiredStateCacheInternal();
    persistDesiredStateToDisk(initial);

    const view = await agentMod.getCurrentDesiredState();
    expect(view.observability?.victoriaMetrics?.bearerToken).toBe('********');
    expect(view.observability?.victoriaLogs?.bearerToken).toBe('********');
    expect(view.observability?.offload?.ingestToken).toBe('********');
    expect(view.observability?.offload?.metrics?.scrapeToken).toBe('********');
    expect(view.snmp?.v3Users?.[0]?.authPassword).toBe('********');
    expect(view.snmp?.v3Users?.[0]?.privPassword).toBe('********');

    hoisted.mockSessionState.current = {
      userId: 'admin-1',
      username: 'admin',
      roles: ['admin'],
      privileges: ['*'],
      source: 'local_admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
    await agentMod.applyDesiredState(view, 60);
    expect(hoisted.mockRunPipeline).toHaveBeenCalledTimes(1);
    const savedState = hoisted.mockRunPipeline.mock.calls[0][0] as typeof initial;
    expect(savedState.observability?.victoriaMetrics?.bearerToken).toBe('vm-secret-123');
    expect(savedState.observability?.victoriaLogs?.bearerToken).toBe('vl-secret-456');
    expect(savedState.observability?.offload?.ingestToken).toBe('axw_svc_edge_ingest_secret');
    expect(savedState.observability?.offload?.metrics?.scrapeToken).toBe('scrape-secret-789');
    expect(savedState.snmp?.v3Users?.[0]?.authPassword).toBe('auth-password-secret');
    expect(savedState.snmp?.v3Users?.[0]?.privPassword).toBe('priv-password-secret');
  });
});
