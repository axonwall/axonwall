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
      displayName: 'Operator',
      roles: ['operator'],
      privileges: [],
      passwordChangeRequired: false,
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

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-topo-redact-'));
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
  callAgentApiDetailed: vi.fn(async () => ({ kind: 'daemon_down' })),
}));

import * as agentMod from '../agent';
import { invalidateDesiredStateCacheInternal, persistDesiredStateToDisk } from '../desired-state-internal';

afterAll(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

describe('Topology Studio peer token redaction & preservation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    hoisted.mockSessionState.current = {
      userId: 'op-1',
      username: 'ops',
      displayName: 'Operator',
      roles: ['operator'],
      privileges: [],
      passwordChangeRequired: false,
      source: 'local',
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
  });

  it('masks topology.peers[].apiToken for non-admin sessions and preserves on admin apply', async () => {
    const initial = DesiredStateSchema.parse({
      topology: {
        enabled: true,
        peers: [
          {
            id: 'vault-01',
            name: 'Vault Node',
            role: 'vault',
            apiUrl: 'https://10.20.0.50:2966',
            apiToken: 'vault-bearer-secret-xyz',
            enabled: true,
          },
        ],
      },
    });
    persistDesiredStateToDisk(initial);
    invalidateDesiredStateCacheInternal();

    const opView = await agentMod.getCurrentDesiredState();
    expect(opView.topology?.peers[0]?.apiToken).toBe('********');

    hoisted.mockSessionState.current = {
      userId: 'adm-1',
      username: 'admin',
      displayName: 'Admin',
      roles: ['admin'],
      privileges: ['*'],
      passwordChangeRequired: false,
      source: 'local',
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const edited = {
      ...opView,
      topology: {
        ...opView.topology!,
        lldp: { enabled: true, excludeWan: true, interfaces: ['eth1'] },
      },
    };
    await agentMod.applyDesiredState(edited);
    const applied = hoisted.mockRunPipeline.mock.calls[0]?.[0] as typeof initial;
    expect(applied.topology?.lldp.enabled).toBe(true);
    expect(applied.topology?.peers[0]?.apiToken).toBe('vault-bearer-secret-xyz');
  });
});
