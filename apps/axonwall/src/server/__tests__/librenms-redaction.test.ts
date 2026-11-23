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

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-librenms-redact-'));
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

describe('LibreNMS secret redaction & preservation', () => {
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

  it('masks all LibreNMS secrets and SNMP credentials for non-admin sessions and preserves on admin apply', async () => {
    const initial = DesiredStateSchema.parse({
      librenms: {
        enabled: true,
        mode: 'k3s',
        domain: 'librenms.axonwall.local',
        apiToken: 'lnms-api-secret-token',
        webhookSecret: 'lnms-webhook-secret-99',
        adminPassword: 'lnms-admin-password',
        snmpDefaults: {
          version: 'v3',
          community: 'private-community',
          v3AuthUser: 'snmpv3user',
          v3AuthPass: 'v3-auth-secret',
          v3CryptoPass: 'v3-priv-secret',
        },
      },
    });
    persistDesiredStateToDisk(initial);
    invalidateDesiredStateCacheInternal();

    const opView = await agentMod.getCurrentDesiredState();
    expect(opView.librenms?.apiToken).toBe('********');
    expect(opView.librenms?.webhookSecret).toBe('********');
    expect(opView.librenms?.adminPassword).toBe('********');
    expect(opView.librenms?.snmpDefaults?.community).toBe('********');
    expect(opView.librenms?.snmpDefaults?.v3AuthPass).toBe('********');
    expect(opView.librenms?.snmpDefaults?.v3CryptoPass).toBe('********');

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

    const editedWithMasks = {
      ...opView,
      librenms: {
        ...opView.librenms!,
        domain: 'nms2.axonwall.local',
      },
    };
    await agentMod.applyDesiredState(editedWithMasks);
    const appliedArg = hoisted.mockRunPipeline.mock.calls[0]?.[0] as {
      librenms?: {
        domain?: string;
        apiToken?: string;
        webhookSecret?: string;
        adminPassword?: string;
        snmpDefaults?: { community?: string; v3AuthPass?: string; v3CryptoPass?: string };
      };
    };
    expect(appliedArg?.librenms?.domain).toBe('nms2.axonwall.local');
    expect(appliedArg?.librenms?.apiToken).toBe('lnms-api-secret-token');
    expect(appliedArg?.librenms?.webhookSecret).toBe('lnms-webhook-secret-99');
    expect(appliedArg?.librenms?.adminPassword).toBe('lnms-admin-password');
    expect(appliedArg?.librenms?.snmpDefaults?.community).toBe('private-community');
    expect(appliedArg?.librenms?.snmpDefaults?.v3AuthPass).toBe('v3-auth-secret');
    expect(appliedArg?.librenms?.snmpDefaults?.v3CryptoPass).toBe('v3-priv-secret');
  });
});
