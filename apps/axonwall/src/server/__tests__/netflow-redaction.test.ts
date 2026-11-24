import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { DesiredStateSchema } from '@axonwall/lib/schemas';
import { buildTcpdumpFilter } from '@axonwall/lib/compile/netflow';
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

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-nf-redact-'));
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

describe('NetFlow ClickHouse & webhook secret redaction & preservation', () => {
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

  it('masks netflow ClickHouse password and rule webhookUrl for non-admin sessions and preserves on admin apply', async () => {
    const initial = DesiredStateSchema.parse({
      netflow: {
        enabled: true,
        storage: {
          mode: 'hybrid',
          clickhouse: {
            enabled: true,
            url: 'http://127.0.0.1:8123',
            database: 'axonwall',
            username: 'admin',
            password: 'super-secret-ch-password',
          },
        },
        reporting: {
          enabled: true,
          webhookUrl: 'https://hooks.example.com/reports/secret-rpt',
        },
        enrichment: {
          geoipCityDownloadUrl: 'https://download.maxmind.com/app/geoip_download?license_key=secret-key-city',
          geoipAsnDownloadUrl: 'https://download.maxmind.com/app/geoip_download?license_key=secret-key-asn',
        },
        alerting: {
          enabled: true,
          rules: [
            {
              id: 'r1',
              name: 'Scan Webhook',
              enabled: true,
              kind: 'port_scan',
              threshold: 25,
              actions: ['webhook'],
              webhookUrl: 'https://hooks.example.com/secret/token-abc',
            },
          ],
        },
      },
    });
    persistDesiredStateToDisk(initial);
    invalidateDesiredStateCacheInternal();

    const opView = await agentMod.getCurrentDesiredState();
    expect(opView.netflow?.storage.clickhouse.password).toBe('********');
    expect(opView.netflow?.reporting.webhookUrl).toBe('********');
    expect(opView.netflow?.enrichment.geoipCityDownloadUrl).toBe('********');
    expect(opView.netflow?.enrichment.geoipAsnDownloadUrl).toBe('********');
    expect(opView.netflow?.alerting.rules[0]?.webhookUrl).toBe('********');

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
      netflow: {
        ...opView.netflow!,
        storage: { ...opView.netflow!.storage, retentionHours: 336 },
      },
    };
    await agentMod.applyDesiredState(edited);
    const applied = hoisted.mockRunPipeline.mock.calls[0]?.[0] as typeof initial;
    expect(applied.netflow?.storage.retentionHours).toBe(336);
    expect(applied.netflow?.storage.clickhouse.password).toBe('super-secret-ch-password');
    expect(applied.netflow?.reporting.webhookUrl).toBe('https://hooks.example.com/reports/secret-rpt');
    expect(applied.netflow?.enrichment.geoipCityDownloadUrl).toBe(
      'https://download.maxmind.com/app/geoip_download?license_key=secret-key-city',
    );
    expect(applied.netflow?.enrichment.geoipAsnDownloadUrl).toBe(
      'https://download.maxmind.com/app/geoip_download?license_key=secret-key-asn',
    );
    expect(applied.netflow?.alerting.rules[0]?.webhookUrl).toBe('https://hooks.example.com/secret/token-abc');
  });

  it('builds safe tcpdump BPF filters for IPv4, IPv6, and ICMP flow pivots', () => {
    expect(
      buildTcpdumpFilter({
        id: '1',
        timestamp: '2026-11-23T00:00:00Z',
        version: 'ipfix',
        exporterIp: '10.80.0.1',
        srcIp: '2001:db8::1',
        dstIp: '2001:db8::2',
        srcPort: 50000,
        dstPort: 443,
        protocol: 6,
        protocolName: 'TCP',
        bytes: 1000,
        packets: 10,
        bps: 8000,
      }),
    ).toBe('tcp and host 2001:db8::1 and host 2001:db8::2 and port 443');

    expect(
      buildTcpdumpFilter({
        id: '2',
        timestamp: '2026-11-23T00:00:00Z',
        version: 'netflow5',
        exporterIp: '10.80.0.1',
        srcIp: '10.80.0.5',
        dstIp: '1.1.1.1',
        srcPort: 0,
        dstPort: 0,
        protocol: 1,
        protocolName: 'ICMP',
        bytes: 84,
        packets: 1,
        bps: 672,
      }),
    ).toBe('icmp and host 10.80.0.5 and host 1.1.1.1');
  });
});
