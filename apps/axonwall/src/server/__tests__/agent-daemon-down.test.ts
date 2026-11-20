import { describe, it, expect, vi, beforeEach } from 'vitest';

// R4-C-H1 / R4-C-M2: daemon-down paths of the UI server actions must
// surface "daemon unavailable" explicitly — never a fabricated healthy
// node, and never an empty snapshot list standing in for "unknown".

const { mockCallAgentApi } = vi.hoisted(() => ({
  mockCallAgentApi: vi.fn(),
}));

vi.mock('../agent-client', () => ({
  callAgentApi: (...args: unknown[]) => mockCallAgentApi(...args),
  callAgentApiDetailed: vi.fn(),
  callAgentApiResponse: vi.fn(),
}));

// Admin session so the real assertActionPermitted passes. (NODE_ENV is
// 'test' under vitest, so isDevRuntime() is false and the production
// daemon-down branches are exercised, not the dev-mode demo fallbacks.)
vi.mock('../auth', () => ({
  getSession: vi.fn(async () => ({
    username: 'admin',
    displayName: 'admin',
    roles: ['admin'],
    privileges: ['*'],
    passwordChangeRequired: false,
    source: 'local_admin',
  })),
}));

import { getAgentStatus, getNasSnapshotsRuntime } from '../agent';

describe('getAgentStatus daemon-down (R4-C-H1)', () => {
  beforeEach(() => {
    mockCallAgentApi.mockReset();
  });

  it('reports daemonDown with UNKNOWN placeholders when the daemon does not answer', async () => {
    mockCallAgentApi.mockResolvedValue(null);

    const status = await getAgentStatus();

    expect(status.daemonDown).toBe(true);
    expect(status.version).toBe('UNKNOWN');
    expect(status.uptimeSeconds).toBe(0);
    expect(status.activeBundleHash).toBe('UNKNOWN');
    expect(status.pendingConfirm).toBe(false);
    expect(status.confirmDeadlineUnix).toBe(0);
    // No interfaces fabricated from os.networkInterfaces(): the host
    // has interfaces, but carrier state was never measured.
    expect(status.interfaces).toEqual([]);
  });

  it('returns live daemon data with daemonDown:false when the daemon answers', async () => {
    mockCallAgentApi.mockResolvedValue({
      node_id: 'axonwall-test',
      version: '0.12.2',
      uptime_seconds: 12345,
      active_bundle_hash: 'abc123',
      pending_confirm: true,
      confirm_deadline_unix: 999,
      interfaces: [
        { name: 'lan', device: 'eth0', is_up: true, ip_addresses: ['10.0.0.1/24'] },
      ],
    });

    const status = await getAgentStatus();

    expect(status.daemonDown).toBe(false);
    expect(status.version).toBe('0.12.2');
    expect(status.uptimeSeconds).toBe(12345);
    expect(status.activeBundleHash).toBe('abc123');
    expect(status.pendingConfirm).toBe(true);
    expect(status.confirmDeadlineUnix).toBe(999);
    expect(status.interfaces).toEqual([
      { name: 'lan', device: 'eth0', isUp: true, ipAddresses: ['10.0.0.1/24'] },
    ]);
  });

  it('does not stamp UI literals or host uptime onto a daemon answer missing those fields', async () => {
    mockCallAgentApi.mockResolvedValue({});

    const status = await getAgentStatus();

    expect(status.daemonDown).toBe(false);
    expect(status.version).toBe('UNKNOWN');
    expect(status.version).not.toBe('0.12.3');
    expect(status.activeBundleHash).toBe('UNKNOWN');
    expect(status.activeBundleHash).not.toBe('hash-active');
    // 0, not the UI host's os.uptime().
    expect(status.uptimeSeconds).toBe(0);
  });
});

describe('getNasSnapshotsRuntime daemon-down (R4-C-M2)', () => {
  beforeEach(() => {
    mockCallAgentApi.mockReset();
  });

  it('throws instead of returning an empty list when the daemon does not answer', async () => {
    mockCallAgentApi.mockResolvedValue(null);

    await expect(getNasSnapshotsRuntime()).rejects.toThrow(/Daemon unavailable/);
  });

  it('throws when the daemon answers without a snapshots array', async () => {
    mockCallAgentApi.mockResolvedValue({});

    await expect(getNasSnapshotsRuntime()).rejects.toThrow(/Daemon unavailable/);
  });

  it('returns the live snapshot list when the daemon answers', async () => {
    const snaps = [
      { dataset: 'tank/shares', name: 'pre-upgrade', createdAt: '2026-11-20T00:00:00Z', usedBytes: 1024 },
    ];
    mockCallAgentApi.mockResolvedValue({ snapshots: snaps });

    await expect(getNasSnapshotsRuntime()).resolves.toEqual(snaps);
  });
});
