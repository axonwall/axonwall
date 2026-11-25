import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { DesiredStateSchema } from '@axonwall/lib/schemas';

const hoisted = vi.hoisted(() => ({
  mockCallAgentApi: vi.fn(),
  mockCallAgentApiDetailed: vi.fn(),
  mockCallAgentApiResponse: vi.fn(),
  mockSession: {
    userId: 'admin-1',
    username: 'admin',
    displayName: 'Admin',
    roles: ['admin'],
    privileges: ['*'],
    passwordChangeRequired: false,
    source: 'local_admin' as const,
    exp: Math.floor(Date.now() / 1000) + 3600,
  },
}));

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-iface-confirm-'));
const etcDir = path.join(root, 'etc');
const stateDir = path.join(root, 'var');
const persistDir = path.join(stateDir, 'etc-axonwall');
const fakeBinDir = path.join(root, 'bin');
for (const d of [etcDir, stateDir, persistDir, fakeBinDir]) {
  fs.mkdirSync(d, { recursive: true });
}

const fakeIpJsonFile = path.join(root, 'live-ip.json');
fs.writeFileSync(fakeIpJsonFile, '[]', 'utf8');
fs.writeFileSync(
  path.join(fakeBinDir, 'ip'),
  `#!/bin/sh\nif [ "$1" = "-j" ] && [ "$2" = "-4" ] && [ "$3" = "addr" ] && [ "$4" = "show" ]; then cat "${fakeIpJsonFile}"; fi\nexit 0\n`,
  { mode: 0o755 }
);

const origPath = process.env.PATH || '';
process.env.PATH = `${fakeBinDir}:${origPath}`;
process.env.AXONWALL_ETC_DIR = etcDir;
process.env.AXONWALL_STATE_DIR = stateDir;
process.env.AXONWALL_PERSIST_YAML_DIR = persistDir;
process.env.AXONWALL_STATE_JSON_PATH = path.join(stateDir, 'state.json');
process.env.JWT_SECRET =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

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

vi.mock('../agent-client', () => ({
  clearCachedAgentToken: vi.fn(),
  getAgentToken: vi.fn(() => 'test-token'),
  callAgentApi: (...args: unknown[]) => hoisted.mockCallAgentApi(...args),
  callAgentApiResponse: (...args: unknown[]) => hoisted.mockCallAgentApiResponse(...args),
  callAgentApiDetailed: (...args: unknown[]) => hoisted.mockCallAgentApiDetailed(...args),
}));

vi.mock('../auth', async () => {
  const actual = await vi.importActual<typeof import('../auth')>('../auth');
  return {
    ...actual,
    getSession: vi.fn(async () => hoisted.mockSession),
  };
});

const {
  controlSystemService,
  saveInterfaceAssignment,
  deleteInterfaceAssignment,
} = await import('../agent');
const { getLastPendingJobId, runDesiredStateApplyPipeline } = await import('../apply-state-internal');
const {
  buildNetworkInterfacesFilesContent,
  findOverlappingSubnet,
  getDesiredStateInternal,
  invalidateDesiredStateCacheInternal,
  persistDesiredStateToDisk,
  snapshotDesiredStateOnDisk,
} = await import('../desired-state-internal');
const { registerWireGuardPeerInternal } = await import('../wg-internal');

const seedCheckpointBaseline = () => {
  const base = DesiredStateSchema.parse({
    version: 1,
    interfaces: [
      { name: 'wan', role: 'wan', device: 'enp3s0', type: 'dhcp', enabled: true },
      { name: 'lan', role: 'lan', device: 'enp5s0', type: 'static', ipv4Address: '10.60.0.1/24', dhcpServer: true, enabled: true },
      { name: 'opt1', role: 'lan', device: 'enp7s0', type: 'dhcp', dhcpServer: false, enabled: true },
      { name: 'opt2', role: 'lan', device: 'enp9s0', type: 'dhcp', dhcpServer: false, enabled: true },
    ],
    system: { hostname: 'ckpt', domain: 'local', dnsServers: ['1.1.1.1'] },
  });
  persistDesiredStateToDisk(base);
  invalidateDesiredStateCacheInternal();
  return base;
};

afterAll(() => {
  process.env.PATH = origPath;
  fs.rmSync(root, { recursive: true, force: true });
});

beforeEach(() => {
  hoisted.mockCallAgentApi.mockReset();
  hoisted.mockCallAgentApiDetailed.mockReset();
  hoisted.mockCallAgentApiResponse.mockReset();
  fs.writeFileSync(fakeIpJsonFile, '[]', 'utf8');
  seedCheckpointBaseline();
});

describe('Interface Commit-Confirm & Lockout Prevention', () => {
  it('saveInterfaceAssignment sends /v1/apply with 120s timeout, NEVER auto-confirms, and does not overwrite disk before /v1/apply', async () => {
    const preYaml = fs.readFileSync(path.join(etcDir, 'interfaces.yaml'), 'utf8');
    const preConf = fs.readFileSync(path.join(etcDir, 'interfaces.conf'), 'utf8');
    let diskYamlDuringApply = '';
    let diskConfDuringApply = '';

    hoisted.mockCallAgentApiDetailed.mockImplementation(async (endpoint: string) => {
      if (endpoint === '/v1/apply') {
        diskYamlDuringApply = fs.readFileSync(path.join(etcDir, 'interfaces.yaml'), 'utf8');
        diskConfDuringApply = fs.readFileSync(path.join(etcDir, 'interfaces.conf'), 'utf8');
        return { kind: 'ok', data: { success: true, message: 'Applied pending confirm' } };
      }
      throw new Error(`Unexpected call to ${endpoint}`);
    });

    const res = await saveInterfaceAssignment({
      name: 'opt3',
      role: 'lan',
      device: 'enp4s0',
      enabled: true,
      type: 'static',
      ipv4Address: '10.70.0.1/24',
      dhcpServer: false,
    });

    expect(res.success).toBe(true);
    expect(res.pendingConfirm).toBe(true);
    expect(res.jobId).toMatch(/^iface-/);
    expect(hoisted.mockCallAgentApiDetailed).toHaveBeenCalledTimes(1);
    expect(hoisted.mockCallAgentApiDetailed.mock.calls[0]?.[0]).toBe('/v1/apply');
    expect(hoisted.mockCallAgentApiDetailed.mock.calls[0]?.[2]?.confirm_timeout_seconds).toBe(120);
    // Must NEVER call /v1/confirm
    const endpoints = hoisted.mockCallAgentApiDetailed.mock.calls.map((c) => c[0]);
    expect(endpoints).not.toContain('/v1/confirm');
    // Disk files were untouched before /v1/apply was invoked (LKG remains clean for axonwalld)
    expect(diskYamlDuringApply).toBe(preYaml);
    expect(diskConfDuringApply).toBe(preConf);
    // Pending job ID retained for header confirm button
    expect(getLastPendingJobId()).toBe(res.jobId);
  });

  it('deleteInterfaceAssignment sends /v1/apply, NEVER auto-confirms, and does not overwrite disk before /v1/apply', async () => {
    const preYaml = fs.readFileSync(path.join(etcDir, 'interfaces.yaml'), 'utf8');
    let diskYamlDuringApply = '';

    hoisted.mockCallAgentApiDetailed.mockImplementation(async (endpoint: string) => {
      if (endpoint === '/v1/apply') {
        diskYamlDuringApply = fs.readFileSync(path.join(etcDir, 'interfaces.yaml'), 'utf8');
        return { kind: 'ok', data: { success: true, message: 'Applied pending confirm' } };
      }
      throw new Error(`Unexpected call to ${endpoint}`);
    });

    const res = await deleteInterfaceAssignment('opt2');
    expect(res.success).toBe(true);
    expect(res.pendingConfirm).toBe(true);
    expect(res.jobId).toMatch(/^iface-del-/);
    expect(hoisted.mockCallAgentApiDetailed).toHaveBeenCalledTimes(1);
    expect(hoisted.mockCallAgentApiDetailed.mock.calls.map((c) => c[0])).toEqual(['/v1/apply']);
    expect(diskYamlDuringApply).toBe(preYaml);
  });

  it('runDesiredStateApplyPipeline does not overwrite disk before /v1/apply and leaves disk untouched on rejection', async () => {
    const base = seedCheckpointBaseline();
    const preYaml = fs.readFileSync(path.join(etcDir, 'interfaces.yaml'), 'utf8');
    const preConf = fs.readFileSync(path.join(etcDir, 'interfaces.conf'), 'utf8');

    const modified = DesiredStateSchema.parse({
      ...base,
      interfaces: [
        ...base.interfaces,
        { name: 'opt3', role: 'lan', device: 'enp4s0', type: 'static', ipv4Address: '10.80.0.1/24', enabled: true },
      ],
    });

    let sawPreYaml = '';
    hoisted.mockCallAgentApiDetailed.mockImplementationOnce(async () => {
      sawPreYaml = fs.readFileSync(path.join(etcDir, 'interfaces.yaml'), 'utf8');
      return { kind: 'ok', data: { success: false, message: 'rejected by daemon' } };
    });

    await expect(runDesiredStateApplyPipeline(modified, 120)).rejects.toThrow(/rejected by daemon/);
    expect(sawPreYaml).toBe(preYaml);
    expect(fs.readFileSync(path.join(etcDir, 'interfaces.yaml'), 'utf8')).toBe(preYaml);
    expect(fs.readFileSync(path.join(etcDir, 'interfaces.conf'), 'utf8')).toBe(preConf);
  });

  it('saveInterfaceAssignment & findOverlappingSubnet block assigning static IP overlapping live DHCP OPT1 (enp7s0) or WAN', async () => {
    fs.writeFileSync(
      fakeIpJsonFile,
      JSON.stringify([
        {
          ifname: 'enp3s0',
          addr_info: [{ family: 'inet', local: '38.57.161.161', prefixlen: 24, scope: 'global', dynamic: true }],
        },
        {
          ifname: 'enp7s0',
          addr_info: [{ family: 'inet', local: '192.168.10.237', prefixlen: 24, scope: 'global', dynamic: true }],
        },
      ]),
      'utf8'
    );

    // Real Check Point reproduction: assigning 192.168.10.50/24 on enp4s0 while OPT1 (enp7s0) has live DHCP 192.168.10.237/24
    await expect(
      saveInterfaceAssignment({
        name: 'opt3',
        role: 'lan',
        device: 'enp4s0',
        enabled: true,
        type: 'static',
        ipv4Address: '192.168.10.50/24',
        dhcpServer: false,
      })
    ).rejects.toThrow(/192\.168\.10\.237\/24.*competing kernel route/i);
    expect(hoisted.mockCallAgentApiDetailed).not.toHaveBeenCalled();

    // Pure helper checks: WAN overlap, self-edit allowed, non-overlapping allowed
    const base = seedCheckpointBaseline();
    const live = [
      { device: 'enp3s0', cidr: '38.57.161.161/24' },
      { device: 'enp7s0', cidr: '192.168.10.237/24' },
    ];
    expect(findOverlappingSubnet('38.57.161.10/24', base.interfaces, live, { excludeNames: ['opt3'], excludeDevices: ['enp4s0'] })).not.toBeNull();
    expect(findOverlappingSubnet('192.168.10.50/24', base.interfaces, live, { excludeNames: ['opt1'], excludeDevices: ['enp7s0'] })).toBeNull();
    expect(findOverlappingSubnet('10.70.0.1/24', base.interfaces, live, { excludeNames: ['opt3'], excludeDevices: ['enp4s0'] })).toBeNull();
  });

  it('buildNetworkInterfacesFilesContent omits gateway on static LAN while preserving gateway on static WAN', () => {
    const state = DesiredStateSchema.parse({
      version: 1,
      interfaces: [
        {
          name: 'wan',
          role: 'wan',
          device: 'enp3s0',
          type: 'static',
          ipv4Address: '38.57.161.161/24',
          ipv4Gateway: '38.57.161.1',
          enabled: true,
        },
        {
          name: 'lan',
          role: 'lan',
          device: 'enp5s0',
          type: 'static',
          ipv4Address: '10.60.0.1/24',
          ipv4Gateway: '10.60.0.254',
          enabled: true,
        },
      ],
    });
    const { ifacesContent, confContent } = buildNetworkInterfacesFilesContent(state);
    expect(ifacesContent).toContain('iface enp3s0 inet static\n    address 38.57.161.161\n    netmask 255.255.255.0\n    gateway 38.57.161.1\n');
    expect(ifacesContent).toContain('iface enp5s0 inet static\n    address 10.60.0.1\n    netmask 255.255.255.0\n');
    expect(ifacesContent).not.toContain('gateway 10.60.0.254');
    expect(confContent).toContain('IFACE_WAN_IPV4_GATEWAY=38.57.161.1\n');
    expect(confContent).toContain('IFACE_LAN_IPV4_GATEWAY=\n');
  });

  it('getDesiredStateInternal refuses to overwrite existing YAML configs with factory defaults on parse failure', async () => {
    const preInterfacesYaml = fs.readFileSync(path.join(etcDir, 'interfaces.yaml'), 'utf8');
    // Corrupt firewall.yaml and ensure fallback state.json cannot rescue it
    for (const p of [
      path.join(etcDir, 'firewall.yaml'),
      path.join(persistDir, 'firewall.yaml'),
    ]) {
      fs.writeFileSync(p, 'rules: [ { broken: {{{yaml\n', 'utf8');
    }
    for (const jp of [
      path.join(stateDir, 'state.json'),
      path.join(etcDir, 'state.json'),
      path.join(persistDir, 'state.json'),
    ]) {
      fs.rmSync(jp, { force: true });
    }
    invalidateDesiredStateCacheInternal();

    await expect(getDesiredStateInternal()).rejects.toThrow(
      /Refusing to overwrite existing Axonwall configuration with factory defaults/i
    );
    // Existing valid interfaces.yaml on disk was NOT clobbered with factory baseline
    expect(fs.readFileSync(path.join(etcDir, 'interfaces.yaml'), 'utf8')).toBe(preInterfacesYaml);
  });

  it('snapshotDesiredStateOnDisk never marks an unreadable existing file as existed: false', () => {
    const targetPath = path.join(etcDir, 'firewall.yaml');
    const origReadFileSync = fs.readFileSync;
    const spy = vi.spyOn(fs, 'readFileSync').mockImplementation((p: any, ...rest: any[]) => {
      if (String(p) === targetPath) {
        const e: any = new Error('EACCES: permission denied');
        e.code = 'EACCES';
        throw e;
      }
      return (origReadFileSync as any)(p, ...rest);
    });
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const snap = snapshotDesiredStateOnDisk();
      const entry = snap.find((e) => e.path === targetPath);
      expect(entry).toBeUndefined();
    } finally {
      spy.mockRestore();
      warnSpy.mockRestore();
    }
  });

  it('controlSystemService refuses stopping critical control-plane services and self-restarting axonwall-ui', async () => {
    for (const unit of [
      'axonwalld.service',
      'axonwall-ui.service',
      'axonwall-controller.service',
      'ssh.service',
      'sshd.service',
    ]) {
      const res = await controlSystemService(unit, 'stop');
      expect(res.success).toBe(false);
      expect(res.message).toMatch(/Refusing to stop critical control-plane unit/i);
    }
    const selfRestart = await controlSystemService('axonwall-ui.service', 'restart');
    expect(selfRestart.success).toBe(false);
    expect(selfRestart.message).toMatch(/Refusing to restart/i);
  });

  it('registerWireGuardPeerInternal refuses disabled WireGuard and NEVER calls /v1/confirm over localhost', async () => {
    await expect(
      registerWireGuardPeerInternal({
        newPeer: {
          name: 'portal-admin',
          publicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
          allowedIps: ['10.99.0.2/32'],
          persistentKeepalive: 25,
          enabled: true,
        },
        actorUsername: 'admin',
      })
    ).rejects.toThrow(/WireGuard server is disabled/i);

    // Enable WireGuard cleanly with a test private key and verify commit-confirm is returned pending
    const crypto = await import('node:crypto');
    const { privateKey: privObj } = crypto.generateKeyPairSync('x25519');
    const privB64 = privObj.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64');
    const wgEnabledState = DesiredStateSchema.parse({
      version: 1,
      interfaces: [
        { name: 'wan', role: 'wan', device: 'enp3s0', type: 'dhcp', enabled: true },
        { name: 'lan', role: 'lan', device: 'enp5s0', type: 'static', ipv4Address: '10.60.0.1/24', dhcpServer: true, enabled: true },
      ],
      wireguard: {
        enabled: true,
        address: '10.99.0.1/24',
        listenPort: 51820,
        privateKey: privB64,
        peers: [],
      },
    });
    persistDesiredStateToDisk(wgEnabledState);
    invalidateDesiredStateCacheInternal();

    hoisted.mockCallAgentApiDetailed.mockResolvedValueOnce({
      kind: 'ok',
      data: { success: true, message: 'Applied pending confirm' },
    });

    const regRes = await registerWireGuardPeerInternal({
      newPeer: {
        name: 'portal-admin',
        publicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        allowedIps: ['10.99.0.2/32'],
        persistentKeepalive: 25,
        enabled: true,
      },
      actorUsername: 'admin',
    });

    expect(regRes.pendingConfirm).toBe(true);
    expect(regRes.jobId).toMatch(/^ui-/);
    expect(hoisted.mockCallAgentApiDetailed.mock.calls.map((c) => c[0])).toEqual(['/v1/apply']);
  });
});
