import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { mintSupabaseToken } from '@axonwall/lib/ldap';
import { enablePluginWithDependencies } from '@axonwall/lib/plugins';
import { DesiredStateSchema } from '@axonwall/lib/schemas';
import type { UserSession } from '@axonwall/lib/rbac';

const hoisted = vi.hoisted(() => {
  const mockSessionState: { current: UserSession | null } = {
    current: {
      userId: 'admin-1',
      username: 'admin',
      displayName: 'Admin',
      roles: ['admin'],
      privileges: ['*'],
      passwordChangeRequired: false,
      source: 'local_admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
    },
  };

  return {
    mockSessionState,
    mockCallAgentApi: vi.fn(),
    mockCallAgentApiResponse: vi.fn(),
    mockCallAgentApiDetailed: vi.fn(),
  };
});

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-bh4-phase5-'));
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
    getSession: vi.fn(async () => hoisted.mockSessionState.current),
  };
});

const agentMod = await import('../agent');
const authMod = await import('../auth');
const wgMod = await import('../wg');
const { getMfaSecret, performAuthentication } = await import('../auth-internal');
const { isPasswordChangeEnforced } = await import('../auth-guard');
const {
  getDesiredStateInternal,
  invalidateDesiredStateCacheInternal,
  persistDesiredStateToDisk,
  syncNetworkInterfacesFiles,
} = await import('../desired-state-internal');
const { vmPowerAction } = await import('../virt');
const {
  assertSafeOutboundUrl,
  isDisallowedSsrfIp,
  ssrfSafeFetch,
} = await import('../ssrf-guard');
const {
  exchangeCodeForIdentity,
  getOidcConfig,
  resolvePublicOrigin,
} = await import('../oidc');
const { GET: gatewayGet } = await import('../../app/api/auth/gateway/route');
const { middleware } = await import('../../middleware');

afterAll(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

beforeEach(() => {
  vi.useRealTimers();
  hoisted.mockCallAgentApi.mockReset();
  hoisted.mockCallAgentApiResponse.mockReset();
  hoisted.mockCallAgentApiDetailed.mockReset();
  process.env.FORCE_PASSWORD_CHANGE = 'true';
  fs.writeFileSync(path.join(stateDir, '.password_changed'), 'done\n', 'utf8');
  hoisted.mockSessionState.current = {
    userId: 'admin-1',
    username: 'admin',
    displayName: 'Admin',
    roles: ['admin'],
    privileges: ['*'],
    passwordChangeRequired: false,
    source: 'local_admin',
    exp: Math.floor(Date.now() / 1000) + 3600,
  };
});

describe('Phase 5 Web Console security & bug-hunt regressions', () => {
  it('W-C1: syncNetworkInterfacesFiles strips non-IP / newline injection payloads from gateway and dnsServers', () => {
    const state = DesiredStateSchema.parse({
      version: 1,
      interfaces: [
        {
          name: 'lan',
          device: 'eth0',
          role: 'lan',
          type: 'static',
          ipv4Address: '192.168.10.1/24',
          enabled: true,
        },
      ],
      system: {
        hostname: 'gw',
        domain: 'local',
        dnsServers: ['1.1.1.1'],
      },
    });
    // Force-bypass schema to verify defense-in-depth inside syncNetworkInterfacesFiles
    (state.interfaces[0] as any).ipv4Gateway = '192.168.10.254\n    post-up /bin/sh -c id';
    (state.system as any).dnsServers = ['9.9.9.9\n    up id', '8.8.8.8'];

    const { confContent, ifacesContent } = syncNetworkInterfacesFiles(state);
    expect(confContent).not.toContain('post-up');
    expect(confContent).not.toContain('up id');
    expect(confContent).toContain('IFACE_LAN_IPV4_GATEWAY=\n');
    expect(confContent).toContain('WAN_DNS1=8.8.8.8');
    expect(ifacesContent).not.toContain('post-up');
    expect(ifacesContent).not.toContain('up id');
    expect(ifacesContent).not.toContain('    gateway ');
    expect(ifacesContent).toContain('    dns-nameservers 8.8.8.8\n');
  });

  it('W-C2 & W-M5: /api/auth/gateway rejects empty roles=, with 400 and enforces live .password_changed state', async () => {
    const gatewayState = enablePluginWithDependencies(
      'identity-aware-proxy',
      DesiredStateSchema.parse({
        version: 1,
        zeroTrust: {
          enabled: true,
          apps: [
            {
              name: 'Gateway Test',
              publicHostname: '127.0.0.1',
              internalUpstream: 'http://10.0.0.5:8080',
              allowedRoles: ['admin'],
              enabled: true,
            },
          ],
        },
      })
    ).state;
    persistDesiredStateToDisk(gatewayState);
    invalidateDesiredStateCacheInternal();

    hoisted.mockSessionState.current = {
      userId: 'ro-1',
      username: 'auditor',
      displayName: 'Auditor',
      roles: ['readonly'],
      privileges: [],
      passwordChangeRequired: false,
      source: 'local',
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const req = new NextRequest('http://127.0.0.1:3000/api/auth/gateway?roles=,');
    const res = await gatewayGet(req);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/Invalid roles parameter/i);

    // W-M5: local_admin session with stale JWT claim passwordChangeRequired:false
    // must still be rejected if .password_changed marker is missing on disk.
    fs.rmSync(path.join(stateDir, '.password_changed'), { force: true });
    fs.rmSync(path.join(etcDir, '.password_changed'), { force: true });
    hoisted.mockSessionState.current = {
      userId: 'admin-1',
      username: 'admin',
      displayName: 'Admin',
      roles: ['admin'],
      privileges: ['*'],
      passwordChangeRequired: false,
      source: 'local_admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
    expect(isPasswordChangeEnforced(hoisted.mockSessionState.current)).toBe(true);
    const gatedRes = await gatewayGet(new NextRequest('http://127.0.0.1:3000/api/auth/gateway?roles=admin'));
    expect(gatedRes.status).toBe(403);
  });

  it('W-H2 & W-H3: operator VM start receives unredacted cloudInit.password while non-admin getCurrentDesiredState masks all 8 secret paths', async () => {
    const stateWithSecrets = DesiredStateSchema.parse({
      version: 1,
      interfaces: [{ name: 'wan', device: 'eth0', role: 'wan', type: 'dhcp', enabled: true }],
      virt: {
        enabled: true,
        defaultPool: 'tank',
        isoPool: 'tank',
        vms: [
          {
            vmid: 101,
            name: 'app-vm',
            cores: 2,
            memoryMb: 2048,
            cloudInit: {
              enabled: true,
              user: 'ubuntu',
              password: 'real-vm-secret-password',
              sshAuthorizedKeys: [],
              ipConfig: 'dhcp',
            },
          },
        ],
      },
      ddns: {
        enabled: true,
        entries: [
          {
            id: 'ddns-1',
            provider: 'cloudflare',
            hostname: 'fw.example.com',
            interface: 'wan',
            apiToken: 'cf-secret-token',
          },
        ],
      },
      captivePortal: {
        enabled: true,
        radiusSecret: 'top-radius-secret',
        zones: [{ name: 'guest', interface: 'lan', enabled: true, authMethod: 'radius', radiusSecret: 'zone-radius-secret' }],
      },
      crowdsec: { enabled: true, apiKey: 'cs-secret-key' },
      ha: { enabled: true, mtlsKey: 'ha-mtls-private-key' },
      observability: {
        alerting: { enabled: true, webhookUrl: 'https://hooks.example.com/secret-token' },
      },
      fleet: {
        enabled: true,
        nodes: [
          {
            id: 'sat-1',
            name: 'sat-1',
            hostname: 'sat-1',
            apiUrl: 'https://198.51.100.10:8443',
            ztpToken: 'ztp-secret-token',
          },
        ],
      },
      threatHarvester: {
        enabled: true,
        teacherLlm: { enabled: true, apiKey: 'llm-secret-key' },
        fleetShipper: { enabled: true, secretKey: 'shipper-secret-key' },
      },
    });
    persistDesiredStateToDisk(stateWithSecrets);
    invalidateDesiredStateCacheInternal();

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

    // W-H3: getCurrentDesiredState masks all 8 secret paths for operator/readonly
    const redacted = await agentMod.getCurrentDesiredState();
    expect(redacted.ddns?.entries?.[0]?.apiToken).toBe('********');
    expect(redacted.captivePortal?.zones?.[0]?.radiusSecret).toBe('********');
    expect(redacted.crowdsec?.apiKey).toBe('********');
    expect(redacted.ha?.mtlsKey).toBe('********');
    expect(redacted.observability?.alerting?.webhookUrl).toBe('********');
    expect(redacted.fleet?.nodes?.[0]?.ztpToken).toBe('********');
    expect(redacted.threatHarvester?.teacherLlm?.apiKey).toBe('********');
    expect(redacted.threatHarvester?.fleetShipper?.secretKey).toBe('********');
    expect(redacted.virt?.vms?.[0]?.cloudInit?.password).toBe('********');

    // W-H3: getThreatHarvesterStatus also redacts secrets for non-admin sessions
    hoisted.mockCallAgentApi.mockResolvedValueOnce({
      daemonDown: false,
      config: {
        enabled: true,
        teacherLlm: { enabled: true, apiKey: 'live-llm-key' },
        fleetShipper: { enabled: true, secretKey: 'live-shipper-key' },
      },
      bpfAttached: true,
      attachedInterfaces: ['eth0'],
      activeHooks: [],
      excludedUprobeDaemons: [],
      stats: { packetsSeen: 10 },
      timestamp: new Date().toISOString(),
    });
    const thStatus = await agentMod.getThreatHarvesterStatus();
    expect(thStatus.config.teacherLlm.apiKey).toBe('********');
    expect(thStatus.config.fleetShipper.secretKey).toBe('********');

    // W-H2: vmPowerAction('start') sends the real stored cloud-init password, not '********'
    hoisted.mockCallAgentApiResponse
      .mockResolvedValueOnce({ success: true }) // register
      .mockResolvedValueOnce({ success: true, message: 'started' }); // start
    const powerRes = await vmPowerAction(101, 'start');
    expect(powerRes.success).toBe(true);
    const registerCall = hoisted.mockCallAgentApiResponse.mock.calls[0];
    expect(registerCall?.[0]).toBe('/v1/virt/vms');
    expect((registerCall?.[2] as any)?.spec?.cloudInit?.password).toBe('real-vm-secret-password');
  });

  it('W-H6: SSRF guard blocks IPv4-mapped IPv6, CGNAT, ULA, non-dotted IPs, private DNS, and HTTP 302 redirects', async () => {
    expect(isDisallowedSsrfIp('::ffff:127.0.0.1')).toBe(true);
    expect(isDisallowedSsrfIp('::ffff:7f00:1')).toBe(true);
    expect(isDisallowedSsrfIp('::ffff:169.254.169.254')).toBe(true);
    expect(isDisallowedSsrfIp('fc00::1')).toBe(true);
    expect(isDisallowedSsrfIp('fd12:3456::1')).toBe(true);
    expect(isDisallowedSsrfIp('100.64.0.1')).toBe(true);
    expect(isDisallowedSsrfIp('93.184.216.34')).toBe(false);

    // Local Ollama mode allows loopback/RFC1918 but still blocks metadata/link-local
    expect(isDisallowedSsrfIp('127.0.0.1', { allowPrivate: true })).toBe(false);
    expect(isDisallowedSsrfIp('169.254.169.254', { allowPrivate: true })).toBe(true);
    expect(isDisallowedSsrfIp('fe80::1', { allowPrivate: true })).toBe(true);

    // Integer IPv4 URL (2852039166 == 169.254.169.254)
    await expect(assertSafeOutboundUrl('https://2852039166/latest/meta-data/')).rejects.toThrow();
    await expect(assertSafeOutboundUrl('https://[::ffff:127.0.0.1]/admin')).rejects.toThrow();
    await expect(
      assertSafeOutboundUrl('https://rebind.example.com/v1', {
        resolveDns: async () => [{ address: '10.0.0.5', family: 4 }],
      })
    ).rejects.toThrow(/prohibited/i);

    // HTTP 302 redirect blocking in ssrfSafeFetch
    const srv = http.createServer((_req, res) => {
      res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
      res.end();
    });
    await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
    const addr = srv.address() as { port: number };
    try {
      await expect(
        ssrfSafeFetch(
          `http://127.0.0.1:${addr.port}/models`,
          { method: 'GET' },
          { allowHttp: true, allowPrivate: true }
        )
      ).rejects.toThrow(/redirect/i);
    } finally {
      srv.close();
    }
  });

  it('W-H7 & W-M4: break-glass MFA reset takes effect immediately without restart and lockout counter resets after expiry', async () => {
    const mfaPath = path.join(etcDir, 'mfa.env');
    process.env.LOCAL_ADMIN_MFA_SECRET = 'JBSWY3DPEHPK3PXP';
    fs.writeFileSync(mfaPath, 'LOCAL_ADMIN_MFA_SECRET=ON_DISK_SECRET\n', 'utf8');
    expect(getMfaSecret()).toBe('ON_DISK_SECRET');

    // Break-glass reset removes all mfa.env files -> must NOT resurrect stale secret unless non-file env-only
    fs.writeFileSync(mfaPath, 'LOCAL_ADMIN_MFA_LAST_STEP=123\n', 'utf8');
    expect(getMfaSecret()).toBeUndefined();
    fs.rmSync(mfaPath, { force: true });
    delete process.env.LOCAL_ADMIN_MFA_SECRET;
    expect(getMfaSecret()).toBeUndefined();

    // W-M4: 5 failed logins lock out for 5 minutes; once expired, 1 wrong attempt does NOT immediately re-lock
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync('correct-horse-battery', salt, 64).toString('hex');
    fs.writeFileSync(
      path.join(etcDir, 'admin.env'),
      `LOCAL_ADMIN_USER=admin\nLOCAL_ADMIN_PASSWORD=scrypt$${salt}$${hash}\n`,
      'utf8'
    );

    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-21T12:00:00Z'));

    for (let i = 0; i < 5; i++) {
      const failRes = await performAuthentication('admin', 'wrong-password');
      expect(failRes.success).toBe(false);
    }
    const lockedRes = await performAuthentication('admin', 'correct-horse-battery');
    expect(lockedRes.success).toBe(false);
    expect(lockedRes.error).toMatch(/Too many failed/i);

    // Advance past 5 minute lockout window
    vi.setSystemTime(new Date('2026-11-21T12:06:00Z'));
    // One single failure should NOT immediately re-lock
    const oneTypo = await performAuthentication('admin', 'still-wrong');
    expect(oneTypo.error).toBe('Invalid username or password');
    // Subsequent valid login still succeeds instead of being re-locked
    const okRes = await performAuthentication('admin', 'correct-horse-battery');
    expect(okRes.success).toBe(true);
  });

  it('W-M3: internal helpers are not exported from "use server" action modules', () => {
    expect('invalidateDesiredStateCache' in agentMod).toBe(false);
    expect('performAuthentication' in authMod).toBe(false);
    expect('deriveWireGuardPublicKey' in wgMod).toBe(false);
  });

  it('W-M6: OIDC rejects empty expectedNonce, resolves X-Forwarded-Host origin, and loads state.sso fallback', async () => {
    delete process.env.OIDC_ISSUER_URL;
    delete process.env.OIDC_CLIENT_ID;
    const state = DesiredStateSchema.parse({
      version: 1,
      interfaces: [{ name: 'wan', device: 'eth0', role: 'wan', type: 'dhcp', enabled: true }],
      sso: {
        enabled: true,
        provider: 'oidc',
        issuerUrl: 'https://idp.example.com/realms/main',
        clientId: 'axonwall-ui',
        clientSecret: 'oidc-secret',
        redirectUri: 'https://fw.example.com:2966/api/auth/callback/oidc',
      },
    });
    persistDesiredStateToDisk(state);
    invalidateDesiredStateCacheInternal();

    const cfg = await getOidcConfig();
    expect(cfg?.issuerUrl).toBe('https://idp.example.com/realms/main');
    expect(cfg?.clientId).toBe('axonwall-ui');
    expect(cfg?.redirectUri).toBe('https://fw.example.com:2966/api/auth/callback/oidc');

    const hdrs = new Headers({
      'x-forwarded-proto': 'https',
      'x-forwarded-host': 'gw.corp.example:2966',
      host: '127.0.0.1:3000',
    });
    const prevTrustProxy = process.env.AXONWALL_TRUST_PROXY;
    const prevTrustedHosts = process.env.AXONWALL_TRUSTED_HOSTS;
    delete process.env.AXONWALL_TRUST_PROXY;
    delete process.env.AXONWALL_TRUSTED_HOSTS;
    try {
      expect(resolvePublicOrigin(hdrs, 'http://127.0.0.1:3000')).toBe('http://127.0.0.1:3000');
      process.env.AXONWALL_TRUST_PROXY = '1';
      expect(resolvePublicOrigin(hdrs, 'http://127.0.0.1:3000')).toBe('https://gw.corp.example:2966');
    } finally {
      if (prevTrustProxy === undefined) delete process.env.AXONWALL_TRUST_PROXY;
      else process.env.AXONWALL_TRUST_PROXY = prevTrustProxy;
      if (prevTrustedHosts === undefined) delete process.env.AXONWALL_TRUSTED_HOSTS;
      else process.env.AXONWALL_TRUSTED_HOSTS = prevTrustedHosts;
    }

    await expect(
      exchangeCodeForIdentity(
        cfg!,
        {
          authorization_endpoint: 'https://idp.example.com/auth',
          token_endpoint: 'https://idp.example.com/token',
          jwks_uri: 'https://idp.example.com/jwks',
        },
        'auth-code',
        'https://fw.example.com:2966/api/auth/callback/oidc',
        undefined
      )
    ).rejects.toThrow();
  });

  it('W-M9: CSRF middleware prefers X-Forwarded-Host and rejects cookie mutations lacking same-origin proof', async () => {
    const token = await mintSupabaseToken(
      {
        userId: 'admin-1',
        username: 'admin',
        displayName: 'Admin',
        roles: ['admin'],
        privileges: ['*'],
        passwordChangeRequired: false,
        source: 'local_admin',
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
      process.env.JWT_SECRET!
    );

    // Legitimate browser behind reverse proxy (Host rewritten to 127.0.0.1:3000)
    const proxiedReq = new NextRequest('http://127.0.0.1:3000/api/v1/apply', {
      method: 'POST',
      headers: {
        host: '127.0.0.1:3000',
        'x-forwarded-host': 'fw.example.com:2966',
        origin: 'https://fw.example.com:2966',
        cookie: `axonwall_session=${token}`,
      },
    });
    const proxiedRes = await middleware(proxiedReq);
    expect(proxiedRes.status).toBe(200);

    // Cookie-auth mutation without Origin, Referer, or Sec-Fetch-Site must 403
    const barePost = new NextRequest('https://fw.example.com:2966/api/v1/apply', {
      method: 'POST',
      headers: {
        host: 'fw.example.com:2966',
        cookie: `axonwall_session=${token}`,
      },
    });
    const bareRes = await middleware(barePost);
    expect(bareRes.status).toBe(403);

    // Cross-origin Referer when Origin is absent must 403
    const badReferer = new NextRequest('https://fw.example.com:2966/api/v1/apply', {
      method: 'POST',
      headers: {
        host: 'fw.example.com:2966',
        referer: 'https://evil.example.net/attack.html',
        cookie: `axonwall_session=${token}`,
      },
    });
    const refRes = await middleware(badReferer);
    expect(refRes.status).toBe(403);
  });
});
