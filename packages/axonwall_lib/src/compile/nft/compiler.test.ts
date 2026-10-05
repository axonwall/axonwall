import { describe, it, expect } from 'vitest';
import { compileNftables } from './index.js';
import { lintRuleset } from '../../lint/index.js';
import { isValidIPv4, isValidCIDR, isValidPortRange } from '../../util/index.js';
import { mintSupabaseToken, verifyToken } from '../../ldap/index.js';
import type { DesiredState } from '../../schemas/index.js';

describe('Axonwall Network Utils', () => {
  it('validates IPv4 and CIDR correctly', () => {
    expect(isValidIPv4('192.168.1.1')).toBe(true);
    expect(isValidIPv4('999.1.1.1')).toBe(false);
    expect(isValidCIDR('192.168.1.0/24')).toBe(true);
    expect(isValidCIDR('10.0.0.1/33')).toBe(false);
    expect(isValidPortRange('80')).toBe(true);
    expect(isValidPortRange('1000-2000')).toBe(true);
    expect(isValidPortRange('70000')).toBe(false);
  });
});

describe('Axonwall nftables Compiler', () => {
  const sampleState: DesiredState = {
    version: 1,
    system: {
      hostname: 'axonwall-core',
      domain: 'axonwall.local',
      dnsServers: ['1.1.1.1'],
      timezone: 'UTC',
      flowtableOffload: true,
      antiLockout: {
        enabled: true,
        interface: 'lan',
        ports: [22, 80, 443, 3000],
      },
    },
    interfaces: [
      {
        name: 'wan',
        device: 'eth0',
        type: 'dhcp',
        enabled: true,
        description: 'WAN Uplink',
        mtu: 1500,
      },
      {
        name: 'lan',
        device: 'eth1',
        type: 'static',
        enabled: true,
        description: 'Corporate LAN',
        ipv4Address: '192.168.100.1/24',
        mtu: 1500,
      },
    ],
    aliases: [
      {
        name: 'web_servers',
        type: 'host',
        entries: ['192.168.100.10', '192.168.100.11'],
        description: 'Internal Web Servers',
        enabled: true,
      },
      {
        name: 'unused_alias',
        type: 'network',
        entries: ['10.50.0.0/16'],
        description: 'Unused test network',
        enabled: true,
      },
    ],
    rules: [
      {
        action: 'pass',
        direction: 'in',
        interface: 'lan',
        quick: true,
        protocol: 'tcp',
        source: 'any',
        sourcePort: '',
        destination: '$web_servers',
        destinationPort: '80',
        gateway: undefined,
        log: true,
        enabled: true,
        description: 'Allow LAN to Web Servers HTTP',
        sortOrder: 10,
      },
      {
        action: 'pass',
        direction: 'in',
        interface: 'lan',
        quick: true,
        protocol: 'any',
        source: 'any',
        sourcePort: '',
        destination: 'any',
        destinationPort: '',
        gateway: undefined,
        log: false,
        enabled: true,
        description: 'Default LAN Catch-All',
        sortOrder: 100,
      },
      {
        action: 'block',
        direction: 'in',
        interface: 'lan',
        quick: true,
        protocol: 'tcp',
        source: 'any',
        sourcePort: '',
        destination: 'any',
        destinationPort: '23',
        gateway: undefined,
        log: true,
        enabled: true,
        description: 'Shadowed Block Telnet Rule',
        sortOrder: 110,
      },
    ],
    nat: [
      {
        type: 'masquerade',
        interface: 'wan',
        protocol: 'any',
        source: 'any',
        sourcePort: '',
        destination: 'any',
        destinationPort: '',
        enabled: true,
        description: 'Default Outbound NAT',
        sortOrder: 100,
        log: false,
      },
    ],
    gateways: [],
    gatewayGroups: [],
    vlans: [],
    bridges: [],
    bonds: [],
    virtualIps: [],
    vrfs: [],
    dhcp: { enabled: true, subnets: [] },
    dns: { enabled: true, listenPort: 53, dnssec: true, dotEnabled: true, dotUpstreams: [], hostOverrides: [] },
    routes: [],
  };

  it('compiles valid nftables ruleset with anti-lockout, aliases, flowtable, and chains', () => {
    const res = compileNftables(sampleState);
    expect(res.nftScript).toContain('table inet axonwall {');
    expect(res.nftScript).toContain('set set_web_servers {');
    expect(res.nftScript).toContain('192.168.100.10, 192.168.100.11');
    expect(res.nftScript).toContain('flowtable ft_fastpath {');
    expect(res.nftScript).toContain('iifname "eth1" tcp dport { 22, 80, 443, 3000 } accept comment "anti-lockout"');
    expect(res.nftScript).toContain('ip daddr @set_web_servers dport 80');
    expect(res.nftScript).toContain('oifname "eth0" masquerade');
  });

  it('detects shadowed rules and unused aliases via linter', () => {
    const issues = lintRuleset(sampleState);
    const shadowed = issues.find((i) => i.type === 'shadowed_rule');
    const unused = issues.find((i) => i.type === 'unused_alias');

    expect(shadowed).toBeDefined();
    expect(shadowed?.message).toContain('Shadowed Block Telnet Rule');
    expect(unused).toBeDefined();
    expect(unused?.aliasName).toBe('unused_alias');
  });
});

describe('Axonwall JWT Minting & Verification', () => {
  it('signs and verifies Supabase-compatible JWT with roles and privileges', async () => {
    const secret = 'super-secret-jwt-token-with-at-least-32-chars!';
    const session = {
      userId: 'cn=josh,ou=users,dc=axonwall,dc=local',
      username: 'josh',
      displayName: 'Joshua Cox',
      source: 'ldap' as const,
      roles: ['admin'],
      privileges: ['*' as const],
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const token = await mintSupabaseToken(session, secret);
    expect(typeof token).toBe('string');

    const verified = await verifyToken(token, secret);
    expect(verified).not.toBeNull();
    expect(verified?.username).toBe('josh');
    expect(verified?.roles).toEqual(['admin']);
    expect(verified?.privileges).toEqual(['*']);
  });
});
