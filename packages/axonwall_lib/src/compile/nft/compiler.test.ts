import { describe, it, expect } from 'vitest';
import { compileNftables, compileSatelliteNftables } from './index.js';
import { lintRuleset } from '../../lint/index.js';
import { isValidIPv4, isValidCIDR, isValidPortRange, isValidDevice } from '../../util/index.js';
import { mintSupabaseToken, verifyToken } from '../../ldap/index.js';
import { InterfaceSchema, DesiredStateSchema, type DesiredState } from '../../schemas/index.js';

describe('Axonwall Network Utils & Schemas', () => {
  it('validates IPv4, CIDR, comma-separated ports, and port ranges correctly', () => {
    expect(isValidIPv4('192.168.1.1')).toBe(true);
    expect(isValidIPv4('999.1.1.1')).toBe(false);
    expect(isValidCIDR('192.168.1.0/24')).toBe(true);
    expect(isValidCIDR('10.0.0.1/33')).toBe(false);
    expect(isValidPortRange('80')).toBe(true);
    expect(isValidPortRange('1000-2000')).toBe(true);
    expect(isValidPortRange('80, 443')).toBe(true);
    expect(isValidPortRange('22, 80, 443, 2966, 3000')).toBe(true);
    expect(isValidPortRange('8000-8080, 9000')).toBe(true);
    expect(isValidPortRange('70000')).toBe(false);
    expect(isValidPortRange('80, 70000')).toBe(false);
    expect(isValidPortRange('2000-1000')).toBe(false);
  });

  it('validates InterfaceSchema device identifier against command injection characters', () => {
    expect(() => InterfaceSchema.parse({ name: 'wan', device: 'eth0' })).not.toThrow();
    expect(() => InterfaceSchema.parse({ name: 'vlan10', device: 'enp1s0.10' })).not.toThrow();
    expect(() => InterfaceSchema.parse({ name: 'bad', device: 'eth0; rm -rf /' })).toThrow('Invalid device identifier');
  });
});

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

describe('Axonwall nftables Compiler', () => {
  it('compiles valid nftables ruleset with atomic table flush, anti-lockout, aliases, flowtable, and chains', () => {
    const res = compileNftables(sampleState);
    expect(res.nftScript).toContain('table inet axonwall {}\nflush table inet axonwall\ntable inet axonwall {');
    expect(res.nftScript).toContain('set set_web_servers {');
    expect(res.nftScript).toContain('192.168.100.10, 192.168.100.11');
    expect(res.nftScript).toContain('flowtable ft_fastpath {');
    expect(res.nftScript).toContain('iifname "eth1" tcp dport { 22, 80, 443, 3000 } accept comment "anti-lockout"');
    expect(res.nftScript).toContain('ip daddr @set_web_servers tcp dport 80');
    expect(res.nftScript).toContain('oifname "eth0" masquerade');
  });

  it('supports IPv6 aliases/rules, ipv6-icmp, comma-separated ports, DNAT edge cases, floating rules, and Suricata physical device mapping', () => {
    const advState: DesiredState = {
      ...sampleState,
      suricata: {
        enabled: true,
        mode: 'ips',
        interfaces: ['wan'],
        nfqueueFailOpen: true,
        nfqueueBypass: true,
        ruleSources: [],
        homeNet: ['192.168.100.0/24'],
      },
      aliases: [
        { name: 'v6_hosts', type: 'host', entries: ['2001:db8::10'], description: 'v6 host', enabled: true },
        { name: 'app_ports', type: 'port', entries: ['8000-8080', '8443'], description: 'ports', enabled: true },
      ],
      rules: [
        {
          action: 'pass',
          direction: 'in',
          interface: 'floating',
          quick: true,
          protocol: 'tcp',
          source: '2001:db8::1/128',
          sourcePort: '',
          destination: '$v6_hosts',
          destinationPort: '80, 443',
          log: false,
          enabled: true,
          description: 'IPv6 multi-port rule',
          sortOrder: 10,
        },
        {
          action: 'pass',
          direction: 'in',
          interface: 'lan',
          quick: true,
          protocol: 'ipv6-icmp',
          source: 'any',
          sourcePort: '',
          destination: 'any',
          destinationPort: '',
          log: false,
          enabled: true,
          description: 'Allow ICMPv6',
          sortOrder: 20,
        },
      ],
      nat: [
        {
          type: 'dnat',
          interface: 'wan',
          protocol: 'any',
          source: 'any',
          sourcePort: '',
          destination: 'wan_ip',
          destinationPort: '8080',
          targetIp: '192.168.100.50',
          targetPort: '80',
          enabled: true,
          description: 'DNAT any proto with port',
          sortOrder: 10,
          log: false,
        },
        {
          type: 'dnat',
          interface: 'wan',
          protocol: 'tcp',
          source: 'any',
          sourcePort: '',
          destination: 'wan_ip',
          destinationPort: '',
          targetIp: '192.168.100.51',
          enabled: true,
          description: 'DNAT tcp without port',
          sortOrder: 20,
          log: false,
        },
        {
          type: 'dnat',
          interface: 'wan',
          protocol: 'tcp',
          source: 'any',
          sourcePort: '',
          destination: 'wan_ip',
          destinationPort: '9000',
          targetIp: '',
          enabled: true,
          description: 'Skipped DNAT without targetIp',
          sortOrder: 30,
          log: false,
        },
      ],
    };

    const res = compileNftables(advState);
    expect(res.nftScript).toContain('set set_v6_hosts {\n    type ipv6_addr;\n    flags interval;');
    expect(res.nftScript).toContain('set set_app_ports {\n    type inet_service;\n    flags interval;');
    expect(res.nftScript).toContain('iifname "eth0" queue num 0-3 bypass comment "suricata-ips-inbound"');
    expect(res.nftScript).toContain('ip6 saddr 2001:db8::1/128 ip6 daddr @set_v6_hosts tcp dport { 80, 443 } accept');
    expect(res.nftScript).toContain('meta l4proto ipv6-icmp accept');
    expect(res.nftScript).toContain('iifname "eth0" meta l4proto { tcp, udp } th dport 8080 dnat ip to 192.168.100.50:80');
    expect(res.nftScript).toContain('iifname "eth0" meta l4proto tcp dnat ip to 192.168.100.51');
    expect(res.nftScript).not.toContain('dport 9000');
  });

  it('compiles satellite nftables for both nested and top-level tunnelIp', () => {
    const sat1 = compileSatelliteNftables({ id: 'sat-1', tunnelIp: '10.99.0.5/24' });
    expect(sat1.nftScript).toContain('udp dport 51820 accept comment "allow-wireguard"');
    const sat2 = compileSatelliteNftables({ id: 'sat-2', wireguard: { tunnelIp: '10.99.0.6/24' } });
    expect(sat2.nftScript).toContain('udp dport 51820 accept comment "allow-wireguard"');
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

  it('tracks shadowed catch-all per direction, respects quick=false, and normalizes port wildcards in duplicate detection', () => {
    const state: DesiredState = {
      ...sampleState,
      rules: [
        {
          id: 'r1',
          action: 'pass',
          direction: 'in',
          interface: 'lan',
          quick: false,
          protocol: 'any',
          source: 'any',
          sourcePort: '',
          destination: 'any',
          destinationPort: '',
          log: false,
          enabled: true,
          description: 'Non-quick catch-all',
          sortOrder: 10,
        },
        {
          id: 'r2',
          action: 'pass',
          direction: 'in',
          interface: 'lan',
          quick: true,
          protocol: 'any',
          source: 'any',
          sourcePort: 'any',
          destination: 'any',
          destinationPort: 'any',
          log: false,
          enabled: true,
          description: 'Quick inbound catch-all',
          sortOrder: 20,
        },
        {
          id: 'r3',
          action: 'block',
          direction: 'out',
          interface: 'lan',
          quick: true,
          protocol: 'tcp',
          source: 'any',
          sourcePort: '',
          destination: 'any',
          destinationPort: '25',
          log: false,
          enabled: true,
          description: 'Outbound rule not shadowed by inbound catch-all',
          sortOrder: 30,
        },
      ],
    };
    const issues = lintRuleset(state);
    expect(issues.some((i) => i.type === 'shadowed_rule')).toBe(false);
    expect(issues.some((i) => i.type === 'duplicate_rule' && i.ruleId === 'r2')).toBe(true);
  });
});

describe('Axonwall JWT Minting & Verification', () => {
  it('signs and verifies Supabase-compatible JWT with roles, privileges, and passwordChangeRequired', async () => {
    const secret = 'super-secret-jwt-token-with-at-least-32-chars!';
    const session = {
      userId: 'cn=josh,ou=users,dc=axonwall,dc=local',
      username: 'josh',
      displayName: 'Joshua Cox',
      source: 'ldap' as const,
      roles: ['admin'],
      privileges: ['*' as const],
      exp: Math.floor(Date.now() / 1000) + 3600,
      passwordChangeRequired: true,
    };

    const token = await mintSupabaseToken(session, secret);
    expect(typeof token).toBe('string');

    const verified = await verifyToken(token, secret);
    expect(verified).not.toBeNull();
    expect(verified?.username).toBe('josh');
    expect(verified?.roles).toEqual(['admin']);
    expect(verified?.privileges).toEqual(['*']);
    expect(verified?.passwordChangeRequired).toBe(true);
  });

  it('sanitizes newlines and backslashes in nft rule description comments', () => {
    const state: DesiredState = {
      ...sampleState,
      rules: [
        {
          action: 'pass',
          direction: 'in',
          interface: 'lan',
          quick: true,
          protocol: 'tcp',
          source: 'any',
          sourcePort: '',
          destination: 'any',
          destinationPort: '80',
          log: false,
          enabled: true,
          description: 'rule 1\nchain exploit { type filter hook input priority -10; }\ncomment "injection"',
          sortOrder: 1,
        },
      ],
    };
    const compiled = compileNftables(state);
    expect(compiled.nftScript).not.toContain('\nchain exploit');
    expect(compiled.nftScript).toContain('comment "rule 1 chain exploit { type filter hook input priority -10; } comment \'injection\'"');
  });

  it('validates InterfaceSchema name against invalid characters and path traversal', () => {
    expect(() => InterfaceSchema.parse({ name: 'lan', device: 'eth0' })).not.toThrow();
    expect(() => InterfaceSchema.parse({ name: 'wan.100', device: 'eth0' })).not.toThrow();
    expect(() => InterfaceSchema.parse({ name: 'lan/../../etc', device: 'eth0' })).toThrow('Invalid interface name');
    expect(() => InterfaceSchema.parse({ name: 'lan foo', device: 'eth0' })).toThrow('Invalid interface name');
  });
});


describe('Axonwall nftables Compiler — HA sync rule (audit S-04)', () => {
  const haState = (listenPort?: number): DesiredState =>
    DesiredStateSchema.parse({
      interfaces: [
        { name: 'wan', device: 'eth0', type: 'dhcp', enabled: true },
        { name: 'lan', device: 'eth1', type: 'static', enabled: true, ipv4Address: '192.168.100.1/24' },
      ],
      ha: {
        enabled: true,
        syncInterface: 'lan',
        ...(listenPort !== undefined ? { sqliteSync: { listenPort } } : {}),
      },
    });

  it('opens the default HA sync port 9876 on the sync interface, not 8443/9443', () => {
    const res = compileNftables(haState());
    expect(res.nftScript).toContain('iifname "eth1" tcp dport 9876 accept comment "ha-state-and-zfs-sync"');
    expect(res.nftScript).not.toContain('8443');
    expect(res.nftScript).not.toContain('9443');
  });

  it('opens a configured custom HA sync port', () => {
    const res = compileNftables(haState(9999));
    expect(res.nftScript).toContain('iifname "eth1" tcp dport 9999 accept comment "ha-state-and-zfs-sync"');
    expect(res.nftScript).not.toContain('tcp dport 9876 accept comment "ha-state-and-zfs-sync"');
  });

  it('emits no HA sync rule when HA is disabled', () => {
    const res = compileNftables(DesiredStateSchema.parse({}));
    expect(res.nftScript).not.toContain('ha-state-and-zfs-sync');
  });
});

describe('Axonwall nftables Compiler — Device Validation and Flowtable Handling', () => {
  it('validates device names correctly with isValidDevice', () => {
    expect(isValidDevice('eth0')).toBe(true);
    expect(isValidDevice('ens18')).toBe(true);
    expect(isValidDevice('vlan.100')).toBe(true);
    expect(isValidDevice('')).toBe(false);
    expect(isValidDevice(undefined)).toBe(false);
    expect(isValidDevice(null)).toBe(false);
    expect(isValidDevice('none')).toBe(false);
    expect(isValidDevice('NONE')).toBe(false);
    expect(isValidDevice('null')).toBe(false);
    expect(isValidDevice('disabled')).toBe(false);
    expect(isValidDevice('unassigned')).toBe(false);
  });

  it('filters out device "none" from flowtable devices and interface dispatchers', () => {
    const stateWithNone: DesiredState = DesiredStateSchema.parse({
      system: {
        flowtableOffload: true,
      },
      interfaces: [
        { name: 'wan', device: 'ens19', type: 'static', enabled: true, ipv4Address: '148.135.193.214/27' },
        { name: 'lan', device: 'none', type: 'static', enabled: true, ipv4Address: '192.168.1.1/24' },
        { name: 'opt1', device: 'ens18', type: 'dhcp', enabled: true },
      ],
    });

    const res = compileNftables(stateWithNone);
    expect(res.nftScript).toContain('devices = { "ens19", "ens18" };');
    expect(res.nftScript).not.toContain('"none"');
    expect(res.nftScript).not.toContain('iifname "none"');
  });

  it('omits flowtable entirely if all interfaces have invalid devices', () => {
    const stateNoDevs: DesiredState = DesiredStateSchema.parse({
      system: {
        flowtableOffload: true,
      },
      interfaces: [
        { name: 'wan', device: 'none', type: 'dhcp', enabled: true },
        { name: 'lan', device: 'unassigned', type: 'static', enabled: true },
      ],
    });

    const res = compileNftables(stateNoDevs);
    expect(res.nftScript).not.toContain('flowtable ft_fastpath');
    expect(res.nftScript).not.toContain('flow add @ft_fastpath');
  });

  it('supports Multi-WAN, Multi-LAN, and Authoritative vs Joined Network DHCP across N ports', () => {
    const multiPortState: DesiredState = DesiredStateSchema.parse({
      system: {
        flowtableOffload: true,
        antiLockout: {
          enabled: true,
          interface: 'lan1',
          interfaces: ['lan1', 'lan2', 'mgmt', 'wan1', 'wan2'],
          ports: [22, 443, 2966],
        },
      },
      interfaces: [
        { name: 'wan1', role: 'wan', device: 'eth0', type: 'dhcp', enabled: true, dhcpServer: false },
        { name: 'wan2', role: 'wan', device: 'eth1', type: 'static', enabled: true, dhcpServer: false, ipv4Address: '203.0.113.2/24' },
        { name: 'lan1', role: 'lan', device: 'eth2', type: 'static', enabled: true, dhcpServer: true, ipv4Address: '192.168.10.1/24' },
        { name: 'lan2', role: 'lan', device: 'eth3', type: 'static', enabled: true, dhcpServer: false, ipv4Address: '192.168.20.250/24' },
        { name: 'mgmt', role: 'lan', device: 'eth4', type: 'dhcp', enabled: true, dhcpServer: false },
      ],
      dhcp: {
        enabled: true,
        subnets: [
          {
            interface: 'lan1',
            subnet: '192.168.10.0/24',
            poolStart: '192.168.10.100',
            poolEnd: '192.168.10.200',
            routers: ['192.168.10.1'],
          },
          {
            interface: 'lan2',
            subnet: '192.168.20.0/24',
            poolStart: '192.168.20.100',
            poolEnd: '192.168.20.200',
            routers: ['192.168.20.250'],
          },
          {
            interface: 'wan2',
            subnet: '203.0.113.0/24',
            poolStart: '203.0.113.100',
            poolEnd: '203.0.113.200',
          },
        ],
      },
    });

    const res = compileNftables(multiPortState);
    // Both WAN interfaces receive outbound NAT masquerading
    expect(res.nftScript).toContain('oifname "eth0" masquerade comment "default-gateway-masquerade"');
    expect(res.nftScript).toContain('oifname "eth1" masquerade comment "default-gateway-masquerade"');

    // All LAN interfaces receive anti-lockout rules, while WAN interfaces never do
    expect(res.nftScript).toContain('iifname "eth2" tcp dport { 22, 443, 2966 } accept comment "anti-lockout-lan1"');
    expect(res.nftScript).toContain('iifname "eth3" tcp dport { 22, 443, 2966 } accept comment "anti-lockout-lan2"');
    expect(res.nftScript).toContain('iifname "eth4" tcp dport { 22, 443, 2966 } accept comment "anti-lockout-mgmt"');
    expect(res.nftScript).not.toContain('anti-lockout-wan1');
    expect(res.nftScript).not.toContain('anti-lockout-wan2');

    // Kea DHCPv4 only binds to authoritative LAN interfaces (lan1 -> eth2), never joined networks (lan2, mgmt) or WANs (wan2)
    const keaFile = res.files.find((f) => f.path === '/etc/kea/kea-dhcp4.conf');
    expect(keaFile).toBeDefined();
    const keaParsed = JSON.parse(keaFile!.content);
    expect(keaParsed.Dhcp4['interfaces-config'].interfaces).toEqual(['eth2']);
    expect(keaParsed.Dhcp4.subnet4).toHaveLength(1);
    expect(keaParsed.Dhcp4.subnet4[0].subnet).toBe('192.168.10.0/24');
  });
});

