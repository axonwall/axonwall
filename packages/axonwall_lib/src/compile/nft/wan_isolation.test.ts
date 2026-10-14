import { describe, it, expect } from 'vitest';
import { compileNftables } from './index.js';
import { lintRuleset } from '../../lint/index.js';
import type { DesiredState } from '../../schemas/index.js';

describe('Axonwall WAN Isolation & Web Management Security', () => {
  const baseState: DesiredState = {
    version: 1,
    system: {
      hostname: 'axonwall-gw',
      domain: 'corp.internal',
      dnsServers: ['1.1.1.1'],
      timezone: 'UTC',
      flowtableOffload: false,
      antiLockout: {
        enabled: true,
        interface: 'lan',
        ports: [22, 80, 443, 2966, 3000],
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
        ipv4Address: '192.168.1.1/24',
        mtu: 1500,
      },
    ],
    aliases: [],
    rules: [],
    nat: [],
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

  it('anti-lockout rule strictly binds to LAN device (eth1) and never WAN (eth0)', () => {
    const res = compileNftables(baseState);
    expect(res.nftScript).toContain('iifname "eth1" tcp dport { 22, 80, 443, 2966, 3000 } accept comment "anti-lockout"');
    expect(res.nftScript).not.toContain('iifname "eth0" tcp dport { 22, 80, 443, 2966, 3000 } accept comment "anti-lockout"');
  });

  it('suppresses antiLockout generation and emits warning if antiLockout.interface is set to wan', () => {
    const wanLockoutState: DesiredState = {
      ...baseState,
      system: {
        ...baseState.system,
        antiLockout: {
          enabled: true,
          interface: 'wan',
          ports: [2966],
        },
      },
    };
    const res = compileNftables(wanLockoutState);
    expect(res.nftScript).not.toContain('comment "anti-lockout"');
    expect(res.warnings.some((w) => w.includes("set to 'wan'"))).toBe(true);

    const issues = lintRuleset(wanLockoutState);
    expect(issues.some((i) => i.type === 'anti_lockout_on_wan' && i.severity === 'error')).toBe(true);
  });

  it('floating rules on interface "any" do not leak into input_wan for local management ports', () => {
    const floatingState: DesiredState = {
      ...baseState,
      rules: [
        {
          id: 'floating-1',
          action: 'pass',
          direction: 'in',
          interface: 'any',
          protocol: 'tcp',
          source: 'any',
          sourcePort: '',
          destination: 'any',
          destinationPort: '2966',
          log: false,
          enabled: true,
          quick: true,
          sortOrder: 10,
          description: 'Floating management rule',
        },
      ],
    };
    const res = compileNftables(floatingState);
    const lines = res.nftScript.split('\n');
    const inputWanIdx = lines.findIndex((l) => l.includes('chain input_wan {'));
    const inputLanIdx = lines.findIndex((l) => l.includes('chain input_lan {'));

    expect(inputWanIdx).toBeGreaterThan(-1);
    expect(inputLanIdx).toBeGreaterThan(-1);

    const inputWanEnd = lines.slice(inputWanIdx).findIndex((l) => l.trim() === '}');
    const inputWanBlock = lines.slice(inputWanIdx, inputWanIdx + inputWanEnd).join('\n');

    expect(inputWanBlock).not.toContain('dport 2966');
  });

  it('detects and warns when a firewall rule exposes management ports on WAN to the public internet', () => {
    const exposedState: DesiredState = {
      ...baseState,
      rules: [
        {
          id: 'rule-wan-bad',
          action: 'pass',
          direction: 'in',
          interface: 'wan',
          protocol: 'tcp',
          source: 'any',
          sourcePort: '',
          destination: 'any',
          destinationPort: '2966',
          log: false,
          enabled: true,
          quick: true,
          sortOrder: 10,
          description: 'Expose web console to WAN',
        },
      ],
    };
    const issues = lintRuleset(exposedState);
    const wanIssue = issues.find((i) => i.type === 'wan_management_exposed');
    expect(wanIssue).toBeDefined();
    expect(wanIssue?.severity).toBe('warning');
    expect(wanIssue?.message).toContain('exposes Web Console / SSH management port(s) on wan to the public internet');
  });

  it('does not warn if a WAN rule restricts source to a specific IP or subnet', () => {
    const safeRemoteState: DesiredState = {
      ...baseState,
      rules: [
        {
          id: 'rule-wan-safe',
          action: 'pass',
          direction: 'in',
          interface: 'wan',
          protocol: 'tcp',
          source: '198.51.100.25/32',
          sourcePort: '',
          destination: 'any',
          destinationPort: '2966',
          log: false,
          enabled: true,
          quick: true,
          sortOrder: 10,
          description: 'Trusted NOC Remote Access',
        },
      ],
    };
    const issues = lintRuleset(safeRemoteState);
    expect(issues.some((i) => i.type === 'wan_management_exposed')).toBe(false);
  });

  it('detects management exposure for port ranges and any port on WAN, but ignores UDP-only or floating rules', () => {
    const rangeState: DesiredState = {
      ...baseState,
      rules: [
        {
          id: 'rule-wan-range',
          action: 'pass',
          direction: 'in',
          interface: 'wan',
          protocol: 'tcp',
          source: 'any',
          sourcePort: '',
          destination: 'any',
          destinationPort: '20-25',
          log: false,
          enabled: true,
          quick: true,
          sortOrder: 10,
          description: 'Expose port range covering SSH',
        },
        {
          id: 'rule-wan-anyport',
          action: 'pass',
          direction: 'in',
          interface: 'wan',
          protocol: 'tcp',
          source: 'any',
          sourcePort: '',
          destination: 'any',
          destinationPort: 'any',
          log: false,
          enabled: true,
          quick: true,
          sortOrder: 20,
          description: 'Expose any TCP port on WAN',
        },
        {
          id: 'rule-wan-udp',
          action: 'pass',
          direction: 'in',
          interface: 'wan',
          protocol: 'udp',
          source: 'any',
          sourcePort: '',
          destination: 'any',
          destinationPort: '443',
          log: false,
          enabled: true,
          quick: true,
          sortOrder: 30,
          description: 'UDP 443 is not TCP management',
        },
      ],
    };
    const issues = lintRuleset(rangeState);
    const wanIssues = issues.filter((i) => i.type === 'wan_management_exposed');
    expect(wanIssues).toHaveLength(2);
    expect(wanIssues.map((i) => i.ruleId)).toEqual(['rule-wan-range', 'rule-wan-anyport']);
  });
});
