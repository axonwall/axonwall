import { describe, it, expect } from 'vitest';
import {
  McpPolicyLimitsSchema,
  validateMcpTarget,
  validateRedirectTargetAllowlist,
  isIpInCidr,
  type McpGuardContext,
} from '../index.js';
import { compileNftables } from '../../compile/nft/index.js';
import { DesiredStateSchema } from '../../schemas/index.js';

describe('Axonwall MCP Safety Guard & Blast-Radius Validator', () => {
  const baseLimits = McpPolicyLimitsSchema.parse({
    maxIpv4PrefixLen: 24,
    maxIpv6PrefixLen: 64,
    allowedRedirectTargets: ['10.99.0.10', '10.99.0.10:2222', '10.99.1.0/24'],
  });

  const guardCtx: McpGuardContext = {
    applianceHostIps: ['192.168.1.1/24', '203.0.113.2/29'],
    gatewayAndHaIps: ['203.0.113.1', '192.168.1.2'],
    callerIp: '192.168.1.50',
    antiLockoutPorts: [2966, 22, 9876],
    policyLimits: baseLimits,
  };

  it('rejects loopback, link-local, multicast, and default route /0', () => {
    expect(validateMcpTarget('127.0.0.1', guardCtx).valid).toBe(false);
    expect(validateMcpTarget('::1', guardCtx).valid).toBe(false);
    expect(validateMcpTarget('169.254.10.20', guardCtx).valid).toBe(false);
    expect(validateMcpTarget('224.0.0.18', guardCtx).valid).toBe(false);
    expect(validateMcpTarget('0.0.0.0/0', guardCtx).valid).toBe(false);
    expect(validateMcpTarget('::/0', guardCtx).valid).toBe(false);
  });

  it('rejects local appliance interface IPs, upstream gateways, and HA peers', () => {
    const appCheck = validateMcpTarget('192.168.1.1', guardCtx);
    expect(appCheck.valid).toBe(false);
    expect(appCheck.reason).toContain('appliance');

    const subnetOverlappingAppliance = validateMcpTarget('192.168.1.0/24', guardCtx);
    expect(subnetOverlappingAppliance.valid).toBe(false);

    const gwCheck = validateMcpTarget('203.0.113.1', guardCtx);
    expect(gwCheck.valid).toBe(false);
    expect(gwCheck.reason).toContain('gateway');

    const haCheck = validateMcpTarget('192.168.1.2', guardCtx);
    expect(haCheck.valid).toBe(false);
  });

  it('rejects the MCP client caller IP to prevent self-lockout', () => {
    const selfCheck = validateMcpTarget('192.168.1.50', guardCtx);
    expect(selfCheck.valid).toBe(false);
    expect(selfCheck.reason).toContain('self-lockout');
  });

  it('rejects anti-lockout management ports (2966, 22, 9876)', () => {
    const portCheck = validateMcpTarget('198.51.100.77', guardCtx, { port: 2966 });
    expect(portCheck.valid).toBe(false);
    expect(portCheck.reason).toContain('anti-lockout');

    const sshCheck = validateMcpTarget('198.51.100.77', guardCtx, { port: 22 });
    expect(sshCheck.valid).toBe(false);
  });

  it('enforces CIDR prefix blast-radius limits (/24 IPv4, /64 IPv6)', () => {
    expect(validateMcpTarget('198.51.0.0/16', guardCtx).valid).toBe(false);
    expect(validateMcpTarget('2001:db8::/48', guardCtx).valid).toBe(false);

    const validV4Subnet = validateMcpTarget('198.51.100.0/24', guardCtx);
    expect(validV4Subnet.valid).toBe(true);
    expect(validV4Subnet.normalizedTarget).toBe('198.51.100.0/24');

    const validV4Host = validateMcpTarget('198.51.100.42/32', guardCtx);
    expect(validV4Host.valid).toBe(true);
    expect(validV4Host.normalizedTarget).toBe('198.51.100.42');

    const validV6Subnet = validateMcpTarget('2001:db8:abcd:1234::/64', guardCtx);
    expect(validV6Subnet.valid).toBe(true);
  });

  it('enforces honeypot / redirection target allowlists', () => {
    expect(
      validateRedirectTargetAllowlist('10.99.0.10:2222', baseLimits.allowedRedirectTargets).valid
    ).toBe(true);
    expect(
      validateRedirectTargetAllowlist('10.99.1.55:8080', baseLimits.allowedRedirectTargets).valid
    ).toBe(true);
    expect(
      validateRedirectTargetAllowlist('198.51.100.99:4444', baseLimits.allowedRedirectTargets).valid
    ).toBe(false);
  });

  it('matches IPv4 and IPv6 addresses against CIDRs accurately', () => {
    expect(isIpInCidr('10.42.5.19', '10.42.0.0/16')).toBe(true);
    expect(isIpInCidr('10.43.5.19', '10.42.0.0/16')).toBe(false);
    expect(isIpInCidr('2001:db8:1::42', '2001:db8:1::/48')).toBe(true);
  });

  it('places loopback and anti-lockout rules before @blocked_ips in compiled nftables', () => {
    const state = DesiredStateSchema.parse({
      version: 1,
      system: {
        hostname: 'axonwall',
        domain: 'local',
        timezone: 'UTC',
        dnsServers: ['1.1.1.1'],
        flowtableOffload: false,
        antiLockout: {
          enabled: true,
          interfaces: ['lan'],
          ports: [2966, 22],
        },
      },
      interfaces: [
        { name: 'wan', device: 'eth0', role: 'wan', enabled: true, dhcp: true },
        { name: 'lan', device: 'eth1', role: 'lan', enabled: true, dhcp: false, ipv4Address: '192.168.1.1/24' },
      ],
      rules: [],
      nat: [],
      aliases: [],
      routes: [],
    });

    const compiled = compileNftables(state);
    const loIdx = compiled.nftScript.indexOf('iif "lo" accept');
    const antiLockoutIdx = compiled.nftScript.indexOf('comment "anti-lockout"');
    const blockedIpsIdx = compiled.nftScript.indexOf('ip saddr @blocked_ips drop');

    expect(loIdx).toBeGreaterThan(0);
    expect(antiLockoutIdx).toBeGreaterThan(loIdx);
    expect(blockedIpsIdx).toBeGreaterThan(antiLockoutIdx);
  });
});
