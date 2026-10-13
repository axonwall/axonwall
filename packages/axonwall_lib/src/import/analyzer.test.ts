import { describe, it, expect } from 'vitest';
import { analyzeRuleShadowing, analyzeSubnetCollisions } from './analyzer.js';
import type { FirewallRule, DesiredState } from '../schemas/index.js';

describe('analyzeRuleShadowing', () => {
  it('detects duplicate rules', () => {
    const rules: FirewallRule[] = [
      {
        action: 'pass',
        direction: 'in',
        interface: 'lan',
        protocol: 'tcp',
        source: '192.168.1.0/24',
        sourcePort: '',
        destination: '10.0.0.1',
        destinationPort: '443',
        enabled: true,
        quick: true,
        log: false,
        description: 'First rule',
        sortOrder: 1,
      },
      {
        action: 'pass',
        direction: 'in',
        interface: 'lan',
        protocol: 'tcp',
        source: '192.168.1.0/24',
        sourcePort: '',
        destination: '10.0.0.1',
        destinationPort: '443',
        enabled: true,
        quick: true,
        log: false,
        description: 'Duplicate rule',
        sortOrder: 2,
      },
    ];

    const report = analyzeRuleShadowing(rules);
    expect(report.totalRules).toBe(2);
    expect(report.issues.length).toBe(1);
    expect(report.issues[0].type).toBe('duplicate');
    expect(report.issues[0].ruleIndex).toBe(2);
    expect(report.issues[0].shadowedByIndex).toBe(1);
  });

  it('detects shadowed rules with opposing actions', () => {
    const rules: FirewallRule[] = [
      {
        action: 'block',
        direction: 'in',
        interface: 'lan',
        protocol: 'any',
        source: 'any',
        sourcePort: '',
        destination: '10.0.0.0/8',
        destinationPort: '',
        enabled: true,
        quick: true,
        log: false,
        description: 'Block all 10.x',
        sortOrder: 1,
      },
      {
        action: 'pass',
        direction: 'in',
        interface: 'lan',
        protocol: 'tcp',
        source: 'any',
        sourcePort: '',
        destination: '10.5.0.1',
        destinationPort: '443',
        enabled: true,
        quick: true,
        log: false,
        description: 'Unreachable pass rule',
        sortOrder: 2,
      },
    ];

    const report = analyzeRuleShadowing(rules);
    expect(report.issues.length).toBe(1);
    expect(report.issues[0].type).toBe('shadowed');
    expect(report.issues[0].ruleIndex).toBe(2);
  });

  it('detects redundant rules with same action', () => {
    const rules: FirewallRule[] = [
      {
        action: 'pass',
        direction: 'in',
        interface: 'lan',
        protocol: 'any',
        source: 'any',
        sourcePort: '',
        destination: '10.0.0.0/8',
        destinationPort: '',
        enabled: true,
        quick: true,
        log: false,
        description: 'Pass all 10.x',
        sortOrder: 1,
      },
      {
        action: 'pass',
        direction: 'in',
        interface: 'lan',
        protocol: 'tcp',
        source: '192.168.1.5',
        sourcePort: '',
        destination: '10.2.2.2',
        destinationPort: '80',
        enabled: true,
        quick: true,
        log: false,
        description: 'Redundant subset pass',
        sortOrder: 2,
      },
    ];

    const report = analyzeRuleShadowing(rules);
    expect(report.issues.length).toBe(1);
    expect(report.issues[0].type).toBe('redundant');
  });
});

describe('analyzeSubnetCollisions', () => {
  it('detects IP and DHCP collisions between running and imported configs', () => {
    const base = {
      interfaces: [{ name: 'lan', ipv4Address: '192.168.1.1/24' }],
      dhcp: { subnets: [{ subnet: '192.168.1.0/24' }] },
    } as any as DesiredState;

    const imported = {
      interfaces: [{ name: 'lan', ipv4Address: '192.168.20.1/24' }],
      dhcp: { subnets: [{ subnet: '192.168.1.0/24' }] },
    } as any as DesiredState;

    const report = analyzeSubnetCollisions(base, imported);
    expect(report.hasCollisions).toBe(true);
    expect(report.collisions.length).toBe(2);
    expect(report.collisions[0].type).toBe('interface_ip');
    expect(report.collisions[1].type).toBe('dhcp_pool');
  });
});
