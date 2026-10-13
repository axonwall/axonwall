import { describe, it, expect } from 'vitest';
import { mergeFirewallConfigs } from './merge.js';
import type { DesiredState } from '../schemas/index.js';

describe('mergeFirewallConfigs', () => {
  it('selectively merges aliases, rules, and vlans without clobbering existing interfaces', () => {
    const active: DesiredState = {
      version: 1,
      system: { hostname: 'axon-core', domain: 'local', dnsServers: [], timezone: 'UTC', flowtableOffload: true, antiLockout: { enabled: true, interface: 'lan', ports: [80, 443] } },
      interfaces: [{ name: 'lan', device: 'eth0', type: 'static', enabled: true, description: 'LAN', mtu: 1500 }],
      vlans: [{ tag: 10, parentInterface: 'eth0', vlanInterface: 'eth0.10', priority: 0, description: 'Mgmt' }],
      aliases: [{ name: 'Servers', type: 'host', entries: ['192.168.1.10'], description: '', enabled: true }],
      rules: [
        {
          action: 'pass',
          direction: 'in',
          interface: 'lan',
          protocol: 'tcp',
          source: 'any',
          sourcePort: '',
          destination: '$Servers',
          destinationPort: '443',
          enabled: true,
          quick: true,
          log: false,
          description: 'Base HTTPS',
          sortOrder: 1,
        },
      ],
      nat: [],
      gateways: [],
      gatewayGroups: [],
      bridges: [],
      bonds: [],
      virtualIps: [],
      vrfs: [],
      dhcp: { enabled: true, subnets: [] },
      dns: { enabled: true, listenPort: 53, dnssec: true, dotEnabled: true, dotUpstreams: [], hostOverrides: [] },
      routes: [],
    };

    const imported: DesiredState = {
      version: 1,
      system: { hostname: 'imported', domain: 'local', dnsServers: [], timezone: 'UTC', flowtableOffload: true, antiLockout: { enabled: true, interface: 'lan', ports: [80] } },
      interfaces: [{ name: 'dmz', device: 'eth1', type: 'static', enabled: true, description: 'DMZ', mtu: 1500 }],
      vlans: [{ tag: 20, parentInterface: 'eth0', vlanInterface: 'eth0.20', priority: 0, description: 'Guest' }],
      aliases: [
        { name: 'Servers', type: 'host', entries: ['10.0.0.50'], description: 'Imported', enabled: true },
        { name: 'Admins', type: 'host', entries: ['192.168.1.5'], description: 'Imported', enabled: true },
      ],
      rules: [
        {
          action: 'pass',
          direction: 'in',
          interface: 'lan',
          protocol: 'tcp',
          source: '$Admins',
          sourcePort: '',
          destination: '$Servers',
          destinationPort: '22',
          enabled: true,
          quick: true,
          log: false,
          description: 'SSH',
          sortOrder: 1,
        },
      ],
      nat: [],
      gateways: [],
      gatewayGroups: [],
      bridges: [],
      bonds: [],
      virtualIps: [],
      vrfs: [],
      dhcp: { enabled: true, subnets: [] },
      dns: { enabled: true, listenPort: 53, dnssec: true, dotEnabled: true, dotUpstreams: [], hostOverrides: [] },
      routes: [],
    };

    const merged = mergeFirewallConfigs(active, imported, {
      includeInterfaces: true,
      includeAliases: true,
      includeVlans: true,
      includeRules: true,
    });

    // Active interfaces preserved, new dmz interface added
    expect(merged.interfaces.length).toBe(2);
    expect(merged.interfaces[1].name).toBe('dmz');

    // VLANs merged
    expect(merged.vlans.length).toBe(2);
    expect(merged.vlans[1].tag).toBe(20);

    // Collision on alias name 'Servers' renamed to 'Servers_imported'
    expect(merged.aliases.length).toBe(3);
    const renamedAlias = merged.aliases.find((a) => a.name === 'Servers_imported');
    expect(renamedAlias).toBeDefined();

    // Rule source/destination remapped to re-named alias
    expect(merged.rules.length).toBe(2);
    expect(merged.rules[1].destination).toBe('$Servers_imported');
  });
});
