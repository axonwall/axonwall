import { describe, it, expect } from 'vitest';
import { compileConntrackd } from './index.js';
import type { HighAvailabilityConfig } from '../../schemas/index.js';

describe('compileConntrackd', () => {
  it('compiles standard unicast UDP conntrackd configuration', () => {
    const ha: HighAvailabilityConfig = {
      enabled: true,
      nodeRole: 'master',
      peerAddress: '192.168.100.2',
      peerPort: 2966,
      vrrpInstances: [],
      conntrackSync: {
        enabled: true,
        interface: 'eth2',
        protocol: 'unicast',
        peerAddress: '192.168.100.2',
        port: 3780,
        multicastGroup: '225.0.0.50',
        bufferSize: 12492800,
        filterIgnoreIps: ['192.168.100.1', '192.168.100.2'],
        mode: 'FTFW',
      },
      sqliteSync: {
        enabled: false,
        mode: 'direct_stream',
        databases: [],
        syncIntervalSeconds: 5,
        listenPort: 9876,
        transport: 'token-http',
      },
      syncSections: {
        interfaces: false,
        firewall: true,
        dhcp: true,
        dns: true,
        aliases: true,
        vpn: true,
        sqlite: true,
      },
    };

    const conf = compileConntrackd(ha, '192.168.100.1');
    expect(conf).toContain('Mode FTFW');
    expect(conf).toContain('UDP {');
    expect(conf).toContain('IPv4_address 192.168.100.1');
    expect(conf).toContain('IPv4_Destination_Address 192.168.100.2');
    expect(conf).toContain('Port 3780');
    expect(conf).toContain('Interface eth2');
    expect(conf).toContain('SndSocketBuffer 12492800');
    expect(conf).toContain('Protocol Accept {\n            TCP\n            UDP\n            ICMP\n        }');
    expect(conf).toContain('IPv4_address 192.168.100.1');
    expect(conf).toContain('IPv4_address 192.168.100.2');
    expect(conf).toContain('/var/run/conntrackd.ctl');
  });

  it('compiles multicast conntrackd configuration', () => {
    const ha: HighAvailabilityConfig = {
      enabled: true,
      nodeRole: 'backup',
      peerAddress: '',
      peerPort: 2966,
      vrrpInstances: [],
      conntrackSync: {
        enabled: true,
        interface: 'vlan100',
        protocol: 'multicast',
        port: 3780,
        multicastGroup: '225.0.0.99',
        bufferSize: 8388608,
        filterIgnoreIps: [],
        mode: 'NOTRACK',
      },
      sqliteSync: {
        enabled: false,
        mode: 'direct_stream',
        databases: [],
        syncIntervalSeconds: 5,
        listenPort: 9876,
        transport: 'token-http',
      },
      syncSections: {
        interfaces: false,
        firewall: true,
        dhcp: true,
        dns: true,
        aliases: true,
        vpn: true,
        sqlite: true,
      },
    };

    const conf = compileConntrackd(ha, '10.0.100.2');
    expect(conf).toContain('Mode NOTRACK');
    expect(conf).toContain('Multicast {');
    expect(conf).toContain('IPv4_address 225.0.0.99');
    expect(conf).toContain('IPv4_interface 10.0.100.2');
    expect(conf).toContain('Interface vlan100');
    expect(conf).toContain('SndSocketBuffer 8388608');
  });
});
