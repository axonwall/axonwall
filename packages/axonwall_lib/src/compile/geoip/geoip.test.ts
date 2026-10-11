import { describe, it, expect } from 'vitest';
import { compileGeoIp, COUNTRY_CIDR_TABLE } from './index.js';
import { compileNftables } from '../nft/index.js';
import type { DesiredState } from '../../schemas/index.js';

describe('GeoIP Location-Based Filtering Compiler', () => {
  it('returns empty results when disabled or countries list is empty', () => {
    const disabledRes = compileGeoIp({
      enabled: false,
      mode: 'block',
      direction: 'in',
      countries: ['CN', 'RU'],
      excludedSubnets: [],
      log: true,
      description: 'Test disabled',
    });
    expect(disabledRes.nftSetDefinitions).toHaveLength(0);
    expect(disabledRes.inputRules).toHaveLength(0);
    expect(disabledRes.forwardRules).toHaveLength(0);

    const emptyRes = compileGeoIp({
      enabled: true,
      mode: 'block',
      direction: 'in',
      countries: [],
      excludedSubnets: [],
      log: true,
      description: 'Test empty',
    });
    expect(emptyRes.nftSetDefinitions).toHaveLength(0);
  });

  it('compiles block mode for high-risk countries with interval sets and exclusions', () => {
    const res = compileGeoIp({
      enabled: true,
      mode: 'block',
      direction: 'both',
      countries: ['CN', 'RU', 'KP'],
      excludedSubnets: ['10.0.0.0/8', '192.168.0.0/16'],
      log: true,
      description: 'Block High-Risk Threat Origins',
    });

    // Check set definitions
    expect(res.nftSetDefinitions.length).toBeGreaterThan(0);
    const setDefJoined = res.nftSetDefinitions.join('\n');
    expect(setDefJoined).toContain('set set_geoip_countries');
    expect(setDefJoined).toContain('type ipv4_addr');
    expect(setDefJoined).toContain('flags interval');
    expect(setDefJoined).toContain('set set_geoip_excluded');
    expect(setDefJoined).toContain('10.0.0.0/8');

    // CN, RU, and KP CIDRs should be in elements
    expect(setDefJoined).toContain('175.45.176.0/22'); // KP
    expect(setDefJoined).toContain('1.0.1.0/24');       // CN
    expect(setDefJoined).toContain('2.60.0.0/14');      // RU

    // Rules
    expect(res.inputRules.length).toBe(1);
    expect(res.inputRules[0]).toContain('ip saddr != @set_geoip_excluded ip saddr @set_geoip_countries log prefix "axonwall-geoip: " drop');
    expect(res.forwardRules.length).toBe(2); // inbound and outbound in forward chain
    expect(res.forwardRules[0]).toContain('ip saddr != @set_geoip_excluded ip saddr @set_geoip_countries');
    expect(res.forwardRules[1]).toContain('ip daddr != @set_geoip_excluded ip daddr @set_geoip_countries');
  });

  it('compiles allow / whitelist mode correctly', () => {
    const res = compileGeoIp({
      enabled: true,
      mode: 'allow',
      direction: 'in',
      countries: ['US', 'DE'],
      excludedSubnets: ['192.168.1.0/24'],
      log: false,
      description: 'Domestic Whitelist Only',
    });

    expect(res.inputRules[0]).toContain('ip saddr != @set_geoip_excluded ip saddr != @set_geoip_countries drop comment "geoip-inbound-whitelist-drop"');
    expect(res.inputRules[0]).not.toContain('log prefix');
  });

  it('integrates seamlessly within compileNftables', () => {
    const dummyState: DesiredState = {
      version: 1,
      system: {
        hostname: 'axonwall-test',
        domain: 'local',
        dnsServers: [],
        timezone: 'UTC',
        flowtableOffload: false,
        antiLockout: {
          enabled: true,
          interface: 'lan',
          ports: [80, 443],
        },
      },
      interfaces: [
        { name: 'wan', device: 'eth0', type: 'dhcp', enabled: true, mtu: 1500, description: '' },
        { name: 'lan', device: 'eth1', type: 'static', enabled: true, mtu: 1500, description: '' },
      ],
      vlans: [],
      bridges: [],
      bonds: [],
      virtualIps: [],
      vrfs: [],
      aliases: [],
      rules: [],
      nat: [],
      gateways: [],
      gatewayGroups: [],
      dhcp: { enabled: false, subnets: [] },
      dns: {
        enabled: false,
        listenPort: 53,
        dnssec: false,
        dotEnabled: false,
        dotUpstreams: [],
        hostOverrides: [],
      },
      routes: [],
      geoip: {
        enabled: true,
        mode: 'block',
        direction: 'in',
        countries: ['IR', 'SY'],
        excludedSubnets: ['10.0.0.0/8'],
        log: true,
        description: 'Block Embargoed Nations',
      },
    };

    const compiled = compileNftables(dummyState);
    expect(compiled.nftScript).toContain('set set_geoip_countries');
    expect(compiled.nftScript).toContain('82.137.200.0/21'); // Syria
    expect(compiled.nftScript).toContain('ip saddr @set_geoip_countries log prefix "axonwall-geoip: " drop');
  });
});
