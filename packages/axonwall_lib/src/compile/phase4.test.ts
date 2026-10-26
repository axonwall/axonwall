import { describe, it, expect } from 'vitest';
import {
  compileKeepalived,
  compileConntrackd,
  filterHaSyncState,
  compileKeaHaHook,
} from './ha/index.js';
import { compileHaProxy } from './haproxy/index.js';
import { compileFreeRadiusClients } from './freeradius/index.js';
import { compileSnmpd } from './snmp/index.js';
import { compileNutUps } from './nut/index.js';
import {
  BUILTIN_PLUGINS,
  validatePluginManifest,
  findPluginById,
  isPluginAllowed,
  isPluginEnabled,
} from '../plugins/index.js';
import { aggregateFlows, serviceNameForPort, type FlowRecord } from '../telemetry/index.js';
import type {
  HighAvailabilityConfig,
  DesiredState,
  HaProxyPluginConfig,
  FreeRadiusPluginConfig,
  SnmpPluginConfig,
  NutUpsConfig,
} from '../schemas/index.js';

describe('Phase 4: High Availability Compilers', () => {
  const mockHaConfig: HighAvailabilityConfig = {
    enabled: true,
    nodeRole: 'master',
    peerAddress: '192.168.1.2',
    peerPort: 2966,
    vrrpInstances: [
      {
        name: 'VI_WAN',
        vrid: 51,
        interface: 'eth0',
        priority: 150,
        virtualIps: ['192.168.1.254/24'],
        authPassword: 'secretpassword',
      },
      {
        name: 'VI_LAN',
        vrid: 52,
        interface: 'eth1',
        priority: 150,
        virtualIps: ['192.168.100.1/24'],
      },
    ],
    conntrackSync: {
      enabled: true,
      interface: 'eth0',
      protocol: 'unicast',
      peerAddress: '192.168.1.2',
      port: 3780,
    },
    sqliteSync: {
      enabled: false,
      mode: 'direct_stream',
      databases: ['/var/lib/axonwall/headscale/db.sqlite'],
      syncIntervalSeconds: 5,
      listenPort: 9876,
      transport: 'token-http',
      requireSignedPayloads: false,
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
    maintenanceMode: false,
  };

  it('compiles keepalived.conf with VRRP instances and priority', () => {
    const output = compileKeepalived(mockHaConfig, 'axon-node-1');
    expect(output).toContain('router_id axon-node-1');
    expect(output).toContain('vrrp_instance VI_WAN');
    expect(output).toContain('state MASTER');
    expect(output).toContain('priority 150');
    expect(output).toContain('virtual_router_id 51');
    expect(output).toContain('192.168.1.254/24');
    expect(output).toContain('auth_type PASS');
    expect(output).toContain('notify_master');
  });

  it('drops priority to 1 in maintenance mode for clean failover', () => {
    const maintConfig: HighAvailabilityConfig = {
      ...mockHaConfig,
      maintenanceMode: true,
    };
    const output = compileKeepalived(maintConfig, 'axon-node-1');
    expect(output).toContain('priority 1');
  });

  it('compiles conntrackd.conf for FTFW UDP unicast sync', () => {
    const output = compileConntrackd(mockHaConfig, '192.168.1.1');
    expect(output).toContain('Mode FTFW');
    expect(output).toContain('IPv4_address 192.168.1.1');
    expect(output).toContain('IPv4_Destination_Address 192.168.1.2');
    expect(output).toContain('Port 3780');
    expect(output).toContain('Interface eth0');
    expect(output).toContain('Path /var/run/conntrackd.ctl');
  });

  it('filters DesiredState based on enabled sync sections', () => {
    const fullState: DesiredState = {
      version: 1,
      system: {
        hostname: 'axonwall',
        domain: 'local',
        dnsServers: ['1.1.1.1'],
        timezone: 'UTC',
        flowtableOffload: true,
        antiLockout: { enabled: true, interface: 'lan', ports: [22, 80, 443, 3000] },
      },
      interfaces: [
        { name: 'lan', device: 'eth1', type: 'static', enabled: true, mtu: 1500, description: '' },
      ],
      vlans: [],
      bridges: [],
      bonds: [],
      virtualIps: [],
      vrfs: [],
      aliases: [
        { name: 'Admins', type: 'host', entries: ['10.0.0.5'], description: '', enabled: true },
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
          destination: 'any',
          destinationPort: '80',
          log: false,
          enabled: true,
          description: '',
          sortOrder: 10,
        },
      ],
      nat: [],
      gateways: [],
      gatewayGroups: [],
      dhcp: { enabled: true, subnets: [] },
      dns: {
        enabled: true,
        listenPort: 53,
        dnssec: true,
        dotEnabled: false,
        dotUpstreams: [],
        hostOverrides: [],
      },
      routes: [],
    };

    const filtered = filterHaSyncState(fullState, {
      interfaces: false,
      firewall: true,
      dhcp: false,
      dns: false,
      aliases: true,
      vpn: false,
      sqlite: false,
    });

    expect(filtered.rules).toHaveLength(1);
    expect(filtered.aliases).toHaveLength(1);
    expect(filtered.interfaces).toBeUndefined();
    expect(filtered.dhcp).toBeUndefined();
  });

  it('compiles Kea DHCP HA hook configuration', () => {
    const hook = compileKeaHaHook(mockHaConfig, '192.168.1.1');
    expect(hook).not.toBeNull();
    expect(hook?.parameters['high-availability'][0]['this-server-name']).toBe('axon-primary');
    expect(hook?.parameters['high-availability'][0].mode).toBe('hot-standby');
    expect(hook?.parameters['high-availability'][0].peers).toHaveLength(2);
  });
});

describe('Phase 4: Plugin Compilers', () => {
  it('compiles HAProxy reverse proxy configuration', () => {
    const config: HaProxyPluginConfig = {
      enabled: true,
      mode: 'http',
      frontends: [
        {
          name: 'fe_https',
          bindPort: 443,
          ssl: true,
          certName: 'axonwall-cert',
          defaultBackend: 'be_apps',
        },
      ],
      backends: [
        {
          name: 'be_apps',
          mode: 'http',
          balance: 'roundrobin',
          servers: [
            { name: 'app1', address: '192.168.100.10', port: 8080, check: true },
            { name: 'app2', address: '192.168.100.11', port: 8080, check: true },
          ],
        },
      ],
    };

    const output = compileHaProxy(config);
    expect(output).toContain('frontend fe_https');
    expect(output).toContain('bind *:443 ssl crt /etc/axonwall/certs/axonwall-cert.pem');
    expect(output).toContain('default_backend be_apps');
    expect(output).toContain('backend be_apps');
    expect(output).toContain('balance roundrobin');
    expect(output).toContain('server app1 192.168.100.10:8080 check');
    expect(output).toContain('server app2 192.168.100.11:8080 check');
  });

  it('sanitizes HAProxy identifiers and certName against path traversal and CRLF', () => {
    const config: HaProxyPluginConfig = {
      enabled: true,
      mode: 'http',
      frontends: [
        {
          name: 'fe\ninjection',
          bindPort: 443,
          ssl: true,
          certName: '../../shadow\nexploit',
          defaultBackend: 'be/app',
        },
      ],
      backends: [
        {
          name: 'be/app',
          mode: 'http',
          balance: 'roundrobin',
          servers: [
            { name: 'srv\n1', address: '10.0.0.1\nmalicious', port: 8080, check: true },
          ],
        },
      ],
    };
    const output = compileHaProxy(config);
    expect(output).not.toContain('../../');
    expect(output).not.toContain('\nexploit');
    expect(output).not.toContain('fe\ninjection');
    expect(output).not.toContain('10.0.0.1\nmalicious');
    expect(output).toContain('frontend fe_injection');
    expect(output).toContain('ssl crt /etc/axonwall/certs/______shadow_exploit.pem');
    expect(output).toContain('server srv_1 10.0.0.1malicious:8080');
  });

  it('compiles FreeRADIUS clients configuration', () => {
    const config: FreeRadiusPluginConfig = {
      enabled: true,
      authPort: 1812,
      acctPort: 1813,
      ldapSync: true,
      clients: [
        {
          name: 'ap_office_1',
          ipAddress: '192.168.100.200',
          secret: 'radiussecret123',
        },
      ],
    };

    const output = compileFreeRadiusClients(config);
    expect(output).toContain('client localhost');
    expect(output).toContain('client ap_office_1');
    expect(output).toContain('ipaddr = 192.168.100.200');
    expect(output).toContain('secret = "radiussecret123"');
  });

  it('compiles Net-SNMP snmpd configuration', () => {
    const config: SnmpPluginConfig = {
      enabled: true,
      community: 'secureReadOnly',
      sysLocation: 'Datacenter Rack 4',
      sysContact: 'ops@example.com',
      listenPort: 161,
    };

    const output = compileSnmpd(config);
    expect(output).toContain('rocommunity secureReadOnly default');
    expect(output).toContain('sysLocation Datacenter Rack 4');
    expect(output).toContain('sysContact ops@example.com');
  });

  it('compiles NUT UPS configuration', () => {
    const config: NutUpsConfig = {
      enabled: true,
      name: 'cyberpower1500',
      driver: 'usbhid-ups',
      port: 'auto',
      shutdownBatteryPct: 25,
      lowBatteryRuntimeSec: 360,
    };

    const { upsConf, nutConf } = compileNutUps(config);
    expect(upsConf).toContain('[cyberpower1500]');
    expect(upsConf).toContain('driver = usbhid-ups');
    expect(upsConf).toContain('override.battery.charge.low = 25');
    expect(nutConf).toContain('MODE=standalone');
  });
});

describe('Phase 4: Plugin Framework & Registry', () => {
  it('contains builtin plugins with valid manifests', () => {
    expect(BUILTIN_PLUGINS.length).toBeGreaterThanOrEqual(5);
    const haproxy = findPluginById('haproxy');
    expect(haproxy).toBeDefined();
    expect(haproxy?.name).toContain('HAProxy');

    for (const plugin of BUILTIN_PLUGINS) {
      expect(() => validatePluginManifest(plugin)).not.toThrow();
    }
  });

  it('validates plugin privileges correctly', () => {
    const haproxy = findPluginById('haproxy')!;
    expect(isPluginAllowed(haproxy, ['services.haproxy', 'system.certificates'])).toBe(true);
    expect(isPluginAllowed(haproxy, ['services.other'])).toBe(false);
    expect(isPluginAllowed(haproxy, ['*'])).toBe(true);
  });

  it('includes headscale as a builtin extension plugin with mesh menu entry', () => {
    const headscale = findPluginById('headscale');
    expect(headscale).toBeDefined();
    expect(headscale?.name).toContain('Headscale');
    expect(headscale?.menuEntry).toEqual({
      title: 'Mesh VPN (Headscale)',
      path: '/vpn/mesh',
      icon: 'Network',
    });
  });

  it('evaluates whether a plugin is enabled/on or disabled/off', () => {
    // When state is undefined or empty
    expect(isPluginEnabled('nut-ups', undefined)).toBe(false);
    expect(isPluginEnabled('nut-ups', {})).toBe(false);
    expect(isPluginEnabled('headscale', {})).toBe(false);

    // NUT UPS
    expect(isPluginEnabled('nut-ups', { ups: { enabled: false } as any })).toBe(false);
    expect(isPluginEnabled('nut-ups', { ups: { enabled: true } as any })).toBe(true);
    expect(isPluginEnabled('nut-ups', { plugins: [{ id: 'nut-ups', enabled: true }] })).toBe(true);
    expect(isPluginEnabled('nut-ups', { plugins: [{ id: 'nut-ups', enabled: false }] })).toBe(false);

    // Headscale
    expect(isPluginEnabled('headscale', { headscale: { enabled: false } as any })).toBe(false);
    expect(isPluginEnabled('headscale', { headscale: { enabled: true } as any })).toBe(true);
    expect(isPluginEnabled('headscale', { plugins: [{ id: 'headscale', enabled: true }] })).toBe(true);

    // HAProxy
    expect(isPluginEnabled('haproxy', { haproxy: { enabled: false } as any })).toBe(false);
    expect(isPluginEnabled('haproxy', { haproxy: { enabled: true } as any })).toBe(true);

    // Generic extension plugin
    expect(isPluginEnabled('tailscale', { plugins: [{ id: 'tailscale', enabled: true }] })).toBe(true);
    expect(isPluginEnabled('tailscale', { plugins: [{ id: 'tailscale', enabled: false }] })).toBe(false);

    // Modern Operator Shell & Editor (cli-workstation) is enabled by default and can be explicitly disabled
    expect(isPluginEnabled('cli-workstation', undefined)).toBe(true);
    expect(isPluginEnabled('cli-workstation', {})).toBe(true);
    expect(isPluginEnabled('cli-workstation', { plugins: [] })).toBe(true);
    expect(isPluginEnabled('cli-workstation', { plugins: [{ id: 'cli-workstation', enabled: true }] })).toBe(true);
    expect(isPluginEnabled('cli-workstation', { plugins: [{ id: 'cli-workstation', enabled: false }] })).toBe(false);
  });
});

describe('Phase 4: Telemetry & Flow Analytics', () => {
  it('maps common ports to human-readable service names', () => {
    expect(serviceNameForPort(443)).toBe('HTTPS');
    expect(serviceNameForPort(53)).toBe('DNS');
    expect(serviceNameForPort(51820)).toBe('WireGuard');
    expect(serviceNameForPort(9999)).toBe('Port 9999');
  });

  it('aggregates raw flows into top talkers, destinations, and ports', () => {
    const flows: FlowRecord[] = [
      {
        timestamp: 1710000000000,
        protocol: 'TCP',
        srcIp: '192.168.100.50',
        srcPort: 54321,
        dstIp: '1.1.1.1',
        dstPort: 443,
        bytes: 50000,
        packets: 40,
        action: 'pass',
      },
      {
        timestamp: 1710000000000,
        protocol: 'TCP',
        srcIp: '192.168.100.50',
        srcPort: 54322,
        dstIp: '1.1.1.1',
        dstPort: 443,
        bytes: 30000,
        packets: 25,
        action: 'pass',
      },
      {
        timestamp: 1710000000000,
        protocol: 'UDP',
        srcIp: '192.168.100.60',
        srcPort: 43210,
        dstIp: '8.8.8.8',
        dstPort: 53,
        bytes: 1200,
        packets: 8,
        action: 'pass',
      },
    ];

    const report = aggregateFlows(flows);
    expect(report.totalBytes).toBe(81200);
    expect(report.totalPackets).toBe(73);
    expect(report.topTalkers[0].ip).toBe('192.168.100.50');
    expect(report.topTalkers[0].bytes).toBe(80000);
    expect(report.topDestinations[0].ip).toBe('1.1.1.1');
    expect(report.topPorts[0].service).toBe('HTTPS');
    expect(report.topPorts[0].bytes).toBe(80000);
    expect(report.topPorts[1].service).toBe('DNS');
  });
});
