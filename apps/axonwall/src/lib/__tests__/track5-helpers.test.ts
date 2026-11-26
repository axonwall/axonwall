import { describe, expect, it } from 'vitest';
import {
  isAbsoluteHttpHref,
  safeAppHref,
  safeHttpHref,
} from '../safe-href';
import {
  allocateLowestUnusedInt,
  allocateLowestUnusedSuffixedName,
  mergeCaptivePortalConfig,
  mergeHaConntrackSync,
  mergeHaVrrpFirstInstance,
  mergeSatelliteNodesForPersist,
  mergeSuricataConfig,
  mergeTlsDecryptionConfig,
  mergeWireGuardPeers,
  parseCsvTokens,
  parseCsvVlanIds,
  parseNonNegativeIntInput,
  resolveNetFlowDraftConfig,
  resolveObservabilityDraftConfig,
} from '../state-preservation';

describe('safe-href XSS and cross-origin guards', () => {
  it('allows valid http and https URLs and blocks dangerous schemes', () => {
    expect(safeHttpHref('https://librenms.example.com/devices')).toBe(
      'https://librenms.example.com/devices'
    );
    expect(safeHttpHref('http://10.0.0.10:8000')).toBe('http://10.0.0.10:8000');
    expect(safeHttpHref('javascript:alert(document.domain)', 'https://fallback.local')).toBe(
      'https://fallback.local'
    );
    expect(safeHttpHref('data:text/html,<script>alert(1)</script>')).toBe('#');
    expect(safeHttpHref('vbscript:msgbox(1)')).toBe('#');
    expect(safeHttpHref('javascript:alert(1)', 'javascript:evil()')).toBe('#');
    expect(safeHttpHref('https://bad\nurl.example')).toBe('#');
  });

  it('validates app and cross-origin portal hrefs without allowing open redirects', () => {
    expect(safeAppHref('/vpn')).toBe('/vpn');
    expect(safeAppHref('https://portal.example.com:2966/vpn')).toBe(
      'https://portal.example.com:2966/vpn'
    );
    expect(safeAppHref('//evil.example/phish', '/login')).toBe('/login');
    expect(safeAppHref('/\\evil.example', '/login')).toBe('/login');
    expect(safeAppHref('javascript:alert(1)', '/login')).toBe('/login');

    expect(isAbsoluteHttpHref('https://portal.example.com/vpn')).toBe(true);
    expect(isAbsoluteHttpHref('http://10.0.0.1/login')).toBe(true);
    expect(isAbsoluteHttpHref('/vpn')).toBe(false);
  });
});

describe('fleet satellite deep-merge preservation', () => {
  it('preserves non-UI SatelliteNodeSchema fields on save', () => {
    const existing = [
      {
        id: 'edge-1',
        name: 'Branch Edge',
        role: 'edge-ngfw' as const,
        haState: 'active' as const,
        edgePlacement: 'dedicated' as const,
        ipv6Mode: 'delegated' as const,
        wanIpv6Prefix: '2001:db8:1::/56',
        wanAddress: '203.0.113.10/24',
        lanAddress: '10.20.0.1/24',
        ztpToken: 'ztp-secret-token',
        portForwards: [
          { proto: 'tcp' as const, wanPort: 8443, targetIp: '10.20.0.5', targetPort: 443 },
        ],
        ipv6Allow: [{ proto: 'tcp' as const, dstIp6: '2001:db8:1::5', dstPort: 443 }],
        zones: [
          { name: 'corp', vlanId: 10, ipv4Cidr: '10.20.10.0/24', ipv6Mode: 'delegated' as const },
        ],
        arch: 'amd64' as const,
        os: 'AxonWall Edge UKI',
        status: 'online' as const,
        wireguard: {
          tunnelIp: '10.99.0.2/24',
          publicKey: 'wg-pub-key-123',
          endpoint: '198.51.100.2:51820',
          connected: true,
        },
        wifi: [
          {
            radio: 'wlan0',
            ssid: 'CorpWifi',
            channel: 36,
            security: 'wpa3-sae' as const,
            fastRoaming: { enabled: true, mobilityDomain: 'a1b2' },
            clientsCount: 4,
            enabled: true,
          },
        ],
        metrics: {
          cpuUsagePercent: 12,
          memUsagePercent: 35,
          uptimeSeconds: 999,
          activeConns: 42,
          rxBytesTotal: 123456,
          txBytesTotal: 654321,
          kernelVersion: '6.12.0',
          skuProfile: 'sku-vm-virtio',
        },
        activePolicyVersion: 3,
      },
    ];

    const merged = mergeSatelliteNodesForPersist(existing, [
      {
        id: 'edge-1',
        name: 'Branch Edge Renamed',
        role: 'edge-ngfw',
        skuProfile: 'sku-vm-virtio',
        fastpathOffload: true,
        wanInterface: 'eth0',
        lanInterface: 'eth1',
        arch: 'amd64',
        os: 'AxonWall Edge UKI',
        ip: '203.0.113.10',
        tunnelIp: '10.99.0.2/24',
        wgConnected: true,
        status: 'online',
        cpuPercent: 18,
        memPercent: 40,
        activeConns: 55,
        offloadedConns: 12,
        pid1Mode: true,
        uptimeSeconds: 1050,
        wifiRadios: [
          {
            radio: 'wlan0',
            ssid: 'CorpWifi',
            channel: 36,
            security: 'wpa3-sae',
            clientsCount: 5,
            enabled: true,
          },
        ],
        lastSeen: 'Just now',
        activePolicyVersion: 4,
      },
    ]);

    expect(merged).toHaveLength(1);
    const node = merged[0]!;
    expect(node.name).toBe('Branch Edge Renamed');
    expect(node.activePolicyVersion).toBe(4);
    expect(node.haState).toBe('active');
    expect(node.ipv6Mode).toBe('delegated');
    expect(node.wanAddress).toBe('203.0.113.10/24');
    expect(node.lanAddress).toBe('10.20.0.1/24');
    expect(node.ztpToken).toBe('ztp-secret-token');
    expect(node.portForwards).toHaveLength(1);
    expect(node.zones).toHaveLength(1);
    expect(node.ipv6Allow).toHaveLength(1);
    expect(node.wireguard.publicKey).toBe('wg-pub-key-123');
    expect(node.wireguard.endpoint).toBe('198.51.100.2:51820');
    expect(node.wifi?.[0]?.fastRoaming).toEqual({ enabled: true, mobilityDomain: 'a1b2' });
    expect(node.metrics?.kernelVersion).toBe('6.12.0');
    expect(node.metrics?.rxBytesTotal).toBe(123456);
  });
});

describe('untouched field preservation on VPN, Security, and HA saves', () => {
  it('preserves WireGuard peer presharedKey across peer updates', () => {
    const existing = [
      {
        id: 'p1',
        name: 'peer-1',
        publicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        presharedKey: 'secret-psk-value',
        allowedIps: ['10.50.0.2/32'],
        persistentKeepalive: 25,
        enabled: true,
      },
    ];
    const merged = mergeWireGuardPeers(
      [
        {
          id: 'p1',
          name: 'peer-1',
          publicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
          allowedIps: ['10.50.0.2/32'],
          enabled: false,
        },
      ],
      existing
    );
    expect(merged[0]?.presharedKey).toBe('secret-psk-value');
    expect(merged[0]?.enabled).toBe(false);
  });

  it('preserves Suricata tlsDecryption when toggling IDS/IPS', () => {
    const merged = mergeSuricataConfig(
      {
        enabled: true,
        mode: 'ips',
        interfaces: ['wan'],
        nfqueueFailOpen: true,
        nfqueueBypass: true,
        tlsDecryption: {
          enabled: true,
          caCertificateId: '11111111-1111-1111-1111-111111111111',
          transparentProxyPort: 3129,
          bypassedDomains: ['*.bank.com'],
        },
        ruleSources: [],
        homeNet: ['10.0.0.0/8'],
      },
      {
        enabled: false,
        mode: 'ids',
        defaultRuleSources: [],
        defaultHomeNet: ['192.168.0.0/16'],
      }
    );
    expect(merged.enabled).toBe(false);
    expect(merged.mode).toBe('ids');
    expect(merged.tlsDecryption?.caCertificateId).toBe('11111111-1111-1111-1111-111111111111');
  });

  it('preserves TLS Decryption caCertificateId and transparentProxyPort', () => {
    const merged = mergeTlsDecryptionConfig(
      {
        enabled: false,
        caCertificateId: '22222222-2222-2222-2222-222222222222',
        transparentProxyPort: 4129,
        bypassedDomains: [],
      },
      { enabled: true, bypassedDomains: ['*.chase.com'] }
    );
    expect(merged.caCertificateId).toBe('22222222-2222-2222-2222-222222222222');
    expect(merged.transparentProxyPort).toBe(4129);
    expect(merged.bypassedDomains).toEqual(['*.chase.com']);
  });

  it('preserves Captive Portal radiusSecret across zone saves', () => {
    const merged = mergeCaptivePortalConfig(
      { enabled: true, radiusSecret: 'super-secret-radius', zones: [] },
      [
        {
          name: 'guest',
          interface: 'opt1',
          listenPort: 8999,
          authServers: ['ldap_internal'],
          sessionTimeoutMinutes: 240,
          idleTimeoutMinutes: 30,
          passThroughMacs: [],
          passThroughIps: [],
          enableBandwidthQuotas: true,
          downloadLimitKbps: 25000,
          uploadLimitKbps: 10000,
          enabled: true,
        },
      ]
    );
    expect(merged.radiusSecret).toBe('super-secret-radius');
    expect(merged.zones).toHaveLength(1);
  });

  it('preserves VRRP secondary VIPs and conntrackSync fields on HA save', () => {
    const vrrp = mergeHaVrrpFirstInstance(
      {
        name: 'VI_WAN',
        vrid: 51,
        interface: 'eth0',
        priority: 150,
        virtualIps: ['192.168.1.254/24', '10.10.0.254/24', '172.16.0.254/24'],
      },
      { vrid: 52, primaryVip: '192.168.2.254/24', authPassword: 'secret' }
    );
    expect(vrrp.virtualIps).toEqual([
      '192.168.2.254/24',
      '10.10.0.254/24',
      '172.16.0.254/24',
    ]);

    const conntrack = mergeHaConntrackSync(
      {
        enabled: true,
        interface: 'eth2',
        protocol: 'multicast',
        port: 3780,
        multicastGroup: '225.0.0.50',
        bufferSize: 2097152,
        filterIgnoreIps: ['127.0.0.1'],
        mode: 'FTFW',
      },
      { enabled: true, syncInterface: 'eth3', peerIp: '10.0.99.2' }
    );
    expect(conntrack.multicastGroup).toBe('225.0.0.50');
    expect(conntrack.bufferSize).toBe(2097152);
    expect(conntrack.filterIgnoreIps).toEqual(['127.0.0.1']);
    expect(conntrack.mode).toBe('FTFW');
  });
});

describe('ID allocation, numeric zero handling, CSV parsing, and safe draft resolvers', () => {
  it('allocates lowest unused XFRM ID and OpenVPN device name without collisions after deletion', () => {
    expect(allocateLowestUnusedInt([30, 31], 30)).toBe(32);
    expect(allocateLowestUnusedInt([31], 30)).toBe(30);
    expect(allocateLowestUnusedSuffixedName(['ovpn-dco1'], 'ovpn-dco')).toBe('ovpn-dco0');
    expect(allocateLowestUnusedSuffixedName(['ovpn-dco0', 'ovpn-dco1'], 'ovpn-dco')).toBe(
      'ovpn-dco2'
    );
  });

  it('preserves 0 when parsing non-negative integer inputs', () => {
    expect(parseNonNegativeIntInput('0', 50)).toBe(0);
    expect(parseNonNegativeIntInput('', 50)).toBe(0);
    expect(parseNonNegativeIntInput('125', 50)).toBe(125);
  });

  it('parses CSV tokens and VLAN IDs cleanly', () => {
    expect(parseCsvTokens('10.0.0.0/8, 192.168.0.0/16, ')).toEqual([
      '10.0.0.0/8',
      '192.168.0.0/16',
    ]);
    expect(parseCsvVlanIds('10, 20, 9999, 0, abc')).toEqual([10, 20]);
  });

  it('resolves intermediate invalid NetFlow and Observability drafts without throwing ZodError', () => {
    const nf = resolveNetFlowDraftConfig({
      storage: {
        mode: 'local',
        compression: 'zstd',
        retentionHours: 0,
        maxDiskMB: 10,
        clickhouse: { enabled: false, url: 'http://127.0.0.1:8123', database: 'axonwall', username: 'admin' },
      },
    } as any);
    expect(nf.storage.maxDiskMB).toBe(10);

    const obs = resolveObservabilityDraftConfig({
      offload: {
        buffer: { maxMemoryMB: 1, diskSpoolEnabled: false, diskSpoolDir: '/tmp', diskSpoolMaxMB: 1 },
        logs: { nflog: { enabled: true, group: 0, rateLimitPerSec: 0 } },
      } as any,
    });
    expect(obs.offload.buffer.diskSpoolMaxMB).toBe(1);
    expect(obs.offload.logs.nflog.rateLimitPerSec).toBe(0);
  });
});
