import { describe, it, expect } from 'vitest';
import { DesiredStateSchema } from '../../schemas/index.js';
import { compileObservabilityBundle } from './index.js';
import { compileNftables } from '../nft/index.js';

describe('Unified Edge Observability & Offload Compiler', () => {
  it('compiles observability_config.json with nodeId, resolved URLs, buffer defaults, and firewall rule metadata', () => {
    const ruleId = 'aaaaaaaa-1111-4111-8111-111111111111';
    const state = DesiredStateSchema.parse({
      system: { hostname: 'checkpoint1' },
      interfaces: [
        { name: 'wan', device: 'enp3s0', type: 'dhcp', role: 'wan', enabled: true },
        { name: 'lan', device: 'enp5s0', type: 'static', role: 'lan', enabled: true, ipv4Address: '10.60.0.1/24' },
      ],
      rules: [
        {
          id: ruleId,
          interface: 'wan',
          direction: 'in',
          action: 'block',
          protocol: 'tcp',
          destinationPort: '22',
          log: true,
          enabled: true,
          description: 'Block WAN SSH scans',
        },
      ],
      observability: {
        offload: {
          enabled: true,
          nodeId: 'edge-dc-01',
          hubUrl: 'https://10.8.0.10:2966/',
          collectorHost: '10.8.0.10',
          collectorPort: 2055,
          ipfixTransport: 'tls',
          ingestToken: 'axw_svc_secret123',
          metrics: {
            enabled: true,
            exposeScrape: true,
            scrapeBind: '10.8.0.1',
            scrapePort: 9105,
          },
          logs: {
            enabled: true,
            nflog: { enabled: true, group: 0, rateLimitPerSec: 25 },
            unboundDns: { enabled: true },
            keaDhcp: { enabled: true },
          },
        },
      },
      dhcp: { enabled: true },
      dns: { enabled: true },
      wireguard: { enabled: true, listenPort: 51820, address: '10.8.0.1/24', peers: [] },
    });

    const bundle = compileObservabilityBundle(state);
    expect(bundle.enabled).toBe(true);
    expect(bundle.nodeId).toBe('edge-dc-01');
    expect(bundle.offload.resolvedRemoteWriteUrl).toBe('https://10.8.0.10:2966/vm/api/v1/write');
    expect(bundle.offload.resolvedVictoriaLogsUrl).toBe('https://10.8.0.10:2966/vl/insert/jsonline');
    expect(bundle.offload.buffer.maxMemoryMB).toBe(24);
    expect(bundle.firewallRules['aaaaaaaa']).toEqual({
      id: ruleId,
      description: 'Block WAN SSH scans',
      action: 'block',
      interface: 'wan',
    });

    const compiled = compileNftables(state);
    const obsFile = compiled.files.find((f) => f.path === '/etc/axonwall/managed/observability_config.json');
    expect(obsFile).toBeDefined();
    expect(obsFile?.fileMode).toBe(0o600);

    // Rate-limited NFLOG emission
    expect(compiled.nftScript).toContain('limit rate 25/second log prefix "axonwall-rule:aaaaaaaa: " group 0');

    // Unbound DNS query logging & Kea DHCP lease logging enabled via offload profile
    const unboundFile = compiled.files.find((f) => f.path === '/etc/unbound/unbound.conf.d/axonwall.conf');
    expect(unboundFile?.content).toContain('log-queries: yes');
    const keaFile = compiled.files.find((f) => f.path === '/etc/kea/kea-dhcp4.conf');
    expect(keaFile?.content).toContain('/var/log/axonwall/kea-dhcp4.log');

    // Scrape firewall allow rule emitted on trusted LAN/wg0 interfaces
    expect(compiled.nftScript).toContain('tcp dport 9105 accept comment "observability-metrics-scrape"');
  });
});
