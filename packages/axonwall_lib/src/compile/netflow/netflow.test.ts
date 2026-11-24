import { describe, it, expect } from 'vitest';
import { DesiredStateSchema } from '../../schemas/index.js';
import { enablePluginWithDependencies, disablePluginWithDependents, isPluginEnabled } from '../../plugins/index.js';
import { parseDesiredStateFromYamlFiles, serializeDesiredStateToYamlFiles } from '../../yaml/index.js';
import { compileNftables } from '../nft/index.js';
import {
  buildFlowExportCsv,
  buildTcpdumpFilter,
  compileNetFlowBundle,
  formatBps,
  formatBytes,
  resolveNetFlowConfig,
  validateFqlQuery,
} from './index.js';

describe('NetFlow / IPFIX / sFlow Collector Compiler & FQL', () => {
  it('enables and disables netflow-collector cleanly without extra OS dependencies', () => {
    const base = DesiredStateSchema.parse({});
    expect(isPluginEnabled('netflow-collector', base)).toBe(false);

    const enabled = enablePluginWithDependencies('netflow-collector', base);
    expect(isPluginEnabled('netflow-collector', enabled.state)).toBe(true);
    expect(enabled.state.netflow?.enabled).toBe(true);
    expect(enabled.state.netflow?.listeners[0]?.port).toBe(2055);

    const disabled = disablePluginWithDependents('netflow-collector', enabled.state);
    expect(isPluginEnabled('netflow-collector', disabled.state)).toBe(false);
    expect(disabled.state.netflow?.enabled).toBe(false);
  });

  it('round-trips netflow configuration inside netflow.yaml and emits managed JSON bundle', () => {
    const state = DesiredStateSchema.parse({
      plugins: [{ id: 'netflow-collector', enabled: true }],
      interfaces: [
        { name: 'lan1', device: 'eth1', type: 'static', enabled: true, ipv4Address: '10.80.0.1/24' },
      ],
      aliases: [
        { name: 'threat_blocklist', type: 'network', entries: ['198.51.100.0/24'], enabled: true },
      ],
      netflow: {
        enabled: true,
        storage: { mode: 'hybrid', retentionHours: 336, maxDiskMB: 8192 },
      },
    });

    const yamlFiles = serializeDesiredStateToYamlFiles(state);
    expect(yamlFiles['netflow.yaml']).toContain('retentionHours: 336');
    const parsed = parseDesiredStateFromYamlFiles(yamlFiles);
    expect(parsed.netflow?.storage.mode).toBe('hybrid');
    expect(parsed.netflow?.storage.maxDiskMB).toBe(8192);

    const nft = compileNftables(state);
    const managed = nft.files.find((f) => f.path === '/etc/axonwall/managed/netflow_config.json');
    expect(managed).toBeDefined();
    expect(managed?.fileMode).toBe(0o600);

    const bundle = compileNetFlowBundle(state);
    expect(bundle.enabled).toBe(true);
    expect(bundle.threatCidrs).toEqual([{ alias: 'threat_blocklist', entry: '198.51.100.0/24' }]);
    expect(bundle.localInterfaces[0]?.device).toBe('eth1');
  });

  it('carries forward legacy observability.flowExport targets seamlessly', () => {
    const state = DesiredStateSchema.parse({
      plugins: [{ id: 'netflow-collector', enabled: true }],
      observability: {
        flowExport: {
          enabled: true,
          version: 'ipfix',
          collectorHost: '10.80.0.50',
          collectorPort: 4739,
          interfaces: ['eth0', 'eth1'],
        },
      },
    });
    const resolved = resolveNetFlowConfig(state);
    expect(resolved.selfExport.targets.some((t) => t.host === '10.80.0.50' && t.port === 4739)).toBe(true);
  });

  it('validates FQL queries accurately and rejects invalid fields or unbalanced parens', () => {
    expect(validateFqlQuery('src=10.80.0.0/24 and (dst_port=443 or proto=tcp) and bytes>10MB')).toMatchObject({
      valid: true,
      clausesCount: 4,
    });
    expect(validateFqlQuery('post_nat_src=203.0.113.5 and peer_as=13335 and city~Chicago and k3s_pod=api')).toMatchObject({
      valid: true,
      clausesCount: 4,
    });
    expect(validateFqlQuery('not threat=""')).toMatchObject({ valid: true });
    expect(validateFqlQuery('')).toMatchObject({ valid: true, clausesCount: 0 });
    expect(validateFqlQuery('src=10.0.0.1)')).toMatchObject({ valid: false });
    expect(validateFqlQuery('bogus_field=123')).toMatchObject({ valid: false });
    expect(validateFqlQuery('bytes>')).toMatchObject({ valid: false });
  });

  it('supports TLS 1.3 listeners in nftables and new adaptive baseline / reporting schemas', () => {
    const state = DesiredStateSchema.parse({
      plugins: [{ id: 'netflow-collector', enabled: true }],
      interfaces: [
        { name: 'lan1', device: 'eth1', type: 'static', role: 'lan', enabled: true, ipv4Address: '10.80.0.1/24' },
      ],
      netflow: {
        enabled: true,
        listeners: [
          {
            id: 'ipfix-tls-4740',
            name: 'WAN Branch IPFIX TLS',
            enabled: true,
            protocol: 'ipfix',
            transport: 'tls',
            port: 4740,
            tls: { useHaPki: true, requireClientCert: true },
          },
        ],
        reporting: {
          enabled: true,
          intervalHours: 24,
          format: 'markdown',
          groupBy: 'interface',
          rangeDays: 30,
          webhookUrl: 'https://hooks.example.com/report',
        },
        alerting: {
          enabled: true,
          rules: [
            {
              id: 'z1',
              name: 'Baseline Z-Score',
              kind: 'baseline_zscore',
              threshold: 3.5,
            },
            {
              id: 'p1',
              name: 'First-Seen Lateral Pair',
              kind: 'first_seen_pair',
              threshold: 102400,
            },
          ],
        },
      },
    });
    const compiled = compileNftables(state);
    expect(compiled.nftScript).toContain('tcp dport 4740 accept comment "netflow-tls-ipfix_tls_4740"');
    const bundle = compileNetFlowBundle(state);
    expect(bundle.config.reporting.enabled).toBe(true);
    expect(bundle.config.reporting.rangeDays).toBe(30);
    expect(bundle.config.enrichment.frrBgpLookup).toBe(true);
    expect(bundle.config.enrichment.natConntrackCorrelation).toBe(true);
  });

  it('formats metrics and generates CSV / tcpdump BPF filters', () => {
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBps(250_000_000)).toBe('250.0 Mbps');
    const flow = {
      id: 'f1',
      timestamp: '2026-11-23T12:00:00Z',
      version: 'ipfix' as const,
      exporterIp: '10.80.0.1',
      srcIp: '10.80.0.25',
      dstIp: '1.1.1.1',
      srcPort: 54321,
      dstPort: 443,
      protocol: 6,
      protocolName: 'TCP',
      bytes: 4096,
      packets: 12,
      bps: 32768,
    };
    const csv = buildFlowExportCsv([flow]);
    expect(csv).toContain('10.80.0.25');
    expect(buildTcpdumpFilter(flow)).toBe('tcp and host 10.80.0.25 and host 1.1.1.1 and port 443');
  });
});
