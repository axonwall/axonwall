import { describe, it, expect } from 'vitest';
import {
  DesiredStateSchema,
  RosenpassConfigSchema,
  compileRosenpass,
  compileNftables,
} from '../index.js';
import { compileGeoIp } from '../compile/geoip/index.js';
import { compileK3s } from '../compile/k3s/index.js';
import { importOpnsenseConfig } from '../import/opnsense/index.js';
import { importPfsenseConfig } from '../import/pfsense/index.js';

describe('v0.12.0 Bug Hunt Regressions (@axonwall/lib)', () => {
  it('preserves OPNsense <disabled>1</disabled> rules, <enable>1</enable> interfaces, and tcp/udp protocol', () => {
    const xml = `<?xml version="1.0"?>
<opnsense>
  <interfaces>
    <wan>
      <if>eth0</if>
      <enable>1</enable>
      <ipaddr>dhcp</ipaddr>
    </wan>
  </interfaces>
  <aliases>
    <alias>
      <name>web_ports</name>
      <type>port</type>
      <address>80,443</address>
    </alias>
  </aliases>
  <filter>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <direction>any</direction>
      <ipprotocol>inet</ipprotocol>
      <protocol>tcp/udp</protocol>
      <disabled>1</disabled>
      <source><any/></source>
      <destination><any/><port>8000:8010</port></destination>
      <descr>Should stay disabled</descr>
    </rule>
  </filter>
</opnsense>`;

    const report = importOpnsenseConfig(xml);
    expect(report.state.interfaces?.length).toBeGreaterThan(0);
    const wan = report.state.interfaces?.find((i) => i.name === 'wan');
    expect(wan?.enabled).toBe(true);
    expect(report.state.rules?.length).toBe(1);
    const rule = report.state.rules?.[0];
    expect(rule?.enabled).toBe(false);
    expect(rule?.direction).toBe('in');
    expect(rule?.protocol).toBe('tcp_udp');
    expect(rule?.destinationPort).toBe('8000-8010');
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });

  it('preserves pfSense <disabled>1</disabled> rules, <enable>1</enable> interfaces, and skips dynamic gateways', () => {
    const xml = `<?xml version="1.0"?>
<pfsense>
  <interfaces>
    <lan>
      <if>eth1</if>
      <enable>1</enable>
      <ipaddr>10.10.0.1</ipaddr>
      <subnet>24</subnet>
    </lan>
  </interfaces>
  <gateways>
    <gateway_item>
      <name>WAN_GW</name>
      <interface>wan</interface>
      <gateway>dynamic</gateway>
    </gateway_item>
  </gateways>
  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>tcp/udp</protocol>
      <disabled>1</disabled>
      <source><any/></source>
      <destination><any/><port>9000:9010</port></destination>
      <descr>Disabled pfSense rule</descr>
    </rule>
  </filter>
</pfsense>`;

    const report = importPfsenseConfig(xml);
    const lan = report.state.interfaces?.find((i) => i.name === 'lan');
    expect(lan?.enabled).toBe(true);
    expect(report.state.rules?.[0]?.enabled).toBe(false);
    expect(report.state.rules?.[0]?.protocol).toBe('tcp_udp');
    expect(report.state.rules?.[0]?.destinationPort).toBe('9000-9010');
    expect((report.state.routing?.gateways ?? []).some((g) => g.address === 'dynamic')).toBe(false);
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });

  it('emits auto-merge and deduplicates overlapping CIDRs for GeoIP FR + RO', () => {
    const geo = compileGeoIp({
      enabled: true,
      mode: 'block',
      direction: 'in',
      countries: ['FR', 'RO', 'IN'],
      excludedSubnets: ['10.0.0.0/8'],
      log: false,
    });
    const text = geo.nftSetDefinitions.join('\n');
    expect(text).toContain('auto-merge;');
    expect(text).not.toContain('82.76.0.0/14');
    expect(text).not.toContain('182.64.0.0/11');
  });

  it('rejects using IP alias in destinationPort and inet_service alias as IP endpoint', () => {
    const state = DesiredStateSchema.parse({
      aliases: [
        { name: 'bad_ip_as_port', type: 'host', entries: ['203.0.113.5'], enabled: true },
        { name: 'svc_ports', type: 'port', entries: ['80', '443'], enabled: true },
      ],
      rules: [
        {
          id: '11111111-1111-4111-8111-111111111111',
          interface: 'wan',
          direction: 'in',
          action: 'pass',
          protocol: 'tcp',
          source: 'any',
          destination: 'any',
          destinationPort: '$bad_ip_as_port',
          enabled: true,
        },
        {
          id: '22222222-2222-4222-8222-222222222222',
          interface: 'wan',
          direction: 'in',
          action: 'pass',
          protocol: 'tcp',
          source: 'any',
          destination: '$svc_ports',
          destinationPort: '443',
          enabled: true,
        },
      ],
    });

    const compiled = compileNftables(state);
    expect(compiled.nftScript).not.toContain('dport @set_bad_ip_as_port');
    expect(compiled.nftScript).not.toContain('ip daddr @set_svc_ports');
  });

  it('forces K3s secondary node to agent mode under single-server-ha-agent', () => {
    const state = DesiredStateSchema.parse({
      ha: { enabled: true, nodeRole: 'backup', peerAddress: '10.80.0.10', interface: 'eth0', authSecret: 'secret' },
      k3s: { enabled: true, role: 'server', haTopology: 'single-server-ha-agent', autoJoinHaPeer: true },
    });
    const compiled = compileK3s(state, 'test-token');
    expect(compiled.k3sConfigYaml).toContain('K3s Agent Configuration');
    expect(compiled.k3sConfigYaml).toContain('server: "https://10.80.0.10:6443"');
    expect(compiled.k3sConfigYaml).not.toContain('cluster-init: true');
  });

  it('remaps Rosenpass default listenAddresses to custom listenPort and assigns distinct peer PQ paths', () => {
    const cfg = RosenpassConfigSchema.parse({
      enabled: true,
      listenPort: 19999,
      peers: [
        {
          name: 'alpha-node',
          wgPeerPublicKey: 'PeerAlphaCurve25519Base64PublicKeyHere00000=',
          endpoint: '203.0.113.10:19999',
          enabled: true,
        },
        {
          name: 'beta-node',
          wgPeerPublicKey: 'PeerBetaCurve25519Base64PublicKeyHere000000=',
          endpoint: '203.0.113.20:19999',
          enabled: true,
        },
      ],
    });

    const res = compileRosenpass(cfg);
    expect(res.configToml).toContain('0.0.0.0:19999');
    expect(res.configToml).toContain('[::]:19999');
    expect(res.configToml).not.toContain('0.0.0.0:9999');
    expect(res.configToml).toContain('/etc/rosenpass/peers/alpha-node-pq.pk');
    expect(res.configToml).toContain('/etc/rosenpass/peers/beta-node-pq.pk');
  });
});
