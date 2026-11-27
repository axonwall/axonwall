import { describe, it, expect } from 'vitest';
import { importOpnsenseConfig } from './index.js';
import { compileKeaDhcp4 } from '../../compile/kea/index.js';
import { compileUnbound } from '../../compile/unbound/index.js';
import { compileWireGuard } from '../../compile/wireguard/index.js';
import { compileNftables } from '../../compile/nft/index.js';
import { DesiredStateSchema } from '../../schemas/index.js';

const SAMPLE_OPNSENSE_XML = `<?xml version="1.0"?>
<opnsense version="24.7">
  <system>
    <hostname>opnsense-core</hostname>
    <domain>lab.local</domain>
    <dnsserver>1.1.1.1</dnsserver>
    <timezone>UTC</timezone>
  </system>
  <interfaces>
    <wan>
      <if>vtnet0</if>
      <ipaddr>dhcp</ipaddr>
      <descr>WAN Uplink</descr>
    </wan>
    <lan>
      <if>vtnet1</if>
      <ipaddr>192.168.1.1</ipaddr>
      <subnet>24</subnet>
      <descr>Office LAN</descr>
    </lan>
  </interfaces>
  <aliases>
    <alias>
      <name>internal_hosts</name>
      <type>host</type>
      <address>192.168.1.10 192.168.1.20</address>
      <descr>Internal DB and API</descr>
    </alias>
  </aliases>
  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <protocol>tcp</protocol>
      <source><any/></source>
      <destination><address>192.168.1.10</address><port>443</port></destination>
      <descr>Allow LAN to HTTPS</descr>
    </rule>
    <rule>
      <type>block</type>
      <interface>wan</interface>
      <protocol>any</protocol>
      <source><any/></source>
      <destination><any/></destination>
      <descr>Block unsolicited WAN</descr>
    </rule>
  </filter>
  <nat>
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <destination><port>8080</port></destination>
      <target>192.168.1.10</target>
      <local_port>80</local_port>
      <descr>Forward 8080 to Internal Web</descr>
    </rule>
  </nat>
  <dhcpd>
    <lan>
      <enable>1</enable>
      <range><from>192.168.1.100</from><to>192.168.1.200</to></range>
      <gateway>192.168.1.1</gateway>
      <dnsserver>192.168.1.1</dnsserver>
      <staticmap>
        <mac>52:54:00:11:22:33</mac>
        <ipaddr>192.168.1.50</ipaddr>
        <hostname>office-printer</hostname>
      </staticmap>
    </lan>
  </dhcpd>
  <unbound>
    <hosts>
      <host>storage</host>
      <domain>lab.local</domain>
      <ip>192.168.1.25</ip>
    </hosts>
  </unbound>
</opnsense>`;

describe('OPNsense XML Importer', () => {
  it('parses OPNsense config.xml into Axonwall DesiredState with full fidelity', () => {
    const report = importOpnsenseConfig(SAMPLE_OPNSENSE_XML);

    expect(report.success).toBe(true);
    expect(report.interfacesCount).toBe(2);
    expect(report.aliasesCount).toBe(1);
    expect(report.rulesCount).toBe(2);
    expect(report.natRulesCount).toBe(1);
    expect(report.dhcpSubnetsCount).toBe(1);
    expect(report.dnsOverridesCount).toBe(1);

    expect(report.state.system.hostname).toBe('opnsense-core');
    expect(report.state.interfaces[0].device).toBe('vtnet0');
    expect(report.state.aliases[0].name).toBe('internal_hosts');
    expect(report.state.aliases[0].entries).toEqual(['192.168.1.10', '192.168.1.20']);
    expect(report.state.rules[0].destination).toBe('192.168.1.10');
    expect(report.state.rules[0].destinationPort).toBe('443');
    expect(report.state.nat[0].targetIp).toBe('192.168.1.10');
    expect(report.state.nat[0].targetPort).toBe('80');
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });

  it('fails closed on unknown/non-pass rule types and skips match rules [SEC-H20]', () => {
    const xml = `<?xml version="1.0"?>
<opnsense>
  <filter>
    <rule>
      <type>match</type>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source><any/></source>
      <destination><any/><port>443</port></destination>
      <descr>OPNsense match rule</descr>
    </rule>
    <rule>
      <type>unknown_op</type>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source><any/></source>
      <destination><any/><port>22</port></destination>
      <descr>Invalid OPNsense type</descr>
    </rule>
  </filter>
</opnsense>`;
    const report = importOpnsenseConfig(xml);
    expect(report.rulesCount).toBe(1);
    expect(report.state.rules[0]!.action).toBe('block');
    expect(report.state.rules[0]!.enabled).toBe(false);
    expect(report.reviewItems?.length).toBe(1);
    expect(report.warnings.some((w) => w.includes('match'))).toBe(true);

    const { nftScript } = compileNftables(report.state);
    expect(nftScript).not.toContain('dport 443');
    expect(nftScript).not.toContain('dport 22');
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });

  it('preserves DNAT source/destination filters and disables negated DNAT rules [SEC-H20]', () => {
    const xml = `<?xml version="1.0"?>
<opnsense>
  <nat>
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source><address>203.0.113.42</address><port>50000</port></source>
      <destination><address>198.51.100.5</address><port>8443</port></destination>
      <target>192.168.1.10</target>
      <local_port>443</local_port>
      <descr>Partner-only DNAT</descr>
    </rule>
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source><not/><address>198.51.100.99</address></source>
      <destination><port>80</port></destination>
      <target>192.168.1.11</target>
      <local_port>80</local_port>
      <descr>Negated DNAT</descr>
    </rule>
  </nat>
</opnsense>`;
    const report = importOpnsenseConfig(xml);
    expect(report.natRulesCount).toBe(2);
    expect(report.state.nat[0]!.source).toBe('203.0.113.42');
    expect(report.state.nat[0]!.sourcePort).toBe('50000');
    expect(report.state.nat[0]!.destination).toBe('198.51.100.5');
    expect(report.state.nat[0]!.destinationPort).toBe('8443');
    expect(report.state.nat[0]!.targetIp).toBe('192.168.1.10');
    expect(report.state.nat[0]!.targetPort).toBe('443');
    expect(report.state.nat[0]!.enabled).toBe(true);

    expect(report.state.nat[1]!.enabled).toBe(false);
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });

  it('disables XML entity expansion against XXE / Billion Laughs [SEC-L10]', () => {
    const xxeXml = `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY secret "EXPANDED_OPN_SECRET">
]>
<opnsense>
  <system>
    <hostname>&secret;</hostname>
  </system>
</opnsense>`;
    const report = importOpnsenseConfig(xxeXml);
    expect(report.state.system.hostname).not.toBe('EXPANDED_OPN_SECRET');
  });
});

describe('Core Services Compilers (Kea, Unbound, WireGuard)', () => {
  it('compiles Kea DHCPv4 JSON configuration', () => {
    const report = importOpnsenseConfig(SAMPLE_OPNSENSE_XML);
    const { keaDhcp4Config } = compileKeaDhcp4(report.state.dhcp, report.state.interfaces);

    const parsed = JSON.parse(keaDhcp4Config);
    expect(parsed.Dhcp4).toBeDefined();
    expect(parsed.Dhcp4.subnet4).toHaveLength(1);
    expect(parsed.Dhcp4.subnet4[0].pools[0].pool).toBe('192.168.1.100 - 192.168.1.200');
    expect(parsed.Dhcp4.subnet4[0].reservations[0]['hw-address']).toBe('52:54:00:11:22:33');
    expect(parsed.Dhcp4.subnet4[0].reservations[0]['ip-address']).toBe('192.168.1.50');
  });

  it('compiles Unbound DNS configuration with overrides', () => {
    const report = importOpnsenseConfig(SAMPLE_OPNSENSE_XML);
    const { unboundConfig } = compileUnbound(report.state.dns);

    expect(unboundConfig).toContain('server:');
    expect(unboundConfig).toContain('local-data: "storage.lab.local. IN A 192.168.1.25"');
    expect(unboundConfig).toContain('forward-zone:');
  });

  it('compiles WireGuard wg0.conf', () => {
    const wgState = {
      enabled: true,
      address: '10.50.0.1/24',
      listenPort: 51820,
      privateKey: 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=',
      peers: [
        {
          id: 'peer-1',
          name: 'admin-laptop',
          publicKey: 'YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=',
          allowedIps: ['10.50.0.2/32'],
          persistentKeepalive: 25,
          enabled: true,
        },
      ],
    };

    const { wgConfig } = compileWireGuard(wgState);
    expect(wgConfig).toContain('[Interface]');
    expect(wgConfig).toContain('Address = 10.50.0.1/24');
    expect(wgConfig).toContain('ListenPort = 51820');
    expect(wgConfig).toContain('[Peer]');
    expect(wgConfig).toContain('PublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=');
    expect(wgConfig).toContain('AllowedIPs = 10.50.0.2/32');
  });
});
