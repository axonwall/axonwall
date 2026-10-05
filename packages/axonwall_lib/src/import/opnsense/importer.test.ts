import { describe, it, expect } from 'vitest';
import { importOpnsenseConfig } from './index.js';
import { compileKeaDhcp4 } from '../../compile/kea/index.js';
import { compileUnbound } from '../../compile/unbound/index.js';
import { compileWireGuard } from '../../compile/wireguard/index.js';

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
