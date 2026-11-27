import { describe, it, expect } from 'vitest';
import { importPfsenseConfig } from './index.js';
import { compileNftables } from '../../compile/nft/index.js';
import { DesiredStateSchema } from '../../schemas/index.js';

const SAMPLE_PFSENSE_XML = `<?xml version="1.0"?>
<pfsense>
  <version>22.4</version>
  <system>
    <hostname>pfsense-router</hostname>
    <domain>office.internal</domain>
    <dnsserver>1.1.1.1</dnsserver>
    <dnsserver>8.8.8.8</dnsserver>
    <timezone>America/New_York</timezone>
  </system>
  <interfaces>
    <wan>
      <enable></enable>
      <if>vtnet0</if>
      <descr>WAN ISP</descr>
      <ipaddr>dhcp</ipaddr>
      <mtu>1500</mtu>
    </wan>
    <lan>
      <enable></enable>
      <if>vtnet1</if>
      <descr>Corporate LAN</descr>
      <ipaddr>192.168.10.1</ipaddr>
      <subnet>24</subnet>
    </lan>
    <opt1>
      <enable></enable>
      <if>vtnet1.100</if>
      <descr>Guest Network</descr>
      <ipaddr>10.0.100.1</ipaddr>
      <subnet>24</subnet>
    </opt1>
  </interfaces>
  <vlans>
    <tag>
      <if>vtnet1</if>
      <tag>100</tag>
      <descr>Guest Wi-Fi VLAN</descr>
    </tag>
  </vlans>
  <aliases>
    <alias>
      <name>Admin_Hosts</name>
      <type>host</type>
      <address>192.168.10.50 192.168.10.51</address>
      <descr>IT Administrators</descr>
    </alias>
    <alias>
      <name>Web_Services</name>
      <type>port</type>
      <address>80 443 8443</address>
      <descr>HTTP and HTTPS ports</descr>
    </alias>
  </aliases>
  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <protocol>tcp</protocol>
      <source>
        <network>lan</network>
      </source>
      <destination>
        <any></any>
        <port>Web_Services</port>
      </destination>
      <descr>Allow LAN to Web Services</descr>
    </rule>
    <rule>
      <type>block</type>
      <interface>opt1</interface>
      <protocol>any</protocol>
      <source>
        <network>opt1</network>
      </source>
      <destination>
        <network>lan</network>
      </destination>
      <descr>Isolate Guest from LAN</descr>
    </rule>
  </filter>
  <nat>
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <destination>
        <port>8443</port>
      </destination>
      <target>192.168.10.25</target>
      <local-port>443</local-port>
      <descr>Forward WAN 8443 to internal HTTPS</descr>
    </rule>
    <outbound>
      <rule>
        <interface>wan</interface>
        <source>
          <network>192.168.10.0/24</network>
        </source>
        <descr>Outbound Masquerade LAN</descr>
      </rule>
    </outbound>
  </nat>
  <dhcpd>
    <lan>
      <enable></enable>
      <range>
        <from>192.168.10.100</from>
        <to>192.168.10.200</to>
      </range>
      <gateway>192.168.10.1</gateway>
      <dnsserver>192.168.10.1</dnsserver>
      <staticmap>
        <mac>52:54:00:aa:bb:cc</mac>
        <ipaddr>192.168.10.25</ipaddr>
        <hostname>fileserver</hostname>
        <descr>NAS Storage</descr>
      </staticmap>
    </lan>
  </dhcpd>
  <unbound>
    <hosts>
      <host>fileserver</host>
      <domain>office.internal</domain>
      <ip>192.168.10.25</ip>
      <descr>Internal NAS</descr>
    </hosts>
  </unbound>
  <staticroutes>
    <route>
      <network>10.20.0.0/16</network>
      <gateway>192.168.10.254</gateway>
      <descr>Datacenter VPN Route</descr>
    </route>
  </staticroutes>
</pfsense>`;

describe('pfSense XML Importer', () => {
  it('parses pfSense config.xml into Axonwall DesiredState with full fidelity', () => {
    const report = importPfsenseConfig(SAMPLE_PFSENSE_XML);

    expect(report.success).toBe(true);
    expect(report.vendor).toBe('pfsense');
    expect(report.interfacesCount).toBe(3);
    expect(report.vlansCount).toBe(1);
    expect(report.aliasesCount).toBe(2);
    expect(report.rulesCount).toBe(2);
    expect(report.natRulesCount).toBe(2);
    expect(report.dhcpSubnetsCount).toBe(1);
    expect(report.dnsOverridesCount).toBe(1);
    expect(report.routesCount).toBe(1);

    expect(report.state.system.hostname).toBe('pfsense-router');
    expect(report.state.system.domain).toBe('office.internal');
    expect(report.state.system.timezone).toBe('America/New_York');

    // Interfaces & VLANs
    expect(report.state.interfaces[0].device).toBe('vtnet0');
    expect(report.state.interfaces[0].type).toBe('dhcp');
    expect(report.state.interfaces[1].ipv4Address).toBe('192.168.10.1/24');
    expect(report.state.vlans[0].tag).toBe(100);
    expect(report.state.vlans[0].parentInterface).toBe('vtnet1');

    // Aliases
    expect(report.state.aliases[0].name).toBe('Admin_Hosts');
    expect(report.state.aliases[0].entries).toEqual(['192.168.10.50', '192.168.10.51']);
    expect(report.state.aliases[1].name).toBe('Web_Services');
    expect(report.state.aliases[1].type).toBe('port');

    // Rules
    expect(report.state.rules[0].action).toBe('pass');
    expect(report.state.rules[0].destinationPort).toBe('$Web_Services');
    expect(report.state.rules[1].action).toBe('block');

    // NAT
    expect(report.state.nat[0].type).toBe('dnat');
    expect(report.state.nat[0].targetIp).toBe('192.168.10.25');
    expect(report.state.nat[0].targetPort).toBe('443');
    expect(report.state.nat[1].type).toBe('masquerade');

    // DHCP & DNS
    expect(report.state.dhcp.subnets[0].poolStart).toBe('192.168.10.100');
    expect(report.state.dhcp.subnets[0].staticMappings[0].hostname).toBe('fileserver');
    expect(report.state.dns.hostOverrides[0].hostname).toBe('fileserver');

    // Routes
    expect(report.state.routes[0].network).toBe('10.20.0.0/16');
    expect(report.state.routes[0].gateway).toBe('192.168.10.254');

    // Verify it compiles cleanly to nftables
    const { nftScript } = compileNftables(report.state);
    expect(nftScript).toContain('table inet axonwall');
    expect(nftScript).toContain('192.168.10.25');
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });

  it('fails closed on unknown/non-pass rule types and skips match rules [SEC-H20]', () => {
    const xml = `<?xml version="1.0"?>
<pfsense>
  <filter>
    <rule>
      <type>match</type>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source><any/></source>
      <destination><any/><port>443</port></destination>
      <descr>Traffic shaper match rule</descr>
    </rule>
    <rule>
      <type>bogus_action</type>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source><any/></source>
      <destination><any/><port>22</port></destination>
      <descr>Unknown type rule</descr>
    </rule>
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source><any/></source>
      <destination><any/><port>23</port></destination>
      <descr>Missing type rule</descr>
    </rule>
  </filter>
</pfsense>`;
    const report = importPfsenseConfig(xml);
    expect(report.rulesCount).toBe(2);
    expect(report.state.rules.every((r) => r.action === 'block' && r.enabled === false)).toBe(true);
    expect(report.reviewItems?.length).toBe(2);
    expect(report.warnings.some((w) => w.includes('match'))).toBe(true);

    const { nftScript } = compileNftables(report.state);
    expect(nftScript).not.toContain('dport 443');
    expect(nftScript).not.toContain('dport 22');
    expect(nftScript).not.toContain('dport 23');
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });

  it('preserves DNAT source/destination filters and disables negated DNAT rules [SEC-H20]', () => {
    const xml = `<?xml version="1.0"?>
<pfsense>
  <aliases>
    <alias>
      <name>Partner_Net</name>
      <type>network</type>
      <address>203.0.113.0/24</address>
    </alias>
  </aliases>
  <nat>
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source><address>Partner_Net</address><port>1024:65535</port></source>
      <destination><address>198.51.100.10</address><port>8443</port></destination>
      <target>192.168.10.25</target>
      <local-port>443</local-port>
      <descr>Restricted Partner Forward</descr>
    </rule>
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source><not/><address>198.51.100.99</address></source>
      <destination><port>80</port></destination>
      <target>192.168.10.26</target>
      <local-port>80</local-port>
      <descr>Negated DNAT source</descr>
    </rule>
  </nat>
</pfsense>`;
    const report = importPfsenseConfig(xml);
    expect(report.natRulesCount).toBe(2);
    expect(report.state.nat[0]!.source).toBe('$Partner_Net');
    expect(report.state.nat[0]!.sourcePort).toBe('1024-65535');
    expect(report.state.nat[0]!.destination).toBe('198.51.100.10');
    expect(report.state.nat[0]!.destinationPort).toBe('8443');
    expect(report.state.nat[0]!.targetIp).toBe('192.168.10.25');
    expect(report.state.nat[0]!.targetPort).toBe('443');
    expect(report.state.nat[0]!.enabled).toBe(true);

    expect(report.state.nat[1]!.enabled).toBe(false);
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });

  it('disables XML entity expansion against XXE / Billion Laughs [SEC-L10]', () => {
    const xxeXml = `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY secret "EXPANDED_ENTITY_VALUE">
]>
<pfsense>
  <system>
    <hostname>&secret;</hostname>
  </system>
</pfsense>`;
    const report = importPfsenseConfig(xxeXml);
    expect(report.state.system.hostname).not.toBe('EXPANDED_ENTITY_VALUE');
  });
});
