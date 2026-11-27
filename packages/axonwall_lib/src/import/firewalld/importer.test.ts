import { describe, it, expect } from 'vitest';
import { importFirewalldConfig } from './index.js';
import { compileNftables } from '../../compile/nft/index.js';
import { DesiredStateSchema } from '../../schemas/index.js';

const SAMPLE_FIREWALLD_XML = `<?xml version="1.0" encoding="utf-8"?>
<ipset type="hash:net" name="trusted_admins">
  <short>Trusted Admin Subnets</short>
  <entry>10.80.0.0/24</entry>
  <entry>192.168.10.50/32</entry>
</ipset>
<zone name="public" target="default">
  <short>Public WAN</short>
  <description>Public facing untrusted network</description>
  <interface name="eth0"/>
  <service name="ssh"/>
  <service name="https"/>
  <port port="8443" protocol="tcp"/>
  <masquerade/>
  <forward-port port="80" protocol="tcp" to-port="8080" to-addr="192.168.1.50"/>
  <rule family="ipv4">
    <source ipset="trusted_admins"/>
    <service name="cockpit"/>
    <log prefix="ADMIN_COCKPIT: "/>
    <accept/>
  </rule>
  <rule family="ipv4">
    <source address="198.51.100.99"/>
    <drop/>
  </rule>
</zone>
<zone name="internal" target="ACCEPT">
  <short>Internal Corporate LAN</short>
  <interface name="eth1"/>
  <service name="dns"/>
  <service name="samba"/>
</zone>
`;

const SAMPLE_FIREWALLD_CLI = `
public (active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0
  sources: 
  services: http https ssh wireguard
  ports: 3000/tcp 10000-10010/udp
  protocols: 
  forward: yes
  masquerade: yes
  forward-ports: 
	port=443:proto=tcp:toport=8443:toaddr=192.168.1.20
  source-ports: 
  icmp-blocks: 
  rich rules: 
	rule family="ipv4" source address="10.10.0.0/16" port port="9090" protocol="tcp" accept
	rule family="ipv4" source address="203.0.113.42" drop

internal (active)
  target: ACCEPT
  interfaces: eth1
  services: dns ntp dhcp
`;

describe('Linux firewalld Importer', () => {
  it('parses firewalld XML zones, ipsets, rich rules, and port forwards into DesiredState and compiles to nftables', () => {
    const report = importFirewalldConfig(SAMPLE_FIREWALLD_XML);

    expect(report.success).toBe(true);
    expect(report.vendor).toBe('firewalld');
    expect(report.aliasesCount).toBe(1);
    expect(report.state.aliases[0].name).toBe('trusted_admins');
    expect(report.state.aliases[0].entries).toContain('10.80.0.0/24');

    // NAT: 1 masquerade + 1 forward-port DNAT
    expect(report.natRulesCount).toBe(2);
    const dnat = report.state.nat.find((n) => n.type === 'dnat');
    expect(dnat).toBeDefined();
    expect(dnat?.targetIp).toBe('192.168.1.50');
    expect(dnat?.targetPort).toBe('8080');

    // Rules: ssh(22), https(443), port 8443, forward pass(8080), rich rule cockpit(9090), rich rule drop, dns(53), samba, internal ACCEPT
    expect(report.rulesCount).toBeGreaterThanOrEqual(8);

    const cockpitRule = report.state.rules.find((r) => r.destinationPort === '9090');
    expect(cockpitRule).toBeDefined();
    expect(cockpitRule?.source).toBe('$trusted_admins');
    expect(cockpitRule?.log).toBe(true);

    const { nftScript } = compileNftables(report.state);
    expect(nftScript).toContain('table inet axonwall');
    expect(nftScript).toContain('192.168.1.50');
  });

  it('parses firewall-cmd --list-all-zones CLI output into DesiredState', () => {
    const report = importFirewalldConfig(SAMPLE_FIREWALLD_CLI);

    expect(report.success).toBe(true);
    expect(report.vendor).toBe('firewalld');
    expect(report.natRulesCount).toBe(2); // masquerade + forward-port 443->8443
    expect(report.rulesCount).toBeGreaterThanOrEqual(9);

    const wgRule = report.state.rules.find((r) => r.destinationPort === '51820');
    expect(wgRule).toBeDefined();
    expect(wgRule?.protocol).toBe('udp');

    const richDrop = report.state.rules.find((r) => r.source === '203.0.113.42');
    expect(richDrop).toBeDefined();
    expect(richDrop?.action).toBe('block');
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });

  it('fails closed on missing/unsupported rich rule actions and prefix quote spoofing [SEC-H20]', () => {
    const cli = `
public (active)
  interfaces: eth0
  rich rules:
    rule family="ipv4" source address="198.51.100.10" log prefix="accept"
    rule family="ipv4" source address="198.51.100.11" port port="8080" protocol="tcp" mark set="1"
`;
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<zone name="public" target="default">
  <interface name="eth0"/>
  <rule family="ipv4">
    <source address="198.51.100.12"/>
    <log prefix="AUDIT: "/>
  </rule>
</zone>`;

    for (const input of [cli, xml]) {
      const report = importFirewalldConfig(input);
      expect(report.rulesCount).toBeGreaterThanOrEqual(1);
      for (const r of report.state.rules) {
        expect(r.action).toBe('block');
        expect(r.enabled).toBe(false);
      }
      expect(report.reviewItems?.length).toBeGreaterThanOrEqual(1);
      expect(report.warnings.length).toBeGreaterThanOrEqual(1);
      expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
    }
  });

  it('never expands unknown service name="..." to protocol any / empty destinationPort [SEC-H20]', () => {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<zone name="public" target="default">
  <interface name="eth0"/>
  <service name="totally_unknown_app"/>
  <rule family="ipv4">
    <source address="198.51.100.5"/>
    <service name="proprietary_custom_daemon"/>
    <accept/>
  </rule>
</zone>`;
    const report = importFirewalldConfig(xml);
    expect(report.rulesCount).toBe(0);
    expect(report.warnings.some((w) => w.includes('totally_unknown_app'))).toBe(true);
    expect(report.warnings.some((w) => w.includes('proprietary_custom_daemon'))).toBe(true);
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });

  it('parses XML <rule> elements structurally without quote-breakout attribute injection [SEC-H20]', () => {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<zone name="public" target="default">
  <interface name="eth0"/>
  <rule family="ipv4">
    <source address='198.51.100.1" accept'/>
    <drop/>
  </rule>
  <rule family="ipv4">
    <source address="203.0.113.20"/>
    <log prefix='LOG" accept'/>
  </rule>
</zone>`;
    const report = importFirewalldConfig(xml);
    // Neither rule can inject an active 'pass' action
    const activePass = report.state.rules.filter((r) => r.enabled && r.action === 'pass');
    expect(activePass).toHaveLength(0);
    expect(report.state.rules.every((r) => r.action === 'block' && r.enabled === false)).toBe(true);
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });

  it('emits invertSource and invertDestination on negated rich rules while keeping them disabled [SEC-H20]', () => {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<zone name="public" target="default">
  <interface name="eth0"/>
  <rule family="ipv4">
    <source invert="True" address="10.0.0.0/8"/>
    <destination not="yes" address="192.168.1.0/24"/>
    <service name="ssh"/>
    <accept/>
  </rule>
</zone>`;
    const report = importFirewalldConfig(xml);
    expect(report.rulesCount).toBe(1);
    const rule = report.state.rules[0]!;
    expect(rule.source).toBe('10.0.0.0/8');
    expect(rule.invertSource).toBe(true);
    expect(rule.destination).toBe('192.168.1.0/24');
    expect(rule.invertDestination).toBe(true);
    expect(rule.enabled).toBe(false);
    expect(report.reviewItems?.[0]?.reason).toBe('negated_both');
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });

  it('disables XML entity expansion against XXE / Billion Laughs [SEC-L10]', () => {
    const xxeXml = `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE zone [
  <!ENTITY evil "EXPANDED_FIREWALLD_SECRET">
]>
<zone name="public" target="default">
  <short>&evil;</short>
  <interface name="eth0"/>
</zone>`;
    const report = importFirewalldConfig(xxeXml);
    expect(report.state.interfaces[0]?.description).not.toContain('EXPANDED_FIREWALLD_SECRET');
    expect(JSON.stringify(report.state)).not.toContain('EXPANDED_FIREWALLD_SECRET');
  });
});
