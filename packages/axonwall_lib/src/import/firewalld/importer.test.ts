import { describe, it, expect } from 'vitest';
import { importFirewalldConfig } from './index.js';
import { compileNftables } from '../../compile/nft/index.js';

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
  });
});
