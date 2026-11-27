import { describe, it, expect } from 'vitest';
import { importMikrotikConfig } from './index.js';
import { compileNftables } from '../../compile/nft/index.js';
import { DesiredStateSchema } from '../../schemas/index.js';

const SAMPLE_MIKROTIK_RSC = `
# RouterOS 7.15.2
/system identity
set name=RB5009-Core
/interface ethernet
set [ find default-name=ether1 ] comment=WAN name=ether1
set [ find default-name=ether2 ] comment=LAN name=ether2
/interface vlan
add interface=ether2 name=vlan50 vlan-id=50
/ip address
add address=192.168.88.1/24 comment=defconf interface=ether2 network=192.168.88.0
/ip pool
add name=dhcp-pool ranges=192.168.88.100-192.168.88.200
/ip dhcp-server
add address-pool=dhcp-pool interface=ether2 name=defconf
/ip dhcp-server network
add address=192.168.88.0/24 dns-server=192.168.88.1 gateway=192.168.88.1
/ip dhcp-server lease
add address=192.168.88.22 comment=printer mac-address=52:54:00:11:22:33
/ip firewall address-list
add address=192.168.88.100 list=it_ops
add address=192.168.88.101 list=it_ops
/ip firewall filter
add action=accept chain=forward comment="Allow HTTPS from LAN to WAN" dst-port=443 in-interface=ether2 out-interface=ether1 protocol=tcp
add action=drop chain=forward comment="Drop all other WAN" in-interface=ether1
/ip firewall nat
add action=masquerade chain=srcnat comment="defconf: masquerade" out-interface=ether1
add action=dst-nat chain=dstnat comment="Port forward 9000 to internal" dst-port=9000 in-interface=ether1 protocol=tcp to-addresses=192.168.88.50 to-ports=9000
/ip dns
set allow-remote-requests=yes servers=1.1.1.1,8.8.8.8
/ip dns static
add address=192.168.88.1 name=router.lan
/ip route
add disabled=no distance=1 dst-address=10.0.0.0/8 gateway=192.168.88.254
`;

describe('MikroTik RouterOS Importer', () => {
  it('parses MikroTik /export .rsc syntax into DesiredState', () => {
    const report = importMikrotikConfig(SAMPLE_MIKROTIK_RSC);

    expect(report.success).toBe(true);
    expect(report.vendor).toBe('mikrotik');
    expect(report.interfacesCount).toBe(1);
    expect(report.vlansCount).toBe(1);
    expect(report.aliasesCount).toBe(1);
    expect(report.rulesCount).toBe(2);
    expect(report.natRulesCount).toBe(2);
    expect(report.dhcpSubnetsCount).toBe(1);
    expect(report.dnsOverridesCount).toBe(1);
    expect(report.routesCount).toBe(1);

    expect(report.state.system.hostname).toBe('RB5009-Core');
    expect(report.state.system.dnsServers).toEqual(['1.1.1.1', '8.8.8.8']);

    expect(report.state.vlans[0].tag).toBe(50);
    expect(report.state.vlans[0].parentInterface).toBe('ether2');

    expect(report.state.aliases[0].name).toBe('it_ops');
    expect(report.state.aliases[0].entries).toEqual(['192.168.88.100', '192.168.88.101']);

    expect(report.state.rules[0].action).toBe('pass');
    expect(report.state.rules[0].destinationPort).toBe('443');
    expect(report.state.rules[1].action).toBe('block');

    expect(report.state.nat[0].type).toBe('masquerade');
    expect(report.state.nat[1].type).toBe('dnat');
    expect(report.state.nat[1].targetIp).toBe('192.168.88.50');

    expect(report.state.dhcp.subnets[0].staticMappings[0].mac).toBe('52:54:00:11:22:33');
    expect(report.state.dns.hostOverrides[0].hostname).toBe('router');

    expect(report.state.routes[0].network).toBe('10.0.0.0/8');

    const { nftScript } = compileNftables(report.state);
    expect(nftScript).toContain('table inet axonwall');
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });

  it('preserves DNAT and SNAT source/destination/port filters and disables negated NAT [SEC-H20]', () => {
    const rsc = `
/ip firewall address-list
add address=203.0.113.0/24 list=trusted_partners
/ip firewall nat
add action=dst-nat chain=dstnat in-interface=ether1 protocol=tcp src-address-list=trusted_partners src-port=1024-65535 dst-address=198.51.100.10 dst-port=8443 to-addresses=192.168.88.50 to-ports=443 comment="Filtered DNAT"
add action=dst-nat chain=dstnat in-interface=ether1 protocol=tcp src-address=!10.0.0.0/8 dst-port=80 to-addresses=192.168.88.51 to-ports=80 comment="Negated DNAT"
add action=src-nat chain=srcnat out-interface=ether1 protocol=udp src-address=192.168.88.10 src-port=5060 dst-address=198.51.100.200 dst-port=5060 to-addresses=198.51.100.1 to-ports=5060 comment="Filtered SNAT"
`;
    const report = importMikrotikConfig(rsc);
    expect(report.natRulesCount).toBe(3);

    const dnat = report.state.nat[0]!;
    expect(dnat.type).toBe('dnat');
    expect(dnat.source).toBe('$trusted_partners');
    expect(dnat.sourcePort).toBe('1024-65535');
    expect(dnat.destination).toBe('198.51.100.10');
    expect(dnat.destinationPort).toBe('8443');
    expect(dnat.targetIp).toBe('192.168.88.50');
    expect(dnat.targetPort).toBe('443');
    expect(dnat.enabled).toBe(true);

    const negatedDnat = report.state.nat[1]!;
    expect(negatedDnat.enabled).toBe(false);
    expect(report.warnings.length).toBeGreaterThanOrEqual(1);

    const snat = report.state.nat[2]!;
    expect(snat.type).toBe('snat');
    expect(snat.protocol).toBe('udp');
    expect(snat.source).toBe('192.168.88.10');
    expect(snat.sourcePort).toBe('5060');
    expect(snat.destination).toBe('198.51.100.200');
    expect(snat.destinationPort).toBe('5060');
    expect(snat.targetIp).toBe('198.51.100.1');
    expect(snat.targetPort).toBe('5060');

    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });
});
