import { describe, it, expect } from 'vitest';
import { importCiscoAsaConfig } from './index.js';
import { compileNftables } from '../../compile/nft/index.js';

const SAMPLE_CISCO_ASA = `
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address dhcp
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.10.1 255.255.255.0
!
interface GigabitEthernet0/1.50
 vlan 50
 nameif dmz
 security-level 50
 ip address 172.16.50.1 255.255.255.0
!
object network WebServer
 host 172.16.50.10
 description Production Web Server
!
object-group network AdminHosts
 network-object host 192.168.10.5
 network-object 192.168.10.64 255.255.255.192
!
access-list outside_in extended permit tcp any host 172.16.50.10 eq 443
access-list outside_in extended permit icmp any any
access-list outside_in extended deny ip any any
access-list inside_in extended permit ip any any
!
nat (inside,outside) source dynamic any interface
nat (outside,dmz) source static any any destination static interface WebServer
!
route inside 10.0.0.0 255.0.0.0 192.168.10.254 1
`;

describe('importCiscoAsaConfig', () => {
  it('parses Cisco ASA configuration into DesiredState and compiles to nftables', () => {
    const report = importCiscoAsaConfig(SAMPLE_CISCO_ASA);

    expect(report.success).toBe(true);
    expect(report.vendor).toBe('cisco');
    expect(report.interfacesCount).toBeGreaterThanOrEqual(2);
    expect(report.vlansCount).toBe(1);
    expect(report.state.vlans[0].tag).toBe(50);
    expect(report.aliasesCount).toBeGreaterThanOrEqual(2);
    expect(report.rulesCount).toBe(4);
    expect(report.natRulesCount).toBe(2);
    expect(report.routesCount).toBe(1);
    expect(report.state.routes[0].network).toBe('10.0.0.0/8');
    expect(report.state.routes[0].gateway).toBe('192.168.10.254');

    const { nftScript } = compileNftables(report.state);
    expect(nftScript).toContain('table inet axonwall');
    expect(nftScript).toContain('443');
  });
});
