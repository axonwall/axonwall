import { describe, it, expect } from 'vitest';
import { importCiscoAsaConfig } from './index.js';
import { compileNftables } from '../../compile/nft/index.js';
import { DesiredStateSchema, FirewallRuleSchema, NatRuleSchema } from '../../schemas/index.js';

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
    // Twice NAT in sample resolves WebServer targetIp cleanly instead of 'any'
    const twiceNat = report.state.nat[1]!;
    expect(twiceNat.type).toBe('dnat');
    expect(twiceNat.targetIp).toBe('172.16.50.10');
    report.state.rules.forEach((r) => expect(() => FirewallRuleSchema.parse(r)).not.toThrow());
    report.state.nat.forEach((n) => expect(() => NatRuleSchema.parse(n)).not.toThrow());
  });

  it('preserves static/DNAT source and port filters in Twice NAT, Object NAT, and dynamic PAT [SEC-H20]', () => {
    const asa = `
object network WebServer
 host 172.16.50.10
!
object network AppServer
 host 172.16.50.20
 nat (dmz,outside) static 198.51.100.20 service tcp 8080 443
!
object network TrustedPartner
 host 203.0.113.50
!
object network InternalNet
 subnet 192.168.10.0 255.255.255.0
!
object service SVC_8443
 service tcp destination eq 8443
!
object service SVC_443
 service tcp destination eq 443
!
nat (inside,outside) source dynamic InternalNet interface
nat (outside,dmz) source static TrustedPartner TrustedPartner destination static 198.51.100.10 WebServer service SVC_8443 SVC_443
`;
    const report = importCiscoAsaConfig(asa);
    expect(report.natRulesCount).toBe(3);

    const objNat = report.state.nat[0]!;
    expect(objNat.type).toBe('dnat');
    expect(objNat.interface).toBe('wan');
    expect(objNat.destination).toBe('198.51.100.20');
    expect(objNat.destinationPort).toBe('443');
    expect(objNat.targetIp).toBe('172.16.50.20');
    expect(objNat.targetPort).toBe('8080');
    expect(objNat.enabled).toBe(true);

    const dynPat = report.state.nat[1]!;
    expect(dynPat.type).toBe('masquerade');
    expect(dynPat.source).toBe('192.168.10.0/24');

    const twiceNat = report.state.nat[2]!;
    expect(twiceNat.type).toBe('dnat');
    expect(twiceNat.source).toBe('203.0.113.50');
    expect(twiceNat.destination).toBe('198.51.100.10');
    expect(twiceNat.destinationPort).toBe('8443');
    expect(twiceNat.targetIp).toBe('172.16.50.10');
    expect(twiceNat.targetPort).toBe('443');
    expect(twiceNat.enabled).toBe(true);

    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });

  it('marks lt/gt/neq/range and source-port ACL clauses enabled: false with review items instead of wildcard pass [SEC-H20]', () => {
    const asa = `
access-list outside_in extended permit tcp any host 172.16.50.10 gt 1023
access-list outside_in extended permit tcp any any lt 1024
access-list outside_in extended permit tcp any any neq 22
access-list outside_in extended permit tcp any any range 8000 8010
access-list outside_in extended permit tcp any eq 12345 host 172.16.50.10 eq 443
access-list outside_in extended permit tcp host 198.51.100.5 gt 1023 host 172.16.50.10 eq 443
access-list outside_in extended permit tcp any host 172.16.50.10 eq https
`;
    const report = importCiscoAsaConfig(asa);
    expect(report.rulesCount).toBe(7);

    // First 6 rules use lt/gt/neq/range or source-port clauses and MUST fail closed
    for (let i = 0; i < 6; i++) {
      expect(report.state.rules[i]!.enabled).toBe(false);
    }
    expect(report.reviewItems?.length).toBe(6);
    expect(report.reviewItems?.every((ri) => ri.reason === 'manual_review')).toBe(true);

    // Source-port rules must not corrupt destination IP/port parsing
    expect(report.state.rules[4]!.sourcePort).toBe('12345');
    expect(report.state.rules[4]!.destination).toBe('172.16.50.10');
    expect(report.state.rules[4]!.destinationPort).toBe('443');
    expect(report.state.rules[5]!.source).toBe('198.51.100.5');
    expect(report.state.rules[5]!.destination).toBe('172.16.50.10');
    expect(report.state.rules[5]!.destinationPort).toBe('443');

    // Standard `eq https` rule remains enabled
    expect(report.state.rules[6]!.enabled).toBe(true);
    expect(report.state.rules[6]!.destinationPort).toBe('443');

    const { nftScript } = compileNftables(report.state);
    expect(nftScript).toContain('tcp dport 443');
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });
});
