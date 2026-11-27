import { describe, it, expect } from 'vitest';
import { importVyosConfig } from './index.js';
import { compileNftables } from '../../compile/nft/index.js';
import { DesiredStateSchema } from '../../schemas/index.js';

const SAMPLE_VYOS_BOOT = `
system {
    host-name edge-router01
    domain-name branch.local
    name-server 1.1.1.1
    time-zone UTC
}
interfaces {
    ethernet eth0 {
        address dhcp
        description "WAN Uplink"
    }
    ethernet eth1 {
        address 192.168.20.1/24
        description "LAN Office"
        vif 20 {
            address 10.0.20.1/24
            description "VLAN 20 Voice"
        }
    }
}
firewall {
    group {
        address-group Trusted_Admins {
            address 192.168.20.10
            address 192.168.20.11
            description "Network Operations Team"
        }
    }
    name WAN_IN {
        default-action drop
        rule 10 {
            action accept
            description "Allow HTTPS to App"
            protocol tcp
            destination {
                port 443
            }
        }
    }
}
nat {
    destination {
        rule 10 {
            description "Forward Port 8080 to internal server"
            inbound-interface eth0
            protocol tcp
            destination {
                port 8080
            }
            translation {
                address 192.168.20.50
                port 80
            }
        }
    }
    source {
        rule 100 {
            description "WAN Outbound Masquerade"
            outbound-interface eth0
            translation {
                address masquerade
            }
        }
    }
}
service {
    dhcp-server {
        shared-network-name LAN_POOL {
            subnet 192.168.20.0/24 {
                default-router 192.168.20.1
                dns-server 192.168.20.1
                range 0 {
                    start 192.168.20.100
                    stop 192.168.20.150
                }
                static-mapping pbx {
                    ip-address 192.168.20.50
                    mac-address 52:54:00:22:33:44
                }
            }
        }
    }
}
protocols {
    static {
        route 172.16.0.0/16 {
            next-hop 192.168.20.254 {
            }
        }
    }
}
`;

describe('VyOS / EdgeOS Importer', () => {
  it('parses VyOS config.boot block syntax into DesiredState', () => {
    const report = importVyosConfig(SAMPLE_VYOS_BOOT);

    expect(report.success).toBe(true);
    expect(report.vendor).toBe('vyos');
    expect(report.interfacesCount).toBe(2);
    expect(report.vlansCount).toBe(1);
    expect(report.aliasesCount).toBe(1);
    expect(report.rulesCount).toBe(1);
    expect(report.natRulesCount).toBe(2);
    expect(report.dhcpSubnetsCount).toBe(1);
    expect(report.routesCount).toBe(1);

    expect(report.state.system.hostname).toBe('edge-router01');
    expect(report.state.system.domain).toBe('branch.local');
    expect(report.state.interfaces[0].device).toBe('eth0');
    expect(report.state.interfaces[0].type).toBe('dhcp');
    expect(report.state.interfaces[1].ipv4Address).toBe('192.168.20.1/24');

    expect(report.state.vlans[0].tag).toBe(20);
    expect(report.state.vlans[0].parentInterface).toBe('eth1');

    expect(report.state.aliases[0].name).toBe('Trusted_Admins');
    expect(report.state.aliases[0].entries).toContain('192.168.20.10');

    expect(report.state.rules[0].action).toBe('pass');
    expect(report.state.rules[0].destinationPort).toBe('443');

    expect(report.state.nat[0].type).toBe('dnat');
    expect(report.state.nat[0].targetIp).toBe('192.168.20.50');
    expect(report.state.nat[0].targetPort).toBe('80');
    expect(report.state.nat[1].type).toBe('masquerade');

    expect(report.state.dhcp.subnets[0].subnet).toBe('192.168.20.0/24');
    expect(report.state.dhcp.subnets[0].staticMappings[0].hostname).toBe('pbx');

    expect(report.state.routes[0].network).toBe('172.16.0.0/16');
    expect(report.state.routes[0].gateway).toBe('192.168.20.254');

    const { nftScript } = compileNftables(report.state);
    expect(nftScript).toContain('table inet axonwall');
  });

  it('parses single-line braces and negated source/destination addresses cleanly', () => {
    const report = importVyosConfig(`
firewall {
    name WAN_IN {
        rule 10 {
            action accept
            protocol tcp
            source { address !10.0.0.0/8 }
            destination { address !192.168.0.0/16 }
        }
        rule 20 { action drop; protocol udp; destination { port 53 }; disable }
    }
}
`);
    expect(report.rulesCount).toBe(2);
    expect(report.state.rules[0]!.invertSource).toBe(true);
    expect(report.state.rules[0]!.source).toBe('10.0.0.0/8');
    expect(report.state.rules[0]!.invertDestination).toBe(true);
    expect(report.state.rules[0]!.destination).toBe('192.168.0.0/16');
    expect(report.state.rules[0]!.enabled).toBe(false);
    expect(report.reviewItems?.[0]?.reason).toBe('negated_both');
    expect(report.state.rules[1]!.action).toBe('block');
    expect(report.state.rules[1]!.destinationPort).toBe('53');
    expect(report.state.rules[1]!.enabled).toBe(false);
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });

  it('preserves DNAT and SNAT source/destination/port filters and fails closed on negated/exclude NAT [SEC-H20]', () => {
    const report = importVyosConfig(`
firewall {
    group {
        address-group Partner_IPs {
            address 203.0.113.10
            address 203.0.113.20
        }
    }
}
nat {
    destination {
        rule 10 {
            inbound-interface eth0
            protocol tcp
            source {
                group {
                    address-group Partner_IPs
                }
                port 1024-65535
            }
            destination {
                address 198.51.100.10
                port 8443
            }
            translation {
                address 192.168.20.50
                port 443
            }
        }
        rule 20 {
            inbound-interface eth0
            protocol tcp
            source {
                address !10.0.0.0/8
            }
            destination {
                port 80
            }
            translation {
                address 192.168.20.51
                port 80
            }
        }
    }
    source {
        rule 100 {
            outbound-interface eth0
            protocol tcp
            source {
                address 192.168.20.0/24
                port 1024-65535
            }
            destination {
                address 198.51.100.200
                port 443
            }
            translation {
                address 198.51.100.1
            }
        }
    }
}
`);
    expect(report.natRulesCount).toBe(3);

    const dnat = report.state.nat[0]!;
    expect(dnat.type).toBe('dnat');
    expect(dnat.source).toBe('$Partner_IPs');
    expect(dnat.sourcePort).toBe('1024-65535');
    expect(dnat.destination).toBe('198.51.100.10');
    expect(dnat.destinationPort).toBe('8443');
    expect(dnat.targetIp).toBe('192.168.20.50');
    expect(dnat.targetPort).toBe('443');
    expect(dnat.enabled).toBe(true);

    const negatedDnat = report.state.nat[1]!;
    expect(negatedDnat.enabled).toBe(false);
    expect(report.warnings.length).toBeGreaterThanOrEqual(1);

    const snat = report.state.nat[2]!;
    expect(snat.type).toBe('snat');
    expect(snat.source).toBe('192.168.20.0/24');
    expect(snat.sourcePort).toBe('1024-65535');
    expect(snat.destination).toBe('198.51.100.200');
    expect(snat.destinationPort).toBe('443');
    expect(snat.targetIp).toBe('198.51.100.1');

    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();
  });
});
