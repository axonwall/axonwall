import { describe, it, expect } from 'vitest';
import { importVyosConfig } from './index.js';
import { compileNftables } from '../../compile/nft/index.js';

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
});
