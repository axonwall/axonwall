import { describe, it, expect } from 'vitest';
import { detectFirewallType, importFirewallConfig } from './index.js';

describe('Unified Firewall Importer & Auto-Detection', () => {
  it('detects pfSense XML configuration', () => {
    const xml = '<pfsense><version>22.4</version><system><hostname>test</hostname></system></pfsense>';
    expect(detectFirewallType(xml)).toBe('pfsense');
    const res = importFirewallConfig(xml);
    expect(res.vendor).toBe('pfsense');
    expect(res.state.system.hostname).toBe('test');
  });

  it('detects OPNsense XML configuration', () => {
    const xml = '<opnsense version="24.7"><system><hostname>opn-test</hostname></system></opnsense>';
    expect(detectFirewallType(xml)).toBe('opnsense');
    const res = importFirewallConfig(xml);
    expect(res.vendor).toBe('opnsense');
    expect(res.state.system.hostname).toBe('opn-test');
  });

  it('detects VyOS / EdgeOS configuration', () => {
    const vyos = `
interfaces {
    ethernet eth0 {
        address dhcp
    }
}
firewall {
    name WAN_IN {
        default-action drop
    }
}
`;
    expect(detectFirewallType(vyos)).toBe('vyos');
    const res = importFirewallConfig(vyos);
    expect(res.vendor).toBe('vyos');
    expect(res.interfacesCount).toBe(1);
  });

  it('detects MikroTik RouterOS /export script', () => {
    const rsc = `
# RouterOS 7.15
/system identity set name=MT-Router
/ip firewall filter add action=accept chain=forward
`;
    expect(detectFirewallType(rsc)).toBe('mikrotik');
    const res = importFirewallConfig(rsc);
    expect(res.vendor).toBe('mikrotik');
    expect(res.state.system.hostname).toBe('MT-Router');
  });

  it('detects Linux iptables-save dump', () => {
    const ipt = `
*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
`;
    expect(detectFirewallType(ipt)).toBe('iptables');
    const res = importFirewallConfig(ipt);
    expect(res.vendor).toBe('iptables');
    expect(res.rulesCount).toBe(1);
  });
});
