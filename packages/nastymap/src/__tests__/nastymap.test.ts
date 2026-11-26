import { describe, expect, it } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import {
  addHostToScan,
  compareNmapScans,
  filterTopology,
  generateNetworkScenario,
  generateTopology,
  HostDetailDrawer,
  parseNmapXml,
  updateHostInScan,
} from '../index.js';

const SAMPLE_XML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV 192.168.10.0/24" start="1700000000" version="7.94" xmloutputversion="1.05">
  <host starttime="1700000001" endtime="1700000002">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.10.1" addrtype="ipv4"/>
    <hostnames><hostname name="gw.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="53"><state state="open" reason="syn-ack"/><service name="domain"/></port>
    </ports>
  </host>
  <runstats>
    <finished time="1700000005" timestr="Tue Nov 14 22:13:25 2023" summary="1 host up" elapsed="5.0" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>`;

describe('nastymap core & mutators', () => {
  it('parses Nmap XML and generates topology', () => {
    const run = parseNmapXml(SAMPLE_XML);
    expect(run.hosts).toHaveLength(1);
    expect(run.hosts[0].ipv4).toBe('192.168.10.1');

    const graph = generateTopology(run);
    expect(graph.nodes.length).toBeGreaterThan(0);

    const diff = compareNmapScans(run, run);
    expect(diff.addedHosts).toHaveLength(0);
    expect(diff.removedHosts).toHaveLength(0);
  });

  it('preserves and defaults runstats.finished across scan mutations', () => {
    const base = parseNmapXml(SAMPLE_XML);
    const updated = updateHostInScan(base, '192.168.10.1', () => ({ comments: 'gw' }));
    expect(updated.runstats.finished).toBeDefined();
    expect(updated.runstats.finished.timestr).toBe('Tue Nov 14 22:13:25 2023');

    const noFinished = { ...base, runstats: { hosts: { up: 1, down: 0, total: 1 } } as any };
    const added = addHostToScan(noFinished, {
      ...base.hosts[0],
      id: '192.168.10.2',
      ipv4: '192.168.10.2',
    });
    expect(added.runstats.finished).toBeDefined();
    expect(typeof added.runstats.finished.timestr).toBe('string');
  });

  it('handles IPv6 subnets and empty device pools safely in scenario generator', () => {
    const scenario = generateNetworkScenario({
      subnet: '2001:db8::/64',
      totalHosts: 10,
      includeSmartphones: false,
      includeLaptops: false,
      includeIoT: false,
    });
    expect(scenario.scan.hosts.length).toBeGreaterThan(0);
    expect(scenario.scan.hosts[0].ipv4).toBe('192.168.1.1');
  });

  it('includes scanned router nodes in onlyOpenPorts filtering and preserves intermediate hops', () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap 10.0.0.0/24" start="1700000000" version="7.94" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <os><osmatch name="Cisco IOS" accuracy="95"><osclass type="router" vendor="Cisco" osfamily="IOS" accuracy="95"/></osmatch></os>
    <ports><port protocol="tcp" portid="80"><state state="closed" reason="reset"/></port></ports>
  </host>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh"/></port></ports>
    <trace><hop ttl="1" ipaddr="10.0.0.254" rtt="1.2"/><hop ttl="2" ipaddr="10.0.0.2" rtt="2.5"/></trace>
  </host>
  <runstats><finished time="1700000005"/><hosts up="2" down="0" total="2"/></runstats>
</nmaprun>`;
    const run = parseNmapXml(xml);
    const graph = generateTopology(run);
    const routerNode = graph.nodes.find((n) => n.id === '10.0.0.1');
    expect(routerNode?.nodeType).toBe('router');
    expect(routerNode?.hostRef).toBeDefined();

    const filtered = filterTopology(graph, { searchQuery: '', onlyOpenPorts: true });
    expect(filtered.visibleNodeIds.has('10.0.0.1')).toBe(false);
    expect(filtered.visibleNodeIds.has('10.0.0.2')).toBe(true);
    expect(filtered.visibleNodeIds.has('10.0.0.254')).toBe(true);
  });

  it('renders HostDetailDrawer cleanly with null and non-null node without hook mismatch', () => {
    const run = parseNmapXml(SAMPLE_XML);
    const graph = generateTopology(run);
    const hostNode = graph.nodes.find((n) => Boolean(n.hostRef))!;
    expect(renderToStaticMarkup(React.createElement(HostDetailDrawer, { node: null, onClose: () => {} }))).toBe('');
    const html = renderToStaticMarkup(React.createElement(HostDetailDrawer, { node: hostNode, onClose: () => {} }));
    expect(html).toContain('192.168.10.1');
  });
});
