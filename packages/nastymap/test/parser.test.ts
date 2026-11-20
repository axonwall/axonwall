import { describe, it, expect } from 'vitest';
import { parseNmapXml } from '../src/parser/nmap-xml-parser.js';
import { mergeScanResults } from '../src/mutation/scan-mutator.js';
import { ENTERPRISE_NETWORK_XML, GLOBAL_PERIMETER_XML, SECURITY_BREACH_BEFORE_XML, SECURITY_BREACH_AFTER_XML } from '../src/data/sample-scans.js';
import { compareNmapScans } from '../src/diff/scan-diff.js';
import { generateTopology } from '../src/topology/topology-engine.js';
import { geocodeIp, isPrivateIp } from '../src/geoip/geocoder.js';

describe('NastyMap XML Parser', () => {
  it('parses enterprise network scan correctly', () => {
    const scan = parseNmapXml(ENTERPRISE_NETWORK_XML);
    expect(scan.scanner).toBe('nmap');
    expect(scan.version).toBe('7.94');
    expect(scan.hosts.length).toBe(8);

    const pfsense = scan.hosts.find((h) => h.ipv4 === '192.168.1.1');
    expect(pfsense).toBeDefined();
    expect(pfsense?.primaryHostname).toBe('pfsense-gateway.corp.local');
    expect(pfsense?.osFamily).toBe('FreeBSD');
    expect(pfsense?.deviceType).toBe('firewall');
    expect(pfsense?.ports.length).toBe(4);
    expect(pfsense?.trace?.hops.length).toBe(1);

    const dc01 = scan.hosts.find((h) => h.ipv4 === '10.0.10.10');
    expect(dc01).toBeDefined();
    expect(dc01?.osFamily).toBe('Windows');
    expect(dc01?.ports.find((p) => p.portid === 3389)?.service?.name).toBe('ms-wbt-server');
    expect(dc01?.trace?.hops.length).toBe(3);
  });

  it('parses global perimeter scan with international traceroutes', () => {
    const scan = parseNmapXml(GLOBAL_PERIMETER_XML);
    expect(scan.hosts.length).toBe(8);

    const cloudflare = scan.hosts.find((h) => h.ipv4 === '1.1.1.1');
    expect(cloudflare).toBeDefined();
    expect(cloudflare?.ports.some((p) => p.portid === 53)).toBe(true);
    expect(cloudflare?.trace?.hops.length).toBe(4);
  });

  it('handles minimal scan without OS or traceroute gracefully', () => {
    const minimalXml = `<?xml version="1.0"?>
    <nmaprun scanner="nmap" args="nmap -sn 192.168.1.5">
      <host>
        <status state="up"/>
        <address addr="192.168.1.5" addrtype="ipv4"/>
      </host>
    </nmaprun>`;

    const scan = parseNmapXml(minimalXml);
    expect(scan.hosts.length).toBe(1);
    expect(scan.hosts[0].ipv4).toBe('192.168.1.5');
    expect(scan.hosts[0].status.state).toBe('up');
    expect(scan.hosts[0].ports.length).toBe(0);
  });
});

describe('NastyMap Diff Engine', () => {
  it('detects added rogue hosts and opened backdoor ports', () => {
    const scanA = parseNmapXml(SECURITY_BREACH_BEFORE_XML);
    const scanB = parseNmapXml(SECURITY_BREACH_AFTER_XML);

    const diff = compareNmapScans(scanA, scanB);
    expect(diff.summary.hostsAdded).toBe(1); // 10.0.10.99
    expect(diff.addedHosts[0].ip).toBe('10.0.10.99');

    const dbHostDiff = diff.modifiedHosts.find((h) => h.ip === '10.0.10.30');
    expect(dbHostDiff).toBeDefined();
    const backdoorPort = dbHostDiff?.portDiffs.find((p) => p.portid === 4444);
    expect(backdoorPort?.changeType).toBe('added');
    expect(backdoorPort?.newPort?.service?.name).toBe('meterpreter');

    const routerDiff = diff.modifiedHosts.find((h) => h.ip === '10.0.10.1');
    expect(routerDiff).toBeDefined();
    const telnetPort = routerDiff?.portDiffs.find((p) => p.portid === 23);
    expect(telnetPort?.changeType).toBe('added');
  });
});

describe('NastyMap Geocoder', () => {
  it('correctly identifies private IP subnets', () => {
    expect(isPrivateIp('192.168.1.1')).toBe(true);
    expect(isPrivateIp('10.0.10.5')).toBe(true);
    expect(isPrivateIp('172.16.0.1')).toBe(true);
    expect(isPrivateIp('127.0.0.1')).toBe(true);
    expect(isPrivateIp('8.8.8.8')).toBe(false);
    expect(isPrivateIp('1.1.1.1')).toBe(false);
  });

  it('geocodes public IP coordinates accurately', () => {
    const google = geocodeIp('8.8.8.8');
    expect(google.countryCode).toBe('US');
    expect(google.city).toBe('Mountain View');
    expect(google.latitude).toBeCloseTo(37.422, 1);
    expect(google.longitude).toBeCloseTo(-122.084, 1);
  });
});

describe('NastyMap Topology Generator', () => {
  it('builds connected graph with scanner origin and traceroute hops', () => {
    const scan = parseNmapXml(ENTERPRISE_NETWORK_XML);
    const graph = generateTopology(scan, { layout: 'force' });

    expect(graph.scannerNode).toBeDefined();
    expect(graph.scannerNode.id).toBe('scanner-origin');
    expect(graph.nodes.length).toBeGreaterThan(scan.hosts.length); // Includes intermediate hops
    expect(graph.links.length).toBeGreaterThan(0);
  });

  it('preserves string versions like "3.10" without numeric trailing-zero stripping', () => {
    const xml = `<?xml version="1.0"?>
    <nmaprun scanner="nmap" args="nmap -sV 192.168.1.50">
      <host>
        <status state="up"/>
        <address addr="192.168.1.50" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache httpd" version="3.10"/>
          </port>
        </ports>
      </host>
    </nmaprun>`;
    const scan = parseNmapXml(xml);
    expect(scan.hosts[0].ports[0].service?.version).toBe('3.10');
  });

  it('merges IPv6-only hosts without collapsing and preserves prior OS/hostname metadata', () => {
    const scan1 = parseNmapXml(`<?xml version="1.0"?>
    <nmaprun scanner="nmap" args="nmap -O -6 2001:db8::10 2001:db8::20">
      <host>
        <status state="up"/>
        <address addr="2001:db8::10" addrtype="ipv6"/>
        <hostnames><hostname name="edge-v6.local" type="PTR"/></hostnames>
        <os><osmatch name="Linux 6.8" accuracy="98"/></os>
        <ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports>
      </host>
      <host>
        <status state="up"/>
        <address addr="2001:db8::20" addrtype="ipv6"/>
      </host>
    </nmaprun>`);

    const scan2 = parseNmapXml(`<?xml version="1.0"?>
    <nmaprun scanner="nmap" args="nmap -p 443 -6 2001:db8::10">
      <host>
        <status state="up"/>
        <address addr="2001:db8::10" addrtype="ipv6"/>
        <ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports>
      </host>
    </nmaprun>`);

    const merged = mergeScanResults(scan1, scan2);
    expect(merged.hosts.length).toBe(2);
    const v6Host = merged.hosts.find((h) => h.ipv6 === '2001:db8::10');
    expect(v6Host?.primaryHostname).toBe('edge-v6.local');
    expect(v6Host?.primaryOs).toBe('Linux 6.8');
    expect(v6Host?.ports.map((p) => p.portid)).toEqual([22, 443]);
  });
});
