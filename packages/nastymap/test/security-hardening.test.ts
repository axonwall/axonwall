import { describe, expect, it } from 'vitest';
import {
  generateHeadlessSvg,
  generateHtmlReport,
  geocodeIp,
  isPrivateIp,
  MAX_NMAP_XML_BYTES,
  MAX_NMAP_XML_DEPTH,
  parseNmapXml,
} from '../src/index.js';
import type { NmapRun, TopologyGraph } from '../src/types/nmap.js';

describe('SEC-L15: SVG numeric attribute coercion', () => {
  it('coerces non-finite and injection values in width, height, coordinates, radii, and fonts', () => {
    const graph = {
      nodes: [
        {
          id: 'scanner-origin',
          label: 'Scanner <evil>',
          ip: '127.0.0.1',
          nodeType: 'scanner',
          status: 'up',
          osFamily: 'Linux',
          osName: 'Linux',
          deviceType: 'security scanner',
          openPorts: [],
          openPortDetails: [],
          hopsAway: 0,
          x: '100" onload="alert(1)' as unknown as number,
          y: Infinity,
          radius: '20" onclick="alert(2)' as unknown as number,
          color: 'url(https://evil.example/a.svg#x)',
        },
        {
          id: '10.0.0.2',
          label: 'Target" onmouseover="alert(3)',
          ip: '10.0.0.2',
          nodeType: 'host',
          status: 'up',
          osFamily: 'Linux',
          osName: 'Linux',
          deviceType: 'server',
          openPorts: [22],
          openPortDetails: [],
          hopsAway: 1,
          x: '250' as unknown as number,
          y: -15,
          radius: -5,
          color: '#22c55e" onload="alert(4)',
        },
      ],
      links: [
        {
          id: 'l1',
          source: 'scanner-origin',
          target: '10.0.0.2',
          type: 'traceroute',
          label: '1.2ms <tag>',
        },
      ],
      subnets: ['10.0.0.0/24'],
    } as unknown as TopologyGraph;

    const svg = generateHeadlessSvg(graph, {
      width: '800" onload="alert(0)' as unknown as number,
      height: NaN,
      title: 'Scan <script>alert(1)</script>',
    });

    expect(svg).toContain('viewBox="0 0 1200 800"');
    expect(svg).toContain('width="1200" height="800"');
    expect(svg).toContain('transform="translate(0, 0)"');
    expect(svg).toContain('transform="translate(250, -15)"');
    expect(svg).toContain('<circle r="10"');
    expect(svg).toContain('x1="0" y1="0" x2="250" y2="-15"');
    expect(svg).toContain('font-size="18"');
    expect(svg).toContain('font-size="11"');
    expect(svg).toContain('font-size="10"');
    expect(svg).toContain('font-size="9"');
    expect(svg).toContain('fill="#3b82f6"');
    expect(svg).toContain('Target&quot; onmouseover=&quot;alert(3)');
    expect(svg).not.toMatch(/"\s+on(?:load|click|mouseover|error)=/i);
    expect(svg).not.toMatch(/\son(?:load|click)=/i);
    expect(svg).not.toContain('Infinity');
    expect(svg).not.toContain('NaN');
    expect(svg).not.toContain('<script>');
  });

  it('escapes title/args and generates valid numeric SVG inside generateHtmlReport', () => {
    const scan: NmapRun = {
      scanner: 'nmap',
      args: 'nmap " onclick="alert(1)',
      start: 1700000000,
      startstr: '2026-01-01',
      version: '7.94',
      xmloutputversion: '1.05',
      hosts: [],
      runstats: {
        finished: { time: 1700000001, elapsed: 1, exit: 'success' },
        hosts: { up: 0, down: 0, total: 0 },
      },
    };
    const graph = {
      nodes: [],
      links: [],
      subnets: [],
    } as unknown as TopologyGraph;

    const html = generateHtmlReport(scan, graph);
    expect(html).toContain('viewBox="0 0 1200 800"');
    expect(html).toContain('&quot; onclick=&quot;alert(1)');
    expect(html).not.toContain('" onclick="alert(1)"');
  });
});

describe('SEC-L15: GeoIP private & non-public IP rejection', () => {
  const nonPublicIps = [
    // 127.0.0.0/8
    '127.0.0.1',
    '127.0.0.2',
    '127.255.255.254',
    // 10.0.0.0/8
    '10.0.0.1',
    '10.255.255.254',
    // 172.16.0.0/12
    '172.16.0.1',
    '172.24.12.34',
    '172.31.255.254',
    // 192.168.0.0/16
    '192.168.0.1',
    '192.168.1.254',
    // 169.254.0.0/16
    '169.254.0.1',
    '169.254.169.254',
    // 100.64.0.0/10 CGNAT
    '100.64.0.1',
    '100.100.1.1',
    '100.127.255.254',
    // 0.0.0.0/8
    '0.0.0.0',
    '0.10.20.30',
    // Loopback / unspecified IPv6
    '::1',
    '0:0:0:0:0:0:0:1',
    '[::1]',
    '::',
    'localhost',
    // ULA fc00::/7
    'fc00::1',
    'fc12:abcd::1',
    'fd00::1',
    'fd12:3456:789a::1',
    'fd00:ec2::254',
    'fdff::1',
    // Link-local fe80::/10
    'fe80::1',
    'fe80::1%eth0',
    'fe9a::1',
    'febf:ffff::1',
    // IPv4-mapped IPv6
    '::ffff:127.0.0.1',
    '::ffff:10.0.0.1',
    '::ffff:172.16.0.1',
    '::ffff:192.168.1.1',
    '::ffff:169.254.169.254',
    '::ffff:100.64.0.1',
    '::ffff:0.0.0.0',
    '::ffff:7f00:1',
    '::FFFF:A9FE:A9FE',
    '0:0:0:0:0:ffff:10.0.0.1',
    // Transition ranges: 64:ff9b:1::/48, 2002::/16, 2001::/32 (+ NAT64 private unwrap)
    '64:ff9b:1::1',
    '64:ff9b:1:dead::beef',
    '64:ff9b::10.0.0.1',
    '64:ff9b::a9fe:a9fe',
    '2002::1',
    '2002:c0a8:0101::1',
    '2002:0808:0808::1',
    '2001::1',
    '2001:0:4136:e378:8000:63bf:3fff:fdd2',
    // Multicast / broadcast / unparseable
    '224.0.0.1',
    '255.255.255.255',
    'ff02::1',
    '0177.0.0.1',
    'not-an-ip',
    '',
  ];

  const publicIps = [
    '8.8.8.8',
    '1.1.1.1',
    '93.184.216.34',
    '172.15.255.254',
    '172.32.0.1',
    '172.67.1.1',
    '100.63.255.254',
    '100.128.0.1',
    '169.255.0.1',
    '::ffff:8.8.8.8',
    '2001:4860:4860::8888',
    '2606:4700:4700::1111',
    '2a00:1450:4001:800::200e',
  ];

  it('rejects all non-public IPv4, IPv6, IPv4-mapped, and transition ranges', () => {
    for (const ip of nonPublicIps) {
      expect(isPrivateIp(ip), `expected isPrivateIp(${ip}) to be true`).toBe(true);
      expect(geocodeIp(ip).isPrivate, `expected geocodeIp(${ip}).isPrivate to be true`).toBe(true);
    }
  });

  it('permits legitimate public IPv4 and IPv6 addresses', () => {
    for (const ip of publicIps) {
      expect(isPrivateIp(ip), `expected isPrivateIp(${ip}) to be false`).toBe(false);
      expect(geocodeIp(ip).isPrivate, `expected geocodeIp(${ip}).isPrivate to be false`).toBe(false);
    }
  });
});

describe('SEC-L15: Max XML payload cap and nesting depth guards', () => {
  it('rejects XML payloads exceeding 25 MB (ASCII and multi-byte UTF-8) before XMLParser', () => {
    expect(MAX_NMAP_XML_BYTES).toBe(25 * 1024 * 1024);

    const oversizedAscii = `<nmaprun>${'A'.repeat(MAX_NMAP_XML_BYTES + 1)}</nmaprun>`;
    expect(() => parseNmapXml(oversizedAscii)).toThrow(/25 MB|maximum allowed size/i);

    // 9M 3-byte UTF-8 chars = 27 MB > 25 MB even though .length is 9M
    const oversizedUtf8 = '€'.repeat(9_000_000);
    expect(oversizedUtf8.length).toBeLessThan(MAX_NMAP_XML_BYTES);
    expect(() => parseNmapXml(oversizedUtf8)).toThrow(/25 MB|maximum allowed size/i);
  });

  it('rejects deeply nested XML bombs and entity declarations before XMLParser', () => {
    const deepCount = MAX_NMAP_XML_DEPTH + 10;
    const deepXml = `${'<a>'.repeat(deepCount)}${'</a>'.repeat(deepCount)}`;
    expect(() => parseNmapXml(deepXml)).toThrow(/nesting depth/i);

    const entityXml = `<?xml version="1.0"?><!DOCTYPE nmaprun [ <!ENTITY lol "lol"> ]><nmaprun/>`;
    expect(() => parseNmapXml(entityXml)).toThrow(/entity declarations/i);
  });

  it('ignores prototype-polluting script element keys while allowing legitimate DOCTYPE nmaprun', () => {
    const xml = `<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap 198.51.100.1">
  <host>
    <status state="up"/>
    <address addr="198.51.100.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <script id="test" output="ok">
          <elem key="__proto__">polluted</elem>
          <elem key="safe">value</elem>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>`;
    const parsed = parseNmapXml(xml);
    expect(parsed.hosts).toHaveLength(1);
    const elems = parsed.hosts[0].ports[0].scripts?.[0].elements;
    expect(elems?.safe).toBe('value');
    expect(({} as any).polluted).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(elems, '__proto__')).toBe(false);
  });
});
