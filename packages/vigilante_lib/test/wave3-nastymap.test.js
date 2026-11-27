import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { generateHeadlessSvg, generateHtmlReport } from '../src/engine/nastymap/exporter.js';
import { isPrivateIp, geocodeIp } from '../src/engine/nastymap/geoip.js';
import { parseNmapXml, MAX_NMAP_XML_BYTES, MAX_NMAP_XML_DEPTH } from '../src/engine/nastymap/parser.js';

describe('Wave 3 SEC-L15: Vigilante NastyMap Hardening', () => {
  it('coerces all numeric SVG attributes and escapes XML in generateHeadlessSvg and generateHtmlReport', () => {
    const graph = {
      nodes: [
        {
          id: 'scanner-origin',
          label: 'Scanner <img src=x onerror=alert(1)>',
          ip: '127.0.0.1',
          nodeType: 'scanner',
          status: 'up',
          x: '10" onload="alert(1)',
          y: Infinity,
          radius: '25" onclick="alert(2)',
          color: 'url(https://evil.test/x.svg#id)',
          riskScore: NaN,
          riskTier: 'LOW',
        },
        {
          id: '10.0.0.5',
          label: 'Host" onmouseover="alert(3)',
          ip: '10.0.0.5',
          nodeType: 'host',
          status: 'up',
          x: '320',
          y: -25,
          radius: -10,
          color: '#ef4444" onload="alert(4)',
          riskScore: 95,
          riskTier: 'CRITICAL',
        },
      ],
      links: [
        {
          id: 'l1',
          source: 'scanner-origin',
          target: '10.0.0.5',
          type: 'lateral-attack-path',
          label: 'Attack <script>alert(5)</script>',
        },
      ],
      subnets: ['10.0.0.0/24'],
    };

    const svg = generateHeadlessSvg(graph, {
      width: '1000" onload="alert(0)',
      height: NaN,
      title: 'Topology <svg onload=alert(1)>',
    });

    assert.match(svg, /viewBox="0 0 1200 800"/);
    assert.match(svg, /width="1200" height="800"/);
    assert.match(svg, /transform="translate\(0, 0\)"/);
    assert.match(svg, /transform="translate\(320, -25\)"/);
    assert.match(svg, /<circle r="10"/);
    assert.match(svg, /x1="0" y1="0" x2="320" y2="-25"/);
    assert.match(svg, /font-size="18"/);
    assert.match(svg, /font-size="11"/);
    assert.match(svg, /font-size="10"/);
    assert.match(svg, /font-size="9"/);
    assert.match(svg, /fill="#3b82f6"/);
    assert.match(svg, /Host&quot; onmouseover=&quot;alert\(3\)/);
    assert.match(svg, /Topology &lt;svg onload=alert\(1\)&gt;/);
    assert.match(svg, /Scanner &lt;img src=x onerror=alert\(1\)&gt;/);
    assert.match(svg, /RISK: 95\/100 \[CRITICAL\]/);
    assert.doesNotMatch(svg, /"\s+on(?:load|click|mouseover|error)=/i);
    assert.doesNotMatch(svg, /<(?:img|script)/i);
    assert.doesNotMatch(svg, /<svg[^>]+on(?:load|click|mouseover|error)=/i);
    assert.doesNotMatch(svg, /Infinity|NaN/);

    const html = generateHtmlReport(
      {
        args: 'nmap " onclick="alert(1)',
        target: '10.0.0.0/24',
        hosts: [
          {
            id: '10.0.0.5',
            ipv4: '10.0.0.5',
            isUp: true,
            ports: [],
            openPortsCount: 'NaN',
            vulnerabilitiesCount: Infinity,
          },
        ],
      },
      graph
    );
    assert.match(html, /viewBox="0 0 1200 800"/);
    assert.match(html, /&quot; onclick=&quot;alert\(1\)/);
    assert.doesNotMatch(html, /" onclick="alert\(1\)"/);
    assert.doesNotMatch(html, /Infinity|NaN/);
  });

  it('rejects all non-public IPv4, IPv6, IPv4-mapped, and transition IP ranges in GeoIP', () => {
    const nonPublic = [
      '127.0.0.1',
      '127.1.2.3',
      '10.0.0.1',
      '10.255.255.254',
      '172.16.0.1',
      '172.31.255.254',
      '192.168.0.1',
      '192.168.255.254',
      '169.254.0.1',
      '169.254.169.254',
      '100.64.0.1',
      '100.127.255.254',
      '0.0.0.0',
      '0.1.2.3',
      '::1',
      '0:0:0:0:0:0:0:1',
      '[::1]',
      '::',
      'localhost',
      'fc00::1',
      'fd00::1',
      'fd12:3456:789a::1',
      'fd00:ec2::254',
      'fe80::1',
      'fe80::1%eth0',
      'febf::1',
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
      '64:ff9b:1::1',
      '64:ff9b::10.0.0.1',
      '2002::1',
      '2002:0808:0808::1',
      '2001::1',
      '2001:0:4136:e378:8000:63bf:3fff:fdd2',
      '224.0.0.1',
      '255.255.255.255',
      'ff02::1',
      '0177.0.0.1',
      'invalid-ip',
      '',
    ];

    for (const ip of nonPublic) {
      assert.equal(isPrivateIp(ip), true, `expected isPrivateIp(${ip}) === true`);
      assert.equal(geocodeIp(ip).isPrivate, true, `expected geocodeIp(${ip}).isPrivate === true`);
    }

    const publicIps = [
      '8.8.8.8',
      '1.1.1.1',
      '93.184.216.34',
      '172.15.255.254',
      '172.32.0.1',
      '100.63.255.254',
      '100.128.0.1',
      '::ffff:8.8.8.8',
      '2001:4860:4860::8888',
      '2606:4700:4700::1111',
      '2a00:1450:4001:800::200e',
    ];

    for (const ip of publicIps) {
      assert.equal(isPrivateIp(ip), false, `expected isPrivateIp(${ip}) === false`);
      assert.equal(geocodeIp(ip).isPrivate, false, `expected geocodeIp(${ip}).isPrivate === false`);
    }
  });

  it('enforces 25 MB XML payload cap, depth limit, and entity guard before XMLParser', () => {
    assert.equal(MAX_NMAP_XML_BYTES, 25 * 1024 * 1024);

    const oversizedAscii = `<nmaprun>${'A'.repeat(MAX_NMAP_XML_BYTES + 1)}</nmaprun>`;
    const asciiRes = parseNmapXml(oversizedAscii, 'big.xml');
    assert.equal(asciiRes.isValid, false);
    assert.match(asciiRes.error, /25 MB|maximum allowed size/i);

    const oversizedUtf8 = '€'.repeat(9_000_000);
    assert.ok(oversizedUtf8.length < MAX_NMAP_XML_BYTES);
    const utf8Res = parseNmapXml(oversizedUtf8, 'utf8-big.xml');
    assert.equal(utf8Res.isValid, false);
    assert.match(utf8Res.error, /25 MB|maximum allowed size/i);

    const deepCount = MAX_NMAP_XML_DEPTH + 10;
    const deepXml = `${'<a>'.repeat(deepCount)}${'</a>'.repeat(deepCount)}`;
    const deepRes = parseNmapXml(deepXml, 'deep.xml');
    assert.equal(deepRes.isValid, false);
    assert.match(deepRes.error, /nesting depth/i);

    const entityXml = '<?xml version="1.0"?><!DOCTYPE nmaprun [ <!ENTITY lol "lol"> ]><nmaprun/>';
    const entityRes = parseNmapXml(entityXml, 'entity.xml');
    assert.equal(entityRes.isValid, false);
    assert.match(entityRes.error, /entity declarations/i);

    const validXml = `<?xml version="1.0"?>
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
    const validRes = parseNmapXml(validXml, 'valid.xml');
    assert.equal(validRes.isValid, true);
    assert.equal(validRes.hosts.length, 1);
    assert.equal(validRes.hosts[0].ports[0].scripts[0].elements.safe, 'value');
    assert.equal({}.polluted, undefined);
  });
});
