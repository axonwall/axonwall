import { XMLParser } from 'fast-xml-parser';
import type {
  DesiredState,
  Interface,
  Vlan,
  Alias,
  FirewallRule,
  NatRule,
  DhcpSubnet,
  DnsHostOverride,
  StaticRoute,
  Gateway,
} from '../../schemas/index.js';
import type { ImportReport, ImportReviewItem } from '../types.js';

function isXmlFlagSet(val: unknown): boolean {
  return val === '' || val === '1' || val === 1 || val === true || val === 'true' || val === 'yes';
}

function normalizeXmlPort(raw: unknown, aliasMap: Map<string, string>): string {
  const s = String(raw ?? '').trim();
  if (!s) return '';
  const alias = aliasMap.get(s);
  if (alias) return `$${alias}`;
  const lower = s.toLowerCase();
  const named: Record<string, string> = {
    http: '80',
    https: '443',
    ssh: '22',
    telnet: '23',
    smtp: '25',
    domain: '53',
    dns: '53',
    bootps: '67',
    bootpc: '68',
    tftp: '69',
    ntp: '123',
    snmp: '161',
    ldap: '389',
    ldaps: '636',
    rdp: '3389',
    'ms-wbt-server': '3389',
  };
  if (named[lower]) return named[lower];
  return s.replace(/:/g, '-');
}

function parseXmlEndpoint(
  endpoint: any,
  aliasMap: Map<string, string>,
  defaultAddr: string,
  mapWanIp = false,
): { addr: string; port: string; negated: boolean } {
  let addr = defaultAddr;
  let port = '';
  let negated = false;

  if (typeof endpoint === 'string') {
    const rawAddr = endpoint.trim();
    if (rawAddr) {
      const aliasMatch = aliasMap.get(rawAddr);
      addr = aliasMatch ? `$${aliasMatch}` : rawAddr;
    }
    return { addr, port, negated };
  }

  if (endpoint && typeof endpoint === 'object') {
    if (endpoint.any !== undefined) {
      addr = defaultAddr;
    } else if (endpoint.network) {
      const rawNet = String(endpoint.network).trim();
      if (rawNet === '(self)') {
        addr = 'self';
      } else if (mapWanIp && (rawNet.toLowerCase() === 'wanip' || rawNet.toLowerCase() === 'wan_ip')) {
        addr = 'wan_ip';
      } else {
        addr = `$${rawNet.replace(/[^a-zA-Z0-9_]/g, '_')}`;
      }
    } else if (endpoint.address) {
      const rawAddr = String(endpoint.address).trim();
      const aliasMatch = aliasMap.get(rawAddr);
      addr = aliasMatch ? `$${aliasMatch}` : rawAddr;
    }
    if (endpoint.not !== undefined && addr !== 'any' && addr !== 'wan_ip') {
      negated = true;
    }
    if (endpoint.port) {
      port = normalizeXmlPort(endpoint.port, aliasMap);
    }
  }

  return { addr, port, negated };
}

export function importPfsenseConfig(xmlContent: string): ImportReport {
  const warnings: string[] = [];
  const reviewItems: ImportReviewItem[] = [];
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    parseTagValue: false,
    processEntities: false,
    isArray: (name) => {
      return [
        'alias',
        'rule',
        'staticmap',
        'hosts',
        'tag',
        'vlan',
        'route',
        'gateway_item',
        'dnsserver',
      ].includes(name);
    },
  });

  let parsed: any;
  try {
    parsed = parser.parse(xmlContent);
  } catch (err: any) {
    throw new Error(`Failed to parse pfSense XML configuration: ${err.message}`);
  }

  const root = parsed.pfsense;
  if (!root) {
    throw new Error('Unrecognized XML root. Expected <pfsense> root element.');
  }

  const version = typeof root.version === 'string' || typeof root.version === 'number'
    ? String(root.version)
    : root['@_version'] || '2.x';

  // System
  const system = root.system || {};
  const hostname = system.hostname || 'axonwall';
  const domain = system.domain || 'local';
  const timezone = system.timezone || 'UTC';
  const dnsServers: string[] = [];
  if (system.dnsserver) {
    const rawServers = Array.isArray(system.dnsserver) ? system.dnsserver : [system.dnsserver];
    for (const s of rawServers) {
      if (typeof s === 'string' && s.trim()) dnsServers.push(s.trim());
    }
  }

  // 1. Interfaces
  const interfaces: Interface[] = [];
  if (root.interfaces) {
    for (const [key, ifData] of Object.entries<any>(root.interfaces)) {
      if (typeof ifData !== 'object' || !ifData) continue;
      const device = ifData.if || key;
      const descr = ifData.descr || key.toUpperCase();
      let ip4 = '';
      if (ifData.ipaddr && ifData.ipaddr !== 'dhcp' && ifData.ipaddr !== 'none') {
        const subnet = ifData.subnet || '24';
        ip4 = `${ifData.ipaddr}/${subnet}`;
      }

      // In pfSense, presence of <enable> (even empty string or undefined in core WAN/LAN) denotes enabled
      const isEnabled = ifData.enable === undefined ? true : isXmlFlagSet(ifData.enable);

      let ip6 = '';
      if (ifData.ipaddrv6 && ifData.ipaddrv6 !== 'none' && ifData.ipaddrv6 !== 'track6') {
        const subnetv6 = ifData.subnetv6 || '64';
        ip6 = `${ifData.ipaddrv6}/${subnetv6}`;
      }

      interfaces.push({
        name: key.toLowerCase(),
        device,
        type: ifData.ipaddr === 'dhcp' ? 'dhcp' : 'static',
        enabled: isEnabled,
        description: descr,
        ipv4Address: ip4 || undefined,
        ipv4Gateway: ifData.gateway || undefined,
        ipv6Address: ip6 || undefined,
        mtu: ifData.mtu ? Number.parseInt(String(ifData.mtu), 10) : 1500,
        macAddress: ifData.spoofmac || undefined,
      });
    }
  }

  // 2. VLANs
  const vlans: Vlan[] = [];
  const rawVlanEntries = root.vlans?.vlan || root.vlans?.tag;
  if (rawVlanEntries) {
    const rawTags = Array.isArray(rawVlanEntries) ? rawVlanEntries : [rawVlanEntries];
    for (const t of rawTags) {
      if (!t.tag) continue;
      const tagNum = Number.parseInt(String(t.tag), 10);
      const parentIf = t.if || 'lan';
      const vlanIf = t.vlanif || `${parentIf}.${tagNum}`;
      vlans.push({
        tag: tagNum,
        parentInterface: parentIf,
        vlanInterface: vlanIf,
        priority: 0,
        description: t.descr || `VLAN ${tagNum}`,
      });
    }
  }

  // 3. Aliases
  const aliases: Alias[] = [];
  const aliasMap = new Map<string, string>();
  if (root.aliases?.alias) {
    const rawAliases = Array.isArray(root.aliases.alias) ? root.aliases.alias : [root.aliases.alias];
    for (const a of rawAliases) {
      if (!a.name) continue;
      const origName = String(a.name).trim();
      const safeName = origName.replace(/[^a-zA-Z0-9_]/g, '_');
      aliasMap.set(origName, safeName);
      aliasMap.set(safeName, safeName);

      let rawEntries: string[] = [];
      if (a.address !== undefined && a.address !== null && String(a.address).trim() !== '') {
        rawEntries = String(a.address).split(/[\s,]+/).filter(Boolean);
      } else if (a.content !== undefined && a.content !== null && String(a.content).trim() !== '') {
        rawEntries = String(a.content).split(/[\s,]+/).filter(Boolean);
      }

      let aliasType: 'host' | 'network' | 'port' | 'mac' | 'urltable' = 'host';
      const pType = String(a.type).toLowerCase();
      if (pType.includes('net')) aliasType = 'network';
      else if (pType.includes('port')) aliasType = 'port';
      else if (pType.includes('mac')) aliasType = 'mac';
      else if (pType.includes('url')) aliasType = 'urltable';

      aliases.push({
        name: safeName,
        type: aliasType,
        entries: aliasType === 'port' ? rawEntries.map((e) => e.replace(/:/g, '-')) : rawEntries,
        description: a.descr ? String(a.descr) : '',
        enabled: a.enabled !== '0' && a.enabled !== 0 && a.enabled !== 'no',
      });
    }
  }

  // 4. Firewall Filter Rules
  const rules: FirewallRule[] = [];
  if (root.filter?.rule) {
    const rawRules = Array.isArray(root.filter.rule) ? root.filter.rule : [root.filter.rule];
    let sortOrder = 10;
    for (const r of rawRules) {
      const rawType = String(r.type ?? '').trim().toLowerCase();
      if (rawType === 'match') {
        warnings.push(
          `Skipped non-terminal pfSense "match" rule${r.descr ? ` ("${r.descr}")` : ''}: queue/tag match rules do not pass or block traffic.`,
        );
        continue;
      }
      let action: 'pass' | 'block' | 'reject';
      let hasUnknownType = false;
      if (rawType === 'pass') {
        action = 'pass';
      } else if (rawType === 'block') {
        action = 'block';
      } else if (rawType === 'reject') {
        action = 'reject';
      } else {
        action = 'block';
        hasUnknownType = true;
      }

      let iface = r.interface ? String(r.interface).toLowerCase() : 'any';
      if (r.floating === 'yes' || r.floating === '1') {
        iface = 'any';
      }

      let proto: 'any' | 'tcp' | 'udp' | 'tcp_udp' | 'icmp' | 'esp' = 'any';
      const rawProto = String(r.protocol || 'any').toLowerCase();
      if (rawProto === 'tcp/udp' || rawProto === 'tcp_udp') proto = 'tcp_udp';
      else if (rawProto === 'tcp') proto = 'tcp';
      else if (rawProto === 'udp') proto = 'udp';
      else if (rawProto.includes('icmp')) proto = 'icmp';
      else if (rawProto === 'esp') proto = 'esp';

      // Source & destination parsing
      const parsedSrc = parseXmlEndpoint(r.source, aliasMap, 'any');
      const parsedDst = parseXmlEndpoint(r.destination, aliasMap, 'any');
      const src = parsedSrc.addr;
      const srcPort = parsedSrc.port;
      const negatedSrc = parsedSrc.negated;
      const dst = parsedDst.addr;
      const dstPort = parsedDst.port;
      const negatedDst = parsedDst.negated;

      const hasNegation = negatedSrc || negatedDst;
      const ruleIndex = rules.length;
      const baseDescr = r.descr ? String(r.descr) : '';
      const reviewPrefixes: string[] = [];
      if (hasUnknownType) reviewPrefixes.push(`Unknown rule type "${rawType || 'missing'}"`);
      if (hasNegation) reviewPrefixes.push('Negated match');
      const finalDescr =
        reviewPrefixes.length > 0 ? `[REVIEW: ${reviewPrefixes.join('; ')}] ${baseDescr}`.trim() : baseDescr;
      const isEnabled = hasNegation || hasUnknownType ? false : !isXmlFlagSet(r.disabled);

      if (hasUnknownType) {
        const matchSummary = `TYPE=${rawType || 'missing'} ${proto} from ${src} to ${dst}`;
        const explanation = `pfSense rule "${baseDescr || sortOrder}" has unrecognized or missing <type> "${rawType || 'missing'}" (${matchSummary}). Imported fail-closed with action: block and enabled: false.`;
        const suggestedResolution = `Verify the intended rule action (pass, block, or reject) in pfSense before enabling.`;
        warnings.push(explanation + ' ' + suggestedResolution);
        reviewItems.push({
          ruleId: String(r.tracker || `rule-${ruleIndex + 1}`),
          ruleIndex,
          reason: 'manual_review',
          originalMatchSummary: matchSummary,
          explanation,
          suggestedResolution,
        });
      }

      if (hasNegation) {
        const reason: ImportReviewItem['reason'] =
          negatedSrc && negatedDst
            ? 'negated_both'
            : negatedSrc
              ? 'negated_source'
              : 'negated_destination';
        const matchSummary = `${action.toUpperCase()} ${proto} from ${negatedSrc ? `!${src}` : src} to ${negatedDst ? `!${dst}` : dst}`;
        const explanation = `Rule "${baseDescr || sortOrder}" uses an inverted (NOT) ${reason === 'negated_both' ? 'source and destination' : reason === 'negated_source' ? 'source' : 'destination'} match (${matchSummary}). Imported with enabled: false so it cannot silently activate with inverted semantics.`;
        const suggestedResolution = `Split into an explicit preceding rule matching ${negatedSrc ? src : dst} with the opposite action, followed by a broader rule matching 'any', then enable the reviewed rules.`;
        warnings.push(explanation + ' ' + suggestedResolution);
        reviewItems.push({
          ruleId: String(r.tracker || `rule-${ruleIndex + 1}`),
          ruleIndex,
          reason,
          originalMatchSummary: matchSummary,
          explanation,
          suggestedResolution,
        });
      }

      rules.push({
        action,
        direction: r.direction === 'out' ? 'out' : 'in',
        interface: iface,
        quick: r.quick !== 'no' && r.quick !== '0',
        protocol: proto,
        source: src,
        sourcePort: srcPort,
        destination: dst,
        destinationPort: dstPort,
        gateway: r.gateway ? String(r.gateway) : undefined,
        ...(negatedSrc ? { invertSource: true } : {}),
        ...(negatedDst ? { invertDestination: true } : {}),
        log: isXmlFlagSet(r.log),
        enabled: isEnabled,
        description: finalDescr,
        sortOrder,
      });
      sortOrder += 10;
    }
  }

  // 5. NAT Rules (DNAT / Port Forwards, Outbound SNAT / Masquerade, 1:1 NAT)
  const nat: NatRule[] = [];
  let natSort = 10;

  // Port Forward (DNAT)
  const validNatProtos = new Set(['any', 'tcp', 'udp', 'tcp_udp', 'icmp', 'ipv6-icmp', 'esp', 'ah', 'gre']);
  if (root.nat?.rule) {
    const rawNat = Array.isArray(root.nat.rule) ? root.nat.rule : [root.nat.rule];
    for (const n of rawNat) {
      const iface = (n.interface || 'wan').toLowerCase();
      const localPort = n['local-port'] || n.local_port || n.destination?.port || '';
      const rawNatProto = String(n.protocol || 'tcp').toLowerCase();
      let natProto = rawNatProto === 'tcp/udp' || rawNatProto === 'tcp_udp' ? 'tcp_udp' : rawNatProto === 'icmpv6' ? 'ipv6-icmp' : rawNatProto;
      if (!validNatProtos.has(natProto)) natProto = 'tcp';

      const dnatSrc = parseXmlEndpoint(n.source, aliasMap, 'any');
      const dnatDst = parseXmlEndpoint(n.destination, aliasMap, 'wan_ip', true);
      const isNoRdr = n.nordr !== undefined && isXmlFlagSet(n.nordr);
      const hasNatReview = dnatSrc.negated || dnatDst.negated || isNoRdr;
      const baseNatDescr = n.descr ? String(n.descr) : '';
      if (hasNatReview) {
        warnings.push(
          `pfSense DNAT rule "${baseNatDescr || natSort}" uses ${isNoRdr ? '<nordr/> exclusion' : 'negated source/destination matching'} which cannot be safely activated as a standard forward; imported with enabled: false.`,
        );
      }

      nat.push({
        type: 'dnat',
        interface: iface,
        protocol: natProto as any,
        source: dnatSrc.addr,
        sourcePort: dnatSrc.port,
        destination: dnatDst.addr,
        destinationPort: normalizeXmlPort(n.destination?.port || localPort || '', aliasMap),
        targetIp: n.target ? String(n.target) : '',
        targetPort: normalizeXmlPort(localPort || '', aliasMap),
        log: isXmlFlagSet(n.log),
        enabled: hasNatReview ? false : !isXmlFlagSet(n.disabled),
        description: hasNatReview ? `[REVIEW: ${isNoRdr ? 'No-RDR' : 'Negated NAT'}] ${baseNatDescr}`.trim() : baseNatDescr,
        sortOrder: natSort,
      });
      natSort += 10;
    }
  }

  // Outbound NAT (Masquerade / SNAT)
  if (root.nat?.outbound?.rule) {
    const rawOutbound = Array.isArray(root.nat.outbound.rule) ? root.nat.outbound.rule : [root.nat.outbound.rule];
    for (const o of rawOutbound) {
      const iface = (o.interface || 'wan').toLowerCase();
      const outSrc = parseXmlEndpoint(o.source, aliasMap, 'any');
      const outDst = parseXmlEndpoint(o.destination, aliasMap, 'any');
      const isNoNat = o.nonat !== undefined && isXmlFlagSet(o.nonat);
      const hasOutReview = outSrc.negated || outDst.negated || isNoNat;
      const baseOutDescr = o.descr ? String(o.descr) : 'Outbound NAT';
      if (hasOutReview) {
        warnings.push(
          `pfSense Outbound NAT rule "${baseOutDescr}" uses ${isNoNat ? '<nonat/> exclusion' : 'negated source/destination matching'}; imported with enabled: false.`,
        );
      }

      nat.push({
        type: o.target ? 'snat' : 'masquerade',
        interface: iface,
        protocol: 'any',
        source: outSrc.addr,
        sourcePort: outSrc.port,
        destination: outDst.addr,
        destinationPort: outDst.port,
        targetIp: o.target ? String(o.target) : undefined,
        log: isXmlFlagSet(o.log),
        enabled: hasOutReview ? false : !isXmlFlagSet(o.disabled),
        description: hasOutReview ? `[REVIEW: ${isNoNat ? 'No-NAT' : 'Negated NAT'}] ${baseOutDescr}` : baseOutDescr,
        sortOrder: natSort,
      });
      natSort += 10;
    }
  }

  // 6. DHCP Server
  const subnets: DhcpSubnet[] = [];
  if (root.dhcpd) {
    for (const [ifKey, dData] of Object.entries<any>(root.dhcpd)) {
      if (typeof dData !== 'object' || !dData || !isXmlFlagSet(dData.enable)) continue;
      const range = dData.range || {};
      const staticMappings = [];
      if (dData.staticmap) {
        const rawMap = Array.isArray(dData.staticmap) ? dData.staticmap : [dData.staticmap];
        for (const m of rawMap) {
          if (m.mac && m.ipaddr) {
            staticMappings.push({
              mac: m.mac,
              ip: m.ipaddr,
              hostname: m.hostname || '',
              description: m.descr || '',
            });
          }
        }
      }

      // Try finding corresponding interface subnet
      const iface = interfaces.find((i) => i.name === ifKey.toLowerCase());
      const subnetCIDR = iface?.ipv4Address || '192.168.1.0/24';

      subnets.push({
        interface: ifKey.toLowerCase(),
        subnet: subnetCIDR,
        poolStart: range.from || '192.168.1.100',
        poolEnd: range.to || '192.168.1.200',
        routers: dData.gateway ? [dData.gateway] : iface?.ipv4Address ? [iface.ipv4Address.split('/')[0]] : [],
        dnsServers: dData.dnsserver ? (Array.isArray(dData.dnsserver) ? dData.dnsserver : [dData.dnsserver]) : [],
        staticMappings,
        enabled: true,
      });
    }
  }

  // 7. DNS Overrides (Unbound & Dnsmasq)
  const hostOverrides: DnsHostOverride[] = [];
  const dnsHosts = root.unbound?.hosts || root.dnsmasq?.hosts;
  if (dnsHosts) {
    const rawHosts = Array.isArray(dnsHosts) ? dnsHosts : [dnsHosts];
    for (const h of rawHosts) {
      if (h.host && h.domain && h.ip) {
        hostOverrides.push({
          hostname: h.host,
          domain: h.domain,
          ip: h.ip,
          description: h.descr || '',
        });
      }
    }
  }

  // 8. Static Routes
  const routes: StaticRoute[] = [];
  if (root.staticroutes?.route) {
    const rawRoutes = Array.isArray(root.staticroutes.route) ? root.staticroutes.route : [root.staticroutes.route];
    for (const r of rawRoutes) {
      if (r.network && r.gateway) {
        routes.push({
          network: r.network,
          gateway: r.gateway,
          description: r.descr || '',
          enabled: true,
        });
      }
    }
  }

  // 9. Gateways
  const gateways: Gateway[] = [];
  if (root.gateways?.gateway_item) {
    const rawGw = Array.isArray(root.gateways.gateway_item) ? root.gateways.gateway_item : [root.gateways.gateway_item];
    for (const g of rawGw) {
      if (g.name && g.gateway && String(g.gateway).trim().toLowerCase() !== 'dynamic') {
        gateways.push({
          name: String(g.name),
          interface: (g.interface || 'wan').toLowerCase(),
          gatewayIp: String(g.gateway).trim(),
          monitorIp: g.monitor ? String(g.monitor) : undefined,
          weight: g.weight ? Number.parseInt(String(g.weight), 10) : 1,
          isDefault: isXmlFlagSet(g.defaultgw) || Boolean(g.defaultgw),
          enabled: !isXmlFlagSet(g.disabled),
          description: g.descr ? String(g.descr) : '',
        });
      }
    }
  }

  const state: DesiredState = {
    version: 1,
    system: {
      hostname,
      domain,
      dnsServers: dnsServers.length > 0 ? dnsServers : ['1.1.1.1'],
      timezone,
      flowtableOffload: true,
      antiLockout: {
        enabled: true,
        interface: 'lan',
        ports: [22, 80, 443, 3000, 2966],
      },
    },
    interfaces,
    vlans,
    aliases,
    rules,
    nat,
    gateways,
    gatewayGroups: [],
    bridges: [],
    bonds: [],
    virtualIps: [],
    vrfs: [],
    dhcp: {
      enabled: subnets.length > 0,
      subnets,
    },
    dns: {
      enabled: true,
      listenPort: 53,
      dnssec: true,
      dotEnabled: true,
      dotUpstreams: ['1.1.1.1@853#cloudflare-dns.com'],
      hostOverrides,
    },
    routes,
  };

  return {
    success: true,
    vendor: 'pfsense',
    version,
    sourceFormat: 'pfSense XML (config.xml)',
    interfacesCount: interfaces.length,
    vlansCount: vlans.length,
    aliasesCount: aliases.length,
    rulesCount: rules.length,
    natRulesCount: nat.length,
    dhcpSubnetsCount: subnets.length,
    dnsOverridesCount: hostOverrides.length,
    routesCount: routes.length,
    warnings,
    reviewItems,
    state,
  };
}
