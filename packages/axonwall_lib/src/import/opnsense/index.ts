import { XMLParser } from 'fast-xml-parser';
import type { DesiredState, Interface, Vlan, Alias, FirewallRule, NatRule, DhcpSubnet, DnsHostOverride } from '../../schemas/index.js';
import type { ImportReport, ImportReviewItem } from '../types.js';

export type { ImportReport } from '../types.js';

function isXmlFlagSet(val: unknown): boolean {
  return val === '' || val === '1' || val === 1 || val === true || val === 'true' || val === 'yes';
}

function isXmlEnableActive(val: unknown): boolean {
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

export function importOpnsenseConfig(xmlContent: string): ImportReport {
  const warnings: string[] = [];
  const reviewItems: ImportReviewItem[] = [];
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    parseTagValue: false,
    isArray: (name) => {
      return ['alias', 'rule', 'staticmap', 'hosts'].includes(name);
    },
  });

  let parsed: any;
  try {
    parsed = parser.parse(xmlContent);
  } catch (err: any) {
    throw new Error(`Failed to parse OPNsense XML configuration: ${err.message}`);
  }

  const root = parsed.opnsense || parsed.pfsense;
  if (!root) {
    throw new Error('Unrecognized XML root. Expected <opnsense> or <pfsense> root element.');
  }

  const system = root.system || {};
  const hostname = system.hostname || 'axonwall';
  const domain = system.domain || 'local';
  const dnsServers: string[] = [];
  if (system.dnsserver) {
    const rawServers = Array.isArray(system.dnsserver) ? system.dnsserver : [system.dnsserver];
    for (const s of rawServers) {
      if (typeof s === 'string' && s) dnsServers.push(s);
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

      interfaces.push({
        name: key.toLowerCase(),
        device: device,
        type: ifData.ipaddr === 'dhcp' ? 'dhcp' : 'static',
        enabled: ifData.enable === undefined ? true : isXmlEnableActive(ifData.enable),
        description: descr,
        ipv4Address: ip4 || undefined,
        mtu: ifData.mtu ? Number.parseInt(String(ifData.mtu), 10) : 1500,
      });
    }
  }

  // 2. Aliases
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
      const opnType = String(a.type).toLowerCase();
      if (opnType.includes('net')) aliasType = 'network';
      else if (opnType.includes('port')) aliasType = 'port';
      else if (opnType.includes('mac')) aliasType = 'mac';
      else if (opnType.includes('url')) aliasType = 'urltable';

      aliases.push({
        name: safeName,
        type: aliasType,
        entries: aliasType === 'port' ? rawEntries.map((e) => e.replace(/:/g, '-')) : rawEntries,
        description: a.descr ? String(a.descr) : '',
        enabled: a.enabled !== '0' && a.enabled !== 0 && a.enabled !== 'no',
      });
    }
  }

  // 3. Firewall Rules
  const rules: FirewallRule[] = [];
  if (root.filter?.rule) {
    const rawRules = Array.isArray(root.filter.rule) ? root.filter.rule : [root.filter.rule];
    let sortOrder = 10;
    for (const r of rawRules) {
      const action = r.type === 'block' ? 'block' : r.type === 'reject' ? 'reject' : 'pass';
      const iface = r.interface || 'any';
      const rawProto = String(r.protocol || 'any').toLowerCase();
      const validProtos = new Set(['any', 'tcp', 'udp', 'tcp_udp', 'icmp', 'ipv6-icmp', 'esp', 'ah', 'gre']);
      let proto = rawProto === 'tcp/udp' || rawProto === 'tcp_udp' ? 'tcp_udp' : rawProto === 'icmpv6' ? 'ipv6-icmp' : rawProto;
      if (!validProtos.has(proto)) {
        proto = 'any';
      }
      const descr = r.descr ? String(r.descr) : '';

      // Parse source
      let src = 'any';
      let srcPort = '';
      let negatedSrc = false;
      if (r.source) {
        if (r.source.any !== undefined) src = 'any';
        else if (r.source.network) {
          const rawNet = String(r.source.network);
          src = rawNet === '(self)' ? 'self' : `$${rawNet.replace(/[^a-zA-Z0-9_]/g, '_')}`;
        } else if (r.source.address) {
          const rawAddr = String(r.source.address).trim();
          const aliasMatch = aliasMap.get(rawAddr);
          src = aliasMatch ? `$${aliasMatch}` : rawAddr;
        }
        if (r.source.not !== undefined && src !== 'any') negatedSrc = true;
        if (r.source.port) srcPort = normalizeXmlPort(r.source.port, aliasMap);
      }

      // Parse destination
      let dst = 'any';
      let dstPort = '';
      let negatedDst = false;
      if (r.destination) {
        if (r.destination.any !== undefined) dst = 'any';
        else if (r.destination.network) {
          const rawNet = String(r.destination.network);
          dst = rawNet === '(self)' ? 'self' : `$${rawNet.replace(/[^a-zA-Z0-9_]/g, '_')}`;
        } else if (r.destination.address) {
          const rawAddr = String(r.destination.address).trim();
          const aliasMatch = aliasMap.get(rawAddr);
          dst = aliasMatch ? `$${aliasMatch}` : rawAddr;
        }
        if (r.destination.not !== undefined && dst !== 'any') negatedDst = true;
        if (r.destination.port) dstPort = normalizeXmlPort(r.destination.port, aliasMap);
      }

      const hasNegation = negatedSrc || negatedDst;
      const ruleIndex = rules.length;
      const finalDescr = hasNegation ? `[REVIEW: Negated match] ${descr}`.trim() : descr;
      const isEnabled = hasNegation ? false : !isXmlFlagSet(r.disabled);

      if (hasNegation) {
        const reason: ImportReviewItem['reason'] =
          negatedSrc && negatedDst
            ? 'negated_both'
            : negatedSrc
              ? 'negated_source'
              : 'negated_destination';
        const matchSummary = `${action.toUpperCase()} ${proto} from ${negatedSrc ? `!${src}` : src} to ${negatedDst ? `!${dst}` : dst}`;
        const explanation = `Rule "${descr || sortOrder}" uses an inverted (NOT) ${reason === 'negated_both' ? 'source and destination' : reason === 'negated_source' ? 'source' : 'destination'} match (${matchSummary}). Imported with enabled: false so it cannot silently activate with inverted semantics.`;
        const suggestedResolution = `Split into an explicit preceding rule matching ${negatedSrc ? src : dst} with the opposite action, followed by a broader rule matching 'any', then enable the reviewed rules.`;
        warnings.push(explanation + ' ' + suggestedResolution);
        reviewItems.push({
          ruleId: String(r['@_uuid'] || r.uuid || `rule-${ruleIndex + 1}`),
          ruleIndex,
          reason,
          originalMatchSummary: matchSummary,
          explanation,
          suggestedResolution,
        });
      }

      const rawDir = String(r.direction || 'in').toLowerCase();
      rules.push({
        action,
        direction: rawDir === 'out' ? 'out' : 'in',
        interface: iface.toLowerCase(),
        quick: r.quick !== '0' && r.quick !== 0,
        protocol: (proto as any) || 'any',
        source: src,
        sourcePort: srcPort,
        destination: dst,
        destinationPort: dstPort,
        log: Boolean(r.log),
        enabled: isEnabled,
        description: finalDescr,
        sortOrder,
      });
      sortOrder += 10;
    }
  }

  // 4. NAT Rules
  const nat: NatRule[] = [];
  if (root.nat?.rule) {
    const rawNat = Array.isArray(root.nat.rule) ? root.nat.rule : [root.nat.rule];
    let sortOrder = 10;
    const validNatProtos = new Set(['any', 'tcp', 'udp', 'tcp_udp', 'icmp', 'ipv6-icmp', 'esp', 'ah', 'gre']);
    for (const n of rawNat) {
      const rawNatProto = String(n.protocol || 'tcp').toLowerCase();
      let natProto = rawNatProto === 'tcp/udp' || rawNatProto === 'tcp_udp' ? 'tcp_udp' : rawNatProto === 'icmpv6' ? 'ipv6-icmp' : rawNatProto;
      if (!validNatProtos.has(natProto)) natProto = 'tcp';
      nat.push({
        type: 'dnat',
        interface: (n.interface || 'wan').toLowerCase(),
        protocol: natProto as any,
        source: 'any',
        sourcePort: '',
        destination: 'wan_ip',
        destinationPort: normalizeXmlPort(n.destination?.port || n.local_port || '', aliasMap),
        targetIp: n.target ? String(n.target) : '',
        targetPort: normalizeXmlPort(n.local_port || '', aliasMap),
        log: Boolean(n.log),
        enabled: !isXmlFlagSet(n.disabled),
        description: n.descr ? String(n.descr) : '',
        sortOrder,
      });
      sortOrder += 10;
    }
  }

  // 5. DHCP Server (dhcpd)
  const subnets: DhcpSubnet[] = [];
  if (root.dhcpd) {
    for (const [ifKey, dData] of Object.entries<any>(root.dhcpd)) {
      if (typeof dData !== 'object' || !dData || !isXmlEnableActive(dData.enable)) continue;
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

      subnets.push({
        interface: ifKey.toLowerCase(),
        subnet: '192.168.1.0/24', // Fallback default if not specified in dhcpd block
        poolStart: range.from || '192.168.1.100',
        poolEnd: range.to || '192.168.1.200',
        routers: dData.gateway ? [dData.gateway] : [],
        dnsServers: dData.dnsserver ? (Array.isArray(dData.dnsserver) ? dData.dnsserver : [dData.dnsserver]) : [],
        staticMappings,
        enabled: true,
      });
    }
  }

  // 6. Unbound DNS Overrides
  const hostOverrides: DnsHostOverride[] = [];
  if (root.unbound?.hosts) {
    const rawHosts = Array.isArray(root.unbound.hosts) ? root.unbound.hosts : [root.unbound.hosts];
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

  const state: DesiredState = {
    version: 1,
    system: {
      hostname,
      domain,
      dnsServers: dnsServers.length > 0 ? dnsServers : ['1.1.1.1'],
      timezone: system.timezone || 'UTC',
      flowtableOffload: true,
      antiLockout: {
        enabled: true,
        interface: 'lan',
        ports: [22, 80, 443, 3000],
      },
    },
    interfaces,
    aliases,
    rules,
    nat,
    gateways: [],
    gatewayGroups: [],
    vlans: [],
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
    routes: [],
  };

  return {
    success: true,
    vendor: 'opnsense',
    version: root['@_version'] || 'unknown',
    sourceFormat: 'OPNsense XML (config.xml)',
    interfacesCount: interfaces.length,
    vlansCount: 0,
    aliasesCount: aliases.length,
    rulesCount: rules.length,
    natRulesCount: nat.length,
    dhcpSubnetsCount: subnets.length,
    dnsOverridesCount: hostOverrides.length,
    routesCount: 0,
    warnings,
    reviewItems,
    state,
  };
}
