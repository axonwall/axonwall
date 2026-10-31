import { XMLParser } from 'fast-xml-parser';
import type { DesiredState, Interface, Vlan, Alias, FirewallRule, NatRule, DhcpSubnet, DnsHostOverride } from '../../schemas/index.js';
import type { ImportReport, ImportReviewItem } from '../types.js';

export type { ImportReport } from '../types.js';

export function importOpnsenseConfig(xmlContent: string): ImportReport {
  const warnings: string[] = [];
  const reviewItems: ImportReviewItem[] = [];
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
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
        enabled: ifData.enable === '' || ifData.enable === '1' || ifData.enable === undefined,
        description: descr,
        ipv4Address: ip4 || undefined,
        mtu: ifData.mtu ? Number.parseInt(ifData.mtu, 10) : 1500,
      });
    }
  }

  // 2. Aliases
  const aliases: Alias[] = [];
  if (root.aliases?.alias) {
    const rawAliases = Array.isArray(root.aliases.alias) ? root.aliases.alias : [root.aliases.alias];
    for (const a of rawAliases) {
      if (!a.name) continue;
      let rawEntries: string[] = [];
      if (typeof a.address === 'string') {
        rawEntries = a.address.split(/[\s,]+/).filter(Boolean);
      } else if (typeof a.content === 'string') {
        rawEntries = a.content.split(/[\s,]+/).filter(Boolean);
      }

      let aliasType: 'host' | 'network' | 'port' | 'mac' | 'urltable' = 'host';
      const opnType = String(a.type).toLowerCase();
      if (opnType.includes('net')) aliasType = 'network';
      else if (opnType.includes('port')) aliasType = 'port';
      else if (opnType.includes('mac')) aliasType = 'mac';
      else if (opnType.includes('url')) aliasType = 'urltable';

      aliases.push({
        name: String(a.name).replace(/[^a-zA-Z0-9_]/g, '_'),
        type: aliasType,
        entries: rawEntries,
        description: a.descr || '',
        enabled: a.enabled !== '0',
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
        else if (r.source.network) src = `$${String(r.source.network).replace(/[^a-zA-Z0-9_]/g, '_')}`;
        else if (r.source.address) src = String(r.source.address);
        if (r.source.not !== undefined && src !== 'any') negatedSrc = true;
        if (r.source.port) srcPort = String(r.source.port);
      }

      // Parse destination
      let dst = 'any';
      let dstPort = '';
      let negatedDst = false;
      if (r.destination) {
        if (r.destination.any !== undefined) dst = 'any';
        else if (r.destination.network) dst = `$${String(r.destination.network).replace(/[^a-zA-Z0-9_]/g, '_')}`;
        else if (r.destination.address) dst = String(r.destination.address);
        if (r.destination.not !== undefined && dst !== 'any') negatedDst = true;
        if (r.destination.port) dstPort = String(r.destination.port);
      }

      const hasNegation = negatedSrc || negatedDst;
      const ruleIndex = rules.length;
      const finalDescr = hasNegation ? `[REVIEW: Negated match] ${descr}`.trim() : descr;
      const isEnabled = hasNegation ? false : r.disabled !== '1';

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

      rules.push({
        action,
        direction: (r.direction as any) || 'in',
        interface: iface.toLowerCase(),
        quick: r.quick !== '0',
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
    for (const n of rawNat) {
      nat.push({
        type: 'dnat',
        interface: (n.interface || 'wan').toLowerCase(),
        protocol: (n.protocol as any) || 'tcp',
        source: 'any',
        sourcePort: '',
        destination: 'wan_ip',
        destinationPort: String(n.destination?.port || n.local_port || ''),
        targetIp: n.target || '',
        targetPort: String(n.local_port || ''),
        log: Boolean(n.log),
        enabled: n.disabled !== '1',
        description: n.descr || '',
        sortOrder,
      });
      sortOrder += 10;
    }
  }

  // 5. DHCP Server (dhcpd)
  const subnets: DhcpSubnet[] = [];
  if (root.dhcpd) {
    for (const [ifKey, dData] of Object.entries<any>(root.dhcpd)) {
      if (typeof dData !== 'object' || !dData || !dData.enable) continue;
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
