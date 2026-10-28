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

export function importPfsenseConfig(xmlContent: string): ImportReport {
  const warnings: string[] = [];
  const reviewItems: ImportReviewItem[] = [];
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
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
      const isEnabled = ifData.enable !== undefined && ifData.enable !== '0';

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
  if (root.vlans?.tag) {
    const rawTags = Array.isArray(root.vlans.tag) ? root.vlans.tag : [root.vlans.tag];
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
      const pType = String(a.type).toLowerCase();
      if (pType.includes('net')) aliasType = 'network';
      else if (pType.includes('port')) aliasType = 'port';
      else if (pType.includes('mac')) aliasType = 'mac';
      else if (pType.includes('url')) aliasType = 'urltable';

      aliases.push({
        name: a.name.replace(/[^a-zA-Z0-9_]/g, '_'),
        type: aliasType,
        entries: rawEntries,
        description: a.descr || '',
        enabled: a.enabled !== '0',
      });
    }
  }

  // 4. Firewall Filter Rules
  const rules: FirewallRule[] = [];
  if (root.filter?.rule) {
    const rawRules = Array.isArray(root.filter.rule) ? root.filter.rule : [root.filter.rule];
    let sortOrder = 10;
    for (const r of rawRules) {
      const action = r.type === 'block' ? 'block' : r.type === 'reject' ? 'reject' : 'pass';
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

      // Source parsing
      let src = 'any';
      let srcPort = '';
      let negatedSrc = false;
      if (r.source) {
        if (r.source.any !== undefined) {
          src = 'any';
        } else if (r.source.network) {
          src = `$${r.source.network}`;
        } else if (r.source.address) {
          src = String(r.source.address);
        }
        if (r.source.not !== undefined && src !== 'any') {
          negatedSrc = true;
        }
        if (r.source.port) {
          srcPort = String(r.source.port);
        }
      }

      // Destination parsing
      let dst = 'any';
      let dstPort = '';
      let negatedDst = false;
      if (r.destination) {
        if (r.destination.any !== undefined) {
          dst = 'any';
        } else if (r.destination.network) {
          dst = `$${r.destination.network}`;
        } else if (r.destination.address) {
          dst = String(r.destination.address);
        }
        if (r.destination.not !== undefined && dst !== 'any') {
          negatedDst = true;
        }
        if (r.destination.port) {
          dstPort = String(r.destination.port);
        }
      }

      const hasNegation = negatedSrc || negatedDst;
      const ruleIndex = rules.length;
      const baseDescr = r.descr ? String(r.descr) : '';
      const finalDescr = hasNegation
        ? `[REVIEW: Negated match] ${baseDescr}`.trim()
        : baseDescr;
      const isEnabled = hasNegation
        ? false
        : r.disabled !== '1' && r.disabled !== 'yes';

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
        log: Boolean(r.log),
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
  if (root.nat?.rule) {
    const rawNat = Array.isArray(root.nat.rule) ? root.nat.rule : [root.nat.rule];
    for (const n of rawNat) {
      const iface = (n.interface || 'wan').toLowerCase();
      const localPort = n['local-port'] || n.local_port || n.destination?.port || '';
      nat.push({
        type: 'dnat',
        interface: iface,
        protocol: (n.protocol as any) || 'tcp',
        source: 'any',
        sourcePort: '',
        destination: 'wan_ip',
        destinationPort: String(n.destination?.port || localPort || ''),
        targetIp: n.target || '',
        targetPort: String(localPort || ''),
        log: Boolean(n.log),
        enabled: n.disabled !== '1' && n.disabled !== 'yes',
        description: n.descr || '',
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
      let src = 'any';
      if (o.source?.network) src = o.source.network;
      else if (o.source?.address) src = o.source.address;

      nat.push({
        type: o.target ? 'snat' : 'masquerade',
        interface: iface,
        protocol: 'any',
        source: src,
        sourcePort: '',
        destination: 'any',
        destinationPort: '',
        targetIp: o.target || undefined,
        log: Boolean(o.log),
        enabled: o.disabled !== '1' && o.disabled !== 'yes',
        description: o.descr || 'Outbound NAT',
        sortOrder: natSort,
      });
      natSort += 10;
    }
  }

  // 6. DHCP Server
  const subnets: DhcpSubnet[] = [];
  if (root.dhcpd) {
    for (const [ifKey, dData] of Object.entries<any>(root.dhcpd)) {
      if (typeof dData !== 'object' || !dData || dData.enable === undefined) continue;
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
      if (g.name && g.gateway) {
        gateways.push({
          name: g.name,
          interface: (g.interface || 'wan').toLowerCase(),
          gatewayIp: g.gateway,
          monitorIp: g.monitor || undefined,
          weight: g.weight ? Number.parseInt(String(g.weight), 10) : 1,
          isDefault: Boolean(g.defaultgw),
          enabled: !g.disabled,
          description: g.descr || '',
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
