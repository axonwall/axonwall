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
} from '../../schemas/index.js';
import type { ImportReport, ImportReviewItem } from '../types.js';

function parseLineKeyValue(line: string): Record<string, string> {
  const result: Record<string, string> = {};
  const regex = /(\S+?)=(?:"([^"]*)"|(\S+))/g;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(line)) !== null) {
    const key = match[1];
    const val = match[2] !== undefined ? match[2] : match[3];
    result[key] = val;
  }

  // Check standalone flags like disabled=yes or action=...
  if (line.includes('disabled=yes')) result.disabled = 'yes';
  return result;
}

export function importMikrotikConfig(rscContent: string): ImportReport {
  const warnings: string[] = [];
  const reviewItems: ImportReviewItem[] = [];
  const lines = rscContent.split('\n');

  let currentSection = '';
  let hostname = 'axonwall';
  const domain = 'local';
  const dnsServers: string[] = [];

  const rawInterfaces: Record<string, { device: string; address?: string; comment?: string }> = {};
  const vlans: Vlan[] = [];
  const addressLists: Record<string, string[]> = {};
  const rules: FirewallRule[] = [];
  const nat: NatRule[] = [];
  const routes: StaticRoute[] = [];
  const dnsOverrides: DnsHostOverride[] = [];

  // DHCP building blocks
  const pools: Record<string, { start: string; end: string }> = {};
  const dhcpNetworks: Record<string, { gateway?: string; dns?: string[] }> = {};
  const dhcpLeases: Record<string, Array<{ mac: string; ip: string; comment?: string }>> = {};

  let sortOrder = 10;
  let natSort = 10;

  for (let rawLine of lines) {
    let line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      if (line.includes('RouterOS')) {
        const vMatch = line.match(/RouterOS\s+([0-9.]+)/i);
        if (vMatch) warnings.push(`Detected RouterOS v${vMatch[1]}`);
      }
      continue;
    }

    if (line.startsWith('/')) {
      const parts = line.split(/\s+/);
      const verbIdx = parts.findIndex((p) => p === 'add' || p === 'set');
      if (verbIdx !== -1) {
        currentSection = parts.slice(0, verbIdx).join(' ');
        line = parts.slice(verbIdx).join(' ').trim();
      } else {
        currentSection = line;
        continue;
      }
    }

    const kv = parseLineKeyValue(line);

    // 1. Interfaces & Addresses
    if (currentSection.startsWith('/interface vlan')) {
      if (kv['vlan-id']) {
        const tag = Number.parseInt(kv['vlan-id'], 10);
        if (!Number.isNaN(tag)) {
          const parentIf = kv.interface || 'ether2';
          const vlanIf = kv.name || `${parentIf}.${tag}`;
          vlans.push({
            tag,
            parentInterface: parentIf,
            vlanInterface: vlanIf,
            priority: 0,
            description: kv.name || kv.comment || `VLAN ${tag}`,
          });
        }
      }
    } else if (currentSection.startsWith('/ip address')) {
      if (kv.address && kv.interface) {
        rawInterfaces[kv.interface] = {
          device: kv.interface,
          address: kv.address,
          comment: kv.comment,
        };
      }
    } else if (currentSection.startsWith('/system identity')) {
      if (kv.name) hostname = kv.name;
    }

    // 2. Address Lists (Aliases)
    else if (currentSection.startsWith('/ip firewall address-list')) {
      if (kv.list && kv.address) {
        if (!addressLists[kv.list]) addressLists[kv.list] = [];
        addressLists[kv.list].push(kv.address);
      }
    }

    // 3. Firewall Filter Rules
    else if (currentSection.startsWith('/ip firewall filter')) {
      const action = kv.action === 'accept' ? 'pass' : kv.action === 'reject' ? 'reject' : 'block';
      let proto: 'any' | 'tcp' | 'udp' | 'tcp_udp' | 'icmp' = 'any';
      if (kv.protocol === 'tcp') proto = 'tcp';
      else if (kv.protocol === 'udp') proto = 'udp';
      else if (kv.protocol === 'icmp') proto = 'icmp';

      let iface = 'any';
      if (kv['in-interface']) {
        const inIface = kv['in-interface'].toLowerCase();
        if (inIface.includes('wan') || inIface.includes('ether1')) iface = 'wan';
        else if (inIface.includes('lan') || inIface.includes('ether2') || inIface.includes('bridge')) iface = 'lan';
        else iface = inIface;
      }

      let rawSrc = kv['src-address'] || (kv['src-address-list'] ? (kv['src-address-list'].startsWith('!') ? `!$${kv['src-address-list'].slice(1)}` : `$${kv['src-address-list']}`) : 'any');
      let negatedSrc = false;
      if (rawSrc.startsWith('!')) {
        negatedSrc = true;
        rawSrc = rawSrc.slice(1) || 'any';
      }

      let rawDst = kv['dst-address'] || (kv['dst-address-list'] ? (kv['dst-address-list'].startsWith('!') ? `!$${kv['dst-address-list'].slice(1)}` : `$${kv['dst-address-list']}`) : 'any');
      let negatedDst = false;
      if (rawDst.startsWith('!')) {
        negatedDst = true;
        rawDst = rawDst.slice(1) || 'any';
      }

      const hasNegation = (negatedSrc && rawSrc !== 'any') || (negatedDst && rawDst !== 'any');
      const ruleIndex = rules.length;
      const baseDesc = kv.comment || `RouterOS Rule (${kv.chain || 'filter'})`;
      const finalDesc = hasNegation ? `[REVIEW: Negated match] ${baseDesc}` : baseDesc;
      const isEnabled = hasNegation ? false : kv.disabled !== 'yes';

      if (hasNegation) {
        const reason: ImportReviewItem['reason'] =
          negatedSrc && negatedDst
            ? 'negated_both'
            : negatedSrc
              ? 'negated_source'
              : 'negated_destination';
        const matchSummary = `${action.toUpperCase()} ${proto} from ${negatedSrc ? `!${rawSrc}` : rawSrc} to ${negatedDst ? `!${rawDst}` : rawDst}`;
        const explanation = `RouterOS rule "${baseDesc}" uses an inverted (!) ${reason === 'negated_both' ? 'source and destination' : reason === 'negated_source' ? 'source' : 'destination'} match (${matchSummary}). Imported with enabled: false so it cannot silently activate with inverted semantics.`;
        const suggestedResolution = `Split into an explicit preceding rule matching ${negatedSrc ? rawSrc : rawDst} with the opposite action, followed by a broader rule matching 'any', then enable the reviewed rules.`;
        warnings.push(explanation + ' ' + suggestedResolution);
        reviewItems.push({
          ruleId: `rule-${ruleIndex + 1}`,
          ruleIndex,
          reason,
          originalMatchSummary: matchSummary,
          explanation,
          suggestedResolution,
        });
      }

      rules.push({
        action,
        direction: 'in',
        interface: iface,
        quick: true,
        protocol: proto,
        source: rawSrc,
        sourcePort: kv['src-port'] || '',
        destination: rawDst,
        destinationPort: kv['dst-port'] || '',
        log: kv.log === 'yes',
        enabled: isEnabled,
        description: finalDesc,
        sortOrder,
      });
      sortOrder += 10;
    }

    // 4. NAT Rules
    else if (currentSection.startsWith('/ip firewall nat')) {
      if (kv.action === 'masquerade' || kv.action === 'src-nat') {
        const outIface = (kv['out-interface'] || 'wan').toLowerCase();
        nat.push({
          type: kv.action === 'masquerade' ? 'masquerade' : 'snat',
          interface: outIface.includes('ether1') ? 'wan' : outIface,
          protocol: 'any',
          source: kv['src-address'] || 'any',
          sourcePort: '',
          destination: 'any',
          destinationPort: '',
          targetIp: kv['to-addresses'] || undefined,
          log: kv.log === 'yes',
          enabled: kv.disabled !== 'yes',
          description: kv.comment || 'RouterOS Masquerade',
          sortOrder: natSort,
        });
        natSort += 10;
      } else if (kv.action === 'dst-nat') {
        const inIface = (kv['in-interface'] || 'wan').toLowerCase();
        nat.push({
          type: 'dnat',
          interface: inIface.includes('ether1') ? 'wan' : inIface,
          protocol: (kv.protocol as any) || 'tcp',
          source: 'any',
          sourcePort: '',
          destination: 'wan_ip',
          destinationPort: kv['dst-port'] || '',
          targetIp: kv['to-addresses'] || '',
          targetPort: kv['to-ports'] || kv['dst-port'] || '',
          log: kv.log === 'yes',
          enabled: kv.disabled !== 'yes',
          description: kv.comment || 'RouterOS Port Forward',
          sortOrder: natSort,
        });
        natSort += 10;
      }
    }

    // 5. DHCP Pool & Leases
    else if (currentSection.startsWith('/ip pool')) {
      if (kv.name && kv.ranges) {
        const parts = kv.ranges.split('-');
        pools[kv.name] = {
          start: parts[0] || '192.168.1.100',
          end: parts[1] || parts[0] || '192.168.1.200',
        };
      }
    } else if (currentSection.startsWith('/ip dhcp-server network')) {
      if (kv.address) {
        const dns = kv['dns-server'] ? kv['dns-server'].split(/[\s,]+/).filter(Boolean) : [];
        dhcpNetworks[kv.address] = {
          gateway: kv.gateway,
          dns,
        };
      }
    } else if (currentSection.startsWith('/ip dhcp-server lease')) {
      if (kv.address && kv['mac-address']) {
        const key = kv.server || 'default';
        if (!dhcpLeases[key]) dhcpLeases[key] = [];
        dhcpLeases[key].push({
          mac: kv['mac-address'],
          ip: kv.address,
          comment: kv.comment,
        });
      }
    }

    // 6. DNS
    else if (currentSection.startsWith('/ip dns static')) {
      if (kv.name && kv.address) {
        const nameParts = kv.name.split('.');
        dnsOverrides.push({
          hostname: nameParts[0] || 'host',
          domain: nameParts.slice(1).join('.') || domain,
          ip: kv.address,
          description: kv.comment || '',
        });
      }
    } else if (currentSection.startsWith('/ip dns')) {
      if (kv.servers) {
        dnsServers.push(...kv.servers.split(/[\s,]+/).filter(Boolean));
      }
    }

    // 7. Routes
    else if (currentSection.startsWith('/ip route')) {
      if (kv['dst-address'] && kv.gateway) {
        routes.push({
          network: kv['dst-address'],
          gateway: kv.gateway,
          description: kv.comment || `Route to ${kv['dst-address']}`,
          enabled: true,
        });
      }
    }
  }

  // Convert rawInterfaces to Axonwall Interface list
  const interfaces: Interface[] = [];
  if (Object.keys(rawInterfaces).length === 0) {
    // Default fallback if none detected
    interfaces.push(
      { name: 'wan', device: 'ether1', type: 'dhcp', enabled: true, description: 'WAN', mtu: 1500 },
      { name: 'lan', device: 'ether2', type: 'static', enabled: true, ipv4Address: '192.168.88.1/24', description: 'LAN', mtu: 1500 }
    );
  } else {
    for (const [dev, data] of Object.entries(rawInterfaces)) {
      const lower = dev.toLowerCase();
      let name = lower;
      if (lower.includes('ether1') || lower.includes('wan')) name = 'wan';
      else if (lower.includes('ether2') || lower.includes('lan') || lower.includes('bridge')) name = 'lan';

      interfaces.push({
        name,
        device: dev,
        type: data.address ? 'static' : 'dhcp',
        enabled: true,
        ipv4Address: data.address,
        description: data.comment || dev.toUpperCase(),
        mtu: 1500,
      });
    }
  }

  // Convert addressLists to Aliases
  const aliases: Alias[] = [];
  for (const [listName, entries] of Object.entries(addressLists)) {
    const isNetwork = entries.some((e) => e.includes('/'));
    aliases.push({
      name: listName.replace(/[^a-zA-Z0-9_]/g, '_'),
      type: isNetwork ? 'network' : 'host',
      entries,
      description: `RouterOS Address List ${listName}`,
      enabled: true,
    });
  }

  // Assemble DHCP Subnets
  const subnets: DhcpSubnet[] = [];
  const primaryPool = Object.values(pools)[0] || { start: '192.168.88.100', end: '192.168.88.200' };
  const allStaticLeases = Object.values(dhcpLeases).flat().map((l) => ({
    mac: l.mac,
    ip: l.ip,
    hostname: l.comment ? l.comment.toLowerCase().replace(/[^a-z0-9-]/g, '') : '',
    description: l.comment || '',
  }));

  const netEntries = Object.entries(dhcpNetworks);
  if (netEntries.length > 0) {
    for (const [netCidr, netInfo] of netEntries) {
      subnets.push({
        interface: 'lan',
        subnet: netCidr,
        poolStart: primaryPool.start,
        poolEnd: primaryPool.end,
        routers: netInfo.gateway ? [netInfo.gateway] : ['192.168.88.1'],
        dnsServers: netInfo.dns && netInfo.dns.length > 0 ? netInfo.dns : ['192.168.88.1'],
        staticMappings: allStaticLeases,
        enabled: true,
      });
    }
  } else if (allStaticLeases.length > 0 || Object.keys(pools).length > 0) {
    subnets.push({
      interface: 'lan',
      subnet: '192.168.88.0/24',
      poolStart: primaryPool.start,
      poolEnd: primaryPool.end,
      routers: ['192.168.88.1'],
      dnsServers: ['192.168.88.1'],
      staticMappings: allStaticLeases,
      enabled: true,
    });
  }

  const state: DesiredState = {
    version: 1,
    system: {
      hostname,
      domain,
      dnsServers: dnsServers.length > 0 ? dnsServers : ['1.1.1.1'],
      timezone: 'UTC',
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
    gateways: [],
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
      hostOverrides: dnsOverrides,
    },
    routes,
  };

  return {
    success: true,
    vendor: 'mikrotik',
    version: 'RouterOS',
    sourceFormat: 'MikroTik RouterOS (/export .rsc)',
    interfacesCount: interfaces.length,
    vlansCount: vlans.length,
    aliasesCount: aliases.length,
    rulesCount: rules.length,
    natRulesCount: nat.length,
    dhcpSubnetsCount: subnets.length,
    dnsOverridesCount: dnsOverrides.length,
    routesCount: routes.length,
    warnings,
    reviewItems,
    state,
  };
}
