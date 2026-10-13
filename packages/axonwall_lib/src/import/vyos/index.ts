import type {
  DesiredState,
  Interface,
  Vlan,
  Alias,
  FirewallRule,
  NatRule,
  DhcpSubnet,
  StaticRoute,
} from '../../schemas/index.js';
import type { ImportReport } from '../types.js';

export function tokenizeVyos(input: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  const len = input.length;

  while (i < len) {
    const ch = input[i];

    if (ch === ' ' || ch === '\t' || ch === '\r') {
      i++;
      continue;
    }

    // Comments (# or // or /* ... */)
    if (ch === '#' || (ch === '/' && input[i + 1] === '/')) {
      while (i < len && input[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && input[i + 1] === '*') {
      i += 2;
      while (i < len - 1 && !(input[i] === '*' && input[i + 1] === '/')) i++;
      i += 2;
      continue;
    }

    if (ch === '\n' || ch === ';') {
      tokens.push(';');
      i++;
      continue;
    }

    if (ch === '{' || ch === '}') {
      tokens.push(ch);
      i++;
      continue;
    }

    if (ch === '"' || ch === "'") {
      const quote = ch;
      i++;
      let str = '';
      while (i < len && input[i] !== quote) {
        if (input[i] === '\\' && i + 1 < len) {
          str += input[i + 1];
          i += 2;
        } else {
          str += input[i];
          i++;
        }
      }
      i++;
      tokens.push(str);
      continue;
    }

    let word = '';
    while (i < len && !/[\s;{}#"']/.test(input[i])) {
      word += input[i];
      i++;
    }
    if (word) {
      tokens.push(word);
    }
  }

  return tokens;
}

export function parseVyosTokens(tokens: string[], index = 0): [any, number] {
  const result: any = {};
  const words: string[] = [];

  while (index < tokens.length) {
    const t = tokens[index];

    if (t === '}') {
      return [result, index + 1];
    }

    if (t === ';') {
      if (words.length > 0) {
        const key = words[0];
        const val = words.length === 2 ? words[1] : words.slice(1).join(' ');
        if (result[key] === undefined) {
          result[key] = val;
        } else if (Array.isArray(result[key])) {
          result[key].push(val);
        } else {
          result[key] = [result[key], val];
        }
        words.length = 0;
      }
      index++;
      continue;
    }

    if (t === '{') {
      index++;
      const [child, nextIndex] = parseVyosTokens(tokens, index);
      index = nextIndex;

      if (words.length === 1) {
        const key = words[0];
        if (!result[key]) {
          result[key] = child;
        } else if (Array.isArray(result[key])) {
          result[key].push(child);
        } else {
          result[key] = [result[key], child];
        }
      } else if (words.length === 2) {
        const group = words[0];
        const key = words[1];
        if (!result[group]) result[group] = {};
        result[group][key] = child;
      } else if (words.length > 2) {
        let cur = result;
        for (let w = 0; w < words.length - 1; w++) {
          if (!cur[words[w]]) cur[words[w]] = {};
          cur = cur[words[w]];
        }
        cur[words[words.length - 1]] = child;
      }
      words.length = 0;
      continue;
    }

    words.push(t);
    index++;
  }

  if (words.length > 0) {
    const key = words[0];
    const val = words.length === 2 ? words[1] : words.slice(1).join(' ');
    result[key] = val;
  }

  return [result, index];
}

export function importVyosConfig(configText: string): ImportReport {
  const warnings: string[] = [];
  let root: any;

  // Check if JSON
  const trimmed = configText.trim();
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      root = JSON.parse(configText);
    } catch {
      // fallback to tokenizing
    }
  }

  if (!root) {
    try {
      const tokens = tokenizeVyos(configText);
      const [parsed] = parseVyosTokens(tokens, 0);
      root = parsed;
    } catch (err: any) {
      throw new Error(`Failed to parse VyOS / EdgeOS configuration: ${err.message}`);
    }
  }

  if (!root || typeof root !== 'object') {
    throw new Error('Failed to parse VyOS configuration: Empty or invalid structure.');
  }

  // System
  const system = root.system || {};
  const hostname = system['host-name'] || system.hostname || 'axonwall';
  const domain = system['domain-name'] || system.domain || 'local';
  const timezone = system['time-zone'] || system.timezone || 'UTC';
  const dnsServers: string[] = [];
  if (system['name-server']) {
    const ns = Array.isArray(system['name-server']) ? system['name-server'] : [system['name-server']];
    for (const s of ns) {
      if (typeof s === 'string' && s.trim()) dnsServers.push(s.trim());
    }
  }

  // 1. Interfaces & VLANs
  const interfaces: Interface[] = [];
  const vlans: Vlan[] = [];
  const rawEthernet = root.interfaces?.ethernet || {};
  for (const [devName, devData] of Object.entries<any>(rawEthernet)) {
    if (typeof devData !== 'object' || !devData) continue;
    const descr = devData.description || devName.toUpperCase();
    let ip4 = '';
    let isDhcp = false;

    if (devData.address) {
      const addrs = Array.isArray(devData.address) ? devData.address : [devData.address];
      for (const a of addrs) {
        if (typeof a === 'string') {
          if (a.toLowerCase() === 'dhcp') isDhcp = true;
          else if (a.includes('.') && a.includes('/') && !ip4) ip4 = a;
        }
      }
    }

    const ifName = devName.toLowerCase().includes('eth0')
      ? 'wan'
      : devName.toLowerCase().includes('eth1')
      ? 'lan'
      : devName.toLowerCase();

    interfaces.push({
      name: ifName,
      device: devName,
      type: isDhcp ? 'dhcp' : 'static',
      enabled: devData.disable === undefined,
      description: descr,
      ipv4Address: ip4 || undefined,
      mtu: devData.mtu ? Number.parseInt(String(devData.mtu), 10) : 1500,
    });

    // Check for VIF (VLAN interfaces)
    if (devData.vif) {
      for (const [tagStr, vifData] of Object.entries<any>(devData.vif)) {
        const tag = Number.parseInt(tagStr, 10);
        if (!Number.isNaN(tag)) {
          vlans.push({
            tag,
            parentInterface: devName,
            vlanInterface: `${devName}.${tag}`,
            priority: 0,
            description: vifData.description || `VLAN ${tag}`,
          });
        }
      }
    }
  }

  // 2. Aliases (from firewall groups)
  const aliases: Alias[] = [];
  const fwGroups = root.firewall?.group || {};
  for (const [groupType, groups] of Object.entries<any>(fwGroups)) {
    if (typeof groups !== 'object' || !groups) continue;
    for (const [grpName, grpData] of Object.entries<any>(groups)) {
      if (typeof grpData !== 'object' || !grpData) continue;
      const entries: string[] = [];
      const addrs = grpData.address || grpData.network || grpData.port;
      if (addrs) {
        const rawList = Array.isArray(addrs) ? addrs : [addrs];
        for (const item of rawList) {
          if (typeof item === 'string') entries.push(...item.split(/[\s,]+/).filter(Boolean));
        }
      }

      let aType: 'host' | 'network' | 'port' = 'host';
      if (groupType.includes('network')) aType = 'network';
      else if (groupType.includes('port')) aType = 'port';

      aliases.push({
        name: grpName.replace(/[^a-zA-Z0-9_]/g, '_'),
        type: aType,
        entries,
        description: grpData.description || '',
        enabled: true,
      });
    }
  }

  // 3. Firewall Filter Rules
  const rules: FirewallRule[] = [];
  let sortOrder = 10;
  const fwChains = root.firewall?.name || root.firewall?.ipv4?.name || {};
  for (const [chainName, chainData] of Object.entries<any>(fwChains)) {
    if (typeof chainData !== 'object' || !chainData) continue;
    const rawRules = chainData.rule || {};

    let targetIface = 'any';
    const lowerChain = chainName.toLowerCase();
    if (lowerChain.includes('wan')) targetIface = 'wan';
    else if (lowerChain.includes('lan')) targetIface = 'lan';

    for (const [ruleId, r] of Object.entries<any>(rawRules)) {
      if (typeof r !== 'object' || !r) continue;
      const action = r.action === 'accept' ? 'pass' : r.action === 'reject' ? 'reject' : 'block';

      let proto: 'any' | 'tcp' | 'udp' | 'tcp_udp' | 'icmp' = 'any';
      const p = String(r.protocol || 'any').toLowerCase();
      if (p === 'tcp_udp' || p === 'tcp/udp') proto = 'tcp_udp';
      else if (p === 'tcp') proto = 'tcp';
      else if (p === 'udp') proto = 'udp';
      else if (p.includes('icmp')) proto = 'icmp';

      let src = 'any';
      let srcPort = '';
      if (r.source) {
        if (r.source.address) src = String(r.source.address);
        else if (r.source.group?.['address-group']) src = `$${r.source.group['address-group']}`;
        else if (r.source.group?.['network-group']) src = `$${r.source.group['network-group']}`;
        if (r.source.port) srcPort = String(r.source.port);
      }

      let dst = 'any';
      let dstPort = '';
      if (r.destination) {
        if (r.destination.address) dst = String(r.destination.address);
        else if (r.destination.group?.['address-group']) dst = `$${r.destination.group['address-group']}`;
        else if (r.destination.group?.['network-group']) dst = `$${r.destination.group['network-group']}`;
        if (r.destination.port) dstPort = String(r.destination.port);
      }

      rules.push({
        action,
        direction: 'in',
        interface: targetIface,
        quick: true,
        protocol: proto,
        source: src,
        sourcePort: srcPort,
        destination: dst,
        destinationPort: dstPort,
        log: r.log === 'enable',
        enabled: r.disable === undefined,
        description: r.description || `Rule ${ruleId} (${chainName})`,
        sortOrder,
      });
      sortOrder += 10;
    }
  }

  // 4. NAT Rules
  const nat: NatRule[] = [];
  let natSort = 10;

  // Destination NAT (Port forwarding)
  const dnatRules = root.nat?.destination?.rule || {};
  for (const [rId, d] of Object.entries<any>(dnatRules)) {
    if (typeof d !== 'object' || !d) continue;
    const iface = d['inbound-interface'] || 'wan';
    nat.push({
      type: 'dnat',
      interface: iface.toLowerCase(),
      protocol: (d.protocol as any) || 'tcp',
      source: 'any',
      sourcePort: '',
      destination: 'wan_ip',
      destinationPort: String(d.destination?.port || ''),
      targetIp: d.translation?.address || '',
      targetPort: String(d.translation?.port || ''),
      log: d.log === 'enable',
      enabled: d.disable === undefined,
      description: d.description || `DNAT Rule ${rId}`,
      sortOrder: natSort,
    });
    natSort += 10;
  }

  // Source NAT (Masquerade)
  const snatRules = root.nat?.source?.rule || {};
  for (const [rId, s] of Object.entries<any>(snatRules)) {
    if (typeof s !== 'object' || !s) continue;
    const iface = s['outbound-interface'] || 'wan';
    const isMasq = s.translation?.address === 'masquerade';
    nat.push({
      type: isMasq ? 'masquerade' : 'snat',
      interface: iface.toLowerCase(),
      protocol: 'any',
      source: s.source?.address || 'any',
      sourcePort: '',
      destination: 'any',
      destinationPort: '',
      targetIp: !isMasq ? s.translation?.address : undefined,
      log: s.log === 'enable',
      enabled: s.disable === undefined,
      description: s.description || `SNAT Rule ${rId}`,
      sortOrder: natSort,
    });
    natSort += 10;
  }

  // 5. DHCP Server
  const subnets: DhcpSubnet[] = [];
  const dhcpServer = root.service?.['dhcp-server']?.['shared-network-name'] || {};
  for (const [netName, netData] of Object.entries<any>(dhcpServer)) {
    if (typeof netData !== 'object' || !netData) continue;
    const rawSubnets = netData.subnet || {};
    for (const [subnetCidr, subData] of Object.entries<any>(rawSubnets)) {
      if (typeof subData !== 'object' || !subData) continue;
      const staticMappings = [];
      if (subData['static-mapping']) {
        for (const [mapName, mapData] of Object.entries<any>(subData['static-mapping'])) {
          if (mapData['ip-address'] && mapData['mac-address']) {
            staticMappings.push({
              mac: mapData['mac-address'],
              ip: mapData['ip-address'],
              hostname: mapName,
              description: `Static lease for ${mapName}`,
            });
          }
        }
      }

      let poolStart = '192.168.1.100';
      let poolEnd = '192.168.1.200';
      if (subData.range) {
        const firstRange = Object.values<any>(subData.range)[0];
        if (firstRange?.start && firstRange?.stop) {
          poolStart = firstRange.start;
          poolEnd = firstRange.stop;
        }
      }

      subnets.push({
        interface: 'lan',
        subnet: subnetCidr,
        poolStart,
        poolEnd,
        routers: subData['default-router'] ? [subData['default-router']] : [],
        dnsServers: subData['dns-server'] ? (Array.isArray(subData['dns-server']) ? subData['dns-server'] : [subData['dns-server']]) : [],
        staticMappings,
        enabled: true,
      });
    }
  }

  // 6. Static Routes
  const routes: StaticRoute[] = [];
  const staticProtocols = root.protocols?.static?.route || {};
  for (const [destCidr, rData] of Object.entries<any>(staticProtocols)) {
    if (typeof rData !== 'object' || !rData) continue;
    const nextHop = rData['next-hop'] ? Object.keys(rData['next-hop'])[0] : undefined;
    if (nextHop) {
      routes.push({
        network: destCidr,
        gateway: nextHop,
        description: `Static route to ${destCidr}`,
        enabled: true,
      });
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
      hostOverrides: [],
    },
    routes,
  };

  return {
    success: true,
    vendor: 'vyos',
    version: 'VyOS / EdgeOS',
    sourceFormat: 'VyOS / EdgeOS (config.boot)',
    interfacesCount: interfaces.length,
    vlansCount: vlans.length,
    aliasesCount: aliases.length,
    rulesCount: rules.length,
    natRulesCount: nat.length,
    dhcpSubnetsCount: subnets.length,
    dnsOverridesCount: 0,
    routesCount: routes.length,
    warnings,
    state,
  };
}
