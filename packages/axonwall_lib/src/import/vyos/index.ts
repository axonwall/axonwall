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
import type { ImportReport, ImportReviewItem } from '../types.js';

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

const FORBIDDEN_VYOS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_VYOS_DEPTH = 64;

function assertSafeVyosKey(key: string): string {
  if (FORBIDDEN_VYOS_KEYS.has(key)) {
    throw new Error(`Forbidden VyOS configuration key: ${key}`);
  }
  return key;
}

function flushVyosWords(result: any, words: string[]): void {
  if (words.length === 0) return;
  const key = assertSafeVyosKey(words[0]);
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

export function parseVyosTokens(tokens: string[], index = 0, depth = 0): [any, number] {
  if (depth > MAX_VYOS_DEPTH) {
    throw new Error(`VyOS configuration exceeds maximum nesting depth of ${MAX_VYOS_DEPTH}`);
  }
  const result: any = Object.create(null);
  const words: string[] = [];

  while (index < tokens.length) {
    const t = tokens[index];

    if (t === '}') {
      // Flush trailing statement inside single-line blocks such as `source { address !10.0.0.0/8 }`.
      flushVyosWords(result, words);
      return [result, index + 1];
    }

    if (t === ';') {
      flushVyosWords(result, words);
      index++;
      continue;
    }

    if (t === '{') {
      index++;
      const [child, nextIndex] = parseVyosTokens(tokens, index, depth + 1);
      index = nextIndex;

      if (words.length === 1) {
        const key = assertSafeVyosKey(words[0]);
        if (!result[key]) {
          result[key] = child;
        } else if (Array.isArray(result[key])) {
          result[key].push(child);
        } else {
          result[key] = [result[key], child];
        }
      } else if (words.length === 2) {
        const group = assertSafeVyosKey(words[0]);
        const key = assertSafeVyosKey(words[1]);
        if (!result[group]) result[group] = Object.create(null);
        result[group][key] = child;
      } else if (words.length > 2) {
        let cur = result;
        for (let w = 0; w < words.length - 1; w++) {
          const seg = assertSafeVyosKey(words[w]);
          if (!cur[seg]) cur[seg] = Object.create(null);
          cur = cur[seg];
        }
        cur[assertSafeVyosKey(words[words.length - 1])] = child;
      }
      words.length = 0;
      continue;
    }

    words.push(t);
    index++;
  }

  flushVyosWords(result, words);

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
  const reviewItems: ImportReviewItem[] = [];
  const parseVyosNegation = (raw: unknown): { value: string; negated: boolean } => {
    const trimmed = String(raw ?? '').trim();
    if (trimmed.startsWith('!')) {
      return { value: trimmed.slice(1).trim(), negated: true };
    }
    return { value: trimmed, negated: false };
  };

  const parseVyosEndpoint = (
    node: any,
    defaultAddr: string,
  ): { addr: string; port: string; negatedAddr: boolean; negatedPort: boolean } => {
    let addr = defaultAddr;
    let port = '';
    let negatedAddr = false;
    let negatedPort = false;
    if (!node || typeof node !== 'object') {
      return { addr, port, negatedAddr, negatedPort };
    }
    if (node.address) {
      const parsed = parseVyosNegation(node.address);
      addr = parsed.value || defaultAddr;
      negatedAddr = parsed.negated && addr !== 'any' && addr !== 'wan_ip';
    } else if (node.group?.['address-group']) {
      const parsed = parseVyosNegation(node.group['address-group']);
      addr = parsed.value ? `$${parsed.value.replace(/[^a-zA-Z0-9_]/g, '_')}` : defaultAddr;
      negatedAddr = parsed.negated && addr !== 'any' && addr !== 'wan_ip';
    } else if (node.group?.['network-group']) {
      const parsed = parseVyosNegation(node.group['network-group']);
      addr = parsed.value ? `$${parsed.value.replace(/[^a-zA-Z0-9_]/g, '_')}` : defaultAddr;
      negatedAddr = parsed.negated && addr !== 'any' && addr !== 'wan_ip';
    }
    if (node.port) {
      const parsed = parseVyosNegation(node.port);
      port = parsed.value.replace(/:/g, '-');
      if (parsed.negated) negatedPort = true;
    } else if (node.group?.['port-group']) {
      const parsed = parseVyosNegation(node.group['port-group']);
      port = parsed.value ? `$${parsed.value.replace(/[^a-zA-Z0-9_]/g, '_')}` : '';
      if (parsed.negated) negatedPort = true;
    }
    return { addr, port, negatedAddr, negatedPort };
  };

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

      const parsedSrc = parseVyosEndpoint(r.source, 'any');
      const parsedDst = parseVyosEndpoint(r.destination, 'any');
      const src = parsedSrc.addr;
      const srcPort = parsedSrc.port;
      const negatedSrc = parsedSrc.negatedAddr;
      const dst = parsedDst.addr;
      const dstPort = parsedDst.port;
      const negatedDst = parsedDst.negatedAddr;
      const negatedPort = parsedSrc.negatedPort || parsedDst.negatedPort;

      const hasNegation = negatedSrc || negatedDst || negatedPort;
      const ruleIndex = rules.length;
      const baseDesc = r.description || `Rule ${ruleId} (${chainName})`;
      const finalDesc = hasNegation ? `[REVIEW: Negated match] ${baseDesc}` : baseDesc;
      const isEnabled = hasNegation ? false : r.disable === undefined;

      if (hasNegation) {
        const reason: ImportReviewItem['reason'] =
          negatedSrc && negatedDst
            ? 'negated_both'
            : negatedSrc
              ? 'negated_source'
              : negatedDst
                ? 'negated_destination'
                : 'manual_review';
        const matchSummary = `${action.toUpperCase()} ${proto} from ${negatedSrc ? `!${src}` : src} to ${negatedDst ? `!${dst}` : dst}`;
        const explanation = `VyOS rule "${baseDesc}" uses an inverted (!) match (${matchSummary}${negatedPort ? ' / negated port' : ''}). Imported with enabled: false so it cannot silently activate with unintended negated semantics.`;
        const suggestedResolution = `Review the negated source/destination/port rules and split into explicit ordered rules before enabling.`;
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
        interface: targetIface,
        quick: true,
        protocol: proto,
        source: src,
        ...(negatedSrc ? { invertSource: true } : {}),
        sourcePort: srcPort,
        destination: dst,
        ...(negatedDst ? { invertDestination: true } : {}),
        destinationPort: dstPort,
        log: r.log === 'enable',
        enabled: isEnabled,
        description: finalDesc,
        sortOrder,
      });
      sortOrder += 10;
    }
  }

  // 4. NAT Rules
  const nat: NatRule[] = [];
  let natSort = 10;

  // Destination NAT (Port forwarding)
  const extractVyosIface = (raw: unknown): string => {
    if (typeof raw === 'string') return raw.toLowerCase();
    if (raw && typeof raw === 'object') {
      const obj = raw as Record<string, unknown>;
      const candidate = obj.name || obj['interface-name'];
      if (typeof candidate === 'string') return candidate.toLowerCase();
    }
    return 'wan';
  };
  const validNatProtos = new Set(['any', 'tcp', 'udp', 'tcp_udp', 'icmp', 'ipv6-icmp', 'esp', 'ah', 'gre']);
  const normalizeVyosNatProto = (raw: unknown): any => {
    const p = String(raw || 'tcp').toLowerCase();
    if (p === 'all') return 'any';
    if (p === 'tcp_udp' || p === 'tcp/udp') return 'tcp_udp';
    if (p.includes('icmpv6')) return 'ipv6-icmp';
    if (validNatProtos.has(p)) return p;
    return 'tcp';
  };
  const dnatRules = root.nat?.destination?.rule || {};
  for (const [rId, d] of Object.entries<any>(dnatRules)) {
    if (typeof d !== 'object' || !d) continue;
    const iface = extractVyosIface(d['inbound-interface']);
    const dnatSrc = parseVyosEndpoint(d.source, 'any');
    const dnatDst = parseVyosEndpoint(d.destination, 'wan_ip');
    const isExclude = d.exclude !== undefined;
    const hasNatReview =
      dnatSrc.negatedAddr || dnatDst.negatedAddr || dnatSrc.negatedPort || dnatDst.negatedPort || isExclude;
    const baseDesc = d.description || `DNAT Rule ${rId}`;
    if (hasNatReview) {
      warnings.push(
        `VyOS DNAT rule "${baseDesc}" uses ${isExclude ? 'exclude' : 'negated source/destination/port'} which cannot be safely activated as a standard forward; imported with enabled: false.`,
      );
    }

    nat.push({
      type: 'dnat',
      interface: iface,
      protocol: normalizeVyosNatProto(d.protocol),
      source: dnatSrc.addr,
      sourcePort: dnatSrc.port,
      destination: dnatDst.addr,
      destinationPort: dnatDst.port,
      targetIp: d.translation?.address || '',
      targetPort: String(d.translation?.port || '').replace(/:/g, '-'),
      log: d.log === 'enable',
      enabled: hasNatReview ? false : d.disable === undefined,
      description: hasNatReview ? `[REVIEW: ${isExclude ? 'NAT exclude' : 'Negated NAT'}] ${baseDesc}` : baseDesc,
      sortOrder: natSort,
    });
    natSort += 10;
  }

  // Source NAT (Masquerade)
  const snatRules = root.nat?.source?.rule || {};
  for (const [rId, s] of Object.entries<any>(snatRules)) {
    if (typeof s !== 'object' || !s) continue;
    const iface = extractVyosIface(s['outbound-interface']);
    const isMasq = s.translation?.address === 'masquerade';
    const snatSrc = parseVyosEndpoint(s.source, 'any');
    const snatDst = parseVyosEndpoint(s.destination, 'any');
    const isExclude = s.exclude !== undefined;
    const hasNatReview =
      snatSrc.negatedAddr || snatDst.negatedAddr || snatSrc.negatedPort || snatDst.negatedPort || isExclude;
    const baseDesc = s.description || `SNAT Rule ${rId}`;
    if (hasNatReview) {
      warnings.push(
        `VyOS SNAT rule "${baseDesc}" uses ${isExclude ? 'exclude' : 'negated source/destination/port'}; imported with enabled: false.`,
      );
    }

    nat.push({
      type: isMasq ? 'masquerade' : 'snat',
      interface: iface,
      protocol: s.protocol ? normalizeVyosNatProto(s.protocol) : 'any',
      source: snatSrc.addr,
      sourcePort: snatSrc.port,
      destination: snatDst.addr,
      destinationPort: snatDst.port,
      targetIp: !isMasq ? s.translation?.address : undefined,
      ...(s.translation?.port ? { targetPort: String(s.translation.port).replace(/:/g, '-') } : {}),
      log: s.log === 'enable',
      enabled: hasNatReview ? false : s.disable === undefined,
      description: hasNatReview ? `[REVIEW: ${isExclude ? 'NAT exclude' : 'Negated NAT'}] ${baseDesc}` : baseDesc,
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
    reviewItems,
    state,
  };
}
