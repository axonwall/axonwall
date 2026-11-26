import { normalizeAntiLockoutInterfaces, inferInterfaceRole } from '../schemas/index.js';
import type { Alias, DesiredState, FirewallRule, Interface, NatRule, PacketTracerQuery } from '../schemas/index.js';
import { COUNTRY_CIDR_TABLE } from '../compile/geoip/index.js';

export interface TraceStep {
  stage: 'interface' | 'dnat' | 'filter' | 'routing' | 'snat';
  description: string;
  matched: boolean;
  action?: string;
  detail?: string;
}

export interface SimulationResult {
  allowed: boolean;
  verdict: 'ALLOW' | 'DROP' | 'REJECT';
  matchedRule?: {
    id?: string;
    description: string;
    action: string;
    sortOrder: number;
  };
  policyRouting?: {
    gateway?: string;
    gatewayGroup?: string;
  };
  nat?: {
    type: 'dnat' | 'snat' | 'masquerade';
    translatedIp: string;
    translatedPort?: number;
  };
  steps: TraceStep[];
}

/**
 * Simulates a packet traversing the Axonwall firewall pipeline (Enhancement E5).
 * Evaluates interface ingress, DNAT, firewall filter rules, policy routing, and outbound NAT.
 */
export function simulatePacket(query: PacketTracerQuery, state: DesiredState): SimulationResult {
  const steps: TraceStep[] = [];
  let currentDstIp = query.dstIp;
  let currentDstPort = query.dstPort;
  let natResult: SimulationResult['nat'] = undefined;
  let policyRoutingResult: SimulationResult['policyRouting'] = undefined;

  // 1. Ingress Interface Validation
  const inIface = state.interfaces.find((i) => i.name === query.inInterface || i.device === query.inInterface);
  if (!inIface || !inIface.enabled) {
    steps.push({
      stage: 'interface',
      description: `Ingress interface "${query.inInterface}" is not configured or disabled`,
      matched: false,
      action: 'DROP',
    });
    return {
      allowed: false,
      verdict: 'DROP',
      steps,
    };
  }

  steps.push({
    stage: 'interface',
    description: `Packet arrived on interface ${inIface.name} (${inIface.device})`,
    matched: true,
    action: 'CONTINUE',
  });

  const isWanIngress = inferInterfaceRole(inIface) === 'wan';
  const localHostIps = new Set<string>();
  for (const i of state.interfaces) {
    if (!i.enabled) continue;
    if (i.ipv4Address) localHostIps.add(i.ipv4Address.split('/')[0]!.trim().toLowerCase());
    if (i.ipv6Address) localHostIps.add(i.ipv6Address.split('/')[0]!.trim().toLowerCase());
  }
  for (const vip of state.virtualIps ?? []) {
    if (vip.ip) localHostIps.add(vip.ip.split('/')[0]!.trim().toLowerCase());
  }

  // 2. Anti-Lockout check (matches compileNftables: uses configured antiLockout interfaces, never WAN)
  const antiLockoutIfaces = new Set(normalizeAntiLockoutInterfaces(state.system.antiLockout));
  if (!isWanIngress && state.system.antiLockout?.enabled && antiLockoutIfaces.has(inIface.name)) {
    const ifaceLocalIps = [inIface.ipv4Address?.split('/')[0], inIface.ipv6Address?.split('/')[0]]
      .filter((v): v is string => Boolean(v))
      .map((v) => v.trim().toLowerCase());
    if (
      query.protocol === 'tcp' &&
      state.system.antiLockout.ports.includes(query.dstPort) &&
      (ifaceLocalIps.length > 0 ? ifaceLocalIps.includes(currentDstIp.trim().toLowerCase()) : true)
    ) {
      steps.push({
        stage: 'filter',
        description: `Anti-Lockout rule matched on port ${query.dstPort}`,
        matched: true,
        action: 'ACCEPT',
      });
      return {
        allowed: true,
        verdict: 'ALLOW',
        steps,
      };
    }
  }

  // 3. DNAT (Port Forwarding) Stage
  const sortedNat = [...state.nat].sort((a, b) => (a.sortOrder ?? 0) - (b.sortOrder ?? 0));
  for (const nat of sortedNat) {
    if (!nat.enabled || nat.type !== 'dnat') continue;
    if (nat.interface !== inIface.name && nat.interface !== 'any' && nat.interface !== 'floating') continue;
    if (nat.source && nat.source !== 'any' && !matchAddress(nat.source, query.srcIp, state.aliases, state.interfaces, localHostIps)) continue;
    if (nat.destination && nat.destination !== 'any' && !matchAddress(nat.destination, currentDstIp, state.aliases, state.interfaces, localHostIps)) continue;

    if (matchProtocol(nat.protocol, query.protocol)) {
      const portMatch = !nat.destinationPort || nat.destinationPort === 'any' || matchPort(nat.destinationPort, query.dstPort, state.aliases);
      if (portMatch && nat.targetIp) {
        currentDstIp = nat.targetIp;
        if (nat.targetPort && nat.targetPort !== 'any') {
          const trimmedTargetPort = nat.targetPort.trim();
          if (/^\d+$/.test(trimmedTargetPort)) {
            const parsedPort = Number.parseInt(trimmedTargetPort, 10);
            if (parsedPort >= 1 && parsedPort <= 65535) {
              currentDstPort = parsedPort;
            }
          }
        }
        natResult = {
          type: 'dnat',
          translatedIp: currentDstIp,
          translatedPort: currentDstPort,
        };
        steps.push({
          stage: 'dnat',
          description: `DNAT rule matched: translated destination to ${currentDstIp}:${currentDstPort}`,
          matched: true,
          action: 'TRANSLATE',
          detail: nat.description,
        });
        break;
      }
    }
  }

  // 4. Firewall Filter Rules Evaluation
  // On WAN interfaces, floating ('any'/'floating') rules only apply to forwarded transit traffic, not local host input.
  const isLocalInputOnWan = isWanIngress && natResult?.type !== 'dnat' && localHostIps.has(currentDstIp.trim().toLowerCase());
  const applicableRules = state.rules
    .filter((r) => {
      if (!r.enabled || r.direction === 'out') return false;
      if (r.interface === inIface.name) return true;
      if (r.interface === 'any' || r.interface === 'floating') {
        if (isLocalInputOnWan) return false;
        if (isWanIngress && natResult?.type !== 'dnat' && (r.destination === 'self' || r.destination === 'wan_ip')) {
          return false;
        }
        return true;
      }
      return false;
    })
    .sort((a, b) => a.sortOrder - b.sortOrder);

  let matchedRule: FirewallRule | undefined;

  for (const rule of applicableRules) {
    if (!matchProtocol(rule.protocol, query.protocol)) continue;
    if (!matchesEndpointWithInvert(rule.source, query.srcIp, Boolean(rule.invertSource), state.aliases, state.interfaces, localHostIps)) continue;
    if (!matchesEndpointWithInvert(rule.destination, currentDstIp, Boolean(rule.invertDestination), state.aliases, state.interfaces, localHostIps)) continue;
    if (!matchPort(rule.sourcePort, query.srcPort, state.aliases)) continue;
    if (!matchPort(rule.destinationPort, currentDstPort, state.aliases)) continue;

    matchedRule = rule;
    steps.push({
      stage: 'filter',
      description: `Matched rule "${rule.description || rule.id || 'unnamed'}" with action ${rule.action.toUpperCase()}`,
      matched: true,
      action: rule.action.toUpperCase(),
      detail: `Direction: ${rule.direction}, SortOrder: ${rule.sortOrder}`,
    });

    if (rule.gateway || rule.gatewayGroup) {
      policyRoutingResult = {
        gateway: rule.gateway,
        gatewayGroup: rule.gatewayGroup,
      };
      steps.push({
        stage: 'routing',
        description: `Policy routing applied to ${rule.gatewayGroup ? `Gateway Group: ${rule.gatewayGroup}` : `Gateway: ${rule.gateway}`}`,
        matched: true,
        action: 'MARK',
      });
    }

    if (rule.quick) {
      break;
    }
  }

  // Default verdict if no rule matched
  if (!matchedRule) {
    // Default policy is drop
    steps.push({
      stage: 'filter',
      description: 'Default implicit drop (no matching pass rule found)',
      matched: true,
      action: 'DROP',
    });
    return {
      allowed: false,
      verdict: 'DROP',
      nat: natResult,
      steps,
    };
  }

  const isAllowed = matchedRule.action === 'pass';
  const verdict = isAllowed ? 'ALLOW' : matchedRule.action === 'reject' ? 'REJECT' : 'DROP';

  // 5. SNAT / Outbound Masquerade Check (if allowed)
  if (isAllowed) {
    const outboundNat = state.nat.find((n) => n.enabled && (n.type === 'masquerade' || n.type === 'snat'));
    if (outboundNat) {
      steps.push({
        stage: 'snat',
        description: `Outbound ${outboundNat.type} will apply on egress interface ${outboundNat.interface}`,
        matched: true,
        action: 'TRANSLATE',
      });
    } else {
      const defaultWan = state.interfaces.find((i) => i.enabled && inferInterfaceRole(i) === 'wan');
      if (defaultWan && defaultWan.name !== inIface.name) {
        steps.push({
          stage: 'snat',
          description: `Default outbound masquerade will apply on WAN interface ${defaultWan.name} (${defaultWan.device})`,
          matched: true,
          action: 'TRANSLATE',
        });
      }
    }
  }

  return {
    allowed: isAllowed,
    verdict,
    matchedRule: {
      id: matchedRule.id,
      description: matchedRule.description,
      action: matchedRule.action,
      sortOrder: matchedRule.sortOrder,
    },
    policyRouting: policyRoutingResult,
    nat: natResult,
    steps,
  };
}

function matchProtocol(ruleProto: string, packetProto: string): boolean {
  if (ruleProto === 'any') return true;
  if (ruleProto === 'tcp_udp') return packetProto === 'tcp' || packetProto === 'udp';
  return ruleProto.toLowerCase() === packetProto.toLowerCase();
}

function matchesEndpointWithInvert(
  ruleAddr: string,
  packetIp: string,
  invert: boolean,
  aliases: Alias[],
  interfaces: Interface[] = [],
  localHostIps?: Set<string>,
): boolean {
  if (!ruleAddr || ruleAddr === 'any') return true;
  const pktIsV6 = packetIp.includes(':');
  if (invert) {
    if (ruleAddr === 'lan_net' && pktIsV6) return false;
    if (ruleAddr.startsWith('$')) {
      const aliasName = ruleAddr.slice(1);
      const alias = aliases.find((a) => a.name.toLowerCase() === aliasName.toLowerCase());
      if (!alias || !alias.enabled) return false;
      const hasFamilyEntry = alias.entries.some((entry) => {
        const upper = entry.trim().toUpperCase();
        if (COUNTRY_CIDR_TABLE[upper]) return !pktIsV6;
        return pktIsV6 ? entry.includes(':') : !entry.includes(':');
      });
      if (!hasFamilyEntry) return false;
    } else if (ruleAddr !== 'self' && ruleAddr !== 'wan_ip') {
      const upper = ruleAddr.trim().toUpperCase();
      if (COUNTRY_CIDR_TABLE[upper]) {
        if (pktIsV6) return false;
      } else if (ruleAddr.includes(':') !== pktIsV6) {
        return false;
      }
    }
  }
  const matched = matchAddress(ruleAddr, packetIp, aliases, interfaces, localHostIps);
  return invert ? !matched : matched;
}

function matchAddress(
  ruleAddr: string,
  packetIp: string,
  aliases: Alias[],
  interfaces: Interface[] = [],
  localHostIps?: Set<string>,
): boolean {
  if (!ruleAddr || ruleAddr === 'any') return true;
  if (ruleAddr.startsWith('$')) {
    const aliasName = ruleAddr.slice(1);
    const alias = aliases.find((a) => a.name.toLowerCase() === aliasName.toLowerCase());
    if (!alias || !alias.enabled) return false;
    return alias.entries.some((entry) => matchSingleAddress(entry, packetIp, interfaces, localHostIps));
  }
  return matchSingleAddress(ruleAddr, packetIp, interfaces, localHostIps);
}

function matchSingleAddress(
  spec: string,
  ip: string,
  interfaces: Interface[] = [],
  localHostIps?: Set<string>,
): boolean {
  if (spec === 'any') return true;
  if (spec === 'wan_ip') {
    const wanIfaces = interfaces.filter((i) => i.enabled && inferInterfaceRole(i) === 'wan' && (i.ipv4Address || i.ipv6Address));
    if (wanIfaces.length === 0) return true;
    const normIp = ip.trim().toLowerCase();
    return wanIfaces.some(
      (i) =>
        i.ipv4Address?.split('/')[0]?.trim().toLowerCase() === normIp ||
        i.ipv6Address?.split('/')[0]?.trim().toLowerCase() === normIp,
    );
  }
  if (spec === 'self') {
    const normIp = ip.trim().toLowerCase();
    if (localHostIps && localHostIps.size > 0) {
      return localHostIps.has(normIp);
    }
    const selfIps = interfaces.flatMap((i) =>
      i.enabled
        ? [i.ipv4Address?.split('/')[0]?.trim().toLowerCase(), i.ipv6Address?.split('/')[0]?.trim().toLowerCase()].filter(
            (v): v is string => Boolean(v),
          )
        : [],
    );
    return selfIps.includes(normIp);
  }
  if (spec === 'lan_net') {
    const lanIfaces = interfaces.filter((i) => i.enabled && inferInterfaceRole(i) === 'lan' && i.ipv4Address);
    if (lanIfaces.length === 0) return isIpInCidr(ip, '192.168.1.0/24');
    return lanIfaces.some((i) => {
      const addr = i.ipv4Address!;
      return isIpInCidr(ip, addr.includes('/') ? addr : `${addr}/24`);
    });
  }
  if (spec === ip) return true;
  const upper = spec.trim().toUpperCase();
  if (COUNTRY_CIDR_TABLE[upper]) {
    return COUNTRY_CIDR_TABLE[upper].some((cidr) => isIpInCidr(ip, cidr));
  }
  if (spec.includes('/')) {
    return isIpInCidr(ip, spec);
  }
  return false;
}

function matchPort(rulePort: string, packetPort: number, aliases: Alias[]): boolean {
  if (!rulePort || rulePort === 'any' || rulePort === '') return true;
  if (rulePort.startsWith('$')) {
    const aliasName = rulePort.slice(1);
    const alias = aliases.find((a) => a.name.toLowerCase() === aliasName.toLowerCase());
    if (!alias || !alias.enabled) return false;
    return alias.entries.some((entry) => matchSinglePort(entry, packetPort));
  }
  return matchSinglePort(rulePort, packetPort);
}

function matchSinglePort(spec: string, port: number): boolean {
  const parts = spec.split(',').map((s) => s.trim()).filter(Boolean);
  if (parts.length > 1) {
    return parts.some((part) => matchSinglePort(part, port));
  }
  const trimmed = parts[0] ?? '';
  if (!trimmed || trimmed === 'any') return true;
  if (trimmed.includes(':')) {
    const [start, end] = trimmed.split(':').map((s) => Number.parseInt(s.trim(), 10));
    return port >= start && port <= end;
  }
  if (trimmed.includes('-')) {
    const [start, end] = trimmed.split('-').map((s) => Number.parseInt(s.trim(), 10));
    return port >= start && port <= end;
  }
  return Number.parseInt(trimmed, 10) === port;
}

function isIpInCidr(ip: string, cidr: string): boolean {
  try {
    const [rangeIp, prefixStr] = cidr.split('/');
    const prefix = Number.parseInt(prefixStr, 10);
    if (Number.isNaN(prefix)) return false;

    if (ip.includes(':') || rangeIp.includes(':')) {
      const ipBig = ipv6ToBigInt(ip);
      const rangeBig = ipv6ToBigInt(rangeIp);
      if (ipBig === null || rangeBig === null || prefix < 0 || prefix > 128) return false;
      if (prefix === 0) return true;
      const shift = 128n - BigInt(prefix);
      const mask = ((1n << BigInt(prefix)) - 1n) << shift;
      return (ipBig & mask) === (rangeBig & mask);
    }

    if (prefix < 0 || prefix > 32) return false;
    const ipNum = ipToInt(ip);
    const rangeNum = ipToInt(rangeIp);
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return (ipNum & mask) === (rangeNum & mask);
  } catch {
    return false;
  }
}

function ipv6ToBigInt(ip: string): bigint | null {
  const parts = ip.split('::');
  if (parts.length > 2) return null;
  let head: string[] = parts[0] ? parts[0].split(':') : [];
  let tail: string[] = parts.length === 2 && parts[1] ? parts[1].split(':') : [];

  if (parts.length === 2) {
    const missing = 8 - (head.length + tail.length);
    if (missing < 0) return null;
    const zeros = new Array(missing).fill('0');
    head = head.concat(zeros).concat(tail);
  } else if (head.length !== 8) {
    return null;
  }

  let result = 0n;
  for (const part of head) {
    const val = Number.parseInt(part || '0', 16);
    if (Number.isNaN(val) || val < 0 || val > 0xffff) return null;
    result = (result << 16n) + BigInt(val);
  }
  return result;
}

function ipToInt(ip: string): number {
  return (
    ip
      .split('.')
      .reduce((acc, octet) => ((acc << 8) + Number.parseInt(octet, 10)) >>> 0, 0) >>> 0
  );
}
