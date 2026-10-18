import { normalizeAntiLockoutInterfaces } from '../schemas/index.js';
import type { Alias, DesiredState, FirewallRule, NatRule, PacketTracerQuery } from '../schemas/index.js';

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

  // 2. Anti-Lockout check
  const antiLockoutIfaces = normalizeAntiLockoutInterfaces(state.system.antiLockout);
  if (state.system.antiLockout?.enabled && antiLockoutIfaces.includes(inIface.name)) {
    if (
      query.protocol === 'tcp' &&
      state.system.antiLockout.ports.includes(query.dstPort) &&
      (inIface.ipv4Address ? currentDstIp === inIface.ipv4Address.split('/')[0] : true)
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
  for (const nat of state.nat) {
    if (!nat.enabled || nat.type !== 'dnat') continue;
    if (nat.interface !== inIface.name && nat.interface !== 'any') continue;

    if (matchProtocol(nat.protocol, query.protocol)) {
      const portMatch = !nat.destinationPort || Number.parseInt(nat.destinationPort, 10) === query.dstPort;
      if (portMatch && nat.targetIp) {
        currentDstIp = nat.targetIp;
        if (nat.targetPort) {
          currentDstPort = Number.parseInt(nat.targetPort, 10);
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
  // In nftables/Axonwall: rules are evaluated in sortOrder.
  const applicableRules = state.rules
    .filter(
      (r) =>
        r.enabled &&
        (r.interface === inIface.name || r.interface === 'any' || r.interface === 'floating') &&
        r.direction !== 'out'
    )
    .sort((a, b) => a.sortOrder - b.sortOrder);

  let matchedRule: FirewallRule | undefined;

  for (const rule of applicableRules) {
    if (!matchProtocol(rule.protocol, query.protocol)) continue;
    if (!matchAddress(rule.source, query.srcIp, state.aliases)) continue;
    if (!matchAddress(rule.destination, currentDstIp, state.aliases)) continue;
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

function matchAddress(ruleAddr: string, packetIp: string, aliases: Alias[]): boolean {
  if (!ruleAddr || ruleAddr === 'any') return true;
  if (ruleAddr.startsWith('$')) {
    const aliasName = ruleAddr.slice(1);
    const alias = aliases.find((a) => a.name === aliasName);
    if (!alias) return false;
    return alias.entries.some((entry) => matchSingleAddress(entry, packetIp));
  }
  return matchSingleAddress(ruleAddr, packetIp);
}

function matchSingleAddress(spec: string, ip: string): boolean {
  if (spec === ip) return true;
  if (spec.includes('/')) {
    return isIpInCidr(ip, spec);
  }
  return false;
}

function matchPort(rulePort: string, packetPort: number, aliases: Alias[]): boolean {
  if (!rulePort || rulePort === 'any' || rulePort === '') return true;
  if (rulePort.startsWith('$')) {
    const aliasName = rulePort.slice(1);
    const alias = aliases.find((a) => a.name === aliasName);
    if (!alias) return false;
    return alias.entries.some((entry) => matchSinglePort(entry, packetPort));
  }
  return matchSinglePort(rulePort, packetPort);
}

function matchSinglePort(spec: string, port: number): boolean {
  if (spec.includes('-')) {
    const [start, end] = spec.split('-').map((s) => Number.parseInt(s.trim(), 10));
    return port >= start && port <= end;
  }
  return Number.parseInt(spec, 10) === port;
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
