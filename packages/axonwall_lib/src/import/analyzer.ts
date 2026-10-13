import type { FirewallRule, DesiredState } from '../schemas/index.js';

export interface RuleShadowIssue {
  type: 'shadowed' | 'redundant' | 'duplicate';
  ruleIndex: number;
  shadowedByIndex: number;
  description: string;
  suggestion: string;
}

export interface RuleAnalysisReport {
  totalRules: number;
  issues: RuleShadowIssue[];
  cleanRuleCount: number;
}

export interface SubnetCollision {
  type: 'interface_ip' | 'dhcp_pool' | 'static_route';
  identifier: string;
  baseValue: string;
  importedValue: string;
  suggestion: string;
}

export interface CollisionReport {
  hasCollisions: boolean;
  collisions: SubnetCollision[];
}

function normalizeProtocol(proto: string): string {
  if (!proto || proto === 'any') return 'any';
  return proto.toLowerCase();
}

function protocolsOverlap(p1: string, p2: string): boolean {
  const norm1 = normalizeProtocol(p1);
  const norm2 = normalizeProtocol(p2);
  if (norm1 === 'any' || norm2 === 'any') return true;
  if (norm1 === 'tcp_udp' && (norm2 === 'tcp' || norm2 === 'udp' || norm2 === 'tcp_udp')) return true;
  if (norm2 === 'tcp_udp' && (norm1 === 'tcp' || norm1 === 'udp')) return true;
  return norm1 === norm2;
}

function parseIpv4ToUint(ip: string): number | null {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return null;
  }
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function parseCidrOrIp(input: string): { base: number; mask: number } | null {
  if (!input || input === 'any') return null;
  const [ipPart, maskPart] = input.split('/');
  const base = parseIpv4ToUint(ipPart);
  if (base === null) return null;

  let prefixLen = 32;
  if (maskPart !== undefined) {
    const parsedMask = Number.parseInt(maskPart, 10);
    if (Number.isNaN(parsedMask) || parsedMask < 0 || parsedMask > 32) return null;
    prefixLen = parsedMask;
  }

  const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
  return { base: (base & mask) >>> 0, mask };
}

function ipEncloses(parent: string, child: string): boolean {
  if (!parent || parent === 'any') return true;
  if (!child || child === 'any') return false;

  const pCidr = parseCidrOrIp(parent);
  const cCidr = parseCidrOrIp(child);
  if (!pCidr || !cCidr) return parent === child;

  // Parent must have smaller or equal prefix length (i.e. larger or equal network)
  if ((pCidr.mask >>> 0) > (cCidr.mask >>> 0)) return false;
  return (cCidr.base & pCidr.mask) >>> 0 === pCidr.base;
}

function portEncloses(parentPort: string, childPort: string): boolean {
  const p = parentPort?.trim() || '';
  const c = childPort?.trim() || '';

  if (!p || p === 'any') return true;
  if (!c || c === 'any') return false;
  return p === c;
}

/**
 * Analyzes an ordered list of firewall rules for:
 * 1. Exact duplicates.
 * 2. Shadowed rules (earlier rule matches a superset with an opposing action, e.g. DROP before PASS).
 * 3. Redundant rules (earlier rule matches a superset with the same action).
 */
export function analyzeRuleShadowing(rules: FirewallRule[]): RuleAnalysisReport {
  const issues: RuleShadowIssue[] = [];

  for (let i = 0; i < rules.length; i++) {
    const current = rules[i];
    if (current.enabled === false) continue;

    for (let j = 0; j < i; j++) {
      const prev = rules[j];
      if (prev.enabled === false) continue;

      // Rules must be on matching interface and direction
      const ifaceMatch =
        prev.interface === 'any' ||
        current.interface === 'any' ||
        prev.interface === 'floating' ||
        current.interface === 'floating' ||
        prev.interface.toLowerCase() === current.interface.toLowerCase();

      const dirMatch = prev.direction === current.direction;
      if (!ifaceMatch || !dirMatch) continue;

      // Check protocol overlap
      if (!protocolsOverlap(prev.protocol, current.protocol)) continue;

      // Check if prev encloses current's source & destination
      const srcEnclosed = ipEncloses(prev.source, current.source);
      const dstEnclosed = ipEncloses(prev.destination, current.destination);
      const srcPortEnclosed = portEncloses(prev.sourcePort, current.sourcePort);
      const dstPortEnclosed = portEncloses(prev.destinationPort, current.destinationPort);

      if (srcEnclosed && dstEnclosed && srcPortEnclosed && dstPortEnclosed) {
        const isExactDuplicate =
          prev.action === current.action &&
          prev.source === current.source &&
          prev.destination === current.destination &&
          prev.protocol === current.protocol &&
          prev.destinationPort === current.destinationPort &&
          prev.sourcePort === current.sourcePort;

        if (isExactDuplicate) {
          issues.push({
            type: 'duplicate',
            ruleIndex: i + 1,
            shadowedByIndex: j + 1,
            description: `Rule #${i + 1} is an identical duplicate of Rule #${j + 1}.`,
            suggestion: `Remove Rule #${i + 1} to eliminate redundancy and reduce kernel table overhead.`,
          });
        } else if (prev.action !== current.action) {
          issues.push({
            type: 'shadowed',
            ruleIndex: i + 1,
            shadowedByIndex: j + 1,
            description: `Rule #${i + 1} (${current.action.toUpperCase()}) is completely shadowed by preceding Rule #${j + 1} (${prev.action.toUpperCase()}).`,
            suggestion: `Move Rule #${i + 1} above Rule #${j + 1}, or refine Rule #${j + 1}'s scope so Rule #${i + 1} can be reached.`,
          });
        } else {
          // Same action, but prev is a superset
          issues.push({
            type: 'redundant',
            ruleIndex: i + 1,
            shadowedByIndex: j + 1,
            description: `Rule #${i + 1} is redundant; traffic is already handled by preceding Rule #${j + 1} with action ${prev.action.toUpperCase()}.`,
            suggestion: `Rule #${i + 1} can safely be removed unless required for distinct logging.`,
          });
        }
        break; // Only report the first preceding rule that shadows it
      }
    }
  }

  return {
    totalRules: rules.length,
    issues,
    cleanRuleCount: rules.length - issues.length,
  };
}

/**
 * Checks for IP/subnet collisions between an active running state and an imported state.
 */
export function analyzeSubnetCollisions(base: DesiredState, imported: DesiredState): CollisionReport {
  const collisions: SubnetCollision[] = [];

  // 1. Interface IP collisions
  const baseIfaces = new Map<string, string>();
  for (const iface of base.interfaces) {
    if (iface.ipv4Address) {
      baseIfaces.set(iface.name, iface.ipv4Address);
    }
  }

  for (const imp of imported.interfaces) {
    if (imp.ipv4Address) {
      const existing = baseIfaces.get(imp.name);
      if (existing && existing !== imp.ipv4Address) {
        collisions.push({
          type: 'interface_ip',
          identifier: imp.name,
          baseValue: existing,
          importedValue: imp.ipv4Address,
          suggestion: `Interface '${imp.name}' has conflicting IP ${existing} vs ${imp.ipv4Address}. Select which interface configuration to preserve.`,
        });
      }
    }
  }

  // 2. DHCP Pool collisions
  const baseSubnets = new Set(base.dhcp?.subnets.map((s) => s.subnet) || []);
  for (const impSub of imported.dhcp?.subnets || []) {
    if (baseSubnets.has(impSub.subnet)) {
      collisions.push({
        type: 'dhcp_pool',
        identifier: impSub.subnet,
        baseValue: impSub.subnet,
        importedValue: impSub.subnet,
        suggestion: `DHCP subnet ${impSub.subnet} is already defined on the system. Merge static leases rather than replacing the scope.`,
      });
    }
  }

  return {
    hasCollisions: collisions.length > 0,
    collisions,
  };
}
