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

function protocolEncloses(parent: string, child: string): boolean {
  const normParent = normalizeProtocol(parent);
  const normChild = normalizeProtocol(child);
  if (normParent === 'any') return true;
  if (normChild === 'any') return false;
  if (normParent === 'tcp_udp') {
    return normChild === 'tcp' || normChild === 'udp' || normChild === 'tcp_udp';
  }
  return normParent === normChild;
}

function ifaceEncloses(parentIface: string, childIface: string): boolean {
  const p = (parentIface || '').trim().toLowerCase();
  const c = (childIface || '').trim().toLowerCase();
  if (p === 'any' || p === 'floating') return true;
  if (c === 'any' || c === 'floating') return false;
  return p === c;
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

function ipEndpointEncloses(
  parent: string,
  child: string,
  parentInvert = false,
  childInvert = false,
): boolean {
  const p = (parent || 'any').trim();
  const c = (child || 'any').trim();
  const pInv = Boolean(parentInvert) && p !== 'any';
  const cInv = Boolean(childInvert) && c !== 'any';

  if (!pInv && !cInv) {
    return ipEncloses(p, c);
  }
  if (pInv && cInv) {
    return ipEncloses(c, p);
  }
  if (pInv && !cInv) {
    if (c === 'any') return false;
    const pCidr = parseCidrOrIp(p);
    const cCidr = parseCidrOrIp(c);
    if (!pCidr || !cCidr) return false;
    const minMask = ((pCidr.mask >>> 0) < (cCidr.mask >>> 0) ? pCidr.mask : cCidr.mask) >>> 0;
    return (pCidr.base & minMask) >>> 0 !== (cCidr.base & minMask) >>> 0;
  }
  return false;
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
  const ordered = rules
    .map((rule, idx) => ({ rule, ruleNumber: idx + 1 }))
    .sort((a, b) => (a.rule.sortOrder ?? 0) - (b.rule.sortOrder ?? 0));

  for (let i = 0; i < ordered.length; i++) {
    const current = ordered[i]!.rule;
    const currentIdx = ordered[i]!.ruleNumber;
    if (current.enabled === false) continue;

    for (let j = 0; j < i; j++) {
      const prev = ordered[j]!.rule;
      const prevIdx = ordered[j]!.ruleNumber;
      if (prev.enabled === false) continue;
      if (prev.quick === false) continue;

      // Prev rule's interface must enclose current's interface and match direction
      const dirMatch = prev.direction === current.direction;
      if (!ifaceEncloses(prev.interface, current.interface) || !dirMatch) continue;

      // Prev protocol must enclose current protocol
      if (!protocolEncloses(prev.protocol, current.protocol)) continue;

      // Check if prev encloses current's source & destination (respecting invert flags)
      const srcEnclosed = ipEndpointEncloses(
        prev.source,
        current.source,
        Boolean(prev.invertSource),
        Boolean(current.invertSource),
      );
      const dstEnclosed = ipEndpointEncloses(
        prev.destination,
        current.destination,
        Boolean(prev.invertDestination),
        Boolean(current.invertDestination),
      );
      const srcPortEnclosed = portEncloses(prev.sourcePort, current.sourcePort);
      const dstPortEnclosed = portEncloses(prev.destinationPort, current.destinationPort);

      if (srcEnclosed && dstEnclosed && srcPortEnclosed && dstPortEnclosed) {
        const isExactDuplicate =
          prev.action === current.action &&
          (prev.source || 'any') === (current.source || 'any') &&
          (prev.destination || 'any') === (current.destination || 'any') &&
          Boolean(prev.invertSource) === Boolean(current.invertSource) &&
          Boolean(prev.invertDestination) === Boolean(current.invertDestination) &&
          prev.protocol === current.protocol &&
          (prev.destinationPort || '') === (current.destinationPort || '') &&
          (prev.sourcePort || '') === (current.sourcePort || '') &&
          prev.interface.toLowerCase() === current.interface.toLowerCase();

        if (isExactDuplicate) {
          issues.push({
            type: 'duplicate',
            ruleIndex: currentIdx,
            shadowedByIndex: prevIdx,
            description: `Rule #${currentIdx} is an identical duplicate of Rule #${prevIdx}.`,
            suggestion: `Remove Rule #${currentIdx} to eliminate redundancy and reduce kernel table overhead.`,
          });
        } else if (prev.action !== current.action) {
          issues.push({
            type: 'shadowed',
            ruleIndex: currentIdx,
            shadowedByIndex: prevIdx,
            description: `Rule #${currentIdx} (${current.action.toUpperCase()}) is completely shadowed by preceding Rule #${prevIdx} (${prev.action.toUpperCase()}).`,
            suggestion: `Move Rule #${currentIdx} above Rule #${prevIdx}, or refine Rule #${prevIdx}'s scope so Rule #${currentIdx} can be reached.`,
          });
        } else {
          // Same action, but prev is a superset
          issues.push({
            type: 'redundant',
            ruleIndex: currentIdx,
            shadowedByIndex: prevIdx,
            description: `Rule #${currentIdx} is redundant; traffic is already handled by preceding Rule #${prevIdx} with action ${prev.action.toUpperCase()}.`,
            suggestion: `Rule #${currentIdx} can safely be removed unless required for distinct logging.`,
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
