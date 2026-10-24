import { normalizeAntiLockoutInterfaces, inferInterfaceRole } from '../schemas/index.js';
import type { DesiredState, FirewallRule } from '../schemas/index.js';

export interface LintIssue {
  type:
    | 'shadowed_rule'
    | 'duplicate_rule'
    | 'unused_alias'
    | 'missing_interface'
    | 'wan_management_exposed'
    | 'anti_lockout_on_wan';
  severity: 'error' | 'warning' | 'info';
  message: string;
  ruleId?: string;
  aliasName?: string;
}

export function lintRuleset(state: DesiredState): LintIssue[] {
  const issues: LintIssue[] = [];

  // 1. Check for missing interface references
  const validIfaces = new Set(state.interfaces.map((i) => i.name));
  validIfaces.add('any');
  validIfaces.add('floating');

  for (const rule of state.rules) {
    if (!validIfaces.has(rule.interface)) {
      issues.push({
        type: 'missing_interface',
        severity: 'error',
        message: `Rule references non-existent interface '${rule.interface}'`,
        ruleId: rule.id,
      });
    }
  }

  // 2. Check for unused aliases
  const referencedAliases = new Set<string>();
  for (const rule of state.rules) {
    for (const val of [rule.source, rule.destination, rule.sourcePort, rule.destinationPort]) {
      if (val && val.startsWith('$')) {
        referencedAliases.add(val.slice(1).toLowerCase());
      }
    }
  }
  if (state.nat) {
    for (const nat of state.nat) {
      for (const val of [nat.source, nat.destination, nat.sourcePort, nat.destinationPort, nat.targetIp, nat.targetPort]) {
        if (val && val.startsWith('$')) {
          referencedAliases.add(val.slice(1).toLowerCase());
        }
      }
    }
  }
  for (const alias of state.aliases) {
    if (!referencedAliases.has(alias.name.toLowerCase())) {
      issues.push({
        type: 'unused_alias',
        severity: 'info',
        message: `Alias '${alias.name}' is defined but not referenced in any firewall rule`,
        aliasName: alias.name,
      });
    }
  }

  // 3. Shadowed and Duplicate Rule Detection per interface
  const rulesByIface = new Map<string, FirewallRule[]>();
  for (const rule of state.rules) {
    if (!rule.enabled) continue;
    const iface = rule.interface;
    if (!rulesByIface.has(iface)) {
      rulesByIface.set(iface, []);
    }
    rulesByIface.get(iface)!.push(rule);
  }

  for (const [iface, rules] of rulesByIface.entries()) {
    const sorted = [...rules].sort((a, b) => a.sortOrder - b.sortOrder);
    const catchAllByDirection = new Map<'in' | 'out', FirewallRule>();
    const normPort = (p?: string) => (!p || p === 'any' ? 'any' : p);

    for (let i = 0; i < sorted.length; i++) {
      const current = sorted[i];
      const dir = current.direction || 'in';

      // Check if previously shadowed by catch-all in the same direction
      const catchAllRule = catchAllByDirection.get(dir);
      if (catchAllRule) {
        issues.push({
          type: 'shadowed_rule',
          severity: 'warning',
          message: `Rule '${current.description || current.id || 'unnamed'}' is shadowed by catch-all rule '${catchAllRule.description || catchAllRule.id || 'unnamed'}' above it on interface ${iface}`,
          ruleId: current.id,
        });
      }

      // Check if current is a shadowing catch-all (must have quick !== false)
      if (
        current.quick !== false &&
        current.protocol === 'any' &&
        (current.source === 'any' || !current.source) &&
        (current.destination === 'any' || !current.destination) &&
        (!current.sourcePort || current.sourcePort === 'any') &&
        (!current.destinationPort || current.destinationPort === 'any')
      ) {
        if (!catchAllByDirection.has(dir)) {
          catchAllByDirection.set(dir, current);
        }
      }

      // Check duplicates against previous rules in same interface
      for (let j = 0; j < i; j++) {
        const prev = sorted[j];
        if (
          prev.action === current.action &&
          prev.protocol === current.protocol &&
          prev.source === current.source &&
          prev.destination === current.destination &&
          normPort(prev.sourcePort) === normPort(current.sourcePort) &&
          normPort(prev.destinationPort) === normPort(current.destinationPort) &&
          prev.direction === current.direction
        ) {
          issues.push({
            type: 'duplicate_rule',
            severity: 'warning',
            message: `Rule has identical match criteria and action to rule above it on interface ${iface}`,
            ruleId: current.id,
          });
          break;
        }
      }
    }
  }

  // 4. Anti-Lockout Interface Safety Check
  const wanIfaces = new Set(
    state.interfaces.filter((i) => inferInterfaceRole(i) === 'wan').map((i) => i.name),
  );
  wanIfaces.add('wan');

  if (state.system?.antiLockout?.enabled) {
    const antiLockoutIfaces = normalizeAntiLockoutInterfaces(state.system.antiLockout);
    const badWan = antiLockoutIfaces.find((n) => wanIfaces.has(n));
    if (badWan) {
      issues.push({
        type: 'anti_lockout_on_wan',
        severity: 'error',
        message: `Anti-Lockout rule cannot be bound to WAN interface '${badWan}'. Management services must be isolated to LAN/internal networks.`,
      });
    }
  }

  // 5. Detect Exposure of Management Services on WAN
  const mgmtPortNums = [22, 80, 443, 2966, 3000];
  const mgmtPorts = new Set(mgmtPortNums.map(String));
  for (const rule of state.rules) {
    if (!rule.enabled || rule.action !== 'pass' || rule.direction !== 'in') continue;
    if (!wanIfaces.has(rule.interface)) continue;
    if (rule.protocol !== 'tcp' && rule.protocol !== 'tcp_udp' && rule.protocol !== 'any') continue;

    const isWildcardSrc = !rule.source || rule.source === 'any' || rule.source === '0.0.0.0/0' || rule.source === '::/0';
    if (isWildcardSrc) {
      const dport = (rule.destinationPort || '').trim().toLowerCase();
      let touchesMgmt = false;

      if (dport === '' || dport === 'any') {
        touchesMgmt = true;
      } else {
        const ports = dport.split(/[\s,]+/).map((p) => p.trim()).filter(Boolean);
        for (const p of ports) {
          if (mgmtPorts.has(p) || p === 'any') {
            touchesMgmt = true;
            break;
          }
          if (p.includes('-')) {
            const [startStr, endStr] = p.split('-').map((s) => s.trim());
            const start = Number.parseInt(startStr, 10);
            const end = Number.parseInt(endStr, 10);
            if (!Number.isNaN(start) && !Number.isNaN(end) && mgmtPortNums.some((mp) => mp >= start && mp <= end)) {
              touchesMgmt = true;
              break;
            }
          }
        }
      }

      if (touchesMgmt) {
        issues.push({
          type: 'wan_management_exposed',
          severity: 'warning',
          message: `Rule '${rule.description || rule.id || 'unnamed'}' exposes Web Console / SSH management port(s) on ${rule.interface} to the public internet (source: any).`,
          ruleId: rule.id,
        });
      }
    }
  }

  return issues;
}
