import type { DesiredState, FirewallRule } from '../schemas/index.js';

export interface LintIssue {
  type: 'shadowed_rule' | 'duplicate_rule' | 'unused_alias' | 'missing_interface';
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
    let catchAllSeen = false;
    let catchAllRule: FirewallRule | null = null;

    for (let i = 0; i < sorted.length; i++) {
      const current = sorted[i];

      // Check if previously shadowed by catch-all
      if (catchAllSeen && catchAllRule) {
        issues.push({
          type: 'shadowed_rule',
          severity: 'warning',
          message: `Rule '${current.description || current.id || 'unnamed'}' is shadowed by catch-all rule '${catchAllRule.description || catchAllRule.id || 'unnamed'}' above it on interface ${iface}`,
          ruleId: current.id,
        });
      }

      // Check if current is catch-all
      if (
        current.protocol === 'any' &&
        (current.source === 'any' || !current.source) &&
        (current.destination === 'any' || !current.destination) &&
        (!current.sourcePort || current.sourcePort === 'any') &&
        (!current.destinationPort || current.destinationPort === 'any')
      ) {
        catchAllSeen = true;
        catchAllRule = current;
      }

      // Check duplicates against previous rules in same interface
      for (let j = 0; j < i; j++) {
        const prev = sorted[j];
        if (
          prev.action === current.action &&
          prev.protocol === current.protocol &&
          prev.source === current.source &&
          prev.destination === current.destination &&
          prev.sourcePort === current.sourcePort &&
          prev.destinationPort === current.destinationPort &&
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

  return issues;
}
