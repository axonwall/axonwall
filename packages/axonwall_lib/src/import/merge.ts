import type { DesiredState, FirewallRule, Alias, Vlan, NatRule, StaticRoute, DnsHostOverride } from '../schemas/index.js';

export interface MergeOptions {
  includeInterfaces?: boolean;
  includeVlans?: boolean;
  includeAliases?: boolean;
  includeRules?: boolean;
  includeNat?: boolean;
  includeDhcpStaticLeases?: boolean;
  includeDnsOverrides?: boolean;
  includeRoutes?: boolean;
  rulePlacement?: 'prepend' | 'append';
  aliasPrefix?: string;
}

/**
 * Selectively merges an imported firewall DesiredState into an existing active DesiredState.
 */
export function mergeFirewallConfigs(
  active: DesiredState,
  imported: DesiredState,
  options: MergeOptions = {}
): DesiredState {
  const merged: DesiredState = JSON.parse(JSON.stringify(active));
  const {
    includeInterfaces = false,
    includeVlans = true,
    includeAliases = true,
    includeRules = true,
    includeNat = true,
    includeDhcpStaticLeases = true,
    includeDnsOverrides = true,
    includeRoutes = true,
    rulePlacement = 'append',
    aliasPrefix = '',
  } = options;

  // 1. Interfaces (Optional, default preserve active)
  if (includeInterfaces && imported.interfaces?.length > 0) {
    const activeNames = new Set(merged.interfaces.map((i) => i.name));
    for (const iface of imported.interfaces) {
      if (!activeNames.has(iface.name)) {
        merged.interfaces.push(iface);
      }
    }
  }

  // 2. VLANs
  if (includeVlans && imported.vlans) {
    const existingTags = new Set(merged.vlans.map((v) => `${v.parentInterface}.${v.tag}`));
    for (const vlan of imported.vlans) {
      const key = `${vlan.parentInterface}.${vlan.tag}`;
      if (!existingTags.has(key)) {
        merged.vlans.push(vlan);
        existingTags.add(key);
      }
    }
  }

  // 3. Aliases
  const aliasNameMap = new Map<string, string>();
  if (includeAliases && imported.aliases) {
    const existingNames = new Set(merged.aliases.map((a) => a.name));
    for (const a of imported.aliases) {
      let finalName = a.name;
      if (aliasPrefix) {
        finalName = `${aliasPrefix}_${a.name}`;
      } else if (existingNames.has(a.name)) {
        finalName = `${a.name}_imported`;
      }
      aliasNameMap.set(a.name, finalName);

      merged.aliases.push({
        ...a,
        name: finalName,
      });
      existingNames.add(finalName);
    }
  }

  const remapAliasRef = (val?: string): string | undefined => {
    if (!val || !val.startsWith('$')) return val;
    const rawAlias = val.slice(1);
    return aliasNameMap.has(rawAlias) ? `$${aliasNameMap.get(rawAlias)}` : val;
  };

  // 4. Firewall Rules
  if (includeRules && imported.rules) {
    const rewrittenRules: FirewallRule[] = imported.rules.map((rule) => ({
      ...rule,
      source: remapAliasRef(rule.source) ?? rule.source,
      destination: remapAliasRef(rule.destination) ?? rule.destination,
      sourcePort: remapAliasRef(rule.sourcePort) ?? rule.sourcePort,
      destinationPort: remapAliasRef(rule.destinationPort) ?? rule.destinationPort,
    }));

    if (rulePlacement === 'prepend') {
      merged.rules = [...rewrittenRules, ...(merged.rules || [])];
    } else {
      merged.rules = [...(merged.rules || []), ...rewrittenRules];
    }
  }

  // 5. NAT Rules
  if (includeNat && imported.nat) {
    const rewrittenNat = imported.nat.map((rule) => ({
      ...rule,
      source: remapAliasRef(rule.source) ?? rule.source,
      destination: remapAliasRef(rule.destination) ?? rule.destination,
      sourcePort: remapAliasRef(rule.sourcePort) ?? rule.sourcePort,
      destinationPort: remapAliasRef(rule.destinationPort) ?? rule.destinationPort,
      targetPort: remapAliasRef(rule.targetPort) ?? rule.targetPort,
    }));
    merged.nat = [...(merged.nat || []), ...rewrittenNat];
  }

  // 6. DHCP Static Mappings
  if (includeDhcpStaticLeases && imported.dhcp?.subnets && merged.dhcp?.subnets) {
    for (const impSub of imported.dhcp.subnets) {
      const targetSub = merged.dhcp.subnets.find((s) => s.subnet === impSub.subnet);
      if (targetSub) {
        const existingMacs = new Set(targetSub.staticMappings.map((m) => m.mac.toLowerCase()));
        for (const map of impSub.staticMappings) {
          if (!existingMacs.has(map.mac.toLowerCase())) {
            targetSub.staticMappings.push(map);
            existingMacs.add(map.mac.toLowerCase());
          }
        }
      } else {
        // If whole subnet doesn't exist, add it
        merged.dhcp.subnets.push(impSub);
      }
    }
  }

  // 7. DNS Host Overrides
  if (includeDnsOverrides && imported.dns?.hostOverrides) {
    const existingHosts = new Set(
      (merged.dns?.hostOverrides || []).map((h) => `${h.hostname}.${h.domain}`.toLowerCase())
    );
    if (!merged.dns) {
      merged.dns = {
        enabled: true,
        listenPort: 53,
        dnssec: true,
        dotEnabled: true,
        dotUpstreams: [],
        hostOverrides: [],
      };
    }
    for (const h of imported.dns.hostOverrides) {
      const key = `${h.hostname}.${h.domain}`.toLowerCase();
      if (!existingHosts.has(key)) {
        merged.dns.hostOverrides.push(h);
        existingHosts.add(key);
      }
    }
  }

  // 8. Static Routes
  if (includeRoutes && imported.routes) {
    const existingNetworks = new Set((merged.routes || []).map((r) => r.network));
    for (const r of imported.routes) {
      if (!existingNetworks.has(r.network)) {
        merged.routes.push(r);
        existingNetworks.add(r.network);
      }
    }
  }

  return merged;
}
