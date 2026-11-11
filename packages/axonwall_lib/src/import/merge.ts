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
  includeVirt?: boolean;
  includeNas?: boolean;
  rulePlacement?: 'prepend' | 'append';
  aliasPrefix?: string;
}

/**
 * Selectively merges an imported firewall/hypervisor/NAS DesiredState into an existing active DesiredState.
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
    includeVirt = true,
    includeNas = true,
    rulePlacement = 'append',
    aliasPrefix = '',
  } = options;

  // 1. Interfaces (Optional, default preserve active)
  merged.interfaces = merged.interfaces || [];
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
    merged.vlans = merged.vlans || [];
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
    merged.aliases = merged.aliases || [];
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
    merged.routes = merged.routes || [];
    const existingNetworks = new Set(merged.routes.map((r) => r.network));
    for (const r of imported.routes) {
      if (!existingNetworks.has(r.network)) {
        merged.routes.push(r);
        existingNetworks.add(r.network);
      }
    }
  }

  // 9. Bridges, KVM VMs, LXC Containers & Security Groups (Proxmox Migration)
  if (includeVirt) {
    if (imported.bridges?.length) {
      merged.bridges = merged.bridges || [];
      const existingBridges = new Set(merged.bridges.map((b) => b.name));
      for (const b of imported.bridges) {
        if (!existingBridges.has(b.name)) {
          merged.bridges.push(b);
          existingBridges.add(b.name);
        }
      }
    }
    if (imported.virt && (imported.virt.vms?.length || imported.virt.containers?.length || imported.virt.securityGroups?.length)) {
      if (!merged.virt) {
        merged.virt = JSON.parse(JSON.stringify(imported.virt));
      } else {
        merged.virt.enabled = merged.virt.enabled || imported.virt.enabled;
        merged.virt.vms = merged.virt.vms || [];
        const existingVmids = new Set(merged.virt.vms.map((v) => v.vmid));
        for (const vm of imported.virt.vms || []) {
          if (!existingVmids.has(vm.vmid)) {
            merged.virt.vms.push(vm);
            existingVmids.add(vm.vmid);
          }
        }
        merged.virt.containers = merged.virt.containers || [];
        const existingCtids = new Set(merged.virt.containers.map((c) => c.ctid));
        for (const ct of imported.virt.containers || []) {
          if (!existingCtids.has(ct.ctid)) {
            merged.virt.containers.push(ct);
            existingCtids.add(ct.ctid);
          }
        }
        merged.virt.securityGroups = merged.virt.securityGroups || [];
        const existingSgs = new Set(merged.virt.securityGroups.map((sg) => sg.name));
        for (const sg of imported.virt.securityGroups || []) {
          if (!existingSgs.has(sg.name)) {
            merged.virt.securityGroups.push(sg);
            existingSgs.add(sg.name);
          }
        }
      }
      merged.plugins = merged.plugins || [];
      const virtPlugin = merged.plugins.find((p) => p.id === 'core-virt');
      if (virtPlugin) virtPlugin.enabled = true;
      else merged.plugins.push({ id: 'core-virt', enabled: true });
    }
  }

  // 10. OpenZFS Pools, Datasets, Shares & Cloud Sync (TrueNAS / Proxmox Storage Migration)
  if (includeNas && imported.nas) {
    if (!merged.nas) {
      merged.nas = JSON.parse(JSON.stringify(imported.nas));
    } else {
      merged.nas.enabled = merged.nas.enabled || imported.nas.enabled;
      merged.nas.pools = merged.nas.pools || [];
      const existingPools = new Set(merged.nas.pools.map((p) => p.name));
      for (const p of imported.nas.pools || []) {
        if (!existingPools.has(p.name)) {
          merged.nas.pools.push(p);
          existingPools.add(p.name);
        }
      }
      merged.nas.datasets = merged.nas.datasets || [];
      const existingDatasets = new Set(merged.nas.datasets.map((d) => `${d.pool}/${d.name}`));
      for (const d of imported.nas.datasets || []) {
        const k = `${d.pool}/${d.name}`;
        if (!existingDatasets.has(k)) {
          merged.nas.datasets.push(d);
          existingDatasets.add(k);
        }
      }
      merged.nas.smbShares = merged.nas.smbShares || [];
      const existingSmb = new Set(merged.nas.smbShares.map((s) => s.name));
      for (const s of imported.nas.smbShares || []) {
        if (!existingSmb.has(s.name)) {
          merged.nas.smbShares.push(s);
          existingSmb.add(s.name);
        }
      }
      merged.nas.nfsExports = merged.nas.nfsExports || [];
      const existingNfs = new Set(merged.nas.nfsExports.map((e) => e.path));
      for (const e of imported.nas.nfsExports || []) {
        if (!existingNfs.has(e.path)) {
          merged.nas.nfsExports.push(e);
          existingNfs.add(e.path);
        }
      }
      merged.nas.iscsiTargets = merged.nas.iscsiTargets || [];
      const existingIscsi = new Set(merged.nas.iscsiTargets.map((t) => t.iqn));
      for (const t of imported.nas.iscsiTargets || []) {
        if (!existingIscsi.has(t.iqn)) {
          merged.nas.iscsiTargets.push(t);
          existingIscsi.add(t.iqn);
        }
      }
      merged.nas.cloudSyncTasks = merged.nas.cloudSyncTasks || [];
      const existingCs = new Set(merged.nas.cloudSyncTasks.map((c) => c.name));
      for (const c of imported.nas.cloudSyncTasks || []) {
        if (!existingCs.has(c.name)) {
          merged.nas.cloudSyncTasks.push(c);
          existingCs.add(c.name);
        }
      }
    }
    if (imported.nas.enabled || (imported.nas.pools?.length ?? 0) > 0 || (imported.nas.smbShares?.length ?? 0) > 0) {
      merged.plugins = merged.plugins || [];
      const nasPlugin = merged.plugins.find((p) => p.id === 'core-nas');
      if (nasPlugin) nasPlugin.enabled = true;
      else merged.plugins.push({ id: 'core-nas', enabled: true });
    }
  }

  return merged;
}
