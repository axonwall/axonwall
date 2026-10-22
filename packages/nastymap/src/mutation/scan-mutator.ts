import type { NmapHost, NmapPort, NmapRun } from '../types/nmap';

/**
 * Immutably updates a specific host in an NmapRun object using an updater callback.
 * Can return either a full NmapHost or a partial patch object.
 */
export function updateHostInScan(
  scan: NmapRun,
  hostIdOrIp: string,
  updater: (prev: NmapHost) => NmapHost | Partial<NmapHost>
): NmapRun {
  const targetId = hostIdOrIp.trim().toLowerCase();

  const updatedHosts = scan.hosts.map((host) => {
    const isMatch =
      host.id.toLowerCase() === targetId ||
      (host.ipv4 && host.ipv4.toLowerCase() === targetId) ||
      (host.ipv6 && host.ipv6.toLowerCase() === targetId) ||
      (host.primaryHostname && host.primaryHostname.toLowerCase() === targetId);

    if (!isMatch) return host;

    const result = updater(host);
    const merged: NmapHost = {
      ...host,
      ...result,
      status: {
        ...host.status,
        ...(result.status || {}),
      },
      ports: result.ports || host.ports,
      tags: result.tags || host.tags,
      customData: {
        ...(host.customData || {}),
        ...(result.customData || {}),
      },
    };

    // Recompute openPortCount
    merged.openPortCount = merged.ports.filter((p) => p.state === 'open').length;

    return merged;
  });

  return {
    ...scan,
    hosts: updatedHosts,
    runstats: {
      ...scan.runstats,
      hosts: {
        ...scan.runstats?.hosts,
        up: updatedHosts.filter((h) => h.status.state === 'up').length,
        down: updatedHosts.filter((h) => h.status.state === 'down').length,
        total: updatedHosts.length,
      },
    },
  };
}

/**
 * Deeply merges a secondary or updated scan into a base NmapRun object.
 * Useful for updating topology graphs after running targeted re-scans.
 */
export function mergeScanResults(baseScan: NmapRun, newScan: NmapRun): NmapRun {
  const hostMap = new Map<string, NmapHost>();

  // Populate base hosts
  for (const host of baseScan.hosts) {
    const key = host.ipv4 || host.id;
    hostMap.set(key, { ...host });
  }

  // Merge in new scan hosts
  for (const newHost of newScan.hosts) {
    const key = newHost.ipv4 || newHost.id;

    if (!hostMap.has(key)) {
      // New host discovered
      hostMap.set(key, { ...newHost });
    } else {
      // Existing host: merge ports, OS, scripts, and preserve user tags & comments
      const existing = hostMap.get(key)!;

      // Merge ports
      const portMap = new Map<number, NmapPort>();
      for (const p of existing.ports) portMap.set(p.portid, p);
      for (const p of newHost.ports) portMap.set(p.portid, p); // Overwrite / add updated port
      const mergedPorts = Array.from(portMap.values()).sort((a, b) => a.portid - b.portid);

      // Merge scripts
      const scriptMap = new Map<string, any>();
      for (const s of existing.hostscripts || []) scriptMap.set(s.id, s);
      for (const s of newHost.hostscripts || []) scriptMap.set(s.id, s);

      const mergedHost: NmapHost = {
        ...existing,
        ...newHost,
        ports: mergedPorts,
        openPortCount: mergedPorts.filter((p) => p.state === 'open').length,
        hostscripts: Array.from(scriptMap.values()),
        comments: newHost.comments || existing.comments,
        tags: Array.from(new Set([...(existing.tags || []), ...(newHost.tags || [])])),
        customData: {
          ...(existing.customData || {}),
          ...(newHost.customData || {}),
        },
      };

      hostMap.set(key, mergedHost);
    }
  }

  const mergedHostsList = Array.from(hostMap.values());

  return {
    ...baseScan,
    hosts: mergedHostsList,
    runstats: {
      ...baseScan.runstats,
      hosts: {
        up: mergedHostsList.filter((h) => h.status.state === 'up').length,
        down: mergedHostsList.filter((h) => h.status.state === 'down').length,
        total: mergedHostsList.length,
      },
    },
  };
}

/**
 * Adds a new host to an Nmap scan
 */
export function addHostToScan(scan: NmapRun, host: NmapHost): NmapRun {
  return {
    ...scan,
    hosts: [...scan.hosts, host],
  };
}

/**
 * Removes a host from an Nmap scan by IP or ID
 */
export function removeHostFromScan(scan: NmapRun, hostIdOrIp: string): NmapRun {
  const targetId = hostIdOrIp.trim().toLowerCase();
  const filtered = scan.hosts.filter(
    (h) =>
      h.id.toLowerCase() !== targetId &&
      (!h.ipv4 || h.ipv4.toLowerCase() !== targetId)
  );

  return {
    ...scan,
    hosts: filtered,
  };
}
