import type { NmapHost, NmapPort, NmapRun } from '../types/nmap';

function buildUpdatedRunstats(
  prevRunstats: NmapRun['runstats'] | undefined,
  hosts: NmapHost[]
): NmapRun['runstats'] {
  const finished = prevRunstats?.finished ?? {
    time: Math.floor(Date.now() / 1000),
    timestr: new Date().toUTCString(),
    elapsed: 0,
    summary: `Nmap scan: ${hosts.length} hosts`,
    exit: 'success',
  };
  return {
    ...prevRunstats,
    finished,
    hosts: {
      ...prevRunstats?.hosts,
      up: hosts.filter((h) => h.status.state === 'up').length,
      down: hosts.filter((h) => h.status.state === 'down').length,
      total: hosts.length,
    },
  };
}

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
    runstats: buildUpdatedRunstats(scan.runstats, updatedHosts),
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
    const key = host.ipv4 || host.ipv6 || host.id;
    hostMap.set(key, { ...host });
  }

  // Merge in new scan hosts
  for (const newHost of newScan.hosts) {
    const key = newHost.ipv4 || newHost.ipv6 || newHost.id;

    if (!hostMap.has(key)) {
      // New host discovered
      hostMap.set(key, { ...newHost });
    } else {
      // Existing host: merge ports, OS, scripts, and preserve user tags & comments
      const existing = hostMap.get(key)!;

      // Merge ports keyed by portid/protocol
      const portMap = new Map<string, NmapPort>();
      for (const p of existing.ports) portMap.set(`${p.portid}/${p.protocol}`, p);
      for (const p of newHost.ports) portMap.set(`${p.portid}/${p.protocol}`, p); // Overwrite / add updated port
      const mergedPorts = Array.from(portMap.values()).sort((a, b) => a.portid - b.portid || a.protocol.localeCompare(b.protocol));

      // Merge scripts
      const scriptMap = new Map<string, any>();
      for (const s of existing.hostscripts || []) scriptMap.set(s.id, s);
      for (const s of newHost.hostscripts || []) scriptMap.set(s.id, s);

      const mergedHostnames =
        newHost.hostnames && newHost.hostnames.length > 0 ? newHost.hostnames : existing.hostnames;
      const mergedPrimaryHostname =
        newHost.primaryHostname && newHost.primaryHostname !== 'Unknown'
          ? newHost.primaryHostname
          : existing.primaryHostname;
      const mergedOs =
        newHost.os && newHost.os.osmatches && newHost.os.osmatches.length > 0
          ? newHost.os
          : (existing.os || newHost.os);
      const mergedPrimaryOs =
        newHost.primaryOs && newHost.primaryOs !== 'Unknown'
          ? newHost.primaryOs
          : existing.primaryOs;
      const mergedOsFamily =
        newHost.osFamily && newHost.osFamily !== 'Unknown'
          ? newHost.osFamily
          : existing.osFamily;

      const mergedHost: NmapHost = {
        ...existing,
        ...newHost,
        addresses: newHost.addresses && newHost.addresses.length > 0 ? newHost.addresses : existing.addresses,
        hostnames: mergedHostnames,
        primaryHostname: mergedPrimaryHostname,
        mac: newHost.mac || existing.mac,
        os: mergedOs,
        primaryOs: mergedPrimaryOs,
        osFamily: mergedOsFamily,
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
    runstats: buildUpdatedRunstats(baseScan.runstats, mergedHostsList),
  };
}

/**
 * Adds a new host to an Nmap scan
 */
export function addHostToScan(scan: NmapRun, host: NmapHost): NmapRun {
  const nextHosts = [...scan.hosts, host];
  return {
    ...scan,
    hosts: nextHosts,
    runstats: buildUpdatedRunstats(scan.runstats, nextHosts),
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
      (!h.ipv4 || h.ipv4.toLowerCase() !== targetId) &&
      (!h.ipv6 || h.ipv6.toLowerCase() !== targetId) &&
      (!h.primaryHostname || h.primaryHostname.toLowerCase() !== targetId)
  );

  return {
    ...scan,
    hosts: filtered,
    runstats: buildUpdatedRunstats(scan.runstats, filtered),
  };
}
