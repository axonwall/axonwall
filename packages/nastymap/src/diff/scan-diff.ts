import type {
  HostDiff,
  HostPortDiff,
  NmapHost,
  NmapPort,
  NmapRun,
  NmapScanDiff,
} from '../types/nmap';

function compareHostPorts(portsA: NmapPort[], portsB: NmapPort[]): HostPortDiff[] {
  const mapA = new Map<number, NmapPort>();
  const mapB = new Map<number, NmapPort>();

  for (const p of portsA) mapA.set(p.portid, p);
  for (const p of portsB) mapB.set(p.portid, p);

  const allPortIds = Array.from(new Set([...mapA.keys(), ...mapB.keys()])).sort((a, b) => a - b);
  const diffs: HostPortDiff[] = [];

  for (const pid of allPortIds) {
    const pA = mapA.get(pid);
    const pB = mapB.get(pid);

    if (!pA && pB) {
      // Port was added in scan B
      diffs.push({
        portid: pid,
        protocol: pB.protocol,
        changeType: 'added',
        newPort: pB,
      });
    } else if (pA && !pB) {
      // Port was removed in scan B
      diffs.push({
        portid: pid,
        protocol: pA.protocol,
        changeType: 'removed',
        oldPort: pA,
      });
    } else if (pA && pB) {
      // Check if state, service, or version changed
      const stateChanged = pA.state !== pB.state;
      const serviceChanged = (pA.service?.name || '') !== (pB.service?.name || '');
      const versionChanged = (pA.service?.version || '') !== (pB.service?.version || '');

      if (stateChanged || serviceChanged || versionChanged) {
        diffs.push({
          portid: pid,
          protocol: pB.protocol,
          changeType: 'modified',
          oldPort: pA,
          newPort: pB,
        });
      } else {
        diffs.push({
          portid: pid,
          protocol: pB.protocol,
          changeType: 'unchanged',
          oldPort: pA,
          newPort: pB,
        });
      }
    }
  }

  return diffs;
}

/**
 * Compare two Nmap scans and produce a structured diff with summary statistics.
 */
export function compareNmapScans(scanA: NmapRun, scanB: NmapRun): NmapScanDiff {
  const mapA = new Map<string, NmapHost>();
  const mapB = new Map<string, NmapHost>();

  for (const h of scanA.hosts) {
    const key = h.ipv4 || h.ipv6 || h.id;
    mapA.set(key, h);
  }

  for (const h of scanB.hosts) {
    const key = h.ipv4 || h.ipv6 || h.id;
    mapB.set(key, h);
  }

  const allHostKeys = Array.from(new Set([...mapA.keys(), ...mapB.keys()]));

  const addedHosts: HostDiff[] = [];
  const removedHosts: HostDiff[] = [];
  const modifiedHosts: HostDiff[] = [];
  const unchangedHosts: HostDiff[] = [];

  let portsAddedCount = 0;
  let portsRemovedCount = 0;
  let portsModifiedCount = 0;

  for (const key of allHostKeys) {
    const hA = mapA.get(key);
    const hB = mapB.get(key);

    if (!hA && hB) {
      // Host added in scan B
      const portDiffs = compareHostPorts([], hB.ports);
      const addedPorts = portDiffs.filter((p) => p.changeType === 'added').length;
      portsAddedCount += addedPorts;

      addedHosts.push({
        ip: key,
        hostname: hB.primaryHostname,
        changeType: 'added',
        newStatus: hB.status.state,
        newOs: hB.primaryOs,
        portDiffs,
        newHost: hB,
      });
    } else if (hA && !hB) {
      // Host removed in scan B
      const portDiffs = compareHostPorts(hA.ports, []);
      const removedPorts = portDiffs.filter((p) => p.changeType === 'removed').length;
      portsRemovedCount += removedPorts;

      removedHosts.push({
        ip: key,
        hostname: hA.primaryHostname,
        changeType: 'removed',
        oldStatus: hA.status.state,
        oldOs: hA.primaryOs,
        portDiffs,
        oldHost: hA,
      });
    } else if (hA && hB) {
      const portDiffs = compareHostPorts(hA.ports, hB.ports);
      const hasPortChanges = portDiffs.some((p) => p.changeType !== 'unchanged');
      const statusChanged = hA.status.state !== hB.status.state;
      const osChanged = (hA.primaryOs || '') !== (hB.primaryOs || '');
      const latencyDeltaMs =
        hA.latencyMs !== undefined && hB.latencyMs !== undefined
          ? Math.round((hB.latencyMs - hA.latencyMs) * 100) / 100
          : undefined;

      for (const p of portDiffs) {
        if (p.changeType === 'added') portsAddedCount++;
        if (p.changeType === 'removed') portsRemovedCount++;
        if (p.changeType === 'modified') portsModifiedCount++;
      }

      const isModified = hasPortChanges || statusChanged || osChanged;

      const diffRecord: HostDiff = {
        ip: key,
        hostname: hB.primaryHostname || hA.primaryHostname,
        changeType: isModified ? 'modified' : 'unchanged',
        statusChanged,
        oldStatus: hA.status.state,
        newStatus: hB.status.state,
        osChanged,
        oldOs: hA.primaryOs,
        newOs: hB.primaryOs,
        portDiffs,
        latencyDeltaMs,
        oldHost: hA,
        newHost: hB,
      };

      if (isModified) {
        modifiedHosts.push(diffRecord);
      } else {
        unchangedHosts.push(diffRecord);
      }
    }
  }

  return {
    oldScan: scanA,
    newScan: scanB,
    addedHosts,
    removedHosts,
    modifiedHosts,
    unchangedHosts,
    summary: {
      totalHostsA: scanA.hosts.length,
      totalHostsB: scanB.hosts.length,
      hostsAdded: addedHosts.length,
      hostsRemoved: removedHosts.length,
      hostsModified: modifiedHosts.length,
      portsAdded: portsAddedCount,
      portsRemoved: portsRemovedCount,
      portsModified: portsModifiedCount,
    },
  };
}
