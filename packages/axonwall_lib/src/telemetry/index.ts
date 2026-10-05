export interface FlowRecord {
  timestamp: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'OTHER';
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  bytes: number;
  packets: number;
  action: 'pass' | 'drop';
  interface?: string;
}

export interface TalkerMetric {
  ip: string;
  bytes: number;
  packets: number;
}

export interface PortMetric {
  port: number;
  protocol: string;
  service: string;
  bytes: number;
}

export interface TimePointMetric {
  timestamp: number;
  ingressBytes: number;
  egressBytes: number;
}

export interface InsightReport {
  totalBytes: number;
  totalPackets: number;
  topTalkers: TalkerMetric[];
  topDestinations: TalkerMetric[];
  topPorts: PortMetric[];
  trafficOverTime: TimePointMetric[];
}

const COMMON_SERVICES: Record<number, string> = {
  22: 'SSH',
  53: 'DNS',
  80: 'HTTP',
  123: 'NTP',
  443: 'HTTPS',
  853: 'DNS-over-TLS',
  1194: 'OpenVPN',
  1812: 'RADIUS-Auth',
  1813: 'RADIUS-Acct',
  3000: 'Axonwall-GUI',
  51820: 'WireGuard',
  8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt',
};

export function serviceNameForPort(port: number): string {
  return COMMON_SERVICES[port] || `Port ${port}`;
}

/**
 * Aggregates raw flow records into an Insight flow report (Top Talkers, Top Destinations, Top Ports).
 */
export function aggregateFlows(flows: FlowRecord[]): InsightReport {
  let totalBytes = 0;
  let totalPackets = 0;

  const srcMap = new Map<string, { bytes: number; packets: number }>();
  const dstMap = new Map<string, { bytes: number; packets: number }>();
  const portMap = new Map<string, { port: number; protocol: string; bytes: number }>();
  const timeMap = new Map<number, { ingressBytes: number; egressBytes: number }>();

  for (const f of flows) {
    totalBytes += f.bytes;
    totalPackets += f.packets;

    // Source stats
    const src = srcMap.get(f.srcIp) || { bytes: 0, packets: 0 };
    src.bytes += f.bytes;
    src.packets += f.packets;
    srcMap.set(f.srcIp, src);

    // Destination stats
    const dst = dstMap.get(f.dstIp) || { bytes: 0, packets: 0 };
    dst.bytes += f.bytes;
    dst.packets += f.packets;
    dstMap.set(f.dstIp, dst);

    // Port stats
    const portKey = `${f.dstPort}/${f.protocol}`;
    const pEntry = portMap.get(portKey) || { port: f.dstPort, protocol: f.protocol, bytes: 0 };
    pEntry.bytes += f.bytes;
    portMap.set(portKey, pEntry);

    // Time-bucket stats (10-second buckets)
    const bucket = Math.floor(f.timestamp / 10000) * 10000;
    const tEntry = timeMap.get(bucket) || { ingressBytes: 0, egressBytes: 0 };
    // Heuristic: internal/LAN source is egress
    if (f.srcIp.startsWith('192.168.') || f.srcIp.startsWith('10.') || f.srcIp.startsWith('172.16.')) {
      tEntry.egressBytes += f.bytes;
    } else {
      tEntry.ingressBytes += f.bytes;
    }
    timeMap.set(bucket, tEntry);
  }

  const topTalkers = Array.from(srcMap.entries())
    .map(([ip, data]) => ({ ip, ...data }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 10);

  const topDestinations = Array.from(dstMap.entries())
    .map(([ip, data]) => ({ ip, ...data }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 10);

  const topPorts = Array.from(portMap.values())
    .map((p) => ({
      port: p.port,
      protocol: p.protocol,
      service: serviceNameForPort(p.port),
      bytes: p.bytes,
    }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 10);

  const trafficOverTime = Array.from(timeMap.entries())
    .map(([timestamp, data]) => ({ timestamp, ...data }))
    .sort((a, b) => a.timestamp - b.timestamp);

  return {
    totalBytes,
    totalPackets,
    topTalkers,
    topDestinations,
    topPorts,
    trafficOverTime,
  };
}
