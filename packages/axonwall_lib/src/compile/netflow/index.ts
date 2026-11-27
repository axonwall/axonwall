import {
  NetFlowConfigSchema,
  type DesiredState,
  type NetFlowConfig,
} from '../../schemas/index.js';
import { isPluginEnabled } from '../../plugins/index.js';
import { isValidIPv4, isValidIPv6 } from '../../util/index.js';

export interface NetFlowInterfaceHint {
  name: string;
  device: string;
  role?: string;
  ipv4Address?: string;
}

export interface NetFlowStaticHostEntry {
  ip: string;
  hostname: string;
  source: 'dns-override' | 'dhcp-reservation';
}

export interface NetFlowThreatEntry {
  alias: string;
  entry: string;
}

export interface CompiledNetFlowBundle {
  enabled: boolean;
  mode: 'collector' | 'exporter' | 'both';
  nodeId: string;
  hubUrl: string;
  ingestToken: string;
  useHaMtls: boolean;
  tlsCaCert: string;
  tlsInsecureSkipVerify: boolean;
  buffer: {
    maxMemoryMB: number;
    diskSpoolEnabled: boolean;
    diskSpoolDir: string;
    diskSpoolMaxMB: number;
  };
  config: NetFlowConfig;
  localHostname: string;
  localInterfaces: NetFlowInterfaceHint[];
  staticHostMap: NetFlowStaticHostEntry[];
  k3sCidrs: {
    podCidr: string;
    serviceCidr: string;
    domain: string;
  };
  threatCidrs: NetFlowThreatEntry[];
  summary: {
    mode: 'collector' | 'exporter' | 'both';
    listenersCount: number;
    exportersCount: number;
    selfTargetsCount: number;
    replicatorTargetsCount: number;
    alertRulesCount: number;
    storageMode: 'local' | 'clickhouse' | 'hybrid';
  };
}

export interface NetFlowRecordView {
  id: string;
  timestamp: string;
  flowStartMs?: number;
  flowEndMs?: number;
  version: 'netflow5' | 'netflow9' | 'ipfix' | 'sflow5';
  exporterIp: string;
  exporterName?: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: number;
  protocolName: string;
  appName?: string;
  srcHost?: string;
  dstHost?: string;
  srcAsn?: number;
  srcOrg?: string;
  dstAsn?: number;
  dstOrg?: string;
  srcCountry?: string;
  dstCountry?: string;
  direction?: 'internal' | 'ingress' | 'egress' | 'transit';
  inIfIndex?: number;
  outIfIndex?: number;
  inIfName?: string;
  outIfName?: string;
  vlanId?: number;
  bytes: number;
  packets: number;
  bps: number;
  pps?: number;
  tcpFlags?: number;
  tcpFlagsStr?: string;
  tos?: number;
  dscp?: number;
  postNatSrcIp?: string;
  postNatDstIp?: string;
  postNatSrcPort?: number;
  postNatDstPort?: number;
  srcMac?: string;
  dstMac?: string;
  k3sNamespace?: string;
  k3sWorkload?: string;
  k3sPodName?: string;
  k3sServiceName?: string;
  srcCity?: string;
  dstCity?: string;
  srcLat?: number;
  srcLon?: number;
  dstLat?: number;
  dstLon?: number;
  peerAs?: number;
  asPath?: number[];
  bgpNextHop?: string;
  rttMs?: number;
  retransmits?: number;
  hostId?: string;
  hostName?: string;
  threatMatch?: string;
  samplingRate?: number;
}

export const KNOWN_FQL_FIELDS = new Set([
  'src',
  'dst',
  'ip',
  'src_ip',
  'dst_ip',
  'src_port',
  'dst_port',
  'port',
  'proto',
  'protocol',
  'app',
  'exporter',
  'exporter_ip',
  'in_if',
  'out_if',
  'if',
  'vlan',
  'bytes',
  'packets',
  'pkts',
  'bps',
  'pps',
  'asn',
  'country',
  'city',
  'peer_as',
  'as_path',
  'direction',
  'dir',
  'tcp_flags',
  'flags',
  'tos',
  'dscp',
  'threat',
  'post_nat_src',
  'post_nat_dst',
  'post_nat_sport',
  'post_nat_dport',
  'k3s_ns',
  'k3s_workload',
  'k3s_pod',
  'rtt_ms',
  'retransmits',
  'host',
  'host_id',
  'node',
  'node_id',
  'version',
]);

export interface FqlValidationResult {
  valid: boolean;
  error?: string;
  normalized: string;
  clausesCount: number;
}

/**
 * Resolves effective NetFlow Collector configuration merged with plugin enablement state
 * and seamlessly carries forward legacy `observability.flowExport` targets when configured.
 */
export function resolveNetFlowConfig(state?: Partial<DesiredState> | null): NetFlowConfig {
  const parsed = NetFlowConfigSchema.parse(state?.netflow ?? {});
  const offload = state?.observability?.offload;
  const legacyExport = state?.observability?.flowExport;
  const offloadIpfixActive = Boolean(offload?.enabled && offload.ipfix?.enabled !== false);
  const legacyActive = Boolean(legacyExport?.enabled && legacyExport.collectorHost?.trim());

  const resolvedMode: 'collector' | 'exporter' | 'both' =
    state?.netflow?.mode ?? (offloadIpfixActive ? 'exporter' : 'both');

  const enabled =
    isPluginEnabled('netflow-collector', state) ||
    offloadIpfixActive ||
    legacyActive ||
    (resolvedMode === 'exporter' && parsed.selfExport.enabled);

  let listeners = parsed.listeners;
  let selfTargets = [...parsed.selfExport.targets];
  if (resolvedMode === 'exporter') {
    listeners = listeners.map((l) => ({ ...l, enabled: false }));
    selfTargets = selfTargets.filter((t) => t.id !== 'local-loopback-ipfix');
  }

  if (offloadIpfixActive && offload?.collectorHost?.trim()) {
    const collectorHost = offload.collectorHost.trim();
    const collectorPort = offload.collectorPort || 2055;
    const alreadyExists = selfTargets.some(
      (t) => t.id === 'edge-offload-ipfix' || (t.host === collectorHost && t.port === collectorPort),
    );
    if (!alreadyExists) {
      selfTargets.push({
        id: 'edge-offload-ipfix',
        name: `Edge Offload (${collectorHost}:${collectorPort})`,
        enabled: true,
        version: offload.ipfix?.version === 'netflow9' ? 'netflow9' : 'ipfix',
        host: collectorHost,
        port: collectorPort,
        transport: offload.ipfixTransport ?? 'udp',
        interfaces: offload.ipfix?.interfaces ?? [],
        activeTimeoutSec: offload.ipfix?.activeTimeoutSec ?? 15,
        inactiveTimeoutSec: 15,
        templateRefreshSec: 300,
        samplingRate: offload.ipfix?.samplingRate ?? 1,
        observationDomainId: 1,
        ...(offload.ipfixTransport === 'tls'
          ? {
              tls: {
                useHaPki: Boolean(offload.useHaMtls),
                caPath: offload.tlsCaCert || '',
                certPath: '',
                keyPath: '',
                requireClientCert: false,
                serverName: collectorHost,
                insecureSkipVerify: Boolean(offload.tlsInsecureSkipVerify),
              },
            }
          : {}),
      });
    }
  }

  if (legacyActive && legacyExport?.collectorHost?.trim()) {
    const legacyHost = legacyExport.collectorHost.trim();
    const legacyPort = legacyExport.collectorPort || 2055;
    const alreadyExists = selfTargets.some(
      (t) => t.host === legacyHost && t.port === legacyPort,
    );
    if (!alreadyExists) {
      selfTargets.push({
        id: 'legacy-observability-export',
        name: `Legacy Flow Export (${legacyHost}:${legacyPort})`,
        enabled: true,
        version: legacyExport.version === 'netflow9' ? 'netflow9' : 'ipfix',
        host: legacyHost,
        port: legacyPort,
        transport: 'udp',
        interfaces: legacyExport.interfaces ?? [],
        activeTimeoutSec: 60,
        inactiveTimeoutSec: 15,
        templateRefreshSec: 300,
        samplingRate: 1,
        observationDomainId: 1,
      });
    }
  }

  const baseSync = parsed.selfExport.metadataSync;
  const hubBase = (offload?.hubUrl || '').trim().replace(/\/+$/, '');
  const metadataSync =
    baseSync?.enabled
      ? baseSync
      : offloadIpfixActive && offload?.ipfix?.pushMetadata !== false && hubBase
        ? {
            enabled: true,
            targetUrl: `${hubBase}/api/v1/netflow/metadata-sync`,
            apiToken: offload?.ingestToken,
            intervalSec: baseSync?.intervalSec ?? 60,
          }
        : baseSync;

  return {
    ...parsed,
    enabled,
    mode: resolvedMode,
    nodeId: parsed.nodeId || offload?.nodeId || state?.system?.hostname,
    listeners,
    selfExport: {
      enabled: parsed.selfExport.enabled || offloadIpfixActive || Boolean(legacyExport?.enabled),
      targets: selfTargets,
      ...(metadataSync ? { metadataSync } : {}),
    },
  };
}

/**
 * Compiles the full runtime JSON bundle consumed by Axonwalld's NetFlowManager
 * at `/etc/axonwall/managed/netflow_config.json`.
 */
export function compileNetFlowBundle(state?: Partial<DesiredState> | null): CompiledNetFlowBundle {
  const config = resolveNetFlowConfig(state);
  const offload = state?.observability?.offload;
  const localHostname = state?.system?.hostname || 'axonwall-edge';
  const mode = config.mode ?? 'both';
  const nodeId = config.nodeId || offload?.nodeId || localHostname;

  const localInterfaces: NetFlowInterfaceHint[] = (state?.interfaces ?? []).map((ifc) => ({
    name: ifc.name,
    device: ifc.device || ifc.name,
    role: ifc.role,
    ipv4Address: ifc.ipv4Address,
  }));

  const staticHostMap: NetFlowStaticHostEntry[] = [];
  for (const ov of state?.dns?.hostOverrides ?? []) {
    if (ov.ip && ov.hostname) {
      staticHostMap.push({
        ip: ov.ip,
        hostname: ov.domain ? `${ov.hostname}.${ov.domain}` : ov.hostname,
        source: 'dns-override',
      });
    }
  }
  for (const sub of state?.dhcp?.subnets ?? []) {
    for (const res of sub.staticMappings ?? []) {
      if (res.ip && res.hostname) {
        staticHostMap.push({
          ip: res.ip,
          hostname: res.hostname,
          source: 'dhcp-reservation',
        });
      }
    }
  }

  const threatCidrs: NetFlowThreatEntry[] = [];
  for (const alias of state?.aliases ?? []) {
    if (!alias.enabled) continue;
    const text = `${alias.name} ${alias.description ?? ''}`.toLowerCase();
    const isThreat =
      text.includes('threat') ||
      text.includes('block') ||
      text.includes('blacklist') ||
      text.includes('malware') ||
      text.includes('drop') ||
      text.includes('botnet') ||
      text.includes('c2');
    if (isThreat && (alias.type === 'host' || alias.type === 'network' || alias.type === 'urltable')) {
      for (const entry of alias.entries ?? []) {
        if (entry.trim()) {
          threatCidrs.push({ alias: alias.name, entry: entry.trim() });
        }
      }
    }
  }

  return {
    enabled: config.enabled,
    mode,
    nodeId,
    hubUrl: (offload?.hubUrl || '').trim(),
    ingestToken: offload?.ingestToken || '',
    useHaMtls: Boolean(offload?.useHaMtls),
    tlsCaCert: offload?.tlsCaCert || '',
    tlsInsecureSkipVerify: Boolean(offload?.tlsInsecureSkipVerify),
    buffer: {
      maxMemoryMB: offload?.buffer?.maxMemoryMB ?? 24,
      diskSpoolEnabled: Boolean(offload?.buffer?.diskSpoolEnabled),
      diskSpoolDir: offload?.buffer?.diskSpoolDir || '/var/lib/axonwall/telemetry-spool',
      diskSpoolMaxMB: offload?.buffer?.diskSpoolMaxMB ?? 256,
    },
    config,
    localHostname,
    localInterfaces,
    staticHostMap,
    k3sCidrs: {
      podCidr: state?.k3s?.clusterCidr || '10.42.0.0/16',
      serviceCidr: state?.k3s?.serviceCidr || '10.43.0.0/16',
      domain: state?.system?.domain || 'cluster.local',
    },
    threatCidrs,
    summary: {
      mode,
      listenersCount: mode === 'exporter' ? 0 : config.listeners.filter((l) => l.enabled).length,
      exportersCount: config.exporterProfiles.length,
      selfTargetsCount: config.selfExport.enabled
        ? config.selfExport.targets.filter((t) => t.enabled).length
        : 0,
      replicatorTargetsCount: config.replicator.enabled
        ? config.replicator.targets.filter((t) => t.enabled).length
        : 0,
      alertRulesCount: config.alerting.enabled
        ? config.alerting.rules.filter((r) => r.enabled).length
        : 0,
      storageMode: config.storage.mode,
    },
  };
}

/**
 * Validates and tokenizes a Flow Query Language (FQL) expression prior to execution or saving.
 */
export function validateFqlQuery(raw: string): FqlValidationResult {
  const input = (raw || '').trim();
  if (!input) {
    return { valid: true, normalized: '', clausesCount: 0 };
  }

  let depth = 0;
  let clauses = 0;
  const tokens: string[] = [];
  let i = 0;

  while (i < input.length) {
    const ch = input[i]!;
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    if (ch === '(') {
      depth++;
      tokens.push('(');
      i++;
      continue;
    }
    if (ch === ')') {
      depth--;
      if (depth < 0) {
        return {
          valid: false,
          error: 'Unmatched closing parenthesis ")" in FQL expression.',
          normalized: input,
          clausesCount: clauses,
        };
      }
      tokens.push(')');
      i++;
      continue;
    }
    if (ch === '"' || ch === "'") {
      const quote = ch;
      let j = i + 1;
      while (j < input.length && input[j] !== quote) j++;
      if (j >= input.length) {
        return {
          valid: false,
          error: 'Unterminated quoted string in FQL expression.',
          normalized: input,
          clausesCount: clauses,
        };
      }
      tokens.push(input.slice(i, j + 1));
      i = j + 1;
      continue;
    }
    if (input.startsWith('&&', i) || input.startsWith('||', i) || input.startsWith('!=', i) || input.startsWith('>=', i) || input.startsWith('<=', i)) {
      tokens.push(input.slice(i, i + 2));
      i += 2;
      continue;
    }
    if (ch === '=' || ch === '>' || ch === '<' || ch === '~') {
      tokens.push(ch);
      i++;
      continue;
    }
    let j = i;
    while (j < input.length && !/[\s()=><!~&|'"]/.test(input[j]!)) j++;
    tokens.push(input.slice(i, j));
    i = j;
  }

  if (depth !== 0) {
    return {
      valid: false,
      error: 'Unclosed parenthesis "(" in FQL expression.',
      normalized: input,
      clausesCount: clauses,
    };
  }

  const ops = new Set(['=', '!=', '>', '>=', '<', '<=', '~']);
  const bools = new Set(['and', 'or', '&&', '||', 'not', '!']);
  for (let idx = 0; idx < tokens.length; idx++) {
    const t = tokens[idx]!;
    const lower = t.toLowerCase();
    if (t === '(' || t === ')' || bools.has(lower)) continue;
    if (ops.has(t)) {
      if (idx === 0 || idx === tokens.length - 1) {
        return {
          valid: false,
          error: `Operator "${t}" is missing a field or value.`,
          normalized: input,
          clausesCount: clauses,
        };
      }
      continue;
    }
    const next = tokens[idx + 1];
    if (next && ops.has(next)) {
      if (!KNOWN_FQL_FIELDS.has(lower)) {
        return {
          valid: false,
          error: `Unknown FQL field "${t}". Allowed fields: ${Array.from(KNOWN_FQL_FIELDS).slice(0, 12).join(', ')}, ...`,
          normalized: input,
          clausesCount: clauses,
        };
      }
      if (!tokens[idx + 2] || bools.has(tokens[idx + 2]!.toLowerCase())) {
        return {
          valid: false,
          error: `Field predicate "${t} ${next}" is missing a comparison value.`,
          normalized: input,
          clausesCount: clauses,
        };
      }
      clauses++;
      idx += 2; // consume field, op, value
    } else {
      // Shorthand keyword/IP search term
      clauses++;
    }
  }

  return {
    valid: true,
    normalized: tokens.join(' '),
    clausesCount: clauses,
  };
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = bytes;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  return `${u === 0 ? Math.round(v) : v.toFixed(1)} ${units[u]}`;
}

export function formatBps(bps: number): string {
  if (!Number.isFinite(bps) || bps <= 0) return '0 bps';
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
  let v = bps;
  let u = 0;
  while (v >= 1000 && u < units.length - 1) {
    v /= 1000;
    u++;
  }
  return `${u === 0 ? Math.round(v) : v.toFixed(1)} ${units[u]}`;
}

function escapeCsvCell(raw: string): string {
  let clean = String(raw ?? '').replace(/[\r\n]+/g, ' ');
  if (/^\s*[=+\-@\t\r]/.test(clean)) {
    clean = `'${clean}`;
  }
  if (clean.includes(',') || clean.includes('"')) {
    return `"${clean.replace(/"/g, '""')}"`;
  }
  return clean;
}

export function buildFlowExportCsv(flows: NetFlowRecordView[]): string {
  const header = [
    'Timestamp',
    'Version',
    'ExporterIP',
    'SrcIP',
    'SrcPort',
    'DstIP',
    'DstPort',
    'Protocol',
    'App',
    'Direction',
    'InIf',
    'OutIf',
    'VLAN',
    'Bytes',
    'Packets',
    'Bps',
    'SrcCountry',
    'DstCountry',
    'Threat',
  ].join(',');
  const rows = flows.map((f) =>
    [
      f.timestamp,
      f.version,
      f.exporterIp,
      f.srcIp,
      String(f.srcPort),
      f.dstIp,
      String(f.dstPort),
      f.protocolName,
      f.appName || '',
      f.direction || '',
      f.inIfName || String(f.inIfIndex ?? ''),
      f.outIfName || String(f.outIfIndex ?? ''),
      f.vlanId ? String(f.vlanId) : '',
      String(f.bytes),
      String(f.packets),
      String(Math.round(f.bps || 0)),
      f.srcCountry || '',
      f.dstCountry || '',
      f.threatMatch || '',
    ]
      .map(escapeCsvCell)
      .join(','),
  );
  return [header, ...rows].join('\n');
}

export function buildTcpdumpFilter(flow: NetFlowRecordView): string {
  const srcIp = String(flow.srcIp ?? '').trim();
  const dstIp = String(flow.dstIp ?? '').trim();
  if (!(isValidIPv4(srcIp) || isValidIPv6(srcIp))) {
    throw new Error(`Invalid source IP for tcpdump filter: ${flow.srcIp}`);
  }
  if (!(isValidIPv4(dstIp) || isValidIPv6(dstIp))) {
    throw new Error(`Invalid destination IP for tcpdump filter: ${flow.dstIp}`);
  }

  const parts: string[] = [];
  if (flow.protocol === 6) parts.push('tcp');
  else if (flow.protocol === 17) parts.push('udp');
  else if (flow.protocol === 1) parts.push('icmp');

  parts.push(`host ${srcIp} and host ${dstIp}`);
  const dstPort = Number(flow.dstPort);
  if ((flow.protocol === 6 || flow.protocol === 17) && Number.isInteger(dstPort) && dstPort >= 1 && dstPort <= 65535) {
    parts.push(`port ${dstPort}`);
  }
  return parts.join(' and ');
}
