import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import { DesiredStateSchema, type DesiredState } from '@axonwall/lib/schemas';
import { readCanonicalConfig } from './atomic-config.js';
import { readAgentToken, resolveControllerDirs } from './dev-paths.js';

export interface TelemetryBridgeTargets {
  vmImportUrl: string;
  vlInsertUrl: string;
  collectorIngestUrl: string;
  /** Primary fallback bearer token (kept for backward compatibility). */
  bearerToken: string;
  vmBearerToken: string;
  vlBearerToken: string;
  collectorBearerToken: string;
}

const MAX_INFLIGHT_BRIDGE_PUSHES = 16;
const MAX_BRIDGE_FLOWS = 500;
const MAX_BRIDGE_LOGS = 500;
let inFlightBridgePushes = 0;

async function withBridgeConcurrencyCap<T>(label: string, fallback: T, fn: () => Promise<T>): Promise<T> {
  if (inFlightBridgePushes >= MAX_INFLIGHT_BRIDGE_PUSHES) {
    warnThrottled(`cap-${label}`, `Dropping ${label} push: outbound concurrency cap (${MAX_INFLIGHT_BRIDGE_PUSHES}) reached`);
    return fallback;
  }
  inFlightBridgePushes++;
  try {
    return await fn();
  } finally {
    inFlightBridgePushes--;
  }
}

const PROTO_NAME_TO_NUM: Record<string, number> = {
  icmp: 1,
  igmp: 2,
  ipip: 4,
  tcp: 6,
  udp: 17,
  ipv6: 41,
  gre: 47,
  esp: 50,
  ah: 51,
  icmpv6: 58,
  'ipv6-icmp': 58,
  sctp: 132,
};

const PROTO_NUM_TO_NAME: Record<number, string> = {
  1: 'ICMP',
  2: 'IGMP',
  4: 'IPIP',
  6: 'TCP',
  17: 'UDP',
  41: 'IPv6',
  47: 'GRE',
  50: 'ESP',
  51: 'AH',
  58: 'ICMPv6',
  132: 'SCTP',
};

export function normalizeFlowProtocol(rawProto: unknown, rawProtoName?: unknown): { protocol: number; protocolName: string } {
  const customName = typeof rawProtoName === 'string' && rawProtoName.trim() ? rawProtoName.trim() : '';
  if (typeof rawProto === 'number' && Number.isInteger(rawProto) && rawProto >= 0 && rawProto <= 255) {
    return {
      protocol: rawProto,
      protocolName: customName || PROTO_NUM_TO_NAME[rawProto] || String(rawProto),
    };
  }
  const s = String(rawProto ?? '').trim().toLowerCase();
  if (/^\d+$/.test(s)) {
    const n = Math.min(255, Math.max(0, Number(s)));
    return {
      protocol: n,
      protocolName: customName || PROTO_NUM_TO_NAME[n] || String(n),
    };
  }
  const num = PROTO_NAME_TO_NUM[s] ?? 0;
  return {
    protocol: num,
    protocolName: customName || PROTO_NUM_TO_NAME[num] || (s ? s.toUpperCase() : 'OTHER'),
  };
}

const lastWarnByKey = new Map<string, number>();

function warnThrottled(key: string, msg: string): void {
  const now = Date.now();
  const prev = lastWarnByKey.get(key) || 0;
  if (now - prev >= 60_000) {
    lastWarnByKey.set(key, now);
    console.warn(`[Telemetry Bridge] ${msg}`);
  }
}

function escapePromLabel(val: string): string {
  return String(val ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\n/g, '\\n')
    .replace(/"/g, '\\"');
}

function normalizeVmImportUrl(raw: string): string {
  const clean = raw.trim().replace(/\/+$/, '');
  if (!clean) return '';
  if (clean.endsWith('/api/v1/import/prometheus')) return clean;
  if (clean.endsWith('/api/v1/write')) {
    return `${clean.slice(0, -'/api/v1/write'.length)}/api/v1/import/prometheus`;
  }
  return `${clean}/api/v1/import/prometheus`;
}

function normalizeVlInsertUrl(raw: string): string {
  const clean = raw.trim().replace(/\/+$/, '');
  if (!clean) return '';
  if (clean.endsWith('/insert/jsonline')) return clean;
  return `${clean}/insert/jsonline`;
}

let cachedStateEntry: {
  key: string;
  ino: bigint;
  mtimeNs: bigint;
  size: bigint;
  state: DesiredState | null;
} | null = null;

function statCacheSig(filePath: string): { ino: bigint; mtimeNs: bigint; size: bigint } | null {
  try {
    const st = fs.statSync(filePath, { bigint: true });
    return { ino: st.ino, mtimeNs: st.mtimeNs, size: st.size };
  } catch {
    return null;
  }
}

export function readCachedDesiredStateBestEffort(): DesiredState | null {
  try {
    const dirs = resolveControllerDirs();
    const mirrorPath = path.join(dirs.etcDir, 'state.json');
    const canonicalSig = statCacheSig(dirs.stateFile);
    const activeSig = canonicalSig ?? statCacheSig(mirrorPath);
    const cacheKey = `${dirs.stateFile}|${mirrorPath}|${canonicalSig ? 'c' : 'm'}`;
    if (
      activeSig &&
      cachedStateEntry &&
      cachedStateEntry.key === cacheKey &&
      cachedStateEntry.ino === activeSig.ino &&
      cachedStateEntry.mtimeNs === activeSig.mtimeNs &&
      cachedStateEntry.size === activeSig.size
    ) {
      return cachedStateEntry.state;
    }

    const loaded = readCanonicalConfig({
      canonicalPath: dirs.stateFile,
      mirrorPaths: [mirrorPath],
      parse: (raw) => {
        try {
          const parsed = DesiredStateSchema.safeParse(JSON.parse(raw));
          return parsed.success ? parsed.data : null;
        } catch {
          return null;
        }
      },
      label: 'state.json',
    });

    if (activeSig) {
      cachedStateEntry = {
        key: cacheKey,
        ino: activeSig.ino,
        mtimeNs: activeSig.mtimeNs,
        size: activeSig.size,
        state: loaded,
      };
    } else {
      cachedStateEntry = null;
    }
    return loaded;
  } catch {
    // Ignore read errors during telemetry forwarding
  }
  return null;
}

export function resolveControllerObservabilityTargets(stateOverride?: DesiredState | null): TelemetryBridgeTargets {
  const state = stateOverride !== undefined ? stateOverride : readCachedDesiredStateBestEffort();
  const obs = state?.observability;
  const offload = obs?.offload;
  const hubBase = offload?.hubUrl ? offload.hubUrl.trim().replace(/\/+$/, '') : '';

  const vmEnv =
    process.env.AXONWALL_VM_IMPORT_URL?.trim() ||
    process.env.AXONWALL_VM_REMOTE_WRITE_URL?.trim() ||
    process.env.VICTORIAMETRICS_URL?.trim() ||
    '';
  const vlEnv =
    process.env.AXONWALL_VL_INSERT_URL?.trim() ||
    process.env.VICTORIALOGS_URL?.trim() ||
    '';
  const collectorIngestUrl = process.env.AXONWALL_COLLECTOR_INGEST_URL?.trim() || '';
  const sharedEnvToken = process.env.AXONWALL_OBSERVABILITY_TOKEN?.trim() || '';
  const offloadToken = offload?.ingestToken?.trim() || '';

  const vmBearerToken =
    process.env.AXONWALL_VM_TOKEN?.trim() ||
    sharedEnvToken ||
    offloadToken ||
    obs?.victoriaMetrics?.bearerToken?.trim() ||
    '';
  const vlBearerToken =
    process.env.AXONWALL_VL_TOKEN?.trim() ||
    sharedEnvToken ||
    offloadToken ||
    obs?.victoriaLogs?.bearerToken?.trim() ||
    '';
  const collectorBearerToken =
    process.env.AXONWALL_COLLECTOR_TOKEN?.trim() ||
    sharedEnvToken ||
    offloadToken ||
    '';
  const bearerToken = vmBearerToken || vlBearerToken || collectorBearerToken || '';

  let vmImportUrl = vmEnv ? normalizeVmImportUrl(vmEnv) : '';
  if (!vmImportUrl) {
    if (obs?.victoriaMetrics?.enabled && obs.victoriaMetrics.url?.trim()) {
      vmImportUrl = normalizeVmImportUrl(obs.victoriaMetrics.url);
    } else if (offload?.enabled && offload.metrics?.enabled) {
      if (offload.metrics.remoteWriteUrl?.trim()) {
        vmImportUrl = normalizeVmImportUrl(offload.metrics.remoteWriteUrl);
      } else if (hubBase) {
        vmImportUrl = `${hubBase}/vm/api/v1/import/prometheus`;
      }
    }
  }

  let vlInsertUrl = vlEnv ? normalizeVlInsertUrl(vlEnv) : '';
  if (!vlInsertUrl) {
    if (obs?.victoriaLogs?.enabled && obs.victoriaLogs.url?.trim()) {
      vlInsertUrl = normalizeVlInsertUrl(obs.victoriaLogs.url);
    } else if (offload?.enabled && offload.logs?.enabled) {
      if (offload.logs.victoriaLogsUrl?.trim()) {
        vlInsertUrl = normalizeVlInsertUrl(offload.logs.victoriaLogsUrl);
      } else if (hubBase) {
        vlInsertUrl = `${hubBase}/vl/insert/jsonline`;
      }
    }
  }

  return {
    vmImportUrl,
    vlInsertUrl,
    collectorIngestUrl,
    bearerToken,
    vmBearerToken,
    vlBearerToken,
    collectorBearerToken,
  };
}

export function formatSatellitePromMetrics(
  satId: string,
  hostname: string,
  metrics: Record<string, any> | undefined,
  timestampMs = Date.now()
): string {
  const labels = `node_id="${escapePromLabel(satId)}",hostname="${escapePromLabel(hostname || satId)}",source="satellite"`;
  const lines: string[] = [];
  const push = (name: string, val: unknown) => {
    if (val === null || val === undefined || typeof val === 'boolean') return;
    if (typeof val === 'string' && val.trim() === '') return;
    const num = Number(val);
    if (Number.isFinite(num)) {
      lines.push(`${name}{${labels}} ${num} ${timestampMs}`);
    }
  };
  push('axonwall_up', 1);
  if (metrics && typeof metrics === 'object') {
    push('axonwall_cpu_usage_percent', metrics.cpuUsagePercent);
    push('axonwall_mem_usage_percent', metrics.memUsagePercent);
    push('axonwall_uptime_seconds', metrics.uptimeSeconds);
    push('axonwall_conntrack_entries', metrics.activeConns);
    push('axonwall_net_rx_bytes_total', metrics.rxBytesTotal);
    push('axonwall_net_tx_bytes_total', metrics.txBytesTotal);
  }
  return `${lines.join('\n')}\n`;
}

function postJsonViaUnixSocket(socketPath: string, reqPath: string, payload: unknown, agentToken: string): Promise<boolean> {
  if (!fs.existsSync(socketPath)) {
    return Promise.resolve(false);
  }
  const body = JSON.stringify(payload);
  return new Promise((resolve) => {
    const req = http.request(
      {
        socketPath,
        path: reqPath,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          ...(agentToken ? { 'X-Axonwall-Agent-Token': agentToken } : {}),
        },
        timeout: 3000,
      },
      (res) => {
        const statusCode = res.statusCode ?? 500;
        const ok = statusCode >= 200 && statusCode < 300;
        let respText = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          if (!ok && respText.length < 1024) {
            respText += chunk;
          }
        });
        res.on('end', () => {
          if (!ok) {
            warnThrottled(
              `sock-${reqPath}-status`,
              `${reqPath} over Unix socket returned HTTP ${statusCode}${respText ? `: ${respText.trim().slice(0, 256)}` : ''}`
            );
          }
          resolve(ok);
        });
      }
    );
    req.on('timeout', () => {
      warnThrottled(`sock-${reqPath}-timeout`, `${reqPath} over Unix socket timed out`);
      req.destroy();
      resolve(false);
    });
    req.on('error', (err) => {
      warnThrottled(`sock-${reqPath}-err`, `${reqPath} over Unix socket failed: ${err?.message || String(err)}`);
      resolve(false);
    });
    req.write(body);
    req.end();
  });
}

export async function bridgeSatelliteMetricsToVM(
  satId: string,
  hostname: string,
  metrics: Record<string, any> | undefined,
  opts?: { targets?: TelemetryBridgeTargets; fetchFn?: typeof fetch; stateOverride?: DesiredState | null }
): Promise<boolean> {
  const targets = opts?.targets ?? resolveControllerObservabilityTargets(opts?.stateOverride);
  if (!targets.vmImportUrl) return false;
  const token = targets.vmBearerToken || targets.bearerToken;
  const fetchImpl = opts?.fetchFn ?? fetch;
  const body = formatSatellitePromMetrics(satId, hostname, metrics);
  return withBridgeConcurrencyCap('vm-metrics', false, async () => {
    try {
      const res = await fetchImpl(targets.vmImportUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body,
        signal: AbortSignal.timeout(3000),
      });
      if (!res.ok) {
        warnThrottled('vm-status', `VM metrics push returned HTTP ${res.status}`);
        return false;
      }
      return true;
    } catch (err: any) {
      warnThrottled('vm-err', `VM metrics push failed: ${err?.message || String(err)}`);
      return false;
    }
  });
}

export async function bridgeSatelliteFlowsAndLogs(
  satId: string,
  hostname: string,
  exporterIp: string,
  batch: { timestamp?: number; flows?: any[]; firewallLogs?: any[] } | undefined,
  opts?: { targets?: TelemetryBridgeTargets; fetchFn?: typeof fetch; stateOverride?: DesiredState | null }
): Promise<{ flowsForwarded: boolean; logsForwarded: boolean }> {
  const targets = opts?.targets ?? resolveControllerObservabilityTargets(opts?.stateOverride);
  const fetchImpl = opts?.fetchFn ?? fetch;
  let flowsForwarded = false;
  let logsForwarded = false;

  const cleanExporterIp = String(exporterIp || '').trim().split('/')[0] || '';
  const fallbackFlowEndMs =
    typeof batch?.timestamp === 'number' && Number.isFinite(batch.timestamp) && batch.timestamp > 0
      ? batch.timestamp > 1e12
        ? Math.floor(batch.timestamp)
        : Math.floor(batch.timestamp * 1000)
      : Date.now();

  if (Array.isArray(batch?.flows) && batch.flows.length > 0) {
    const normalizedFlows = batch.flows
      .slice(0, MAX_BRIDGE_FLOWS)
      .filter((f) => f && typeof f === 'object')
      .map((f) => {
        const { protocol, protocolName } = normalizeFlowProtocol(f.protocol, f.protocolName);
        return {
          ...f,
          protocol,
          protocolName,
          srcPort: Math.max(0, Math.min(65535, Math.floor(Number(f.srcPort) || 0))),
          dstPort: Math.max(0, Math.min(65535, Math.floor(Number(f.dstPort) || 0))),
          bytes: Math.max(0, Math.floor(Number(f.bytes) || 0)),
          packets: Math.max(0, Math.floor(Number(f.packets) || 0)),
          flowEndMs: typeof f.flowEndMs === 'number' && f.flowEndMs > 0 ? f.flowEndMs : fallbackFlowEndMs,
          exporterIp: cleanExporterIp,
          hostId: satId,
          hostName: hostname || satId,
        };
      });

    if (normalizedFlows.length > 0) {
      const flowPayload = {
        nodeId: satId,
        hostname: hostname || satId,
        exporterIp: cleanExporterIp,
        flows: normalizedFlows,
      };
      if (targets.collectorIngestUrl) {
        const ingestUrl = targets.collectorIngestUrl.trim().replace(/\/+$/, '');
        const fullUrl = ingestUrl.endsWith('/v1/netflow/ingest-batch')
          ? ingestUrl
          : `${ingestUrl}/v1/netflow/ingest-batch`;
        const collectorToken = targets.collectorBearerToken || targets.bearerToken;
        flowsForwarded = await withBridgeConcurrencyCap('collector-flows', false, async () => {
          try {
            const res = await fetchImpl(fullUrl, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                ...(collectorToken ? { Authorization: `Bearer ${collectorToken}` } : {}),
              },
              body: JSON.stringify(flowPayload),
              signal: AbortSignal.timeout(3000),
            });
            if (!res.ok) {
              warnThrottled('flows-http-status', `Collector flow batch push returned HTTP ${res.status}`);
              return false;
            }
            return true;
          } catch (err: any) {
            warnThrottled('flows-http', `Collector flow batch push failed: ${err?.message || String(err)}`);
            return false;
          }
        });
      } else {
        const sock = resolveControllerDirs().agentSock;
        flowsForwarded = await withBridgeConcurrencyCap('sock-flows', false, () =>
          postJsonViaUnixSocket(
            sock,
            '/v1/netflow/ingest-batch',
            flowPayload,
            readAgentToken() || ''
          )
        );
      }
    }
  }

  if (Array.isArray(batch?.firewallLogs) && batch.firewallLogs.length > 0 && targets.vlInsertUrl) {
    const vlToken = targets.vlBearerToken || targets.bearerToken;
    const ndjson = batch.firewallLogs
      .slice(0, MAX_BRIDGE_LOGS)
      .map((entry) => {
        if (entry && typeof entry === 'object') {
          const ts = entry._time || entry.timestamp || new Date().toISOString();
          const msg =
            entry._msg ||
            entry.message ||
            `${entry.action || 'EVENT'} ${entry.srcIp || ''} -> ${entry.dstIp || ''}`.trim();
          return JSON.stringify({
            level: 'warn',
            ...entry,
            _time: ts,
            _msg: msg,
            node_id: satId,
            hostname: hostname || satId,
            source: 'satellite-firewall',
          });
        }
        return JSON.stringify({
          _time: new Date().toISOString(),
          _msg: String(entry ?? ''),
          node_id: satId,
          hostname: hostname || satId,
          source: 'satellite-firewall',
          level: 'info',
        });
      })
      .join('\n');

    logsForwarded = await withBridgeConcurrencyCap('vl-logs', false, async () => {
      try {
        const res = await fetchImpl(targets.vlInsertUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-ndjson',
            ...(vlToken ? { Authorization: `Bearer ${vlToken}` } : {}),
          },
          body: `${ndjson}\n`,
          signal: AbortSignal.timeout(3000),
        });
        if (!res.ok) {
          warnThrottled('vl-status', `VL log insert returned HTTP ${res.status}`);
          return false;
        }
        return true;
      } catch (err: any) {
        warnThrottled('vl-err', `VL log insert failed: ${err?.message || String(err)}`);
        return false;
      }
    });
  }

  return { flowsForwarded, logsForwarded };
}
