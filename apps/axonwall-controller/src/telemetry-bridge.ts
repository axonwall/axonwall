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
  bearerToken: string;
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

function readLocalStateBestEffort(): DesiredState | null {
  try {
    const dirs = resolveControllerDirs();
    return readCanonicalConfig({
      canonicalPath: dirs.stateFile,
      mirrorPaths: [path.join(dirs.etcDir, 'state.json')],
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
  } catch {
    // Ignore read errors during telemetry forwarding
  }
  return null;
}

export function resolveControllerObservabilityTargets(stateOverride?: DesiredState | null): TelemetryBridgeTargets {
  const state = stateOverride !== undefined ? stateOverride : readLocalStateBestEffort();
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
  const bearerToken =
    process.env.AXONWALL_OBSERVABILITY_TOKEN?.trim() ||
    offload?.ingestToken?.trim() ||
    obs?.victoriaMetrics?.bearerToken?.trim() ||
    obs?.victoriaLogs?.bearerToken?.trim() ||
    '';

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
        res.resume();
        resolve((res.statusCode ?? 500) >= 200 && (res.statusCode ?? 500) < 300);
      }
    );
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.on('error', () => resolve(false));
    req.write(body);
    req.end();
  });
}

export async function bridgeSatelliteMetricsToVM(
  satId: string,
  hostname: string,
  metrics: Record<string, any> | undefined,
  opts?: { targets?: TelemetryBridgeTargets; fetchFn?: typeof fetch }
): Promise<boolean> {
  const targets = opts?.targets ?? resolveControllerObservabilityTargets();
  if (!targets.vmImportUrl) return false;
  const fetchImpl = opts?.fetchFn ?? fetch;
  const body = formatSatellitePromMetrics(satId, hostname, metrics);
  try {
    const res = await fetchImpl(targets.vmImportUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        ...(targets.bearerToken ? { Authorization: `Bearer ${targets.bearerToken}` } : {}),
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
}

export async function bridgeSatelliteFlowsAndLogs(
  satId: string,
  hostname: string,
  exporterIp: string,
  batch: { flows?: any[]; firewallLogs?: any[] } | undefined,
  opts?: { targets?: TelemetryBridgeTargets; fetchFn?: typeof fetch }
): Promise<{ flowsForwarded: boolean; logsForwarded: boolean }> {
  const targets = opts?.targets ?? resolveControllerObservabilityTargets();
  const fetchImpl = opts?.fetchFn ?? fetch;
  let flowsForwarded = false;
  let logsForwarded = false;

  if (Array.isArray(batch?.flows) && batch.flows.length > 0) {
    const flowPayload = {
      nodeId: satId,
      hostname: hostname || satId,
      exporterIp: exporterIp || '',
      flows: batch.flows,
    };
    if (targets.collectorIngestUrl) {
      const ingestUrl = targets.collectorIngestUrl.trim().replace(/\/+$/, '');
      const fullUrl = ingestUrl.endsWith('/v1/netflow/ingest-batch')
        ? ingestUrl
        : `${ingestUrl}/v1/netflow/ingest-batch`;
      try {
        const res = await fetchImpl(fullUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(targets.bearerToken ? { Authorization: `Bearer ${targets.bearerToken}` } : {}),
          },
          body: JSON.stringify(flowPayload),
          signal: AbortSignal.timeout(3000),
        });
        flowsForwarded = res.ok;
      } catch (err: any) {
        warnThrottled('flows-http', `Collector flow batch push failed: ${err?.message || String(err)}`);
      }
    } else {
      const sock = resolveControllerDirs().agentSock;
      flowsForwarded = await postJsonViaUnixSocket(
        sock,
        '/v1/netflow/ingest-batch',
        flowPayload,
        readAgentToken() || ''
      );
    }
  }

  if (Array.isArray(batch?.firewallLogs) && batch.firewallLogs.length > 0 && targets.vlInsertUrl) {
    const ndjson = batch.firewallLogs
      .map((entry) => {
        if (entry && typeof entry === 'object') {
          return JSON.stringify({
            _time: entry._time || entry.timestamp || new Date().toISOString(),
            _msg:
              entry._msg ||
              entry.message ||
              `${entry.action || 'EVENT'} ${entry.srcIp || ''} -> ${entry.dstIp || ''}`.trim(),
            node_id: satId,
            hostname: hostname || satId,
            source: 'satellite-firewall',
            level: entry.level || 'warn',
            ...entry,
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

    try {
      const res = await fetchImpl(targets.vlInsertUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-ndjson',
          ...(targets.bearerToken ? { Authorization: `Bearer ${targets.bearerToken}` } : {}),
        },
        body: `${ndjson}\n`,
        signal: AbortSignal.timeout(3000),
      });
      logsForwarded = res.ok;
      if (!res.ok) {
        warnThrottled('vl-status', `VL log insert returned HTTP ${res.status}`);
      }
    } catch (err: any) {
      warnThrottled('vl-err', `VL log insert failed: ${err?.message || String(err)}`);
    }
  }

  return { flowsForwarded, logsForwarded };
}
