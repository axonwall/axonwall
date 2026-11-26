import type { DesiredState } from '@axonwall/lib/schemas';
import { callAgentApiDetailed } from './agent-client';
import { getDesiredStateInternal } from './desired-state-internal';

export interface ObservabilityEndpointInfo {
  configured: boolean;
  url: string;
  bearerToken?: string;
}

export interface ResolvedObservabilityEndpoints {
  victoriaMetrics: ObservabilityEndpointInfo;
  victoriaLogs: ObservabilityEndpointInfo;
  clickhouse: {
    configured: boolean;
    url: string;
  };
}

export interface VictoriaMetricsQueryResult {
  configured: boolean;
  unavailable: boolean;
  status: 'ok' | 'unconfigured' | 'error';
  resultType?: string;
  result?: any[];
  reason?: string;
}

export interface VictoriaLogsQueryResult {
  configured: boolean;
  unavailable: boolean;
  status: 'ok' | 'unconfigured' | 'error';
  entries: Array<Record<string, any>>;
  reason?: string;
}

export interface ObservabilityNodeSummary {
  nodeId: string;
  nodeName: string;
  exporterIp: string;
  flowsCount: number;
  lastSeenMs: number;
  metricsOnline?: boolean;
}

function stripTrailingSlash(url: string): string {
  return url.trim().replace(/\/+$/, '');
}

export function resolveObservabilityEndpoints(state?: DesiredState | null): ResolvedObservabilityEndpoints {
  const vmEnv = process.env.VICTORIAMETRICS_URL?.trim();
  const vmTokenEnv = process.env.VICTORIAMETRICS_TOKEN?.trim() || process.env.AXONWALL_OBSERVABILITY_TOKEN?.trim();
  const vlEnv = process.env.VICTORIALOGS_URL?.trim();
  const vlTokenEnv = process.env.VICTORIALOGS_TOKEN?.trim() || process.env.AXONWALL_OBSERVABILITY_TOKEN?.trim();
  const chEnvUrl = process.env.CLICKHOUSE_URL?.trim();

  const obs = state?.observability;
  const offload = obs?.offload;
  const hubBase = offload?.hubUrl ? stripTrailingSlash(offload.hubUrl) : '';

  let vmUrl = '';
  let vmToken = vmTokenEnv;
  if (vmEnv) {
    vmUrl = stripTrailingSlash(vmEnv);
  } else if (obs?.victoriaMetrics?.enabled && obs.victoriaMetrics.url?.trim()) {
    vmUrl = stripTrailingSlash(obs.victoriaMetrics.url);
    vmToken = obs.victoriaMetrics.bearerToken?.trim() || vmToken;
  } else if (offload?.enabled && offload.metrics?.enabled) {
    const rw = offload.metrics.remoteWriteUrl?.trim();
    if (rw) {
      vmUrl = stripTrailingSlash(rw.replace(/\/api\/v1\/write\/?$/, ''));
    } else if (hubBase) {
      vmUrl = `${hubBase}/vm`;
    }
    vmToken = offload.ingestToken?.trim() || vmToken;
  }

  let vlUrl = '';
  let vlToken = vlTokenEnv;
  if (vlEnv) {
    vlUrl = stripTrailingSlash(vlEnv);
  } else if (obs?.victoriaLogs?.enabled && obs.victoriaLogs.url?.trim()) {
    vlUrl = stripTrailingSlash(obs.victoriaLogs.url);
    vlToken = obs.victoriaLogs.bearerToken?.trim() || vlToken;
  } else if (offload?.enabled && offload.logs?.enabled) {
    const ins = offload.logs.victoriaLogsUrl?.trim();
    if (ins) {
      vlUrl = stripTrailingSlash(ins.replace(/\/insert\/jsonline\/?$/, ''));
    } else if (hubBase) {
      vlUrl = `${hubBase}/vl`;
    }
    vlToken = offload.ingestToken?.trim() || vlToken;
  }

  let chUrl = '';
  if (chEnvUrl) {
    chUrl = chEnvUrl;
  } else if (state?.netflow?.storage?.clickhouse?.enabled && state.netflow.storage.clickhouse.url?.trim()) {
    chUrl = state.netflow.storage.clickhouse.url.trim();
  } else if (obs?.clickhouse?.enabled && obs.clickhouse.url?.trim()) {
    chUrl = obs.clickhouse.url.trim();
  }

  return {
    victoriaMetrics: {
      configured: Boolean(vmUrl),
      url: vmUrl,
      ...(vmToken ? { bearerToken: vmToken } : {}),
    },
    victoriaLogs: {
      configured: Boolean(vlUrl),
      url: vlUrl,
      ...(vlToken ? { bearerToken: vlToken } : {}),
    },
    clickhouse: {
      configured: Boolean(chUrl),
      url: chUrl,
    },
  };
}

async function resolveStateOrDefault(state?: DesiredState | null): Promise<DesiredState | null> {
  if (state !== undefined) return state;
  return await getDesiredStateInternal().catch(() => null);
}

export async function queryVictoriaMetricsInstant(
  query: string,
  opts?: { state?: DesiredState | null; timeSec?: number; timeoutMs?: number }
): Promise<VictoriaMetricsQueryResult> {
  const trimmed = query.trim();
  if (!trimmed) {
    return { configured: true, unavailable: false, status: 'error', reason: 'Empty PromQL query.' };
  }
  const st = await resolveStateOrDefault(opts?.state);
  const { victoriaMetrics } = resolveObservabilityEndpoints(st);
  if (!victoriaMetrics.configured) {
    return {
      configured: false,
      unavailable: false,
      status: 'unconfigured',
      reason: 'VictoriaMetrics endpoint is not configured.',
    };
  }

  const params = new URLSearchParams({ query: trimmed });
  if (typeof opts?.timeSec === 'number' && Number.isFinite(opts.timeSec)) {
    params.set('time', String(Math.floor(opts.timeSec)));
  }

  try {
    const res = await fetch(`${victoriaMetrics.url}/api/v1/query?${params.toString()}`, {
      method: 'GET',
      headers: victoriaMetrics.bearerToken
        ? { Authorization: `Bearer ${victoriaMetrics.bearerToken}` }
        : undefined,
      signal: AbortSignal.timeout(opts?.timeoutMs ?? 5000),
      cache: 'no-store',
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return {
        configured: true,
        unavailable: true,
        status: 'error',
        reason: `VictoriaMetrics HTTP ${res.status}${text ? `: ${text.slice(0, 180)}` : ''}`,
      };
    }
    const body = (await res.json()) as { status?: string; data?: { resultType?: string; result?: any[] }; error?: string };
    if (body.status !== 'success') {
      return {
        configured: true,
        unavailable: false,
        status: 'error',
        reason: body.error || 'VictoriaMetrics query failed.',
      };
    }
    return {
      configured: true,
      unavailable: false,
      status: 'ok',
      resultType: body.data?.resultType,
      result: Array.isArray(body.data?.result) ? body.data.result : [],
    };
  } catch (err: any) {
    return {
      configured: true,
      unavailable: true,
      status: 'error',
      reason: err?.message || 'VictoriaMetrics unreachable.',
    };
  }
}

export async function queryVictoriaMetricsRange(
  query: string,
  startSec: number,
  endSec: number,
  stepSec: number,
  opts?: { state?: DesiredState | null; timeoutMs?: number }
): Promise<VictoriaMetricsQueryResult> {
  const trimmed = query.trim();
  if (!trimmed) {
    return { configured: true, unavailable: false, status: 'error', reason: 'Empty PromQL query.' };
  }
  const st = await resolveStateOrDefault(opts?.state);
  const { victoriaMetrics } = resolveObservabilityEndpoints(st);
  if (!victoriaMetrics.configured) {
    return {
      configured: false,
      unavailable: false,
      status: 'unconfigured',
      reason: 'VictoriaMetrics endpoint is not configured.',
    };
  }

  const safeStep = Math.max(5, Math.floor(stepSec || 60));
  const safeEnd = Math.floor(endSec || Date.now() / 1000);
  const safeStart = Math.min(safeEnd - safeStep, Math.floor(startSec || safeEnd - 3600));

  const params = new URLSearchParams({
    query: trimmed,
    start: String(safeStart),
    end: String(safeEnd),
    step: String(safeStep),
  });

  try {
    const res = await fetch(`${victoriaMetrics.url}/api/v1/query_range?${params.toString()}`, {
      method: 'GET',
      headers: victoriaMetrics.bearerToken
        ? { Authorization: `Bearer ${victoriaMetrics.bearerToken}` }
        : undefined,
      signal: AbortSignal.timeout(opts?.timeoutMs ?? 5000),
      cache: 'no-store',
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return {
        configured: true,
        unavailable: true,
        status: 'error',
        reason: `VictoriaMetrics HTTP ${res.status}${text ? `: ${text.slice(0, 180)}` : ''}`,
      };
    }
    const body = (await res.json()) as { status?: string; data?: { resultType?: string; result?: any[] }; error?: string };
    if (body.status !== 'success') {
      return {
        configured: true,
        unavailable: false,
        status: 'error',
        reason: body.error || 'VictoriaMetrics range query failed.',
      };
    }
    return {
      configured: true,
      unavailable: false,
      status: 'ok',
      resultType: body.data?.resultType,
      result: Array.isArray(body.data?.result) ? body.data.result : [],
    };
  } catch (err: any) {
    return {
      configured: true,
      unavailable: true,
      status: 'error',
      reason: err?.message || 'VictoriaMetrics unreachable.',
    };
  }
}

export async function queryVictoriaLogs(
  query: string,
  opts?: { state?: DesiredState | null; start?: string; end?: string; limit?: number; timeoutMs?: number }
): Promise<VictoriaLogsQueryResult> {
  const st = await resolveStateOrDefault(opts?.state);
  const { victoriaLogs } = resolveObservabilityEndpoints(st);
  if (!victoriaLogs.configured) {
    return {
      configured: false,
      unavailable: false,
      status: 'unconfigured',
      entries: [],
      reason: 'VictoriaLogs endpoint is not configured.',
    };
  }

  const limit = Math.max(1, Math.min(2000, Math.floor(opts?.limit ?? 200)));
  const form = new URLSearchParams({
    query: query.trim() || '*',
    limit: String(limit),
  });
  if (opts?.start?.trim()) form.set('start', opts.start.trim());
  if (opts?.end?.trim()) form.set('end', opts.end.trim());

  try {
    const res = await fetch(`${victoriaLogs.url}/select/logsql/query`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(victoriaLogs.bearerToken ? { Authorization: `Bearer ${victoriaLogs.bearerToken}` } : {}),
      },
      body: form.toString(),
      signal: AbortSignal.timeout(opts?.timeoutMs ?? 5000),
      cache: 'no-store',
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return {
        configured: true,
        unavailable: true,
        status: 'error',
        entries: [],
        reason: `VictoriaLogs HTTP ${res.status}${text ? `: ${text.slice(0, 180)}` : ''}`,
      };
    }
    const text = await res.text();
    const entries: Array<Record<string, any>> = [];
    for (const rawLine of text.split('\n')) {
      const line = rawLine.trim();
      if (!line) continue;
      try {
        const parsed = JSON.parse(line);
        if (parsed && typeof parsed === 'object') {
          entries.push(parsed as Record<string, any>);
        }
      } catch {
        // Skip malformed NDJSON line without dropping the response
      }
    }
    return {
      configured: true,
      unavailable: false,
      status: 'ok',
      entries,
    };
  } catch (err: any) {
    return {
      configured: true,
      unavailable: true,
      status: 'error',
      entries: [],
      reason: err?.message || 'VictoriaLogs unreachable.',
    };
  }
}

export async function fetchObservabilityNodes(
  state?: DesiredState | null
): Promise<ObservabilityNodeSummary[]> {
  const byId = new Map<string, ObservabilityNodeSummary>();

  const daemonRes = await callAgentApiDetailed<{ nodes?: ObservabilityNodeSummary[] }>(
    '/v1/netflow/nodes',
    'GET',
    undefined,
    3000
  ).catch(() => ({ kind: 'daemon_down' as const }));

  if (daemonRes.kind === 'ok' && Array.isArray(daemonRes.data?.nodes)) {
    for (const n of daemonRes.data.nodes) {
      const id = String(n.nodeId || n.nodeName || n.exporterIp || '').trim();
      if (!id) continue;
      byId.set(id, {
        nodeId: n.nodeId || id,
        nodeName: n.nodeName || n.nodeId || id,
        exporterIp: n.exporterIp || '',
        flowsCount: Number(n.flowsCount || 0),
        lastSeenMs: Number(n.lastSeenMs || 0),
      });
    }
  }

  const st = await resolveStateOrDefault(state);
  const vmRes = await queryVictoriaMetricsInstant('max by (node_id, hostname) (axonwall_up)', {
    state: st,
    timeoutMs: 2500,
  });
  if (vmRes.status === 'ok' && Array.isArray(vmRes.result)) {
    for (const series of vmRes.result) {
      const id = String(series?.metric?.node_id || '').trim();
      if (!id) continue;
      const hostname = String(series?.metric?.hostname || id).trim();
      const val = Number(series?.value?.[1] ?? 0);
      const tsSec = Number(series?.value?.[0] ?? 0);
      const existing = byId.get(id);
      if (existing) {
        existing.metricsOnline = val >= 1;
        if (!existing.nodeName && hostname) existing.nodeName = hostname;
        if (!existing.lastSeenMs && tsSec > 0) existing.lastSeenMs = Math.floor(tsSec * 1000);
      } else {
        byId.set(id, {
          nodeId: id,
          nodeName: hostname || id,
          exporterIp: '',
          flowsCount: 0,
          lastSeenMs: tsSec > 0 ? Math.floor(tsSec * 1000) : 0,
          metricsOnline: val >= 1,
        });
      }
    }
  }

  return Array.from(byId.values()).sort((a, b) => a.nodeName.localeCompare(b.nodeName));
}
