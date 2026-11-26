import {
  ObservabilityConfigSchema,
  type DesiredState,
  type ObservabilityOffloadConfig,
} from '../../schemas/index.js';

export interface ObservabilityInterfaceMeta {
  name: string;
  device: string;
  role?: string;
  ipv4Address?: string;
}

export interface ObservabilityRuleMeta {
  id: string;
  description: string;
  action: 'pass' | 'block' | 'reject';
  interface: string;
}

export interface CompiledObservabilityBundle {
  nodeId: string;
  hostname: string;
  enabled: boolean;
  offload: ObservabilityOffloadConfig & {
    resolvedRemoteWriteUrl: string;
    resolvedVictoriaLogsUrl: string;
  };
  victoriaMetrics: {
    enabled: boolean;
    url: string;
    bearerToken?: string;
  };
  victoriaLogs: {
    enabled: boolean;
    url: string;
    bearerToken?: string;
  };
  clickhouse: {
    enabled: boolean;
    url: string;
    database: string;
    username: string;
    password?: string;
  };
  activeMitigation: {
    acceptRemoteBlocks: boolean;
    maxTtlSec: number;
    protectedCidrs: string[];
  };
  interfaces: ObservabilityInterfaceMeta[];
  firewallRules: Record<string, ObservabilityRuleMeta>;
}

/**
 * Compiles unified edge-to-central observability and telemetry shipping configuration
 * written to `/etc/axonwall/managed/observability_config.json`.
 */
export function compileObservabilityBundle(
  state?: Partial<DesiredState> | null,
): CompiledObservabilityBundle {
  const obs = ObservabilityConfigSchema.parse(state?.observability ?? {});
  const hostname = state?.system?.hostname || 'axonwall-edge';
  const offload = obs.offload ?? ObservabilityConfigSchema.shape.offload.unwrap().parse({});

  const nodeId = (offload.nodeId || state?.netflow?.nodeId || hostname).trim() || hostname;
  const hubBase = (offload.hubUrl || '').trim().replace(/\/+$/, '');

  const resolvedRemoteWriteUrl =
    offload.metrics.remoteWriteUrl?.trim() ||
    (obs.victoriaMetrics?.enabled && obs.victoriaMetrics.url
      ? `${obs.victoriaMetrics.url.replace(/\/+$/, '')}/api/v1/write`
      : hubBase
        ? `${hubBase}/vm/api/v1/write`
        : '');

  const resolvedVictoriaLogsUrl =
    offload.logs.victoriaLogsUrl?.trim() ||
    (obs.victoriaLogs?.enabled && obs.victoriaLogs.url
      ? `${obs.victoriaLogs.url.replace(/\/+$/, '')}/insert/jsonline`
      : hubBase
        ? `${hubBase}/vl/insert/jsonline`
        : '');

  const nfCh = state?.netflow?.storage?.clickhouse;
  const obsCh = obs.clickhouse;
  const clickhouse = {
    enabled: Boolean(nfCh?.enabled || obsCh?.enabled),
    url: nfCh?.enabled ? nfCh.url : obsCh?.url || 'http://127.0.0.1:8123',
    database: nfCh?.enabled ? nfCh.database : obsCh?.database || 'axonwall',
    username: nfCh?.enabled ? nfCh.username : obsCh?.username || 'admin',
    password: nfCh?.password || obsCh?.password,
  };

  const interfaces: ObservabilityInterfaceMeta[] = (state?.interfaces ?? [])
    .filter((i) => i.enabled)
    .map((i) => ({
      name: i.name,
      device: i.device || i.name,
      role: i.role,
      ipv4Address: i.ipv4Address,
    }));

  const firewallRules: Record<string, ObservabilityRuleMeta> = {};
  for (const r of state?.rules ?? []) {
    const prefix = (r.id || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 8);
    if (!prefix) continue;
    firewallRules[prefix] = {
      id: r.id || prefix,
      description: r.description || '',
      action: r.action,
      interface: r.interface,
    };
  }

  return {
    nodeId,
    hostname,
    enabled: Boolean(
      offload.enabled ||
        offload.metrics.exposeScrape ||
        obs.victoriaMetrics?.enabled ||
        obs.victoriaLogs?.enabled,
    ),
    offload: {
      ...offload,
      resolvedRemoteWriteUrl,
      resolvedVictoriaLogsUrl,
    },
    victoriaMetrics: {
      enabled: Boolean(obs.victoriaMetrics?.enabled),
      url: obs.victoriaMetrics?.url || 'http://127.0.0.1:8428',
      bearerToken: obs.victoriaMetrics?.bearerToken,
    },
    victoriaLogs: {
      enabled: Boolean(obs.victoriaLogs?.enabled),
      url: obs.victoriaLogs?.url || 'http://127.0.0.1:9428',
      bearerToken: obs.victoriaLogs?.bearerToken,
    },
    clickhouse,
    activeMitigation: {
      acceptRemoteBlocks: Boolean(offload.activeMitigation?.acceptRemoteBlocks),
      maxTtlSec: offload.activeMitigation?.maxTtlSec ?? 3600,
      protectedCidrs: offload.activeMitigation?.protectedCidrs ?? ['127.0.0.0/8', '10.8.0.0/24'],
    },
    interfaces,
    firewallRules,
  };
}
