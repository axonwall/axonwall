import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DesiredStateSchema } from '@axonwall/lib/schemas';

vi.mock('../desired-state-internal', () => ({
  getDesiredStateInternal: vi.fn(async () => null),
}));

vi.mock('../agent-client', () => ({
  callAgentApiDetailed: vi.fn(async () => ({ kind: 'unreachable' })),
}));

import {
  fetchObservabilityNodes,
  queryVictoriaLogs,
  queryVictoriaMetricsInstant,
  queryVictoriaMetricsRange,
  resolveObservabilityEndpoints,
} from '../observability-clients';

describe('Observability Clients & Endpoint Resolution', () => {
  const origEnv = { ...process.env };
  const origFetch = globalThis.fetch;

  beforeEach(() => {
    delete process.env.VICTORIAMETRICS_URL;
    delete process.env.VICTORIAMETRICS_TOKEN;
    delete process.env.VICTORIALOGS_URL;
    delete process.env.VICTORIALOGS_TOKEN;
    delete process.env.AXONWALL_OBSERVABILITY_TOKEN;
    delete process.env.CLICKHOUSE_URL;
  });

  afterEach(() => {
    process.env = { ...origEnv };
    globalThis.fetch = origFetch;
    vi.restoreAllMocks();
  });

  it('resolves env > explicit VM/VL > hubUrl offload precedence cleanly', () => {
    const unconfigured = resolveObservabilityEndpoints(DesiredStateSchema.parse({}));
    expect(unconfigured.victoriaMetrics.configured).toBe(false);
    expect(unconfigured.victoriaLogs.configured).toBe(false);

    const fromHub = resolveObservabilityEndpoints(
      DesiredStateSchema.parse({
        observability: {
          offload: {
            enabled: true,
            hubUrl: 'https://analytics.internal/',
            ingestToken: 'axw_svc_hub_tok',
            metrics: { enabled: true },
            logs: { enabled: true },
          },
        },
      })
    );
    expect(fromHub.victoriaMetrics).toEqual({
      configured: true,
      url: 'https://analytics.internal/vm',
      bearerToken: 'axw_svc_hub_tok',
    });
    expect(fromHub.victoriaLogs).toEqual({
      configured: true,
      url: 'https://analytics.internal/vl',
      bearerToken: 'axw_svc_hub_tok',
    });

    process.env.VICTORIAMETRICS_URL = 'http://vm.k3s.local:8428/';
    process.env.VICTORIAMETRICS_TOKEN = 'env-token';
    const fromEnv = resolveObservabilityEndpoints(
      DesiredStateSchema.parse({
        observability: {
          victoriaMetrics: { enabled: true, url: 'http://other:8428', bearerToken: 'state-tok' },
        },
      })
    );
    expect(fromEnv.victoriaMetrics).toEqual({
      configured: true,
      url: 'http://vm.k3s.local:8428',
      bearerToken: 'env-token',
    });
  });

  it('queries VictoriaMetrics instant/range with bearer auth and degrades cleanly on failure', async () => {
    process.env.VICTORIAMETRICS_URL = 'http://vm.local:8428';
    process.env.VICTORIAMETRICS_TOKEN = 'vm-secret';

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      expect((init?.headers as Record<string, string>)?.Authorization).toBe('Bearer vm-secret');
      if (url.includes('/api/v1/query_range')) {
        return new Response(
          JSON.stringify({ status: 'success', data: { resultType: 'matrix', result: [{ metric: { node_id: 'edge-1' }, values: [[1700000000, '42.5']] }] } }),
          { status: 200 }
        );
      }
      return new Response(
        JSON.stringify({ status: 'success', data: { resultType: 'vector', result: [{ metric: { node_id: 'edge-1' }, value: [1700000000, '1'] }] } }),
        { status: 200 }
      );
    });
    globalThis.fetch = fetchMock as typeof fetch;

    const inst = await queryVictoriaMetricsInstant('axonwall_up', { state: null });
    expect(inst.status).toBe('ok');
    expect(inst.result).toHaveLength(1);

    const rng = await queryVictoriaMetricsRange('axonwall_cpu_usage_percent', 1700000000, 1700003600, 60, { state: null });
    expect(rng.status).toBe('ok');
    expect(rng.result?.[0]?.values?.[0]?.[1]).toBe('42.5');

    globalThis.fetch = vi.fn(async () => new Response('backend error', { status: 502 })) as typeof fetch;
    const errRes = await queryVictoriaMetricsInstant('axonwall_up', { state: null });
    expect(errRes.status).toBe('error');
    expect(errRes.unavailable).toBe(true);
    expect(errRes.reason).toContain('HTTP 502');
  });

  it('parses VictoriaLogs NDJSON safely and merges VM nodes in fetchObservabilityNodes', async () => {
    process.env.VICTORIALOGS_URL = 'http://vl.local:9428';
    process.env.VICTORIAMETRICS_URL = 'http://vm.local:8428';

    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/select/logsql/query')) {
        return new Response(
          '{"_time":"2026-11-25T12:00:00Z","_msg":"drop wan","node_id":"edge-1","source":"nflog"}\n{corrupt-json}\n{"_time":"2026-11-25T12:00:01Z","_msg":"dhcp ack","node_id":"edge-1","source":"kea"}\n',
          { status: 200 }
        );
      }
      return new Response(
        JSON.stringify({
          status: 'success',
          data: {
            resultType: 'vector',
            result: [{ metric: { node_id: 'edge-1', hostname: 'checkpoint1' }, value: [1700000000, '1'] }],
          },
        }),
        { status: 200 }
      );
    }) as typeof fetch;

    const logs = await queryVictoriaLogs('source:"nflog"', { state: null, limit: 50 });
    expect(logs.status).toBe('ok');
    expect(logs.entries).toHaveLength(2);
    expect(logs.entries[0].node_id).toBe('edge-1');

    const nodes = await fetchObservabilityNodes(null);
    expect(nodes).toEqual([
      {
        nodeId: 'edge-1',
        nodeName: 'checkpoint1',
        exporterIp: '',
        flowsCount: 0,
        lastSeenMs: 1700000000000,
        metricsOnline: true,
      },
    ]);
  });
});
