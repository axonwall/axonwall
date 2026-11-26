import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DesiredStateSchema } from '@axonwall/lib/schemas';

const mockSsrfSafeFetch = vi.fn();

vi.mock('../desired-state-internal', () => ({
  getDesiredStateInternal: vi.fn(async () => null),
}));

vi.mock('../agent-client', () => ({
  callAgentApiDetailed: vi.fn(async () => ({ kind: 'unreachable' })),
}));

vi.mock('../ssrf-guard', () => ({
  ssrfSafeFetch: (...args: any[]) => mockSsrfSafeFetch(...args),
}));

import {
  fetchObservabilityNodes,
  queryVictoriaLogs,
  queryVictoriaMetricsInstant,
  queryVictoriaMetricsRange,
  resolveObservabilityEndpoints,
} from '../observability-clients';

function makeSsrfRes(body: string, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: '',
    headers: {},
    text: async () => body,
    json: async () => JSON.parse(body),
  };
}

describe('Observability Clients & Endpoint Resolution', () => {
  const origEnv = { ...process.env };

  beforeEach(() => {
    delete process.env.VICTORIAMETRICS_URL;
    delete process.env.VICTORIAMETRICS_TOKEN;
    delete process.env.VICTORIALOGS_URL;
    delete process.env.VICTORIALOGS_TOKEN;
    delete process.env.AXONWALL_OBSERVABILITY_TOKEN;
    delete process.env.CLICKHOUSE_URL;
    mockSsrfSafeFetch.mockReset();
  });

  afterEach(() => {
    process.env = { ...origEnv };
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

  it('does not leak hub ingestToken to cross-origin remoteWriteUrl or victoriaLogsUrl', () => {
    const crossOrigin = resolveObservabilityEndpoints(
      DesiredStateSchema.parse({
        observability: {
          offload: {
            enabled: true,
            hubUrl: 'https://analytics.internal/',
            ingestToken: 'axw_svc_hub_tok',
            metrics: { enabled: true, remoteWriteUrl: 'https://evil.example/api/v1/write' },
            logs: { enabled: true, victoriaLogsUrl: 'https://evil.example/insert/jsonline' },
          },
        },
      })
    );
    expect(crossOrigin.victoriaMetrics.bearerToken).toBeUndefined();
    expect(crossOrigin.victoriaLogs.bearerToken).toBeUndefined();
  });

  it('queries VictoriaMetrics instant/range with bearer auth and degrades cleanly on failure', async () => {
    process.env.VICTORIAMETRICS_URL = 'http://vm.local:8428';
    process.env.VICTORIAMETRICS_TOKEN = 'vm-secret';

    mockSsrfSafeFetch.mockImplementation(async (input: string, init?: { headers?: Record<string, string> }) => {
      expect(init?.headers?.Authorization).toBe('Bearer vm-secret');
      if (input.includes('/api/v1/query_range')) {
        return makeSsrfRes(
          JSON.stringify({ status: 'success', data: { resultType: 'matrix', result: [{ metric: { node_id: 'edge-1' }, values: [[1700000000, '42.5']] }] } }),
          200
        );
      }
      return makeSsrfRes(
        JSON.stringify({ status: 'success', data: { resultType: 'vector', result: [{ metric: { node_id: 'edge-1' }, value: [1700000000, '1'] }] } }),
        200
      );
    });

    const inst = await queryVictoriaMetricsInstant('axonwall_up', { state: null });
    expect(inst.status).toBe('ok');
    expect(inst.result).toHaveLength(1);

    const rng = await queryVictoriaMetricsRange('axonwall_host_cpu_usage_percent', 1700000000, 1700003600, 60, { state: null });
    expect(rng.status).toBe('ok');
    expect(rng.result?.[0]?.values?.[0]?.[1]).toBe('42.5');

    mockSsrfSafeFetch.mockResolvedValueOnce(makeSsrfRes('backend error', 502));
    const errRes = await queryVictoriaMetricsInstant('axonwall_up', { state: null });
    expect(errRes.status).toBe('error');
    expect(errRes.unavailable).toBe(true);
    expect(errRes.reason).toContain('HTTP 502');
  });

  it('parses VictoriaLogs NDJSON safely and merges VM nodes in fetchObservabilityNodes', async () => {
    process.env.VICTORIALOGS_URL = 'http://vl.local:9428';
    process.env.VICTORIAMETRICS_URL = 'http://vm.local:8428';

    mockSsrfSafeFetch.mockImplementation(async (input: string) => {
      if (input.includes('/select/logsql/query')) {
        return makeSsrfRes(
          '{"_time":"2026-11-25T12:00:00Z","_msg":"drop wan","node_id":"edge-1","source":"nflog"}\n{corrupt-json}\n{"_time":"2026-11-25T12:00:01Z","_msg":"dhcp ack","node_id":"edge-1","source":"kea"}\n',
          200
        );
      }
      return makeSsrfRes(
        JSON.stringify({
          status: 'success',
          data: {
            resultType: 'vector',
            result: [{ metric: { node_id: 'edge-1', hostname: 'checkpoint1' }, value: [1700000000, '1'] }],
          },
        }),
        200
      );
    });

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
