import { NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { callAgentApiDetailed } from '@/server/agent-client';
import { getDesiredStateInternal } from '@/server/desired-state-internal';
import { resolveObservabilityEndpoints } from '@/server/observability-clients';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  return 500;
}

export async function GET() {
  try {
    const session = await getSession();
    assertActionPermitted(session);

    const [daemonRes, state] = await Promise.all([
      callAgentApiDetailed<Record<string, unknown>>('/v1/observability/status', 'GET', undefined, 5000),
      getDesiredStateInternal().catch(() => null),
    ]);

    const resolved = resolveObservabilityEndpoints(state);
    const endpoints = {
      victoriaMetrics: {
        configured: resolved.victoriaMetrics.configured,
        url: resolved.victoriaMetrics.url,
        hasToken: Boolean(resolved.victoriaMetrics.bearerToken),
      },
      victoriaLogs: {
        configured: resolved.victoriaLogs.configured,
        url: resolved.victoriaLogs.url,
        hasToken: Boolean(resolved.victoriaLogs.bearerToken),
      },
      clickhouse: resolved.clickhouse,
    };

    if (daemonRes.kind === 'ok') {
      return NextResponse.json({
        status: 'ok',
        daemonDown: false,
        daemon: daemonRes.data,
        endpoints,
      });
    }

    return NextResponse.json({
      status: daemonRes.kind === 'http_error' ? 'error' : 'degraded',
      daemonDown: daemonRes.kind !== 'http_error',
      error: daemonRes.kind === 'http_error' ? daemonRes.message : 'axonwalld daemon unreachable',
      daemon: null,
      endpoints,
    });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to inspect observability status';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
