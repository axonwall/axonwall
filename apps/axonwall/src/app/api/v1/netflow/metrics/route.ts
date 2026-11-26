import http from 'node:http';
import { NextResponse } from 'next/server';
import { clearCachedAgentToken, getAgentToken } from '@/server/agent-client';
import { getAgentApiSocketPath } from '@/server/dev-paths';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { checkPluginApiGuard } from '@/server/plugin-guard';

export const dynamic = 'force-dynamic';

function fetchDaemonMetrics(canRetry401: boolean): Promise<{ status: number; body: string }> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (res: { status: number; body: string }) => {
      if (settled) return;
      settled = true;
      resolve(res);
    };

    const token = getAgentToken();
    const req = http.request(
      {
        socketPath: getAgentApiSocketPath(),
        path: '/v1/netflow/metrics',
        method: 'GET',
        headers: {
          Accept: 'text/plain; version=0.0.4',
          ...(token ? { 'X-Axonwall-Agent-Token': token } : {}),
        },
        timeout: 4_000,
      },
      (res) => {
        if (res.statusCode === 401 && canRetry401) {
          res.resume();
          clearCachedAgentToken();
          settled = true;
          resolve(fetchDaemonMetrics(false));
          return;
        }
        let body = '';
        res.on('data', (chunk) => {
          body += chunk;
        });
        res.on('error', () => {
          finish({ status: 503, body: '# metrics stream error\n' });
        });
        res.on('end', () => {
          finish({ status: res.statusCode || 500, body });
        });
      },
    );
    req.on('error', () => {
      finish({ status: 503, body: '# axonwalld daemon unreachable\n' });
    });
    req.on('timeout', () => {
      req.destroy();
      finish({ status: 504, body: '# metrics timeout\n' });
    });
    req.end();
  });
}

export async function GET() {
  try {
    const session = await getSession();
    assertActionPermitted(session);
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Unauthorized';
    const status = msg.includes('Unauthorized') ? 401 : 403;
    return new NextResponse(msg, { status });
  }
  const guard = await checkPluginApiGuard('netflow-collector');
  if (guard) return guard;

  const res = await fetchDaemonMetrics(true);
  return new NextResponse(res.body, {
    status: res.status,
    headers: { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' },
  });
}
