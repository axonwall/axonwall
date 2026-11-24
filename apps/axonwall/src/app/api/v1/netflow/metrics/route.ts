import http from 'node:http';
import { NextResponse } from 'next/server';
import { clearCachedAgentToken, getAgentToken } from '@/server/agent-client';
import { getAgentApiSocketPath } from '@/server/dev-paths';
import { getSession } from '@/server/auth';
import { isConsoleUser, isPasswordChangeEnforced } from '@/server/auth-guard';

export const dynamic = 'force-dynamic';

function fetchDaemonMetrics(canRetry401: boolean): Promise<{ status: number; body: string }> {
  return new Promise((resolve) => {
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
          resolve(fetchDaemonMetrics(false));
          return;
        }
        let body = '';
        res.on('data', (chunk) => {
          body += chunk;
        });
        res.on('end', () => {
          resolve({ status: res.statusCode || 500, body });
        });
      },
    );
    req.on('error', () => {
      resolve({ status: 503, body: '# axonwalld daemon unreachable\n' });
    });
    req.on('timeout', () => {
      req.destroy();
      resolve({ status: 504, body: '# metrics timeout\n' });
    });
    req.end();
  });
}

export async function GET() {
  const session = await getSession();
  const mustChange = isPasswordChangeEnforced(session);
  if (!session || mustChange) {
    return new NextResponse(mustChange ? 'Forbidden: Password change required' : 'Unauthorized', {
      status: mustChange ? 403 : 401,
    });
  }
  if (!isConsoleUser(session)) {
    return new NextResponse('Forbidden: Console role required', { status: 403 });
  }

  const res = await fetchDaemonMetrics(true);
  return new NextResponse(res.body, {
    status: res.status,
    headers: { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' },
  });
}
