import { NextRequest } from 'next/server';
import http from 'node:http';

import { clearCachedAgentToken, getAgentToken } from '@/server/agent-client';
import { getAgentApiSocketPath } from '@/server/dev-paths';
import { getSession } from '@/server/auth';
import { isPasswordChangeEnforced } from '@/server/auth-guard';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const session = await getSession();
  const mustChangePassword = isPasswordChangeEnforced(session);
  if (!session || mustChangePassword) {
    return new Response(
      mustChangePassword ? 'Forbidden: Password change required' : 'Unauthorized',
      { status: mustChangePassword ? 403 : 401 }
    );
  }

  const { searchParams } = new URL(req.url);
  const qs = new URLSearchParams();
  for (const key of ['namespace', 'name', 'resource', 'container', 'tail', 'previous', 'timestamps', 'sinceSeconds']) {
    const val = searchParams.get(key);
    if (val !== null && val !== '') {
      qs.set(key, val);
    }
  }

  const encoder = new TextEncoder();
  let cleanup = () => {};

  const stream = new ReadableStream({
    start(controller) {
      let cleanedUp = false;
      let unixReq: http.ClientRequest | null = null;

      cleanup = () => {
        if (cleanedUp) return;
        cleanedUp = true;
        if (unixReq) {
          try {
            unixReq.destroy();
          } catch {}
          unixReq = null;
        }
      };

      req.signal.addEventListener('abort', cleanup);

      const sendDaemonError = (msg: string) => {
        if (cleanedUp) return;
        try {
          controller.enqueue(
            encoder.encode(`event: error\ndata: ${JSON.stringify({ error: msg })}\n\n`)
          );
        } catch {}
        cleanup();
        try {
          controller.close();
        } catch {}
      };

      const connect = (canRetry401: boolean) => {
        if (cleanedUp) return;
        const token = getAgentToken();
        const activeReq = http.request(
          {
            socketPath: getAgentApiSocketPath(),
            path: `/v1/k3s/logs/stream?${qs.toString()}`,
            method: 'GET',
            headers: {
              Accept: 'text/event-stream',
              ...(token ? { 'X-Axonwall-Agent-Token': token } : {}),
            },
          },
          (res) => {
            if (res.statusCode === 401 && canRetry401 && !cleanedUp) {
              res.resume();
              clearCachedAgentToken();
              connect(false);
              return;
            }
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
              res.on('data', (chunk) => {
                if (cleanedUp) return;
                try {
                  controller.enqueue(chunk);
                } catch {
                  cleanup();
                }
              });
              res.on('end', () => {
                cleanup();
                try {
                  controller.close();
                } catch {}
              });
              res.on('error', () => {
                cleanup();
                try {
                  controller.close();
                } catch {}
              });
            } else {
              let errBody = '';
              res.on('data', (c) => {
                errBody += c.toString();
              });
              res.on('end', () => {
                sendDaemonError(
                  errBody.trim() || `K3s log stream returned HTTP ${res.statusCode || 500}`
                );
              });
            }
          }
        );

        activeReq.on('error', () => {
          if (unixReq === activeReq && !cleanedUp) {
            sendDaemonError('Live pod log stream unavailable: axonwalld daemon unreachable.');
          }
        });

        unixReq = activeReq;
        activeReq.end();
      };

      connect(true);
    },
    cancel() {
      cleanup();
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    },
  });
}
