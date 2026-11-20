import { NextRequest } from 'next/server';
import http from 'node:http';

import { getAgentToken } from '@/server/agent-client';
import { getAgentApiSocketPath } from '@/server/dev-paths';
import { getSession } from '@/server/auth';

export async function GET(req: NextRequest) {
  // Live packet capture is privileged telemetry: require a console
  // session. This route proxies the daemon directly (it does not go
  // through a session-checked server/agent.ts helper), so the check
  // lives here -- it was the one API route missing it (audit A-06/B-10).
  const session = await getSession();
  if (!session || session.passwordChangeRequired) {
    return new Response(session?.passwordChangeRequired ? 'Forbidden: Password change required' : 'Unauthorized', {
      status: session?.passwordChangeRequired ? 403 : 401,
    });
  }
  if (!session.roles?.includes('admin')) {
    return new Response('Forbidden: Admin role required', { status: 403 });
  }

  const { searchParams } = new URL(req.url);
  const iface = searchParams.get('interface') || 'any';
  const filter = searchParams.get('filter') || '';
  const protocol = searchParams.get('protocol') || 'any';

  const encoder = new TextEncoder();

  let cleanup = () => {};

  const stream = new ReadableStream({
    start(controller) {
      let cleanedUp = false;
      let interval: NodeJS.Timeout | null = null;
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
        if (interval) {
          clearInterval(interval);
          interval = null;
        }
      };

      req.signal.addEventListener('abort', cleanup);

      // 1. Try proxying from axonwalld Unix socket
      const token = getAgentToken();
      unixReq = http.request(
        {
          socketPath: getAgentApiSocketPath(),
          path: `/v1/events/packets?interface=${encodeURIComponent(iface)}&protocol=${encodeURIComponent(protocol)}&filter=${encodeURIComponent(filter)}`,
          method: 'GET',
          headers: {
            Accept: 'text/event-stream',
            ...(token ? { 'X-Axonwall-Agent-Token': token } : {}),
          },
        },
        (res) => {
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
            // C5: daemon answered with an error — do NOT fabricate
            // traffic. Close the stream with an error event so the
            // flows page shows "live feed unavailable" instead of
            // invented hosts the operator could filter and export.
            sendDaemonError(controller);
          }
        }
      );

      unixReq.on('error', () => {
        // Daemon socket unreachable: same fail-closed error event,
        // never a simulated stream.
        if (!cleanedUp) {
          sendDaemonError(controller);
        }
      });

      unixReq.end();

      function sendDaemonError(ctrl: ReadableStreamDefaultController) {
        if (cleanedUp) return;
        try {
          ctrl.enqueue(
            encoder.encode(
              `event: error\ndata: ${JSON.stringify({
                error:
                  'Live packet feed unavailable: the axonwalld daemon is unreachable or returned an error. No traffic is shown.',
              })}\n\n`
            )
          );
        } catch {}
        cleanup();
        try {
          ctrl.close();
        } catch {}
      }
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
