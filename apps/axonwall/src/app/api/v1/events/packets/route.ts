import { NextRequest } from 'next/server';
import http from 'node:http';

import { clearCachedAgentToken, getAgentToken } from '@/server/agent-client';
import { getAgentApiSocketPath } from '@/server/dev-paths';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { checkPluginApiGuard } from '@/server/plugin-guard';

export async function GET(req: NextRequest) {
  // Live packet capture is privileged telemetry: require a console
  // session. This route proxies the daemon directly (it does not go
  // through a session-checked server/agent.ts helper), so the check
  // lives here -- it was the one API route missing it (audit A-06/B-10).
  const session = await getSession();
  try {
    assertActionPermitted(session, 'admin');
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unauthorized';
    return new Response(msg, { status: msg === 'Unauthorized' ? 401 : 403 });
  }
  const guard = await checkPluginApiGuard('packet-diagnostics');
  if (guard) return guard;

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

      // 1. Try proxying from axonwalld Unix socket (retry once on 401 after token rotation)
      const connect = (canRetry401: boolean) => {
        if (cleanedUp) return;
        const token = getAgentToken();
        const activeReq = http.request(
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
              // C5: daemon answered with an error — do NOT fabricate
              // traffic. Close the stream with an error event so the
              // flows page shows "live feed unavailable" instead of
              // invented hosts the operator could filter and export.
              res.resume();
              sendDaemonError(controller);
            }
          }
        );

        activeReq.on('error', () => {
          // Daemon socket unreachable: same fail-closed error event,
          // never a simulated stream.
          if (unixReq === activeReq && !cleanedUp) {
            sendDaemonError(controller);
          }
        });

        unixReq = activeReq;
        activeReq.end();
      };

      connect(true);

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
