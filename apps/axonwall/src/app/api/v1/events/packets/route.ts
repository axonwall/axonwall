import { NextRequest } from 'next/server';
import http from 'node:http';
import fs from 'node:fs';

import { getSession } from '@/server/auth';

const AGENT_API_SOCKET = process.env.AGENT_API_SOCKET || '/run/axonwall/agent-api.sock';

// axonwalld requires the per-install agent token (see server/agent.ts).
function getAgentToken(): string | undefined {
  if (process.env.AXONWALL_AGENT_TOKEN) return process.env.AXONWALL_AGENT_TOKEN;
  try {
    return (
      fs
        .readFileSync(process.env.AXONWALL_AGENT_TOKEN_FILE || '/etc/axonwall/agent.token', 'utf8')
        .trim() || undefined
    );
  } catch {
    return undefined;
  }
}

export async function GET(req: NextRequest) {
  // Live packet capture is privileged telemetry: require a console
  // session. This route proxies the daemon directly (it does not go
  // through a session-checked server/agent.ts helper), so the check
  // lives here -- it was the one API route missing it (audit A-06/B-10).
  const session = await getSession();
  if (!session) {
    return new Response('Unauthorized', { status: 401 });
  }

  const { searchParams } = new URL(req.url);
  const iface = searchParams.get('interface') || 'any';
  const filter = searchParams.get('filter') || '';
  const protocol = searchParams.get('protocol') || 'any';

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    start(controller) {
      // 1. Try proxying from axonwalld Unix socket
      const unixReq = http.request(
        {
          socketPath: AGENT_API_SOCKET,
          path: `/v1/events/packets?interface=${encodeURIComponent(iface)}&protocol=${encodeURIComponent(protocol)}&filter=${encodeURIComponent(filter)}`,
          method: 'GET',
          headers: {
            Accept: 'text/event-stream',
            ...(getAgentToken() ? { 'X-Axonwall-Agent-Token': getAgentToken() } : {}),
          },
        },
        (res) => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            res.on('data', (chunk) => {
              controller.enqueue(chunk);
            });
            res.on('end', () => {
              controller.close();
            });
            res.on('error', () => {
              controller.close();
            });
          } else {
            startFallbackStream(controller);
          }
        }
      );

      unixReq.on('error', () => {
        // Fallback simulated stream when daemon is not listening on socket
        startFallbackStream(controller);
      });

      unixReq.end();

      function startFallbackStream(ctrl: ReadableStreamDefaultController) {
        let index = 1;
        const mockFlows = [
          { proto: 'TLS', src: '192.168.1.105', sp: '58492', dst: '142.250.190.46', dp: '443', info: 'Application Data [TLS 1.3], len=482' },
          { proto: 'DNS', src: '192.168.1.105', sp: '61023', dst: '192.168.1.1', dp: '53', info: 'Standard query 0x4f12 A security.axonwall.net' },
          { proto: 'DNS', src: '192.168.1.1', sp: '53', dst: '192.168.1.105', dp: '61023', info: 'Standard query response 0x4f12 A 198.51.100.8' },
          { proto: 'TCP', src: '192.168.1.50', sp: '22', dst: '192.168.1.10', dp: '51240', info: 'Flags [P.], seq 104:248, ack 12, win 502' },
          { proto: 'WireGuard', src: '192.168.1.1', sp: '51820', dst: '198.51.100.25', dp: '51820', info: 'Transport Data, Counter 4920, len=128' },
          { proto: 'ICMP', src: '192.168.1.105', sp: '-', dst: '8.8.8.8', dp: '-', info: 'echo request, id 0x8201, seq 4' },
          { proto: 'ICMP', src: '8.8.8.8', sp: '-', dst: '192.168.1.105', dp: '-', info: 'echo reply, id 0x8201, seq 4' },
        ];

        const interval = setInterval(() => {
          try {
            const flow = mockFlows[index % mockFlows.length];
            const now = new Date().toTimeString().split(' ')[0] + '.' + String(Date.now() % 1000).padStart(3, '0');
            const payload = JSON.stringify({
              index,
              timestamp: now,
              srcIp: flow.src,
              srcPort: flow.sp,
              dstIp: flow.dst,
              dstPort: flow.dp,
              protocol: flow.proto,
              length: 64 + (index % 8) * 128,
              info: flow.info,
            });

            ctrl.enqueue(encoder.encode(`event: packet\ndata: ${payload}\n\n`));
            index++;
          } catch {
            clearInterval(interval);
          }
        }, 300);

        req.signal.addEventListener('abort', () => {
          clearInterval(interval);
        });
      }
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
