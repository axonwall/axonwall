import { compileNftables } from '@axonwall/lib/compile/nft';
import { lintRuleset } from '@axonwall/lib/lint';
import type { DesiredState } from '@axonwall/lib/schemas';
import * as crypto from 'node:crypto';

export interface CompiledBundle {
  jobId: string;
  bundleHash: string;
  nftScript: string;
  warnings: string[];
  generatedAt: string;
}

export function buildArtifactBundle(jobId: string, state: DesiredState): CompiledBundle {
  // 1. Run linter
  const issues = lintRuleset(state);
  const warnings = issues.map((i) => `[${i.severity.toUpperCase()}] ${i.message}`);

  // 2. Compile to atomic nftables ruleset
  const { nftScript } = compileNftables(state);

  // 3. Compute deterministic bundle hash
  const hash = crypto.createHash('sha256').update(nftScript).digest('hex');

  return {
    jobId,
    bundleHash: hash,
    nftScript,
    warnings,
    generatedAt: new Date().toISOString(),
  };
}

import { WebSocketServer, WebSocket } from 'ws';
import * as http from 'node:http';

async function main() {
  console.log('[Axonwall Controller] Starting Axonwall Control Plane Worker...');
  console.log('[Axonwall Controller] Monitoring config changes and apply pipeline.');

  // Set up an HTTP server for WebSocket upgrades
  const server = http.createServer((req, res) => {
    res.writeHead(200);
    res.end('Axonwall Control Plane\\n');
  });

  const wss = new WebSocketServer({ noServer: true });

  server.on('upgrade', (request, socket, head) => {
    const { pathname } = new URL(request.url || '', `http://${request.headers.host}`);
    
    if (pathname === '/ws/satellite') {
      // Basic ZTP token validation
      const satId = request.headers['x-axonwall-satellite-id'] as string;
      const token = request.headers['x-axonwall-ztp-token'] as string;

      if (!satId || !token) {
        console.log(`[Fleet Manager] Rejected connection: missing ZTP headers`);
        socket.write('HTTP/1.1 401 Unauthorized\\r\\n\\r\\n');
        socket.destroy();
        return;
      }

      // TODO: Validate token against a Supabase DB or config file
      console.log(`[Fleet Manager] Authenticating Satellite ID: ${satId} with token: ${token}`);

      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request, satId);
      });
    } else {
      socket.write('HTTP/1.1 404 Not Found\\r\\n\\r\\n');
      socket.destroy();
    }
  });

  wss.on('connection', (ws: WebSocket, request: http.IncomingMessage, satId: string) => {
    console.log(`[Fleet Manager] Satellite Enrolled & Connected: ${satId}`);
    
    // Simulate pushing an initial compiled nftables script
    ws.send(JSON.stringify({
      type: 'SYNC_NFTABLES',
      payload: {
        script: `
flush ruleset
table inet axonwall {
  chain input {
    type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    # Allow inbound WireGuard/SSH for management
    tcp dport 22 accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
}
        `
      }
    }));

    ws.on('message', (message) => {
      // Handle telemetry and heartbeats
      const size = Array.isArray(message) ? message[0].length : (message as Buffer).length;
      console.log(`[Fleet Manager] Received telemetry from ${satId}: ${size} bytes`);
    });

    ws.on('close', () => {
      console.log(`[Fleet Manager] Satellite Disconnected: ${satId}`);
    });
  });

  const port = process.env.CONTROLLER_PORT || 8443;
  server.listen(port, () => {
    console.log(`[Axonwall Controller] Fleet Manager listening on port ${port}`);
  });
}

if (process.env.NODE_ENV !== 'test') {
  main().catch((err) => {
    console.error('[Axonwall Controller] Fatal error:', err);
    process.exit(1);
  });
}
