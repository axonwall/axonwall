import promClient from 'prom-client';
import { compileNftables, compileSatelliteNftables } from '@axonwall/lib/compile/nft';
import { lintRuleset } from '@axonwall/lib/lint';
import type { DesiredState } from '@axonwall/lib/schemas';
import * as crypto from 'node:crypto';

export interface CompiledBundle {
  jobId: string;
  bundleHash: string;
  nftScript: string;
  files: { path: string, content: string, fileMode: number }[];
  reloadServices: string[];
  warnings: string[];
  generatedAt: string;
}

export function buildArtifactBundle(jobId: string, state: DesiredState): CompiledBundle {
  // 1. Run linter
  const issues = lintRuleset(state);
  const warnings = issues.map((i) => `[${i.severity.toUpperCase()}] ${i.message}`);

  // 2. Compile to atomic nftables ruleset
  const { nftScript, files, reloadServices } = compileNftables(state);

  // 3. Compute deterministic bundle hash
  const hash = crypto.createHash('sha256').update(nftScript).digest('hex');

  return {
    jobId,
    bundleHash: hash,
    nftScript,
    files,
    reloadServices,
    warnings,
    generatedAt: new Date().toISOString(),
  };
}

import { WebSocketServer, WebSocket } from 'ws';
import * as http from 'node:http';
import * as https from 'node:https';
import * as fs from 'node:fs';
import { listUsers, createUser, createPreAuthKey } from './headscale.js';


async function main() {
  console.log('[Axonwall Controller] Starting Axonwall Control Plane Worker...');
  console.log('[Axonwall Controller] Monitoring config changes and apply pipeline.');

  // In-memory fleet registry of active satellites
  interface SatelliteState {
    id: string;
    connectedAt: string;
    lastSeen: string;
    ip?: string;
    arch?: string;
    wgPrivateKey?: string;
    wgPublicKey?: string;
    tunnelIp?: string;
    ws?: WebSocket;
    metrics?: {
      uptimeSeconds: number;
      cpuUsagePercent: number;
      memUsagePercent: number;
      activeConns: number;
      rxBytesTotal: number;
      txBytesTotal: number;
    };
  }

  const activeSatellites = new Map<string, SatelliteState>();

// Prometheus Metrics Definition
const prometheusRegistry = new promClient.Registry();
promClient.collectDefaultMetrics({ register: prometheusRegistry });

const satUptimeGauge = new promClient.Gauge({
  name: 'axonwall_satellite_uptime_seconds',
  help: 'Uptime of the satellite node in seconds',
  labelNames: ['satellite_id'],
  registers: [prometheusRegistry]
});

const satCpuGauge = new promClient.Gauge({
  name: 'axonwall_satellite_cpu_usage_percent',
  help: 'CPU usage of the satellite node',
  labelNames: ['satellite_id'],
  registers: [prometheusRegistry]
});

const satMemGauge = new promClient.Gauge({
  name: 'axonwall_satellite_memory_usage_percent',
  help: 'Memory usage of the satellite node',
  labelNames: ['satellite_id'],
  registers: [prometheusRegistry]
});

const satConnsGauge = new promClient.Gauge({
  name: 'axonwall_satellite_active_connections',
  help: 'Number of active netfilter tracked connections',
  labelNames: ['satellite_id'],
  registers: [prometheusRegistry]
});

const satRxBytesGauge = new promClient.Counter({
  name: 'axonwall_satellite_rx_bytes_total',
  help: 'Total received bytes on the satellite',
  labelNames: ['satellite_id'],
  registers: [prometheusRegistry]
});

const satTxBytesGauge = new promClient.Counter({
  name: 'axonwall_satellite_tx_bytes_total',
  help: 'Total transmitted bytes on the satellite',
  labelNames: ['satellite_id'],
  registers: [prometheusRegistry]
});

// A local tracker to help track monotonic counters without errors when re-setting
const lastRxTxBytes = new Map<string, {rx: number, tx: number}>();


  // Set up an HTTP server for WebSocket upgrades and REST queries
  
  
  const certPath = '/etc/axonwall/certs/hub.crt';
  const keyPath = '/etc/axonwall/certs/hub.key';
  const caPath = '/etc/axonwall/certs/ca.crt';

  const uiPort = parseInt(process.env.UI_PORT || '3000', 10);
  let server;
  const requestHandler = (req: any, res: any) => {
    const { pathname } = new URL(req.url || '', `http://${req.headers.host}`);

    
    if (pathname === '/metrics' && req.method === 'GET') {
      prometheusRegistry.metrics().then((metricsStr) => {
        res.writeHead(200, { 'Content-Type': prometheusRegistry.contentType });
        res.end(metricsStr);
      });
      return;
    }

    
    if (pathname === '/api/v1/fleet/block' && req.method === 'POST') {
      let body = '';
      req.on('data', (chunk: any) => body += chunk.toString());
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          const target = payload.target;
          const isMac = payload.isMac || false;
          
          if (!target) {
            res.writeHead(400);
            return res.end(JSON.stringify({ error: 'Missing target' }));
          }

          console.log(`[Fleet Manager] AI Copilot requested global block for: ${target} (isMac: ${isMac})`);

          let count = 0;
          for (const sat of activeSatellites.values()) {
            if (sat.ws && sat.ws.readyState === WebSocket.OPEN) {
              sat.ws.send(JSON.stringify({
                type: 'BLOCK_TARGET',
                payload: { target, isMac }
              }));
              count++;
            }
          }

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, notifiedSatellites: count }));
        } catch (err) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
      });
      return;
    }

    if (pathname === '/api/v1/fleet/satellites' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      // Exclude ws from JSON
      const satellitesData = Array.from(activeSatellites.values()).map(s => {
        const { ws, ...rest } = s;
        return rest;
      });
      res.end(JSON.stringify({
        totalConnected: activeSatellites.size,
        satellites: satellitesData,
      }));
      return;
    }

    // Reverse proxy all other HTTP traffic to the Axonwall Web Console on port 3000
    const uiReq = http.request({
      hostname: '127.0.0.1',
      port: uiPort,
      path: req.url,
      method: req.method,
      headers: {
        ...req.headers,
        'x-forwarded-proto': req.socket?.encrypted ? 'https' : 'http',
        'x-forwarded-host': req.headers.host,
        'x-forwarded-for': req.socket?.remoteAddress || '127.0.0.1',
      },
    }, (uiRes) => {
      res.writeHead(uiRes.statusCode || 200, uiRes.headers);
      uiRes.pipe(res);
    });

    req.on('aborted', () => uiReq.destroy());

    uiReq.on('error', () => {
      // If the upstream died mid-response, headers are already sent: writeHead would throw
      // and crash the whole controller (and every satellite connection with it).
      if (res.headersSent) {
        res.destroy();
        return;
      }
      res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!DOCTYPE html>
<html>
<head><title>Axonwall Appliance - Initializing</title>
<meta http-equiv="refresh" content="3">
<style>
body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
.card { background: #1e293b; padding: 2.5rem; border-radius: 12px; border: 1px solid #334155; text-align: center; max-width: 480px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); }
h1 { color: #38bdf8; margin: 0 0 1rem 0; font-size: 1.5rem; }
p { color: #94a3b8; font-size: 0.95rem; line-height: 1.5; margin: 0 0 1.5rem 0; }
.spinner { border: 3px solid #334155; border-top: 3px solid #38bdf8; border-radius: 50%; width: 28px; height: 28px; animation: spin 1s linear infinite; margin: 0 auto; }
@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="card">
  <h1>Axonwall Web Console</h1>
  <p>The web management console is initializing. This page will refresh automatically...</p>
  <div class="spinner"></div>
</div>
</body>
</html>`);
    });

    req.pipe(uiReq);
  };

  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    console.log('[Axonwall Controller] Starting in SECURE mTLS mode');
    server = https.createServer({
      cert: fs.readFileSync(certPath),
      key: fs.readFileSync(keyPath),
      ca: fs.existsSync(caPath) ? fs.readFileSync(caPath) : undefined,
      requestCert: fs.existsSync(caPath),
      rejectUnauthorized: false
    }, requestHandler);
  } else {
    console.log('[Axonwall Controller] Starting in INSECURE HTTP mode');
    server = http.createServer(requestHandler);
  }

  const wss = new WebSocketServer({ noServer: true, maxPayload: 1048576 });

  server.on('upgrade', (request, socket, head) => {
    const { pathname } = new URL(request.url || '', `http://${request.headers.host}`);
    
    if (pathname === '/ws/satellite') {
      // Basic ZTP token validation
      const satId = request.headers['x-axonwall-satellite-id'] as string;
      const token = request.headers['x-axonwall-ztp-token'] as string;

      if (!satId || !token) {
        console.log(`[Fleet Manager] Rejected connection: missing ZTP headers`);
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }

      const expectedToken = process.env.AXONWALL_ZTP_TOKEN;
      if (!expectedToken && process.env.NODE_ENV === 'production') {
        console.log(`[Fleet Manager] Rejected connection: AXONWALL_ZTP_TOKEN not configured`);
        socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
        socket.destroy();
        return;
      }

      const tokenToMatch = expectedToken || 'dev-ztp-token';
      const isTokenValid = token.length === tokenToMatch.length &&
        crypto.timingSafeEqual(Buffer.from(token), Buffer.from(tokenToMatch));

      if (!isTokenValid) {
        console.log(`[Fleet Manager] Rejected connection: invalid ZTP token for ${satId}`);
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }

      // If a CA certificate is configured, enforce valid client certificate
      if (fs.existsSync(caPath)) {
        const tlsSocket = socket as any;
        if (!tlsSocket.authorized) {
          console.log(`[Fleet Manager] Rejected connection: unauthorized client TLS certificate for ${satId}`);
          socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
          socket.destroy();
          return;
        }
      }

      console.log(`[Fleet Manager] Satellite authenticated successfully: ${satId}`);

      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request, satId);
      });
    } else {
      const uiWsReq = http.request({
        hostname: '127.0.0.1',
        port: uiPort,
        path: request.url,
        method: request.method,
        headers: request.headers,
      });

      uiWsReq.on('upgrade', (uiRes, uiSocket, uiHead) => {
        const headerLines: string[] = [];
        for (let i = 0; i < uiRes.rawHeaders.length; i += 2) {
          headerLines.push(`${uiRes.rawHeaders[i]}: ${uiRes.rawHeaders[i + 1]}`);
        }
        socket.write(`HTTP/1.1 101 Switching Protocols\r\n${headerLines.join('\r\n')}\r\n\r\n`);
        if (uiHead && uiHead.length) socket.write(uiHead);
        if (head && head.length) uiSocket.write(head);
        uiSocket.on('error', () => socket.destroy());
        socket.on('error', () => uiSocket.destroy());
        uiSocket.pipe(socket);
        socket.pipe(uiSocket);
      });

      // Upstream refused the upgrade (e.g. 404): don't leave the client socket hanging
      uiWsReq.on('response', (uiRes) => {
        socket.end(`HTTP/1.1 ${uiRes.statusCode || 502} ${uiRes.statusMessage || 'Bad Gateway'}\r\n\r\n`);
        uiRes.resume();
      });

      uiWsReq.on('error', () => {
        socket.destroy();
      });

      uiWsReq.end();
    }
  });

  let ipCounter = 2; // Start from 10.99.0.2

  function broadcastMeshTopology() {
    console.log('[Fleet Manager] Computing and broadcasting full-mesh SD-WAN topology...');
    const allSats = Array.from(activeSatellites.values());

    for (const sat of allSats) {
      if (!sat.ws || sat.ws.readyState !== WebSocket.OPEN) continue;

      const peers = allSats
        .filter(p => p.id !== sat.id)
        .map(p => ({
          publicKey: p.wgPublicKey,
          endpoint: `${p.ip}:51820`, // Assuming they are reachable on their public IP on 51820
          allowedIps: `${p.tunnelIp!.split('/')[0]}/32`, // Only route their tunnel IP for the mesh
          keepAliveSec: 25,
        }));

      sat.ws.send(JSON.stringify({
        type: 'SYNC_WIREGUARD',
        payload: {
          interfaceName: 'wg-axon0',
          tunnelIp: sat.tunnelIp,
          listenPort: 51820,
          privateKey: sat.wgPrivateKey,
          peers: peers,
        }
      }));
    }
  }

  wss.on('connection', async (ws: WebSocket, request: http.IncomingMessage, satId: string) => {
    const remoteIp = request.socket.remoteAddress || '127.0.0.1';
    console.log(`[Fleet Manager] Satellite Enrolled & Connected: ${satId} from ${remoteIp}`);

    // In a real app we'd use libsodium, here we mock standard length base64 keys
    const mockPrivKey = crypto.randomBytes(32).toString('base64');
    const mockPubKey = crypto.randomBytes(32).toString('base64');

    const state: SatelliteState = {
      id: satId,
      connectedAt: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      ip: remoteIp.replace(/^::ffff:/, ''),
      arch: (request.headers['user-agent']?.includes('arm') ? 'arm64' : 'amd64'),
      wgPrivateKey: mockPrivKey,
      wgPublicKey: mockPubKey,
      tunnelIp: `10.99.0.${ipCounter++}/24`,
      ws: ws,
    };
    activeSatellites.set(satId, state);

    // 1. Headscale ZTP Identity Provisioning
    try {
      console.log(`[Fleet Manager] Provisioning Headscale PreAuthKey for ${satId}...`);
      let users = await listUsers();
      let satelliteUser = users.find((u: any) => u.name === 'satellites');
      if (!satelliteUser) {
        satelliteUser = await createUser('satellites');
      }

      // Generate a 1-hour ephemeral key
      const expiration = new Date(Date.now() + 60 * 60 * 1000).toISOString();
      const preAuthKey = await createPreAuthKey('satellites', false, true, expiration);

      ws.send(JSON.stringify({
        type: 'SYNC_HEADSCALE',
        payload: {
          serverUrl: process.env.HEADSCALE_EXTERNAL_URL || 'https://hub.axonwall.local',
          authKey: preAuthKey.key
        }
      }));
      console.log(`[Fleet Manager] Dispatched Headscale ZTP credentials to ${satId}`);
    } catch (err: any) {
      console.error(`[Fleet Manager] Failed to provision Headscale key for ${satId}: ${err.message}`);
    }

    // 2. Push initial compiled nftables ruleset
    const { nftScript } = compileSatelliteNftables(state);
    ws.send(JSON.stringify({
      type: 'SYNC_NFTABLES',
      payload: {
        script: nftScript
      }
    }));

    // 3. Broadcast mesh update to all satellites (including the new one)
    broadcastMeshTopology();

    ws.on('message', (message) => {
      state.lastSeen = new Date().toISOString();
      try {
        const text = message.toString();
        const parsed = JSON.parse(text);
        if (parsed.type === 'TELEMETRY_REPORT') {
          // payload was marshaled by Go, so parsed.payload is an array of bytes or object? Wait.
          // Wait, if Go does payloadBytes, err := json.Marshal(report)
          // and then msg := EnvelopeMessage { ... Payload: payloadBytes }
          // then env.Payload is actually a raw JSON object string or embedded object?
          // Since EnvelopeMessage.Payload is json.RawMessage, it writes literally as JSON object!
          // So parsed.payload is NOT a string. It's the parsed object itself.
          let report: any;
          if (typeof parsed.payload === 'string') {
              report = JSON.parse(parsed.payload);
          } else {
              report = parsed.payload;
          }
          state.metrics = report.metrics;
          console.log(`[Fleet Manager] Telemetry from ${satId}: CPU ${report.metrics.cpuUsagePercent?.toFixed(1)}% | RAM ${report.metrics.memUsagePercent?.toFixed(1)}% | Active Conns: ${report.metrics.activeConns}`);
          
          // Update Prometheus metrics
          satUptimeGauge.set({ satellite_id: satId }, report.metrics.uptimeSeconds || 0);
          satCpuGauge.set({ satellite_id: satId }, report.metrics.cpuUsagePercent || 0);
          satMemGauge.set({ satellite_id: satId }, report.metrics.memUsagePercent || 0);
          satConnsGauge.set({ satellite_id: satId }, report.metrics.activeConns || 0);
          
          // Handle counter increments safely
          const currentRx = report.metrics.rxBytesTotal || 0;
          const currentTx = report.metrics.txBytesTotal || 0;
          const last = lastRxTxBytes.get(satId) || { rx: 0, tx: 0 };
          
          if (currentRx >= last.rx) satRxBytesGauge.inc({ satellite_id: satId }, currentRx - last.rx);
          if (currentTx >= last.tx) satTxBytesGauge.inc({ satellite_id: satId }, currentTx - last.tx);
          
          lastRxTxBytes.set(satId, { rx: currentRx, tx: currentTx });
        }
      } catch {
        // Ping or non-JSON message
      }
    });

    ws.on('close', () => {
      console.log(`[Fleet Manager] Satellite Disconnected: ${satId}`);
      satUptimeGauge.remove({ satellite_id: satId });
      satCpuGauge.remove({ satellite_id: satId });
      satMemGauge.remove({ satellite_id: satId });
      satConnsGauge.remove({ satellite_id: satId });
      lastRxTxBytes.delete(satId);
      activeSatellites.delete(satId);
      broadcastMeshTopology();
    });
  });

  const port = parseInt(process.env.CONTROLLER_PORT || '2966', 10);
  server.listen(port, '0.0.0.0', () => {
    console.log(`[Axonwall Controller] Fleet Manager listening on 0.0.0.0:${port}`);
  });
}

if (process.env.NODE_ENV !== 'test') {
  main().catch((err) => {
    console.error('[Axonwall Controller] Fatal error:', err);
    process.exit(1);
  });
}
