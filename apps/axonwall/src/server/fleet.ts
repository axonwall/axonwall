'use server';

import * as http from 'node:http';
import * as https from 'node:https';
import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';
import { getAgentToken } from './agent-client';
import { getDesiredStateInternal } from './desired-state-internal';

export interface LiveFleetSatellite {
  id: string;
  role?: 'satellite' | 'edge-ngfw';
  skuProfile?: string;
  wanInterface?: string;
  lanInterface?: string;
  fastpathOffload?: boolean;
  ip?: string;
  arch?: string;
  tunnelIp?: string;
  wireguard?: { tunnelIp: string };
  connectedAt?: string;
  lastSeen?: string;
  disconnectedAt?: string;
  lastApplyError?: string;
  metrics?: {
    uptimeSeconds: number;
    cpuUsagePercent: number;
    memUsagePercent: number;
    activeConns: number;
    rxBytesTotal: number;
    txBytesTotal: number;
    pid1Mode?: boolean;
    kernelVersion?: string;
    skuProfile?: string;
  };
}

export interface FleetApiEnvelope<T> {
  reachable: boolean;
  status?: number;
  error?: string;
  data?: T;
}

async function resolveControllerConnection(): Promise<{ baseUrl: string; token: string }> {
  const envUrl = process.env.CONTROLLER_URL?.trim();
  const state = envUrl ? null : await getDesiredStateInternal().catch(() => null);
  const port = state?.fleet?.listenPort ?? 2966;
  const baseUrl = (envUrl || `https://127.0.0.1:${port}`).replace(/\/+$/, '');
  const token =
    process.env.AXONWALL_FLEET_TOKEN?.trim() ||
    process.env.AXONWALL_ZTP_TOKEN?.trim() ||
    getAgentToken() ||
    '';
  return { baseUrl, token };
}

function isLoopbackHost(hostname: string): boolean {
  const clean = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '');
  return clean === '127.0.0.1' || clean === 'localhost' || clean === '::1';
}

function requestControllerJson<T>(
  baseUrl: string,
  token: string,
  method: 'GET' | 'POST',
  reqPath: string,
  body?: unknown,
  timeoutMs = 4000
): Promise<FleetApiEnvelope<T>> {
  return new Promise((resolve) => {
    let parsed: URL;
    try {
      parsed = new URL(`${baseUrl}${reqPath}`);
    } catch (err: any) {
      resolve({ reachable: false, error: err?.message || 'Invalid controller URL' });
      return;
    }

    const payload = body !== undefined ? JSON.stringify(body) : undefined;
    const isHttps = parsed.protocol === 'https:';
    const headers: Record<string, string | number> = {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(payload
        ? {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
          }
        : {}),
    };

    const transport = isHttps ? https : http;
    const req = transport.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: `${parsed.pathname}${parsed.search}`,
        method,
        headers,
        timeout: timeoutMs,
        ...(isHttps && isLoopbackHost(parsed.hostname) ? { rejectUnauthorized: false } : {}),
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => {
          raw += chunk;
        });
        res.on('end', () => {
          const status = res.statusCode ?? 500;
          let json: any = null;
          try {
            json = raw ? JSON.parse(raw) : null;
          } catch {
            json = null;
          }
          if (status >= 200 && status < 300) {
            resolve({ reachable: true, status, data: json as T });
          } else {
            resolve({
              reachable: true,
              status,
              error: json?.error || json?.message || `Controller HTTP ${status}`,
              data: json as T,
            });
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({ reachable: false, error: 'Controller request timed out' });
    });
    req.on('error', (err: any) => {
      resolve({ reachable: false, error: err?.message || 'Controller unreachable' });
    });
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

export async function getLiveFleetSatellitesAction(): Promise<
  FleetApiEnvelope<{ satellites: LiveFleetSatellite[] }>
> {
  const session = await getSession();
  assertActionPermitted(session);
  const { baseUrl, token } = await resolveControllerConnection();
  const res = await requestControllerJson<LiveFleetSatellite[] | { satellites?: LiveFleetSatellite[] }>(
    baseUrl,
    token,
    'GET',
    '/api/v1/fleet/satellites'
  );
  if (!res.reachable || (res.status && res.status >= 400)) {
    return { reachable: res.reachable, status: res.status, error: res.error };
  }
  const satellites = Array.isArray(res.data)
    ? res.data
    : Array.isArray(res.data?.satellites)
      ? res.data.satellites
      : [];
  return { reachable: true, status: res.status, data: { satellites } };
}

export async function getLiveFleetFlowsAction(): Promise<FleetApiEnvelope<Record<string, unknown>>> {
  const session = await getSession();
  assertActionPermitted(session);
  const { baseUrl, token } = await resolveControllerConnection();
  return await requestControllerJson<Record<string, unknown>>(
    baseUrl,
    token,
    'GET',
    '/api/v1/fleet/flows'
  );
}

export async function triggerFleetSyncAction(
  nodeId?: string
): Promise<FleetApiEnvelope<{ syncedCount?: number; message?: string }>> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  const { baseUrl, token } = await resolveControllerConnection();
  return await requestControllerJson<{ syncedCount?: number; message?: string }>(
    baseUrl,
    token,
    'POST',
    '/api/v1/fleet/sync',
    nodeId ? { nodeId } : {}
  );
}

export async function blockFleetTargetAction(
  target: string,
  ttlSeconds = 300,
  reason = 'Fleet Operator XDP/NFT Block'
): Promise<FleetApiEnvelope<{ blockedCount?: number; message?: string }>> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  const { baseUrl, token } = await resolveControllerConnection();
  return await requestControllerJson<{ blockedCount?: number; message?: string }>(
    baseUrl,
    token,
    'POST',
    '/api/v1/fleet/block',
    { target: target.trim(), ttlSeconds, reason }
  );
}

export async function unblockFleetTargetAction(
  target: string,
  reason = 'Fleet Operator Unblock'
): Promise<FleetApiEnvelope<{ unblockedCount?: number; message?: string }>> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  const { baseUrl, token } = await resolveControllerConnection();
  return await requestControllerJson<{ unblockedCount?: number; message?: string }>(
    baseUrl,
    token,
    'POST',
    '/api/v1/fleet/unblock',
    { target: target.trim(), reason }
  );
}
