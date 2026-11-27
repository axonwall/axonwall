import * as dns from 'node:dns';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as net from 'node:net';
import * as path from 'node:path';
import { DesiredStateSchema, type DesiredState } from '@axonwall/lib/schemas';
import { readCanonicalConfig } from './atomic-config.js';
import { readAgentToken, resolveControllerDirs } from './dev-paths.js';

export function isValidSatelliteId(satId: unknown): satId is string {
  return (
    typeof satId === 'string' &&
    /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/.test(satId) &&
    !satId.includes('..')
  );
}

function stripControlChars(val: string, maxLen = 256): string {
  return val.replace(/[\x00-\x1f\x7f]/g, '').slice(0, maxLen);
}

function toFiniteNonNegativeInt(val: unknown): number {
  if (val === null || val === undefined || typeof val === 'boolean') return 0;
  if (typeof val === 'string' && val.trim() === '') return 0;
  const n = Number(val);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
}

function clampPortNumber(val: unknown): number {
  const n = toFiniteNonNegativeInt(val);
  return Math.min(65535, n);
}

function sanitizeIpString(val: unknown): string {
  if (typeof val !== 'string') return '';
  const clean = val.trim();
  if (!clean || clean.length > 64) return '';
  return net.isIP(clean) !== 0 ? clean : '';
}

function parseIpv6Groups(rawIp: string): number[] | null {
  const zoneIdx = rawIp.indexOf('%');
  const ip = zoneIdx >= 0 ? rawIp.slice(0, zoneIdx) : rawIp;
  if (!net.isIPv6(ip)) return null;

  const parts = ip.split('::');
  if (parts.length > 2) return null;

  const parseSegment = (seg: string): number[] | null => {
    if (!seg) return [];
    const tokens = seg.split(':');
    const out: number[] = [];
    for (let i = 0; i < tokens.length; i++) {
      const tok = tokens[i]!;
      if (tok.includes('.')) {
        if (i !== tokens.length - 1 || !net.isIPv4(tok)) return null;
        const octets = tok.split('.').map(Number);
        out.push(((octets[0]! << 8) | octets[1]!) >>> 0, ((octets[2]! << 8) | octets[3]!) >>> 0);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(tok)) return null;
        out.push(parseInt(tok, 16));
      }
    }
    return out;
  };

  const head = parseSegment(parts[0] || '');
  if (!head) return null;
  if (parts.length === 1) {
    return head.length === 8 ? head : null;
  }
  const tail = parseSegment(parts[1] || '');
  if (!tail) return null;
  const fillCount = 8 - (head.length + tail.length);
  if (fillCount < 1) return null;
  return [...head, ...new Array<number>(fillCount).fill(0), ...tail];
}

function isDisallowedIpv4Octets(octets: number[]): boolean {
  const [a, b] = octets;
  if (a === undefined || b === undefined) return true;
  if (a === 0) return true; // 0.0.0.0/8 unspecified
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / IMDS
  if (a >= 224) return true; // multicast / reserved
  return false;
}

export function isDisallowedObservabilityIp(rawIp: string): boolean {
  const ip = rawIp.trim();
  if (!ip || ip.includes('%')) return true;
  if (net.isIPv4(ip)) {
    return isDisallowedIpv4Octets(ip.split('.').map(Number));
  }
  const g = parseIpv6Groups(ip);
  if (!g) return true;
  // :: (unspecified)
  if (g.every((w) => w === 0)) return true;
  // fe80::/10 link-local
  if ((g[0]! & 0xffc0) === 0xfe80) return true;
  // fec0::/10 deprecated site-local
  if ((g[0]! & 0xffc0) === 0xfec0) return true;
  // ff00::/8 multicast
  if ((g[0]! & 0xff00) === 0xff00) return true;
  // fd00:ec2::/32 (AWS IPv6 IMDS fd00:ec2::254)
  if (g[0] === 0xfd00 && g[1] === 0x0ec2) return true;
  // 64:ff9b:1::/48 local-use NAT64
  if (g[0] === 0x0064 && g[1] === 0xff9b && g[2] === 0x0001) return true;
  // 2001::/32 Teredo, 2002::/16 6to4
  if (g[0] === 0x2001 && g[1] === 0x0000) return true;
  if (g[0] === 0x2002) return true;
  // ::ffff:0:0/96 IPv4-mapped IPv6
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
    return isDisallowedIpv4Octets([
      (g[6]! >> 8) & 0xff,
      g[6]! & 0xff,
      (g[7]! >> 8) & 0xff,
      g[7]! & 0xff,
    ]);
  }
  return false;
}

function isLoopbackHost(cleanHost: string): boolean {
  if (cleanHost === 'localhost' || cleanHost.endsWith('.localhost')) return true;
  if (net.isIPv4(cleanHost)) {
    return cleanHost.startsWith('127.');
  }
  const g = parseIpv6Groups(cleanHost);
  if (!g) return false;
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0 && g[6] === 0 && g[7] === 1) {
    return true;
  }
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
    return ((g[6]! >> 8) & 0xff) === 127;
  }
  return false;
}

const DISALLOWED_METADATA_HOSTS = new Set([
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  'instance-data',
]);

export type ObservabilityUrlValidation =
  | { ok: true; url: string; origin: string; isLoopback: boolean }
  | { ok: false; reason: string };

export function validateObservabilityTargetUrl(rawUrl: unknown): ObservabilityUrlValidation {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return { ok: false, reason: 'Empty observability URL' };
  }
  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return { ok: false, reason: 'Malformed observability URL' };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, reason: `Unsupported observability protocol: ${parsed.protocol}` };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, reason: 'Observability URL must not embed credentials' };
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, '').replace(/\.+$/, '').toLowerCase();
  if (!host || host.includes('%')) {
    return { ok: false, reason: 'Invalid observability hostname' };
  }
  if (DISALLOWED_METADATA_HOSTS.has(host)) {
    return { ok: false, reason: `Metadata hostname denied: ${host}` };
  }
  if (net.isIP(host) !== 0 && isDisallowedObservabilityIp(host)) {
    return { ok: false, reason: `Link-local/IMDS or disallowed IP denied: ${host}` };
  }
  return {
    ok: true,
    url: parsed.toString(),
    origin: parsed.origin,
    isLoopback: isLoopbackHost(host),
  };
}

async function assertSafeObservabilityDns(targetUrl: string): Promise<boolean> {
  let host = '';
  try {
    host = new URL(targetUrl).hostname.replace(/^\[|\]$/g, '').replace(/\.+$/, '').toLowerCase();
  } catch {
    return false;
  }
  if (!host || host === 'localhost' || host.endsWith('.localhost') || net.isIP(host) !== 0) {
    return true;
  }
  try {
    const records = await dns.promises.lookup(host, { all: true });
    for (const rec of records) {
      if (isDisallowedObservabilityIp(rec.address)) {
        return false;
      }
    }
  } catch {
    // Allow fetchImpl (including test mocks) to handle unresolvable hostnames normally.
  }
  return true;
}

export interface TelemetryBridgeTargets {
  vmImportUrl: string;
  vlInsertUrl: string;
  collectorIngestUrl: string;
  /** Primary fallback bearer token (kept for backward compatibility). */
  bearerToken: string;
  vmBearerToken: string;
  vlBearerToken: string;
  collectorBearerToken: string;
}

const MAX_INFLIGHT_BRIDGE_PUSHES = 16;
const MAX_BRIDGE_FLOWS = 500;
const MAX_BRIDGE_LOGS = 500;
let inFlightBridgePushes = 0;

async function withBridgeConcurrencyCap<T>(label: string, fallback: T, fn: () => Promise<T>): Promise<T> {
  if (inFlightBridgePushes >= MAX_INFLIGHT_BRIDGE_PUSHES) {
    warnThrottled(`cap-${label}`, `Dropping ${label} push: outbound concurrency cap (${MAX_INFLIGHT_BRIDGE_PUSHES}) reached`);
    return fallback;
  }
  inFlightBridgePushes++;
  try {
    return await fn();
  } finally {
    inFlightBridgePushes--;
  }
}

const PROTO_NAME_TO_NUM: Record<string, number> = {
  icmp: 1,
  igmp: 2,
  ipip: 4,
  tcp: 6,
  udp: 17,
  ipv6: 41,
  gre: 47,
  esp: 50,
  ah: 51,
  icmpv6: 58,
  'ipv6-icmp': 58,
  sctp: 132,
};

const PROTO_NUM_TO_NAME: Record<number, string> = {
  1: 'ICMP',
  2: 'IGMP',
  4: 'IPIP',
  6: 'TCP',
  17: 'UDP',
  41: 'IPv6',
  47: 'GRE',
  50: 'ESP',
  51: 'AH',
  58: 'ICMPv6',
  132: 'SCTP',
};

export function normalizeFlowProtocol(rawProto: unknown, rawProtoName?: unknown): { protocol: number; protocolName: string } {
  const customName =
    typeof rawProtoName === 'string' && rawProtoName.trim()
      ? stripControlChars(rawProtoName.trim(), 32)
      : '';
  if (typeof rawProto === 'number' && Number.isInteger(rawProto) && rawProto >= 0 && rawProto <= 255) {
    return {
      protocol: rawProto,
      protocolName: customName || PROTO_NUM_TO_NAME[rawProto] || String(rawProto),
    };
  }
  const s = stripControlChars(String(rawProto ?? '').trim().toLowerCase(), 32);
  if (/^\d+$/.test(s)) {
    const n = Math.min(255, Math.max(0, Number(s)));
    return {
      protocol: n,
      protocolName: customName || PROTO_NUM_TO_NAME[n] || String(n),
    };
  }
  const num = PROTO_NAME_TO_NUM[s] ?? 0;
  return {
    protocol: num,
    protocolName: customName || PROTO_NUM_TO_NAME[num] || (s ? s.toUpperCase() : 'OTHER'),
  };
}

const lastWarnByKey = new Map<string, number>();

function warnThrottled(key: string, msg: string): void {
  const now = Date.now();
  const prev = lastWarnByKey.get(key) || 0;
  if (now - prev >= 60_000) {
    lastWarnByKey.set(key, now);
    console.warn(`[Telemetry Bridge] ${msg}`);
  }
}

function escapePromLabel(val: string): string {
  return String(val ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\n/g, '\\n')
    .replace(/"/g, '\\"');
}

function normalizeVmImportUrl(raw: string): string {
  const clean = raw.trim().replace(/\/+$/, '');
  if (!clean) return '';
  if (clean.endsWith('/api/v1/import/prometheus')) return clean;
  if (clean.endsWith('/api/v1/write')) {
    return `${clean.slice(0, -'/api/v1/write'.length)}/api/v1/import/prometheus`;
  }
  return `${clean}/api/v1/import/prometheus`;
}

function normalizeVlInsertUrl(raw: string): string {
  const clean = raw.trim().replace(/\/+$/, '');
  if (!clean) return '';
  if (clean.endsWith('/insert/jsonline')) return clean;
  return `${clean}/insert/jsonline`;
}

let cachedStateEntry: {
  key: string;
  ino: bigint;
  mtimeNs: bigint;
  size: bigint;
  state: DesiredState | null;
} | null = null;

function statCacheSig(filePath: string): { ino: bigint; mtimeNs: bigint; size: bigint } | null {
  try {
    const st = fs.statSync(filePath, { bigint: true });
    return { ino: st.ino, mtimeNs: st.mtimeNs, size: st.size };
  } catch {
    return null;
  }
}

export function readCachedDesiredStateBestEffort(): DesiredState | null {
  try {
    const dirs = resolveControllerDirs();
    const mirrorPath = path.join(dirs.etcDir, 'state.json');
    const canonicalSig = statCacheSig(dirs.stateFile);
    const activeSig = canonicalSig ?? statCacheSig(mirrorPath);
    const cacheKey = `${dirs.stateFile}|${mirrorPath}|${canonicalSig ? 'c' : 'm'}`;
    if (
      activeSig &&
      cachedStateEntry &&
      cachedStateEntry.key === cacheKey &&
      cachedStateEntry.ino === activeSig.ino &&
      cachedStateEntry.mtimeNs === activeSig.mtimeNs &&
      cachedStateEntry.size === activeSig.size
    ) {
      return cachedStateEntry.state;
    }

    const loaded = readCanonicalConfig({
      canonicalPath: dirs.stateFile,
      mirrorPaths: [mirrorPath],
      parse: (raw) => {
        try {
          const parsed = DesiredStateSchema.safeParse(JSON.parse(raw));
          return parsed.success ? parsed.data : null;
        } catch {
          return null;
        }
      },
      label: 'state.json',
      mode: 0o600,
    });

    if (activeSig) {
      cachedStateEntry = {
        key: cacheKey,
        ino: activeSig.ino,
        mtimeNs: activeSig.mtimeNs,
        size: activeSig.size,
        state: loaded,
      };
    } else {
      cachedStateEntry = null;
    }
    return loaded;
  } catch {
    // Ignore read errors during telemetry forwarding
  }
  return null;
}

export function resolveControllerObservabilityTargets(stateOverride?: DesiredState | null): TelemetryBridgeTargets {
  const state = stateOverride !== undefined ? stateOverride : readCachedDesiredStateBestEffort();
  const obs = state?.observability;
  const offload = obs?.offload;
  const rawHubBase = offload?.hubUrl ? offload.hubUrl.trim().replace(/\/+$/, '') : '';
  const hubCheck = rawHubBase ? validateObservabilityTargetUrl(rawHubBase) : null;
  if (rawHubBase && hubCheck && !hubCheck.ok) {
    warnThrottled('obs-hub-url', `Rejected unsafe offload.hubUrl: ${hubCheck.reason}`);
  }
  const validHubBase = hubCheck?.ok ? rawHubBase : '';

  const vmEnv =
    process.env.AXONWALL_VM_IMPORT_URL?.trim() ||
    process.env.AXONWALL_VM_REMOTE_WRITE_URL?.trim() ||
    process.env.VICTORIAMETRICS_URL?.trim() ||
    '';
  const vlEnv =
    process.env.AXONWALL_VL_INSERT_URL?.trim() ||
    process.env.VICTORIALOGS_URL?.trim() ||
    '';
  const rawCollectorEnv = process.env.AXONWALL_COLLECTOR_INGEST_URL?.trim() || '';
  const envVmToken = process.env.AXONWALL_VM_TOKEN?.trim() || '';
  const envVlToken = process.env.AXONWALL_VL_TOKEN?.trim() || '';
  const envCollectorToken = process.env.AXONWALL_COLLECTOR_TOKEN?.trim() || '';
  const sharedEnvToken = process.env.AXONWALL_OBSERVABILITY_TOKEN?.trim() || '';
  const offloadToken = offload?.ingestToken?.trim() || '';

  let vmImportUrl = '';
  let vmBearerToken = '';
  if (vmEnv) {
    const candidate = normalizeVmImportUrl(vmEnv);
    const check = validateObservabilityTargetUrl(candidate);
    if (check.ok) {
      vmImportUrl = check.url;
      vmBearerToken = envVmToken || sharedEnvToken || '';
    } else {
      warnThrottled('obs-vm-env-url', `Rejected unsafe env VM URL: ${check.reason}`);
    }
  } else if (obs?.victoriaMetrics?.enabled && obs.victoriaMetrics.url?.trim()) {
    const candidate = normalizeVmImportUrl(obs.victoriaMetrics.url);
    const check = validateObservabilityTargetUrl(candidate);
    if (check.ok) {
      vmImportUrl = check.url;
      vmBearerToken =
        obs.victoriaMetrics.bearerToken?.trim() ||
        (check.isLoopback ? envVmToken || sharedEnvToken : '') ||
        '';
    } else {
      warnThrottled('obs-vm-state-url', `Rejected unsafe state VictoriaMetrics URL: ${check.reason}`);
    }
  } else if (offload?.enabled && offload.metrics?.enabled) {
    if (offload.metrics.remoteWriteUrl?.trim()) {
      const candidate = normalizeVmImportUrl(offload.metrics.remoteWriteUrl);
      const check = validateObservabilityTargetUrl(candidate);
      if (check.ok) {
        vmImportUrl = check.url;
        if (!rawHubBase || (hubCheck?.ok && check.origin === hubCheck.origin)) {
          vmBearerToken = offloadToken;
        }
      } else {
        warnThrottled('obs-vm-offload-url', `Rejected unsafe offload remoteWriteUrl: ${check.reason}`);
      }
    } else if (validHubBase && hubCheck?.ok) {
      const candidate = `${validHubBase}/vm/api/v1/import/prometheus`;
      const check = validateObservabilityTargetUrl(candidate);
      if (check.ok) {
        vmImportUrl = check.url;
        vmBearerToken = offloadToken;
      }
    }
  }

  let vlInsertUrl = '';
  let vlBearerToken = '';
  if (vlEnv) {
    const candidate = normalizeVlInsertUrl(vlEnv);
    const check = validateObservabilityTargetUrl(candidate);
    if (check.ok) {
      vlInsertUrl = check.url;
      vlBearerToken = envVlToken || sharedEnvToken || '';
    } else {
      warnThrottled('obs-vl-env-url', `Rejected unsafe env VL URL: ${check.reason}`);
    }
  } else if (obs?.victoriaLogs?.enabled && obs.victoriaLogs.url?.trim()) {
    const candidate = normalizeVlInsertUrl(obs.victoriaLogs.url);
    const check = validateObservabilityTargetUrl(candidate);
    if (check.ok) {
      vlInsertUrl = check.url;
      vlBearerToken =
        obs.victoriaLogs.bearerToken?.trim() ||
        (check.isLoopback ? envVlToken || sharedEnvToken : '') ||
        '';
    } else {
      warnThrottled('obs-vl-state-url', `Rejected unsafe state VictoriaLogs URL: ${check.reason}`);
    }
  } else if (offload?.enabled && offload.logs?.enabled) {
    if (offload.logs.victoriaLogsUrl?.trim()) {
      const candidate = normalizeVlInsertUrl(offload.logs.victoriaLogsUrl);
      const check = validateObservabilityTargetUrl(candidate);
      if (check.ok) {
        vlInsertUrl = check.url;
        if (!rawHubBase || (hubCheck?.ok && check.origin === hubCheck.origin)) {
          vlBearerToken = offloadToken;
        }
      } else {
        warnThrottled('obs-vl-offload-url', `Rejected unsafe offload victoriaLogsUrl: ${check.reason}`);
      }
    } else if (validHubBase && hubCheck?.ok) {
      const candidate = `${validHubBase}/vl/insert/jsonline`;
      const check = validateObservabilityTargetUrl(candidate);
      if (check.ok) {
        vlInsertUrl = check.url;
        vlBearerToken = offloadToken;
      }
    }
  }

  let collectorIngestUrl = '';
  let collectorBearerToken = '';
  if (rawCollectorEnv) {
    const check = validateObservabilityTargetUrl(rawCollectorEnv);
    if (check.ok) {
      collectorIngestUrl = check.url.replace(/\/+$/, '');
      collectorBearerToken = envCollectorToken || sharedEnvToken || '';
    } else {
      warnThrottled('obs-collector-env-url', `Rejected unsafe collector ingest URL: ${check.reason}`);
    }
  }

  const bearerToken = vmBearerToken || vlBearerToken || collectorBearerToken || '';

  return {
    vmImportUrl,
    vlInsertUrl,
    collectorIngestUrl,
    bearerToken,
    vmBearerToken,
    vlBearerToken,
    collectorBearerToken,
  };
}

export function formatSatellitePromMetrics(
  satId: string,
  hostname: string,
  metrics: Record<string, any> | undefined,
  timestampMs = Date.now()
): string {
  if (!isValidSatelliteId(satId)) {
    throw new Error('Invalid satellite ID');
  }
  const safeHostname = stripControlChars(hostname || satId, 128) || satId;
  const safeTs = Number.isFinite(timestampMs) ? Math.floor(timestampMs) : Date.now();
  const labels = `node_id="${escapePromLabel(satId)}",hostname="${escapePromLabel(safeHostname)}",source="satellite"`;
  const lines: string[] = [];
  const push = (name: string, val: unknown) => {
    if (val === null || val === undefined || typeof val === 'boolean') return;
    if (typeof val === 'string' && val.trim() === '') return;
    const num = Number(val);
    if (Number.isFinite(num)) {
      lines.push(`${name}{${labels}} ${num} ${safeTs}`);
    }
  };
  push('axonwall_up', 1);
  if (metrics && typeof metrics === 'object') {
    push('axonwall_cpu_usage_percent', metrics.cpuUsagePercent);
    push('axonwall_mem_usage_percent', metrics.memUsagePercent);
    push('axonwall_uptime_seconds', metrics.uptimeSeconds);
    push('axonwall_conntrack_entries', metrics.activeConns);
    push('axonwall_net_rx_bytes_total', metrics.rxBytesTotal);
    push('axonwall_net_tx_bytes_total', metrics.txBytesTotal);
  }
  return `${lines.join('\n')}\n`;
}

function postJsonViaUnixSocket(socketPath: string, reqPath: string, payload: unknown, agentToken: string): Promise<boolean> {
  if (!fs.existsSync(socketPath)) {
    return Promise.resolve(false);
  }
  const body = JSON.stringify(payload);
  return new Promise((resolve) => {
    const req = http.request(
      {
        socketPath,
        path: reqPath,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          ...(agentToken ? { 'X-Axonwall-Agent-Token': agentToken } : {}),
        },
        timeout: 3000,
      },
      (res) => {
        const statusCode = res.statusCode ?? 500;
        const ok = statusCode >= 200 && statusCode < 300;
        let respText = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          if (!ok && respText.length < 1024) {
            respText += chunk;
          }
        });
        res.on('end', () => {
          if (!ok) {
            warnThrottled(
              `sock-${reqPath}-status`,
              `${reqPath} over Unix socket returned HTTP ${statusCode}${respText ? `: ${respText.trim().slice(0, 256)}` : ''}`
            );
          }
          resolve(ok);
        });
      }
    );
    req.on('timeout', () => {
      warnThrottled(`sock-${reqPath}-timeout`, `${reqPath} over Unix socket timed out`);
      req.destroy();
      resolve(false);
    });
    req.on('error', (err) => {
      warnThrottled(`sock-${reqPath}-err`, `${reqPath} over Unix socket failed: ${err?.message || String(err)}`);
      resolve(false);
    });
    req.write(body);
    req.end();
  });
}

const ALLOWED_FLOW_DIRECTIONS = new Set(['internal', 'ingress', 'egress', 'transit']);
const ALLOWED_LOG_LEVELS = new Set(['debug', 'info', 'warn', 'error']);

export function sanitizeSatelliteFlowRecord(
  f: any,
  cleanExporterIp: string,
  satId: string,
  hostname: string,
  fallbackFlowEndMs: number
): Record<string, unknown> {
  const { protocol, protocolName } = normalizeFlowProtocol(f?.protocol, f?.protocolName);
  const srcIp = sanitizeIpString(f?.srcIp);
  const dstIp = sanitizeIpString(f?.dstIp);
  const flowEndMs =
    typeof f?.flowEndMs === 'number' && Number.isFinite(f.flowEndMs) && f.flowEndMs > 0
      ? Math.floor(f.flowEndMs)
      : fallbackFlowEndMs;
  const out: Record<string, unknown> = {
    srcIp,
    dstIp,
    protocol,
    protocolName,
    srcPort: clampPortNumber(f?.srcPort),
    dstPort: clampPortNumber(f?.dstPort),
    bytes: toFiniteNonNegativeInt(f?.bytes),
    packets: toFiniteNonNegativeInt(f?.packets),
    flowEndMs,
    exporterIp: cleanExporterIp,
    hostId: satId,
    hostName: hostname || satId,
  };
  if (typeof f?.flowStartMs === 'number' && Number.isFinite(f.flowStartMs) && f.flowStartMs > 0) {
    out.flowStartMs = Math.floor(f.flowStartMs);
  }
  if (typeof f?.state === 'string' && f.state.trim()) {
    out.state = stripControlChars(f.state.trim(), 32);
  }
  if (typeof f?.offloaded === 'boolean') {
    out.offloaded = f.offloaded;
  }
  if (typeof f?.inIfName === 'string' && f.inIfName.trim()) {
    out.inIfName = stripControlChars(f.inIfName.trim(), 32);
  }
  if (typeof f?.outIfName === 'string' && f.outIfName.trim()) {
    out.outIfName = stripControlChars(f.outIfName.trim(), 32);
  }
  if (typeof f?.direction === 'string' && ALLOWED_FLOW_DIRECTIONS.has(f.direction)) {
    out.direction = f.direction;
  }
  return out;
}

function sanitizeLogTimestamp(rawTime: unknown, rawTimestamp: unknown): string {
  for (const cand of [rawTime, rawTimestamp]) {
    if (typeof cand === 'number' && Number.isFinite(cand) && cand > 0) {
      const ms = cand > 1e12 ? Math.floor(cand) : Math.floor(cand * 1000);
      return new Date(ms).toISOString();
    }
    if (typeof cand === 'string' && cand.trim()) {
      const parsed = Date.parse(cand.trim());
      if (!Number.isNaN(parsed)) {
        return new Date(parsed).toISOString();
      }
    }
  }
  return new Date().toISOString();
}

export function sanitizeSatelliteFirewallLog(
  entry: unknown,
  satId: string,
  hostname: string
): Record<string, unknown> {
  if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
    const obj = entry as Record<string, unknown>;
    const ts = sanitizeLogTimestamp(obj._time, obj.timestamp);
    const srcIp = sanitizeIpString(obj.srcIp);
    const dstIp = sanitizeIpString(obj.dstIp);
    const action =
      typeof obj.action === 'string' && obj.action.trim()
        ? stripControlChars(obj.action.trim(), 32)
        : '';
    const rawMsg =
      (typeof obj._msg === 'string' && obj._msg) ||
      (typeof obj.message === 'string' && obj.message) ||
      `${action || 'EVENT'} ${srcIp} -> ${dstIp}`.trim();
    const level =
      typeof obj.level === 'string' && ALLOWED_LOG_LEVELS.has(obj.level.toLowerCase())
        ? obj.level.toLowerCase()
        : 'warn';
    const out: Record<string, unknown> = {
      level,
      _time: ts,
      _msg: stripControlChars(rawMsg, 1024),
      node_id: satId,
      hostname: hostname || satId,
      source: 'satellite-firewall',
    };
    if (typeof obj.ruleId === 'string' && obj.ruleId.trim()) {
      out.ruleId = stripControlChars(obj.ruleId.trim(), 64);
    }
    if (action) out.action = action;
    if (srcIp) out.srcIp = srcIp;
    if (dstIp) out.dstIp = dstIp;
    if (typeof obj.protocol === 'string' && obj.protocol.trim()) {
      out.protocol = stripControlChars(obj.protocol.trim(), 32);
    } else if (typeof obj.protocol === 'number' && Number.isInteger(obj.protocol) && obj.protocol >= 0 && obj.protocol <= 255) {
      out.protocol = obj.protocol;
    }
    if (obj.srcPort !== undefined && obj.srcPort !== null && obj.srcPort !== '') {
      const p = clampPortNumber(obj.srcPort);
      if (p > 0) out.srcPort = p;
    }
    if (obj.dstPort !== undefined && obj.dstPort !== null && obj.dstPort !== '') {
      const p = clampPortNumber(obj.dstPort);
      if (p > 0) out.dstPort = p;
    }
    if (typeof obj.inIface === 'string' && obj.inIface.trim()) {
      out.inIface = stripControlChars(obj.inIface.trim(), 32);
    }
    if (typeof obj.outIface === 'string' && obj.outIface.trim()) {
      out.outIface = stripControlChars(obj.outIface.trim(), 32);
    }
    return out;
  }
  return {
    _time: new Date().toISOString(),
    _msg: stripControlChars(String(entry ?? ''), 1024),
    node_id: satId,
    hostname: hostname || satId,
    source: 'satellite-firewall',
    level: 'info',
  };
}

export async function bridgeSatelliteMetricsToVM(
  satId: string,
  hostname: string,
  metrics: Record<string, any> | undefined,
  opts?: { targets?: TelemetryBridgeTargets; fetchFn?: typeof fetch; stateOverride?: DesiredState | null }
): Promise<boolean> {
  if (!isValidSatelliteId(satId)) {
    warnThrottled('vm-bad-satid', 'Rejected VM metrics push for invalid satellite ID');
    return false;
  }
  const targets = opts?.targets ?? resolveControllerObservabilityTargets(opts?.stateOverride);
  if (!targets.vmImportUrl) return false;
  const urlCheck = validateObservabilityTargetUrl(targets.vmImportUrl);
  if (!urlCheck.ok || !(await assertSafeObservabilityDns(urlCheck.url))) {
    warnThrottled('vm-ssrf', `Blocked unsafe VM metrics URL: ${!urlCheck.ok ? urlCheck.reason : 'DNS resolved to disallowed IP'}`);
    return false;
  }
  const token = targets.vmBearerToken ?? targets.bearerToken;
  const fetchImpl = opts?.fetchFn ?? fetch;
  const body = formatSatellitePromMetrics(satId, hostname, metrics);
  return withBridgeConcurrencyCap('vm-metrics', false, async () => {
    try {
      const res = await fetchImpl(urlCheck.url, {
        method: 'POST',
        redirect: 'error',
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body,
        signal: AbortSignal.timeout(3000),
      });
      if (!res.ok) {
        warnThrottled('vm-status', `VM metrics push returned HTTP ${res.status}`);
        return false;
      }
      return true;
    } catch (err: any) {
      warnThrottled('vm-err', `VM metrics push failed: ${err?.message || String(err)}`);
      return false;
    }
  });
}

export async function bridgeSatelliteFlowsAndLogs(
  satId: string,
  hostname: string,
  exporterIp: string,
  batch: { timestamp?: number; flows?: any[]; firewallLogs?: any[] } | undefined,
  opts?: { targets?: TelemetryBridgeTargets; fetchFn?: typeof fetch; stateOverride?: DesiredState | null }
): Promise<{ flowsForwarded: boolean; logsForwarded: boolean }> {
  if (!isValidSatelliteId(satId)) {
    warnThrottled('batch-bad-satid', 'Rejected flow/log bridge for invalid satellite ID');
    return { flowsForwarded: false, logsForwarded: false };
  }
  const targets = opts?.targets ?? resolveControllerObservabilityTargets(opts?.stateOverride);
  const fetchImpl = opts?.fetchFn ?? fetch;
  let flowsForwarded = false;
  let logsForwarded = false;

  const cleanHost = stripControlChars(hostname || satId, 128) || satId;
  const cleanExporterIp = sanitizeIpString(String(exporterIp || '').trim().split('/')[0] || '');
  const fallbackFlowEndMs =
    typeof batch?.timestamp === 'number' && Number.isFinite(batch.timestamp) && batch.timestamp > 0
      ? batch.timestamp > 1e12
        ? Math.floor(batch.timestamp)
        : Math.floor(batch.timestamp * 1000)
      : Date.now();

  if (Array.isArray(batch?.flows) && batch.flows.length > 0) {
    const normalizedFlows = batch.flows
      .slice(0, MAX_BRIDGE_FLOWS)
      .filter((f) => f && typeof f === 'object' && !Array.isArray(f))
      .map((f) => sanitizeSatelliteFlowRecord(f, cleanExporterIp, satId, cleanHost, fallbackFlowEndMs));

    if (normalizedFlows.length > 0) {
      const flowPayload = {
        nodeId: satId,
        hostname: cleanHost,
        exporterIp: cleanExporterIp,
        flows: normalizedFlows,
      };
      if (targets.collectorIngestUrl) {
        const ingestUrl = targets.collectorIngestUrl.trim().replace(/\/+$/, '');
        const fullUrl = ingestUrl.endsWith('/v1/netflow/ingest-batch')
          ? ingestUrl
          : `${ingestUrl}/v1/netflow/ingest-batch`;
        const collectorUrlCheck = validateObservabilityTargetUrl(fullUrl);
        if (!collectorUrlCheck.ok || !(await assertSafeObservabilityDns(collectorUrlCheck.url))) {
          warnThrottled('collector-ssrf', `Blocked unsafe collector URL: ${!collectorUrlCheck.ok ? collectorUrlCheck.reason : 'DNS resolved to disallowed IP'}`);
        } else {
          const collectorToken = targets.collectorBearerToken ?? targets.bearerToken;
          flowsForwarded = await withBridgeConcurrencyCap('collector-flows', false, async () => {
            try {
              const res = await fetchImpl(collectorUrlCheck.url, {
                method: 'POST',
                redirect: 'error',
                headers: {
                  'Content-Type': 'application/json',
                  ...(collectorToken ? { Authorization: `Bearer ${collectorToken}` } : {}),
                },
                body: JSON.stringify(flowPayload),
                signal: AbortSignal.timeout(3000),
              });
              if (!res.ok) {
                warnThrottled('flows-http-status', `Collector flow batch push returned HTTP ${res.status}`);
                return false;
              }
              return true;
            } catch (err: any) {
              warnThrottled('flows-http', `Collector flow batch push failed: ${err?.message || String(err)}`);
              return false;
            }
          });
        }
      } else {
        const sock = resolveControllerDirs().agentSock;
        flowsForwarded = await withBridgeConcurrencyCap('sock-flows', false, () =>
          postJsonViaUnixSocket(
            sock,
            '/v1/netflow/ingest-batch',
            flowPayload,
            readAgentToken() || ''
          )
        );
      }
    }
  }

  if (Array.isArray(batch?.firewallLogs) && batch.firewallLogs.length > 0 && targets.vlInsertUrl) {
    const vlUrlCheck = validateObservabilityTargetUrl(targets.vlInsertUrl);
    if (!vlUrlCheck.ok || !(await assertSafeObservabilityDns(vlUrlCheck.url))) {
      warnThrottled('vl-ssrf', `Blocked unsafe VL insert URL: ${!vlUrlCheck.ok ? vlUrlCheck.reason : 'DNS resolved to disallowed IP'}`);
    } else {
      const vlToken = targets.vlBearerToken ?? targets.bearerToken;
      const ndjson = batch.firewallLogs
        .slice(0, MAX_BRIDGE_LOGS)
        .map((entry) => JSON.stringify(sanitizeSatelliteFirewallLog(entry, satId, cleanHost)))
        .join('\n');

      logsForwarded = await withBridgeConcurrencyCap('vl-logs', false, async () => {
        try {
          const res = await fetchImpl(vlUrlCheck.url, {
            method: 'POST',
            redirect: 'error',
            headers: {
              'Content-Type': 'application/x-ndjson',
              ...(vlToken ? { Authorization: `Bearer ${vlToken}` } : {}),
            },
            body: `${ndjson}\n`,
            signal: AbortSignal.timeout(3000),
          });
          if (!res.ok) {
            warnThrottled('vl-status', `VL log insert returned HTTP ${res.status}`);
            return false;
          }
          return true;
        } catch (err: any) {
          warnThrottled('vl-err', `VL log insert failed: ${err?.message || String(err)}`);
          return false;
        }
      });
    }
  }

  return { flowsForwarded, logsForwarded };
}
