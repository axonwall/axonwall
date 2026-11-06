import promClient from 'prom-client';
import { compileNftables, compileSatelliteNftables } from '@axonwall/lib/compile/nft';
import { lintRuleset } from '@axonwall/lib/lint';
import { DesiredStateSchema, type DesiredState } from '@axonwall/lib/schemas';
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

  // 3. Compute deterministic bundle hash over nftScript, files, and reloadServices
  const hashInput = JSON.stringify({
    nftScript,
    files: [...files]
      .sort((a, b) => a.path.localeCompare(b.path))
      .map((f) => ({ path: f.path, content: f.content, fileMode: f.fileMode })),
    reloadServices: [...reloadServices].sort(),
  });
  const hash = crypto.createHash('sha256').update(hashInput).digest('hex');

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
import * as net from 'node:net';
import * as path from 'node:path';
import * as os from 'node:os';
import * as child_process from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { listUsers, createUser, createPreAuthKey } from './headscale.js';
import { authenticateMcpToken, createMcpApiKeyRecord, listMcpApiKeys, revokeMcpApiKeyRecord } from './mcp/authz.js';
import { processMcpJsonRpcMessage, MCP_RESOURCES_CATALOG, MCP_TOOLS_CATALOG, type JsonRpcRequest } from './mcp/server.js';
import { recordMcpAuditEntry, verifyMcpAuditChain, queryMcpAuditEntries } from './mcp/audit.js';
import { isMcpServerEnabled, getMcpServerStatus } from '@axonwall/lib/mcp';

export interface ControllerTlsConfig {
  cert: Buffer | string;
  key: Buffer | string;
  ca?: Buffer | string;
  isFallback?: boolean;
}

// Returns true when the leaf at certPath chains to caPath, false when
// openssl ran and rejected it, and null when the check itself could not
// run (openssl missing). A rejected leaf must never be served: it is the
// permanent bad-leaf trap of B-H3, where a self-signed leaf minted under
// an operator CA keeps CA-pinned satellites rejected forever.
function leafChainsToCa(certPath: string, caPath: string): boolean | null {
  try {
    child_process.execFileSync('openssl', ['verify', '-CAfile', caPath, certPath], { timeout: 15000, stdio: 'ignore' });
    return true;
  } catch (err: any) {
    if (err && typeof err.status === 'number') return false;
    return null;
  }
}

// Operator-CA mode is: ca.crt exists on disk but no matching on-box CA
// key exists, so this controller cannot issue a leaf that chains to the
// operator CA. Minting a self-signed leaf in that mode is exactly the
// B-H3 failure (the rotate tool deliberately refuses, then the
// controller undid the refusal). Fail startup loudly instead of
// minting, and never let the emergency fallback paper over it either.
function assertNotOperatorCaWithoutKey(caPath: string, caKeyPath: string): void {
  if (fs.existsSync(caPath) && !fs.existsSync(caKeyPath)) {
    throw new Error(
      '[Axonwall Controller] Refusing to mint a self-signed hub certificate: ca.crt exists but no ' +
      'matching on-box CA key was found (operator-CA mode). Install an operator-issued hub.crt/hub.key ' +
      'pair that chains to ca.crt, or remove ca.crt to use appliance-CA provisioning.'
    );
  }
}

export function ensureControllerTls(
  certPath: string = '/etc/axonwall/certs/hub.crt',
  keyPath: string = '/etc/axonwall/certs/hub.key',
  caPath: string = '/etc/axonwall/certs/ca.crt',
  caKeyPath: string = path.join(path.dirname(caPath), 'ca.key')
): ControllerTlsConfig | null {
  // If explicit insecure HTTP is requested for testing/mocking
  if (process.env.AXONWALL_INSECURE_HTTP === '1') {
    console.warn('[Axonwall Controller] AXONWALL_INSECURE_HTTP=1 is set: running in plaintext mode (DEV/TEST ONLY)');
    return null;
  }

  // 1. Check if cert and key already exist and are non-empty
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    try {
      const certStat = fs.statSync(certPath);
      const keyStat = fs.statSync(keyPath);
      if (certStat.size > 0 && keyStat.size > 0) {
        const cert = fs.readFileSync(certPath);
        const key = fs.readFileSync(keyPath);
        const ca = fs.existsSync(caPath) ? fs.readFileSync(caPath) : undefined;
        if (ca && leafChainsToCa(certPath, caPath) === false) {
          // B-H3: a leaf that does not chain to the on-disk CA is
          // unusable for CA-pinned satellites; do not serve it. Fall
          // through to re-provisioning (or the operator-CA refusal).
          console.warn('[Axonwall Controller] Existing hub certificate does not chain to the on-disk CA; ignoring it so it can be re-provisioned instead of served.');
        } else {
          return { cert, key, ca };
        }
      }
    } catch (err) {
      console.warn('[Axonwall Controller] Existing cert files could not be read:', err);
    }
  }

  // 2. Try provisioning via axonwall-rotate-hub-cert --ensure if available
  const rotateCandidates = ['/usr/local/bin/axonwall-rotate-hub-cert', '/usr/bin/axonwall-rotate-hub-cert'];
  const rotateBin = rotateCandidates.find((p) => fs.existsSync(p));
  if (rotateBin) {
    try {
      console.log(`[Axonwall Controller] Running ${rotateBin} --ensure to provision hub TLS certificate...`);
      child_process.execFileSync(rotateBin, ['--ensure'], { timeout: 15000, stdio: 'ignore' });
      if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
        const cert = fs.readFileSync(certPath);
        const key = fs.readFileSync(keyPath);
        if (cert.length > 0 && key.length > 0) {
          const ca = fs.existsSync(caPath) ? fs.readFileSync(caPath) : undefined;
          if (ca && leafChainsToCa(certPath, caPath) === false) {
            console.warn('[Axonwall Controller] Rotated hub certificate does not chain to the on-disk CA; ignoring it so it can be re-provisioned instead of served.');
          } else {
            return { cert, key, ca };
          }
        }
      }
    } catch (err) {
      console.warn('[Axonwall Controller] axonwall-rotate-hub-cert execution failed:', err);
    }
  }

  // 3. Try generating directly to certPath/keyPath with openssl.
  // B-H3: never self-generate when an operator CA exists without a
  // matching on-box CA key — fail startup loudly instead.
  assertNotOperatorCaWithoutKey(caPath, caKeyPath);
  const generateSignedOrSelfSignedCert = (targetKeyPath: string, targetCertPath: string, days: string) => {
    const san = 'DNS:localhost,DNS:axonwall.local,IP:127.0.0.1';
    if (fs.existsSync(caPath) && fs.existsSync(caKeyPath)) {
      const csrPath = `${targetCertPath}.csr`;
      const extPath = `${targetCertPath}.ext`;
      try {
        child_process.execFileSync(
          'openssl',
          [
            'req',
            '-newkey',
            'rsa:2048',
            '-nodes',
            '-keyout',
            targetKeyPath,
            '-out',
            csrPath,
            '-subj',
            '/O=Axonwall/OU=Appliance/CN=axonwall',
          ],
          { timeout: 15000, stdio: 'ignore' }
        );
        fs.writeFileSync(
          extPath,
          `basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=${san}\n`,
          { mode: 0o600 }
        );
        child_process.execFileSync(
          'openssl',
          [
            'x509',
            '-req',
            '-in',
            csrPath,
            '-CA',
            caPath,
            '-CAkey',
            caKeyPath,
            '-CAcreateserial',
            '-out',
            targetCertPath,
            '-days',
            days,
            '-sha256',
            '-extfile',
            extPath,
          ],
          { timeout: 15000, stdio: 'ignore' }
        );
      } finally {
        try { fs.unlinkSync(csrPath); } catch {}
        try { fs.unlinkSync(extPath); } catch {}
      }
    } else {
      child_process.execFileSync(
        'openssl',
        [
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-nodes',
          '-keyout',
          targetKeyPath,
          '-out',
          targetCertPath,
          '-days',
          days,
          '-subj',
          '/O=Axonwall/OU=Appliance/CN=axonwall',
          '-addext',
          `subjectAltName=${san}`,
        ],
        { timeout: 15000, stdio: 'ignore' }
      );
    }
  };
  try {
    const certDir = path.dirname(certPath);
    if (!fs.existsSync(certDir)) {
      fs.mkdirSync(certDir, { recursive: true, mode: 0o750 });
    }
    generateSignedOrSelfSignedCert(keyPath, certPath, '3650');

    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
      const cert = fs.readFileSync(certPath);
      const key = fs.readFileSync(keyPath);
      try {
        fs.chmodSync(keyPath, 0o600);
        fs.chmodSync(certPath, 0o644);
      } catch {}
      if (cert.length > 0 && key.length > 0) {
        console.log('[Axonwall Controller] Successfully generated local hub certificate via openssl');
        // B-H3: include the on-disk CA when it exists, so the mTLS
        // gate (requestCert) is actually armed for CA-issued satellites.
        const ca = fs.existsSync(caPath) ? fs.readFileSync(caPath) : undefined;
        return { cert, key, ca };
      }
    }
  } catch (err) {
    console.warn('[Axonwall Controller] Generating certificate in target directory failed:', err);
  }

  // 4. Emergency fallback: generate temporary self-signed cert in tmpdir.
  // B-H3: the fallback must not defeat the operator-CA refusal either.
  assertNotOperatorCaWithoutKey(caPath, caKeyPath);
  try {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-tls-'));
    const tmpKey = path.join(tmpDir, 'hub.key');
    const tmpCert = path.join(tmpDir, 'hub.crt');
    generateSignedOrSelfSignedCert(tmpKey, tmpCert, '30');

    const cert = fs.readFileSync(tmpCert);
    const key = fs.readFileSync(tmpKey);
    try {
      fs.unlinkSync(tmpKey);
      fs.unlinkSync(tmpCert);
      fs.rmdirSync(tmpDir);
    } catch {}

    if (cert.length > 0 && key.length > 0) {
      console.warn(
        '[Axonwall Controller] Using emergency temporary self-signed TLS certificate to ensure port 2966 stays encrypted'
      );
      // B-H3: include the on-disk CA when it exists (see step 3).
      const ca = fs.existsSync(caPath) ? fs.readFileSync(caPath) : undefined;
      return { cert, key, ca, isFallback: true };
    }
  } catch (err) {
    console.error('[Axonwall Controller] Critical error generating emergency TLS certificate:', err);
  }

  return null;
}

export {
  authenticateMcpToken,
  createMcpApiKeyRecord,
  listMcpApiKeys,
  revokeMcpApiKeyRecord,
  processMcpJsonRpcMessage,
  MCP_RESOURCES_CATALOG,
  MCP_TOOLS_CATALOG,
  recordMcpAuditEntry,
  verifyMcpAuditChain,
  queryMcpAuditEntries,
  isMcpServerEnabled,
  getMcpServerStatus,
};

// ========================================================================
// Fleet / HA helpers (exported for tests; used by the handlers in main()).
// B-H2a/B-H2b/B-M6: the HA endpoint must never default an unknown role
// to a state-changing broadcast, never promote without an explicit
// target, and never invent a VIP or forward an unvalidated MAC.
// ========================================================================

const HA_PROMOTE_ROLES = new Set(['master', 'active', 'promote']);
const HA_DEMOTE_ROLES = new Set(['standby', 'demote', 'backup']);

export function isValidMacAddress(value: unknown): boolean {
  return typeof value === 'string' && /^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$/.test(value.trim());
}

export function normalizeMacAddress(value: string): string {
  return value.trim().toLowerCase().replace(/-/g, ':');
}

export function isValidCidr(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  const parts = value.trim().split('/');
  if (parts.length !== 2) return false;
  const family = net.isIP(parts[0]!);
  if (family !== 4 && family !== 6) return false;
  if (!/^\d{1,3}$/.test(parts[1]!)) return false;
  const prefix = Number(parts[1]);
  return prefix >= 0 && prefix <= (family === 4 ? 32 : 128);
}

export interface HaTransitionRequest {
  role?: unknown;
  state?: unknown;
  type?: unknown;
  satelliteId?: unknown;
  sharedWanMac?: unknown;
  lanVip?: unknown;
}

export interface HaTransitionValidation {
  ok: boolean;
  error?: string;
  status?: number;
  transition?: 'PROMOTE' | 'DEMOTE';
  role?: 'active' | 'standby';
  satelliteId?: string;
  sharedWanMac?: string;
  lanVip?: string;
}

// Validates an /api/v1/fleet/ha-transition payload without touching the
// registry. `fleetLanVip` is the LAN VIP from fleet config (hosted edge
// LAN address); it is the only permitted non-explicit VIP source —
// there is no hardcoded default. Role precedence is role > state > type.
export type FleetSyncBodyValidation =
  | { ok: true; desired: DesiredState | undefined }
  | { ok: false; status: 400; error: string };

// B-H1: parse the POST /api/v1/fleet/sync body. An empty body means
// "re-sync from the on-disk state" (desired === undefined, so
// syncSatelliteDesiredState loads /etc/axonwall/state.json). A
// non-empty body must be valid JSON matching DesiredStateSchema;
// anything else is a 400. The previous handler silently ignored a
// schema failure and synced `null`, which syncSatelliteDesiredState
// treats as a value (not "load from disk"), so edge satellites were
// pushed hardcoded default interface config.
export function parseFleetSyncBody(body: string): FleetSyncBodyValidation {
  if (!body.trim()) {
    return { ok: true, desired: undefined };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(body);
  } catch {
    return { ok: false, status: 400, error: 'Invalid JSON' };
  }
  const parsed = DesiredStateSchema.safeParse(raw);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const detail = first ? ` (${first.path.join('.') || 'body'}: ${first.message})` : '';
    return { ok: false, status: 400, error: `Invalid DesiredState body${detail}` };
  }
  return { ok: true, desired: parsed.data };
}

export function validateHaTransition(payload: HaTransitionRequest, fleetLanVip?: string): HaTransitionValidation {
  const rawRole = String(payload.role ?? payload.state ?? payload.type ?? '').toLowerCase();
  if (!rawRole) {
    return { ok: false, status: 400, error: 'Missing HA role: expected one of master/active/promote (PROMOTE) or standby/demote/backup (DEMOTE)' };
  }
  let transition: 'PROMOTE' | 'DEMOTE';
  if (HA_PROMOTE_ROLES.has(rawRole)) transition = 'PROMOTE';
  else if (HA_DEMOTE_ROLES.has(rawRole)) transition = 'DEMOTE';
  else {
    return { ok: false, status: 400, error: `Unknown HA role "${rawRole}": expected one of master/active/promote (PROMOTE) or standby/demote/backup (DEMOTE)` };
  }
  const satelliteId = typeof payload.satelliteId === 'string' ? payload.satelliteId.trim() : '';
  if (transition === 'PROMOTE' && !satelliteId) {
    return { ok: false, status: 400, error: 'satelliteId is required for PROMOTE: promoting without an explicit target would activate every edge at once' };
  }
  let sharedWanMac: string | undefined;
  if (payload.sharedWanMac !== undefined) {
    if (!isValidMacAddress(payload.sharedWanMac)) {
      return { ok: false, status: 400, error: 'Invalid sharedWanMac: expected a MAC address (e.g. 02:00:00:00:00:01)' };
    }
    sharedWanMac = normalizeMacAddress(payload.sharedWanMac as string);
  }
  let lanVip: string | undefined;
  if (typeof payload.lanVip === 'string' && payload.lanVip.trim() !== '') {
    if (!isValidCidr(payload.lanVip)) {
      return { ok: false, status: 400, error: 'Invalid lanVip: expected an IP/CIDR (e.g. 10.0.0.1/24)' };
    }
    lanVip = payload.lanVip.trim();
  } else if (transition === 'PROMOTE') {
    if (fleetLanVip && isValidCidr(fleetLanVip)) lanVip = fleetLanVip.trim();
    else {
      return { ok: false, status: 400, error: 'lanVip is required for PROMOTE: supply it explicitly or configure the fleet LAN address; no default VIP is assumed' };
    }
  }
  return {
    ok: true,
    transition,
    role: transition === 'PROMOTE' ? 'active' : 'standby',
    satelliteId: satelliteId || undefined,
    sharedWanMac,
    lanVip,
  };
}

// B-M2: disconnected satellites are retained (for reconnect identity)
// only for a grace period, then pruned. The mesh peer filter itself is
// stricter: only OPEN sockets are ever broadcast as live peers.
export const MESH_DISCONNECTED_GRACE_MS = 24 * 60 * 60 * 1000;

export function shouldPruneDisconnectedSatellite(
  disconnectedAt: string | undefined,
  nowMs: number,
  graceMs: number = MESH_DISCONNECTED_GRACE_MS,
): boolean {
  if (!disconnectedAt) return false;
  const t = Date.parse(disconnectedAt);
  if (Number.isNaN(t)) return false;
  return nowMs - t >= graceMs;
}

// B-H4: Headscale provisioning retries on bounded backoff while the
// socket is open, instead of a single attempt per controller lifetime.
// Delays are the waits before each attempt (first attempt immediate).
export function headscaleRetryDelaysMs(): number[] {
  return [0, 5000, 15000, 30000, 60000];
}

export interface HeadscaleProvisionDeps {
  listUsers: () => Promise<any[]>;
  createUser: (name: string) => Promise<any>;
  createPreAuthKey: (user: string, reusable: boolean, ephemeral: boolean, expiration: string) => Promise<{ key: string }>;
  serverUrl: string;
  send: (msg: unknown) => void;
  isOpen: () => boolean;
  sleep?: (ms: number) => Promise<void>;
  delaysMs?: number[];
}

// Mints a 1-hour ephemeral pre-auth key and sends SYNC_HEADSCALE,
// retrying on failure while the socket stays open. Returns true only
// when the credentials were actually sent on an open socket.
export async function provisionHeadscaleWithRetry(deps: HeadscaleProvisionDeps): Promise<boolean> {
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const delays = deps.delaysMs ?? headscaleRetryDelaysMs();
  for (const delay of delays) {
    if (delay > 0) await sleep(delay);
    if (!deps.isOpen()) return false;
    try {
      const users = await deps.listUsers();
      let satelliteUser = users.find((u: any) => u.name === 'satellites');
      if (!satelliteUser) satelliteUser = await deps.createUser('satellites');
      void satelliteUser;
      const expiration = new Date(Date.now() + 60 * 60 * 1000).toISOString();
      const preAuthKey = await deps.createPreAuthKey('satellites', false, true, expiration);
      if (!deps.isOpen()) return false;
      deps.send({
        type: 'SYNC_HEADSCALE',
        payload: { serverUrl: deps.serverUrl, authKey: preAuthKey.key },
      });
      return true;
    } catch (err: any) {
      console.error(`[Fleet Manager] Headscale provisioning attempt failed: ${err?.message || err}`);
    }
  }
  return false;
}

function getSafeRedirectUrl(
  req: http.IncomingMessage,
  targetPort: number
): { targetUrl: string; escapedUrl: string; scriptSafeUrl: string } {
  const rawHostHeader = (req.headers.host || '').trim();
  let hostname = 'localhost';
  if (rawHostHeader) {
    const ipv6Match = rawHostHeader.match(/^(\[[0-9a-fA-F:]+\])(?::\d+)?$/);
    if (ipv6Match) {
      hostname = ipv6Match[1]!;
    } else {
      const hostMatch = rawHostHeader.match(/^([a-zA-Z0-9.-]+)(?::\d+)?$/);
      if (hostMatch) {
        hostname = hostMatch[1]!;
      }
    }
  }

  // Strip control characters, ensure leading single slash, prevent protocol-relative redirects
  let safePath = (req.url || '/').replace(/[\x00-\x1f\x7f]/g, '');
  if (!safePath.startsWith('/')) {
    safePath = '/' + safePath;
  }
  safePath = safePath.replace(/^\/+/, '/');

  const targetUrl = `https://${hostname}:${targetPort}${safePath}`;
  const escapedUrl = targetUrl
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
  const scriptSafeUrl = JSON.stringify(targetUrl)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026');

  return { targetUrl, escapedUrl, scriptSafeUrl };
}

// B-M5: derive a satellite's effective role. The fleet node's
// configured role always wins. For unconfigured nodes, telemetry
// (pid1Mode) and the id prefix are fallbacks only: a telemetry report
// with pid1Mode latches 'edge-ngfw', a later report without it clears
// a telemetry-latched edge role (but never an id-prefix edge role),
// and the sync path (pid1ModeReported undefined) keeps a latched edge
// role or the id-prefix fallback. Used by both the telemetry handler
// and syncSatelliteDesiredState so the two paths cannot drift apart.
export function deriveSatelliteRole(input: {
  configuredRole?: 'satellite' | 'edge-ngfw' | null;
  currentRole?: 'satellite' | 'edge-ngfw' | null;
  satelliteId: string;
  pid1ModeReported?: boolean;
}): 'satellite' | 'edge-ngfw' {
  if (input.configuredRole) {
    return input.configuredRole;
  }
  if (input.pid1ModeReported === true) {
    return 'edge-ngfw';
  }
  if (input.pid1ModeReported === false) {
    if (
      input.currentRole === 'edge-ngfw' &&
      !input.satelliteId.startsWith('edge-') &&
      input.satelliteId !== 'edge'
    ) {
      return 'satellite';
    }
    return input.currentRole || 'satellite';
  }
  if (
    input.currentRole === 'edge-ngfw' ||
    input.satelliteId.startsWith('edge-') ||
    input.satelliteId === 'edge'
  ) {
    return 'edge-ngfw';
  }
  return input.currentRole || 'satellite';
}

export function createHttpRedirectServer(targetPort: number): http.Server {
  const redirectServer = http.createServer((req, res) => {
    const { targetUrl, escapedUrl, scriptSafeUrl } = getSafeRedirectUrl(req, targetPort);

    res.writeHead(301, {
      Location: targetUrl,
      'Content-Type': 'text/html; charset=utf-8',
      Connection: 'close',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    });
    res.end(`<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="refresh" content="0;url=${escapedUrl}">
  <title>Redirecting to HTTPS</title>
</head>
<body style="font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #94a3b8; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0;">
  <div style="background: #1e293b; padding: 2rem; border-radius: 8px; border: 1px solid #334155; text-align: center; max-width: 480px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5);">
    <h2 style="color: #38bdf8; margin: 0 0 1rem 0;">Upgrading to Secure HTTPS...</h2>
    <p style="margin: 0 0 1rem 0;">Redirecting you automatically to the secure management console.</p>
    <p style="margin: 0; font-size: 0.85rem;"><a href="${escapedUrl}" style="color: #38bdf8; text-decoration: underline;">Click here if you are not redirected</a></p>
  </div>
  <script>location.href = ${scriptSafeUrl};</script>
</body>
</html>`);
  });

  redirectServer.on('upgrade', (req, socket) => {
    const { targetUrl } = getSafeRedirectUrl(req, targetPort);
    const safeLocation = targetUrl.replace(/[\r\n]/g, '');
    socket.write(
      'HTTP/1.1 301 Moved Permanently\r\n' +
      `Location: ${safeLocation}\r\n` +
      'Connection: close\r\n' +
      'Content-Type: text/plain\r\n\r\n' +
      'Redirecting to HTTPS\r\n'
    );
    socket.destroy();
  });

  redirectServer.on('clientError', (err, socket) => {
    socket.destroy(err);
  });

  return redirectServer;
}

export function createPortMultiplexer(
  httpsServer: https.Server,
  redirectServer: http.Server,
  opts?: { handshakeTimeoutMs?: number },
): net.Server {
  // B-L2: the pre-handshake timeout used to be cleared on the first
  // byte, so a client that sent one byte and stalled held a socket
  // forever before the TLS handshake. Keep a handshake deadline
  // after the first byte instead: it is cleared when the TLS
  // handshake completes (TLS branch) or the first HTTP request
  // arrives (redirect branch), and on socket close/error. A plain
  // JS timer is used rather than socket.setTimeout because the
  // socket timeout is unreliable once the TLS wrapper owns the
  // handle. The deadline is keyed by remote address+port for TLS
  // (the TLSSocket is a different object from the raw socket) and
  // by socket object for the redirect branch (req.socket is the
  // raw socket); both are unique among open connections on this
  // listener.
  const handshakeTimeoutMs = opts?.handshakeTimeoutMs ?? 10000;
  const pendingTls = new Map<string, NodeJS.Timeout>();
  const pendingRedirect = new Map<net.Socket, NodeJS.Timeout>();
  const tlsKey = (socket: net.Socket) => `${socket.remoteAddress}:${socket.remotePort}`;
  const clearTlsDeadlineByKey = (key: string) => {
    const timer = pendingTls.get(key);
    if (timer) {
      clearTimeout(timer);
      pendingTls.delete(key);
    }
  };
  const clearTlsDeadline = (socket: net.Socket) => {
    clearTlsDeadlineByKey(tlsKey(socket));
  };
  const clearRedirectDeadline = (socket: net.Socket) => {
    const timer = pendingRedirect.get(socket);
    if (timer) {
      clearTimeout(timer);
      pendingRedirect.delete(socket);
    }
  };
  httpsServer.on('secureConnection', (tlsSocket: net.Socket) => {
    clearTlsDeadline(tlsSocket);
  });
  redirectServer.on('request', (req: http.IncomingMessage) => {
    if (req.socket) clearRedirectDeadline(req.socket as net.Socket);
  });

  const tcpMultiplexer = net.createServer((socket) => {
    let handled = false;
    const connKey = tlsKey(socket);

    // Mitigate slowloris / connection exhaustion prior to TLS handshake:
    // destroy unauthenticated connections that send 0 bytes within 5 seconds.
    socket.setTimeout(5000, () => {
      if (!handled) {
        handled = true;
        socket.destroy();
      }
    });

    const onReadable = () => {
      if (handled) return;
      const buf = socket.read(1);
      if (!buf) return;
      handled = true;
      socket.setTimeout(0); // Clear pre-handshake timeout before handing socket over
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
      socket.unshift(buf);
      if (buf[0] === 0x16) {
        const timer = setTimeout(() => {
          pendingTls.delete(connKey);
          socket.destroy();
        }, handshakeTimeoutMs);
        pendingTls.set(connKey, timer);
        socket.once('close', () => clearTlsDeadlineByKey(connKey));
        socket.once('error', () => clearTlsDeadlineByKey(connKey));
        httpsServer.emit('connection', socket);
      } else {
        const timer = setTimeout(() => {
          pendingRedirect.delete(socket);
          socket.destroy();
        }, handshakeTimeoutMs);
        pendingRedirect.set(socket, timer);
        socket.once('close', () => clearRedirectDeadline(socket));
        socket.once('error', () => clearRedirectDeadline(socket));
        redirectServer.emit('connection', socket);
      }
    };

    const onError = (_err: Error) => {
      if (!handled) {
        handled = true;
        socket.destroy();
      }
    };

    const onClose = () => {
      handled = true;
    };

    socket.once('readable', onReadable);
    socket.once('error', onError);
    socket.once('close', onClose);
  });

  tcpMultiplexer.on('error', (err) => {
    console.error('[Axonwall Controller] TCP Multiplexer error:', err);
  });

  tcpMultiplexer.on('close', () => {
    if (typeof (httpsServer as any).closeAllConnections === 'function') {
      (httpsServer as any).closeAllConnections();
    }
    if (typeof (redirectServer as any).closeAllConnections === 'function') {
      (redirectServer as any).closeAllConnections();
    }
    httpsServer.close();
    redirectServer.close();
  });

  return tcpMultiplexer;
}

async function main() {
  console.log('[Axonwall Controller] Starting Axonwall Control Plane Worker...');
  console.log('[Axonwall Controller] Monitoring config changes and apply pipeline.');

  // In-memory fleet registry of active satellites
  interface SatelliteState {
    id: string;
    connectedAt: string;
    lastSeen: string;
    role?: 'satellite' | 'edge-ngfw';
    skuProfile?: string;
    wanInterface?: string;
    lanInterface?: string;
    fastpathOffload?: boolean;
    ip?: string;
    arch?: string;
    wgPrivateKey?: string;
    wgPublicKey?: string;
    tunnelIp?: string;
    wireguard?: { tunnelIp: string };
    ws?: WebSocket;
    headscaleEnrolled?: boolean;
    // B-M2: set when the socket closes; the entry is pruned after the
    // grace period instead of being retained until the fleet cap.
    disconnectedAt?: string;
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
    edgeFlows?: any[];
    edgeFirewallLogs?: any[];
  }

  const activeSatellites = new Map<string, SatelliteState>();

  // B-H2b: the edge last promoted to active via /fleet/ha-transition.
  // The controller demotes this edge before promoting a different one.
  let activeHaEdgeId: string | null = null;

  function loadLocalDesiredState(): DesiredState | null {
    const candidates = ['/etc/axonwall/state.json', '/var/lib/axonwall/state.json'];
    for (const p of candidates) {
      try {
        if (fs.existsSync(p)) {
          const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
          const parsed = DesiredStateSchema.safeParse(raw);
          if (parsed.success) return parsed.data;
        }
      } catch {
        // Ignore parse/read error
      }
    }
    return null;
  }

  // B-H1: the fleet-sync body is validated by parseFleetSyncBody
  // (exported above, beside validateHaTransition) before any
  // means "re-sync from the on-disk state" (desired === undefined,
  // so syncSatelliteDesiredState loads /etc/axonwall/state.json); a
  // non-empty body that fails validation is a 400, never a silent
  // sync of default/empty state. Passing null here used to mean
  // "sync with empty state", which pushed hardcoded default edge
  // config (WAN DHCP, LAN 10.0.0.1/24) to every connected edge.
  function syncSatelliteDesiredState(sat: SatelliteState, desiredState?: DesiredState | null) {
    if (!sat.ws || sat.ws.readyState !== WebSocket.OPEN) return;

    const localState = desiredState !== undefined ? desiredState : loadLocalDesiredState();
    const fleetNode = localState?.fleet?.nodes?.find((n) => n.id === sat.id);
    const hostedEdge = localState?.hostedEdge;
    // B-M5: role is derived from the fleet node's configured role on
    // every sync (see deriveSatelliteRole). Telemetry and the id
    // prefix are only fallbacks for unconfigured nodes, and a
    // configured 'satellite' role clears a latched 'edge-ngfw'.
    sat.role = deriveSatelliteRole({ configuredRole: fleetNode?.role, currentRole: sat.role, satelliteId: sat.id });
    const isEdge = sat.role === 'edge-ngfw';

    const resolvedWanInterface = fleetNode?.wanInterface || sat.wanInterface || 'eth0';
    const resolvedLanInterface = fleetNode?.lanInterface || sat.lanInterface || 'eth1';
    const wanIpv6Mode =
      hostedEdge?.wan?.ipv6Mode || fleetNode?.ipv6Mode || 'auto';
    const lanIpv6Mode =
      hostedEdge?.lan?.ipv6Mode || fleetNode?.ipv6Mode || 'delegated';

    const mergedNode = {
      ...fleetNode,
      ...sat,
      role: sat.role,
      skuProfile: fleetNode?.skuProfile || sat.skuProfile || hostedEdge?.skuProfile || 'sku-vm-virtio',
      wanInterface: resolvedWanInterface,
      lanInterface: resolvedLanInterface,
      portForwards: fleetNode?.portForwards || hostedEdge?.portForwards || [],
      ipv6Allow: fleetNode?.ipv6Allow || hostedEdge?.ipv6Allow || [],
      zones: fleetNode?.zones || [],
      disabledIpv6Interfaces:
        fleetNode?.disabledIpv6Interfaces ||
        [
          ...(wanIpv6Mode === 'disabled' ? [resolvedWanInterface] : []),
          ...(lanIpv6Mode === 'disabled' ? [resolvedLanInterface] : []),
        ],
    };

    const { nftScript } = compileSatelliteNftables(mergedNode);
    sat.ws.send(
      JSON.stringify({
        type: 'SYNC_NFTABLES',
        payload: {
          script: nftScript,
        },
      }),
    );

    if (isEdge) {
      const wanDev = resolvedWanInterface;
      const lanDev = resolvedLanInterface;
      const wanAddress =
        fleetNode?.wanAddress ||
        (hostedEdge?.wan?.ipv4Mode === 'static' && hostedEdge.wan.ipv4Address
          ? hostedEdge.wan.ipv4Address
          : 'dhcp');
      const wanGateway =
        hostedEdge?.wan?.ipv4Mode === 'static' ? hostedEdge.wan.ipv4Gateway : undefined;
      const lanAddress =
        fleetNode?.lanAddress || hostedEdge?.lan?.edgeAddress || '10.0.0.1/24';

      const interfaces: Array<{
        name: string;
        device: string;
        address?: string;
        gateway?: string;
        ipv6Mode?: string;
        mtu: number;
        enabled: boolean;
      }> = [
        {
          name: 'wan',
          device: wanDev,
          address: wanAddress,
          ...(wanGateway ? { gateway: wanGateway } : {}),
          ipv6Mode: wanIpv6Mode,
          mtu: 1500,
          enabled: true,
        },
        {
          name: 'lan',
          device: lanDev,
          address: lanAddress,
          ipv6Mode: lanIpv6Mode,
          mtu: 1500,
          enabled: true,
        },
      ];

      if (Array.isArray(mergedNode.zones)) {
        for (const z of mergedNode.zones) {
          if (z && typeof z.vlanId === 'number' && z.ipv4Cidr) {
            interfaces.push({
              name: z.name,
              device: `${lanDev}.${z.vlanId}`,
              address: z.ipv4Cidr,
              ipv6Mode: z.ipv6Mode || 'delegated',
              mtu: 1500,
              enabled: true,
            });
          }
        }
      }

      sat.ws.send(
        JSON.stringify({
          type: 'SYNC_INTERFACES',
          payload: { interfaces },
        }),
      );

      const enabledRoutes = (localState?.routes ?? [])
        .filter((r) => r.enabled)
        .map((r) => ({
          destination: r.network,
          gateway: r.gateway,
          ...(r.interface ? { device: r.interface } : {}),
        }));
      sat.ws.send(
        JSON.stringify({
          type: 'SYNC_ROUTES',
          payload: { routes: enabledRoutes },
        }),
      );
    }
  }

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

const satFlowsCounter = new promClient.Counter({
  name: 'axonwall_satellite_flow_events_total',
  help: 'Total stateless conntrack flow and firewall log records streamed from Edge NGFWs',
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
  const port = parseInt(process.env.CONTROLLER_PORT || '2966', 10);
  let server: net.Server | http.Server;
  let mainServer: https.Server | http.Server;
  const requestHandler = (req: any, res: any) => {
    let pathname: string;
    try {
      pathname = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`).pathname;
    } catch {
      res.writeHead(400);
      res.end('Bad Request');
      return;
    }

    
    
    const verifyFleetAuth = (req: any, res: any): boolean => {
      if (fs.existsSync(caPath)) {
        const tlsSocket = req.socket as any;
        let peerCert: any = null;
        try { peerCert = tlsSocket?.getPeerCertificate?.(); } catch { peerCert = null; }
        if (tlsSocket && tlsSocket.authorized === false && peerCert && Object.keys(peerCert).length > 0) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized: invalid client certificate' }));
          return false;
        }
      }
      const token = (req.headers['x-axonwall-ztp-token'] || req.headers['authorization']?.replace(/^Bearer\s+/i, '')) as string;
      const expectedToken = process.env.AXONWALL_ZTP_TOKEN;
      if (!expectedToken) {
        // Fail closed in every environment: there is no hardcoded
        // fallback token. Developers can set AXONWALL_ZTP_TOKEN to
        // any value they like in their own environment.
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Fleet management authentication unconfigured' }));
        return false;
      }
      const isValid = token && token.length === expectedToken.length &&
        crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken));
      if (!isValid) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Valid X-Axonwall-ZTP-Token required' }));
        return false;
      }
      return true;
    };

    if (pathname === '/metrics' && req.method === 'GET') {
      // Metrics disclose fleet size, versions and traffic counters: they
      // require the fleet token or a CA-verified client certificate.
      const tlsSocket = req.socket as any;
      if (!(tlsSocket && tlsSocket.authorized === true) && !verifyFleetAuth(req, res)) return;
      prometheusRegistry.metrics().then((metricsStr) => {
        res.writeHead(200, { 'Content-Type': prometheusRegistry.contentType });
        res.end(metricsStr);
      }).catch(() => {
        if (!res.headersSent) {
          res.writeHead(500);
          res.end('Internal Server Error');
        }
      });
      return;
    }

    if (pathname === '/api/v1/fleet/flows' && req.method === 'GET') {
      if (!verifyFleetAuth(req, res)) return;
      const nodesData: Record<string, { flows: any[]; firewallLogs: any[]; lastSeen: string }> = {};
      for (const [id, sat] of activeSatellites.entries()) {
        nodesData[id] = {
          flows: sat.edgeFlows || [],
          firewallLogs: sat.edgeFirewallLogs || [],
          lastSeen: sat.lastSeen,
        };
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ nodes: nodesData }));
      return;
    }

    if (pathname === '/api/v1/fleet/block' && req.method === 'POST') {
      if (!verifyFleetAuth(req, res)) return;
      let body = '';
      let aborted = false;
      req.on('data', (chunk: any) => {
        if (aborted) return;
        body += chunk.toString();
        if (body.length > 65536) {
          aborted = true;
          res.writeHead(413, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Payload too large' }));
          req.destroy();
          return;
        }
      });
      req.on('end', () => {
        if (aborted) return;
        try {
          const payload = JSON.parse(body);
          const rawTarget = typeof payload.target === 'string' ? payload.target.trim() : '';
          const isMac = Boolean(payload.isMac);
          
          if (!rawTarget) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Missing target' }));
          }

          // Strict validation of block target to prevent nft syntax injection
          let target = rawTarget;
          if (isMac) {
            const macRegex = /^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$/;
            if (!macRegex.test(rawTarget)) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              return res.end(JSON.stringify({ error: 'Invalid MAC address target' }));
            }
            target = rawTarget.toLowerCase().replace(/-/g, ':');
          } else {
            const slashParts = rawTarget.split('/');
            if (slashParts.length > 2) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              return res.end(JSON.stringify({ error: 'Invalid IP address or CIDR target' }));
            }
            const ipPart = slashParts[0] || '';
            const prefixStr = slashParts[1];
            const ipFamily = net.isIP(ipPart);
            if (ipFamily !== 4 && ipFamily !== 6) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              return res.end(JSON.stringify({ error: 'Invalid IP address or CIDR target' }));
            }
            if (prefixStr !== undefined) {
              if (!/^\d{1,3}$/.test(prefixStr)) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ error: 'Invalid CIDR prefix length' }));
              }
              const prefixNum = Number(prefixStr);
              const maxPrefix = ipFamily === 4 ? 32 : 128;
              if (prefixNum < 0 || prefixNum > maxPrefix) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ error: 'Invalid CIDR prefix length' }));
              }
            }
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
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
      });
      return;
    }

    if (pathname === '/api/v1/fleet/satellites' && req.method === 'GET') {
      if (!verifyFleetAuth(req, res)) return;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      // Exclude ws and wgPrivateKey from JSON
      const satellitesData = Array.from(activeSatellites.values()).map(s => {
        const { ws, wgPrivateKey, ...rest } = s;
        return rest;
      });
      res.end(JSON.stringify({
        totalConnected: Array.from(activeSatellites.values()).filter(s => s.ws && s.ws.readyState === WebSocket.OPEN).length,
        totalEnrolled: activeSatellites.size,
        satellites: satellitesData,
      }));
      return;
    }

    if (pathname === '/api/v1/fleet/ha-transition' && req.method === 'POST') {
      if (!verifyFleetAuth(req, res)) return;
      let body = '';
      let aborted = false;
      req.on('data', (chunk: any) => {
        if (aborted) return;
        body += chunk.toString();
        if (body.length > 65536) {
          aborted = true;
          res.writeHead(413, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Payload too large' }));
          req.destroy();
          return;
        }
      });
      req.on('end', () => {
        if (aborted) return;
        try {
          const payload = body ? JSON.parse(body) : {};
          // B-H2a/B-M6: validate role/MAC/VIP before any broadcast;
          // the fleet LAN address is the only non-explicit VIP source.
          const fleetLanVip = loadLocalDesiredState()?.hostedEdge?.lan?.edgeAddress;
          const validation = validateHaTransition(payload, fleetLanVip);
          if (!validation.ok) {
            res.writeHead(validation.status || 400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: validation.error }));
            return;
          }
          const msgType = validation.transition!;
          const normalizedRole = validation.role!;
          const sharedWanMac = validation.sharedWanMac;
          const lanVip = validation.lanVip;
          const targetId = validation.satelliteId || '';

          const sendTransition = (sat: SatelliteState, type: 'PROMOTE' | 'DEMOTE', role: 'active' | 'standby'): boolean => {
            if (!sat.ws || sat.ws.readyState !== WebSocket.OPEN) return false;
            // The satellite's EdgeHATransitionPayload reads lanVipV4
            // (lanVip is kept for backward compatibility with any
            // consumer that still reads the old field name).
            sat.ws.send(
              JSON.stringify({
                type,
                payload: {
                  role,
                  sharedWanMac,
                  lanVip,
                  lanVipV4: lanVip,
                },
              }),
            );
            return true;
          };

          // B-M6: a named target that matches no connected satellite
          // must not report success with zero notified.
          if (targetId) {
            const target = activeSatellites.get(targetId);
            if (!target || !target.ws || target.ws.readyState !== WebSocket.OPEN) {
              res.writeHead(404, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ success: false, error: `No connected satellite matches satelliteId "${targetId}"`, notifiedEdges: 0 }));
              return;
            }
            let demoted = 0;
            // B-H2b: demote the previously active edge before
            // promoting the new one, so two edges never hold the
            // same VIP / shared WAN MAC at once.
            if (msgType === 'PROMOTE' && activeHaEdgeId && activeHaEdgeId !== targetId) {
              const previous = activeSatellites.get(activeHaEdgeId);
              if (previous && sendTransition(previous, 'DEMOTE', 'standby')) demoted++;
            }
            const notified = sendTransition(target, msgType, normalizedRole) ? 1 : 0;
            if (msgType === 'PROMOTE' && notified === 1) activeHaEdgeId = targetId;
            if (msgType === 'DEMOTE' && activeHaEdgeId === targetId) activeHaEdgeId = null;
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, transition: msgType, role: normalizedRole, notifiedEdges: notified, demotedEdges: demoted }));
            return;
          }

          // Untargeted DEMOTE is the safe direction (stand down all
          // edges); untargeted PROMOTE is unreachable here because
          // validation requires a satelliteId for PROMOTE.
          let notified = 0;
          for (const sat of activeSatellites.values()) {
            const isTarget = sat.role === 'edge-ngfw' || sat.id.startsWith('edge-') || sat.id === 'edge';
            if (isTarget && sendTransition(sat, msgType, normalizedRole)) notified++;
          }
          if (msgType === 'DEMOTE') activeHaEdgeId = null;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, transition: msgType, role: normalizedRole, notifiedEdges: notified }));
        } catch {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
      });
      return;
    }

    if (pathname === '/api/v1/fleet/sync' && req.method === 'POST') {
      if (!verifyFleetAuth(req, res)) return;
      let body = '';
      let aborted = false;
      req.on('data', (chunk: any) => {
        if (aborted) return;
        body += chunk.toString();
        if (body.length > 524288) {
          aborted = true;
          res.writeHead(413, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Payload too large' }));
          req.destroy();
          return;
        }
      });
      req.on('end', () => {
        if (aborted) return;
        // B-H1: validate the body before syncing anything. A 400 here
        // means no satellite was synced.
        const validation = parseFleetSyncBody(body);
        if (!validation.ok) {
          res.writeHead(validation.status, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: validation.error }));
          return;
        }
        const desired = validation.desired;
        let synced = 0;
        for (const sat of activeSatellites.values()) {
          if (sat.ws && sat.ws.readyState === WebSocket.OPEN) {
            syncSatelliteDesiredState(sat, desired);
            synced++;
          }
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, syncedSatellites: synced }));
      });
      return;
    }

    // ========================================================================
    // Security AI / VigilSOC Model Context Protocol (MCP) Endpoint (/api/v1/mcp)
    // ========================================================================
    if (pathname === '/api/v1/mcp' || pathname === '/api/v1/mcp/sse') {
      const serverStatus = getMcpServerStatus();
      if (!serverStatus.enabled) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: {
            code: -32000,
            message: serverStatus.disabledReason || 'Axonwall MCP server is disabled by administrator policy',
          },
        }));
        return;
      }

      const authHeader = (req.headers.authorization || '').trim();
      const rawToken = authHeader.toLowerCase().startsWith('bearer ')
        ? authHeader.slice(7).trim()
        : ((req.headers['x-axonwall-mcp-token'] as string) || '').trim();
      const clientIp = (req.socket?.remoteAddress || '127.0.0.1').replace(/^::ffff:/i, '');

      const authRes = authenticateMcpToken(rawToken, clientIp, req);
      if (!authRes.authenticated || !authRes.key) {
        recordMcpAuditEntry({
          keyId: authRes.key?.id ?? 'unauthenticated',
          keyName: authRes.key?.name ?? 'unauthenticated',
          agentType: authRes.key?.agentType ?? 'unknown',
          clientIp,
          toolName: `http:${req.method}:${pathname}`,
          requiredScope: 'mcp:auth',
          decision: 'denied',
          denialReason: authRes.errorMessage || 'Authentication failed',
          paramsSummary: { pathname, method: req.method },
        });
        res.writeHead(authRes.errorStatus || 401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32001, message: authRes.errorMessage || 'Unauthorized MCP request' },
        }));
        return;
      }

      const authenticatedKey = authRes.key;

      if (req.method === 'GET') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
        });
        res.write(`event: endpoint\ndata: /api/v1/mcp\n\n`);
        const keepAlive = setInterval(() => {
          if (!res.writableEnded) {
            res.write(`: ping ${Date.now()}\n\n`);
          }
        }, 15000);
        req.on('close', () => clearInterval(keepAlive));
        return;
      }

      if (req.method === 'POST') {
        let body = '';
        let aborted = false;
        req.on('data', (chunk: any) => {
          if (aborted) return;
          body += chunk.toString();
          if (body.length > 262144) {
            aborted = true;
            res.writeHead(413, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Payload too large' } }));
            req.destroy();
          }
        });
        req.on('end', async () => {
          if (aborted) return;
          try {
            const rpcPayload = JSON.parse(body) as JsonRpcRequest;
            const rpcResp = await processMcpJsonRpcMessage(rpcPayload, {
              key: authenticatedKey,
              clientIp,
              onFleetBroadcastBlock: (targetIp: string) => {
                let notified = 0;
                for (const sat of activeSatellites.values()) {
                  if (sat.ws && sat.ws.readyState === WebSocket.OPEN) {
                    sat.ws.send(JSON.stringify({
                      type: 'BLOCK_TARGET',
                      payload: { target: targetIp, isMac: false },
                    }));
                    notified++;
                  }
                }
                return notified;
              },
            });
            if (!rpcResp) {
              res.writeHead(202);
              res.end();
              return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(rpcResp));
          } catch {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              jsonrpc: '2.0',
              id: null,
              error: { code: -32700, message: 'Invalid JSON-RPC payload' },
            }));
          }
        });
        return;
      }

      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Method Not Allowed' }));
      return;
    }

    // Reverse proxy all other HTTP traffic to the Axonwall Web Console on port 3000
    // Use the actual Host requested on this reverse proxy; never overwrite with client-supplied Origin
    const forwardedHost = req.headers.host || (req.headers['x-forwarded-host'] as string) || 'localhost';
    // B-L3: the proxied request used to have no timeout and only
    // propagated mid-request aborts, so a wedged UI accumulated
    // sockets forever and responses kept generating for dead clients.
    let upstreamRes: http.IncomingMessage | null = null;
    let proxyTimedOut = false;
    const destroyUpstream = () => {
      try { uiReq.destroy(); } catch {}
      try { upstreamRes?.destroy(); } catch {}
    };
    const uiReq = http.request({
      hostname: '127.0.0.1',
      port: uiPort,
      path: req.url,
      method: req.method,
      headers: {
        ...req.headers,
        'x-forwarded-proto': (req.headers['x-forwarded-proto'] as string) || (req.socket?.encrypted ? 'https' : 'http'),
        'x-forwarded-host': forwardedHost,
        'x-forwarded-for': req.socket?.remoteAddress || '127.0.0.1',
      },
    }, (uiRes) => {
      upstreamRes = uiRes;
      res.writeHead(uiRes.statusCode || 200, uiRes.headers);
      uiRes.pipe(res);
    });

    // 30s upstream timeout: destroy the upstream request and answer
    // 502 (or destroy the client response if headers already went).
    uiReq.setTimeout(30000, () => {
      proxyTimedOut = true;
      destroyUpstream();
      if (res.headersSent) {
        res.destroy();
        return;
      }
      try {
        res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Bad Gateway: web console upstream timed out');
      } catch {
        res.destroy();
      }
    });

    req.on('aborted', destroyUpstream);
    // A client disconnect after the response started must also kill
    // the upstream request/response, not just a mid-request abort.
    res.on('close', destroyUpstream);

    uiReq.on('error', () => {
      // The timeout path above already answered; do not double-send.
      if (proxyTimedOut) return;
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

  const tlsConfig = ensureControllerTls(certPath, keyPath, caPath);

  if (tlsConfig) {
    console.log(`[Axonwall Controller] Starting in SECURE mTLS mode (HTTP auto-upgrade enabled on port ${port})`);
    const httpsServer = https.createServer({
      cert: tlsConfig.cert,
      key: tlsConfig.key,
      ca: tlsConfig.ca ? tlsConfig.ca : undefined,
      requestCert: true,
      // Client certificates are enforced per-path, not at the TLS layer:
      // this listener is shared by the web console (browsers have no
      // client cert) and by satellites that only receive their cert
      // during ZTP provisioning, as well as MCP clients using mTLS
      // fingerprint pinning. Fleet paths verify instead: /ws/satellite
      // requires socket.authorized when a CA exists, and the fleet HTTP
      // API rejects presented-but-invalid certificates (verifyFleetAuth).
      rejectUnauthorized: false
    }, requestHandler);

    const redirectServer = createHttpRedirectServer(port);
    const tcpMultiplexer = createPortMultiplexer(httpsServer, redirectServer);

    mainServer = httpsServer;
    server = tcpMultiplexer;
  } else {
    console.warn('[Axonwall Controller] WARNING: Starting in INSECURE HTTP mode (Plaintext HTTP enabled)');
    mainServer = http.createServer(requestHandler);
    server = mainServer;
  }

  const wss = new WebSocketServer({ noServer: true, maxPayload: 1048576 });

  mainServer.on('upgrade', (request, socket, head) => {
    let pathname: string;
    try {
      pathname = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`).pathname;
    } catch {
      socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
      socket.destroy();
      return;
    }
    
    if (pathname === '/ws/satellite') {
      // Basic ZTP token validation
      const satId = (request.headers['x-axonwall-satellite-id'] as string || '').trim();
      const token = request.headers['x-axonwall-ztp-token'] as string;

      if (!satId || !token) {
        console.log(`[Fleet Manager] Rejected connection: missing ZTP headers`);
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }

      // Validate satellite ID syntax to prevent Prometheus label cardinality explosion / injection
      if (!/^[a-zA-Z0-9._-]{1,64}$/.test(satId)) {
        console.log(`[Fleet Manager] Rejected connection: invalid satellite ID syntax: ${satId}`);
        socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
        socket.destroy();
        return;
      }

      const expectedToken = process.env.AXONWALL_ZTP_TOKEN;
      if (!expectedToken) {
        // Fail closed in every environment (no hardcoded fallback token).
        console.log(`[Fleet Manager] Rejected connection: AXONWALL_ZTP_TOKEN not configured`);
        socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
        socket.destroy();
        return;
      }

      const isTokenValid = token.length === expectedToken.length &&
        crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken));

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

      // B-M1: fleet-cap eviction runs ONLY for authenticated
      // connections. Previously it ran before the token/CA checks, so
      // unauthenticated probes could evict disconnected satellites'
      // state (WireGuard keys, tunnel IP, headscale flag) with no
      // valid credential at all.
      if (!activeSatellites.has(satId) && activeSatellites.size >= 500) {
        let oldestDisconnectedId: string | null = null;
        let oldestTime = Infinity;

        for (const [id, sat] of activeSatellites.entries()) {
          if (!sat.ws) {
            const seenTime = Date.parse(sat.lastSeen) || 0;
            if (seenTime < oldestTime) {
              oldestTime = seenTime;
              oldestDisconnectedId = id;
            }
          }
        }

        if (oldestDisconnectedId) {
          try {
            satUptimeGauge.remove({ satellite_id: oldestDisconnectedId });
            satCpuGauge.remove({ satellite_id: oldestDisconnectedId });
            satMemGauge.remove({ satellite_id: oldestDisconnectedId });
            satConnsGauge.remove({ satellite_id: oldestDisconnectedId });
            // B-M3: the rx/tx/flows counters were never removed here
            // (or on close), so evicted series leaked forever and a
            // reconnect restarted the delta from zero, double-counting
            // the satellite's lifetime bytes.
            satRxBytesGauge.remove({ satellite_id: oldestDisconnectedId });
            satTxBytesGauge.remove({ satellite_id: oldestDisconnectedId });
            satFlowsCounter.remove({ satellite_id: oldestDisconnectedId });
          } catch {
            // Metrics might already have been removed
          }
          lastRxTxBytes.delete(oldestDisconnectedId);
          activeSatellites.delete(oldestDisconnectedId);
          console.log(`[Fleet Manager] Evicted stale disconnected satellite ${oldestDisconnectedId} to make room for ${satId}`);
        } else {
          console.log(`[Fleet Manager] Rejected connection: fleet size limit reached (500 active satellites)`);
          socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
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

      // B-M2: only satellites with an OPEN socket are live peers.
      // Previously every registry entry — including satellites dead
      // for months — was broadcast forever, wasting handshakes and
      // risking traffic to a reassigned IP.
      const peers = allSats
        .filter(p => p.id !== sat.id && p.ws && p.ws.readyState === WebSocket.OPEN)
        .map(p => {
          const formattedIp = p.ip && p.ip.includes(':') && !p.ip.startsWith('[') ? `[${p.ip}]` : p.ip;
          return {
            publicKey: p.wgPublicKey,
            endpoint: `${formattedIp}:51820`, // Assuming they are reachable on their public IP on 51820
            allowedIps: `${p.tunnelIp!.split('/')[0]}/32`, // Only route their tunnel IP for the mesh
            keepAliveSec: 25,
          };
        });

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

  // B-M2: one fleet-wide timer prunes disconnected entries after the
  // grace period instead of retaining them until the 500-entry cap.
  const meshPruneTimer = setInterval(() => {
    const now = Date.now();
    for (const [id, sat] of activeSatellites.entries()) {
      if (!sat.ws && shouldPruneDisconnectedSatellite(sat.disconnectedAt, now)) {
        activeSatellites.delete(id);
        console.log(`[Fleet Manager] Pruned disconnected satellite ${id} after the mesh grace period`);
      }
    }
  }, 60 * 1000);
  meshPruneTimer.unref?.();

  wss.on('connection', async (ws: WebSocket, request: http.IncomingMessage, satId: string) => {
    const remoteIp = request.socket.remoteAddress || '127.0.0.1';
    console.log(`[Fleet Manager] Satellite Enrolled & Connected: ${satId} from ${remoteIp}`);

    const existing = activeSatellites.get(satId);
    if (existing?.ws && existing.ws !== ws) {
      try {
        existing.ws.terminate();
      } catch {
        // Ignore termination errors
      }
      lastRxTxBytes.delete(satId);
    }

    let wgPrivateKey = existing?.wgPrivateKey;
    let wgPublicKey = existing?.wgPublicKey;
    if (!wgPrivateKey || !wgPublicKey) {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
      const rawPriv = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32);
      const rawPub = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
      wgPrivateKey = rawPriv.toString('base64');
      wgPublicKey = rawPub.toString('base64');
    }

    let tunnelIp = existing?.tunnelIp;
    if (!tunnelIp) {
      const usedIps = new Set(Array.from(activeSatellites.values()).map(s => s.tunnelIp?.split('/')[0]).filter(Boolean));
      for (let thirdOctet = 0; thirdOctet <= 255 && !tunnelIp; thirdOctet++) {
        for (let fourthOctet = thirdOctet === 0 ? 2 : 1; fourthOctet <= 254; fourthOctet++) {
          const candidate = `10.99.${thirdOctet}.${fourthOctet}`;
          if (!usedIps.has(candidate)) {
            tunnelIp = `${candidate}/16`;
            break;
          }
        }
      }
      if (!tunnelIp) {
        const idx = ipCounter++;
        const thirdOctet = Math.floor(idx / 250) % 256;
        const fourthOctet = (idx % 250) + 2;
        tunnelIp = `10.99.${thirdOctet}.${fourthOctet}/16`;
      }
    }

    const state: SatelliteState = {
      id: satId,
      connectedAt: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      role: existing?.role || (satId.startsWith('edge-') || satId === 'edge' ? 'edge-ngfw' : 'satellite'),
      skuProfile: existing?.skuProfile,
      wanInterface: existing?.wanInterface,
      lanInterface: existing?.lanInterface,
      fastpathOffload: existing?.fastpathOffload,
      ip: remoteIp.replace(/^::ffff:/, ''),
      arch: (request.headers['user-agent']?.includes('arm') ? 'arm64' : 'amd64'),
      wgPrivateKey,
      wgPublicKey,
      tunnelIp,
      wireguard: { tunnelIp },
      ws: ws,
      headscaleEnrolled: existing?.headscaleEnrolled || false,
    };
    activeSatellites.set(satId, state);

    // Register event listeners immediately before any async provisioning
    ws.on('message', (message) => {
      state.lastSeen = new Date().toISOString();
      try {
        const text = message.toString();
        const parsed = JSON.parse(text);
        if (parsed.type === 'REQUEST_HEADSCALE') {
          // B-H4: satellite-initiated re-provision (e.g. a satellite
          // wiped/reimaged under the same ID, whose latched
          // headscaleEnrolled flag would otherwise never re-send
          // credentials). Runs even when the flag is latched.
          void requestHeadscaleProvision();
        } else if (parsed.type === 'TELEMETRY_REPORT') {
          let report: any;
          if (typeof parsed.payload === 'string') {
              report = JSON.parse(parsed.payload);
          } else {
              report = parsed.payload;
          }
          // B-L1: a report without metrics used to throw on the log
          // line below (unguarded report.metrics access), which the
          // outer catch swallowed — dropping the whole report, wiping
          // the last-known metrics, and suppressing the PING reply.
          // Skip the metrics block with a warning instead, and always
          // send PING for a well-formed report.
          if (!report || typeof report !== 'object') {
            return;
          }
          if (report.metrics) {
            state.metrics = report.metrics;
            // B-M5: telemetry is only a fallback signal for nodes with
            // no configured fleet role (see deriveSatelliteRole). A
            // configured role wins over telemetry, and when pid1Mode
            // stops being reported the latched edge role is cleared
            // instead of sticking forever.
            const fleetNode = loadLocalDesiredState()?.fleet?.nodes?.find((n) => n.id === satId);
            state.role = deriveSatelliteRole({
              configuredRole: fleetNode?.role,
              currentRole: state.role,
              satelliteId: satId,
              pid1ModeReported: Boolean(report.metrics.pid1Mode),
            });
            if (report.metrics?.skuProfile) {
              state.skuProfile = report.metrics.skuProfile;
            }
            console.log(
              `[Fleet Manager] Telemetry from ${satId}: CPU ${Number(report.metrics?.cpuUsagePercent ?? 0).toFixed(1)}% | RAM ${Number(report.metrics?.memUsagePercent ?? 0).toFixed(1)}% | Active Conns: ${report.metrics?.activeConns}`
            );

            // Update Prometheus metrics
            satUptimeGauge.set({ satellite_id: satId }, Number(report.metrics.uptimeSeconds) || 0);
            satCpuGauge.set({ satellite_id: satId }, Number(report.metrics.cpuUsagePercent) || 0);
            satMemGauge.set({ satellite_id: satId }, Number(report.metrics.memUsagePercent) || 0);
            satConnsGauge.set({ satellite_id: satId }, Number(report.metrics.activeConns) || 0);

            // Handle counter increments safely (including counter reset across satellite reboot)
            const currentRx = Number(report.metrics.rxBytesTotal) || 0;
            const currentTx = Number(report.metrics.txBytesTotal) || 0;
            const last = lastRxTxBytes.get(satId) || { rx: 0, tx: 0 };

            const rxDelta = currentRx >= last.rx ? currentRx - last.rx : currentRx;
            const txDelta = currentTx >= last.tx ? currentTx - last.tx : currentTx;
            if (rxDelta > 0) satRxBytesGauge.inc({ satellite_id: satId }, rxDelta);
            if (txDelta > 0) satTxBytesGauge.inc({ satellite_id: satId }, txDelta);

            lastRxTxBytes.set(satId, { rx: currentRx, tx: currentTx });
          } else {
            console.log(`[Fleet Manager] Telemetry from ${satId} without metrics; keeping last-known metrics.`);
          }

          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'PING', payload: {} }));
          }
        } else if (parsed.type === 'EDGE_FLOW_BATCH') {
          const batch = typeof parsed.payload === 'string' ? JSON.parse(parsed.payload) : parsed.payload;
          if (Array.isArray(batch?.flows)) {
            state.edgeFlows = batch.flows.slice(0, 100);
            satFlowsCounter.inc({ satellite_id: satId }, batch.flows.length);
          }
          if (Array.isArray(batch?.firewallLogs) && batch.firewallLogs.length > 0) {
            const existingLogs = state.edgeFirewallLogs || [];
            state.edgeFirewallLogs = [...batch.firewallLogs, ...existingLogs].slice(0, 100);
            satFlowsCounter.inc({ satellite_id: satId }, batch.firewallLogs.length);
          }
        }
      } catch {
        // Ping or non-JSON message
      }
    });

    ws.on('close', () => {
      console.log(`[Fleet Manager] Satellite Disconnected: ${satId}`);
      const current = activeSatellites.get(satId);
      if (current?.ws === ws) {
        satUptimeGauge.remove({ satellite_id: satId });
        satCpuGauge.remove({ satellite_id: satId });
        satMemGauge.remove({ satellite_id: satId });
        satConnsGauge.remove({ satellite_id: satId });
        // B-M3: remove the counters like the gauges. Otherwise the
        // next telemetry report after a reconnect increments the
        // persistent counter by the satellite's entire lifetime total
        // again, because lastRxTxBytes restarts at zero.
        satRxBytesGauge.remove({ satellite_id: satId });
        satTxBytesGauge.remove({ satellite_id: satId });
        satFlowsCounter.remove({ satellite_id: satId });
        lastRxTxBytes.delete(satId);
        current.ws = undefined;
        // B-M2: timestamp the disconnect for grace-period pruning.
        current.disconnectedAt = new Date().toISOString();
        if (activeHaEdgeId === satId) activeHaEdgeId = null;
        broadcastMeshTopology();
      }
    });

    // 1. Headscale ZTP Identity Provisioning (only on initial enrollment / if not already enrolled)
    // B-H4: previously a single attempt per controller lifetime — any
    // failure was only logged, with no retry and no re-trigger, and a
    // reconnecting satellite kept its latched headscaleEnrolled flag
    // forever. Now provisioning retries on bounded backoff while the
    // socket is open, and it is NOT awaited: the initial ruleset sync
    // below must not wait out up to ~110s of backoff.
    const provisionHeadscale = () => provisionHeadscaleWithRetry({
      listUsers,
      createUser,
      createPreAuthKey,
      serverUrl: process.env.HEADSCALE_EXTERNAL_URL || 'https://hub.axonwall.local',
      send: (msg) => {
        if (ws.readyState !== WebSocket.OPEN) throw new Error('satellite socket closed before SYNC_HEADSCALE could be sent');
        ws.send(JSON.stringify(msg));
      },
      isOpen: () => ws.readyState === WebSocket.OPEN,
    });
    let headscaleProvisioning: Promise<boolean> | null = null;
    const requestHeadscaleProvision = (): Promise<boolean> => {
      if (headscaleProvisioning) return headscaleProvisioning;
      headscaleProvisioning = provisionHeadscale().then((ok) => {
        // On failure the flag clears, so the next connect retries
        // automatically; on success the satellite is enrolled.
        state.headscaleEnrolled = ok;
        headscaleProvisioning = null;
        if (ok) console.log(`[Fleet Manager] Dispatched Headscale ZTP credentials to ${satId}`);
        else console.error(`[Fleet Manager] Headscale provisioning for ${satId} exhausted its retries; it will retry on reconnect or on a REQUEST_HEADSCALE message`);
        return ok;
      });
      return headscaleProvisioning;
    };
    if (!state.headscaleEnrolled) {
      void requestHeadscaleProvision();
    }

    // 2. Push initial compiled nftables ruleset (and SYNC_INTERFACES / SYNC_ROUTES for edge-ngfw)
    if (ws.readyState === WebSocket.OPEN) {
      syncSatelliteDesiredState(state);
    }

    // 3. Broadcast mesh update to all satellites (including the new one)
    broadcastMeshTopology();
  });

  server.listen(port, '0.0.0.0', () => {
    console.log(`[Axonwall Controller] Fleet Manager listening on 0.0.0.0:${port}`);
  });
}

const isDirectExecution = () => {
  if (process.env.NODE_ENV === 'test') return false;
  try {
    return !!process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
  } catch {
    return false;
  }
};

if (isDirectExecution()) {
  main().catch((err) => {
    console.error('[Axonwall Controller] Fatal error:', err);
    process.exit(1);
  });
}
