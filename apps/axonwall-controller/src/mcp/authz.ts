import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type * as http from 'node:http';
import {
  McpApiKeySchema,
  McpPolicyLimitsSchema,
  isIpInCidr,
  isMcpServerEnabled,
  getMcpServerStatus,
  type McpApiKey,
  type McpApiKeyPublic,
  type McpPolicyLimits,
  type McpScope,
} from '@axonwall/lib/mcp';
import { acquireMcpLockFile } from './lockfile.js';
import { resolveControllerDirs } from '../dev-paths.js';
import { readCanonicalConfig, writeCanonicalConfig, writeFileAtomicSync } from '../atomic-config.js';

// R4-B-L2: the per-key sliding-window budget used to live only in
// this module-level map, so every fresh axonwall-mcp stdio process
// started with a full budget and the limit was unenforced on the
// stdio transport. Buckets are now persisted to a state file under
// the controller var dir (atomic write, short lock) and reloaded
// whenever the file changes, so the budget survives across stdio
// process invocations. The in-process map stays as a cache only.
const rateLimitBuckets = new Map<string, number[]>();
let rateLimitDiskMtimeMs = -1;
let rateLimitDiskLoaded = false;

export function resolveMcpRateLimitPath(): string {
  if (process.env.AXONWALL_MCP_RATE_LIMIT_PATH) {
    return process.env.AXONWALL_MCP_RATE_LIMIT_PATH;
  }
  return path.join(resolveControllerDirs().varDir, 'mcp-rate-limits.json');
}

function parseRateLimitState(raw: string): Record<string, number[]> | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    const out: Record<string, number[]> = {};
    for (const [keyId, stamps] of Object.entries(parsed as Record<string, unknown>)) {
      if (!Array.isArray(stamps)) continue;
      const valid = (stamps as unknown[]).filter(
        (ts): ts is number => typeof ts === 'number' && Number.isFinite(ts)
      );
      if (valid.length > 0) out[keyId] = valid;
    }
    return out;
  } catch {
    return null;
  }
}

function loadRateLimitStateFromDisk(): Record<string, number[]> {
  const statePath = resolveMcpRateLimitPath();
  try {
    if (!fs.existsSync(statePath)) return {};
    const parsed = parseRateLimitState(fs.readFileSync(statePath, 'utf8'));
    if (parsed === null) {
      console.warn(`[MCP RateLimit] Ignoring corrupt rate-limit state file ${statePath}; starting from an empty budget.`);
      return {};
    }
    try {
      rateLimitDiskMtimeMs = fs.statSync(statePath).mtimeMs;
    } catch {}
    rateLimitDiskLoaded = true;
    return parsed;
  } catch (err: any) {
    console.warn(`[MCP RateLimit] Could not read rate-limit state file ${statePath} (${err?.message || err}); starting from an empty budget.`);
    return {};
  }
}

function persistRateLimitState(): boolean {
  const statePath = resolveMcpRateLimitPath();
  const now = Date.now();
  const windowStart = now - 60_000;
  const snapshot: Record<string, number[]> = {};
  for (const [keyId, stamps] of rateLimitBuckets.entries()) {
    const kept = stamps.filter((ts) => ts > windowStart);
    if (kept.length > 0) snapshot[keyId] = kept;
  }
  // Best-effort durability: the limit still holds in-process when
  // the disk write fails, but the budget then does not survive a
  // process restart — so a failure is logged loudly, never silent.
  let release: (() => void) | null = null;
  try {
    release = acquireMcpLockFile(`${statePath}.lock`, 2000);
  } catch (err: any) {
    console.warn(`[MCP RateLimit] Could not lock rate-limit state file ${statePath} (${err?.message || err}); budget kept in memory only for this process.`);
    return false;
  }
  try {
    writeFileAtomicSync(statePath, JSON.stringify(snapshot, null, 2), 0o660);
    try {
      rateLimitDiskMtimeMs = fs.statSync(statePath).mtimeMs;
    } catch {}
    rateLimitDiskLoaded = true;
    return true;
  } catch (err: any) {
    console.warn(`[MCP RateLimit] Failed to persist rate-limit state to ${statePath} (${err?.message || err}); budget kept in memory only for this process.`);
    return false;
  } finally {
    try {
      release?.();
    } catch {}
  }
}

/** Refresh the in-process cache from disk when another process changed the file. */
function refreshRateLimitBucketsFromDisk(): void {
  const statePath = resolveMcpRateLimitPath();
  let mtimeMs = -1;
  try {
    if (!fs.existsSync(statePath)) return;
    mtimeMs = fs.statSync(statePath).mtimeMs;
  } catch {
    return;
  }
  if (rateLimitDiskLoaded && mtimeMs === rateLimitDiskMtimeMs) return;
  const disk = loadRateLimitStateFromDisk();
  const now = Date.now();
  const windowStart = now - 60_000;
  for (const [keyId, stamps] of Object.entries(disk)) {
    const merged = Array.from(
      new Set([...(rateLimitBuckets.get(keyId) ?? []), ...stamps])
    ).filter((ts) => ts > windowStart);
    rateLimitBuckets.set(keyId, merged);
  }
}

// R4-B-M1: the canonical mcp-keys.json path. There is exactly one:
// the env override when set, otherwise <varDir>/mcp-keys.json. The
// old resolver returned a mirror copy (persistYamlDir / etcDir)
// whenever the primary was unreadable, and the loader took the
// first candidate that parsed — so a stale mirror could defeat a
// revocation. Reads and writes now go through this path only; see
// readCanonicalConfig / writeCanonicalConfig.
export function resolveMcpKeysPath(): string {
  if (process.env.AXONWALL_MCP_KEYS_PATH) {
    return process.env.AXONWALL_MCP_KEYS_PATH;
  }
  return path.join(resolveControllerDirs().varDir, 'mcp-keys.json');
}

/** Mirror copies, written best-effort after the canonical write. Never read. */
function mcpKeysMirrorPaths(): string[] {
  if (process.env.AXONWALL_MCP_KEYS_PATH) return [];
  const dirs = resolveControllerDirs();
  return [
    path.join(dirs.persistYamlDir, 'mcp-keys.json'),
    path.join(dirs.etcDir, 'mcp-keys.json'),
  ];
}

function parseMcpKeysFile(raw: string): McpApiKey[] | null {
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return null;
    const valid: McpApiKey[] = [];
    for (const item of parsed) {
      const res = McpApiKeySchema.safeParse(item);
      if (res.success) {
        valid.push(res.data);
      }
    }
    return valid;
  } catch {
    return null;
  }
}

function loadMcpKeysInternal(): McpApiKey[] {
  return (
    readCanonicalConfig({
      canonicalPath: resolveMcpKeysPath(),
      mirrorPaths: mcpKeysMirrorPaths(),
      parse: parseMcpKeysFile,
      label: 'mcp-keys.json',
    }) ?? []
  );
}

function saveMcpKeysInternal(keys: McpApiKey[]): void {
  // Throws when the canonical write fails: a revocation or disable
  // that did not land must never report success.
  writeCanonicalConfig({
    canonicalPath: resolveMcpKeysPath(),
    mirrorPaths: mcpKeysMirrorPaths(),
    serialized: JSON.stringify(keys, null, 2),
    mode: 0o660,
    label: 'mcp-keys.json',
  });
}

/**
 * Re-read the canonical keys file and confirm the mutation landed.
 * A write that reported success but is not visible on re-read (disk
 * error after rename, wrong path, concurrent clobber) is a failed
 * revocation/disable, not a success.
 */
function verifyMcpKeysMutation(check: (keys: McpApiKey[]) => boolean, what: string): void {
  if (!check(loadMcpKeysInternal())) {
    throw new Error(
      `mcp-keys.json mutation did not land on re-read of the canonical file (${resolveMcpKeysPath()}): ${what}. ` +
        `Treat the change as NOT applied.`
    );
  }
}

export function hashMcpToken(rawToken: string): string {
  return crypto.createHash('sha256').update(rawToken.trim()).digest('hex');
}

// B-S1: last-used metadata lives in a sidecar file next to the keys
// file (<keys>.lastused.json), keyed by key id. Authentication used
// to rewrite the whole mcp-keys.json on every request to record
// lastUsedAt; a request that loaded the list before a revocation
// and saved after it resurrected the revoked key (and could drop a
// concurrently created key). Authentication now only reads the keys
// file and writes this sidecar, so it can never resurrect a key.
// The sidecar is anchored to the resolved primary keys path.
interface LastUsedEntry {
  lastUsedAt: string;
  lastUsedIp: string;
}

function readLastUsedSidecar(keysPath: string): Record<string, LastUsedEntry> {
  try {
    const raw = fs.readFileSync(`${keysPath}.lastused.json`, 'utf8');
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, LastUsedEntry>;
    }
  } catch {
    // Missing or corrupt sidecar: metadata is best-effort.
  }
  return {};
}

function writeLastUsedSidecar(keysPath: string, keyId: string, entry: LastUsedEntry): void {
  // B-L2: this used to be an unlocked read-modify-write of a shared
  // file, so two concurrent authentications for different keys both
  // read, both added their entry, and the last writer silently
  // dropped the other's lastUsedAt/lastUsedIp. Hold a dedicated lock
  // across the read + rename. The timeout is short on purpose: this
  // is best-effort metadata updated on every authentication, so a
  // lock that cannot be taken quickly is skipped, not waited on.
  let release: (() => void) | null = null;
  try {
    try {
      release = acquireMcpLockFile(`${keysPath}.lastused.json.lock`, 2000);
    } catch {
      return;
    }
    const sidecarPath = `${keysPath}.lastused.json`;
    const all = readLastUsedSidecar(keysPath);
    all[keyId] = entry;
    fs.mkdirSync(path.dirname(sidecarPath), { recursive: true, mode: 0o775 });
    const tmpPath = `${sidecarPath}.tmp.${process.pid}.${crypto.randomUUID()}`;
    fs.writeFileSync(tmpPath, JSON.stringify(all, null, 2), { mode: 0o660 });
    fs.renameSync(tmpPath, sidecarPath);
  } catch {
    // Non-fatal metadata update.
  } finally {
    release?.();
  }
}

// Serialise a key-file mutation (create/revoke/toggle) against other
// processes holding the same keys file. The lock guards the primary
// keys path; saveMcpKeysInternal fans the result out to the mirror
// paths afterwards, as before.
function withMcpKeysLock<T>(fn: () => T): T {
  const release = acquireMcpLockFile(`${resolveMcpKeysPath()}.lock`);
  try {
    return fn();
  } finally {
    release();
  }
}

export interface CreateMcpApiKeyInput {
  name: string;
  agentType?: 'vigilsoc' | 'soar' | 'custom-ai' | 'readonly-analyst';
  scopes: McpScope[];
  allowedSourceCidrs?: string[];
  mtlsCertFingerprintSha256?: string;
  policyLimits?: Partial<McpPolicyLimits>;
  expiresInDays?: number;
  createdBy?: string;
}

export interface CreatedMcpApiKeyResult {
  /** Full secret token — only returned ONCE at creation time */
  rawToken: string;
  key: McpApiKeyPublic;
}

export function createMcpApiKeyRecord(input: CreateMcpApiKeyInput): CreatedMcpApiKeyResult {
  const shortId = crypto.randomBytes(4).toString('hex');
  const secretHex = crypto.randomBytes(32).toString('hex');
  const keyPrefix = `axw_mcp_${shortId}`;
  const rawToken = `${keyPrefix}_${secretHex}`;
  const secretHashSha256 = hashMcpToken(rawToken);

  const now = new Date();
  let expiresAt: string | undefined;
  if (input.expiresInDays && input.expiresInDays > 0) {
    expiresAt = new Date(now.getTime() + input.expiresInDays * 86400 * 1000).toISOString();
  }

  const parsedLimits = McpPolicyLimitsSchema.parse(input.policyLimits ?? {});

  const record: McpApiKey = McpApiKeySchema.parse({
    id: `mcp_key_${shortId}`,
    name: input.name.trim(),
    agentType: input.agentType ?? 'vigilsoc',
    keyPrefix,
    secretHashSha256,
    scopes: input.scopes,
    allowedSourceCidrs: (input.allowedSourceCidrs ?? []).map((c) => c.trim()).filter(Boolean),
    mtlsCertFingerprintSha256: input.mtlsCertFingerprintSha256?.trim() || undefined,
    policyLimits: parsedLimits,
    enabled: true,
    createdAt: now.toISOString(),
    expiresAt,
    createdBy: input.createdBy ?? 'admin',
  });

  withMcpKeysLock(() => {
    const existing = loadMcpKeysInternal();
    existing.unshift(record);
    saveMcpKeysInternal(existing);
    verifyMcpKeysMutation(
      (keys) => keys.some((k) => k.id === record.id),
      `newly created key ${record.id} is missing`
    );
  });

  const { secretHashSha256: _omitted, ...publicRecord } = record;
  return {
    rawToken,
    key: publicRecord,
  };
}

export function listMcpApiKeys(): McpApiKeyPublic[] {
  const sidecar = readLastUsedSidecar(resolveMcpKeysPath());
  return loadMcpKeysInternal().map(({ secretHashSha256: _omitted, ...pub }) => {
    const entry = sidecar[pub.id];
    if (entry) {
      return { ...pub, lastUsedAt: entry.lastUsedAt, lastUsedIp: entry.lastUsedIp };
    }
    return pub;
  });
}

export function revokeMcpApiKeyRecord(keyId: string): boolean {
  const revoked = withMcpKeysLock(() => {
    const keys = loadMcpKeysInternal();
    const idx = keys.findIndex((k) => k.id === keyId);
    if (idx === -1) return false;
    keys.splice(idx, 1);
    saveMcpKeysInternal(keys);
    // R4-B-M1: a revocation is only real once the canonical file no
    // longer contains the key. Verify by re-reading; throw (do not
    // report success) when the key is still there.
    verifyMcpKeysMutation(
      (reloaded) => !reloaded.some((k) => k.id === keyId),
      `revoked key ${keyId} is still present`
    );
    return true;
  });
  if (revoked) rateLimitBuckets.delete(keyId);
  return revoked;
}

export function toggleMcpApiKeyRecord(keyId: string, enabled: boolean): McpApiKeyPublic | null {
  return withMcpKeysLock(() => {
    const keys = loadMcpKeysInternal();
    const target = keys.find((k) => k.id === keyId);
    if (!target) return null;
    target.enabled = enabled;
    saveMcpKeysInternal(keys);
    verifyMcpKeysMutation(
      (reloaded) => reloaded.find((k) => k.id === keyId)?.enabled === enabled,
      `key ${keyId} did not persist enabled=${enabled}`
    );
    const { secretHashSha256: _omitted, ...pub } = target;
    return pub;
  });
}

export interface McpAuthResult {
  authenticated: boolean;
  key?: McpApiKey;
  clientIp: string;
  errorStatus?: number;
  errorMessage?: string;
}

function extractClientCertificateFingerprint(req?: http.IncomingMessage): string | null {
  if (!req) return null;
  const sock = req.socket as any;
  if (sock && typeof sock.getPeerCertificate === 'function') {
    try {
      const cert = sock.getPeerCertificate();
      if (cert && cert.fingerprint256) {
        return String(cert.fingerprint256).replace(/:/g, '').toLowerCase();
      }
    } catch {
      return null;
    }
  }
  return null;
}

function checkSlidingWindowRateLimit(keyId: string, limitPerMinute: number): boolean {
  // C-M9: hold the rate-limit file lock across the full read-check-append-write cycle
  // and keep arrays rather than deduplicating identical millisecond timestamps.
  const statePath = resolveMcpRateLimitPath();
  let release: (() => void) | null = null;
  try {
    release = acquireMcpLockFile(`${statePath}.lock`, 2000);
  } catch (err: any) {
    console.warn(`[MCP RateLimit] Could not lock ${statePath} (${err?.message || err}); falling back to process budget.`);
    release = null;
  }
  try {
    const now = Date.now();
    const windowStart = now - 60_000;
    if (release) {
      const disk = loadRateLimitStateFromDisk();
      const pruned: Record<string, number[]> = {};
      for (const [k, stamps] of Object.entries(disk)) {
        const kept = stamps.filter((ts) => typeof ts === 'number' && ts > windowStart);
        if (kept.length > 0) pruned[k] = kept;
      }
      const existing = pruned[keyId] ?? [];
      if (existing.length >= limitPerMinute) {
        rateLimitBuckets.set(keyId, existing);
        return false;
      }
      existing.push(now);
      pruned[keyId] = existing;
      rateLimitBuckets.set(keyId, existing);
      try {
        writeFileAtomicSync(statePath, JSON.stringify(pruned, null, 2), 0o660);
        try {
          rateLimitDiskMtimeMs = fs.statSync(statePath).mtimeMs;
        } catch {}
        rateLimitDiskLoaded = true;
      } catch (err: any) {
        console.warn(`[MCP RateLimit] Failed to persist rate-limit state to ${statePath} (${err?.message || err}).`);
      }
      return true;
    }

    refreshRateLimitBucketsFromDisk();
    const timestamps = (rateLimitBuckets.get(keyId) ?? []).filter((ts) => ts > windowStart);
    if (timestamps.length >= limitPerMinute) {
      rateLimitBuckets.set(keyId, timestamps);
      return false;
    }
    timestamps.push(now);
    rateLimitBuckets.set(keyId, timestamps);
    return true;
  } finally {
    try {
      release?.();
    } catch {}
  }
}

/**
 * Authenticates an incoming HTTP or Stdio MCP request against `/var/lib/axonwall/mcp-keys.json`.
 */
export function authenticateMcpToken(
  rawToken: string | undefined,
  clientIp: string,
  req?: http.IncomingMessage
): McpAuthResult {
  const cleanIp = (clientIp || '127.0.0.1').replace(/^::ffff:/i, '').trim();

  // 1. Check Master Kill-Switch / Disable State
  const serverStatus = getMcpServerStatus();
  if (!serverStatus.enabled) {
    return {
      authenticated: false,
      clientIp: cleanIp,
      errorStatus: 503,
      errorMessage: serverStatus.disabledReason || 'Axonwall MCP server is disabled by administrator policy',
    };
  }

  if (!rawToken || !rawToken.trim().startsWith('axw_mcp_')) {
    return {
      authenticated: false,
      clientIp: cleanIp,
      errorStatus: 401,
      errorMessage: 'Missing or malformed Axonwall MCP Bearer token (expected axw_mcp_<id>_<secret>)',
    };
  }

  const candidateHashHex = hashMcpToken(rawToken);
  const candidateBuf = Buffer.from(candidateHashHex, 'hex');
  const keys = loadMcpKeysInternal();

  let matchedKey: McpApiKey | undefined;
  for (const k of keys) {
    const storedBuf = Buffer.from(k.secretHashSha256, 'hex');
    if (storedBuf.length === candidateBuf.length && crypto.timingSafeEqual(storedBuf, candidateBuf)) {
      matchedKey = k;
      break;
    }
  }

  if (!matchedKey) {
    return {
      authenticated: false,
      clientIp: cleanIp,
      errorStatus: 401,
      errorMessage: 'Invalid or revoked Axonwall MCP API key',
    };
  }

  if (!matchedKey.enabled) {
    return {
      authenticated: false,
      key: matchedKey,
      clientIp: cleanIp,
      errorStatus: 403,
      errorMessage: `MCP API key '${matchedKey.name}' (${matchedKey.id}) is currently disabled`,
    };
  }

  if (matchedKey.expiresAt) {
    const expMs = Date.parse(matchedKey.expiresAt);
    if (!Number.isNaN(expMs) && expMs <= Date.now()) {
      return {
        authenticated: false,
        key: matchedKey,
        clientIp: cleanIp,
        errorStatus: 403,
        errorMessage: `MCP API key '${matchedKey.name}' expired at ${matchedKey.expiresAt}`,
      };
    }
  }

  // Enforce source CIDR allowlist if configured
  if (matchedKey.allowedSourceCidrs && matchedKey.allowedSourceCidrs.length > 0) {
    const allowed = matchedKey.allowedSourceCidrs.some((cidr) => isIpInCidr(cleanIp, cidr));
    if (!allowed) {
      return {
        authenticated: false,
        key: matchedKey,
        clientIp: cleanIp,
        errorStatus: 403,
        errorMessage: `Client IP '${cleanIp}' is not in allowedSourceCidrs (${matchedKey.allowedSourceCidrs.join(', ')}) for key '${matchedKey.name}'`,
      };
    }
  }

  // Enforce optional mTLS client certificate fingerprint binding
  if (matchedKey.mtlsCertFingerprintSha256) {
    const expectedFp = matchedKey.mtlsCertFingerprintSha256.replace(/:/g, '').toLowerCase();
    const peerFp = extractClientCertificateFingerprint(req);
    if (!peerFp || peerFp !== expectedFp) {
      return {
        authenticated: false,
        key: matchedKey,
        clientIp: cleanIp,
        errorStatus: 403,
        errorMessage: `mTLS client certificate fingerprint mismatch for key '${matchedKey.name}'`,
      };
    }
  }

  // Enforce per-key sliding-window rate limit
  if (!checkSlidingWindowRateLimit(matchedKey.id, matchedKey.policyLimits.rateLimitPerMinute)) {
    return {
      authenticated: false,
      key: matchedKey,
      clientIp: cleanIp,
      errorStatus: 429,
      errorMessage: `Rate limit exceeded (${matchedKey.policyLimits.rateLimitPerMinute} req/min) for MCP key '${matchedKey.name}'`,
    };
  }

  // Update lastUsedAt / lastUsedIp metadata in the sidecar only.
  // B-S1: never rewrite the keys file here — a full rewrite on
  // every authentication is the lost-update race that could
  // resurrect a revoked key.
  try {
    const now = new Date().toISOString();
    matchedKey.lastUsedAt = now;
    matchedKey.lastUsedIp = cleanIp;
    writeLastUsedSidecar(resolveMcpKeysPath(), matchedKey.id, { lastUsedAt: now, lastUsedIp: cleanIp });
  } catch {
    // Non-fatal metadata update
  }

  return {
    authenticated: true,
    key: matchedKey,
    clientIp: cleanIp,
  };
}

/**
 * Checks whether an authenticated MCP key possesses the required scope for a tool or resource.
 */
export function hasMcpScope(key: McpApiKey, requiredScope: McpScope): boolean {
  return key.scopes.includes(requiredScope);
}
