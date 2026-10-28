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

const rateLimitBuckets = new Map<string, number[]>();

export function resolveMcpKeysPath(): string {
  if (process.env.AXONWALL_MCP_KEYS_PATH) {
    return process.env.AXONWALL_MCP_KEYS_PATH;
  }
  const primaryDir = '/var/lib/axonwall';
  const primaryFile = path.join(primaryDir, 'mcp-keys.json');
  try {
    if (fs.existsSync(primaryFile)) {
      fs.accessSync(primaryFile, fs.constants.R_OK);
      return primaryFile;
    }
    fs.mkdirSync(primaryDir, { recursive: true, mode: 0o775 });
    fs.accessSync(primaryDir, fs.constants.W_OK);
    return primaryFile;
  } catch {
    for (const candidate of ['/var/lib/axonwall/etc-axonwall/mcp-keys.json', '/etc/axonwall/mcp-keys.json']) {
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
    return primaryFile;
  }
}

function loadMcpKeysInternal(): McpApiKey[] {
  const candidatePaths = process.env.AXONWALL_MCP_KEYS_PATH
    ? [process.env.AXONWALL_MCP_KEYS_PATH]
    : Array.from(
        new Set([
          resolveMcpKeysPath(),
          '/var/lib/axonwall/mcp-keys.json',
          '/var/lib/axonwall/etc-axonwall/mcp-keys.json',
          '/etc/axonwall/mcp-keys.json',
        ]),
      );

  for (const keysPath of candidatePaths) {
    if (!fs.existsSync(keysPath)) continue;
    try {
      const raw = fs.readFileSync(keysPath, 'utf8');
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) continue;
      const valid: McpApiKey[] = [];
      for (const item of parsed) {
        const res = McpApiKeySchema.safeParse(item);
        if (res.success) {
          valid.push(res.data);
        }
      }
      return valid;
    } catch {
      // try next candidate
    }
  }
  return [];
}

function saveMcpKeysInternal(keys: McpApiKey[]): void {
  const serialized = JSON.stringify(keys, null, 2);
  const targetPaths = process.env.AXONWALL_MCP_KEYS_PATH
    ? [process.env.AXONWALL_MCP_KEYS_PATH]
    : [
        resolveMcpKeysPath(),
        '/var/lib/axonwall/etc-axonwall/mcp-keys.json',
        '/etc/axonwall/mcp-keys.json',
      ];
  for (const keysPath of Array.from(new Set(targetPaths))) {
    try {
      fs.mkdirSync(path.dirname(keysPath), { recursive: true, mode: 0o775 });
      const tmpPath = `${keysPath}.tmp.${process.pid}`;
      fs.writeFileSync(tmpPath, serialized, { mode: 0o660 });
      try {
        fs.chmodSync(tmpPath, 0o660);
      } catch {}
      fs.renameSync(tmpPath, keysPath);
    } catch {
      try {
        fs.writeFileSync(keysPath, serialized, { mode: 0o660 });
        fs.chmodSync(keysPath, 0o660);
      } catch {}
    }
  }
}

export function hashMcpToken(rawToken: string): string {
  return crypto.createHash('sha256').update(rawToken.trim()).digest('hex');
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

  const existing = loadMcpKeysInternal();
  existing.unshift(record);
  saveMcpKeysInternal(existing);

  const { secretHashSha256: _omitted, ...publicRecord } = record;
  return {
    rawToken,
    key: publicRecord,
  };
}

export function listMcpApiKeys(): McpApiKeyPublic[] {
  return loadMcpKeysInternal().map(({ secretHashSha256: _omitted, ...pub }) => pub);
}

export function revokeMcpApiKeyRecord(keyId: string): boolean {
  const keys = loadMcpKeysInternal();
  const idx = keys.findIndex((k) => k.id === keyId);
  if (idx === -1) return false;
  keys.splice(idx, 1);
  saveMcpKeysInternal(keys);
  rateLimitBuckets.delete(keyId);
  return true;
}

export function toggleMcpApiKeyRecord(keyId: string, enabled: boolean): McpApiKeyPublic | null {
  const keys = loadMcpKeysInternal();
  const target = keys.find((k) => k.id === keyId);
  if (!target) return null;
  target.enabled = enabled;
  saveMcpKeysInternal(keys);
  const { secretHashSha256: _omitted, ...pub } = target;
  return pub;
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
  const now = Date.now();
  const windowStart = now - 60_000;
  const timestamps = (rateLimitBuckets.get(keyId) ?? []).filter((ts) => ts > windowStart);
  if (timestamps.length >= limitPerMinute) {
    rateLimitBuckets.set(keyId, timestamps);
    return false;
  }
  timestamps.push(now);
  rateLimitBuckets.set(keyId, timestamps);
  return true;
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

  // Update lastUsedAt / lastUsedIp metadata
  try {
    matchedKey.lastUsedAt = new Date().toISOString();
    matchedKey.lastUsedIp = cleanIp;
    saveMcpKeysInternal(keys);
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
