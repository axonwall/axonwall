import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { UserSession } from '@axonwall/lib/rbac';
import { writeAuthFileSafe } from './auth-internal';
import { getEtcConfigDir, getPersistConfigDir } from './dev-paths';

export type ServiceTokenRole = 'admin' | 'operator' | 'readonly';

export interface ServiceTokenRecord {
  id: string;
  name: string;
  role: ServiceTokenRole;
  scopes: string[];
  secretHash: string;
  createdAt: string;
  expiresAt?: string;
  lastUsedAt?: string;
  revokedAt?: string;
}

export type PublicServiceTokenRecord = Omit<ServiceTokenRecord, 'secretHash'>;

const TOKEN_RE = /^axw_svc_([a-f0-9]{12})_([a-f0-9]{48})$/;
const VALID_ROLES = new Set<ServiceTokenRole>(['admin', 'operator', 'readonly']);
const LAST_USED_TOUCH_INTERVAL_MS = 60_000;
const LOCK_STALE_MS = 30_000;
const LOCK_TIMEOUT_MS = 5_000;
const SLEEP_BUF = new Int32Array(new SharedArrayBuffer(4));

function sleepSyncMs(ms: number): void {
  Atomics.wait(SLEEP_BUF, 0, 0, ms);
}

function getServiceTokenPaths(): string[] {
  return Array.from(
    new Set([
      path.join(getPersistConfigDir(), 'service-tokens.json'),
      path.join(getEtcConfigDir(), 'service-tokens.json'),
    ])
  );
}

function withServiceTokenLock<T>(fn: () => T): T {
  const primary = getServiceTokenPaths()[0]!;
  const lockPath = `${primary}.lock`;
  const dir = path.dirname(lockPath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o750 });

  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  let fd: number | null = null;
  while (fd === null) {
    try {
      fd = fs.openSync(lockPath, 'wx', 0o600);
    } catch (err: any) {
      if (err?.code !== 'EEXIST') throw err;
      try {
        const st = fs.statSync(lockPath);
        if (Date.now() - st.mtimeMs > LOCK_STALE_MS) {
          fs.unlinkSync(lockPath);
          continue;
        }
      } catch {}
      if (Date.now() >= deadline) {
        throw new Error('Timed out acquiring service token store lock');
      }
      sleepSyncMs(10);
    }
  }

  try {
    fs.writeSync(fd, `${process.pid}\n`);
    return fn();
  } finally {
    try {
      fs.closeSync(fd);
    } catch {}
    try {
      fs.unlinkSync(lockPath);
    } catch {}
  }
}

function isValidTokenRecord(item: unknown): item is ServiceTokenRecord {
  if (!item || typeof item !== 'object') return false;
  const rec = item as Record<string, unknown>;
  return (
    typeof rec.id === 'string' &&
    typeof rec.name === 'string' &&
    typeof rec.role === 'string' &&
    VALID_ROLES.has(rec.role as ServiceTokenRole) &&
    Array.isArray(rec.scopes) &&
    typeof rec.secretHash === 'string'
  );
}

function pickLaterIso(a?: string, b?: string): string | undefined {
  if (!a) return b;
  if (!b) return a;
  const ta = Date.parse(a);
  const tb = Date.parse(b);
  if (Number.isNaN(ta)) return b;
  if (Number.isNaN(tb)) return a;
  return tb > ta ? b : a;
}

function readTokenRecords(options?: { failOnCorrupt?: boolean }): ServiceTokenRecord[] {
  const merged = new Map<string, ServiceTokenRecord>();
  let readableMirrorCount = 0;
  let corruptError: Error | null = null;

  for (const filePath of getServiceTokenPaths()) {
    try {
      if (!fs.existsSync(filePath)) continue;
      const raw = fs.readFileSync(filePath, 'utf-8');
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) {
        corruptError = corruptError ?? new Error(`Invalid service token store format at ${filePath}`);
        continue;
      }
      readableMirrorCount += 1;
      for (const item of parsed) {
        if (!isValidTokenRecord(item)) continue;
        const existing = merged.get(item.id);
        if (!existing) {
          merged.set(item.id, { ...item });
          continue;
        }
        // Mirror reconciliation: any revocation across mirrors always wins,
        // and the most recent lastUsedAt timestamp is preserved.
        const revokedAt = existing.revokedAt || item.revokedAt;
        const lastUsedAt = pickLaterIso(existing.lastUsedAt, item.lastUsedAt);
        merged.set(item.id, {
          ...existing,
          ...(revokedAt ? { revokedAt } : {}),
          ...(lastUsedAt ? { lastUsedAt } : {}),
        });
      }
    } catch (err: any) {
      corruptError = corruptError ?? (err instanceof Error ? err : new Error('Failed to read service token store'));
    }
  }

  if (options?.failOnCorrupt && corruptError && readableMirrorCount === 0) {
    throw corruptError;
  }

  return Array.from(merged.values());
}

function writeTokenRecords(records: ServiceTokenRecord[]): void {
  const payload = `${JSON.stringify(records, null, 2)}\n`;
  const paths = getServiceTokenPaths();
  // Fail-closed primary write: never silently report success if the primary store cannot be updated.
  writeAuthFileSafe(paths[0]!, payload, 0o600);
  for (const mirrorPath of paths.slice(1)) {
    try {
      writeAuthFileSafe(mirrorPath, payload, 0o600);
    } catch {
      // Secondary mirror sync is best-effort once primary atomic write succeeded.
    }
  }
}

function hashSecret(secret: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(secret, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

function verifySecretHash(secret: string, stored: string): boolean {
  const parts = stored.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt' || !parts[1] || !parts[2]) {
    return false;
  }
  try {
    const expected = Buffer.from(parts[2], 'hex');
    const actual = crypto.scryptSync(secret, parts[1], expected.length);
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

function toPublicRecord(rec: ServiceTokenRecord): PublicServiceTokenRecord {
  const { secretHash: _secretHash, ...pub } = rec;
  return pub;
}

export function listServiceTokens(): PublicServiceTokenRecord[] {
  return readTokenRecords().map(toPublicRecord);
}

export function createServiceToken(input: {
  name: string;
  role?: ServiceTokenRole;
  scopes?: string[];
  expiresAt?: string;
}): { record: PublicServiceTokenRecord; plaintextToken: string } {
  const name = String(input.name || '').trim();
  if (!name || name.length > 128) {
    throw new Error('Service token name must be 1-128 characters.');
  }
  let role: ServiceTokenRole = 'readonly';
  if (input.role !== undefined) {
    if (typeof input.role !== 'string' || !VALID_ROLES.has(input.role as ServiceTokenRole)) {
      throw new Error(
        `Invalid service token role '${String(input.role)}': expected admin, operator, or readonly.`
      );
    }
    role = input.role as ServiceTokenRole;
  }
  const scopes = Array.from(
    new Set(
      (input.scopes || ['observability:ingest'])
        .map((s) => String(s).trim())
        .filter((s) => s.length > 0 && s.length <= 64)
    )
  );
  if (scopes.length === 0) {
    throw new Error('At least one non-empty scope is required.');
  }

  let expiresAt: string | undefined;
  if (input.expiresAt && input.expiresAt.trim()) {
    const parsedMs = Date.parse(input.expiresAt.trim());
    if (Number.isNaN(parsedMs) || parsedMs <= Date.now()) {
      throw new Error('expiresAt must be a valid future ISO timestamp.');
    }
    expiresAt = new Date(parsedMs).toISOString();
  }

  const id = crypto.randomBytes(6).toString('hex');
  const secret = crypto.randomBytes(24).toString('hex');
  const record: ServiceTokenRecord = {
    id,
    name,
    role,
    scopes,
    secretHash: hashSecret(secret),
    createdAt: new Date().toISOString(),
    ...(expiresAt ? { expiresAt } : {}),
  };

  withServiceTokenLock(() => {
    const existing = readTokenRecords({ failOnCorrupt: true });
    existing.push(record);
    writeTokenRecords(existing);
  });

  return {
    record: toPublicRecord(record),
    plaintextToken: `axw_svc_${id}_${secret}`,
  };
}

export function revokeServiceToken(id: string): boolean {
  const target = String(id || '').trim();
  if (!target) return false;
  return withServiceTokenLock(() => {
    const records = readTokenRecords({ failOnCorrupt: true });
    const idx = records.findIndex((r) => r.id === target);
    if (idx < 0) return false;
    if (!records[idx].revokedAt) {
      records[idx] = {
        ...records[idx],
        revokedAt: new Date().toISOString(),
      };
      writeTokenRecords(records);
    }
    return true;
  });
}

export function verifyServiceToken(rawToken: string): PublicServiceTokenRecord | null {
  const trimmed = String(rawToken || '').trim();
  const match = TOKEN_RE.exec(trimmed);
  if (!match) {
    return null;
  }
  const [, id, secret] = match;
  const records = readTokenRecords();
  const idx = records.findIndex((r) => r.id === id);
  if (idx < 0) {
    return null;
  }
  const rec = records[idx];
  if (rec.revokedAt) {
    return null;
  }
  if (rec.expiresAt) {
    const expMs = Date.parse(rec.expiresAt);
    if (Number.isNaN(expMs) || expMs <= Date.now()) {
      return null;
    }
  }
  if (!verifySecretHash(secret, rec.secretHash)) {
    return null;
  }

  const nowMs = Date.now();
  const lastUsedMs = rec.lastUsedAt ? Date.parse(rec.lastUsedAt) : 0;
  if (!lastUsedMs || Number.isNaN(lastUsedMs) || nowMs - lastUsedMs >= LAST_USED_TOUCH_INTERVAL_MS) {
    try {
      return withServiceTokenLock(() => {
        const latest = readTokenRecords({ failOnCorrupt: true });
        const latestIdx = latest.findIndex((r) => r.id === id);
        if (latestIdx < 0 || latest[latestIdx]!.revokedAt) {
          return null;
        }
        latest[latestIdx] = {
          ...latest[latestIdx]!,
          lastUsedAt: new Date(nowMs).toISOString(),
        };
        writeTokenRecords(latest);
        return toPublicRecord(latest[latestIdx]!);
      });
    } catch {
      // Non-fatal if read-only fs during verification
    }
  }

  return toPublicRecord(rec);
}

export function hasServiceTokenScope(session: UserSession | null, requiredScope: string): boolean {
  if (!session) return false;
  if (session.source !== 'service_token') return true;
  const scopes = session.scopes || [];
  return scopes.includes('*') || scopes.includes(requiredScope);
}
