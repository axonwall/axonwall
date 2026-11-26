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

function getServiceTokenPaths(): string[] {
  return Array.from(
    new Set([
      path.join(getPersistConfigDir(), 'service-tokens.json'),
      path.join(getEtcConfigDir(), 'service-tokens.json'),
    ])
  );
}

function readTokenRecords(): ServiceTokenRecord[] {
  for (const filePath of getServiceTokenPaths()) {
    try {
      if (!fs.existsSync(filePath)) continue;
      const raw = fs.readFileSync(filePath, 'utf-8');
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return parsed.filter(
          (item): item is ServiceTokenRecord =>
            Boolean(item) &&
            typeof item.id === 'string' &&
            typeof item.name === 'string' &&
            typeof item.role === 'string' &&
            Array.isArray(item.scopes) &&
            typeof item.secretHash === 'string'
        );
      }
    } catch {
      // Ignore corrupt/unreadable candidate path and try fallback
    }
  }
  return [];
}

function writeTokenRecords(records: ServiceTokenRecord[]): void {
  const payload = `${JSON.stringify(records, null, 2)}\n`;
  for (const filePath of getServiceTokenPaths()) {
    try {
      writeAuthFileSafe(filePath, payload, 0o600);
    } catch {
      // Best-effort sync to mirror path; primary path write throws below if none exist
    }
  }
  const paths = getServiceTokenPaths();
  if (!paths.some((p) => fs.existsSync(p))) {
    writeAuthFileSafe(paths[paths.length - 1], payload, 0o600);
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
  const role: ServiceTokenRole = input.role && VALID_ROLES.has(input.role) ? input.role : 'operator';
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

  const existing = readTokenRecords();
  existing.push(record);
  writeTokenRecords(existing);

  return {
    record: toPublicRecord(record),
    plaintextToken: `axw_svc_${id}_${secret}`,
  };
}

export function revokeServiceToken(id: string): boolean {
  const target = String(id || '').trim();
  if (!target) return false;
  const records = readTokenRecords();
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
    records[idx] = {
      ...rec,
      lastUsedAt: new Date(nowMs).toISOString(),
    };
    try {
      writeTokenRecords(records);
    } catch {
      // Non-fatal if read-only fs during verification
    }
    return toPublicRecord(records[idx]);
  }

  return toPublicRecord(rec);
}

export function hasServiceTokenScope(session: UserSession | null, requiredScope: string): boolean {
  if (!session) return false;
  if (session.source !== 'service_token') return true;
  const scopes = session.scopes || [];
  return scopes.includes('*') || scopes.includes(requiredScope);
}
