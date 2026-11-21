import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { getStateDir } from './dev-paths';

export type HeadscaleInviteMode = 'onboard' | 'reset';
export type HeadscaleInviteStatus = 'pending' | 'redeemed' | 'revoked';
export type HeadscaleInviteEffectiveStatus = HeadscaleInviteStatus | 'expired';

interface StoredInviteRecord {
  id: string;
  username: string;
  displayName: string;
  mode: HeadscaleInviteMode;
  tokenHash: string;
  createdAt: string;
  expiresAt: string;
  createdBy: string;
  createStarterKey: boolean;
  status: HeadscaleInviteStatus;
  redeemedAt?: string;
  revokedAt?: string;
}

export interface PublicInviteRecord {
  id: string;
  username: string;
  displayName: string;
  mode: HeadscaleInviteMode;
  createdAt: string;
  expiresAt: string;
  createdBy: string;
  createStarterKey: boolean;
  status: HeadscaleInviteStatus;
  effectiveStatus: HeadscaleInviteEffectiveStatus;
  redeemedAt?: string;
  revokedAt?: string;
}

const VALID_USERNAME_RE = /^[a-z][a-z0-9_-]{0,31}$/;
const RESERVED_USERNAMES = new Set([
  'root',
  'admin',
  'axonwall',
  'axonwall-controller',
  'axonwall-headscale',
  'axonwall-api',
  'openldap',
  'ldap',
  'sshd',
  'nobody',
  'www-data',
  'daemon',
  'sync',
]);

const MAX_STORED_INVITES = 500;
const redeemingHashes = new Set<string>();

const INVITE_RATE_WINDOW_MS = 5 * 60 * 1000;
const INVITE_RATE_MAX_ATTEMPTS = 20;
const INVITE_RATE_MAX_KEYS = 1000;
const inviteRateLimits = new Map<string, { count: number; resetAt: number }>();

export function checkInviteRateLimit(clientKey: string): boolean {
  const key = (clientKey || 'unknown').trim() || 'unknown';
  const now = Date.now();
  for (const [k, rec] of inviteRateLimits) {
    if (rec.resetAt <= now) {
      inviteRateLimits.delete(k);
    }
  }
  const existing = inviteRateLimits.get(key);
  if (!existing || existing.resetAt <= now) {
    while (inviteRateLimits.size >= INVITE_RATE_MAX_KEYS) {
      const oldest = inviteRateLimits.keys().next().value;
      if (oldest === undefined) break;
      inviteRateLimits.delete(oldest);
    }
    inviteRateLimits.set(key, { count: 1, resetAt: now + INVITE_RATE_WINDOW_MS });
    return true;
  }
  if (existing.count >= INVITE_RATE_MAX_ATTEMPTS) {
    return false;
  }
  existing.count += 1;
  return true;
}

export function resetInviteRateLimitForTests(): void {
  inviteRateLimits.clear();
}

export function validateInviteUsername(username: string): string {
  const clean = String(username || '').trim().toLowerCase();
  if (!VALID_USERNAME_RE.test(clean)) {
    throw new Error(
      'Username must be 1–32 lowercase characters starting with a letter (letters, digits, _, -)'
    );
  }
  if (RESERVED_USERNAMES.has(clean)) {
    throw new Error(`Username '${clean}' is reserved`);
  }
  return clean;
}

function getInvitesFilePath(): string {
  const override = process.env.AXONWALL_HEADSCALE_INVITES_PATH?.trim();
  if (override) return override;
  return path.join(getStateDir(), 'headscale-invites.json');
}

function hashInviteToken(rawToken: string): string {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}

function constantTimeHashMatch(a: string, b: string): boolean {
  if (!a || !b) return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

function computeEffectiveStatus(record: StoredInviteRecord, now = Date.now()): HeadscaleInviteEffectiveStatus {
  if (record.status !== 'pending') return record.status;
  const expMs = Date.parse(record.expiresAt);
  if (!Number.isFinite(expMs) || now >= expMs) {
    return 'expired';
  }
  return 'pending';
}

function toPublicInvite(record: StoredInviteRecord, now = Date.now()): PublicInviteRecord {
  const { tokenHash: _omit, ...rest } = record;
  return {
    ...rest,
    effectiveStatus: computeEffectiveStatus(record, now),
  };
}

function readInviteStore(): StoredInviteRecord[] {
  const filePath = getInvitesFilePath();
  try {
    if (!fs.existsSync(filePath)) return [];
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    return Array.isArray(parsed) ? (parsed as StoredInviteRecord[]) : [];
  } catch {
    return [];
  }
}

function writeInviteStore(records: StoredInviteRecord[]): void {
  const filePath = getInvitesFilePath();
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o750 });

  // Prune historical consumed/revoked/expired records cleanly before storing
  let pruned = records;
  if (pruned.length > MAX_STORED_INVITES) {
    const now = Date.now();
    const pending = pruned.filter((r) => computeEffectiveStatus(r, now) === 'pending');
    const inactive = pruned.filter((r) => computeEffectiveStatus(r, now) !== 'pending');
    const keepInactive = Math.max(0, MAX_STORED_INVITES - pending.length);
    pruned = [...inactive.slice(-keepInactive), ...pending].slice(-MAX_STORED_INVITES);
  }

  const tmpPath = path.join(dir, `.headscale-invites-${process.pid}-${crypto.randomBytes(6).toString('hex')}.tmp`);
  fs.writeFileSync(tmpPath, JSON.stringify(pruned, null, 2) + '\n', { mode: 0o600 });
  try {
    fs.chmodSync(tmpPath, 0o600);
  } catch {}
  fs.renameSync(tmpPath, filePath);
}

export async function createHeadscaleInvite(params: {
  username: string;
  displayName?: string;
  mode?: HeadscaleInviteMode;
  createStarterKey?: boolean;
  expiryHours?: number;
  createdBy: string;
}): Promise<{ invite: PublicInviteRecord; rawToken: string }> {
  const username = validateInviteUsername(params.username);
  const mode: HeadscaleInviteMode = params.mode === 'reset' ? 'reset' : 'onboard';
  const rawDisplay = (params.displayName || '').trim();
  if (/[\r\n\x00]/.test(rawDisplay)) {
    throw new Error('Display name contains invalid control characters');
  }
  const displayName = rawDisplay.slice(0, 64) || username;
  const expiryHours = Math.min(168, Math.max(1, Math.round(Number(params.expiryHours) || 48)));
  const createStarterKey = params.createStarterKey !== false;

  const now = new Date();
  const nowIso = now.toISOString();
  const expiresAt = new Date(now.getTime() + expiryHours * 3600 * 1000).toISOString();

  const records = readInviteStore();
  // Supersede any existing pending invite for the same username
  for (const r of records) {
    if (r.username === username && r.status === 'pending') {
      r.status = 'revoked';
      r.revokedAt = nowIso;
    }
  }

  const rawToken = crypto.randomBytes(24).toString('base64url');
  const record: StoredInviteRecord = {
    id: crypto.randomUUID(),
    username,
    displayName,
    mode,
    tokenHash: hashInviteToken(rawToken),
    createdAt: nowIso,
    expiresAt,
    createdBy: params.createdBy || 'admin',
    createStarterKey,
    status: 'pending',
  };

  records.push(record);
  writeInviteStore(records);

  return {
    invite: toPublicInvite(record, now.getTime()),
    rawToken,
  };
}

export function listHeadscaleInvites(): PublicInviteRecord[] {
  const now = Date.now();
  return readInviteStore()
    .map((r) => toPublicInvite(r, now))
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
}

export function revokeHeadscaleInvite(inviteId: string): PublicInviteRecord {
  const records = readInviteStore();
  const rec = records.find((r) => r.id === inviteId);
  if (!rec) {
    const err = new Error('Invite not found');
    (err as any).code = 'NOT_FOUND';
    throw err;
  }
  if (rec.status === 'pending') {
    rec.status = 'revoked';
    rec.revokedAt = new Date().toISOString();
    writeInviteStore(records);
  }
  return toPublicInvite(rec);
}

export function previewHeadscaleInvite(rawToken: string): {
  status: 'valid' | 'expired' | 'used' | 'revoked' | 'invalid';
  invite?: PublicInviteRecord;
} {
  const token = String(rawToken || '').trim();
  if (!token || token.length < 16 || token.length > 256) {
    return { status: 'invalid' };
  }
  const targetHash = hashInviteToken(token);
  const records = readInviteStore();
  const rec = records.find((r) => constantTimeHashMatch(r.tokenHash, targetHash));
  if (!rec) {
    return { status: 'invalid' };
  }
  const eff = computeEffectiveStatus(rec);
  if (eff === 'redeemed') return { status: 'used' };
  if (eff === 'revoked') return { status: 'revoked' };
  if (eff === 'expired') return { status: 'expired' };
  return {
    status: 'valid',
    invite: toPublicInvite(rec),
  };
}

export async function consumeHeadscaleInvite<T>(
  rawToken: string,
  provisionFn: (invite: PublicInviteRecord) => Promise<T>
): Promise<{ invite: PublicInviteRecord; result: T }> {
  const token = String(rawToken || '').trim();
  if (!token || token.length < 16 || token.length > 256) {
    const err = new Error('Invalid invite link');
    (err as any).code = 'INVALID_TOKEN';
    throw err;
  }

  const targetHash = hashInviteToken(token);
  if (redeemingHashes.has(targetHash)) {
    const err = new Error('Invite activation is already in progress');
    (err as any).code = 'CONFLICT';
    throw err;
  }

  redeemingHashes.add(targetHash);
  try {
    const records = readInviteStore();
    const rec = records.find((r) => constantTimeHashMatch(r.tokenHash, targetHash));
    if (!rec) {
      const err = new Error('Invite link is invalid or does not exist');
      (err as any).code = 'INVALID_TOKEN';
      throw err;
    }

    const eff = computeEffectiveStatus(rec);
    if (eff === 'redeemed') {
      const err = new Error('This invite link has already been used');
      (err as any).code = 'ALREADY_USED';
      throw err;
    }
    if (eff === 'revoked') {
      const err = new Error('This invite link has been revoked by an administrator');
      (err as any).code = 'REVOKED';
      throw err;
    }
    if (eff === 'expired') {
      const err = new Error('This invite link has expired');
      (err as any).code = 'EXPIRED';
      throw err;
    }

    const publicBefore = toPublicInvite(rec);
    const result = await provisionFn(publicBefore);

    // Re-read before marking redeemed so concurrent revocations or store updates are preserved
    const latestRecords = readInviteStore();
    const target = latestRecords.find((r) => r.id === rec.id);
    if (!target) {
      const err = new Error('Invite record disappeared during redemption');
      (err as any).code = 'INVALID_TOKEN';
      throw err;
    }
    if (target.status !== 'pending') {
      const err = new Error('Invite is no longer pending');
      (err as any).code = 'CONFLICT';
      throw err;
    }
    target.status = 'redeemed';
    target.redeemedAt = new Date().toISOString();
    writeInviteStore(latestRecords);

    return {
      invite: toPublicInvite(target),
      result,
    };
  } finally {
    redeemingHashes.delete(targetHash);
  }
}
