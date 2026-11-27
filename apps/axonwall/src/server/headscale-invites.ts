import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { callAgentApiDetailed } from './agent-client';
import { getStateDir } from './dev-paths';

export type HeadscaleInviteMode = 'onboard' | 'reset';
export type HeadscaleInviteStatus = 'pending' | 'redeemed' | 'revoked';
export type InternalInviteStatus = HeadscaleInviteStatus | 'redeeming';
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
  status: InternalInviteStatus;
  redeemingAt?: string;
  redeemingClaimId?: string;
  redeemedAt?: string;
  revokedAt?: string;
  pinSalt?: string;
  pinHash?: string;
  failedPinAttempts?: number;
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
  requiresPin: boolean;
  status: HeadscaleInviteStatus;
  effectiveStatus: HeadscaleInviteEffectiveStatus;
  redeemedAt?: string;
  revokedAt?: string;
}

export const MAX_PIN_ATTEMPTS = 5;

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
const REDEEMING_STALE_MS = 2 * 60 * 1000;
const LOCK_STALE_MS = 30_000;
const LOCK_TIMEOUT_MS = 5_000;
const SLEEP_BUF = new Int32Array(new SharedArrayBuffer(4));

function sleepSyncMs(ms: number): void {
  Atomics.wait(SLEEP_BUF, 0, 0, ms);
}

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
    if (!existing && inviteRateLimits.size >= INVITE_RATE_MAX_KEYS) {
      // Hard global cap: fail closed (429) rather than evicting tracked entries or growing unboundedly.
      return false;
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

function hashInvitePin(pin: string, saltHex: string): string {
  return crypto.scryptSync(pin, saltHex, 32).toString('hex');
}

function constantTimeHashMatch(a: string, b: string): boolean {
  if (!a || !b) return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

function computeEffectiveStatus(record: StoredInviteRecord, now = Date.now()): HeadscaleInviteEffectiveStatus {
  if (record.status !== 'pending' && record.status !== 'redeeming') {
    return record.status;
  }
  const expMs = Date.parse(record.expiresAt);
  if (!Number.isFinite(expMs) || now >= expMs) {
    return 'expired';
  }
  return 'pending';
}

function toPublicInvite(record: StoredInviteRecord, now = Date.now()): PublicInviteRecord {
  const {
    tokenHash: _omitTokenHash,
    pinSalt: _omitPinSalt,
    pinHash: _omitPinHash,
    failedPinAttempts: _omitPinAttempts,
    redeemingAt: _omitRedeemingAt,
    redeemingClaimId: _omitClaimId,
    ...rest
  } = record;
  const publicStatus: HeadscaleInviteStatus =
    rest.status === 'redeeming' ? 'pending' : rest.status;
  return {
    ...rest,
    status: publicStatus,
    requiresPin: Boolean(record.pinHash && record.pinSalt),
    effectiveStatus: computeEffectiveStatus(record, now),
  };
}

function withInviteStoreLock<T>(fn: () => T): T {
  const filePath = getInvitesFilePath();
  const lockPath = `${filePath}.lock`;
  const dir = path.dirname(filePath);
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
        throw new Error('Timed out acquiring invite store lock');
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

function readInviteStore(): StoredInviteRecord[] {
  const filePath = getInvitesFilePath();
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (err: any) {
    if (err?.code === 'ENOENT') {
      return [];
    }
    throw new Error(`Failed to read invite store: ${err?.message || 'unknown error'}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('Invite store contains corrupt JSON; refusing to overwrite existing invites');
  }
  if (!Array.isArray(parsed)) {
    throw new Error('Invite store has invalid non-array format; refusing to overwrite existing invites');
  }
  return parsed as StoredInviteRecord[];
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
  let fd: number | null = null;
  try {
    fd = fs.openSync(tmpPath, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify(pruned, null, 2) + '\n', 'utf8');
    try {
      fs.fsyncSync(fd);
    } catch {}
    fs.closeSync(fd);
    fd = null;
    try {
      fs.chmodSync(tmpPath, 0o600);
    } catch {}
    fs.renameSync(tmpPath, filePath);
  } catch (err) {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {}
    }
    try {
      if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
    } catch {}
    throw err;
  }
}

export async function createHeadscaleInvite(params: {
  username: string;
  displayName?: string;
  mode?: HeadscaleInviteMode;
  createStarterKey?: boolean;
  requirePin?: boolean;
  expiryHours?: number;
  createdBy: string;
}): Promise<{ invite: PublicInviteRecord; rawToken: string; invitePin?: string }> {
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

  let invitePin: string | undefined;
  let pinSalt: string | undefined;
  let pinHash: string | undefined;
  if (params.requirePin) {
    invitePin = String(crypto.randomInt(100000, 1000000));
    pinSalt = crypto.randomBytes(16).toString('hex');
    pinHash = hashInvitePin(invitePin, pinSalt);
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
    ...(pinSalt && pinHash ? { pinSalt, pinHash, failedPinAttempts: 0 } : {}),
  };

  withInviteStoreLock(() => {
    const records = readInviteStore();
    // Supersede any existing pending/in-flight invite for the same username
    for (const r of records) {
      if (r.username === username && (r.status === 'pending' || r.status === 'redeeming')) {
        r.status = 'revoked';
        r.revokedAt = nowIso;
        delete r.redeemingAt;
        delete r.redeemingClaimId;
      }
    }
    records.push(record);
    writeInviteStore(records);
  });

  return {
    invite: toPublicInvite(record, now.getTime()),
    rawToken,
    ...(invitePin ? { invitePin } : {}),
  };
}

export function listHeadscaleInvites(): PublicInviteRecord[] {
  const now = Date.now();
  return withInviteStoreLock(() => readInviteStore())
    .map((r) => toPublicInvite(r, now))
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
}

export function revokeHeadscaleInvite(inviteId: string): PublicInviteRecord {
  return withInviteStoreLock(() => {
    const records = readInviteStore();
    const rec = records.find((r) => r.id === inviteId);
    if (!rec) {
      const err = new Error('Invite not found');
      (err as any).code = 'NOT_FOUND';
      throw err;
    }
    if (rec.status === 'pending' || rec.status === 'redeeming') {
      rec.status = 'revoked';
      rec.revokedAt = new Date().toISOString();
      delete rec.redeemingAt;
      delete rec.redeemingClaimId;
      writeInviteStore(records);
    }
    return toPublicInvite(rec);
  });
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
  const records = withInviteStoreLock(() => readInviteStore());
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
  provisionFn: (invite: PublicInviteRecord) => Promise<T>,
  options?: { pin?: string }
): Promise<{ invite: PublicInviteRecord; result: T }> {
  const token = String(rawToken || '').trim();
  if (!token || token.length < 16 || token.length > 256) {
    const err = new Error('Invalid invite link');
    (err as any).code = 'INVALID_TOKEN';
    throw err;
  }

  const targetHash = hashInviteToken(token);
  const claimId = crypto.randomUUID();

  // Phase 1: Under exclusive file lock, validate status/PIN and transition pending -> redeeming on disk.
  const { recordId, publicBefore } = withInviteStoreLock(() => {
    const records = readInviteStore();
    const rec = records.find((r) => constantTimeHashMatch(r.tokenHash, targetHash));
    if (!rec) {
      const err = new Error('Invite link is invalid or does not exist');
      (err as any).code = 'INVALID_TOKEN';
      throw err;
    }

    const nowMs = Date.now();
    const eff = computeEffectiveStatus(rec, nowMs);
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

    if (rec.status === 'redeeming') {
      const startedMs = rec.redeemingAt ? Date.parse(rec.redeemingAt) : 0;
      if (!Number.isNaN(startedMs) && nowMs - startedMs < REDEEMING_STALE_MS) {
        const err = new Error('Invite activation is already in progress');
        (err as any).code = 'CONFLICT';
        throw err;
      }
    }

    if (rec.pinHash && rec.pinSalt) {
      const submittedPin = String(options?.pin ?? '').trim();
      const pinMatches =
        /^\d{6}$/.test(submittedPin) &&
        constantTimeHashMatch(rec.pinHash, hashInvitePin(submittedPin, rec.pinSalt));
      if (!pinMatches) {
        const nextAttempts = (rec.failedPinAttempts ?? 0) + 1;
        rec.failedPinAttempts = nextAttempts;
        if (nextAttempts >= MAX_PIN_ATTEMPTS) {
          rec.status = 'revoked';
          rec.revokedAt = new Date().toISOString();
          writeInviteStore(records);
          const err = new Error('Invite revoked after too many invalid PIN attempts');
          (err as any).code = 'REVOKED';
          (err as any).statusCode = 410;
          throw err;
        }
        writeInviteStore(records);
        const remaining = MAX_PIN_ATTEMPTS - nextAttempts;
        const err = new Error(
          `Invalid or missing 6-digit invite PIN (${remaining} attempt${remaining === 1 ? '' : 's'} remaining)`
        );
        (err as any).code = 'INVALID_PIN';
        (err as any).statusCode = 403;
        throw err;
      }
    }

    rec.status = 'redeeming';
    rec.redeemingAt = new Date(nowMs).toISOString();
    rec.redeemingClaimId = claimId;
    writeInviteStore(records);

    return { recordId: rec.id, publicBefore: toPublicInvite(rec, nowMs) };
  });

  // Phase 2: Execute provisioning outside lock; on failure revert redeeming -> pending, on success commit redeemed.
  let result: T;
  try {
    result = await provisionFn(publicBefore);
  } catch (err) {
    try {
      withInviteStoreLock(() => {
        const latestRecords = readInviteStore();
        const target = latestRecords.find((r) => r.id === recordId);
        if (target && target.status === 'redeeming' && target.redeemingClaimId === claimId) {
          target.status = 'pending';
          delete target.redeemingAt;
          delete target.redeemingClaimId;
          writeInviteStore(latestRecords);
        }
      });
    } catch {
      // Do not mask original provisioning failure if cleanup fails.
    }
    throw err;
  }

  const redeemedPublic = withInviteStoreLock(() => {
    const latestRecords = readInviteStore();
    const target = latestRecords.find((r) => r.id === recordId);
    if (!target) {
      const err = new Error('Invite record disappeared during redemption');
      (err as any).code = 'INVALID_TOKEN';
      throw err;
    }
    if (target.status !== 'redeeming' || target.redeemingClaimId !== claimId) {
      const err = new Error('Invite is no longer pending');
      (err as any).code = 'CONFLICT';
      throw err;
    }
    target.status = 'redeemed';
    target.redeemedAt = new Date().toISOString();
    delete target.redeemingAt;
    delete target.redeemingClaimId;
    writeInviteStore(latestRecords);
    return toPublicInvite(target);
  });

  return {
    invite: redeemedPublic,
    result,
  };
}

export function getActivePendingInviteWindow(now = Date.now()): {
  pendingCount: number;
  latestExpiresAt: string | null;
} {
  let pendingCount = 0;
  let maxExpMs = 0;
  for (const rec of readInviteStore()) {
    if (computeEffectiveStatus(rec, now) !== 'pending') continue;
    pendingCount += 1;
    const expMs = Date.parse(rec.expiresAt);
    if (Number.isFinite(expMs) && expMs > maxExpMs) {
      maxExpMs = expMs;
    }
  }
  return {
    pendingCount,
    latestExpiresAt: maxExpMs > 0 ? new Date(maxExpMs).toISOString() : null,
  };
}

export async function syncHeadscaleWanWindow(): Promise<void> {
  try {
    await callAgentApiDetailed('/v1/vpn/headscale/wan-window/sync', 'POST', {}, 2500);
  } catch {
    // Best-effort sync; periodic ticker & post-apply reconciliation also keep nftables in sync.
  }
}
