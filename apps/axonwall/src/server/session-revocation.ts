import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { getEtcConfigDir, getStateDir } from './dev-paths';

import type { UserSession } from '@axonwall/lib/rbac';

/**
 * Server-side session revocation (audit B-09). Session JWTs are
 * stateless, so logout and password changes used to invalidate
 * nothing: a stolen token stayed valid for its full 8 hours.
 *
 * Two file-backed mechanisms, consistent with the appliance's other
 * auth state (admin.env, .password_changed markers):
 *
 * - Session epoch: a counter stored under /var/lib/axonwall (mirrored
 *   to /etc/axonwall). Every minted token carries the epoch as its
 *   session_epoch claim; getSession rejects tokens whose epoch no
 *   longer matches. Changing the admin password bumps the epoch,
 *   which kills every outstanding session at once.
 * - Per-token denylist: logout appends the token's jti to
 *   revoked-jtis; getSession rejects listed tokens. The file is
 *   trimmed to the most recent 500 entries (8-hour tokens age out
 *   quickly, so the list stays small).
 *
 * This module is deliberately NOT a Server Actions module (no
 * 'use server'): it exports synchronous helpers that route handlers
 * (e.g. the OIDC callback) also need.
 */

function getEpochPaths(): string[] {
  return Array.from(
    new Set([path.join(getStateDir(), 'session-epoch'), path.join(getEtcConfigDir(), 'session-epoch')])
  );
}
function getUserEpochPaths(): string[] {
  return Array.from(
    new Set([
      path.join(getStateDir(), 'user-session-epochs.json'),
      path.join(getEtcConfigDir(), 'user-session-epochs.json'),
    ])
  );
}
function getRevokedPaths(): string[] {
  return Array.from(
    new Set([path.join(getStateDir(), 'revoked-jtis'), path.join(getEtcConfigDir(), 'revoked-jtis')])
  );
}
const DEFAULT_REVOKED_TTL_SEC = 8 * 3600;
const MAX_USER_EPOCHS = 2000;

let memoryEpoch = 0;
const memoryUserEpochs = new Map<string, number>();
const memoryRevokedJtis = new Map<string, number>();

function writeRevocationFileAtomic(filePath: string, content: string, mode = 0o660): void {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o750 });
  const base = path.basename(filePath);
  const tmpPath = path.join(dir, `.${base}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  let fd: number | null = null;
  try {
    fd = fs.openSync(tmpPath, 'wx', mode);
    fs.writeFileSync(fd, content, 'utf8');
    try {
      fs.fsyncSync(fd);
    } catch {}
    fs.closeSync(fd);
    fd = null;
    try {
      fs.chmodSync(tmpPath, mode);
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

function normalizeEpochUserKey(username: string, source?: string): string {
  const cleanUser = username.trim().toLowerCase();
  if (!cleanUser) return '';
  if (source === 'oidc' && !cleanUser.startsWith('oidc:')) {
    return `oidc:${cleanUser}`;
  }
  if (source === 'ldap' && !cleanUser.startsWith('ldap:')) {
    return `ldap:${cleanUser}`;
  }
  return cleanUser;
}

function readUserEpochMap(): Map<string, number> {
  const combined = new Map<string, number>(memoryUserEpochs);
  for (const p of getUserEpochPaths()) {
    try {
      const parsed = JSON.parse(fs.readFileSync(p, 'utf-8')) as Record<string, unknown>;
      if (!parsed || typeof parsed !== 'object') continue;
      for (const [k, v] of Object.entries(parsed)) {
        const num = Number(v);
        if (Number.isFinite(num) && num > (combined.get(k) ?? 0)) {
          combined.set(k, num);
        }
      }
    } catch {}
  }
  return combined;
}

export function currentUserSessionEpoch(username: string, source?: string): number {
  const key = normalizeEpochUserKey(username, source);
  if (!key) return 0;
  const epoch = readUserEpochMap().get(key) ?? 0;
  if (epoch > (memoryUserEpochs.get(key) ?? 0)) {
    memoryUserEpochs.set(key, epoch);
  }
  return epoch;
}

/** Invalidate outstanding sessions for a single user (e.g. self-service password reset/change). */
export function bumpUserSessionEpoch(username: string, source?: string): number {
  const key = normalizeEpochUserKey(username, source);
  if (!key) return 0;
  const combined = readUserEpochMap();
  const nextVal = Math.max(Date.now(), (combined.get(key) ?? 0) + 1);
  combined.delete(key);
  combined.set(key, nextVal);
  while (combined.size > MAX_USER_EPOCHS) {
    const oldest = combined.keys().next().value;
    if (oldest === undefined) break;
    combined.delete(oldest);
  }
  memoryUserEpochs.delete(key);
  memoryUserEpochs.set(key, nextVal);
  const serialized = JSON.stringify(Object.fromEntries(combined)) + '\n';
  for (const p of getUserEpochPaths()) {
    try {
      writeRevocationFileAtomic(p, serialized, 0o660);
    } catch {}
  }
  return nextVal;
}

export function currentSessionEpoch(): number {
  let maxEpoch = memoryEpoch;
  for (const p of getEpochPaths()) {
    try {
      const value = Number(fs.readFileSync(p, 'utf-8').trim());
      if (Number.isFinite(value) && value > maxEpoch) {
        maxEpoch = value;
      }
    } catch {}
  }
  memoryEpoch = maxEpoch;
  return maxEpoch;
}

/** Stamp a session with the current global and per-user epochs before it is minted. */
export function stampSessionEpoch(session: UserSession): void {
  session.sessionEpoch = currentSessionEpoch();
  session.userSessionEpoch = currentUserSessionEpoch(session.username, session.source);
}

/** Invalidate every outstanding session (password change). */
export function bumpSessionEpoch(): void {
  const nextVal = Math.max(Date.now(), currentSessionEpoch() + 1);
  memoryEpoch = nextVal;
  const next = String(nextVal);
  for (const p of getEpochPaths()) {
    try {
      writeRevocationFileAtomic(p, next, 0o660);
    } catch {}
  }
}

function readRevokedJtiMap(nowSec = Math.floor(Date.now() / 1000)): Map<string, number> {
  const combined = new Map<string, number>();
  for (const [jti, exp] of memoryRevokedJtis) {
    if (exp <= nowSec) {
      memoryRevokedJtis.delete(jti);
    } else {
      combined.set(jti, exp);
    }
  }
  for (const p of getRevokedPaths()) {
    try {
      const lines = fs
        .readFileSync(p, 'utf-8')
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean);
      for (const line of lines) {
        const lastColon = line.lastIndexOf(':');
        let jti = line;
        let exp = nowSec + DEFAULT_REVOKED_TTL_SEC;
        if (lastColon > 0) {
          const maybeExp = line.slice(lastColon + 1);
          if (/^\d+$/.test(maybeExp)) {
            jti = line.slice(0, lastColon);
            exp = Number(maybeExp);
          }
        }
        if (!jti || exp <= nowSec) continue;
        const prev = combined.get(jti) ?? 0;
        if (exp > prev) combined.set(jti, exp);
      }
    } catch {}
  }
  return combined;
}

/** Revoke one token by its jti (logout) until its JWT expiry. */
export function revokeTokenJti(jti: string, expSec?: number): void {
  if (!jti) return;
  const nowSec = Math.floor(Date.now() / 1000);
  const effectiveExp =
    typeof expSec === 'number' && Number.isFinite(expSec) && expSec > nowSec
      ? Math.floor(expSec)
      : nowSec + DEFAULT_REVOKED_TTL_SEC;
  memoryRevokedJtis.set(jti, Math.max(effectiveExp, memoryRevokedJtis.get(jti) ?? 0));
  const combined = readRevokedJtiMap(nowSec);
  const content =
    Array.from(combined.entries())
      .map(([id, exp]) => `${id}:${exp}`)
      .join('\n') + '\n';
  for (const p of getRevokedPaths()) {
    try {
      writeRevocationFileAtomic(p, content, 0o660);
    } catch {}
  }
}

/** True when a decoded session has been revoked or predates the epoch. */
export function isSessionRevoked(session: UserSession): boolean {
  if ((session.sessionEpoch ?? 0) !== currentSessionEpoch()) return true;
  if ((session.userSessionEpoch ?? 0) < currentUserSessionEpoch(session.username, session.source)) return true;
  if (session.jti && readRevokedJtiMap().has(session.jti)) return true;
  return false;
}
