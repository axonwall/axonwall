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

const EPOCH_PATHS = Array.from(
  new Set([path.join(getStateDir(), 'session-epoch'), path.join(getEtcConfigDir(), 'session-epoch')])
);
const USER_EPOCH_PATHS = Array.from(
  new Set([
    path.join(getStateDir(), 'user-session-epochs.json'),
    path.join(getEtcConfigDir(), 'user-session-epochs.json'),
  ])
);
const REVOKED_PATHS = Array.from(
  new Set([path.join(getStateDir(), 'revoked-jtis'), path.join(getEtcConfigDir(), 'revoked-jtis')])
);
const MAX_REVOKED_ENTRIES = 500;
const MAX_USER_EPOCHS = 2000;

let memoryEpoch = 0;
const memoryUserEpochs = new Map<string, number>();
const memoryRevokedJtis = new Set<string>();

function normalizeEpochUserKey(username: string): string {
  return username.trim().toLowerCase();
}

function readUserEpochMap(): Map<string, number> {
  const combined = new Map<string, number>(memoryUserEpochs);
  for (const p of USER_EPOCH_PATHS) {
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

export function currentUserSessionEpoch(username: string): number {
  const key = normalizeEpochUserKey(username);
  if (!key) return 0;
  const epoch = readUserEpochMap().get(key) ?? 0;
  if (epoch > (memoryUserEpochs.get(key) ?? 0)) {
    memoryUserEpochs.set(key, epoch);
  }
  return epoch;
}

/** Invalidate outstanding sessions for a single user (e.g. self-service password reset/change). */
export function bumpUserSessionEpoch(username: string): number {
  const key = normalizeEpochUserKey(username);
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
  for (const p of USER_EPOCH_PATHS) {
    try {
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, serialized, { mode: 0o660 });
    } catch {}
  }
  return nextVal;
}

export function currentSessionEpoch(): number {
  let maxEpoch = memoryEpoch;
  for (const p of EPOCH_PATHS) {
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
  session.userSessionEpoch = currentUserSessionEpoch(session.username);
}

/** Invalidate every outstanding session (password change). */
export function bumpSessionEpoch(): void {
  const nextVal = Math.max(Date.now(), currentSessionEpoch() + 1);
  memoryEpoch = nextVal;
  const next = String(nextVal);
  for (const p of EPOCH_PATHS) {
    try {
      fs.writeFileSync(p, next, { mode: 0o660 });
    } catch {}
  }
}

function readRevokedJtis(): string[] {
  const combined = new Set<string>(memoryRevokedJtis);
  for (const p of REVOKED_PATHS) {
    try {
      const lines = fs
        .readFileSync(p, 'utf-8')
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean);
      for (const l of lines) combined.add(l);
    } catch {}
  }
  return Array.from(combined);
}

/** Revoke one token by its jti (logout). */
export function revokeTokenJti(jti: string): void {
  if (!jti) return;
  memoryRevokedJtis.add(jti);
  const entries = readRevokedJtis().slice(-MAX_REVOKED_ENTRIES);
  const content = entries.join('\n') + '\n';
  for (const p of REVOKED_PATHS) {
    try {
      fs.writeFileSync(p, content, { mode: 0o660 });
    } catch {}
  }
}

/** True when a decoded session has been revoked or predates the epoch. */
export function isSessionRevoked(session: UserSession): boolean {
  if ((session.sessionEpoch ?? 0) !== currentSessionEpoch()) return true;
  if ((session.userSessionEpoch ?? 0) < currentUserSessionEpoch(session.username)) return true;
  if (session.jti && readRevokedJtis().includes(session.jti)) return true;
  return false;
}
