import fs from 'node:fs';

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

const EPOCH_PATHS = ['/var/lib/axonwall/session-epoch', '/etc/axonwall/session-epoch'];
const REVOKED_PATHS = ['/var/lib/axonwall/revoked-jtis', '/etc/axonwall/revoked-jtis'];
const MAX_REVOKED_ENTRIES = 500;

export function currentSessionEpoch(): number {
  for (const p of EPOCH_PATHS) {
    try {
      const value = Number(fs.readFileSync(p, 'utf-8').trim());
      if (Number.isFinite(value) && value > 0) return value;
    } catch {}
  }
  return 0;
}

/** Stamp a session with the current epoch before it is minted. */
export function stampSessionEpoch(session: UserSession): void {
  session.sessionEpoch = currentSessionEpoch();
}

/** Invalidate every outstanding session (password change). */
export function bumpSessionEpoch(): void {
  const next = String(Date.now());
  for (const p of EPOCH_PATHS) {
    try {
      fs.writeFileSync(p, next, { mode: 0o644 });
    } catch {}
  }
}

function readRevokedJtis(): string[] {
  for (const p of REVOKED_PATHS) {
    try {
      return fs
        .readFileSync(p, 'utf-8')
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean);
    } catch {}
  }
  return [];
}

/** Revoke one token by its jti (logout). */
export function revokeTokenJti(jti: string): void {
  if (!jti) return;
  const entries = [...readRevokedJtis(), jti].slice(-MAX_REVOKED_ENTRIES);
  const content = entries.join('\n') + '\n';
  for (const p of REVOKED_PATHS) {
    try {
      fs.writeFileSync(p, content, { mode: 0o644 });
    } catch {}
  }
}

/** True when a decoded session has been revoked or predates the epoch. */
export function isSessionRevoked(session: UserSession): boolean {
  if ((session.sessionEpoch ?? 0) !== currentSessionEpoch()) return true;
  if (session.jti && readRevokedJtis().includes(session.jti)) return true;
  return false;
}
