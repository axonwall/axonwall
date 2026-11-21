import fs from 'node:fs';
import path from 'node:path';
import type { UserSession } from '@axonwall/lib/rbac';
import { getEtcConfigDir, getStateDir } from './dev-paths';

const ROLE_HIERARCHY: Record<string, number> = {
  readonly: 1,
  operator: 2,
  admin: 3,
};

/**
 * The single source of truth for whether the local break-glass admin password
 * has never been changed (no `.password_changed` marker exists).
 */
export function passwordChangeRequiredNow(): boolean {
  try {
    const markerCandidates = Array.from(
      new Set([
        path.join(getStateDir(), '.password_changed'),
        path.join(getEtcConfigDir(), '.password_changed'),
        './.password_changed',
      ])
    );
    if (markerCandidates.some((p) => fs.existsSync(p))) {
      return false;
    }
  } catch {}

  if (process.env.NODE_ENV !== 'production' && process.env.FORCE_PASSWORD_CHANGE !== 'true') {
    return false;
  }

  return true;
}

export function isPasswordChangeEnforced(session: UserSession | null): boolean {
  if (!session) {
    return false;
  }
  return (
    Boolean(session.passwordChangeRequired) ||
    (session.source === 'local_admin' && passwordChangeRequiredNow())
  );
}

/**
 * Asserts that a valid authenticated session exists and that any
 * required roles or password changes are satisfied.
 */
export function assertActionPermitted(
  session: UserSession | null,
  requiredRole?: string
): asserts session is UserSession {
  if (!session) {
    throw new Error('Unauthorized');
  }
  const mustChangePassword = isPasswordChangeEnforced(session);
  if (mustChangePassword && requiredRole && requiredRole !== 'readonly') {
    throw new Error('Forbidden: Password change required before performing this action');
  }
  if (requiredRole) {
    if (session.privileges?.includes('*')) {
      return;
    }
    const roles = session.roles || [];
    const requiredRank = ROLE_HIERARCHY[requiredRole];
    const isPermitted =
      requiredRank !== undefined
        ? roles.some((r) => (ROLE_HIERARCHY[r] ?? 0) >= requiredRank)
        : roles.includes(requiredRole);
    if (!isPermitted) {
      throw new Error(`Forbidden: ${requiredRole} role required`);
    }
  }
}
