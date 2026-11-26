import fs from 'node:fs';
import path from 'node:path';
import type { UserSession } from '@axonwall/lib/rbac';
import { getEtcConfigDir, getStateDir } from './dev-paths';

const ROLE_HIERARCHY: Record<string, number> = {
  vpn_user: 0,
  readonly: 1,
  operator: 2,
  admin: 3,
};

export function isConsoleUser(session: UserSession | null): boolean {
  if (!session) return false;
  if (session.source === 'service_token' && !session.scopes?.includes('*')) {
    return false;
  }
  if (session.privileges?.includes('*')) return true;
  const roles = session.roles || [];
  return roles.some((r) => r === 'admin' || r === 'operator' || r === 'readonly');
}

export function isVpnPortalOnlyUser(session: UserSession | null): boolean {
  if (!session || isConsoleUser(session)) return false;
  return Boolean(
    session.roles?.includes('vpn_user') || session.privileges?.includes('vpn.mesh.self')
  );
}

/**
 * Rejects unauthenticated, password-change-pending, and non-interactive
 * service-token sessions on interactive account/credential/backup routes.
 */
export function assertInteractiveSession(
  session: UserSession | null
): asserts session is UserSession {
  if (!session) {
    throw new Error('Unauthorized');
  }
  if (session.source === 'service_token') {
    throw new Error('Forbidden: Service tokens cannot perform interactive administrative or account actions');
  }
  if (isPasswordChangeEnforced(session)) {
    throw new Error('Forbidden: Password change required before performing this action');
  }
}

/**
 * Asserts that a session is authorized to access Mesh VPN self-service APIs.
 * Permits vpn_user as well as console roles (readonly/operator/admin), but never service tokens.
 */
export function assertMeshSelfServicePermitted(
  session: UserSession | null
): asserts session is UserSession {
  if (!session) {
    throw new Error('Unauthorized');
  }
  if (session.source === 'service_token') {
    throw new Error('Forbidden: Service tokens cannot access Mesh VPN self-service endpoints');
  }
  if (isPasswordChangeEnforced(session)) {
    throw new Error('Forbidden: Password change required before performing this action');
  }
  if (isConsoleUser(session) || session.roles?.includes('vpn_user') || session.privileges?.includes('vpn.mesh.self')) {
    return;
  }
  throw new Error('Forbidden: Mesh VPN self-service access required');
}

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
 * required roles, service-token scopes, or password changes are satisfied.
 */
export function assertActionPermitted(
  session: UserSession | null,
  requiredRole?: string,
  requiredScope?: string | string[]
): asserts session is UserSession {
  if (!session) {
    throw new Error('Unauthorized');
  }
  const mustChangePassword = isPasswordChangeEnforced(session);
  if (mustChangePassword && requiredRole && requiredRole !== 'readonly') {
    throw new Error('Forbidden: Password change required before performing this action');
  }

  const effectiveRole = requiredRole ?? 'readonly';
  const roles = session.roles || [];
  const requiredRank = ROLE_HIERARCHY[effectiveRole];

  if (session.source === 'service_token') {
    const roleOk =
      requiredRank !== undefined
        ? roles.some((r) => (ROLE_HIERARCHY[r] ?? -1) >= requiredRank)
        : roles.includes(effectiveRole);
    if (!roleOk) {
      throw new Error(`Forbidden: ${effectiveRole} role required`);
    }
    const tokenScopes = Array.isArray(session.scopes) ? session.scopes : [];
    if (tokenScopes.includes('*')) {
      return;
    }
    const allowedScopes = Array.isArray(requiredScope)
      ? requiredScope
      : requiredScope
        ? [requiredScope]
        : [];
    if (allowedScopes.length === 0 || !allowedScopes.some((s) => tokenScopes.includes(s))) {
      throw new Error(
        allowedScopes.length > 0
          ? `Forbidden: Service token lacks required scope (${allowedScopes.join(' or ')})`
          : 'Forbidden: Scoped service token is not permitted on this endpoint'
      );
    }
    return;
  }

  if (session.privileges?.includes('*')) {
    return;
  }
  const isPermitted =
    requiredRank !== undefined
      ? roles.some((r) => (ROLE_HIERARCHY[r] ?? -1) >= requiredRank)
      : roles.includes(effectiveRole);
  if (!isPermitted) {
    throw new Error(`Forbidden: ${effectiveRole} role required`);
  }
}
