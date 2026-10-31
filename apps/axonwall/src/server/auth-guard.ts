import type { UserSession } from '@axonwall/lib/rbac';

const ROLE_HIERARCHY: Record<string, number> = {
  readonly: 1,
  operator: 2,
  admin: 3,
};

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
  if (session.passwordChangeRequired && requiredRole && requiredRole !== 'readonly') {
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
