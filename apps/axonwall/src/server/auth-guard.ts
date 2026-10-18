import type { UserSession } from '@axonwall/lib/rbac';

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
  if (session.passwordChangeRequired) {
    throw new Error('Forbidden: Password change required before performing this action');
  }
  if (requiredRole && (!session.roles || !session.roles.includes(requiredRole))) {
    throw new Error(`Forbidden: ${requiredRole} role required`);
  }
}
