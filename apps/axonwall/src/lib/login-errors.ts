/**
 * Strict allowlist mapping for `/login?error=` query codes so arbitrary
 * attacker-supplied URL text is never reflected in the login UI (SEC-L21).
 */

const LOGIN_ERROR_ALLOWLIST: Record<string, string> = {
  // Canonical error codes
  sso_not_configured: 'SSO is not configured.',
  sso_unreachable: 'SSO provider unreachable.',
  sso_invalid_callback: 'Invalid SSO callback.',
  sso_invalid_state: 'Invalid SSO state.',
  sso_unauthorized: 'Your SSO account is not authorized for any Axonwall role.',
  sso_email_unverified: 'Your SSO email address must be verified before signing in.',
  sso_failed: 'SSO sign-in failed.',
  session_expired: 'Your session has expired. Please sign in again.',
  unauthorized: 'Authentication is required.',

  // Fixed messages currently emitted by /api/auth/sso/login and /api/auth/callback/oidc
  'SSO is not configured': 'SSO is not configured.',
  'SSO provider unreachable': 'SSO provider unreachable.',
  'Invalid SSO callback': 'Invalid SSO callback.',
  'Invalid SSO state': 'Invalid SSO state.',
  'Your SSO account is not authorized for any Axonwall role':
    'Your SSO account is not authorized for any Axonwall role.',
  'SSO sign-in failed': 'SSO sign-in failed.',
};

export function resolveLoginQueryError(rawError: string | null | undefined): string | null {
  if (typeof rawError !== 'string') return null;
  const trimmed = rawError.trim();
  if (!trimmed) return null;
  if (!Object.prototype.hasOwnProperty.call(LOGIN_ERROR_ALLOWLIST, trimmed)) {
    return null;
  }
  return LOGIN_ERROR_ALLOWLIST[trimmed];
}
