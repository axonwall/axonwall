export const SESSION_COOKIE = 'axonwall_session';

export function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (process.env.NODE_ENV === 'production' && !secret) {
    throw new Error('JWT_SECRET environment variable is required in production');
  }
  return secret || 'super-secret-axonwall-jwt-signing-key-32-bytes!';
}
