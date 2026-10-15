import * as fs from 'node:fs';

export const SESSION_COOKIE = 'axonwall_session';

export function getJwtSecret(): string {
  if (process.env.JWT_SECRET) {
    return process.env.JWT_SECRET;
  }
  try {
    if (fs.existsSync('/etc/axonwall/axonwall.env')) {
      const content = fs.readFileSync('/etc/axonwall/axonwall.env', 'utf8');
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (trimmed.startsWith('JWT_SECRET=')) {
          const val = trimmed.slice('JWT_SECRET='.length).trim();
          if (val) {
            process.env.JWT_SECRET = val;
            return val;
          }
        }
      }
    }
  } catch {}
  return 'super-secret-axonwall-jwt-signing-key-32-bytes!';
}
