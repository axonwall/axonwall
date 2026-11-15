import * as fs from 'node:fs';
import * as path from 'node:path';
import { getEtcConfigDir } from './dev-paths';

export const SESSION_COOKIE = 'axonwall_session';

export function getJwtSecret(): string {
  if (process.env.JWT_SECRET) {
    return process.env.JWT_SECRET;
  }
  const envCandidates = Array.from(
    new Set([path.join(getEtcConfigDir(), 'axonwall.env'), '/etc/axonwall/axonwall.env'])
  );
  for (const envPath of envCandidates) {
    try {
      if (fs.existsSync(envPath)) {
        const content = fs.readFileSync(envPath, 'utf8');
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
  }
  // Fail closed: a session secret must never fall back to a value
  // printed in the source tree. Anyone who can read this repository
  // could otherwise mint admin sessions for any deployment that
  // forgot to configure one (the shipped Docker compose did exactly
  // that). Packaged appliances always provision a random per-device
  // secret into axonwall.env at first boot, so this only fires on
  // misconfigured deployments -- which should fail loudly, here, at
  // the first auth request, instead of silently running forgeable.
  throw new Error(
    'JWT_SECRET is not configured: set the JWT_SECRET environment variable or provision /etc/axonwall/axonwall.env (packaged appliances generate one at first boot). Refusing to sign or verify sessions with a fallback secret.'
  );
}
