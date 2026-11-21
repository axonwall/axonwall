import crypto from 'node:crypto';
import type { NextRequest } from 'next/server';
import { getDesiredStateInternal } from './desired-state-internal';
import { resolvePublicOrigin } from './oidc';
import { isHeadscaleSocketReady, readHeadscaleConfigDefaults } from './headscale';

export interface HeadscaleNetworkInfo {
  enabled: boolean;
  serviceRunning: boolean;
  serverUrl: string;
  portalUrl: string;
  magicDnsDomain: string;
  allowSelfRegistration: boolean;
  defaultKeyExpiryHours: number;
}

export async function resolveHeadscaleNetworkInfo(
  req?: Pick<NextRequest, 'headers' | 'nextUrl'>
): Promise<HeadscaleNetworkInfo> {
  const state = await getDesiredStateInternal().catch(() => null);
  const cfgDefaults = readHeadscaleConfigDefaults();

  const reqOrigin = req
    ? resolvePublicOrigin(req.headers, req.nextUrl?.origin || 'https://axonwall.local')
    : '';

  const enabled = Boolean(state?.headscale?.enabled);
  const serviceRunning = isHeadscaleSocketReady();
  const magicDnsDomain =
    state?.headscale?.magicDnsDomain?.trim() ||
    cfgDefaults.magicDnsDomain ||
    'tailnet.axonwall.local';

  const configuredServerUrl = state?.headscale?.serverUrl?.trim().replace(/\/+$/, '') || '';
  const fallbackCfgUrl =
    cfgDefaults.serverUrl && cfgDefaults.serverUrl !== 'http://127.0.0.1:8080'
      ? cfgDefaults.serverUrl
      : '';
  const serverUrl = configuredServerUrl || fallbackCfgUrl || '';

  const configuredPortalUrl = state?.headscale?.portalUrl?.trim().replace(/\/+$/, '') || '';
  const portalUrl = configuredPortalUrl || reqOrigin || '';

  return {
    enabled,
    serviceRunning,
    serverUrl,
    portalUrl,
    magicDnsDomain,
    allowSelfRegistration: state?.headscale?.allowSelfRegistration !== false,
    defaultKeyExpiryHours: state?.headscale?.defaultKeyExpiryHours ?? 24,
  };
}

export function resolveClientIp(req: Request): string {
  const fwd = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
  if (fwd) return fwd;
  const realIp = req.headers.get('x-real-ip')?.trim();
  if (realIp) return realIp;
  return 'unknown';
}

export function generateTemporaryPassword(length = 16): string {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const digits = '23456789';
  const symbols = '!@#%*-_+=';
  const all = upper + lower + digits + symbols;

  const chars = [
    upper[crypto.randomInt(upper.length)],
    lower[crypto.randomInt(lower.length)],
    digits[crypto.randomInt(digits.length)],
    symbols[crypto.randomInt(symbols.length)],
  ];
  while (chars.length < length) {
    chars.push(all[crypto.randomInt(all.length)]);
  }
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

export function buildQuickConnectCommand(serverUrl: string, authKey?: string | null): string {
  const loginArg = serverUrl ? `--login-server=${serverUrl}` : '--login-server=<YOUR_HEADSCALE_URL>';
  if (authKey) {
    return `tailscale up ${loginArg} --authkey=${authKey}`;
  }
  return `tailscale up ${loginArg}`;
}
