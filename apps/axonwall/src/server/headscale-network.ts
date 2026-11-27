import crypto from 'node:crypto';
import net from 'node:net';
import type { NextRequest } from 'next/server';
import { sanitizeHaProxyHostname } from '@axonwall/lib/compile/haproxy';
import { getDesiredStateInternal } from './desired-state-internal';
import { resolvePublicOrigin } from './oidc';
import { isHeadscaleSocketReady, readHeadscaleConfigDefaults } from './headscale';

export interface HeadscaleWanInviteNetworkInfo {
  enabled: boolean;
  hostname: string;
  bindPort: number;
  baseUrl: string;
  autoWindow: boolean;
  requirePin: boolean;
  portKnocking: {
    enabled: boolean;
    protocol: 'tcp' | 'udp';
    sequence: number[];
    stepTimeoutSec: number;
    openDurationSec: number;
  };
}

export interface HeadscaleNetworkInfo {
  enabled: boolean;
  serviceRunning: boolean;
  serverUrl: string;
  portalUrl: string;
  magicDnsDomain: string;
  allowSelfRegistration: boolean;
  defaultKeyExpiryHours: number;
  wanInvite: HeadscaleWanInviteNetworkInfo;
}

export async function resolveHeadscaleNetworkInfo(
  req?: Pick<NextRequest, 'headers' | 'nextUrl'>
): Promise<HeadscaleNetworkInfo> {
  const state = await getDesiredStateInternal().catch(() => null);
  const cfgDefaults = readHeadscaleConfigDefaults();

  const reqOrigin = req ? resolvePublicOrigin(req.headers, '') : '';

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

  const wan = state?.headscale?.wanInvite;
  const wanEnabled = Boolean(enabled && wan?.enabled);
  const wanHostname = sanitizeHaProxyHostname(wan?.hostname);
  const rawBindPort = wan?.bindPort ?? 8443;
  const wanBindPort = Number.isInteger(rawBindPort) && rawBindPort >= 1 && rawBindPort <= 65535 ? rawBindPort : 8443;
  const wanBaseUrl =
    wanEnabled && wanHostname
      ? `https://${wanHostname}${wanBindPort === 443 ? '' : `:${wanBindPort}`}`
      : '';
  const knock = wan?.portKnocking;
  const knockSequence =
    knock?.sequence && knock.sequence.length >= 2 ? knock.sequence : [41821, 52913, 38477];

  return {
    enabled,
    serviceRunning,
    serverUrl,
    portalUrl,
    magicDnsDomain,
    allowSelfRegistration: state?.headscale?.allowSelfRegistration !== false,
    defaultKeyExpiryHours: state?.headscale?.defaultKeyExpiryHours ?? 24,
    wanInvite: {
      enabled: wanEnabled,
      hostname: wanHostname,
      bindPort: wanBindPort,
      baseUrl: wanBaseUrl,
      autoWindow: wan?.autoWindow !== false,
      requirePin: Boolean(wan?.requirePin),
      portKnocking: {
        enabled: Boolean(wanEnabled && knock?.enabled),
        protocol: knock?.protocol === 'tcp' ? 'tcp' : 'udp',
        sequence: knockSequence,
        stepTimeoutSec: knock?.stepTimeoutSec ?? 15,
        openDurationSec: knock?.openDurationSec ?? 900,
      },
    },
  };
}

function normalizeIpLiteral(raw: string | undefined | null): string {
  const trimmed = (raw || '').trim();
  if (!trimmed) return '';
  const stripped =
    trimmed.startsWith('::ffff:') && net.isIPv4(trimmed.slice(7)) ? trimmed.slice(7) : trimmed;
  return net.isIP(stripped) ? stripped : '';
}

function isLoopbackIp(ip: string): boolean {
  return ip === '127.0.0.1' || ip === '::1';
}

export function resolveClientIp(req: Request, peerIpOverride?: string): string {
  const rawPeer =
    peerIpOverride ??
    (req as { ip?: string; socket?: { remoteAddress?: string } }).ip ??
    (req as { socket?: { remoteAddress?: string } }).socket?.remoteAddress;
  const peerIp = normalizeIpLiteral(rawPeer);
  const trustProxy =
    process.env.AXONWALL_TRUST_PROXY === '1' ||
    process.env.AXONWALL_TRUST_PROXY === 'true' ||
    (peerIp !== '' && isLoopbackIp(peerIp));

  if (trustProxy) {
    const rawXff = req.headers.get('x-forwarded-for');
    if (rawXff) {
      const parts = rawXff
        .split(',')
        .map((p) => normalizeIpLiteral(p))
        .filter(Boolean);
      const rightmost = parts[parts.length - 1];
      if (rightmost) return rightmost;
    }
    const realIp = normalizeIpLiteral(req.headers.get('x-real-ip'));
    if (realIp) return realIp;
  }
  return peerIp || 'unknown';
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

export function buildPortKnockCommands(
  hostname: string,
  protocol: 'tcp' | 'udp',
  sequence: number[]
): { unix: string; powershell: string } {
  const cleanHost = sanitizeHaProxyHostname(hostname) || '<INVITE_HOST>';
  const ports = (sequence.length > 0 ? sequence : [41821, 52913, 38477]).filter(
    (p) => Number.isInteger(p) && p >= 1 && p <= 65535
  );
  const portsSpace = ports.join(' ');
  const portsComma = ports.join(',');

  if (protocol === 'tcp') {
    const unix = `for p in ${portsSpace}; do nc -z -w 1 ${cleanHost} "$p" >/dev/null 2>&1 || true; sleep 0.25; done`;
    const powershell = `${portsComma} | ForEach-Object { $c = New-Object System.Net.Sockets.TcpClient; $ar = $c.BeginConnect('${cleanHost}', $_, $null, $null); $ar.AsyncWaitHandle.WaitOne(250) | Out-Null; $c.Close(); Start-Sleep -Milliseconds 250 }`;
    return { unix, powershell };
  }

  const unix = `for p in ${portsSpace}; do printf 'knock' | nc -u -w 1 ${cleanHost} "$p" >/dev/null 2>&1 || true; sleep 0.25; done`;
  const powershell = `$u = New-Object System.Net.Sockets.UdpClient; $b = [Text.Encoding]::ASCII.GetBytes('knock'); ${portsComma} | ForEach-Object { $u.Send($b, $b.Length, '${cleanHost}', $_) | Out-Null; Start-Sleep -Milliseconds 250 }; $u.Close()`;
  return { unix, powershell };
}
