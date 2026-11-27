/**
 * Safe CLI command quoting, YAML scalar quoting, WireGuard config generation,
 * and strict input validators for UI-generated commands and configs (SEC-M17).
 */

const CONTROL_OR_NEWLINE_RE = /[\u0000-\u001f\u007f]/;
const RFC_HOSTNAME_RE =
  /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$/;
const LINUX_IFACE_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,14}$/;
const NODE_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;
const TOKEN_RE = /^[A-Za-z0-9._~+/=:-]{1,512}$/;
const WIREGUARD_KEY_RE = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;
const SHELL_UNSAFE_URL_RE = /[\u0000-\u001f\u007f\s'"`$;|&<>\\()]/;

export const ALLOWED_FLEET_SKUS = [
  'sku-vm-virtio',
  'sku-x86-intel-n100-i226',
  'sku-x86-enterprise-10g-25g',
  'sku-arm64-router',
  'generic-edge',
] as const;

export function hasControlOrNewline(value: string): boolean {
  return CONTROL_OR_NEWLINE_RE.test(value);
}

/**
 * Escapes an arbitrary value as a POSIX shell single-quoted literal.
 * NUL bytes are stripped because POSIX command arguments cannot carry NUL.
 */
export function posixShellQuote(value: string): string {
  const clean = String(value).replace(/\0/g, '');
  return `'${clean.replace(/'/g, `'\\''`)}'`;
}

/**
 * Escapes an arbitrary value as a PowerShell single-quoted literal.
 * Inside PowerShell single quotes only `''` is special; `$()`, backticks,
 * and semicolons are treated literally.
 */
export function powershellQuote(value: string): string {
  const clean = String(value).replace(/\0/g, '');
  return `'${clean.replace(/'/g, "''")}'`;
}

export function isSafeYamlScalar(value: string): boolean {
  if (typeof value !== 'string') return false;
  if (hasControlOrNewline(value)) return false;
  if (/['"]/.test(value)) return false;
  return true;
}

/**
 * Quotes a YAML scalar using JSON double-quoting after rejecting newlines,
 * control characters, and quote characters.
 */
export function yamlQuoteScalar(value: string): string {
  if (!isSafeYamlScalar(value)) {
    throw new Error('YAML scalar contains disallowed control characters, newlines, or quotes.');
  }
  return JSON.stringify(value);
}

export function isValidHostname(raw: string | null | undefined): boolean {
  if (typeof raw !== 'string') return false;
  const trimmed = raw.trim();
  if (!trimmed || trimmed !== raw) return false;
  if (hasControlOrNewline(trimmed)) return false;
  return RFC_HOSTNAME_RE.test(trimmed);
}

/**
 * Normalizes and validates a hostname (stripping an optional scheme, path, or trailing :port,
 * while strictly rejecting userinfo `@`, whitespace, quotes, or control characters).
 */
export function sanitizeHostname(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed || hasControlOrNewline(trimmed)) return null;
  if (/[\s@'"`$;|&<>\\()[\]]/.test(trimmed)) return null;

  let host = trimmed.replace(/^https?:\/\//i, '');
  const slashIdx = host.indexOf('/');
  if (slashIdx >= 0) host = host.slice(0, slashIdx);
  const colonIdx = host.indexOf(':');
  if (colonIdx >= 0) {
    const portPart = host.slice(colonIdx + 1);
    if (!/^\d{1,5}$/.test(portPart)) return null;
    host = host.slice(0, colonIdx);
  }
  host = host.toLowerCase();
  return RFC_HOSTNAME_RE.test(host) ? host : null;
}

export function sanitizeHttpUrl(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed || SHELL_UNSAFE_URL_RE.test(trimmed)) return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    if (parsed.username || parsed.password) return null;
    if (!parsed.hostname) return null;
    return trimmed.replace(/\/+$/, '');
  } catch {
    return null;
  }
}

export function isValidHttpUrl(raw: string | null | undefined): boolean {
  return sanitizeHttpUrl(raw) !== null;
}

export function isValidInterfaceName(raw: string | null | undefined): boolean {
  if (typeof raw !== 'string') return false;
  const trimmed = raw.trim();
  if (!trimmed || trimmed !== raw) return false;
  if (hasControlOrNewline(trimmed) || trimmed.includes('..')) return false;
  return LINUX_IFACE_RE.test(trimmed);
}

export function isValidIpv4(raw: string): boolean {
  const parts = raw.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return false;
  }
  return true;
}

export function isValidIpv6(raw: string): boolean {
  if (!raw || raw.includes(' ') || hasControlOrNewline(raw)) return false;
  if ((raw.match(/::/g) || []).length > 1) return false;
  // Disallow zone IDs or embedded invalid characters
  if (!/^[0-9a-fA-F:]+$/.test(raw)) return false;
  const halves = raw.split('::');
  if (halves.length === 1) {
    const groups = halves[0].split(':');
    return groups.length === 8 && groups.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g));
  }
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  if (left.length + right.length >= 8) return false;
  return (
    left.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g)) &&
    right.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))
  );
}

export function isValidIpAddress(raw: string | null | undefined): boolean {
  if (typeof raw !== 'string') return false;
  const trimmed = raw.trim();
  if (!trimmed || trimmed !== raw || hasControlOrNewline(trimmed)) return false;
  return isValidIpv4(trimmed) || isValidIpv6(trimmed);
}

export function isValidCidr(raw: string | null | undefined): boolean {
  if (typeof raw !== 'string') return false;
  const trimmed = raw.trim();
  if (!trimmed || trimmed !== raw || hasControlOrNewline(trimmed)) return false;
  const slashIdx = trimmed.indexOf('/');
  if (slashIdx < 0 || trimmed.indexOf('/', slashIdx + 1) >= 0) return false;
  const ip = trimmed.slice(0, slashIdx);
  const prefixStr = trimmed.slice(slashIdx + 1);
  if (!/^\d{1,3}$/.test(prefixStr)) return false;
  if (prefixStr.length > 1 && prefixStr.startsWith('0')) return false;
  const prefix = Number(prefixStr);
  if (isValidIpv4(ip)) {
    return prefix >= 0 && prefix <= 32;
  }
  if (isValidIpv6(ip)) {
    return prefix >= 0 && prefix <= 128;
  }
  return false;
}

export function isValidToken(raw: string | null | undefined): boolean {
  if (typeof raw !== 'string') return false;
  const trimmed = raw.trim();
  if (!trimmed || trimmed !== raw || hasControlOrNewline(trimmed)) return false;
  return TOKEN_RE.test(trimmed);
}

export function isValidNodeId(raw: string | null | undefined): boolean {
  if (typeof raw !== 'string') return false;
  const trimmed = raw.trim();
  if (!trimmed || trimmed !== raw || hasControlOrNewline(trimmed)) return false;
  return NODE_ID_RE.test(trimmed);
}

export function isValidWireGuardKey(raw: string | null | undefined): boolean {
  if (typeof raw !== 'string') return false;
  const trimmed = raw.trim();
  if (!trimmed || trimmed !== raw || hasControlOrNewline(trimmed)) return false;
  return WIREGUARD_KEY_RE.test(trimmed);
}

export function isValidPort(port: number | string): boolean {
  const n = typeof port === 'number' ? port : /^\d{1,5}$/.test(port) ? Number(port) : Number.NaN;
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

export function sanitizeKnockPorts(raw: string, minPort = 1, maxCount = 5): number[] {
  return raw
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter((s) => /^\d{1,5}$/.test(s))
    .map((s) => Number.parseInt(s, 10))
    .filter((n) => Number.isInteger(n) && n >= minPort && n <= 65535)
    .slice(0, maxCount);
}

export type TailscaleCommandTarget = 'linux' | 'macos' | 'windows' | 'docker';

export function buildTailscaleConnectCommand(
  target: TailscaleCommandTarget,
  serverUrl: string | null | undefined,
  authKey: string | null | undefined,
  placeholderUrl = '<YOUR_HEADSCALE_URL>'
): string {
  const cleanUrl = sanitizeHttpUrl(serverUrl) ?? placeholderUrl;
  const cleanKey = isValidToken(authKey?.trim()) ? authKey!.trim() : '<YOUR_AUTH_KEY>';

  if (target === 'windows') {
    return `& "C:\\Program Files\\Tailscale\\tailscale.exe" up ${powershellQuote(`--login-server=${cleanUrl}`)} ${powershellQuote(`--authkey=${cleanKey}`)}`;
  }
  if (target === 'docker') {
    return `docker run -d --name=tailscale --restart=unless-stopped -e ${posixShellQuote(`TS_AUTHKEY=${cleanKey}`)} -e ${posixShellQuote(`TS_EXTRA_ARGS=--login-server=${cleanUrl}`)} ghcr.io/tailscale/tailscale:latest`;
  }
  const prefix = target === 'linux' ? 'sudo tailscale up' : 'tailscale up';
  return `${prefix} --login-server=${posixShellQuote(cleanUrl)} --authkey=${posixShellQuote(cleanKey)}`;
}

export function buildPortKnockPreviewCommand(
  hostname: string | null | undefined,
  protocol: 'tcp' | 'udp',
  sequenceInput: string
): string {
  const cleanHost = sanitizeHostname(hostname) || '<INVITE_HOST>';
  const ports = sanitizeKnockPorts(sequenceInput, 1, 5);
  const portList = (ports.length > 0 ? ports : [41821, 52913, 38477]).join(' ');
  const probe = protocol === 'tcp' ? 'nc -z -w 1' : "printf 'knock' | nc -u -w 1";
  return `for p in ${portList}; do ${probe} ${posixShellQuote(cleanHost)} "$p" >/dev/null 2>&1 || true; sleep 0.25; done`;
}

export interface FleetZtpInput {
  hubHostname: string;
  listenPort: number;
  nodeId: string;
  nodeRole: 'edge-ngfw' | 'satellite';
  nodeSku: string;
  wanInterface: string;
  lanInterface: string;
  ztpToken: string;
}

export type FleetZtpResult =
  | {
      ok: true;
      ukiCmdline: string;
      cloudInitSnippet: string;
      bootstrapCommand: string;
    }
  | {
      ok: false;
      error: string;
    };

export function buildFleetZtpSnippets(input: FleetZtpInput): FleetZtpResult {
  const rawHost = input.hubHostname.trim();
  const unbracketedIpv6 =
    rawHost.startsWith('[') && rawHost.endsWith(']') ? rawHost.slice(1, -1) : rawHost;
  const safeHost =
    sanitizeHostname(rawHost) ||
    (isValidIpv6(unbracketedIpv6) ? `[${unbracketedIpv6}]` : null);
  if (!safeHost) {
    return { ok: false, error: 'Invalid hub hostname for ZTP snippet generation.' };
  }
  if (!isValidPort(input.listenPort)) {
    return { ok: false, error: 'Invalid hub listen port (must be 1-65535).' };
  }
  const defaultNodeId = input.nodeRole === 'edge-ngfw' ? 'edge-ngfw-01' : 'sat-branch-01';
  const rawNodeId = input.nodeId.trim() || defaultNodeId;
  if (!isValidNodeId(rawNodeId)) {
    return {
      ok: false,
      error: 'Invalid Node ID: use 1-64 characters from [a-zA-Z0-9._-] without spaces, quotes, or newlines.',
    };
  }
  if (!(ALLOWED_FLEET_SKUS as readonly string[]).includes(input.nodeSku)) {
    return { ok: false, error: 'Invalid hardware SKU profile.' };
  }
  const rawWan = input.wanInterface.trim() || 'eth0';
  const rawLan = input.lanInterface.trim() || 'eth1';
  if (!isValidInterfaceName(rawWan) || !isValidInterfaceName(rawLan)) {
    return {
      ok: false,
      error: 'Invalid interface name: use Linux interface characters [a-zA-Z0-9._-] (max 15 chars, no quotes or newlines).',
    };
  }
  const rawToken = input.ztpToken.trim();
  if (rawToken && (!isValidToken(rawToken) || !isSafeYamlScalar(rawToken))) {
    return {
      ok: false,
      error: 'Invalid ZTP token: whitespace, quotes, newlines, and shell metacharacters are not allowed.',
    };
  }

  const hubUrl = `wss://${safeHost}:${input.listenPort}/ws/satellite`;
  const effectiveToken = rawToken || '<AXONWALL_ZTP_TOKEN>';
  const ukiCmdline = `console=ttyS0,115200 quiet loglevel=3 axonwall.hub=${hubUrl} axonwall.id=${rawNodeId} axonwall.token=${effectiveToken} axonwall.sku=${input.nodeSku} axonwall.slot=A axonwall.wan=${rawWan}:dhcp axonwall.lan=${rawLan}:192.168.1.1/24`;

  const cloudInitSnippet = [
    '#cloud-config',
    `hostname: ${yamlQuoteScalar(rawNodeId)}`,
    'axonwall:',
    `  hub: ${yamlQuoteScalar(hubUrl)}`,
    `  id: ${yamlQuoteScalar(rawNodeId)}`,
    `  token: ${yamlQuoteScalar(effectiveToken)}`,
    `  sku: ${yamlQuoteScalar(input.nodeSku)}`,
    '  interfaces:',
    '    - name: wan',
    `      device: ${yamlQuoteScalar(rawWan)}`,
    '      address: dhcp',
    '    - name: lan',
    `      device: ${yamlQuoteScalar(rawLan)}`,
    '      address: "192.168.1.1/24"',
  ].join('\n');

  const bootstrapCommand =
    input.nodeRole === 'edge-ngfw'
      ? `./packaging/edge-uki/build-edge-uki.sh \\\n  --sku ${posixShellQuote(input.nodeSku)} \\\n  --cmdline ${posixShellQuote(ukiCmdline)}`
      : `./axonwall-satellite \\\n  -core ${posixShellQuote(hubUrl)} \\\n  -id ${posixShellQuote(rawNodeId)} \\\n  -token ${posixShellQuote(effectiveToken)}`;

  return {
    ok: true,
    ukiCmdline,
    cloudInitSnippet,
    bootstrapCommand,
  };
}

export interface WireGuardClientProfileInput {
  peerName: string;
  allowedIp: string;
  serverAddress: string;
  serverPublicKey: string;
  listenPort: number;
  systemHostname?: string;
  systemDomain?: string;
}

export type WireGuardClientProfileResult =
  | { ok: true; conf: string }
  | { ok: false; error: string };

export function buildWireGuardClientProfile(
  input: WireGuardClientProfileInput
): WireGuardClientProfileResult {
  if (!input.serverPublicKey || !isValidWireGuardKey(input.serverPublicKey.trim())) {
    return {
      ok: false,
      error:
        'Cannot export client config: server public key is missing or not a valid 44-character base64 WireGuard key.',
    };
  }
  const cleanPeerName = input.peerName.trim();
  if (!cleanPeerName || hasControlOrNewline(cleanPeerName)) {
    return {
      ok: false,
      error: 'Cannot export client config: peer name contains invalid control characters or line breaks.',
    };
  }
  const cleanAllowedIp = input.allowedIp.trim();
  if (!isValidCidr(cleanAllowedIp) && !isValidIpAddress(cleanAllowedIp)) {
    return {
      ok: false,
      error: 'Cannot export client config: peer AllowedIPs must be a valid IP or CIDR without line breaks.',
    };
  }
  const cleanServerAddr = input.serverAddress.trim();
  if (!isValidCidr(cleanServerAddr)) {
    return {
      ok: false,
      error: 'Cannot export client config: server Tunnel CIDR is invalid.',
    };
  }
  const dnsIp = cleanServerAddr.split('/')[0];
  if (!isValidIpAddress(dnsIp)) {
    return {
      ok: false,
      error: 'Cannot export client config: derived DNS IP is invalid.',
    };
  }
  if (!isValidPort(input.listenPort)) {
    return {
      ok: false,
      error: 'Cannot export client config: WireGuard listen port must be between 1 and 65535.',
    };
  }

  const hostPart = (input.systemHostname || 'vpn').trim();
  const domainPart = (input.systemDomain || 'axonwall.local').trim();
  const endpointHost = `${hostPart}.${domainPart}`;
  if (!isValidHostname(hostPart) || !isValidHostname(domainPart) || !isValidHostname(endpointHost)) {
    return {
      ok: false,
      error: 'Cannot export client config: system hostname/domain must be a valid RFC hostname without line breaks.',
    };
  }

  const conf = `# Axonwall WireGuard Client Profile: ${cleanPeerName}
[Interface]
# PrivateKey: paste the private key generated on this device below.
# The server never stores it, so this profile cannot connect until you add it.
# PrivateKey = <paste-this-device-private-key-here>
Address = ${cleanAllowedIp}
DNS = ${dnsIp}

[Peer]
PublicKey = ${input.serverPublicKey.trim()}
Endpoint = ${endpointHost}:${input.listenPort}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`;

  return { ok: true, conf };
}
