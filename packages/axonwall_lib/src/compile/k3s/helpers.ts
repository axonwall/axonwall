import type { DesiredState } from '../../schemas/index.js';

export function yamlStr(v: unknown): string {
  return JSON.stringify(String(v ?? '').replace(/[\r\n\0]/g, ''));
}

export function indentMultiline(text: string, spaces: number): string {
  const pad = ' '.repeat(spaces);
  return text
    .split('\n')
    .map((line) => (line.length > 0 ? `${pad}${line}` : ''))
    .join('\n');
}

export function deriveBaseDn(domain?: string): string {
  const cleaned = (domain || 'axonwall.local').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  if (!cleaned || cleaned === 'local' || cleaned === 'localhost') {
    return 'dc=axonwall,dc=local';
  }
  const parts = cleaned.split('.').filter((p) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(p));
  if (parts.length === 0) {
    return 'dc=axonwall,dc=local';
  }
  if (parts.length === 1) {
    parts.push('local');
  }
  return parts.map((p) => `dc=${p}`).join(',');
}

export function resolveApplianceLanIp(state?: Partial<DesiredState> | null): string {
  const candidates = [
    ...(state?.interfaces ?? []).filter((i) => i.enabled && i.role === 'lan'),
    ...(state?.interfaces ?? []).filter((i) => i.enabled),
  ];
  for (const iface of candidates) {
    const raw = (iface.ipv4Address || (iface as { address?: string }).address || '').trim();
    const ip = raw.split('/')[0]?.trim();
    if (ip && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip) && !ip.startsWith('127.')) {
      return ip;
    }
  }
  for (const vip of state?.virtualIps ?? []) {
    const ip = vip.ip.split('/')[0]?.trim();
    if (ip && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip) && !ip.startsWith('127.')) {
      return ip;
    }
  }
  return '192.168.1.1';
}

export function rewritePodLdapUrl(rawUrl: string, lanIp: string): string {
  const trimmed = rawUrl.trim() || 'ldap://127.0.0.1:389';
  return trimmed.replace(/^(ldaps?:\/\/)(127\.0\.0\.1|localhost)(?=[:/]|$)/i, `$1${lanIp}`);
}

export function buildUnboundLocalDataOverride(commentHeader: string, domain: string, ip: string): string {
  return [
    `# ${commentHeader}`,
    'server:',
    `  local-data: "${domain}. IN A ${ip}"`,
    '',
  ].join('\n');
}
