/**
 * Axonwall Network Utilities
 * High-performance IP, CIDR, Port, and MAC manipulation
 */

export function isValidIPv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return false;
    const num = Number.parseInt(part, 10);
    if (num < 0 || num > 255) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
  }
  return true;
}

export function isValidIPv6(ip: string): boolean {
  // Basic IPv6 regex pattern
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/;
  return ipv6Regex.test(ip);
}

export function isValidCIDR(cidr: string): boolean {
  const parts = cidr.split('/');
  if (parts.length !== 2) return false;
  const [ip, prefix] = parts;
  const prefixNum = Number.parseInt(prefix, 10);
  if (Number.isNaN(prefixNum)) return false;

  if (isValidIPv4(ip)) {
    return prefixNum >= 0 && prefixNum <= 32;
  }
  if (isValidIPv6(ip)) {
    return prefixNum >= 0 && prefixNum <= 128;
  }
  return false;
}

export function isValidPort(port: number | string): boolean {
  const p = typeof port === 'string' ? Number.parseInt(port, 10) : port;
  return !Number.isNaN(p) && p >= 1 && p <= 65535;
}

export function isValidPortRange(range: string): boolean {
  if (range.includes('-')) {
    const [start, end] = range.split('-').map((s) => Number.parseInt(s.trim(), 10));
    return isValidPort(start) && isValidPort(end) && start <= end;
  }
  return isValidPort(range);
}

export function isValidMAC(mac: string): boolean {
  return /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(mac);
}

export function sanitizeIdentifier(name: string): string {
  return name.replace(/[^a-zA-Z0-9_]/g, '_').toLowerCase();
}
