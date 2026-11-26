import dns from 'node:dns/promises';
import net from 'node:net';

const METADATA_HOSTNAMES = new Set([
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  'instance-data',
  '169.254.169.254'
]);

/**
 * Parse a dotted IPv4 address into an unsigned 32-bit integer, or null.
 */
export function parseIpv4Int(ip) {
  const parts = String(ip).split('.');
  if (parts.length !== 4) return null;
  let val = 0;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    val = ((val << 8) | n) >>> 0;
  }
  return val;
}

/**
 * Parse any canonical or compressed IPv6 string (including dotted IPv4-mapped)
 * into a 128-bit BigInt, or null if invalid.
 */
export function parseIpv6BigInt(ip) {
  let clean = String(ip || '').replace(/^\[|\]$/g, '').split('%')[0].toLowerCase();
  if (!clean) return null;

  if (clean.includes('.')) {
    const lastColon = clean.lastIndexOf(':');
    if (lastColon === -1) return null;
    const v4Int = parseIpv4Int(clean.slice(lastColon + 1));
    if (v4Int === null) return null;
    const hi = ((v4Int >>> 16) & 0xffff).toString(16);
    const lo = (v4Int & 0xffff).toString(16);
    clean = `${clean.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const halves = clean.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = halves.length === 2 ? 8 - (left.length + right.length) : 0;
  if (missing < 0 || (halves.length === 1 && left.length !== 8)) return null;
  const groups = [...left, ...Array(missing).fill('0'), ...right];
  if (groups.length !== 8) return null;

  let val = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    val = (val << 16n) | BigInt(parseInt(g, 16));
  }
  return val;
}

/**
 * Check whether an IPv4 or IPv6 address falls in metadata/link-local,
 * loopback, RFC1918, ULA, CGNAT, or reserved/multicast ranges.
 */
export function classifyIpRange(ip) {
  const raw = String(ip || '').replace(/^\[|\]$/g, '').split('%')[0].trim();
  const family = net.isIP(raw);
  if (family === 4) {
    const v4 = parseIpv4Int(raw);
    if (v4 === null) return 'invalid';
    const a = (v4 >>> 24) & 0xff;
    const b = (v4 >>> 16) & 0xff;
    if (a === 0) return 'unspecified';
    if (a === 169 && b === 254) return 'metadata'; // link-local / cloud IMDS
    if (a === 127) return 'loopback';
    if (a === 10) return 'private';
    if (a === 172 && b >= 16 && b <= 31) return 'private';
    if (a === 192 && b === 168) return 'private';
    if (a === 100 && b >= 64 && b <= 127) return 'private'; // CGNAT RFC6598
    if (a === 192 && b === 0) return 'reserved';
    if (a >= 224) return 'reserved'; // multicast / Class E / broadcast
    return 'public';
  }
  if (family === 6) {
    const v6 = parseIpv6BigInt(raw);
    if (v6 === null) return 'invalid';
    // Unwrap IPv4-mapped ::ffff:0:0/96 (both dotted ::ffff:a.b.c.d and hex ::ffff:a9fe:a9fe)
    if ((v6 >> 32n) === 0xffffn) {
      const v4 = Number(v6 & 0xffffffffn);
      const dotted = `${(v4 >>> 24) & 0xff}.${(v4 >>> 16) & 0xff}.${(v4 >>> 8) & 0xff}.${v4 & 0xff}`;
      return classifyIpRange(dotted);
    }
    // Unwrap deprecated IPv4-compatible ::/96 when non-loopback/unspecified
    if ((v6 >> 32n) === 0n && v6 > 1n) {
      const v4 = Number(v6 & 0xffffffffn);
      const dotted = `${(v4 >>> 24) & 0xff}.${(v4 >>> 16) & 0xff}.${(v4 >>> 8) & 0xff}.${v4 & 0xff}`;
      return classifyIpRange(dotted);
    }
    // Unwrap NAT64 64:ff9b::/96 (RFC 6052 Well-Known Prefix)
    if ((v6 >> 32n) === 0x0064ff9b0000000000000000n) {
      const v4 = Number(v6 & 0xffffffffn);
      const dotted = `${(v4 >>> 24) & 0xff}.${(v4 >>> 16) & 0xff}.${(v4 >>> 8) & 0xff}.${v4 & 0xff}`;
      return classifyIpRange(dotted);
    }
    if (v6 === 0n) return 'unspecified';
    if (v6 === 1n) return 'loopback';
    // fe80::/10 link-local
    if ((v6 >> 118n) === 0x3fan) return 'metadata';
    // fc00::/7 Unique Local Address (includes AWS IPv6 IMDS fd00:ec2::254)
    if ((v6 >> 121n) === 0x7en) {
      // fd00:ec2::254 specifically is AWS EC2 IPv6 IMDS
      const awsImds6 = 0xfd000ec2000000000000000000000254n;
      if (v6 === awsImds6) return 'metadata';
      return 'private';
    }
    // ff00::/8 multicast
    if ((v6 >> 120n) === 0xffn) return 'reserved';
    return 'public';
  }
  return 'unknown';
}

function assertIpAllowed(ip, { allowPrivate = false, allowLoopback = false, allowMetadata = false }, label) {
  const cls = classifyIpRange(ip);
  if (cls === 'public') return;
  if (cls === 'metadata' && allowMetadata) return;
  if (cls === 'loopback' && allowLoopback) return;
  if (cls === 'private' && allowPrivate) return;
  throw new Error(`Blocked SSRF ${label}: address '${ip}' (${cls}) is not permitted`);
}

/**
 * Shared outbound target validation (SSRF guard) across HTTP probes, OIDC, scanners, and diagnostics.
 * Parses URL or bare host, canonicalizes IPv4/IPv6 (including hex ::ffff: unwrapping), resolves DNS,
 * and blocks IMDS/link-local, RFC1918/ULA, loopback, and reserved ranges unless explicitly permitted.
 *
 * @param {string} targetRaw
 * @param {Object} [options={}]
 * @returns {Promise<{ url: URL, hostname: string, isIp: boolean, addresses: string[] }>}
 */
export async function assertSafeOutboundTarget(targetRaw, options = {}) {
  const {
    label = 'target',
    allowedProtocols = ['http:', 'https:'],
    allowBareHost = false,
    allowHttpOnlyForLoopback = false,
    allowPrivate = process.env.VIGILANTE_ALLOW_PRIVATE_TARGETS === '1',
    allowLoopback = false,
    allowMetadata = false,
    failOnDnsError = false,
    dnsLookup = dns.lookup
  } = options;

  const raw = String(targetRaw ?? '').trim();
  if (!raw) {
    throw new Error(`Invalid ${label}: empty target`);
  }

  let parsed;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) {
    parsed = new URL(raw);
  } else if (allowBareHost) {
    const bare = raw.replace(/^\[|\]$/g, '');
    const bracketedMatch = raw.match(/^\[([^\]]+)\](?::\d+)?(?:[/?#]|$)/);
    if (bracketedMatch) {
      if (net.isIP(bracketedMatch[1]) !== 6) {
        throw new Error(`Invalid ${label} '${targetRaw}'`);
      }
      parsed = new URL(`http://${raw}`);
    } else if (net.isIP(bare) === 6) {
      parsed = new URL(`http://[${bare}]`);
    } else if (/^[a-zA-Z0-9.-]+:\d+(?:[/?#]|$)/.test(raw) || net.isIP(bare) === 4 || /^[a-zA-Z0-9.-]+(?:[/?#]|$)/.test(raw)) {
      parsed = new URL(`http://${raw}`);
    } else {
      throw new Error(`Invalid ${label} '${targetRaw}'`);
    }
  } else {
    parsed = new URL(raw);
  }

  if (!allowedProtocols.includes(parsed.protocol)) {
    throw new Error(`Disallowed ${label} protocol '${parsed.protocol}'`);
  }

  const rawHost = parsed.hostname.replace(/^\[|\]$/g, '').split('%')[0].replace(/\.+$/, '').toLowerCase();
  if (!rawHost) {
    throw new Error(`Invalid ${label}: missing hostname`);
  }

  const isLocalhostName = rawHost === 'localhost' || rawHost.endsWith('.localhost');
  if (allowHttpOnlyForLoopback && parsed.protocol === 'http:') {
    const cls = net.isIP(rawHost) ? classifyIpRange(rawHost) : (isLocalhostName ? 'loopback' : null);
    if (cls !== 'loopback') {
      throw new Error(`Unsafe ${label} protocol '${parsed.protocol}': HTTPS required for non-loopback hosts`);
    }
  }

  if (METADATA_HOSTNAMES.has(rawHost) && !allowMetadata) {
    throw new Error(`Blocked SSRF ${label}: metadata hostname '${rawHost}' is forbidden`);
  }

  if (isLocalhostName && !allowLoopback) {
    throw new Error(`Blocked SSRF ${label}: loopback hostname '${rawHost}' is forbidden`);
  }

  const ipFamily = net.isIP(rawHost);
  if (ipFamily !== 0) {
    assertIpAllowed(rawHost, { allowPrivate, allowLoopback, allowMetadata }, label);
    return { url: parsed, hostname: rawHost, isIp: true, addresses: [rawHost] };
  }

  let resolved = [];
  try {
    const records = await dnsLookup(rawHost, { all: true });
    resolved = Array.isArray(records)
      ? records.map(r => (typeof r === 'string' ? r : r.address)).filter(Boolean)
      : (records?.address ? [records.address] : []);
  } catch (err) {
    if (failOnDnsError) {
      throw new Error(`DNS resolution failed for ${label} '${rawHost}': ${err.message}`);
    }
    return { url: parsed, hostname: rawHost, isIp: false, addresses: [] };
  }

  if (resolved.length === 0 && failOnDnsError) {
    throw new Error(`DNS resolution returned no addresses for ${label} '${rawHost}'`);
  }

  for (const addr of resolved) {
    assertIpAllowed(addr, { allowPrivate, allowLoopback, allowMetadata }, label);
  }

  return { url: parsed, hostname: rawHost, isIp: false, addresses: resolved };
}
