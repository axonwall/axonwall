/**
 * NastyMap GeoIP Resolver
 * Provides lightweight, fast offline geocoding and IP metadata classification.
 */

// Well-known public ranges and landmarks for offline demo and simulation
const KNOWN_GEO_SUBNETS = [
  { prefix: '8.8.', country: 'US', countryCode: 'USA', city: 'Mountain View', lat: 37.4056, lon: -122.0775, isp: 'Google LLC' },
  { prefix: '1.1.1.', country: 'AU', countryCode: 'AUS', city: 'Sydney', lat: -33.8688, lon: 151.2093, isp: 'Cloudflare Inc.' },
  { prefix: '9.9.9.', country: 'US', countryCode: 'USA', city: 'Berkeley', lat: 37.8715, lon: -122.2730, isp: 'Quad9 DNS' },
  { prefix: '76.76.21.', country: 'US', countryCode: 'USA', city: 'San Francisco', lat: 37.7749, lon: -122.4194, isp: 'Vercel Inc.' },
  { prefix: '140.82.', country: 'US', countryCode: 'USA', city: 'San Francisco', lat: 37.7749, lon: -122.4194, isp: 'GitHub Inc.' },
  { prefix: '185.199.', country: 'US', countryCode: 'USA', city: 'Seattle', lat: 47.6062, lon: -122.3321, isp: 'Fastly CDN' },
  { prefix: '151.101.', country: 'US', countryCode: 'USA', city: 'New York', lat: 40.7128, lon: -74.0060, isp: 'Fastly Inc.' },
  { prefix: '13.107.', country: 'US', countryCode: 'USA', city: 'Redmond', lat: 47.6740, lon: -122.1215, isp: 'Microsoft Corp' },
  { prefix: '52.', country: 'US', countryCode: 'USA', city: 'Ashburn', lat: 39.0438, lon: -77.4874, isp: 'Amazon AWS' },
  { prefix: '34.', country: 'US', countryCode: 'USA', city: 'Council Bluffs', lat: 41.2619, lon: -95.8608, isp: 'Google Cloud' },
  { prefix: '104.', country: 'US', countryCode: 'USA', city: 'Chicago', lat: 41.8781, lon: -87.6298, isp: 'Akamai / Cloudflare' }
];

function parseIpv4Int(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let val = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    if (part.length > 1 && part.startsWith('0')) return null;
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    val = ((val << 8) | octet) >>> 0;
  }
  return val;
}

function isPrivateIpv4Int(v4) {
  const a = (v4 >>> 24) & 0xff;
  const b = (v4 >>> 16) & 0xff;
  const c = (v4 >>> 8) & 0xff;

  if (a === 0) return true; // 0.0.0.0/8 ("This host on this network")
  if (a === 10) return true; // 10.0.0.0/8 (RFC 1918)
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (CGNAT RFC 6598)
  if (a === 127) return true; // 127.0.0.0/8 (Loopback)
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 (Link-local / IMDS)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 (RFC 1918)
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24 (IETF Protocol Assignments)
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 (RFC 1918)
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 (Benchmarking)
  if (a >= 224) return true; // 224.0.0.0/4 Multicast & 240.0.0.0/4 Reserved / Broadcast
  return false;
}

function parseIpv6BigInt(ip) {
  let clean = ip.trim().replace(/^\[|\]$/g, '').split('%')[0].toLowerCase();
  if (!clean || !clean.includes(':')) return null;

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
  if (halves.length === 2 && missing < 1) return null;
  if (halves.length === 1 && left.length !== 8) return null;

  const groups = halves.length === 2
    ? [...left, ...Array(missing).fill('0'), ...right]
    : left;
  if (groups.length !== 8) return null;

  let val = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    val = (val << 16n) | BigInt(parseInt(g, 16));
  }
  return val;
}

function isPrivateIpv6BigInt(v6) {
  if (v6 === 0n) return true; // :: (unspecified)
  if (v6 === 1n) return true; // ::1 (loopback)

  // Unwrap IPv4-mapped IPv6 (::ffff:0:0/96)
  if ((v6 >> 32n) === 0xffffn) {
    return isPrivateIpv4Int(Number(v6 & 0xffffffffn));
  }

  // Unwrap IPv4-translated SIIT (::ffff:0:0:0/96)
  if ((v6 >> 32n) === 0xffff0000n) {
    return isPrivateIpv4Int(Number(v6 & 0xffffffffn));
  }

  // Unwrap deprecated IPv4-compatible IPv6 (::/96)
  if ((v6 >> 32n) === 0n && v6 > 1n) {
    return isPrivateIpv4Int(Number(v6 & 0xffffffffn));
  }

  // Unwrap NAT64 Well-Known Prefix (64:ff9b::/96)
  if ((v6 >> 32n) === 0x0064ff9b0000000000000000n) {
    return isPrivateIpv4Int(Number(v6 & 0xffffffffn));
  }

  // NAT64 Local-Use Prefix (64:ff9b:1::/48)
  if ((v6 >> 80n) === 0x0064ff9b0001n) return true;

  // 6to4 transition range (2002::/16)
  if ((v6 >> 112n) === 0x2002n) return true;

  // Teredo transition range (2001::/32)
  if ((v6 >> 96n) === 0x20010000n) return true;

  // Benchmarking (2001:2::/48) and ORCHIDv2 (2001:20::/28)
  if ((v6 >> 80n) === 0x200100020000n) return true;
  if ((v6 >> 100n) === 0x2001002n) return true;

  // Discard-only (100::/64)
  if ((v6 >> 64n) === 0x0100000000000000n) return true;

  // Unique Local Addresses (fc00::/7, including fd12:, etc.)
  if ((v6 >> 121n) === 0x7en) return true;

  // Link-Local (fe80::/10)
  if ((v6 >> 118n) === 0x3fan) return true;

  // Deprecated Site-Local (fec0::/10)
  if ((v6 >> 118n) === 0x3fbn) return true;

  // Multicast (ff00::/8)
  if ((v6 >> 120n) === 0xffn) return true;

  return false;
}

/**
 * Determines if an IP address belongs to non-public space (RFC 1918, loopback, link-local,
 * CGNAT, 0.0.0.0/8, ULA, IPv4-mapped IPv6, NAT64/6to4/Teredo transition, multicast/reserved).
 * Fails closed (returns true) for empty or unparseable inputs.
 * @param {string} ip
 * @returns {boolean}
 */
export function isPrivateIp(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const trimmed = ip.trim();
  if (!trimmed) return true;
  const lower = trimmed.toLowerCase();
  if (lower === 'localhost' || lower.endsWith('.localhost')) return true;

  if (!trimmed.includes(':')) {
    const v4 = parseIpv4Int(trimmed);
    if (v4 === null) return true;
    return isPrivateIpv4Int(v4);
  }

  const v6 = parseIpv6BigInt(trimmed);
  if (v6 === null) return true;
  return isPrivateIpv6BigInt(v6);
}

/**
 * Geocodes an IP address to latitude, longitude, city, country, and ASN/ISP info.
 * @param {string} ip
 * @returns {Object} Geolocation metadata
 */
export function geocodeIp(ip) {
  if (!ip || typeof ip !== 'string' || !ip.trim()) {
    return {
      ip: ip || 'unknown',
      isPrivate: true,
      country: 'Private Network',
      countryCode: 'LAN',
      city: 'Local Subnet',
      lat: 0,
      lon: 0,
      isp: 'Internal'
    };
  }

  const normalizedIp = ip.trim().replace(/^\[|\]$/g, '').split('%')[0];
  const isPriv = isPrivateIp(normalizedIp);
  if (isPriv) {
    return {
      ip: normalizedIp,
      isPrivate: true,
      country: 'Private Network (RFC 1918)',
      countryCode: 'LAN',
      city: 'Local Area Network',
      lat: 0,
      lon: 0,
      isp: 'Internal Routing'
    };
  }

  // Check known public ranges
  for (const range of KNOWN_GEO_SUBNETS) {
    if (normalizedIp.startsWith(range.prefix)) {
      return {
        ip: normalizedIp,
        isPrivate: false,
        country: range.country,
        countryCode: range.countryCode,
        city: range.city,
        lat: range.lat,
        lon: range.lon,
        isp: range.isp
      };
    }
  }

  // Deterministic fallback geocoding hash for demo/simulation of public IPs
  const hash = normalizedIp.includes(':')
    ? normalizedIp.split(':').reduce((acc, part) => (acc * 31 + (parseInt(part || '0', 16) || 0)) % 10000, 0)
    : normalizedIp.split('.').reduce((acc, octet) => (acc * 31 + (parseInt(octet || '0', 10) || 0)) % 10000, 0);
  const fallbackLat = ((hash % 1400) - 700) / 10; // -70 to +70
  const fallbackLon = (((hash * 7) % 3600) - 1800) / 10; // -180 to +180

  return {
    ip: normalizedIp,
    isPrivate: false,
    country: 'Public IP',
    countryCode: 'PUB',
    city: 'Internet Gateway',
    lat: fallbackLat,
    lon: fallbackLon,
    isp: 'Public ASN'
  };
}
