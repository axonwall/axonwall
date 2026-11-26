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

/**
 * Determines if an IP address belongs to RFC 1918 / private / loopback space.
 * @param {string} ip
 * @returns {boolean}
 */
export function isPrivateIp(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const normalized = ip.trim().toLowerCase().split('%')[0];
  if (!normalized) return true;
  if (normalized === 'localhost' || normalized === '::1' || normalized === '::' || normalized === '0.0.0.0') return true;

  // Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:192.168.1.1)
  if (normalized.startsWith('::ffff:')) {
    const mapped = normalized.slice(7);
    if (mapped.includes('.')) return isPrivateIp(mapped);
    const hexParts = mapped.split(':').filter(Boolean);
    if (hexParts.length === 2) {
      const hi = parseInt(hexParts[0], 16);
      const lo = parseInt(hexParts[1], 16);
      if (!Number.isNaN(hi) && !Number.isNaN(lo)) {
        return isPrivateIp(`${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`);
      }
    }
  }

  if (normalized.startsWith('127.')) return true; // Loopback 127.0.0.0/8
  if (normalized.startsWith('10.')) return true;
  if (normalized.startsWith('192.168.')) return true;
  if (normalized.startsWith('172.')) {
    const parts = normalized.split('.');
    const second = parseInt(parts[1], 10);
    if (!isNaN(second) && second >= 16 && second <= 31) return true;
  }
  if (normalized.startsWith('169.254.')) return true; // Link-local
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(normalized)) return true; // CGNAT 100.64.0.0/10
  // IPv6 Unique Local fc00::/7 (fc00:: - fdff::) and Link-Local fe80::/10
  if (/^f[cd][0-9a-f]{2}:/.test(normalized) || /^fe[89ab][0-9a-f]:/.test(normalized)) return true;
  return false;
}

/**
 * Geocodes an IP address to latitude, longitude, city, country, and ASN/ISP info.
 * @param {string} ip
 * @returns {Object} Geolocation metadata
 */
export function geocodeIp(ip) {
  if (!ip || typeof ip !== 'string') {
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

  const isPriv = isPrivateIp(ip);
  if (isPriv) {
    return {
      ip,
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
    if (ip.startsWith(range.prefix)) {
      return {
        ip,
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
  const hash = ip.includes(':')
    ? ip.split(':').reduce((acc, part) => (acc * 31 + (parseInt(part || '0', 16) || 0)) % 10000, 0)
    : ip.split('.').reduce((acc, octet) => (acc * 31 + (parseInt(octet || '0', 10) || 0)) % 10000, 0);
  const fallbackLat = ((hash % 1400) - 700) / 10; // -70 to +70
  const fallbackLon = (((hash * 7) % 3600) - 1800) / 10; // -180 to +180

  return {
    ip,
    isPrivate: false,
    country: 'Public IP',
    countryCode: 'PUB',
    city: 'Internet Gateway',
    lat: fallbackLat,
    lon: fallbackLon,
    isp: 'Public ASN'
  };
}
