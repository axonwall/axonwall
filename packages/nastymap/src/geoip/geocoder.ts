import type { NmapGeoLocation } from '../types/nmap';

interface GeoRecord {
  prefix: string; // e.g. "8.8.8", "1.1.1", "140.211", "104.244"
  city: string;
  region: string;
  country: string;
  countryCode: string;
  latitude: number;
  longitude: number;
  isp: string;
  asn: string;
  org: string;
  timezone: string;
}

// Built-in GeoIP Database for fast offline lookup of major public internet prefixes
const KNOWN_GEO_PREFIXES: GeoRecord[] = [
  // Google / US West
  {
    prefix: '8.8.8',
    city: 'Mountain View',
    region: 'California',
    country: 'United States',
    countryCode: 'US',
    latitude: 37.422,
    longitude: -122.084,
    isp: 'Google LLC',
    asn: 'AS15169',
    org: 'Google Public DNS',
    timezone: 'America/Los_Angeles',
  },
  {
    prefix: '8.8.4',
    city: 'Mountain View',
    region: 'California',
    country: 'United States',
    countryCode: 'US',
    latitude: 37.422,
    longitude: -122.084,
    isp: 'Google LLC',
    asn: 'AS15169',
    org: 'Google DNS',
    timezone: 'America/Los_Angeles',
  },
  {
    prefix: '34.',
    city: 'Council Bluffs',
    region: 'Iowa',
    country: 'United States',
    countryCode: 'US',
    latitude: 41.2619,
    longitude: -95.8608,
    isp: 'Google Cloud Platform',
    asn: 'AS396982',
    org: 'Google Cloud (us-central1)',
    timezone: 'America/Chicago',
  },
  {
    prefix: '35.',
    city: 'The Dalles',
    region: 'Oregon',
    country: 'United States',
    countryCode: 'US',
    latitude: 45.5946,
    longitude: -121.1787,
    isp: 'Google Cloud Platform',
    asn: 'AS15169',
    org: 'Google Cloud (us-west1)',
    timezone: 'America/Los_Angeles',
  },
  // Cloudflare
  {
    prefix: '1.1.1',
    city: 'Sydney',
    region: 'New South Wales',
    country: 'Australia',
    countryCode: 'AU',
    latitude: -33.8688,
    longitude: 151.2093,
    isp: 'Cloudflare, Inc.',
    asn: 'AS13335',
    org: 'APNIC and Cloudflare DNS',
    timezone: 'Australia/Sydney',
  },
  {
    prefix: '104.',
    city: 'San Francisco',
    region: 'California',
    country: 'United States',
    countryCode: 'US',
    latitude: 37.7749,
    longitude: -122.4194,
    isp: 'Cloudflare, Inc.',
    asn: 'AS13335',
    org: 'Cloudflare Edge Network',
    timezone: 'America/Los_Angeles',
  },
  {
    prefix: '172.67',
    city: 'Chicago',
    region: 'Illinois',
    country: 'United States',
    countryCode: 'US',
    latitude: 41.8781,
    longitude: -87.6298,
    isp: 'Cloudflare, Inc.',
    asn: 'AS13335',
    org: 'Cloudflare Edge',
    timezone: 'America/Chicago',
  },
  // AWS US East (N. Virginia)
  {
    prefix: '52.',
    city: 'Ashburn',
    region: 'Virginia',
    country: 'United States',
    countryCode: 'US',
    latitude: 39.0438,
    longitude: -77.4874,
    isp: 'Amazon Technologies Inc.',
    asn: 'AS16509',
    org: 'Amazon AWS (us-east-1)',
    timezone: 'America/New_York',
  },
  {
    prefix: '54.',
    city: 'Seattle',
    region: 'Washington',
    country: 'United States',
    countryCode: 'US',
    latitude: 47.6062,
    longitude: -122.3321,
    isp: 'Amazon.com, Inc.',
    asn: 'AS16509',
    org: 'Amazon Web Services',
    timezone: 'America/Los_Angeles',
  },
  {
    prefix: '3.',
    city: 'Columbus',
    region: 'Ohio',
    country: 'United States',
    countryCode: 'US',
    latitude: 39.9612,
    longitude: -82.9988,
    isp: 'Amazon.com, Inc.',
    asn: 'AS16509',
    org: 'Amazon AWS (us-east-2)',
    timezone: 'America/New_York',
  },
  // Microsoft Azure / UK & Europe
  {
    prefix: '20.',
    city: 'Dublin',
    region: 'Leinster',
    country: 'Ireland',
    countryCode: 'IE',
    latitude: 53.3498,
    longitude: -6.2603,
    isp: 'Microsoft Corporation',
    asn: 'AS8075',
    org: 'Microsoft Azure Europe',
    timezone: 'Europe/Dublin',
  },
  {
    prefix: '40.',
    city: 'Amsterdam',
    region: 'North Holland',
    country: 'Netherlands',
    countryCode: 'NL',
    latitude: 52.3676,
    longitude: 4.9041,
    isp: 'Microsoft Corporation',
    asn: 'AS8075',
    org: 'Microsoft Azure (West Europe)',
    timezone: 'Europe/Amsterdam',
  },
  {
    prefix: '51.',
    city: 'London',
    region: 'England',
    country: 'United Kingdom',
    countryCode: 'GB',
    latitude: 51.5074,
    longitude: -0.1278,
    isp: 'Microsoft Corporation',
    asn: 'AS8075',
    org: 'Azure UK South',
    timezone: 'Europe/London',
  },
  // European Providers (Hetzner, OVH)
  {
    prefix: '138.201',
    city: 'Nuremberg',
    region: 'Bavaria',
    country: 'Germany',
    countryCode: 'DE',
    latitude: 49.4521,
    longitude: 11.0767,
    isp: 'Hetzner Online GmbH',
    asn: 'AS24940',
    org: 'Hetzner Cloud DE',
    timezone: 'Europe/Berlin',
  },
  {
    prefix: '142.44',
    city: 'Beauharnois',
    region: 'Quebec',
    country: 'Canada',
    countryCode: 'CA',
    latitude: 45.3142,
    longitude: -73.8783,
    isp: 'OVH SAS',
    asn: 'AS16276',
    org: 'OVH Hosting Inc.',
    timezone: 'America/Toronto',
  },
  {
    prefix: '51.38',
    city: 'Roubaix',
    region: 'Hauts-de-France',
    country: 'France',
    countryCode: 'FR',
    latitude: 50.6927,
    longitude: 3.1778,
    isp: 'OVH SAS',
    asn: 'AS16276',
    org: 'OVH SAS Gravelines',
    timezone: 'Europe/Paris',
  },
  // Asia Pacific / Tokyo / Singapore
  {
    prefix: '133.',
    city: 'Tokyo',
    region: 'Kanto',
    country: 'Japan',
    countryCode: 'JP',
    latitude: 35.6762,
    longitude: 139.6503,
    isp: 'National Institute of Informatics',
    asn: 'AS2907',
    org: 'SINET Academic Network',
    timezone: 'Asia/Tokyo',
  },
  {
    prefix: '103.',
    city: 'Singapore',
    region: 'Central',
    country: 'Singapore',
    countryCode: 'SG',
    latitude: 1.3521,
    longitude: 103.8198,
    isp: 'Singtel Telecommunications',
    asn: 'AS7473',
    org: 'Singtel Asia Exchange',
    timezone: 'Asia/Singapore',
  },
  {
    prefix: '119.',
    city: 'Seoul',
    region: 'Seoul-teukbyeolsi',
    country: 'South Korea',
    countryCode: 'KR',
    latitude: 37.5665,
    longitude: 126.978,
    isp: 'KT Corporation',
    asn: 'AS4766',
    org: 'Korea Telecom GigaNet',
    timezone: 'Asia/Seoul',
  },
  // South America / Brazil
  {
    prefix: '177.',
    city: 'São Paulo',
    region: 'Sao Paulo',
    country: 'Brazil',
    countryCode: 'BR',
    latitude: -23.5505,
    longitude: -46.6333,
    isp: 'Claro Brasil',
    asn: 'AS28573',
    org: 'Embratel NET',
    timezone: 'America/Sao_Paulo',
  },
  // India / South Asia
  {
    prefix: '106.',
    city: 'Mumbai',
    region: 'Maharashtra',
    country: 'India',
    countryCode: 'IN',
    latitude: 19.076,
    longitude: 72.8777,
    isp: 'Reliance Jio Infocomm',
    asn: 'AS55836',
    org: 'Jio Digital Gateway',
    timezone: 'Asia/Kolkata',
  },
  // Quad9 & OpenDNS
  {
    prefix: '9.9.9',
    city: 'Zurich',
    region: 'Zurich',
    country: 'Switzerland',
    countryCode: 'CH',
    latitude: 47.3769,
    longitude: 8.5417,
    isp: 'Quad9 DNS',
    asn: 'AS19281',
    org: 'Quad9 Foundation',
    timezone: 'Europe/Zurich',
  },
  {
    prefix: '208.67',
    city: 'San Francisco',
    region: 'California',
    country: 'United States',
    countryCode: 'US',
    latitude: 37.7749,
    longitude: -122.4194,
    isp: 'Cisco OpenDNS LLC',
    asn: 'AS36692',
    org: 'OpenDNS Anycast',
    timezone: 'America/Los_Angeles',
  },
  // Scanme.nmap.org
  {
    prefix: '45.33.32',
    city: 'Fremont',
    region: 'California',
    country: 'United States',
    countryCode: 'US',
    latitude: 37.5485,
    longitude: -121.9886,
    isp: 'Linode LLC',
    asn: 'AS63949',
    org: 'Nmap Project (scanme.nmap.org)',
    timezone: 'America/Los_Angeles',
  },
];

/**
 * Check if an IP is in RFC1918 private space, loopback, or link-local.
 */
export function isPrivateIp(ip: string): boolean {
  if (!ip) return true;
  if (ip === '127.0.0.1' || ip === 'localhost' || ip === '::1') return true;
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (ip.startsWith('169.254.')) return true; // Link-local
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return true; // 172.16.0.0 - 172.31.255.255
  if (ip.startsWith('fc00:') || ip.startsWith('fd00:') || ip.startsWith('fe80:')) return true;
  return false;
}

/**
 * Deterministically hash an IP to a pseudo-geographic location for private/lab network visualization.
 */
function getDeterministicPrivateLocation(ip: string): NmapGeoLocation {
  let hash = 0;
  for (let i = 0; i < ip.length; i++) {
    hash = (hash << 5) - hash + ip.charCodeAt(i);
    hash |= 0;
  }
  const normalized = Math.abs(hash);

  // Cluster private IPs around a simulated Enterprise HQ / Data Center Campus (e.g. San Francisco or New York area)
  // with a small, visually pleasing radial jitter
  const centerLat = 37.7749; // San Francisco Tech Hub HQ
  const centerLng = -122.4194;
  const radiusOffset = 0.05 + ((normalized % 100) / 100) * 0.15;
  const angle = ((normalized % 360) * Math.PI) / 180;

  const lat = Number((centerLat + Math.sin(angle) * radiusOffset).toFixed(4));
  const lng = Number((centerLng + Math.cos(angle) * radiusOffset).toFixed(4));

  const subnetPart = ip.split('.').slice(0, 3).join('.');

  return {
    ip,
    city: 'Local Intranet HQ',
    region: 'Corporate Campus',
    country: 'Internal Network',
    countryCode: 'LAN',
    latitude: lat,
    longitude: lng,
    isp: 'Enterprise Intranet',
    asn: 'RFC-1918 Private',
    org: `Subnet ${subnetPart}.0/24`,
    timezone: 'UTC',
    isPrivate: true,
  };
}

/**
 * Geocode an IP address to geographic coordinates, country, and organization.
 */
export function geocodeIp(ip: string): NmapGeoLocation {
  if (!ip) {
    return {
      ip: '0.0.0.0',
      latitude: 0,
      longitude: 0,
      country: 'Unknown',
      countryCode: 'UN',
      isPrivate: true,
    };
  }

  if (isPrivateIp(ip)) {
    return getDeterministicPrivateLocation(ip);
  }

  // Check known prefixes first
  for (const rec of KNOWN_GEO_PREFIXES) {
    if (ip.startsWith(rec.prefix)) {
      return {
        ip,
        city: rec.city,
        region: rec.region,
        country: rec.country,
        countryCode: rec.countryCode,
        latitude: rec.latitude,
        longitude: rec.longitude,
        isp: rec.isp,
        asn: rec.asn,
        org: rec.org,
        timezone: rec.timezone,
        isPrivate: false,
      };
    }
  }

  // Fallback for general public IPs: Deterministic Global Placement based on IP octets
  const octets = ip.split('.').map((o) => parseInt(o, 10) || 0);
  const o1 = octets[0] || 0;
  const o2 = octets[1] || 0;
  const o3 = octets[2] || 0;

  // Distribute over major world continents
  const globalRegions = [
    { city: 'New York', region: 'New York', country: 'United States', countryCode: 'US', lat: 40.7128, lng: -74.006, tz: 'America/New_York' },
    { city: 'London', region: 'England', country: 'United Kingdom', countryCode: 'GB', lat: 51.5074, lng: -0.1278, tz: 'Europe/London' },
    { city: 'Frankfurt', region: 'Hesse', country: 'Germany', countryCode: 'DE', lat: 50.1109, lng: 8.6821, tz: 'Europe/Berlin' },
    { city: 'Tokyo', region: 'Tokyo', country: 'Japan', countryCode: 'JP', lat: 35.6762, lng: 139.6503, tz: 'Asia/Tokyo' },
    { city: 'Singapore', region: 'Singapore', country: 'Singapore', countryCode: 'SG', lat: 1.3521, lng: 103.8198, tz: 'Asia/Singapore' },
    { city: 'Sydney', region: 'NSW', country: 'Australia', countryCode: 'AU', lat: -33.8688, lng: 151.2093, tz: 'Australia/Sydney' },
    { city: 'São Paulo', region: 'SP', country: 'Brazil', countryCode: 'BR', lat: -23.5505, lng: -46.6333, tz: 'America/Sao_Paulo' },
    { city: 'Stockholm', region: 'Stockholm', country: 'Sweden', countryCode: 'SE', lat: 59.3293, lng: 18.0686, tz: 'Europe/Stockholm' },
  ];

  const regionIndex = (o1 + o2) % globalRegions.length;
  const reg = globalRegions[regionIndex];

  // Jitter slightly so distinct IPs in the same region don't overlap exactly
  const jitterLat = ((o3 % 20) - 10) * 0.08;
  const jitterLng = (((o2 + o3) % 20) - 10) * 0.08;

  return {
    ip,
    city: reg.city,
    region: reg.region,
    country: reg.country,
    countryCode: reg.countryCode,
    latitude: Number((reg.lat + jitterLat).toFixed(4)),
    longitude: Number((reg.lng + jitterLng).toFixed(4)),
    isp: `Autonomous System AS${10000 + (o1 * 100 + o2)}`,
    asn: `AS${10000 + (o1 * 100 + o2)}`,
    org: `Internet Gateway ${o1}.${o2}.0.0`,
    timezone: reg.tz,
    isPrivate: false,
  };
}
