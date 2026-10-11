import type { GeoIpConfig } from '../../schemas/index.js';

export interface CompiledGeoIp {
  nftSetDefinitions: string[];
  inputRules: string[];
  forwardRules: string[];
}

/**
 * Built-in ISO 3166-1 alpha-2 country allocation tables with aggregated representative CIDR prefixes.
 * Enables zero-external-dependency line-rate GeoIP blocking and whitelisting.
 */
export const COUNTRY_CIDR_TABLE: Record<string, string[]> = {
  CN: [
    '1.0.1.0/24', '1.0.2.0/23', '14.0.0.0/11', '27.8.0.0/13', '36.96.0.0/12',
    '42.0.0.0/11', '58.14.0.0/15', '59.32.0.0/11', '101.64.0.0/11', '110.16.0.0/12',
    '111.0.0.0/10', '112.0.0.0/10', '113.64.0.0/11', '114.216.0.0/13', '115.192.0.0/12',
    '116.128.0.0/10', '117.128.0.0/10', '118.112.0.0/13', '119.0.0.0/12', '120.0.0.0/11',
    '121.0.0.0/11', '122.0.0.0/11', '123.56.0.0/14', '124.64.0.0/11', '175.0.0.0/11',
    '180.96.0.0/11', '182.88.0.0/13', '183.0.0.0/10', '218.0.0.0/11', '220.160.0.0/11',
    '221.0.0.0/11', '222.128.0.0/11', '223.64.0.0/11',
  ],
  RU: [
    '2.60.0.0/14', '5.16.0.0/12', '31.13.0.0/16', '37.19.128.0/17', '46.17.40.0/21',
    '62.76.0.0/15', '77.37.128.0/17', '78.25.0.0/16', '79.132.0.0/14', '80.64.0.0/13',
    '81.16.128.0/17', '82.145.0.0/16', '83.149.0.0/16', '85.92.128.0/17', '87.224.0.0/12',
    '89.175.0.0/16', '91.122.0.0/15', '92.242.0.0/16', '93.158.128.0/17', '94.25.0.0/16',
    '95.24.0.0/14', '176.14.0.0/15', '178.64.0.0/13', '188.162.0.0/15', '194.85.0.0/16',
    '195.208.0.0/15', '212.164.0.0/14', '213.87.0.0/16', '217.118.64.0/18',
  ],
  KP: [
    '175.45.176.0/22', '210.52.109.0/24', '198.18.0.0/15',
  ],
  IR: [
    '2.176.0.0/12', '5.160.0.0/12', '31.56.0.0/14', '37.114.0.0/15', '78.38.0.0/15',
    '80.191.0.0/16', '82.99.192.0/18', '85.185.0.0/16', '89.165.0.0/16', '91.98.0.0/15',
    '92.42.48.0/20', '94.101.128.0/17', '188.158.0.0/15', '194.225.0.0/16',
  ],
  BY: [
    '37.212.0.0/14', '46.53.128.0/17', '82.209.192.0/18', '86.57.128.0/17',
    '93.84.0.0/15', '93.125.0.0/16', '178.120.0.0/14', '194.158.192.0/19',
  ],
  SY: [
    '82.137.200.0/21', '82.137.208.0/20', '82.137.224.0/19', '185.73.184.0/22',
    '185.87.12.0/22', '194.126.32.0/19',
  ],
  RO: [
    '79.112.0.0/13', '82.76.0.0/14', '86.120.0.0/13', '89.32.0.0/14',
    '92.80.0.0/13', '188.24.0.0/14',
  ],
  US: [
    '3.0.0.0/9', '8.0.0.0/9', '12.0.0.0/9', '13.0.0.0/8', '24.0.0.0/10',
    '52.0.0.0/11', '54.0.0.0/11', '64.0.0.0/10', '72.0.0.0/10', '104.0.0.0/10',
    '142.250.0.0/15', '172.217.0.0/16',
  ],
  DE: [
    '46.4.0.0/14', '85.10.192.0/18', '88.130.0.0/15', '91.0.0.0/10',
    '144.76.0.0/16', '178.63.0.0/16',
  ],
  GB: [
    '25.0.0.0/8', '51.0.0.0/10', '81.128.0.0/11', '86.0.0.0/11', '90.192.0.0/10',
  ],
  FR: [
    '51.68.0.0/14', '77.128.0.0/10', '82.64.0.0/11', '88.160.0.0/11', '90.0.0.0/10',
  ],
  BR: [
    '177.0.0.0/11', '179.96.0.0/11', '186.192.0.0/11', '187.0.0.0/11',
    '189.0.0.0/11', '201.0.0.0/11',
  ],
  IN: [
    '49.12.0.0/14', '103.0.0.0/10', '106.192.0.0/11', '115.96.0.0/11',
    '117.192.0.0/11', '182.64.0.0/11',
  ],
  AU: [
    '1.120.0.0/13', '101.160.0.0/11', '120.144.0.0/12', '139.130.0.0/16',
    '144.130.0.0/15', '203.0.112.0/20',
  ],
  JP: [
    '114.144.0.0/12', '124.32.0.0/11', '126.0.0.0/9', '133.0.0.0/8', '210.128.0.0/10',
  ],
};

/**
 * Compiles GeoIP configuration into nftables native interval sets and evaluation rules.
 */
export function compileGeoIp(config?: GeoIpConfig): CompiledGeoIp {
  if (!config || !config.enabled || config.countries.length === 0) {
    return {
      nftSetDefinitions: [],
      inputRules: [],
      forwardRules: [],
    };
  }

  // Aggregate CIDRs for all selected country codes
  const countryCidrs = new Set<string>();
  for (const cc of config.countries) {
    const code = cc.toUpperCase();
    const cidrs = COUNTRY_CIDR_TABLE[code] || [];
    for (const c of cidrs) {
      countryCidrs.add(c);
    }
  }

  const setDefs: string[] = [];
  const inputRules: string[] = [];
  const forwardRules: string[] = [];

  const elements = Array.from(countryCidrs).join(', ');
  if (!elements) {
    return { nftSetDefinitions: [], inputRules: [], forwardRules: [] };
  }

  // 1. Primary GeoIP Country Interval Set
  setDefs.push(`  set set_geoip_countries {`);
  setDefs.push(`    type ipv4_addr;`);
  setDefs.push(`    flags interval;`);
  setDefs.push(`    elements = { ${elements} };`);
  setDefs.push(`  }`);

  // 2. Excluded Subnets Set (e.g. RFC 1918 Private ranges)
  const excluded = (config.excludedSubnets && config.excludedSubnets.length > 0)
    ? config.excludedSubnets
    : ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

  setDefs.push(`  set set_geoip_excluded {`);
  setDefs.push(`    type ipv4_addr;`);
  setDefs.push(`    flags interval;`);
  setDefs.push(`    elements = { ${excluded.join(', ')} };`);
  setDefs.push(`  }`);

  const logAction = config.log ? 'log prefix "axonwall-geoip: " ' : '';

  // 3. Rule Generation based on Mode and Direction
  if (config.mode === 'block') {
    if (config.direction === 'in' || config.direction === 'both') {
      const inRule = `ip saddr != @set_geoip_excluded ip saddr @set_geoip_countries ${logAction}drop comment "geoip-inbound-block"`;
      inputRules.push(inRule);
      forwardRules.push(inRule);
    }
    if (config.direction === 'out' || config.direction === 'both') {
      const outRule = `ip daddr != @set_geoip_excluded ip daddr @set_geoip_countries ${logAction}drop comment "geoip-outbound-block"`;
      forwardRules.push(outRule);
    }
  } else if (config.mode === 'allow') {
    // Whitelist mode: external traffic MUST belong to set_geoip_countries
    if (config.direction === 'in' || config.direction === 'both') {
      const inRule = `ip saddr != @set_geoip_excluded ip saddr != @set_geoip_countries ${logAction}drop comment "geoip-inbound-whitelist-drop"`;
      inputRules.push(inRule);
      forwardRules.push(inRule);
    }
    if (config.direction === 'out' || config.direction === 'both') {
      const outRule = `ip daddr != @set_geoip_excluded ip daddr != @set_geoip_countries ${logAction}drop comment "geoip-outbound-whitelist-drop"`;
      forwardRules.push(outRule);
    }
  }

  return {
    nftSetDefinitions: setDefs,
    inputRules,
    forwardRules,
  };
}
