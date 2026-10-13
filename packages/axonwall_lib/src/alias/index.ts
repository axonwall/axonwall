import { isValidCIDR, isValidIPv4 } from '../util/index.js';
export * from './threat_feeds.js';

export interface SetDiff {
  toAdd: string[];
  toDelete: string[];
  nftStatements: string[];
}

/**
 * Parses raw text from a threat intelligence / URL Table feed (Spamhaus, FireHOL, etc.).
 * Ignores comments (# or ;) and empty lines, extracting valid IPv4 addresses and CIDRs.
 */
export function parseUrlTableFeed(rawText: string): string[] {
  const lines = rawText.split(/\r?\n/);
  const validIps: string[] = [];

  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) {
      continue;
    }
    // Extract first token (in case line has inline comments)
    const token = line.split(/\s+/)[0]?.trim();
    if (token && (isValidCIDR(token) || isValidIPv4(token))) {
      validIps.push(token);
    }
  }

  return Array.from(new Set(validIps));
}

/**
 * Computes an incremental delta between existing elements in an nftables named set
 * and the newly resolved entries, outputting minimal atomic nftables commands.
 */
export function computeSetDiff(
  tableName: string,
  setName: string,
  currentElements: string[],
  newElements: string[]
): SetDiff {
  const currentSet = new Set(currentElements);
  const targetSet = new Set(newElements);

  const toAdd = newElements.filter((el) => !currentSet.has(el));
  const toDelete = currentElements.filter((el) => !targetSet.has(el));

  const nftStatements: string[] = [];

  if (toDelete.length > 0) {
    nftStatements.push(`delete element inet ${tableName} ${setName} { ${toDelete.join(', ')} }`);
  }

  if (toAdd.length > 0) {
    nftStatements.push(`add element inet ${tableName} ${setName} { ${toAdd.join(', ')} }`);
  }

  return {
    toAdd,
    toDelete,
    nftStatements,
  };
}

/**
 * Mock GeoIP Country-to-Prefix Resolver (supports standard ISO 3166-1 alpha-2 codes).
 */
export function resolveGeoIpPrefixes(countryCode: string): string[] {
  const normalized = countryCode.toUpperCase();
  const sampleGeoDb: Record<string, string[]> = {
    US: ['198.51.100.0/24', '192.0.2.0/24', '142.250.0.0/16'],
    DE: ['194.25.0.0/16', '193.159.0.0/16'],
    CN: ['202.96.0.0/16', '202.106.0.0/16', '114.114.114.0/24'],
    RU: ['95.173.128.0/17', '178.62.0.0/16'],
  };

  return sampleGeoDb[normalized] || [`203.0.113.0/24`];
}

/**
 * Mock ASN to IP Prefix Resolver.
 */
export function resolveAsnPrefixes(asn: number): string[] {
  const sampleAsnDb: Record<number, string[]> = {
    15169: ['8.8.8.0/24', '8.8.4.0/24', '142.250.0.0/16'], // Google
    13335: ['1.1.1.0/24', '1.0.0.0/24', '104.16.0.0/12'], // Cloudflare
    16509: ['3.0.0.0/9', '52.94.0.0/16'],                  // Amazon AWS
  };

  return sampleAsnDb[asn] || [`198.51.100.0/24`];
}
