import { isValidCIDR, isValidIPv4 } from '../util/index.js';

export interface ThreatFeedSource {
  id: string;
  name: string;
  url: string;
  category: 'malware' | 'botnet' | 'reputation' | 'bogon';
  defaultEnabled: boolean;
  entriesCount?: number;
  description: string;
}

export const COMMUNITY_THREAT_FEEDS: ThreatFeedSource[] = [
  {
    id: 'spamhaus-drop',
    name: 'Spamhaus DROP (Don\'t Route Or Peer)',
    url: 'https://www.spamhaus.org/drop/drop.txt',
    category: 'reputation',
    defaultEnabled: true,
    description: 'Advisory list consisting of netblocks leased or hijacked for criminal purposes.',
  },
  {
    id: 'spamhaus-edrop',
    name: 'Spamhaus Extended DROP (EDROP)',
    url: 'https://www.spamhaus.org/drop/edrop.txt',
    category: 'reputation',
    defaultEnabled: true,
    description: 'Extension to DROP targeting sub-allocated netblocks controlled by criminal networks.',
  },
  {
    id: 'abusech-feodo',
    name: 'abuse.ch Feodo Tracker Botnet C2',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    category: 'botnet',
    defaultEnabled: true,
    description: 'Real-time IP addresses of active Command & Control (C2) servers for Dridex, Emotet, QakBot.',
  },
  {
    id: 'emerging-threats-compromised',
    name: 'Emerging Threats Compromised IPs',
    url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    category: 'malware',
    defaultEnabled: true,
    description: 'Daily verified compromised internet hosts acting as scanning, exploit, or infection vectors.',
  },
];

export interface ThreatFeedCompileOptions {
  tableName?: string;
  setName?: string;
  chunkSize?: number;
}

export interface ThreatFeedCompileResult {
  totalInputEntries: number;
  uniqueEntries: number;
  prunedEnclosedEntries: number;
  finalCidrs: string[];
  nftCommands: string[];
}

function parseIpv4ToUint(ip: string): number | null {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return null;
  }
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

interface ParsedPrefix {
  cidr: string;
  base: number;
  mask: number;
  prefixLen: number;
}

function parseCidrOrIp(input: string): ParsedPrefix | null {
  if (!input) return null;
  const [ipPart, maskPart] = input.split('/');
  const baseIp = parseIpv4ToUint(ipPart);
  if (baseIp === null) return null;

  let prefixLen = 32;
  if (maskPart !== undefined) {
    const parsedMask = Number.parseInt(maskPart, 10);
    if (Number.isNaN(parsedMask) || parsedMask < 0 || parsedMask > 32) return null;
    prefixLen = parsedMask;
  }

  const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
  const canonicalBase = (baseIp & mask) >>> 0;
  const cidr = prefixLen === 32 ? ipPart : `${(canonicalBase >>> 24) & 255}.${(canonicalBase >>> 16) & 255}.${(canonicalBase >>> 8) & 255}.${canonicalBase & 255}/${prefixLen}`;

  return {
    cidr,
    base: canonicalBase,
    mask,
    prefixLen,
  };
}

/**
 * Minimizes an array of IPv4 addresses and CIDR blocks:
 * 1. Validates syntax
 * 2. Deduplicates exact matches
 * 3. Prunes redundant entries enclosed by broader supernets (e.g. 10.1.2.0/24 pruned if 10.0.0.0/8 present)
 */
export function minimizeThreatCidrs(entries: string[]): {
  minimized: string[];
  totalInput: number;
  prunedCount: number;
} {
  const parsedList: ParsedPrefix[] = [];
  const seenExact = new Set<string>();

  for (const entry of entries) {
    const parsed = parseCidrOrIp(entry.trim());
    if (parsed && !seenExact.has(parsed.cidr)) {
      seenExact.add(parsed.cidr);
      parsedList.push(parsed);
    }
  }

  // Sort primarily by prefix length ascending (broadest supernets first: /8, /16, /24, /32)
  parsedList.sort((a, b) => {
    if (a.prefixLen !== b.prefixLen) return a.prefixLen - b.prefixLen;
    return a.base - b.base;
  });

  const kept: ParsedPrefix[] = [];
  let prunedCount = entries.length - seenExact.size; // Initial duplicates count

  for (const candidate of parsedList) {
    let isEnclosed = false;
    for (const supernet of kept) {
      // Check if candidate is enclosed in supernet
      if ((supernet.mask >>> 0) <= (candidate.mask >>> 0)) {
        if ((candidate.base & supernet.mask) >>> 0 === supernet.base) {
          isEnclosed = true;
          break;
        }
      }
    }

    if (isEnclosed) {
      prunedCount++;
    } else {
      kept.push(candidate);
    }
  }

  return {
    minimized: kept.map((p) => p.cidr),
    totalInput: entries.length,
    prunedCount,
  };
}

/**
 * Compiles atomic nftables element addition statements for high-speed kernel set updates.
 */
export function compileThreatFeedNft(
  cidrs: string[],
  options: ThreatFeedCompileOptions = {}
): ThreatFeedCompileResult {
  const {
    tableName = 'axonwall',
    setName = 'threat_feed_block',
    chunkSize = 1000,
  } = options;

  const { minimized, totalInput, prunedCount } = minimizeThreatCidrs(cidrs);

  const nftCommands: string[] = [];
  // Ensure the set exists with interval flags
  nftCommands.push(
    `add set inet ${tableName} ${setName} { type ipv4_addr; flags interval; auto-merge; comment "Axonwall Dynamic Threat Feeds"; }`
  );

  // Chunk elements for atomic batch execution without exceeding netlink payload limits
  for (let i = 0; i < minimized.length; i += chunkSize) {
    const chunk = minimized.slice(i, i + chunkSize);
    if (chunk.length > 0) {
      nftCommands.push(
        `add element inet ${tableName} ${setName} { ${chunk.join(', ')} }`
      );
    }
  }

  return {
    totalInputEntries: totalInput,
    uniqueEntries: minimized.length,
    prunedEnclosedEntries: prunedCount,
    finalCidrs: minimized,
    nftCommands,
  };
}
