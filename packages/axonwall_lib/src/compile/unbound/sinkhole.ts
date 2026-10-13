import type { DnsBlocklistConfig } from '../../schemas/index.js';

export interface SinkholeCompilationOptions {
  feedDomains?: string[];
}

export interface SinkholeCompilationResult {
  config: string;
  totalBlocked: number;
  prunedSubdomains: number;
  whitelistedCount: number;
}

/**
 * Normalizes a domain name:
 * - lowercase
 * - strips leading/trailing dots and whitespace
 */
export function normalizeDomain(raw: string): string | null {
  if (!raw) return null;
  let d = raw.trim().toLowerCase();

  // Strip comment if inline
  if (d.includes('#')) {
    d = d.split('#')[0].trim();
  }

  // Handle hosts file format (e.g. "0.0.0.0 ads.example.com" or "127.0.0.1 ads.example.com")
  const parts = d.split(/\s+/);
  if (parts.length > 1) {
    // If the first part is an IP address, take the second part
    if (parts[0] === '0.0.0.0' || parts[0] === '127.0.0.1' || parts[0] === '::1') {
      d = parts[1];
    } else {
      d = parts[0];
    }
  }

  // Strip trailing dot
  while (d.endsWith('.')) {
    d = d.slice(0, -1);
  }

  // Strip leading dot or wildcard
  if (d.startsWith('*.')) {
    d = d.slice(2);
  } else if (d.startsWith('.')) {
    d = d.slice(1);
  }

  if (!d || d === 'localhost' || d === 'broadcasthost' || d.length > 253) {
    return null;
  }

  // Basic domain validation
  if (!/^[a-z0-9-_]+(\.[a-z0-9-_]+)+$/.test(d)) {
    return null;
  }

  return d;
}

/**
 * Parses raw text from a hosts file or blocklist feed (newline-separated) into domain list.
 */
export function parseFeedContent(content: string): string[] {
  const lines = content.split('\n');
  const domains: string[] = [];
  for (const line of lines) {
    const norm = normalizeDomain(line);
    if (norm) {
      domains.push(norm);
    }
  }
  return domains;
}

/**
 * Compiles a production Unbound DNS sinkhole configuration.
 * Features:
 * - Subdomain pruning: if 'example.com' is blocked, 'a.b.example.com' is omitted since Unbound applies local-zone to all subdomains.
 * - Whitelist overrides: whitelisted domains are emitted with 'transparent' or excluded from blocklist.
 */
export function compileUnboundSinkhole(
  config: DnsBlocklistConfig,
  feedDomains: string[] = []
): SinkholeCompilationResult {
  const action = config.action || 'always_null';

  // 1. Build Whitelist Set
  const whitelistSet = new Set<string>();
  for (const d of config.whitelist) {
    const norm = normalizeDomain(d);
    if (norm) whitelistSet.add(norm);
  }

  // 2. Collect Candidate Domains
  const candidateSet = new Set<string>();
  for (const d of config.blacklist) {
    const norm = normalizeDomain(d);
    if (norm && !whitelistSet.has(norm)) {
      candidateSet.add(norm);
    }
  }

  for (const d of feedDomains) {
    const norm = normalizeDomain(d);
    if (norm && !whitelistSet.has(norm)) {
      candidateSet.add(norm);
    }
  }

  // 3. Sort domains by label depth (shortest to longest) for wildcard pruning
  // E.g. 'doubleclick.net' comes before 'ad.doubleclick.net'
  const sortedDomains = Array.from(candidateSet).sort((a, b) => {
    const depthA = a.split('.').length;
    const depthB = b.split('.').length;
    if (depthA !== depthB) return depthA - depthB;
    return a.localeCompare(b);
  });

  const blockedRootSet = new Set<string>();
  let prunedCount = 0;

  for (const domain of sortedDomains) {
    // Check if any parent domain is already in blockedRootSet
    const labels = domain.split('.');
    let isSubdomainOfBlocked = false;

    for (let i = 1; i < labels.length - 1; i++) {
      const parentDomain = labels.slice(i).join('.');
      if (blockedRootSet.has(parentDomain)) {
        isSubdomainOfBlocked = true;
        break;
      }
    }

    if (isSubdomainOfBlocked) {
      prunedCount++;
    } else {
      blockedRootSet.add(domain);
    }
  }

  // 4. Generate Unbound Configuration Lines
  const lines: string[] = [];
  lines.push('# Axonwall Unbound DNS Sinkhole / Threat Intelligence Configuration');
  lines.push('# Generated automatically by @axonwall/lib');
  lines.push('server:');

  // Whitelisted domains are declared transparent first
  if (whitelistSet.size > 0) {
    lines.push('  # Whitelist overrides (transparent lookup)');
    for (const w of Array.from(whitelistSet).sort()) {
      lines.push(`  local-zone: "${w}." transparent`);
    }
    lines.push('');
  }

  // Blacklisted zones
  lines.push(`  # Blocked / Sinkholed Domains (${action})`);
  const finalBlocked = Array.from(blockedRootSet).sort();
  for (const b of finalBlocked) {
    lines.push(`  local-zone: "${b}." ${action}`);
  }

  return {
    config: lines.join('\n'),
    totalBlocked: finalBlocked.length,
    prunedSubdomains: prunedCount,
    whitelistedCount: whitelistSet.size,
  };
}
