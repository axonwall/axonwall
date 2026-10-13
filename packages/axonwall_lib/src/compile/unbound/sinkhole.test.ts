import { describe, it, expect } from 'vitest';
import {
  normalizeDomain,
  parseFeedContent,
  compileUnboundSinkhole,
} from './sinkhole.js';
import type { DnsBlocklistConfig } from '../../schemas/index.js';

describe('Unbound DNS Sinkhole Compiler', () => {
  it('should normalize various domain string formats', () => {
    expect(normalizeDomain('EXAMPLE.COM')).toBe('example.com');
    expect(normalizeDomain('  example.com. ')).toBe('example.com');
    expect(normalizeDomain('*.adserver.com')).toBe('adserver.com');
    expect(normalizeDomain('.tracking.net')).toBe('tracking.net');
    expect(normalizeDomain('0.0.0.0 badhost.ru # tracker')).toBe('badhost.ru');
    expect(normalizeDomain('127.0.0.1 malware.cc')).toBe('malware.cc');
    expect(normalizeDomain('# Just a comment line')).toBeNull();
    expect(normalizeDomain('localhost')).toBeNull();
    expect(normalizeDomain('invalid_ domain!@#')).toBeNull();
  });

  it('should parse multi-line hosts file content', () => {
    const raw = `
# StevenBlack hosts excerpt
127.0.0.1 localhost
127.0.0.1 ads.example.com
0.0.0.0 tracker.analytics.org
malware-payload.biz
`;
    const domains = parseFeedContent(raw);
    expect(domains).toEqual(['ads.example.com', 'tracker.analytics.org', 'malware-payload.biz']);
  });

  it('should prune redundant subdomains when root domain is blocked', () => {
    const config: DnsBlocklistConfig = {
      enabled: true,
      feeds: [],
      whitelist: [],
      blacklist: [
        'evil.com',
        'sub.evil.com',
        'deep.nested.sub.evil.com',
        'goodsite.org',
      ],
      action: 'always_null',
    };

    const res = compileUnboundSinkhole(config);
    expect(res.totalBlocked).toBe(2); // 'evil.com' and 'goodsite.org'
    expect(res.prunedSubdomains).toBe(2);
    expect(res.config).toContain('local-zone: "evil.com." always_null');
    expect(res.config).toContain('local-zone: "goodsite.org." always_null');
    expect(res.config).not.toContain('local-zone: "sub.evil.com." always_null');
  });

  it('should respect whitelist overrides and render transparent zone', () => {
    const config: DnsBlocklistConfig = {
      enabled: true,
      feeds: [],
      whitelist: ['trusted-tracker.com', 'allowed.corp'],
      blacklist: ['trusted-tracker.com', 'dangerous.com'],
      action: 'always_nxdomain',
    };

    const res = compileUnboundSinkhole(config);
    expect(res.whitelistedCount).toBe(2);
    expect(res.config).toContain('local-zone: "trusted-tracker.com." transparent');
    expect(res.config).toContain('local-zone: "dangerous.com." always_nxdomain');
    expect(res.config).not.toContain('local-zone: "trusted-tracker.com." always_nxdomain');
  });
});
