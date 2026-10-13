import { describe, it, expect } from 'vitest';
import {
  COMMUNITY_THREAT_FEEDS,
  minimizeThreatCidrs,
  compileThreatFeedNft,
} from './threat_feeds.js';

describe('Dynamic Threat Feed Aggregator', () => {
  it('should have pre-configured community threat feeds', () => {
    expect(COMMUNITY_THREAT_FEEDS.length).toBeGreaterThanOrEqual(4);
    const drop = COMMUNITY_THREAT_FEEDS.find((f) => f.id === 'spamhaus-drop');
    expect(drop).toBeDefined();
    expect(drop?.url).toContain('spamhaus.org');
  });

  it('should minimize CIDRs by pruning enclosed subnets and deduplicating', () => {
    const input = [
      '10.0.0.0/8',
      '10.1.0.0/16', // Enclosed in 10.0.0.0/8
      '10.1.2.3',    // Enclosed in 10.0.0.0/8
      '192.168.1.1',
      '192.168.1.1', // Duplicate
      '192.168.1.0/24', // Encloses 192.168.1.1
      '1.1.1.1',
    ];

    const result = minimizeThreatCidrs(input);
    expect(result.totalInput).toBe(7);
    expect(result.minimized).toContain('10.0.0.0/8');
    expect(result.minimized).toContain('192.168.1.0/24');
    expect(result.minimized).toContain('1.1.1.1');
    expect(result.minimized).not.toContain('10.1.0.0/16');
    expect(result.minimized).not.toContain('10.1.2.3');
    expect(result.minimized).not.toContain('192.168.1.1');
    expect(result.prunedCount).toBe(4);
  });

  it('should compile atomic nft element addition batches with chunking', () => {
    const cidrs = [
      '198.51.100.1',
      '198.51.100.2',
      '198.51.100.3',
      '203.0.113.0/24',
    ];

    const res = compileThreatFeedNft(cidrs, {
      tableName: 'axonwall',
      setName: 'threat_feed_block',
      chunkSize: 2,
    });

    expect(res.nftCommands.length).toBe(3); // 1 create set + 2 chunked add elements
    expect(res.nftCommands[0]).toContain('add set inet axonwall threat_feed_block');
    expect(res.nftCommands[0]).toContain('flags interval; auto-merge');
    expect(res.nftCommands[1]).toContain('add element inet axonwall threat_feed_block');
    expect(res.nftCommands[2]).toContain('add element inet axonwall threat_feed_block');
  });
});
