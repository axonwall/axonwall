import { describe, expect, it, vi } from 'vitest';
import { CaptiveSessionManager } from './index.js';
import type { CaptivePortalZone } from '../schemas/index.js';

describe('CaptiveSessionManager security invariants (SEC-M24)', () => {
  const zone: CaptivePortalZone = {
    name: 'guest',
    interface: 'eth2',
    listenPort: 8999,
    authServers: ['ldap_internal'],
    sessionTimeoutMinutes: 60,
    idleTimeoutMinutes: 10,
    passThroughMacs: [],
    passThroughIps: [],
    enableBandwidthQuotas: false,
    downloadLimitKbps: 1000,
    uploadLimitKbps: 1000,
    enabled: true,
  };

  it('requires both IP and MAC to match when clientMac is provided and prunes expired sessions', () => {
    vi.useFakeTimers();
    try {
      const mgr = new CaptiveSessionManager();
      mgr.createSession(zone, '10.99.0.50', 'aa:bb:cc:dd:ee:01', 'alice');

      // Exact IP + MAC matches (case-insensitive MAC)
      expect(mgr.isClientAuthenticated('10.99.0.50', 'AA:BB:CC:DD:EE:01')).toBe(true);
      // Matching IP with mismatched MAC must be rejected (prevents IP-spoofing across MACs)
      expect(mgr.isClientAuthenticated('10.99.0.50', 'aa:bb:cc:dd:ee:99')).toBe(false);
      // Matching MAC with mismatched IP must be rejected (prevents MAC-spoofing across IPs)
      expect(mgr.isClientAuthenticated('10.99.0.51', 'aa:bb:cc:dd:ee:01')).toBe(false);
      // IP-only lookup still works when clientMac is unknown/omitted
      expect(mgr.isClientAuthenticated('10.99.0.50')).toBe(true);

      // Advance past sessionTimeoutMinutes (60m) and ensure expired session is pruned
      vi.advanceTimersByTime(61 * 60 * 1000);
      expect(mgr.isClientAuthenticated('10.99.0.50', 'aa:bb:cc:dd:ee:01')).toBe(false);
      expect(mgr.getActiveSessions()).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });
});
