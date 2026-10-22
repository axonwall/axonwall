import { describe, it, expect } from 'vitest';
import { generateNetworkScenario } from '../src/simulator/host-generator';

describe('Dynamic Host & Scenario Generator', () => {
  it('generates a realistic network scenario with default options', () => {
    const { scan, threats } = generateNetworkScenario({ totalHosts: 15, threatCount: 2 });

    expect(scan).toBeDefined();
    expect(scan.hosts.length).toBe(15);
    expect(threats.length).toBe(2);

    // Gateway exists at .1
    const gateway = scan.hosts.find((h) => h.ipv4?.endsWith('.1'));
    expect(gateway).toBeDefined();
    expect(gateway?.customData?.isGateway).toBe(true);

    // Threat hosts have isMalicious flag
    const maliciousHosts = scan.hosts.filter((h) => h.customData?.isMalicious === true);
    expect(maliciousHosts.length).toBe(2);

    for (const m of maliciousHosts) {
      expect(m.customData?.threatInfo).toBeDefined();
      expect(m.customData?.threatInfo.threatType).toBeDefined();
      expect(m.ports.length).toBeGreaterThan(0);
      expect(m.customData?.threatInfo.detectionClues.length).toBeGreaterThan(0);
    }

    // Normal hosts have categories (phone, laptop, iot)
    const normalHosts = scan.hosts.filter((h) => h.customData?.isMalicious === false && !h.customData?.isGateway);
    expect(normalHosts.length).toBe(12);
    for (const nh of normalHosts) {
      expect(nh.status.state).toBe('up');
      expect(nh.primaryHostname).toBeDefined();
      expect(nh.addresses.length).toBeGreaterThanOrEqual(1);
    }
  });

  it('supports custom subnet and higher threat counts', () => {
    const { scan, threats } = generateNetworkScenario({
      subnet: '10.42.0.0/24',
      totalHosts: 25,
      threatCount: 4,
    });

    expect(scan.hosts.length).toBe(25);
    expect(threats.length).toBe(4);

    for (const h of scan.hosts) {
      expect(h.ipv4?.startsWith('10.42.0.')).toBe(true);
    }
  });
});
