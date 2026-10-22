import { describe, it, expect } from 'vitest';
import {
  parseNmapXml,
  updateHostInScan,
  mergeScanResults,
  addHostToScan,
  removeHostFromScan,
  ENTERPRISE_NETWORK_XML,
  GLOBAL_PERIMETER_XML,
} from '../src/index';
import type { NmapHost, HostAction } from '../src/types/nmap';

describe('NastyMap Extensibility & Scan Mutation Engine', () => {
  it('updates a specific host in an NmapRun object immutably', () => {
    const scan = parseNmapXml(ENTERPRISE_NETWORK_XML);
    const targetIp = '10.0.10.30';

    const updatedScan = updateHostInScan(scan, targetIp, (host) => {
      return {
        comments: 'Critical Production DB - Under Investigation',
        tags: ['quarantined', 'tier-1'],
        isQuarantined: true,
        latencyMs: 1.45,
      };
    });

    const targetHost = updatedScan.hosts.find((h) => h.ipv4 === targetIp);
    expect(targetHost).toBeDefined();
    expect(targetHost?.comments).toBe('Critical Production DB - Under Investigation');
    expect(targetHost?.tags).toContain('quarantined');
    expect(targetHost?.isQuarantined).toBe(true);
    expect(targetHost?.latencyMs).toBe(1.45);

    // Original scan must remain unaffected
    const originalHost = scan.hosts.find((h) => h.ipv4 === targetIp);
    expect(originalHost?.isQuarantined).toBeUndefined();
  });

  it('allows adding discovered ports and updates openPortCount automatically', () => {
    const scan = parseNmapXml(ENTERPRISE_NETWORK_XML);
    const targetIp = '192.168.1.1';
    const initialHost = scan.hosts.find((h) => h.ipv4 === targetIp)!;
    expect(initialHost).toBeDefined();
    const initialPortCount = initialHost.ports.filter((p) => p.state === 'open').length;

    const updatedScan = updateHostInScan(scan, targetIp, (host) => {
      return {
        ports: [
          ...host.ports,
          {
            portid: 8443,
            protocol: 'tcp',
            state: 'open',
            service: {
              name: 'https-alt',
              product: 'Custom Admin Portal',
              version: '2.4.1',
            },
          },
        ],
      };
    });

    const updatedHost = updatedScan.hosts.find((h) => h.ipv4 === targetIp)!;
    expect(updatedHost.openPortCount).toBe(initialPortCount + 1);
    expect(updatedHost.ports.some((p) => p.portid === 8443)).toBe(true);
  });

  it('deeply merges two scans together', () => {
    const scanA = parseNmapXml(ENTERPRISE_NETWORK_XML);
    const scanB = parseNmapXml(GLOBAL_PERIMETER_XML);

    const merged = mergeScanResults(scanA, scanB);
    expect(merged.hosts.length).toBeGreaterThan(scanA.hosts.length);

    // Verify hosts from both scans exist in merged result
    expect(merged.hosts.some((h) => h.ipv4 === '192.168.1.1')).toBe(true);
    expect(merged.hosts.some((h) => h.ipv4 === '1.1.1.1')).toBe(true);
  });

  it('executes custom host actions and updates the host state correctly', async () => {
    const scan = parseNmapXml(ENTERPRISE_NETWORK_XML);
    const host = scan.hosts[0]!;

    let actionExecuted = false;
    let receivedHostId = '';

    const deepScanAction: HostAction = {
      id: 'deep-scan',
      label: 'Deep Scan',
      shortcut: 'd',
      onClick: async (targetHost, context) => {
        actionExecuted = true;
        receivedHostId = targetHost.id;
        context.updateHost((prev) => ({
          customData: { deepScanTimestamp: 123456 },
          tags: [...(prev.tags || []), 'deep-scanned'],
        }));
      },
    };

    let updatedScan = scan;
    const mockContext = {
      updateHost: (updater: (prev: NmapHost) => NmapHost | Partial<NmapHost>) => {
        updatedScan = updateHostInScan(updatedScan, host.id, updater);
      },
      notify: () => {},
    };

    await deepScanAction.onClick(host, mockContext);

    expect(actionExecuted).toBe(true);
    expect(receivedHostId).toBe(host.id);

    const checkHost = updatedScan.hosts.find((h) => h.id === host.id)!;
    expect(checkHost.tags).toContain('deep-scanned');
    expect(checkHost.customData?.deepScanTimestamp).toBe(123456);
  });
});
