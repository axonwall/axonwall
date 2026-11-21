import { describe, expect, it, vi, beforeEach } from 'vitest';

const { mockCallAgentApi } = vi.hoisted(() => ({
  mockCallAgentApi: vi.fn(),
}));

vi.mock('../agent-client', () => ({
  callAgentApi: (...args: unknown[]) => mockCallAgentApi(...args),
  callAgentApiDetailed: vi.fn(),
  callAgentApiResponse: vi.fn(),
}));

vi.mock('../auth', () => ({
  getSession: vi.fn(async () => ({
    username: 'admin',
    displayName: 'admin',
    roles: ['admin'],
    privileges: ['*'],
    passwordChangeRequired: false,
    source: 'local_admin',
  })),
}));

import {
  buildFlowTopologyGraph,
  buildSketchWaveformData,
  computeDataplaneRatePoint,
  normalizeEbpfOverviewResponse,
  type XdpBlockedEntry,
  type XdpFlowEntry,
  type XdpVerdictStats,
} from '@/lib/ebpf-telemetry';
import { getEbpfOverviewTelemetry } from '../agent';

describe('normalizeEbpfOverviewResponse', () => {
  it('translates raw axonwalld /v1/ebpf/overview payload accurately and idempotently', () => {
    const futureIso = new Date(Date.now() + 120_000).toISOString();
    const rawDaemonPayload = {
      dataplane: {
        running: true,
        attachedInterfaces: ['eth0', 'eth1'],
        synFloodLimitPps: 2500,
        stats: {
          rxPackets: 50000,
          rxBytes: 32000000,
          xdpPass: 49500,
          xdpDrop: 500,
          ipv4Packets: 45000,
          ipv6Packets: 5000,
          vlanPackets: 1200,
          tcpSynPackets: 4200,
          lpmCidrDrops: 300,
          synFloodDrops: 200,
        },
        perCpuStats: [
          {
            cpu: 0,
            rxPackets: 25000,
            rxBytes: 16000000,
            xdpPass: 24750,
            xdpDrop: 250,
            ipv4Packets: 22500,
            ipv6Packets: 2500,
            vlanPackets: 600,
            tcpSynPackets: 2100,
            lpmCidrDrops: 150,
            synFloodDrops: 100,
          },
          {
            cpu: 1,
            rxPackets: 25000,
            rxBytes: 16000000,
            xdpPass: 24750,
            xdpDrop: 250,
            ipv4Packets: 22500,
            ipv6Packets: 2500,
            vlanPackets: 600,
            tcpSynPackets: 2100,
            lpmCidrDrops: 150,
            synFloodDrops: 100,
          },
        ],
        totalFlowCount: 2,
        totalFlowCountV4: 1,
        totalFlowCountV6: 1,
        protocolBreakdown: [{ protocol: 6, protoName: 'TCP', flows: 2, packets: 300, bytes: 180000 }],
        topPorts: [
          {
            port: 443,
            service: 'HTTPS',
            protocol: 6,
            protoName: 'TCP',
            flows: 2,
            packets: 300,
            bytes: 180000,
            synPackets: 4,
            rstPackets: 1,
          },
        ],
        vlanBreakdown: [{ vlanId: 10, flows: 1, packets: 100, bytes: 60000 }],
        synRateMeters: [{ ip: '198.51.100.77', family: 4, synCount: 3000, droppedPackets: 200, windowAgeMs: 400 }],
        topFlows: [
          {
            family: 4,
            srcIp: '198.51.100.77',
            dstIp: '10.0.0.1',
            srcPort: 44123,
            dstPort: 443,
            vlanId: 10,
            protocol: 6,
            protoName: 'TCP',
            packets: 200,
            bytes: 120000,
            synPackets: 2,
            rstPackets: 0,
            tcpFlags: 'SYN|ACK',
            ageMs: 50,
          },
        ],
        activeBlocks: [
          {
            ip: '198.51.100.0/24',
            family: 4,
            isCidr: true,
            dropPackets: 300,
            dropBytes: 18000,
            reasonCode: 4,
            reason: 'LPM CIDR',
            expiresAt: futureIso,
          },
        ],
      },
      lsm: {
        attached: true,
        attachedHooks: ['lsm/bpf', 'lsm/socket_bind', 'lsm/bpf_token_create'],
        allowlist: [{ path: '/usr/sbin/axonwalld', dev: 1, ino: 42, flags: 1 }],
        recentEvents: [
          {
            timestamp: futureIso,
            pid: 1234,
            uid: 1000,
            hookId: 5,
            hook: 'lsm/bpf_token',
            blocked: true,
            dev: 1,
            ino: 99,
            comm: 'kprobe-test',
            detail: 'denied kprobe',
            mitreTechnique: 'T1611',
          },
        ],
      },
      bpfTokens: {
        capabilities: {
          kernelRelease: '6.12.5-arch1-1',
          kernelMajor: 6,
          kernelMinor: 12,
          kernel69OrNewer: true,
          btfHasBpfToken: true,
          btfHasLsmTokenCreate: true,
          btfHasLsmTokenCmd: true,
          unprivilegedBpfDisabled: '1',
          userNsCloneAllowed: true,
          supported: true,
        },
        presets: [
          {
            id: 'network-dataplane',
            name: 'XDP & TC Container Network Dataplane',
            summary: 'Permits XDP and TCX in UserNS',
            delegateCmds: 'prog_load:map_create',
            delegateProgs: 'xdp:sched_cls',
            delegateMaps: 'hash:ringbuf',
            delegateAttachs: 'xdp:tcx_ingress',
          },
        ],
        profiles: [
          {
            id: 'k3s-net-safe',
            targetKind: 'k3s-pod',
            targetRef: 'vow-system/cilium',
            preset: 'network-dataplane',
            enabled: true,
            delegateCmds: 'prog_load:map_create',
            delegateProgs: 'xdp:sched_cls',
            delegateMaps: 'hash:ringbuf',
            delegateAttachs: 'xdp:tcx_ingress',
            bpffsMountPath: '/run/axonwall/bpffs-tokens/k3s-net-safe',
          },
        ],
        activeMounts: [
          {
            mountId: 91,
            mountPoint: '/run/axonwall/bpffs-tokens/k3s-net-safe',
            readOnly: false,
            hasDelegation: true,
          },
        ],
      },
      bpfInventory: {
        timestamp: futureIso,
        available: true,
        statsEnabled: true,
        totalPrograms: 5,
        totalMaps: 12,
        totalJitedBytes: 16384,
        totalProgMemlockBytes: 32768,
        totalMapMemlockBytes: 1048576,
        programsByType: [{ type: 'XDP', count: 1, totalBytes: 4096, totalRunTimeNs: 9000, totalRunCount: 500 }],
        mapsByType: [{ type: 'LRUHash', count: 2, totalBytes: 524288, totalRunTimeNs: 0, totalRunCount: 0 }],
        programs: [],
        maps: [],
      },
      kernelRca: {
        timestamp: futureIso,
        tcp: {
          available: true,
          inSegs: 1000,
          outSegs: 1000,
          retransSegs: 1,
          retransmitRatioPct: 0.1,
          currEstab: 12,
          attemptFails: 0,
          estabResets: 0,
          inErrs: 0,
          outRsts: 0,
        },
        udp: { available: true, inDatagrams: 500, outDatagrams: 400, noPorts: 0, inErrors: 0, rcvbufErrors: 0, sndbufErrors: 0 },
        cgroupCpu: { available: true, sourcePath: '/sys/fs/cgroup/cpu.stat', nrPeriods: 100, nrThrottled: 2, throttledUsec: 5000, throttleRatioPct: 2.0 },
        memory: { available: true, oomKillCount: 0, majorPageFaults: 3, allocStalls: 0, psiSomeAvg10: 0.25, psiFullAvg10: 0, psiAvailable: true },
      },
      virt: {
        timestamp: futureIso,
        workloads: [
          {
            kind: 'lxc',
            id: 101,
            name: 'ct-net',
            status: 'running',
            pid: 555,
            bpfTokenEnabled: true,
            bpfTokenPreset: 'network-dataplane',
            netdevs: [
              {
                device: 'veth101_0',
                operState: 'up',
                rxBytes: 2048,
                txBytes: 1024,
                rxPackets: 20,
                txPackets: 10,
                rxDropped: 0,
                txDropped: 0,
                xdpProgAttached: true,
              },
            ],
          },
        ],
        bridgeStats: [
          {
            device: 'br0',
            operState: 'up',
            rxBytes: 4096,
            txBytes: 4096,
            rxPackets: 40,
            txPackets: 40,
            rxDropped: 0,
            txDropped: 0,
            xdpProgAttached: false,
          },
        ],
        iommuEnabled: true,
        iommuGroups: 16,
      },
      k3s: {
        timestamp: futureIso,
        cluster: { serviceActive: true, running: true, enabled: true, zfsLocalPvPool: 'tank/openebs', volumes: [] },
        cniInterfaces: [
          {
            device: 'flannel-wg',
            operState: 'up',
            rxBytes: 8192,
            txBytes: 8192,
            rxPackets: 50,
            txPackets: 50,
            rxDropped: 0,
            txDropped: 0,
            xdpProgAttached: false,
          },
        ],
      },
      nas: {
        timestamp: futureIso,
        pools: [],
        arc: { available: true, sizeBytes: 104857600, targetMaxBytes: 536870912, hits: 990, misses: 10, hitRatioPct: 99.0 },
        zil: { available: true, commitCount: 42, commitWriterCount: 1, itxCount: 80, itxMetaslabNormalCount: 20, itxMetaslabSlogCount: 60 },
        poolIoStats: [{ pool: 'tank', nreadBytes: 1073741824, nwrittenBytes: 536870912, reads: 100, writes: 50, waitQueueDepth: 0, activeQueueDepth: 1 }],
      },
    };

    const norm = normalizeEbpfOverviewResponse(rawDaemonPayload);
    expect(norm.daemonDown).toBe(false);
    expect(norm.dataplane.xdpStats.xdpPassPackets).toBe(49500);
    expect(norm.dataplane.xdpStats.xdpDropPackets).toBe(500);
    expect(norm.dataplane.xdpStats.vlanTaggedPackets).toBe(1200);
    expect(norm.dataplane.xdpStats.lpmCidrDrops).toBe(300);
    expect(norm.dataplane.perCpuStats).toHaveLength(2);
    expect(norm.dataplane.blockedIps).toHaveLength(1);
    expect(norm.dataplane.blockedIps[0].family).toBe('ipv4');
    expect(norm.dataplane.blockedIps[0].droppedPackets).toBe(300);
    expect(norm.dataplane.blockedIps[0].expiresInSeconds).toBeGreaterThan(100);

    expect(norm.bpfLsm.attached).toBe(true);
    expect(norm.bpfLsm.denialEventsCount).toBe(1);
    expect(norm.bpfTokens.supportsBpfToken).toBe(true);
    expect(norm.bpfTokens.activeProfiles[0].name).toBe('k3s-net-safe');
    expect(norm.bpfTokens.activeProfiles[0].mounted).toBe(true);
    expect(norm.bpfTokens.presets['network-dataplane']?.delegateProgs).toBe('xdp:sched_cls');

    expect(norm.bpfInventory?.available).toBe(true);
    expect(norm.bpfInventory?.totalPrograms).toBe(5);
    expect(norm.kernelRca?.tcp.retransmitRatioPct).toBe(0.1);
    expect(norm.kernelRca?.cgroupCpu.throttleRatioPct).toBe(2.0);

    expect(norm.virt.runningLxcCount).toBe(1);
    expect(norm.virt.vnetInterfaces).toHaveLength(2);
    expect(norm.k3s.cniInterfaces[0].name).toBe('flannel-wg');
    expect(norm.k3s.openEbsDatasets).toEqual(['tank/openebs']);

    expect(norm.nas.zfsModuleLoaded).toBe(true);
    expect(norm.nas.arc.maxSizeBytes).toBe(536870912);
    expect(norm.nas.zil.zilCommitCount).toBe(42);
    expect(norm.nas.poolIoStats?.[0].pool).toBe('tank');

    const second = normalizeEbpfOverviewResponse(norm);
    expect(second.dataplane.xdpStats.xdpPassPackets).toBe(49500);
    expect(second.bpfTokens.activeProfiles[0].mounted).toBe(true);
    expect(second.nas.zil.zilCommitCount).toBe(42);
  });
});

describe('getEbpfOverviewTelemetry server action', () => {
  beforeEach(() => {
    mockCallAgentApi.mockReset();
  });

  it('reports daemonDown:true and empty structures when axonwalld is unreachable', async () => {
    mockCallAgentApi.mockResolvedValue(null);
    const res = await getEbpfOverviewTelemetry();
    expect(res.daemonDown).toBe(true);
    expect(res.dataplane.topFlows).toEqual([]);
    expect(res.bpfInventory?.available).toBe(false);
    expect(res.kernelRca?.tcp.available).toBe(false);
  });

  it('normalizes live daemon telemetry when axonwalld answers', async () => {
    mockCallAgentApi.mockResolvedValue({
      dataplane: {
        running: true,
        attachedInterfaces: ['wan0'],
        stats: { rxPackets: 10, rxBytes: 640, xdpPass: 9, xdpDrop: 1 },
        activeBlocks: [],
        topFlows: [],
      },
      lsm: { attached: true, attachedHooks: ['lsm/bpf'], recentEvents: [] },
      bpfTokens: { capabilities: { kernelRelease: '6.12.0', supported: true }, presets: [], profiles: [] },
    });
    const res = await getEbpfOverviewTelemetry();
    expect(res.daemonDown).toBe(false);
    expect(res.dataplane.xdpStats.xdpPassPackets).toBe(9);
    expect(res.dataplane.xdpStats.xdpDropPackets).toBe(1);
    expect(res.bpfLsm.attachedHooks).toEqual(['lsm/bpf']);
  });
});

describe('computeDataplaneRatePoint', () => {
  const base: XdpVerdictStats = {
    rxPackets: 1000,
    rxBytes: 1_000_000,
    ipv4Packets: 900,
    ipv6Packets: 100,
    vlanTaggedPackets: 50,
    xdpDropPackets: 10,
    xdpDropBytes: 640,
    xdpPassPackets: 990,
    tcpSynPackets: 20,
    lpmCidrDrops: 5,
    synFloodDrops: 2,
  };

  it('computes accurate positive deltas and guards counter resets', () => {
    const zero = computeDataplaneRatePoint(null, base, 4, 't0');
    expect(zero.rxPps).toBe(0);
    expect(zero.rxMbps).toBe(0);

    const next: XdpVerdictStats = {
      ...base,
      rxPackets: 3000,
      rxBytes: 3_000_000,
      xdpPassPackets: 2950,
      xdpDropPackets: 50,
      tcpSynPackets: 100,
      lpmCidrDrops: 25,
      synFloodDrops: 10,
    };
    const point = computeDataplaneRatePoint(base, next, 4, 't1');
    expect(point.rxPps).toBe(500);
    expect(point.passPps).toBe(490);
    expect(point.dropPps).toBe(10);
    expect(point.synPps).toBe(20);
    expect(point.lpmDropPps).toBe(5);
    expect(point.synFloodDropPps).toBe(2);
    expect(point.rxMbps).toBe(4);

    const resetPoint = computeDataplaneRatePoint(next, base, 4, 't2');
    expect(resetPoint.rxPps).toBe(0);
    expect(resetPoint.rxMbps).toBe(0);
  });
});

describe('buildFlowTopologyGraph & buildSketchWaveformData', () => {
  const flows: XdpFlowEntry[] = [
    {
      family: 4,
      srcIp: '10.0.0.5',
      dstIp: '10.0.0.1',
      srcPort: 50000,
      dstPort: 443,
      vlanId: 0,
      protocol: 6,
      protoName: 'TCP',
      packets: 100,
      bytes: 150000,
      synPackets: 2,
      rstPackets: 0,
      ageMs: 10,
    },
    {
      family: 4,
      srcIp: '203.0.113.9',
      dstIp: '10.0.0.1',
      srcPort: 41000,
      dstPort: 22,
      vlanId: 20,
      protocol: 6,
      protoName: 'TCP',
      packets: 40,
      bytes: 3200,
      synPackets: 35,
      rstPackets: 0,
      ageMs: 20,
    },
    {
      family: 6,
      srcIp: 'fd00::5',
      dstIp: 'fd00::1',
      srcPort: 52000,
      dstPort: 53,
      vlanId: 0,
      protocol: 17,
      protoName: 'UDP',
      packets: 10,
      bytes: 900,
      synPackets: 0,
      rstPackets: 0,
      ageMs: 30,
    },
  ];
  const blocked: XdpBlockedEntry[] = [
    { ip: '203.0.113.9', family: 'ipv4', expiresInSeconds: 300, droppedPackets: 12, droppedBytes: 800 },
  ];

  it('builds filtered 3-tier topology graphs highlighting blocked and SYN-heavy paths', () => {
    const all = buildFlowTopologyGraph(flows, blocked);
    expect(all.sources).toHaveLength(3);
    expect(all.hubs).toHaveLength(3);
    expect(all.edges).toHaveLength(6);

    const anom = buildFlowTopologyGraph(flows, blocked, { anomalyOnly: true });
    expect(anom.totalMatchedFlows).toBe(1);
    expect(anom.sources[0].label).toBe('203.0.113.9');
    expect(anom.sources[0].isBlocked).toBe(true);

    const v6Only = buildFlowTopologyGraph(flows, blocked, { familyFilter: '6' });
    expect(v6Only.totalMatchedFlows).toBe(1);
    expect(v6Only.hubs[0].label).toBe('UDP:53');
  });

  it('transforms Threat Harvester 16-packet signed vectors cleanly', () => {
    const pts = buildSketchWaveformData([128, -512, 64, 0, 0], [0, 450, 1200, 0, 0]);
    expect(pts).toHaveLength(3);
    expect(pts[0].direction).toBe('egress');
    expect(pts[1].direction).toBe('ingress');
    expect(pts[1].absBytes).toBe(512);
    expect(pts[2].iatMs).toBe(1.2);
  });
});
