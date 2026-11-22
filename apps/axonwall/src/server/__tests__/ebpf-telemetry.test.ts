import { describe, expect, it, vi, beforeEach } from 'vitest';

const { mockCallAgentApi, mockCallAgentApiResponse } = vi.hoisted(() => ({
  mockCallAgentApi: vi.fn(),
  mockCallAgentApiResponse: vi.fn(),
}));

vi.mock('../agent-client', () => ({
  callAgentApi: (...args: unknown[]) => mockCallAgentApi(...args),
  callAgentApiDetailed: vi.fn(),
  callAgentApiResponse: (...args: unknown[]) => mockCallAgentApiResponse(...args),
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
  buildBpfDependencyGraph,
  buildFlowHeatmapMatrix,
  buildFlowTopologyGraph,
  buildSketchWaveformData,
  buildXdpPipelineModel,
  computeBpfProgramRuntimeDeltas,
  computeDataplaneRatePoint,
  computeSoftnetDeltas,
  correlateListeningSocketsWithXdp,
  normalizeEbpfOverviewResponse,
  type BpfProgramInventoryItem,
  type KernelBpfInventory,
  type KernelSocketTelemetry,
  type KernelSoftnetTelemetry,
  type XdpBlockedEntry,
  type XdpFlowEntry,
  type XdpPortSummary,
  type XdpVerdictStats,
} from '@/lib/ebpf-telemetry';
import { getEbpfOverviewTelemetry, toggleKernelBpfStatsAction } from '../agent';

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
        totalLinks: 1,
        totalJitedBytes: 16384,
        totalProgMemlockBytes: 32768,
        totalMapMemlockBytes: 1048576,
        programsByType: [{ type: 'XDP', count: 1, totalBytes: 4096, totalRunTimeNs: 9000, totalRunCount: 500 }],
        mapsByType: [{ type: 'LRUHash', count: 2, totalBytes: 524288, totalRunTimeNs: 0, totalRunCount: 0 }],
        programs: [
          {
            id: 42,
            type: 'XDP',
            name: 'xdp_flow_tracker',
            tag: 'abc123',
            jitedBytes: 4096,
            translatedBytes: 2048,
            verifiedInsns: 850,
            memlockBytes: 8192,
            mapCount: 2,
            mapIds: [101, 102],
            hasBtf: true,
            createdByUid: 0,
            runCount: 500,
            runTimeNs: 9000,
            recursionMisses: 0,
          },
        ],
        maps: [],
        links: [
          {
            id: 7,
            type: 'xdp',
            programId: 42,
            attachDetail: 'xdp:eth0',
          },
        ],
      },
      softnet: {
        timestamp: futureIso,
        available: true,
        cpuCount: 2,
        totalProcessed: 15000,
        totalDropped: 1,
        totalTimeSqueeze: 3,
        totalCpuCollision: 0,
        totalReceivedRps: 20,
        totalFlowLimitCount: 0,
        perCpu: [
          { cpu: 1, processed: 5000, dropped: 0, timeSqueeze: 1, cpuCollision: 0, receivedRps: 5, flowLimitCount: 0 },
          { cpu: 0, processed: 10000, dropped: 1, timeSqueeze: 2, cpuCollision: 0, receivedRps: 15, flowLimitCount: 0 },
        ],
      },
      sockets: {
        timestamp: futureIso,
        available: true,
        totalTcpSockets: 14,
        ipv4TcpSockets: 10,
        ipv6TcpSockets: 4,
        totalUdpSockets: 6,
        ipv4UdpSockets: 4,
        ipv6UdpSockets: 2,
        tcpStates: { LISTEN: 4, ESTABLISHED: 8, SYN_RECV: 2 },
        listeningPorts: [{ protocol: 'TCP', port: 443, service: 'HTTPS', ipv4Sockets: 1, ipv6Sockets: 1, totalCount: 2 }],
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
    expect(norm.bpfInventory?.totalLinks).toBe(1);
    expect(norm.bpfInventory?.programs[0].mapIds).toEqual([101, 102]);
    expect(norm.bpfInventory?.links[0].attachDetail).toBe('xdp:eth0');
    expect(norm.softnet?.available).toBe(true);
    expect(norm.softnet?.perCpu[0].cpu).toBe(0);
    expect(norm.sockets?.available).toBe(true);
    expect(norm.sockets?.tcpStates.ESTABLISHED).toBe(8);
    expect(norm.sockets?.tcpStates.TIME_WAIT).toBe(0);
    expect(norm.sockets?.listeningPorts[0].service).toBe('HTTPS');
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
    expect(second.bpfInventory?.links).toHaveLength(1);
    expect(second.softnet?.totalTimeSqueeze).toBe(3);
    expect(second.sockets?.listeningPorts[0].port).toBe(443);
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

describe('Expanded eBPF visualization builders & sysctl toggle', () => {
  beforeEach(() => {
    mockCallAgentApiResponse.mockReset();
  });

  it('computes XDP pipeline stage breakdown in cumulative and delta modes with safe clamping', () => {
    const stats: XdpVerdictStats = {
      rxPackets: 1000,
      rxBytes: 640_000,
      ipv4Packets: 800,
      ipv6Packets: 180,
      vlanTaggedPackets: 250,
      xdpDropPackets: 100,
      xdpDropBytes: 6400,
      xdpPassPackets: 900,
      tcpSynPackets: 40,
      lpmCidrDrops: 35,
      synFloodDrops: 25,
    };

    const cum = buildXdpPipelineModel(stats, null, 'cumulative');
    expect(cum.vlanTagged).toBe(250);
    expect(cum.untagged).toBe(750);
    expect(cum.otherL3).toBe(20);
    expect(cum.hostBlocklistDrop).toBe(40);

    const nextStats: XdpVerdictStats = {
      ...stats,
      rxPackets: 1400,
      rxBytes: 1_040_000,
      ipv4Packets: 1100,
      ipv6Packets: 280,
      vlanTaggedPackets: 350,
      xdpPassPackets: 1260,
      xdpDropPackets: 140,
      lpmCidrDrops: 55,
      synFloodDrops: 35,
    };
    const deltaSample = computeDataplaneRatePoint(stats, nextStats, 2, 't1');
    expect(deltaSample.vlanPps).toBe(50);

    const delta = buildXdpPipelineModel(nextStats, deltaSample, 'delta');
    expect(delta.mode).toBe('delta');
    expect(delta.rxTotal).toBe(200);
    expect(delta.vlanTagged).toBe(50);
    expect(delta.untagged).toBe(150);
    expect(delta.ipv4).toBe(150);
    expect(delta.ipv6).toBe(50);
    expect(delta.otherL3).toBe(0);
    expect(delta.lpmCidrDrop).toBe(10);
    expect(delta.synFloodDrop).toBe(5);
    expect(delta.hostBlocklistDrop).toBe(5);
  });

  it('computes per-program runtime deltas, share %, and guards counter wraps', () => {
    const p1Prev: BpfProgramInventoryItem[] = [
      {
        id: 1,
        type: 'XDP',
        name: 'xdp_main',
        tag: 't1',
        jitedBytes: 4096,
        translatedBytes: 2048,
        verifiedInsns: 500,
        memlockBytes: 8192,
        mapCount: 1,
        mapIds: [10],
        hasBtf: true,
        createdByUid: 0,
        runCount: 1000,
        runTimeNs: 500_000,
        recursionMisses: 0,
      },
      {
        id: 2,
        type: 'LSM',
        name: 'lsm_guard',
        tag: 't2',
        jitedBytes: 2048,
        translatedBytes: 1024,
        verifiedInsns: 200,
        memlockBytes: 4096,
        mapCount: 1,
        mapIds: [11],
        hasBtf: true,
        createdByUid: 0,
        runCount: 200,
        runTimeNs: 100_000,
        recursionMisses: 1,
      },
    ];
    const p1Next: BpfProgramInventoryItem[] = [
      { ...p1Prev[0], runCount: 5000, runTimeNs: 2_500_000 },
      { ...p1Prev[1], runCount: 400, runTimeNs: 300_000 },
    ];

    const deltas = computeBpfProgramRuntimeDeltas(p1Prev, p1Next, 2);
    expect(deltas[0].id).toBe(1);
    expect(deltas[0].runsPerSec).toBe(2000);
    expect(deltas[0].cpuUsPerSec).toBe(1000);
    expect(deltas[0].avgNsPerRun).toBe(500);
    expect(deltas[1].cpuUsPerSec).toBe(100);
    expect(deltas[0].sharePct).toBeCloseTo(90.9, 1);

    const wrapped = computeBpfProgramRuntimeDeltas(p1Next, p1Prev, 2);
    expect(wrapped[0].runsPerSec).toBe(0);
    expect(wrapped[0].cpuUsPerSec).toBe(0);
  });

  it('computes per-CPU softnet delta rates safely', () => {
    const prev: KernelSoftnetTelemetry = {
      timestamp: '2026-11-22T00:00:00Z',
      available: true,
      cpuCount: 2,
      totalProcessed: 1100,
      totalDropped: 1,
      totalTimeSqueeze: 2,
      totalCpuCollision: 0,
      totalReceivedRps: 0,
      totalFlowLimitCount: 0,
      perCpu: [
        { cpu: 0, processed: 1000, dropped: 1, timeSqueeze: 2, cpuCollision: 0, receivedRps: 0, flowLimitCount: 0 },
        { cpu: 1, processed: 100, dropped: 0, timeSqueeze: 0, cpuCollision: 0, receivedRps: 0, flowLimitCount: 0 },
      ],
    };
    const next: KernelSoftnetTelemetry = {
      ...prev,
      totalProcessed: 1700,
      totalDropped: 3,
      totalTimeSqueeze: 4,
      perCpu: [
        { cpu: 0, processed: 1400, dropped: 3, timeSqueeze: 4, cpuCollision: 0, receivedRps: 4, flowLimitCount: 0 },
        { cpu: 1, processed: 300, dropped: 0, timeSqueeze: 0, cpuCollision: 0, receivedRps: 0, flowLimitCount: 0 },
      ],
    };
    const deltas = computeSoftnetDeltas(prev, next, 2);
    expect(deltas).toHaveLength(2);
    expect(deltas[0].processedPerSec).toBe(200);
    expect(deltas[0].droppedPerSec).toBe(1);
    expect(deltas[0].timeSqueezePerSec).toBe(1);
    expect(deltas[0].receivedRpsPerSec).toBe(2);
    expect(deltas[1].processedPerSec).toBe(100);
  });

  it('builds Link <-> Program <-> Map dependency graph and deduplicates shared maps', () => {
    const inv: KernelBpfInventory = {
      timestamp: '2026-11-22T00:00:00Z',
      available: true,
      statsEnabled: true,
      totalPrograms: 2,
      totalMaps: 3,
      totalLinks: 1,
      totalJitedBytes: 6144,
      totalProgMemlockBytes: 12288,
      totalMapMemlockBytes: 30000,
      programsByType: [],
      mapsByType: [],
      programs: [
        {
          id: 10,
          type: 'XDP',
          name: 'xdp_main',
          tag: 'aa',
          jitedBytes: 4096,
          translatedBytes: 2048,
          verifiedInsns: 900,
          memlockBytes: 8192,
          mapCount: 2,
          mapIds: [100, 200, 999],
          hasBtf: true,
          createdByUid: 0,
          runCount: 100,
          runTimeNs: 50000,
          recursionMisses: 0,
        },
        {
          id: 11,
          type: 'LSM',
          name: 'lsm_main',
          tag: 'bb',
          jitedBytes: 2048,
          translatedBytes: 1024,
          verifiedInsns: 300,
          memlockBytes: 4096,
          mapCount: 1,
          mapIds: [200],
          hasBtf: true,
          createdByUid: 0,
          runCount: 50,
          runTimeNs: 10000,
          recursionMisses: 0,
        },
      ],
      maps: [
        { id: 100, type: 'PerCPUArray', name: 'xdp_stats_map', keySize: 4, valueSize: 64, maxEntries: 1, memlockBytes: 10000, frozen: false, hasBtf: true },
        { id: 200, type: 'RingBuf', name: 'shared_events', keySize: 0, valueSize: 0, maxEntries: 4096, memlockBytes: 20000, frozen: false, hasBtf: true },
      ],
      links: [{ id: 1, type: 'xdp', programId: 10, attachDetail: 'xdp:eth0' }],
    };

    const g = buildBpfDependencyGraph(inv);
    expect(g.programs).toHaveLength(2);
    expect(g.maps).toHaveLength(2);
    expect(g.linkToProgEdges).toHaveLength(1);
    // Map 999 doesn't exist in inv.maps so orphan edges are omitted cleanly
    expect(g.progToMapEdges).toHaveLength(3);

    const searchFiltered = buildBpfDependencyGraph(inv, { search: 'xdp_stats_map' });
    expect(searchFiltered.programs).toHaveLength(1);
    expect(searchFiltered.programs[0].id).toBe(10);
  });

  it('builds flow heatmap matrix and correlates listening ports with XDP traffic', () => {
    const flows: XdpFlowEntry[] = [
      {
        family: 4,
        srcIp: '198.51.100.20',
        dstIp: '10.0.0.1',
        srcPort: 50001,
        dstPort: 443,
        vlanId: 0,
        protocol: 6,
        protoName: 'TCP',
        packets: 100,
        bytes: 60000,
        synPackets: 10,
        rstPackets: 0,
        ageMs: 10,
      },
      {
        family: 4,
        srcIp: '203.0.113.9',
        dstIp: '10.0.0.1',
        srcPort: 50002,
        dstPort: 22,
        vlanId: 0,
        protocol: 6,
        protoName: 'TCP',
        packets: 50,
        bytes: 3200,
        synPackets: 45,
        rstPackets: 1,
        ageMs: 20,
      },
    ];
    const blocked: XdpBlockedEntry[] = [
      { ip: '203.0.113.9', family: 'ipv4', expiresInSeconds: 120, droppedPackets: 50, droppedBytes: 3200 },
    ];

    const matrix = buildFlowHeatmapMatrix(flows, blocked);
    expect(matrix.rows).toHaveLength(2);
    expect(matrix.cols).toHaveLength(2);
    const sshCell = matrix.cells['203.0.113.9|TCP:22'];
    expect(sshCell.isBlocked).toBe(true);
    expect(sshCell.synRatioPct).toBe(90);

    const sockets: KernelSocketTelemetry = {
      timestamp: '2026-11-22T00:00:00Z',
      available: true,
      totalTcpSockets: 4,
      ipv4TcpSockets: 3,
      ipv6TcpSockets: 1,
      totalUdpSockets: 1,
      ipv4UdpSockets: 1,
      ipv6UdpSockets: 0,
      tcpStates: { LISTEN: 2, ESTABLISHED: 2 },
      listeningPorts: [
        { protocol: 'TCP', port: 22, service: 'SSH', ipv4Sockets: 1, ipv6Sockets: 0, totalCount: 1 },
        { protocol: 'TCP', port: 443, service: 'HTTPS', ipv4Sockets: 1, ipv6Sockets: 1, totalCount: 2 },
      ],
    };
    const topPorts: XdpPortSummary[] = [
      { port: 443, service: 'HTTPS', protocol: 6, protoName: 'TCP', flows: 5, packets: 100, bytes: 60000, synPackets: 4, rstPackets: 0 },
    ];

    const corr = correlateListeningSocketsWithXdp(sockets, topPorts);
    expect(corr).toHaveLength(2);
    expect(corr[0].port).toBe(443);
    expect(corr[0].activeInXdp).toBe(true);
    expect(corr[0].xdpBytes).toBe(60000);
    expect(corr[1].port).toBe(22);
    expect(corr[1].activeInXdp).toBe(false);
  });

  it('toggles kernel.bpf_stats_enabled through toggleKernelBpfStatsAction', async () => {
    mockCallAgentApiResponse.mockResolvedValue({ success: true, statsEnabled: true });
    const ok = await toggleKernelBpfStatsAction(true);
    expect(ok).toEqual({ success: true, statsEnabled: true });
    expect(mockCallAgentApiResponse).toHaveBeenCalledWith(
      '/v1/ebpf/bpf-stats',
      'POST',
      { enabled: true },
      8000
    );

    mockCallAgentApiResponse.mockResolvedValue(null);
    const down = await toggleKernelBpfStatsAction(false);
    expect(down.success).toBe(false);
    expect(down.error).toContain('Daemon unavailable');
  });
});
