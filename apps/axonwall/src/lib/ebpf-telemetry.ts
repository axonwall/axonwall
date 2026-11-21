// Pure types, wire-schema normalizer, and graph/chart data transformations for
// Axonwall eBPF observability visualizations. Every metric derives strictly from
// real kernel telemetry returned by axonwalld or live SSE packet streams.

export interface BpfTokenProfileStatus {
  name: string;
  mountPath: string;
  preset: 'networking-safe' | 'cgroup-observability' | 'firewall-xdp-tc' | 'socket-observability' | 'network-dataplane' | 'cgroup-microsegmentation' | 'custom';
  delegateCmds: string;
  delegateProgs: string;
  delegateMaps: string;
  delegateAttachs: string;
  mounted: boolean;
  mountOptions?: string;
  ring0IsolationVerified: boolean;
  workloadTarget?: string;
  targetKind?: string;
  cmdsMaskHex?: string;
  progsMaskHex?: string;
}

export interface BpfTokenCapabilityReport {
  kernelRelease: string;
  major: number;
  minor: number;
  patch: number;
  supportsBpfToken: boolean;
  supportsUserNsBpf: boolean;
  bpffsRootMounted: boolean;
  unprivilegedBpfSysctl: string;
  bpfLsmActive: boolean;
  btfHasBpfToken?: boolean;
  btfHasLsmTokenCreate?: boolean;
  btfHasLsmTokenCmd?: boolean;
  forbiddenRing0ProgTypes: string[];
  activeProfiles: BpfTokenProfileStatus[];
  presets: Record<
    string,
    {
      name?: string;
      summary?: string;
      delegateCmds: string;
      delegateProgs: string;
      delegateMaps: string;
      delegateAttachs: string;
      cmdsMaskHex?: string;
      progsMaskHex?: string;
      mapsMaskHex?: string;
      attachsMaskHex?: string;
    }
  >;
}

export interface XdpVerdictStats {
  rxPackets: number;
  rxBytes: number;
  ipv4Packets: number;
  ipv6Packets: number;
  vlanTaggedPackets: number;
  xdpDropPackets: number;
  xdpDropBytes: number;
  xdpPassPackets: number;
  tcpSynPackets: number;
  lpmCidrDrops?: number;
  synFloodDrops?: number;
}

export interface XdpPerCpuStat {
  cpu: number;
  rxPackets: number;
  rxBytes: number;
  xdpPass: number;
  xdpDrop: number;
  ipv4Packets: number;
  ipv6Packets: number;
  vlanPackets: number;
  tcpSynPackets: number;
  lpmCidrDrops: number;
  synFloodDrops: number;
}

export interface XdpFlowEntry {
  family: number;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  vlanId: number;
  protocol: number;
  protoName: string;
  packets: number;
  bytes: number;
  synPackets: number;
  rstPackets: number;
  tcpFlags?: string;
  ageMs: number;
}

export interface XdpProtocolSummary {
  protocol: number;
  protoName: string;
  flows: number;
  packets: number;
  bytes: number;
}

export interface XdpPortSummary {
  port: number;
  service: string;
  protocol: number;
  protoName: string;
  flows: number;
  packets: number;
  bytes: number;
  synPackets: number;
  rstPackets: number;
}

export interface XdpVlanSummary {
  vlanId: number;
  flows: number;
  packets: number;
  bytes: number;
}

export interface XdpSynMeterEntry {
  ip: string;
  family: number;
  synCount: number;
  droppedPackets: number;
  windowAgeMs: number;
}

export interface XdpBlockedEntry {
  ip: string;
  family: 'ipv4' | 'ipv6';
  isCidr?: boolean;
  expiresInSeconds: number;
  droppedPackets: number;
  droppedBytes: number;
  reason?: string;
  reasonCode?: number;
  expiresAt?: string;
}

export interface BpfLsmAllowlistEntry {
  path: string;
  dev: number;
  ino: number;
  flags: number;
}

export interface BpfLsmEventEntry {
  timestamp: string;
  pid: number;
  uid: number;
  hookId: number;
  hook: string;
  blocked: boolean;
  dev: number;
  ino: number;
  comm: string;
  detail: string;
  mitreTechnique: string;
}

export interface BpfProgramInventoryItem {
  id: number;
  type: string;
  name: string;
  tag: string;
  jitedBytes: number;
  translatedBytes: number;
  verifiedInsns: number;
  memlockBytes: number;
  mapCount: number;
  hasBtf: boolean;
  createdByUid: number;
  runCount: number;
  runTimeNs: number;
  recursionMisses: number;
}

export interface BpfMapInventoryItem {
  id: number;
  type: string;
  name: string;
  keySize: number;
  valueSize: number;
  maxEntries: number;
  memlockBytes: number;
  frozen: boolean;
  hasBtf: boolean;
}

export interface BpfTypeAggregate {
  type: string;
  count: number;
  totalBytes: number;
  totalRunTimeNs: number;
  totalRunCount: number;
}

export interface KernelBpfInventory {
  timestamp: string;
  available: boolean;
  error?: string;
  statsEnabled: boolean;
  totalPrograms: number;
  totalMaps: number;
  totalJitedBytes: number;
  totalProgMemlockBytes: number;
  totalMapMemlockBytes: number;
  programsByType: BpfTypeAggregate[];
  mapsByType: BpfTypeAggregate[];
  programs: BpfProgramInventoryItem[];
  maps: BpfMapInventoryItem[];
}

export interface KernelRcaTelemetry {
  timestamp: string;
  tcp: {
    available: boolean;
    inSegs: number;
    outSegs: number;
    retransSegs: number;
    retransmitRatioPct: number;
    currEstab: number;
    attemptFails: number;
    estabResets: number;
    inErrs: number;
    outRsts: number;
  };
  udp: {
    available: boolean;
    inDatagrams: number;
    outDatagrams: number;
    noPorts: number;
    inErrors: number;
    rcvbufErrors: number;
    sndbufErrors: number;
  };
  cgroupCpu: {
    available: boolean;
    sourcePath?: string;
    nrPeriods: number;
    nrThrottled: number;
    throttledUsec: number;
    throttleRatioPct: number;
  };
  memory: {
    available: boolean;
    oomKillCount: number;
    majorPageFaults: number;
    allocStalls: number;
    psiSomeAvg10: number;
    psiFullAvg10: number;
    psiAvailable: boolean;
  };
}

export interface NetdevTrafficStat {
  name: string;
  kind: string;
  operState: string;
  mtu: number;
  rxBytes: number;
  txBytes: number;
  rxPackets: number;
  txPackets: number;
  rxDropped: number;
  txDropped: number;
  xdpAttached: boolean;
}

export interface VirtWorkloadSummary {
  kind: string;
  id: number;
  name: string;
  status: string;
  pid: number;
  bpfTokenEnabled: boolean;
  bpfTokenProfileId?: string;
  bpfTokenPreset?: string;
  netdevs: NetdevTrafficStat[];
}

export interface NasPoolIoStat {
  pool: string;
  nreadBytes: number;
  nwrittenBytes: number;
  reads: number;
  writes: number;
  waitQueueDepth: number;
  activeQueueDepth: number;
}

export interface ThreatHarvesterOverviewSummary {
  enabled: boolean;
  captureMode: string;
  bpfAttached: boolean;
  totalEpisodes: number;
  goldEpisodes: number;
  silverEpisodes: number;
  spoolUsedBytes: number;
  spoolQuotaBytes: number;
}

export interface ZfsDeepTelemetry {
  timestamp: string;
  zfsModuleLoaded: boolean;
  arc: {
    sizeBytes: number;
    maxSizeBytes: number;
    minSizeBytes: number;
    hits: number;
    misses: number;
    hitRatioPct: number;
    demandDataHits: number;
    demandDataMisses: number;
    l2Hits: number;
    l2Misses: number;
    l2SizeBytes: number;
    memoryThrottleCount: number;
  };
  zil: {
    zilCommitCount: number;
    zilCommitWriterCount: number;
    itxCount: number;
    itxIndirectBytes: number;
    itxCopiedBytes: number;
    itxNeedcopyBytes: number;
    slogBytesWritten?: number;
    itxMetaslabNormalCount?: number;
    itxMetaslabSlogCount?: number;
  };
  pools: Array<{
    pool: string;
    state: string;
    nreadBytes: number;
    nwrittenBytes: number;
    reads: number;
    writes: number;
    wtimeNs: number;
    rtimeNs: number;
    syncqReadActive: number;
    syncqWriteActive: number;
    asyncqReadActive: number;
    asyncqWriteActive: number;
    scrubqReadActive: number;
  }>;
  poolIoStats?: NasPoolIoStat[];
}

export interface VirtDutyTelemetry {
  timestamp: string;
  kvmAvailable: boolean;
  iommuGroupsCount: number;
  lxcInstalled: boolean;
  qemuInstalled: boolean;
  vnetInterfaces: NetdevTrafficStat[];
  workloads?: VirtWorkloadSummary[];
  bridgeStats?: NetdevTrafficStat[];
  runningQemuCount: number;
  runningLxcCount: number;
  unprivilegedLxcTokenMounts: string[];
}

export interface K3sDutyTelemetry {
  timestamp: string;
  serviceActive: boolean;
  binaryPresent: boolean;
  userNamespacesSupported: boolean;
  cniInterfaces: NetdevTrafficStat[];
  kubepodsCgroupV2: boolean;
  bpfTokenReady: boolean;
  openEbsDatasets: string[];
}

export interface EbpfOverviewTelemetry {
  daemonDown?: boolean;
  dataplane: {
    running?: boolean;
    attachedInterfaces: string[];
    dualStackEnabled: boolean;
    vlanPeelingEnabled: boolean;
    synFloodLimitPps?: number;
    xdpStats: XdpVerdictStats;
    perCpuStats?: XdpPerCpuStat[];
    totalFlowCount?: number;
    totalFlowCountV4?: number;
    totalFlowCountV6?: number;
    protocolBreakdown?: XdpProtocolSummary[];
    topPorts?: XdpPortSummary[];
    vlanBreakdown?: XdpVlanSummary[];
    synRateMeters?: XdpSynMeterEntry[];
    topFlows?: XdpFlowEntry[];
    blockedIps: XdpBlockedEntry[];
    topFlowsCount: number;
  };
  bpfLsm: {
    attached: boolean;
    attachedHooks: string[];
    denialEventsCount: number;
    allowlist?: BpfLsmAllowlistEntry[];
    recentEvents?: BpfLsmEventEntry[];
  };
  bpfTokens: BpfTokenCapabilityReport;
  bpfInventory?: KernelBpfInventory;
  kernelRca?: KernelRcaTelemetry;
  virt: VirtDutyTelemetry;
  k3s: K3sDutyTelemetry;
  nas: ZfsDeepTelemetry;
  threatHarvester?: ThreatHarvesterOverviewSummary;
}

export const FORBIDDEN_RING0_PROG_TYPES = [
  'kprobe',
  'tracepoint',
  'perf_event',
  'raw_tracepoint',
  'raw_tracepoint_writable',
  'tracing',
  'struct_ops',
  'ext',
  'lsm',
  'syscall',
];

export const SAFE_DELEGATABLE_PROG_TYPES = [
  'xdp',
  'sched_cls',
  'sched_act',
  'socket_filter',
  'cgroup_skb',
  'cgroup_sock',
  'cgroup_sock_addr',
  'sk_skb',
  'sk_msg',
  'sock_ops',
];

const num = (v: unknown, fallback = 0): number => {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
};

const parseMajorMinor = (rel: string): [number, number, number] => {
  const m = String(rel || '').match(/^(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!m) return [0, 0, 0];
  return [Number(m[1]) || 0, Number(m[2]) || 0, Number(m[3]) || 0];
};

const normalizeNetdev = (raw: any, kindHint = 'netdev'): NetdevTrafficStat => ({
  name: String(raw?.name ?? raw?.device ?? ''),
  kind: String(raw?.kind ?? kindHint),
  operState: String(raw?.operState ?? 'unknown'),
  mtu: num(raw?.mtu, 0),
  rxBytes: num(raw?.rxBytes),
  txBytes: num(raw?.txBytes),
  rxPackets: num(raw?.rxPackets),
  txPackets: num(raw?.txPackets),
  rxDropped: num(raw?.rxDropped),
  txDropped: num(raw?.txDropped),
  xdpAttached: Boolean(raw?.xdpAttached ?? raw?.xdpProgAttached),
});

export function createEmptyKernelBpfInventory(errMsg?: string): KernelBpfInventory {
  return {
    timestamp: new Date().toISOString(),
    available: false,
    ...(errMsg ? { error: errMsg } : {}),
    statsEnabled: false,
    totalPrograms: 0,
    totalMaps: 0,
    totalJitedBytes: 0,
    totalProgMemlockBytes: 0,
    totalMapMemlockBytes: 0,
    programsByType: [],
    mapsByType: [],
    programs: [],
    maps: [],
  };
}

export function createEmptyKernelRca(): KernelRcaTelemetry {
  return {
    timestamp: new Date().toISOString(),
    tcp: {
      available: false,
      inSegs: 0,
      outSegs: 0,
      retransSegs: 0,
      retransmitRatioPct: 0,
      currEstab: 0,
      attemptFails: 0,
      estabResets: 0,
      inErrs: 0,
      outRsts: 0,
    },
    udp: {
      available: false,
      inDatagrams: 0,
      outDatagrams: 0,
      noPorts: 0,
      inErrors: 0,
      rcvbufErrors: 0,
      sndbufErrors: 0,
    },
    cgroupCpu: {
      available: false,
      nrPeriods: 0,
      nrThrottled: 0,
      throttledUsec: 0,
      throttleRatioPct: 0,
    },
    memory: {
      available: false,
      oomKillCount: 0,
      majorPageFaults: 0,
      allocStalls: 0,
      psiSomeAvg10: 0,
      psiFullAvg10: 0,
      psiAvailable: false,
    },
  };
}

/**
 * Normalizes both axonwalld's raw GET /v1/ebpf/overview payload and an
 * already-normalized EbpfOverviewTelemetry object into the unified UI shape.
 */
export function normalizeEbpfOverviewResponse(raw: any): EbpfOverviewTelemetry {
  const nowMs = Date.now();
  const dp = raw?.dataplane ?? {};
  const rawStats = dp?.xdpStats ?? dp?.stats ?? {};
  const rawFlows: any[] = Array.isArray(dp?.topFlows) ? dp.topFlows : [];

  const topFlows: XdpFlowEntry[] = rawFlows.map((f) => ({
    family: num(f?.family, 4),
    srcIp: String(f?.srcIp ?? ''),
    dstIp: String(f?.dstIp ?? ''),
    srcPort: num(f?.srcPort),
    dstPort: num(f?.dstPort),
    vlanId: num(f?.vlanId),
    protocol: num(f?.protocol),
    protoName: String(f?.protoName ?? ''),
    packets: num(f?.packets),
    bytes: num(f?.bytes),
    synPackets: num(f?.synPackets),
    rstPackets: num(f?.rstPackets),
    tcpFlags: typeof f?.tcpFlags === 'string' ? f.tcpFlags : undefined,
    ageMs: num(f?.ageMs),
  }));

  const rawBlocks: any[] = Array.isArray(dp?.blockedIps)
    ? dp.blockedIps
    : Array.isArray(dp?.activeBlocks)
      ? dp.activeBlocks
      : [];
  const blockedIps: XdpBlockedEntry[] = rawBlocks.map((b) => {
    let expiresInSeconds = num(b?.expiresInSeconds, -1);
    if (expiresInSeconds < 0 && typeof b?.expiresAt === 'string' && b.expiresAt) {
      const expMs = Date.parse(b.expiresAt);
      expiresInSeconds = Number.isFinite(expMs) ? Math.max(0, Math.round((expMs - nowMs) / 1000)) : 0;
    }
    const fam = b?.family === 'ipv6' || num(b?.family) === 6 ? 'ipv6' : 'ipv4';
    return {
      ip: String(b?.ip ?? ''),
      family: fam,
      isCidr: Boolean(b?.isCidr),
      expiresInSeconds: Math.max(0, expiresInSeconds),
      droppedPackets: num(b?.droppedPackets ?? b?.dropPackets),
      droppedBytes: num(b?.droppedBytes ?? b?.dropBytes),
      reason: typeof b?.reason === 'string' ? b.reason : undefined,
      reasonCode: b?.reasonCode != null ? num(b.reasonCode) : undefined,
      expiresAt: typeof b?.expiresAt === 'string' ? b.expiresAt : undefined,
    };
  });

  // LSM normalization (raw: raw.lsm, normalized: raw.bpfLsm)
  const rawLsm = raw?.bpfLsm ?? raw?.lsm ?? {};
  const recentEvents: BpfLsmEventEntry[] = Array.isArray(rawLsm?.recentEvents)
    ? rawLsm.recentEvents.map((ev: any) => ({
        timestamp: String(ev?.timestamp ?? ''),
        pid: num(ev?.pid),
        uid: num(ev?.uid),
        hookId: num(ev?.hookId),
        hook: String(ev?.hook ?? ''),
        blocked: Boolean(ev?.blocked),
        dev: num(ev?.dev),
        ino: num(ev?.ino),
        comm: String(ev?.comm ?? ''),
        detail: String(ev?.detail ?? ''),
        mitreTechnique: String(ev?.mitreTechnique ?? ''),
      }))
    : [];
  const denialEventsCount =
    rawLsm?.denialEventsCount != null
      ? num(rawLsm.denialEventsCount)
      : recentEvents.filter((e) => e.blocked).length;

  // BPF_TOKEN normalization (raw: raw.bpfTokens.{capabilities,presets,profiles,activeMounts})
  const rawTok = raw?.bpfTokens ?? {};
  const caps = rawTok?.capabilities ?? rawTok;
  const kernelRelease = String(caps?.kernelRelease ?? '6.12.0');
  const [parsedMaj, parsedMin, parsedPatch] = parseMajorMinor(kernelRelease);
  const major = num(caps?.kernelMajor ?? caps?.major, parsedMaj);
  const minor = num(caps?.kernelMinor ?? caps?.minor, parsedMin);
  const patch = num(caps?.patch, parsedPatch);
  const supportsBpfToken = Boolean(caps?.supported ?? caps?.supportsBpfToken ?? caps?.kernel69OrNewer);

  const activeMounts: Array<{ mountPoint?: string; delegateCmds?: string; delegateProgs?: string; hasDelegation?: boolean }> =
    Array.isArray(rawTok?.activeMounts) ? rawTok.activeMounts : [];
  const mountByPath = new Map(
    activeMounts.filter((m) => typeof m?.mountPoint === 'string').map((m) => [m.mountPoint!, m])
  );

  let activeProfiles: BpfTokenProfileStatus[] = [];
  if (Array.isArray(rawTok?.activeProfiles)) {
    activeProfiles = rawTok.activeProfiles;
  } else if (Array.isArray(rawTok?.profiles)) {
    activeProfiles = rawTok.profiles.map((p: any) => {
      const mountPath = String(p?.bpffsMountPath ?? p?.mountPath ?? '');
      const mInfo = mountByPath.get(mountPath);
      return {
        name: String(p?.id ?? p?.name ?? ''),
        mountPath,
        preset: (p?.preset || 'network-dataplane') as BpfTokenProfileStatus['preset'],
        delegateCmds: String(p?.delegateCmds ?? ''),
        delegateProgs: String(p?.delegateProgs ?? ''),
        delegateMaps: String(p?.delegateMaps ?? ''),
        delegateAttachs: String(p?.delegateAttachs ?? ''),
        mounted: Boolean(mInfo?.hasDelegation ?? mInfo ?? p?.mounted ?? p?.enabled),
        mountOptions: p?.mountPreviewCmd ? String(p.mountPreviewCmd) : undefined,
        ring0IsolationVerified: Boolean(rawLsm?.attached ?? true),
        workloadTarget: p?.targetRef ? String(p.targetRef) : p?.workloadTarget ? String(p.workloadTarget) : undefined,
        targetKind: p?.targetKind ? String(p.targetKind) : undefined,
        cmdsMaskHex: p?.cmdsMaskHex ? String(p.cmdsMaskHex) : undefined,
        progsMaskHex: p?.progsMaskHex ? String(p.progsMaskHex) : undefined,
      };
    });
  }

  const presetsRecord: BpfTokenCapabilityReport['presets'] = {};
  if (Array.isArray(rawTok?.presets)) {
    for (const pr of rawTok.presets) {
      if (pr?.id) {
        presetsRecord[String(pr.id)] = {
          name: pr.name ? String(pr.name) : undefined,
          summary: pr.summary ? String(pr.summary) : undefined,
          delegateCmds: String(pr.delegateCmds ?? ''),
          delegateProgs: String(pr.delegateProgs ?? ''),
          delegateMaps: String(pr.delegateMaps ?? ''),
          delegateAttachs: String(pr.delegateAttachs ?? ''),
          cmdsMaskHex: pr.cmdsMaskHex ? String(pr.cmdsMaskHex) : undefined,
          progsMaskHex: pr.progsMaskHex ? String(pr.progsMaskHex) : undefined,
          mapsMaskHex: pr.mapsMaskHex ? String(pr.mapsMaskHex) : undefined,
          attachsMaskHex: pr.attachsMaskHex ? String(pr.attachsMaskHex) : undefined,
        };
      }
    }
  } else if (rawTok?.presets && typeof rawTok.presets === 'object') {
    Object.assign(presetsRecord, rawTok.presets);
  }

  // Virt normalization
  const rawVirt = raw?.virt ?? {};
  const workloads: VirtWorkloadSummary[] = Array.isArray(rawVirt?.workloads)
    ? rawVirt.workloads.map((w: any) => ({
        kind: String(w?.kind ?? 'vm'),
        id: num(w?.id),
        name: String(w?.name ?? ''),
        status: String(w?.status ?? 'unknown'),
        pid: num(w?.pid),
        bpfTokenEnabled: Boolean(w?.bpfTokenEnabled),
        bpfTokenProfileId: w?.bpfTokenProfileId ? String(w.bpfTokenProfileId) : undefined,
        bpfTokenPreset: w?.bpfTokenPreset ? String(w.bpfTokenPreset) : undefined,
        netdevs: Array.isArray(w?.netdevs) ? w.netdevs.map((nd: any) => normalizeNetdev(nd, String(w?.kind ?? 'virt'))) : [],
      }))
    : [];
  const bridgeStats: NetdevTrafficStat[] = Array.isArray(rawVirt?.bridgeStats)
    ? rawVirt.bridgeStats.map((b: any) => normalizeNetdev(b, 'bridge'))
    : [];
  const flatVirtIfaces: NetdevTrafficStat[] = Array.isArray(rawVirt?.vnetInterfaces)
    ? rawVirt.vnetInterfaces.map((n: any) => normalizeNetdev(n, 'virt'))
    : [
        ...workloads.flatMap((w) =>
          w.netdevs.map((nd) => ({ ...nd, kind: w.kind === 'lxc' ? `lxc:${w.name}` : `vm:${w.name}` }))
        ),
        ...bridgeStats,
      ];

  // K3s normalization
  const rawK3s = raw?.k3s ?? {};
  const k3sCluster = rawK3s?.cluster ?? rawK3s;
  const k3sCni: NetdevTrafficStat[] = Array.isArray(rawK3s?.cniInterfaces)
    ? rawK3s.cniInterfaces.map((c: any) => normalizeNetdev(c, 'cni'))
    : [];
  const mappedVolumes = Array.isArray(k3sCluster?.volumes)
    ? k3sCluster.volumes.map((v: any) => String(v?.dataset ?? v?.name ?? '')).filter(Boolean)
    : [];
  const openEbsDatasets: string[] = Array.isArray(rawK3s?.openEbsDatasets)
    ? rawK3s.openEbsDatasets
    : mappedVolumes.length > 0
      ? mappedVolumes
      : k3sCluster?.zfsLocalPvPool
        ? [String(k3sCluster.zfsLocalPvPool)]
        : [];

  // NAS / OpenZFS normalization
  const rawNas = raw?.nas ?? {};
  const rawArc = rawNas?.arc ?? {};
  const rawZil = rawNas?.zil ?? {};
  const rawPoolIo: NasPoolIoStat[] = Array.isArray(rawNas?.poolIoStats)
    ? rawNas.poolIoStats.map((p: any) => ({
        pool: String(p?.pool ?? ''),
        nreadBytes: num(p?.nreadBytes),
        nwrittenBytes: num(p?.nwrittenBytes),
        reads: num(p?.reads),
        writes: num(p?.writes),
        waitQueueDepth: num(p?.waitQueueDepth),
        activeQueueDepth: num(p?.activeQueueDepth),
      }))
    : [];
  const rawPools = Array.isArray(rawNas?.pools) ? rawNas.pools : [];
  const zfsModuleLoaded = Boolean(
    rawNas?.zfsModuleLoaded ?? (rawArc?.available || rawZil?.available || rawPools.length > 0 || rawPoolIo.length > 0)
  );

  // BPF Kernel Inventory & Kernel RCA
  const bpfInventory: KernelBpfInventory = raw?.bpfInventory
    ? {
        timestamp: String(raw.bpfInventory.timestamp ?? new Date().toISOString()),
        available: Boolean(raw.bpfInventory.available),
        error: raw.bpfInventory.error ? String(raw.bpfInventory.error) : undefined,
        statsEnabled: Boolean(raw.bpfInventory.statsEnabled),
        totalPrograms: num(raw.bpfInventory.totalPrograms),
        totalMaps: num(raw.bpfInventory.totalMaps),
        totalJitedBytes: num(raw.bpfInventory.totalJitedBytes),
        totalProgMemlockBytes: num(raw.bpfInventory.totalProgMemlockBytes),
        totalMapMemlockBytes: num(raw.bpfInventory.totalMapMemlockBytes),
        programsByType: Array.isArray(raw.bpfInventory.programsByType) ? raw.bpfInventory.programsByType : [],
        mapsByType: Array.isArray(raw.bpfInventory.mapsByType) ? raw.bpfInventory.mapsByType : [],
        programs: Array.isArray(raw.bpfInventory.programs) ? raw.bpfInventory.programs : [],
        maps: Array.isArray(raw.bpfInventory.maps) ? raw.bpfInventory.maps : [],
      }
    : createEmptyKernelBpfInventory();

  const kernelRca: KernelRcaTelemetry = raw?.kernelRca
    ? {
        timestamp: String(raw.kernelRca.timestamp ?? new Date().toISOString()),
        tcp: { ...createEmptyKernelRca().tcp, ...(raw.kernelRca.tcp ?? {}) },
        udp: { ...createEmptyKernelRca().udp, ...(raw.kernelRca.udp ?? {}) },
        cgroupCpu: { ...createEmptyKernelRca().cgroupCpu, ...(raw.kernelRca.cgroupCpu ?? {}) },
        memory: { ...createEmptyKernelRca().memory, ...(raw.kernelRca.memory ?? {}) },
      }
    : createEmptyKernelRca();

  return {
    daemonDown: Boolean(raw?.daemonDown),
    dataplane: {
      running: Boolean(dp?.running ?? (Array.isArray(dp?.attachedInterfaces) && dp.attachedInterfaces.length > 0)),
      attachedInterfaces: Array.isArray(dp?.attachedInterfaces) ? dp.attachedInterfaces.map(String) : [],
      dualStackEnabled: dp?.dualStackEnabled ?? true,
      vlanPeelingEnabled: dp?.vlanPeelingEnabled ?? true,
      synFloodLimitPps: dp?.synFloodLimitPps != null ? num(dp.synFloodLimitPps) : undefined,
      xdpStats: {
        rxPackets: num(rawStats?.rxPackets),
        rxBytes: num(rawStats?.rxBytes),
        ipv4Packets: num(rawStats?.ipv4Packets),
        ipv6Packets: num(rawStats?.ipv6Packets),
        vlanTaggedPackets: num(rawStats?.vlanTaggedPackets ?? rawStats?.vlanPackets),
        xdpDropPackets: num(rawStats?.xdpDropPackets ?? rawStats?.xdpDrop),
        xdpDropBytes: num(rawStats?.xdpDropBytes),
        xdpPassPackets: num(rawStats?.xdpPassPackets ?? rawStats?.xdpPass),
        tcpSynPackets: num(rawStats?.tcpSynPackets),
        lpmCidrDrops: num(rawStats?.lpmCidrDrops),
        synFloodDrops: num(rawStats?.synFloodDrops),
      },
      perCpuStats: Array.isArray(dp?.perCpuStats) ? dp.perCpuStats : [],
      totalFlowCount: dp?.totalFlowCount != null ? num(dp.totalFlowCount) : topFlows.length,
      totalFlowCountV4: num(dp?.totalFlowCountV4),
      totalFlowCountV6: num(dp?.totalFlowCountV6),
      protocolBreakdown: Array.isArray(dp?.protocolBreakdown) ? dp.protocolBreakdown : [],
      topPorts: Array.isArray(dp?.topPorts) ? dp.topPorts : [],
      vlanBreakdown: Array.isArray(dp?.vlanBreakdown) ? dp.vlanBreakdown : [],
      synRateMeters: Array.isArray(dp?.synRateMeters) ? dp.synRateMeters : [],
      topFlows,
      blockedIps,
      topFlowsCount: dp?.topFlowsCount != null ? num(dp.topFlowsCount) : num(dp?.totalFlowCount, topFlows.length),
    },
    bpfLsm: {
      attached: Boolean(rawLsm?.attached),
      attachedHooks: Array.isArray(rawLsm?.attachedHooks) ? rawLsm.attachedHooks.map(String) : [],
      denialEventsCount,
      allowlist: Array.isArray(rawLsm?.allowlist) ? rawLsm.allowlist : [],
      recentEvents,
    },
    bpfTokens: {
      kernelRelease,
      major,
      minor,
      patch,
      supportsBpfToken,
      supportsUserNsBpf: Boolean(caps?.supportsUserNsBpf ?? caps?.userNsCloneAllowed ?? supportsBpfToken),
      bpffsRootMounted: Boolean(rawTok?.bpffsRootMounted ?? activeMounts.length > 0),
      unprivilegedBpfSysctl: String(caps?.unprivilegedBpfSysctl ?? caps?.unprivilegedBpfDisabled ?? ''),
      bpfLsmActive: Boolean(rawTok?.bpfLsmActive ?? rawLsm?.attached),
      btfHasBpfToken: caps?.btfHasBpfToken != null ? Boolean(caps.btfHasBpfToken) : undefined,
      btfHasLsmTokenCreate: caps?.btfHasLsmTokenCreate != null ? Boolean(caps.btfHasLsmTokenCreate) : undefined,
      btfHasLsmTokenCmd: caps?.btfHasLsmTokenCmd != null ? Boolean(caps.btfHasLsmTokenCmd) : undefined,
      forbiddenRing0ProgTypes: Array.isArray(rawTok?.forbiddenRing0ProgTypes)
        ? rawTok.forbiddenRing0ProgTypes.map(String)
        : FORBIDDEN_RING0_PROG_TYPES,
      activeProfiles,
      presets: presetsRecord,
    },
    bpfInventory,
    kernelRca,
    virt: {
      timestamp: String(rawVirt?.timestamp ?? new Date().toISOString()),
      kvmAvailable: Boolean(rawVirt?.kvmAvailable ?? workloads.some((w) => w.kind === 'vm')),
      iommuGroupsCount: num(rawVirt?.iommuGroupsCount ?? rawVirt?.iommuGroups),
      lxcInstalled: Boolean(rawVirt?.lxcInstalled ?? workloads.some((w) => w.kind === 'lxc')),
      qemuInstalled: Boolean(rawVirt?.qemuInstalled ?? workloads.some((w) => w.kind === 'vm')),
      vnetInterfaces: flatVirtIfaces,
      workloads,
      bridgeStats,
      runningQemuCount:
        rawVirt?.runningQemuCount != null
          ? num(rawVirt.runningQemuCount)
          : workloads.filter((w) => w.kind === 'vm' && w.status === 'running').length,
      runningLxcCount:
        rawVirt?.runningLxcCount != null
          ? num(rawVirt.runningLxcCount)
          : workloads.filter((w) => w.kind === 'lxc' && w.status === 'running').length,
      unprivilegedLxcTokenMounts: Array.isArray(rawVirt?.unprivilegedLxcTokenMounts)
        ? rawVirt.unprivilegedLxcTokenMounts
        : workloads.filter((w) => w.kind === 'lxc' && w.bpfTokenEnabled).map((w) => `${w.name}:${w.bpfTokenPreset || 'token'}`),
    },
    k3s: {
      timestamp: String(rawK3s?.timestamp ?? new Date().toISOString()),
      serviceActive: Boolean(k3sCluster?.serviceActive ?? k3sCluster?.running),
      binaryPresent: Boolean(rawK3s?.binaryPresent ?? k3sCluster?.enabled ?? k3sCluster?.serviceActive),
      userNamespacesSupported: Boolean(rawK3s?.userNamespacesSupported ?? (caps?.userNsCloneAllowed && supportsBpfToken)),
      cniInterfaces: k3sCni,
      kubepodsCgroupV2: Boolean(rawK3s?.kubepodsCgroupV2 ?? kernelRca.cgroupCpu.available),
      bpfTokenReady: Boolean(rawK3s?.bpfTokenReady ?? (supportsBpfToken && caps?.btfHasBpfToken !== false)),
      openEbsDatasets,
    },
    nas: {
      timestamp: String(rawNas?.timestamp ?? new Date().toISOString()),
      zfsModuleLoaded,
      arc: {
        sizeBytes: num(rawArc?.sizeBytes),
        maxSizeBytes: num(rawArc?.maxSizeBytes ?? rawArc?.targetMaxBytes),
        minSizeBytes: num(rawArc?.minSizeBytes),
        hits: num(rawArc?.hits),
        misses: num(rawArc?.misses),
        hitRatioPct: num(rawArc?.hitRatioPct),
        demandDataHits: num(rawArc?.demandDataHits),
        demandDataMisses: num(rawArc?.demandDataMisses),
        l2Hits: num(rawArc?.l2Hits),
        l2Misses: num(rawArc?.l2Misses),
        l2SizeBytes: num(rawArc?.l2SizeBytes),
        memoryThrottleCount: num(rawArc?.memoryThrottleCount),
      },
      zil: {
        zilCommitCount: num(rawZil?.zilCommitCount ?? rawZil?.commitCount),
        zilCommitWriterCount: num(rawZil?.zilCommitWriterCount ?? rawZil?.commitWriterCount),
        itxCount: num(rawZil?.itxCount),
        itxIndirectBytes: num(rawZil?.itxIndirectBytes),
        itxCopiedBytes: num(rawZil?.itxCopiedBytes),
        itxNeedcopyBytes: num(rawZil?.itxNeedcopyBytes),
        slogBytesWritten: num(rawZil?.slogBytesWritten),
        itxMetaslabNormalCount: num(rawZil?.itxMetaslabNormalCount),
        itxMetaslabSlogCount: num(rawZil?.itxMetaslabSlogCount),
      },
      pools: rawPools,
      poolIoStats: rawPoolIo,
    },
    ...(raw?.threatHarvester ? { threatHarvester: raw.threatHarvester } : {}),
  };
}

export interface DataplaneRateSample {
  time: string;
  rxPps: number;
  passPps: number;
  dropPps: number;
  synPps: number;
  synFloodDropPps: number;
  lpmDropPps: number;
  v4Pps: number;
  v6Pps: number;
  rxMbps: number;
}

export function computeDataplaneRatePoint(
  prev: XdpVerdictStats | null,
  next: XdpVerdictStats,
  elapsedSec: number,
  label: string
): DataplaneRateSample {
  const dt = elapsedSec > 0.1 ? elapsedSec : 0;
  if (!prev || dt <= 0) {
    return {
      time: label,
      rxPps: 0,
      passPps: 0,
      dropPps: 0,
      synPps: 0,
      synFloodDropPps: 0,
      lpmDropPps: 0,
      v4Pps: 0,
      v6Pps: 0,
      rxMbps: 0,
    };
  }
  const rate = (a: number | undefined, b: number | undefined): number => {
    const na = num(a);
    const nb = num(b);
    if (nb < na) return 0; // Guard against counter reset
    return Math.round((nb - na) / dt);
  };
  const byteDelta = next.rxBytes >= prev.rxBytes ? next.rxBytes - prev.rxBytes : 0;
  const rxMbps = Math.round(((byteDelta * 8) / dt / 1_000_000) * 1000) / 1000;

  return {
    time: label,
    rxPps: rate(prev.rxPackets, next.rxPackets),
    passPps: rate(prev.xdpPassPackets, next.xdpPassPackets),
    dropPps: rate(prev.xdpDropPackets, next.xdpDropPackets),
    synPps: rate(prev.tcpSynPackets, next.tcpSynPackets),
    synFloodDropPps: rate(prev.synFloodDrops, next.synFloodDrops),
    lpmDropPps: rate(prev.lpmCidrDrops, next.lpmCidrDrops),
    v4Pps: rate(prev.ipv4Packets, next.ipv4Packets),
    v6Pps: rate(prev.ipv6Packets, next.ipv6Packets),
    rxMbps,
  };
}

export interface FlowGraphNode {
  id: string;
  tier: 'src' | 'hub' | 'dst';
  label: string;
  sublabel: string;
  bytes: number;
  packets: number;
  isBlocked: boolean;
  isAnomaly: boolean;
  ip?: string;
  vlanId?: number;
  protoName?: string;
  port?: number;
}

export interface FlowGraphEdge {
  id: string;
  from: string;
  to: string;
  bytes: number;
  packets: number;
  synPackets: number;
  rstPackets: number;
  protoName: string;
  isBlocked: boolean;
  isSynHeavy: boolean;
  isRstHeavy: boolean;
  flows: XdpFlowEntry[];
}

export interface FlowTopologyGraph {
  sources: FlowGraphNode[];
  hubs: FlowGraphNode[];
  destinations: FlowGraphNode[];
  edges: FlowGraphEdge[];
  totalMatchedFlows: number;
}

export function buildFlowTopologyGraph(
  flows: XdpFlowEntry[],
  blockedIps: XdpBlockedEntry[],
  options: {
    protocolFilter?: string;
    familyFilter?: 'all' | '4' | '6';
    anomalyOnly?: boolean;
    search?: string;
    maxFlows?: number;
  } = {}
): FlowTopologyGraph {
  const blockedSet = new Set(blockedIps.map((b) => b.ip));
  const protoF = (options.protocolFilter || 'all').toUpperCase();
  const famF = options.familyFilter || 'all';
  const searchF = (options.search || '').trim().toLowerCase();
  const anomalyOnly = Boolean(options.anomalyOnly);
  const maxFlows = options.maxFlows ?? 36;

  const isFlowSynHeavy = (f: XdpFlowEntry) =>
    f.synPackets >= 5 && f.packets > 0 && f.synPackets / f.packets >= 0.45;
  const isFlowRstHeavy = (f: XdpFlowEntry) =>
    f.rstPackets >= 3 && f.packets > 0 && f.rstPackets / f.packets >= 0.25;

  const filtered = flows.filter((f) => {
    if (protoF !== 'ALL' && f.protoName.toUpperCase() !== protoF) return false;
    if (famF !== 'all' && String(f.family) !== famF) return false;
    const blocked = blockedSet.has(f.srcIp) || blockedSet.has(f.dstIp);
    const anomaly = blocked || isFlowSynHeavy(f) || isFlowRstHeavy(f);
    if (anomalyOnly && !anomaly) return false;
    if (searchF) {
      const hay = `${f.srcIp}:${f.srcPort} ${f.dstIp}:${f.dstPort} ${f.protoName} vlan:${f.vlanId}`.toLowerCase();
      if (!hay.includes(searchF)) return false;
    }
    return true;
  });

  const sorted = [...filtered].sort((a, b) => b.bytes - a.bytes || b.packets - a.packets);
  const slice = sorted.slice(0, maxFlows);

  const srcMap = new Map<string, FlowGraphNode>();
  const hubMap = new Map<string, FlowGraphNode>();
  const dstMap = new Map<string, FlowGraphNode>();
  const edgeMap = new Map<string, FlowGraphEdge>();

  const upsertEdge = (from: string, to: string, f: XdpFlowEntry, blocked: boolean, synH: boolean, rstH: boolean) => {
    const key = `${from}=>${to}`;
    const existing = edgeMap.get(key);
    if (existing) {
      existing.bytes += f.bytes;
      existing.packets += f.packets;
      existing.synPackets += f.synPackets;
      existing.rstPackets += f.rstPackets;
      existing.isBlocked = existing.isBlocked || blocked;
      existing.isSynHeavy = existing.isSynHeavy || synH;
      existing.isRstHeavy = existing.isRstHeavy || rstH;
      existing.flows.push(f);
    } else {
      edgeMap.set(key, {
        id: key,
        from,
        to,
        bytes: f.bytes,
        packets: f.packets,
        synPackets: f.synPackets,
        rstPackets: f.rstPackets,
        protoName: f.protoName || 'OTHER',
        isBlocked: blocked,
        isSynHeavy: synH,
        isRstHeavy: rstH,
        flows: [f],
      });
    }
  };

  for (const f of slice) {
    const srcId = `src:${f.srcIp}`;
    const portLabel = f.dstPort > 0 ? `${f.protoName || 'L4'}:${f.dstPort}` : f.protoName || `PROTO:${f.protocol}`;
    const vlanSuffix = f.vlanId > 0 ? `•v${f.vlanId}` : '';
    const hubId = `hub:${portLabel}${vlanSuffix}`;
    const dstId = `dst:${f.dstIp}`;

    const srcBlocked = blockedSet.has(f.srcIp);
    const dstBlocked = blockedSet.has(f.dstIp);
    const synH = isFlowSynHeavy(f);
    const rstH = isFlowRstHeavy(f);
    const flowAnomaly = srcBlocked || dstBlocked || synH || rstH;

    const sNode = srcMap.get(srcId);
    if (sNode) {
      sNode.bytes += f.bytes;
      sNode.packets += f.packets;
      sNode.isBlocked = sNode.isBlocked || srcBlocked;
      sNode.isAnomaly = sNode.isAnomaly || flowAnomaly;
    } else {
      srcMap.set(srcId, {
        id: srcId,
        tier: 'src',
        label: f.srcIp,
        sublabel: `IPv${f.family}${srcBlocked ? ' • XDP_DROP' : ''}`,
        bytes: f.bytes,
        packets: f.packets,
        isBlocked: srcBlocked,
        isAnomaly: flowAnomaly,
        ip: f.srcIp,
      });
    }

    const hNode = hubMap.get(hubId);
    if (hNode) {
      hNode.bytes += f.bytes;
      hNode.packets += f.packets;
      hNode.isBlocked = hNode.isBlocked || srcBlocked || dstBlocked;
      hNode.isAnomaly = hNode.isAnomaly || flowAnomaly;
    } else {
      hubMap.set(hubId, {
        id: hubId,
        tier: 'hub',
        label: portLabel,
        sublabel: f.vlanId > 0 ? `VLAN ${f.vlanId}` : 'Untagged',
        bytes: f.bytes,
        packets: f.packets,
        isBlocked: srcBlocked || dstBlocked,
        isAnomaly: flowAnomaly,
        vlanId: f.vlanId,
        protoName: f.protoName,
        port: f.dstPort,
      });
    }

    const dNode = dstMap.get(dstId);
    if (dNode) {
      dNode.bytes += f.bytes;
      dNode.packets += f.packets;
      dNode.isBlocked = dNode.isBlocked || dstBlocked;
      dNode.isAnomaly = dNode.isAnomaly || flowAnomaly;
    } else {
      dstMap.set(dstId, {
        id: dstId,
        tier: 'dst',
        label: f.dstIp,
        sublabel: `IPv${f.family}${dstBlocked ? ' • XDP_DROP' : ''}`,
        bytes: f.bytes,
        packets: f.packets,
        isBlocked: dstBlocked,
        isAnomaly: flowAnomaly,
        ip: f.dstIp,
      });
    }

    upsertEdge(srcId, hubId, f, srcBlocked, synH, rstH);
    upsertEdge(hubId, dstId, f, dstBlocked, synH, rstH);
  }

  const byBytes = (a: FlowGraphNode, b: FlowGraphNode) => b.bytes - a.bytes || b.packets - a.packets;
  return {
    sources: Array.from(srcMap.values()).sort(byBytes).slice(0, 10),
    hubs: Array.from(hubMap.values()).sort(byBytes).slice(0, 10),
    destinations: Array.from(dstMap.values()).sort(byBytes).slice(0, 10),
    edges: Array.from(edgeMap.values()),
    totalMatchedFlows: filtered.length,
  };
}

export interface SketchWaveformPoint {
  idx: number;
  label: string;
  signedBytes: number;
  absBytes: number;
  direction: 'egress' | 'ingress';
  iatUs: number;
  iatMs: number;
}

export function buildSketchWaveformData(pktSizes: number[] = [], iatUs: number[] = []): SketchWaveformPoint[] {
  const len = Math.max(pktSizes.length, iatUs.length);
  const points: SketchWaveformPoint[] = [];
  for (let i = 0; i < len; i++) {
    const signed = num(pktSizes[i], 0);
    const iat = Math.max(0, num(iatUs[i], 0));
    if (i > 0 && signed === 0 && iat === 0) {
      // Skip trailing zero padding once packets stop
      const hasMoreNonZero =
        pktSizes.slice(i + 1).some((v) => v !== 0) || iatUs.slice(i + 1).some((v) => v !== 0);
      if (!hasMoreNonZero) break;
    }
    points.push({
      idx: i + 1,
      label: `P${i + 1}`,
      signedBytes: signed,
      absBytes: Math.abs(signed),
      direction: signed < 0 ? 'ingress' : 'egress',
      iatUs: iat,
      iatMs: Math.round((iat / 1000) * 100) / 100,
    });
  }
  return points;
}

export function formatBytesCompact(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let val = bytes;
  let idx = 0;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  return `${val >= 100 || idx === 0 ? val.toFixed(0) : val.toFixed(1)} ${units[idx]}`;
}

export function formatPps(pps: number): string {
  if (!Number.isFinite(pps) || pps <= 0) return '0 pps';
  if (pps >= 1_000_000) return `${(pps / 1_000_000).toFixed(2)} Mpps`;
  if (pps >= 1_000) return `${(pps / 1_000).toFixed(1)} kpps`;
  return `${Math.round(pps)} pps`;
}

export function formatDurationNs(ns: number): string {
  if (!Number.isFinite(ns) || ns <= 0) return '0 ns';
  if (ns >= 1_000_000_000) return `${(ns / 1_000_000_000).toFixed(2)} s`;
  if (ns >= 1_000_000) return `${(ns / 1_000_000).toFixed(2)} ms`;
  if (ns >= 1_000) return `${(ns / 1_000).toFixed(1)} µs`;
  return `${Math.round(ns)} ns`;
}
