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
  mapIds: number[];
  hasBtf: boolean;
  createdByUid: number;
  runCount: number;
  runTimeNs: number;
  recursionMisses: number;
}

export interface BpfLinkInventoryItem {
  id: number;
  type: string;
  programId: number;
  attachDetail?: string;
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
  totalLinks: number;
  totalJitedBytes: number;
  totalProgMemlockBytes: number;
  totalMapMemlockBytes: number;
  programsByType: BpfTypeAggregate[];
  mapsByType: BpfTypeAggregate[];
  programs: BpfProgramInventoryItem[];
  maps: BpfMapInventoryItem[];
  links: BpfLinkInventoryItem[];
}

export interface SoftnetCpuStat {
  cpu: number;
  processed: number;
  dropped: number;
  timeSqueeze: number;
  cpuCollision: number;
  receivedRps: number;
  flowLimitCount: number;
}

export interface KernelSoftnetTelemetry {
  timestamp: string;
  available: boolean;
  cpuCount: number;
  totalProcessed: number;
  totalDropped: number;
  totalTimeSqueeze: number;
  totalCpuCollision: number;
  totalReceivedRps: number;
  totalFlowLimitCount: number;
  perCpu: SoftnetCpuStat[];
}

export const LINUX_TCP_STATE_ORDER = [
  'LISTEN',
  'SYN_SENT',
  'SYN_RECV',
  'ESTABLISHED',
  'FIN_WAIT1',
  'FIN_WAIT2',
  'CLOSE_WAIT',
  'LAST_ACK',
  'TIME_WAIT',
  'CLOSING',
  'CLOSE',
] as const;

export interface KernelListeningPort {
  protocol: string;
  port: number;
  service: string;
  ipv4Sockets: number;
  ipv6Sockets: number;
  totalCount: number;
}

export interface KernelSocketTelemetry {
  timestamp: string;
  available: boolean;
  totalTcpSockets: number;
  ipv4TcpSockets: number;
  ipv6TcpSockets: number;
  totalUdpSockets: number;
  ipv4UdpSockets: number;
  ipv6UdpSockets: number;
  tcpStates: Record<string, number>;
  listeningPorts: KernelListeningPort[];
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
  softnet?: KernelSoftnetTelemetry;
  sockets?: KernelSocketTelemetry;
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
    totalLinks: 0,
    totalJitedBytes: 0,
    totalProgMemlockBytes: 0,
    totalMapMemlockBytes: 0,
    programsByType: [],
    mapsByType: [],
    programs: [],
    maps: [],
    links: [],
  };
}

export function createEmptySoftnetTelemetry(): KernelSoftnetTelemetry {
  return {
    timestamp: new Date().toISOString(),
    available: false,
    cpuCount: 0,
    totalProcessed: 0,
    totalDropped: 0,
    totalTimeSqueeze: 0,
    totalCpuCollision: 0,
    totalReceivedRps: 0,
    totalFlowLimitCount: 0,
    perCpu: [],
  };
}

export function createEmptyKernelSocketTelemetry(): KernelSocketTelemetry {
  const tcpStates: Record<string, number> = {};
  for (const st of LINUX_TCP_STATE_ORDER) {
    tcpStates[st] = 0;
  }
  return {
    timestamp: new Date().toISOString(),
    available: false,
    totalTcpSockets: 0,
    ipv4TcpSockets: 0,
    ipv6TcpSockets: 0,
    totalUdpSockets: 0,
    ipv4UdpSockets: 0,
    ipv6UdpSockets: 0,
    tcpStates,
    listeningPorts: [],
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
  const rawInvLinks: BpfLinkInventoryItem[] = Array.isArray(raw?.bpfInventory?.links)
    ? raw.bpfInventory.links.map((lnk: any) => ({
        id: num(lnk?.id),
        type: String(lnk?.type ?? 'unknown'),
        programId: num(lnk?.programId),
        ...(lnk?.attachDetail ? { attachDetail: String(lnk.attachDetail) } : {}),
      }))
    : [];
  const rawInvProgs: BpfProgramInventoryItem[] = Array.isArray(raw?.bpfInventory?.programs)
    ? raw.bpfInventory.programs.map((p: any) => {
        const mapIds: number[] = Array.isArray(p?.mapIds)
          ? p.mapIds.map((id: unknown) => num(id)).filter((id: number) => id > 0)
          : [];
        return {
          id: num(p?.id),
          type: String(p?.type ?? ''),
          name: String(p?.name ?? ''),
          tag: String(p?.tag ?? ''),
          jitedBytes: num(p?.jitedBytes),
          translatedBytes: num(p?.translatedBytes),
          verifiedInsns: num(p?.verifiedInsns),
          memlockBytes: num(p?.memlockBytes),
          mapCount: p?.mapCount != null ? num(p.mapCount) : mapIds.length,
          mapIds,
          hasBtf: Boolean(p?.hasBtf),
          createdByUid: num(p?.createdByUid),
          runCount: num(p?.runCount),
          runTimeNs: num(p?.runTimeNs),
          recursionMisses: num(p?.recursionMisses),
        };
      })
    : [];
  const bpfInventory: KernelBpfInventory = raw?.bpfInventory
    ? {
        timestamp: String(raw.bpfInventory.timestamp ?? new Date().toISOString()),
        available: Boolean(raw.bpfInventory.available),
        error: raw.bpfInventory.error ? String(raw.bpfInventory.error) : undefined,
        statsEnabled: Boolean(raw.bpfInventory.statsEnabled),
        totalPrograms: num(raw.bpfInventory.totalPrograms, rawInvProgs.length),
        totalMaps: num(raw.bpfInventory.totalMaps),
        totalLinks: raw.bpfInventory.totalLinks != null ? num(raw.bpfInventory.totalLinks) : rawInvLinks.length,
        totalJitedBytes: num(raw.bpfInventory.totalJitedBytes),
        totalProgMemlockBytes: num(raw.bpfInventory.totalProgMemlockBytes),
        totalMapMemlockBytes: num(raw.bpfInventory.totalMapMemlockBytes),
        programsByType: Array.isArray(raw.bpfInventory.programsByType) ? raw.bpfInventory.programsByType : [],
        mapsByType: Array.isArray(raw.bpfInventory.mapsByType) ? raw.bpfInventory.mapsByType : [],
        programs: rawInvProgs,
        maps: Array.isArray(raw.bpfInventory.maps) ? raw.bpfInventory.maps : [],
        links: rawInvLinks,
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

  const rawSoft = raw?.softnet;
  const softnetPerCpu: SoftnetCpuStat[] = Array.isArray(rawSoft?.perCpu)
    ? rawSoft.perCpu
        .map((c: any) => ({
          cpu: num(c?.cpu),
          processed: num(c?.processed),
          dropped: num(c?.dropped),
          timeSqueeze: num(c?.timeSqueeze),
          cpuCollision: num(c?.cpuCollision),
          receivedRps: num(c?.receivedRps),
          flowLimitCount: num(c?.flowLimitCount),
        }))
        .sort((a: SoftnetCpuStat, b: SoftnetCpuStat) => a.cpu - b.cpu)
    : [];
  const softnet: KernelSoftnetTelemetry = rawSoft
    ? {
        timestamp: String(rawSoft.timestamp ?? new Date().toISOString()),
        available: Boolean(rawSoft.available ?? softnetPerCpu.length > 0),
        cpuCount: num(rawSoft.cpuCount, softnetPerCpu.length),
        totalProcessed: num(rawSoft.totalProcessed),
        totalDropped: num(rawSoft.totalDropped),
        totalTimeSqueeze: num(rawSoft.totalTimeSqueeze),
        totalCpuCollision: num(rawSoft.totalCpuCollision),
        totalReceivedRps: num(rawSoft.totalReceivedRps),
        totalFlowLimitCount: num(rawSoft.totalFlowLimitCount),
        perCpu: softnetPerCpu,
      }
    : createEmptySoftnetTelemetry();

  const rawSock = raw?.sockets;
  const normalizedTcpStates: Record<string, number> = { ...createEmptyKernelSocketTelemetry().tcpStates };
  if (rawSock?.tcpStates && typeof rawSock.tcpStates === 'object') {
    for (const [k, v] of Object.entries(rawSock.tcpStates)) {
      normalizedTcpStates[k] = num(v);
    }
  }
  const normalizedListeningPorts: KernelListeningPort[] = Array.isArray(rawSock?.listeningPorts)
    ? rawSock.listeningPorts.map((lp: any) => ({
        protocol: String(lp?.protocol ?? 'TCP').toUpperCase(),
        port: num(lp?.port),
        service: String(lp?.service ?? ''),
        ipv4Sockets: num(lp?.ipv4Sockets),
        ipv6Sockets: num(lp?.ipv6Sockets),
        totalCount: num(lp?.totalCount, num(lp?.ipv4Sockets) + num(lp?.ipv6Sockets)),
      }))
    : [];
  const sockets: KernelSocketTelemetry = rawSock
    ? {
        timestamp: String(rawSock.timestamp ?? new Date().toISOString()),
        available: Boolean(rawSock.available),
        totalTcpSockets: num(rawSock.totalTcpSockets),
        ipv4TcpSockets: num(rawSock.ipv4TcpSockets),
        ipv6TcpSockets: num(rawSock.ipv6TcpSockets),
        totalUdpSockets: num(rawSock.totalUdpSockets),
        ipv4UdpSockets: num(rawSock.ipv4UdpSockets),
        ipv6UdpSockets: num(rawSock.ipv6UdpSockets),
        tcpStates: normalizedTcpStates,
        listeningPorts: normalizedListeningPorts,
      }
    : createEmptyKernelSocketTelemetry();

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
    softnet,
    sockets,
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
  vlanPps: number;
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
      vlanPps: 0,
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
    vlanPps: rate(prev.vlanTaggedPackets, next.vlanTaggedPackets),
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

export interface XdpPipelineModel {
  mode: 'cumulative' | 'delta';
  rxTotal: number;
  vlanTagged: number;
  untagged: number;
  ipv4: number;
  ipv6: number;
  otherL3: number;
  xdpPass: number;
  xdpDrop: number;
  lpmCidrDrop: number;
  synFloodDrop: number;
  hostBlocklistDrop: number;
  tcpSyn: number;
  dropBytes: number;
  rxBytes: number;
}

export function buildXdpPipelineModel(
  stats: XdpVerdictStats | null | undefined,
  deltaSample?: DataplaneRateSample | null,
  mode: 'cumulative' | 'delta' = 'cumulative'
): XdpPipelineModel {
  if (mode === 'delta' && deltaSample) {
    const rxTotal = Math.max(0, num(deltaSample.rxPps));
    const vlanTagged = Math.min(rxTotal, Math.max(0, num(deltaSample.vlanPps)));
    const untagged = Math.max(0, rxTotal - vlanTagged);
    const ipv4 = Math.min(rxTotal, Math.max(0, num(deltaSample.v4Pps)));
    const ipv6 = Math.min(Math.max(0, rxTotal - ipv4), Math.max(0, num(deltaSample.v6Pps)));
    const otherL3 = Math.max(0, rxTotal - ipv4 - ipv6);
    const xdpPass = Math.max(0, num(deltaSample.passPps));
    const xdpDrop = Math.max(0, num(deltaSample.dropPps));
    const lpmCidrDrop = Math.min(xdpDrop, Math.max(0, num(deltaSample.lpmDropPps)));
    const synFloodDrop = Math.min(Math.max(0, xdpDrop - lpmCidrDrop), Math.max(0, num(deltaSample.synFloodDropPps)));
    const hostBlocklistDrop = Math.max(0, xdpDrop - lpmCidrDrop - synFloodDrop);

    return {
      mode: 'delta',
      rxTotal,
      vlanTagged,
      untagged,
      ipv4,
      ipv6,
      otherL3,
      xdpPass,
      xdpDrop,
      lpmCidrDrop,
      synFloodDrop,
      hostBlocklistDrop,
      tcpSyn: Math.max(0, num(deltaSample.synPps)),
      dropBytes: 0,
      rxBytes: Math.round((Math.max(0, num(deltaSample.rxMbps)) * 1_000_000) / 8),
    };
  }

  const rxTotal = Math.max(0, num(stats?.rxPackets));
  const vlanTagged = Math.min(rxTotal, Math.max(0, num(stats?.vlanTaggedPackets)));
  const untagged = Math.max(0, rxTotal - vlanTagged);
  const ipv4 = Math.min(rxTotal, Math.max(0, num(stats?.ipv4Packets)));
  const ipv6 = Math.min(Math.max(0, rxTotal - ipv4), Math.max(0, num(stats?.ipv6Packets)));
  const otherL3 = Math.max(0, rxTotal - ipv4 - ipv6);
  const xdpPass = Math.max(0, num(stats?.xdpPassPackets));
  const xdpDrop = Math.max(0, num(stats?.xdpDropPackets));
  const lpmCidrDrop = Math.min(xdpDrop, Math.max(0, num(stats?.lpmCidrDrops)));
  const synFloodDrop = Math.min(Math.max(0, xdpDrop - lpmCidrDrop), Math.max(0, num(stats?.synFloodDrops)));
  const hostBlocklistDrop = Math.max(0, xdpDrop - lpmCidrDrop - synFloodDrop);

  return {
    mode: 'cumulative',
    rxTotal,
    vlanTagged,
    untagged,
    ipv4,
    ipv6,
    otherL3,
    xdpPass,
    xdpDrop,
    lpmCidrDrop,
    synFloodDrop,
    hostBlocklistDrop,
    tcpSyn: Math.max(0, num(stats?.tcpSynPackets)),
    dropBytes: Math.max(0, num(stats?.xdpDropBytes)),
    rxBytes: Math.max(0, num(stats?.rxBytes)),
  };
}

export interface BpfProgramRuntimeDelta {
  id: number;
  name: string;
  type: string;
  runsPerSec: number;
  cpuUsPerSec: number;
  avgNsPerRun: number;
  totalRunTimeMs: number;
  totalRunCount: number;
  jitedBytes: number;
  recursionMisses: number;
  sharePct: number;
}

export function computeBpfProgramRuntimeDeltas(
  prevProgs: BpfProgramInventoryItem[],
  nextProgs: BpfProgramInventoryItem[],
  elapsedSec: number
): BpfProgramRuntimeDelta[] {
  const dt = elapsedSec > 0.1 ? elapsedSec : 0;
  const prevMap = new Map<number, BpfProgramInventoryItem>();
  for (const p of prevProgs) {
    prevMap.set(p.id, p);
  }

  let sumCpuUsPerSec = 0;
  let sumTotalRunTimeNs = 0;
  const rows = nextProgs.map((next) => {
    const prev = prevMap.get(next.id);
    const deltaRuns = dt > 0 && prev && next.runCount >= prev.runCount ? next.runCount - prev.runCount : 0;
    const deltaNs = dt > 0 && prev && next.runTimeNs >= prev.runTimeNs ? next.runTimeNs - prev.runTimeNs : 0;

    const runsPerSec = dt > 0 && prev ? Math.round((deltaRuns / dt) * 10) / 10 : 0;
    const cpuUsPerSec = dt > 0 && prev ? Math.round((deltaNs / 1000 / dt) * 100) / 100 : 0;
    const avgNsPerRun =
      deltaRuns > 0 && deltaNs >= 0
        ? Math.round((deltaNs / deltaRuns) * 10) / 10
        : next.runCount > 0
          ? Math.round((next.runTimeNs / next.runCount) * 10) / 10
          : 0;
    const totalRunTimeMs = Math.round((next.runTimeNs / 1_000_000) * 1000) / 1000;

    sumCpuUsPerSec += cpuUsPerSec;
    sumTotalRunTimeNs += Math.max(0, next.runTimeNs);

    return {
      id: next.id,
      name: next.name,
      type: next.type,
      runsPerSec,
      cpuUsPerSec,
      avgNsPerRun,
      totalRunTimeMs,
      totalRunCount: next.runCount,
      jitedBytes: next.jitedBytes,
      recursionMisses: next.recursionMisses,
      rawRunTimeNs: Math.max(0, next.runTimeNs),
      sharePct: 0,
    };
  });

  const useDeltaShare = sumCpuUsPerSec > 0;
  const enriched: BpfProgramRuntimeDelta[] = rows.map(({ rawRunTimeNs, ...r }) => ({
    ...r,
    sharePct: useDeltaShare
      ? Math.round((r.cpuUsPerSec / sumCpuUsPerSec) * 1000) / 10
      : sumTotalRunTimeNs > 0
        ? Math.round((rawRunTimeNs / sumTotalRunTimeNs) * 1000) / 10
        : 0,
  }));

  enriched.sort(
    (a, b) =>
      b.cpuUsPerSec - a.cpuUsPerSec ||
      b.totalRunTimeMs - a.totalRunTimeMs ||
      b.jitedBytes - a.jitedBytes ||
      a.id - b.id
  );
  return enriched;
}

export interface SoftnetCpuDelta {
  cpu: number;
  processedPerSec: number;
  droppedPerSec: number;
  timeSqueezePerSec: number;
  cpuCollisionPerSec: number;
  receivedRpsPerSec: number;
  flowLimitPerSec: number;
}

export function computeSoftnetDeltas(
  prev: KernelSoftnetTelemetry | null | undefined,
  next: KernelSoftnetTelemetry | null | undefined,
  elapsedSec: number
): SoftnetCpuDelta[] {
  if (!next || !next.available || next.perCpu.length === 0) {
    return [];
  }
  const dt = elapsedSec > 0.1 ? elapsedSec : 0;
  const prevByCpu = new Map<number, SoftnetCpuStat>();
  if (prev?.available) {
    for (const c of prev.perCpu) {
      prevByCpu.set(c.cpu, c);
    }
  }

  const rate = (a: number | undefined, b: number): number => {
    if (dt <= 0 || a == null || b < a) return 0;
    return Math.round(((b - a) / dt) * 10) / 10;
  };

  return next.perCpu
    .map((cur) => {
      const p = prevByCpu.get(cur.cpu);
      return {
        cpu: cur.cpu,
        processedPerSec: p ? rate(p.processed, cur.processed) : 0,
        droppedPerSec: p ? rate(p.dropped, cur.dropped) : 0,
        timeSqueezePerSec: p ? rate(p.timeSqueeze, cur.timeSqueeze) : 0,
        cpuCollisionPerSec: p ? rate(p.cpuCollision, cur.cpuCollision) : 0,
        receivedRpsPerSec: p ? rate(p.receivedRps, cur.receivedRps) : 0,
        flowLimitPerSec: p ? rate(p.flowLimitCount, cur.flowLimitCount) : 0,
      };
    })
    .sort((a, b) => a.cpu - b.cpu);
}

export interface BpfDependencyGraphScatterPoint {
  id: number;
  name: string;
  type: string;
  verifiedInsns: number;
  translatedBytes: number;
  jitedKiB: number;
  avgNsPerRun: number;
  runCount: number;
  mapCount: number;
}

export interface BpfDependencyGraph {
  links: BpfLinkInventoryItem[];
  programs: BpfProgramInventoryItem[];
  maps: BpfMapInventoryItem[];
  linkToProgEdges: Array<{ id: string; linkId: number; programId: number }>;
  progToMapEdges: Array<{ id: string; programId: number; mapId: number }>;
  totalProgramsMatched: number;
  totalMapsReferenced: number;
  availableTypes: string[];
  scatterPoints: BpfDependencyGraphScatterPoint[];
}

export function buildBpfDependencyGraph(
  inventory: KernelBpfInventory | undefined,
  opts: { typeFilter?: string; search?: string; maxPrograms?: number } = {}
): BpfDependencyGraph {
  const allProgs = inventory?.programs || [];
  const allMaps = inventory?.maps || [];
  const allLinks = inventory?.links || [];

  const availableTypes = Array.from(new Set(allProgs.map((p) => p.type).filter(Boolean))).sort();
  if (!inventory?.available || allProgs.length === 0) {
    return {
      links: [],
      programs: [],
      maps: [],
      linkToProgEdges: [],
      progToMapEdges: [],
      totalProgramsMatched: 0,
      totalMapsReferenced: 0,
      availableTypes,
      scatterPoints: [],
    };
  }

  const mapsById = new Map<number, BpfMapInventoryItem>();
  for (const m of allMaps) {
    mapsById.set(m.id, m);
  }

  const linksByProg = new Map<number, BpfLinkInventoryItem[]>();
  for (const l of allLinks) {
    const arr = linksByProg.get(l.programId);
    if (arr) arr.push(l);
    else linksByProg.set(l.programId, [l]);
  }

  const typeF = (opts.typeFilter || 'all').trim().toLowerCase();
  const q = (opts.search || '').trim().toLowerCase();
  const maxPrograms = Math.max(1, opts.maxPrograms ?? 14);

  const matched = allProgs.filter((p) => {
    if (typeF !== 'all' && p.type.toLowerCase() !== typeF) {
      return false;
    }
    if (!q) return true;

    if (
      p.name.toLowerCase().includes(q) ||
      p.type.toLowerCase().includes(q) ||
      p.tag.toLowerCase().includes(q) ||
      String(p.id).includes(q)
    ) {
      return true;
    }

    const pLinks = linksByProg.get(p.id) || [];
    if (
      pLinks.some(
        (l) =>
          l.type.toLowerCase().includes(q) ||
          (l.attachDetail || '').toLowerCase().includes(q) ||
          String(l.id).includes(q)
      )
    ) {
      return true;
    }

    return p.mapIds.some((mid) => {
      const m = mapsById.get(mid);
      if (!m) return String(mid).includes(q);
      return m.name.toLowerCase().includes(q) || m.type.toLowerCase().includes(q) || String(m.id).includes(q);
    });
  });

  const sortedMatched = [...matched].sort((a, b) => {
    const scoreA = (linksByProg.get(a.id)?.length || 0) * 4 + a.mapIds.length * 2 + (a.jitedBytes > 0 ? 1 : 0);
    const scoreB = (linksByProg.get(b.id)?.length || 0) * 4 + b.mapIds.length * 2 + (b.jitedBytes > 0 ? 1 : 0);
    return scoreB - scoreA || b.jitedBytes - a.jitedBytes || a.id - b.id;
  });

  const scatterPoints: BpfDependencyGraphScatterPoint[] = sortedMatched.map((p) => ({
    id: p.id,
    name: p.name,
    type: p.type,
    verifiedInsns: p.verifiedInsns,
    translatedBytes: p.translatedBytes,
    jitedKiB: Math.round((p.jitedBytes / 1024) * 100) / 100,
    avgNsPerRun: p.runCount > 0 ? Math.round((p.runTimeNs / p.runCount) * 10) / 10 : 0,
    runCount: p.runCount,
    mapCount: p.mapCount,
  }));

  const displayedProgs = sortedMatched.slice(0, maxPrograms);
  const displayedProgIds = new Set(displayedProgs.map((p) => p.id));

  const displayedLinks: BpfLinkInventoryItem[] = [];
  const linkToProgEdges: Array<{ id: string; linkId: number; programId: number }> = [];
  for (const l of allLinks) {
    if (displayedProgIds.has(l.programId)) {
      displayedLinks.push(l);
      linkToProgEdges.push({
        id: `link:${l.id}->prog:${l.programId}`,
        linkId: l.id,
        programId: l.programId,
      });
    }
  }

  const displayedMapIds = new Set<number>();
  const progToMapEdges: Array<{ id: string; programId: number; mapId: number }> = [];
  for (const p of displayedProgs) {
    for (const mid of p.mapIds) {
      if (mapsById.has(mid)) {
        displayedMapIds.add(mid);
        progToMapEdges.push({
          id: `prog:${p.id}->map:${mid}`,
          programId: p.id,
          mapId: mid,
        });
      }
    }
  }

  const displayedMaps = Array.from(displayedMapIds)
    .map((id) => mapsById.get(id)!)
    .sort((a, b) => b.memlockBytes - a.memlockBytes || a.id - b.id);

  return {
    links: displayedLinks,
    programs: displayedProgs,
    maps: displayedMaps,
    linkToProgEdges,
    progToMapEdges,
    totalProgramsMatched: matched.length,
    totalMapsReferenced: displayedMaps.length,
    availableTypes,
    scatterPoints,
  };
}

export interface FlowHeatmapCell {
  rowSrcIp: string;
  colKey: string;
  dstPort: number;
  protocol: number;
  protoName: string;
  bytes: number;
  packets: number;
  synPackets: number;
  rstPackets: number;
  synRatioPct: number;
  flowCount: number;
  isBlocked: boolean;
  flows: XdpFlowEntry[];
}

export interface FlowHeatmapMatrix {
  rows: Array<{ srcIp: string; totalBytes: number; totalPackets: number; isBlocked: boolean }>;
  cols: Array<{ colKey: string; dstPort: number; protocol: number; protoName: string; label: string; totalBytes: number }>;
  cells: Record<string, FlowHeatmapCell>;
  maxBytes: number;
  maxPackets: number;
  maxSyn: number;
}

export function buildFlowHeatmapMatrix(
  flows: XdpFlowEntry[],
  blockedIps: XdpBlockedEntry[],
  maxRows = 10,
  maxCols = 10
): FlowHeatmapMatrix {
  const blockedSet = new Set(blockedIps.map((b) => b.ip));
  const rowAgg = new Map<string, { srcIp: string; totalBytes: number; totalPackets: number; isBlocked: boolean }>();
  const colAgg = new Map<
    string,
    { colKey: string; dstPort: number; protocol: number; protoName: string; label: string; totalBytes: number }
  >();
  const rawCells = new Map<string, FlowHeatmapCell>();

  const makeColKey = (f: XdpFlowEntry): { key: string; label: string } => {
    const proto = (f.protoName || `PROTO${f.protocol}`).toUpperCase();
    if (f.dstPort > 0) {
      return { key: `${proto}:${f.dstPort}`, label: `${proto}:${f.dstPort}` };
    }
    return { key: `${proto}:0`, label: proto };
  };

  for (const f of flows) {
    if (!f.srcIp) continue;
    const isBlocked = blockedSet.has(f.srcIp) || blockedSet.has(f.dstIp);
    const r = rowAgg.get(f.srcIp);
    if (r) {
      r.totalBytes += f.bytes;
      r.totalPackets += f.packets;
      r.isBlocked = r.isBlocked || blockedSet.has(f.srcIp);
    } else {
      rowAgg.set(f.srcIp, {
        srcIp: f.srcIp,
        totalBytes: f.bytes,
        totalPackets: f.packets,
        isBlocked: blockedSet.has(f.srcIp),
      });
    }

    const colInfo = makeColKey(f);
    const c = colAgg.get(colInfo.key);
    if (c) {
      c.totalBytes += f.bytes;
    } else {
      colAgg.set(colInfo.key, {
        colKey: colInfo.key,
        dstPort: f.dstPort,
        protocol: f.protocol,
        protoName: f.protoName || `PROTO:${f.protocol}`,
        label: colInfo.label,
        totalBytes: f.bytes,
      });
    }

    const cellId = `${f.srcIp}|${colInfo.key}`;
    const existing = rawCells.get(cellId);
    if (existing) {
      existing.bytes += f.bytes;
      existing.packets += f.packets;
      existing.synPackets += f.synPackets;
      existing.rstPackets += f.rstPackets;
      existing.flowCount += 1;
      existing.isBlocked = existing.isBlocked || isBlocked;
      existing.flows.push(f);
    } else {
      rawCells.set(cellId, {
        rowSrcIp: f.srcIp,
        colKey: colInfo.key,
        dstPort: f.dstPort,
        protocol: f.protocol,
        protoName: f.protoName || `PROTO:${f.protocol}`,
        bytes: f.bytes,
        packets: f.packets,
        synPackets: f.synPackets,
        rstPackets: f.rstPackets,
        synRatioPct: 0,
        flowCount: 1,
        isBlocked,
        flows: [f],
      });
    }
  }

  const rows = Array.from(rowAgg.values())
    .sort((a, b) => b.totalBytes - a.totalBytes || b.totalPackets - a.totalPackets || a.srcIp.localeCompare(b.srcIp))
    .slice(0, Math.max(1, maxRows));
  const cols = Array.from(colAgg.values())
    .sort((a, b) => b.totalBytes - a.totalBytes || a.dstPort - b.dstPort || a.colKey.localeCompare(b.colKey))
    .slice(0, Math.max(1, maxCols));

  const rowSet = new Set(rows.map((r) => r.srcIp));
  const colSet = new Set(cols.map((c) => c.colKey));

  const cells: Record<string, FlowHeatmapCell> = {};
  let maxBytes = 0;
  let maxPackets = 0;
  let maxSyn = 0;

  for (const [cellId, cell] of rawCells.entries()) {
    if (!rowSet.has(cell.rowSrcIp) || !colSet.has(cell.colKey)) continue;
    const synRatioPct =
      cell.packets > 0 ? Math.round((cell.synPackets / cell.packets) * 1000) / 10 : 0;
    const enriched: FlowHeatmapCell = { ...cell, synRatioPct };
    cells[cellId] = enriched;
    if (enriched.bytes > maxBytes) maxBytes = enriched.bytes;
    if (enriched.packets > maxPackets) maxPackets = enriched.packets;
    if (enriched.synPackets > maxSyn) maxSyn = enriched.synPackets;
  }

  return { rows, cols, cells, maxBytes, maxPackets, maxSyn };
}

export interface CorrelatedListeningService {
  protocol: string;
  port: number;
  service: string;
  ipv4Sockets: number;
  ipv6Sockets: number;
  totalSockets: number;
  xdpFlows: number;
  xdpPackets: number;
  xdpBytes: number;
  synPackets: number;
  synRatioPct: number;
  activeInXdp: boolean;
}

export function correlateListeningSocketsWithXdp(
  sockets: KernelSocketTelemetry | undefined,
  topPorts: XdpPortSummary[] | undefined
): CorrelatedListeningService[] {
  const listening = sockets?.listeningPorts || [];
  if (listening.length === 0) return [];

  const portLookup = new Map<string, XdpPortSummary>();
  for (const tp of topPorts || []) {
    const key = `${String(tp.protoName || '').toUpperCase()}:${tp.port}`;
    const prev = portLookup.get(key);
    if (!prev || tp.bytes > prev.bytes) {
      portLookup.set(key, tp);
    }
  }

  const correlated: CorrelatedListeningService[] = listening.map((lp) => {
    const proto = lp.protocol.toUpperCase();
    const xdp = portLookup.get(`${proto}:${lp.port}`);
    const xdpFlows = xdp?.flows ?? 0;
    const xdpPackets = xdp?.packets ?? 0;
    const xdpBytes = xdp?.bytes ?? 0;
    const synPackets = xdp?.synPackets ?? 0;
    const synRatioPct = xdpPackets > 0 ? Math.round((synPackets / xdpPackets) * 1000) / 10 : 0;

    return {
      protocol: proto,
      port: lp.port,
      service: lp.service || xdp?.service || '',
      ipv4Sockets: lp.ipv4Sockets,
      ipv6Sockets: lp.ipv6Sockets,
      totalSockets: lp.totalCount,
      xdpFlows,
      xdpPackets,
      xdpBytes,
      synPackets,
      synRatioPct,
      activeInXdp: xdpPackets > 0 || xdpFlows > 0,
    };
  });

  correlated.sort((a, b) => b.xdpBytes - a.xdpBytes || b.xdpPackets - a.xdpPackets || a.port - b.port);
  return correlated;
}
