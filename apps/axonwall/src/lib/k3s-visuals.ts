import type { VowAppDefinition } from '@axonwall/lib/compile/vow';
import type {
  K3sClusterPulse,
  K3sEventItem,
  K3sIngressSummary,
  K3sNodeCondition,
  K3sNodePulse,
  K3sNodeTaint,
  K3sPodHotspot,
  K3sServiceSummary,
  K3sTopologyEdge,
  K3sTopologyNode,
} from '@/components/k3s/types';

export const GIB = 1024 * 1024 * 1024;
export const MIB = 1024 * 1024;

export interface K3sPulseHistoryPoint {
  timestamp: string;
  timeLabel: string;
  cpuUsagePct: number;
  cpuRequestPct: number;
  cpuUsageCores: number;
  cpuAllocatableCores: number;
  memUsagePct: number;
  memRequestPct: number;
  memUsageGiB: number;
  memAllocatableGiB: number;
  podsRunning: number;
  podsUnhealthy: number;
  podsTotal: number;
  totalRestarts: number;
  warningEventsCount: number;
}

export interface ClusterAttentionItem {
  label: string;
  severity: 'warn' | 'err';
  resource: string;
  search?: string;
}

export interface ClusterCapacitySummary {
  nodesReady: number;
  nodesTotal: number;
  nodesCordoned: number;
  etcdVotersReady: number;
  etcdVotersTotal: number;
  cpuAllocatableCores: number;
  cpuRequestsCores: number;
  cpuLimitsCores: number;
  cpuUsageCores: number;
  cpuUsagePct: number;
  cpuRequestPct: number;
  cpuLimitPct: number;
  memAllocatableGiB: number;
  memRequestsGiB: number;
  memLimitsGiB: number;
  memUsageGiB: number;
  memUsagePct: number;
  memRequestPct: number;
  memLimitPct: number;
  podsTotal: number;
  podsRunning: number;
  podsUnhealthy: number;
  podCapacityAll: number;
  podCapacitySchedulable: number;
  podDensityPct: number;
  workloadsReady: number;
  workloadsTotal: number;
  workloadReadinessPct: number;
  pvcsBound: number;
  pvcsTotal: number;
  totalStorageGiB: number;
  attentionItems: ClusterAttentionItem[];
}

export interface EventReasonBreakdownItem {
  reason: string;
  warningCount: number;
  normalCount: number;
  totalEvents: number;
  rowCount: number;
}

export interface MergedPodHotspot {
  id: string;
  name: string;
  namespace: string;
  nodeName: string;
  status: string;
  cpuMillis: number;
  memMiB: number;
  memBytes: number;
  restarts: number;
  isUnhealthy: boolean;
  bubbleSize: number;
}

export interface ParsedNodeCondition {
  key: 'Ready' | 'EtcdIsVoter' | 'MemoryPressure' | 'DiskPressure' | 'PIDPressure' | 'NetworkUnavailable';
  shortLabel: string;
  ok: boolean;
  present: boolean;
  reason: string;
  message: string;
}

export interface BinPackedPodTile {
  id: string;
  name: string;
  namespace: string;
  status: string;
  statusTone: string;
  subtitle: string;
  restarts: number;
  cpuMillis: number | null;
  memBytes: number | null;
  pvcNames: string[];
  isUnhealthy: boolean;
}

export interface BinPackedNodeBucket {
  nodeName: string;
  isUnscheduledBucket: boolean;
  status: string;
  roles: string[];
  internalIp: string;
  version: string;
  unschedulable: boolean;
  cpuUsePct: number;
  cpuReqPct: number;
  cpuLimitPct: number;
  cpuUsedCores: number;
  cpuAllocatableCores: number;
  memUsePct: number;
  memReqPct: number;
  memLimitPct: number;
  memUsedGiB: number;
  memAllocatableGiB: number;
  podCount: number;
  podCapacity: number;
  podPct: number;
  conditions: ParsedNodeCondition[];
  taints: K3sNodeTaint[];
  pods: BinPackedPodTile[];
  totalMatchedPods: number;
}

export interface OrderedTopologyColumns {
  ingresses: K3sTopologyNode[];
  services: K3sTopologyNode[];
  workloads: K3sTopologyNode[];
  pods: K3sTopologyNode[];
  infra: K3sTopologyNode[];
  visibleEdges: K3sTopologyEdge[];
  visibleNodes: K3sTopologyNode[];
}

export interface StorageClassChartDatum {
  name: string;
  provisioner: string;
  isDefault: boolean;
  gib: number;
  pvcCount: number;
  boundCount: number;
  pendingCount: number;
}

export interface StorageNamespaceSlice {
  name: string;
  gib: number;
  pvcCount: number;
  boundCount: number;
  pendingCount: number;
}

export interface StorageAttachmentEntry {
  pvcId: string;
  name: string;
  namespace: string;
  status: string;
  capacity: string;
  capacityBytes: number;
  storageClass: string;
  volumeName: string;
  pods: Array<{ id: string; name: string; status: string; statusTone: string; nodeName: string }>;
  isPending: boolean;
  isOrphaned: boolean;
}

export interface StorageVolumeGraph {
  byClass: StorageClassChartDatum[];
  byNamespace: StorageNamespaceSlice[];
  attachments: StorageAttachmentEntry[];
  totalGiB: number;
  boundCount: number;
  pendingCount: number;
  orphanedCount: number;
  attachedCount: number;
}

export interface WorkloadKindReadinessDatum {
  kind: string;
  resource: string;
  ready: number;
  degraded: number;
  total: number;
}

export interface NamespaceFootprintDatum {
  name: string;
  workloads: number;
  services: number;
  ingresses: number;
  podsRunning: number;
  podsUnhealthy: number;
  totalObjects: number;
}

export interface IngressRouteFlow {
  ingress: K3sIngressSummary;
  backends: Array<{
    serviceName: string;
    serviceType: string;
    clusterIP: string;
    readyEndpoints: number;
    podCount: number;
    hasHealthyEndpoints: boolean;
  }>;
  hasBrokenBackend: boolean;
}

export interface WorkloadsVisualSummary {
  readinessByKind: WorkloadKindReadinessDatum[];
  namespaceFootprint: NamespaceFootprintDatum[];
  serviceTypes: Array<{ name: string; count: number }>;
  zeroEndpointServices: K3sServiceSummary[];
  ingressPosture: {
    total: number;
    tlsCount: number;
    httpOnlyCount: number;
    totalHosts: number;
    brokenBackendsCount: number;
  };
  ingressRoutes: IngressRouteFlow[];
}

export interface VowCategoryMemoryDatum {
  category: string;
  memoryMb: number;
  memoryGb: number;
  appCount: number;
}

export interface VowDependencyNode {
  id: string;
  name: string;
  category: string;
  memoryMb: number;
  isAutoDep: boolean;
  isExplicit: boolean;
  namespace: string;
  depth: number;
  livePods: number;
  liveUnhealthy: number;
}

export interface VowVisualSummary {
  memoryByCategory: VowCategoryMemoryDatum[];
  ramBudget: {
    stackMemoryGb: number;
    clusterAllocatableGb: number;
    clusterUsedGb: number;
    clusterFreeGb: number;
    projectedTotalPct: number;
    fitsInFreeRam: boolean;
    hasLiveCluster: boolean;
  };
  dependencyGraph: {
    nodes: VowDependencyNode[];
    edges: Array<{ from: string; to: string }>;
  };
}

function asArray<T>(val: T[] | null | undefined): T[] {
  return Array.isArray(val) ? val : [];
}

function safeRound(value: number, decimals = 2): number {
  if (!Number.isFinite(value)) return 0;
  const factor = Math.pow(10, decimals);
  return Math.round(value * factor) / factor;
}

function formatTimeLabel(isoTimestamp?: string): string {
  const parsed = isoTimestamp ? new Date(isoTimestamp) : new Date();
  const d = Number.isNaN(parsed.getTime()) ? new Date() : parsed;
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
}

function isUnhealthyStatus(status?: string, tone?: string): boolean {
  if (tone === 'err' || tone === 'warn') return true;
  const s = (status || '').toLowerCase();
  return (
    s.includes('fail') ||
    s.includes('error') ||
    s.includes('crash') ||
    s.includes('pending') ||
    s.includes('backoff') ||
    s.includes('terminat') ||
    s.includes('unknown') ||
    s.includes('init:')
  );
}

export function computeClusterCapacitySummary(pulse: K3sClusterPulse | null | undefined): ClusterCapacitySummary {
  const nodes = asArray(pulse?.nodes);
  const counts = pulse?.counts;
  const services = asArray(pulse?.servicesSummary);
  const storageByClass = asArray(pulse?.storageByClass);
  const pvcsSummary = asArray(pulse?.pvcsSummary);

  let cpuAllocatableMillis = 0;
  let cpuRequestsMillis = 0;
  let cpuLimitsMillis = 0;
  let cpuUsageMillis = 0;
  let hasCpuUsage = false;

  let memAllocatableBytes = 0;
  let memRequestsBytes = 0;
  let memLimitsBytes = 0;
  let memUsageBytes = 0;
  let hasMemUsage = false;

  let podCapacityAll = 0;
  let podCapacitySchedulable = 0;
  let etcdVotersTotal = 0;
  let etcdVotersReady = 0;

  for (const n of nodes) {
    cpuAllocatableMillis += Number(n.cpuAllocatableMillis) || 0;
    cpuRequestsMillis += Number(n.cpuRequestsMillis) || 0;
    cpuLimitsMillis += Number(n.cpuLimitsMillis) || 0;
    if (n.cpuUsageMillis !== null && n.cpuUsageMillis !== undefined && Number.isFinite(n.cpuUsageMillis)) {
      cpuUsageMillis += n.cpuUsageMillis;
      hasCpuUsage = true;
    }

    memAllocatableBytes += Number(n.memAllocatableBytes) || 0;
    memRequestsBytes += Number(n.memRequestsBytes) || 0;
    memLimitsBytes += Number(n.memLimitsBytes) || 0;
    if (n.memUsageBytes !== null && n.memUsageBytes !== undefined && Number.isFinite(n.memUsageBytes)) {
      memUsageBytes += n.memUsageBytes;
      hasMemUsage = true;
    }

    const cap = Number(n.podCapacity) || 0;
    podCapacityAll += cap;
    if (n.status === 'Ready' && !n.unschedulable) {
      podCapacitySchedulable += cap;
    }

    const conds = asArray(n.conditions);
    const etcdCond = conds.find((c) => c.type === 'EtcdIsVoter');
    const roleHasEtcd = (n.roles || '').toLowerCase().includes('etcd') || (n.roles || '').toLowerCase().includes('control-plane');
    if (etcdCond || roleHasEtcd) {
      etcdVotersTotal += 1;
      if (etcdCond ? etcdCond.status === 'True' : n.status === 'Ready') {
        etcdVotersReady += 1;
      }
    }
  }

  const effectiveCpuUsageMillis = hasCpuUsage ? cpuUsageMillis : cpuRequestsMillis;
  const effectiveMemUsageBytes = hasMemUsage ? memUsageBytes : memRequestsBytes;

  const cpuAllocatableCores = safeRound(cpuAllocatableMillis / 1000, 2);
  const cpuRequestsCores = safeRound(cpuRequestsMillis / 1000, 2);
  const cpuLimitsCores = safeRound(cpuLimitsMillis / 1000, 2);
  const cpuUsageCores = safeRound(effectiveCpuUsageMillis / 1000, 2);

  const memAllocatableGiB = safeRound(memAllocatableBytes / GIB, 1);
  const memRequestsGiB = safeRound(memRequestsBytes / GIB, 1);
  const memLimitsGiB = safeRound(memLimitsBytes / GIB, 1);
  const memUsageGiB = safeRound(effectiveMemUsageBytes / GIB, 1);

  const cpuUsagePct =
    cpuAllocatableMillis > 0 ? Math.min(100, Math.round((effectiveCpuUsageMillis / cpuAllocatableMillis) * 100)) : 0;
  const cpuRequestPct =
    cpuAllocatableMillis > 0 ? Math.round((cpuRequestsMillis / cpuAllocatableMillis) * 100) : 0;
  const cpuLimitPct =
    cpuAllocatableMillis > 0 ? Math.round((cpuLimitsMillis / cpuAllocatableMillis) * 100) : 0;

  const memUsagePct =
    memAllocatableBytes > 0 ? Math.min(100, Math.round((effectiveMemUsageBytes / memAllocatableBytes) * 100)) : 0;
  const memRequestPct =
    memAllocatableBytes > 0 ? Math.round((memRequestsBytes / memAllocatableBytes) * 100) : 0;
  const memLimitPct =
    memAllocatableBytes > 0 ? Math.round((memLimitsBytes / memAllocatableBytes) * 100) : 0;

  const nodesTotal = counts?.nodesTotal ?? nodes.length;
  const nodesReady = counts?.nodesReady ?? nodes.filter((n) => n.status === 'Ready').length;
  const nodesCordoned = counts?.nodesCordoned ?? nodes.filter((n) => n.unschedulable).length;

  const podsRunning = counts?.podsRunning ?? 0;
  const podsTotal = counts?.podsTotal ?? 0;
  const podsUnhealthy = (counts?.podsPending ?? 0) + (counts?.podsFailed ?? 0) + (counts?.podsUnknown ?? 0);

  const podCapDenominator = podCapacitySchedulable > 0 ? podCapacitySchedulable : podCapacityAll;
  const podDensityPct = podCapDenominator > 0 ? Math.min(100, Math.round((podsTotal / podCapDenominator) * 100)) : 0;

  const workloadsReady =
    (counts?.deploymentsReady ?? 0) + (counts?.statefulSetsReady ?? 0) + (counts?.daemonSetsReady ?? 0);
  const workloadsTotal =
    (counts?.deploymentsTotal ?? 0) + (counts?.statefulSetsTotal ?? 0) + (counts?.daemonSetsTotal ?? 0);
  const workloadReadinessPct =
    workloadsTotal > 0 ? Math.round((workloadsReady / workloadsTotal) * 100) : 100;

  const pvcsBound = counts?.pvcsBound ?? pvcsSummary.filter((p) => p.status === 'Bound').length;
  const pvcsTotal = counts?.pvcsTotal ?? pvcsSummary.length;
  const classBytes = storageByClass.reduce((acc, s) => acc + (Number(s.totalBytes) || 0), 0);
  const pvcBytes = pvcsSummary.reduce((acc, p) => acc + (Number(p.capacityBytes) || 0), 0);
  const totalStorageGiB = safeRound((classBytes > 0 ? classBytes : pvcBytes) / GIB, 1);

  const attentionItems: ClusterAttentionItem[] = [];
  const notReadyNodes = nodesTotal - nodesReady;
  if (notReadyNodes > 0) {
    attentionItems.push({
      label: `${notReadyNodes} ${notReadyNodes === 1 ? 'node' : 'nodes'} NotReady`,
      severity: 'err',
      resource: 'nodes',
    });
  }
  if ((counts?.podsFailed ?? 0) + (counts?.podsUnknown ?? 0) > 0) {
    const failed = (counts?.podsFailed ?? 0) + (counts?.podsUnknown ?? 0);
    attentionItems.push({
      label: `${failed} ${failed === 1 ? 'pod' : 'pods'} Failed/Unknown`,
      severity: 'err',
      resource: 'pods',
      search: 'Failed',
    });
  }
  if ((counts?.podsPending ?? 0) > 0) {
    const pending = counts?.podsPending ?? 0;
    attentionItems.push({
      label: `${pending} ${pending === 1 ? 'pod' : 'pods'} Pending`,
      severity: 'warn',
      resource: 'pods',
      search: 'Pending',
    });
  }
  if (workloadsTotal > workloadsReady) {
    const deg = workloadsTotal - workloadsReady;
    attentionItems.push({
      label: `${deg} degraded ${deg === 1 ? 'workload' : 'workloads'}`,
      severity: 'warn',
      resource: 'deployments',
    });
  }
  if (pvcsTotal > pvcsBound) {
    const unbound = pvcsTotal - pvcsBound;
    attentionItems.push({
      label: `${unbound} unbound ${unbound === 1 ? 'PVC' : 'PVCs'}`,
      severity: 'warn',
      resource: 'persistentvolumeclaims',
      search: 'Pending',
    });
  }
  const zeroEpSvcs = services.filter((s) => s.readyEndpoints === 0).length;
  if (zeroEpSvcs > 0) {
    attentionItems.push({
      label: `${zeroEpSvcs} services with 0 endpoints`,
      severity: 'warn',
      resource: 'services',
    });
  }

  return {
    nodesReady,
    nodesTotal,
    nodesCordoned,
    etcdVotersReady,
    etcdVotersTotal,
    cpuAllocatableCores,
    cpuRequestsCores,
    cpuLimitsCores,
    cpuUsageCores,
    cpuUsagePct,
    cpuRequestPct,
    cpuLimitPct,
    memAllocatableGiB,
    memRequestsGiB,
    memLimitsGiB,
    memUsageGiB,
    memUsagePct,
    memRequestPct,
    memLimitPct,
    podsTotal,
    podsRunning,
    podsUnhealthy,
    podCapacityAll,
    podCapacitySchedulable,
    podDensityPct,
    workloadsReady,
    workloadsTotal,
    workloadReadinessPct,
    pvcsBound,
    pvcsTotal,
    totalStorageGiB,
    attentionItems,
  };
}

export function appendPulseHistory(
  prev: K3sPulseHistoryPoint[],
  pulse: K3sClusterPulse | null | undefined,
  maxPoints = 30
): K3sPulseHistoryPoint[] {
  if (!pulse || !pulse.available) return prev;
  const ts = pulse.timestamp || new Date().toISOString();
  if (prev.length > 0 && prev[prev.length - 1].timestamp === ts) {
    return prev;
  }

  const cap = computeClusterCapacitySummary(pulse);
  const point: K3sPulseHistoryPoint = {
    timestamp: ts,
    timeLabel: formatTimeLabel(ts),
    cpuUsagePct: cap.cpuUsagePct,
    cpuRequestPct: Math.min(100, cap.cpuRequestPct),
    cpuUsageCores: cap.cpuUsageCores,
    cpuAllocatableCores: cap.cpuAllocatableCores,
    memUsagePct: cap.memUsagePct,
    memRequestPct: Math.min(100, cap.memRequestPct),
    memUsageGiB: cap.memUsageGiB,
    memAllocatableGiB: cap.memAllocatableGiB,
    podsRunning: cap.podsRunning,
    podsUnhealthy: cap.podsUnhealthy,
    podsTotal: cap.podsTotal,
    totalRestarts: pulse.counts?.totalRestarts ?? 0,
    warningEventsCount: pulse.counts?.warningEventsCount ?? 0,
  };

  const next = [...prev, point];
  if (next.length > maxPoints) {
    return next.slice(next.length - maxPoints);
  }
  return next;
}

export function buildEventReasonBreakdown(
  events: K3sEventItem[] | null | undefined,
  maxReasons = 10
): EventReasonBreakdownItem[] {
  const list = asArray(events);
  const map = new Map<string, EventReasonBreakdownItem>();

  for (const ev of list) {
    const reason = (ev.reason || 'Unknown').trim() || 'Unknown';
    const occurrences = Math.max(1, Number(ev.count) || 1);
    let item = map.get(reason);
    if (!item) {
      item = {
        reason,
        warningCount: 0,
        normalCount: 0,
        totalEvents: 0,
        rowCount: 0,
      };
      map.set(reason, item);
    }
    item.rowCount += 1;
    item.totalEvents += occurrences;
    if (ev.type === 'Warning') {
      item.warningCount += 1;
    } else {
      item.normalCount += 1;
    }
  }

  return Array.from(map.values())
    .sort((a, b) => {
      const aWarn = a.warningCount > 0 ? 1 : 0;
      const bWarn = b.warningCount > 0 ? 1 : 0;
      if (aWarn !== bWarn) return bWarn - aWarn;
      if (b.rowCount !== a.rowCount) return b.rowCount - a.rowCount;
      if (b.totalEvents !== a.totalEvents) return b.totalEvents - a.totalEvents;
      return a.reason.localeCompare(b.reason);
    })
    .slice(0, maxReasons);
}

export function buildPodResourceHotspots(
  topResourcePods: K3sPodHotspot[] | null | undefined,
  topRestartingPods: K3sPodHotspot[] | null | undefined
): {
  all: MergedPodHotspot[];
  byCpu: MergedPodHotspot[];
  byMem: MergedPodHotspot[];
  scatterPoints: MergedPodHotspot[];
} {
  const map = new Map<string, MergedPodHotspot>();

  const upsert = (p: K3sPodHotspot) => {
    const id = `${p.namespace}/${p.name}`;
    const existing = map.get(id);
    const cpuMillis =
      p.cpuMillis !== null && p.cpuMillis !== undefined && Number.isFinite(p.cpuMillis)
        ? Math.max(0, Math.round(p.cpuMillis))
        : existing?.cpuMillis ?? 0;
    const memBytes =
      p.memBytes !== null && p.memBytes !== undefined && Number.isFinite(p.memBytes)
        ? Math.max(0, p.memBytes)
        : existing?.memBytes ?? 0;
    const restarts = Math.max(Number(p.restarts) || 0, existing?.restarts ?? 0);
    const status = p.status || existing?.status || 'Unknown';
    const memMiB = safeRound(memBytes / MIB, 1);

    map.set(id, {
      id,
      name: p.name,
      namespace: p.namespace,
      nodeName: p.nodeName || existing?.nodeName || 'unscheduled',
      status,
      cpuMillis,
      memMiB,
      memBytes,
      restarts,
      isUnhealthy: isUnhealthyStatus(status),
      bubbleSize: Math.max(48, Math.min(280, 56 + restarts * 18)),
    });
  };

  for (const p of asArray(topResourcePods)) upsert(p);
  for (const p of asArray(topRestartingPods)) upsert(p);

  const all = Array.from(map.values());
  const byCpu = [...all].sort((a, b) => b.cpuMillis - a.cpuMillis || b.memMiB - a.memMiB).slice(0, 10);
  const byMem = [...all].sort((a, b) => b.memMiB - a.memMiB || b.cpuMillis - a.cpuMillis).slice(0, 10);
  const scatterPoints = all.filter((p) => Number.isFinite(p.cpuMillis) && Number.isFinite(p.memMiB));

  return { all, byCpu, byMem, scatterPoints };
}

function parseNodeConditions(conds: K3sNodeCondition[] | null | undefined, nodeStatus: string): ParsedNodeCondition[] {
  const list = asArray(conds);
  const find = (type: string) => list.find((c) => c.type === type);

  const specs: Array<{
    key: ParsedNodeCondition['key'];
    shortLabel: string;
    expectedTrue: boolean;
  }> = [
    { key: 'Ready', shortLabel: 'Ready', expectedTrue: true },
    { key: 'EtcdIsVoter', shortLabel: 'Etcd', expectedTrue: true },
    { key: 'MemoryPressure', shortLabel: 'Mem', expectedTrue: false },
    { key: 'DiskPressure', shortLabel: 'Disk', expectedTrue: false },
    { key: 'PIDPressure', shortLabel: 'PID', expectedTrue: false },
  ];

  const parsed: ParsedNodeCondition[] = [];
  for (const sp of specs) {
    const c = find(sp.key);
    if (!c && sp.key === 'EtcdIsVoter') {
      continue;
    }
    const present = Boolean(c);
    const ok = c
      ? sp.expectedTrue
        ? c.status === 'True'
        : c.status === 'False'
      : sp.key === 'Ready'
        ? nodeStatus === 'Ready'
        : true;

    parsed.push({
      key: sp.key,
      shortLabel: sp.shortLabel,
      ok,
      present,
      reason: c?.reason || (ok ? 'Healthy' : 'Unknown'),
      message: c?.message || '',
    });
  }
  return parsed;
}

export function buildNodeBinPackingData(
  pulse: K3sClusterPulse | null | undefined,
  opts?: { namespace?: string; search?: string; issuesOnly?: boolean }
): BinPackedNodeBucket[] {
  const nodes = asArray(pulse?.nodes);
  const topoNodes = asArray(pulse?.topology?.nodes);
  const topoEdges = asArray(pulse?.topology?.edges);
  const nsFilter = opts?.namespace && opts.namespace !== '_all' ? opts.namespace : null;
  const searchLower = (opts?.search || '').trim().toLowerCase();
  const issuesOnly = Boolean(opts?.issuesOnly);

  const hotspotLookup = new Map<string, K3sPodHotspot>();
  for (const h of asArray(pulse?.topResourcePods)) {
    hotspotLookup.set(`${h.namespace}/${h.name}`, h);
  }
  for (const h of asArray(pulse?.topRestartingPods)) {
    const k = `${h.namespace}/${h.name}`;
    const prev = hotspotLookup.get(k);
    hotspotLookup.set(k, {
      ...h,
      cpuMillis: prev?.cpuMillis ?? h.cpuMillis,
      memBytes: prev?.memBytes ?? h.memBytes,
    });
  }

  // Map podId -> pvcNames[] via pod-to-pvc edges
  const podPvcMap = new Map<string, string[]>();
  const podNodeEdgeMap = new Map<string, string>();
  for (const e of topoEdges) {
    if (e.relation === 'pod-to-pvc' && e.target.startsWith('pvc/')) {
      const parts = e.target.split('/');
      const pvcName = parts[parts.length - 1] || e.target;
      const arr = podPvcMap.get(e.source) || [];
      arr.push(pvcName);
      podPvcMap.set(e.source, arr);
    }
    if (e.relation === 'pod-to-node' && e.target.startsWith('node/')) {
      podNodeEdgeMap.set(e.source, e.target.slice('node/'.length));
    }
  }

  const podsByNode = new Map<string, BinPackedPodTile[]>();
  for (const tn of topoNodes) {
    if (tn.kind !== 'Pod') continue;
    const ns = tn.namespace || 'default';
    const hostNode = tn.parentNodeName || podNodeEdgeMap.get(tn.id) || 'Unscheduled';
    const hotspot = hotspotLookup.get(`${ns}/${tn.name}`);
    const restartsMatch = tn.subtitle?.match(/↻\s*(\d+)/);
    const parsedRestarts = hotspot?.restarts ?? (restartsMatch ? Number(restartsMatch[1]) : 0);
    const tile: BinPackedPodTile = {
      id: tn.id,
      name: tn.name,
      namespace: ns,
      status: tn.status,
      statusTone: tn.statusTone,
      subtitle: tn.subtitle || tn.status,
      restarts: Number.isFinite(parsedRestarts) ? parsedRestarts : 0,
      cpuMillis: hotspot?.cpuMillis ?? null,
      memBytes: hotspot?.memBytes ?? null,
      pvcNames: podPvcMap.get(tn.id) || [],
      isUnhealthy: isUnhealthyStatus(tn.status, tn.statusTone),
    };
    const arr = podsByNode.get(hostNode) || [];
    arr.push(tile);
    podsByNode.set(hostNode, arr);
  }

  const filterPod = (p: BinPackedPodTile): boolean => {
    if (nsFilter && p.namespace !== nsFilter) return false;
    if (issuesOnly && !p.isUnhealthy && p.restarts === 0) return false;
    if (
      searchLower &&
      !p.name.toLowerCase().includes(searchLower) &&
      !p.namespace.toLowerCase().includes(searchLower) &&
      !p.status.toLowerCase().includes(searchLower)
    ) {
      return false;
    }
    return true;
  };

  const makeBucket = (n: K3sNodePulse | null, fallbackName: string): BinPackedNodeBucket => {
    const rawPods = (podsByNode.get(fallbackName) || []).sort((a, b) => {
      if (a.isUnhealthy !== b.isUnhealthy) return a.isUnhealthy ? -1 : 1;
      if (a.restarts !== b.restarts) return b.restarts - a.restarts;
      return a.name.localeCompare(b.name);
    });
    const matchedPods = rawPods.filter(filterPod);

    const cpuAlloc = n?.cpuAllocatableMillis || 0;
    const cpuUsed = (n?.cpuUsageMillis ?? n?.cpuRequestsMillis) || 0;
    const cpuReq = n?.cpuRequestsMillis || 0;
    const cpuLim = n?.cpuLimitsMillis || 0;

    const memAlloc = n?.memAllocatableBytes || 0;
    const memUsed = (n?.memUsageBytes ?? n?.memRequestsBytes) || 0;
    const memReq = n?.memRequestsBytes || 0;
    const memLim = n?.memLimitsBytes || 0;

    return {
      nodeName: n?.name || fallbackName,
      isUnscheduledBucket: n === null,
      status: n?.status || 'Pending',
      roles: n
        ? (n.roles || '')
            .split(',')
            .map((r) => r.trim())
            .filter(Boolean)
        : ['unscheduled'],
      internalIp: n?.internalIp || '—',
      version: n?.version || '—',
      unschedulable: Boolean(n?.unschedulable),
      cpuUsePct: cpuAlloc > 0 ? Math.min(100, Math.round((cpuUsed / cpuAlloc) * 100)) : 0,
      cpuReqPct: cpuAlloc > 0 ? Math.min(100, Math.round((cpuReq / cpuAlloc) * 100)) : 0,
      cpuLimitPct: cpuAlloc > 0 ? Math.round((cpuLim / cpuAlloc) * 100) : 0,
      cpuUsedCores: safeRound(cpuUsed / 1000, 2),
      cpuAllocatableCores: safeRound(cpuAlloc / 1000, 2),
      memUsePct: memAlloc > 0 ? Math.min(100, Math.round((memUsed / memAlloc) * 100)) : 0,
      memReqPct: memAlloc > 0 ? Math.min(100, Math.round((memReq / memAlloc) * 100)) : 0,
      memLimitPct: memAlloc > 0 ? Math.round((memLim / memAlloc) * 100) : 0,
      memUsedGiB: safeRound(memUsed / GIB, 1),
      memAllocatableGiB: safeRound(memAlloc / GIB, 1),
      podCount: n?.podCount ?? rawPods.length,
      podCapacity: n?.podCapacity ?? 0,
      podPct: n && n.podCapacity > 0 ? Math.min(100, Math.round((n.podCount / n.podCapacity) * 100)) : 0,
      conditions: n ? parseNodeConditions(n.conditions, n.status) : [],
      taints: n ? asArray(n.taints) : [],
      pods: matchedPods,
      totalMatchedPods: matchedPods.length,
    };
  };

  const buckets: BinPackedNodeBucket[] = [];
  const knownNames = new Set(nodes.map((n) => n.name));

  for (const n of nodes) {
    const b = makeBucket(n, n.name);
    if (issuesOnly && n.status === 'Ready' && !n.unschedulable && b.pods.length === 0) {
      continue;
    }
    if (nsFilter && b.pods.length === 0 && n.status === 'Ready') {
      continue;
    }
    buckets.push(b);
  }

  for (const extraNode of podsByNode.keys()) {
    if (!knownNames.has(extraNode)) {
      const b = makeBucket(null, extraNode);
      if (b.pods.length > 0) buckets.push(b);
    }
  }

  return buckets;
}

export function orderTopologyColumnsBarycenter(
  nodes: K3sTopologyNode[] | null | undefined,
  edges: K3sTopologyEdge[] | null | undefined,
  opts?: { hideIsolated?: boolean; issuesOnly?: boolean }
): OrderedTopologyColumns {
  const rawNodes = asArray(nodes);
  const rawEdges = asArray(edges);
  const hideIsolated = Boolean(opts?.hideIsolated);
  const issuesOnly = Boolean(opts?.issuesOnly);

  let activeNodes = rawNodes;

  if (issuesOnly) {
    const keepIds = new Set<string>();
    for (const n of rawNodes) {
      if (n.statusTone === 'err' || n.statusTone === 'warn') {
        keepIds.add(n.id);
      }
    }
    // Expand 1-hop context so user sees what Ingress/Service/Node connects to the unhealthy node
    const seedIds = Array.from(keepIds);
    for (const id of seedIds) {
      for (const e of rawEdges) {
        if (e.source === id) keepIds.add(e.target);
        if (e.target === id) keepIds.add(e.source);
      }
    }
    activeNodes = activeNodes.filter((n) => keepIds.has(n.id));
  }

  const activeNodeSet = new Set(activeNodes.map((n) => n.id));
  let activeEdges = rawEdges.filter((e) => activeNodeSet.has(e.source) && activeNodeSet.has(e.target));

  if (hideIsolated) {
    const connected = new Set<string>();
    for (const e of activeEdges) {
      connected.add(e.source);
      connected.add(e.target);
    }
    activeNodes = activeNodes.filter((n) => connected.has(n.id));
    const connSet = new Set(activeNodes.map((n) => n.id));
    activeEdges = activeEdges.filter((e) => connSet.has(e.source) && connSet.has(e.target));
  }

  const ingresses: K3sTopologyNode[] = [];
  const services: K3sTopologyNode[] = [];
  const workloads: K3sTopologyNode[] = [];
  const pods: K3sTopologyNode[] = [];
  const infra: K3sTopologyNode[] = [];

  for (const n of activeNodes) {
    if (n.kind === 'Ingress') ingresses.push(n);
    else if (n.kind === 'Service') services.push(n);
    else if (n.kind === 'Deployment' || n.kind === 'StatefulSet' || n.kind === 'DaemonSet' || n.kind === 'Job') {
      workloads.push(n);
    } else if (n.kind === 'Pod') {
      pods.push(n);
    } else {
      infra.push(n);
    }
  }

  // Initial deterministic sort: namespace + name (Infra puts Nodes before PVCs)
  const sortAlpha = (a: K3sTopologyNode, b: K3sTopologyNode) =>
    `${a.namespace || ''}/${a.name}`.localeCompare(`${b.namespace || ''}/${b.name}`);

  ingresses.sort(sortAlpha);
  services.sort(sortAlpha);
  workloads.sort(sortAlpha);
  pods.sort((a, b) => {
    const na = a.parentNodeName || 'zzz';
    const nb = b.parentNodeName || 'zzz';
    if (na !== nb) return na.localeCompare(nb);
    return sortAlpha(a, b);
  });
  infra.sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === 'Node' ? -1 : 1;
    return sortAlpha(a, b);
  });

  // Build adjacency for barycenter ordering
  const neighbors = new Map<string, string[]>();
  for (const e of activeEdges) {
    const a1 = neighbors.get(e.source) || [];
    a1.push(e.target);
    neighbors.set(e.source, a1);

    const a2 = neighbors.get(e.target) || [];
    a2.push(e.source);
    neighbors.set(e.target, a2);
  }

  const reorderByNeighborColumn = (col: K3sTopologyNode[], refIndexMap: Map<string, number>) => {
    if (refIndexMap.size === 0 || col.length <= 1) return;
    const originalIdx = new Map(col.map((n, i) => [n.id, i]));
    const score = (n: K3sTopologyNode): number => {
      const nbs = neighbors.get(n.id) || [];
      let sum = 0;
      let cnt = 0;
      for (const nb of nbs) {
        const pos = refIndexMap.get(nb);
        if (pos !== undefined) {
          sum += pos;
          cnt += 1;
        }
      }
      if (cnt === 0) return 100000 + (originalIdx.get(n.id) ?? 0);
      return sum / cnt;
    };
    col.sort((a, b) => {
      const sa = score(a);
      const sb = score(b);
      if (Math.abs(sa - sb) > 0.001) return sa - sb;
      return (originalIdx.get(a.id) ?? 0) - (originalIdx.get(b.id) ?? 0);
    });
  };

  const toIdxMap = (col: K3sTopologyNode[]) => new Map(col.map((n, i) => [n.id, i]));

  // Pass 1: Left-to-Right (Ingress -> Service -> Workload -> Pod -> Infra)
  // Align Services to Ingresses when possible, else leave ordered cleanly
  if (ingresses.length > 0) {
    reorderByNeighborColumn(services, toIdxMap(ingresses));
  }
  // Align Pods to Services & Workloads
  const leftOfPods = new Map<string, number>();
  services.forEach((n, i) => leftOfPods.set(n.id, i));
  workloads.forEach((n, i) => leftOfPods.set(n.id, i));
  reorderByNeighborColumn(pods, leftOfPods);

  // Align Infra (Nodes & PVCs) to Pods
  if (pods.length > 0) {
    reorderByNeighborColumn(infra, toIdxMap(pods));
  }

  // Pass 2: Pull Workloads toward their Pods
  if (pods.length > 0) {
    reorderByNeighborColumn(workloads, toIdxMap(pods));
  }

  return {
    ingresses,
    services,
    workloads,
    pods,
    infra,
    visibleEdges: activeEdges,
    visibleNodes: activeNodes,
  };
}

export function buildStorageVolumeGraph(pulse: K3sClusterPulse | null | undefined): StorageVolumeGraph {
  const storageClasses = asArray(pulse?.storageByClass);
  const pvcs = asArray(pulse?.pvcsSummary);
  const topoNodes = asArray(pulse?.topology?.nodes);
  const topoEdges = asArray(pulse?.topology?.edges);

  const byClass: StorageClassChartDatum[] = storageClasses
    .map((sc) => ({
      name: sc.name,
      provisioner: sc.provisioner || 'csi',
      isDefault: Boolean(sc.isDefault),
      gib: safeRound((Number(sc.totalBytes) || 0) / GIB, 2),
      pvcCount: Number(sc.pvcCount) || 0,
      boundCount: Number(sc.boundCount) || 0,
      pendingCount: Math.max(0, (Number(sc.pvcCount) || 0) - (Number(sc.boundCount) || 0)),
    }))
    .sort((a, b) => b.gib - a.gib || b.pvcCount - a.pvcCount);

  const nsMap = new Map<string, StorageNamespaceSlice>();
  let totalBytes = 0;
  let boundCount = 0;
  let pendingCount = 0;

  for (const pvc of pvcs) {
    const ns = pvc.namespace || 'default';
    const bytes = Number(pvc.capacityBytes) || 0;
    totalBytes += bytes;
    const isBound = pvc.status === 'Bound';
    if (isBound) boundCount += 1;
    else pendingCount += 1;

    let entry = nsMap.get(ns);
    if (!entry) {
      entry = { name: ns, gib: 0, pvcCount: 0, boundCount: 0, pendingCount: 0 };
      nsMap.set(ns, entry);
    }
    entry.gib = safeRound(entry.gib + bytes / GIB, 2);
    entry.pvcCount += 1;
    if (isBound) entry.boundCount += 1;
    else entry.pendingCount += 1;
  }

  const byNamespace = Array.from(nsMap.values()).sort((a, b) => b.gib - a.gib || b.pvcCount - a.pvcCount);

  // Build Pod lookup & Pod->PVC reverse map
  const podNodeMap = new Map<string, K3sTopologyNode>();
  for (const tn of topoNodes) {
    if (tn.kind === 'Pod') podNodeMap.set(tn.id, tn);
  }
  const podToHostNode = new Map<string, string>();
  const pvcToPodIds = new Map<string, string[]>();

  for (const e of topoEdges) {
    if (e.relation === 'pod-to-node' && e.target.startsWith('node/')) {
      podToHostNode.set(e.source, e.target.slice('node/'.length));
    }
    if (e.relation === 'pod-to-pvc' && e.target.startsWith('pvc/')) {
      const arr = pvcToPodIds.get(e.target) || [];
      if (!arr.includes(e.source)) arr.push(e.source);
      pvcToPodIds.set(e.target, arr);
    }
  }

  let orphanedCount = 0;
  let attachedCount = 0;

  const attachments: StorageAttachmentEntry[] = pvcs.map((pvc) => {
    const ns = pvc.namespace || 'default';
    const pvcId = `pvc/${ns}/${pvc.name}`;
    const podIds = pvcToPodIds.get(pvcId) || [];
    const pods = podIds.map((pid) => {
      const pn = podNodeMap.get(pid);
      const podName = pn?.name || pid.split('/').pop() || pid;
      return {
        id: pid,
        name: podName,
        status: pn?.status || 'Unknown',
        statusTone: pn?.statusTone || 'muted',
        nodeName: pn?.parentNodeName || podToHostNode.get(pid) || 'unscheduled',
      };
    });
    const isPending = pvc.status !== 'Bound';
    const isOrphaned = !isPending && pods.length === 0;
    if (isOrphaned) orphanedCount += 1;
    if (pods.length > 0) attachedCount += 1;

    return {
      pvcId,
      name: pvc.name,
      namespace: ns,
      status: pvc.status,
      capacity: pvc.capacity || `${safeRound((Number(pvc.capacityBytes) || 0) / GIB, 1)}Gi`,
      capacityBytes: Number(pvc.capacityBytes) || 0,
      storageClass: pvc.storageClass || '—',
      volumeName: pvc.volumeName || '',
      pods,
      isPending,
      isOrphaned,
    };
  });

  const classTotalGiB = byClass.reduce((acc, c) => acc + c.gib, 0);
  const totalGiB = safeRound(classTotalGiB > 0 ? classTotalGiB : totalBytes / GIB, 1);

  return {
    byClass,
    byNamespace,
    attachments,
    totalGiB,
    boundCount,
    pendingCount,
    orphanedCount,
    attachedCount,
  };
}

export function buildWorkloadsVisualSummary(pulse: K3sClusterPulse | null | undefined): WorkloadsVisualSummary {
  const counts = pulse?.counts;
  const nsStats = asArray(pulse?.namespaceStats);
  const services = asArray(pulse?.servicesSummary);
  const ingresses = asArray(pulse?.ingressesSummary);
  const workloads = asArray(pulse?.workloadsSummary);
  const topoEdges = asArray(pulse?.topology?.edges);

  const readinessByKind: WorkloadKindReadinessDatum[] = [
    {
      kind: 'Deployments',
      resource: 'deployments',
      ready: counts?.deploymentsReady ?? 0,
      degraded: Math.max(0, (counts?.deploymentsTotal ?? 0) - (counts?.deploymentsReady ?? 0)),
      total: counts?.deploymentsTotal ?? 0,
    },
    {
      kind: 'StatefulSets',
      resource: 'statefulsets',
      ready: counts?.statefulSetsReady ?? 0,
      degraded: Math.max(0, (counts?.statefulSetsTotal ?? 0) - (counts?.statefulSetsReady ?? 0)),
      total: counts?.statefulSetsTotal ?? 0,
    },
    {
      kind: 'DaemonSets',
      resource: 'daemonsets',
      ready: counts?.daemonSetsReady ?? 0,
      degraded: Math.max(0, (counts?.daemonSetsTotal ?? 0) - (counts?.daemonSetsReady ?? 0)),
      total: counts?.daemonSetsTotal ?? 0,
    },
    {
      kind: 'Jobs',
      resource: 'jobs',
      ready: (counts?.jobsSucceeded ?? 0) + (counts?.jobsActive ?? 0),
      degraded: counts?.jobsFailed ?? 0,
      total: (counts?.jobsSucceeded ?? 0) + (counts?.jobsActive ?? 0) + (counts?.jobsFailed ?? 0),
    },
  ];

  // Count workloads per namespace from workloadsSummary
  const wlByNs = new Map<string, number>();
  for (const w of workloads) {
    const ns = w.namespace || 'default';
    wlByNs.set(ns, (wlByNs.get(ns) || 0) + 1);
  }

  const namespaceFootprint: NamespaceFootprintDatum[] = nsStats
    .map((ns) => {
      const wlCount = wlByNs.get(ns.name) || 0;
      return {
        name: ns.name,
        workloads: wlCount,
        services: ns.services || 0,
        ingresses: ns.ingresses || 0,
        podsRunning: ns.podsRunning || 0,
        podsUnhealthy: ns.podsUnhealthy || 0,
        totalObjects: wlCount + (ns.services || 0) + (ns.ingresses || 0) + (ns.podsTotal || 0),
      };
    })
    .sort((a, b) => b.totalObjects - a.totalObjects || a.name.localeCompare(b.name))
    .slice(0, 10);

  const typeCounts = new Map<string, number>();
  const zeroEndpointServices: K3sServiceSummary[] = [];
  const serviceByKey = new Map<string, K3sServiceSummary>();

  for (const svc of services) {
    const t = svc.type || 'ClusterIP';
    typeCounts.set(t, (typeCounts.get(t) || 0) + 1);
    serviceByKey.set(`${svc.namespace}/${svc.name}`, svc);
    if ((svc.readyEndpoints ?? 0) === 0 && svc.name !== 'kubernetes') {
      zeroEndpointServices.push(svc);
    }
  }

  const serviceTypes = Array.from(typeCounts.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);

  const svcPodCountMap = new Map<string, number>();
  for (const e of topoEdges) {
    if (e.relation === 'service-to-pod' && e.source.startsWith('service/')) {
      svcPodCountMap.set(e.source, (svcPodCountMap.get(e.source) || 0) + 1);
    }
  }

  let tlsCount = 0;
  let totalHosts = 0;
  let brokenBackendsCount = 0;

  const ingressRoutes: IngressRouteFlow[] = ingresses.map((ing) => {
    if (ing.tls) tlsCount += 1;
    totalHosts += asArray(ing.hosts).length;
    const ns = ing.namespace || 'default';
    let hasBrokenBackend = false;

    const backends = asArray(ing.backends).map((svcName) => {
      const svc = serviceByKey.get(`${ns}/${svcName}`);
      const readyEndpoints = svc ? svc.readyEndpoints : 0;
      const podCount = svcPodCountMap.get(`service/${ns}/${svcName}`) ?? 0;
      const hasHealthyEndpoints = Boolean(svc && readyEndpoints > 0);
      if (!hasHealthyEndpoints) {
        hasBrokenBackend = true;
        brokenBackendsCount += 1;
      }
      return {
        serviceName: svcName,
        serviceType: svc?.type || 'Missing',
        clusterIP: svc?.clusterIP || '—',
        readyEndpoints,
        podCount,
        hasHealthyEndpoints,
      };
    });

    return {
      ingress: ing,
      backends,
      hasBrokenBackend,
    };
  });

  return {
    readinessByKind,
    namespaceFootprint,
    serviceTypes,
    zeroEndpointServices,
    ingressPosture: {
      total: ingresses.length,
      tlsCount,
      httpOnlyCount: Math.max(0, ingresses.length - tlsCount),
      totalHosts,
      brokenBackendsCount,
    },
    ingressRoutes,
  };
}

export function buildVowVisualSummary(
  enabledAppIds: string[],
  resolvedAppIds: string[],
  autoDeps: string[],
  catalog: VowAppDefinition[],
  pulse: K3sClusterPulse | null | undefined
): VowVisualSummary {
  const catalogMap = new Map(catalog.map((a) => [a.id, a]));
  const explicitSet = new Set(enabledAppIds || []);
  const autoDepSet = new Set(autoDeps || []);
  const resolvedSet = new Set(resolvedAppIds || []);

  const catMap = new Map<string, { memoryMb: number; appCount: number }>();
  let totalStackMb = 0;

  for (const id of resolvedSet) {
    const app = catalogMap.get(id);
    if (!app) continue;
    totalStackMb += app.estimatedMemoryMb || 0;
    const entry = catMap.get(app.category) || { memoryMb: 0, appCount: 0 };
    entry.memoryMb += app.estimatedMemoryMb || 0;
    entry.appCount += 1;
    catMap.set(app.category, entry);
  }

  const memoryByCategory: VowCategoryMemoryDatum[] = Array.from(catMap.entries())
    .map(([category, info]) => ({
      category,
      memoryMb: info.memoryMb,
      memoryGb: safeRound(info.memoryMb / 1024, 2),
      appCount: info.appCount,
    }))
    .sort((a, b) => b.memoryMb - a.memoryMb);

  const hasLiveCluster = Boolean(pulse?.available && asArray(pulse?.nodes).length > 0);
  const cap = hasLiveCluster ? computeClusterCapacitySummary(pulse) : null;
  const clusterAllocatableGb = cap?.memAllocatableGiB ?? 0;
  const clusterUsedGb = cap?.memUsageGiB ?? 0;
  const clusterFreeGb = safeRound(Math.max(0, clusterAllocatableGb - clusterUsedGb), 1);
  const stackMemoryGb = safeRound(totalStackMb / 1024, 2);
  const projectedTotalPct =
    clusterAllocatableGb > 0
      ? Math.round(((clusterUsedGb + stackMemoryGb) / clusterAllocatableGb) * 100)
      : 0;
  const fitsInFreeRam = !hasLiveCluster || stackMemoryGb <= clusterFreeGb;

  // Match namespace pod counts from live cluster pulse
  const nsStatMap = new Map(asArray(pulse?.namespaceStats).map((n) => [n.name, n]));

  // Compute topological depth for dependency graph
  const depthMemo = new Map<string, number>();
  const visiting = new Set<string>();
  const getDepth = (id: string): number => {
    if (depthMemo.has(id)) return depthMemo.get(id)!;
    if (visiting.has(id)) return 0;
    visiting.add(id);
    const app = catalogMap.get(id);
    let maxParent = -1;
    if (app?.dependencies) {
      for (const dep of app.dependencies) {
        if (resolvedSet.has(dep)) {
          maxParent = Math.max(maxParent, getDepth(dep));
        }
      }
    }
    visiting.delete(id);
    const d = maxParent + 1;
    depthMemo.set(id, d);
    return d;
  };

  const depNodes: VowDependencyNode[] = [];
  const depEdges: Array<{ from: string; to: string }> = [];

  for (const id of resolvedSet) {
    const app = catalogMap.get(id);
    if (!app) continue;
    const ns = app.namespace || app.id;
    const nsInfo = nsStatMap.get(ns);
    depNodes.push({
      id: app.id,
      name: app.name,
      category: app.category,
      memoryMb: app.estimatedMemoryMb,
      isAutoDep: autoDepSet.has(app.id),
      isExplicit: explicitSet.has(app.id),
      namespace: ns,
      depth: getDepth(app.id),
      livePods: nsInfo?.podsRunning ?? 0,
      liveUnhealthy: nsInfo?.podsUnhealthy ?? 0,
    });
    if (app.dependencies) {
      for (const dep of app.dependencies) {
        if (resolvedSet.has(dep)) {
          depEdges.push({ from: dep, to: app.id });
        }
      }
    }
  }

  depNodes.sort((a, b) => a.depth - b.depth || a.name.localeCompare(b.name));

  return {
    memoryByCategory,
    ramBudget: {
      stackMemoryGb,
      clusterAllocatableGb,
      clusterUsedGb,
      clusterFreeGb,
      projectedTotalPct,
      fitsInFreeRam,
      hasLiveCluster,
    },
    dependencyGraph: {
      nodes: depNodes,
      edges: depEdges,
    },
  };
}
