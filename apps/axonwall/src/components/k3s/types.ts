export interface K3sNamedCount {
  name: string;
  count: number;
}

export interface K3sClusterCounts {
  nodesReady: number;
  nodesTotal: number;
  nodesCordoned: number;
  podsRunning: number;
  podsPending: number;
  podsFailed: number;
  podsSucceeded: number;
  podsUnknown: number;
  podsTotal: number;
  totalRestarts: number;
  deploymentsReady: number;
  deploymentsTotal: number;
  statefulSetsReady: number;
  statefulSetsTotal: number;
  daemonSetsReady: number;
  daemonSetsTotal: number;
  jobsActive: number;
  jobsSucceeded: number;
  jobsFailed: number;
  cronJobsTotal: number;
  servicesTotal: number;
  ingressesTotal: number;
  pvcsBound: number;
  pvcsTotal: number;
  pvsTotal: number;
  storageClassesTotal: number;
  namespacesTotal: number;
  configMapsTotal: number;
  secretsTotal: number;
  networkPoliciesTotal: number;
  hpasTotal: number;
  crdsTotal: number;
  warningEventsCount: number;
  normalEventsCount: number;
}

export interface K3sNamespacePulse {
  name: string;
  status: string;
  podsRunning: number;
  podsUnhealthy: number;
  podsTotal: number;
  services: number;
  ingresses: number;
  pvcs: number;
}

export interface K3sNodeCondition {
  type: string;
  status: string;
  reason?: string;
  message?: string;
}

export interface K3sNodeTaint {
  key: string;
  value?: string;
  effect: string;
}

export interface K3sNodePulse {
  name: string;
  status: string;
  roles: string;
  internalIp: string;
  version: string;
  osImage: string;
  kernelVersion: string;
  containerRuntime: string;
  unschedulable: boolean;
  creationTimestamp: string;
  podCount: number;
  podCapacity: number;
  cpuCapacityMillis: number;
  cpuAllocatableMillis: number;
  cpuRequestsMillis: number;
  cpuLimitsMillis: number;
  cpuUsageMillis?: number | null;
  memCapacityBytes: number;
  memAllocatableBytes: number;
  memRequestsBytes: number;
  memLimitsBytes: number;
  memUsageBytes?: number | null;
  conditions: K3sNodeCondition[];
  taints: K3sNodeTaint[];
  labels?: Record<string, string>;
}

export interface K3sStorageClassUsage {
  name: string;
  provisioner: string;
  pvcCount: number;
  boundCount: number;
  totalBytes: number;
  isDefault: boolean;
}

export interface K3sPodHotspot {
  name: string;
  namespace: string;
  restarts: number;
  status: string;
  nodeName: string;
  cpuMillis?: number | null;
  memBytes?: number | null;
  creationTimestamp: string;
}

export interface K3sEventItem {
  type: string;
  reason: string;
  namespace: string;
  involvedKind: string;
  involvedName: string;
  message: string;
  count: number;
  lastTimestamp: string;
  source: string;
}

export interface K3sWorkloadSummary {
  kind: string;
  resource: string;
  name: string;
  namespace: string;
  ready: number;
  desired: number;
  available: number;
  images?: string[];
  creationTimestamp: string;
}

export interface K3sServiceSummary {
  name: string;
  namespace: string;
  type: string;
  clusterIP: string;
  externalIP: string;
  ports?: string[];
  readyEndpoints: number;
  creationTimestamp: string;
}

export interface K3sIngressSummary {
  name: string;
  namespace: string;
  class: string;
  hosts?: string[];
  address: string;
  tls: boolean;
  backends?: string[];
  creationTimestamp: string;
}

export interface K3sPvcSummary {
  name: string;
  namespace: string;
  status: string;
  volumeName: string;
  capacity: string;
  capacityBytes: number;
  accessModes?: string[];
  storageClass: string;
  creationTimestamp: string;
}

export type TopologyNodeKind =
  | 'Ingress'
  | 'Service'
  | 'Deployment'
  | 'StatefulSet'
  | 'DaemonSet'
  | 'Job'
  | 'Pod'
  | 'Node'
  | 'PVC';

export type StatusTone = 'ok' | 'warn' | 'err' | 'info' | 'muted';

export interface K3sTopologyNode {
  id: string;
  kind: TopologyNodeKind | string;
  resource: string;
  name: string;
  namespace?: string;
  status: string;
  statusTone: StatusTone | string;
  subtitle?: string;
  parentNodeName?: string;
  meta?: Record<string, string>;
}

export interface K3sTopologyEdge {
  id: string;
  source: string;
  target: string;
  relation:
    | 'ingress-to-service'
    | 'service-to-pod'
    | 'workload-to-pod'
    | 'pod-to-node'
    | 'pod-to-pvc'
    | string;
  label?: string;
}

export interface K3sTopologyGraph {
  nodes: K3sTopologyNode[];
  edges: K3sTopologyEdge[];
}

export interface K3sClusterPulse {
  available: boolean;
  error?: string;
  timestamp: string;
  metricsAvailable: boolean;
  cniPlugin: string;
  k3sVersion: string;
  counts: K3sClusterCounts;
  podPhaseDistribution: K3sNamedCount[];
  namespaceStats: K3sNamespacePulse[];
  nodes: K3sNodePulse[];
  storageByClass: K3sStorageClassUsage[];
  topRestartingPods: K3sPodHotspot[];
  topResourcePods: K3sPodHotspot[];
  recentEvents: K3sEventItem[];
  workloadsSummary: K3sWorkloadSummary[];
  servicesSummary: K3sServiceSummary[];
  ingressesSummary: K3sIngressSummary[];
  pvcsSummary: K3sPvcSummary[];
  topology: K3sTopologyGraph;
}

export interface K3sAPIResource {
  name: string;
  shortNames: string[];
  apiVersion: string;
  namespaced: boolean;
  kind: string;
  verbs: string[];
}

export interface K3sNamespaceSummary {
  name: string;
  status: string;
  creationTimestamp: string;
  labels?: Record<string, string>;
  podCount: number;
}

export interface K3sResourceItem {
  uid: string;
  name: string;
  namespace?: string;
  kind: string;
  apiVersion: string;
  creationTimestamp: string;
  status: string;
  statusTone: StatusTone | string;
  labels?: Record<string, string>;
  ownerRef?: string;
  summary: Record<string, any>;
}

export interface K3sResourceListResponse {
  resource: string;
  namespace: string;
  namespaced: boolean;
  items: K3sResourceItem[];
  count: number;
  error?: string;
}

export interface K3sRelatedResource {
  relation: string;
  kind: string;
  resource: string;
  name: string;
  namespace?: string;
  status?: string;
  statusTone?: StatusTone | string;
  detail?: string;
}

export interface K3sResourceInspectResponse {
  resource: string;
  kind: string;
  apiVersion: string;
  name: string;
  namespace?: string;
  object: Record<string, any>;
  yaml: string;
  describe: string;
  events: K3sEventItem[];
  related: K3sRelatedResource[];
  decodedSecretData?: Record<string, string>;
  secretRedacted?: boolean;
  error?: string;
}

export interface K3sLogsResponse {
  logs: string;
  linesCount: number;
  truncated: boolean;
  container?: string;
  previous: boolean;
  error?: string;
}

export type K3sActionType =
  | 'delete'
  | 'scale'
  | 'rollout-restart'
  | 'rollout-undo'
  | 'cordon'
  | 'uncordon'
  | 'drain'
  | 'trigger-cronjob'
  | 'suspend-cronjob'
  | 'apply-yaml'
  | 'exec';

export interface K3sActionRequest {
  action: K3sActionType;
  resource?: string;
  namespace?: string;
  name?: string;
  replicas?: number;
  suspend?: boolean;
  force?: boolean;
  dryRun?: boolean;
  yaml?: string;
  container?: string;
  command?: string;
}

export interface K3sActionResponse {
  success: boolean;
  message: string;
  output?: string;
  exitCode: number;
  latencyMs?: number;
}

// --- K9s Built-In Resource Catalog ---

export type K9sResourceGroupName =
  | 'Workloads'
  | 'Network'
  | 'Storage'
  | 'Config'
  | 'Cluster'
  | 'RBAC'
  | 'CRDs';

export interface K9sResourceDef {
  id: string; // canonical plural resource arg sent to kubectl
  label: string;
  kind: string;
  shortName: string;
  aliases: string[];
  group: K9sResourceGroupName;
  namespaced: boolean;
  supportsLogs?: boolean;
  supportsExec?: boolean;
  supportsScale?: boolean;
  supportsRestart?: boolean;
  supportsCordon?: boolean;
  supportsCronJob?: boolean;
  supportsDecode?: boolean;
}

export const K9S_RESOURCE_CATALOG: K9sResourceDef[] = [
  // Workloads
  {
    id: 'pods',
    label: 'Pods',
    kind: 'Pod',
    shortName: 'po',
    aliases: ['po', 'pod', 'pods'],
    group: 'Workloads',
    namespaced: true,
    supportsLogs: true,
    supportsExec: true,
  },
  {
    id: 'deployments',
    label: 'Deployments',
    kind: 'Deployment',
    shortName: 'deploy',
    aliases: ['deploy', 'deployment', 'deployments', 'dp'],
    group: 'Workloads',
    namespaced: true,
    supportsLogs: true,
    supportsScale: true,
    supportsRestart: true,
  },
  {
    id: 'statefulsets',
    label: 'StatefulSets',
    kind: 'StatefulSet',
    shortName: 'sts',
    aliases: ['sts', 'statefulset', 'statefulsets'],
    group: 'Workloads',
    namespaced: true,
    supportsLogs: true,
    supportsScale: true,
    supportsRestart: true,
  },
  {
    id: 'daemonsets',
    label: 'DaemonSets',
    kind: 'DaemonSet',
    shortName: 'ds',
    aliases: ['ds', 'daemonset', 'daemonsets'],
    group: 'Workloads',
    namespaced: true,
    supportsLogs: true,
    supportsRestart: true,
  },
  {
    id: 'replicasets',
    label: 'ReplicaSets',
    kind: 'ReplicaSet',
    shortName: 'rs',
    aliases: ['rs', 'replicaset', 'replicasets'],
    group: 'Workloads',
    namespaced: true,
    supportsScale: true,
  },
  {
    id: 'jobs',
    label: 'Jobs',
    kind: 'Job',
    shortName: 'job',
    aliases: ['job', 'jobs'],
    group: 'Workloads',
    namespaced: true,
    supportsLogs: true,
  },
  {
    id: 'cronjobs',
    label: 'CronJobs',
    kind: 'CronJob',
    shortName: 'cj',
    aliases: ['cj', 'cronjob', 'cronjobs'],
    group: 'Workloads',
    namespaced: true,
    supportsCronJob: true,
  },

  // Network
  {
    id: 'services',
    label: 'Services',
    kind: 'Service',
    shortName: 'svc',
    aliases: ['svc', 'service', 'services'],
    group: 'Network',
    namespaced: true,
  },
  {
    id: 'ingresses',
    label: 'Ingresses',
    kind: 'Ingress',
    shortName: 'ing',
    aliases: ['ing', 'ingress', 'ingresses'],
    group: 'Network',
    namespaced: true,
  },
  {
    id: 'endpoints',
    label: 'Endpoints',
    kind: 'Endpoints',
    shortName: 'ep',
    aliases: ['ep', 'endpoint', 'endpoints'],
    group: 'Network',
    namespaced: true,
  },
  {
    id: 'networkpolicies',
    label: 'NetworkPolicies',
    kind: 'NetworkPolicy',
    shortName: 'netpol',
    aliases: ['netpol', 'np', 'networkpolicy', 'networkpolicies'],
    group: 'Network',
    namespaced: true,
  },

  // Storage
  {
    id: 'persistentvolumeclaims',
    label: 'PV Claims (PVC)',
    kind: 'PersistentVolumeClaim',
    shortName: 'pvc',
    aliases: ['pvc', 'persistentvolumeclaim', 'persistentvolumeclaims'],
    group: 'Storage',
    namespaced: true,
  },
  {
    id: 'persistentvolumes',
    label: 'PersistentVolumes',
    kind: 'PersistentVolume',
    shortName: 'pv',
    aliases: ['pv', 'persistentvolume', 'persistentvolumes'],
    group: 'Storage',
    namespaced: false,
  },
  {
    id: 'storageclasses',
    label: 'StorageClasses',
    kind: 'StorageClass',
    shortName: 'sc',
    aliases: ['sc', 'storageclass', 'storageclasses'],
    group: 'Storage',
    namespaced: false,
  },

  // Config & Autoscaling
  {
    id: 'configmaps',
    label: 'ConfigMaps',
    kind: 'ConfigMap',
    shortName: 'cm',
    aliases: ['cm', 'configmap', 'configmaps'],
    group: 'Config',
    namespaced: true,
  },
  {
    id: 'secrets',
    label: 'Secrets',
    kind: 'Secret',
    shortName: 'sec',
    aliases: ['sec', 'secret', 'secrets'],
    group: 'Config',
    namespaced: true,
    supportsDecode: true,
  },
  {
    id: 'horizontalpodautoscalers',
    label: 'HPAs',
    kind: 'HorizontalPodAutoscaler',
    shortName: 'hpa',
    aliases: ['hpa', 'horizontalpodautoscaler', 'horizontalpodautoscalers'],
    group: 'Config',
    namespaced: true,
  },

  // Cluster
  {
    id: 'nodes',
    label: 'Nodes',
    kind: 'Node',
    shortName: 'no',
    aliases: ['no', 'node', 'nodes'],
    group: 'Cluster',
    namespaced: false,
    supportsCordon: true,
  },
  {
    id: 'namespaces',
    label: 'Namespaces',
    kind: 'Namespace',
    shortName: 'ns',
    aliases: ['ns', 'namespace', 'namespaces'],
    group: 'Cluster',
    namespaced: false,
  },
  {
    id: 'events',
    label: 'Events',
    kind: 'Event',
    shortName: 'ev',
    aliases: ['ev', 'event', 'events'],
    group: 'Cluster',
    namespaced: true,
  },

  // RBAC
  {
    id: 'serviceaccounts',
    label: 'ServiceAccounts',
    kind: 'ServiceAccount',
    shortName: 'sa',
    aliases: ['sa', 'serviceaccount', 'serviceaccounts'],
    group: 'RBAC',
    namespaced: true,
  },
  {
    id: 'roles',
    label: 'Roles',
    kind: 'Role',
    shortName: 'role',
    aliases: ['role', 'roles'],
    group: 'RBAC',
    namespaced: true,
  },
  {
    id: 'rolebindings',
    label: 'RoleBindings',
    kind: 'RoleBinding',
    shortName: 'rb',
    aliases: ['rb', 'rolebinding', 'rolebindings'],
    group: 'RBAC',
    namespaced: true,
  },
  {
    id: 'clusterroles',
    label: 'ClusterRoles',
    kind: 'ClusterRole',
    shortName: 'cr',
    aliases: ['cr', 'clusterrole', 'clusterroles'],
    group: 'RBAC',
    namespaced: false,
  },
  {
    id: 'clusterrolebindings',
    label: 'ClusterRoleBindings',
    kind: 'ClusterRoleBinding',
    shortName: 'crb',
    aliases: ['crb', 'clusterrolebinding', 'clusterrolebindings'],
    group: 'RBAC',
    namespaced: false,
  },

  // CRDs
  {
    id: 'customresourcedefinitions',
    label: 'CRDs',
    kind: 'CustomResourceDefinition',
    shortName: 'crd',
    aliases: ['crd', 'crds', 'customresourcedefinition', 'customresourcedefinitions'],
    group: 'CRDs',
    namespaced: false,
  },
];

export const K9S_RESOURCE_GROUPS: K9sResourceGroupName[] = [
  'Workloads',
  'Network',
  'Storage',
  'Config',
  'Cluster',
  'RBAC',
  'CRDs',
];

export const K9S_RESOURCE_MAP: Record<string, K9sResourceDef> = Object.fromEntries(
  K9S_RESOURCE_CATALOG.map((r) => [r.id, r])
);

export const K9S_ALIAS_MAP: Record<string, string> = (() => {
  const m: Record<string, string> = {};
  for (const r of K9S_RESOURCE_CATALOG) {
    m[r.id] = r.id;
    m[r.shortName] = r.id;
    m[r.kind.toLowerCase()] = r.id;
    for (const a of r.aliases) {
      m[a.toLowerCase()] = r.id;
    }
  }
  return m;
})();

export function resolveK9sResourceAlias(input: string): string {
  const clean = input.trim().toLowerCase();
  return K9S_ALIAS_MAP[clean] || clean;
}

// --- Shared Pure UI Formatting Helpers ---

export function formatAge(isoTimestamp?: string): string {
  if (!isoTimestamp) return '—';
  const parsed = Date.parse(isoTimestamp);
  if (Number.isNaN(parsed)) return '—';
  const diffSec = Math.max(0, Math.floor((Date.now() - parsed) / 1000));
  if (diffSec < 60) return `${diffSec}s`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 48) return `${diffHr}h`;
  const diffDays = Math.floor(diffHr / 24);
  return `${diffDays}d`;
}

export function formatCpuMillis(millis?: number | null): string {
  if (millis === null || millis === undefined || Number.isNaN(millis)) return 'N/A';
  if (millis >= 1000) {
    const cores = millis / 1000;
    return Number.isInteger(cores) ? `${cores} cores` : `${cores.toFixed(2)} cores`;
  }
  return `${Math.round(millis)}m`;
}

export function formatBytes(bytes?: number | null): string {
  if (bytes === null || bytes === undefined || Number.isNaN(bytes)) return 'N/A';
  if (bytes === 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let idx = 0;
  let val = bytes;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  return val >= 10 || idx === 0 ? `${val.toFixed(0)} ${units[idx]}` : `${val.toFixed(1)} ${units[idx]}`;
}

export function getStatusBadgeClass(tone?: string): string {
  switch (tone) {
    case 'ok':
      return 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30';
    case 'warn':
      return 'bg-amber-500/15 text-amber-300 border-amber-500/30';
    case 'err':
      return 'bg-rose-500/15 text-rose-300 border-rose-500/30';
    case 'info':
      return 'bg-sky-500/15 text-sky-300 border-sky-500/30';
    default:
      return 'bg-slate-800/80 text-slate-300 border-slate-700';
  }
}
