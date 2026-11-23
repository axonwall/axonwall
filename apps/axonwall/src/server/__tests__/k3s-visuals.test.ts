import { describe, expect, it } from 'vitest';
import type { VowAppDefinition } from '@axonwall/lib/compile/vow';
import type { K3sClusterPulse, K3sTopologyEdge, K3sTopologyNode } from '@/components/k3s/types';
import {
  GIB,
  MIB,
  appendPulseHistory,
  buildEventReasonBreakdown,
  buildNodeBinPackingData,
  buildPodResourceHotspots,
  buildStorageVolumeGraph,
  buildVowVisualSummary,
  buildWorkloadsVisualSummary,
  computeClusterCapacitySummary,
  orderTopologyColumnsBarycenter,
} from '@/lib/k3s-visuals';

function makeSamplePulse(overrides: Partial<K3sClusterPulse> = {}): K3sClusterPulse {
  return {
    available: true,
    timestamp: '2026-11-23T03:00:00Z',
    metricsAvailable: true,
    cniPlugin: 'flannel',
    k3sVersion: 'v1.32.3+k3s1',
    counts: {
      nodesReady: 2,
      nodesTotal: 3,
      nodesCordoned: 1,
      podsRunning: 4,
      podsPending: 1,
      podsFailed: 1,
      podsSucceeded: 0,
      podsUnknown: 0,
      podsTotal: 6,
      totalRestarts: 7,
      deploymentsReady: 2,
      deploymentsTotal: 3,
      statefulSetsReady: 1,
      statefulSetsTotal: 1,
      daemonSetsReady: 1,
      daemonSetsTotal: 1,
      jobsActive: 0,
      jobsSucceeded: 2,
      jobsFailed: 1,
      cronJobsTotal: 1,
      servicesTotal: 3,
      ingressesTotal: 2,
      pvcsBound: 1,
      pvcsTotal: 3,
      pvsTotal: 2,
      storageClassesTotal: 2,
      namespacesTotal: 3,
      configMapsTotal: 5,
      secretsTotal: 5,
      networkPoliciesTotal: 1,
      hpasTotal: 0,
      crdsTotal: 10,
      warningEventsCount: 3,
      normalEventsCount: 4,
    },
    podPhaseDistribution: [
      { name: 'Running', count: 4 },
      { name: 'Pending', count: 1 },
      { name: 'Failed', count: 1 },
    ],
    namespaceStats: [
      { name: 'app-ns', status: 'Active', podsRunning: 3, podsUnhealthy: 1, podsTotal: 4, services: 2, ingresses: 1, pvcs: 2 },
      { name: 'db-ns', status: 'Active', podsRunning: 1, podsUnhealthy: 1, podsTotal: 2, services: 1, ingresses: 1, pvcs: 1 },
    ],
    nodes: [
      {
        name: 'klaxon',
        status: 'Ready',
        roles: 'control-plane,etcd,master',
        internalIp: '10.80.0.202',
        version: 'v1.32.3+k3s1',
        osImage: 'Debian',
        kernelVersion: '6.12',
        containerRuntime: 'containerd://2.0',
        unschedulable: false,
        creationTimestamp: '2026-11-18T00:00:00Z',
        podCount: 3,
        podCapacity: 110,
        cpuCapacityMillis: 4000,
        cpuAllocatableMillis: 4000,
        cpuRequestsMillis: 1500,
        cpuLimitsMillis: 6000,
        cpuUsageMillis: 1000,
        memCapacityBytes: 8 * GIB,
        memAllocatableBytes: 8 * GIB,
        memRequestsBytes: 4 * GIB,
        memLimitsBytes: 10 * GIB,
        memUsageBytes: 2 * GIB,
        conditions: [
          { type: 'Ready', status: 'True', reason: 'KubeletReady' },
          { type: 'EtcdIsVoter', status: 'True', reason: 'MemberNotLearner' },
          { type: 'MemoryPressure', status: 'False', reason: 'KubeletHasSufficientMemory' },
          { type: 'DiskPressure', status: 'False', reason: 'KubeletHasNoDiskPressure' },
          { type: 'PIDPressure', status: 'False', reason: 'KubeletHasSufficientPID' },
        ],
        taints: [],
      },
      {
        name: 'saxon',
        status: 'Ready',
        roles: 'control-plane,etcd,master',
        internalIp: '10.80.0.203',
        version: 'v1.32.3+k3s1',
        osImage: 'Debian',
        kernelVersion: '6.12',
        containerRuntime: 'containerd://2.0',
        unschedulable: false,
        creationTimestamp: '2026-11-18T00:00:00Z',
        podCount: 3,
        podCapacity: 110,
        cpuCapacityMillis: 4000,
        cpuAllocatableMillis: 4000,
        cpuRequestsMillis: 1000,
        cpuLimitsMillis: 2000,
        cpuUsageMillis: 1000,
        memCapacityBytes: 8 * GIB,
        memAllocatableBytes: 8 * GIB,
        memRequestsBytes: 2 * GIB,
        memLimitsBytes: 4 * GIB,
        memUsageBytes: 2 * GIB,
        conditions: [
          { type: 'Ready', status: 'True', reason: 'KubeletReady' },
          { type: 'EtcdIsVoter', status: 'True', reason: 'MemberNotLearner' },
        ],
        taints: [],
      },
      {
        name: 'offline-worker',
        status: 'NotReady',
        roles: 'worker',
        internalIp: '10.80.0.299',
        version: 'v1.32.3+k3s1',
        osImage: 'Debian',
        kernelVersion: '6.12',
        containerRuntime: 'containerd://2.0',
        unschedulable: true,
        creationTimestamp: '2026-11-18T00:00:00Z',
        podCount: 0,
        podCapacity: 110,
        cpuCapacityMillis: 4000,
        cpuAllocatableMillis: 4000,
        cpuRequestsMillis: 0,
        cpuLimitsMillis: 0,
        cpuUsageMillis: 0,
        memCapacityBytes: 8 * GIB,
        memAllocatableBytes: 8 * GIB,
        memRequestsBytes: 0,
        memLimitsBytes: 0,
        memUsageBytes: 0,
        conditions: [{ type: 'Ready', status: 'False', reason: 'NodeStatusUnknown' }],
        taints: [{ key: 'node.kubernetes.io/unreachable', effect: 'NoSchedule' }],
      },
    ],
    storageByClass: [
      { name: 'openebs-lvmpv', provisioner: 'zfs.csi.openebs.io', pvcCount: 2, boundCount: 1, totalBytes: 30 * GIB, isDefault: false },
      { name: 'axonwall-replicated-ha', provisioner: 'io.openebs.csi-mayastor', pvcCount: 1, boundCount: 0, totalBytes: 10 * GIB, isDefault: true },
    ],
    topRestartingPods: [
      { name: 'api-0', namespace: 'app-ns', restarts: 5, status: 'CrashLoopBackOff', nodeName: 'klaxon', cpuMillis: 250, memBytes: 256 * MIB, creationTimestamp: '' },
    ],
    topResourcePods: [
      { name: 'api-0', namespace: 'app-ns', restarts: 5, status: 'CrashLoopBackOff', nodeName: 'klaxon', cpuMillis: 300, memBytes: 512 * MIB, creationTimestamp: '' },
      { name: 'db-0', namespace: 'db-ns', restarts: 0, status: 'Running', nodeName: 'saxon', cpuMillis: 450, memBytes: 1024 * MIB, creationTimestamp: '' },
    ],
    recentEvents: [
      { type: 'Warning', reason: 'BackOff', namespace: 'app-ns', involvedKind: 'Pod', involvedName: 'api-0', message: 'Back-off restarting', count: 12, lastTimestamp: '', source: 'kubelet' },
      { type: 'Normal', reason: 'Started', namespace: 'db-ns', involvedKind: 'Pod', involvedName: 'db-0', message: 'Started container', count: 1, lastTimestamp: '', source: 'kubelet' },
      { type: 'Normal', reason: 'Started', namespace: 'app-ns', involvedKind: 'Pod', involvedName: 'web-0', message: 'Started container', count: 2, lastTimestamp: '', source: 'kubelet' },
    ],
    workloadsSummary: [
      { kind: 'Deployment', resource: 'deployments', name: 'web', namespace: 'app-ns', ready: 1, desired: 1, available: 1, creationTimestamp: '' },
      { kind: 'Deployment', resource: 'deployments', name: 'worker', namespace: 'app-ns', ready: 0, desired: 1, available: 0, creationTimestamp: '' },
      { kind: 'StatefulSet', resource: 'statefulsets', name: 'db', namespace: 'db-ns', ready: 1, desired: 1, available: 1, creationTimestamp: '' },
    ],
    servicesSummary: [
      { name: 'web', namespace: 'app-ns', type: 'ClusterIP', clusterIP: '10.43.0.10', externalIP: '', ports: ['80/TCP'], readyEndpoints: 2, creationTimestamp: '' },
      { name: 'dead-svc', namespace: 'app-ns', type: 'LoadBalancer', clusterIP: '10.43.0.11', externalIP: '', ports: ['443/TCP'], readyEndpoints: 0, creationTimestamp: '' },
      { name: 'db', namespace: 'db-ns', type: 'ClusterIP', clusterIP: '10.43.0.12', externalIP: '', ports: ['5432/TCP'], readyEndpoints: 1, creationTimestamp: '' },
    ],
    ingressesSummary: [
      { name: 'web-ing', namespace: 'app-ns', class: 'nginx', hosts: ['app.local'], address: '10.80.0.200', tls: true, backends: ['web'], creationTimestamp: '' },
      { name: 'broken-ing', namespace: 'app-ns', class: 'nginx', hosts: ['broken.local'], address: '', tls: false, backends: ['dead-svc'], creationTimestamp: '' },
    ],
    pvcsSummary: [
      { name: 'db-data', namespace: 'db-ns', status: 'Bound', volumeName: 'pv-1', capacity: '20Gi', capacityBytes: 20 * GIB, accessModes: ['RWO'], storageClass: 'openebs-lvmpv', creationTimestamp: '' },
      { name: 'orphaned-vol', namespace: 'app-ns', status: 'Bound', volumeName: 'pv-2', capacity: '10Gi', capacityBytes: 10 * GIB, accessModes: ['RWO'], storageClass: 'openebs-lvmpv', creationTimestamp: '' },
      { name: 'pending-vol', namespace: 'app-ns', status: 'Pending', volumeName: '', capacity: '10Gi', capacityBytes: 10 * GIB, accessModes: ['RWO'], storageClass: 'axonwall-replicated-ha', creationTimestamp: '' },
    ],
    topology: {
      nodes: [
        { id: 'ingress/app-ns/web-ing', kind: 'Ingress', resource: 'ingresses', name: 'web-ing', namespace: 'app-ns', status: 'TLS', statusTone: 'info' },
        { id: 'service/app-ns/web', kind: 'Service', resource: 'services', name: 'web', namespace: 'app-ns', status: 'ClusterIP', statusTone: 'ok' },
        { id: 'service/app-ns/dead-svc', kind: 'Service', resource: 'services', name: 'dead-svc', namespace: 'app-ns', status: 'NoEndpoints', statusTone: 'warn' },
        { id: 'deployment/app-ns/web', kind: 'Deployment', resource: 'deployments', name: 'web', namespace: 'app-ns', status: '1/1', statusTone: 'ok' },
        { id: 'pod/app-ns/web-0', kind: 'Pod', resource: 'pods', name: 'web-0', namespace: 'app-ns', status: 'Running', statusTone: 'ok', parentNodeName: 'klaxon' },
        { id: 'pod/app-ns/api-0', kind: 'Pod', resource: 'pods', name: 'api-0', namespace: 'app-ns', status: 'CrashLoopBackOff', statusTone: 'err', subtitle: '↻ 5 • 250m', parentNodeName: 'klaxon' },
        { id: 'pod/db-ns/db-0', kind: 'Pod', resource: 'pods', name: 'db-0', namespace: 'db-ns', status: 'Running', statusTone: 'ok', parentNodeName: 'saxon' },
        { id: 'node/klaxon', kind: 'Node', resource: 'nodes', name: 'klaxon', status: 'Ready', statusTone: 'ok' },
        { id: 'node/saxon', kind: 'Node', resource: 'nodes', name: 'saxon', status: 'Ready', statusTone: 'ok' },
        { id: 'pvc/db-ns/db-data', kind: 'PVC', resource: 'persistentvolumeclaims', name: 'db-data', namespace: 'db-ns', status: 'Bound', statusTone: 'ok' },
        { id: 'pvc/app-ns/orphaned-vol', kind: 'PVC', resource: 'persistentvolumeclaims', name: 'orphaned-vol', namespace: 'app-ns', status: 'Bound', statusTone: 'ok' },
      ],
      edges: [
        { id: 'e1', source: 'ingress/app-ns/web-ing', target: 'service/app-ns/web', relation: 'ingress-to-service' },
        { id: 'e2', source: 'service/app-ns/web', target: 'pod/app-ns/web-0', relation: 'service-to-pod' },
        { id: 'e3', source: 'deployment/app-ns/web', target: 'pod/app-ns/web-0', relation: 'workload-to-pod' },
        { id: 'e4', source: 'pod/app-ns/web-0', target: 'node/klaxon', relation: 'pod-to-node' },
        { id: 'e5', source: 'pod/app-ns/api-0', target: 'node/klaxon', relation: 'pod-to-node' },
        { id: 'e6', source: 'pod/db-ns/db-0', target: 'node/saxon', relation: 'pod-to-node' },
        { id: 'e7', source: 'pod/db-ns/db-0', target: 'pvc/db-ns/db-data', relation: 'pod-to-pvc' },
      ],
    },
    ...overrides,
  };
}

describe('k3s-visuals helpers', () => {
  it('handles nullish/malformed pulse slices without throwing', () => {
    const broken = {
      available: true,
      timestamp: '2026-11-23T03:00:00Z',
      metricsAvailable: false,
      cniPlugin: 'flannel',
      k3sVersion: 'v1.32.3',
      counts: {} as any,
      podPhaseDistribution: null as any,
      namespaceStats: null as any,
      nodes: null as any,
      storageByClass: null as any,
      topRestartingPods: null as any,
      topResourcePods: null as any,
      recentEvents: null as any,
      workloadsSummary: null as any,
      servicesSummary: null as any,
      ingressesSummary: null as any,
      pvcsSummary: null as any,
      topology: null as any,
    } satisfies K3sClusterPulse;

    const cap = computeClusterCapacitySummary(broken);
    expect(cap.nodesTotal).toBe(0);
    expect(cap.cpuUsagePct).toBe(0);
    expect(buildEventReasonBreakdown(broken.recentEvents)).toEqual([]);
    expect(buildPodResourceHotspots(broken.topResourcePods, broken.topRestartingPods).all).toEqual([]);
    expect(buildNodeBinPackingData(broken)).toEqual([]);
    expect(buildStorageVolumeGraph(broken).attachments).toEqual([]);
    expect(buildWorkloadsVisualSummary(broken).ingressRoutes).toEqual([]);
    expect(orderTopologyColumnsBarycenter(null, null).visibleNodes).toEqual([]);
  });

  it('computes capacity summary, overcommit percentages, Etcd voters, and attention items', () => {
    const pulse = makeSamplePulse();
    const cap = computeClusterCapacitySummary(pulse);

    expect(cap.cpuAllocatableCores).toBe(12);
    expect(cap.cpuUsageCores).toBe(2);
    expect(cap.cpuUsagePct).toBe(17);
    expect(cap.memAllocatableGiB).toBe(24);
    expect(cap.memUsageGiB).toBe(4);
    expect(cap.memLimitPct).toBe(58);
    expect(cap.etcdVotersTotal).toBe(2);
    expect(cap.etcdVotersReady).toBe(2);
    // Schedulable pod capacity excludes offline-worker (NotReady + unschedulable)
    expect(cap.podCapacityAll).toBe(330);
    expect(cap.podCapacitySchedulable).toBe(220);
    expect(cap.totalStorageGiB).toBe(40);
    expect(cap.attentionItems.map((a) => a.label)).toEqual([
      '1 node NotReady',
      '1 pod Failed/Unknown',
      '1 pod Pending',
      '1 degraded workload',
      '2 unbound PVCs',
      '1 services with 0 endpoints',
    ]);
  });

  it('deduplicates and caps pulse history ring buffer', () => {
    const p1 = makeSamplePulse({ timestamp: '2026-11-23T03:00:00Z' });
    const p2 = makeSamplePulse({ timestamp: '2026-11-23T03:00:05Z' });
    const p3 = makeSamplePulse({ timestamp: '2026-11-23T03:00:10Z' });

    let hist = appendPulseHistory([], p1, 2);
    expect(hist).toHaveLength(1);
    // Duplicate timestamp ignored
    hist = appendPulseHistory(hist, p1, 2);
    expect(hist).toHaveLength(1);
    hist = appendPulseHistory(hist, p2, 2);
    expect(hist).toHaveLength(2);
    hist = appendPulseHistory(hist, p3, 2);
    expect(hist).toHaveLength(2);
    expect(hist[0].timestamp).toBe('2026-11-23T03:00:05Z');
    expect(hist[1].timestamp).toBe('2026-11-23T03:00:10Z');
  });

  it('prioritizes Warning events in EventReasonBreakdown', () => {
    const pulse = makeSamplePulse();
    const breakdown = buildEventReasonBreakdown(pulse.recentEvents);
    expect(breakdown[0].reason).toBe('BackOff');
    expect(breakdown[0].warningCount).toBe(1);
    expect(breakdown[0].totalEvents).toBe(12);
    expect(breakdown[1].reason).toBe('Started');
    expect(breakdown[1].rowCount).toBe(2);
  });

  it('merges pod hotspots cleanly and builds node bin-packing buckets', () => {
    const pulse = makeSamplePulse();
    const hotspots = buildPodResourceHotspots(pulse.topResourcePods, pulse.topRestartingPods);
    expect(hotspots.byCpu[0].id).toBe('db-ns/db-0');
    expect(hotspots.byCpu[1].restarts).toBe(5);
    expect(hotspots.scatterPoints).toHaveLength(2);

    const allBuckets = buildNodeBinPackingData(pulse);
    expect(allBuckets).toHaveLength(3);
    const saxonBucket = allBuckets.find((b) => b.nodeName === 'saxon')!;
    expect(saxonBucket.pods[0].pvcNames).toEqual(['db-data']);

    const issuesOnly = buildNodeBinPackingData(pulse, { issuesOnly: true });
    expect(issuesOnly.some((b) => b.nodeName === 'saxon')).toBe(false);
    const klaxonIssues = issuesOnly.find((b) => b.nodeName === 'klaxon')!;
    expect(klaxonIssues.pods.map((p) => p.name)).toEqual(['api-0']);
  });

  it('orders topology columns and respects hideIsolated and issuesOnly filters', () => {
    const pulse = makeSamplePulse();
    const nodes: K3sTopologyNode[] = pulse.topology.nodes;
    const edges: K3sTopologyEdge[] = pulse.topology.edges;

    const full = orderTopologyColumnsBarycenter(nodes, edges);
    expect(full.ingresses).toHaveLength(1);
    expect(full.pods).toHaveLength(3);

    const noIso = orderTopologyColumnsBarycenter(nodes, edges, { hideIsolated: true });
    expect(noIso.visibleNodes.some((n) => n.name === 'dead-svc')).toBe(false);
    expect(noIso.visibleNodes.some((n) => n.name === 'orphaned-vol')).toBe(false);

    const issues = orderTopologyColumnsBarycenter(nodes, edges, { issuesOnly: true });
    // api-0 is err + its 1-hop node/klaxon; dead-svc is warn
    expect(issues.visibleNodes.some((n) => n.name === 'api-0')).toBe(true);
    expect(issues.visibleNodes.some((n) => n.name === 'dead-svc')).toBe(true);
    expect(issues.visibleNodes.some((n) => n.name === 'web-ing')).toBe(false);
  });

  it('builds storage volume attachment graph flagging pending & orphaned PVCs', () => {
    const sg = buildStorageVolumeGraph(makeSamplePulse());
    expect(sg.totalGiB).toBe(40);
    expect(sg.boundCount).toBe(2);
    expect(sg.pendingCount).toBe(1);
    expect(sg.attachedCount).toBe(1);
    expect(sg.orphanedCount).toBe(1);

    const dbData = sg.attachments.find((a) => a.name === 'db-data')!;
    expect(dbData.pods).toHaveLength(1);
    expect(dbData.pods[0].nodeName).toBe('saxon');

    const orphan = sg.attachments.find((a) => a.name === 'orphaned-vol')!;
    expect(orphan.isOrphaned).toBe(true);
  });

  it('builds workloads visual summary including zero-endpoint services and ingress chains', () => {
    const ws = buildWorkloadsVisualSummary(makeSamplePulse());
    expect(ws.zeroEndpointServices.map((s) => s.name)).toEqual(['dead-svc']);
    expect(ws.ingressPosture).toEqual({
      total: 2,
      tlsCount: 1,
      httpOnlyCount: 1,
      totalHosts: 2,
      brokenBackendsCount: 1,
    });
    const broken = ws.ingressRoutes.find((r) => r.ingress.name === 'broken-ing')!;
    expect(broken.hasBrokenBackend).toBe(true);
    const healthy = ws.ingressRoutes.find((r) => r.ingress.name === 'web-ing')!;
    expect(healthy.backends[0].podCount).toBe(1);
  });

  it('computes VOW RAM budget headroom and dependency graph with live pod matching', () => {
    const catalog: VowAppDefinition[] = [
      { id: 'argocd', name: 'ArgoCD', category: 'DevOps & GitOps', description: '', enablerVar: 'a', estimatedMemoryMb: 1024, namespace: 'app-ns' },
      { id: 'certmanager', name: 'Cert-Manager', category: 'Security & Identity', description: '', enablerVar: 'b', estimatedMemoryMb: 512, namespace: 'cert-manager' },
      { id: 'app1', name: 'MyApp', category: 'Collaboration & Business', description: '', enablerVar: 'c', estimatedMemoryMb: 512, dependencies: ['argocd', 'certmanager'], namespace: 'db-ns' },
    ];
    const pulse = makeSamplePulse();
    const res = buildVowVisualSummary(['app1'], ['argocd', 'certmanager', 'app1'], ['argocd', 'certmanager'], catalog, pulse);

    expect(res.ramBudget.hasLiveCluster).toBe(true);
    expect(res.ramBudget.stackMemoryGb).toBe(2);
    expect(res.ramBudget.clusterFreeGb).toBe(20);
    expect(res.ramBudget.fitsInFreeRam).toBe(true);
    expect(res.dependencyGraph.edges).toEqual([
      { from: 'argocd', to: 'app1' },
      { from: 'certmanager', to: 'app1' },
    ]);
    const argoNode = res.dependencyGraph.nodes.find((n) => n.id === 'argocd')!;
    expect(argoNode.depth).toBe(0);
    expect(argoNode.livePods).toBe(3);
    expect(res.dependencyGraph.nodes.find((n) => n.id === 'app1')!.depth).toBe(1);
  });
});
