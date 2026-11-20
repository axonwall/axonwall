'use client';

import React, { useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Boxes,
  CheckCircle2,
  Cpu,
  Database,
  FileText,
  Globe,
  HardDrive,
  Layers,
  Network,
  RefreshCw,
  RotateCcw,
  Server,
  ShieldAlert,
  Terminal,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  formatAge,
  formatBytes,
  formatCpuMillis,
  type K3sClusterPulse,
} from './types';

interface K3sPulseChartsProps {
  pulse: K3sClusterPulse;
  onSelectFilter: (opts: { resource: string; namespace?: string; search?: string }) => void;
  onInspectResource: (opts: {
    resource: string;
    name: string;
    namespace?: string;
    tab?: 'overview' | 'describe' | 'yaml' | 'logs' | 'exec' | 'events';
  }) => void;
}

const PHASE_COLOR_MAP: Record<string, string> = {
  Running: '#10b981',
  Succeeded: '#0ea5e9',
  Completed: '#0ea5e9',
  Pending: '#f59e0b',
  ContainerCreating: '#f59e0b',
  PodInitializing: '#f59e0b',
  Terminating: '#fb923c',
  Failed: '#f43f5e',
  CrashLoopBackOff: '#e11d48',
  ImagePullBackOff: '#be123c',
  ErrImagePull: '#be123c',
  Error: '#f43f5e',
  Unknown: '#64748b',
};

function colorForPhase(name: string, index: number): string {
  if (PHASE_COLOR_MAP[name]) return PHASE_COLOR_MAP[name];
  if (name.startsWith('Init:')) return '#f59e0b';
  const fallback = ['#8b5cf6', '#06b6d4', '#ec4899', '#84cc16', '#64748b'];
  return fallback[index % fallback.length];
}

export function K3sPulseCharts({
  pulse,
  onSelectFilter,
  onInspectResource,
}: K3sPulseChartsProps) {
  const [nodeMetricMode, setNodeMetricMode] = useState<'cpu' | 'mem'>('cpu');
  const [eventFilter, setEventFilter] = useState<'all' | 'Warning' | 'Normal'>('all');

  const c = pulse.counts;

  const totalPvcGiB = useMemo(() => {
    const bytes = pulse.storageByClass.reduce((acc, s) => acc + (s.totalBytes || 0), 0);
    return (bytes / (1024 * 1024 * 1024)).toFixed(1);
  }, [pulse.storageByClass]);

  const phaseChartData = useMemo(() => {
    return (pulse.podPhaseDistribution || []).map((p, idx) => ({
      name: p.name,
      count: p.count,
      fill: colorForPhase(p.name, idx),
    }));
  }, [pulse.podPhaseDistribution]);

  const namespaceChartData = useMemo(() => {
    return (pulse.namespaceStats || []).slice(0, 12).map((ns) => ({
      name: ns.name,
      running: ns.podsRunning,
      unhealthy: ns.podsUnhealthy,
      other: Math.max(0, ns.podsTotal - ns.podsRunning - ns.podsUnhealthy),
    }));
  }, [pulse.namespaceStats]);

  const nodeChartData = useMemo(() => {
    return (pulse.nodes || []).map((n) => {
      if (nodeMetricMode === 'cpu') {
        return {
          name: n.name,
          allocatable: Number((n.cpuAllocatableMillis / 1000).toFixed(2)),
          requested: Number((n.cpuRequestsMillis / 1000).toFixed(2)),
          limits: Number((n.cpuLimitsMillis / 1000).toFixed(2)),
          usage:
            n.cpuUsageMillis !== null && n.cpuUsageMillis !== undefined
              ? Number((n.cpuUsageMillis / 1000).toFixed(2))
              : undefined,
        };
      }
      const gi = 1024 * 1024 * 1024;
      return {
        name: n.name,
        allocatable: Number((n.memAllocatableBytes / gi).toFixed(2)),
        requested: Number((n.memRequestsBytes / gi).toFixed(2)),
        limits: Number((n.memLimitsBytes / gi).toFixed(2)),
        usage:
          n.memUsageBytes !== null && n.memUsageBytes !== undefined
            ? Number((n.memUsageBytes / gi).toFixed(2))
            : undefined,
      };
    });
  }, [pulse.nodes, nodeMetricMode]);

  const filteredEvents = useMemo(() => {
    const evs = pulse.recentEvents || [];
    if (eventFilter === 'all') return evs.slice(0, 40);
    return evs.filter((e) => e.type === eventFilter).slice(0, 40);
  }, [pulse.recentEvents, eventFilter]);

  const unhealthyPods = c.podsPending + c.podsFailed + c.podsUnknown;

  return (
    <div className="space-y-6">
      {/* Row 1: 6 Core KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
        <button
          type="button"
          onClick={() => onSelectFilter({ resource: 'nodes' })}
          className="text-left p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-emerald-500/40 transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Nodes</span>
            <Server className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono text-white mt-1">
            {c.nodesReady}/{c.nodesTotal}
          </div>
          <div className="text-[11px] font-mono text-slate-400 mt-1">
            {c.nodesCordoned > 0 ? `${c.nodesCordoned} cordoned` : pulse.k3sVersion || 'All schedulable'}
          </div>
        </button>

        <button
          type="button"
          onClick={() => onSelectFilter({ resource: 'pods' })}
          className="text-left p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-emerald-500/40 transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Pods</span>
            <Boxes className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono text-white mt-1">
            {c.podsRunning}/{c.podsTotal}
          </div>
          <div className="text-[11px] font-mono mt-1 flex items-center gap-2">
            <span className={unhealthyPods > 0 ? 'text-amber-300' : 'text-emerald-400'}>
              {unhealthyPods > 0 ? `${unhealthyPods} non-running` : 'Healthy'}
            </span>
            <span className="text-slate-500">• ↻ {c.totalRestarts}</span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => onSelectFilter({ resource: 'deployments' })}
          className="text-left p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-sky-500/40 transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Workloads</span>
            <Layers className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-xl font-bold font-mono text-white mt-1">
            {c.deploymentsReady + c.statefulSetsReady + c.daemonSetsReady}/
            {c.deploymentsTotal + c.statefulSetsTotal + c.daemonSetsTotal}
          </div>
          <div className="text-[11px] font-mono text-slate-400 mt-1">
            D:{c.deploymentsTotal} S:{c.statefulSetsTotal} DS:{c.daemonSetsTotal}
          </div>
        </button>

        <button
          type="button"
          onClick={() => onSelectFilter({ resource: 'services' })}
          className="text-left p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/40 transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Services &amp; Ing</span>
            <Globe className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-xl font-bold font-mono text-white mt-1">
            {c.servicesTotal} / {c.ingressesTotal}
          </div>
          <div className="text-[11px] font-mono text-slate-400 mt-1">
            NetPol:{c.networkPoliciesTotal} • CNI:{pulse.cniPlugin}
          </div>
        </button>

        <button
          type="button"
          onClick={() => onSelectFilter({ resource: 'persistentvolumeclaims' })}
          className="text-left p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-amber-500/40 transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>OpenEBS PVCs</span>
            <Database className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono text-white mt-1">
            {c.pvcsBound}/{c.pvcsTotal} Bound
          </div>
          <div className="text-[11px] font-mono text-slate-400 mt-1">
            {totalPvcGiB} GiB • {c.storageClassesTotal} Classes
          </div>
        </button>

        <button
          type="button"
          onClick={() => onSelectFilter({ resource: 'events' })}
          className="text-left p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-rose-500/40 transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Cluster Events</span>
            <AlertTriangle
              className={`w-4 h-4 ${c.warningEventsCount > 0 ? 'text-amber-400' : 'text-emerald-400'}`}
            />
          </div>
          <div
            className={`text-xl font-bold font-mono mt-1 ${
              c.warningEventsCount > 0 ? 'text-amber-300' : 'text-emerald-400'
            }`}
          >
            {c.warningEventsCount} Warn
          </div>
          <div className="text-[11px] font-mono text-slate-400 mt-1">
            {c.normalEventsCount} Normal • {c.crdsTotal} CRDs
          </div>
        </button>
      </div>

      {/* Row 2: Pod Phase Donut + Pods by Namespace + Node Capacity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Pod Phase Distribution Donut */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white">Pod Health Distribution</h3>
              <p className="text-[11px] text-slate-400">Click any slice to filter Pods in K9s</p>
            </div>
            <span className="text-xs font-mono text-emerald-400">{c.podsTotal} total</span>
          </div>
          {phaseChartData.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-xs text-slate-500">
              No pods present in cluster.
            </div>
          ) : (
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={phaseChartData}
                    dataKey="count"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={2}
                    onClick={(entry: any) => {
                      if (entry?.name) {
                        onSelectFilter({ resource: 'pods', search: String(entry.name) });
                      }
                    }}
                  >
                    {phaseChartData.map((entry) => (
                      <Cell key={entry.name} fill={entry.fill} className="cursor-pointer" />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '0.5rem',
                      fontSize: '12px',
                      color: '#f1f5f9',
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Namespace Pod Breakdown */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white">Pods by Namespace</h3>
              <p className="text-[11px] text-slate-400">Click bar to jump to namespace</p>
            </div>
            <span className="text-xs font-mono text-slate-400">{c.namespacesTotal} ns</span>
          </div>
          {namespaceChartData.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-xs text-slate-500">
              No namespace telemetry.
            </div>
          ) : (
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={namespaceChartData} layout="vertical" margin={{ left: 10, right: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={95}
                    tick={{ fill: '#cbd5e1', fontSize: 11 }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '0.5rem',
                      fontSize: '12px',
                      color: '#f1f5f9',
                    }}
                  />
                  <Bar
                    dataKey="running"
                    stackId="a"
                    name="Running"
                    fill="#10b981"
                    className="cursor-pointer"
                    onClick={(entry: any) => {
                      if (entry?.name) {
                        onSelectFilter({ resource: 'pods', namespace: String(entry.name) });
                      }
                    }}
                  />
                  <Bar
                    dataKey="unhealthy"
                    stackId="a"
                    name="Pending / Error"
                    fill="#f43f5e"
                    className="cursor-pointer"
                    onClick={(entry: any) => {
                      if (entry?.name) {
                        onSelectFilter({ resource: 'pods', namespace: String(entry.name) });
                      }
                    }}
                  />
                  <Bar dataKey="other" stackId="a" name="Completed" fill="#0ea5e9" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Node Capacity & Requests Chart */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-bold text-white">Node Resource Allocation</h3>
              <p className="text-[11px] text-slate-400">
                {pulse.metricsAvailable
                  ? 'Allocatable, Requested & Live Usage'
                  : 'Requests vs Allocatable (metrics-server N/A)'}
              </p>
            </div>
            <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-[11px]">
              <button
                type="button"
                onClick={() => setNodeMetricMode('cpu')}
                className={`px-2 py-1 rounded-md font-mono transition ${
                  nodeMetricMode === 'cpu' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                CPU
              </button>
              <button
                type="button"
                onClick={() => setNodeMetricMode('mem')}
                className={`px-2 py-1 rounded-md font-mono transition ${
                  nodeMetricMode === 'mem' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                MEM
              </button>
            </div>
          </div>
          {nodeChartData.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-xs text-slate-500">
              No nodes registered.
            </div>
          ) : (
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={nodeChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="name" tick={{ fill: '#cbd5e1', fontSize: 11 }} />
                  <YAxis
                    tick={{ fill: '#94a3b8', fontSize: 11 }}
                    unit={nodeMetricMode === 'cpu' ? 'c' : 'Gi'}
                    width={46}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '0.5rem',
                      fontSize: '12px',
                      color: '#f1f5f9',
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                  <Bar dataKey="allocatable" name="Allocatable" fill="#334155" />
                  <Bar dataKey="requested" name="Requested" fill="#0ea5e9" />
                  {pulse.metricsAvailable && (
                    <Bar dataKey="usage" name="Live Usage" fill="#10b981" />
                  )}
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Row 3: Node Matrix + StorageClass Usage + Workload Health */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Live Node Cards */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-emerald-400" /> Node Utilization Matrix
            </h3>
            <span className="text-[11px] font-mono text-slate-400">{pulse.nodes.length} nodes</span>
          </div>
          <div className="space-y-3">
            {pulse.nodes.map((n) => {
              const cpuPct =
                n.cpuAllocatableMillis > 0
                  ? Math.min(
                      100,
                      Math.round(
                        (((n.cpuUsageMillis ?? n.cpuRequestsMillis) || 0) / n.cpuAllocatableMillis) * 100
                      )
                    )
                  : 0;
              const memPct =
                n.memAllocatableBytes > 0
                  ? Math.min(
                      100,
                      Math.round(
                        (((n.memUsageBytes ?? n.memRequestsBytes) || 0) / n.memAllocatableBytes) * 100
                      )
                    )
                  : 0;
              const podPct =
                n.podCapacity > 0 ? Math.min(100, Math.round((n.podCount / n.podCapacity) * 100)) : 0;

              return (
                <div
                  key={n.name}
                  onClick={() => onInspectResource({ resource: 'nodes', name: n.name })}
                  className="p-3 rounded-xl bg-slate-950 border border-slate-800 hover:border-emerald-500/40 cursor-pointer space-y-2 transition"
                >
                  <div className="flex items-center justify-between gap-2 text-xs">
                    <span className="font-mono font-bold text-white truncate">{n.name}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                        n.status === 'Ready' && !n.unschedulable
                          ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                          : 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                      }`}
                    >
                      {n.status}
                      {n.unschedulable ? ' • Cordoned' : ''}
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-[10px] font-mono text-slate-400">
                    <div>
                      <div className="flex justify-between">
                        <span>CPU {n.cpuUsageMillis != null ? 'Use' : 'Req'}</span>
                        <span className="text-slate-200">{cpuPct}%</span>
                      </div>
                      <div className="h-1.5 bg-slate-800 rounded-full mt-1 overflow-hidden">
                        <div className="h-full bg-emerald-500" style={{ width: `${cpuPct}%` }} />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between">
                        <span>MEM {n.memUsageBytes != null ? 'Use' : 'Req'}</span>
                        <span className="text-slate-200">{memPct}%</span>
                      </div>
                      <div className="h-1.5 bg-slate-800 rounded-full mt-1 overflow-hidden">
                        <div className="h-full bg-sky-500" style={{ width: `${memPct}%` }} />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between">
                        <span>Pods</span>
                        <span className="text-slate-200">
                          {n.podCount}/{n.podCapacity || '—'}
                        </span>
                      </div>
                      <div className="h-1.5 bg-slate-800 rounded-full mt-1 overflow-hidden">
                        <div className="h-full bg-amber-500" style={{ width: `${podPct}%` }} />
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* StorageClass Consumption */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <HardDrive className="w-4 h-4 text-amber-400" /> StorageClass Utilization
            </h3>
            <button
              type="button"
              onClick={() => onSelectFilter({ resource: 'storageclasses' })}
              className="text-[11px] font-mono text-sky-400 hover:underline"
            >
              View Classes →
            </button>
          </div>
          {pulse.storageByClass.length === 0 ? (
            <div className="text-xs text-slate-500 py-8 text-center">No StorageClasses found.</div>
          ) : (
            <div className="space-y-2.5">
              {pulse.storageByClass.map((sc) => (
                <div
                  key={sc.name}
                  onClick={() => onSelectFilter({ resource: 'persistentvolumeclaims', search: sc.name })}
                  className="p-3 rounded-xl bg-slate-950 border border-slate-800 hover:border-amber-500/40 cursor-pointer transition space-y-1"
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-bold text-white truncate">
                      {sc.name}
                      {sc.isDefault && (
                        <span className="ml-2 px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 text-[9px]">
                          DEFAULT
                        </span>
                      )}
                    </span>
                    <span className="font-mono text-amber-300">{formatBytes(sc.totalBytes)}</span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                    <span className="truncate">{sc.provisioner || 'csi'}</span>
                    <span>
                      {sc.boundCount}/{sc.pvcCount} PVCs bound
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top Restarting / Resource Hotspot Pods */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <RotateCcw className="w-4 h-4 text-rose-400" /> Pod Restarts &amp; Hotspots
            </h3>
            <span className="text-[11px] font-mono text-slate-400">Top {pulse.topRestartingPods.length}</span>
          </div>
          {pulse.topRestartingPods.length === 0 ? (
            <div className="p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/20 text-xs text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>Zero container restarts across all pods.</span>
            </div>
          ) : (
            <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
              {pulse.topRestartingPods.map((p) => (
                <div
                  key={`${p.namespace}/${p.name}`}
                  className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between gap-2 text-xs"
                >
                  <div className="min-w-0">
                    <div className="font-mono font-semibold text-white truncate">{p.name}</div>
                    <div className="text-[10px] font-mono text-slate-400 truncate">
                      {p.namespace} • {p.status} • {p.nodeName || 'unscheduled'}
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <span className="px-2 py-0.5 rounded bg-rose-500/15 border border-rose-500/30 text-rose-300 font-mono text-[10px]">
                      ↻ {p.restarts}
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        onInspectResource({
                          resource: 'pods',
                          namespace: p.namespace,
                          name: p.name,
                          tab: 'logs',
                        })
                      }
                      className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[10px] text-sky-300 font-mono"
                    >
                      Logs
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Row 4: Live Cluster Events Stream */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-bold text-white">Live Cluster Events Stream</h3>
            <span className="text-[11px] font-mono text-slate-400">
              Click any event row to inspect its target object
            </span>
          </div>
          <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-xs">
            {(['all', 'Warning', 'Normal'] as const).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setEventFilter(t)}
                className={`px-2.5 py-1 rounded-md font-mono text-[11px] transition ${
                  eventFilter === t
                    ? 'bg-emerald-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {t === 'all' ? `All (${pulse.recentEvents.length})` : t}
              </button>
            ))}
          </div>
        </div>
        <div className="max-h-72 overflow-y-auto">
          {filteredEvents.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-500">No matching cluster events.</div>
          ) : (
            <table className="w-full text-left border-collapse text-xs">
              <thead className="sticky top-0 bg-slate-950 border-b border-slate-800 text-[10px] uppercase tracking-wider text-slate-400">
                <tr>
                  <th className="py-2.5 px-3">Age</th>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Namespace</th>
                  <th className="py-2.5 px-3">Object</th>
                  <th className="py-2.5 px-3">Reason</th>
                  <th className="py-2.5 px-3">Message</th>
                  <th className="py-2.5 px-3 text-right">Count</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredEvents.map((ev, idx) => (
                  <tr
                    key={`${ev.namespace}-${ev.involvedName}-${ev.reason}-${idx}`}
                    onClick={() => {
                      if (ev.involvedKind && ev.involvedName) {
                        const plural = ev.involvedKind.toLowerCase().endsWith('s')
                          ? `${ev.involvedKind.toLowerCase()}es`
                          : `${ev.involvedKind.toLowerCase()}s`;
                        onInspectResource({
                          resource: plural,
                          namespace: ev.namespace,
                          name: ev.involvedName,
                        });
                      }
                    }}
                    className="hover:bg-slate-800/50 cursor-pointer"
                  >
                    <td className="py-2 px-3 font-mono text-slate-400 whitespace-nowrap">
                      {formatAge(ev.lastTimestamp)}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <span
                        className={`px-1.5 py-0.5 rounded font-mono text-[10px] border ${
                          ev.type === 'Warning'
                            ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                            : 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                        }`}
                      >
                        {ev.type}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-mono text-slate-300 whitespace-nowrap">
                      {ev.namespace || 'cluster'}
                    </td>
                    <td className="py-2 px-3 font-mono text-emerald-300 whitespace-nowrap">
                      {ev.involvedKind}/{ev.involvedName}
                    </td>
                    <td className="py-2 px-3 font-mono text-white whitespace-nowrap">{ev.reason}</td>
                    <td className="py-2 px-3 text-slate-300 max-w-md truncate">{ev.message}</td>
                    <td className="py-2 px-3 font-mono text-slate-400 text-right">{ev.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
