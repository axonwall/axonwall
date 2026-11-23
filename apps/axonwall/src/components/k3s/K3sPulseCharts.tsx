'use client';

import React, { useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Boxes,
  CheckCircle2,
  Cpu,
  Database,
  Globe,
  HardDrive,
  Layers,
  RotateCcw,
  Server,
  TrendingUp,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from 'recharts';
import {
  formatAge,
  formatBytes,
  formatCpuMillis,
  type K3sClusterPulse,
} from './types';
import { K3sCapacityRings } from './K3sCapacityRings';
import {
  buildEventReasonBreakdown,
  buildPodResourceHotspots,
  computeClusterCapacitySummary,
  type K3sPulseHistoryPoint,
} from '@/lib/k3s-visuals';

interface K3sPulseChartsProps {
  pulse: K3sClusterPulse;
  history?: K3sPulseHistoryPoint[];
  autoRefreshSec?: number;
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
  history = [],
  autoRefreshSec = 5,
  onSelectFilter,
  onInspectResource,
}: K3sPulseChartsProps) {
  const [trendMode, setTrendMode] = useState<'compute' | 'workloads'>('compute');
  const [nsMode, setNsMode] = useState<'health' | 'footprint'>('health');
  const [nodeMetricMode, setNodeMetricMode] = useState<'cpu' | 'mem'>('cpu');
  const [showNodeLimits, setShowNodeLimits] = useState<boolean>(false);
  const [hotspotMode, setHotspotMode] = useState<'scatter' | 'cpu' | 'mem'>('scatter');
  const [eventFilter, setEventFilter] = useState<'all' | 'Warning' | 'Normal'>('all');
  const [reasonFilter, setReasonFilter] = useState<string | null>(null);

  const c = pulse.counts;
  const storageClasses = pulse.storageByClass || [];
  const topRestartingPods = pulse.topRestartingPods || [];
  const recentEvents = pulse.recentEvents || [];
  const nodes = pulse.nodes || [];

  const capacitySummary = useMemo(() => computeClusterCapacitySummary(pulse), [pulse]);

  const totalPvcGiB = useMemo(() => {
    const bytes = storageClasses.reduce((acc, s) => acc + (s.totalBytes || 0), 0);
    return (bytes / (1024 * 1024 * 1024)).toFixed(1);
  }, [storageClasses]);

  const maxScBytes = useMemo(
    () => Math.max(1, ...storageClasses.map((s) => s.totalBytes || 0)),
    [storageClasses]
  );

  const phaseChartData = useMemo(() => {
    return (pulse.podPhaseDistribution || []).map((p, idx) => ({
      name: p.name,
      count: p.count,
      fill: colorForPhase(p.name, idx),
    }));
  }, [pulse.podPhaseDistribution]);

  const healthyPodPct = useMemo(() => {
    if (!c.podsTotal) return 100;
    return Math.round(((c.podsRunning + c.podsSucceeded) / c.podsTotal) * 100);
  }, [c.podsRunning, c.podsSucceeded, c.podsTotal]);

  const namespaceChartData = useMemo(() => {
    return (pulse.namespaceStats || []).slice(0, 12).map((ns) => ({
      name: ns.name,
      running: ns.podsRunning,
      unhealthy: ns.podsUnhealthy,
      other: Math.max(0, ns.podsTotal - ns.podsRunning - ns.podsUnhealthy),
      podsTotal: ns.podsTotal,
      services: ns.services,
      ingresses: ns.ingresses,
      pvcs: ns.pvcs,
    }));
  }, [pulse.namespaceStats]);

  const hasNodeOvercommit = useMemo(
    () =>
      nodes.some(
        (n) =>
          (n.cpuAllocatableMillis > 0 && n.cpuLimitsMillis > n.cpuAllocatableMillis) ||
          (n.memAllocatableBytes > 0 && n.memLimitsBytes > n.memAllocatableBytes)
      ),
    [nodes]
  );

  const nodeChartData = useMemo(() => {
    return nodes.map((n) => {
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
  }, [nodes, nodeMetricMode]);

  const hotspots = useMemo(
    () => buildPodResourceHotspots(pulse.topResourcePods, pulse.topRestartingPods),
    [pulse.topResourcePods, pulse.topRestartingPods]
  );

  const reasonBreakdown = useMemo(
    () => buildEventReasonBreakdown(recentEvents, 10),
    [recentEvents]
  );

  const filteredEvents = useMemo(() => {
    return recentEvents
      .filter((e) => (eventFilter === 'all' ? true : e.type === eventFilter))
      .filter((e) => (reasonFilter ? e.reason === reasonFilter : true))
      .slice(0, 40);
  }, [recentEvents, eventFilter, reasonFilter]);

  const unhealthyPods = c.podsPending + c.podsFailed + c.podsUnknown;

  return (
    <div className="space-y-6">
      {/* Row 0: Cluster Capacity Rings + Attention Signals */}
      <K3sCapacityRings pulse={pulse} onSelectFilter={onSelectFilter} />

      {/* Row 1: 6 Core Clickable Inventory KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
        <button
          type="button"
          onClick={() => onSelectFilter({ resource: 'nodes' })}
          className="text-left p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-emerald-500/40 transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-300">
            <span>Nodes</span>
            <Server className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-white mt-1">
            {c.nodesReady}/{c.nodesTotal}
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400 mt-1">
            {c.nodesCordoned > 0 ? `${c.nodesCordoned} cordoned` : pulse.k3sVersion || 'All schedulable'}
          </div>
        </button>

        <button
          type="button"
          onClick={() => onSelectFilter({ resource: 'pods' })}
          className="text-left p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-emerald-500/40 transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-300">
            <span>Pods</span>
            <Boxes className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-white mt-1">
            {c.podsRunning}/{c.podsTotal}
          </div>
          <div className="text-[11px] font-mono tabular-nums mt-1 flex items-center gap-2">
            <span className={unhealthyPods > 0 ? 'text-amber-300' : 'text-emerald-400'}>
              {unhealthyPods > 0 ? `${unhealthyPods} non-running` : 'Healthy'}
            </span>
            <span className="text-slate-400">• ↻ {c.totalRestarts}</span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => onSelectFilter({ resource: 'deployments' })}
          className="text-left p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-sky-500/40 transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-300">
            <span>Workloads</span>
            <Layers className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-white mt-1">
            {c.deploymentsReady + c.statefulSetsReady + c.daemonSetsReady}/
            {c.deploymentsTotal + c.statefulSetsTotal + c.daemonSetsTotal}
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400 mt-1">
            D:{c.deploymentsTotal} S:{c.statefulSetsTotal} DS:{c.daemonSetsTotal}
          </div>
        </button>

        <button
          type="button"
          onClick={() => onSelectFilter({ resource: 'services' })}
          className="text-left p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/40 transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-300">
            <span>Services &amp; Ing</span>
            <Globe className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-white mt-1">
            {c.servicesTotal} / {c.ingressesTotal}
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400 mt-1">
            NetPol:{c.networkPoliciesTotal} • CNI:{pulse.cniPlugin}
          </div>
        </button>

        <button
          type="button"
          onClick={() => onSelectFilter({ resource: 'persistentvolumeclaims' })}
          className="text-left p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-amber-500/40 transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-300">
            <span>OpenEBS PVCs</span>
            <Database className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-white mt-1">
            {c.pvcsBound}/{c.pvcsTotal} Bound
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400 mt-1">
            {totalPvcGiB} GiB • {c.storageClassesTotal} Classes
          </div>
        </button>

        <button
          type="button"
          onClick={() => onSelectFilter({ resource: 'events' })}
          className="text-left p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-rose-500/40 transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-300">
            <span>Cluster Events</span>
            <AlertTriangle
              className={`w-4 h-4 ${c.warningEventsCount > 0 ? 'text-amber-400' : 'text-emerald-400'}`}
            />
          </div>
          <div
            className={`text-xl font-bold font-mono tabular-nums mt-1 ${
              c.warningEventsCount > 0 ? 'text-amber-300' : 'text-emerald-400'
            }`}
          >
            {c.warningEventsCount} Warn
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400 mt-1">
            {c.normalEventsCount} Normal • {c.crdsTotal} CRDs
          </div>
        </button>
      </div>

      {/* Row 1.5: Live Cluster Telemetry Trend (Polling Time-Series) */}
      <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-emerald-400" /> Live Cluster Telemetry Trend
            </h3>
            <p className="text-xs text-slate-400">
              Rolling time-series recorded from live cluster snapshots ({history.length}/30 samples •{' '}
              {autoRefreshSec > 0 ? `polling every ${autoRefreshSec}s` : 'auto-poll paused'})
            </p>
          </div>
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-[11px]">
            <button
              type="button"
              onClick={() => setTrendMode('compute')}
              className={`px-2.5 py-1 rounded-md font-mono transition ${
                trendMode === 'compute' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              CPU &amp; Memory %
            </button>
            <button
              type="button"
              onClick={() => setTrendMode('workloads')}
              className={`px-2.5 py-1 rounded-md font-mono transition ${
                trendMode === 'workloads' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              Pods &amp; Warnings
            </button>
          </div>
        </div>

        {history.length < 2 ? (
          <div className="p-5 rounded-xl bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-4 text-xs font-mono tabular-nums">
            <div className="space-y-1">
              <div className="text-slate-200 font-semibold">
                Baseline captured at {history[0]?.timeLabel || 'now'} — awaiting next poll sample to plot curve
              </div>
              <div className="text-slate-400">
                {autoRefreshSec > 0
                  ? `Next live snapshot arrives in ≤${autoRefreshSec}s.`
                  : 'Enable Poll interval in header to stream continuous time-series samples.'}
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-4">
              <span className="text-emerald-300">
                CPU Usage: <strong>{capacitySummary.cpuUsagePct}%</strong> ({capacitySummary.cpuUsageCores}c)
              </span>
              <span className="text-sky-300">
                Memory Usage: <strong>{capacitySummary.memUsagePct}%</strong> ({capacitySummary.memUsageGiB} GiB)
              </span>
              <span className="text-slate-200">
                Pods: <strong>{c.podsRunning}/{c.podsTotal}</strong>
              </span>
            </div>
          </div>
        ) : (
          <div className="h-[190px] w-full min-w-0">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={history} margin={{ top: 6, right: 12, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="k3sCpuGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="k3sMemGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="timeLabel" tick={{ fill: '#94a3b8', fontSize: 10.5 }} />
                <YAxis
                  tick={{ fill: '#94a3b8', fontSize: 11 }}
                  domain={trendMode === 'compute' ? [0, 100] : ['auto', 'auto']}
                  unit={trendMode === 'compute' ? '%' : ''}
                  width={42}
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
                {trendMode === 'compute' ? (
                  <>
                    <Area
                      type="monotone"
                      dataKey="cpuUsagePct"
                      name="CPU Usage %"
                      stroke="#10b981"
                      strokeWidth={2}
                      fill="url(#k3sCpuGrad)"
                    />
                    <Area
                      type="monotone"
                      dataKey="memUsagePct"
                      name="Memory Usage %"
                      stroke="#0ea5e9"
                      strokeWidth={2}
                      fill="url(#k3sMemGrad)"
                    />
                  </>
                ) : (
                  <>
                    <Area
                      type="monotone"
                      dataKey="podsRunning"
                      name="Running Pods"
                      stroke="#10b981"
                      strokeWidth={2}
                      fill="url(#k3sCpuGrad)"
                    />
                    <Area
                      type="monotone"
                      dataKey="podsUnhealthy"
                      name="Unhealthy Pods"
                      stroke="#f43f5e"
                      strokeWidth={2}
                      fill="none"
                    />
                    <Area
                      type="monotone"
                      dataKey="warningEventsCount"
                      name="Warning Events"
                      stroke="#f59e0b"
                      strokeWidth={1.8}
                      fill="none"
                    />
                  </>
                )}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Row 2: Pod Phase Donut + Namespace Breakdown + Node Allocation */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Pod Phase Distribution Donut */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white">Pod Health Distribution</h3>
              <p className="text-xs text-slate-400">Click any slice to filter Pods in K9s</p>
            </div>
            <span className="text-xs font-mono tabular-nums text-emerald-400">{c.podsTotal} total</span>
          </div>
          {phaseChartData.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-xs text-slate-400">
              No pods present in cluster.
            </div>
          ) : (
            <div className="h-[220px] w-full min-w-0 relative">
              <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center pb-5">
                <span className="text-lg font-bold font-mono tabular-nums text-white">
                  {healthyPodPct}%
                </span>
                <span className="text-[10px] font-mono text-slate-400">healthy</span>
              </div>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={phaseChartData}
                    dataKey="count"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={52}
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

        {/* Namespace Pod / Resource Footprint */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-bold text-white">Namespace Distribution</h3>
              <p className="text-xs text-slate-400">Click any bar to jump to namespace</p>
            </div>
            <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-[10px] font-mono">
              <button
                type="button"
                onClick={() => setNsMode('health')}
                className={`px-2 py-1 rounded transition ${
                  nsMode === 'health' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Pods
              </button>
              <button
                type="button"
                onClick={() => setNsMode('footprint')}
                className={`px-2 py-1 rounded transition ${
                  nsMode === 'footprint' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Objects
              </button>
            </div>
          </div>
          {namespaceChartData.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-xs text-slate-400">
              No namespace telemetry.
            </div>
          ) : (
            <div className="h-[220px] w-full min-w-0">
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
                  {nsMode === 'health' ? (
                    <>
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
                    </>
                  ) : (
                    <>
                      <Bar
                        dataKey="podsTotal"
                        stackId="b"
                        name="Pods"
                        fill="#10b981"
                        className="cursor-pointer"
                        onClick={(entry: any) => {
                          if (entry?.name) {
                            onSelectFilter({ resource: 'pods', namespace: String(entry.name) });
                          }
                        }}
                      />
                      <Bar
                        dataKey="services"
                        stackId="b"
                        name="Services"
                        fill="#38bdf8"
                        className="cursor-pointer"
                        onClick={(entry: any) => {
                          if (entry?.name) {
                            onSelectFilter({ resource: 'services', namespace: String(entry.name) });
                          }
                        }}
                      />
                      <Bar dataKey="ingresses" stackId="b" name="Ingresses" fill="#06b6d4" />
                      <Bar dataKey="pvcs" stackId="b" name="PVCs" fill="#f59e0b" />
                    </>
                  )}
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Node Capacity, Requests & Overcommit */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>Node Resource Allocation</span>
                {hasNodeOvercommit && (
                  <span className="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-[10px] font-mono text-amber-300">
                    Overcommit
                  </span>
                )}
              </h3>
              <p className="text-xs text-slate-400">
                {pulse.metricsAvailable
                  ? 'Allocatable, Requested & Live Usage'
                  : 'Requests vs Allocatable (metrics-server N/A)'}
              </p>
            </div>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => setShowNodeLimits((v) => !v)}
                className={`px-2 py-1 rounded-md border text-[10px] font-mono transition ${
                  showNodeLimits
                    ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                    : 'bg-slate-950 border-slate-800 text-slate-300'
                }`}
              >
                Lim
              </button>
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
          </div>
          {nodeChartData.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-xs text-slate-400">
              No nodes registered.
            </div>
          ) : (
            <div className="h-[220px] w-full min-w-0">
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
                  {showNodeLimits && <Bar dataKey="limits" name="Limits" fill="#f59e0b" />}
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Row 2.5: Top Pod Resource Consumers (CPU vs Memory Scatter & Top Bars) */}
      <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-sky-400" /> Top Pod Resource Consumers
            </h3>
            <p className="text-xs text-slate-400">
              Live CPU vs Memory correlation (bubble size scales with restarts) — click any pod to inspect
            </p>
          </div>
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-[11px] font-mono">
            {(
              [
                { id: 'scatter', label: 'CPU × Mem Scatter' },
                { id: 'cpu', label: 'Top CPU' },
                { id: 'mem', label: 'Top Memory' },
              ] as const
            ).map((m) => (
              <button
                key={m.id}
                type="button"
                onClick={() => setHotspotMode(m.id)}
                className={`px-2.5 py-1 rounded-md transition ${
                  hotspotMode === m.id ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                {m.label}
              </button>
            ))}
          </div>
        </div>

        {hotspots.all.length === 0 ? (
          <div className="p-6 rounded-xl bg-slate-950 border border-slate-800 text-center text-xs text-slate-400">
            No live pod resource metrics available yet (verify metrics-server is active in kube-system).
          </div>
        ) : (
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 items-start">
            <div className="xl:col-span-2 h-[230px] w-full min-w-0">
              <ResponsiveContainer width="100%" height="100%">
                {hotspotMode === 'scatter' ? (
                  <ScatterChart margin={{ top: 10, right: 20, left: 4, bottom: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis
                      type="number"
                      dataKey="cpuMillis"
                      name="CPU"
                      unit="m"
                      tick={{ fill: '#94a3b8', fontSize: 11 }}
                    />
                    <YAxis
                      type="number"
                      dataKey="memMiB"
                      name="Memory"
                      unit=" MiB"
                      width={68}
                      tick={{ fill: '#94a3b8', fontSize: 11 }}
                    />
                    <ZAxis type="number" dataKey="bubbleSize" range={[50, 260]} />
                    <Tooltip
                      cursor={{ strokeDasharray: '3 3', stroke: '#475569' }}
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        borderColor: '#334155',
                        borderRadius: '0.5rem',
                        fontSize: '12px',
                        color: '#f1f5f9',
                      }}
                      formatter={(val: any, name: any) => [String(val), String(name)]}
                      labelFormatter={(_l: any, payload: any) =>
                        payload?.[0]?.payload
                          ? `${payload[0].payload.namespace}/${payload[0].payload.name} (${payload[0].payload.nodeName})`
                          : ''
                      }
                    />
                    <Scatter
                      data={hotspots.scatterPoints}
                      name="Pods"
                      className="cursor-pointer"
                      onClick={(entry: any) => {
                        const p = entry?.payload || entry;
                        if (p?.name && p?.namespace) {
                          onInspectResource({
                            resource: 'pods',
                            namespace: p.namespace,
                            name: p.name,
                            tab: 'overview',
                          });
                        }
                      }}
                    >
                      {hotspots.scatterPoints.map((pt) => (
                        <Cell
                          key={pt.id}
                          fill={
                            pt.isUnhealthy
                              ? '#f43f5e'
                              : pt.restarts > 0
                                ? '#f59e0b'
                                : '#10b981'
                          }
                        />
                      ))}
                    </Scatter>
                  </ScatterChart>
                ) : (
                  <BarChart
                    data={hotspotMode === 'cpu' ? hotspots.byCpu : hotspots.byMem}
                    layout="vertical"
                    margin={{ left: 10, right: 18 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                    <XAxis
                      type="number"
                      tick={{ fill: '#94a3b8', fontSize: 11 }}
                      unit={hotspotMode === 'cpu' ? 'm' : ' MiB'}
                    />
                    <YAxis
                      type="category"
                      dataKey="name"
                      width={150}
                      tick={{ fill: '#cbd5e1', fontSize: 10.5 }}
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
                      dataKey={hotspotMode === 'cpu' ? 'cpuMillis' : 'memMiB'}
                      name={hotspotMode === 'cpu' ? 'CPU (m)' : 'Memory (MiB)'}
                      fill={hotspotMode === 'cpu' ? '#10b981' : '#0ea5e9'}
                      className="cursor-pointer"
                      onClick={(entry: any) => {
                        const p = entry?.payload || entry;
                        if (p?.name && p?.namespace) {
                          onInspectResource({
                            resource: 'pods',
                            namespace: p.namespace,
                            name: p.name,
                            tab: 'overview',
                          });
                        }
                      }}
                    />
                  </BarChart>
                )}
              </ResponsiveContainer>
            </div>

            {/* Interactive Top Hotspot List */}
            <div className="space-y-1.5 max-h-[230px] overflow-y-auto pr-1">
              {(hotspotMode === 'cpu' ? hotspots.byCpu : hotspots.byMem).slice(0, 6).map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() =>
                    onInspectResource({
                      resource: 'pods',
                      namespace: p.namespace,
                      name: p.name,
                      tab: 'overview',
                    })
                  }
                  className="w-full text-left p-2.5 rounded-xl bg-slate-950 border border-slate-800 hover:border-emerald-500/40 flex items-center justify-between gap-2 text-xs transition"
                >
                  <div className="min-w-0">
                    <div className="font-mono font-semibold text-white truncate">{p.name}</div>
                    <div className="text-[10px] font-mono text-slate-400 truncate">
                      {p.namespace} • {p.nodeName}
                    </div>
                  </div>
                  <div className="text-right font-mono tabular-nums text-[11px] shrink-0">
                    <div className="text-emerald-300">{formatCpuMillis(p.cpuMillis)}</div>
                    <div className="text-sky-300">{formatBytes(p.memBytes)}</div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Row 3: Node Matrix + StorageClass Usage + Pod Restarts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Live Node Cards */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-emerald-400" /> Node Utilization Matrix
            </h3>
            <span className="text-[11px] font-mono tabular-nums text-slate-400">{nodes.length} nodes</span>
          </div>
          <div className="space-y-3">
            {nodes.map((n) => {
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
                <button
                  key={n.name}
                  type="button"
                  onClick={() => onInspectResource({ resource: 'nodes', name: n.name })}
                  className="w-full text-left p-3 rounded-xl bg-slate-950 border border-slate-800 hover:border-emerald-500/40 space-y-2 transition"
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
                  <div className="grid grid-cols-3 gap-2 text-[10px] font-mono tabular-nums text-slate-300">
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
                </button>
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
          {storageClasses.length === 0 ? (
            <div className="text-xs text-slate-400 py-8 text-center">No StorageClasses found.</div>
          ) : (
            <div className="space-y-2.5">
              {storageClasses.map((sc) => {
                const sharePct = Math.round(((sc.totalBytes || 0) / maxScBytes) * 100);
                return (
                  <button
                    key={sc.name}
                    type="button"
                    onClick={() => onSelectFilter({ resource: 'persistentvolumeclaims', search: sc.name })}
                    className="w-full text-left p-3 rounded-xl bg-slate-950 border border-slate-800 hover:border-amber-500/40 transition space-y-1.5"
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
                      <span className="font-mono tabular-nums text-amber-300">{formatBytes(sc.totalBytes)}</span>
                    </div>
                    <div className="h-1 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-amber-500" style={{ width: `${sharePct}%` }} />
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono tabular-nums">
                      <span className="truncate">{sc.provisioner || 'csi'}</span>
                      <span>
                        {sc.boundCount}/{sc.pvcCount} PVCs bound
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Top Restarting / Resource Hotspot Pods */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <RotateCcw className="w-4 h-4 text-rose-400" /> Pod Restarts &amp; Hotspots
            </h3>
            <span className="text-[11px] font-mono tabular-nums text-slate-400">Top {topRestartingPods.length}</span>
          </div>
          {topRestartingPods.length === 0 ? (
            <div className="p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/20 text-xs text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>Zero container restarts across all pods.</span>
            </div>
          ) : (
            <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
              {topRestartingPods.map((p) => (
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
                    <span className="px-2 py-0.5 rounded bg-rose-500/15 border border-rose-500/30 text-rose-300 font-mono tabular-nums text-[10px]">
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

      {/* Row 4: Event Reason Breakdown + Live Cluster Events Stream */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-bold text-white">Event Reasons &amp; Live Events Stream</h3>
            <span className="text-[11px] font-mono text-slate-400">
              Click any reason bar or event row to filter / inspect
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {reasonFilter && (
              <button
                type="button"
                onClick={() => setReasonFilter(null)}
                className="px-2.5 py-1 rounded-lg bg-sky-500/15 border border-sky-500/30 text-sky-300 font-mono text-[11px]"
              >
                Reason: {reasonFilter} ✕
              </button>
            )}
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
                  {t === 'all' ? `All (${recentEvents.length})` : t}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Event Reason Histogram */}
        {reasonBreakdown.length > 0 && (
          <div className="p-4 border-b border-slate-800 bg-slate-950/40">
            <div className="h-[170px] w-full min-w-0">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={reasonBreakdown} layout="vertical" margin={{ left: 10, right: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 10.5 }} />
                  <YAxis
                    type="category"
                    dataKey="reason"
                    width={150}
                    tick={{ fill: '#cbd5e1', fontSize: 10.5 }}
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
                    dataKey="warningCount"
                    stackId="ev"
                    name="Warning rows"
                    fill="#f59e0b"
                    className="cursor-pointer"
                    onClick={(entry: any) => {
                      const r = entry?.reason || entry?.payload?.reason;
                      if (r) setReasonFilter((cur) => (cur === r ? null : String(r)));
                    }}
                  />
                  <Bar
                    dataKey="normalCount"
                    stackId="ev"
                    name="Normal rows"
                    fill="#38bdf8"
                    className="cursor-pointer"
                    onClick={(entry: any) => {
                      const r = entry?.reason || entry?.payload?.reason;
                      if (r) setReasonFilter((cur) => (cur === r ? null : String(r)));
                    }}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        <div className="max-h-72 overflow-y-auto">
          {filteredEvents.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-400">No matching cluster events.</div>
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
                    <td className="py-2 px-3 font-mono tabular-nums text-slate-400 whitespace-nowrap">
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
                    <td className="py-2 px-3 font-mono tabular-nums text-slate-400 text-right">{ev.count}</td>
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
