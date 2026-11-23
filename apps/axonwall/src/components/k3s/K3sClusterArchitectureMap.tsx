'use client';

import React, { useMemo, useState } from 'react';
import Link from 'next/link';
import { Activity, CheckCircle2, Cpu, Network, ShieldAlert, SlidersHorizontal } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { K3sClusterPulse, K3sNodePulse } from './types';
import { computeClusterCapacitySummary } from '@/lib/k3s-visuals';

interface K3sClusterArchitectureMapProps {
  pulse: K3sClusterPulse;
  cniPlugin: string;
  onConfigureNode?: (nodeName: string) => void;
}

export function K3sClusterArchitectureMap({
  pulse,
  cniPlugin,
  onConfigureNode,
}: K3sClusterArchitectureMapProps) {
  const [metricMode, setMetricMode] = useState<'cpu' | 'mem'>('cpu');
  const [showLimits, setShowLimits] = useState<boolean>(false);

  const nodes: K3sNodePulse[] = Array.isArray(pulse.nodes) ? pulse.nodes : [];
  const cap = useMemo(() => computeClusterCapacitySummary(pulse), [pulse]);

  const controlPlaneNodes = useMemo(
    () =>
      nodes.filter((n) => {
        const r = (n.roles || '').toLowerCase();
        return r.includes('control-plane') || r.includes('master') || r.includes('etcd');
      }),
    [nodes]
  );

  const svgLayout = useMemo(() => {
    const count = Math.max(1, nodes.length);
    const boxW = Math.min(200, Math.max(150, Math.floor(960 / count) - 18));
    const boxH = 82;
    const gap = Math.max(16, Math.floor((1040 - count * boxW) / (count + 1)));
    const width = Math.max(960, count * (boxW + gap) + gap);
    const hubX = width / 2;
    const hubY = 58;
    const nodeY = 178;

    const placed = nodes.map((n, idx) => {
      const x = gap + idx * (boxW + gap);
      const isCp =
        (n.roles || '').toLowerCase().includes('control-plane') ||
        (n.roles || '').toLowerCase().includes('etcd');
      const isEdge = (n.roles || '').toLowerCase().includes('edge');
      const cpuPct =
        n.cpuAllocatableMillis > 0
          ? Math.min(100, Math.round((((n.cpuUsageMillis ?? n.cpuRequestsMillis) || 0) / n.cpuAllocatableMillis) * 100))
          : 0;
      const memPct =
        n.memAllocatableBytes > 0
          ? Math.min(100, Math.round((((n.memUsageBytes ?? n.memRequestsBytes) || 0) / n.memAllocatableBytes) * 100))
          : 0;
      return { node: n, x, y: nodeY, w: boxW, h: boxH, isCp, isEdge, cpuPct, memPct };
    });

    return { width, height: 292, hubX, hubY, placed };
  }, [nodes]);

  const allocationChartData = useMemo(() => {
    const gi = 1024 * 1024 * 1024;
    return nodes.map((n) => {
      if (metricMode === 'cpu') {
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
  }, [nodes, metricMode]);

  const quorumHealthy = cap.etcdVotersTotal === 0 || cap.etcdVotersReady >= Math.floor(cap.etcdVotersTotal / 2) + 1;

  return (
    <div className="space-y-5">
      {/* Control Plane & Etcd Quorum Topology SVG */}
      <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-bold text-white">
              HA Control Plane, Embedded Etcd Quorum &amp; Node Mesh
            </h3>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono tabular-nums">
            <span
              className={`px-2.5 py-1 rounded-lg border ${
                quorumHealthy
                  ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                  : 'bg-rose-500/15 border-rose-500/30 text-rose-300'
              }`}
            >
              Etcd Quorum: {cap.etcdVotersReady}/{cap.etcdVotersTotal || controlPlaneNodes.length} Voters{' '}
              {quorumHealthy ? 'Healthy' : 'Degraded'}
            </span>
            <span className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-sky-300">
              CNI: {cniPlugin === 'cilium-ebpf' ? 'Cilium eBPF + Hubble' : 'Flannel WireGuard-Native'}
            </span>
            <Link
              href="/k3s/explorer?resource=nodes"
              className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 hover:border-emerald-500/40 text-emerald-300"
            >
              Inspect in K9s →
            </Link>
          </div>
        </div>

        <div className="overflow-x-auto rounded-xl bg-slate-950 border border-slate-800 p-2">
          <svg
            viewBox={`0 0 ${svgLayout.width} ${svgLayout.height}`}
            className="w-full min-w-[780px] h-auto select-none"
            role="img"
            aria-label="Kubernetes HA control plane and node topology"
          >
            <defs>
              <pattern id="k3s-arch-grid" width="28" height="28" patternUnits="userSpaceOnUse">
                <path d="M 28 0 L 0 0 0 28" fill="none" stroke="rgba(30,41,59,0.5)" strokeWidth="1" />
              </pattern>
            </defs>
            <rect width={svgLayout.width} height={svgLayout.height} fill="url(#k3s-arch-grid)" />

            {/* Mesh Links between Control Plane Hub and All Nodes */}
            {svgLayout.placed.map((p) => {
              const cx = p.x + p.w / 2;
              const cy = p.y;
              const isReady = p.node.status === 'Ready';
              const stroke = !isReady
                ? '#f43f5e'
                : p.isCp
                  ? '#10b981'
                  : '#38bdf8';
              const d = `M ${svgLayout.hubX} ${svgLayout.hubY + 26} C ${svgLayout.hubX} ${svgLayout.hubY + 75}, ${cx} ${cy - 55}, ${cx} ${cy}`;
              return (
                <path
                  key={`link-${p.node.name}`}
                  d={d}
                  fill="none"
                  stroke={stroke}
                  strokeWidth={p.isCp ? 2 : 1.5}
                  strokeDasharray={!isReady ? '5 4' : p.isCp ? undefined : '4 3'}
                  strokeOpacity={isReady ? 0.7 : 0.6}
                />
              );
            })}

            {/* Control Plane Peer Line across CP nodes */}
            {svgLayout.placed.filter((p) => p.isCp).length > 1 && (
              <line
                x1={svgLayout.placed.filter((p) => p.isCp)[0].x + svgLayout.placed[0].w / 2}
                y1={svgLayout.placed[0].y + svgLayout.placed[0].h + 16}
                x2={
                  svgLayout.placed.filter((p) => p.isCp).slice(-1)[0].x +
                  svgLayout.placed[0].w / 2
                }
                y2={svgLayout.placed[0].y + svgLayout.placed[0].h + 16}
                stroke="#10b981"
                strokeWidth="1.5"
                strokeOpacity="0.45"
                strokeDasharray="3 3"
              />
            )}

            {/* Central Control Plane / Embedded Etcd Box */}
            <g transform={`translate(${svgLayout.hubX - 180}, ${svgLayout.hubY - 26})`}>
              <rect
                width={360}
                height={52}
                rx={12}
                fill="#0f172a"
                stroke={quorumHealthy ? '#10b981' : '#f43f5e'}
                strokeWidth={1.8}
              />
              <text
                x={180}
                y={22}
                textAnchor="middle"
                fill="#f8fafc"
                fontSize={12}
                fontWeight={700}
                fontFamily="ui-monospace, monospace"
              >
                K3s HA API Server &amp; Embedded Etcd Raft
              </text>
              <text
                x={180}
                y={39}
                textAnchor="middle"
                fill="#94a3b8"
                fontSize={10.5}
                fontFamily="ui-monospace, monospace"
              >
                {pulse.k3sVersion || 'k3s'} • {cniPlugin} • {cap.podsRunning}/{cap.podsTotal} pods active
              </text>
            </g>

            {/* Individual Cluster Node Cards */}
            {svgLayout.placed.map((p) => {
              const stroke =
                p.node.status !== 'Ready'
                  ? '#f43f5e'
                  : p.node.unschedulable
                    ? '#f59e0b'
                    : p.isCp
                      ? '#10b981'
                      : '#38bdf8';

              return (
                <g
                  key={p.node.name}
                  transform={`translate(${p.x}, ${p.y})`}
                  className={onConfigureNode ? 'cursor-pointer' : undefined}
                  onClick={() => onConfigureNode?.(p.node.name)}
                >
                  <rect
                    width={p.w}
                    height={p.h}
                    rx={12}
                    fill="#0f172a"
                    stroke={stroke}
                    strokeWidth={1.6}
                  />
                  <circle cx={14} cy={18} r={4} fill={stroke} />
                  <text
                    x={24}
                    y={21}
                    fill="#f8fafc"
                    fontSize={11.5}
                    fontWeight={700}
                    fontFamily="ui-monospace, monospace"
                  >
                    {p.node.name.length > 16 ? `${p.node.name.slice(0, 15)}…` : p.node.name}
                  </text>
                  <text
                    x={12}
                    y={36}
                    fill="#94a3b8"
                    fontSize={9.5}
                    fontFamily="ui-monospace, monospace"
                  >
                    {p.node.internalIp || '—'} • {p.node.podCount} pods
                  </text>
                  {/* CPU Micro-bar */}
                  <text x={12} y={53} fill="#94a3b8" fontSize={9} fontFamily="ui-monospace, monospace">
                    CPU {p.cpuPct}%
                  </text>
                  <rect x={68} y={46} width={p.w - 80} height={6} rx={3} fill="#1e293b" />
                  <rect
                    x={68}
                    y={46}
                    width={Math.max(0, Math.round(((p.w - 80) * p.cpuPct) / 100))}
                    height={6}
                    rx={3}
                    fill="#10b981"
                  />
                  {/* MEM Micro-bar */}
                  <text x={12} y={69} fill="#94a3b8" fontSize={9} fontFamily="ui-monospace, monospace">
                    MEM {p.memPct}%
                  </text>
                  <rect x={68} y={62} width={p.w - 80} height={6} rx={3} fill="#1e293b" />
                  <rect
                    x={68}
                    y={62}
                    width={Math.max(0, Math.round(((p.w - 80) * p.memPct) / 100))}
                    height={6}
                    rx={3}
                    fill="#0ea5e9"
                  />
                </g>
              );
            })}
          </svg>
        </div>
        {onConfigureNode && (
          <p className="text-[11px] font-mono text-slate-400">
            Click any node chassis above to configure its Kubernetes roles, labels, taints, and scheduling policy.
          </p>
        )}
      </div>

      {/* Node Resource Comparison Chart + Node Health Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Per-Node CPU / MEM Bar Chart */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Cpu className="w-4 h-4 text-emerald-400" /> Node Allocatable vs Requested vs Usage
              </h3>
              <p className="text-xs text-slate-400">
                {pulse.metricsAvailable
                  ? 'Live kubelet usage alongside Kubernetes scheduler requests'
                  : 'Kubernetes scheduler requests vs allocatable capacity'}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setShowLimits((v) => !v)}
                className={`px-2 py-1 rounded-md border text-[11px] font-mono transition ${
                  showLimits
                    ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                    : 'bg-slate-950 border-slate-800 text-slate-300'
                }`}
              >
                Limits
              </button>
              <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-[11px]">
                <button
                  type="button"
                  onClick={() => setMetricMode('cpu')}
                  className={`px-2 py-1 rounded-md font-mono transition ${
                    metricMode === 'cpu' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  CPU
                </button>
                <button
                  type="button"
                  onClick={() => setMetricMode('mem')}
                  className={`px-2 py-1 rounded-md font-mono transition ${
                    metricMode === 'mem' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  MEM
                </button>
              </div>
            </div>
          </div>

          <div className="h-[240px] w-full min-w-0">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={allocationChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: '#cbd5e1', fontSize: 11 }} />
                <YAxis
                  tick={{ fill: '#94a3b8', fontSize: 11 }}
                  unit={metricMode === 'cpu' ? 'c' : 'Gi'}
                  width={48}
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
                {showLimits && <Bar dataKey="limits" name="Limits" fill="#f59e0b" />}
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Node Conditions & Pressure Matrix */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-sky-400" /> Kubelet Conditions &amp; Taints Matrix
              </h3>
              <p className="text-xs text-slate-400">
                Real-time node pressure sensors, etcd voter state, and active scheduler taints
              </p>
            </div>
            <span className="text-xs font-mono tabular-nums text-slate-400">
              {nodes.length} nodes
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs font-mono">
              <thead className="bg-slate-950 border-b border-slate-800 text-[10px] uppercase text-slate-400">
                <tr>
                  <th className="py-2.5 px-3">Node</th>
                  <th className="py-2.5 px-2 text-center">Ready</th>
                  <th className="py-2.5 px-2 text-center">Etcd</th>
                  <th className="py-2.5 px-2 text-center">MemOK</th>
                  <th className="py-2.5 px-2 text-center">DiskOK</th>
                  <th className="py-2.5 px-2 text-center">PIDOK</th>
                  <th className="py-2.5 px-3 text-right">Config</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {nodes.map((n) => {
                  const conds = Array.isArray(n.conditions) ? n.conditions : [];
                  const getCond = (t: string) => conds.find((c) => c.type === t);
                  const readyOk = getCond('Ready')?.status === 'True';
                  const etcdC = getCond('EtcdIsVoter');
                  const memOk = getCond('MemoryPressure') ? getCond('MemoryPressure')?.status === 'False' : readyOk;
                  const diskOk = getCond('DiskPressure') ? getCond('DiskPressure')?.status === 'False' : readyOk;
                  const pidOk = getCond('PIDPressure') ? getCond('PIDPressure')?.status === 'False' : readyOk;
                  const taintCount = Array.isArray(n.taints) ? n.taints.length : 0;

                  const cellDot = (ok: boolean, na = false, title = '') =>
                    na ? (
                      <span className="text-slate-500">—</span>
                    ) : ok ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 inline" aria-label={title || 'Healthy'} />
                    ) : (
                      <ShieldAlert className="w-3.5 h-3.5 text-rose-400 inline" aria-label={title || 'Alert'} />
                    );

                  return (
                    <tr key={n.name} className="hover:bg-slate-800/40">
                      <td className="py-2.5 px-3 text-white font-semibold whitespace-nowrap">
                        <div>{n.name}</div>
                        {taintCount > 0 && (
                          <div className="text-[10px] text-amber-300">
                            {taintCount} {taintCount === 1 ? 'taint' : 'taints'}
                          </div>
                        )}
                      </td>
                      <td className="py-2.5 px-2 text-center">{cellDot(readyOk, false, getCond('Ready')?.message)}</td>
                      <td className="py-2.5 px-2 text-center">
                        {cellDot(etcdC?.status === 'True', !etcdC, etcdC?.message)}
                      </td>
                      <td className="py-2.5 px-2 text-center">{cellDot(memOk, false, getCond('MemoryPressure')?.message)}</td>
                      <td className="py-2.5 px-2 text-center">{cellDot(diskOk, false, getCond('DiskPressure')?.message)}</td>
                      <td className="py-2.5 px-2 text-center">{cellDot(pidOk, false, getCond('PIDPressure')?.message)}</td>
                      <td className="py-2.5 px-3 text-right">
                        {onConfigureNode ? (
                          <button
                            type="button"
                            onClick={() => onConfigureNode(n.name)}
                            className="p-1.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-sky-500/40 text-sky-300"
                            title={`Edit ${n.name} roles & taints`}
                          >
                            <SlidersHorizontal className="w-3.5 h-3.5" />
                          </button>
                        ) : (
                          <Link
                            href={`/k3s/explorer?resource=nodes&name=${encodeURIComponent(n.name)}`}
                            className="text-emerald-300 hover:underline"
                          >
                            Inspect
                          </Link>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
