'use client';

import React, { useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AlertTriangle, CheckCircle2, Database, HardDrive, Layers, Link2 } from 'lucide-react';
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
import type { K3sClusterPulse } from './types';
import { buildStorageVolumeGraph } from '@/lib/k3s-visuals';

interface K3sStorageVisualsProps {
  pulse: K3sClusterPulse;
  selectedNs?: string;
  onSelectNamespace?: (ns: string) => void;
}

const NS_COLORS = [
  '#10b981',
  '#0ea5e9',
  '#f59e0b',
  '#a855f7',
  '#06b6d4',
  '#34d399',
  '#38bdf8',
  '#fb923c',
  '#ec4899',
  '#84cc16',
];

export function K3sStorageVisuals({
  pulse,
  selectedNs = '_all',
  onSelectNamespace,
}: K3sStorageVisualsProps) {
  const router = useRouter();
  const [hoveredPvcId, setHoveredPvcId] = useState<string | null>(null);
  const graph = useMemo(() => buildStorageVolumeGraph(pulse), [pulse]);

  const svgModel = useMemo(() => {
    const pvcs = graph.attachments;
    const podMap = new Map<string, { id: string; name: string; status: string; statusTone: string; nodeName: string }>();
    const nodeMap = new Map<string, { id: string; name: string }>();
    const edges: Array<{ from: string; to: string; kind: 'pvc-pod' | 'pod-node'; broken?: boolean }> = [];

    for (const att of pvcs) {
      for (const p of att.pods) {
        podMap.set(p.id, p);
        edges.push({ from: att.pvcId, to: p.id, kind: 'pvc-pod', broken: att.isPending });
        const nodeId = `node/${p.nodeName}`;
        nodeMap.set(nodeId, { id: nodeId, name: p.nodeName });
        edges.push({ from: p.id, to: nodeId, kind: 'pod-node' });
      }
    }

    const pods = Array.from(podMap.values());
    const hostNodes = Array.from(nodeMap.values()).sort((a, b) => a.name.localeCompare(b.name));

    const boxW = 240;
    const boxH = 44;
    const rowGap = 56;
    const topMargin = 46;
    const colX = [28, 370, 712];

    const pvcPos = new Map<string, { x: number; y: number }>();
    pvcs.forEach((a, i) => pvcPos.set(a.pvcId, { x: colX[0], y: topMargin + i * rowGap }));

    const podPos = new Map<string, { x: number; y: number }>();
    pods.forEach((p, i) => podPos.set(p.id, { x: colX[1], y: topMargin + i * rowGap }));

    const nodePos = new Map<string, { x: number; y: number }>();
    hostNodes.forEach((n, i) => nodePos.set(n.id, { x: colX[2], y: topMargin + i * 74 }));

    const maxRows = Math.max(pvcs.length, pods.length, hostNodes.length * 1.3, 3);
    const height = Math.max(230, topMargin + Math.ceil(maxRows) * rowGap + 24);

    return {
      pvcs,
      pods,
      hostNodes,
      edges,
      boxW,
      boxH,
      colX,
      pvcPos,
      podPos,
      nodePos,
      width: 980,
      height,
    };
  }, [graph.attachments]);

  const highlightedSet = useMemo(() => {
    if (!hoveredPvcId) return null;
    const set = new Set<string>([hoveredPvcId]);
    const att = graph.attachments.find((a) => a.pvcId === hoveredPvcId);
    if (att) {
      for (const p of att.pods) {
        set.add(p.id);
        set.add(`node/${p.nodeName}`);
      }
    }
    return set;
  }, [hoveredPvcId, graph.attachments]);

  return (
    <div className="space-y-6">
      {/* 4-Card Storage Summary KPI Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-300">
            <span>Provisioned Storage</span>
            <HardDrive className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-white">
            {graph.totalGiB} GiB
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400">
            Across {pulse.counts?.pvsTotal ?? 0} PersistentVolumes
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-300">
            <span>Bound vs Pending Claims</span>
            {graph.pendingCount > 0 ? (
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            )}
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-white">
            {graph.boundCount} / {graph.boundCount + graph.pendingCount}
          </div>
          <div
            className={`text-[11px] font-mono tabular-nums ${
              graph.pendingCount > 0 ? 'text-amber-300' : 'text-emerald-400'
            }`}
          >
            {graph.pendingCount > 0 ? `${graph.pendingCount} Pending claim` : 'All PVCs Bound'}
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-300">
            <span>CSI StorageClasses</span>
            <Layers className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-white">
            {graph.byClass.length}
          </div>
          <div className="text-[11px] font-mono text-slate-400 truncate">
            {graph.byClass.filter((c) => c.pvcCount > 0).length} actively holding PVCs
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-300">
            <span>Pod Volume Attachments</span>
            <Link2 className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-white">
            {graph.attachedCount} Mounted
          </div>
          <div
            className={`text-[11px] font-mono tabular-nums ${
              graph.orphanedCount > 0 ? 'text-amber-300' : 'text-slate-400'
            }`}
          >
            {graph.orphanedCount > 0
              ? `${graph.orphanedCount} Bound unmounted (idle)`
              : 'All bound PVCs attached'}
          </div>
        </div>
      </div>

      {/* Dual Charts: StorageClass Capacity & Namespace Footprint Donut */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Horizontal BarChart of StorageClass Allocated GiB */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <HardDrive className="w-4 h-4 text-emerald-400" /> StorageClass Allocation (Live GiB)
              </h2>
              <p className="text-xs text-slate-400">
                Provisioned capacity by CSI StorageClass and bound PVC count
              </p>
            </div>
            <span className="text-xs font-mono tabular-nums text-emerald-400">
              {graph.totalGiB} GiB
            </span>
          </div>

          {graph.byClass.length === 0 ? (
            <div className="h-[230px] flex items-center justify-center text-xs text-slate-400">
              No StorageClasses detected yet.
            </div>
          ) : (
            <div className="h-[230px] w-full min-w-0">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={graph.byClass} layout="vertical" margin={{ left: 10, right: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} unit=" GiB" />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={150}
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
                    formatter={(val: any, _name: any, entry: any) => {
                      const d = entry?.payload;
                      return [
                        `${val} GiB (${d?.boundCount ?? 0}/${d?.pvcCount ?? 0} bound • ${d?.provisioner || 'csi'})`,
                        'Allocated',
                      ];
                    }}
                  />
                  <Bar dataKey="gib" name="Allocated GiB" radius={[0, 4, 4, 0]}>
                    {graph.byClass.map((sc) => (
                      <Cell
                        key={sc.name}
                        fill={sc.pendingCount > 0 ? '#f59e0b' : sc.gib > 0 ? '#10b981' : '#475569'}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Namespace Storage Footprint Donut */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <Database className="w-4 h-4 text-sky-400" /> Namespace Storage Footprint
              </h2>
              <p className="text-xs text-slate-400">
                Click any namespace slice or pill to filter the Live PVC table below
              </p>
            </div>
            {selectedNs !== '_all' && onSelectNamespace && (
              <button
                type="button"
                onClick={() => onSelectNamespace('_all')}
                className="px-2 py-0.5 rounded bg-slate-950 border border-slate-700 text-[11px] font-mono text-sky-300 hover:text-white"
              >
                Clear: {selectedNs} ✕
              </button>
            )}
          </div>

          {graph.byNamespace.length === 0 ? (
            <div className="h-[230px] flex items-center justify-center text-xs text-slate-400">
              No PersistentVolumeClaims provisioned in cluster.
            </div>
          ) : (
            <div className="h-[230px] w-full min-w-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={graph.byNamespace}
                    dataKey="gib"
                    nameKey="name"
                    cx="42%"
                    cy="50%"
                    innerRadius={48}
                    outerRadius={82}
                    paddingAngle={2}
                    onClick={(entry: any) => {
                      if (entry?.name && onSelectNamespace) {
                        onSelectNamespace(entry.name === selectedNs ? '_all' : entry.name);
                      }
                    }}
                  >
                    {graph.byNamespace.map((ns, idx) => (
                      <Cell
                        key={ns.name}
                        fill={NS_COLORS[idx % NS_COLORS.length]}
                        fillOpacity={selectedNs === '_all' || selectedNs === ns.name ? 1 : 0.28}
                        className="cursor-pointer"
                      />
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
                    formatter={(val: any, name: any, entry: any) => [
                      `${val} GiB (${entry?.payload?.pvcCount ?? 0} PVCs)`,
                      String(name),
                    ]}
                  />
                  <Legend
                    layout="vertical"
                    align="right"
                    verticalAlign="middle"
                    wrapperStyle={{ fontSize: '11px', maxWidth: '46%' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* PVC -> Pod -> Host Node Live Volume Attachment Map */}
      <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Link2 className="w-4 h-4 text-amber-400" /> PVC &rarr; Pod &rarr; Node Volume Attachment Map
            </h2>
            <p className="text-xs text-slate-400">
              Hover any PersistentVolumeClaim to highlight its mounting Pod and host Axonwall Node • Click to inspect in K9s
            </p>
          </div>
          <div className="flex items-center gap-3 text-[11px] font-mono text-slate-300">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" /> Mounted
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-400" /> Pending
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-slate-400" /> Unmounted
            </span>
          </div>
        </div>

        {svgModel.pvcs.length === 0 ? (
          <div className="py-10 text-center rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-400">
            No PVCs to map yet. Deploy a stateful workload with an OpenEBS StorageClass above.
          </div>
        ) : (
          <div className="max-h-[460px] overflow-auto rounded-xl bg-slate-950 border border-slate-800 p-2">
            <svg
              viewBox={`0 0 ${svgModel.width} ${svgModel.height}`}
              className="w-full min-w-[780px] h-auto select-none"
              role="img"
              aria-label="PVC to Pod to Node storage attachment diagram"
            >
              <text x={svgModel.colX[0]} y={24} fill="#94a3b8" fontSize={11} fontWeight={700} fontFamily="ui-monospace, monospace">
                PERSISTENT VOLUME CLAIMS ({svgModel.pvcs.length})
              </text>
              <text x={svgModel.colX[1]} y={24} fill="#94a3b8" fontSize={11} fontWeight={700} fontFamily="ui-monospace, monospace">
                MOUNTING PODS ({svgModel.pods.length})
              </text>
              <text x={svgModel.colX[2]} y={24} fill="#94a3b8" fontSize={11} fontWeight={700} fontFamily="ui-monospace, monospace">
                HOST NODES ({svgModel.hostNodes.length})
              </text>

              {/* Attachment Bezier Curves */}
              {svgModel.edges.map((e, idx) => {
                const src = e.kind === 'pvc-pod' ? svgModel.pvcPos.get(e.from) : svgModel.podPos.get(e.from);
                const dst = e.kind === 'pvc-pod' ? svgModel.podPos.get(e.to) : svgModel.nodePos.get(e.to);
                if (!src || !dst) return null;

                const isHot =
                  highlightedSet === null || (highlightedSet.has(e.from) && highlightedSet.has(e.to));
                const x1 = src.x + svgModel.boxW;
                const y1 = src.y + svgModel.boxH / 2;
                const x2 = dst.x;
                const y2 = dst.y + svgModel.boxH / 2;
                const dx = Math.max(40, Math.abs(x2 - x1) * 0.45);
                const d = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;

                return (
                  <path
                    key={`${e.from}->${e.to}-${idx}`}
                    d={d}
                    fill="none"
                    stroke={e.kind === 'pvc-pod' ? '#f59e0b' : '#818cf8'}
                    strokeWidth={hoveredPvcId && isHot ? 2.4 : 1.5}
                    strokeOpacity={isHot ? 0.8 : 0.12}
                    strokeDasharray={e.kind === 'pod-node' ? '4 4' : undefined}
                  />
                );
              })}

              {/* PVC Nodes */}
              {svgModel.pvcs.map((att) => {
                const pos = svgModel.pvcPos.get(att.pvcId);
                if (!pos) return null;
                const dimmed = highlightedSet !== null && !highlightedSet.has(att.pvcId);
                const stroke = att.isPending ? '#f59e0b' : att.isOrphaned ? '#64748b' : '#10b981';
                const href = `/k3s/explorer?resource=persistentvolumeclaims&namespace=${encodeURIComponent(
                  att.namespace
                )}&name=${encodeURIComponent(att.name)}`;

                return (
                  <g
                    key={att.pvcId}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    opacity={dimmed ? 0.25 : 1}
                    onMouseEnter={() => setHoveredPvcId(att.pvcId)}
                    onMouseLeave={() => setHoveredPvcId(null)}
                    onClick={() => router.push(href)}
                    className="cursor-pointer"
                  >
                    <rect
                      width={svgModel.boxW}
                      height={svgModel.boxH}
                      rx={8}
                      fill="#0f172a"
                      stroke={stroke}
                      strokeWidth={1.5}
                    />
                    <circle cx={12} cy={15} r={3.5} fill={stroke} />
                    <text x={21} y={18} fill="#cbd5e1" fontSize={10} fontWeight={700} fontFamily="ui-monospace, monospace">
                      {att.name.length > 26 ? `${att.name.slice(0, 24)}..` : att.name}
                    </text>
                    <text x={12} y={34} fill="#94a3b8" fontSize={9.5} fontFamily="ui-monospace, monospace">
                      {att.namespace} • {att.capacity} • {att.isPending ? 'PENDING' : att.isOrphaned ? 'IDLE' : att.storageClass}
                    </text>
                  </g>
                );
              })}

              {/* Mounting Pod Nodes */}
              {svgModel.pods.map((pod) => {
                const pos = svgModel.podPos.get(pod.id);
                if (!pos) return null;
                const dimmed = highlightedSet !== null && !highlightedSet.has(pod.id);
                const stroke =
                  pod.statusTone === 'err' ? '#f43f5e' : pod.statusTone === 'warn' ? '#f59e0b' : '#10b981';
                const parts = pod.id.split('/');
                const ns = parts[1] || 'default';
                const href = `/k3s/explorer?resource=pods&namespace=${encodeURIComponent(ns)}&name=${encodeURIComponent(
                  pod.name
                )}`;

                return (
                  <g
                    key={pod.id}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    opacity={dimmed ? 0.25 : 1}
                    onClick={() => router.push(href)}
                    className="cursor-pointer"
                  >
                    <rect
                      width={svgModel.boxW}
                      height={svgModel.boxH}
                      rx={8}
                      fill="#0f172a"
                      stroke={stroke}
                      strokeWidth={1.4}
                    />
                    <text x={12} y={18} fill="#f8fafc" fontSize={10.5} fontWeight={600} fontFamily="ui-monospace, monospace">
                      {pod.name.length > 27 ? `${pod.name.slice(0, 25)}..` : pod.name}
                    </text>
                    <text x={12} y={34} fill="#94a3b8" fontSize={9.5} fontFamily="ui-monospace, monospace">
                      Pod • {pod.status}
                    </text>
                  </g>
                );
              })}

              {/* Host Nodes */}
              {svgModel.hostNodes.map((n) => {
                const pos = svgModel.nodePos.get(n.id);
                if (!pos) return null;
                const dimmed = highlightedSet !== null && !highlightedSet.has(n.id);
                const href = `/k3s/explorer?resource=nodes&name=${encodeURIComponent(n.name)}`;

                return (
                  <g
                    key={n.id}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    opacity={dimmed ? 0.25 : 1}
                    onClick={() => router.push(href)}
                    className="cursor-pointer"
                  >
                    <rect
                      width={svgModel.boxW}
                      height={svgModel.boxH}
                      rx={8}
                      fill="#0f172a"
                      stroke="#818cf8"
                      strokeWidth={1.5}
                    />
                    <circle cx={12} cy={15} r={3.5} fill="#818cf8" />
                    <text x={21} y={18} fill="#f8fafc" fontSize={11} fontWeight={700} fontFamily="ui-monospace, monospace">
                      {n.name}
                    </text>
                    <text x={12} y={34} fill="#94a3b8" fontSize={9.5} fontFamily="ui-monospace, monospace">
                      Axonwall K3s Node
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        )}
      </div>
    </div>
  );
}
