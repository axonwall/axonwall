'use client';

import React, { useEffect, useMemo, useState } from 'react';
import { Cpu, GitBranch, Layers } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { VowAppDefinition } from '@axonwall/lib/compile/vow';
import type { K3sClusterPulse } from './types';
import { buildVowVisualSummary } from '@/lib/k3s-visuals';

interface K3sVowVisualsProps {
  enabledAppIds: string[];
  resolvedAppIds: string[];
  autoDeps: string[];
  catalog: VowAppDefinition[];
  pulse: K3sClusterPulse | null;
}

export function K3sVowVisuals({
  enabledAppIds,
  resolvedAppIds,
  autoDeps,
  catalog,
  pulse,
}: K3sVowVisualsProps) {
  const [mounted, setMounted] = useState(false);
  const [graphExpanded, setGraphExpanded] = useState(true);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  useEffect(() => {
    setMounted(true);
  }, []);

  const summary = useMemo(
    () => buildVowVisualSummary(enabledAppIds, resolvedAppIds, autoDeps, catalog, pulse),
    [enabledAppIds, resolvedAppIds, autoDeps, catalog, pulse]
  );

  // Depth-tiered columns for VOW dependency SVG
  const depLayout = useMemo(() => {
    const nodes = summary.dependencyGraph.nodes;
    const edges = summary.dependencyGraph.edges;
    const byDepth = new Map<number, typeof nodes>();

    for (const n of nodes) {
      const arr = byDepth.get(n.depth) || [];
      arr.push(n);
      byDepth.set(n.depth, arr);
    }

    const depths = Array.from(byDepth.keys()).sort((a, b) => a - b);
    const colCount = Math.max(1, depths.length);
    const boxW = 210;
    const boxH = 54;
    const colGap = 70;
    const leftPad = 24;
    const topPad = 40;
    const rowGap = 68;

    const posMap = new Map<string, { x: number; y: number; node: (typeof nodes)[number] }>();
    let maxRows = 1;

    depths.forEach((d, colIdx) => {
      const colNodes = byDepth.get(d) || [];
      if (colNodes.length > maxRows) maxRows = colNodes.length;
      const x = leftPad + colIdx * (boxW + colGap);
      colNodes.forEach((n, rowIdx) => {
        posMap.set(n.id, { x, y: topPad + rowIdx * rowGap, node: n });
      });
    });

    const width = Math.max(720, leftPad * 2 + colCount * boxW + Math.max(0, colCount - 1) * colGap);
    const height = Math.max(190, topPad + maxRows * rowGap + 18);

    return { nodes, edges, posMap, boxW, boxH, depths, width, height };
  }, [summary.dependencyGraph]);

  const highlighted = useMemo(() => {
    if (!hoveredNodeId) return null;
    const set = new Set<string>([hoveredNodeId]);
    for (const e of summary.dependencyGraph.edges) {
      if (e.from === hoveredNodeId) set.add(e.to);
      if (e.to === hoveredNodeId) set.add(e.from);
    }
    return set;
  }, [hoveredNodeId, summary.dependencyGraph.edges]);

  const usedPct =
    summary.ramBudget.clusterAllocatableGb > 0
      ? Math.min(100, Math.round((summary.ramBudget.clusterUsedGb / summary.ramBudget.clusterAllocatableGb) * 100))
      : 0;
  const vovAddPct =
    summary.ramBudget.clusterAllocatableGb > 0
      ? Math.min(
          100 - usedPct,
          Math.round((summary.ramBudget.stackMemoryGb / summary.ramBudget.clusterAllocatableGb) * 100)
        )
      : 0;

  return (
    <div className="space-y-5">
      {/* Row 1: RAM Headroom Fit + Category Budget BarChart */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Cluster RAM Headroom vs Projected Stack */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-4 flex flex-col justify-between">
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Cpu className="w-4 h-4 text-emerald-400" /> Cluster Memory Fit vs Selected VOW Stack
              </h3>
              {summary.ramBudget.hasLiveCluster ? (
                <span
                  className={`px-2 py-0.5 rounded text-[11px] font-mono border ${
                    summary.ramBudget.fitsInFreeRam
                      ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                      : 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                  }`}
                >
                  {summary.ramBudget.fitsInFreeRam ? 'Fits in Free RAM' : 'Exceeds Free RAM'}
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-400">
                  Cluster Offline
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400">
              {summary.ramBudget.hasLiveCluster
                ? `${summary.ramBudget.stackMemoryGb} GiB projected across ${resolvedAppIds.length} resolved operators vs ${summary.ramBudget.clusterFreeGb} GiB currently free on cluster (${summary.ramBudget.clusterAllocatableGb} GiB total).`
                : `Estimated ${summary.ramBudget.stackMemoryGb} GiB RAM footprint for ${resolvedAppIds.length} resolved apps (connect K3s cluster to compare against live node headroom).`}
            </p>
          </div>

          <div className="space-y-2.5">
            {summary.ramBudget.hasLiveCluster && (
              <>
                <div className="h-3.5 rounded-full bg-slate-950 border border-slate-800 overflow-hidden flex">
                  <div
                    className="h-full bg-sky-500"
                    style={{ width: `${usedPct}%` }}
                    title={`Live Cluster Used: ${summary.ramBudget.clusterUsedGb} GiB`}
                  />
                  <div
                    className={`h-full ${summary.ramBudget.fitsInFreeRam ? 'bg-emerald-500' : 'bg-amber-500'}`}
                    style={{ width: `${vovAddPct}%` }}
                    title={`Selected VOW Stack: ${summary.ramBudget.stackMemoryGb} GiB`}
                  />
                </div>
                <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono tabular-nums text-slate-300">
                  <span className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-sm bg-sky-500" />
                    Used: {summary.ramBudget.clusterUsedGb} GiB ({usedPct}%)
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span
                      className={`w-2.5 h-2.5 rounded-sm ${
                        summary.ramBudget.fitsInFreeRam ? 'bg-emerald-500' : 'bg-amber-500'
                      }`}
                    />
                    VOW Budget: +{summary.ramBudget.stackMemoryGb} GiB
                  </span>
                  <span className="text-slate-400">
                    Projected: {summary.ramBudget.projectedTotalPct}% of {summary.ramBudget.clusterAllocatableGb} GiB
                  </span>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Category Memory Breakdown */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Layers className="w-4 h-4 text-sky-400" /> Stack Memory Footprint by Category
              </h3>
              <p className="text-xs text-slate-400">
                Estimated RAM allocation across resolved app categories
              </p>
            </div>
            <span className="text-xs font-mono tabular-nums text-emerald-400">
              {summary.ramBudget.stackMemoryGb} GiB
            </span>
          </div>

          {!mounted ? (
            <div className="h-[190px] rounded-xl bg-slate-950 border border-slate-800 animate-pulse" />
          ) : summary.memoryByCategory.length === 0 ? (
            <div className="h-[190px] flex items-center justify-center text-xs text-slate-400">
              Select at least one application below to visualize category memory breakdown.
            </div>
          ) : (
            <div className="h-[190px] w-full min-w-0">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={summary.memoryByCategory} layout="vertical" margin={{ left: 10, right: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} unit=" GiB" />
                  <YAxis
                    type="category"
                    dataKey="category"
                    width={160}
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
                    formatter={(val: any, _name: any, entry: any) => [
                      `${val} GiB (${entry?.payload?.appCount ?? 0} apps)`,
                      'Estimated RAM',
                    ]}
                  />
                  <Bar dataKey="memoryGb" name="Estimated GiB" fill="#10b981" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Collapsible Operator Dependency & Live Cluster Presence Graph */}
      <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <GitBranch className="w-4 h-4 text-emerald-400" /> Resolved App Dependency Graph &amp; Live Namespace Pods
            </h3>
            <p className="text-xs text-slate-400">
              Auto-resolved operator dependencies matched against live running pods per app namespace
            </p>
          </div>
          <button
            type="button"
            onClick={() => setGraphExpanded((v) => !v)}
            className="px-3 py-1 rounded-lg bg-slate-950 border border-slate-800 hover:border-emerald-500/40 text-xs font-mono text-emerald-300"
          >
            {graphExpanded ? 'Hide Graph' : `Show Graph (${depLayout.nodes.length} apps)`}
          </button>
        </div>

        {graphExpanded &&
          (depLayout.nodes.length === 0 ? (
            <div className="py-8 text-center rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-400">
              No VOW applications enabled yet.
            </div>
          ) : (
            <div className="max-h-[420px] overflow-auto rounded-xl bg-slate-950 border border-slate-800 p-2">
              <svg
                viewBox={`0 0 ${depLayout.width} ${depLayout.height}`}
                className="w-full min-w-[680px] h-auto select-none"
                role="img"
                aria-label="VOW app dependency graph"
              >
                {depLayout.depths.map((d, i) => (
                  <text
                    key={`tier-${d}`}
                    x={24 + i * (depLayout.boxW + 70)}
                    y={22}
                    fill="#94a3b8"
                    fontSize={10.5}
                    fontWeight={700}
                    fontFamily="ui-monospace, monospace"
                  >
                    {d === 0 ? 'FOUNDATION / CORES' : `DEPENDENT TIER ${d}`}
                  </text>
                ))}

                {/* Dependency Edges */}
                {depLayout.edges.map((e, idx) => {
                  const src = depLayout.posMap.get(e.from);
                  const dst = depLayout.posMap.get(e.to);
                  if (!src || !dst) return null;
                  const hot = highlighted === null || (highlighted.has(e.from) && highlighted.has(e.to));
                  const x1 = src.x + depLayout.boxW;
                  const y1 = src.y + depLayout.boxH / 2;
                  const x2 = dst.x;
                  const y2 = dst.y + depLayout.boxH / 2;
                  const dx = Math.max(30, Math.abs(x2 - x1) * 0.45);
                  return (
                    <path
                      key={`${e.from}->${e.to}-${idx}`}
                      d={`M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`}
                      fill="none"
                      stroke="#38bdf8"
                      strokeWidth={hoveredNodeId && hot ? 2.2 : 1.4}
                      strokeOpacity={hot ? 0.72 : 0.14}
                    />
                  );
                })}

                {/* App Nodes */}
                {depLayout.nodes.map((node) => {
                  const pos = depLayout.posMap.get(node.id);
                  if (!pos) return null;
                  const dimmed = highlighted !== null && !highlighted.has(node.id);
                  const stroke =
                    node.liveUnhealthy > 0
                      ? '#f43f5e'
                      : node.livePods > 0
                        ? '#10b981'
                        : node.isAutoDep
                          ? '#f59e0b'
                          : '#475569';

                  return (
                    <g
                      key={node.id}
                      transform={`translate(${pos.x}, ${pos.y})`}
                      opacity={dimmed ? 0.25 : 1}
                      onMouseEnter={() => setHoveredNodeId(node.id)}
                      onMouseLeave={() => setHoveredNodeId(null)}
                    >
                      <rect
                        width={depLayout.boxW}
                        height={depLayout.boxH}
                        rx={8}
                        fill="#0f172a"
                        stroke={stroke}
                        strokeWidth={hoveredNodeId === node.id ? 2 : 1.4}
                      />
                      <circle cx={12} cy={17} r={3.5} fill={stroke} />
                      <text x={22} y={20} fill="#f8fafc" fontSize={11} fontWeight={700} fontFamily="ui-monospace, monospace">
                        {node.name.length > 20 ? `${node.name.slice(0, 18)}..` : node.name}
                      </text>
                      <text x={12} y={35} fill="#94a3b8" fontSize={9.5} fontFamily="ui-monospace, monospace">
                        ns:{node.namespace} • {node.memoryMb}MB
                      </text>
                      <text
                        x={12}
                        y={47}
                        fill={node.livePods > 0 ? '#34d399' : '#94a3b8'}
                        fontSize={9}
                        fontFamily="ui-monospace, monospace"
                      >
                        {node.livePods > 0
                          ? `${node.livePods} running pod${node.livePods === 1 ? '' : 's'}${node.liveUnhealthy > 0 ? ` (${node.liveUnhealthy} unhealthy)` : ''}`
                          : node.isAutoDep
                            ? 'Auto-Dependency (pending deploy)'
                            : 'Configured (not deployed)'}
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>
          ))}
      </div>
    </div>
  );
}
