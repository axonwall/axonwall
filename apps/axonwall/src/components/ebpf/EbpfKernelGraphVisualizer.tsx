'use client';

import React, { useMemo, useState } from 'react';
import { GitBranch, RotateCcw, Search } from 'lucide-react';
import {
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from 'recharts';
import {
  buildBpfDependencyGraph,
  formatBytesCompact,
  formatDurationNs,
  type BpfLinkInventoryItem,
  type BpfMapInventoryItem,
  type BpfProgramInventoryItem,
  type KernelBpfInventory,
} from '@/lib/ebpf-telemetry';

interface EbpfKernelGraphVisualizerProps {
  inventory?: KernelBpfInventory;
  daemonDown?: boolean;
}

type SelectedItem =
  | { kind: 'link'; item: BpfLinkInventoryItem }
  | { kind: 'program'; item: BpfProgramInventoryItem }
  | { kind: 'map'; item: BpfMapInventoryItem }
  | null;

const TYPE_COLORS: Record<string, string> = {
  XDP: '#10b981',
  LSM: '#f43f5e',
  Tracing: '#38bdf8',
  SchedCLS: '#a855f7',
  CGroupSKB: '#f59e0b',
  RawTracepoint: '#06b6d4',
};

function colorForProgType(t: string): string {
  return TYPE_COLORS[t] || '#34d399';
}

function truncateText(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 2)}..`;
}

export function EbpfKernelGraphVisualizer({
  inventory,
  daemonDown = false,
}: EbpfKernelGraphVisualizerProps) {
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<SelectedItem>(null);
  const [scatterYMetric, setScatterYMetric] = useState<'jitedKiB' | 'avgNsPerRun'>('jitedKiB');

  const graph = useMemo(
    () => buildBpfDependencyGraph(inventory, { typeFilter, search, maxPrograms: 14 }),
    [inventory, typeFilter, search]
  );

  const hasVerifiedInsns = useMemo(
    () => graph.scatterPoints.some((pt) => pt.verifiedInsns > 0),
    [graph.scatterPoints]
  );
  const hasRuntimeStats = useMemo(
    () => graph.scatterPoints.some((pt) => pt.avgNsPerRun > 0),
    [graph.scatterPoints]
  );
  const effectiveScatterY =
    scatterYMetric === 'avgNsPerRun' && hasRuntimeStats ? 'avgNsPerRun' : 'jitedKiB';

  const hasLinksColumn = graph.links.length > 0;

  const layout = useMemo(() => {
    const rowStep = 50;
    const topPad = 42;
    const linkColX = 24;
    const progColX = hasLinksColumn ? 344 : 64;
    const mapColX = hasLinksColumn ? 684 : 556;
    const nodeW = hasLinksColumn ? 272 : 340;
    const nodeH = 38;

    const linksPos = new Map<number, { x: number; y: number; w: number; h: number }>();
    const progsPos = new Map<number, { x: number; y: number; w: number; h: number }>();
    const mapsPos = new Map<number, { x: number; y: number; w: number; h: number }>();

    graph.links.forEach((l, idx) => {
      linksPos.set(l.id, { x: linkColX, y: topPad + idx * rowStep, w: nodeW, h: nodeH });
    });
    graph.programs.forEach((p, idx) => {
      progsPos.set(p.id, { x: progColX, y: topPad + idx * rowStep, w: nodeW, h: nodeH });
    });
    graph.maps.forEach((m, idx) => {
      mapsPos.set(m.id, { x: mapColX, y: topPad + idx * rowStep, w: nodeW, h: nodeH });
    });

    const maxRows = Math.max(graph.links.length, graph.programs.length, graph.maps.length, 3);
    const height = Math.max(240, topPad + maxRows * rowStep + 24);

    return { linkColX, progColX, mapColX, nodeW, nodeH, linksPos, progsPos, mapsPos, height };
  }, [graph, hasLinksColumn]);

  const highlightSets = useMemo(() => {
    const linkIds = new Set<number>();
    const progIds = new Set<number>();
    const mapIds = new Set<number>();
    if (!selected) return { active: false, linkIds, progIds, mapIds };

    if (selected.kind === 'link') {
      linkIds.add(selected.item.id);
      progIds.add(selected.item.programId);
      const prog = graph.programs.find((p) => p.id === selected.item.programId);
      if (prog) {
        prog.mapIds.forEach((mid) => mapIds.add(mid));
      }
    } else if (selected.kind === 'program') {
      progIds.add(selected.item.id);
      selected.item.mapIds.forEach((mid) => mapIds.add(mid));
      graph.links.forEach((l) => {
        if (l.programId === selected.item.id) linkIds.add(l.id);
      });
    } else if (selected.kind === 'map') {
      mapIds.add(selected.item.id);
      graph.programs.forEach((p) => {
        if (p.mapIds.includes(selected.item.id)) {
          progIds.add(p.id);
          graph.links.forEach((l) => {
            if (l.programId === p.id) linkIds.add(l.id);
          });
        }
      });
    }

    return { active: true, linkIds, progIds, mapIds };
  }, [selected, graph]);

  return (
    <section className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-emerald-400" />
            Kernel <code className="font-mono text-xs text-emerald-300">bpf_link</code> &harr; Program &harr; Map Architecture Graph
          </h3>
          <p className="text-xs text-slate-400">
            Interactive Ring-0 object wiring enumerated from <code className="font-mono">sys_bpf</code> (showing{' '}
            {graph.programs.length} of {graph.totalProgramsMatched} matched programs, {graph.maps.length} referenced maps,{' '}
            {graph.links.length} links).
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative w-56">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter hook, prog, map, ID..."
              aria-label="Filter BPF dependency graph"
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500/50"
            />
          </div>
          {selected && (
            <button
              type="button"
              onClick={() => setSelected(null)}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200 hover:text-white"
            >
              <RotateCcw className="w-3 h-3" />
              Clear Selection
            </button>
          )}
        </div>
      </div>

      {graph.availableTypes.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          {(['all', ...graph.availableTypes] as string[]).map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setTypeFilter(t)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition ${
                typeFilter === t
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {t === 'all' ? `All Types (${inventory?.totalPrograms ?? 0})` : t}
            </button>
          ))}
        </div>
      )}

      {daemonDown ? (
        <div className="py-10 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
          Daemon offline — kernel eBPF dependency graph unavailable.
        </div>
      ) : !inventory?.available ? (
        <div className="py-10 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
          {inventory?.error || 'Kernel sys_bpf object enumeration unavailable on this host.'}
        </div>
      ) : graph.programs.length === 0 ? (
        <div className="py-10 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
          No loaded eBPF programs match the active search or type filter.
        </div>
      ) : (
        <div className="space-y-5">
          {!hasLinksColumn && (
            <div className="text-xs text-slate-400">
              No active <code className="font-mono text-slate-300">bpf_link</code> handles reported; showing direct Program &rarr; Map ownership edges.
            </div>
          )}

          <div className="max-h-[460px] overflow-auto rounded-lg bg-slate-950 border border-slate-800 p-2">
            <svg
              viewBox={`0 0 980 ${layout.height}`}
              role="img"
              aria-label="Kernel BPF link, program, and map dependency graph"
              className="w-full min-w-[760px] h-auto select-none"
            >
              <rect
                x={0}
                y={0}
                width={980}
                height={layout.height}
                fill="transparent"
                onClick={() => setSelected(null)}
              />

              {/* Column headings */}
              {hasLinksColumn && (
                <text x={layout.linkColX} y={24} fill="#94a3b8" fontSize={10} fontWeight={700}>
                  BPF LINKS ({graph.links.length})
                </text>
              )}
              <text x={layout.progColX} y={24} fill="#94a3b8" fontSize={10} fontWeight={700}>
                EBPF PROGRAMS ({graph.programs.length})
              </text>
              <text x={layout.mapColX} y={24} fill="#94a3b8" fontSize={10} fontWeight={700}>
                BPF MAPS ({graph.maps.length})
              </text>

              {/* Link -> Program Edges */}
              {graph.linkToProgEdges.map((edge) => {
                const lp = layout.linksPos.get(edge.linkId);
                const pp = layout.progsPos.get(edge.programId);
                if (!lp || !pp) return null;
                const x1 = lp.x + lp.w;
                const y1 = lp.y + lp.h / 2;
                const x2 = pp.x;
                const y2 = pp.y + pp.h / 2;
                const cx = (x1 + x2) / 2;
                const highlighted =
                  !highlightSets.active ||
                  (highlightSets.linkIds.has(edge.linkId) && highlightSets.progIds.has(edge.programId));
                return (
                  <path
                    key={edge.id}
                    d={`M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`}
                    fill="none"
                    stroke={highlighted ? '#38bdf8' : '#1e293b'}
                    strokeWidth={highlighted && highlightSets.active ? 2.2 : 1.2}
                    strokeOpacity={highlighted ? 0.8 : 0.25}
                  />
                );
              })}

              {/* Program -> Map Edges */}
              {graph.progToMapEdges.map((edge) => {
                const pp = layout.progsPos.get(edge.programId);
                const mp = layout.mapsPos.get(edge.mapId);
                if (!pp || !mp) return null;
                const x1 = pp.x + pp.w;
                const y1 = pp.y + pp.h / 2;
                const x2 = mp.x;
                const y2 = mp.y + mp.h / 2;
                const cx = (x1 + x2) / 2;
                const highlighted =
                  !highlightSets.active ||
                  (highlightSets.progIds.has(edge.programId) && highlightSets.mapIds.has(edge.mapId));
                return (
                  <path
                    key={edge.id}
                    d={`M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`}
                    fill="none"
                    stroke={highlighted ? '#10b981' : '#1e293b'}
                    strokeWidth={highlighted && highlightSets.active ? 2.2 : 1.2}
                    strokeOpacity={highlighted ? 0.75 : 0.22}
                  />
                );
              })}

              {/* Link Nodes */}
              {graph.links.map((lnk) => {
                const pos = layout.linksPos.get(lnk.id);
                if (!pos) return null;
                const isSelected = selected?.kind === 'link' && selected.item.id === lnk.id;
                const highlighted = !highlightSets.active || highlightSets.linkIds.has(lnk.id);
                return (
                  <g
                    key={`link-${lnk.id}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelected({ kind: 'link', item: lnk });
                    }}
                    role="button"
                    tabIndex={0}
                    aria-label={`BPF Link ${lnk.id} ${lnk.attachDetail || lnk.type}`}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setSelected({ kind: 'link', item: lnk });
                      }
                    }}
                    className="cursor-pointer outline-none"
                    opacity={highlighted ? 1 : 0.28}
                  >
                    <rect
                      x={pos.x}
                      y={pos.y}
                      width={pos.w}
                      height={pos.h}
                      rx={6}
                      fill="#082f49"
                      stroke={isSelected ? '#f8fafc' : '#38bdf8'}
                      strokeWidth={isSelected ? 2 : 1}
                    />
                    <text x={pos.x + 10} y={pos.y + 15} fill="#e0f2fe" fontSize={11} fontFamily="monospace" fontWeight={700}>
                      {truncateText(lnk.attachDetail || `${lnk.type} link`, 31)}
                    </text>
                    <text x={pos.x + 10} y={pos.y + 30} fill="#7dd3fc" fontSize={10} fontFamily="monospace">
                      #{lnk.id} · {lnk.type} -&gt; prog#{lnk.programId}
                    </text>
                  </g>
                );
              })}

              {/* Program Nodes */}
              {graph.programs.map((prog) => {
                const pos = layout.progsPos.get(prog.id);
                if (!pos) return null;
                const isSelected = selected?.kind === 'program' && selected.item.id === prog.id;
                const highlighted = !highlightSets.active || highlightSets.progIds.has(prog.id);
                const stroke = colorForProgType(prog.type);
                return (
                  <g
                    key={`prog-${prog.id}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelected({ kind: 'program', item: prog });
                    }}
                    role="button"
                    tabIndex={0}
                    aria-label={`BPF Program ${prog.name} (${prog.type})`}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setSelected({ kind: 'program', item: prog });
                      }
                    }}
                    className="cursor-pointer outline-none"
                    opacity={highlighted ? 1 : 0.28}
                  >
                    <rect
                      x={pos.x}
                      y={pos.y}
                      width={pos.w}
                      height={pos.h}
                      rx={6}
                      fill="#064e3b"
                      fillOpacity={0.55}
                      stroke={isSelected ? '#f8fafc' : stroke}
                      strokeWidth={isSelected ? 2 : 1.1}
                    />
                    <text x={pos.x + 10} y={pos.y + 15} fill="#f8fafc" fontSize={11} fontFamily="monospace" fontWeight={700}>
                      {truncateText(prog.name, hasLinksColumn ? 29 : 36)}
                    </text>
                    <text x={pos.x + 10} y={pos.y + 30} fill="#a7f3d0" fontSize={10} fontFamily="monospace">
                      #{prog.id} · {prog.type} · {formatBytesCompact(prog.jitedBytes)} · {prog.mapIds.length} maps
                    </text>
                  </g>
                );
              })}

              {/* Map Nodes */}
              {graph.maps.map((m) => {
                const pos = layout.mapsPos.get(m.id);
                if (!pos) return null;
                const isSelected = selected?.kind === 'map' && selected.item.id === m.id;
                const highlighted = !highlightSets.active || highlightSets.mapIds.has(m.id);
                return (
                  <g
                    key={`map-${m.id}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelected({ kind: 'map', item: m });
                    }}
                    role="button"
                    tabIndex={0}
                    aria-label={`BPF Map ${m.name} (${m.type})`}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setSelected({ kind: 'map', item: m });
                      }
                    }}
                    className="cursor-pointer outline-none"
                    opacity={highlighted ? 1 : 0.28}
                  >
                    <rect
                      x={pos.x}
                      y={pos.y}
                      width={pos.w}
                      height={pos.h}
                      rx={6}
                      fill="#1e1b4b"
                      fillOpacity={0.75}
                      stroke={isSelected ? '#f8fafc' : '#a855f7'}
                      strokeWidth={isSelected ? 2 : 1}
                    />
                    <text x={pos.x + 10} y={pos.y + 15} fill="#f3e8ff" fontSize={11} fontFamily="monospace" fontWeight={700}>
                      {truncateText(m.name, hasLinksColumn ? 29 : 36)}
                    </text>
                    <text x={pos.x + 10} y={pos.y + 30} fill="#d8b4fe" fontSize={10} fontFamily="monospace">
                      #{m.id} · {m.type} · {formatBytesCompact(m.memlockBytes)}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Selected Kernel Object Inspector */}
          {selected && (
            <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
              {selected.kind === 'link' && (
                <div className="flex flex-wrap items-center gap-4 font-mono tabular-nums text-slate-200">
                  <span className="text-sky-300 font-bold">BPF Link #{selected.item.id}</span>
                  <span>Type: {selected.item.type}</span>
                  <span>Target Prog: #{selected.item.programId}</span>
                  {selected.item.attachDetail && <span>Hook: {selected.item.attachDetail}</span>}
                </div>
              )}
              {selected.kind === 'program' && (
                <div className="flex flex-wrap items-center gap-4 font-mono tabular-nums text-slate-200">
                  <span className="text-emerald-300 font-bold">
                    Prog #{selected.item.id} ({selected.item.name})
                  </span>
                  <span>Type: {selected.item.type}</span>
                  <span>Tag: {selected.item.tag}</span>
                  <span>JIT: {formatBytesCompact(selected.item.jitedBytes)}</span>
                  <span>XLAT: {formatBytesCompact(selected.item.translatedBytes)}</span>
                  <span>Verified: {selected.item.verifiedInsns.toLocaleString()} insns</span>
                  <span>Runs: {selected.item.runCount.toLocaleString()}</span>
                  <span>Avg: {selected.item.runCount > 0 ? formatDurationNs(selected.item.runTimeNs / selected.item.runCount) : '0 ns'}</span>
                  <span>Rec. Misses: {selected.item.recursionMisses}</span>
                </div>
              )}
              {selected.kind === 'map' && (
                <div className="flex flex-wrap items-center gap-4 font-mono tabular-nums text-slate-200">
                  <span className="text-purple-300 font-bold">
                    Map #{selected.item.id} ({selected.item.name})
                  </span>
                  <span>Type: {selected.item.type}</span>
                  <span>Key/Val: {selected.item.keySize}B / {selected.item.valueSize}B</span>
                  <span>Max Entries: {selected.item.maxEntries.toLocaleString()}</span>
                  <span>Memlock: {formatBytesCompact(selected.item.memlockBytes)}</span>
                  <span>BTF: {selected.item.hasBtf ? 'Yes' : 'No'}</span>
                  <span>Frozen: {selected.item.frozen ? 'Yes' : 'No'}</span>
                </div>
              )}
            </div>
          )}

          {/* Verifier Complexity vs JIT / Execution Latency Scatter Plot */}
          {graph.scatterPoints.length > 0 && (
            <div className="pt-4 border-t border-slate-800 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h4 className="text-sm font-bold text-white">
                    Verifier Complexity vs JIT / Execution Cost ({graph.scatterPoints.length} programs)
                  </h4>
                  <p className="text-xs text-slate-400">
                    Plots {hasVerifiedInsns ? 'verifier instructions checked' : 'translated bytecode bytes'} against{' '}
                    {effectiveScatterY === 'avgNsPerRun' ? 'average ns per invocation' : 'JIT machine-code KiB'}. Click any point to inspect in graph.
                  </p>
                </div>

                <div className="flex items-center gap-1 rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs">
                  <button
                    type="button"
                    onClick={() => setScatterYMetric('jitedKiB')}
                    className={`px-2.5 py-1 rounded font-semibold transition ${
                      effectiveScatterY === 'jitedKiB' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    JIT KiB
                  </button>
                  <button
                    type="button"
                    onClick={() => setScatterYMetric('avgNsPerRun')}
                    disabled={!hasRuntimeStats}
                    title={!hasRuntimeStats ? 'Enable bpf_stats_enabled to plot avg ns/run' : undefined}
                    className={`px-2.5 py-1 rounded font-semibold transition disabled:opacity-40 ${
                      effectiveScatterY === 'avgNsPerRun' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Avg ns/run
                  </button>
                </div>
              </div>

              <div className="h-[220px] rounded-lg bg-slate-950 border border-slate-800 p-2">
                <ResponsiveContainer width="100%" height="100%">
                  <ScatterChart margin={{ top: 10, right: 16, bottom: 10, left: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis
                      type="number"
                      dataKey={hasVerifiedInsns ? 'verifiedInsns' : 'translatedBytes'}
                      name={hasVerifiedInsns ? 'Verified Insns' : 'Translated Bytes'}
                      tick={{ fill: '#94a3b8', fontSize: 11 }}
                    />
                    <YAxis
                      type="number"
                      dataKey={effectiveScatterY}
                      name={effectiveScatterY === 'avgNsPerRun' ? 'Avg ns/run' : 'JIT KiB'}
                      tick={{ fill: '#94a3b8', fontSize: 11 }}
                    />
                    <ZAxis type="number" dataKey="mapCount" range={[48, 220]} name="Maps" />
                    <Tooltip
                      cursor={{ strokeDasharray: '3 3', stroke: '#475569' }}
                      content={({ active, payload }) => {
                        if (!active || !payload || !payload.length) return null;
                        const pt = payload[0]?.payload;
                        if (!pt) return null;
                        return (
                          <div className="rounded-lg bg-slate-900 border border-slate-700 px-3 py-2 text-xs text-slate-100 space-y-0.5 tabular-nums">
                            <div className="font-mono font-bold text-emerald-300">
                              {pt.name} (#{pt.id})
                            </div>
                            <div className="text-slate-300">Type: {pt.type}</div>
                            <div>
                              {hasVerifiedInsns ? `Verified: ${pt.verifiedInsns.toLocaleString()} insns` : `Translated: ${formatBytesCompact(pt.translatedBytes)}`}
                            </div>
                            <div>JIT Size: {pt.jitedKiB} KiB · Maps: {pt.mapCount}</div>
                            {pt.runCount > 0 && <div>Avg Runtime: {pt.avgNsPerRun} ns/run</div>}
                          </div>
                        );
                      }}
                    />
                    <Scatter
                      data={graph.scatterPoints}
                      onClick={(point: any) => {
                        const targetId = point?.id ?? point?.payload?.id;
                        const found = inventory?.programs.find((p) => p.id === targetId);
                        if (found) setSelected({ kind: 'program', item: found });
                      }}
                      className="cursor-pointer"
                    >
                      {graph.scatterPoints.map((pt) => (
                        <Cell key={pt.id} fill={colorForProgType(pt.type)} />
                      ))}
                    </Scatter>
                  </ScatterChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
