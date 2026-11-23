'use client';

import React, { useMemo, useState } from 'react';
import Link from 'next/link';
import { Cpu, Database, Filter, RotateCcw, Search, Server } from 'lucide-react';
import type { K3sClusterPulse } from './types';
import { formatBytes, formatCpuMillis } from './types';
import {
  buildNodeBinPackingData,
  type BinPackedNodeBucket,
  type BinPackedPodTile,
} from '@/lib/k3s-visuals';

interface K3sNodeBinPackingMapProps {
  pulse: K3sClusterPulse;
  namespace?: string;
  search?: string;
  issuesOnly?: boolean;
  onInspectPod?: (opts: {
    resource: string;
    name: string;
    namespace?: string;
    tab?: 'overview' | 'logs' | 'describe';
  }) => void;
  onInspectNode?: (nodeName: string) => void;
}

function tileToneClasses(tile: BinPackedPodTile, isFocused: boolean): string {
  const ring = isFocused ? 'ring-2 ring-white scale-105' : '';
  if (tile.statusTone === 'err' || tile.isUnhealthy && !tile.status.toLowerCase().includes('pending')) {
    return `bg-rose-500/25 border-rose-400/70 text-rose-200 hover:bg-rose-500/40 ${ring}`;
  }
  if (tile.statusTone === 'warn' || tile.status.toLowerCase().includes('pending')) {
    return `bg-amber-500/25 border-amber-400/70 text-amber-200 hover:bg-amber-500/40 ${ring}`;
  }
  if (tile.status === 'Succeeded' || tile.status === 'Completed' || tile.statusTone === 'info') {
    return `bg-sky-500/25 border-sky-400/60 text-sky-200 hover:bg-sky-500/40 ${ring}`;
  }
  return `bg-emerald-500/25 border-emerald-400/60 text-emerald-200 hover:bg-emerald-500/40 ${ring}`;
}

export function K3sNodeBinPackingMap({
  pulse,
  namespace: controlledNs,
  search: controlledSearch,
  issuesOnly: controlledIssuesOnly,
  onInspectPod,
  onInspectNode,
}: K3sNodeBinPackingMapProps) {
  const [localNs, setLocalNs] = useState('_all');
  const [localSearch, setLocalSearch] = useState('');
  const [localIssuesOnly, setLocalIssuesOnly] = useState(false);
  const [focusedPodByNode, setFocusedPodByNode] = useState<Record<string, BinPackedPodTile | null>>({});

  const effectiveNs = controlledNs !== undefined ? controlledNs : localNs;
  const effectiveSearch = controlledSearch !== undefined ? controlledSearch : localSearch;
  const effectiveIssues = controlledIssuesOnly !== undefined ? controlledIssuesOnly : localIssuesOnly;

  const showToolbar =
    controlledNs === undefined && controlledSearch === undefined && controlledIssuesOnly === undefined;

  const namespaces = useMemo(
    () => (pulse.namespaceStats || []).map((n) => n.name).sort(),
    [pulse.namespaceStats]
  );

  const buckets = useMemo<BinPackedNodeBucket[]>(
    () =>
      buildNodeBinPackingData(pulse, {
        namespace: effectiveNs,
        search: effectiveSearch,
        issuesOnly: effectiveIssues,
      }),
    [pulse, effectiveNs, effectiveSearch, effectiveIssues]
  );

  return (
    <div className="space-y-4">
      {showToolbar && (
        <div className="p-3.5 rounded-2xl bg-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2.5">
            <select
              value={localNs}
              onChange={(e) => setLocalNs(e.target.value)}
              aria-label="Filter node bin-packing map by namespace"
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono"
            >
              <option value="_all">All Namespaces ({namespaces.length})</option>
              {namespaces.map((ns) => (
                <option key={ns} value={ns}>
                  {ns}
                </option>
              ))}
            </select>

            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={localSearch}
                onChange={(e) => setLocalSearch(e.target.value)}
                placeholder="Filter pods on nodes..."
                className="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-400 font-mono w-48"
              />
            </div>

            <button
              type="button"
              onClick={() => setLocalIssuesOnly((v) => !v)}
              className={`px-2.5 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-1.5 transition ${
                localIssuesOnly
                  ? 'bg-amber-500/20 border-amber-500/40 text-amber-300'
                  : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
              }`}
            >
              <Filter className="w-3.5 h-3.5" />
              Issues Only
            </button>
          </div>

          <div className="flex items-center gap-3 text-[11px] font-mono text-slate-300">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500/40 border border-emerald-400" /> Running
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-amber-500/40 border border-amber-400" /> Pending
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-rose-500/40 border border-rose-400" /> Failed
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-sky-500/40 border border-sky-400" /> Completed
            </span>
          </div>
        </div>
      )}

      {buckets.length === 0 ? (
        <div className="p-10 rounded-2xl bg-slate-900 border border-slate-800 text-center text-xs text-slate-300 space-y-2">
          <Server className="w-6 h-6 text-slate-500 mx-auto" />
          <p>No nodes or pods match the active filter criteria.</p>
          {effectiveIssues && showToolbar && (
            <button
              type="button"
              onClick={() => setLocalIssuesOnly(false)}
              className="inline-flex items-center gap-1 px-3 py-1 rounded-lg bg-slate-950 border border-slate-700 text-emerald-300 font-mono"
            >
              <RotateCcw className="w-3 h-3" /> Show All Nodes
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          {buckets.map((bucket) => {
            const focusedPod = focusedPodByNode[bucket.nodeName] || null;
            const nodeBorder =
              bucket.status !== 'Ready'
                ? 'border-rose-500/40'
                : bucket.unschedulable
                  ? 'border-amber-500/40'
                  : 'border-slate-800';

            return (
              <div
                key={bucket.nodeName}
                className={`p-4 rounded-2xl bg-slate-900 border ${nodeBorder} space-y-3 flex flex-col justify-between`}
              >
                <div className="space-y-3">
                  {/* Node Header */}
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2 min-w-0">
                      <Cpu className="w-4 h-4 text-emerald-400 shrink-0" />
                      {onInspectNode ? (
                        <button
                          type="button"
                          onClick={() => onInspectNode(bucket.nodeName)}
                          className="font-mono text-sm font-bold text-white hover:text-emerald-300 transition truncate"
                        >
                          {bucket.nodeName}
                        </button>
                      ) : (
                        <span className="font-mono text-sm font-bold text-white truncate">
                          {bucket.nodeName}
                        </span>
                      )}
                      <span
                        className={`px-2 py-0.5 rounded border text-[10px] font-mono ${
                          bucket.status === 'Ready' && !bucket.unschedulable
                            ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                            : bucket.unschedulable
                              ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                              : 'bg-rose-500/15 border-rose-500/30 text-rose-300'
                        }`}
                      >
                        {bucket.status}
                        {bucket.unschedulable ? ' • Cordoned' : ''}
                      </span>
                      {bucket.roles.slice(0, 4).map((r) => (
                        <span
                          key={r}
                          className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-300"
                        >
                          {r}
                        </span>
                      ))}
                    </div>

                    <span className="text-[11px] font-mono tabular-nums text-slate-400">
                      {bucket.internalIp}
                    </span>
                  </div>

                  {/* Conditions + Taints Strip */}
                  {(bucket.conditions.length > 0 || bucket.taints.length > 0) && (
                    <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
                      {bucket.conditions.map((c) => (
                        <span
                          key={c.key}
                          title={`${c.key}: ${c.reason}${c.message ? ` — ${c.message}` : ''}`}
                          className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border ${
                            c.ok
                              ? 'bg-slate-950 border-slate-800 text-slate-300'
                              : 'bg-rose-500/15 border-rose-500/40 text-rose-300'
                          }`}
                        >
                          <span className={`w-1.5 h-1.5 rounded-full ${c.ok ? 'bg-emerald-400' : 'bg-rose-400'}`} />
                          {c.shortLabel}
                        </span>
                      ))}
                      {bucket.taints.map((t, i) => (
                        <span
                          key={`${t.key}-${i}`}
                          title={`${t.key}${t.value ? `=${t.value}` : ''}:${t.effect}`}
                          className="px-1.5 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 truncate max-w-[180px]"
                        >
                          taint:{t.key.split('/').pop()}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* CPU / MEM / Pod Allocation Bars */}
                  {!bucket.isUnscheduledBucket && (
                    <div className="grid grid-cols-3 gap-3 text-[11px] font-mono tabular-nums">
                      <div>
                        <div className="flex justify-between text-slate-300">
                          <span>CPU</span>
                          <span>
                            {bucket.cpuUsedCores}/{bucket.cpuAllocatableCores}c
                          </span>
                        </div>
                        <div className="h-1.5 bg-slate-950 border border-slate-800 rounded-full mt-1 overflow-hidden relative">
                          <div
                            className="h-full bg-sky-500/40 absolute top-0 left-0"
                            style={{ width: `${bucket.cpuReqPct}%` }}
                          />
                          <div
                            className="h-full bg-emerald-500 relative"
                            style={{ width: `${bucket.cpuUsePct}%` }}
                          />
                        </div>
                      </div>

                      <div>
                        <div className="flex justify-between text-slate-300">
                          <span>MEM</span>
                          <span>
                            {bucket.memUsedGiB}/{bucket.memAllocatableGiB}G
                          </span>
                        </div>
                        <div className="h-1.5 bg-slate-950 border border-slate-800 rounded-full mt-1 overflow-hidden relative">
                          <div
                            className="h-full bg-indigo-400/45 absolute top-0 left-0"
                            style={{ width: `${bucket.memReqPct}%` }}
                          />
                          <div
                            className="h-full bg-sky-500 relative"
                            style={{ width: `${bucket.memUsePct}%` }}
                          />
                        </div>
                      </div>

                      <div>
                        <div className="flex justify-between text-slate-300">
                          <span>Pods</span>
                          <span>
                            {bucket.pods.length} ({bucket.podCount}/{bucket.podCapacity || '—'})
                          </span>
                        </div>
                        <div className="h-1.5 bg-slate-950 border border-slate-800 rounded-full mt-1 overflow-hidden">
                          <div
                            className="h-full bg-amber-500"
                            style={{ width: `${bucket.podPct}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Bin-Packed Pod Heatmap Grid */}
                  <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800/90 min-h-[76px]">
                    {bucket.pods.length === 0 ? (
                      <div className="h-[52px] flex items-center justify-center text-[11px] font-mono text-slate-400">
                        {bucket.status !== 'Ready'
                          ? 'Node offline — 0 scheduled pods'
                          : 'No pods match active filters on this node'}
                      </div>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {bucket.pods.map((tile) => {
                          const isFocused = focusedPod?.id === tile.id;
                          const shortName =
                            tile.name.length > 18 ? `${tile.name.slice(0, 16)}..` : tile.name;

                          const tileInner = (
                            <>
                              <span className="truncate font-mono text-[10px] font-medium">
                                {shortName}
                              </span>
                              {tile.pvcNames.length > 0 && (
                                <Database
                                  className="w-2.5 h-2.5 text-amber-300 shrink-0"
                                  aria-label="Mounts PVC"
                                />
                              )}
                              {tile.restarts > 0 && (
                                <span
                                  className="px-1 rounded bg-rose-600/80 text-white text-[9px] font-mono tabular-nums shrink-0"
                                  title={`${tile.restarts} restarts`}
                                >
                                  ↻{tile.restarts}
                                </span>
                              )}
                            </>
                          );

                          if (onInspectPod) {
                            return (
                              <button
                                key={tile.id}
                                type="button"
                                onMouseEnter={() =>
                                  setFocusedPodByNode((prev) => ({ ...prev, [bucket.nodeName]: tile }))
                                }
                                onFocus={() =>
                                  setFocusedPodByNode((prev) => ({ ...prev, [bucket.nodeName]: tile }))
                                }
                                onClick={() =>
                                  onInspectPod({
                                    resource: 'pods',
                                    name: tile.name,
                                    namespace: tile.namespace,
                                    tab: 'overview',
                                  })
                                }
                                title={`${tile.namespace}/${tile.name} (${tile.status})`}
                                className={`px-2 py-1 rounded-md border flex items-center gap-1 max-w-[175px] transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white ${tileToneClasses(
                                  tile,
                                  isFocused
                                )}`}
                              >
                                {tileInner}
                              </button>
                            );
                          }

                          return (
                            <Link
                              key={tile.id}
                              href={`/k3s/explorer?resource=pods&namespace=${encodeURIComponent(
                                tile.namespace
                              )}&name=${encodeURIComponent(tile.name)}`}
                              onMouseEnter={() =>
                                setFocusedPodByNode((prev) => ({ ...prev, [bucket.nodeName]: tile }))
                              }
                              title={`${tile.namespace}/${tile.name} (${tile.status})`}
                              className={`px-2 py-1 rounded-md border flex items-center gap-1 max-w-[175px] transition ${tileToneClasses(
                                tile,
                                isFocused
                              )}`}
                            >
                              {tileInner}
                            </Link>
                          );
                        })}
                      </div>
                    )}
                  </div>
                </div>

                {/* Focused Pod Telemetry Footer */}
                <div className="pt-1 border-t border-slate-800/70 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono min-h-[24px]">
                  {focusedPod ? (
                    <>
                      <div className="flex items-center gap-2 min-w-0 truncate">
                        <span className="text-emerald-300 font-semibold truncate">
                          {focusedPod.namespace}/{focusedPod.name}
                        </span>
                        <span className="text-slate-400 shrink-0">• {focusedPod.status}</span>
                        {focusedPod.restarts > 0 && (
                          <span className="text-rose-300 shrink-0">↻ {focusedPod.restarts}</span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 text-slate-300 shrink-0 tabular-nums">
                        {focusedPod.cpuMillis !== null && (
                          <span>CPU: {formatCpuMillis(focusedPod.cpuMillis)}</span>
                        )}
                        {focusedPod.memBytes !== null && (
                          <span>MEM: {formatBytes(focusedPod.memBytes)}</span>
                        )}
                        {focusedPod.pvcNames.length > 0 && (
                          <span className="text-amber-300">
                            PVC: {focusedPod.pvcNames.join(', ')}
                          </span>
                        )}
                      </div>
                    </>
                  ) : (
                    <span className="text-slate-400">
                      {bucket.pods.length} {bucket.pods.length === 1 ? 'pod' : 'pods'} shown • Hover any pod tile for telemetry, click to inspect
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
