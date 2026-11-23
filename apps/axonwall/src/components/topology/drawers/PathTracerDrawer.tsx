'use client';

import React, { useMemo } from 'react';
import { ArrowRight, Route, X } from 'lucide-react';
import { traceFabricPath, type TracedPathResult } from '@axonwall/lib/compile/topology';
import type { DesiredState, TopologyCableEdge, TopologyCanvasNode } from '@axonwall/lib/schemas';
import type { TopologyFabricSnapshot } from '@/server/agent';
import { buildProbeSnapshotForEval } from '../hydrateFabric';
import { HEALTH_TONE_CLASSES, type FabricHealthEvaluation } from '../types';

interface PathTracerDrawerProps {
  open: boolean;
  onClose: () => void;
  nodes: TopologyCanvasNode[];
  cables: TopologyCableEdge[];
  health: FabricHealthEvaluation;
  draftState: DesiredState | null;
  fabric: TopologyFabricSnapshot | null;
  sourceNodeId: string;
  targetNodeId: string;
  onChangeEndpoints: (sourceId: string, targetId: string) => void;
  onHighlightPath: (nodeIds: string[], cableIds: string[]) => void;
}

export function PathTracerDrawer({
  open,
  onClose,
  nodes,
  cables,
  health,
  draftState,
  fabric,
  sourceNodeId,
  targetNodeId,
  onChangeEndpoints,
  onHighlightPath,
}: PathTracerDrawerProps) {
  const probeEval = useMemo(() => buildProbeSnapshotForEval(fabric, draftState), [fabric, draftState]);

  const result: TracedPathResult = useMemo(
    () => traceFabricPath(nodes, cables, health, draftState, sourceNodeId, targetNodeId, probeEval),
    [nodes, cables, health, draftState, sourceNodeId, targetNodeId, probeEval],
  );

  const applyPreset = (fromKind: TopologyCanvasNode['kind'], toKind: TopologyCanvasNode['kind']) => {
    const src = nodes.find((n) => n.kind === fromKind) ?? nodes[0];
    const dst = nodes.find((n) => n.kind === toKind) ?? nodes[nodes.length - 1];
    if (!src || !dst) return;
    onChangeEndpoints(src.id, dst.id);
    const traced = traceFabricPath(nodes, cables, health, draftState, src.id, dst.id, probeEval);
    onHighlightPath(
      traced.hops.map((h) => h.nodeId),
      traced.hops.map((h) => h.cableId).filter((c): c is string => Boolean(c)),
    );
  };

  if (!open) return null;

  const overallStyle = HEALTH_TONE_CLASSES[result.overallHealth];

  return (
    <aside className="w-[400px] shrink-0 h-full bg-slate-950 border-l border-slate-800 flex flex-col overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-800 bg-slate-900 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Route className="w-4 h-4 text-sky-400" />
          <div>
            <h3 className="text-sm font-semibold text-white">Interactive Path Tracer</h3>
            <p className="text-[11px] text-slate-400">Trace hops across NAT, firewall &amp; K3s NetworkPolicy</p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => {
            onHighlightPath([], []);
            onClose();
          }}
          className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-4 border-b border-slate-800 space-y-3 text-xs">
        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={() => applyPreset('wan', 'k3s-service')}
            className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-sky-300 text-[11px]"
          >
            WAN → K3s Service
          </button>
          <button
            type="button"
            onClick={() => applyPreset('edge-ngfw', 'vault')}
            className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-sky-300 text-[11px]"
          >
            Edge → Vault
          </button>
          <button
            type="button"
            onClick={() => applyPreset('edge-ngfw', 'nas')}
            className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-sky-300 text-[11px]"
          >
            Edge → NAS
          </button>
        </div>

        <div className="space-y-2">
          <label className="block">
            <span className="text-slate-400 block mb-1">Source Endpoint</span>
            <select
              value={sourceNodeId}
              onChange={(e) => {
                const next = e.target.value;
                onChangeEndpoints(next, targetNodeId);
                const traced = traceFabricPath(nodes, cables, health, draftState, next, targetNodeId, probeEval);
                onHighlightPath(
                  traced.hops.map((h) => h.nodeId),
                  traced.hops.map((h) => h.cableId).filter((c): c is string => Boolean(c)),
                );
              }}
              className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white"
            >
              <option value="">Select source...</option>
              {nodes.map((n) => (
                <option key={n.id} value={n.id}>
                  {n.label} ({n.kind})
                </option>
              ))}
            </select>
          </label>

          <label className="block">
            <span className="text-slate-400 block mb-1">Destination Endpoint</span>
            <select
              value={targetNodeId}
              onChange={(e) => {
                const next = e.target.value;
                onChangeEndpoints(sourceNodeId, next);
                const traced = traceFabricPath(nodes, cables, health, draftState, sourceNodeId, next, probeEval);
                onHighlightPath(
                  traced.hops.map((h) => h.nodeId),
                  traced.hops.map((h) => h.cableId).filter((c): c is string => Boolean(c)),
                );
              }}
              className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white"
            >
              <option value="">Select target...</option>
              {nodes.map((n) => (
                <option key={n.id} value={n.id}>
                  {n.label} ({n.kind})
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className={`px-3 py-2 rounded-lg border ${overallStyle.border} ${overallStyle.badgeBg} flex items-center justify-between`}>
          <span className={`font-semibold uppercase ${overallStyle.text}`}>
            {result.hops.length === 0
              ? 'No path in canvas graph'
              : result.reachable
                ? `Path Healthy (${result.overallHealth})`
                : 'Path Faulty / Blocked'}
          </span>
          <span className="font-mono text-slate-300">{result.hops.length} hops</span>
        </div>
      </div>

      <div className="p-3 space-y-2.5 overflow-y-auto flex-1 text-xs">
        {result.hops.map((hop) => {
          const hopStyle = HEALTH_TONE_CLASSES[hop.health];
          return (
            <div key={`${hop.step}-${hop.nodeId}`} className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-white flex items-center gap-1.5 truncate">
                  <span className="font-mono text-slate-400">#{hop.step}</span>
                  <span>{hop.nodeLabel}</span>
                </span>
                <span className={`px-1.5 py-0.5 rounded font-mono text-[10px] uppercase ${hopStyle.badgeBg} ${hopStyle.text}`}>
                  {hop.health}
                </span>
              </div>

              {hop.cableLabel && (
                <div className="text-[11px] font-mono text-sky-300 flex items-center gap-1">
                  <ArrowRight className="w-3 h-3" />
                  via {hop.cableLabel}
                </div>
              )}

              <div className="text-slate-300">{hop.reason}</div>

              {hop.matchingNatRules.length > 0 && (
                <div className="text-[11px] font-mono text-amber-300/90">
                  NAT: {hop.matchingNatRules.join(' | ')}
                </div>
              )}
              {hop.matchingFirewallRules.length > 0 && (
                <div className="text-[11px] font-mono text-emerald-300/90">
                  FW: {hop.matchingFirewallRules.slice(0, 3).join(' | ')}
                </div>
              )}
              {hop.matchingNetworkPolicies.length > 0 && (
                <div className="text-[11px] font-mono text-cyan-300/90">
                  NetPol: {hop.matchingNetworkPolicies.join(' | ')}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </aside>
  );
}
