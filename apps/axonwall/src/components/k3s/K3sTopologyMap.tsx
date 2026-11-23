'use client';

import React, { useMemo, useRef, useState } from 'react';
import {
  Activity,
  Cpu,
  EyeOff,
  Filter,
  Maximize2,
  Network,
  RotateCcw,
  Search,
  Terminal,
  X,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import type {
  K3sClusterPulse,
  K3sNodePulse,
  K3sPodHotspot,
  K3sTopologyEdge,
  K3sTopologyGraph,
  K3sTopologyNode,
} from './types';
import { K3sNodeBinPackingMap } from './K3sNodeBinPackingMap';
import { orderTopologyColumnsBarycenter } from '@/lib/k3s-visuals';

interface K3sTopologyMapProps {
  graph: K3sTopologyGraph;
  namespaces: string[];
  initialNamespace?: string;
  pulse?: K3sClusterPulse;
  nodes?: K3sNodePulse[];
  topResourcePods?: K3sPodHotspot[];
  topRestartingPods?: K3sPodHotspot[];
  onInspectNode: (node: K3sTopologyNode) => void;
  onInspectResource?: (opts: {
    resource: string;
    name: string;
    namespace?: string;
    tab?: 'overview' | 'describe' | 'yaml' | 'logs' | 'exec' | 'events';
  }) => void;
}

type LayerKey = 'Ingress' | 'Service' | 'Workload' | 'Pod' | 'Node' | 'PVC';

const LAYER_LABELS: { key: LayerKey; label: string; color: string }[] = [
  { key: 'Ingress', label: 'Ingresses', color: '#06b6d4' },
  { key: 'Service', label: 'Services', color: '#38bdf8' },
  { key: 'Workload', label: 'Workloads', color: '#10b981' },
  { key: 'Pod', label: 'Pods', color: '#34d399' },
  { key: 'Node', label: 'Nodes', color: '#818cf8' },
  { key: 'PVC', label: 'PVCs', color: '#f59e0b' },
];

function nodeLayerKey(kind: string): LayerKey {
  if (kind === 'Deployment' || kind === 'StatefulSet' || kind === 'DaemonSet' || kind === 'Job') {
    return 'Workload';
  }
  if (kind === 'Ingress' || kind === 'Service' || kind === 'Pod' || kind === 'Node' || kind === 'PVC') {
    return kind;
  }
  return 'Workload';
}

function toneStrokeColor(tone: string, kind: string): string {
  switch (tone) {
    case 'err':
      return '#f43f5e';
    case 'warn':
      return '#f59e0b';
    case 'info':
      return kind === 'Ingress' ? '#06b6d4' : '#38bdf8';
    case 'ok':
      return '#10b981';
    default:
      return '#64748b';
  }
}

function edgeColor(rel: string): string {
  switch (rel) {
    case 'ingress-to-service':
      return '#06b6d4';
    case 'service-to-pod':
      return '#38bdf8';
    case 'workload-to-pod':
      return '#10b981';
    case 'pod-to-pvc':
      return '#f59e0b';
    case 'pod-to-node':
      return '#818cf8';
    default:
      return '#64748b';
  }
}

function markerIdForRelation(rel: string): string {
  switch (rel) {
    case 'ingress-to-service':
      return 'url(#k3s-arrow-cyan)';
    case 'service-to-pod':
      return 'url(#k3s-arrow-sky)';
    case 'workload-to-pod':
      return 'url(#k3s-arrow-emerald)';
    case 'pod-to-pvc':
      return 'url(#k3s-arrow-amber)';
    case 'pod-to-node':
      return 'url(#k3s-arrow-indigo)';
    default:
      return 'url(#k3s-arrow-slate)';
  }
}

interface PositionedNode {
  node: K3sTopologyNode;
  x: number;
  y: number;
  w: number;
  h: number;
}

const LOG_CAPABLE_KINDS = new Set(['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job']);

export function K3sTopologyMap({
  graph,
  namespaces,
  initialNamespace = '_all',
  pulse,
  nodes,
  topResourcePods,
  topRestartingPods,
  onInspectNode,
  onInspectResource,
}: K3sTopologyMapProps) {
  const [layoutMode, setLayoutMode] = useState<'flow' | 'binpack'>('flow');
  const [selectedNs, setSelectedNs] = useState<string>(initialNamespace || '_all');
  const [search, setSearch] = useState('');
  const [issuesOnly, setIssuesOnly] = useState(false);
  const [hideIsolated, setHideIsolated] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState<{ startX: number; startY: number; origX: number; origY: number } | null>(
    null
  );
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [pinnedId, setPinnedId] = useState<string | null>(null);
  const [visibleLayers, setVisibleLayers] = useState<Record<LayerKey, boolean>>({
    Ingress: true,
    Service: true,
    Workload: true,
    Pod: true,
    Node: true,
    PVC: true,
  });

  const canvasContainerRef = useRef<HTMLDivElement>(null);

  const toggleLayer = (k: LayerKey) => {
    setVisibleLayers((prev) => ({ ...prev, [k]: !prev[k] }));
  };

  // Filter nodes & edges by namespace and enabled layers, then run Barycenter column ordering
  const ordered = useMemo(() => {
    const rawNodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
    const rawEdges = Array.isArray(graph?.edges) ? graph.edges : [];

    const allowedNodeIds = new Set<string>();
    const nsNodes = rawNodes.filter((n) => {
      const layer = nodeLayerKey(n.kind);
      if (!visibleLayers[layer]) return false;
      if (selectedNs === '_all') return true;
      if (n.kind === 'Node') return true;
      return n.namespace === selectedNs;
    });

    for (const n of nsNodes) allowedNodeIds.add(n.id);
    const nsEdges = rawEdges.filter((e) => allowedNodeIds.has(e.source) && allowedNodeIds.has(e.target));

    const activeNodeTargetIds = new Set(nsEdges.map((e) => e.target));
    const prunedNodes = nsNodes.filter((n) => {
      if (n.kind === 'Node' && selectedNs !== '_all' && visibleLayers.Pod) {
        return activeNodeTargetIds.has(n.id);
      }
      return true;
    });

    const prunedIds = new Set(prunedNodes.map((n) => n.id));
    const prunedEdges = nsEdges.filter((e) => prunedIds.has(e.source) && prunedIds.has(e.target));

    return orderTopologyColumnsBarycenter(prunedNodes, prunedEdges, {
      hideIsolated,
      issuesOnly,
    });
  }, [graph, selectedNs, visibleLayers, hideIsolated, issuesOnly]);

  // Deterministic 5-column layered SVG layout using barycenter-ordered columns
  const layout = useMemo(() => {
    const boxW = 172;
    const boxH = 56;
    const colX = [16, 234, 452, 670, 888];
    const rowGap = 72;
    const topMargin = 62;

    const placeCol = (items: K3sTopologyNode[], x: number): PositionedNode[] =>
      items.map((node, i) => ({
        node,
        x,
        y: topMargin + i * rowGap,
        w: boxW,
        h: boxH,
      }));

    const positioned = [
      ...placeCol(ordered.ingresses, colX[0]),
      ...placeCol(ordered.services, colX[1]),
      ...placeCol(ordered.workloads, colX[2]),
      ...placeCol(ordered.pods, colX[3]),
      ...placeCol(ordered.infra, colX[4]),
    ];

    const posMap = new Map<string, PositionedNode>();
    let maxY = 420;
    for (const p of positioned) {
      posMap.set(p.node.id, p);
      if (p.y + p.h + 40 > maxY) {
        maxY = p.y + p.h + 40;
      }
    }

    return {
      positioned,
      posMap,
      width: 1076,
      height: maxY,
      colHeaders: [
        { title: `Ingresses (${ordered.ingresses.length})`, x: colX[0] },
        { title: `Services (${ordered.services.length})`, x: colX[1] },
        { title: `Workloads (${ordered.workloads.length})`, x: colX[2] },
        { title: `Pods (${ordered.pods.length})`, x: colX[3] },
        { title: `Nodes & PVCs (${ordered.infra.length})`, x: colX[4] },
      ],
    };
  }, [ordered]);

  const activeFocusId = pinnedId || hoveredId;
  const pinnedNodeObj = useMemo(
    () => (pinnedId ? ordered.visibleNodes.find((n) => n.id === pinnedId) || null : null),
    [pinnedId, ordered.visibleNodes]
  );

  // Full upstream/downstream adjacency for spotlight & hop stats
  const spotlightInfo = useMemo(() => {
    if (!activeFocusId) return null;
    const connected = new Set<string>([activeFocusId]);
    let upstreamCount = 0;
    let downstreamCount = 0;

    // Traverse downstream
    const downQueue = [activeFocusId];
    const downSeen = new Set<string>([activeFocusId]);
    while (downQueue.length > 0) {
      const cur = downQueue.shift()!;
      for (const e of ordered.visibleEdges) {
        if (e.source === cur && !downSeen.has(e.target)) {
          downSeen.add(e.target);
          connected.add(e.target);
          downstreamCount += 1;
          downQueue.push(e.target);
        }
      }
    }

    // Traverse upstream
    const upQueue = [activeFocusId];
    const upSeen = new Set<string>([activeFocusId]);
    while (upQueue.length > 0) {
      const cur = upQueue.shift()!;
      for (const e of ordered.visibleEdges) {
        if (e.target === cur && !upSeen.has(e.source)) {
          upSeen.add(e.source);
          connected.add(e.source);
          upstreamCount += 1;
          upQueue.push(e.source);
        }
      }
    }

    return { connected, upstreamCount, downstreamCount };
  }, [activeFocusId, ordered.visibleEdges]);

  // Construct pulse object for bin-packing view (prefers full pulse prop when supplied)
  const effectivePulseForBinPack = useMemo<K3sClusterPulse>(() => {
    if (pulse) return pulse;
    return {
      available: true,
      timestamp: new Date().toISOString(),
      metricsAvailable: false,
      cniPlugin: 'flannel',
      k3sVersion: '',
      counts: {} as any,
      podPhaseDistribution: [],
      namespaceStats: namespaces.map((n) => ({
        name: n,
        status: 'Active',
        podsRunning: 0,
        podsUnhealthy: 0,
        podsTotal: 0,
        services: 0,
        ingresses: 0,
        pvcs: 0,
      })),
      nodes: nodes || [],
      storageByClass: [],
      topRestartingPods: topRestartingPods || [],
      topResourcePods: topResourcePods || [],
      recentEvents: [],
      workloadsSummary: [],
      servicesSummary: [],
      ingressesSummary: [],
      pvcsSummary: [],
      topology: graph,
    };
  }, [pulse, namespaces, nodes, topRestartingPods, topResourcePods, graph]);

  const handleFitView = () => {
    const el = canvasContainerRef.current;
    if (!el) return;
    const availW = Math.max(320, el.clientWidth - 24);
    const availH = Math.max(240, el.clientHeight - 24);
    const scaleW = availW / layout.width;
    const scaleH = availH / layout.height;
    const nextZoom = Math.max(0.4, Math.min(1.25, Number(Math.min(scaleW, scaleH).toFixed(2))));
    setZoom(nextZoom);
    setPan({ x: 0, y: 0 });
  };

  const qLower = search.trim().toLowerCase();

  return (
    <div className="space-y-4">
      {/* Topology Toolbar */}
      <div className="p-3.5 rounded-2xl bg-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Layout Mode Switcher */}
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-xs font-mono">
            <button
              type="button"
              onClick={() => setLayoutMode('flow')}
              className={`px-2.5 py-1 rounded-md flex items-center gap-1.5 transition ${
                layoutMode === 'flow' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              <Network className="w-3.5 h-3.5" /> Traffic Flow
            </button>
            <button
              type="button"
              onClick={() => setLayoutMode('binpack')}
              className={`px-2.5 py-1 rounded-md flex items-center gap-1.5 transition ${
                layoutMode === 'binpack' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" /> Node Bin-Packing
            </button>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-300 font-medium">Ns:</span>
            <select
              value={selectedNs}
              onChange={(e) => setSelectedNs(e.target.value)}
              aria-label="Filter topology by namespace"
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono"
            >
              <option value="_all">All ({namespaces.length})</option>
              {namespaces.map((ns) => (
                <option key={ns} value={ns}>
                  {ns}
                </option>
              ))}
            </select>
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Highlight object..."
              className="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-400 font-mono w-40"
            />
          </div>

          <button
            type="button"
            onClick={() => setIssuesOnly((v) => !v)}
            className={`px-2.5 py-1.5 rounded-lg text-[11px] font-mono border transition flex items-center gap-1.5 ${
              issuesOnly
                ? 'bg-amber-500/20 border-amber-500/40 text-amber-300'
                : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
            }`}
          >
            <Filter className="w-3 h-3" /> Issues Only
          </button>

          {layoutMode === 'flow' && (
            <button
              type="button"
              onClick={() => setHideIsolated((v) => !v)}
              className={`px-2.5 py-1.5 rounded-lg text-[11px] font-mono border transition flex items-center gap-1.5 ${
                hideIsolated
                  ? 'bg-sky-500/20 border-sky-500/40 text-sky-300'
                  : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
              }`}
            >
              <EyeOff className="w-3 h-3" /> Hide Isolated
            </button>
          )}
        </div>

        {layoutMode === 'flow' && (
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => setZoom((z) => Math.max(0.4, Number((z - 0.15).toFixed(2))))}
              className="p-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 hover:text-white"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <span className="text-xs font-mono tabular-nums text-slate-300 w-11 text-center">
              {Math.round(zoom * 100)}%
            </span>
            <button
              type="button"
              onClick={() => setZoom((z) => Math.min(2, Number((z + 0.15).toFixed(2))))}
              className="p-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 hover:text-white"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={handleFitView}
              className="px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 hover:text-white text-xs flex items-center gap-1"
              title="Fit Entire Graph"
            >
              <Maximize2 className="w-3 h-3" /> Fit
            </button>
            <button
              type="button"
              onClick={() => {
                setZoom(1);
                setPan({ x: 0, y: 0 });
                setPinnedId(null);
              }}
              className="px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 hover:text-white text-xs flex items-center gap-1"
              title="Reset View"
            >
              <RotateCcw className="w-3 h-3" /> Reset
            </button>
          </div>
        )}
      </div>

      {/* Layer Pill Strip (in Flow Graph mode) */}
      {layoutMode === 'flow' && (
        <div className="flex flex-wrap items-center justify-between gap-2 px-1">
          <div className="flex flex-wrap items-center gap-1.5">
            {LAYER_LABELS.map((l) => (
              <button
                key={l.key}
                type="button"
                onClick={() => toggleLayer(l.key)}
                className={`px-2 py-1 rounded-md text-[11px] font-mono border transition flex items-center gap-1.5 ${
                  visibleLayers[l.key]
                    ? 'bg-slate-900 border-slate-700 text-slate-200'
                    : 'bg-slate-950/40 border-slate-800/60 text-slate-400 line-through opacity-60'
                }`}
              >
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: l.color }} />
                {l.label}
              </button>
            ))}
          </div>
          <span className="text-[11px] font-mono tabular-nums text-slate-400">
            {ordered.visibleNodes.length} objects • {ordered.visibleEdges.length} links
          </span>
        </div>
      )}

      {/* Main Canvas Area: Either Node Bin-Packing Map OR Traffic Flow SVG */}
      {layoutMode === 'binpack' ? (
        <K3sNodeBinPackingMap
          pulse={effectivePulseForBinPack}
          namespace={selectedNs}
          search={search}
          issuesOnly={issuesOnly}
          onInspectPod={(opts) => {
            if (onInspectResource) {
              onInspectResource(opts);
            } else {
              onInspectNode({
                id: `pod/${opts.namespace || 'default'}/${opts.name}`,
                kind: 'Pod',
                resource: opts.resource,
                name: opts.name,
                namespace: opts.namespace,
                status: 'Running',
                statusTone: 'ok',
              });
            }
          }}
          onInspectNode={(nodeName) => {
            onInspectNode({
              id: `node/${nodeName}`,
              kind: 'Node',
              resource: 'nodes',
              name: nodeName,
              status: 'Ready',
              statusTone: 'ok',
            });
          }}
        />
      ) : (
        <>
          {/* Pinned Trace Action Bar */}
          {pinnedNodeObj && spotlightInfo && (
            <div className="p-3 rounded-xl bg-slate-900 border border-emerald-500/40 flex flex-wrap items-center justify-between gap-3 text-xs">
              <div className="flex flex-wrap items-center gap-2.5 min-w-0">
                <span className="px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 font-mono text-[10px] font-bold text-emerald-300">
                  LOCKED TRACE
                </span>
                <span className="font-mono font-bold text-white truncate">
                  {pinnedNodeObj.kind}/{pinnedNodeObj.namespace ? `${pinnedNodeObj.namespace}/` : ''}
                  {pinnedNodeObj.name}
                </span>
                <span className="font-mono text-slate-400 tabular-nums">
                  ({spotlightInfo.upstreamCount} upstream • {spotlightInfo.downstreamCount} downstream)
                </span>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => onInspectNode(pinnedNodeObj)}
                  className="px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-[11px] flex items-center gap-1.5"
                >
                  <Terminal className="w-3 h-3" /> Open Inspector
                </button>
                {onInspectResource && LOG_CAPABLE_KINDS.has(pinnedNodeObj.kind) && (
                  <button
                    type="button"
                    onClick={() =>
                      onInspectResource({
                        resource: pinnedNodeObj.resource,
                        name: pinnedNodeObj.name,
                        namespace: pinnedNodeObj.namespace,
                        tab: 'logs',
                      })
                    }
                    className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-700 hover:border-sky-500/40 text-sky-300 font-mono text-[11px] flex items-center gap-1"
                  >
                    <Activity className="w-3 h-3" /> Logs
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setPinnedId(null)}
                  className="p-1 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 hover:text-white"
                  title="Clear locked trace"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}

          {/* SVG Canvas */}
          <div
            ref={canvasContainerRef}
            className="rounded-2xl bg-slate-950 border border-slate-800 overflow-auto relative select-none"
            style={{ height: '640px', cursor: dragging ? 'grabbing' : 'grab' }}
            onMouseDown={(e) => {
              if ((e.target as HTMLElement).closest('[data-topo-node="true"]')) return;
              setDragging({ startX: e.clientX, startY: e.clientY, origX: pan.x, origY: pan.y });
            }}
            onMouseMove={(e) => {
              if (!dragging) return;
              setPan({
                x: dragging.origX + (e.clientX - dragging.startX),
                y: dragging.origY + (e.clientY - dragging.startY),
              });
            }}
            onMouseUp={() => setDragging(null)}
            onMouseLeave={() => setDragging(null)}
          >
            {ordered.visibleNodes.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-400 text-xs space-y-2">
                <Network className="w-8 h-8 text-slate-600" />
                <span>No Kubernetes resources match the selected namespace/layer/issue filter.</span>
              </div>
            ) : (
              <svg
                width={layout.width * zoom}
                height={layout.height * zoom}
                viewBox={`0 0 ${layout.width} ${layout.height}`}
                className="block"
                role="img"
                aria-label="Kubernetes resource topology flow graph"
              >
                <defs>
                  <pattern id="k3s-topo-grid" width="32" height="32" patternUnits="userSpaceOnUse">
                    <path d="M 32 0 L 0 0 0 32" fill="none" stroke="rgba(30,41,59,0.55)" strokeWidth="1" />
                  </pattern>
                  {[
                    { id: 'k3s-arrow-cyan', color: '#06b6d4' },
                    { id: 'k3s-arrow-sky', color: '#38bdf8' },
                    { id: 'k3s-arrow-emerald', color: '#10b981' },
                    { id: 'k3s-arrow-amber', color: '#f59e0b' },
                    { id: 'k3s-arrow-indigo', color: '#818cf8' },
                    { id: 'k3s-arrow-slate', color: '#64748b' },
                  ].map((m) => (
                    <marker
                      key={m.id}
                      id={m.id}
                      viewBox="0 0 10 10"
                      refX="8"
                      refY="5"
                      markerWidth="5.5"
                      markerHeight="5.5"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 1.5 L 9 5 L 0 8.5 z" fill={m.color} fillOpacity="0.85" />
                    </marker>
                  ))}
                </defs>

                <rect
                  width={layout.width}
                  height={layout.height}
                  fill="url(#k3s-topo-grid)"
                  onClick={() => setPinnedId(null)}
                />

                <g transform={`translate(${pan.x}, ${pan.y})`}>
                  {/* Column Headers */}
                  {layout.colHeaders.map((h) => (
                    <text
                      key={h.title}
                      x={h.x}
                      y={34}
                      fill="#94a3b8"
                      fontSize={12}
                      fontWeight={700}
                      fontFamily="ui-monospace, SFMono-Regular, monospace"
                    >
                      {h.title}
                    </text>
                  ))}

                  {/* Edges */}
                  {ordered.visibleEdges.map((e: K3sTopologyEdge) => {
                    const src = layout.posMap.get(e.source);
                    const dst = layout.posMap.get(e.target);
                    if (!src || !dst) return null;

                    const isHighlighted =
                      spotlightInfo === null ||
                      (spotlightInfo.connected.has(e.source) && spotlightInfo.connected.has(e.target));

                    const x1 = src.x + src.w;
                    const y1 = src.y + src.h / 2;
                    const x2 = dst.x;
                    const y2 = dst.y + dst.h / 2;
                    const dx = Math.max(22, Math.abs(x2 - x1) * 0.45);
                    const d = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;

                    return (
                      <path
                        key={e.id}
                        d={d}
                        fill="none"
                        stroke={edgeColor(e.relation)}
                        strokeWidth={activeFocusId && isHighlighted ? 2.4 : 1.5}
                        strokeOpacity={isHighlighted ? 0.72 : 0.08}
                        strokeDasharray={e.relation === 'pod-to-node' ? '4 4' : undefined}
                        markerEnd={isHighlighted ? markerIdForRelation(e.relation) : undefined}
                      />
                    );
                  })}

                  {/* Nodes */}
                  {layout.positioned.map(({ node, x, y, w, h }) => {
                    const isSearchMatch =
                      qLower !== '' &&
                      (node.name.toLowerCase().includes(qLower) ||
                        (node.namespace || '').toLowerCase().includes(qLower) ||
                        node.kind.toLowerCase().includes(qLower));
                    const isDimmed =
                      (spotlightInfo !== null && !spotlightInfo.connected.has(node.id)) ||
                      (qLower !== '' && !isSearchMatch);
                    const stroke =
                      pinnedId === node.id
                        ? '#f8fafc'
                        : isSearchMatch
                          ? '#10b981'
                          : toneStrokeColor(node.statusTone, node.kind);
                    const meta = `${node.kind.toUpperCase()}${node.namespace ? ` • ${node.namespace}` : ''}`;
                    const sub = node.subtitle || node.status;

                    return (
                      <g
                        key={node.id}
                        data-topo-node="true"
                        transform={`translate(${x}, ${y})`}
                        opacity={isDimmed ? 0.2 : 1}
                        className="cursor-pointer"
                        onMouseEnter={() => setHoveredId(node.id)}
                        onMouseLeave={() => setHoveredId(null)}
                        onClick={() => setPinnedId((cur) => (cur === node.id ? null : node.id))}
                        onDoubleClick={() => onInspectNode(node)}
                      >
                        <rect
                          width={w}
                          height={h}
                          rx={10}
                          fill="#0f172a"
                          stroke={stroke}
                          strokeWidth={activeFocusId === node.id || isSearchMatch ? 2.2 : 1.4}
                        />
                        <circle cx={13} cy={17} r={4} fill={toneStrokeColor(node.statusTone, node.kind)} />
                        <text
                          x={24}
                          y={20}
                          fill="#94a3b8"
                          fontSize={9.5}
                          fontWeight={700}
                          fontFamily="ui-monospace, monospace"
                        >
                          {meta.length > 23 ? meta.slice(0, 22) + '…' : meta}
                        </text>
                        <text
                          x={12}
                          y={36}
                          fill="#f8fafc"
                          fontSize={11.5}
                          fontWeight={600}
                          fontFamily="ui-monospace, monospace"
                        >
                          {node.name.length > 20 ? node.name.slice(0, 19) + '…' : node.name}
                        </text>
                        <text
                          x={12}
                          y={49}
                          fill="#94a3b8"
                          fontSize={9.5}
                          fontFamily="ui-monospace, monospace"
                        >
                          {sub.length > 25 ? sub.slice(0, 24) + '…' : sub}
                        </text>
                      </g>
                    );
                  })}
                </g>
              </svg>
            )}
          </div>

          {/* Legend */}
          <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400 px-1">
            <div className="flex flex-wrap items-center gap-4">
              <span className="flex items-center gap-1.5">
                <span className="w-4 h-0.5 bg-cyan-400 inline-block" /> Ingress &rarr; Service
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-4 h-0.5 bg-sky-400 inline-block" /> Service &rarr; Pod
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-4 h-0.5 bg-emerald-400 inline-block" /> Workload &rarr; Pod
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-4 h-0.5 border-t border-dashed border-indigo-400 inline-block" /> Pod &rarr; Node
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-4 h-0.5 bg-amber-400 inline-block" /> Pod &rarr; PVC
              </span>
            </div>
            <span>Click node to lock trace • Double-click to open K9s Inspector</span>
          </div>
        </>
      )}
    </div>
  );
}
