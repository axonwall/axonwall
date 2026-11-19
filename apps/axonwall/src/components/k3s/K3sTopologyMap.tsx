'use client';

import React, { useMemo, useState } from 'react';
import {
  Database,
  Globe,
  Layers,
  Maximize2,
  Network,
  RotateCcw,
  Search,
  Server,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import type { K3sTopologyEdge, K3sTopologyGraph, K3sTopologyNode } from './types';

interface K3sTopologyMapProps {
  graph: K3sTopologyGraph;
  namespaces: string[];
  initialNamespace?: string;
  onInspectNode: (node: K3sTopologyNode) => void;
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

interface PositionedNode {
  node: K3sTopologyNode;
  x: number;
  y: number;
  w: number;
  h: number;
}

export function K3sTopologyMap({
  graph,
  namespaces,
  initialNamespace = '_all',
  onInspectNode,
}: K3sTopologyMapProps) {
  const [selectedNs, setSelectedNs] = useState<string>(initialNamespace || '_all');
  const [search, setSearch] = useState('');
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState<{ startX: number; startY: number; origX: number; origY: number } | null>(
    null
  );
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [visibleLayers, setVisibleLayers] = useState<Record<LayerKey, boolean>>({
    Ingress: true,
    Service: true,
    Workload: true,
    Pod: true,
    Node: true,
    PVC: true,
  });

  const toggleLayer = (k: LayerKey) => {
    setVisibleLayers((prev) => ({ ...prev, [k]: !prev[k] }));
  };

  // Filter nodes & edges by namespace and enabled layers
  const filtered = useMemo(() => {
    const allowedNodeIds = new Set<string>();
    const nsNodes = graph.nodes.filter((n) => {
      const layer = nodeLayerKey(n.kind);
      if (!visibleLayers[layer]) return false;
      if (selectedNs === '_all') return true;
      // Always keep cluster Nodes when Pods in selectedNs are scheduled onto them (or show all nodes)
      if (n.kind === 'Node') return true;
      return n.namespace === selectedNs;
    });

    for (const n of nsNodes) {
      allowedNodeIds.add(n.id);
    }

    const nsEdges = graph.edges.filter(
      (e) => allowedNodeIds.has(e.source) && allowedNodeIds.has(e.target)
    );

    // Prune Nodes that have 0 scheduled Pods when filtering to a single namespace, unless Pods are hidden
    const activeNodeTargetIds = new Set(nsEdges.map((e) => e.target));
    const finalNodes = nsNodes.filter((n) => {
      if (n.kind === 'Node' && selectedNs !== '_all' && visibleLayers.Pod) {
        return activeNodeTargetIds.has(n.id);
      }
      return true;
    });

    const finalIds = new Set(finalNodes.map((n) => n.id));
    const finalEdges = nsEdges.filter((e) => finalIds.has(e.source) && finalIds.has(e.target));

    return { nodes: finalNodes, edges: finalEdges };
  }, [graph, selectedNs, visibleLayers]);

  // Deterministic 5-column layered SVG layout
  const layout = useMemo(() => {
    const colIngress: K3sTopologyNode[] = [];
    const colService: K3sTopologyNode[] = [];
    const colWorkload: K3sTopologyNode[] = [];
    const colPod: K3sTopologyNode[] = [];
    const colInfra: K3sTopologyNode[] = [];

    for (const n of filtered.nodes) {
      if (n.kind === 'Ingress') colIngress.push(n);
      else if (n.kind === 'Service') colService.push(n);
      else if (n.kind === 'Deployment' || n.kind === 'StatefulSet' || n.kind === 'DaemonSet' || n.kind === 'Job') {
        colWorkload.push(n);
      } else if (n.kind === 'Pod') {
        colPod.push(n);
      } else {
        colInfra.push(n);
      }
    }

    // Group pods by parentNodeName so Pods stay visually near their Node
    colPod.sort((a, b) => {
      const na = a.parentNodeName || 'zzz';
      const nb = b.parentNodeName || 'zzz';
      if (na !== nb) return na.localeCompare(nb);
      return a.name.localeCompare(b.name);
    });

    const boxW = 190;
    const boxH = 56;
    const colX = [36, 286, 536, 786, 1046];
    const rowGap = 74;
    const topMargin = 62;

    const placeCol = (items: K3sTopologyNode[], x: number): PositionedNode[] => {
      return items.map((node, i) => ({
        node,
        x,
        y: topMargin + i * rowGap,
        w: boxW,
        h: boxH,
      }));
    };

    const positioned = [
      ...placeCol(colIngress, colX[0]),
      ...placeCol(colService, colX[1]),
      ...placeCol(colWorkload, colX[2]),
      ...placeCol(colPod, colX[3]),
      ...placeCol(colInfra, colX[4]),
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
      width: 1280,
      height: maxY,
      colHeaders: [
        { title: `Ingresses (${colIngress.length})`, x: colX[0] },
        { title: `Services (${colService.length})`, x: colX[1] },
        { title: `Workloads (${colWorkload.length})`, x: colX[2] },
        { title: `Pods (${colPod.length})`, x: colX[3] },
        { title: `Nodes & PVCs (${colInfra.length})`, x: colX[4] },
      ],
    };
  }, [filtered.nodes]);

  // Adjacency for hover spotlight
  const connectedIds = useMemo(() => {
    if (!hoveredId) return null;
    const set = new Set<string>([hoveredId]);
    // 1-hop & 2-hop trace upstream/downstream
    const frontier = [hoveredId];
    const visited = new Set<string>([hoveredId]);
    while (frontier.length > 0) {
      const cur = frontier.shift()!;
      for (const e of filtered.edges) {
        if (e.source === cur && !visited.has(e.target)) {
          set.add(e.target);
          visited.add(e.target);
          frontier.push(e.target);
        }
        if (e.target === cur && !visited.has(e.source)) {
          set.add(e.source);
          visited.add(e.source);
          frontier.push(e.source);
        }
      }
    }
    return set;
  }, [hoveredId, filtered.edges]);

  const qLower = search.trim().toLowerCase();

  return (
    <div className="space-y-4">
      {/* Topology Toolbar */}
      <div className="p-3.5 rounded-2xl bg-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-medium">Namespace:</span>
            <select
              value={selectedNs}
              onChange={(e) => setSelectedNs(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono"
            >
              <option value="_all">All Namespaces ({namespaces.length})</option>
              {namespaces.map((ns) => (
                <option key={ns} value={ns}>
                  {ns}
                </option>
              ))}
            </select>
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Highlight object..."
              className="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white font-mono w-44"
            />
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            {LAYER_LABELS.map((l) => (
              <button
                key={l.key}
                type="button"
                onClick={() => toggleLayer(l.key)}
                className={`px-2 py-1 rounded-md text-[11px] font-mono border transition flex items-center gap-1.5 ${
                  visibleLayers[l.key]
                    ? 'bg-slate-950 border-slate-700 text-slate-200'
                    : 'bg-slate-950/40 border-slate-800/60 text-slate-500 line-through'
                }`}
              >
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: l.color }} />
                {l.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => setZoom((z) => Math.max(0.45, Number((z - 0.15).toFixed(2))))}
            className="p-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 hover:text-white"
            title="Zoom Out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <span className="text-xs font-mono text-slate-300 w-11 text-center">
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
            onClick={() => {
              setZoom(1);
              setPan({ x: 0, y: 0 });
            }}
            className="px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 hover:text-white text-xs flex items-center gap-1"
            title="Reset View"
          >
            <RotateCcw className="w-3 h-3" /> Reset
          </button>
        </div>
      </div>

      {/* SVG Canvas */}
      <div
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
        {filtered.nodes.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 text-xs space-y-2">
            <Network className="w-8 h-8 text-slate-700" />
            <span>No Kubernetes resources match the selected namespace/layer filter.</span>
          </div>
        ) : (
          <svg
            width={layout.width * zoom}
            height={layout.height * zoom}
            viewBox={`0 0 ${layout.width} ${layout.height}`}
            className="block"
          >
            <defs>
              <pattern id="k3s-topo-grid" width="32" height="32" patternUnits="userSpaceOnUse">
                <path d="M 32 0 L 0 0 0 32" fill="none" stroke="rgba(30,41,59,0.55)" strokeWidth="1" />
              </pattern>
            </defs>

            <rect width={layout.width} height={layout.height} fill="url(#k3s-topo-grid)" />

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
              {filtered.edges.map((e: K3sTopologyEdge) => {
                const src = layout.posMap.get(e.source);
                const dst = layout.posMap.get(e.target);
                if (!src || !dst) return null;

                const isHighlighted =
                  connectedIds === null ||
                  (connectedIds.has(e.source) && connectedIds.has(e.target));

                const x1 = src.x + src.w;
                const y1 = src.y + src.h / 2;
                const x2 = dst.x;
                const y2 = dst.y + dst.h / 2;
                const dx = Math.max(40, Math.abs(x2 - x1) * 0.45);
                const d = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;

                return (
                  <path
                    key={e.id}
                    d={d}
                    fill="none"
                    stroke={edgeColor(e.relation)}
                    strokeWidth={hoveredId && isHighlighted ? 2.4 : 1.5}
                    strokeOpacity={isHighlighted ? 0.72 : 0.08}
                    strokeDasharray={e.relation === 'pod-to-node' ? '4 4' : undefined}
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
                  (connectedIds !== null && !connectedIds.has(node.id)) ||
                  (qLower !== '' && !isSearchMatch);
                const stroke = isSearchMatch
                  ? '#10b981'
                  : toneStrokeColor(node.statusTone, node.kind);

                return (
                  <g
                    key={node.id}
                    data-topo-node="true"
                    transform={`translate(${x}, ${y})`}
                    opacity={isDimmed ? 0.2 : 1}
                    className="cursor-pointer"
                    onMouseEnter={() => setHoveredId(node.id)}
                    onMouseLeave={() => setHoveredId(null)}
                    onClick={() => onInspectNode(node)}
                  >
                    <rect
                      width={w}
                      height={h}
                      rx={10}
                      fill="#0f172a"
                      stroke={stroke}
                      strokeWidth={hoveredId === node.id || isSearchMatch ? 2.2 : 1.4}
                    />
                    <circle cx={13} cy={17} r={4} fill={stroke} />
                    <text
                      x={24}
                      y={20}
                      fill="#94a3b8"
                      fontSize={9.5}
                      fontWeight={700}
                      fontFamily="ui-monospace, monospace"
                    >
                      {node.kind.toUpperCase()}
                      {node.namespace ? ` • ${node.namespace}` : ''}
                    </text>
                    <text
                      x={12}
                      y={36}
                      fill="#f8fafc"
                      fontSize={11.5}
                      fontWeight={600}
                      fontFamily="ui-monospace, monospace"
                    >
                      {node.name.length > 22 ? node.name.slice(0, 21) + '…' : node.name}
                    </text>
                    <text
                      x={12}
                      y={49}
                      fill="#94a3b8"
                      fontSize={9.5}
                      fontFamily="ui-monospace, monospace"
                    >
                      {(node.subtitle || node.status).slice(0, 27)}
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
            <span className="w-4 h-0.5 bg-cyan-400 inline-block" /> Ingress → Service
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-4 h-0.5 bg-sky-400 inline-block" /> Service → Pod
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-4 h-0.5 bg-emerald-400 inline-block" /> Workload → Pod
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-4 h-0.5 border-t border-dashed border-indigo-400 inline-block" /> Pod → Node
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-4 h-0.5 bg-amber-400 inline-block" /> Pod → PVC
          </span>
        </div>
        <span>Hover any box to trace flow • Click any node to open K9s Inspector</span>
      </div>
    </div>
  );
}
