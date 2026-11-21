'use client';

import React, { useMemo, useState } from 'react';
import {
  Filter,
  Network,
  RotateCcw,
  Search,
  ShieldAlert,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import {
  buildFlowTopologyGraph,
  formatBytesCompact,
  type FlowGraphEdge,
  type FlowGraphNode,
  type XdpBlockedEntry,
  type XdpFlowEntry,
} from '@/lib/ebpf-telemetry';

export interface SsePacketLike {
  srcIp: string;
  srcPort: string;
  dstIp: string;
  dstPort: string;
  protocol: string;
  length: number;
}

interface EbpfFlowTopologyMapProps {
  flows: XdpFlowEntry[];
  blockedIps: XdpBlockedEntry[];
  ssePackets?: SsePacketLike[];
  daemonDown?: boolean;
  onBlockIp?: (ip: string) => void;
}

interface PlacedNode {
  node: FlowGraphNode;
  x: number;
  y: number;
  w: number;
  h: number;
}

function isLoopbackOrInvalid(ip?: string): boolean {
  if (!ip) return true;
  if (ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0' || ip === '::') return true;
  return ip.startsWith('127.');
}

function truncateLabel(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 2)}..`;
}

export function EbpfFlowTopologyMap({
  flows,
  blockedIps,
  ssePackets = [],
  daemonDown = false,
  onBlockIp,
}: EbpfFlowTopologyMapProps) {
  const [sourceMode, setSourceMode] = useState<'xdp' | 'sse'>('xdp');
  const [protocolFilter, setProtocolFilter] = useState<string>('all');
  const [familyFilter, setFamilyFilter] = useState<'all' | '4' | '6'>('all');
  const [anomalyOnly, setAnomalyOnly] = useState(false);
  const [search, setSearch] = useState('');
  const [zoom, setZoom] = useState(1);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [selectedItem, setSelectedItem] = useState<
    | { kind: 'node'; node: FlowGraphNode }
    | { kind: 'edge'; edge: FlowGraphEdge }
    | null
  >(null);

  const activeFlows = useMemo<XdpFlowEntry[]>(() => {
    if (sourceMode === 'xdp' && flows.length > 0) {
      return flows;
    }
    if (sourceMode === 'xdp' && flows.length === 0 && ssePackets.length === 0) {
      return [];
    }
    if (sourceMode === 'sse') {
      // Aggregate live buffered SSE packets into pseudo-flow records strictly from real tap buffer
      const map = new Map<string, XdpFlowEntry>();
      for (const p of ssePackets) {
        const sPort = Number.parseInt(p.srcPort, 10) || 0;
        const dPort = Number.parseInt(p.dstPort, 10) || 0;
        const proto = (p.protocol || 'OTHER').toUpperCase();
        const isV6 = p.srcIp.includes(':') || p.dstIp.includes(':');
        const k = `${p.srcIp}:${sPort}->${p.dstIp}:${dPort}:${proto}`;
        const existing = map.get(k);
        if (existing) {
          existing.packets += 1;
          existing.bytes += Math.max(0, Number(p.length) || 0);
        } else {
          map.set(k, {
            family: isV6 ? 6 : 4,
            srcIp: p.srcIp,
            dstIp: p.dstIp,
            srcPort: sPort,
            dstPort: dPort,
            vlanId: 0,
            protocol: proto === 'TCP' ? 6 : proto === 'UDP' ? 17 : 0,
            protoName: proto,
            packets: 1,
            bytes: Math.max(0, Number(p.length) || 0),
            synPackets: 0,
            rstPackets: 0,
            ageMs: 0,
          });
        }
      }
      return Array.from(map.values());
    }
    return flows;
  }, [sourceMode, flows, ssePackets]);

  const graph = useMemo(
    () =>
      buildFlowTopologyGraph(activeFlows, blockedIps, {
        protocolFilter,
        familyFilter,
        anomalyOnly,
        search,
        maxFlows: 36,
      }),
    [activeFlows, blockedIps, protocolFilter, familyFilter, anomalyOnly, search]
  );

  const layout = useMemo(() => {
    const colX = [36, 400, 764];
    const boxW = 240;
    const boxH = 52;
    const rowGap = 68;
    const topMargin = 54;

    const place = (nodes: FlowGraphNode[], x: number): PlacedNode[] =>
      nodes.map((node, idx) => ({
        node,
        x,
        y: topMargin + idx * rowGap,
        w: boxW,
        h: boxH,
      }));

    const placed = [
      ...place(graph.sources, colX[0]),
      ...place(graph.hubs, colX[1]),
      ...place(graph.destinations, colX[2]),
    ];

    const posMap = new Map<string, PlacedNode>();
    let maxY = 340;
    for (const p of placed) {
      posMap.set(p.node.id, p);
      if (p.y + p.h + 36 > maxY) {
        maxY = p.y + p.h + 36;
      }
    }

    return {
      placed,
      posMap,
      width: 1040,
      height: maxY,
      colHeaders: [
        { title: `Source Endpoints (${graph.sources.length})`, x: colX[0] },
        { title: `Service Ports / VLANs (${graph.hubs.length})`, x: colX[1] },
        { title: `Destination Targets (${graph.destinations.length})`, x: colX[2] },
      ],
    };
  }, [graph]);

  const connectedSet = useMemo(() => {
    if (!hoveredNodeId) return null;
    const set = new Set<string>([hoveredNodeId]);
    for (const e of graph.edges) {
      if (e.from === hoveredNodeId) set.add(e.to);
      if (e.to === hoveredNodeId) set.add(e.from);
    }
    return set;
  }, [hoveredNodeId, graph.edges]);

  const edgeColor = (edge: FlowGraphEdge): string => {
    if (edge.isBlocked || edge.isRstHeavy) return '#f43f5e';
    if (edge.isSynHeavy) return '#f59e0b';
    if (edge.protoName === 'UDP') return '#38bdf8';
    if (edge.protoName === 'ICMP' || edge.protoName === 'ICMPv6') return '#a855f7';
    return '#10b981';
  };

  return (
    <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Network className="w-4 h-4 text-emerald-400" />
            Live XDP 5-Tuple Flow &amp; Talker Topology
          </h3>
          <p className="text-xs text-slate-400">
            Click any endpoint or path to inspect packets, SYN/RST ratios, VLAN ID, or enforce line-rate{' '}
            <code className="font-mono text-rose-300">XDP_DROP</code>
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex rounded-lg bg-slate-950 border border-slate-800 p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setSourceMode('xdp')}
              className={`px-2.5 py-1 rounded-md font-medium transition ${
                sourceMode === 'xdp' ? 'bg-emerald-500/20 text-emerald-300' : 'text-slate-400 hover:text-white'
              }`}
            >
              XDP Maps ({flows.length})
            </button>
            <button
              type="button"
              onClick={() => setSourceMode('sse')}
              className={`px-2.5 py-1 rounded-md font-medium transition ${
                sourceMode === 'sse' ? 'bg-sky-500/20 text-sky-300' : 'text-slate-400 hover:text-white'
              }`}
            >
              Live Tap Buffer ({ssePackets.length})
            </button>
          </div>
        </div>
      </div>

      {/* Filter & Zoom Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 pb-2 border-b border-slate-800">
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            aria-label="Filter by protocol"
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white"
          >
            <option value="all">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
            <option value="ICMPv6">ICMPv6</option>
          </select>

          <select
            value={familyFilter}
            onChange={(e) => setFamilyFilter(e.target.value as 'all' | '4' | '6')}
            aria-label="Filter by IP family"
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white"
          >
            <option value="all">IPv4 + IPv6</option>
            <option value="4">IPv4 Only</option>
            <option value="6">IPv6 Only</option>
          </select>

          <button
            type="button"
            onClick={() => setAnomalyOnly((a) => !a)}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition ${
              anomalyOnly
                ? 'bg-amber-500/20 border-amber-500/40 text-amber-300'
                : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
            }`}
          >
            <Filter className="w-3.5 h-3.5" />
            Anomalies Only
          </button>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="IP, port, VLAN..."
              className="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white font-mono w-44"
            />
          </div>
        </div>

        <div className="flex items-center gap-1.5 text-xs">
          <button
            type="button"
            onClick={() => setZoom((z) => Math.max(0.65, Number((z - 0.15).toFixed(2))))}
            className="p-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 hover:text-white"
            aria-label="Zoom out flow graph"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <span className="font-mono tabular-nums text-slate-300 w-12 text-center">
            {Math.round(zoom * 100)}%
          </span>
          <button
            type="button"
            onClick={() => setZoom((z) => Math.min(1.6, Number((z + 0.15).toFixed(2))))}
            className="p-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 hover:text-white"
            aria-label="Zoom in flow graph"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={() => {
              setZoom(1);
              setSelectedItem(null);
            }}
            className="p-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 hover:text-white"
            aria-label="Reset flow graph zoom"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* SVG Canvas */}
      {daemonDown && sourceMode === 'xdp' ? (
        <div className="h-[260px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg">
          Daemon offline — XDP LRU flow maps are unreachable. Switch to Live Tap Buffer if SSE is active.
        </div>
      ) : graph.edges.length === 0 ? (
        <div className="h-[260px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg text-center px-4">
          {activeFlows.length === 0
            ? sourceMode === 'xdp'
              ? 'No active flows in kernel XDP flow_map yet. Attach XDP on an active interface or switch to Live Tap Buffer.'
              : 'No buffered packets captured on /api/v1/events/packets yet.'
            : 'No flows match the active protocol/family/anomaly filter.'}
        </div>
      ) : (
        <div className="overflow-auto rounded-lg bg-slate-950 border border-slate-800/90 max-h-[540px]">
          <svg
            width={Math.round(layout.width * zoom)}
            height={Math.round(layout.height * zoom)}
            viewBox={`0 0 ${layout.width} ${layout.height}`}
            className="block select-none"
          >
            {/* Column titles */}
            {layout.colHeaders.map((h) => (
              <text
                key={h.title}
                x={h.x}
                y={28}
                fill="#94a3b8"
                fontSize={12}
                fontWeight={600}
                fontFamily="ui-sans-serif, system-ui, sans-serif"
              >
                {h.title}
              </text>
            ))}

            {/* Cubic Bezier weighted edges */}
            {graph.edges.map((edge) => {
              const fromPos = layout.posMap.get(edge.from);
              const toPos = layout.posMap.get(edge.to);
              if (!fromPos || !toPos) return null;

              const x1 = fromPos.x + fromPos.w;
              const y1 = fromPos.y + fromPos.h / 2;
              const x2 = toPos.x;
              const y2 = toPos.y + toPos.h / 2;
              const cx1 = x1 + (x2 - x1) * 0.45;
              const cx2 = x1 + (x2 - x1) * 0.55;
              const strokeW = Math.max(1.5, Math.min(6.5, Math.log2(Math.max(64, edge.bytes)) - 5));
              const dim =
                connectedSet !== null &&
                !(connectedSet.has(edge.from) && connectedSet.has(edge.to));
              const isSelected =
                selectedItem?.kind === 'edge' && selectedItem.edge.id === edge.id;

              return (
                <path
                  key={edge.id}
                  d={`M ${x1} ${y1} C ${cx1} ${y1}, ${cx2} ${y2}, ${x2} ${y2}`}
                  fill="none"
                  stroke={edgeColor(edge)}
                  strokeWidth={isSelected ? strokeW + 1.5 : strokeW}
                  strokeOpacity={dim ? 0.14 : isSelected ? 1 : 0.72}
                  strokeDasharray={edge.isBlocked ? '6 4' : undefined}
                  className="cursor-pointer transition-opacity"
                  onClick={() => setSelectedItem({ kind: 'edge', edge })}
                />
              );
            })}

            {/* Tier Nodes */}
            {layout.placed.map(({ node, x, y, w, h }) => {
              const dim = connectedSet !== null && !connectedSet.has(node.id);
              const selected =
                selectedItem?.kind === 'node' && selectedItem.node.id === node.id;
              const stroke = node.isBlocked
                ? '#f43f5e'
                : node.isAnomaly
                  ? '#f59e0b'
                  : node.tier === 'hub'
                    ? '#38bdf8'
                    : '#10b981';

              return (
                <g
                  key={node.id}
                  transform={`translate(${x}, ${y})`}
                  opacity={dim ? 0.25 : 1}
                  className="cursor-pointer"
                  onMouseEnter={() => setHoveredNodeId(node.id)}
                  onMouseLeave={() => setHoveredNodeId(null)}
                  onClick={() => setSelectedItem({ kind: 'node', node })}
                >
                  <rect
                    width={w}
                    height={h}
                    rx={8}
                    fill={selected ? '#1e293b' : '#0f172a'}
                    stroke={stroke}
                    strokeWidth={selected ? 2 : 1}
                  />
                  <text
                    x={12}
                    y={22}
                    fill="#f8fafc"
                    fontSize={12}
                    fontWeight={600}
                    fontFamily="ui-monospace, SFMono-Regular, monospace"
                  >
                    {truncateLabel(node.label, 22)}
                  </text>
                  <text
                    x={12}
                    y={39}
                    fill="#94a3b8"
                    fontSize={10.5}
                    fontFamily="ui-monospace, SFMono-Regular, monospace"
                  >
                    {truncateLabel(
                      `${node.sublabel} • ${formatBytesCompact(node.bytes)}`,
                      29
                    )}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
      )}

      {/* Selected Node or Edge Inspector */}
      {selectedItem && (
        <div className="pt-3 border-t border-slate-800 space-y-3 text-xs">
          {selectedItem.kind === 'node' ? (
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="space-y-0.5">
                <div className="font-mono font-bold text-white text-sm">
                  {selectedItem.node.label}
                  <span className="ml-2 text-xs font-normal text-slate-400">
                    ({selectedItem.node.sublabel})
                  </span>
                </div>
                <div className="font-mono tabular-nums text-slate-300">
                  {formatBytesCompact(selectedItem.node.bytes)} •{' '}
                  {selectedItem.node.packets.toLocaleString()} packets
                </div>
              </div>
              {selectedItem.node.ip && onBlockIp && !isLoopbackOrInvalid(selectedItem.node.ip) && (
                <button
                  type="button"
                  onClick={() => onBlockIp(selectedItem.node.ip!)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-xs font-semibold text-white"
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  Enforce XDP_DROP ({selectedItem.node.ip})
                </button>
              )}
            </div>
          ) : (
            <div className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="font-mono font-bold text-white">
                  {selectedItem.edge.protoName} Path • {formatBytesCompact(selectedItem.edge.bytes)} (
                  {selectedItem.edge.packets.toLocaleString()} pkts)
                </div>
                <div className="font-mono tabular-nums text-slate-300">
                  SYN: {selectedItem.edge.synPackets} • RST: {selectedItem.edge.rstPackets}
                </div>
              </div>
              <div className="overflow-x-auto max-h-40">
                <table className="w-full text-left font-mono text-[11px] tabular-nums">
                  <thead className="text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-1.5 pr-2">5-Tuple</th>
                      <th className="py-1.5 px-2">VLAN</th>
                      <th className="py-1.5 px-2">Flags</th>
                      <th className="py-1.5 px-2">Packets / Bytes</th>
                      <th className="py-1.5 pl-2 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {selectedItem.edge.flows.slice(0, 8).map((f, i) => (
                      <tr key={i}>
                        <td className="py-1.5 pr-2 text-slate-200">
                          {f.srcIp}:{f.srcPort} -&gt; {f.dstIp}:{f.dstPort}
                        </td>
                        <td className="py-1.5 px-2 text-purple-300">{f.vlanId || '-'}</td>
                        <td className="py-1.5 px-2 text-amber-300">{f.tcpFlags || '-'}</td>
                        <td className="py-1.5 px-2 text-slate-300">
                          {f.packets.toLocaleString()} / {formatBytesCompact(f.bytes)}
                        </td>
                        <td className="py-1.5 pl-2 text-right">
                          {onBlockIp && !isLoopbackOrInvalid(f.srcIp) && (
                            <button
                              type="button"
                              onClick={() => onBlockIp(f.srcIp)}
                              className="px-2 py-0.5 rounded bg-rose-600/80 hover:bg-rose-500 text-white text-[10px]"
                            >
                              XDP_DROP Src
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
