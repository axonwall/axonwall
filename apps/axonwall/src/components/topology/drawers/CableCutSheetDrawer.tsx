'use client';

import React, { useMemo, useState } from 'react';
import { Download, Search, X } from 'lucide-react';
import { exportCableCutSheet } from '@axonwall/lib/compile/topology';
import type { TopologyCableEdge, TopologyCanvasNode } from '@axonwall/lib/schemas';
import { HEALTH_TONE_CLASSES, type FabricHealthEvaluation } from '../types';

interface CableCutSheetDrawerProps {
  open: boolean;
  onClose: () => void;
  nodes: TopologyCanvasNode[];
  cables: TopologyCableEdge[];
  health: FabricHealthEvaluation;
}

function downloadText(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function CableCutSheetDrawer({
  open,
  onClose,
  nodes,
  cables,
  health,
}: CableCutSheetDrawerProps) {
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'planned' | 'installed'>('all');

  const rows = useMemo(() => {
    const nodeMap = new Map(nodes.map((n) => [n.id, n]));
    const q = query.trim().toLowerCase();
    return cables
      .filter((c) => c.layer === 'physical' || c.status === 'planned')
      .filter((c) => (statusFilter === 'all' ? true : c.status === statusFilter))
      .map((c) => {
        const src = nodeMap.get(c.sourceNodeId);
        const dst = nodeMap.get(c.targetNodeId);
        const srcPort = src?.ports.find((p) => p.id === c.sourcePortId)?.name || c.sourcePortId;
        const dstPort = dst?.ports.find((p) => p.id === c.targetPortId)?.name || c.targetPortId;
        return {
          cable: c,
          srcLabel: `${src?.label || c.sourceNodeId}:${srcPort}`,
          dstLabel: `${dst?.label || c.targetNodeId}:${dstPort}`,
          health: health.cableHealth[c.id],
        };
      })
      .filter(
        (r) =>
          !q ||
          (r.cable.cableLabel || '').toLowerCase().includes(q) ||
          r.srcLabel.toLowerCase().includes(q) ||
          r.dstLabel.toLowerCase().includes(q) ||
          r.cable.medium.toLowerCase().includes(q),
      );
  }, [nodes, cables, health, query, statusFilter]);

  if (!open) return null;

  const handleExport = (fmt: 'csv' | 'markdown' | 'json') => {
    const body = exportCableCutSheet(nodes, cables, health, fmt);
    const ext = fmt === 'markdown' ? 'md' : fmt;
    const mime = fmt === 'json' ? 'application/json' : fmt === 'csv' ? 'text/csv' : 'text/markdown';
    downloadText(`axonwall-cable-cut-sheet.${ext}`, body, mime);
  };

  return (
    <aside className="w-[460px] shrink-0 h-full bg-slate-950 border-l border-slate-800 flex flex-col overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-800 bg-slate-900 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-white">Physical Cable Cut-Sheet ({rows.length})</h3>
          <p className="text-[11px] text-slate-400">Planned &amp; installed runs with LLDP/LibreNMS verification</p>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-3 border-b border-slate-800 space-y-2 bg-slate-950">
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter host, port, label, medium..."
              className="w-full pl-8 pr-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-xs text-white"
            />
          </div>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as typeof statusFilter)}
            className="px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-xs text-white"
          >
            <option value="all">All Status</option>
            <option value="planned">Planned</option>
            <option value="installed">Installed</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          {(['csv', 'markdown', 'json'] as const).map((fmt) => (
            <button
              key={fmt}
              type="button"
              onClick={() => handleExport(fmt)}
              className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-[11px] font-mono text-sky-300 flex items-center gap-1 uppercase"
            >
              <Download className="w-3 h-3" />
              {fmt}
            </button>
          ))}
        </div>
      </div>

      <div className="p-3 space-y-2 overflow-y-auto flex-1 text-xs">
        {rows.length === 0 ? (
          <div className="py-10 text-center text-slate-400">No physical or planned cables match your filter.</div>
        ) : (
          rows.map(({ cable, srcLabel, dstLabel, health: ch }) => {
            const tone = ch?.status ?? 'yellow';
            const style = HEALTH_TONE_CLASSES[tone];
            return (
              <div key={cable.id} className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-white truncate">
                    {cable.cableLabel || cable.id}
                  </span>
                  <span className={`px-1.5 py-0.5 rounded font-mono text-[10px] uppercase ${style.badgeBg} ${style.text}`}>
                    {tone} · {cable.status}
                  </span>
                </div>
                <div className="font-mono text-[11px] text-slate-300 truncate">
                  {srcLabel} → {dstLabel}
                </div>
                <div className="flex flex-wrap gap-2 text-[10px] font-mono text-slate-400">
                  <span>{cable.medium}</span>
                  {cable.lengthMeters ? <span>{cable.lengthMeters}m</span> : null}
                  {cable.speedMbps ? <span>{cable.speedMbps} Mbps</span> : null}
                  {cable.color ? <span>color:{cable.color}</span> : null}
                  {cable.vlanIds.length > 0 ? <span>vlan:{cable.vlanIds.join(',')}</span> : null}
                </div>
                {ch?.reason && <div className="text-[11px] text-slate-400">{ch.reason}</div>}
              </div>
            );
          })
        )}
      </div>
    </aside>
  );
}
