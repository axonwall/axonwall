'use client';

import React, { useMemo, useState } from 'react';
import { Plus, Search, X } from 'lucide-react';
import type { TopologyCanvasNode } from '@axonwall/lib/schemas';
import { NODE_KIND_CATALOG } from '../types';

interface CommandPaletteModalProps {
  open: boolean;
  onClose: () => void;
  nodes: TopologyCanvasNode[];
  onSelectNode: (nodeId: string) => void;
  onInsertCatalogNode: (kind: TopologyCanvasNode['kind']) => void;
}

export function CommandPaletteModal({
  open,
  onClose,
  nodes,
  onSelectNode,
  onInsertCatalogNode,
}: CommandPaletteModalProps) {
  const [query, setQuery] = useState('');

  const q = query.trim().toLowerCase();

  const matchingNodes = useMemo(
    () =>
      nodes
        .filter(
          (n) =>
            !q ||
            n.label.toLowerCase().includes(q) ||
            n.kind.toLowerCase().includes(q) ||
            (n.hostRef || '').toLowerCase().includes(q),
        )
        .slice(0, 12),
    [nodes, q],
  );

  const matchingCatalog = useMemo(
    () =>
      NODE_KIND_CATALOG.filter(
        (c) => !q || c.label.toLowerCase().includes(q) || c.kind.toLowerCase().includes(q),
      ),
    [q],
  );

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 bg-black/75 flex items-start justify-center pt-20 p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-xl bg-slate-950 border border-slate-800 rounded-xl shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-4 py-3 border-b border-slate-800 flex items-center gap-2.5 bg-slate-900">
          <Search className="w-4 h-4 text-sky-400 shrink-0" />
          <input
            type="text"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape') onClose();
            }}
            placeholder="Jump to host / K3s resource or insert node type..."
            className="flex-1 bg-transparent text-sm text-white placeholder-slate-500 focus:outline-none"
          />
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="max-h-[420px] overflow-y-auto p-3 space-y-4 text-xs">
          {matchingNodes.length > 0 && (
            <div className="space-y-1">
              <div className="px-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                Canvas Nodes
              </div>
              {matchingNodes.map((n) => (
                <button
                  key={n.id}
                  type="button"
                  onClick={() => {
                    onSelectNode(n.id);
                    onClose();
                  }}
                  className="w-full px-3 py-2 rounded-lg hover:bg-slate-900 flex items-center justify-between text-left"
                >
                  <span className="font-medium text-white truncate">{n.label}</span>
                  <span className="font-mono text-[11px] text-slate-400">
                    {n.kind} · {n.layer}
                  </span>
                </button>
              ))}
            </div>
          )}

          {matchingCatalog.length > 0 && (
            <div className="space-y-1">
              <div className="px-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                Add Node to Canvas
              </div>
              {matchingCatalog.map((item) => (
                <button
                  key={item.kind}
                  type="button"
                  onClick={() => {
                    onInsertCatalogNode(item.kind);
                    onClose();
                  }}
                  className="w-full px-3 py-2 rounded-lg hover:bg-slate-900 flex items-center justify-between text-left"
                >
                  <span className="flex items-center gap-2 text-sky-300 font-medium">
                    <Plus className="w-3.5 h-3.5" />
                    {item.label}
                  </span>
                  <span className="font-mono text-[11px] text-slate-400">{item.layer}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
