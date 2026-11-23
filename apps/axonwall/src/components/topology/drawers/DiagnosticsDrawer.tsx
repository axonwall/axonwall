'use client';

import React, { useMemo, useState } from 'react';
import { AlertCircle, AlertTriangle, Crosshair, Info, Wrench, X } from 'lucide-react';
import type { TopologyDiagnostic } from '@axonwall/lib/compile/topology';

interface DiagnosticsDrawerProps {
  open: boolean;
  onClose: () => void;
  diagnostics: TopologyDiagnostic[];
  onFocusTarget: (nodeId?: string, edgeId?: string) => void;
  onApplyQuickFix: (diag: TopologyDiagnostic) => void;
}

export function DiagnosticsDrawer({
  open,
  onClose,
  diagnostics,
  onFocusTarget,
  onApplyQuickFix,
}: DiagnosticsDrawerProps) {
  const [filter, setFilter] = useState<'all' | 'error' | 'warning' | 'info'>('all');

  const filtered = useMemo(() => {
    if (filter === 'all') return diagnostics;
    return diagnostics.filter((d) => d.severity === filter);
  }, [diagnostics, filter]);

  if (!open) return null;

  return (
    <aside className="w-[390px] shrink-0 h-full bg-slate-950 border-l border-slate-800 flex flex-col overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-800 bg-slate-900 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-white">Topology Diagnostics ({diagnostics.length})</h3>
          <p className="text-[11px] text-slate-400">MTU/VLAN mismatches, SPOFs, K3s routes &amp; planned links</p>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="px-4 py-2 border-b border-slate-800/80 flex items-center gap-1.5 bg-slate-950">
        {(['all', 'error', 'warning', 'info'] as const).map((tab) => (
          <button
            key={tab}
            type="button"
            onClick={() => setFilter(tab)}
            className={`px-2.5 py-1 rounded text-[11px] font-medium capitalize ${
              filter === tab
                ? 'bg-sky-600 text-white'
                : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      <div className="p-3 space-y-2.5 overflow-y-auto flex-1">
        {filtered.length === 0 ? (
          <div className="py-10 text-center text-xs text-slate-400">
            No {filter === 'all' ? '' : filter} diagnostics detected.
          </div>
        ) : (
          filtered.map((d) => {
            const sevStyles =
              d.severity === 'error'
                ? 'border-rose-500/40 bg-rose-500/10 text-rose-300'
                : d.severity === 'warning'
                  ? 'border-amber-500/40 bg-amber-500/10 text-amber-300'
                  : 'border-sky-500/35 bg-sky-500/10 text-sky-300';

            return (
              <div key={d.id} className={`p-3 rounded-lg border text-xs space-y-2 ${sevStyles}`}>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-1.5 font-semibold">
                    {d.severity === 'error' ? (
                      <AlertCircle className="w-4 h-4 shrink-0" />
                    ) : d.severity === 'warning' ? (
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                    ) : (
                      <Info className="w-4 h-4 shrink-0" />
                    )}
                    <span>{d.title}</span>
                  </div>
                  <span className="font-mono text-[10px] opacity-80">{d.code}</span>
                </div>

                <p className="text-slate-200/90 leading-relaxed">{d.detail}</p>

                <div className="flex items-center gap-2 pt-1">
                  {(d.nodeId || d.edgeId) && (
                    <button
                      type="button"
                      onClick={() => onFocusTarget(d.nodeId, d.edgeId)}
                      className="px-2 py-1 rounded bg-slate-900/80 hover:bg-slate-900 border border-slate-700 text-slate-200 text-[11px] flex items-center gap-1"
                    >
                      <Crosshair className="w-3 h-3" />
                      Locate
                    </button>
                  )}
                  {d.quickFix && (
                    <button
                      type="button"
                      onClick={() => onApplyQuickFix(d)}
                      className="px-2.5 py-1 rounded bg-sky-600 hover:bg-sky-500 text-white text-[11px] font-medium flex items-center gap-1"
                    >
                      <Wrench className="w-3 h-3" />
                      {d.quickFix.label}
                    </button>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </aside>
  );
}
