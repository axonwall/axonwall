'use client';

import React from 'react';
import { Flame } from 'lucide-react';
import { formatBytes } from '@axonwall/lib/compile/netflow';
import type { NetFlowHeatmapMatrixSnapshot } from './types';

interface FlowHeatmapsPanelProps {
  hostHeatmap?: NetFlowHeatmapMatrixSnapshot;
  portTimeHeatmap?: NetFlowHeatmapMatrixSnapshot;
  onFilterFql: (clause: string) => void;
}

function heatBg(value: number, maxValue: number): string {
  if (!value || maxValue <= 0) return 'rgba(15, 23, 42, 0.7)';
  const ratio = Math.log10(1 + value) / Math.log10(1 + maxValue);
  if (ratio > 0.8) return 'rgba(245, 158, 11, 0.82)'; // amber hotspot
  if (ratio > 0.5) return 'rgba(16, 185, 129, 0.72)'; // emerald
  if (ratio > 0.25) return 'rgba(56, 189, 248, 0.55)'; // sky
  return 'rgba(56, 189, 248, 0.22)';
}

function MatrixGrid({
  title,
  subtitle,
  matrix,
  emptyLabel,
  onCellClick,
}: {
  title: string;
  subtitle: string;
  matrix?: NetFlowHeatmapMatrixSnapshot;
  emptyLabel: string;
  onCellClick: (row: string, col: string) => void;
}) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
      <div className="flex items-center gap-2">
        <Flame className="w-4 h-4 text-amber-400" />
        <div>
          <h3 className="text-sm font-semibold text-white">{title}</h3>
          <p className="text-xs text-slate-400">{subtitle}</p>
        </div>
      </div>

      {!matrix || matrix.rowLabels.length === 0 || matrix.colLabels.length === 0 ? (
        <div className="py-12 text-center text-xs text-slate-500">{emptyLabel}</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-[10px] font-mono border-collapse">
            <thead>
              <tr>
                <th className="text-left text-slate-400 py-1 pr-2 font-normal">Src / Key</th>
                {matrix.colLabels.map((c) => (
                  <th
                    key={c}
                    className="text-center text-slate-400 px-1 py-1 font-normal max-w-[74px] truncate"
                    title={c}
                  >
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {matrix.rowLabels.map((row, rIdx) => (
                <tr key={row}>
                  <td className="text-slate-200 py-1 pr-2 whitespace-nowrap max-w-[130px] truncate" title={row}>
                    {row}
                  </td>
                  {matrix.colLabels.map((col, cIdx) => {
                    const val = matrix.values[rIdx]?.[cIdx] ?? 0;
                    return (
                      <td key={`${row}-${col}`} className="p-0.5">
                        <button
                          type="button"
                          onClick={() => val > 0 && onCellClick(row, col)}
                          title={`${row} × ${col}: ${formatBytes(val)}`}
                          style={{ backgroundColor: heatBg(val, matrix.maxValue) }}
                          className="w-full h-6 rounded text-white/90 hover:ring-1 hover:ring-white/60 transition flex items-center justify-center"
                        >
                          {val > 0 ? formatBytes(val).replace(' ', '') : ''}
                        </button>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function FlowHeatmapsPanel({ hostHeatmap, portTimeHeatmap, onFilterFql }: FlowHeatmapsPanelProps) {
  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
      <MatrixGrid
        title="Host × Host Intensity Matrix (Top 12 × 12)"
        subtitle="Log-scaled byte volume; click any active cell to filter src & dst in FQL"
        matrix={hostHeatmap}
        emptyLabel="Run a query with matching flows to render the Host × Host matrix."
        onCellClick={(srcIp, dstIp) => onFilterFql(`src=${srcIp} and dst=${dstIp}`)}
      />
      <MatrixGrid
        title="Destination Port × Time Heatmap"
        subtitle="Spot port scans, periodic beaconing & backup bursts across time buckets"
        matrix={portTimeHeatmap}
        emptyLabel="Run a query with TCP/UDP ports to render the Port × Time heatmap."
        onCellClick={(port) => onFilterFql(`dst_port=${port}`)}
      />
    </div>
  );
}
