'use client';

import React, { useMemo, useState } from 'react';
import { formatBytes } from '@axonwall/lib/compile/netflow';
import type { NetFlowQueryResponseSnapshot } from './types';

interface FlowSankeyMatrixProps {
  links: NetFlowQueryResponseSnapshot['sankeyLinks'];
  onFilterFql: (fql: string) => void;
}

interface LayoutNode {
  id: string;
  label: string;
  totalBytes: number;
  y: number;
  h: number;
  col: 0 | 1 | 2;
}

export function FlowSankeyMatrix({ links, onFilterFql }: FlowSankeyMatrixProps) {
  const [hoveredKey, setHoveredKey] = useState<string | null>(null);

  const layout = useMemo(() => {
    const srcApp = links.filter((l) => l.stage === 'src-to-app').slice(0, 8);
    const appDst = links.filter((l) => l.stage === 'app-to-dst').slice(0, 8);
    if (srcApp.length === 0 && appDst.length === 0) return null;

    const srcWeights = new Map<string, number>();
    const appWeights = new Map<string, number>();
    const dstWeights = new Map<string, number>();

    for (const l of srcApp) {
      srcWeights.set(l.source, (srcWeights.get(l.source) ?? 0) + l.bytes);
      appWeights.set(l.target, (appWeights.get(l.target) ?? 0) + l.bytes);
    }
    for (const l of appDst) {
      appWeights.set(l.source, Math.max(appWeights.get(l.source) ?? 0, l.bytes));
      dstWeights.set(l.target, (dstWeights.get(l.target) ?? 0) + l.bytes);
    }

    const SVG_H = 260;
    const PAD_Y = 12;
    const GAP = 8;

    const buildCol = (weights: Map<string, number>, col: 0 | 1 | 2): Map<string, LayoutNode> => {
      const entries = Array.from(weights.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8);
      const total = Math.max(1, entries.reduce((s, [, w]) => s + w, 0));
      const usableH = Math.max(80, SVG_H - PAD_Y * 2 - Math.max(0, entries.length - 1) * GAP);
      let y = PAD_Y;
      const map = new Map<string, LayoutNode>();
      for (const [id, bytes] of entries) {
        const h = Math.max(14, (bytes / total) * usableH);
        map.set(id, { id, label: id, totalBytes: bytes, y, h, col });
        y += h + GAP;
      }
      return map;
    };

    const srcMap = buildCol(srcWeights, 0);
    const appMap = buildCol(appWeights, 1);
    const dstMap = buildCol(dstWeights, 2);
    return { srcApp, appDst, srcMap, appMap, dstMap, SVG_H };
  }, [links]);

  if (!layout) {
    return (
      <div className="h-[220px] flex items-center justify-center text-xs text-slate-500">
        No flow paths recorded in this time window yet.
      </div>
    );
  }

  const COL_X = [12, 340, 668] as const;
  const NODE_W = 140;

  return (
    <div className="w-full overflow-x-auto">
      <svg viewBox={`0 0 820 ${layout.SVG_H}`} className="w-full min-w-[640px] h-[250px]">
        {/* Stage 1 Ribbons: Source -> App */}
        {layout.srcApp.map((l, idx) => {
          const sNode = layout.srcMap.get(l.source);
          const aNode = layout.appMap.get(l.target);
          if (!sNode || !aNode) return null;
          const x1 = COL_X[0] + NODE_W;
          const x2 = COL_X[1];
          const y1 = sNode.y + sNode.h / 2;
          const y2 = aNode.y + aNode.h / 2;
          const cx = (x1 + x2) / 2;
          const k = `s1-${idx}`;
          const active = hoveredKey === null || hoveredKey === k;
          return (
            <path
              key={k}
              d={`M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`}
              fill="none"
              stroke="#38bdf8"
              strokeWidth={Math.max(2, Math.min(18, (l.bytes / Math.max(1, sNode.totalBytes)) * 12))}
              strokeOpacity={active ? 0.55 : 0.12}
              onMouseEnter={() => setHoveredKey(k)}
              onMouseLeave={() => setHoveredKey(null)}
              onClick={() => onFilterFql(`app="${l.target}"`)}
              className="cursor-pointer transition-opacity"
            >
              <title>{`${l.source} -> ${l.target}: ${formatBytes(l.bytes)}`}</title>
            </path>
          );
        })}

        {/* Stage 2 Ribbons: App -> Destination */}
        {layout.appDst.map((l, idx) => {
          const aNode = layout.appMap.get(l.source);
          const dNode = layout.dstMap.get(l.target);
          if (!aNode || !dNode) return null;
          const x1 = COL_X[1] + NODE_W;
          const x2 = COL_X[2];
          const y1 = aNode.y + aNode.h / 2;
          const y2 = dNode.y + dNode.h / 2;
          const cx = (x1 + x2) / 2;
          const k = `s2-${idx}`;
          const active = hoveredKey === null || hoveredKey === k;
          return (
            <path
              key={k}
              d={`M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`}
              fill="none"
              stroke="#10b981"
              strokeWidth={Math.max(2, Math.min(18, (l.bytes / Math.max(1, aNode.totalBytes)) * 12))}
              strokeOpacity={active ? 0.55 : 0.12}
              onMouseEnter={() => setHoveredKey(k)}
              onMouseLeave={() => setHoveredKey(null)}
              onClick={() => onFilterFql(`app="${l.source}"`)}
              className="cursor-pointer transition-opacity"
            >
              <title>{`${l.source} -> ${l.target}: ${formatBytes(l.bytes)}`}</title>
            </path>
          );
        })}

        {/* Node Columns */}
        {[
          { map: layout.srcMap, x: COL_X[0], fill: '#0284c7', prefix: 'src' },
          { map: layout.appMap, x: COL_X[1], fill: '#059669', prefix: 'app' },
          { map: layout.dstMap, x: COL_X[2], fill: '#7c3aed', prefix: 'dst' },
        ].map((colCfg) =>
          Array.from(colCfg.map.values()).map((n) => (
            <g
              key={`${colCfg.prefix}-${n.id}`}
              onClick={() =>
                onFilterFql(colCfg.prefix === 'app' ? `app="${n.id}"` : `${n.id}`)
              }
              className="cursor-pointer"
            >
              <rect x={colCfg.x} y={n.y} width={NODE_W} height={n.h} rx={4} fill={colCfg.fill} fillOpacity={0.22} stroke={colCfg.fill} strokeOpacity={0.7} />
              <text
                x={colCfg.x + 6}
                y={n.y + Math.min(n.h / 2 + 4, 14)}
                fill="#e2e8f0"
                fontSize={10}
                fontFamily="monospace"
              >
                {n.label.length > 18 ? `${n.label.slice(0, 16)}..` : n.label}
              </text>
            </g>
          )),
        )}
      </svg>
    </div>
  );
}
