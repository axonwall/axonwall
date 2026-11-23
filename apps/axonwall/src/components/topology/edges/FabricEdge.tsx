'use client';

import React, { memo } from 'react';
import { BaseEdge, EdgeLabelRenderer, getSmoothStepPath, type EdgeProps } from '@xyflow/react';
import { HEALTH_TONE_CLASSES, type TopologyFlowEdge } from '../types';

function formatBps(bps?: number): string {
  if (!bps || bps <= 0) return '';
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)}G`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)}M`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)}K`;
  return `${Math.round(bps)}b`;
}

export const FabricEdge = memo(function FabricEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  selected,
}: EdgeProps<TopologyFlowEdge>) {
  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
    borderRadius: 12,
  });

  const model = data?.model;
  const tone = data?.health?.status ?? 'yellow';
  const toneStyle = HEALTH_TONE_CLASSES[tone];
  const isPlanned = model?.status === 'planned';
  const isFiber = model?.medium === 'fiber-om4' || model?.medium === 'fiber-os2' || model?.medium === 'sfp-dac';
  const throughput =
    data?.health?.rxBps || data?.health?.txBps
      ? `${formatBps(data.health?.rxBps)}/${formatBps(data.health?.txBps)}`
      : '';
  const pillText = [model?.cableLabel || model?.medium || '', throughput].filter(Boolean).join(' · ');

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        style={{
          stroke: data?.isTraced ? '#38bdf8' : toneStyle.stroke,
          strokeWidth: selected || data?.isTraced ? 3.5 : isFiber ? 2.8 : 2,
          strokeDasharray: isPlanned ? '6 4' : model?.layer === 'vpn' ? '3 3' : undefined,
          opacity: selected || data?.isTraced ? 1 : 0.85,
        }}
      />
      {(pillText || selected) && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
              pointerEvents: 'all',
            }}
            title={data?.health?.reason || model?.cableLabel}
            className={`px-2 py-0.5 rounded-full text-[10px] font-mono border shadow-sm cursor-pointer ${
              selected
                ? 'bg-slate-900 border-sky-400 text-white'
                : `bg-slate-950/90 ${toneStyle.border} ${toneStyle.text}`
            }`}
          >
            {pillText || model?.id}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
});

export const TOPOLOGY_EDGE_TYPES = {
  fabricEdge: FabricEdge,
};
