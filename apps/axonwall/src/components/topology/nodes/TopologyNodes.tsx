'use client';

import React, { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import {
  AlertTriangle,
  Box,
  Boxes,
  Cloud,
  Cpu,
  Database,
  Globe,
  HardDrive,
  Layers,
  Lock,
  Network,
  Radio,
  Router,
  Server,
  Shield,
} from 'lucide-react';
import type { TopologyCanvasNode } from '@axonwall/lib/schemas';
import { HEALTH_TONE_CLASSES, type TopologyFlowNode } from '../types';

function NodeIcon({ kind }: { kind: TopologyCanvasNode['kind'] }) {
  const cls = 'w-4 h-4 shrink-0';
  switch (kind) {
    case 'wan':
      return <Globe className={`${cls} text-sky-400`} />;
    case 'edge-ngfw':
      return <Shield className={`${cls} text-emerald-400`} />;
    case 'switch':
    case 'patch-panel':
      return <Network className={`${cls} text-cyan-400`} />;
    case 'vault':
      return <Lock className={`${cls} text-amber-400`} />;
    case 'nas':
    case 'k3s-pvc':
      return <HardDrive className={`${cls} text-indigo-400`} />;
    case 'k3s-node':
      return <Cpu className={`${cls} text-sky-300`} />;
    case 'satellite':
      return <Radio className={`${cls} text-purple-400`} />;
    case 'vlan':
    case 'bridge-bond':
    case 'vip':
      return <Layers className={`${cls} text-teal-400`} />;
    case 'vpn-overlay':
    case 'haproxy':
      return <Router className={`${cls} text-violet-400`} />;
    case 'k3s-ingress':
    case 'k3s-crd':
      return <Cloud className={`${cls} text-cyan-300`} />;
    case 'k3s-service':
    case 'k3s-netpol':
      return <Database className={`${cls} text-emerald-300`} />;
    case 'k3s-workload':
    case 'kvm-vm':
    case 'lxc-container':
      return <Boxes className={`${cls} text-slate-300`} />;
    default:
      return <Server className={`${cls} text-slate-400`} />;
  }
}

export const TopologyNodeCard = memo(function TopologyNodeCard({ data, selected }: NodeProps<TopologyFlowNode>) {
  const model = data.model;
  const nodeTone = data.health?.status ?? 'yellow';
  const toneStyle = HEALTH_TONE_CLASSES[nodeTone];
  const ports =
    model.ports && model.ports.length > 0
      ? model.ports
      : [{ id: 'default', name: 'default', kind: 'generic' as const, vlanIds: [], planned: !model.managed }];

  return (
    <div
      className={`min-w-[235px] max-w-[285px] rounded-xl bg-slate-950/95 border transition shadow-lg ${
        data.isTraced
          ? 'ring-2 ring-sky-400 border-sky-400'
          : selected
            ? 'ring-2 ring-white/40 ' + toneStyle.border
            : toneStyle.border
      }`}
    >
      {/* Header */}
      <div
        className="px-3 py-2 border-b border-slate-800/90 flex items-center justify-between gap-2 bg-slate-900/80 rounded-t-xl"
        title={data.health?.reason || model.label}
      >
        <div className="flex items-center gap-2 min-w-0">
          <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${toneStyle.dot}`} />
          <NodeIcon kind={model.kind} />
          <div className="min-w-0">
            <div className="text-xs font-semibold text-white truncate">{model.label}</div>
            <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wide flex items-center gap-1.5">
              <span>{model.kind}</span>
              <span>·</span>
              <span>{model.layer}</span>
            </div>
          </div>
        </div>
        {(data.activeAlertsCount ?? 0) > 0 && (
          <span
            className="px-1.5 py-0.5 rounded bg-rose-500/20 border border-rose-500/40 text-[10px] font-mono text-rose-300 flex items-center gap-1 shrink-0"
            title="Active LibreNMS alerts"
          >
            <AlertTriangle className="w-3 h-3" />
            {data.activeAlertsCount}
          </span>
        )}
      </div>

      {/* Per-Port Endpoint Handles (with Left target & Right source handles per port) */}
      <div className="py-1.5 divide-y divide-slate-800/50">
        {ports.map((port) => {
          const pk = `${model.id}:${port.id}`;
          const pHealth = data.portHealth?.[pk];
          const pTone = pHealth?.status ?? 'yellow';
          const pStyle = HEALTH_TONE_CLASSES[pTone];
          const speedLabel =
            port.speedMbps && port.speedMbps >= 1000
              ? `${port.speedMbps / 1000}G`
              : port.speedMbps
                ? `${port.speedMbps}M`
                : port.mtu
                  ? `mtu:${port.mtu}`
                  : '';

          return (
            <div
              key={port.id}
              onClick={() => data.onSelectPort?.(model.id, port.id)}
              className="relative px-3.5 py-1.5 flex items-center justify-between gap-2 text-[11px] hover:bg-slate-900/70 cursor-pointer"
              title={pHealth?.reason || `${port.name} (${pTone})`}
            >
              <Handle
                type="target"
                position={Position.Left}
                id={port.id}
                className={`!w-2.5 !h-2.5 !border !border-slate-950 ${pStyle.dot}`}
                style={{ left: -5 }}
              />
              <div className="flex items-center gap-1.5 min-w-0">
                <span className={`w-2 h-2 rounded-full shrink-0 ${pStyle.dot}`} />
                <span className="font-mono text-slate-200 truncate">{port.name}</span>
              </div>
              <div className="flex items-center gap-1 text-[10px] font-mono text-slate-400 shrink-0">
                {port.vlanIds?.length ? (
                  <span className="px-1 rounded bg-slate-800 text-slate-300">v{port.vlanIds.join(',')}</span>
                ) : null}
                {speedLabel ? <span>{speedLabel}</span> : null}
                {port.planned ? <Box className="w-2.5 h-2.5 text-amber-400" /> : null}
              </div>
              <Handle
                type="source"
                position={Position.Right}
                id={port.id}
                className={`!w-2.5 !h-2.5 !border !border-slate-950 ${pStyle.dot}`}
                style={{ right: -5 }}
              />
            </div>
          );
        })}
      </div>
    </div>
  );
});

export const TOPOLOGY_NODE_TYPES = {
  fabricNode: TopologyNodeCard,
};
