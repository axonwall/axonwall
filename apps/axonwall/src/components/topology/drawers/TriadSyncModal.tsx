'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { ArrowDownToLine, ArrowUpFromLine, ExternalLink, RefreshCw, X } from 'lucide-react';
import type { TopologyCableEdge, TopologyCanvasNode } from '@axonwall/lib/schemas';
import {
  syncTopologyLibreNmsAction,
  syncTopologyNetBoxAction,
  type TopologyFabricSnapshot,
} from '@/server/agent';
import type { FabricHealthEvaluation } from '../types';

interface TriadSyncModalProps {
  open: boolean;
  onClose: () => void;
  nodes: TopologyCanvasNode[];
  cables: TopologyCableEdge[];
  health: FabricHealthEvaluation;
  fabric: TopologyFabricSnapshot | null;
  onFabricRefresh: () => void;
  onPullMerged: (pulled: { nodes?: TopologyCanvasNode[]; cables?: TopologyCableEdge[] }) => void;
}

export function TriadSyncModal({
  open,
  onClose,
  nodes,
  cables,
  fabric,
  onFabricRefresh,
  onPullMerged,
}: TriadSyncModalProps) {
  const [overwriteLabels, setOverwriteLabels] = useState(false);
  const [busy, setBusy] = useState(false);
  const [output, setOutput] = useState<Record<string, unknown> | null>(null);

  if (!open) return null;

  const buildNetBoxPayload = () => {
    const nodeMap = new Map(nodes.map((n) => [n.id, n]));
    const devices = nodes
      .filter((n) => ['edge-ngfw', 'k3s-node', 'vault', 'nas', 'satellite', 'switch', 'patch-panel'].includes(n.kind))
      .map((n) => ({
        name: n.hostRef || n.label,
        role: n.kind,
        status: 'active',
        comments: `Synced from Topology Studio (${n.id})`,
      }));
    const cablePayloads = cables
      .filter((c) => c.layer === 'physical' || c.status === 'installed' || c.status === 'planned')
      .map((c) => {
        const src = nodeMap.get(c.sourceNodeId);
        const dst = nodeMap.get(c.targetNodeId);
        return {
          aDevice: src?.hostRef || src?.label || c.sourceNodeId,
          aInterface: src?.ports.find((p) => p.id === c.sourcePortId)?.name || c.sourcePortId,
          bDevice: dst?.hostRef || dst?.label || c.targetNodeId,
          bInterface: dst?.ports.find((p) => p.id === c.targetPortId)?.name || c.targetPortId,
          type: c.medium === 'fiber-om4' ? 'mmf-om4' : c.medium === 'fiber-os2' ? 'smf-os2' : 'cat6a',
          status: c.status === 'planned' ? 'planned' : 'connected',
          label: c.cableLabel || c.id,
          color: c.color,
          length: c.lengthMeters,
          lengthUnit: c.lengthMeters ? 'm' : undefined,
          comments: c.notes,
        };
      });
    return { devices, cables: cablePayloads };
  };

  const runNetBox = async (action: 'preview' | 'push' | 'pull') => {
    setBusy(true);
    try {
      const payload = buildNetBoxPayload();
      const res = await syncTopologyNetBoxAction({
        action,
        dryRun: action === 'preview',
        overwriteLabels,
        devices: payload.devices,
        cables: payload.cables,
      });
      setOutput(res);
      if (action === 'pull' && res && typeof res === 'object') {
        const inv = (res as Record<string, unknown>).inventory as
          | {
              devices?: Array<{ id?: number; name: string; role?: string; primaryIp?: string; comments?: string }>;
              interfaces?: Array<{ deviceName: string; name: string; mtu?: number }>;
              cables?: Array<{
                id?: number;
                aDevice: string;
                aInterface: string;
                bDevice: string;
                bInterface: string;
                type?: string;
                status?: string;
                label?: string;
                color?: string;
                length?: number;
                comments?: string;
              }>;
            }
          | undefined;
        if (inv) {
          const resolveNode = (devName: string): TopologyCanvasNode | undefined =>
            nodes.find(
              (n) =>
                (n.hostRef || '').toLowerCase() === devName.toLowerCase() ||
                n.label.toLowerCase() === devName.toLowerCase(),
            );
          const extraNodes: TopologyCanvasNode[] = [];
          const findOrSynthesizeNodeId = (devName: string): string => {
            const existing = resolveNode(devName);
            if (existing) return existing.id;
            const nbId = `nb-${devName.toLowerCase().replace(/[^a-z0-9._-]+/g, '-')}`;
            if (!extraNodes.some((n) => n.id === nbId)) {
              const devMeta = inv.devices?.find((d) => d.name.toLowerCase() === devName.toLowerCase());
              const devPorts = (inv.interfaces ?? [])
                .filter((i) => i.deviceName.toLowerCase() === devName.toLowerCase())
                .map((i) => ({
                  id: i.name,
                  name: i.name,
                  kind: 'physical-nic' as const,
                  mtu: i.mtu,
                  vlanIds: [],
                  planned: true,
                }));
              extraNodes.push({
                id: nbId,
                kind: 'generic-host',
                label: devName,
                hostRef: devName,
                layer: 'physical',
                managed: false,
                position: { x: 820 + extraNodes.length * 60, y: 140 + extraNodes.length * 80 },
                ports: devPorts.length > 0 ? devPorts : [{ id: 'eth0', name: 'eth0', kind: 'physical-nic', vlanIds: [], planned: true }],
                metadata: { netboxRole: devMeta?.role, primaryIp: devMeta?.primaryIp },
              });
            }
            return nbId;
          };

          for (const d of inv.devices ?? []) {
            if (!resolveNode(d.name)) {
              findOrSynthesizeNodeId(d.name);
            }
          }

          const pulledCables: TopologyCableEdge[] = (inv.cables ?? []).map((c, idx) => {
            const srcId = findOrSynthesizeNodeId(c.aDevice);
            const dstId = findOrSynthesizeNodeId(c.bDevice);
            const med: TopologyCableEdge['medium'] =
              c.type?.includes('om4') || c.type?.includes('mmf')
                ? 'fiber-om4'
                : c.type?.includes('smf') || c.type?.includes('os2')
                  ? 'fiber-os2'
                  : c.type?.includes('dac')
                    ? 'sfp-dac'
                    : 'rj45-cat6a';
            return {
              id: c.id ? `nb-cable-${c.id}` : `nb-cable-${idx}-${srcId}-${dstId}`,
              sourceNodeId: srcId,
              sourcePortId: c.aInterface || 'eth0',
              targetNodeId: dstId,
              targetPortId: c.bInterface || 'eth0',
              layer: 'physical',
              medium: med,
              status: c.status === 'planned' ? 'planned' : 'installed',
              cableLabel: c.label || `${c.aDevice}:${c.aInterface} -> ${c.bDevice}:${c.bInterface}`,
              color: c.color,
              lengthMeters: c.length,
              vlanIds: [],
              notes: c.comments,
            };
          });

          if (extraNodes.length > 0 || pulledCables.length > 0) {
            onPullMerged({ nodes: extraNodes, cables: pulledCables });
          }
        }
        onFabricRefresh();
      }
      if (action === 'push') onFabricRefresh();
    } finally {
      setBusy(false);
    }
  };

  const runLibreNms = async (action: 'preview' | 'push' | 'pull' | 'enroll') => {
    setBusy(true);
    try {
      const res = await syncTopologyLibreNmsAction({
        action,
        dryRun: action === 'preview',
        overwriteLabels,
      });
      setOutput(res);
      onFabricRefresh();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
      <div className="w-full max-w-3xl max-h-[85vh] bg-slate-950 border border-slate-800 rounded-xl shadow-2xl flex flex-col overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 bg-slate-900 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-white">NetBox &amp; LibreNMS Triad Synchronization</h2>
            <p className="text-xs text-slate-400">
              Bi-directional sync between Axonwall Topology Studio, NetBox DCIM/Cables &amp; LibreNMS SNMP/LLDP
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-4 overflow-y-auto flex-1 text-xs">
          <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={overwriteLabels}
              onChange={(e) => setOverwriteLabels(e.target.checked)}
              className="accent-sky-500"
            />
            <span>Overwrite existing external labels/notes on push (default preserves external edits &amp; reports conflicts)</span>
          </label>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* NetBox Panel */}
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-semibold text-white">NetBox DCIM / IPAM</div>
                  <div className="font-mono text-[11px] text-slate-400">
                    {fabric?.netbox?.available
                      ? `Connected · ${fabric.netbox.devices.length} devices · ${fabric.netbox.cables.length} cables`
                      : fabric?.netbox?.error || 'Not configured or unavailable'}
                  </div>
                </div>
                <Link href="/services/netbox" className="text-sky-400 hover:underline flex items-center gap-1">
                  Open <ExternalLink className="w-3 h-3" />
                </Link>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void runNetBox('preview')}
                  className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200"
                >
                  Preview Diff
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void runNetBox('push')}
                  className="px-2.5 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-white font-medium flex items-center gap-1"
                >
                  <ArrowUpFromLine className="w-3.5 h-3.5" />
                  Push to NetBox
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void runNetBox('pull')}
                  className="px-2.5 py-1.5 rounded bg-emerald-600/80 hover:bg-emerald-500 text-white font-medium flex items-center gap-1"
                >
                  <ArrowDownToLine className="w-3.5 h-3.5" />
                  Pull into Canvas
                </button>
              </div>
            </div>

            {/* LibreNMS Panel */}
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-semibold text-white">LibreNMS Telemetry</div>
                  <div className="font-mono text-[11px] text-slate-400">
                    {fabric?.librenms?.available
                      ? `Connected · ${fabric.librenms.devices.length} devices · ${fabric.librenms.links.length} LLDP links`
                      : fabric?.librenms?.error || 'Not configured or unavailable'}
                  </div>
                </div>
                <Link href="/services/librenms" className="text-sky-400 hover:underline flex items-center gap-1">
                  Open <ExternalLink className="w-3 h-3" />
                </Link>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void runLibreNms('preview')}
                  className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200"
                >
                  Preview Sync
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void runLibreNms('enroll')}
                  className="px-2.5 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-white font-medium flex items-center gap-1"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Enroll &amp; Sync
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void runLibreNms('pull')}
                  className="px-2.5 py-1.5 rounded bg-emerald-600/80 hover:bg-emerald-500 text-white font-medium flex items-center gap-1"
                >
                  <ArrowDownToLine className="w-3.5 h-3.5" />
                  Pull LLDP/Ports
                </button>
              </div>
            </div>
          </div>

          {output && (
            <div className="space-y-1.5">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Triad Sync Report
              </div>
              <pre className="p-3 rounded-lg bg-slate-900 border border-slate-800 font-mono text-[11px] text-slate-200 overflow-x-auto max-h-60">
                {JSON.stringify(output, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
