'use client';

import React, { useMemo, useState } from 'react';
import Link from 'next/link';
import {
  AlertTriangle,
  Cable,
  ExternalLink,
  Plus,
  Server,
  Shield,
  Trash2,
  X,
} from 'lucide-react';
import {
  TopologyCableMediumSchema,
  TopologyConfigSchema,
  TopologyPeerRoleSchema,
  type DesiredState,
  type Interface,
  type TopologyCableEdge,
  type TopologyCanvasNode,
  type TopologyPortSpec,
} from '@axonwall/lib/schemas';
import type { TopologyFabricSnapshot } from '@/server/agent';
import {
  HEALTH_TONE_CLASSES,
  type FabricHealthEvaluation,
  type StagedK3sEdit,
  type StagedPeerEdit,
} from '../types';

interface InspectorDrawerProps {
  selectedNode: TopologyCanvasNode | null;
  selectedPortId: string | null;
  selectedEdge: TopologyCableEdge | null;
  nodes: TopologyCanvasNode[];
  health: FabricHealthEvaluation;
  fabric: TopologyFabricSnapshot | null;
  draftState: DesiredState | null;
  onUpdateNode: (node: TopologyCanvasNode) => void;
  onDeleteNode: (nodeId: string) => void;
  onUpdateEdge: (edge: TopologyCableEdge) => void;
  onDeleteEdge: (edgeId: string) => void;
  onStageLocalState: (updater: (prev: DesiredState) => DesiredState) => void;
  onStageK3sEdit: (edit: StagedK3sEdit) => void;
  onStagePeerEdit: (edit: StagedPeerEdit) => void;
  onClose: () => void;
}

export function InspectorDrawer({
  selectedNode,
  selectedPortId,
  selectedEdge,
  nodes,
  health,
  fabric,
  draftState,
  onUpdateNode,
  onDeleteNode,
  onUpdateEdge,
  onDeleteEdge,
  onStageLocalState,
  onStageK3sEdit,
  onStagePeerEdit,
  onClose,
}: InspectorDrawerProps) {
  const [newPortName, setNewPortName] = useState('');
  const [newPortKind, setNewPortKind] = useState<TopologyPortSpec['kind']>('physical-nic');
  const [newPortSpeed, setNewPortSpeed] = useState('1000');
  const [crdYaml, setCrdYaml] = useState('');
  const [scaleReplicasInput, setScaleReplicasInput] = useState('');
  const [nodeRolesInput, setNodeRolesInput] = useState('');
  const [peerDraftHostname, setPeerDraftHostname] = useState('');

  const localHostId = useMemo(() => {
    const raw = (fabric?.local?.localHostId || draftState?.system?.hostname || 'axonwall-local')
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, '-')
      .replace(/^-+|-+$/g, '');
    return `host-${raw || 'node'}`;
  }, [fabric?.local?.localHostId, draftState?.system?.hostname]);

  const matchingLibreAlerts = useMemo(() => {
    if (!selectedNode || !fabric?.librenms?.alerts) return [];
    const hostKey = (selectedNode.hostRef || selectedNode.label).toLowerCase();
    return fabric.librenms.alerts.filter(
      (a) =>
        a.deviceHostname.toLowerCase().includes(hostKey) ||
        hostKey.includes(a.deviceHostname.toLowerCase()),
    );
  }, [selectedNode, fabric?.librenms?.alerts]);

  if (!selectedNode && !selectedEdge) {
    return null;
  }

  // Cable / Edge Inspector
  if (selectedEdge) {
    const ch = health.cableHealth[selectedEdge.id];
    const tone = ch?.status ?? 'yellow';
    const toneStyle = HEALTH_TONE_CLASSES[tone];
    const srcNode = nodes.find((n) => n.id === selectedEdge.sourceNodeId);
    const dstNode = nodes.find((n) => n.id === selectedEdge.targetNodeId);

    return (
      <aside className="w-[380px] shrink-0 h-full bg-slate-950 border-l border-slate-800 flex flex-col overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between gap-2 bg-slate-900">
          <div className="flex items-center gap-2 min-w-0">
            <Cable className="w-4 h-4 text-sky-400 shrink-0" />
            <div className="min-w-0">
              <div className="text-sm font-semibold text-white truncate">
                {selectedEdge.cableLabel || selectedEdge.id}
              </div>
              <div className="text-[11px] font-mono text-slate-400 truncate">
                {srcNode?.label || selectedEdge.sourceNodeId}:{selectedEdge.sourcePortId} →{' '}
                {dstNode?.label || selectedEdge.targetNodeId}:{selectedEdge.targetPortId}
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
            aria-label="Close inspector"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-4 space-y-4 overflow-y-auto flex-1 text-xs">
          <div className={`px-3 py-2 rounded-lg border ${toneStyle.border} ${toneStyle.badgeBg}`}>
            <div className={`font-semibold uppercase tracking-wide text-[11px] ${toneStyle.text}`}>
              {tone} {ch?.verifiedBy ? `(${ch.verifiedBy})` : ''}
            </div>
            <div className="text-slate-300 mt-0.5">{ch?.reason || 'No telemetry check recorded'}</div>
          </div>

          <div className="space-y-3">
            <label className="block">
              <span className="text-slate-400 font-medium block mb-1">Cable / Link Label</span>
              <input
                type="text"
                value={selectedEdge.cableLabel || ''}
                onChange={(e) => onUpdateEdge({ ...selectedEdge, cableLabel: e.target.value })}
                placeholder="e.g. Uplink CAT6A-01"
                className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono focus:outline-none focus:border-sky-500"
              />
            </label>

            <div className="grid grid-cols-2 gap-2">
              <label className="block">
                <span className="text-slate-400 font-medium block mb-1">Medium</span>
                <select
                  value={selectedEdge.medium}
                  onChange={(e) =>
                    onUpdateEdge({
                      ...selectedEdge,
                      medium: e.target.value as TopologyCableEdge['medium'],
                    })
                  }
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                >
                  {TopologyCableMediumSchema.options.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
              </label>

              <label className="block">
                <span className="text-slate-400 font-medium block mb-1">Status</span>
                <select
                  value={selectedEdge.status}
                  onChange={(e) =>
                    onUpdateEdge({
                      ...selectedEdge,
                      status: e.target.value as TopologyCableEdge['status'],
                    })
                  }
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                >
                  <option value="planned">planned</option>
                  <option value="installed">installed</option>
                  <option value="virtual">virtual</option>
                </select>
              </label>
            </div>

            <div className="grid grid-cols-3 gap-2">
              <label className="block">
                <span className="text-slate-400 font-medium block mb-1">Speed (Mbps)</span>
                <input
                  type="number"
                  min={1}
                  value={selectedEdge.speedMbps ?? ''}
                  onChange={(e) =>
                    onUpdateEdge({
                      ...selectedEdge,
                      speedMbps: e.target.value ? Number(e.target.value) : undefined,
                    })
                  }
                  placeholder="1000"
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>

              <label className="block">
                <span className="text-slate-400 font-medium block mb-1">Length (m)</span>
                <input
                  type="number"
                  min={0}
                  step="0.5"
                  value={selectedEdge.lengthMeters ?? ''}
                  onChange={(e) =>
                    onUpdateEdge({
                      ...selectedEdge,
                      lengthMeters: e.target.value ? Number(e.target.value) : undefined,
                    })
                  }
                  placeholder="2.0"
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>

              <label className="block">
                <span className="text-slate-400 font-medium block mb-1">MTU</span>
                <input
                  type="number"
                  min={68}
                  max={65535}
                  value={selectedEdge.mtu ?? ''}
                  onChange={(e) =>
                    onUpdateEdge({
                      ...selectedEdge,
                      mtu: e.target.value ? Number(e.target.value) : undefined,
                    })
                  }
                  placeholder="1500"
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <label className="block">
                <span className="text-slate-400 font-medium block mb-1">Jacket Color</span>
                <input
                  type="text"
                  value={selectedEdge.color || ''}
                  onChange={(e) => onUpdateEdge({ ...selectedEdge, color: e.target.value })}
                  placeholder="blue / aqua / yellow"
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>

              <label className="block">
                <span className="text-slate-400 font-medium block mb-1">VLAN IDs (CSV)</span>
                <input
                  type="text"
                  value={selectedEdge.vlanIds.join(', ')}
                  onChange={(e) => {
                    const vlans = e.target.value
                      .split(',')
                      .map((v) => Number(v.trim()))
                      .filter((n) => Number.isInteger(n) && n >= 1 && n <= 4094);
                    onUpdateEdge({ ...selectedEdge, vlanIds: vlans });
                  }}
                  placeholder="10, 20"
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>
            </div>

            <label className="block">
              <span className="text-slate-400 font-medium block mb-1">Physical Routing / Rack Notes</span>
              <textarea
                rows={3}
                value={selectedEdge.notes || ''}
                onChange={(e) => onUpdateEdge({ ...selectedEdge, notes: e.target.value })}
                placeholder="Patch Panel J04 -> Switch Port 12..."
                className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
              />
            </label>
          </div>
        </div>

        <div className="px-4 py-3 border-t border-slate-800 flex justify-between items-center bg-slate-900/60">
          <button
            type="button"
            onClick={() => onDeleteEdge(selectedEdge.id)}
            className="px-3 py-1.5 rounded bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/40 text-rose-300 text-xs font-medium flex items-center gap-1.5"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Remove Cable
          </button>
          <span className="text-[11px] font-mono text-slate-500">ID: {selectedEdge.id}</span>
        </div>
      </aside>
    );
  }

  // Node Inspector
  if (!selectedNode) return null;

  const nh = health.nodeHealth[selectedNode.id];
  const tone = nh?.status ?? 'yellow';
  const toneStyle = HEALTH_TONE_CLASSES[tone];
  const selectedPort =
    selectedNode.ports.find((p) => p.id === selectedPortId) ?? selectedNode.ports[0] ?? null;

  // Match Local Interface in Draft DesiredState
  const isLocalHost = selectedNode.id === localHostId;
  const matchedLocalIf: Interface | undefined =
    isLocalHost && selectedPort
      ? draftState?.interfaces.find(
          (i) => (i.device || i.name) === selectedPort.id || i.name === selectedPort.id,
        )
      : undefined;

  // Match Peer entry in draftState.topology.peers
  const peerIdFromMeta =
    typeof selectedNode.metadata?.peerId === 'string'
      ? selectedNode.metadata.peerId
      : selectedNode.id.startsWith('peer-')
        ? selectedNode.id.slice(5)
        : undefined;
  const matchedPeer = peerIdFromMeta
    ? draftState?.topology?.peers?.find((p) => p.id === peerIdFromMeta)
    : undefined;

  // Match K3s metadata
  const k3sKind = typeof selectedNode.metadata?.kind === 'string' ? selectedNode.metadata.kind : '';
  const k3sNs = typeof selectedNode.metadata?.namespace === 'string' ? selectedNode.metadata.namespace : 'default';
  const k3sName =
    typeof selectedNode.metadata?.name === 'string'
      ? selectedNode.metadata.name
      : selectedNode.hostRef || selectedNode.label;
  const k3sNodeName =
    typeof selectedNode.metadata?.nodeName === 'string' ? selectedNode.metadata.nodeName : '';

  const handleAddPort = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = newPortName.trim();
    if (!clean) return;
    const id = clean.toLowerCase().replace(/[^a-z0-9._-]+/g, '-');
    if (selectedNode.ports.some((p) => p.id === id)) return;
    const speedNum = Number(newPortSpeed);
    onUpdateNode({
      ...selectedNode,
      ports: [
        ...selectedNode.ports,
        {
          id,
          name: clean,
          kind: newPortKind,
          speedMbps: Number.isFinite(speedNum) && speedNum > 0 ? speedNum : undefined,
          vlanIds: [],
          planned: !selectedNode.managed,
        },
      ],
    });
    setNewPortName('');
  };

  return (
    <aside className="w-[380px] shrink-0 h-full bg-slate-950 border-l border-slate-800 flex flex-col overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between gap-2 bg-slate-900">
        <div className="flex items-center gap-2 min-w-0">
          <Server className="w-4 h-4 text-sky-400 shrink-0" />
          <div className="min-w-0">
            <div className="text-sm font-semibold text-white truncate">{selectedNode.label}</div>
            <div className="text-[11px] font-mono text-slate-400 uppercase truncate">
              {selectedNode.kind} · {selectedNode.layer}
            </div>
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
          aria-label="Close inspector"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-4 space-y-4 overflow-y-auto flex-1 text-xs">
        {/* Node Health Summary */}
        <div className={`px-3 py-2 rounded-lg border ${toneStyle.border} ${toneStyle.badgeBg}`}>
          <div className={`font-semibold uppercase tracking-wide text-[11px] ${toneStyle.text}`}>
            Health: {tone}
          </div>
          <div className="text-slate-300 mt-0.5">{nh?.reason || 'No telemetry probe yet'}</div>
        </div>

        {/* Active LibreNMS Alerts on Node */}
        {matchingLibreAlerts.length > 0 && (
          <div className="px-3 py-2 rounded-lg border border-rose-500/40 bg-rose-500/10 space-y-1.5">
            <div className="flex items-center justify-between text-rose-300 font-semibold">
              <span className="flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" />
                {matchingLibreAlerts.length} Active LibreNMS Alert(s)
              </span>
              <Link
                href="/services/librenms"
                className="text-[11px] text-sky-300 hover:underline flex items-center gap-1"
              >
                Open <ExternalLink className="w-3 h-3" />
              </Link>
            </div>
            {matchingLibreAlerts.slice(0, 3).map((a) => (
              <div key={a.id} className="text-[11px] font-mono text-rose-200/90 truncate">
                [{a.severity}] {a.rule}: {a.message}
              </div>
            ))}
          </div>
        )}

        {/* Basic Canvas Identity */}
        <div className="space-y-2.5 pb-3 border-b border-slate-800/80">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Canvas Object
          </div>
          <label className="block">
            <span className="text-slate-400 block mb-1">Display Label</span>
            <input
              type="text"
              value={selectedNode.label}
              onChange={(e) => onUpdateNode({ ...selectedNode, label: e.target.value })}
              className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white"
            />
          </label>
          <label className="block">
            <span className="text-slate-400 block mb-1">Host / Resource Ref</span>
            <input
              type="text"
              value={selectedNode.hostRef || ''}
              onChange={(e) => onUpdateNode({ ...selectedNode, hostRef: e.target.value })}
              placeholder="Hostname or resource identifier"
              className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
            />
          </label>
        </div>

        {/* Ports & Selected Port Inspector */}
        <div className="space-y-2.5 pb-3 border-b border-slate-800/80">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Ports ({selectedNode.ports.length})
            </span>
          </div>

          {selectedPort && (
            <div className="p-2.5 rounded bg-slate-900 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono font-semibold text-white">{selectedPort.name}</span>
                <span className="text-[10px] font-mono text-slate-400">
                  {selectedPort.planned ? 'planned' : 'active'} · {selectedPort.kind}
                </span>
              </div>
              <div className="text-[11px] text-slate-400">
                {health.portHealth[`${selectedNode.id}:${selectedPort.id}`]?.reason ||
                  'Click any port row on the node card to inspect it.'}
              </div>
            </div>
          )}

          {/* Add Planned / Switch / Patch Port */}
          <form onSubmit={handleAddPort} className="grid grid-cols-12 gap-1.5 items-center">
            <input
              type="text"
              value={newPortName}
              onChange={(e) => setNewPortName(e.target.value)}
              placeholder="Port name (e.g. sfp2)"
              className="col-span-5 px-2 py-1 rounded bg-slate-900 border border-slate-700 text-white font-mono text-[11px]"
            />
            <select
              value={newPortKind}
              onChange={(e) => setNewPortKind(e.target.value as TopologyPortSpec['kind'])}
              className="col-span-4 px-1.5 py-1 rounded bg-slate-900 border border-slate-700 text-white font-mono text-[11px]"
            >
              <option value="physical-nic">physical-nic</option>
              <option value="sfp">sfp</option>
              <option value="switch-port">switch-port</option>
              <option value="wan-uplink">wan-uplink</option>
              <option value="vlan-if">vlan-if</option>
              <option value="tunnel">tunnel</option>
            </select>
            <input
              type="number"
              min={1}
              value={newPortSpeed}
              onChange={(e) => setNewPortSpeed(e.target.value)}
              title="Speed (Mbps)"
              className="col-span-2 px-1.5 py-1 rounded bg-slate-900 border border-slate-700 text-white font-mono text-[11px]"
            />
            <button
              type="submit"
              className="col-span-1 p-1.5 rounded bg-sky-600 hover:bg-sky-500 text-white flex items-center justify-center"
              title="Add Port"
            >
              <Plus className="w-3.5 h-3.5" />
            </button>
          </form>
        </div>

        {/* Direct Local Interface Configuration -> Staged DesiredState */}
        {matchedLocalIf && (
          <div className="space-y-2.5 pb-3 border-b border-slate-800/80">
            <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-emerald-400">
              <Shield className="w-3.5 h-3.5" />
              Stage Local Interface ({matchedLocalIf.name} / {matchedLocalIf.device})
            </div>
            <label className="block">
              <span className="text-slate-400 block mb-1">IPv4 Address / CIDR</span>
              <input
                type="text"
                value={matchedLocalIf.ipv4Address || ''}
                onChange={(e) =>
                  onStageLocalState((prev) => ({
                    ...prev,
                    interfaces: prev.interfaces.map((i) =>
                      i.name === matchedLocalIf.name ? { ...i, ipv4Address: e.target.value } : i,
                    ),
                  }))
                }
                placeholder="10.80.0.1/24"
                className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
              />
            </label>
            <div className="grid grid-cols-2 gap-2">
              <label className="block">
                <span className="text-slate-400 block mb-1">MTU</span>
                <input
                  type="number"
                  min={576}
                  max={65535}
                  value={matchedLocalIf.mtu ?? 1500}
                  onChange={(e) =>
                    onStageLocalState((prev) => ({
                      ...prev,
                      interfaces: prev.interfaces.map((i) =>
                        i.name === matchedLocalIf.name
                          ? { ...i, mtu: Math.max(576, Number(e.target.value) || 1500) }
                          : i,
                      ),
                    }))
                  }
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>
              <label className="flex items-center gap-2 pt-5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={matchedLocalIf.enabled}
                  onChange={(e) =>
                    onStageLocalState((prev) => ({
                      ...prev,
                      interfaces: prev.interfaces.map((i) =>
                        i.name === matchedLocalIf.name ? { ...i, enabled: e.target.checked } : i,
                      ),
                    }))
                  }
                  className="accent-sky-500"
                />
                <span className="text-slate-200">Interface Enabled</span>
              </label>
            </div>
          </div>
        )}

        {/* WireGuard Local Config Stage */}
        {selectedNode.id === 'vpn-wireguard' && draftState?.wireguard && (
          <div className="space-y-2.5 pb-3 border-b border-slate-800/80">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-violet-400">
              Stage WireGuard Config
            </div>
            <div className="grid grid-cols-2 gap-2">
              <label className="block">
                <span className="text-slate-400 block mb-1">Tunnel CIDR</span>
                <input
                  type="text"
                  value={draftState.wireguard.address}
                  onChange={(e) =>
                    onStageLocalState((prev) => ({
                      ...prev,
                      wireguard: { ...(prev.wireguard ?? { enabled: true, listenPort: 51820, peers: [] }), address: e.target.value },
                    }))
                  }
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>
              <label className="block">
                <span className="text-slate-400 block mb-1">Listen Port</span>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={draftState.wireguard.listenPort}
                  onChange={(e) =>
                    onStageLocalState((prev) => ({
                      ...prev,
                      wireguard: {
                        ...(prev.wireguard ?? { enabled: true, address: '10.10.0.1/24', peers: [] }),
                        listenPort: Number(e.target.value) || 51820,
                      },
                    }))
                  }
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>
            </div>
          </div>
        )}

        {/* Remote Axonwall Peer Host Configuration */}
        {matchedPeer && (
          <div className="space-y-2.5 pb-3 border-b border-slate-800/80">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-sky-400">
              Peer Axonwall Host Connection
            </div>
            <div className="grid grid-cols-2 gap-2">
              <label className="block">
                <span className="text-slate-400 block mb-1">Role</span>
                <select
                  value={matchedPeer.role}
                  onChange={(e) =>
                    onStageLocalState((prev) => ({
                      ...prev,
                      topology: {
                        ...(TopologyConfigSchema.parse(prev.topology ?? {})),
                        peers: (prev.topology?.peers ?? []).map((p) =>
                          p.id === matchedPeer.id
                            ? { ...p, role: e.target.value as (typeof matchedPeer)['role'] }
                            : p,
                        ),
                      },
                    }))
                  }
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                >
                  {TopologyPeerRoleSchema.options.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block">
                <span className="text-slate-400 block mb-1">Site / Rack</span>
                <input
                  type="text"
                  value={matchedPeer.site || ''}
                  onChange={(e) =>
                    onStageLocalState((prev) => ({
                      ...prev,
                      topology: {
                        ...(TopologyConfigSchema.parse(prev.topology ?? {})),
                        peers: (prev.topology?.peers ?? []).map((p) =>
                          p.id === matchedPeer.id ? { ...p, site: e.target.value } : p,
                        ),
                      },
                    }))
                  }
                  placeholder="dc-main"
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>
            </div>
            <label className="block">
              <span className="text-slate-400 block mb-1">Management API URL</span>
              <input
                type="url"
                value={matchedPeer.apiUrl}
                onChange={(e) =>
                  onStageLocalState((prev) => ({
                    ...prev,
                    topology: {
                      ...(TopologyConfigSchema.parse(prev.topology ?? {})),
                      peers: (prev.topology?.peers ?? []).map((p) =>
                        p.id === matchedPeer.id ? { ...p, apiUrl: e.target.value } : p,
                      ),
                    },
                  }))
                }
                className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
              />
            </label>
            <label className="block">
              <span className="text-slate-400 block mb-1">Bearer API Token</span>
              <input
                type="password"
                value={matchedPeer.apiToken || ''}
                onChange={(e) =>
                  onStageLocalState((prev) => ({
                    ...prev,
                    topology: {
                      ...(TopologyConfigSchema.parse(prev.topology ?? {})),
                      peers: (prev.topology?.peers ?? []).map((p) =>
                        p.id === matchedPeer.id ? { ...p, apiToken: e.target.value } : p,
                      ),
                    },
                  }))
                }
                placeholder="Keep masked or enter new token"
                className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
              />
            </label>
            <label className="block">
              <span className="text-slate-400 block mb-1">SHA-256 TLS Pin (Hex)</span>
              <input
                type="text"
                value={matchedPeer.tlsCertSha256 || ''}
                onChange={(e) =>
                  onStageLocalState((prev) => ({
                    ...prev,
                    topology: {
                      ...(TopologyConfigSchema.parse(prev.topology ?? {})),
                      peers: (prev.topology?.peers ?? []).map((p) =>
                        p.id === matchedPeer.id ? { ...p, tlsCertSha256: e.target.value } : p,
                      ),
                    },
                  }))
                }
                placeholder="64-hex SHA256 fingerprint"
                className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
              />
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={matchedPeer.useHaMtls}
                onChange={(e) =>
                  onStageLocalState((prev) => ({
                    ...prev,
                    topology: {
                      ...(TopologyConfigSchema.parse(prev.topology ?? {})),
                      peers: (prev.topology?.peers ?? []).map((p) =>
                        p.id === matchedPeer.id ? { ...p, useHaMtls: e.target.checked } : p,
                      ),
                    },
                  }))
                }
                className="accent-sky-500"
              />
              <span className="text-slate-200">Use Axonwall HA mTLS Identity</span>
            </label>

            <div className="pt-2 flex items-center gap-2">
              <input
                type="text"
                value={peerDraftHostname}
                onChange={(e) => setPeerDraftHostname(e.target.value)}
                placeholder="New remote hostname (optional)"
                className="flex-1 px-2 py-1 rounded bg-slate-900 border border-slate-700 text-white font-mono text-[11px]"
              />
              <button
                type="button"
                disabled={!peerDraftHostname.trim()}
                onClick={() => {
                  if (!draftState) return;
                  const hostNameNext = peerDraftHostname.trim();
                  onStagePeerEdit({
                    peerId: matchedPeer.id,
                    name: matchedPeer.name,
                    summary: `Set hostname=${hostNameNext} on peer ${matchedPeer.name}`,
                    state: {
                      ...draftState,
                      system: { ...draftState.system, hostname: hostNameNext },
                    },
                  });
                  setPeerDraftHostname('');
                }}
                className="px-2.5 py-1 rounded bg-sky-600/80 hover:bg-sky-500 disabled:opacity-40 text-white text-[11px] font-medium"
              >
                Stage Peer
              </button>
            </div>
          </div>
        )}

        {/* Kubernetes Live Resource Configuration */}
        {selectedNode.layer === 'k3s' && (
          <div className="space-y-2.5 pb-3 border-b border-slate-800/80">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400">
              Stage Kubernetes Mutation
            </div>

            {selectedNode.kind === 'k3s-workload' && (k3sKind === 'Deployment' || k3sKind === 'StatefulSet') && (
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min={0}
                  max={50}
                  value={scaleReplicasInput}
                  onChange={(e) => setScaleReplicasInput(e.target.value)}
                  placeholder={`Replicas (${String(selectedNode.metadata?.replicas ?? 1)})`}
                  className="flex-1 px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
                <button
                  type="button"
                  onClick={() => {
                    const num = Number(scaleReplicasInput);
                    if (!Number.isInteger(num) || num < 0) return;
                    onStageK3sEdit({
                      id: `k3s-scale-${k3sNs}-${k3sName}`,
                      kind: k3sKind,
                      name: k3sName,
                      namespace: k3sNs,
                      scaleReplicas: num,
                      summary: `Scale ${k3sKind} ${k3sNs}/${k3sName} -> ${num} replicas`,
                    });
                    setScaleReplicasInput('');
                  }}
                  className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
                >
                  Stage Scale
                </button>
              </div>
            )}

            {selectedNode.kind === 'k3s-node' && k3sNodeName && (
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={nodeRolesInput}
                  onChange={(e) => setNodeRolesInput(e.target.value)}
                  placeholder="Roles CSV (e.g. control-plane,worker)"
                  className="flex-1 px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
                <button
                  type="button"
                  onClick={() => {
                    const roles = nodeRolesInput
                      .split(',')
                      .map((r) => r.trim())
                      .filter(Boolean);
                    if (roles.length === 0) return;
                    onStageK3sEdit({
                      id: `k3s-role-${k3sNodeName}`,
                      kind: 'Node',
                      name: k3sNodeName,
                      nodeRoles: roles,
                      summary: `Label Node ${k3sNodeName} roles=[${roles.join(',')}]`,
                    });
                    setNodeRolesInput('');
                  }}
                  className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
                >
                  Stage Roles
                </button>
              </div>
            )}

            <label className="block">
              <span className="text-slate-400 block mb-1">Apply Ingress / CRD / NetworkPolicy YAML</span>
              <textarea
                rows={4}
                value={crdYaml}
                onChange={(e) => setCrdYaml(e.target.value)}
                placeholder={`apiVersion: traefik.io/v1alpha1\nkind: IngressRoute\nmetadata:\n  name: ${k3sName}\n  namespace: ${k3sNs}`}
                className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono text-[11px]"
              />
            </label>
            <button
              type="button"
              disabled={!crdYaml.trim()}
              onClick={() => {
                onStageK3sEdit({
                  id: `k3s-yaml-${Date.now()}`,
                  kind: k3sKind || 'Manifest',
                  name: k3sName,
                  namespace: k3sNs,
                  manifestYaml: crdYaml,
                  summary: `Apply YAML to ${k3sNs}/${k3sName}`,
                });
                setCrdYaml('');
              }}
              className="w-full py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 border border-slate-700 text-sky-300 font-medium"
            >
              Stage Kubernetes Manifest
            </button>
          </div>
        )}
      </div>

      <div className="px-4 py-3 border-t border-slate-800 flex items-center justify-between bg-slate-900/60">
        {!selectedNode.managed ? (
          <button
            type="button"
            onClick={() => onDeleteNode(selectedNode.id)}
            className="px-3 py-1.5 rounded bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/40 text-rose-300 text-xs font-medium flex items-center gap-1.5"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Remove Node
          </button>
        ) : (
          <span className="text-[11px] text-slate-400">Managed live object</span>
        )}
        <span className="text-[11px] font-mono text-slate-500 truncate max-w-[160px]">{selectedNode.id}</span>
      </div>
    </aside>
  );
}
