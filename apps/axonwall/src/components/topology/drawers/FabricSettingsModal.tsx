'use client';

import React, { useMemo, useState } from 'react';
import { Plus, Radio, Server, ShieldCheck, Trash2, X } from 'lucide-react';
import { compileLldpdConfig } from '@axonwall/lib/compile/topology';
import {
  TopologyConfigSchema,
  TopologyPeerRoleSchema,
  type DesiredState,
  type TopologyPeerHost,
} from '@axonwall/lib/schemas';

interface FabricSettingsModalProps {
  open: boolean;
  onClose: () => void;
  draftState: DesiredState | null;
  onStageLocalState: (updater: (prev: DesiredState) => DesiredState) => void;
}

export function FabricSettingsModal({
  open,
  onClose,
  draftState,
  onStageLocalState,
}: FabricSettingsModalProps) {
  const [peerName, setPeerName] = useState('');
  const [peerRole, setPeerRole] = useState<TopologyPeerHost['role']>('k3s-storage');
  const [peerUrl, setPeerUrl] = useState('https://10.80.0.200:2966');
  const [peerToken, setPeerToken] = useState('');
  const [peerPin, setPeerPin] = useState('');
  const [peerMtls, setPeerMtls] = useState(false);
  const [peerSite, setPeerSite] = useState('');
  const [peerRack, setPeerRack] = useState('');

  const topo = useMemo(
    () => TopologyConfigSchema.parse(draftState?.topology ?? {}),
    [draftState?.topology],
  );
  const lldpBundle = useMemo(() => compileLldpdConfig(draftState), [draftState]);

  if (!open) return null;

  const handleAddPeer = (e: React.FormEvent) => {
    e.preventDefault();
    const cleanName = peerName.trim();
    const cleanUrl = peerUrl.trim();
    if (!cleanName || !cleanUrl) return;
    const peerId = cleanName.toLowerCase().replace(/[^a-z0-9._-]+/g, '-');
    const newPeer: TopologyPeerHost = {
      id: `${peerId}-${Date.now().toString(36).slice(-4)}`,
      name: cleanName,
      role: peerRole,
      apiUrl: cleanUrl,
      apiToken: peerToken.trim() || undefined,
      tlsCertSha256: peerPin.trim() || undefined,
      useHaMtls: peerMtls,
      enabled: true,
      site: peerSite.trim() || undefined,
      rack: peerRack.trim() || undefined,
    };
    onStageLocalState((prev) => {
      const cur = TopologyConfigSchema.parse(prev.topology ?? {});
      return {
        ...prev,
        topology: {
          ...cur,
          peers: [...cur.peers, newPeer],
        },
      };
    });
    setPeerName('');
    setPeerToken('');
    setPeerPin('');
    setPeerSite('');
    setPeerRack('');
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
      <div className="w-full max-w-3xl max-h-[85vh] bg-slate-950 border border-slate-800 rounded-xl shadow-2xl flex flex-col overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 bg-slate-900 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-sky-400" />
            <div>
              <h2 className="text-sm font-semibold text-white">LLDP Discovery, Polling &amp; Multi-Host Peers</h2>
              <p className="text-xs text-slate-400">
                All staged changes below save into <code className="font-mono">topology.yaml</code> on Apply / Save
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-5 overflow-y-auto flex-1 text-xs">
          {/* Non-WAN LLDP Discovery */}
          <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <div>
                  <div className="font-semibold text-white">Local LLDP Neighbor Discovery (`lldpd`)</div>
                  <div className="text-slate-400">
                    Strictly excludes WAN interfaces to prevent upstream L2 topology leakage
                  </div>
                </div>
              </div>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={topo.lldp.enabled}
                  onChange={(e) =>
                    onStageLocalState((prev) => {
                      const cur = TopologyConfigSchema.parse(prev.topology ?? {});
                      return {
                        ...prev,
                        topology: {
                          ...cur,
                          lldp: { ...cur.lldp, enabled: e.target.checked, excludeWan: true },
                        },
                      };
                    })
                  }
                  className="accent-sky-500"
                />
                <span className="text-white font-medium">Enable `lldpd`</span>
              </label>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-[11px]">
              <div className="px-3 py-2 rounded bg-slate-950 border border-slate-800">
                <div className="text-slate-400 mb-1">Allowed Internal Interfaces</div>
                <div className="text-emerald-300">
                  {lldpBundle.allowedInterfaces.length > 0
                    ? lldpBundle.allowedInterfaces.join(', ')
                    : 'None detected'}
                </div>
              </div>
              <div className="px-3 py-2 rounded bg-slate-950 border border-slate-800">
                <div className="text-slate-400 mb-1">Strictly Excluded WAN Interfaces</div>
                <div className="text-amber-300">
                  {lldpBundle.excludedWanInterfaces.length > 0
                    ? lldpBundle.excludedWanInterfaces.join(', ')
                    : 'None'}
                </div>
              </div>
            </div>

            <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
              {lldpBundle.confContent}
            </pre>
          </div>

          {/* Adaptive Telemetry Polling */}
          <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
            <div className="font-semibold text-white">Adaptive Telemetry Polling</div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <label className="block">
                <span className="text-slate-400 block mb-1">Local Fast Probe (sec)</span>
                <input
                  type="number"
                  min={2}
                  max={300}
                  value={topo.polling.localIntervalSec}
                  onChange={(e) =>
                    onStageLocalState((prev) => {
                      const cur = TopologyConfigSchema.parse(prev.topology ?? {});
                      return {
                        ...prev,
                        topology: {
                          ...cur,
                          polling: {
                            ...cur.polling,
                            localIntervalSec: Math.max(2, Number(e.target.value) || 5),
                          },
                        },
                      };
                    })
                  }
                  className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
                />
              </label>
              <label className="block">
                <span className="text-slate-400 block mb-1">Full Fabric / Peers (sec)</span>
                <input
                  type="number"
                  min={5}
                  max={600}
                  value={topo.polling.peerIntervalSec}
                  onChange={(e) =>
                    onStageLocalState((prev) => {
                      const cur = TopologyConfigSchema.parse(prev.topology ?? {});
                      return {
                        ...prev,
                        topology: {
                          ...cur,
                          polling: {
                            ...cur.polling,
                            peerIntervalSec: Math.max(5, Number(e.target.value) || 10),
                          },
                        },
                      };
                    })
                  }
                  className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
                />
              </label>
              <label className="flex items-center gap-2 pt-5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={topo.polling.pauseWhenHidden}
                  onChange={(e) =>
                    onStageLocalState((prev) => {
                      const cur = TopologyConfigSchema.parse(prev.topology ?? {});
                      return {
                        ...prev,
                        topology: {
                          ...cur,
                          polling: { ...cur.polling, pauseWhenHidden: e.target.checked },
                        },
                      };
                    })
                  }
                  className="accent-sky-500"
                />
                <span className="text-slate-200">Pause when tab hidden</span>
              </label>
            </div>
          </div>

          {/* Peer Axonwall Hosts */}
          <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center gap-2 font-semibold text-white">
              <Server className="w-4 h-4 text-sky-400" />
              Peer Axonwall Hosts ({topo.peers.length})
            </div>

            {topo.peers.length > 0 && (
              <div className="space-y-2">
                {topo.peers.map((p) => (
                  <div
                    key={p.id}
                    className="px-3 py-2 rounded bg-slate-950 border border-slate-800 flex items-center justify-between gap-2"
                  >
                    <div className="min-w-0">
                      <div className="font-semibold text-white truncate">
                        {p.name} <span className="font-mono text-sky-400">[{p.role}]</span>
                      </div>
                      <div className="font-mono text-[11px] text-slate-400 truncate">
                        {p.apiUrl} {p.tlsCertSha256 ? `· pin:${p.tlsCertSha256.slice(0, 12)}...` : ''}
                        {p.useHaMtls ? ' · HA-mTLS' : ''}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        onStageLocalState((prev) => {
                          const cur = TopologyConfigSchema.parse(prev.topology ?? {});
                          return {
                            ...prev,
                            topology: {
                              ...cur,
                              peers: cur.peers.filter((item) => item.id !== p.id),
                            },
                          };
                        })
                      }
                      className="p-1.5 rounded hover:bg-rose-500/20 text-slate-400 hover:text-rose-300"
                      title="Remove peer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}

            <form onSubmit={handleAddPeer} className="grid grid-cols-1 md:grid-cols-2 gap-2.5 pt-2 border-t border-slate-800">
              <input
                type="text"
                value={peerName}
                onChange={(e) => setPeerName(e.target.value)}
                placeholder="Host name (e.g. vault-01)"
                className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white"
              />
              <select
                value={peerRole}
                onChange={(e) => setPeerRole(e.target.value as TopologyPeerHost['role'])}
                className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
              >
                {TopologyPeerRoleSchema.options.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
              <input
                type="url"
                value={peerUrl}
                onChange={(e) => setPeerUrl(e.target.value)}
                placeholder="https://10.80.0.200:2966"
                className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
              />
              <input
                type="password"
                value={peerToken}
                onChange={(e) => setPeerToken(e.target.value)}
                placeholder="Bearer API Token (optional if mTLS)"
                className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
              />
              <input
                type="text"
                value={peerPin}
                onChange={(e) => setPeerPin(e.target.value)}
                placeholder="SHA-256 TLS Pin (64-char hex)"
                className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
              />
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={peerSite}
                  onChange={(e) => setPeerSite(e.target.value)}
                  placeholder="Site"
                  className="w-1/2 px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white"
                />
                <input
                  type="text"
                  value={peerRack}
                  onChange={(e) => setPeerRack(e.target.value)}
                  placeholder="Rack"
                  className="w-1/2 px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white"
                />
              </div>
              <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={peerMtls}
                  onChange={(e) => setPeerMtls(e.target.checked)}
                  className="accent-sky-500"
                />
                <span>Use Axonwall HA mTLS</span>
              </label>
              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={!peerName.trim() || !peerUrl.trim()}
                  className="px-3.5 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white font-semibold flex items-center gap-1"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Add Peer Host
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
