'use client';

import React, { useEffect, useRef, useState } from 'react';
import { Database, FileBarChart, Globe, Play, Plus, Radio, Share2, Shield, Trash2 } from 'lucide-react';
import {
  NetFlowListenerProtocolSchema,
  type DesiredState,
  type NetFlowListener,
  type NetFlowReplicatorTarget,
  type NetFlowSelfExportTarget,
} from '@axonwall/lib/schemas';
import { injectNetFlowTestBurstAction, triggerNetFlowGeoIPUpdateAction } from '@/server/agent';
import { parseCsvTokens, resolveNetFlowDraftConfig } from '@/lib/state-preservation';

interface PipelineConfigTabProps {
  draftState: DesiredState | null;
  onUpdateDraft: (updater: (prev: DesiredState) => DesiredState) => void;
  onAfterInject: () => void;
}

export function PipelineConfigTab({
  draftState,
  onUpdateDraft,
  onAfterInject,
}: PipelineConfigTabProps) {
  const [burstProto, setBurstProto] = useState<'ipfix' | 'netflow9' | 'netflow5' | 'sflow5'>('ipfix');
  const [burstResult, setBurstResult] = useState<string | null>(null);
  const [injecting, setInjecting] = useState(false);

  // Add Listener Form
  const [lName, setLName] = useState('');
  const [lProto, setLProto] = useState<NetFlowListener['protocol']>('auto');
  const [lTrans, setLTrans] = useState<NetFlowListener['transport']>('udp');
  const [lPort, setLPort] = useState('4739');
  const [lAllowed, setLAllowed] = useState('');

  // Add Self-Export Target Form
  const [seName, setSeName] = useState('');
  const [seVer, setSeVer] = useState<NetFlowSelfExportTarget['version']>('ipfix');
  const [seTrans, setSeTrans] = useState<NetFlowSelfExportTarget['transport']>('udp');
  const [seHost, setSeHost] = useState('');
  const [sePort, setSePort] = useState('2055');
  const [seServerName, setSeServerName] = useState('');
  const [seInsecureSkipVerify, setSeInsecureSkipVerify] = useState(false);
  const [geoUpdating, setGeoUpdating] = useState(false);
  const [geoMsg, setGeoMsg] = useState<string | null>(null);

  // Add Replicator Target Form
  const [repName, setRepName] = useState('');
  const [repHost, setRepHost] = useState('');
  const [repPort, setRepPort] = useState('2055');
  const [repExporters, setRepExporters] = useState('');
  const [repRate, setRepRate] = useState('0');

  const cfg = resolveNetFlowDraftConfig(draftState?.netflow);
  const [internalCidrsText, setInternalCidrsText] = useState(() => cfg.enrichment.internalCidrs.join(', '));
  const internalCidrsTextRef = useRef(internalCidrsText);
  internalCidrsTextRef.current = internalCidrsText;

  useEffect(() => {
    const externalCsv = cfg.enrichment.internalCidrs.join(',');
    const localCsv = parseCsvTokens(internalCidrsTextRef.current).join(',');
    if (externalCsv !== localCsv) {
      setInternalCidrsText(cfg.enrichment.internalCidrs.join(', '));
    }
  }, [cfg.enrichment.internalCidrs]);

  const handleTestBurst = async () => {
    setInjecting(true);
    setBurstResult(null);
    try {
      const res = await injectNetFlowTestBurstAction(burstProto, 16);
      setBurstResult(
        res.success
          ? `Injected ${res.injected} synthetic ${burstProto.toUpperCase()} flows successfully.`
          : res.error || 'Injection failed.',
      );
      if (res.success) onAfterInject();
    } finally {
      setInjecting(false);
    }
  };

  return (
    <div className="space-y-6 text-xs">
      {/* Pipeline Mode & Multi-Node Identity */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
        <div>
          <h3 className="text-sm font-semibold text-white">Pipeline Mode &amp; Node Identity</h3>
          <p className="text-slate-400 mt-0.5">
            Select whether this host collects flows, exports eBPF/conntrack IPFIX upstream (edge offload), or runs both.
          </p>
        </div>
        <label className="block">
          <span className="text-slate-400 block mb-1">Operating Mode</span>
          <select
            value={cfg.mode ?? 'both'}
            onChange={(e) =>
              onUpdateDraft((prev) => {
                const cur = resolveNetFlowDraftConfig(prev.netflow);
                return {
                  ...prev,
                  netflow: { ...cur, mode: e.target.value as 'collector' | 'exporter' | 'both' },
                };
              })
            }
            className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
          >
            <option value="both">both (Collect + Export)</option>
            <option value="exporter">exporter (Edge Offload Only)</option>
            <option value="collector">collector (Central Hub / K3s)</option>
          </select>
        </label>
        <label className="block">
          <span className="text-slate-400 block mb-1">Node ID Override (optional)</span>
          <input
            type="text"
            value={cfg.nodeId || ''}
            onChange={(e) =>
              onUpdateDraft((prev) => {
                const cur = resolveNetFlowDraftConfig(prev.netflow);
                return {
                  ...prev,
                  netflow: { ...cur, nodeId: e.target.value.trim() || undefined },
                };
              })
            }
            placeholder="e.g. edge-checkpoint1 (auto-hostname if empty)"
            className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
          />
        </label>
      </div>

      {/* Synthetic Pipeline Verification Burst */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-white">End-to-End Pipeline Verification Burst</h3>
          <p className="text-slate-400">
            Transmit wire-encoded synthetic flow datagrams into the collector to verify decoding, Zstd persistence &amp; FQL queries
          </p>
          {burstResult && <div className="font-mono text-emerald-300 mt-1">{burstResult}</div>}
        </div>
        <div className="flex items-center gap-2">
          <select
            value={burstProto}
            onChange={(e) => setBurstProto(e.target.value as typeof burstProto)}
            className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
          >
            <option value="ipfix">IPFIX (v10)</option>
            <option value="netflow9">NetFlow v9</option>
            <option value="netflow5">NetFlow v5</option>
            <option value="sflow5">sFlow v5</option>
          </select>
          <button
            type="button"
            disabled={injecting}
            onClick={() => void handleTestBurst()}
            className="px-3.5 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white font-semibold flex items-center gap-1.5"
          >
            <Play className="w-3.5 h-3.5" />
            {injecting ? 'Sending...' : 'Send Test Burst'}
          </button>
        </div>
      </div>

      {/* Multi-Protocol Collectors / Listeners */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center gap-2">
          <Radio className="w-4 h-4 text-sky-400" />
          <div>
            <h3 className="text-sm font-semibold text-white">Collector Socket Listeners ({cfg.listeners.length})</h3>
            <p className="text-slate-400">Bind multiple UDP/TCP listeners with kernel socket buffer tuning and exporter CIDR ACLs</p>
          </div>
        </div>

        <div className="space-y-2">
          {cfg.listeners.map((l) => (
            <div key={l.id} className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-2 font-mono">
              <div>
                <span className="font-semibold text-white">{l.name}</span> · {l.transport.toUpperCase()}{' '}
                {l.bindAddress}:{l.port} · {l.protocol} · {l.workers}w · rcvbuf {l.socketRecvBufferKB}KB
                {l.allowedExporters.length > 0 ? ` · ACL [${l.allowedExporters.join(', ')}]` : ''}
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={l.enabled}
                  onChange={(e) =>
                    onUpdateDraft((prev) => {
                      const cur = resolveNetFlowDraftConfig(prev.netflow);
                      return {
                        ...prev,
                        netflow: {
                          ...cur,
                          listeners: cur.listeners.map((item) =>
                            item.id === l.id ? { ...item, enabled: e.target.checked } : item,
                          ),
                        },
                      };
                    })
                  }
                  className="accent-sky-500"
                />
                <button
                  type="button"
                  onClick={() =>
                    onUpdateDraft((prev) => {
                      const cur = resolveNetFlowDraftConfig(prev.netflow);
                      return {
                        ...prev,
                        netflow: {
                          ...cur,
                          listeners: cur.listeners.filter((item) => item.id !== l.id),
                        },
                      };
                    })
                  }
                  className="p-1 rounded hover:bg-rose-500/20 text-slate-400 hover:text-rose-300"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-6 gap-2 pt-2 border-t border-slate-800">
          <input
            type="text"
            value={lName}
            onChange={(e) => setLName(e.target.value)}
            placeholder="Listener name (sFlow 6343)"
            className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white"
          />
          <select
            value={lProto}
            onChange={(e) => setLProto(e.target.value as NetFlowListener['protocol'])}
            className="px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
          >
            {NetFlowListenerProtocolSchema.options.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
          <select
            value={lTrans}
            onChange={(e) => setLTrans(e.target.value as NetFlowListener['transport'])}
            className="px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
          >
            <option value="udp">udp (SO_REUSEPORT)</option>
            <option value="tcp">tcp</option>
            <option value="tls">tls (TLS 1.3 mTLS)</option>
          </select>
          <input
            type="number"
            min={1}
            max={65535}
            value={lPort}
            onChange={(e) => setLPort(e.target.value)}
            placeholder="Port"
            className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
          />
          <input
            type="text"
            value={lAllowed}
            onChange={(e) => setLAllowed(e.target.value)}
            placeholder="Allowed CIDRs CSV"
            className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
          />
          <button
            type="button"
            disabled={!lName.trim()}
            onClick={() => {
              const newL: NetFlowListener = {
                id: `nfl-${Date.now().toString(36)}`,
                name: lName.trim(),
                enabled: true,
                protocol: lProto,
                transport: lTrans,
                bindAddress: '0.0.0.0',
                port: Math.max(1, Math.min(65535, Number(lPort) || 6343)),
                socketRecvBufferKB: 8192,
                workers: 4,
                allowedExporters: lAllowed
                  .split(',')
                  .map((s) => s.trim())
                  .filter(Boolean),
                dropUnknownTemplates: false,
                ...(lTrans === 'tls'
                  ? {
                      tls: {
                        useHaPki: true,
                        requireClientCert: true,
                        certPath: '',
                        keyPath: '',
                        caPath: '',
                      },
                    }
                  : {}),
              };
              onUpdateDraft((prev) => {
                const cur = resolveNetFlowDraftConfig(prev.netflow);
                return { ...prev, netflow: { ...cur, listeners: [...cur.listeners, newL] } };
              });
              setLName('');
              setLAllowed('');
            }}
            className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white font-semibold flex items-center justify-center gap-1"
          >
            <Plus className="w-3.5 h-3.5" />
            Add Listener
          </button>
        </div>
      </div>

      {/* Axonwall Self-Exporter + Raw UDP Replicator */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Local eBPF / Conntrack Self-Exporter</h3>
            <label className="flex items-center gap-2 cursor-pointer text-slate-200">
              <input
                type="checkbox"
                checked={cfg.selfExport.enabled}
                onChange={(e) =>
                  onUpdateDraft((prev) => {
                    const cur = resolveNetFlowDraftConfig(prev.netflow);
                    return {
                      ...prev,
                      netflow: { ...cur, selfExport: { ...cur.selfExport, enabled: e.target.checked } },
                    };
                  })
                }
                className="accent-sky-500"
              />
              Enabled
            </label>
          </div>
          <div className="space-y-1.5 font-mono">
            {cfg.selfExport.targets.map((t) => (
              <div key={t.id} className="px-3 py-2 rounded bg-slate-950 border border-slate-800 flex items-center justify-between gap-2">
                <div>
                  <div>
                    {t.name} · {t.version.toUpperCase()} ({t.transport.toUpperCase()}) → {t.host}:{t.port}
                  </div>
                  {t.transport === 'tls' && t.tls && (
                    <div className="text-[11px] text-slate-400">
                      TLS {t.tls.useHaPki ? 'HA-PKI mTLS' : 'custom'}
                      {t.tls.serverName ? ` · SNI=${t.tls.serverName}` : ''}
                      {t.tls.insecureSkipVerify ? ' · insecureSkipVerify=true' : ''}
                    </div>
                  )}
                </div>
                <button
                  type="button"
                  onClick={() =>
                    onUpdateDraft((prev) => {
                      const cur = resolveNetFlowDraftConfig(prev.netflow);
                      return {
                        ...prev,
                        netflow: {
                          ...cur,
                          selfExport: {
                            ...cur.selfExport,
                            targets: cur.selfExport.targets.filter((x) => x.id !== t.id),
                          },
                        },
                      };
                    })
                  }
                  className="text-slate-400 hover:text-rose-300"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
          {seTrans === 'tls' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-2">
              <input
                type="text"
                value={seServerName}
                onChange={(e) => setSeServerName(e.target.value)}
                placeholder="TLS SNI serverName (optional, e.g. collector.k3s.local)"
                className="px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
              />
              <label className="flex items-center gap-2 text-slate-300 cursor-pointer px-2">
                <input
                  type="checkbox"
                  checked={seInsecureSkipVerify}
                  onChange={(e) => setSeInsecureSkipVerify(e.target.checked)}
                  className="accent-sky-500"
                />
                <span>Allow self-signed cert (`insecureSkipVerify`)</span>
              </label>
            </div>
          )}
          <div className="grid grid-cols-5 gap-2 pt-2 border-t border-slate-800">
            <input
              type="text"
              value={seName}
              onChange={(e) => setSeName(e.target.value)}
              placeholder="Target name"
              className="px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white"
            />
            <select
              value={seVer}
              onChange={(e) => setSeVer(e.target.value as NetFlowSelfExportTarget['version'])}
              className="px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            >
              <option value="ipfix">ipfix</option>
              <option value="netflow9">netflow9</option>
            </select>
            <select
              value={seTrans}
              onChange={(e) => setSeTrans(e.target.value as NetFlowSelfExportTarget['transport'])}
              className="px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            >
              <option value="udp">udp</option>
              <option value="tcp">tcp</option>
              <option value="tls">tls (mTLS)</option>
            </select>
            <input
              type="text"
              value={seHost}
              onChange={(e) => setSeHost(e.target.value)}
              placeholder="Host e.g. 10.80.0.50"
              className="px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
            <div className="flex gap-1">
              <input
                type="number"
                value={sePort}
                onChange={(e) => setSePort(e.target.value)}
                className="w-16 px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
              />
              <button
                type="button"
                disabled={!seName.trim() || !seHost.trim()}
                onClick={() => {
                  const nextTgt: NetFlowSelfExportTarget = {
                    id: `se-${Date.now().toString(36)}`,
                    name: seName.trim(),
                    enabled: true,
                    version: seVer,
                    host: seHost.trim(),
                    port: Number(sePort) || 2055,
                    transport: seTrans,
                    interfaces: [],
                    activeTimeoutSec: 60,
                    inactiveTimeoutSec: 15,
                    templateRefreshSec: 300,
                    samplingRate: 1,
                    observationDomainId: 1,
                    ...(seTrans === 'tls'
                      ? {
                          tls: {
                            useHaPki: true,
                            requireClientCert: true,
                            certPath: '',
                            keyPath: '',
                            caPath: '',
                            serverName: seServerName.trim() || undefined,
                            insecureSkipVerify: seInsecureSkipVerify,
                          },
                        }
                      : {}),
                  };
                  onUpdateDraft((prev) => {
                    const cur = resolveNetFlowDraftConfig(prev.netflow);
                    return {
                      ...prev,
                      netflow: {
                        ...cur,
                        selfExport: { ...cur.selfExport, targets: [...cur.selfExport.targets, nextTgt] },
                      },
                    };
                  });
                  setSeName('');
                  setSeHost('');
                  setSeServerName('');
                  setSeInsecureSkipVerify(false);
                }}
                className="flex-1 px-2 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white font-semibold"
              >
                +
              </button>
            </div>
          </div>
        </div>

        {/* UDP Fan-Out Replicator */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white flex items-center gap-1.5">
              <Share2 className="w-4 h-4 text-emerald-400" />
              Raw Flow Replicator (Fan-Out Mirror)
            </h3>
            <label className="flex items-center gap-2 cursor-pointer text-slate-200">
              <input
                type="checkbox"
                checked={cfg.replicator.enabled}
                onChange={(e) =>
                  onUpdateDraft((prev) => {
                    const cur = resolveNetFlowDraftConfig(prev.netflow);
                    return {
                      ...prev,
                      netflow: { ...cur, replicator: { ...cur.replicator, enabled: e.target.checked } },
                    };
                  })
                }
                className="accent-sky-500"
              />
              Enabled
            </label>
          </div>
          <div className="space-y-1.5 font-mono">
            {cfg.replicator.targets.map((r) => (
              <div key={r.id} className="px-3 py-2 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                <span>
                  {r.name} → {r.destinationHost}:{r.destinationPort}
                  {r.rateLimitPps > 0 ? ` (max ${r.rateLimitPps} pps)` : ''}
                </span>
                <button
                  type="button"
                  onClick={() =>
                    onUpdateDraft((prev) => {
                      const cur = resolveNetFlowDraftConfig(prev.netflow);
                      return {
                        ...prev,
                        netflow: {
                          ...cur,
                          replicator: {
                            ...cur.replicator,
                            targets: cur.replicator.targets.filter((x) => x.id !== r.id),
                          },
                        },
                      };
                    })
                  }
                  className="text-slate-400 hover:text-rose-300"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
          <div className="grid grid-cols-4 gap-2 pt-2 border-t border-slate-800">
            <input
              type="text"
              value={repName}
              onChange={(e) => setRepName(e.target.value)}
              placeholder="SIEM / Mirror name"
              className="px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white"
            />
            <input
              type="text"
              value={repHost}
              onChange={(e) => setRepHost(e.target.value)}
              placeholder="Dest IP"
              className="px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
            <input
              type="text"
              value={repExporters}
              onChange={(e) => setRepExporters(e.target.value)}
              placeholder="Exporter filter CSV"
              className="px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
            <div className="flex gap-1">
              <input
                type="number"
                value={repPort}
                onChange={(e) => setRepPort(e.target.value)}
                title="Port"
                className="w-16 px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
              />
              <button
                type="button"
                disabled={!repName.trim() || !repHost.trim()}
                onClick={() => {
                  const newRep: NetFlowReplicatorTarget = {
                    id: `rep-${Date.now().toString(36)}`,
                    name: repName.trim(),
                    enabled: true,
                    destinationHost: repHost.trim(),
                    destinationPort: Number(repPort) || 2055,
                    spoofSourceIp: false,
                    filterExporters: repExporters
                      .split(',')
                      .map((s) => s.trim())
                      .filter(Boolean),
                    filterProtocols: [],
                    rateLimitPps: Number(repRate) || 0,
                  };
                  onUpdateDraft((prev) => {
                    const cur = resolveNetFlowDraftConfig(prev.netflow);
                    return {
                      ...prev,
                      netflow: {
                        ...cur,
                        replicator: { ...cur.replicator, targets: [...cur.replicator.targets, newRep] },
                      },
                    };
                  });
                  setRepName('');
                  setRepHost('');
                  setRepExporters('');
                  setRepRate('0');
                }}
                className="flex-1 px-2 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white font-semibold"
              >
                +
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Storage + Enrichment Settings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 font-semibold text-white text-sm">
            <Database className="w-4 h-4 text-sky-400" />
            Chunk Storage, Retention &amp; ClickHouse
          </div>
          <div className="grid grid-cols-2 gap-3">
            <label className="block">
              <span className="text-slate-400 block mb-1">Storage Mode</span>
              <select
                value={cfg.storage.mode}
                onChange={(e) =>
                  onUpdateDraft((prev) => {
                    const cur = resolveNetFlowDraftConfig(prev.netflow);
                    return {
                      ...prev,
                      netflow: { ...cur, storage: { ...cur.storage, mode: e.target.value as typeof cfg.storage.mode } },
                    };
                  })
                }
                className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
              >
                <option value="local">local (Zstd/Gzip Chunks)</option>
                <option value="hybrid">hybrid (Local + ClickHouse)</option>
                <option value="clickhouse">clickhouse only</option>
              </select>
            </label>
            <label className="block">
              <span className="text-slate-400 block mb-1">Compression</span>
              <select
                value={cfg.storage.compression}
                onChange={(e) =>
                  onUpdateDraft((prev) => {
                    const cur = resolveNetFlowDraftConfig(prev.netflow);
                    return {
                      ...prev,
                      netflow: {
                        ...cur,
                        storage: { ...cur.storage, compression: e.target.value as typeof cfg.storage.compression },
                      },
                    };
                  })
                }
                className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
              >
                <option value="zstd">zstd</option>
                <option value="gzip">gzip</option>
                <option value="none">none</option>
              </select>
            </label>
            <label className="block">
              <span className="text-slate-400 block mb-1">Retention (Hours)</span>
              <input
                type="number"
                min={1}
                value={cfg.storage.retentionHours || ''}
                onChange={(e) => {
                  const v = e.target.value.trim();
                  const n = v === '' ? 0 : Number(v);
                  if (Number.isNaN(n)) return;
                  onUpdateDraft((prev) => {
                    const cur = resolveNetFlowDraftConfig(prev.netflow);
                    return {
                      ...prev,
                      netflow: { ...cur, storage: { ...cur.storage, retentionHours: Math.max(0, Math.trunc(n)) } },
                    };
                  });
                }}
                className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
              />
            </label>
            <label className="block">
              <span className="text-slate-400 block mb-1">Max Disk Quota (MB)</span>
              <input
                type="number"
                min={64}
                value={cfg.storage.maxDiskMB || ''}
                onChange={(e) => {
                  const v = e.target.value.trim();
                  const n = v === '' ? 0 : Number(v);
                  if (Number.isNaN(n)) return;
                  onUpdateDraft((prev) => {
                    const cur = resolveNetFlowDraftConfig(prev.netflow);
                    return {
                      ...prev,
                      netflow: { ...cur, storage: { ...cur.storage, maxDiskMB: Math.max(0, Math.trunc(n)) } },
                    };
                  });
                }}
                className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
              />
            </label>
          </div>
          <div className="pt-2 border-t border-slate-800 space-y-2">
            <label className="flex items-center gap-2 cursor-pointer text-slate-200">
              <input
                type="checkbox"
                checked={cfg.storage.clickhouse.enabled}
                onChange={(e) =>
                  onUpdateDraft((prev) => {
                    const cur = resolveNetFlowDraftConfig(prev.netflow);
                    return {
                      ...prev,
                      netflow: {
                        ...cur,
                        storage: { ...cur.storage, clickhouse: { ...cur.storage.clickhouse, enabled: e.target.checked } },
                      },
                    };
                  })
                }
                className="accent-sky-500"
              />
              Enable ClickHouse Historical Sink
            </label>
            {cfg.storage.clickhouse.enabled && (
              <div className="grid grid-cols-2 gap-2">
                <input
                  type="text"
                  value={cfg.storage.clickhouse.url}
                  onChange={(e) =>
                    onUpdateDraft((prev) => {
                      const cur = resolveNetFlowDraftConfig(prev.netflow);
                      return {
                        ...prev,
                        netflow: {
                          ...cur,
                          storage: { ...cur.storage, clickhouse: { ...cur.storage.clickhouse, url: e.target.value } },
                        },
                      };
                    })
                  }
                  placeholder="http://127.0.0.1:8123"
                  className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
                />
                <input
                  type="password"
                  value={cfg.storage.clickhouse.password || ''}
                  onChange={(e) =>
                    onUpdateDraft((prev) => {
                      const cur = resolveNetFlowDraftConfig(prev.netflow);
                      return {
                        ...prev,
                        netflow: {
                          ...cur,
                          storage: {
                            ...cur.storage,
                            clickhouse: { ...cur.storage.clickhouse, password: e.target.value },
                          },
                        },
                      };
                    })
                  }
                  placeholder="Password"
                  className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
                />
              </div>
            )}
          </div>
        </div>

        {/* Multi-Source Enrichment */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 font-semibold text-white text-sm">
            <Shield className="w-4 h-4 text-emerald-400" />
            Flow Enrichment &amp; Topology Overlay
          </div>
          <div className="grid grid-cols-2 gap-2">
            {(
              [
                ['reverseDns', 'Async Reverse DNS (PTR)'],
                ['keaDhcpLeases', 'Kea DHCPv4 Lease Map'],
                ['unboundOverrides', 'Unbound Host Overrides'],
                ['librenmsIfNames', 'LibreNMS SNMP ifNames'],
                ['netboxInventory', 'NetBox DCIM/IPAM'],
                ['k3sPodServiceTagging', 'K3s Pod/Service Tags'],
                ['frrBgpLookup', 'FRR BGP AS-Path'],
                ['natConntrackCorrelation', 'NAT / CGNAT Conntrack'],
                ['geoipAsn', 'GeoIP MMDB Country/City/ASN'],
                ['threatIntelMatch', 'Threat Alias IOC Match'],
              ] as const
            ).map(([field, label]) => (
              <label key={field} className="flex items-center gap-2 cursor-pointer text-slate-200">
                <input
                  type="checkbox"
                  checked={Boolean(cfg.enrichment[field])}
                  onChange={(e) =>
                    onUpdateDraft((prev) => {
                      const cur = resolveNetFlowDraftConfig(prev.netflow);
                      return {
                        ...prev,
                        netflow: { ...cur, enrichment: { ...cur.enrichment, [field]: e.target.checked } },
                      };
                    })
                  }
                  className="accent-sky-500"
                />
                <span>{label}</span>
              </label>
            ))}
          </div>
          <label className="flex items-center gap-2 cursor-pointer text-sky-300 pt-1">
            <input
              type="checkbox"
              checked={cfg.topologyOverlay.enabled}
              onChange={(e) =>
                onUpdateDraft((prev) => {
                  const cur = resolveNetFlowDraftConfig(prev.netflow);
                  return {
                    ...prev,
                    netflow: { ...cur, topologyOverlay: { ...cur.topologyOverlay, enabled: e.target.checked } },
                  };
                })
              }
              className="accent-sky-500"
            />
            Publish live throughput rates to Topology Studio fabric edges
          </label>
          <label className="block pt-1">
            <span className="text-slate-400 block mb-1">Internal CIDRs (Direction Classifier)</span>
            <input
              type="text"
              value={internalCidrsText}
              onChange={(e) => {
                const nextText = e.target.value;
                setInternalCidrsText(nextText);
                internalCidrsTextRef.current = nextText;
                onUpdateDraft((prev) => {
                  const cur = resolveNetFlowDraftConfig(prev.netflow);
                  return {
                    ...prev,
                    netflow: {
                      ...cur,
                      enrichment: {
                        ...cur.enrichment,
                        internalCidrs: parseCsvTokens(nextText),
                      },
                    },
                  };
                });
              }}
              onBlur={() => {
                setInternalCidrsText(parseCsvTokens(internalCidrsTextRef.current).join(', '));
              }}
              className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
          </label>
          <div className="pt-2 border-t border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-white flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-cyan-400" />
                MaxMind `.mmdb` Auto-Updater
              </span>
              <button
                type="button"
                disabled={geoUpdating}
                onClick={() => {
                  setGeoUpdating(true);
                  setGeoMsg(null);
                  void triggerNetFlowGeoIPUpdateAction().then((res) => {
                    setGeoUpdating(false);
                    setGeoMsg(res.success ? 'GeoIP databases refreshed.' : res.error || 'Update failed.');
                  });
                }}
                className="px-2.5 py-1 rounded bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 font-semibold"
              >
                {geoUpdating ? 'Updating...' : 'Update DBs Now'}
              </button>
            </div>
            {geoMsg && <div className="font-mono text-[11px] text-cyan-300">{geoMsg}</div>}
            <label className="flex items-center gap-2 cursor-pointer text-slate-200">
              <input
                type="checkbox"
                checked={cfg.enrichment.geoipAutoUpdate}
                onChange={(e) =>
                  onUpdateDraft((prev) => {
                    const cur = resolveNetFlowDraftConfig(prev.netflow);
                    return {
                      ...prev,
                      netflow: { ...cur, enrichment: { ...cur.enrichment, geoipAutoUpdate: e.target.checked } },
                    };
                  })
                }
                className="accent-sky-500"
              />
              <span>Auto-download MMDB files every {cfg.enrichment.geoipUpdateIntervalHours}h</span>
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <input
                type="text"
                value={cfg.enrichment.geoipCityDownloadUrl}
                onChange={(e) =>
                  onUpdateDraft((prev) => {
                    const cur = resolveNetFlowDraftConfig(prev.netflow);
                    return {
                      ...prev,
                      netflow: { ...cur, enrichment: { ...cur.enrichment, geoipCityDownloadUrl: e.target.value } },
                    };
                  })
                }
                placeholder="City MMDB URL (optional)"
                className="px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
              />
              <input
                type="text"
                value={cfg.enrichment.geoipAsnDownloadUrl}
                onChange={(e) =>
                  onUpdateDraft((prev) => {
                    const cur = resolveNetFlowDraftConfig(prev.netflow);
                    return {
                      ...prev,
                      netflow: { ...cur, enrichment: { ...cur.enrichment, geoipAsnDownloadUrl: e.target.value } },
                    };
                  })
                }
                placeholder="ASN MMDB URL (optional)"
                className="px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Scheduled 95th-Percentile Reporting */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 font-semibold text-white text-sm">
            <FileBarChart className="w-4 h-4 text-amber-400" />
            Scheduled 95th-Percentile Reports &amp; Webhook Export
          </div>
          <label className="flex items-center gap-2 cursor-pointer text-slate-200">
            <input
              type="checkbox"
              checked={cfg.reporting.enabled}
              onChange={(e) =>
                onUpdateDraft((prev) => {
                  const cur = resolveNetFlowDraftConfig(prev.netflow);
                  return {
                    ...prev,
                    netflow: { ...cur, reporting: { ...cur.reporting, enabled: e.target.checked } },
                  };
                })
              }
              className="accent-sky-500"
            />
            Enabled
          </label>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <label className="block">
            <span className="text-slate-400 block mb-1">Interval (Hours)</span>
            <input
              type="number"
              min={1}
              max={720}
              value={cfg.reporting.intervalHours || ''}
              onChange={(e) => {
                const v = e.target.value.trim();
                const n = v === '' ? 0 : Number(v);
                if (Number.isNaN(n)) return;
                onUpdateDraft((prev) => {
                  const cur = resolveNetFlowDraftConfig(prev.netflow);
                  return {
                    ...prev,
                    netflow: { ...cur, reporting: { ...cur.reporting, intervalHours: Math.max(0, Math.trunc(n)) } },
                  };
                });
              }}
              className="w-full px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
          </label>
          <label className="block">
            <span className="text-slate-400 block mb-1">Lookback (Days)</span>
            <input
              type="number"
              min={1}
              max={90}
              value={cfg.reporting.rangeDays || ''}
              onChange={(e) => {
                const v = e.target.value.trim();
                const n = v === '' ? 0 : Number(v);
                if (Number.isNaN(n)) return;
                onUpdateDraft((prev) => {
                  const cur = resolveNetFlowDraftConfig(prev.netflow);
                  return {
                    ...prev,
                    netflow: { ...cur, reporting: { ...cur.reporting, rangeDays: Math.max(0, Math.trunc(n)) } },
                  };
                });
              }}
              className="w-full px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
          </label>
          <label className="block">
            <span className="text-slate-400 block mb-1">Group By</span>
            <select
              value={cfg.reporting.groupBy}
              onChange={(e) =>
                onUpdateDraft((prev) => {
                  const cur = resolveNetFlowDraftConfig(prev.netflow);
                  return {
                    ...prev,
                    netflow: { ...cur, reporting: { ...cur.reporting, groupBy: e.target.value as typeof cfg.reporting.groupBy } },
                  };
                })
              }
              className="w-full px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            >
              <option value="interface">interface</option>
              <option value="exporter">exporter</option>
              <option value="vlan">vlan</option>
              <option value="subnet">subnet</option>
            </select>
          </label>
          <label className="block">
            <span className="text-slate-400 block mb-1">Format</span>
            <select
              value={cfg.reporting.format}
              onChange={(e) =>
                onUpdateDraft((prev) => {
                  const cur = resolveNetFlowDraftConfig(prev.netflow);
                  return {
                    ...prev,
                    netflow: { ...cur, reporting: { ...cur.reporting, format: e.target.value as typeof cfg.reporting.format } },
                  };
                })
              }
              className="w-full px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            >
              <option value="markdown">markdown</option>
              <option value="csv">csv</option>
              <option value="json">json</option>
            </select>
          </label>
          <label className="block">
            <span className="text-slate-400 block mb-1">Webhook URL (optional)</span>
            <input
              type="url"
              value={cfg.reporting.webhookUrl}
              onChange={(e) =>
                onUpdateDraft((prev) => {
                  const cur = resolveNetFlowDraftConfig(prev.netflow);
                  return {
                    ...prev,
                    netflow: { ...cur, reporting: { ...cur.reporting, webhookUrl: e.target.value } },
                  };
                })
              }
              placeholder="https://..."
              className="w-full px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
          </label>
        </div>
      </div>
    </div>
  );
}
