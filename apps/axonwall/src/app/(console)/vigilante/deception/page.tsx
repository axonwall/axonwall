'use client';

import React, { useState, useEffect } from 'react';
import {
  Radio,
  ShieldAlert,
  AlertTriangle,
  Plus,
  Trash2,
  RefreshCw,
  Zap,
  Target,
  Flag,
  Server,
  Key,
} from 'lucide-react';
import {
  getDeceptionMeshStatusAction,
  soarBlockIPAction,
  type DeceptionCanary,
} from '@/server/vigilante';

export default function DeceptionMeshPage() {
  const [canaries, setCanaries] = useState<DeceptionCanary[]>([]);
  const [activeCount, setActiveCount] = useState(0);
  const [isolatedCount, setIsolatedCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [statusBanner, setStatusBanner] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      const res = await getDeceptionMeshStatusAction();
      setCanaries(res.canaries);
      setActiveCount(res.activeHoneynetsCount);
      setIsolatedCount(res.isolatedAttackersCount);
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || 'Failed to load deception mesh' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleContain = async (ip: string) => {
    setStatusBanner(null);
    const res = await soarBlockIPAction(ip, 86400);
    if (res.success) {
      setStatusBanner({ type: 'success', message: `Offender contained: ${res.message}` });
      loadData();
    } else {
      setStatusBanner({ type: 'error', message: res.message });
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <Radio className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Deception Mesh & Honeynets</h1>
            <p className="text-sm text-slate-400">
              Low-interaction decoy services, Kerberoast canary tokens, and dynamic kCTF honeycombs.
            </p>
          </div>
        </div>

        <button
          onClick={loadData}
          className="px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-xl text-xs text-slate-300 font-medium flex items-center gap-2 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh Decoys
        </button>
      </div>

      {statusBanner && (
        <div
          className={`p-4 rounded-xl border text-xs font-medium flex items-center justify-between ${
            statusBanner.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
          }`}
        >
          <span>{statusBanner.message}</span>
          <button onClick={() => setStatusBanner(null)} className="text-slate-400 hover:text-white">
            ×
          </button>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400">Active Decoy Honeycombs</div>
          <div className="text-2xl font-bold text-cyan-400">{activeCount} Deployed</div>
          <div className="text-[11px] text-slate-500">Listening on isolated VLANs</div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400">Tripped Traps (24h)</div>
          <div className="text-2xl font-bold text-amber-400">
            {canaries.reduce((acc, c) => acc + c.trippedCount, 0)} Alarms
          </div>
          <div className="text-[11px] text-slate-500">Autonomous SOAR isolation triggered</div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400">Isolated Attackers</div>
          <div className="text-2xl font-bold text-rose-400">{isolatedCount} Quarantined</div>
          <div className="text-[11px] text-slate-500">nftables prerouting drop active</div>
        </div>
      </div>

      {/* Decoys Inventory */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-6">
        <div className="flex items-center justify-between">
          <span className="text-white font-semibold text-sm">Deployed Canary Traps</span>
          <span className="text-xs text-slate-500">Zero false-positive alarms guaranteed</span>
        </div>

        <div className="space-y-3">
          {canaries.map((canary) => (
            <div
              key={canary.id}
              className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs transition-all ${
                canary.status === 'triggered'
                  ? 'bg-amber-950/20 border-amber-500/40'
                  : 'bg-slate-950/70 border-slate-800'
              }`}
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      canary.status === 'triggered'
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    }`}
                  >
                    {canary.status}
                  </span>
                  <span className="font-semibold text-white">{canary.name}</span>
                </div>

                <div className="flex items-center gap-4 text-[11px] text-slate-400 font-mono">
                  <span>Decoy IP: {canary.ipAddress}</span>
                  <span>Type: {canary.type}</span>
                  {canary.lastTrippedAt && (
                    <span className="text-amber-400">Last Tripped: {new Date(canary.lastTrippedAt).toLocaleTimeString()}</span>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-3">
                <div className="text-right">
                  <span className="text-[10px] text-slate-500 uppercase block">Trip Count</span>
                  <span className="font-mono font-bold text-amber-300">{canary.trippedCount} Hits</span>
                </div>
                {canary.status === 'triggered' && (
                  <button
                    onClick={() => handleContain(canary.ipAddress)}
                    className="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white font-semibold rounded-lg text-xs transition-colors flex items-center gap-1.5 shadow-lg shadow-rose-900/30"
                  >
                    <Zap className="w-3.5 h-3.5" />
                    Quarantine Source
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
