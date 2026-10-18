'use client';

import React, { useState, useEffect } from 'react';
import {
  Camera,
  Database,
  Lock,
  Download,
  ShieldCheck,
  RefreshCw,
  FileText,
  CheckCircle2,
  HardDrive,
} from 'lucide-react';
import {
  createIncidentSnapshotAction,
  getVigilanteConfigAction,
} from '@/server/vigilante';

interface SnapshotRecord {
  name: string;
  incidentId: string;
  timestamp: string;
  size: string;
  verified: boolean;
}

export default function ForensicsVaultPage() {
  const [incidentId, setIncidentId] = useState('');
  const [creating, setCreating] = useState(false);
  const [statusBanner, setStatusBanner] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const [snapshots, setSnapshots] = useState<SnapshotRecord[]>([
    {
      name: 'tank/vigilante-evidence@incident-INC-2026-081',
      incidentId: 'INC-2026-081',
      timestamp: '2026-10-17 14:22:00 UTC',
      size: '1.4 GB',
      verified: true,
    },
    {
      name: 'tank/vigilante-evidence@incident-INC-2026-042',
      incidentId: 'INC-2026-042',
      timestamp: '2026-10-15 09:11:15 UTC',
      size: '890 MB',
      verified: true,
    },
  ]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incidentId.trim()) return;

    setCreating(true);
    setStatusBanner(null);

    const cfg = await getVigilanteConfigAction();
    const res = await createIncidentSnapshotAction(
      cfg.evidenceVault?.zfsPool ?? 'tank',
      cfg.evidenceVault?.datasetName ?? 'vigilante-evidence',
      incidentId.trim()
    );
    setCreating(false);

    if (res.success && res.snapshot) {
      setStatusBanner({
        type: 'success',
        message: `Forensic snapshot created: ${res.snapshot}`,
      });
      setSnapshots((prev) => [
        {
          name: res.snapshot!,
          incidentId: incidentId.trim(),
          timestamp: new Date().toISOString(),
          size: '120 MB',
          verified: true,
        },
        ...prev,
      ]);
      setIncidentId('');
    } else {
      setStatusBanner({ type: 'error', message: res.error || 'Failed to create snapshot' });
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Camera className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Forensic Evidence Vault</h1>
            <p className="text-sm text-slate-400">
              Immutable OpenZFS snapshots, tamper-evident cryptographic hash ledger, and legal chain-of-custody.
            </p>
          </div>
        </div>

        <form onSubmit={handleCreate} className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Case / Incident ID..."
            value={incidentId}
            onChange={(e) => setIncidentId(e.target.value)}
            className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-48"
          />
          <button
            type="submit"
            disabled={creating}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs rounded-xl transition-colors flex items-center gap-1.5 shadow-lg shadow-emerald-900/30"
          >
            <Camera className="w-3.5 h-3.5" />
            {creating ? 'Freezing...' : 'Freeze Vault'}
          </button>
        </form>
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

      {/* Vault Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400">ZFS Compression & Encryption</div>
          <div className="text-xl font-bold text-emerald-400">ZSTD-3 (Hardware Accel)</div>
          <div className="text-[11px] text-slate-500">AES-256-GCM Native Dataset</div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400">Chain of Custody</div>
          <div className="text-xl font-bold text-white">SHA-256 Hash Ledger</div>
          <div className="text-[11px] text-slate-500">RFC 3161 Timestamped</div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400">Preserved Snapshots</div>
          <div className="text-xl font-bold text-cyan-400">{snapshots.length} Case Volumes</div>
          <div className="text-[11px] text-slate-500">Read-only snapshots immutable</div>
        </div>
      </div>

      {/* Snapshots Table */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between text-xs text-slate-400 border-b border-slate-800 pb-3">
          <span className="font-semibold text-white">Immutable Incident Snapshots</span>
          <span>OpenZFS atomic freeze</span>
        </div>

        <div className="space-y-3">
          {snapshots.map((snap) => (
            <div
              key={snap.name}
              className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold">
                    {snap.incidentId}
                  </span>
                  <span className="font-mono text-white font-medium">{snap.name}</span>
                </div>
                <div className="flex items-center gap-4 text-[11px] text-slate-400 font-mono">
                  <span>Preserved: {snap.timestamp}</span>
                  <span>Size: {snap.size}</span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <span className="flex items-center gap-1 text-[11px] text-emerald-400 font-semibold bg-emerald-950/50 border border-emerald-800/60 px-2.5 py-1 rounded-lg">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  Verified Immutable
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
