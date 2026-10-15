'use client';

import { useState, useEffect } from 'react';
import { Camera, Plus, ArrowRightLeft } from 'lucide-react';
import {
  getCurrentDesiredState,
  applyDesiredState,
  getNasSnapshotsRuntime,
  createNasSnapshotAction,
  type NasSnapshotItem,
} from '@/server/agent';
import type { DesiredState } from '@axonwall/lib/schemas';

export default function ZfsSnapshotsPage() {
  const [state, setState] = useState<DesiredState | null>(null);
  const [snapshots, setSnapshots] = useState<NasSnapshotItem[]>([]);
  const [dataset, setDataset] = useState('tank/shares/general');
  const [label, setLabel] = useState('');
  const [interval, setIntervalVal] = useState<'hourly' | 'daily' | 'weekly'>('hourly');
  const [keepCount, setKeepCount] = useState(24);
  const [msg, setMsg] = useState<string | null>(null);

  const load = async () => {
    try {
      const [st, snaps] = await Promise.all([getCurrentDesiredState(), getNasSnapshotsRuntime()]);
      setState(st);
      setSnapshots(snaps || []);
    } catch {}
  };

  useEffect(() => {
    load();
  }, []);

  const handleManualSnapshot = async () => {
    const res = await createNasSnapshotAction(dataset, label || undefined);
    setMsg(res.message);
    await load();
  };

  const handleAddPolicy = async () => {
    if (!state) return;
    const next = structuredClone(state);
    next.nas = next.nas || {
      enabled: true,
      workgroup: 'WORKGROUP',
      serverString: 'Axonwall Enterprise ZFS NAS',
      pools: [],
      datasets: [],
      snapshotPolicies: [],
      smbShares: [],
      nfsExports: [],
      iscsiTargets: [],
    };
    next.nas.snapshotPolicies = [
      ...next.nas.snapshotPolicies,
      {
        dataset,
        interval,
        keepCount,
        replicateToHaPeer: true,
        enabled: true,
      },
    ];
    await applyDesiredState(next);
    setState(next);
    setMsg(`Automated ${interval} snapshot & HA replication policy saved for ${dataset}.`);
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex items-center gap-3 border-b border-slate-800 pb-6">
        <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
          <Camera className="w-5 h-5" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">ZFS Snapshots & 2-Node HA Replication</h1>
          <p className="text-sm text-slate-400">
            Take instant Copy-on-Write ZFS snapshots and stream incremental <code className="text-emerald-400">zfs send -I</code> deltas to your HA Backup node.
          </p>
        </div>
      </div>

      {msg && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300">
          {msg}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Camera className="w-4 h-4 text-emerald-400" /> Take Instant ZFS Snapshot
          </h2>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Dataset</label>
              <input
                type="text"
                value={dataset}
                onChange={(e) => setDataset(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Snapshot Label (optional)</label>
              <input
                type="text"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="pre-upgrade"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
          </div>
          <button
            onClick={handleManualSnapshot}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white"
          >
            Create Snapshot Now
          </button>
        </div>

        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <ArrowRightLeft className="w-4 h-4 text-emerald-400" /> Automated Snapshot & HA Sync Policy
          </h2>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Dataset</label>
              <input
                type="text"
                value={dataset}
                onChange={(e) => setDataset(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Schedule</label>
              <select
                value={interval}
                onChange={(e) => setIntervalVal(e.target.value as any)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white"
              >
                <option value="hourly">Hourly</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Retention Count</label>
              <input
                type="number"
                value={keepCount}
                onChange={(e) => setKeepCount(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
          </div>
          <button
            onClick={handleAddPolicy}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white"
          >
            Add Replication Schedule
          </button>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-3">
        <h3 className="text-sm font-bold text-white">Active Snapshot & HA Replication Policies</h3>
        {(state?.nas?.snapshotPolicies ?? []).length === 0 ? (
          <p className="text-xs text-slate-500">No automated policies configured yet.</p>
        ) : (
          <div className="space-y-2">
            {(state?.nas?.snapshotPolicies ?? []).map((p, idx) => (
              <div key={idx} className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between text-xs">
                <span className="font-mono text-white">{p.dataset}</span>
                <span className="text-slate-400 font-mono">Every {p.interval} • Keep {p.keepCount} snapshots</span>
                <span className="text-emerald-400 font-semibold">HA ZFS Stream Enabled</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
