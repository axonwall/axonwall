'use client';

import { useState, useEffect } from 'react';
import { Camera, Plus, ArrowRightLeft, AlertTriangle, RotateCcw, Trash2 } from 'lucide-react';
import {
  getCurrentDesiredState,
  getNasSnapshotsRuntime,
  createNasSnapshotAction,
  rollbackNasSnapshotAction,
  deleteNasSnapshotAction,
  type NasSnapshotItem,
} from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import type { DesiredState } from '@axonwall/lib/schemas';

export default function ZfsSnapshotsPage() {
  const { applyState } = useDesiredStateApply();
  // C-B13: the runtime snapshot list was fetched into `snapshots` and
  // then never rendered, so a snapshot created by "Create Snapshot
  // Now" could only be trusted from the banner text. The list is now
  // shown below (name/dataset/created/size). No delete/rollback server
  // action exists yet, so this section is read-only.
  const formatBytes = (bytes: number): string => {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
    return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  };
  const [state, setState] = useState<DesiredState | null>(null);
  const [snapshots, setSnapshots] = useState<NasSnapshotItem[]>([]);
  const [dataset, setDataset] = useState('tank/shares/general');
  const [label, setLabel] = useState('');
  const [interval, setIntervalVal] = useState<'hourly' | 'daily' | 'weekly'>('hourly');
  const [keepCount, setKeepCount] = useState(24);
  const [msg, setMsg] = useState<string | null>(null);
  // B19: the banner used to be always emerald, so a failed snapshot
  // or save looked like a confirmed one. Type it so errors render red.
  const [msgKind, setMsgKind] = useState<'success' | 'error'>('success');

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
    try {
      const res = await createNasSnapshotAction(dataset, label || undefined);
      // B19: check res.success — a daemon success:false message must
      // not render in the green success banner. (C-B1: the operator may
      // be about to upgrade on its strength.)
      setMsgKind(res.success ? 'success' : 'error');
      setMsg(res.message);
      await load();
    } catch (err: any) {
      setMsgKind('error');
      setMsg(`Error: ${err?.message || 'Failed to create snapshot'}`);
    }
  };

  const handleRollback = async (fullSnap: string) => {
    if (!confirm(`Roll back dataset to snapshot '${fullSnap}'? Uncommitted changes since this snapshot will be reverted.`)) {
      return;
    }
    try {
      const res = await rollbackNasSnapshotAction(fullSnap);
      setMsgKind(res.success ? 'success' : 'error');
      setMsg(res.message);
      await load();
    } catch (err: any) {
      setMsgKind('error');
      setMsg(`Error: ${err?.message || 'Failed to roll back snapshot'}`);
    }
  };

  const handleDeleteSnapshot = async (fullSnap: string) => {
    if (!confirm(`Destroy ZFS snapshot '${fullSnap}' permanently?`)) return;
    try {
      const res = await deleteNasSnapshotAction(fullSnap);
      setMsgKind(res.success ? 'success' : 'error');
      setMsg(res.message);
      await load();
    } catch (err: any) {
      setMsgKind('error');
      setMsg(`Error: ${err?.message || 'Failed to delete snapshot'}`);
    }
  };

  const handleAddPolicy = async () => {
    if (!state) return;
    try {
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
      await applyState(next);
      setState(next);
      // C-B7: no scheduler or `zfs send` loop consumes snapshotPolicies
      // anywhere — the policy is only recorded. Say so, instead of
      // promising automated snapshots and HA replication that never run.
      setMsgKind('success');
      setMsg(
        `Snapshot policy recorded for ${dataset} (${interval}, keep ${keepCount}). Note: no automatic scheduler exists yet — snapshots are manual only and nothing is replicated to the HA peer.`
      );
    } catch (err: any) {
      setMsgKind('error');
      setMsg(`Error: ${err?.message || 'Failed to save snapshot policy'}`);
    }
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
            Take instant Copy-on-Write ZFS snapshots. Automated schedules and streaming incremental{' '}
            <code className="text-emerald-400">zfs send -I</code> deltas to an HA Backup node are not implemented yet.
          </p>
        </div>
      </div>

      {msg && (
        <div
          className={
            msgKind === 'error'
              ? 'p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300 flex items-start gap-2'
              : 'p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300'
          }
        >
          {msgKind === 'error' && <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />}
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
            <ArrowRightLeft className="w-4 h-4 text-emerald-400" /> Snapshot & HA Sync Policy (recorded only — not executed)
          </h2>
          <p className="text-xs text-slate-400">
            Policies are stored for later use. No scheduler runs them and no replication stream exists yet — take snapshots
            manually with “Create Snapshot Now” above.
          </p>
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
        <h3 className="text-sm font-bold text-white">Recorded Snapshot & HA Replication Policies</h3>
        {(state?.nas?.snapshotPolicies ?? []).length === 0 ? (
          <p className="text-xs text-slate-500">No snapshot policies recorded yet.</p>
        ) : (
          <div className="space-y-2">
            {(state?.nas?.snapshotPolicies ?? []).map((p, idx) => (
              <div key={idx} className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between text-xs">
                <span className="font-mono text-white">{p.dataset}</span>
                <span className="text-slate-400 font-mono">Every {p.interval} • Keep {p.keepCount} snapshots</span>
                <span className="text-amber-400 font-semibold">Recorded only — not scheduled, HA replication not implemented</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-3">
        <h3 className="text-sm font-bold text-white">Runtime Snapshots (live from the daemon)</h3>
        {snapshots.length === 0 ? (
          <p className="text-xs text-slate-500">
            No snapshots reported by the daemon. If you just created one and it is not listed here,
            the creation may not have landed — check the message above.
          </p>
        ) : (
          <div className="space-y-2">
            {snapshots.map((s) => {
              const fullSnap = `${s.dataset}@${s.name}`;
              return (
                <div
                  key={fullSnap}
                  className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs"
                >
                  <span className="font-mono text-white">{fullSnap}</span>
                  <span className="text-slate-400 font-mono">
                    {s.createdAt ? new Date(s.createdAt).toLocaleString() : 'unknown date'}
                  </span>
                  <span className="text-slate-400 font-mono">{formatBytes(s.usedBytes)}</span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleRollback(fullSnap)}
                      className="px-2.5 py-1 rounded bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-amber-300 inline-flex items-center gap-1"
                    >
                      <RotateCcw className="w-3 h-3" /> Rollback
                    </button>
                    <button
                      onClick={() => handleDeleteSnapshot(fullSnap)}
                      className="px-2.5 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-rose-300 inline-flex items-center gap-1"
                    >
                      <Trash2 className="w-3 h-3" /> Destroy
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
