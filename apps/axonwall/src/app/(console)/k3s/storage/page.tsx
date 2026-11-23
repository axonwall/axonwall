'use client';

import { useState, useEffect, useMemo } from 'react';
import Link from 'next/link';
import { Database, Terminal, RefreshCw } from 'lucide-react';
import { getCurrentDesiredState, getK3sClusterPulseAction } from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import type { DesiredState } from '@axonwall/lib/schemas';
import { formatAge, type K3sClusterPulse } from '@/components/k3s/types';
import { K3sStorageVisuals } from '@/components/k3s/K3sStorageVisuals';

export default function OpenEbsStoragePage() {
  const { applyState } = useDesiredStateApply();
  const [state, setState] = useState<DesiredState | null>(null);
  const [pulse, setPulse] = useState<K3sClusterPulse | null>(null);
  const [refreshingLive, setRefreshingLive] = useState(false);
  const [selectedNs, setSelectedNs] = useState<string>('_all');
  const [zfsPool, setZfsPool] = useState('tank');
  const [replicatedPool, setReplicatedPool] = useState('tank/openebs-replicated');
  const [replicas, setReplicas] = useState(2);
  // C-L5: typed banner — errors render red, not emerald.
  const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadLive = async () => {
    setRefreshingLive(true);
    try {
      const p = await getK3sClusterPulseAction();
      setPulse(p);
    } catch {
    } finally {
      setRefreshingLive(false);
    }
  };

  useEffect(() => {
    getCurrentDesiredState().then((st) => {
      setState(st);
      if (st.k3s?.openEbs) {
        setZfsPool(st.k3s.openEbs.zfsLocalPvPool || 'tank');
        setReplicatedPool(st.k3s.openEbs.replicatedBackingPool || 'tank/openebs-replicated');
        setReplicas(st.k3s.openEbs.defaultReplicaCount || 2);
      }
    }).catch(() => {});
    loadLive();
  }, []);

  const filteredPvcs = useMemo(() => {
    const pvcs = pulse?.pvcsSummary || [];
    if (selectedNs === '_all') return pvcs;
    return pvcs.filter((p) => (p.namespace || 'default') === selectedNs);
  }, [pulse?.pvcsSummary, selectedNs]);

  const handleSave = async () => {
    if (!state) return;
    const next = structuredClone(state);
    // C-M3: storage cannot invent a whole K3s cluster config (CIDRs, CNI,
    // pools) on a box with no K3s configuration. Enable K3s from the
    // Cluster page first, then return here — the pool/replica values below
    // are the ones shown in this form, chosen by the operator.
    if (!next.k3s) {
      setMsg({
        type: 'error',
        text: 'K3s is not configured yet — enable it from the Cluster page first. Storage settings cannot create a cluster configuration on their own.',
      });
      return;
    }
    next.k3s.openEbs = {
      enabled: true,
      zfsLocalPvEnabled: true,
      zfsLocalPvPool: zfsPool,
      replicatedStorageEnabled: true,
      defaultReplicaCount: replicas,
      replicatedBackingPool: replicatedPool,
    };
    // C2: a fingerprint mismatch (or any apply failure) must be visible,
    // not an unhandled rejection — the save did not happen.
    try {
      const res = await applyState(next);
      setState(next);
      setMsg({ type: 'success', text: `OpenEBS ZFS-LocalPV & Replicated HA StorageClasses reconciled (${res.message})` });
    } catch (err: any) {
      setMsg({ type: 'error', text: err?.message || 'Failed to save OpenEBS storage configuration.' });
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">OpenEBS Distributed Storage</h1>
            <p className="text-sm text-slate-400">
              CSI StorageClasses backed by local ZFS datasets (<code className="text-emerald-400">axonwall-zfs-local</code>) and synchronous 2-node NVMe-oF replication (<code className="text-emerald-400">axonwall-replicated-ha</code>).
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2.5">
          <Link
            href="/k3s/explorer?resource=persistentvolumeclaims"
            className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-emerald-500/40 text-xs font-semibold text-emerald-300 flex items-center gap-1.5 transition"
          >
            <Terminal className="w-3.5 h-3.5" /> Open K9s Storage Explorer
          </Link>
          <button
            type="button"
            onClick={loadLive}
            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300"
            title="Refresh Live Storage Telemetry"
          >
            <RefreshCw className={`w-4 h-4 ${refreshingLive ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {msg && (
        <div
          className={`p-4 rounded-xl border text-xs ${
            msg.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
          }`}
        >
          {msg.text}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <span className="font-mono text-sm font-bold text-white">axonwall-zfs-local</span>
            <span className="px-2.5 py-1 rounded bg-emerald-500/15 text-emerald-400 text-xs font-mono">
              zfs.csi.openebs.io
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Zero-overhead dynamic ZFS dataset and zvol provisioner with native ZFS compression and snapshots.
          </p>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Backing ZFS Pool</label>
            <input
              type="text"
              value={zfsPool}
              onChange={(e) => setZfsPool(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
            />
          </div>
        </div>

        <div className="p-6 rounded-2xl bg-slate-900 border border-emerald-500/30 space-y-3">
          <div className="flex items-center justify-between">
            <span className="font-mono text-sm font-bold text-white">axonwall-replicated-ha (Default)</span>
            <span className="px-2.5 py-1 rounded bg-sky-500/15 text-sky-400 text-xs font-mono">
              io.openebs.csi-mayastor
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Synchronous N-way block replication across primary and secondary HA Axonwall nodes for instant pod failover.
          </p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Backing Dataset</label>
              <input
                type="text"
                value={replicatedPool}
                onChange={(e) => setReplicatedPool(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Synchronous Replicas</label>
              <input
                type="number"
                min={1}
                max={3}
                value={replicas}
                onChange={(e) => setReplicas(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
          </div>
        </div>
      </div>

      <div className="flex justify-end">
        <button
          onClick={handleSave}
          className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white"
        >
          Apply OpenEBS StorageClasses
        </button>
      </div>

      {/* Live OpenEBS & Persistent Volume Visualization */}
      <div className="space-y-6 pt-2">
        {!pulse?.available ? (
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 text-xs font-mono text-slate-400">
            {pulse?.error || 'Live OpenEBS storage telemetry unavailable until k3s.service answers.'}
          </div>
        ) : (
          <K3sStorageVisuals
            pulse={pulse}
            selectedNs={selectedNs}
            onSelectNamespace={setSelectedNs}
          />
        )}

        <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
          <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2.5">
              <h3 className="text-sm font-bold text-white">Live PersistentVolumeClaims (PVCs)</h3>
              {selectedNs !== '_all' && (
                <button
                  type="button"
                  onClick={() => setSelectedNs('_all')}
                  className="px-2 py-0.5 rounded bg-sky-500/15 border border-sky-500/30 text-[11px] font-mono text-sky-300 hover:text-white"
                >
                  Namespace: {selectedNs} ✕
                </button>
              )}
            </div>
            <Link
              href="/k3s/explorer?resource=persistentvolumes"
              className="text-xs font-mono text-sky-400 hover:underline"
            >
              Browse PersistentVolumes (:pv) →
            </Link>
          </div>
          {!pulse?.available ? (
            <div className="p-6 text-xs font-mono text-slate-400">
              {pulse?.error || 'Live PVC inventory unavailable.'}
            </div>
          ) : filteredPvcs.length === 0 ? (
            <div className="p-6 text-xs text-slate-400">
              {selectedNs !== '_all'
                ? `No PersistentVolumeClaims found in namespace '${selectedNs}'.`
                : 'No PersistentVolumeClaims provisioned in cluster.'}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead className="bg-slate-950/70 text-[10px] uppercase text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-4">Namespace</th>
                    <th className="py-2.5 px-4">PVC Name</th>
                    <th className="py-2.5 px-4">Status</th>
                    <th className="py-2.5 px-4">Capacity</th>
                    <th className="py-2.5 px-4">AccessModes</th>
                    <th className="py-2.5 px-4">StorageClass</th>
                    <th className="py-2.5 px-4">Volume</th>
                    <th className="py-2.5 px-4">Age</th>
                    <th className="py-2.5 px-4 text-right">K9s</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredPvcs.map((pvc) => (
                    <tr key={`${pvc.namespace}/${pvc.name}`} className="hover:bg-slate-800/40">
                      <td className="py-2.5 px-4 text-slate-400">{pvc.namespace}</td>
                      <td className="py-2.5 px-4 text-white font-semibold">{pvc.name}</td>
                      <td className="py-2.5 px-4">
                        <span
                          className={`px-2 py-0.5 rounded border text-[10px] ${
                            pvc.status === 'Bound'
                              ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                              : 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                          }`}
                        >
                          {pvc.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-amber-300">{pvc.capacity || '—'}</td>
                      <td className="py-2.5 px-4 text-slate-300">{(pvc.accessModes || []).join(', ') || '—'}</td>
                      <td className="py-2.5 px-4 text-sky-300">{pvc.storageClass || '—'}</td>
                      <td className="py-2.5 px-4 text-slate-400 max-w-xs truncate">{pvc.volumeName || '—'}</td>
                      <td className="py-2.5 px-4 text-slate-400">{formatAge(pvc.creationTimestamp)}</td>
                      <td className="py-2.5 px-4 text-right">
                        <Link
                          href={`/k3s/explorer?resource=persistentvolumeclaims&namespace=${encodeURIComponent(pvc.namespace)}&name=${encodeURIComponent(pvc.name)}`}
                          className="text-sky-400 hover:underline"
                        >
                          Inspect →
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
