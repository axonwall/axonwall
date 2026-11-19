'use client';

import { useState, useEffect, useMemo } from 'react';
import Link from 'next/link';
import { Database, CheckCircle2, Layers, Terminal, RefreshCw, HardDrive } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { getCurrentDesiredState, getK3sClusterPulseAction } from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import type { DesiredState } from '@axonwall/lib/schemas';
import { formatAge, type K3sClusterPulse } from '@/components/k3s/types';

export default function OpenEbsStoragePage() {
  const { applyState } = useDesiredStateApply();
  const [state, setState] = useState<DesiredState | null>(null);
  const [pulse, setPulse] = useState<K3sClusterPulse | null>(null);
  const [refreshingLive, setRefreshingLive] = useState(false);
  const [zfsPool, setZfsPool] = useState('tank');
  const [replicatedPool, setReplicatedPool] = useState('tank/openebs-replicated');
  const [replicas, setReplicas] = useState(2);
  const [msg, setMsg] = useState<string | null>(null);

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

  const storageChartData = useMemo(() => {
    if (!pulse?.storageByClass) return [];
    const gi = 1024 * 1024 * 1024;
    return pulse.storageByClass.map((sc) => ({
      name: sc.name,
      gib: Number((sc.totalBytes / gi).toFixed(2)),
      pvcs: sc.pvcCount,
      bound: sc.boundCount,
    }));
  }, [pulse?.storageByClass]);

  const handleSave = async () => {
    if (!state) return;
    const next = structuredClone(state);
    next.k3s = next.k3s || {
      enabled: true,
      clusterCidr: '10.42.0.0/16',
      serviceCidr: '10.43.0.0/16',
      nodeIpInterface: 'lan',
      flannelBackend: 'wireguard-native',
      disableTraefik: false,
      autoJoinHaPeer: true,
      openEbs: {
        enabled: true,
        zfsLocalPvEnabled: true,
        zfsLocalPvPool: zfsPool,
        replicatedStorageEnabled: true,
        defaultReplicaCount: replicas,
        replicatedBackingPool: replicatedPool,
      },
      enableUserNamespaces: false,
      bpfTokenProfiles: [],
      workloads: [],
    };
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
      setMsg(`OpenEBS ZFS-LocalPV & Replicated HA StorageClasses reconciled (${res.message})`);
    } catch (err: any) {
      setMsg(err?.message || 'Failed to save OpenEBS storage configuration.');
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
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300">
          {msg}
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
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <HardDrive className="w-4 h-4 text-amber-400" /> StorageClass Allocation (Live Cluster)
              </h2>
              <p className="text-xs text-slate-400">
                Provisioned PVC GiB capacity and bound claim counts grouped by CSI StorageClass.
              </p>
            </div>
            {pulse?.available && (
              <div className="text-xs font-mono text-slate-300">
                {pulse.counts.pvcsBound}/{pulse.counts.pvcsTotal} PVCs Bound • {pulse.counts.pvsTotal} PVs
              </div>
            )}
          </div>

          {!pulse?.available ? (
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-400">
              {pulse?.error || 'Live OpenEBS storage telemetry unavailable until k3s.service answers.'}
            </div>
          ) : storageChartData.length === 0 ? (
            <div className="text-xs text-slate-500 py-6 text-center">No StorageClasses detected yet.</div>
          ) : (
            <div className="h-[240px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={storageChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="name" tick={{ fill: '#cbd5e1', fontSize: 11 }} />
                  <YAxis yAxisId="left" tick={{ fill: '#94a3b8', fontSize: 11 }} unit=" GiB" />
                  <YAxis yAxisId="right" orientation="right" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '0.5rem',
                      fontSize: '12px',
                      color: '#f1f5f9',
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                  <Bar yAxisId="left" dataKey="gib" name="Allocated GiB" fill="#10b981" />
                  <Bar yAxisId="right" dataKey="pvcs" name="Total PVCs" fill="#38bdf8" />
                  <Bar yAxisId="right" dataKey="bound" name="Bound PVCs" fill="#f59e0b" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-sm font-bold text-white">Live PersistentVolumeClaims (PVCs)</h3>
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
          ) : pulse.pvcsSummary.length === 0 ? (
            <div className="p-6 text-xs text-slate-500">No PersistentVolumeClaims provisioned in cluster.</div>
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
                  {pulse.pvcsSummary.map((pvc) => (
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
