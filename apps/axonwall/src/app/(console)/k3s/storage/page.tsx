'use client';

import { useState, useEffect } from 'react';
import { Database, CheckCircle2, Layers } from 'lucide-react';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import type { DesiredState } from '@axonwall/lib/schemas';

export default function OpenEbsStoragePage() {
  const [state, setState] = useState<DesiredState | null>(null);
  const [zfsPool, setZfsPool] = useState('tank');
  const [replicatedPool, setReplicatedPool] = useState('tank/openebs-replicated');
  const [replicas, setReplicas] = useState(2);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    getCurrentDesiredState().then((st) => {
      setState(st);
      if (st.k3s?.openEbs) {
        setZfsPool(st.k3s.openEbs.zfsLocalPvPool || 'tank');
        setReplicatedPool(st.k3s.openEbs.replicatedBackingPool || 'tank/openebs-replicated');
        setReplicas(st.k3s.openEbs.defaultReplicaCount || 2);
      }
    }).catch(() => {});
  }, []);

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
    const res = await applyDesiredState(next);
    setState(next);
    setMsg(`OpenEBS ZFS-LocalPV & Replicated HA StorageClasses reconciled (${res.message})`);
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex items-center gap-3 border-b border-slate-800 pb-6">
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
    </div>
  );
}
