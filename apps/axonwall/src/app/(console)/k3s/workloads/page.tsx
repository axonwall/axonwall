'use client';

import { useState, useEffect } from 'react';
import { Boxes, Plus, Trash2 } from 'lucide-react';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import type { DesiredState } from '@axonwall/lib/schemas';

export default function K3sWorkloadsPage() {
  const [state, setState] = useState<DesiredState | null>(null);
  const [name, setName] = useState('minio-s3');
  const [image, setImage] = useState('quay.io/minio/minio:latest');
  const [port, setPort] = useState(9000);
  const [storageClass, setStorageClass] = useState<'axonwall-replicated-ha' | 'axonwall-zfs-local' | 'none'>('axonwall-replicated-ha');
  const [storageSizeGb, setStorageSizeGb] = useState(50);

  useEffect(() => {
    getCurrentDesiredState().then(setState).catch(() => {});
  }, []);

  const addWorkload = async () => {
    if (!state || !name.trim()) return;
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
        zfsLocalPvPool: 'tank',
        replicatedStorageEnabled: true,
        defaultReplicaCount: 2,
        replicatedBackingPool: 'tank/openebs-replicated',
      },
      workloads: [],
    };
    next.k3s.workloads = [
      ...next.k3s.workloads.filter((w) => w.name !== name.trim()),
      {
        name: name.trim(),
        namespace: 'default',
        image: image.trim(),
        replicas: 1,
        port,
        storageClass,
        storageSizeGb,
        mountPath: '/data',
        enabled: true,
      },
    ];
    await applyDesiredState(next);
    setState(next);
  };

  const removeWorkload = async (wlName: string) => {
    if (!state?.k3s) return;
    const next = structuredClone(state);
    if (next.k3s) {
      next.k3s.workloads = next.k3s.workloads.filter((w) => w.name !== wlName);
    }
    await applyDesiredState(next);
    setState(next);
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex items-center gap-3 border-b border-slate-800 pb-6">
        <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
          <Boxes className="w-5 h-5" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">K3s Workloads & Stateful Applications</h1>
          <p className="text-sm text-slate-400">
            Deploy stateful applications backed by OpenEBS replicated PVCs for automatic failover across HA nodes.
          </p>
        </div>
      </div>

      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Plus className="w-4 h-4 text-emerald-400" /> Deploy K3s Workload
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Workload Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Container Image</label>
            <input
              type="text"
              value={image}
              onChange={(e) => setImage(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Port</label>
            <input
              type="number"
              value={port}
              onChange={(e) => setPort(Number(e.target.value))}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">OpenEBS StorageClass</label>
            <select
              value={storageClass}
              onChange={(e) => setStorageClass(e.target.value as any)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white"
            >
              <option value="axonwall-replicated-ha">axonwall-replicated-ha (2-Node Sync)</option>
              <option value="axonwall-zfs-local">axonwall-zfs-local (Local ZFS)</option>
              <option value="none">Stateless (No PVC)</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">PVC Size (GiB)</label>
            <input
              type="number"
              value={storageSizeGb}
              onChange={(e) => setStorageSizeGb(Number(e.target.value))}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
            />
          </div>
        </div>
        <button
          onClick={addWorkload}
          className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white"
        >
          Deploy to K3s Cluster
        </button>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-3">
        <h3 className="text-sm font-bold text-white">Deployed Workloads</h3>
        {(state?.k3s?.workloads ?? []).length === 0 ? (
          <p className="text-xs text-slate-500">No workloads deployed yet.</p>
        ) : (
          <div className="space-y-2">
            {(state?.k3s?.workloads ?? []).map((w) => (
              <div key={w.name} className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between text-xs">
                <div>
                  <span className="font-mono font-bold text-white">{w.name}</span>
                  <span className="text-slate-400 font-mono ml-2">({w.image})</span>
                </div>
                <div className="flex items-center gap-4">
                  <span className="font-mono text-emerald-400">
                    {w.storageClass} ({w.storageSizeGb}Gi)
                  </span>
                  <button onClick={() => removeWorkload(w.name)} className="text-rose-400 hover:text-rose-300">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
