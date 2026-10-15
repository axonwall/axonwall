'use client';

import { useState, useEffect } from 'react';
import { Cpu, ArrowRightLeft, CheckCircle2, RefreshCw } from 'lucide-react';
import {
  getCurrentDesiredState,
  applyDesiredState,
  getK3sRuntimeStatus,
  triggerK3sHaAutoJoin,
  type K3sRuntimeStatus,
} from '@/server/agent';
import type { DesiredState } from '@axonwall/lib/schemas';

export default function K3sClusterPage() {
  const [state, setState] = useState<DesiredState | null>(null);
  const [status, setStatus] = useState<K3sRuntimeStatus | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [joining, setJoining] = useState(false);

  const load = async () => {
    try {
      const [st, rt] = await Promise.all([getCurrentDesiredState(), getK3sRuntimeStatus()]);
      setState(st);
      setStatus(rt);
    } catch {}
  };

  useEffect(() => {
    load();
  }, []);

  const handleAutoJoin = async () => {
    setJoining(true);
    setMsg(null);
    try {
      const res = await triggerK3sHaAutoJoin();
      setMsg(res.message);
      await load();
    } catch (err: any) {
      setMsg(err?.message || 'HA cluster join failed');
    } finally {
      setJoining(false);
    }
  };

  const handleSaveConfig = async () => {
    if (!state) return;
    const next = structuredClone(state);
    next.capabilities = {
      firewallEnabled: next.capabilities?.firewallEnabled !== false,
      nasEnabled: Boolean(next.capabilities?.nasEnabled ?? next.nas?.enabled),
      k3sEnabled: true,
    };
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
    next.k3s.enabled = true;
    const res = await applyDesiredState(next);
    setState(next);
    setMsg(`K3s control plane configuration applied (${res.message})`);
    await load();
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Kubernetes (K3s) HA Control Plane</h1>
            <p className="text-sm text-slate-400">
              Replaces legacy TrueNAS Kubernetes with lightweight K3s, WireGuard flannel mesh, and automatic 2-node HA cluster join.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleAutoJoin}
            disabled={joining}
            className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-semibold text-white flex items-center gap-2 transition"
          >
            <ArrowRightLeft className="w-3.5 h-3.5" />
            {joining ? 'Joining HA Peer Cluster...' : 'Auto-Join HA Peer Node'}
          </button>
          <button
            onClick={handleSaveConfig}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white transition"
          >
            Reconcile K3s Cluster
          </button>
        </div>
      </div>

      {msg && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300">
          {msg}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
          <span className="text-xs text-slate-400 block">Control Plane Status</span>
          <span className="text-lg font-bold text-emerald-400 font-mono mt-1 block">
            {status?.serviceActive ? 'ACTIVE (Ready)' : 'STANDBY'}
          </span>
        </div>
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
          <span className="text-xs text-slate-400 block">HA Cluster Role</span>
          <span className="text-lg font-bold text-white font-mono mt-1 block">
            {status?.role || 'primary-server'}
          </span>
        </div>
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
          <span className="text-xs text-slate-400 block">CNI Backend</span>
          <span className="text-lg font-bold text-sky-400 font-mono mt-1 block">
            {state?.k3s?.flannelBackend || 'wireguard-native'}
          </span>
        </div>
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
          <span className="text-xs text-slate-400 block">OpenEBS CSI Engine</span>
          <span className="text-lg font-bold text-emerald-400 font-mono mt-1 block">
            {status?.openEbsHealthy ? 'HEALTHY (2 Classes)' : 'PENDING'}
          </span>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-sm font-bold text-white">Cluster Nodes</h3>
          <span className="text-xs text-slate-400 font-mono">
            Auto-Join Endpoint: /api/v1/sync/k3s-token
          </span>
        </div>
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-[11px] font-semibold uppercase tracking-wider text-slate-400 bg-slate-950/60">
              <th className="py-3.5 px-4">Node Hostname</th>
              <th className="py-3.5 px-4">Roles</th>
              <th className="py-3.5 px-4">Internal IP</th>
              <th className="py-3.5 px-4">K3s Version</th>
              <th className="py-3.5 px-4">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70 text-xs">
            {(status?.nodes ?? []).map((n) => (
              <tr key={n.name} className="hover:bg-slate-800/40">
                <td className="py-3.5 px-4 font-mono text-white font-semibold">{n.name}</td>
                <td className="py-3.5 px-4 font-mono text-slate-300">{n.roles}</td>
                <td className="py-3.5 px-4 font-mono text-slate-300">{n.internalIp}</td>
                <td className="py-3.5 px-4 font-mono text-slate-400">{n.version}</td>
                <td className="py-3.5 px-4">
                  <span className="inline-flex items-center gap-1 text-emerald-400 font-semibold">
                    <CheckCircle2 className="w-3.5 h-3.5" /> {n.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
