'use client';

import { useState, useEffect } from 'react';
import { Cpu, ArrowRightLeft, CheckCircle2, RefreshCw, Database, RotateCcw } from 'lucide-react';
import {
  getCurrentDesiredState,
  getK3sRuntimeStatus,
  triggerK3sHaAutoJoin,
  getK3sEtcdSnapshotsAction,
  manageK3sEtcdSnapshotAction,
  type K3sRuntimeStatus,
  type K3sEtcdSnapshotItem,
} from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import type { DesiredState } from '@axonwall/lib/schemas';

export default function K3sClusterPage() {
  const { applyState } = useDesiredStateApply();
  const [state, setState] = useState<DesiredState | null>(null);
  const [status, setStatus] = useState<K3sRuntimeStatus | null>(null);
  const [etcdSnapshots, setEtcdSnapshots] = useState<K3sEtcdSnapshotItem[]>([]);
  const [snapName, setSnapName] = useState('');
  const [lbName, setLbName] = useState('bgp-pool-0');
  const [lbCidr, setLbCidr] = useState('192.168.1.240/28');
  const [lbMode, setLbMode] = useState<'bgp' | 'l2-arp' | 'both'>('both');
  const [msg, setMsg] = useState<string | null>(null);
  const [joining, setJoining] = useState(false);

  const load = async () => {
    try {
      const [st, rt, snaps] = await Promise.all([
        getCurrentDesiredState(),
        getK3sRuntimeStatus(),
        getK3sEtcdSnapshotsAction().catch(() => []),
      ]);
      setState(st);
      setStatus(rt);
      setEtcdSnapshots(snaps || []);
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
      virtEnabled: Boolean(next.capabilities?.virtEnabled ?? next.virt?.enabled),
      vigilanteEnabled: Boolean(next.capabilities?.vigilanteEnabled ?? next.vigilante?.enabled),
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
      enableUserNamespaces: false,
      bpfTokenProfiles: [],
      workloads: [],
    };
    next.k3s.enabled = true;
    // C2: a fingerprint mismatch (or any apply failure) must be visible,
    // not an unhandled rejection — the save did not happen.
    try {
      const res = await applyState(next);
      setState(next);
      setMsg(`K3s control plane configuration applied (${res.message})`);
    } catch (err: any) {
      setMsg(err?.message || 'Failed to save K3s configuration.');
    }
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
              Combines an enterprise grade NAS foundation with lightweight K3s, WireGuard flannel mesh, and automatic 2-node HA cluster join.
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
            {state?.k3s?.cniPlugin === 'cilium-ebpf'
              ? 'cilium-ebpf (kube-proxy-less)'
              : state?.k3s?.flannelBackend || 'wireguard-native'}
          </span>
        </div>
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
          <span className="text-xs text-slate-400 block">OpenEBS CSI Engine</span>
          <span className="text-lg font-bold text-emerald-400 font-mono mt-1 block">
            {status?.openEbsHealthy ? 'HEALTHY (2 Classes)' : 'PENDING'}
          </span>
        </div>
      </div>

      <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-bold text-white">
              Linux 6.9+ User Namespaces &amp; Unprivileged <code className="text-emerald-400 font-mono">BPF_TOKEN</code> Delegation
            </span>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
              K8s 1.33+ UserNamespacesSupport
            </span>
          </div>
          <p className="text-xs text-slate-400 max-w-3xl">
            Enables <code className="text-slate-200 font-mono">UserNamespacesSupport=true</code> across kube-apiserver and kubelet so{' '}
            <code className="text-slate-200 font-mono">hostUsers: false</code> pods can load safe networking eBPF programs via{' '}
            <code className="text-emerald-300 font-mono">LIBBPF_BPF_TOKEN_PATH=/sys/fs/bpf</code> while Axonwall CO-RE BPF-LSM blocks{' '}
            <code className="text-rose-300 font-mono">kprobe/tracepoint/lsm</code> Ring-0 memory reads.
          </p>
        </div>
        <label className="inline-flex items-center gap-2.5 px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 cursor-pointer shrink-0">
          <input
            type="checkbox"
            checked={Boolean(state?.k3s?.enableUserNamespaces)}
            onChange={(e) => {
              if (!state) return;
              const next = structuredClone(state);
              if (next.k3s) {
                next.k3s.enableUserNamespaces = e.target.checked;
                setState(next);
              }
            }}
            className="accent-emerald-500 w-4 h-4"
          />
          <span className="text-xs font-semibold text-slate-200">
            {state?.k3s?.enableUserNamespaces ? 'UserNS Enabled' : 'Enable UserNS'}
          </span>
        </label>
      </div>

      {/* CNI Engine & Embedded Etcd Disaster-Recovery Snapshots */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-bold text-white">CNI Dataplane Engine</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-sky-500/15 text-sky-300 border border-sky-500/30">
              Cilium eBPF + Hubble Ready
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Select Flannel WireGuard-Native mesh or full Cilium eBPF CNI (<code className="text-sky-300">--flannel-backend=none --disable-kube-proxy</code>) with socket-level Service LB and Hubble L7 flows.
          </p>
          <select
            value={state?.k3s?.cniPlugin || 'flannel'}
            onChange={(e) => {
              if (!state) return;
              const next = structuredClone(state);
              next.k3s = next.k3s || ({ enabled: true, flannelBackend: 'wireguard-native', disableTraefik: false, autoJoinHaPeer: true, enableUserNamespaces: true, bpfTokenProfiles: [], workloads: [], clusterCidr: '10.42.0.0/16', serviceCidr: '10.43.0.0/16', nodeIpInterface: 'lan' } as any);
              next.k3s!.cniPlugin = e.target.value as 'flannel' | 'cilium-ebpf';
              setState(next);
            }}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
          >
            <option value="flannel">Flannel WireGuard-Native (Encrypted Overlay)</option>
            <option value="cilium-ebpf">Cilium eBPF (Kube-Proxy Replacement + Hubble)</option>
          </select>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-bold text-white flex items-center gap-2">
              <Database className="w-4 h-4 text-emerald-400" />
              Embedded Etcd Snapshots &amp; Cluster Recovery
            </span>
            <span className="text-xs font-mono text-slate-400">{etcdSnapshots.length} snapshots</span>
          </div>
          <div className="flex gap-2">
            <input
              type="text"
              value={snapName}
              onChange={(e) => setSnapName(e.target.value)}
              placeholder="Snapshot name (e.g. pre-upgrade)"
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
            />
            <button
              type="button"
              onClick={async () => {
                const res = await manageK3sEtcdSnapshotAction('save', snapName.trim());
                setMsg(res.message);
                setSnapName('');
                await load();
              }}
              className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white"
            >
              Save Snapshot
            </button>
          </div>
          {etcdSnapshots.length > 0 && (
            <div className="max-h-28 overflow-y-auto space-y-1.5 pt-1">
              {etcdSnapshots.map((s) => (
                <div key={s.name} className="flex items-center justify-between text-xs bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5">
                  <span className="font-mono text-slate-200 truncate">{s.name}</span>
                  <button
                    type="button"
                    onClick={async () => {
                      if (!confirm(`Trigger K3s --cluster-reset-restore-path recovery from '${s.name}'?`)) return;
                      const res = await manageK3sEtcdSnapshotAction('restore', s.name);
                      setMsg(res.message);
                      await load();
                    }}
                    className="text-amber-300 hover:text-amber-200 inline-flex items-center gap-1 font-medium"
                  >
                    <RotateCcw className="w-3 h-3" /> Restore
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-bold text-white">
              Bare-Metal LoadBalancer IP Pools (Cilium LB-IPAM + FRR BGP Speaker)
            </h3>
            <p className="text-xs text-slate-400">
              Pools in <code className="font-mono text-sky-300">bgp</code> or <code className="font-mono text-sky-300">both</code> mode automatically peer Cilium with local FRRouting BGP (<code className="font-mono">127.0.0.1</code>) to advertise Service VIPs upstream.
            </p>
          </div>
          <label className="inline-flex items-center gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={state?.k3s?.etcdSnapshots?.enabled !== false}
              onChange={(e) => {
                if (!state) return;
                const next = structuredClone(state);
                if (next.k3s) {
                  next.k3s.etcdSnapshots = {
                    enabled: e.target.checked,
                    scheduleCron: next.k3s.etcdSnapshots?.scheduleCron || '0 */6 * * *',
                    retention: next.k3s.etcdSnapshots?.retention || 14,
                    snapshotDir: next.k3s.etcdSnapshots?.snapshotDir || '/var/lib/rancher/k3s/server/db/snapshots',
                    s3Enabled: next.k3s.etcdSnapshots?.s3Enabled || false,
                    s3Region: next.k3s.etcdSnapshots?.s3Region || 'us-east-1',
                  };
                  setState(next);
                }
              }}
              className="accent-emerald-500"
            />
            Scheduled Etcd Snapshots (6h Cron)
          </label>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
          <input
            type="text"
            value={lbName}
            onChange={(e) => setLbName(e.target.value)}
            placeholder="bgp-pool-0"
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
          />
          <input
            type="text"
            value={lbCidr}
            onChange={(e) => setLbCidr(e.target.value)}
            placeholder="192.168.1.240/28"
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
          />
          <select
            value={lbMode}
            onChange={(e) => setLbMode(e.target.value as 'bgp' | 'l2-arp' | 'both')}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
          >
            <option value="both">BGP + L2 ARP/NDP</option>
            <option value="bgp">BGP Only (FRR Peering)</option>
            <option value="l2-arp">L2 ARP/NDP Only</option>
          </select>
          <button
            type="button"
            onClick={() => {
              if (!state || !lbName.trim() || !lbCidr.trim()) return;
              const next = structuredClone(state);
              next.k3s = next.k3s || ({
                enabled: true,
                clusterCidr: '10.42.0.0/16',
                serviceCidr: '10.43.0.0/16',
                nodeIpInterface: 'lan',
                flannelBackend: 'wireguard-native',
                disableTraefik: false,
                autoJoinHaPeer: true,
                enableUserNamespaces: true,
                bpfTokenProfiles: [],
                workloads: [],
              } as any);
              const existingPools = next.k3s!.serviceLbPools ?? [];
              next.k3s!.serviceLbPools = [
                ...existingPools.filter((p) => p.name !== lbName.trim()),
                {
                  name: lbName.trim().toLowerCase(),
                  cidr: lbCidr.trim(),
                  mode: lbMode,
                  autoAssign: true,
                },
              ];
              setState(next);
              setMsg(`Staged ServiceLB pool '${lbName.trim()}' (${lbCidr.trim()}). Click Reconcile K3s Cluster to apply.`);
            }}
            className="px-3.5 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-semibold text-white"
          >
            Add ServiceLB Pool
          </button>
        </div>

        {(state?.k3s?.serviceLbPools ?? []).length > 0 && (
          <div className="flex flex-wrap gap-2 pt-1">
            {(state?.k3s?.serviceLbPools ?? []).map((p) => (
              <span
                key={p.name}
                className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-sky-300"
              >
                {p.name}: {p.cidr} ({p.mode})
                <button
                  type="button"
                  onClick={() => {
                    if (!state?.k3s) return;
                    const next = structuredClone(state);
                    if (next.k3s) {
                      next.k3s.serviceLbPools = (next.k3s.serviceLbPools ?? []).filter((x) => x.name !== p.name);
                      setState(next);
                    }
                  }}
                  className="text-slate-500 hover:text-rose-400"
                >
                  ✕
                </button>
              </span>
            ))}
          </div>
        )}
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
