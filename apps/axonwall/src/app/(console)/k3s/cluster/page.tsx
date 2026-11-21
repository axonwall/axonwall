'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Cpu,
  ArrowRightLeft,
  CheckCircle2,
  Database,
  RotateCcw,
  SlidersHorizontal,
  X,
  Plus,
  Trash2,
  ShieldAlert,
  Terminal,
  Network,
  Activity,
} from 'lucide-react';
import {
  getCurrentDesiredState,
  getK3sRuntimeStatus,
  triggerK3sHaAutoJoin,
  getK3sEtcdSnapshotsAction,
  manageK3sEtcdSnapshotAction,
  updateK3sNodeSchedulingAction,
  getK3sClusterPulseAction,
  type K3sRuntimeStatus,
  type K3sEtcdSnapshotItem,
  type K3sNodeTaintItem,
} from '@/server/agent';
import type { K3sClusterPulse } from '@/components/k3s/types';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import { executePluginAction } from '@/server/plugins';
import { K3sConfigSchema, type DesiredState } from '@axonwall/lib/schemas';

const SYSTEM_CONDITION_TAINT_KEYS = new Set([
  'node.kubernetes.io/not-ready',
  'node.kubernetes.io/unreachable',
  'node.kubernetes.io/disk-pressure',
  'node.kubernetes.io/memory-pressure',
  'node.kubernetes.io/pid-pressure',
  'node.kubernetes.io/network-unavailable',
  'node.kubernetes.io/unschedulable',
  'node.cloudprovider.kubernetes.io/uninitialized',
]);

const PROTECTED_LABEL_PREFIXES = [
  'kubernetes.io/',
  'beta.kubernetes.io/',
  'node.kubernetes.io/',
  'k3s.io/',
];

const MANAGED_ROLE_LABEL_KEYS = new Set([
  'node-role.kubernetes.io/control-plane',
  'node-role.kubernetes.io/master',
  'node-role.kubernetes.io/etcd',
  'node-role.kubernetes.io/edge',
  'node-role.kubernetes.io/worker',
  'node-role.kubernetes.io/storage',
  'axonwall.io/role',
  'svclb.k3s.cattle.io/enablelb',
]);

function isEditableCustomLabelKey(key: string): boolean {
  if (PROTECTED_LABEL_PREFIXES.some((p) => key.startsWith(p))) return false;
  if (MANAGED_ROLE_LABEL_KEYS.has(key)) return false;
  return true;
}

type K3sNodeItem = K3sRuntimeStatus['nodes'][number];

export default function K3sClusterPage() {
  const { applyState } = useDesiredStateApply();
  const [state, setState] = useState<DesiredState | null>(null);
  const [status, setStatus] = useState<K3sRuntimeStatus | null>(null);
  const [pulse, setPulse] = useState<K3sClusterPulse | null>(null);
  const [etcdSnapshots, setEtcdSnapshots] = useState<K3sEtcdSnapshotItem[]>([]);
  const [snapName, setSnapName] = useState('');
  const [lbName, setLbName] = useState('bgp-pool-0');
  const [lbCidr, setLbCidr] = useState('192.168.1.240/28');
  const [lbMode, setLbMode] = useState<'bgp' | 'l2-arp' | 'both'>('both');
  // C-L5: typed banner — errors render red, not emerald. Main fixed the
  // same finding with an { ok, text } banner; this file uses main's shape.
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [joining, setJoining] = useState(false);

  // Node Roles, Labels & Taints modal state
  const [editingNode, setEditingNode] = useState<K3sNodeItem | null>(null);
  const [editRoles, setEditRoles] = useState<string[]>([]);
  const [editEnableLb, setEditEnableLb] = useState<'auto' | 'true' | 'false'>('auto');
  const [editUnschedulable, setEditUnschedulable] = useState(false);
  const [editTaints, setEditTaints] = useState<K3sNodeTaintItem[]>([]);
  const [initialEditableTaints, setInitialEditableTaints] = useState<K3sNodeTaintItem[]>([]);
  const [newTaintKey, setNewTaintKey] = useState('');
  const [newTaintVal, setNewTaintVal] = useState('');
  const [newTaintEffect, setNewTaintEffect] = useState<'NoSchedule' | 'PreferNoSchedule' | 'NoExecute'>('NoSchedule');
  const [editCustomLabels, setEditCustomLabels] = useState<Record<string, string>>({});
  const [initialCustomLabelKeys, setInitialCustomLabelKeys] = useState<string[]>([]);
  const [newLabelKey, setNewLabelKey] = useState('');
  const [newLabelVal, setNewLabelVal] = useState('');
  const [modalError, setModalError] = useState<string | null>(null);
  const [savingNode, setSavingNode] = useState(false);

  const openNodeModal = (node: K3sNodeItem) => {
    const roleList = (node.roles || '')
      .split(',')
      .map((r) => r.trim().toLowerCase())
      .filter((r) => r === 'edge' || r === 'worker' || r === 'storage');
    const labels = node.labels || {};
    const lbVal = labels['svclb.k3s.cattle.io/enablelb'];
    const custom: Record<string, string> = {};
    for (const [k, v] of Object.entries(labels)) {
      if (isEditableCustomLabelKey(k)) {
        custom[k] = v;
      }
    }
    const editableTaints = (node.taints || []).filter(
      (t) => !SYSTEM_CONDITION_TAINT_KEYS.has(t.key)
    );

    setEditingNode(node);
    setEditRoles(roleList);
    setEditEnableLb(lbVal === 'true' ? 'true' : lbVal === 'false' ? 'false' : 'auto');
    setEditUnschedulable(Boolean(node.unschedulable));
    const clonedTaints = editableTaints.map((t) => ({ ...t }));
    setEditTaints(clonedTaints);
    setInitialEditableTaints(clonedTaints);
    setEditCustomLabels(custom);
    setInitialCustomLabelKeys(Object.keys(custom));
    setNewTaintKey('');
    setNewTaintVal('');
    setNewTaintEffect('NoSchedule');
    setNewLabelKey('');
    setNewLabelVal('');
    setModalError(null);
  };

  const applyPreset = (preset: 'edge' | 'worker-storage' | 'control-plane') => {
    setModalError(null);
    if (preset === 'edge') {
      setEditRoles(['edge']);
      setEditUnschedulable(false);
      setEditTaints([{ key: 'CriticalAddonsOnly', value: 'true', effect: 'NoExecute' }]);
    } else if (preset === 'worker-storage') {
      setEditRoles(['worker', 'storage']);
      setEditUnschedulable(false);
      setEditTaints((prev) =>
        prev.filter(
          (t) =>
            t.key !== 'CriticalAddonsOnly' &&
            t.key !== 'node-role.kubernetes.io/control-plane' &&
            t.key !== 'axonwall.io/edge'
        )
      );
    } else {
      setEditRoles([]);
      setEditUnschedulable(false);
      setEditTaints([{ key: 'node-role.kubernetes.io/control-plane', value: 'true', effect: 'NoSchedule' }]);
    }
  };

  const handleSaveNodeScheduling = async () => {
    if (!editingNode) return;
    setSavingNode(true);
    setModalError(null);
    try {
      const customLabels: Record<string, string> = { ...editCustomLabels };
      const removeLabels: string[] = initialCustomLabelKeys.filter(
        (k) => !(k in editCustomLabels)
      );
      if (editEnableLb === 'true' || editEnableLb === 'false') {
        customLabels['svclb.k3s.cattle.io/enablelb'] = editEnableLb;
      } else if (editingNode.labels && 'svclb.k3s.cattle.io/enablelb' in editingNode.labels) {
        removeLabels.push('svclb.k3s.cattle.io/enablelb');
      }

      const currentTaintSet = new Set(
        editTaints.map((t) => `${t.key}\0${t.value ?? ''}\0${t.effect}`)
      );
      const removeTaints: K3sNodeTaintItem[] = initialEditableTaints.filter(
        (t) => !currentTaintSet.has(`${t.key}\0${t.value ?? ''}\0${t.effect}`)
      );

      const res = await updateK3sNodeSchedulingAction({
        nodeName: editingNode.name,
        roles: editRoles,
        customLabels,
        removeLabels,
        taints: editTaints,
        removeTaints,
        unschedulable: editUnschedulable,
      });
      if (!res.success) {
        setModalError(res.message || 'Failed to update node scheduling.');
        return;
      }
      setMsg({ ok: true, text: res.message });
      setEditingNode(null);
      await load();
    } catch (err: any) {
      setModalError(err?.message || 'Failed to update node roles and taints.');
    } finally {
      setSavingNode(false);
    }
  };

  const load = async () => {
    try {
      const [st, rt, snaps, pl] = await Promise.all([
        getCurrentDesiredState(),
        getK3sRuntimeStatus(),
        getK3sEtcdSnapshotsAction().catch(() => []),
        getK3sClusterPulseAction().catch(() => null),
      ]);
      setState(st);
      setStatus(rt);
      setEtcdSnapshots(snaps || []);
      setPulse(pl);
    } catch (err: any) {
      setMsg({ ok: false, text: err?.message || 'Failed to load K3s runtime telemetry' });
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleAutoJoin = async () => {
    setJoining(true);
    setMsg(null);
    try {
      const res = await triggerK3sHaAutoJoin();
      setMsg({ ok: Boolean(res.success), text: res.message });
      await load();
    } catch (err: any) {
      setMsg({ ok: false, text: err?.message || 'HA cluster join failed' });
    } finally {
      setJoining(false);
    }
  };

  const handleSaveConfig = async () => {
    if (!state) return;
    const wasK3sEnabled = Boolean(state.capabilities?.k3sEnabled ?? state.k3s?.enabled);
    const next = structuredClone(state);
    next.capabilities = {
      firewallEnabled: next.capabilities?.firewallEnabled !== false,
      nasEnabled: Boolean(next.capabilities?.nasEnabled ?? next.nas?.enabled),
      k3sEnabled: true,
      virtEnabled: Boolean(next.capabilities?.virtEnabled ?? next.virt?.enabled),
      vigilanteEnabled: Boolean(next.capabilities?.vigilanteEnabled ?? next.vigilante?.enabled),
    };
    const nextPlugins = next.plugins ? [...next.plugins] : [];
    const k3sIdx = nextPlugins.findIndex((p) => p.id === 'core-k3s');
    if (k3sIdx >= 0) {
      nextPlugins[k3sIdx] = { ...nextPlugins[k3sIdx], id: 'core-k3s', enabled: true };
    } else {
      nextPlugins.push({ id: 'core-k3s', enabled: true });
    }
    next.plugins = nextPlugins;
    // C-M3: never invent a full K3s/OpenEBS config here. When no K3s
    // config exists yet, materialize the schema's own defaults (cluster /
    // service CIDRs, CNI) and leave openEbs unset — no pool names, replica
    // counts or forced replication the operator never chose. OpenEBS is
    // enabled from the Storage page, where the operator sees the values.
    next.k3s = next.k3s ? { ...next.k3s, enabled: true } : K3sConfigSchema.parse({ enabled: true });
    // C2: a fingerprint mismatch (or any apply failure) must be visible,
    // not an unhandled rejection — the save did not happen.
    try {
      if (!wasK3sEnabled) {
        const installRes = await executePluginAction('core-k3s', 'install');
        if (!installRes.success) {
          setMsg({
            ok: false,
            text: `Failed to install core-k3s binaries: ${installRes.message}`,
          });
          return;
        }
      }
      const res = await applyState(next);
      setState(next);
      setMsg({ ok: true, text: `K3s control plane configuration applied (${res.message})` });
      await load();
    } catch (err: any) {
      setMsg({ ok: false, text: err?.message || 'Failed to save K3s configuration.' });
    }
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

        <div className="flex flex-wrap items-center gap-2.5">
          <Link
            href="/k3s/explorer"
            className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-emerald-500/40 text-xs font-semibold text-emerald-300 flex items-center gap-2 transition"
          >
            <Terminal className="w-3.5 h-3.5" />
            Open K9s Live Explorer
          </Link>
          <Link
            href="/k3s/explorer?view=topology"
            className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-cyan-500/40 text-xs font-semibold text-cyan-300 flex items-center gap-2 transition"
          >
            <Network className="w-3.5 h-3.5" />
            Topology Map
          </Link>
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
        <div
          className={`p-4 rounded-xl border text-xs ${
            msg.ok
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
          }`}
        >
          {msg.text}
        </div>
      )}

      {status?.daemonDown && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-xs text-amber-300">
          Daemon unreachable — K3s cluster state is unknown. The control plane, nodes and storage below are not live data.
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
          <span className="text-xs text-slate-400 block">Control Plane Status</span>
          <span
            className={`text-lg font-bold font-mono mt-1 block ${
              status?.daemonDown ? 'text-slate-400' : 'text-emerald-400'
            }`}
          >
            {status?.daemonDown ? 'UNKNOWN' : status?.serviceActive ? 'ACTIVE (Ready)' : 'STANDBY'}
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
          <span
            className={`text-lg font-bold font-mono mt-1 block ${
              status?.daemonDown ? 'text-slate-400' : 'text-emerald-400'
            }`}
          >
            {status?.daemonDown ? 'UNKNOWN' : status?.openEbsHealthy ? 'HEALTHY (2 Classes)' : 'PENDING'}
          </span>
        </div>
      </div>

      {/* Live Cluster Visualization & Resource Inventory Strip */}
      {pulse?.available && (
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-emerald-400" />
              <span className="text-sm font-bold text-white">Live Cluster Pulse &amp; Workload Inventory</span>
              <span className="text-xs font-mono text-slate-400">
                ({pulse.counts.podsTotal} pods • ↻ {pulse.counts.totalRestarts} restarts)
              </span>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <Link
                href="/k3s/explorer?view=pulse"
                className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 hover:border-emerald-500/40 text-emerald-300 font-mono"
              >
                Full Pulse &amp; Charts →
              </Link>
              <Link
                href="/k3s/explorer?view=topology"
                className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/40 text-cyan-300 font-mono"
              >
                Traffic Topology →
              </Link>
            </div>
          </div>

          {/* Segmented Pod Health Bar */}
          {pulse.counts.podsTotal > 0 && (
            <div className="space-y-1.5">
              <div className="h-2.5 w-full rounded-full bg-slate-950 overflow-hidden flex border border-slate-800">
                {pulse.counts.podsRunning > 0 && (
                  <div
                    className="bg-emerald-500 h-full"
                    style={{ width: `${(pulse.counts.podsRunning / pulse.counts.podsTotal) * 100}%` }}
                    title={`Running: ${pulse.counts.podsRunning}`}
                  />
                )}
                {pulse.counts.podsPending > 0 && (
                  <div
                    className="bg-amber-500 h-full"
                    style={{ width: `${(pulse.counts.podsPending / pulse.counts.podsTotal) * 100}%` }}
                    title={`Pending: ${pulse.counts.podsPending}`}
                  />
                )}
                {pulse.counts.podsFailed + pulse.counts.podsUnknown > 0 && (
                  <div
                    className="bg-rose-500 h-full"
                    style={{
                      width: `${((pulse.counts.podsFailed + pulse.counts.podsUnknown) / pulse.counts.podsTotal) * 100}%`,
                    }}
                    title={`Failed/Unknown: ${pulse.counts.podsFailed + pulse.counts.podsUnknown}`}
                  />
                )}
                {pulse.counts.podsSucceeded > 0 && (
                  <div
                    className="bg-sky-500 h-full"
                    style={{ width: `${(pulse.counts.podsSucceeded / pulse.counts.podsTotal) * 100}%` }}
                    title={`Succeeded: ${pulse.counts.podsSucceeded}`}
                  />
                )}
              </div>
              <div className="flex flex-wrap gap-4 text-[11px] font-mono text-slate-400">
                <span className="text-emerald-400">● Running: {pulse.counts.podsRunning}</span>
                <span className="text-amber-300">● Pending: {pulse.counts.podsPending}</span>
                <span className="text-rose-400">● Failed/Unknown: {pulse.counts.podsFailed + pulse.counts.podsUnknown}</span>
                <span className="text-sky-400">● Succeeded: {pulse.counts.podsSucceeded}</span>
              </div>
            </div>
          )}

          {/* Clickable Resource Inventory Pills */}
          <div className="flex flex-wrap gap-2">
            {[
              { label: 'Deployments', val: `${pulse.counts.deploymentsReady}/${pulse.counts.deploymentsTotal}`, res: 'deployments', cls: 'text-emerald-300' },
              { label: 'StatefulSets', val: `${pulse.counts.statefulSetsReady}/${pulse.counts.statefulSetsTotal}`, res: 'statefulsets', cls: 'text-sky-300' },
              { label: 'DaemonSets', val: `${pulse.counts.daemonSetsReady}/${pulse.counts.daemonSetsTotal}`, res: 'daemonsets', cls: 'text-sky-300' },
              { label: 'Services', val: String(pulse.counts.servicesTotal), res: 'services', cls: 'text-cyan-300' },
              { label: 'Ingresses', val: String(pulse.counts.ingressesTotal), res: 'ingresses', cls: 'text-cyan-300' },
              { label: 'PVCs Bound', val: `${pulse.counts.pvcsBound}/${pulse.counts.pvcsTotal}`, res: 'persistentvolumeclaims', cls: 'text-amber-300' },
              { label: 'Warning Events', val: String(pulse.counts.warningEventsCount), res: 'events', cls: pulse.counts.warningEventsCount > 0 ? 'text-amber-300' : 'text-slate-300' },
            ].map((pill) => (
              <Link
                key={pill.res}
                href={`/k3s/explorer?resource=${pill.res}`}
                className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-emerald-500/40 text-xs font-mono transition"
              >
                <span className="text-slate-400">{pill.label}: </span>
                <span className={`font-bold ${pill.cls}`}>{pill.val}</span>
              </Link>
            ))}
          </div>
        </div>
      )}

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
              next.k3s = next.k3s || K3sConfigSchema.parse({ enabled: true });
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
                try {
                  const res = await manageK3sEtcdSnapshotAction('save', snapName.trim());
                  setMsg({ ok: res.success, text: res.message });
                  if (res.success) {
                    setSnapName('');
                  }
                  await load();
                } catch (err: any) {
                  setMsg({ ok: false, text: err?.message || 'Failed to save etcd snapshot' });
                }
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
                      try {
                        const res = await manageK3sEtcdSnapshotAction('restore', s.name);
                        setMsg({ ok: res.success, text: res.message });
                        await load();
                      } catch (err: any) {
                        setMsg({ ok: false, text: err?.message || `Failed to restore etcd snapshot '${s.name}'` });
                      }
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
              // C-M3: staging a pool must not invent a cluster config.
              next.k3s = next.k3s || K3sConfigSchema.parse({ enabled: true });
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
              setMsg({
                ok: true,
                text: `Staged ServiceLB pool '${lbName.trim()}' (${lbCidr.trim()}). Click Reconcile K3s Cluster to apply.`,
              });
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
              <th className="py-3.5 px-4">Taints</th>
              <th className="py-3.5 px-4">Internal IP</th>
              <th className="py-3.5 px-4">Capacity &amp; Allocation</th>
              <th className="py-3.5 px-4">K3s Version</th>
              <th className="py-3.5 px-4">Status</th>
              <th className="py-3.5 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70 text-xs">
            {(status?.nodes ?? []).map((n) => {
              const roleTokens = (n.roles || '')
                .split(',')
                .map((r) => r.trim())
                .filter(Boolean);
              const taints = n.taints ?? [];
              const np = pulse?.nodes?.find((p) => p.name === n.name);
              const cpuPct =
                np && np.cpuAllocatableMillis > 0
                  ? Math.min(100, Math.round((((np.cpuUsageMillis ?? np.cpuRequestsMillis) || 0) / np.cpuAllocatableMillis) * 100))
                  : 0;
              const memPct =
                np && np.memAllocatableBytes > 0
                  ? Math.min(100, Math.round((((np.memUsageBytes ?? np.memRequestsBytes) || 0) / np.memAllocatableBytes) * 100))
                  : 0;
              return (
                <tr key={n.name} className="hover:bg-slate-800/40">
                  <td className="py-3.5 px-4 font-mono text-white font-semibold">
                    <div className="flex items-center gap-2">
                      <span>{n.name}</span>
                      {n.unschedulable && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-300 text-[10px] font-semibold">
                          CORDONED
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-3.5 px-4">
                    <div className="flex flex-wrap gap-1">
                      {roleTokens.map((role) => {
                        const badgeClass =
                          role === 'edge'
                            ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                            : role === 'control-plane' || role === 'master' || role === 'etcd'
                            ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                            : 'bg-sky-500/15 border-sky-500/30 text-sky-300';
                        return (
                          <span
                            key={role}
                            className={`px-2 py-0.5 rounded border text-[10px] font-mono ${badgeClass}`}
                          >
                            {role}
                          </span>
                        );
                      })}
                    </div>
                  </td>
                  <td className="py-3.5 px-4">
                    {taints.length === 0 ? (
                      <span className="text-slate-500 font-mono">&lt;none&gt;</span>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {taints.map((t, idx) => (
                          <span
                            key={`${t.key}-${t.effect}-${idx}`}
                            className="px-2 py-0.5 rounded bg-slate-950 border border-slate-700 text-amber-200 text-[10px] font-mono"
                          >
                            {t.value ? `${t.key}=${t.value}:${t.effect}` : `${t.key}:${t.effect}`}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="py-3.5 px-4 font-mono text-slate-300">{n.internalIp}</td>
                  <td className="py-3.5 px-4 min-w-[170px]">
                    {np ? (
                      <div className="space-y-1 text-[10px] font-mono text-slate-400">
                        <div className="flex items-center gap-2">
                          <span className="w-7">CPU</span>
                          <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div className="h-full bg-emerald-500" style={{ width: `${cpuPct}%` }} />
                          </div>
                          <span className="text-slate-200 w-7 text-right">{cpuPct}%</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="w-7">MEM</span>
                          <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div className="h-full bg-sky-500" style={{ width: `${memPct}%` }} />
                          </div>
                          <span className="text-slate-200 w-7 text-right">{memPct}%</span>
                        </div>
                        <div className="text-slate-400">
                          Pods: <span className="text-slate-200">{np.podCount}/{np.podCapacity || '—'}</span>
                        </div>
                      </div>
                    ) : (
                      <span className="text-slate-500 font-mono">—</span>
                    )}
                  </td>
                  <td className="py-3.5 px-4 font-mono text-slate-400">{n.version}</td>
                  <td className="py-3.5 px-4">
                    <span
                      className={`inline-flex items-center gap-1 font-semibold ${
                        n.status === 'Ready' ? 'text-emerald-400' : 'text-amber-400'
                      }`}
                    >
                      {n.status === 'Ready' ? <CheckCircle2 className="w-3.5 h-3.5" /> : null} {n.status}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-right whitespace-nowrap">
                    <div className="inline-flex items-center gap-1.5">
                      <Link
                        href={`/k3s/explorer?resource=nodes&name=${encodeURIComponent(n.name)}`}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-emerald-300 text-xs font-medium transition"
                      >
                        <Terminal className="w-3.5 h-3.5" />
                        Inspect
                      </Link>
                      <button
                        type="button"
                        onClick={() => openNodeModal(n)}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium transition"
                      >
                        <SlidersHorizontal className="w-3.5 h-3.5 text-sky-400" />
                        Roles &amp; Taints
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {status?.daemonDown && (status?.nodes ?? []).length === 0 && (
              <tr>
                <td colSpan={8} className="py-8 px-4 text-center text-slate-500">
                  Cluster nodes unknown — daemon unreachable.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {editingNode && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-2xl bg-slate-900 border border-slate-700 shadow-2xl">
            <div className="flex items-start justify-between gap-4 p-5 border-b border-slate-800">
              <div className="space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-base font-bold text-white font-mono">
                    {editingNode.name}
                  </h2>
                  {(editingNode.roles || '')
                    .split(',')
                    .map((r) => r.trim())
                    .filter((r) => r === 'control-plane' || r === 'etcd' || r === 'master')
                    .map((r) => (
                      <span
                        key={r}
                        className="px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-[10px] font-mono"
                      >
                        {r} (immutable)
                      </span>
                    ))}
                </div>
                <p className="text-xs text-slate-400 font-mono">
                  {editingNode.internalIp} • {editingNode.version}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setEditingNode(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-5 text-xs">
              {modalError && (
                <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300">
                  {modalError}
                </div>
              )}

              {/* Presets */}
              <div className="space-y-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block">
                  Workload Placement Presets
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <button
                    type="button"
                    onClick={() => applyPreset('edge')}
                    className="p-2.5 rounded-xl bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-left transition"
                  >
                    <div className="font-semibold text-amber-300">Edge Node (Networking)</div>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      role=edge + CriticalAddonsOnly:NoExecute
                    </div>
                  </button>
                  <button
                    type="button"
                    onClick={() => applyPreset('worker-storage')}
                    className="p-2.5 rounded-xl bg-sky-500/10 hover:bg-sky-500/20 border border-sky-500/30 text-left transition"
                  >
                    <div className="font-semibold text-sky-300">Worker + Storage</div>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      worker,storage roles • Clear scheduling taints
                    </div>
                  </button>
                  <button
                    type="button"
                    onClick={() => applyPreset('control-plane')}
                    className="p-2.5 rounded-xl bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-left transition"
                  >
                    <div className="font-semibold text-emerald-300">Control-Plane Dedicated</div>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      control-plane=true:NoSchedule
                    </div>
                  </button>
                </div>
                <p className="text-[11px] text-slate-400">
                  Note: K3s CoreDNS, Traefik, Cilium, and Klipper ServiceLB tolerate{' '}
                  <code className="text-amber-300 font-mono">CriticalAddonsOnly</code>, keeping edge
                  networking active while scheduling general jobs and apps off edge nodes.
                </p>
              </div>

              {/* Roles & Cordon */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1 border-t border-slate-800">
                <div className="space-y-2">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block">
                    Adjustable Roles
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {(['edge', 'worker', 'storage'] as const).map((r) => {
                      const active = editRoles.includes(r);
                      return (
                        <label
                          key={r}
                          className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border cursor-pointer ${
                            active
                              ? 'bg-sky-500/15 border-sky-500/40 text-sky-200'
                              : 'bg-slate-950 border-slate-800 text-slate-400'
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={active}
                            onChange={(e) => {
                              setEditRoles((prev) =>
                                e.target.checked
                                  ? Array.from(new Set([...prev, r]))
                                  : prev.filter((x) => x !== r)
                              );
                            }}
                            className="accent-sky-500"
                          />
                          <span className="font-mono">{r}</span>
                        </label>
                      );
                    })}
                  </div>
                </div>

                <div className="space-y-2">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block">
                    ServiceLB &amp; Cordon Controls
                  </span>
                  <div className="flex flex-col gap-2">
                    <select
                      value={editEnableLb}
                      onChange={(e) => setEditEnableLb(e.target.value as 'auto' | 'true' | 'false')}
                      className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 font-mono"
                    >
                      <option value="auto">ServiceLB: Auto (svclb.k3s.cattle.io/enablelb unset)</option>
                      <option value="true">ServiceLB: Pin Enabled (true)</option>
                      <option value="false">ServiceLB: Exclude (false)</option>
                    </select>
                    <label className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 cursor-pointer text-slate-200">
                      <input
                        type="checkbox"
                        checked={editUnschedulable}
                        onChange={(e) => setEditUnschedulable(e.target.checked)}
                        className="accent-amber-500"
                      />
                      <span>Cordon Node (<code className="font-mono text-amber-300">spec.unschedulable</code>)</span>
                    </label>
                  </div>
                </div>
              </div>

              {/* Taints */}
              <div className="space-y-2.5 pt-2 border-t border-slate-800">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block">
                  Kubernetes Taints
                </span>

                {(editingNode.taints ?? []).some((t) => SYSTEM_CONDITION_TAINT_KEYS.has(t.key)) && (
                  <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-2 text-[11px] text-slate-400">
                    <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="text-slate-300 font-semibold">System condition taints preserved:</span>{' '}
                      {(editingNode.taints ?? [])
                        .filter((t) => SYSTEM_CONDITION_TAINT_KEYS.has(t.key))
                        .map((t) => `${t.key}:${t.effect}`)
                        .join(', ')}
                    </div>
                  </div>
                )}

                <div className="space-y-1.5">
                  {editTaints.length === 0 ? (
                    <div className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-500 font-mono">
                      No custom/operator taints configured.
                    </div>
                  ) : (
                    editTaints.map((t, idx) => (
                      <div
                        key={`${t.key}-${idx}`}
                        className="flex items-center justify-between gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800"
                      >
                        <span className="font-mono text-amber-200 truncate">
                          {t.value ? `${t.key}=${t.value}` : t.key}
                        </span>
                        <div className="flex items-center gap-2 shrink-0">
                          <select
                            value={t.effect}
                            onChange={(e) => {
                              const eff = e.target.value as 'NoSchedule' | 'PreferNoSchedule' | 'NoExecute';
                              setEditTaints((prev) =>
                                prev.map((item, i) => (i === idx ? { ...item, effect: eff } : item))
                              );
                            }}
                            className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-[11px] font-mono text-slate-200"
                          >
                            <option value="NoSchedule">NoSchedule</option>
                            <option value="PreferNoSchedule">PreferNoSchedule</option>
                            <option value="NoExecute">NoExecute</option>
                          </select>
                          <button
                            type="button"
                            onClick={() =>
                              setEditTaints((prev) => prev.filter((_, i) => i !== idx))
                            }
                            className="p-1 text-slate-400 hover:text-rose-400"
                            title="Remove taint"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-12 gap-2">
                  <input
                    type="text"
                    value={newTaintKey}
                    onChange={(e) => setNewTaintKey(e.target.value)}
                    placeholder="Key (e.g. CriticalAddonsOnly)"
                    className="sm:col-span-5 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-white font-mono"
                  />
                  <input
                    type="text"
                    value={newTaintVal}
                    onChange={(e) => setNewTaintVal(e.target.value)}
                    placeholder="Value (optional)"
                    className="sm:col-span-3 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-white font-mono"
                  />
                  <select
                    value={newTaintEffect}
                    onChange={(e) =>
                      setNewTaintEffect(e.target.value as 'NoSchedule' | 'PreferNoSchedule' | 'NoExecute')
                    }
                    className="sm:col-span-2 bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-white font-mono"
                  >
                    <option value="NoSchedule">NoSchedule</option>
                    <option value="PreferNoSchedule">PreferNoSchedule</option>
                    <option value="NoExecute">NoExecute</option>
                  </select>
                  <button
                    type="button"
                    onClick={() => {
                      const key = newTaintKey.trim();
                      if (!key) return;
                      if (SYSTEM_CONDITION_TAINT_KEYS.has(key)) {
                        setModalError(`System condition taint '${key}' is managed automatically by Kubernetes.`);
                        return;
                      }
                      setModalError(null);
                      setEditTaints((prev) => [
                        ...prev.filter((t) => !(t.key === key && t.effect === newTaintEffect)),
                        { key, value: newTaintVal.trim(), effect: newTaintEffect },
                      ]);
                      setNewTaintKey('');
                      setNewTaintVal('');
                    }}
                    className="sm:col-span-2 inline-flex items-center justify-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-semibold"
                  >
                    <Plus className="w-3.5 h-3.5" /> Add
                  </button>
                </div>
              </div>

              {/* Custom Labels */}
              <div className="space-y-2.5 pt-2 border-t border-slate-800">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block">
                  Custom Node Labels
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(editCustomLabels).length === 0 ? (
                    <span className="text-slate-500 font-mono">No custom user labels set.</span>
                  ) : (
                    Object.entries(editCustomLabels).map(([k, v]) => (
                      <span
                        key={k}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 font-mono text-sky-300"
                      >
                        {k}={v}
                        <button
                          type="button"
                          onClick={() => {
                            setEditCustomLabels((prev) => {
                              const next = { ...prev };
                              delete next[k];
                              return next;
                            });
                          }}
                          className="text-slate-500 hover:text-rose-400"
                        >
                          ✕
                        </button>
                      </span>
                    ))
                  )}
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-12 gap-2">
                  <input
                    type="text"
                    value={newLabelKey}
                    onChange={(e) => setNewLabelKey(e.target.value)}
                    placeholder="Label key (e.g. topology.kubernetes.io/zone)"
                    className="sm:col-span-6 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-white font-mono"
                  />
                  <input
                    type="text"
                    value={newLabelVal}
                    onChange={(e) => setNewLabelVal(e.target.value)}
                    placeholder="Value"
                    className="sm:col-span-4 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-white font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => {
                      const k = newLabelKey.trim();
                      if (!k) return;
                      if (!isEditableCustomLabelKey(k)) {
                        setModalError(`Label key '${k}' is protected or managed via role controls above.`);
                        return;
                      }
                      setModalError(null);
                      setEditCustomLabels((prev) => ({ ...prev, [k]: newLabelVal.trim() }));
                      setNewLabelKey('');
                      setNewLabelVal('');
                    }}
                    className="sm:col-span-2 inline-flex items-center justify-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-semibold"
                  >
                    <Plus className="w-3.5 h-3.5" /> Add
                  </button>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 p-5 border-t border-slate-800 bg-slate-950/60">
              <button
                type="button"
                onClick={() => setEditingNode(null)}
                disabled={savingNode}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSaveNodeScheduling}
                disabled={savingNode}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white"
              >
                {savingNode ? 'Applying...' : `Apply to ${editingNode.name}`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
