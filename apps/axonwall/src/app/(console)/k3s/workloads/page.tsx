'use client';

import { useState, useEffect, useMemo } from 'react';
import Link from 'next/link';
import { Boxes, Plus, Trash2, Globe, Activity, Terminal, RefreshCw, Network, Search } from 'lucide-react';
import { getCurrentDesiredState, getK3sClusterPulseAction } from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import type { DesiredState, K3sWorkloadSpec } from '@axonwall/lib/schemas';
import { formatAge, type K3sClusterPulse } from '@/components/k3s/types';
import { K3sWorkloadsVisuals } from '@/components/k3s/K3sWorkloadsVisuals';

export default function K3sWorkloadsPage() {
  const { applyState } = useDesiredStateApply();
  const [state, setState] = useState<DesiredState | null>(null);
  const [pulse, setPulse] = useState<K3sClusterPulse | null>(null);
  const [liveTab, setLiveTab] = useState<'workloads' | 'services' | 'ingresses'>('workloads');
  const [refreshingLive, setRefreshingLive] = useState(false);
  const [selectedNs, setSelectedNs] = useState<string>('_all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [zeroEndpointsOnly, setZeroEndpointsOnly] = useState<boolean>(false);
  const [name, setName] = useState('minio-s3');
  const [image, setImage] = useState('quay.io/minio/minio:latest');
  const [port, setPort] = useState(9000);
  const [serviceType, setServiceType] = useState<NonNullable<K3sWorkloadSpec['serviceType']>>('ClusterIP');
  const [ingressHostname, setIngressHostname] = useState('');
  const [exposeViaHaproxy, setExposeViaHaproxy] = useState(true);
  const [storageClass, setStorageClass] = useState<'axonwall-replicated-ha' | 'axonwall-zfs-local' | 'none'>('axonwall-replicated-ha');
  const [storageSizeGb, setStorageSizeGb] = useState(50);

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
    getCurrentDesiredState().then(setState).catch(() => {});
    loadLive();
  }, []);

  const filteredWorkloads = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return (pulse?.workloadsSummary || []).filter((w) => {
      if (selectedNs !== '_all' && (w.namespace || 'default') !== selectedNs) return false;
      if (
        q &&
        !w.name.toLowerCase().includes(q) &&
        !(w.namespace || '').toLowerCase().includes(q) &&
        !w.kind.toLowerCase().includes(q)
      ) {
        return false;
      }
      return true;
    });
  }, [pulse?.workloadsSummary, selectedNs, searchQuery]);

  const filteredServices = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return (pulse?.servicesSummary || []).filter((sv) => {
      if (selectedNs !== '_all' && (sv.namespace || 'default') !== selectedNs) return false;
      if (zeroEndpointsOnly && sv.readyEndpoints !== 0) return false;
      if (
        q &&
        !sv.name.toLowerCase().includes(q) &&
        !(sv.namespace || '').toLowerCase().includes(q) &&
        !sv.type.toLowerCase().includes(q)
      ) {
        return false;
      }
      return true;
    });
  }, [pulse?.servicesSummary, selectedNs, searchQuery, zeroEndpointsOnly]);

  const filteredIngresses = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return (pulse?.ingressesSummary || []).filter((ing) => {
      if (selectedNs !== '_all' && (ing.namespace || 'default') !== selectedNs) return false;
      if (
        q &&
        !ing.name.toLowerCase().includes(q) &&
        !(ing.namespace || '').toLowerCase().includes(q) &&
        !(ing.hosts || []).join(',').toLowerCase().includes(q)
      ) {
        return false;
      }
      return true;
    });
  }, [pulse?.ingressesSummary, selectedNs, searchQuery]);

  const addWorkload = async () => {
    if (!state || !name.trim()) return;
    const next = structuredClone(state);
    // C-M3: deploying a workload cannot invent a whole K3s/OpenEBS cluster
    // config (CIDRs, pools, replica counts) on a box with no K3s
    // configuration. Enable K3s from the Cluster page first.
    if (!next.k3s) {
      alert('K3s is not configured yet — enable it from the Cluster page first. A workload cannot create a cluster configuration on its own.');
      return;
    }
    // C-M4: replacing an existing workload must be an explicit operator
    // choice, not a silent upsert.
    if (
      next.k3s.workloads.some((w) => w.name === name.trim()) &&
      !confirm(`Workload "${name.trim()}" already exists in the configuration and will be replaced with the new definition. Continue?`)
    ) {
      return;
    }
    const trimmedIngress = ingressHostname.trim();
    next.k3s.workloads = [
      ...next.k3s.workloads.filter((w) => w.name !== name.trim()),
      {
        name: name.trim(),
        namespace: 'default',
        image: image.trim(),
        replicas: 1,
        port,
        serviceType,
        ...(trimmedIngress ? { ingressHostname: trimmedIngress, exposeViaHaproxy } : {}),
        storageClass,
        storageSizeGb,
        mountPath: '/data',
        enabled: true,
      },
    ];
    try {
      await applyState(next);
      setState(next);
      setIngressHostname('');
    } catch (err: any) {
      alert(err?.message || 'Failed to add workload.');
    }
  };

  const removeWorkload = async (wlName: string) => {
    if (!state?.k3s) return;
    const next = structuredClone(state);
    if (next.k3s) {
      next.k3s.workloads = next.k3s.workloads.filter((w) => w.name !== wlName);
    }
    try {
      await applyState(next);
      setState(next);
    } catch (err: any) {
      alert(err?.message || 'Failed to remove workload.');
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Boxes className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">K3s Workloads &amp; Converged Ingress</h1>
            <p className="text-sm text-slate-400">
              Deploy stateful apps backed by OpenEBS ZFS PVCs with automatic Unbound split-DNS &amp; HAProxy TLS SNI/Host routing.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2.5">
          <Link
            href="/k3s/explorer"
            className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-emerald-500/40 text-xs font-semibold text-emerald-300 flex items-center gap-1.5 transition"
          >
            <Terminal className="w-3.5 h-3.5" /> Open K9s Explorer
          </Link>
          <Link
            href="/k3s/explorer?view=topology"
            className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-cyan-500/40 text-xs font-semibold text-cyan-300 flex items-center gap-1.5 transition"
          >
            <Network className="w-3.5 h-3.5" /> Ingress Topology
          </Link>
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

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Kubernetes Service Type</label>
            <select
              value={serviceType}
              onChange={(e) => setServiceType(e.target.value as NonNullable<K3sWorkloadSpec['serviceType']>)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
            >
              <option value="ClusterIP">ClusterIP (Internal / Ingress)</option>
              <option value="LoadBalancer">LoadBalancer (Cilium LB-IPAM + FRR BGP)</option>
              <option value="NodePort">NodePort</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Converged Ingress Hostname (optional)</label>
            <input
              type="text"
              value={ingressHostname}
              onChange={(e) => setIngressHostname(e.target.value)}
              placeholder="s3.axonwall.local"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
            />
          </div>
          <div className="flex items-end pb-2">
            <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={exposeViaHaproxy}
                onChange={(e) => setExposeViaHaproxy(e.target.checked)}
              />
              Auto-register Unbound DNS + HAProxy TLS Backend
            </label>
          </div>
        </div>

        <button
          onClick={addWorkload}
          className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white"
        >
          Save Workload Configuration
        </button>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-3">
        <h3 className="text-sm font-bold text-white">Declarative Config Workloads (/etc/axonwall/k3s.yaml)</h3>
        <p className="text-[11px] text-slate-500">
          Desired-state entries only — deployment status is not checked against the live cluster.
        </p>
        {(state?.k3s?.workloads ?? []).length === 0 ? (
          <p className="text-xs text-slate-500">No declarative workloads configured yet.</p>
        ) : (
          <div className="space-y-2">
            {(state?.k3s?.workloads ?? []).map((w) => (
              <div key={w.name} className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono font-bold text-white">{w.name}</span>
                  <span className="text-slate-400 font-mono">({w.image})</span>
                  {w.serviceType && w.serviceType !== 'ClusterIP' && (
                    <span className="px-2 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/30 font-mono text-[10px]">
                      {w.serviceType}
                    </span>
                  )}
                  {w.ingressHostname && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-mono text-[10px]">
                      <Globe className="w-3 h-3" /> {w.ingressHostname}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-4">
                  <span className="font-mono text-emerald-400">
                    {w.storageClass} ({w.storageSizeGb}Gi)
                  </span>
                  <Link
                    href={`/k3s/explorer?resource=deployments&namespace=${encodeURIComponent(w.namespace || 'default')}&name=${encodeURIComponent(w.name)}`}
                    className="text-sky-400 hover:underline font-mono text-[11px]"
                  >
                    Inspect →
                  </Link>
                  <button onClick={() => removeWorkload(w.name)} className="text-rose-400 hover:text-rose-300">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Live Cluster Workloads & Ingress Visualizations */}
      {pulse?.available && (
        <K3sWorkloadsVisuals
          pulse={pulse}
          selectedNs={selectedNs}
          onSelectNamespace={setSelectedNs}
          onShowZeroEndpointServices={() => {
            setLiveTab('services');
            setZeroEndpointsOnly((prev) => !prev);
          }}
        />
      )}

      {/* Live Cluster Workloads, Services & Ingresses Inspector */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-bold text-white">Live Cluster Inventory</h3>
            {pulse?.available && (
              <span className="text-[11px] font-mono text-slate-400">
                ({pulse.counts.podsRunning}/{pulse.counts.podsTotal} pods running)
              </span>
            )}
            {selectedNs !== '_all' && (
              <button
                type="button"
                onClick={() => setSelectedNs('_all')}
                className="px-2 py-0.5 rounded bg-sky-500/15 border border-sky-500/30 text-[11px] font-mono text-sky-300 hover:text-white"
              >
                ns: {selectedNs} ✕
              </button>
            )}
            {zeroEndpointsOnly && (
              <button
                type="button"
                onClick={() => setZeroEndpointsOnly(false)}
                className="px-2 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-[11px] font-mono text-amber-300 hover:text-white"
              >
                0-Endpoint Services ✕
              </button>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter rows..."
                className="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-xs text-white placeholder-slate-400 font-mono w-40"
              />
            </div>
            <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-xs">
              {(
                [
                  { id: 'workloads', label: `Workloads (${filteredWorkloads.length})` },
                  { id: 'services', label: `Services (${filteredServices.length})` },
                  { id: 'ingresses', label: `Ingresses (${filteredIngresses.length})` },
                ] as const
              ).map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setLiveTab(t.id)}
                  className={`px-3 py-1 rounded-md font-mono text-[11px] transition ${
                    liveTab === t.id ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
            <button
              type="button"
              onClick={loadLive}
              className="p-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 hover:text-white"
              title="Refresh Live Inventory"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshingLive ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {!pulse?.available ? (
          <div className="p-6 text-xs font-mono text-slate-400">
            {pulse?.error || 'Live cluster inventory unavailable until k3s.service answers.'}
          </div>
        ) : liveTab === 'workloads' ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs font-mono">
              <thead className="bg-slate-950/70 text-[10px] uppercase text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-4">Namespace</th>
                  <th className="py-2.5 px-4">Workload</th>
                  <th className="py-2.5 px-4">Kind</th>
                  <th className="py-2.5 px-4">Readiness</th>
                  <th className="py-2.5 px-4">Images</th>
                  <th className="py-2.5 px-4">Age</th>
                  <th className="py-2.5 px-4 text-right">K9s</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredWorkloads.map((w) => {
                  const pct = w.desired > 0 ? Math.min(100, Math.round((w.ready / w.desired) * 100)) : 100;
                  return (
                    <tr key={`${w.kind}/${w.namespace}/${w.name}`} className="hover:bg-slate-800/40">
                      <td className="py-2.5 px-4 text-slate-400">{w.namespace}</td>
                      <td className="py-2.5 px-4 text-white font-semibold">{w.name}</td>
                      <td className="py-2.5 px-4 text-sky-300">{w.kind}</td>
                      <td className="py-2.5 px-4 min-w-[130px]">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full ${pct >= 100 ? 'bg-emerald-500' : 'bg-amber-500'}`}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                          <span className={pct >= 100 ? 'text-emerald-300' : 'text-amber-300'}>
                            {w.ready}/{w.desired}
                          </span>
                        </div>
                      </td>
                      <td className="py-2.5 px-4 text-slate-400 max-w-xs truncate">
                        {(w.images || []).join(', ') || '—'}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400">{formatAge(w.creationTimestamp)}</td>
                      <td className="py-2.5 px-4 text-right whitespace-nowrap space-x-2">
                        <Link
                          href={`/k3s/explorer?resource=${encodeURIComponent(w.resource)}&namespace=${encodeURIComponent(w.namespace)}&name=${encodeURIComponent(w.name)}`}
                          className="text-sky-400 hover:underline"
                        >
                          Inspect
                        </Link>
                        <Link
                          href={`/k3s/explorer?resource=${encodeURIComponent(w.resource)}&namespace=${encodeURIComponent(w.namespace)}&name=${encodeURIComponent(w.name)}&tab=logs`}
                          className="text-emerald-400 hover:underline"
                        >
                          Logs
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : liveTab === 'services' ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs font-mono">
              <thead className="bg-slate-950/70 text-[10px] uppercase text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-4">Namespace</th>
                  <th className="py-2.5 px-4">Service</th>
                  <th className="py-2.5 px-4">Type</th>
                  <th className="py-2.5 px-4">ClusterIP / ExternalIP</th>
                  <th className="py-2.5 px-4">Ports</th>
                  <th className="py-2.5 px-4">Endpoints</th>
                  <th className="py-2.5 px-4 text-right">K9s</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredServices.map((sv) => (
                  <tr key={`${sv.namespace}/${sv.name}`} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-4 text-slate-400">{sv.namespace}</td>
                    <td className="py-2.5 px-4 text-white font-semibold">{sv.name}</td>
                    <td className="py-2.5 px-4 text-sky-300">{sv.type}</td>
                    <td className="py-2.5 px-4 text-slate-300">
                      {sv.clusterIP}
                      {sv.externalIP ? ` • ${sv.externalIP}` : ''}
                    </td>
                    <td className="py-2.5 px-4 text-slate-300">{(sv.ports || []).join(', ') || '—'}</td>
                    <td className={`py-2.5 px-4 ${sv.readyEndpoints > 0 ? 'text-emerald-400' : 'text-amber-300'}`}>
                      {sv.readyEndpoints} ready
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <Link
                        href={`/k3s/explorer?resource=services&namespace=${encodeURIComponent(sv.namespace)}&name=${encodeURIComponent(sv.name)}`}
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
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs font-mono">
              <thead className="bg-slate-950/70 text-[10px] uppercase text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-4">Namespace</th>
                  <th className="py-2.5 px-4">Ingress</th>
                  <th className="py-2.5 px-4">Class / TLS</th>
                  <th className="py-2.5 px-4">Hosts</th>
                  <th className="py-2.5 px-4">Backends</th>
                  <th className="py-2.5 px-4">Address</th>
                  <th className="py-2.5 px-4 text-right">K9s</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredIngresses.map((ing) => (
                  <tr key={`${ing.namespace}/${ing.name}`} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-4 text-slate-400">{ing.namespace}</td>
                    <td className="py-2.5 px-4 text-white font-semibold">{ing.name}</td>
                    <td className="py-2.5 px-4 text-emerald-300">
                      {ing.class || 'default'} • {ing.tls ? 'TLS' : 'HTTP'}
                    </td>
                    <td className="py-2.5 px-4 text-cyan-300">{(ing.hosts || []).join(', ') || '*'}</td>
                    <td className="py-2.5 px-4 text-slate-300">{(ing.backends || []).join(', ') || '—'}</td>
                    <td className="py-2.5 px-4 text-slate-300">{ing.address || 'Pending'}</td>
                    <td className="py-2.5 px-4 text-right">
                      <Link
                        href={`/k3s/explorer?resource=ingresses&namespace=${encodeURIComponent(ing.namespace)}&name=${encodeURIComponent(ing.name)}`}
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
  );
}
