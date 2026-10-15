'use client';

import { useState, useEffect } from 'react';
import { Database, Plus, Trash2, RefreshCw, ShieldCheck, HardDrive } from 'lucide-react';
import {
  getCurrentDesiredState,
  applyDesiredState,
  getNasDisksInventory,
  getNasPoolsRuntime,
  scrubNasPoolAction,
  type NasDiskItem,
  type NasPoolStatus,
} from '@/server/agent';
import type { DesiredState, ZfsPool } from '@axonwall/lib/schemas';

export default function ZfsPoolsPage() {
  const [state, setState] = useState<DesiredState | null>(null);
  const [disks, setDisks] = useState<NasDiskItem[]>([]);
  const [runtimePools, setRuntimePools] = useState<NasPoolStatus[]>([]);
  const [poolName, setPoolName] = useState('tank');
  const [topology, setTopology] = useState<ZfsPool['topology']>('mirror');
  const [selectedDisks, setSelectedDisks] = useState<string[]>([]);
  const [compression, setCompression] = useState<ZfsPool['compression']>('lz4');
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const loadAll = async () => {
    try {
      const [st, d, p] = await Promise.all([
        getCurrentDesiredState(),
        getNasDisksInventory(),
        getNasPoolsRuntime(),
      ]);
      setState(st);
      setDisks(d.disks || []);
      setRuntimePools(p || []);
      const eligible = (d.disks || []).filter((x) => x.eligibleForZfs).map((x) => x.path);
      if (selectedDisks.length === 0 && eligible.length > 0) {
        setSelectedDisks(eligible.slice(0, 2));
      }
    } catch {}
  };

  useEffect(() => {
    loadAll();
  }, []);

  const toggleDisk = (path: string) => {
    setSelectedDisks((prev) =>
      prev.includes(path) ? prev.filter((p) => p !== path) : [...prev, path]
    );
  };

  const handleCreatePool = async () => {
    if (!state || !poolName.trim() || selectedDisks.length === 0) return;
    setSaving(true);
    setStatusMsg(null);
    try {
      const next = structuredClone(state);
      next.capabilities = {
        firewallEnabled: next.capabilities?.firewallEnabled !== false,
        nasEnabled: true,
        k3sEnabled: Boolean(next.capabilities?.k3sEnabled ?? next.k3s?.enabled),
      };
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
      next.nas.enabled = true;
      next.nas.pools = [
        ...next.nas.pools.filter((p) => p.name !== poolName.trim()),
        {
          name: poolName.trim(),
          topology,
          dataDisks: selectedDisks,
          cacheDisks: [],
          logDisks: [],
          spareDisks: [],
          ashift: 12,
          autotrim: true,
          compression,
          scrubScheduleCron: '0 2 * * 0',
          description: `ZFS ${topology.toUpperCase()} storage pool`,
        },
      ];
      const res = await applyDesiredState(next);
      setState(next);
      setStatusMsg(`Pool '${poolName}' provisioned (${res.message})`);
      await loadAll();
    } catch (err: any) {
      setStatusMsg(err?.message || 'Failed to create ZFS pool');
    } finally {
      setSaving(false);
    }
  };

  const handleDeletePool = async (name: string) => {
    if (!state) return;
    setSaving(true);
    try {
      const next = structuredClone(state);
      if (next.nas) {
        next.nas.pools = next.nas.pools.filter((p) => p.name !== name);
      }
      await applyDesiredState(next);
      setState(next);
      await loadAll();
    } finally {
      setSaving(false);
    }
  };

  const handleScrub = async (name: string) => {
    const res = await scrubNasPoolAction(name);
    setStatusMsg(res.message);
  };

  const configuredPools = state?.nas?.pools ?? [];

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex items-center justify-between border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">ZFS Storage Pools & RAID-Z</h1>
            <p className="text-sm text-slate-400">
              Create and scrub OpenZFS pools using Stripe, Mirror (RAID-10), RAID-Z1/Z2/Z3, or dRAID topologies.
            </p>
          </div>
        </div>
      </div>

      {statusMsg && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 flex items-center justify-between">
          <span>{statusMsg}</span>
          <button onClick={() => setStatusMsg(null)}>✕</button>
        </div>
      )}

      {/* Pool Builder Card */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-5">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Plus className="w-4 h-4 text-emerald-400" /> Provision New ZFS Pool
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Pool Name</label>
            <input
              type="text"
              value={poolName}
              onChange={(e) => setPoolName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              placeholder="tank"
            />
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">ZFS RAID Topology</label>
            <select
              value={topology}
              onChange={(e) => setTopology(e.target.value as ZfsPool['topology'])}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white"
            >
              <option value="stripe">Stripe (RAID-0 / Single Partition)</option>
              <option value="mirror">Mirror (RAID-1 / RAID-10)</option>
              <option value="raidz1">RAID-Z1 (Single Parity, 3+ VDEVs)</option>
              <option value="raidz2">RAID-Z2 (Dual Parity, 4+ VDEVs)</option>
              <option value="raidz3">RAID-Z3 (Triple Parity, 5+ VDEVs)</option>
              <option value="draid1">dRAID1 (Distributed Spare RAID)</option>
              <option value="draid2">dRAID2 (Dual Parity Distributed RAID)</option>
            </select>
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">Inline Compression</label>
            <select
              value={compression}
              onChange={(e) => setCompression(e.target.value as ZfsPool['compression'])}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white"
            >
              <option value="lz4">lz4 (Recommended High-Speed)</option>
              <option value="zstd">zstd (High Ratio)</option>
              <option value="off">off</option>
            </select>
          </div>
        </div>

        <div>
          <label className="block text-xs text-slate-400 mb-2">
            Select Member Disks / Installer <code className="text-emerald-400">axon_zfs_*</code> Partitions
          </label>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {disks.map((d) => {
              const checked = selectedDisks.includes(d.path);
              return (
                <button
                  type="button"
                  key={d.path}
                  onClick={() => toggleDisk(d.path)}
                  className={`p-3 rounded-xl border text-left transition flex items-center justify-between ${
                    checked
                      ? 'bg-emerald-500/10 border-emerald-500/40 text-white'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="font-mono text-xs font-semibold truncate">{d.path}</div>
                    <div className="text-[11px] text-slate-500 truncate">{d.model}</div>
                  </div>
                  <HardDrive className={`w-4 h-4 shrink-0 ${checked ? 'text-emerald-400' : 'text-slate-600'}`} />
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex justify-end">
          <button
            disabled={saving || selectedDisks.length === 0}
            onClick={handleCreatePool}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-xs font-semibold text-white transition"
          >
            {saving ? 'Applying Pool Configuration...' : 'Create & Apply ZFS Pool'}
          </button>
        </div>
      </div>

      {/* Configured Pools List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {configuredPools.map((pool) => {
          const live = runtimePools.find((r) => r.name === pool.name);
          return (
            <div key={pool.name} className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="text-base font-bold text-white font-mono">{pool.name}</h3>
                  <span className="text-xs text-slate-400 uppercase font-mono">
                    Topology: {pool.topology} • Compression: {pool.compression}
                  </span>
                </div>
                <span className="px-2.5 py-1 rounded-md bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-xs font-mono font-bold">
                  {live?.health || 'ONLINE'}
                </span>
              </div>

              <div className="text-xs text-slate-400 space-y-1">
                <div>Mountpoint: <span className="font-mono text-slate-200">/mnt/{pool.name}</span></div>
                <div>VDEVs: <span className="font-mono text-slate-300">{pool.dataDisks.join(', ')}</span></div>
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-slate-800">
                <button
                  onClick={() => handleScrub(pool.name)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 flex items-center gap-1.5"
                >
                  <RefreshCw className="w-3.5 h-3.5 text-emerald-400" /> Scrub Pool
                </button>
                <button
                  onClick={() => handleDeletePool(pool.name)}
                  className="px-3 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-xs text-rose-400 flex items-center gap-1.5"
                >
                  <Trash2 className="w-3.5 h-3.5" /> Remove
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
