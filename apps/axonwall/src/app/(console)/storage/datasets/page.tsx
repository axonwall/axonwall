'use client';

import { useState, useEffect } from 'react';
import { Layers, Plus, Trash2, Lock, Unlock } from 'lucide-react';
import { getCurrentDesiredState, manageNasDatasetEncryptionAction } from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import type { DesiredState, ZfsDataset } from '@axonwall/lib/schemas';

export default function ZfsDatasetsPage() {
  const { applyState } = useDesiredStateApply();
  const [state, setState] = useState<DesiredState | null>(null);
  const [pool, setPool] = useState('tank');
  const [name, setName] = useState('shares/general');
  const [type, setType] = useState<'filesystem' | 'zvol'>('filesystem');
  const [quotaGb, setQuotaGb] = useState(500);
  const [refQuotaGb, setRefQuotaGb] = useState(0);
  const [volSizeGb, setVolSizeGb] = useState(50);
  const [recordSize, setRecordSize] = useState<ZfsDataset['recordSize']>('128K');
  const [atime, setAtime] = useState<'off' | 'on'>('off');
  const [syncMode, setSyncMode] = useState<'standard' | 'always' | 'disabled'>('standard');
  const [encryption, setEncryption] = useState<'off' | 'aes-256-gcm' | 'aes-256-ccm'>('off');
  const [specialSmallBlocks, setSpecialSmallBlocks] = useState<NonNullable<ZfsDataset['specialSmallBlocks']>>('0');
  const [replicateHa, setReplicateHa] = useState(true);
  const [banner, setBanner] = useState<{ ok: boolean; text: string } | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    getCurrentDesiredState().then((st) => {
      setState(st);
      if (st.nas?.pools?.[0]?.name) {
        setPool(st.nas.pools[0].name);
      }
    }).catch(() => {});
  }, []);

  const handleAddDataset = async () => {
    if (!state || !name.trim()) return;
    setSaving(true);
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
      next.nas.datasets = [
        ...next.nas.datasets.filter((d) => !(d.pool === pool && d.name === name.trim())),
        {
          name: name.trim(),
          pool,
          type,
          compression: 'lz4',
          dedup: 'off',
          quotaGb: type === 'filesystem' ? quotaGb : 0,
          ...(type === 'filesystem' && refQuotaGb > 0 ? { refQuotaGb } : {}),
          recordSize,
          atime,
          sync: syncMode,
          volSizeGb: type === 'zvol' ? volSizeGb : 0,
          aclMode: 'passthrough',
          encryption,
          ...(encryption !== 'off'
            ? {
                keyFormat: 'passphrase' as const,
                keyLocation: 'prompt',
              }
            : {}),
          ...(specialSmallBlocks !== '0' ? { specialSmallBlocks } : {}),
          replicateToHaPeer: replicateHa,
          description: '',
        },
      ];
      await applyState(next);
      setState(next);
    } catch (err: any) {
      // C2: a fingerprint mismatch (or any apply failure) must be visible,
      // not an unhandled rejection — the dataset was not added. This page
      // has no banner state, so the failure is alerted like the fleet page
      // does for its errors.
      alert(err?.message || 'Failed to add dataset.');
    } finally {
      setSaving(false);
    }
  };

  const handleRemove = async (dsPool: string, dsName: string) => {
    if (!state?.nas) return;
    const next = structuredClone(state);
    if (next.nas) {
      next.nas.datasets = next.nas.datasets.filter((d) => !(d.pool === dsPool && d.name === dsName));
    }
    // C2: see handleAddDataset above — a refused apply must be visible.
    try {
      await applyState(next);
      setState(next);
    } catch (err: any) {
      alert(err?.message || 'Failed to remove dataset.');
    }
  };

  const handleEncryptionKey = async (fullDataset: string, action: 'load-key' | 'unload-key') => {
    let keyMaterial = '';
    if (action === 'load-key') {
      const entered = window.prompt(`Enter passphrase / hex key to unlock encrypted ZFS dataset '${fullDataset}':`);
      if (entered === null) return;
      keyMaterial = entered;
    } else if (!confirm(`Unload encryption key and lock dataset '${fullDataset}'?`)) {
      return;
    }
    try {
      const res = await manageNasDatasetEncryptionAction(fullDataset, action, keyMaterial);
      setBanner({ ok: res.success, text: res.message });
    } catch (err: any) {
      setBanner({ ok: false, text: err?.message || `Failed to ${action} on ${fullDataset}` });
    }
  };

  const datasets = state?.nas?.datasets ?? [];

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex items-center gap-3 border-b border-slate-800 pb-6">
        <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
          <Layers className="w-5 h-5" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">ZFS Datasets & Zvols</h1>
          <p className="text-sm text-slate-400">
            Configure hierarchical POSIX/NFSv4 datasets, quotas, record sizes, and block Zvols for iSCSI targets.
          </p>
        </div>
      </div>

      {banner && (
        <div
          className={`p-4 rounded-xl text-xs flex items-center justify-between ${
            banner.ok
              ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border border-rose-500/30 text-rose-300'
          }`}
        >
          <span>{banner.text}</span>
          <button onClick={() => setBanner(null)}>✕</button>
        </div>
      )}

      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Plus className="w-4 h-4 text-emerald-400" /> Create Dataset or Zvol
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Parent Pool</label>
            <input
              type="text"
              value={pool}
              onChange={(e) => setPool(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Dataset Path</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              placeholder="shares/media"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Type</label>
            <select
              value={type}
              onChange={(e) => setType(e.target.value as 'filesystem' | 'zvol')}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white"
            >
              <option value="filesystem">Filesystem (SMB / NFS)</option>
              <option value="zvol">Zvol Block Device (iSCSI)</option>
            </select>
          </div>
          {type === 'filesystem' ? (
            <div>
              <label className="block text-xs text-slate-400 mb-1">Quota (GB, 0=Unlimited)</label>
              <input
                type="number"
                value={quotaGb}
                onChange={(e) => setQuotaGb(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
          ) : (
            <div>
              <label className="block text-xs text-slate-400 mb-1">Zvol Size (GB)</label>
              <input
                type="number"
                value={volSizeGb}
                onChange={(e) => setVolSizeGb(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
          )}
          <div>
            <label className="block text-xs text-slate-400 mb-1">Record Size</label>
            <select
              value={recordSize}
              onChange={(e) => setRecordSize(e.target.value as ZfsDataset['recordSize'])}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white"
            >
              <option value="16K">16K (Database / Postgres)</option>
              <option value="64K">64K (Virtual Machines)</option>
              <option value="128K">128K (General Purpose)</option>
              <option value="1M">1M (Large Media / Backups)</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 pt-1">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Native ZFS Encryption</label>
            <select
              value={encryption}
              onChange={(e) => setEncryption(e.target.value as any)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white"
            >
              <option value="off">Off (Inherit / Unencrypted)</option>
              <option value="aes-256-gcm">AES-256-GCM (Hardware AES-NI Authenticated)</option>
              <option value="aes-256-ccm">AES-256-CCM</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Special NVMe Small-Block Cutoff</label>
            <select
              value={specialSmallBlocks}
              onChange={(e) => setSpecialSmallBlocks(e.target.value as NonNullable<ZfsDataset['specialSmallBlocks']>)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white"
            >
              <option value="0">0 (Metadata Only on Special VDEV)</option>
              <option value="16K">16K (Offload ≤16K DB blocks to NVMe)</option>
              <option value="32K">32K (Offload ≤32K small files to NVMe)</option>
              <option value="64K">64K (Offload ≤64K VM blocks to NVMe)</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">RefQuota (GB, Excl. Snapshots)</label>
            <input
              type="number"
              min={0}
              value={refQuotaGb}
              onChange={(e) => setRefQuotaGb(Number(e.target.value))}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">ZIL Sync Policy</label>
            <select
              value={syncMode}
              onChange={(e) => setSyncMode(e.target.value as 'standard' | 'always' | 'disabled')}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white"
            >
              <option value="standard">standard (POSIX Default)</option>
              <option value="always">always (Strict SLOG Commit)</option>
              <option value="disabled">disabled (Async Only)</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Access Time (atime)</label>
            <select
              value={atime}
              onChange={(e) => setAtime(e.target.value as 'off' | 'on')}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white"
            >
              <option value="off">off (Recommended NVMe/DB)</option>
              <option value="on">on</option>
            </select>
          </div>
        </div>

        <div className="flex items-center justify-between pt-2">
          <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={replicateHa}
              onChange={(e) => setReplicateHa(e.target.checked)}
              className="rounded border-slate-700"
            />
            Replicate incremental ZFS snapshots to Secondary HA Peer node automatically
          </label>
          <button
            disabled={saving}
            onClick={handleAddDataset}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white"
          >
            {saving ? 'Applying...' : 'Create Dataset'}
          </button>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-[11px] font-semibold uppercase tracking-wider text-slate-400 bg-slate-950/60">
              <th className="py-3.5 px-4">Dataset / Zvol</th>
              <th className="py-3.5 px-4">Type</th>
              <th className="py-3.5 px-4">Compression / Record</th>
              <th className="py-3.5 px-4">Quota / Size</th>
              <th className="py-3.5 px-4">HA Replication</th>
              <th className="py-3.5 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70 text-xs">
            {datasets.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate-500">
                  No datasets configured yet. Create one above.
                </td>
              </tr>
            ) : (
              datasets.map((d) => (
                <tr key={`${d.pool}/${d.name}`} className="hover:bg-slate-800/40">
                  <td className="py-3.5 px-4 font-mono text-white">{d.pool}/{d.name}</td>
                  <td className="py-3.5 px-4 uppercase font-mono text-slate-300">{d.type}</td>
                  <td className="py-3.5 px-4 font-mono text-slate-300">{d.compression} • {d.recordSize}</td>
                  <td className="py-3.5 px-4 font-mono text-slate-300">
                    {d.type === 'zvol' ? `${d.volSizeGb || 10} GB` : d.quotaGb ? `${d.quotaGb} GB` : 'Unlimited'}
                  </td>
                  <td className="py-3.5 px-4">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${d.replicateToHaPeer ? 'bg-emerald-500/15 text-emerald-400' : 'bg-slate-800 text-slate-400'}`}>
                        {d.replicateToHaPeer ? 'Active ZFS Send/Recv' : 'Local Only'}
                      </span>
                      {d.encryption && d.encryption !== 'off' && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/15 text-amber-300 border border-amber-500/30 uppercase">
                          {d.encryption}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-3.5 px-4 text-right space-x-2">
                    {d.encryption && d.encryption !== 'off' && (
                      <>
                        <button
                          onClick={() => handleEncryptionKey(`${d.pool}/${d.name}`, 'load-key')}
                          className="text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1"
                          title="Unlock encrypted dataset"
                        >
                          <Unlock className="w-3.5 h-3.5" /> Unlock
                        </button>
                        <button
                          onClick={() => handleEncryptionKey(`${d.pool}/${d.name}`, 'unload-key')}
                          className="text-amber-400 hover:text-amber-300 inline-flex items-center gap-1"
                          title="Unload key & lock dataset"
                        >
                          <Lock className="w-3.5 h-3.5" /> Lock
                        </button>
                      </>
                    )}
                    <button
                      onClick={() => handleRemove(d.pool, d.name)}
                      className="text-rose-400 hover:text-rose-300 inline-flex items-center gap-1"
                    >
                      <Trash2 className="w-3.5 h-3.5" /> Delete
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
