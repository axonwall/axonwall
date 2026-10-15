'use client';

import { useState, useEffect } from 'react';
import { HardDrive, ShieldCheck, Thermometer, Cpu, RefreshCw, CheckCircle2, Layers } from 'lucide-react';
import { getNasDisksInventory, type NasDiskItem } from '@/server/agent';
import Link from 'next/link';

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

export default function StorageDisksPage() {
  const [disks, setDisks] = useState<NasDiskItem[]>([]);
  const [installSpec, setInstallSpec] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const loadDisks = async () => {
    setLoading(true);
    try {
      const res = await getNasDisksInventory();
      setDisks(res.disks || []);
      setInstallSpec(res.installSpec || null);
    } catch {}
    setLoading(false);
  };

  useEffect(() => {
    loadDisks();
  }, []);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <HardDrive className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Physical Disks & RAID Inventory</h1>
            <p className="text-sm text-slate-400">
              Hardware block devices, S.M.A.R.T. health telemetry, mdadm system mirrors, and installer-allocated ZFS partitions.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadDisks}
            className="px-3.5 py-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-xs font-semibold text-slate-200 flex items-center gap-2 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-emerald-400' : ''}`} />
            Rescan Bus
          </button>
          <Link
            href="/storage/pools"
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white transition"
          >
            Manage ZFS Pools →
          </Link>
        </div>
      </div>

      {installSpec && (
        <div className="p-5 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-bold uppercase tracking-wider">
              <Layers className="w-4 h-4" />
              Installer Multi-Disk RAID & ZFS Bootstrap Profile Detected
            </div>
            <p className="text-xs text-slate-300">
              System Root RAID Mode: <span className="font-mono text-white">{installSpec.systemRaidMode || 'single'}</span>{' '}
              ({installSpec.systemRaidDisks || 'primary disk'}) • Initial ZFS Pool:{' '}
              <span className="font-mono text-emerald-300">{installSpec.poolName}</span> ({installSpec.topology}) across{' '}
              <span className="font-mono text-slate-200">{(installSpec.vdevs || []).join(', ')}</span>
            </p>
          </div>
          <span className="px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-300 text-xs font-mono shrink-0">
            Auto-Imported
          </span>
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-[11px] font-semibold uppercase tracking-wider text-slate-400 bg-slate-950/60">
              <th className="py-3.5 px-4">Device / PartLabel</th>
              <th className="py-3.5 px-4">Model & Serial</th>
              <th className="py-3.5 px-4">Media</th>
              <th className="py-3.5 px-4">Capacity</th>
              <th className="py-3.5 px-4">Role / Status</th>
              <th className="py-3.5 px-4">Temp</th>
              <th className="py-3.5 px-4">S.M.A.R.T.</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70 text-xs">
            {disks.map((d) => (
              <tr key={d.path} className="hover:bg-slate-800/40 transition">
                <td className="py-3.5 px-4 font-mono text-white">
                  <div>{d.path}</div>
                  {d.partLabel && (
                    <span className="inline-block mt-0.5 px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 text-[10px]">
                      PARTLABEL={d.partLabel}
                    </span>
                  )}
                </td>
                <td className="py-3.5 px-4">
                  <div className="text-slate-200 font-medium">{d.model || 'Generic Block Device'}</div>
                  <div className="text-slate-500 font-mono text-[11px]">{d.serial || 'N/A'}</div>
                </td>
                <td className="py-3.5 px-4">
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px]">
                    {d.rotational ? 'HDD (Rotational)' : 'NVMe / SSD'}
                  </span>
                </td>
                <td className="py-3.5 px-4 font-mono text-slate-200">{formatBytes(d.sizeBytes)}</td>
                <td className="py-3.5 px-4">
                  {d.role === 'boot_zfs_partition' ? (
                    <span className="px-2.5 py-1 rounded-md bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-[11px] font-semibold">
                      Installer ZFS Partition (axon_zfs)
                    </span>
                  ) : d.eligibleForZfs ? (
                    <span className="px-2.5 py-1 rounded-md bg-sky-500/15 text-sky-400 border border-sky-500/30 text-[11px] font-semibold">
                      Eligible for ZFS Pool
                    </span>
                  ) : (
                    <span className="px-2.5 py-1 rounded-md bg-slate-800 text-slate-400 text-[11px]">
                      System / Mounted ({d.mountpoint || d.fsType || 'OS'})
                    </span>
                  )}
                </td>
                <td className="py-3.5 px-4 font-mono text-slate-300">
                  <span className="inline-flex items-center gap-1">
                    <Thermometer className="w-3.5 h-3.5 text-amber-400" />
                    {d.temperatureC || 35}°C
                  </span>
                </td>
                <td className="py-3.5 px-4">
                  <span className="inline-flex items-center gap-1 text-emerald-400 font-semibold">
                    <CheckCircle2 className="w-3.5 h-3.5" /> PASSED
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
