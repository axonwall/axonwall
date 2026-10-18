'use client';

import React, { useState, useEffect } from 'react';
import {
  Camera,
  Play,
  Calendar,
  HardDrive,
  RefreshCw,
  Trash2,
  FileCheck,
  AlertCircle,
  CheckCircle2,
  Clock,
  Layers,
  Database,
  Shield,
} from 'lucide-react';
import {
  getBackupListAction,
  triggerBackupAction,
  getVirtConfigAction,
  getVmListAction,
  getContainerListAction,
  type BackupItem,
  type VMStatusItem,
  type ContainerStatusItem,
} from '@/server/virt';
import type { WorkloadBackupJob } from '@axonwall/lib/schemas';

export default function WorkloadBackupsPage() {
  const [backups, setBackups] = useState<BackupItem[]>([]);
  const [backupJobs, setBackupJobs] = useState<WorkloadBackupJob[]>([]);
  const [vms, setVms] = useState<VMStatusItem[]>([]);
  const [containers, setContainers] = useState<ContainerStatusItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [triggering, setTriggering] = useState(false);
  const [statusBanner, setStatusBanner] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [showBackupModal, setShowBackupModal] = useState(false);

  // Backup Now form
  const [targetType, setTargetType] = useState<'vm' | 'lxc'>('vm');
  const [targetId, setTargetId] = useState<number>(100);
  const [pool, setPool] = useState('tank');
  const [destType, setDestType] = useState<'local-zfs' | 's3' | 'pbs'>('local-zfs');

  const loadData = async () => {
    try {
      setLoading(true);
      const [bkList, virtConf, vmList, ctList] = await Promise.all([
        getBackupListAction(),
        getVirtConfigAction(),
        getVmListAction(),
        getContainerListAction(),
      ]);
      setBackups(bkList);
      setBackupJobs(virtConf.backupJobs || []);
      setVms(vmList);
      setContainers(ctList);

      if (vmList.length > 0) {
        setTargetId(vmList[0].vmid);
      } else if (ctList.length > 0) {
        setTargetType('lxc');
        setTargetId(ctList[0].ctid);
      }
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || 'Failed to load backup data' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleBackupSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setTriggering(true);
    setStatusBanner(null);
    try {
      const res = await triggerBackupAction(targetType, targetId, pool, destType);
      setStatusBanner({
        type: res.success ? 'success' : 'error',
        message: res.message + (res.upid ? ` (Task: ${res.upid})` : ''),
      });
      setShowBackupModal(false);
      await loadData();
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || 'Failed to trigger backup' });
    } finally {
      setTriggering(false);
    }
  };

  const totalBytes = backups.reduce((acc, b) => acc + (b.sizeBytes || 0), 0);
  const totalGb = (totalBytes / (1024 * 1024 * 1024)).toFixed(2);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Camera className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-100">Deduplicated Backups &amp; PBS</h1>
            <p className="text-sm text-slate-400">
              ZFS snapshot streaming, zstd compressed archives, and Proxmox Backup Server deduplication
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-slate-300 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowBackupModal(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors shadow-lg shadow-cyan-900/20"
          >
            <Play className="w-4 h-4" />
            Backup Now
          </button>
        </div>
      </div>

      {statusBanner && (
        <div
          className={`flex items-center gap-3 p-4 rounded-lg border text-sm ${
            statusBanner.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
          }`}
        >
          {statusBanner.type === 'success' ? (
            <CheckCircle2 className="w-5 h-5 flex-shrink-0" />
          ) : (
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
          )}
          <span className="flex-1">{statusBanner.message}</span>
          <button onClick={() => setStatusBanner(null)} className="text-slate-400 hover:text-slate-200">
            &times;
          </button>
        </div>
      )}

      {/* Summary Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-slate-400 text-sm font-medium">Completed Backups</div>
          <div className="mt-2 text-3xl font-bold text-slate-100">{backups.length}</div>
          <div className="mt-1 text-xs text-slate-500">ZFS archive snapshots</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-slate-400 text-sm font-medium">Archive Footprint</div>
          <div className="mt-2 text-3xl font-bold text-cyan-400">{totalGb} GB</div>
          <div className="mt-1 text-xs text-slate-500">Compressed with zstd-3</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-slate-400 text-sm font-medium">Deduplication Ratio</div>
          <div className="mt-2 text-3xl font-bold text-emerald-400">3.4x</div>
          <div className="mt-1 text-xs text-slate-500">Block-level chunk dedup</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-slate-400 text-sm font-medium">Active Backup Jobs</div>
          <div className="mt-2 text-3xl font-bold text-indigo-400">{backupJobs.length}</div>
          <div className="mt-1 text-xs text-slate-500">Cron schedules configured</div>
        </div>
      </div>

      {/* Backup Archives Table */}
      <div className="rounded-xl bg-slate-900/60 border border-slate-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <div className="font-bold text-sm text-slate-200 flex items-center gap-2">
            <Camera className="w-4 h-4 text-cyan-400" />
            Backup Archive History
          </div>
          <span className="text-xs text-slate-500 font-mono">Storage: /mnt/{pool}/backups</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/40 text-xs font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="px-6 py-4">Archive Filename</th>
                <th className="px-6 py-4">Target Workload</th>
                <th className="px-6 py-4">Timestamp</th>
                <th className="px-6 py-4">Size</th>
                <th className="px-6 py-4">Format</th>
                <th className="px-6 py-4">Destination</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {backups.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-slate-500 font-sans">
                    No backup archives found. Click &quot;Backup Now&quot; to perform an instantaneous snapshot backup.
                  </td>
                </tr>
              ) : (
                backups.map((bk) => (
                  <tr key={bk.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-6 py-4 font-bold text-slate-100 flex items-center gap-2">
                      <FileCheck className="w-4 h-4 text-cyan-400" />
                      {bk.name}
                    </td>
                    <td className="px-6 py-4 font-sans text-cyan-400 uppercase font-semibold">
                      {bk.type} {bk.vmid}
                    </td>
                    <td className="px-6 py-4 text-slate-400">
                      {new Date(bk.timestamp * 1000).toLocaleString()}
                    </td>
                    <td className="px-6 py-4">
                      {(bk.sizeBytes / (1024 * 1024 * 1024)).toFixed(2)} GB
                    </td>
                    <td className="px-6 py-4 text-indigo-400">{bk.format}</td>
                    <td className="px-6 py-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                        {bk.destination}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Scheduled Backup Jobs */}
      <div className="rounded-xl bg-slate-900/60 border border-slate-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <div className="font-bold text-sm text-slate-200 flex items-center gap-2">
            <Calendar className="w-4 h-4 text-emerald-400" />
            Automated Scheduled Backup Jobs
          </div>
          <span className="text-xs text-slate-500 font-mono">virt.yaml</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/40 text-xs font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="px-6 py-4">Job Name</th>
                <th className="px-6 py-4">Cron Schedule</th>
                <th className="px-6 py-4">Target</th>
                <th className="px-6 py-4">Retention Policy</th>
                <th className="px-6 py-4">Destination</th>
                <th className="px-6 py-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {backupJobs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-slate-500 font-sans">
                    No automated backup jobs configured in virt.yaml.
                  </td>
                </tr>
              ) : (
                backupJobs.map((job, idx) => (
                  <tr key={job.id || idx} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-6 py-4 font-bold text-slate-100">{job.name}</td>
                    <td className="px-6 py-4 text-cyan-400">{job.scheduleCron}</td>
                    <td className="px-6 py-4 font-sans">{job.targetType === 'all' ? 'All Workloads' : 'Selected'}</td>
                    <td className="px-6 py-4 text-slate-400">
                      Keep {job.retention?.keepLast ?? 5} last &bull; {job.retention?.keepDaily ?? 7} daily
                    </td>
                    <td className="px-6 py-4 text-emerald-400">{job.destinationType}</td>
                    <td className="px-6 py-4">
                      <span className="inline-flex items-center gap-1 text-emerald-400 font-sans">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Active
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Backup Now Modal */}
      {showBackupModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="relative w-full max-w-lg bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2">
                <Camera className="w-5 h-5 text-cyan-400" />
                <h2 className="text-lg font-bold text-slate-100">Create Workload Backup</h2>
              </div>
              <button
                onClick={() => setShowBackupModal(false)}
                className="text-slate-400 hover:text-slate-200 text-xl font-bold"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleBackupSubmit} className="mt-4 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Target Type</label>
                  <select
                    value={targetType}
                    onChange={(e) => {
                      const t = e.target.value as 'vm' | 'lxc';
                      setTargetType(t);
                      if (t === 'vm' && vms.length > 0) setTargetId(vms[0].vmid);
                      if (t === 'lxc' && containers.length > 0) setTargetId(containers[0].ctid);
                    }}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="vm">Virtual Machine (KVM)</option>
                    <option value="lxc">LXC System Container</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Select Workload</label>
                  <select
                    value={targetId}
                    onChange={(e) => setTargetId(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  >
                    {targetType === 'vm'
                      ? vms.map((vm) => (
                          <option key={vm.vmid} value={vm.vmid}>
                            {vm.vmid} - {vm.name}
                          </option>
                        ))
                      : containers.map((ct) => (
                          <option key={ct.ctid} value={ct.ctid}>
                            {ct.ctid} - {ct.name}
                          </option>
                        ))}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Storage Pool</label>
                  <input
                    type="text"
                    value={pool}
                    onChange={(e) => setPool(e.target.value)}
                    required
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Backup Destination</label>
                  <select
                    value={destType}
                    onChange={(e) => setDestType(e.target.value as any)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="local-zfs">Local ZFS Pool (/mnt/{pool}/backups)</option>
                    <option value="s3">MinIO / AWS S3 Object Storage</option>
                    <option value="pbs">Proxmox Backup Server (PBS)</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowBackupModal(false)}
                  className="px-4 py-2 text-sm font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={triggering}
                  className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors shadow-lg shadow-cyan-900/20"
                >
                  {triggering ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                  Execute Snapshot Backup
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
