'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Boxes,
  Plus,
  Play,
  Square,
  RefreshCw,
  Terminal,
  Trash2,
  HardDrive,
  Cpu,
  Activity,
  AlertCircle,
  CheckCircle2,
  Shield,
  Layers,
} from 'lucide-react';
import {
  getContainerListAction,
  containerPowerAction,
  saveContainerAction,
  deleteContainerAction,
  getVirtConfigAction,
  type ContainerStatusItem,
} from '@/server/virt';
import type { LxcContainer } from '@axonwall/lib/schemas';

export default function LxcContainersPage() {
  const [containers, setContainers] = useState<ContainerStatusItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<number | null>(null);
  const [statusBanner, setStatusBanner] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);

  // Form state
  const [ctid, setCtid] = useState<number>(200);
  const [hostname, setHostname] = useState('');
  const [template, setTemplate] = useState('debian-12-standard');
  const [cores, setCores] = useState(2);
  const [memoryMb, setMemoryMb] = useState(1024);
  const [swapMb, setSwapMb] = useState(512);
  const [rootfsPool, setRootfsPool] = useState('tank');
  const [rootfsSizeGb, setRootfsSizeGb] = useState(8);
  const [unprivileged, setUnprivileged] = useState(true);
  const [nesting, setNesting] = useState(true);
  const [bridge, setBridge] = useState('br0');

  const loadData = async () => {
    try {
      setLoading(true);
      const [ctList, virtConf] = await Promise.all([
        getContainerListAction(),
        getVirtConfigAction(),
      ]);
      setContainers(ctList);

      const existingIds = (virtConf.containers || []).map((c) => c.ctid);
      let nextId = 200;
      while (existingIds.includes(nextId)) {
        nextId++;
      }
      setCtid(nextId);
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || 'Failed to load LXC containers' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  const handlePower = async (targetCtid: number, action: 'start' | 'stop', force = false) => {
    setActionLoading(targetCtid);
    setStatusBanner(null);
    try {
      const res = await containerPowerAction(targetCtid, action, force);
      setStatusBanner({
        type: res.success ? 'success' : 'error',
        message: res.message + (res.upid ? ` (Task: ${res.upid})` : ''),
      });
      await loadData();
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || `Failed to ${action} container ${targetCtid}` });
    } finally {
      setActionLoading(null);
    }
  };

  const handleDelete = async (targetCtid: number) => {
    if (!confirm(`Are you sure you want to delete container ${targetCtid}? This will destroy its rootfs.`)) return;
    setStatusBanner(null);
    try {
      const res = await deleteContainerAction(targetCtid);
      setStatusBanner({ type: 'success', message: res.message });
      await loadData();
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || 'Failed to delete container' });
    }
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!hostname.trim()) return;

    const newCt: LxcContainer = {
      ctid,
      hostname: hostname.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, '-'),
      description: '',
      template,
      unprivileged,
      cores,
      memoryMb,
      swapMb,
      rootfsPool,
      rootfsSizeGb,
      features: nesting ? ['nesting'] : [],
      autostart: false,
      haManaged: false,
      enabled: true,
      mountPoints: [],
      nics: [
        {
          bridge,
          model: 'virtio',
          mac: '',
          firewall: true,
          rateLimitMbps: 0,
        },
      ],
      dnsServers: ['1.1.1.1'],
    };

    try {
      const res = await saveContainerAction(newCt);
      setStatusBanner({ type: 'success', message: res.message });
      setShowCreateModal(false);
      setHostname('');
      await loadData();
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || 'Failed to create container' });
    }
  };

  const totalCores = containers.reduce((acc, ct) => acc + (ct.cores || 0), 0);
  const totalRamGb = (containers.reduce((acc, ct) => acc + (ct.memoryMb || 0), 0) / 1024).toFixed(1);
  const runningCts = containers.filter((c) => c.status === 'running').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Boxes className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-slate-100">LXC System Containers</h1>
              <p className="text-sm text-slate-400">
                Lightweight OS containers on ZFS subvolumes with unprivileged isolation
              </p>
            </div>
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
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors shadow-lg shadow-cyan-900/20"
          >
            <Plus className="w-4 h-4" />
            Create Container
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

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="flex items-center justify-between text-slate-400 text-sm font-medium">
            <span>Total Containers</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-3xl font-bold text-slate-100">{containers.length}</div>
          <div className="mt-1 text-xs text-slate-500">LXC system containers</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="flex items-center justify-between text-slate-400 text-sm font-medium">
            <span>Running Containers</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-3xl font-bold text-emerald-400">{runningCts}</div>
          <div className="mt-1 text-xs text-slate-500">{containers.length - runningCts} stopped</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="flex items-center justify-between text-slate-400 text-sm font-medium">
            <span>Allocated Cores</span>
            <Cpu className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 text-3xl font-bold text-slate-100">{totalCores}</div>
          <div className="mt-1 text-xs text-slate-500">cgroup cpuset assigned</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="flex items-center justify-between text-slate-400 text-sm font-medium">
            <span>Allocated Memory</span>
            <HardDrive className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-3xl font-bold text-slate-100">{totalRamGb} GB</div>
          <div className="mt-1 text-xs text-slate-500">cgroup memory limit</div>
        </div>
      </div>

      {/* Container Table */}
      <div className="rounded-xl bg-slate-900/60 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/60 text-xs font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="px-6 py-4">CTID</th>
                <th className="px-6 py-4">Hostname</th>
                <th className="px-6 py-4">Status</th>
                <th className="px-6 py-4">Cores / RAM</th>
                <th className="px-6 py-4">IP Address</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {containers.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-slate-500 font-sans">
                    No LXC containers configured. Click &quot;Create Container&quot; to provision one.
                  </td>
                </tr>
              ) : (
                containers.map((ct) => {
                  const isRunning = ct.status === 'running';
                  const isBusy = actionLoading === ct.ctid;

                  return (
                    <tr key={ct.ctid} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-6 py-4 font-bold text-cyan-400">{ct.ctid}</td>
                      <td className="px-6 py-4 font-sans font-medium text-slate-200">{ct.name}</td>
                      <td className="px-6 py-4">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
                            isRunning
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                              : 'bg-slate-800 text-slate-400 border border-slate-700'
                          }`}
                        >
                          <span className={`w-1.5 h-1.5 rounded-full ${isRunning ? 'bg-emerald-400' : 'bg-slate-500'}`} />
                          {ct.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        {ct.cores} cores &bull; {ct.memoryMb} MB
                      </td>
                      <td className="px-6 py-4">{ct.ipAddress || '—'}</td>
                      <td className="px-6 py-4 text-right space-x-2">
                        {isRunning ? (
                          <button
                            onClick={() => handlePower(ct.ctid, 'stop')}
                            disabled={isBusy}
                            className="px-2.5 py-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded text-xs transition-colors"
                          >
                            <Square className="w-3.5 h-3.5 inline mr-1" /> Stop
                          </button>
                        ) : (
                          <button
                            onClick={() => handlePower(ct.ctid, 'start')}
                            disabled={isBusy}
                            className="px-2.5 py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded text-xs transition-colors"
                          >
                            <Play className="w-3.5 h-3.5 inline mr-1" /> Start
                          </button>
                        )}

                        <Link
                          href={`/compute/console/${ct.ctid}?type=serial`}
                          target="_blank"
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded text-xs transition-colors"
                        >
                          <Terminal className="w-3.5 h-3.5" /> Shell
                        </Link>

                        <button
                          onClick={() => handleDelete(ct.ctid)}
                          disabled={isRunning || isBusy}
                          className="p-1.5 text-slate-500 hover:text-rose-400 disabled:opacity-30 transition-colors"
                          title="Delete Container"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Container Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm overflow-y-auto">
          <div className="relative w-full max-w-xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 my-8">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2">
                <Boxes className="w-5 h-5 text-cyan-400" />
                <h2 className="text-lg font-bold text-slate-100">Create LXC Container</h2>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-slate-200 text-xl font-bold"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateSubmit} className="mt-4 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">CTID</label>
                  <input
                    type="number"
                    value={ctid}
                    onChange={(e) => setCtid(Number(e.target.value))}
                    min={100}
                    max={99999}
                    required
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Hostname</label>
                  <input
                    type="text"
                    value={hostname}
                    onChange={(e) => setHostname(e.target.value)}
                    placeholder="e.g. redis-prod"
                    required
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">Template</label>
                <select
                  value={template}
                  onChange={(e) => setTemplate(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                >
                  <option value="debian-12-standard">Debian 12 Bookworm (Standard)</option>
                  <option value="ubuntu-24.04-standard">Ubuntu 24.04 LTS (Noble)</option>
                  <option value="alpine-3.20">Alpine Linux 3.20</option>
                  <option value="archlinux-base">Arch Linux (Base)</option>
                </select>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Cores</label>
                  <input
                    type="number"
                    value={cores}
                    onChange={(e) => setCores(Number(e.target.value))}
                    min={1}
                    max={32}
                    required
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Memory (MB)</label>
                  <input
                    type="number"
                    value={memoryMb}
                    onChange={(e) => setMemoryMb(Number(e.target.value))}
                    min={256}
                    step={256}
                    required
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Swap (MB)</label>
                  <input
                    type="number"
                    value={swapMb}
                    onChange={(e) => setSwapMb(Number(e.target.value))}
                    min={0}
                    step={256}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Rootfs ZFS Pool</label>
                  <input
                    type="text"
                    value={rootfsPool}
                    onChange={(e) => setRootfsPool(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Disk Size (GB)</label>
                  <input
                    type="number"
                    value={rootfsSizeGb}
                    onChange={(e) => setRootfsSizeGb(Number(e.target.value))}
                    min={2}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Network Bridge</label>
                  <input
                    type="text"
                    value={bridge}
                    onChange={(e) => setBridge(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  />
                </div>
                <div className="space-y-2 pt-5">
                  <label className="flex items-center gap-2 cursor-pointer text-xs font-medium text-slate-300">
                    <input
                      type="checkbox"
                      checked={unprivileged}
                      onChange={(e) => setUnprivileged(e.target.checked)}
                      className="rounded bg-slate-950 border-slate-800 text-cyan-600 focus:ring-0"
                    />
                    Unprivileged Container (User Namespaces)
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer text-xs font-medium text-slate-300">
                    <input
                      type="checkbox"
                      checked={nesting}
                      onChange={(e) => setNesting(e.target.checked)}
                      className="rounded bg-slate-950 border-slate-800 text-cyan-600 focus:ring-0"
                    />
                    Enable Nesting (Docker / Podman in CT)
                  </label>
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 text-sm font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-sm font-medium bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors shadow-lg shadow-cyan-900/20"
                >
                  Create &amp; Provision Container
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
