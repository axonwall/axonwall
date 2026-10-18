'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Cpu,
  Plus,
  Play,
  Square,
  RotateCcw,
  Pause,
  RefreshCw,
  Terminal,
  Trash2,
  HardDrive,
  Network,
  Activity,
  AlertCircle,
  CheckCircle2,
  Key,
  Shield,
  Layers,
  Settings2,
} from 'lucide-react';
import {
  getVmListAction,
  vmPowerAction,
  saveVmAction,
  deleteVmAction,
  getVirtConfigAction,
  getIsoListAction,
  type VMStatusItem,
  type IsoItem,
} from '@/server/virt';
import type { VirtualMachine, VmDiskBus } from '@axonwall/lib/schemas';

export default function VirtualMachinesPage() {
  const [vms, setVms] = useState<VMStatusItem[]>([]);
  const [isos, setIsos] = useState<IsoItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<number | null>(null);
  const [statusBanner, setStatusBanner] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);

  // Form state
  const [vmid, setVmid] = useState<number>(100);
  const [name, setName] = useState('');
  const [osType, setOsType] = useState<'linux' | 'windows' | 'freebsd' | 'other'>('linux');
  const [cores, setCores] = useState(2);
  const [sockets, setSockets] = useState(1);
  const [cpuType, setCpuType] = useState<'host' | 'x86-64-v2-AES' | 'kvm64'>('host');
  const [memoryMb, setMemoryMb] = useState(2048);
  const [diskSizeGb, setDiskSizeGb] = useState(32);
  const [diskBus, setDiskBus] = useState<VmDiskBus>('virtio');
  const [pool, setPool] = useState('tank');
  const [bridge, setBridge] = useState('br0');
  const [vlanTag, setVlanTag] = useState<number | undefined>(undefined);
  const [selectedIso, setSelectedIso] = useState<string>('');
  const [bios, setBios] = useState<'ovmf' | 'seabios'>('ovmf');
  const [tpm2, setTpm2] = useState(false);
  const [enableCloudInit, setEnableCloudInit] = useState(true);
  const [ciUser, setCiUser] = useState('axonadmin');
  const [ciPassword, setCiPassword] = useState('');
  const [ciSshKey, setCiSshKey] = useState('');
  const [ciIpConfig, setCiIpConfig] = useState('dhcp');

  const loadData = async () => {
    try {
      setLoading(true);
      const [vmList, isoList, virtConf] = await Promise.all([
        getVmListAction(),
        getIsoListAction(),
        getVirtConfigAction(),
      ]);
      setVms(vmList);
      setIsos(isoList);

      // Auto-assign next free VMID
      const existingIds = (virtConf.vms || []).map((v) => v.vmid);
      let nextId = 100;
      while (existingIds.includes(nextId)) {
        nextId++;
      }
      setVmid(nextId);
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || 'Failed to load VMs' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  const handlePower = async (targetVmid: number, action: 'start' | 'stop' | 'reset' | 'pause' | 'resume', force = false) => {
    setActionLoading(targetVmid);
    setStatusBanner(null);
    try {
      const res = await vmPowerAction(targetVmid, action, force);
      setStatusBanner({
        type: res.success ? 'success' : 'error',
        message: res.message + (res.upid ? ` (Task: ${res.upid})` : ''),
      });
      await loadData();
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || `Failed to ${action} VM ${targetVmid}` });
    } finally {
      setActionLoading(null);
    }
  };

  const handleDelete = async (targetVmid: number) => {
    if (!confirm(`Are you sure you want to delete VM ${targetVmid}? This cannot be undone.`)) return;
    setStatusBanner(null);
    try {
      const res = await deleteVmAction(targetVmid);
      setStatusBanner({ type: 'success', message: res.message });
      await loadData();
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || 'Failed to delete VM' });
    }
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    const newVm: VirtualMachine = {
      vmid,
      name: name.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, '-'),
      description: '',
      osType,
      bios,
      secureBoot: false,
      tpm2,
      sockets,
      cores,
      cpuType,
      memoryMb,
      balloonMinMb: 0,
      agent: true,
      autostart: false,
      haManaged: false,
      enabled: true,
      disks: [
        {
          name: 'disk0',
          pool,
          sizeGb: diskSizeGb,
          bus: diskBus,
          cache: 'none',
          discard: true,
          readOnly: false,
          backup: true,
          iopsReadLimit: 0,
          iopsWriteLimit: 0,
        },
      ],
      nics: [
        {
          bridge,
          model: 'virtio',
          mac: '',
          vlanTag: vlanTag ? Number(vlanTag) : undefined,
          firewall: true,
          rateLimitMbps: 0,
        },
      ],
      iso: selectedIso || undefined,
      cloudInit: enableCloudInit
        ? {
            user: ciUser || 'axonadmin',
            password: ciPassword || undefined,
            sshAuthorizedKeys: ciSshKey.trim() ? [ciSshKey.trim()] : [],
            ipConfig: ciIpConfig || 'dhcp',
            nameservers: ['1.1.1.1', '8.8.8.8'],
          }
        : undefined,
      pciPassthrough: [],
      usbPassthrough: [],
    };

    try {
      const res = await saveVmAction(newVm);
      setStatusBanner({ type: 'success', message: res.message });
      setShowCreateModal(false);
      setName('');
      await loadData();
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || 'Failed to create VM' });
    }
  };

  const totalCores = vms.reduce((acc, vm) => acc + (vm.cores || 0), 0);
  const totalRamGb = (vms.reduce((acc, vm) => acc + (vm.memoryMb || 0), 0) / 1024).toFixed(1);
  const runningVms = vms.filter((v) => v.status === 'running').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Cpu className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-slate-100">Virtual Machines</h1>
              <p className="text-sm text-slate-400">
                KVM/QEMU hypervisor with ZFS ZVOL storage, Cloud-Init, and noVNC console
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
            Create Virtual Machine
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
            <span>Total Virtual Machines</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-3xl font-bold text-slate-100">{vms.length}</div>
          <div className="mt-1 text-xs text-slate-500">Configured in virt.yaml</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="flex items-center justify-between text-slate-400 text-sm font-medium">
            <span>Running VMs</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-3xl font-bold text-emerald-400">{runningVms}</div>
          <div className="mt-1 text-xs text-slate-500">{vms.length - runningVms} stopped</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="flex items-center justify-between text-slate-400 text-sm font-medium">
            <span>Allocated vCPUs</span>
            <Cpu className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 text-3xl font-bold text-slate-100">{totalCores}</div>
          <div className="mt-1 text-xs text-slate-500">Threads provisioned</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="flex items-center justify-between text-slate-400 text-sm font-medium">
            <span>Allocated Memory</span>
            <HardDrive className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-3xl font-bold text-slate-100">{totalRamGb} GB</div>
          <div className="mt-1 text-xs text-slate-500">Host RAM committed</div>
        </div>
      </div>

      {/* VM Table */}
      <div className="rounded-xl bg-slate-900/60 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/60 text-xs font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="px-6 py-4">VMID</th>
                <th className="px-6 py-4">Name</th>
                <th className="px-6 py-4">Status</th>
                <th className="px-6 py-4">vCPUs / RAM</th>
                <th className="px-6 py-4">Agent</th>
                <th className="px-6 py-4">Uptime</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {vms.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center text-slate-500 font-sans">
                    No virtual machines configured. Click &quot;Create Virtual Machine&quot; to provision one.
                  </td>
                </tr>
              ) : (
                vms.map((vm) => {
                  const isRunning = vm.status === 'running';
                  const isPaused = vm.status === 'paused';
                  const isBusy = actionLoading === vm.vmid;

                  return (
                    <tr key={vm.vmid} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-6 py-4 font-bold text-cyan-400">{vm.vmid}</td>
                      <td className="px-6 py-4 font-sans font-medium text-slate-200">{vm.name}</td>
                      <td className="px-6 py-4">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
                            isRunning
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                              : isPaused
                              ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                              : 'bg-slate-800 text-slate-400 border border-slate-700'
                          }`}
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              isRunning ? 'bg-emerald-400' : isPaused ? 'bg-amber-400' : 'bg-slate-500'
                            }`}
                          />
                          {vm.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        {vm.cores} cores &bull; {vm.memoryMb} MB
                      </td>
                      <td className="px-6 py-4">
                        {vm.agentRunning ? (
                          <span className="text-emerald-400 font-sans flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5" /> QGA Active
                          </span>
                        ) : (
                          <span className="text-slate-500 font-sans">No Guest Agent</span>
                        )}
                      </td>
                      <td className="px-6 py-4">
                        {isRunning && vm.uptimeSeconds > 0
                          ? `${Math.floor(vm.uptimeSeconds / 60)}m ${vm.uptimeSeconds % 60}s`
                          : '—'}
                      </td>
                      <td className="px-6 py-4 text-right space-x-2">
                        {isRunning ? (
                          <>
                            <button
                              onClick={() => handlePower(vm.vmid, 'stop')}
                              disabled={isBusy}
                              className="px-2.5 py-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded text-xs transition-colors"
                              title="ACPI Shutdown"
                            >
                              <Square className="w-3.5 h-3.5 inline mr-1" /> Stop
                            </button>
                            <button
                              onClick={() => handlePower(vm.vmid, 'reset')}
                              disabled={isBusy}
                              className="px-2.5 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 rounded text-xs transition-colors"
                              title="Hardware Reset"
                            >
                              <RotateCcw className="w-3.5 h-3.5 inline" />
                            </button>
                          </>
                        ) : (
                          <button
                            onClick={() => handlePower(vm.vmid, 'start')}
                            disabled={isBusy}
                            className="px-2.5 py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded text-xs transition-colors"
                          >
                            <Play className="w-3.5 h-3.5 inline mr-1" /> Start
                          </button>
                        )}

                        <Link
                          href={`/compute/console/${vm.vmid}?type=vnc`}
                          target="_blank"
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded text-xs transition-colors"
                        >
                          <Terminal className="w-3.5 h-3.5" /> Console
                        </Link>

                        <button
                          onClick={() => handleDelete(vm.vmid)}
                          disabled={isRunning || isBusy}
                          className="p-1.5 text-slate-500 hover:text-rose-400 disabled:opacity-30 transition-colors"
                          title="Delete VM"
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

      {/* Create VM Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm overflow-y-auto">
          <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 my-8">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2">
                <Cpu className="w-5 h-5 text-cyan-400" />
                <h2 className="text-lg font-bold text-slate-100">Create KVM Virtual Machine</h2>
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
                  <label className="block text-xs font-semibold text-slate-400 mb-1">VMID</label>
                  <input
                    type="number"
                    value={vmid}
                    onChange={(e) => setVmid(Number(e.target.value))}
                    min={100}
                    max={99999}
                    required
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Name</label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. debian-prod"
                    required
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">OS Type</label>
                  <select
                    value={osType}
                    onChange={(e) => setOsType(e.target.value as any)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="linux">Linux 6.x / 5.x</option>
                    <option value="windows">Microsoft Windows</option>
                    <option value="freebsd">FreeBSD</option>
                    <option value="other">Other / Generic</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">BIOS Firmware</label>
                  <select
                    value={bios}
                    onChange={(e) => setBios(e.target.value as any)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="ovmf">OVMF (UEFI)</option>
                    <option value="seabios">SeaBIOS (Legacy)</option>
                  </select>
                </div>
                <div className="flex items-center pt-6">
                  <label className="flex items-center gap-2 cursor-pointer text-xs font-medium text-slate-300">
                    <input
                      type="checkbox"
                      checked={tpm2}
                      onChange={(e) => setTpm2(e.target.checked)}
                      className="rounded bg-slate-950 border-slate-800 text-cyan-600 focus:ring-0"
                    />
                    Enable TPM 2.0 (vTPM)
                  </label>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Cores</label>
                  <input
                    type="number"
                    value={cores}
                    onChange={(e) => setCores(Number(e.target.value))}
                    min={1}
                    max={64}
                    required
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">CPU Type</label>
                  <select
                    value={cpuType}
                    onChange={(e) => setCpuType(e.target.value as any)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="host">Host Pass-Through</option>
                    <option value="x86-64-v2-AES">x86-64-v2-AES (Migration-safe)</option>
                    <option value="kvm64">kvm64</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Memory (MB)</label>
                  <input
                    type="number"
                    value={memoryMb}
                    onChange={(e) => setMemoryMb(Number(e.target.value))}
                    min={512}
                    step={512}
                    required
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              </div>

              {/* Storage */}
              <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-3">
                <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
                  <HardDrive className="w-4 h-4 text-cyan-400" />
                  Primary ZFS Disk (ZVOL)
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">ZFS Pool</label>
                    <input
                      type="text"
                      value={pool}
                      onChange={(e) => setPool(e.target.value)}
                      className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-slate-100 text-xs"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">Size (GB)</label>
                    <input
                      type="number"
                      value={diskSizeGb}
                      onChange={(e) => setDiskSizeGb(Number(e.target.value))}
                      min={1}
                      className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-slate-100 text-xs"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">Disk Bus</label>
                    <select
                      value={diskBus}
                      onChange={(e) => setDiskBus(e.target.value as any)}
                      className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-slate-100 text-xs"
                    >
                      <option value="virtio">VirtIO Block (Fastest)</option>
                      <option value="scsi">VirtIO SCSI</option>
                      <option value="sata">SATA</option>
                      <option value="nvme">NVMe Emulation</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Network & Optical */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Network Bridge</label>
                  <input
                    type="text"
                    value={bridge}
                    onChange={(e) => setBridge(e.target.value)}
                    placeholder="br0 or vmbr0"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Installation ISO</label>
                  <select
                    value={selectedIso}
                    onChange={(e) => setSelectedIso(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="">None (Network / Cloud-Init boot)</option>
                    {isos.map((iso) => (
                      <option key={iso.path} value={iso.path}>
                        {iso.name} ({(iso.sizeBytes / (1024 * 1024 * 1024)).toFixed(2)} GB)
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Cloud Init Section */}
              <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-xs font-bold text-slate-300">
                    <Key className="w-4 h-4 text-emerald-400" />
                    Cloud-Init Provisioning
                  </span>
                  <input
                    type="checkbox"
                    checked={enableCloudInit}
                    onChange={(e) => setEnableCloudInit(e.target.checked)}
                    className="rounded bg-slate-950 border-slate-800 text-cyan-600 focus:ring-0"
                  />
                </div>

                {enableCloudInit && (
                  <div className="space-y-3 pt-2">
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">Default User</label>
                        <input
                          type="text"
                          value={ciUser}
                          onChange={(e) => setCiUser(e.target.value)}
                          className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-slate-100 text-xs"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">Password</label>
                        <input
                          type="password"
                          value={ciPassword}
                          onChange={(e) => setCiPassword(e.target.value)}
                          placeholder="Optional"
                          className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-slate-100 text-xs"
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-[11px] text-slate-400 mb-1">SSH Public Key</label>
                      <input
                        type="text"
                        value={ciSshKey}
                        onChange={(e) => setCiSshKey(e.target.value)}
                        placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5..."
                        className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-slate-100 text-xs font-mono"
                      />
                    </div>
                  </div>
                )}
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
                  Create &amp; Provision VM
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
