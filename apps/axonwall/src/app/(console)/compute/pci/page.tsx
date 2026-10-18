'use client';

import React, { useState, useEffect } from 'react';
import {
  Network,
  Cpu,
  RefreshCw,
  Shield,
  Layers,
  CheckCircle2,
  AlertCircle,
  Sliders,
  Unlink,
  Link as LinkIcon,
} from 'lucide-react';
import {
  getPciInventoryAction,
  bindPciVfioAction,
  unbindPciVfioAction,
  configureSriovAction,
  type PciDeviceItem,
} from '@/server/virt';

export default function PciPassthroughPage() {
  const [devices, setDevices] = useState<PciDeviceItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [statusBanner, setStatusBanner] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // SR-IOV modal
  const [sriovDev, setSriovDev] = useState<PciDeviceItem | null>(null);
  const [sriovNumVfs, setSriovNumVfs] = useState(0);

  const loadData = async () => {
    try {
      setLoading(true);
      const devs = await getPciInventoryAction();
      setDevices(devs);
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || 'Failed to scan PCI devices' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleBind = async (bdf: string) => {
    setActionLoading(bdf);
    setStatusBanner(null);
    try {
      const res = await bindPciVfioAction(bdf);
      setStatusBanner({ type: 'success', message: res.message });
      await loadData();
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || `Failed to bind ${bdf}` });
    } finally {
      setActionLoading(null);
    }
  };

  const handleUnbind = async (bdf: string) => {
    setActionLoading(bdf);
    setStatusBanner(null);
    try {
      const res = await unbindPciVfioAction(bdf);
      setStatusBanner({ type: 'success', message: res.message });
      await loadData();
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || `Failed to unbind ${bdf}` });
    } finally {
      setActionLoading(null);
    }
  };

  const handleSriovSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sriovDev) return;

    setActionLoading(sriovDev.bdf);
    try {
      const res = await configureSriovAction(sriovDev.bdf, sriovNumVfs);
      setStatusBanner({ type: 'success', message: res.message });
      setSriovDev(null);
      await loadData();
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || 'Failed to configure SR-IOV' });
    } finally {
      setActionLoading(null);
    }
  };

  const vfioBoundCount = devices.filter((d) => d.isVfioBound).length;
  const sriovCount = devices.filter((d) => d.sriovSupported).length;
  const totalVfsAllocated = devices.reduce((acc, d) => acc + (d.sriovNumVfs || 0), 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Network className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-100">PCIe VFIO &amp; SR-IOV Passthrough</h1>
            <p className="text-sm text-slate-400">
              Hardware IOMMU group isolation, GPU/NIC device passthrough, and Single Root I/O Virtualization
            </p>
          </div>
        </div>

        <button
          onClick={loadData}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-2 text-sm font-medium bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-slate-300 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Rescan Host Bus
        </button>
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
          <div className="text-slate-400 text-sm font-medium">Host PCI Devices</div>
          <div className="mt-2 text-3xl font-bold text-slate-100">{devices.length}</div>
          <div className="mt-1 text-xs text-slate-500">Enumerated via sysfs</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-slate-400 text-sm font-medium">VFIO-Bound Devices</div>
          <div className="mt-2 text-3xl font-bold text-cyan-400">{vfioBoundCount}</div>
          <div className="mt-1 text-xs text-slate-500">Ready for VM passthrough</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-slate-400 text-sm font-medium">SR-IOV Capable Devices</div>
          <div className="mt-2 text-3xl font-bold text-indigo-400">{sriovCount}</div>
          <div className="mt-1 text-xs text-slate-500">Hardware VF partitioning</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-slate-400 text-sm font-medium">Active Virtual Functions</div>
          <div className="mt-2 text-3xl font-bold text-emerald-400">{totalVfsAllocated}</div>
          <div className="mt-1 text-xs text-slate-500">VFs spawned on host</div>
        </div>
      </div>

      {/* Devices Table */}
      <div className="rounded-xl bg-slate-900/60 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/60 text-xs font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="px-6 py-4">BDF / Slot</th>
                <th className="px-6 py-4">Device Description</th>
                <th className="px-6 py-4">IOMMU Group</th>
                <th className="px-6 py-4">Current Driver</th>
                <th className="px-6 py-4">SR-IOV Status</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {devices.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-slate-500 font-sans">
                    No PCI devices detected. Ensure VT-d / AMD-Vi IOMMU is enabled in BIOS.
                  </td>
                </tr>
              ) : (
                devices.map((dev) => {
                  const isBusy = actionLoading === dev.bdf;

                  return (
                    <tr key={dev.bdf} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-6 py-4 font-bold text-cyan-400">{dev.bdf}</td>
                      <td className="px-6 py-4 font-sans">
                        <div className="font-medium text-slate-200">{dev.deviceName}</div>
                        <div className="text-xs text-slate-500 font-mono">
                          ID: {dev.vendorId}:{dev.deviceId} &bull; Class: {dev.deviceClass}
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                          Group {dev.iommuGroup >= 0 ? dev.iommuGroup : 'None'}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${
                            dev.isVfioBound
                              ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                              : 'bg-slate-800 text-slate-400 border-slate-700'
                          }`}
                        >
                          {dev.currentDriver}
                        </span>
                      </td>
                      <td className="px-6 py-4 font-sans">
                        {dev.sriovSupported ? (
                          <span className="text-emerald-400 text-xs">
                            {dev.sriovNumVfs} / {dev.sriovTotalVfs} VFs active
                          </span>
                        ) : (
                          <span className="text-slate-600 text-xs">Unsupported</span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-right space-x-2">
                        {dev.sriovSupported && (
                          <button
                            onClick={() => {
                              setSriovDev(dev);
                              setSriovNumVfs(dev.sriovNumVfs);
                            }}
                            className="px-2.5 py-1.5 bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 rounded text-xs transition-colors"
                          >
                            <Sliders className="w-3.5 h-3.5 inline mr-1" /> VFs
                          </button>
                        )}

                        {dev.isVfioBound ? (
                          <button
                            onClick={() => handleUnbind(dev.bdf)}
                            disabled={isBusy}
                            className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-xs transition-colors"
                            title="Release back to host driver"
                          >
                            <Unlink className="w-3.5 h-3.5 inline mr-1" /> Release
                          </button>
                        ) : (
                          <button
                            onClick={() => handleBind(dev.bdf)}
                            disabled={isBusy}
                            className="px-2.5 py-1.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded text-xs transition-colors"
                            title="Bind to vfio-pci for VM passthrough"
                          >
                            <LinkIcon className="w-3.5 h-3.5 inline mr-1" /> Bind VFIO
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* SR-IOV Configuration Modal */}
      {sriovDev && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="relative w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2">
                <Sliders className="w-5 h-5 text-indigo-400" />
                <h2 className="text-lg font-bold text-slate-100">Configure SR-IOV Virtual Functions</h2>
              </div>
              <button
                onClick={() => setSriovDev(null)}
                className="text-slate-400 hover:text-slate-200 text-xl font-bold"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleSriovSubmit} className="mt-4 space-y-4">
              <div className="text-xs text-slate-400">
                Device: <span className="font-mono text-cyan-400 font-bold">{sriovDev.bdf}</span> ({sriovDev.deviceName})
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">
                  Number of VFs (Max: {sriovDev.sriovTotalVfs})
                </label>
                <input
                  type="number"
                  value={sriovNumVfs}
                  onChange={(e) => setSriovNumVfs(Number(e.target.value))}
                  min={0}
                  max={sriovDev.sriovTotalVfs}
                  required
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  Setting VFs to 0 tears down all spawned virtual NICs on this physical controller.
                </p>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setSriovDev(null)}
                  className="px-4 py-2 text-sm font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-sm font-medium bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors shadow-lg shadow-indigo-900/20"
                >
                  Apply SR-IOV Allocation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
