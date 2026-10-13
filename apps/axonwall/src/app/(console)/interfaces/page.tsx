'use client';

import {
  Network,
  CheckCircle2,
  ArrowRight,
  Loader2,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  X,
  Save,
  Radio,
  Wifi,
  Server,
} from 'lucide-react';
import { useState, useEffect } from 'react';
import {
  getLogicalInterfacesView,
  getPhysicalNetworkDevices,
  saveInterfaceAssignment,
  type LogicalInterfaceView,
} from '@/server/agent';

export default function InterfacesPage() {
  const [interfaces, setInterfaces] = useState<LogicalInterfaceView[]>([]);
  const [physicalDevs, setPhysicalDevs] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [editingIface, setEditingIface] = useState<LogicalInterfaceView | null>(null);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Edit form state
  const [editForm, setEditForm] = useState({
    device: '',
    enabled: true,
    type: 'dhcp' as 'dhcp' | 'static',
    ipv4Address: '',
    ipv4Gateway: '',
    description: '',
    mtu: 1500,
  });

  const loadData = () => {
    setLoading(true);
    Promise.all([getLogicalInterfacesView(), getPhysicalNetworkDevices()])
      .then(([ifaceData, devData]) => {
        setInterfaces(ifaceData);
        setPhysicalDevs(devData);
      })
      .catch(() => {
        setInterfaces([]);
        setPhysicalDevs([]);
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, []);

  const openConfigModal = (iface: LogicalInterfaceView) => {
    setEditingIface(iface);
    setEditForm({
      device: iface.device,
      enabled: iface.enabled,
      type: iface.type,
      ipv4Address: iface.ipv4Address || '',
      ipv4Gateway: iface.ipv4Gateway || '',
      description: iface.description,
      mtu: iface.mtu,
    });
    setFeedback(null);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingIface) return;
    setSaving(true);
    setFeedback(null);

    try {
      const res = await saveInterfaceAssignment({
        name: editingIface.name,
        device: editForm.device,
        enabled: editForm.enabled,
        type: editForm.type,
        ipv4Address: editForm.type === 'static' ? editForm.ipv4Address : undefined,
        ipv4Gateway: editForm.type === 'static' ? editForm.ipv4Gateway : undefined,
        description: editForm.description,
        mtu: Number(editForm.mtu) || 1500,
      });

      setFeedback({ type: 'success', message: res.message });
      setEditingIface(null);
      loadData();
    } catch (err: any) {
      setFeedback({ type: 'error', message: err.message || 'Failed to save interface configuration' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <Network className="w-6 h-6 text-emerald-400" />
            <span>Interfaces Assignments</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Configure logical roles (WAN, LAN, OPT1, OPT2), physical NIC devices, and non-authoritative attached networks.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300">
            <span className="text-slate-500">Detected NICs:</span>
            <span className="text-emerald-400 font-bold">{physicalDevs.join(', ') || 'None'}</span>
          </div>
        </div>
      </div>

      {feedback && (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between ${
            feedback.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
          }`}
        >
          <div className="flex items-center gap-2 text-sm">
            {feedback.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 shrink-0" />
            )}
            <span>{feedback.message}</span>
          </div>
          <button
            type="button"
            onClick={() => setFeedback(null)}
            className="text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center p-12 bg-slate-900 border border-slate-800 rounded-xl text-slate-400 gap-3">
          <Loader2 className="w-5 h-5 animate-spin text-emerald-400" />
          <span>Scanning physical and logical network interfaces...</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {interfaces.map((iface) => {
            const isOpt = iface.isOpt;
            return (
              <div
                key={iface.name}
                className={`bg-slate-900 border rounded-xl p-5 space-y-4 transition ${
                  iface.enabled ? 'border-slate-800' : 'border-slate-800/50 opacity-70'
                }`}
              >
                {/* Header Card */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <div
                      className={`p-2 rounded-lg ${
                        iface.enabled
                          ? isOpt
                            ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                            : iface.name === 'wan'
                            ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20'
                            : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'bg-slate-800 text-slate-500'
                      }`}
                    >
                      <Network className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h2 className="text-base font-bold text-white uppercase">{iface.label}</h2>
                        <span className="text-xs bg-slate-800 text-slate-300 font-mono px-2 py-0.5 rounded border border-slate-700">
                          {iface.device || 'Unbound'}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 font-sans">{iface.description}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <span
                      className={`text-xs font-semibold px-2 py-0.5 rounded border ${
                        iface.enabled && iface.liveStatus.isUp
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                          : iface.enabled
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                          : 'bg-slate-800 text-slate-500 border-slate-700'
                      }`}
                    >
                      {iface.enabled ? (iface.liveStatus.isUp ? 'Link Up' : 'No Carrier') : 'Disabled'}
                    </span>
                    <button
                      type="button"
                      onClick={() => openConfigModal(iface)}
                      className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition cursor-pointer border border-slate-700"
                      title="Configure Interface"
                    >
                      <Settings2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {/* Non-Authoritative Safeguard Banner for OPT1 & OPT2 */}
                {isOpt && (
                  <div className="p-3 bg-cyan-950/40 border border-cyan-800/50 rounded-lg flex items-start gap-2.5 text-xs text-cyan-200">
                    <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold text-cyan-300 block">
                        Attached Network (Non-Authoritative DHCP)
                      </span>
                      <span>
                        Axonwall acts as a client on this interface. Local ISC Kea DHCP server is disabled to prevent rogue DHCP offers on attached networks.
                      </span>
                    </div>
                  </div>
                )}

                {/* LAN DHCP Status */}
                {iface.name === 'lan' && (
                  <div className="p-3 bg-emerald-950/30 border border-emerald-800/40 rounded-lg flex items-start gap-2.5 text-xs text-emerald-200">
                    <Server className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold text-emerald-300 block">Authoritative DHCP Active</span>
                      <span>Serving dynamic address leases and DNS via Kea DHCP & Unbound.</span>
                    </div>
                  </div>
                )}

                {/* Details Grid */}
                <div className="space-y-2 text-xs font-mono text-slate-300 divide-y divide-slate-800/80">
                  <div className="flex justify-between py-1.5">
                    <span className="text-slate-400 font-sans">IPv4 Configuration</span>
                    <span className="text-white font-medium">
                      {iface.type === 'dhcp' ? 'DHCP Client' : 'Static IPv4'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span className="text-slate-400 font-sans">Current IP Address</span>
                    <span
                      className={
                        iface.liveStatus.currentIp !== 'Unassigned'
                          ? 'text-emerald-400 font-bold'
                          : 'text-slate-500'
                      }
                    >
                      {iface.liveStatus.currentIp}
                    </span>
                  </div>
                  {iface.type === 'static' && (
                    <div className="flex justify-between py-1.5">
                      <span className="text-slate-400 font-sans">Configured Static IP</span>
                      <span className="text-slate-200">{iface.ipv4Address || 'None'}</span>
                    </div>
                  )}
                  <div className="flex justify-between py-1.5">
                    <span className="text-slate-400 font-sans">Default Gateway</span>
                    <span>{iface.liveStatus.currentGateway}</span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span className="text-slate-400 font-sans">MAC Address</span>
                    <span>{iface.liveStatus.mac}</span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span className="text-slate-400 font-sans">MTU</span>
                    <span>{iface.mtu}</span>
                  </div>
                </div>

                <div className="pt-2">
                  <button
                    type="button"
                    onClick={() => openConfigModal(iface)}
                    className="w-full py-2 px-3 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg transition flex items-center justify-center gap-1.5 cursor-pointer border border-slate-700"
                  >
                    <Settings2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Configure {iface.name.toUpperCase()} Assignment</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Interface Configuration Modal */}
      {editingIface && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <Settings2 className="w-5 h-5 text-emerald-400" />
                  <span>Configure Interface: {editingIface.name.toUpperCase()}</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  {editingIface.isOpt
                    ? 'Attach to an existing network without running an authoritative DHCP server.'
                    : 'Configure physical device assignment and addressing.'}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setEditingIface(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSave} className="space-y-4">
              {/* Enable Switch */}
              <div className="flex items-center justify-between p-3 bg-slate-950 rounded-xl border border-slate-800">
                <div>
                  <span className="text-sm font-semibold text-white block">Enable Interface</span>
                  <span className="text-xs text-slate-400">Activate this logical interface in Axonwall</span>
                </div>
                <input
                  type="checkbox"
                  checked={editForm.enabled}
                  onChange={(e) => setEditForm({ ...editForm, enabled: e.target.checked })}
                  className="w-5 h-5 rounded accent-emerald-500 cursor-pointer"
                />
              </div>

              {/* Physical NIC Selector */}
              <div>
                <label className="text-xs font-medium text-slate-300 block mb-1.5">
                  Physical Network Device (Linux NIC)
                </label>
                <select
                  value={editForm.device}
                  onChange={(e) => setEditForm({ ...editForm, device: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                >
                  <option value="">-- Unassigned (None) --</option>
                  {physicalDevs.map((dev) => (
                    <option key={dev} value={dev}>
                      {dev}
                    </option>
                  ))}
                  {/* Keep current device if not in physicalDevs list */}
                  {editForm.device && !physicalDevs.includes(editForm.device) && (
                    <option value={editForm.device}>{editForm.device} (Current)</option>
                  )}
                </select>
              </div>

              {/* IPv4 Configuration Mode */}
              <div>
                <label className="text-xs font-medium text-slate-300 block mb-1.5">
                  IPv4 Addressing Mode
                </label>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => setEditForm({ ...editForm, type: 'dhcp' })}
                    className={`p-3 rounded-lg border text-left cursor-pointer transition ${
                      editForm.type === 'dhcp'
                        ? 'border-emerald-500 bg-emerald-500/10 text-white'
                        : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <span className="text-xs font-bold block">DHCP Client</span>
                    <span className="text-[11px] text-slate-400 block mt-0.5">
                      {editingIface.isOpt
                        ? 'Get IP from attached network (Recommended)'
                        : 'Obtain lease from upstream'}
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setEditForm({ ...editForm, type: 'static' })}
                    className={`p-3 rounded-lg border text-left cursor-pointer transition ${
                      editForm.type === 'static'
                        ? 'border-emerald-500 bg-emerald-500/10 text-white'
                        : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <span className="text-xs font-bold block">Static IPv4</span>
                    <span className="text-[11px] text-slate-400 block mt-0.5">
                      Assign fixed IP & subnet mask
                    </span>
                  </button>
                </div>
              </div>

              {/* Static IP Fields */}
              {editForm.type === 'static' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3 bg-slate-950 rounded-xl border border-slate-800">
                  <div>
                    <label className="text-xs font-medium text-slate-300 block mb-1">
                      IPv4 Address / CIDR
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. 10.0.50.1/24"
                      value={editForm.ipv4Address}
                      onChange={(e) => setEditForm({ ...editForm, ipv4Address: e.target.value })}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-emerald-500"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium text-slate-300 block mb-1">
                      Gateway (Optional)
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. 10.0.50.254"
                      value={editForm.ipv4Gateway}
                      onChange={(e) => setEditForm({ ...editForm, ipv4Gateway: e.target.value })}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-emerald-500"
                    />
                  </div>
                </div>
              )}

              {/* Safeguard Notice for OPT1 & OPT2 */}
              {editingIface.isOpt && (
                <div className="p-3 bg-cyan-950/40 border border-cyan-800/40 rounded-xl flex items-start gap-2.5 text-xs text-cyan-200">
                  <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-cyan-300 block">
                      DHCP Server Safeguard Active
                    </span>
                    <span>
                      Axonwall will not broadcast DHCP offers on {editingIface.name.toUpperCase()}. If attached to an office, lab, or home router subnet, existing DHCP servers will operate normally without IP collisions.
                    </span>
                  </div>
                </div>
              )}

              {/* Description & MTU */}
              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2">
                  <label className="text-xs font-medium text-slate-300 block mb-1">Description</label>
                  <input
                    type="text"
                    value={editForm.description}
                    onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">MTU</label>
                  <input
                    type="number"
                    value={editForm.mtu}
                    onChange={(e) => setEditForm({ ...editForm, mtu: Number(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              {/* Modal Actions */}
              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setEditingIface(null)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
                >
                  {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
                  <span>{saving ? 'Saving...' : 'Save Configuration'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
