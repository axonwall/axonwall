'use client';

import {
  Network,
  CheckCircle2,
  Loader2,
  Settings2,
  ShieldCheck,
  AlertTriangle,
  X,
  Save,
  Server,
  Plus,
  Trash2,
  Globe,
  Cpu,
} from 'lucide-react';
import { useState, useEffect } from 'react';
import {
  getLogicalInterfacesView,
  getPhysicalNetworkDevices,
  saveInterfaceAssignment,
  deleteInterfaceAssignment,
  type LogicalInterfaceView,
} from '@/server/agent';

function suggestPoolFromCidr(cidr: string): { start: string; end: string } | null {
  const parts = (cidr || '').trim().split('/');
  const ip = parts[0] || '';
  const octets = ip.split('.').map((n) => parseInt(n, 10));
  if (octets.length !== 4 || octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return null;
  }
  const base = `${octets[0]}.${octets[1]}.${octets[2]}`;
  return { start: `${base}.100`, end: `${base}.200` };
}

export default function InterfacesPage() {
  const [interfaces, setInterfaces] = useState<LogicalInterfaceView[]>([]);
  const [physicalDevs, setPhysicalDevs] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [editingIface, setEditingIface] = useState<LogicalInterfaceView | null>(null);
  const [isCreatingNew, setIsCreatingNew] = useState(false);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Edit / Create form state
  const [editForm, setEditForm] = useState({
    name: '',
    originalName: '',
    role: 'lan' as 'wan' | 'lan',
    device: '',
    enabled: true,
    type: 'dhcp' as 'dhcp' | 'static',
    dhcpServer: false,
    dhcpPoolStart: '',
    dhcpPoolEnd: '',
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

  const getNextInterfaceName = (role: 'wan' | 'lan'): string => {
    const existingNames = new Set(interfaces.map((i) => i.name.toLowerCase()));
    if (!existingNames.has(role)) return role;
    let idx = 2;
    while (existingNames.has(`${role}${idx}`)) {
      idx += 1;
    }
    return `${role}${idx}`;
  };

  const getFirstUnassignedDevice = (): string => {
    const usedDevs = new Set(
      interfaces.filter((i) => i.enabled && i.device && i.device !== 'none').map((i) => i.device)
    );
    return physicalDevs.find((d) => !usedDevs.has(d)) || '';
  };

  const openAddModal = (presetRole: 'wan' | 'lan', presetDevice?: string) => {
    const nextName = getNextInterfaceName(presetRole);
    const dev = presetDevice ?? getFirstUnassignedDevice();
    const lanIndex = interfaces.filter((i) => i.role === 'lan').length + 1;
    const defaultStaticIp = `192.168.${lanIndex === 1 ? 1 : 10 + lanIndex}.1/24`;
    const pool = suggestPoolFromCidr(defaultStaticIp);

    setIsCreatingNew(true);
    setEditingIface({
      name: nextName,
      label: `${nextName.toUpperCase()} (${presetRole.toUpperCase()})`,
      role: presetRole,
      device: dev,
      enabled: true,
      type: presetRole === 'wan' ? 'dhcp' : 'static',
      dhcpServer: presetRole === 'lan',
      dhcpPoolStart: pool?.start || '',
      dhcpPoolEnd: pool?.end || '',
      ipv4Address: presetRole === 'lan' ? defaultStaticIp : '',
      ipv4Gateway: '',
      description:
        presetRole === 'wan'
          ? `${nextName.toUpperCase()} WAN Uplink`
          : `${nextName.toUpperCase()} Local Network`,
      mtu: 1500,
      isAuthoritativeDhcp: presetRole === 'lan',
      isOpt: false,
      liveStatus: {
        isUp: false,
        carrier: 'Unknown',
        currentIp: 'Unassigned',
        currentGateway: 'None',
        mac: '00:00:00:00:00:00',
      },
    });
    setEditForm({
      name: nextName,
      originalName: '',
      role: presetRole,
      device: dev,
      enabled: true,
      type: presetRole === 'wan' ? 'dhcp' : 'static',
      dhcpServer: presetRole === 'lan',
      dhcpPoolStart: pool?.start || '',
      dhcpPoolEnd: pool?.end || '',
      ipv4Address: presetRole === 'lan' ? defaultStaticIp : '',
      ipv4Gateway: '',
      description:
        presetRole === 'wan'
          ? `${nextName.toUpperCase()} WAN Uplink`
          : `${nextName.toUpperCase()} Local Network`,
      mtu: 1500,
    });
    setFeedback(null);
  };

  const openConfigModal = (iface: LogicalInterfaceView) => {
    const pool = suggestPoolFromCidr(iface.ipv4Address || '192.168.1.1/24');
    setIsCreatingNew(false);
    setEditingIface(iface);
    setEditForm({
      name: iface.name,
      originalName: iface.name,
      role: iface.role,
      device: iface.device === 'none' ? '' : iface.device,
      enabled: iface.enabled,
      type: iface.type,
      dhcpServer: iface.dhcpServer,
      dhcpPoolStart: iface.dhcpPoolStart || pool?.start || '',
      dhcpPoolEnd: iface.dhcpPoolEnd || pool?.end || '',
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
        name: editForm.name || editingIface.name,
        originalName: isCreatingNew ? undefined : editForm.originalName || editingIface.name,
        role: editForm.role,
        device: editForm.device,
        enabled: editForm.enabled,
        type: editForm.type,
        dhcpServer: editForm.role === 'lan' && editForm.type === 'static' ? editForm.dhcpServer : false,
        dhcpPoolStart:
          editForm.role === 'lan' && editForm.type === 'static' && editForm.dhcpServer
            ? editForm.dhcpPoolStart
            : undefined,
        dhcpPoolEnd:
          editForm.role === 'lan' && editForm.type === 'static' && editForm.dhcpServer
            ? editForm.dhcpPoolEnd
            : undefined,
        ipv4Address: editForm.type === 'static' ? editForm.ipv4Address : undefined,
        ipv4Gateway: editForm.type === 'static' ? editForm.ipv4Gateway : undefined,
        description: editForm.description,
        mtu: Number(editForm.mtu) || 1500,
      });

      setFeedback({ type: 'success', message: res.message });
      setEditingIface(null);
      setIsCreatingNew(false);
      loadData();
    } catch (err: any) {
      setFeedback({ type: 'error', message: err.message || 'Failed to save interface configuration' });
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (iface: LogicalInterfaceView) => {
    if (!confirm(`Remove logical interface ${iface.name.toUpperCase()} (${iface.device || 'unassigned'})?`)) {
      return;
    }
    setSaving(true);
    setFeedback(null);
    try {
      const res = await deleteInterfaceAssignment(iface.name);
      setFeedback({ type: 'success', message: res.message });
      if (editingIface?.name === iface.name) {
        setEditingIface(null);
      }
      loadData();
    } catch (err: any) {
      setFeedback({ type: 'error', message: err.message || 'Failed to remove interface' });
    } finally {
      setSaving(false);
    }
  };

  const assignedByDev = new Map<string, LogicalInterfaceView>();
  for (const iface of interfaces) {
    if (iface.device && iface.device !== 'none') {
      assignedByDev.set(iface.device, iface);
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <Network className="w-6 h-6 text-emerald-400" />
            <span>Network Interfaces (Multi-WAN &amp; Multi-LAN)</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Assign any number of physical ports to WAN uplinks or LAN networks. Each LAN can act as an{' '}
            <span className="text-emerald-300 font-medium">Authoritative DHCP Server</span> or{' '}
            <span className="text-cyan-300 font-medium">Join an Existing Network</span> where another router is authoritative.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={() => openAddModal('wan')}
            className="px-3.5 py-2 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/40 text-indigo-300 text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Add WAN Uplink</span>
          </button>
          <button
            type="button"
            onClick={() => openAddModal('lan')}
            className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer shadow-sm"
          >
            <Plus className="w-4 h-4" />
            <span>Add LAN Interface</span>
          </button>
        </div>
      </div>

      {/* Physical Ports Strip */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2.5">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-emerald-400" />
            <span>Detected Physical Ports ({physicalDevs.length})</span>
          </span>
          <span className="text-[11px] text-slate-500">
            Click an unassigned NIC to configure it as a WAN or LAN port
          </span>
        </div>
        <div className="flex flex-wrap gap-2">
          {physicalDevs.map((dev) => {
            const bound = assignedByDev.get(dev);
            return (
              <button
                key={dev}
                type="button"
                onClick={() => (bound ? openConfigModal(bound) : openAddModal('lan', dev))}
                className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-2 transition cursor-pointer ${
                  bound
                    ? bound.role === 'wan'
                      ? 'bg-indigo-950/50 border-indigo-500/30 text-indigo-200 hover:border-indigo-400'
                      : bound.isAuthoritativeDhcp
                        ? 'bg-emerald-950/50 border-emerald-500/30 text-emerald-200 hover:border-emerald-400'
                        : 'bg-cyan-950/50 border-cyan-500/30 text-cyan-200 hover:border-cyan-400'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white hover:border-slate-600'
                }`}
              >
                <span className="font-bold text-white">{dev}</span>
                {bound ? (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-black/40 uppercase font-sans font-semibold">
                    {bound.name} ({bound.role})
                  </span>
                ) : (
                  <span className="text-[10px] text-slate-500 font-sans">+ Assign Port</span>
                )}
              </button>
            );
          })}
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
            const isWan = iface.role === 'wan';
            const isAuthDhcp = iface.role === 'lan' && iface.isAuthoritativeDhcp;
            const isJoinedLan = iface.role === 'lan' && !iface.isAuthoritativeDhcp;

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
                          ? isWan
                            ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20'
                            : isAuthDhcp
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                              : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                          : 'bg-slate-800 text-slate-500'
                      }`}
                    >
                      {isWan ? <Globe className="w-5 h-5" /> : <Network className="w-5 h-5" />}
                    </div>
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <h2 className="text-base font-bold text-white uppercase">{iface.name}</h2>
                        <span
                          className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                            isWan
                              ? 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30'
                              : isAuthDhcp
                                ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                                : 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                          }`}
                        >
                          {isWan ? 'WAN Uplink' : isAuthDhcp ? 'LAN • Authoritative DHCP' : 'LAN • Joined Network'}
                        </span>
                        <span className="text-xs bg-slate-800 text-slate-300 font-mono px-2 py-0.5 rounded border border-slate-700">
                          {iface.device && iface.device !== 'none' ? iface.device : 'Unassigned'}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 font-sans mt-0.5">{iface.description}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5">
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
                    {interfaces.length > 1 && (
                      <button
                        type="button"
                        onClick={() => handleDelete(iface)}
                        className="p-1.5 rounded-lg bg-slate-800 hover:bg-rose-950/60 text-slate-400 hover:text-rose-300 transition cursor-pointer border border-slate-700 hover:border-rose-800"
                        title="Remove Interface"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>

                {/* Role & DHCP Authority Banner */}
                {isWan && (
                  <div className="p-3 bg-indigo-950/35 border border-indigo-800/40 rounded-lg flex items-start gap-2.5 text-xs text-indigo-200">
                    <Globe className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold text-indigo-300 block">
                        External WAN Uplink (Outbound NAT Masquerade)
                      </span>
                      <span>
                        Protected by strict WAN input firewall rules. Kea DHCP server and management anti-lockout rules are never exposed on WAN ports.
                      </span>
                    </div>
                  </div>
                )}

                {isAuthDhcp && (
                  <div className="p-3 bg-emerald-950/30 border border-emerald-800/40 rounded-lg flex items-start gap-2.5 text-xs text-emerald-200">
                    <Server className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold text-emerald-300 block">
                        Authoritative Network (Kea DHCPv4 Server Active)
                      </span>
                      <span>
                        Axonwall is the gateway and authoritative DHCP/DNS server on this network
                        {iface.dhcpPoolStart && iface.dhcpPoolEnd
                          ? ` (Pool: ${iface.dhcpPoolStart} – ${iface.dhcpPoolEnd}).`
                          : '.'}
                      </span>
                    </div>
                  </div>
                )}

                {isJoinedLan && (
                  <div className="p-3 bg-cyan-950/40 border border-cyan-800/50 rounded-lg flex items-start gap-2.5 text-xs text-cyan-200">
                    <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold text-cyan-300 block">
                        Joined Existing Network (Non-Authoritative)
                      </span>
                      <span>
                        Another router/server is authoritative on this network. Axonwall joins via{' '}
                        {iface.type === 'dhcp' ? 'DHCP Client' : 'Static IPv4'} and disables Kea DHCP server on this port.
                      </span>
                    </div>
                  </div>
                )}

                {/* Details Grid */}
                <div className="space-y-2 text-xs font-mono text-slate-300 divide-y divide-slate-800/80">
                  <div className="flex justify-between py-1.5">
                    <span className="text-slate-400 font-sans">Participation Mode</span>
                    <span className="text-white font-medium">
                      {isWan
                        ? iface.type === 'dhcp'
                          ? 'WAN — DHCP Client'
                          : 'WAN — Static IPv4'
                        : isAuthDhcp
                          ? 'Authoritative Gateway + DHCP Server'
                          : iface.type === 'dhcp'
                            ? 'Joined Network — DHCP Client'
                            : 'Joined Network — Static IPv4'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span className="text-slate-400 font-sans">Live IPv4 Address</span>
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
                    <span className="text-slate-400 font-sans">Gateway</span>
                    <span>{iface.ipv4Gateway || iface.liveStatus.currentGateway}</span>
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
                    <span>Configure {iface.name.toUpperCase()}</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Interface Configuration / Creation Modal */}
      {editingIface && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 space-y-5 shadow-2xl my-8">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <Settings2 className="w-5 h-5 text-emerald-400" />
                  <span>
                    {isCreatingNew
                      ? 'Add Network Interface'
                      : `Configure Interface: ${editingIface.name.toUpperCase()}`}
                  </span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Configure role (Multi-WAN or Multi-LAN), physical NIC binding, and DHCP authority.
                </p>
              </div>
              <button
                type="button"
                onClick={() => {
                  setEditingIface(null);
                  setIsCreatingNew(false);
                }}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSave} className="space-y-4">
              {/* Interface Name & Enable Switch */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">
                    Logical Interface Name
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. wan, wan2, lan, lan2, mgmt"
                    value={editForm.name}
                    onChange={(e) =>
                      setEditForm({
                        ...editForm,
                        name: e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, ''),
                      })
                    }
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-emerald-500"
                  />
                </div>
                <div className="flex items-center justify-between p-3 bg-slate-950 rounded-xl border border-slate-800">
                  <div>
                    <span className="text-xs font-semibold text-white block">Enable Interface</span>
                    <span className="text-[11px] text-slate-400">Bring link up &amp; apply rules</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={editForm.enabled}
                    onChange={(e) => setEditForm({ ...editForm, enabled: e.target.checked })}
                    className="w-5 h-5 rounded accent-emerald-500 cursor-pointer"
                  />
                </div>
              </div>

              {/* Role Selector: WAN vs LAN */}
              <div>
                <label className="text-xs font-medium text-slate-300 block mb-1.5">
                  Interface Role
                </label>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => {
                      const nextName =
                        isCreatingNew && editForm.name.startsWith('lan')
                          ? getNextInterfaceName('wan')
                          : editForm.name;
                      setEditForm({
                        ...editForm,
                        name: nextName,
                        role: 'wan',
                        dhcpServer: false,
                      });
                    }}
                    className={`p-3 rounded-xl border text-left cursor-pointer transition ${
                      editForm.role === 'wan'
                        ? 'border-indigo-500 bg-indigo-500/15 text-white'
                        : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <span className="text-xs font-bold flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5 text-indigo-400" />
                      <span>WAN Uplink (Multi-WAN)</span>
                    </span>
                    <span className="text-[11px] text-slate-400 block mt-1">
                      ISP/upstream gateway with outbound NAT masquerade &amp; strict ingress firewall
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      const nextName =
                        isCreatingNew && editForm.name.startsWith('wan')
                          ? getNextInterfaceName('lan')
                          : editForm.name;
                      setEditForm({
                        ...editForm,
                        name: nextName,
                        role: 'lan',
                      });
                    }}
                    className={`p-3 rounded-xl border text-left cursor-pointer transition ${
                      editForm.role === 'lan'
                        ? 'border-emerald-500 bg-emerald-500/15 text-white'
                        : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <span className="text-xs font-bold flex items-center gap-1.5">
                      <Network className="w-3.5 h-3.5 text-emerald-400" />
                      <span>LAN / Internal (Multi-LAN)</span>
                    </span>
                    <span className="text-[11px] text-slate-400 block mt-1">
                      Local subnet (Authoritative DHCP server) or join an existing network
                    </span>
                  </button>
                </div>
              </div>

              {/* Physical NIC Selector */}
              <div>
                <label className="text-xs font-medium text-slate-300 block mb-1.5">
                  Physical Network Port (Linux NIC)
                </label>
                <select
                  value={editForm.device}
                  onChange={(e) => setEditForm({ ...editForm, device: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                >
                  <option value="">-- Unassigned (None) --</option>
                  {physicalDevs.map((dev) => {
                    const bound = assignedByDev.get(dev);
                    const isBoundElsewhere = bound && bound.name !== editForm.originalName;
                    return (
                      <option key={dev} value={dev}>
                        {dev}
                        {isBoundElsewhere ? ` (currently ${bound.name.toUpperCase()})` : ''}
                      </option>
                    );
                  })}
                  {editForm.device && !physicalDevs.includes(editForm.device) && (
                    <option value={editForm.device}>{editForm.device} (Current)</option>
                  )}
                </select>
              </div>

              {/* Network Participation / Addressing Mode */}
              {editForm.role === 'wan' ? (
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1.5">
                    WAN Addressing Mode
                  </label>
                  <div className="grid grid-cols-2 gap-3">
                    <button
                      type="button"
                      onClick={() => setEditForm({ ...editForm, type: 'dhcp', dhcpServer: false })}
                      className={`p-3 rounded-lg border text-left cursor-pointer transition ${
                        editForm.type === 'dhcp'
                          ? 'border-indigo-500 bg-indigo-500/10 text-white'
                          : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <span className="text-xs font-bold block">DHCP Client</span>
                      <span className="text-[11px] text-slate-400 block mt-0.5">
                        Obtain dynamic IP &amp; gateway from upstream ISP/router
                      </span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setEditForm({ ...editForm, type: 'static', dhcpServer: false })}
                      className={`p-3 rounded-lg border text-left cursor-pointer transition ${
                        editForm.type === 'static'
                          ? 'border-indigo-500 bg-indigo-500/10 text-white'
                          : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <span className="text-xs font-bold block">Static IPv4</span>
                      <span className="text-[11px] text-slate-400 block mt-0.5">
                        Fixed WAN IP address, netmask &amp; upstream gateway
                      </span>
                    </button>
                  </div>
                </div>
              ) : (
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1.5">
                    LAN Network Authority &amp; Addressing Mode
                  </label>
                  <div className="grid grid-cols-1 gap-2.5">
                    {/* Option 1: Authoritative DHCP Server */}
                    <button
                      type="button"
                      onClick={() => {
                        const nextIp = editForm.ipv4Address || '192.168.1.1/24';
                        const pool = suggestPoolFromCidr(nextIp);
                        setEditForm({
                          ...editForm,
                          type: 'static',
                          dhcpServer: true,
                          ipv4Address: nextIp,
                          dhcpPoolStart: editForm.dhcpPoolStart || pool?.start || '192.168.1.100',
                          dhcpPoolEnd: editForm.dhcpPoolEnd || pool?.end || '192.168.1.200',
                        });
                      }}
                      className={`p-3 rounded-xl border text-left cursor-pointer transition ${
                        editForm.type === 'static' && editForm.dhcpServer
                          ? 'border-emerald-500 bg-emerald-500/10 text-white'
                          : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-emerald-300">
                          1. Authoritative Network (Axonwall is Gateway &amp; DHCP Server)
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
                          Kea DHCP ON
                        </span>
                      </div>
                      <span className="text-[11px] text-slate-400 block mt-1">
                        Assign a static gateway IP to Axonwall and serve dynamic DHCPv4 leases to clients on this port.
                      </span>
                    </button>

                    {/* Option 2: Join Existing Network via DHCP Client */}
                    <button
                      type="button"
                      onClick={() =>
                        setEditForm({
                          ...editForm,
                          type: 'dhcp',
                          dhcpServer: false,
                        })
                      }
                      className={`p-3 rounded-xl border text-left cursor-pointer transition ${
                        editForm.type === 'dhcp' && !editForm.dhcpServer
                          ? 'border-cyan-500 bg-cyan-500/10 text-white'
                          : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-cyan-300">
                          2. Join Existing Network — DHCP Client (Non-Authoritative)
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300">
                          Kea DHCP OFF
                        </span>
                      </div>
                      <span className="text-[11px] text-slate-400 block mt-1">
                        Another router/server is authoritative on this network. Axonwall obtains an IP lease via DHCP client and never offers DHCP leases.
                      </span>
                    </button>

                    {/* Option 3: Join Existing Network via Static IP */}
                    <button
                      type="button"
                      onClick={() =>
                        setEditForm({
                          ...editForm,
                          type: 'static',
                          dhcpServer: false,
                        })
                      }
                      className={`p-3 rounded-xl border text-left cursor-pointer transition ${
                        editForm.type === 'static' && !editForm.dhcpServer
                          ? 'border-cyan-500 bg-cyan-500/10 text-white'
                          : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-cyan-300">
                          3. Join Existing Network — Static IPv4 (Non-Authoritative)
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300">
                          Kea DHCP OFF
                        </span>
                      </div>
                      <span className="text-[11px] text-slate-400 block mt-1">
                        Another router/server is authoritative (or static subnet). Axonwall uses a fixed IPv4 address without running a DHCP server.
                      </span>
                    </button>
                  </div>
                </div>
              )}

              {/* Static IP + Optional DHCP Pool Fields */}
              {editForm.type === 'static' && (
                <div className="space-y-3 p-3.5 bg-slate-950 rounded-xl border border-slate-800">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="text-xs font-medium text-slate-300 block mb-1">
                        IPv4 Address / CIDR
                      </label>
                      <input
                        type="text"
                        required
                        placeholder="e.g. 192.168.10.1/24"
                        value={editForm.ipv4Address}
                        onChange={(e) => {
                          const val = e.target.value;
                          const pool = suggestPoolFromCidr(val);
                          setEditForm({
                            ...editForm,
                            ipv4Address: val,
                            ...(pool && editForm.dhcpServer
                              ? { dhcpPoolStart: pool.start, dhcpPoolEnd: pool.end }
                              : {}),
                          });
                        }}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-emerald-500"
                      />
                    </div>
                    <div>
                      <label className="text-xs font-medium text-slate-300 block mb-1">
                        Upstream Gateway {editForm.role === 'wan' ? '(Required for Static WAN)' : '(Optional)'}
                      </label>
                      <input
                        type="text"
                        placeholder="e.g. 192.168.10.254"
                        value={editForm.ipv4Gateway}
                        onChange={(e) => setEditForm({ ...editForm, ipv4Gateway: e.target.value })}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-emerald-500"
                      />
                    </div>
                  </div>

                  {editForm.role === 'lan' && editForm.dhcpServer && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-slate-800/80">
                      <div>
                        <label className="text-xs font-medium text-emerald-300 block mb-1">
                          Authoritative DHCP Pool Start
                        </label>
                        <input
                          type="text"
                          placeholder="e.g. 192.168.10.100"
                          value={editForm.dhcpPoolStart}
                          onChange={(e) => setEditForm({ ...editForm, dhcpPoolStart: e.target.value })}
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-emerald-500"
                        />
                      </div>
                      <div>
                        <label className="text-xs font-medium text-emerald-300 block mb-1">
                          Authoritative DHCP Pool End
                        </label>
                        <input
                          type="text"
                          placeholder="e.g. 192.168.10.200"
                          value={editForm.dhcpPoolEnd}
                          onChange={(e) => setEditForm({ ...editForm, dhcpPoolEnd: e.target.value })}
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-emerald-500"
                        />
                      </div>
                    </div>
                  )}
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
                  onClick={() => {
                    setEditingIface(null);
                    setIsCreatingNew(false);
                  }}
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
                  <span>{saving ? 'Saving...' : 'Save Interface'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

