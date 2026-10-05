'use client';

import { useState } from 'react';
import { Layers, Network, GitFork, ShieldAlert, Cpu, Plus, Trash2, CheckCircle2 } from 'lucide-react';
import type { Vlan, Bridge, Bond, VirtualIp, Vrf } from '@axonwall/lib/schemas';

export default function AdvancedInterfacesPage() {
  const [activeTab, setActiveTab] = useState<'vlan' | 'bridge' | 'bond' | 'vip' | 'vrf'>('vlan');

  // Sample initial state
  const [vlans, setVlans] = useState<Vlan[]>([
    {
      id: 'vlan-10',
      tag: 10,
      parentInterface: 'eth1',
      vlanInterface: 'eth1.10',
      priority: 0,
      description: 'Management VLAN',
    },
    {
      id: 'vlan-20',
      tag: 20,
      parentInterface: 'eth1',
      vlanInterface: 'eth1.20',
      priority: 2,
      description: 'IoT Isolated Network',
    },
    {
      id: 'vlan-30',
      tag: 30,
      parentInterface: 'eth1',
      vlanInterface: 'eth1.30',
      priority: 5,
      description: 'VoIP Telephony',
    },
  ]);

  const [bridges, setBridges] = useState<Bridge[]>([
    {
      id: 'br-lan',
      name: 'br0',
      members: [
        { interface: 'eth2', stp: true, cost: 100, priority: 32 },
        { interface: 'eth3', stp: true, cost: 100, priority: 32 },
      ],
      vlanFiltering: true,
      stp: false,
      description: 'Main LAN Bridge with VLAN Filtering',
    },
  ]);

  const [bonds, setBonds] = useState<Bond[]>([
    {
      id: 'bond-uplink',
      name: 'bond0',
      members: ['eth4', 'eth5'],
      mode: '802.3ad',
      lacpRate: 'fast',
      xmitHashPolicy: 'layer2+3',
      miimon: 100,
      description: 'Dual 10GbE LACP Uplink to Core Switch',
    },
  ]);

  const [vips, setVips] = useState<VirtualIp[]>([
    {
      id: 'vip-1',
      interface: 'wan',
      ip: '198.51.100.10',
      subnetBits: 32,
      type: 'alias',
      description: 'Secondary WAN Public IP for DMZ Mail',
    },
    {
      id: 'vip-2',
      interface: 'lan',
      ip: '192.168.100.254',
      subnetBits: 24,
      type: 'carp',
      vhid: 1,
      password: 'vrrpPassword',
      description: 'CARP HA Virtual Gateway IP',
    },
  ]);

  const [vrfs, setVrfs] = useState<Vrf[]>([
    {
      id: 'vrf-mgmt',
      name: 'vrf_mgmt',
      tableId: 100,
      interfaces: ['eth0.10'],
      description: 'Out-of-band Management Isolation Table',
    },
  ]);

  // Form states for quick add
  const [newVlanTag, setNewVlanTag] = useState('');
  const [newVlanParent, setNewVlanParent] = useState('eth1');
  const [newVlanDesc, setNewVlanDesc] = useState('');

  const handleAddVlan = (e: React.FormEvent) => {
    e.preventDefault();
    const tag = Number.parseInt(newVlanTag, 10);
    if (!tag || tag < 1 || tag > 4094) return;
    setVlans([
      ...vlans,
      {
        id: `vlan-${Date.now()}`,
        tag,
        parentInterface: newVlanParent,
        vlanInterface: `${newVlanParent}.${tag}`,
        priority: 0,
        description: newVlanDesc,
      },
    ]);
    setNewVlanTag('');
    setNewVlanDesc('');
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-emerald-400" />
          Advanced Interfaces & Virtual Topologies
        </h1>
        <p className="text-sm text-slate-400">
          Configure 802.1Q VLANs, Linux VLAN-aware bridges, LAGG 802.3ad LACP bonding, Virtual IPs, and VRFs.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-1">
        <button
          onClick={() => setActiveTab('vlan')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
            activeTab === 'vlan'
              ? 'border-emerald-400 text-emerald-400 bg-slate-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4" />
          VLANs (802.1Q) ({vlans.length})
        </button>
        <button
          onClick={() => setActiveTab('bridge')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
            activeTab === 'bridge'
              ? 'border-emerald-400 text-emerald-400 bg-slate-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Network className="w-4 h-4" />
          Bridges ({bridges.length})
        </button>
        <button
          onClick={() => setActiveTab('bond')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
            activeTab === 'bond'
              ? 'border-emerald-400 text-emerald-400 bg-slate-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <GitFork className="w-4 h-4" />
          Bonds / LAGG ({bonds.length})
        </button>
        <button
          onClick={() => setActiveTab('vip')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
            activeTab === 'vip'
              ? 'border-emerald-400 text-emerald-400 bg-slate-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          Virtual IPs ({vips.length})
        </button>
        <button
          onClick={() => setActiveTab('vrf')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
            activeTab === 'vrf'
              ? 'border-emerald-400 text-emerald-400 bg-slate-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Cpu className="w-4 h-4" />
          VRF Routing Tables ({vrfs.length})
        </button>
      </div>

      {/* Tab: VLANs */}
      {activeTab === 'vlan' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center">
              <div>
                <h3 className="font-semibold text-white">802.1Q Tagged VLAN Interfaces</h3>
                <p className="text-xs text-slate-400">Created as kernel sub-interfaces (e.g. eth1.100)</p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">VLAN Tag</th>
                    <th className="px-4 py-3">Device Interface</th>
                    <th className="px-4 py-3">Parent Link</th>
                    <th className="px-4 py-3">802.1p Priority</th>
                    <th className="px-4 py-3">Description</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {vlans.map((vlan) => (
                    <tr key={vlan.id || vlan.tag} className="hover:bg-slate-800/30">
                      <td className="px-4 py-3 font-mono text-emerald-400 font-semibold">
                        Tag {vlan.tag}
                      </td>
                      <td className="px-4 py-3 font-mono font-medium text-white">{vlan.vlanInterface}</td>
                      <td className="px-4 py-3 font-mono text-slate-400">{vlan.parentInterface}</td>
                      <td className="px-4 py-3 font-mono">{vlan.priority}</td>
                      <td className="px-4 py-3 text-slate-400">{vlan.description}</td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => setVlans(vlans.filter((v) => v.id !== vlan.id))}
                          className="text-slate-500 hover:text-red-400 transition"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Add VLAN Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
            <h4 className="font-semibold text-white mb-3 text-sm flex items-center gap-2">
              <Plus className="w-4 h-4 text-emerald-400" />
              Add 802.1Q VLAN
            </h4>
            <form onSubmit={handleAddVlan} className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">VLAN Tag (1-4094)</label>
                <input
                  type="number"
                  min="1"
                  max="4094"
                  value={newVlanTag}
                  onChange={(e) => setNewVlanTag(e.target.value)}
                  placeholder="100"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Parent Physical Link</label>
                <select
                  value={newVlanParent}
                  onChange={(e) => setNewVlanParent(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                >
                  <option value="eth0">eth0 (WAN)</option>
                  <option value="eth1">eth1 (LAN)</option>
                  <option value="bond0">bond0 (LACP)</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Description</label>
                <input
                  type="text"
                  value={newVlanDesc}
                  onChange={(e) => setNewVlanDesc(e.target.value)}
                  placeholder="e.g. DMZ Isolated"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div>
                <button
                  type="submit"
                  className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-2 px-4 rounded-lg text-sm transition flex items-center justify-center gap-2"
                >
                  <Plus className="w-4 h-4" />
                  Create VLAN
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Tab: Bridges */}
      {activeTab === 'bridge' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-slate-800 flex justify-between items-center">
            <div>
              <h3 className="font-semibold text-white">Linux VLAN-Aware Bridges</h3>
              <p className="text-xs text-slate-400">High-performance L2 switching in kernel space</p>
            </div>
          </div>
          <table className="w-full text-sm text-left">
            <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Bridge Name</th>
                <th className="px-4 py-3">Member Interfaces</th>
                <th className="px-4 py-3">VLAN Filtering</th>
                <th className="px-4 py-3">STP (Spanning Tree)</th>
                <th className="px-4 py-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {bridges.map((br) => (
                <tr key={br.id || br.name} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3 font-mono font-semibold text-white">{br.name}</td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1.5 flex-wrap">
                      {br.members.map((m) => (
                        <span key={m.interface} className="px-2 py-0.5 rounded bg-slate-800 font-mono text-xs text-emerald-400 border border-slate-700">
                          {m.interface}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    {br.vlanFiltering ? (
                      <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Enabled (vlan_filtering 1)
                      </span>
                    ) : (
                      <span className="text-xs text-slate-500">Disabled</span>
                    )}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{br.stp ? 'Enabled' : 'Disabled'}</td>
                  <td className="px-4 py-3 text-slate-400">{br.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab: Bonds */}
      {activeTab === 'bond' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-slate-800 flex justify-between items-center">
            <div>
              <h3 className="font-semibold text-white">Link Aggregation Groups (LAGG / Bonds)</h3>
              <p className="text-xs text-slate-400">802.3ad LACP, active-backup, and round-robin bonding</p>
            </div>
          </div>
          <table className="w-full text-sm text-left">
            <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Bond Name</th>
                <th className="px-4 py-3">Mode</th>
                <th className="px-4 py-3">Slaves / Members</th>
                <th className="px-4 py-3">LACP Rate</th>
                <th className="px-4 py-3">Transmit Hash</th>
                <th className="px-4 py-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {bonds.map((b) => (
                <tr key={b.id || b.name} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3 font-mono font-semibold text-white">{b.name}</td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-xs font-mono border border-emerald-500/20 font-semibold">
                      {b.mode}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300">
                    {b.members.join(', ')}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{b.lacpRate}</td>
                  <td className="px-4 py-3 font-mono text-xs">{b.xmitHashPolicy}</td>
                  <td className="px-4 py-3 text-slate-400">{b.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab: Virtual IPs */}
      {activeTab === 'vip' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-slate-800 flex justify-between items-center">
            <div>
              <h3 className="font-semibold text-white">Virtual IP Addresses (VIP)</h3>
              <p className="text-xs text-slate-400">IP Aliases for multi-IP WANs and CARP/VRRP high availability</p>
            </div>
          </div>
          <table className="w-full text-sm text-left">
            <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Virtual IP / Subnet</th>
                <th className="px-4 py-3">Interface</th>
                <th className="px-4 py-3">VHID / Group</th>
                <th className="px-4 py-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {vips.map((vip) => (
                <tr key={vip.id} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3">
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-mono uppercase font-semibold ${
                        vip.type === 'carp'
                          ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                          : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                      }`}
                    >
                      {vip.type}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono font-medium text-white">
                    {vip.ip}/{vip.subnetBits}
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-400">{vip.interface}</td>
                  <td className="px-4 py-3 font-mono text-xs">{vip.vhid ? `vhid ${vip.vhid}` : '-'}</td>
                  <td className="px-4 py-3 text-slate-400">{vip.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab: VRF */}
      {activeTab === 'vrf' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-slate-800 flex justify-between items-center">
            <div>
              <h3 className="font-semibold text-white">VRF (Virtual Routing and Forwarding)</h3>
              <p className="text-xs text-slate-400">Strict kernel routing domain and interface isolation (E11)</p>
            </div>
          </div>
          <table className="w-full text-sm text-left">
            <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">VRF Name</th>
                <th className="px-4 py-3">Routing Table ID</th>
                <th className="px-4 py-3">Bound Interfaces</th>
                <th className="px-4 py-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {vrfs.map((vrf) => (
                <tr key={vrf.id} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3 font-mono font-semibold text-emerald-400">{vrf.name}</td>
                  <td className="px-4 py-3 font-mono text-white">table {vrf.tableId}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300">{vrf.interfaces.join(', ')}</td>
                  <td className="px-4 py-3 text-slate-400">{vrf.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
