'use client';

import { useState } from 'react';
import { Route, Plus, Trash2, Globe, Layers } from 'lucide-react';
import type { Gateway, GatewayGroup } from '@axonwall/lib/schemas';

export default function GatewaysAndGroupsPage() {
  const [gateways] = useState<Gateway[]>([
    {
      id: 'gw-wan1',
      name: 'WAN1_Fiber_GW',
      interface: 'wan',
      gatewayIp: '198.51.100.1',
      monitorIp: '1.1.1.1',
      weight: 1,
      isDefault: true,
      enabled: true,
      description: 'Primary Gigabit Fiber Uplink',
    },
    {
      id: 'gw-wan2',
      name: 'WAN2_LTE_GW',
      interface: 'opt1',
      gatewayIp: '203.0.113.1',
      monitorIp: '8.8.8.8',
      weight: 1,
      isDefault: false,
      enabled: true,
      description: 'Secondary Backup 5G/LTE Gateway',
    },
  ]);

  const [groups, setGroups] = useState<GatewayGroup[]>([
    {
      id: 'grp-failover',
      name: 'WAN_Failover_Tier1_Tier2',
      trigger: 'loss',
      members: [
        { gatewayName: 'WAN1_Fiber_GW', tier: 1, weight: 1 },
        { gatewayName: 'WAN2_LTE_GW', tier: 2, weight: 1 },
      ],
      description: 'Automatic failover to LTE if Fiber experiences >20% packet loss',
    },
    {
      id: 'grp-balance',
      name: 'WAN_LoadBalance_Equal',
      trigger: 'down',
      members: [
        { gatewayName: 'WAN1_Fiber_GW', tier: 1, weight: 2 },
        { gatewayName: 'WAN2_LTE_GW', tier: 1, weight: 1 },
      ],
      description: 'Weighted 2:1 ECMP load balancing between Fiber and LTE',
    },
  ]);

  const [newGroupName, setNewGroupName] = useState('');
  const [newGroupTrigger, setNewGroupTrigger] = useState<'down' | 'loss' | 'latency' | 'both'>('loss');
  const [newGroupDesc, setNewGroupDesc] = useState('');

  const handleAddGroup = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newGroupName) return;
    setGroups([
      ...groups,
      {
        id: `grp-${Date.now()}`,
        name: newGroupName,
        trigger: newGroupTrigger,
        members: [
          { gatewayName: 'WAN1_Fiber_GW', tier: 1, weight: 1 },
          { gatewayName: 'WAN2_LTE_GW', tier: 2, weight: 1 },
        ],
        description: newGroupDesc,
      },
    ]);
    setNewGroupName('');
    setNewGroupDesc('');
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <Route className="w-6 h-6 text-emerald-400" />
          Multi-WAN Gateway Groups & Policy Routing
        </h1>
        <p className="text-sm text-slate-400">
          Manage upstream gateway health monitors, multi-tiered failover groups, and weighted ECMP load balancing.
        </p>
      </div>

      {/* Upstream Gateways Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex justify-between items-center">
          <div>
            <h3 className="font-semibold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-emerald-400" />
              Configured Gateways
            </h3>
            <p className="text-xs text-slate-400">Monitored via ICMP probes for packet loss and latency</p>
          </div>
        </div>

        <table className="w-full text-sm text-left">
          <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
            <tr>
              <th className="px-4 py-3">Gateway Name</th>
              <th className="px-4 py-3">Interface</th>
              <th className="px-4 py-3">Gateway IP</th>
              <th className="px-4 py-3">Monitor Target</th>
              <th className="px-4 py-3">Default Route</th>
              <th className="px-4 py-3">RTT / Loss</th>
              <th className="px-4 py-3">Description</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-slate-300">
            {gateways.map((gw) => (
              <tr key={gw.id || gw.name} className="hover:bg-slate-800/30">
                <td className="px-4 py-3 font-semibold text-white font-mono">{gw.name}</td>
                <td className="px-4 py-3 font-mono text-emerald-400 uppercase text-xs">{gw.interface}</td>
                <td className="px-4 py-3 font-mono">{gw.gatewayIp}</td>
                <td className="px-4 py-3 font-mono text-slate-400">{gw.monitorIp || gw.gatewayIp}</td>
                <td className="px-4 py-3">
                  {gw.isDefault ? (
                    <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-xs font-mono border border-emerald-500/20 font-semibold">
                      Primary Default
                    </span>
                  ) : (
                    <span className="text-xs text-slate-500">Secondary</span>
                  )}
                </td>
                <td className="px-4 py-3 font-mono text-xs">
                  <span className="text-emerald-400 font-semibold">2.4 ms</span>
                  <span className="text-slate-500 text-[10px] ml-1.5">(0% loss)</span>
                </td>
                <td className="px-4 py-3 text-slate-400 text-xs">{gw.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Gateway Groups */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex justify-between items-center">
          <div>
            <h3 className="font-semibold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-emerald-400" />
              Multi-WAN Gateway Groups
            </h3>
            <p className="text-xs text-slate-400">
              Assigned directly in Firewall Rules to enforce policy routing (<code className="text-emerald-400">route-to</code>)
            </p>
          </div>
        </div>

        <div className="p-4 space-y-4">
          {groups.map((grp) => (
            <div key={grp.id} className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
              <div className="flex justify-between items-start">
                <div>
                  <h4 className="font-bold text-white font-mono text-sm">{grp.name}</h4>
                  <p className="text-xs text-slate-400 mt-0.5">{grp.description}</p>
                </div>
                <div className="flex items-center gap-3">
                  <span className="px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300">
                    Trigger on: <strong className="text-emerald-400 uppercase">{grp.trigger}</strong>
                  </span>
                  <button
                    onClick={() => setGroups(groups.filter((g) => g.id !== grp.id))}
                    className="text-slate-500 hover:text-red-400 transition"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Tiers Matrix */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-1">
                {grp.members.map((m) => (
                  <div
                    key={m.gatewayName}
                    className="p-3 bg-slate-900 border border-slate-800 rounded-lg flex items-center justify-between"
                  >
                    <div>
                      <span className="text-xs font-mono text-white block font-medium">{m.gatewayName}</span>
                      <span className="text-[11px] text-slate-400">Weight: {m.weight}</span>
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                        m.tier === 1
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                      }`}
                    >
                      Tier {m.tier}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Add Gateway Group */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <h4 className="font-semibold text-white mb-3 text-sm flex items-center gap-2">
          <Plus className="w-4 h-4 text-emerald-400" />
          Create New Gateway Group
        </h4>
        <form onSubmit={handleAddGroup} className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Group Name</label>
            <input
              type="text"
              value={newGroupName}
              onChange={(e) => setNewGroupName(e.target.value)}
              placeholder="e.g. WAN_VOIP_FAILOVER"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Failover Trigger</label>
            <select
              value={newGroupTrigger}
              onChange={(e) => setNewGroupTrigger(e.target.value as any)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
            >
              <option value="loss">Packet Loss (&gt; 20%)</option>
              <option value="latency">High Latency (&gt; 150ms)</option>
              <option value="both">Packet Loss or Latency</option>
              <option value="down">Member Down Only</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Description</label>
            <input
              type="text"
              value={newGroupDesc}
              onChange={(e) => setNewGroupDesc(e.target.value)}
              placeholder="Failover purpose"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500"
            />
          </div>
          <div>
            <button
              type="submit"
              className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-2 px-4 rounded-lg text-sm transition flex items-center justify-center gap-2"
            >
              <Plus className="w-4 h-4" />
              Add Group
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
