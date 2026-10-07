'use client';

import React, { useState } from 'react';

export default function GatewaysPage() {
  const [gateways, setGateways] = useState([
    { id: 'gw-wan1', name: 'WAN_ISP1', interface: 'eth0', ip: '192.168.1.1', tier: 1, status: 'Online', latency: '12ms', loss: '0%' },
    { id: 'gw-wan2', name: 'WAN_ISP2_BACKUP', interface: 'eth2', ip: '10.0.0.1', tier: 2, status: 'Standby', latency: '24ms', loss: '0%' }
  ]);

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Multi-WAN Gateways</h1>
          <p className="text-sm text-slate-500 mt-1">Configure gateway groups, load balancing, and failover tiers.</p>
        </div>
        <button className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded text-sm font-medium">
          Add Gateway
        </button>
      </div>

      <div className="bg-white border rounded-lg shadow-sm overflow-hidden">
        <table className="w-full text-sm text-left">
          <thead className="bg-slate-50 text-slate-600 font-medium border-b">
            <tr>
              <th className="px-6 py-3">Name</th>
              <th className="px-6 py-3">Interface</th>
              <th className="px-6 py-3">Gateway IP</th>
              <th className="px-6 py-3">Tier</th>
              <th className="px-6 py-3">Monitor Status</th>
              <th className="px-6 py-3">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {gateways.map((gw) => (
              <tr key={gw.id} className="hover:bg-slate-50/50">
                <td className="px-6 py-4 font-medium">{gw.name}</td>
                <td className="px-6 py-4"><code>{gw.interface}</code></td>
                <td className="px-6 py-4">{gw.ip}</td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${gw.tier === 1 ? 'bg-blue-100 text-blue-700' : 'bg-slate-100 text-slate-600'}`}>
                    Tier {gw.tier}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <div className="flex flex-col">
                    <span className={`text-xs font-semibold ${gw.status === 'Online' ? 'text-green-600' : 'text-amber-600'}`}>
                      {gw.status}
                    </span>
                    <span className="text-xs text-slate-400">{gw.latency} | {gw.loss} loss</span>
                  </div>
                </td>
                <td className="px-6 py-4 text-blue-600 hover:underline cursor-pointer">Edit</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      
      <div className="bg-blue-50 border border-blue-100 p-4 rounded-lg">
        <h3 className="text-sm font-semibold text-blue-800">Dynamic Probing Active</h3>
        <p className="text-sm text-blue-600 mt-1">
          The routing engine is actively probing 8.8.8.8 over all gateways via ICMP. Traffic will automatically failover to Tier 2 if Tier 1 experiences greater than 20% packet loss.
        </p>
      </div>
    </div>
  );
}
