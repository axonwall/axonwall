'use client';

import { Route, CheckCircle2, ArrowRight } from 'lucide-react';
import { useState } from 'react';

export default function RoutingPage() {
  const [gateways] = useState([
    {
      name: 'WAN_DHCP',
      interface: 'wan',
      gateway: '192.168.1.1',
      monitorIp: '1.1.1.1',
      rtt: '1.4 ms',
      loss: '0.0%',
      status: 'Online',
      isDefault: true,
    },
  ]);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Gateways & Routing</h1>
        <p className="text-sm text-slate-400 mt-1">
          Monitor uplink gateways, packet loss, RTT, and multi-WAN failover policies.
        </p>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-950 text-slate-400 text-xs font-semibold uppercase tracking-wider border-b border-slate-800">
            <tr>
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Interface</th>
              <th className="px-4 py-3">Gateway IP</th>
              <th className="px-4 py-3">Monitor IP</th>
              <th className="px-4 py-3">RTT</th>
              <th className="px-4 py-3">Packet Loss</th>
              <th className="px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
            {gateways.map((gw) => (
              <tr key={gw.name} className="hover:bg-slate-800/40 transition">
                <td className="px-4 py-3 font-semibold text-white">
                  {gw.name} {gw.isDefault && <span className="text-[10px] bg-slate-800 px-1.5 py-0.5 rounded text-slate-400 font-sans">Default</span>}
                </td>
                <td className="px-4 py-3 text-slate-400 uppercase">{gw.interface}</td>
                <td className="px-4 py-3 text-slate-300">{gw.gateway}</td>
                <td className="px-4 py-3 text-cyan-400">{gw.monitorIp}</td>
                <td className="px-4 py-3 text-emerald-400">{gw.rtt}</td>
                <td className="px-4 py-3 text-emerald-400">{gw.loss}</td>
                <td className="px-4 py-3">
                  <span className="inline-flex items-center gap-1 text-emerald-400 font-medium">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    {gw.status}
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
