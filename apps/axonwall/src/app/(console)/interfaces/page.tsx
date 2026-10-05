'use client';

import { Network, CheckCircle2, ArrowRight } from 'lucide-react';
import { useState } from 'react';

export default function InterfacesPage() {
  const [interfaces] = useState([
    {
      name: 'wan',
      device: 'eth0',
      type: 'DHCP Client',
      ipv4: '192.168.1.150/24',
      gateway: '192.168.1.1',
      mtu: 1500,
      mac: '52:54:00:12:34:56',
      status: 'Up',
    },
    {
      name: 'lan',
      device: 'eth1',
      type: 'Static IPv4',
      ipv4: '192.168.100.1/24',
      gateway: 'None',
      mtu: 1500,
      mac: '52:54:00:12:34:57',
      status: 'Up',
    },
  ]);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Interfaces Assignments</h1>
        <p className="text-sm text-slate-400 mt-1">
          Configure logical network interfaces, Linux physical devices, and IP addressing.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {interfaces.map((iface) => (
          <div
            key={iface.name}
            className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Network className="w-5 h-5 text-emerald-400" />
                <h2 className="text-lg font-bold text-white uppercase">{iface.name}</h2>
                <span className="text-xs bg-slate-800 text-slate-300 font-mono px-2 py-0.5 rounded border border-slate-700">
                  {iface.device}
                </span>
              </div>
              <span className="text-xs font-semibold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                {iface.status}
              </span>
            </div>

            <div className="space-y-2 text-xs font-mono text-slate-300 divide-y divide-slate-800/80">
              <div className="flex justify-between py-1.5">
                <span className="text-slate-400 font-sans">IPv4 Configuration</span>
                <span>{iface.type}</span>
              </div>
              <div className="flex justify-between py-1.5">
                <span className="text-slate-400 font-sans">IPv4 Address</span>
                <span className="text-emerald-400">{iface.ipv4}</span>
              </div>
              <div className="flex justify-between py-1.5">
                <span className="text-slate-400 font-sans">Default Gateway</span>
                <span>{iface.gateway}</span>
              </div>
              <div className="flex justify-between py-1.5">
                <span className="text-slate-400 font-sans">MTU</span>
                <span>{iface.mtu}</span>
              </div>
              <div className="flex justify-between py-1.5">
                <span className="text-slate-400 font-sans">MAC Address</span>
                <span>{iface.mac}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
