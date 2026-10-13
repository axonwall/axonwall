'use client';

import { Network, CheckCircle2, ArrowRight, Loader2 } from 'lucide-react';
import { useState, useEffect } from 'react';
import { getSystemInterfaces, type LiveInterfaceInfo } from '@/server/agent';

export default function InterfacesPage() {
  const [interfaces, setInterfaces] = useState<LiveInterfaceInfo[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getSystemInterfaces()
      .then((data) => setInterfaces(data))
      .catch(() => setInterfaces([]))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Interfaces Assignments</h1>
        <p className="text-sm text-slate-400 mt-1">
          Configure logical network interfaces, Linux physical devices, and IP addressing.
        </p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center p-12 bg-slate-900 border border-slate-800 rounded-xl text-slate-400 gap-3">
          <Loader2 className="w-5 h-5 animate-spin text-emerald-400" />
          <span>Scanning physical and virtual network interfaces...</span>
        </div>
      ) : interfaces.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400">
          <Network className="w-8 h-8 text-slate-600 mx-auto mb-2" />
          <p className="font-semibold text-slate-300">No Network Interfaces Detected</p>
          <p className="text-xs text-slate-500 mt-1">Ensure network devices are connected and recognized by the host OS kernel.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {interfaces.map((iface) => (
            <div
              key={iface.device}
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
                <span
                  className={`text-xs font-semibold px-2 py-0.5 rounded border ${
                    iface.status === 'Up'
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                  }`}
                >
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
                  <span className={iface.ipv4 !== 'Unassigned' ? 'text-emerald-400 font-bold' : 'text-slate-500'}>
                    {iface.ipv4}
                  </span>
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
      )}
    </div>
  );
}
