'use client';

import { useState } from 'react';
import { Server, Plus, CheckCircle2, FileCode } from 'lucide-react';
import { compileKeaDhcp4 } from '@axonwall/lib/compile/kea';
import type { DhcpConfig, Interface } from '@axonwall/lib/schemas';

const SAMPLE_DHCP: DhcpConfig = {
  enabled: true,
  subnets: [
    {
      interface: 'lan',
      subnet: '192.168.100.0/24',
      poolStart: '192.168.100.100',
      poolEnd: '192.168.100.200',
      routers: ['192.168.100.1'],
      dnsServers: ['192.168.100.1'],
      staticMappings: [
        {
          mac: '52:54:00:11:22:33',
          ip: '192.168.100.50',
          hostname: 'office-nas',
          description: 'Synology Storage Server',
        },
      ],
      enabled: true,
    },
  ],
};

const SAMPLE_INTERFACES: Interface[] = [
  { name: 'lan', device: 'eth1', type: 'static', enabled: true, description: 'LAN', mtu: 1500 },
];

export default function DhcpPage() {
  const [dhcp] = useState<DhcpConfig>(SAMPLE_DHCP);
  const [showKeaConfig, setShowKeaConfig] = useState(false);

  const { keaDhcp4Config } = compileKeaDhcp4(dhcp, SAMPLE_INTERFACES);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">DHCP Server (Kea)</h1>
          <p className="text-sm text-slate-400 mt-1">
            High-performance dynamic address allocation and static reservations powered by ISC Kea.
          </p>
        </div>

        <button
          type="button"
          onClick={() => setShowKeaConfig(!showKeaConfig)}
          className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer border border-slate-700"
        >
          <FileCode className="w-3.5 h-3.5" />
          <span>{showKeaConfig ? 'Hide Kea JSON' : 'View Kea JSON'}</span>
        </button>
      </div>

      {showKeaConfig && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
          <span className="text-xs font-mono text-emerald-400 font-semibold block">
            Generated /etc/axonwall/managed/kea-dhcp4.conf
          </span>
          <pre className="bg-slate-950 p-4 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto max-h-72">
            {keaDhcp4Config}
          </pre>
        </div>
      )}

      {/* Subnets Overview */}
      <div className="grid grid-cols-1 gap-6">
        {dhcp.subnets.map((sub) => (
          <div key={sub.subnet} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="w-5 h-5 text-emerald-400" />
                <h2 className="text-base font-bold text-white uppercase">{sub.interface} Subnet</h2>
                <span className="text-xs bg-slate-800 text-slate-300 font-mono px-2 py-0.5 rounded border border-slate-700">
                  {sub.subnet}
                </span>
              </div>
              <span className="text-xs font-semibold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Active
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                <span className="text-slate-400 block font-sans mb-1">Dynamic IP Pool</span>
                <span className="text-emerald-400">{sub.poolStart} - {sub.poolEnd}</span>
              </div>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                <span className="text-slate-400 block font-sans mb-1">Advertised Gateway</span>
                <span className="text-slate-200">{sub.routers.join(', ') || 'Auto'}</span>
              </div>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                <span className="text-slate-400 block font-sans mb-1">DNS Servers</span>
                <span className="text-slate-200">{sub.dnsServers.join(', ') || 'Auto'}</span>
              </div>
            </div>

            {/* Static Mappings Table */}
            <div className="space-y-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block">
                Static DHCP Reservations
              </span>
              <div className="bg-slate-950 border border-slate-800/80 rounded-lg overflow-hidden">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-900/60 text-slate-400 uppercase border-b border-slate-800">
                    <tr>
                      <th className="px-4 py-2.5">MAC Address</th>
                      <th className="px-4 py-2.5">IP Address</th>
                      <th className="px-4 py-2.5">Hostname</th>
                      <th className="px-4 py-2.5">Description</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {sub.staticMappings.map((m) => (
                      <tr key={m.mac} className="hover:bg-slate-900/40">
                        <td className="px-4 py-2.5 text-slate-300">{m.mac}</td>
                        <td className="px-4 py-2.5 text-emerald-400">{m.ip}</td>
                        <td className="px-4 py-2.5 text-white font-sans">{m.hostname || '-'}</td>
                        <td className="px-4 py-2.5 text-slate-400 font-sans">{m.description || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
