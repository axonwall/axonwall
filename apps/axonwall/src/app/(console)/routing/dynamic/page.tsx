'use client';

import { useState } from 'react';
import { Route, Terminal, Shield, CheckCircle2 } from 'lucide-react';
import { compileFrr } from '@axonwall/lib/compile/frr';
import type { FrrConfig } from '@axonwall/lib/schemas';

export default function DynamicRoutingPage() {
  const [bgpEnabled, setBgpEnabled] = useState(true);
  const [bgpAs, setBgpAs] = useState(64512);
  const [bgpRouterId, setBgpRouterId] = useState('1.1.1.1');
  const [bgpNetworks] = useState(['10.0.0.0/16', '192.168.100.0/24']);

  const [ospfEnabled, setOspfEnabled] = useState(true);
  const [ospfRouterId, setOspfRouterId] = useState('1.1.1.1');
  const [ospfRedistribute, setOspfRedistribute] = useState(true);

  const [applied, setApplied] = useState(false);

  const frrConfig: FrrConfig = {
    enabled: bgpEnabled || ospfEnabled,
    bgp: {
      enabled: bgpEnabled,
      asNumber: bgpAs,
      routerId: bgpRouterId,
      networks: bgpNetworks,
      neighbors: [
        {
          peerIp: '198.51.100.254',
          remoteAs: 65000,
          description: 'Tier-1 ISP Uplink',
          password: 'BgpSecretPassword',
          bfd: true,
          nextHopSelf: true,
          softReconfiguration: true,
        },
      ],
    },
    ospf: {
      enabled: ospfEnabled,
      routerId: ospfRouterId,
      redistributeConnected: ospfRedistribute,
      redistributeDefault: false,
      areas: [
        {
          areaId: '0.0.0.0',
          interfaces: ['eth1'],
          networks: ['192.168.100.0/24'],
        },
      ],
    },
  };

  const compiled = compileFrr(frrConfig);

  const handleApply = () => {
    setApplied(true);
    setTimeout(() => setApplied(false), 3000);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <Route className="w-6 h-6 text-emerald-400" />
          Dynamic Routing (FRRouting: BGP / OSPF / BFD)
        </h1>
        <p className="text-sm text-slate-400">
          Carrier-grade dynamic routing protocols integrated directly into Linux kernel forwarding tables.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          {/* BGP Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="font-semibold text-white">Border Gateway Protocol (BGP)</h3>
                <p className="text-xs text-slate-400">Exterior routing and multi-homed ISP peering</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={bgpEnabled}
                  onChange={(e) => setBgpEnabled(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-600"></div>
              </label>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Autonomous System (AS Number)</label>
                <input
                  type="number"
                  value={bgpAs}
                  onChange={(e) => setBgpAs(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">BGP Router ID</label>
                <input
                  type="text"
                  value={bgpRouterId}
                  onChange={(e) => setBgpRouterId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>
            </div>

            <div>
              <span className="block text-xs font-medium text-slate-400 mb-1.5">Configured BGP Neighbors</span>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between text-xs font-mono">
                <div>
                  <span className="text-white font-semibold">198.51.100.254</span>
                  <span className="text-slate-400 ml-2">(Remote AS 65000)</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">
                    BFD Fast Failover
                  </span>
                  <span className="text-emerald-400 font-bold">ESTABLISHED</span>
                </div>
              </div>
            </div>
          </div>

          {/* OSPF Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="font-semibold text-white">Open Shortest Path First (OSPFv2)</h3>
                <p className="text-xs text-slate-400">Interior IGP link-state routing across local segments</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={ospfEnabled}
                  onChange={(e) => setOspfEnabled(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-600"></div>
              </label>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">OSPF Router ID</label>
                <input
                  type="text"
                  value={ospfRouterId}
                  onChange={(e) => setOspfRouterId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>
              <div className="flex items-center gap-3 pt-6">
                <input
                  type="checkbox"
                  id="redistConnected"
                  checked={ospfRedistribute}
                  onChange={(e) => setOspfRedistribute(e.target.checked)}
                  className="rounded bg-slate-950 border-slate-700 text-emerald-600 focus:ring-emerald-500"
                />
                <label htmlFor="redistConnected" className="text-sm text-slate-300 cursor-pointer">
                  Redistribute Connected Subnets
                </label>
              </div>
            </div>
          </div>

          <div className="flex justify-end">
            <button
              type="button"
              onClick={handleApply}
              className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-2.5 px-6 rounded-lg text-sm transition flex items-center gap-2 shadow-sm"
            >
              {applied ? <CheckCircle2 className="w-4 h-4" /> : <Shield className="w-4 h-4" />}
              {applied ? 'Reloaded in FRR vtysh' : 'Apply Dynamic Routing'}
            </button>
          </div>
        </div>

        {/* Right 1 Col: Live frr.conf Preview */}
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col h-full">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                <Terminal className="w-4 h-4 text-emerald-400" />
                Rendered frr.conf
              </div>
              <span className="text-[10px] text-emerald-400 font-mono">FRR 10.0</span>
            </div>
            <pre className="mt-3 p-3 bg-slate-950 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap flex-1 border border-slate-900">
              {compiled.frrConf}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
