'use client';

import { Route, CheckCircle2, Plus, Trash2 } from 'lucide-react';
import { useState, useEffect } from 'react';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import type { DesiredState, Gateway, StaticRoute } from '@axonwall/lib/schemas';

export default function RoutingPage() {
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [routes, setRoutes] = useState<StaticRoute[]>([]);
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  // Static route form
  const [newNetwork, setNewNetwork] = useState('');
  const [newGwIp, setNewGwIp] = useState('');
  const [newIface, setNewIface] = useState('auto');
  const [newDesc, setNewDesc] = useState('');

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        setFullState(state);
        setGateways(
          state.gateways?.length
            ? state.gateways
            : [
                {
                  name: 'WAN_DHCP',
                  interface: 'wan',
                  gatewayIp: '192.168.1.1',
                  monitorIp: '1.1.1.1',
                  weight: 1,
                  isDefault: true,
                  enabled: true,
                  description: 'Primary WAN Gateway',
                },
              ]
        );
        setRoutes(state.routes || []);
      })
      .catch(() => {});
  }, []);

  const persistRouting = async (nextGateways: Gateway[], nextRoutes: StaticRoute[]) => {
    setGateways(nextGateways);
    setRoutes(nextRoutes);
    setSaving(true);
    setStatusMsg(null);
    try {
      const current = fullState || (await getCurrentDesiredState());
      const nextState: DesiredState = {
        ...current,
        gateways: nextGateways,
        routes: nextRoutes,
      };
      setFullState(nextState);
      const res = await applyDesiredState(nextState);
      setStatusMsg(res.message || 'Saved routing configuration to /etc/axonwall/routing.yaml');
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to save routing state'}`);
    } finally {
      setSaving(false);
    }
  };

  const handleAddRoute = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNetwork.trim() || !newGwIp.trim()) return;
    const nextRoutes: StaticRoute[] = [
      ...routes,
      {
        network: newNetwork.trim(),
        gateway: newGwIp.trim(),
        interface: newIface,
        description: newDesc.trim(),
        enabled: true,
      },
    ];
    setNewNetwork('');
    setNewGwIp('');
    setNewDesc('');
    await persistRouting(gateways, nextRoutes);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Gateways & Static Routing</h1>
        <p className="text-sm text-slate-400 mt-1">
          Configure upstream gateways and static kernel routes synced with{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/routing.yaml</code>.
        </p>
      </div>

      {statusMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{statusMsg}</span>
        </div>
      )}

      {/* Gateways Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800">
          <h2 className="text-sm font-semibold text-white">Upstream Gateways</h2>
        </div>
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-950 text-slate-400 text-xs font-semibold uppercase tracking-wider border-b border-slate-800">
            <tr>
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Interface</th>
              <th className="px-4 py-3">Gateway IP</th>
              <th className="px-4 py-3">Monitor IP</th>
              <th className="px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
            {gateways.map((gw) => (
              <tr key={gw.name} className="hover:bg-slate-800/40 transition">
                <td className="px-4 py-3 font-semibold text-white">
                  {gw.name}{' '}
                  {gw.isDefault && (
                    <span className="text-[10px] bg-slate-800 px-1.5 py-0.5 rounded text-slate-400 font-sans">
                      Default
                    </span>
                  )}
                </td>
                <td className="px-4 py-3 text-slate-400 uppercase">{gw.interface}</td>
                <td className="px-4 py-3 text-slate-300">{gw.gatewayIp}</td>
                <td className="px-4 py-3 text-cyan-400">{gw.monitorIp || 'Auto'}</td>
                <td className="px-4 py-3">
                  <span className="inline-flex items-center gap-1 text-emerald-400 font-medium">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    Online
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Static Routes Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Route className="w-4 h-4 text-emerald-400" />
            <span>Static Routes</span>
          </h2>
          <span className="text-xs text-slate-400">{routes.length} configured routes</span>
        </div>

        {routes.length === 0 ? (
          <div className="p-6 text-center text-slate-500 text-xs border border-slate-800 rounded-lg">
            No custom static routes configured. Add a static route below or in <code className="text-emerald-400">/etc/axonwall/routing.yaml</code>.
          </div>
        ) : (
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 uppercase border-b border-slate-800 font-sans">
              <tr>
                <th className="px-4 py-2.5">Destination Network</th>
                <th className="px-4 py-2.5">Next-Hop Gateway</th>
                <th className="px-4 py-2.5">Interface</th>
                <th className="px-4 py-2.5">Description</th>
                <th className="px-4 py-2.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {routes.map((rt, idx) => (
                <tr key={`${rt.network}-${idx}`} className="hover:bg-slate-800/40">
                  <td className="px-4 py-2.5 text-emerald-400 font-semibold">{rt.network}</td>
                  <td className="px-4 py-2.5 text-white">{rt.gateway}</td>
                  <td className="px-4 py-2.5 text-slate-400 uppercase">{rt.interface || 'auto'}</td>
                  <td className="px-4 py-2.5 text-slate-400 font-sans">{rt.description || '-'}</td>
                  <td className="px-4 py-2.5 text-right">
                    <button
                      type="button"
                      onClick={() =>
                        persistRouting(
                          gateways,
                          routes.filter((_, i) => i !== idx)
                        )
                      }
                      className="text-slate-500 hover:text-red-400 transition"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <form onSubmit={handleAddRoute} className="grid grid-cols-1 md:grid-cols-5 gap-2 pt-2">
          <input
            type="text"
            value={newNetwork}
            onChange={(e) => setNewNetwork(e.target.value)}
            placeholder="Network CIDR (10.20.0.0/16)"
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
            required
          />
          <input
            type="text"
            value={newGwIp}
            onChange={(e) => setNewGwIp(e.target.value)}
            placeholder="Gateway IP (192.168.1.254)"
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
            required
          />
          <select
            value={newIface}
            onChange={(e) => setNewIface(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-emerald-500"
          >
            <option value="auto">Auto (Kernel Resolution)</option>
            {fullState?.interfaces && fullState.interfaces.length > 0 ? (
              fullState.interfaces.map((iface) => (
                <option key={iface.name} value={iface.name}>
                  {iface.name.toUpperCase()} ({iface.device})
                </option>
              ))
            ) : (
              <>
                <option value="lan">LAN</option>
                <option value="wan">WAN</option>
                <option value="opt1">OPT1</option>
                <option value="opt2">OPT2</option>
              </>
            )}
          </select>
          <input
            type="text"
            value={newDesc}
            onChange={(e) => setNewDesc(e.target.value)}
            placeholder="Description"
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white"
          />
          <button
            type="submit"
            disabled={saving}
            className="bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg px-3 py-1.5 text-xs font-medium flex items-center justify-center gap-1.5 transition cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Static Route</span>
          </button>
        </form>
      </div>
    </div>
  );
}
