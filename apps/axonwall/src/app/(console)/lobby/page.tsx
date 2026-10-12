import {
  ShieldCheck,
  Cpu,
  HardDrive,
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  Server,
  Terminal,
  CheckCircle2,
} from 'lucide-react';
import { getAgentStatus } from '../../../server/agent';

export default async function LobbyPage() {
  const status = await getAgentStatus();
  const arch = process.arch === 'x64' ? 'amd64' : process.arch;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">System Dashboard</h1>
        <p className="text-sm text-slate-400 mt-1">
          Operational overview of Axonwall Linux appliance and nftables data plane.
        </p>
      </div>

      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 block font-medium">Data Plane Engine</span>
            <span className="text-lg font-bold text-white mt-1 block">nftables</span>
            <span className="text-[11px] text-emerald-400 flex items-center gap-1 mt-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Fastpath Active
            </span>
          </div>
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 block font-medium">System Uptime</span>
            <span className="text-lg font-bold text-white mt-1 block">
              {Math.floor(status.uptimeSeconds / 3600)}h {Math.floor((status.uptimeSeconds % 3600) / 60)}m
            </span>
            <span className="text-[11px] text-slate-400 mt-1 block font-mono">Debian 13 Linux ({arch})</span>
          </div>
          <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <Activity className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 block font-medium">Identity & Auth</span>
            <span className="text-lg font-bold text-white mt-1 block">OpenLDAP</span>
            <span className="text-[11px] text-emerald-400 flex items-center gap-1 mt-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Directory Synced
            </span>
          </div>
          <div className="w-10 h-10 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
            <Server className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 block font-medium">Commit-Confirm State</span>
            <span className="text-lg font-bold text-white mt-1 block">
              {status.pendingConfirm ? 'Pending' : 'Healthy'}
            </span>
            <span className="text-[11px] text-slate-400 mt-1 block">Signed LKG Enforced</span>
          </div>
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Cpu className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Main Grid: Interfaces & Services */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Network Interfaces */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold text-white">Interfaces Status</h2>
            <span className="text-xs text-slate-400">Auto-Refreshed</span>
          </div>

          <div className="space-y-3">
            {status.interfaces.map((iface) => (
              <div
                key={iface.name}
                className="bg-slate-950 border border-slate-800/80 rounded-lg p-3 flex items-center justify-between"
              >
                <div className="flex items-center gap-3">
                  <span
                    className={`w-2.5 h-2.5 rounded-full ${
                      iface.isUp ? 'bg-emerald-500' : 'bg-red-500'
                    }`}
                  />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm text-white uppercase">
                        {iface.name}
                      </span>
                      <span className="text-xs text-slate-400 font-mono">({iface.device})</span>
                    </div>
                    <span className="text-xs text-slate-400 font-mono">
                      {iface.ipAddresses.join(', ') || 'No IP configured'}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 text-xs font-mono">
                  <span
                    className={`px-2.5 py-0.5 rounded text-[11px] font-semibold border ${
                      iface.isUp
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                        : 'bg-slate-800 text-slate-500 border-slate-700'
                    }`}
                  >
                    {iface.isUp ? 'Carrier UP' : 'Carrier DOWN'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Managed Daemons & Services */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold text-white">Core Services</h2>
            <span className="text-xs text-emerald-400 font-medium">All Running</span>
          </div>

          <div className="grid grid-cols-2 gap-3 text-sm">
            <div className="bg-slate-950 border border-slate-800/80 p-3 rounded-lg flex items-center justify-between">
              <div>
                <span className="font-medium text-white block">axonwalld</span>
                <span className="text-xs text-slate-400">Privileged Data Agent</span>
              </div>
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
            </div>

            <div className="bg-slate-950 border border-slate-800/80 p-3 rounded-lg flex items-center justify-between">
              <div>
                <span className="font-medium text-white block">OpenLDAP</span>
                <span className="text-xs text-slate-400">slapd Directory Service</span>
              </div>
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
            </div>

            <div className="bg-slate-950 border border-slate-800/80 p-3 rounded-lg flex items-center justify-between">
              <div>
                <span className="font-medium text-white block">Supabase Postgres</span>
                <span className="text-xs text-slate-400">Configuration & RLS Store</span>
              </div>
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
            </div>

            <div className="bg-slate-950 border border-slate-800/80 p-3 rounded-lg flex items-center justify-between">
              <div>
                <span className="font-medium text-white block">WireGuard</span>
                <span className="text-xs text-slate-400">Kernel VPN Subsystem</span>
              </div>
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
