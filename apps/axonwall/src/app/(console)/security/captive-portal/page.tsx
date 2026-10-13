'use client';

import { useState } from 'react';
import { Users, Wifi, Trash2, Plus, CheckCircle2, Clock, ArrowDown, ArrowUp } from 'lucide-react';
import type { CaptivePortalZone } from '@axonwall/lib/schemas';

interface ActiveSessionView {
  sessionId: string;
  clientIp: string;
  clientMac: string;
  username: string;
  remainingMinutes: number;
  downloadMb: number;
  uploadMb: number;
}

export default function CaptivePortalPage() {
  const [zones] = useState<CaptivePortalZone[]>([]);
  const [sessions, setSessions] = useState<ActiveSessionView[]>([]);

  const handleDisconnect = (id: string) => {
    setSessions(sessions.filter((s) => s.sessionId !== id));
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <Wifi className="w-6 h-6 text-emerald-400" />
          Captive Portal & Guest Access
        </h1>
        <p className="text-sm text-slate-400">
          User authentication, voucher generation, bandwidth throttling, and session tracking for guest networks.
        </p>
      </div>

      {/* Zone Overview */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h3 className="font-semibold text-white">Active Portal Zones</h3>
            <p className="text-xs text-slate-400">HTTP/HTTPS redirection to internal authentication daemon</p>
          </div>
          <span className="px-2.5 py-1 rounded bg-slate-800 text-slate-400 text-xs font-mono font-bold border border-slate-700">
            Daemon Port 8999
          </span>
        </div>

        {zones.length === 0 ? (
          <div className="p-6 text-center text-slate-500 text-xs">
            No captive portal zones configured. Add a guest portal zone on an interface or VLAN.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {zones.map((z) => (
              <div key={z.id} className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
                <div className="flex justify-between items-start">
                  <div>
                    <h4 className="font-bold text-white text-sm">{z.name}</h4>
                    <span className="text-xs font-mono text-emerald-400 uppercase">{z.interface}</span>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-xs">
                    Timeout: {z.sessionTimeoutMinutes} min
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs pt-1">
                  <div className="p-2 bg-slate-900 rounded border border-slate-800 flex items-center gap-1.5 text-slate-300">
                    <ArrowDown className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Max: {z.downloadLimitKbps / 1000} Mbps</span>
                  </div>
                  <div className="p-2 bg-slate-900 rounded border border-slate-800 flex items-center gap-1.5 text-slate-300">
                    <ArrowUp className="w-3.5 h-3.5 text-blue-400" />
                    <span>Max: {z.uploadLimitKbps / 1000} Mbps</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Active Sessions */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex justify-between items-center">
          <div>
            <h3 className="font-semibold text-white flex items-center gap-2">
              <Users className="w-4 h-4 text-emerald-400" />
              Authenticated Guest Sessions
            </h3>
            <p className="text-xs text-slate-400">Real-time authorized IP/MAC leases</p>
          </div>
          <span className="text-xs text-slate-400 font-mono">{sessions.length} Active Clients</span>
        </div>

        {sessions.length === 0 ? (
          <div className="p-8 text-center text-slate-400">
            <Users className="w-8 h-8 text-slate-600 mx-auto mb-2" />
            <p className="font-semibold text-slate-300">No Active Guest Sessions</p>
            <p className="text-xs text-slate-500 mt-1">
              Active guest logins and authenticated vouchers will appear here in real-time.
            </p>
          </div>
        ) : (
          <table className="w-full text-sm text-left">
            <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Client IP</th>
                <th className="px-4 py-3">MAC Address</th>
                <th className="px-4 py-3">Authenticated User / Voucher</th>
                <th className="px-4 py-3">Remaining Time</th>
                <th className="px-4 py-3">Data Transferred</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {sessions.map((s) => (
                <tr key={s.sessionId} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3 font-mono font-semibold text-white text-xs">{s.clientIp}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-400">{s.clientMac}</td>
                  <td className="px-4 py-3">
                    <span className="text-xs font-semibold text-emerald-400">{s.username}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center gap-1 font-mono text-xs text-slate-300">
                      <Clock className="w-3.5 h-3.5 text-slate-500" />
                      {Math.floor(s.remainingMinutes / 60)}h {s.remainingMinutes % 60}m
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300">
                    ↓ {s.downloadMb} MB &nbsp; ↑ {s.uploadMb} MB
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleDisconnect(s.sessionId)}
                      className="text-slate-500 hover:text-red-400 transition"
                      title="Disconnect Session"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
