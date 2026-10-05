'use client';

import { Settings, History, Users, Shield, Server, CheckCircle2 } from 'lucide-react';
import { useState } from 'react';

export default function SystemPage() {
  const [revisions] = useState([
    {
      rev: '#002',
      date: '2026-10-05 05:30',
      author: 'admin (LDAP)',
      message: 'Added internal web servers alias and HTTP allow rule',
      status: 'Active (LKG)',
      hash: 'sha256:d8a9e4...',
    },
    {
      rev: '#001',
      date: '2026-10-05 05:00',
      author: 'system',
      message: 'Initial factory bootstrap configuration',
      status: 'Archived',
      hash: 'sha256:1a2b3c...',
    },
  ]);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">System & Configuration</h1>
        <p className="text-sm text-slate-400 mt-1">
          Immutable configuration revisions, commit-confirm audit trail, and LDAP directory status.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 text-white font-semibold">
            <Server className="w-5 h-5 text-indigo-400" />
            <h2>Identity & Access (LDAP)</h2>
          </div>
          <div className="text-xs text-slate-300 space-y-2">
            <div className="flex justify-between">
              <span className="text-slate-400">Server Type:</span>
              <span>OpenLDAP (Internal)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Base DN:</span>
              <span className="font-mono text-emerald-400">dc=axonwall,dc=local</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Directory Status:</span>
              <span className="text-emerald-400 flex items-center gap-1 font-medium">
                <CheckCircle2 className="w-3.5 h-3.5" /> Connected
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Fallback Admin:</span>
              <span className="text-amber-400 font-mono">root / enabled</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 text-white font-semibold">
            <Shield className="w-5 h-5 text-emerald-400" />
            <h2>Data Plane Security</h2>
          </div>
          <div className="text-xs text-slate-300 space-y-2">
            <div className="flex justify-between">
              <span className="text-slate-400">Kernel Firewall:</span>
              <span>Linux nftables v1.1.3</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Table Ownership:</span>
              <span className="font-mono text-cyan-400">inet axonwall</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Docker Coexistence:</span>
              <span className="text-emerald-400 font-medium">Enabled</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Early-Boot Apply:</span>
              <span className="text-emerald-400 font-medium">Active (systemd)</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 text-white font-semibold">
            <Settings className="w-5 h-5 text-cyan-400" />
            <h2>Controller Status</h2>
          </div>
          <div className="text-xs text-slate-300 space-y-2">
            <div className="flex justify-between">
              <span className="text-slate-400">Agent Socket:</span>
              <span className="font-mono text-slate-300">/run/axonwall/agent.sock</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Rollback Timeout:</span>
              <span>120 seconds</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Storage Backend:</span>
              <span>PostgreSQL 17 (Supabase)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Revision History */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center gap-2 text-white font-semibold">
          <History className="w-5 h-5 text-emerald-400" />
          <h2>Configuration Revision History & Audit Trail</h2>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm font-mono text-xs">
            <thead className="bg-slate-950 text-slate-400 text-xs font-semibold uppercase tracking-wider border-b border-slate-800 font-sans">
              <tr>
                <th className="px-4 py-3">Revision</th>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Author</th>
                <th className="px-4 py-3">Message</th>
                <th className="px-4 py-3">Bundle Hash</th>
                <th className="px-4 py-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {revisions.map((rev) => (
                <tr key={rev.rev} className="hover:bg-slate-800/40 transition">
                  <td className="px-4 py-3 font-bold text-white">{rev.rev}</td>
                  <td className="px-4 py-3 text-slate-400">{rev.date}</td>
                  <td className="px-4 py-3 text-slate-300">{rev.author}</td>
                  <td className="px-4 py-3 text-slate-200 font-sans">{rev.message}</td>
                  <td className="px-4 py-3 text-cyan-400">{rev.hash}</td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold text-[11px]">
                      {rev.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
