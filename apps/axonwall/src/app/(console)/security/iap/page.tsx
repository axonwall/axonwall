'use client';

import { useState, useEffect } from 'react';
import { Shield, Plus, Trash2, CheckCircle2 } from 'lucide-react';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import type { DesiredState, ZeroTrustApp } from '@axonwall/lib/schemas';

export default function IAPDashboardPage() {
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [apps, setApps] = useState<ZeroTrustApp[]>([]);
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const [newName, setNewName] = useState('');
  const [newHost, setNewHost] = useState('');
  const [newUpstream, setNewUpstream] = useState('');
  const [newRoles, setNewRoles] = useState<string[]>(['admin']);
  const [newAllowAny, setNewAllowAny] = useState(false);

  const ROLE_OPTIONS = [
    { value: 'admin', label: 'Admin' },
    { value: 'operator', label: 'Operator' },
    { value: 'readonly', label: 'Read-only' },
  ];

  const toggleNewRole = (role: string) =>
    setNewRoles((prev) => (prev.includes(role) ? prev.filter((r) => r !== role) : [...prev, role]));

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        setFullState(state);
        if (state.zeroTrust?.apps) {
          setApps(state.zeroTrust.apps);
        }
      })
      .catch(() => {});
  }, []);

  const persistApps = async (nextApps: ZeroTrustApp[]) => {
    setApps(nextApps);
    setSaving(true);
    setStatusMsg(null);
    try {
      const current = fullState || (await getCurrentDesiredState());
      const nextState: DesiredState = {
        ...current,
        zeroTrust: {
          enabled: nextApps.length > 0,
          apps: nextApps,
        },
      };
      setFullState(nextState);
      const res = await applyDesiredState(nextState);
      setStatusMsg(res.message || 'Saved Zero-Trust IAP applications to /etc/axonwall/security.yaml');
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to save IAP apps'}`);
    } finally {
      setSaving(false);
    }
  };

  const handleAddApp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim() || !newHost.trim() || !newUpstream.trim()) return;
    const nextApps: ZeroTrustApp[] = [
      ...apps,
      {
        name: newName.trim(),
        publicHostname: newHost.trim(),
        internalUpstream: newUpstream.trim(),
        // An app is never saved with a silently empty policy: open
        // access is the explicit allowAnyAuthenticated flag, and no
        // role selection means the admin-only default (audit B-S3).
        allowedRoles: newAllowAny ? [] : newRoles.length > 0 ? newRoles : ['admin'],
        allowAnyAuthenticated: newAllowAny,
        enabled: true,
        description: 'Zero-Trust Protected Application',
      },
    ];
    setNewName('');
    setNewHost('');
    setNewUpstream('');
    setNewRoles(['admin']);
    setNewAllowAny(false);
    await persistApps(nextApps);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
          <Shield className="w-6 h-6 text-emerald-400" />
          Identity-Aware Proxy (IAP)
        </h1>
        <p className="text-slate-400 text-sm mt-1">
          Publish internal applications securely with Zero Trust, synced with{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/security.yaml</code>.
        </p>
      </div>

      {statusMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{statusMsg}</span>
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex justify-between items-center">
          <h2 className="text-base font-semibold text-slate-200">Published Applications</h2>
          <span className="text-xs text-slate-400">{apps.length} active policies</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="text-xs text-slate-400 uppercase bg-slate-950 border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Public Hostname</th>
                <th className="px-4 py-3">Internal Upstream</th>
                <th className="px-4 py-3">Allowed Roles</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {apps.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-500 font-sans">
                    No applications published yet. Add an application below or in <code className="text-emerald-400">/etc/axonwall/security.yaml</code>.
                  </td>
                </tr>
              ) : (
                apps.map((app) => (
                  <tr key={app.name} className="hover:bg-slate-800/40">
                    <td className="px-4 py-3 font-semibold text-white font-sans">{app.name}</td>
                    <td className="px-4 py-3 text-emerald-400">{app.publicHostname}</td>
                    <td className="px-4 py-3 text-slate-300">{app.internalUpstream}</td>
                    <td className="px-4 py-3 text-slate-400">
                      {app.allowAnyAuthenticated
                        ? 'Any authenticated user'
                        : app.allowedRoles && app.allowedRoles.length > 0
                          ? app.allowedRoles.join(', ')
                          : 'admin (default)'}
                    </td>
                    <td className="px-4 py-3 text-emerald-400">Protected</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => persistApps(apps.filter((a) => a.name !== app.name))}
                        className="text-slate-500 hover:text-red-400 transition"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <form onSubmit={handleAddApp} className="grid grid-cols-1 md:grid-cols-5 gap-2 pt-3 border-t border-slate-800">
          <input
            type="text"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="App Name (Grafana)"
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white"
            required
          />
          <input
            type="text"
            value={newHost}
            onChange={(e) => setNewHost(e.target.value)}
            placeholder="grafana.corp.axonwall.io"
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
            required
          />
          <input
            type="text"
            value={newUpstream}
            onChange={(e) => setNewUpstream(e.target.value)}
            placeholder="http://10.10.1.25:3000"
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
            required
          />
          <div className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 flex flex-col gap-1.5">
            <div className={`flex flex-wrap gap-x-3 gap-y-1 ${newAllowAny ? 'opacity-40 pointer-events-none' : ''}`}>
              {ROLE_OPTIONS.map((role) => (
                <label key={role.value} className="flex items-center gap-1.5 text-[11px] text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={newRoles.includes(role.value)}
                    onChange={() => toggleNewRole(role.value)}
                    className="accent-emerald-500"
                  />
                  {role.label}
                </label>
              ))}
            </div>
            <label className="flex items-center gap-1.5 text-[11px] text-amber-300/90 cursor-pointer">
              <input
                type="checkbox"
                checked={newAllowAny}
                onChange={(e) => setNewAllowAny(e.target.checked)}
                className="accent-amber-500"
              />
              Any authenticated user
            </label>
            <span className="text-[10px] text-slate-500 leading-snug">
              {newAllowAny
                ? 'Every signed-in session, including read-only SSO users, can use this app.'
                : newRoles.length === 0
                  ? 'No roles selected: admin only.'
                  : 'Only the selected roles can use this app.'}
            </span>
          </div>
          <button
            type="submit"
            disabled={saving}
            className="bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg px-3 py-1.5 text-xs font-medium flex items-center justify-center gap-1.5 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Application</span>
          </button>
        </form>
      </div>
    </div>
  );
}
