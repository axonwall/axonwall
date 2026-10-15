'use client';

import { useState, useEffect } from 'react';
import { Shield, Plus, Copy, Check, Server, Users, Key, Network, Save, CheckCircle2 } from 'lucide-react';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import type { DesiredState } from '@axonwall/lib/schemas';

type Tab = 'machines' | 'users' | 'keys';

export default function MeshVpnPage() {
  const [activeTab, setActiveTab] = useState<Tab>('machines');
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [headscaleEnabled, setHeadscaleEnabled] = useState(false);
  const [magicDnsDomain, setMagicDnsDomain] = useState('tailnet.axonwall.local');
  const [savingConfig, setSavingConfig] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  
  // Data states
  const [machines, setMachines] = useState<any[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const [keys, setKeys] = useState<any[]>([]);
  
  // UI states
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  // Form states
  const [newUserName, setNewUserName] = useState('');
  const [newKeyUser, setNewKeyUser] = useState('');

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        setFullState(state);
        if (state.headscale) {
          setHeadscaleEnabled(state.headscale.enabled);
          setMagicDnsDomain(state.headscale.magicDnsDomain || 'tailnet.axonwall.local');
        }
      })
      .catch(() => {});
  }, []);

  const handleSaveHeadscaleConfig = async () => {
    setSavingConfig(true);
    setStatusMsg(null);
    try {
      const current = fullState || (await getCurrentDesiredState());
      const nextState: DesiredState = {
        ...current,
        headscale: {
          enabled: headscaleEnabled,
          magicDnsDomain: magicDnsDomain.trim() || 'tailnet.axonwall.local',
        },
      };
      setFullState(nextState);
      const res = await applyDesiredState(nextState);
      setStatusMsg(res.message || 'Saved Headscale configuration to /etc/axonwall/vpn.yaml');
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to save Headscale settings'}`);
    } finally {
      setSavingConfig(false);
    }
  };

  useEffect(() => {
    fetchData();
    if (activeTab === 'keys') {
      fetchUsersForDropdown();
    }
  }, [activeTab]);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      if (activeTab === 'machines') {
        const res = await fetch('/api/v1/vpn/mesh/machines');
        const json = await res.json();
        if (json.status === 'ok') setMachines(json.data);
        else setError(json.error || 'Failed to fetch machines');
      } else if (activeTab === 'users') {
        const res = await fetch('/api/v1/vpn/mesh/users');
        const json = await res.json();
        if (json.status === 'ok') setUsers(json.data);
        else setError(json.error || 'Failed to fetch users');
      } else if (activeTab === 'keys') {
        const res = await fetch('/api/v1/vpn/mesh/keys');
        const json = await res.json();
        if (json.status === 'ok') setKeys(json.data);
        else setError(json.error || 'Failed to fetch keys');
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchUsersForDropdown = async () => {
    try {
      const res = await fetch('/api/v1/vpn/mesh/users');
      const json = await res.json();
      if (json.status === 'ok') setUsers(json.data);
    } catch (err) {
      console.error(err);
    }
  }

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUserName.trim()) return;
    try {
      const res = await fetch('/api/v1/vpn/mesh/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newUserName.trim() }),
      });
      if (res.ok) {
        setNewUserName('');
        fetchData();
      }
    } catch (err) {
      console.error('Failed to create user', err);
    }
  };

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyUser.trim()) return;
    try {
      const res = await fetch('/api/v1/vpn/mesh/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          user: newKeyUser.trim(),
          reusable: true,
          ephemeral: false,
          expiration: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() // 30 days
        }),
      });
      if (res.ok) {
        setNewKeyUser('');
        fetchData();
      }
    } catch (err) {
      console.error('Failed to create key', err);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-emerald-400" />
            Mesh VPN (Headscale)
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Private overlay network compatible with Tailscale clients, synced with{' '}
            <code className="text-emerald-400 font-mono">/etc/axonwall/vpn.yaml</code>.
          </p>
        </div>
        <button
          type="button"
          onClick={handleSaveHeadscaleConfig}
          disabled={savingConfig}
          className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
        >
          <Save className="w-3.5 h-3.5" />
          <span>{savingConfig ? 'Saving YAML...' : 'Save to vpn.yaml'}</span>
        </button>
      </div>

      {statusMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{statusMsg}</span>
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs">
        <div className="flex items-center gap-3">
          <span className="font-semibold text-white">Control Plane Status:</span>
          <button
            type="button"
            onClick={() => setHeadscaleEnabled(!headscaleEnabled)}
            className={`px-2.5 py-1 rounded font-medium border cursor-pointer transition ${
              headscaleEnabled
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}
          >
            {headscaleEnabled ? 'Enabled' : 'Disabled'}
          </button>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-slate-400">MagicDNS Base Domain:</span>
          <input
            type="text"
            value={magicDnsDomain}
            onChange={(e) => setMagicDnsDomain(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-emerald-400 font-mono w-56"
          />
        </div>
      </div>

      <div className="border-b border-slate-800">
        <nav className="-mb-px flex space-x-6" aria-label="Tabs">
          <button
            onClick={() => setActiveTab('machines')}
            className={`whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2 ${
              activeTab === 'machines'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-700'
            }`}
          >
            <Server className="w-4 h-4" />
            Machines
          </button>
          <button
            onClick={() => setActiveTab('users')}
            className={`whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2 ${
              activeTab === 'users'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-700'
            }`}
          >
            <Users className="w-4 h-4" />
            Users
          </button>
          <button
            onClick={() => setActiveTab('keys')}
            className={`whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2 ${
              activeTab === 'keys'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-700'
            }`}
          >
            <Key className="w-4 h-4" />
            Auth Keys
          </button>
        </nav>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-500/50 text-red-200 px-4 py-3 rounded-lg text-sm">
          {error}
        </div>
      )}

      {/* MACHINES TAB */}
      {activeTab === 'machines' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
          <div className="p-5 border-b border-slate-800 flex justify-between items-center">
            <h2 className="text-base font-bold text-white">Connected Machines</h2>
            <button className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-1">
              <Network className="w-3.5 h-3.5" />
              Manage Routes
            </button>
          </div>
          {loading ? (
            <div className="p-5 text-sm text-slate-400">Loading machines...</div>
          ) : machines.length === 0 ? (
            <div className="p-10 text-center text-sm text-slate-500">
              No machines connected. Create a user and an auth key to get started.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950 text-slate-400 uppercase border-b border-slate-800 font-sans">
                  <tr>
                    <th className="px-4 py-3">ID</th>
                    <th className="px-4 py-3">Name</th>
                    <th className="px-4 py-3">IP Addresses</th>
                    <th className="px-4 py-3">User</th>
                    <th className="px-4 py-3">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {machines.map((m: any) => (
                    <tr key={m.id} className="hover:bg-slate-800/40 transition">
                      <td className="px-4 py-3 text-slate-500">{m.id}</td>
                      <td className="px-4 py-3 font-semibold text-white font-sans">{m.name}</td>
                      <td className="px-4 py-3 text-emerald-400">{m.ipAddresses?.join(', ')}</td>
                      <td className="px-4 py-3 text-slate-300">{m.user?.name || '-'}</td>
                      <td className="px-4 py-3 text-slate-500">
                        {m.lastSeen ? new Date(m.lastSeen).toLocaleString() : 'Never'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* USERS TAB */}
      {activeTab === 'users' && (
        <div className="space-y-4">
          <form onSubmit={handleCreateUser} className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex items-end gap-4">
            <div className="flex-1">
              <label className="block text-xs font-medium text-slate-400 mb-1">New User Name</label>
              <input
                type="text"
                value={newUserName}
                onChange={(e) => setNewUserName(e.target.value)}
                placeholder="e.g. alice@example.com or admin"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500"
              />
            </div>
            <button
              type="submit"
              disabled={!newUserName.trim()}
              className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition"
            >
              <Plus className="w-4 h-4" />
              Add User
            </button>
          </form>

          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
            {loading ? (
              <div className="p-5 text-sm text-slate-400">Loading users...</div>
            ) : users.length === 0 ? (
              <div className="p-10 text-center text-sm text-slate-500">No users found.</div>
            ) : (
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950 text-slate-400 uppercase border-b border-slate-800 font-sans">
                  <tr>
                    <th className="px-4 py-3">ID</th>
                    <th className="px-4 py-3">Name</th>
                    <th className="px-4 py-3">Created</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {users.map((u: any) => (
                    <tr key={u.id} className="hover:bg-slate-800/40 transition">
                      <td className="px-4 py-3 text-slate-500">{u.id}</td>
                      <td className="px-4 py-3 font-semibold text-white font-sans">{u.name}</td>
                      <td className="px-4 py-3 text-slate-400">
                        {new Date(u.createdAt).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* KEYS TAB */}
      {activeTab === 'keys' && (
        <div className="space-y-4">
          <form onSubmit={handleCreateKey} className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex items-end gap-4">
            <div className="flex-1">
              <label className="block text-xs font-medium text-slate-400 mb-1">Select User</label>
              <select
                value={newKeyUser}
                onChange={(e) => setNewKeyUser(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500"
              >
                <option value="">-- Choose User --</option>
                {users.length === 0 && <option disabled>Load users first...</option>}
                {users.map(u => (
                  <option key={u.id} value={u.name}>{u.name}</option>
                ))}
              </select>
            </div>
            <button
              type="submit"
              disabled={!newKeyUser}
              className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition"
            >
              <Plus className="w-4 h-4" />
              Generate Auth Key
            </button>
          </form>

          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
            {loading ? (
              <div className="p-5 text-sm text-slate-400">Loading keys...</div>
            ) : keys.length === 0 ? (
              <div className="p-10 text-center text-sm text-slate-500">No auth keys found.</div>
            ) : (
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950 text-slate-400 uppercase border-b border-slate-800 font-sans">
                  <tr>
                    <th className="px-4 py-3">User</th>
                    <th className="px-4 py-3">Key</th>
                    <th className="px-4 py-3">Reusable</th>
                    <th className="px-4 py-3">Expiration</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {keys.map((k: any) => (
                    <tr key={k.id} className="hover:bg-slate-800/40 transition">
                      <td className="px-4 py-3 font-semibold text-white font-sans">{k.user?.name}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className="text-emerald-400 bg-emerald-400/10 px-2 py-0.5 rounded truncate max-w-[200px]">
                            {k.key}
                          </span>
                          <button
                            onClick={() => handleCopy(k.key, k.id)}
                            className="text-slate-400 hover:text-white"
                          >
                            {copied === k.id ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-slate-400">{k.reusable ? 'Yes' : 'No'}</td>
                      <td className="px-4 py-3 text-slate-500">
                        {new Date(k.expiration).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
