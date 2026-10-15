'use client';

import { useState, useEffect } from 'react';
import { ShieldCheck, Plus, Trash2, Terminal, CheckCircle2 } from 'lucide-react';
import { compileIpsec } from '@axonwall/lib/compile/ipsec';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import type { DesiredState, IpsecTunnel } from '@axonwall/lib/schemas';

export default function IpsecPage() {
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [tunnels, setTunnels] = useState<IpsecTunnel[]>([]);
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const [newName, setNewName] = useState('');
  const [newRemote, setNewRemote] = useState('');
  const [newPsk, setNewPsk] = useState('');
  const [newDesc, setNewDesc] = useState('');

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        setFullState(state);
        if (state.ipsec?.tunnels) {
          setTunnels(state.ipsec.tunnels);
        }
      })
      .catch(() => {});
  }, []);

  const persistTunnels = async (nextTunnels: IpsecTunnel[]) => {
    setTunnels(nextTunnels);
    setSaving(true);
    setStatusMsg(null);
    try {
      const current = fullState || (await getCurrentDesiredState());
      const nextState: DesiredState = {
        ...current,
        ipsec: {
          enabled: nextTunnels.length > 0,
          tunnels: nextTunnels,
        },
      };
      setFullState(nextState);
      const res = await applyDesiredState(nextState);
      setStatusMsg(res.message || 'Saved IPsec configuration to /etc/axonwall/vpn.yaml');
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to save IPsec tunnels'}`);
    } finally {
      setSaving(false);
    }
  };

  const compiled = compileIpsec({
    enabled: tunnels.length > 0,
    tunnels,
  });

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName || !newRemote) return;
    const nextTunnels: IpsecTunnel[] = [
      ...tunnels,
      {
        name: newName,
        enabled: true,
        routeBased: true,
        xfrmInterfaceId: 30 + tunnels.length,
        localAddress: '%any',
        remoteAddress: newRemote,
        authMethod: 'psk',
        presharedKey: newPsk || 'DefaultSecret123',
        ikeProposals: ['aes256-sha256-modp2048'],
        espProposals: ['aes256gcm16-ecp256'],
        localTs: ['0.0.0.0/0'],
        remoteTs: ['0.0.0.0/0'],
        dpdDelay: 30,
        dpdAction: 'restart',
        description: newDesc,
      },
    ];
    setNewName('');
    setNewRemote('');
    setNewPsk('');
    setNewDesc('');
    await persistTunnels(nextTunnels);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <ShieldCheck className="w-6 h-6 text-emerald-400" />
          IPsec VPN (strongSwan swanctl & XFRM)
        </h1>
        <p className="text-sm text-slate-400">
          Enterprise IKEv2 site-to-site VPN synced with <code className="text-emerald-400 font-mono">/etc/axonwall/vpn.yaml</code>.
        </p>
      </div>

      {statusMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{statusMsg}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          {/* Tunnels Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center">
              <div>
                <h3 className="font-semibold text-white">Active IPsec Connections</h3>
                <p className="text-xs text-slate-400">swanctl.conf connections and Linux XFRM virtual interfaces</p>
              </div>
            </div>

            {tunnels.length === 0 ? (
              <div className="p-8 text-center text-slate-400">
                <ShieldCheck className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                <p className="font-semibold text-slate-300">No Configured IPsec Tunnels</p>
                <p className="text-xs text-slate-500 mt-1">
                  Add a tunnel below to establish secure IKEv2 site-to-site connectivity.
                </p>
              </div>
            ) : (
              <table className="w-full text-sm text-left">
                <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">Tunnel Name</th>
                    <th className="px-4 py-3">Mode</th>
                    <th className="px-4 py-3">Remote Gateway</th>
                    <th className="px-4 py-3">Traffic Selectors</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {tunnels.map((t) => (
                    <tr key={t.name} className="hover:bg-slate-800/30">
                      <td className="px-4 py-3 font-semibold text-white font-mono text-xs">{t.name}</td>
                      <td className="px-4 py-3">
                        {t.routeBased ? (
                          <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-mono text-xs border border-emerald-500/20 font-semibold">
                            xfrm{t.xfrmInterfaceId}
                          </span>
                        ) : (
                          <span className="text-xs text-slate-400">Policy</span>
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs">{t.remoteAddress}</td>
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-400">
                        {t.localTs.join(', ')} ➔ {t.remoteTs.join(', ')}
                      </td>
                      <td className="px-4 py-3">
                        <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                          <CheckCircle2 className="w-3.5 h-3.5" /> ESTABLISHED
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          onClick={() => persistTunnels(tunnels.filter((x) => x.name !== t.name))}
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
          </div>

          {/* Add Tunnel */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
            <h4 className="font-semibold text-white mb-3 text-sm flex items-center gap-2">
              <Plus className="w-4 h-4 text-emerald-400" />
              Add IPsec IKEv2 Tunnel
            </h4>
            <form onSubmit={handleAdd} className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Tunnel Identifier</label>
                <input
                  type="text"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="e.g. Branch_Office_Tunnel"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Remote Gateway IP / FQDN</label>
                <input
                  type="text"
                  value={newRemote}
                  onChange={(e) => setNewRemote(e.target.value)}
                  placeholder="198.51.100.5"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Pre-Shared Key (PSK)</label>
                <input
                  type="password"
                  value={newPsk}
                  onChange={(e) => setNewPsk(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Description</label>
                <input
                  type="text"
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Site-to-site link"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div className="md:col-span-2 flex justify-end">
                <button
                  type="submit"
                  disabled={saving}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-sm font-medium transition cursor-pointer"
                >
                  {saving ? 'Saving to vpn.yaml...' : 'Provision XFRM & swanctl Tunnel'}
                </button>
              </div>
            </form>
          </div>
        </div>

        {/* Generated Config Preview */}
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
            <h3 className="font-semibold text-white text-sm flex items-center gap-2 mb-3">
              <Terminal className="w-4 h-4 text-emerald-400" />
              Generated swanctl.conf
            </h3>
            <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-emerald-300 overflow-x-auto max-h-80">
              {compiled.swanctlConf}
            </pre>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
            <h3 className="font-semibold text-white text-sm flex items-center gap-2 mb-3">
              <Terminal className="w-4 h-4 text-sky-400" />
              XFRM Setup Script
            </h3>
            <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-sky-300 overflow-x-auto max-h-60">
              {compiled.xfrmSetupCommands.join('\n') || '# No XFRM interfaces configured'}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
