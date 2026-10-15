'use client';

import { useState, useEffect } from 'react';
import { KeyRound, Plus, Trash2, Copy, Check, FileText, Save, CheckCircle2 } from 'lucide-react';
import { compileWireGuard } from '@axonwall/lib/compile/wireguard';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import type { DesiredState } from '@axonwall/lib/schemas';

export default function WireGuardPage() {
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [copied, setCopied] = useState(false);
  const [selectedClientConf, setSelectedClientConf] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const [serverConfig, setServerConfig] = useState({
    enabled: false,
    address: '10.50.0.1/24',
    listenPort: 51820,
    publicKey: 'AxonwallWgServerPublicKeyBase64Placeholder000=',
    privateKey: '',
    peers: [] as Array<{
      id?: string;
      name: string;
      publicKey: string;
      allowedIps: string[];
      endpoint?: string;
      persistentKeepalive: number;
      enabled: boolean;
    }>,
  });

  // New Peer Form
  const [peerName, setPeerName] = useState('');
  const [peerPubKey, setPeerPubKey] = useState('');
  const [peerAllowedIps, setPeerAllowedIps] = useState('10.50.0.2/32');
  const [peerEndpoint, setPeerEndpoint] = useState('');

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        setFullState(state);
        if (state.wireguard) {
          setServerConfig({
            enabled: state.wireguard.enabled,
            address: state.wireguard.address || '10.50.0.1/24',
            listenPort: state.wireguard.listenPort || 51820,
            publicKey: 'AxonwallWgServerPublicKeyBase64Placeholder000=',
            privateKey: state.wireguard.privateKey || '',
            peers: state.wireguard.peers || [],
          });
        }
      })
      .catch(() => {});
  }, []);

  const persistWireGuard = async (nextWg: typeof serverConfig) => {
    setServerConfig(nextWg);
    setSaving(true);
    setStatusMsg(null);
    try {
      const current = fullState || (await getCurrentDesiredState());
      const nextState: DesiredState = {
        ...current,
        wireguard: {
          enabled: nextWg.enabled,
          address: nextWg.address,
          listenPort: Number(nextWg.listenPort) || 51820,
          privateKey: nextWg.privateKey && nextWg.privateKey.length >= 32 ? nextWg.privateKey : undefined,
          peers: nextWg.peers.map((p) => ({
            id: p.id,
            name: p.name,
            publicKey: p.publicKey,
            allowedIps: p.allowedIps,
            endpoint: p.endpoint || undefined,
            persistentKeepalive: p.persistentKeepalive ?? 25,
            enabled: p.enabled ?? true,
          })),
        },
      };
      setFullState(nextState);
      const res = await applyDesiredState(nextState);
      setStatusMsg(res.message || 'Saved WireGuard configuration to /etc/axonwall/vpn.yaml');
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to save WireGuard settings'}`);
    } finally {
      setSaving(false);
    }
  };

  const handleAddPeer = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!peerName.trim() || !peerPubKey.trim()) return;
    const paddedKey =
      peerPubKey.trim().length >= 32
        ? peerPubKey.trim()
        : `${peerPubKey.trim()}${'A'.repeat(32 - peerPubKey.trim().length)}=`;
    const nextWg = {
      ...serverConfig,
      enabled: true,
      peers: [
        ...serverConfig.peers,
        {
          name: peerName.trim(),
          publicKey: paddedKey,
          allowedIps: peerAllowedIps
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean),
          endpoint: peerEndpoint.trim() || undefined,
          persistentKeepalive: 25,
          enabled: true,
        },
      ],
    };
    setPeerName('');
    setPeerPubKey('');
    setPeerEndpoint('');
    await persistWireGuard(nextWg);
  };

  const handleDeletePeer = async (name: string) => {
    const nextWg = {
      ...serverConfig,
      peers: serverConfig.peers.filter((p) => p.name !== name),
    };
    await persistWireGuard(nextWg);
  };

  compileWireGuard(serverConfig as any);

  function generateClientProfile(peerNameStr: string, allowedIp: string) {
    const conf = `# Axonwall WireGuard Client Profile: ${peerNameStr}
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY_HERE>
Address = ${allowedIp}
DNS = ${serverConfig.address.split('/')[0]}

[Peer]
PublicKey = ${serverConfig.publicKey}
Endpoint = vpn.axonwall.local:${serverConfig.listenPort}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`;
    setSelectedClientConf(conf);
  }

  function handleCopy() {
    if (!selectedClientConf) return;
    navigator.clipboard.writeText(selectedClientConf);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">WireGuard VPN</h1>
          <p className="text-sm text-slate-400 mt-1">
            In-kernel encrypted tunnels synced with <code className="text-emerald-400 font-mono">/etc/axonwall/vpn.yaml</code>.
          </p>
        </div>
        <button
          type="button"
          onClick={() => persistWireGuard(serverConfig)}
          disabled={saving}
          className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
        >
          <Save className="w-3.5 h-3.5" />
          <span>{saving ? 'Saving YAML...' : 'Save to vpn.yaml'}</span>
        </button>
      </div>

      {statusMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{statusMsg}</span>
        </div>
      )}

      {/* Server Tunnel Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <KeyRound className="w-5 h-5 text-emerald-400" />
            <h2 className="text-base font-bold text-white">Server Interface (wg0)</h2>
            <button
              type="button"
              onClick={() => persistWireGuard({ ...serverConfig, enabled: !serverConfig.enabled })}
              className={`text-xs px-2.5 py-0.5 rounded font-medium cursor-pointer border transition ${
                serverConfig.enabled
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
              }`}
            >
              {serverConfig.enabled ? 'Enabled' : 'Disabled'}
            </button>
          </div>
          <div className="flex items-center gap-3 text-xs font-mono">
            <label className="text-slate-400">
              Tunnel CIDR:{' '}
              <input
                type="text"
                value={serverConfig.address}
                onChange={(e) => setServerConfig({ ...serverConfig, address: e.target.value })}
                className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-emerald-400 w-36"
              />
            </label>
            <label className="text-slate-400">
              UDP Port:{' '}
              <input
                type="number"
                value={serverConfig.listenPort}
                onChange={(e) => setServerConfig({ ...serverConfig, listenPort: Number(e.target.value) })}
                className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-white w-24"
              />
            </label>
          </div>
        </div>

        <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs text-slate-300 flex items-center justify-between">
          <div>
            <span className="text-slate-500 block font-sans text-[11px]">Server Public Key</span>
            <span className="text-slate-400 select-all">{serverConfig.publicKey}</span>
          </div>
        </div>
      </div>

      {/* Peers List */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl space-y-4 p-5">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-base font-bold text-white">Configured Peers</h2>
          <span className="text-xs text-slate-400">{serverConfig.peers.length} active peers</span>
        </div>

        {serverConfig.peers.length === 0 ? (
          <div className="p-8 text-center text-slate-400 border border-slate-800/80 rounded-lg">
            <KeyRound className="w-8 h-8 text-slate-600 mx-auto mb-2" />
            <p className="font-semibold text-slate-300">No Configured Peers</p>
            <p className="text-xs text-slate-500 mt-1">
              Add a peer below or edit <code className="text-emerald-400">/etc/axonwall/vpn.yaml</code> directly.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 uppercase border-b border-slate-800 font-sans">
                <tr>
                  <th className="px-4 py-3">Peer Name</th>
                  <th className="px-4 py-3">Allowed IPs</th>
                  <th className="px-4 py-3">Endpoint</th>
                  <th className="px-4 py-3">Keepalive</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {serverConfig.peers.map((peer) => (
                  <tr key={peer.name} className="hover:bg-slate-800/40 transition">
                    <td className="px-4 py-3 font-semibold text-white font-sans">{peer.name}</td>
                    <td className="px-4 py-3 text-emerald-400">{peer.allowedIps.join(', ')}</td>
                    <td className="px-4 py-3 text-slate-400">{peer.endpoint || 'Dynamic / Roadwarrior'}</td>
                    <td className="px-4 py-3 text-slate-300">{peer.persistentKeepalive}s</td>
                    <td className="px-4 py-3 text-right flex items-center justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => generateClientProfile(peer.name, peer.allowedIps[0] || '10.50.0.2/32')}
                        className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-2.5 py-1 rounded text-[11px] font-sans transition cursor-pointer border border-slate-700"
                      >
                        Export Client Conf
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDeletePeer(peer.name)}
                        className="text-slate-500 hover:text-red-400 transition p-1"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Add Peer Form */}
        <form onSubmit={handleAddPeer} className="grid grid-cols-1 md:grid-cols-5 gap-2 pt-3 border-t border-slate-800">
          <input
            type="text"
            value={peerName}
            onChange={(e) => setPeerName(e.target.value)}
            placeholder="Peer Name (laptop-01)"
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white"
            required
          />
          <input
            type="text"
            value={peerPubKey}
            onChange={(e) => setPeerPubKey(e.target.value)}
            placeholder="Base64 Public Key (min 32 chars)"
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
            required
          />
          <input
            type="text"
            value={peerAllowedIps}
            onChange={(e) => setPeerAllowedIps(e.target.value)}
            placeholder="Allowed IPs (10.50.0.2/32)"
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
            required
          />
          <input
            type="text"
            value={peerEndpoint}
            onChange={(e) => setPeerEndpoint(e.target.value)}
            placeholder="Endpoint (optional host:port)"
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
          />
          <button
            type="submit"
            disabled={saving}
            className="bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg px-3 py-1.5 text-xs font-medium flex items-center justify-center gap-1.5 transition cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Peer</span>
          </button>
        </form>
      </div>

      {/* Generated Client Conf Modal/Card */}
      {selectedClientConf && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-semibold text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-emerald-400" />
              <span>Exported Client WireGuard Configuration</span>
            </span>
            <button
              type="button"
              onClick={handleCopy}
              className="bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied!' : 'Copy to Clipboard'}</span>
            </button>
          </div>
          <pre className="bg-slate-950 p-4 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto">
            {selectedClientConf}
          </pre>
        </div>
      )}
    </div>
  );
}
