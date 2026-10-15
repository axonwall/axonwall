'use client';

import { useState, useEffect } from 'react';
import { KeyRound, Terminal, Download, Cpu, CheckCircle2, Copy, Plus, Trash2 } from 'lucide-react';
import { compileOpenVpn, generateClientOvpnProfile } from '@axonwall/lib/compile/openvpn';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import type { DesiredState, OpenVpnServer } from '@axonwall/lib/schemas';

export default function OpenVpnPage() {
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [servers, setServers] = useState<OpenVpnServer[]>([]);
  const [copied, setCopied] = useState(false);
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  // Add server form
  const [newName, setNewName] = useState('');
  const [newPort, setNewPort] = useState(1194);
  const [newProto, setNewProto] = useState<'udp' | 'tcp'>('udp');
  const [newTunnelNet, setNewTunnelNet] = useState('10.8.0.0/24');

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        setFullState(state);
        if (state.openvpn?.servers) {
          setServers(state.openvpn.servers);
        }
      })
      .catch(() => {});
  }, []);

  const persistServers = async (nextServers: OpenVpnServer[]) => {
    setServers(nextServers);
    setSaving(true);
    setStatusMsg(null);
    try {
      const current = fullState || (await getCurrentDesiredState());
      const nextState: DesiredState = {
        ...current,
        openvpn: {
          enabled: nextServers.length > 0,
          servers: nextServers,
        },
      };
      setFullState(nextState);
      const res = await applyDesiredState(nextState);
      setStatusMsg(res.message || 'Saved OpenVPN configuration to /etc/axonwall/vpn.yaml');
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to save OpenVPN servers'}`);
    } finally {
      setSaving(false);
    }
  };

  const handleAddServer = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim()) return;
    const nextServers: OpenVpnServer[] = [
      ...servers,
      {
        name: newName.trim(),
        enabled: true,
        protocol: newProto,
        port: Number(newPort) || 1194,
        deviceType: 'tun',
        devName: `ovpn-dco${servers.length}`,
        dcoEnabled: true,
        tunnelNetwork: newTunnelNet.trim() || '10.8.0.0/24',
        cipher: 'AES-256-GCM',
        authDigest: 'SHA256',
        clientToClient: false,
        duplicateCn: false,
        cso: [],
        description: 'OpenVPN DCO Server',
      },
    ];
    setNewName('');
    await persistServers(nextServers);
  };

  const selectedServer = servers[0];

  const compiled = compileOpenVpn({
    enabled: servers.length > 0,
    servers,
  });

  const clientProfile = selectedServer
    ? generateClientOvpnProfile({
        serverHost: 'vpn.axonwall.example.com',
        serverPort: selectedServer.port || 1194,
        protocol: selectedServer.protocol || 'udp',
        cipher: selectedServer.cipher || 'AES-256-GCM',
        caCert: '-----BEGIN CERTIFICATE-----\n# Provisioned CA Certificate\n-----END CERTIFICATE-----',
      })
    : '# No OpenVPN server instance selected or configured.';

  const handleCopy = () => {
    if (!selectedServer) return;
    navigator.clipboard.writeText(clientProfile);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <KeyRound className="w-6 h-6 text-emerald-400" />
          OpenVPN 2.6 with Data Channel Offload (DCO)
        </h1>
        <p className="text-sm text-slate-400">
          Wire-speed remote access VPN leveraging <code className="text-emerald-400">ovpn-dco</code> and persisted to{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/vpn.yaml</code>.
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
          {/* Server Instances */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center">
              <div>
                <h3 className="font-semibold text-white">OpenVPN Server Instances</h3>
                <p className="text-xs text-slate-400">Managing instances and kernel offload devices</p>
              </div>
            </div>

            {servers.length === 0 ? (
              <div className="p-8 text-center text-slate-400">
                <KeyRound className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                <p className="font-semibold text-slate-300">No OpenVPN Servers Configured</p>
                <p className="text-xs text-slate-500 mt-1">
                  Create an OpenVPN server instance below or edit <code className="text-emerald-400">/etc/axonwall/vpn.yaml</code>.
                </p>
              </div>
            ) : (
              <table className="w-full text-sm text-left">
                <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">Server Instance</th>
                    <th className="px-4 py-3">Port / Proto</th>
                    <th className="px-4 py-3">Tunnel Subnet</th>
                    <th className="px-4 py-3">DCO Offload</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {servers.map((s) => (
                    <tr key={s.name} className="hover:bg-slate-800/30">
                      <td className="px-4 py-3 font-semibold text-white font-mono text-xs">{s.name}</td>
                      <td className="px-4 py-3 font-mono text-xs uppercase text-emerald-400">
                        {s.port} / {s.protocol}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs">{s.tunnelNetwork}</td>
                      <td className="px-4 py-3">
                        {s.dcoEnabled ? (
                          <span className="inline-flex items-center gap-1 text-xs text-emerald-400 font-mono">
                            <Cpu className="w-3.5 h-3.5" /> Kernel DCO
                          </span>
                        ) : (
                          <span className="text-xs text-slate-500">Userspace tun</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          onClick={() => persistServers(servers.filter((x) => x.name !== s.name))}
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

            {/* Add Server Form */}
            <form onSubmit={handleAddServer} className="p-4 border-t border-slate-800 grid grid-cols-1 md:grid-cols-5 gap-2">
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="Instance Name (corp-ovpn)"
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
                required
              />
              <input
                type="number"
                value={newPort}
                onChange={(e) => setNewPort(Number(e.target.value))}
                placeholder="1194"
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
              />
              <select
                value={newProto}
                onChange={(e) => setNewProto(e.target.value as 'udp' | 'tcp')}
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
              >
                <option value="udp">UDP</option>
                <option value="tcp">TCP</option>
              </select>
              <input
                type="text"
                value={newTunnelNet}
                onChange={(e) => setNewTunnelNet(e.target.value)}
                placeholder="10.8.0.0/24"
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
              />
              <button
                type="submit"
                disabled={saving}
                className="bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg px-3 py-1.5 text-xs font-medium flex items-center justify-center gap-1.5 transition cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Instance</span>
              </button>
            </form>
          </div>

          {/* Client Profile Exporter */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
            <div className="flex justify-between items-center">
              <div>
                <h4 className="font-semibold text-white text-sm flex items-center gap-2">
                  <Download className="w-4 h-4 text-emerald-400" />
                  Road Warrior Client Profile (.ovpn) Export
                </h4>
                <p className="text-xs text-slate-400">Pre-configured client bundle ready for OpenVPN Connect or Linux NetworkManager</p>
              </div>
              {selectedServer && (
                <button
                  type="button"
                  onClick={handleCopy}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-white transition flex items-center gap-1.5 border border-slate-700"
                >
                  {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied!' : 'Copy .ovpn'}
                </button>
              )}
            </div>
            <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-300 overflow-x-auto max-h-48">
              {clientProfile}
            </pre>
          </div>
        </div>

        {/* Server Config Preview */}
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
            <h3 className="font-semibold text-white text-sm flex items-center gap-2 mb-3">
              <Terminal className="w-4 h-4 text-emerald-400" />
              Generated Server Config
            </h3>
            <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-emerald-300 overflow-x-auto max-h-96">
              {compiled.servers[0]?.serverConf || '# No OpenVPN server instance configured'}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
