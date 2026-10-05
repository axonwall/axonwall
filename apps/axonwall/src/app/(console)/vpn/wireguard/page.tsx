'use client';

import { useState } from 'react';
import { KeyRound, Shield, Plus, Copy, Check, FileText } from 'lucide-react';
import { compileWireGuard } from '@axonwall/lib/compile/wireguard';

export default function WireGuardPage() {
  const [copied, setCopied] = useState(false);
  const [selectedClientConf, setSelectedClientConf] = useState<string | null>(null);

  const serverConfig = {
    enabled: true,
    address: '10.50.0.1/24',
    listenPort: 51820,
    publicKey: 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=',
    privateKey: 'W1234567890abcdef1234567890abcdef1234567890=',
    peers: [
      {
        id: 'peer-1',
        name: 'admin-roadwarrior',
        publicKey: 'YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=',
        allowedIps: ['10.50.0.2/32'],
        endpoint: '',
        persistentKeepalive: 25,
        enabled: true,
      },
      {
        id: 'peer-2',
        name: 'branch-office-gw',
        publicKey: 'Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2I=',
        allowedIps: ['10.50.0.10/32', '192.168.200.0/24'],
        endpoint: '203.0.113.50:51820',
        persistentKeepalive: 25,
        enabled: true,
      },
    ],
  };

  const { wgConfig } = compileWireGuard(serverConfig);

  function generateClientProfile(peerName: string, allowedIp: string) {
    const conf = `# Axonwall WireGuard Client Profile: ${peerName}
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY_HERE>
Address = ${allowedIp}
DNS = 10.50.0.1

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
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">WireGuard VPN</h1>
        <p className="text-sm text-slate-400 mt-1">
          Modern, high-performance in-kernel encrypted tunnels for site-to-site and road-warrior access.
        </p>
      </div>

      {/* Server Tunnel Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <KeyRound className="w-5 h-5 text-emerald-400" />
            <h2 className="text-base font-bold text-white">Server Interface (wg0)</h2>
            <span className="text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded font-medium">
              Listening :51820
            </span>
          </div>
          <span className="text-xs font-mono text-slate-400">Tunnel IP: {serverConfig.address}</span>
        </div>

        <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs text-slate-300 flex items-center justify-between">
          <div>
            <span className="text-slate-500 block font-sans text-[11px]">Server Public Key</span>
            <span className="text-emerald-400 select-all">{serverConfig.publicKey}</span>
          </div>
        </div>
      </div>

      {/* Peers List */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl space-y-3 p-5">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-base font-bold text-white">Configured Peers</h2>
          <span className="text-xs text-slate-400">{serverConfig.peers.length} active peers</span>
        </div>

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
                <tr key={peer.id} className="hover:bg-slate-800/40 transition">
                  <td className="px-4 py-3 font-semibold text-white font-sans">{peer.name}</td>
                  <td className="px-4 py-3 text-emerald-400">{peer.allowedIps.join(', ')}</td>
                  <td className="px-4 py-3 text-slate-400">{peer.endpoint || 'Dynamic / Roadwarrior'}</td>
                  <td className="px-4 py-3 text-slate-300">{peer.persistentKeepalive}s</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      onClick={() => generateClientProfile(peer.name, peer.allowedIps[0])}
                      className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-2.5 py-1 rounded text-[11px] font-sans transition cursor-pointer border border-slate-700"
                    >
                      Export Client Conf
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
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
