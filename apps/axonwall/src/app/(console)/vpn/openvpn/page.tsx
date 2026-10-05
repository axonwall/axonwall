'use client';

import { useState } from 'react';
import { KeyRound, Terminal, Download, Cpu, CheckCircle2, Copy } from 'lucide-react';
import { compileOpenVpn, generateClientOvpnProfile } from '@axonwall/lib/compile/openvpn';
import type { OpenVpnServer } from '@axonwall/lib/schemas';

export default function OpenVpnPage() {
  const [servers] = useState<OpenVpnServer[]>([
    {
      id: 'ovpn-roadwarrior',
      name: 'Corporate_RemoteAccess',
      enabled: true,
      protocol: 'udp',
      port: 1194,
      deviceType: 'tun',
      devName: 'ovpn-dco0',
      dcoEnabled: true,
      tunnelNetwork: '10.8.0.0/24',
      localNetwork: '192.168.100.0/24',
      cipher: 'AES-256-GCM',
      authDigest: 'SHA256',
      clientToClient: true,
      duplicateCn: false,
      cso: [
        {
          id: 'cso-admin',
          commonName: 'secops-laptop',
          assignedIp: '10.8.0.10',
          pushRoutes: ['192.168.200.0/24'],
          description: 'Security Admin Static IP and DMZ Route',
        },
      ],
      description: 'High-speed remote worker gateway accelerated by Linux ovpn-dco',
    },
  ]);

  const [copied, setCopied] = useState(false);
  const [selectedServer] = useState(servers[0]);

  const compiled = compileOpenVpn({
    enabled: true,
    servers,
  });

  const clientProfile = generateClientOvpnProfile({
    serverHost: 'vpn.axonwall.example.com',
    serverPort: selectedServer?.port || 1194,
    protocol: selectedServer?.protocol || 'udp',
    cipher: selectedServer?.cipher || 'AES-256-GCM',
    caCert: '-----BEGIN CERTIFICATE-----\nMIIB/zCCAaWgAwIBAgIU...\n-----END CERTIFICATE-----',
  });

  const handleCopy = () => {
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
          Wire-speed remote access VPN leveraging the Linux kernel <code className="text-emerald-400">ovpn-dco</code> module for in-kernel packet encryption.
        </p>
      </div>

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

            <table className="w-full text-sm text-left">
              <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Server Instance</th>
                  <th className="px-4 py-3">Port / Proto</th>
                  <th className="px-4 py-3">Tunnel Subnet</th>
                  <th className="px-4 py-3">DCO Offload</th>
                  <th className="px-4 py-3">Overrides (CSO)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {servers.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-800/30">
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
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">{s.cso?.length || 0} Clients</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Client Specific Overrides (CSO) */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center">
              <div>
                <h3 className="font-semibold text-white">Client-Specific Overrides (CSO)</h3>
                <p className="text-xs text-slate-400">Static IP assignments and customized route pushes per certificate CN</p>
              </div>
            </div>

            <table className="w-full text-sm text-left">
              <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Client Common Name (CN)</th>
                  <th className="px-4 py-3">Assigned Static IP</th>
                  <th className="px-4 py-3">Pushed Subnets</th>
                  <th className="px-4 py-3">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {selectedServer?.cso?.map((c) => (
                  <tr key={c.id || c.commonName} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3 font-mono font-semibold text-white text-xs">{c.commonName}</td>
                    <td className="px-4 py-3 font-mono text-emerald-400 text-xs">{c.assignedIp || 'Dynamic'}</td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">
                      {c.pushRoutes?.join(', ') || 'None'}
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-xs">{c.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
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
              <button
                type="button"
                onClick={handleCopy}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-white transition flex items-center gap-1.5 border border-slate-700"
              >
                {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied!' : 'Copy .ovpn'}
              </button>
            </div>
            <pre className="p-3 bg-slate-950 rounded-lg text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap border border-slate-800">
              {clientProfile}
            </pre>
          </div>
        </div>

        {/* Right 1 Col: Live Server Conf */}
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col h-full">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                <Terminal className="w-4 h-4 text-emerald-400" />
                Rendered Server Config
              </div>
              <span className="text-[10px] text-emerald-400 font-mono">DCO Enabled</span>
            </div>
            <pre className="mt-3 p-3 bg-slate-950 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap flex-1 border border-slate-900">
              {compiled.servers[0]?.serverConf || '# No servers configured'}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
