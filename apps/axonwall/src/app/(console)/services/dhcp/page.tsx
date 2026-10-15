'use client';

import { useState, useEffect } from 'react';
import { Server, Plus, Trash2, CheckCircle2, FileCode, ShieldCheck, Save } from 'lucide-react';
import { compileKeaDhcp4 } from '@axonwall/lib/compile/kea';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import type { DesiredState, DhcpConfig, Interface } from '@axonwall/lib/schemas';

const DEFAULT_DHCP: DhcpConfig = {
  enabled: true,
  subnets: [
    {
      interface: 'lan',
      subnet: '192.168.1.0/24',
      poolStart: '192.168.1.100',
      poolEnd: '192.168.1.200',
      routers: ['192.168.1.1'],
      dnsServers: ['192.168.1.1'],
      staticMappings: [],
      enabled: true,
    },
  ],
};

const DEFAULT_INTERFACES: Interface[] = [
  { name: 'lan', device: 'eth1', type: 'static', enabled: true, description: 'LAN', mtu: 1500 },
];

export default function DhcpPage() {
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [dhcp, setDhcp] = useState<DhcpConfig>(DEFAULT_DHCP);
  const [interfaces, setInterfaces] = useState<Interface[]>(DEFAULT_INTERFACES);
  const [showKeaConfig, setShowKeaConfig] = useState(false);
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  // New static mapping form
  const [newMac, setNewMac] = useState('');
  const [newIp, setNewIp] = useState('');
  const [newHostname, setNewHostname] = useState('');
  const [newDesc, setNewDesc] = useState('');

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        setFullState(state);
        if (state?.dhcp?.subnets?.length) {
          setDhcp(state.dhcp);
        }
        if (state?.interfaces?.length) {
          setInterfaces(state.interfaces);
        }
      })
      .catch(() => {});
  }, []);

  const persistDhcp = async (updatedDhcp: DhcpConfig) => {
    setDhcp(updatedDhcp);
    setSaving(true);
    setStatusMsg(null);
    try {
      const current = fullState || (await getCurrentDesiredState());
      const nextState: DesiredState = {
        ...current,
        dhcp: updatedDhcp,
      };
      setFullState(nextState);
      const res = await applyDesiredState(nextState);
      setStatusMsg(res.message || 'Saved to /etc/axonwall/services.yaml');
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to save DHCP configuration'}`);
    } finally {
      setSaving(false);
    }
  };

  const handleAddStaticMapping = async (subnetIdx: number, e: React.FormEvent) => {
    e.preventDefault();
    if (!newMac.trim() || !newIp.trim()) return;
    const nextSubnets = dhcp.subnets.map((s, idx) =>
      idx === subnetIdx
        ? {
            ...s,
            staticMappings: [
              ...s.staticMappings,
              {
                mac: newMac.trim(),
                ip: newIp.trim(),
                hostname: newHostname.trim() || undefined,
                description: newDesc.trim(),
              },
            ],
          }
        : s
    );
    setNewMac('');
    setNewIp('');
    setNewHostname('');
    setNewDesc('');
    await persistDhcp({ ...dhcp, subnets: nextSubnets });
  };

  const handleDeleteStaticMapping = async (subnetIdx: number, mac: string) => {
    const nextSubnets = dhcp.subnets.map((s, idx) =>
      idx === subnetIdx
        ? {
            ...s,
            staticMappings: s.staticMappings.filter((m) => m.mac !== mac),
          }
        : s
    );
    await persistDhcp({ ...dhcp, subnets: nextSubnets });
  };

  const handleUpdatePool = (subnetIdx: number, field: 'poolStart' | 'poolEnd' | 'subnet', value: string) => {
    setDhcp({
      ...dhcp,
      subnets: dhcp.subnets.map((s, idx) => (idx === subnetIdx ? { ...s, [field]: value } : s)),
    });
  };

  const { keaDhcp4Config } = compileKeaDhcp4(dhcp, interfaces);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">DHCP Server (Kea)</h1>
          <p className="text-sm text-slate-400 mt-1">
            High-performance dynamic address allocation and static reservations synced with{' '}
            <code className="text-emerald-400 font-mono">/etc/axonwall/services.yaml</code>.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => persistDhcp(dhcp)}
            disabled={saving}
            className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{saving ? 'Saving YAML...' : 'Save to services.yaml'}</span>
          </button>
          <button
            type="button"
            onClick={() => setShowKeaConfig(!showKeaConfig)}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer border border-slate-700"
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>{showKeaConfig ? 'Hide Kea JSON' : 'View Kea JSON'}</span>
          </button>
        </div>
      </div>

      {statusMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{statusMsg}</span>
        </div>
      )}

      {/* Non-Authoritative Safeguard Banner for Attached Networks */}
      <div className="p-4 bg-cyan-950/40 border border-cyan-800/40 rounded-xl flex items-start gap-3 text-xs text-cyan-200">
        <ShieldCheck className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="font-semibold text-cyan-300 block text-sm">
            DHCP Server Authority Policy & Attached Networks
          </span>
          <p className="text-slate-300 leading-relaxed">
            Axonwall operates as an authoritative DHCP server solely on configured internal subnets (e.g. <strong>LAN</strong>). Optional interfaces (<strong>OPT1</strong> and <strong>OPT2</strong>) are designated for attached networks (corporate LANs, guest networks, upstream router subnets) and run strictly in non-authoritative mode without Kea DHCP listening to prevent rogue DHCP offer collisions.
          </p>
        </div>
      </div>

      {showKeaConfig && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
          <span className="text-xs font-mono text-emerald-400 font-semibold block">
            Generated /etc/axonwall/managed/kea-dhcp4.conf
          </span>
          <pre className="bg-slate-950 p-4 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto max-h-72">
            {keaDhcp4Config}
          </pre>
        </div>
      )}

      {/* Subnets Overview */}
      <div className="grid grid-cols-1 gap-6">
        {dhcp.subnets.map((sub, subIdx) => (
          <div key={`${sub.interface}-${subIdx}`} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="w-5 h-5 text-emerald-400" />
                <h2 className="text-base font-bold text-white uppercase">{sub.interface} Subnet</h2>
                <span className="text-xs bg-slate-800 text-slate-300 font-mono px-2 py-0.5 rounded border border-slate-700">
                  {sub.subnet}
                </span>
              </div>
              <span className="text-xs font-semibold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Active
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80 space-y-2">
                <span className="text-slate-400 block font-sans">Dynamic IP Pool Range</span>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={sub.poolStart}
                    onChange={(e) => handleUpdatePool(subIdx, 'poolStart', e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded px-2 py-1 text-emerald-400"
                  />
                  <span className="text-slate-500">-</span>
                  <input
                    type="text"
                    value={sub.poolEnd}
                    onChange={(e) => handleUpdatePool(subIdx, 'poolEnd', e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded px-2 py-1 text-emerald-400"
                  />
                </div>
              </div>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                <span className="text-slate-400 block font-sans mb-1">Advertised Gateway</span>
                <span className="text-slate-200">{sub.routers.join(', ') || 'Auto'}</span>
              </div>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                <span className="text-slate-400 block font-sans mb-1">DNS Servers</span>
                <span className="text-slate-200">{sub.dnsServers.join(', ') || 'Auto'}</span>
              </div>
            </div>

            {/* Static Mappings Table */}
            <div className="space-y-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block">
                Static DHCP Reservations
              </span>
              <div className="bg-slate-950 border border-slate-800/80 rounded-lg overflow-hidden">
                {sub.staticMappings.length === 0 ? (
                  <div className="p-6 text-center text-slate-500 text-xs">
                    No static IP reservations configured for {sub.interface}.
                  </div>
                ) : (
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-900/60 text-slate-400 uppercase border-b border-slate-800">
                      <tr>
                        <th className="px-4 py-2.5">MAC Address</th>
                        <th className="px-4 py-2.5">IP Address</th>
                        <th className="px-4 py-2.5">Hostname</th>
                        <th className="px-4 py-2.5">Description</th>
                        <th className="px-4 py-2.5 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {sub.staticMappings.map((m) => (
                        <tr key={m.mac} className="hover:bg-slate-900/40">
                          <td className="px-4 py-2.5 text-slate-300">{m.mac}</td>
                          <td className="px-4 py-2.5 text-emerald-400">{m.ip}</td>
                          <td className="px-4 py-2.5 text-white font-sans">{m.hostname || '-'}</td>
                          <td className="px-4 py-2.5 text-slate-400 font-sans">{m.description || '-'}</td>
                          <td className="px-4 py-2.5 text-right">
                            <button
                              type="button"
                              onClick={() => handleDeleteStaticMapping(subIdx, m.mac)}
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

              {/* Add Static Reservation Form */}
              <form
                onSubmit={(e) => handleAddStaticMapping(subIdx, e)}
                className="grid grid-cols-1 md:grid-cols-5 gap-2 pt-2"
              >
                <input
                  type="text"
                  value={newMac}
                  onChange={(e) => setNewMac(e.target.value)}
                  placeholder="MAC (aa:bb:cc:dd:ee:ff)"
                  className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
                  required
                />
                <input
                  type="text"
                  value={newIp}
                  onChange={(e) => setNewIp(e.target.value)}
                  placeholder="IPv4 (192.168.1.50)"
                  className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
                  required
                />
                <input
                  type="text"
                  value={newHostname}
                  onChange={(e) => setNewHostname(e.target.value)}
                  placeholder="Hostname (nas-01)"
                  className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white"
                />
                <input
                  type="text"
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Description"
                  className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white"
                />
                <button
                  type="submit"
                  disabled={saving}
                  className="bg-slate-800 hover:bg-slate-700 text-emerald-400 border border-slate-700 rounded-lg px-3 py-1.5 text-xs font-medium flex items-center justify-center gap-1.5 transition cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Add Reservation</span>
                </button>
              </form>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
