'use client';

import { useState } from 'react';
import {
  ShieldAlert,
  Radio,
  Server,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  ArrowRightLeft,
  Lock,
  Power,
  Layers,
} from 'lucide-react';
import { compileKeepalived, compileConntrackd } from '@axonwall/lib/compile/ha';
import type { HighAvailabilityConfig } from '@axonwall/lib/schemas';

export default function HighAvailabilityPage() {
  const [activeTab, setActiveTab] = useState<'vrrp' | 'conntrack' | 'sync' | 'raw'>('vrrp');
  const [syncStatus, setSyncStatus] = useState<string | null>(null);

  const [haConfig, setHaConfig] = useState<HighAvailabilityConfig>({
    enabled: true,
    nodeRole: 'master',
    peerAddress: '192.168.1.2',
    peerPort: 8443,
    vrrpInstances: [
      {
        name: 'VI_WAN',
        vrid: 51,
        interface: 'eth0',
        priority: 150,
        virtualIps: ['192.168.1.254/24'],
        authPassword: 'vrrppassword',
      },
      {
        name: 'VI_LAN',
        vrid: 52,
        interface: 'eth1',
        priority: 150,
        virtualIps: ['192.168.100.1/24'],
      },
    ],
    conntrackSync: {
      enabled: true,
      interface: 'eth0',
      protocol: 'unicast',
      peerAddress: '192.168.1.2',
      port: 3780,
    },
    syncSections: {
      interfaces: false,
      firewall: true,
      dhcp: true,
      dns: true,
      aliases: true,
      vpn: true,
    },
    maintenanceMode: false,
  });

  const keepalivedOutput = compileKeepalived(haConfig, 'axonwall-node01');
  const conntrackdOutput = compileConntrackd(haConfig, '192.168.1.1');

  const handleSyncToPeer = () => {
    setSyncStatus('Initiating mTLS bundle handshake to peer 192.168.1.2:8443...');
    setTimeout(() => {
      setSyncStatus('Replication succeeded: 6 sections synchronized with 0 conflicts.');
    }, 1200);
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <ArrowRightLeft className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">High Availability (HA)</h1>
              <p className="text-sm text-slate-400">
                Keepalived VRRP active/standby failover, conntrackd state synchronization, and mTLS configuration replication.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setHaConfig({ ...haConfig, maintenanceMode: !haConfig.maintenanceMode })}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition flex items-center gap-2 border ${
              haConfig.maintenanceMode
                ? 'bg-amber-500/10 text-amber-400 border-amber-500/30 hover:bg-amber-500/20'
                : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
            }`}
          >
            <Power className="w-4 h-4" />
            {haConfig.maintenanceMode ? 'Maintenance Active (Forced Failover)' : 'Enable Maintenance'}
          </button>
          <button
            onClick={handleSyncToPeer}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium transition flex items-center gap-2 shadow-lg shadow-emerald-950/40"
          >
            <RefreshCw className="w-4 h-4" />
            Sync to Peer Now
          </button>
        </div>
      </div>

      {syncStatus && (
        <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-500/30 flex items-center justify-between text-sm text-emerald-300">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-400" />
            <span>{syncStatus}</span>
          </div>
          <button onClick={() => setSyncStatus(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Cluster Overview Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Local Cluster Node</div>
          <div className="flex items-center gap-2">
            <div className={`w-3 h-3 rounded-full ${haConfig.maintenanceMode ? 'bg-amber-400' : 'bg-emerald-400'}`} />
            <span className="text-xl font-bold text-white capitalize">{haConfig.nodeRole}</span>
          </div>
          <p className="text-xs text-slate-400 mt-2">
            {haConfig.maintenanceMode ? 'Priority lowered to 1 (standby taking over)' : 'Operating at full VRRP priority 150'}
          </p>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Peer Node</div>
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-emerald-400" />
            <span className="text-xl font-bold text-white">{haConfig.peerAddress}</span>
          </div>
          <p className="text-xs text-emerald-400 mt-2 flex items-center gap-1">
            <Lock className="w-3 h-3" /> mTLS Port 8443 Healthy
          </p>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Conntrack State Sync</div>
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-sky-400" />
            <span className="text-xl font-bold text-white">FTFW Unicast</span>
          </div>
          <p className="text-xs text-slate-400 mt-2">4,812 active connections mirrored</p>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Failover Latency</div>
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-purple-400" />
            <span className="text-xl font-bold text-white">&lt; 1.0 sec</span>
          </div>
          <p className="text-xs text-slate-400 mt-2">GARP broadcast on state change</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
        <button
          onClick={() => setActiveTab('vrrp')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
            activeTab === 'vrrp' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          Virtual IP Instances (VRRP)
        </button>
        <button
          onClick={() => setActiveTab('conntrack')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
            activeTab === 'conntrack' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          Conntrackd Sync
        </button>
        <button
          onClick={() => setActiveTab('sync')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
            activeTab === 'sync' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          mTLS Section Sync
        </button>
        <button
          onClick={() => setActiveTab('raw')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
            activeTab === 'raw' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          Rendered Configs (keepalived / conntrackd)
        </button>
      </div>

      {/* Tab: VRRP */}
      {activeTab === 'vrrp' && (
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-6">
          <h2 className="text-lg font-semibold text-white">Active VRRP Virtual Routers</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-slate-800 text-slate-400 text-xs uppercase font-medium">
                <tr>
                  <th className="pb-3">Instance</th>
                  <th className="pb-3">VRID</th>
                  <th className="pb-3">Interface</th>
                  <th className="pb-3">Priority</th>
                  <th className="pb-3">Virtual IP (VIP)</th>
                  <th className="pb-3">State</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
                {haConfig.vrrpInstances.map((v) => (
                  <tr key={v.name} className="hover:bg-slate-800/30">
                    <td className="py-4 font-semibold text-white">{v.name}</td>
                    <td className="py-4 text-emerald-400">{v.vrid}</td>
                    <td className="py-4 text-slate-300">{v.interface}</td>
                    <td className="py-4 text-slate-300">
                      {haConfig.maintenanceMode ? <span className="text-amber-400">1 (Maint)</span> : v.priority}
                    </td>
                    <td className="py-4 text-slate-200">{v.virtualIps.join(', ')}</td>
                    <td className="py-4">
                      <span className="px-2.5 py-1 rounded-md text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        {haConfig.nodeRole.toUpperCase()}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab: Conntrack */}
      {activeTab === 'conntrack' && (
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">Kernel Conntrack State Synchronization</h2>
              <p className="text-sm text-slate-400">
                Mirrors established TCP/UDP connections across the cluster in real time so active calls and VPN tunnels do not drop during failover.
              </p>
            </div>
            <span className="px-3 py-1 bg-sky-500/10 text-sky-400 border border-sky-500/20 rounded-lg text-xs font-medium">
              conntrackd.service Active
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block mb-1">SYNC PROTOCOL</span>
              <span className="text-emerald-400 font-bold">FTFW (Fault-Tolerant Firewall)</span>
            </div>
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block mb-1">TRANSMISSION MODE</span>
              <span className="text-white font-bold">UDP Unicast (Port 3780)</span>
            </div>
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block mb-1">SYNC INTERFACE</span>
              <span className="text-white font-bold">{haConfig.conntrackSync.interface}</span>
            </div>
          </div>
        </div>
      )}

      {/* Tab: Sync Sections */}
      {activeTab === 'sync' && (
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-6">
          <div>
            <h2 className="text-lg font-semibold text-white">mTLS Configuration Synchronization</h2>
            <p className="text-sm text-slate-400">
              Select which configuration sections to automatically push to the secondary cluster node upon apply.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {Object.entries(haConfig.syncSections).map(([section, enabled]) => (
              <label
                key={section}
                className="flex items-center gap-3 p-4 rounded-xl bg-slate-950 border border-slate-800 hover:border-slate-700 cursor-pointer transition"
              >
                <input
                  type="checkbox"
                  checked={enabled}
                  onChange={(e) => {
                    setHaConfig({
                      ...haConfig,
                      syncSections: {
                        ...haConfig.syncSections,
                        [section]: e.target.checked,
                      },
                    });
                  }}
                  className="rounded border-slate-700 text-emerald-600 focus:ring-emerald-500"
                />
                <div>
                  <span className="text-sm font-semibold text-white capitalize">{section}</span>
                  <p className="text-xs text-slate-400">
                    {section === 'interfaces'
                      ? 'Sync physical NICs and IP addresses (careful: requires identical hardware)'
                      : `Replicate ${section} rules, policies, and definitions`}
                  </p>
                </div>
              </label>
            ))}
          </div>
        </div>
      )}

      {/* Tab: Raw */}
      {activeTab === 'raw' && (
        <div className="space-y-6">
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="text-sm font-semibold text-slate-300">Generated /etc/keepalived/keepalived.conf</h3>
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto max-h-80">
              {keepalivedOutput}
            </pre>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="text-sm font-semibold text-slate-300">Generated /etc/conntrackd/conntrackd.conf</h3>
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto max-h-80">
              {conntrackdOutput}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
