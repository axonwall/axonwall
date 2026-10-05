'use client';

import { useState } from 'react';
import {
  Server,
  Play,
  Square,
  RotateCw,
  CheckCircle2,
  AlertCircle,
  FileText,
  Search,
  Shield,
  Activity,
} from 'lucide-react';

interface ManagedService {
  name: string;
  unit: string;
  description: string;
  status: 'active' | 'inactive' | 'failed';
  pid: number;
  memory: string;
  uptime: string;
}

export default function ServicesSupervisorPage() {
  const [services, setServices] = useState<ManagedService[]>([
    {
      name: 'Axonwall Privileged Daemon',
      unit: 'axonwalld.service',
      description: 'Go privileged nftables & netlink transaction supervisor',
      status: 'active',
      pid: 612,
      memory: '24.1 MB',
      uptime: '4d 18h',
    },
    {
      name: 'Keepalived VRRP Daemon',
      unit: 'keepalived.service',
      description: 'High availability virtual router failover daemon',
      status: 'active',
      pid: 745,
      memory: '8.4 MB',
      uptime: '4d 18h',
    },
    {
      name: 'Conntrack State Sync',
      unit: 'conntrackd.service',
      description: 'Connection tracking state table sync over FTFW',
      status: 'active',
      pid: 802,
      memory: '14.2 MB',
      uptime: '4d 18h',
    },
    {
      name: 'Suricata IDS/IPS',
      unit: 'suricata.service',
      description: 'Next-gen intrusion detection and prevention (NFQUEUE fail-open)',
      status: 'active',
      pid: 914,
      memory: '312.0 MB',
      uptime: '2d 06h',
    },
    {
      name: 'Unbound DNS Resolver',
      unit: 'unbound.service',
      description: 'Recursive DNSSEC validating caching resolver with RPZ blocklists',
      status: 'active',
      pid: 530,
      memory: '42.8 MB',
      uptime: '4d 18h',
    },
    {
      name: 'ISC Kea DHCPv4 Server',
      unit: 'kea-dhcp4.service',
      description: 'High-performance DHCPv4 server with HA hooks',
      status: 'active',
      pid: 588,
      memory: '18.9 MB',
      uptime: '4d 18h',
    },
    {
      name: 'FRRouting Dynamic Engine',
      unit: 'frr.service',
      description: 'BGP, OSPF, and BFD routing protocol daemon',
      status: 'active',
      pid: 1044,
      memory: '38.6 MB',
      uptime: '3d 11h',
    },
    {
      name: 'HAProxy Reverse Proxy',
      unit: 'haproxy.service',
      description: 'L4/L7 load balancer and SSL/TLS termination',
      status: 'active',
      pid: 1120,
      memory: '22.4 MB',
      uptime: '1d 04h',
    },
    {
      name: 'CrowdSec Security Engine',
      unit: 'crowdsec.service',
      description: 'Collaborative IPS agent and nftables set bouncer',
      status: 'active',
      pid: 1205,
      memory: '64.5 MB',
      uptime: '4d 18h',
    },
  ]);

  const [selectedLogs, setSelectedLogs] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  const handleAction = (unit: string, action: 'restart' | 'stop' | 'start') => {
    setActionNotice(`Executing systemctl ${action} ${unit}...`);
    setTimeout(() => {
      setActionNotice(`Successfully completed ${action} for ${unit}.`);
      setTimeout(() => setActionNotice(null), 3000);
    }, 800);
  };

  const filteredServices = services.filter(
    (s) =>
      s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.unit.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Service Supervisor & Watchdog</h1>
            <p className="text-sm text-slate-400">
              Systemd unit lifecycle manager, health probes, automated failure recovery, and journal logging.
            </p>
          </div>
        </div>

        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search service units..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-64"
          />
        </div>
      </div>

      {actionNotice && (
        <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-500/30 flex items-center gap-3 text-sm text-emerald-300">
          <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-400" />
          <span>{actionNotice}</span>
        </div>
      )}

      {/* Services Table */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-800 text-slate-400 text-xs uppercase font-medium">
              <tr>
                <th className="pb-3">Service Name</th>
                <th className="pb-3">Unit Name</th>
                <th className="pb-3">Status</th>
                <th className="pb-3">PID</th>
                <th className="pb-3">Memory</th>
                <th className="pb-3">Uptime</th>
                <th className="pb-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {filteredServices.map((svc) => (
                <tr key={svc.unit} className="hover:bg-slate-800/30">
                  <td className="py-4">
                    <span className="font-sans font-semibold text-white block">{svc.name}</span>
                    <span className="text-[11px] font-sans text-slate-400">{svc.description}</span>
                  </td>
                  <td className="py-4 text-emerald-400">{svc.unit}</td>
                  <td className="py-4">
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                      Active (running)
                    </span>
                  </td>
                  <td className="py-4 text-slate-300">{svc.pid}</td>
                  <td className="py-4 text-slate-300">{svc.memory}</td>
                  <td className="py-4 text-slate-400">{svc.uptime}</td>
                  <td className="py-4 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <button
                        title="Restart"
                        onClick={() => handleAction(svc.unit, 'restart')}
                        className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition"
                      >
                        <RotateCw className="w-3.5 h-3.5" />
                      </button>
                      <button
                        title="Stop"
                        onClick={() => handleAction(svc.unit, 'stop')}
                        className="p-1.5 rounded-lg bg-slate-800 hover:bg-rose-950/60 text-slate-300 hover:text-rose-400 transition"
                      >
                        <Square className="w-3.5 h-3.5" />
                      </button>
                      <button
                        title="Journal Logs"
                        onClick={() =>
                          setSelectedLogs(
                            `journalctl -u ${svc.unit} -n 50 --no-pager\n-- Logs begin at Mon 2026-10-05 02:00:01 UTC --\n[INFO] [${svc.unit}] Service entered running state\n[INFO] [${svc.unit}] Initialization completed without warnings.\n[INFO] [${svc.unit}] Listening on unix socket /run/${svc.unit.replace('.service', '')}.sock`
                          )
                        }
                        className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-emerald-400 transition"
                      >
                        <FileText className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Logs Modal */}
      {selectedLogs && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <FileText className="w-4 h-4 text-emerald-400" />
                Journal Logs
              </h2>
              <button
                onClick={() => setSelectedLogs(null)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto max-h-96 whitespace-pre-wrap">
              {selectedLogs}
            </pre>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedLogs(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
