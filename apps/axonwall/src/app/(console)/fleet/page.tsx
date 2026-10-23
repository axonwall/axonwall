'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Radio,
  Server,
  Wifi,
  Shield,
  ShieldAlert,
  RefreshCw,
  Plus,
  Activity,
  CheckCircle2,
  Copy,
  Flame,
  Search,
  Trash2,
} from 'lucide-react';
import { MeshGraph } from './MeshGraph';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';

interface WifiRadioInfo {
  radio: string;
  ssid: string;
  channel?: number;
  security: 'wpa2-psk' | 'wpa3-sae' | 'wpa3-enterprise' | 'open';
  clientsCount: number;
  enabled: boolean;
}

interface SatelliteNodeView {
  id: string;
  name: string;
  arch: 'mipsle' | 'arm64' | 'amd64' | 'armv7' | 'unknown';
  os: string;
  ip: string;
  tunnelIp: string;
  wgConnected: boolean;
  status: 'online' | 'offline' | 'enrolling' | 'degraded';
  cpuPercent: number;
  memPercent: number;
  activeConns: number;
  uptimeSeconds: number;
  wifiRadios: WifiRadioInfo[];
  wifiClients: number;
  lastSeen: string;
  activePolicyVersion: number;
}

const generateZtpToken = (): string =>
  'ztp_axon_' +
  Array.from(crypto.getRandomValues(new Uint8Array(12)), (b) => b.toString(16).padStart(2, '0')).join('');

function formatUptime(seconds: number): string {
  if (!seconds || seconds <= 0) return '—';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${mins}m`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

export default function FleetPage() {
  const [satellites, setSatellites] = useState<SatelliteNodeView[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [listenPort, setListenPort] = useState(2966);
  const [heartbeatIntervalSec, setHeartbeatIntervalSec] = useState(30);
  const [watchdogTimeoutSec, setWatchdogTimeoutSec] = useState(60);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'online' | 'enrolling' | 'degraded' | 'offline'>('ALL');
  const [selectedSat, setSelectedSat] = useState<SatelliteNodeView | null>(null);
  const [isZtpModalOpen, setIsZtpModalOpen] = useState(false);
  const [generatedToken, setGeneratedToken] = useState('');
  const [newNodeId, setNewNodeId] = useState('');
  const [newNodeName, setNewNodeName] = useState('');
  const [newNodeArch, setNewNodeArch] = useState<'amd64' | 'arm64' | 'mipsle' | 'armv7'>('arm64');
  const [copied, setCopied] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [hubHostname, setHubHostname] = useState('127.0.0.1');

  useEffect(() => {
    if (typeof window !== 'undefined' && window.location.hostname) {
      setHubHostname(window.location.hostname);
    }
  }, []);

  const loadFleetState = useCallback(async () => {
    try {
      const state = await getCurrentDesiredState();
      if (state.fleet) {
        setListenPort(state.fleet.listenPort ?? 2966);
        setHeartbeatIntervalSec(state.fleet.defaultHeartbeatIntervalSec ?? 30);
        setWatchdogTimeoutSec(state.fleet.watchdogTimeoutSec ?? 60);
      }
      const nodes = state.fleet?.nodes ?? [];
      const loaded: SatelliteNodeView[] = nodes.map((s) => {
        const wifiRadios: WifiRadioInfo[] = (s.wifi ?? []).map((w) => ({
          radio: w.radio,
          ssid: w.ssid,
          channel: w.channel,
          security: w.security ?? 'wpa3-sae',
          clientsCount: w.clientsCount ?? 0,
          enabled: w.enabled ?? true,
        }));
        return {
          id: s.id,
          name: s.name,
          arch: s.arch ?? 'unknown',
          os: s.os || 'Linux',
          ip: s.ip || '—',
          tunnelIp: s.wireguard?.tunnelIp || '—',
          wgConnected: Boolean(s.wireguard?.connected || s.status === 'online'),
          status: s.status ?? 'enrolling',
          cpuPercent: s.metrics?.cpuUsagePercent ?? 0,
          memPercent: s.metrics?.memUsagePercent ?? 0,
          activeConns: s.metrics?.activeConns ?? 0,
          uptimeSeconds: s.metrics?.uptimeSeconds ?? 0,
          wifiRadios,
          wifiClients: wifiRadios.reduce((sum, w) => sum + (w.clientsCount || 0), 0),
          lastSeen: s.lastSeen || 'Never',
          activePolicyVersion: s.activePolicyVersion ?? 1,
        };
      });
      setSatellites(loaded);
      setSelectedSat((prev) => {
        if (prev) {
          const updated = loaded.find((item) => item.id === prev.id);
          if (updated) return updated;
        }
        return loaded[0] ?? null;
      });
    } catch {
      // Keep current state on transient error
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadFleetState();
  }, [loadFleetState]);

  const persistSatellites = async (nextSatellites: SatelliteNodeView[]) => {
    setIsSaving(true);
    try {
      const state = await getCurrentDesiredState();
      await applyDesiredState({
        ...state,
        fleet: {
          enabled: true,
          listenPort: state.fleet?.listenPort ?? listenPort,
          defaultHeartbeatIntervalSec: state.fleet?.defaultHeartbeatIntervalSec ?? heartbeatIntervalSec,
          watchdogTimeoutSec: state.fleet?.watchdogTimeoutSec ?? watchdogTimeoutSec,
          nodes: nextSatellites.map((s, idx) => ({
            id: s.id,
            name: s.name,
            arch: s.arch,
            os: s.os,
            ip: s.ip === '—' ? '127.0.0.1' : s.ip,
            lastSeen: s.lastSeen === 'Never' ? undefined : s.lastSeen,
            status: s.status,
            wireguard: {
              tunnelIp: s.tunnelIp === '—' ? `10.99.0.${idx + 2}/24` : s.tunnelIp,
              connected: s.wgConnected,
            },
            wifi: s.wifiRadios,
            metrics: {
              cpuUsagePercent: s.cpuPercent,
              memUsagePercent: s.memPercent,
              uptimeSeconds: s.uptimeSeconds,
              activeConns: s.activeConns,
              rxBytesTotal: 0,
              txBytesTotal: 0,
            },
            activePolicyVersion: s.activePolicyVersion,
          })),
        },
      });
      setSatellites(nextSatellites);
      setSelectedSat((prev) => {
        if (prev) {
          return nextSatellites.find((n) => n.id === prev.id) ?? nextSatellites[0] ?? null;
        }
        return nextSatellites[0] ?? null;
      });
    } catch {
      // Ignore apply errors in UI
    } finally {
      setIsSaving(false);
    }
  };

  const handleSyncFleetToYaml = async () => {
    await persistSatellites(satellites);
  };

  const handleEnrollNode = async () => {
    const cleanId = newNodeId.trim() || `sat-node-${satellites.length + 1}`;
    const cleanName = newNodeName.trim() || cleanId;
    if (satellites.some((s) => s.id === cleanId)) {
      alert(`Satellite node ID "${cleanId}" is already registered.`);
      return;
    }
    const nextTunnelOctet = Math.min(254, satellites.length + 2);
    const created: SatelliteNodeView = {
      id: cleanId,
      name: cleanName,
      arch: newNodeArch,
      os: 'Linux Edge Appliance',
      ip: '—',
      tunnelIp: `10.99.0.${nextTunnelOctet}/24`,
      wgConnected: false,
      status: 'enrolling',
      cpuPercent: 0,
      memPercent: 0,
      activeConns: 0,
      uptimeSeconds: 0,
      wifiRadios: [],
      wifiClients: 0,
      lastSeen: 'Awaiting ZTP handshake',
      activePolicyVersion: 1,
    };
    const nextList = [...satellites, created];
    await persistSatellites(nextList);
    setSelectedSat(created);
    setNewNodeId('');
    setNewNodeName('');
    setIsZtpModalOpen(false);
  };

  const handleRemoveNode = async (id: string) => {
    const nextList = satellites.filter((s) => s.id !== id);
    await persistSatellites(nextList);
  };

  const handlePushPolicy = async (id: string) => {
    const nextList = satellites.map((s) =>
      s.id === id ? { ...s, activePolicyVersion: s.activePolicyVersion + 1 } : s
    );
    await persistSatellites(nextList);
  };

  const handleQuarantine = async (id: string) => {
    const nextList = satellites.map((s) =>
      s.id === id ? { ...s, status: 'degraded' as const, wgConnected: false } : s
    );
    await persistSatellites(nextList);
  };

  const filtered = satellites.filter((s) => {
    if (statusFilter !== 'ALL' && s.status !== statusFilter) {
      return false;
    }
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      s.name.toLowerCase().includes(q) ||
      s.id.toLowerCase().includes(q) ||
      s.ip.toLowerCase().includes(q) ||
      s.tunnelIp.toLowerCase().includes(q) ||
      s.os.toLowerCase().includes(q)
    );
  });

  const onlineCount = satellites.filter((s) => s.status === 'online').length;
  const wgConnectedCount = satellites.filter((s) => s.wgConnected).length;
  const totalWifiClients = satellites.reduce((acc, s) => acc + s.wifiClients, 0);
  const wifiApCount = satellites.filter((s) => s.wifiRadios.some((r) => r.enabled)).length;

  const bootstrapNodeId = newNodeId.trim() || 'sat-node-$(cat /sys/class/net/eth0/address | tr -d \':\')';
  const bootstrapCommand = `./axonwall-satellite \\\n  -core wss://${hubHostname}:${listenPort}/ws/satellite \\\n  -id ${bootstrapNodeId} \\\n  -token ${generatedToken}`;

  const handleCopyZtp = () => {
    navigator.clipboard.writeText(
      `./axonwall-satellite -core wss://${hubHostname}:${listenPort}/ws/satellite -id ${bootstrapNodeId} -token ${generatedToken}`
    );
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
              <Radio className="w-6 h-6 text-emerald-400" />
              Fleet & Satellites (SD-Branch)
            </h1>
            <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              OpenWrt & Linux Ready
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Centralized orchestration, zero-touch provisioning (ZTP), and distributed nftables microsegmentation across remote edge routers and access points.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              setGeneratedToken(generateZtpToken());
              setIsZtpModalOpen(true);
            }}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-emerald-500 text-slate-950 font-semibold text-sm hover:bg-emerald-400 transition shadow-lg shadow-emerald-500/20 cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            Enroll Satellite (ZTP)
          </button>
          <button
            onClick={handleSyncFleetToYaml}
            disabled={isSaving}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 font-medium text-sm hover:bg-slate-700 transition cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isSaving ? 'animate-spin' : ''}`} />
            {isSaving ? 'Saving to ha.yaml...' : 'Sync All Nodes'}
          </button>
        </div>
      </div>

      {/* Overview Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Edge Nodes</div>
            <div className="text-2xl font-bold text-white mt-1">{satellites.length}</div>
            <div className="text-xs text-emerald-400 mt-0.5">
              {satellites.length === 0 ? 'No satellites enrolled' : `${onlineCount} Online & Active`}
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Server className="w-5 h-5" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">WireGuard SD-WAN</div>
            <div className="text-2xl font-bold text-white mt-1">
              {wgConnectedCount} / {satellites.length}
            </div>
            <div className="text-xs text-slate-400 mt-0.5">
              {satellites.length === 0 ? 'No Active Tunnels' : 'Full Hub-and-Spoke Mesh'}
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <Radio className="w-5 h-5" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Edge Wi-Fi Clients</div>
            <div className="text-2xl font-bold text-white mt-1">{totalWifiClients}</div>
            <div className="text-xs text-slate-400 mt-0.5">
              {wifiApCount > 0
                ? `Across ${wifiApCount} AP${wifiApCount === 1 ? '' : 's'}`
                : 'No Active Wireless APs'}
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
            <Wifi className="w-5 h-5" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Edge Watchdog</div>
            <div className="text-2xl font-bold text-white mt-1">{watchdogTimeoutSec}s</div>
            <div className="text-xs text-emerald-400 mt-0.5">
              Heartbeat every {heartbeatIntervalSec}s
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
            <Shield className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* SD-WAN Topology Visualization */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800">
        <h2 className="text-lg font-bold text-white mb-4">WireGuard SD-WAN Full Mesh Topology</h2>
        <MeshGraph
          nodes={satellites.map((s) => ({
            id: s.id,
            label: s.name,
            isDegraded: s.status === 'degraded' || s.status === 'offline',
          }))}
        />
      </div>

      {/* Main Content Area: Search & Satellites Table */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search by satellite ID, name, IP or OS..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-slate-400 font-medium mr-1">Status Filter:</span>
            {(['ALL', 'online', 'enrolling', 'degraded', 'offline'] as const).map((status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={`px-2.5 py-1 rounded-full text-xs font-medium transition cursor-pointer uppercase ${
                  statusFilter === status
                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    : 'bg-slate-800/80 text-slate-400 border border-slate-700/60 hover:text-slate-200'
                }`}
              >
                {status}
              </button>
            ))}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <tr>
                  <th className="px-4 py-3">Satellite Node</th>
                  <th className="px-4 py-3">Architecture & OS</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">WireGuard Tunnel</th>
                  <th className="px-4 py-3">Telemetry (CPU / RAM)</th>
                  <th className="px-4 py-3">Edge Clients</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {isLoading ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center text-slate-400 text-sm">
                      Loading fleet state...
                    </td>
                  </tr>
                ) : satellites.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center">
                      <div className="flex flex-col items-center justify-center space-y-2">
                        <Server className="w-8 h-8 text-slate-600" />
                        <div className="text-sm font-semibold text-slate-300">
                          No Satellite Nodes Enrolled
                        </div>
                        <p className="text-xs text-slate-500 max-w-md">
                          No remote edge appliances are currently registered in <code className="text-slate-400">/etc/axonwall/ha.yaml</code>. Click &ldquo;Enroll Satellite (ZTP)&rdquo; to generate a bootstrap token and register your first node.
                        </p>
                      </div>
                    </td>
                  </tr>
                ) : filtered.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-slate-500 text-sm">
                      No satellite nodes match the current search or status filter.
                    </td>
                  </tr>
                ) : (
                  filtered.map((sat) => {
                    const isSelected = selectedSat?.id === sat.id;
                    return (
                      <tr
                        key={sat.id}
                        onClick={() => setSelectedSat(sat)}
                        className={`cursor-pointer transition hover:bg-slate-800/40 ${
                          isSelected ? 'bg-slate-800/60' : ''
                        }`}
                      >
                        <td className="px-4 py-3.5">
                          <div className="font-medium text-white flex items-center gap-2">
                            {sat.name}
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                              v{sat.activePolicyVersion}
                            </span>
                          </div>
                          <div className="text-xs text-slate-400 font-mono mt-0.5">
                            {sat.id}
                          </div>
                        </td>

                        <td className="px-4 py-3.5">
                          <div className="flex items-center gap-1.5">
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-800 border border-slate-700 text-slate-300 uppercase">
                              {sat.arch}
                            </span>
                            <span className="text-xs text-slate-300">{sat.os}</span>
                          </div>
                          <div className="text-xs text-slate-500 font-mono mt-0.5">{sat.ip}</div>
                        </td>

                        <td className="px-4 py-3.5">
                          {sat.status === 'online' ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                              Online
                            </span>
                          ) : sat.status === 'enrolling' ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                              Enrolling
                            </span>
                          ) : sat.status === 'offline' ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
                              <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
                              Offline
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
                              <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                              Degraded
                            </span>
                          )}
                          <div className="text-[11px] text-slate-500 mt-0.5">{sat.lastSeen}</div>
                        </td>

                        <td className="px-4 py-3.5">
                          <div className="font-mono text-xs text-cyan-400 font-medium">{sat.tunnelIp}</div>
                          <div className="text-xs text-slate-500 mt-0.5">
                            {sat.wgConnected ? 'Mesh: wg-axon0 (Connected)' : 'Mesh: wg-axon0 (Standby)'}
                          </div>
                        </td>

                        <td className="px-4 py-3.5">
                          <div className="flex items-center gap-3">
                            <div>
                              <div className="text-xs text-slate-300">CPU {sat.cpuPercent}%</div>
                              <div className="w-16 h-1.5 bg-slate-800 rounded-full mt-1 overflow-hidden">
                                <div
                                  className={`h-full rounded-full ${
                                    sat.cpuPercent > 80 ? 'bg-red-500' : 'bg-emerald-500'
                                  }`}
                                  style={{ width: `${Math.min(100, sat.cpuPercent)}%` }}
                                />
                              </div>
                            </div>
                            <div>
                              <div className="text-xs text-slate-300">RAM {sat.memPercent}%</div>
                              <div className="w-16 h-1.5 bg-slate-800 rounded-full mt-1 overflow-hidden">
                                <div
                                  className="h-full rounded-full bg-cyan-500"
                                  style={{ width: `${Math.min(100, sat.memPercent)}%` }}
                                />
                              </div>
                            </div>
                          </div>
                          <div className="text-[11px] text-slate-500 mt-1">{sat.activeConns} flows</div>
                        </td>

                        <td className="px-4 py-3.5">
                          {sat.wifiClients > 0 ? (
                            <div className="flex items-center gap-1.5 text-xs text-purple-400 font-medium">
                              <Wifi className="w-3.5 h-3.5" />
                              {sat.wifiClients} Wi-Fi Clients
                            </div>
                          ) : (
                            <span className="text-xs text-slate-500">Wired Only</span>
                          )}
                        </td>

                        <td className="px-4 py-3.5 text-right">
                          <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                            <button
                              title="Push Policy"
                              onClick={() => handlePushPolicy(sat.id)}
                              className="p-1.5 rounded-lg text-slate-400 hover:text-emerald-400 hover:bg-slate-800 transition cursor-pointer"
                            >
                              <RefreshCw className="w-4 h-4" />
                            </button>
                            <button
                              title="Quarantine"
                              onClick={() => handleQuarantine(sat.id)}
                              className="p-1.5 rounded-lg text-slate-400 hover:text-amber-400 hover:bg-slate-800 transition cursor-pointer"
                            >
                              <ShieldAlert className="w-4 h-4" />
                            </button>
                            <button
                              title="Remove Satellite"
                              onClick={() => handleRemoveNode(sat.id)}
                              className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-slate-800 transition cursor-pointer"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Selected Satellite Detail Inspector */}
      {selectedSat && (
        <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Radio className="w-5 h-5 text-emerald-400" />
                Edge Node Inspector: {selectedSat.name}
              </h2>
              <div className="flex flex-wrap items-center gap-2 mt-1">
                <span className="text-xs text-slate-400 font-mono">
                  ID: {selectedSat.id} | Arch: {selectedSat.arch} | Tunnel: {selectedSat.tunnelIp}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  Policy rev: v{selectedSat.activePolicyVersion}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handlePushPolicy(selectedSat.id)}
                className="px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20 rounded-lg text-xs font-semibold transition cursor-pointer"
              >
                Sync nftables
              </button>
              <button
                onClick={() => handleQuarantine(selectedSat.id)}
                className="px-3 py-1.5 bg-amber-500/10 border border-amber-500/20 text-amber-400 hover:bg-amber-500/20 rounded-lg text-xs font-semibold transition cursor-pointer"
              >
                Isolate Node
              </button>
              <button
                onClick={() => handleRemoveNode(selectedSat.id)}
                className="px-3 py-1.5 bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 rounded-lg text-xs font-semibold transition cursor-pointer"
              >
                Remove
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
            <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
              <div className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
                <Flame className="w-3.5 h-3.5 text-orange-400" />
                Active nftables Ruleset
              </div>
              <div className="text-sm font-semibold text-white mt-1">
                Policy v{selectedSat.activePolicyVersion} (atomic)
              </div>
              <div className="text-[11px] text-slate-500 mt-0.5">
                Watchdog Timer: {watchdogTimeoutSec}s
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
              <div className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
                <Wifi className="w-3.5 h-3.5 text-purple-400" />
                Wireless Radios (mac80211)
              </div>
              <div className="text-sm font-semibold text-white mt-1">
                {selectedSat.wifiRadios.length > 0
                  ? `${selectedSat.wifiRadios.length} SSID${selectedSat.wifiRadios.length === 1 ? '' : 's'} Configured`
                  : 'No Wi-Fi Radios'}
              </div>
              <div className="text-[11px] text-slate-500 mt-0.5">
                {selectedSat.wifiClients} Connected Clients
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
              <div className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                Kernel Uptime & Health
              </div>
              <div className="text-sm font-semibold text-white mt-1">
                {formatUptime(selectedSat.uptimeSeconds)}
              </div>
              <div className="text-[11px] text-slate-500 mt-0.5">
                {selectedSat.activeConns} conntrack sessions
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ZTP Enrollment Modal */}
      {isZtpModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 space-y-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2.5">
                <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                  <Plus className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white">Enroll New Satellite (ZTP)</h3>
                  <p className="text-xs text-slate-400">Zero-Touch Provisioning bootstrap for OpenWrt or Linux</p>
                </div>
              </div>
              <button
                onClick={() => setIsZtpModalOpen(false)}
                className="text-slate-400 hover:text-white text-sm cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider block mb-1">
                    Node ID
                  </label>
                  <input
                    type="text"
                    placeholder="sat-branch-01"
                    value={newNodeId}
                    onChange={(e) => setNewNodeId(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider block mb-1">
                    Display Name
                  </label>
                  <input
                    type="text"
                    placeholder="Branch Edge Router"
                    value={newNodeName}
                    onChange={(e) => setNewNodeName(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider block mb-1">
                    Architecture
                  </label>
                  <select
                    value={newNodeArch}
                    onChange={(e) => setNewNodeArch(e.target.value as 'amd64' | 'arm64' | 'mipsle' | 'armv7')}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
                  >
                    <option value="arm64">arm64</option>
                    <option value="amd64">amd64</option>
                    <option value="mipsle">mipsle</option>
                    <option value="armv7">armv7</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider block mb-1.5">
                  One-Time Enrollment Token
                </label>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    readOnly
                    value={generatedToken}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm font-mono text-emerald-400"
                  />
                  <button
                    onClick={() => {
                      setGeneratedToken(generateZtpToken());
                    }}
                    className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg border border-slate-700 cursor-pointer"
                  >
                    Regenerate
                  </button>
                </div>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider block mb-1.5">
                  Bootstrapping Command (Run on edge device)
                </label>
                <div className="relative">
                  <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 overflow-x-auto">
                    {bootstrapCommand}
                  </pre>
                  <button
                    onClick={handleCopyZtp}
                    className="absolute top-2 right-2 p-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs flex items-center gap-1 border border-slate-700 cursor-pointer"
                  >
                    {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2 border-t border-slate-800">
              <button
                onClick={() => setIsZtpModalOpen(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium rounded-lg cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleEnrollNode}
                disabled={isSaving}
                className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-sm font-semibold rounded-lg cursor-pointer disabled:opacity-50"
              >
                {isSaving ? 'Registering...' : 'Register Node in Fleet'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
