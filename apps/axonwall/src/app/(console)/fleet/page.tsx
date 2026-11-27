'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { PluginDisabledGate } from '@/components/PluginDisabledGate';
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
import { getCurrentDesiredState } from '@/server/agent';
import {
  blockFleetTargetAction,
  getLiveFleetSatellitesAction,
  triggerFleetSyncAction,
  unblockFleetTargetAction,
  type LiveFleetSatellite,
} from '@/server/fleet';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import { mergeSatelliteNodesForPersist } from '@/lib/state-preservation';
import {
  buildFleetZtpSnippets,
  isValidInterfaceName,
  isValidNodeId,
} from '@/lib/shell-quote';

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
  role: 'satellite' | 'edge-ngfw';
  skuProfile?: 'sku-x86-intel-n100-i226' | 'sku-x86-enterprise-10g-25g' | 'sku-vm-virtio' | 'sku-arm64-router' | 'generic-edge';
  fastpathOffload?: boolean;
  wanInterface?: string;
  lanInterface?: string;
  arch: 'mipsle' | 'arm64' | 'amd64' | 'armv7' | 'unknown';
  os: string;
  ip: string;
  tunnelIp: string;
  wgConnected: boolean;
  status: 'online' | 'offline' | 'enrolling' | 'degraded';
  cpuPercent: number;
  memPercent: number;
  activeConns: number;
  offloadedConns: number;
  pid1Mode: boolean;
  uptimeSeconds: number;
  wifiRadios: WifiRadioInfo[];
  wifiClients: number;
  lastSeen: string;
  activePolicyVersion: number;
}

// N4: there is no per-node token generation. The hub validates the
// presented token against its single shared AXONWALL_ZTP_TOKEN, so the
// modal holds a paste of that hub token — a locally generated token would
// always be rejected with 401. The token is never persisted here.

function formatUptime(seconds: number): string {
  if (!seconds || seconds <= 0) return '—';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${mins}m`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function FleetPageContent() {
  const [satellites, setSatellites] = useState<SatelliteNodeView[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [listenPort, setListenPort] = useState(2966);
  const [heartbeatIntervalSec, setHeartbeatIntervalSec] = useState(30);
  const [watchdogTimeoutSec, setWatchdogTimeoutSec] = useState(60);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'online' | 'enrolling' | 'degraded' | 'offline'>('ALL');
  const [selectedSat, setSelectedSat] = useState<SatelliteNodeView | null>(null);
  const [isZtpModalOpen, setIsZtpModalOpen] = useState(false);
  const [hubZtpToken, setHubZtpToken] = useState('');
  const [newNodeId, setNewNodeId] = useState('');
  const [newNodeName, setNewNodeName] = useState('');
  const [newNodeRole, setNewNodeRole] = useState<'edge-ngfw' | 'satellite'>('edge-ngfw');
  const [newNodeSku, setNewNodeSku] = useState<'sku-vm-virtio' | 'sku-x86-intel-n100-i226' | 'sku-x86-enterprise-10g-25g' | 'sku-arm64-router'>('sku-vm-virtio');
  const [newNodeArch, setNewNodeArch] = useState<'amd64' | 'arm64' | 'mipsle' | 'armv7'>('amd64');
  const [newNodeWan, setNewNodeWan] = useState('eth0');
  const [newNodeLan, setNewNodeLan] = useState('eth1');
  const [newNodeFastpath, setNewNodeFastpath] = useState(true);
  const [copied, setCopied] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  // D16: persist failures used to be silently swallowed, leaving the UI
  // showing a change as applied when it was not.
  const [saveError, setSaveError] = useState<string | null>(null);
  const [hubHostname, setHubHostname] = useState('127.0.0.1');
  const [controllerStatus, setControllerStatus] = useState<{
    reachable: boolean;
    error?: string;
    liveCount: number;
  }>({ reachable: false, liveCount: 0 });
  const [syncNotice, setSyncNotice] = useState<string | null>(null);
  const [blockTarget, setBlockTarget] = useState('');
  const [blockTtl, setBlockTtl] = useState(300);
  const [blockReason, setBlockReason] = useState('Central operator block');
  const [blockSubmitting, setBlockSubmitting] = useState(false);

  useEffect(() => {
    if (typeof window !== 'undefined' && window.location.hostname) {
      setHubHostname(window.location.hostname);
    }
  }, []);

  const loadFleetState = useCallback(async () => {
    try {
      const [state, liveRes] = await Promise.all([
        getCurrentDesiredState(),
        getLiveFleetSatellitesAction().catch((err: any) => ({
          reachable: false,
          error: err?.message || 'Controller unreachable',
          data: undefined,
        })),
      ]);
      if (state.fleet) {
        setListenPort(state.fleet.listenPort ?? 2966);
        setHeartbeatIntervalSec(state.fleet.defaultHeartbeatIntervalSec ?? 30);
        setWatchdogTimeoutSec(state.fleet.watchdogTimeoutSec ?? 60);
      }

      const liveSats = liveRes.reachable ? liveRes.data?.satellites ?? [] : [];
      const liveById = new Map<string, LiveFleetSatellite>(liveSats.map((ls) => [ls.id, ls]));
      setControllerStatus({
        reachable: liveRes.reachable,
        error: liveRes.error,
        liveCount: liveSats.length,
      });

      const nodes = state.fleet?.nodes ?? [];
      const seen = new Set<string>();
      const loaded: SatelliteNodeView[] = nodes.map((s) => {
        seen.add(s.id);
        const live = liveById.get(s.id);
        const wifiRadios: WifiRadioInfo[] = (s.wifi ?? []).map((w) => ({
          radio: w.radio,
          ssid: w.ssid,
          channel: w.channel,
          security: w.security ?? 'wpa3-sae',
          clientsCount: w.clientsCount ?? 0,
          enabled: w.enabled ?? true,
        }));
        const role = live?.role ?? s.role ?? 'satellite';
        const isLiveOnline = Boolean(live && !live.disconnectedAt);
        return {
          id: s.id,
          name: s.name,
          role,
          skuProfile: (live?.skuProfile as SatelliteNodeView['skuProfile']) ?? s.skuProfile,
          fastpathOffload: live?.fastpathOffload ?? s.fastpathOffload ?? true,
          wanInterface: live?.wanInterface || s.wanInterface || 'eth0',
          lanInterface: live?.lanInterface || s.lanInterface || 'eth1',
          arch: (live?.arch as SatelliteNodeView['arch']) ?? s.arch ?? 'unknown',
          os: s.os || (role === 'edge-ngfw' ? 'AxonWall Edge UKI (PID 1 Go)' : 'Linux'),
          ip: live?.ip || s.ip || '—',
          tunnelIp: live?.wireguard?.tunnelIp || live?.tunnelIp || s.wireguard?.tunnelIp || '—',
          wgConnected: isLiveOnline || Boolean(s.wireguard?.connected || s.status === 'online'),
          status: isLiveOnline
            ? live?.lastApplyError
              ? 'degraded'
              : 'online'
            : live?.disconnectedAt
              ? 'offline'
              : s.status ?? 'enrolling',
          cpuPercent: live?.metrics?.cpuUsagePercent ?? s.metrics?.cpuUsagePercent ?? 0,
          memPercent: live?.metrics?.memUsagePercent ?? s.metrics?.memUsagePercent ?? 0,
          activeConns: live?.metrics?.activeConns ?? s.metrics?.activeConns ?? 0,
          offloadedConns: s.metrics?.offloadedConns ?? 0,
          pid1Mode: live?.metrics?.pid1Mode ?? s.metrics?.pid1Mode ?? role === 'edge-ngfw',
          uptimeSeconds: live?.metrics?.uptimeSeconds ?? s.metrics?.uptimeSeconds ?? 0,
          wifiRadios,
          wifiClients: wifiRadios.reduce((sum, w) => sum + (w.clientsCount || 0), 0),
          lastSeen: live?.lastSeen || s.lastSeen || 'Never',
          activePolicyVersion: s.activePolicyVersion ?? 1,
        };
      });

      for (const live of liveSats) {
        if (seen.has(live.id)) continue;
        const role = live.role ?? 'satellite';
        const isLiveOnline = !live.disconnectedAt;
        loaded.push({
          id: live.id,
          name: live.id,
          role,
          skuProfile: live.skuProfile as SatelliteNodeView['skuProfile'],
          fastpathOffload: live.fastpathOffload ?? true,
          wanInterface: live.wanInterface || 'eth0',
          lanInterface: live.lanInterface || 'eth1',
          arch: (live.arch as SatelliteNodeView['arch']) || 'unknown',
          os: role === 'edge-ngfw' ? 'AxonWall Edge UKI (PID 1 Go)' : 'Linux',
          ip: live.ip || '—',
          tunnelIp: live.wireguard?.tunnelIp || live.tunnelIp || '—',
          wgConnected: isLiveOnline,
          status: isLiveOnline ? (live.lastApplyError ? 'degraded' : 'online') : 'offline',
          cpuPercent: live.metrics?.cpuUsagePercent ?? 0,
          memPercent: live.metrics?.memUsagePercent ?? 0,
          activeConns: live.metrics?.activeConns ?? 0,
          offloadedConns: 0,
          pid1Mode: live.metrics?.pid1Mode ?? role === 'edge-ngfw',
          uptimeSeconds: live.metrics?.uptimeSeconds ?? 0,
          wifiRadios: [],
          wifiClients: 0,
          lastSeen: live.lastSeen || 'Just now',
          activePolicyVersion: 1,
        });
      }

      setLoadError(null);
      setSatellites(loaded);
      setSelectedSat((prev) => {
        if (prev) {
          const updated = loaded.find((item) => item.id === prev.id);
          if (updated) return updated;
        }
        return loaded[0] ?? null;
      });
    } catch (err: any) {
      // Keep current state on transient error, but block writes so stale/empty state cannot wipe fleet.nodes.
      setLoadError(err?.message || 'Failed to load fleet state.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  const { applyState } = useDesiredStateApply({
    onConfigChanged: () => {
      void loadFleetState();
    },
  });

  useEffect(() => {
    loadFleetState();
  }, [loadFleetState]);

  const persistSatellites = async (nextSatellites: SatelliteNodeView[]): Promise<boolean> => {
    if (loadError) {
      setSaveError('Cannot save fleet changes while fleet state failed to load. Retry loading first.');
      return false;
    }
    setIsSaving(true);
    setSaveError(null);
    try {
      const state = await getCurrentDesiredState();
      const mergedNodes = mergeSatelliteNodesForPersist(state.fleet?.nodes, nextSatellites);
      const applyRes = await applyState({
        ...state,
        fleet: {
          ...(state.fleet ?? {}),
          enabled: state.fleet?.enabled ?? true,
          listenPort: state.fleet?.listenPort ?? listenPort,
          defaultHeartbeatIntervalSec: state.fleet?.defaultHeartbeatIntervalSec ?? heartbeatIntervalSec,
          watchdogTimeoutSec: state.fleet?.watchdogTimeoutSec ?? watchdogTimeoutSec,
          nodes: mergedNodes,
        },
      });
      if (!applyRes.success) {
        throw new Error(applyRes.message || 'Failed to save fleet changes.');
      }
      setSatellites(nextSatellites);
      setSelectedSat((prev) => {
        if (prev) {
          return nextSatellites.find((n) => n.id === prev.id) ?? nextSatellites[0] ?? null;
        }
        return nextSatellites[0] ?? null;
      });
      return true;
    } catch (err: any) {
      // D16: surface persist failures instead of silently dropping them —
      // the local list is left unchanged so the UI never shows a change
      // as applied when it was not.
      setSaveError(err?.message || 'Failed to save fleet changes.');
      return false;
    } finally {
      setIsSaving(false);
    }
  };

  const handleSyncFleetToYaml = async () => {
    if (loadError) return;
    setSyncNotice(null);
    const saved = await persistSatellites(satellites);
    if (!saved) return;
    const syncRes = await triggerFleetSyncAction().catch(() => null);
    const syncedCount =
      (syncRes?.data as { syncedSatellites?: number; syncedCount?: number } | undefined)?.syncedSatellites ??
      syncRes?.data?.syncedCount ??
      satellites.length;
    if (syncRes?.reachable && (!syncRes.status || syncRes.status < 400)) {
      setSyncNotice(`Synced desired state to live controller (${syncedCount} nodes).`);
    } else if (syncRes && !syncRes.reachable) {
      setSyncNotice('Saved fleet.yaml locally (controller daemon offline — push skipped).');
    } else if (syncRes?.error) {
      setSyncNotice(`Saved locally; controller sync warning: ${syncRes.error}`);
    }
    await loadFleetState();
  };

  // D16: allocate the first tunnel octet not already in use by a live
  // node, instead of list length + 2. Length-based allocation collided
  // after a removal: removing a node shrank the list, so the next
  // enrollment reused an octet still held by a remaining node.
  const allocateTunnelIp = (existing: SatelliteNodeView[]): string => {
    const used = new Set(
      existing
        .map((s) => s.tunnelIp.match(/^10\.99\.0\.(\d+)\/24$/)?.[1])
        .filter((o): o is string => o !== undefined)
        .map(Number)
    );
    for (let octet = 2; octet <= 254; octet++) {
      if (!used.has(octet)) return `10.99.0.${octet}/24`;
    }
    throw new Error('No free WireGuard tunnel addresses remain in 10.99.0.0/24.');
  };

  const handleEnrollNode = async () => {
    const cleanId = newNodeId.trim() || `${newNodeRole === 'edge-ngfw' ? 'edge-ngfw' : 'sat-node'}-${satellites.length + 1}`;
    const cleanName = newNodeName.trim() || cleanId;
    if (!isValidNodeId(cleanId)) {
      alert('Invalid Node ID: use 1-64 characters from [a-zA-Z0-9._-] without spaces, quotes, or newlines.');
      return;
    }
    const cleanWan = newNodeWan.trim() || 'eth0';
    const cleanLan = newNodeLan.trim() || 'eth1';
    if (!isValidInterfaceName(cleanWan) || !isValidInterfaceName(cleanLan)) {
      alert('Invalid WAN/LAN interface name.');
      return;
    }
    if (satellites.some((s) => s.id === cleanId)) {
      alert(`Satellite node ID "${cleanId}" is already registered.`);
      return;
    }
    let tunnelIp: string;
    try {
      tunnelIp = allocateTunnelIp(satellites);
    } catch (err: any) {
      alert(err?.message || 'Could not allocate a tunnel IP.');
      return;
    }
    const created: SatelliteNodeView = {
      id: cleanId,
      name: cleanName,
      role: newNodeRole,
      skuProfile: newNodeRole === 'edge-ngfw' ? newNodeSku : 'generic-edge',
      fastpathOffload: newNodeFastpath,
      wanInterface: newNodeWan.trim() || 'eth0',
      lanInterface: newNodeLan.trim() || 'eth1',
      arch: newNodeRole === 'edge-ngfw' && newNodeSku === 'sku-arm64-router' ? 'arm64' : newNodeArch,
      os: newNodeRole === 'edge-ngfw' ? `AxonWall Edge UKI (${newNodeSku})` : 'Linux Edge Appliance',
      ip: '—',
      tunnelIp,
      wgConnected: false,
      status: 'enrolling',
      cpuPercent: 0,
      memPercent: 0,
      activeConns: 0,
      offloadedConns: 0,
      pid1Mode: newNodeRole === 'edge-ngfw',
      uptimeSeconds: 0,
      wifiRadios: [],
      wifiClients: 0,
      lastSeen: 'Awaiting ZTP handshake',
      activePolicyVersion: 1,
    };
    const nextList = [...satellites, created];
    const saved = await persistSatellites(nextList);
    if (!saved) return;
    setSelectedSat(created);
    setNewNodeId('');
    setNewNodeName('');
    setIsZtpModalOpen(false);
  };

  const handleRemoveNode = async (id: string) => {
    if (loadError) return;
    const nextList = satellites.filter((s) => s.id !== id);
    await persistSatellites(nextList);
  };

  const handlePushPolicy = async (id: string) => {
    if (loadError) return;
    const nextList = satellites.map((s) =>
      s.id === id ? { ...s, activePolicyVersion: s.activePolicyVersion + 1 } : s
    );
    const saved = await persistSatellites(nextList);
    if (!saved) return;
    const syncRes = await triggerFleetSyncAction(id).catch(() => null);
    if (syncRes?.reachable && (!syncRes.status || syncRes.status < 400)) {
      setSyncNotice(`Pushed policy update to ${id}.`);
    } else if (syncRes?.error) {
      setSyncNotice(`Updated policy version for ${id}; controller offline/warn: ${syncRes.error}`);
    }
  };

  const handleQuarantine = async (id: string) => {
    if (loadError) return;
    const nextList = satellites.map((s) =>
      s.id === id ? { ...s, status: 'degraded' as const, wgConnected: false } : s
    );
    await persistSatellites(nextList);
  };

  const handleFleetBlock = async (mode: 'block' | 'unblock') => {
    const target = blockTarget.trim();
    if (!target) return;
    setBlockSubmitting(true);
    setSyncNotice(null);
    try {
      const res =
        mode === 'block'
          ? await blockFleetTargetAction(target, blockTtl, blockReason)
          : await unblockFleetTargetAction(target, blockReason);
      if (res.reachable && (!res.status || res.status < 400)) {
        setSyncNotice(
          `${mode === 'block' ? 'Blocked' : 'Unblocked'} ${target} across active fleet satellites.`
        );
        setBlockTarget('');
      } else {
        setSyncNotice(res.error || `Fleet ${mode} failed (controller unreachable)`);
      }
    } finally {
      setBlockSubmitting(false);
    }
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

  const ztpSnippets = buildFleetZtpSnippets({
    hubHostname,
    listenPort,
    nodeId: newNodeId,
    nodeRole: newNodeRole,
    nodeSku: newNodeSku,
    wanInterface: newNodeWan,
    lanInterface: newNodeLan,
    ztpToken: hubZtpToken,
  });

  const handleCopyZtp = () => {
    if (!ztpSnippets.ok) return;
    navigator.clipboard.writeText(
      newNodeRole === 'edge-ngfw' ? ztpSnippets.cloudInitSnippet : ztpSnippets.bootstrapCommand
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
            <span
              className={`px-2 py-0.5 text-xs font-semibold rounded-full border ${
                controllerStatus.reachable
                  ? 'bg-sky-500/10 text-sky-300 border-sky-500/30'
                  : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
              }`}
              title={controllerStatus.error || 'Axonwall Controller WebSocket & REST status'}
            >
              {controllerStatus.reachable
                ? `Controller Live (${controllerStatus.liveCount} connected)`
                : 'Controller Offline / Degraded'}
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Centralized orchestration, zero-touch provisioning (ZTP), and distributed nftables microsegmentation across remote edge routers and access points.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              setHubZtpToken('');
              setIsZtpModalOpen(true);
            }}
            disabled={Boolean(loadError) || isLoading}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-emerald-500 text-slate-950 font-semibold text-sm hover:bg-emerald-400 transition shadow-lg shadow-emerald-500/20 cursor-pointer disabled:opacity-50"
          >
            <Plus className="w-4 h-4" />
            Enroll Satellite (ZTP)
          </button>
          <button
            onClick={handleSyncFleetToYaml}
            disabled={isSaving || Boolean(loadError) || isLoading}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 font-medium text-sm hover:bg-slate-700 transition cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isSaving ? 'animate-spin' : ''}`} />
            {isSaving ? 'Syncing Fleet...' : 'Sync All Nodes'}
          </button>
        </div>
      </div>

      {loadError && (
        <div className="p-4 rounded-xl border text-xs font-medium bg-rose-500/10 border-rose-500/30 text-rose-300 flex items-center justify-between gap-3">
          <span>
            Failed to load fleet configuration ({loadError}). Fleet modifications are disabled until state reloads cleanly.
          </span>
          <button
            type="button"
            onClick={() => void loadFleetState()}
            className="px-2.5 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 border border-rose-500/40 shrink-0 cursor-pointer"
          >
            Retry Load
          </button>
        </div>
      )}

      {syncNotice && (
        <div className="p-3.5 rounded-xl border text-xs font-medium bg-sky-500/10 border-sky-500/30 text-sky-200 flex items-center justify-between">
          <span>{syncNotice}</span>
          <button onClick={() => setSyncNotice(null)} className="text-slate-400 hover:text-white">
            ×
          </button>
        </div>
      )}

      {/* Fleet-Wide Live Block / Unblock Action Bar */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-wrap items-center gap-3">
        <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
          <ShieldAlert className="w-4 h-4 text-amber-400" />
          Fleet XDP/NFT Mitigation
        </span>
        <input
          type="text"
          value={blockTarget}
          onChange={(e) => setBlockTarget(e.target.value)}
          placeholder="Target IPv4/IPv6 or MAC (e.g. 203.0.113.50)"
          className="flex-1 min-w-[220px] px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-white"
        />
        <input
          type="number"
          min={60}
          max={86400}
          value={blockTtl}
          onChange={(e) => setBlockTtl(Number(e.target.value) || 300)}
          title="Block TTL (seconds)"
          className="w-24 px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-white"
        />
        <input
          type="text"
          value={blockReason}
          onChange={(e) => setBlockReason(e.target.value)}
          placeholder="Audit reason"
          className="w-52 px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white"
        />
        <button
          type="button"
          disabled={!blockTarget.trim() || blockSubmitting}
          onClick={() => void handleFleetBlock('block')}
          className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-40 text-white text-xs font-semibold cursor-pointer"
        >
          Block Fleet-Wide
        </button>
        <button
          type="button"
          disabled={!blockTarget.trim() || blockSubmitting}
          onClick={() => void handleFleetBlock('unblock')}
          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 border border-slate-700 text-xs font-semibold cursor-pointer"
        >
          Unblock
        </button>
      </div>

      {/* D16: fleet save failures are surfaced here instead of swallowed. */}
      {saveError && (
        <div className="p-4 rounded-xl border text-xs font-medium bg-rose-500/10 border-rose-500/30 text-rose-300 flex items-center justify-between">
          <span>Fleet changes were NOT saved: {saveError}</span>
          <button onClick={() => setSaveError(null)} className="text-slate-400 hover:text-white">
            ×
          </button>
        </div>
      )}

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
                            {sat.role === 'edge-ngfw' && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                                UKI NGFW
                              </span>
                            )}
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
                              title="Bump policy version (local record only — nothing is pushed to the node)"
                              disabled={Boolean(loadError) || isSaving}
                              onClick={() => handlePushPolicy(sat.id)}
                              className="p-1.5 rounded-lg text-slate-400 hover:text-emerald-400 hover:bg-slate-800 transition cursor-pointer disabled:opacity-40"
                            >
                              <RefreshCw className="w-4 h-4" />
                            </button>
                            <button
                              title="Mark degraded (local record only — the WireGuard tunnel stays up)"
                              disabled={Boolean(loadError) || isSaving}
                              onClick={() => handleQuarantine(sat.id)}
                              className="p-1.5 rounded-lg text-slate-400 hover:text-amber-400 hover:bg-slate-800 transition cursor-pointer disabled:opacity-40"
                            >
                              <ShieldAlert className="w-4 h-4" />
                            </button>
                            <button
                              title="Remove Satellite"
                              disabled={Boolean(loadError) || isSaving}
                              onClick={() => handleRemoveNode(sat.id)}
                              className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-slate-800 transition cursor-pointer disabled:opacity-40"
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
                {selectedSat.role === 'edge-ngfw' && (
                  <span className="px-2 py-0.5 rounded text-xs font-semibold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                    Super-Slim Edge NGFW (Single-File EFI UKI)
                  </span>
                )}
              </h2>
              <div className="flex flex-wrap items-center gap-2 mt-1">
                <span className="text-xs text-slate-400 font-mono">
                  ID: {selectedSat.id} | Arch: {selectedSat.arch} | Tunnel: {selectedSat.tunnelIp}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  Policy rev: v{selectedSat.activePolicyVersion}
                </span>
                {selectedSat.skuProfile && selectedSat.skuProfile !== 'generic-edge' && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                    SKU: {selectedSat.skuProfile}
                  </span>
                )}
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                title="Bump policy version in the local fleet record only — nothing is pushed to the node"
                disabled={Boolean(loadError) || isSaving}
                onClick={() => handlePushPolicy(selectedSat.id)}
                className="px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20 rounded-lg text-xs font-semibold transition cursor-pointer disabled:opacity-40"
              >
                Bump policy version
              </button>
              <button
                title="Mark degraded in the local fleet record only — the WireGuard tunnel stays up"
                disabled={Boolean(loadError) || isSaving}
                onClick={() => handleQuarantine(selectedSat.id)}
                className="px-3 py-1.5 bg-amber-500/10 border border-amber-500/20 text-amber-400 hover:bg-amber-500/20 rounded-lg text-xs font-semibold transition cursor-pointer disabled:opacity-40"
              >
                Mark degraded
              </button>
              <button
                disabled={Boolean(loadError) || isSaving}
                onClick={() => handleRemoveNode(selectedSat.id)}
                className="px-3 py-1.5 bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 rounded-lg text-xs font-semibold transition cursor-pointer disabled:opacity-40"
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
                {selectedSat.role === 'edge-ngfw'
                  ? `nf_flowtable fastpath: ${selectedSat.fastpathOffload !== false ? 'Enabled' : 'Disabled'} (${selectedSat.wanInterface || 'eth0'} ↔ ${selectedSat.lanInterface || 'eth1'})`
                  : `Watchdog Timer: ${watchdogTimeoutSec}s`}
              </div>
            </div>

            {selectedSat.role === 'edge-ngfw' ? (
              <div className="p-3.5 rounded-lg bg-slate-950/60 border border-cyan-500/20">
                <div className="text-xs font-medium text-cyan-300 flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-cyan-400" />
                  Hardened Monolithic UKI Posture
                </div>
                <div className="text-sm font-semibold text-white mt-1">
                  PID 1 Static Go (/init) • CONFIG_MODULES=n
                </div>
                <div className="text-[11px] text-slate-400 mt-0.5">
                  Zero /bin/sh • Zero glibc • Diskless RAM-only Streamer
                </div>
              </div>
            ) : (
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
            )}

            <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
              <div className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                Kernel Uptime & Conntrack
              </div>
              <div className="text-sm font-semibold text-white mt-1">
                {formatUptime(selectedSat.uptimeSeconds)}
              </div>
              <div className="text-[11px] text-slate-500 mt-0.5">
                {selectedSat.activeConns} active flows ({selectedSat.offloadedConns || 0} HW/SW offloaded)
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ZTP Enrollment Modal */}
      {isZtpModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-5 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2.5">
                <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                  <Plus className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white">Enroll Edge NGFW or Satellite (ZTP)</h3>
                  <p className="text-xs text-slate-400">
                    Provision a Super-Slim Single-File EFI UKI NGFW (PID 1 Go) or a standard OpenWrt/Linux satellite
                  </p>
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
              <div>
                <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider block mb-1.5">
                  Appliance Role & Operating Mode
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  <button
                    type="button"
                    onClick={() => setNewNodeRole('edge-ngfw')}
                    className={`p-3 rounded-xl border text-left transition cursor-pointer ${
                      newNodeRole === 'edge-ngfw'
                        ? 'bg-cyan-500/10 border-cyan-500/40 text-white'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="text-xs font-bold text-cyan-300">Super-Slim Edge NGFW (Single-File EFI UKI)</div>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      Custom monolithic kernel (CONFIG_MODULES=n) + static Go PID 1 (/init). Zero local storage.
                    </div>
                  </button>
                  <button
                    type="button"
                    onClick={() => setNewNodeRole('satellite')}
                    className={`p-3 rounded-xl border text-left transition cursor-pointer ${
                      newNodeRole === 'satellite'
                        ? 'bg-emerald-500/10 border-emerald-500/40 text-white'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="text-xs font-bold text-emerald-300">Branch / Wireless Satellite</div>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      Runs on existing OpenWrt, Alpine, or Debian routers with optional Wi-Fi AP telemetry.
                    </div>
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider block mb-1">
                    Node ID
                  </label>
                  <input
                    type="text"
                    placeholder={newNodeRole === 'edge-ngfw' ? 'edge-ngfw-01' : 'sat-branch-01'}
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
                    placeholder={newNodeRole === 'edge-ngfw' ? 'Perimeter Edge NGFW' : 'Branch Edge Router'}
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
                    <option value="amd64">amd64</option>
                    <option value="arm64">arm64</option>
                    <option value="mipsle">mipsle</option>
                    <option value="armv7">armv7</option>
                  </select>
                </div>
              </div>

              {newNodeRole === 'edge-ngfw' && (
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3.5 rounded-xl bg-slate-950/70 border border-slate-800">
                  <div className="sm:col-span-3">
                    <label className="text-xs font-semibold text-cyan-300 uppercase tracking-wider block mb-1">
                      Manufacturing Hardware SKU Profile (Monolithic Kernel)
                    </label>
                    <select
                      value={newNodeSku}
                      onChange={(e) =>
                        setNewNodeSku(
                          e.target.value as
                            | 'sku-x86-intel-n100-i226'
                            | 'sku-x86-enterprise-10g-25g'
                            | 'sku-vm-virtio'
                            | 'sku-arm64-router'
                        )
                      }
                      className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                    >
                      <option value="sku-vm-virtio">
                        sku-vm-virtio (Default — Minimalist KVM / QEMU / Proxmox / Cloud VirtIO, GOAMD64=v1)
                      </option>
                      <option value="sku-x86-intel-n100-i226">
                        sku-x86-intel-n100-i226 (Intel N100/N305 + i225/i226 2.5GbE, GOAMD64=v3)
                      </option>
                      <option value="sku-x86-enterprise-10g-25g">
                        sku-x86-enterprise-10g-25g (1U Xeon/EPYC + X520/X710/E810/ConnectX-6, GOAMD64=v3)
                      </option>
                      <option value="sku-arm64-router">
                        sku-arm64-router (MediaTek Filogic / Marvell Armada DSA, GOARCH=arm64)
                      </option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[11px] font-semibold text-slate-400 uppercase block mb-1">
                      WAN Interface
                    </label>
                    <input
                      type="text"
                      value={newNodeWan}
                      onChange={(e) => setNewNodeWan(e.target.value)}
                      className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200"
                    />
                  </div>
                  <div>
                    <label className="text-[11px] font-semibold text-slate-400 uppercase block mb-1">
                      LAN Interface
                    </label>
                    <input
                      type="text"
                      value={newNodeLan}
                      onChange={(e) => setNewNodeLan(e.target.value)}
                      className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200"
                    />
                  </div>
                  <div className="flex items-end pb-1">
                    <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={newNodeFastpath}
                        onChange={(e) => setNewNodeFastpath(e.target.checked)}
                        className="rounded border-slate-700 bg-slate-900 text-cyan-500"
                      />
                      <span>Enable nf_flowtable Fastpath</span>
                    </label>
                  </div>
                </div>
              )}

              <div>
                <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider block mb-1.5">
                  Hub ZTP Enrollment Token (shared)
                </label>
                <input
                  type="text"
                  value={hubZtpToken}
                  onChange={(e) => setHubZtpToken(e.target.value.trim())}
                  placeholder="Paste the hub's AXONWALL_ZTP_TOKEN"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm font-mono text-emerald-400 placeholder:text-slate-600"
                />
                <p className="text-xs text-amber-300/90 mt-1.5">
                  Paste the token configured on the hub (<code className="font-mono">AXONWALL_ZTP_TOKEN</code>).
                  The hub rejects any other value with 401 — a token generated here would never work.
                  The token is used only in the snippet below and is never stored.
                  {hubZtpToken === '' && ' Paste the hub token before copying the snippet.'}
                </p>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider block mb-1.5">
                  {newNodeRole === 'edge-ngfw'
                    ? 'Autonomous Cloud-Init User-Data (#cloud-config for Proxmox / KVM / AWS / GCP)'
                    : 'Bootstrapping Command (Run on edge device)'}
                </label>
                {!ztpSnippets.ok ? (
                  <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-xs text-rose-300">
                    {ztpSnippets.error}
                  </div>
                ) : (
                  <>
                    <div className="relative">
                      <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap break-all">
                        {newNodeRole === 'edge-ngfw'
                          ? ztpSnippets.cloudInitSnippet
                          : ztpSnippets.bootstrapCommand}
                      </pre>
                      <button
                        onClick={handleCopyZtp}
                        className="absolute top-2 right-2 p-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs flex items-center gap-1 border border-slate-700 cursor-pointer"
                      >
                        {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copied ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    {newNodeRole === 'edge-ngfw' && (
                      <div className="mt-2">
                        <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                          Or Custom Single-File EFI UKI Builder Command (6.4 MB BOOTX64.EFI)
                        </label>
                        <pre className="p-2.5 bg-slate-950/60 border border-slate-800/80 rounded-lg text-[11px] font-mono text-slate-400 overflow-x-auto whitespace-pre-wrap break-all">
                          {ztpSnippets.bootstrapCommand}
                        </pre>
                      </div>
                    )}
                  </>
                )}
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
                disabled={isSaving || Boolean(loadError)}
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

export default function FleetPage() {
  return (
    <PluginDisabledGate pluginId="fleet-controller">
      <FleetPageContent />
    </PluginDisabledGate>
  );
}
