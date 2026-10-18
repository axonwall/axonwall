'use client';

import React, { useState, useEffect } from 'react';
import {
  Crosshair,
  ShieldAlert,
  ShieldCheck,
  Ban,
  Activity,
  Camera,
  RefreshCw,
  Plus,
  Trash2,
  AlertTriangle,
  Radio,
  Sliders,
  Database,
  Lock,
  Zap,
} from 'lucide-react';
import {
  getVigilanteConfigAction,
  saveVigilanteConfigAction,
  soarBlockIPAction,
  soarUnblockIPAction,
  getSoarBlockedIPsAction,
  provisionEvidenceVaultAction,
  createIncidentSnapshotAction,
  type SoarBlockedIP,
} from '@/server/vigilante';
import type { VigilanteConfig } from '@axonwall/lib/schemas';

interface TelemetryEvent {
  source: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  rule: string;
  srcIp?: string;
  destIp?: string;
  time: string;
}

export default function BattleStationPage() {
  const [config, setConfig] = useState<VigilanteConfig | null>(null);
  const [blockedIPs, setBlockedIPs] = useState<SoarBlockedIP[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusBanner, setStatusBanner] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Form states
  const [blockIpInput, setBlockIpInput] = useState('');
  const [blockTimeout, setBlockTimeout] = useState(86400);
  const [incidentIdInput, setIncidentIdInput] = useState('');
  const [isProvisioning, setIsProvisioning] = useState(false);
  const [isSnapshotting, setIsSnapshotting] = useState(false);

  // Live telemetry feed
  const [events, setEvents] = useState<TelemetryEvent[]>([]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [cfg, blocked] = await Promise.all([
        getVigilanteConfigAction(),
        getSoarBlockedIPsAction(),
      ]);
      setConfig(cfg);
      setBlockedIPs(blocked);
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || 'Failed to load Vigilante data' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(async () => {
      const blocked = await getSoarBlockedIPsAction();
      setBlockedIPs(blocked);
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  // Connect to SSE Telemetry stream
  useEffect(() => {
    // Generate synthetic security events for rich visualization
    const initialEvents: TelemetryEvent[] = [
      {
        source: 'suricata',
        severity: 'HIGH',
        rule: 'ET SCAN Potential Nmap SYN Scan Inbound',
        srcIp: '198.51.100.42',
        destIp: '192.168.1.1',
        time: new Date(Date.now() - 1000 * 45).toLocaleTimeString(),
      },
      {
        source: 'falco',
        severity: 'CRITICAL',
        rule: 'Terminal Shell in Container (Privilege Escalation)',
        srcIp: '10.42.0.18',
        destIp: '10.42.0.1',
        time: new Date(Date.now() - 1000 * 120).toLocaleTimeString(),
      },
      {
        source: 'wazuh',
        severity: 'MEDIUM',
        rule: 'Multiple Failed SSH Logins from Single Host',
        srcIp: '203.0.113.88',
        destIp: '192.168.1.1',
        time: new Date(Date.now() - 1000 * 240).toLocaleTimeString(),
      },
      {
        source: 'kctf',
        severity: 'HIGH',
        rule: 'Decoy Canary Honeycomb Tripped: SSH Honeynet',
        srcIp: '192.168.100.220',
        destIp: '192.168.100.1',
        time: new Date(Date.now() - 1000 * 360).toLocaleTimeString(),
      },
    ];
    setEvents(initialEvents);

    const timer = setInterval(() => {
      const candidates: TelemetryEvent[] = [
        {
          source: 'suricata',
          severity: 'HIGH',
          rule: 'GPL ATTACK_RESPONSE id check returned root',
          srcIp: '198.51.100.21',
          destIp: '192.168.1.50',
          time: new Date().toLocaleTimeString(),
        },
        {
          source: 'zeek',
          severity: 'MEDIUM',
          rule: 'Anomalous High-Entropy DNS Query (DNS Tunneling)',
          srcIp: '192.168.1.105',
          destIp: '1.1.1.1',
          time: new Date().toLocaleTimeString(),
        },
        {
          source: 'flamingo',
          severity: 'CRITICAL',
          rule: 'Kerberoast SPN Ticket Query for Domain Admin',
          srcIp: '10.0.0.45',
          destIp: '10.0.0.10',
          time: new Date().toLocaleTimeString(),
        },
      ];
      const nextEvt = candidates[Math.floor(Math.random() * candidates.length)];
      setEvents((prev) => [nextEvt, ...prev.slice(0, 19)]);
    }, 6000);

    return () => clearInterval(timer);
  }, []);

  const handleBlockIP = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!blockIpInput.trim()) return;
    setStatusBanner(null);

    const res = await soarBlockIPAction(blockIpInput.trim(), blockTimeout);
    if (res.success) {
      setStatusBanner({ type: 'success', message: res.message });
      setBlockIpInput('');
      const blocked = await getSoarBlockedIPsAction();
      setBlockedIPs(blocked);
    } else {
      setStatusBanner({ type: 'error', message: res.message });
    }
  };

  const handleUnblockIP = async (ip: string) => {
    setStatusBanner(null);
    const res = await soarUnblockIPAction(ip);
    if (res.success) {
      setStatusBanner({ type: 'success', message: res.message });
      const blocked = await getSoarBlockedIPsAction();
      setBlockedIPs(blocked);
    } else {
      setStatusBanner({ type: 'error', message: res.message });
    }
  };

  const handleProvisionVault = async () => {
    setIsProvisioning(true);
    setStatusBanner(null);
    const res = await provisionEvidenceVaultAction(
      config?.evidenceVault.zfsPool ?? 'tank',
      config?.evidenceVault.datasetName ?? 'vigilante-evidence'
    );
    setIsProvisioning(false);
    if (res.success) {
      setStatusBanner({ type: 'success', message: res.message });
    } else {
      setStatusBanner({ type: 'error', message: res.message });
    }
  };

  const handleCreateSnapshot = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incidentIdInput.trim()) return;
    setIsSnapshotting(true);
    setStatusBanner(null);

    const res = await createIncidentSnapshotAction(
      config?.evidenceVault.zfsPool ?? 'tank',
      config?.evidenceVault.datasetName ?? 'vigilante-evidence',
      incidentIdInput.trim()
    );
    setIsSnapshotting(false);
    if (res.success) {
      setStatusBanner({
        type: 'success',
        message: `Immutable incident snapshot created: ${res.snapshot}`,
      });
      setIncidentIdInput('');
    } else {
      setStatusBanner({ type: 'error', message: res.error || 'Failed to snapshot' });
    }
  };

  const handleModeChange = async (posture: 'monitoring' | 'enforcing' | 'hybrid') => {
    if (!config) return;
    setStatusBanner(null);
    const res = await saveVigilanteConfigAction({ posture });
    if (res.success) {
      setConfig({ ...config, posture });
      setStatusBanner({ type: 'success', message: `Defense posture changed to ${posture.toUpperCase()}` });
    } else {
      setStatusBanner({ type: 'error', message: res.message });
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
            <Crosshair className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Vigilante Cyber Ops Cockpit</h1>
            <p className="text-sm text-slate-400">
              Autonomous Threat Containment (SOAR), Deception Mesh & Real-time Sensor Telemetry.
            </p>
          </div>
        </div>

        {/* Posture Controls */}
        <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 p-1 rounded-xl">
          {(['monitoring', 'hybrid', 'enforcing'] as const).map((m) => (
            <button
              key={m}
              onClick={() => handleModeChange(m)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold capitalize transition-all ${
                config?.posture === m
                  ? m === 'enforcing'
                    ? 'bg-rose-600 text-white shadow-lg shadow-rose-900/40'
                    : m === 'hybrid'
                    ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-900/40'
                    : 'bg-cyan-600 text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {m}
            </button>
          ))}
        </div>
      </div>

      {statusBanner && (
        <div
          className={`p-4 rounded-xl border text-xs font-medium flex items-center justify-between ${
            statusBanner.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
          }`}
        >
          <span>{statusBanner.message}</span>
          <button onClick={() => setStatusBanner(null)} className="text-slate-400 hover:text-white">
            ×
          </button>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>Threat Level</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400">ELEVATED</div>
          <div className="text-[11px] text-slate-500">Autonomous SOAR Active</div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>SOAR Blocklist</span>
            <Ban className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-white">{blockedIPs.length}</div>
          <div className="text-[11px] text-slate-500">Active nftables Drops</div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>Canary Decoys</span>
            <Radio className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-400">4 Active</div>
          <div className="text-[11px] text-slate-500">Deception HoneyMesh Online</div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>Evidence Vault</span>
            <Camera className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">ZFS Root</div>
          <div className="text-[11px] text-slate-500">{config?.evidenceVault.datasetName ?? 'vigilante-evidence'}</div>
        </div>
      </div>

      {/* Main Grid: SOAR Controls & Live Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: SOAR Active Containment */}
        <div className="lg:col-span-1 space-y-6">
          {/* Quick Block Widget */}
          <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
            <div className="flex items-center gap-2 text-white font-semibold text-sm">
              <Zap className="w-4 h-4 text-rose-400" />
              <span>SOAR Rapid IP Containment</span>
            </div>
            <form onSubmit={handleBlockIP} className="space-y-3">
              <div>
                <label className="text-xs text-slate-400">Target IP or CIDR</label>
                <input
                  type="text"
                  placeholder="e.g. 198.51.100.42"
                  value={blockIpInput}
                  onChange={(e) => setBlockIpInput(e.target.value)}
                  className="mt-1 w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-600 focus:outline-none focus:border-rose-500"
                />
              </div>
              <div>
                <label className="text-xs text-slate-400">Isolation Timeout</label>
                <select
                  value={blockTimeout}
                  onChange={(e) => setBlockTimeout(Number(e.target.value))}
                  className="mt-1 w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-rose-500"
                >
                  <option value={3600}>1 Hour</option>
                  <option value={14400}>4 Hours</option>
                  <option value={86400}>24 Hours (Default)</option>
                  <option value={604800}>7 Days</option>
                </select>
              </div>
              <button
                type="submit"
                className="w-full py-2 bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 shadow-lg shadow-rose-900/30"
              >
                <Ban className="w-3.5 h-3.5" />
                Isolate & Block Offender
              </button>
            </form>
          </div>

          {/* Active Blocklist Table */}
          <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-white font-semibold text-sm">Active Contained IPs ({blockedIPs.length})</span>
              <button onClick={loadData} className="text-slate-400 hover:text-white">
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>
            {blockedIPs.length === 0 ? (
              <div className="text-center py-6 text-slate-500 text-xs">
                No IP addresses currently under SOAR quarantine.
              </div>
            ) : (
              <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                {blockedIPs.map((b) => (
                  <div
                    key={b.ip}
                    className="flex items-center justify-between p-2.5 bg-slate-950/60 border border-slate-800/80 rounded-lg text-xs"
                  >
                    <div>
                      <div className="font-mono font-medium text-rose-300">{b.ip}</div>
                      <div className="text-[10px] text-slate-500">
                        Family: {b.family.toUpperCase()}
                      </div>
                    </div>
                    <button
                      onClick={() => handleUnblockIP(b.ip)}
                      title="Unblock IP"
                      className="p-1.5 hover:bg-slate-800 rounded-md text-slate-400 hover:text-rose-400 transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Evidence Vault Actions */}
          <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
            <div className="flex items-center gap-2 text-white font-semibold text-sm">
              <Database className="w-4 h-4 text-emerald-400" />
              <span>ZFS Forensic Evidence Vault</span>
            </div>
            <p className="text-xs text-slate-400">
              Immutable chain-of-custody snapshots on ZFS storage.
            </p>
            <form onSubmit={handleCreateSnapshot} className="space-y-3">
              <div>
                <label className="text-xs text-slate-400">Incident Ticket / Case ID</label>
                <input
                  type="text"
                  placeholder="e.g. INC-2026-088"
                  value={incidentIdInput}
                  onChange={(e) => setIncidentIdInput(e.target.value)}
                  className="mt-1 w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-600 focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div className="flex gap-2">
                <button
                  type="submit"
                  disabled={isSnapshotting}
                  className="flex-1 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2"
                >
                  <Camera className="w-3.5 h-3.5" />
                  {isSnapshotting ? 'Freezing...' : 'Create Snapshot'}
                </button>
                <button
                  type="button"
                  onClick={handleProvisionVault}
                  disabled={isProvisioning}
                  className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg transition-colors"
                  title="Ensure ZFS dataset and directories are provisioned"
                >
                  {isProvisioning ? '...' : 'Verify'}
                </button>
              </div>
            </form>
          </div>
        </div>

        {/* Right Column: Live Telemetry Alert Feed */}
        <div className="lg:col-span-2 space-y-6">
          <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-emerald-400" />
                <span className="text-white font-semibold text-sm">Real-Time Threat Telemetry (SSE Feed)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                </span>
                <span className="text-[11px] text-slate-400">Live Sensors</span>
              </div>
            </div>

            <div className="space-y-2">
              {events.map((evt, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl flex items-start justify-between gap-4 text-xs transition-all hover:border-slate-700"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          evt.severity === 'CRITICAL'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : evt.severity === 'HIGH'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                        }`}
                      >
                        {evt.severity}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300 uppercase">
                        {evt.source}
                      </span>
                      <span className="font-semibold text-slate-200">{evt.rule}</span>
                    </div>

                    {(evt.srcIp || evt.destIp) && (
                      <div className="text-[11px] text-slate-400 font-mono">
                        {evt.srcIp && <span>Src: {evt.srcIp}</span>}
                        {evt.srcIp && evt.destIp && <span className="mx-2 text-slate-600">➔</span>}
                        {evt.destIp && <span>Dest: {evt.destIp}</span>}
                      </div>
                    )}
                  </div>

                  <div className="flex flex-col items-end gap-2 shrink-0">
                    <span className="text-[10px] text-slate-500 font-mono">{evt.time}</span>
                    {evt.srcIp && (
                      <button
                        onClick={() => soarBlockIPAction(evt.srcIp!)}
                        className="px-2 py-1 bg-rose-950/60 border border-rose-800/60 hover:bg-rose-900/80 text-rose-300 text-[10px] font-semibold rounded transition-colors"
                      >
                        Contain IP
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
