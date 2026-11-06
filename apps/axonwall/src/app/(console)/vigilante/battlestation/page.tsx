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
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';

interface TelemetryEvent {
  source: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  rule: string;
  srcIp?: string;
  destIp?: string;
  time: string;
}

export default function BattleStationPage() {
  // C2: the config saves below go through saveVigilanteConfigAction, which
  // applies state server-side — pass the load-time fingerprint so a
  // same-slice cross-tab change is refused instead of overwritten.
  const { getFingerprint, refreshFingerprint } = useDesiredStateApply();
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
      try {
        const blocked = await getSoarBlockedIPsAction();
        setBlockedIPs(blocked);
      } catch {}
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  // Telemetry stream initialized empty until real alerts arrive
  useEffect(() => {
    setEvents([]);
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

  const handleContainIP = async (ip: string) => {
    if (!ip.trim()) return;
    setStatusBanner(null);

    const res = await soarBlockIPAction(ip.trim(), blockTimeout);
    if (res.success) {
      setStatusBanner({ type: 'success', message: res.message });
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
    const fingerprint = getFingerprint();
    const res = await saveVigilanteConfigAction(
      { posture },
      fingerprint ? { expectedFingerprint: fingerprint } : undefined
    );
    if (res.success) {
      await refreshFingerprint();
      setConfig({ ...config, posture });
      setStatusBanner({ type: 'success', message: `Defense posture changed to ${posture.toUpperCase()}` });
    } else {
      setStatusBanner({ type: 'error', message: res.message });
    }
  };

  const handleLdapAuthChange = async (
    patch: Partial<NonNullable<VigilanteConfig['ldapAuth']>>
  ) => {
    if (!config) return;
    setStatusBanner(null);
    const nextLdapAuth = {
      enabled: config.ldapAuth?.enabled ?? true,
      autoProvisionPrincipals: config.ldapAuth?.autoProvisionPrincipals ?? true,
      allowLocalBreakGlass: config.ldapAuth?.allowLocalBreakGlass ?? true,
      defaultRole: config.ldapAuth?.defaultRole ?? 'viewer',
      syncModuleSso: config.ldapAuth?.syncModuleSso ?? true,
      ...patch,
    };
    const fingerprint = getFingerprint();
    const res = await saveVigilanteConfigAction(
      { ldapAuth: nextLdapAuth },
      fingerprint ? { expectedFingerprint: fingerprint } : undefined
    );
    if (res.success) {
      await refreshFingerprint();
      setConfig({ ...config, ldapAuth: nextLdapAuth });
      setStatusBanner({
        type: 'success',
        message: 'Updated Vigilante OpenLDAP Directory & SOC RBAC integration settings.',
      });
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
            <AlertTriangle className="w-4 h-4 text-slate-500" />
          </div>
          <div className="text-2xl font-bold text-slate-400">Unknown</div>
          <div className="text-[11px] text-slate-500">No live threat feed connected</div>
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
            <Radio className="w-4 h-4 text-slate-500" />
          </div>
          <div className="text-2xl font-bold text-slate-400">—</div>
          <div className="text-[11px] text-slate-500">See Deception page for live count</div>
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
                <Activity className="w-4 h-4 text-slate-400" />
                <span className="text-white font-semibold text-sm">Threat Telemetry</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 text-[11px] font-semibold">
                  Feed not connected
                </span>
              </div>
            </div>

            <div className="space-y-2">
              {events.length === 0 && (
                <div className="p-4 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
                  No telemetry feed connected — no live sensor data is reaching
                  this page. An empty list here means &ldquo;no data&rdquo;, not
                  &ldquo;no threats&rdquo;.
                </div>
              )}
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
                        onClick={() => handleContainIP(evt.srcIp!)}
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

          {/* Local OpenLDAP Directory & SOC RBAC Integration Card */}
          <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2.5">
                <Lock className="w-4 h-4 text-cyan-400" />
                <div>
                  <div className="text-white font-semibold text-sm">
                    Local OpenLDAP Directory & SOC RBAC Integration
                  </div>
                  <div className="text-xs text-slate-400">
                    Dedicated service bind (<span className="font-mono text-cyan-300">cn=svc-vigilante,ou=services</span>) and 14-permission CASL role mapping via <span className="font-mono text-slate-300">/etc/axonwall/ldap-plugins/vigilante.json</span>
                  </div>
                </div>
              </div>
              <span
                className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider border ${
                  (config?.ldapAuth?.enabled ?? true)
                    ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                    : 'bg-slate-800 text-slate-400 border-slate-700'
                }`}
              >
                {(config?.ldapAuth?.enabled ?? true) ? 'OpenLDAP Active' : 'OpenLDAP Disabled'}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <label className="flex items-center justify-between p-3 bg-slate-950/70 border border-slate-800 rounded-xl cursor-pointer">
                <div>
                  <div className="font-medium text-slate-200">Enable OpenLDAP Authentication</div>
                  <div className="text-[11px] text-slate-500">Authenticate SOC analysts against local slapd</div>
                </div>
                <input
                  type="checkbox"
                  checked={config?.ldapAuth?.enabled ?? true}
                  onChange={(e) => handleLdapAuthChange({ enabled: e.target.checked })}
                  className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
                />
              </label>

              <label className="flex items-center justify-between p-3 bg-slate-950/70 border border-slate-800 rounded-xl cursor-pointer">
                <div>
                  <div className="font-medium text-slate-200">JIT Principal Auto-Provisioning</div>
                  <div className="text-[11px] text-slate-500">Sync LDAP UID & groups into Vigilante authz.yaml</div>
                </div>
                <input
                  type="checkbox"
                  checked={config?.ldapAuth?.autoProvisionPrincipals ?? true}
                  onChange={(e) => handleLdapAuthChange({ autoProvisionPrincipals: e.target.checked })}
                  className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
                />
              </label>

              <label className="flex items-center justify-between p-3 bg-slate-950/70 border border-slate-800 rounded-xl cursor-pointer">
                <div>
                  <div className="font-medium text-slate-200">Allow Break-Glass Local Fallback</div>
                  <div className="text-[11px] text-slate-500">Permit local token/password if slapd is unreachable</div>
                </div>
                <input
                  type="checkbox"
                  checked={config?.ldapAuth?.allowLocalBreakGlass ?? true}
                  onChange={(e) => handleLdapAuthChange({ allowLocalBreakGlass: e.target.checked })}
                  className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
                />
              </label>

              <label className="flex items-center justify-between p-3 bg-slate-950/70 border border-slate-800 rounded-xl cursor-pointer">
                <div>
                  <div className="font-medium text-slate-200">Propagate K3s Module SSO</div>
                  <div className="text-[11px] text-slate-500">Sync vigilante-ldap-sso to Vigil-SOC, OpenSearch & Wazuh</div>
                </div>
                <input
                  type="checkbox"
                  checked={config?.ldapAuth?.syncModuleSso ?? true}
                  onChange={(e) => handleLdapAuthChange({ syncModuleSso: e.target.checked })}
                  className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
                />
              </label>
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-slate-950/70 border border-slate-800 rounded-xl text-xs">
              <div>
                <div className="font-medium text-slate-200">Default Fallback CASL Role</div>
                <div className="text-[11px] text-slate-500">Assigned when an authenticated LDAP user matches no explicit SOC group</div>
              </div>
              <select
                value={config?.ldapAuth?.defaultRole ?? 'viewer'}
                onChange={(e) =>
                  handleLdapAuthChange({
                    defaultRole: e.target.value as 'owner' | 'admin' | 'operator' | 'viewer',
                  })
                }
                className="px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-white focus:outline-none focus:border-cyan-500"
              >
                <option value="viewer">viewer (Read-Only SOC Auditor)</option>
                <option value="operator">operator (SOC Analyst & Threat Hunter)</option>
                <option value="admin">admin (SOC Administrator)</option>
                <option value="owner">owner (Full Platform Owner)</option>
              </select>
            </div>

            <div className="overflow-x-auto border border-slate-800 rounded-xl">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="py-2 px-3 font-medium">OpenLDAP POSIX Group</th>
                    <th className="py-2 px-3 font-medium">GID</th>
                    <th className="py-2 px-3 font-medium">Vigilante CASL Role</th>
                    <th className="py-2 px-3 font-medium">Granted Capabilities</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70 text-slate-300">
                  <tr>
                    <td className="py-2 px-3 font-mono text-cyan-300">axonwall-admin</td>
                    <td className="py-2 px-3 font-mono text-slate-400">10000</td>
                    <td className="py-2 px-3 font-semibold text-rose-300">owner</td>
                    <td className="py-2 px-3 text-slate-400">All 14 SOC permissions + Principal & Owner Management</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 font-mono text-cyan-300">vigilante-admin</td>
                    <td className="py-2 px-3 font-mono text-slate-400">10230</td>
                    <td className="py-2 px-3 font-semibold text-amber-300">admin</td>
                    <td className="py-2 px-3 text-slate-400">All 14 SOC permissions (Cluster, Modules, Scans, Forensics, CTF)</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 font-mono text-cyan-300">axonwall-operator / vigilante-operator</td>
                    <td className="py-2 px-3 font-mono text-slate-400">10001 / 10231</td>
                    <td className="py-2 px-3 font-semibold text-emerald-300">operator</td>
                    <td className="py-2 px-3 text-slate-400">Deploy Modules, Run Scans/Forensics/Simulations, Manage CTF</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 font-mono text-cyan-300">axonwall-readonly / vigilante-readonly</td>
                    <td className="py-2 px-3 font-mono text-slate-400">10002 / 10232</td>
                    <td className="py-2 px-3 font-semibold text-slate-300">viewer</td>
                    <td className="py-2 px-3 text-slate-400">Read-Only Cluster, Modules, Scans, Telemetry, Forensics & CTF</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
