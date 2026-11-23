'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  Activity,
  AlertTriangle,
  ArrowLeftRight,
  Check,
  CheckCircle2,
  Copy,
  Database,
  ExternalLink,
  Eye,
  EyeOff,
  FileCode2,
  KeyRound,
  Layers,
  Loader2,
  Play,
  Plus,
  RefreshCw,
  Server,
  ShieldCheck,
  Trash2,
  Webhook,
  XCircle,
} from 'lucide-react';
import {
  compileLibreNmsBundle,
  resolveLibreNmsConfig,
} from '@axonwall/lib/compile/librenms';
import {
  disablePluginWithDependents,
  enablePluginWithDependencies,
} from '@axonwall/lib/plugins';
import {
  LibreNmsConfigSchema,
  type DesiredState,
  type LibreNmsConfig,
} from '@axonwall/lib/schemas';
import {
  getCurrentDesiredState,
  getLibreNmsCredentialsAction,
  getLibreNmsStatusAction,
  getLibreNmsTopologyAction,
  triggerLibreNmsNetBoxSyncAction,
  triggerLibreNmsSyncAction,
  type LibreNmsCredentialsSnapshot,
  type LibreNmsNetBoxSyncResultSnapshot,
  type LibreNmsStatusSnapshot,
  type LibreNmsSyncResultSnapshot,
  type LibreNmsTopologySnapshot,
} from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';

const TABS = [
  { id: 'overview', label: 'Overview & Enrollment' },
  { id: 'snmp', label: 'SNMP & Subnets' },
  { id: 'triad', label: 'NetBox Triad Bridge' },
  { id: 'credentials', label: 'LDAP, Secrets & Webhook' },
  { id: 'manifests', label: 'Compiled Configs' },
] as const;

export default function LibreNmsStudioPage() {
  const { applyState } = useDesiredStateApply();
  const [state, setState] = useState<DesiredState | null>(null);
  const [config, setConfig] = useState<LibreNmsConfig>(() => LibreNmsConfigSchema.parse({}));
  const [status, setStatus] = useState<LibreNmsStatusSnapshot | null>(null);
  const [topology, setTopology] = useState<LibreNmsTopologySnapshot | null>(null);
  const [syncResult, setSyncResult] = useState<LibreNmsSyncResultSnapshot | null>(null);
  const [triadResult, setTriadResult] = useState<LibreNmsNetBoxSyncResultSnapshot | null>(null);
  const [creds, setCreds] = useState<LibreNmsCredentialsSnapshot | null>(null);
  const [revealCreds, setRevealCreds] = useState(false);
  const [overwriteLabels, setOverwriteLabels] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<(typeof TABS)[number]['id']>('overview');
  const [saving, setSaving] = useState(false);
  const [syncingMode, setSyncingMode] = useState<'dry' | 'live' | null>(null);
  const [triadBusy, setTriadBusy] = useState<'preview' | 'push' | 'pull' | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadAll = useCallback(async (revealSecrets = false) => {
    setRefreshing(true);
    try {
      const [st, liveSt, credSnap, topoSnap] = await Promise.all([
        getCurrentDesiredState(),
        getLibreNmsStatusAction().catch(() => null),
        getLibreNmsCredentialsAction(revealSecrets).catch(() => null),
        getLibreNmsTopologyAction().catch(() => null),
      ]);
      setState(st);
      setConfig(resolveLibreNmsConfig(st));
      if (liveSt) {
        setStatus(liveSt);
        if (liveSt.lastSync) setSyncResult(liveSt.lastSync);
      }
      if (credSnap) setCreds(credSnap);
      if (topoSnap) setTopology(topoSnap);
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to load LibreNMS state',
      });
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void loadAll(false);
  }, [loadAll]);

  const previewCompiled = useMemo(() => {
    const draftState: Partial<DesiredState> = {
      ...(state ?? {}),
      librenms: config,
      plugins: config.enabled
        ? [
            ...(state?.plugins ?? []).filter((p) => p.id !== 'librenms' && (config.mode === 'external' || p.id !== 'core-k3s')),
            ...(config.mode === 'k3s' ? [{ id: 'core-k3s', enabled: true }] : []),
            { id: 'librenms', enabled: true },
          ]
        : (state?.plugins ?? []).map((p) => (p.id === 'librenms' ? { ...p, enabled: false } : p)),
    };
    return compileLibreNmsBundle(draftState);
  }, [state, config]);

  const handleSaveAndApply = async (enableOverride?: boolean) => {
    if (!state) return;
    setSaving(true);
    setBanner(null);
    try {
      const targetEnabled = enableOverride !== undefined ? enableOverride : config.enabled;
      const updatedCfg: LibreNmsConfig = { ...config, enabled: targetEnabled };
      let nextState: DesiredState = structuredClone(state);
      nextState.librenms = updatedCfg;
      if (targetEnabled) {
        const res = enablePluginWithDependencies('librenms', nextState);
        nextState = res.state;
        nextState.librenms = updatedCfg;
      } else {
        const res = disablePluginWithDependents('librenms', nextState);
        nextState = res.state;
        nextState.librenms = updatedCfg;
      }
      const applyRes = await applyState(nextState);
      setConfig(updatedCfg);
      setState(nextState);
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new Event('axonwall-capabilities-updated'));
      }
      setBanner({
        type: 'success',
        text: `Saved LibreNMS configuration to /etc/axonwall/services.yaml (${applyRes.message}).`,
      });
      await loadAll(revealCreds);
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to save LibreNMS config',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleEnrollSync = async (dryRun: boolean) => {
    setSyncingMode(dryRun ? 'dry' : 'live');
    setBanner(null);
    try {
      const res = await triggerLibreNmsSyncAction({ dryRun });
      setSyncResult(res);
      setBanner({
        type: res.success ? 'success' : 'error',
        text: res.success
          ? `${dryRun ? 'Dry-run preview' : 'Device enrollment'} complete: ${res.enrolled} enrolled, ${res.existing} already tracked (${res.subnets} discovery subnet(s)).`
          : res.error || 'LibreNMS device enrollment failed',
      });
      if (!dryRun) {
        await loadAll(revealCreds);
      }
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'LibreNMS device enrollment failed',
      });
    } finally {
      setSyncingMode(null);
    }
  };

  const handleTriadSync = async (action: 'preview' | 'push' | 'pull') => {
    setTriadBusy(action);
    setBanner(null);
    try {
      const res = await triggerLibreNmsNetBoxSyncAction({
        action,
        dryRun: action === 'preview',
        overwriteLabels,
      });
      setTriadResult(res);
      setBanner({
        type: res.success ? 'success' : 'error',
        text: res.success
          ? `Triad ${action.toUpperCase()} completed (${res.devicesQueued} device(s), ${res.cablesQueued} LLDP link(s)).`
          : res.error || `Triad ${action} failed`,
      });
      await loadAll(revealCreds);
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : `Triad ${action} failed`,
      });
    } finally {
      setTriadBusy(null);
    }
  };

  const handleCopy = async (key: string, val: string) => {
    try {
      await navigator.clipboard.writeText(val);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {}
  };

  const handleToggleReveal = async () => {
    const nextReveal = !revealCreds;
    setRevealCreds(nextReveal);
    const nextCreds = await getLibreNmsCredentialsAction(nextReveal).catch(() => null);
    if (nextCreds) setCreds(nextCreds);
  };

  const k3sHealthy = Boolean(status?.apiReachable || (status?.podReadyCount ?? 0) > 0);
  const combinedAlerts = topology?.alerts ?? [];
  const enrollmentTargets = status?.enrollmentPlan?.targets ?? previewCompiled.enrollmentPlan.targets;

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2.5 flex-wrap">
            <Activity className="w-6 h-6 text-emerald-400" />
            <h1 className="text-2xl font-bold text-white tracking-tight">
              LibreNMS SNMP, LLDP &amp; Health Monitoring
            </h1>
            <span
              className={`px-2 py-0.5 rounded-full text-xs font-mono border ${
                config.enabled
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
              }`}
            >
              {config.enabled ? `ENABLED · ${config.mode.toUpperCase()}` : 'DISABLED'}
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            SNMPv2c/v3 polling, LLDP/CDP/FDB physical link verification, optical DOM telemetry, Syslog/Trap receivers, and NetBox Triad sync.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => void loadAll(revealCreds)}
            disabled={refreshing}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 hover:border-slate-500 text-xs font-medium text-slate-200 flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh Probe
          </button>
          <a
            href={status?.endpointUrl || previewCompiled.endpointUrl}
            target="_blank"
            rel="noreferrer"
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 hover:border-sky-500/50 text-xs font-medium text-sky-300 flex items-center gap-1.5"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            Open LibreNMS UI
          </a>
          <button
            onClick={() => void handleSaveAndApply(!config.enabled)}
            disabled={saving || !state}
            className={`px-3 py-2 rounded-lg text-xs font-semibold border transition flex items-center gap-1.5 ${
              config.enabled
                ? 'bg-amber-500/10 border-amber-500/40 text-amber-300 hover:bg-amber-500/20'
                : 'bg-emerald-600 hover:bg-emerald-500 border-emerald-500 text-white'
            }`}
          >
            {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            {config.enabled ? 'Disable LibreNMS' : 'Enable & Deploy'}
          </button>
          <button
            onClick={() => void handleSaveAndApply()}
            disabled={saving || !state}
            className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-semibold text-white flex items-center gap-1.5 disabled:opacity-50"
          >
            {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            Save &amp; Apply
          </button>
        </div>
      </div>

      {banner && (
        <div
          className={`px-4 py-3 rounded-lg border text-xs flex items-center justify-between gap-3 ${
            banner.type === 'success'
              ? 'bg-emerald-950/50 border-emerald-500/40 text-emerald-200'
              : 'bg-rose-950/50 border-rose-500/40 text-rose-200'
          }`}
        >
          <span>{banner.text}</span>
          <button onClick={() => setBanner(null)} className="text-slate-400 hover:text-white">
            Dismiss
          </button>
        </div>
      )}

      {/* 4 Crisp Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
            <span>API &amp; Runtime</span>
            {k3sHealthy ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <XCircle className="w-4 h-4 text-slate-500" />
            )}
          </div>
          <div className="text-lg font-semibold text-white">
            {status?.apiReachable
              ? `Online ${status.librenmsVersion ? `v${status.librenmsVersion}` : ''}`
              : config.enabled
                ? status?.manifestPresent
                  ? 'Staging / Booting'
                  : 'Pending Apply'
                : 'Inactive'}
          </div>
          <div className="text-[11px] font-mono text-slate-400 mt-1 truncate">
            {config.mode === 'k3s'
              ? `Pods ${status?.podReadyCount ?? 0}/${status?.podTotalCount ?? 0} · ns:${config.namespace}`
              : status?.endpointUrl || config.externalUrl || 'External endpoint'}
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
            <span>Monitored Devices</span>
            <Server className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-lg font-semibold text-white">
            {topology?.available ? topology.devices.length : status?.deviceCount ?? 0}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Auto-enroll queue: {enrollmentTargets.length} host(s)
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
            <span>Ports &amp; LLDP Links</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-lg font-semibold text-white">
            {topology?.available
              ? `${topology.ports.length} ports · ${topology.links.length} links`
              : `${status?.portCount ?? 0} ports · ${status?.linkCount ?? 0} links`}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Feeds physical verification in <Link href="/topology" className="text-sky-400 hover:underline">Topology Studio</Link>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
            <span>Active &amp; Webhook Alerts</span>
            <AlertTriangle
              className={`w-4 h-4 ${combinedAlerts.length > 0 ? 'text-rose-400' : 'text-emerald-400'}`}
            />
          </div>
          <div className={`text-lg font-semibold ${combinedAlerts.length > 0 ? 'text-rose-300' : 'text-white'}`}>
            {combinedAlerts.length}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Polled: {status?.activeAlertCount ?? 0} · Real-time webhook: {status?.webhookAlertCount ?? 0}
          </div>
        </div>
      </div>

      {/* Section Navigation Tabs */}
      <div className="flex flex-wrap gap-1.5 border-b border-slate-800 pb-2">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-3.5 py-2 rounded-lg text-xs font-medium transition ${
              activeTab === tab.id
                ? 'bg-sky-600/20 text-sky-300 border border-sky-500/40'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
            <h2 className="text-sm font-semibold text-white">Runtime Mode &amp; K3s Stack</h2>

            <div className="grid grid-cols-2 gap-3">
              {(['k3s', 'external'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setConfig((prev) => ({ ...prev, mode: m }))}
                  className={`p-3 rounded-lg border text-left transition ${
                    config.mode === m
                      ? 'bg-sky-500/10 border-sky-500/50 text-white'
                      : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="text-xs font-semibold uppercase">{m === 'k3s' ? 'Embedded K3s Stack' : 'External Instance'}</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    {m === 'k3s'
                      ? 'MariaDB 11 + Valkey + RRDcached + Dispatcher + Syslog/Traps'
                      : 'Connect to existing LibreNMS server via URL + API Token'}
                  </div>
                </button>
              ))}
            </div>

            {config.mode === 'k3s' ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <label className="text-xs text-slate-300 space-y-1">
                  <span>FQDN Domain</span>
                  <input
                    value={config.domain}
                    onChange={(e) => setConfig((p) => ({ ...p, domain: e.target.value }))}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 font-mono text-xs"
                  />
                </label>
                <label className="text-xs text-slate-300 space-y-1">
                  <span>K3s Namespace</span>
                  <input
                    value={config.namespace}
                    onChange={(e) => setConfig((p) => ({ ...p, namespace: e.target.value }))}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 font-mono text-xs"
                  />
                </label>
                <label className="text-xs text-slate-300 space-y-1">
                  <span>OpenEBS StorageClass</span>
                  <input
                    value={config.storageClass}
                    onChange={(e) => setConfig((p) => ({ ...p, storageClass: e.target.value }))}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 font-mono text-xs"
                  />
                </label>
                <label className="text-xs text-slate-300 space-y-1">
                  <span>RRD &amp; Data PVC (GiB) / DB (GiB)</span>
                  <div className="flex gap-2">
                    <input
                      type="number"
                      min={5}
                      value={config.dataVolumeSizeGb}
                      onChange={(e) => setConfig((p) => ({ ...p, dataVolumeSizeGb: Number(e.target.value) || 20 }))}
                      className="w-1/2 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 font-mono text-xs"
                    />
                    <input
                      type="number"
                      min={5}
                      value={config.dbVolumeSizeGb}
                      onChange={(e) => setConfig((p) => ({ ...p, dbVolumeSizeGb: Number(e.target.value) || 15 }))}
                      className="w-1/2 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 font-mono text-xs"
                    />
                  </div>
                </label>
              </div>
            ) : (
              <div className="space-y-3">
                <label className="text-xs text-slate-300 space-y-1 block">
                  <span>External LibreNMS Base URL</span>
                  <input
                    placeholder="https://nms.example.com"
                    value={config.externalUrl || ''}
                    onChange={(e) => setConfig((p) => ({ ...p, externalUrl: e.target.value }))}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 font-mono text-xs"
                  />
                </label>
                <label className="text-xs text-slate-300 space-y-1 block">
                  <span>External X-Auth-Token (API Token)</span>
                  <input
                    type="password"
                    placeholder="Paste LibreNMS REST API token"
                    value={config.apiToken || ''}
                    onChange={(e) => setConfig((p) => ({ ...p, apiToken: e.target.value }))}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 font-mono text-xs"
                  />
                </label>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-2">
              {[
                { key: 'syslogEnabled', label: 'Syslog-NG UDP/514 Collector' },
                { key: 'snmpTrapEnabled', label: 'SNMPTrapd UDP/162 Receiver' },
                { key: 'ingressEnabled', label: 'Traefik HTTPS Ingress' },
                { key: 'unboundAutoDns', label: 'Unbound Local DNS Override' },
              ].map((item) => (
                <label
                  key={item.key}
                  className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/60 border border-slate-800 text-xs text-slate-200 cursor-pointer"
                >
                  <span>{item.label}</span>
                  <input
                    type="checkbox"
                    checked={Boolean(config[item.key as keyof LibreNmsConfig])}
                    onChange={(e) =>
                      setConfig((p) => ({ ...p, [item.key]: e.target.checked }))
                    }
                    className="accent-emerald-500"
                  />
                </label>
              ))}
            </div>
          </div>

          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white">Axonwall Auto-Enrollment Plan</h2>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => void handleEnrollSync(true)}
                  disabled={syncingMode !== null}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 flex items-center gap-1.5"
                >
                  {syncingMode === 'dry' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                  Dry-Run
                </button>
                <button
                  type="button"
                  onClick={() => void handleEnrollSync(false)}
                  disabled={syncingMode !== null}
                  className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white flex items-center gap-1.5"
                >
                  {syncingMode === 'live' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                  Enroll Hosts Now
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {[
                { key: 'autoEnrollAxonwallHosts', label: 'Local & HA Peer' },
                { key: 'autoEnrollFleetSatellites', label: 'Fleet Satellites' },
                { key: 'autoEnrollTopologyPeers', label: 'Topology Peer Hosts' },
              ].map((opt) => (
                <label
                  key={opt.key}
                  className="flex items-center gap-2 p-2 rounded-lg bg-slate-950/60 border border-slate-800 text-xs text-slate-300 cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={Boolean(config.sync[opt.key as keyof LibreNmsConfig['sync']])}
                    onChange={(e) =>
                      setConfig((p) => ({
                        ...p,
                        sync: { ...p.sync, [opt.key]: e.target.checked },
                      }))
                    }
                    className="accent-emerald-500"
                  />
                  <span>{opt.label}</span>
                </label>
              ))}
            </div>

            <div className="overflow-x-auto border border-slate-800 rounded-lg">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400">
                  <tr>
                    <th className="p-2.5">Display Name</th>
                    <th className="p-2.5">Target IP / Host</th>
                    <th className="p-2.5">Source</th>
                    <th className="p-2.5">SNMP</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 text-slate-200">
                  {enrollmentTargets.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="p-4 text-center text-slate-500">
                        No SNMP enrollment targets detected yet.
                      </td>
                    </tr>
                  ) : (
                    enrollmentTargets.map((t) => (
                      <tr key={t.id}>
                        <td className="p-2.5 font-medium">{t.displayName}</td>
                        <td className="p-2.5 font-mono text-sky-300">{t.hostname}</td>
                        <td className="p-2.5 text-slate-400">{t.source}</td>
                        <td className="p-2.5 font-mono text-slate-300">{t.snmpVersion}:{t.port}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {syncResult && (
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 flex flex-wrap gap-4">
                <span>Mode: <strong className="text-white">{syncResult.dryRun ? 'Dry-Run' : 'Live'}</strong></span>
                <span>Enrolled: <strong className="text-emerald-400">{syncResult.enrolled}</strong></span>
                <span>Already Tracked: <strong className="text-sky-400">{syncResult.existing}</strong></span>
                <span>Failed: <strong className={syncResult.failed > 0 ? 'text-rose-400' : 'text-slate-300'}>{syncResult.failed}</strong></span>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'snmp' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
            <h2 className="text-sm font-semibold text-white">Default SNMP Credentials (v2c / v3)</h2>
            <div className="grid grid-cols-2 gap-3">
              <label className="text-xs text-slate-300 space-y-1">
                <span>SNMP Version</span>
                <select
                  value={config.snmpDefaults.version}
                  onChange={(e) =>
                    setConfig((p) => ({
                      ...p,
                      snmpDefaults: { ...p.snmpDefaults, version: e.target.value as 'v2c' | 'v3' },
                    }))
                  }
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 text-xs"
                >
                  <option value="v2c">SNMPv2c</option>
                  <option value="v3">SNMPv3 (AuthPriv / AuthNoPriv)</option>
                </select>
              </label>
              <label className="text-xs text-slate-300 space-y-1">
                <span>SNMP Port</span>
                <input
                  type="number"
                  value={config.snmpDefaults.port}
                  onChange={(e) =>
                    setConfig((p) => ({
                      ...p,
                      snmpDefaults: { ...p.snmpDefaults, port: Number(e.target.value) || 161 },
                    }))
                  }
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 font-mono text-xs"
                />
              </label>
            </div>

            {config.snmpDefaults.version === 'v2c' ? (
              <label className="text-xs text-slate-300 space-y-1 block">
                <span>SNMPv2c Read Community</span>
                <input
                  type="password"
                  value={config.snmpDefaults.community}
                  onChange={(e) =>
                    setConfig((p) => ({
                      ...p,
                      snmpDefaults: { ...p.snmpDefaults, community: e.target.value },
                    }))
                  }
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 font-mono text-xs"
                />
              </label>
            ) : (
              <div className="grid grid-cols-2 gap-3">
                <label className="text-xs text-slate-300 space-y-1">
                  <span>Security Level</span>
                  <select
                    value={config.snmpDefaults.v3AuthLevel}
                    onChange={(e) =>
                      setConfig((p) => ({
                        ...p,
                        snmpDefaults: {
                          ...p.snmpDefaults,
                          v3AuthLevel: e.target.value as 'noAuthNoPriv' | 'authNoPriv' | 'authPriv',
                        },
                      }))
                    }
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 text-xs"
                  >
                    <option value="authPriv">authPriv</option>
                    <option value="authNoPriv">authNoPriv</option>
                    <option value="noAuthNoPriv">noAuthNoPriv</option>
                  </select>
                </label>
                <label className="text-xs text-slate-300 space-y-1">
                  <span>SNMPv3 Username</span>
                  <input
                    value={config.snmpDefaults.v3AuthUser || ''}
                    onChange={(e) =>
                      setConfig((p) => ({
                        ...p,
                        snmpDefaults: { ...p.snmpDefaults, v3AuthUser: e.target.value },
                      }))
                    }
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 font-mono text-xs"
                  />
                </label>
                <label className="text-xs text-slate-300 space-y-1">
                  <span>Auth Algo / Passphrase</span>
                  <div className="flex gap-2">
                    <select
                      value={config.snmpDefaults.v3AuthAlgo}
                      onChange={(e) =>
                        setConfig((p) => ({
                          ...p,
                          snmpDefaults: {
                            ...p.snmpDefaults,
                            v3AuthAlgo: e.target.value as 'SHA' | 'SHA-256' | 'SHA-512' | 'MD5',
                          },
                        }))
                      }
                      className="w-1/3 px-2 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 text-xs"
                    >
                      <option value="SHA-256">SHA-256</option>
                      <option value="SHA-512">SHA-512</option>
                      <option value="SHA">SHA</option>
                    </select>
                    <input
                      type="password"
                      value={config.snmpDefaults.v3AuthPass || ''}
                      onChange={(e) =>
                        setConfig((p) => ({
                          ...p,
                          snmpDefaults: { ...p.snmpDefaults, v3AuthPass: e.target.value },
                        }))
                      }
                      className="w-2/3 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 font-mono text-xs"
                    />
                  </div>
                </label>
                <label className="text-xs text-slate-300 space-y-1">
                  <span>Crypto Algo / Passphrase</span>
                  <div className="flex gap-2">
                    <select
                      value={config.snmpDefaults.v3CryptoAlgo}
                      onChange={(e) =>
                        setConfig((p) => ({
                          ...p,
                          snmpDefaults: {
                            ...p.snmpDefaults,
                            v3CryptoAlgo: e.target.value as 'AES' | 'AES-256' | 'DES',
                          },
                        }))
                      }
                      className="w-1/3 px-2 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 text-xs"
                    >
                      <option value="AES">AES</option>
                      <option value="AES-256">AES-256</option>
                    </select>
                    <input
                      type="password"
                      value={config.snmpDefaults.v3CryptoPass || ''}
                      onChange={(e) =>
                        setConfig((p) => ({
                          ...p,
                          snmpDefaults: { ...p.snmpDefaults, v3CryptoPass: e.target.value },
                        }))
                      }
                      className="w-2/3 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 font-mono text-xs"
                    />
                  </div>
                </label>
              </div>
            )}
          </div>

          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-white">Management-VLAN Auto-Discovery Subnets</h2>
                <p className="text-xs text-slate-400">Emitted into LibreNMS autodiscovery nets[] for switches, PDUs, UPS, and APs.</p>
              </div>
              <button
                type="button"
                onClick={() =>
                  setConfig((p) => ({
                    ...p,
                    discoverySubnets: [
                      ...p.discoverySubnets,
                      { cidr: '10.10.0.0/24', label: 'Management VLAN', enabled: true },
                    ],
                  }))
                }
                className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-white flex items-center gap-1"
              >
                <Plus className="w-3.5 h-3.5" /> Add Subnet
              </button>
            </div>

            <div className="space-y-2">
              {config.discoverySubnets.length === 0 ? (
                <div className="p-4 rounded-lg border border-dashed border-slate-800 text-xs text-slate-500 text-center">
                  No discovery CIDRs added yet.
                </div>
              ) : (
                config.discoverySubnets.map((sub, idx) => (
                  <div key={`${idx}-${sub.cidr}`} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={sub.enabled}
                      onChange={(e) => {
                        const list = [...config.discoverySubnets];
                        list[idx] = { ...sub, enabled: e.target.checked };
                        setConfig((p) => ({ ...p, discoverySubnets: list }));
                      }}
                      className="accent-emerald-500"
                    />
                    <input
                      value={sub.cidr}
                      onChange={(e) => {
                        const list = [...config.discoverySubnets];
                        list[idx] = { ...sub, cidr: e.target.value };
                        setConfig((p) => ({ ...p, discoverySubnets: list }));
                      }}
                      placeholder="10.10.0.0/24"
                      className="w-40 px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-slate-100"
                    />
                    <input
                      value={sub.label}
                      onChange={(e) => {
                        const list = [...config.discoverySubnets];
                        list[idx] = { ...sub, label: e.target.value };
                        setConfig((p) => ({ ...p, discoverySubnets: list }));
                      }}
                      placeholder="Description"
                      className="flex-1 px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200"
                    />
                    <button
                      type="button"
                      onClick={() =>
                        setConfig((p) => ({
                          ...p,
                          discoverySubnets: p.discoverySubnets.filter((_, i) => i !== idx),
                        }))
                      }
                      className="p-1.5 text-slate-500 hover:text-rose-400"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'triad' && (
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <ArrowLeftRight className="w-4 h-4 text-sky-400" />
                LibreNMS ↔ NetBox ↔ Topology Studio Bi-Directional Bridge
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Push discovered switches and LLDP/CDP physical links from LibreNMS into NetBox DCIM, or pull NetBox rack devices into LibreNMS SNMP polling.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <label className="flex items-center gap-1.5 text-xs text-slate-300 mr-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={overwriteLabels}
                  onChange={(e) => setOverwriteLabels(e.target.checked)}
                  className="accent-sky-500"
                />
                Overwrite Conflicting Labels
              </label>
              <button
                type="button"
                disabled={triadBusy !== null}
                onClick={() => void handleTriadSync('preview')}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 flex items-center gap-1.5"
              >
                {triadBusy === 'preview' && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                Preview Conflicts
              </button>
              <button
                type="button"
                disabled={triadBusy !== null}
                onClick={() => void handleTriadSync('push')}
                className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white flex items-center gap-1.5"
              >
                {triadBusy === 'push' && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                Push LLDP Links → NetBox
              </button>
              <button
                type="button"
                disabled={triadBusy !== null}
                onClick={() => void handleTriadSync('pull')}
                className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-semibold text-white flex items-center gap-1.5"
              >
                {triadBusy === 'pull' && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                Pull NetBox → LibreNMS
              </button>
            </div>
          </div>

          {triadResult && (
            <div className="space-y-3">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="text-slate-400">Action</div>
                  <div className="font-mono text-white mt-0.5">
                    {triadResult.action.toUpperCase()} ({triadResult.dryRun ? 'Preview' : 'Applied'})
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="text-slate-400">Queued Devices / Cables</div>
                  <div className="font-mono text-white mt-0.5">
                    {triadResult.devicesQueued} dev · {triadResult.cablesQueued} cables
                  </div>
                </div>
                {triadResult.netboxResult && (
                  <>
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="text-slate-400">NetBox Cables (C / U / =)</div>
                      <div className="font-mono text-emerald-300 mt-0.5">
                        {triadResult.netboxResult.cables.created} / {triadResult.netboxResult.cables.updated} /{' '}
                        {triadResult.netboxResult.cables.unchanged}
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="text-slate-400">Conflicts Detected</div>
                      <div className="font-mono text-amber-300 mt-0.5">
                        {triadResult.netboxResult.conflicts.length}
                      </div>
                    </div>
                  </>
                )}
              </div>

              {triadResult.netboxResult && triadResult.netboxResult.conflicts.length > 0 && (
                <div className="overflow-x-auto border border-slate-800 rounded-lg">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950 text-slate-400">
                      <tr>
                        <th className="p-2.5">Cable Pair</th>
                        <th className="p-2.5">Field</th>
                        <th className="p-2.5">Axonwall / LibreNMS</th>
                        <th className="p-2.5">NetBox Existing</th>
                        <th className="p-2.5">Resolution</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 text-slate-200">
                      {triadResult.netboxResult.conflicts.map((c, i) => (
                        <tr key={`${c.key}-${c.field}-${i}`}>
                          <td className="p-2.5 font-mono">{c.key}</td>
                          <td className="p-2.5">{c.field}</td>
                          <td className="p-2.5 text-sky-300">{c.axonwallVal}</td>
                          <td className="p-2.5 text-amber-300">{c.netboxVal}</td>
                          <td className="p-2.5 font-mono text-slate-300">{c.resolution}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === 'credentials' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                OpenLDAP SSO (`svc-librenms`)
              </h2>
              <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.ldapAuth.enabled}
                  onChange={(e) =>
                    setConfig((p) => ({ ...p, ldapAuth: { ...p.ldapAuth, enabled: e.target.checked } }))
                  }
                  className="accent-emerald-500"
                />
                Enable LDAP Auth
              </label>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
              <label className="text-slate-300 space-y-1">
                <span>Level 10 Admin Group</span>
                <input
                  value={config.ldapAuth.adminGroup}
                  onChange={(e) =>
                    setConfig((p) => ({ ...p, ldapAuth: { ...p.ldapAuth, adminGroup: e.target.value } }))
                  }
                  className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-slate-100"
                />
              </label>
              <label className="text-slate-300 space-y-1">
                <span>Level 5 Operator Group</span>
                <input
                  value={config.ldapAuth.operatorGroup}
                  onChange={(e) =>
                    setConfig((p) => ({ ...p, ldapAuth: { ...p.ldapAuth, operatorGroup: e.target.value } }))
                  }
                  className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-slate-100"
                />
              </label>
              <label className="text-slate-300 space-y-1">
                <span>Level 1 Read-Only Group</span>
                <input
                  value={config.ldapAuth.readonlyGroup}
                  onChange={(e) =>
                    setConfig((p) => ({ ...p, ldapAuth: { ...p.ldapAuth, readonlyGroup: e.target.value } }))
                  }
                  className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-slate-100"
                />
              </label>
            </div>
            <div className="text-xs text-slate-400 font-mono bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-1">
              <div>Base DN: {previewCompiled.baseDn}</div>
              <div>Bind DN: {previewCompiled.bindDn}</div>
              <div>LDAP URI: {previewCompiled.podLdapUrl}</div>
              <div>GIDs: librenms-admin (10250), librenms-operator (10251), librenms-readonly (10252)</div>
            </div>
          </div>

          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-amber-400" />
                Bootstrap Secrets &amp; Real-Time Alert Webhook
              </h2>
              <button
                type="button"
                onClick={() => void handleToggleReveal()}
                className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 flex items-center gap-1.5"
              >
                {revealCreds ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                {revealCreds ? 'Hide Secrets' : 'Reveal Secrets'}
              </button>
            </div>

            <div className="space-y-2 text-xs">
              {[
                { key: 'user', label: 'Admin Username', val: creds?.adminUsername || config.adminUsername },
                { key: 'pass', label: 'Bootstrap Admin Password', val: revealCreds ? creds?.adminPassword || 'Not generated yet' : '********' },
                { key: 'token', label: 'LibreNMS REST API Token', val: revealCreds ? creds?.apiToken || 'Not generated yet' : creds?.tokenPreview || '********' },
                { key: 'webhook', label: 'Webhook Shared Secret (X-Axonwall-Webhook-Secret)', val: revealCreds ? creds?.webhookSecret || 'Not generated yet' : '********' },
              ].map((row) => (
                <div key={row.key} className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <div>
                    <div className="text-[11px] text-slate-400">{row.label}</div>
                    <div className="font-mono text-slate-100 mt-0.5">{row.val}</div>
                  </div>
                  <button
                    type="button"
                    onClick={() => void handleCopy(row.key, row.val)}
                    className="p-1.5 text-slate-400 hover:text-white"
                  >
                    {copiedKey === row.key ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              ))}
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <Webhook className="w-3.5 h-3.5 text-sky-400" />
                LibreNMS Alert Transport Target
              </div>
              <pre className="text-[11px] font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap">
{`POST https://<axonwall-console>:2966/api/v1/services/librenms/webhook
Header: X-Axonwall-Webhook-Secret: <webhookSecret>
Body: {"hostname":"{{ $hostname }}","ip":"{{ $ip }}","rule":"{{ $title }}","severity":"{{ $severity }}","state":1,"msg":"{{ $msg }}"}`}
              </pre>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'manifests' && (
        <div className="space-y-4">
          {[
            { title: 'axonwall_ldap.php', content: previewCompiled.ldapConfigPhp },
            { title: 'axonwall_discovery.php', content: previewCompiled.discoveryConfigPhp },
            { title: 'Unbound Local DNS Override', content: previewCompiled.unboundOverrides || '# Unbound override inactive' },
            { title: 'K3s Deployment Manifests (/var/lib/rancher/k3s/server/manifests/axonwall-librenms.yaml)', content: previewCompiled.k3sManifestsYaml || '# External mode or disabled — no K3s manifests emitted' },
          ].map((item) => (
            <div key={item.title} className="rounded-xl bg-slate-900/60 border border-slate-800 overflow-hidden">
              <div className="px-4 py-2.5 bg-slate-950 border-b border-slate-800 flex items-center justify-between text-xs font-mono text-slate-300">
                <span className="flex items-center gap-1.5">
                  <FileCode2 className="w-3.5 h-3.5 text-sky-400" />
                  {item.title}
                </span>
                <Database className="w-3.5 h-3.5 text-slate-600" />
              </div>
              <pre className="p-4 text-xs font-mono text-slate-300 overflow-x-auto max-h-80">{item.content}</pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
