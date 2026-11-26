'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import {
  Activity,
  AlertTriangle,
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
  Network,
  Play,
  RefreshCw,
  Server,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import {
  compileNetBoxBundle,
  resolveNetBoxConfig,
} from '@axonwall/lib/compile/netbox';
import {
  disablePluginWithDependents,
  enablePluginWithDependencies,
} from '@axonwall/lib/plugins';
import {
  NetBoxConfigSchema,
  type DesiredState,
  type NetBoxConfig,
} from '@axonwall/lib/schemas';
import {
  getCurrentDesiredState,
  getNetBoxCredentialsAction,
  getNetBoxStatusAction,
  triggerNetBoxSyncAction,
  type NetBoxCredentialsSnapshot,
  type NetBoxStatusSnapshot,
  type NetBoxSyncResultSnapshot,
} from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import { safeHttpHref } from '@/lib/safe-href';
import { parseNonNegativeIntInput } from '@/lib/state-preservation';

const SYNC_SCOPE_FLAGS: Array<{
  key: keyof NetBoxConfig['sync'];
  label: string;
  desc: string;
}> = [
  {
    key: 'syncInterfaces',
    label: 'Physical, VLAN, Bridge & Bond Interfaces',
    desc: 'Push appliance NICs, MTU, VLAN sub-interfaces, LACP LAGs, Bridges, and WireGuard endpoints to DCIM.',
  },
  {
    key: 'syncVlans',
    label: '802.1Q VLAN Tags',
    desc: 'Register VLAN tags and parent trunk interfaces under the assigned appliance Site.',
  },
  {
    key: 'syncVrfs',
    label: 'VRF Routing Tables',
    desc: 'Mirror Linux policy-routing VRFs and route distinguishers into NetBox IPAM VRFs.',
  },
  {
    key: 'syncPrefixes',
    label: 'IPv4/IPv6 Interface, DHCP & K3s Prefixes',
    desc: 'Deduplicate interface subnets, Kea DHCP pools, WireGuard CIDRs, and K3s pod/service networks.',
  },
  {
    key: 'syncVirtualIps',
    label: 'CARP / VRRP Floating Virtual IPs',
    desc: 'Track HA VRRP failover VIPs and interface IP aliases with VIP role metadata.',
  },
  {
    key: 'syncDhcpLeases',
    label: 'Static Mappings & Live Kea DHCP Leases',
    desc: 'Continuously reconcile DHCP static reservations and active Kea IPv4 leases from /var/lib/kea/kea-leases4.csv.',
  },
  {
    key: 'syncVirtualMachines',
    label: 'KVM Virtual Machines & LXC Containers',
    desc: 'Mirror Hypervisor vCPUs, memory, disk capacity, and running state into NetBox Virtualization.',
  },
  {
    key: 'syncK3sNodes',
    label: 'K3s Cluster Nodes',
    desc: 'Register every K3s control-plane, storage, edge, and worker host in DCIM Devices.',
  },
  {
    key: 'autoSyncOnApply',
    label: 'Auto-Sync Inventory After Config Apply',
    desc: 'Trigger an idempotent REST API sync automatically whenever /etc/axonwall config is applied.',
  },
];

export default function NetBoxStudioPage() {
  const { applyState } = useDesiredStateApply();
  const [state, setState] = useState<DesiredState | null>(null);
  const [config, setConfig] = useState<NetBoxConfig>(() => NetBoxConfigSchema.parse({}));
  const [status, setStatus] = useState<NetBoxStatusSnapshot | null>(null);
  const [syncResult, setSyncResult] = useState<NetBoxSyncResultSnapshot | null>(null);
  const [creds, setCreds] = useState<NetBoxCredentialsSnapshot | null>(null);
  const [revealCreds, setRevealCreds] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'k3s' | 'ldap' | 'manifests'>('overview');
  const [saving, setSaving] = useState(false);
  const [syncingMode, setSyncingMode] = useState<'dry' | 'live' | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadAll = useCallback(async (revealSecretFields = false) => {
    setRefreshing(true);
    try {
      const [st, liveSt, credSnap] = await Promise.all([
        getCurrentDesiredState(),
        getNetBoxStatusAction().catch(() => null),
        getNetBoxCredentialsAction(revealSecretFields).catch(() => null),
      ]);
      setState(st);
      setConfig(resolveNetBoxConfig(st));
      if (liveSt) {
        setStatus(liveSt);
        if (liveSt.lastSync) {
          setSyncResult((prev) => prev ?? liveSt.lastSync ?? null);
        }
      }
      if (credSnap) {
        setCreds(credSnap);
      }
    } catch {
      // ignore initial auth/transient errors handled cleanly by layout
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void loadAll(false);
  }, [loadAll]);

  const lastValidBundleRef = useRef<ReturnType<typeof compileNetBoxBundle> | null>(null);
  const { bundle, validationError } = useMemo(() => {
    const previewState: Partial<DesiredState> = {
      ...(state ?? {}),
      netbox: config,
      plugins: [
        ...(state?.plugins ?? []).filter((p) => p.id !== 'netbox'),
        { id: 'netbox', enabled: config.enabled },
      ],
    };
    try {
      const compiled = compileNetBoxBundle(previewState);
      lastValidBundleRef.current = compiled;
      return { bundle: compiled, validationError: null as string | null };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Invalid NetBox configuration';
      const fallback = lastValidBundleRef.current ?? compileNetBoxBundle(state ?? {});
      return { bundle: fallback, validationError: msg };
    }
  }, [state, config]);

  const copyText = (key: string, val: string) => {
    if (!val) return;
    navigator.clipboard?.writeText(val).catch(() => {});
    setCopiedKey(key);
    setTimeout(() => setCopiedKey((cur) => (cur === key ? null : cur)), 1800);
  };

  const handleSave = async (overrideEnabled?: boolean) => {
    if (!state) return;
    const targetEnabled = overrideEnabled !== undefined ? overrideEnabled : config.enabled;
    const candidateConfig: NetBoxConfig = {
      ...config,
      enabled: targetEnabled,
      externalUrl: config.externalUrl?.trim() ? config.externalUrl.trim() : undefined,
    };
    const parsedCfg = NetBoxConfigSchema.safeParse(candidateConfig);
    if (!parsedCfg.success) {
      setBanner({
        type: 'error',
        text: `Invalid NetBox settings: ${parsedCfg.error.issues.map((i) => `${i.path.join('.') || 'netbox'}: ${i.message}`).join('; ')}`,
      });
      return;
    }
    setSaving(true);
    setBanner(null);
    try {
      const nextConfig: NetBoxConfig = parsedCfg.data;
      let nextState = structuredClone(state);
      nextState.netbox = nextConfig;
      if (targetEnabled) {
        const resDep = enablePluginWithDependencies('netbox', nextState);
        nextState = resDep.state;
        nextState.netbox = nextConfig;
      } else {
        const resDep = disablePluginWithDependents('netbox', nextState);
        nextState = resDep.state;
        nextState.netbox = nextConfig;
      }
      const res = await applyState(nextState);
      setState(nextState);
      setConfig(nextConfig);
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new Event('axonwall-capabilities-updated'));
      }
      setBanner({
        type: 'success',
        text: `Saved NetBox DCIM & IPAM configuration to /etc/axonwall/services.yaml (${res.message}).`,
      });
      await loadAll(revealCreds);
    } catch (err: unknown) {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to save NetBox configuration',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleSync = async (dryRun: boolean) => {
    setSyncingMode(dryRun ? 'dry' : 'live');
    setBanner(null);
    try {
      const res = await triggerNetBoxSyncAction({ dryRun });
      setSyncResult(res);
      if (res.success) {
        setBanner({
          type: 'success',
          text: dryRun
            ? `Dry-run completed against ${res.endpoint}: ${res.devicesSynced} devices, ${res.interfaces.created} interfaces, ${res.prefixes.created} prefixes, ${res.ipAddresses.created} IPs, ${res.virtualMachines.created} VMs queued.`
            : `Synced inventory to NetBox (${res.endpoint}): ${res.devicesSynced} devices, ${res.prefixes.created + res.prefixes.updated} prefixes, ${res.ipAddresses.created + res.ipAddresses.updated} IPs.`,
        });
      } else {
        setBanner({
          type: 'error',
          text: res.error || 'NetBox inventory sync did not complete.',
        });
      }
      if (!dryRun) {
        const latest = await getNetBoxStatusAction().catch(() => null);
        if (latest) setStatus(latest);
      }
    } catch (err: unknown) {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to trigger NetBox inventory sync',
      });
    } finally {
      setSyncingMode(null);
    }
  };

  const handleToggleReveal = async () => {
    const nextReveal = !revealCreds;
    setRevealCreds(nextReveal);
    const snap = await getNetBoxCredentialsAction(nextReveal).catch(() => null);
    if (snap) setCreds(snap);
  };

  const safeHref = safeHttpHref(
    bundle.endpointUrl,
    safeHttpHref(`https://${bundle.domain}`, 'https://netbox.axonwall.local')
  );

  return (
    <div className="p-6 lg:p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="flex items-start gap-4 min-w-0">
          <div className="w-11 h-11 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 shrink-0">
            <Network className="w-6 h-6" />
          </div>
          <div className="space-y-1.5 min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                NetBox DCIM &amp; IPAM
              </h1>
              <span
                className={`px-2 py-0.5 rounded-full text-[11px] font-mono border ${
                  config.enabled
                    ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                    : 'bg-slate-800 border-slate-700 text-slate-400'
                }`}
              >
                {config.enabled ? 'ENABLED' : 'DISABLED'}
              </span>
              <span
                className={`px-2 py-0.5 rounded-full text-[11px] font-mono border ${
                  status?.k3sReady
                    ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                    : 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                }`}
              >
                {status?.k3sReady ? 'K3S READY' : 'K3S PENDING'}
              </span>
              {status?.apiReachable && (
                <span className="px-2 py-0.5 rounded-full text-[11px] font-mono bg-cyan-500/15 border border-cyan-500/30 text-cyan-300">
                  API LIVE{status.netboxVersion ? ` • v${status.netboxVersion}` : ''}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 max-w-2xl">
              K3s-native NetBox source of truth (PostgreSQL 16 + Valkey 8 on OpenEBS ZFS, OpenLDAP SSO via{' '}
              <code className="text-emerald-300 font-mono">cn=svc-netbox</code>, Unbound Auto-DNS, and idempotent Axonwall IPAM/DCIM sync).
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => void loadAll(revealCreds)}
            disabled={refreshing}
            className="px-3 py-2 rounded-xl text-xs font-semibold bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 transition flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <a
            href={safeHref}
            target="_blank"
            rel="noopener noreferrer"
            className="px-3 py-2 rounded-xl text-xs font-semibold bg-slate-950 hover:bg-slate-800 text-sky-300 border border-sky-500/30 transition flex items-center gap-1.5"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            Open NetBox UI
          </a>
          <button
            type="button"
            disabled={syncingMode !== null || !status?.manifestPresent}
            onClick={() => void handleSync(true)}
            className="px-3 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-100 border border-slate-700 transition flex items-center gap-1.5"
          >
            {syncingMode === 'dry' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5 text-cyan-400" />}
            Dry-Run Sync
          </button>
          <button
            type="button"
            disabled={syncingMode !== null || !status?.manifestPresent}
            onClick={() => void handleSync(false)}
            className="px-3 py-2 rounded-xl text-xs font-semibold bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white transition flex items-center gap-1.5"
          >
            {syncingMode === 'live' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            Sync Inventory Now
          </button>
          <button
            type="button"
            disabled={saving || !state}
            onClick={() => void handleSave(!config.enabled)}
            className={`px-3 py-2 rounded-xl text-xs font-semibold transition flex items-center gap-1.5 ${
              config.enabled
                ? 'bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30'
                : 'bg-emerald-600 hover:bg-emerald-500 text-white'
            }`}
          >
            {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
            {config.enabled ? 'Disable' : 'Enable & Deploy'}
          </button>
          <button
            type="button"
            disabled={saving || !state}
            onClick={() => void handleSave()}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white transition flex items-center gap-1.5"
          >
            {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
            Save &amp; Apply
          </button>
        </div>
      </div>

      {banner && (
        <div
          className={`p-3.5 rounded-xl border text-xs flex items-center justify-between gap-3 ${
            banner.type === 'success'
              ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-200'
              : 'bg-rose-950/40 border-rose-500/30 text-rose-200'
          }`}
        >
          <div className="flex items-center gap-2 min-w-0">
            {banner.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
            )}
            <span className="break-words">{banner.text}</span>
          </div>
          <button
            type="button"
            onClick={() => setBanner(null)}
            className="text-slate-400 hover:text-white font-mono shrink-0"
          >
            Dismiss
          </button>
        </div>
      )}

      {validationError && (
        <div className="p-3 rounded-xl bg-amber-950/30 border border-amber-500/30 text-xs text-amber-200 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
          <span>Draft contains incomplete/invalid values (preview showing last valid config): {validationError}</span>
        </div>
      )}

      {status?.daemonDown && (
        <div className="p-3.5 rounded-xl bg-amber-950/30 border border-amber-500/30 text-xs text-amber-200">
          Host daemon <code className="font-mono">axonwalld</code> is currently unreachable ({status.statusError}). Displaying compiled desired state preview.
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>NetBox Endpoint</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-base font-bold font-mono tabular-nums text-white truncate">
            {status?.apiReachable ? 'Online (200 OK)' : status?.manifestPresent ? 'Manifest Staged' : 'Not Deployed'}
          </div>
          <div className="text-[11px] font-mono text-slate-400 truncate">{bundle.endpointUrl}</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>K3s Pod Readiness</span>
            <Layers className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-base font-bold font-mono tabular-nums text-white">
            {status ? `${status.podReadyCount} / ${status.podTotalCount} Ready` : '0 / 0 Ready'}
          </div>
          <div className="text-[11px] font-mono text-slate-400 truncate">
            ns:{bundle.namespace} {status?.clusterIp ? `• svc:${status.clusterIp}` : ''}
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Planned Inventory Objects</span>
            <Database className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-base font-bold font-mono tabular-nums text-white">
            {bundle.syncPlan.summary.totalObjects} objects
          </div>
          <div className="text-[11px] font-mono text-slate-400 tabular-nums truncate">
            {bundle.syncPlan.summary.interfacesCount} ifaces • {bundle.syncPlan.summary.prefixesCount} prefixes • {bundle.syncPlan.summary.ipAddressesCount} IPs
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>OpenLDAP Directory Bind</span>
            <KeyRound className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-base font-bold font-mono text-white">
            {status?.ldapBound ? 'Bound (svc-netbox)' : config.ldapAuth.enabled ? 'Auto-Provision' : 'Disabled'}
          </div>
          <div className="text-[11px] font-mono text-slate-400 truncate">{bundle.baseDn}</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
        {[
          { id: 'overview', label: 'Overview & Inventory Sync', icon: Activity },
          { id: 'k3s', label: 'K3s, Storage & Credentials', icon: Server },
          { id: 'ldap', label: 'OpenLDAP SSO', icon: KeyRound },
          { id: 'manifests', label: 'K3s Manifests & Unbound DNS', icon: FileCode2 },
        ].map((tab) => {
          const Icon = tab.icon;
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`px-3.5 py-2 rounded-xl text-xs font-semibold transition flex items-center gap-2 border ${
                active
                  ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Sync Scope Toggles */}
          <div className="lg:col-span-7 p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-bold text-white">Axonwall-to-NetBox Sync Scope</h2>
                <p className="text-xs text-slate-400">
                  Idempotent sync upserts DCIM, IPAM, and Virtualization state via NetBox v4 REST API.
                </p>
              </div>
              <label className="flex items-center gap-2 text-xs font-mono text-slate-200 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.sync.enabled}
                  onChange={(e) =>
                    setConfig((cur) => ({
                      ...cur,
                      sync: { ...cur.sync, enabled: e.target.checked },
                    }))
                  }
                  className="rounded border-slate-700 bg-slate-950 text-emerald-500 focus:ring-emerald-500"
                />
                Sync Enabled
              </label>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {SYNC_SCOPE_FLAGS.map((flag) => (
                <label
                  key={flag.key}
                  className="p-3 rounded-xl bg-slate-950 border border-slate-800 hover:border-slate-700 cursor-pointer flex items-start gap-2.5"
                >
                  <input
                    type="checkbox"
                    checked={Boolean(config.sync[flag.key])}
                    onChange={(e) =>
                      setConfig((cur) => ({
                        ...cur,
                        sync: { ...cur.sync, [flag.key]: e.target.checked },
                      }))
                    }
                    className="mt-0.5 rounded border-slate-700 bg-slate-900 text-emerald-500 focus:ring-emerald-500"
                  />
                  <div className="space-y-0.5 min-w-0">
                    <div className="text-xs font-semibold text-slate-200">{flag.label}</div>
                    <div className="text-[11px] text-slate-400 leading-relaxed">{flag.desc}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Live Sync Plan & Pod Status */}
          <div className="lg:col-span-5 space-y-6">
            <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold text-white">Compiled Inventory Plan</h2>
                <span className="text-[11px] font-mono text-emerald-400">
                  Site: {bundle.syncPlan.site.slug}
                </span>
              </div>
              <div className="grid grid-cols-3 gap-2.5 font-mono tabular-nums text-xs">
                {[
                  { label: 'VRFs', val: bundle.syncPlan.summary.vrfsCount },
                  { label: 'VLANs', val: bundle.syncPlan.summary.vlansCount },
                  { label: 'Interfaces', val: bundle.syncPlan.summary.interfacesCount },
                  { label: 'Prefixes', val: bundle.syncPlan.summary.prefixesCount },
                  { label: 'IP Addresses', val: bundle.syncPlan.summary.ipAddressesCount },
                  { label: 'VMs / LXCs', val: bundle.syncPlan.summary.virtualMachinesCount },
                ].map((c) => (
                  <div key={c.label} className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-400">{c.label}</div>
                    <div className="text-sm font-bold text-white">{c.val}</div>
                  </div>
                ))}
              </div>
              <div className="text-[11px] text-slate-400 font-mono truncate">
                Device: {bundle.syncPlan.device.hostname} ({bundle.syncPlan.device.primaryIp || 'unassigned'})
              </div>
            </div>

            {syncResult && (
              <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-bold text-white">
                    {syncResult.dryRun ? 'Last Dry-Run Plan' : 'Last Live Sync Report'}
                  </h2>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                      syncResult.success
                        ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                        : 'bg-rose-500/15 border-rose-500/30 text-rose-300'
                    }`}
                  >
                    {syncResult.success ? 'SUCCESS' : 'FAILED'}
                  </span>
                </div>
                <div className="text-[11px] font-mono text-slate-400 space-y-1 tabular-nums">
                  <div>Timestamp: {syncResult.timestamp}</div>
                  <div>Target: {syncResult.endpoint}</div>
                  <div className="grid grid-cols-2 gap-1 pt-1 text-slate-300">
                    <span>Devices synced: {syncResult.devicesSynced}</span>
                    <span>VRFs: +{syncResult.vrfs.created} / ~{syncResult.vrfs.updated}</span>
                    <span>VLANs: +{syncResult.vlans.created} / ~{syncResult.vlans.updated}</span>
                    <span>Interfaces: +{syncResult.interfaces.created} / ~{syncResult.interfaces.updated}</span>
                    <span>Prefixes: +{syncResult.prefixes.created} / ~{syncResult.prefixes.updated}</span>
                    <span>IPs: +{syncResult.ipAddresses.created} / ~{syncResult.ipAddresses.updated}</span>
                    <span>VMs/LXCs: +{syncResult.virtualMachines.created} / ~{syncResult.virtualMachines.updated}</span>
                  </div>
                  {syncResult.warnings && syncResult.warnings.length > 0 && (
                    <div className="text-amber-300 pt-1">
                      Warnings ({syncResult.warnings.length}): {syncResult.warnings.slice(0, 3).join('; ')}
                    </div>
                  )}
                </div>
              </div>
            )}

            <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold text-white">Live K3s Workload Pods</h2>
                <Link
                  href="/k3s/explorer?resource=pods"
                  className="text-xs font-mono text-emerald-400 hover:text-emerald-300"
                >
                  Inspect in K9s &rarr;
                </Link>
              </div>
              {status?.pods && status.pods.length > 0 ? (
                <div className="space-y-2">
                  {status.pods.map((p) => (
                    <div
                      key={p.name}
                      className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between gap-2 text-xs font-mono"
                    >
                      <div className="min-w-0">
                        <div className="text-white font-semibold truncate">{p.name}</div>
                        <div className="text-[10px] text-slate-400 truncate">
                          {p.node || 'pending'} • {p.image || 'netbox'}
                        </div>
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] shrink-0 border ${
                          p.ready
                            ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                            : 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                        }`}
                      >
                        {p.phase || 'Pending'}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-slate-400 font-mono">
                  {config.enabled
                    ? 'Waiting for K3s scheduler to spin up netbox / postgres / valkey pods.'
                    : 'Enable NetBox DCIM & IPAM above to deploy pods into K3s.'}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'k3s' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
            <h2 className="text-sm font-bold text-white">K3s Deployment, Images &amp; OpenEBS PVCs</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <label className="space-y-1">
                <span className="text-slate-400">K3s Namespace</span>
                <input
                  type="text"
                  value={config.namespace}
                  onChange={(e) => setConfig((c) => ({ ...c, namespace: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                />
              </label>
              <label className="space-y-1">
                <span className="text-slate-400">FQDN / Ingress Host</span>
                <input
                  type="text"
                  value={config.domain}
                  onChange={(e) => setConfig((c) => ({ ...c, domain: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                />
              </label>
              <label className="space-y-1 sm:col-span-2">
                <span className="text-slate-400">NetBox Image</span>
                <input
                  type="text"
                  value={config.image}
                  onChange={(e) => setConfig((c) => ({ ...c, image: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                />
              </label>
              <label className="space-y-1">
                <span className="text-slate-400">PostgreSQL Image</span>
                <input
                  type="text"
                  value={config.postgresImage}
                  onChange={(e) => setConfig((c) => ({ ...c, postgresImage: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                />
              </label>
              <label className="space-y-1">
                <span className="text-slate-400">Valkey / Redis Image</span>
                <input
                  type="text"
                  value={config.valkeyImage}
                  onChange={(e) => setConfig((c) => ({ ...c, valkeyImage: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                />
              </label>
              <label className="space-y-1">
                <span className="text-slate-400">OpenEBS StorageClass</span>
                <input
                  type="text"
                  value={config.storageClass}
                  onChange={(e) => setConfig((c) => ({ ...c, storageClass: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                />
              </label>
              <label className="space-y-1">
                <span className="text-slate-400">Postgres PVC (GiB)</span>
                <input
                  type="number"
                  min={1}
                  max={2000}
                  value={config.postgresStorageGb || ''}
                  onChange={(e) =>
                    setConfig((c) => ({
                      ...c,
                      postgresStorageGb: parseNonNegativeIntInput(e.target.value, c.postgresStorageGb),
                    }))
                  }
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono tabular-nums"
                />
              </label>
              <label className="space-y-1">
                <span className="text-slate-400">Media PVC (GiB)</span>
                <input
                  type="number"
                  min={1}
                  max={2000}
                  value={config.mediaStorageGb || ''}
                  onChange={(e) =>
                    setConfig((c) => ({
                      ...c,
                      mediaStorageGb: parseNonNegativeIntInput(e.target.value, c.mediaStorageGb),
                    }))
                  }
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono tabular-nums"
                />
              </label>
              <label className="space-y-1">
                <span className="text-slate-400">Web / Worker Replicas</span>
                <div className="flex gap-2">
                  <input
                    type="number"
                    min={1}
                    max={5}
                    aria-label="Web replicas"
                    value={config.replicas || ''}
                    onChange={(e) =>
                      setConfig((c) => ({
                        ...c,
                        replicas: parseNonNegativeIntInput(e.target.value, c.replicas),
                      }))
                    }
                    className="w-1/2 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono tabular-nums"
                  />
                  <input
                    type="number"
                    min={1}
                    max={5}
                    aria-label="Worker replicas"
                    value={config.workerReplicas || ''}
                    onChange={(e) =>
                      setConfig((c) => ({
                        ...c,
                        workerReplicas: parseNonNegativeIntInput(e.target.value, c.workerReplicas),
                      }))
                    }
                    className="w-1/2 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono tabular-nums"
                  />
                </div>
              </label>
              <label className="space-y-1">
                <span className="text-slate-400">NetBox Site Name</span>
                <input
                  type="text"
                  value={config.siteName}
                  onChange={(e) => setConfig((c) => ({ ...c, siteName: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white"
                />
              </label>
              <label className="space-y-1">
                <span className="text-slate-400">Site Slug</span>
                <input
                  type="text"
                  value={config.siteSlug}
                  onChange={(e) => setConfig((c) => ({ ...c, siteSlug: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                />
              </label>
            </div>

            <div className="flex flex-wrap gap-4 pt-2 text-xs text-slate-300">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.ingressEnabled}
                  onChange={(e) => setConfig((c) => ({ ...c, ingressEnabled: e.target.checked }))}
                />
                Traefik K3s Ingress
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.ingressTls}
                  onChange={(e) => setConfig((c) => ({ ...c, ingressTls: e.target.checked }))}
                />
                Ingress TLS
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.syncUnboundDns}
                  onChange={(e) => setConfig((c) => ({ ...c, syncUnboundDns: e.target.checked }))}
                />
                Unbound Auto-DNS Override
              </label>
            </div>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-bold text-white">Bootstrap Superuser &amp; REST Token</h2>
                <p className="text-xs text-slate-400">
                  Random host credentials are generated automatically in{' '}
                  <code className="font-mono text-emerald-400">/etc/axonwall/netbox/secrets.json</code> (mode 0600).
                </p>
              </div>
              <button
                type="button"
                onClick={() => void handleToggleReveal()}
                className="px-2.5 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs font-mono text-slate-300 flex items-center gap-1.5"
              >
                {revealCreds ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                {revealCreds ? 'Hide' : 'Reveal'}
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <label className="space-y-1">
                <span className="text-slate-400">Superuser Username</span>
                <input
                  type="text"
                  value={config.superuserUsername}
                  onChange={(e) => setConfig((c) => ({ ...c, superuserUsername: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                />
              </label>
              <label className="space-y-1">
                <span className="text-slate-400">Superuser Email</span>
                <input
                  type="email"
                  value={config.superuserEmail}
                  onChange={(e) => setConfig((c) => ({ ...c, superuserEmail: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                />
              </label>
              <label className="space-y-1 sm:col-span-2">
                <span className="text-slate-400">External URL Override (optional)</span>
                <input
                  type="text"
                  placeholder="https://netbox.axonwall.local"
                  value={config.externalUrl ?? ''}
                  onChange={(e) => setConfig((c) => ({ ...c, externalUrl: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                />
              </label>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between gap-2">
                <span className="text-slate-400">Generated API Token:</span>
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-emerald-300 truncate">
                    {revealCreds ? creds?.apiToken || 'Pending deploy' : creds?.tokenPreview || 'Configured on apply'}
                  </span>
                  {revealCreds && creds?.apiToken && (
                    <button
                      type="button"
                      onClick={() => copyText('token', creds.apiToken!)}
                      className="text-slate-400 hover:text-white"
                      aria-label="Copy API Token"
                    >
                      {copiedKey === 'token' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  )}
                </div>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-slate-400">Superuser Password:</span>
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-sky-300 truncate">
                    {revealCreds ? creds?.superuserPassword || 'Pending deploy' : '••••••••••••'}
                  </span>
                  {revealCreds && creds?.superuserPassword && (
                    <button
                      type="button"
                      onClick={() => copyText('pass', creds.superuserPassword!)}
                      className="text-slate-400 hover:text-white"
                      aria-label="Copy Superuser Password"
                    >
                      {copiedKey === 'pass' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'ldap' && (
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-bold text-white">OpenLDAP Single Sign-On (`django_auth_ldap`)</h2>
              <p className="text-xs text-slate-400">
                Uses Axonwall service account <code className="font-mono text-emerald-400">{bundle.bindDn}</code> and rewrites loopback URIs to{' '}
                <code className="font-mono text-sky-400">{bundle.podLdapUrl}</code> so K3s pods reach OpenLDAP cleanly.
              </p>
            </div>
            <label className="flex items-center gap-2 text-xs font-mono text-slate-200 cursor-pointer">
              <input
                type="checkbox"
                checked={config.ldapAuth.enabled}
                onChange={(e) =>
                  setConfig((c) => ({ ...c, ldapAuth: { ...c.ldapAuth, enabled: e.target.checked } }))
                }
              />
              LDAP Auth Enabled
            </label>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            <label className="space-y-1">
              <span className="text-slate-400">LDAP URI (Appliance)</span>
              <input
                type="text"
                value={config.ldapAuth.url}
                onChange={(e) =>
                  setConfig((c) => ({ ...c, ldapAuth: { ...c.ldapAuth, url: e.target.value } }))
                }
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
              />
            </label>
            <label className="space-y-1">
              <span className="text-slate-400">Base DN (optional override)</span>
              <input
                type="text"
                placeholder={bundle.baseDn}
                value={config.ldapAuth.baseDn ?? ''}
                onChange={(e) =>
                  setConfig((c) => ({ ...c, ldapAuth: { ...c.ldapAuth, baseDn: e.target.value } }))
                }
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
              />
            </label>
            <label className="space-y-1">
              <span className="text-slate-400">Bind DN (optional override)</span>
              <input
                type="text"
                placeholder={bundle.bindDn}
                value={config.ldapAuth.bindDn ?? ''}
                onChange={(e) =>
                  setConfig((c) => ({ ...c, ldapAuth: { ...c.ldapAuth, bindDn: e.target.value } }))
                }
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
              />
            </label>
          </div>

          <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-80">
            {bundle.ldapConfigPy}
          </pre>
        </div>
      )}

      {activeTab === 'manifests' && (
        <div className="space-y-6">
          <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold text-white">
                Unbound Split-DNS Override (<code className="font-mono text-emerald-400">/etc/unbound/unbound.conf.d/netbox.conf</code>)
              </h2>
              <button
                type="button"
                onClick={() => copyText('unbound', bundle.unboundOverrides)}
                className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 hover:text-white flex items-center gap-1"
              >
                {copiedKey === 'unbound' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                Copy
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto">
              {bundle.unboundOverrides || '# Enable NetBox + Unbound Auto-DNS to emit split-DNS local-data record'}
            </pre>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold text-white">
                Compiled K3s Manifests (<code className="font-mono text-sky-400">/var/lib/rancher/k3s/server/manifests/axonwall-netbox.yaml</code>)
              </h2>
              <button
                type="button"
                onClick={() => copyText('k3s-yaml', bundle.k3sManifestsYaml)}
                className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 hover:text-white flex items-center gap-1"
              >
                {copiedKey === 'k3s-yaml' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                Copy YAML
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-96">
              {bundle.k3sManifestsYaml || '# Enable NetBox DCIM & IPAM (and core-k3s) to render K3s StatefulSets, Deployments, Services, PVCs & Ingress'}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
