'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Layers,
  GitBranch,
  Cpu,
  ShieldCheck,
  Search,
  CheckCircle2,
  AlertTriangle,
  Sparkles,
  FileCode,
  Globe,
  Lock,
  Power,
  Loader2,
  ExternalLink,
  Boxes,
  KeyRound,
} from 'lucide-react';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import { VowConfigSchema, type DesiredState, type VowConfig, type VowCdRunner } from '@axonwall/lib/schemas';
import {
  isPluginEnabled,
  enablePluginWithDependencies,
  arePluginDependenciesMet,
} from '@axonwall/lib/plugins';
import {
  VOW_APP_CATALOG,
  VOW_DEPLOYMENT_PRESETS,
  VOW_WAFFLE_BLUEPRINTS,
  VOW_ROLES,
  VOW_ROLE_PERMISSIONS,
  resolveVowAppDependencies,
  compileVowBundle,
  type VowAppCategory,
  type VowRole,
} from '@axonwall/lib/compile/vow';

const CATEGORIES: Array<'All' | VowAppCategory> = [
  'All',
  'DevOps & GitOps',
  'Security & Identity',
  'Databases & Storage',
  'Observability & Monitoring',
  'Collaboration & Business',
  'AI, ML & GPU',
  'Messaging & IoT',
];

export default function VigilantOctoWafflePage() {
  const [state, setState] = useState<DesiredState | null>(null);
  const [saving, setSaving] = useState(false);
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const [activeTab, setActiveTab] = useState<'catalog' | 'blueprints' | 'manifests' | 'authz'>('catalog');
  const [selectedCategory, setSelectedCategory] = useState<'All' | VowAppCategory>('All');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    getCurrentDesiredState()
      .then((s) => setState(s))
      .catch(() => {});
  }, []);

  const vowConfig: VowConfig = useMemo(() => {
    return state?.vow ?? VowConfigSchema.parse({ enabled: false });
  }, [state]);

  const k3sEnabled = useMemo(() => isPluginEnabled('core-k3s', state), [state]);
  const vowEnabled = useMemo(() => isPluginEnabled('vigilant-octo-waffle', state), [state]);
  const depCheck = useMemo(() => arePluginDependenciesMet('vigilant-octo-waffle', state), [state]);

  const { resolvedApps, autoAddedDependencies } = useMemo(
    () => resolveVowAppDependencies(vowConfig.enabledApps ?? []),
    [vowConfig.enabledApps]
  );

  const compiledBundle = useMemo(() => {
    if (!state) return null;
    return compileVowBundle(state);
  }, [state]);

  const totalMemoryMb = useMemo(() => {
    return resolvedApps.reduce((sum, id) => {
      const app = VOW_APP_CATALOG.find((a) => a.id === id);
      return sum + (app?.estimatedMemoryMb ?? 0);
    }, 0);
  }, [resolvedApps]);

  const filteredApps = useMemo(() => {
    return VOW_APP_CATALOG.filter((app) => {
      if (selectedCategory !== 'All' && app.category !== selectedCategory) return false;
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        app.name.toLowerCase().includes(q) ||
        app.id.toLowerCase().includes(q) ||
        app.description.toLowerCase().includes(q) ||
        app.category.toLowerCase().includes(q)
      );
    });
  }, [selectedCategory, searchQuery]);

  const saveVowConfig = async (updater: (current: VowConfig, draftState: DesiredState) => VowConfig, notice?: string) => {
    if (!state) return;
    setSaving(true);
    setBanner(null);
    try {
      const next = structuredClone(state);
      const currentVow = next.vow ?? VowConfigSchema.parse({ enabled: true });
      next.vow = updater(currentVow, next);
      const res = await applyDesiredState(next);
      setState(next);
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new Event('axonwall-capabilities-updated'));
      }
      setBanner({
        type: 'success',
        text: notice || `Vigilant Octo Waffle configuration applied (${res.message})`,
      });
    } catch (err: any) {
      setBanner({
        type: 'error',
        text: err?.message || 'Failed to save Vigilant Octo Waffle configuration',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleEnableVowWithK3s = async () => {
    if (!state) return;
    setSaving(true);
    setBanner(null);
    try {
      const { state: next, autoEnabledDependencies } = enablePluginWithDependencies('vigilant-octo-waffle', state);
      const res = await applyDesiredState(next);
      setState(next);
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new Event('axonwall-capabilities-updated'));
      }
      const depMsg =
        autoEnabledDependencies.length > 0
          ? ` (auto-enabled required dependency: ${autoEnabledDependencies.join(', ')})`
          : '';
      setBanner({
        type: 'success',
        text: `Vigilant Octo Waffle enabled${depMsg} — ${res.message}`,
      });
    } catch (err: any) {
      setBanner({
        type: 'error',
        text: err?.message || 'Failed to enable Vigilant Octo Waffle',
      });
    } finally {
      setSaving(false);
    }
  };

  const toggleApp = (appId: string) => {
    const current = new Set(vowConfig.enabledApps ?? []);
    if (current.has(appId)) {
      current.delete(appId);
    } else {
      current.add(appId);
    }
    const nextApps = Array.from(current);
    const { autoAddedDependencies: autoDeps } = resolveVowAppDependencies(nextApps);
    const depNote =
      autoDeps.length > 0 ? ` (auto-included dependencies: ${autoDeps.join(', ')})` : '';
    saveVowConfig(
      (cfg) => ({
        ...cfg,
        enabled: true,
        activePreset: 'custom',
        enabledApps: nextApps,
      }),
      `Updated VOW app selection${depNote}`
    );
  };

  const applyPreset = (presetId: VowConfig['activePreset'], apps: string[], label: string) => {
    saveVowConfig(
      (cfg) => ({
        ...cfg,
        enabled: true,
        activePreset: presetId,
        enabledApps: apps,
      }),
      `Applied preset "${label}" (${apps.length} apps)`
    );
  };

  const applyBlueprint = (blueprintId: string, apps: string[], label: string) => {
    saveVowConfig(
      (cfg) => ({
        ...cfg,
        enabled: true,
        activePreset: 'custom',
        activeBlueprint: blueprintId,
        enabledApps: Array.from(new Set(['argocd', 'certmanager', ...apps])),
      }),
      `Activated Waffle Blueprint "${label}"`
    );
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <Layers className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-2xl font-bold text-white tracking-tight">Vigilant Octo Waffle (VOW)</h1>
              <span className="px-2 py-0.5 rounded bg-sky-500/15 border border-sky-500/30 text-[10px] font-mono font-bold text-sky-300">
                Requires: core-k3s
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                  vowEnabled
                    ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                    : 'bg-slate-800 border-slate-700 text-slate-400'
                }`}
              >
                {vowEnabled ? 'ACTIVE PLATFORM' : 'STANDBY'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Cloud-Native Kubernetes GitOps & App Platform • Dual ArgoCD + FluxCD Engine • 37+ Curated Operators • Local mkcert TLS + Unbound DNS Auto-Zones
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-800 text-xs">
            <span className="text-slate-400">Active Stack RAM: </span>
            <span className="font-mono font-bold text-emerald-400">
              {(totalMemoryMb / 1024).toFixed(1)} GB ({resolvedApps.length} apps)
            </span>
          </div>
          {!vowEnabled && (
            <button
              disabled={saving}
              onClick={handleEnableVowWithK3s}
              className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-lg shadow-emerald-950/50 transition"
            >
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Power className="w-4 h-4" />}
              Enable VOW {k3sEnabled ? '' : '+ K3s Dependency'}
            </button>
          )}
        </div>
      </div>

      {/* Dependency Guard Banner if core-k3s is disabled */}
      {!depCheck.met && (
        <div className="p-4 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <h3 className="text-xs font-bold text-amber-300 uppercase tracking-wider">
                Plugin Dependency Required: Kubernetes (core-k3s)
              </h3>
              <p className="text-xs text-slate-300 mt-0.5">
                Vigilant Octo Waffle deploys GitOps controllers and Helm workloads onto the embedded Axonwall K3s cluster. Enabling VOW will automatically enable <code className="text-amber-300 font-mono">core-k3s</code>.
              </p>
            </div>
          </div>
          <button
            disabled={saving}
            onClick={handleEnableVowWithK3s}
            className="px-4 py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 text-xs font-bold shrink-0 transition"
          >
            Enable core-k3s & VOW Now
          </button>
        </div>
      )}

      {banner && (
        <div
          className={`p-3.5 rounded-xl border text-xs font-medium flex items-center justify-between ${
            banner.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
          }`}
        >
          <span>{banner.text}</span>
          <button onClick={() => setBanner(null)} className="text-slate-400 hover:text-white">
            ✕
          </button>
        </div>
      )}

      {/* Control Plane Configuration Strip */}
      <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <div>
          <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-1.5">
            GitOps CD Runner
          </label>
          <select
            value={vowConfig.cdRunner}
            onChange={(e) =>
              saveVowConfig(
                (cfg) => ({ ...cfg, cdRunner: e.target.value as VowCdRunner }),
                `Switched GitOps CD Runner to ${e.target.value.toUpperCase()}`
              )
            }
            className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white focus:border-emerald-500 focus:outline-none"
          >
            <option value="argocd">ArgoCD (Application CRDs)</option>
            <option value="flux">FluxCD v2 (Auto-Synthesized HelmReleases)</option>
            <option value="both">Dual Engine (ArgoCD + FluxCD)</option>
          </select>
        </div>

        <div>
          <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-1.5">
            Platform Ingress Domain
          </label>
          <input
            type="text"
            value={vowConfig.domain}
            onChange={(e) => {
              const val = e.target.value;
              setState((prev) =>
                prev ? { ...prev, vow: { ...(prev.vow ?? vowConfig), domain: val } } : prev
              );
            }}
            onBlur={() =>
              saveVowConfig((cfg) => ({ ...cfg, domain: vowConfig.domain || 'vow.axonwall.local' }))
            }
            className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-white focus:border-emerald-500 focus:outline-none"
          />
        </div>

        <div className="flex flex-col justify-between">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
            Local TLS (mkcert CA)
          </span>
          <button
            onClick={() =>
              saveVowConfig((cfg) => ({ ...cfg, localTlsMkcert: !cfg.localTlsMkcert }))
            }
            className={`px-3 py-2 rounded-lg border text-xs font-semibold flex items-center justify-between transition ${
              vowConfig.localTlsMkcert
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                : 'bg-slate-950 border-slate-800 text-slate-400'
            }`}
          >
            <span className="flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5" /> mkcert + Cert-Manager
            </span>
            <span>{vowConfig.localTlsMkcert ? 'ON' : 'OFF'}</span>
          </button>
        </div>

        <div className="flex flex-col justify-between">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
            Unbound DNS Auto-Zone
          </span>
          <button
            onClick={() =>
              saveVowConfig((cfg) => ({ ...cfg, syncUnboundDns: !cfg.syncUnboundDns }))
            }
            className={`px-3 py-2 rounded-lg border text-xs font-semibold flex items-center justify-between transition ${
              vowConfig.syncUnboundDns
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                : 'bg-slate-950 border-slate-800 text-slate-400'
            }`}
          >
            <span className="flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5" /> *.{vowConfig.domain}
            </span>
            <span>{vowConfig.syncUnboundDns ? 'SYNCED' : 'OFF'}</span>
          </button>
        </div>

        <div className="flex flex-col justify-between">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
            CASL Authorization
          </span>
          <button
            onClick={() =>
              saveVowConfig((cfg) => ({ ...cfg, authzEnabled: !cfg.authzEnabled }))
            }
            className={`px-3 py-2 rounded-lg border text-xs font-semibold flex items-center justify-between transition ${
              vowConfig.authzEnabled
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                : 'bg-slate-950 border-slate-800 text-slate-400'
            }`}
          >
            <span className="flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" /> 34-Perm Guard
            </span>
            <span>{vowConfig.authzEnabled ? 'ENFORCED' : 'PERMISSIVE'}</span>
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-3">
        {[
          { id: 'catalog', label: `App Catalog (${VOW_APP_CATALOG.length})`, icon: Boxes },
          { id: 'blueprints', label: 'Presets & Waffle Blueprints', icon: Sparkles },
          { id: 'manifests', label: 'Synthesized Argo / Flux / DNS Manifests', icon: FileCode },
          { id: 'authz', label: 'CASL Authorization Matrix', icon: KeyRound },
        ].map((tab) => {
          const Icon = tab.icon;
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition ${
                active
                  ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                  : 'bg-slate-900/60 text-slate-400 border border-slate-800 hover:text-white'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* TAB 1: APP CATALOG */}
      {activeTab === 'catalog' && (
        <div className="space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex flex-wrap gap-1.5">
              {CATEGORIES.map((cat) => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                    selectedCategory === cat
                      ? 'bg-emerald-600 text-white'
                      : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>

            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Filter 37+ K8s apps & operators..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-4 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none w-64"
              />
            </div>
          </div>

          {autoAddedDependencies.length > 0 && (
            <div className="p-3 rounded-xl bg-sky-500/10 border border-sky-500/20 text-xs text-sky-300 flex items-center gap-2">
              <Cpu className="w-4 h-4 shrink-0" />
              <span>
                Auto-resolved operator dependencies active:{' '}
                <strong className="font-mono">{autoAddedDependencies.join(', ')}</strong>
              </span>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredApps.map((app) => {
              const isExplicit = (vowConfig.enabledApps ?? []).includes(app.id);
              const isAutoDep = autoAddedDependencies.includes(app.id);
              const isActive = isExplicit || isAutoDep;
              const fqdn = app.subdomain ? `https://${app.subdomain}.${vowConfig.domain}` : null;

              return (
                <div
                  key={app.id}
                  className={`p-5 rounded-2xl border transition flex flex-col justify-between space-y-4 ${
                    isActive
                      ? 'bg-slate-900/95 border-emerald-500/40 shadow-md shadow-emerald-950/20'
                      : 'bg-slate-900/50 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="space-y-2.5">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <span className="text-[10px] font-semibold uppercase tracking-wider text-emerald-400">
                          {app.category}
                        </span>
                        <h3 className="text-sm font-bold text-white">{app.name}</h3>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-400">
                        {app.estimatedMemoryMb} MB
                      </span>
                    </div>

                    <p className="text-xs text-slate-400 leading-relaxed">{app.description}</p>

                    <div className="flex flex-wrap gap-1.5 pt-1">
                      <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-400">
                        ns: {app.namespace || app.id}
                      </span>
                      {app.dependencies &&
                        app.dependencies.map((dep) => (
                          <span
                            key={dep}
                            className="px-2 py-0.5 rounded bg-sky-500/10 border border-sky-500/20 text-[10px] font-mono text-sky-300"
                          >
                            dep: {dep}
                          </span>
                        ))}
                      {isAutoDep && (
                        <span className="px-2 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-[10px] font-mono text-amber-300">
                          Auto-Dependency
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between gap-2">
                    <div className="truncate text-[11px] font-mono text-slate-400">
                      {fqdn ? (
                        <a
                          href={fqdn}
                          target="_blank"
                          rel="noreferrer"
                          className="hover:text-emerald-400 flex items-center gap-1 truncate"
                        >
                          <ExternalLink className="w-3 h-3 shrink-0" />
                          {app.subdomain}.{vowConfig.domain}
                        </a>
                      ) : (
                        <span>cluster-internal</span>
                      )}
                    </div>

                    <button
                      disabled={saving}
                      onClick={() => toggleApp(app.id)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition shrink-0 ${
                        isActive
                          ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 hover:bg-rose-500/15 hover:text-rose-300 hover:border-rose-500/30'
                          : 'bg-slate-800 hover:bg-emerald-600 text-slate-200 hover:text-white'
                      }`}
                    >
                      {isActive ? 'Enabled' : 'Enable App'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 2: PRESETS & WAFFLE BLUEPRINTS */}
      {activeTab === 'blueprints' && (
        <div className="space-y-8">
          <div className="space-y-3">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              1-Click Deployment Presets
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {VOW_DEPLOYMENT_PRESETS.map((preset) => {
                const isSelected = vowConfig.activePreset === preset.id;
                return (
                  <div
                    key={preset.id}
                    className={`p-5 rounded-2xl border flex flex-col justify-between space-y-4 ${
                      isSelected
                        ? 'bg-slate-900 border-emerald-500/40'
                        : 'bg-slate-900/60 border-slate-800'
                    }`}
                  >
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <h3 className="text-sm font-bold text-white">{preset.name}</h3>
                        <span className="text-[11px] font-mono text-emerald-400">
                          ~{(preset.estimatedMemoryMb / 1024).toFixed(1)} GB RAM
                        </span>
                      </div>
                      <p className="text-xs text-slate-400">{preset.description}</p>
                      <div className="flex flex-wrap gap-1 pt-1">
                        {preset.apps.slice(0, 8).map((a) => (
                          <span
                            key={a}
                            className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-300"
                          >
                            {a}
                          </span>
                        ))}
                        {preset.apps.length > 8 && (
                          <span className="px-2 py-0.5 rounded bg-slate-950 text-[10px] font-mono text-slate-400">
                            +{preset.apps.length - 8} more
                          </span>
                        )}
                      </div>
                    </div>
                    <button
                      disabled={saving}
                      onClick={() => applyPreset(preset.id, preset.apps, preset.name)}
                      className="w-full py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition"
                    >
                      {isSelected ? 'Active Preset (Re-apply)' : `Activate ${preset.name}`}
                    </button>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="space-y-3">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Waffle Multi-Stage Architecture Blueprints (waffle.dev/v1)
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {VOW_WAFFLE_BLUEPRINTS.map((bp) => {
                const isSelected = vowConfig.activeBlueprint === bp.id;
                return (
                  <div
                    key={bp.id}
                    className={`p-5 rounded-2xl border flex flex-col justify-between space-y-4 ${
                      isSelected
                        ? 'bg-slate-900 border-emerald-500/40'
                        : 'bg-slate-900/60 border-slate-800'
                    }`}
                  >
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-sm font-bold text-white">{bp.name}</h3>
                          <span className="text-[11px] font-mono text-slate-400">
                            {bp.id} • ns: {bp.defaultNamespace} • sc: {bp.defaultStorageClass}
                          </span>
                        </div>
                        <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-[10px] font-mono text-emerald-300">
                          v{bp.version}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300">{bp.description}</p>
                      <div className="space-y-1.5">
                        {bp.stages.map((st, idx) => (
                          <div
                            key={st.id}
                            className="p-2.5 rounded-xl bg-slate-950 border border-slate-800/80 text-xs flex items-center justify-between"
                          >
                            <div>
                              <span className="font-mono text-emerald-400 mr-2">Stage {idx + 1}:</span>
                              <span className="font-semibold text-white">{st.name}</span>
                              <span className="text-slate-500 ml-2">({st.mode})</span>
                            </div>
                            <div className="flex gap-1">
                              {st.charts.map((c) => (
                                <span
                                  key={c}
                                  className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-sky-300"
                                >
                                  {c}
                                </span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                    <button
                      disabled={saving}
                      onClick={() => applyBlueprint(bp.id, bp.apps, bp.name)}
                      className="w-full py-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold transition"
                    >
                      {isSelected ? 'Blueprint Active' : 'Deploy Waffle Blueprint'}
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: SYNTHESIZED MANIFESTS */}
      {activeTab === 'manifests' && compiledBundle && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                <GitBranch className="w-3.5 h-3.5" /> ArgoCD Application CRDs (argo/*/argocd.yaml)
              </h3>
              <span className="text-[11px] font-mono text-slate-400">
                {resolvedApps.length} Applications
              </span>
            </div>
            <pre className="p-4 rounded-2xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto max-h-96">
              {compiledBundle.argoManifestsYaml}
            </pre>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider text-sky-400 flex items-center gap-1.5">
                <GitBranch className="w-3.5 h-3.5" /> Auto-Synthesized FluxCD v2 Manifests (GitRepository + HelmRelease)
              </h3>
              <span className="text-[11px] font-mono text-slate-400">
                interval: {vowConfig.fluxInterval}
              </span>
            </div>
            <pre className="p-4 rounded-2xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-sky-300 overflow-x-auto max-h-96">
              {compiledBundle.fluxManifestsYaml}
            </pre>
          </div>

          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-amber-400">
              Unbound DNS Local-Zone Overrides (/etc/unbound/unbound.conf.d/vow.conf)
            </h3>
            <pre className="p-4 rounded-2xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-amber-300 overflow-x-auto max-h-80">
              {compiledBundle.unboundOverrides}
            </pre>
          </div>

          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-purple-400">
              Compiled VOW Environment (.env.enabler)
            </h3>
            <pre className="p-4 rounded-2xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-purple-300 overflow-x-auto max-h-80">
              {compiledBundle.enablerEnv}
            </pre>
          </div>
        </div>
      )}

      {/* TAB 4: CASL AUTHORIZATION MATRIX */}
      {activeTab === 'authz' && compiledBundle && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white">CASL Role-Based Permission Bundles</h3>
                <p className="text-xs text-slate-400">
                  Paperclip-style explainable authorization model backed by <code className="font-mono">.vow/authz.yaml</code>
                </p>
              </div>
              <select
                value={vowConfig.defaultRole}
                onChange={(e) =>
                  saveVowConfig((cfg) => ({ ...cfg, defaultRole: e.target.value as VowRole }))
                }
                className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
              >
                {VOW_ROLES.map((r) => (
                  <option key={r} value={r}>
                    Default Role: {r}
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-3">
              {VOW_ROLES.map((role) => {
                const perms = VOW_ROLE_PERMISSIONS[role];
                return (
                  <div key={role} className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 font-mono">
                        {role}
                      </span>
                      <span className="text-[11px] font-mono text-slate-400">
                        {perms.length} permissions
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {perms.map((p) => (
                        <span
                          key={p}
                          className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-300"
                        >
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" /> Compiled .vow/authz.yaml Policy Store
            </h3>
            <pre className="p-4 rounded-2xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto max-h-[540px]">
              {compiledBundle.authzYaml}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
