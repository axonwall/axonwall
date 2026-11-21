'use client';

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  Activity,
  AlertTriangle,
  Binary,
  BookOpen,
  CheckCircle2,
  Cpu,
  Database,
  Download,
  Eye,
  Filter,
  Lock,
  Pin,
  Play,
  RefreshCw,
  Save,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Trash2,
  Upload,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { ThreatSketchWaveform } from '@/components/ebpf/EbpfSecurityVisualizer';
import {
  disablePluginWithDependents,
  enablePluginWithDependencies,
  isPluginEnabled,
} from '@axonwall/lib/plugins';
import {
  ThreatHarvesterConfigSchema,
  type DesiredState,
  type ThreatHarvesterConfig,
} from '@axonwall/lib/schemas';
import {
  annotateThreatHarvesterEpisodeAction,
  getCurrentDesiredState,
  getThreatHarvesterStatus,
  listThreatHarvesterEpisodes,
  reviewThreatHarvesterEpisodeAction,
  shipThreatHarvesterCorpusAction,
  simulateThreatHarvesterEpisodeAction,
  updateThreatHarvesterLiveConfigAction,
  type ThreatEpisode,
  type ThreatHarvesterStatusSnapshot,
} from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';

type TabId = 'telemetry' | 'episodes' | 'policy' | 'export';

type ScenarioId =
  | 'honeypot_rce_memfd'
  | 'dns_c2_exfil'
  | 'credential_stuffing_redacted'
  | 'benign_k3s_egress';

const SCENARIO_OPTIONS: Array<{ id: ScenarioId; label: string }> = [
  { id: 'honeypot_rce_memfd', label: 'Honeypot RCE + memfd (Gold)' },
  { id: 'dns_c2_exfil', label: 'DNS Tunnel / High-Entropy C2 (Silver)' },
  { id: 'credential_stuffing_redacted', label: 'Credential Stuffing + DLP Redaction' },
  { id: 'benign_k3s_egress', label: 'Benign K3s Registry Pull (Negative Sample)' },
];

const TIER_BADGE_MAP: Record<string, string> = {
  gold_malicious: 'bg-red-500/15 text-red-300 border-red-500/40',
  silver_malicious: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  benign_sampled: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
  unlabeled_anomaly: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40',
};

const REVIEW_BADGE_MAP: Record<string, string> = {
  pinned_gold: 'bg-purple-500/15 text-purple-300 border-purple-500/40',
  approved_malicious: 'bg-red-500/15 text-red-300 border-red-500/40',
  marked_benign: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
  pending: 'bg-slate-800 text-slate-300 border-slate-700',
};

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let val = bytes;
  let idx = 0;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  return `${val >= 100 || idx === 0 ? val.toFixed(0) : val.toFixed(2)} ${units[idx]}`;
}

function splitCsv(raw: string): string[] {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function splitPorts(raw: string): number[] {
  return raw
    .split(',')
    .map((s) => Number.parseInt(s.trim(), 10))
    .filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535);
}

export default function ThreatHarvesterPage() {
  const { applyState } = useDesiredStateApply();
  const [activeTab, setActiveTab] = useState<TabId>('telemetry');
  const [desiredState, setDesiredState] = useState<DesiredState | null>(null);
  const [status, setStatus] = useState<ThreatHarvesterStatusSnapshot | null>(null);
  const [config, setConfig] = useState<ThreatHarvesterConfig>(() => ThreatHarvesterConfigSchema.parse({}));
  const [episodes, setEpisodes] = useState<ThreatEpisode[]>([]);
  const [episodeTotal, setEpisodeTotal] = useState(0);
  const [selectedEpisodeId, setSelectedEpisodeId] = useState<string | null>(null);

  const [tierFilter, setTierFilter] = useState<string>('all');
  const [reviewFilter, setReviewFilter] = useState<string>('all');
  const [scenario, setScenario] = useState<ScenarioId>('honeypot_rce_memfd');

  // Text buffers for comma-separated policy inputs
  const [watchedIfacesText, setWatchedIfacesText] = useState('');
  const [firehoseIfacesText, setFirehoseIfacesText] = useState('');
  const [firehoseNsText, setFirehoseNsText] = useState('');
  const [canaryPortsText, setCanaryPortsText] = useState('23, 2323, 3389, 4444, 5900, 6379, 9200, 27017');
  const [uprobeAllowlistText, setUprobeAllowlistText] = useState('');

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [statusBanner, setStatusBanner] = useState<{ kind: 'ok' | 'warn' | 'err'; text: string } | null>(null);

  const syncPolicyTextBuffers = useCallback((cfg: ThreatHarvesterConfig) => {
    setWatchedIfacesText((cfg.watchedInterfaces || []).join(', '));
    setFirehoseIfacesText((cfg.firehoseInterfaces || []).join(', '));
    setFirehoseNsText((cfg.firehoseNamespaces || []).join(', '));
    setCanaryPortsText((cfg.canaryPorts || []).join(', '));
    setUprobeAllowlistText((cfg.tlsUprobeAllowlist || []).join(', '));
  }, []);

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [st, snap, epRes] = await Promise.all([
        getCurrentDesiredState().catch(() => null),
        getThreatHarvesterStatus(),
        listThreatHarvesterEpisodes({ tier: tierFilter, reviewStatus: reviewFilter, limit: 150 }),
      ]);
      if (st) {
        setDesiredState(st);
      }
      setStatus(snap);
      const mergedCfg = ThreatHarvesterConfigSchema.parse(st?.threatHarvester ?? snap.config ?? {});
      setConfig(mergedCfg);
      syncPolicyTextBuffers(mergedCfg);
      setEpisodes(epRes.episodes || []);
      setEpisodeTotal(epRes.total || 0);
      setSelectedEpisodeId((prev) => {
        if (prev && epRes.episodes.some((e) => e.id === prev)) return prev;
        return epRes.episodes[0]?.id ?? null;
      });
    } catch (err: any) {
      setStatusBanner({ kind: 'err', text: `Failed to load harvester telemetry: ${err?.message || String(err)}` });
    } finally {
      setLoading(false);
    }
  }, [reviewFilter, syncPolicyTextBuffers, tierFilter]);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const pluginEnabled = useMemo(() => {
    if (desiredState) {
      return isPluginEnabled('ebpf-threat-harvester', desiredState);
    }
    return Boolean(status?.config?.enabled);
  }, [desiredState, status]);

  const selectedEpisode = useMemo(() => {
    return episodes.find((e) => e.id === selectedEpisodeId) ?? episodes[0] ?? null;
  }, [episodes, selectedEpisodeId]);

  const buildMergedConfig = useCallback((): ThreatHarvesterConfig => {
    return ThreatHarvesterConfigSchema.parse({
      ...config,
      watchedInterfaces: splitCsv(watchedIfacesText),
      firehoseInterfaces: splitCsv(firehoseIfacesText),
      firehoseNamespaces: splitCsv(firehoseNsText),
      canaryPorts: splitPorts(canaryPortsText),
      tlsUprobeAllowlist: splitCsv(uprobeAllowlistText),
    });
  }, [canaryPortsText, config, firehoseIfacesText, firehoseNsText, uprobeAllowlistText, watchedIfacesText]);

  const handleToggleOptIn = async () => {
    if (!desiredState) return;
    setSaving(true);
    setStatusBanner(null);
    try {
      const currentCfg = buildMergedConfig();
      const toggled = pluginEnabled
        ? disablePluginWithDependents('ebpf-threat-harvester', { ...desiredState, threatHarvester: currentCfg })
        : enablePluginWithDependencies('ebpf-threat-harvester', { ...desiredState, threatHarvester: currentCfg });
      const nextCfg = ThreatHarvesterConfigSchema.parse({
        ...currentCfg,
        enabled: !pluginEnabled,
      });
      const nextState: DesiredState = {
        ...toggled.state,
        threatHarvester: nextCfg,
      };
      const applyRes = await applyState(nextState);
      if (!applyRes.success) {
        throw new Error(applyRes.message || 'Failed to apply desired state');
      }
      const liveRes = await updateThreatHarvesterLiveConfigAction(nextCfg);
      setDesiredState(nextState);
      setConfig(nextCfg);
      if (liveRes.status) {
        setStatus(liveRes.status);
      }
      setStatusBanner({
        kind: liveRes.success ? 'ok' : 'warn',
        text: liveRes.success
          ? `Axonwall Blackbox harvester ${!pluginEnabled ? 'enabled' : 'disabled'} in DesiredState and live daemon.`
          : `Saved DesiredState toggle, but live daemon returned: ${liveRes.error || 'unreachable'}`,
      });
      await loadAll();
    } catch (err: any) {
      setStatusBanner({ kind: 'err', text: `Toggle failed: ${err?.message || String(err)}` });
    } finally {
      setSaving(false);
    }
  };

  const handleSavePolicy = async () => {
    setSaving(true);
    setStatusBanner(null);
    try {
      const nextCfg = buildMergedConfig();
      if (desiredState) {
        const baseToggle = nextCfg.enabled
          ? enablePluginWithDependencies('ebpf-threat-harvester', desiredState).state
          : disablePluginWithDependents('ebpf-threat-harvester', desiredState).state;
        const nextState: DesiredState = {
          ...baseToggle,
          threatHarvester: nextCfg,
        };
        const applyRes = await applyState(nextState);
        if (!applyRes.success) {
          throw new Error(applyRes.message || 'DesiredState apply rejected');
        }
        setDesiredState(nextState);
      }
      const liveRes = await updateThreatHarvesterLiveConfigAction(nextCfg);
      setConfig(nextCfg);
      syncPolicyTextBuffers(nextCfg);
      if (liveRes.status) {
        setStatus(liveRes.status);
      }
      setStatusBanner({
        kind: liveRes.success ? 'ok' : 'warn',
        text: liveRes.success
          ? 'Saved Threat Harvester policy to security.yaml & synchronized live Ring-0 eBPF collector.'
          : `Saved DesiredState, but live daemon sync returned: ${liveRes.error || 'unreachable'}`,
      });
    } catch (err: any) {
      setStatusBanner({ kind: 'err', text: `Policy save failed: ${err?.message || String(err)}` });
    } finally {
      setSaving(false);
    }
  };

  const handleSimulate = async () => {
    setBusyAction('simulate');
    setStatusBanner(null);
    try {
      const res = await simulateThreatHarvesterEpisodeAction(scenario);
      if (!res.success || !res.episode) {
        throw new Error(res.error || 'Failed to synthesize episode');
      }
      setStatusBanner({
        kind: 'ok',
        text: `Synthesized ${res.episode.labelTier} episode ${res.episode.id} (${scenario}, ${res.episode.redactionCount} secrets scrubbed).`,
      });
      setSelectedEpisodeId(res.episode.id);
      await loadAll();
    } catch (err: any) {
      setStatusBanner({ kind: 'err', text: `Simulation failed: ${err?.message || String(err)}` });
    } finally {
      setBusyAction(null);
    }
  };

  const handleReviewEpisode = async (
    id: string,
    action: 'pinned_gold' | 'approved_malicious' | 'marked_benign' | 'delete'
  ) => {
    setBusyAction(`review:${id}`);
    setStatusBanner(null);
    try {
      const res = await reviewThreatHarvesterEpisodeAction({ id, action });
      if (!res.success) {
        throw new Error(res.error || 'Review action failed');
      }
      setStatusBanner({ kind: 'ok', text: `Updated episode ${id} -> ${action}.` });
      await loadAll();
    } catch (err: any) {
      setStatusBanner({ kind: 'err', text: `Review update failed: ${err?.message || String(err)}` });
    } finally {
      setBusyAction(null);
    }
  };

  const handleAnnotateEpisode = async (id: string) => {
    setBusyAction(`annotate:${id}`);
    setStatusBanner(null);
    try {
      const res = await annotateThreatHarvesterEpisodeAction(id);
      if (!res.success) {
        throw new Error(res.error || 'Teacher-LLM annotation failed');
      }
      setStatusBanner({ kind: 'ok', text: `Teacher-LLM enriched reasoning trace for episode ${id}.` });
      await loadAll();
    } catch (err: any) {
      setStatusBanner({ kind: 'err', text: `Teacher-LLM annotate failed: ${err?.message || String(err)}` });
    } finally {
      setBusyAction(null);
    }
  };

  const handleDownloadExport = async () => {
    setBusyAction('export');
    setStatusBanner(null);
    try {
      const url = `/api/v1/security/threat-harvester/export?anonymize=${config.anonymizeOnExport ? 'true' : 'false'}`;
      const resp = await fetch(url);
      if (!resp.ok) {
        const errBody = await resp.json().catch(() => null);
        throw new Error(errBody?.error || `Export returned HTTP ${resp.status}`);
      }
      const blob = await resp.blob();
      const objUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = objUrl;
      a.download = `axonwall-threat-corpus-${config.anonymizeOnExport ? 'anon' : 'raw'}.tar.zst`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(objUrl);
      setStatusBanner({
        kind: 'ok',
        text: `Downloaded ${formatBytes(blob.size)} Dual-Track .tar.zst corpus (${config.anonymizeOnExport ? 'Crypto-PAn + HMAC anonymized' : 'raw internal IPs'}).`,
      });
    } catch (err: any) {
      setStatusBanner({ kind: 'err', text: `Export failed: ${err?.message || String(err)}` });
    } finally {
      setBusyAction(null);
    }
  };

  const handleShipNow = async () => {
    setBusyAction('ship');
    setStatusBanner(null);
    try {
      const res = await shipThreatHarvesterCorpusAction();
      if (!res.success) {
        throw new Error(res.error || 'Fleet S3 ship failed');
      }
      setStatusBanner({
        kind: 'ok',
        text: `Shipped anonymized Dual-Track .tar.zst corpus to ${res.objectKey || 'S3/Vault bucket'}.`,
      });
      await loadAll();
    } catch (err: any) {
      setStatusBanner({ kind: 'err', text: `Fleet ship failed: ${err?.message || String(err)}` });
    } finally {
      setBusyAction(null);
    }
  };

  const stats = status?.stats;
  const quotaPct =
    stats && stats.spoolQuotaBytes > 0
      ? Math.min(100, Math.round((stats.spoolUsedBytes / stats.spoolQuotaBytes) * 100))
      : 0;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 text-slate-100">
      {/* Header Banner */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 bg-slate-900/90 border border-slate-800 rounded-2xl p-6">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Binary className="w-6 h-6" />
            </span>
            <h1 className="text-2xl font-bold tracking-tight text-white">
              Axonwall Blackbox: eBPF Threat-LLM Harvester
            </h1>
            <span
              className={`px-2.5 py-0.5 text-xs font-mono font-semibold rounded-full border ${
                pluginEnabled
                  ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40'
                  : 'bg-slate-800 text-slate-300 border-slate-700'
              }`}
            >
              {pluginEnabled ? 'OPT-IN ACTIVE' : 'OPT-IN DISABLED'}
            </span>
            <span className="px-2.5 py-0.5 text-xs font-mono rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
              MODE: {config.captureMode.toUpperCase()}
            </span>
            {status?.bpfAttached ? (
              <span className="px-2.5 py-0.5 text-xs font-mono rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                RING-0 ATTACHED ({(status.activeHooks || []).length} hooks)
              </span>
            ) : (
              <span className="px-2.5 py-0.5 text-xs font-mono rounded-full bg-amber-500/15 text-amber-300 border border-amber-500/30">
                {status?.daemonDown ? 'DAEMON OFFLINE' : 'RING-0 STANDBY'}
              </span>
            )}
          </div>
          <p className="text-sm text-slate-400 max-w-3xl">
            Opt-in Ring-0 flight recorder correlating wire-plane{' '}
            <code className="text-cyan-300">TCX</code> flow sketches,{' '}
            <code className="text-amber-300">sched_process_exec</code> +{' '}
            <code className="text-red-300">memfd_create</code> host lineage, and guarded TLS uprobes
            with mandatory pre-disk DLP scrubbing into Dual-Track{' '}
            <strong className="text-slate-200">Causal Episode SFT/RLVR JSONL + Apache Parquet</strong>{' '}
            training corpora.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <Link
            href="/docs/threat-harvester"
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
          >
            <BookOpen className="w-4 h-4 text-cyan-400" />
            Blackbox Guide
          </Link>
          <button
            type="button"
            onClick={handleToggleOptIn}
            disabled={saving || !desiredState}
            className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold border transition ${
              pluginEnabled
                ? 'bg-red-500/15 hover:bg-red-500/25 text-red-300 border-red-500/40'
                : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 border-emerald-400'
            }`}
          >
            <Shield className="w-4 h-4" />
            {pluginEnabled ? 'Disable Blackbox Harvester' : 'Enable Opt-In Harvester'}
          </button>

          <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 rounded-lg p-1">
            <select
              value={scenario}
              onChange={(e) => setScenario(e.target.value as ScenarioId)}
              className="bg-transparent text-xs text-slate-200 px-2 py-1 focus:outline-none"
            >
              {SCENARIO_OPTIONS.map((opt) => (
                <option key={opt.id} value={opt.id} className="bg-slate-900">
                  {opt.label}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={handleSimulate}
              disabled={busyAction !== null}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/30 transition"
            >
              <Play className="w-3.5 h-3.5" />
              {busyAction === 'simulate' ? 'Synthesizing...' : 'Simulate Episode'}
            </button>
          </div>

          <button
            type="button"
            onClick={() => void loadAll()}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Status Banner */}
      {statusBanner && (
        <div
          className={`p-3.5 rounded-xl border text-xs font-mono flex items-center justify-between gap-3 ${
            statusBanner.kind === 'err'
              ? 'bg-red-950/60 border-red-500/50 text-red-200'
              : statusBanner.kind === 'warn'
                ? 'bg-amber-950/50 border-amber-500/50 text-amber-200'
                : 'bg-emerald-950/50 border-emerald-500/40 text-emerald-200'
          }`}
        >
          <div className="flex items-center gap-2.5">
            {statusBanner.kind === 'err' ? (
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            )}
            <span>{statusBanner.text}</span>
          </div>
          <button
            type="button"
            onClick={() => setStatusBanner(null)}
            className="text-slate-400 hover:text-slate-200 text-xs"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
        {(
          [
            { id: 'telemetry', label: 'Flight Recorder & Ring-0 Telemetry', icon: Activity },
            { id: 'episodes', label: `Causal Episodes & Review Queue (${episodeTotal})`, icon: Eye },
            { id: 'policy', label: 'Capture Policy & TLS Uprobes', icon: Cpu },
            { id: 'export', label: 'Dataset Export & Vault S3 Lake', icon: Database },
          ] as const
        ).map((tab) => {
          const Icon = tab.icon;
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold border transition ${
                active
                  ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40'
                  : 'bg-slate-900/70 text-slate-400 border-slate-800 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* TAB 1: Flight Recorder & Ring-0 Telemetry */}
      {activeTab === 'telemetry' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-1.5">
              <div className="text-xs text-slate-400 uppercase tracking-wider">Wire &amp; Ringbuf Throughput</div>
              <div className="text-2xl font-bold font-mono text-white">
                {(stats?.packetsSeen ?? 0).toLocaleString()} <span className="text-xs text-slate-400">pkts</span>
              </div>
              <div className="text-xs font-mono text-slate-400 flex items-center justify-between">
                <span>Drops: {stats?.ringbufDrops ?? 0}</span>
                <span className={stats?.backpressureTripped ? 'text-red-400 font-semibold' : 'text-emerald-400'}>
                  {stats?.backpressureTripped ? 'CIRCUIT BREAKER TRIPPED' : 'Backpressure OK'}
                </span>
              </div>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-1.5">
              <div className="text-xs text-slate-400 uppercase tracking-wider">Two-Tier Flight Recorder</div>
              <div className="text-2xl font-bold font-mono text-cyan-300">
                {stats?.tier0Events ?? 0} <span className="text-xs text-slate-400">Tier-0</span> /{' '}
                <span className="text-amber-300">{stats?.tier1PayloadEvents ?? 0}</span>{' '}
                <span className="text-xs text-slate-400">Tier-1</span>
              </div>
              <div className="text-xs font-mono text-slate-400">
                Dark Ports: {stats?.darkPortHits ?? 0} | memfd: {stats?.memfdAlerts ?? 0} | Uprobe:{' '}
                {stats?.tlsUprobeEvents ?? 0}
              </div>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-1.5">
              <div className="text-xs text-slate-400 uppercase tracking-wider">Oracle Episode Corpus</div>
              <div className="text-2xl font-bold font-mono text-white">
                {stats?.totalEpisodes ?? 0} <span className="text-xs text-slate-400">episodes</span>
              </div>
              <div className="text-xs font-mono text-slate-400">
                <span className="text-red-300">Gold {stats?.goldEpisodes ?? 0}</span> ·{' '}
                <span className="text-amber-300">Silver {stats?.silverEpisodes ?? 0}</span> ·{' '}
                <span className="text-emerald-300">Benign {stats?.benignEpisodes ?? 0}</span> ·{' '}
                <span className="text-purple-300">Pinned {stats?.pinnedEpisodes ?? 0}</span>
              </div>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400 uppercase tracking-wider">
                <span>DLP &amp; Spool Quota</span>
                <span className="text-cyan-300 font-mono">
                  {stats?.zfsBacked ? 'OpenZFS zstd' : 'Local Spool'}
                </span>
              </div>
              <div className="text-lg font-bold font-mono text-white">
                {formatBytes(stats?.spoolUsedBytes ?? 0)}{' '}
                <span className="text-xs text-slate-400">/ {formatBytes(stats?.spoolQuotaBytes ?? 0)}</span>
              </div>
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full ${quotaPct > 85 ? 'bg-red-500' : 'bg-cyan-500'}`}
                  style={{ width: `${quotaPct}%` }}
                />
              </div>
              <div className="text-xs font-mono text-emerald-300">
                Pre-disk secrets scrubbed: {stats?.redactedSecrets ?? 0}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold text-white flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  Ring-0 eBPF Hooks &amp; Attached Interfaces
                </h2>
                <span className="text-xs font-mono text-slate-400">
                  Window: {config.correlationWindowSec}s | Max Slice: {config.maxPayloadBytes} B
                </span>
              </div>
              {status?.bpfLoadError && (
                <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-500/30 text-xs font-mono text-amber-200">
                  Kernel load notice: {status.bpfLoadError}
                </div>
              )}
              <div className="space-y-2">
                <div className="text-xs text-slate-400">Active eBPF Programs</div>
                <div className="flex flex-wrap gap-2">
                  {(status?.activeHooks?.length ? status.activeHooks : ['(standby — enable opt-in plugin on host)']).map(
                    (hook) => (
                      <span
                        key={hook}
                        className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300"
                      >
                        {hook}
                      </span>
                    )
                  )}
                </div>
              </div>
              <div className="space-y-2">
                <div className="text-xs text-slate-400">TCX Attached Interfaces</div>
                <div className="flex flex-wrap gap-2">
                  {(status?.attachedInterfaces?.length
                    ? status.attachedInterfaces
                    : ['(none attached yet)']
                  ).map((iface) => (
                    <span
                      key={iface}
                      className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-300"
                    >
                      {iface}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold text-white flex items-center gap-2">
                  <Lock className="w-4 h-4 text-emerald-400" />
                  Control-Plane TLS Uprobe Exclusion Guard
                </h2>
                <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                  HARDCODED ENFORCEMENT
                </span>
              </div>
              <p className="text-xs text-slate-400">
                To prevent key material leakage and observer feedback loops, <code className="text-cyan-300">uprobe/SSL_write</code>{' '}
                is unconditionally blocked for these Axonwall control-plane daemons even if specified in an allowlist:
              </p>
              <div className="flex flex-wrap gap-2">
                {(status?.excludedUprobeDaemons || []).map((daemon) => (
                  <span
                    key={daemon}
                    className="px-2.5 py-1 rounded-lg bg-red-950/30 border border-red-500/30 text-xs font-mono text-red-200"
                  >
                    {daemon}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Ring-0 Signal & Corpus Visualizations */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-7 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold text-white">Ring-0 Capture Signal Distribution</h2>
                <span className="text-xs font-mono tabular-nums text-cyan-300">
                  {(stats?.packetsSeen ?? 0).toLocaleString()} pkts inspected
                </span>
              </div>
              <div className="h-[210px]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={[
                      { signal: 'Tier-0 Sketches', count: stats?.tier0Events ?? 0, fill: '#06b6d4' },
                      { signal: 'Tier-1 Payloads', count: stats?.tier1PayloadEvents ?? 0, fill: '#f59e0b' },
                      { signal: 'Dark-Port Hits', count: stats?.darkPortHits ?? 0, fill: '#f43f5e' },
                      { signal: 'Memfd Alerts', count: stats?.memfdAlerts ?? 0, fill: '#ef4444' },
                      { signal: 'TLS Uprobes', count: stats?.tlsUprobeEvents ?? 0, fill: '#a855f7' },
                      { signal: 'DLP Redactions', count: stats?.redactedSecrets ?? 0, fill: '#10b981' },
                    ]}
                    layout="vertical"
                    margin={{ left: 10, right: 16 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                    <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                    <YAxis type="category" dataKey="signal" width={118} tick={{ fill: '#cbd5e1', fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        borderColor: '#334155',
                        borderRadius: '0.5rem',
                        fontSize: '12px',
                        color: '#f1f5f9',
                      }}
                    />
                    <Bar dataKey="count" name="Events" radius={[0, 4, 4, 0]}>
                      {[
                        '#06b6d4',
                        '#f59e0b',
                        '#f43f5e',
                        '#ef4444',
                        '#a855f7',
                        '#10b981',
                      ].map((color, idx) => (
                        <Cell key={idx} fill={color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="lg:col-span-5 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold text-white">Oracle Episode Corpus Mix</h2>
                <span className="text-xs font-mono tabular-nums text-slate-300">
                  {stats?.totalEpisodes ?? 0} total
                </span>
              </div>
              {(stats?.totalEpisodes ?? 0) === 0 ? (
                <div className="h-[210px] flex items-center justify-center text-xs text-slate-400">
                  No episodes spooled yet. Capture live threats or run a scenario simulation above.
                </div>
              ) : (
                <div className="h-[210px]">
                  <ResponsiveContainer width="100%" height="100%">
                    {(() => {
                      const corpusSlices = [
                        { name: 'Gold Malicious', value: stats?.goldEpisodes ?? 0, fill: '#f43f5e' },
                        { name: 'Silver Malicious', value: stats?.silverEpisodes ?? 0, fill: '#f59e0b' },
                        { name: 'Benign Sampled', value: stats?.benignEpisodes ?? 0, fill: '#10b981' },
                        {
                          name: 'Unlabeled Anomaly',
                          value: Math.max(
                            0,
                            (stats?.totalEpisodes ?? 0) -
                              (stats?.goldEpisodes ?? 0) -
                              (stats?.silverEpisodes ?? 0) -
                              (stats?.benignEpisodes ?? 0)
                          ),
                          fill: '#06b6d4',
                        },
                      ].filter((s) => s.value > 0);
                      return (
                        <PieChart>
                          <Pie
                            data={corpusSlices}
                            dataKey="value"
                            nameKey="name"
                            cx="50%"
                            cy="50%"
                            innerRadius={45}
                            outerRadius={75}
                            paddingAngle={2}
                          >
                            {corpusSlices.map((s) => (
                              <Cell key={s.name} fill={s.fill} />
                            ))}
                          </Pie>
                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#0f172a',
                              borderColor: '#334155',
                              borderRadius: '0.5rem',
                              fontSize: '12px',
                              color: '#f1f5f9',
                            }}
                          />
                          <Legend wrapperStyle={{ fontSize: '11px' }} />
                        </PieChart>
                      );
                    })()}
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Causal Episodes & Review Queue */}
      {activeTab === 'episodes' && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/80 border border-slate-800 rounded-xl p-4">
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-2 text-xs text-slate-300">
                <Filter className="w-4 h-4 text-cyan-400" />
                <span>Label Tier:</span>
                <select
                  value={tierFilter}
                  onChange={(e) => setTierFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200"
                >
                  <option value="all">All Tiers</option>
                  <option value="gold_malicious">Gold Malicious</option>
                  <option value="silver_malicious">Silver Malicious</option>
                  <option value="benign_sampled">Benign Sampled</option>
                  <option value="unlabeled_anomaly">Unlabeled Anomaly</option>
                </select>
              </div>
              <div className="flex items-center gap-2 text-xs text-slate-300">
                <span>Review Status:</span>
                <select
                  value={reviewFilter}
                  onChange={(e) => setReviewFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200"
                >
                  <option value="all">All Statuses</option>
                  <option value="pending">Pending ({stats?.pendingReview ?? 0})</option>
                  <option value="pinned_gold">Pinned Gold ({stats?.pinnedEpisodes ?? 0})</option>
                  <option value="approved_malicious">Approved Malicious</option>
                  <option value="marked_benign">Marked Benign</option>
                </select>
              </div>
            </div>
            <div className="text-xs font-mono text-slate-400">
              Showing {episodes.length} of {episodeTotal} episodes
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* Episode List */}
            <div className="lg:col-span-5 bg-slate-900/80 border border-slate-800 rounded-2xl divide-y divide-slate-800 max-h-[680px] overflow-y-auto">
              {episodes.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-400 space-y-2">
                  <p>No threat episodes match this filter yet.</p>
                  <p>Use &quot;Simulate Episode&quot; above to seed a scrubbed Gold, Silver, or Benign example.</p>
                </div>
              ) : (
                episodes.map((ep) => {
                  const isSelected = selectedEpisode?.id === ep.id;
                  return (
                    <button
                      key={ep.id}
                      type="button"
                      onClick={() => setSelectedEpisodeId(ep.id)}
                      className={`w-full text-left p-4 transition space-y-1.5 ${
                        isSelected ? 'bg-cyan-500/10' : 'hover:bg-slate-800/40'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs font-bold text-white truncate">{ep.id}</span>
                        <div className="flex items-center gap-1.5 shrink-0">
                          {ep.pinned && <Pin className="w-3.5 h-3.5 text-purple-400" />}
                          <span
                            className={`px-2 py-0.5 text-[10px] font-mono rounded border ${
                              TIER_BADGE_MAP[ep.labelTier] || TIER_BADGE_MAP.unlabeled_anomaly
                            }`}
                          >
                            {ep.labelTier}
                          </span>
                        </div>
                      </div>
                      <div className="text-xs font-mono text-slate-300">
                        {ep.srcIp}:{ep.srcPort} -&gt; {ep.dstIp}:{ep.dstPort} ({ep.protoName})
                      </div>
                      <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-slate-400">
                        <span>score {ep.verdictScore.toFixed(2)}</span>
                        <span>| {ep.pktCount} pkts</span>
                        {ep.procComm && <span>| proc {ep.procComm}</span>}
                        {ep.memfdExec && <span className="text-red-400 font-semibold">[MEMFD]</span>}
                        {ep.redactionCount > 0 && (
                          <span className="text-emerald-400">[{ep.redactionCount} scrubbed]</span>
                        )}
                      </div>
                    </button>
                  );
                })
              )}
            </div>

            {/* Episode Inspector */}
            <div className="lg:col-span-7 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-5">
              {!selectedEpisode ? (
                <div className="py-20 text-center text-xs text-slate-400">
                  Select an episode from the queue to inspect its multi-plane eBPF vector, Causal DSL, SFT reasoning trace, and redacted L7 slice.
                </div>
              ) : (
                <>
                  <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800 pb-4">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="font-mono text-sm font-bold text-white">{selectedEpisode.id}</h3>
                        <span
                          className={`px-2 py-0.5 text-[11px] font-mono rounded border ${
                            REVIEW_BADGE_MAP[selectedEpisode.reviewStatus] || REVIEW_BADGE_MAP.pending
                          }`}
                        >
                          {selectedEpisode.reviewStatus}
                        </span>
                        {(selectedEpisode.mitreAttack || []).map((t) => (
                          <span
                            key={t}
                            className="px-2 py-0.5 text-[11px] font-mono rounded bg-slate-950 border border-slate-700 text-amber-300"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                      <div className="text-xs text-slate-400 mt-1 font-mono">
                        Captured {selectedEpisode.createdAt} | Oracles:{' '}
                        {(selectedEpisode.oracleSources || []).join(', ') || 'none'}
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-1.5">
                      <button
                        type="button"
                        onClick={() => void handleReviewEpisode(selectedEpisode.id, 'pinned_gold')}
                        disabled={busyAction !== null}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-purple-500/20 hover:bg-purple-500/30 text-purple-200 border border-purple-500/40"
                      >
                        <Pin className="w-3.5 h-3.5" />
                        Pin Gold
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleReviewEpisode(selectedEpisode.id, 'approved_malicious')}
                        disabled={busyAction !== null}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-red-500/20 hover:bg-red-500/30 text-red-200 border border-red-500/40"
                      >
                        <ShieldAlert className="w-3.5 h-3.5" />
                        Malicious
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleReviewEpisode(selectedEpisode.id, 'marked_benign')}
                        disabled={busyAction !== null}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-200 border border-emerald-500/40"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        Benign
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleAnnotateEpisode(selectedEpisode.id)}
                        disabled={busyAction !== null}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-200 border border-cyan-500/40"
                      >
                        <Sparkles className="w-3.5 h-3.5" />
                        Teacher-LLM
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleReviewEpisode(selectedEpisode.id, 'delete')}
                        disabled={busyAction !== null}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-red-950/60 text-slate-300 hover:text-red-300 border border-slate-700"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Features Grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                    <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5">
                      <div className="text-[10px] text-slate-500">JA4T / SNI</div>
                      <div className="text-cyan-300 truncate">{selectedEpisode.ja4t || '-'}</div>
                      <div className="text-slate-400 truncate">{selectedEpisode.sni || 'no sni'}</div>
                    </div>
                    <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5">
                      <div className="text-[10px] text-slate-500">PROCESS LINEAGE</div>
                      <div className="text-white truncate">
                        {selectedEpisode.procComm || 'wire-only'} ({selectedEpisode.procPid || 0})
                      </div>
                      <div className="text-slate-400 truncate">cgroup {selectedEpisode.cgroupId}</div>
                    </div>
                    <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5">
                      <div className="text-[10px] text-slate-500">FLOW METRICS</div>
                      <div className="text-white">
                        {selectedEpisode.pktCount} pkts / {formatBytes(selectedEpisode.byteCount)}
                      </div>
                      <div className="text-slate-400">
                        {selectedEpisode.durationMs.toFixed(1)} ms | H={selectedEpisode.dnsEntropy.toFixed(2)}
                      </div>
                    </div>
                    <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5">
                      <div className="text-[10px] text-slate-500">RECOMMENDED TOOL</div>
                      <div className="text-amber-300 truncate">
                        {selectedEpisode.recommendedMcpTool || 'none (monitor)'}
                      </div>
                      <div className="text-emerald-300">redacted: {selectedEpisode.redactionCount}</div>
                    </div>
                  </div>

                  {/* Packet Sketch & IAT Waveform */}
                  <ThreatSketchWaveform
                    pktSizes={selectedEpisode.pktSizes}
                    iatUs={selectedEpisode.iatUs}
                  />

                  {/* Causal DSL */}
                  <div className="space-y-1.5">
                    <div className="text-xs font-semibold text-slate-300">Chronological Causal Episode DSL (SFT Input)</div>
                    <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 whitespace-pre-wrap overflow-x-auto max-h-48">
                      {selectedEpisode.causalDsl}
                    </pre>
                  </div>

                  {/* SFT Reasoning Trace */}
                  <div className="space-y-1.5">
                    <div className="text-xs font-semibold text-slate-300">SFT / Teacher-LLM Reasoning Trace (Target)</div>
                    <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-200 whitespace-pre-wrap overflow-x-auto max-h-40">
                      {selectedEpisode.reasoningTrace}
                    </pre>
                  </div>

                  {/* Redacted Payload Slice */}
                  {selectedEpisode.scrubbedPayload && (
                    <div className="space-y-1.5">
                      <div className="text-xs font-semibold text-slate-300">
                        Pre-Disk DLP-Scrubbed Payload Slice ({selectedEpisode.redactionCount} redactions)
                      </div>
                      <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-amber-200 whitespace-pre-wrap break-all overflow-x-auto max-h-40">
                        {selectedEpisode.scrubbedPayload}
                      </pre>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Capture Policy & TLS Uprobes */}
      {activeTab === 'policy' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
              <h2 className="text-sm font-bold text-white">Adaptive Flight Recorder &amp; Escalation</h2>

              <label className="block space-y-1">
                <span className="text-xs text-slate-300">Capture Mode</span>
                <select
                  value={config.captureMode}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      captureMode: e.target.value as ThreatHarvesterConfig['captureMode'],
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white"
                >
                  <option value="adaptive">adaptive — Tier-0 Sketches + Retroactive Tier-1 Escalation</option>
                  <option value="firehose">firehose — Continuous L7 Slice Capture on Watched Scope</option>
                  <option value="honeypot_only">honeypot_only — Capture Canary Dark-Ports &amp; MCP Honeypots Only</option>
                </select>
              </label>

              <label className="block space-y-1">
                <span className="text-xs text-slate-300">Watched Interfaces (CSV, empty = WAN/all uplinks)</span>
                <input
                  type="text"
                  value={watchedIfacesText}
                  onChange={(e) => setWatchedIfacesText(e.target.value)}
                  placeholder="wan0, eth0"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                />
              </label>

              <label className="block space-y-1">
                <span className="text-xs text-slate-300">Firehose Override Interfaces (CSV)</span>
                <input
                  type="text"
                  value={firehoseIfacesText}
                  onChange={(e) => setFirehoseIfacesText(e.target.value)}
                  placeholder="eth2, dmz0"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                />
              </label>

              <label className="block space-y-1">
                <span className="text-xs text-slate-300">Firehose K3s Namespaces (CSV)</span>
                <input
                  type="text"
                  value={firehoseNsText}
                  onChange={(e) => setFirehoseNsText(e.target.value)}
                  placeholder="honeypot, ingress-dmz"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                />
              </label>

              <label className="block space-y-1">
                <span className="text-xs text-slate-300">Canary Dark-Ports (CSV TCP/UDP Ports)</span>
                <input
                  type="text"
                  value={canaryPortsText}
                  onChange={(e) => setCanaryPortsText(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                />
              </label>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <label className="block space-y-1">
                  <span className="text-xs text-slate-300">Max Payload Bytes</span>
                  <input
                    type="number"
                    min={256}
                    max={65536}
                    value={config.maxPayloadBytes}
                    onChange={(e) => setConfig({ ...config, maxPayloadBytes: Number(e.target.value) || 4096 })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                  />
                </label>
                <label className="block space-y-1">
                  <span className="text-xs text-slate-300">Oracle Window (s)</span>
                  <input
                    type="number"
                    min={5}
                    max={300}
                    value={config.correlationWindowSec}
                    onChange={(e) => setConfig({ ...config, correlationWindowSec: Number(e.target.value) || 45 })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                  />
                </label>
                <label className="block space-y-1">
                  <span className="text-xs text-slate-300">Benign Sample Rate</span>
                  <input
                    type="number"
                    step="0.001"
                    min={0}
                    max={1}
                    value={config.benignSampleRate}
                    onChange={(e) => setConfig({ ...config, benignSampleRate: Number(e.target.value) || 0 })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                  />
                </label>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <label className="block space-y-1">
                  <span className="text-xs text-slate-300">Spool Directory</span>
                  <input
                    type="text"
                    value={config.spoolDir}
                    onChange={(e) => setConfig({ ...config, spoolDir: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                  />
                </label>
                <label className="block space-y-1">
                  <span className="text-xs text-slate-300">Max Spool Quota (GiB)</span>
                  <input
                    type="number"
                    min={1}
                    max={10000}
                    value={config.maxSpoolGb}
                    onChange={(e) => setConfig({ ...config, maxSpoolGb: Number(e.target.value) || 10 })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                  />
                </label>
              </div>

              <label className="flex items-center gap-2.5 text-xs text-slate-200 pt-1">
                <input
                  type="checkbox"
                  checked={config.pinGoldEpisodes}
                  onChange={(e) => setConfig({ ...config, pinGoldEpisodes: e.target.checked })}
                  className="rounded border-slate-700 bg-slate-950 text-cyan-500"
                />
                Protect Gold &amp; manually reviewed episodes from spool FIFO quota eviction
              </label>
            </div>

            <div className="space-y-6">
              {/* Guarded TLS Uprobes */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
                <h2 className="text-sm font-bold text-white flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  Guarded Cleartext TLS Uprobes (<code className="text-cyan-300">uprobe/SSL_write</code>)
                </h2>
                <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-500/30 text-xs text-amber-200">
                  Off by default. Capturing cleartext <code className="font-mono">SSL_write</code> buffers only runs
                  for explicit non-control-plane binaries or honeypot pods; <code className="font-mono">axonwalld</code>,{' '}
                  <code className="font-mono">sshd</code>, <code className="font-mono">vault</code>,{' '}
                  <code className="font-mono">slapd</code>, <code className="font-mono">k3s</code>,{' '}
                  <code className="font-mono">containerd</code>, and <code className="font-mono">*</code> wildcards
                  are unconditionally blocked.
                </div>

                <label className="flex items-center gap-2.5 text-xs text-slate-200">
                  <input
                    type="checkbox"
                    checked={config.enableTlsUprobes}
                    onChange={(e) => setConfig({ ...config, enableTlsUprobes: e.target.checked })}
                    className="rounded border-slate-700 bg-slate-950 text-amber-500"
                  />
                  Enable guarded <code className="font-mono text-amber-300">uprobe/SSL_write</code> attachment
                </label>

                <label className="flex items-center gap-2.5 text-xs text-slate-200">
                  <input
                    type="checkbox"
                    checked={config.autoHoneypotTlsUprobes}
                    onChange={(e) => setConfig({ ...config, autoHoneypotTlsUprobes: e.target.checked })}
                    className="rounded border-slate-700 bg-slate-950 text-cyan-500"
                  />
                  Auto-allow TLS uprobes inside tagged honeypot pods
                </label>

                <label className="block space-y-1">
                  <span className="text-xs text-slate-300">Explicit Binary Allowlist (CSV paths or process names)</span>
                  <input
                    type="text"
                    value={uprobeAllowlistText}
                    onChange={(e) => setUprobeAllowlistText(e.target.value)}
                    placeholder="/usr/bin/curl, /usr/local/bin/decoy-httpd"
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                  />
                </label>
              </div>

              {/* Teacher-LLM Config */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
                <h2 className="text-sm font-bold text-white flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  Teacher-LLM Reasoning Trace Distiller
                </h2>
                <label className="flex items-center gap-2.5 text-xs text-slate-200">
                  <input
                    type="checkbox"
                    checked={config.teacherLlm.enabled}
                    onChange={(e) =>
                      setConfig({
                        ...config,
                        teacherLlm: { ...config.teacherLlm, enabled: e.target.checked },
                      })
                    }
                    className="rounded border-slate-700 bg-slate-950 text-cyan-500"
                  />
                  Enable OpenAI-compatible Teacher-LLM episode annotation
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <label className="block space-y-1">
                    <span className="text-xs text-slate-300">Chat Completions Endpoint</span>
                    <input
                      type="text"
                      value={config.teacherLlm.endpoint}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          teacherLlm: { ...config.teacherLlm, endpoint: e.target.value },
                        })
                      }
                      className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                    />
                  </label>
                  <label className="block space-y-1">
                    <span className="text-xs text-slate-300">Teacher Model ID</span>
                    <input
                      type="text"
                      value={config.teacherLlm.model}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          teacherLlm: { ...config.teacherLlm, model: e.target.value },
                        })
                      }
                      className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                    />
                  </label>
                  <label className="block space-y-1">
                    <span className="text-xs text-slate-300">Bearer API Key (Optional)</span>
                    <input
                      type="password"
                      value={config.teacherLlm.apiKey || ''}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          teacherLlm: { ...config.teacherLlm, apiKey: e.target.value },
                        })
                      }
                      placeholder="sk-..."
                      className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                    />
                  </label>
                  <label className="block space-y-1">
                    <span className="text-xs text-slate-300">Hourly Call Budget</span>
                    <input
                      type="number"
                      min={1}
                      max={10000}
                      value={config.teacherLlm.maxCallsPerHour}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          teacherLlm: {
                            ...config.teacherLlm,
                            maxCallsPerHour: Number(e.target.value) || 30,
                          },
                        })
                      }
                      className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                    />
                  </label>
                </div>
              </div>
            </div>
          </div>

          <div className="flex justify-end">
            <button
              type="button"
              onClick={() => void handleSavePolicy()}
              disabled={saving}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 transition"
            >
              <Save className="w-4 h-4" />
              {saving ? 'Saving & Synchronizing...' : 'Save & Apply Harvester Policy'}
            </button>
          </div>
        </div>
      )}

      {/* TAB 4: Dataset Export & Vault S3 Lake */}
      {activeTab === 'export' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Download className="w-4 h-4 text-cyan-400" />
              Dual-Track Training Bundle Export (<code className="text-cyan-300">.tar.zst</code>)
            </h2>
            <p className="text-xs text-slate-400">
              Exports a reproducible archive containing <code className="text-slate-200">manifest.json</code>,{' '}
              <code className="text-slate-200">train.jsonl</code> &amp; <code className="text-slate-200">val.jsonl</code>{' '}
              (ChatML SFT + RLVR causal episodes), and <code className="text-slate-200">features.parquet</code>{' '}
              (Apache Parquet 1.0 tabular flow/burst/entropy matrix).
            </p>

            <label className="flex items-center gap-2.5 text-xs text-slate-200">
              <input
                type="checkbox"
                checked={config.anonymizeOnExport}
                onChange={(e) => setConfig({ ...config, anonymizeOnExport: e.target.checked })}
                className="rounded border-slate-700 bg-slate-950 text-emerald-500"
              />
              Enable prefix-preserving AES-128 Crypto-PAn IP anonymization &amp; HMAC-SHA256 hostname scrubbing
            </label>

            <label className="block space-y-1">
              <span className="text-xs text-slate-300">Anonymization Salt (Optional Override)</span>
              <input
                type="password"
                value={config.anonymizationSalt || ''}
                onChange={(e) => setConfig({ ...config, anonymizationSalt: e.target.value })}
                placeholder="Per-appliance persistent key when empty"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
              />
            </label>

            <div className="flex flex-wrap gap-3 pt-2">
              <button
                type="button"
                onClick={() => void handleDownloadExport()}
                disabled={busyAction !== null}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition"
              >
                <Download className="w-4 h-4" />
                {busyAction === 'export' ? 'Packing .tar.zst...' : 'Download .tar.zst Corpus'}
              </button>
              <button
                type="button"
                onClick={() => void handleSavePolicy()}
                disabled={saving}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
              >
                <Save className="w-4 h-4" />
                Save Export Settings
              </button>
            </div>
          </div>

          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Upload className="w-4 h-4 text-emerald-400" />
              Axonwall Vault / Fleet S3 Data-Lake Shipper (AWS SigV4)
            </h2>

            <label className="flex items-center gap-2.5 text-xs text-slate-200">
              <input
                type="checkbox"
                checked={config.fleetShipper.enabled}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    fleetShipper: { ...config.fleetShipper, enabled: e.target.checked },
                  })
                }
                className="rounded border-slate-700 bg-slate-950 text-emerald-500"
              />
              Enable AWS SigV4 corpus shipping to S3 / MinIO / Axonwall Vault
            </label>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <label className="block space-y-1 sm:col-span-2">
                <span className="text-xs text-slate-300">S3 Endpoint URL</span>
                <input
                  type="text"
                  value={config.fleetShipper.endpoint}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      fleetShipper: { ...config.fleetShipper, endpoint: e.target.value },
                    })
                  }
                  placeholder="https://vault.internal:9000"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                />
              </label>
              <label className="block space-y-1">
                <span className="text-xs text-slate-300">Region</span>
                <input
                  type="text"
                  value={config.fleetShipper.region}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      fleetShipper: { ...config.fleetShipper, region: e.target.value },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                />
              </label>
              <label className="block space-y-1">
                <span className="text-xs text-slate-300">Bucket</span>
                <input
                  type="text"
                  value={config.fleetShipper.bucket}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      fleetShipper: { ...config.fleetShipper, bucket: e.target.value },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                />
              </label>
              <label className="block space-y-1">
                <span className="text-xs text-slate-300">Object Key Prefix</span>
                <input
                  type="text"
                  value={config.fleetShipper.prefix}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      fleetShipper: { ...config.fleetShipper, prefix: e.target.value },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                />
              </label>
              <label className="flex items-center gap-2 text-xs text-slate-200 pt-5">
                <input
                  type="checkbox"
                  checked={config.fleetShipper.usePathStyle}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      fleetShipper: { ...config.fleetShipper, usePathStyle: e.target.checked },
                    })
                  }
                  className="rounded border-slate-700 bg-slate-950 text-cyan-500"
                />
                Path-style addressing (MinIO / R2)
              </label>
              <label className="block space-y-1">
                <span className="text-xs text-slate-300">Access Key</span>
                <input
                  type="text"
                  value={config.fleetShipper.accessKey || ''}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      fleetShipper: { ...config.fleetShipper, accessKey: e.target.value },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                />
              </label>
              <label className="block space-y-1">
                <span className="text-xs text-slate-300">Secret Key</span>
                <input
                  type="password"
                  value={config.fleetShipper.secretKey || ''}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      fleetShipper: { ...config.fleetShipper, secretKey: e.target.value },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white"
                />
              </label>
            </div>

            {(status?.config?.fleetShipper?.lastShippedKey || status?.config?.fleetShipper?.lastError) && (
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-1">
                {status.config.fleetShipper.lastShippedAt && (
                  <div className="text-emerald-300">
                    Last shipped {status.config.fleetShipper.lastShippedAt}:{' '}
                    {status.config.fleetShipper.lastShippedKey}
                  </div>
                )}
                {status.config.fleetShipper.lastError && (
                  <div className="text-red-300">Last ship error: {status.config.fleetShipper.lastError}</div>
                )}
              </div>
            )}

            <div className="flex flex-wrap gap-3 pt-1">
              <button
                type="button"
                onClick={() => void handleSavePolicy()}
                disabled={saving}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
              >
                <Save className="w-4 h-4" />
                Save Shipper Policy
              </button>
              <button
                type="button"
                onClick={() => void handleShipNow()}
                disabled={busyAction !== null}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 transition"
              >
                <Upload className="w-4 h-4" />
                {busyAction === 'ship' ? 'Shipping Corpus...' : 'Ship Corpus Now'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
