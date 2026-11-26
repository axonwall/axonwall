'use client';

import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Check,
  Copy,
  KeyRound,
  Loader2,
  Plus,
  Radio,
  RefreshCw,
  Save,
  ShieldAlert,
  Trash2,
} from 'lucide-react';
import {
  ObservabilityConfigSchema,
  ObservabilityOffloadSchema,
  SnmpPluginConfigSchema,
  type DesiredState,
} from '@axonwall/lib/schemas';
import { getCurrentDesiredState } from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import {
  parseCsvTokens,
  parseNonNegativeIntInput,
  resolveObservabilityDraftConfig,
} from '@/lib/state-preservation';

interface ServiceTokenMeta {
  id: string;
  name: string;
  role: 'admin' | 'operator' | 'readonly';
  scopes: string[];
  createdAt: string;
  expiresAt?: string;
  lastUsedAt?: string;
  revokedAt?: string;
}

interface ObservabilityStatusPayload {
  daemonDown?: boolean;
  daemon?: {
    enabled?: boolean;
    offloadEnabled?: boolean;
    nodeId?: string;
    hostname?: string;
    metricsUrl?: string;
    logsUrl?: string;
    acceptsMitigation?: boolean;
    metricsLastPushMs?: number;
    logsLastPushMs?: number;
    metricsLastError?: string;
    logsLastError?: string;
    metricsQueue?: { queuedItems?: number; queuedBytes?: number; diskSpoolBytes?: number; droppedTotal?: number; sentTotal?: number };
    logsQueue?: { queuedItems?: number; queuedBytes?: number; diskSpoolBytes?: number; droppedTotal?: number; sentTotal?: number };
    netflowQueue?: { queuedItems?: number; queuedBytes?: number; diskSpoolBytes?: number; droppedTotal?: number; sentTotal?: number };
  } | null;
  endpoints?: {
    victoriaMetrics?: { configured?: boolean; url?: string };
    victoriaLogs?: { configured?: boolean; url?: string };
    clickhouse?: { configured?: boolean; url?: string };
  };
}

const SCOPE_PRESETS = ['observability:ingest', 'netflow:ingest', 'observability:mitigate', '*'] as const;

export default function ObservabilityOffloadPage() {
  const { applyState } = useDesiredStateApply();
  const [liveState, setLiveState] = useState<DesiredState | null>(null);
  const [draftState, setDraftState] = useState<DesiredState | null>(null);
  const [statusData, setStatusData] = useState<ObservabilityStatusPayload | null>(null);
  const [tokens, setTokens] = useState<ServiceTokenMeta[]>([]);

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [banner, setBanner] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  // New Service Token Form
  const [tokName, setTokName] = useState('');
  const [tokRole, setTokRole] = useState<'admin' | 'operator' | 'readonly'>('operator');
  const [tokScopes, setTokScopes] = useState<string[]>(['observability:ingest', 'netflow:ingest']);
  const [createdPlaintext, setCreatedPlaintext] = useState<string | null>(null);
  const [copiedTok, setCopiedTok] = useState(false);

  const resolvedDraftObs = resolveObservabilityDraftConfig(draftState?.observability);
  const [protectedCidrsText, setProtectedCidrsText] = useState(() =>
    resolvedDraftObs.offload.activeMitigation.protectedCidrs.join(', ')
  );
  const protectedCidrsTextRef = useRef(protectedCidrsText);
  protectedCidrsTextRef.current = protectedCidrsText;

  useEffect(() => {
    const externalCsv = resolvedDraftObs.offload.activeMitigation.protectedCidrs.join(',');
    const localCsv = parseCsvTokens(protectedCidrsTextRef.current).join(',');
    if (externalCsv !== localCsv) {
      setProtectedCidrsText(resolvedDraftObs.offload.activeMitigation.protectedCidrs.join(', '));
    }
  }, [resolvedDraftObs.offload.activeMitigation.protectedCidrs]);

  const loadRuntime = useCallback(async () => {
    const [stRes, tokRes] = await Promise.all([
      fetch('/api/v1/observability/status', { cache: 'no-store' })
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
      fetch('/api/v1/system/service-tokens', { cache: 'no-store' })
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
    ]);
    if (stRes) setStatusData(stRes);
    if (Array.isArray(tokRes?.tokens)) setTokens(tokRes.tokens);
  }, []);

  useEffect(() => {
    let active = true;
    const init = async () => {
      setLoading(true);
      try {
        const [st] = await Promise.all([getCurrentDesiredState(), loadRuntime()]);
        if (!active) return;
        setLiveState(st);
        setDraftState(structuredClone(st));
      } catch (err: any) {
        if (active) setBanner({ kind: 'err', text: err?.message || 'Failed to load observability settings' });
      } finally {
        if (active) setLoading(false);
      }
    };
    void init();
    const timer = setInterval(() => void loadRuntime(), 8000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [loadRuntime]);

  if (loading || !draftState) {
    return (
      <div className="p-10 flex items-center justify-center gap-2 text-slate-300 text-sm">
        <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
        Loading Observability &amp; Offload Control Center...
      </div>
    );
  }

  const obs = resolvedDraftObs;
  const offload = obs.offload;
  const vmCfg = obs.victoriaMetrics ?? { enabled: false, url: 'http://127.0.0.1:8428' };
  const vlCfg = obs.victoriaLogs ?? { enabled: false, url: 'http://127.0.0.1:9428' };
  const snmpCfg = draftState.snmp ?? SnmpPluginConfigSchema.parse({});

  const updateOffload = (updater: (cur: typeof offload) => typeof offload) => {
    setDraftState((prev) => {
      if (!prev) return prev;
      const curObs = resolveObservabilityDraftConfig(prev.observability);
      return {
        ...prev,
        observability: {
          ...curObs,
          offload: updater(curObs.offload),
        },
      };
    });
  };

  const updateObs = (updater: (cur: typeof obs) => typeof obs) => {
    setDraftState((prev) => {
      if (!prev) return prev;
      const curObs = resolveObservabilityDraftConfig(prev.observability);
      return {
        ...prev,
        observability: updater(curObs),
      };
    });
  };

  const handleSave = async () => {
    const obsCheck = ObservabilityConfigSchema.safeParse(draftState.observability ?? {});
    if (!obsCheck.success) {
      setBanner({
        kind: 'err',
        text: `Invalid observability configuration: ${obsCheck.error.issues.map((i) => `${i.path.join('.') || 'observability'}: ${i.message}`).join('; ')}`,
      });
      return;
    }
    const offloadCheck = ObservabilityOffloadSchema.safeParse(obsCheck.data.offload ?? {});
    if (!offloadCheck.success) {
      setBanner({
        kind: 'err',
        text: `Invalid offload configuration: ${offloadCheck.error.issues.map((i) => `${i.path.join('.') || 'offload'}: ${i.message}`).join('; ')}`,
      });
      return;
    }
    setSaving(true);
    setBanner(null);
    try {
      const normalizedState: DesiredState = {
        ...draftState,
        observability: { ...obsCheck.data, offload: offloadCheck.data },
      };
      const res = await applyState(normalizedState);
      if (res.success) {
        setLiveState(structuredClone(normalizedState));
        setDraftState(structuredClone(normalizedState));
        setBanner({ kind: 'ok', text: res.message || 'Observability, offload & logging configuration applied.' });
        await loadRuntime();
      } else {
        setBanner({ kind: 'err', text: res.message || 'Failed to apply configuration' });
      }
    } catch (err: any) {
      setBanner({ kind: 'err', text: err?.message || 'Failed to apply configuration' });
    } finally {
      setSaving(false);
    }
  };

  const handleCreateToken = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tokName.trim()) return;
    try {
      const res = await fetch('/api/v1/system/service-tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: tokName.trim(),
          role: tokRole,
          scopes: tokScopes.length > 0 ? tokScopes : ['observability:ingest'],
        }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok) {
        setBanner({ kind: 'err', text: json?.error || `Failed to create service token (HTTP ${res.status})` });
        return;
      }
      setCreatedPlaintext(json?.plaintextToken || null);
      setCopiedTok(false);
      setTokName('');
      await loadRuntime();
    } catch (err: any) {
      setBanner({ kind: 'err', text: err?.message || 'Failed to create service token' });
    }
  };

  const handleRevokeToken = async (id: string) => {
    try {
      const res = await fetch(`/api/v1/system/service-tokens/${encodeURIComponent(id)}`, { method: 'DELETE' });
      const json = await res.json().catch(() => null);
      if (!res.ok) {
        setBanner({ kind: 'err', text: json?.error || `Failed to revoke service token (HTTP ${res.status})` });
        return;
      }
      await loadRuntime();
    } catch (err: any) {
      setBanner({ kind: 'err', text: err?.message || 'Failed to revoke service token' });
    }
  };

  const dirty = Boolean(
    liveState &&
      (JSON.stringify(liveState.observability) !== JSON.stringify(draftState.observability) ||
        JSON.stringify(liveState.dhcp) !== JSON.stringify(draftState.dhcp) ||
        JSON.stringify(liveState.dns) !== JSON.stringify(draftState.dns) ||
        JSON.stringify(liveState.snmp) !== JSON.stringify(draftState.snmp))
  );

  const daemon = statusData?.daemon;
  const formatQueueBytes = (b?: number) => `${((b || 0) / (1024 * 1024)).toFixed(2)} MiB`;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 text-xs">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400">
            <Radio className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Observability &amp; Telemetry Offload</h1>
            <p className="text-sm text-slate-400">
              Ship IPFIX flows, Prometheus metrics, and NFLOG/service logs off edge routers onto central K3s/ZFS storage.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void loadRuntime()}
            className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
          <button
            type="button"
            disabled={!dirty || saving}
            onClick={() => void handleSave()}
            className={`px-4 py-1.5 rounded-lg font-semibold flex items-center gap-1.5 ${
              dirty ? 'bg-emerald-600 hover:bg-emerald-500 text-white' : 'bg-slate-800 text-slate-400'
            }`}
          >
            <Save className="w-3.5 h-3.5" />
            {saving ? 'Applying...' : dirty ? 'Save & Apply Offload Config' : 'Saved'}
          </button>
        </div>
      </div>

      {banner && (
        <div
          className={`px-4 py-2.5 rounded-xl border flex items-center gap-2 ${
            banner.kind === 'ok'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/40 text-rose-300'
          }`}
        >
          {banner.kind === 'ok' ? <Check className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
          <span>{banner.text}</span>
        </div>
      )}

      {/* 1. Live Shipper Health */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { label: 'Metrics Remote-Write Shipper', q: daemon?.metricsQueue, ts: daemon?.metricsLastPushMs, err: daemon?.metricsLastError },
          { label: 'Logs Shipper (NFLOG/Services)', q: daemon?.logsQueue, ts: daemon?.logsLastPushMs, err: daemon?.logsLastError },
          { label: 'IPFIX Export Queue', q: daemon?.netflowQueue, ts: undefined, err: undefined },
        ].map((card) => (
          <div key={card.label} className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-1.5">
            <div className="flex items-center justify-between text-slate-300 font-semibold">
              <span>{card.label}</span>
              <Activity className="w-4 h-4 text-sky-400" />
            </div>
            <div className="font-mono text-slate-400">
              RAM Queue: <span className="text-white">{formatQueueBytes(card.q?.queuedBytes)}</span> · Spool:{' '}
              <span className="text-white">{formatQueueBytes(card.q?.diskSpoolBytes)}</span>
            </div>
            <div className="font-mono text-slate-400">
              Sent: <span className="text-emerald-400">{(card.q?.sentTotal ?? 0).toLocaleString()}</span> · Dropped:{' '}
              <span className={card.q?.droppedTotal ? 'text-rose-400' : 'text-slate-300'}>
                {(card.q?.droppedTotal ?? 0).toLocaleString()}
              </span>
            </div>
            {card.ts ? (
              <div className="text-[11px] font-mono text-slate-500">Last push: {new Date(card.ts).toLocaleTimeString()}</div>
            ) : null}
            {card.err ? <div className="text-[11px] font-mono text-rose-300 truncate">{card.err}</div> : null}
          </div>
        ))}
      </div>

      {/* 2. Edge Telemetry Offload Configuration */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-semibold text-white">Edge Telemetry Offload (`observability.offload`)</h2>
            <p className="text-slate-400">
              Push eBPF/Conntrack IPFIX, Prometheus metrics, and logs off this edge node with bounded RAM/disk buffering.
            </p>
          </div>
          <label className="flex items-center gap-2 font-semibold text-white cursor-pointer">
            <input
              type="checkbox"
              checked={offload.enabled}
              onChange={(e) => updateOffload((c) => ({ ...c, enabled: e.target.checked }))}
              className="accent-emerald-500"
            />
            Enable Offload
          </label>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <label className="block">
            <span className="text-slate-400 block mb-1">Node ID Override</span>
            <input
              type="text"
              value={offload.nodeId || ''}
              onChange={(e) => updateOffload((c) => ({ ...c, nodeId: e.target.value.trim() || undefined }))}
              placeholder="edge-checkpoint1"
              className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
          </label>
          <label className="block md:col-span-2">
            <span className="text-slate-400 block mb-1">Analytics Hub Base URL (`hubUrl`)</span>
            <input
              type="text"
              value={offload.hubUrl || ''}
              onChange={(e) => updateOffload((c) => ({ ...c, hubUrl: e.target.value.trim() || undefined }))}
              placeholder="https://analytics.internal"
              className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
          </label>
          <label className="block">
            <span className="text-slate-400 block mb-1">Service Token (`axw_svc_*`)</span>
            <input
              type="password"
              value={offload.ingestToken || ''}
              onChange={(e) => updateOffload((c) => ({ ...c, ingestToken: e.target.value || undefined }))}
              placeholder="axw_svc_..."
              className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
          </label>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 items-end">
          <label className="block md:col-span-2">
            <span className="text-slate-400 block mb-1">IPFIX Collector Host (`collectorHost`)</span>
            <input
              type="text"
              value={offload.collectorHost || ''}
              onChange={(e) => updateOffload((c) => ({ ...c, collectorHost: e.target.value.trim() || undefined }))}
              placeholder="10.8.0.10 or k3s.internal"
              className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
          </label>
          <label className="block">
            <span className="text-slate-400 block mb-1">Collector Port</span>
            <input
              type="number"
              value={offload.collectorPort}
              onChange={(e) => updateOffload((c) => ({ ...c, collectorPort: Number(e.target.value) || 2055 }))}
              className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
          </label>
          <label className="block">
            <span className="text-slate-400 block mb-1">IPFIX Transport</span>
            <select
              value={offload.ipfixTransport}
              onChange={(e) =>
                updateOffload((c) => ({ ...c, ipfixTransport: e.target.value as 'udp' | 'tcp' | 'tls' }))
              }
              className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            >
              <option value="udp">udp (WG mesh)</option>
              <option value="tcp">tcp (reliable)</option>
              <option value="tls">tls (TLS 1.3 mTLS)</option>
            </select>
          </label>
          <div className="flex flex-col gap-1.5 pb-1">
            <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={offload.useHaMtls}
                onChange={(e) => updateOffload((c) => ({ ...c, useHaMtls: e.target.checked }))}
                className="accent-sky-500"
              />
              Use HA PKI mTLS
            </label>
            <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={offload.tlsInsecureSkipVerify}
                onChange={(e) => updateOffload((c) => ({ ...c, tlsInsecureSkipVerify: e.target.checked }))}
                className="accent-sky-500"
              />
              Skip TLS verify
            </label>
          </div>
        </div>

        {/* Metrics & Logs Streams */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-3 border-t border-slate-800">
          <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between font-semibold text-white">
              <span>Metrics Offload (Prometheus Remote-Write)</span>
              <input
                type="checkbox"
                checked={offload.metrics.enabled}
                onChange={(e) => updateOffload((c) => ({ ...c, metrics: { ...c.metrics, enabled: e.target.checked } }))}
                className="accent-emerald-500"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <label className="block col-span-2">
                <span className="text-slate-400 block mb-1">Remote-Write URL Override (optional)</span>
                <input
                  type="text"
                  value={offload.metrics.remoteWriteUrl || ''}
                  onChange={(e) =>
                    updateOffload((c) => ({ ...c, metrics: { ...c.metrics, remoteWriteUrl: e.target.value.trim() || undefined } }))
                  }
                  placeholder="Defaults to <hubUrl>/vm/api/v1/write"
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>
              <label className="block">
                <span className="text-slate-400 block mb-1">Push Interval (sec)</span>
                <input
                  type="number"
                  min={5}
                  value={offload.metrics.intervalSec || ''}
                  onChange={(e) => {
                    const n = parseNonNegativeIntInput(e.target.value, offload.metrics.intervalSec);
                    updateOffload((c) => ({ ...c, metrics: { ...c.metrics, intervalSec: n } }));
                  }}
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>
              <label className="flex items-center gap-2 text-slate-300 cursor-pointer pt-5">
                <input
                  type="checkbox"
                  checked={offload.metrics.exposeScrape}
                  onChange={(e) =>
                    updateOffload((c) => ({ ...c, metrics: { ...c.metrics, exposeScrape: e.target.checked } }))
                  }
                  className="accent-sky-500"
                />
                Also expose Prometheus `/metrics`
              </label>
            </div>
            {offload.metrics.exposeScrape && (
              <div className="grid grid-cols-3 gap-2">
                <input
                  type="text"
                  value={offload.metrics.scrapeBind}
                  onChange={(e) =>
                    updateOffload((c) => ({ ...c, metrics: { ...c.metrics, scrapeBind: e.target.value } }))
                  }
                  placeholder="10.8.0.2"
                  className="px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
                <input
                  type="number"
                  value={offload.metrics.scrapePort || ''}
                  onChange={(e) => {
                    const n = parseNonNegativeIntInput(e.target.value, offload.metrics.scrapePort);
                    updateOffload((c) => ({ ...c, metrics: { ...c.metrics, scrapePort: n } }));
                  }}
                  className="px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
                <input
                  type="password"
                  value={offload.metrics.scrapeToken || ''}
                  onChange={(e) =>
                    updateOffload((c) => ({ ...c, metrics: { ...c.metrics, scrapeToken: e.target.value || undefined } }))
                  }
                  placeholder="Scrape bearer token"
                  className="px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </div>
            )}
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between font-semibold text-white">
              <span>Structured Log Offload (VictoriaLogs)</span>
              <input
                type="checkbox"
                checked={offload.logs.enabled}
                onChange={(e) => updateOffload((c) => ({ ...c, logs: { ...c.logs, enabled: e.target.checked } }))}
                className="accent-emerald-500"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <label className="block">
                <span className="text-slate-400 block mb-1">VictoriaLogs URL Override</span>
                <input
                  type="text"
                  value={offload.logs.victoriaLogsUrl || ''}
                  onChange={(e) =>
                    updateOffload((c) => ({ ...c, logs: { ...c.logs, victoriaLogsUrl: e.target.value.trim() || undefined } }))
                  }
                  placeholder="<hubUrl>/vl/insert/jsonline"
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>
              <label className="block">
                <span className="text-slate-400 block mb-1">NFLOG Rate Limit (/sec)</span>
                <input
                  type="number"
                  min={0}
                  value={offload.logs.nflog.rateLimitPerSec}
                  onChange={(e) => {
                    const n = parseNonNegativeIntInput(e.target.value, offload.logs.nflog.rateLimitPerSec);
                    updateOffload((c) => ({
                      ...c,
                      logs: { ...c.logs, nflog: { ...c.logs.nflog, rateLimitPerSec: n } },
                    }));
                  }}
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pt-1">
              {[
                { label: 'NFLOG Drops', val: offload.logs.nflog.enabled, set: (v: boolean) => updateOffload((c) => ({ ...c, logs: { ...c.logs, nflog: { ...c.logs.nflog, enabled: v } } })) },
                { label: 'journald Units', val: offload.logs.journald.enabled, set: (v: boolean) => updateOffload((c) => ({ ...c, logs: { ...c.logs, journald: { ...c.logs.journald, enabled: v } } })) },
                { label: 'Suricata EVE', val: offload.logs.suricata.enabled, set: (v: boolean) => updateOffload((c) => ({ ...c, logs: { ...c.logs, suricata: { enabled: v } } })) },
                { label: 'CrowdSec Alerts', val: offload.logs.crowdsec.enabled, set: (v: boolean) => updateOffload((c) => ({ ...c, logs: { ...c.logs, crowdsec: { enabled: v } } })) },
                { label: 'Kea DHCP Logs', val: offload.logs.keaDhcp.enabled, set: (v: boolean) => updateOffload((c) => ({ ...c, logs: { ...c.logs, keaDhcp: { enabled: v } } })) },
                { label: 'Unbound DNS (opt-in)', val: offload.logs.unboundDns.enabled, set: (v: boolean) => updateOffload((c) => ({ ...c, logs: { ...c.logs, unboundDns: { enabled: v } } })) },
              ].map((s) => (
                <label key={s.label} className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={s.val}
                    onChange={(e) => s.set(e.target.checked)}
                    className="accent-amber-500"
                  />
                  <span>{s.label}</span>
                </label>
              ))}
            </div>
          </div>
        </div>

        {/* Bounded Buffering + Opt-in Remote Active Mitigation */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-3 border-t border-slate-800">
          <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-2">
            <div className="font-semibold text-white">Bounded Ring Buffer &amp; Disk Spool</div>
            <div className="grid grid-cols-3 gap-2">
              <label className="block">
                <span className="text-slate-400 block mb-1">Max RAM (MiB)</span>
                <input
                  type="number"
                  min={4}
                  max={256}
                  value={offload.buffer.maxMemoryMB || ''}
                  onChange={(e) => {
                    const n = parseNonNegativeIntInput(e.target.value, offload.buffer.maxMemoryMB);
                    updateOffload((c) => ({ ...c, buffer: { ...c.buffer, maxMemoryMB: n } }));
                  }}
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>
              <label className="flex items-center gap-2 text-slate-300 cursor-pointer pt-5">
                <input
                  type="checkbox"
                  checked={offload.buffer.diskSpoolEnabled}
                  onChange={(e) =>
                    updateOffload((c) => ({ ...c, buffer: { ...c.buffer, diskSpoolEnabled: e.target.checked } }))
                  }
                  className="accent-sky-500"
                />
                Zstd Disk Spool
              </label>
              <label className="block">
                <span className="text-slate-400 block mb-1">Max Disk (MiB)</span>
                <input
                  type="number"
                  min={16}
                  value={offload.buffer.diskSpoolMaxMB || ''}
                  onChange={(e) => {
                    const n = parseNonNegativeIntInput(e.target.value, offload.buffer.diskSpoolMaxMB);
                    updateOffload((c) => ({ ...c, buffer: { ...c.buffer, diskSpoolMaxMB: n } }));
                  }}
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>
            </div>
          </div>

          <div className="bg-slate-950 border border-amber-500/30 rounded-lg p-4 space-y-2">
            <div className="flex items-center justify-between font-semibold text-amber-300">
              <span className="flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4" />
                Opt-In Remote Active XDP Mitigation
              </span>
              <input
                type="checkbox"
                checked={offload.activeMitigation.acceptRemoteBlocks}
                onChange={(e) =>
                  updateOffload((c) => ({
                    ...c,
                    activeMitigation: { ...c.activeMitigation, acceptRemoteBlocks: e.target.checked },
                  }))
                }
                className="accent-amber-500"
              />
            </div>
            <div className="grid grid-cols-3 gap-2">
              <label className="block">
                <span className="text-slate-400 block mb-1">Max TTL (sec)</span>
                <input
                  type="number"
                  min={60}
                  value={offload.activeMitigation.maxTtlSec || ''}
                  onChange={(e) => {
                    const n = parseNonNegativeIntInput(e.target.value, offload.activeMitigation.maxTtlSec);
                    updateOffload((c) => ({
                      ...c,
                      activeMitigation: { ...c.activeMitigation, maxTtlSec: n },
                    }));
                  }}
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>
              <label className="block col-span-2">
                <span className="text-slate-400 block mb-1">Protected Anti-Lockout CIDRs (CSV)</span>
                <input
                  type="text"
                  value={protectedCidrsText}
                  onChange={(e) => {
                    const nextText = e.target.value;
                    setProtectedCidrsText(nextText);
                    protectedCidrsTextRef.current = nextText;
                    updateOffload((c) => ({
                      ...c,
                      activeMitigation: {
                        ...c.activeMitigation,
                        protectedCidrs: parseCsvTokens(nextText),
                      },
                    }));
                  }}
                  onBlur={() => {
                    setProtectedCidrsText(parseCsvTokens(protectedCidrsTextRef.current).join(', '));
                  }}
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </label>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Central Analytics Endpoints & Daemon Log Toggles */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <h2 className="text-sm font-semibold text-white">Central VictoriaMetrics &amp; VictoriaLogs Query Endpoints</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="space-y-2 bg-slate-950 border border-slate-800 rounded-lg p-3">
              <label className="flex items-center justify-between text-slate-200 font-semibold cursor-pointer">
                <span>VictoriaMetrics Query</span>
                <input
                  type="checkbox"
                  checked={vmCfg.enabled}
                  onChange={(e) =>
                    updateObs((c) => ({ ...c, victoriaMetrics: { ...vmCfg, enabled: e.target.checked } }))
                  }
                  className="accent-emerald-500"
                />
              </label>
              <input
                type="text"
                value={vmCfg.url}
                onChange={(e) => updateObs((c) => ({ ...c, victoriaMetrics: { ...vmCfg, url: e.target.value } }))}
                placeholder="http://victoriametrics:8428"
                className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
              />
              <input
                type="password"
                value={vmCfg.bearerToken || ''}
                onChange={(e) =>
                  updateObs((c) => ({ ...c, victoriaMetrics: { ...vmCfg, bearerToken: e.target.value || undefined } }))
                }
                placeholder="Bearer token (optional)"
                className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
              />
            </div>

            <div className="space-y-2 bg-slate-950 border border-slate-800 rounded-lg p-3">
              <label className="flex items-center justify-between text-slate-200 font-semibold cursor-pointer">
                <span>VictoriaLogs Query</span>
                <input
                  type="checkbox"
                  checked={vlCfg.enabled}
                  onChange={(e) =>
                    updateObs((c) => ({ ...c, victoriaLogs: { ...vlCfg, enabled: e.target.checked } }))
                  }
                  className="accent-emerald-500"
                />
              </label>
              <input
                type="text"
                value={vlCfg.url}
                onChange={(e) => updateObs((c) => ({ ...c, victoriaLogs: { ...vlCfg, url: e.target.value } }))}
                placeholder="http://victorialogs:9428"
                className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
              />
              <input
                type="password"
                value={vlCfg.bearerToken || ''}
                onChange={(e) =>
                  updateObs((c) => ({ ...c, victoriaLogs: { ...vlCfg, bearerToken: e.target.value || undefined } }))
                }
                placeholder="Bearer token (optional)"
                className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
              />
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <h2 className="text-sm font-semibold text-white">Local Daemon Logging &amp; SNMPv3 Quick Controls</h2>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <label className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-lg p-3 text-slate-200 cursor-pointer">
              <input
                type="checkbox"
                checked={Boolean(draftState.dhcp?.logLeases)}
                onChange={(e) =>
                  setDraftState((p) => (p ? { ...p, dhcp: { ...p.dhcp, logLeases: e.target.checked } } : p))
                }
                className="accent-sky-500"
              />
              <span>Kea DHCP Lease Logging</span>
            </label>
            <label className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-lg p-3 text-slate-200 cursor-pointer">
              <input
                type="checkbox"
                checked={Boolean(draftState.dns?.logQueries)}
                onChange={(e) =>
                  setDraftState((p) => (p ? { ...p, dns: { ...p.dns, logQueries: e.target.checked } } : p))
                }
                className="accent-amber-500"
              />
              <span>Unbound Query Log (opt-in)</span>
            </label>
            <label className="block bg-slate-950 border border-slate-800 rounded-lg p-2.5">
              <span className="text-slate-400 block mb-1">SNMP Protocol</span>
              <select
                value={snmpCfg.version ?? 'v2c'}
                onChange={(e) =>
                  setDraftState((p) =>
                    p
                      ? {
                          ...p,
                          snmp: { ...snmpCfg, version: e.target.value as 'v2c' | 'v3' },
                        }
                      : p
                  )
                }
                className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 text-white font-mono"
              >
                <option value="v2c">SNMPv2c</option>
                <option value="v3">SNMPv3 USM (authPriv)</option>
              </select>
            </label>
          </div>
        </div>
      </div>

      {/* 4. Scoped Service Tokens */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center gap-2 font-semibold text-white text-sm">
          <KeyRound className="w-4 h-4 text-emerald-400" />
          Scoped Service Tokens (`axw_svc_*`) for Edge Offload &amp; Automation
        </div>

        {createdPlaintext && (
          <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 space-y-1.5">
            <div className="text-emerald-300 font-semibold">Token created — copy now (shown once only):</div>
            <div className="flex items-center gap-2 font-mono text-white bg-slate-950 px-3 py-2 rounded border border-slate-800">
              <span className="truncate flex-1">{createdPlaintext}</span>
              <button
                type="button"
                onClick={() => {
                  void navigator.clipboard.writeText(createdPlaintext);
                  setCopiedTok(true);
                }}
                className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs flex items-center gap-1"
              >
                <Copy className="w-3.5 h-3.5" />
                {copiedTok ? 'Copied' : 'Copy'}
              </button>
            </div>
          </div>
        )}

        <form onSubmit={handleCreateToken} className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
          <label className="block">
            <span className="text-slate-400 block mb-1">Token Name</span>
            <input
              type="text"
              value={tokName}
              onChange={(e) => setTokName(e.target.value)}
              placeholder="e.g. checkpoint1-offload"
              className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white"
            />
          </label>
          <label className="block">
            <span className="text-slate-400 block mb-1">RBAC Role</span>
            <select
              value={tokRole}
              onChange={(e) => setTokRole(e.target.value as 'admin' | 'operator' | 'readonly')}
              className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            >
              <option value="operator">operator</option>
              <option value="readonly">readonly</option>
              <option value="admin">admin</option>
            </select>
          </label>
          <div className="flex flex-wrap gap-2 pb-1">
            {SCOPE_PRESETS.map((sc) => (
              <label key={sc} className="flex items-center gap-1 text-slate-300 cursor-pointer font-mono">
                <input
                  type="checkbox"
                  checked={tokScopes.includes(sc)}
                  onChange={() =>
                    setTokScopes((prev) => (prev.includes(sc) ? prev.filter((x) => x !== sc) : [...prev, sc]))
                  }
                  className="accent-sky-500"
                />
                {sc}
              </label>
            ))}
          </div>
          <button
            type="submit"
            disabled={!tokName.trim()}
            className="px-3.5 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white font-semibold flex items-center justify-center gap-1.5"
          >
            <Plus className="w-3.5 h-3.5" />
            Generate Service Token
          </button>
        </form>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono">
            <thead className="border-b border-slate-800 text-slate-400">
              <tr>
                <th className="py-2 pr-3">Name</th>
                <th className="py-2 px-3">ID</th>
                <th className="py-2 px-3">Role / Scopes</th>
                <th className="py-2 px-3">Last Used</th>
                <th className="py-2 pl-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {tokens.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-4 text-center text-slate-500">
                    No service tokens issued yet.
                  </td>
                </tr>
              ) : (
                tokens.map((t) => (
                  <tr key={t.id}>
                    <td className="py-2 pr-3 text-white">{t.name}</td>
                    <td className="py-2 px-3 text-slate-400">{t.id}</td>
                    <td className="py-2 px-3 text-slate-300">
                      {t.role} [{t.scopes.join(', ')}]
                    </td>
                    <td className="py-2 px-3 text-slate-400">
                      {t.lastUsedAt ? new Date(t.lastUsedAt).toLocaleString() : 'Never'}
                    </td>
                    <td className="py-2 pl-3 text-right">
                      {t.revokedAt ? (
                        <span className="text-rose-400">Revoked</span>
                      ) : (
                        <button
                          type="button"
                          onClick={() => void handleRevokeToken(t.id)}
                          className="text-slate-400 hover:text-rose-300 inline-flex items-center gap-1"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
