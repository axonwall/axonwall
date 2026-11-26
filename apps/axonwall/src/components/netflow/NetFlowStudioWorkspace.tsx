'use client';

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Check,
  Loader2,
  RefreshCw,
  Save,
} from 'lucide-react';
import { formatBps, formatBytes } from '@axonwall/lib/compile/netflow';
import { NetFlowConfigSchema, type DesiredState } from '@axonwall/lib/schemas';
import {
  ackNetFlowAlertAction,
  getCurrentDesiredState,
  getNetFlowAlertsAction,
  getNetFlowExportersAction,
  getNetFlowStatusAction,
  getNetFlowTemplatesAction,
  queryNetFlowAction,
} from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import { AlertsAnomaliesTab } from './AlertsAnomaliesTab';
import { ExportersTemplatesTab } from './ExportersTemplatesTab';
import { FlowExplorerTab } from './FlowExplorerTab';
import { FlowHeatmapsPanel } from './FlowHeatmapsPanel';
import { GeoTrafficMap } from './GeoTrafficMap';
import { LiveTailTab } from './LiveTailTab';
import { PipelineConfigTab } from './PipelineConfigTab';
import { ReportsPanel } from './ReportsPanel';
import type {
  NetFlowAlertSnapshot,
  NetFlowExporterSnapshot,
  NetFlowQueryResponseSnapshot,
  NetFlowStatusSnapshot,
  NetFlowTemplateSnapshot,
} from './types';

type StudioTab = 'explorer' | 'maps' | 'reports' | 'live' | 'exporters' | 'alerts' | 'config';

export function NetFlowStudioWorkspace() {
  const { applyState } = useDesiredStateApply();
  const [activeTab, setActiveTab] = useState<StudioTab>('explorer');
  const [liveState, setLiveState] = useState<DesiredState | null>(null);
  const [draftState, setDraftState] = useState<DesiredState | null>(null);

  const [status, setStatus] = useState<NetFlowStatusSnapshot | null>(null);
  const [queryRes, setQueryRes] = useState<NetFlowQueryResponseSnapshot | null>(null);
  const [exporters, setExporters] = useState<NetFlowExporterSnapshot[]>([]);
  const [templates, setTemplates] = useState<NetFlowTemplateSnapshot[]>([]);
  const [alerts, setAlerts] = useState<NetFlowAlertSnapshot[]>([]);

  const [fql, setFql] = useState('');
  const [rangeMinutes, setRangeMinutes] = useState(60);
  const [groupBy, setGroupBy] = useState('protocol');
  const [scope, setScope] = useState<'local' | 'fleet'>('local');
  const [selectedNodeId, setSelectedNodeId] = useState<string>('all');
  const [nodes, setNodes] = useState<Array<{ nodeId: string; nodeName: string; exporterIp: string; flowsCount: number }>>([]);
  const [biflow, setBiflow] = useState(false);
  const [customWindow, setCustomWindow] = useState<{ startMs: number; endMs: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [querying, setQuerying] = useState(false);
  const [saving, setSaving] = useState(false);
  const [banner, setBanner] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const runQuery = useCallback(
    async (
      overrideFql?: string,
      overrides?: {
        scope?: 'local' | 'fleet';
        nodeId?: string;
        biflow?: boolean;
        window?: { startMs: number; endMs: number } | null;
        rangeMins?: number;
        gb?: string;
      },
    ) => {
      setQuerying(true);
      try {
        const effWin = overrides && 'window' in overrides ? overrides.window : customWindow;
        const baseFql = (overrideFql !== undefined ? overrideFql : fql).trim();
        const effNode = overrides?.nodeId !== undefined ? overrides.nodeId : selectedNodeId;
        const effectiveFql =
          effNode && effNode !== 'all'
            ? baseFql
              ? `(${baseFql}) and node="${effNode.replace(/"/g, '')}"`
              : `node="${effNode.replace(/"/g, '')}"`
            : baseFql;
        const res = await queryNetFlowAction({
          rangeMinutes: overrides?.rangeMins ?? rangeMinutes,
          startMs: effWin?.startMs,
          endMs: effWin?.endMs,
          fql: effectiveFql,
          groupBy: overrides?.gb ?? groupBy,
          biflow: overrides?.biflow ?? biflow,
          scope: overrides?.scope ?? scope,
          limit: 200,
        });
        setQueryRes(res);
      } finally {
        setQuerying(false);
      }
    },
    [biflow, customWindow, fql, groupBy, rangeMinutes, scope, selectedNodeId],
  );

  const refreshRuntime = useCallback(async () => {
    const [st, exp, tmpl, al, nodesJson] = await Promise.all([
      getNetFlowStatusAction(),
      getNetFlowExportersAction(),
      getNetFlowTemplatesAction(),
      getNetFlowAlertsAction(),
      fetch('/api/v1/netflow/nodes', { cache: 'no-store' })
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
    ]);
    setStatus(st);
    setExporters(exp);
    setTemplates(tmpl);
    setAlerts(al);
    if (Array.isArray(nodesJson?.nodes)) {
      setNodes(nodesJson.nodes);
    }
  }, []);

  useEffect(() => {
    let active = true;
    const init = async () => {
      setLoading(true);
      try {
        const s = await getCurrentDesiredState();
        if (!active) return;
        setLiveState(s);
        setDraftState(structuredClone(s));
        await Promise.all([refreshRuntime(), runQuery('')]);
      } catch (err) {
        if (active) {
          setBanner({
            kind: 'err',
            text: err instanceof Error ? err.message : 'Failed to load NetFlow collector telemetry',
          });
        }
      } finally {
        if (active) setLoading(false);
      }
    };
    void init();
    const timer = setInterval(() => {
      void refreshRuntime();
    }, 8000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [refreshRuntime, runQuery]);

  const hasUnsavedChanges = useMemo(
    () =>
      Boolean(
        liveState &&
          draftState &&
          JSON.stringify(liveState.netflow) !== JSON.stringify(draftState.netflow),
      ),
    [draftState, liveState],
  );

  const handleSave = async () => {
    if (!draftState) return;
    setSaving(true);
    setBanner(null);
    try {
      const res = await applyState(draftState);
      if (res.success) {
        setLiveState(structuredClone(draftState));
        setBanner({ kind: 'ok', text: res.message || 'Saved netflow.yaml and restarted pipeline cleanly.' });
        await refreshRuntime();
      } else {
        setBanner({ kind: 'err', text: res.message || 'Failed to apply NetFlow configuration' });
      }
    } catch (err) {
      setBanner({
        kind: 'err',
        text: err instanceof Error ? err.message : 'Failed to save NetFlow configuration',
      });
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="py-20 flex items-center justify-center text-slate-300 text-sm gap-2">
        <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
        Loading NetFlow Collector Studio...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <Activity className="w-6 h-6 text-sky-400" />
            NetFlow / IPFIX / sFlow Collector Studio
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Multi-protocol collector (v5/v9/IPFIX/sFlow v5), eBPF self-exporter, UDP replicator, FQL analytics &amp; XDP SOAR mitigation
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center rounded-lg bg-slate-900 border border-slate-700 p-0.5 text-xs font-mono">
            {(['local', 'fleet'] as const).map((sc) => (
              <button
                key={sc}
                type="button"
                onClick={() => {
                  setScope(sc);
                  void runQuery(undefined, { scope: sc });
                }}
                className={`px-2.5 py-1 rounded ${
                  scope === sc ? 'bg-sky-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                {sc === 'local' ? 'Local Host' : 'Entire Fleet'}
              </button>
            ))}
          </div>
          <select
            aria-label="Filter by exporter node"
            value={selectedNodeId}
            onChange={(e) => {
              const nextNode = e.target.value;
              setSelectedNodeId(nextNode);
              void runQuery(undefined, { nodeId: nextNode });
            }}
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200"
          >
            <option value="all">All Nodes ({nodes.length || 1})</option>
            {nodes.map((n) => (
              <option key={n.nodeId} value={n.nodeId}>
                {n.nodeName || n.nodeId} ({n.flowsCount.toLocaleString()})
              </option>
            ))}
          </select>
          <a
            href="/api/v1/netflow/metrics"
            target="_blank"
            rel="noreferrer"
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-[11px] font-mono text-emerald-300"
            title="OpenMetrics / Prometheus scrape endpoint"
          >
            /metrics
          </a>
          <button
            type="button"
            onClick={() => void Promise.all([refreshRuntime(), runQuery()])}
            className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs text-slate-200 flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
          <button
            type="button"
            disabled={!hasUnsavedChanges || saving}
            onClick={() => void handleSave()}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 ${
              hasUnsavedChanges
                ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                : 'bg-slate-800 text-slate-400 cursor-default'
            }`}
          >
            <Save className="w-3.5 h-3.5" />
            {saving ? 'Saving...' : hasUnsavedChanges ? 'Save Changes to netflow.yaml' : 'Saved'}
          </button>
        </div>
      </div>

      {banner && (
        <div
          className={`px-4 py-2.5 rounded-xl border text-xs flex items-center justify-between ${
            banner.kind === 'ok'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/40 text-rose-300'
          }`}
        >
          <span className="flex items-center gap-2">
            {banner.kind === 'ok' ? <Check className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
            {banner.text}
          </span>
          <button type="button" onClick={() => setBanner(null)} className="underline">
            Dismiss
          </button>
        </div>
      )}

      {queryRes?.peerErrors && queryRes.peerErrors.length > 0 && (
        <div className="px-4 py-2 rounded-xl border border-amber-500/40 bg-amber-500/10 text-xs font-mono text-amber-200">
          Fleet federation partial warning: {queryRes.peerErrors.map((e) => `${e.peerName}: ${e.error}`).join(' · ')}
        </div>
      )}

      {/* Top KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-[11px] uppercase tracking-wider text-slate-400">Collector Status</span>
          <div className="text-lg font-bold font-mono text-white mt-1">
            {status?.running ? 'RUNNING' : status?.daemonDown ? 'DAEMON DOWN' : 'STOPPED'}
          </div>
          <div className="text-[11px] font-mono text-slate-400 mt-0.5">
            {status?.listeners.filter((l) => l.listening).length ?? 0}/{status?.listeners.length ?? 0} listeners up
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-[11px] uppercase tracking-wider text-slate-400">Flows Ingested</span>
          <div className="text-xl font-bold font-mono text-sky-400 mt-1">
            {(status?.flowsIngested ?? 0).toLocaleString()}
          </div>
          <div className="text-[11px] font-mono text-slate-400 mt-0.5">
            {formatBytes(status?.bytesIngested ?? 0)} total
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-[11px] uppercase tracking-wider text-slate-400">Window Avg Rate</span>
          <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
            {formatBps(queryRes?.avgBps ?? 0)}
          </div>
          <div className="text-[11px] font-mono text-slate-400 mt-0.5">
            Self-export: {(status?.selfExportedFlows ?? 0).toLocaleString()} · Repl: {(status?.replicatedPackets ?? 0).toLocaleString()}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-[11px] uppercase tracking-wider text-slate-400">Exporters &amp; Templates</span>
          <div className="text-xl font-bold font-mono text-white mt-1">
            {status?.exportersCount ?? 0} / {status?.templatesCount ?? 0}
          </div>
          <div className="text-[11px] font-mono text-slate-400 mt-0.5">
            Decode errs: {status?.decodeErrors ?? 0}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-[11px] uppercase tracking-wider text-slate-400">Storage &amp; Alerts</span>
          <div className="text-xl font-bold font-mono text-amber-300 mt-1">
            {(status?.diskUsageMb ?? 0).toFixed(1)} MB
          </div>
          <div className="text-[11px] font-mono text-slate-400 mt-0.5">
            {status?.storageMode || 'local'} · {status?.activeAlertsCount ?? 0} unacked · MMDB:{' '}
            {status?.geoipCityLoaded || status?.geoipAsnLoaded ? 'ready' : 'fallback'} · BGP: {status?.bgpPrefixes ?? 0}
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-3">
        {(
          [
            ['explorer', 'Flow Explorer & Sankey'],
            ['maps', 'Maps & Heatmaps'],
            ['reports', '95th-Pct Reports'],
            ['live', 'Live Tail (SSE)'],
            ['exporters', `Exporters & Templates (${exporters.length})`],
            ['alerts', `Alerts & Baselines (${alerts.filter((a) => !a.acknowledged).length})`],
            ['config', 'Pipeline & Listeners Config'],
          ] as Array<[StudioTab, string]>
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            onClick={() => setActiveTab(id)}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold transition ${
              activeTab === id
                ? 'bg-sky-600 text-white'
                : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {activeTab === 'explorer' && (
        <FlowExplorerTab
          queryRes={queryRes}
          loading={querying}
          fql={fql}
          rangeMinutes={rangeMinutes}
          groupBy={groupBy}
          biflow={biflow}
          customWindow={customWindow}
          draftState={draftState}
          onChangeFql={setFql}
          onChangeRange={(m) => {
            setRangeMinutes(m);
            void runQuery(undefined, { rangeMins: m, window: null });
          }}
          onChangeGroupBy={(gb) => {
            setGroupBy(gb);
            void runQuery(undefined, { gb });
          }}
          onToggleBiflow={(b) => {
            setBiflow(b);
            void runQuery(undefined, { biflow: b });
          }}
          onChangeCustomWindow={(w) => {
            setCustomWindow(w);
            void runQuery(undefined, { window: w });
          }}
          onRunQuery={(override) => void runQuery(override)}
          onApplyAlias={async (nextState) => {
            const res = await applyState(nextState);
            if (res.success) {
              setLiveState(structuredClone(nextState));
              setDraftState(structuredClone(nextState));
            }
            return res;
          }}
          onSaveView={(name, fqlVal, rng, gb) => {
            setDraftState((prev) => {
              if (!prev) return prev;
              const cur = NetFlowConfigSchema.parse(prev.netflow ?? {});
              return {
                ...prev,
                netflow: {
                  ...cur,
                  savedViews: [
                    ...cur.savedViews,
                    { id: `sv-${Date.now().toString(36)}`, name, fql: fqlVal, range: rng, groupBy: gb },
                  ],
                },
              };
            });
          }}
        />
      )}

      {activeTab === 'maps' && (
        <div className="space-y-5">
          <GeoTrafficMap
            geoArcs={queryRes?.geoArcs}
            topCountries={queryRes?.topCountries}
            onFilterFql={(clause) => {
              const next = fql.trim() ? `(${fql.trim()}) and ${clause}` : clause;
              setFql(next);
              setActiveTab('explorer');
              void runQuery(next);
            }}
          />
          <FlowHeatmapsPanel
            hostHeatmap={queryRes?.hostHeatmap}
            portTimeHeatmap={queryRes?.portTimeHeatmap}
            onFilterFql={(clause) => {
              const next = fql.trim() ? `(${fql.trim()}) and ${clause}` : clause;
              setFql(next);
              setActiveTab('explorer');
              void runQuery(next);
            }}
          />
        </div>
      )}

      {activeTab === 'reports' && <ReportsPanel />}

      {activeTab === 'live' && <LiveTailTab />}

      {activeTab === 'exporters' && (
        <ExportersTemplatesTab
          exporters={exporters}
          templates={templates}
          draftState={draftState}
          onRefresh={() => void refreshRuntime()}
          onUpdateDraft={(updater) => setDraftState((prev) => (prev ? updater(prev) : prev))}
        />
      )}

      {activeTab === 'alerts' && (
        <AlertsAnomaliesTab
          alerts={alerts}
          draftState={draftState}
          onAckAlert={(id) => {
            void ackNetFlowAlertAction(id).then(() => refreshRuntime());
          }}
          onUpdateDraft={(updater) => setDraftState((prev) => (prev ? updater(prev) : prev))}
        />
      )}

      {activeTab === 'config' && (
        <PipelineConfigTab
          draftState={draftState}
          onUpdateDraft={(updater) => setDraftState((prev) => (prev ? updater(prev) : prev))}
          onAfterInject={() => void Promise.all([refreshRuntime(), runQuery()])}
        />
      )}
    </div>
  );
}
