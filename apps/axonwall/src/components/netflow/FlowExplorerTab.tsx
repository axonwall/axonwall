'use client';

import React, { useMemo, useState } from 'react';
import Link from 'next/link';
import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceArea,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  Ban,
  Binary,
  BookmarkPlus,
  Check,
  Copy,
  Download,
  Filter,
  GitBranch,
  ListPlus,
  RefreshCw,
  ShieldAlert,
  X,
} from 'lucide-react';
import {
  buildFlowExportCsv,
  buildTcpdumpFilter,
  formatBps,
  formatBytes,
  validateFqlQuery,
} from '@axonwall/lib/compile/netflow';
import type { Alias, DesiredState } from '@axonwall/lib/schemas';
import { FlowSankeyMatrix } from './FlowSankeyMatrix';
import { FqlInputBar, type FqlLiveSuggestions } from './FqlInputBar';
import {
  FQL_PRESETS,
  SERIES_COLORS,
  TIME_RANGE_OPTIONS,
  type NetFlowQueryRecordSnapshot,
  type NetFlowQueryResponseSnapshot,
  type NetFlowTopEntrySnapshot,
} from './types';

interface FlowExplorerTabProps {
  queryRes: NetFlowQueryResponseSnapshot | null;
  loading: boolean;
  fql: string;
  rangeMinutes: number;
  groupBy: string;
  biflow: boolean;
  customWindow: { startMs: number; endMs: number } | null;
  draftState: DesiredState | null;
  onChangeFql: (next: string) => void;
  onChangeRange: (mins: number) => void;
  onChangeGroupBy: (gb: string) => void;
  onToggleBiflow: (b: boolean) => void;
  onChangeCustomWindow: (w: { startMs: number; endMs: number } | null) => void;
  onRunQuery: (overrideFql?: string) => void;
  onSaveView: (name: string, fql: string, range: string, groupBy: string) => void;
  onApplyAlias?: (nextState: DesiredState) => Promise<{ success: boolean; message?: string }>;
}

export function FlowExplorerTab({
  queryRes,
  loading,
  fql,
  rangeMinutes,
  groupBy,
  biflow,
  customWindow,
  draftState,
  onChangeFql,
  onChangeRange,
  onChangeGroupBy,
  onToggleBiflow,
  onChangeCustomWindow,
  onRunQuery,
  onSaveView,
  onApplyAlias,
}: FlowExplorerTabProps) {
  const [selectedFlow, setSelectedFlow] = useState<NetFlowQueryRecordSnapshot | null>(null);
  const [chartUnit, setChartUnit] = useState<'bps' | 'pps'>('bps');
  const [topTab, setTopTab] = useState<'conversations' | 'sources' | 'destinations' | 'apps' | 'infra'>('conversations');
  const [tableMode, setTableMode] = useState<'flows' | 'sessions'>('flows');
  const [newViewName, setNewViewName] = useState('');
  const [copiedBpf, setCopiedBpf] = useState(false);

  // Time-brush drag zoom state on AreaChart
  const [dragLeft, setDragLeft] = useState<string | null>(null);
  const [dragRight, setDragRight] = useState<string | null>(null);

  // Inline SOC action feedback state
  const [xdpTtl, setXdpTtl] = useState(3600);
  const [blockedIps, setBlockedIps] = useState<Record<string, boolean>>({});
  const [actionToast, setActionToast] = useState<string | null>(null);
  const [aliasPickerIp, setAliasPickerIp] = useState<string | null>(null);
  const [targetAliasName, setTargetAliasName] = useState('netflow_watchlist');

  const fqlCheck = useMemo(() => validateFqlQuery(fql), [fql]);

  const liveSuggestions = useMemo<FqlLiveSuggestions>(
    () => ({
      exporters: (queryRes?.topExporters ?? []).map((x) => x.key),
      interfaces: (queryRes?.topInterfaces ?? []).map((x) => x.key),
      apps: (queryRes?.topApps ?? []).map((x) => x.key),
      countries: (queryRes?.topCountries ?? []).map((x) => x.key),
    }),
    [queryRes],
  );

  const chartData = useMemo(() => {
    if (!queryRes?.timeseries?.length) return [];
    return queryRes.timeseries.map((pt) => {
      const row: Record<string, string | number> = { time: pt.timeLabel, tsMs: pt.timestampMs };
      if (chartUnit === 'pps') {
        row['PPS'] = Math.round(pt.pps);
      } else {
        for (const k of queryRes.seriesKeys) {
          row[k] = Math.round((pt.series[k] ?? 0) / 1000); // Kbps
        }
      }
      return row;
    });
  }, [queryRes, chartUnit]);

  const savedViews = draftState?.netflow?.savedViews ?? [];

  const appendFilter = (clause: string) => {
    const next = fql.trim() ? `(${fql.trim()}) and ${clause}` : clause;
    onChangeFql(next);
    onRunQuery(next);
  };

  const handleXdpToggle = async (ip: string) => {
    const currentlyBlocked = Boolean(blockedIps[ip]);
    try {
      const res = await fetch(
        currentlyBlocked ? `/api/v1/ebpf/xdp/block?ip=${encodeURIComponent(ip)}` : '/api/v1/ebpf/xdp/block',
        currentlyBlocked
          ? { method: 'DELETE' }
          : {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ ip, ttlSeconds: xdpTtl }),
            },
      );
      if (res.ok) {
        setBlockedIps((prev) => ({ ...prev, [ip]: !currentlyBlocked }));
        setActionToast(currentlyBlocked ? `Removed XDP block for ${ip}` : `Blocked ${ip} in Ring-0 XDP (${xdpTtl}s)`);
      } else {
        const data = (await res.json().catch(() => ({}))) as { error?: string };
        setActionToast(data.error || `Failed XDP action on ${ip}`);
      }
    } catch {
      setActionToast(`Network error invoking XDP block on ${ip}`);
    }
  };

  const handleAddIpToAlias = async (ip: string, aliasName: string) => {
    if (!draftState || !onApplyAlias) return;
    const cleanName = aliasName.trim() || 'netflow_watchlist';
    const existing = draftState.aliases ?? [];
    const idx = existing.findIndex((a) => a.name === cleanName);
    let nextAliases: Alias[];
    if (idx >= 0) {
      const cur = existing[idx]!;
      const entries = cur.entries.includes(ip) ? cur.entries : [...cur.entries, ip];
      nextAliases = existing.map((a, i) => (i === idx ? { ...a, entries } : a));
    } else {
      nextAliases = [
        ...existing,
        {
          name: cleanName,
          type: 'network',
          description: 'Added from NetFlow Studio',
          entries: [ip],
          enabled: true,
        },
      ];
    }
    const res = await onApplyAlias({ ...draftState, aliases: nextAliases });
    setAliasPickerIp(null);
    setActionToast(
      res.success ? `Added ${ip} to firewall alias "${cleanName}"` : res.message || `Failed updating alias ${cleanName}`,
    );
  };

  const handleDownload = (fmt: 'csv' | 'json') => {
    const flows = queryRes?.flows ?? [];
    if (flows.length === 0) return;
    const content = fmt === 'csv' ? buildFlowExportCsv(flows) : JSON.stringify(flows, null, 2);
    const blob = new Blob([content], { type: fmt === 'csv' ? 'text/csv' : 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `axonwall-netflow-${Date.now()}.${fmt}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const renderTopList = (title: string, items: NetFlowTopEntrySnapshot[], field: string) => (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2.5">
      <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</div>
      {items.length === 0 ? (
        <div className="text-xs text-slate-500 py-4 text-center">No entries recorded.</div>
      ) : (
        <div className="space-y-1.5">
          {items.slice(0, 8).map((item) => {
            const pct = queryRes?.totalBytes ? Math.min(100, Math.round((item.bytes / queryRes.totalBytes) * 100)) : 0;
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => appendFilter(`${field}="${item.key}"`)}
                className="w-full text-left group hover:bg-slate-800/70 rounded px-2 py-1 transition"
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="font-mono text-white truncate max-w-[190px]">
                    {item.label || item.key}
                  </span>
                  <span className="font-mono text-sky-300 text-[11px]">
                    {formatBytes(item.bytes)} ({pct}%)
                  </span>
                </div>
                <div className="h-1 bg-slate-950 rounded overflow-hidden mt-1">
                  <div className="h-full bg-sky-500/80" style={{ width: `${Math.max(2, pct)}%` }} />
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );

  return (
    <div className="space-y-5">
      {/* FQL Filter, Time Window & Saved Views Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <FqlInputBar
            value={fql}
            onChange={onChangeFql}
            onSubmit={() => {
              if (fqlCheck.valid) onRunQuery();
            }}
            live={liveSuggestions}
          />

          <select
            value={rangeMinutes}
            onChange={(e) => {
              onChangeCustomWindow(null);
              onChangeRange(Number(e.target.value));
            }}
            className="px-2.5 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-white"
          >
            {TIME_RANGE_OPTIONS.map((t) => (
              <option key={t.id} value={t.minutes}>
                Last {t.label}
              </option>
            ))}
          </select>

          <select
            value={groupBy}
            onChange={(e) => onChangeGroupBy(e.target.value)}
            className="px-2.5 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-white"
          >
            <option value="protocol">Group: Protocol</option>
            <option value="app">Group: Application</option>
            <option value="direction">Group: Direction</option>
            <option value="src">Group: Source</option>
            <option value="dst">Group: Destination</option>
            <option value="exporter">Group: Exporter</option>
            <option value="vlan">Group: VLAN</option>
          </select>

          <button
            type="button"
            disabled={!fqlCheck.valid || loading}
            onClick={() => onRunQuery()}
            className="px-3.5 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white text-xs font-semibold flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Query
          </button>

          {customWindow && (
            <button
              type="button"
              onClick={() => onChangeCustomWindow(null)}
              className="px-2.5 py-2 rounded-lg bg-amber-500/15 border border-amber-500/40 text-amber-200 text-[11px] font-mono flex items-center gap-1"
            >
              Zoomed: {new Date(customWindow.startMs).toLocaleTimeString()}–{new Date(customWindow.endMs).toLocaleTimeString()}
              <X className="w-3 h-3 ml-1" />
            </button>
          )}

          {queryRes?.engine && (
            <span className="px-2 py-1.5 rounded bg-slate-950 text-[10px] font-mono text-slate-400">
              engine:{queryRes.engine}
            </span>
          )}

          <button
            type="button"
            onClick={() => handleDownload('csv')}
            className="px-2.5 py-2 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs flex items-center gap-1"
            title="Export matched flows CSV"
          >
            <Download className="w-3.5 h-3.5 text-emerald-400" />
            CSV
          </button>
          <button
            type="button"
            onClick={() => handleDownload('json')}
            className="px-2.5 py-2 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs flex items-center gap-1"
            title="Export matched flows JSON"
          >
            JSON
          </button>
        </div>

        {!fqlCheck.valid && (
          <div className="text-xs text-rose-400 font-mono">{fqlCheck.error}</div>
        )}
        {queryRes?.fqlError && (
          <div className="text-xs text-rose-400 font-mono">Query error: {queryRes.fqlError}</div>
        )}

        {/* Quick Filter Presets + Saved Views */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] text-slate-400 flex items-center gap-1">
              <Filter className="w-3 h-3" /> Presets:
            </span>
            <button
              type="button"
              onClick={() => {
                onChangeFql('');
                onRunQuery('');
              }}
              className="px-2 py-0.5 rounded bg-slate-950 hover:bg-slate-800 border border-slate-800 text-[11px] text-slate-300"
            >
              Reset All
            </button>
            {FQL_PRESETS.map((p) => (
              <button
                key={p.label}
                type="button"
                onClick={() => {
                  onChangeFql(p.fql);
                  onRunQuery(p.fql);
                }}
                className="px-2 py-0.5 rounded bg-slate-950 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-sky-300"
              >
                {p.label}
              </button>
            ))}
            {savedViews.map((sv) => (
              <button
                key={sv.id}
                type="button"
                onClick={() => {
                  onChangeFql(sv.fql);
                  onRunQuery(sv.fql);
                }}
                className="px-2 py-0.5 rounded bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/40 text-[11px] text-emerald-300"
              >
                ★ {sv.name}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1.5">
            <input
              type="text"
              value={newViewName}
              onChange={(e) => setNewViewName(e.target.value)}
              placeholder="Save view name..."
              className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-[11px] text-white w-36"
            />
            <button
              type="button"
              disabled={!newViewName.trim()}
              onClick={() => {
                onSaveView(newViewName.trim(), fql, `${rangeMinutes}m`, groupBy);
                setNewViewName('');
              }}
              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-[11px] text-slate-200 flex items-center gap-1"
            >
              <BookmarkPlus className="w-3 h-3 text-sky-400" />
              Pin View
            </button>
          </div>
        </div>
      </div>

      {/* Stacked Throughput Chart + Interactive Flow Sankey Matrix */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white">Throughput History ({groupBy})</h3>
              <p className="text-xs text-slate-400">
                Matched {queryRes?.totalMatchedFlows ?? 0} flows · {formatBytes(queryRes?.totalBytes ?? 0)} · Avg{' '}
                {formatBps(queryRes?.avgBps ?? 0)}
              </p>
            </div>
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded border border-slate-800">
              {(['bps', 'pps'] as const).map((u) => (
                <button
                  key={u}
                  type="button"
                  onClick={() => setChartUnit(u)}
                  className={`px-2 py-0.5 rounded text-[11px] font-mono uppercase ${
                    chartUnit === u ? 'bg-sky-600 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {u}
                </button>
              ))}
            </div>
          </div>

          <div className="h-[250px] w-full select-none">
            {chartData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                Waiting for ingested NetFlow / IPFIX / sFlow data points...
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={chartData}
                  onMouseDown={(state) => {
                    if (state && typeof state.activeLabel === 'string') {
                      setDragLeft(state.activeLabel);
                      setDragRight(state.activeLabel);
                    }
                  }}
                  onMouseMove={(state) => {
                    if (dragLeft && state && typeof state.activeLabel === 'string') {
                      setDragRight(state.activeLabel);
                    }
                  }}
                  onMouseUp={() => {
                    if (dragLeft && dragRight && dragLeft !== dragRight) {
                      const p1 = chartData.find((d) => String(d.time) === dragLeft);
                      const p2 = chartData.find((d) => String(d.time) === dragRight);
                      const t1 = Number(p1?.tsMs ?? 0);
                      const t2 = Number(p2?.tsMs ?? 0);
                      if (t1 > 0 && t2 > 0) {
                        const lo = Math.min(t1, t2);
                        const hi = Math.max(t1, t2) + 60_000;
                        onChangeCustomWindow({ startMs: lo, endMs: hi });
                      }
                    }
                    setDragLeft(null);
                    setDragRight(null);
                  }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#94a3b8' }} />
                  <YAxis
                    tick={{ fontSize: 10, fill: '#94a3b8' }}
                    unit={chartUnit === 'pps' ? ' pps' : ' Kbps'}
                    width={72}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#020617',
                      borderColor: '#334155',
                      fontSize: '12px',
                      color: '#f8fafc',
                    }}
                  />
                  {chartUnit === 'pps' ? (
                    <Area type="monotone" dataKey="PPS" stroke="#10b981" fill="#10b981" fillOpacity={0.25} />
                  ) : (
                    (queryRes?.seriesKeys ?? []).map((key, idx) => (
                      <Area
                        key={key}
                        type="monotone"
                        dataKey={key}
                        stackId="1"
                        stroke={SERIES_COLORS[idx % SERIES_COLORS.length]}
                        fill={SERIES_COLORS[idx % SERIES_COLORS.length]}
                        fillOpacity={0.28}
                      />
                    ))
                  )}
                  {dragLeft && dragRight && dragLeft !== dragRight && (
                    <ReferenceArea x1={dragLeft} x2={dragRight} strokeOpacity={0.4} fill="#38bdf8" fillOpacity={0.18} />
                  )}
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
          <div className="text-[10px] font-mono text-slate-500">Tip: click and drag across chart area to zoom time window</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white">Conversation Matrix (Src → App → Dst)</h3>
              <p className="text-xs text-slate-400">Click any ribbon or endpoint to filter FQL dynamically</p>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              {queryRes?.uniqueSources ?? 0} src · {queryRes?.uniqueDestinations ?? 0} dst
            </span>
          </div>
          <FlowSankeyMatrix links={queryRes?.sankeyLinks ?? []} onFilterFql={(c) => appendFilter(c)} />
        </div>
      </div>

      {/* Multi-Dimensional Top-N Switcher */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-1.5">
          {[
            { id: 'conversations', label: 'Top Conversations' },
            { id: 'sources', label: 'Sources & Destinations' },
            { id: 'apps', label: 'Apps & Protocols' },
            { id: 'infra', label: 'Exporters, Interfaces, VLANs & Geo' },
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setTopTab(tab.id as typeof topTab)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border ${
                topTab === tab.id
                  ? 'bg-sky-600 border-sky-500 text-white'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {topTab === 'conversations' && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="overflow-x-auto max-h-[320px]">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase font-mono border-b border-slate-800 sticky top-0">
                  <tr>
                    <th className="px-3 py-2">Source</th>
                    <th className="px-3 py-2">Destination</th>
                    <th className="px-3 py-2">App / Proto</th>
                    <th className="px-3 py-2">Dir</th>
                    <th className="px-3 py-2">Bytes</th>
                    <th className="px-3 py-2">Packets</th>
                    <th className="px-3 py-2">Avg Rate</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70 font-mono">
                  {(queryRes?.topConversations ?? []).map((c, idx) => (
                    <tr
                      key={`${c.srcIp}-${c.dstIp}-${c.dstPort}-${idx}`}
                      onClick={() => appendFilter(`src=${c.srcIp} and dst=${c.dstIp}`)}
                      className="hover:bg-slate-800/50 cursor-pointer text-slate-200"
                    >
                      <td className="px-3 py-2">{c.srcHost ? `${c.srcHost} (${c.srcIp})` : c.srcIp}</td>
                      <td className="px-3 py-2">
                        {c.dstHost ? `${c.dstHost} (${c.dstIp})` : c.dstIp}:{c.dstPort}
                      </td>
                      <td className="px-3 py-2 text-sky-300">
                        {c.appName || c.protocolName} ({c.protocolName})
                      </td>
                      <td className="px-3 py-2 text-slate-400">{c.direction || '-'}</td>
                      <td className="px-3 py-2 text-emerald-300">{formatBytes(c.bytes)}</td>
                      <td className="px-3 py-2 text-slate-300">{c.packets.toLocaleString()}</td>
                      <td className="px-3 py-2 text-slate-300 flex items-center gap-1.5">
                        {formatBps(c.bps)}
                        {c.threatMatch ? (
                          <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 text-[10px]">
                            {c.threatMatch}
                          </span>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                  {(queryRes?.topConversations ?? []).length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-4 py-6 text-center text-slate-500">
                        No conversations match this filter/window.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {topTab === 'sources' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {renderTopList('Top Source Talkers', queryRes?.topSources ?? [], 'src')}
            {renderTopList('Top Destinations', queryRes?.topDestinations ?? [], 'dst')}
          </div>
        )}

        {topTab === 'apps' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {renderTopList('Applications / Services', queryRes?.topApps ?? [], 'app')}
            {renderTopList('L4 Protocols', queryRes?.topProtocols ?? [], 'proto')}
            {renderTopList('Top ASNs / Organizations', queryRes?.topAsns ?? [], 'asn')}
          </div>
        )}

        {topTab === 'infra' && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {renderTopList('Exporters', queryRes?.topExporters ?? [], 'exporter')}
            {renderTopList('Interfaces', queryRes?.topInterfaces ?? [], 'if')}
            {renderTopList('VLANs', queryRes?.topVlans ?? [], 'vlan')}
            {renderTopList('Countries', queryRes?.topCountries ?? [], 'country')}
          </div>
        )}
      </div>

      {actionToast && (
        <div className="px-3 py-2 rounded-lg bg-slate-900 border border-sky-500/40 text-xs font-mono text-sky-200 flex items-center justify-between">
          <span>{actionToast}</span>
          <button type="button" onClick={() => setActionToast(null)} className="underline text-slate-400">
            Dismiss
          </button>
        </div>
      )}

      {/* Raw Flow Records / Bidirectional Sessions Table + Slide-Over Detail Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className={`${selectedFlow ? 'lg:col-span-2' : 'lg:col-span-3'} bg-slate-900 border border-slate-800 rounded-xl overflow-hidden`}>
          <div className="px-4 py-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setTableMode('flows')}
                className={`px-2.5 py-1 rounded text-xs font-semibold ${
                  tableMode === 'flows' ? 'bg-sky-600 text-white' : 'bg-slate-950 text-slate-400 hover:text-white'
                }`}
              >
                Raw Flows ({queryRes?.flows.length ?? 0}/{queryRes?.totalMatchedFlows ?? 0})
              </button>
              <button
                type="button"
                onClick={() => {
                  setTableMode('sessions');
                  if (!biflow) onToggleBiflow(true);
                }}
                className={`px-2.5 py-1 rounded text-xs font-semibold ${
                  tableMode === 'sessions' ? 'bg-sky-600 text-white' : 'bg-slate-950 text-slate-400 hover:text-white'
                }`}
              >
                Bidirectional Sessions ({queryRes?.sessions?.length ?? 0})
              </button>
            </div>
            <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
              <span>XDP TTL:</span>
              <select
                value={xdpTtl}
                onChange={(e) => setXdpTtl(Number(e.target.value))}
                className="px-1.5 py-0.5 rounded bg-slate-950 text-slate-200"
              >
                <option value={900}>15m</option>
                <option value={3600}>1h</option>
                <option value={86400}>24h</option>
              </select>
            </div>
          </div>

          {tableMode === 'sessions' ? (
            <div className="overflow-x-auto max-h-[420px]">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase font-mono border-b border-slate-800 sticky top-0">
                  <tr>
                    <th className="px-3 py-2">Initiator</th>
                    <th className="px-3 py-2">Responder</th>
                    <th className="px-3 py-2">App</th>
                    <th className="px-3 py-2">Fwd / Rev</th>
                    <th className="px-3 py-2">Asym</th>
                    <th className="px-3 py-2">RTT / Retx</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {(queryRes?.sessions ?? []).map((s) => (
                    <tr key={s.id} className="hover:bg-slate-800/40 text-slate-200">
                      <td className="px-3 py-2 whitespace-nowrap">
                        {s.initiatorHost ? `${s.initiatorHost} (${s.initiatorIp})` : s.initiatorIp}:{s.initiatorPort}
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap">
                        {s.responderHost ? `${s.responderHost} (${s.responderIp})` : s.responderIp}:{s.responderPort}
                      </td>
                      <td className="px-3 py-2 text-sky-300">
                        {s.appName || s.protocolName}
                        {s.unansweredSyn && (
                          <span className="ml-1.5 px-1 py-0.5 rounded bg-amber-500/20 text-amber-300 text-[10px]">
                            NO-SYN-ACK
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap">
                        <span className="text-emerald-300">{formatBytes(s.bytesFwd)}</span> /{' '}
                        <span className="text-sky-300">{formatBytes(s.bytesRev)}</span>
                      </td>
                      <td className="px-3 py-2 text-amber-300">{Math.round(s.asymmetryRatio * 100)}%</td>
                      <td className="px-3 py-2 text-slate-300">
                        {s.avgRttMs ? `${s.avgRttMs.toFixed(1)}ms` : '-'} · retx {s.totalRetransmits ?? 0}
                      </td>
                    </tr>
                  ))}
                  {(queryRes?.sessions ?? []).length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                        {biflow ? 'No stitched bidirectional sessions found.' : 'Click Bidirectional Sessions to stitch active flows.'}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="overflow-x-auto max-h-[420px]">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase font-mono border-b border-slate-800 sticky top-0">
                  <tr>
                    <th className="px-3 py-2">Time</th>
                    <th className="px-3 py-2">Source</th>
                    <th className="px-3 py-2">Destination</th>
                    <th className="px-3 py-2">App / Tags</th>
                    <th className="px-3 py-2">Bytes</th>
                    <th className="px-3 py-2">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {(queryRes?.flows ?? []).map((f) => {
                    const sel = selectedFlow?.id === f.id;
                    const isBlocked = Boolean(blockedIps[f.srcIp]);
                    return (
                      <tr
                        key={f.id}
                        onClick={() => setSelectedFlow(f)}
                        className={`cursor-pointer ${
                          sel ? 'bg-sky-950/60 text-sky-200' : 'hover:bg-slate-800/50 text-slate-300'
                        }`}
                      >
                        <td className="px-3 py-2 whitespace-nowrap text-slate-400">
                          <div>{new Date(f.timestamp).toLocaleTimeString()}</div>
                          {f.hostName && <div className="text-[10px] text-cyan-300">{f.hostName}</div>}
                        </td>
                        <td className="px-3 py-2 whitespace-nowrap">
                          <div>
                            {f.srcIp}:{f.srcPort}
                          </div>
                          {f.postNatSrcIp && (
                            <div className="text-[10px] text-amber-300">
                              NAT {f.postNatSrcIp}:{f.postNatSrcPort}
                            </div>
                          )}
                        </td>
                        <td className="px-3 py-2 whitespace-nowrap">
                          <div>
                            {f.dstIp}:{f.dstPort}
                          </div>
                          {f.peerAs ? <div className="text-[10px] text-slate-400">AS{f.peerAs}</div> : null}
                        </td>
                        <td className="px-3 py-2 whitespace-nowrap">
                          <span>{f.appName || f.protocolName}</span>
                          {f.k3sPodName && (
                            <span className="ml-1 px-1 py-0.5 rounded bg-indigo-500/20 text-indigo-300 text-[10px]">
                              {f.k3sNamespace}/{f.k3sPodName}
                            </span>
                          )}
                          {f.threatMatch ? <ShieldAlert className="w-3.5 h-3.5 text-rose-400 inline ml-1" /> : null}
                        </td>
                        <td className="px-3 py-2 whitespace-nowrap text-emerald-300">
                          <div>{formatBytes(f.bytes)}</div>
                          {f.rttMs ? <div className="text-[10px] text-slate-400">{f.rttMs.toFixed(1)}ms</div> : null}
                        </td>
                        <td
                          className="px-3 py-2 whitespace-nowrap"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <div className="flex items-center gap-1">
                            <button
                              type="button"
                              onClick={() => void handleXdpToggle(f.srcIp)}
                              title={isBlocked ? `Unblock ${f.srcIp} from Ring-0 XDP` : `Block ${f.srcIp} in Ring-0 XDP`}
                              className={`p-1 rounded ${
                                isBlocked
                                  ? 'bg-rose-600 text-white'
                                  : 'bg-slate-950 hover:bg-rose-600/30 text-rose-300'
                              }`}
                            >
                              <Ban className="w-3 h-3" />
                            </button>
                            <Link
                              href={`/diagnostics/packet-capture?bpf=${encodeURIComponent(buildTcpdumpFilter(f))}&iface=${encodeURIComponent(f.inIfName || 'any')}`}
                              title="Pivot to Live Packet Capture"
                              className="p-1 rounded bg-slate-950 hover:bg-slate-800 text-emerald-300"
                            >
                              <Binary className="w-3 h-3" />
                            </Link>
                            <button
                              type="button"
                              onClick={() => setAliasPickerIp(aliasPickerIp === f.srcIp ? null : f.srcIp)}
                              title="Add Src IP to Firewall Alias"
                              className="p-1 rounded bg-slate-950 hover:bg-slate-800 text-amber-300"
                            >
                              <ListPlus className="w-3 h-3" />
                            </button>
                            <Link
                              href={`/topology?focus=${encodeURIComponent(f.srcIp)}`}
                              title="Inspect in Topology Studio"
                              className="p-1 rounded bg-slate-950 hover:bg-slate-800 text-sky-300"
                            >
                              <GitBranch className="w-3 h-3" />
                            </Link>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                  {(queryRes?.flows ?? []).length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                        No raw flows found. Enable self-export or send a synthetic test burst in Pipeline Config.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}

          {aliasPickerIp && (
            <div className="px-4 py-3 bg-slate-950 border-t border-slate-800 flex flex-wrap items-center gap-2 text-xs">
              <span className="font-mono text-amber-300">Add {aliasPickerIp} to Alias:</span>
              <input
                type="text"
                list="netflow-alias-names"
                value={targetAliasName}
                onChange={(e) => setTargetAliasName(e.target.value)}
                className="px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono text-white"
              />
              <datalist id="netflow-alias-names">
                {(draftState?.aliases ?? []).map((a) => (
                  <option key={a.name} value={a.name} />
                ))}
              </datalist>
              <button
                type="button"
                onClick={() => void handleAddIpToAlias(aliasPickerIp, targetAliasName)}
                className="px-2.5 py-1 rounded bg-amber-600 hover:bg-amber-500 text-white font-semibold"
              >
                Apply Alias
              </button>
              <button type="button" onClick={() => setAliasPickerIp(null)} className="text-slate-400 underline">
                Cancel
              </button>
            </div>
          )}
        </div>

        {selectedFlow && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <span className="font-semibold text-white">Flow Dissector</span>
              <button
                type="button"
                onClick={() => setSelectedFlow(null)}
                className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-1.5 font-mono">
              {[
                ['Version / Host', `${selectedFlow.version.toUpperCase()} (${selectedFlow.hostName || selectedFlow.exporterName || selectedFlow.exporterIp})`],
                ['Source', `${selectedFlow.srcIp}:${selectedFlow.srcPort} ${selectedFlow.srcHost ? `(${selectedFlow.srcHost})` : ''}`],
                ['Destination', `${selectedFlow.dstIp}:${selectedFlow.dstPort} ${selectedFlow.dstHost ? `(${selectedFlow.dstHost})` : ''}`],
                ['NAT Translation', selectedFlow.postNatSrcIp || selectedFlow.postNatDstIp ? `${selectedFlow.postNatSrcIp || selectedFlow.srcIp}:${selectedFlow.postNatSrcPort || selectedFlow.srcPort} → ${selectedFlow.postNatDstIp || selectedFlow.dstIp}:${selectedFlow.postNatDstPort || selectedFlow.dstPort}` : 'none'],
                ['Protocol / App', `${selectedFlow.protocolName} · ${selectedFlow.appName || '-'} · ${selectedFlow.direction || '-'}`],
                ['Counters / NPM', `${formatBytes(selectedFlow.bytes)} · ${selectedFlow.packets} pkts · RTT ${selectedFlow.rttMs ? `${selectedFlow.rttMs.toFixed(1)}ms` : '-'} · Retx ${selectedFlow.retransmits ?? 0}`],
                ['Interfaces / VLAN', `in=${selectedFlow.inIfName || selectedFlow.inIfIndex || '-'} out=${selectedFlow.outIfName || selectedFlow.outIfIndex || '-'} vlan=${selectedFlow.vlanId || 0}`],
                ['Geo / City', `${selectedFlow.srcCountry || '-'} ${selectedFlow.srcCity || ''} → ${selectedFlow.dstCountry || '-'} ${selectedFlow.dstCity || ''}`],
                ['BGP AS / Path', selectedFlow.peerAs ? `Peer AS${selectedFlow.peerAs} · Path [${(selectedFlow.asPath ?? []).join(' ')}] · NH ${selectedFlow.bgpNextHop || '-'}` : `${selectedFlow.srcOrg || '-'} → ${selectedFlow.dstOrg || '-'}`],
                ['K3s / Threat', `ns=${selectedFlow.k3sNamespace || '-'} pod=${selectedFlow.k3sPodName || selectedFlow.k3sWorkload || '-'} · threat=${selectedFlow.threatMatch || 'none'}`],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between gap-2 py-1 border-b border-slate-800/50">
                  <span className="text-slate-400 font-sans shrink-0">{k}</span>
                  <span className="text-slate-100 text-right break-all">{v}</span>
                </div>
              ))}
            </div>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => void handleXdpToggle(selectedFlow.srcIp)}
                className="py-2 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-200 font-semibold flex items-center justify-center gap-1"
              >
                <Ban className="w-3.5 h-3.5" />
                {blockedIps[selectedFlow.srcIp] ? 'Unblock XDP' : 'Block in XDP'}
              </button>
              <Link
                href={`/diagnostics/packet-capture?bpf=${encodeURIComponent(buildTcpdumpFilter(selectedFlow))}&iface=${encodeURIComponent(selectedFlow.inIfName || 'any')}`}
                className="py-2 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-200 font-semibold flex items-center justify-center gap-1"
              >
                <Binary className="w-3.5 h-3.5" />
                Live PCAP
              </Link>
            </div>
            <button
              type="button"
              onClick={() => {
                void navigator.clipboard?.writeText(buildTcpdumpFilter(selectedFlow));
                setCopiedBpf(true);
                setTimeout(() => setCopiedBpf(false), 1800);
              }}
              className="w-full py-2 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-sky-300 font-mono flex items-center justify-center gap-1.5"
            >
              {copiedBpf ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copiedBpf ? 'Copied tcpdump BPF filter!' : `Copy BPF: ${buildTcpdumpFilter(selectedFlow)}`}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
