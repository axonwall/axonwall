'use client';

import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  FileText,
  Filter,
  Loader2,
  RefreshCw,
  Search,
} from 'lucide-react';

interface LogEntry {
  _time?: string;
  _msg?: string;
  node_id?: string;
  hostname?: string;
  source?: string;
  level?: string;
  src_ip?: string;
  dst_ip?: string;
  action?: string;
  rule_id?: string;
  [key: string]: unknown;
}

interface NodeOption {
  nodeId: string;
  nodeName: string;
}

const SOURCES = ['all', 'nflog', 'journald', 'suricata', 'crowdsec', 'kea', 'unbound', 'satellite-firewall'] as const;
const LEVELS = ['all', 'error', 'warn', 'info'] as const;
const WINDOWS = [
  { id: '15m', label: '15m' },
  { id: '1h', label: '1h' },
  { id: '6h', label: '6h' },
  { id: '24h', label: '24h' },
] as const;

export default function ReportingLogsPage() {
  const [queryText, setQueryText] = useState('');
  const [nodeId, setNodeId] = useState('all');
  const [source, setSource] = useState<string>('all');
  const [level, setLevel] = useState<string>('all');
  const [windowId, setWindowId] = useState<string>('1h');
  const [autoRefresh, setAutoRefresh] = useState(false);

  const [nodes, setNodes] = useState<NodeOption[]>([]);
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [unconfigured, setUnconfigured] = useState(false);
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/observability/logs/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          q: queryText.trim(),
          nodeId,
          source,
          level,
          start: windowId,
          limit: 250,
        }),
      });
      const json = (await res.json().catch(() => null)) as {
        data?: {
          configured?: boolean;
          unavailable?: boolean;
          entries?: LogEntry[];
          reason?: string;
        };
        error?: string;
      } | null;

      if (!res.ok) {
        setStatusMsg(json?.error || `HTTP ${res.status}`);
        setEntries([]);
        return;
      }

      const d = json?.data;
      setUnconfigured(d?.configured === false);
      setStatusMsg(d?.reason || null);
      setEntries(Array.isArray(d?.entries) ? d.entries : []);
    } catch (err: any) {
      setStatusMsg(err?.message || 'Failed to query logs');
      setEntries([]);
    } finally {
      setLoading(false);
    }
  }, [level, nodeId, queryText, source, windowId]);

  useEffect(() => {
    fetch('/api/v1/netflow/nodes', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (Array.isArray(d?.nodes)) setNodes(d.nodes);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    void fetchLogs();
  }, [fetchLogs]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(() => {
      void fetchLogs();
    }, 5000);
    return () => clearInterval(timer);
  }, [autoRefresh, fetchLogs]);

  const badgeClass = (lvl?: string) => {
    switch ((lvl || '').toLowerCase()) {
      case 'error':
      case 'crit':
        return 'bg-rose-500/15 text-rose-300 border-rose-500/30';
      case 'warn':
      case 'warning':
        return 'bg-amber-500/15 text-amber-300 border-amber-500/30';
      default:
        return 'bg-sky-500/15 text-sky-300 border-sky-500/30';
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Centralized Log Explorer</h1>
            <p className="text-sm text-slate-400">
              Query LogsQL streams across edge NFLOG firewall events, journald, Suricata IDS, CrowdSec, Kea DHCP, and Unbound DNS.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="accent-emerald-500"
            />
            Live Tail (5s)
          </label>
          <button
            type="button"
            onClick={() => void fetchLogs()}
            className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs text-slate-200 flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filters & Query Bar */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void fetchLogs();
        }}
        className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3"
      >
        <div className="flex flex-wrap gap-2">
          <div className="relative flex-1 min-w-[240px]">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={queryText}
              onChange={(e) => setQueryText(e.target.value)}
              placeholder='LogsQL filter (e.g. DROP OR src_ip:"192.168.10." OR _msg:~timeout)'
              className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-sm text-white font-mono"
            />
          </div>
          <select
            value={nodeId}
            onChange={(e) => setNodeId(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white font-mono"
          >
            <option value="all">All Nodes ({nodes.length})</option>
            {nodes.map((n) => (
              <option key={n.nodeId} value={n.nodeId}>
                {n.nodeName || n.nodeId}
              </option>
            ))}
          </select>
          <select
            value={level}
            onChange={(e) => setLevel(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white font-mono"
          >
            {LEVELS.map((lvl) => (
              <option key={lvl} value={lvl}>
                Level: {lvl}
              </option>
            ))}
          </select>
          <select
            value={windowId}
            onChange={(e) => setWindowId(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white font-mono"
          >
            {WINDOWS.map((w) => (
              <option key={w.id} value={w.id}>
                Last {w.label}
              </option>
            ))}
          </select>
          <button
            type="submit"
            disabled={loading}
            className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-semibold text-white"
          >
            Run LogsQL
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <Filter className="w-3.5 h-3.5 text-slate-400 mr-1" />
          {SOURCES.map((src) => (
            <button
              key={src}
              type="button"
              onClick={() => setSource(src)}
              className={`px-2.5 py-1 rounded-md font-mono transition ${
                source === src
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                  : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-white'
              }`}
            >
              {src}
            </button>
          ))}
        </div>
      </form>

      {(unconfigured || statusMsg) && (
        <div
          className={`p-4 rounded-xl border text-xs flex items-center gap-2 ${
            unconfigured
              ? 'bg-slate-900 border-slate-800 text-slate-300'
              : 'bg-amber-500/10 border-amber-500/30 text-amber-200'
          }`}
        >
          <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400" />
          <span>
            {statusMsg || 'VictoriaLogs endpoint is not configured.'}{' '}
            <a href="/reporting/observability" className="underline text-sky-400">
              Configure Observability &amp; Offload
            </a>
          </span>
        </div>
      )}

      {/* Results */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 uppercase">
              <tr>
                <th className="py-2.5 px-3 w-8" />
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Node</th>
                <th className="py-2.5 px-3">Source</th>
                <th className="py-2.5 px-3">Level</th>
                <th className="py-2.5 px-3">Message</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {loading && entries.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-slate-400">
                    <span className="inline-flex items-center gap-2">
                      <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
                      Querying VictoriaLogs...
                    </span>
                  </td>
                </tr>
              ) : entries.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-slate-500">
                    No matching log events in the selected window.
                  </td>
                </tr>
              ) : (
                entries.map((row, idx) => {
                  const isOpen = expandedIdx === idx;
                  return (
                    <React.Fragment key={idx}>
                      <tr
                        onClick={() => setExpandedIdx(isOpen ? null : idx)}
                        className="hover:bg-slate-950/80 cursor-pointer transition"
                      >
                        <td className="py-2 px-3 text-slate-500">
                          {isOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap text-slate-400">
                          {row._time ? new Date(row._time).toLocaleString() : '—'}
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap text-sky-300">
                          {String(row.hostname || row.node_id || 'local')}
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap text-slate-300">
                          {String(row.source || 'syslog')}
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <span className={`px-1.5 py-0.5 rounded border text-[10px] ${badgeClass(String(row.level || 'info'))}`}>
                            {String(row.level || 'info').toUpperCase()}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-slate-200 max-w-2xl truncate">
                          {String(row._msg || '')}
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-slate-950">
                          <td colSpan={6} className="p-3">
                            <pre className="text-[11px] text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                              {JSON.stringify(row, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
