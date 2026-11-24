'use client';

import React, { useCallback, useEffect, useState } from 'react';
import { Camera, Download, FileBarChart, RefreshCw } from 'lucide-react';
import { formatBps, formatBytes } from '@axonwall/lib/compile/netflow';
import { generateNetFlowReportAction, getNetFlowReportAction } from '@/server/agent';
import type { NetFlowReportResponseSnapshot } from './types';

export function ReportsPanel() {
  const [rangeDays, setRangeDays] = useState(7);
  const [groupBy, setGroupBy] = useState<'interface' | 'exporter' | 'vlan' | 'subnet'>('interface');
  const [report, setReport] = useState<NetFlowReportResponseSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const loadReport = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getNetFlowReportAction({ rangeDays, groupBy, format: 'json' });
      setReport(res);
    } finally {
      setLoading(false);
    }
  }, [groupBy, rangeDays]);

  useEffect(() => {
    void loadReport();
  }, [loadReport]);

  const handleSaveSnapshot = async () => {
    setSaving(true);
    setMsg(null);
    try {
      const res = await generateNetFlowReportAction({ rangeDays, groupBy, format: 'markdown' });
      if (res.success && res.report) {
        setReport(res.report);
        setMsg(res.savedPath ? `Snapshot saved: ${res.savedPath}` : 'Report snapshot saved.');
      } else {
        setMsg('Failed to generate report snapshot.');
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-5">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <FileBarChart className="w-4 h-4 text-emerald-400" />
          <div>
            <h3 className="text-sm font-semibold text-white">95th-Percentile ISP &amp; Capacity Utilization Report</h3>
            <p className="text-xs text-slate-400">
              Computed over 5-minute intervals ({report?.bucketSeconds ?? 300}s buckets) across hot + disk flow chunks
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          <select
            value={rangeDays}
            onChange={(e) => setRangeDays(Number(e.target.value))}
            className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 font-mono text-white"
          >
            <option value={1}>Last 24h (1d)</option>
            <option value={7}>Last 7 Days</option>
            <option value={30}>Last 30 Days</option>
            <option value={90}>Last 90 Days</option>
          </select>
          <select
            value={groupBy}
            onChange={(e) => setGroupBy(e.target.value as typeof groupBy)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 font-mono text-white"
          >
            <option value="interface">Group: Interface</option>
            <option value="exporter">Group: Exporter</option>
            <option value="vlan">Group: VLAN</option>
            <option value="subnet">Group: /24 Subnet</option>
          </select>
          <button
            type="button"
            disabled={loading}
            onClick={() => void loadReport()}
            className="px-3 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-slate-200 flex items-center gap-1"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Recompute
          </button>
          <a
            href={`/api/v1/netflow/reports?rangeDays=${rangeDays}&groupBy=${groupBy}&format=csv&raw=1`}
            className="px-2.5 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-emerald-300 flex items-center gap-1"
          >
            <Download className="w-3.5 h-3.5" />
            CSV
          </a>
          <a
            href={`/api/v1/netflow/reports?rangeDays=${rangeDays}&groupBy=${groupBy}&format=markdown&raw=1`}
            className="px-2.5 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-sky-300 flex items-center gap-1"
          >
            <Download className="w-3.5 h-3.5" />
            Markdown
          </a>
          <button
            type="button"
            disabled={saving}
            onClick={() => void handleSaveSnapshot()}
            className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white font-semibold flex items-center gap-1.5"
          >
            <Camera className="w-3.5 h-3.5" />
            {saving ? 'Saving...' : 'Save Snapshot'}
          </button>
        </div>
      </div>

      {msg && (
        <div className="px-3 py-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs font-mono text-emerald-300">
          {msg}
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto max-h-[440px]">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono border-b border-slate-800 sticky top-0">
              <tr>
                <th className="px-4 py-2.5">Group ({groupBy})</th>
                <th className="px-4 py-2.5 text-right">95th Percentile</th>
                <th className="px-4 py-2.5 text-right">99th Percentile</th>
                <th className="px-4 py-2.5 text-right">Peak Rate</th>
                <th className="px-4 py-2.5 text-right">Average Rate</th>
                <th className="px-4 py-2.5 text-right">Total Bytes</th>
                <th className="px-4 py-2.5 text-right">Flows / 5m Samples</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {(report?.rows ?? []).map((row) => (
                <tr key={row.groupKey} className="hover:bg-slate-800/40 text-slate-200">
                  <td className="px-4 py-2 font-semibold text-white">{row.groupKey}</td>
                  <td className="px-4 py-2 text-right text-amber-300 font-semibold">{formatBps(row.p95Bps)}</td>
                  <td className="px-4 py-2 text-right text-rose-300">{formatBps(row.p99Bps)}</td>
                  <td className="px-4 py-2 text-right text-slate-300">{formatBps(row.peakBps)}</td>
                  <td className="px-4 py-2 text-right text-sky-300">{formatBps(row.avgBps)}</td>
                  <td className="px-4 py-2 text-right text-emerald-300">{formatBytes(row.totalBytes)}</td>
                  <td className="px-4 py-2 text-right text-slate-400">
                    {row.totalFlows.toLocaleString()} / {row.sampleCount}
                  </td>
                </tr>
              ))}
              {(report?.rows ?? []).length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-slate-500">
                    No flow records in this window yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {report?.savedSnapshots && report.savedSnapshots.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
          <div className="text-xs font-semibold text-white">Recent Saved Report Snapshots</div>
          <div className="flex flex-wrap gap-2 font-mono text-[11px] text-slate-300">
            {report.savedSnapshots.map((s) => (
              <span key={s} className="px-2 py-1 rounded bg-slate-950">
                {s}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
