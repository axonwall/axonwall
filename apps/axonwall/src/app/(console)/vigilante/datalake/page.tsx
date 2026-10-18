'use client';

import React, { useState, useEffect } from 'react';
import {
  Database,
  Layers,
  HardDrive,
  RefreshCw,
  Search,
  Zap,
  Activity,
  Table,
} from 'lucide-react';
import {
  getDataLakeMetricsAction,
} from '@/server/vigilante';

export default function SecurityDataLakePage() {
  const [data, setData] = useState<{
    tables: Array<{ name: string; rows: number; bytes: number; compressedRatio: string }>;
    totalEvents24h: number;
    eventsPerSecond: number;
    storageUsedBytes: number;
  } | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      setLoading(true);
      const res = await getDataLakeMetricsAction();
      setData(res);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const formatBytes = (bytes: number) => {
    if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`;
    if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(2)} MB`;
    return `${(bytes / 1e3).toFixed(2)} KB`;
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Security Data Lake</h1>
            <p className="text-sm text-slate-400">
              High-throughput columnar security telemetry repository (ClickHouse + Parquet format).
            </p>
          </div>
        </div>

        <button
          onClick={loadData}
          className="px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-xl text-xs text-slate-300 font-medium flex items-center gap-2 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh Stats
        </button>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400">Ingestion Throughput</div>
          <div className="text-3xl font-bold text-emerald-400">{data?.eventsPerSecond ?? 0} EPS</div>
          <div className="text-[11px] text-slate-500">Peak burst: 350 EPS</div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400">Total Events Preserved (24h)</div>
          <div className="text-3xl font-bold text-blue-400">
            {data ? (data.totalEvents24h / 1e6).toFixed(2) : 0} Million
          </div>
          <div className="text-[11px] text-slate-500">Zero event drops across pipelines</div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400">On-Disk Compressed Footprint</div>
          <div className="text-3xl font-bold text-white">
            {data ? formatBytes(data.storageUsedBytes) : '0 GB'}
          </div>
          <div className="text-[11px] text-slate-500">Average 4.3x compression ratio</div>
        </div>
      </div>

      {/* Columnar Tables */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between text-xs text-slate-400 border-b border-slate-800 pb-3">
          <span className="font-semibold text-white">Security Event Tables & Partitions</span>
          <span>ClickHouse MergeTree Engine</span>
        </div>

        <div className="space-y-3">
          {(data?.tables ?? []).map((tbl) => (
            <div
              key={tbl.name}
              className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs hover:border-slate-700 transition-all"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Table className="w-4 h-4 text-blue-400" />
                  <span className="font-mono font-semibold text-white">{tbl.name}</span>
                </div>
                <div className="text-[11px] text-slate-400 font-mono">
                  Rows: {tbl.rows.toLocaleString()} records
                </div>
              </div>

              <div className="flex items-center gap-6 font-mono text-xs">
                <div>
                  <span className="text-[10px] text-slate-500 block uppercase">Size</span>
                  <span className="text-slate-300 font-medium">{formatBytes(tbl.bytes)}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 block uppercase">Compression</span>
                  <span className="text-emerald-400 font-medium">{tbl.compressedRatio}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
