'use client';

import { useState } from 'react';
import {
  Activity,
  Cpu,
  Database,
  HardDrive,
  RefreshCw,
  Server,
  Zap,
  Layers,
  ArrowUpRight,
  ArrowDownLeft,
} from 'lucide-react';

export default function SystemHealthPage() {
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d'>('1h');
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => setIsRefreshing(false), 600);
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">System Health & Telemetry</h1>
            <p className="text-sm text-slate-400">
              High-resolution time-series monitoring powered by embedded VictoriaMetrics and Linux cgroups.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center rounded-lg bg-slate-900 border border-slate-800 p-1">
            {(['1h', '24h', '7d'] as const).map((r) => (
              <button
                key={r}
                onClick={() => setTimeRange(r)}
                className={`px-3 py-1 rounded text-xs font-semibold transition ${
                  timeRange === r ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                {r.toUpperCase()}
              </button>
            ))}
          </div>

          <button
            onClick={handleRefresh}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800 transition"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* KPI Status Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* CPU */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">CPU Utilization</span>
            <Cpu className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">14.2%</span>
            <span className="text-xs text-emerald-400">4 Cores (arm64)</span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div className="bg-emerald-500 h-full rounded-full" style={{ width: '14.2%' }} />
          </div>
        </div>

        {/* Memory */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Memory (RAM)</span>
            <Database className="w-4 h-4 text-sky-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">1.82 GB</span>
            <span className="text-xs text-slate-400">/ 7.84 GB</span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div className="bg-sky-500 h-full rounded-full" style={{ width: '23.2%' }} />
          </div>
        </div>

        {/* Conntrack States */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Conntrack Table</span>
            <Layers className="w-4 h-4 text-purple-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">4,812</span>
            <span className="text-xs text-slate-400">/ 262,144 max</span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div className="bg-purple-500 h-full rounded-full" style={{ width: '1.8%' }} />
          </div>
        </div>

        {/* nftables Rates */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Firewall Evaluation</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">28,450</span>
            <span className="text-xs text-slate-400">pkts/sec</span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div className="bg-amber-500 h-full rounded-full" style={{ width: '38%' }} />
          </div>
        </div>
      </div>

      {/* Network Bandwidth Gauges */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ArrowDownLeft className="w-5 h-5 text-emerald-400" />
              <h2 className="text-base font-semibold text-white">WAN Ingress Throughput</h2>
            </div>
            <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
              eth0 (WAN)
            </span>
          </div>
          <div className="h-44 flex items-end justify-between gap-1 p-3 bg-slate-950 rounded-xl border border-slate-800/80">
            {[42, 58, 65, 30, 45, 80, 92, 70, 85, 95, 60, 48, 75, 88, 98, 91, 84, 76, 89, 94].map((v, i) => (
              <div key={i} className="flex-1 flex flex-col items-center gap-1 group">
                <div
                  className="w-full bg-emerald-500/80 hover:bg-emerald-400 transition-all rounded-t"
                  style={{ height: `${v}%` }}
                />
              </div>
            ))}
          </div>
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>Peak: 980 Mbps</span>
            <span>Current: 940 Mbps</span>
            <span>Average: 742 Mbps</span>
          </div>
        </div>

        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ArrowUpRight className="w-5 h-5 text-sky-400" />
              <h2 className="text-base font-semibold text-white">WAN Egress Throughput</h2>
            </div>
            <span className="text-xs font-mono text-sky-400 bg-sky-500/10 px-2 py-0.5 rounded border border-sky-500/20">
              eth0 (WAN)
            </span>
          </div>
          <div className="h-44 flex items-end justify-between gap-1 p-3 bg-slate-950 rounded-xl border border-slate-800/80">
            {[20, 25, 32, 28, 40, 52, 60, 45, 55, 68, 42, 35, 48, 56, 70, 62, 58, 49, 54, 61].map((v, i) => (
              <div key={i} className="flex-1 flex flex-col items-center gap-1 group">
                <div
                  className="w-full bg-sky-500/80 hover:bg-sky-400 transition-all rounded-t"
                  style={{ height: `${v}%` }}
                />
              </div>
            ))}
          </div>
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>Peak: 700 Mbps</span>
            <span>Current: 610 Mbps</span>
            <span>Average: 485 Mbps</span>
          </div>
        </div>
      </div>

      {/* Embedded VictoriaMetrics Configuration */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">VictoriaMetrics Engine Status</h2>
            <p className="text-xs text-slate-400">
              Slim single-node time-series database configured for local retention and Prometheus-compatible scraping.
            </p>
          </div>
          <span className="px-3 py-1 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-lg text-xs font-medium">
            HTTP 127.0.0.1:8428 OK
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block mb-1">PROMETHEUS ENDPOINT</span>
            <span className="text-white font-semibold">http://127.0.0.1:9090/metrics</span>
          </div>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block mb-1">DATA RETENTION</span>
            <span className="text-emerald-400 font-semibold">30 Days (Disk Footprint: 214 MB)</span>
          </div>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block mb-1">SCRAPE INTERVAL</span>
            <span className="text-white font-semibold">10 seconds</span>
          </div>
        </div>
      </div>
    </div>
  );
}
