'use client';

import { useState, useEffect, useCallback } from 'react';
import {
  Activity,
  Cpu,
  Database,
  RefreshCw,
  Zap,
  Layers,
  ShieldAlert,
  ShieldCheck,
  ArrowUpRight,
  ArrowDownLeft,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { getSystemHealthTelemetry, getHubCertStatus, type SystemHealthMetrics, type HubCertStatus } from '../../../../server/agent';

interface PromPoint {
  time: string;
  ts: number;
  cpu?: number;
  memPct?: number;
  rxKbps?: number;
  txKbps?: number;
  conntrack?: number;
  rttMs?: number;
  lossPct?: number;
}

interface NodeOption {
  nodeId: string;
  nodeName: string;
  metricsOnline?: boolean;
}

const WINDOW_SECONDS: Record<string, number> = {
  '15m': 900,
  '1h': 3600,
  '6h': 21600,
  '24h': 86400,
};

function mergeSeries(
  seriesList: Array<{ key: keyof PromPoint; result: any[]; transform?: (v: number) => number }>
): PromPoint[] {
  const buckets = new Map<number, PromPoint>();
  for (const { key, result, transform } of seriesList) {
    if (!Array.isArray(result) || result.length === 0) continue;
    for (const s of result) {
      const values = Array.isArray(s?.values) ? s.values : [];
      for (const pair of values) {
        const ts = Number(pair?.[0] ?? 0);
        const raw = Number(pair?.[1] ?? 0);
        if (!Number.isFinite(ts) || !Number.isFinite(raw)) continue;
        const val = transform ? transform(raw) : raw;
        const existing = buckets.get(ts) || {
          ts,
          time: new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        };
        const prev = existing[key];
        (existing as any)[key] = typeof prev === 'number' ? prev + val : val;
        buckets.set(ts, existing);
      }
    }
  }
  return Array.from(buckets.values()).sort((a, b) => a.ts - b.ts);
}

export default function SystemHealthPage() {
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [metrics, setMetrics] = useState<SystemHealthMetrics | null>(null);
  const [metricsLoaded, setMetricsLoaded] = useState(false);
  const [cert, setCert] = useState<HubCertStatus | null>(null);

  const [nodes, setNodes] = useState<NodeOption[]>([]);
  const [selectedNode, setSelectedNode] = useState<string>('all');
  const [windowId, setWindowId] = useState<string>('1h');
  const [vmSeries, setVmSeries] = useState<PromPoint[]>([]);
  const [vmStatus, setVmStatus] = useState<{
    configured: boolean;
    unavailable: boolean;
    url?: string;
    reason?: string;
  }>({ configured: false, unavailable: false });

  const loadVmTelemetry = useCallback(async (nodeVal: string, winVal: string) => {
    const endSec = Math.floor(Date.now() / 1000);
    const span = WINDOW_SECONDS[winVal] || 3600;
    const startSec = endSec - span;
    const stepSec = Math.max(15, Math.floor(span / 60));
    const nodeFilter = nodeVal !== 'all' ? `{node_id="${nodeVal.replace(/"/g, '')}"}` : '';

    const runProm = async (query: string) => {
      const res = await fetch('/api/v1/observability/metrics/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, start: startSec, end: endSec, step: stepSec }),
      });
      if (!res.ok) return null;
      const json = await res.json().catch(() => null);
      return json?.data ?? null;
    };

    const [statusRes, cpuRes, memRes, rxRes, txRes, ctRes, rttRes, lossRes] = await Promise.all([
      fetch('/api/v1/observability/status', { cache: 'no-store' })
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
      runProm(`avg(axonwall_host_cpu_usage_percent${nodeFilter} or axonwall_cpu_usage_percent${nodeFilter})`),
      runProm(
        `avg((axonwall_host_memory_used_bytes${nodeFilter} / clamp_min(axonwall_host_memory_total_bytes${nodeFilter}, 1) * 100) or axonwall_mem_usage_percent${nodeFilter})`
      ),
      runProm(
        `sum(rate(axonwall_interface_rx_bytes_total${nodeFilter}[1m]) or rate(axonwall_net_rx_bytes_total${nodeFilter}[1m]))`
      ),
      runProm(
        `sum(rate(axonwall_interface_tx_bytes_total${nodeFilter}[1m]) or rate(axonwall_net_tx_bytes_total${nodeFilter}[1m]))`
      ),
      runProm(`sum(axonwall_conntrack_entries${nodeFilter})`),
      runProm(`avg(axonwall_sdwan_gateway_rtt_ms${nodeFilter} or axonwall_sdwan_rtt_ms${nodeFilter})`),
      runProm(
        `avg(axonwall_sdwan_gateway_packet_loss_percent${nodeFilter} or axonwall_sdwan_packet_loss_percent${nodeFilter})`
      ),
    ]);

    const vmEndpoint = statusRes?.endpoints?.victoriaMetrics;
    const primaryRes = cpuRes ?? memRes ?? rxRes ?? txRes ?? ctRes ?? rttRes ?? lossRes;
    if (primaryRes) {
      setVmStatus({
        configured: Boolean(primaryRes.configured),
        unavailable: Boolean(primaryRes.unavailable),
        url: vmEndpoint?.url,
        reason: primaryRes.reason,
      });
      setVmSeries(
        mergeSeries([
          { key: 'cpu', result: cpuRes?.result ?? [], transform: (v) => Number(v.toFixed(1)) },
          { key: 'memPct', result: memRes?.result ?? [], transform: (v) => Number(v.toFixed(1)) },
          { key: 'rxKbps', result: rxRes?.result ?? [], transform: (v) => Math.round(v / 1024) },
          { key: 'txKbps', result: txRes?.result ?? [], transform: (v) => Math.round(v / 1024) },
          { key: 'conntrack', result: ctRes?.result ?? [], transform: (v) => Math.round(v) },
          { key: 'rttMs', result: rttRes?.result ?? [], transform: (v) => Number(v.toFixed(2)) },
          { key: 'lossPct', result: lossRes?.result ?? [], transform: (v) => Number(v.toFixed(1)) },
        ])
      );
    } else if (vmEndpoint) {
      setVmStatus({ configured: Boolean(vmEndpoint.configured), unavailable: true, url: vmEndpoint.url });
    }
  }, []);

  useEffect(() => {
    getSystemHealthTelemetry()
      .then(setMetrics)
      .catch(() => {})
      .finally(() => setMetricsLoaded(true));
    getHubCertStatus()
      .then(setCert)
      .catch((err: any) =>
        setCert({ state: 'error', message: err?.message || 'Failed to load hub certificate status.' })
      );
    fetch('/api/v1/netflow/nodes', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (Array.isArray(d?.nodes)) setNodes(d.nodes);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    void loadVmTelemetry(selectedNode, windowId);
  }, [loadVmTelemetry, selectedNode, windowId]);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      const [data, certData] = await Promise.all([
        getSystemHealthTelemetry().catch(() => null),
        getHubCertStatus().catch((err: any) => ({
          state: 'error' as const,
          message: err?.message || 'Failed to load hub certificate status.',
        })),
        loadVmTelemetry(selectedNode, windowId),
      ]);
      if (data) setMetrics(data);
      if (certData) setCert(certData);
    } finally {
      setMetricsLoaded(true);
      setIsRefreshing(false);
    }
  };

  const latestPoint = vmSeries[vmSeries.length - 1];

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">System Health & Telemetry</h1>
            <p className="text-sm text-slate-400">
              High-resolution time-series monitoring from VictoriaMetrics and local kernel subsystem telemetry.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label="Filter telemetry by node"
            value={selectedNode}
            onChange={(e) => setSelectedNode(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200"
          >
            <option value="all">All Nodes ({nodes.length || 1})</option>
            {nodes.map((n) => (
              <option key={n.nodeId} value={n.nodeId}>
                {n.nodeName || n.nodeId}
              </option>
            ))}
          </select>
          <div className="flex items-center rounded-lg bg-slate-900 border border-slate-800 p-0.5 text-xs font-mono">
            {(['15m', '1h', '6h', '24h'] as const).map((w) => (
              <button
                key={w}
                type="button"
                onClick={() => setWindowId(w)}
                className={`px-2.5 py-1 rounded ${
                  windowId === w ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                {w}
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
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">CPU Load / Utilization</span>
            <Cpu className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">
              {typeof latestPoint?.cpu === 'number'
                ? `${latestPoint.cpu.toFixed(1)}%`
                : metrics
                  ? metrics.loadAvg[0].toFixed(2)
                  : metricsLoaded
                    ? 'Unknown'
                    : '…'}
            </span>
            <span className="text-xs text-emerald-400">
              {metrics ? `${metrics.cpuCount} Cores (${metrics.arch})` : metricsLoaded ? 'VM series' : ''}
            </span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div
              className="bg-emerald-500 h-full rounded-full transition-all"
              style={{
                width:
                  typeof latestPoint?.cpu === 'number'
                    ? `${Math.min(100, Math.round(latestPoint.cpu))}%`
                    : metrics
                      ? `${Math.min(100, Math.round(metrics.loadAvg[0] * 25))}%`
                      : '0%',
              }}
            />
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Memory (RAM)</span>
            <Database className="w-4 h-4 text-sky-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">
              {metrics
                ? `${metrics.usedMemGB} GB`
                : typeof latestPoint?.memPct === 'number'
                  ? `${latestPoint.memPct.toFixed(1)}%`
                  : metricsLoaded
                    ? 'Unknown'
                    : '…'}
            </span>
            <span className="text-xs text-slate-400">
              {metrics ? `/ ${metrics.totalMemGB} GB` : ''}
            </span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div
              className="bg-sky-500 h-full rounded-full transition-all"
              style={{
                width: metrics
                  ? `${metrics.memPercent}%`
                  : typeof latestPoint?.memPct === 'number'
                    ? `${Math.min(100, Math.round(latestPoint.memPct))}%`
                    : '0%',
              }}
            />
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Conntrack Table</span>
            <Layers className="w-4 h-4 text-purple-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">
              {typeof latestPoint?.conntrack === 'number' ? latestPoint.conntrack.toLocaleString() : '—'}
            </span>
            <span className="text-xs text-slate-400">
              {typeof latestPoint?.conntrack === 'number' ? 'tracked flows' : 'Awaiting VM metric'}
            </span>
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">SD-WAN RTT / Loss</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">
              {typeof latestPoint?.rttMs === 'number' ? `${latestPoint.rttMs} ms` : '—'}
            </span>
            <span className="text-xs text-slate-400">
              {typeof latestPoint?.lossPct === 'number' ? `${latestPoint.lossPct}% loss` : 'No probe metric'}
            </span>
          </div>
        </div>
      </div>

      {/* Hub TLS certificate */}
      {cert?.state === 'missing' && (
        <div className="p-5 rounded-2xl border space-y-2 bg-slate-900 border-slate-800">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Hub TLS Certificate</span>
            <ShieldCheck className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-sm text-slate-300">
            No hub certificate is installed on this box — expiry tracking does not apply.
          </div>
        </div>
      )}

      {cert?.state === 'error' && (
        <div className="p-5 rounded-2xl border space-y-2 bg-red-500/10 border-red-500/30">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Hub TLS Certificate</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-sm text-red-200">
            Hub certificate status unknown: {cert.message}
          </div>
        </div>
      )}

      {cert?.state === 'ok' && (
        <div
          className={`p-5 rounded-2xl border space-y-2 ${
            cert.daysRemaining < 0
              ? 'bg-red-500/10 border-red-500/30'
              : cert.daysRemaining <= 90
                ? 'bg-amber-500/10 border-amber-500/30'
                : 'bg-slate-900 border-slate-800'
          }`}
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Hub TLS Certificate</span>
            {cert.daysRemaining < 0 ? (
              <ShieldAlert className="w-4 h-4 text-red-400" />
            ) : cert.daysRemaining <= 90 ? (
              <ShieldAlert className="w-4 h-4 text-amber-400" />
            ) : (
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            )}
          </div>
          <div className="text-sm text-slate-300">
            Expires <span className="text-white font-semibold">{new Date(cert.expiresAt).toLocaleDateString()}</span>{' '}
            ({cert.daysRemaining} days remaining) · {cert.subject}
          </div>
        </div>
      )}

      {/* Time-Series Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ArrowDownLeft className="w-5 h-5 text-emerald-400" />
              <h2 className="text-base font-semibold text-white">Interface Throughput (RX / TX KB/s)</h2>
            </div>
            <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
              {selectedNode === 'all' ? 'All Nodes' : selectedNode}
            </span>
          </div>
          {vmSeries.length > 0 ? (
            <div className="h-52">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={vmSeries}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="time" tick={{ fontSize: 11, fill: '#94a3b8' }} />
                  <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} unit=" KB/s" width={72} />
                  <Tooltip />
                  <Area type="monotone" dataKey="rxKbps" name="RX KB/s" stroke="#10b981" fill="#10b981" fillOpacity={0.2} />
                  <Area type="monotone" dataKey="txKbps" name="TX KB/s" stroke="#38bdf8" fill="#38bdf8" fillOpacity={0.15} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-52 flex items-center justify-center p-3 bg-slate-950 rounded-xl border border-slate-800/80">
              <p className="text-xs text-slate-500 text-center">
                {!vmStatus.configured
                  ? 'VictoriaMetrics not configured — enable Central Analytics or Edge Offload to view historical throughput.'
                  : vmStatus.reason || 'No throughput time-series samples found in selected window.'}
              </p>
            </div>
          )}
        </div>

        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ArrowUpRight className="w-5 h-5 text-sky-400" />
              <h2 className="text-base font-semibold text-white">CPU, Memory &amp; SD-WAN Latency</h2>
            </div>
            <span className="text-xs font-mono text-sky-400 bg-sky-500/10 px-2 py-0.5 rounded border border-sky-500/20">
              {windowId}
            </span>
          </div>
          {vmSeries.length > 0 ? (
            <div className="h-52">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={vmSeries}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="time" tick={{ fontSize: 11, fill: '#94a3b8' }} />
                  <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} width={52} />
                  <Tooltip />
                  <Line type="monotone" dataKey="cpu" name="CPU %" stroke="#10b981" dot={false} />
                  <Line type="monotone" dataKey="memPct" name="RAM %" stroke="#38bdf8" dot={false} />
                  <Line type="monotone" dataKey="rttMs" name="SD-WAN RTT ms" stroke="#f59e0b" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-52 flex items-center justify-center p-3 bg-slate-950 rounded-xl border border-slate-800/80">
              <p className="text-xs text-slate-500 text-center">
                {!vmStatus.configured
                  ? 'VictoriaMetrics not configured — enable Central Analytics or Edge Offload to view CPU/RAM/SD-WAN history.'
                  : vmStatus.reason || 'No system metric samples found in selected window.'}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* VictoriaMetrics Backend Status */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">VictoriaMetrics Engine Status</h2>
            <p className="text-xs text-slate-400">
              Prometheus Remote-Write &amp; PromQL backend for edge routers and satellites.
            </p>
          </div>
          <span
            className={`px-3 py-1 rounded-lg text-xs font-medium border ${
              vmStatus.configured && !vmStatus.unavailable
                ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                : vmStatus.configured
                  ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}
          >
            {vmStatus.configured && !vmStatus.unavailable
              ? 'Connected'
              : vmStatus.configured
                ? 'Degraded / Unreachable'
                : 'Not configured'}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block mb-1">VICTORIAMETRICS URL</span>
            <span className="text-white font-semibold">{vmStatus.url || 'Unconfigured'}</span>
          </div>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block mb-1">QUERY WINDOW</span>
            <span className="text-slate-200 font-semibold">{windowId}</span>
          </div>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block mb-1">NODES REPORTING</span>
            <span className="text-slate-200 font-semibold">{nodes.length}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
