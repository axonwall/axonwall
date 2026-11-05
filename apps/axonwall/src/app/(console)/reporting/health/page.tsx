'use client';

import { useState, useEffect } from 'react';
import {
  Activity,
  Cpu,
  Database,
  HardDrive,
  RefreshCw,
  Server,
  Zap,
  Layers,
  ShieldAlert,
  ShieldCheck,
  ArrowUpRight,
  ArrowDownLeft,
} from 'lucide-react';
import { getSystemHealthTelemetry, getHubCertStatus, type SystemHealthMetrics, type HubCertStatus } from '../../../../server/agent';

export default function SystemHealthPage() {
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [metrics, setMetrics] = useState<SystemHealthMetrics | null>(null);
  // null = not loaded yet. The server action now distinguishes 'missing'
  // from 'error', so a failed cert read renders an alert, not nothing.
  const [cert, setCert] = useState<HubCertStatus | null>(null);

  useEffect(() => {
    getSystemHealthTelemetry().then(setMetrics).catch(() => {});
    getHubCertStatus()
      .then(setCert)
      .catch((err: any) =>
        setCert({ state: 'error', message: err?.message || 'Failed to load hub certificate status.' })
      );
  }, []);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      const data = await getSystemHealthTelemetry();
      setMetrics(data);
    } catch {
    }
    try {
      // C12: Refresh used to fetch telemetry only, so a stale cert
      // display persisted indefinitely after first load.
      const certData = await getHubCertStatus();
      setCert(certData);
    } catch (err: any) {
      setCert({ state: 'error', message: err?.message || 'Failed to load hub certificate status.' });
    } finally {
      setIsRefreshing(false);
    }
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
              High-resolution time-series monitoring powered by embedded Linux cgroups and netfilter subsystem.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* C13: the 1h/24h/7d control changed no data, no fetch, and no
              chart — the charts were constants. No time-series query
              exists for this page, so the control is removed rather
              than left as a dead control that implies range-filtered
              data. */}
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
            <span className="text-2xl font-bold text-white font-mono">
              {metrics ? `${metrics.loadAvg[0].toFixed(2)}` : 'Active'}
            </span>
            <span className="text-xs text-emerald-400">
              {metrics ? `${metrics.cpuCount} Cores (${metrics.arch})` : 'Cores Active'}
            </span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div
              className="bg-emerald-500 h-full rounded-full transition-all"
              style={{ width: metrics ? `${Math.min(100, Math.round(metrics.loadAvg[0] * 25))}%` : '20%' }}
            />
          </div>
        </div>

        {/* Memory */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Memory (RAM)</span>
            <Database className="w-4 h-4 text-sky-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">
              {metrics ? `${metrics.usedMemGB} GB` : 'Active'}
            </span>
            <span className="text-xs text-slate-400">
              {metrics ? `/ ${metrics.totalMemGB} GB` : ''}
            </span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div
              className="bg-sky-500 h-full rounded-full transition-all"
              style={{ width: metrics ? `${metrics.memPercent}%` : '25%' }}
            />
          </div>
        </div>

        {/* Conntrack States */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Netfilter Subsystem</span>
            <Layers className="w-4 h-4 text-purple-400" />
          </div>
          <div className="flex items-baseline gap-2">
            {/* C13: was a hardcoded "Active" at 100% with no measurement
                behind it. No conntrack telemetry is wired here. */}
            <span className="text-2xl font-bold text-slate-400">Unknown</span>
            <span className="text-xs text-slate-500">No measurement available</span>
          </div>
        </div>

        {/* nftables Rates */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Packet Filtering</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            {/* C13: was a hardcoded "Enforcing" at 100% with no check
                behind it. */}
            <span className="text-2xl font-bold text-slate-400">Unknown</span>
            <span className="text-xs text-slate-500">No measurement available</span>
          </div>
        </div>
      </div>

      {/* Network Bandwidth Gauges */}
      {/* Hub TLS certificate (audit B-14) */}
      {/* C12: 'missing' renders an informational card and 'error' an
          alert — neither vanishes the way the old null did. The
          expired-cert icon is red, not amber: the old <= 90 branch gave
          an expired cert the amber icon, understating expiry. */}
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
            Hub certificate status unknown: {cert.message} Check the certificate at
            /etc/axonwall/certs/hub.crt — expiry warnings cannot be shown until it is readable.
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
            Expires{' '}
            <span className="text-white font-semibold">{new Date(cert.expiresAt).toLocaleDateString()}</span>{' '}
            {cert.daysRemaining < 0
              ? `(expired ${Math.abs(cert.daysRemaining)} days ago)`
              : `(${cert.daysRemaining} days remaining)`}{' '}
            · {cert.subject}
          </div>
          {cert.daysRemaining <= 90 && (
            <p className="text-xs text-amber-300">
              Rotate before expiry with <span className="font-mono">axonwall-rotate-hub-cert</span> on the
              appliance. Satellites pinned to the fleet CA are unaffected; browsers must re-trust the new
              self-signed certificate.
            </p>
          )}
        </div>
      )}

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
          {/* C13: the bars and Peak/Current/Average labels were constants
              that never changed with the time range or with traffic. */}
          <div className="h-44 flex items-center justify-center p-3 bg-slate-950 rounded-xl border border-slate-800/80">
            <p className="text-xs text-slate-500 text-center">
              Throughput history unavailable — no time-series query is wired for this page.
            </p>
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
          <div className="h-44 flex items-center justify-center p-3 bg-slate-950 rounded-xl border border-slate-800/80">
            <p className="text-xs text-slate-500 text-center">
              Throughput history unavailable — no time-series query is wired for this page.
            </p>
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
          {/* C13: was a hardcoded "OK" badge that asserted the service
              healthy without checking it. */}
          <span className="px-3 py-1 bg-slate-800 text-slate-400 border border-slate-700 rounded-lg text-xs font-medium">
            Status unknown (not checked)
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block mb-1">PROMETHEUS ENDPOINT</span>
            <span className="text-white font-semibold">http://127.0.0.1:9090/metrics</span>
          </div>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block mb-1">DATA RETENTION</span>
            <span className="text-slate-400 font-semibold">Unknown</span>
          </div>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block mb-1">SCRAPE INTERVAL</span>
            <span className="text-slate-400 font-semibold">Unknown</span>
          </div>
        </div>
      </div>
    </div>
  );
}
