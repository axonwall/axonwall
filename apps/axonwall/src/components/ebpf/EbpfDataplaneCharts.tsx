'use client';

import React, { useMemo, useState } from 'react';
import {
  Activity,
  Cpu,
  Layers,
  Network,
  ShieldAlert,
} from 'lucide-react';
import {
  Area,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ComposedChart,
  Legend,
  Line,
  Pie,
  PieChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  formatBytesCompact,
  formatPps,
  type DataplaneRateSample,
  type EbpfOverviewTelemetry,
} from '@/lib/ebpf-telemetry';

interface EbpfDataplaneChartsProps {
  overview: EbpfOverviewTelemetry | null;
  rateHistory: DataplaneRateSample[];
}

const TOOLTIP_STYLE = {
  backgroundColor: '#0f172a',
  borderColor: '#334155',
  borderRadius: '0.5rem',
  fontSize: '12px',
  color: '#f1f5f9',
};

const PROTO_COLORS: Record<string, string> = {
  TCP: '#10b981',
  UDP: '#38bdf8',
  ICMP: '#f59e0b',
  ICMPv6: '#a855f7',
  ESP: '#ec4899',
  AH: '#f97316',
  GRE: '#06b6d4',
};

export function EbpfDataplaneCharts({ overview, rateHistory }: EbpfDataplaneChartsProps) {
  const [rateChartMode, setRateChartMode] = useState<'verdict' | 'bandwidth'>('verdict');
  const [cpuChartMetric, setCpuChartMetric] = useState<'packets' | 'bytes'>('packets');

  const dp = overview?.dataplane;
  const stats = dp?.xdpStats;
  const daemonDown = Boolean(overview?.daemonDown);

  const perCpuData = useMemo(() => {
    const list = dp?.perCpuStats || [];
    return list.map((c) => ({
      core: `CPU ${c.cpu}`,
      passPkts: c.xdpPass,
      dropPkts: c.xdpDrop,
      rxBytesKiB: Math.round((c.rxBytes / 1024) * 10) / 10,
      rxPackets: c.rxPackets,
      synPackets: c.tcpSynPackets,
    }));
  }, [dp?.perCpuStats]);

  const rssSkewRatio = useMemo(() => {
    const list = dp?.perCpuStats || [];
    if (list.length < 2) return null;
    const total = list.reduce((acc, c) => acc + c.rxPackets, 0);
    if (total === 0) return 1.0;
    const avg = total / list.length;
    const max = Math.max(...list.map((c) => c.rxPackets));
    return avg > 0 ? Math.round((max / avg) * 100) / 100 : 1.0;
  }, [dp?.perCpuStats]);

  const protoPieData = useMemo(() => {
    return (dp?.protocolBreakdown || []).map((p, idx) => ({
      name: p.protoName || `PROTO ${p.protocol}`,
      bytes: p.bytes,
      packets: p.packets,
      flows: p.flows,
      fill:
        PROTO_COLORS[p.protoName] ||
        ['#10b981', '#38bdf8', '#f59e0b', '#a855f7', '#ec4899', '#64748b'][idx % 6],
    }));
  }, [dp?.protocolBreakdown]);

  const topPortsData = useMemo(() => {
    return (dp?.topPorts || []).slice(0, 10).map((pt) => ({
      label: pt.service ? `${pt.port} (${pt.service})` : `${pt.protoName}:${pt.port}`,
      kib: Math.round((pt.bytes / 1024) * 10) / 10,
      bytes: pt.bytes,
      packets: pt.packets,
      flows: pt.flows,
      synPackets: pt.synPackets,
      rstPackets: pt.rstPackets,
      isSynHeavy: pt.packets > 0 && pt.synPackets / pt.packets >= 0.45,
    }));
  }, [dp?.topPorts]);

  const blockedBarData = useMemo(() => {
    return (dp?.blockedIps || [])
      .slice()
      .sort((a, b) => b.droppedPackets - a.droppedPackets)
      .slice(0, 10)
      .map((b) => ({
        ip: b.ip,
        droppedPackets: b.droppedPackets,
        droppedBytes: b.droppedBytes,
        expiresInSeconds: b.expiresInSeconds,
        family: b.family,
      }));
  }, [dp?.blockedIps]);

  const synMetersData = useMemo(() => {
    return (dp?.synRateMeters || []).slice(0, 10).map((m) => ({
      ip: m.ip,
      synCount: m.synCount,
      droppedPackets: m.droppedPackets,
      windowAgeMs: m.windowAgeMs,
    }));
  }, [dp?.synRateMeters]);

  const latestRate = rateHistory[rateHistory.length - 1];
  const totalV4V6 = (stats?.ipv4Packets ?? 0) + (stats?.ipv6Packets ?? 0);
  const v4Pct = totalV4V6 > 0 ? Math.round(((stats?.ipv4Packets ?? 0) / totalV4V6) * 100) : 0;
  const v6Pct = totalV4V6 > 0 ? 100 - v4Pct : 0;
  const vlanPct =
    (stats?.rxPackets ?? 0) > 0
      ? Math.min(100, Math.round(((stats?.vlanTaggedPackets ?? 0) / (stats?.rxPackets ?? 1)) * 100))
      : 0;

  const totalDrops = stats?.xdpDropPackets ?? 0;
  const synDrops = stats?.synFloodDrops ?? 0;
  const lpmDrops = stats?.lpmCidrDrops ?? 0;
  const hostDrops = Math.max(0, totalDrops - synDrops - lpmDrops);
  const synLimit = dp?.synFloodLimitPps ?? 0;

  return (
    <div className="space-y-6">
      {/* Live Dataplane Summary Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 p-4 rounded-xl bg-slate-900/80 border border-slate-800">
        <div className="space-y-1">
          <div className="text-xs text-slate-400 flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-emerald-400" />
            Live XDP Rate
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-white">
            {daemonDown ? 'Offline' : latestRate ? formatPps(latestRate.rxPps) : 'Sampling...'}
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400">
            {latestRate ? `${latestRate.rxMbps.toFixed(2)} Mbps • ${formatPps(latestRate.dropPps)} drop` : '4s delta window'}
          </div>
        </div>

        <div className="space-y-1">
          <div className="text-xs text-slate-400 flex items-center gap-1.5">
            <Network className="w-3.5 h-3.5 text-sky-400" />
            Cumulative XDP RX
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-white">
            {(stats?.rxPackets ?? 0).toLocaleString()}
          </div>
          <div className="text-[11px] font-mono tabular-nums text-sky-300">
            {formatBytesCompact(stats?.rxBytes ?? 0)} ({dp?.attachedInterfaces?.length || 0} NICs)
          </div>
        </div>

        <div className="space-y-1">
          <div className="text-xs text-slate-400 flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            Line-Rate XDP_DROP
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-rose-300">
            {totalDrops.toLocaleString()}
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400">
            Host {hostDrops.toLocaleString()} • CIDR {lpmDrops.toLocaleString()} • SYN {synDrops.toLocaleString()}
          </div>
        </div>

        <div className="space-y-1">
          <div className="text-xs text-slate-400 flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-amber-400" />
            Active LRU Flows
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-white">
            {(dp?.totalFlowCount ?? dp?.topFlowsCount ?? 0).toLocaleString()}
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400">
            v4: {(dp?.totalFlowCountV4 ?? 0).toLocaleString()} • v6: {(dp?.totalFlowCountV6 ?? 0).toLocaleString()}
          </div>
        </div>

        <div className="space-y-1">
          <div className="text-xs text-slate-400 flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-purple-400" />
            NIC RSS Core Skew
          </div>
          <div
            className={`text-xl font-bold font-mono tabular-nums ${
              rssSkewRatio !== null && rssSkewRatio > 2.0 ? 'text-amber-300' : 'text-emerald-300'
            }`}
          >
            {rssSkewRatio !== null ? `${rssSkewRatio.toFixed(2)}x` : '—'}
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400">
            {(dp?.perCpuStats?.length ?? 0) > 0
              ? `${dp?.perCpuStats?.length} online CPUs`
              : 'No per-CPU XDP samples'}
          </div>
        </div>
      </div>

      {/* Row 1: Rolling XDP Time-Series + Per-CPU Core Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-7 p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-base font-bold text-white">Real-Time XDP Ring-0 Verdict Rate</h3>
              <p className="text-xs text-slate-400">
                Computed from live <code className="font-mono text-emerald-300">xdp_stats_map</code> per-CPU counter deltas
              </p>
            </div>
            <div className="inline-flex rounded-lg bg-slate-950 border border-slate-800 p-0.5 text-xs">
              <button
                type="button"
                onClick={() => setRateChartMode('verdict')}
                className={`px-2.5 py-1 rounded-md font-medium transition ${
                  rateChartMode === 'verdict' ? 'bg-emerald-500/20 text-emerald-300' : 'text-slate-400 hover:text-white'
                }`}
              >
                PPS Verdicts
              </button>
              <button
                type="button"
                onClick={() => setRateChartMode('bandwidth')}
                className={`px-2.5 py-1 rounded-md font-medium transition ${
                  rateChartMode === 'bandwidth' ? 'bg-sky-500/20 text-sky-300' : 'text-slate-400 hover:text-white'
                }`}
              >
                Mbps &amp; Drop Cause
              </button>
            </div>
          </div>

          {daemonDown ? (
            <div className="h-[250px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg">
              Daemon offline — real-time XDP verdict telemetry cannot be sampled.
            </div>
          ) : rateHistory.length < 2 ? (
            <div className="h-[250px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg">
              Collecting second poll sample to compute live packet-per-second deltas...
            </div>
          ) : (
            <div className="h-[250px]">
              <ResponsiveContainer width="100%" height="100%">
                {rateChartMode === 'verdict' ? (
                  <ComposedChart data={rateHistory}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                    <XAxis dataKey="time" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                    <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} width={58} />
                    <Tooltip
                      contentStyle={TOOLTIP_STYLE}
                      formatter={(val: any, name: any) => [`${Number(val ?? 0).toLocaleString()} pps`, String(name)]}
                    />
                    <Legend wrapperStyle={{ fontSize: '11px' }} />
                    <Area
                      type="monotone"
                      dataKey="passPps"
                      name="XDP_PASS"
                      stroke="#10b981"
                      fill="#10b981"
                      fillOpacity={0.18}
                    />
                    <Area
                      type="monotone"
                      dataKey="dropPps"
                      name="XDP_DROP"
                      stroke="#f43f5e"
                      fill="#f43f5e"
                      fillOpacity={0.25}
                    />
                    <Line
                      type="monotone"
                      dataKey="synPps"
                      name="TCP SYN"
                      stroke="#f59e0b"
                      dot={false}
                      strokeWidth={1.75}
                    />
                  </ComposedChart>
                ) : (
                  <ComposedChart data={rateHistory}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                    <XAxis dataKey="time" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                    <YAxis yAxisId="mbps" tick={{ fill: '#38bdf8', fontSize: 11 }} width={52} unit=" Mb" />
                    <YAxis yAxisId="drops" orientation="right" tick={{ fill: '#f43f5e', fontSize: 11 }} width={48} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Legend wrapperStyle={{ fontSize: '11px' }} />
                    <Area
                      yAxisId="mbps"
                      type="monotone"
                      dataKey="rxMbps"
                      name="Ingress Mbps"
                      stroke="#38bdf8"
                      fill="#38bdf8"
                      fillOpacity={0.2}
                    />
                    <Bar yAxisId="drops" dataKey="synFloodDropPps" name="SYN-Flood Drops/s" fill="#f59e0b" stackId="d" />
                    <Bar yAxisId="drops" dataKey="lpmDropPps" name="LPM CIDR Drops/s" fill="#f43f5e" stackId="d" />
                  </ComposedChart>
                )}
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Per-CPU XDP Core Distribution */}
        <div className="lg:col-span-5 p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-base font-bold text-white">Per-CPU XDP Core Load</h3>
              <p className="text-xs text-slate-400">
                Inspect NIC RSS queue fan-out across <code className="font-mono text-sky-300">PERCPU_ARRAY</code>
              </p>
            </div>
            <div className="inline-flex rounded-lg bg-slate-950 border border-slate-800 p-0.5 text-xs">
              <button
                type="button"
                onClick={() => setCpuChartMetric('packets')}
                className={`px-2.5 py-1 rounded-md font-medium transition ${
                  cpuChartMetric === 'packets' ? 'bg-emerald-500/20 text-emerald-300' : 'text-slate-400 hover:text-white'
                }`}
              >
                Packets
              </button>
              <button
                type="button"
                onClick={() => setCpuChartMetric('bytes')}
                className={`px-2.5 py-1 rounded-md font-medium transition ${
                  cpuChartMetric === 'bytes' ? 'bg-sky-500/20 text-sky-300' : 'text-slate-400 hover:text-white'
                }`}
              >
                KiB RX
              </button>
            </div>
          </div>

          {perCpuData.length === 0 ? (
            <div className="h-[250px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg">
              {daemonDown
                ? 'Daemon offline — per-CPU XDP map unavailable.'
                : 'XDP dataplane has no active CPU counters attached yet.'}
            </div>
          ) : (
            <div className="h-[250px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={perCpuData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="core" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} width={58} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                  {cpuChartMetric === 'packets' ? (
                    <>
                      <Bar dataKey="passPkts" name="XDP_PASS" stackId="cpu" fill="#10b981" radius={[0, 0, 0, 0]} />
                      <Bar dataKey="dropPkts" name="XDP_DROP" stackId="cpu" fill="#f43f5e" radius={[4, 4, 0, 0]} />
                    </>
                  ) : (
                    <Bar dataKey="rxBytesKiB" name="RX Volume (KiB)" fill="#38bdf8" radius={[4, 4, 0, 0]} />
                  )}
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Row 2: Protocol / L3 Family Breakdown + Top Service Ports */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-5 p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-white">Protocol, Dual-Stack &amp; VLAN Mix</h3>
              <p className="text-xs text-slate-400">Aggregated directly from XDP 5-tuple flow tables</p>
            </div>
            <span className="text-xs font-mono tabular-nums text-emerald-400">
              {protoPieData.reduce((s, p) => s + p.flows, 0)} flows
            </span>
          </div>

          {protoPieData.length === 0 ? (
            <div className="h-[190px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg">
              No active flows in <code className="font-mono mx-1">flow_map</code> /{' '}
              <code className="font-mono ml-1">flow6_map</code>.
            </div>
          ) : (
            <div className="h-[190px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protoPieData}
                    dataKey="bytes"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={44}
                    outerRadius={74}
                    paddingAngle={2}
                  >
                    {protoPieData.map((entry) => (
                      <Cell key={entry.name} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={TOOLTIP_STYLE}
                    formatter={(val: any, name: any) => [formatBytesCompact(Number(val ?? 0)), String(name)]}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Dual-Stack & VLAN proportional breakdown */}
          <div className="space-y-2.5 pt-2 border-t border-slate-800 text-xs">
            <div>
              <div className="flex justify-between font-mono tabular-nums text-[11px] mb-1">
                <span className="text-emerald-300">IPv4 ({v4Pct}%)</span>
                <span className="text-sky-300">IPv6 ({v6Pct}%)</span>
              </div>
              <div className="h-2 w-full rounded-full bg-slate-950 overflow-hidden flex">
                <div className="bg-emerald-500 h-full" style={{ width: `${v4Pct}%` }} />
                <div className="bg-sky-500 h-full" style={{ width: `${v6Pct}%` }} />
              </div>
            </div>

            <div className="flex items-center justify-between text-[11px] font-mono tabular-nums text-slate-300">
              <span>802.1Q / QinQ VLAN Tagged</span>
              <span className="text-purple-300">
                {(stats?.vlanTaggedPackets ?? 0).toLocaleString()} pkts ({vlanPct}%)
              </span>
            </div>

            {(dp?.vlanBreakdown || []).filter((v) => v.vlanId > 0).length > 0 && (
              <div className="flex flex-wrap gap-1.5 pt-1">
                {(dp?.vlanBreakdown || [])
                  .filter((v) => v.vlanId > 0)
                  .slice(0, 8)
                  .map((v) => (
                    <span
                      key={v.vlanId}
                      className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 font-mono tabular-nums text-[11px] text-purple-300"
                    >
                      VLAN {v.vlanId}: {formatBytesCompact(v.bytes)}
                    </span>
                  ))}
              </div>
            )}
          </div>
        </div>

        {/* Top Destination Service Ports */}
        <div className="lg:col-span-7 p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-white">Top Destination Services by XDP Bytes</h3>
              <p className="text-xs text-slate-400">
                Amber bars indicate elevated TCP SYN ratio (&ge;45% SYN packets)
              </p>
            </div>
            <span className="text-xs font-mono tabular-nums text-slate-400">
              {topPortsData.length} active ports
            </span>
          </div>

          {topPortsData.length === 0 ? (
            <div className="h-[270px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg">
              No Layer-4 port flow entries recorded yet.
            </div>
          ) : (
            <div className="h-[270px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topPortsData} layout="vertical" margin={{ left: 10, right: 16 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} unit=" KiB" />
                  <YAxis
                    type="category"
                    dataKey="label"
                    width={126}
                    tick={{ fill: '#e2e8f0', fontSize: 11 }}
                  />
                  <Tooltip
                    contentStyle={TOOLTIP_STYLE}
                    formatter={(val: any, _name: any, props: any) => {
                      const p = props?.payload;
                      return [
                        `${formatBytesCompact(p?.bytes ?? Number(val) * 1024)} • ${p?.packets ?? 0} pkts (${p?.flows ?? 0} flows)`,
                        'Volume',
                      ];
                    }}
                  />
                  <Bar dataKey="kib" name="Volume (KiB)" radius={[0, 4, 4, 0]}>
                    {topPortsData.map((entry) => (
                      <Cell key={entry.label} fill={entry.isSynHeavy ? '#f59e0b' : '#38bdf8'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Row 3: XDP Fast-Drop Effectiveness & Live SYN-Flood Meter */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-white">XDP Blocklist Impact by Source / CIDR</h3>
              <p className="text-xs text-slate-400">Packets dropped in NIC DMA before socket allocation</p>
            </div>
            <span className="text-xs font-mono tabular-nums text-rose-300">
              {dp?.blockedIps?.length ?? 0} active rules
            </span>
          </div>

          {blockedBarData.length === 0 ? (
            <div className="h-[200px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg">
              No active IP or CIDR entries in <code className="font-mono mx-1">blocklist_map</code>.
            </div>
          ) : (
            <div className="h-[200px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={blockedBarData} layout="vertical" margin={{ left: 8, right: 16 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <YAxis type="category" dataKey="ip" width={132} tick={{ fill: '#fda4af', fontSize: 11 }} />
                  <Tooltip
                    contentStyle={TOOLTIP_STYLE}
                    formatter={(val: any, _name: any, props: any) => [
                      `${Number(val ?? 0).toLocaleString()} pkts (${formatBytesCompact(props?.payload?.droppedBytes ?? 0)})`,
                      'XDP_DROP',
                    ]}
                  />
                  <Bar dataKey="droppedPackets" name="Dropped Packets" fill="#f43f5e" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-white">Per-Source TCP SYN Rate Meter</h3>
              <p className="text-xs text-slate-400">
                Top talkers inside 1s sliding <code className="font-mono text-amber-300">syn_meter_map</code> windows
              </p>
            </div>
            <span className="text-xs font-mono tabular-nums text-amber-300">
              {synLimit >= 20 ? `Threshold: ${synLimit.toLocaleString()} PPS` : 'Limiter disabled (0 PPS)'}
            </span>
          </div>

          {synMetersData.length === 0 ? (
            <div className="h-[200px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg">
              No active TCP SYN rate-meter entries in current window.
            </div>
          ) : (
            <div className="h-[200px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={synMetersData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="ip" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} width={48} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                  {synLimit >= 20 && (
                    <ReferenceLine
                      y={synLimit}
                      stroke="#f43f5e"
                      strokeDasharray="4 4"
                      label={{ value: 'SYN Cap', fill: '#fda4af', fontSize: 10 }}
                    />
                  )}
                  <Bar dataKey="synCount" name="Observed SYN/s" fill="#f59e0b" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="droppedPackets" name="SYN Drops" fill="#f43f5e" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
