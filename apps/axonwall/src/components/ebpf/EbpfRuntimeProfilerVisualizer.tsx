'use client';

import React, { useMemo, useState } from 'react';
import { Cpu, Flame, Power, Server } from 'lucide-react';
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  formatBytesCompact,
  formatDurationNs,
  type BpfProgramRuntimeDelta,
  type KernelBpfInventory,
  type KernelSoftnetTelemetry,
  type SoftnetCpuDelta,
} from '@/lib/ebpf-telemetry';

interface EbpfRuntimeProfilerVisualizerProps {
  inventory?: KernelBpfInventory;
  softnet?: KernelSoftnetTelemetry;
  programDeltas: BpfProgramRuntimeDelta[];
  runtimeHistory: Array<Record<string, number | string>>;
  topProgramSeries: Array<{ key: string; label: string; color: string }>;
  softnetDeltas: SoftnetCpuDelta[];
  daemonDown: boolean;
  togglingStats: boolean;
  onToggleBpfStats: (enabled: boolean) => void;
}

type FlameMetric = 'cpuUs' | 'totalMs' | 'avgNs' | 'jited';

const TYPE_BG_PALETTE: Record<string, string> = {
  XDP: 'bg-emerald-600/80 hover:bg-emerald-500/85 border-emerald-400/50 text-white',
  LSM: 'bg-rose-600/80 hover:bg-rose-500/85 border-rose-400/50 text-white',
  Tracing: 'bg-sky-600/80 hover:bg-sky-500/85 border-sky-400/50 text-white',
  SchedCLS: 'bg-purple-600/80 hover:bg-purple-500/85 border-purple-400/50 text-white',
  CGroupSKB: 'bg-amber-600/80 hover:bg-amber-500/85 border-amber-400/50 text-white',
  RawTracepoint: 'bg-cyan-600/80 hover:bg-cyan-500/85 border-cyan-400/50 text-white',
};

function frameClassForType(type: string): string {
  return TYPE_BG_PALETTE[type] || 'bg-teal-600/80 hover:bg-teal-500/85 border-teal-400/50 text-white';
}

function metricValue(d: BpfProgramRuntimeDelta, metric: FlameMetric): number {
  switch (metric) {
    case 'cpuUs':
      return d.cpuUsPerSec;
    case 'totalMs':
      return d.totalRunTimeMs;
    case 'avgNs':
      return d.avgNsPerRun;
    case 'jited':
      return Math.round((d.jitedBytes / 1024) * 100) / 100;
  }
}

function formatMetricUnit(val: number, metric: FlameMetric): string {
  switch (metric) {
    case 'cpuUs':
      return `${val.toFixed(1)} µs/s`;
    case 'totalMs':
      return `${val.toFixed(2)} ms`;
    case 'avgNs':
      return formatDurationNs(val);
    case 'jited':
      return `${val.toFixed(1)} KiB`;
  }
}

export function EbpfRuntimeProfilerVisualizer({
  inventory,
  softnet,
  programDeltas,
  runtimeHistory,
  topProgramSeries,
  softnetDeltas,
  daemonDown,
  togglingStats,
  onToggleBpfStats,
}: EbpfRuntimeProfilerVisualizerProps) {
  const [selectedMetric, setSelectedMetric] = useState<FlameMetric | null>(null);
  const [zoomedType, setZoomedType] = useState<string | null>(null);
  const [selectedProgId, setSelectedProgId] = useState<number | null>(null);
  const [softnetMode, setSoftnetMode] = useState<'cumulative' | 'rate'>('cumulative');
  const [selectedCpu, setSelectedCpu] = useState<number | null>(null);

  const statsEnabled = Boolean(inventory?.statsEnabled);
  const hasLiveCpu = programDeltas.some((d) => d.cpuUsPerSec > 0);
  const hasCumulativeTime = programDeltas.some((d) => d.totalRunTimeMs > 0);

  const effectiveMetric: FlameMetric =
    selectedMetric ?? (hasLiveCpu ? 'cpuUs' : hasCumulativeTime ? 'totalMs' : 'jited');

  const totalCpuUsPerSec = useMemo(
    () => programDeltas.reduce((acc, d) => acc + d.cpuUsPerSec, 0),
    [programDeltas]
  );
  const totalCallsPerSec = useMemo(
    () => programDeltas.reduce((acc, d) => acc + d.runsPerSec, 0),
    [programDeltas]
  );
  const totalRecursionMisses = useMemo(
    () => programDeltas.reduce((acc, d) => acc + d.recursionMisses, 0),
    [programDeltas]
  );

  // Scoped programs for Icicle / Flame-Strip
  const scopedDeltas = useMemo(() => {
    const base = zoomedType ? programDeltas.filter((d) => d.type === zoomedType) : programDeltas;
    return base.slice().sort((a, b) => metricValue(b, effectiveMetric) - metricValue(a, effectiveMetric));
  }, [programDeltas, zoomedType, effectiveMetric]);

  const typeSegments = useMemo(() => {
    const agg = new Map<string, number>();
    for (const d of programDeltas) {
      const v = metricValue(d, effectiveMetric);
      if (v <= 0) continue;
      agg.set(d.type, (agg.get(d.type) || 0) + v);
    }
    const entries = Array.from(agg.entries()).sort((a, b) => b[1] - a[1]);
    const total = entries.reduce((acc, [, v]) => acc + v, 0);
    return {
      total,
      items: entries.map(([type, value]) => ({
        type,
        value,
        pct: total > 0 ? (value / total) * 100 : 0,
      })),
    };
  }, [programDeltas, effectiveMetric]);

  const scopedTotalValue = useMemo(
    () => scopedDeltas.reduce((acc, d) => acc + metricValue(d, effectiveMetric), 0),
    [scopedDeltas, effectiveMetric]
  );

  const selectedProgram = useMemo(() => {
    if (selectedProgId != null) {
      const found = programDeltas.find((d) => d.id === selectedProgId);
      if (found) return found;
    }
    return scopedDeltas[0] ?? null;
  }, [selectedProgId, programDeltas, scopedDeltas]);

  // SoftIRQ NAPI heatmap rows (joined cumulative + delta rate)
  const softnetDeltaMap = useMemo(() => {
    const m = new Map<number, SoftnetCpuDelta>();
    for (const d of softnetDeltas) m.set(d.cpu, d);
    return m;
  }, [softnetDeltas]);

  const hasSoftnetRate = softnetDeltas.some((d) => d.processedPerSec > 0 || d.timeSqueezePerSec > 0 || d.droppedPerSec > 0);
  const effectiveSoftnetMode: 'cumulative' | 'rate' =
    softnetMode === 'rate' && hasSoftnetRate ? 'rate' : 'cumulative';

  const maxSoftnetLoad = useMemo(() => {
    if (!softnet?.perCpu?.length) return 1;
    let mx = 1;
    for (const c of softnet.perCpu) {
      const v = effectiveSoftnetMode === 'rate' ? softnetDeltaMap.get(c.cpu)?.processedPerSec || 0 : c.processed;
      if (v > mx) mx = v;
    }
    return mx;
  }, [softnet?.perCpu, softnetDeltaMap, effectiveSoftnetMode]);

  const activeCpuStat = useMemo(() => {
    if (!softnet?.perCpu?.length) return null;
    if (selectedCpu != null) {
      const found = softnet.perCpu.find((c) => c.cpu === selectedCpu);
      if (found) return found;
    }
    return softnet.perCpu[0] ?? null;
  }, [softnet?.perCpu, selectedCpu]);

  return (
    <div className="space-y-6">
      {/* Control Header & Live Execution KPIs */}
      <section className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Flame className="w-5 h-5 text-amber-400" />
              Ring-0 eBPF Execution Profiler &amp; SoftIRQ NAPI Pressure
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Measures real per-program kernel CPU execution budget (<code className="font-mono">bpf_prog_info.run_time_ns</code>) and per-CPU network SoftIRQ saturation from{' '}
              <code className="font-mono">/proc/net/softnet_stat</code>.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <span
              className={`px-2.5 py-1 rounded-md text-xs font-mono border ${
                statsEnabled
                  ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                  : 'bg-slate-950 border-slate-700 text-slate-300'
              }`}
            >
              bpf_stats_enabled: {statsEnabled ? '1 (ACTIVE)' : '0 (DISABLED)'}
            </span>
            <button
              type="button"
              disabled={daemonDown || togglingStats}
              onClick={() => onToggleBpfStats(!statsEnabled)}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition disabled:opacity-50 ${
                statsEnabled
                  ? 'bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-200'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white'
              }`}
            >
              <Power className="w-3.5 h-3.5" />
              {togglingStats
                ? 'Updating sysctl...'
                : statsEnabled
                  ? 'Disable bpf_stats_enabled'
                  : 'Enable bpf_stats_enabled'}
            </button>
          </div>
        </div>

        {/* Summary KPI Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 py-3 px-4 rounded-lg bg-slate-950 border border-slate-800 text-xs tabular-nums">
          <div>
            <div className="text-slate-400">Live Ring-0 BPF CPU</div>
            <div className="text-base font-bold font-mono text-emerald-300 mt-0.5">
              {statsEnabled ? `${totalCpuUsPerSec.toFixed(1)} µs/s` : 'Stats off'}
            </div>
          </div>
          <div>
            <div className="text-slate-400">Live Program Calls/s</div>
            <div className="text-base font-bold font-mono text-sky-300 mt-0.5">
              {statsEnabled ? `${Math.round(totalCallsPerSec).toLocaleString()} /s` : 'Stats off'}
            </div>
          </div>
          <div>
            <div className="text-slate-400">Loaded BPF Programs</div>
            <div className="text-base font-bold font-mono text-white mt-0.5">
              {(inventory?.totalPrograms ?? 0).toLocaleString()}
            </div>
          </div>
          <div>
            <div className="text-slate-400">Recursion Misses</div>
            <div
              className={`text-base font-bold font-mono mt-0.5 ${
                totalRecursionMisses > 0 ? 'text-amber-300' : 'text-slate-200'
              }`}
            >
              {totalRecursionMisses.toLocaleString()}
            </div>
          </div>
        </div>

        {/* Proportional Execution Budget Icicle / Flame-Strip */}
        <div className="space-y-3 pt-2 border-t border-slate-800">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-bold text-white">
                Proportional Ring-0 Execution &amp; Footprint Icicle Strip
              </h3>
              <p className="text-xs text-slate-400">
                Click a program type in Tier 2 to zoom in, or click any program bar in Tier 3 to inspect call rates and latency.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-1 rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs">
              {(
                [
                  { id: 'cpuUs' as const, label: 'Live CPU µs/s' },
                  { id: 'totalMs' as const, label: 'Total ms' },
                  { id: 'avgNs' as const, label: 'Avg ns/run' },
                  { id: 'jited' as const, label: 'JIT KiB' },
                ] as const
              ).map((m) => (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => setSelectedMetric(m.id)}
                  className={`px-2.5 py-1 rounded font-semibold transition ${
                    effectiveMetric === m.id
                      ? 'bg-emerald-600 text-white'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {m.label}
                </button>
              ))}
            </div>
          </div>

          {daemonDown ? (
            <div className="py-8 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
              Daemon offline — kernel eBPF program runtime stats unavailable.
            </div>
          ) : !inventory?.available || programDeltas.length === 0 ? (
            <div className="py-8 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
              {inventory?.error || 'No kernel eBPF programs enumerated via sys_bpf.'}
            </div>
          ) : typeSegments.total === 0 ? (
            <div className="py-8 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 space-y-2">
              <div>
                Selected metric reports <code className="font-mono text-amber-300">0</code> across loaded programs.
              </div>
              {!statsEnabled && (effectiveMetric === 'cpuUs' || effectiveMetric === 'totalMs' || effectiveMetric === 'avgNs') && (
                <div className="text-slate-400">
                  Enable <code className="font-mono text-emerald-300">kernel.bpf_stats_enabled</code> above or switch to{' '}
                  <button
                    type="button"
                    onClick={() => setSelectedMetric('jited')}
                    className="underline text-emerald-300 hover:text-emerald-200"
                  >
                    JIT KiB
                  </button>{' '}
                  to inspect compiled code footprint.
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-1.5 rounded-lg bg-slate-950 border border-slate-800 p-3">
              {/* Tier 1: Root Frame */}
              <button
                type="button"
                onClick={() => setZoomedType(null)}
                className="w-full h-7 px-3 rounded bg-slate-800 hover:bg-slate-700 border border-slate-600 text-left text-xs font-mono text-white flex items-center justify-between tabular-nums transition"
              >
                <span>
                  all kernel bpf programs ({programDeltas.length})
                  {zoomedType ? ` · zoomed into ${zoomedType} (click to reset)` : ''}
                </span>
                <span>{formatMetricUnit(typeSegments.total, effectiveMetric)}</span>
              </button>

              {/* Tier 2: By Program Type */}
              <div className="flex w-full h-8 gap-0.5 overflow-hidden rounded">
                {typeSegments.items.map((seg) => {
                  const pct = Math.max(2, seg.pct);
                  const activeZoom = zoomedType === seg.type;
                  return (
                    <button
                      key={seg.type}
                      type="button"
                      onClick={() => setZoomedType(activeZoom ? null : seg.type)}
                      style={{ width: `${pct}%` }}
                      title={`${seg.type}: ${formatMetricUnit(seg.value, effectiveMetric)} (${seg.pct.toFixed(1)}%)`}
                      className={`h-full px-2 border text-left text-[11px] font-mono truncate transition ${frameClassForType(
                        seg.type
                      )} ${activeZoom ? 'ring-2 ring-white' : ''}`}
                    >
                      {seg.pct >= 8 ? `${seg.type} ${seg.pct.toFixed(0)}%` : seg.type}
                    </button>
                  );
                })}
              </div>

              {/* Tier 3: Individual Programs in Scope */}
              <div className="flex w-full h-9 gap-0.5 overflow-hidden rounded">
                {scopedDeltas
                  .filter((d) => metricValue(d, effectiveMetric) > 0)
                  .slice(0, 20)
                  .map((d) => {
                    const val = metricValue(d, effectiveMetric);
                    const pct = scopedTotalValue > 0 ? Math.max(2, (val / scopedTotalValue) * 100) : 0;
                    const isSelected = selectedProgram?.id === d.id;
                    return (
                      <button
                        key={d.id}
                        type="button"
                        onClick={() => setSelectedProgId(d.id)}
                        style={{ width: `${pct}%` }}
                        title={`${d.name} (#${d.id}): ${formatMetricUnit(val, effectiveMetric)}`}
                        className={`h-full px-2 border text-left text-[11px] font-mono truncate transition ${frameClassForType(
                          d.type
                        )} ${isSelected ? 'ring-2 ring-white' : 'opacity-90'}`}
                      >
                        {pct >= 7 ? `${d.name}` : `#${d.id}`}
                      </button>
                    );
                  })}
              </div>

              {/* Selected Frame Inspector */}
              {selectedProgram && (
                <div className="pt-2.5 mt-1 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs font-mono tabular-nums text-slate-200">
                  <div className="flex flex-wrap items-center gap-3">
                    <span className="font-bold text-emerald-300">
                      {selectedProgram.name} (#{selectedProgram.id})
                    </span>
                    <span className="text-slate-300">{selectedProgram.type}</span>
                    <span>CPU: {selectedProgram.cpuUsPerSec.toFixed(2)} µs/s</span>
                    <span>Rate: {selectedProgram.runsPerSec.toLocaleString()} calls/s</span>
                    <span>Avg: {formatDurationNs(selectedProgram.avgNsPerRun)}</span>
                  </div>
                  <div className="flex flex-wrap items-center gap-3 text-slate-300">
                    <span>Total: {selectedProgram.totalRunTimeMs.toFixed(2)} ms</span>
                    <span>JIT: {formatBytesCompact(selectedProgram.jitedBytes)}</span>
                    <span>Share: {selectedProgram.sharePct.toFixed(1)}%</span>
                    <span>Misses: {selectedProgram.recursionMisses}</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Live Multi-Program CPU Timeline */}
        <div className="space-y-2 pt-3 border-t border-slate-800">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-sky-400" />
              Live Top-Program CPU Budget Timeline (µs/s)
            </h3>
            <span className="text-xs font-mono text-slate-400 tabular-nums">
              {runtimeHistory.length} samples captured
            </span>
          </div>

          {!statsEnabled ? (
            <div className="py-6 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
              Live CPU timeline stands by while <code className="font-mono text-slate-300">bpf_stats_enabled=0</code>. Click{' '}
              <strong className="text-emerald-300">Enable bpf_stats_enabled</strong> above to stream live kernel execution curves.
            </div>
          ) : runtimeHistory.length < 2 || topProgramSeries.length === 0 ? (
            <div className="py-6 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
              Collecting baseline <code className="font-mono">run_time_ns</code> samples (~8s between polls) to render live CPU curves...
            </div>
          ) : (
            <div className="h-[220px] rounded-lg bg-slate-950 border border-slate-800 p-2">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={runtimeHistory}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="time" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} unit=" µs" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '0.5rem',
                      fontSize: '12px',
                      color: '#f1f5f9',
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                  {topProgramSeries.map((series) => (
                    <Line
                      key={series.key}
                      type="monotone"
                      dataKey={series.key}
                      name={series.label}
                      stroke={series.color}
                      strokeWidth={2}
                      dot={false}
                      isAnimationActive={false}
                    />
                  ))}
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </section>

      {/* Per-CPU SoftIRQ / NAPI Pressure Heatmap (/proc/net/softnet_stat) */}
      <section className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-sky-400" />
              Per-CPU <code className="font-mono text-xs text-sky-300">NET_RX_SOFTIRQ</code> &amp; NAPI Ring Pressure Heatmap
            </h3>
            <p className="text-xs text-slate-400">
              Real per-core NAPI budget exhaustion (<code className="font-mono">time_squeeze</code>), ring overflows (<code className="font-mono">dropped</code>), and RPS IPI counters from{' '}
              <code className="font-mono">/proc/net/softnet_stat</code>.
            </p>
          </div>

          <div className="flex items-center gap-1 rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs">
            <button
              type="button"
              onClick={() => setSoftnetMode('cumulative')}
              className={`px-2.5 py-1 rounded font-semibold transition ${
                effectiveSoftnetMode === 'cumulative' ? 'bg-sky-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              Cumulative
            </button>
            <button
              type="button"
              onClick={() => setSoftnetMode('rate')}
              disabled={!hasSoftnetRate}
              className={`px-2.5 py-1 rounded font-semibold transition disabled:opacity-40 ${
                effectiveSoftnetMode === 'rate' ? 'bg-sky-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              Live Rate (/s)
            </button>
          </div>
        </div>

        {daemonDown ? (
          <div className="py-8 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
            Daemon offline — <code className="font-mono">/proc/net/softnet_stat</code> telemetry unavailable.
          </div>
        ) : !softnet?.available || softnet.perCpu.length === 0 ? (
          <div className="py-8 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
            No <code className="font-mono">/proc/net/softnet_stat</code> counters reported by the daemon.
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 lg:grid-cols-8 gap-2">
              {softnet.perCpu.map((cpu) => {
                const delta = softnetDeltaMap.get(cpu.cpu);
                const droppedVal = effectiveSoftnetMode === 'rate' ? delta?.droppedPerSec ?? 0 : cpu.dropped;
                const squeezeVal = effectiveSoftnetMode === 'rate' ? delta?.timeSqueezePerSec ?? 0 : cpu.timeSqueeze;
                const collisionVal =
                  effectiveSoftnetMode === 'rate' ? delta?.cpuCollisionPerSec ?? 0 : cpu.cpuCollision;
                const processedVal =
                  effectiveSoftnetMode === 'rate' ? delta?.processedPerSec ?? 0 : cpu.processed;

                const isCritical = droppedVal > 0 || collisionVal > 0;
                const isSqueezed = !isCritical && squeezeVal > 0;
                const ratio = maxSoftnetLoad > 0 ? processedVal / maxSoftnetLoad : 0;
                const isSelected = activeCpuStat?.cpu === cpu.cpu;

                const toneClass = isCritical
                  ? 'bg-rose-950/60 border-rose-500/60 text-rose-100'
                  : isSqueezed
                    ? 'bg-amber-950/50 border-amber-500/60 text-amber-100'
                    : ratio >= 0.65
                      ? 'bg-emerald-950/65 border-emerald-500/50 text-emerald-100'
                      : ratio >= 0.25
                        ? 'bg-emerald-950/35 border-emerald-500/30 text-slate-100'
                        : 'bg-slate-950 border-slate-800 text-slate-200';

                return (
                  <button
                    key={cpu.cpu}
                    type="button"
                    onClick={() => setSelectedCpu(cpu.cpu)}
                    className={`p-2.5 rounded-lg border text-left transition tabular-nums ${toneClass} ${
                      isSelected ? 'ring-2 ring-white' : 'hover:border-slate-500'
                    }`}
                  >
                    <div className="flex items-center justify-between text-[11px] font-mono font-bold">
                      <span>CPU {cpu.cpu}</span>
                      {isCritical ? (
                        <span className="text-rose-300">DROP</span>
                      ) : isSqueezed ? (
                        <span className="text-amber-300">SQZ</span>
                      ) : (
                        <span className="text-emerald-400">OK</span>
                      )}
                    </div>
                    <div className="text-xs font-mono mt-1 truncate">
                      {effectiveSoftnetMode === 'rate'
                        ? `${Math.round(processedVal).toLocaleString()}/s`
                        : processedVal.toLocaleString()}
                    </div>
                    <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">
                      sqz:{Math.round(squeezeVal)} · drp:{Math.round(droppedVal)}
                    </div>
                  </button>
                );
              })}
            </div>

            {activeCpuStat && (
              <div className="pt-3 border-t border-slate-800 space-y-2 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2 font-mono tabular-nums text-slate-200">
                  <span className="font-bold text-sky-300">
                    CPU {activeCpuStat.cpu} SoftIRQ Detail
                  </span>
                  <div className="flex flex-wrap items-center gap-4">
                    <span>Processed: {activeCpuStat.processed.toLocaleString()}</span>
                    <span className={activeCpuStat.dropped > 0 ? 'text-rose-300 font-bold' : ''}>
                      Dropped: {activeCpuStat.dropped.toLocaleString()}
                    </span>
                    <span className={activeCpuStat.timeSqueeze > 0 ? 'text-amber-300 font-bold' : ''}>
                      time_squeeze: {activeCpuStat.timeSqueeze.toLocaleString()}
                    </span>
                    <span>cpu_collision: {activeCpuStat.cpuCollision.toLocaleString()}</span>
                    <span>received_rps: {activeCpuStat.receivedRps.toLocaleString()}</span>
                    <span>flow_limit_count: {activeCpuStat.flowLimitCount.toLocaleString()}</span>
                  </div>
                </div>
                {(activeCpuStat.dropped > 0 || activeCpuStat.timeSqueeze > 0) && (
                  <p className="text-slate-300">
                    Non-zero <code className="font-mono text-amber-300">time_squeeze</code> or{' '}
                    <code className="font-mono text-rose-300">dropped</code> indicates NAPI ran out of per-IRQ budget before draining the RX ring. Consider raising{' '}
                    <code className="font-mono text-slate-100">net.core.netdev_budget</code> /{' '}
                    <code className="font-mono text-slate-100">net.core.netdev_max_backlog</code> or balancing RSS queues across CPUs.
                  </p>
                )}
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
