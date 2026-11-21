'use client';

import React, { useMemo, useState } from 'react';
import {
  Activity,
  CheckCircle2,
  KeyRound,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  buildSketchWaveformData,
  FORBIDDEN_RING0_PROG_TYPES,
  SAFE_DELEGATABLE_PROG_TYPES,
  type EbpfOverviewTelemetry,
} from '@/lib/ebpf-telemetry';

const TOOLTIP_STYLE = {
  backgroundColor: '#0f172a',
  borderColor: '#334155',
  borderRadius: '0.5rem',
  fontSize: '12px',
  color: '#f1f5f9',
};

interface EbpfLsmAndTokenVisualizerProps {
  overview: EbpfOverviewTelemetry | null;
  selectedPreset?: string;
}

export function EbpfLsmAndTokenVisualizer({
  overview,
  selectedPreset = 'network-dataplane',
}: EbpfLsmAndTokenVisualizerProps) {
  const recentEvents = overview?.bpfLsm?.recentEvents || [];
  const allowlist = overview?.bpfLsm?.allowlist || [];
  const presets = overview?.bpfTokens?.presets || {};

  const hookChartData = useMemo(() => {
    const counts = new Map<string, { hook: string; blocked: number; audited: number }>();
    for (const ev of recentEvents) {
      const shortHook = ev.hook.split(' ')[0] || ev.hook || 'lsm/unknown';
      const entry = counts.get(shortHook) || { hook: shortHook, blocked: 0, audited: 0 };
      if (ev.blocked) entry.blocked += 1;
      else entry.audited += 1;
      counts.set(shortHook, entry);
    }
    return Array.from(counts.values());
  }, [recentEvents]);

  const activePresetInfo = useMemo(() => {
    if (presets[selectedPreset]) return presets[selectedPreset];
    if (selectedPreset === 'networking-safe' || selectedPreset === 'firewall-xdp-tc') {
      return presets['network-dataplane'] || presets[selectedPreset];
    }
    if (selectedPreset === 'cgroup-observability') {
      return presets['cgroup-microsegmentation'] || presets[selectedPreset];
    }
    return presets['network-dataplane'] || Object.values(presets)[0];
  }, [presets, selectedPreset]);

  const delegatedProgSet = useMemo(() => {
    const raw = activePresetInfo?.delegateProgs || '';
    return new Set(
      raw
        .split(':')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
    );
  }, [activePresetInfo]);

  const forbiddenList = overview?.bpfTokens?.forbiddenRing0ProgTypes?.length
    ? overview.bpfTokens.forbiddenRing0ProgTypes
    : FORBIDDEN_RING0_PROG_TYPES;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
      {/* Left: BPF-LSM Enforcement Activity & Event Timeline */}
      <div className="lg:col-span-6 p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-purple-400" />
              BPF-LSM Ring-0 Hook Activity &amp; Denials
            </h3>
            <p className="text-xs text-slate-400">
              Lockless <code className="font-mono text-purple-300">BPF_MAP_TYPE_RINGBUF</code> MAC enforcement +{' '}
              {allowlist.length} verified <code className="font-mono">(s_dev, i_ino)</code> binaries
            </p>
          </div>
          <span className="text-xs font-mono tabular-nums text-purple-300">
            {overview?.bpfLsm.attachedHooks?.length ?? 0} hooks
          </span>
        </div>

        {hookChartData.length > 0 && (
          <div className="h-[170px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={hookChartData} layout="vertical" margin={{ left: 6, right: 14 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" allowDecimals={false} tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis type="category" dataKey="hook" width={120} tick={{ fill: '#cbd5e1', fontSize: 11 }} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
                <Bar dataKey="blocked" name="Blocked (-EPERM)" stackId="h" fill="#f43f5e" />
                <Bar dataKey="audited" name="Token Audit (Allowed)" stackId="h" fill="#10b981" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        <div className="space-y-2 border-t border-slate-800 pt-3">
          <div className="text-xs font-semibold text-slate-300">
            Recent Ring-0 LSM Events ({recentEvents.length})
          </div>
          {recentEvents.length === 0 ? (
            <div className="py-6 text-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg">
              {overview?.daemonDown
                ? 'Daemon offline — BPF-LSM event ring is unreachable.'
                : 'No BPF-LSM denial or token audit events emitted since daemon startup.'}
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80 max-h-52 overflow-y-auto text-xs font-mono tabular-nums">
              {recentEvents.slice(0, 20).map((ev, idx) => (
                <div key={`${ev.timestamp}-${ev.pid}-${idx}`} className="py-2 flex items-start justify-between gap-2">
                  <div className="space-y-0.5 min-w-0">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                          ev.blocked
                            ? 'bg-rose-500/20 text-rose-200 border border-rose-500/40'
                            : 'bg-emerald-500/15 text-emerald-200 border border-emerald-500/30'
                        }`}
                      >
                        {ev.blocked ? '-EPERM' : 'ALLOWED'}
                      </span>
                      <span className="text-white font-semibold">{ev.comm || 'unknown'}</span>
                      <span className="text-slate-400">pid {ev.pid}</span>
                      {ev.mitreTechnique && (
                        <span className="text-amber-300">{ev.mitreTechnique}</span>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-300 truncate">{ev.detail || ev.hook}</div>
                  </div>
                  <div className="text-[10px] text-slate-400 shrink-0 text-right">
                    <div>dev {ev.dev}</div>
                    <div>ino {ev.ino}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Right: BPF_TOKEN Least-Privilege Capability Matrix */}
      <div className="lg:col-span-6 p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-sky-400" />
              <code className="font-mono text-sky-300">BPF_TOKEN</code> Boundary Matrix ({selectedPreset})
            </h3>
            <p className="text-xs text-slate-400">
              Visual verification of Linux 6.9+ delegated safe net progs vs Ring-0 vetoed programs
            </p>
          </div>
          <span className="text-xs font-mono tabular-nums text-sky-300">
            {overview?.bpfTokens.activeProfiles?.length ?? 0} mounted tokens
          </span>
        </div>

        <div className="space-y-3">
          <div>
            <div className="text-xs font-semibold text-emerald-300 mb-2 flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" />
              Safe Networking Delegation Surface (Tenant UserNS)
            </div>
            <div className="flex flex-wrap gap-1.5">
              {SAFE_DELEGATABLE_PROG_TYPES.map((prog) => {
                const granted = delegatedProgSet.has(prog);
                return (
                  <span
                    key={prog}
                    className={`inline-flex items-center gap-1 px-2 py-1 rounded text-[11px] font-mono border ${
                      granted
                        ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-200'
                        : 'bg-slate-950 border-slate-800 text-slate-400'
                    }`}
                  >
                    {granted && <CheckCircle2 className="w-3 h-3 text-emerald-400" />}
                    {prog}
                  </span>
                );
              })}
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800">
            <div className="text-xs font-semibold text-rose-300 mb-2 flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5" />
              Unconditionally Vetoed by <code className="font-mono">lsm/bpf_token_*</code> (No Host RAM Read)
            </div>
            <div className="flex flex-wrap gap-1.5">
              {forbiddenList.map((prog) => (
                <span
                  key={prog}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded text-[11px] font-mono bg-rose-950/50 border border-rose-500/35 text-rose-200"
                >
                  {prog}
                </span>
              ))}
            </div>
          </div>

          {activePresetInfo && (
            <div className="pt-3 border-t border-slate-800 grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono">
              <div className="text-slate-300 break-words">
                <span className="text-sky-300 font-semibold">delegate_cmds: </span>
                {activePresetInfo.delegateCmds}
              </div>
              <div className="text-slate-300 break-words">
                <span className="text-purple-300 font-semibold">delegate_maps: </span>
                {activePresetInfo.delegateMaps}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

interface ThreatSketchWaveformProps {
  pktSizes?: number[];
  iatUs?: number[];
}

export function ThreatSketchWaveform({ pktSizes = [], iatUs = [] }: ThreatSketchWaveformProps) {
  const [showRaw, setShowRaw] = useState(false);
  const waveform = useMemo(() => buildSketchWaveformData(pktSizes, iatUs), [pktSizes, iatUs]);

  if (waveform.length === 0) {
    return (
      <div className="p-3 rounded-lg bg-slate-950 border border-dashed border-slate-800 text-xs text-slate-400">
        No eBPF TC packet-length sketch vector captured on this episode.
      </div>
    );
  }

  return (
    <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-xs font-bold text-white flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            eBPF TC Bidirectional Flow Sketch &amp; Inter-Arrival Jitter
          </div>
          <div className="text-[11px] text-slate-400">
            Positive bars (+B) = egress wire size; Negative bars (-B) = ingress wire size
          </div>
        </div>
        <button
          type="button"
          onClick={() => setShowRaw((s) => !s)}
          className="px-2 py-1 rounded bg-slate-900 border border-slate-700 text-[11px] font-mono text-slate-300 hover:text-white"
        >
          {showRaw ? 'Hide Vectors' : 'Raw Arrays'}
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="h-[155px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={waveform}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis dataKey="label" tick={{ fill: '#94a3b8', fontSize: 10 }} />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 10 }} width={48} unit=" B" />
              <ReferenceLine y={0} stroke="#475569" />
              <Tooltip
                contentStyle={TOOLTIP_STYLE}
                formatter={(val: any) => {
                  const n = Number(val ?? 0);
                  return [`${Math.abs(n)} B (${n < 0 ? 'ingress' : 'egress'})`, 'Packet Size'];
                }}
              />
              <Bar dataKey="signedBytes" name="Signed Size (B)" radius={[2, 2, 2, 2]}>
                {waveform.map((pt) => (
                  <Cell key={pt.idx} fill={pt.signedBytes < 0 ? '#f43f5e' : '#38bdf8'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="h-[155px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={waveform}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis dataKey="label" tick={{ fill: '#94a3b8', fontSize: 10 }} />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 10 }} width={52} unit=" ms" />
              <Tooltip
                contentStyle={TOOLTIP_STYLE}
                formatter={(val: any, _name: any, props: any) => [
                  `${val} ms (${props?.payload?.iatUs ?? 0} us)`,
                  'Inter-Arrival',
                ]}
              />
              <Area
                type="monotone"
                dataKey="iatMs"
                name="IAT (ms)"
                stroke="#f59e0b"
                fill="#f59e0b"
                fillOpacity={0.2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {showRaw && (
        <div className="pt-2 border-t border-slate-800 space-y-1 font-mono text-[11px]">
          <div className="text-cyan-300 break-all">sizes: [{pktSizes.join(', ')}]</div>
          <div className="text-slate-400 break-all">iat_us: [{iatUs.join(', ')}]</div>
        </div>
      )}
    </div>
  );
}
