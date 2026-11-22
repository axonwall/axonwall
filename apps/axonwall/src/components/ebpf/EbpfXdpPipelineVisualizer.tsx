'use client';

import React, { useMemo, useState } from 'react';
import { Activity, ShieldAlert } from 'lucide-react';
import {
  buildXdpPipelineModel,
  formatBytesCompact,
  formatPps,
  type DataplaneRateSample,
  type EbpfOverviewTelemetry,
} from '@/lib/ebpf-telemetry';

interface EbpfXdpPipelineVisualizerProps {
  overview: EbpfOverviewTelemetry | null;
  latestRateSample: DataplaneRateSample | null;
  synLimitPps: number;
}

type StageId =
  | 'rx'
  | 'vlan'
  | 'untagged'
  | 'ipv4'
  | 'ipv6'
  | 'otherL3'
  | 'pass'
  | 'blocklist'
  | 'lpm'
  | 'synflood';

interface StageMeta {
  id: StageId;
  title: string;
  maps: string[];
  description: string;
  accentClass: string;
}

const STAGE_METADATA: Record<StageId, StageMeta> = {
  rx: {
    id: 'rx',
    title: 'NIC DMA Ring Ingress',
    maps: ['xdp_stats_map (PERCPU_ARRAY)'],
    description: 'Raw frames intercepted directly in the NIC driver RX ring before sk_buff allocation.',
    accentClass: 'text-emerald-300',
  },
  vlan: {
    id: 'vlan',
    title: '802.1Q / QinQ VLAN Peeler',
    maps: ['xdp_stats_map', 'flow_map', 'flow6_map'],
    description: 'Hardware or stacked 0x8100 / 0x88a8 VLAN headers decoded in-kernel prior to L3 parsing.',
    accentClass: 'text-sky-300',
  },
  untagged: {
    id: 'untagged',
    title: 'Untagged Ethernet Frames',
    maps: ['xdp_stats_map'],
    description: 'Frames with no 802.1Q/802.1ad tag dispatched straight to EtherType L3 classification.',
    accentClass: 'text-slate-200',
  },
  ipv4: {
    id: 'ipv4',
    title: 'IPv4 Parser & Flow Hash',
    maps: ['flow_map (LRU_PERCPU_HASH)'],
    description: 'IPv4 L3/L4 5-tuple parsed and accounted in per-CPU LRU flow telemetry maps.',
    accentClass: 'text-emerald-300',
  },
  ipv6: {
    id: 'ipv6',
    title: 'IPv6 Dual-Stack Parser',
    maps: ['flow6_map (LRU_PERCPU_HASH)'],
    description: 'IPv6 L3/L4 headers parsed cleanly without NAT/conntrack lookup overhead.',
    accentClass: 'text-purple-300',
  },
  otherL3: {
    id: 'otherL3',
    title: 'Non-IP EtherTypes (ARP / L2)',
    maps: ['xdp_stats_map'],
    description: 'Non-IPv4/IPv6 control frames such as ARP, LLDP, or EAPOL forwarded to host stack.',
    accentClass: 'text-slate-300',
  },
  pass: {
    id: 'pass',
    title: 'XDP_PASS -> Linux Stack / Netfilter',
    maps: ['flow_map', 'flow6_map'],
    description: 'Permitted traffic handed up to tc/nftables stateful inspection and sockets.',
    accentClass: 'text-emerald-300',
  },
  blocklist: {
    id: 'blocklist',
    title: 'Exact Host Fast-Drop (XDP_DROP)',
    maps: ['blocklist_map', 'blocklist_v6_map'],
    description: 'Per-IP dynamic blocklist entries with monotonic kernel TTL expiry dropped before sk_buff.',
    accentClass: 'text-rose-300',
  },
  lpm: {
    id: 'lpm',
    title: 'LPM Trie CIDR Fast-Drop (XDP_DROP)',
    maps: ['lpm_v4_map', 'lpm_v6_map (LPM_TRIE)'],
    description: 'Longest-prefix-match subnet rules enforced at NIC DMA speed with zero iptables traversal.',
    accentClass: 'text-orange-300',
  },
  synflood: {
    id: 'synflood',
    title: 'Per-Source SYN-Flood Shield (XDP_DROP)',
    maps: ['syn_rate_map (LRU_HASH)'],
    description: 'Per-1-second sliding SYN counter exceeding configured PPS threshold dropped at Ring-0.',
    accentClass: 'text-amber-300',
  },
};

function formatStageValue(val: number, mode: 'cumulative' | 'delta'): string {
  if (mode === 'delta') return formatPps(val);
  return `${Math.round(val).toLocaleString()} pkts`;
}

function pctLabel(part: number, total: number): string {
  if (total <= 0) return '0.0%';
  return `${((part / total) * 100).toFixed(1)}%`;
}

function ribbonThickness(part: number, total: number, maxStroke = 28): number {
  if (total <= 0 || part <= 0) return 2;
  return Math.max(3, Math.min(maxStroke, (part / total) * maxStroke));
}

function bezierPath(x1: number, y1: number, x2: number, y2: number): string {
  const cx = (x1 + x2) / 2;
  return `M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`;
}

export function EbpfXdpPipelineVisualizer({
  overview,
  latestRateSample,
  synLimitPps,
}: EbpfXdpPipelineVisualizerProps) {
  const [mode, setMode] = useState<'cumulative' | 'delta'>('cumulative');
  const [selectedStage, setSelectedStage] = useState<StageId>('rx');

  const daemonDown = Boolean(overview?.daemonDown);
  const dp = overview?.dataplane;
  const stats = dp?.xdpStats;
  const attachedIfaces = dp?.attachedInterfaces || [];
  const hasDelta = Boolean(latestRateSample && (latestRateSample.rxPps > 0 || latestRateSample.time));

  const effectiveMode: 'cumulative' | 'delta' =
    mode === 'delta' && latestRateSample ? 'delta' : 'cumulative';

  const model = useMemo(
    () => buildXdpPipelineModel(stats, latestRateSample, effectiveMode),
    [stats, latestRateSample, effectiveMode]
  );

  const stageValueMap: Record<StageId, number> = {
    rx: model.rxTotal,
    vlan: model.vlanTagged,
    untagged: model.untagged,
    ipv4: model.ipv4,
    ipv6: model.ipv6,
    otherL3: model.otherL3,
    pass: model.xdpPass,
    blocklist: model.hostBlocklistDrop,
    lpm: model.lpmCidrDrop,
    synflood: model.synFloodDrop,
  };

  const activeMeta = STAGE_METADATA[selectedStage];
  const activeValue = stageValueMap[selectedStage] ?? 0;

  const totalForPct = model.rxTotal > 0 ? model.rxTotal : 0;

  return (
    <section className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-400" />
            Ring-0 XDP Packet Pipeline &amp; Verdict Flow
          </h3>
          <p className="text-xs text-slate-400">
            Proportional flow across NIC DMA RX, 802.1Q VLAN peeling, IPv4/IPv6 parsing, and fast-drop verdicts. Click any stage to inspect kernel maps.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {attachedIfaces.length > 0 && (
            <span className="px-2.5 py-1 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono">
              XDP NICs: {attachedIfaces.join(', ')}
            </span>
          )}
          <div className="flex items-center gap-1 rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs">
            <button
              type="button"
              onClick={() => setMode('cumulative')}
              className={`px-2.5 py-1 rounded font-semibold transition ${
                effectiveMode === 'cumulative' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              Cumulative
            </button>
            <button
              type="button"
              onClick={() => setMode('delta')}
              disabled={!hasDelta}
              title={!hasDelta ? 'Wait for 2 polling ticks (~8s) to measure live PPS delta' : undefined}
              className={`px-2.5 py-1 rounded font-semibold transition disabled:opacity-40 ${
                effectiveMode === 'delta' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              Live PPS
            </button>
          </div>
        </div>
      </div>

      {daemonDown ? (
        <div className="py-10 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
          Daemon offline — live XDP pipeline counters unavailable.
        </div>
      ) : model.rxTotal === 0 && (stats?.rxPackets ?? 0) === 0 ? (
        <div className="py-10 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
          {attachedIfaces.length > 0
            ? `XDP program attached on ${attachedIfaces.join(', ')} — awaiting ingress packets.`
            : 'XDP dataplane not attached on host interfaces — zero packets intercepted.'}
        </div>
      ) : (
        <div className="space-y-3">
          <div className="overflow-x-auto rounded-lg bg-slate-950 border border-slate-800 p-2">
            <svg
              viewBox="0 0 980 300"
              role="img"
              aria-label="Interactive XDP Ring-0 packet pipeline flow diagram"
              className="w-full min-w-[760px] h-auto select-none"
            >
              {/* Column headers */}
              <text x={24} y={20} fill="#94a3b8" fontSize={10} fontWeight={700}>
                1. DMA INGRESS
              </text>
              <text x={246} y={20} fill="#94a3b8" fontSize={10} fontWeight={700}>
                2. L2 VLAN PEELER
              </text>
              <text x={508} y={20} fill="#94a3b8" fontSize={10} fontWeight={700}>
                3. DUAL-STACK L3 PARSER
              </text>
              <text x={772} y={20} fill="#94a3b8" fontSize={10} fontWeight={700}>
                4. XDP VERDICT
              </text>

              {/* Connecting Stage Rails so cross-stage transitions never fabricate unmeasured pairs */}
              <rect x={442} y={54} width={6} height={206} rx={3} fill="#1e293b" />
              <rect x={706} y={54} width={6} height={206} rx={3} fill="#1e293b" />

              {/* Stage 1 -> Stage 2 Ribbons */}
              <path
                d={bezierPath(188, 128, 246, 92)}
                fill="none"
                stroke={model.vlanTagged > 0 ? '#38bdf8' : '#334155'}
                strokeWidth={ribbonThickness(model.vlanTagged, model.rxTotal)}
                strokeOpacity={model.vlanTagged > 0 ? 0.55 : 0.35}
                strokeDasharray={model.vlanTagged > 0 ? undefined : '4 4'}
              />
              <path
                d={bezierPath(188, 168, 246, 196)}
                fill="none"
                stroke={model.untagged > 0 ? '#64748b' : '#334155'}
                strokeWidth={ribbonThickness(model.untagged, model.rxTotal)}
                strokeOpacity={model.untagged > 0 ? 0.5 : 0.3}
                strokeDasharray={model.untagged > 0 ? undefined : '4 4'}
              />

              {/* Stage 2 -> Rail 1 */}
              <path
                d={bezierPath(414, 92, 442, 118)}
                fill="none"
                stroke={model.vlanTagged > 0 ? '#38bdf8' : '#334155'}
                strokeWidth={ribbonThickness(model.vlanTagged, model.rxTotal)}
                strokeOpacity={0.45}
                strokeDasharray={model.vlanTagged > 0 ? undefined : '4 4'}
              />
              <path
                d={bezierPath(414, 196, 442, 178)}
                fill="none"
                stroke={model.untagged > 0 ? '#64748b' : '#334155'}
                strokeWidth={ribbonThickness(model.untagged, model.rxTotal)}
                strokeOpacity={0.45}
                strokeDasharray={model.untagged > 0 ? undefined : '4 4'}
              />

              {/* Rail 1 -> Stage 3 */}
              <path
                d={bezierPath(448, 118, 508, 92)}
                fill="none"
                stroke={model.ipv4 > 0 ? '#10b981' : '#334155'}
                strokeWidth={ribbonThickness(model.ipv4, model.rxTotal)}
                strokeOpacity={model.ipv4 > 0 ? 0.55 : 0.3}
                strokeDasharray={model.ipv4 > 0 ? undefined : '4 4'}
              />
              <path
                d={bezierPath(448, 174, 508, 178)}
                fill="none"
                stroke={model.ipv6 > 0 ? '#a855f7' : '#334155'}
                strokeWidth={ribbonThickness(model.ipv6, model.rxTotal)}
                strokeOpacity={model.ipv6 > 0 ? 0.55 : 0.3}
                strokeDasharray={model.ipv6 > 0 ? undefined : '4 4'}
              />
              <path
                d={bezierPath(448, 224, 508, 250)}
                fill="none"
                stroke={model.otherL3 > 0 ? '#94a3b8' : '#1e293b'}
                strokeWidth={ribbonThickness(model.otherL3, model.rxTotal, 18)}
                strokeOpacity={model.otherL3 > 0 ? 0.45 : 0.2}
                strokeDasharray={model.otherL3 > 0 ? undefined : '4 4'}
              />

              {/* Stage 3 -> Rail 2 */}
              <path
                d={bezierPath(676, 92, 706, 118)}
                fill="none"
                stroke={model.ipv4 > 0 ? '#10b981' : '#334155'}
                strokeWidth={ribbonThickness(model.ipv4, model.rxTotal)}
                strokeOpacity={0.45}
                strokeDasharray={model.ipv4 > 0 ? undefined : '4 4'}
              />
              <path
                d={bezierPath(676, 178, 706, 174)}
                fill="none"
                stroke={model.ipv6 > 0 ? '#a855f7' : '#334155'}
                strokeWidth={ribbonThickness(model.ipv6, model.rxTotal)}
                strokeOpacity={0.45}
                strokeDasharray={model.ipv6 > 0 ? undefined : '4 4'}
              />
              {model.otherL3 > 0 && (
                <path
                  d={bezierPath(676, 250, 706, 224)}
                  fill="none"
                  stroke="#94a3b8"
                  strokeWidth={ribbonThickness(model.otherL3, model.rxTotal, 18)}
                  strokeOpacity={0.35}
                />
              )}

              {/* Rail 2 -> Stage 4 Verdicts */}
              <path
                d={bezierPath(712, 108, 772, 76)}
                fill="none"
                stroke={model.xdpPass > 0 ? '#10b981' : '#334155'}
                strokeWidth={ribbonThickness(model.xdpPass, model.rxTotal)}
                strokeOpacity={model.xdpPass > 0 ? 0.6 : 0.3}
                strokeDasharray={model.xdpPass > 0 ? undefined : '4 4'}
              />
              <path
                d={bezierPath(712, 160, 772, 146)}
                fill="none"
                stroke={model.hostBlocklistDrop > 0 ? '#f43f5e' : '#334155'}
                strokeWidth={ribbonThickness(model.hostBlocklistDrop, model.rxTotal, 22)}
                strokeOpacity={model.hostBlocklistDrop > 0 ? 0.7 : 0.25}
                strokeDasharray={model.hostBlocklistDrop > 0 ? undefined : '4 4'}
              />
              <path
                d={bezierPath(712, 198, 772, 206)}
                fill="none"
                stroke={model.lpmCidrDrop > 0 ? '#fb923c' : '#334155'}
                strokeWidth={ribbonThickness(model.lpmCidrDrop, model.rxTotal, 22)}
                strokeOpacity={model.lpmCidrDrop > 0 ? 0.7 : 0.25}
                strokeDasharray={model.lpmCidrDrop > 0 ? undefined : '4 4'}
              />
              <path
                d={bezierPath(712, 232, 772, 266)}
                fill="none"
                stroke={model.synFloodDrop > 0 ? '#f59e0b' : '#334155'}
                strokeWidth={ribbonThickness(model.synFloodDrop, model.rxTotal, 22)}
                strokeOpacity={model.synFloodDrop > 0 ? 0.7 : 0.25}
                strokeDasharray={model.synFloodDrop > 0 ? undefined : '4 4'}
              />

              {/* Interactive Nodes */}
              {(
                [
                  {
                    id: 'rx' as const,
                    x: 24,
                    y: 74,
                    w: 164,
                    h: 152,
                    title: 'NIC DMA RX',
                    sub: formatStageValue(model.rxTotal, effectiveMode),
                    foot:
                      effectiveMode === 'delta'
                        ? `${latestRateSample?.rxMbps ?? 0} Mbps`
                        : `${formatBytesCompact(model.rxBytes)} total`,
                    stroke: '#10b981',
                    fill: '#022c22',
                  },
                  {
                    id: 'vlan' as const,
                    x: 246,
                    y: 52,
                    w: 168,
                    h: 80,
                    title: '802.1Q / QinQ',
                    sub: formatStageValue(model.vlanTagged, effectiveMode),
                    foot: pctLabel(model.vlanTagged, totalForPct),
                    stroke: '#38bdf8',
                    fill: '#082f49',
                  },
                  {
                    id: 'untagged' as const,
                    x: 246,
                    y: 156,
                    w: 168,
                    h: 80,
                    title: 'Untagged L2',
                    sub: formatStageValue(model.untagged, effectiveMode),
                    foot: pctLabel(model.untagged, totalForPct),
                    stroke: '#64748b',
                    fill: '#0f172a',
                  },
                  {
                    id: 'ipv4' as const,
                    x: 508,
                    y: 50,
                    w: 168,
                    h: 80,
                    title: 'IPv4 L3/L4',
                    sub: formatStageValue(model.ipv4, effectiveMode),
                    foot: pctLabel(model.ipv4, totalForPct),
                    stroke: '#10b981',
                    fill: '#064e3b',
                  },
                  {
                    id: 'ipv6' as const,
                    x: 508,
                    y: 140,
                    w: 168,
                    h: 76,
                    title: 'IPv6 L3/L4',
                    sub: formatStageValue(model.ipv6, effectiveMode),
                    foot: pctLabel(model.ipv6, totalForPct),
                    stroke: '#a855f7',
                    fill: '#3b0764',
                  },
                  {
                    id: 'otherL3' as const,
                    x: 508,
                    y: 226,
                    w: 168,
                    h: 48,
                    title: 'Other EtherType',
                    sub: formatStageValue(model.otherL3, effectiveMode),
                    foot: pctLabel(model.otherL3, totalForPct),
                    stroke: '#475569',
                    fill: '#0f172a',
                  },
                  {
                    id: 'pass' as const,
                    x: 772,
                    y: 44,
                    w: 184,
                    h: 64,
                    title: 'XDP_PASS -> Netfilter',
                    sub: formatStageValue(model.xdpPass, effectiveMode),
                    foot: pctLabel(model.xdpPass, totalForPct),
                    stroke: '#10b981',
                    fill: '#022c22',
                  },
                  {
                    id: 'blocklist' as const,
                    x: 772,
                    y: 118,
                    w: 184,
                    h: 54,
                    title: 'Host Blocklist Drop',
                    sub: formatStageValue(model.hostBlocklistDrop, effectiveMode),
                    foot: pctLabel(model.hostBlocklistDrop, totalForPct),
                    stroke: '#f43f5e',
                    fill: model.hostBlocklistDrop > 0 ? '#4c0519' : '#0f172a',
                  },
                  {
                    id: 'lpm' as const,
                    x: 772,
                    y: 180,
                    w: 184,
                    h: 54,
                    title: 'LPM CIDR Drop',
                    sub: formatStageValue(model.lpmCidrDrop, effectiveMode),
                    foot: pctLabel(model.lpmCidrDrop, totalForPct),
                    stroke: '#fb923c',
                    fill: model.lpmCidrDrop > 0 ? '#431407' : '#0f172a',
                  },
                  {
                    id: 'synflood' as const,
                    x: 772,
                    y: 242,
                    w: 184,
                    h: 50,
                    title: 'SYN-Flood Drop',
                    sub: formatStageValue(model.synFloodDrop, effectiveMode),
                    foot: synLimitPps > 0 ? `Shield ${synLimitPps} pps` : 'Shield off',
                    stroke: '#f59e0b',
                    fill: model.synFloodDrop > 0 ? '#451a03' : '#0f172a',
                  },
                ] as const
              ).map((node) => {
                const isSelected = selectedStage === node.id;
                return (
                  <g
                    key={node.id}
                    onClick={() => setSelectedStage(node.id)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setSelectedStage(node.id);
                      }
                    }}
                    tabIndex={0}
                    role="button"
                    aria-label={`${node.title}: ${node.sub}`}
                    className="cursor-pointer outline-none"
                  >
                    <rect
                      x={node.x}
                      y={node.y}
                      width={node.w}
                      height={node.h}
                      rx={8}
                      fill={node.fill}
                      fillOpacity={0.78}
                      stroke={isSelected ? '#f8fafc' : node.stroke}
                      strokeWidth={isSelected ? 2 : 1.2}
                    />
                    <text x={node.x + 10} y={node.y + 18} fill="#f8fafc" fontSize={11} fontWeight={700}>
                      {node.title}
                    </text>
                    <text
                      x={node.x + 10}
                      y={node.y + 34}
                      fill="#e2e8f0"
                      fontSize={11}
                      fontFamily="monospace"
                    >
                      {node.sub}
                    </text>
                    <text x={node.x + 10} y={node.y + node.h - 8} fill="#94a3b8" fontSize={10} fontFamily="monospace">
                      {node.foot}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Selected Stage Inspector Bar */}
          <div className="pt-2 border-t border-slate-800 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3 text-xs">
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`font-bold ${activeMeta.accentClass}`}>{activeMeta.title}</span>
                <span className="font-mono tabular-nums text-white font-semibold">
                  {formatStageValue(activeValue, effectiveMode)} ({pctLabel(activeValue, totalForPct)})
                </span>
                {selectedStage === 'blocklist' || selectedStage === 'lpm' || selectedStage === 'synflood' ? (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-500/15 border border-rose-500/30 text-rose-300 font-mono text-[11px] tabular-nums">
                    <ShieldAlert className="w-3 h-3" />
                    Total Dropped Bytes: {formatBytesCompact(model.dropBytes)}
                  </span>
                ) : null}
              </div>
              <p className="text-slate-400 leading-relaxed">{activeMeta.description}</p>
            </div>

            <div className="flex flex-wrap items-center gap-1.5 shrink-0">
              <span className="text-slate-400">BPF Maps:</span>
              {activeMeta.maps.map((m) => (
                <code
                  key={m}
                  className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-emerald-300"
                >
                  {m}
                </code>
              ))}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
