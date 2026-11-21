'use client';

import React, { useMemo } from 'react';
import { Activity, Network } from 'lucide-react';
import {
  Area,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ComposedChart,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { formatBytesCompact } from '@/lib/ebpf-telemetry';
import type { SsePacketLike } from './EbpfFlowTopologyMap';

export interface FlowsRatePoint {
  time: string;
  pps: number;
  kbps: number;
}

interface FlowsLiveVisualStripProps {
  packets: SsePacketLike[];
  rateSeries: FlowsRatePoint[];
  isStreaming: boolean;
  feedError: string | null;
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
  DNS: '#06b6d4',
};

export function FlowsLiveVisualStrip({
  packets,
  rateSeries,
  isStreaming,
  feedError,
}: FlowsLiveVisualStripProps) {
  const protocolBreakdown = useMemo(() => {
    const counts = new Map<string, { proto: string; count: number; bytes: number }>();
    for (const p of packets) {
      const k = (p.protocol || 'OTHER').toUpperCase();
      const entry = counts.get(k) || { proto: k, count: 0, bytes: 0 };
      entry.count += 1;
      entry.bytes += Number(p.length) || 0;
      counts.set(k, entry);
    }
    return Array.from(counts.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [packets]);

  const topTalkers = useMemo(() => {
    const counts = new Map<string, { pair: string; bytes: number; pkts: number }>();
    for (const p of packets) {
      const pair = `${p.srcIp} -> ${p.dstIp}`;
      const entry = counts.get(pair) || { pair, bytes: 0, pkts: 0 };
      entry.pkts += 1;
      entry.bytes += Number(p.length) || 0;
      counts.set(pair, entry);
    }
    return Array.from(counts.values())
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 6)
      .map((t) => ({
        ...t,
        kib: Math.round((t.bytes / 1024) * 100) / 100,
      }));
  }, [packets]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
      <div className="lg:col-span-5 p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2.5">
        <div className="flex items-center justify-between text-xs">
          <span className="font-semibold text-white flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-emerald-400" />
            Live Stream Rate (30s Window)
          </span>
          <span className="font-mono tabular-nums text-slate-400">
            {isStreaming ? 'SSE Active' : feedError ? 'Feed Offline' : 'Paused'}
          </span>
        </div>

        {rateSeries.length === 0 ? (
          <div className="h-[150px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg">
            Waiting for live packet ticks from <code className="font-mono mx-1">/api/v1/events/packets</code>...
          </div>
        ) : (
          <div className="h-[150px]">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={rateSeries}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="time" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                <YAxis yAxisId="pps" tick={{ fill: '#10b981', fontSize: 10 }} width={40} />
                <YAxis yAxisId="kbps" orientation="right" tick={{ fill: '#38bdf8', fontSize: 10 }} width={46} unit=" KB" />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Area
                  yAxisId="pps"
                  type="monotone"
                  dataKey="pps"
                  name="Packets/s"
                  stroke="#10b981"
                  fill="#10b981"
                  fillOpacity={0.2}
                />
                <Line
                  yAxisId="kbps"
                  type="monotone"
                  dataKey="kbps"
                  name="KiB/s"
                  stroke="#38bdf8"
                  dot={false}
                  strokeWidth={1.75}
                />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      <div className="lg:col-span-3 p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between text-xs">
          <span className="font-semibold text-white">Protocol Split (Buffer)</span>
          <span className="font-mono tabular-nums text-slate-400">{packets.length} pkts</span>
        </div>

        {protocolBreakdown.length === 0 ? (
          <div className="h-[150px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg">
            No packets in ring buffer yet.
          </div>
        ) : (
          <div className="space-y-2 pt-1">
            {protocolBreakdown.map((p) => {
              const pct = packets.length > 0 ? Math.round((p.count / packets.length) * 100) : 0;
              const color = PROTO_COLORS[p.proto] || '#64748b';
              return (
                <div key={p.proto} className="space-y-1 text-[11px] font-mono tabular-nums">
                  <div className="flex justify-between text-slate-200">
                    <span>{p.proto}</span>
                    <span>
                      {p.count} ({pct}%) • {formatBytesCompact(p.bytes)}
                    </span>
                  </div>
                  <div className="h-1.5 rounded-full bg-slate-950 overflow-hidden">
                    <div className="h-full" style={{ width: `${pct}%`, backgroundColor: color }} />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="lg:col-span-4 p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2.5">
        <div className="flex items-center justify-between text-xs">
          <span className="font-semibold text-white flex items-center gap-1.5">
            <Network className="w-3.5 h-3.5 text-sky-400" />
            Top Buffer Talkers (KiB)
          </span>
        </div>

        {topTalkers.length === 0 ? (
          <div className="h-[150px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg">
            Capture live traffic to populate talker distribution.
          </div>
        ) : (
          <div className="h-[150px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topTalkers} layout="vertical" margin={{ left: 4, right: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                <YAxis type="category" dataKey="pair" width={145} tick={{ fill: '#cbd5e1', fontSize: 10 }} />
                <Tooltip
                  contentStyle={TOOLTIP_STYLE}
                  formatter={(val: any, _name: any, props: any) => [
                    `${formatBytesCompact(props?.payload?.bytes ?? Number(val) * 1024)} (${props?.payload?.pkts ?? 0} pkts)`,
                    'Traffic',
                  ]}
                />
                <Bar dataKey="kib" name="KiB" radius={[0, 3, 3, 0]}>
                  {topTalkers.map((t, idx) => (
                    <Cell key={t.pair} fill={idx === 0 ? '#10b981' : '#38bdf8'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
}
