'use client';

import React, { useMemo, useState } from 'react';
import { HardDrive, Network, Server } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  formatBytesCompact,
  type EbpfOverviewTelemetry,
  type NetdevTrafficStat,
} from '@/lib/ebpf-telemetry';

interface EbpfCrossDutyVisualizerProps {
  overview: EbpfOverviewTelemetry | null;
}

const TOOLTIP_STYLE = {
  backgroundColor: '#0f172a',
  borderColor: '#334155',
  borderRadius: '0.5rem',
  fontSize: '12px',
  color: '#f1f5f9',
};

interface NetdevRow extends NetdevTrafficStat {
  duty: 'virt' | 'bridge' | 'k3s';
}

export function EbpfCrossDutyVisualizer({ overview }: EbpfCrossDutyVisualizerProps) {
  const [dutyFilter, setDutyFilter] = useState<'all' | 'virt' | 'k3s'>('all');
  const [netMetric, setNetMetric] = useState<'bytes' | 'packets' | 'drops'>('bytes');

  const daemonDown = Boolean(overview?.daemonDown);

  const combinedNetdevs = useMemo<NetdevRow[]>(() => {
    const out: NetdevRow[] = [];
    const seen = new Set<string>();

    const pushUnique = (nd: NetdevTrafficStat, duty: NetdevRow['duty']) => {
      if (!nd.name || seen.has(`${duty}:${nd.name}`)) return;
      seen.add(`${duty}:${nd.name}`);
      out.push({ ...nd, duty });
    };

    for (const w of overview?.virt.workloads || []) {
      for (const nd of w.netdevs || []) {
        pushUnique({ ...nd, kind: `${w.kind.toUpperCase()}:${w.name}` }, 'virt');
      }
    }
    for (const br of overview?.virt.bridgeStats || []) {
      pushUnique({ ...br, kind: 'bridge' }, 'bridge');
    }
    if (out.length === 0) {
      for (const nd of overview?.virt.vnetInterfaces || []) {
        pushUnique(nd, nd.kind === 'bridge' ? 'bridge' : 'virt');
      }
    }
    for (const cni of overview?.k3s.cniInterfaces || []) {
      pushUnique({ ...cni, kind: 'cni' }, 'k3s');
    }

    return out
      .filter((item) => {
        if (dutyFilter === 'all') return true;
        if (dutyFilter === 'virt') return item.duty === 'virt' || item.duty === 'bridge';
        return item.duty === 'k3s';
      })
      .sort((a, b) => b.rxBytes + b.txBytes - (a.rxBytes + a.txBytes))
      .slice(0, 12);
  }, [overview, dutyFilter]);

  const netdevChartData = useMemo(() => {
    return combinedNetdevs.map((d) => ({
      device: d.name,
      kind: d.kind,
      xdpAttached: d.xdpAttached,
      rxVal:
        netMetric === 'bytes'
          ? Math.round((d.rxBytes / (1024 * 1024)) * 100) / 100
          : netMetric === 'packets'
            ? d.rxPackets
            : d.rxDropped,
      txVal:
        netMetric === 'bytes'
          ? Math.round((d.txBytes / (1024 * 1024)) * 100) / 100
          : netMetric === 'packets'
            ? d.txPackets
            : d.txDropped,
    }));
  }, [combinedNetdevs, netMetric]);

  const nas = overview?.nas;
  const arc = nas?.arc;
  const zil = nas?.zil;
  const poolIoData = useMemo(() => {
    const src = nas?.poolIoStats?.length ? nas.poolIoStats : nas?.pools || [];
    return src.map((p: any) => ({
      pool: String(p.pool ?? p.name ?? 'pool'),
      readGiB: Math.round((Number(p.nreadBytes ?? 0) / (1024 * 1024 * 1024)) * 100) / 100,
      writeGiB: Math.round((Number(p.nwrittenBytes ?? 0) / (1024 * 1024 * 1024)) * 100) / 100,
      reads: Number(p.reads ?? 0),
      writes: Number(p.writes ?? 0),
      waitQ: Number(p.waitQueueDepth ?? 0),
      activeQ: Number(p.activeQueueDepth ?? 0),
    }));
  }, [nas]);

  const arcUsedPct =
    arc && arc.maxSizeBytes > 0 ? Math.min(100, Math.round((arc.sizeBytes / arc.maxSizeBytes) * 100)) : 0;
  const arcHitPct = arc ? Math.min(100, Math.max(0, arc.hitRatioPct)) : 0;
  const totalItx = (zil?.itxMetaslabNormalCount ?? 0) + (zil?.itxMetaslabSlogCount ?? 0);
  const slogPct = totalItx > 0 ? Math.round(((zil?.itxMetaslabSlogCount ?? 0) / totalItx) * 100) : 0;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
      {/* Left: Virtualization TAP/veth + K3s CNI Ring-0 Netdev Chart */}
      <div className="lg:col-span-7 p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2.5">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Network className="w-4 h-4 text-sky-400" />
              Cross-Duty Netdev Telemetry (Virt TAP/veth &amp; K3s CNI)
            </h3>
            <p className="text-xs text-slate-400">
              Live kernel <code className="font-mono text-sky-300">/sys/class/net</code> throughput and XDP hook attachment across bridges, VMs, LXC &amp; CNI overlays
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <div className="inline-flex rounded-lg bg-slate-950 border border-slate-800 p-0.5 text-[11px]">
              {(['all', 'virt', 'k3s'] as const).map((f) => (
                <button
                  key={f}
                  type="button"
                  onClick={() => setDutyFilter(f)}
                  className={`px-2 py-0.5 rounded font-medium capitalize ${
                    dutyFilter === f ? 'bg-sky-500/20 text-sky-300' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {f === 'all' ? 'All Duties' : f === 'virt' ? 'Virt / Bridge' : 'K3s CNI'}
                </button>
              ))}
            </div>
            <div className="inline-flex rounded-lg bg-slate-950 border border-slate-800 p-0.5 text-[11px]">
              {(['bytes', 'packets', 'drops'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setNetMetric(m)}
                  className={`px-2 py-0.5 rounded font-medium capitalize ${
                    netMetric === m ? 'bg-emerald-500/20 text-emerald-300' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {m === 'bytes' ? 'MiB' : m}
                </button>
              ))}
            </div>
          </div>
        </div>

        {daemonDown ? (
          <div className="h-[250px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg">
            Daemon offline — Virt and K3s CNI netdev statistics unavailable.
          </div>
        ) : netdevChartData.length === 0 ? (
          <div className="h-[250px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg text-center px-4">
            No active VM TAP, LXC veth, bridge, or K3s CNI interfaces detected on host.
          </div>
        ) : (
          <>
            <div className="h-[240px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={netdevChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="device" tick={{ fill: '#cbd5e1', fontSize: 11 }} />
                  <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} width={56} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                  <Bar
                    dataKey="rxVal"
                    name={netMetric === 'bytes' ? 'RX (MiB)' : netMetric === 'packets' ? 'RX Pkts' : 'RX Dropped'}
                    fill={netMetric === 'drops' ? '#f43f5e' : '#10b981'}
                    radius={[4, 4, 0, 0]}
                  />
                  <Bar
                    dataKey="txVal"
                    name={netMetric === 'bytes' ? 'TX (MiB)' : netMetric === 'packets' ? 'TX Pkts' : 'TX Dropped'}
                    fill={netMetric === 'drops' ? '#f59e0b' : '#38bdf8'}
                    radius={[4, 4, 0, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800 text-[11px] font-mono tabular-nums">
              {combinedNetdevs.map((d) => (
                <span
                  key={`${d.duty}-${d.name}`}
                  className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-200"
                >
                  <Server className="w-3 h-3 text-slate-400" />
                  <span>{d.name}</span>
                  <span className="text-slate-400">({d.operState})</span>
                  {d.xdpAttached && <span className="text-emerald-300">XDP</span>}
                </span>
              ))}
            </div>
          </>
        )}
      </div>

      {/* Right: OpenZFS ARC / ZIL & Pool I/O Kstats */}
      <div className="lg:col-span-5 p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <HardDrive className="w-4 h-4 text-emerald-400" />
              OpenZFS ARC, ZIL &amp; Pool I/O Kstats
            </h3>
            <p className="text-xs text-slate-400">
              Live kernel <code className="font-mono text-emerald-300">/proc/spl/kstat/zfs</code> efficiency &amp; ZIO depth
            </p>
          </div>
          <span className="text-xs font-mono tabular-nums text-emerald-300">
            {nas?.zfsModuleLoaded ? `${poolIoData.length} pool(s)` : 'ZFS Standby'}
          </span>
        </div>

        {!nas?.zfsModuleLoaded ? (
          <div className="h-[250px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg text-center px-4">
            OpenZFS kstats not active on this host (<code className="font-mono mx-1">/proc/spl/kstat/zfs</code> absent).
          </div>
        ) : (
          <div className="space-y-4">
            {/* ARC Hit Ratio & Memory Target Bars */}
            <div className="space-y-2.5 text-xs">
              <div>
                <div className="flex justify-between font-mono tabular-nums mb-1">
                  <span className="text-slate-300">ARC Hit Efficiency</span>
                  <span className="text-emerald-300 font-bold">{arcHitPct.toFixed(2)}%</span>
                </div>
                <div className="h-2 rounded-full bg-slate-950 overflow-hidden">
                  <div className="h-full bg-emerald-500" style={{ width: `${arcHitPct}%` }} />
                </div>
                <div className="flex justify-between font-mono tabular-nums text-[11px] text-slate-400 mt-1">
                  <span>Hits: {(arc?.hits ?? 0).toLocaleString()}</span>
                  <span>Misses: {(arc?.misses ?? 0).toLocaleString()}</span>
                </div>
              </div>

              <div>
                <div className="flex justify-between font-mono tabular-nums mb-1">
                  <span className="text-slate-300">ARC Memory Ceiling</span>
                  <span className="text-sky-300">
                    {formatBytesCompact(arc?.sizeBytes ?? 0)} / {formatBytesCompact(arc?.maxSizeBytes ?? 0)} ({arcUsedPct}%)
                  </span>
                </div>
                <div className="h-2 rounded-full bg-slate-950 overflow-hidden">
                  <div className="h-full bg-sky-500" style={{ width: `${arcUsedPct}%` }} />
                </div>
                <div className="flex justify-between font-mono tabular-nums text-[11px] text-slate-400 mt-1">
                  <span>L2ARC Hits: {(arc?.l2Hits ?? 0).toLocaleString()}</span>
                  <span>ZIL Commits: {(zil?.zilCommitCount ?? 0).toLocaleString()} ({slogPct}% SLOG)</span>
                </div>
              </div>
            </div>

            {/* Pool I/O Chart */}
            {poolIoData.length > 0 ? (
              <div className="h-[175px] pt-2 border-t border-slate-800">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={poolIoData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                    <XAxis dataKey="pool" tick={{ fill: '#cbd5e1', fontSize: 11 }} />
                    <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} width={50} unit=" GiB" />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Legend wrapperStyle={{ fontSize: '11px' }} />
                    <Bar dataKey="readGiB" name="Read (GiB)" fill="#10b981" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="writeGiB" name="Written (GiB)" fill="#a855f7" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="pt-2 border-t border-slate-800 text-xs text-slate-400">
                ZFS kstats loaded; no imported zpool I/O tables found yet.
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
