'use client';

import React, { useMemo, useState } from 'react';
import { Cpu, Database, Lock, Search } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  formatBytesCompact,
  formatDurationNs,
  type KernelBpfInventory,
} from '@/lib/ebpf-telemetry';

interface EbpfKernelInventoryPanelProps {
  inventory?: KernelBpfInventory;
  daemonDown?: boolean;
}

const TOOLTIP_STYLE = {
  backgroundColor: '#0f172a',
  borderColor: '#334155',
  borderRadius: '0.5rem',
  fontSize: '12px',
  color: '#f1f5f9',
};

export function EbpfKernelInventoryPanel({ inventory, daemonDown = false }: EbpfKernelInventoryPanelProps) {
  const [tableView, setTableView] = useState<'programs' | 'maps'>('programs');
  const [progMetric, setProgMetric] = useState<'count' | 'jited' | 'runtime'>('count');
  const [query, setQuery] = useState('');

  const available = Boolean(inventory?.available);
  const q = query.trim().toLowerCase();

  const progChartData = useMemo(() => {
    return (inventory?.programsByType || []).slice(0, 10).map((t) => ({
      type: t.type,
      value:
        progMetric === 'count'
          ? t.count
          : progMetric === 'jited'
            ? Math.round((t.totalBytes / 1024) * 10) / 10
            : Math.round((t.totalRunTimeNs / 1_000_000) * 100) / 100,
      count: t.count,
      jitedBytes: t.totalBytes,
      runTimeNs: t.totalRunTimeNs,
    }));
  }, [inventory?.programsByType, progMetric]);

  const mapChartData = useMemo(() => {
    return (inventory?.maps || [])
      .slice()
      .sort((a, b) => b.memlockBytes - a.memlockBytes)
      .slice(0, 10)
      .map((m) => ({
        name: m.name,
        type: m.type,
        memKiB: Math.round((m.memlockBytes / 1024) * 10) / 10,
        memlockBytes: m.memlockBytes,
        maxEntries: m.maxEntries,
      }));
  }, [inventory?.maps]);

  const filteredPrograms = useMemo(() => {
    const progs = inventory?.programs || [];
    if (!q) return progs;
    return progs.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.type.toLowerCase().includes(q) ||
        p.tag.toLowerCase().includes(q) ||
        String(p.id).includes(q)
    );
  }, [inventory?.programs, q]);

  const filteredMaps = useMemo(() => {
    const maps = inventory?.maps || [];
    if (!q) return maps;
    return maps.filter(
      (m) =>
        m.name.toLowerCase().includes(q) ||
        m.type.toLowerCase().includes(q) ||
        String(m.id).includes(q)
    );
  }, [inventory?.maps, q]);

  return (
    <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Cpu className="w-4 h-4 text-emerald-400" />
            Live Kernel eBPF Program &amp; Map Inventory (<code className="font-mono text-xs text-emerald-300">sys_bpf</code>)
          </h3>
          <p className="text-xs text-slate-400">
            Enumerated directly from the running Linux kernel via <code className="font-mono">BPF_PROG_GET_NEXT_ID</code> and{' '}
            <code className="font-mono">BPF_MAP_GET_NEXT_ID</code>
          </p>
        </div>

        <span
          className={`px-2.5 py-1 rounded-md text-xs font-mono border ${
            inventory?.statsEnabled
              ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
              : 'bg-slate-950 border-slate-800 text-slate-300'
          }`}
        >
          bpf_stats_enabled: {inventory?.statsEnabled ? 'ON (ns/run active)' : 'OFF (0 ns reported)'}
        </span>
      </div>

      {/* Flat segmented metrics strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 py-3 px-4 rounded-lg bg-slate-950 border border-slate-800 text-xs">
        <div>
          <div className="text-slate-400">Loaded Programs</div>
          <div className="text-lg font-bold font-mono tabular-nums text-white mt-0.5">
            {available ? inventory?.totalPrograms.toLocaleString() : '—'}
          </div>
        </div>
        <div>
          <div className="text-slate-400">Loaded Maps</div>
          <div className="text-lg font-bold font-mono tabular-nums text-sky-300 mt-0.5">
            {available ? inventory?.totalMaps.toLocaleString() : '—'}
          </div>
        </div>
        <div>
          <div className="text-slate-400">Total JIT Code</div>
          <div className="text-lg font-bold font-mono tabular-nums text-emerald-300 mt-0.5">
            {available ? formatBytesCompact(inventory?.totalJitedBytes ?? 0) : '—'}
          </div>
        </div>
        <div>
          <div className="text-slate-400">Locked BPF Memory</div>
          <div className="text-lg font-bold font-mono tabular-nums text-purple-300 mt-0.5">
            {available
              ? formatBytesCompact(
                  (inventory?.totalProgMemlockBytes ?? 0) + (inventory?.totalMapMemlockBytes ?? 0)
                )
              : '—'}
          </div>
        </div>
      </div>

      {!available ? (
        <div className="p-4 rounded-lg bg-slate-950 border border-dashed border-slate-800 text-xs text-slate-400">
          {daemonDown
            ? 'Daemon offline — live kernel BPF program and map inventory is unavailable.'
            : inventory?.error ||
              'Kernel BPF enumeration returned unavailable on this host (requires CAP_BPF / CAP_SYS_ADMIN in axonwalld).'}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {/* Programs by Type */}
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-slate-200">Loaded BPF Programs by Type</span>
                <div className="inline-flex rounded-lg bg-slate-950 border border-slate-800 p-0.5 text-[11px]">
                  <button
                    type="button"
                    onClick={() => setProgMetric('count')}
                    className={`px-2 py-0.5 rounded font-medium ${
                      progMetric === 'count' ? 'bg-emerald-500/20 text-emerald-300' : 'text-slate-400'
                    }`}
                  >
                    Count
                  </button>
                  <button
                    type="button"
                    onClick={() => setProgMetric('jited')}
                    className={`px-2 py-0.5 rounded font-medium ${
                      progMetric === 'jited' ? 'bg-sky-500/20 text-sky-300' : 'text-slate-400'
                    }`}
                  >
                    JIT KiB
                  </button>
                  <button
                    type="button"
                    onClick={() => setProgMetric('runtime')}
                    className={`px-2 py-0.5 rounded font-medium ${
                      progMetric === 'runtime' ? 'bg-amber-500/20 text-amber-300' : 'text-slate-400'
                    }`}
                  >
                    Runtime ms
                  </button>
                </div>
              </div>

              {progChartData.length === 0 ? (
                <div className="h-[220px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg">
                  No loaded eBPF programs currently reported by the kernel.
                </div>
              ) : (
                <div className="h-[220px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={progChartData} layout="vertical" margin={{ left: 6, right: 14 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                      <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                      <YAxis type="category" dataKey="type" width={118} tick={{ fill: '#cbd5e1', fontSize: 11 }} />
                      <Tooltip contentStyle={TOOLTIP_STYLE} />
                      <Bar
                        dataKey="value"
                        name={progMetric === 'count' ? 'Programs' : progMetric === 'jited' ? 'JIT KiB' : 'Runtime ms'}
                        fill={progMetric === 'runtime' ? '#f59e0b' : progMetric === 'jited' ? '#38bdf8' : '#10b981'}
                        radius={[0, 4, 4, 0]}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>

            {/* Top BPF Maps by Memory Footprint */}
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-slate-200">Top BPF Maps by Locked RAM</span>
                <span className="text-[11px] font-mono tabular-nums text-slate-400">
                  {formatBytesCompact(inventory?.totalMapMemlockBytes ?? 0)} total
                </span>
              </div>

              {mapChartData.length === 0 ? (
                <div className="h-[220px] flex items-center justify-center text-xs text-slate-400 border border-dashed border-slate-800 rounded-lg">
                  No eBPF maps currently allocated in the kernel.
                </div>
              ) : (
                <div className="h-[220px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={mapChartData} layout="vertical" margin={{ left: 6, right: 14 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                      <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} unit=" KiB" />
                      <YAxis type="category" dataKey="name" width={128} tick={{ fill: '#7dd3fc', fontSize: 11 }} />
                      <Tooltip
                        contentStyle={TOOLTIP_STYLE}
                        formatter={(val: any, _name: any, props: any) => [
                          `${formatBytesCompact(props?.payload?.memlockBytes ?? Number(val) * 1024)} (${props?.payload?.type}, max ${props?.payload?.maxEntries?.toLocaleString()})`,
                          'Memlock',
                        ]}
                      />
                      <Bar dataKey="memKiB" name="Locked RAM (KiB)" fill="#a855f7" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          </div>

          {/* Interactive Table */}
          <div className="space-y-3 pt-2 border-t border-slate-800">
            <div className="flex flex-wrap items-center justify-between gap-2.5">
              <div className="inline-flex rounded-lg bg-slate-950 border border-slate-800 p-0.5 text-xs">
                <button
                  type="button"
                  onClick={() => setTableView('programs')}
                  className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-md font-medium ${
                    tableView === 'programs' ? 'bg-emerald-500/20 text-emerald-300' : 'text-slate-400'
                  }`}
                >
                  <Cpu className="w-3.5 h-3.5" />
                  Programs ({filteredPrograms.length})
                </button>
                <button
                  type="button"
                  onClick={() => setTableView('maps')}
                  className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-md font-medium ${
                    tableView === 'maps' ? 'bg-sky-500/20 text-sky-300' : 'text-slate-400'
                  }`}
                >
                  <Database className="w-3.5 h-3.5" />
                  Maps ({filteredMaps.length})
                </button>
              </div>

              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Filter ID, name, type, tag..."
                  className="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white font-mono w-56"
                />
              </div>
            </div>

            <div className="overflow-x-auto max-h-72">
              {tableView === 'programs' ? (
                <table className="w-full text-left text-xs font-mono tabular-nums">
                  <thead className="text-[11px] uppercase text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2 pr-2">ID</th>
                      <th className="py-2 px-2">Name / Tag</th>
                      <th className="py-2 px-2">Type</th>
                      <th className="py-2 px-2">JIT / Insns</th>
                      <th className="py-2 px-2">Maps</th>
                      <th className="py-2 px-2">Run Count</th>
                      <th className="py-2 pl-2 text-right">Avg / Total CPU</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {filteredPrograms.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="py-6 text-center text-slate-400 font-sans">
                          No loaded BPF programs match the filter.
                        </td>
                      </tr>
                    ) : (
                      filteredPrograms.slice(0, 60).map((p) => {
                        const avgNs = p.runCount > 0 ? p.runTimeNs / p.runCount : 0;
                        return (
                          <tr key={p.id} className="hover:bg-slate-800/40">
                            <td className="py-1.5 pr-2 text-slate-400">{p.id}</td>
                            <td className="py-1.5 px-2 text-white">
                              {p.name}
                              <span className="ml-2 text-[10px] text-slate-400">{p.tag}</span>
                              {p.hasBtf && (
                                <span className="ml-1.5 px-1 py-0.5 rounded bg-emerald-500/15 text-emerald-300 text-[10px]">
                                  BTF
                                </span>
                              )}
                            </td>
                            <td className="py-1.5 px-2 text-sky-300">{p.type}</td>
                            <td className="py-1.5 px-2 text-slate-300">
                              {formatBytesCompact(p.jitedBytes)} ({p.verifiedInsns} insns)
                            </td>
                            <td className="py-1.5 px-2 text-slate-300">{p.mapCount}</td>
                            <td className="py-1.5 px-2 text-slate-200">{p.runCount.toLocaleString()}</td>
                            <td className="py-1.5 pl-2 text-right text-amber-300">
                              {p.runCount > 0 ? `${formatDurationNs(avgNs)} / ${formatDurationNs(p.runTimeNs)}` : '—'}
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              ) : (
                <table className="w-full text-left text-xs font-mono tabular-nums">
                  <thead className="text-[11px] uppercase text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2 pr-2">ID</th>
                      <th className="py-2 px-2">Name</th>
                      <th className="py-2 px-2">Map Type</th>
                      <th className="py-2 px-2">Key / Value Bytes</th>
                      <th className="py-2 px-2">Max Entries</th>
                      <th className="py-2 px-2">Locked RAM</th>
                      <th className="py-2 pl-2 text-right">State</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {filteredMaps.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="py-6 text-center text-slate-400 font-sans">
                          No loaded BPF maps match the filter.
                        </td>
                      </tr>
                    ) : (
                      filteredMaps.slice(0, 60).map((m) => (
                        <tr key={m.id} className="hover:bg-slate-800/40">
                          <td className="py-1.5 pr-2 text-slate-400">{m.id}</td>
                          <td className="py-1.5 px-2 text-sky-300">{m.name}</td>
                          <td className="py-1.5 px-2 text-slate-200">{m.type}</td>
                          <td className="py-1.5 px-2 text-slate-300">
                            {m.keySize}B / {m.valueSize}B
                          </td>
                          <td className="py-1.5 px-2 text-slate-300">{m.maxEntries.toLocaleString()}</td>
                          <td className="py-1.5 px-2 text-purple-300">{formatBytesCompact(m.memlockBytes)}</td>
                          <td className="py-1.5 pl-2 text-right">
                            {m.frozen ? (
                              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300 text-[10px]">
                                <Lock className="w-2.5 h-2.5" /> Frozen
                              </span>
                            ) : (
                              <span className="text-slate-400 text-[10px]">Mutable</span>
                            )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
