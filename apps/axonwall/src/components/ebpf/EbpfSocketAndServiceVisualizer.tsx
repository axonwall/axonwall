'use client';

import React, { useMemo, useState } from 'react';
import { Activity, Grid3X3, Network, ShieldAlert } from 'lucide-react';
import {
  buildFlowHeatmapMatrix,
  correlateListeningSocketsWithXdp,
  formatBytesCompact,
  LINUX_TCP_STATE_ORDER,
  type FlowHeatmapCell,
  type KernelSocketTelemetry,
  type XdpBlockedEntry,
  type XdpFlowEntry,
  type XdpPortSummary,
} from '@/lib/ebpf-telemetry';

interface EbpfSocketAndServiceVisualizerProps {
  sockets?: KernelSocketTelemetry;
  flows: XdpFlowEntry[];
  topPorts: XdpPortSummary[];
  blockedIps: XdpBlockedEntry[];
  daemonDown: boolean;
  onBlockIp: (ip: string) => void;
}

type HeatmapMetric = 'bytes' | 'packets' | 'synPackets';

const STATE_PHASE: Record<string, { label: string; group: 'handshake' | 'active' | 'teardown' }> = {
  LISTEN: { label: 'LISTEN', group: 'handshake' },
  SYN_SENT: { label: 'SYN_SENT', group: 'handshake' },
  SYN_RECV: { label: 'SYN_RECV', group: 'handshake' },
  ESTABLISHED: { label: 'ESTABLISHED', group: 'active' },
  FIN_WAIT1: { label: 'FIN_WAIT1', group: 'teardown' },
  FIN_WAIT2: { label: 'FIN_WAIT2', group: 'teardown' },
  CLOSE_WAIT: { label: 'CLOSE_WAIT', group: 'teardown' },
  LAST_ACK: { label: 'LAST_ACK', group: 'teardown' },
  TIME_WAIT: { label: 'TIME_WAIT', group: 'teardown' },
  CLOSING: { label: 'CLOSING', group: 'teardown' },
  CLOSE: { label: 'CLOSE', group: 'teardown' },
};

function isLoopbackIp(ip: string): boolean {
  return ip === '127.0.0.1' || ip === '::1' || ip.startsWith('127.');
}

export function EbpfSocketAndServiceVisualizer({
  sockets,
  flows,
  topPorts,
  blockedIps,
  daemonDown,
  onBlockIp,
}: EbpfSocketAndServiceVisualizerProps) {
  const [heatmapMetric, setHeatmapMetric] = useState<HeatmapMetric>('bytes');
  const [selectedCell, setSelectedCell] = useState<FlowHeatmapCell | null>(null);

  const tcpStateRows = useMemo(() => {
    const counts = sockets?.tcpStates || {};
    const total = sockets?.totalTcpSockets || 0;
    return LINUX_TCP_STATE_ORDER.map((state) => {
      const count = counts[state] ?? 0;
      const pct = total > 0 ? (count / total) * 100 : 0;
      const warning =
        (state === 'SYN_RECV' && count >= 64) ||
        (state === 'CLOSE_WAIT' && count >= 100) ||
        (state === 'TIME_WAIT' && count >= 1000);
      return {
        state,
        count,
        pct,
        group: STATE_PHASE[state]?.group || 'teardown',
        warning,
      };
    });
  }, [sockets]);

  const heatmap = useMemo(
    () => buildFlowHeatmapMatrix(flows, blockedIps, 10, 10),
    [flows, blockedIps]
  );

  const correlatedServices = useMemo(
    () => correlateListeningSocketsWithXdp(sockets, topPorts),
    [sockets, topPorts]
  );

  const maxHeatmapValue =
    heatmapMetric === 'bytes'
      ? heatmap.maxBytes
      : heatmapMetric === 'packets'
        ? heatmap.maxPackets
        : heatmap.maxSyn;

  return (
    <div className="space-y-6">
      {/* 1. Live Kernel TCP/UDP Socket State Machine Funnel */}
      <section className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Network className="w-5 h-5 text-emerald-400" />
              Live Kernel TCP Socket State Machine &amp; Endpoint Census
            </h2>
            <p className="text-xs text-slate-400">
              Measured directly from <code className="font-mono">/proc/net/tcp</code>,{' '}
              <code className="font-mono">tcp6</code>, <code className="font-mono">udp</code>, and{' '}
              <code className="font-mono">udp6</code>. Flags half-open SYN pressure, <code className="font-mono">CLOSE_WAIT</code> descriptor leaks, and <code className="font-mono">TIME_WAIT</code> bursts.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 py-3 px-4 rounded-lg bg-slate-950 border border-slate-800 text-xs tabular-nums">
          <div>
            <div className="text-slate-400">Total TCP Sockets</div>
            <div className="text-base font-bold font-mono text-white mt-0.5">
              {(sockets?.totalTcpSockets ?? 0).toLocaleString()}
            </div>
          </div>
          <div>
            <div className="text-slate-400">IPv4 / IPv6 TCP</div>
            <div className="text-base font-bold font-mono text-emerald-300 mt-0.5">
              {(sockets?.ipv4TcpSockets ?? 0).toLocaleString()} / {(sockets?.ipv6TcpSockets ?? 0).toLocaleString()}
            </div>
          </div>
          <div>
            <div className="text-slate-400">Total UDP Sockets</div>
            <div className="text-base font-bold font-mono text-sky-300 mt-0.5">
              {(sockets?.totalUdpSockets ?? 0).toLocaleString()}
            </div>
          </div>
          <div>
            <div className="text-slate-400">ESTABLISHED / SYN_RECV</div>
            <div className="text-base font-bold font-mono text-purple-300 mt-0.5">
              {(sockets?.tcpStates?.ESTABLISHED ?? 0).toLocaleString()} /{' '}
              {(sockets?.tcpStates?.SYN_RECV ?? 0).toLocaleString()}
            </div>
          </div>
          <div>
            <div className="text-slate-400">Listening Endpoints</div>
            <div className="text-base font-bold font-mono text-white mt-0.5">
              {(sockets?.listeningPorts?.length ?? 0).toLocaleString()}
            </div>
          </div>
        </div>

        {daemonDown ? (
          <div className="py-8 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
            Daemon offline — kernel socket state machine telemetry unavailable.
          </div>
        ) : !sockets?.available ? (
          <div className="py-8 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
            Kernel socket tables unavailable or empty.
          </div>
        ) : (
          <div className="space-y-3 rounded-lg bg-slate-950 border border-slate-800 p-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {(
                [
                  { key: 'handshake' as const, title: 'Passive & Handshake', accent: 'bg-sky-500' },
                  { key: 'active' as const, title: 'Active Connected State', accent: 'bg-emerald-500' },
                  { key: 'teardown' as const, title: 'Teardown & Socket Drain', accent: 'bg-purple-500' },
                ] as const
              ).map((phase) => {
                const phaseRows = tcpStateRows.filter((r) => r.group === phase.key);
                return (
                  <div key={phase.key} className="space-y-2.5">
                    <div className="text-xs font-semibold text-slate-300 border-b border-slate-800 pb-1.5">
                      {phase.title}
                    </div>
                    <div className="space-y-2">
                      {phaseRows.map((row) => (
                        <div key={row.state} className="space-y-1 text-xs tabular-nums">
                          <div className="flex items-center justify-between font-mono">
                            <span className={row.warning ? 'text-amber-300 font-bold' : 'text-slate-200'}>
                              {row.state}
                            </span>
                            <span className="text-slate-300">
                              {row.count.toLocaleString()} ({row.pct.toFixed(1)}%)
                            </span>
                          </div>
                          <div className="h-2 rounded-full bg-slate-900 overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all ${
                                row.warning ? 'bg-amber-400' : phase.accent
                              }`}
                              style={{ width: `${row.count > 0 ? Math.max(3, row.pct) : 0}%` }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </section>

      {/* 2. Source IP x Destination Service/Port Traffic Heatmap Matrix */}
      <section className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Grid3X3 className="w-4 h-4 text-sky-400" />
              Source IP &times; Destination Service Traffic Matrix
            </h3>
            <p className="text-xs text-slate-400">
              Live XDP <code className="font-mono">flow_map</code> / <code className="font-mono">flow6_map</code> intensity across top sources and L4 ports. Amber cells mark high SYN ratios (&ge;45%); click any populated cell to inspect 5-tuples or fast-drop.
            </p>
          </div>

          <div className="flex items-center gap-1 rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs">
            {(
              [
                { id: 'bytes' as const, label: 'Bytes' },
                { id: 'packets' as const, label: 'Packets' },
                { id: 'synPackets' as const, label: 'SYN Count' },
              ] as const
            ).map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => setHeatmapMetric(opt.id)}
                className={`px-2.5 py-1 rounded font-semibold transition ${
                  heatmapMetric === opt.id ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        {daemonDown ? (
          <div className="py-8 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
            Daemon offline — live XDP flow matrix unavailable.
          </div>
        ) : heatmap.rows.length === 0 || heatmap.cols.length === 0 ? (
          <div className="py-8 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
            No active flows present in XDP flow tables yet.
          </div>
        ) : (
          <div className="space-y-3">
            <div className="overflow-x-auto rounded-lg bg-slate-950 border border-slate-800 p-3">
              <table className="w-full border-collapse text-xs tabular-nums">
                <thead>
                  <tr>
                    <th className="py-2 pr-3 text-left font-mono text-[11px] text-slate-400">
                      Source IP \ Dst Port
                    </th>
                    {heatmap.cols.map((col) => (
                      <th
                        key={col.colKey}
                        className="px-1.5 py-2 text-center font-mono text-[11px] text-slate-300 whitespace-nowrap"
                      >
                        {col.label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {heatmap.rows.map((row) => (
                    <tr key={row.srcIp} className="border-t border-slate-800/70">
                      <td className="py-1.5 pr-3 font-mono text-[11px] text-slate-200 whitespace-nowrap">
                        <span className={row.isBlocked ? 'text-rose-300 font-bold' : ''}>
                          {row.srcIp}
                        </span>
                        {row.isBlocked && (
                          <span className="ml-1.5 px-1.5 py-0.5 rounded bg-rose-500/20 border border-rose-500/40 text-rose-300 text-[10px]">
                            DROP
                          </span>
                        )}
                      </td>
                      {heatmap.cols.map((col) => {
                        const cell = heatmap.cells[`${row.srcIp}|${col.colKey}`];
                        if (!cell) {
                          return (
                            <td key={col.colKey} className="p-1 text-center">
                              <div className="h-8 min-w-[60px] rounded bg-slate-900/50 border border-slate-900" />
                            </td>
                          );
                        }
                        const rawVal =
                          heatmapMetric === 'bytes'
                            ? cell.bytes
                            : heatmapMetric === 'packets'
                              ? cell.packets
                              : cell.synPackets;
                        const norm = maxHeatmapValue > 0 ? rawVal / maxHeatmapValue : 0;
                        const isSynHeavy = cell.synPackets >= 5 && cell.synRatioPct >= 45;
                        const isSelected =
                          selectedCell?.rowSrcIp === cell.rowSrcIp && selectedCell?.colKey === cell.colKey;

                        const bgStyle = cell.isBlocked
                          ? `rgba(244, 63, 94, ${0.18 + norm * 0.55})`
                          : isSynHeavy
                            ? `rgba(245, 158, 11, ${0.18 + norm * 0.58})`
                            : `rgba(16, 185, 129, ${0.14 + norm * 0.62})`;

                        const display =
                          heatmapMetric === 'bytes'
                            ? formatBytesCompact(cell.bytes)
                            : rawVal.toLocaleString();

                        return (
                          <td key={col.colKey} className="p-1 text-center">
                            <button
                              type="button"
                              onClick={() => setSelectedCell(cell)}
                              style={{ backgroundColor: bgStyle }}
                              title={`${cell.rowSrcIp} -> ${col.label}: ${formatBytesCompact(cell.bytes)}, ${cell.packets} pkts, SYN ${cell.synRatioPct}%`}
                              className={`h-8 w-full min-w-[60px] px-1.5 rounded border font-mono text-[11px] text-white transition ${
                                isSelected
                                  ? 'border-white ring-1 ring-white'
                                  : cell.isBlocked
                                    ? 'border-rose-500/60'
                                    : isSynHeavy
                                      ? 'border-amber-500/60'
                                      : 'border-emerald-500/30 hover:border-slate-300'
                              }`}
                            >
                              {display}
                            </button>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {selectedCell && (
              <div className="pt-3 border-t border-slate-800 space-y-2.5 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-mono tabular-nums text-slate-200 flex flex-wrap items-center gap-3">
                    <span className="font-bold text-emerald-300">
                      {selectedCell.rowSrcIp} &rarr; {selectedCell.protoName}:{selectedCell.dstPort}
                    </span>
                    <span>{formatBytesCompact(selectedCell.bytes)}</span>
                    <span>{selectedCell.packets.toLocaleString()} pkts</span>
                    <span className={selectedCell.synRatioPct >= 45 ? 'text-amber-300 font-bold' : ''}>
                      SYN: {selectedCell.synPackets} ({selectedCell.synRatioPct}%)
                    </span>
                    <span>RST: {selectedCell.rstPackets}</span>
                    <span>{selectedCell.flowCount} flows</span>
                  </div>

                  <button
                    type="button"
                    disabled={isLoopbackIp(selectedCell.rowSrcIp)}
                    onClick={() => onBlockIp(selectedCell.rowSrcIp)}
                    className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-40 text-xs font-semibold text-white"
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    {isLoopbackIp(selectedCell.rowSrcIp)
                      ? 'Loopback Protected'
                      : selectedCell.isBlocked
                        ? 'Refresh XDP_DROP'
                        : 'Block Source in XDP'}
                  </button>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-[11px] font-mono tabular-nums">
                    <thead className="text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="py-1.5 pr-3">5-Tuple Endpoint</th>
                        <th className="py-1.5 px-3">VLAN</th>
                        <th className="py-1.5 px-3">Flags</th>
                        <th className="py-1.5 px-3">Packets</th>
                        <th className="py-1.5 pl-3">Bytes</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70 text-slate-200">
                      {selectedCell.flows.slice(0, 8).map((f, idx) => (
                        <tr key={`${f.srcIp}:${f.srcPort}-${f.dstIp}:${f.dstPort}-${idx}`}>
                          <td className="py-1.5 pr-3">
                            {f.srcIp}:{f.srcPort} &rarr; {f.dstIp}:{f.dstPort}
                          </td>
                          <td className="py-1.5 px-3 text-sky-300">
                            {f.vlanId > 0 ? `VLAN ${f.vlanId}` : 'Untagged'}
                          </td>
                          <td className="py-1.5 px-3 text-slate-300">{f.tcpFlags || '-'}</td>
                          <td className="py-1.5 px-3">{f.packets.toLocaleString()}</td>
                          <td className="py-1.5 pl-3">{formatBytesCompact(f.bytes)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}
      </section>

      {/* 3. Listening Host Services x XDP Ingress Exposure Table */}
      <section className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-400" />
            Host Listening Services &times; XDP Ingress Exposure ({correlatedServices.length})
          </h3>
          <p className="text-xs text-slate-400">
            Joins open host TCP/UDP listening sockets against active XDP dataplane ingress ports to distinguish actively hit services from quiet local listeners.
          </p>
        </div>

        {daemonDown ? (
          <div className="py-8 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
            Daemon offline — host listening socket inventory unavailable.
          </div>
        ) : correlatedServices.length === 0 ? (
          <div className="py-8 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
            No bound listening TCP/UDP sockets reported.
          </div>
        ) : (
          <div className="overflow-x-auto max-h-80 rounded-lg bg-slate-950 border border-slate-800 p-2">
            <table className="w-full text-left text-xs tabular-nums">
              <thead className="text-[11px] uppercase text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2 pr-3">Proto / Port</th>
                  <th className="py-2 px-3">Service</th>
                  <th className="py-2 px-3">Sockets (IPv4 / IPv6)</th>
                  <th className="py-2 px-3">XDP Flows</th>
                  <th className="py-2 px-3">XDP Packets</th>
                  <th className="py-2 px-3">XDP Bytes</th>
                  <th className="py-2 px-3">SYN Ratio</th>
                  <th className="py-2 pl-3">XDP Exposure</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 font-mono text-[11px] text-slate-200">
                {correlatedServices.slice(0, 32).map((svc) => (
                  <tr key={`${svc.protocol}:${svc.port}`} className="hover:bg-slate-900/60">
                    <td className="py-2 pr-3 font-semibold text-white">
                      {svc.protocol}:{svc.port}
                    </td>
                    <td className="py-2 px-3 text-slate-300 font-sans">
                      {svc.service || '-'}
                    </td>
                    <td className="py-2 px-3">
                      {svc.ipv4Sockets} / {svc.ipv6Sockets}
                    </td>
                    <td className="py-2 px-3">{svc.xdpFlows.toLocaleString()}</td>
                    <td className="py-2 px-3">{svc.xdpPackets.toLocaleString()}</td>
                    <td className="py-2 px-3 text-emerald-300">
                      {formatBytesCompact(svc.xdpBytes)}
                    </td>
                    <td className="py-2 px-3">
                      <span className={svc.synRatioPct >= 45 ? 'text-amber-300 font-bold' : 'text-slate-300'}>
                        {svc.synRatioPct}%
                      </span>
                    </td>
                    <td className="py-2 pl-3 font-sans">
                      {svc.activeInXdp ? (
                        <span className="px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-[11px]">
                          Active XDP
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-400 text-[11px]">
                          Quiet Listener
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
