'use client';

import React, { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { Binary, Pause, Play, Radio, Trash2 } from 'lucide-react';
import { buildTcpdumpFilter, formatBps, formatBytes, validateFqlQuery } from '@axonwall/lib/compile/netflow';
import { FqlInputBar } from './FqlInputBar';
import type { NetFlowQueryRecordSnapshot } from './types';

export function LiveTailTab() {
  const [streaming, setStreaming] = useState(true);
  const [fql, setFql] = useState('');
  const [appliedFql, setAppliedFql] = useState('');
  const [flows, setFlows] = useState<NetFlowQueryRecordSnapshot[]>([]);
  const [fps, setFps] = useState(0);
  const [streamErr, setStreamErr] = useState<string | null>(null);
  const counterRef = useRef(0);
  const sseRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const t = setInterval(() => {
      setFps(counterRef.current);
      counterRef.current = 0;
    }, 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (!streaming) {
      sseRef.current?.close();
      sseRef.current = null;
      return;
    }

    setStreamErr(null);
    const qs = appliedFql.trim() ? `?fql=${encodeURIComponent(appliedFql.trim())}` : '';
    const sse = new EventSource(`/api/v1/netflow/stream${qs}`);
    sseRef.current = sse;

    sse.addEventListener('flow', (ev) => {
      try {
        const rec = JSON.parse((ev as MessageEvent).data) as NetFlowQueryRecordSnapshot;
        counterRef.current++;
        setFlows((prev) => [rec, ...prev.slice(0, 299)]);
      } catch {}
    });

    sse.addEventListener('error', (ev) => {
      const data = (ev as MessageEvent).data;
      if (!data) return;
      try {
        const parsed = JSON.parse(data);
        setStreamErr(parsed.error || 'NetFlow live stream unavailable.');
      } catch {
        setStreamErr('NetFlow live stream unavailable.');
      }
      sse.close();
      setStreaming(false);
    });

    return () => {
      sse.close();
    };
  }, [streaming, appliedFql]);

  const check = validateFqlQuery(fql);

  return (
    <div className="space-y-4">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Radio className={`w-4 h-4 ${streaming ? 'text-emerald-400' : 'text-slate-500'}`} />
          <span className="text-xs font-mono text-white">
            {streaming ? `STREAMING (${fps} flows/s)` : 'PAUSED'} · Buffer: {flows.length}/300
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2 flex-1 max-w-2xl">
          <FqlInputBar
            value={fql}
            onChange={setFql}
            onSubmit={() => {
              if (check.valid) setAppliedFql(fql);
            }}
            placeholder="Server-side FQL stream filter (e.g. dst_port=443)"
          />
          <button
            type="button"
            disabled={!check.valid}
            onClick={() => setAppliedFql(fql)}
            className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white text-xs font-medium"
          >
            Apply Filter
          </button>
          <button
            type="button"
            onClick={() => setStreaming((s) => !s)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 ${
              streaming ? 'bg-amber-600 hover:bg-amber-500 text-white' : 'bg-emerald-600 hover:bg-emerald-500 text-white'
            }`}
          >
            {streaming ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            {streaming ? 'Pause' : 'Resume'}
          </button>
          <button
            type="button"
            onClick={() => setFlows([])}
            className="px-2.5 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-xs text-slate-300 flex items-center gap-1"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Clear
          </button>
        </div>
      </div>

      {streamErr && (
        <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-xs text-amber-200">
          {streamErr}
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto max-h-[540px]">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono border-b border-slate-800 sticky top-0">
              <tr>
                <th className="px-3 py-2">Timestamp</th>
                <th className="px-3 py-2">Ver</th>
                <th className="px-3 py-2">Exporter</th>
                <th className="px-3 py-2">Source</th>
                <th className="px-3 py-2">Destination</th>
                <th className="px-3 py-2">App / Proto</th>
                <th className="px-3 py-2">Bytes / Rate</th>
                <th className="px-3 py-2">Dir / PCAP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {flows.map((f, i) => (
                <tr key={`${f.id}-${i}`} className="hover:bg-slate-800/40 text-slate-200">
                  <td className="px-3 py-1.5 text-slate-400 whitespace-nowrap">
                    {new Date(f.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="px-3 py-1.5 text-sky-300 uppercase text-[10px]">{f.version}</td>
                  <td className="px-3 py-1.5 text-slate-400">{f.exporterName || f.exporterIp}</td>
                  <td className="px-3 py-1.5 whitespace-nowrap">
                    {f.srcIp}:{f.srcPort}
                  </td>
                  <td className="px-3 py-1.5 whitespace-nowrap">
                    {f.dstIp}:{f.dstPort}
                  </td>
                  <td className="px-3 py-1.5 text-cyan-300">{f.appName || f.protocolName}</td>
                  <td className="px-3 py-1.5 text-emerald-300 whitespace-nowrap">
                    {formatBytes(f.bytes)} ({formatBps(f.bps)})
                  </td>
                  <td className="px-3 py-1.5 text-slate-400 flex items-center gap-2">
                    <span>{f.direction || '-'}</span>
                    <Link
                      href={`/diagnostics/packet-capture?bpf=${encodeURIComponent(buildTcpdumpFilter(f))}&iface=${encodeURIComponent(f.inIfName || 'any')}`}
                      title="Open in Live Packet Capture"
                      className="text-emerald-300 hover:text-emerald-200"
                    >
                      <Binary className="w-3.5 h-3.5" />
                    </Link>
                  </td>
                </tr>
              ))}
              {flows.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-10 text-center text-slate-500">
                    Waiting for incoming NetFlow / IPFIX / sFlow datagrams...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
