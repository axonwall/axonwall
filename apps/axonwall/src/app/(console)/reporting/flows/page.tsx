'use client';

import { useState, useEffect, useRef } from 'react';
import {
  Activity,
  Play,
  Pause,
  Filter,
  Trash2,
  Download,
  Wifi,
  Radio,
  Layers,
  Search,
  Maximize2,
} from 'lucide-react';

interface StreamPacket {
  index: number;
  timestamp: string;
  srcIp: string;
  srcPort: string;
  dstIp: string;
  dstPort: string;
  protocol: string;
  length: number;
  info: string;
}

export default function FlowsDashboardPage() {
  const [isStreaming, setIsStreaming] = useState(true);
  const [selectedIface, setSelectedIface] = useState('any');
  const [selectedProto, setSelectedProto] = useState('any');
  const [searchFilter, setSearchFilter] = useState('');
  const [packets, setPackets] = useState<StreamPacket[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<StreamPacket | null>(null);
  const [packetsPerSec, setPacketsPerSec] = useState(0);

  const eventSourceRef = useRef<EventSource | null>(null);
  const ppsCounterRef = useRef(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setPacketsPerSec(ppsCounterRef.current);
      ppsCounterRef.current = 0;
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!isStreaming) {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      return;
    }

    const query = new URLSearchParams();
    if (selectedIface !== 'any') query.set('interface', selectedIface);
    if (selectedProto !== 'any') query.set('protocol', selectedProto);

    const sse = new EventSource(`/api/v1/events/packets?${query.toString()}`);
    eventSourceRef.current = sse;

    sse.addEventListener('packet', (event) => {
      try {
        const pkt = JSON.parse(event.data) as StreamPacket;
        ppsCounterRef.current++;
        setPackets((prev) => [pkt, ...prev.slice(0, 199)]);
      } catch {}
    });

    sse.onerror = () => {
      // EventSource automatically retries
    };

    return () => {
      sse.close();
    };
  }, [isStreaming, selectedIface, selectedProto]);

  const filteredPackets = packets.filter((p) => {
    if (!searchFilter) return true;
    const q = searchFilter.toLowerCase();
    return (
      p.srcIp.toLowerCase().includes(q) ||
      p.dstIp.toLowerCase().includes(q) ||
      p.info.toLowerCase().includes(q) ||
      p.protocol.toLowerCase().includes(q)
    );
  });

  const handleClear = () => {
    setPackets([]);
    setSelectedPacket(null);
  };

  const handleExportCsv = () => {
    if (packets.length === 0) return;
    const header = 'Index,Timestamp,Protocol,SourceIP,SourcePort,DestinationIP,DestinationPort,Length,Info\n';
    const rows = packets
      .map(
        (p) =>
          `"${p.index}","${p.timestamp}","${p.protocol}","${p.srcIp}","${p.srcPort}","${p.dstIp}","${p.dstPort}","${p.length}","${p.info.replace(/"/g, '""')}"`
      )
      .join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `axonwall-packet-trace-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <Radio className="w-6 h-6 text-emerald-400" />
            <span>Live Flow Observability & Packet Tracing</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time packet capture, kernel-level eBPF connection telemetry, and protocol dissection.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setIsStreaming(!isStreaming)}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer ${
              isStreaming
                ? 'bg-amber-600 hover:bg-amber-500 text-white'
                : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow'
            }`}
          >
            {isStreaming ? (
              <>
                <Pause className="w-3.5 h-3.5" />
                <span>Pause Stream</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Resume Stream</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={handleClear}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition flex items-center gap-1.5 border border-slate-700 font-medium cursor-pointer"
          >
            <Trash2 className="w-3.5 h-3.5 text-slate-400" />
            <span>Clear</span>
          </button>

          <button
            type="button"
            onClick={handleExportCsv}
            disabled={packets.length === 0}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-xs text-slate-300 transition flex items-center gap-1.5 border border-slate-700 font-medium cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Metrics Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider block">
            Stream Status
          </span>
          <div className="flex items-center gap-2 mt-1">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                isStreaming ? 'bg-emerald-500 animate-pulse' : 'bg-slate-600'
              }`}
            />
            <span className="text-base font-bold font-mono text-white">
              {isStreaming ? 'LIVE (NFLOG/eBPF)' : 'PAUSED'}
            </span>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider block">
            Packet Velocity
          </span>
          <span className="text-2xl font-bold font-mono text-emerald-400 mt-1 block">
            {packetsPerSec} <span className="text-xs text-slate-500 font-sans">pkt/sec</span>
          </span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider block">
            Captured in Ring Buffer
          </span>
          <span className="text-2xl font-bold font-mono text-cyan-400 mt-1 block">
            {packets.length} <span className="text-xs text-slate-500 font-sans">packets</span>
          </span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider block">
            Active Filter
          </span>
          <span className="text-base font-bold font-mono text-white mt-1 block truncate">
            {selectedIface} / {selectedProto}
          </span>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-500" />
          <span className="text-xs font-medium text-slate-300">Interface:</span>
          <select
            value={selectedIface}
            onChange={(e) => setSelectedIface(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-xs text-white focus:outline-none focus:border-emerald-500 font-mono"
          >
            <option value="any">any</option>
            <option value="eth0">eth0 (WAN)</option>
            <option value="eth1">eth1 (LAN)</option>
            <option value="wg0">wg0 (VPN)</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-slate-300">Protocol:</span>
          <select
            value={selectedProto}
            onChange={(e) => setSelectedProto(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-xs text-white focus:outline-none focus:border-emerald-500 font-mono"
          >
            <option value="any">any</option>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="icmp">ICMP</option>
            <option value="dns">DNS</option>
            <option value="tls">TLS/HTTPS</option>
          </select>
        </div>

        <div className="flex-1 min-w-[200px] relative">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
          <input
            type="text"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            placeholder="Search IP, port, or payload info..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white focus:outline-none focus:border-emerald-500 font-mono"
          />
        </div>
      </div>

      {/* Packet Stream Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Packet Table */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto max-h-[500px]">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 uppercase font-mono sticky top-0 border-b border-slate-800">
                <tr>
                  <th className="px-3 py-2.5">Time</th>
                  <th className="px-3 py-2.5">Proto</th>
                  <th className="px-3 py-2.5">Source</th>
                  <th className="px-3 py-2.5">Destination</th>
                  <th className="px-3 py-2.5">Length</th>
                  <th className="px-3 py-2.5">Info</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filteredPackets.map((pkt) => {
                  const isSelected = selectedPacket?.index === pkt.index;
                  return (
                    <tr
                      key={pkt.index}
                      onClick={() => setSelectedPacket(pkt)}
                      className={`cursor-pointer transition ${
                        isSelected
                          ? 'bg-emerald-950/40 text-emerald-200'
                          : 'hover:bg-slate-800/50 text-slate-300'
                      }`}
                    >
                      <td className="px-3 py-2 text-slate-400 whitespace-nowrap">
                        {pkt.timestamp}
                      </td>
                      <td className="px-3 py-2">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            pkt.protocol === 'TLS'
                              ? 'bg-purple-500/20 text-purple-300'
                              : pkt.protocol === 'DNS'
                              ? 'bg-cyan-500/20 text-cyan-300'
                              : pkt.protocol === 'TCP'
                              ? 'bg-blue-500/20 text-blue-300'
                              : pkt.protocol === 'ICMP'
                              ? 'bg-amber-500/20 text-amber-300'
                              : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          {pkt.protocol}
                        </span>
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap">
                        {pkt.srcIp}:{pkt.srcPort}
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap">
                        {pkt.dstIp}:{pkt.dstPort}
                      </td>
                      <td className="px-3 py-2 text-slate-400 whitespace-nowrap">
                        {pkt.length} B
                      </td>
                      <td className="px-3 py-2 text-slate-300 truncate max-w-xs" title={pkt.info}>
                        {pkt.info}
                      </td>
                    </tr>
                  );
                })}
                {filteredPackets.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                      Waiting for incoming packet stream...
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Detailed Packet Dissector Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="text-sm font-semibold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-emerald-400" />
              <span>Packet Header Dissector</span>
            </span>
            {selectedPacket && (
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                Frame #{selectedPacket.index}
              </span>
            )}
          </div>

          {selectedPacket ? (
            <div className="space-y-4 text-xs font-mono">
              <div className="space-y-1.5 bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-[11px] font-sans font-semibold text-emerald-400 uppercase tracking-wider block">
                  Network Layer (IPv4)
                </span>
                <div className="text-slate-300 flex justify-between">
                  <span className="text-slate-500">Source:</span>
                  <span>{selectedPacket.srcIp}</span>
                </div>
                <div className="text-slate-300 flex justify-between">
                  <span className="text-slate-500">Destination:</span>
                  <span>{selectedPacket.dstIp}</span>
                </div>
                <div className="text-slate-300 flex justify-between">
                  <span className="text-slate-500">Total Length:</span>
                  <span>{selectedPacket.length} bytes</span>
                </div>
              </div>

              <div className="space-y-1.5 bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-[11px] font-sans font-semibold text-cyan-400 uppercase tracking-wider block">
                  Transport Layer ({selectedPacket.protocol})
                </span>
                <div className="text-slate-300 flex justify-between">
                  <span className="text-slate-500">Src Port:</span>
                  <span>{selectedPacket.srcPort}</span>
                </div>
                <div className="text-slate-300 flex justify-between">
                  <span className="text-slate-500">Dst Port:</span>
                  <span>{selectedPacket.dstPort}</span>
                </div>
              </div>

              <div className="space-y-1.5 bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-[11px] font-sans font-semibold text-amber-400 uppercase tracking-wider block">
                  Application / Payload Dissection
                </span>
                <p className="text-slate-300 break-words font-mono text-[11px] leading-relaxed">
                  {selectedPacket.info}
                </p>
              </div>
            </div>
          ) : (
            <div className="h-48 flex flex-col items-center justify-center text-slate-500 text-xs text-center">
              <span>Select any packet row in the stream to inspect protocol headers.</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
