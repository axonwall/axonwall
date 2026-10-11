'use client';

import { useState } from 'react';
import {
  Binary,
  Play,
  Download,
  Filter,
  RefreshCw,
  Search,
  CheckCircle2,
  AlertCircle,
  Network,
  Clock,
  Layers,
  FileCode,
  Shield,
  ChevronRight,
  ChevronDown
} from 'lucide-react';
import { startPacketCapture, type CaptureResult, type CapturedPacket } from '@/server/agent';

const BPF_PRESETS = [
  { label: 'All Traffic', filter: '' },
  { label: 'DNS (Port 53)', filter: 'port 53' },
  { label: 'HTTPS / TLS (Port 443)', filter: 'tcp port 443' },
  { label: 'WireGuard (Port 51820)', filter: 'udp port 51820' },
  { label: 'ICMP (Ping/Traceroute)', filter: 'icmp' },
  { label: 'SSH (Port 22)', filter: 'tcp port 22' },
];

export default function PacketCapturePage() {
  const [iface, setIface] = useState('any');
  const [filter, setFilter] = useState('');
  const [count, setCount] = useState(50);
  const [isCapturing, setIsCapturing] = useState(false);
  const [result, setResult] = useState<CaptureResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Table filtering and inspection
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedProto, setSelectedProto] = useState('ALL');
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  async function handleStartCapture() {
    setIsCapturing(true);
    setError(null);
    try {
      const res = await startPacketCapture(iface, filter, count);
      setResult(res);
    } catch (err: any) {
      setError(err?.message || 'Failed to execute packet capture');
    } finally {
      setIsCapturing(false);
    }
  }

  const filteredPackets = (result?.packets || []).filter((pkt) => {
    if (selectedProto !== 'ALL') {
      if (selectedProto === 'DNS' && pkt.protocol !== 'DNS') return false;
      if (selectedProto === 'TLS' && !pkt.protocol.includes('TLS')) return false;
      if (selectedProto === 'TCP' && pkt.protocol !== 'TCP') return false;
      if (selectedProto === 'UDP' && pkt.protocol !== 'UDP') return false;
      if (selectedProto === 'ICMP' && pkt.protocol !== 'ICMP') return false;
      if (selectedProto === 'WireGuard' && pkt.protocol !== 'WireGuard') return false;
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        pkt.srcIp.toLowerCase().includes(q) ||
        pkt.dstIp.toLowerCase().includes(q) ||
        pkt.srcPort.toLowerCase().includes(q) ||
        pkt.dstPort.toLowerCase().includes(q) ||
        pkt.protocol.toLowerCase().includes(q) ||
        pkt.info.toLowerCase().includes(q);
      if (!match) return false;
    }

    return true;
  });

  const getProtoBadge = (proto: string) => {
    if (proto === 'DNS') {
      return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-sky-950 text-sky-400 border border-sky-800">DNS</span>;
    }
    if (proto.includes('TLS')) {
      return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800">TLS 1.3</span>;
    }
    if (proto === 'HTTP') {
      return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-950 text-amber-400 border border-amber-800">HTTP</span>;
    }
    if (proto === 'WireGuard') {
      return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-indigo-950 text-indigo-400 border border-indigo-800">WireGuard</span>;
    }
    if (proto === 'ICMP') {
      return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-950 text-rose-400 border border-rose-800">ICMP</span>;
    }
    if (proto === 'SSH') {
      return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-cyan-950 text-cyan-400 border border-cyan-800">SSH</span>;
    }
    if (proto === 'TCP') {
      return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-purple-950 text-purple-400 border border-purple-800">TCP</span>;
    }
    return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">{proto}</span>;
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Binary className="w-5 h-5" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-white">Live Packet Capture</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Real-time bounded packet sniffer with multi-protocol frame dissection and direct PCAP export for Wireshark inspection.
          </p>
        </div>

        {result && (
          <a
            href={`/api/diagnostics/packet-capture/download?id=${result.id}`}
            download={`${result.id}.pcap`}
            className="inline-flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-white text-sm font-medium px-4 py-2 rounded-lg border border-slate-700 transition"
          >
            <Download className="w-4 h-4 text-emerald-400" />
            <span>Export .pcap</span>
          </a>
        )}
      </div>

      {/* Capture Configuration Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
              Interface
            </label>
            <select
              value={iface}
              onChange={(e) => setIface(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
            >
              <option value="any">any (All Active Interfaces)</option>
              <option value="eth0">eth0 (WAN Gateway)</option>
              <option value="eth1">eth1 (LAN Primary)</option>
              <option value="wg0">wg0 (WireGuard Site-to-Site)</option>
              <option value="lo">lo (Loopback Internal)</option>
            </select>
          </div>

          <div className="md:col-span-2">
            <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
              BPF Filter Expression (Berkeley Packet Filter)
            </label>
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="e.g. host 192.168.100.50 or port 53 or icmp"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500 font-mono"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
              Max Frame Count
            </label>
            <select
              value={count}
              onChange={(e) => setCount(Number(e.target.value))}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
            >
              <option value={25}>25 frames</option>
              <option value={50}>50 frames (Recommended)</option>
              <option value={100}>100 frames</option>
              <option value={200}>200 frames (Deep Audit)</option>
            </select>
          </div>
        </div>

        {/* Quick Filter Presets */}
        <div>
          <span className="text-xs font-medium text-slate-400 mr-2">Quick Presets:</span>
          <div className="inline-flex flex-wrap gap-1.5 mt-1 sm:mt-0">
            {BPF_PRESETS.map((p) => (
              <button
                key={p.label}
                type="button"
                onClick={() => setFilter(p.filter)}
                className={`text-xs px-2.5 py-1 rounded-md transition border ${
                  filter === p.filter
                    ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 font-medium'
                    : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-white hover:border-slate-700'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* Action Button */}
        <div className="pt-2 flex items-center justify-between border-t border-slate-800/80">
          <button
            type="button"
            onClick={handleStartCapture}
            disabled={isCapturing}
            className="bg-emerald-600 hover:bg-emerald-500 text-white px-5 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 transition cursor-pointer disabled:opacity-50"
          >
            {isCapturing ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-white" />
                <span>Capturing wire frames (tcpdump)...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Start Live Capture</span>
              </>
            )}
          </button>

          {result && (
            <span className="text-xs font-mono text-slate-400">
              Captured {result.packetCount} frames on <span className="text-emerald-400">{result.interface}</span>
            </span>
          )}
        </div>
      </div>

      {/* Error message */}
      {error && (
        <div className="bg-rose-500/10 border border-rose-500/30 rounded-xl p-4 flex items-center gap-3 text-rose-300 text-sm">
          <AlertCircle className="w-5 h-5 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="space-y-4">
          {/* Metadata bar */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 text-xs">
            <div className="flex items-center gap-6">
              <div>
                <span className="text-slate-500 block uppercase font-semibold text-[10px]">Session ID</span>
                <span className="text-slate-200 font-mono font-medium">{result.id}</span>
              </div>
              <div>
                <span className="text-slate-500 block uppercase font-semibold text-[10px]">Active Filter</span>
                <span className="text-emerald-400 font-mono">{result.filter || '(all frames)'}</span>
              </div>
              <div>
                <span className="text-slate-500 block uppercase font-semibold text-[10px]">Completed At</span>
                <span className="text-slate-300 font-mono">{new Date(result.completedAt).toLocaleTimeString()}</span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <a
                href={`/api/diagnostics/packet-capture/download?id=${result.id}`}
                download={`${result.id}.pcap`}
                className="bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition font-medium"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download .pcap ({result.packetCount} pkts)</span>
              </a>
            </div>
          </div>

          {/* Filter / Search Bar */}
          <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search IP, port, info payload..."
                className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
              />
            </div>

            <div className="flex items-center gap-1 overflow-x-auto w-full sm:w-auto pb-1 sm:pb-0">
              {['ALL', 'DNS', 'TLS', 'TCP', 'UDP', 'ICMP', 'WireGuard'].map((proto) => (
                <button
                  key={proto}
                  type="button"
                  onClick={() => setSelectedProto(proto)}
                  className={`text-xs px-2.5 py-1 rounded-md border transition ${
                    selectedProto === proto
                      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 font-medium'
                      : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white'
                  }`}
                >
                  {proto}
                </button>
              ))}
            </div>
          </div>

          {/* Packet Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-slate-950/60 text-slate-400 uppercase font-semibold text-[10px] tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3 w-12 text-center">#</th>
                    <th className="py-2.5 px-3 w-28">Timestamp</th>
                    <th className="py-2.5 px-3 w-48">Source</th>
                    <th className="py-2.5 px-3 w-48">Destination</th>
                    <th className="py-2.5 px-3 w-28">Protocol</th>
                    <th className="py-2.5 px-3 w-20 text-right">Length</th>
                    <th className="py-2.5 px-4">Frame Info / Dissection</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {filteredPackets.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                        No packets matched the current filter criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredPackets.map((pkt) => {
                      const isExpanded = expandedRow === pkt.index;
                      return (
                        <tr
                          key={pkt.index}
                          onClick={() => setExpandedRow(isExpanded ? null : pkt.index)}
                          className="hover:bg-slate-800/40 transition cursor-pointer"
                        >
                          <td className="py-2 px-3 text-center text-slate-500 text-[11px]">
                            {pkt.index}
                          </td>
                          <td className="py-2 px-3 text-slate-400 text-[11px]">
                            {pkt.timestamp}
                          </td>
                          <td className="py-2 px-3 text-slate-200">
                            {pkt.srcIp}{pkt.srcPort !== '-' && <span className="text-slate-500">:{pkt.srcPort}</span>}
                          </td>
                          <td className="py-2 px-3 text-slate-200">
                            {pkt.dstIp}{pkt.dstPort !== '-' && <span className="text-slate-500">:{pkt.dstPort}</span>}
                          </td>
                          <td className="py-2 px-3">
                            {getProtoBadge(pkt.protocol)}
                          </td>
                          <td className="py-2 px-3 text-right text-slate-400">
                            {pkt.length} B
                          </td>
                          <td className="py-2 px-4 text-slate-300 truncate max-w-md font-sans">
                            <div className="flex items-center justify-between">
                              <span className="truncate">{pkt.info}</span>
                              {isExpanded ? (
                                <ChevronDown className="w-3.5 h-3.5 text-slate-500 shrink-0 ml-2" />
                              ) : (
                                <ChevronRight className="w-3.5 h-3.5 text-slate-500 shrink-0 ml-2" />
                              )}
                            </div>
                            {isExpanded && (
                              <div className="mt-2 p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono space-y-1 text-slate-300">
                                <div><strong className="text-slate-500">Frame #:</strong> {pkt.index}</div>
                                <div><strong className="text-slate-500">Arrival Time:</strong> {pkt.timestamp}</div>
                                <div><strong className="text-slate-500">IP Flow:</strong> {pkt.srcIp}:{pkt.srcPort} &rarr; {pkt.dstIp}:{pkt.dstPort}</div>
                                <div><strong className="text-slate-500">Protocol:</strong> {pkt.protocol}</div>
                                <div><strong className="text-slate-500">Frame Length:</strong> {pkt.length} bytes</div>
                                <div><strong className="text-slate-500">Dissected Payload:</strong> {pkt.info}</div>
                              </div>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
