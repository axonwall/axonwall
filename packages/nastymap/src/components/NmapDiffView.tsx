import React, { useState } from 'react';
import type { NmapRun, NmapScanDiff } from '../types/nmap';
import { compareNmapScans } from '../diff/scan-diff';
import { SAMPLE_SCANS } from '../data/sample-scans';
import { parseNmapXml } from '../parser/nmap-xml-parser';
import {
  GitCompare,
  PlusCircle,
  MinusCircle,
  AlertCircle,
  CheckCircle,
  ArrowRight,
  ShieldAlert,
  Server,
  Activity,
  Layers,
  Sparkles,
} from 'lucide-react';

export interface NmapDiffViewProps {
  scanA?: NmapRun;
  scanB?: NmapRun;
  className?: string;
}

export function NmapDiffView({ scanA: propScanA, scanB: propScanB, className = '' }: NmapDiffViewProps) {
  // Default to sample breach diff if not provided
  const [scanA, setScanA] = useState<NmapRun>(
    propScanA || parseNmapXml(SAMPLE_SCANS.breachDiff.xmlA)
  );
  const [scanB, setScanB] = useState<NmapRun>(
    propScanB || parseNmapXml(SAMPLE_SCANS.breachDiff.xmlB)
  );
  const [filterMode, setFilterMode] = useState<'all' | 'added' | 'removed' | 'modified'>('all');

  const diffResult: NmapScanDiff = compareNmapScans(scanA, scanB);
  const { summary, addedHosts, removedHosts, modifiedHosts, unchangedHosts } = diffResult;

  const handleLoadSampleBreach = () => {
    setScanA(parseNmapXml(SAMPLE_SCANS.breachDiff.xmlA));
    setScanB(parseNmapXml(SAMPLE_SCANS.breachDiff.xmlB));
  };

  const handleUploadA = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        setScanA(parseNmapXml(event.target?.result as string));
      } catch (err: any) {
        alert(`Failed to parse Scan A: ${err.message}`);
      }
    };
    reader.readAsText(file);
  };

  const handleUploadB = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        setScanB(parseNmapXml(event.target?.result as string));
      } catch (err: any) {
        alert(`Failed to parse Scan B: ${err.message}`);
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* 1. Header & Scan Selector */}
      <div className="p-5 rounded-2xl bg-zinc-950/90 border border-zinc-800/80 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <GitCompare size={20} className="text-sky-400" />
              <span>Nmap Scan Comparison & Diff Engine</span>
            </h3>
            <p className="text-xs text-zinc-400 mt-1">
              Compare baseline vs new scan to identify unauthorized hosts, opened backdoors, and service modifications.
            </p>
          </div>

          <button
            onClick={handleLoadSampleBreach}
            className="px-3.5 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-xs font-semibold text-zinc-200 flex items-center gap-1.5 transition-colors self-start sm:self-auto"
          >
            <Sparkles size={14} className="text-amber-400" />
            <span>Load Sample Incident Diff</span>
          </button>
        </div>

        {/* Scan Selection inputs */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-zinc-800/80">
          <div className="p-3.5 rounded-xl bg-zinc-900/60 border border-zinc-800 flex items-center justify-between">
            <div>
              <span className="text-[10px] font-bold text-sky-400 uppercase tracking-wider block">
                Scan A (Baseline / Before)
              </span>
              <span className="text-xs font-mono text-white font-semibold">
                {scanA.hosts.length} Hosts · {scanA.startstr}
              </span>
            </div>
            <label className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs cursor-pointer border border-zinc-700">
              Change A
              <input type="file" onChange={handleUploadA} accept=".xml" className="hidden" />
            </label>
          </div>

          <div className="p-3.5 rounded-xl bg-zinc-900/60 border border-zinc-800 flex items-center justify-between">
            <div>
              <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider block">
                Scan B (Current / After)
              </span>
              <span className="text-xs font-mono text-white font-semibold">
                {scanB.hosts.length} Hosts · {scanB.startstr}
              </span>
            </div>
            <label className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs cursor-pointer border border-zinc-700">
              Change B
              <input type="file" onChange={handleUploadB} accept=".xml" className="hidden" />
            </label>
          </div>
        </div>
      </div>

      {/* 2. Summary Metric Badges */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
        <div
          onClick={() => setFilterMode('added')}
          className={`p-4 rounded-xl border cursor-pointer transition-all ${
            filterMode === 'added'
              ? 'bg-emerald-950/60 border-emerald-500 shadow-lg'
              : 'bg-zinc-900/60 border-zinc-800/80 hover:border-emerald-500/50'
          }`}
        >
          <div className="flex items-center justify-between text-xs text-emerald-400 mb-1">
            <span className="font-semibold">New Hosts Added</span>
            <PlusCircle size={15} />
          </div>
          <div className="text-2xl font-bold text-emerald-400 font-mono">+{summary.hostsAdded}</div>
          <div className="text-[11px] text-zinc-500 mt-1">Discovered in Scan B</div>
        </div>

        <div
          onClick={() => setFilterMode('removed')}
          className={`p-4 rounded-xl border cursor-pointer transition-all ${
            filterMode === 'removed'
              ? 'bg-rose-950/60 border-rose-500 shadow-lg'
              : 'bg-zinc-900/60 border-zinc-800/80 hover:border-rose-500/50'
          }`}
        >
          <div className="flex items-center justify-between text-xs text-rose-400 mb-1">
            <span className="font-semibold">Hosts Removed/Down</span>
            <MinusCircle size={15} />
          </div>
          <div className="text-2xl font-bold text-rose-400 font-mono">-{summary.hostsRemoved}</div>
          <div className="text-[11px] text-zinc-500 mt-1">Missing in Scan B</div>
        </div>

        <div
          onClick={() => setFilterMode('modified')}
          className={`p-4 rounded-xl border cursor-pointer transition-all ${
            filterMode === 'modified'
              ? 'bg-amber-950/60 border-amber-500 shadow-lg'
              : 'bg-zinc-900/60 border-zinc-800/80 hover:border-amber-500/50'
          }`}
        >
          <div className="flex items-center justify-between text-xs text-amber-400 mb-1">
            <span className="font-semibold">Hosts Modified</span>
            <AlertCircle size={15} />
          </div>
          <div className="text-2xl font-bold text-amber-400 font-mono">~{summary.hostsModified}</div>
          <div className="text-[11px] text-zinc-500 mt-1">Port/State/OS changes</div>
        </div>

        <div
          onClick={() => setFilterMode('all')}
          className={`p-4 rounded-xl border cursor-pointer transition-all ${
            filterMode === 'all'
              ? 'bg-sky-950/60 border-sky-500 shadow-lg'
              : 'bg-zinc-900/60 border-zinc-800/80 hover:border-sky-500/50'
          }`}
        >
          <div className="flex items-center justify-between text-xs text-sky-400 mb-1">
            <span className="font-semibold">Port Level Changes</span>
            <Layers size={15} />
          </div>
          <div className="text-2xl font-bold text-white font-mono">
            <span className="text-emerald-400">+{summary.portsAdded}</span> / <span className="text-rose-400">-{summary.portsRemoved}</span>
          </div>
          <div className="text-[11px] text-zinc-500 mt-1">{summary.portsModified} modified ports</div>
        </div>
      </div>

      {/* 3. Detailed Changelog Cards */}
      <div className="space-y-3.5">
        <h4 className="text-xs font-bold uppercase tracking-wider text-zinc-400 flex items-center justify-between">
          <span>Security Diff Changelog</span>
          <span className="text-zinc-500 font-normal">
            Showing: {filterMode.toUpperCase()}
          </span>
        </h4>

        {/* Added Hosts */}
        {(filterMode === 'all' || filterMode === 'added') &&
          addedHosts.map((host) => (
            <div
              key={`added-${host.ip}`}
              className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-800/50 space-y-2 hover:border-emerald-700 transition-colors"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <PlusCircle size={16} className="text-emerald-400" />
                  <span className="font-mono font-bold text-emerald-300 text-sm">{host.ip}</span>
                  {host.hostname && (
                    <span className="text-xs text-zinc-300 font-sans">({host.hostname})</span>
                  )}
                </div>
                <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 font-mono text-[10px] font-bold uppercase border border-emerald-800">
                  NEW HOST ADDED
                </span>
              </div>
              {host.newOs && (
                <p className="text-xs text-zinc-400 font-sans">Detected OS: <span className="text-white font-medium">{host.newOs}</span></p>
              )}
              {host.portDiffs.length > 0 && (
                <div className="pt-2 border-t border-emerald-900/40 space-y-1">
                  <span className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider block">
                    Discovered Open Ports:
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {host.portDiffs.map((p) => (
                      <span
                        key={p.portid}
                        className="px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 text-xs font-mono border border-emerald-800/60"
                      >
                        +{p.portid}/{p.protocol} ({p.newPort?.service?.name || 'unknown'}{p.newPort?.service?.extrainfo && ` - ${p.newPort.service.extrainfo}`})
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}

        {/* Removed Hosts */}
        {(filterMode === 'all' || filterMode === 'removed') &&
          removedHosts.map((host) => (
            <div
              key={`removed-${host.ip}`}
              className="p-4 rounded-xl bg-rose-950/20 border border-rose-800/50 space-y-2 hover:border-rose-700 transition-colors"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <MinusCircle size={16} className="text-rose-400" />
                  <span className="font-mono font-bold text-rose-300 text-sm">{host.ip}</span>
                  {host.hostname && (
                    <span className="text-xs text-zinc-300 font-sans">({host.hostname})</span>
                  )}
                </div>
                <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-400 font-mono text-[10px] font-bold uppercase border border-rose-800">
                  HOST NO LONGER RESPONSIVE
                </span>
              </div>
              <p className="text-xs text-zinc-400">Host was present in Scan A but did not respond in Scan B.</p>
            </div>
          ))}

        {/* Modified Hosts */}
        {(filterMode === 'all' || filterMode === 'modified') &&
          modifiedHosts.map((host) => (
            <div
              key={`modified-${host.ip}`}
              className="p-4 rounded-xl bg-amber-950/20 border border-amber-800/50 space-y-2.5 hover:border-amber-700 transition-colors"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <AlertCircle size={16} className="text-amber-400" />
                  <span className="font-mono font-bold text-amber-300 text-sm">{host.ip}</span>
                  {host.hostname && (
                    <span className="text-xs text-zinc-300 font-sans">({host.hostname})</span>
                  )}
                </div>
                <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-400 font-mono text-[10px] font-bold uppercase border border-amber-800">
                  MODIFIED
                </span>
              </div>

              {/* Port Changes */}
              <div className="space-y-1.5 pt-1">
                {host.portDiffs
                  .filter((p) => p.changeType !== 'unchanged')
                  .map((p) => (
                    <div
                      key={p.portid}
                      className={`p-2 rounded text-xs font-mono flex items-center justify-between ${
                        p.changeType === 'added'
                          ? 'bg-emerald-950/50 text-emerald-300 border border-emerald-800/40'
                          : p.changeType === 'removed'
                          ? 'bg-rose-950/50 text-rose-300 border border-rose-800/40'
                          : 'bg-amber-950/50 text-amber-300 border border-amber-800/40'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <span className="font-bold">
                          {p.changeType === 'added' ? '+' : p.changeType === 'removed' ? '-' : '~'} {p.portid}/{p.protocol}
                        </span>
                        <span>
                          {p.newPort?.service?.name || p.oldPort?.service?.name || 'unknown'}
                        </span>
                        {(p.newPort?.service?.extrainfo || p.oldPort?.service?.extrainfo) && (
                          <span className="text-[11px] opacity-80">
                            ({p.newPort?.service?.extrainfo || p.oldPort?.service?.extrainfo})
                          </span>
                        )}
                      </div>
                      <span className="text-[10px] uppercase font-bold tracking-wider">
                        PORT {p.changeType}
                      </span>
                    </div>
                  ))}
              </div>

              {host.latencyDeltaMs !== undefined && Math.abs(host.latencyDeltaMs) > 0 && (
                <p className="text-[11px] text-zinc-400 font-mono pt-1">
                  Latency shift: <span className={host.latencyDeltaMs > 0 ? 'text-rose-400' : 'text-emerald-400'}>
                    {host.latencyDeltaMs > 0 ? `+${host.latencyDeltaMs}ms (slower)` : `${host.latencyDeltaMs}ms (faster)`}
                  </span>
                </p>
              )}
            </div>
          ))}

        {addedHosts.length === 0 && removedHosts.length === 0 && modifiedHosts.length === 0 && (
          <div className="p-8 text-center text-zinc-500 bg-zinc-900/30 rounded-xl border border-zinc-800">
            <CheckCircle size={32} className="mx-auto text-emerald-400 mb-2 opacity-70" />
            <p className="text-sm font-semibold text-zinc-300">Scans are identical!</p>
            <p className="text-xs text-zinc-500 mt-0.5">No changes in hosts, ports, or OS versions detected.</p>
          </div>
        )}
      </div>
    </div>
  );
}
