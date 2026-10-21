import React, { useState } from 'react';
import type { NmapRun } from '../types/nmap';
import { Terminal, Copy, Check, Info, Calendar, Clock, Activity, Shield } from 'lucide-react';

export interface NmapCommandViewerProps {
  scan: NmapRun;
  className?: string;
}

const FLAG_EXPLANATIONS: Record<string, string> = {
  '-sS': 'SYN Stealth Scan (TCP half-open)',
  '-sT': 'TCP Connect Scan',
  '-sU': 'UDP Scan',
  '-sV': 'Version Detection (Probe open ports to determine service/version info)',
  '-O': 'Enable OS Detection',
  '-A': 'Aggressive Scan (Enables OS detection, version detection, script scanning, and traceroute)',
  '--traceroute': 'Trace hop path to each target host',
  '-T4': 'Timing Template: Aggressive (Speed up scan on reliable networks)',
  '-T5': 'Timing Template: Insane (Very fast scan)',
  '-T3': 'Timing Template: Normal',
  '-p': 'Port Specification (Scan specific ports or port ranges)',
  '-Pn': 'Treat all hosts as online (Skip host discovery)',
  '-sn': 'Ping Scan (Host discovery only, disable port scan)',
  '-v': 'Increase Verbosity Level',
  '-vv': 'High Verbosity Level',
  '-sC': 'Equivalent to --script=default',
};

export function NmapCommandViewer({ scan, className = '' }: NmapCommandViewerProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (typeof navigator !== 'undefined') {
      navigator.clipboard.writeText(scan.args);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  // Extract flags from scan.args
  const tokens = scan.args.split(/\s+/);
  const recognizedFlags = tokens.map((token) => {
    const clean = token.trim();
    return {
      token: clean,
      desc: FLAG_EXPLANATIONS[clean] || (clean.startsWith('-') ? 'Nmap Command Flag' : 'Target Specifier / Range'),
      isFlag: clean.startsWith('-'),
    };
  });

  return (
    <div className={`p-4 rounded-xl bg-zinc-950/80 border border-zinc-800/80 space-y-3.5 ${className}`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-zinc-400">
          <Terminal size={14} className="text-sky-400" />
          <span>Executed Nmap Command</span>
        </div>
        <button
          onClick={handleCopy}
          className="px-2.5 py-1 rounded bg-zinc-900 hover:bg-zinc-800 text-zinc-300 hover:text-white text-xs font-mono flex items-center gap-1.5 border border-zinc-800 transition-colors"
        >
          {copied ? (
            <>
              <Check size={12} className="text-emerald-400" />
              <span className="text-emerald-400">Copied</span>
            </>
          ) : (
            <>
              <Copy size={12} />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>

      {/* Raw Command Box */}
      <div className="p-3 rounded-lg bg-black/60 border border-zinc-800/90 font-mono text-xs text-sky-300 flex items-center gap-2 overflow-x-auto select-all">
        <span className="text-emerald-400 font-bold select-none">$</span>
        <span>{scan.args}</span>
      </div>

      {/* Token Explanations */}
      <div className="flex flex-wrap gap-1.5 pt-1">
        {recognizedFlags.map((flag, idx) => (
          <div
            key={idx}
            className={`px-2 py-1 rounded text-[11px] font-mono flex items-center gap-1.5 border ${
              flag.isFlag
                ? 'bg-sky-950/40 text-sky-300 border-sky-800/40'
                : 'bg-zinc-900 text-zinc-300 border-zinc-800'
            }`}
            title={flag.desc}
          >
            <span className="font-bold">{flag.token}</span>
            <span className="text-[10px] text-zinc-400 font-sans border-l border-zinc-700/60 pl-1.5 hidden sm:inline">
              {flag.desc}
            </span>
          </div>
        ))}
      </div>

      {/* Scan Metadata Footer */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-zinc-800/60 text-[11px] text-zinc-400">
        <div className="flex items-center gap-1.5">
          <Calendar size={12} className="text-zinc-500" />
          <span>{scan.startstr}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Clock size={12} className="text-zinc-500" />
          <span>{scan.runstats?.finished.elapsed ? `${scan.runstats.finished.elapsed}s elapsed` : 'Active'}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Shield size={12} className="text-zinc-500" />
          <span>Nmap v{scan.version}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Activity size={12} className="text-zinc-500" />
          <span>{scan.hosts.length} Targets Scanned</span>
        </div>
      </div>
    </div>
  );
}
