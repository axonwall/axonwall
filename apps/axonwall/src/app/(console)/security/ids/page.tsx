'use client';

import { useState } from 'react';
import { ShieldAlert, Terminal, AlertTriangle, ShieldCheck, RefreshCw, CheckCircle2 } from 'lucide-react';
import { compileSuricata, type SuricataAlert } from '@axonwall/lib/compile/suricata';
import type { SuricataConfig } from '@axonwall/lib/schemas';

const SAMPLE_ALERTS: SuricataAlert[] = [
  {
    timestamp: '2026-10-05T06:10:14Z',
    gid: 1,
    sid: 2024897,
    rev: 4,
    signature: 'ET SCAN Potential SSH Brute Force Attack detected',
    category: 'Attempted Information Leak',
    severity: 1,
    srcIp: '198.51.100.88',
    srcPort: 54123,
    dstIp: '192.168.100.1',
    dstPort: 22,
    proto: 'TCP',
    action: 'blocked',
  },
  {
    timestamp: '2026-10-05T06:08:22Z',
    gid: 1,
    sid: 2013028,
    rev: 8,
    signature: 'ET POLICY Suspicious Inbound TLS Client Hello with empty SNI',
    category: 'Potential Corporate Privacy Violation',
    severity: 2,
    srcIp: '203.0.113.44',
    srcPort: 49811,
    dstIp: '192.168.100.10',
    dstPort: 443,
    proto: 'TCP',
    action: 'blocked',
  },
  {
    timestamp: '2026-10-05T06:05:01Z',
    gid: 1,
    sid: 2008983,
    rev: 12,
    signature: 'ET DNS Query for Known Dynamic DNS Domain (.duckdns.org)',
    category: 'Network Scan',
    severity: 3,
    srcIp: '192.168.100.45',
    srcPort: 61002,
    dstIp: '1.1.1.1',
    dstPort: 53,
    proto: 'UDP',
    action: 'allowed',
  },
];

export default function SuricataIdsPage() {
  const [enabled, setEnabled] = useState(true);
  const [mode, setMode] = useState<'ids' | 'ips'>('ips');
  const [nfqueueFailOpen, setNfqueueFailOpen] = useState(true);
  const [nfqueueBypass, setNfqueueBypass] = useState(true);
  const [alerts] = useState<SuricataAlert[]>(SAMPLE_ALERTS);

  const suricataConfig: SuricataConfig = {
    enabled,
    mode,
    interfaces: ['wan'],
    nfqueueFailOpen,
    nfqueueBypass,
    ruleSources: [
      {
        name: 'ET Open Ruleset',
        url: 'https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz',
        enabled: true,
      },
    ],
    homeNet: ['192.168.0.0/16', '10.0.0.0/8'],
  };

  const compiled = compileSuricata(suricataConfig);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <ShieldAlert className="w-6 h-6 text-emerald-400" />
          Suricata 7.0 Intrusion Detection & Prevention (IDS / IPS)
        </h1>
        <p className="text-sm text-slate-400">
          In-kernel deep packet inspection using Linux NFQUEUE with automatic fail-open resilience and Emerging Threats signatures.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          {/* Engine Settings */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="font-semibold text-white">Inspection Mode</h3>
                <p className="text-xs text-slate-400">Control packet action upon signature match</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={enabled}
                  onChange={(e) => setEnabled(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-600"></div>
              </label>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <button
                type="button"
                onClick={() => setMode('ips')}
                className={`p-4 rounded-xl border text-left transition ${
                  mode === 'ips'
                    ? 'border-emerald-500 bg-emerald-500/10 text-white'
                    : 'border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between font-bold text-sm">
                  <span>IPS (Inline Prevention)</span>
                  {mode === 'ips' && <span className="text-xs text-emerald-400 font-mono">Active</span>}
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Actively drops packets matching malicious signatures using NFQUEUE diversion.
                </p>
              </button>

              <button
                type="button"
                onClick={() => setMode('ids')}
                className={`p-4 rounded-xl border text-left transition ${
                  mode === 'ids'
                    ? 'border-emerald-500 bg-emerald-500/10 text-white'
                    : 'border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between font-bold text-sm">
                  <span>IDS (Passive Detection)</span>
                  {mode === 'ids' && <span className="text-xs text-emerald-400 font-mono">Active</span>}
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Passively generates alerts without disrupting flow or dropping packets.
                </p>
              </button>
            </div>

            {/* Resilience Toggles */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
              <label className="flex items-start gap-3 p-3 bg-slate-950 rounded-lg border border-slate-800 cursor-pointer">
                <input
                  type="checkbox"
                  checked={nfqueueFailOpen}
                  onChange={(e) => setNfqueueFailOpen(e.target.checked)}
                  className="rounded bg-slate-900 border-slate-700 text-emerald-600 focus:ring-emerald-500 mt-1"
                />
                <div>
                  <span className="text-xs font-semibold text-white block">NFQUEUE Fail-Open</span>
                  <span className="text-[11px] text-slate-400">
                    If Suricata crashes, kernel automatically allows traffic to avoid outages.
                  </span>
                </div>
              </label>

              <label className="flex items-start gap-3 p-3 bg-slate-950 rounded-lg border border-slate-800 cursor-pointer">
                <input
                  type="checkbox"
                  checked={nfqueueBypass}
                  onChange={(e) => setNfqueueBypass(e.target.checked)}
                  className="rounded bg-slate-900 border-slate-700 text-emerald-600 focus:ring-emerald-500 mt-1"
                />
                <div>
                  <span className="text-xs font-semibold text-white block">NFQUEUE Bypass</span>
                  <span className="text-[11px] text-slate-400">
                    Bypasses inspection on extreme load spikes to prevent buffer congestion.
                  </span>
                </div>
              </label>
            </div>
          </div>

          {/* Live Alerts Feed */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center">
              <div>
                <h3 className="font-semibold text-white flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  Live EVE JSON Security Events
                </h3>
                <p className="text-xs text-slate-400">Parsed real-time alerts from /var/log/suricata/eve.json</p>
              </div>
              <button
                type="button"
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 flex items-center gap-1.5 border border-slate-700"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Refresh Alerts
              </button>
            </div>

            <table className="w-full text-sm text-left">
              <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Signature Name</th>
                  <th className="px-4 py-3">Category</th>
                  <th className="px-4 py-3">Source ➔ Destination</th>
                  <th className="px-4 py-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {alerts.map((a, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono ${
                          a.severity === 1
                            ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                            : a.severity === 2
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                            : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                        }`}
                      >
                        {a.severity === 1 ? 'HIGH (1)' : a.severity === 2 ? 'MED (2)' : 'LOW (3)'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-semibold text-white text-xs block">{a.signature}</span>
                      <span className="text-[10px] text-slate-500 font-mono">SID {a.sid}</span>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">{a.category}</td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-300">
                      {a.srcIp}:{a.srcPort} ➔ {a.dstIp}:{a.dstPort}
                    </td>
                    <td className="px-4 py-3">
                      {a.action === 'blocked' ? (
                        <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 text-xs font-mono font-bold border border-red-500/20">
                          BLOCKED
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-xs font-mono font-bold border border-emerald-500/20">
                          ALLOWED
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right 1 Col: Live Suricata Config Preview */}
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col h-full">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                <Terminal className="w-4 h-4 text-emerald-400" />
                Rendered suricata.yaml
              </div>
              <span className="text-[10px] text-emerald-400 font-mono">Suricata 7</span>
            </div>
            <pre className="mt-3 p-3 bg-slate-950 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap flex-1 border border-slate-900">
              {compiled.suricataYaml}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
