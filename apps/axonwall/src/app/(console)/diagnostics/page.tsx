'use client';

import { useState } from 'react';
import { Terminal, Play, CheckCircle2, AlertCircle } from 'lucide-react';
import { runDiagnostic } from '../../../server/agent';

export default function DiagnosticsPage() {
  const [tool, setTool] = useState<'ping' | 'port_probe'>('ping');
  const [target, setTarget] = useState('1.1.1.1');
  const [port, setPort] = useState(80);
  const [output, setOutput] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  async function handleRun() {
    setIsRunning(true);
    setOutput('Executing test...');
    try {
      const res = await runDiagnostic(tool, target, port);
      setOutput(res.output);
    } finally {
      setIsRunning(false);
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Network Diagnostics</h1>
        <p className="text-sm text-slate-400 mt-1">
          Perform bounded ping connectivity, DNS resolution, and TCP port checks from the firewall data plane.
        </p>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
              Diagnostic Tool
            </label>
            <select
              value={tool}
              onChange={(e) => setTool(e.target.value as any)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
            >
              <option value="ping">Ping (ICMP Echo)</option>
              <option value="port_probe">TCP Port Probe</option>
            </select>
          </div>

          <div className="md:col-span-2">
            <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
              Target Hostname / IP
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
              placeholder="e.g. 1.1.1.1 or cloudflare.com"
            />
          </div>

          {tool === 'port_probe' && (
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
                TCP Port
              </label>
              <input
                type="number"
                value={port}
                onChange={(e) => setPort(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
              />
            </div>
          )}
        </div>

        <div>
          <button
            type="button"
            onClick={handleRun}
            disabled={isRunning}
            className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition cursor-pointer disabled:opacity-50"
          >
            <Play className="w-4 h-4 fill-current" />
            <span>{isRunning ? 'Running Diagnostic...' : 'Execute Diagnostic'}</span>
          </button>
        </div>
      </div>

      {output && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <span>Console Output</span>
          </div>
          <pre className="bg-slate-950 border border-slate-800/80 rounded-lg p-4 font-mono text-xs text-emerald-400 whitespace-pre-wrap">
            {output}
          </pre>
        </div>
      )}
    </div>
  );
}
