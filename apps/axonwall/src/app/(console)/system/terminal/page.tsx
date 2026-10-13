'use client';

import { useState, useEffect, useRef } from 'react';
import {
  Terminal,
  Cpu,
  Fan,
  Zap,
  Activity,
  Send,
  Play,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Layers,
  Sparkles,
  Wifi,
} from 'lucide-react';
import {
  executeTerminalCommand,
  getHardwareTelemetry,
  type HardwareTelemetry,
  type TerminalExecResponse,
} from '@/server/agent';

interface HistoryItem {
  command: string;
  output: string;
  exitCode: number;
  latencyMs: number;
  timestamp: string;
}

const QUICK_COMMANDS = [
  { label: 'nft ruleset', cmd: 'nft list ruleset' },
  { label: 'conntrack states', cmd: 'conntrack -L 2>/dev/null || cat /proc/net/nf_conntrack' },
  { label: 'ip links', cmd: 'ip -d link show' },
  { label: 'systemctl status', cmd: 'systemctl status axonwalld --no-pager' },
  { label: 'kernel version', cmd: 'uname -a' },
  { label: 'memory stats', cmd: 'free -h' },
];

export default function TerminalPage() {
  const [activeTab, setActiveTab] = useState<'terminal' | 'hardware'>('terminal');
  const [commandInput, setCommandInput] = useState('');
  const [isExecuting, setIsExecuting] = useState(false);
  const [history, setHistory] = useState<HistoryItem[]>([
    {
      command: 'systemctl status axonwalld',
      output: `● axonwalld.service - Axonwall Privileged Agent
   Loaded: loaded (/lib/systemd/system/axonwalld.service; enabled)
   Active: active (running)
   Main PID: 1042 (axonwalld)
   Tasks: 14 (limit: 4915)
   Memory: 24.2M
   CGroup: /system.slice/axonwalld.service
           └─1042 /usr/sbin/axonwalld --bundle-dir=/var/lib/axonwall/bundles`,
      exitCode: 0,
      latencyMs: 12,
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);

  const [telemetry, setTelemetry] = useState<HardwareTelemetry | null>(null);
  const [isLoadingTelem, setIsLoadingTelem] = useState(false);

  const terminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [history]);

  useEffect(() => {
    if (activeTab === 'hardware') {
      loadTelemetry();
    }
  }, [activeTab]);

  const loadTelemetry = async () => {
    setIsLoadingTelem(true);
    try {
      const data = await getHardwareTelemetry();
      setTelemetry(data);
    } catch {}
    setIsLoadingTelem(false);
  };

  const handleRunCommand = async (cmdToRun?: string) => {
    const cmd = cmdToRun !== undefined ? cmdToRun : commandInput;
    if (!cmd.trim() || isExecuting) return;

    setIsExecuting(true);
    try {
      const resp = await executeTerminalCommand(cmd);
      setHistory((prev) => [
        ...prev,
        {
          command: cmd,
          output: resp.output,
          exitCode: resp.exitCode,
          latencyMs: resp.latencyMs,
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
      if (cmdToRun === undefined) {
        setCommandInput('');
      }
    } catch (err: any) {
      setHistory((prev) => [
        ...prev,
        {
          command: cmd,
          output: `Execution error: ${err?.message || 'Failed to run command'}`,
          exitCode: 1,
          latencyMs: 0,
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <Terminal className="w-6 h-6 text-emerald-400" />
            <span>Appliance Shell & Hardware Telemetry</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Privileged appliance web shell, HWMON environmental sensor telemetry, and SFP+ Digital Optical Monitoring.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center bg-slate-900 border border-slate-800 rounded-lg p-1">
          <button
            type="button"
            onClick={() => setActiveTab('terminal')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'terminal'
                ? 'bg-emerald-600 text-white shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Web Shell</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('hardware')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'hardware'
                ? 'bg-emerald-600 text-white shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>Hardware Sensors</span>
          </button>
        </div>
      </div>

      {activeTab === 'terminal' ? (
        <div className="space-y-4">
          {/* Quick Action Chips */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-500 font-medium mr-1">Quick Tools:</span>
            {QUICK_COMMANDS.map((qc) => (
              <button
                key={qc.label}
                type="button"
                onClick={() => handleRunCommand(qc.cmd)}
                disabled={isExecuting}
                className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 text-[11px] font-mono text-slate-300 transition cursor-pointer"
              >
                {qc.label}
              </button>
            ))}
          </div>

          {/* Terminal Console Window */}
          <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col h-[580px]">
            {/* Window Chrome */}
            <div className="bg-slate-900/90 border-b border-slate-800 px-4 py-2.5 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-red-500/80" />
                <span className="w-3 h-3 rounded-full bg-amber-500/80" />
                <span className="w-3 h-3 rounded-full bg-emerald-500/80" />
                <span className="text-xs font-mono text-slate-400 ml-2">
                  axonwall-core# (privileged bash session)
                </span>
              </div>
              <span className="text-[11px] font-mono text-emerald-400/90">
                Connected via agent.sock
              </span>
            </div>

            {/* Scrollable Command Transcript */}
            <div className="flex-1 p-4 overflow-y-auto space-y-4 font-mono text-xs text-slate-200 leading-relaxed">
              {history.map((item, idx) => (
                <div key={idx} className="space-y-1">
                  <div className="flex items-center gap-2 text-emerald-400">
                    <span className="text-slate-500 select-none">[{item.timestamp}]</span>
                    <span className="text-slate-400 font-bold">axonwall#</span>
                    <span className="text-white font-semibold">{item.command}</span>
                    <span className="text-[10px] text-slate-600 ml-auto font-sans">
                      {item.latencyMs}ms | exit {item.exitCode}
                    </span>
                  </div>
                  <pre className="text-slate-300 whitespace-pre-wrap pl-4 border-l border-slate-800 py-1 bg-slate-900/30 rounded">
                    {item.output || '<no output>'}
                  </pre>
                </div>
              ))}
              <div ref={terminalEndRef} />
            </div>

            {/* Input Bar */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleRunCommand();
              }}
              className="bg-slate-900 border-t border-slate-800 p-3 flex items-center gap-2"
            >
              <span className="text-emerald-400 font-mono text-xs font-bold pl-2 select-none">
                axonwall#
              </span>
              <input
                type="text"
                value={commandInput}
                onChange={(e) => setCommandInput(e.target.value)}
                disabled={isExecuting}
                placeholder="Enter shell command (e.g. nft list ruleset, conntrack -L, ethtool eth0)..."
                className="flex-1 bg-transparent border-none text-xs font-mono text-white placeholder-slate-600 focus:outline-none"
              />
              <button
                type="submit"
                disabled={isExecuting || !commandInput.trim()}
                className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer shadow"
              >
                {isExecuting ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Send className="w-3.5 h-3.5" />
                )}
                <span>Run</span>
              </button>
            </form>
          </div>
        </div>
      ) : (
        /* Hardware Telemetry View */
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <span className="text-sm font-semibold text-white">
              Appliance Environmental Sensors & Transceivers
            </span>
            <button
              type="button"
              onClick={loadTelemetry}
              disabled={isLoadingTelem}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs text-slate-300 transition flex items-center gap-1.5 border border-slate-800 font-medium cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoadingTelem ? 'animate-spin' : ''}`} />
              <span>Refresh Readings</span>
            </button>
          </div>

          {/* Temperature Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {telemetry?.temperatures.map((temp) => (
              <div
                key={temp.name}
                className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400 font-medium truncate">
                    {temp.label}
                  </span>
                  <Cpu className="w-4 h-4 text-emerald-400 shrink-0" />
                </div>
                <div className="mt-2 flex items-baseline gap-1">
                  <span className="text-2xl font-bold font-mono text-white">
                    {temp.value.toFixed(1)}
                  </span>
                  <span className="text-xs text-slate-400 font-mono">{temp.unit}</span>
                </div>
                <div className="mt-2 text-[10px] text-slate-500 flex justify-between">
                  <span>Warn: {temp.warning || 85}°C</span>
                  <span>Crit: {temp.critical || 100}°C</span>
                </div>
              </div>
            ))}
          </div>

          {/* Fans & Voltages */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Fan Tachometers */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <span className="text-sm font-semibold text-white flex items-center gap-2">
                <Fan className="w-4 h-4 text-cyan-400" />
                <span>Chassis & Cooler Fans</span>
              </span>
              <div className="space-y-3 font-mono text-xs">
                {telemetry?.fans.map((fan) => (
                  <div
                    key={fan.name}
                    className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between"
                  >
                    <span className="text-slate-300 font-sans">{fan.label}</span>
                    <span className="font-bold text-emerald-400">{fan.rpm.toLocaleString()} RPM</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Voltage Rails */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <span className="text-sm font-semibold text-white flex items-center gap-2">
                <Zap className="w-4 h-4 text-amber-400" />
                <span>Power Supply Voltage Rails</span>
              </span>
              <div className="space-y-3 font-mono text-xs">
                {telemetry?.voltages.map((v) => (
                  <div
                    key={v.name}
                    className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between"
                  >
                    <span className="text-slate-300 font-sans">{v.label}</span>
                    <span className="font-bold text-white">
                      {v.value.toFixed(2)} {v.unit}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* SFP+ Optical DOM Transceivers */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-800">
              <h3 className="font-semibold text-white flex items-center gap-2">
                <Wifi className="w-4 h-4 text-emerald-400" />
                <span>SFP+ / QSFP Optical Transceivers (Digital Optical Monitoring)</span>
              </h3>
              <p className="text-xs text-slate-400">
                Laser power levels, bias currents, and supply voltages via ethtool DOM inspection
              </p>
            </div>

            <table className="w-full text-sm text-left font-mono text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase border-b border-slate-800 font-sans">
                <tr>
                  <th className="px-4 py-3">Port</th>
                  <th className="px-4 py-3">Transceiver</th>
                  <th className="px-4 py-3">Module Temp</th>
                  <th className="px-4 py-3">Tx Power</th>
                  <th className="px-4 py-3">Rx Power</th>
                  <th className="px-4 py-3">Bias Current</th>
                  <th className="px-4 py-3 text-right">Link Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {telemetry?.transceivers.map((opt) => (
                  <tr key={opt.interface} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3 font-bold text-white">{opt.interface}</td>
                    <td className="px-4 py-3">
                      <span className="text-slate-200">{opt.vendor}</span>{' '}
                      <span className="text-slate-500 font-mono">({opt.partNumber})</span>
                    </td>
                    <td className="px-4 py-3 text-emerald-400 font-semibold">
                      {opt.temperature.toFixed(1)} °C
                    </td>
                    <td className="px-4 py-3 font-semibold text-white">{opt.txPowerDbm} dBm</td>
                    <td className="px-4 py-3 font-semibold text-white">{opt.rxPowerDbm} dBm</td>
                    <td className="px-4 py-3 text-slate-400">{opt.biasCurrentMa} mA</td>
                    <td className="px-4 py-3 text-right">
                      <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-bold border border-emerald-500/20">
                        {opt.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
