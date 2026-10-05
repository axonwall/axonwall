'use client';

import { useState } from 'react';
import {
  BatteryCharging,
  Zap,
  Clock,
  ShieldCheck,
  RefreshCw,
  Power,
  Settings,
} from 'lucide-react';
import { compileNutUps } from '@axonwall/lib/compile/nut';
import type { NutUpsConfig } from '@axonwall/lib/schemas';

export default function UpsMonitoringPage() {
  const [upsConfig, setUpsConfig] = useState<NutUpsConfig>({
    enabled: true,
    name: 'axonups',
    driver: 'usbhid-ups',
    port: 'auto',
    shutdownBatteryPct: 20,
    lowBatteryRuntimeSec: 300,
  });

  const { upsConf, nutConf } = compileNutUps(upsConfig);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <BatteryCharging className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">UPS Battery Monitoring (NUT)</h1>
            <p className="text-sm text-slate-400">
              Network UPS Tools monitoring, battery runtime statistics, and automated emergency shutdown.
            </p>
          </div>
        </div>

        <span className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          Status: OL (On Line Utility Power)
        </span>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Charge */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Battery Charge</span>
            <BatteryCharging className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">100%</span>
            <span className="text-xs text-emerald-400">Normal</span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div className="bg-emerald-500 h-full rounded-full" style={{ width: '100%' }} />
          </div>
        </div>

        {/* Runtime */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Estimated Runtime</span>
            <Clock className="w-4 h-4 text-sky-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">48 min</span>
            <span className="text-xs text-slate-400">under current load</span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div className="bg-sky-500 h-full rounded-full" style={{ width: '80%' }} />
          </div>
        </div>

        {/* Output Load */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Inverter Load</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">22%</span>
            <span className="text-xs text-slate-400">185 Watts</span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div className="bg-amber-500 h-full rounded-full" style={{ width: '22%' }} />
          </div>
        </div>

        {/* Input Voltage */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Utility Voltage</span>
            <Power className="w-4 h-4 text-purple-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">120.4 V</span>
            <span className="text-xs text-slate-400">60 Hz</span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div className="bg-purple-500 h-full rounded-full" style={{ width: '100%' }} />
          </div>
        </div>
      </div>

      {/* Settings & Configuration */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <h2 className="text-base font-semibold text-white">NUT Daemon Configuration</h2>
          <div className="space-y-4 text-xs font-mono">
            <div>
              <label className="text-slate-400 block mb-1">UPS IDENTIFIER NAME</label>
              <input
                type="text"
                value={upsConfig.name}
                onChange={(e) => setUpsConfig({ ...upsConfig, name: e.target.value })}
                className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="text-slate-400 block mb-1">NUT DRIVER</label>
              <input
                type="text"
                value={upsConfig.driver}
                onChange={(e) => setUpsConfig({ ...upsConfig, driver: e.target.value })}
                className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="text-slate-400 block mb-1">COMMUNICATION PORT</label>
              <input
                type="text"
                value={upsConfig.port}
                onChange={(e) => setUpsConfig({ ...upsConfig, port: e.target.value })}
                className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="text-slate-400 block mb-1">EMERGENCY SHUTDOWN THRESHOLD (%)</label>
              <input
                type="number"
                value={upsConfig.shutdownBatteryPct}
                onChange={(e) => setUpsConfig({ ...upsConfig, shutdownBatteryPct: parseInt(e.target.value) || 20 })}
                className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>
        </div>

        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <h2 className="text-base font-semibold text-white">Generated /etc/nut/ups.conf</h2>
          <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto max-h-64">
            {upsConf}
          </pre>
          <h2 className="text-base font-semibold text-white pt-2">Generated /etc/nut/nut.conf</h2>
          <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto">
            {nutConf}
          </pre>
        </div>
      </div>
    </div>
  );
}
