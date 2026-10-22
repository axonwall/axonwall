'use client';

import { useState, useEffect } from 'react';
import {
  BatteryCharging,
  Zap,
  Clock,
  ShieldCheck,
  RefreshCw,
  Power,
  Settings,
  HelpCircle,
  Save,
} from 'lucide-react';
import { compileNutUps } from '@axonwall/lib/compile/nut';
import type { NutUpsConfig } from '@axonwall/lib/schemas';
import { getUpsStatus, getCurrentDesiredState, applyDesiredState, type UpsStatus } from '@/server/agent';

export default function UpsMonitoringPage() {
  const [upsStatus, setUpsStatus] = useState<UpsStatus | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [upsConfig, setUpsConfig] = useState<NutUpsConfig>({
    enabled: false,
    name: 'axonups',
    driver: 'usbhid-ups',
    port: 'auto',
    shutdownBatteryPct: 20,
    lowBatteryRuntimeSec: 300,
  });

  const fetchStatus = async () => {
    setIsRefreshing(true);
    try {
      const data = await getUpsStatus();
      setUpsStatus(data);
    } catch {
      setUpsStatus({
        connected: false,
        status: 'DISCONNECTED',
        chargePct: null,
        runtimeSeconds: null,
        loadPct: null,
        inputVoltage: null,
        model: null,
        isVirtual: false,
        message: 'Unable to query NUT daemon',
      });
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchStatus();
    getCurrentDesiredState()
      .then((state) => {
        if (state.ups) setUpsConfig(state.ups);
      })
      .catch(() => {});
  }, []);

  const handleSaveUps = async () => {
    setIsSaving(true);
    try {
      const state = await getCurrentDesiredState();
      await applyDesiredState({ ...state, ups: upsConfig });
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new Event('axonwall-capabilities-updated'));
      }
    } catch {}
    setIsSaving(false);
  };

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

        <div className="flex items-center gap-3">
          <button
            onClick={handleSaveUps}
            disabled={isSaving}
            className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{isSaving ? 'Saving...' : 'Save to system.yaml'}</span>
          </button>
          <button
            onClick={fetchStatus}
            disabled={isRefreshing}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-white transition cursor-pointer"
            title="Refresh UPS Telemetry"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
          </button>

          {upsStatus?.connected ? (
            <span className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              Status: {upsStatus.status} (Online Utility Power)
            </span>
          ) : (
            <span className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800/80 text-slate-400 border border-slate-700 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-slate-500" />
              Status: Disconnected {upsStatus?.isVirtual ? '(Virtual Machine)' : '(No UPS Detected)'}
            </span>
          )}
        </div>
      </div>

      {/* Disconnected / Virtual Machine Info Callout */}
      {!upsStatus?.connected && (
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-start gap-3 text-xs text-slate-400">
          <HelpCircle className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-slate-200 block mb-0.5">
              {upsStatus?.isVirtual
                ? 'Virtual Machine Environment Detected'
                : 'No Battery Hardware or NUT Daemon Detected'}
            </span>
            <span>
              {upsStatus?.message ||
                'This system is operating in a virtualized or containerized environment without attached physical UPS hardware. To monitor a UPS, pass through a USB/serial device to this VM or configure a remote NUT server below.'}
            </span>
          </div>
        </div>
      )}

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Charge */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Battery Charge</span>
            <BatteryCharging className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white font-mono">
              {upsStatus?.chargePct != null ? `${upsStatus.chargePct}%` : '--'}
            </span>
            <span className="text-xs text-slate-500">
              {upsStatus?.chargePct != null ? 'Normal' : 'No Hardware'}
            </span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div
              className="bg-emerald-500 h-full rounded-full transition-all"
              style={{ width: upsStatus?.chargePct != null ? `${upsStatus.chargePct}%` : '0%' }}
            />
          </div>
        </div>

        {/* Runtime */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Estimated Runtime</span>
            <Clock className="w-4 h-4 text-sky-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white font-mono">
              {upsStatus?.runtimeSeconds != null
                ? `${Math.round(upsStatus.runtimeSeconds / 60)} min`
                : '--'}
            </span>
            <span className="text-xs text-slate-500">
              {upsStatus?.runtimeSeconds != null ? 'under current load' : 'N/A'}
            </span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div
              className="bg-sky-500 h-full rounded-full transition-all"
              style={{
                width:
                  upsStatus?.runtimeSeconds != null
                    ? `${Math.min(100, Math.round((upsStatus.runtimeSeconds / 3600) * 100))}%`
                    : '0%',
              }}
            />
          </div>
        </div>

        {/* Output Load */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Inverter Load</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white font-mono">
              {upsStatus?.loadPct != null ? `${upsStatus.loadPct}%` : '--'}
            </span>
            <span className="text-xs text-slate-500">
              {upsStatus?.loadPct != null ? 'Active' : 'N/A'}
            </span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div
              className="bg-amber-500 h-full rounded-full transition-all"
              style={{ width: upsStatus?.loadPct != null ? `${upsStatus.loadPct}%` : '0%' }}
            />
          </div>
        </div>

        {/* Input Voltage */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Utility Voltage</span>
            <Power className="w-4 h-4 text-purple-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white font-mono">
              {upsStatus?.inputVoltage != null ? `${upsStatus.inputVoltage} V` : '--'}
            </span>
            <span className="text-xs text-slate-500">
              {upsStatus?.inputVoltage != null ? 'Grid' : 'N/A'}
            </span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div
              className="bg-purple-500 h-full rounded-full transition-all"
              style={{ width: upsStatus?.inputVoltage != null ? '100%' : '0%' }}
            />
          </div>
        </div>
      </div>

      {/* Settings & Configuration */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-base font-semibold text-white">NUT Daemon Configuration</h2>
            <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
              <span>Enable NUT</span>
              <input
                type="checkbox"
                checked={upsConfig.enabled}
                onChange={(e) => setUpsConfig({ ...upsConfig, enabled: e.target.checked })}
                className="rounded bg-slate-950 border-slate-700 text-emerald-500 focus:ring-emerald-500"
              />
            </label>
          </div>

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
