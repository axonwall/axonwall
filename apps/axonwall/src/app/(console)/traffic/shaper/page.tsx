'use client';

import { useState, useEffect } from 'react';
import { Gauge, CheckCircle2, Shield, Terminal, ArrowDown, ArrowUp, Cpu } from 'lucide-react';
import { compileTrafficShaper } from '@axonwall/lib/compile/tc';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import type { DesiredState, TrafficShaperConfig } from '@axonwall/lib/schemas';

export default function TrafficShaperPage() {
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [enabled, setEnabled] = useState(true);
  const [downloadMbps, setDownloadMbps] = useState(250);
  const [uploadMbps, setUploadMbps] = useState(50);
  const [scheduler, setScheduler] = useState<'cake' | 'fq_codel' | 'htb'>('cake');
  const [cakeDiffserv, setCakeDiffserv] = useState<'diffserv3' | 'diffserv4' | 'besteffort'>('diffserv4');
  const [cakeAckFilter, setCakeAckFilter] = useState(true);
  const [applied, setApplied] = useState(false);
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        setFullState(state);
        if (state.trafficShaper) {
          setEnabled(state.trafficShaper.enabled);
          const first = state.trafficShaper.interfaces?.[0];
          if (first) {
            setDownloadMbps(first.downloadBandwidthMbps);
            setUploadMbps(first.uploadBandwidthMbps);
            setScheduler(first.scheduler);
            setCakeDiffserv(first.cakeDiffserv);
            setCakeAckFilter(first.cakeAckFilter);
          }
        }
      })
      .catch(() => {});
  }, []);

  const currentConfig: TrafficShaperConfig = {
    enabled,
    interfaces: [
      {
        interface: 'eth0',
        downloadBandwidthMbps: downloadMbps,
        uploadBandwidthMbps: uploadMbps,
        scheduler,
        cakeDiffserv,
        cakeAckFilter,
        enabled: true,
        queues: [],
      },
    ],
  };

  const compiled = compileTrafficShaper(currentConfig);

  const handleApply = async () => {
    setSaving(true);
    setStatusMsg(null);
    try {
      const current = fullState || (await getCurrentDesiredState());
      const nextState: DesiredState = {
        ...current,
        trafficShaper: currentConfig,
      };
      setFullState(nextState);
      const res = await applyDesiredState(nextState);
      setStatusMsg(res.message || 'Saved Traffic Shaper configuration to /etc/axonwall/firewall.yaml');
      setApplied(true);
      setTimeout(() => setApplied(false), 3000);
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to save Traffic Shaper settings'}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <Gauge className="w-6 h-6 text-emerald-400" />
          Smart QoS & Traffic Shaper
        </h1>
        <p className="text-sm text-slate-400">
          Bufferbloat mitigation using Linux kernel CAKE, FQ_CoDel, and HTB synced with{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/firewall.yaml</code>.
        </p>
      </div>

      {statusMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{statusMsg}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Shaper Configuration */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h3 className="font-semibold text-white">QoS Engine</h3>
                <p className="text-xs text-slate-400">Enforce latency-sensitive queuing on edge uplinks</p>
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

            {/* Bandwidth Limits */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
                <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400 uppercase tracking-wider mb-2">
                  <ArrowDown className="w-4 h-4" />
                  Download Bandwidth (Ingress)
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    min="1"
                    max="10000"
                    value={downloadMbps}
                    onChange={(e) => setDownloadMbps(Number(e.target.value))}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xl font-bold font-mono text-white focus:outline-none focus:border-emerald-500"
                  />
                  <span className="text-sm font-semibold text-slate-400">Mbps</span>
                </div>
                <span className="text-[11px] text-slate-500 mt-2 block">
                  Redirected to virtual <code className="text-emerald-400">ifb-eth0</code> interface
                </span>
              </div>

              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
                <div className="flex items-center gap-2 text-xs font-semibold text-blue-400 uppercase tracking-wider mb-2">
                  <ArrowUp className="w-4 h-4" />
                  Upload Bandwidth (Egress)
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    min="1"
                    max="10000"
                    value={uploadMbps}
                    onChange={(e) => setUploadMbps(Number(e.target.value))}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xl font-bold font-mono text-white focus:outline-none focus:border-emerald-500"
                  />
                  <span className="text-sm font-semibold text-slate-400">Mbps</span>
                </div>
                <span className="text-[11px] text-slate-500 mt-2 block">
                  Direct root qdisc shaping on <code className="text-emerald-400">eth0</code>
                </span>
              </div>
            </div>

            {/* Scheduler Select */}
            <div className="space-y-3">
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Queuing Discipline / Scheduler
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <button
                  type="button"
                  onClick={() => setScheduler('cake')}
                  className={`p-3 rounded-lg border text-left transition ${
                    scheduler === 'cake'
                      ? 'border-emerald-500 bg-emerald-500/10 text-white'
                      : 'border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="font-semibold text-sm flex items-center justify-between">
                    CAKE
                    {scheduler === 'cake' && <span className="text-xs text-emerald-400 font-mono">Recommended</span>}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    State-of-the-art bufferbloat fighter with automatic per-host fairness.
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => setScheduler('fq_codel')}
                  className={`p-3 rounded-lg border text-left transition ${
                    scheduler === 'fq_codel'
                      ? 'border-emerald-500 bg-emerald-500/10 text-white'
                      : 'border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="font-semibold text-sm">FQ_CoDel</div>
                  <p className="text-xs text-slate-400 mt-1">
                    Fair Queuing Controlled Delay for fast responsive flows.
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => setScheduler('htb')}
                  className={`p-3 rounded-lg border text-left transition ${
                    scheduler === 'htb'
                      ? 'border-emerald-500 bg-emerald-500/10 text-white'
                      : 'border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="font-semibold text-sm">HTB Hierarchy</div>
                  <p className="text-xs text-slate-400 mt-1">
                    Hierarchical Token Bucket with custom bandwidth guarantees.
                  </p>
                </button>
              </div>
            </div>

            {/* CAKE Advanced Options */}
            {scheduler === 'cake' && (
              <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-4">
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  <Cpu className="w-4 h-4 text-emerald-400" />
                  CAKE Tuning Parameters
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">DiffServ Priority Tiers</label>
                    <select
                      value={cakeDiffserv}
                      onChange={(e) => setCakeDiffserv(e.target.value as any)}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                    >
                      <option value="diffserv4">diffserv4 (Bulk, Best Effort, Video, Voice)</option>
                      <option value="diffserv3">diffserv3 (Bulk, Best Effort, Voice)</option>
                      <option value="besteffort">besteffort (Single tier, per-host fairness)</option>
                    </select>
                  </div>
                  <div className="flex items-center gap-3 pt-4">
                    <input
                      type="checkbox"
                      id="ackFilter"
                      checked={cakeAckFilter}
                      onChange={(e) => setCakeAckFilter(e.target.checked)}
                      className="rounded bg-slate-900 border-slate-700 text-emerald-600 focus:ring-emerald-500"
                    />
                    <label htmlFor="ackFilter" className="text-sm text-slate-300 cursor-pointer">
                      Enable TCP ACK-Filter
                      <span className="block text-xs text-slate-500">
                        Compacts redundant ACKs to maximize upload efficiency
                      </span>
                    </label>
                  </div>
                </div>
              </div>
            )}

            <div className="pt-2 flex justify-end">
              <button
                type="button"
                onClick={handleApply}
                disabled={saving}
                className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-medium py-2.5 px-6 rounded-lg text-sm transition flex items-center gap-2 shadow-sm cursor-pointer"
              >
                {applied ? <CheckCircle2 className="w-4 h-4" /> : <Shield className="w-4 h-4" />}
                {saving ? 'Saving to firewall.yaml...' : applied ? 'Applied & Saved to firewall.yaml' : 'Save & Apply Shaper'}
              </button>
            </div>
          </div>
        </div>

        {/* Right 1 Col: Live Script Preview */}
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col h-full">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                <Terminal className="w-4 h-4 text-emerald-400" />
                Live Kernel tc Script
              </div>
              <span className="text-[10px] text-emerald-400 font-mono">Real-Time</span>
            </div>
            <pre className="mt-3 p-3 bg-slate-950 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap flex-1 border border-slate-900">
              {compiled.shScript}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
