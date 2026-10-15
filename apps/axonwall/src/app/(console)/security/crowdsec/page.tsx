'use client';

import { useState, useEffect } from 'react';
import { Shield, ShieldAlert, CheckCircle2, Terminal, RefreshCw, Trash2, Save } from 'lucide-react';
import { compileCrowdSec } from '@axonwall/lib/compile/crowdsec';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import type { DesiredState, CrowdSecConfig } from '@axonwall/lib/schemas';

interface RemediationDecision {
  id: string;
  ip: string;
  scenario: string;
  duration: string;
  action: 'drop' | 'reject';
}

export default function CrowdSecPage() {
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [lapiUrl, setLapiUrl] = useState('http://127.0.0.1:8080/');
  const [decisions, setDecisions] = useState<RemediationDecision[]>([]);
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        setFullState(state);
        if (state.crowdsec) {
          setEnabled(state.crowdsec.enabled);
          setLapiUrl(state.crowdsec.lapiUrl || 'http://127.0.0.1:8080/');
        }
      })
      .catch(() => {});
  }, []);

  const crowdSecConfig: CrowdSecConfig = {
    enabled,
    lapiUrl,
    apiKey: fullState?.crowdsec?.apiKey || '9a8b7c6d5e4f3a2b1c0d',
    remediationSetName: fullState?.crowdsec?.remediationSetName || 'set_crowdsec_blacklists',
    action: fullState?.crowdsec?.action || 'drop',
    logBanned: fullState?.crowdsec?.logBanned ?? true,
  };

  const handleSaveCrowdSec = async (nextEnabled = enabled) => {
    setEnabled(nextEnabled);
    setSaving(true);
    setStatusMsg(null);
    try {
      const current = fullState || (await getCurrentDesiredState());
      const nextState: DesiredState = {
        ...current,
        crowdsec: {
          ...crowdSecConfig,
          enabled: nextEnabled,
        },
      };
      setFullState(nextState);
      const res = await applyDesiredState(nextState);
      setStatusMsg(res.message || 'Saved CrowdSec configuration to /etc/axonwall/security.yaml');
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to save CrowdSec settings'}`);
    } finally {
      setSaving(false);
    }
  };

  const compiled = compileCrowdSec(crowdSecConfig);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-emerald-400" />
            CrowdSec Threat Intelligence & nftables Bouncer
          </h1>
          <p className="text-sm text-slate-400">
            Crowdsourced cyber defense synced with <code className="text-emerald-400 font-mono">/etc/axonwall/security.yaml</code>.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => handleSaveCrowdSec(!enabled)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer transition ${
              enabled
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}
          >
            {enabled ? 'Bouncer Enabled' : 'Bouncer Disabled'}
          </button>
          <button
            type="button"
            onClick={() => handleSaveCrowdSec(enabled)}
            disabled={saving}
            className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{saving ? 'Saving YAML...' : 'Save to security.yaml'}</span>
          </button>
        </div>
      </div>

      {statusMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{statusMsg}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          {/* Status & Stats */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <span className="text-xs font-medium text-slate-400 uppercase tracking-wider block">
                CrowdSec LAPI Connection
              </span>
              <span className="text-lg font-bold font-mono text-slate-400 mt-1 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-slate-500" /> Standby
              </span>
              <span className="text-[11px] text-slate-500 mt-0.5 block">{lapiUrl}</span>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <span className="text-xs font-medium text-slate-400 uppercase tracking-wider block">
                Active Banned IPs
              </span>
              <span className="text-2xl font-bold font-mono text-emerald-400 mt-1 block">
                {decisions.length} IPs
              </span>
              <span className="text-[11px] text-slate-500 mt-0.5 block">Held in set_crowdsec_blacklists</span>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <span className="text-xs font-medium text-slate-400 uppercase tracking-wider block">
                Bouncer Mode
              </span>
              <span className="text-lg font-bold font-mono text-white mt-1 block">
                Kernel nftables
              </span>
              <span className="text-[11px] text-slate-500 mt-0.5 block">Zero userspace context switch</span>
            </div>
          </div>

          {/* Active Decisions Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center">
              <div>
                <h3 className="font-semibold text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-emerald-400" />
                  Active Remediated Attackers
                </h3>
                <p className="text-xs text-slate-400">Synchronized via CrowdSec Local API</p>
              </div>
            </div>

            {decisions.length === 0 ? (
              <div className="p-8 text-center text-slate-400">
                <CheckCircle2 className="w-8 h-8 text-emerald-500/80 mx-auto mb-2" />
                <p className="font-semibold text-slate-300">No Active Bans</p>
                <p className="text-xs text-slate-500 mt-1">Zero malicious IPs are currently quarantined in the nftables remediation set.</p>
              </div>
            ) : (
              <table className="w-full text-sm text-left">
                <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">Attacker IP</th>
                    <th className="px-4 py-3">Triggered Scenario</th>
                    <th className="px-4 py-3">Remaining Ban</th>
                    <th className="px-4 py-3">Action</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {decisions.map((d) => (
                    <tr key={d.id} className="hover:bg-slate-800/30">
                      <td className="px-4 py-3 font-mono font-semibold text-red-400 text-xs">{d.ip}</td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-300">{d.scenario}</td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-400">{d.duration}</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 text-xs font-mono font-bold border border-red-500/20 uppercase">
                          {d.action}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => setDecisions(decisions.filter((x) => x.id !== d.id))}
                          className="text-slate-500 hover:text-red-400 transition"
                          title="Unban IP"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Right 1 Col: Live Bouncer Config */}
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col h-full">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                <Terminal className="w-4 h-4 text-emerald-400" />
                crowdsec-firewall-bouncer.yaml
              </div>
              <span className="text-[10px] text-emerald-400 font-mono">nftables</span>
            </div>
            <pre className="mt-3 p-3 bg-slate-950 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap flex-1 border border-slate-900">
              {compiled.bouncerYaml}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
