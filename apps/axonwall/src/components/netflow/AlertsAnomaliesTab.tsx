'use client';

import React, { useCallback, useEffect, useState } from 'react';
import { Activity, Bell, CheckCheck, Plus, RefreshCw, RotateCcw, ShieldAlert, Trash2 } from 'lucide-react';
import { formatBps } from '@axonwall/lib/compile/netflow';
import {
  NetFlowAlertActionSchema,
  NetFlowAlertRuleKindSchema,
  NetFlowConfigSchema,
  type DesiredState,
  type NetFlowAlertRule,
} from '@axonwall/lib/schemas';
import { getNetFlowBaselinesAction, resetNetFlowBaselinesAction } from '@/server/agent';
import type { NetFlowAlertSnapshot, NetFlowBaselineSummarySnapshot } from './types';

interface AlertsAnomaliesTabProps {
  alerts: NetFlowAlertSnapshot[];
  draftState: DesiredState | null;
  onAckAlert: (id: string) => void;
  onUpdateDraft: (updater: (prev: DesiredState) => DesiredState) => void;
}

export function AlertsAnomaliesTab({
  alerts,
  draftState,
  onAckAlert,
  onUpdateDraft,
}: AlertsAnomaliesTabProps) {
  const [name, setName] = useState('');
  const [kind, setKind] = useState<NetFlowAlertRule['kind']>('port_scan');
  const [severity, setSeverity] = useState<NetFlowAlertRule['severity']>('high');
  const [threshold, setThreshold] = useState('50');
  const [windowSec, setWindowSec] = useState('60');
  const [fqlFilter, setFqlFilter] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [actions, setActions] = useState<NetFlowAlertRule['actions']>(['alert_log']);
  const [baselines, setBaselines] = useState<NetFlowBaselineSummarySnapshot[]>([]);
  const [loadingBase, setLoadingBase] = useState(false);

  const loadBaselines = useCallback(async () => {
    setLoadingBase(true);
    try {
      const list = await getNetFlowBaselinesAction(30);
      setBaselines(list);
    } finally {
      setLoadingBase(false);
    }
  }, []);

  useEffect(() => {
    void loadBaselines();
  }, [loadBaselines]);

  const rules = draftState?.netflow?.alerting?.rules ?? [];

  const toggleAction = (act: NetFlowAlertRule['actions'][number]) => {
    setActions((prev) => (prev.includes(act) ? prev.filter((a) => a !== act) : [...prev, act]));
  };

  const handleAddRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    const rule: NetFlowAlertRule = {
      id: `nfr-${Date.now().toString(36)}`,
      name: name.trim(),
      enabled: true,
      kind,
      severity,
      fqlFilter: fqlFilter.trim() || undefined,
      threshold: Math.max(0, Number(threshold) || 0),
      windowSec: Math.max(10, Number(windowSec) || 60),
      cooldownSec: 300,
      actions: actions.length > 0 ? actions : ['alert_log'],
      xdpBlockTtlSec: 900,
      webhookUrl: webhookUrl.trim() || undefined,
    };
    onUpdateDraft((prev) => {
      const cur = NetFlowConfigSchema.parse(prev.netflow ?? {});
      return {
        ...prev,
        netflow: {
          ...cur,
          alerting: {
            ...cur.alerting,
            rules: [...cur.alerting.rules, rule],
          },
        },
      };
    });
    setName('');
    setFqlFilter('');
    setWebhookUrl('');
  };

  return (
    <div className="space-y-6">
      {/* Live Alert Feed */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <div>
              <h3 className="text-sm font-semibold text-white">Real-Time Flow Anomalies &amp; Alerts ({alerts.length})</h3>
              <p className="text-xs text-slate-400">Triggered detections across sliding flow windows with automated mitigation log</p>
            </div>
          </div>
          {alerts.some((a) => !a.acknowledged) && (
            <button
              type="button"
              onClick={() => onAckAlert('all')}
              className="px-3 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-xs text-emerald-300 flex items-center gap-1.5"
            >
              <CheckCheck className="w-3.5 h-3.5" />
              Acknowledge All
            </button>
          )}
        </div>

        {alerts.length === 0 ? (
          <div className="py-8 text-center text-xs text-slate-500">
            No flow anomalies triggered.
          </div>
        ) : (
          <div className="space-y-2 max-h-[340px] overflow-y-auto">
            {alerts.map((a) => (
              <div
                key={a.id}
                className={`p-3 rounded-lg border text-xs flex flex-wrap items-center justify-between gap-3 ${
                  a.acknowledged
                    ? 'bg-slate-950/60 border-slate-800 text-slate-400'
                    : a.severity === 'critical'
                      ? 'bg-rose-500/10 border-rose-500/40 text-rose-200'
                      : 'bg-amber-500/10 border-amber-500/40 text-amber-200'
                }`}
              >
                <div className="space-y-0.5 min-w-0">
                  <div className="font-semibold flex items-center gap-2">
                    <span className="uppercase font-mono text-[10px] px-1.5 py-0.5 rounded bg-black/30">
                      {a.severity}
                    </span>
                    <span>{a.ruleName}</span>
                    <span className="font-mono text-[11px] opacity-80">culprit: {a.culpritIp}</span>
                  </div>
                  <div className="text-slate-300">{a.summary}</div>
                  <div className="font-mono text-[10px] text-slate-400">
                    {new Date(a.timestamp).toLocaleString()} · Actions: {a.actionsTaken.join(', ')}
                  </div>
                </div>
                {!a.acknowledged && (
                  <button
                    type="button"
                    onClick={() => onAckAlert(a.id)}
                    className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-white text-[11px]"
                  >
                    Ack
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Alert Rule Builder */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bell className="w-4 h-4 text-sky-400" />
            <div>
              <h3 className="text-sm font-semibold text-white">Flow Anomaly Rules &amp; SOAR/XDP Response ({rules.length})</h3>
              <p className="text-xs text-slate-400">Configure thresholds &amp; automatic response actions (remember to Save Changes)</p>
            </div>
          </div>
          <label className="flex items-center gap-2 text-xs text-slate-200 cursor-pointer">
            <input
              type="checkbox"
              checked={draftState?.netflow?.alerting?.enabled ?? true}
              onChange={(e) =>
                onUpdateDraft((prev) => {
                  const cur = NetFlowConfigSchema.parse(prev.netflow ?? {});
                  return { ...prev, netflow: { ...cur, alerting: { ...cur.alerting, enabled: e.target.checked } } };
                })
              }
              className="accent-sky-500"
            />
            Alert Engine Enabled
          </label>
        </div>

        <div className="space-y-2 text-xs">
          {rules.map((r) => (
            <div
              key={r.id}
              className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-2"
            >
              <div>
                <div className="font-semibold text-white flex items-center gap-2">
                  <span>{r.name}</span>
                  <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-900 text-sky-300">
                    {r.kind}
                  </span>
                  <span className="font-mono text-[10px] text-slate-400">
                    thresh={r.threshold} · win={r.windowSec}s
                  </span>
                </div>
                <div className="font-mono text-[11px] text-slate-400 mt-0.5">
                  Actions: {r.actions.join(', ')} {r.fqlFilter ? `· FQL: ${r.fqlFilter}` : ''}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={r.enabled}
                  onChange={(e) =>
                    onUpdateDraft((prev) => {
                      const cur = NetFlowConfigSchema.parse(prev.netflow ?? {});
                      return {
                        ...prev,
                        netflow: {
                          ...cur,
                          alerting: {
                            ...cur.alerting,
                            rules: cur.alerting.rules.map((item) =>
                              item.id === r.id ? { ...item, enabled: e.target.checked } : item,
                            ),
                          },
                        },
                      };
                    })
                  }
                  className="accent-sky-500"
                />
                <button
                  type="button"
                  onClick={() =>
                    onUpdateDraft((prev) => {
                      const cur = NetFlowConfigSchema.parse(prev.netflow ?? {});
                      return {
                        ...prev,
                        netflow: {
                          ...cur,
                          alerting: {
                            ...cur.alerting,
                            rules: cur.alerting.rules.filter((item) => item.id !== r.id),
                          },
                        },
                      };
                    })
                  }
                  className="p-1 rounded hover:bg-rose-500/20 text-slate-400 hover:text-rose-300"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>

        <form onSubmit={handleAddRule} className="pt-3 border-t border-slate-800 space-y-3 text-xs">
          <div className="grid grid-cols-1 md:grid-cols-5 gap-2">
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Rule name"
              className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white"
            />
            <select
              value={kind}
              onChange={(e) => setKind(e.target.value as NetFlowAlertRule['kind'])}
              className="px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            >
              {NetFlowAlertRuleKindSchema.options.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as NetFlowAlertRule['severity'])}
              className="px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            >
              <option value="info">info</option>
              <option value="warning">warning</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
            <input
              type="number"
              min={0}
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
              placeholder="Threshold"
              className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
            <input
              type="number"
              min={10}
              value={windowSec}
              onChange={(e) => setWindowSec(e.target.value)}
              placeholder="Window (sec)"
              className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            <input
              type="text"
              value={fqlFilter}
              onChange={(e) => setFqlFilter(e.target.value)}
              placeholder="Optional FQL filter scope (e.g. direction=egress)"
              className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
            <input
              type="url"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              placeholder="Optional Webhook URL"
              className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
            />
          </div>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-slate-400">Actions:</span>
              {NetFlowAlertActionSchema.options.map((act) => (
                <label key={act} className="flex items-center gap-1.5 text-slate-200 cursor-pointer font-mono">
                  <input
                    type="checkbox"
                    checked={actions.includes(act)}
                    onChange={() => toggleAction(act)}
                    className="accent-sky-500"
                  />
                  {act}
                </label>
              ))}
            </div>
            <button
              type="submit"
              disabled={!name.trim()}
              className="px-3.5 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white font-semibold flex items-center gap-1"
            >
              <Plus className="w-3.5 h-3.5" />
              Add Alert Rule
            </button>
          </div>
          {kind === 'baseline_zscore' && (
            <div className="text-[11px] font-mono text-sky-300">
              Adaptive EWMA Z-score threshold (recommended: 3.5 standard deviations above 7-day hour-of-day baseline)
            </div>
          )}
          {kind === 'first_seen_pair' && (
            <div className="text-[11px] font-mono text-amber-300">
              Minimum byte threshold to alert on newly observed /24→ASN or cross-VLAN lateral pairs (recommended: 102400)
            </div>
          )}
        </form>
      </div>

      {/* Adaptive 7-Day EWMA Baselines */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-400" />
            <div>
              <h3 className="text-sm font-semibold text-white">Adaptive 7-Day Hour-of-Day Baselines ({baselines.length})</h3>
              <p className="text-xs text-slate-400">Online EWMA mean &amp; standard deviation learned per host (168 weekly hourly slots)</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <button
              type="button"
              onClick={() => void loadBaselines()}
              className="px-2.5 py-1 rounded bg-slate-950 hover:bg-slate-800 text-slate-300 flex items-center gap-1"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingBase ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <button
              type="button"
              onClick={() =>
                void resetNetFlowBaselinesAction().then(() => {
                  setBaselines([]);
                })
              }
              className="px-2.5 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 flex items-center gap-1"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset Models
            </button>
          </div>
        </div>

        <div className="overflow-x-auto max-h-[260px]">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono">
              <tr>
                <th className="px-3 py-2">Entity IP / If</th>
                <th className="px-3 py-2">Samples</th>
                <th className="px-3 py-2">EWMA Rate</th>
                <th className="px-3 py-2">Stddev Rate</th>
                <th className="px-3 py-2">EWMA PPS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-slate-200">
              {baselines.map((b) => (
                <tr key={b.entity}>
                  <td className="px-3 py-1.5 text-white">{b.entity}</td>
                  <td className="px-3 py-1.5 text-slate-400">{b.samples}</td>
                  <td className="px-3 py-1.5 text-emerald-300">{formatBps(b.ewmaBps)}</td>
                  <td className="px-3 py-1.5 text-sky-300">± {formatBps(b.stddevBps)}</td>
                  <td className="px-3 py-1.5 text-slate-300">{b.ewmaPps.toFixed(1)} pps</td>
                </tr>
              ))}
              {baselines.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-6 text-center text-slate-500">
                    Add a `baseline_zscore` alert rule to start accumulating adaptive host models.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
