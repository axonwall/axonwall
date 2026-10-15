'use client';

import React, { useState, useEffect } from 'react';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Shield, ShieldAlert, Zap, Loader2, CheckCircle2, Save } from 'lucide-react';
import { Switch } from '@/components/ui/switch';
import {
  getRecentThreatAlerts,
  getSystemServicesStatus,
  getCurrentDesiredState,
  applyDesiredState,
  type ThreatAlert,
  type LiveServiceInfo,
} from '@/server/agent';
import type { DesiredState } from '@axonwall/lib/schemas';

export default function IdsIpsPage() {
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [services, setServices] = useState<LiveServiceInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [suricataEnabled, setSuricataEnabled] = useState(false);
  const [suricataMode, setSuricataMode] = useState<'ids' | 'ips'>('ips');
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([getRecentThreatAlerts(), getSystemServicesStatus(), getCurrentDesiredState()])
      .then(([alertData, serviceData, state]) => {
        setAlerts(alertData);
        setServices(serviceData);
        setFullState(state);
        if (state.suricata) {
          setSuricataEnabled(state.suricata.enabled);
          setSuricataMode(state.suricata.mode || 'ips');
        }
      })
      .catch(() => {
        setAlerts([]);
        setServices([]);
      })
      .finally(() => setLoading(false));
  }, []);

  const handleSaveSuricata = async (nextEnabled = suricataEnabled, nextMode = suricataMode) => {
    setSuricataEnabled(nextEnabled);
    setSuricataMode(nextMode);
    setSaving(true);
    setStatusMsg(null);
    try {
      const current = fullState || (await getCurrentDesiredState());
      const nextState: DesiredState = {
        ...current,
        suricata: {
          enabled: nextEnabled,
          mode: nextMode,
          interfaces: current.suricata?.interfaces || ['wan'],
          nfqueueFailOpen: current.suricata?.nfqueueFailOpen ?? true,
          nfqueueBypass: current.suricata?.nfqueueBypass ?? true,
          ruleSources: current.suricata?.ruleSources || [
            {
              name: 'ET Open Ruleset',
              url: 'https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz',
              enabled: true,
            },
          ],
          homeNet: current.suricata?.homeNet || ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'],
        },
      };
      setFullState(nextState);
      const res = await applyDesiredState(nextState);
      setStatusMsg(res.message || 'Saved Suricata configuration to /etc/axonwall/security.yaml');
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to save Suricata settings'}`);
    } finally {
      setSaving(false);
    }
  };

  const suricataService = services.find((s) => s.unit === 'suricata.service');
  const suricataRunning = suricataService?.status === 'active' || suricataEnabled;

  const crowdsecService = services.find((s) => s.unit === 'crowdsec.service');
  const crowdsecRunning = crowdsecService?.status === 'active';

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Intrusion Prevention (IDS/IPS)</h1>
          <p className="text-muted-foreground mt-1">
            Automated threat defense utilizing Suricata inspection synced with{' '}
            <code className="text-emerald-400 font-mono">/etc/axonwall/security.yaml</code>.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={suricataMode}
            onChange={(e) => handleSaveSuricata(suricataEnabled, e.target.value as 'ids' | 'ips')}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
          >
            <option value="ips">IPS Mode (Inline Drop)</option>
            <option value="ids">IDS Mode (Alert Only)</option>
          </select>
          <button
            type="button"
            onClick={() => handleSaveSuricata(!suricataEnabled, suricataMode)}
            disabled={saving}
            className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{suricataEnabled ? 'Disable Suricata' : 'Enable Suricata'}</span>
          </button>
        </div>
      </div>

      {statusMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{statusMsg}</span>
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <div>
              <CardTitle className="text-lg">Suricata IPS Engine ({suricataMode.toUpperCase()})</CardTitle>
              <CardDescription>Deep packet inspection rules engine</CardDescription>
            </div>
            <Badge
              variant={suricataRunning ? 'default' : 'secondary'}
              className={suricataRunning ? 'bg-emerald-500' : ''}
            >
              {suricataRunning ? 'ONLINE' : 'STOPPED'}
            </Badge>
          </CardHeader>
          <CardContent>
            <div className="mt-4 flex items-center space-x-4">
              <ShieldAlert className={`h-8 w-8 ${suricataRunning ? 'text-emerald-500' : 'text-gray-400'}`} />
              <div>
                <div className="font-medium">
                  Status: {suricataRunning ? `Active (${suricataMode.toUpperCase()} / NFQUEUE)` : 'Disabled / Inactive'}
                </div>
                <div className="text-sm text-muted-foreground">
                  {suricataRunning
                    ? `PID: ${suricataService?.pid || 'active'} · Memory: ${suricataService?.memory || 'configured in security.yaml'}`
                    : 'Systemd service suricata.service is not currently active'}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <div>
              <CardTitle className="text-lg">CrowdSec Bouncer</CardTitle>
              <CardDescription>Collaborative network behavior reputation</CardDescription>
            </div>
            <Badge
              variant={crowdsecRunning ? 'default' : 'secondary'}
              className={crowdsecRunning ? 'bg-indigo-500' : ''}
            >
              {crowdsecRunning ? 'ONLINE' : 'STOPPED'}
            </Badge>
          </CardHeader>
          <CardContent>
            <div className="mt-4 flex items-center space-x-4">
              <Shield className={`h-8 w-8 ${crowdsecRunning ? 'text-indigo-500' : 'text-gray-400'}`} />
              <div>
                <div className="font-medium">
                  Status: {crowdsecRunning ? 'Active (nftables)' : 'Disabled / Inactive'}
                </div>
                <div className="text-sm text-muted-foreground">
                  {crowdsecRunning
                    ? `PID: ${crowdsecService?.pid || '--'} · Memory: ${crowdsecService?.memory || '--'}`
                    : 'Systemd service crowdsec.service is not currently active'}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent Threat Events</CardTitle>
          <CardDescription>Real-time stream from /var/log/suricata/eve.json</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center p-8 text-muted-foreground gap-3">
              <Loader2 className="w-5 h-5 animate-spin" />
              <span>Reading Suricata event telemetry...</span>
            </div>
          ) : alerts.length === 0 ? (
            <div className="border border-dashed rounded-lg p-8 text-center text-muted-foreground">
              <CheckCircle2 className="h-8 w-8 mx-auto mb-2 text-emerald-500/80" />
              <p className="font-medium text-foreground">No Threat Events Logged</p>
              <p className="text-xs mt-1">
                Zero security anomalies or intrusions recorded in the local IDS journal.
              </p>
            </div>
          ) : (
            <div className="rounded-md border overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50 dark:bg-zinc-900">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Timestamp</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Signature</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Dest</th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Action</th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-black divide-y divide-gray-200 dark:divide-zinc-800">
                  {alerts.map((alert, i) => (
                    <tr key={i}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        <Badge variant={alert.severity === 1 ? 'destructive' : 'secondary'}>
                          {alert.severity === 1 ? 'HIGH' : 'MEDIUM'}
                        </Badge>
                      </td>
                      <td className="px-6 py-4 text-sm font-medium">
                        {alert.signature}
                        <div className="text-xs text-muted-foreground font-normal">{alert.category}</div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-500">{alert.srcIp}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-500">{alert.dstIp}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-right">
                        <Badge className="bg-red-500 text-white flex items-center gap-1 ml-auto w-fit">
                          <Zap className="h-3 w-3" /> {alert.action === 'blocked' ? 'Blocked' : 'Alert'}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
