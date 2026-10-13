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
import { Shield, ShieldAlert, Zap, Loader2, CheckCircle2 } from 'lucide-react';
import { Switch } from '@/components/ui/switch';
import {
  getRecentThreatAlerts,
  getSystemServicesStatus,
  type ThreatAlert,
  type LiveServiceInfo,
} from '@/server/agent';

export default function IdsIpsPage() {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [services, setServices] = useState<LiveServiceInfo[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([getRecentThreatAlerts(), getSystemServicesStatus()])
      .then(([alertData, serviceData]) => {
        setAlerts(alertData);
        setServices(serviceData);
      })
      .catch(() => {
        setAlerts([]);
        setServices([]);
      })
      .finally(() => setLoading(false));
  }, []);

  const suricataService = services.find((s) => s.unit === 'suricata.service');
  const suricataRunning = suricataService?.status === 'active';

  const crowdsecService = services.find((s) => s.unit === 'crowdsec.service');
  const crowdsecRunning = crowdsecService?.status === 'active';

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Intrusion Prevention (IDS/IPS)</h1>
        <p className="text-muted-foreground mt-1">
          Automated threat defense utilizing Suricata AF_PACKET inspection and CrowdSec distributed IP reputation.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <div>
              <CardTitle className="text-lg">Suricata IPS Engine</CardTitle>
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
                  Status: {suricataRunning ? 'Active (NFQUEUE)' : 'Disabled / Inactive'}
                </div>
                <div className="text-sm text-muted-foreground">
                  {suricataRunning
                    ? `PID: ${suricataService?.pid || '--'} · Memory: ${suricataService?.memory || '--'}`
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
