'use client';

import React, { useState } from 'react';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Shield, ShieldAlert, Zap } from 'lucide-react';
import { Switch } from '@/components/ui/switch';

export default function IdsIpsPage() {
  const [suricataEnabled, setSuricataEnabled] = useState(true);
  const [crowdsecEnabled, setCrowdsecEnabled] = useState(true);

  const recentAlerts = [
    {
      timestamp: new Date().toISOString(),
      signature: 'ET MALWARE Win32/CoinMiner.A Checkin',
      category: 'A Network Trojan was Detected',
      severity: 1,
      srcIp: '192.168.1.55',
      dstIp: '142.250.190.46',
      action: 'blocked'
    },
    {
      timestamp: new Date(Date.now() - 150000).toISOString(),
      signature: 'GPL SCAN SSH brute force login attempt',
      category: 'Attempted Information Leak',
      severity: 2,
      srcIp: '185.122.204.1',
      dstIp: '192.168.1.10',
      action: 'blocked'
    }
  ];

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
            <Switch checked={suricataEnabled} onCheckedChange={setSuricataEnabled} />
          </CardHeader>
          <CardContent>
            <div className="mt-4 flex items-center space-x-4">
              <ShieldAlert className={`h-8 w-8 ${suricataEnabled ? 'text-emerald-500' : 'text-gray-400'}`} />
              <div>
                <div className="font-medium">Status: {suricataEnabled ? 'Active (NFQUEUE)' : 'Disabled'}</div>
                <div className="text-sm text-muted-foreground">32,450 rules loaded (EmergingThreats Open)</div>
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
            <Switch checked={crowdsecEnabled} onCheckedChange={setCrowdsecEnabled} />
          </CardHeader>
          <CardContent>
            <div className="mt-4 flex items-center space-x-4">
              <Shield className={`h-8 w-8 ${crowdsecEnabled ? 'text-indigo-500' : 'text-gray-400'}`} />
              <div>
                <div className="font-medium">Status: {crowdsecEnabled ? 'Active (nftables)' : 'Disabled'}</div>
                <div className="text-sm text-muted-foreground">1,894,002 IPs blocked globally</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent Threat Events</CardTitle>
          <CardDescription>Real-time stream from eve.json</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
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
                {recentAlerts.map((alert, i) => (
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
                        <Zap className="h-3 w-3" /> Blocked
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
