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
import { Button } from '@/components/ui/button';
import { Activity, Plus, ServerCrash, Settings2, ShieldCheck, Wifi } from 'lucide-react';

export default function GatewaysPage() {
  const [isRefreshing, setIsRefreshing] = useState(false);

  const gateways = [
    {
      name: 'WAN1_FIBER',
      interface: 'eth0',
      ip: '192.168.1.1',
      monitor: '8.8.8.8',
      status: 'online',
      latency: 12,
      packetLoss: 0,
      tier: 1,
    },
    {
      name: 'WAN2_5G',
      interface: 'eth1',
      ip: '10.0.0.1',
      monitor: '1.1.1.1',
      status: 'standby',
      latency: 45,
      packetLoss: 2,
      tier: 2,
    },
    {
      name: 'WAN3_STARLINK',
      interface: 'eth2',
      ip: '100.64.0.1',
      monitor: '9.9.9.9',
      status: 'offline',
      latency: 0,
      packetLoss: 100,
      tier: 3,
    },
  ];

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => setIsRefreshing(false), 1000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Multi-WAN Gateways</h1>
          <p className="text-muted-foreground mt-1">
            Configure gateway groups, load balancing, and automated SD-WAN failover.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={handleRefresh} disabled={isRefreshing}>
            {isRefreshing ? 'Probing...' : 'Probe Links'}
          </Button>
          <Button>
            <Plus className="h-4 w-4 mr-2" /> Add Gateway
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Links</CardTitle>
            <Wifi className="h-4 w-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">1 / 3</div>
            <p className="text-xs text-muted-foreground mt-1">Tier 1 routing active</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Average Latency</CardTitle>
            <Activity className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">12ms</div>
            <p className="text-xs text-muted-foreground mt-1">Across online gateways</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Gateway Groups</CardTitle>
            <Settings2 className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">1 Active</div>
            <p className="text-xs text-muted-foreground mt-1">Default Failover Group</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Configured Gateways</CardTitle>
          <CardDescription>
            Real-time link status based on active ICMP probing.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {gateways.map((gw) => (
              <div
                key={gw.name}
                className="flex items-center justify-between p-4 border rounded-lg"
              >
                <div className="flex items-center space-x-4">
                  <div
                    className={`p-2 rounded-full ${
                      gw.status === 'online'
                        ? 'bg-emerald-100 text-emerald-600 dark:bg-emerald-900 dark:text-emerald-400'
                        : gw.status === 'standby'
                        ? 'bg-yellow-100 text-yellow-600 dark:bg-yellow-900 dark:text-yellow-400'
                        : 'bg-red-100 text-red-600 dark:bg-red-900 dark:text-red-400'
                    }`}
                  >
                    {gw.status === 'online' ? (
                      <ShieldCheck className="h-5 w-5" />
                    ) : gw.status === 'standby' ? (
                      <Activity className="h-5 w-5" />
                    ) : (
                      <ServerCrash className="h-5 w-5" />
                    )}
                  </div>
                  <div>
                    <h3 className="font-medium flex items-center gap-2">
                      {gw.name}
                      {gw.tier === 1 && (
                        <Badge variant="secondary" className="text-[10px] h-4">Tier 1</Badge>
                      )}
                    </h3>
                    <div className="text-sm text-muted-foreground flex gap-3 mt-1">
                      <span>Dev: {gw.interface}</span>
                      <span>Next-Hop: {gw.ip}</span>
                      <span>Monitor: {gw.monitor}</span>
                    </div>
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1">
                  <Badge
                    variant={
                      gw.status === 'online'
                        ? 'default'
                        : gw.status === 'standby'
                        ? 'secondary'
                        : 'destructive'
                    }
                    className={
                      gw.status === 'online'
                        ? 'bg-emerald-500 hover:bg-emerald-600'
                        : gw.status === 'standby'
                        ? 'bg-yellow-500 hover:bg-yellow-600 text-white'
                        : ''
                    }
                  >
                    {gw.status.toUpperCase()}
                  </Badge>
                  {gw.status !== 'offline' && (
                    <div className="text-xs text-muted-foreground">
                      {gw.latency}ms / {gw.packetLoss}% loss
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Gateway Groups (Load Balancing / Failover)</CardTitle>
          <CardDescription>
            Group multiple gateways together to define tier-based failover or packet load balancing.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="border rounded-lg p-4">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h4 className="font-semibold text-lg">Default Failover</h4>
                <p className="text-sm text-muted-foreground">Active Policy: Tier-Based Failover</p>
              </div>
              <Button variant="outline" size="sm">Edit Group</Button>
            </div>
            
            <div className="space-y-2">
              <div className="flex justify-between text-sm py-1 border-b">
                <span className="font-medium text-emerald-600">Tier 1 (Active)</span>
                <span>WAN1_FIBER</span>
              </div>
              <div className="flex justify-between text-sm py-1 border-b">
                <span className="font-medium text-yellow-600">Tier 2 (Standby)</span>
                <span>WAN2_5G</span>
              </div>
              <div className="flex justify-between text-sm py-1">
                <span className="font-medium text-muted-foreground">Tier 3 (Standby)</span>
                <span>WAN3_STARLINK</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
