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
import { Button } from '@/components/ui/button';
import { Activity, Plus, ServerCrash, Settings2, ShieldCheck, Wifi, Loader2 } from 'lucide-react';
import { getGatewaysTelemetry, type LiveGatewayInfo } from '@/server/agent';

export default function GatewaysPage() {
  const [gateways, setGateways] = useState<LiveGatewayInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchGateways = async () => {
    try {
      const data = await getGatewaysTelemetry();
      setGateways(data);
    } catch {
      setGateways([]);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchGateways();
  }, []);

  const handleRefresh = () => {
    setIsRefreshing(true);
    fetchGateways();
  };

  const onlineCount = gateways.filter((g) => g.status === 'online').length;
  const avgLatency =
    onlineCount > 0
      ? `${Math.round(gateways.filter((g) => g.status === 'online').reduce((acc, curr) => acc + curr.latency, 0) / onlineCount)}ms`
      : '--';

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
          <Button variant="outline" onClick={handleRefresh} disabled={isRefreshing || loading}>
            {isRefreshing ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" /> Probing...
              </>
            ) : (
              'Probe Links'
            )}
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
            <div className="text-2xl font-bold">
              {onlineCount} / {gateways.length}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {onlineCount > 0 ? 'Default route active' : 'No active upstream link'}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Average Latency</CardTitle>
            <Activity className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{avgLatency}</div>
            <p className="text-xs text-muted-foreground mt-1">Across online gateways</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Gateway Groups</CardTitle>
            <Settings2 className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">0 Active</div>
            <p className="text-xs text-muted-foreground mt-1">No Multi-WAN groups configured</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Configured Gateways</CardTitle>
          <CardDescription>
            Real-time link status based on kernel routing table and active ICMP probing.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center p-8 text-muted-foreground gap-3">
              <Loader2 className="w-5 h-5 animate-spin" />
              <span>Scanning routing table and probing gateways...</span>
            </div>
          ) : gateways.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <ServerCrash className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="font-medium">No Default Gateway Detected</p>
              <p className="text-xs mt-1">Configure an interface with a default route or DHCP client to enable gateway monitoring.</p>
            </div>
          ) : (
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
          )}
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
          <div className="border border-dashed rounded-lg p-6 text-center text-muted-foreground">
            <Settings2 className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <h4 className="font-medium text-foreground">No Gateway Groups Configured</h4>
            <p className="text-xs mt-1 max-w-sm mx-auto">
              Create a gateway group when you have two or more WAN interfaces to enable automatic failover or round-robin traffic distribution.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
