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
import { Activity, Plus, ServerCrash, Settings2, ShieldCheck, Wifi, Loader2, Trash2 } from 'lucide-react';
import {
  getGatewaysTelemetry,
  getCurrentDesiredState,
  applyDesiredState,
  type LiveGatewayInfo,
} from '@/server/agent';
import type { DesiredState, Gateway, GatewayGroup } from '@axonwall/lib/schemas';

export default function GatewaysPage() {
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [gateways, setGateways] = useState<LiveGatewayInfo[]>([]);
  const [configuredGateways, setConfiguredGateways] = useState<Gateway[]>([]);
  const [gatewayGroups, setGatewayGroups] = useState<GatewayGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  // Add gateway form
  const [newName, setNewName] = useState('');
  const [newIface, setNewIface] = useState('wan');
  const [newIp, setNewIp] = useState('');
  const [newMonitor, setNewMonitor] = useState('1.1.1.1');

  const fetchGateways = async () => {
    try {
      const [data, state] = await Promise.all([getGatewaysTelemetry(), getCurrentDesiredState()]);
      setGateways(data);
      setFullState(state);
      setConfiguredGateways(state.gateways || []);
      setGatewayGroups(state.gatewayGroups || []);
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

  const handleAddGateway = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim() || !newIp.trim()) return;
    try {
      const current = fullState || (await getCurrentDesiredState());
      const nextGws: Gateway[] = [
        ...(current.gateways || []),
        {
          name: newName.trim(),
          interface: newIface,
          gatewayIp: newIp.trim(),
          monitorIp: newMonitor.trim() || '1.1.1.1',
          weight: 1,
          isDefault: (current.gateways || []).length === 0,
          enabled: true,
          description: 'Configured upstream gateway',
        },
      ];
      const nextState: DesiredState = { ...current, gateways: nextGws };
      setFullState(nextState);
      setConfiguredGateways(nextGws);
      const res = await applyDesiredState(nextState);
      setStatusMsg(res.message || 'Saved gateway to /etc/axonwall/routing.yaml');
      setNewName('');
      setNewIp('');
      setShowAddForm(false);
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to save gateway'}`);
    }
  };

  const handleDeleteConfiguredGateway = async (name: string) => {
    try {
      const current = fullState || (await getCurrentDesiredState());
      const nextGws = (current.gateways || []).filter((g) => g.name !== name);
      const nextState: DesiredState = { ...current, gateways: nextGws };
      setFullState(nextState);
      setConfiguredGateways(nextGws);
      const res = await applyDesiredState(nextState);
      setStatusMsg(res.message || 'Removed gateway from /etc/axonwall/routing.yaml');
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to delete gateway'}`);
    }
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
            Configure gateway groups, load balancing, and automated SD-WAN failover synced with{' '}
            <code className="text-emerald-400 font-mono">/etc/axonwall/routing.yaml</code>.
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
          <Button onClick={() => setShowAddForm(!showAddForm)}>
            <Plus className="h-4 w-4 mr-2" /> Add Gateway
          </Button>
        </div>
      </div>

      {statusMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300">
          {statusMsg}
        </div>
      )}

      {showAddForm && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Add Upstream Gateway (/etc/axonwall/routing.yaml)</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleAddGateway} className="grid grid-cols-1 md:grid-cols-5 gap-3">
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="Name (WAN2_FIBER)"
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
                required
              />
              <input
                type="text"
                value={newIface}
                onChange={(e) => setNewIface(e.target.value)}
                placeholder="Interface (wan)"
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
                required
              />
              <input
                type="text"
                value={newIp}
                onChange={(e) => setNewIp(e.target.value)}
                placeholder="Gateway IP (203.0.113.1)"
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
                required
              />
              <input
                type="text"
                value={newMonitor}
                onChange={(e) => setNewMonitor(e.target.value)}
                placeholder="Monitor IP (1.1.1.1)"
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
              <Button type="submit">Save to routing.yaml</Button>
            </form>
          </CardContent>
        </Card>
      )}

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
            <div className="text-2xl font-bold">{gatewayGroups.length} Active</div>
            <p className="text-xs text-muted-foreground mt-1">
              {configuredGateways.length} gateways in routing.yaml
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Configured & Live Gateways</CardTitle>
          <CardDescription>
            Real-time link status based on kernel routing table, ICMP probing, and /etc/axonwall/routing.yaml.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center p-8 text-muted-foreground gap-3">
              <Loader2 className="w-5 h-5 animate-spin" />
              <span>Scanning routing table and probing gateways...</span>
            </div>
          ) : gateways.length === 0 && configuredGateways.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <ServerCrash className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="font-medium">No Default Gateway Detected</p>
              <p className="text-xs mt-1">Configure an interface with a default route or click Add Gateway above.</p>
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
              {configuredGateways.map((cg) => (
                <div
                  key={`cfg-${cg.name}`}
                  className="flex items-center justify-between p-4 border border-emerald-500/20 rounded-lg bg-slate-900/40"
                >
                  <div>
                    <h3 className="font-medium text-white flex items-center gap-2 font-mono text-sm">
                      {cg.name}
                      <Badge variant="outline" className="text-[10px]">routing.yaml</Badge>
                    </h3>
                    <div className="text-xs text-slate-400 flex gap-3 mt-1 font-mono">
                      <span>Interface: {cg.interface}</span>
                      <span>Gateway IP: {cg.gatewayIp}</span>
                      <span>Monitor: {cg.monitorIp || '1.1.1.1'}</span>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleDeleteConfiguredGateway(cg.name)}
                    className="text-slate-400 hover:text-red-400 p-1"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
