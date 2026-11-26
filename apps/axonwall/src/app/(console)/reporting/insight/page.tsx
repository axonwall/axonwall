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
import { Activity, Network, ShieldAlert, Loader2 } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import {
  getNetworkInsightTelemetry,
  queryNetFlowAction,
  type NetFlowQueryRecordSnapshot,
  type NetworkInsightTelemetry,
} from '@/server/agent';

interface NodeOption {
  nodeId: string;
  nodeName: string;
  flowsCount: number;
}

export default function ReportingInsightPage() {
  const [telemetry, setTelemetry] = useState<NetworkInsightTelemetry | null>(null);
  const [timeData, setTimeData] = useState<{ time: string; rxKb: number; txKb: number }[]>([]);
  const [loading, setLoading] = useState(true);
  const [nodes, setNodes] = useState<NodeOption[]>([]);
  const [selectedNode, setSelectedNode] = useState<string>('local');
  const [nodeFlows, setNodeFlows] = useState<NetFlowQueryRecordSnapshot[]>([]);
  const [nodeLoading, setNodeLoading] = useState(false);

  useEffect(() => {
    fetch('/api/v1/netflow/nodes', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (Array.isArray(d?.nodes)) setNodes(d.nodes);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    let lastRx = 0;
    let lastTx = 0;

    const poll = async () => {
      try {
        const data = await getNetworkInsightTelemetry();
        setTelemetry(data);

        const now = new Date();
        const rxRate = lastRx > 0 && data.totalRxBytes >= lastRx ? Math.round((data.totalRxBytes - lastRx) / 2048) : 0;
        const txRate = lastTx > 0 && data.totalTxBytes >= lastTx ? Math.round((data.totalTxBytes - lastTx) / 2048) : 0;
        lastRx = data.totalRxBytes;
        lastTx = data.totalTxBytes;

        setTimeData((prev) => {
          const newData = [...prev, { time: now.toLocaleTimeString(), rxKb: rxRate, txKb: txRate }];
          if (newData.length > 20) newData.shift();
          return newData;
        });
      } catch {
      } finally {
        setLoading(false);
      }
    };

    poll();
    const interval = setInterval(poll, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (selectedNode === 'local') {
      setNodeFlows([]);
      return;
    }
    let active = true;
    setNodeLoading(true);
    queryNetFlowAction({
      rangeMinutes: 60,
      fql: selectedNode === 'all' ? '' : `node="${selectedNode.replace(/"/g, '')}"`,
      limit: 50,
    })
      .then((res) => {
        if (active) setNodeFlows(res.flows || []);
      })
      .catch(() => {
        if (active) setNodeFlows([]);
      })
      .finally(() => {
        if (active) setNodeLoading(false);
      });
    return () => {
      active = false;
    };
  }, [selectedNode]);

  const flows = telemetry?.flows || [];
  const currentRx = timeData[timeData.length - 1]?.rxKb || 0;
  const currentTx = timeData[timeData.length - 1]?.txKb || 0;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Live Network Insight</h1>
          <p className="text-muted-foreground mt-1">
            Real-time wire-speed kernel socket tracking, conntrack telemetry, and multi-node NetFlow analytics.
          </p>
        </div>

        <select
          aria-label="Insight node scope"
          value={selectedNode}
          onChange={(e) => setSelectedNode(e.target.value)}
          className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-white"
        >
          <option value="local">Local Kernel Sockets</option>
          <option value="all">All Nodes (NetFlow / ClickHouse 1h)</option>
          {nodes.map((n) => (
            <option key={n.nodeId} value={n.nodeId}>
              Node: {n.nodeName || n.nodeId} ({n.flowsCount})
            </option>
          ))}
        </select>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Live Throughput (RX / TX)</CardTitle>
            <Activity className="h-4 w-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono">
              ↓ {currentRx} KB/s &nbsp; ↑ {currentTx} KB/s
            </div>
            <p className="text-xs text-muted-foreground mt-1">Measured from /proc/net/dev</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Tracked Connections / Sockets</CardTitle>
            <Network className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono">{telemetry?.conntrackCount ?? '--'}</div>
            <p className="text-xs text-muted-foreground mt-1">
              {telemetry?.conntrackCount == null
                ? 'Conntrack count unavailable — /proc read failed'
                : 'Kernel nf_conntrack active entries'}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Observed NetFlow Nodes</CardTitle>
            <ShieldAlert className="h-4 w-4 text-sky-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono">{nodes.length}</div>
            <p className="text-xs text-muted-foreground mt-1">Distinct edge/satellite exporters indexed</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Bandwidth Rate History</CardTitle>
          <CardDescription>Aggregate traffic rate measured directly from kernel network subsystem.</CardDescription>
        </CardHeader>
        <CardContent className="h-[300px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeData}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="time" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} width={80} unit=" KB/s" />
              <Tooltip />
              <Area type="monotone" dataKey="rxKb" name="Download (RX)" stroke="#10b981" fill="#10b981" fillOpacity={0.2} />
              <Area type="monotone" dataKey="txKb" name="Upload (TX)" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.1} />
            </AreaChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {selectedNode === 'local' ? (
        <Card>
          <CardHeader>
            <CardTitle>Active Socket Connections</CardTitle>
            <CardDescription>Live TCP/UDP session states from host networking stack</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50 dark:bg-zinc-900">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Local Address:Port</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Peer Address:Port</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Protocol</th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">State</th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-black divide-y divide-gray-200 dark:divide-zinc-800">
                  {loading ? (
                    <tr>
                      <td colSpan={4} className="px-6 py-8 text-center text-sm text-gray-500">
                        <div className="flex items-center justify-center gap-2">
                          <Loader2 className="w-4 h-4 animate-spin text-emerald-500" />
                          <span>Scanning active network sockets...</span>
                        </div>
                      </td>
                    </tr>
                  ) : flows.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="px-6 py-8 text-center text-sm text-gray-500">
                        No active non-loopback TCP or UDP sessions detected.
                      </td>
                    </tr>
                  ) : (
                    flows.map((flow, i) => (
                      <tr key={i}>
                        <td className="px-6 py-3 whitespace-nowrap text-sm font-mono text-gray-900 dark:text-gray-100">{flow.srcIp}</td>
                        <td className="px-6 py-3 whitespace-nowrap text-sm font-mono text-gray-500">{flow.dstIp}</td>
                        <td className="px-6 py-3 whitespace-nowrap text-sm">
                          <Badge variant="outline">{flow.protocol}</Badge>
                        </td>
                        <td className="px-6 py-3 whitespace-nowrap text-sm text-right font-mono text-xs text-emerald-400">
                          {flow.state}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Aggregated Node Flows ({selectedNode})</CardTitle>
            <CardDescription>Historical &amp; real-time IPFIX/NetFlow sessions over the last 60 minutes</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50 dark:bg-zinc-900">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Destination</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Proto / App</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Interface</th>
                    <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">Bytes</th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-black divide-y divide-gray-200 dark:divide-zinc-800 font-mono text-xs">
                  {nodeLoading ? (
                    <tr>
                      <td colSpan={5} className="px-6 py-8 text-center text-gray-500">
                        Loading node flows...
                      </td>
                    </tr>
                  ) : nodeFlows.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-6 py-8 text-center text-gray-500">
                        No NetFlow records returned for node filter &quot;{selectedNode}&quot;.
                      </td>
                    </tr>
                  ) : (
                    nodeFlows.map((f, idx) => (
                      <tr key={f.id || idx}>
                        <td className="px-4 py-2.5">{f.srcIp}:{f.srcPort}</td>
                        <td className="px-4 py-2.5">{f.dstIp}:{f.dstPort}</td>
                        <td className="px-4 py-2.5">{f.protocolName} {f.appName ? `(${f.appName})` : ''}</td>
                        <td className="px-4 py-2.5">{f.inIfName || f.inIfIndex || '—'}</td>
                        <td className="px-4 py-2.5 text-right">{(f.bytes || 0).toLocaleString()} B</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
