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
import { Activity, Network, ShieldAlert } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface FlowRecord {
  srcIp: string;
  dstIp: string;
  protocol: number;
  packets: number;
  bytes: number;
}

export default function ReportingInsightPage() {
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [timeData, setTimeData] = useState<{ time: string; totalBytes: number }[]>([]);

  useEffect(() => {
    // Simulated WebSocket streaming (as a standalone UI demo without needing the actual socket server)
    const interval = setInterval(() => {
      const newFlows = Array.from({ length: 5 }).map(() => ({
        srcIp: `192.168.1.${Math.floor(Math.random() * 255)}`,
        dstIp: `${Math.floor(Math.random() * 255)}.0.0.1`,
        protocol: Math.random() > 0.5 ? 6 : 17,
        packets: Math.floor(Math.random() * 1000),
        bytes: Math.floor(Math.random() * 150000),
      })).sort((a, b) => b.bytes - a.bytes);

      setFlows(newFlows);

      const totalBytes = newFlows.reduce((acc, f) => acc + f.bytes, 0);
      const now = new Date();
      setTimeData(prev => {
        const newData = [...prev, { time: now.toLocaleTimeString(), totalBytes }];
        if (newData.length > 20) newData.shift();
        return newData;
      });
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Live Network Insight (eBPF)</h1>
        <p className="text-muted-foreground mt-1">
          Real-time wire-speed XDP flow tracking and bandwidth analytics.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">XDP Processed Bytes</CardTitle>
            <Activity className="h-4 w-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{(timeData[timeData.length - 1]?.totalBytes || 0) / 1000} KB/s</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active UDP/TCP Sessions</CardTitle>
            <Network className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{flows.length * 12}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">DDoS Mitigation Dropped</CardTitle>
            <ShieldAlert className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">0 pkts</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Bandwidth Flow (Top 50)</CardTitle>
          <CardDescription>Aggregate traffic rate measured directly in the kernel via eBPF.</CardDescription>
        </CardHeader>
        <CardContent className="h-[300px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeData}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="time" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} width={80} />
              <Tooltip />
              <Area type="monotone" dataKey="totalBytes" stroke="#10b981" fill="#10b981" fillOpacity={0.2} />
            </AreaChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Top Flows (Live Table)</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50 dark:bg-zinc-900">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source IP</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Destination IP</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Proto</th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Packets</th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Bytes</th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-black divide-y divide-gray-200 dark:divide-zinc-800">
                {flows.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-4 text-center text-sm text-gray-500">
                      Waiting for XDP telemetry stream...
                    </td>
                  </tr>
                ) : (
                  flows.map((flow, i) => (
                    <tr key={i}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">{flow.srcIp}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{flow.dstIp}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        <Badge variant="outline">{flow.protocol === 6 ? 'TCP' : 'UDP'}</Badge>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-right text-gray-500">{flow.packets.toLocaleString()}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-right text-gray-900 dark:text-gray-100 font-medium">
                        {(flow.bytes / 1024).toFixed(2)} KB
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
