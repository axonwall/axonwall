import React from 'react';
import type { NmapRun } from '../types/nmap';
import { Server, Activity, ShieldCheck, Layers, PieChart, BarChart2, Clock, Globe } from 'lucide-react';

export interface NmapStatsProps {
  scan: NmapRun;
  className?: string;
}

export function NmapStats({ scan, className = '' }: NmapStatsProps) {
  const totalHosts = scan.hosts.length;
  const upHosts = scan.hosts.filter((h) => h.status.state === 'up').length;
  const downHosts = totalHosts - upHosts;

  // Ports stats
  let openPortsCount = 0;
  let closedPortsCount = 0;
  let filteredPortsCount = 0;
  const serviceCounts = new Map<string, number>();
  const osCounts = new Map<string, number>();
  const subnetCounts = new Map<string, number>();
  let totalLatency = 0;
  let latencyCount = 0;

  for (const host of scan.hosts) {
    if (host.latencyMs !== undefined) {
      totalLatency += host.latencyMs;
      latencyCount++;
    }

    const osFam = host.osFamily || 'Unknown';
    osCounts.set(osFam, (osCounts.get(osFam) || 0) + 1);

    const sub = host.ipv4 ? `${host.ipv4.split('.').slice(0, 3).join('.')}.0/24` : 'Other';
    subnetCounts.set(sub, (subnetCounts.get(sub) || 0) + 1);

    for (const p of host.ports) {
      if (p.state === 'open') {
        openPortsCount++;
        const sName = p.service?.name || `Port ${p.portid}`;
        serviceCounts.set(sName, (serviceCounts.get(sName) || 0) + 1);
      } else if (p.state === 'closed') {
        closedPortsCount++;
      } else if (p.state === 'filtered') {
        filteredPortsCount++;
      }
    }
  }

  const avgLatency = latencyCount > 0 ? (totalLatency / latencyCount).toFixed(1) : 'N/A';
  const totalPortRecords = openPortsCount + closedPortsCount + filteredPortsCount || 1;

  // Sorted Top Services
  const topServices = Array.from(serviceCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);

  // Sorted OS Families
  const topOs = Array.from(osCounts.entries())
    .sort((a, b) => b[1] - a[1]);

  return (
    <div className={`space-y-6 ${className}`}>
      {/* 1. Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800/80">
          <div className="flex items-center justify-between text-xs text-zinc-400 mb-1">
            <span>Discovered Hosts</span>
            <Server size={15} className="text-sky-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">{totalHosts}</div>
          <div className="text-xs text-zinc-500 mt-1 flex items-center gap-1.5">
            <span className="text-emerald-400 font-semibold">{upHosts} Up</span> · <span>{downHosts} Down</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800/80">
          <div className="flex items-center justify-between text-xs text-zinc-400 mb-1">
            <span>Open Services/Ports</span>
            <ShieldCheck size={15} className="text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 font-mono">{openPortsCount}</div>
          <div className="text-xs text-zinc-500 mt-1">Across all live targets</div>
        </div>

        <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800/80">
          <div className="flex items-center justify-between text-xs text-zinc-400 mb-1">
            <span>Average Latency</span>
            <Activity size={15} className="text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">{avgLatency} {avgLatency !== 'N/A' && 'ms'}</div>
          <div className="text-xs text-zinc-500 mt-1">{latencyCount} responsive hosts</div>
        </div>

        <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800/80">
          <div className="flex items-center justify-between text-xs text-zinc-400 mb-1">
            <span>Scan Duration</span>
            <Clock size={15} className="text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">
            {scan.runstats?.finished.elapsed ? `${scan.runstats.finished.elapsed}s` : 'Completed'}
          </div>
          <div className="text-xs text-zinc-500 mt-1 font-mono text-[11px] truncate">Nmap v{scan.version}</div>
        </div>
      </div>

      {/* 2. Charts & Breakdowns */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Port States */}
        <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800/80 space-y-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-zinc-300 uppercase tracking-wider">
            <PieChart size={14} className="text-sky-400" />
            <span>Port State Distribution</span>
          </div>
          <div className="space-y-2.5 pt-1">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-emerald-400 font-medium">Open ({openPortsCount})</span>
                <span className="text-zinc-400 font-mono">{Math.round((openPortsCount / totalPortRecords) * 100)}%</span>
              </div>
              <div className="w-full h-2 bg-zinc-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-emerald-500 rounded-full"
                  style={{ width: `${(openPortsCount / totalPortRecords) * 100}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-amber-400 font-medium">Filtered ({filteredPortsCount})</span>
                <span className="text-zinc-400 font-mono">{Math.round((filteredPortsCount / totalPortRecords) * 100)}%</span>
              </div>
              <div className="w-full h-2 bg-zinc-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-amber-500 rounded-full"
                  style={{ width: `${(filteredPortsCount / totalPortRecords) * 100}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-zinc-400 font-medium">Closed ({closedPortsCount})</span>
                <span className="text-zinc-500 font-mono">{Math.round((closedPortsCount / totalPortRecords) * 100)}%</span>
              </div>
              <div className="w-full h-2 bg-zinc-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-zinc-600 rounded-full"
                  style={{ width: `${(closedPortsCount / totalPortRecords) * 100}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Operating Systems */}
        <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800/80 space-y-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-zinc-300 uppercase tracking-wider">
            <BarChart2 size={14} className="text-purple-400" />
            <span>Operating Systems</span>
          </div>
          <div className="space-y-2 pt-1">
            {topOs.map(([osName, count]) => (
              <div key={osName} className="flex items-center justify-between text-xs">
                <span className="text-zinc-300 truncate max-w-[150px]">{osName}</span>
                <div className="flex items-center gap-2">
                  <div className="w-24 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-purple-500 rounded-full"
                      style={{ width: `${(count / totalHosts) * 100}%` }}
                    />
                  </div>
                  <span className="font-mono text-zinc-400 w-4 text-right">{count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Discovered Services */}
        <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800/80 space-y-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-zinc-300 uppercase tracking-wider">
            <Layers size={14} className="text-emerald-400" />
            <span>Top Services</span>
          </div>
          <div className="space-y-2 pt-1">
            {topServices.length === 0 ? (
              <p className="text-xs text-zinc-500">No services identified</p>
            ) : (
              topServices.map(([sName, count]) => (
                <div key={sName} className="flex items-center justify-between text-xs">
                  <span className="text-zinc-300 font-mono uppercase">{sName}</span>
                  <div className="flex items-center gap-2">
                    <div className="w-24 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-emerald-500 rounded-full"
                        style={{ width: `${(count / (openPortsCount || 1)) * 100}%` }}
                      />
                    </div>
                    <span className="font-mono text-zinc-400 w-4 text-right">{count}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
