import React, { useState, useMemo } from 'react';
import type { NmapHost, NmapRun, HostAction } from '../types/nmap';
import { getHostIcon } from '../icons/index';
import {
  Search,
  ArrowUpDown,
  Download,
  Filter,
  Shield,
  Activity,
  Server,
  ChevronRight,
  Zap,
  Radio,
} from 'lucide-react';

export interface HostTableProps {
  scan: NmapRun;
  onSelectHost?: (host: NmapHost) => void;
  onUpdateHost?: (hostId: string, updater: (prev: NmapHost) => NmapHost | Partial<NmapHost>) => void;
  customActions?: HostAction[];
  className?: string;
}

type SortField = 'ip' | 'hostname' | 'status' | 'os' | 'ports' | 'latency';

export function HostTable({
  scan,
  onSelectHost,
  onUpdateHost,
  customActions = [],
  className = '',
}: HostTableProps) {
  const [search, setSearch] = useState('');
  const [sortField, setSortField] = useState<SortField>('ip');
  const [sortAsc, setSortAsc] = useState(true);
  const [statusFilter, setStatusFilter] = useState<'all' | 'up' | 'down'>('all');
  const [onlyOpenPorts, setOnlyOpenPorts] = useState<boolean>(false);

  const filteredHosts = useMemo(() => {
    const q = search.trim().toLowerCase();
    return scan.hosts.filter((h) => {
      if (statusFilter !== 'all' && h.status.state !== statusFilter) return false;
      if (onlyOpenPorts && !h.ports.some((p) => p.state === 'open')) return false;
      if (!q) return true;

      const ip = (h.ipv4 || h.ipv6 || h.id).toLowerCase();
      const name = (h.primaryHostname || '').toLowerCase();
      const os = (h.primaryOs || h.osFamily || '').toLowerCase();
      const services = h.ports
        .map((p) => `${p.portid} ${p.service?.name || ''}`)
        .join(' ')
        .toLowerCase();

      return ip.includes(q) || name.includes(q) || os.includes(q) || services.includes(q);
    });
  }, [scan.hosts, search, statusFilter, onlyOpenPorts]);

  const sortedHosts = useMemo(() => {
    return [...filteredHosts].sort((a, b) => {
      let valA: any = '';
      let valB: any = '';

      switch (sortField) {
        case 'ip':
          valA = a.ipv4 || a.id;
          valB = b.ipv4 || b.id;
          break;
        case 'hostname':
          valA = a.primaryHostname || '';
          valB = b.primaryHostname || '';
          break;
        case 'status':
          valA = a.status.state;
          valB = b.status.state;
          break;
        case 'os':
          valA = a.primaryOs || a.osFamily || '';
          valB = b.primaryOs || b.osFamily || '';
          break;
        case 'ports':
          valA = a.ports.filter((p) => p.state === 'open').length;
          valB = b.ports.filter((p) => p.state === 'open').length;
          break;
        case 'latency':
          valA = a.latencyMs || 99999;
          valB = b.latencyMs || 99999;
          break;
      }

      if (valA < valB) return sortAsc ? -1 : 1;
      if (valA > valB) return sortAsc ? 1 : -1;
      return 0;
    });
  }, [filteredHosts, sortField, sortAsc]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortAsc((a) => !a);
    } else {
      setSortField(field);
      setSortAsc(true);
    }
  };

  const exportCsv = () => {
    const headers = ['IP Address', 'Hostname', 'Status', 'Operating System', 'Open Ports', 'Latency (ms)'];
    const rows = sortedHosts.map((h) => [
      h.ipv4 || h.id,
      h.primaryHostname || '',
      h.status.state,
      h.primaryOs || h.osFamily || 'Unknown',
      h.ports.filter((p) => p.state === 'open').map((p) => `${p.portid}/${p.protocol}`).join('; '),
      h.latencyMs !== undefined ? h.latencyMs : '',
    ]);

    const escapeCsvCell = (val: unknown): string => {
      const str = String(val ?? '');
      const neutralized = /^[=+\-@\t\r]/.test(str) ? `'${str}` : str;
      return `"${neutralized.replace(/"/g, '""')}"`;
    };

    const csvContent = [
      headers.map(escapeCsvCell).join(','),
      ...rows.map((r) => r.map(escapeCsvCell).join(',')),
    ].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nmap-hosts-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className={`rounded-2xl bg-zinc-950 border border-zinc-800/80 overflow-hidden flex flex-col ${className}`}>
      {/* Top Search & Filter bar */}
      <div className="p-4 bg-zinc-900/80 border-b border-zinc-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 flex-1 min-w-[240px]">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-2.5 text-zinc-400" />
            <input
              type="text"
              placeholder="Filter hosts by IP, hostname, OS, port, service..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-zinc-950 border border-zinc-800 text-xs text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-sky-500 font-sans"
            />
          </div>

          <div className="flex items-center bg-zinc-950 p-1 rounded-lg border border-zinc-800 text-xs font-medium">
            <button
              onClick={() => setStatusFilter('all')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                statusFilter === 'all' ? 'bg-sky-600 text-white font-semibold' : 'text-zinc-400 hover:text-white'
              }`}
            >
              All ({scan.hosts.length})
            </button>
            <button
              onClick={() => setStatusFilter(statusFilter === 'up' ? 'all' : 'up')}
              className={`px-2.5 py-1 rounded-md transition-colors flex items-center gap-1.5 ${
                statusFilter === 'up' ? 'bg-emerald-600 text-white font-semibold' : 'text-zinc-400 hover:text-white'
              }`}
              title="Filter to hosts that responded to ping (state=up)"
            >
              <Radio size={11} className={statusFilter === 'up' ? 'text-white animate-pulse' : 'text-emerald-400'} />
              <span>Ping Up ({scan.hosts.filter((h) => h.status.state === 'up').length})</span>
            </button>
            <button
              onClick={() => setOnlyOpenPorts((v) => !v)}
              className={`px-2.5 py-1 rounded-md transition-colors flex items-center gap-1.5 ${
                onlyOpenPorts ? 'bg-amber-600 text-white font-semibold' : 'text-zinc-400 hover:text-white'
              }`}
              title="Filter out hosts with zero open ports"
            >
              <Shield size={12} className={onlyOpenPorts ? 'text-amber-200' : 'text-zinc-500'} />
              <span>With Open Ports ({scan.hosts.filter((h) => h.ports.some((p) => p.state === 'open')).length})</span>
            </button>
          </div>
        </div>

        <button
          onClick={exportCsv}
          className="px-3 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-xs font-semibold text-zinc-200 flex items-center gap-1.5 transition-colors"
        >
          <Download size={13} />
          <span>Export CSV</span>
        </button>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-sans">
          <thead className="bg-zinc-900/60 border-b border-zinc-800 text-zinc-400 font-semibold uppercase tracking-wider text-[11px]">
            <tr>
              <th className="py-3 px-4 cursor-pointer hover:text-white" onClick={() => handleSort('ip')}>
                <div className="flex items-center gap-1">
                  <span>Host IP</span>
                  <ArrowUpDown size={12} />
                </div>
              </th>
              <th className="py-3 px-4 cursor-pointer hover:text-white" onClick={() => handleSort('hostname')}>
                <div className="flex items-center gap-1">
                  <span>Hostname</span>
                  <ArrowUpDown size={12} />
                </div>
              </th>
              <th className="py-3 px-4 cursor-pointer hover:text-white" onClick={() => handleSort('status')}>
                <div className="flex items-center gap-1">
                  <span>Status</span>
                  <ArrowUpDown size={12} />
                </div>
              </th>
              <th className="py-3 px-4 cursor-pointer hover:text-white" onClick={() => handleSort('os')}>
                <div className="flex items-center gap-1">
                  <span>OS / Device</span>
                  <ArrowUpDown size={12} />
                </div>
              </th>
              <th className="py-3 px-4 cursor-pointer hover:text-white" onClick={() => handleSort('ports')}>
                <div className="flex items-center gap-1">
                  <span>Open Ports</span>
                  <ArrowUpDown size={12} />
                </div>
              </th>
              <th className="py-3 px-4 cursor-pointer hover:text-white" onClick={() => handleSort('latency')}>
                <div className="flex items-center gap-1">
                  <span>Latency</span>
                  <ArrowUpDown size={12} />
                </div>
              </th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-850">
            {sortedHosts.map((host) => {
              const IconComp = getHostIcon(host.osFamily, host.deviceType);
              const openPorts = host.ports.filter((p) => p.state === 'open');

              return (
                <tr
                  key={host.id}
                  onClick={() => onSelectHost && onSelectHost(host)}
                  className="hover:bg-zinc-900/50 cursor-pointer transition-colors group"
                >
                  <td className="py-3 px-4 font-mono font-bold text-sky-400">
                    <div className="flex items-center gap-2">
                      <IconComp size={15} className="text-zinc-400 group-hover:text-sky-400 transition-colors" />
                      <span>{host.ipv4 || host.ipv6 || host.id}</span>
                    </div>
                  </td>
                  <td className="py-3 px-4 text-zinc-200 font-medium">
                    {host.primaryHostname || '-'}
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex flex-col gap-0.5 items-start">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase flex items-center gap-1 ${
                          host.status.state === 'up'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                            : 'bg-rose-950 text-rose-400 border border-rose-800/60'
                        }`}
                      >
                        <Radio size={9} className={host.status.state === 'up' ? 'text-emerald-400' : 'text-rose-400'} />
                        <span>{host.status.state}</span>
                      </span>
                      {host.status.reason && (
                        <span className="text-[9.5px] font-mono text-zinc-500 truncate max-w-[110px]" title={`Ping response reason: ${host.status.reason}`}>
                          {host.status.reason}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 px-4 text-zinc-300">
                    <div>{host.primaryOs || host.osFamily || 'Unknown'}</div>
                    <span className="text-[10px] text-zinc-500 capitalize">{host.deviceType}</span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex flex-wrap gap-1 max-w-xs">
                      {openPorts.length === 0 ? (
                        <span className="text-zinc-500 font-mono">-</span>
                      ) : (
                        openPorts.slice(0, 4).map((p) => (
                          <span
                            key={p.portid}
                            className="px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-300 font-mono text-[10px]"
                          >
                            {p.portid}/{p.protocol}
                          </span>
                        ))
                      )}
                      {openPorts.length > 4 && (
                        <span className="text-zinc-500 text-[10px] font-mono self-center">
                          +{openPorts.length - 4} more
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono text-zinc-400">
                    {host.latencyMs !== undefined ? `${host.latencyMs} ms` : '-'}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <div className="flex items-center justify-end gap-1">
                      {customActions.map((action) => {
                        if (action.isVisible && !action.isVisible(host)) return null;
                        const disabled = action.isDisabled && action.isDisabled(host);
                        return (
                          <button
                            key={action.id}
                            disabled={disabled}
                            onClick={async (e) => {
                              e.stopPropagation();
                              const res = await action.onClick(host, {
                                updateHost: (updater) => {
                                  if (onUpdateHost) onUpdateHost(host.id, updater);
                                },
                                scan,
                              });
                              if (res && onUpdateHost) {
                                onUpdateHost(host.id, () => res);
                              }
                            }}
                            className={`p-1.5 rounded text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors ${
                              disabled ? 'opacity-40 cursor-not-allowed' : ''
                            }`}
                            title={action.tooltip || action.label}
                          >
                            {action.icon || <Zap size={14} />}
                          </button>
                        );
                      })}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectHost && onSelectHost(host);
                        }}
                        className="p-1 rounded text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors"
                        title="Inspect Host"
                      >
                        <ChevronRight size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
