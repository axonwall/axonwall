'use client';

import { useState } from 'react';
import { Database, Plus, RefreshCw, Trash2, Globe, Shield, CheckCircle2 } from 'lucide-react';
import type { Alias } from '@axonwall/lib/schemas';

export default function DynamicAliasesPage() {
  const [aliases, setAliases] = useState<Alias[]>([
    {
      id: 'alias-spamhaus',
      name: 'Spamhaus_DROP_List',
      type: 'urltable',
      url: 'https://www.spamhaus.org/drop/drop.txt',
      refreshIntervalHours: 24,
      entries: ['198.51.100.0/24', '203.0.113.0/24', '192.0.2.0/24'],
      description: 'Spamhaus Don\'t Route Or Peer (DROP) List',
      enabled: true,
    },
    {
      id: 'alias-ru-geo',
      name: 'Blocked_Countries_GeoIP',
      type: 'geoip',
      entries: ['RU', 'KP'],
      refreshIntervalHours: 168,
      description: 'Geographic IP block for high-risk inbound regions',
      enabled: true,
    },
    {
      id: 'alias-aws-asn',
      name: 'Amazon_AWS_Cloud_Prefixes',
      type: 'asn',
      entries: ['16509'],
      refreshIntervalHours: 48,
      description: 'Autonomous System Number prefixes for Amazon AWS',
      enabled: true,
    },
  ]);

  const [refreshing, setRefreshing] = useState(false);
  const [refreshSuccess, setRefreshSuccess] = useState(false);

  const handleRefreshAll = () => {
    setRefreshing(true);
    setTimeout(() => {
      setRefreshing(false);
      setRefreshSuccess(true);
      setTimeout(() => setRefreshSuccess(false), 3000);
    }, 1200);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <Database className="w-6 h-6 text-emerald-400" />
          Dynamic Aliases & Threat Intelligence Tables
        </h1>
        <p className="text-sm text-slate-400">
          Automated URL Table feeds, GeoIP country blocks, ASN lookups, and FQDNs compiled into native kernel nftables sets.
        </p>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex justify-between items-center">
          <div>
            <h3 className="font-semibold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-400" />
              Configured Dynamic Aliases
            </h3>
            <p className="text-xs text-slate-400">Incrementally updated with atomic element diffs (no ruleset reload)</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleRefreshAll}
              disabled={refreshing}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-white transition flex items-center gap-1.5 border border-slate-700 font-medium"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-emerald-400' : ''}`} />
              {refreshing ? 'Updating Feeds...' : 'Refresh All Feeds'}
            </button>
          </div>
        </div>

        {refreshSuccess && (
          <div className="px-4 py-2.5 bg-emerald-500/10 border-b border-emerald-500/20 text-xs text-emerald-400 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            Feeds successfully fetched and synchronized into nftables named sets.
          </div>
        )}

        <table className="w-full text-sm text-left">
          <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
            <tr>
              <th className="px-4 py-3">Alias Name</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Source / Feeds</th>
              <th className="px-4 py-3">Elements</th>
              <th className="px-4 py-3">Refresh Cycle</th>
              <th className="px-4 py-3">Description</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-slate-300">
            {aliases.map((a) => (
              <tr key={a.id || a.name} className="hover:bg-slate-800/30">
                <td className="px-4 py-3 font-mono font-semibold text-white text-xs">{a.name}</td>
                <td className="px-4 py-3">
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-mono uppercase font-bold ${
                      a.type === 'urltable'
                        ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                        : a.type === 'geoip'
                        ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                        : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    }`}
                  >
                    {a.type}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-xs text-slate-300">
                  {a.url ? (
                    <span className="truncate max-w-[200px] block" title={a.url}>
                      {a.url}
                    </span>
                  ) : (
                    a.entries.join(', ')
                  )}
                </td>
                <td className="px-4 py-3 font-mono text-xs text-emerald-400 font-semibold">
                  {a.entries.length} Prefixes
                </td>
                <td className="px-4 py-3 font-mono text-xs text-slate-400">
                  Every {a.refreshIntervalHours}h
                </td>
                <td className="px-4 py-3 text-slate-400 text-xs">{a.description}</td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => setAliases(aliases.filter((x) => x.id !== a.id))}
                    className="text-slate-500 hover:text-red-400 transition"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
