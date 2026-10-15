'use client';

import { useState, useMemo, useEffect } from 'react';
import {
  Database,
  Plus,
  RefreshCw,
  Trash2,
  Globe,
  Shield,
  CheckCircle2,
  Terminal,
  ExternalLink,
  Flame,
} from 'lucide-react';
import type { DesiredState, Alias } from '@axonwall/lib/schemas';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import { COMMUNITY_THREAT_FEEDS, compileThreatFeedNft } from '@axonwall/lib/alias';

export default function DynamicAliasesPage() {
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [aliases, setAliases] = useState<Alias[]>([
    {
      name: 'Spamhaus_DROP_List',
      type: 'urltable',
      url: 'https://www.spamhaus.org/drop/drop.txt',
      refreshIntervalHours: 24,
      entries: ['198.51.100.0/24', '203.0.113.0/24', '192.0.2.0/24'],
      description: "Spamhaus Don't Route Or Peer (DROP) List",
      enabled: true,
    },
    {
      name: 'Blocked_Countries_GeoIP',
      type: 'geoip',
      entries: ['RU', 'KP'],
      refreshIntervalHours: 168,
      description: 'Geographic IP block for high-risk inbound regions',
      enabled: true,
    },
    {
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
  const [showNftPreview, setShowNftPreview] = useState(false);

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        setFullState(state);
        if (state.aliases?.length) {
          setAliases(state.aliases);
        }
      })
      .catch(() => {});
  }, []);

  const persistAliases = async (nextAliases: Alias[]) => {
    setAliases(nextAliases);
    setRefreshing(true);
    try {
      const current = fullState || (await getCurrentDesiredState());
      const nextState: DesiredState = {
        ...current,
        aliases: nextAliases,
      };
      setFullState(nextState);
      await applyDesiredState(nextState);
      setRefreshSuccess(true);
      setTimeout(() => setRefreshSuccess(false), 3000);
    } catch {}
    setRefreshing(false);
  };

  const handleRefreshAll = () => {
    persistAliases(aliases);
  };

  const handleSubscribeFeed = (feed: (typeof COMMUNITY_THREAT_FEEDS)[0]) => {
    const existing = aliases.find((a) => a.url === feed.url);
    if (existing) return;

    const newAlias: Alias = {
      name: feed.name.replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 31),
      type: 'urltable',
      url: feed.url,
      refreshIntervalHours: 24,
      entries: ['198.51.100.0/24', '203.0.113.0/24'],
      description: feed.description,
      enabled: true,
    };

    persistAliases([...aliases, newAlias]);
  };

  const compiledNftOutput = useMemo(() => {
    const sampleCidrs = aliases
      .filter((a) => a.enabled)
      .flatMap((a) => a.entries);
    return compileThreatFeedNft(sampleCidrs, {
      tableName: 'axonwall',
      setName: 'threat_feeds',
      chunkSize: 10,
    });
  }, [aliases]);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Database className="w-6 h-6 text-emerald-400" />
            <span>Dynamic Aliases & Threat Intelligence Tables</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Automated URL Table feeds, GeoIP country blocks, ASN lookups, and FQDNs compiled into native kernel nftables sets.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowNftPreview(!showNftPreview)}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition flex items-center gap-1.5 border border-slate-700 font-medium cursor-pointer"
          >
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>{showNftPreview ? 'Hide nft Commands' : 'Preview nft Batch'}</span>
          </button>

          <button
            type="button"
            onClick={handleRefreshAll}
            disabled={refreshing}
            className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs text-white transition flex items-center gap-1.5 shadow font-medium cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            <span>{refreshing ? 'Updating Feeds...' : 'Refresh All Feeds'}</span>
          </button>
        </div>
      </div>

      {/* Community Threat Feeds Directory */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Flame className="w-4 h-4 text-amber-400" />
            <span className="text-sm font-semibold text-white">
              Curated Community Threat Intelligence Feeds
            </span>
          </div>
          <span className="text-xs text-slate-400">
            One-click subscription into kernel-level interval sets
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {COMMUNITY_THREAT_FEEDS.map((feed) => {
            const isSubscribed = aliases.some((a) => a.url === feed.url);
            return (
              <div
                key={feed.id}
                className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 flex flex-col justify-between space-y-3"
              >
                <div>
                  <div className="flex items-center justify-between gap-1">
                    <span className="font-semibold text-white text-xs">{feed.name}</span>
                    <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-slate-800 text-amber-400">
                      {feed.category}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                    {feed.description}
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => handleSubscribeFeed(feed)}
                  disabled={isSubscribed}
                  className={`w-full py-1.5 rounded text-xs font-medium transition flex items-center justify-center gap-1 cursor-pointer ${
                    isSubscribed
                      ? 'bg-slate-800 text-slate-500 border border-slate-700'
                      : 'bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600/30 border border-emerald-500/40'
                  }`}
                >
                  {isSubscribed ? (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Subscribed</span>
                    </>
                  ) : (
                    <>
                      <Plus className="w-3.5 h-3.5" />
                      <span>Subscribe Feed</span>
                    </>
                  )}
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* nftables Batch Commands Preview */}
      {showNftPreview && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-white flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span>Generated Linux Kernel nftables Batch Script</span>
            </span>
            <span className="text-[11px] text-slate-400 font-mono">
              Pruned: {compiledNftOutput.prunedEnclosedEntries} enclosed CIDRs | Unique: {compiledNftOutput.uniqueEntries}
            </span>
          </div>
          <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-300 max-h-56 overflow-y-auto leading-relaxed">
            {compiledNftOutput.nftCommands.join('\n')}
          </pre>
        </div>
      )}

      {/* Configured Dynamic Aliases Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex justify-between items-center">
          <div>
            <h3 className="font-semibold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-400" />
              Configured Dynamic Aliases
            </h3>
            <p className="text-xs text-slate-400">Incrementally updated with atomic element diffs (no ruleset reload)</p>
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
                    type="button"
                    onClick={() => persistAliases(aliases.filter((x) => x.name !== a.name))}
                    className="text-slate-500 hover:text-red-400 transition cursor-pointer"
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
