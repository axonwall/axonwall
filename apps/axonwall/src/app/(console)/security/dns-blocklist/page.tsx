'use client';

import { useState } from 'react';
import { ShieldCheck, CheckCircle2, ShieldAlert, Globe, Plus, Trash2, ShieldX } from 'lucide-react';
import type { DnsBlocklistConfig } from '@axonwall/lib/schemas';

export default function DnsBlocklistPage() {
  const [enabled, setEnabled] = useState(true);
  const [action, setAction] = useState<'always_null' | 'always_nxdomain'>('always_null');

  const [feeds, setFeeds] = useState([
    {
      id: 'feed-stevenblack',
      name: 'StevenBlack Unified Malware & Adware',
      url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
      entriesCount: 84210,
      enabled: true,
    },
    {
      id: 'feed-oisd',
      name: 'OISD Full Telemetry & Tracking Shield',
      url: 'https://big.oisd.nl/unbound',
      entriesCount: 154800,
      enabled: true,
    },
  ]);

  const [whitelist, setWhitelist] = useState<string[]>([
    'gateway.discord.gg',
    'app.datadoghq.com',
    'github.com',
  ]);

  const [blacklist, setBlacklist] = useState<string[]>([
    'telemetry.device-manufacturer.com',
    'adservice.evil-tracker.org',
  ]);

  const [newWhiteDomain, setNewWhiteDomain] = useState('');
  const [newBlackDomain, setNewBlackDomain] = useState('');

  const totalBlockedDomains = feeds.reduce((acc, f) => (f.enabled ? acc + f.entriesCount : acc), 0) + blacklist.length;

  const handleAddWhite = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newWhiteDomain || whitelist.includes(newWhiteDomain)) return;
    setWhitelist([...whitelist, newWhiteDomain.trim()]);
    setNewWhiteDomain('');
  };

  const handleAddBlack = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newBlackDomain || blacklist.includes(newBlackDomain)) return;
    setBlacklist([...blacklist, newBlackDomain.trim()]);
    setNewBlackDomain('');
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <ShieldX className="w-6 h-6 text-emerald-400" />
          DNS Blocklist & Threat Sinkholing (Unbound RPZ)
        </h1>
        <p className="text-sm text-slate-400">
          Network-wide malware, phishing, and ad-blocking sinkhole executed at sub-millisecond speeds in Unbound DNS.
        </p>
      </div>

      {/* Stats Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider block">
            Total Sinkholed Domains
          </span>
          <span className="text-2xl font-bold font-mono text-emerald-400 mt-1 block">
            {totalBlockedDomains.toLocaleString()}
          </span>
          <span className="text-[11px] text-slate-500 mt-0.5 block">Aggregated from active threat feeds</span>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider block">
            Sinkhole Action
          </span>
          <span className="text-xl font-bold font-mono text-white mt-1 block uppercase">
            {action === 'always_null' ? '0.0.0.0 (Null IP)' : 'NXDOMAIN (Not Found)'}
          </span>
          <span className="text-[11px] text-slate-500 mt-0.5 block">Instant rejection without timeout</span>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider block">
            DNS Protection State
          </span>
          <span className="text-xl font-bold font-mono text-emerald-400 mt-1 flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5" /> Active & Enforcing
          </span>
          <span className="text-[11px] text-slate-500 mt-0.5 block">Applied across all LAN subnets</span>
        </div>
      </div>

      {/* Blocklist Feeds */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex justify-between items-center">
          <div>
            <h3 className="font-semibold text-white">Community Threat Intelligence Feeds</h3>
            <p className="text-xs text-slate-400">Regularly updated curated malware and advertising blocklists</p>
          </div>
        </div>

        <table className="w-full text-sm text-left">
          <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
            <tr>
              <th className="px-4 py-3">Feed Name</th>
              <th className="px-4 py-3">URL</th>
              <th className="px-4 py-3">Blocked Entries</th>
              <th className="px-4 py-3 text-right">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-slate-300">
            {feeds.map((f) => (
              <tr key={f.id} className="hover:bg-slate-800/30">
                <td className="px-4 py-3 font-semibold text-white text-xs">{f.name}</td>
                <td className="px-4 py-3 font-mono text-xs text-slate-400 truncate max-w-xs">{f.url}</td>
                <td className="px-4 py-3 font-mono text-emerald-400 text-xs font-semibold">
                  {f.entriesCount.toLocaleString()} domains
                </td>
                <td className="px-4 py-3 text-right">
                  <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-xs font-mono font-bold border border-emerald-500/20">
                    Active
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Whitelist and Custom Blacklist */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Whitelist */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
          <div>
            <h4 className="font-semibold text-white text-sm flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              Domain Whitelist (Exemptions)
            </h4>
            <p className="text-xs text-slate-400">Domains that will always resolve normally (transparent)</p>
          </div>

          <form onSubmit={handleAddWhite} className="flex gap-2">
            <input
              type="text"
              value={newWhiteDomain}
              onChange={(e) => setNewWhiteDomain(e.target.value)}
              placeholder="e.g. tracking.allowed-company.com"
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-emerald-500 font-mono"
            />
            <button
              type="submit"
              className="bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium px-3 py-1.5 rounded-lg transition"
            >
              Add
            </button>
          </form>

          <div className="space-y-1.5">
            {whitelist.map((domain) => (
              <div
                key={domain}
                className="p-2 bg-slate-950 rounded border border-slate-800 flex items-center justify-between text-xs font-mono"
              >
                <span className="text-slate-300">{domain}</span>
                <button
                  onClick={() => setWhitelist(whitelist.filter((d) => d !== domain))}
                  className="text-slate-500 hover:text-red-400"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Custom Blacklist */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
          <div>
            <h4 className="font-semibold text-white text-sm flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              Custom Blacklist (Direct Sinkhole)
            </h4>
            <p className="text-xs text-slate-400">Local domain rules to immediately block across the network</p>
          </div>

          <form onSubmit={handleAddBlack} className="flex gap-2">
            <input
              type="text"
              value={newBlackDomain}
              onChange={(e) => setNewBlackDomain(e.target.value)}
              placeholder="e.g. telemetry.unwanted.org"
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-emerald-500 font-mono"
            />
            <button
              type="submit"
              className="bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium px-3 py-1.5 rounded-lg transition"
            >
              Add
            </button>
          </form>

          <div className="space-y-1.5">
            {blacklist.map((domain) => (
              <div
                key={domain}
                className="p-2 bg-slate-950 rounded border border-slate-800 flex items-center justify-between text-xs font-mono"
              >
                <span className="text-slate-300">{domain}</span>
                <button
                  onClick={() => setBlacklist(blacklist.filter((d) => d !== domain))}
                  className="text-slate-500 hover:text-red-400"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
