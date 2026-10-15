'use client';

import { useState, useMemo, useEffect } from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  ShieldAlert,
  Globe,
  Plus,
  Trash2,
  ShieldX,
  Terminal,
  RefreshCw,
  Sliders,
  Check,
} from 'lucide-react';
import type { DesiredState, DnsBlocklistConfig } from '@axonwall/lib/schemas';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import { compileUnboundSinkhole } from '@axonwall/lib/compile/unbound';

export default function DnsBlocklistPage() {
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [enabled, setEnabled] = useState(true);
  const [action, setAction] = useState<'always_null' | 'always_nxdomain'>('always_null');
  const [showConfigPreview, setShowConfigPreview] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

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
    {
      id: 'feed-abuse-ch',
      name: 'abuse.ch URLhaus Host & Domain Blocklist',
      url: 'https://urlhaus.abuse.ch/downloads/hostfile/',
      entriesCount: 19430,
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
    'beacon.analytics-tracker.net',
  ]);

  const [newWhiteDomain, setNewWhiteDomain] = useState('');
  const [newBlackDomain, setNewBlackDomain] = useState('');

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        setFullState(state);
        if (state.dns?.blocklist) {
          setEnabled(state.dns.blocklist.enabled);
          setAction(state.dns.blocklist.action || 'always_null');
          if (state.dns.blocklist.feeds?.length) {
            setFeeds(
              state.dns.blocklist.feeds.map((f, i) => ({
                id: f.id || `feed-${i}`,
                name: f.name,
                url: f.url,
                entriesCount: f.entriesCount || 0,
                enabled: f.enabled,
              }))
            );
          }
          if (state.dns.blocklist.whitelist) setWhitelist(state.dns.blocklist.whitelist);
          if (state.dns.blocklist.blacklist) setBlacklist(state.dns.blocklist.blacklist);
        }
      })
      .catch(() => {});
  }, []);

  const toggleFeed = (id: string) => {
    setFeeds(feeds.map((f) => (f.id === id ? { ...f, enabled: !f.enabled } : f)));
  };

  const compiledResult = useMemo(() => {
    const config: DnsBlocklistConfig = {
      enabled,
      feeds,
      whitelist,
      blacklist,
      action,
    };
    return compileUnboundSinkhole(config);
  }, [enabled, feeds, whitelist, blacklist, action]);

  const totalBlockedDomains =
    feeds.reduce((acc, f) => (f.enabled ? acc + f.entriesCount : acc), 0) + blacklist.length;

  const handleSave = async () => {
    setIsSaving(true);
    setSaveSuccess(false);
    try {
      const current = fullState || (await getCurrentDesiredState());
      const nextState: DesiredState = {
        ...current,
        dns: {
          ...current.dns,
          blocklist: {
            enabled,
            feeds: feeds.map((f) => ({
              name: f.name,
              url: f.url,
              entriesCount: f.entriesCount,
              enabled: f.enabled,
            })),
            whitelist,
            blacklist,
            action,
          },
        },
      };
      setFullState(nextState);
      await applyDesiredState(nextState);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } finally {
      setIsSaving(false);
    }
  };

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
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <ShieldX className="w-6 h-6 text-emerald-400" />
            <span>DNS Blocklist & Threat Sinkholing (Unbound RPZ)</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Network-wide malware, phishing, and ad-blocking sinkhole executed at sub-millisecond speeds in Unbound DNS.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => setShowConfigPreview(!showConfigPreview)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center gap-1.5 transition cursor-pointer"
          >
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>{showConfigPreview ? 'Hide Unbound Conf' : 'Preview Unbound Conf'}</span>
          </button>

          <button
            type="button"
            onClick={handleSave}
            disabled={isSaving}
            className="px-4 py-1.5 rounded-lg text-xs font-medium bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white flex items-center gap-1.5 transition cursor-pointer shadow"
          >
            {isSaving ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : saveSuccess ? (
              <Check className="w-3.5 h-3.5" />
            ) : (
              <ShieldCheck className="w-3.5 h-3.5" />
            )}
            <span>{isSaving ? 'Saving...' : saveSuccess ? 'Saved!' : 'Save & Deploy'}</span>
          </button>
        </div>
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
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider block">
              Sinkhole Action
            </span>
            <div className="flex items-center bg-slate-950 rounded p-0.5 border border-slate-800 text-[10px] font-mono">
              <button
                type="button"
                onClick={() => setAction('always_null')}
                className={`px-1.5 py-0.5 rounded cursor-pointer ${
                  action === 'always_null'
                    ? 'bg-emerald-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                0.0.0.0
              </button>
              <button
                type="button"
                onClick={() => setAction('always_nxdomain')}
                className={`px-1.5 py-0.5 rounded cursor-pointer ${
                  action === 'always_nxdomain'
                    ? 'bg-emerald-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                NXDOMAIN
              </button>
            </div>
          </div>
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

      {/* Unbound Config Preview (Collapsible) */}
      {showConfigPreview && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-white flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span>Generated Unbound Blocklist Configuration (/etc/unbound/unbound.conf.d/blocklist.conf)</span>
            </span>
            <span className="text-[11px] text-slate-400 font-mono">
              Pruned: {compiledResult.prunedSubdomains} redundant subdomains
            </span>
          </div>
          <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-300 max-h-56 overflow-y-auto leading-relaxed">
            {compiledResult.config}
          </pre>
        </div>
      )}

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
                  <button
                    type="button"
                    onClick={() => toggleFeed(f.id)}
                    className={`px-2.5 py-1 rounded text-xs font-mono font-bold cursor-pointer transition ${
                      f.enabled
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20'
                        : 'bg-slate-800 text-slate-500 border border-slate-700 hover:text-slate-300'
                    }`}
                  >
                    {f.enabled ? 'Enabled' : 'Disabled'}
                  </button>
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
