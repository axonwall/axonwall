'use client';

import { useState, useEffect } from 'react';
import {
  MapPin,
  Shield,
  ShieldAlert,
  Globe,
  CheckCircle2,
  AlertCircle,
  Search,
  Filter,
  RefreshCw,
  Code2,
  Trash2,
  Layers,
  ArrowRight
} from 'lucide-react';
import { compileGeoIp, COUNTRY_CIDR_TABLE } from '@axonwall/lib/compile/geoip';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import type { DesiredState, GeoIpConfig } from '@axonwall/lib/schemas';

interface CountryItem {
  code: string;
  name: string;
  region: string;
  flag: string;
  risk?: 'high' | 'medium' | 'normal';
}

const COUNTRIES: CountryItem[] = [
  { code: 'CN', name: 'China', region: 'Asia', flag: '🇨🇳', risk: 'high' },
  { code: 'RU', name: 'Russian Federation', region: 'Europe/Asia', flag: '🇷🇺', risk: 'high' },
  { code: 'KP', name: 'North Korea (DPRK)', region: 'Asia', flag: '🇰🇵', risk: 'high' },
  { code: 'IR', name: 'Iran (Islamic Republic)', region: 'Middle East', flag: '🇮🇷', risk: 'high' },
  { code: 'BY', name: 'Belarus', region: 'Europe', flag: '🇧🇾', risk: 'high' },
  { code: 'SY', name: 'Syrian Arab Republic', region: 'Middle East', flag: '🇸🇾', risk: 'high' },
  { code: 'RO', name: 'Romania', region: 'Europe', flag: '🇷🇴', risk: 'medium' },
  { code: 'US', name: 'United States', region: 'Americas', flag: '🇺🇸', risk: 'normal' },
  { code: 'CA', name: 'Canada', region: 'Americas', flag: '🇨🇦', risk: 'normal' },
  { code: 'GB', name: 'United Kingdom', region: 'Europe', flag: '🇬🇧', risk: 'normal' },
  { code: 'DE', name: 'Germany', region: 'Europe', flag: '🇩🇪', risk: 'normal' },
  { code: 'FR', name: 'France', region: 'Europe', flag: '🇫🇷', risk: 'normal' },
  { code: 'NL', name: 'Netherlands', region: 'Europe', flag: '🇳🇱', risk: 'normal' },
  { code: 'ES', name: 'Spain', region: 'Europe', flag: '🇪🇸', risk: 'normal' },
  { code: 'IT', name: 'Italy', region: 'Europe', flag: '🇮🇹', risk: 'normal' },
  { code: 'BR', name: 'Brazil', region: 'Americas', flag: '🇧🇷', risk: 'normal' },
  { code: 'IN', name: 'India', region: 'Asia', flag: '🇮🇳', risk: 'normal' },
  { code: 'AU', name: 'Australia', region: 'Oceania', flag: '🇦🇺', risk: 'normal' },
  { code: 'JP', name: 'Japan', region: 'Asia', flag: '🇯🇵', risk: 'normal' },
  { code: 'KR', name: 'South Korea', region: 'Asia', flag: '🇰🇷', risk: 'normal' },
];

export default function GeoIpPage() {
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [config, setConfig] = useState<GeoIpConfig>({
    enabled: true,
    mode: 'block',
    direction: 'in',
    countries: ['CN', 'RU', 'KP', 'IR', 'BY', 'SY'],
    excludedSubnets: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
    log: true,
    description: 'Automated line-rate boundary drop for high-threat origin nations',
  });

  const [search, setSearch] = useState('');
  const [showScript, setShowScript] = useState(false);
  const [savedMessage, setSavedMessage] = useState<string | null>(null);

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        setFullState(state);
        if (state.geoip) {
          setConfig(state.geoip);
        }
      })
      .catch(() => {});
  }, []);

  // Compile real-time preview of nftables interval sets
  const compiled = compileGeoIp(config);

  const filteredCountries = COUNTRIES.filter(
    (c) =>
      c.name.toLowerCase().includes(search.toLowerCase()) ||
      c.code.toLowerCase().includes(search.toLowerCase()) ||
      c.region.toLowerCase().includes(search.toLowerCase())
  );

  function toggleCountry(code: string) {
    setConfig((prev) => {
      const exists = prev.countries.includes(code);
      const updated = exists
        ? prev.countries.filter((c) => c !== code)
        : [...prev.countries, code];
      return { ...prev, countries: updated };
    });
  }

  function applyPreset(countries: string[], mode: 'block' | 'allow' = 'block') {
    setConfig((prev) => ({
      ...prev,
      mode,
      countries,
    }));
  }

  async function handleSave() {
    try {
      const current = fullState || (await getCurrentDesiredState());
      const nextState: DesiredState = {
        ...current,
        geoip: config,
      };
      setFullState(nextState);
      const res = await applyDesiredState(nextState);
      setSavedMessage(res.message || 'GeoIP configuration saved to /etc/axonwall/security.yaml.');
    } catch (err: any) {
      setSavedMessage(`Error: ${err?.message || 'Failed to save GeoIP policy'}`);
    }
    setTimeout(() => setSavedMessage(null), 4000);
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <MapPin className="w-5 h-5" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-white">GeoIP Location Filtering</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Native Linux kernel line-rate boundary enforcement using <code className="text-emerald-400">nftables</code> interval sets.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowScript(!showScript)}
            className="inline-flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium px-3.5 py-2 rounded-lg border border-slate-700 transition cursor-pointer"
          >
            <Code2 className="w-4 h-4 text-emerald-400" />
            <span>{showScript ? 'Hide nftables' : 'View nftables'}</span>
          </button>
          <button
            type="button"
            onClick={handleSave}
            className="bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition cursor-pointer flex items-center gap-2 shadow-sm"
          >
            <CheckCircle2 className="w-4 h-4" />
            <span>Apply GeoIP Policy</span>
          </button>
        </div>
      </div>

      {savedMessage && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-4 flex items-center gap-3 text-emerald-300 text-sm">
          <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-400" />
          <span>{savedMessage}</span>
        </div>
      )}

      {/* Main Settings Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 space-y-6">
          {/* Policy Controls */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-white">Filtering Status</h3>
                <p className="text-xs text-slate-400">Enable kernel GeoIP sets</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.enabled}
                  onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-600"></div>
              </label>
            </div>

            <div className="space-y-3 pt-3 border-t border-slate-800">
              <label className="block text-xs font-semibold text-slate-400 uppercase">
                Enforcement Mode
              </label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setConfig({ ...config, mode: 'block' })}
                  className={`py-2 px-3 text-xs font-medium rounded-lg border transition text-center ${
                    config.mode === 'block'
                      ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 font-semibold'
                      : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-white'
                  }`}
                >
                  Block / Blacklist
                </button>
                <button
                  type="button"
                  onClick={() => setConfig({ ...config, mode: 'allow' })}
                  className={`py-2 px-3 text-xs font-medium rounded-lg border transition text-center ${
                    config.mode === 'allow'
                      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 font-semibold'
                      : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-white'
                  }`}
                >
                  Allow / Whitelist
                </button>
              </div>
            </div>

            <div className="space-y-3 pt-3 border-t border-slate-800">
              <label className="block text-xs font-semibold text-slate-400 uppercase">
                Traffic Direction
              </label>
              <select
                value={config.direction}
                onChange={(e) => setConfig({ ...config, direction: e.target.value as any })}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
              >
                <option value="in">Inbound Connections Only</option>
                <option value="out">Outbound Connections Only</option>
                <option value="both">Bidirectional (Both In & Out)</option>
              </select>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-slate-800">
              <div>
                <span className="text-xs font-medium text-slate-300 block">Security Log Events</span>
                <span className="text-[11px] text-slate-500 block">Log dropped flows with prefix</span>
              </div>
              <input
                type="checkbox"
                checked={config.log}
                onChange={(e) => setConfig({ ...config, log: e.target.checked })}
                className="w-4 h-4 rounded bg-slate-950 border-slate-800 text-emerald-500 focus:ring-emerald-500"
              />
            </div>
          </div>

          {/* Quick Presets */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <h3 className="text-xs font-semibold text-slate-400 uppercase">One-Click Presets</h3>
            <div className="space-y-2">
              <button
                type="button"
                onClick={() => applyPreset(['CN', 'RU', 'KP', 'IR', 'BY', 'SY'], 'block')}
                className="w-full text-left text-xs p-2.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 transition flex items-center justify-between"
              >
                <span>Shield Against High-Risk Threat Origins</span>
                <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
              </button>
              <button
                type="button"
                onClick={() => applyPreset(['KP', 'IR', 'SY'], 'block')}
                className="w-full text-left text-xs p-2.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 transition flex items-center justify-between"
              >
                <span>Drop Embargoed Nations</span>
                <Shield className="w-3.5 h-3.5 text-amber-400" />
              </button>
              <button
                type="button"
                onClick={() => applyPreset(['US', 'CA', 'GB', 'DE', 'FR'], 'allow')}
                className="w-full text-left text-xs p-2.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 transition flex items-center justify-between"
              >
                <span>Domestic / Allied Whitelist Only</span>
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              </button>
              <button
                type="button"
                onClick={() => applyPreset([])}
                className="w-full text-left text-xs p-2.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-white transition flex items-center justify-between"
              >
                <span>Clear All Selected Countries</span>
                <Trash2 className="w-3.5 h-3.5 text-slate-500" />
              </button>
            </div>
          </div>
        </div>

        {/* Country Selector Matrix */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold text-white">Target Countries & Territories</h3>
                <p className="text-xs text-slate-400">
                  {config.countries.length} selected ({config.mode === 'block' ? 'Blocked' : 'Whitelisted'})
                </p>
              </div>

              <div className="relative w-full sm:w-64">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Filter country or code..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
                />
              </div>
            </div>

            {/* Selected Chips */}
            {config.countries.length > 0 && (
              <div className="flex flex-wrap gap-1.5 p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg">
                {config.countries.map((code) => {
                  const country = COUNTRIES.find((c) => c.code === code);
                  return (
                    <span
                      key={code}
                      onClick={() => toggleCountry(code)}
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium cursor-pointer border transition ${
                        config.mode === 'block'
                          ? 'bg-rose-500/10 text-rose-300 border-rose-500/30 hover:bg-rose-500/20'
                          : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30 hover:bg-emerald-500/20'
                      }`}
                    >
                      <span>{country?.flag || '🌐'}</span>
                      <span>{country?.name || code}</span>
                      <span className="text-[10px] text-slate-400">✕</span>
                    </span>
                  );
                })}
              </div>
            )}

            {/* Grid of Countries */}
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5 max-h-[460px] overflow-y-auto pr-1">
              {filteredCountries.map((c) => {
                const isSelected = config.countries.includes(c.code);
                const cidrCount = COUNTRY_CIDR_TABLE[c.code]?.length || 0;
                return (
                  <div
                    key={c.code}
                    onClick={() => toggleCountry(c.code)}
                    className={`p-3 rounded-lg border cursor-pointer transition flex items-center justify-between ${
                      isSelected
                        ? config.mode === 'block'
                          ? 'bg-rose-950/20 border-rose-500/40 text-white'
                          : 'bg-emerald-950/20 border-emerald-500/40 text-white'
                        : 'bg-slate-950 border-slate-800/80 hover:border-slate-700 text-slate-300'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span className="text-xl shrink-0">{c.flag}</span>
                      <div className="truncate">
                        <span className="text-xs font-medium block truncate">{c.name}</span>
                        <span className="text-[10px] text-slate-500 block">
                          {c.code} &bull; {cidrCount} aggregated CIDRs
                        </span>
                      </div>
                    </div>

                    <div className="shrink-0 ml-2">
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => {}}
                        className={`w-4 h-4 rounded bg-slate-900 border-slate-700 pointer-events-none ${
                          config.mode === 'block' ? 'text-rose-500' : 'text-emerald-500'
                        }`}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Generated nftables Modal / Card */}
      {showScript && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Code2 className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-white">Compiled Kernel nftables Output</h3>
            </div>
            <span className="text-xs font-mono text-slate-500">Atomic set size: {compiled.nftSetDefinitions.length} definitions</span>
          </div>
          <pre className="bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-xs text-emerald-400 overflow-x-auto whitespace-pre-wrap max-h-96">
            {`# Native nftables table inet axonwall set definition\n` +
              compiled.nftSetDefinitions.join('\n') +
              `\n\n# Chain input rules:\n` +
              compiled.inputRules.join('\n') +
              `\n\n# Chain forward rules:\n` +
              compiled.forwardRules.join('\n')}
          </pre>
        </div>
      )}
    </div>
  );
}
