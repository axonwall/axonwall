'use client';

import React, { useState, useEffect } from 'react';
import {
  Boxes,
  Shield,
  Activity,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
  Power,
  RefreshCw,
  Search,
  Filter,
} from 'lucide-react';
import {
  listSecurityModulesAction,
  toggleSecurityModuleAction,
  type SecurityModuleStatus,
} from '@/server/vigilante';

export default function SecurityModulesPage() {
  const [modules, setModules] = useState<SecurityModuleStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [statusBanner, setStatusBanner] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      const res = await listSecurityModulesAction();
      setModules(res);
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || 'Failed to load security modules' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleToggle = async (id: string, currentEnabled: boolean) => {
    setTogglingId(id);
    setStatusBanner(null);
    const res = await toggleSecurityModuleAction(id, !currentEnabled);
    setTogglingId(null);

    if (res.success) {
      setStatusBanner({ type: 'success', message: `${id} ${!currentEnabled ? 'enabled' : 'disabled'}` });
      setModules((prev) =>
        prev.map((m) => (m.id === id ? { ...m, enabled: !currentEnabled, health: !currentEnabled ? 'healthy' : 'offline' } : m))
      );
    } else {
      setStatusBanner({ type: 'error', message: res.message });
    }
  };

  const filteredModules = modules.filter((m) => {
    if (categoryFilter !== 'all' && m.category !== categoryFilter) return false;
    if (search && !m.name.toLowerCase().includes(search.toLowerCase()) && !m.description.toLowerCase().includes(search.toLowerCase())) {
      return false;
    }
    return true;
  });

  const categories = [
    { id: 'all', label: 'All Modules (12)' },
    { id: 'threat_detection', label: 'Threat Detection' },
    { id: 'siem_edr', label: 'SIEM & EDR' },
    { id: 'ad_identity', label: 'Active Directory' },
    { id: 'vulnerability', label: 'Vulnerability / DAST' },
    { id: 'deception', label: 'Deception & Canaries' },
    { id: 'purple_team', label: 'Purple Team' },
  ];

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <Boxes className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Vigilante Security Modules</h1>
            <p className="text-sm text-slate-400">
              12 integrated security subsystems spanning detection, identity auditing, SIEM, and automated purple teaming.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search module..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-56"
            />
          </div>
          <button
            onClick={loadData}
            className="p-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-xl text-slate-400 hover:text-white transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {statusBanner && (
        <div
          className={`p-4 rounded-xl border text-xs font-medium flex items-center justify-between ${
            statusBanner.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
          }`}
        >
          <span>{statusBanner.message}</span>
          <button onClick={() => setStatusBanner(null)} className="text-slate-400 hover:text-white">
            ×
          </button>
        </div>
      )}

      {/* Categories Bar */}
      <div className="flex flex-wrap gap-2">
        {categories.map((cat) => (
          <button
            key={cat.id}
            onClick={() => setCategoryFilter(cat.id)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              categoryFilter === cat.id
                ? 'bg-cyan-500/20 border border-cyan-500/40 text-cyan-300'
                : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            {cat.label}
          </button>
        ))}
      </div>

      {/* Modules Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredModules.map((mod) => (
          <div
            key={mod.id}
            className={`p-6 rounded-2xl border transition-all flex flex-col justify-between gap-6 ${
              mod.enabled
                ? 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
                : 'bg-slate-950/40 border-slate-900 opacity-70'
            }`}
          >
            <div className="space-y-4">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <h3 className="text-base font-semibold text-white">{mod.name}</h3>
                  <div className="text-[11px] text-cyan-400 font-mono mt-0.5">{mod.subdomain}.axonwall.internal</div>
                </div>
                <div
                  className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    mod.enabled
                      ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      : 'bg-slate-800 text-slate-400 border border-slate-700'
                  }`}
                >
                  {mod.health}
                </div>
              </div>

              <p className="text-xs text-slate-400 leading-relaxed">{mod.description}</p>

              <div className="grid grid-cols-2 gap-2 text-xs pt-2 border-t border-slate-800/80">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block">Port</span>
                  <span className="font-mono text-slate-300 font-medium">:{mod.port}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block">Throughput</span>
                  <span className="font-mono text-emerald-400 font-medium">
                    {mod.telemetryEps > 0 ? `${mod.telemetryEps} EPS` : 'Idle'}
                  </span>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-between gap-3 pt-4 border-t border-slate-800/80">
              <span className="text-[11px] text-slate-500 capitalize">{mod.category.replace('_', ' ')}</span>
              <button
                disabled={togglingId === mod.id}
                onClick={() => handleToggle(mod.id, mod.enabled)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
                  mod.enabled
                    ? 'bg-slate-800 hover:bg-slate-700 text-slate-200'
                    : 'bg-cyan-600 hover:bg-cyan-500 text-white'
                }`}
              >
                <Power className="w-3.5 h-3.5" />
                {togglingId === mod.id ? 'Toggling...' : mod.enabled ? 'Disable' : 'Enable'}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
