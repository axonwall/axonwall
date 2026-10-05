'use client';

import { useState } from 'react';
import {
  Boxes,
  Download,
  Trash2,
  CheckCircle2,
  Shield,
  Layers,
  ExternalLink,
  Search,
  Settings,
} from 'lucide-react';
import { BUILTIN_PLUGINS, type PluginManifest } from '@axonwall/lib/plugins';

export default function PluginManagerPage() {
  const [installedPlugins, setInstalledPlugins] = useState<Record<string, boolean>>({
    haproxy: true,
    freeradius: true,
    snmp: false,
    'nut-ups': true,
    tailscale: false,
    ntopng: false,
  });

  const [selectedPlugin, setSelectedPlugin] = useState<PluginManifest | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  const toggleInstall = (id: string) => {
    setInstalledPlugins((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const filteredPlugins = BUILTIN_PLUGINS.filter(
    (p) =>
      p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.description.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Boxes className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Plugin Store & Extensions</h1>
            <p className="text-sm text-slate-400">
              Modular extensions packaged with Zod schemas, systemd sandbox isolation, and nftables integration hooks.
            </p>
          </div>
        </div>

        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search plugins & extensions..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-64"
          />
        </div>
      </div>

      {/* Plugins Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredPlugins.map((plugin) => {
          const isInstalled = !!installedPlugins[plugin.id];
          return (
            <div
              key={plugin.id}
              className="p-6 rounded-2xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between space-y-4"
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="text-base font-semibold text-white tracking-tight">{plugin.name}</h3>
                    <span className="text-xs text-slate-500 font-mono">v{plugin.version} • {plugin.author}</span>
                  </div>
                  <span
                    className={`px-2.5 py-1 rounded-md text-[11px] font-semibold border ${
                      isInstalled
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}
                  >
                    {isInstalled ? 'Installed' : 'Available'}
                  </span>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed line-clamp-3">
                  {plugin.description}
                </p>

                <div className="flex flex-wrap gap-1.5 pt-1">
                  {plugin.systemdUnits.map((u) => (
                    <span key={u} className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-400">
                      {u}
                    </span>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between pt-4 border-t border-slate-800/80">
                <button
                  onClick={() => setSelectedPlugin(plugin)}
                  className="text-xs text-slate-400 hover:text-emerald-400 font-medium flex items-center gap-1 transition"
                >
                  <Shield className="w-3.5 h-3.5" /> Manifest
                </button>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => toggleInstall(plugin.id)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition flex items-center gap-1.5 ${
                      isInstalled
                        ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20 hover:bg-rose-500/20'
                        : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-950/40'
                    }`}
                  >
                    {isInstalled ? (
                      <>
                        <Trash2 className="w-3.5 h-3.5" /> Uninstall
                      </>
                    ) : (
                      <>
                        <Download className="w-3.5 h-3.5" /> Install Plugin
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Manifest Modal */}
      {selectedPlugin && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Shield className="w-5 h-5 text-emerald-400" />
                Plugin Manifest: {selectedPlugin.id}
              </h2>
              <button
                onClick={() => setSelectedPlugin(null)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-500 block">ID & VERSION</span>
                <span className="text-white font-mono">{selectedPlugin.id} @ {selectedPlugin.version}</span>
              </div>
              <div>
                <span className="text-slate-500 block">REQUIRED PRIVILEGES</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedPlugin.privileges.map((p) => (
                    <span key={p} className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
                      {p}
                    </span>
                  ))}
                </div>
              </div>
              <div>
                <span className="text-slate-500 block">SYSTEMD SANDBOX UNITS</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedPlugin.systemdUnits.map((u) => (
                    <span key={u} className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 font-mono">
                      {u}
                    </span>
                  ))}
                </div>
              </div>
              {selectedPlugin.nftHooks && (
                <div>
                  <span className="text-slate-500 block">NFTABLES HOOK POINTS</span>
                  <div className="mt-1 space-y-1">
                    {selectedPlugin.nftHooks.map((h, i) => (
                      <div key={i} className="p-2 rounded bg-slate-950 border border-slate-800 font-mono text-sky-400">
                        {h.table} → chain {h.chain} (priority {h.priority})
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedPlugin(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
