'use client';

import React, { useState } from 'react';
import { Layers, Plus, RefreshCw, Server, Trash2 } from 'lucide-react';
import { formatBps, formatBytes } from '@axonwall/lib/compile/netflow';
import {
  NetFlowConfigSchema,
  NetFlowExporterVendorSchema,
  type DesiredState,
  type NetFlowExporterProfile,
} from '@axonwall/lib/schemas';
import type { NetFlowExporterSnapshot, NetFlowTemplateSnapshot } from './types';

interface ExportersTemplatesTabProps {
  exporters: NetFlowExporterSnapshot[];
  templates: NetFlowTemplateSnapshot[];
  draftState: DesiredState | null;
  onRefresh: () => void;
  onUpdateDraft: (updater: (prev: DesiredState) => DesiredState) => void;
}

export function ExportersTemplatesTab({
  exporters,
  templates,
  draftState,
  onRefresh,
  onUpdateDraft,
}: ExportersTemplatesTabProps) {
  const [ip, setIp] = useState('');
  const [name, setName] = useState('');
  const [vendor, setVendor] = useState<NetFlowExporterProfile['vendor']>('axonwall');
  const [site, setSite] = useState('');
  const [sampling, setSampling] = useState('0');
  const [aliasesRaw, setAliasesRaw] = useState('');
  const [expandedTmplKey, setExpandedTmplKey] = useState<string | null>(null);

  const profiles = draftState?.netflow?.exporterProfiles ?? [];

  const handleAddProfile = (e: React.FormEvent) => {
    e.preventDefault();
    if (!ip.trim() || !name.trim()) return;
    const aliases: Record<string, string> = {};
    for (const pair of aliasesRaw.split(',')) {
      const [k, v] = pair.split('=').map((s) => s.trim());
      if (k && v) aliases[k] = v;
    }
    const profile: NetFlowExporterProfile = {
      id: `exp-${Date.now().toString(36)}`,
      ip: ip.trim(),
      name: name.trim(),
      site: site.trim() || undefined,
      vendor,
      samplingRateOverride: Math.max(0, Number(sampling) || 0),
      ifIndexAliases: aliases,
      enabled: true,
      expectedFpsMin: 0,
    };
    onUpdateDraft((prev) => {
      const cur = NetFlowConfigSchema.parse(prev.netflow ?? {});
      return {
        ...prev,
        netflow: {
          ...cur,
          exporterProfiles: [...cur.exporterProfiles, profile],
        },
      };
    });
    setIp('');
    setName('');
    setSite('');
    setSampling('0');
    setAliasesRaw('');
  };

  return (
    <div className="space-y-6">
      {/* Live Runtime Exporters */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-sky-400" />
            <div>
              <h3 className="text-sm font-semibold text-white">Active Flow Exporters ({exporters.length})</h3>
              <p className="text-xs text-slate-400">Live rate, sampling &amp; sFlow interface counters per exporting device</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onRefresh}
            className="px-3 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-xs text-slate-200 flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>

        {exporters.length === 0 ? (
          <div className="py-8 text-center text-xs text-slate-500">
            No exporters have reported yet. Configure your switches/routers to export NetFlow/IPFIX/sFlow or trigger a test burst.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 uppercase font-mono border-b border-slate-800">
                <tr>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Exporter</th>
                  <th className="px-3 py-2">Vendor / Site</th>
                  <th className="px-3 py-2">Protocols</th>
                  <th className="px-3 py-2">Flows / Bytes</th>
                  <th className="px-3 py-2">Throughput</th>
                  <th className="px-3 py-2">Sample / Tmpls</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 font-mono">
                {exporters.map((e) => (
                  <tr key={e.exporterIp} className="text-slate-200">
                    <td className="px-3 py-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                          e.status === 'green'
                            ? 'bg-emerald-500/20 text-emerald-300'
                            : e.status === 'yellow'
                              ? 'bg-amber-500/20 text-amber-300'
                              : 'bg-rose-500/20 text-rose-300'
                        }`}
                      >
                        {e.status}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <div className="font-semibold text-white">{e.name}</div>
                      <div className="text-[11px] text-slate-400">{e.exporterIp}</div>
                    </td>
                    <td className="px-3 py-2 text-slate-300">
                      {e.vendor} {e.site ? `· ${e.site}` : ''}
                    </td>
                    <td className="px-3 py-2 text-sky-300">{e.versions.join(', ') || '-'}</td>
                    <td className="px-3 py-2">
                      {e.flowsReceived.toLocaleString()} / {formatBytes(e.bytesAccounted)}
                    </td>
                    <td className="px-3 py-2 text-emerald-300">
                      {formatBps(e.bpsEstimate)} · {e.fpsEstimate.toFixed(1)} fps
                    </td>
                    <td className="px-3 py-2 text-slate-400">
                      1:{e.samplingRate || 1} · {e.templatesCount} tmpl
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Configured Exporter Profiles & IfIndex Aliases */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div>
          <h3 className="text-sm font-semibold text-white">Configured Exporter Profiles ({profiles.length})</h3>
          <p className="text-xs text-slate-400">
            Map exporter IPs to names, sites, static sampling overrides &amp; SNMP <code className="font-mono">ifIndex</code> aliases (remember to click Save Changes in top bar)
          </p>
        </div>

        {profiles.length > 0 && (
          <div className="space-y-2">
            {profiles.map((p) => (
              <div
                key={p.id}
                className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs"
              >
                <div className="font-mono">
                  <span className="font-semibold text-white">{p.name}</span> ({p.ip}) · {p.vendor}
                  {p.samplingRateOverride > 1 ? ` · 1:${p.samplingRateOverride}` : ''}
                  {Object.keys(p.ifIndexAliases ?? {}).length > 0
                    ? ` · ifAliases: ${Object.entries(p.ifIndexAliases)
                        .map(([k, v]) => `${k}=${v}`)
                        .join(', ')}`
                    : ''}
                </div>
                <button
                  type="button"
                  onClick={() =>
                    onUpdateDraft((prev) => {
                      const cur = NetFlowConfigSchema.parse(prev.netflow ?? {});
                      return {
                        ...prev,
                        netflow: {
                          ...cur,
                          exporterProfiles: cur.exporterProfiles.filter((item) => item.id !== p.id),
                        },
                      };
                    })
                  }
                  className="p-1.5 rounded hover:bg-rose-500/20 text-slate-400 hover:text-rose-300"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        )}

        <form onSubmit={handleAddProfile} className="grid grid-cols-1 md:grid-cols-6 gap-2 text-xs">
          <input
            type="text"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="Exporter IP (10.80.0.2)"
            className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
          />
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Name (Core Switch)"
            className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white"
          />
          <select
            value={vendor}
            onChange={(e) => setVendor(e.target.value as NetFlowExporterProfile['vendor'])}
            className="px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
          >
            {NetFlowExporterVendorSchema.options.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
          <input
            type="number"
            min={0}
            value={sampling}
            onChange={(e) => setSampling(e.target.value)}
            placeholder="Sample override"
            title="Sampling Rate Override (0 = auto)"
            className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
          />
          <input
            type="text"
            value={aliasesRaw}
            onChange={(e) => setAliasesRaw(e.target.value)}
            placeholder="ifIndex aliases: 1=wan0,2=lan0"
            className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
          />
          <button
            type="submit"
            disabled={!ip.trim() || !name.trim()}
            className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white font-semibold flex items-center justify-center gap-1"
          >
            <Plus className="w-3.5 h-3.5" />
            Add Profile
          </button>
        </form>
      </div>

      {/* Live Decoded Template Cache Inspector */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-emerald-400" />
          <div>
            <h3 className="text-sm font-semibold text-white">NetFlow v9 / IPFIX Template Cache Inspector ({templates.length})</h3>
            <p className="text-xs text-slate-400">Live templates learned from active exporters (click any template to expand field IEs)</p>
          </div>
        </div>

        {templates.length === 0 ? (
          <div className="py-6 text-center text-xs text-slate-500">
            No v9/IPFIX templates cached yet.
          </div>
        ) : (
          <div className="space-y-2 text-xs">
            {templates.map((t) => {
              const k = `${t.exporterIp}|${t.sourceId}|${t.version}|${t.templateId}`;
              const open = expandedTmplKey === k;
              return (
                <div key={k} className="bg-slate-950 border border-slate-800 rounded-lg overflow-hidden">
                  <button
                    type="button"
                    onClick={() => setExpandedTmplKey(open ? null : k)}
                    className="w-full px-3 py-2 flex flex-wrap items-center justify-between gap-2 text-left hover:bg-slate-900/60 font-mono"
                  >
                    <span className="text-white font-semibold">
                      {t.exporterIp} (domain {t.sourceId}) · {t.version.toUpperCase()} Template #{t.templateId}
                      {t.isOptions ? ' [OPTIONS]' : ''}
                    </span>
                    <span className="text-slate-400">
                      {t.fieldCount} fields · {t.totalBytes} B · {t.packetsUsing.toLocaleString()} hits
                    </span>
                  </button>
                  {open && (
                    <div className="px-3 py-2 border-t border-slate-800 flex flex-wrap gap-1.5 font-mono text-[11px]">
                      {t.fields.map((f, idx) => (
                        <span
                          key={`${f.fieldType}-${idx}`}
                          className={`px-2 py-0.5 rounded border ${
                            f.isScope
                              ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                              : 'bg-slate-900 border-slate-700 text-sky-300'
                          }`}
                        >
                          {f.fieldName} ({f.enterpriseId ? `ent:${f.enterpriseId}/` : ''}#{f.fieldType}:{' '}
                          {f.length === 65535 ? 'var' : `${f.length}B`})
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
