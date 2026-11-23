'use client';

import React, { useMemo, useState } from 'react';
import Link from 'next/link';
import { AlertTriangle, Boxes, CheckCircle2, Globe, Layers, Lock, Network, Unlock } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { K3sClusterPulse } from './types';
import { buildWorkloadsVisualSummary } from '@/lib/k3s-visuals';

interface K3sWorkloadsVisualsProps {
  pulse: K3sClusterPulse;
  selectedNs: string;
  onSelectNamespace: (ns: string) => void;
  onShowZeroEndpointServices: () => void;
  defaultShowIngressFlow?: boolean;
}

export function K3sWorkloadsVisuals({
  pulse,
  selectedNs,
  onSelectNamespace,
  onShowZeroEndpointServices,
  defaultShowIngressFlow = true,
}: K3sWorkloadsVisualsProps) {
  const [flowExpanded, setFlowExpanded] = useState(defaultShowIngressFlow);
  const [hoveredIngress, setHoveredIngress] = useState<string | null>(null);

  const summary = useMemo(() => buildWorkloadsVisualSummary(pulse), [pulse]);

  const filteredRoutes = useMemo(() => {
    if (selectedNs === '_all') return summary.ingressRoutes;
    return summary.ingressRoutes.filter((r) => (r.ingress.namespace || 'default') === selectedNs);
  }, [summary.ingressRoutes, selectedNs]);

  const tlsPct =
    summary.ingressPosture.total > 0
      ? Math.round((summary.ingressPosture.tlsCount / summary.ingressPosture.total) * 100)
      : 100;

  return (
    <div className="space-y-5">
      {/* 3-Panel Overview Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Panel 1: Workload Readiness by Kind */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Boxes className="w-4 h-4 text-emerald-400" /> Controller Readiness by Kind
              </h3>
              <p className="text-xs text-slate-400">Ready vs degraded/failed across workload types</p>
            </div>
            <Link
              href="/k3s/explorer?resource=deployments"
              className="text-[11px] font-mono text-sky-400 hover:underline"
            >
              Explorer →
            </Link>
          </div>

          <div className="h-[210px] w-full min-w-0">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={summary.readinessByKind} layout="vertical" margin={{ left: 10, right: 16 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis
                  type="category"
                  dataKey="kind"
                  width={92}
                  tick={{ fill: '#cbd5e1', fontSize: 11 }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '0.5rem',
                    fontSize: '12px',
                    color: '#f1f5f9',
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
                <Bar dataKey="ready" stackId="a" name="Ready / OK" fill="#10b981" />
                <Bar dataKey="degraded" stackId="a" name="Degraded / Failed" fill="#f43f5e" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Panel 2: Namespace Footprint */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Layers className="w-4 h-4 text-sky-400" /> Namespace Footprint (Top 10)
              </h3>
              <p className="text-xs text-slate-400">Click any bar to filter the inventory table below</p>
            </div>
            {selectedNs !== '_all' && (
              <button
                type="button"
                onClick={() => onSelectNamespace('_all')}
                className="px-2 py-0.5 rounded bg-slate-950 border border-slate-700 text-[11px] font-mono text-sky-300 hover:text-white"
              >
                {selectedNs} ✕
              </button>
            )}
          </div>

          {summary.namespaceFootprint.length === 0 ? (
            <div className="h-[210px] flex items-center justify-center text-xs text-slate-400">
              No namespace telemetry yet.
            </div>
          ) : (
            <div className="h-[210px] w-full min-w-0">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={summary.namespaceFootprint} layout="vertical" margin={{ left: 8, right: 12 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={96}
                    tick={{ fill: '#cbd5e1', fontSize: 11 }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '0.5rem',
                      fontSize: '12px',
                      color: '#f1f5f9',
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                  <Bar
                    dataKey="workloads"
                    stackId="a"
                    name="Workloads"
                    fill="#10b981"
                    className="cursor-pointer"
                    onClick={(entry: any) => {
                      if (entry?.name) {
                        onSelectNamespace(entry.name === selectedNs ? '_all' : String(entry.name));
                      }
                    }}
                  />
                  <Bar
                    dataKey="services"
                    stackId="a"
                    name="Services"
                    fill="#38bdf8"
                    className="cursor-pointer"
                    onClick={(entry: any) => {
                      if (entry?.name) {
                        onSelectNamespace(entry.name === selectedNs ? '_all' : String(entry.name));
                      }
                    }}
                  />
                  <Bar
                    dataKey="ingresses"
                    stackId="a"
                    name="Ingresses"
                    fill="#06b6d4"
                    className="cursor-pointer"
                    onClick={(entry: any) => {
                      if (entry?.name) {
                        onSelectNamespace(entry.name === selectedNs ? '_all' : String(entry.name));
                      }
                    }}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Panel 3: Service Exposure & Ingress TLS Posture */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" /> Service Exposure &amp; Ingress TLS Posture
            </h3>

            {/* Service Type Breakdown */}
            <div className="flex flex-wrap gap-2">
              {summary.serviceTypes.map((st) => (
                <div
                  key={st.name}
                  className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono tabular-nums"
                >
                  <span className="text-slate-400">{st.name}: </span>
                  <span className="text-sky-300 font-bold">{st.count}</span>
                </div>
              ))}
            </div>

            {/* TLS Bar */}
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-300 flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-emerald-400" />
                  Ingress TLS Termination
                </span>
                <span className="text-emerald-300 font-bold tabular-nums">
                  {summary.ingressPosture.tlsCount}/{summary.ingressPosture.total} ({tlsPct}%)
                </span>
              </div>
              <div className="h-2 rounded-full bg-slate-800 overflow-hidden flex">
                <div
                  className="h-full bg-emerald-500"
                  style={{ width: `${tlsPct}%` }}
                  title={`TLS Enabled: ${summary.ingressPosture.tlsCount}`}
                />
                {summary.ingressPosture.httpOnlyCount > 0 && (
                  <div
                    className="h-full bg-amber-500"
                    style={{ width: `${100 - tlsPct}%` }}
                    title={`Plain HTTP: ${summary.ingressPosture.httpOnlyCount}`}
                  />
                )}
              </div>
              <div className="flex items-center justify-between text-[11px] font-mono tabular-nums text-slate-400">
                <span>{summary.ingressPosture.totalHosts} exposed hostnames</span>
                {summary.ingressPosture.httpOnlyCount > 0 && (
                  <span className="text-amber-300 flex items-center gap-1">
                    <Unlock className="w-3 h-3" /> {summary.ingressPosture.httpOnlyCount} HTTP-only
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Zero Endpoint Service Alert */}
          {summary.zeroEndpointServices.length > 0 ? (
            <button
              type="button"
              onClick={onShowZeroEndpointServices}
              className="w-full p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/30 hover:bg-amber-500/20 text-left text-xs font-mono text-amber-300 flex items-center justify-between gap-2 transition"
            >
              <span className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                {summary.zeroEndpointServices.length} {summary.zeroEndpointServices.length === 1 ? 'service has' : 'services have'} 0 ready endpoints
              </span>
              <span className="text-[11px] underline shrink-0">Filter Services →</span>
            </button>
          ) : (
            <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-xs font-mono text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              All active Services have healthy ready endpoints
            </div>
          )}
        </div>
      </div>

      {/* Interactive Converged Ingress Routing Flow */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">
              Converged Ingress &rarr; Service &rarr; Pod Traffic Chains
            </h3>
            <span className="text-xs font-mono tabular-nums text-slate-400">
              ({filteredRoutes.length} routes)
            </span>
          </div>
          <button
            type="button"
            onClick={() => setFlowExpanded((e) => !e)}
            className="px-3 py-1 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/40 text-xs font-mono text-cyan-300"
          >
            {flowExpanded ? 'Collapse Routes' : 'Show Ingress Routing Chains'}
          </button>
        </div>

        {flowExpanded && (
          <div className="p-4 space-y-2.5 max-h-[340px] overflow-y-auto bg-slate-950/60">
            {filteredRoutes.length === 0 ? (
              <div className="py-6 text-center text-xs text-slate-400">
                No Ingress routes match the selected namespace.
              </div>
            ) : (
              filteredRoutes.map((route) => {
                const key = `${route.ingress.namespace}/${route.ingress.name}`;
                const isHov = hoveredIngress === key;
                const hosts = Array.isArray(route.ingress.hosts) ? route.ingress.hosts : [];

                return (
                  <div
                    key={key}
                    onMouseEnter={() => setHoveredIngress(key)}
                    onMouseLeave={() => setHoveredIngress(null)}
                    className={`p-3 rounded-xl border transition flex flex-col lg:flex-row lg:items-center justify-between gap-3 ${
                      route.hasBrokenBackend
                        ? 'bg-rose-500/5 border-rose-500/30'
                        : isHov
                          ? 'bg-slate-900 border-cyan-500/40'
                          : 'bg-slate-950 border-slate-800'
                    }`}
                  >
                    {/* Ingress Source */}
                    <Link
                      href={`/k3s/explorer?resource=ingresses&namespace=${encodeURIComponent(
                        route.ingress.namespace
                      )}&name=${encodeURIComponent(route.ingress.name)}`}
                      className="min-w-[230px] max-w-sm space-y-0.5 hover:text-cyan-300 transition"
                    >
                      <div className="flex items-center gap-1.5 text-xs font-mono font-bold text-white">
                        {route.ingress.tls ? (
                          <Lock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        ) : (
                          <Unlock className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                        )}
                        <span className="truncate">{route.ingress.name}</span>
                        <span className="text-[10px] text-slate-400 font-normal">
                          ({route.ingress.namespace})
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-cyan-300 truncate">
                        {hosts.join(', ') || '*'}
                      </div>
                    </Link>

                    {/* Flow Arrows -> Backend Services + Pods */}
                    <div className="flex flex-wrap items-center gap-2 flex-1 lg:justify-end">
                      {route.backends.length === 0 ? (
                        <span className="text-[11px] font-mono text-slate-400">
                          No backends specified
                        </span>
                      ) : (
                        route.backends.map((b) => (
                          <Link
                            key={b.serviceName}
                            href={`/k3s/explorer?resource=services&namespace=${encodeURIComponent(
                              route.ingress.namespace
                            )}&name=${encodeURIComponent(b.serviceName)}`}
                            className={`px-2.5 py-1.5 rounded-lg border text-[11px] font-mono tabular-nums inline-flex items-center gap-2 transition ${
                              b.hasHealthyEndpoints
                                ? 'bg-slate-900 border-slate-800 hover:border-sky-500/40 text-slate-200'
                                : 'bg-rose-500/15 border-rose-500/40 text-rose-200'
                            }`}
                          >
                            <span className="text-sky-300 font-semibold">svc/{b.serviceName}</span>
                            <span className="text-slate-400">→</span>
                            <span className={b.readyEndpoints > 0 ? 'text-emerald-300' : 'text-rose-300'}>
                              {b.readyEndpoints} ep / {b.podCount} pods
                            </span>
                          </Link>
                        ))
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        )}
      </div>
    </div>
  );
}
