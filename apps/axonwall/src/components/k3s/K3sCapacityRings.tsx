'use client';

import React, { useMemo } from 'react';
import Link from 'next/link';
import { AlertTriangle, Cpu, Database, HardDrive, Layers, Server } from 'lucide-react';
import type { K3sClusterPulse } from './types';
import { computeClusterCapacitySummary, type ClusterAttentionItem } from '@/lib/k3s-visuals';

interface K3sCapacityRingsProps {
  pulse: K3sClusterPulse;
  onSelectFilter?: (opts: { resource: string; namespace?: string; search?: string }) => void;
  showAttentionStrip?: boolean;
}

interface RadialGaugeProps {
  pct: number;
  secondaryPct?: number;
  color: string;
  secondaryColor?: string;
  centerText: string;
  label: string;
}

function RadialGauge({
  pct,
  secondaryPct,
  color,
  secondaryColor = '#38bdf8',
  centerText,
  label,
}: RadialGaugeProps) {
  const r = 30;
  const circ = 2 * Math.PI * r;
  const clamped = Math.max(0, Math.min(100, pct));
  const offset = circ - (clamped / 100) * circ;

  const rInner = 23;
  const circInner = 2 * Math.PI * rInner;
  const clampedInner = secondaryPct !== undefined ? Math.max(0, Math.min(100, secondaryPct)) : 0;
  const offsetInner = circInner - (clampedInner / 100) * circInner;

  return (
    <svg
      viewBox="0 0 80 80"
      className="w-14 h-14 shrink-0"
      role="img"
      aria-label={`${label}: ${centerText}`}
    >
      <circle
        cx="40"
        cy="40"
        r={r}
        fill="none"
        stroke="#1e293b"
        strokeWidth="6.5"
      />
      {secondaryPct !== undefined && (
        <>
          <circle
            cx="40"
            cy="40"
            r={rInner}
            fill="none"
            stroke="#0f172a"
            strokeWidth="3"
          />
          <circle
            cx="40"
            cy="40"
            r={rInner}
            fill="none"
            stroke={secondaryColor}
            strokeOpacity={0.65}
            strokeWidth="3"
            strokeDasharray={circInner}
            strokeDashoffset={offsetInner}
            strokeLinecap="round"
            transform="rotate(-90 40 40)"
          />
        </>
      )}
      <circle
        cx="40"
        cy="40"
        r={r}
        fill="none"
        stroke={color}
        strokeWidth="6.5"
        strokeDasharray={circ}
        strokeDashoffset={offset}
        strokeLinecap="round"
        transform="rotate(-90 40 40)"
        className="transition-[stroke-dashoffset] duration-300 ease-out"
      />
      <text
        x="40"
        y="43.5"
        textAnchor="middle"
        fill="#f8fafc"
        fontSize="13.5"
        fontWeight="700"
        fontFamily="ui-monospace, SFMono-Regular, monospace"
      >
        {centerText}
      </text>
    </svg>
  );
}

export function K3sCapacityRings({
  pulse,
  onSelectFilter,
  showAttentionStrip = true,
}: K3sCapacityRingsProps) {
  const cap = useMemo(() => computeClusterCapacitySummary(pulse), [pulse]);

  const cpuTone = cap.cpuUsagePct >= 85 ? '#f43f5e' : cap.cpuUsagePct >= 70 ? '#f59e0b' : '#10b981';
  const memTone = cap.memUsagePct >= 85 ? '#f43f5e' : cap.memUsagePct >= 70 ? '#f59e0b' : '#0ea5e9';
  const podTone = cap.podDensityPct >= 85 ? '#f59e0b' : '#34d399';
  const wlTone = cap.workloadReadinessPct < 100 ? '#f59e0b' : '#10b981';
  const pvcPct = cap.pvcsTotal > 0 ? Math.round((cap.pvcsBound / cap.pvcsTotal) * 100) : 100;
  const pvcTone = cap.pvcsBound < cap.pvcsTotal ? '#f59e0b' : '#06b6d4';

  const cardClass =
    'text-left p-3 rounded-xl bg-slate-900 border border-slate-800 hover:border-emerald-500/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500/60 transition flex items-center gap-2.5 min-w-0';

  const renderCard = (
    key: string,
    resource: string,
    icon: React.ReactNode,
    title: string,
    gauge: React.ReactNode,
    primaryMetric: string,
    secondaryMetric: string,
    badge?: { text: string; tone: 'warn' | 'err' | 'ok' }
  ) => {
    const inner = (
      <>
        {gauge}
        <div className="min-w-0 flex-1 space-y-0.5">
          <div className="flex items-center justify-between gap-1.5 text-xs font-medium text-slate-300">
            <span className="flex items-center gap-1.5 truncate">
              {icon}
              <span className="truncate">{title}</span>
            </span>
          </div>
          <div className="text-sm font-bold font-mono tabular-nums text-white truncate">
            {primaryMetric}
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400 truncate">
            {secondaryMetric}
          </div>
          {badge && (
            <span
              className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-mono tabular-nums border whitespace-nowrap max-w-full truncate ${
                badge.tone === 'err'
                  ? 'bg-rose-500/15 border-rose-500/30 text-rose-300'
                  : badge.tone === 'warn'
                    ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                    : 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
              }`}
            >
              {badge.text}
            </span>
          )}
        </div>
      </>
    );

    if (onSelectFilter) {
      return (
        <button
          key={key}
          type="button"
          onClick={() => onSelectFilter({ resource })}
          className={cardClass}
        >
          {inner}
        </button>
      );
    }

    return (
      <Link key={key} href={`/k3s/explorer?resource=${encodeURIComponent(resource)}`} className={cardClass}>
        {inner}
      </Link>
    );
  };

  const renderAttentionItem = (item: ClusterAttentionItem, idx: number) => {
    const cls = `px-2.5 py-1 rounded-lg border text-[11px] font-mono tabular-nums inline-flex items-center gap-1.5 transition focus-visible:outline-none focus-visible:ring-2 ${
      item.severity === 'err'
        ? 'bg-rose-500/10 border-rose-500/30 text-rose-300 hover:bg-rose-500/20 focus-visible:ring-rose-500/50'
        : 'bg-amber-500/10 border-amber-500/30 text-amber-300 hover:bg-amber-500/20 focus-visible:ring-amber-500/50'
    }`;

    if (onSelectFilter) {
      return (
        <button
          key={`${item.resource}-${idx}`}
          type="button"
          onClick={() => onSelectFilter({ resource: item.resource, search: item.search })}
          className={cls}
        >
          <AlertTriangle className="w-3 h-3 shrink-0" />
          <span>{item.label}</span>
        </button>
      );
    }

    return (
      <Link
        key={`${item.resource}-${idx}`}
        href={`/k3s/explorer?resource=${encodeURIComponent(item.resource)}`}
        className={cls}
      >
        <AlertTriangle className="w-3 h-3 shrink-0" />
        <span>{item.label}</span>
      </Link>
    );
  };

  const offlineNodes = Math.max(0, cap.nodesTotal - cap.nodesReady);
  const podBadgeText =
    offlineNodes > 0 && cap.nodesCordoned > 0
      ? `${offlineNodes} off · ${cap.nodesCordoned} cord`
      : offlineNodes > 0
        ? `${offlineNodes} offline`
        : `${cap.nodesCordoned} cordoned`;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-3">
        {renderCard(
          'cpu',
          'nodes',
          <Cpu className="w-3.5 h-3.5 text-emerald-400 shrink-0" />,
          'CPU',
          <RadialGauge
            pct={cap.cpuUsagePct}
            secondaryPct={cap.cpuRequestPct}
            color={cpuTone}
            secondaryColor="#0ea5e9"
            centerText={`${cap.cpuUsagePct}%`}
            label="Cluster CPU usage"
          />,
          `${cap.cpuUsageCores}/${cap.cpuAllocatableCores} cores`,
          `Req ${cap.cpuRequestsCores}c (${cap.cpuRequestPct}%)`,
          cap.cpuLimitPct > 100
            ? { text: `Lim ${cap.cpuLimitPct}% over`, tone: 'warn' }
            : undefined
        )}

        {renderCard(
          'mem',
          'nodes',
          <Server className="w-3.5 h-3.5 text-sky-400 shrink-0" />,
          'Memory',
          <RadialGauge
            pct={cap.memUsagePct}
            secondaryPct={cap.memRequestPct}
            color={memTone}
            secondaryColor="#818cf8"
            centerText={`${cap.memUsagePct}%`}
            label="Cluster memory usage"
          />,
          `${cap.memUsageGiB}/${cap.memAllocatableGiB} GiB`,
          `Req ${cap.memRequestsGiB}G (${cap.memRequestPct}%)`,
          cap.memLimitPct > 100
            ? { text: `Lim ${cap.memLimitPct}% over`, tone: 'warn' }
            : undefined
        )}

        {renderCard(
          'pods',
          'pods',
          <Layers className="w-3.5 h-3.5 text-emerald-400 shrink-0" />,
          'Pod Slots',
          <RadialGauge
            pct={cap.podDensityPct}
            color={podTone}
            centerText={`${cap.podDensityPct}%`}
            label="Schedulable pod slot density"
          />,
          `${cap.podsRunning}/${cap.podsTotal} up`,
          `Cap ${cap.podCapacitySchedulable || cap.podCapacityAll} slots`,
          cap.nodesCordoned > 0 || offlineNodes > 0
            ? {
                text: podBadgeText,
                tone: offlineNodes > 0 ? 'err' : 'warn',
              }
            : undefined
        )}

        {renderCard(
          'workloads',
          'deployments',
          <Layers className="w-3.5 h-3.5 text-sky-400 shrink-0" />,
          'Workloads',
          <RadialGauge
            pct={cap.workloadReadinessPct}
            color={wlTone}
            centerText={`${cap.workloadReadinessPct}%`}
            label="Workload readiness"
          />,
          `${cap.workloadsReady}/${cap.workloadsTotal} ready`,
          cap.workloadsTotal > cap.workloadsReady
            ? `${cap.workloadsTotal - cap.workloadsReady} degraded`
            : 'All converged'
        )}

        {renderCard(
          'storage-quorum',
          'persistentvolumeclaims',
          <HardDrive className="w-3.5 h-3.5 text-amber-400 shrink-0" />,
          'Storage',
          <RadialGauge
            pct={pvcPct}
            color={pvcTone}
            centerText={`${cap.pvcsBound}/${cap.pvcsTotal}`}
            label="PersistentVolumeClaims bound"
          />,
          `${cap.totalStorageGiB} GiB`,
          cap.etcdVotersTotal > 0
            ? `Etcd ${cap.etcdVotersReady}/${cap.etcdVotersTotal} voters`
            : `Nodes ${cap.nodesReady}/${cap.nodesTotal} ready`,
          cap.pvcsBound < cap.pvcsTotal
            ? { text: `${cap.pvcsTotal - cap.pvcsBound} unbound`, tone: 'warn' }
            : undefined
        )}
      </div>

      {showAttentionStrip && cap.attentionItems.length > 0 && (
        <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-center gap-2">
          <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5 mr-1">
            <Database className="w-3.5 h-3.5 text-amber-400" />
            Cluster Signals:
          </span>
          {cap.attentionItems.map(renderAttentionItem)}
        </div>
      )}
    </div>
  );
}
