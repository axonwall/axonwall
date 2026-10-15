import React from 'react';
import { Info, Lightbulb, AlertTriangle, AlertOctagon } from 'lucide-react';

interface CalloutProps {
  type?: 'info' | 'tip' | 'warning' | 'caution';
  title?: string;
  children: React.ReactNode;
}

export function Callout({ type = 'info', title, children }: CalloutProps) {
  const configs = {
    info: {
      border: 'border-sky-500/30 bg-sky-950/20 text-sky-200',
      icon: Info,
      iconColor: 'text-sky-400',
      defaultTitle: 'Note',
    },
    tip: {
      border: 'border-emerald-500/30 bg-emerald-950/20 text-emerald-200',
      icon: Lightbulb,
      iconColor: 'text-emerald-400',
      defaultTitle: 'ProTip',
    },
    warning: {
      border: 'border-amber-500/30 bg-amber-950/20 text-amber-200',
      icon: AlertTriangle,
      iconColor: 'text-amber-400',
      defaultTitle: 'Important',
    },
    caution: {
      border: 'border-rose-500/30 bg-rose-950/20 text-rose-200',
      icon: AlertOctagon,
      iconColor: 'text-rose-400',
      defaultTitle: 'Caution',
    },
  };

  const config = configs[type] || configs.info;
  const Icon = config.icon;

  return (
    <div className={`my-6 rounded-xl border p-4.5 text-xs sm:text-sm leading-relaxed ${config.border}`}>
      <div className="flex items-center gap-2 font-semibold mb-1.5">
        <Icon className={`w-4 h-4 shrink-0 ${config.iconColor}`} />
        <span>{title || config.defaultTitle}</span>
      </div>
      <div className="text-slate-300 space-y-2 pl-6">{children}</div>
    </div>
  );
}
