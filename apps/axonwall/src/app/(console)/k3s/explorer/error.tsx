'use client';

import React, { useEffect } from 'react';
import { AlertTriangle, RefreshCw, Terminal } from 'lucide-react';
import Link from 'next/link';

export default function K3sExplorerError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('K3s Explorer Crash Caught by Error Boundary:', error);
  }, [error]);

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-6">
      <div className="p-6 rounded-2xl bg-rose-500/10 border border-rose-500/30 space-y-4">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-xl bg-rose-500/20 border border-rose-500/30 flex items-center justify-center text-rose-400 shrink-0">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <h2 className="text-lg font-bold text-white">K9s Live Explorer Cockpit Encountered an Error</h2>
            <p className="text-xs text-rose-300">
              {error.message || 'An unexpected client error occurred while rendering Kubernetes resources.'}
            </p>
            {error.digest && (
              <p className="text-[11px] font-mono text-slate-400">
                Digest: <code className="text-slate-300">{error.digest}</code>
              </p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3 pt-2">
          <button
            type="button"
            onClick={() => reset()}
            className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs flex items-center gap-2 transition shadow"
          >
            <RefreshCw className="w-4 h-4" /> Reset &amp; Reload Cockpit
          </button>
          <Link
            href="/k3s/cluster"
            className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-medium transition"
          >
            Go to K3s Cluster Status
          </Link>
          <Link
            href="/k3s/workloads"
            className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-medium transition"
          >
            Go to K3s Workloads
          </Link>
        </div>
      </div>
    </div>
  );
}
