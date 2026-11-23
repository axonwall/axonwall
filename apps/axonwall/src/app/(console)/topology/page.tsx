'use client';

import React, { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { GitBranch, Loader2, Power } from 'lucide-react';
import { enablePluginWithDependencies, isPluginEnabled } from '@axonwall/lib/plugins';
import type { DesiredState } from '@axonwall/lib/schemas';
import { getCurrentDesiredState } from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import { TopologyStudioWorkspace } from '@/components/topology/TopologyStudioWorkspace';

export default function TopologyStudioPage() {
  const { applyState } = useDesiredStateApply();
  const [state, setState] = useState<DesiredState | null>(null);
  const [loading, setLoading] = useState(true);
  const [enabling, setEnabling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const s = await getCurrentDesiredState();
      setState(s);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load configuration');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleEnable = async () => {
    if (!state) return;
    setEnabling(true);
    setError(null);
    try {
      const res = enablePluginWithDependencies('topology-studio', state);
      const applied = await applyState(res.state);
      if (applied.success) {
        setState(res.state);
      } else {
        setError(applied.message || 'Failed to enable Topology Studio');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to enable Topology Studio');
    } finally {
      setEnabling(false);
    }
  };

  if (loading) {
    return (
      <div className="h-[calc(100vh-4rem)] flex items-center justify-center bg-slate-950 text-slate-300 text-sm gap-2">
        <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
        Loading Topology Studio...
      </div>
    );
  }

  if (!state || !isPluginEnabled('topology-studio', state)) {
    return (
      <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center bg-slate-950 p-6">
        <div className="max-w-lg w-full rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-400">
              <GitBranch className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-white">Topology Studio</h1>
              <p className="text-xs text-slate-400">
                Opt-in multi-host network, physical cable planner, K3s ingress &amp; NetBox/LibreNMS Triad editor
              </p>
            </div>
          </div>

          <p className="text-sm text-slate-300 leading-relaxed">
            Topology Studio is currently disabled. Enabling it initializes <code className="font-mono text-sky-300">/etc/axonwall/topology.yaml</code> with zero overhead when closed and unlocks live edge/peer/K3s visualization and staged multi-target commits.
          </p>

          {error && (
            <div className="px-3 py-2 rounded bg-rose-500/10 border border-rose-500/40 text-xs text-rose-300">
              {error}
            </div>
          )}

          <div className="flex items-center justify-between pt-2">
            <Link href="/system/plugins" className="text-xs text-slate-400 hover:text-white underline">
              Manage in Plugin Store
            </Link>
            <button
              type="button"
              disabled={enabling || !state}
              onClick={() => void handleEnable()}
              className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white text-xs font-semibold flex items-center gap-2"
            >
              <Power className="w-4 h-4" />
              {enabling ? 'Enabling...' : 'Enable Topology Studio'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-[calc(100vh-4rem)] w-full overflow-hidden">
      <TopologyStudioWorkspace />
    </div>
  );
}
