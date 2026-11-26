'use client';

import React, { useMemo, useState } from 'react';
import {
  CheckCircle2,
  GitCommit,
  Play,
  RotateCcw,
  ShieldAlert,
  Trash2,
  X,
} from 'lucide-react';
import { buildFabricApplyPlan } from '@axonwall/lib/compile/topology';
import type { DesiredState } from '@axonwall/lib/schemas';
import type { TopologyApplyPlanResultSnapshot } from '@/server/agent';
import type { StagedK3sEdit, StagedPeerEdit } from '../types';

interface StagedDiffModalProps {
  open: boolean;
  onClose: () => void;
  liveState: DesiredState | null;
  draftState: DesiredState | null;
  k3sEdits: StagedK3sEdit[];
  peerEdits: StagedPeerEdit[];
  onRemoveK3sEdit: (id: string) => void;
  onRemovePeerEdit: (peerId: string) => void;
  onResetDraft: () => void;
  onApplyComplete: (appliedLocal: boolean) => void;
}

export function StagedDiffModal({
  open,
  onClose,
  liveState,
  draftState,
  k3sEdits,
  peerEdits,
  onRemoveK3sEdit,
  onRemovePeerEdit,
  onResetDraft,
  onApplyComplete,
}: StagedDiffModalProps) {
  const [confirmTimeoutSec, setConfirmTimeoutSec] = useState(120);
  const [running, setRunning] = useState(false);
  const [lastResult, setLastResult] = useState<TopologyApplyPlanResultSnapshot | null>(null);

  const changedSections = useMemo(() => {
    if (!liveState || !draftState) return [];
    const keys: Array<keyof DesiredState> = [
      'system',
      'interfaces',
      'vlans',
      'wireguard',
      'routes',
      'rules',
      'nat',
      'gateways',
      'plugins',
      'topology',
    ];
    return keys
      .filter((k) => JSON.stringify(liveState[k]) !== JSON.stringify(draftState[k]))
      .map((k) => String(k));
  }, [liveState, draftState]);

  const plan = useMemo(
    () =>
      buildFabricApplyPlan({
        localState: changedSections.length > 0 && draftState ? draftState : undefined,
        k3sEdits,
        peerEdits: peerEdits.map((p) => ({
          peerId: p.peerId,
          name: p.name,
          apiUrl: 'peer',
          state: p.state as DesiredState,
        })),
        confirmTimeoutSeconds: confirmTimeoutSec,
      }),
    [changedSections.length, draftState, k3sEdits, peerEdits, confirmTimeoutSec],
  );

  if (!open) return null;

  const hasChanges = changedSections.length > 0 || k3sEdits.length > 0 || peerEdits.length > 0;

  const executePlan = async (dryRun: boolean) => {
    setRunning(true);
    try {
      const resp = await fetch('/api/v1/topology/apply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          dryRun,
          confirmTimeoutSeconds: confirmTimeoutSec,
          k3sEdits: k3sEdits.map((k) => ({
            kind: k.kind,
            name: k.name,
            namespace: k.namespace,
            manifestYaml: k.manifestYaml,
            scaleReplicas: k.scaleReplicas,
            nodeRoles: k.nodeRoles,
          })),
          peerEdits: peerEdits.map((p) => ({
            peerId: p.peerId,
            name: p.name,
            ...(p.hostname ? { hostname: p.hostname } : {}),
            ...(p.patch ? { patch: p.patch } : {}),
            ...(p.state ? { state: p.state as DesiredState } : {}),
          })),
          localState: changedSections.length > 0 && draftState ? draftState : undefined,
        }),
      });
      const json = (await resp.json().catch(() => null)) as
        | { status?: string; data?: TopologyApplyPlanResultSnapshot; error?: string }
        | null;
      if (json?.data) {
        setLastResult(json.data);
        if (json.data.success && !dryRun) {
          onApplyComplete(changedSections.length > 0);
        }
      } else {
        setLastResult({
          success: false,
          dryRun,
          timestamp: new Date().toISOString(),
          confirmTimeoutSeconds: confirmTimeoutSec,
          rolledBackAny: false,
          results: [],
          error: json?.error || `Fabric apply request failed (HTTP ${resp.status})`,
        });
      }
    } catch (err) {
      setLastResult({
        success: false,
        dryRun,
        timestamp: new Date().toISOString(),
        confirmTimeoutSeconds: confirmTimeoutSec,
        rolledBackAny: false,
        results: [],
        error: err instanceof Error ? err.message : 'Fabric apply request failed',
      });
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
      <div className="w-full max-w-3xl max-h-[85vh] bg-slate-950 border border-slate-800 rounded-xl shadow-2xl flex flex-col overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 bg-slate-900 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <GitCommit className="w-5 h-5 text-sky-400" />
            <div>
              <h2 className="text-sm font-semibold text-white">Staged Multi-Target Fabric Diff &amp; Apply</h2>
              <p className="text-xs text-slate-400">
                Phased apply: Dry-Run → Kubernetes &amp; Remote Peers → Local Edge (with rollback guard)
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-4 overflow-y-auto flex-1 text-xs">
          {!hasChanges ? (
            <div className="py-8 text-center text-slate-400 border border-dashed border-slate-800 rounded-lg">
              No staged configuration or topology changes pending.
            </div>
          ) : (
            <>
              {/* Summary of Queued Items */}
              <div className="space-y-2">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  Queued Change Inventory
                </div>
                {changedSections.length > 0 && (
                  <div className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
                    <div>
                      <span className="font-semibold text-white">Local / Edge Appliance:</span>{' '}
                      <span className="font-mono text-sky-300">{changedSections.join(', ')}</span>
                    </div>
                    <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 font-mono text-[10px]">
                      Phase 3
                    </span>
                  </div>
                )}

                {k3sEdits.map((k) => (
                  <div
                    key={k.id}
                    className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between gap-2"
                  >
                    <span className="font-mono text-slate-200 truncate">{k.summary}</span>
                    <button
                      type="button"
                      onClick={() => onRemoveK3sEdit(k.id)}
                      className="text-slate-400 hover:text-rose-400 shrink-0"
                      title="Unstage"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}

                {peerEdits.map((p) => (
                  <div
                    key={p.peerId}
                    className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between gap-2"
                  >
                    <span className="font-mono text-slate-200 truncate">{p.summary}</span>
                    <button
                      type="button"
                      onClick={() => onRemovePeerEdit(p.peerId)}
                      className="text-slate-400 hover:text-rose-400 shrink-0"
                      title="Unstage"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>

              {/* Execution Phases */}
              <div className="space-y-2">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  Execution Plan
                </div>
                <div className="space-y-1.5">
                  {plan.phases.map((ph) => (
                    <div key={ph.phase} className="px-3 py-2 rounded-lg bg-slate-900/70 border border-slate-800">
                      <div className="font-semibold text-white">
                        Phase {ph.phase}: {ph.name}
                      </div>
                      {ph.targets.length === 0 ? (
                        <div className="text-slate-500 mt-0.5">No targets queued in this phase.</div>
                      ) : (
                        <ul className="mt-1 space-y-0.5 text-slate-300 font-mono text-[11px]">
                          {ph.targets.map((t, i) => (
                            <li key={`${t.targetId}-${i}`}>• {t.summary}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}

          {/* Last Execution Result */}
          {lastResult && (
            <div
              className={`p-3 rounded-lg border space-y-2 ${
                lastResult.success
                  ? 'bg-emerald-500/10 border-emerald-500/40'
                  : 'bg-rose-500/10 border-rose-500/40'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-white flex items-center gap-1.5">
                  {lastResult.success ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                  )}
                  {lastResult.dryRun ? 'Dry-Run Validation' : 'Phased Fabric Apply'}:{' '}
                  {lastResult.success ? 'PASSED' : 'FAILED'}
                </span>
                {lastResult.rolledBackAny && (
                  <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-mono text-[10px]">
                    AUTO-ROLLED BACK
                  </span>
                )}
              </div>
              {lastResult.error && <div className="text-rose-300 font-mono">{lastResult.error}</div>}
              {lastResult.results.length > 0 && (
                <div className="space-y-1">
                  {lastResult.results.map((r, idx) => (
                    <div
                      key={`${r.targetId}-${idx}`}
                      className="flex items-center justify-between text-[11px] font-mono bg-slate-950/70 px-2.5 py-1 rounded border border-slate-800"
                    >
                      <span className="text-slate-200">
                        P{r.phase} [{r.targetType}] {r.targetId}
                      </span>
                      <span className={r.success ? 'text-emerald-300' : 'text-rose-300'}>
                        {r.rolledBack ? 'ROLLED BACK' : r.success ? r.message || 'OK' : r.error || 'ERROR'}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="px-5 py-3 border-t border-slate-800 bg-slate-900/70 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-xs text-slate-300">
              <span>Rollback Timer (s):</span>
              <input
                type="number"
                min={10}
                max={3600}
                value={confirmTimeoutSec}
                onChange={(e) => setConfirmTimeoutSec(Math.max(10, Number(e.target.value) || 120))}
                className="w-20 px-2 py-1 rounded bg-slate-950 border border-slate-700 text-white font-mono text-xs"
              />
            </label>
            <button
              type="button"
              onClick={onResetDraft}
              disabled={!hasChanges || running}
              className="px-2.5 py-1.5 rounded border border-slate-700 hover:bg-slate-800 disabled:opacity-40 text-slate-300 text-xs flex items-center gap-1"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Discard Staged
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={!hasChanges || running}
              onClick={() => void executePlan(true)}
              className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 border border-slate-700 text-sky-300 text-xs font-medium"
            >
              {running ? 'Working...' : 'Dry-Run Validate'}
            </button>
            <button
              type="button"
              disabled={!hasChanges || running}
              onClick={() => void executePlan(false)}
              className="px-3.5 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white text-xs font-semibold flex items-center gap-1.5"
            >
              <Play className="w-3.5 h-3.5" />
              {running ? 'Applying...' : 'Commit Phased Apply'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
