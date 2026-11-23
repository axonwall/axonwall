'use client';

import React, { useState } from 'react';
import { ArrowUpRight, CopyPlus, Layers, Trash2, X } from 'lucide-react';
import type { DesiredState, TopologyCableEdge, TopologyCanvasNode } from '@axonwall/lib/schemas';

interface ScenarioManagerModalProps {
  open: boolean;
  onClose: () => void;
  draftState: DesiredState | null;
  liveNodes: TopologyCanvasNode[];
  liveCables: TopologyCableEdge[];
  activeScenarioId: string | undefined;
  onSelectScenario: (scenarioId: string | undefined) => void;
  onCreateScenario: (name: string, description: string, cloneCurrent: boolean) => void;
  onDeleteScenario: (scenarioId: string) => void;
  onPromoteScenarioToLive: (scenarioId: string) => void;
}

export function ScenarioManagerModal({
  open,
  onClose,
  draftState,
  liveNodes,
  liveCables,
  activeScenarioId,
  onSelectScenario,
  onCreateScenario,
  onDeleteScenario,
  onPromoteScenarioToLive,
}: ScenarioManagerModalProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [cloneCurrent, setCloneCurrent] = useState(true);

  if (!open) return null;

  const scenarios = draftState?.topology?.scenarios ?? [];

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    onCreateScenario(name.trim(), description.trim(), cloneCurrent);
    setName('');
    setDescription('');
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
      <div className="w-full max-w-2xl max-h-[85vh] bg-slate-950 border border-slate-800 rounded-xl shadow-2xl flex flex-col overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 bg-slate-900 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-sky-400" />
            <div>
              <h2 className="text-sm font-semibold text-white">What-If &amp; Rack Plan Scenarios</h2>
              <p className="text-xs text-slate-400">
                Design cable plans or upgrade topologies in isolation, then promote them to Live Fabric
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
          {/* Live Fabric Baseline */}
          <div
            className={`p-3 rounded-lg border flex items-center justify-between ${
              !activeScenarioId
                ? 'border-sky-500/60 bg-sky-500/10'
                : 'border-slate-800 bg-slate-900'
            }`}
          >
            <div>
              <div className="font-semibold text-white">Live Fabric (Production Baseline)</div>
              <div className="font-mono text-[11px] text-slate-400">
                {liveNodes.length} nodes · {liveCables.length} cables
              </div>
            </div>
            <button
              type="button"
              onClick={() => {
                onSelectScenario(undefined);
                onClose();
              }}
              className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white"
            >
              {!activeScenarioId ? 'Active' : 'Switch to Live'}
            </button>
          </div>

          {/* Saved What-If Scenarios */}
          <div className="space-y-2">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Saved Scenarios ({scenarios.length})
            </div>
            {scenarios.length === 0 ? (
              <div className="py-5 text-center text-slate-500 border border-dashed border-slate-800 rounded-lg">
                No What-If scenarios yet.
              </div>
            ) : (
              scenarios.map((sc) => {
                const isActive = activeScenarioId === sc.id;
                const diffNodes = Math.abs(sc.nodes.length - liveNodes.length);
                const diffCables = Math.abs(sc.cables.length - liveCables.length);
                return (
                  <div
                    key={sc.id}
                    className={`p-3 rounded-lg border flex flex-wrap items-center justify-between gap-2 ${
                      isActive ? 'border-sky-500/60 bg-sky-500/10' : 'border-slate-800 bg-slate-900'
                    }`}
                  >
                    <div className="min-w-0">
                      <div className="font-semibold text-white">{sc.name}</div>
                      {sc.description && <div className="text-slate-400">{sc.description}</div>}
                      <div className="font-mono text-[11px] text-slate-400 mt-0.5">
                        {sc.nodes.length} nodes · {sc.cables.length} cables (Δ {diffNodes}n / {diffCables}c vs live)
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => {
                          onSelectScenario(sc.id);
                          onClose();
                        }}
                        className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white"
                      >
                        {isActive ? 'Active' : 'Edit'}
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          onPromoteScenarioToLive(sc.id);
                          onClose();
                        }}
                        className="px-2.5 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-medium flex items-center gap-1"
                        title="Promote this scenario to Live Fabric draft"
                      >
                        <ArrowUpRight className="w-3.5 h-3.5" />
                        Promote
                      </button>
                      <button
                        type="button"
                        onClick={() => onDeleteScenario(sc.id)}
                        className="p-1.5 rounded hover:bg-rose-500/20 text-slate-400 hover:text-rose-300"
                        title="Delete scenario"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Create New Scenario */}
          <form onSubmit={handleCreate} className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
            <div className="font-semibold text-white flex items-center gap-1.5">
              <CopyPlus className="w-4 h-4 text-sky-400" />
              Create New What-If Scenario
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. 10GbE Core Switch Cutover"
                className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white"
              />
              <input
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Optional migration notes"
                className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white"
              />
            </div>
            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={cloneCurrent}
                  onChange={(e) => setCloneCurrent(e.target.checked)}
                  className="accent-sky-500"
                />
                <span>Clone current nodes &amp; cables</span>
              </label>
              <button
                type="submit"
                disabled={!name.trim()}
                className="px-3.5 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white font-semibold"
              >
                Create Scenario
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
