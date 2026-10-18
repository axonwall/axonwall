'use client';

import React, { useState, useEffect } from 'react';
import {
  GitBranch,
  ShieldAlert,
  Users,
  Server,
  Key,
  AlertTriangle,
  RefreshCw,
  Zap,
  ArrowRight,
} from 'lucide-react';
import {
  getAttackGraphDataAction,
  type AttackNode,
  type AttackEdge,
} from '@/server/vigilante';

export default function AttackGraphPage() {
  const [nodes, setNodes] = useState<AttackNode[]>([]);
  const [edges, setEdges] = useState<AttackEdge[]>([]);
  const [criticalPaths, setCriticalPaths] = useState(0);
  const [selectedNode, setSelectedNode] = useState<AttackNode | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      setLoading(true);
      const res = await getAttackGraphDataAction();
      setNodes(res.nodes);
      setEdges(res.edges);
      setCriticalPaths(res.criticalPathsCount);
      if (res.nodes.length > 0) {
        setSelectedNode(res.nodes.find((n) => n.highValue) || res.nodes[0]);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const getNodeIcon = (type: AttackNode['type']) => {
    switch (type) {
      case 'User':
        return Users;
      case 'Computer':
        return Server;
      default:
        return Key;
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
            <GitBranch className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Active Directory Attack Graph</h1>
            <p className="text-sm text-slate-400">
              Correlated BloodHound + Flamingo lateral movement attack paths & privilege escalation graph.
            </p>
          </div>
        </div>

        <button
          onClick={loadData}
          className="px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-xl text-xs text-slate-300 font-medium flex items-center gap-2 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Recompute Paths
        </button>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400">Critical Lateral Attack Paths</div>
          <div className="text-2xl font-bold text-rose-400">{criticalPaths} Paths Identified</div>
          <div className="text-[11px] text-slate-500">Shortest step to DA: 3 hops</div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400">Compromised Identities</div>
          <div className="text-2xl font-bold text-amber-400">
            {nodes.filter((n) => n.compromised).length} / {nodes.length} Nodes
          </div>
          <div className="text-[11px] text-slate-500">Includes service accounts</div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400">Crown Jewel Target</div>
          <div className="text-2xl font-bold text-purple-400">CORP.LOCAL Root</div>
          <div className="text-[11px] text-slate-500">Domain Controller Isolation Ready</div>
        </div>
      </div>

      {/* Graph Visualizer & Details Split */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Visual Graph View */}
        <div className="lg:col-span-2 p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-6">
          <div className="flex items-center justify-between text-xs text-slate-400 border-b border-slate-800 pb-3">
            <span className="font-semibold text-white">Identity & Workstation Topology Graph</span>
            <span>Click any node to inspect risk & privileges</span>
          </div>

          <div className="space-y-3">
            {edges.map((edge) => {
              const src = nodes.find((n) => n.id === edge.source);
              const tgt = nodes.find((n) => n.id === edge.target);

              return (
                <div
                  key={edge.id}
                  className="p-3 bg-slate-950/80 border border-slate-800/80 rounded-xl flex items-center justify-between gap-4 text-xs hover:border-purple-500/50 transition-all cursor-pointer"
                  onClick={() => tgt && setSelectedNode(tgt)}
                >
                  <div className="flex items-center gap-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        src?.compromised
                          ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {src?.label}
                    </span>
                    <div className="flex items-center gap-1 text-purple-400 font-mono text-[11px]">
                      <span>──[{edge.relationship}]──</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        tgt?.highValue
                          ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {tgt?.label}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-slate-500">Risk Weight:</span>
                    <span
                      className={`font-mono font-bold text-[11px] ${
                        edge.riskWeight >= 80 ? 'text-rose-400' : 'text-amber-400'
                      }`}
                    >
                      {edge.riskWeight}/100
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Node Detail Card */}
        <div className="lg:col-span-1 p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 text-white font-semibold text-sm">
            <ShieldAlert className="w-4 h-4 text-purple-400" />
            <span>Node Inspector</span>
          </div>

          {selectedNode ? (
            <div className="space-y-4">
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="text-[11px] text-slate-500 uppercase">{selectedNode.type}</div>
                <div className="text-lg font-bold text-white font-mono">{selectedNode.label}</div>
                <div className="flex gap-2 pt-1">
                  {selectedNode.compromised && (
                    <span className="px-2 py-0.5 rounded bg-rose-500/20 border border-rose-500/40 text-rose-300 text-[10px] font-bold">
                      COMPROMISED
                    </span>
                  )}
                  {selectedNode.highValue && (
                    <span className="px-2 py-0.5 rounded bg-purple-500/20 border border-purple-500/40 text-purple-300 text-[10px] font-bold">
                      CROWN JEWEL
                    </span>
                  )}
                </div>
              </div>

              <div className="space-y-2 text-xs">
                <div className="text-slate-400 font-medium">SOAR Remediation Recommendation:</div>
                <p className="text-slate-300 leading-relaxed bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                  {selectedNode.compromised
                    ? 'Revoke Active Directory Kerberos ticket, force password change, and purge cached credentials on workstation.'
                    : 'Enforce Tier 0 Administrative separation and disable unconstrained delegation to this object.'}
                </p>
              </div>
            </div>
          ) : (
            <div className="text-center py-10 text-slate-500 text-xs">Select a node from the attack graph.</div>
          )}
        </div>
      </div>
    </div>
  );
}
