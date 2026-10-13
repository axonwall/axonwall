'use client';

import { Settings, History, Users, Shield, Server, CheckCircle2, RotateCcw, FileDiff, RefreshCw, GitCommit, Check } from 'lucide-react';
import { useState, useEffect } from 'react';
import {
  getGitOpsHistory,
  getCommitDiff,
  rollbackToGitOpsCommit,
  type GitCommitRecord,
} from '@/server/gitops';

export default function SystemPage() {
  const [commits, setCommits] = useState<GitCommitRecord[]>([]);
  const [currentHash, setCurrentHash] = useState<string | undefined>();
  const [isLoading, setIsLoading] = useState(true);
  const [selectedDiff, setSelectedDiff] = useState<{ hash: string; diff: string } | null>(null);
  const [isLoadingDiff, setIsLoadingDiff] = useState(false);
  const [rollingBackHash, setRollingBackHash] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  useEffect(() => {
    loadGitOps();
  }, []);

  const loadGitOps = async () => {
    setIsLoading(true);
    try {
      const data = await getGitOpsHistory();
      setCommits(data.commits);
      setCurrentHash(data.currentHash);
    } catch {}
    setIsLoading(false);
  };

  const handleViewDiff = async (hash: string) => {
    if (selectedDiff?.hash === hash) {
      setSelectedDiff(null);
      return;
    }
    setIsLoadingDiff(true);
    try {
      const diff = await getCommitDiff(hash);
      setSelectedDiff({ hash, diff });
    } catch {
      setSelectedDiff({ hash, diff: 'Failed to load diff.' });
    } finally {
      setIsLoadingDiff(false);
    }
  };

  const handleRollback = async (hash: string) => {
    const confirm = window.confirm(
      `Revert active firewall configuration to Git revision ${hash.slice(0, 8)}?\n\nWatchdog safety rollback will be armed for 120s.`
    );
    if (!confirm) return;

    setRollingBackHash(hash);
    setActionMessage(null);
    try {
      const res = await rollbackToGitOpsCommit(hash);
      setActionMessage(res.message);
      await loadGitOps();
    } catch (err: any) {
      setActionMessage(`Rollback failed: ${err?.message || 'Unknown error'}`);
    } finally {
      setRollingBackHash(null);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <GitCommit className="w-6 h-6 text-emerald-400" />
            <span>System & GitOps Audit Trail</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Immutable configuration versioning via Git, commit-confirm audit trail, and LDAP directory status.
          </p>
        </div>

        <button
          type="button"
          onClick={loadGitOps}
          disabled={isLoading}
          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition flex items-center gap-1.5 border border-slate-700 font-medium cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh GitOps</span>
        </button>
      </div>

      {actionMessage && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
          <span>{actionMessage}</span>
        </div>
      )}

      {/* System Service Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 text-white font-semibold">
            <Server className="w-5 h-5 text-indigo-400" />
            <h2>Identity & Access (LDAP)</h2>
          </div>
          <div className="text-xs text-slate-300 space-y-2">
            <div className="flex justify-between">
              <span className="text-slate-400">Server Type:</span>
              <span>OpenLDAP (Internal)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Base DN:</span>
              <span className="font-mono text-emerald-400">dc=axonwall,dc=local</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Directory Status:</span>
              <span className="text-emerald-400 flex items-center gap-1 font-medium">
                <CheckCircle2 className="w-3.5 h-3.5" /> Connected
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Fallback Admin:</span>
              <span className="text-amber-400 font-mono">root / enabled</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 text-white font-semibold">
            <Shield className="w-5 h-5 text-emerald-400" />
            <h2>Data Plane Security</h2>
          </div>
          <div className="text-xs text-slate-300 space-y-2">
            <div className="flex justify-between">
              <span className="text-slate-400">Kernel Firewall:</span>
              <span className="text-emerald-400 font-medium">Linux nftables (Active)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Table Ownership:</span>
              <span className="font-mono text-cyan-400">inet axonwall</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">GitOps Repository:</span>
              <span className="text-emerald-400 font-mono">/var/lib/axonwall/gitops</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Early-Boot Apply:</span>
              <span className="text-emerald-400 font-medium">Active (systemd)</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 text-white font-semibold">
            <Settings className="w-5 h-5 text-cyan-400" />
            <h2>Controller Status</h2>
          </div>
          <div className="text-xs text-slate-300 space-y-2">
            <div className="flex justify-between">
              <span className="text-slate-400">Agent Socket:</span>
              <span className="font-mono text-slate-300">/run/axonwall/agent.sock</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Rollback Timeout:</span>
              <span>120 seconds</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Active Commit:</span>
              <span className="font-mono text-emerald-400">
                {currentHash ? currentHash.slice(0, 8) : 'HEAD'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Revision History */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-sm">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-white font-semibold">
            <History className="w-5 h-5 text-emerald-400" />
            <h2>GitOps Configuration Audit Trail & Version Control</h2>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            {commits.length} Committed Revision{commits.length === 1 ? '' : 's'}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm font-mono text-xs">
            <thead className="bg-slate-950 text-slate-400 text-xs font-semibold uppercase tracking-wider border-b border-slate-800 font-sans">
              <tr>
                <th className="px-4 py-3">Commit</th>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Author</th>
                <th className="px-4 py-3">Message</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {commits.map((commit, idx) => {
                const isCurrent = idx === 0 || commit.hash === currentHash;
                return (
                  <tr key={commit.hash} className="hover:bg-slate-800/40 transition">
                    <td className="px-4 py-3 font-bold text-white flex items-center gap-1.5">
                      <GitCommit className="w-3.5 h-3.5 text-cyan-400" />
                      <span>{commit.shortHash}</span>
                    </td>
                    <td className="px-4 py-3 text-slate-400">{commit.date}</td>
                    <td className="px-4 py-3 text-slate-300">{commit.author}</td>
                    <td className="px-4 py-3 text-slate-200 font-sans">{commit.message}</td>
                    <td className="px-4 py-3">
                      {isCurrent ? (
                        <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold text-[11px]">
                          Active (LKG)
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 text-[11px]">
                          Archived
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right space-x-2">
                      <button
                        type="button"
                        onClick={() => handleViewDiff(commit.hash)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-sans transition cursor-pointer"
                      >
                        {selectedDiff?.hash === commit.hash ? 'Hide Diff' : 'View Diff'}
                      </button>
                      {!isCurrent && (
                        <button
                          type="button"
                          onClick={() => handleRollback(commit.hash)}
                          disabled={rollingBackHash === commit.hash}
                          className="px-2.5 py-1 rounded bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/30 text-xs font-sans transition cursor-pointer"
                        >
                          {rollingBackHash === commit.hash ? 'Reverting...' : 'Rollback'}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Selected Commit Diff Viewer */}
        {selectedDiff && (
          <div className="mt-4 bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-white flex items-center gap-2">
                <FileDiff className="w-4 h-4 text-cyan-400" />
                <span>Diff for Commit {selectedDiff.hash.slice(0, 8)}</span>
              </span>
              <button
                type="button"
                onClick={() => setSelectedDiff(null)}
                className="text-slate-500 hover:text-slate-300 text-xs font-sans"
              >
                Close
              </button>
            </div>
            <pre className="bg-slate-900 border border-slate-800/80 rounded p-3 text-xs font-mono text-slate-300 overflow-x-auto max-h-72 leading-relaxed">
              {selectedDiff.diff}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
