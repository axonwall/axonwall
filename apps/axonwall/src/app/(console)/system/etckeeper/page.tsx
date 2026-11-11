'use client';

import React, { useState, useEffect, useMemo } from 'react';
import Link from 'next/link';
import {
  GitBranch,
  GitCommit,
  History,
  Settings,
  FileDiff,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  Clock,
  Save,
  Play,
  Search,
  Filter,
  Copy,
  Check,
  FolderGit2,
  FileCode2,
  EyeOff,
  ArrowLeft,
} from 'lucide-react';
import {
  getEtckeeperStatus,
  getEtckeeperHistory,
  getEtckeeperDiff,
  commitEtckeeper,
  initEtckeeper,
  saveEtckeeperConfig,
  type EtckeeperStatus,
  type EtckeeperCommitLog,
  type EtckeeperConfig,
} from '@/server/gitops';

function UnifiedDiffViewer({ diff, title }: { diff: string; title?: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(diff);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const lines = useMemo(() => (diff || '').split('\n'), [diff]);

  return (
    <div className="rounded-xl bg-slate-950 border border-slate-800 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 bg-slate-900/90 border-b border-slate-800 text-xs">
        <div className="flex items-center gap-2 font-mono text-slate-300">
          <FileDiff className="w-4 h-4 text-emerald-400" />
          <span>{title || 'Unified Git Diff (/etc)'}</span>
        </div>
        <button
          type="button"
          onClick={handleCopy}
          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center gap-1.5 transition cursor-pointer"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copied ? 'Copied' : 'Copy Diff'}</span>
        </button>
      </div>
      <div className="p-4 max-h-[540px] overflow-auto font-mono text-xs leading-relaxed">
        {lines.map((line, i) => {
          let cls = 'text-slate-300';
          if (line.startsWith('diff --git') || line.startsWith('index ')) {
            cls = 'text-amber-300 font-bold pt-2';
          } else if (line.startsWith('--- ') || line.startsWith('+++ ')) {
            cls = 'text-cyan-300 font-semibold';
          } else if (line.startsWith('@@')) {
            cls = 'text-purple-400 bg-purple-950/30 px-1 rounded';
          } else if (line.startsWith('+')) {
            cls = 'text-emerald-300 bg-emerald-950/30 px-1';
          } else if (line.startsWith('-')) {
            cls = 'text-rose-300 bg-rose-950/30 px-1';
          } else if (line.startsWith('commit ') || line.startsWith('Author:') || line.startsWith('Date:')) {
            cls = 'text-slate-400';
          }
          return (
            <div key={i} className={`whitespace-pre ${cls}`}>
              {line || ' '}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function EtckeeperPage() {
  const [activeTab, setActiveTab] = useState<'logs' | 'config'>('logs');
  const [status, setStatus] = useState<EtckeeperStatus | null>(null);
  const [history, setHistory] = useState<EtckeeperCommitLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Commit & Diff state
  const [commitMessage, setCommitMessage] = useState('');
  const [isCommitting, setIsCommitting] = useState(false);
  const [isInitializing, setIsInitializing] = useState(false);
  const [selectedCommitDiff, setSelectedCommitDiff] = useState<{ hash: string; diff: string } | null>(null);
  const [isLoadingDiffHash, setIsLoadingDiffHash] = useState<string | null>(null);
  const [workingTreeDiff, setWorkingTreeDiff] = useState<string | null>(null);
  const [isLoadingWorkingDiff, setIsLoadingWorkingDiff] = useState(false);

  // History filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [pathFilter, setPathFilter] = useState('');
  const [historyLimit, setHistoryLimit] = useState(50);

  // Configuration form state
  const [vcs, setVcs] = useState('git');
  const [dailyAutocommit, setDailyAutocommit] = useState(true);
  const [autoCommitOnApply, setAutoCommitOnApply] = useState(true);
  const [avoidSpecialFileWarning, setAvoidSpecialFileWarning] = useState(false);
  const [avoidCommitBeforeInstall, setAvoidCommitBeforeInstall] = useState(false);
  const [highlevelPkgMgr, setHighlevelPkgMgr] = useState('apt');
  const [lowlevelPkgMgr, setLowlevelPkgMgr] = useState('dpkg');
  const [pushRemote, setPushRemote] = useState('');
  const [gitCommitOptions, setGitCommitOptions] = useState('');
  const [ignorePatternsText, setIgnorePatternsText] = useState('zfs/zpool.cache');
  const [rawConfig, setRawConfig] = useState('');
  const [isSavingConfig, setIsSavingConfig] = useState(false);

  const populateConfigForm = (cfg?: EtckeeperConfig) => {
    if (!cfg) return;
    setVcs(cfg.vcs || 'git');
    setDailyAutocommit(cfg.dailyAutocommit ?? true);
    setAutoCommitOnApply(cfg.autoCommitOnApply ?? true);
    setAvoidSpecialFileWarning(cfg.avoidSpecialFileWarning ?? false);
    setAvoidCommitBeforeInstall(cfg.avoidCommitBeforeInstall ?? false);
    setHighlevelPkgMgr(cfg.highlevelPackageManager || 'apt');
    setLowlevelPkgMgr(cfg.lowlevelPackageManager || 'dpkg');
    setPushRemote(cfg.pushRemote || '');
    setGitCommitOptions(cfg.gitCommitOptions || '');
    setIgnorePatternsText((cfg.customIgnorePatterns || ['zfs/zpool.cache']).join('\n'));
    setRawConfig(cfg.rawConfig || '');
  };

  const loadData = async (limitOverride?: number, pathOverride?: string) => {
    setIsLoading(true);
    try {
      const effectiveLimit = limitOverride ?? historyLimit;
      const effectivePath = pathOverride ?? pathFilter;
      const [st, hist] = await Promise.all([
        getEtckeeperStatus(),
        getEtckeeperHistory(effectiveLimit, effectivePath),
      ]);
      setStatus(st);
      setHistory(hist);
      if (st?.config) {
        populateConfigForm(st.config);
      }
    } catch (err: any) {
      setActionMessage({
        type: 'error',
        text: err?.message || 'Failed to load etckeeper status from daemon.',
      });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleInitRepo = async () => {
    setIsInitializing(true);
    setActionMessage(null);
    try {
      const res = await initEtckeeper();
      setActionMessage({
        type: res.success ? 'success' : 'error',
        text: res.message,
      });
      await loadData();
    } catch (err: any) {
      setActionMessage({
        type: 'error',
        text: err?.message || 'Failed to initialize etckeeper.',
      });
    } finally {
      setIsInitializing(false);
    }
  };

  const handleCommitNow = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setIsCommitting(true);
    setActionMessage(null);
    try {
      const msg = commitMessage.trim() || 'Manual /etc snapshot via Axonwall Web Console';
      const res = await commitEtckeeper(msg);
      setActionMessage({
        type: res.success ? 'success' : 'error',
        text: res.message,
      });
      if (res.success) {
        setCommitMessage('');
        setWorkingTreeDiff(null);
        await loadData();
      }
    } catch (err: any) {
      setActionMessage({
        type: 'error',
        text: err?.message || 'Commit failed.',
      });
    } finally {
      setIsCommitting(false);
    }
  };

  const handleToggleCommitDiff = async (hash: string) => {
    if (selectedCommitDiff?.hash === hash) {
      setSelectedCommitDiff(null);
      return;
    }
    setIsLoadingDiffHash(hash);
    try {
      const diff = await getEtckeeperDiff(hash);
      setSelectedCommitDiff({ hash, diff });
    } catch (err: any) {
      setSelectedCommitDiff({
        hash,
        diff: `Failed to load diff for ${hash}: ${err?.message || 'Unknown error'}`,
      });
    } finally {
      setIsLoadingDiffHash(null);
    }
  };

  const handleToggleWorkingTreeDiff = async () => {
    if (workingTreeDiff !== null) {
      setWorkingTreeDiff(null);
      return;
    }
    setIsLoadingWorkingDiff(true);
    try {
      const diff = await getEtckeeperDiff('');
      setWorkingTreeDiff(diff);
    } catch (err: any) {
      setWorkingTreeDiff(`Failed to load working tree diff: ${err?.message || 'Unknown error'}`);
    } finally {
      setIsLoadingWorkingDiff(false);
    }
  };

  const handleQuickIgnoreFile = async (filePath: string) => {
    const existing = ignorePatternsText
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
    if (!existing.includes(filePath)) {
      existing.push(filePath);
    }
    setIgnorePatternsText(existing.join('\n'));
    setIsSavingConfig(true);
    setActionMessage(null);
    try {
      const res = await saveEtckeeperConfig({
        vcs,
        dailyAutocommit,
        autoCommitOnApply,
        avoidSpecialFileWarning,
        avoidCommitBeforeInstall,
        highlevelPackageManager: highlevelPkgMgr,
        lowlevelPackageManager: lowlevelPkgMgr,
        pushRemote,
        gitCommitOptions,
        customIgnorePatterns: existing,
      });
      setActionMessage({
        type: res.success ? 'success' : 'error',
        text: res.success
          ? `Added "${filePath}" to /etc/.gitignore and untracked from git index.`
          : res.message,
      });
      await loadData();
    } finally {
      setIsSavingConfig(false);
    }
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingConfig(true);
    setActionMessage(null);
    try {
      const patterns = ignorePatternsText
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean);
      const res = await saveEtckeeperConfig({
        vcs,
        dailyAutocommit,
        autoCommitOnApply,
        avoidSpecialFileWarning,
        avoidCommitBeforeInstall,
        highlevelPackageManager: highlevelPkgMgr,
        lowlevelPackageManager: lowlevelPkgMgr,
        pushRemote,
        gitCommitOptions,
        customIgnorePatterns: patterns,
      });
      setActionMessage({
        type: res.success ? 'success' : 'error',
        text: res.message,
      });
      if (res.config) {
        populateConfigForm(res.config);
      }
      await loadData();
    } catch (err: any) {
      setActionMessage({
        type: 'error',
        text: err?.message || 'Failed to save etckeeper configuration.',
      });
    } finally {
      setIsSavingConfig(false);
    }
  };

  const filteredHistory = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return history;
    return history.filter(
      (item) =>
        item.hash.toLowerCase().includes(q) ||
        item.subject.toLowerCase().includes(q) ||
        item.author.toLowerCase().includes(q)
    );
  }, [history, searchQuery]);

  const modifiedFiles = status?.modifiedFiles || [];

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
            <Link href="/system" className="hover:text-emerald-400 flex items-center gap-1 transition">
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>System Configuration</span>
            </Link>
            <span>/</span>
            <span className="text-slate-300">Etckeeper (/etc Version Control)</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <FolderGit2 className="w-6 h-6 text-emerald-400" />
            <span>Etckeeper Configuration, Commit Logs &amp; Unified Diffs</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Full <code className="text-emerald-400 font-mono">/etc</code> directory version control, automated bundle commit hooks, ignore rules, and historical diff inspection.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {status?.installed && !status?.initialized && (
            <button
              type="button"
              onClick={handleInitRepo}
              disabled={isInitializing}
              className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{isInitializing ? 'Initializing...' : 'Initialize /etc Repo'}</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => loadData()}
            disabled={isLoading}
            className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 transition flex items-center gap-1.5 border border-slate-700 font-medium cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh Status</span>
          </button>
        </div>
      </div>

      {/* Action Banner */}
      {actionMessage && (
        <div
          className={`p-3.5 rounded-xl border text-xs flex items-center justify-between gap-2 ${
            actionMessage.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
          }`}
        >
          <div className="flex items-center gap-2">
            {actionMessage.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
            ) : (
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            )}
            <span>{actionMessage.text}</span>
          </div>
          <button
            type="button"
            onClick={() => setActionMessage(null)}
            className="text-slate-400 hover:text-white text-xs cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Status Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Repository State</span>
            <GitBranch className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-lg font-bold text-white flex items-center gap-2">
            {status?.installed ? (
              status.initialized ? (
                <span className="text-emerald-400">Active ({status.vcs || 'git'})</span>
              ) : (
                <span className="text-amber-400">Uninitialized</span>
              )
            ) : (
              <span className="text-rose-400">Not Installed</span>
            )}
          </div>
          <div className="text-xs text-slate-400 font-mono">
            Tracked: <span className="text-cyan-400">{status?.trackedPath || '/etc'}</span> ({status?.totalCommits ?? history.length} commits)
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Working Tree (/etc)</span>
            <FileDiff className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-lg font-bold">
            {status?.clean ? (
              <span className="text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                <span>Clean (Committed)</span>
              </span>
            ) : (
              <span className="text-amber-400 flex items-center gap-1.5">
                <AlertCircle className="w-4 h-4" />
                <span>{modifiedFiles.length} Modified File{modifiedFiles.length === 1 ? '' : 's'}</span>
              </span>
            )}
          </div>
          <div className="text-xs text-slate-400 flex items-center justify-between">
            <span>Bundle Autocommit: {status?.config?.autoCommitOnApply !== false ? 'Enabled' : 'Disabled'}</span>
            {!status?.clean && (
              <button
                type="button"
                onClick={handleToggleWorkingTreeDiff}
                className="text-cyan-400 hover:underline font-medium cursor-pointer"
              >
                {workingTreeDiff !== null ? 'Hide Diff' : 'View Diff'}
              </button>
            )}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Daily Timer (systemd)</span>
            <Clock className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-lg font-bold">
            {status?.timerActive ? (
              <span className="text-emerald-400">etckeeper.timer Active</span>
            ) : (
              <span className="text-slate-400">Timer Inactive</span>
            )}
          </div>
          <div className="text-xs text-slate-400 truncate" title={status?.nextTimerRun || ''}>
            {status?.nextTimerRun ? `Next: ${status.nextTimerRun}` : 'Daily autocommit schedule'}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Latest /etc Commit</span>
            <GitCommit className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-lg font-bold font-mono text-purple-400">
            {status?.lastCommitHash ? status.lastCommitHash.slice(0, 8) : 'None'}
          </div>
          <div className="text-xs text-slate-400 truncate" title={status?.lastCommitMsg || ''}>
            {status?.lastCommitMsg || 'No commits recorded yet'}
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
        <button
          type="button"
          onClick={() => setActiveTab('logs')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold transition flex items-center gap-2 cursor-pointer ${
            activeTab === 'logs'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white bg-slate-900 border border-slate-800'
          }`}
        >
          <History className="w-4 h-4 text-emerald-400" />
          <span>Commit History &amp; Diffs ({history.length})</span>
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('config')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold transition flex items-center gap-2 cursor-pointer ${
            activeTab === 'config'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white bg-slate-900 border border-slate-800'
          }`}
        >
          <Settings className="w-4 h-4 text-cyan-400" />
          <span>Etckeeper Configuration (/etc/etckeeper/etckeeper.conf)</span>
        </button>
      </div>

      {/* TAB 1: COMMIT LOGS & DIFFS */}
      {activeTab === 'logs' && (
        <div className="space-y-6">
          {/* Manual Snapshot Commit Bar */}
          <form
            onSubmit={handleCommitNow}
            className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row items-stretch sm:items-center gap-3"
          >
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 shrink-0">
              <GitCommit className="w-4 h-4 text-emerald-400" />
              <span>Create /etc Snapshot:</span>
            </div>
            <input
              type="text"
              value={commitMessage}
              onChange={(e) => setCommitMessage(e.target.value)}
              placeholder="Enter commit message (e.g., Baseline /etc snapshot before maintenance)..."
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-emerald-500"
            />
            <button
              type="submit"
              disabled={isCommitting || !status?.installed}
              className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center justify-center gap-1.5 transition cursor-pointer disabled:opacity-50 shrink-0"
            >
              <GitCommit className="w-3.5 h-3.5" />
              <span>{isCommitting ? 'Committing /etc...' : 'Commit /etc Changes Now'}</span>
            </button>
          </form>

          {/* Uncommitted Working Tree Changes Card */}
          {(!status?.clean || modifiedFiles.length > 0 || workingTreeDiff !== null) && (
            <div className="bg-slate-900 border border-amber-500/30 rounded-xl p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-bold text-white flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 text-amber-400" />
                    <span>Uncommitted Changes in /etc ({modifiedFiles.length})</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    These files have been modified or created in <code className="text-amber-300 font-mono">/etc</code> since the last commit. Commit them above or ignore noisy runtime cache files.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleToggleWorkingTreeDiff}
                    disabled={isLoadingWorkingDiff}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-cyan-300 border border-slate-700 font-medium flex items-center gap-1.5 transition cursor-pointer"
                  >
                    <FileDiff className="w-3.5 h-3.5" />
                    <span>
                      {isLoadingWorkingDiff
                        ? 'Loading Diff...'
                        : workingTreeDiff !== null
                        ? 'Hide Working Tree Diff'
                        : 'Inspect Working Tree Diff'}
                    </span>
                  </button>
                </div>
              </div>

              {modifiedFiles.length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {modifiedFiles.map((file, idx) => (
                    <div
                      key={`${file.path}-${idx}`}
                      className="flex items-center justify-between px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono"
                    >
                      <div className="flex items-center gap-2 truncate">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            file.status.includes('?') || file.status.includes('A')
                              ? 'bg-emerald-500/20 text-emerald-300'
                              : file.status.includes('D')
                              ? 'bg-rose-500/20 text-rose-300'
                              : 'bg-amber-500/20 text-amber-300'
                          }`}
                        >
                          {file.status}
                        </span>
                        <span className="text-slate-200 truncate" title={`/etc/${file.path}`}>
                          /etc/{file.path}
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleQuickIgnoreFile(file.path)}
                        disabled={isSavingConfig}
                        title="Add to /etc/.gitignore and untrack from git"
                        className="text-[11px] text-slate-400 hover:text-amber-300 flex items-center gap-1 shrink-0 ml-2 cursor-pointer"
                      >
                        <EyeOff className="w-3 h-3" />
                        <span>Ignore</span>
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {workingTreeDiff !== null && (
                <UnifiedDiffViewer diff={workingTreeDiff} title="git -C /etc diff (Uncommitted Working Tree)" />
              )}
            </div>
          )}

          {/* Commit History Table & Search */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-white font-semibold">
                <History className="w-5 h-5 text-emerald-400" />
                <h2>/etc Git Commit History (etckeeper)</h2>
              </div>

              <div className="flex flex-wrap items-center gap-2 text-xs">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Filter commits..."
                    className="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-white font-mono focus:outline-none focus:border-emerald-500"
                  />
                </div>

                <div className="flex items-center gap-1">
                  <Filter className="w-3.5 h-3.5 text-slate-500" />
                  <input
                    type="text"
                    value={pathFilter}
                    onChange={(e) => setPathFilter(e.target.value)}
                    placeholder="Path (e.g. axonwall/)"
                    className="w-40 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-white font-mono focus:outline-none focus:border-emerald-500"
                  />
                  <button
                    type="button"
                    onClick={() => loadData(historyLimit, pathFilter)}
                    className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 cursor-pointer"
                  >
                    Apply
                  </button>
                </div>

                <select
                  value={historyLimit}
                  onChange={(e) => {
                    const next = Number(e.target.value) || 50;
                    setHistoryLimit(next);
                    loadData(next, pathFilter);
                  }}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-white font-mono"
                >
                  <option value={25}>25 commits</option>
                  <option value={50}>50 commits</option>
                  <option value={100}>100 commits</option>
                  <option value={200}>200 commits</option>
                </select>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-slate-950 text-slate-400 text-xs font-semibold uppercase tracking-wider border-b border-slate-800 font-sans">
                  <tr>
                    <th className="px-4 py-3">Commit</th>
                    <th className="px-4 py-3">Timestamp</th>
                    <th className="px-4 py-3">Author</th>
                    <th className="px-4 py-3">Subject</th>
                    <th className="px-4 py-3 text-right">Diff</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredHistory.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-slate-500 font-sans">
                        No etckeeper commits match the current filter.
                      </td>
                    </tr>
                  ) : (
                    filteredHistory.map((item, idx) => {
                      const shortHash = item.shortHash || item.hash.slice(0, 8);
                      const isExpanded = selectedCommitDiff?.hash === item.hash;
                      const isLoadingThis = isLoadingDiffHash === item.hash;
                      return (
                        <React.Fragment key={item.hash}>
                          <tr className="hover:bg-slate-800/40 transition">
                            <td className="px-4 py-3 font-bold text-white flex items-center gap-1.5">
                              <GitCommit className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                              <span>{shortHash}</span>
                              {idx === 0 && (
                                <span className="ml-1 px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-sans">
                                  HEAD
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-3 text-slate-400 whitespace-nowrap">
                              {item.date ? new Date(item.date).toLocaleString() : '—'}
                            </td>
                            <td className="px-4 py-3 text-cyan-300">{item.author}</td>
                            <td className="px-4 py-3 text-slate-200 font-sans">{item.subject}</td>
                            <td className="px-4 py-3 text-right">
                              <button
                                type="button"
                                onClick={() => handleToggleCommitDiff(item.hash)}
                                disabled={isLoadingThis}
                                className={`px-3 py-1 rounded text-xs font-sans transition cursor-pointer ${
                                  isExpanded
                                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                                    : 'bg-slate-800 hover:bg-slate-700 text-slate-200'
                                }`}
                              >
                                {isLoadingThis ? 'Loading...' : isExpanded ? 'Hide Diff' : 'View Diff'}
                              </button>
                            </td>
                          </tr>
                          {isExpanded && selectedCommitDiff && (
                            <tr>
                              <td colSpan={5} className="p-4 bg-slate-950/60">
                                <UnifiedDiffViewer
                                  diff={selectedCommitDiff.diff}
                                  title={`git -C /etc show ${shortHash} — ${item.subject}`}
                                />
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: ETCKEEPER CONFIGURATION */}
      {activeTab === 'config' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <form
            onSubmit={handleSaveConfig}
            className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-base font-bold text-white">Etckeeper Daemon &amp; Hook Settings</h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Persisted directly to <code className="text-emerald-400 font-mono">/etc/etckeeper/etckeeper.conf</code> and <code className="text-emerald-400 font-mono">/etc/.gitignore</code>
                </p>
              </div>
              <button
                type="submit"
                disabled={isSavingConfig}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
              >
                <Save className="w-3.5 h-3.5" />
                <span>{isSavingConfig ? 'Saving...' : 'Save Etckeeper Config'}</span>
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <label className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={autoCommitOnApply}
                  onChange={(e) => setAutoCommitOnApply(e.target.checked)}
                  className="mt-0.5 rounded bg-slate-900 border-slate-700 text-emerald-500"
                />
                <div>
                  <div className="font-semibold text-white">Autocommit on Axonwall Apply</div>
                  <div className="text-slate-400 mt-0.5">
                    Automatically commit <code className="text-emerald-400">/etc</code> whenever firewall bundles, YAML files, users, or LDAP bindings are applied.
                  </div>
                </div>
              </label>

              <label className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={dailyAutocommit}
                  onChange={(e) => setDailyAutocommit(e.target.checked)}
                  className="mt-0.5 rounded bg-slate-900 border-slate-700 text-emerald-500"
                />
                <div>
                  <div className="font-semibold text-white">Daily Scheduled Autocommit (etckeeper.timer)</div>
                  <div className="text-slate-400 mt-0.5">
                    Enables <code className="text-cyan-400">etckeeper.timer</code> to automatically commit manual SSH edits in <code className="text-emerald-400">/etc</code> daily.
                  </div>
                </div>
              </label>

              <label className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={avoidSpecialFileWarning}
                  onChange={(e) => setAvoidSpecialFileWarning(e.target.checked)}
                  className="mt-0.5 rounded bg-slate-900 border-slate-700 text-emerald-500"
                />
                <div>
                  <div className="font-semibold text-white">Avoid Special File Warnings</div>
                  <div className="text-slate-400 mt-0.5">
                    Sets <code className="text-slate-300">AVOID_SPECIAL_FILE_WARNING=1</code> so sockets or pipes in <code className="text-emerald-400">/etc</code> do not halt non-interactive commits.
                  </div>
                </div>
              </label>

              <label className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={avoidCommitBeforeInstall}
                  onChange={(e) => setAvoidCommitBeforeInstall(e.target.checked)}
                  className="mt-0.5 rounded bg-slate-900 border-slate-700 text-emerald-500"
                />
                <div>
                  <div className="font-semibold text-white">Avoid Pre-Install Autocommit</div>
                  <div className="text-slate-400 mt-0.5">
                    Sets <code className="text-slate-300">AVOID_COMMIT_BEFORE_INSTALL=1</code> to disable automatic commits prior to <code className="text-slate-300">apt/dpkg</code> package runs.
                  </div>
                </div>
              </label>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div>
                <label className="block font-semibold text-slate-400 uppercase mb-1.5">VCS Backend</label>
                <select
                  value={vcs}
                  onChange={(e) => setVcs(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
                >
                  <option value="git">git (Recommended)</option>
                  <option value="hg">hg (Mercurial)</option>
                  <option value="bzr">bzr (Bazaar)</option>
                  <option value="darcs">darcs</option>
                </select>
              </div>

              <div>
                <label className="block font-semibold text-slate-400 uppercase mb-1.5">High-Level Package Manager</label>
                <input
                  type="text"
                  value={highlevelPkgMgr}
                  onChange={(e) => setHighlevelPkgMgr(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-400 uppercase mb-1.5">Low-Level Package Manager</label>
                <input
                  type="text"
                  value={lowlevelPkgMgr}
                  onChange={(e) => setLowlevelPkgMgr(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
                />
              </div>

              <div className="md:col-span-2">
                <label className="block font-semibold text-slate-400 uppercase mb-1.5">
                  Push Remote (PUSH_REMOTE)
                </label>
                <input
                  type="text"
                  value={pushRemote}
                  onChange={(e) => setPushRemote(e.target.value)}
                  placeholder="Optional git remote name(s), e.g. origin"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-400 uppercase mb-1.5">
                  Git Commit Options
                </label>
                <input
                  type="text"
                  value={gitCommitOptions}
                  onChange={(e) => setGitCommitOptions(e.target.value)}
                  placeholder="e.g. --quiet"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
                />
              </div>
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <label className="font-semibold text-slate-400 uppercase">
                  Custom /etc/.gitignore Patterns (One relative path or glob per line)
                </label>
                <div className="flex items-center gap-1.5">
                  {['zfs/zpool.cache', 'axonwall/slot_versions.json', 'mtab'].map((preset) => (
                    <button
                      key={preset}
                      type="button"
                      onClick={() => {
                        const lines = ignorePatternsText
                          .split('\n')
                          .map((s) => s.trim())
                          .filter(Boolean);
                        if (!lines.includes(preset)) {
                          setIgnorePatternsText([...lines, preset].join('\n'));
                        }
                      }}
                      className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-[11px] font-mono text-cyan-300 cursor-pointer"
                    >
                      + {preset}
                    </button>
                  ))}
                </div>
              </div>
              <textarea
                rows={6}
                value={ignorePatternsText}
                onChange={(e) => setIgnorePatternsText(e.target.value)}
                spellCheck={false}
                placeholder="zfs/zpool.cache"
                className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-300 focus:outline-none focus:border-emerald-500"
              />
              <p className="text-[11px] text-slate-400">
                Managed in <code className="text-slate-300 font-mono">/etc/.gitignore</code> outside etckeeper&apos;s auto-generated block so <code className="text-slate-300 font-mono">etckeeper update-ignore</code> preserves them. Exact paths listed here are also untracked from the git index (<code className="text-slate-300 font-mono">git rm --cached</code>) while remaining on disk.
              </p>
            </div>
          </form>

          {/* Raw /etc/etckeeper/etckeeper.conf Preview */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 uppercase tracking-wider">
              <FileCode2 className="w-4 h-4 text-cyan-400" />
              <span>/etc/etckeeper/etckeeper.conf</span>
            </div>
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 overflow-auto max-h-[540px] leading-relaxed">
              {rawConfig || '# /etc/etckeeper/etckeeper.conf not loaded'}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
