'use client';

import {
  Settings,
  History,
  Users,
  Shield,
  Server,
  CheckCircle2,
  RotateCcw,
  FileDiff,
  RefreshCw,
  GitCommit,
  Check,
  FileCode2,
  Save,
  AlertCircle,
  Terminal,
} from 'lucide-react';
import { useState, useEffect } from 'react';
import {
  getGitOpsHistory,
  getCommitDiff,
  rollbackToGitOpsCommit,
  type GitCommitRecord,
} from '@/server/gitops';
import {
  getCurrentDesiredState,
  applyDesiredState,
  getYamlConfigFilesSnapshot,
  saveYamlDomainFile,
} from '@/server/agent';
import { AXONWALL_YAML_DOMAINS, type AxonwallYamlDomainFile } from '@axonwall/lib/yaml';

export default function SystemPage() {
  const [activeTab, setActiveTab] = useState<'yaml' | 'general' | 'gitops'>('yaml');

  // General System Settings
  const [hostname, setHostname] = useState('axonwall');
  const [domain, setDomain] = useState('home.arpa');
  const [timezone, setTimezone] = useState('UTC');
  const [dnsServersText, setDnsServersText] = useState('1.1.1.1, 9.9.9.9');
  const [sshEnabled, setSshEnabled] = useState(true);
  const [sshPort, setSshPort] = useState(22);
  const [webGuiPort, setWebGuiPort] = useState(443);
  const [isSavingGeneral, setIsSavingGeneral] = useState(false);

  // Live YAML Editor state
  const [yamlFiles, setYamlFiles] = useState<Record<string, string>>({});
  const [selectedFilename, setSelectedFilename] = useState<AxonwallYamlDomainFile>('system.yaml');
  const [editorContent, setEditorContent] = useState('');
  const [isSavingYaml, setIsSavingYaml] = useState(false);
  const [yamlErrors, setYamlErrors] = useState<Array<{ file: string; path: string; message: string }>>([]);

  // GitOps History
  const [commits, setCommits] = useState<GitCommitRecord[]>([]);
  const [currentHash, setCurrentHash] = useState<string | undefined>();
  const [isLoading, setIsLoading] = useState(true);
  const [selectedDiff, setSelectedDiff] = useState<{ hash: string; diff: string } | null>(null);
  const [isLoadingDiff, setIsLoadingDiff] = useState(false);
  const [rollingBackHash, setRollingBackHash] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  useEffect(() => {
    loadAll();
  }, []);

  const loadAll = async () => {
    setIsLoading(true);
    try {
      const [gitData, state, snapshot] = await Promise.all([
        getGitOpsHistory(),
        getCurrentDesiredState(),
        getYamlConfigFilesSnapshot(),
      ]);
      setCommits(gitData.commits);
      setCurrentHash(gitData.currentHash);

      if (state.system) {
        setHostname(state.system.hostname || 'axonwall');
        setDomain(state.system.domain || 'home.arpa');
        setTimezone(state.system.timezone || 'UTC');
        setDnsServersText((state.system.dnsServers || ['1.1.1.1', '9.9.9.9']).join(', '));
        setSshEnabled(state.system.sshEnabled ?? true);
        setSshPort(state.system.sshPort ?? 22);
        setWebGuiPort(state.system.webGuiPort ?? 443);
      }

      setYamlFiles(snapshot.files);
      if (snapshot.files[selectedFilename]) {
        setEditorContent(snapshot.files[selectedFilename]);
      }
    } catch {}
    setIsLoading(false);
  };

  const handleSelectDomain = (filename: AxonwallYamlDomainFile) => {
    setSelectedFilename(filename);
    setYamlErrors([]);
    setEditorContent(yamlFiles[filename] || '');
  };

  const handleSaveYamlDomain = async () => {
    setIsSavingYaml(true);
    setYamlErrors([]);
    setActionMessage(null);
    try {
      const res = await saveYamlDomainFile(selectedFilename, editorContent);
      if (!res.success) {
        setYamlErrors([{ file: selectedFilename, path: '', message: res.message || 'Validation failed' }]);
      } else {
        setActionMessage(`Validated and applied /etc/axonwall/${selectedFilename} to daemon & GitOps.`);
        await loadAll();
      }
    } catch (err: any) {
      setYamlErrors([{ file: selectedFilename, path: '', message: err?.message || 'Save failed' }]);
    } finally {
      setIsSavingYaml(false);
    }
  };

  const handleSaveGeneral = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingGeneral(true);
    setActionMessage(null);
    try {
      const state = await getCurrentDesiredState();
      const dnsServers = dnsServersText
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      await applyDesiredState({
        ...state,
        system: {
          ...state.system,
          hostname: hostname.trim() || 'axonwall',
          domain: domain.trim() || 'home.arpa',
          timezone: timezone.trim() || 'UTC',
          dnsServers: dnsServers.length > 0 ? dnsServers : ['1.1.1.1', '9.9.9.9'],
          flowtableOffload: state.system?.flowtableOffload ?? true,
          antiLockout: state.system?.antiLockout ?? {
            enabled: true,
            interface: 'lan',
            ports: [22, 80, 443, 2966, 3000],
          },
          sshEnabled,
          sshPort,
          webGuiPort,
        },
      });
      setActionMessage('Saved General System Settings to /etc/axonwall/system.yaml');
      await loadAll();
    } catch (err: any) {
      setActionMessage(`Failed to save system settings: ${err?.message || 'Unknown error'}`);
    } finally {
      setIsSavingGeneral(false);
    }
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
      await loadAll();
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
            <span>System Configuration, /etc/axonwall/ YAML & GitOps</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Bidirectional YAML configuration engine (`/etc/axonwall/*.yaml`), general appliance settings, and GitOps version control.
          </p>
        </div>

        <button
          type="button"
          onClick={loadAll}
          disabled={isLoading}
          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition flex items-center gap-1.5 border border-slate-700 font-medium cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Reload from /etc/axonwall/</span>
        </button>
      </div>

      {actionMessage && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
          <span>{actionMessage}</span>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
        <button
          type="button"
          onClick={() => setActiveTab('yaml')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold transition flex items-center gap-2 cursor-pointer ${
            activeTab === 'yaml'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white bg-slate-900 border border-slate-800'
          }`}
        >
          <FileCode2 className="w-4 h-4 text-emerald-400" />
          <span>/etc/axonwall/*.yaml Live Editor</span>
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('general')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold transition flex items-center gap-2 cursor-pointer ${
            activeTab === 'general'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white bg-slate-900 border border-slate-800'
          }`}
        >
          <Settings className="w-4 h-4 text-cyan-400" />
          <span>General System Settings (system.yaml)</span>
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('gitops')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold transition flex items-center gap-2 cursor-pointer ${
            activeTab === 'gitops'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white bg-slate-900 border border-slate-800'
          }`}
        >
          <History className="w-4 h-4 text-indigo-400" />
          <span>GitOps Audit Trail ({commits.length})</span>
        </button>
      </div>

      {/* TAB 1: Live /etc/axonwall/*.yaml Editor */}
      {activeTab === 'yaml' && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span>/etc/axonwall/ Files</span>
            </div>
            <div className="space-y-1">
              {AXONWALL_YAML_DOMAINS.map((dom) => {
                const isSelected = selectedFilename === dom.filename;
                return (
                  <button
                    key={dom.filename}
                    type="button"
                    onClick={() => handleSelectDomain(dom.filename)}
                    className={`w-full text-left px-3 py-2 rounded-lg text-xs font-mono transition flex items-center justify-between cursor-pointer ${
                      isSelected
                        ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-semibold'
                        : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
                    }`}
                  >
                    <span>/etc/axonwall/{dom.filename}</span>
                    {isSelected && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />}
                  </button>
                );
              })}
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] text-slate-400 space-y-1.5 font-mono">
              <div className="text-slate-200 font-sans font-semibold">CLI Bidirectional Sync</div>
              <div>$ vim /etc/axonwall/{selectedFilename}</div>
              <div>$ axonwallctl validate</div>
              <div>$ axonwallctl apply</div>
            </div>
          </div>

          <div className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
              <div>
                <h2 className="text-sm font-bold text-white font-mono">
                  /etc/axonwall/{selectedFilename}
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Changes saved here or via SSH (`vim` / `axonwallctl edit {selectedFilename.replace('.yaml', '')}`) synchronize automatically with the Web Console.
                </p>
              </div>
              <button
                type="button"
                onClick={handleSaveYamlDomain}
                disabled={isSavingYaml}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
              >
                <Save className="w-3.5 h-3.5" />
                <span>{isSavingYaml ? 'Validating & Applying...' : `Validate & Apply ${selectedFilename}`}</span>
              </button>
            </div>

            {yamlErrors.length > 0 && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300 space-y-1">
                <div className="font-semibold flex items-center gap-1.5">
                  <AlertCircle className="w-4 h-4 text-rose-400" />
                  <span>Schema Validation Errors</span>
                </div>
                {yamlErrors.map((err, idx) => (
                  <div key={idx} className="font-mono text-[11px] pl-5">
                    {err.file} {err.path ? `(${err.path})` : ''}: {err.message}
                  </div>
                ))}
              </div>
            )}

            <textarea
              rows={22}
              value={editorContent}
              onChange={(e) => setEditorContent(e.target.value)}
              spellCheck={false}
              className="w-full p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-300 focus:outline-none focus:border-emerald-500 leading-relaxed"
            />
          </div>
        </div>
      )}

      {/* TAB 2: General System Settings (system.yaml) */}
      {activeTab === 'general' && (
        <form onSubmit={handleSaveGeneral} className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-base font-bold text-white">General Appliance Settings</h2>
              <p className="text-xs text-slate-400">
                Persisted directly to <code className="text-emerald-400">/etc/axonwall/system.yaml</code>
              </p>
            </div>
            <button
              type="submit"
              disabled={isSavingGeneral}
              className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{isSavingGeneral ? 'Saving...' : 'Save to system.yaml'}</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5 text-xs">
            <div>
              <label className="block font-semibold text-slate-400 uppercase mb-1.5">Hostname</label>
              <input
                type="text"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>
            <div>
              <label className="block font-semibold text-slate-400 uppercase mb-1.5">Domain</label>
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>
            <div>
              <label className="block font-semibold text-slate-400 uppercase mb-1.5">Timezone</label>
              <input
                type="text"
                value={timezone}
                onChange={(e) => setTimezone(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>
            <div className="md:col-span-3">
              <label className="block font-semibold text-slate-400 uppercase mb-1.5">
                Upstream DNS Servers (Comma-separated)
              </label>
              <input
                type="text"
                value={dnsServersText}
                onChange={(e) => setDnsServersText(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>
            <div>
              <label className="block font-semibold text-slate-400 uppercase mb-1.5">SSH Daemon</label>
              <label className="flex items-center gap-2 pt-2 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={sshEnabled}
                  onChange={(e) => setSshEnabled(e.target.checked)}
                  className="rounded bg-slate-950 border-slate-700 text-emerald-500"
                />
                <span>Enable OpenSSH Server</span>
              </label>
            </div>
            <div>
              <label className="block font-semibold text-slate-400 uppercase mb-1.5">SSH Port</label>
              <input
                type="number"
                value={sshPort}
                onChange={(e) => setSshPort(Number(e.target.value) || 22)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>
            <div>
              <label className="block font-semibold text-slate-400 uppercase mb-1.5">Web GUI HTTPS Port</label>
              <input
                type="number"
                value={webGuiPort}
                onChange={(e) => setWebGuiPort(Number(e.target.value) || 443)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>
          </div>
        </form>
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
              <span className="text-slate-400">Canonical Config:</span>
              <span className="font-mono text-cyan-400">/etc/axonwall/*.yaml</span>
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
                <span>YAML Diff for Commit {selectedDiff.hash.slice(0, 8)}</span>
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
