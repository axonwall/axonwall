'use client';

import { useState } from 'react';
import {
  Download,
  Upload,
  Lock,
  GitBranch,
  Cloud,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  HardDrive,
  FileCheck,
  Key,
  FileCode2,
  Copy,
  Disc,
  Server,
  Eye,
  EyeOff,
  Check,
  Terminal,
} from 'lucide-react';
import {
  exportUnifiedYamlConfig,
  exportCloudInitConfigAction,
  type CloudInitExportSnapshot,
} from '@/server/agent';

export default function BackupPage() {
  // Export states
  const [passphrase, setPassphrase] = useState('');
  const [isExporting, setIsExporting] = useState(false);
  const [isExportingYaml, setIsExportingYaml] = useState(false);
  const [exportMessage, setExportMessage] = useState<string | null>(null);

  // Cloud-Init Replicator states
  const [ciRedactSecrets, setCiRedactSecrets] = useState(true);
  const [ciTemplateMode, setCiTemplateMode] = useState(false);
  const [ciIncludeStorage, setCiIncludeStorage] = useState(true);
  const [ciIncludeUsers, setCiIncludeUsers] = useState(true);
  const [ciIncludePackages, setCiIncludePackages] = useState(true);
  const [ciHostnameOverride, setCiHostnameOverride] = useState('');
  const [ciSnapshot, setCiSnapshot] = useState<CloudInitExportSnapshot | null>(null);
  const [isGeneratingCi, setIsGeneratingCi] = useState(false);
  const [isDownloadingIso, setIsDownloadingIso] = useState(false);
  const [showCiPreview, setShowCiPreview] = useState(false);
  const [copiedCi, setCopiedCi] = useState(false);

  // Restore states
  const [restorePassphrase, setRestorePassphrase] = useState('');
  const [restoreFile, setRestoreFile] = useState<File | null>(null);
  const [isRestoring, setIsRestoring] = useState(false);
  const [restoreStatus, setRestoreStatus] = useState<{ success?: boolean; message?: string } | null>(null);

  // Cloud S3 states
  const [s3Enabled, setS3Enabled] = useState(true);
  const [s3Bucket, setS3Bucket] = useState('enterprise-axonwall-backups');
  const [s3Endpoint, setS3Endpoint] = useState('https://s3.eu-central-1.amazonaws.com');
  const [s3Schedule, setS3Schedule] = useState('daily');

  // GitOps states
  const [gitOpsEnabled, setGitOpsEnabled] = useState(true);
  const [gitRepo, setGitRepo] = useState('git@github.com:enterprise/axonwall-fleet-gitops.git');
  const [gitBranch, setGitBranch] = useState('main');

  async function handleExportYaml() {
    setIsExportingYaml(true);
    setExportMessage(null);
    try {
      const yamlContent = await exportUnifiedYamlConfig();
      const blob = new Blob([yamlContent], { type: 'text/yaml;charset=utf-8' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `axonwall-config-${new Date().toISOString().slice(0, 10)}.yaml`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      setExportMessage('Exported unified /etc/axonwall/*.yaml configuration as YAML.');
    } catch (err: any) {
      alert(err?.message || 'YAML export failed');
    } finally {
      setIsExportingYaml(false);
    }
  }

  async function handlePreviewCloudInit() {
    setIsGeneratingCi(true);
    setExportMessage(null);
    try {
      const snap = await exportCloudInitConfigAction({
        redactSecrets: ciRedactSecrets,
        templateMode: ciTemplateMode,
        includeStorage: ciIncludeStorage,
        includeUsers: ciIncludeUsers,
        includePackages: ciIncludePackages,
        hostnameOverride: ciHostnameOverride.trim() || undefined,
      });
      setCiSnapshot(snap);
      setShowCiPreview(true);
    } catch (err: any) {
      alert(err?.message || 'Failed to introspect host for Cloud-Init export');
    } finally {
      setIsGeneratingCi(false);
    }
  }

  async function handleDownloadCloudInitYaml() {
    setIsGeneratingCi(true);
    setExportMessage(null);
    try {
      const snap = await exportCloudInitConfigAction({
        redactSecrets: ciRedactSecrets,
        templateMode: ciTemplateMode,
        includeStorage: ciIncludeStorage,
        includeUsers: ciIncludeUsers,
        includePackages: ciIncludePackages,
        hostnameOverride: ciHostnameOverride.trim() || undefined,
      });
      setCiSnapshot(snap);
      const blob = new Blob([snap.yaml], { type: 'text/yaml;charset=utf-8' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `axonwall-${snap.hostname}-cloud-config-${new Date().toISOString().slice(0, 10)}.yaml`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      setExportMessage(
        `Exported Cloud-Init #cloud-config YAML for '${snap.hostname}' (${snap.storageSummary.layoutMode}, ${snap.usersCount} user(s), ${snap.packagesCount} package(s)).`
      );
    } catch (err: any) {
      alert(err?.message || 'Cloud-Init YAML export failed');
    } finally {
      setIsGeneratingCi(false);
    }
  }

  async function handleDownloadCloudInitIso() {
    setIsDownloadingIso(true);
    setExportMessage(null);
    try {
      const res = await fetch('/api/system/cloudinit/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          format: 'iso',
          redactSecrets: ciRedactSecrets,
          templateMode: ciTemplateMode,
          includeStorage: ciIncludeStorage,
          includeUsers: ciIncludeUsers,
          includePackages: ciIncludePackages,
          hostnameOverride: ciHostnameOverride.trim() || undefined,
        }),
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      const hostSlug = (ciHostnameOverride.trim() || ciSnapshot?.hostname || 'axonwall').replace(
        /[^a-zA-Z0-9-]/g,
        '-'
      );
      a.href = url;
      a.download = `axonwall-${hostSlug}-cidata-${new Date().toISOString().slice(0, 10)}.iso`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      setExportMessage(
        'Generated and downloaded bootable NoCloud seed image (cidata.iso) with /user-data and /meta-data.'
      );
    } catch (err: any) {
      alert(err?.message || 'Failed to generate NoCloud cidata.iso');
    } finally {
      setIsDownloadingIso(false);
    }
  }

  async function handleCopyCloudInitYaml() {
    if (!ciSnapshot?.yaml) return;
    try {
      await navigator.clipboard.writeText(ciSnapshot.yaml);
      setCopiedCi(true);
      setTimeout(() => setCopiedCi(false), 2000);
    } catch {}
  }

  async function handleExport(e: React.FormEvent) {
    e.preventDefault();
    if (!passphrase || passphrase.length < 8) {
      alert('Passphrase must be at least 8 characters long');
      return;
    }

    setIsExporting(true);
    setExportMessage(null);

    try {
      const res = await fetch('/api/system/backup/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passphrase }),
      });

      if (!res.ok) {
        throw new Error(await res.text());
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `axonwall-backup-${new Date().toISOString().slice(0, 10)}.axb`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      setExportMessage('Encrypted backup generated and downloaded successfully.');
    } catch (err: any) {
      alert(err?.message || 'Export failed');
    } finally {
      setIsExporting(false);
    }
  }

  async function handleRestore(e: React.FormEvent) {
    e.preventDefault();
    if (!restoreFile || !restorePassphrase) {
      alert('Please provide both the backup file (.axb) and decryption passphrase');
      return;
    }

    setIsRestoring(true);
    setRestoreStatus(null);

    try {
      const formData = new FormData();
      formData.append('file', restoreFile);
      formData.append('passphrase', restorePassphrase);

      const res = await fetch('/api/system/backup/restore', {
        method: 'POST',
        body: formData,
      });

      const data = await res.json();
      if (data.success) {
        setRestoreStatus({
          success: true,
          message: data.message,
        });
      } else {
        setRestoreStatus({
          success: false,
          message: data.error || 'Decryption verification failed',
        });
      }
    } catch (err: any) {
      setRestoreStatus({
        success: false,
        message: err?.message || 'Restore request failed',
      });
    } finally {
      setIsRestoring(false);
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <HardDrive className="w-5 h-5" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-white">Backup, Cloning & Disaster Recovery</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Cloud-Init appliance replicator (#cloud-config &amp; cidata.iso), AES-256-GCM encrypted archives, unified YAML export, and GitOps sync.
          </p>
        </div>

        <button
          type="button"
          onClick={handleExportYaml}
          disabled={isExportingYaml}
          className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-emerald-300 text-xs font-semibold flex items-center gap-2 transition cursor-pointer disabled:opacity-50"
        >
          <FileCode2 className="w-4 h-4 text-emerald-400" />
          <span>{isExportingYaml ? 'Generating YAML...' : 'Export Unified YAML (axonwall.yaml)'}</span>
        </button>
      </div>

      {exportMessage && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-4 flex items-center gap-3 text-emerald-300 text-sm">
          <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-400" />
          <span>{exportMessage}</span>
        </div>
      )}

      {/* Cloud-Init Appliance Replicator Card */}
      <div className="bg-slate-900 border border-emerald-500/30 rounded-xl p-6 space-y-5 shadow-lg shadow-emerald-950/10">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-start gap-3">
            <div className="p-2.5 rounded-xl bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 mt-0.5">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h2 className="text-base font-bold text-white">
                  Cloud-Init Appliance Replicator (#cloud-config &amp; NoCloud ISO)
                </h2>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                  Zero-Touch Clone
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Introspects live disk partitioning (A/B slots, RAID, LUKS, ZFS), OS users &amp; SSH keys, enabled plugin packages, and full firewall DesiredState to build another Axonwall appliance just like this one.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={handlePreviewCloudInit}
              disabled={isGeneratingCi}
              className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium flex items-center gap-2 transition cursor-pointer disabled:opacity-50"
            >
              {isGeneratingCi ? (
                <RefreshCw className="w-4 h-4 animate-spin text-emerald-400" />
              ) : showCiPreview ? (
                <EyeOff className="w-4 h-4 text-emerald-400" />
              ) : (
                <Eye className="w-4 h-4 text-emerald-400" />
              )}
              <span>{ciSnapshot && showCiPreview ? 'Refresh Preview' : 'Inspect & Preview YAML'}</span>
            </button>

            <button
              type="button"
              onClick={handleDownloadCloudInitYaml}
              disabled={isGeneratingCi}
              className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-2 transition cursor-pointer disabled:opacity-50"
            >
              <Download className="w-4 h-4" />
              <span>Download cloud-config.yaml</span>
            </button>

            <button
              type="button"
              onClick={handleDownloadCloudInitIso}
              disabled={isDownloadingIso}
              className="px-3.5 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold flex items-center gap-2 transition cursor-pointer disabled:opacity-50"
            >
              {isDownloadingIso ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <Disc className="w-4 h-4" />
              )}
              <span>{isDownloadingIso ? 'Building ISO...' : 'Download Bootable cidata.iso'}</span>
            </button>
          </div>
        </div>

        {/* Configuration Controls */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          {/* Column 1: Replication Mode & Target Hostname */}
          <div className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-3.5 space-y-3">
            <div>
              <label className="block font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1.5">
                Replication Profile
              </label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setCiTemplateMode(false)}
                  className={`px-2.5 py-2 rounded-lg border text-left transition cursor-pointer ${
                    !ciTemplateMode
                      ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300 font-semibold'
                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="text-xs">1:1 Exact Clone</div>
                  <div className="text-[10px] text-slate-400 font-normal mt-0.5">
                    Keep static WAN/LAN IPs
                  </div>
                </button>
                <button
                  type="button"
                  onClick={() => setCiTemplateMode(true)}
                  className={`px-2.5 py-2 rounded-lg border text-left transition cursor-pointer ${
                    ciTemplateMode
                      ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300 font-semibold'
                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="text-xs">Fleet Template</div>
                  <div className="text-[10px] text-slate-400 font-normal mt-0.5">
                    WAN DHCP + strip MACs
                  </div>
                </button>
              </div>
            </div>

            <div>
              <label className="block font-semibold text-slate-400 uppercase text-[11px] mb-1">
                Target Hostname Override (Optional)
              </label>
              <input
                type="text"
                value={ciHostnameOverride}
                onChange={(e) => setCiHostnameOverride(e.target.value)}
                placeholder={ciTemplateMode ? 'Auto: <hostname>-clone' : 'Keep current hostname...'}
                className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono text-xs focus:outline-none focus:ring-1 focus:ring-emerald-500"
              />
            </div>
          </div>

          {/* Column 2: Included Subsystems */}
          <div className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-3.5 space-y-2.5">
            <div className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
              Introspected Subsystems
            </div>

            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={ciIncludeStorage}
                onChange={(e) => setCiIncludeStorage(e.target.checked)}
                className="mt-0.5 w-4 h-4 rounded bg-slate-900 border-slate-700 text-emerald-500"
              />
              <div>
                <div className="text-slate-200 font-medium">Disk &amp; A/B Partition Topology</div>
                <div className="text-[11px] text-slate-500">
                  Exports <code className="text-slate-400">axonwall.storage</code> for automated ISO installer partitioning
                </div>
              </div>
            </label>

            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={ciIncludeUsers}
                onChange={(e) => setCiIncludeUsers(e.target.checked)}
                className="mt-0.5 w-4 h-4 rounded bg-slate-900 border-slate-700 text-emerald-500"
              />
              <div>
                <div className="text-slate-200 font-medium">OS Administrators &amp; SSH Keys</div>
                <div className="text-[11px] text-slate-500">
                  Exports <code className="text-slate-400">users</code> and authorized OpenSSH public keys
                </div>
              </div>
            </label>

            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={ciIncludePackages}
                onChange={(e) => setCiIncludePackages(e.target.checked)}
                className="mt-0.5 w-4 h-4 rounded bg-slate-900 border-slate-700 text-emerald-500"
              />
              <div>
                <div className="text-slate-200 font-medium">Enabled Plugin Packages</div>
                <div className="text-[11px] text-slate-500">
                  Pre-installs FRR, Suricata, WireGuard, NUT, Headscale, and guest agents
                </div>
              </div>
            </label>
          </div>

          {/* Column 3: Secret Redaction & CLI Usage */}
          <div className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-3.5 flex flex-col justify-between space-y-3">
            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={ciRedactSecrets}
                onChange={(e) => setCiRedactSecrets(e.target.checked)}
                className="mt-0.5 w-4 h-4 rounded bg-slate-900 border-slate-700 text-emerald-500"
              />
              <div>
                <div className="text-slate-200 font-medium flex items-center gap-1.5">
                  <span>Redact Passwords &amp; Private Keys</span>
                  <span className="px-1.5 py-0.2 rounded text-[10px] bg-emerald-500/15 text-emerald-400">
                    Recommended
                  </span>
                </div>
                <div className="text-[11px] text-slate-500 mt-0.5">
                  Replaces WireGuard private keys, IPsec/BGP PSKs, and admin passwords with{' '}
                  <code className="text-amber-300">CHANGE_ME_ON_DEPLOY</code>. Uncheck only for air-gapped 1:1 clones.
                </div>
              </div>
            </label>

            <div className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1">
              <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-300">
                <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                <span>CLI Equivalent on Appliance:</span>
              </div>
              <code className="block text-[11px] font-mono text-emerald-400 break-all">
                axonwallctl cloudinit export --iso /tmp/cidata.iso
                {ciTemplateMode ? ' --template' : ''}
                {!ciRedactSecrets ? ' --no-redact' : ''}
              </code>
            </div>
          </div>
        </div>

        {/* Live Introspection Summary & Preview Drawer */}
        {ciSnapshot && (
          <div className="space-y-3 pt-2 border-t border-slate-800">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-2.5 py-1 rounded-md bg-slate-950 border border-slate-800 text-slate-300 font-mono">
                  Host: <strong className="text-white">{ciSnapshot.fqdn}</strong>
                </span>
                <span className="px-2.5 py-1 rounded-md bg-slate-950 border border-slate-800 text-slate-300 font-mono">
                  Layout: <strong className="text-emerald-400">{ciSnapshot.storageSummary.layoutMode}</strong> (Slot A:{' '}
                  {ciSnapshot.storageSummary.slotAGb}GB / Slot B: {ciSnapshot.storageSummary.slotBGb}GB)
                </span>
                <span className="px-2.5 py-1 rounded-md bg-slate-950 border border-slate-800 text-slate-300 font-mono">
                  Disks: <strong className="text-sky-400">{ciSnapshot.storageSummary.targetDisks.join(', ')}</strong>
                </span>
                <span className="px-2.5 py-1 rounded-md bg-slate-950 border border-slate-800 text-slate-300 font-mono">
                  Users: <strong className="text-white">{ciSnapshot.usersCount}</strong> ({ciSnapshot.sshKeysCount} SSH key(s))
                </span>
                <span className="px-2.5 py-1 rounded-md bg-slate-950 border border-slate-800 text-slate-300 font-mono">
                  Packages: <strong className="text-white">{ciSnapshot.packagesCount}</strong>
                </span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleCopyCloudInitYaml}
                  className="px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 flex items-center gap-1.5 cursor-pointer"
                >
                  {copiedCi ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-300">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-slate-400" />
                      <span>Copy #cloud-config</span>
                    </>
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => setShowCiPreview(!showCiPreview)}
                  className="px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 cursor-pointer"
                >
                  {showCiPreview ? 'Hide YAML' : 'Show YAML'}
                </button>
              </div>
            </div>

            {showCiPreview && (
              <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono text-emerald-300 overflow-x-auto max-h-96 leading-relaxed">
                {ciSnapshot.yaml}
              </pre>
            )}
          </div>
        )}
      </div>

      {/* Main Grid: Export and Restore */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Export Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
              <Download className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white">Create Encrypted Backup (.axb)</h3>
              <p className="text-xs text-slate-400">Download complete firewall state with AES-256-GCM encryption</p>
            </div>
          </div>

          <form onSubmit={handleExport} className="space-y-4 pt-2">
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
                Decryption Passphrase
              </label>
              <div className="relative">
                <Key className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                <input
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="Minimum 8 characters..."
                  required
                  minLength={8}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
                />
              </div>
              <span className="text-[11px] text-slate-500 mt-1 block">
                Derived with PBKDF2 (100,000 rounds). Store this passphrase securely.
              </span>
            </div>

            <button
              type="submit"
              disabled={isExporting}
              className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-2 rounded-lg text-xs transition cursor-pointer flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {isExporting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
              <span>{isExporting ? 'Encrypting & Generating Archive...' : 'Download Encrypted Backup'}</span>
            </button>
          </form>
        </div>

        {/* Restore Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white">Restore from Backup Archive</h3>
              <p className="text-xs text-slate-400">Upload and verify an encrypted (.axb) configuration snapshot</p>
            </div>
          </div>

          <form onSubmit={handleRestore} className="space-y-4 pt-2">
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
                Select Backup File (.axb)
              </label>
              <input
                type="file"
                accept=".axb"
                onChange={(e) => setRestoreFile(e.target.files?.[0] || null)}
                required
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 file:mr-3 file:py-1 file:px-2.5 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-emerald-400 hover:file:bg-slate-700"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
                Archive Passphrase
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                <input
                  type="password"
                  value={restorePassphrase}
                  onChange={(e) => setRestorePassphrase(e.target.value)}
                  placeholder="Enter archive decryption passphrase..."
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isRestoring}
              className="w-full bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium py-2 rounded-lg text-xs transition cursor-pointer flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {isRestoring ? <RefreshCw className="w-4 h-4 animate-spin text-emerald-400" /> : <FileCheck className="w-4 h-4 text-emerald-400" />}
              <span>{isRestoring ? 'Decrypting & Verifying Archive...' : 'Validate & Restore Snapshot'}</span>
            </button>
          </form>

          {restoreStatus && (
            <div
              className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${
                restoreStatus.success
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
              }`}
            >
              {restoreStatus.success ? (
                <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
              ) : (
                <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
              )}
              <span>{restoreStatus.message}</span>
            </div>
          )}
        </div>
      </div>

      {/* Cloud S3 & GitOps Automation Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* S3 Object Storage Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400">
                <Cloud className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white">S3 Cloud Storage Synchronization</h3>
                <p className="text-xs text-slate-400">Auto-upload encrypted archives to AWS, Cloudflare R2, or MinIO</p>
              </div>
            </div>
            <input
              type="checkbox"
              checked={s3Enabled}
              onChange={(e) => setS3Enabled(e.target.checked)}
              className="w-4 h-4 rounded bg-slate-950 border-slate-800 text-emerald-500 focus:ring-emerald-500"
            />
          </div>

          <div className="space-y-3 pt-2 text-xs">
            <div>
              <label className="block font-semibold text-slate-400 uppercase mb-1">Target Bucket Name</label>
              <input
                type="text"
                value={s3Bucket}
                onChange={(e) => setS3Bucket(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
              />
            </div>
            <div>
              <label className="block font-semibold text-slate-400 uppercase mb-1">Endpoint URL</label>
              <input
                type="text"
                value={s3Endpoint}
                onChange={(e) => setS3Endpoint(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
              />
            </div>
            <div>
              <label className="block font-semibold text-slate-400 uppercase mb-1">Schedule</label>
              <select
                value={s3Schedule}
                onChange={(e) => setS3Schedule(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white"
              >
                <option value="hourly">Hourly Automated Snapshot</option>
                <option value="daily">Daily at 02:00 UTC (Recommended)</option>
                <option value="weekly">Weekly on Sunday</option>
              </select>
            </div>
          </div>
        </div>

        {/* GitOps Repository Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400">
                <GitBranch className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white">GitOps Continuous Delivery</h3>
                <p className="text-xs text-slate-400">Auto-commit DesiredState JSON/YAML on confirmed applies</p>
              </div>
            </div>
            <input
              type="checkbox"
              checked={gitOpsEnabled}
              onChange={(e) => setGitOpsEnabled(e.target.checked)}
              className="w-4 h-4 rounded bg-slate-950 border-slate-800 text-emerald-500 focus:ring-emerald-500"
            />
          </div>

          <div className="space-y-3 pt-2 text-xs">
            <div>
              <label className="block font-semibold text-slate-400 uppercase mb-1">Git Repository (SSH/HTTPS)</label>
              <input
                type="text"
                value={gitRepo}
                onChange={(e) => setGitRepo(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
              />
            </div>
            <div>
              <label className="block font-semibold text-slate-400 uppercase mb-1">Branch</label>
              <input
                type="text"
                value={gitBranch}
                onChange={(e) => setGitBranch(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
              />
            </div>
            <div className="p-2.5 bg-slate-950/70 border border-slate-800/80 rounded-lg flex items-center justify-between">
              <span className="text-slate-400">Git Sync Status:</span>
              <span className="text-emerald-400 font-mono font-medium flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" /> Synchronized (commit 0004097)
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
