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
  Clock,
  Shield,
  FileCheck,
  Key,
  FileCode2,
} from 'lucide-react';
import { exportUnifiedYamlConfig } from '@/server/agent';

export default function BackupPage() {
  // Export states
  const [passphrase, setPassphrase] = useState('');
  const [isExporting, setIsExporting] = useState(false);
  const [isExportingYaml, setIsExportingYaml] = useState(false);
  const [exportMessage, setExportMessage] = useState<string | null>(null);

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
            <h1 className="text-2xl font-bold tracking-tight text-white">Backup & Disaster Recovery</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Automated AES-256-GCM encrypted cloud backups, plaintext YAML export, GitOps continuous delivery, and instant state restoration.
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
