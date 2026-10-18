'use client';

import React, { useState, useEffect } from 'react';
import {
  HardDrive,
  Download,
  Plus,
  RefreshCw,
  Trash2,
  FileCheck,
  AlertCircle,
  CheckCircle2,
  ExternalLink,
} from 'lucide-react';
import {
  getIsoListAction,
  downloadIsoAction,
  getVirtConfigAction,
  type IsoItem,
} from '@/server/virt';

export default function IsoManagementPage() {
  const [isos, setIsos] = useState<IsoItem[]>([]);
  const [pool, setPool] = useState('tank');
  const [loading, setLoading] = useState(true);
  const [statusBanner, setStatusBanner] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [showDownloadModal, setShowDownloadModal] = useState(false);

  // Download form
  const [url, setUrl] = useState('');
  const [filename, setFilename] = useState('');
  const [sha256, setSha256] = useState('');
  const [downloading, setDownloading] = useState(false);

  const loadData = async () => {
    try {
      setLoading(true);
      const [list, virtConf] = await Promise.all([
        getIsoListAction(pool),
        getVirtConfigAction(),
      ]);
      setIsos(list);
      if (virtConf.isoPool) {
        setPool(virtConf.isoPool);
      }
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || 'Failed to load ISO images' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [pool]);

  const handleDownloadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim() || !filename.trim()) return;

    setDownloading(true);
    setStatusBanner(null);
    try {
      const res = await downloadIsoAction(url.trim(), filename.trim(), pool, sha256.trim() || undefined);
      setStatusBanner({
        type: res.success ? 'success' : 'error',
        message: res.message + (res.upid ? ` (Task: ${res.upid})` : ''),
      });
      setShowDownloadModal(false);
      setUrl('');
      setFilename('');
      setSha256('');
      await loadData();
    } catch (err: any) {
      setStatusBanner({ type: 'error', message: err?.message || 'Failed to trigger ISO download' });
    } finally {
      setDownloading(false);
    }
  };

  const totalBytes = isos.reduce((acc, iso) => acc + (iso.sizeBytes || 0), 0);
  const totalGb = (totalBytes / (1024 * 1024 * 1024)).toFixed(2);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <HardDrive className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-100">ISO Images &amp; Installation Media</h1>
            <p className="text-sm text-slate-400">
              Manage operating system ISOs, Cloud-Init templates, and virtio driver media
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-slate-300 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowDownloadModal(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors shadow-lg shadow-cyan-900/20"
          >
            <Download className="w-4 h-4" />
            Download from URL
          </button>
        </div>
      </div>

      {statusBanner && (
        <div
          className={`flex items-center gap-3 p-4 rounded-lg border text-sm ${
            statusBanner.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
          }`}
        >
          {statusBanner.type === 'success' ? (
            <CheckCircle2 className="w-5 h-5 flex-shrink-0" />
          ) : (
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
          )}
          <span className="flex-1">{statusBanner.message}</span>
          <button onClick={() => setStatusBanner(null)} className="text-slate-400 hover:text-slate-200">
            &times;
          </button>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-slate-400 text-sm font-medium">Available ISO Images</div>
          <div className="mt-2 text-3xl font-bold text-slate-100">{isos.length}</div>
          <div className="mt-1 text-xs text-slate-500">Stored in /mnt/{pool}/isos</div>
        </div>
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-slate-400 text-sm font-medium">Total Media Footprint</div>
          <div className="mt-2 text-3xl font-bold text-cyan-400">{totalGb} GB</div>
          <div className="mt-1 text-xs text-slate-500">ZFS compression active</div>
        </div>
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-slate-400 text-sm font-medium">Active ISO Storage Pool</div>
          <div className="mt-2 text-3xl font-bold text-emerald-400">{pool}</div>
          <div className="mt-1 text-xs text-slate-500">Primary ZFS storage pool</div>
        </div>
      </div>

      {/* ISO Table */}
      <div className="rounded-xl bg-slate-900/60 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/60 text-xs font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="px-6 py-4">Filename</th>
                <th className="px-6 py-4">Filesystem Path</th>
                <th className="px-6 py-4">Size</th>
                <th className="px-6 py-4">Pool</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {isos.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-6 py-12 text-center text-slate-500 font-sans">
                    No ISO images found. Click &quot;Download from URL&quot; to fetch Debian, Ubuntu, Windows, or Alpine ISOs.
                  </td>
                </tr>
              ) : (
                isos.map((iso) => (
                  <tr key={iso.path} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-6 py-4 font-bold text-slate-100 flex items-center gap-2">
                      <FileCheck className="w-4 h-4 text-cyan-400" />
                      {iso.name}
                    </td>
                    <td className="px-6 py-4 text-slate-400">{iso.path}</td>
                    <td className="px-6 py-4">
                      {(iso.sizeBytes / (1024 * 1024 * 1024)).toFixed(2)} GB
                    </td>
                    <td className="px-6 py-4 text-cyan-400">{iso.pool}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Download ISO Modal */}
      {showDownloadModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="relative w-full max-w-lg bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2">
                <Download className="w-5 h-5 text-cyan-400" />
                <h2 className="text-lg font-bold text-slate-100">Download ISO from URL</h2>
              </div>
              <button
                onClick={() => setShowDownloadModal(false)}
                className="text-slate-400 hover:text-slate-200 text-xl font-bold"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleDownloadSubmit} className="mt-4 space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">Source Download URL</label>
                <input
                  type="url"
                  value={url}
                  onChange={(e) => {
                    setUrl(e.target.value);
                    if (!filename) {
                      const guessed = e.target.value.split('/').pop()?.split('?')[0];
                      if (guessed && (guessed.endsWith('.iso') || guessed.endsWith('.img'))) {
                        setFilename(guessed);
                      }
                    }
                  }}
                  placeholder="https://cdimage.debian.org/.../debian-12.8.0-amd64-netinst.iso"
                  required
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">Target Filename (.iso)</label>
                <input
                  type="text"
                  value={filename}
                  onChange={(e) => setFilename(e.target.value)}
                  placeholder="debian-12-standard.iso"
                  required
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Storage Pool</label>
                  <input
                    type="text"
                    value={pool}
                    onChange={(e) => setPool(e.target.value)}
                    required
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Expected SHA-256 (Optional)</label>
                  <input
                    type="text"
                    value={sha256}
                    onChange={(e) => setSha256(e.target.value)}
                    placeholder="Hash verification"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 text-sm focus:border-cyan-500 focus:outline-none font-mono text-xs"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowDownloadModal(false)}
                  className="px-4 py-2 text-sm font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={downloading}
                  className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors shadow-lg shadow-cyan-900/20"
                >
                  {downloading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                  Start Download Task
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
