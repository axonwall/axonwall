'use client';

import React, { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {
  BookOpen,
  Boxes,
  CheckCircle2,
  Download,
  ExternalLink,
  Loader2,
  Maximize2,
  Power,
  RefreshCw,
  Trash2,
  AlertTriangle,
} from 'lucide-react';
import {
  enablePluginWithDependencies,
  disablePluginWithDependents,
} from '@axonwall/lib/plugins';
import type { DesiredState } from '@axonwall/lib/schemas';
import { getCurrentDesiredState } from '@/server/agent';
import { executePluginAction } from '@/server/plugins';
import { getDocsPortalStatus, type DocsPortalStatus } from '@/server/docs-portal';
import { buildOnlineDocsUrl, ONLINE_DOCS_BASE_URL } from '@/lib/docs-portal-urls';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';

export default function DocsPortalPage() {
  const params = useParams<{ slug?: string[] }>();
  const slug = Array.isArray(params?.slug) ? params.slug : [];
  const { applyState } = useDesiredStateApply();

  const [hash, setHash] = useState('');
  const [state, setState] = useState<DesiredState | null>(null);
  const [status, setStatus] = useState<DocsPortalStatus>({
    installed: false,
    enabled: false,
    version: null,
    guideCount: null,
    builtAt: null,
    onlineBaseUrl: ONLINE_DOCS_BASE_URL,
  });
  const [loading, setLoading] = useState(true);
  const [actionBusy, setActionBusy] = useState<'install' | 'enable' | 'disable' | 'uninstall' | null>(null);
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      const [docsStatus, desired] = await Promise.all([
        getDocsPortalStatus(),
        getCurrentDesiredState().catch(() => null),
      ]);
      setStatus(docsStatus);
      if (desired) setState(desired);
    } catch {
      // Fail closed to offline fallback UI when status cannot be fetched
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      setHash(window.location.hash || '');
    }
    void loadStatus();
    const handler = () => {
      void loadStatus();
    };
    window.addEventListener('axonwall-capabilities-updated', handler);
    return () => window.removeEventListener('axonwall-capabilities-updated', handler);
  }, [loadStatus]);

  const syncDesiredStatePlugin = async (enable: boolean) => {
    const base = state ?? (await getCurrentDesiredState().catch(() => null));
    if (!base) return;
    const res = enable
      ? enablePluginWithDependencies('docs-portal', base)
      : disablePluginWithDependents('docs-portal', base);
    await applyState(res.state);
    setState(res.state);
  };

  const handleInstallOrEnable = async (mode: 'install' | 'enable') => {
    setActionBusy(mode);
    setBanner(null);
    try {
      const actionRes = await executePluginAction('docs-portal', mode);
      if (!actionRes.success) {
        setBanner({ type: 'error', text: actionRes.message || `Failed to ${mode} Offline Documentation Portal.` });
        return;
      }
      await syncDesiredStatePlugin(true);
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new Event('axonwall-capabilities-updated'));
      }
      await loadStatus();
      setBanner({ type: 'success', text: actionRes.message });
    } catch (err: unknown) {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : `Failed to ${mode} Offline Documentation Portal.`,
      });
    } finally {
      setActionBusy(null);
    }
  };

  const handleDisableOrUninstall = async (mode: 'disable' | 'uninstall') => {
    setActionBusy(mode);
    setBanner(null);
    try {
      const actionRes = await executePluginAction('docs-portal', mode);
      if (!actionRes.success) {
        setBanner({ type: 'error', text: actionRes.message || `Failed to ${mode} Offline Documentation Portal.` });
        return;
      }
      await syncDesiredStatePlugin(false);
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new Event('axonwall-capabilities-updated'));
      }
      await loadStatus();
      setBanner({ type: 'success', text: actionRes.message });
    } catch (err: unknown) {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : `Failed to ${mode} Offline Documentation Portal.`,
      });
    } finally {
      setActionBusy(null);
    }
  };

  const cleanSlugPath = slug.filter((s) => /^[a-z0-9-]+$/.test(s)).join('/');
  const cleanHash = /^#[a-z0-9-]+$/i.test(hash) ? hash : '';
  const iframeSrc = `/api/docs-bundle/docs/${cleanSlugPath ? `${cleanSlugPath}/` : ''}${cleanHash}`;
  const onlineUrl = buildOnlineDocsUrl(slug, cleanHash);

  if (loading) {
    return (
      <div className="p-12 max-w-3xl mx-auto flex items-center justify-center gap-3 text-slate-400">
        <Loader2 className="w-5 h-5 animate-spin text-emerald-400" />
        <span className="text-sm">Checking Offline Documentation Portal status...</span>
      </div>
    );
  }

  if (status.installed && status.enabled) {
    return (
      <div className="-m-6 h-[calc(100vh-4rem)] flex flex-col bg-[#080c14]">
        <div className="h-11 shrink-0 px-4 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5 text-xs">
            <BookOpen className="w-4 h-4 text-emerald-400" />
            <span className="font-semibold text-white">Offline Documentation Portal</span>
            {status.version && (
              <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-mono text-[11px]">
                v{status.version}
              </span>
            )}
            {status.guideCount !== null && (
              <span className="text-slate-400 font-mono text-[11px] hidden sm:inline">
                {status.guideCount} guides
              </span>
            )}
          </div>

          <div className="flex items-center gap-2 text-xs">
            <a
              href={iframeSrc}
              target="_blank"
              rel="noopener noreferrer"
              className="px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition inline-flex items-center gap-1.5"
            >
              <Maximize2 className="w-3.5 h-3.5" /> Open Full Tab
            </a>
            <a
              href={onlineUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition inline-flex items-center gap-1.5"
            >
              <ExternalLink className="w-3.5 h-3.5" /> Online Mirror
            </a>
            <button
              disabled={actionBusy !== null}
              onClick={() => void handleDisableOrUninstall('disable')}
              className="px-2.5 py-1 rounded-md bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 transition inline-flex items-center gap-1.5 disabled:opacity-50"
            >
              {actionBusy === 'disable' ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Power className="w-3.5 h-3.5" />
              )}
              Disable
            </button>
            <button
              disabled={actionBusy !== null}
              onClick={() => void handleDisableOrUninstall('uninstall')}
              className="px-2.5 py-1 rounded-md bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 transition inline-flex items-center gap-1.5 disabled:opacity-50"
            >
              {actionBusy === 'uninstall' ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Trash2 className="w-3.5 h-3.5" />
              )}
              Uninstall
            </button>
          </div>
        </div>

        <iframe
          src={iframeSrc}
          title="Axonwall Offline Documentation"
          className="w-full flex-1 border-0 bg-[#080c14]"
        />
      </div>
    );
  }

  return (
    <div className="p-8 max-w-3xl mx-auto space-y-6">
      <div className="rounded-2xl bg-slate-900 border border-slate-800 p-8 space-y-6 shadow-xl">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-11 h-11 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white tracking-tight">
                Offline Documentation Portal
              </h1>
              <p className="text-xs text-slate-400 mt-0.5 font-mono">
                Plugin ID: docs-portal • Target: {cleanSlugPath ? `/docs/${cleanSlugPath}` : '/docs'}
                {cleanHash}
              </p>
            </div>
          </div>

          <span
            className={`px-2.5 py-1 rounded-md text-xs font-semibold border ${
              status.installed
                ? 'bg-sky-500/10 text-sky-400 border-sky-500/20'
                : 'bg-slate-800 text-slate-300 border-slate-700'
            }`}
          >
            {status.installed ? 'Installed • Disabled' : 'Not Installed'}
          </span>
        </div>

        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall strips the 26 static documentation guides out of base images and `.deb` packages
          to keep the console footprint lean. Read always-current documentation online at{' '}
          <span className="font-mono text-emerald-400">axonwall.com/docs</span>, or install the
          verified offline documentation bundle (~1.2 MB compressed) on demand for air-gapped
          environments.
        </p>

        {banner && (
          <div
            className={`p-3.5 rounded-xl border text-xs flex items-start gap-2.5 ${
              banner.type === 'success'
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
            }`}
          >
            {banner.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
            ) : (
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            )}
            <span>{banner.text}</span>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <a
            href={onlineUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="px-4 py-2.5 rounded-xl text-sm font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-950/40 transition inline-flex items-center gap-2"
          >
            <ExternalLink className="w-4 h-4" />
            Read Online at axonwall.com/docs
          </a>

          {status.installed ? (
            <button
              disabled={actionBusy !== null}
              onClick={() => void handleInstallOrEnable('enable')}
              className="px-4 py-2.5 rounded-xl text-sm font-semibold bg-slate-800 hover:bg-slate-700 text-white border border-slate-700 transition inline-flex items-center gap-2 disabled:opacity-50"
            >
              {actionBusy === 'enable' ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" /> Enabling...
                </>
              ) : (
                <>
                  <Power className="w-4 h-4 text-emerald-400" /> Enable Offline Docs Plugin
                </>
              )}
            </button>
          ) : (
            <button
              disabled={actionBusy !== null}
              onClick={() => void handleInstallOrEnable('install')}
              className="px-4 py-2.5 rounded-xl text-sm font-semibold bg-slate-800 hover:bg-slate-700 text-white border border-slate-700 transition inline-flex items-center gap-2 disabled:opacity-50"
            >
              {actionBusy === 'install' ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" /> Installing Bundle...
                </>
              ) : (
                <>
                  <Download className="w-4 h-4 text-emerald-400" /> Install Offline Docs Plugin
                </>
              )}
            </button>
          )}

          <Link
            href="/system/plugins"
            className="px-3.5 py-2.5 rounded-xl text-xs font-medium bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 transition inline-flex items-center gap-1.5"
          >
            <Boxes className="w-3.5 h-3.5 text-slate-400" /> Manage in Plugin Store
          </Link>

          <button
            onClick={() => void loadStatus()}
            className="px-3 py-2.5 rounded-xl text-xs font-medium text-slate-400 hover:text-white transition inline-flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>

        <div className="rounded-xl bg-slate-950/80 border border-slate-800/80 p-4 text-xs text-slate-400 space-y-1.5">
          <div className="font-semibold text-slate-200">Air-Gapped Drop-In Option</div>
          <p>
            Stage{' '}
            <code className="font-mono text-emerald-400">axonwall-docs-latest.tar.gz</code> +{' '}
            <code className="font-mono text-emerald-400">axonwall-docs-latest.tar.gz.sha256</code>{' '}
            under <code className="font-mono text-slate-200">/var/lib/axonwall/downloads/</code>{' '}
            (or set <code className="font-mono text-slate-200">AXONWALL_DOCS_BUNDLE_PATH</code>),
            then click <strong>Install Offline Docs Plugin</strong>.
          </p>
        </div>
      </div>
    </div>
  );
}
