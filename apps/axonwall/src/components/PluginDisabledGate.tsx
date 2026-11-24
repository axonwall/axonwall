'use client';

import React, { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { Download, Loader2, Package, Power, Shield } from 'lucide-react';
import {
  enablePluginWithDependencies,
  findPluginById,
  isPluginEnabled,
} from '@axonwall/lib/plugins';
import type { DesiredState } from '@axonwall/lib/schemas';
import { getCurrentDesiredState } from '@/server/agent';
import {
  executePluginAction,
  getExtensionPlugins,
  type ExtensionPluginLiveStatus,
} from '@/server/plugins';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';

export interface PluginDisabledGateProps {
  pluginId: string;
  title?: string;
  description?: string;
  children: React.ReactNode;
}

/**
 * Opt-in gate that blocks child page rendering (and child data-fetching effects)
 * until the backing plugin is enabled in DesiredState, with 1-click install + enable.
 */
export function PluginDisabledGate({
  pluginId,
  title,
  description,
  children,
}: PluginDisabledGateProps) {
  const { applyState, refreshFingerprint } = useDesiredStateApply();
  const [desiredState, setDesiredState] = useState<DesiredState | null>(null);
  const [liveStatus, setLiveStatus] = useState<ExtensionPluginLiveStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const manifest = findPluginById(pluginId);

  const loadGateState = useCallback(async () => {
    try {
      const [state, liveRes] = await Promise.all([
        getCurrentDesiredState(),
        getExtensionPlugins().catch(() => null),
      ]);
      setDesiredState(state);
      const match = liveRes?.plugins?.find((p) => p.id === pluginId) ?? null;
      setLiveStatus(match);
      setError(null);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : `Failed to verify '${pluginId}' plugin state`);
    } finally {
      setLoading(false);
    }
  }, [pluginId]);

  useEffect(() => {
    void loadGateState();
    const onCapUpdate = () => {
      void loadGateState();
    };
    window.addEventListener('axonwall-capabilities-updated', onCapUpdate);
    return () => {
      window.removeEventListener('axonwall-capabilities-updated', onCapUpdate);
    };
  }, [loadGateState]);

  const handleEnableOrInstall = async () => {
    setWorking(true);
    setError(null);
    try {
      const hasManifestPackages = Boolean(
        manifest?.packages &&
          ((manifest.packages.debian && manifest.packages.debian.length > 0) ||
            (manifest.packages.alpine && manifest.packages.alpine.length > 0) ||
            (manifest.packages.arch && manifest.packages.arch.length > 0)),
      );
      const hasLivePackages = Boolean(liveStatus?.packages && liveStatus.packages.length > 0);
      const needsInstall =
        (hasManifestPackages || hasLivePackages) &&
        !liveStatus?.installed &&
        !liveStatus?.bundled;

      if (needsInstall) {
        const installRes = await executePluginAction(pluginId, 'install');
        if (!installRes.success) {
          setError(installRes.message || `Failed to install '${pluginId}' packages`);
          return;
        }
        await refreshFingerprint();
      }

      const latestState = await getCurrentDesiredState();
      const enabled = enablePluginWithDependencies(pluginId, latestState);
      const applied = await applyState(enabled.state);
      if (!applied.success) {
        setError(applied.message || `Failed to enable plugin '${pluginId}'`);
        return;
      }

      setDesiredState(enabled.state);
      window.dispatchEvent(new Event('axonwall-capabilities-updated'));
      await loadGateState();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : `Failed to activate plugin '${pluginId}'`);
    } finally {
      setWorking(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-[60vh] flex items-center justify-center p-6 text-slate-300 text-sm gap-2">
        <Loader2 className="w-4 h-4 animate-spin text-emerald-400" />
        Checking plugin status for <code className="font-mono text-emerald-300">{pluginId}</code>...
      </div>
    );
  }

  if (desiredState && isPluginEnabled(pluginId, desiredState)) {
    return <>{children}</>;
  }

  const resolvedTitle = title || manifest?.name || pluginId;
  const resolvedDescription = description || manifest?.description || '';
  const packageList =
    liveStatus?.packages && liveStatus.packages.length > 0
      ? liveStatus.packages
      : manifest?.packages?.debian || manifest?.packages?.alpine || [];
  const hasPackages = packageList.length > 0;
  const needsInstall = hasPackages && !liveStatus?.installed && !liveStatus?.bundled;

  return (
    <div className="min-h-[70vh] flex items-center justify-center p-6">
      <div className="max-w-lg w-full rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4 shadow-xl">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-lg bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
            <Shield className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-lg font-semibold text-white">{resolvedTitle}</h1>
              <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-400">
                {pluginId}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              On-demand Axonwall extension plugin (disabled in Lean Router/NGFW Core)
            </p>
          </div>
        </div>

        {resolvedDescription && (
          <p className="text-sm text-slate-300 leading-relaxed">{resolvedDescription}</p>
        )}

        {hasPackages && (
          <div className="rounded-lg bg-slate-950 border border-slate-800 p-3 space-y-1.5">
            <div className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
              <Package className="w-3.5 h-3.5 text-emerald-400" />
              <span>
                {liveStatus?.installed || liveStatus?.bundled
                  ? 'Required OS packages already installed'
                  : 'OS packages installed on demand when activated'}
              </span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {packageList.map((pkg) => (
                <code
                  key={pkg}
                  className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300"
                >
                  {pkg}
                </code>
              ))}
            </div>
          </div>
        )}

        {error && (
          <div className="px-3 py-2 rounded bg-rose-500/10 border border-rose-500/40 text-xs text-rose-300">
            {error}
          </div>
        )}

        <div className="flex items-center justify-between pt-2">
          <Link href="/system/plugins" className="text-xs text-slate-400 hover:text-white underline">
            Manage in Plugin Store
          </Link>
          <button
            type="button"
            disabled={working || !desiredState}
            onClick={() => void handleEnableOrInstall()}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white text-xs font-semibold flex items-center gap-2 cursor-pointer"
          >
            {working ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : needsInstall ? (
              <Download className="w-4 h-4" />
            ) : (
              <Power className="w-4 h-4" />
            )}
            {working
              ? needsInstall
                ? 'Installing & Enabling...'
                : 'Enabling...'
              : needsInstall
                ? 'Install & Enable Plugin'
                : 'Enable Plugin'}
          </button>
        </div>
      </div>
    </div>
  );
}
