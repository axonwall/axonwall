'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { findPluginById, isPluginEnabled } from '@axonwall/lib/plugins';
import type { DesiredState } from '@axonwall/lib/schemas';
import { getCurrentDesiredState } from '@/server/agent';

export interface PluginAwareLinkProps {
  pluginId: string;
  href: string;
  disabledHref?: string;
  className?: string;
  title?: string;
  enabled?: boolean;
  children: React.ReactNode;
}

let cachedStatePromise: Promise<DesiredState | null> | null = null;
let listenerRegistered = false;

function invalidateCachedDesiredState() {
  cachedStatePromise = null;
}

function getSharedDesiredState(): Promise<DesiredState | null> {
  if (typeof window !== 'undefined' && !listenerRegistered) {
    listenerRegistered = true;
    window.addEventListener('axonwall-capabilities-updated', invalidateCachedDesiredState);
  }
  if (!cachedStatePromise) {
    cachedStatePromise = getCurrentDesiredState().catch(() => null);
  }
  return cachedStatePromise;
}

/**
 * Renders a Next.js Link to `href` when `pluginId` is enabled, or routes to
 * `/system/plugins` with an inline amber "Opt-in" badge when the backing
 * extension plugin is disabled.
 */
export function PluginAwareLink({
  pluginId,
  href,
  disabledHref = '/system/plugins',
  className,
  title,
  enabled,
  children,
}: PluginAwareLinkProps) {
  const [desiredState, setDesiredState] = useState<DesiredState | null>(null);

  useEffect(() => {
    if (typeof enabled === 'boolean') return;
    let active = true;
    const load = () => {
      void getSharedDesiredState().then((s) => {
        if (active && s) setDesiredState(s);
      });
    };
    load();
    const onUpdate = () => {
      invalidateCachedDesiredState();
      load();
    };
    window.addEventListener('axonwall-capabilities-updated', onUpdate);
    return () => {
      active = false;
      window.removeEventListener('axonwall-capabilities-updated', onUpdate);
    };
  }, [enabled]);

  const active =
    typeof enabled === 'boolean'
      ? enabled
      : desiredState
        ? isPluginEnabled(pluginId, desiredState)
        : Boolean(findPluginById(pluginId)?.defaultEnabled);

  if (active) {
    return (
      <Link href={href} className={className} title={title}>
        {children}
      </Link>
    );
  }

  return (
    <Link
      href={disabledHref}
      className={className}
      title={title ?? `Requires opt-in plugin '${pluginId}' — open Plugin Store to enable`}
    >
      {children}
      <span className="ml-1 px-1.5 py-0.5 rounded text-[10px] font-mono uppercase bg-amber-500/15 text-amber-300 border border-amber-500/30">
        Opt-in
      </span>
    </Link>
  );
}
