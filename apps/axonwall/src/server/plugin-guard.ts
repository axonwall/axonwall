import { NextResponse } from 'next/server';
import { isPluginEnabled } from '@axonwall/lib/plugins';
import { getDesiredStateInternal } from './desired-state-internal';

/**
 * Throws a Forbidden error when the requested plugin is disabled in DesiredState.
 * Plain server helper (not a Server Action) imported by route handlers and server actions.
 */
export async function assertPluginEnabled(pluginId: string): Promise<void> {
  const state = await getDesiredStateInternal();
  if (!isPluginEnabled(pluginId, state)) {
    throw new Error(`Forbidden: Plugin '${pluginId}' is not enabled. Enable it in System -> Plugins.`);
  }
}

/**
 * Fail-closed guard for Next.js App Router API handlers.
 * Returns a 403 JSON response when the plugin is disabled, or null when permitted.
 */
export async function checkPluginApiGuard(pluginId: string): Promise<NextResponse | null> {
  const state = await getDesiredStateInternal();
  if (!isPluginEnabled(pluginId, state)) {
    return NextResponse.json(
      { error: `Forbidden: Plugin '${pluginId}' is not enabled. Enable it in System -> Plugins.` },
      { status: 403 },
    );
  }
  return null;
}
