'use server';

import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';
import { callAgentApi } from './agent-client';
import { invalidateDesiredStateCache } from './agent';

export interface ExtensionPluginLiveStatus {
  id: string;
  name: string;
  version: string;
  category: string;
  description: string;
  author: string;
  enabled: boolean;
  defaultEnabled?: boolean;
  coreRole?: boolean;
  installed: boolean;
  bundled: boolean;
  dependencies?: string[];
  requiredBinaries: string[];
  missingBinaries: string[];
  packages: string[];
  installedAt?: string;
  systemdUnits?: string[];
  systemdServices?: { unit: string; active: boolean; state: string }[];
}

export interface PluginsApiResponse {
  plugins: ExtensionPluginLiveStatus[];
  osFamily: 'alpine' | 'debian';
}

export interface PluginActionResult {
  success: boolean;
  message: string;
  output?: string;
}

export async function getExtensionPlugins(): Promise<PluginsApiResponse> {
  const session = await getSession();
  assertActionPermitted(session);

  const res = await callAgentApi<PluginsApiResponse>('/v1/system/plugins', 'GET', undefined, 5000);
  // C25: a daemon outage used to collapse to "no extensions" plus a
  // possibly wrong default OS family. Throw a distinct
  // daemon-unavailable error so the page shows an unknown state and
  // keeps its previous list instead of an empty one.
  if (!res || !res.plugins) {
    throw new Error('Daemon unavailable: could not load extension plugins from axonwalld');
  }
  return res;
}

export async function executePluginAction(
  pluginId: string,
  action: 'install' | 'uninstall' | 'reconfigure' | 'enable' | 'disable'
): Promise<PluginActionResult> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  if (!/^[a-z0-9-]+$/.test(pluginId)) {
    return {
      success: false,
      message: 'Invalid plugin identifier format.',
    };
  }

  const res = await callAgentApi<PluginActionResult>(
    '/v1/system/plugins/action',
    'POST',
    { pluginId, action },
    300000 // Allow up to 5 minutes for apt/apk package manager downloads and configuration hooks
  );

  if (!res) {
    return {
      success: false,
      message: 'Failed to communicate with axonwalld agent daemon or operation timed out.',
    };
  }

  await invalidateDesiredStateCache();
  return res;
}
