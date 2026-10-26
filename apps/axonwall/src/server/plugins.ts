'use server';

import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';
import { callAgentApi } from './agent-client';

export interface ExtensionPluginLiveStatus {
  id: string;
  name: string;
  version: string;
  category: string;
  description: string;
  author: string;
  installed: boolean;
  bundled: boolean;
  requiredBinaries: string[];
  missingBinaries: string[];
  packages: string[];
  installedAt?: string;
  systemdUnits?: string[];
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
  if (!res || !res.plugins) {
    return {
      plugins: [],
      osFamily: 'debian',
    };
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
    90000 // Allow up to 90 seconds for apt/apk package manager downloads
  );

  if (!res) {
    return {
      success: false,
      message: 'Failed to communicate with axonwalld agent daemon.',
    };
  }

  return res;
}
