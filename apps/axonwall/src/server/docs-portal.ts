'use server';

import { isPluginEnabled } from '@axonwall/lib/plugins';
import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';
import { getDesiredStateInternal } from './desired-state-internal';
import {
  ONLINE_DOCS_BASE_URL,
  getDocsBundleSiteDir,
  readDocsBundleMeta,
} from './docs-portal-utils';

export interface DocsPortalStatus {
  installed: boolean;
  enabled: boolean;
  version: string | null;
  guideCount: number | null;
  builtAt: string | null;
  onlineBaseUrl: string;
}

export async function getDocsPortalStatus(): Promise<DocsPortalStatus> {
  const session = await getSession();
  assertActionPermitted(session);

  const state = await getDesiredStateInternal();
  const meta = readDocsBundleMeta(getDocsBundleSiteDir());

  return {
    installed: meta.installed,
    enabled: meta.installed && isPluginEnabled('docs-portal', state),
    version: meta.version,
    guideCount: meta.guideCount,
    builtAt: meta.builtAt,
    onlineBaseUrl: ONLINE_DOCS_BASE_URL,
  };
}
