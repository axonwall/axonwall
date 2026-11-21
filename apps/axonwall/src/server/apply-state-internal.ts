import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { compileNftables } from '@axonwall/lib/compile/nft';
import { lintRuleset } from '@axonwall/lib/lint';
import type { DesiredState } from '@axonwall/lib/schemas';
import { callAgentApi, callAgentApiDetailed } from './agent-client';
import { isApplianceRuntime, isDevRuntime, readHostOSRelease } from './dev-paths';
import {
  invalidateDesiredStateCacheInternal,
  persistDesiredStateToDisk,
  readAllYamlConfigFiles,
  restoreDesiredStateSnapshot,
  snapshotDesiredStateOnDisk,
  syncNetworkInterfacesFiles,
} from './desired-state-internal';

export function isDevModeRuntimeInternal(): boolean {
  return (
    isDevRuntime() ||
    process.env.AXONWALL_DEV_MODE === '1' ||
    process.env.AXONWALL_DEV_MODE === 'true' ||
    process.env.NODE_ENV === 'development'
  );
}

let mockPendingConfirm = false;
let mockDeadline = 0;
let mockActiveRuleset = '';
let lastPendingJobId = '';

export function getLastPendingJobId(): string {
  return lastPendingJobId;
}

export function setLastPendingJobId(jobId: string): void {
  lastPendingJobId = jobId;
}

export function getMockApplyState() {
  return {
    pendingConfirm: mockPendingConfirm,
    confirmDeadlineUnix: mockDeadline,
    activeBundleHash: mockActiveRuleset ? 'hash-active-ruleset' : 'hash-initial-default',
  };
}

export function clearMockPendingConfirm(): void {
  mockPendingConfirm = false;
  mockDeadline = 0;
}

export async function runDesiredStateApplyPipeline(
  normalizedState: DesiredState,
  confirmTimeoutSeconds = 120,
  options?: { expectedFingerprint?: string; actorUsername?: string }
): Promise<{ success: boolean; message: string; nftScript: string; warnings: string[]; jobId?: string; devMode?: boolean }> {
  if (options?.expectedFingerprint) {
    const { fingerprint: currentFingerprint } = readAllYamlConfigFiles();
    if (currentFingerprint !== options.expectedFingerprint) {
      throw new Error(
        'Configuration changed since it was loaded; reload the latest configuration and retry instead of overwriting it.'
      );
    }
  }

  const diskSnapshot = snapshotDesiredStateOnDisk();

  const lintIssues = lintRuleset(normalizedState);
  const { nftScript, files, reloadServices, warnings: compileWarnings } = compileNftables(normalizedState);
  const warnings = [...lintIssues.map((i) => i.message), ...(compileWarnings || [])];
  const bundleHash = crypto.createHash('sha256').update(nftScript).digest('hex');

  const yamlDaemonFiles = persistDesiredStateToDisk(normalizedState);
  const { confContent, ifacesContent } = syncNetworkInterfacesFiles(normalizedState);

  const allFiles = [
    ...files.map((f: any) => ({
      ...f,
      fileMode: f.fileMode ?? f.file_mode ?? 0o600,
      file_mode: f.file_mode ?? f.fileMode ?? 0o600,
    })),
    ...Object.entries(yamlDaemonFiles).map(([filePath, content]) => ({
      path: filePath,
      content,
      fileMode: 0o660,
      file_mode: 0o660,
    })),
    {
      path: '/etc/axonwall/interfaces.conf',
      content: confContent,
      fileMode: 0o664,
      file_mode: 0o664,
    },
    ...(isApplianceRuntime() && readHostOSRelease().family === 'debian'
      ? [
          {
            path: '/etc/network/interfaces',
            content: ifacesContent,
            fileMode: 0o644,
            file_mode: 0o644,
          },
        ]
      : []),
    {
      path: '/etc/axonwall/state.json',
      content: JSON.stringify(normalizedState, null, 2),
      fileMode: 0o660,
      file_mode: 0o660,
    },
  ];

  const jobId = `ui-${Date.now()}`;
  lastPendingJobId = jobId;
  const applyRes = await callAgentApiDetailed<any>(
    '/v1/apply',
    'POST',
    {
      job_id: jobId,
      bundle_hash: bundleHash,
      nft_script: nftScript,
      files: allFiles,
      reload_services: reloadServices,
      confirm_timeout_seconds: confirmTimeoutSeconds,
    },
    120_000
  );

  if (applyRes.kind === 'ok') {
    const daemonResp = applyRes.data;
    if (!daemonResp.success) {
      const restored = restoreDesiredStateSnapshot(diskSnapshot);
      invalidateDesiredStateCacheInternal();
      lastPendingJobId = '';
      throw new Error(
        (daemonResp.message || 'Ruleset validation failed on daemon') +
          (restored
            ? ''
            : ' WARNING: on-disk configuration could not be fully restored to its pre-apply state; disk and daemon state may diverge.')
      );
    }
    try {
      const { recordGitOpsChange } = await import('./gitops');
      await recordGitOpsChange(
        normalizedState,
        options?.actorUsername || 'admin',
        `Configuration applied to /etc/axonwall/*.yaml (SHA256: ${bundleHash.slice(0, 12)})`
      );
    } catch {}
    return {
      success: true,
      jobId,
      message: daemonResp.message,
      nftScript,
      warnings,
      devMode: false,
    };
  }

  if (applyRes.kind === 'http_error') {
    const restored = restoreDesiredStateSnapshot(diskSnapshot);
    invalidateDesiredStateCacheInternal();
    lastPendingJobId = '';
    throw new Error(
      (applyRes.message || 'Ruleset validation failed on daemon') +
        (restored
          ? ''
          : ' WARNING: on-disk configuration could not be fully restored to its pre-apply state; disk and daemon state may diverge.')
    );
  }

  if (applyRes.kind === 'timeout') {
    try {
      const status = await callAgentApi<any>('/v1/status', 'GET', undefined, 5000);
      const livePending = status?.pending_job_id || status?.pendingJobId;
      if (livePending) {
        lastPendingJobId = livePending;
      }
    } catch {}
    throw new Error(
      'axonwalld apply request timed out after 120s — the configuration may still be committing or awaiting confirm/rollback on axonwalld. Check pending commit-confirm status before retrying.'
    );
  }

  const devMode = isDevModeRuntimeInternal();
  if (!devMode) {
    const restored = restoreDesiredStateSnapshot(diskSnapshot);
    invalidateDesiredStateCacheInternal();
    lastPendingJobId = '';
    throw new Error(
      'axonwalld is unreachable — the configuration was NOT applied and no commit-confirm is active' +
        (restored
          ? '. On-disk configuration was restored to its pre-apply state.'
          : ' WARNING: on-disk configuration could not be fully restored to its pre-apply state; disk and daemon state may diverge.')
    );
  }

  try {
    const { recordGitOpsChange } = await import('./gitops');
    await recordGitOpsChange(
      normalizedState,
      options?.actorUsername || 'admin',
      `Configuration applied to /etc/axonwall/*.yaml (SHA256: ${bundleHash.slice(0, 12)})`
    );
  } catch {}

  try {
    const routes = normalizedState.routes || [];
    for (const r of routes) {
      if (!r.network || !r.gateway) continue;
      const isV6 = r.network.includes(':') || r.gateway.includes(':');
      const family = isV6 ? '-6' : '-4';
      if (r.enabled ?? true) {
        const args = [family, 'route', 'replace', r.network, 'via', r.gateway, 'proto', 'static'];
        try {
          execFileSync('ip', args, { stdio: 'ignore', timeout: 2000 });
        } catch {}
      } else {
        const args = [family, 'route', 'del', r.network, 'proto', 'static'];
        try {
          execFileSync('ip', args, { stdio: 'ignore', timeout: 2000 });
        } catch {}
      }
    }
  } catch {}

  mockPendingConfirm = true;
  mockDeadline = Math.floor(Date.now() / 1000) + confirmTimeoutSeconds;
  mockActiveRuleset = nftScript;

  return {
    success: true,
    message: `Configuration saved to /etc/axonwall/*.yaml and applied (DEV MODE — no daemon running). Commit-confirm active for ${confirmTimeoutSeconds}s.`,
    nftScript,
    warnings,
    devMode: true,
  };
}
