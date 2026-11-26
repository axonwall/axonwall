'use server';

import { execFileSync } from 'node:child_process';
import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';
import { assertPluginEnabled } from './plugin-guard';
import { DesiredStateSchema, type DesiredState } from '@axonwall/lib/schemas';
import {
  AXONWALL_YAML_FILENAMES,
  parseDesiredStateFromYamlFiles,
} from '@axonwall/lib/yaml';
import { applyDesiredState } from './agent';
import { callAgentApi, callAgentApiResponse } from './agent-client';
import {
  GITOPS_DIR,
  GIT_BASE_ARGS,
  ensureGitOpsRepo,
  recordGitOpsChangeInternal,
} from './gitops-internal';

export interface GitCommitRecord {
  hash: string;
  shortHash: string;
  author: string;
  date: string;
  message: string;
}

export interface GitOpsHistory {
  isAvailable: boolean;
  commits: GitCommitRecord[];
  currentHash?: string;
}

export interface EtckeeperFileChange {
  status: string;
  path: string;
}

export interface EtckeeperConfig {
  vcs: string;
  dailyAutocommit: boolean;
  avoidSpecialFileWarning: boolean;
  avoidCommitBeforeInstall: boolean;
  highlevelPackageManager: string;
  lowlevelPackageManager: string;
  pushRemote: string;
  gitCommitOptions: string;
  autoCommitOnApply: boolean;
  customIgnorePatterns: string[];
  confPath?: string;
  rawConfig?: string;
}

export interface EtckeeperStatus {
  installed: boolean;
  vcs: string;
  clean: boolean;
  lastCommitHash?: string;
  lastCommitMsg?: string;
  lastCommitAuthor?: string;
  lastCommitTime?: string;
  trackedPath: string;
  initialized?: boolean;
  totalCommits?: number;
  modifiedFiles?: EtckeeperFileChange[];
  timerActive?: boolean;
  timerEnabled?: boolean;
  nextTimerRun?: string;
  lastTimerRun?: string;
  config?: EtckeeperConfig;
}

export interface EtckeeperCommitLog {
  hash: string;
  shortHash?: string;
  author: string;
  date: string;
  subject: string;
}

export async function getEtckeeperStatus(): Promise<EtckeeperStatus | null> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('etckeeper-audit');
  const resp = await callAgentApi<EtckeeperStatus & { error?: string }>('/v1/system/etckeeper/status', 'GET');
  if (!resp || resp.error) {
    return null;
  }
  return resp;
}

export async function getEtckeeperConfig(): Promise<EtckeeperConfig | null> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('etckeeper-audit');
  const resp = await callAgentApi<EtckeeperConfig & { error?: string }>('/v1/system/etckeeper/config', 'GET');
  if (!resp || resp.error) {
    return null;
  }
  return resp;
}

export async function saveEtckeeperConfig(
  config: Partial<EtckeeperConfig>
): Promise<{ success: boolean; message: string; config?: EtckeeperConfig }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('etckeeper-audit');
  const resp = await callAgentApiResponse<{
    success?: boolean;
    message?: string;
    error?: string;
    config?: EtckeeperConfig;
  }>('/v1/system/etckeeper/config', 'POST', config);
  if (resp && resp.success) {
    return {
      success: true,
      message: resp.message || 'Saved /etc/etckeeper/etckeeper.conf successfully.',
      config: resp.config,
    };
  }
  return {
    success: false,
    message: resp?.message || resp?.error || 'Failed to update etckeeper configuration.',
  };
}

export async function initEtckeeper(): Promise<{
  success: boolean;
  message: string;
  status?: EtckeeperStatus;
}> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('etckeeper-audit');
  const resp = await callAgentApiResponse<{
    success?: boolean;
    message?: string;
    error?: string;
    status?: EtckeeperStatus;
  }>('/v1/system/etckeeper/init', 'POST', {}, 60_000);
  if (resp && resp.success) {
    return {
      success: true,
      message: resp.message || 'Initialized etckeeper in /etc.',
      status: resp.status,
    };
  }
  return {
    success: false,
    message: resp?.message || resp?.error || 'Failed to initialize etckeeper.',
  };
}

export async function getEtckeeperHistory(
  limit = 50,
  pathFilter?: string
): Promise<EtckeeperCommitLog[]> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('etckeeper-audit');
  const params = new URLSearchParams();
  if (limit > 0) params.set('limit', String(limit));
  if (pathFilter && pathFilter.trim()) {
    params.set('path', pathFilter.trim());
  }
  const qs = params.toString() ? `?${params.toString()}` : '';
  const resp = await callAgentApi<{ history?: EtckeeperCommitLog[]; error?: string }>(
    `/v1/system/etckeeper/history${qs}`,
    'GET'
  );
  return resp?.history || [];
}

export async function getEtckeeperDiff(commitHash?: string): Promise<string> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('etckeeper-audit');
  if (commitHash !== undefined && commitHash !== '') {
    if (!/^[0-9a-fA-F]{4,64}$/.test(commitHash)) {
      throw new Error('Invalid commit hash format');
    }
  }
  const q = commitHash ? `?commit=${encodeURIComponent(commitHash)}` : '';
  const resp = await callAgentApi<{ diff?: string; error?: string }>(
    `/v1/system/etckeeper/diff${q}`,
    'GET'
  );
  // C-M5: a null response means the daemon did not answer. Returning the
  // "no changes" string here told the operator /etc was clean when its
  // state was simply unknown. Throw so callers show a load failure.
  if (!resp) {
    throw new Error('Daemon unavailable: could not load etckeeper diff from axonwalld.');
  }
  if (resp?.error) {
    return `Error loading diff: ${resp.error}`;
  }
  return resp?.diff || 'No uncommitted changes or diff is empty.';
}

export async function commitEtckeeper(message: string): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('etckeeper-audit');
  const author = session.username || 'admin';
  const resp = await callAgentApiResponse<{ success?: boolean; message?: string; error?: string }>(
    '/v1/system/etckeeper/commit',
    'POST',
    { message, author }
  );
  if (resp && resp.success) {
    return { success: true, message: resp.message || 'Changes in /etc committed successfully.' };
  }
  return {
    success: false,
    message: resp?.message || resp?.error || 'Failed to record commit via etckeeper.',
  };
}

export async function recordGitOpsChange(
  state: DesiredState,
  _author = 'admin',
  commitMsg = 'Firewall state updated (/etc/axonwall/*.yaml)'
): Promise<string | null> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  return recordGitOpsChangeInternal(state, session.username || 'admin', commitMsg);
}

export async function getGitOpsHistory(): Promise<GitOpsHistory> {
  const session = await getSession();
  assertActionPermitted(session);

  ensureGitOpsRepo();
  try {
    const rawLog = execFileSync('git', [...GIT_BASE_ARGS, 'log', '-n', '25', '--pretty=format:%H|%h|%an|%ai|%s'], {
      cwd: GITOPS_DIR,
      encoding: 'utf8',
      timeout: 1500,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();

    if (!rawLog) {
      return {
        isAvailable: true,
        commits: [
          {
            hash: '0000000000000000000000000000000000000001',
            shortHash: 'init',
            author: 'system',
            date: new Date().toISOString(),
            message: 'Initial baseline /etc/axonwall/*.yaml state committed',
          },
        ],
      };
    }

    const commits: GitCommitRecord[] = rawLog.split('\n').map((line) => {
      const [hash, shortHash, author, date, ...rest] = line.split('|');
      return {
        hash,
        shortHash,
        author,
        date,
        message: rest.join('|'),
      };
    });

    const currentHash = commits[0]?.hash;

    return {
      isAvailable: true,
      commits,
      currentHash,
    };
  } catch {
    return {
      isAvailable: false,
      commits: [],
    };
  }
}

export async function getCommitDiff(commitHash: string): Promise<string> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const trimmed = (commitHash || '').trim();
  if (!/^[0-9a-fA-F]{4,64}$/.test(trimmed)) {
    return 'Invalid commit hash.';
  }
  const safeHash = trimmed;
  try {
    const yamlDiff = execFileSync('git', [...GIT_BASE_ARGS, 'show', safeHash, '--color=never', '--', '*.yaml'], {
      cwd: GITOPS_DIR,
      encoding: 'utf8',
      timeout: 2000,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    if (yamlDiff && yamlDiff.includes('diff --git')) {
      return yamlDiff;
    }
    const diff = execFileSync('git', [...GIT_BASE_ARGS, 'show', safeHash, '--color=never'], {
      cwd: GITOPS_DIR,
      encoding: 'utf8',
      timeout: 2000,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return diff;
  } catch {
    return 'Unable to load diff for specified commit.';
  }
}

export async function rollbackToGitOpsCommit(
  commitHash: string
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const trimmed = (commitHash || '').trim();
  if (!/^[0-9a-fA-F]{4,64}$/.test(trimmed)) {
    return { success: false, message: 'Invalid commit hash.' };
  }
  const safeHash = trimmed;
  try {
    let state: DesiredState | null = null;
    const yamlMap: Record<string, string> = {};
    for (const filename of AXONWALL_YAML_FILENAMES) {
      try {
        const rawYaml = execFileSync('git', [...GIT_BASE_ARGS, 'show', `${safeHash}:${filename}`], {
          cwd: GITOPS_DIR,
          encoding: 'utf8',
          timeout: 1500,
          stdio: ['ignore', 'pipe', 'ignore'],
        });
        if (rawYaml) yamlMap[filename] = rawYaml;
      } catch {}
    }

    if (Object.keys(yamlMap).length > 0) {
      state = parseDesiredStateFromYamlFiles(yamlMap);
    } else {
      const rawJson = execFileSync('git', [...GIT_BASE_ARGS, 'show', `${safeHash}:state.json`], {
        cwd: GITOPS_DIR,
        encoding: 'utf8',
        timeout: 2000,
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      state = DesiredStateSchema.parse(JSON.parse(rawJson));
    }

    const res = await applyDesiredState(state, 120);
    return {
      success: res.success,
      message: `Successfully rolled back /etc/axonwall/*.yaml state to commit ${safeHash.slice(0, 8)}. Safety rollback armed for 120s.`,
    };
  } catch (err: any) {
    return {
      success: false,
      message: err.message || 'Failed to rollback to target commit',
    };
  }
}
