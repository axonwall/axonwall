'use server';

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';
import { DesiredStateSchema, type DesiredState } from '@axonwall/lib/schemas';
import {
  AXONWALL_YAML_FILENAMES,
  serializeDesiredStateToYamlFiles,
  parseDesiredStateFromYamlFiles,
} from '@axonwall/lib/yaml';
import { applyDesiredState } from './agent';
import { callAgentApi } from './agent-client';

const GITOPS_DIR = process.env.GITOPS_DIR || '/var/lib/axonwall/gitops';

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

export interface EtckeeperStatus {
  installed: boolean;
  vcs: string;
  clean: boolean;
  lastCommitHash?: string;
  lastCommitMsg?: string;
  lastCommitTime?: string;
  trackedPath: string;
}

export interface EtckeeperCommitLog {
  hash: string;
  author: string;
  date: string;
  subject: string;
}

export async function getEtckeeperStatus(): Promise<EtckeeperStatus | null> {
  const session = await getSession();
  assertActionPermitted(session);
  return await callAgentApi<EtckeeperStatus>('/v1/system/etckeeper/status', 'GET');
}

export async function getEtckeeperHistory(limit = 25): Promise<EtckeeperCommitLog[]> {
  const session = await getSession();
  assertActionPermitted(session);
  const resp = await callAgentApi<{ history: EtckeeperCommitLog[] }>(
    `/v1/system/etckeeper/history`,
    'GET'
  );
  return resp?.history || [];
}

export async function getEtckeeperDiff(commitHash?: string): Promise<string> {
  const session = await getSession();
  assertActionPermitted(session);
  const q = commitHash ? `?commit=${encodeURIComponent(commitHash)}` : '';
  const resp = await callAgentApi<{ diff: string }>(
    `/v1/system/etckeeper/diff${q}`,
    'GET'
  );
  return resp?.diff || 'No diff available or etckeeper not initialized.';
}

export async function commitEtckeeper(message: string): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  const author = session.username || 'admin';
  const resp = await callAgentApi<{ success: boolean; message?: string }>(
    '/v1/system/etckeeper/commit',
    'POST',
    { message, author }
  );
  if (resp && resp.success) {
    return { success: true, message: resp.message || 'Changes in /etc committed successfully.' };
  }
  return { success: false, message: 'Failed to record commit via etckeeper.' };
}

const GIT_BASE_ARGS = ['-c', `safe.directory=${GITOPS_DIR}`];

function ensureGitOpsRepo() {
  try {
    if (!fs.existsSync(GITOPS_DIR)) {
      fs.mkdirSync(GITOPS_DIR, { recursive: true, mode: 0o775 });
    }
    const gitDir = path.join(GITOPS_DIR, '.git');
    if (!fs.existsSync(gitDir)) {
      execFileSync('git', [...GIT_BASE_ARGS, 'init', '--initial-branch=main'], { cwd: GITOPS_DIR, stdio: 'ignore' });
      execFileSync('git', [...GIT_BASE_ARGS, 'config', 'user.name', 'Axonwall System'], { cwd: GITOPS_DIR, stdio: 'ignore' });
      execFileSync('git', [...GIT_BASE_ARGS, 'config', 'user.email', 'gitops@axonwall.internal'], { cwd: GITOPS_DIR, stdio: 'ignore' });
      execFileSync('git', [...GIT_BASE_ARGS, 'config', 'core.sharedRepository', 'group'], { cwd: GITOPS_DIR, stdio: 'ignore' });
    }
  } catch {}
}

export async function recordGitOpsChange(
  state: DesiredState,
  _author = 'admin',
  commitMsg = 'Firewall state updated (/etc/axonwall/*.yaml)'
): Promise<string | null> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  try {
    ensureGitOpsRepo();
    const yamlFiles = serializeDesiredStateToYamlFiles(state);
    for (const [filename, content] of Object.entries(yamlFiles)) {
      fs.writeFileSync(path.join(GITOPS_DIR, filename), content, { mode: 0o660 });
    }

    const stateFile = path.join(GITOPS_DIR, 'state.json');
    fs.writeFileSync(stateFile, JSON.stringify(state, null, 2), { mode: 0o660 });

    execFileSync('git', [...GIT_BASE_ARGS, 'add', ...AXONWALL_YAML_FILENAMES, 'state.json'], { cwd: GITOPS_DIR, stdio: 'ignore' });
    const safeAuthor = (session.username || 'admin').replace(/[^a-zA-Z0-9._-]/g, '') || 'admin';
    const safeMsg = (commitMsg || 'Firewall state updated').replace(/[\r\n]+/g, ' ').slice(0, 200);
    execFileSync('git', [...GIT_BASE_ARGS, 'commit', '-m', safeMsg, `--author=${safeAuthor} <${safeAuthor}@axonwall.local>`], {
      cwd: GITOPS_DIR,
      stdio: 'ignore',
    });

    const hash = execFileSync('git', [...GIT_BASE_ARGS, 'rev-parse', 'HEAD'], { cwd: GITOPS_DIR, encoding: 'utf8' }).trim();
    return hash;
  } catch {
    return null;
  }
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
  assertActionPermitted(session);

  const safeHash = commitHash.replace(/[^a-zA-Z0-9]/g, '');
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

  const safeHash = commitHash.replace(/[^a-zA-Z0-9]/g, '');
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
