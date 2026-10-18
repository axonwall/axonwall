'use server';

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { getSession } from './auth';
import { DesiredStateSchema, type DesiredState } from '@axonwall/lib/schemas';
import {
  AXONWALL_YAML_FILENAMES,
  serializeDesiredStateToYamlFiles,
  parseDesiredStateFromYamlFiles,
} from '@axonwall/lib/yaml';
import { applyDesiredState } from './agent';

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

function ensureGitOpsRepo() {
  try {
    if (!fs.existsSync(GITOPS_DIR)) {
      fs.mkdirSync(GITOPS_DIR, { recursive: true, mode: 0o750 });
    }
    const gitDir = path.join(GITOPS_DIR, '.git');
    if (!fs.existsSync(gitDir)) {
      execFileSync('git', ['init', '--initial-branch=main'], { cwd: GITOPS_DIR, stdio: 'ignore' });
      execFileSync('git', ['config', 'user.name', 'Axonwall System'], { cwd: GITOPS_DIR, stdio: 'ignore' });
      execFileSync('git', ['config', 'user.email', 'gitops@axonwall.internal'], { cwd: GITOPS_DIR, stdio: 'ignore' });
    }
  } catch {}
}

export async function recordGitOpsChange(
  state: DesiredState,
  _author = 'admin',
  commitMsg = 'Firewall state updated (/etc/axonwall/*.yaml)'
): Promise<string | null> {
  const session = await getSession();
  if (!session || !session.roles.includes('admin') || session.passwordChangeRequired) {
    throw new Error('Unauthorized');
  }

  try {
    ensureGitOpsRepo();
    const yamlFiles = serializeDesiredStateToYamlFiles(state);
    for (const [filename, content] of Object.entries(yamlFiles)) {
      fs.writeFileSync(path.join(GITOPS_DIR, filename), content, { mode: 0o640 });
    }

    const stateFile = path.join(GITOPS_DIR, 'state.json');
    fs.writeFileSync(stateFile, JSON.stringify(state, null, 2), { mode: 0o640 });

    execFileSync('git', ['add', ...AXONWALL_YAML_FILENAMES, 'state.json'], { cwd: GITOPS_DIR, stdio: 'ignore' });
    const safeAuthor = (session.username || 'admin').replace(/[^a-zA-Z0-9._-]/g, '') || 'admin';
    const safeMsg = (commitMsg || 'Firewall state updated').replace(/[\r\n]+/g, ' ').slice(0, 200);
    execFileSync('git', ['commit', '-m', safeMsg, `--author=${safeAuthor} <${safeAuthor}@axonwall.local>`], {
      cwd: GITOPS_DIR,
      stdio: 'ignore',
    });

    const hash = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: GITOPS_DIR, encoding: 'utf8' }).trim();
    return hash;
  } catch {
    return null;
  }
}

export async function getGitOpsHistory(): Promise<GitOpsHistory> {
  const session = await getSession();
  if (!session) throw new Error('Unauthorized');

  ensureGitOpsRepo();
  try {
    const rawLog = execFileSync('git', ['log', '-n', '25', '--pretty=format:%H|%h|%an|%ai|%s'], {
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
  if (!session) throw new Error('Unauthorized');

  const safeHash = commitHash.replace(/[^a-zA-Z0-9]/g, '');
  try {
    const yamlDiff = execFileSync('git', ['show', safeHash, '--color=never', '--', '*.yaml'], {
      cwd: GITOPS_DIR,
      encoding: 'utf8',
      timeout: 2000,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    if (yamlDiff && yamlDiff.includes('diff --git')) {
      return yamlDiff;
    }
    const diff = execFileSync('git', ['show', safeHash, '--color=never'], {
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
  if (!session || !session.roles.includes('admin') || session.passwordChangeRequired) {
    throw new Error('Unauthorized: Admin privileges required to rollback configuration');
  }

  const safeHash = commitHash.replace(/[^a-zA-Z0-9]/g, '');
  try {
    let state: DesiredState | null = null;
    const yamlMap: Record<string, string> = {};
    for (const filename of AXONWALL_YAML_FILENAMES) {
      try {
        const rawYaml = execFileSync('git', ['show', `${safeHash}:${filename}`], {
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
      const rawJson = execFileSync('git', ['show', `${safeHash}:state.json`], {
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
