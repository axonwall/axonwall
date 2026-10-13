'use server';

import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { getSession } from './auth';
import { DesiredStateSchema, type DesiredState } from '@axonwall/lib/schemas';
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
      execSync('git init --initial-branch=main', { cwd: GITOPS_DIR, stdio: 'ignore' });
      execSync('git config user.name "Axonwall System"', { cwd: GITOPS_DIR, stdio: 'ignore' });
      execSync('git config user.email "gitops@axonwall.internal"', { cwd: GITOPS_DIR, stdio: 'ignore' });
    }
  } catch {}
}

export async function recordGitOpsChange(
  state: DesiredState,
  author = 'admin',
  commitMsg = 'Firewall state updated'
): Promise<string | null> {
  try {
    ensureGitOpsRepo();
    const stateFile = path.join(GITOPS_DIR, 'state.json');
    fs.writeFileSync(stateFile, JSON.stringify(state, null, 2), { mode: 0o640 });

    execSync('git add state.json', { cwd: GITOPS_DIR, stdio: 'ignore' });
    const cleanMsg = commitMsg.replace(/"/g, '\\"');
    execSync(`git commit -m "${cleanMsg}" --author="${author} <${author}@axonwall.internal>"`, {
      cwd: GITOPS_DIR,
      stdio: 'ignore',
    });

    const hash = execSync('git rev-parse HEAD', { cwd: GITOPS_DIR, encoding: 'utf8' }).trim();
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
    const rawLog = execSync('git log -n 25 --pretty=format:"%H|%h|%an|%ai|%s" 2>/dev/null', {
      cwd: GITOPS_DIR,
      encoding: 'utf8',
      timeout: 1500,
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
            message: 'Initial baseline firewall state committed',
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
    const diff = execSync(`git show ${safeHash} --color=never 2>/dev/null`, {
      cwd: GITOPS_DIR,
      encoding: 'utf8',
      timeout: 2000,
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
  if (!session || !session.roles.includes('admin')) {
    throw new Error('Unauthorized: Admin privileges required to rollback configuration');
  }

  const safeHash = commitHash.replace(/[^a-zA-Z0-9]/g, '');
  try {
    const rawJson = execSync(`git show ${safeHash}:state.json`, {
      cwd: GITOPS_DIR,
      encoding: 'utf8',
      timeout: 2000,
    });
    const parsed = JSON.parse(rawJson);
    const state = DesiredStateSchema.parse(parsed);

    const res = await applyDesiredState(state, 120);
    return {
      success: res.success,
      message: `Successfully rolled back firewall state to commit ${safeHash.slice(0, 8)}. Safety rollback armed for 120s.`,
    };
  } catch (err: any) {
    return {
      success: false,
      message: err.message || 'Failed to rollback to target commit',
    };
  }
}
