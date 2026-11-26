import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import type { DesiredState } from '@axonwall/lib/schemas';
import { AXONWALL_YAML_FILENAMES, serializeDesiredStateToYamlFiles } from '@axonwall/lib/yaml';

export const GITOPS_DIR = process.env.GITOPS_DIR || '/var/lib/axonwall/gitops';

export const GIT_BASE_ARGS = [
  '-c',
  `safe.directory=${GITOPS_DIR}`,
  '-c',
  'user.name=Axonwall System',
  '-c',
  'user.email=gitops@axonwall.internal',
];

export function ensureGitOpsRepo(): void {
  try {
    if (!fs.existsSync(GITOPS_DIR)) {
      fs.mkdirSync(GITOPS_DIR, { recursive: true, mode: 0o775 });
    }
    const gitDir = path.join(GITOPS_DIR, '.git');
    if (!fs.existsSync(gitDir)) {
      execFileSync('git', [...GIT_BASE_ARGS, 'init', '--initial-branch=main'], {
        cwd: GITOPS_DIR,
        stdio: 'ignore',
      });
      execFileSync('git', [...GIT_BASE_ARGS, 'config', 'user.name', 'Axonwall System'], {
        cwd: GITOPS_DIR,
        stdio: 'ignore',
      });
      execFileSync('git', [...GIT_BASE_ARGS, 'config', 'user.email', 'gitops@axonwall.internal'], {
        cwd: GITOPS_DIR,
        stdio: 'ignore',
      });
      execFileSync('git', [...GIT_BASE_ARGS, 'config', 'core.sharedRepository', 'group'], {
        cwd: GITOPS_DIR,
        stdio: 'ignore',
      });
    }
  } catch {}
}

/**
 * Internal GitOps commit helper callable by already-authorized server pipelines
 * (e.g. operator WireGuard peer mutations) without exposing a public Server Action.
 */
export async function recordGitOpsChangeInternal(
  state: DesiredState,
  author = 'admin',
  commitMsg = 'Firewall state updated (/etc/axonwall/*.yaml)'
): Promise<string | null> {
  try {
    ensureGitOpsRepo();
    const yamlFiles = serializeDesiredStateToYamlFiles(state);
    for (const [filename, content] of Object.entries(yamlFiles)) {
      fs.writeFileSync(path.join(GITOPS_DIR, filename), content, { mode: 0o660 });
    }

    const stateFile = path.join(GITOPS_DIR, 'state.json');
    fs.writeFileSync(stateFile, JSON.stringify(state, null, 2), { mode: 0o660 });

    execFileSync('git', [...GIT_BASE_ARGS, 'add', ...AXONWALL_YAML_FILENAMES, 'state.json'], {
      cwd: GITOPS_DIR,
      stdio: 'ignore',
    });
    const safeAuthor = (author || 'admin').replace(/[^a-zA-Z0-9._-]/g, '') || 'admin';
    const safeMsg = (commitMsg || 'Firewall state updated').replace(/[\r\n]+/g, ' ').slice(0, 200);
    execFileSync(
      'git',
      [...GIT_BASE_ARGS, 'commit', '-m', safeMsg, `--author=${safeAuthor} <${safeAuthor}@axonwall.local>`],
      {
        cwd: GITOPS_DIR,
        stdio: 'ignore',
      }
    );

    const hash = execFileSync('git', [...GIT_BASE_ARGS, 'rev-parse', 'HEAD'], {
      cwd: GITOPS_DIR,
      encoding: 'utf8',
    }).trim();
    return hash;
  } catch {
    return null;
  }
}
