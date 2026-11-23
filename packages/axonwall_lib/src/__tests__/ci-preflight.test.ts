import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '../../../../');

describe('CI & Packaging Preflight', () => {
  it('passes shell syntax, preseed parity, BusyBox mktemp, merged-usr rsync, and bootloader cache checks', () => {
    const scriptPath = resolve(REPO_ROOT, 'scripts/ci-preflight.sh');
    let output = '';
    try {
      output = execFileSync('bash', [scriptPath], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        stdio: 'pipe',
      });
    } catch (err: unknown) {
      const e = err as { stdout?: string; stderr?: string; message?: string };
      throw new Error(
        `ci-preflight.sh failed:\n${e.stdout ?? ''}\n${e.stderr ?? ''}\n${e.message ?? ''}`,
      );
    }
    expect(output).toContain('All CI & Packaging Preflight checks passed!');
  });
});
