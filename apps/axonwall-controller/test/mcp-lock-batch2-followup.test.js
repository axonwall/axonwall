// B2-M4 follow-up: the MCP propose lockfile is now also taken by
// the CLI apply path and by every TUI disk save. These tests drive
// the real built CLI binary against temp dirs (no daemon socket,
// so the apply takes the disk-only path) while the test process
// holds the lock the MCP propose path uses — acquired through the
// exact functions the propose handler calls (acquireMcpLockFile /
// desiredStateLockPath, exported from dist/index.js). The full MCP
// propose handler itself cannot run in this sandbox: it reads the
// hardcoded /etc/axonwall/state.json shared with the sibling batch
// worktrees, so the test process stands in for a concurrent propose
// by holding its lock; the propose handler's own locked section is
// covered by the batch-2 tests in mcp-batch2.test.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-mcp-lock-followup-'));
const etcDir = path.join(tmpRoot, 'etc');
const persistDir = path.join(tmpRoot, 'var-etc');
const statePath = path.join(tmpRoot, 'state.json');
const gitopsDir = path.join(tmpRoot, 'gitops');
const sockPath = path.join(tmpRoot, 'agent-api.sock');
const lockPath = path.join(tmpRoot, 'state.json.lock');

// The lock-path override (same pattern as AXONWALL_HA_STATE_PATH)
// keeps the test hermetic: the CLI child, the TUI save, and the
// MCP lock functions below all resolve to this temp lockfile
// instead of the shared /etc/axonwall/state.json.lock.
process.env.AXONWALL_DESIRED_STATE_LOCK_PATH = lockPath;

const { acquireMcpLockFile, desiredStateLockPath } = await import('../dist/index.js');

const cliPath = path.resolve(import.meta.dirname, '../dist/axonwallctl.js');
const cliEnv = {
  ...process.env,
  AXONWALL_ETC_DIR: etcDir,
  AXONWALL_PERSIST_YAML_DIR: persistDir,
  AXONWALL_STATE_FILE: statePath,
  AXONWALL_GITOPS_DIR: gitopsDir,
  AXONWALL_AGENT_API_SOCK: sockPath,
  AXONWALL_DESIRED_STATE_LOCK_PATH: lockPath,
};

test.after(() => {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

function runApplyAsync() {
  const child = spawn(process.execPath, [cliPath, 'apply'], { env: cliEnv });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => { stdout += d; });
  child.stderr.on('data', (d) => { stderr += d; });
  const done = new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
  return { child, done };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function markYamlFile() {
  // A trailing comment changes the file bytes without changing the
  // parsed state, so an apply rewriting the file strips the mark.
  const yaml = fs.readdirSync(etcDir).find((f) => f.endsWith('.yaml'));
  assert.ok(yaml, 'a YAML file must exist to mark');
  const p = path.join(etcDir, yaml);
  fs.appendFileSync(p, '\n# lock-followup-mark\n');
  return p;
}

test('B2-M4 follow-up: the lock path honors the override and is deterministic', () => {
  assert.equal(desiredStateLockPath(), lockPath);
  assert.equal(desiredStateLockPath(), desiredStateLockPath());
});

test('B2-M4 follow-up: seed apply writes the config to disk (no daemon)', async () => {
  const { done } = runApplyAsync();
  const res = await done;
  assert.equal(res.status, 0, `seed apply must exit 0, got ${res.status}: ${res.stderr}`);
  assert.match(res.stdout + res.stderr, /disk only/);
  assert.ok(fs.existsSync(statePath), 'the seed apply must write state.json');
  assert.ok(fs.readdirSync(etcDir).some((f) => f.endsWith('.yaml')), 'the seed apply must write YAML files');
});

test('B2-M4 follow-up: a CLI apply waits for the MCP lock, then completes after release', async () => {
  const marked = markYamlFile();
  // The test process holds the lock exactly the way an MCP
  // propose_firewall_rule call does (same function, same path).
  const release = acquireMcpLockFile(desiredStateLockPath());
  assert.ok(fs.existsSync(lockPath), 'holding the lock must create the lockfile');
  try {
    const { child, done } = runApplyAsync();
    await sleep(1500);
    assert.equal(child.exitCode, null, 'the CLI apply must still be waiting for the lock after 1.5 s');
    assert.match(fs.readFileSync(marked, 'utf8'), /lock-followup-mark/, 'no disk write may happen while the lock is held');
    release();
    const res = await done;
    assert.equal(res.status, 0, `the apply must complete once the lock is released, got ${res.status}: ${res.stderr}`);
    assert.doesNotMatch(fs.readFileSync(marked, 'utf8'), /lock-followup-mark/, 'the apply must rewrite the marked file after release');
  } finally {
    // Release is idempotent; a second call is a no-op.
    release();
  }
});

test('B2-M4 follow-up: a CLI apply fails closed when the MCP lock never frees', async () => {
  const marked = markYamlFile();
  const stateBefore = fs.readFileSync(statePath);
  const release = acquireMcpLockFile(desiredStateLockPath());
  // Keep the lock fresh: acquireMcpLockFile breaks a lock whose
  // mtime is older than ~9.5 s as stale, so a plain hold would be
  // broken before the CLI's 10 s timeout fires. Touching the
  // lockfile simulates a live holder still working (a heartbeat) —
  // the only way the timeout path is reachable at all.
  const touchTimer = setInterval(() => {
    try { fs.utimesSync(lockPath, new Date(), new Date()); } catch {}
  }, 1000);
  try {
    const { done } = runApplyAsync();
    // The CLI waits the 10 s lock timeout, then exits 1.
    const res = await done;
    assert.equal(res.status, 1, `the apply must exit 1 on lock timeout, got ${res.status}: ${res.stdout} ${res.stderr}`);
    assert.match(res.stdout + res.stderr, /Could not lock DesiredState/);
    assert.match(fs.readFileSync(marked, 'utf8'), /lock-followup-mark/, 'a timed-out apply must not write anything');
    assert.ok(fs.readFileSync(statePath).equals(stateBefore), 'state.json must be byte-identical after a timed-out apply');
  } finally {
    clearInterval(touchTimer);
    release();
  }
});

test('B2-M4 follow-up: a TUI save returns null while the MCP lock is held, and saves after release', async () => {
  // The TUI module only renders on direct execution, so importing
  // it here is inert; this drives the real saveStateToDisk.
  process.env.AXONWALL_CONFIG_DIR = etcDir;
  process.env.AXONWALL_PERSIST_YAML_DIR = persistDir;
  process.env.AXONWALL_STATE_FILE = statePath;
  const { saveStateToDisk } = await import('../dist/axonwall-tui.js');
  const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));

  const marked = markYamlFile();
  // Hold the lock in a separate process: the TUI save blocks the
  // event loop synchronously while it waits, so an in-process
  // holder could never refresh the lockfile mid-wait and the lock
  // would go stale before the save's timeout. The holder stands in
  // for a concurrent MCP propose holding the lock and touches it so
  // it stays fresh (a live holder still working).
  const holderPath = path.resolve(import.meta.dirname, './hold-mcp-lock.mjs');
  const holder = spawn(process.execPath, [holderPath], {
    env: { ...process.env, AXONWALL_DESIRED_STATE_LOCK_PATH: lockPath },
  });
  let holderOut = '';
  holder.stdout.on('data', (d) => { holderOut += d; });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('lock holder did not start')), 10000);
    holder.stdout.on('data', () => {
      if (holderOut.includes('holding')) { clearTimeout(timer); resolve(); }
    });
    holder.on('error', reject);
  });
  try {
    // The TUI waits its 2 s lock timeout, then reports the save
    // did not happen instead of writing unlocked.
    const blocked = saveStateToDisk(state);
    // NOTE: assert on a boolean, never on the returned object —
    // a failed assert.equal against the (huge) daemon-files object
    // makes the runner format a ~170 KB diff and choke the worker.
    assert.ok(blocked === null, 'a TUI save must return null while the MCP lock is held');
    assert.match(fs.readFileSync(marked, 'utf8'), /lock-followup-mark/, 'no disk write may happen while the lock is held');
  } finally {
    const closed = new Promise((resolve) => holder.on('close', resolve));
    holder.kill('SIGTERM');
    await closed;
  }
  const saved = saveStateToDisk(state);
  assert.ok(saved, 'a TUI save must succeed once the lock is released');
  assert.ok(saved.daemonFiles, 'a successful save returns the daemon files');
  assert.ok(saved.snapshot instanceof Map, 'a successful save returns the pre-save snapshot');
  assert.doesNotMatch(fs.readFileSync(marked, 'utf8'), /lock-followup-mark/, 'the save must rewrite the marked file after release');
});
