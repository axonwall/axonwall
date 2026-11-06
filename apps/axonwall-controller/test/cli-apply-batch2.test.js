// B2-M5 (B-M5): axonwallctl apply used to write the new config to
// disk before asking the daemon, and on a daemon rejection the
// rejected config stayed on disk as if it were current — disk,
// GitOps, and kernel then disagreed. The fix snapshots the on-disk
// config before overwriting it and restores it on an explicit
// rejection, while keeping the new files on a daemon outage (the
// intentional disk-only sync). These tests drive the real built CLI
// binary against temp dirs and a fake daemon unix socket.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';

const cliPath = path.resolve(import.meta.dirname, '../dist/axonwallctl.js');
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-cli-apply-'));
const etcDir = path.join(tmpRoot, 'etc');
const persistDir = path.join(tmpRoot, 'var-etc');
const statePath = path.join(tmpRoot, 'state.json');
const gitopsDir = path.join(tmpRoot, 'gitops');
const sockPath = path.join(tmpRoot, 'agent-api.sock');

const cliEnv = {
  ...process.env,
  AXONWALL_ETC_DIR: etcDir,
  AXONWALL_PERSIST_YAML_DIR: persistDir,
  AXONWALL_STATE_FILE: statePath,
  AXONWALL_GITOPS_DIR: gitopsDir,
  AXONWALL_AGENT_API_SOCK: sockPath,
};

// Async spawn (not spawnSync): the fake daemon runs in this
// process, so a blocking spawn would starve it and the CLI's
// request would time out instead of being answered.
function runApply() {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, 'apply'], { env: cliEnv });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

function snapshotAllFiles() {
  const snap = new Map();
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (!entry.isSocket()) snap.set(path.relative(tmpRoot, p), fs.readFileSync(p));
    }
  };
  walk(tmpRoot);
  return snap;
}

function assertSameSnapshot(a, b) {
  assert.deepEqual([...a.keys()].sort(), [...b.keys()].sort(), 'the same set of config files must exist');
  for (const [rel, content] of a.entries()) {
    assert.ok(b.get(rel).equals(content), `file ${rel} must be byte-identical after restore`);
  }
}

// Fake daemon: rejects the apply when rejectMode is true.
// When silentMode is true it never answers, so the CLI's 15s
// request timeout fires (B2-M6 timeout case).
let rejectMode = true;
let silentMode = false;
const fakeDaemon = http.createServer((req, res) => {
  if (silentMode) return; // accept the connection, never answer
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    if (req.url === '/v1/apply' && req.method === 'POST') {
      res.end(JSON.stringify(rejectMode
        ? { success: false, message: 'rejected for test: nftables syntax check failed' }
        : { success: true, message: 'applied' }));
      return;
    }
    if (req.url === '/v1/confirm' && req.method === 'POST') {
      res.end(JSON.stringify({ success: true, message: 'confirmed' }));
      return;
    }
    res.writeHead(404);
    res.end('{}');
  });
});

let seedSnapshot;
let sentinelFile;

test.after(() => {
  try { fakeDaemon.close(); } catch {}
  try { fs.unlinkSync(sockPath); } catch {}
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

test('B2-M5: offline apply writes the config to disk (seed)', async () => {
  const res = await runApply();
  assert.equal(res.status, 0, `offline apply must exit 0, got ${res.status}: ${res.stderr}`);
  assert.match(res.stdout + res.stderr, /disk only/);
  seedSnapshot = snapshotAllFiles();
  assert.ok(seedSnapshot.size > 0, 'the seed apply must write config files');
  // Pick a YAML file to mark: a comment changes the file bytes
  // without changing the parsed state.
  sentinelFile = [...seedSnapshot.keys()].find((k) => k.endsWith('.yaml'));
  assert.ok(sentinelFile, 'a YAML file must exist to mark');
});

test('B2-M5: a daemon rejection restores the previous on-disk config', async () => {
  // Mark one file so the second apply's rewrite is observable:
  // the mark changes the file bytes without changing the parsed
  // state, so a rewrite strips it. The restore must put disk back
  // to exactly how it was immediately before THIS apply — mark
  // included — not to the seed state and not to the rewritten state.
  fs.appendFileSync(path.join(tmpRoot, sentinelFile), '\n# b2-m5-sentinel\n');
  const preRejectSnapshot = snapshotAllFiles();
  assert.ok(preRejectSnapshot.get(sentinelFile).includes('b2-m5-sentinel'));

  await new Promise((resolve, reject) => {
    fakeDaemon.listen(sockPath, (err) => (err ? reject(err) : resolve()));
  });
  rejectMode = true;
  const res = await runApply();
  assert.equal(res.status, 1, `a rejected apply must exit 1, got ${res.status}: ${res.stdout} ${res.stderr}`);
  assert.match(res.stdout + res.stderr, /Daemon rejected bundle/);
  assert.match(res.stdout + res.stderr, /Restored the previous on-disk configuration/);
  assertSameSnapshot(preRejectSnapshot, snapshotAllFiles());
});

test('B2-M5: an offline apply keeps the new disk writes (no restore)', async () => {
  // Stop the daemon first, so this apply takes the offline path.
  await new Promise((resolve) => fakeDaemon.close(resolve));
  try { fs.unlinkSync(sockPath); } catch {}
  // The sentinel is still on disk from the restored state above.
  // The offline path rewrites the files and must NOT restore
  // them, so the mark must be stripped by the rewrite.
  const res = await runApply();
  assert.equal(res.status, 0, `offline apply must exit 0, got ${res.status}: ${res.stderr}`);
  const after = snapshotAllFiles();
  assert.ok(!after.get(sentinelFile).includes('b2-m5-sentinel'), 'the offline rewrite must keep the new files');
});

test('B2-M6: a daemon timeout is status-unknown, not "socket offline"', async () => {
  await new Promise((resolve, reject) => {
    fakeDaemon.listen(sockPath, (err) => (err ? reject(err) : resolve()));
  });
  silentMode = true;
  // Mark a file: the apply rewrites it, and the timeout path must
  // keep the new writes (no restore) while saying the status is
  // unknown — never "socket offline".
  fs.appendFileSync(path.join(tmpRoot, sentinelFile), '\n# b2-m6-sentinel\n');
  const res = await runApply();
  assert.equal(res.status, 0, `a timed-out apply must exit 0, got ${res.status}: ${res.stderr}`);
  assert.match(res.stdout + res.stderr, /Apply status unknown/);
  assert.doesNotMatch(res.stdout + res.stderr, /daemon socket offline/);
  const after = snapshotAllFiles();
  assert.ok(!after.get(sentinelFile).includes('b2-m6-sentinel'), 'the timed-out rewrite must keep the new files');
});
