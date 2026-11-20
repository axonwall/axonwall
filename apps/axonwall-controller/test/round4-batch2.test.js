// Round-4 batch B2 (controller) regression tests.
//
// Each finding gets at least one test driving the real built code
// (dist/index.js, dist/axonwallctl.js) against temp dirs and a fake
// daemon on a unix socket — no live daemon, no live box.
//   R4-B-M1  canonical config paths (keys, settings, state)
//   R4-B-M2  mcp_emergency_clear_all checks the XDP clear-all
//   R4-B-M3  missing satellite COMMAND_ACK surfaces in lastApplyError
//   R4-B-M4  axonwallctl update always passes a version (CLI e2e)
//   R4-B-L1  mcp_inspect_nas_storage reports per-source failures
//   R4-B-L2  MCP rate-limit budget survives across stdio processes
//   R4-B-L4  persistSyncedRoutes reports failure
//   R4-B-L6  live-but-slow lock holder is never broken (two processes)
// R4-B-H1 (TUI toggle), R4-B-L3 (TUI refreshAll) and R4-B-L5
// (dev-path anchoring) are UI / process-cwd behaviour with no
// node:test seam in this repo; they are verified by the manual
// checks recorded in results-batch2.md, not here.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as http from 'node:http';
import { spawn } from 'node:child_process';

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-round4-batch2-'));
const varDir = path.join(tmpRoot, 'var');
const etcDir = path.join(tmpRoot, 'etc');
const persistDir = path.join(tmpRoot, 'var-etc');
const statePath = path.join(varDir, 'state.json');
const keysPath = path.join(varDir, 'mcp-keys.json');
const rateLimitPath = path.join(tmpRoot, 'mcp-rate-limits.json');
const agentSock = path.join(tmpRoot, 'agent.sock');
const auditPath = path.join(tmpRoot, 'mcp-audit.jsonl');
for (const d of [varDir, etcDir, persistDir]) fs.mkdirSync(d, { recursive: true });

process.env.AXONWALL_STATE_DIR = varDir;
process.env.AXONWALL_ETC_DIR = etcDir;
process.env.AXONWALL_PERSIST_YAML_DIR = persistDir;
process.env.AXONWALL_STATE_FILE = statePath;
process.env.AXONWALL_MCP_RATE_LIMIT_PATH = rateLimitPath;
process.env.AXONWALL_AGENT_API_SOCK = agentSock;
process.env.AXONWALL_MCP_ENABLED = 'true';
process.env.AXONWALL_MCP_AUDIT_PATH = auditPath;

const {
  createMcpApiKeyRecord,
  listMcpApiKeys,
  revokeMcpApiKeyRecord,
  authenticateMcpToken,
  processMcpJsonRpcMessage,
  getMcpServerStatus,
  saveMcpSettings,
  readCanonicalConfig,
  writeCanonicalConfig,
  persistSyncedRoutes,
  loadPersistedSyncedRoutes,
  isPendingCommandStale,
  recordCommandAck,
  pendingCommandStaleMsFor,
  missingCommandAckError,
  PENDING_COMMAND_STALE_MS,
  PENDING_COMMAND_SHORT_STALE_MS,
  acquireMcpLockFile,
} = await import('../dist/index.js');

test.after(() => {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- Fake daemon (unix socket), controlled per test -----------------------
let flushMode = 'ok'; // 'ok' | 'error'
let xdpMode = 'ok'; // 'ok' | 'error'
let nasDisksMode = 'ok'; // 'ok' | 'error'
let statusVersion = '0.12.3'; // string | undefined (absent version)
let lastUpdateBody = null;

const daemon = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    const send = (status, obj) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(obj));
    };
    if (req.url === '/v1/mcp/flush' && req.method === 'POST') {
      if (flushMode === 'error') return send(500, { success: false, error: 'flush subsystem error' });
      return send(200, { success: true, clearedCount: 3 });
    }
    if (req.url === '/v1/ebpf/xdp/block' && req.method === 'DELETE') {
      if (xdpMode === 'error') return send(500, { success: false, error: 'XDP subsystem error' });
      return send(200, { success: true, cleared: 5 });
    }
    if (req.url === '/v1/nas/telemetry') return send(200, { pools: [] });
    if (req.url === '/v1/nas/disks') {
      if (nasDisksMode === 'error') return send(500, { error: 'ZFS disks query failed' });
      return send(200, { disks: [{ name: 'tank' }] });
    }
    if (req.url === '/v1/nas/snapshots') return send(200, { snapshots: [{ name: 'tank@snap1' }] });
    if (req.url === '/v1/status') {
      return send(200, statusVersion === undefined ? {} : { version: statusVersion });
    }
    if (req.url === '/v1/system/update' && req.method === 'POST') {
      try { lastUpdateBody = JSON.parse(body || '{}'); } catch { lastUpdateBody = null; }
      return send(200, { success: true, message: 'update accepted' });
    }
    return send(404, { error: 'not found' });
  });
});
await new Promise((resolve) => daemon.listen(agentSock, resolve));
test.after(() => daemon.close());

async function callTool(key, name, args = {}) {
  const res = await processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } },
    { key, clientIp: '127.0.0.1' }
  );
  assert.ok(res && !res.error, `expected a tool result, got ${JSON.stringify(res)}`);
  const text = res.result.content[0].text;
  return JSON.parse(text);
}

function runCli(args, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [path.resolve(import.meta.dirname, '../dist/axonwallctl.js'), ...args],
      {
        env: {
          ...process.env,
          AXONWALL_ETC_DIR: etcDir,
          AXONWALL_STATE_DIR: varDir,
          AXONWALL_PERSIST_YAML_DIR: persistDir,
          AXONWALL_GITOPS_DIR: path.join(tmpRoot, 'gitops'),
          AXONWALL_AGENT_API_SOCK: agentSock,
          ...extraEnv,
        },
      }
    );
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

// --- R4-B-M1: canonical config paths --------------------------------------
test('R4-B-M1: a stale keys mirror never defeats a revocation (canonical read wins)', () => {
  const created = createMcpApiKeyRecord({
    name: 'b-m1-test',
    scopes: ['mcp:telemetry:read'],
    policyLimits: { rateLimitPerMinute: 6000 },
  });
  // The create fanned out to the mirrors; now poison the etc mirror
  // with a stale copy that still contains a "revoked" key.
  const staleKey = { ...JSON.parse(fs.readFileSync(keysPath, 'utf8'))[0] };
  const etcMirror = path.join(etcDir, 'mcp-keys.json');
  const staleSet = [
    staleKey,
    {
      id: 'mcp_key_stale0001',
      name: 'stale-revived-key',
      agentType: 'soar',
      keyPrefix: 'axw_mcp_stale0001',
      secretHashSha256: '00'.repeat(32),
      scopes: ['mcp:telemetry:read'],
      allowedSourceCidrs: [],
      policyLimits: { rateLimitPerMinute: 120 },
      enabled: true,
      createdAt: new Date().toISOString(),
      createdBy: 'test',
    },
  ];
  fs.writeFileSync(etcMirror, JSON.stringify(staleSet, null, 2));
  // The stale mirror must be invisible to loads.
  assert.equal(listMcpApiKeys().some((k) => k.id === 'mcp_key_stale0001'), false);
  assert.equal(listMcpApiKeys().some((k) => k.id === created.key.id), true);

  assert.equal(revokeMcpApiKeyRecord(created.key.id), true);
  // Revoked key must not authenticate, even though the stale mirror
  // still contains it.
  const auth = authenticateMcpToken(created.rawToken, '127.0.0.1');
  assert.equal(auth.authenticated, false);
  assert.equal(auth.errorStatus, 401);
});

test('R4-B-M1: a failed canonical keys write throws instead of reporting success', () => {
  // Point the canonical path at an existing directory: the keys
  // lock (a sibling file) can still be taken, but the atomic
  // rename onto the directory fails — so the failure under test is
  // the save itself, not lock acquisition.
  const keysDir = path.join(tmpRoot, 'keys-is-dir');
  fs.mkdirSync(keysDir, { recursive: true });
  process.env.AXONWALL_MCP_KEYS_PATH = keysDir;
  try {
    assert.throws(
      () =>
        createMcpApiKeyRecord({
          name: 'b-m1-fail',
          scopes: ['mcp:telemetry:read'],
        }),
      /Failed to persist mcp-keys\.json to canonical path/
    );
  } finally {
    delete process.env.AXONWALL_MCP_KEYS_PATH;
  }
});

test('R4-B-M1: settings load never prefers a stale enabled mirror over a canonical disable', () => {
  // The env override (AXONWALL_MCP_ENABLED=true, set for the other
  // tests in this file) outranks the file; drop it while asserting
  // file-based status, then restore it.
  const savedEnv = process.env.AXONWALL_MCP_ENABLED;
  delete process.env.AXONWALL_MCP_ENABLED;
  try {
    const saved = saveMcpSettings({
      enabled: false,
      disabledReason: 'Disabled in test',
      disabledAt: new Date().toISOString(),
      disabledBy: 'test',
    });
    assert.equal(saved.ok, true);
    assert.equal(getMcpServerStatus().enabled, false);
    // Poison both mirrors with enabled:true.
    for (const mirror of [path.join(persistDir, 'mcp-settings.json'), path.join(etcDir, 'mcp-settings.json')]) {
      fs.writeFileSync(mirror, JSON.stringify({ enabled: true }, null, 2));
    }
    const status = getMcpServerStatus();
    assert.equal(status.enabled, false, 'canonical disable must win over stale enabled mirrors');
    assert.equal(status.source, 'settings_file');
    // Restore: re-enable through the canonical path so later tests
    // (which call processMcpJsonRpcMessage) see an enabled server.
    assert.equal(saveMcpSettings({ enabled: true }).ok, true);
    assert.equal(getMcpServerStatus().enabled, true);
  } finally {
    if (savedEnv !== undefined) process.env.AXONWALL_MCP_ENABLED = savedEnv;
  }
});

test('R4-B-M1: a failed canonical settings write returns ok:false', () => {
  const blocker = path.join(tmpRoot, 'blocker-file-2');
  fs.writeFileSync(blocker, 'not a directory');
  process.env.AXONWALL_MCP_SETTINGS_PATH = path.join(blocker, 'mcp-settings.json');
  try {
    const res = saveMcpSettings({ enabled: true });
    assert.equal(res.ok, false);
    assert.match(res.error || '', /Failed to persist mcp-settings\.json to canonical path/);
  } finally {
    delete process.env.AXONWALL_MCP_SETTINGS_PATH;
  }
});

test('R4-B-M1: canonical helper — corrupt canonical fails closed, missing canonical adopts newest mirror', () => {
  const dir = path.join(tmpRoot, 'canonical-helper');
  fs.mkdirSync(dir, { recursive: true });
  const canonical = path.join(dir, 'cfg.json');
  const mirrorOld = path.join(dir, 'old.json');
  const mirrorNew = path.join(dir, 'new.json');
  const parse = (raw) => {
    try {
      const v = JSON.parse(raw);
      return v && typeof v.value === 'string' ? v : null;
    } catch {
      return null;
    }
  };
  // Missing canonical + two mirrors: newest wins, and is adopted.
  fs.writeFileSync(mirrorOld, JSON.stringify({ value: 'old' }));
  fs.utimesSync(mirrorOld, new Date(Date.now() - 60000), new Date(Date.now() - 60000));
  fs.writeFileSync(mirrorNew, JSON.stringify({ value: 'new' }));
  assert.deepEqual(
    readCanonicalConfig({ canonicalPath: canonical, mirrorPaths: [mirrorOld, mirrorNew], parse, label: 'cfg.json' }),
    { value: 'new' }
  );
  assert.equal(JSON.parse(fs.readFileSync(canonical, 'utf8')).value, 'new');
  // Corrupt canonical: no fallback to the (valid) mirrors.
  fs.writeFileSync(canonical, '{not json');
  assert.equal(
    readCanonicalConfig({ canonicalPath: canonical, mirrorPaths: [mirrorOld, mirrorNew], parse, label: 'cfg.json' }),
    null
  );
  // Canonical write failure throws.
  const blockedDir = path.join(tmpRoot, 'blocker-file-3');
  fs.writeFileSync(blockedDir, 'not a directory');
  assert.throws(
    () =>
      writeCanonicalConfig({
        canonicalPath: path.join(blockedDir, 'cfg.json'),
        mirrorPaths: [],
        serialized: '{}',
        label: 'cfg.json',
      }),
    /Failed to persist cfg\.json to canonical path/
  );
});

// --- R4-B-M2: emergency clear-all checks the XDP step ----------------------
test('R4-B-M2: mcp_emergency_clear_all denies when the XDP clear-all fails', async () => {
  const key = createMcpApiKeyRecord({
    name: 'b-m2-test',
    scopes: ['mcp:firewall:apply'],
    policyLimits: { rateLimitPerMinute: 6000 },
  }).key;
  flushMode = 'ok';
  xdpMode = 'error';
  const denied = await callTool(key, 'mcp_emergency_clear_all', { reason: 'test' });
  assert.equal(denied.success, false);
  assert.match(denied.error, /XDP fast-drop clear-all failed/);
  assert.match(denied.error, /may still be enforced/);

  xdpMode = 'ok';
  const ok = await callTool(key, 'mcp_emergency_clear_all', { reason: 'test' });
  assert.equal(ok.success, true);
  assert.equal(ok.clearedCount, 3);
  assert.equal(ok.xdpCleared, true);
  flushMode = 'ok';
});

// --- R4-B-L1: NAS per-source failures --------------------------------------
test('R4-B-L1: mcp_inspect_nas_storage flags a failed disks source instead of reporting no disks', async () => {
  const key = createMcpApiKeyRecord({
    name: 'b-l1-test',
    scopes: ['mcp:nas:read', 'mcp:telemetry:read'],
    policyLimits: { rateLimitPerMinute: 6000 },
  }).key;
  nasDisksMode = 'error';
  const res = await callTool(key, 'mcp_inspect_nas_storage', {});
  assert.deepEqual(res.disks, []);
  assert.equal(res.partialDaemonFailure, true);
  assert.deepEqual(res.failedSources, ['disks']);
  assert.match(res.error, /unknown, not empty/);
  assert.equal(res.daemonDown, undefined);

  nasDisksMode = 'ok';
  const okRes = await callTool(key, 'mcp_inspect_nas_storage', {});
  assert.equal(okRes.partialDaemonFailure, undefined);
  assert.equal(okRes.failedSources, undefined);
  assert.equal(okRes.disks.length, 1);
});

// --- R4-B-M3: missing COMMAND_ACK ------------------------------------------
test('R4-B-M3: HA-transition/block commands expire in 60s, others in 5 min', () => {
  assert.equal(PENDING_COMMAND_SHORT_STALE_MS, 60 * 1000);
  assert.equal(PENDING_COMMAND_STALE_MS, 5 * 60 * 1000);
  assert.equal(pendingCommandStaleMsFor('PROMOTE'), 60 * 1000);
  assert.equal(pendingCommandStaleMsFor('DEMOTE'), 60 * 1000);
  assert.equal(pendingCommandStaleMsFor('BLOCK_TARGET'), 60 * 1000);
  assert.equal(pendingCommandStaleMsFor('UNBLOCK_TARGET'), 60 * 1000);
  assert.equal(pendingCommandStaleMsFor('SYNC_ROUTES'), 5 * 60 * 1000);
  assert.equal(pendingCommandStaleMsFor('SYNC_HEADSCALE'), 5 * 60 * 1000);
  const sentAt = 1_000_000;
  assert.equal(isPendingCommandStale(sentAt, sentAt + 61_000, pendingCommandStaleMsFor('PROMOTE')), true);
  assert.equal(isPendingCommandStale(sentAt, sentAt + 59_000, pendingCommandStaleMsFor('PROMOTE')), false);
  assert.equal(isPendingCommandStale(sentAt, sentAt + 61_000, pendingCommandStaleMsFor('SYNC_ROUTES')), false);
});

test('R4-B-M3: a missing ack records command, id and wait in lastApplyError, and a later success clears it', () => {
  const state = {};
  const err = missingCommandAckError('PROMOTE', 'cmd_abc123', 1_000_000, 1_061_000);
  assert.match(err, /PROMOTE/);
  assert.match(err, /cmd_abc123/);
  assert.match(err, /no COMMAND_ACK received within 60s/);
  recordCommandAck(state, { command: 'PROMOTE', commandId: 'cmd_abc123', success: false, error: err });
  assert.match(state.lastApplyError, /^PROMOTE: /);
  assert.match(state.lastApplyError, /cmd_abc123/);
  recordCommandAck(state, { command: 'PROMOTE', commandId: 'cmd_abc123', success: true });
  assert.equal(state.lastApplyError, undefined);
});

// --- R4-B-L4: synced-routes persist ----------------------------------------
test('R4-B-L4: persistSyncedRoutes returns true on success and the record round-trips from the canonical path', () => {
  const routes = { 'edge-1': [{ destination: '10.0.0.0/24', gateway: '10.99.0.1' }] };
  assert.equal(persistSyncedRoutes(routes), true);
  assert.deepEqual(loadPersistedSyncedRoutes(), routes);
  // A stale mirror must not win the load.
  fs.writeFileSync(
    path.join(etcDir, 'synced-routes.json'),
    JSON.stringify({ 'edge-1': [{ destination: '192.168.99.0/24', gateway: '10.99.0.9' }] })
  );
  assert.deepEqual(loadPersistedSyncedRoutes(), routes);
});

test('R4-B-L4: persistSyncedRoutes returns false (loudly) when the canonical write fails', () => {
  const blocker = path.join(tmpRoot, 'blocker-file-4');
  fs.writeFileSync(blocker, 'not a directory');
  const prev = process.env.AXONWALL_SYNCED_ROUTES_PATH;
  process.env.AXONWALL_SYNCED_ROUTES_PATH = path.join(blocker, 'synced-routes.json');
  try {
    assert.equal(persistSyncedRoutes({ 'edge-1': [] }), false);
  } finally {
    if (prev === undefined) delete process.env.AXONWALL_SYNCED_ROUTES_PATH;
    else process.env.AXONWALL_SYNCED_ROUTES_PATH = prev;
  }
});

// --- R4-B-L2: rate-limit budget survives across processes -------------------
test('R4-B-L2: a fresh stdio process sees the previous process budget (disk-backed)', async () => {
  const created = createMcpApiKeyRecord({
    name: 'b-l2-test',
    scopes: ['mcp:telemetry:read'],
    policyLimits: { rateLimitPerMinute: 2 },
  });
  assert.equal(authenticateMcpToken(created.rawToken, '127.0.0.1').authenticated, true);
  assert.equal(authenticateMcpToken(created.rawToken, '127.0.0.1').authenticated, true);
  const third = authenticateMcpToken(created.rawToken, '127.0.0.1');
  assert.equal(third.authenticated, false);
  assert.equal(third.errorStatus, 429);

  // The budget was persisted: the state file holds this key's stamps.
  const state = JSON.parse(fs.readFileSync(rateLimitPath, 'utf8'));
  assert.ok(Array.isArray(state[created.key.id]) && state[created.key.id].length >= 2);

  // A brand-new process must NOT get a fresh budget.
  const probe = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.resolve(import.meta.dirname, 'rate-limit-probe.mjs'), created.rawToken, '1'], {
      env: {
        ...process.env,
        AXONWALL_MCP_KEYS_PATH: keysPath,
        AXONWALL_MCP_RATE_LIMIT_PATH: rateLimitPath,
        AXONWALL_MCP_ENABLED: 'true',
      },
    });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.on('error', reject);
    child.on('close', () => resolve(out.trim()));
  });
  assert.match(probe, /^DENIED 429/, `fresh process must inherit the exhausted budget, got: ${probe}`);
});

// --- R4-B-M4: axonwallctl update always passes a version -------------------
test('R4-B-M4: bare update resolves the installed version from the daemon and passes it on', async () => {
  statusVersion = '0.12.3';
  lastUpdateBody = null;
  const res = await runCli(['update']);
  assert.equal(res.status, 0, `stdout: ${res.stdout}\nstderr: ${res.stderr}`);
  assert.ok(lastUpdateBody, 'daemon /v1/system/update must have been called');
  assert.equal(lastUpdateBody.version, '0.12.3');
});

test('R4-B-M4: an explicit --version wins over the daemon and file versions', async () => {
  statusVersion = '0.12.3';
  fs.writeFileSync(path.join(etcDir, 'version'), '0.11.0\n');
  lastUpdateBody = null;
  const res = await runCli(['update', '--version', '9.9.9']);
  assert.equal(res.status, 0, `stdout: ${res.stdout}\nstderr: ${res.stderr}`);
  assert.equal(lastUpdateBody.version, '9.9.9');
  fs.rmSync(path.join(etcDir, 'version'));
});

test('R4-B-M4: with no daemon version, the version file is the fallback', async () => {
  statusVersion = undefined;
  fs.writeFileSync(path.join(etcDir, 'version'), '0.11.0\n');
  lastUpdateBody = null;
  const res = await runCli(['update']);
  assert.equal(res.status, 0, `stdout: ${res.stdout}\nstderr: ${res.stderr}`);
  assert.equal(lastUpdateBody.version, '0.11.0');
  fs.rmSync(path.join(etcDir, 'version'));
  statusVersion = '0.12.3';
});

test('R4-B-M4: with no version anywhere, update fails closed instead of invoking the updater version-less', async () => {
  // No daemon socket: point the CLI at a socket that does not exist.
  const res = await runCli(['update'], { AXONWALL_AGENT_API_SOCK: path.join(tmpRoot, 'no-such.sock') });
  assert.notEqual(res.status, 0);
  assert.match(res.stderr + res.stdout, /--version/);
});

// --- R4-B-L6: live-but-slow lock holder ------------------------------------
test('R4-B-L6: a live holder past the stale threshold is NOT broken (waiter times out)', async () => {
  const lockPath = path.join(tmpRoot, 'round4-lock.json.lock');
  process.env.AXONWALL_DESIRED_STATE_LOCK_PATH = lockPath;
  const holder = spawn(process.execPath, [path.resolve(import.meta.dirname, 'hold-mcp-lock-round4.mjs')], {
    env: { ...process.env, AXONWALL_DESIRED_STATE_LOCK_PATH: lockPath, HOLD_MS: '13000' },
  });
  let holderOut = '';
  holder.stdout.on('data', (d) => { holderOut += d; });
  try {
    await new Promise((resolve) => {
      const iv = setInterval(() => {
        if (holderOut.includes('holding')) { clearInterval(iv); resolve(); }
      }, 50);
    });
    const t0 = Date.now();
    // The stale threshold at a 12 s timeout is 10 s; a pre-fix
    // waiter would break the lock at ~10 s. The holder lives for
    // 13 s, so the waiter must time out at 12 s instead.
    assert.throws(() => acquireMcpLockFile(lockPath, 12000), /timed out waiting for lock/);
    const dt = Date.now() - t0;
    assert.ok(dt >= 11500, `waiter must wait out its full timeout (waited ${dt}ms)`);
  } finally {
    holder.kill('SIGTERM');
    await new Promise((r) => holder.on('close', r));
    delete process.env.AXONWALL_DESIRED_STATE_LOCK_PATH;
  }
});

test('R4-B-L6: a dead holder lock is still broken promptly', async () => {
  const lockPath = path.join(tmpRoot, 'dead-lock.json.lock');
  fs.writeFileSync(
    lockPath,
    JSON.stringify({ pid: 987654, createdAt: new Date(Date.now() - 60000).toISOString(), token: 'dead:1:abc' })
  );
  const old = new Date(Date.now() - 60000);
  fs.utimesSync(lockPath, old, old);
  const t0 = Date.now();
  const release = acquireMcpLockFile(lockPath, 10000);
  const dt = Date.now() - t0;
  assert.ok(dt < 2000, `dead-holder break must be fast (took ${dt}ms)`);
  release();
  assert.equal(fs.existsSync(lockPath), false);
});

test('R4-B-L6: normal acquire/release still works and removes the lockfile', () => {
  const lockPath = path.join(tmpRoot, 'normal-lock.json.lock');
  const release = acquireMcpLockFile(lockPath, 5000);
  assert.equal(fs.existsSync(lockPath), true);
  release();
  assert.equal(fs.existsSync(lockPath), false);
});
