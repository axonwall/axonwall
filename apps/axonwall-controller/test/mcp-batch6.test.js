import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import * as tls from 'node:tls';
import { execSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Batch 6 regression tests: B-S1, B-S2, B-L2, B-L4.
//
// Env vars are set before the dynamic dist imports below (the
// pattern used by mcp.test.js): controller module constants such as
// the MCP keys/audit paths and HEADSCALE_BIN are read at import
// time, so a static import would be too late.
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-batch6-test-'));
const keysPath = path.join(tmpDir, 'mcp-keys.json');
const auditPath = path.join(tmpDir, 'mcp-audit.jsonl');
process.env.AXONWALL_MCP_KEYS_PATH = keysPath;
process.env.AXONWALL_MCP_AUDIT_PATH = auditPath;
process.env.AXONWALL_AGENT_API_SOCK = path.join(tmpDir, 'nonexistent-agent.sock');
process.env.AXONWALL_MCP_ENABLED = 'true';

// Fake headscale CLI emitting the shapes the real CLI emits:
// camelCase RFC3339 strings (see the B-L4 note in headscale.ts).
const sockPath = path.join(tmpDir, 'headscale.sock');
fs.writeFileSync(sockPath, '');
process.env.HEADSCALE_SOCKET_PATH = sockPath;
const fakeBin = path.join(tmpDir, 'headscale');
fs.writeFileSync(
  fakeBin,
  `#!/usr/bin/env node
const args = process.argv.slice(2);
let i = 0;
if (args[0] === '--config') i = 2;
const rest = args.slice(i);
const out = (o) => process.stdout.write(JSON.stringify(o));
if (rest[0] === 'users' && rest[1] === 'list') {
  out([{ id: 1, name: 'alice', createdAt: '2026-01-02T03:04:05Z' }]);
} else if (rest[0] === 'preauthkeys' && rest[1] === 'create') {
  out({ id: 'k1', key: 'hskey-test', reusable: false, ephemeral: false, expiration: '2026-12-31T23:59:59Z', user: { id: 1, name: 'alice' } });
} else if (rest[0] === 'preauthkeys' && rest[1] === 'list') {
  out([{ id: 'k1', key: 'hskey-test', reusable: false, ephemeral: false, used: false, expiration: '2026-12-31T23:59:59Z', createdAt: '2026-01-02T03:04:05Z', user: { id: 1 } }]);
} else if (rest[0] === 'nodes' && rest[1] === 'list') {
  out([{ id: 'n1', given_name: 'node1', ip_addresses: ['100.64.0.1'], user: { id: 1, name: 'alice' }, lastSeen: '2026-02-03T04:05:06Z', online: true, approved_routes: [] }]);
} else {
  process.stdout.write('null');
}
`
);
fs.chmodSync(fakeBin, 0o755);
process.env.HEADSCALE_BIN = fakeBin;

const {
  createMcpApiKeyRecord,
  authenticateMcpToken,
  recordMcpAuditEntry,
  verifyMcpAuditChain,
  createPortMultiplexer,
  createHttpRedirectServer,
} = await import('../dist/index.js');
const { listUsers, createPreAuthKey, listPreAuthKeys, listMachines, parseHeadscaleTimestamp } =
  await import('../dist/headscale.js');

// ------------------------------------------------------------------
// B-S1: authentication must not rewrite the keys file.
// ------------------------------------------------------------------
test('B-S1: authenticateMcpToken leaves mcp-keys.json byte-identical and records last-used in the sidecar', () => {
  const { rawToken, key } = createMcpApiKeyRecord({
    name: 'Batch6 S1',
    agentType: 'vigilsoc',
    scopes: ['mcp:telemetry:read'],
    allowedSourceCidrs: ['10.42.0.0/16'],
  });
  const before = fs.readFileSync(keysPath, 'utf8');
  const auth = authenticateMcpToken(rawToken, '10.42.0.5');
  assert.equal(auth.authenticated, true);
  // Pre-fix, authentication rewrote the whole keys file (updating
  // lastUsedAt in place). A concurrent revocation landing between
  // the auth's load and its save was then resurrected. Post-fix,
  // authentication never touches the keys file, so a revocation
  // cannot be lost this way.
  assert.equal(fs.readFileSync(keysPath, 'utf8'), before);
  const sidecar = JSON.parse(fs.readFileSync(`${keysPath}.lastused.json`, 'utf8'));
  assert.ok(sidecar[key.id], 'sidecar should carry an entry for the key');
  assert.ok(sidecar[key.id].lastUsedAt, 'sidecar should carry lastUsedAt');
  assert.equal(sidecar[key.id].lastUsedIp, '10.42.0.5');
});

// ------------------------------------------------------------------
// B-S2: concurrent audit writers must not fork the hash chain.
// ------------------------------------------------------------------
test('B-S2: parallel audit writers produce a valid chain with every entry', async () => {
  const distIndex = fileURLToPath(new URL('../dist/index.js', import.meta.url));
  const workerPath = path.join(tmpDir, 'audit-worker.mjs');
  fs.writeFileSync(
    workerPath,
    `const { recordMcpAuditEntry } = await import(${JSON.stringify(distIndex)});
for (let i = 0; i < 20; i++) {
  recordMcpAuditEntry({
    keyId: 'k-' + process.argv[2],
    keyName: 'worker-' + process.argv[2],
    agentType: 'vigilsoc',
    clientIp: '10.42.0.1',
    toolName: 'telemetry.read',
    requiredScope: 'mcp:telemetry:read',
    decision: 'allowed',
    paramsSummary: 'entry-' + process.argv[2] + '-' + i,
  });
}
`
  );
  const workers = 6;
  await Promise.all(
    Array.from({ length: workers }, (_, w) =>
      new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [workerPath, String(w)], {
          env: { ...process.env, AXONWALL_MCP_AUDIT_PATH: auditPath },
          stdio: 'inherit',
        });
        child.on('error', reject);
        child.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`worker ${w} exited ${code}`))));
      })
    )
  );
  const chain = verifyMcpAuditChain();
  assert.equal(chain.valid, true, `audit chain must verify; got ${JSON.stringify(chain)}`);
  assert.equal(chain.totalEntries, workers * 20, 'every concurrently written entry must be present exactly once');
});

// ------------------------------------------------------------------
// B-L2: handshake deadline survives the first byte.
// ------------------------------------------------------------------
function makeCertPair(dir) {
  const keyPath = path.join(dir, 'key.pem');
  const certPath = path.join(dir, 'cert.pem');
  execSync(`openssl req -x509 -newkey rsa:2048 -keyout ${keyPath} -out ${certPath} -days 1 -nodes -subj "/CN=localhost"`);
  return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
}

test('B-L2: a client that sends one TLS byte then stalls is destroyed after the handshake deadline', async (t) => {
  const { key, cert } = makeCertPair(tmpDir);
  const httpsServer = https.createServer({ cert, key }, (_req, res) => res.end('{}'));
  const redirectServer = createHttpRedirectServer(2966);
  const multiplexer = createPortMultiplexer(httpsServer, redirectServer, { handshakeTimeoutMs: 300 });
  await new Promise((resolve) => multiplexer.listen(0, '127.0.0.1', resolve));
  const port = multiplexer.address().port;
  t.after(() => {
    if (typeof httpsServer.closeAllConnections === 'function') httpsServer.closeAllConnections();
    if (typeof redirectServer.closeAllConnections === 'function') redirectServer.closeAllConnections();
    multiplexer.close();
    httpsServer.close();
    redirectServer.close();
  });
  const client = net.connect(port, '127.0.0.1');
  t.after(() => client.destroy());
  await new Promise((resolve) => client.once('connect', resolve));
  client.write(Buffer.from([0x16])); // one TLS byte, then stall forever
  const closed = await Promise.race([
    new Promise((resolve) => client.once('close', () => resolve(true))),
    new Promise((resolve) => setTimeout(() => resolve(false), 3000)),
  ]);
  // Pre-fix, the 5s pre-handshake timeout was cleared on the first
  // byte, so this socket was never destroyed and the test times out.
  assert.equal(closed, true, 'stalled post-first-byte connection must be destroyed by the handshake deadline');
});

test('B-L2: a completed TLS handshake is NOT destroyed by the handshake deadline', async (t) => {
  const { key, cert } = makeCertPair(tmpDir);
  const httpsServer = https.createServer({ cert, key }, (_req, res) => res.end('{}'));
  const redirectServer = createHttpRedirectServer(2966);
  const multiplexer = createPortMultiplexer(httpsServer, redirectServer, { handshakeTimeoutMs: 300 });
  await new Promise((resolve) => multiplexer.listen(0, '127.0.0.1', resolve));
  const port = multiplexer.address().port;
  t.after(() => {
    if (typeof httpsServer.closeAllConnections === 'function') httpsServer.closeAllConnections();
    if (typeof redirectServer.closeAllConnections === 'function') redirectServer.closeAllConnections();
    multiplexer.close();
    httpsServer.close();
    redirectServer.close();
  });
  const client = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false });
  t.after(() => client.destroy());
  await new Promise((resolve, reject) => {
    client.once('secureConnect', resolve);
    client.once('error', reject);
  });
  // Idle well past the deadline: a completed handshake must survive.
  await new Promise((resolve) => setTimeout(resolve, 1000));
  assert.equal(client.destroyed, false, 'idle post-handshake connection must survive the deadline');
});

// ------------------------------------------------------------------
// B-L4: headscale timestamps are parsed polymorphically.
// ------------------------------------------------------------------
test('B-L4: parseHeadscaleTimestamp accepts {seconds}, RFC3339, and numeric epochs', () => {
  assert.equal(parseHeadscaleTimestamp({ seconds: 1767225600 }), '2026-01-01T00:00:00.000Z');
  assert.equal(parseHeadscaleTimestamp({ seconds: '1767225600' }), '2026-01-01T00:00:00.000Z');
  assert.equal(parseHeadscaleTimestamp('2026-01-02T03:04:05Z'), '2026-01-02T03:04:05.000Z');
  assert.equal(parseHeadscaleTimestamp(1767225600), '2026-01-01T00:00:00.000Z');
  assert.equal(parseHeadscaleTimestamp(1767225600000), '2026-01-01T00:00:00.000Z');
  assert.equal(parseHeadscaleTimestamp(null), undefined);
  assert.equal(parseHeadscaleTimestamp('not-a-date'), undefined);
  assert.equal(parseHeadscaleTimestamp({}), undefined);
});

test('B-L4: headscale list functions use the camelCase RFC3339 timestamps the CLI actually emits', async () => {
  const users = await listUsers();
  assert.equal(users[0].createdAt, '2026-01-02T03:04:05.000Z');
  // Pre-fix, createPreAuthKey read .seconds off the truthy RFC3339
  // string and collapsed the expiration to epoch 1970.
  const created = await createPreAuthKey(1, false, false);
  assert.equal(created.expiration, '2026-12-31T23:59:59.000Z');
  const listed = await listPreAuthKeys();
  assert.equal(listed[0].expiration, '2026-12-31T23:59:59.000Z');
  assert.equal(listed[0].createdAt, '2026-01-02T03:04:05.000Z');
  const machines = await listMachines();
  assert.equal(machines[0].lastSeen, '2026-02-03T04:05:06.000Z');
});
