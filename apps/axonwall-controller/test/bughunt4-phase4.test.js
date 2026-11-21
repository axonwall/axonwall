import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-bh4-ctrl-'));
const varDir = path.join(tmpRoot, 'var');
const etcDir = path.join(tmpRoot, 'etc');
const persistDir = path.join(tmpRoot, 'persist');
const runDir = path.join(tmpRoot, 'run');
for (const d of [varDir, etcDir, persistDir, runDir]) {
  fs.mkdirSync(d, { recursive: true });
}

const statePath = path.join(varDir, 'state.json');
fs.writeFileSync(
  statePath,
  JSON.stringify(
    {
      version: 1,
      interfaces: [
        { name: 'wan', device: 'eth0', role: 'wan', type: 'dhcp', enabled: true },
        { name: 'lan', device: 'eth1', role: 'lan', type: 'static', ipv4Address: '192.168.1.1', enabled: true },
      ],
      rules: [],
      nat: [],
      dns: { enabled: true },
      dhcp: { enabled: false },
      system: { hostname: 'fw', domain: 'local' },
      mcp: { enabled: true },
    },
    null,
    2
  )
);

process.env.AXONWALL_VAR_DIR = varDir;
process.env.AXONWALL_ETC_DIR = etcDir;
process.env.AXONWALL_PERSIST_YAML_DIR = persistDir;
process.env.AXONWALL_STATE_JSON_PATH = statePath;
process.env.AXONWALL_DESIRED_STATE_LOCK_PATH = path.join(runDir, 'state.json.lock');
process.env.AXONWALL_MCP_KEYS_PATH = path.join(varDir, 'mcp-keys.json');
process.env.AXONWALL_MCP_AUDIT_PATH = path.join(varDir, 'mcp-audit.jsonl');
process.env.AXONWALL_MCP_RATE_LIMIT_PATH = path.join(varDir, 'mcp-rate-limits.json');
process.env.AXONWALL_MCP_SETTINGS_PATH = path.join(varDir, 'mcp-settings.json');
process.env.AXONWALL_MCP_ENABLED = 'true';
process.env.AXONWALL_AGENT_API_SOCK = path.join(runDir, 'agent-api.sock');

const {
  authenticateMcpToken,
  createMcpApiKeyRecord,
  processMcpJsonRpcMessage,
  queryMcpAuditEntries,
  acquireMcpLockFile,
} = await import('../dist/index.js');

const { McpRenderK3sBpfTokenRequestSchema } = await import('@axonwall/lib/mcp');

test('Phase4: C-C3 redacts sensitive keyMaterial in denied MCP audit entries', async () => {
  const { key } = createMcpApiKeyRecord({
    name: 'nas-ro-audit-test',
    agentType: 'vigilsoc',
    scopes: ['mcp:telemetry:read'],
    allowedSourceCidrs: ['127.0.0.1/32'],
    policyLimits: { rateLimitPerMinute: 60 },
  });

  const resp = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'mcp_nas_snapshot_or_scrub',
        arguments: {
          action: 'unlock_dataset',
          target: 'tank/secrets',
          keyMaterial: 'super-secret-zfs-passphrase-123',
        },
      },
    },
    { key, clientIp: '127.0.0.1' }
  );
  assert.equal(resp?.result?.isError, true);

  const entries = queryMcpAuditEntries(10);
  const serialized = JSON.stringify(entries);
  assert.equal(serialized.includes('super-secret-zfs-passphrase-123'), false, 'raw keyMaterial must never land in audit log');
});

test('Phase4: C-H8 blocks 0.0.0.0/0 and 1-65535 unscoped WAN pass rules & C-H5 catches HTTP 200 success:false apply rejections', async (t) => {
  const server = http.createServer((req, res) => {
    if (req.url === '/v1/apply' && req.method === 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, message: 'nftables syntax validation failed: bad rule' }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise((resolve) => server.listen(process.env.AXONWALL_AGENT_API_SOCK, resolve));
  t.after(() => server.close());

  const { key } = createMcpApiKeyRecord({
    name: 'fw-admin-test',
    agentType: 'vigilsoc',
    scopes: ['mcp:firewall:write', 'mcp:firewall:apply'],
    allowedSourceCidrs: ['127.0.0.1/32'],
    policyLimits: { rateLimitPerMinute: 60 },
  });

  const wildcardBypass = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'mcp_propose_firewall_rule',
        arguments: {
          rule: {
            interface: 'wan',
            action: 'pass',
            protocol: 'tcp',
            source: '0.0.0.0/0',
            destination: '0.0.0.0/0',
            destinationPort: '1-65535',
            description: 'wildcard-bypass',
          },
          applyImmediately: false,
          audit: { reason: 'test wildcard pass rejection' },
        },
      },
    },
    { key, clientIp: '127.0.0.1' }
  );
  assert.equal(wildcardBypass?.result?.isError, true, 'C-H8: 0.0.0.0/0 + 1-65535 WAN pass rule must be rejected');

  const http200Fail = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'mcp_propose_firewall_rule',
        arguments: {
          rule: {
            interface: 'lan',
            action: 'pass',
            protocol: 'tcp',
            source: '192.168.1.50/32',
            destination: '10.0.0.10/32',
            destinationPort: '443',
            description: 'should-rollback-on-200-false',
          },
          applyImmediately: true,
          confirmTimeoutSeconds: 60,
          audit: { reason: 'test HTTP 200 success:false rollback' },
        },
      },
    },
    { key, clientIp: '127.0.0.1' }
  );
  assert.equal(http200Fail?.result?.isError, true, 'C-H5: HTTP 200 success:false must error');
  assert.match(http200Fail.result.content[0].text, /nftables syntax validation failed/);
  const persisted = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  assert.equal(persisted.rules.length, 0, 'C-H5: rejected rule must be rolled back from state.json');
});

test('Phase4: C-M5 rejects newline/YAML injection in K3s BPF render schema', () => {
  const bad = McpRenderK3sBpfTokenRequestSchema.safeParse({
    profileId: 'k3s-net-dataplane',
    workloadName: 'bad-name',
    namespace: 'default',
    image: 'busybox\n          securityContext:\n            privileged: true',
  });
  assert.equal(bad.success, false, 'C-M5: multiline image injection must fail schema');
});

test('Phase4: C-M6 fails closed in mcp_revert_lease when /v1/mcp/leases fetch fails', async (t) => {
  let revertCalled = false;
  try { fs.unlinkSync(process.env.AXONWALL_AGENT_API_SOCK); } catch {}
  const server = http.createServer((req, res) => {
    if (req.url === '/v1/mcp/leases') {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'internal error' }));
      return;
    }
    if (req.url === '/v1/mcp/revert') {
      revertCalled = true;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
  });
  await new Promise((resolve) => server.listen(process.env.AXONWALL_AGENT_API_SOCK, resolve));
  t.after(() => server.close());

  const { key } = createMcpApiKeyRecord({
    name: 'shape-only-key',
    agentType: 'vigilsoc',
    scopes: ['mcp:traffic:shape'],
    allowedSourceCidrs: ['127.0.0.1/32'],
    policyLimits: { rateLimitPerMinute: 60 },
  });

  const resp = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: {
        name: 'mcp_revert_lease',
        arguments: { leaseId: 'blackhole-lease-1', reason: 'cross-scope test' },
      },
    },
    { key, clientIp: '127.0.0.1' }
  );
  assert.equal(resp?.result?.isError, true, 'C-M6: must deny when lease scope cannot be verified');
  assert.equal(revertCalled, false, 'C-M6: /v1/mcp/revert must not be called when /v1/mcp/leases failed');
});

test('Phase4: C-M9 preserves same-ms burst counts & C-L1 immediately reclaims dead-PID locks', () => {
  const { rawToken } = createMcpApiKeyRecord({
    name: 'burst-limit-key',
    agentType: 'vigilsoc',
    scopes: ['mcp:telemetry:read'],
    allowedSourceCidrs: ['127.0.0.1/32'],
    policyLimits: { rateLimitPerMinute: 2 },
  });
  assert.equal(authenticateMcpToken(rawToken, '127.0.0.1').authenticated, true);
  assert.equal(authenticateMcpToken(rawToken, '127.0.0.1').authenticated, true);
  assert.equal(authenticateMcpToken(rawToken, '127.0.0.1').authenticated, false, '3rd burst call within same ms must fail');

  // C-L1: dead non-self PID lock is immediately broken without waiting mtime stale threshold
  const lockPath = path.join(runDir, 'dead-pid.lock');
  fs.writeFileSync(lockPath, JSON.stringify({ pid: 99999999, createdAt: Date.now() }));
  const t0 = Date.now();
  const rel = acquireMcpLockFile(lockPath, 1500);
  const elapsed = Date.now() - t0;
  rel();
  assert.ok(elapsed < 500, `C-L1: expected immediate dead-PID lock break, took ${elapsed}ms`);
});

test('cleanup temp root', () => {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});
