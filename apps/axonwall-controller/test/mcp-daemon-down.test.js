import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// B-H5: with axonwalld unreachable (socket file absent), every tactical MCP
// tool must deny — never fabricate a lease id, never report success.
// This is the controller side of the A-M13 family: the daemon side is
// covered by the Go engine tests.
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-mcp-daemon-down-'));
process.env.AXONWALL_MCP_KEYS_PATH = path.join(tmpDir, 'mcp-keys.json');
process.env.AXONWALL_MCP_AUDIT_PATH = path.join(tmpDir, 'mcp-audit.jsonl');
process.env.AXONWALL_AGENT_API_SOCK = path.join(tmpDir, 'nonexistent-agent.sock');
process.env.AXONWALL_MCP_ENABLED = 'true';

const { createMcpApiKeyRecord, authenticateMcpToken, processMcpJsonRpcMessage } = await import(
  '../dist/index.js'
);

test('MCP tactical tools deny (never fabricate success) when axonwalld is down', async () => {
  const { rawToken } = createMcpApiKeyRecord({
    name: 'DaemonDown Test Agent',
    agentType: 'vigilsoc',
    scopes: [
      'mcp:traffic:blackhole',
      'mcp:traffic:shape',
      'mcp:traffic:redirect',
      'mcp:firewall:apply',
    ],
    allowedSourceCidrs: ['10.42.0.0/16'],
    policyLimits: {
      maxIpv4PrefixLen: 24,
      maxIpv6PrefixLen: 64,
      allowedRedirectTargets: ['10.99.0.10:2222'],
    },
  });

  const auth = authenticateMcpToken(rawToken, '10.42.1.25');
  assert.equal(auth.authenticated, true);
  const env = { key: auth.key, clientIp: '10.42.1.25' };

  const calls = [
    {
      name: 'mcp_blackhole_traffic',
      arguments: {
        target: '198.51.100.20',
        mode: 'nft_drop',
        ttlSeconds: 1800,
        audit: { reason: 'Daemon-down regression probe' },
      },
    },
    {
      name: 'mcp_shape_traffic',
      arguments: {
        target: '198.51.100.20',
        rateKbps: 64,
        audit: { reason: 'Daemon-down regression probe' },
      },
    },
    {
      name: 'mcp_redirect_traffic',
      arguments: {
        source: '198.51.100.20',
        targetDestination: '10.99.0.10:2222',
        ttlSeconds: 1800,
        audit: { reason: 'Daemon-down regression probe' },
      },
    },
    {
      name: 'mcp_sinkhole_dns',
      arguments: {
        domain: 'c2.badactor.example',
        sinkholeIp: '0.0.0.0',
        ttlSeconds: 3600,
        audit: { reason: 'Daemon-down regression probe' },
      },
    },
    {
      name: 'mcp_revert_lease',
      arguments: { leaseId: 'mcp_lease_doesnotexist', reason: 'Daemon-down regression probe' },
    },
    {
      name: 'mcp_emergency_clear_all',
      arguments: { reason: 'Daemon-down regression probe' },
    },
  ];

  for (let i = 0; i < calls.length; i++) {
    const res = await processMcpJsonRpcMessage(
      {
        jsonrpc: '2.0',
        id: i + 1,
        method: 'tools/call',
        params: calls[i],
      },
      env
    );
    assert.equal(res?.result?.isError, true, `${calls[i].name} must deny when the daemon is down`);
    const text = res.result.content[0].text;
    const payload = JSON.parse(text);
    assert.equal(payload.success, false, `${calls[i].name} must not report success`);
    assert.ok(
      !text.includes('mcp_lease_'),
      `${calls[i].name} must not fabricate a lease id, got: ${text}`
    );
  }
});
