import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-mcp-test-'));
process.env.AXONWALL_MCP_KEYS_PATH = path.join(tmpDir, 'mcp-keys.json');
process.env.AXONWALL_MCP_AUDIT_PATH = path.join(tmpDir, 'mcp-audit.jsonl');
process.env.AXONWALL_AGENT_API_SOCK = path.join(tmpDir, 'nonexistent-agent.sock');

const {
  createMcpApiKeyRecord,
  authenticateMcpToken,
  verifyMcpAuditChain,
  processMcpJsonRpcMessage,
} = await import('../dist/index.js');

test('MCP AuthZ, Blast-Radius Guardrails & Hash-Chained Audit Verification', async () => {
  // 1. Provision a scoped VigilSOC key restricted to 10.42.0.0/16 and honeypot 10.99.0.10:2222
  const { rawToken, key } = createMcpApiKeyRecord({
    name: 'VigilSOC Test Agent',
    agentType: 'vigilsoc',
    scopes: ['mcp:telemetry:read', 'mcp:traffic:blackhole', 'mcp:traffic:redirect'],
    allowedSourceCidrs: ['10.42.0.0/16'],
    policyLimits: {
      maxIpv4PrefixLen: 24,
      maxIpv6PrefixLen: 64,
      allowedRedirectTargets: ['10.99.0.10:2222'],
    },
  });

  assert.ok(rawToken.startsWith('axw_mcp_'));
  assert.equal(key.name, 'VigilSOC Test Agent');

  // 2. Reject connection from unauthorized source IP
  const badIpAuth = authenticateMcpToken(rawToken, '192.168.99.99');
  assert.equal(badIpAuth.authenticated, false);
  assert.equal(badIpAuth.errorStatus, 403);

  // 3. Accept connection from allowed source CIDR
  const goodAuth = authenticateMcpToken(rawToken, '10.42.1.25');
  assert.equal(goodAuth.authenticated, true);
  assert.ok(goodAuth.key);

  const env = { key: goodAuth.key, clientIp: '10.42.1.25' };

  // 4. Reject tool call when scope is missing (mcp:traffic:shape not granted)
  const deniedShape = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'mcp_shape_traffic',
        arguments: {
          target: '198.51.100.20',
          rateKbps: 64,
          audit: { reason: 'Throttle suspected exfiltration host' },
        },
      },
    },
    env
  );
  assert.equal(deniedShape?.result?.isError, true);

  // 5. Reject blackhole targeting caller's own IP (10.42.1.25)
  const deniedSelf = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'mcp_blackhole_traffic',
        arguments: {
          target: '10.42.1.25',
          audit: { reason: 'Attempt to block own MCP agent IP' },
        },
      },
    },
    env
  );
  assert.equal(deniedSelf?.result?.isError, true);

  // 6. Allow valid tactical blackhole of external C2 IP
  const allowedBlackhole = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'mcp_blackhole_traffic',
        arguments: {
          target: '198.51.100.88',
          mode: 'nft_drop',
          ttlSeconds: 1800,
          audit: {
            reason: 'Confirmed Cobalt Strike C2 beacon destination',
            incidentId: 'INC-2026-901',
            mitreTechniqueId: 'T1071.001',
          },
        },
      },
    },
    env
  );
  assert.ok(!allowedBlackhole?.result?.isError);
  const blackholePayload = JSON.parse(allowedBlackhole.result.content[0].text);
  assert.equal(blackholePayload.success, true);
  assert.ok(blackholePayload.lease.id.startsWith('mcp_lease_'));

  // 7. Verify SHA-256 hash-chained audit log integrity
  const chainStatus = verifyMcpAuditChain();
  assert.equal(chainStatus.valid, true);
  assert.equal(chainStatus.totalEntries, 3);
});
