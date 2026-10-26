import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-mcp-test-'));
process.env.AXONWALL_MCP_KEYS_PATH = path.join(tmpDir, 'mcp-keys.json');
process.env.AXONWALL_MCP_AUDIT_PATH = path.join(tmpDir, 'mcp-audit.jsonl');
process.env.AXONWALL_AGENT_API_SOCK = path.join(tmpDir, 'nonexistent-agent.sock');
process.env.AXONWALL_MCP_ENABLED = 'true';

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

test('MCP Master Kill-Switch / Disable Subsystem Verification (Disabled by Default)', async () => {
  const {
    createMcpApiKeyRecord,
    authenticateMcpToken,
    processMcpJsonRpcMessage,
    isMcpServerEnabled,
  } = await import('../dist/index.js');

  const { rawToken } = createMcpApiKeyRecord({
    name: 'KillSwitch Agent',
    scopes: ['mcp:telemetry:read'],
  });

  // 1. Verify disabled by default without env vars or settings file
  delete process.env.AXONWALL_MCP_ENABLED;
  delete process.env.AXONWALL_DISABLE_MCP;
  delete process.env.AXONWALL_MCP_SETTINGS_PATH;

  assert.equal(isMcpServerEnabled(), false);

  const authDefault = authenticateMcpToken(rawToken, '127.0.0.1');
  assert.equal(authDefault.authenticated, false);
  assert.equal(authDefault.errorStatus, 503);
  assert.ok(authDefault.errorMessage?.toLowerCase().includes('disabled by default'));

  // 2. Explicitly enable via environment variable AXONWALL_MCP_ENABLED=true
  process.env.AXONWALL_MCP_ENABLED = 'true';
  assert.equal(isMcpServerEnabled(), true);

  const authEnv = authenticateMcpToken(rawToken, '127.0.0.1');
  assert.equal(authEnv.authenticated, true);

  // 3. Disable via environment variable AXONWALL_MCP_ENABLED=false
  process.env.AXONWALL_MCP_ENABLED = 'false';
  assert.equal(isMcpServerEnabled(), false);

  const disabledAuthEnv = authenticateMcpToken(rawToken, '127.0.0.1');
  assert.equal(disabledAuthEnv.authenticated, false);
  assert.equal(disabledAuthEnv.errorStatus, 503);
  assert.ok(disabledAuthEnv.errorMessage?.toLowerCase().includes('disabled'));

  // JSON-RPC message rejected when disabled
  const rpcRespEnv = await processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id: 10, method: 'tools/list', params: {} },
    { key: authEnv.key, clientIp: '127.0.0.1' }
  );
  assert.ok(rpcRespEnv?.error);
  assert.equal(rpcRespEnv.error.code, -32000);
  assert.ok(rpcRespEnv.error.message.toLowerCase().includes('disabled'));

  delete process.env.AXONWALL_MCP_ENABLED;

  // 4. Disable via AXONWALL_DISABLE_MCP=1
  process.env.AXONWALL_DISABLE_MCP = '1';
  assert.equal(isMcpServerEnabled(), false);

  const disabledAuthKill = authenticateMcpToken(rawToken, '127.0.0.1');
  assert.equal(disabledAuthKill.authenticated, false);
  assert.equal(disabledAuthKill.errorStatus, 503);

  delete process.env.AXONWALL_DISABLE_MCP;

  // 5. Explicitly enable and disable via persistent configuration file
  const settingsFile = path.join(tmpDir, 'mcp-settings.json');
  process.env.AXONWALL_MCP_SETTINGS_PATH = settingsFile;

  // Explicitly enable via file
  fs.writeFileSync(settingsFile, JSON.stringify({ enabled: true }));
  assert.equal(isMcpServerEnabled(), true);

  const reEnabledAuth = authenticateMcpToken(rawToken, '127.0.0.1');
  assert.equal(reEnabledAuth.authenticated, true);

  // Explicitly disable via file
  fs.writeFileSync(settingsFile, JSON.stringify({
    enabled: false,
    disabledReason: 'Emergency maintenance lockdown',
    disabledAt: new Date().toISOString(),
    disabledBy: 'secops-admin',
  }));

  assert.equal(isMcpServerEnabled(), false);

  const disabledAuthFile = authenticateMcpToken(rawToken, '127.0.0.1');
  assert.equal(disabledAuthFile.authenticated, false);
  assert.equal(disabledAuthFile.errorStatus, 503);
  assert.ok(disabledAuthFile.errorMessage?.includes('Emergency maintenance lockdown'));

  delete process.env.AXONWALL_MCP_SETTINGS_PATH;
});

