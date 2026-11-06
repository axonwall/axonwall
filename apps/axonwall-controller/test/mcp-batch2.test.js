import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as http from 'node:http';

// Batch 2 of the 2026-11-05 round-2 Axonwall bug hunt: B2-M2.
// MCP propose_firewall_rule with applyImmediately always
// auto-rolled back: the jobId needed to confirm was generated
// server-side and never returned, and there was no MCP confirm
// tool at all. The propose response now returns the jobId and
// mcp_confirm_apply confirms it against the daemon's exact-match
// /v1/confirm.
//
// The fake daemon below is a unix-socket HTTP server standing in
// for axonwalld: it records the jobId each /v1/confirm receives
// and answers success or a job-mismatch, so the confirm tool is
// exercised end to end without a real daemon.

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-mcp-batch2-'));
process.env.AXONWALL_MCP_KEYS_PATH = path.join(tmpDir, 'mcp-keys.json');
process.env.AXONWALL_MCP_AUDIT_PATH = path.join(tmpDir, 'mcp-audit.jsonl');
const agentSock = path.join(tmpDir, 'agent.sock');
process.env.AXONWALL_AGENT_API_SOCK = agentSock;
process.env.AXONWALL_MCP_ENABLED = 'true';

const {
  MCP_TOOLS_CATALOG,
  createMcpApiKeyRecord,
  authenticateMcpToken,
  processMcpJsonRpcMessage,
  newMcpApplyJobId,
} = await import('../dist/index.js');

// Fake daemon state, controlled per test.
let confirmMode = 'ok';
const confirmJobIds = [];
const fakeDaemon = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    if (req.url === '/v1/confirm' && req.method === 'POST') {
      let jobId = '';
      try { jobId = JSON.parse(body).jobId || ''; } catch {}
      confirmJobIds.push(jobId);
      if (confirmMode === 'ok') {
        res.end(JSON.stringify({ success: true, message: 'Configuration confirmed and promoted to last-known-good.' }));
      } else {
        res.end(JSON.stringify({ success: false, message: `Job ID mismatch for pending confirmation: expected mcp_apply_other, got ${jobId}` }));
      }
      return;
    }
    // Canned read-path data for the B2-M3 resource tests.
    if (req.url.startsWith('/v1/mcp/flows')) {
      res.end(JSON.stringify({ flows: [{ srcIp: '10.0.0.5', dstIp: '93.184.216.34', bytes: 1234 }] }));
      return;
    }
    if (req.url === '/v1/mcp/leases') {
      res.end(JSON.stringify({ leases: [{ leaseId: 'mcp_lease_1', target: '198.51.100.20' }] }));
      return;
    }
    if (req.url === '/v1/arp') {
      res.end(JSON.stringify([{ ip: '10.0.0.5', mac: '02:00:00:00:00:05' }]));
      return;
    }
    if (req.url === '/v1/leases') {
      res.end(JSON.stringify([{ ip: '10.0.0.5', hostname: 'edge-1' }]));
      return;
    }
    if (req.url === '/v1/status') {
      res.end(JSON.stringify({ interfaces: [{ name: 'wan', device: 'eth0' }] }));
      return;
    }
    res.writeHead(404);
    res.end('{}');
  });
});

const { rawToken } = createMcpApiKeyRecord({
  name: 'Batch2 Confirm Test Agent',
  agentType: 'vigilsoc',
  scopes: ['mcp:firewall:apply'],
  allowedSourceCidrs: ['10.42.0.0/16'],
  policyLimits: {
    maxIpv4PrefixLen: 24,
    maxIpv6PrefixLen: 64,
    allowedRedirectTargets: [],
  },
});
const auth = authenticateMcpToken(rawToken, '10.42.1.25');
assert.equal(auth.authenticated, true);
const env = { key: auth.key, clientIp: '10.42.1.25' };

// A second key with the telemetry read scope, for the B2-M3
// resource tests (the confirm key above only has firewall:apply).
const { rawToken: telemetryToken } = createMcpApiKeyRecord({
  name: 'Batch2 Telemetry Test Agent',
  agentType: 'vigilsoc',
  scopes: ['mcp:telemetry:read'],
  allowedSourceCidrs: ['10.42.0.0/16'],
  policyLimits: {
    maxIpv4PrefixLen: 24,
    maxIpv6PrefixLen: 64,
    allowedRedirectTargets: [],
  },
});
const telemetryAuth = authenticateMcpToken(telemetryToken, '10.42.1.25');
assert.equal(telemetryAuth.authenticated, true);
const telemetryEnv = { key: telemetryAuth.key, clientIp: '10.42.1.25' };

async function callTool(name, args, id = 1) {
  return processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } },
    env,
  );
}

async function readResource(uri, id = 1) {
  const res = await processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id, method: 'resources/read', params: { uri } },
    telemetryEnv,
  );
  assert.ok(res?.result?.contents?.[0]?.text, `resources/read ${uri} must return text, got: ${JSON.stringify(res)}`);
  return JSON.parse(res.result.contents[0].text);
}

test('B2-M2: apply job ids are unique and carry a random suffix', () => {
  const ids = new Set(Array.from({ length: 1000 }, () => newMcpApplyJobId()));
  assert.equal(ids.size, 1000, '1000 generated ids must all be distinct');
  for (const id of ids) {
    assert.match(id, /^mcp_apply_\d+_[0-9a-f]{8}$/, `unexpected jobId format: ${id}`);
  }
});

test('B2-M2: mcp_confirm_apply is in the tools catalog', () => {
  const tool = MCP_TOOLS_CATALOG.find((t) => t.name === 'mcp_confirm_apply');
  assert.ok(tool, 'mcp_confirm_apply must be advertised');
  assert.deepEqual(tool.inputSchema.required, ['jobId']);
});

test('B2-M2: confirm forwards the exact jobId and reports the daemon confirmation', async () => {
  confirmMode = 'ok';
  confirmJobIds.length = 0;
  const res = await callTool('mcp_confirm_apply', { jobId: 'mcp_apply_1234_deadbeef' });
  assert.equal(res?.result?.isError, undefined, `confirm must succeed, got: ${JSON.stringify(res)}`);
  const payload = JSON.parse(res.result.content[0].text);
  assert.equal(payload.success, true);
  assert.equal(payload.confirmed, true);
  assert.equal(payload.jobId, 'mcp_apply_1234_deadbeef');
  assert.deepEqual(confirmJobIds, ['mcp_apply_1234_deadbeef'], 'the daemon must receive the exact jobId');
});

test('B2-M2: a daemon job-mismatch refusal is a denial, not a success', async () => {
  confirmMode = 'mismatch';
  const res = await callTool('mcp_confirm_apply', { jobId: 'mcp_apply_1234_deadbeef' }, 2);
  assert.equal(res?.result?.isError, true, 'a refused confirm must be an error');
  const payload = JSON.parse(res.result.content[0].text);
  assert.equal(payload.success, false);
  assert.match(payload.error, /Job ID mismatch/);
});

test('B2-M2: confirm without a jobId is denied before touching the daemon', async () => {
  confirmJobIds.length = 0;
  const res = await callTool('mcp_confirm_apply', {}, 3);
  assert.equal(res?.result?.isError, true);
  const payload = JSON.parse(res.result.content[0].text);
  assert.equal(payload.success, false);
  assert.match(payload.error, /jobId is required/);
  assert.deepEqual(confirmJobIds, [], 'no daemon call may happen without a jobId');
});

test('B2-M3: read paths return data without a daemonDown flag when the daemon is up', async () => {
  const flows = await readResource('axonwall://telemetry/flows/top', 10);
  assert.equal(flows.flows.length, 1);
  assert.equal(flows.daemonDown, undefined);

  const leases = await readResource('axonwall://firewall/tactical-leases', 11);
  assert.equal(leases.leases.length, 1);
  assert.equal(leases.leases[0].leaseId, 'mcp_lease_1');
  assert.equal(leases.daemonDown, undefined);

  const map = await readResource('axonwall://topology/nastymap', 12);
  assert.equal(map.arpTable.length, 1);
  assert.equal(map.dhcpLeases.length, 1);
  assert.equal(map.daemonDown, undefined);

  const ifaces = await readResource('axonwall://telemetry/interfaces', 13);
  assert.equal(ifaces.interfaces.length, 1);
  assert.equal(ifaces.daemonDown, undefined);
});

test('B2-M2: confirm denies when the daemon is down', async () => {
  await new Promise((resolve) => fakeDaemon.close(resolve));
  try { fs.unlinkSync(agentSock); } catch {}
  const res = await callTool('mcp_confirm_apply', { jobId: 'mcp_apply_1234_deadbeef' }, 4);
  assert.equal(res?.result?.isError, true);
  const payload = JSON.parse(res.result.content[0].text);
  assert.equal(payload.success, false);
  assert.match(payload.error, /Daemon unreachable/);

  // B2-M3, daemon-down half: read paths must say the daemon is
  // down instead of reporting empty lists as facts. The fake
  // daemon is stopped now, so these all hit the unreachable path.
  const flows = await readResource('axonwall://telemetry/flows/top', 5);
  assert.deepEqual(flows.flows, []);
  assert.equal(flows.daemonDown, true);
  assert.match(flows.error, /socket not available|unreachable/);

  const leases = await readResource('axonwall://firewall/tactical-leases', 6);
  assert.deepEqual(leases.leases, []);
  assert.equal(leases.daemonDown, true);

  const map = await readResource('axonwall://topology/nastymap', 7);
  assert.deepEqual(map.arpTable, []);
  assert.deepEqual(map.dhcpLeases, []);
  assert.equal(map.daemonDown, true);
  assert.match(map.error, /ARP table/);
  assert.match(map.error, /DHCP leases/);

  // mcp_query_threat_events needs the telemetry scope, so it goes
  // through the telemetry key, not the confirm key.
  const threat = await processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id: 8, method: 'tools/call', params: { name: 'mcp_query_threat_events', arguments: {} } },
    telemetryEnv,
  );
  assert.equal(threat?.result?.isError, undefined);
  const threatPayload = JSON.parse(threat.result.content[0].text);
  assert.deepEqual(threatPayload.activeMcpLeases, []);
  assert.equal(threatPayload.daemonDown, true);
});

// The fake daemon serves every test in this file (the daemon-down
// test above stops it last); start it once up front and clean up
// the temp dir when the file finishes.
await new Promise((resolve) => fakeDaemon.listen(agentSock, resolve));
after(() => {
  try { fakeDaemon.close(); } catch {}
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
});
