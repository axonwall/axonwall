import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as http from 'node:http';

// Round-3 bug-hunt fix batch 3 (controller MCP/fleet/TUI) regression
// tests: B-H1 (hub side), B-H5, B-M3.
//
// B-H1: a reverted or flushed blackhole lease must be lifted from
// the fleet too (fleetUnblockedSatellites), not just from the hub
// daemon.
// B-H5: mcp_configure_lxc_bpf_token must deny (and roll DesiredState
// back) when the daemon rejects the BPF_TOKEN profile sync, instead
// of reporting success with daemonProfileSync 'staged_offline'.
// B-M3: stdio mcp_blackhole_traffic with propagateToFleet must deny
// instead of creating a hub-only lease and reporting success with
// fleetPropagatedSatellites: 0.

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-mcp-bughunt3-batch3-'));
process.env.AXONWALL_MCP_KEYS_PATH = path.join(tmpDir, 'mcp-keys.json');
process.env.AXONWALL_MCP_AUDIT_PATH = path.join(tmpDir, 'mcp-audit.jsonl');
const statePath = path.join(tmpDir, 'state.json');
process.env.AXONWALL_STATE_FILE = statePath;
process.env.AXONWALL_STATE_JSON_PATH = statePath;
process.env.AXONWALL_DESIRED_STATE_LOCK_PATH = `${statePath}.lock`;
const agentSock = path.join(tmpDir, 'agent.sock');
process.env.AXONWALL_AGENT_API_SOCK = agentSock;
process.env.AXONWALL_MCP_ENABLED = 'true';

function seedState(bpfToken) {
  fs.writeFileSync(
    statePath,
    JSON.stringify(
      {
        version: 1,
        system: {
          hostname: 'klaxon',
          domain: 'axonwall.local',
          timezone: 'UTC',
          dnsServers: ['1.1.1.1'],
          antiLockout: { enabled: true, interfaces: ['lan'], ports: [2966, 22, 9876] },
        },
        interfaces: [
          { name: 'wan', device: 'eth0', role: 'wan', type: 'static', ipv4Address: '203.0.113.10/24', ipv4Gateway: '203.0.113.1', enabled: true },
          { name: 'lan', device: 'eth1', role: 'lan', type: 'static', ipv4Address: '10.80.0.202/24', enabled: true },
        ],
        hostedEdge: { enabled: true },
        virt: {
          enabled: true,
          defaultPool: 'tank',
          isoPool: 'tank',
          vms: [],
          containers: [
            {
              ctid: 205,
              hostname: 'cilium-sensor',
              template: 'debian-12-standard',
              unprivileged: true,
              cores: 2,
              memoryMb: 1024,
              rootfsPool: 'tank',
              rootfsSizeGb: 8,
              nics: [],
              ...(bpfToken ? { bpfToken } : {}),
            },
          ],
        },
      },
      null,
      2,
    ),
  );
}
seedState(undefined);

const {
  createMcpApiKeyRecord,
  authenticateMcpToken,
  processMcpJsonRpcMessage,
  validateFleetBlockTarget,
  parseFleetBlockTtl,
} = await import('../dist/index.js');

// Fake daemon state, controlled per test.
let ebpfTokensMode = 'ok';
let leasesMode = [];
const daemonRequests = [];
const fakeDaemon = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    daemonRequests.push({ method: req.method, url: req.url, body });
    if (req.url?.startsWith('/v1/ebpf/tokens')) {
      if (ebpfTokensMode === 'fail') {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'daemon rejected BPF_TOKEN profile: preset not allowed' }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ profile: { id: 'ct-205', enabled: true } }));
      }
      return;
    }
    if (req.url === '/v1/mcp/leases') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ leases: leasesMode }));
      return;
    }
    if (req.url === '/v1/mcp/blackhole' && req.method === 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ lease: { id: 'lease-1', kind: 'blackhole' } }));
      return;
    }
    if (req.url === '/v1/mcp/revert' && req.method === 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, revertedLeaseId: 'lease-1' }));
      return;
    }
    if (req.url === '/v1/mcp/flush' && req.method === 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, clearedCount: 2 }));
      return;
    }
    if (req.url === '/v1/mcp/posture') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ posture: {}, leases: [] }));
      return;
    }
    res.writeHead(404);
    res.end('{}');
  });
});
await new Promise((resolve) => fakeDaemon.listen(agentSock, resolve));
after(() => fakeDaemon.close());

const { rawToken } = createMcpApiKeyRecord({
  name: 'Batch3 B-H1/B-H5/B-M3 Test Agent',
  agentType: 'vigilsoc',
  scopes: ['mcp:virt:manage', 'mcp:ebpf:manage', 'mcp:traffic:blackhole', 'mcp:fleet:broadcast', 'mcp:firewall:apply'],
  allowedSourceCidrs: ['10.42.0.0/16'],
  policyLimits: {
    maxIpv4PrefixLen: 24,
    maxIpv6PrefixLen: 64,
    allowedRedirectTargets: [],
  },
});
const auth = authenticateMcpToken(rawToken, '10.42.1.25');
assert.equal(auth.authenticated, true);

// Stdio-shaped env: no fleet callbacks at all.
const env = { key: auth.key, clientIp: '10.42.1.25' };
// HTTP-shaped env: fleet callbacks record what they were asked to do.
const fleetBlockCalls = [];
const fleetUnblockCalls = [];
const envWithFleet = {
  key: auth.key,
  clientIp: '10.42.1.25',
  onFleetBroadcastBlock: (ip, reason, ttlSeconds) => {
    fleetBlockCalls.push({ ip, reason, ttlSeconds });
    return 2;
  },
  onFleetBroadcastUnblock: (ip, reason) => {
    fleetUnblockCalls.push({ ip, reason });
    return 1;
  },
};

async function callTool(name, args, useEnv = env, id = 1) {
  return processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } },
    useEnv,
  );
}

function readState() {
  return JSON.parse(fs.readFileSync(statePath, 'utf8'));
}

test('B-H5: daemon-rejected BPF_TOKEN enable denies and leaves DesiredState unchanged', async () => {
  ebpfTokensMode = 'fail';
  seedState(undefined);
  const denied = await callTool('mcp_configure_lxc_bpf_token', {
    ctid: 205,
    enabled: true,
    preset: 'network-dataplane',
    audit: { reason: 'Enable BPF_TOKEN while the daemon rejects the profile' },
  });
  assert.equal(denied?.result?.isError, true);
  assert.match(denied.result.content[0].text, /Daemon rejected/);
  assert.doesNotMatch(denied.result.content[0].text, /staged_offline/);
  const ct = readState().virt.containers.find((c) => c.ctid === 205);
  assert.equal(ct.bpfToken, undefined);
});

test('B-H5: daemon-rejected BPF_TOKEN disable denies and keeps the live delegation in DesiredState', async () => {
  ebpfTokensMode = 'fail';
  seedState({ enabled: true, preset: 'network-dataplane', auditViaBpfLsm: true });
  const denied = await callTool('mcp_configure_lxc_bpf_token', {
    ctid: 205,
    enabled: false,
    preset: 'network-dataplane',
    audit: { reason: 'Revoke BPF_TOKEN while the daemon cannot delete the profile' },
  });
  assert.equal(denied?.result?.isError, true);
  assert.match(denied.result.content[0].text, /Daemon/);
  const ct = readState().virt.containers.find((c) => c.ctid === 205);
  assert.equal(ct.bpfToken?.enabled, true);
});

test('B-H5: daemon-accepted BPF_TOKEN enable still succeeds with daemonProfileSync synced', async () => {
  ebpfTokensMode = 'ok';
  seedState(undefined);
  const ok = await callTool('mcp_configure_lxc_bpf_token', {
    ctid: 205,
    enabled: true,
    preset: 'network-dataplane',
    audit: { reason: 'Enable BPF_TOKEN with a healthy daemon' },
  });
  assert.ok(!ok?.result?.isError);
  const payload = JSON.parse(ok.result.content[0].text);
  assert.equal(payload.success, true);
  assert.equal(payload.daemonProfileSync, 'synced');
  const ct = readState().virt.containers.find((c) => c.ctid === 205);
  assert.equal(ct.bpfToken?.enabled, true);
});

test('B-M3: stdio blackhole with propagateToFleet denies and creates no hub lease', async () => {
  daemonRequests.length = 0;
  const denied = await callTool('mcp_blackhole_traffic', {
    target: '198.51.100.7',
    ttlSeconds: 3600,
    propagateToFleet: true,
    audit: { reason: 'Block a C2 host fleet-wide over stdio' },
  });
  assert.equal(denied?.result?.isError, true);
  assert.match(denied.result.content[0].text, /Fleet propagation is unavailable over this transport/);
  assert.equal(
    daemonRequests.some((r) => r.method === 'POST' && r.url === '/v1/mcp/blackhole'),
    false,
  );
});

test('B-M3: HTTP blackhole with propagateToFleet passes the TTL in seconds to the fleet callback', async () => {
  daemonRequests.length = 0;
  fleetBlockCalls.length = 0;
  const ok = await callTool(
    'mcp_blackhole_traffic',
    {
      target: '198.51.100.7',
      ttlSeconds: 3600,
      propagateToFleet: true,
      audit: { reason: 'Block a C2 host fleet-wide over HTTP' },
    },
    envWithFleet,
  );
  assert.ok(!ok?.result?.isError);
  const payload = JSON.parse(ok.result.content[0].text);
  assert.equal(payload.success, true);
  assert.equal(payload.fleetPropagatedSatellites, 2);
  assert.equal(fleetBlockCalls.length, 1);
  assert.equal(fleetBlockCalls[0].ip, '198.51.100.7');
  // B-H1: the callback now receives seconds (3600), not the old
  // Math.ceil(ttl/60) minutes (60).
  assert.equal(fleetBlockCalls[0].ttlSeconds, 3600);
  assert.equal(
    daemonRequests.some((r) => r.method === 'POST' && r.url === '/v1/mcp/blackhole'),
    true,
  );
});

test('B-H1: reverting a blackhole lease unblocks it on the fleet', async () => {
  leasesMode = [{ id: 'lease-1', kind: 'blackhole', normalizedTarget: '198.51.100.7' }];
  fleetUnblockCalls.length = 0;
  const ok = await callTool(
    'mcp_revert_lease',
    { leaseId: 'lease-1', reason: 'C2 host cleared' },
    envWithFleet,
  );
  assert.ok(!ok?.result?.isError);
  const payload = JSON.parse(ok.result.content[0].text);
  assert.equal(payload.success, true);
  assert.equal(payload.fleetUnblockedSatellites, 1);
  assert.deepEqual(fleetUnblockCalls.map((c) => c.ip), ['198.51.100.7']);
});

test('B-H1: emergency clear-all unblocks each distinct blackhole target, not shape leases', async () => {
  leasesMode = [
    { id: 'lease-1', kind: 'blackhole', normalizedTarget: '198.51.100.7' },
    { id: 'lease-2', kind: 'blackhole', normalizedTarget: '198.51.100.8' },
    { id: 'lease-3', kind: 'shape', normalizedTarget: '10.0.0.0/24' },
    { id: 'lease-4', kind: 'blackhole', normalizedTarget: '198.51.100.7' },
  ];
  fleetUnblockCalls.length = 0;
  const ok = await callTool('mcp_emergency_clear_all', { reason: 'Emergency flush' }, envWithFleet);
  assert.ok(!ok?.result?.isError);
  const payload = JSON.parse(ok.result.content[0].text);
  assert.equal(payload.success, true);
  assert.equal(payload.clearedCount, 2);
  assert.equal(payload.fleetUnblockedSatellites, 2);
  assert.deepEqual(fleetUnblockCalls.map((c) => c.ip).sort(), ['198.51.100.7', '198.51.100.8']);
});

test('B-H1: fleet block target validation and TTL parsing', () => {
  assert.deepEqual(validateFleetBlockTarget({ target: '198.51.100.7' }), {
    ok: true, target: '198.51.100.7', isMac: false,
  });
  assert.deepEqual(validateFleetBlockTarget({ target: '198.51.100.0/24' }), {
    ok: true, target: '198.51.100.0/24', isMac: false,
  });
  assert.deepEqual(validateFleetBlockTarget({ target: '02-00-00-00-00-05', isMac: true }), {
    ok: true, target: '02:00:00:00:00:05', isMac: true,
  });
  assert.equal(validateFleetBlockTarget({ target: '' }).ok, false);
  assert.equal(validateFleetBlockTarget({ target: 'not-an-ip' }).ok, false);
  assert.equal(validateFleetBlockTarget({ target: '198.51.100.7/33' }).ok, false);
  assert.equal(validateFleetBlockTarget({ target: 'not-a-mac', isMac: true }).ok, false);

  assert.equal(parseFleetBlockTtl({}), 0);
  assert.equal(parseFleetBlockTtl({ ttlSeconds: 0 }), 0);
  assert.equal(parseFleetBlockTtl({ ttlSeconds: -5 }), 0);
  assert.equal(parseFleetBlockTtl({ ttlSeconds: 3600 }), 3600);
  assert.equal(parseFleetBlockTtl({ ttlSeconds: '3600' }), 3600);
  assert.equal(parseFleetBlockTtl({ ttlSeconds: 999999 }), 604800);
});
