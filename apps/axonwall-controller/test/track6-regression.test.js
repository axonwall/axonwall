import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawn } from 'node:child_process';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-track6-'));
const etcDir = path.join(tmpDir, 'etc');
const persistYamlDir = path.join(tmpDir, 'var-etc');
const varDir = path.join(tmpDir, 'var');
const statePath = path.join(varDir, 'state.json');
const gitopsDir = path.join(tmpDir, 'gitops');
const agentSockPath = path.join(tmpDir, 'agent-api.sock');
const evePath = path.join(tmpDir, 'eve.json');
const keysPath = path.join(tmpDir, 'mcp-keys.json');
const auditPath = path.join(tmpDir, 'mcp-audit.jsonl');
const headscaleSock = path.join(tmpDir, 'headscale.sock');
const fakeHeadscaleBin = path.join(tmpDir, 'fake-headscale');

fs.mkdirSync(etcDir, { recursive: true });
fs.mkdirSync(persistYamlDir, { recursive: true });
fs.mkdirSync(varDir, { recursive: true });
fs.mkdirSync(gitopsDir, { recursive: true });
fs.writeFileSync(headscaleSock, '');
fs.writeFileSync(
  fakeHeadscaleBin,
  `#!/bin/sh
printf '%s\\n' "$*" > ${JSON.stringify(path.join(tmpDir, 'headscale-args.txt'))}
printf '{"id":1,"given_name":"edge-test"}'
`,
  { mode: 0o755 },
);

const seedState = {
  version: 1,
  capabilities: {
    firewallEnabled: true,
    nasEnabled: false,
    k3sEnabled: false,
    virtEnabled: true,
    vigilanteEnabled: false,
  },
  system: {
    hostname: 'hub-track6',
    antiLockout: {
      enabled: true,
      interface: 'lan',
      interfaces: ['lan'],
      ports: [22, 80, 443, 2966, 3000],
    },
  },
  hostedEdge: { enabled: true },
  interfaces: [
    { name: 'wan', role: 'wan', device: 'eth0', type: 'dhcp', enabled: true },
    { name: 'wan2', role: 'wan', device: 'eth1', type: 'static', ipv4Address: '198.51.100.2/24', ipv4Gateway: '198.51.100.1', enabled: true },
    { name: 'lan', role: 'lan', device: 'eth2', type: 'static', ipv4Address: '10.80.0.1/24', enabled: true },
  ],
  rules: [],
  aliases: [],
  plugins: [
    { id: 'core-nas', enabled: false },
    { id: 'fleet-controller', enabled: false },
  ],
};
fs.writeFileSync(statePath, JSON.stringify(seedState, null, 2));

process.env.AXONWALL_ETC_DIR = etcDir;
process.env.AXONWALL_PERSIST_YAML_DIR = persistYamlDir;
process.env.AXONWALL_VAR_DIR = varDir;
process.env.AXONWALL_STATE_FILE = statePath;
process.env.AXONWALL_GITOPS_DIR = gitopsDir;
process.env.AXONWALL_AGENT_API_SOCK = agentSockPath;
process.env.AXONWALL_SURICATA_EVE_PATH = evePath;
process.env.AXONWALL_MCP_KEYS_PATH = keysPath;
process.env.AXONWALL_MCP_AUDIT_PATH = auditPath;
process.env.AXONWALL_MCP_ENABLED = 'true';
process.env.HEADSCALE_SOCKET_PATH = headscaleSock;
process.env.HEADSCALE_BIN = fakeHeadscaleBin;

const recordedDaemonRequests = [];
let mockLeases = [];
let mockVms = [
  { vmid: 100, name: 'edge-gw' },
  { vmid: 200, name: 'app-vm' },
];
let mockContainers = [
  { ctid: 100, hostname: 'app-web' },
];

const fakeDaemon = http.createServer((req, res) => {
  let rawBody = '';
  req.on('data', (chunk) => { rawBody += chunk; });
  req.on('end', () => {
    let body = null;
    try { body = rawBody ? JSON.parse(rawBody) : null; } catch { body = rawBody; }
    recordedDaemonRequests.push({ method: req.method, url: req.url, body });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    if (req.url === '/v1/mcp/posture') {
      res.end(JSON.stringify({
        posture: {
          applianceIps: ['10.80.0.1'],
          gatewayAndHaIps: ['198.51.100.1'],
          antiLockoutPorts: [22, 80, 443, 2966, 3000],
        },
        leases: mockLeases,
      }));
      return;
    }
    if (req.url === '/v1/mcp/leases') {
      res.end(JSON.stringify({ leases: mockLeases }));
      return;
    }
    if (req.url === '/v1/virt/vms' && req.method === 'GET') {
      res.end(JSON.stringify({ vms: mockVms }));
      return;
    }
    if (req.url === '/v1/virt/containers' && req.method === 'GET') {
      res.end(JSON.stringify({ containers: mockContainers }));
      return;
    }
    if (req.url === '/v1/netflow/query') {
      res.end(JSON.stringify({ flows: [{ srcIp: '1.2.3.4', hostId: 'edge-01' }] }));
      return;
    }
    if (req.url === '/v1/observability/mitigate') {
      res.end(JSON.stringify({ accepted: true, targetIp: body?.targetIp, ttlSec: body?.ttlSec }));
      return;
    }
    if (req.url === '/v1/netflow/ingest-batch') {
      res.end(JSON.stringify({ success: true, ingested: body?.flows?.length || 0 }));
      return;
    }
    res.end(JSON.stringify({ success: true, message: 'ok' }));
  });
});

await new Promise((resolve) => fakeDaemon.listen(agentSockPath, resolve));

const {
  createMcpApiKeyRecord,
  authenticateMcpToken,
  processMcpJsonRpcMessage,
  formatSatellitePromMetrics,
  normalizeFlowProtocol,
  readCachedDesiredStateBestEffort,
  resolveControllerObservabilityTargets,
  bridgeSatelliteMetricsToVM,
  bridgeSatelliteFlowsAndLogs,
  isMetricsMtlsAuthorized,
  isFleetPluginEnabledForController,
} = await import('../dist/index.js');

const { registerMachine } = await import('../dist/headscale.js');
const { classifyTuiApplyResponse, saveStateToDisk } = await import('../dist/axonwall-tui.js');

const ctlPath = path.resolve(import.meta.dirname, '../dist/axonwallctl.js');

function runCtl(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [ctlPath, ...args], { env: process.env });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

test.after(() => {
  try { fakeDaemon.close(); } catch {}
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
});

test('Track6 1.1: mcp_trigger_edge_mitigation requires ebpf/blackhole scope and enforces anti-lockout & TTL policy limits', async () => {
  const { rawToken: fwTok } = createMcpApiKeyRecord({
    name: 'FwWriteOnly',
    agentType: 'custom-ai',
    scopes: ['mcp:firewall:write'],
    allowedSourceCidrs: ['203.0.113.0/24'],
  });
  const fwAuth = authenticateMcpToken(fwTok, '203.0.113.50');
  assert.equal(fwAuth.authenticated, true);

  const deniedScope = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'mcp_trigger_edge_mitigation', arguments: { targetIp: '198.51.100.99', ttlSec: 300 } },
    },
    { key: fwAuth.key, clientIp: '203.0.113.50' },
  );
  assert.equal(deniedScope.result.isError, true);
  assert.match(deniedScope.result.content[0].text, /lacks required scope/i);

  const { rawToken: ebpfTok } = createMcpApiKeyRecord({
    name: 'EbpfTightPolicy',
    agentType: 'vigilsoc',
    scopes: ['mcp:ebpf:manage'],
    allowedSourceCidrs: ['203.0.113.0/24'],
    policyLimits: {
      maxTtlSeconds: 90,
      maxActiveLeases: 1,
      allowInternalRFC1918Targets: false,
      rateLimitPerMinute: 60,
    },
  });
  const ebpfAuth = authenticateMcpToken(ebpfTok, '203.0.113.50');
  const env = { key: ebpfAuth.key, clientIp: '203.0.113.50' };

  // Caller self-lockout rejected
  const selfDeny = await processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'mcp_trigger_edge_mitigation', arguments: { targetIp: '203.0.113.50' } } },
    env,
  );
  assert.equal(selfDeny.result.isError, true);

  // Gateway / HA peer rejected
  const gwDeny = await processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'mcp_trigger_edge_mitigation', arguments: { targetIp: '198.51.100.1' } } },
    env,
  );
  assert.equal(gwDeny.result.isError, true);

  // RFC1918 rejected when allowInternalRFC1918Targets === false
  const rfcDeny = await processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'mcp_trigger_edge_mitigation', arguments: { targetIp: '10.20.30.40' } } },
    env,
  );
  assert.equal(rfcDeny.result.isError, true);

  // Valid external target has ttlSec clamped to policyLimits.maxTtlSeconds (90)
  recordedDaemonRequests.length = 0;
  const okRes = await processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'mcp_trigger_edge_mitigation', arguments: { targetIp: '198.51.100.99', ttlSec: 3600 } } },
    env,
  );
  assert.equal(okRes.result.isError, false);
  const mitigateCall = recordedDaemonRequests.find((r) => r.url === '/v1/observability/mitigate');
  assert.ok(mitigateCall);
  assert.equal(mitigateCall.body.ttlSec, 90);

  // maxActiveLeases enforced
  mockLeases = [{ id: 'lease-1', createdByKeyId: ebpfAuth.key.id, kind: 'blackhole' }];
  const capDeny = await processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'mcp_trigger_edge_mitigation', arguments: { targetIp: '198.51.100.100', ttlSec: 60 } } },
    env,
  );
  assert.equal(capDeny.result.isError, true);
  assert.match(capDeny.result.content[0].text, /Maximum active tactical leases/);
  mockLeases = [];
});

test('Track6 1.2 & 1.3: firewall rule guards catch invertSource/invertDestination, floating/wan2, and competitor import secrets/guards', async () => {
  const { rawToken } = createMcpApiKeyRecord({
    name: 'FwAdmin',
    agentType: 'custom-ai',
    scopes: ['mcp:firewall:write', 'mcp:telemetry:read'],
    allowedSourceCidrs: ['127.0.0.1/32'],
  });
  const auth = authenticateMcpToken(rawToken, '127.0.0.1');
  const env = { key: auth.key, clientIp: '127.0.0.1' };

  // Block with invertSource must be rejected
  const invBlock = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 10,
      method: 'tools/call',
      params: {
        name: 'mcp_propose_firewall_rule',
        arguments: {
          rule: { interface: 'lan', action: 'block', protocol: 'icmp', source: '198.51.100.77', invertSource: true, destination: 'any', destinationPort: 'any' },
          audit: { reason: 'test invertSource block guard' },
        },
      },
    },
    env,
  );
  assert.equal(invBlock.result.isError, true);

  // Pass on wan with inverted source+dst wildcard must be rejected
  const invPass = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 11,
      method: 'tools/call',
      params: {
        name: 'mcp_propose_firewall_rule',
        arguments: {
          rule: { interface: 'wan', action: 'pass', protocol: 'any', source: '198.51.100.1', invertSource: true, destination: '198.51.100.2', invertDestination: true, destinationPort: 'any' },
          audit: { reason: 'test inverted wildcard pass guard' },
        },
      },
    },
    env,
  );
  assert.equal(invPass.result.isError, true);

  // Wildcard pass on floating or wan2 must be rejected
  for (const iface of ['floating', 'wan2']) {
    const res = await processMcpJsonRpcMessage(
      {
        jsonrpc: '2.0',
        id: 12,
        method: 'tools/call',
        params: {
          name: 'mcp_propose_firewall_rule',
          arguments: {
            rule: { interface: iface, action: 'pass', protocol: 'any', source: 'any', destination: 'any', destinationPort: 'any' },
            audit: { reason: `test ${iface} wildcard guard` },
          },
        },
      },
      env,
    );
    assert.equal(res.result.isError, true, `wildcard pass on ${iface} must be rejected`);
  }

  // Competitor import: unsafe rules rejected on stage AND rawConfig redacted from audit trail on denial
  const unsafeIptables = `*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp -j ACCEPT
COMMIT
# SECRET_VPN_PSK=super_secret_preshared_key_12345
`;
  const deniedImport = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 13,
      method: 'tools/call',
      params: {
        name: 'mcp_import_competitor_config',
        arguments: {
          vendor: 'iptables',
          rawConfig: unsafeIptables,
          stageToDesiredState: true,
          audit: { reason: 'test unsafe import stage & secret redaction' },
        },
      },
    },
    env,
  );
  assert.equal(deniedImport.result.isError, true);
  const auditContents = fs.readFileSync(auditPath, 'utf8');
  assert.doesNotMatch(auditContents, /super_secret_preshared_key_12345/);
  assert.match(auditContents, /"rawConfig":"\[REDACTED\]"/);
});

test('Track6 1.4, 1.5, 1.6, 1.7: historical flows FQL/rangeMinutes, LogsQL escaping+pipes, LXC 100 virt guard, and bounded eve.json alerts', async () => {
  const { rawToken } = createMcpApiKeyRecord({
    name: 'TelemetryAndVirt',
    agentType: 'custom-ai',
    scopes: ['mcp:telemetry:read', 'mcp:virt:manage'],
    allowedSourceCidrs: ['127.0.0.1/32'],
  });
  const auth = authenticateMcpToken(rawToken, '127.0.0.1');
  const env = { key: auth.key, clientIp: '127.0.0.1' };

  // 1.4: historical flows rangeMinutes + node= syntax + parenthesized OR
  recordedDaemonRequests.length = 0;
  await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 20,
      method: 'tools/call',
      params: { name: 'mcp_query_historical_flows', arguments: { fql: 'proto=tcp || proto=udp', nodeId: 'edge-01', window: '24h', limit: 50 } },
    },
    env,
  );
  const fqReq = recordedDaemonRequests.find((r) => r.url === '/v1/netflow/query');
  assert.ok(fqReq);
  assert.equal(fqReq.body.rangeMinutes, 1440);
  assert.equal(fqReq.body.fql, '(proto=tcp || proto=udp) && (node="edge-01")');

  // 1.5: LogsQL backslash escaping and pipe precedence
  const observedLogsQl = [];
  const vlServer = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const params = new URLSearchParams(body);
      observedLogsQl.push(params.get('query'));
      res.writeHead(200, { 'Content-Type': 'application/x-ndjson' });
      res.end('');
    });
  });
  await new Promise((resolve) => vlServer.listen(0, '127.0.0.1', resolve));
  const vlAddr = vlServer.address();
  process.env.AXONWALL_VL_INSERT_URL = `http://127.0.0.1:${vlAddr.port}/insert/jsonline`;
  try {
    await processMcpJsonRpcMessage(
      {
        jsonrpc: '2.0',
        id: 21,
        method: 'tools/call',
        params: { name: 'mcp_query_logs', arguments: { query: 'error | stats count()', nodeId: 'edge\\1', source: 'sat"fw' } },
      },
      env,
    );
    assert.equal(observedLogsQl[0], 'node_id:"edge\\\\1" source:"sat\\"fw" (error) | stats count()');
  } finally {
    delete process.env.AXONWALL_VL_INSERT_URL;
    await new Promise((resolve) => vlServer.close(resolve));
  }

  // 1.6: LXC 100 allowed while VM 100 blocked when hostedEdge.enabled === true
  const lxcStop = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 22,
      method: 'tools/call',
      params: { name: 'mcp_control_virt_workload', arguments: { workloadType: 'lxc', id: 100, action: 'stop', audit: { reason: 'restart web container' } } },
    },
    env,
  );
  assert.equal(lxcStop.result.isError, undefined);

  const vmStop = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 23,
      method: 'tools/call',
      params: { name: 'mcp_control_virt_workload', arguments: { workloadType: 'vm', id: 100, action: 'stop', audit: { reason: 'should fail' } } },
    },
    env,
  );
  assert.equal(vmStop.result.isError, true);

  // 1.7: Bounded tail read & alert filtering on > 1.5MB eve.json
  const noiseLine = JSON.stringify({ event_type: 'flow', src_ip: '10.0.0.1', dest_ip: '1.1.1.1' }) + '\n';
  const alertLine = JSON.stringify({ event_type: 'alert', src_ip: '198.51.100.77', dest_ip: '10.80.0.1', alert: { signature: 'ET SCAN' } }) + '\n';
  fs.writeFileSync(evePath, noiseLine.repeat(24000) + alertLine + noiseLine.repeat(20));

  const alertsRes = await processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id: 24, method: 'resources/read', params: { uri: 'axonwall://telemetry/alerts/suricata' } },
    env,
  );
  const parsedAlerts = JSON.parse(alertsRes.result.contents[0].text);
  assert.equal(parsedAlerts.alerts.length, 1);
  assert.equal(parsedAlerts.alerts[0].event_type, 'alert');

  const threatRes = await processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id: 25, method: 'tools/call', params: { name: 'mcp_query_threat_events', arguments: { limit: 10 } } },
    env,
  );
  const parsedThreat = JSON.parse(threatRes.result.content[0].text);
  assert.equal(parsedThreat.suricataAlerts.length, 1);
  assert.equal(parsedThreat.suricataAlerts[0].event_type, 'alert');
});

test('Track6 2.1-2.5: telemetry-bridge protocol uint8, CIDR strip, log anti-spoof, split tokens, null metric skip, metrics CA gate & WS plugin gate', async () => {
  // Null / empty / boolean metrics must not become 0
  const prom = formatSatellitePromMetrics('sat-1', 'sat-1', {
    cpuUsagePercent: 12.5,
    memUsagePercent: null,
    uptimeSeconds: '',
    activeConns: false,
    rxBytesTotal: undefined,
  }, 1700000000000);
  assert.match(prom, /axonwall_cpu_usage_percent.* 12\.5 /);
  assert.doesNotMatch(prom, /axonwall_mem_usage_percent/);
  assert.doesNotMatch(prom, /axonwall_uptime_seconds/);
  assert.doesNotMatch(prom, /axonwall_conntrack_entries/);
  assert.doesNotMatch(prom, /axonwall_net_rx_bytes_total/);

  assert.deepEqual(normalizeFlowProtocol('tcp'), { protocol: 6, protocolName: 'TCP' });
  assert.deepEqual(normalizeFlowProtocol('udp'), { protocol: 17, protocolName: 'UDP' });
  assert.deepEqual(normalizeFlowProtocol('icmpv6'), { protocol: 58, protocolName: 'ICMPv6' });

  // Split tokens
  const splitTargets = resolveControllerObservabilityTargets({
    observability: {
      victoriaMetrics: { enabled: true, url: 'http://127.0.0.1:8428', bearerToken: 'vm_tok' },
      victoriaLogs: { enabled: true, url: 'http://127.0.0.1:9428', bearerToken: 'vl_tok' },
    },
  });
  assert.equal(splitTargets.vmBearerToken, 'vm_tok');
  assert.equal(splitTargets.vlBearerToken, 'vl_tok');

  // Flow normalization + CIDR strip + firewall log anti-spoofing
  const captured = { flows: null, vlLines: [], authHeaders: {} };
  const obsSrv = http.createServer((req, res) => {
    let b = '';
    req.on('data', (c) => { b += c; });
    req.on('end', () => {
      captured.authHeaders[req.url] = req.headers.authorization;
      if (req.url === '/v1/netflow/ingest-batch') {
        captured.flows = JSON.parse(b);
        res.writeHead(200).end('{"success":true}');
      } else if (req.url === '/insert/jsonline') {
        captured.vlLines = b.trim().split('\n').map((l) => JSON.parse(l));
        res.writeHead(204).end();
      } else {
        res.writeHead(204).end();
      }
    });
  });
  await new Promise((resolve) => obsSrv.listen(0, '127.0.0.1', resolve));
  const obsBase = `http://127.0.0.1:${obsSrv.address().port}`;
  try {
    const res = await bridgeSatelliteFlowsAndLogs(
      'sat-real',
      'sat-real-host',
      '10.99.0.2/16',
      {
        flows: [{ protocol: 'tcp', srcIp: '10.0.0.5', dstIp: '1.1.1.1', srcPort: 12345, dstPort: 443, bytes: 100, packets: 2, hostId: 'spoof-node' }],
        firewallLogs: [{ message: 'blocked', node_id: 'hub-spoof', hostname: 'evil-hub', source: 'suricata' }],
      },
      {
        targets: {
          vmImportUrl: `${obsBase}/api/v1/import/prometheus`,
          vlInsertUrl: `${obsBase}/insert/jsonline`,
          collectorIngestUrl: obsBase,
          bearerToken: '',
          vmBearerToken: 'vm_only',
          vlBearerToken: 'vl_only',
          collectorBearerToken: 'col_only',
        },
      },
    );
    assert.deepEqual(res, { flowsForwarded: true, logsForwarded: true });
    assert.equal(captured.flows.exporterIp, '10.99.0.2');
    assert.equal(captured.flows.flows[0].protocol, 6);
    assert.equal(captured.flows.flows[0].protocolName, 'TCP');
    assert.equal(captured.flows.flows[0].hostId, 'sat-real');
    assert.equal(captured.vlLines[0].node_id, 'sat-real');
    assert.equal(captured.vlLines[0].hostname, 'sat-real-host');
    assert.equal(captured.vlLines[0].source, 'satellite-firewall');
    assert.equal(captured.authHeaders['/insert/jsonline'], 'Bearer vl_only');
    assert.equal(captured.authHeaders['/v1/netflow/ingest-batch'], 'Bearer col_only');
  } finally {
    await new Promise((resolve) => obsSrv.close(resolve));
  }

  // mtime-cached DesiredState read
  assert.equal(readCachedDesiredStateBestEffort()?.system?.hostname, 'hub-track6');
  assert.equal(readCachedDesiredStateBestEffort()?.system?.hostname, 'hub-track6');

  // /metrics CA gate & /ws/satellite fleet-controller gate
  assert.equal(isMetricsMtlsAuthorized({ authorized: true }, false), false);
  assert.equal(isMetricsMtlsAuthorized({ authorized: false }, true), false);
  assert.equal(isMetricsMtlsAuthorized({ authorized: true }, true), true);
  assert.equal(isFleetPluginEnabledForController(seedState), false);
  assert.equal(isFleetPluginEnabledForController({ ...seedState, plugins: [{ id: 'fleet-controller', enabled: true }] }), true);
});

test('Track6 3.1-3.6: headscale mkey:, TUI HTTP-200 success:false & atomic save, and axonwallctl netflow/virt/setCoreRolePlugin', async () => {
  // 3.1: headscale registerMachine accepts legacy mkey: and nodekey: keys
  const hsRes = await registerMachine('ops', 'mkey:abcdef123456');
  assert.equal(hsRes.given_name, 'edge-test');
  const seenArgs = fs.readFileSync(path.join(tmpDir, 'headscale-args.txt'), 'utf8');
  assert.match(seenArgs, /--key mkey:abcdef123456/);

  // 3.2: TUI classifyTuiApplyResponse catches HTTP-200 { success: false, message }
  assert.equal(classifyTuiApplyResponse({ success: false, message: 'nftables validation failed' }), 'rejected');
  assert.equal(classifyTuiApplyResponse({ success: false, errorKind: 'offline', error: 'offline' }), 'offline');
  assert.equal(classifyTuiApplyResponse({ success: false, errorKind: 'timeout', error: 'timed out' }), 'timeout');
  assert.equal(classifyTuiApplyResponse({ success: true }), 'applied');

  // 3.6 (TUI): atomic saveStateToDisk leaves no temp files
  const saved = saveStateToDisk(JSON.parse(fs.readFileSync(statePath, 'utf8')));
  assert.ok(saved);
  for (const dir of [varDir, etcDir, persistYamlDir]) {
    const leftover = fs.readdirSync(dir).filter((f) => f.includes('.tmp-'));
    assert.deepEqual(leftover, []);
  }

  // 3.5: axonwallctl netflow query parses space-separated valueFlags cleanly
  recordedDaemonRequests.length = 0;
  const nfRes = await runCtl(['netflow', 'query', '--minutes', '1440', '--limit', '100', '--scope', 'fleet', 'proto=tcp']);
  assert.equal(nfRes.status, 0, nfRes.stderr);
  const ctlFlowReq = recordedDaemonRequests.find((r) => r.url === '/v1/netflow/query');
  assert.ok(ctlFlowReq);
  assert.equal(ctlFlowReq.body.rangeMinutes, 1440);
  assert.equal(ctlFlowReq.body.limit, 100);
  assert.equal(ctlFlowReq.body.scope, 'fleet');
  assert.equal(ctlFlowReq.body.fql, 'proto=tcp');

  // 3.4: axonwallctl virt rollback / migrate / restore block Hosted Edge VM #100 without --force
  for (const args of [
    ['virt', 'migrate', '100', '10.0.0.2'],
    ['virt', 'rollback', 'vm', '100', 'snap1'],
    ['virt', 'restore', 'edge.vma.zst', 'vm', '100'],
  ]) {
    const blocked = await runCtl(args);
    assert.notEqual(blocked.status, 0, `expected ${args.join(' ')} to block VM 100 without --force`);
    assert.match(blocked.stderr, /anti-lockout guard/i);
  }
  const forcedMig = await runCtl(['virt', 'migrate', '100', '10.0.0.2', '--force']);
  assert.equal(forcedMig.status, 0, forcedMig.stderr);

  // 3.6 (CLI): axonwallctl plugin enable core-nas updates state.json capabilities & plugins atomically under lock
  const plugRes = await runCtl(['plugin', 'enable', 'core-nas']);
  assert.equal(plugRes.status, 0, plugRes.stderr);
  const updatedState = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  assert.equal(updatedState.capabilities.nasEnabled, true);
  assert.equal(updatedState.nas.enabled, true);
  assert.equal(updatedState.plugins.find((p) => p.id === 'core-nas')?.enabled, true);
});
