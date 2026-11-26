import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-obs-bridge-'));
process.env.AXONWALL_MCP_KEYS_PATH = path.join(tmpDir, 'mcp-keys.json');
process.env.AXONWALL_MCP_AUDIT_PATH = path.join(tmpDir, 'mcp-audit.jsonl');
process.env.AXONWALL_AGENT_API_SOCK = path.join(tmpDir, 'nonexistent-agent.sock');
process.env.AXONWALL_MCP_ENABLED = 'true';

const {
  createMcpApiKeyRecord,
  authenticateMcpToken,
  processMcpJsonRpcMessage,
  formatSatellitePromMetrics,
  bridgeSatelliteMetricsToVM,
  bridgeSatelliteFlowsAndLogs,
  MCP_RESOURCES_CATALOG,
  MCP_TOOLS_CATALOG,
} = await import('../dist/index.js');

test('telemetry-bridge formats Prometheus lines and ships VM, VL, and collector flow batches', async () => {
  const received = { vm: [], vl: [], flows: [], headers: {} };
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      received.headers[req.url] = req.headers.authorization || '';
      if (req.url === '/vm/api/v1/import/prometheus') {
        received.vm.push(body);
        res.writeHead(204).end();
      } else if (req.url === '/vl/insert/jsonline') {
        received.vl.push(body);
        res.writeHead(204).end();
      } else if (req.url === '/v1/netflow/ingest-batch') {
        received.flows.push(JSON.parse(body));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"success":true,"ingested":1}');
      } else if (req.url.startsWith('/vm/api/v1/query')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'success', data: { resultType: 'vector', result: [{ metric: { node_id: 'sat-1' }, value: [1700000000, '1'] }] } }));
      } else if (req.url === '/vl/select/logsql/query') {
        res.writeHead(200, { 'Content-Type': 'application/x-ndjson' });
        res.end('{"_time":"2026-11-25T00:00:00Z","_msg":"sat fw drop","node_id":"sat-1","source":"satellite-firewall"}\n');
      } else {
        res.writeHead(404).end();
      }
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  try {
    const lineText = formatSatellitePromMetrics(
      'sat-1',
      'branch-"north"',
      { cpuUsagePercent: 22.5, memUsagePercent: 48.0, uptimeSeconds: 1200, activeConns: 95, rxBytesTotal: 1000, txBytesTotal: 2000 },
      1700000000000
    );
    assert.match(lineText, /axonwall_cpu_usage_percent\{node_id="sat-1",hostname="branch-\\"north\\"",source="satellite"\} 22\.5 1700000000000/);

    const targets = {
      vmImportUrl: `${baseUrl}/vm/api/v1/import/prometheus`,
      vlInsertUrl: `${baseUrl}/vl/insert/jsonline`,
      collectorIngestUrl: baseUrl,
      bearerToken: 'axw_svc_test_secret',
    };

    const vmOk = await bridgeSatelliteMetricsToVM(
      'sat-1',
      'branch-north',
      { cpuUsagePercent: 22.5, memUsagePercent: 48.0, uptimeSeconds: 1200, activeConns: 95, rxBytesTotal: 1000, txBytesTotal: 2000 },
      { targets }
    );
    assert.equal(vmOk, true);
    assert.equal(received.vm.length, 1);
    assert.equal(received.headers['/vm/api/v1/import/prometheus'], 'Bearer axw_svc_test_secret');

    const batchRes = await bridgeSatelliteFlowsAndLogs(
      'sat-1',
      'branch-north',
      '10.8.0.12',
      {
        flows: [{ srcIp: '10.1.1.5', dstIp: '1.1.1.1', bytes: 512, packets: 4, protocol: 6 }],
        firewallLogs: [{ message: 'dropped port scan', action: 'DROP', srcIp: '198.51.100.7', dstIp: '10.1.1.5' }],
      },
      { targets }
    );
    assert.deepEqual(batchRes, { flowsForwarded: true, logsForwarded: true });
    assert.equal(received.flows[0].nodeId, 'sat-1');
    assert.equal(received.flows[0].exporterIp, '10.8.0.12');
    assert.match(received.vl[0], /"source":"satellite-firewall"/);

    // MCP catalog and scope checks for new observability tools
    assert.ok(MCP_RESOURCES_CATALOG.some((r) => r.uri === 'axonwall://observability/offload-status'));
    assert.ok(MCP_RESOURCES_CATALOG.some((r) => r.uri === 'axonwall://observability/nodes'));
    for (const toolName of [
      'mcp_query_metrics',
      'mcp_query_logs',
      'mcp_query_historical_flows',
      'mcp_trigger_edge_mitigation',
    ]) {
      assert.ok(MCP_TOOLS_CATALOG.some((t) => t.name === toolName), `Missing tool ${toolName}`);
    }

    process.env.AXONWALL_VM_IMPORT_URL = targets.vmImportUrl;
    process.env.AXONWALL_VL_INSERT_URL = targets.vlInsertUrl;
    process.env.AXONWALL_OBSERVABILITY_TOKEN = targets.bearerToken;

    const { rawToken: readTok } = createMcpApiKeyRecord({
      name: 'TelemetryReader',
      agentType: 'vigilsoc',
      scopes: ['mcp:telemetry:read'],
      allowedSourceCidrs: ['10.42.0.0/16'],
    });
    const readAuth = authenticateMcpToken(readTok, '10.42.0.5');
    assert.equal(readAuth.authenticated, true);
    const readEnv = { key: readAuth.key, clientIp: '10.42.0.5' };

    const metricsRes = await processMcpJsonRpcMessage(
      { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'mcp_query_metrics', arguments: { query: 'axonwall_up' } } },
      readEnv
    );
    assert.equal(metricsRes.result.isError, undefined);
    assert.match(metricsRes.result.content[0].text, /sat-1/);

    const logsRes = await processMcpJsonRpcMessage(
      { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'mcp_query_logs', arguments: { nodeId: 'sat-1', source: 'satellite-firewall' } } },
      readEnv
    );
    assert.equal(logsRes.result.isError, undefined);
    assert.match(logsRes.result.content[0].text, /sat fw drop/);

    // Read-only key must be denied mcp_trigger_edge_mitigation
    const denyMitRes = await processMcpJsonRpcMessage(
      { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'mcp_trigger_edge_mitigation', arguments: { targetIp: '203.0.113.44', reason: 'test' } } },
      readEnv
    );
    assert.equal(denyMitRes.result.isError, true);
    assert.match(denyMitRes.result.content[0].text, /lacks required scope/);
  } finally {
    delete process.env.AXONWALL_VM_IMPORT_URL;
    delete process.env.AXONWALL_VL_INSERT_URL;
    delete process.env.AXONWALL_OBSERVABILITY_TOKEN;
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
