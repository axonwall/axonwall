import test from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as os from 'node:os';
import * as path from 'node:path';
import { execSync, spawn } from 'node:child_process';
import { WebSocket } from 'ws';

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-fleet-w2-'));
const etcDir = path.join(tmpRoot, 'etc');
const varDir = path.join(tmpRoot, 'var');
const persistDir = path.join(tmpRoot, 'var-etc');
const stateFile = path.join(varDir, 'state.json');
const keysPath = path.join(varDir, 'mcp-keys.json');
const auditPath = path.join(varDir, 'mcp-audit.jsonl');
const rateLimitPath = path.join(varDir, 'mcp-rate-limits.json');
const haStatePath = path.join(varDir, 'active-ha-edge.json');
const syncedRoutesPath = path.join(varDir, 'synced-routes.json');
const agentSock = path.join(tmpRoot, 'agent-api.sock');

for (const d of [etcDir, varDir, persistDir, path.join(etcDir, 'certs')]) {
  fs.mkdirSync(d, { recursive: true });
}

fs.writeFileSync(
  stateFile,
  JSON.stringify(
    {
      version: 1,
      interfaces: [
        { name: 'wan', device: 'eth0', role: 'wan', type: 'dhcp', enabled: true },
        { name: 'lan', device: 'eth1', role: 'lan', type: 'static', ipv4Address: '10.88.0.1/24', enabled: true },
      ],
      hostedEdge: {
        enabled: true,
        lan: { edgeAddress: '10.88.0.1/24' },
      },
      rules: [],
      aliases: [],
      plugins: [
        { id: 'fleet-controller', enabled: true },
        { id: 'mcp-ai-control', enabled: true },
      ],
      mcp: { enabled: true },
    },
    null,
    2
  )
);

process.env.AXONWALL_ETC_DIR = etcDir;
process.env.AXONWALL_VAR_DIR = varDir;
process.env.AXONWALL_PERSIST_YAML_DIR = persistDir;
process.env.AXONWALL_STATE_FILE = stateFile;
process.env.AXONWALL_STATE_JSON_PATH = stateFile;
process.env.AXONWALL_MCP_KEYS_PATH = keysPath;
process.env.AXONWALL_MCP_AUDIT_PATH = auditPath;
process.env.AXONWALL_MCP_RATE_LIMIT_PATH = rateLimitPath;
process.env.AXONWALL_HA_STATE_PATH = haStatePath;
process.env.AXONWALL_SYNCED_ROUTES_PATH = syncedRoutesPath;
process.env.AXONWALL_AGENT_API_SOCK = agentSock;
process.env.AXONWALL_MCP_ENABLED = 'true';
process.env.AXONWALL_FLEET_ENABLED = 'true';
process.env.AXONWALL_ZTP_TOKEN = 'ztp_wave2_super_secret_token';

const {
  startControllerServer,
  verifySatellitePeerCertIdentity,
  isValidWireGuardPublicKey,
  isValidSatelliteId,
  normalizeSatelliteSkuProfile,
  toFiniteMetricNumber,
  sanitizeSatelliteMetrics,
  createHeadscaleRequestLimiter,
  createMcpAuthFailureLimiter,
  sanitizeSatelliteFlowRecord,
  sanitizeSatelliteFirewallLog,
  validateObservabilityTargetUrl,
  isDisallowedObservabilityIp,
  resolveControllerObservabilityTargets,
  formatSatellitePromMetrics,
  bridgeSatelliteMetricsToVM,
  bridgeSatelliteFlowsAndLogs,
  readCanonicalConfig,
  createMcpApiKeyRecord,
  queryMcpAuditEntries,
  persistHaState,
} = await import('../dist/index.js');

const mcpBin = path.resolve(import.meta.dirname, '../dist/axonwall-mcp.js');
const ctlBin = path.resolve(import.meta.dirname, '../dist/axonwallctl.js');

test.after(() => {
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch {}
});

function generateCaAndCerts(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const caKey = path.join(dir, 'ca.key');
  const caCrt = path.join(dir, 'ca.crt');
  execSync(
    `openssl req -x509 -newkey rsa:2048 -keyout "${caKey}" -out "${caCrt}" -days 30 -nodes -subj "/CN=Axonwall-Test-CA"`,
    { stdio: 'ignore' }
  );

  const issueLeaf = (name, subj, san) => {
    const key = path.join(dir, `${name}.key`);
    const csr = path.join(dir, `${name}.csr`);
    const ext = path.join(dir, `${name}.ext`);
    const crt = path.join(dir, `${name}.crt`);
    execSync(`openssl req -newkey rsa:2048 -keyout "${key}" -out "${csr}" -nodes -subj "${subj}"`, { stdio: 'ignore' });
    const eku = name === 'hub' ? 'serverAuth,clientAuth' : 'clientAuth';
    fs.writeFileSync(
      ext,
      `basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=${eku}\n${san ? `subjectAltName=${san}\n` : ''}`
    );
    execSync(
      `openssl x509 -req -in "${csr}" -CA "${caCrt}" -CAkey "${caKey}" -CAcreateserial -out "${crt}" -days 30 -sha256 -extfile "${ext}"`,
      { stdio: 'ignore' }
    );
    return { key, crt };
  };

  const hub = issueLeaf('hub', '/CN=hub.axonwall.local', 'DNS:localhost,DNS:axonwall.local,IP:127.0.0.1');
  return { caKey, caCrt, hub, issueLeaf };
}

function connectWs(url, opts) {
  return new Promise((resolve) => {
    const ws = new WebSocket(url, opts);
    const messages = [];
    let settled = false;
    ws.on('message', (data) => {
      try { messages.push(JSON.parse(data.toString())); } catch {}
    });
    ws.on('open', () => {
      if (!settled) {
        settled = true;
        resolve({ ok: true, ws, messages });
      }
    });
    ws.on('unexpected-response', (_req, res) => {
      if (!settled) {
        settled = true;
        res.resume();
        resolve({ ok: false, statusCode: res.statusCode });
      }
    });
    ws.on('error', (err) => {
      if (!settled) {
        settled = true;
        resolve({ ok: false, error: err });
      }
    });
  });
}

async function waitForMessage(messages, predicate, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const found = messages.find(predicate);
    if (found) return found;
    await new Promise((r) => setTimeout(r, 20));
  }
  return undefined;
}

// ============================================================================
// 1. [SEC-C03] mTLS identity binding, WireGuard key isolation, HA takeover,
//    and runtime setSecureContext() reload
// ============================================================================

test('SEC-C03 unit: verifySatellitePeerCertIdentity enforces strict CN/SAN binding and rejects spoofing', () => {
  // Exact CN fallback when no SANs exist
  assert.equal(verifySatellitePeerCertIdentity({ subject: { CN: 'sat-1' } }, 'sat-1'), true);
  assert.equal(verifySatellitePeerCertIdentity({ subject: { CN: 'SAT-1' } }, 'sat-1'), true);
  assert.equal(verifySatellitePeerCertIdentity({ subject: { CN: 'sat-2' } }, 'sat-1'), false);

  // SAN DNS / URI exact match
  assert.equal(
    verifySatellitePeerCertIdentity({ subject: { CN: 'ignored' }, subjectaltname: 'URI:urn:axonwall:satellite:edge-1' }, 'edge-1'),
    true
  );
  assert.equal(
    verifySatellitePeerCertIdentity({ subject: { CN: 'ignored' }, subjectaltname: 'DNS:sat-1' }, 'sat-1'),
    true
  );

  // SAN takes precedence over CN (prevents CN-vs-SAN smuggling)
  assert.equal(
    verifySatellitePeerCertIdentity({ subject: { CN: 'sat-1' }, subjectaltname: 'DNS:sat-2' }, 'sat-1'),
    false
  );
  assert.equal(
    verifySatellitePeerCertIdentity(
      { subject: { CN: 'sat-1' }, subjectaltname: 'DNS:sat-1, URI:urn:axonwall:satellite:sat-2' },
      'sat-1'
    ),
    false
  );

  // Rejects prefix/suffix, wildcards, multi-CN, and invalid satIds
  assert.equal(verifySatellitePeerCertIdentity({ subject: { CN: '*' } }, 'sat-1'), false);
  assert.equal(verifySatellitePeerCertIdentity({ subjectaltname: 'DNS:*.axonwall.local' }, 'sat-1'), false);
  assert.equal(verifySatellitePeerCertIdentity({ subjectaltname: 'DNS:sat-1.evil.com' }, 'sat-1'), false);
  assert.equal(verifySatellitePeerCertIdentity({ subject: { CN: ['sat-1', 'sat-2'] } }, 'sat-1'), false);
  assert.equal(verifySatellitePeerCertIdentity({ subject: { CN: '../etc' } }, '../etc'), false);
  assert.equal(verifySatellitePeerCertIdentity(null, 'sat-1'), false);
});

test('SEC-C03 e2e: /ws/satellite rejects mTLS cert-to-satId spoofing before upgrade, WS disconnect, WG keys, or PROMOTE', async (t) => {
  const certsDir = path.join(etcDir, 'certs');
  fs.rmSync(certsDir, { recursive: true, force: true });
  const pki = generateCaAndCerts(certsDir);
  const activeCert = pki.issueLeaf('edge-active', '/CN=edge-active', 'URI:urn:axonwall:satellite:edge-active');
  const rogueCert = pki.issueLeaf('sat-rogue', '/CN=sat-rogue', 'DNS:sat-rogue');
  const smuggleCert = pki.issueLeaf('smuggle', '/CN=edge-active', 'DNS:sat-rogue');

  // Seed persisted active HA edge for edge-active
  persistHaState({ activeHaEdgeId: 'edge-active', lanVip: '10.88.0.1/24', sharedWanMac: '02:00:00:00:00:01' });

  const ctrl = await startControllerServer({ port: 0, host: '127.0.0.1' });
  t.after(async () => {
    await ctrl.close();
    fs.rmSync(certsDir, { recursive: true, force: true });
    fs.mkdirSync(certsDir, { recursive: true });
    try { fs.unlinkSync(haStatePath); } catch {}
  });
  assert.equal(ctrl.getHasFleetMtlsCa(), true);

  // 1. Legitimate edge-active connects with matching mTLS cert
  const legit = await connectWs(`wss://127.0.0.1:${ctrl.port}/ws/satellite`, {
    ca: fs.readFileSync(pki.caCrt),
    cert: fs.readFileSync(activeCert.crt),
    key: fs.readFileSync(activeCert.key),
    rejectUnauthorized: false,
    headers: {
      'x-axonwall-satellite-id': 'edge-active',
      'x-axonwall-ztp-token': process.env.AXONWALL_ZTP_TOKEN,
    },
  });
  assert.equal(legit.ok, true, 'legitimate mTLS satellite must connect');
  t.after(() => { try { legit.ws?.terminate(); } catch {} });

  const legitWg = await waitForMessage(legit.messages, (m) => m.type === 'SYNC_WIREGUARD');
  assert.ok(legitWg?.payload?.privateKey, 'legitimate satellite receives its WireGuard privateKey');
  const legitPromote = await waitForMessage(legit.messages, (m) => m.type === 'PROMOTE');
  assert.ok(legitPromote, 'active HA edge receives PROMOTE');

  // 2. Spoofing attempt: sat-rogue cert claiming x-axonwall-satellite-id: edge-active
  const spoof1 = await connectWs(`wss://127.0.0.1:${ctrl.port}/ws/satellite`, {
    ca: fs.readFileSync(pki.caCrt),
    cert: fs.readFileSync(rogueCert.crt),
    key: fs.readFileSync(rogueCert.key),
    rejectUnauthorized: false,
    headers: {
      'x-axonwall-satellite-id': 'edge-active',
      'x-axonwall-ztp-token': process.env.AXONWALL_ZTP_TOKEN,
    },
  });
  assert.equal(spoof1.ok, false);
  assert.equal(spoof1.statusCode, 403, 'spoofed satId must fail with 403 before upgrade');

  // 3. CN-vs-SAN smuggling cert (CN=edge-active, SAN=DNS:sat-rogue) claiming edge-active
  const spoof2 = await connectWs(`wss://127.0.0.1:${ctrl.port}/ws/satellite`, {
    ca: fs.readFileSync(pki.caCrt),
    cert: fs.readFileSync(smuggleCert.crt),
    key: fs.readFileSync(smuggleCert.key),
    rejectUnauthorized: false,
    headers: {
      'x-axonwall-satellite-id': 'edge-active',
      'x-axonwall-ztp-token': process.env.AXONWALL_ZTP_TOKEN,
    },
  });
  assert.equal(spoof2.ok, false);
  assert.equal(spoof2.statusCode, 403, 'CN-vs-SAN mismatch must fail with 403');

  // 4. Legitimate edge-active socket was NOT disconnected
  assert.equal(legit.ws.readyState, WebSocket.OPEN, 'spoofed upgrade must never disconnect existing enrolled WS');

  // 5. Invalid client cert on HTTP fleet API returns 401 when mTLS CA is active
  const rogueAgent = new https.Agent({
    cert: fs.readFileSync(rogueCert.crt),
    key: fs.readFileSync(rogueCert.key),
    rejectUnauthorized: false,
  });
  // Self-signed cert not from CA
  const untrustedKey = path.join(tmpRoot, 'untrusted.key');
  const untrustedCrt = path.join(tmpRoot, 'untrusted.crt');
  execSync(`openssl req -x509 -newkey rsa:2048 -keyout "${untrustedKey}" -out "${untrustedCrt}" -days 1 -nodes -subj "/CN=evil"`, { stdio: 'ignore' });
  const httpStatus = await new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: '127.0.0.1',
        port: ctrl.port,
        path: '/api/v1/fleet/satellites',
        method: 'GET',
        cert: fs.readFileSync(untrustedCrt),
        key: fs.readFileSync(untrustedKey),
        rejectUnauthorized: false,
        agent: false,
        headers: { 'x-axonwall-ztp-token': process.env.AXONWALL_ZTP_TOKEN },
      },
      (res) => {
        res.resume();
        resolve(res.statusCode);
      }
    );
    req.on('error', reject);
    req.end();
  });
  assert.equal(httpStatus, 401);
  rogueAgent.destroy();
});

test('SEC-C03 e2e: non-mTLS bootstrap mode rotates keys (no sibling wgPrivateKey leak), supports client pubkey, and reloads TLS CA via setSecureContext()', async (t) => {
  const certsDir = path.join(etcDir, 'certs');
  fs.rmSync(certsDir, { recursive: true, force: true });
  fs.mkdirSync(certsDir, { recursive: true });
  try { fs.unlinkSync(haStatePath); } catch {}

  // Start WITHOUT ca.crt -> non-mTLS bootstrap mode (auto-minted self-signed hub cert)
  const ctrl = await startControllerServer({ port: 0, host: '127.0.0.1' });
  t.after(async () => {
    await ctrl.close();
    fs.rmSync(certsDir, { recursive: true, force: true });
    fs.mkdirSync(certsDir, { recursive: true });
  });
  assert.equal(ctrl.getHasFleetMtlsCa(), false);

  // 1. First bootstrap satellite connects and receives privateKey K1
  const boot1 = await connectWs(`wss://127.0.0.1:${ctrl.port}/ws/satellite`, {
    rejectUnauthorized: false,
    headers: {
      'x-axonwall-satellite-id': 'sat-boot',
      'x-axonwall-ztp-token': process.env.AXONWALL_ZTP_TOKEN,
    },
  });
  assert.equal(boot1.ok, true);
  const wg1 = await waitForMessage(boot1.messages, (m) => m.type === 'SYNC_WIREGUARD');
  assert.ok(wg1?.payload?.privateKey);
  boot1.ws.close();
  await new Promise((r) => boot1.ws.once('close', r));

  // 2. Unverified second claimant claiming sat-boot must NOT receive K1
  const boot2 = await connectWs(`wss://127.0.0.1:${ctrl.port}/ws/satellite`, {
    rejectUnauthorized: false,
    headers: {
      'x-axonwall-satellite-id': 'sat-boot',
      'x-axonwall-ztp-token': process.env.AXONWALL_ZTP_TOKEN,
    },
  });
  assert.equal(boot2.ok, true);
  const wg2 = await waitForMessage(boot2.messages, (m) => m.type === 'SYNC_WIREGUARD');
  assert.ok(wg2?.payload?.privateKey);
  assert.notEqual(wg2.payload.privateKey, wg1.payload.privateKey, 'unverified claimant must never receive previously enrolled wgPrivateKey');
  boot2.ws.close();
  await new Promise((r) => boot2.ws.once('close', r));

  // 3. Satellite presenting its own WireGuard public key does not get a hub-generated privateKey
  const { publicKey: clientPubObj } = crypto.generateKeyPairSync('x25519');
  const clientPubB64 = clientPubObj.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
  assert.equal(isValidWireGuardPublicKey(clientPubB64), true);

  const bootPubOnly = await connectWs(`wss://127.0.0.1:${ctrl.port}/ws/satellite`, {
    rejectUnauthorized: false,
    headers: {
      'x-axonwall-satellite-id': 'sat-clientkey',
      'x-axonwall-ztp-token': process.env.AXONWALL_ZTP_TOKEN,
      'x-axonwall-wg-public-key': clientPubB64,
    },
  });
  assert.equal(bootPubOnly.ok, true);
  const wgPubOnly = await waitForMessage(bootPubOnly.messages, (m) => m.type === 'SYNC_WIREGUARD');
  assert.ok(wgPubOnly);
  assert.equal(wgPubOnly.payload.privateKey, undefined, 'satellite-generated pubkey flow must omit privateKey');
  bootPubOnly.ws.close();
  await new Promise((r) => bootPubOnly.ws.once('close', r));

  // 4. Provision CA + CA-signed hub leaf at runtime WITHOUT restarting controller -> setSecureContext() activates mTLS!
  const pki = generateCaAndCerts(certsDir);
  const dynSatCert = pki.issueLeaf('sat-dyn', '/CN=sat-dyn', 'URI:urn:axonwall:satellite:sat-dyn');
  const wrongSatCert = pki.issueLeaf('sat-other', '/CN=sat-other', 'URI:urn:axonwall:satellite:sat-other');

  // Connect without client cert -> connection listener refreshes SecureContext & rejects with 403
  const noCertAfterCa = await connectWs(`wss://127.0.0.1:${ctrl.port}/ws/satellite`, {
    rejectUnauthorized: false,
    headers: {
      'x-axonwall-satellite-id': 'sat-dyn',
      'x-axonwall-ztp-token': process.env.AXONWALL_ZTP_TOKEN,
    },
  });
  assert.equal(noCertAfterCa.ok, false);
  assert.equal(noCertAfterCa.statusCode, 403);
  assert.equal(ctrl.getHasFleetMtlsCa(), true, 'runtime reload must arm hasFleetMtlsCa via setSecureContext()');

  // Wrong identity cert rejected 403
  const wrongAfterCa = await connectWs(`wss://127.0.0.1:${ctrl.port}/ws/satellite`, {
    cert: fs.readFileSync(wrongSatCert.crt),
    key: fs.readFileSync(wrongSatCert.key),
    rejectUnauthorized: false,
    headers: {
      'x-axonwall-satellite-id': 'sat-dyn',
      'x-axonwall-ztp-token': process.env.AXONWALL_ZTP_TOKEN,
    },
  });
  assert.equal(wrongAfterCa.ok, false);
  assert.equal(wrongAfterCa.statusCode, 403);

  // Matching cert succeeds
  const rightAfterCa = await connectWs(`wss://127.0.0.1:${ctrl.port}/ws/satellite`, {
    cert: fs.readFileSync(dynSatCert.crt),
    key: fs.readFileSync(dynSatCert.key),
    rejectUnauthorized: false,
    headers: {
      'x-axonwall-satellite-id': 'sat-dyn',
      'x-axonwall-ztp-token': process.env.AXONWALL_ZTP_TOKEN,
    },
  });
  assert.equal(rightAfterCa.ok, true);
  rightAfterCa.ws.close();
});

// ============================================================================
// 2. [SEC-H12] & [SEC-M21] Telemetry, Flow/Log Allowlisting & SSRF Hardening
// ============================================================================

test('SEC-H12 / SEC-M21 unit: SKU enum, finite metrics, satId, Headscale cooldown, flow/log allowlisting, and SSRF guard', async () => {
  // SKU profile allowlist
  assert.equal(normalizeSatelliteSkuProfile('sku-vm-virtio'), 'sku-vm-virtio');
  assert.equal(normalizeSatelliteSkuProfile('sku-x86-intel-n100-i226'), 'sku-x86-intel-n100-i226');
  assert.equal(normalizeSatelliteSkuProfile('sku-x86-enterprise-10g-25g'), 'sku-x86-enterprise-10g-25g');
  assert.equal(normalizeSatelliteSkuProfile('sku-arm64-router'), 'sku-arm64-router');
  assert.equal(normalizeSatelliteSkuProfile('generic-edge'), 'generic-edge');
  assert.equal(normalizeSatelliteSkuProfile('sku-vm\nadd rule inet filter input accept'), undefined);
  assert.equal(normalizeSatelliteSkuProfile('custom-evil'), undefined);

  // Finite metric coercion (no Infinity / -Infinity poisoning)
  assert.equal(toFiniteMetricNumber(Infinity, true), 0);
  assert.equal(toFiniteMetricNumber(-Infinity, true), 0);
  assert.equal(toFiniteMetricNumber('Infinity', true), 0);
  assert.equal(toFiniteMetricNumber(-5, true), 0);
  assert.equal(toFiniteMetricNumber(42.5, true), 42.5);

  const sm = sanitizeSatelliteMetrics({
    uptimeSeconds: Infinity,
    cpuUsagePercent: 'Infinity',
    memUsagePercent: 61.2,
    activeConns: -10,
    rxBytesTotal: 1024,
    txBytesTotal: NaN,
    skuProfile: 'bad\ninjection',
    evilExtra: 'drop-me',
  });
  assert.deepEqual(sm, {
    uptimeSeconds: 0,
    cpuUsagePercent: 0,
    memUsagePercent: 61.2,
    activeConns: 0,
    rxBytesTotal: 1024,
    txBytesTotal: 0,
  });
  assert.equal('evilExtra' in sm, false);

  // satId validation
  assert.equal(isValidSatelliteId('edge-01.prod_1'), true);
  assert.equal(isValidSatelliteId('../escape'), false);
  assert.equal(isValidSatelliteId('..'), false);
  assert.equal(isValidSatelliteId('-leading-dash'), false);
  assert.throws(() => formatSatellitePromMetrics('../evil', 'host', {}), /Invalid satellite ID/);

  // REQUEST_HEADSCALE 60s cooldown
  const limiter = createHeadscaleRequestLimiter(60_000, 100);
  assert.equal(limiter.allow('sat-1', 1_000_000), true);
  assert.equal(limiter.allow('sat-1', 1_010_000), false);
  assert.equal(limiter.allow('sat-2', 1_010_000), true);
  assert.equal(limiter.allow('sat-1', 1_060_000), true);

  // Flow & firewall log allowlisting (no ...f or ...entry spread)
  const cleanFlow = sanitizeSatelliteFlowRecord(
    {
      protocol: 'tcp',
      srcIp: '10.1.2.3',
      dstIp: '198.51.100.1',
      srcPort: 999999,
      dstPort: 443,
      bytes: Infinity,
      packets: -5,
      hostId: 'spoofed',
      injectedSql: "'; DROP TABLE flows; --",
    },
    '10.99.0.5',
    'sat-real',
    'sat-host',
    1700000000000
  );
  assert.equal(cleanFlow.hostId, 'sat-real');
  assert.equal(cleanFlow.bytes, 0);
  assert.equal(cleanFlow.packets, 0);
  assert.equal(cleanFlow.srcPort, 65535);
  assert.equal('injectedSql' in cleanFlow, false);

  const cleanLog = sanitizeSatelliteFirewallLog(
    {
      message: 'blocked',
      node_id: 'hub-spoof',
      source: 'suricata',
      injectedKey: 'should-not-exist',
      tenant: 'other',
    },
    'sat-real',
    'sat-host'
  );
  assert.equal(cleanLog.node_id, 'sat-real');
  assert.equal(cleanLog.source, 'satellite-firewall');
  assert.equal('injectedKey' in cleanLog, false);
  assert.equal('tenant' in cleanLog, false);

  // Observability SSRF validation
  for (const badUrl of [
    'http://169.254.169.254/latest/meta-data/',
    'http://0xa9fea9fe/latest/meta-data/',
    'http://[fe80::1]:8428/api/v1/import/prometheus',
    'http://[fd00:ec2::254]/latest/meta-data/',
    'http://[::ffff:169.254.169.254]/vm',
    'file:///etc/shadow',
    'ftp://127.0.0.1/file',
    'http://metadata.google.internal/computeMetadata/v1/',
    'https://user:pass@127.0.0.1:8428/',
  ]) {
    assert.equal(validateObservabilityTargetUrl(badUrl).ok, false, `must reject SSRF URL: ${badUrl}`);
  }
  assert.equal(isDisallowedObservabilityIp('169.254.169.254'), true);
  assert.equal(isDisallowedObservabilityIp('fe80::1'), true);
  assert.equal(isDisallowedObservabilityIp('fd00:ec2::254'), true);
  assert.equal(isDisallowedObservabilityIp('127.0.0.1'), false);
  assert.equal(validateObservabilityTargetUrl('http://127.0.0.1:8428/vm').ok, true);

  // Token scoping: do not leak env token to non-loopback state.json URL or ingestToken cross-origin
  const prevObsTok = process.env.AXONWALL_OBSERVABILITY_TOKEN;
  process.env.AXONWALL_OBSERVABILITY_TOKEN = 'env_secret_must_not_leak';
  try {
    const stateTargets = resolveControllerObservabilityTargets({
      observability: {
        victoriaMetrics: { enabled: true, url: 'https://remote.example.invalid:8428' },
        victoriaLogs: { enabled: true, url: 'http://169.254.169.254/latest/meta-data' },
      },
    });
    assert.equal(stateTargets.vmBearerToken, '', 'env token must not attach to non-loopback state.json URL');
    assert.equal(stateTargets.vlInsertUrl, '', 'IMDS URL in state.json must be rejected');

    const offloadTargets = resolveControllerObservabilityTargets({
      observability: {
        offload: {
          enabled: true,
          hubUrl: 'https://hub.example.invalid',
          ingestToken: 'hub_ingest_secret',
          metrics: { enabled: true, remoteWriteUrl: 'https://cross-origin.example.invalid/vm' },
          logs: { enabled: true },
        },
      },
    });
    assert.equal(offloadTargets.vmBearerToken, '', 'offload ingestToken must not leak cross-origin');
    assert.equal(offloadTargets.vlBearerToken, 'hub_ingest_secret');
  } finally {
    if (prevObsTok === undefined) delete process.env.AXONWALL_OBSERVABILITY_TOKEN;
    else process.env.AXONWALL_OBSERVABILITY_TOKEN = prevObsTok;
  }

  // bridgeSatelliteMetricsToVM & bridgeSatelliteFlowsAndLogs block SSRF URLs without calling fetchFn and enforce redirect: 'error'
  let fetchCalled = 0;
  let seenInit = null;
  const mockFetch = async (_url, init) => {
    fetchCalled++;
    seenInit = init;
    return new Response(null, { status: 204 });
  };
  const blockedVm = await bridgeSatelliteMetricsToVM(
    'sat-1',
    'sat-1',
    { cpuUsagePercent: 10 },
    {
      targets: {
        vmImportUrl: 'http://169.254.169.254/latest/meta-data',
        vlInsertUrl: '',
        collectorIngestUrl: '',
        bearerToken: 'secret',
        vmBearerToken: 'secret',
        vlBearerToken: '',
        collectorBearerToken: '',
      },
      fetchFn: mockFetch,
    }
  );
  assert.equal(blockedVm, false);
  assert.equal(fetchCalled, 0, 'blocked SSRF URL must never invoke fetch');

  const blockedBatch = await bridgeSatelliteFlowsAndLogs(
    'sat-1',
    'sat-1',
    '10.99.0.2',
    {
      flows: [{ protocol: 'tcp', srcIp: '10.0.0.1', dstIp: '1.1.1.1', bytes: 10, packets: 1 }],
      firewallLogs: [{ message: 'drop' }],
    },
    {
      targets: {
        vmImportUrl: '',
        vlInsertUrl: 'http://[fd00:ec2::254]/vl/insert/jsonline',
        collectorIngestUrl: 'http://[fe80::1]/v1/netflow/ingest-batch',
        bearerToken: 'secret',
        vmBearerToken: '',
        vlBearerToken: 'secret',
        collectorBearerToken: 'secret',
      },
      fetchFn: mockFetch,
    }
  );
  assert.deepEqual(blockedBatch, { flowsForwarded: false, logsForwarded: false });
  assert.equal(fetchCalled, 0);

  const okVm = await bridgeSatelliteMetricsToVM(
    'sat-1',
    'sat-1',
    { cpuUsagePercent: 10 },
    {
      targets: {
        vmImportUrl: 'http://127.0.0.1:8428/api/v1/import/prometheus',
        vlInsertUrl: '',
        collectorIngestUrl: '',
        bearerToken: '',
        vmBearerToken: 'local_tok',
        vlBearerToken: '',
        collectorBearerToken: '',
      },
      fetchFn: mockFetch,
    }
  );
  assert.equal(okVm, true);
  assert.equal(fetchCalled, 1);
  assert.equal(seenInit.redirect, 'error', 'fetch must disable redirects');
  assert.equal(seenInit.headers.Authorization, 'Bearer local_tok');
});

test('SEC-H12 e2e: telemetry with invalid skuProfile and Infinity values never poisons /metrics or /api/v1/fleet/satellites', async (t) => {
  const certsDir = path.join(etcDir, 'certs');
  fs.rmSync(certsDir, { recursive: true, force: true });
  fs.mkdirSync(certsDir, { recursive: true });
  try { fs.unlinkSync(haStatePath); } catch {}

  const ctrl = await startControllerServer({ port: 0, host: '127.0.0.1' });
  t.after(async () => { await ctrl.close(); });

  const sat = await connectWs(`wss://127.0.0.1:${ctrl.port}/ws/satellite`, {
    rejectUnauthorized: false,
    headers: {
      'x-axonwall-satellite-id': 'sat-telemetry-1',
      'x-axonwall-ztp-token': process.env.AXONWALL_ZTP_TOKEN,
    },
  });
  assert.equal(sat.ok, true);
  t.after(() => { try { sat.ws.terminate(); } catch {} });

  sat.ws.send(
    JSON.stringify({
      type: 'TELEMETRY_REPORT',
      payload: {
        metrics: {
          uptimeSeconds: 120,
          cpuUsagePercent: Infinity,
          memUsagePercent: 45,
          activeConns: 12,
          rxBytesTotal: 1e309,
          txBytesTotal: -1e309,
          skuProfile: 'bad\nadd rule inet',
          extraSpoof: 'should-be-stripped',
        },
      },
    })
  );
  sat.ws.send(
    JSON.stringify({
      type: 'EDGE_FLOW_BATCH',
      payload: {
        flows: [{ protocol: 'tcp', srcIp: '10.0.0.2', dstIp: '1.1.1.1', bytes: 100, packets: 1, spoofProp: 'x' }],
        firewallLogs: [{ message: 'test-drop', node_id: 'evil', extraLogProp: 'y' }],
      },
    })
  );

  await waitForMessage(sat.messages, (m) => m.type === 'PING');

  const getJson = (urlPath) =>
    new Promise((resolve, reject) => {
      const req = https.request(
        {
          hostname: '127.0.0.1',
          port: ctrl.port,
          path: urlPath,
          method: 'GET',
          rejectUnauthorized: false,
          agent: false,
          headers: { 'x-axonwall-ztp-token': process.env.AXONWALL_ZTP_TOKEN },
        },
        (res) => {
          let b = '';
          res.on('data', (c) => (b += c));
          res.on('end', () => resolve({ status: res.statusCode, body: b }));
        }
      );
      req.on('error', reject);
      req.end();
    });

  const satListRes = await getJson('/api/v1/fleet/satellites');
  assert.equal(satListRes.status, 200);
  const satEntry = JSON.parse(satListRes.body).satellites.find((s) => s.id === 'sat-telemetry-1');
  assert.ok(satEntry);
  assert.equal(satEntry.skuProfile, undefined, 'invalid skuProfile must be rejected');
  assert.equal(satEntry.metrics.skuProfile, undefined);
  assert.equal('extraSpoof' in satEntry.metrics, false);
  assert.equal(satEntry.metrics.rxBytesTotal, 0);

  const flowsRes = await getJson('/api/v1/fleet/flows');
  const nodeFlows = JSON.parse(flowsRes.body).nodes['sat-telemetry-1'];
  assert.equal('spoofProp' in nodeFlows.flows[0], false);
  assert.equal('extraLogProp' in nodeFlows.firewallLogs[0], false);
  assert.equal(nodeFlows.firewallLogs[0].node_id, 'sat-telemetry-1');

  const metricsRes = await getJson('/metrics');
  assert.equal(metricsRes.status, 200);
  assert.doesNotMatch(metricsRes.body, /\+Inf|-Inf|NaN/);
});

// ============================================================================
// 3. [SEC-M20] Invalid Bearer token rate limiting on POST /api/v1/mcp
// ============================================================================

test('SEC-M20: POST /api/v1/mcp invalid Bearer token flood returns 429 and coalesces audit entries', async (t) => {
  const certsDir = path.join(etcDir, 'certs');
  fs.rmSync(certsDir, { recursive: true, force: true });
  fs.mkdirSync(certsDir, { recursive: true });
  try { fs.unlinkSync(auditPath); } catch {}

  // Verify unit limiter bounds tracked IPs
  const unitLimiter = createMcpAuthFailureLimiter({ maxFailuresPerWindow: 2, auditBurstPerWindow: 1, maxTrackedIps: 3 });
  assert.equal(unitLimiter.recordFailure('1.1.1.1', 401).shouldAudit, true);
  assert.equal(unitLimiter.recordFailure('1.1.1.1', 401).coalescedNotice, true);
  assert.equal(unitLimiter.recordFailure('1.1.1.1', 401).blocked, true);
  assert.equal(unitLimiter.isBlocked('1.1.1.1'), true);
  unitLimiter.recordFailure('2.2.2.2', 401);
  unitLimiter.recordFailure('3.3.3.3', 401);
  unitLimiter.recordFailure('4.4.4.4', 401);
  assert.equal(unitLimiter.size(), 3, 'tracked IP map must stay bounded');

  // Seed one MCP key so authenticateMcpToken exercises real path
  createMcpApiKeyRecord({ name: 'w2-rate-test', scopes: ['mcp:telemetry:read'], allowedSourceCidrs: ['127.0.0.1/32'] });

  const ctrl = await startControllerServer({ port: 0, host: '127.0.0.1' });
  t.after(async () => { await ctrl.close(); });

  const postBadMcp = () =>
    new Promise((resolve, reject) => {
      const req = https.request(
        {
          hostname: '127.0.0.1',
          port: ctrl.port,
          path: '/api/v1/mcp',
          method: 'POST',
          rejectUnauthorized: false,
          agent: false,
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer axw_mcp_invalid_0000000000',
          },
        },
        (res) => {
          res.resume();
          res.on('end', () => resolve(res.statusCode));
        }
      );
      req.on('error', reject);
      req.end(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }));
    });

  const statuses = [];
  for (let i = 0; i < 22; i++) {
    statuses.push(await postBadMcp());
  }
  assert.ok(statuses.slice(0, 15).every((s) => s === 401), `first 15 should be 401, got ${statuses.slice(0, 15)}`);
  assert.ok(statuses.slice(15).every((s) => s === 429), `subsequent requests should be 429, got ${statuses.slice(15)}`);

  const auditEntries = queryMcpAuditEntries(100).entries.filter((e) => e.toolName === 'http:POST:/api/v1/mcp');
  assert.ok(auditEntries.length <= 4, `audit entries must be coalesced (got ${auditEntries.length} for 22 flood attempts)`);
});

// ============================================================================
// 4. [SEC-L11] axonwall-mcp CLI, axonwallctl cwd & harvester --raw, atomic-config
// ============================================================================

test('SEC-L11: axonwall-mcp rejects --token CLI flag, accepts AXONWALL_MCP_TOKEN / --token-stdin, and caps oversized lines', async (t) => {
  const mcpTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-mcp-cli-w2-'));
  t.after(() => fs.rmSync(mcpTmp, { recursive: true, force: true }));
  const mcpKeys = path.join(mcpTmp, 'mcp-keys.json');
  const mcpAudit = path.join(mcpTmp, 'mcp-audit.jsonl');
  const mcpRate = path.join(mcpTmp, 'mcp-rate.json');

  const prevKeys = process.env.AXONWALL_MCP_KEYS_PATH;
  const prevAudit = process.env.AXONWALL_MCP_AUDIT_PATH;
  const prevRate = process.env.AXONWALL_MCP_RATE_LIMIT_PATH;
  process.env.AXONWALL_MCP_KEYS_PATH = mcpKeys;
  process.env.AXONWALL_MCP_AUDIT_PATH = mcpAudit;
  process.env.AXONWALL_MCP_RATE_LIMIT_PATH = mcpRate;
  const { rawToken } = createMcpApiKeyRecord({
    name: 'stdio-cli-test',
    scopes: ['mcp:telemetry:read'],
    allowedSourceCidrs: ['127.0.0.1/32'],
  });
  if (prevKeys === undefined) delete process.env.AXONWALL_MCP_KEYS_PATH;
  else process.env.AXONWALL_MCP_KEYS_PATH = prevKeys;
  if (prevAudit === undefined) delete process.env.AXONWALL_MCP_AUDIT_PATH;
  else process.env.AXONWALL_MCP_AUDIT_PATH = prevAudit;
  if (prevRate === undefined) delete process.env.AXONWALL_MCP_RATE_LIMIT_PATH;
  else process.env.AXONWALL_MCP_RATE_LIMIT_PATH = prevRate;

  const baseEnv = {
    ...process.env,
    AXONWALL_MCP_KEYS_PATH: mcpKeys,
    AXONWALL_MCP_AUDIT_PATH: mcpAudit,
    AXONWALL_MCP_RATE_LIMIT_PATH: mcpRate,
    AXONWALL_MCP_ENABLED: 'true',
  };
  delete baseEnv.AXONWALL_MCP_TOKEN;

  const runMcp = (args, stdinData, extraEnv = {}) =>
    new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [mcpBin, ...args], { env: { ...baseEnv, ...extraEnv } });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => (stdout += d));
      child.stderr.on('data', (d) => (stderr += d));
      child.on('error', reject);
      child.on('close', (code) => resolve({ code, stdout, stderr }));
      if (stdinData) child.stdin.write(stdinData);
      child.stdin.end();
    });

  // 1. --token=<tok> and --token <tok> must be rejected
  for (const args of [[`--token=${rawToken}`], ['--token', rawToken]]) {
    const res = await runMcp(args, '');
    assert.notEqual(res.code, 0, `${args.join(' ')} must fail`);
    assert.match(res.stderr, /--token on the command line is rejected/i);
  }

  // 2. AXONWALL_MCP_TOKEN env var + oversized line (>2.5MB) rejected cleanly without breaking next valid line
  const oversized = 'A'.repeat(2_600_000) + '\n';
  const validInit = JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'initialize' }) + '\n';
  const envRes = await runMcp([], oversized + validInit, { AXONWALL_MCP_TOKEN: rawToken });
  assert.equal(envRes.code, 0, envRes.stderr);
  const envLines = envRes.stdout.trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(envLines.length, 2);
  assert.equal(envLines[0].error.code, -32600);
  assert.equal(envLines[1].id, 7);
  assert.ok(envLines[1].result);

  // 3. --token-stdin reads token from line 1 and handles JSON-RPC on line 2
  const stdinRes = await runMcp(['--token-stdin'], `${rawToken}\n${validInit}`);
  assert.equal(stdinRes.code, 0, stdinRes.stderr);
  const stdinLines = stdinRes.stdout.trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(stdinLines.length, 1);
  assert.equal(stdinLines[0].id, 7);
});

test('SEC-L11: axonwallctl guards cwd fallback (kubeconfig/config) and writes harvester export --raw with mode 0600', async (t) => {
  const ctlTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-ctl-w2-'));
  t.after(() => fs.rmSync(ctlTmp, { recursive: true, force: true }));

  const evilCwd = path.join(ctlTmp, 'evil-cwd');
  const evilScripts = path.join(evilCwd, 'scripts');
  const evilNvimDir = path.join(evilCwd, 'packaging/iso/config/includes.chroot/etc/axonwall/nvim');
  fs.mkdirSync(evilScripts, { recursive: true });
  fs.mkdirSync(evilNvimDir, { recursive: true });
  const markerFile = path.join(ctlTmp, 'pwned');
  fs.writeFileSync(
    path.join(evilScripts, 'update-kubeconfig.sh'),
    `#!/bin/sh\ntouch ${JSON.stringify(markerFile)}\n`,
    { mode: 0o755 }
  );
  fs.writeFileSync(path.join(evilNvimDir, 'init.lua'), '-- evil lua\n');

  const sock = path.join(ctlTmp, 'agent.sock');
  const fakeDaemon = http.createServer((req, res) => {
    if (req.url?.startsWith('/v1/security/threat-harvester/export')) {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
      res.end(Buffer.from('raw-sensitive-corpus-bytes'));
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((r) => fakeDaemon.listen(sock, r));
  t.after(() => fakeDaemon.close());

  const runCtl = (args, cwd, extraEnv = {}) =>
    new Promise((resolve, reject) => {
      const env = {
        ...process.env,
        AXONWALL_ETC_DIR: etcDir,
        AXONWALL_VAR_DIR: varDir,
        AXONWALL_PERSIST_YAML_DIR: persistDir,
        AXONWALL_STATE_FILE: stateFile,
        AXONWALL_AGENT_API_SOCK: sock,
        ...extraEnv,
      };
      delete env.AXONWALL_DEV;
      delete env.AXONWALL_DEV_MODE;
      delete env.AXONWALL_DEV_DIR;
      const child = spawn(process.execPath, [ctlBin, ...args], { cwd, env });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => (stdout += d));
      child.stderr.on('data', (d) => (stderr += d));
      child.on('error', reject);
      child.on('close', (code) => resolve({ code, stdout, stderr }));
    });

  // 1. Untrusted cwd update-kubeconfig.sh must NOT be executed (neither in prod/test nor with AXONWALL_DEV=1)
  if (!fs.existsSync('/usr/local/bin/axonwall-kubeconfig') && !fs.existsSync('/opt/axonwall/scripts/update-kubeconfig.sh')) {
    const res1 = await runCtl(['kubeconfig'], evilCwd);
    assert.notEqual(res1.code, 0);
    assert.equal(fs.existsSync(markerFile), false, 'evil cwd update-kubeconfig.sh must never execute');

    // Even with AXONWALL_DEV=1, arbitrary cwd outside workspace root must not execute
    const res2 = await runCtl(['kubeconfig', '--help'], evilCwd, { AXONWALL_DEV: '1' });
    void res2;
    assert.equal(fs.existsSync(markerFile), false, 'evil cwd script must not execute even when AXONWALL_DEV=1');
  }

  // 2. Untrusted cwd init.lua must NOT be used by axonwallctl config
  if (!fs.existsSync('/etc/axonwall/nvim/init.lua')) {
    const cfgRes = await runCtl(['config'], evilCwd, { AXONWALL_NVIM_INIT: '' });
    assert.notEqual(cfgRes.code, 0);
    assert.match(cfgRes.stderr, /init\.lua not found/);
  }

  // 3. harvester export --raw writes with mode 0600 and tightens pre-existing 0644 file
  const rawOut = path.join(ctlTmp, 'corpus-raw.tar.zst');
  fs.writeFileSync(rawOut, 'stale', { mode: 0o644 });
  fs.chmodSync(rawOut, 0o644);
  const expRes = await runCtl(['harvester', 'export', rawOut, '--raw'], ctlTmp);
  assert.equal(expRes.code, 0, expRes.stderr);
  assert.equal(fs.statSync(rawOut).mode & 0o777, 0o600, 'harvester export --raw must enforce 0600 mode');

  // Symlink export target must be refused
  const symTarget = path.join(ctlTmp, 'target.txt');
  const symOut = path.join(ctlTmp, 'sym.tar.zst');
  fs.writeFileSync(symTarget, 'keep');
  fs.symlinkSync(symTarget, symOut);
  const symRes = await runCtl(['harvester', 'export', symOut, '--raw'], ctlTmp);
  assert.notEqual(symRes.code, 0);
  assert.equal(fs.readFileSync(symTarget, 'utf8'), 'keep');
});

test('SEC-L11: atomic-config readCanonicalConfig mirror adoption defaults to 0600 and respects explicit mode', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-atomic-w2-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const mirror = path.join(dir, 'mirror.json');
  fs.writeFileSync(mirror, JSON.stringify({ secret: 'top' }), { mode: 0o660 });

  const canonDefault = path.join(dir, 'canon-default.json');
  const val1 = readCanonicalConfig({
    canonicalPath: canonDefault,
    mirrorPaths: [mirror],
    parse: (raw) => JSON.parse(raw),
    label: 'default-mode.json',
  });
  assert.deepEqual(val1, { secret: 'top' });
  assert.equal(fs.statSync(canonDefault).mode & 0o777, 0o600, 'default mirror adoption must use 0600');

  const canonExplicit = path.join(dir, 'canon-explicit.json');
  const val2 = readCanonicalConfig({
    canonicalPath: canonExplicit,
    mirrorPaths: [mirror],
    parse: (raw) => JSON.parse(raw),
    label: 'explicit-mode.json',
    mode: 0o640,
  });
  assert.deepEqual(val2, { secret: 'top' });
  assert.equal(fs.statSync(canonExplicit).mode & 0o777, 0o640, 'explicit mirror adoption mode must be honored');
});
