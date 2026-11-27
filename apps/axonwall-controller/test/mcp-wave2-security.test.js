import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-mcp-wave2-'));
const statePath = path.join(tmpRoot, 'state.json');
const keysPath = path.join(tmpRoot, 'mcp-keys.json');
const auditPath = path.join(tmpRoot, 'mcp-audit.jsonl');
const agentSock = path.join(tmpRoot, 'agent.sock');
const mountsPath = path.join(tmpRoot, 'proc-mounts');
const cmdlinePath = path.join(tmpRoot, 'proc-cmdline');

process.env.AXONWALL_STATE_FILE = statePath;
process.env.AXONWALL_STATE_JSON_PATH = statePath;
process.env.AXONWALL_DESIRED_STATE_LOCK_PATH = `${statePath}.lock`;
process.env.AXONWALL_MCP_KEYS_PATH = keysPath;
process.env.AXONWALL_MCP_AUDIT_PATH = auditPath;
process.env.AXONWALL_MCP_RATE_LIMIT_PATH = path.join(tmpRoot, 'mcp-rate-limits.json');
process.env.AXONWALL_AGENT_API_SOCK = agentSock;
process.env.AXONWALL_MCP_ENABLED = 'true';
process.env.AXONWALL_PROC_MOUNTS_PATH = mountsPath;
process.env.AXONWALL_PROC_CMDLINE_PATH = cmdlinePath;

function writeBaseState(overrides = {}) {
  const base = {
    version: 1,
    system: {
      hostname: 'mcp-wave2-fw',
      domain: 'axonwall.local',
      timezone: 'UTC',
      dnsServers: ['1.1.1.1'],
      antiLockout: { enabled: true, interface: 'lan', interfaces: ['lan'], ports: [22, 80, 443, 2966, 3000, 9876] },
    },
    interfaces: [
      { name: 'wan', device: 'eth0', role: 'wan', type: 'static', ipv4Address: '203.0.113.10/24', ipv4Gateway: '203.0.113.1', enabled: true },
      { name: 'lan', device: 'eth1', role: 'lan', type: 'static', ipv4Address: '10.80.0.1/24', enabled: true },
    ],
    aliases: [],
    rules: [],
    nat: [],
    vlans: [],
    routes: [],
    bridges: [],
    hostedEdge: { enabled: true },
    ha: {
      enabled: true,
      nodeRole: 'master',
      peerAddress: '10.80.0.203',
      peerIp: '10.80.0.203',
      vrrpInstances: [],
    },
    topology: {
      enabled: true,
      peers: [
        { id: 'topo-1', name: 'peer-active', role: 'edge-ngfw', apiUrl: 'https://10.80.0.204:2966', enabled: true },
        { id: 'topo-off', name: 'peer-disabled', role: 'edge-ngfw', apiUrl: 'https://10.80.0.206:2966', enabled: false },
      ],
    },
    fleet: {
      enabled: true,
      nodes: [
        { id: 'sat-01', name: 'sat-01', arch: 'amd64', ip: '10.80.0.205', status: 'online', wireguard: { tunnelIp: '10.99.0.5/24' } },
      ],
    },
    virt: {
      enabled: true,
      defaultPool: 'tank',
      isoPool: 'tank',
      vms: [
        { vmid: 100, name: 'axonwall-edge-ngfw', cores: 2, memoryMb: 1024, disks: [], nics: [] },
        { vmid: 102, name: 'app-worker-vm', cores: 2, memoryMb: 2048, disks: [], nics: [] },
      ],
      containers: [
        { ctid: 205, hostname: 'app-ct', template: 'debian-12-standard', unprivileged: true, cores: 2, memoryMb: 1024, rootfsPool: 'tank', rootfsSizeGb: 8, nics: [] },
      ],
    },
    ...overrides,
  };
  fs.writeFileSync(statePath, JSON.stringify(base, null, 2));
}
writeBaseState();
fs.writeFileSync(mountsPath, 'customrootpool/ROOT/axonwall / zfs rw,noatime 0 0\ntank/vms /mnt/tank/vms zfs rw 0 0\n');
fs.writeFileSync(cmdlinePath, 'root=ZFS=custombootpool/ROOT/default quiet\n');

const {
  createMcpApiKeyRecord,
  authenticateMcpToken,
  processMcpJsonRpcMessage,
  recordMcpAuditEntry,
  verifyMcpAuditChain,
  queryMcpAuditEntries,
  acquireMcpLockFile,
} = await import('../dist/index.js');

const daemonCalls = [];
let mockLeases = [];
let fleetUnblockCalls = [];

const fakeDaemon = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    let parsedBody = {};
    try { parsedBody = body ? JSON.parse(body) : {}; } catch { parsedBody = { raw: body }; }
    daemonCalls.push({ method: req.method, url: req.url, body: parsedBody });
    res.writeHead(200, { 'Content-Type': 'application/json' });

    if (req.url === '/v1/mcp/posture') {
      res.end(JSON.stringify({
        posture: {
          applianceIps: ['203.0.113.10', '10.80.0.1'],
          gatewayAndHaIps: ['203.0.113.1', '10.80.0.203'],
          antiLockoutPorts: [22, 80, 443, 2966, 3000, 9876],
        },
        leases: mockLeases,
      }));
      return;
    }
    if (req.url === '/v1/mcp/leases') {
      res.end(JSON.stringify({ leases: mockLeases }));
      return;
    }
    if (req.url === '/v1/mcp/revert') {
      res.end(JSON.stringify({ success: true, leaseId: parsedBody.leaseId }));
      return;
    }
    if (req.url === '/v1/virt/vms') {
      res.end(JSON.stringify({ vms: [{ vmid: 100, name: 'axonwall-edge-ngfw' }, { vmid: 102, name: 'app-worker-vm' }] }));
      return;
    }
    if (req.url === '/v1/virt/migrate') {
      res.end(JSON.stringify({ success: true, upid: 'UPID:migrate:102', targetPeerIp: parsedBody.targetPeerIp }));
      return;
    }
    if (req.url === '/v1/virt/backups') {
      res.end(JSON.stringify({ success: true, archiveName: parsedBody.archiveName || null }));
      return;
    }
    if (req.url === '/v1/virt/snapshots' || req.url === '/v1/virt/clone') {
      res.end(JSON.stringify({ success: true, ...parsedBody }));
      return;
    }
    if (req.url?.startsWith('/v1/nas/')) {
      res.end(JSON.stringify({ success: true, ...parsedBody }));
      return;
    }
    if (req.url?.startsWith('/v1/mcp/flows')) {
      res.end(JSON.stringify({ flows: [] }));
      return;
    }
    res.end(JSON.stringify({ success: true }));
  });
});

await new Promise((resolve) => fakeDaemon.listen(agentSock, resolve));
after(() => {
  fakeDaemon.close();
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

function makeKeyEnv(scopes, extra = {}) {
  const { rawToken } = createMcpApiKeyRecord({
    name: `key-${Math.random().toString(16).slice(2, 8)}`,
    agentType: 'vigilsoc',
    scopes,
    allowedSourceCidrs: ['127.0.0.1/32'],
    policyLimits: {
      maxIpv4PrefixLen: 24,
      maxIpv6PrefixLen: 64,
      rateLimitPerMinute: 6000,
      ...(extra.policyLimits || {}),
    },
  });
  const auth = authenticateMcpToken(rawToken, '127.0.0.1');
  assert.equal(auth.authenticated, true);
  return {
    key: auth.key,
    clientIp: '127.0.0.1',
    ...(extra.onFleetBroadcastUnblock ? { onFleetBroadcastUnblock: extra.onFleetBroadcastUnblock } : {}),
  };
}

async function callTool(name, args, env, id = 1) {
  return processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } },
    env,
  );
}

function readState() {
  return JSON.parse(fs.readFileSync(statePath, 'utf8'));
}

// ============================================================================
// 1. [SEC-H13] mcp_import_competitor_config scope, NAT, post-merge & schema
// ============================================================================
test('SEC-H13: mcp_import_competitor_config gates virt bridges/SGs, NAS iscsi/snapshot/cloudsync, NAT & network sections', async () => {
  writeBaseState();
  const fwOnlyEnv = makeKeyEnv(['mcp:firewall:write']);

  // Virt bridges & securityGroups must require mcp:virt:manage
  const proxmoxBridgeOnly = [
    '# /etc/pve/qemu-server/dummy',
    'iface vmbr9 inet manual',
    '  bridge-ports eth2',
  ].join('\n');
  const denyBridge = await callTool('mcp_import_competitor_config', {
    vendor: 'proxmox',
    rawConfig: proxmoxBridgeOnly,
    stageToDesiredState: true,
    audit: { reason: 'Stage Proxmox bridge without virt scope' },
  }, fwOnlyEnv);
  assert.equal(denyBridge?.result?.isError, true);
  assert.match(denyBridge.result.content[0].text, /mcp:virt:manage/);

  const proxmoxSgOnly = [
    '[securitygroup web_sg]',
    'IN ACCEPT -p tcp -dport 8443',
  ].join('\n');
  const denySg = await callTool('mcp_import_competitor_config', {
    vendor: 'proxmox',
    rawConfig: proxmoxSgOnly,
    stageToDesiredState: true,
    audit: { reason: 'Stage Proxmox security group without virt scope' },
  }, fwOnlyEnv);
  assert.equal(denySg?.result?.isError, true);
  assert.match(denySg.result.content[0].text, /mcp:virt:manage/);

  // NAS iscsiTargets, snapshotPolicies, cloudSyncTasks must require mcp:nas:manage
  for (const [label, payload] of [
    ['iscsi', { TrueNAS: true, iscsi_targets: [{ name: 't0', zvol: 'tank/vol0' }] }],
    ['snapshots', { TrueNAS: true, snapshot_tasks: [{ dataset: 'tank/vms', lifetime_unit: 'DAY', lifetime_value: 7 }] }],
    ['cloudsync', { cloudsync_tasks: [{ description: 'b2_sync', path: '/mnt/tank/data', attributes: { bucket: 'my-bucket' } }] }],
  ]) {
    const denyNas = await callTool('mcp_import_competitor_config', {
      vendor: 'truenas',
      rawConfig: JSON.stringify(payload),
      stageToDesiredState: true,
      audit: { reason: `Stage TrueNAS ${label} without nas scope` },
    }, fwOnlyEnv);
    assert.equal(denyNas?.result?.isError, true, `TrueNAS ${label} must be denied without mcp:nas:manage`);
    assert.match(denyNas.result.content[0].text, /mcp:nas:manage/);
  }

  // pfSense XML with VLAN + DNS override + route + NAT must fail on fw-only key
  const pfWithNatAndNet = `<?xml version="1.0"?>
<pfsense>
  <vlans><vlan><if>eth1</if><tag>50</tag><descr>IoT</descr></vlan></vlans>
  <staticroutes><route><network>10.55.0.0/16</network><gateway>10.80.0.254</gateway></route></staticroutes>
  <unbound><hosts><host>app</host><domain>corp.local</domain><ip>10.80.0.50</ip></hosts></unbound>
  <nat>
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <destination><network>wanip</network><port>8443</port></destination>
      <target>10.99.0.10</target>
      <local-port>8443</local-port>
    </rule>
  </nat>
  <filter></filter>
</pfsense>`;

  const denyNatScope = await callTool('mcp_import_competitor_config', {
    vendor: 'pfsense',
    rawConfig: pfWithNatAndNet,
    stageToDesiredState: true,
    audit: { reason: 'Stage pfSense NAT without mcp:traffic:redirect' },
  }, fwOnlyEnv);
  assert.equal(denyNatScope?.result?.isError, true);
  assert.equal(readState().nat.length, 0);
  assert.equal(readState().vlans.length, 0);

  // NAT rule rejected when allowedRedirectTargets is empty
  const fwRedirectNoAllowEnv = makeKeyEnv(['mcp:firewall:write', 'mcp:firewall:apply', 'mcp:traffic:redirect']);
  const denyNatAllowlist = await callTool('mcp_import_competitor_config', {
    vendor: 'pfsense',
    rawConfig: pfWithNatAndNet,
    stageToDesiredState: true,
    audit: { reason: 'Stage pfSense NAT with empty allowlist' },
  }, fwRedirectNoAllowEnv);
  assert.equal(denyNatAllowlist?.result?.isError, true);
  assert.match(denyNatAllowlist.result.content[0].text, /allowedRedirectTargets/);

  // NAT rule on anti-lockout port 2966 rejected even if target is allowlisted
  const fwRedirectAllowEnv = makeKeyEnv(
    ['mcp:firewall:write', 'mcp:firewall:apply', 'mcp:traffic:redirect'],
    { policyLimits: { allowedRedirectTargets: ['10.99.0.10:8443', '10.99.0.10:2966'] } },
  );
  const pfNatAntiLockout = `<?xml version="1.0"?>
<pfsense>
  <nat>
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <destination><network>wanip</network><port>2966</port></destination>
      <target>10.99.0.10</target>
      <local-port>2966</local-port>
    </rule>
  </nat>
  <filter></filter>
</pfsense>`;
  const denyNatLockout = await callTool('mcp_import_competitor_config', {
    vendor: 'pfsense',
    rawConfig: pfNatAntiLockout,
    stageToDesiredState: true,
    audit: { reason: 'Stage pfSense NAT hijacking anti-lockout port 2966' },
  }, fwRedirectAllowEnv);
  assert.equal(denyNatLockout?.result?.isError, true);
  assert.match(denyNatLockout.result.content[0].text, /anti-lockout/);

  // Valid NAT + network infra succeeds with proper scopes & allowlist
  const okImport = await callTool('mcp_import_competitor_config', {
    vendor: 'pfsense',
    rawConfig: pfWithNatAndNet,
    stageToDesiredState: true,
    audit: { reason: 'Stage authorized pfSense NAT and network config' },
  }, fwRedirectAllowEnv);
  assert.equal(okImport?.result?.isError, undefined, `expected authorized import to succeed, got: ${okImport?.result?.content?.[0]?.text}`);
  assert.equal(readState().nat.length, 1);
  assert.equal(readState().vlans.length, 1);

  // Post-merge alias-shadowing guard check on nextState.rules
  writeBaseState({
    aliases: [{ name: 'corp', type: 'network', entries: ['10.80.0.50/32'], enabled: true, description: 'safe existing alias' }],
  });
  const pfAliasCollision = `<?xml version="1.0"?>
<pfsense>
  <aliases>
    <alias><name>corp</name><type>network</type><address>0.0.0.0/0</address></alias>
  </aliases>
  <filter>
    <rule>
      <type>block</type>
      <interface>lan</interface>
      <protocol>tcp</protocol>
      <source><address>corp</address></source>
      <destination><any/></destination>
    </rule>
  </filter>
</pfsense>`;
  const denyPostMerge = await callTool('mcp_import_competitor_config', {
    vendor: 'pfsense',
    rawConfig: pfAliasCollision,
    stageToDesiredState: true,
    audit: { reason: 'Test post-merge remapped alias validation' },
  }, fwOnlyEnv);
  assert.equal(denyPostMerge?.result?.isError, true);
  assert.equal(readState().rules.length, 0);
});

// ============================================================================
// 2. [SEC-H14 (MCP)] mcp_control_virt_workload peer allowlist & path safety
// ============================================================================
test('SEC-H14: mcp_control_virt_workload enforces peer allowlist for live_migrate and rejects leading - / ..', async () => {
  writeBaseState();
  const virtEnv = makeKeyEnv(['mcp:virt:manage']);

  // Reject unauthorized / disabled / non-IP live_migrate targets
  for (const badIp of ['192.0.2.99', '169.254.169.254', '10.80.0.206', 'evil.example.com', '10.80.0.0/24', '-oProxyCommand=id']) {
    daemonCalls.length = 0;
    const res = await callTool('mcp_control_virt_workload', {
      workloadType: 'vm',
      id: 102,
      action: 'live_migrate',
      targetHostIp: badIp,
      audit: { reason: `Test unauthorized live_migrate target ${badIp}` },
    }, virtEnv);
    assert.equal(res?.result?.isError, true, `targetHostIp '${badIp}' must be rejected`);
    assert.equal(daemonCalls.some((c) => c.url === '/v1/virt/migrate'), false);
  }

  // Allow configured HA peer (10.80.0.203), enabled topology peer (10.80.0.204), and fleet node (10.80.0.205)
  for (const goodIp of ['10.80.0.203', '10.80.0.204', '10.80.0.205']) {
    daemonCalls.length = 0;
    const res = await callTool('mcp_control_virt_workload', {
      workloadType: 'vm',
      id: 102,
      action: 'live_migrate',
      targetHostIp: goodIp,
      audit: { reason: `Migrate VM 102 to authorized peer ${goodIp}` },
    }, virtEnv);
    assert.equal(res?.result?.isError, undefined, `authorized peer ${goodIp} must succeed`);
    assert.equal(daemonCalls.some((c) => c.url === '/v1/virt/migrate' && c.body.targetPeerIp === goodIp), true);
  }

  // Fail closed when no peers are configured at all
  writeBaseState({ ha: undefined, topology: { enabled: false, peers: [] }, fleet: { enabled: false, nodes: [] } });
  const denyNoPeers = await callTool('mcp_control_virt_workload', {
    workloadType: 'vm',
    id: 102,
    action: 'live_migrate',
    targetHostIp: '10.80.0.203',
    audit: { reason: 'Fail closed when no HA or fleet peers are configured' },
  }, virtEnv);
  assert.equal(denyNoPeers?.result?.isError, true);

  writeBaseState();
  // Reject leading '-' and '..' in snapshotName, newName, backupArchivePath
  for (const badSnap of ['-rf', 'snap..1', '.hidden']) {
    const r = await callTool('mcp_control_virt_workload', {
      workloadType: 'vm',
      id: 102,
      action: 'snapshot',
      snapshotName: badSnap,
      audit: { reason: 'Test bad snapshot name rejection' },
    }, virtEnv);
    assert.equal(r?.result?.isError, true, `snapshotName '${badSnap}' must be rejected`);
  }
  for (const badClone of ['-badname', 'clone..name']) {
    const r = await callTool('mcp_control_virt_workload', {
      workloadType: 'vm',
      id: 102,
      action: 'clone',
      newId: 105,
      newName: badClone,
      audit: { reason: 'Test bad clone newName rejection' },
    }, virtEnv);
    assert.equal(r?.result?.isError, true, `newName '${badClone}' must be rejected`);
  }
  for (const badPath of ['../../etc/passwd.vma.zst', '-evil.vma.zst', '/var/backups/-evil.vma.zst', 'foo..bar.vma.zst', 'backup.tar.gz', '.hidden.vma.zst']) {
    daemonCalls.length = 0;
    const r = await callTool('mcp_control_virt_workload', {
      workloadType: 'vm',
      id: 102,
      action: 'restore',
      backupArchivePath: badPath,
      audit: { reason: 'Test unsafe backupArchivePath rejection' },
    }, virtEnv);
    assert.equal(r?.result?.isError, true, `backupArchivePath '${badPath}' must be rejected`);
    assert.equal(daemonCalls.some((c) => c.url === '/v1/virt/backups'), false);
  }

  // Valid .vma.zst archive succeeds
  const okRestore = await callTool('mcp_control_virt_workload', {
    workloadType: 'vm',
    id: 102,
    action: 'restore',
    backupArchivePath: '/var/lib/axonwall/backups/vm-102-2026.vma.zst',
    audit: { reason: 'Valid backup archive restore' },
  }, virtEnv);
  assert.equal(okRestore?.result?.isError, undefined);
  assert.equal(daemonCalls.some((c) => c.url === '/v1/virt/backups' && c.body.archiveName === 'vm-102-2026.vma.zst'), true);
});

// ============================================================================
// 3. [SEC-H15] validateFirewallRuleAgainstGuard pass rules & block "," bypass
// ============================================================================
test('SEC-H15: validateFirewallRuleAgainstGuard blocks broad/mgmt WAN pass rules, spaced ranges, and empty block port tokens', async () => {
  writeBaseState();
  const fwEnv = makeKeyEnv(['mcp:firewall:write']);

  const badPassRules = [
    // Half-internet CIDR + management port
    { interface: 'wan', action: 'pass', protocol: 'tcp', source: '0.0.0.0/1', destination: '10.80.0.50/32', destinationPort: '443' },
    { interface: 'wan', action: 'pass', protocol: 'tcp', source: '128.0.0.0/1', destination: '10.80.0.50/32', destinationPort: '22' },
    // Non-RFC1918 public source + management port
    { interface: 'wan', action: 'pass', protocol: 'tcp', source: '198.51.100.5/32', destination: '10.80.0.50/32', destinationPort: '2966' },
    // Narrow source -> self/wan_ip/lan_net/any on management port or broad span
    { interface: 'wan', action: 'pass', protocol: 'tcp', source: '10.80.0.5/32', destination: 'self', destinationPort: '22' },
    { interface: 'wan', action: 'pass', protocol: 'tcp', source: '10.80.0.5/32', destination: 'wan_ip', destinationPort: '3000' },
    { interface: 'wan', action: 'pass', protocol: 'tcp', source: '10.80.0.5/32', destination: 'lan_net', destinationPort: '80' },
    { interface: 'floating', action: 'pass', protocol: 'tcp', source: '10.80.0.5/32', destination: 'any', destinationPort: '9876' },
    // Broad port span (> 100 ports) and privileged port range
    { interface: 'wan', action: 'pass', protocol: 'tcp', source: '0.0.0.0/1', destination: '10.80.0.50/32', destinationPort: '8000-8200' },
    { interface: 'wan', action: 'pass', protocol: 'tcp', source: '0.0.0.0/1', destination: '10.80.0.50/32', destinationPort: '500-600' },
    // Broad source + lan_net destination even on high port
    { interface: 'any', action: 'pass', protocol: 'tcp', source: '0.0.0.0/1', destination: 'lan_net', destinationPort: '8443' },
  ];

  for (const rule of badPassRules) {
    const res = await callTool('mcp_propose_firewall_rule', {
      rule,
      audit: { reason: 'Test SEC-H15 unsafe pass rule rejection' },
    }, fwEnv);
    assert.equal(res?.result?.isError, true, `unsafe pass rule ${JSON.stringify(rule)} must be rejected`);
  }

  // Spaced port range '1 - 65535' via competitor import (bypassing FirewallRuleSchema whitespace check)
  const pfSpacedRange = `<?xml version="1.0"?>
<pfsense>
  <filter>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source><address>0.0.0.0/1</address></source>
      <destination><address>10.80.0.50/32</address><port>1 - 65535</port></destination>
    </rule>
  </filter>
</pfsense>`;
  const resSpaced = await callTool('mcp_import_competitor_config', {
    vendor: 'pfsense',
    rawConfig: pfSpacedRange,
    stageToDesiredState: true,
    audit: { reason: 'Test spaced port range 1 - 65535 guard' },
  }, fwEnv);
  assert.equal(resSpaced?.result?.isError, true, 'spaced range 1 - 65535 on WAN must be rejected');

  // Empty comma-delimited port token bypass ("," / "80,") on block/reject
  for (const badPort of [',', '80,', ',80', ' , ']) {
    const resBlockComma = await callTool('mcp_propose_firewall_rule', {
      rule: {
        interface: 'lan',
        action: 'block',
        protocol: 'tcp',
        source: '198.51.100.25/32',
        destination: '10.80.0.50/32',
        destinationPort: badPort,
      },
      audit: { reason: 'Test empty comma port token guard on block' },
    }, fwEnv);
    assert.equal(resBlockComma?.result?.isError, true, `block rule with destinationPort '${badPort}' must fail closed`);
  }

  // Also test comma-only port token via pfSense import (bypassing schema refine)
  const pfCommaBlock = `<?xml version="1.0"?>
<pfsense>
  <filter>
    <rule>
      <type>block</type>
      <interface>lan</interface>
      <protocol>tcp</protocol>
      <source><address>198.51.100.25/32</address></source>
      <destination><address>10.80.0.50/32</address><port>,</port></destination>
    </rule>
  </filter>
</pfsense>`;
  const resImportComma = await callTool('mcp_import_competitor_config', {
    vendor: 'pfsense',
    rawConfig: pfCommaBlock,
    stageToDesiredState: true,
    audit: { reason: 'Test comma-only destinationPort on imported block rule' },
  }, fwEnv);
  assert.equal(resImportComma?.result?.isError, true, 'imported block rule with destinationPort "," must fail closed');

  // Legitimate narrow WAN pass rule on non-mgmt unprivileged port succeeds
  const okWanPass = await callTool('mcp_propose_firewall_rule', {
    rule: {
      interface: 'wan',
      action: 'pass',
      protocol: 'tcp',
      source: 'any',
      destination: '10.80.0.50/32',
      destinationPort: '8443',
      description: 'Allow HTTPS on alt port 8443 to DMZ server',
    },
    audit: { reason: 'Allow legitimate alt-port 8443 ingress to DMZ server' },
  }, fwEnv);
  assert.equal(okWanPass?.result?.isError, undefined, `legitimate DMZ rule should pass, got: ${okWanPass?.result?.content?.[0]?.text}`);
});

// ============================================================================
// 4. [SEC-H16] & [SEC-M20] Audit truncation, backward getLastHash, rotation, no /tmp, lockfile
// ============================================================================
test('SEC-H16/M20: audit paramsSummary cap, >256KB getLastHash, rotation + checkpoint verification, and no /tmp fallback', async () => {
  const auditTestDir = fs.mkdtempSync(path.join(tmpRoot, 'audit-suite-'));
  const customAudit = path.join(auditTestDir, 'mcp-audit.jsonl');
  const savedAuditEnv = process.env.AXONWALL_MCP_AUDIT_PATH;
  const savedMaxBytes = process.env.AXONWALL_MCP_AUDIT_MAX_BYTES;
  process.env.AXONWALL_MCP_AUDIT_PATH = customAudit;
  delete process.env.AXONWALL_MCP_AUDIT_MAX_BYTES;

  try {
    // 4a. paramsSummary > 4KB is capped with _truncated: true and chain remains valid
    const bigEntry = recordMcpAuditEntry({
      keyId: 'k-big',
      keyName: 'big-test',
      agentType: 'vigilsoc',
      clientIp: '127.0.0.1',
      toolName: 'mcp_query_flows',
      requiredScope: 'mcp:telemetry:read',
      decision: 'allowed',
      paramsSummary: { hugeField: 'X'.repeat(25_000), keepSmall: 42 },
    });
    assert.equal(bigEntry.recorded, true);
    const bigLine = fs.readFileSync(customAudit, 'utf8').trim().split('\n')[0];
    const bigParsed = JSON.parse(bigLine);
    assert.equal(bigParsed.paramsSummary._truncated, true);
    assert.ok(Buffer.byteLength(JSON.stringify(bigParsed.paramsSummary), 'utf8') <= 4096);
    assert.equal(verifyMcpAuditChain().valid, true);

    // 4a-bis. mcp_query_flows & mcp_query_threat_events redact sensitive keys and cap paramsSummary
    const telEnv = makeKeyEnv(['mcp:telemetry:read']);
    await callTool('mcp_query_flows', {
      srcIp: '10.80.0.5',
      secret: 'top_secret_leak_probe',
      oversizedExtra: 'Y'.repeat(12_000),
    }, telEnv);
    await callTool('mcp_query_threat_events', {
      srcIp: '10.80.0.5',
      token: 'axw_secret_token_leak',
      oversizedExtra: 'W'.repeat(12_000),
    }, telEnv);
    const tailEntries = queryMcpAuditEntries(2).entries;
    assert.equal(tailEntries.length, 2);
    for (const te of tailEntries) {
      const jsonStr = JSON.stringify(te.paramsSummary);
      assert.equal(te.paramsSummary._truncated, true);
      assert.ok(Buffer.byteLength(jsonStr, 'utf8') <= 4096);
      assert.equal(jsonStr.includes('top_secret_leak_probe'), false);
      assert.equal(jsonStr.includes('axw_secret_token_leak'), false);
    }

    // 4b. getLastHash() scans backwards > 256 KB across preceding '\n' to find entryHash
    const largeAudit = path.join(auditTestDir, 'large-entry.jsonl');
    process.env.AXONWALL_MCP_AUDIT_PATH = largeAudit;
    const firstRec = recordMcpAuditEntry({
      keyId: 'k-0',
      keyName: 'seed',
      agentType: 'vigilsoc',
      clientIp: '127.0.0.1',
      toolName: 'seed_tool',
      requiredScope: 'mcp:telemetry:read',
      decision: 'allowed',
      paramsSummary: { seed: true },
    });
    assert.equal(firstRec.recorded, true);
    const hugePartial = {
      id: 'mcp_aud_huge01',
      timestamp: '2026-11-27T00:00:00.000Z',
      keyId: 'k-1',
      keyName: 'legacy',
      agentType: 'vigilsoc',
      clientIp: '127.0.0.1',
      toolName: 'legacy_tool',
      requiredScope: 'mcp:telemetry:read',
      decision: 'allowed',
      denialReason: null,
      paramsSummary: { blob: 'Z'.repeat(320 * 1024) },
      auditMetadata: null,
      leaseId: null,
      prevHash: firstRec.entryHash,
    };
    const canonical = JSON.stringify({
      id: hugePartial.id,
      timestamp: hugePartial.timestamp,
      keyId: hugePartial.keyId,
      keyName: hugePartial.keyName,
      agentType: hugePartial.agentType,
      clientIp: hugePartial.clientIp,
      toolName: hugePartial.toolName,
      requiredScope: hugePartial.requiredScope,
      decision: hugePartial.decision,
      denialReason: hugePartial.denialReason,
      paramsSummary: hugePartial.paramsSummary,
      auditMetadata: hugePartial.auditMetadata,
      leaseId: hugePartial.leaseId,
      prevHash: hugePartial.prevHash,
    });
    const hugeHash = crypto.createHash('sha256').update(canonical).digest('hex');
    const hugeEntry = {
      id: hugePartial.id,
      timestamp: hugePartial.timestamp,
      keyId: hugePartial.keyId,
      keyName: hugePartial.keyName,
      agentType: hugePartial.agentType,
      clientIp: hugePartial.clientIp,
      toolName: hugePartial.toolName,
      requiredScope: hugePartial.requiredScope,
      decision: hugePartial.decision,
      paramsSummary: hugePartial.paramsSummary,
      prevHash: hugePartial.prevHash,
      entryHash: hugeHash,
    };
    fs.appendFileSync(largeAudit, JSON.stringify(hugeEntry) + '\n');
    const chainedAfterHuge = recordMcpAuditEntry({
      keyId: 'k-2',
      keyName: 'next',
      agentType: 'vigilsoc',
      clientIp: '127.0.0.1',
      toolName: 'mcp_query_flows',
      requiredScope: 'mcp:telemetry:read',
      decision: 'allowed',
      paramsSummary: { ok: true },
    });
    assert.equal(chainedAfterHuge.recorded, true);
    assert.equal(chainedAfterHuge.prevHash, hugeHash, 'must chain to >256KB preceding entryHash, not GENESIS_HASH');
    assert.equal(verifyMcpAuditChain().valid, true);

    // 4c. Corrupt non-empty audit file never silently falls back to GENESIS_HASH
    const corruptAudit = path.join(auditTestDir, 'corrupt.jsonl');
    process.env.AXONWALL_MCP_AUDIT_PATH = corruptAudit;
    fs.writeFileSync(corruptAudit, 'NOT_VALID_JSON_CORRUPT_LINE\n');
    const failCorrupt = recordMcpAuditEntry({
      keyId: 'k-corrupt',
      keyName: 'corrupt',
      agentType: 'vigilsoc',
      clientIp: '127.0.0.1',
      toolName: 'mcp_query_flows',
      requiredScope: 'mcp:telemetry:read',
      decision: 'allowed',
      paramsSummary: { ok: true },
    });
    assert.equal(failCorrupt.recorded, false);
    assert.equal(fs.readFileSync(corruptAudit, 'utf8'), 'NOT_VALID_JSON_CORRUPT_LINE\n');

    // 4d. Size-based log rotation + hash-linked checkpoint + streaming query
    const rotAudit = path.join(auditTestDir, 'rot-audit.jsonl');
    process.env.AXONWALL_MCP_AUDIT_PATH = rotAudit;
    process.env.AXONWALL_MCP_AUDIT_MAX_BYTES = '900';
    for (let i = 0; i < 12; i++) {
      const rec = recordMcpAuditEntry({
        keyId: 'k-rot',
        keyName: 'rot-agent',
        agentType: 'vigilsoc',
        clientIp: '127.0.0.1',
        toolName: 'mcp_query_flows',
        requiredScope: 'mcp:telemetry:read',
        decision: 'allowed',
        paramsSummary: { seq: i, pad: 'A'.repeat(120) },
      });
      assert.equal(rec.recorded, true);
    }
    assert.equal(fs.existsSync(`${rotAudit}.1`), true, 'rotated archive .1 must exist');
    assert.equal(fs.existsSync(`${rotAudit}.checkpoint.json`), true, 'rotation checkpoint must exist');
    const rotVerify = verifyMcpAuditChain();
    assert.equal(rotVerify.valid, true, `rotated audit chain must verify: ${JSON.stringify(rotVerify)}`);
    const queried = queryMcpAuditEntries(4);
    assert.equal(queried.integrity.valid, true);
    assert.equal(queried.entries.length, 4);
    assert.equal(queried.entries[0].paramsSummary.seq, 11);

    // Tampering with rotated archive .1 or checkpoint metadata must invalidate verification
    const origArchive = fs.readFileSync(`${rotAudit}.1`, 'utf8');
    fs.writeFileSync(`${rotAudit}.1`, origArchive.replace('"seq":', '"seq_tampered":'));
    assert.equal(verifyMcpAuditChain().valid, false);
    fs.writeFileSync(`${rotAudit}.1`, origArchive);
    assert.equal(verifyMcpAuditChain().valid, true);

    const origCheckpoint = fs.readFileSync(`${rotAudit}.checkpoint.json`, 'utf8');
    const cpObj = JSON.parse(origCheckpoint);
    fs.writeFileSync(`${rotAudit}.checkpoint.json`, JSON.stringify({ ...cpObj, anchorHash: 'f'.repeat(64) }));
    assert.equal(verifyMcpAuditChain().valid, false);
    fs.writeFileSync(`${rotAudit}.checkpoint.json`, origCheckpoint);
    assert.equal(verifyMcpAuditChain().valid, true);

    // 4e. Fail closed when no writable secure audit directory exists (never fall back to /tmp/axonwall)
    const distIndex = fileURLToPath(new URL('../dist/index.js', import.meta.url));
    const childEnv = { ...process.env, NODE_ENV: 'production' };
    for (const k of [
      'AXONWALL_MCP_AUDIT_PATH',
      'AXONWALL_STATE_DIR',
      'AXONWALL_LOG_DIR',
      'AXONWALL_DEV_DIR',
      'AXONWALL_DEV',
      'AXONWALL_DEV_MODE',
      'AXONWALL_ETC_DIR',
      'AXONWALL_CONFIG_DIR',
    ]) {
      delete childEnv[k];
    }
    const probe = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `const { recordMcpAuditEntry } = await import(${JSON.stringify(distIndex)});
         const res = recordMcpAuditEntry({ keyId:'k', keyName:'n', agentType:'soar', clientIp:'127.0.0.1', toolName:'t', requiredScope:'mcp:telemetry:read', decision:'allowed', paramsSummary:{} });
         console.log(JSON.stringify({ recorded: res.recorded }));`,
      ],
      { env: childEnv, encoding: 'utf8' },
    );
    const outObj = JSON.parse(probe.stdout.trim().split('\n').pop() || '{}');
    assert.equal(outObj.recorded, false);
    assert.equal(fs.existsSync('/tmp/axonwall/mcp-audit.jsonl'), false);

    // 4f. Symlinked lockfile is rejected cleanly
    const targetFile = path.join(auditTestDir, 'victim.txt');
    const symLock = path.join(auditTestDir, 'sym.lock');
    fs.writeFileSync(targetFile, 'untouched');
    fs.symlinkSync(targetFile, symLock);
    assert.throws(() => acquireMcpLockFile(symLock, 500), /Refusing symlinked lockfile/);
    assert.equal(fs.readFileSync(targetFile, 'utf8'), 'untouched');
  } finally {
    process.env.AXONWALL_MCP_AUDIT_PATH = savedAuditEnv;
    if (savedMaxBytes !== undefined) process.env.AXONWALL_MCP_AUDIT_MAX_BYTES = savedMaxBytes;
    else delete process.env.AXONWALL_MCP_AUDIT_MAX_BYTES;
  }
});

// ============================================================================
// 5. [SEC-H17] mcp_revert_lease scope enforcement & fleet broadcast gate
// ============================================================================
test('SEC-H17: mcp_revert_lease removes mcp:firewall:write bypass, fails closed on unknown kind, and gates fleet unblock', async () => {
  mockLeases = [
    { id: 'lease-bh', kind: 'blackhole', normalizedTarget: '198.51.100.10' },
    { id: 'lease-sh', kind: 'shape', normalizedTarget: '198.51.100.11' },
    { id: 'lease-rd', kind: 'redirect', normalizedTarget: '198.51.100.12' },
    { id: 'lease-xdp', kind: 'xdp_drop', normalizedTarget: '198.51.100.13' },
    { id: 'lease-unk', kind: 'custom_unknown_kind', normalizedTarget: '198.51.100.14' },
    { id: 'lease-nokind', normalizedTarget: '198.51.100.15' },
  ];

  // Key with mcp:firewall:write + mcp:firewall:apply cannot revert ANY tactical lease
  const fwKeyEnv = makeKeyEnv(['mcp:firewall:write', 'mcp:firewall:apply']);
  for (const lease of mockLeases) {
    const res = await callTool('mcp_revert_lease', { leaseId: lease.id, reason: 'Attempt firewall:write bypass' }, fwKeyEnv);
    assert.equal(res?.result?.isError, true, `mcp:firewall:write must not revert ${lease.id}`);
  }

  // Key with mcp:traffic:blackhole (NO mcp:fleet:broadcast) can revert blackhole locally WITHOUT calling fleet unblock
  fleetUnblockCalls = [];
  const bhNoFleetEnv = makeKeyEnv(['mcp:traffic:blackhole'], {
    onFleetBroadcastUnblock: (ip, reason) => {
      fleetUnblockCalls.push({ ip, reason });
      return 1;
    },
  });
  const okLocalBh = await callTool('mcp_revert_lease', { leaseId: 'lease-bh', reason: 'Local blackhole revert' }, bhNoFleetEnv);
  assert.equal(okLocalBh?.result?.isError, undefined);
  assert.equal(JSON.parse(okLocalBh.result.content[0].text).fleetUnblockedSatellites, 0);
  assert.equal(fleetUnblockCalls.length, 0, 'onFleetBroadcastUnblock must NOT be called without mcp:fleet:broadcast');

  // Same blackhole key cannot revert xdp_drop, shape, redirect, unknown, or missing kind
  for (const badId of ['lease-sh', 'lease-rd', 'lease-xdp', 'lease-unk', 'lease-nokind']) {
    const res = await callTool('mcp_revert_lease', { leaseId: badId, reason: 'Cross-kind revert attempt' }, bhNoFleetEnv);
    assert.equal(res?.result?.isError, true, `blackhole key must not revert ${badId}`);
  }

  // Key with mcp:ebpf:manage can revert xdp_drop
  const ebpfEnv = makeKeyEnv(['mcp:ebpf:manage']);
  const okXdp = await callTool('mcp_revert_lease', { leaseId: 'lease-xdp', reason: 'Revert XDP drop lease' }, ebpfEnv);
  assert.equal(okXdp?.result?.isError, undefined);

  // Key with mcp:traffic:blackhole + mcp:fleet:broadcast calls onFleetBroadcastUnblock
  fleetUnblockCalls = [];
  const bhFleetEnv = makeKeyEnv(['mcp:traffic:blackhole', 'mcp:fleet:broadcast'], {
    onFleetBroadcastUnblock: (ip, reason) => {
      fleetUnblockCalls.push({ ip, reason });
      return 2;
    },
  });
  const okFleetBh = await callTool('mcp_revert_lease', { leaseId: 'lease-bh', reason: 'Fleet-wide unblock' }, bhFleetEnv);
  assert.equal(okFleetBh?.result?.isError, undefined);
  assert.equal(JSON.parse(okFleetBh.result.content[0].text).fleetUnblockedSatellites, 2);
  assert.equal(fleetUnblockCalls.length, 1);
});

// ============================================================================
// 6. [SEC-M22 (MCP server)] mcp_manage_zfs_nas root-pool & cloud_sync guard
// ============================================================================
test('SEC-M22: mcp_manage_zfs_nas blocks destructive ops on rpool/bpool/zroot/dynamic root pool & bad cloud_sync targets', async () => {
  const nasEnv = makeKeyEnv(['mcp:nas:manage']);

  for (const protectedPool of ['rpool', 'bpool', 'zroot', 'customrootpool', 'custombootpool']) {
    for (const op of [
      { action: 'rollback', target: `${protectedPool}/ROOT/os@snap1` },
      { action: 'delete_snapshot', target: `${protectedPool}/ROOT/os@snap1` },
      { action: 'lock_dataset', target: `${protectedPool}/ROOT/os` },
      { action: 'discard_checkpoint', target: protectedPool },
    ]) {
      daemonCalls.length = 0;
      const res = await callTool('mcp_manage_zfs_nas', {
        ...op,
        audit: { reason: `Test root-pool protection for ${op.action} on ${op.target}` },
      }, nasEnv);
      assert.equal(res?.result?.isError, true, `${op.action} on protected pool ${op.target} must be blocked`);
      assert.equal(daemonCalls.some((c) => c.url?.startsWith('/v1/nas/')), false);
    }
  }

  // Leading-slash dataset bypass attempt is also rejected
  const slashBypass = await callTool('mcp_manage_zfs_nas', {
    action: 'rollback',
    target: '/zroot/ROOT@snap1',
    audit: { reason: 'Test leading slash root pool bypass' },
  }, nasEnv);
  assert.equal(slashBypass?.result?.isError, true);

  // Destructive ops on non-system pool 'tank' still succeed
  const okTankRollback = await callTool('mcp_manage_zfs_nas', {
    action: 'rollback',
    target: 'tank/vms@snap1',
    audit: { reason: 'Rollback data pool tank/vms snapshot' },
  }, nasEnv);
  assert.equal(okTankRollback?.result?.isError, undefined);

  // cloud_sync rejects leading '-', '.', and '..'
  for (const badCloud of ['-verbose', '../escape', 'task..one', '.hidden']) {
    const res = await callTool('mcp_manage_zfs_nas', {
      action: 'cloud_sync',
      target: badCloud,
      audit: { reason: 'Test unsafe cloud_sync target rejection' },
    }, nasEnv);
    assert.equal(res?.result?.isError, true, `cloud_sync target '${badCloud}' must be rejected`);
  }
  const okCloud = await callTool('mcp_manage_zfs_nas', {
    action: 'cloud_sync',
    target: 'nightly-b2_sync.1',
    audit: { reason: 'Trigger valid cloud_sync task' },
  }, nasEnv);
  assert.equal(okCloud?.result?.isError, undefined);
});
