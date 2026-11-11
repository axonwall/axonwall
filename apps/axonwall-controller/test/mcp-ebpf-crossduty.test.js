import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as http from 'node:http';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-mcp-ebpf-crossduty-'));
process.env.AXONWALL_MCP_KEYS_PATH = path.join(tmpDir, 'mcp-keys.json');
process.env.AXONWALL_MCP_AUDIT_PATH = path.join(tmpDir, 'mcp-audit.jsonl');
const statePath = path.join(tmpDir, 'state.json');
process.env.AXONWALL_STATE_FILE = statePath;
process.env.AXONWALL_STATE_JSON_PATH = statePath;
process.env.AXONWALL_DESIRED_STATE_LOCK_PATH = `${statePath}.lock`;
const agentSock = path.join(tmpDir, 'agent.sock');
process.env.AXONWALL_AGENT_API_SOCK = agentSock;
process.env.AXONWALL_MCP_ENABLED = 'true';

// Seed DesiredState with one unprivileged LXC container (CT 205), one privileged LXC container (CT 206),
// and one Hosted Edge VM (VM 100) to test anti-lockout and CLONE_NEWUSER invariants.
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
        vms: [
          {
            vmid: 100,
            name: 'axonwall-edge-ngfw',
            cores: 2,
            memoryMb: 1024,
            disks: [],
            nics: [],
          },
          {
            vmid: 102,
            name: 'debian-workload',
            cores: 2,
            memoryMb: 2048,
            disks: [],
            nics: [],
          },
        ],
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
          },
          {
            ctid: 206,
            hostname: 'legacy-priv-ct',
            template: 'debian-12-standard',
            unprivileged: false,
            cores: 2,
            memoryMb: 1024,
            rootfsPool: 'tank',
            rootfsSizeGb: 8,
            nics: [],
          },
        ],
      },
    },
    null,
    2,
  ),
);

const {
  MCP_RESOURCES_CATALOG,
  MCP_TOOLS_CATALOG,
  createMcpApiKeyRecord,
  authenticateMcpToken,
  processMcpJsonRpcMessage,
  verifyMcpAuditChain,
} = await import('../dist/index.js');

const daemonRequests = [];
const fakeDaemon = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => {
    body += c;
  });
  req.on('end', () => {
    daemonRequests.push({ method: req.method, url: req.url, body });
    res.writeHead(200, { 'Content-Type': 'application/json' });

    if (req.url?.startsWith('/v1/ebpf/overview')) {
      res.end(
        JSON.stringify({
          dataplane: {
            attachedIfaces: ['eth0', 'eth1'],
            stats: { rxPackets: 12000, xdpPass: 11950, xdpDrop: 50, ipv4Packets: 9000, ipv6Packets: 3000, vlanPackets: 1400 },
            topFlows: [],
            activeBlocks: [],
          },
          lsm: {
            attached: true,
            attachedHooks: ['bprm_check_security', 'kernel_module_request', 'bpf', 'bpf_token_create', 'bpf_token_cmd'],
          },
          bpfTokens: {
            capabilities: { supportsBpfTokenCreate: true, supportsLsmBpfTokenCreate: true, supportsLsmBpfTokenCmd: true },
            profiles: [],
          },
        }),
      );
      return;
    }

    if (req.url?.startsWith('/v1/ebpf/xdp/block')) {
      const parsedBody = body ? JSON.parse(body) : {};
      res.end(JSON.stringify({ success: true, ip: parsedBody.ip, blocks: [{ ip: parsedBody.ip || '198.51.100.77', dropPackets: 12 }] }));
      return;
    }

    if (req.url?.startsWith('/v1/ebpf/tokens/render-k3s')) {
      res.end(
        JSON.stringify({
          success: true,
          manifestYaml: 'apiVersion: v1\nkind: Pod\nspec:\n  hostUsers: false\n  # LIBBPF_BPF_TOKEN_PATH=/sys/fs/bpf\n',
        }),
      );
      return;
    }

    if (req.url?.startsWith('/v1/ebpf/tokens')) {
      if (req.method === 'GET') {
        res.end(
          JSON.stringify({
            capabilities: { supportsBpfTokenCreate: true },
            presets: [{ id: 'network-dataplane' }],
            profiles: [],
            activeMounts: [],
          }),
        );
        return;
      }
      const parsedBody = body ? JSON.parse(body) : {};
      res.end(JSON.stringify({ success: true, profile: { id: parsedBody.id, preset: parsedBody.preset } }));
      return;
    }

    if (req.url === '/v1/mcp/posture') {
      res.end(
        JSON.stringify({
          posture: {
            applianceIps: ['203.0.113.10', '10.80.0.202'],
            gatewayAndHaIps: ['203.0.113.1', '10.80.0.203'],
            antiLockoutPorts: [2966, 22, 9876],
          },
          leases: [],
        }),
      );
      return;
    }

    if (req.url === '/v1/virt/vms') {
      if (req.method === 'POST') {
        const parsedBody = JSON.parse(body);
        res.end(JSON.stringify({ success: true, action: parsedBody.action, vmid: parsedBody.vmid }));
        return;
      }
      res.end(JSON.stringify({ vms: [{ vmid: 100, name: 'axonwall-edge-ngfw' }, { vmid: 102, name: 'debian-workload' }] }));
      return;
    }

    if (req.url === '/v1/virt/containers') {
      res.end(JSON.stringify({ containers: [{ ctid: 205, hostname: 'cilium-sensor', unprivileged: true }] }));
      return;
    }

    if (req.url === '/v1/virt/pci') {
      res.end(JSON.stringify({ devices: [] }));
      return;
    }

    if (req.url === '/v1/virt/backups') {
      res.end(JSON.stringify({ backups: [] }));
      return;
    }

    if (req.url === '/v1/virt/telemetry') {
      res.end(JSON.stringify({ vnetInterfaces: [{ name: 'tap102i0', rxBytes: 4096 }], iommuGroupsCount: 8 }));
      return;
    }

    if (req.url === '/v1/k3s/telemetry') {
      res.end(JSON.stringify({ status: { running: true, clusterHa: true }, cniInterfaces: [{ name: 'cni0' }], bpfTokenProfiles: [] }));
      return;
    }

    if (req.url === '/v1/nas/telemetry') {
      res.end(
        JSON.stringify({
          arc: { hitRatioPercent: 98.4, sizeBytes: 4294967296 },
          zil: { zilCommitCount: 412 },
          pools: [{ name: 'tank', health: 'ONLINE' }],
        }),
      );
      return;
    }

    if (req.url === '/v1/nas/disks') {
      res.end(JSON.stringify({ disks: [{ name: 'nvme0n1' }] }));
      return;
    }

    if (req.url === '/v1/nas/snapshots') {
      if (req.method === 'POST') {
        const parsedBody = JSON.parse(body);
        res.end(JSON.stringify({ success: true, snapshot: `${parsedBody.dataset}@${parsedBody.label}` }));
        return;
      }
      res.end(JSON.stringify({ snapshots: ['tank/vms@auto-1'] }));
      return;
    }

    if (req.url === '/v1/nas/scrub') {
      res.end(JSON.stringify({ success: true, message: 'Started ZFS scrub on pool tank' }));
      return;
    }

    if (req.url === '/v1/nas/checkpoint') {
      const parsedBody = body ? JSON.parse(body) : {};
      res.end(JSON.stringify({ success: true, pool: parsedBody.pool, discard: Boolean(parsedBody.discard) }));
      return;
    }

    if (req.url === '/v1/nas/smart-test') {
      const parsedBody = body ? JSON.parse(body) : {};
      res.end(JSON.stringify({ success: true, device: parsedBody.device, testType: parsedBody.testType }));
      return;
    }

    if (req.url === '/v1/security/rootkit/status') {
      res.end(JSON.stringify({ verdict: 'CLEAN_HARDENED', bpfLsmAttached: true }));
      return;
    }

    if (req.url === '/v1/ebpf/xdp/syn-limit') {
      const parsedBody = body ? JSON.parse(body) : {};
      res.end(JSON.stringify({ success: true, maxSynPps: parsedBody.maxSynPps ?? 0 }));
      return;
    }

    if (req.url === '/v1/k3s/etcd-snapshots') {
      if (req.method === 'POST') {
        const parsedBody = body ? JSON.parse(body) : {};
        res.end(JSON.stringify({ success: true, action: parsedBody.action, name: parsedBody.name || 'auto' }));
        return;
      }
      res.end(JSON.stringify({ snapshots: [{ name: 'etcd-snapshot-k3s-1700000000' }] }));
      return;
    }

    res.writeHead(404);
    res.end('{}');
  });
});

await new Promise((resolve) => fakeDaemon.listen(agentSock, resolve));
after(() => {
  fakeDaemon.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('MCP eBPF, BPF_TOKEN_CREATE, Virtualization, K3s & NAS resources and tools enforce Ring-0 and anti-lockout invariants', async () => {
  // Verify catalog completeness
  for (const uri of [
    'axonwall://ebpf/dataplane',
    'axonwall://ebpf/bpf-tokens',
    'axonwall://virt/workloads',
    'axonwall://virt/libvirt-domains',
    'axonwall://k3s/cluster',
    'axonwall://k3s/etcd-snapshots',
    'axonwall://nas/storage-telemetry',
    'axonwall://security/rootkit-posture',
  ]) {
    assert.ok(MCP_RESOURCES_CATALOG.some((r) => r.uri === uri), `Missing resource ${uri}`);
  }

  for (const toolName of [
    'mcp_inspect_ebpf_dataplane',
    'mcp_xdp_fast_drop',
    'mcp_manage_bpf_token_profile',
    'mcp_inspect_virt_workloads',
    'mcp_control_virt_workload',
    'mcp_configure_lxc_bpf_token',
    'mcp_inspect_k3s_cluster',
    'mcp_manage_k3s_cluster',
    'mcp_render_k3s_bpf_token_manifest',
    'mcp_inspect_nas_storage',
    'mcp_nas_snapshot_or_scrub',
    'mcp_manage_zfs_nas',
    'mcp_import_competitor_config',
  ]) {
    assert.ok(MCP_TOOLS_CATALOG.some((t) => t.name === toolName), `Missing tool ${toolName}`);
  }

  // 1. Domain-scoped NAS read-only key can read NAS telemetry resource, but NOT system overview
  const { rawToken: nasReadToken } = createMcpApiKeyRecord({
    name: 'NAS Read-Only Analyst',
    agentType: 'readonly-analyst',
    scopes: ['mcp:nas:read'],
  });
  const nasAuth = authenticateMcpToken(nasReadToken, '10.80.0.50');
  assert.equal(nasAuth.authenticated, true);
  const nasEnv = { key: nasAuth.key, clientIp: '10.80.0.50' };

  const nasRes = await processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id: 1, method: 'resources/read', params: { uri: 'axonwall://nas/storage-telemetry' } },
    nasEnv,
  );
  assert.ok(!nasRes?.error);
  const nasBody = JSON.parse(nasRes.result.contents[0].text);
  assert.equal(nasBody.telemetry.arc.hitRatioPercent, 98.4);

  const deniedOverview = await processMcpJsonRpcMessage(
    { jsonrpc: '2.0', id: 2, method: 'resources/read', params: { uri: 'axonwall://system/overview' } },
    nasEnv,
  );
  assert.ok(deniedOverview?.error);

  // 2. Full eBPF + Virt + K3s + NAS SecOps key
  const { rawToken: opsToken } = createMcpApiKeyRecord({
    name: 'Cross-Duty eBPF Ops Agent',
    agentType: 'vigilsoc',
    scopes: [
      'mcp:ebpf:read',
      'mcp:ebpf:manage',
      'mcp:virt:read',
      'mcp:virt:manage',
      'mcp:k3s:read',
      'mcp:nas:manage',
    ],
    policyLimits: {
      maxIpv4PrefixLen: 24,
      maxIpv6PrefixLen: 64,
      maxTtlSeconds: 1800,
      allowedRedirectTargets: [],
    },
  });
  const opsAuth = authenticateMcpToken(opsToken, '10.80.0.50');
  assert.equal(opsAuth.authenticated, true);
  const opsEnv = { key: opsAuth.key, clientIp: '10.80.0.50' };

  // 3. XDP fast-drop rejects appliance IP & caller IP, allows external attacker IP (capped to maxTtlSeconds)
  const xdpSelfDrop = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'mcp_xdp_fast_drop',
        arguments: {
          action: 'block',
          ipAddress: '10.80.0.50',
          ttlSeconds: 600,
          audit: { reason: 'Attempt to XDP-drop own MCP caller IP' },
        },
      },
    },
    opsEnv,
  );
  assert.equal(xdpSelfDrop?.result?.isError, true);

  const xdpGoodDrop = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: {
        name: 'mcp_xdp_fast_drop',
        arguments: {
          action: 'block',
          ipAddress: '198.51.100.77',
          ttlSeconds: 7200, // exceeds key maxTtlSeconds=1800 -> bounded to 1800
          audit: { reason: 'Line-rate XDP drop for volumetric SYN flood source' },
        },
      },
    },
    opsEnv,
  );
  assert.ok(!xdpGoodDrop?.result?.isError);
  const xdpGoodPayload = JSON.parse(xdpGoodDrop.result.content[0].text);
  assert.equal(xdpGoodPayload.success, true);
  assert.equal(xdpGoodPayload.ttlSeconds, 1800);

  // 4. BPF_TOKEN profile rejects Ring-0 kprobe/lsm, allows safe network-dataplane preset
  const badToken = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: {
        name: 'mcp_manage_bpf_token_profile',
        arguments: {
          operation: 'upsert',
          id: 'evil-kprobe-token',
          preset: 'custom',
          delegateCmds: 'prog_load:map_create',
          delegateProgs: 'xdp:kprobe',
          delegateMaps: 'hash',
          delegateAttachs: 'xdp',
          audit: { reason: 'Attempt to smuggle kprobe into UserNS BPF_TOKEN' },
        },
      },
    },
    opsEnv,
  );
  assert.equal(badToken?.result?.isError, true);
  assert.ok(badToken.result.content[0].text.includes('bpf_probe_read_kernel'));

  const goodToken = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 6,
      method: 'tools/call',
      params: {
        name: 'mcp_manage_bpf_token_profile',
        arguments: {
          operation: 'upsert',
          id: 'k3s-cilium-dataplane',
          targetKind: 'k3s-pod',
          preset: 'network-dataplane',
          audit: { reason: 'Provision safe UserNS networking BPF_TOKEN profile for Cilium' },
        },
      },
    },
    opsEnv,
  );
  assert.ok(!goodToken?.result?.isError);

  // 5. Configure LXC BPF_TOKEN rejects privileged CT 206, succeeds on unprivileged CT 205
  const deniedPrivLxc = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: {
        name: 'mcp_configure_lxc_bpf_token',
        arguments: {
          ctid: 206,
          enabled: true,
          preset: 'network-dataplane',
          audit: { reason: 'Attempt BPF_TOKEN on privileged container without CLONE_NEWUSER' },
        },
      },
    },
    opsEnv,
  );
  assert.equal(deniedPrivLxc?.result?.isError, true);
  assert.ok(deniedPrivLxc.result.content[0].text.includes('unprivileged: false'));

  const okUnprivLxc = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 8,
      method: 'tools/call',
      params: {
        name: 'mcp_configure_lxc_bpf_token',
        arguments: {
          ctid: 205,
          enabled: true,
          preset: 'network-dataplane',
          audit: { reason: 'Enable Linux 6.9+ bpffs delegation for unprivileged Cilium sensor CT 205' },
        },
      },
    },
    opsEnv,
  );
  assert.ok(!okUnprivLxc?.result?.isError);
  const lxcPayload = JSON.parse(okUnprivLxc.result.content[0].text);
  assert.equal(lxcPayload.success, true);
  assert.ok(lxcPayload.compiledBpfDirectives.some((l) => l.includes('LIBBPF_BPF_TOKEN_PATH=/sys/fs/bpf')));
  assert.ok(lxcPayload.compiledBpfDirectives.some((l) => l.includes('delegate_progs=')));

  // 6. Virt anti-lockout blocks stopping Hosted Edge VM 100, allows rebooting workload VM 102 (mapped to 'reset')
  const stopEdge = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 9,
      method: 'tools/call',
      params: {
        name: 'mcp_control_virt_workload',
        arguments: {
          workloadType: 'vm',
          id: 100,
          action: 'stop',
          audit: { reason: 'Attempt to stop Hosted Edge NGFW transit VM' },
        },
      },
    },
    opsEnv,
  );
  assert.equal(stopEdge?.result?.isError, true);
  assert.ok(stopEdge.result.content[0].text.includes('Anti-lockout guard'));

  const rebootWorkload = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 10,
      method: 'tools/call',
      params: {
        name: 'mcp_control_virt_workload',
        arguments: {
          workloadType: 'vm',
          id: 102,
          action: 'reboot',
          audit: { reason: 'Reboot guest workload VM 102 after kernel update' },
        },
      },
    },
    opsEnv,
  );
  assert.ok(!rebootWorkload?.result?.isError);
  assert.equal(JSON.parse(rebootWorkload.result.content[0].text).result.action, 'reset');

  // 7. Render K3s BPF_TOKEN manifest & trigger ZFS snapshot
  const k3sManifest = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 11,
      method: 'tools/call',
      params: {
        name: 'mcp_render_k3s_bpf_token_manifest',
        arguments: {
          profileId: 'k3s-cilium-dataplane',
          preset: 'network-dataplane',
          workloadName: 'packet-sensor',
          kind: 'DaemonSet',
        },
      },
    },
    opsEnv,
  );
  assert.ok(!k3sManifest?.result?.isError);
  assert.ok(JSON.parse(k3sManifest.result.content[0].text).manifestYaml.includes('hostUsers: false'));

  const zfsSnap = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 12,
      method: 'tools/call',
      params: {
        name: 'mcp_nas_snapshot_or_scrub',
        arguments: {
          action: 'snapshot',
          target: 'tank/vms',
          snapshotLabel: 'pre-maintenance',
          audit: { reason: 'Create atomic ZFS snapshot prior to hypervisor maintenance' },
        },
      },
    },
    opsEnv,
  );
  assert.ok(!zfsSnap?.result?.isError);
  assert.equal(JSON.parse(zfsSnap.result.content[0].text).snapshot, 'tank/vms@pre-maintenance');

  // 8. Parity-Plus: XDP LPM CIDR drop + Ring-0 SYN-flood PPS rate-limiter floor enforcement
  const cidrBlock = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 13,
      method: 'tools/call',
      params: {
        name: 'mcp_xdp_fast_drop',
        arguments: {
          action: 'block',
          ipAddress: '198.51.100.0/24',
          audit: { reason: 'Drop malicious /24 BGP hijack range in XDP LPM trie' },
        },
      },
    },
    opsEnv,
  );
  assert.ok(!cidrBlock?.result?.isError);
  const cidrParsed = JSON.parse(cidrBlock.result.content[0].text);
  assert.equal(cidrParsed.ipAddress, '198.51.100.0/24');
  assert.equal(cidrParsed.isCidr, true);

  const synTooLow = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 14,
      method: 'tools/call',
      params: {
        name: 'mcp_xdp_fast_drop',
        arguments: {
          action: 'set_syn_limit',
          synFloodLimitPps: 5,
          audit: { reason: 'Attempt dangerously low 5 PPS SYN limit' },
        },
      },
    },
    opsEnv,
  );
  assert.equal(synTooLow?.result?.isError, true);

  const synValid = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 15,
      method: 'tools/call',
      params: {
        name: 'mcp_xdp_fast_drop',
        arguments: {
          action: 'set_syn_limit',
          synFloodLimitPps: 5000,
          audit: { reason: 'Enable 5000 PPS Ring-0 TCP SYN-flood shield' },
        },
      },
    },
    opsEnv,
  );
  assert.ok(!synValid?.result?.isError);
  assert.equal(JSON.parse(synValid.result.content[0].text).synFloodLimitPps, 5000);

  // 9. Parity-Plus: Competitor migration import (Proxmox VE & TrueNAS SCALE) + RBAC scope enforcement
  const { rawToken: fwOnlyToken } = createMcpApiKeyRecord({
    name: 'Firewall Migration Agent',
    agentType: 'custom-ai',
    scopes: ['mcp:firewall:write'],
  });
  const fwOnlyEnv = { key: authenticateMcpToken(fwOnlyToken, '10.80.0.50').key, clientIp: '10.80.0.50' };

  const proxmoxRaw = [
    '# /etc/pve/qemu-server/301.conf',
    'name: pve-migrated-db',
    'cores: 4',
    'memory: 8192',
    'bios: ovmf',
    'tpmstate0: local-zfs:vm-301-disk-1,version=v2.0',
    'scsi0: local-zfs:vm-301-disk-0,size=64G',
    'net0: virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=20',
  ].join('\n');

  // Dry-run succeeds with mcp:firewall:write alone
  const pveDryRun = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 16,
      method: 'tools/call',
      params: {
        name: 'mcp_import_competitor_config',
        arguments: {
          rawConfig: proxmoxRaw,
          stageToDesiredState: false,
          audit: { reason: 'Dry-run Proxmox VE 8.x VM migration analysis' },
        },
      },
    },
    fwOnlyEnv,
  );
  assert.ok(!pveDryRun?.result?.isError);
  const pveDryParsed = JSON.parse(pveDryRun.result.content[0].text);
  assert.equal(pveDryParsed.vendor, 'proxmox');
  assert.equal(pveDryParsed.summary.vmsImported, 1);

  // Staging Proxmox VM without mcp:virt:manage is denied
  const pveDeniedStage = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 17,
      method: 'tools/call',
      params: {
        name: 'mcp_import_competitor_config',
        arguments: {
          rawConfig: proxmoxRaw,
          stageToDesiredState: true,
          audit: { reason: 'Attempt to stage Proxmox VM without mcp:virt:manage' },
        },
      },
    },
    fwOnlyEnv,
  );
  assert.equal(pveDeniedStage?.result?.isError, true);

  // TrueNAS SCALE dry-run auto-detection
  const truenasRaw = JSON.stringify({
    version: 'TrueNAS-SCALE-24.10.1',
    pools: [{ name: 'rustpool', topology: { data: [{ type: 'RAIDZ2', disks: ['sda', 'sdb', 'sdc', 'sdd'] }] } }],
    datasets: [{ id: 'rustpool/media', pool: 'rustpool', compression: 'ZSTD', encryption: true }],
    sharing_smb: [{ name: 'media', path: '/mnt/rustpool/media', timemachine: true }],
  });
  const tnDryRun = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 18,
      method: 'tools/call',
      params: {
        name: 'mcp_import_competitor_config',
        arguments: {
          rawConfig: truenasRaw,
          audit: { reason: 'Dry-run TrueNAS SCALE storage & SMB migration' },
        },
      },
    },
    fwOnlyEnv,
  );
  assert.ok(!tnDryRun?.result?.isError);
  const tnParsed = JSON.parse(tnDryRun.result.content[0].text);
  assert.equal(tnParsed.vendor, 'truenas');
  assert.equal(tnParsed.summary.poolsImported, 1);
  assert.equal(tnParsed.summary.sharesImported, 1);

  // Paired mcp_manage_zfs_nas checkpoint & SMART self-test execution
  const zfsCkpt = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 19,
      method: 'tools/call',
      params: {
        name: 'mcp_manage_zfs_nas',
        arguments: {
          action: 'checkpoint',
          target: 'tank',
          audit: { reason: 'Create whole-pool ZFS checkpoint prior to schema upgrade' },
        },
      },
    },
    opsEnv,
  );
  assert.ok(!zfsCkpt?.result?.isError);
  assert.equal(JSON.parse(zfsCkpt.result.content[0].text).action, 'checkpoint');

  const smartRun = await processMcpJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 20,
      method: 'tools/call',
      params: {
        name: 'mcp_manage_zfs_nas',
        arguments: {
          action: 'smart_test',
          target: '/dev/nvme0n1',
          smartTestType: 'short',
          audit: { reason: 'Run proactive NVMe short SMART self-test' },
        },
      },
    },
    opsEnv,
  );
  assert.ok(!smartRun?.result?.isError);
  assert.equal(JSON.parse(smartRun.result.content[0].text).action, 'smart_test');

  // 10. Verify unbroken SHA-256 hash-chained audit trail across all allowed & denied operations
  const chain = verifyMcpAuditChain();
  assert.equal(chain.valid, true);
  assert.ok(chain.totalEntries >= 16);
});
