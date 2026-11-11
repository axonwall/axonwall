import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import {
  McpBlackholeRequestSchema,
  McpShapeRequestSchema,
  McpRedirectRequestSchema,
  McpDnsSinkholeRequestSchema,
  McpPcapSampleRequestSchema,
  McpProposeRuleRequestSchema,
  McpXdpFastDropRequestSchema,
  McpManageBpfTokenProfileRequestSchema,
  McpVirtControlRequestSchema,
  McpConfigureLxcBpfTokenRequestSchema,
  McpRenderK3sBpfTokenRequestSchema,
  McpNasActionRequestSchema,
  McpK3sManageRequestSchema,
  McpImportCompetitorRequestSchema,
  parseIpOrCidr,
  validateMcpTarget,
  validateRedirectTargetAllowlist,
  validateBpfTokenDelegationInput,
  validateVirtWorkloadSafety,
  validateZfsResourcePath,
  getMcpServerStatus,
  type McpApiKey,
  type McpGuardContext,
  type McpScope,
} from '@axonwall/lib/mcp';
import { DesiredStateSchema, type DesiredState } from '@axonwall/lib/schemas';
import { importFirewallConfig, mergeFirewallConfigs } from '@axonwall/lib/import';
import { compileNftables } from '@axonwall/lib/compile/nft';
import { compileLxcContainer } from '@axonwall/lib/compile/virt';
import { serializeDesiredStateToYamlFiles } from '@axonwall/lib/yaml';
import { hasMcpScope } from './authz.js';
import { acquireMcpLockFile, desiredStateLockPath } from './lockfile.js';
export { desiredStateLockPath } from './lockfile.js';
import { recordMcpAuditEntry, queryMcpAuditEntries } from './audit.js';

const AGENT_SOCKET_PATH = process.env.AXONWALL_AGENT_API_SOCK || '/run/axonwall/agent-api.sock';
const AGENT_TOKEN_PATHS = [
  '/etc/axonwall/agent.token',
  '/var/lib/axonwall/etc-axonwall/agent.token',
  '/run/axonwall/agent.token',
];

function readAgentToken(): string {
  if (process.env.AXONWALL_AGENT_TOKEN) {
    return process.env.AXONWALL_AGENT_TOKEN.trim();
  }
  for (const p of AGENT_TOKEN_PATHS) {
    try {
      if (fs.existsSync(p)) {
        const tok = fs.readFileSync(p, 'utf8').trim();
        if (tok) return tok;
      }
    } catch {
      // Try next path
    }
  }
  return '';
}

// B2-M2: apply job ids. The daemon requires an exact job-id
// match to confirm an apply, and the propose response must return
// the id so the caller can confirm it (previously the id was
// generated server-side and never returned, so every
// applyImmediately rule auto-rolled back). A bare Date.now() id
// also collides when two applies land in the same millisecond
// against the daemon's single pending slot, so the id carries a
// random suffix.
export function newMcpApplyJobId(): string {
  return `mcp_apply_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

// B2-M4: insert a proposed rule into a DesiredState, preserving
// the established ordering (block/reject rules go before the
// first pass rule, everything else appends). Split out so the
// locked reload-mutate-persist section in propose_firewall_rule
// and its rollback path apply exactly the same mutation.
export function insertMcpRuleIntoState(targetState: DesiredState, rule: DesiredState['rules'][number]): void {
  const isBlockOrReject = rule.action === 'block' || rule.action === 'reject';
  if (isBlockOrReject) {
    const firstPassIdx = targetState.rules.findIndex((r) => r.action === 'pass');
    if (firstPassIdx !== -1) {
      targetState.rules.splice(firstPassIdx, 0, rule);
    } else {
      targetState.rules.push(rule);
    }
  } else {
    targetState.rules.push(rule);
  }
}

export async function callAxonwalldApi<T = any>(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  pathUrl: string,
  body?: unknown,
  timeoutMs = 15000
): Promise<{ ok: boolean; status: number; data: T }> {
  if (!fs.existsSync(AGENT_SOCKET_PATH)) {
    return {
      ok: false,
      status: 503,
      data: { error: `axonwalld socket not available at ${AGENT_SOCKET_PATH}` } as unknown as T,
    };
  }

  const token = readAgentToken();
  const payloadStr = body !== undefined ? JSON.stringify(body) : undefined;

  return new Promise((resolve) => {
    const req = http.request(
      {
        socketPath: AGENT_SOCKET_PATH,
        path: pathUrl,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'X-Axonwall-Agent-Token': token } : {}),
          ...(payloadStr ? { 'Content-Length': Buffer.byteLength(payloadStr) } : {}),
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let parsed: any = raw;
          try {
            parsed = raw ? JSON.parse(raw) : {};
          } catch {
            parsed = { raw };
          }
          const status = res.statusCode || 500;
          resolve({
            ok: status >= 200 && status < 300,
            status,
            data: parsed as T,
          });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({
        ok: false,
        status: 504,
        data: { error: 'axonwalld request timed out' } as unknown as T,
      });
    });

    req.on('error', (err) => {
      resolve({
        ok: false,
        status: 502,
        data: { error: err.message } as unknown as T,
      });
    });

    if (payloadStr) {
      req.write(payloadStr);
    }
    req.end();
  });
}

function loadLocalDesiredState(): DesiredState | null {
  const customState = process.env.AXONWALL_STATE_JSON_PATH || process.env.AXONWALL_STATE_FILE;
  const candidates = [
    ...(customState ? [customState] : []),
    '/etc/axonwall/state.json',
    '/var/lib/axonwall/state.json',
  ];
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) {
        const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
        const parsed = DesiredStateSchema.safeParse(raw);
        if (parsed.success) return parsed.data;
      }
    } catch {
      // continue
    }
  }
  return null;
}

function persistDesiredStateToDisk(targetState: DesiredState): void {
  const customState = process.env.AXONWALL_STATE_JSON_PATH || process.env.AXONWALL_STATE_FILE;
  if (customState) {
    try {
      fs.mkdirSync(path.dirname(customState), { recursive: true, mode: 0o770 });
      fs.writeFileSync(customState, JSON.stringify(targetState, null, 2), { mode: 0o600 });
      const yamlFiles = serializeDesiredStateToYamlFiles(targetState);
      const customDir = path.dirname(customState);
      for (const [fn, content] of Object.entries(yamlFiles)) {
        fs.writeFileSync(path.join(customDir, fn), content, { mode: 0o660 });
      }
    } catch {
      // ignore custom override errors
    }
    return;
  }
  try {
    fs.writeFileSync('/etc/axonwall/state.json', JSON.stringify(targetState, null, 2), { mode: 0o600 });
  } catch {
    // Fallback if /etc/axonwall not writable in dev
  }
  try {
    fs.writeFileSync('/var/lib/axonwall/state.json', JSON.stringify(targetState, null, 2), { mode: 0o600 });
  } catch {}
  try {
    const yamlFiles = serializeDesiredStateToYamlFiles(targetState);
    for (const dir of ['/etc/axonwall', '/var/lib/axonwall/etc-axonwall']) {
      if (fs.existsSync(dir)) {
        for (const [fn, content] of Object.entries(yamlFiles)) {
          fs.writeFileSync(`${dir}/${fn}`, content, { mode: 0o660 });
        }
      }
    }
  } catch {}
}

function resolveBpfTokenPresetMasks(preset: string): {
  delegateCmds: string;
  delegateProgs: string;
  delegateMaps: string;
  delegateAttachs: string;
} {
  switch (preset) {
    case 'socket-observability':
      return {
        delegateCmds: 'prog_load:map_create:map_lookup_elem:map_update_elem:btf_load:link_create',
        delegateProgs: 'socket_filter:cgroup_skb',
        delegateMaps: 'hash:array:percpu_array:ringbuf:lru_hash',
        delegateAttachs: 'cgroup_inet_ingress:cgroup_inet_egress',
      };
    case 'cgroup-microsegmentation':
      return {
        delegateCmds: 'prog_load:map_create:map_lookup_elem:map_update_elem:map_delete_elem:btf_load:link_create',
        delegateProgs: 'cgroup_skb:cgroup_sock:cgroup_sock_addr:sk_skb:sk_msg',
        delegateMaps: 'hash:array:percpu_hash:lru_hash:ringbuf:sockmap:sockhash',
        delegateAttachs: 'cgroup_inet_ingress:cgroup_inet_egress:cgroup_inet4_connect:cgroup_inet6_connect:sk_skb_stream_verdict',
      };
    case 'network-dataplane':
    default:
      return {
        delegateCmds: 'prog_load:map_create:map_lookup_elem:map_update_elem:map_delete_elem:btf_load:link_create:obj_pin',
        delegateProgs: 'xdp:sched_cls:sched_act:socket_filter:cgroup_skb',
        delegateMaps: 'hash:array:percpu_hash:percpu_array:lru_hash:lru_percpu_hash:ringbuf:lpm_trie',
        delegateAttachs: 'xdp:tcx_ingress:tcx_egress:cgroup_inet_ingress:cgroup_inet_egress',
      };
  }
}

function renderOfflineK3sBpfTokenYaml(params: {
  profileId: string;
  preset: string;
  workloadName: string;
  namespace: string;
  image: string;
  kind: 'Pod' | 'DaemonSet';
}): string {
  const masks = resolveBpfTokenPresetMasks(params.preset);
  const hostPinPath = `/run/axonwall/bpf-tokens/${params.profileId}`;
  const podSpec = [
    `hostUsers: false`,
    `automountServiceAccountToken: false`,
    `securityContext:`,
    `  seccompProfile:`,
    `    type: RuntimeDefault`,
    `containers:`,
    `  - name: ebpf-agent`,
    `    image: ${params.image}`,
    `    env:`,
    `      - name: LIBBPF_BPF_TOKEN_PATH`,
    `        value: "/sys/fs/bpf"`,
    `    securityContext:`,
    `      allowPrivilegeEscalation: false`,
    `      capabilities:`,
    `        drop: ["ALL"]`,
    `        add: ["BPF", "NET_ADMIN"]`,
    `    volumeMounts:`,
    `      - name: delegated-bpffs`,
    `        mountPath: /sys/fs/bpf`,
    `volumes:`,
    `  - name: delegated-bpffs`,
    `    hostPath:`,
    `      path: ${hostPinPath}`,
    `      type: Directory`,
  ];
  const header = [
    `# Generated by Axonwall Linux 6.9+ BPF_TOKEN_CREATE K3s Compiler`,
    `# Profile: ${params.profileId} (Preset: ${params.preset})`,
    `# Delegated bpffs options: delegate_cmds=${masks.delegateCmds},delegate_progs=${masks.delegateProgs},delegate_maps=${masks.delegateMaps},delegate_attachs=${masks.delegateAttachs}`,
    `# Ring-0 Guard: kprobe/tracepoint/lsm/perf_event/tracing blocked by Axonwall BPF-LSM`,
  ].join('\n');

  if (params.kind === 'DaemonSet') {
    const indented = podSpec.map((l) => `      ${l}`).join('\n');
    return `${header}
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ${params.workloadName}
  namespace: ${params.namespace}
  labels:
    app.kubernetes.io/name: ${params.workloadName}
    axonwall.io/bpf-token-profile: ${params.profileId}
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: ${params.workloadName}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ${params.workloadName}
        axonwall.io/bpf-token-profile: ${params.profileId}
    spec:
${indented}
`;
  }
  const indented = podSpec.map((l) => `  ${l}`).join('\n');
  return `${header}
apiVersion: v1
kind: Pod
metadata:
  name: ${params.workloadName}
  namespace: ${params.namespace}
  labels:
    app.kubernetes.io/name: ${params.workloadName}
    axonwall.io/bpf-token-profile: ${params.profileId}
spec:
${indented}
`;
}

async function buildGuardContext(key: McpApiKey, clientIp: string): Promise<{
  ctx: McpGuardContext;
  activeLeasesCount: number;
}> {
  const applianceHostIps = new Set<string>(['192.168.1.1']);
  const gatewayAndHaIps = new Set<string>();
  const antiLockoutPorts = new Set<number>([2966, 22, 9876]);
  let activeLeasesCount = 0;

  // 1. Inspect local DesiredState
  const state = loadLocalDesiredState();
  if (state) {
    for (const p of state.system?.antiLockout?.ports ?? []) {
      antiLockoutPorts.add(p);
    }
    for (const iface of state.interfaces ?? []) {
      if (iface.ipv4Address) applianceHostIps.add(iface.ipv4Address.split('/')[0]!);
      if (iface.ipv6Address) applianceHostIps.add(iface.ipv6Address.split('/')[0]!);
      if (iface.ipv4Gateway) gatewayAndHaIps.add(iface.ipv4Gateway.split('/')[0]!);
      if (iface.ipv6Gateway) gatewayAndHaIps.add(iface.ipv6Gateway.split('/')[0]!);
    }
    for (const gw of state.gateways ?? []) {
      if (gw.gatewayIp) gatewayAndHaIps.add(gw.gatewayIp.split('/')[0]!);
    }
    if (state.ha?.peerIp) gatewayAndHaIps.add(state.ha.peerIp.split('/')[0]!);
    if (state.ha?.peerAddress) gatewayAndHaIps.add(state.ha.peerAddress.split('/')[0]!);
  }

  // 2. Query live posture & leases from axonwalld if running
  const postureRes = await callAxonwalldApi('GET', '/v1/mcp/posture');
  if (postureRes.ok && postureRes.data) {
    for (const ip of postureRes.data.posture?.applianceIps ?? []) {
      applianceHostIps.add(ip);
    }
    for (const ip of postureRes.data.posture?.gatewayAndHaIps ?? []) {
      gatewayAndHaIps.add(ip);
    }
    for (const p of postureRes.data.posture?.antiLockoutPorts ?? []) {
      antiLockoutPorts.add(Number(p));
    }
    if (Array.isArray(postureRes.data.leases)) {
      activeLeasesCount = postureRes.data.leases.filter(
        (l: any) => l.createdByKeyId === key.id
      ).length;
    }
  }

  return {
    ctx: {
      applianceHostIps: Array.from(applianceHostIps),
      gatewayAndHaIps: Array.from(gatewayAndHaIps),
      callerIp: clientIp,
      antiLockoutPorts: Array.from(antiLockoutPorts),
      policyLimits: key.policyLimits,
    },
    activeLeasesCount,
  };
}

// ============================================================================
// MCP Tool & Resource Definitions
// ============================================================================

export const MCP_RESOURCES_CATALOG = [
  {
    uri: 'axonwall://system/overview',
    name: 'Axonwall Appliance & Security Posture Overview',
    description: 'Appliance version, interfaces, protected management IPs, HA status, and active MCP key policy limits.',
    mimeType: 'application/json',
  },
  {
    uri: 'axonwall://telemetry/interfaces',
    name: 'Live Interface Traffic Counters',
    description: 'Real-time RX/TX bytes, packets, drops, and errors across all firewall interfaces.',
    mimeType: 'application/json',
  },
  {
    uri: 'axonwall://telemetry/alerts/suricata',
    name: 'Suricata IDS/IPS Threat Alerts',
    description: 'Recent Suricata EVE JSON threat alerts, anomalies, and DNS/TLS inspection events.',
    mimeType: 'application/json',
  },
  {
    uri: 'axonwall://telemetry/flows/top',
    name: 'Top Active Conntrack Network Flows',
    description: 'Highest-volume active kernel conntrack sessions ranked by bytes transferred.',
    mimeType: 'application/json',
  },
  {
    uri: 'axonwall://firewall/tactical-leases',
    name: 'Active AI / MCP Tactical Traffic Control Leases',
    description: 'All currently active TTL-bounded blackholes, tc shapers/tarpits, DNAT redirects, and DNS sinkholes.',
    mimeType: 'application/json',
  },
  {
    uri: 'axonwall://firewall/ruleset-summary',
    name: 'Declarative Firewall, NAT & Shaper Summary',
    description: 'Redacted summary of declarative firewall rules, NAT mappings, aliases, static routes, and QoS queues.',
    mimeType: 'application/json',
  },
  {
    uri: 'axonwall://topology/nastymap',
    name: 'NastyMap Network Topology & Host Inventory',
    description: 'Discovered LAN/OPT hosts, ARP neighbor table, and DHCP leases.',
    mimeType: 'application/json',
  },
  {
    uri: 'axonwall://audit/mcp-trail',
    name: 'Tamper-Evident MCP Audit Trail',
    description: 'Recent SHA-256 hash-chained MCP tool invocation records and chain verification status.',
    mimeType: 'application/json',
  },
  {
    uri: 'axonwall://ebpf/dataplane',
    name: 'Ring-0 eBPF XDP Dataplane & BPF-LSM Posture',
    description:
      'Dual-stack IPv4/IPv6 + 802.1Q/802.1ad VLAN XDP LRU flow telemetry, per-CPU XDP PASS/DROP verdicts, active TTL-bounded XDP drops, and 5-hook CO-RE BPF-LSM enforcement events.',
    mimeType: 'application/json',
  },
  {
    uri: 'axonwall://ebpf/bpf-tokens',
    name: 'Linux 6.9+ BPF_TOKEN_CREATE Unprivileged Delegation Registry',
    description:
      'Kernel BTF capabilities (BPF_TOKEN_CREATE, lsm/bpf_token_create, lsm/bpf_token_cmd), curated least-privilege presets, configured delegation profiles, and live /proc/self/mountinfo bpffs delegations.',
    mimeType: 'application/json',
  },
  {
    uri: 'axonwall://virt/workloads',
    name: 'KVM Virtual Machines, Unprivileged LXC & vnet eBPF Telemetry',
    description:
      'KVM/QEMU guests, LXC containers (including CLONE_NEWUSER + BPF_TOKEN status), VFIO/IOMMU PCI inventory, and host TAP/veth XDP/traffic counters.',
    mimeType: 'application/json',
  },
  {
    uri: 'axonwall://k3s/cluster',
    name: 'K3s Kubernetes Cluster, CNI & UserNS BPF_TOKEN Posture',
    description:
      'K3s HA control-plane status, nodes, OpenEBS ZFS PVCs, CNI bridge/vxlan dataplane counters, and K3s UserNS BPF_TOKEN delegation profiles.',
    mimeType: 'application/json',
  },
  {
    uri: 'axonwall://nas/storage-telemetry',
    name: 'OpenZFS Deep Storage, ARC/L2ARC & ZIL/SLOG Telemetry',
    description:
      'ZFS pool health, dataset utilization, /proc/spl/kstat/zfs/arcstats hit/miss ratios, ZIL/SLOG sync commit counters, per-pool ZIO queue depth, snapshots, and SMB/NFS/iSCSI status.',
    mimeType: 'application/json',
  },
  {
    uri: 'axonwall://security/rootkit-posture',
    name: 'Ghost-in-the-Ring Kernel & io_uring Rootkit Posture',
    description:
      'BPF-LSM (s_dev, i_ino) binary allowlist, io_uring ring auditing, hidden LKM/BPF checks, and UserNS BPF_TOKEN Ring-0 isolation verdicts.',
    mimeType: 'application/json',
  },
  {
    uri: 'axonwall://k3s/etcd-snapshots',
    name: 'K3s Embedded Etcd Disaster Recovery Snapshots',
    description:
      'Inventory of embedded etcd cluster snapshots stored on the appliance for single-click K3s HA control-plane recovery.',
    mimeType: 'application/json',
  },
  {
    uri: 'axonwall://virt/libvirt-domains',
    name: 'Libvirt XML Domain Definitions for KVM Virtual Machines',
    description:
      'Standard <domain type=\'kvm\'> Libvirt XML definitions exported for all registered KVM/QEMU virtual machines.',
    mimeType: 'application/json',
  },
];

export const MCP_TOOLS_CATALOG = [
  {
    name: 'mcp_query_flows',
    description:
      'Query live Linux kernel conntrack flows (/proc/net/nf_conntrack) to inspect active connections, byte volume, protocol, and NAT states. Requires scope: mcp:telemetry:read.',
    inputSchema: {
      type: 'object',
      properties: {
        srcIp: { type: 'string', description: 'Filter by source IP address' },
        dstIp: { type: 'string', description: 'Filter by destination IP address' },
        protocol: { type: 'string', enum: ['any', 'tcp', 'udp', 'icmp'], default: 'any' },
        state: { type: 'string', description: 'Optional TCP state filter (e.g. ESTABLISHED, SYN_SENT)' },
        port: { type: 'number', description: 'Filter by source or destination port (1-65535)' },
        minBytes: { type: 'number', description: 'Minimum bytes transferred' },
        limit: { type: 'number', default: 50, description: 'Max flows to return (1-500)' },
      },
    },
  },
  {
    name: 'mcp_query_threat_events',
    description:
      'Search Suricata IDS/IPS EVE threat alerts and active SOAR/MCP blocklists. Requires scope: mcp:telemetry:read.',
    inputSchema: {
      type: 'object',
      properties: {
        srcIp: { type: 'string', description: 'Filter alerts by source IP' },
        dstIp: { type: 'string', description: 'Filter alerts by destination IP' },
        signatureContains: { type: 'string', description: 'Case-insensitive substring match on alert signature' },
        limit: { type: 'number', default: 50 },
      },
    },
  },
  {
    name: 'mcp_inspect_host_context',
    description:
      'Retrieve comprehensive 360-degree forensics on a single IP: ARP/MAC neighbor entry, Kea DHCP lease hostname, active conntrack flows, Suricata IDS alerts, and active MCP tactical leases. Requires scope: mcp:telemetry:read.',
    inputSchema: {
      type: 'object',
      properties: {
        ipAddress: { type: 'string', description: 'IPv4 or IPv6 host address to inspect' },
      },
      required: ['ipAddress'],
    },
  },
  {
    name: 'mcp_capture_packet_sample',
    description:
      'Run a strictly bounded live BPF packet capture (max 100 packets, max 15s) on a firewall interface and return dissected packet headers/info. Requires scope: mcp:pcap:capture.',
    inputSchema: {
      type: 'object',
      properties: {
        interface: { type: 'string', default: 'wan', description: 'Logical or kernel interface name (wan, lan, opt1, any)' },
        srcIp: { type: 'string', description: 'Optional source host IP filter' },
        dstIp: { type: 'string', description: 'Optional destination host IP filter' },
        protocol: { type: 'string', enum: ['any', 'tcp', 'udp', 'icmp', 'icmp6', 'arp'], default: 'any' },
        port: { type: 'number', description: 'Optional L4 port filter (1-65535)' },
        maxPackets: { type: 'number', default: 25, description: 'Number of packets to capture (1-100)' },
        durationSeconds: { type: 'number', default: 5, description: 'Capture timeout in seconds (1-15)' },
      },
    },
  },
  {
    name: 'mcp_blackhole_traffic',
    description:
      'Immediately blackhole/quarantine an offending IP or CIDR at the kernel level (nftables table inet axonwall_mcp drop/reject or kernel blackhole route), optionally severing established C2 sockets via conntrack -D and broadcasting to fleet satellites. Protected appliance/gateway/caller IPs and anti-lockout ports are strictly immune. Requires scope: mcp:traffic:blackhole.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Target IP or CIDR (must satisfy key blast-radius prefix limit, e.g. >= /24)' },
        mode: { type: 'string', enum: ['nft_drop', 'nft_reject', 'route_blackhole'], default: 'nft_drop' },
        direction: { type: 'string', enum: ['both', 'inbound', 'outbound'], default: 'both' },
        protocol: { type: 'string', enum: ['any', 'tcp', 'udp', 'icmp'], default: 'any' },
        port: { type: 'number', description: 'Optional specific L4 destination port to block (1-65535)' },
        killActiveConnections: { type: 'boolean', default: true, description: 'Sever established conntrack sessions immediately' },
        propagateToFleet: { type: 'boolean', default: false, description: 'Broadcast block to connected fleet satellites (requires mcp:fleet:broadcast)' },
        ttlSeconds: { type: 'number', default: 3600, description: 'Mandatory self-healing lease TTL in seconds (10-604800)' },
        audit: {
          type: 'object',
          properties: {
            reason: { type: 'string', description: 'Detailed security justification (min 10 chars)' },
            incidentId: { type: 'string' },
            mitreTechniqueId: { type: 'string', description: 'Optional MITRE ATT&CK ID (e.g. T1071.001)' },
            confidence: { type: 'number' },
          },
          required: ['reason'],
        },
      },
      required: ['target', 'audit'],
    },
  },
  {
    name: 'mcp_shape_traffic',
    description:
      'Dynamically throttle bandwidth (Linux tc HTB) and/or inject artificial tarpit latency, jitter, or packet loss (tc netem) and DSCP markings for a suspicious IP or subnet (e.g. suspected data exfiltration or aggressive scanner). Requires scope: mcp:traffic:shape.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Target IP or CIDR to throttle/tarpit' },
        interface: { type: 'string', default: 'wan', description: 'Interface to attach shaper class on' },
        direction: { type: 'string', enum: ['both', 'egress', 'ingress'], default: 'both' },
        rateKbps: { type: 'number', description: 'Guaranteed/throttled bandwidth in kbps (min 8)' },
        ceilKbps: { type: 'number', description: 'Ceiling bandwidth in kbps' },
        latencyMs: { type: 'number', default: 0, description: 'Injected tarpit delay in ms (0-5000)' },
        jitterMs: { type: 'number', default: 0, description: 'Delay jitter in ms (0-1000)' },
        packetLossPercent: { type: 'number', default: 0, description: 'Artificial packet loss % (0-50)' },
        dscpMark: { type: 'number', description: 'Optional DSCP codepoint (0-63) to stamp on packets' },
        ttlSeconds: { type: 'number', default: 3600 },
        audit: {
          type: 'object',
          properties: {
            reason: { type: 'string' },
            incidentId: { type: 'string' },
            mitreTechniqueId: { type: 'string' },
            confidence: { type: 'number' },
          },
          required: ['reason'],
        },
      },
      required: ['target', 'rateKbps', 'audit'],
    },
  },
  {
    name: 'mcp_redirect_traffic',
    description:
      'Transparently steer traffic from a specific attacker IP/CIDR toward an isolated deception honeypot (attacker-scoped DNAT in table inet axonwall_mcp) or policy-routing scrubbing gateway without affecting normal users. Target destination MUST be in the MCP key allowedRedirectTargets allowlist. Requires scope: mcp:traffic:redirect.',
    inputSchema: {
      type: 'object',
      properties: {
        source: { type: 'string', description: 'Attacker source IP or CIDR to redirect' },
        originalDstIp: { type: 'string', description: 'Optional original destination IP being targeted' },
        originalDstPort: { type: 'number', description: 'Optional original destination port (e.g. 22, 445, 3389)' },
        protocol: { type: 'string', enum: ['tcp', 'udp', 'any'], default: 'tcp' },
        redirectType: { type: 'string', enum: ['dnat_honeypot', 'policy_route'], default: 'dnat_honeypot' },
        targetDestination: {
          type: 'string',
          description: 'Honeypot IP[:port] or policy-route gateway IP (must match key allowedRedirectTargets)',
        },
        masqueradeReturn: { type: 'boolean', default: true },
        ttlSeconds: { type: 'number', default: 3600 },
        audit: {
          type: 'object',
          properties: {
            reason: { type: 'string' },
            incidentId: { type: 'string' },
            mitreTechniqueId: { type: 'string' },
            confidence: { type: 'number' },
          },
          required: ['reason'],
        },
      },
      required: ['source', 'targetDestination', 'audit'],
    },
  },
  {
    name: 'mcp_sinkhole_dns',
    description:
      'Dynamically sinkhole a malicious C2 or phishing domain in Unbound DNS (local-zone override) with automatic TTL expiry. Requires scope: mcp:traffic:redirect.',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string', description: 'Fully qualified domain name to sinkhole (e.g. c2.badactor.example)' },
        sinkholeIp: { type: 'string', default: '0.0.0.0', description: 'IP to return (0.0.0.0 or allowed honeypot IP)' },
        includeSubdomains: { type: 'boolean', default: true },
        ttlSeconds: { type: 'number', default: 3600 },
        audit: {
          type: 'object',
          properties: {
            reason: { type: 'string' },
            incidentId: { type: 'string' },
            mitreTechniqueId: { type: 'string' },
            confidence: { type: 'number' },
          },
          required: ['reason'],
        },
      },
      required: ['domain', 'audit'],
    },
  },
  {
    name: 'mcp_revert_lease',
    description:
      'Immediately revert and remove a specific tactical lease (blackhole, traffic shaper, redirect, or DNS sinkhole) by its leaseId.',
    inputSchema: {
      type: 'object',
      properties: {
        leaseId: { type: 'string', description: 'The leaseId returned when the tactical action was created' },
        reason: { type: 'string', description: 'Reason for reverting the tactical lease' },
      },
      required: ['leaseId', 'reason'],
    },
  },
  {
    name: 'mcp_emergency_clear_all',
    description:
      'Emergency panic switch: immediately flush all AI/MCP tactical blackholes, tc shapers, redirects, and DNS sinkholes from the kernel.',
    inputSchema: {
      type: 'object',
      properties: {
        reason: { type: 'string', description: 'Audit reason for emergency flush' },
      },
      required: ['reason'],
    },
  },
  {
    name: 'mcp_propose_firewall_rule',
    description:
      'Stage a persistent declarative firewall rule into DesiredState, and optionally apply it with mandatory Commit-Confirm automatic rollback protection. Requires mcp:firewall:write (and mcp:firewall:apply if applyImmediately=true). When applied, the response returns the jobId: confirm it with mcp_confirm_apply before the commit-confirm window expires or the daemon auto-rolls the ruleset back.',
    inputSchema: {
      type: 'object',
      properties: {
        rule: {
          type: 'object',
          description: 'Declarative FirewallRule object (interface, direction, action, protocol, source, destination, destinationPort, description)',
        },
        applyImmediately: { type: 'boolean', default: false },
        confirmTimeoutSeconds: { type: 'number', default: 120, description: 'Commit-Confirm rollback watchdog timer (60-600s)' },
        audit: {
          type: 'object',
          properties: {
            reason: { type: 'string' },
            incidentId: { type: 'string' },
            mitreTechniqueId: { type: 'string' },
            confidence: { type: 'number' },
          },
          required: ['reason'],
        },
      },
      required: ['rule', 'audit'],
    },
  },
  {
    name: 'mcp_confirm_apply',
    description:
      'Confirm a firewall rule apply that was applied with Commit-Confirm protection (mcp_propose_firewall_rule with applyImmediately=true), promoting it to last-known-good so the daemon does not auto-roll it back. Pass the jobId returned by the propose call. Requires mcp:firewall:apply.',
    inputSchema: {
      type: 'object',
      properties: {
        jobId: { type: 'string', description: 'The jobId returned by mcp_propose_firewall_rule when the rule was applied' },
        reason: { type: 'string', description: 'Optional reason for confirming the apply' },
      },
      required: ['jobId'],
    },
  },
  {
    name: 'mcp_inspect_ebpf_dataplane',
    description:
      'Inspect unified Ring-0 eBPF telemetry: dual-stack IPv4/IPv6 + 802.1Q/802.1ad VLAN XDP LRU flow maps, per-CPU XDP PASS/DROP verdicts, active TTL-bounded XDP drops, 5-hook CO-RE BPF-LSM enforcement events, Linux 6.9+ BPF_TOKEN_CREATE profiles, and cross-duty Virt/K3s/NAS dataplane posture. Requires scope: mcp:ebpf:read or mcp:telemetry:read.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', default: 50, description: 'Max XDP flows to return (1-200)' },
      },
    },
  },
  {
    name: 'mcp_xdp_fast_drop',
    description:
      'Program or remove a wire-speed Ring-0 XDP_DROP entry (pre-sk_buff, pre-conntrack) for an offending IPv4/IPv6 host OR CIDR subnet prefix (via BPF_MAP_TYPE_LPM_TRIE cidr_block4_map / cidr_block6_map), or configure per-source XDP TCP SYN-flood PPS rate limiting. Enforces blast-radius prefix limits and appliance/gateway/HA/caller anti-lockout immunity. Requires scope: mcp:ebpf:manage.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['block', 'unblock', 'set_syn_limit'], default: 'block' },
        ipAddress: {
          type: 'string',
          description: 'IPv4/IPv6 host address OR CIDR subnet prefix (e.g. 198.51.100.0/24 or 2001:db8:dead::/48) to drop/unblock at NIC XDP layer',
        },
        synFloodLimitPps: {
          type: 'number',
          description: 'Per-source TCP SYN packet-per-second cap enforced in XDP ring-0 when action="set_syn_limit" (0 disables)',
        },
        ttlSeconds: { type: 'number', default: 900, description: 'Kernel monotonic TTL in seconds before auto-expiry (10-604800)' },
        audit: {
          type: 'object',
          properties: {
            reason: { type: 'string', description: 'Security justification (min 10 chars)' },
            incidentId: { type: 'string' },
            mitreTechniqueId: { type: 'string' },
            confidence: { type: 'number' },
          },
          required: ['reason'],
        },
      },
      required: ['audit'],
    },
  },
  {
    name: 'mcp_manage_bpf_token_profile',
    description:
      'Create, update, or delete a Linux 6.9+ BPF_TOKEN_CREATE least-privilege bpffs delegation profile (delegate_cmds, delegate_progs, delegate_maps, delegate_attachs) for unprivileged user-namespace workloads. Strictly rejects Ring-0 memory/tracing programs (kprobe, tracepoint, raw_tracepoint, perf_event, tracing, lsm, struct_ops, ext, syscall) that expose bpf_probe_read_kernel(). Requires scope: mcp:ebpf:manage.',
    inputSchema: {
      type: 'object',
      properties: {
        operation: { type: 'string', enum: ['upsert', 'delete'], default: 'upsert' },
        id: { type: 'string', description: 'Profile identifier (e.g. k3s-cilium-userns or ct-105)' },
        targetKind: { type: 'string', enum: ['lxc', 'k3s-pod', 'standalone'], default: 'standalone' },
        targetRef: { type: 'string', description: 'Target LXC CTID or K3s namespace/pod selector' },
        preset: {
          type: 'string',
          enum: ['socket-observability', 'network-dataplane', 'cgroup-microsegmentation', 'custom'],
          default: 'network-dataplane',
        },
        enabled: { type: 'boolean', default: true },
        delegateCmds: { type: 'string', description: 'Optional colon-delimited bpf_cmd bitmask (e.g. prog_load:map_create:btf_load:link_create)' },
        delegateProgs: { type: 'string', description: 'Optional colon-delimited safe networking bpf_prog_type bitmask (e.g. xdp:sched_cls:cgroup_skb)' },
        delegateMaps: { type: 'string', description: 'Optional colon-delimited bpf_map_type bitmask' },
        delegateAttachs: { type: 'string', description: 'Optional colon-delimited bpf_attach_type bitmask' },
        auditViaBpfLsm: { type: 'boolean', default: true },
        description: { type: 'string' },
        audit: {
          type: 'object',
          properties: {
            reason: { type: 'string' },
            incidentId: { type: 'string' },
            mitreTechniqueId: { type: 'string' },
            confidence: { type: 'number' },
          },
          required: ['reason'],
        },
      },
      required: ['id', 'audit'],
    },
  },
  {
    name: 'mcp_inspect_virt_workloads',
    description:
      'Inspect KVM/QEMU virtual machines, unprivileged LXC containers (including CLONE_NEWUSER + BPF_TOKEN status), VFIO/IOMMU PCI devices, backups, and host TAP/veth XDP dataplane stats. Requires scope: mcp:virt:read or mcp:telemetry:read.',
    inputSchema: {
      type: 'object',
      properties: {
        includeBackups: { type: 'boolean', default: true },
        includePci: { type: 'boolean', default: true },
      },
    },
  },
  {
    name: 'mcp_control_virt_workload',
    description:
      'Execute lifecycle and enterprise hypervisor operations (start, stop, reboot, pause, resume, backup, restore, snapshot, rollback, clone, live_migrate, qga_interfaces, export_libvirt_xml) on a KVM virtual machine or LXC container. Anti-lockout guard prevents stopping or pausing Hosted Edge / transit NGFW VMs. Requires scope: mcp:virt:manage.',
    inputSchema: {
      type: 'object',
      properties: {
        workloadType: { type: 'string', enum: ['vm', 'lxc'] },
        id: { type: 'number', description: 'VMID or CTID (100-99999)' },
        action: {
          type: 'string',
          enum: [
            'start',
            'stop',
            'reboot',
            'pause',
            'resume',
            'backup',
            'restore',
            'snapshot',
            'rollback',
            'clone',
            'live_migrate',
            'qga_interfaces',
            'export_libvirt_xml',
          ],
        },
        force: { type: 'boolean', default: false },
        storagePool: { type: 'string', description: 'Optional ZFS pool for backup/restore action' },
        snapshotName: { type: 'string', description: 'Snapshot label for snapshot or rollback actions' },
        backupArchivePath: { type: 'string', description: 'Backup archive filename (.vma.zst) for restore action' },
        newId: { type: 'number', description: 'Target VMID for clone action (100-99999)' },
        newName: { type: 'string', description: 'Target VM name for clone action' },
        linkedClone: { type: 'boolean', default: true, description: 'Use instant zero-copy ZFS linked clone (true) or independent full clone (false)' },
        targetHostIp: { type: 'string', description: 'Target peer hypervisor IP for live_migrate action' },
        audit: {
          type: 'object',
          properties: {
            reason: { type: 'string' },
            incidentId: { type: 'string' },
            mitreTechniqueId: { type: 'string' },
            confidence: { type: 'number' },
          },
          required: ['reason'],
        },
      },
      required: ['workloadType', 'id', 'action', 'audit'],
    },
  },
  {
    name: 'mcp_configure_lxc_bpf_token',
    description:
      'Declaratively enable, update, or disable Linux 6.9+ BPF_TOKEN_CREATE bpffs delegation + LIBBPF_BPF_TOKEN_PATH=/sys/fs/bpf on an unprivileged LXC container (CLONE_NEWUSER) in DesiredState (virt.yaml) and register its profile with axonwalld. Rejects privileged containers and Ring-0 tracing programs. Requires scopes: mcp:virt:manage AND mcp:ebpf:manage.',
    inputSchema: {
      type: 'object',
      properties: {
        ctid: { type: 'number', description: 'Target unprivileged LXC CTID (100-99999)' },
        enabled: { type: 'boolean', description: 'Enable or disable BPF_TOKEN delegation on this container' },
        preset: {
          type: 'string',
          enum: ['socket-observability', 'network-dataplane', 'cgroup-microsegmentation', 'custom'],
          default: 'network-dataplane',
        },
        delegateCmds: { type: 'string' },
        delegateProgs: { type: 'string' },
        delegateMaps: { type: 'string' },
        delegateAttachs: { type: 'string' },
        audit: {
          type: 'object',
          properties: {
            reason: { type: 'string' },
            incidentId: { type: 'string' },
            mitreTechniqueId: { type: 'string' },
            confidence: { type: 'number' },
          },
          required: ['reason'],
        },
      },
      required: ['ctid', 'enabled', 'audit'],
    },
  },
  {
    name: 'mcp_inspect_k3s_cluster',
    description:
      'Inspect K3s Kubernetes HA cluster health, node inventory, OpenEBS ZFS PVCs, CNI bridge/vxlan traffic & XDP program attachments, and K3s UserNS BPF_TOKEN delegation profiles. Requires scope: mcp:k3s:read or mcp:telemetry:read.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'mcp_render_k3s_bpf_token_manifest',
    description:
      'Render a hardened Kubernetes Pod or DaemonSet YAML manifest using hostUsers: false (UserNamespacesSupport=true), LIBBPF_BPF_TOKEN_PATH=/sys/fs/bpf, RuntimeDefault seccomp, and a delegated bpffs mount for Linux 6.9+ unprivileged eBPF workloads. Requires scope: mcp:k3s:read, mcp:ebpf:read, or mcp:telemetry:read.',
    inputSchema: {
      type: 'object',
      properties: {
        profileId: { type: 'string', default: 'k3s-net-dataplane' },
        preset: {
          type: 'string',
          enum: ['socket-observability', 'network-dataplane', 'cgroup-microsegmentation'],
          default: 'network-dataplane',
        },
        workloadName: { type: 'string', default: 'ebpf-packet-inspector' },
        namespace: { type: 'string', default: 'default' },
        image: { type: 'string', default: 'ghcr.io/cilium/cilium:v1.16.4' },
        kind: { type: 'string', enum: ['Pod', 'DaemonSet'], default: 'Pod' },
      },
    },
  },
  {
    name: 'mcp_inspect_nas_storage',
    description:
      'Inspect OpenZFS pools, datasets, physical disk SMART/inventory, snapshots, SMB/NFS/iSCSI shares, and deep /proc/spl/kstat/zfs telemetry (ARC/L2ARC hit ratios, ZIL/SLOG sync commits, per-pool ZIO queue depth). Requires scope: mcp:nas:read or mcp:telemetry:read.',
    inputSchema: {
      type: 'object',
      properties: {
        includeDisks: { type: 'boolean', default: true },
        includeSnapshots: { type: 'boolean', default: true },
      },
    },
  },
  {
    name: 'mcp_nas_snapshot_or_scrub',
    description:
      'Execute enterprise OpenZFS NAS operations (snapshot, rollback, delete_snapshot, scrub, trim, checkpoint, discard_checkpoint, unlock_dataset, lock_dataset, smart_test, cloud_sync) with strict ZFS identifier sanitization and SHA-256 hash-chained audit logging. Requires scope: mcp:nas:manage.',
    inputSchema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: [
            'snapshot',
            'rollback',
            'delete_snapshot',
            'scrub',
            'trim',
            'checkpoint',
            'discard_checkpoint',
            'unlock_dataset',
            'lock_dataset',
            'smart_test',
            'cloud_sync',
          ],
        },
        target: {
          type: 'string',
          description: 'ZFS dataset (e.g. tank/vms), snapshot (dataset@label), pool (tank), block device (/dev/nvme0n1), or cloud-sync task name',
        },
        snapshotLabel: { type: 'string', description: 'Optional snapshot label (e.g. pre-upgrade)' },
        keyMaterial: { type: 'string', description: 'Optional passphrase/hex key when unlocking an AES-256-GCM ZFS dataset' },
        smartTestType: { type: 'string', enum: ['short', 'long'], default: 'short' },
        audit: {
          type: 'object',
          properties: {
            reason: { type: 'string' },
            incidentId: { type: 'string' },
            mitreTechniqueId: { type: 'string' },
            confidence: { type: 'number' },
          },
          required: ['reason'],
        },
      },
      required: ['action', 'target', 'audit'],
    },
  },
  {
    name: 'mcp_manage_zfs_nas',
    description:
      'Unified enterprise OpenZFS NAS/SAN lifecycle tool (paired with mcp_nas_snapshot_or_scrub) supporting snapshot, rollback, delete_snapshot, scrub, trim, checkpoint, discard_checkpoint, unlock_dataset, lock_dataset, smart_test, and cloud_sync with root-pool protection and SHA-256 hash-chained audit logging. Requires scope: mcp:nas:manage.',
    inputSchema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: [
            'snapshot',
            'rollback',
            'delete_snapshot',
            'scrub',
            'trim',
            'checkpoint',
            'discard_checkpoint',
            'unlock_dataset',
            'lock_dataset',
            'smart_test',
            'cloud_sync',
          ],
        },
        target: {
          type: 'string',
          description: 'ZFS dataset (e.g. tank/vms), snapshot (dataset@label), pool (tank), block device (/dev/nvme0n1), or cloud-sync task name',
        },
        snapshotLabel: { type: 'string', description: 'Optional snapshot label (e.g. pre-upgrade)' },
        keyMaterial: { type: 'string', description: 'Optional passphrase/hex key when unlocking an AES-256-GCM ZFS dataset' },
        smartTestType: { type: 'string', enum: ['short', 'long'], default: 'short' },
        audit: {
          type: 'object',
          properties: {
            reason: { type: 'string' },
            incidentId: { type: 'string' },
            mitreTechniqueId: { type: 'string' },
            confidence: { type: 'number' },
          },
          required: ['reason'],
        },
      },
      required: ['action', 'target', 'audit'],
    },
  },
  {
    name: 'mcp_manage_k3s_cluster',
    description:
      'Manage K3s embedded etcd cluster disaster recovery snapshots (etcd_snapshot_list, etcd_snapshot_save, etcd_snapshot_restore) with strict filename sanitization and SHA-256 hash-chained audit logging. Requires scope: mcp:k3s:manage.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['etcd_snapshot_list', 'etcd_snapshot_save', 'etcd_snapshot_restore'] },
        snapshotName: { type: 'string', description: 'Snapshot name for save or restore' },
        audit: {
          type: 'object',
          properties: {
            reason: { type: 'string' },
            incidentId: { type: 'string' },
            mitreTechniqueId: { type: 'string' },
            confidence: { type: 'number' },
          },
          required: ['reason'],
        },
      },
      required: ['action', 'audit'],
    },
  },
  {
    name: 'mcp_import_competitor_config',
    description:
      'Parse, audit, and optionally stage legacy configurations from OPNsense, pfSense, Proxmox VE 8.x, TrueNAS SCALE, VyOS, MikroTik RouterOS, Cisco ASA, iptables, or firewalld into unified Axonwall DesiredState (translating firewall/NAT rules, KVM VMs, LXC containers, ZFS pools/datasets, and SMB/NFS shares). Requires scope: mcp:firewall:write.',
    inputSchema: {
      type: 'object',
      properties: {
        vendor: {
          type: 'string',
          enum: ['pfsense', 'opnsense', 'vyos', 'mikrotik', 'iptables', 'cisco', 'firewalld', 'proxmox', 'truenas'],
          description: 'Optional explicit vendor format (auto-detected when omitted)',
        },
        rawConfig: { type: 'string', description: 'Raw XML, JSON, .conf, .rsc, or CLI export text' },
        stageToDesiredState: {
          type: 'boolean',
          default: false,
          description: 'When true, merges imported objects into /etc/axonwall/*.yaml DesiredState (dry-run preview when false)',
        },
        audit: {
          type: 'object',
          properties: {
            reason: { type: 'string' },
            incidentId: { type: 'string' },
            mitreTechniqueId: { type: 'string' },
            confidence: { type: 'number' },
          },
          required: ['reason'],
        },
      },
      required: ['rawConfig'],
    },
  },
];

// ============================================================================
// MCP Resource & Tool Dispatcher
// ============================================================================

export interface McpExecutionEnvironment {
  key: McpApiKey;
  clientIp: string;
  onFleetBroadcastBlock?: (ip: string, reason: string, durationMinutes: number) => number;
}

function getAllowedScopesForResourceUri(uri: string): McpScope[] {
  switch (uri) {
    case 'axonwall://ebpf/dataplane':
    case 'axonwall://ebpf/bpf-tokens':
    case 'axonwall://security/rootkit-posture':
      return ['mcp:ebpf:read', 'mcp:telemetry:read'];
    case 'axonwall://virt/workloads':
    case 'axonwall://virt/libvirt-domains':
      return ['mcp:virt:read', 'mcp:telemetry:read'];
    case 'axonwall://k3s/cluster':
    case 'axonwall://k3s/etcd-snapshots':
      return ['mcp:k3s:read', 'mcp:telemetry:read'];
    case 'axonwall://nas/storage-telemetry':
      return ['mcp:nas:read', 'mcp:telemetry:read'];
    default:
      return ['mcp:telemetry:read'];
  }
}

export async function handleMcpReadResource(
  uri: string,
  env: McpExecutionEnvironment
): Promise<{ contents: { uri: string; mimeType: string; text: string }[] }> {
  const acceptedScopes = getAllowedScopesForResourceUri(uri);
  const matchedScope = acceptedScopes.find((s) => hasMcpScope(env.key, s));
  if (!matchedScope) {
    const scopeDesc = acceptedScopes.join(' or ');
    recordMcpAuditEntry({
      keyId: env.key.id,
      keyName: env.key.name,
      agentType: env.key.agentType,
      clientIp: env.clientIp,
      toolName: `resource:${uri}`,
      requiredScope: acceptedScopes[0]!,
      decision: 'denied',
      denialReason: `Missing required scope (${scopeDesc})`,
      paramsSummary: { uri },
    });
    throw new Error(`Authorization denied: missing required scope ${scopeDesc}`);
  }

  let payload: unknown;

  switch (uri) {
    case 'axonwall://system/overview': {
      const { ctx, activeLeasesCount } = await buildGuardContext(env.key, env.clientIp);
      const statusRes = await callAxonwalldApi('GET', '/v1/status');
      payload = {
        applianceStatus: statusRes.ok ? statusRes.data : { status: 'standalone' },
        protectedPosture: {
          applianceHostIps: ctx.applianceHostIps,
          gatewayAndHaIps: ctx.gatewayAndHaIps,
          antiLockoutPorts: ctx.antiLockoutPorts,
        },
        authenticatedPrincipal: {
          keyId: env.key.id,
          name: env.key.name,
          agentType: env.key.agentType,
          scopes: env.key.scopes,
          policyLimits: env.key.policyLimits,
          activeLeasesOwned: activeLeasesCount,
        },
      };
      break;
    }

    case 'axonwall://telemetry/interfaces': {
      const statusRes = await callAxonwalldApi('GET', '/v1/status');
      payload = {
        interfaces: statusRes.ok ? statusRes.data?.interfaces ?? [] : [],
        timestamp: new Date().toISOString(),
        // B2-M3: daemon-down must not collapse to an empty list
        // with no signal — an empty list reads as "no interfaces",
        // not "daemon unreachable".
        ...(!statusRes.ok
          ? { daemonDown: true, error: statusRes.data?.error || 'axonwalld unreachable' }
          : {}),
      };
      break;
    }

    case 'axonwall://telemetry/alerts/suricata': {
      const alerts: unknown[] = [];
      try {
        if (fs.existsSync('/var/log/suricata/eve.json')) {
          const lines = fs.readFileSync('/var/log/suricata/eve.json', 'utf8').trim().split('\n');
          for (const line of lines.slice(-50).reverse()) {
            try {
              alerts.push(JSON.parse(line));
            } catch {
              // ignore
            }
          }
        }
      } catch {
        // ignore
      }
      payload = { alerts };
      break;
    }

    case 'axonwall://telemetry/flows/top': {
      const flowsRes = await callAxonwalldApi('GET', '/v1/mcp/flows?limit=50');
      // B2-M3: daemon-down must not collapse to an empty list with
      // no signal — zero flows reads as "no traffic", not "daemon
      // unreachable". Same envelope as the tactical-write tools
      // use to deny on daemon-down.
      payload = flowsRes.ok
        ? { flows: flowsRes.data?.flows ?? [] }
        : { flows: [], daemonDown: true, error: flowsRes.data?.error || 'axonwalld unreachable' };
      break;
    }

    case 'axonwall://firewall/tactical-leases': {
      const leasesRes = await callAxonwalldApi('GET', '/v1/mcp/leases');
      // B2-M3: zero leases while axonwalld is down would tell a
      // SOAR agent no tactical lease is active, when the kernel
      // may still be enforcing blackholes/shapers from before the
      // daemon died.
      payload = leasesRes.ok
        ? { leases: leasesRes.data?.leases ?? [] }
        : { leases: [], daemonDown: true, error: leasesRes.data?.error || 'axonwalld unreachable' };
      break;
    }

    case 'axonwall://firewall/ruleset-summary': {
      const state = loadLocalDesiredState();
      payload = state
        ? {
            version: state.version,
            hostname: state.system?.hostname,
            antiLockout: state.system?.antiLockout,
            interfaces: state.interfaces,
            rulesCount: state.rules?.length ?? 0,
            rules: state.rules ?? [],
            natRules: state.nat ?? [],
            aliases: state.aliases ?? [],
            routes: state.routes ?? [],
            trafficShaper: state.trafficShaper,
          }
        : { message: 'No declarative DesiredState file found on disk' };
      break;
    }

    case 'axonwall://topology/nastymap': {
      const arpRes = await callAxonwalldApi('GET', '/v1/arp');
      const leasesRes = await callAxonwalldApi('GET', '/v1/leases');
      // B2-M3: "no hosts" must not be reported as a fact when the
      // daemon is unreachable. Each source is flagged separately.
      const daemonErrors = [
        ...(!arpRes.ok ? [`ARP table: ${arpRes.data?.error || 'axonwalld unreachable'}`] : []),
        ...(!leasesRes.ok ? [`DHCP leases: ${leasesRes.data?.error || 'axonwalld unreachable'}`] : []),
      ];
      payload = {
        arpTable: arpRes.ok ? arpRes.data : [],
        dhcpLeases: leasesRes.ok ? leasesRes.data : [],
        ...(daemonErrors.length ? { daemonDown: true, error: daemonErrors.join('; ') } : {}),
      };
      break;
    }

    case 'axonwall://audit/mcp-trail': {
      payload = queryMcpAuditEntries(50);
      break;
    }

    case 'axonwall://ebpf/dataplane': {
      const res = await callAxonwalldApi('GET', '/v1/ebpf/overview?limit=50');
      payload = res.ok
        ? {
            dataplane: res.data?.dataplane ?? {},
            lsm: res.data?.lsm ?? {},
            bpfTokensSummary: res.data?.bpfTokens ?? {},
          }
        : {
            dataplane: null,
            lsm: null,
            daemonDown: true,
            error: res.data?.error || 'axonwalld unreachable',
          };
      break;
    }

    case 'axonwall://ebpf/bpf-tokens': {
      const res = await callAxonwalldApi('GET', '/v1/ebpf/tokens');
      payload = res.ok
        ? res.data
        : {
            capabilities: null,
            presets: [],
            profiles: [],
            activeMounts: [],
            daemonDown: true,
            error: res.data?.error || 'axonwalld unreachable',
          };
      break;
    }

    case 'axonwall://virt/workloads': {
      const [vmsRes, ctsRes, pciRes, telRes] = await Promise.all([
        callAxonwalldApi('GET', '/v1/virt/vms'),
        callAxonwalldApi('GET', '/v1/virt/containers'),
        callAxonwalldApi('GET', '/v1/virt/pci'),
        callAxonwalldApi('GET', '/v1/virt/telemetry'),
      ]);
      const anyDown = !vmsRes.ok && !ctsRes.ok && !telRes.ok;
      payload = {
        vms: vmsRes.ok ? vmsRes.data?.vms ?? [] : [],
        containers: ctsRes.ok ? ctsRes.data?.containers ?? [] : [],
        pciDevices: pciRes.ok ? pciRes.data?.devices ?? [] : [],
        ebpfTelemetry: telRes.ok ? telRes.data : null,
        ...(anyDown
          ? { daemonDown: true, error: vmsRes.data?.error || 'axonwalld unreachable' }
          : {}),
      };
      break;
    }

    case 'axonwall://k3s/cluster': {
      const res = await callAxonwalldApi('GET', '/v1/k3s/telemetry');
      payload = res.ok
        ? res.data
        : {
            status: null,
            cniInterfaces: [],
            bpfTokenProfiles: [],
            daemonDown: true,
            error: res.data?.error || 'axonwalld unreachable',
          };
      break;
    }

    case 'axonwall://nas/storage-telemetry': {
      const [telRes, disksRes, snapsRes] = await Promise.all([
        callAxonwalldApi('GET', '/v1/nas/telemetry'),
        callAxonwalldApi('GET', '/v1/nas/disks'),
        callAxonwalldApi('GET', '/v1/nas/snapshots'),
      ]);
      payload = {
        telemetry: telRes.ok ? telRes.data : null,
        disks: disksRes.ok ? disksRes.data?.disks ?? [] : [],
        snapshots: snapsRes.ok ? snapsRes.data?.snapshots ?? [] : [],
        ...(!telRes.ok
          ? { daemonDown: true, error: telRes.data?.error || 'axonwalld unreachable' }
          : {}),
      };
      break;
    }

    case 'axonwall://security/rootkit-posture': {
      const res = await callAxonwalldApi('GET', '/v1/security/rootkit/status');
      payload = res.ok
        ? res.data
        : {
            verdict: 'UNKNOWN_DAEMON_DOWN',
            daemonDown: true,
            error: res.data?.error || 'axonwalld unreachable',
          };
      break;
    }

    case 'axonwall://k3s/etcd-snapshots': {
      const res = await callAxonwalldApi('GET', '/v1/k3s/etcd-snapshots');
      payload = res.ok
        ? res.data
        : {
            snapshots: [],
            daemonDown: true,
            error: res.data?.error || 'axonwalld unreachable',
          };
      break;
    }

    case 'axonwall://virt/libvirt-domains': {
      const res = await callAxonwalldApi('GET', '/v1/virt/libvirt-xml');
      payload = res.ok
        ? res.data
        : {
            domains: [],
            daemonDown: true,
            error: res.data?.error || 'axonwalld unreachable',
          };
      break;
    }

    default:
      throw new Error(`Unknown MCP resource URI: ${uri}`);
  }

  recordMcpAuditEntry({
    keyId: env.key.id,
    keyName: env.key.name,
    agentType: env.key.agentType,
    clientIp: env.clientIp,
    toolName: `resource:${uri}`,
    requiredScope: matchedScope,
    decision: 'allowed',
    paramsSummary: { uri },
  });

  return {
    contents: [
      {
        uri,
        mimeType: 'application/json',
        text: JSON.stringify(payload, null, 2),
      },
    ],
  };
}

export async function handleMcpCallTool(
  toolName: string,
  rawArgs: Record<string, unknown> | undefined,
  env: McpExecutionEnvironment
): Promise<{ content: { type: 'text'; text: string }[]; isError?: boolean }> {
  const args = rawArgs ?? {};

  const deny = (requiredScope: string, reason: string, auditMeta?: any) => {
    recordMcpAuditEntry({
      keyId: env.key.id,
      keyName: env.key.name,
      agentType: env.key.agentType,
      clientIp: env.clientIp,
      toolName,
      requiredScope,
      decision: 'denied',
      denialReason: reason,
      paramsSummary: args,
      auditMetadata: auditMeta,
    });
    return {
      isError: true,
      content: [{ type: 'text' as const, text: JSON.stringify({ success: false, error: reason }, null, 2) }],
    };
  };

  const requireScope = (scope: McpScope, auditMeta?: any) => {
    if (!hasMcpScope(env.key, scope)) {
      return deny(scope, `Authorization denied: MCP key '${env.key.name}' lacks required scope '${scope}'`, auditMeta);
    }
    return null;
  };

  const requireAnyScope = (scopes: McpScope[], auditMeta?: any): { matched?: McpScope; err?: ReturnType<typeof deny> } => {
    const matched = scopes.find((s) => hasMcpScope(env.key, s));
    if (!matched) {
      return {
        err: deny(
          scopes[0]!,
          `Authorization denied: MCP key '${env.key.name}' lacks required scope (${scopes.join(' or ')})`,
          auditMeta,
        ),
      };
    }
    return { matched };
  };

  switch (toolName) {
    case 'mcp_query_flows': {
      const scopeErr = requireScope('mcp:telemetry:read');
      if (scopeErr) return scopeErr;

      const qs = new URLSearchParams();
      if (typeof args.srcIp === 'string' && args.srcIp) qs.set('srcIp', args.srcIp);
      if (typeof args.dstIp === 'string' && args.dstIp) qs.set('dstIp', args.dstIp);
      if (typeof args.protocol === 'string' && args.protocol) qs.set('protocol', args.protocol);
      if (typeof args.state === 'string' && args.state) qs.set('state', args.state);
      if (typeof args.port === 'number') qs.set('port', String(args.port));
      if (typeof args.minBytes === 'number') qs.set('minBytes', String(args.minBytes));
      qs.set('limit', String(typeof args.limit === 'number' ? Math.min(500, Math.max(1, args.limit)) : 50));

      const res = await callAxonwalldApi('GET', `/v1/mcp/flows?${qs.toString()}`);
      recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:telemetry:read',
        decision: 'allowed',
        paramsSummary: args,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(res.ok ? res.data : { flows: [], note: res.data?.error }, null, 2),
          },
        ],
      };
    }

    case 'mcp_query_threat_events': {
      const scopeErr = requireScope('mcp:telemetry:read');
      if (scopeErr) return scopeErr;

      const limit = typeof args.limit === 'number' ? Math.min(200, Math.max(1, args.limit)) : 50;
      const srcFilter = typeof args.srcIp === 'string' ? args.srcIp.trim() : '';
      const dstFilter = typeof args.dstIp === 'string' ? args.dstIp.trim() : '';
      const sigFilter = typeof args.signatureContains === 'string' ? args.signatureContains.toLowerCase() : '';

      const matchingAlerts: any[] = [];
      try {
        if (fs.existsSync('/var/log/suricata/eve.json')) {
          const lines = fs.readFileSync('/var/log/suricata/eve.json', 'utf8').trim().split('\n');
          for (let i = lines.length - 1; i >= 0 && matchingAlerts.length < limit; i--) {
            const line = lines[i];
            if (!line) continue;
            try {
              const ev = JSON.parse(line);
              if (srcFilter && ev.src_ip !== srcFilter) continue;
              if (dstFilter && ev.dest_ip !== dstFilter) continue;
              if (sigFilter) {
                const sig = String(ev.alert?.signature || '').toLowerCase();
                if (!sig.includes(sigFilter)) continue;
              }
              matchingAlerts.push(ev);
            } catch {
              // skip
            }
          }
        }
      } catch {
        // skip
      }

      const leasesRes = await callAxonwalldApi('GET', '/v1/mcp/leases');
      recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:telemetry:read',
        decision: 'allowed',
        paramsSummary: args,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                suricataAlerts: matchingAlerts,
                activeMcpLeases: leasesRes.ok ? leasesRes.data?.leases ?? [] : [],
                // B2-M3: zero leases while axonwalld is down is not
                // "no leases active" — the kernel may still be
                // enforcing leases from before the daemon died.
                ...(!leasesRes.ok
                  ? { daemonDown: true, error: leasesRes.data?.error || 'axonwalld unreachable' }
                  : {}),
              },
              null,
              2
            ),
          },
        ],
      };
    }

    case 'mcp_inspect_host_context': {
      const scopeErr = requireScope('mcp:telemetry:read');
      if (scopeErr) return scopeErr;

      const ipAddress = typeof args.ipAddress === 'string' ? args.ipAddress.trim() : '';
      if (!ipAddress) {
        return deny('mcp:telemetry:read', 'ipAddress parameter is required');
      }

      const res = await callAxonwalldApi('GET', `/v1/mcp/host-context?ip=${encodeURIComponent(ipAddress)}`);
      recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:telemetry:read',
        decision: 'allowed',
        paramsSummary: { ipAddress },
      });

      return {
        content: [{ type: 'text', text: JSON.stringify(res.data, null, 2) }],
        isError: !res.ok,
      };
    }

    case 'mcp_capture_packet_sample': {
      const scopeErr = requireScope('mcp:pcap:capture');
      if (scopeErr) return scopeErr;

      const parsed = McpPcapSampleRequestSchema.safeParse(args);
      if (!parsed.success) {
        return deny('mcp:pcap:capture', `Invalid packet capture parameters: ${parsed.error.message}`);
      }

      const res = await callAxonwalldApi('POST', '/v1/mcp/pcap-sample', parsed.data, 20000);
      recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:pcap:capture',
        decision: 'allowed',
        paramsSummary: parsed.data,
      });

      return {
        content: [{ type: 'text', text: JSON.stringify(res.data, null, 2) }],
        isError: !res.ok,
      };
    }

    case 'mcp_blackhole_traffic': {
      const parsed = McpBlackholeRequestSchema.safeParse(args);
      if (!parsed.success) {
        return deny('mcp:traffic:blackhole', `Schema validation failed: ${parsed.error.message}`);
      }
      const req = parsed.data;

      const scopeErr = requireScope('mcp:traffic:blackhole', req.audit);
      if (scopeErr) return scopeErr;

      if (req.propagateToFleet) {
        const fleetErr = requireScope('mcp:fleet:broadcast', req.audit);
        if (fleetErr) return fleetErr;
      }

      const { ctx, activeLeasesCount } = await buildGuardContext(env.key, env.clientIp);
      if (activeLeasesCount >= env.key.policyLimits.maxActiveLeases) {
        return deny(
          'mcp:traffic:blackhole',
          `Maximum active tactical leases (${env.key.policyLimits.maxActiveLeases}) reached for key '${env.key.name}'`,
          req.audit
        );
      }

      const targetCheck = validateMcpTarget(req.target, ctx, { port: req.port });
      if (!targetCheck.valid) {
        return deny('mcp:traffic:blackhole', targetCheck.reason || 'Target rejected by safety guard', req.audit);
      }

      const boundedTtl = Math.min(req.ttlSeconds, env.key.policyLimits.maxTtlSeconds);

      const daemonRes = await callAxonwalldApi('POST', '/v1/mcp/blackhole', {
        ...req,
        target: targetCheck.normalizedTarget,
        ttlSeconds: boundedTtl,
        callerIp: env.clientIp,
        maxIpv4PrefixLen: env.key.policyLimits.maxIpv4PrefixLen,
        maxIpv6PrefixLen: env.key.policyLimits.maxIpv6PrefixLen,
        keyId: env.key.id,
        keyName: env.key.name,
      });

      if (!daemonRes.ok || !daemonRes.data?.lease?.id) {
        return deny('mcp:traffic:blackhole', daemonRes.data?.error || 'Daemon rejected blackhole request', req.audit);
      }

      const lease = daemonRes.data.lease;

      let fleetPropagatedCount = 0;
      if (req.propagateToFleet && env.onFleetBroadcastBlock && targetCheck.normalizedTarget) {
        fleetPropagatedCount = env.onFleetBroadcastBlock(
          targetCheck.normalizedTarget,
          req.audit.reason,
          Math.ceil(boundedTtl / 60)
        );
      }

      const auditEntry = recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:traffic:blackhole',
        decision: 'allowed',
        paramsSummary: {
          target: targetCheck.normalizedTarget,
          mode: req.mode,
          direction: req.direction,
          port: req.port,
          ttlSeconds: boundedTtl,
          propagateToFleet: req.propagateToFleet,
        },
        auditMetadata: req.audit,
        leaseId: lease.id,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                lease,
                fleetPropagatedSatellites: fleetPropagatedCount,
                auditEntryHash: auditEntry.recorded ? auditEntry.entryHash : null,
                auditRecorded: auditEntry.recorded,
              },
              null,
              2
            ),
          },
        ],
      };
    }

    case 'mcp_shape_traffic': {
      const parsed = McpShapeRequestSchema.safeParse(args);
      if (!parsed.success) {
        return deny('mcp:traffic:shape', `Schema validation failed: ${parsed.error.message}`);
      }
      const req = parsed.data;

      const scopeErr = requireScope('mcp:traffic:shape', req.audit);
      if (scopeErr) return scopeErr;

      const { ctx, activeLeasesCount } = await buildGuardContext(env.key, env.clientIp);
      if (activeLeasesCount >= env.key.policyLimits.maxActiveLeases) {
        return deny(
          'mcp:traffic:shape',
          `Maximum active tactical leases (${env.key.policyLimits.maxActiveLeases}) reached for key '${env.key.name}'`,
          req.audit
        );
      }

      const targetCheck = validateMcpTarget(req.target, ctx);
      if (!targetCheck.valid) {
        return deny('mcp:traffic:shape', targetCheck.reason || 'Target rejected by safety guard', req.audit);
      }

      const boundedTtl = Math.min(req.ttlSeconds, env.key.policyLimits.maxTtlSeconds);

      const daemonRes = await callAxonwalldApi('POST', '/v1/mcp/shape', {
        ...req,
        target: targetCheck.normalizedTarget,
        ttlSeconds: boundedTtl,
        callerIp: env.clientIp,
        maxIpv4PrefixLen: env.key.policyLimits.maxIpv4PrefixLen,
        maxIpv6PrefixLen: env.key.policyLimits.maxIpv6PrefixLen,
        keyId: env.key.id,
        keyName: env.key.name,
      });

      if (!daemonRes.ok || !daemonRes.data?.lease?.id) {
        return deny('mcp:traffic:shape', daemonRes.data?.error || 'Daemon rejected traffic shaping request', req.audit);
      }

      const lease = daemonRes.data.lease;

      const auditEntry = recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:traffic:shape',
        decision: 'allowed',
        paramsSummary: {
          target: targetCheck.normalizedTarget,
          interface: req.interface,
          rateKbps: req.rateKbps,
          latencyMs: req.latencyMs,
          ttlSeconds: boundedTtl,
        },
        auditMetadata: req.audit,
        leaseId: lease.id,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ success: true, lease, auditEntryHash: auditEntry.recorded ? auditEntry.entryHash : null, auditRecorded: auditEntry.recorded }, null, 2),
          },
        ],
      };
    }

    case 'mcp_redirect_traffic': {
      const parsed = McpRedirectRequestSchema.safeParse(args);
      if (!parsed.success) {
        return deny('mcp:traffic:redirect', `Schema validation failed: ${parsed.error.message}`);
      }
      const req = parsed.data;

      const scopeErr = requireScope('mcp:traffic:redirect', req.audit);
      if (scopeErr) return scopeErr;

      const { ctx, activeLeasesCount } = await buildGuardContext(env.key, env.clientIp);
      if (activeLeasesCount >= env.key.policyLimits.maxActiveLeases) {
        return deny(
          'mcp:traffic:redirect',
          `Maximum active tactical leases (${env.key.policyLimits.maxActiveLeases}) reached for key '${env.key.name}'`,
          req.audit
        );
      }

      const sourceCheck = validateMcpTarget(req.source, ctx, { port: req.originalDstPort });
      if (!sourceCheck.valid) {
        return deny('mcp:traffic:redirect', sourceCheck.reason || 'Source rejected by safety guard', req.audit);
      }

      if (req.originalDstIp) {
        const origDstCheck = validateMcpTarget(req.originalDstIp, ctx, { port: req.originalDstPort });
        if (!origDstCheck.valid) {
          return deny('mcp:traffic:redirect', origDstCheck.reason || 'originalDstIp rejected by safety guard', req.audit);
        }
      }

      const destCheck = validateRedirectTargetAllowlist(
        req.targetDestination,
        env.key.policyLimits.allowedRedirectTargets
      );
      if (!destCheck.valid) {
        return deny('mcp:traffic:redirect', destCheck.reason || 'Redirect destination not in allowlist', req.audit);
      }
      const rawRedirectHost = (destCheck.normalizedTarget || req.targetDestination).replace(/^\[([^\]]+)\](?::\d+)?$/, '$1').replace(/:\d+$/, '');
      const redirectSafetyCheck = validateMcpTarget(rawRedirectHost, ctx);
      if (!redirectSafetyCheck.valid) {
        return deny('mcp:traffic:redirect', redirectSafetyCheck.reason || 'Redirect target rejected by safety guard', req.audit);
      }

      const boundedTtl = Math.min(req.ttlSeconds, env.key.policyLimits.maxTtlSeconds);

      const daemonRes = await callAxonwalldApi('POST', '/v1/mcp/redirect', {
        ...req,
        source: sourceCheck.normalizedTarget,
        targetDestination: destCheck.normalizedTarget,
        ttlSeconds: boundedTtl,
        callerIp: env.clientIp,
        maxIpv4PrefixLen: env.key.policyLimits.maxIpv4PrefixLen,
        maxIpv6PrefixLen: env.key.policyLimits.maxIpv6PrefixLen,
        keyId: env.key.id,
        keyName: env.key.name,
      });

      if (!daemonRes.ok || !daemonRes.data?.lease?.id) {
        return deny('mcp:traffic:redirect', daemonRes.data?.error || 'Daemon rejected redirect request', req.audit);
      }

      const lease = daemonRes.data.lease;

      const auditEntry = recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:traffic:redirect',
        decision: 'allowed',
        paramsSummary: {
          source: sourceCheck.normalizedTarget,
          targetDestination: destCheck.normalizedTarget,
          redirectType: req.redirectType,
          ttlSeconds: boundedTtl,
        },
        auditMetadata: req.audit,
        leaseId: lease.id,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ success: true, lease, auditEntryHash: auditEntry.recorded ? auditEntry.entryHash : null, auditRecorded: auditEntry.recorded }, null, 2),
          },
        ],
      };
    }

    case 'mcp_sinkhole_dns': {
      const parsed = McpDnsSinkholeRequestSchema.safeParse(args);
      if (!parsed.success) {
        return deny('mcp:traffic:redirect', `Schema validation failed: ${parsed.error.message}`);
      }
      const req = parsed.data;

      const scopeErr = requireScope('mcp:traffic:redirect', req.audit);
      if (scopeErr) return scopeErr;

      const { ctx, activeLeasesCount } = await buildGuardContext(env.key, env.clientIp);
      if (activeLeasesCount >= env.key.policyLimits.maxActiveLeases) {
        return deny(
          'mcp:traffic:redirect',
          `Maximum active tactical leases (${env.key.policyLimits.maxActiveLeases}) reached for key '${env.key.name}'`,
          req.audit
        );
      }

      const normDomain = req.domain.trim().toLowerCase().replace(/\.+$/, '');
      const localState = loadLocalDesiredState();
      const sysDomain = localState?.system?.domain?.trim().toLowerCase().replace(/\.+$/, '');
      if (
        normDomain === 'localhost' ||
        normDomain.endsWith('.localhost') ||
        normDomain === 'axonwall.local' ||
        normDomain.endsWith('.axonwall.local') ||
        normDomain === 'home.arpa' ||
        normDomain.endsWith('.home.arpa') ||
        (sysDomain && (normDomain === sysDomain || normDomain.endsWith(`.${sysDomain}`)))
      ) {
        return deny('mcp:traffic:redirect', `Cannot sinkhole internal appliance domain '${req.domain}'`, req.audit);
      }

      const cleanSinkholeIp = req.sinkholeIp.trim();
      const isNullSinkhole =
        cleanSinkholeIp === '0.0.0.0' || cleanSinkholeIp === '::' || cleanSinkholeIp === '127.0.0.1';
      if (!isNullSinkhole) {
        const allowCheck = validateRedirectTargetAllowlist(
          cleanSinkholeIp,
          env.key.policyLimits.allowedRedirectTargets
        );
        if (!allowCheck.valid) {
          return deny(
            'mcp:traffic:redirect',
            allowCheck.reason || `Custom sinkholeIp '${cleanSinkholeIp}' must be in allowedRedirectTargets`,
            req.audit
          );
        }
        const targetCheck = validateMcpTarget(cleanSinkholeIp, ctx);
        if (!targetCheck.valid) {
          return deny('mcp:traffic:redirect', targetCheck.reason || 'Sinkhole IP rejected by safety guard', req.audit);
        }
      }

      const boundedTtl = Math.min(req.ttlSeconds, env.key.policyLimits.maxTtlSeconds);
      const daemonRes = await callAxonwalldApi('POST', '/v1/mcp/sinkhole-dns', {
        ...req,
        domain: normDomain,
        sinkholeIp: cleanSinkholeIp,
        ttlSeconds: boundedTtl,
        keyId: env.key.id,
        keyName: env.key.name,
      });

      if (!daemonRes.ok || !daemonRes.data?.lease?.id) {
        return deny('mcp:traffic:redirect', daemonRes.data?.error || 'Daemon rejected DNS sinkhole request', req.audit);
      }

      const lease = daemonRes.data.lease;

      const auditEntry = recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:traffic:redirect',
        decision: 'allowed',
        paramsSummary: {
          domain: normDomain,
          sinkholeIp: cleanSinkholeIp,
          ttlSeconds: boundedTtl,
        },
        auditMetadata: req.audit,
        leaseId: lease.id,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ success: true, lease, auditEntryHash: auditEntry.recorded ? auditEntry.entryHash : null, auditRecorded: auditEntry.recorded }, null, 2),
          },
        ],
      };
    }

    case 'mcp_revert_lease': {
      const hasAnyWriteScope =
        hasMcpScope(env.key, 'mcp:traffic:blackhole') ||
        hasMcpScope(env.key, 'mcp:traffic:shape') ||
        hasMcpScope(env.key, 'mcp:traffic:redirect') ||
        hasMcpScope(env.key, 'mcp:firewall:write');
      if (!hasAnyWriteScope) {
        return deny('mcp:traffic:*', 'MCP key lacks any traffic control write scope to revert leases');
      }

      const leaseId = typeof args.leaseId === 'string' ? args.leaseId.trim() : '';
      const reason = typeof args.reason === 'string' ? args.reason.trim() : 'Reverted via MCP';
      if (!leaseId) {
        return deny('mcp:traffic:*', 'leaseId is required');
      }

      const leasesRes = await callAxonwalldApi<{ leases?: Array<{ id?: string; kind?: string }> }>('GET', '/v1/mcp/leases');
      if (leasesRes.ok && Array.isArray(leasesRes.data?.leases)) {
        const targetLease = leasesRes.data.leases.find((l) => l.id === leaseId);
        if (targetLease?.kind && !hasMcpScope(env.key, 'mcp:firewall:write')) {
          const requiredForKind =
            targetLease.kind === 'blackhole'
              ? 'mcp:traffic:blackhole'
              : targetLease.kind === 'shape'
                ? 'mcp:traffic:shape'
                : targetLease.kind === 'redirect' || targetLease.kind === 'dns_sinkhole'
                  ? 'mcp:traffic:redirect'
                  : null;
          if (requiredForKind && !hasMcpScope(env.key, requiredForKind)) {
            return deny(requiredForKind, `MCP key lacks required scope '${requiredForKind}' to revert ${targetLease.kind} lease '${leaseId}'`);
          }
        }
      }

      const daemonRes = await callAxonwalldApi('POST', '/v1/mcp/revert', { leaseId });
      if (!daemonRes.ok) {
        return deny('mcp:traffic:*', daemonRes.data?.error || `Failed to revert lease '${leaseId}'`);
      }

      recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:traffic:*',
        decision: 'allowed',
        paramsSummary: { leaseId, reason },
        leaseId,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              daemonRes.data,
              null,
              2
            ),
          },
        ],
      };
    }

    case 'mcp_emergency_clear_all': {
      if (!hasMcpScope(env.key, 'mcp:firewall:apply')) {
        return deny('mcp:firewall:apply', "Authorization denied: 'mcp_emergency_clear_all' requires scope 'mcp:firewall:apply'");
      }

      const reason = typeof args.reason === 'string' ? args.reason.trim() : 'Emergency flush via MCP';
      const daemonRes = await callAxonwalldApi('POST', '/v1/mcp/flush', {});
      // B-H5: a daemon failure here must deny, not report success with
      // clearedCount 0 while every tactical lease is still active.
      if (!daemonRes.ok) {
        return deny(
          'mcp:firewall:apply',
          daemonRes.data?.error || 'Daemon unavailable: emergency clear-all was not applied; tactical leases are still active'
        );
      }
      recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:firewall:apply',
        decision: 'allowed',
        paramsSummary: { reason },
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                clearedCount: daemonRes.data?.clearedCount ?? 0,
                reason,
              },
              null,
              2
            ),
          },
        ],
      };
    }

    case 'mcp_propose_firewall_rule': {
      const parsed = McpProposeRuleRequestSchema.safeParse(args);
      if (!parsed.success) {
        return deny('mcp:firewall:write', `Schema validation failed: ${parsed.error.message}`);
      }
      const req = parsed.data;

      const writeErr = requireScope('mcp:firewall:write', req.audit);
      if (writeErr) return writeErr;

      if (req.applyImmediately) {
        const applyErr = requireScope('mcp:firewall:apply', req.audit);
        if (applyErr) return applyErr;
      }

      const state = loadLocalDesiredState();
      if (!state) {
        return deny('mcp:firewall:write', 'DesiredState file (/etc/axonwall/state.json) not found on appliance', req.audit);
      }

      const { ctx } = await buildGuardContext(env.key, env.clientIp);
      const checkEndpoint = (endpointVal: string | undefined, label: 'source' | 'destination', disallowWildcard: boolean): string | null => {
        if (!endpointVal || endpointVal === 'any') {
          if (disallowWildcard) {
            return `Wildcard '${endpointVal || 'any'}' ${label} on ${req.rule.action} rule exceeds blast-radius policy and is prohibited via MCP`;
          }
          return null;
        }
        if (endpointVal === 'self' || endpointVal === 'wan_ip') {
          if (req.rule.action === 'block' || req.rule.action === 'reject') {
            return `Targeting appliance endpoint '${endpointVal}' in ${label} on ${req.rule.action} rule is prohibited by anti-lockout guard`;
          }
          return null;
        }
        if (endpointVal === 'lan_net') {
          if (req.rule.action === 'block' || req.rule.action === 'reject') {
            return `Targeting entire '${endpointVal}' in ${label} on ${req.rule.action} rule is prohibited by anti-lockout guard`;
          }
          return null;
        }
        if (endpointVal.startsWith('$')) {
          const aliasName = endpointVal.slice(1);
          const aliasObj = (state.aliases ?? []).find((a) => a.name === aliasName);
          if (!aliasObj || !aliasObj.entries || aliasObj.entries.length === 0) {
            return `Referenced alias '${endpointVal}' in ${label} does not exist or has no entries`;
          }
          for (const entry of aliasObj.entries) {
            if (req.rule.action === 'block' || req.rule.action === 'reject') {
              const entryCheck = validateMcpTarget(entry, ctx);
              if (!entryCheck.valid) {
                return `Alias '${endpointVal}' entry '${entry}' in ${label} rejected by guard: ${entryCheck.reason}`;
              }
            }
          }
          return null;
        }
        if (req.rule.action === 'block' || req.rule.action === 'reject') {
          const directCheck = validateMcpTarget(endpointVal, ctx);
          if (!directCheck.valid) {
            return `Rule ${label} rejected by guard: ${directCheck.reason}`;
          }
        }
        return null;
      };

      const isBlockOrReject = req.rule.action === 'block' || req.rule.action === 'reject';
      if (!isBlockOrReject) {
        const srcErr = checkEndpoint(req.rule.source, 'source', false);
        if (srcErr) return deny('mcp:firewall:write', srcErr, req.audit);
        const dstErr = checkEndpoint(req.rule.destination, 'destination', false);
        if (dstErr) return deny('mcp:firewall:write', dstErr, req.audit);
        const ruleIface = (req.rule.interface || 'any').toLowerCase();
        const isWanOrAny = ruleIface === 'wan' || ruleIface === 'any';
        const rawPassDport = (req.rule.destinationPort || '').trim();
        if (
          isWanOrAny &&
          (!req.rule.source || req.rule.source === 'any') &&
          (!req.rule.destination || req.rule.destination === 'any' || req.rule.destination === 'self' || req.rule.destination === 'wan_ip') &&
          (!rawPassDport || rawPassDport === 'any')
        ) {
          return deny(
            'mcp:firewall:write',
            `Unscoped wildcard pass rule on '${ruleIface}' is prohibited via MCP`,
            req.audit,
          );
        }
      }

      if (isBlockOrReject) {
        const srcErr = checkEndpoint(req.rule.source, 'source', true);
        if (srcErr) return deny('mcp:firewall:write', srcErr, req.audit);
        if (req.rule.destination && req.rule.destination !== 'any') {
          const dstErr = checkEndpoint(req.rule.destination, 'destination', false);
          if (dstErr) return deny('mcp:firewall:write', dstErr, req.audit);
        }

        const protectedTcpPorts = ctx.antiLockoutPorts ?? [2966, 22, 9876];
        const protectedUdpPorts = [53, 67, 68, 51820];
        const rawDport = (req.rule.destinationPort || '').trim();
        const affectsTcp =
          req.rule.protocol === 'any' || req.rule.protocol === 'tcp' || req.rule.protocol === 'tcp_udp';
        const affectsUdp =
          req.rule.protocol === 'any' || req.rule.protocol === 'udp' || req.rule.protocol === 'tcp_udp';
        const protectedPorts = Array.from(
          new Set([
            ...(affectsTcp ? protectedTcpPorts : []),
            ...(affectsUdp ? protectedUdpPorts : []),
          ])
        );

        if ((affectsTcp || affectsUdp) && (!rawDport || rawDport === 'any')) {
          return deny(
            'mcp:firewall:write',
            `Wildcard/empty destinationPort on ${req.rule.action} rule covers protected ports (${protectedPorts.join(', ')})`,
            req.audit,
          );
        }
        const validatePortToken = (part: string): string | null => {
          if (/^\d+$/.test(part)) {
            const portNum = Number(part);
            if (portNum < 1 || portNum > 65535) {
              return `Invalid destinationPort '${part}'`;
            }
            if (protectedPorts.includes(portNum)) {
              return `Blocking protected port ${portNum} is prohibited`;
            }
            return null;
          }
          const rangeMatch = part.match(/^(\d+)\s*[-:]\s*(\d+)$/);
          if (rangeMatch) {
            const start = Math.min(Number(rangeMatch[1]), Number(rangeMatch[2]));
            const end = Math.max(Number(rangeMatch[1]), Number(rangeMatch[2]));
            if (start < 1 || end > 65535) {
              return `Invalid port range '${part}'`;
            }
            const hit = protectedPorts.find((p) => p >= start && p <= end);
            if (hit !== undefined) {
              return `Port range ${part} overlaps protected port ${hit}`;
            }
            return null;
          }
          return `Invalid or unresolvable destinationPort token '${part}'`;
        };
        if (rawDport && rawDport !== 'any') {
          if (rawDport.startsWith('$')) {
            const aliasName = rawDport.slice(1);
            const aliasObj = (state.aliases ?? []).find((a) => a.name === aliasName && a.type === 'port');
            if (!aliasObj || !aliasObj.entries || aliasObj.entries.length === 0) {
              return deny(
                'mcp:firewall:write',
                `Referenced port alias '${rawDport}' in destinationPort does not exist or has no entries`,
                req.audit,
              );
            }
            for (const entry of aliasObj.entries) {
              const portErr = validatePortToken(entry.trim());
              if (portErr) return deny('mcp:firewall:write', portErr, req.audit);
            }
          } else {
            for (const part of rawDport.split(',').map((s) => s.trim()).filter(Boolean)) {
              const portErr = validatePortToken(part);
              if (portErr) return deny('mcp:firewall:write', portErr, req.audit);
            }
          }
        }
      }

      const persistDesiredState = (targetState: DesiredState) => {
        try {
          fs.writeFileSync('/etc/axonwall/state.json', JSON.stringify(targetState, null, 2), { mode: 0o600 });
        } catch {
          // Fallback if /etc/axonwall not writable in dev
        }
        try {
          fs.writeFileSync('/var/lib/axonwall/state.json', JSON.stringify(targetState, null, 2), { mode: 0o600 });
        } catch {}
        try {
          const yamlFiles = serializeDesiredStateToYamlFiles(targetState);
          for (const dir of ['/etc/axonwall', '/var/lib/axonwall/etc-axonwall']) {
            if (fs.existsSync(dir)) {
              for (const [fn, content] of Object.entries(yamlFiles)) {
                fs.writeFileSync(`${dir}/${fn}`, content, { mode: 0o660 });
              }
            }
          }
        } catch {}
      };

      // B2-M4: serialize the load -> mutate -> persist window with
      // the MCP lockfile. Two concurrent proposes (or a propose
      // racing a console/TUI save) used to load the same state,
      // mutate their own stale copies, and persist last-writer-wins
      // — the loser's rule vanished from disk AND from the kernel
      // (the second apply pushed the loser's rule-less state),
      // while both calls reported success. The lock is held only
      // around the synchronous reload/mutate/persist, never across
      // the awaits (guard build above, daemon apply below), and the
      // mutation is re-applied to a freshly reloaded state inside
      // the lock so a concurrent writer's rule cannot be clobbered.
      // `state` stays the guard-phase snapshot (const, so the guard
      // closures keep their non-null narrowing); `liveState` is the
      // freshly reloaded state the apply below compiles.
      let liveState = state;
      let releaseStateLock: (() => void) | null = null;
      try {
        try {
          releaseStateLock = acquireMcpLockFile(desiredStateLockPath());
        } catch (err: any) {
          return deny('mcp:firewall:write', `Could not lock DesiredState for the rule update (${err?.message || err}); retry the propose`, req.audit);
        }
        const fresh = loadLocalDesiredState();
        if (!fresh) {
          return deny('mcp:firewall:write', 'DesiredState file (/etc/axonwall/state.json) not found on appliance', req.audit);
        }
        insertMcpRuleIntoState(fresh, req.rule);
        persistDesiredState(fresh);
        liveState = fresh;
      } finally {
        releaseStateLock?.();
      }

      let applyStatus = 'staged_only';
      let applyJobId: string | undefined;
      if (req.applyImmediately) {
        const compiled = compileNftables(liveState);
        const hashInput = JSON.stringify({
          nftScript: compiled.nftScript,
          files: [...compiled.files]
            .sort((a, b) => a.path.localeCompare(b.path))
            .map((f) => ({ path: f.path, content: f.content, fileMode: f.fileMode })),
          reloadServices: [...compiled.reloadServices].sort(),
        });
        // B2-M2: the jobId is returned in the response (below) so
        // the caller can confirm the apply with mcp_confirm_apply
        // before the commit-confirm window expires.
        applyJobId = newMcpApplyJobId();
        const applyRes = await callAxonwalldApi('POST', '/v1/apply', {
          nftScript: compiled.nftScript,
          confirmTimeoutSeconds: req.confirmTimeoutSeconds,
          files: compiled.files,
          jobId: applyJobId,
          bundleHash: crypto.createHash('sha256').update(hashInput).digest('hex'),
          nftablesRuleset: compiled.nftScript,
          reloadServices: compiled.reloadServices,
          commitConfirmTimeoutSec: req.confirmTimeoutSeconds,
        });
        if (!applyRes.ok) {
          // B2-M4: roll the staged rule back out under the same
          // lock, reloaded fresh — restoring a stale snapshot here
          // would clobber a concurrent writer's rule exactly like
          // the bug above. The rule is removed by deep equality
          // (rule.id is optional), so a pre-existing identical
          // rule survives as one copy.
          const stagedRuleJson = JSON.stringify(req.rule);
          let releaseRollbackLock: (() => void) | null = null;
          try {
            try {
              releaseRollbackLock = acquireMcpLockFile(desiredStateLockPath());
            } catch {
              // Best effort: the daemon rejected the apply, so the
              // staged rule is inert in the kernel; a locked
              // rollback that cannot run is logged, not fatal.
              console.error('[MCP] Could not lock DesiredState to roll back a rejected staged rule; the staged rule remains on disk');
              releaseRollbackLock = null;
            }
            if (releaseRollbackLock) {
              const fresh = loadLocalDesiredState();
              if (fresh) {
                const idx = fresh.rules.findIndex((r) => JSON.stringify(r) === stagedRuleJson);
                if (idx !== -1) {
                  fresh.rules.splice(idx, 1);
                  persistDesiredState(fresh);
                }
              }
            }
          } finally {
            releaseRollbackLock?.();
          }
          return deny(
            'mcp:firewall:apply',
            applyRes.data?.error || 'Daemon rejected ruleset apply; rolled back staged rule',
            req.audit,
          );
        }
        applyStatus = `applied_with_commit_confirm_${req.confirmTimeoutSeconds}s`;
      }

      const auditEntry = recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: req.applyImmediately ? 'mcp:firewall:apply' : 'mcp:firewall:write',
        decision: 'allowed',
        paramsSummary: {
          ruleId: req.rule.id,
          action: req.rule.action,
          source: req.rule.source,
          destination: req.rule.destination,
          applyStatus,
        },
        auditMetadata: req.audit,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                rule: req.rule,
                applyStatus,
                ...(applyJobId ? { jobId: applyJobId } : {}),
                commitConfirmNotice: req.applyImmediately
                  ? `Declarative state applied with ${req.confirmTimeoutSeconds}s Commit-Confirm watchdog protection. Confirm it with mcp_confirm_apply and jobId "${applyJobId}" before the window expires or the daemon auto-rolls the ruleset back.`
                  : 'Rule staged in DesiredState.',
                auditEntryHash: auditEntry.recorded ? auditEntry.entryHash : null,
                auditRecorded: auditEntry.recorded,
              },
              null,
              2
            ),
          },
        ],
      };
    }

    case 'mcp_confirm_apply': {
      const applyErr = requireScope('mcp:firewall:apply');
      if (applyErr) return applyErr;

      const jobId = typeof args.jobId === 'string' ? args.jobId.trim() : '';
      if (!jobId) {
        return deny('mcp:firewall:apply', 'jobId is required: pass the jobId returned by mcp_propose_firewall_rule when the rule was applied');
      }

      // B2-M2: the other half of the propose flow. The daemon
      // requires an exact job-id match to confirm, and a mismatch
      // (or no pending job) is a 200 with success:false, not an
      // HTTP error — so check the payload, not just the status.
      const confirmRes = await callAxonwalldApi('POST', '/v1/confirm', { jobId, job_id: jobId });
      if (!confirmRes.ok) {
        return deny(
          'mcp:firewall:apply',
          `Daemon unreachable: could not confirm the apply; the ruleset may auto-roll back at the end of its commit-confirm window${confirmRes.data?.error ? ` (${confirmRes.data.error})` : ''}`,
        );
      }
      if (confirmRes.data?.success !== true) {
        return deny('mcp:firewall:apply', confirmRes.data?.message || `Daemon refused to confirm job ${jobId}`);
      }

      recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:firewall:apply',
        decision: 'allowed',
        paramsSummary: { jobId, reason: typeof args.reason === 'string' ? args.reason : undefined },
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                jobId,
                confirmed: true,
                message: confirmRes.data?.message || 'Configuration confirmed and promoted to last-known-good.',
              },
              null,
              2
            ),
          },
        ],
      };
    }

    case 'mcp_inspect_ebpf_dataplane': {
      const { matched, err } = requireAnyScope(['mcp:ebpf:read', 'mcp:telemetry:read']);
      if (err) return err;

      const limit = typeof args.limit === 'number' ? Math.min(200, Math.max(1, Math.trunc(args.limit))) : 50;
      const res = await callAxonwalldApi('GET', `/v1/ebpf/overview?limit=${limit}`);
      recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: matched!,
        decision: 'allowed',
        paramsSummary: { limit },
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              res.ok
                ? res.data
                : {
                    dataplane: null,
                    lsm: null,
                    bpfTokens: null,
                    daemonDown: true,
                    error: res.data?.error || 'axonwalld unreachable',
                  },
              null,
              2,
            ),
          },
        ],
      };
    }

    case 'mcp_xdp_fast_drop': {
      const parsed = McpXdpFastDropRequestSchema.safeParse(args);
      if (!parsed.success) {
        return deny('mcp:ebpf:manage', `Schema validation failed: ${parsed.error.message}`);
      }
      const req = parsed.data;

      const scopeErr = requireScope('mcp:ebpf:manage', req.audit);
      if (scopeErr) return scopeErr;

      if (req.action === 'set_syn_limit') {
        const maxSynPps = req.synFloodLimitPps ?? 0;
        if (maxSynPps > 0 && maxSynPps < 20) {
          return deny('mcp:ebpf:manage', 'synFloodLimitPps must be 0 (disabled) or >= 20 PPS to prevent self-lockout', req.audit);
        }
        const daemonRes = await callAxonwalldApi('POST', '/v1/ebpf/xdp/syn-limit', { maxSynPps });
        if (!daemonRes.ok) {
          return deny('mcp:ebpf:manage', daemonRes.data?.error || 'Daemon rejected XDP SYN-flood limit update', req.audit);
        }
        const auditEntry = recordMcpAuditEntry({
          keyId: env.key.id,
          keyName: env.key.name,
          agentType: env.key.agentType,
          clientIp: env.clientIp,
          toolName,
          requiredScope: 'mcp:ebpf:manage',
          decision: 'allowed',
          paramsSummary: { action: 'set_syn_limit', synFloodLimitPps: maxSynPps },
          auditMetadata: req.audit,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  action: 'set_syn_limit',
                  synFloodLimitPps: maxSynPps,
                  auditEntryHash: auditEntry.recorded ? auditEntry.entryHash : null,
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      if (!req.ipAddress) {
        return deny('mcp:ebpf:manage', 'ipAddress (host IP or CIDR subnet) is required for block/unblock', req.audit);
      }

      const parsedIp = parseIpOrCidr(req.ipAddress);
      if (!parsedIp) {
        return deny('mcp:ebpf:manage', `Invalid IPv4/IPv6 address or CIDR prefix '${req.ipAddress}'`, req.audit);
      }

      const targetValue = parsedIp.isSingleHost ? parsedIp.address : parsedIp.normalizedCidr;

      if (req.action === 'block') {
        const { ctx } = await buildGuardContext(env.key, env.clientIp);
        const targetCheck = validateMcpTarget(targetValue, ctx);
        if (!targetCheck.valid) {
          return deny('mcp:ebpf:manage', targetCheck.reason || 'Target rejected by anti-lockout / blast-radius guard', req.audit);
        }

        const boundedTtl = Math.min(req.ttlSeconds, env.key.policyLimits.maxTtlSeconds);
        const daemonRes = await callAxonwalldApi('POST', '/v1/ebpf/xdp/block', {
          ip: targetCheck.normalizedTarget || targetValue,
          ttlSeconds: boundedTtl,
          reasonCode: parsedIp.isSingleHost ? 1 : 4,
          reason: req.audit.reason,
        });
        if (!daemonRes.ok) {
          return deny('mcp:ebpf:manage', daemonRes.data?.error || 'Daemon rejected XDP fast-drop block', req.audit);
        }

        const auditEntry = recordMcpAuditEntry({
          keyId: env.key.id,
          keyName: env.key.name,
          agentType: env.key.agentType,
          clientIp: env.clientIp,
          toolName,
          requiredScope: 'mcp:ebpf:manage',
          decision: 'allowed',
          paramsSummary: { action: 'block', ipAddress: targetValue, isCidr: !parsedIp.isSingleHost, ttlSeconds: boundedTtl },
          auditMetadata: req.audit,
        });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  action: 'block',
                  ipAddress: targetValue,
                  isCidr: !parsedIp.isSingleHost,
                  ttlSeconds: boundedTtl,
                  activeBlocks: daemonRes.data?.blocks ?? [],
                  auditEntryHash: auditEntry.recorded ? auditEntry.entryHash : null,
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      const daemonRes = await callAxonwalldApi(
        'DELETE',
        `/v1/ebpf/xdp/block?ip=${encodeURIComponent(targetValue)}`,
      );
      if (!daemonRes.ok) {
        return deny('mcp:ebpf:manage', daemonRes.data?.error || 'Daemon rejected XDP fast-drop unblock', req.audit);
      }

      const auditEntry = recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:ebpf:manage',
        decision: 'allowed',
        paramsSummary: { action: 'unblock', ipAddress: targetValue },
        auditMetadata: req.audit,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                action: 'unblock',
                ipAddress: targetValue,
                auditEntryHash: auditEntry.recorded ? auditEntry.entryHash : null,
              },
              null,
              2,
            ),
          },
        ],
      };
    }

    case 'mcp_manage_bpf_token_profile': {
      const parsed = McpManageBpfTokenProfileRequestSchema.safeParse(args);
      if (!parsed.success) {
        return deny('mcp:ebpf:manage', `Schema validation failed: ${parsed.error.message}`);
      }
      const req = parsed.data;

      const scopeErr = requireScope('mcp:ebpf:manage', req.audit);
      if (scopeErr) return scopeErr;

      if (req.operation === 'upsert') {
        const maskCheck = validateBpfTokenDelegationInput(req);
        if (!maskCheck.valid) {
          return deny('mcp:ebpf:manage', maskCheck.reason || 'Rejected unsafe BPF_TOKEN delegation bitmask', req.audit);
        }

        const daemonRes = await callAxonwalldApi('POST', '/v1/ebpf/tokens', {
          id: req.id,
          targetKind: req.targetKind,
          targetRef: req.targetRef || '',
          preset: req.preset,
          enabled: req.enabled,
          delegateCmds: req.delegateCmds || '',
          delegateProgs: req.delegateProgs || '',
          delegateMaps: req.delegateMaps || '',
          delegateAttachs: req.delegateAttachs || '',
          auditViaBpfLsm: req.auditViaBpfLsm,
          description: req.description || '',
        });
        if (!daemonRes.ok) {
          return deny('mcp:ebpf:manage', daemonRes.data?.error || 'Daemon rejected BPF_TOKEN profile upsert', req.audit);
        }

        const auditEntry = recordMcpAuditEntry({
          keyId: env.key.id,
          keyName: env.key.name,
          agentType: env.key.agentType,
          clientIp: env.clientIp,
          toolName,
          requiredScope: 'mcp:ebpf:manage',
          decision: 'allowed',
          paramsSummary: { operation: 'upsert', id: req.id, preset: req.preset, targetKind: req.targetKind },
          auditMetadata: req.audit,
        });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  operation: 'upsert',
                  profile: daemonRes.data?.profile ?? null,
                  auditEntryHash: auditEntry.recorded ? auditEntry.entryHash : null,
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      const daemonRes = await callAxonwalldApi('DELETE', `/v1/ebpf/tokens?id=${encodeURIComponent(req.id)}`);
      if (!daemonRes.ok) {
        return deny('mcp:ebpf:manage', daemonRes.data?.error || `Daemon rejected BPF_TOKEN profile deletion for '${req.id}'`, req.audit);
      }

      const auditEntry = recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:ebpf:manage',
        decision: 'allowed',
        paramsSummary: { operation: 'delete', id: req.id },
        auditMetadata: req.audit,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                operation: 'delete',
                deletedId: req.id,
                auditEntryHash: auditEntry.recorded ? auditEntry.entryHash : null,
              },
              null,
              2,
            ),
          },
        ],
      };
    }

    case 'mcp_inspect_virt_workloads': {
      const { matched, err } = requireAnyScope(['mcp:virt:read', 'mcp:telemetry:read']);
      if (err) return err;

      const includeBackups = args.includeBackups !== false;
      const includePci = args.includePci !== false;
      const [vmsRes, ctsRes, telRes, pciRes, backupsRes] = await Promise.all([
        callAxonwalldApi('GET', '/v1/virt/vms'),
        callAxonwalldApi('GET', '/v1/virt/containers'),
        callAxonwalldApi('GET', '/v1/virt/telemetry'),
        includePci ? callAxonwalldApi('GET', '/v1/virt/pci') : Promise.resolve({ ok: true, status: 200, data: { devices: [] } }),
        includeBackups ? callAxonwalldApi('GET', '/v1/virt/backups') : Promise.resolve({ ok: true, status: 200, data: { backups: [] } }),
      ]);

      recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: matched!,
        decision: 'allowed',
        paramsSummary: { includeBackups, includePci },
      });

      const daemonDown = !vmsRes.ok && !ctsRes.ok && !telRes.ok;
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                vms: vmsRes.ok ? vmsRes.data?.vms ?? [] : [],
                containers: ctsRes.ok ? ctsRes.data?.containers ?? [] : [],
                ebpfTelemetry: telRes.ok ? telRes.data : null,
                ...(includePci ? { pciDevices: pciRes.ok ? pciRes.data?.devices ?? [] : [] } : {}),
                ...(includeBackups ? { backups: backupsRes.ok ? backupsRes.data?.backups ?? [] : [] } : {}),
                ...(daemonDown ? { daemonDown: true, error: vmsRes.data?.error || 'axonwalld unreachable' } : {}),
              },
              null,
              2,
            ),
          },
        ],
      };
    }

    case 'mcp_control_virt_workload': {
      const parsed = McpVirtControlRequestSchema.safeParse(args);
      if (!parsed.success) {
        return deny('mcp:virt:manage', `Schema validation failed: ${parsed.error.message}`);
      }
      const req = parsed.data;

      const scopeErr = requireScope('mcp:virt:manage', req.audit);
      if (scopeErr) return scopeErr;

      const localState = loadLocalDesiredState();
      let workloadName: string | undefined;
      if (req.workloadType === 'vm') {
        workloadName = localState?.virt?.vms?.find((v) => v.vmid === req.id)?.name;
        if (!workloadName) {
          const vmsRes = await callAxonwalldApi('GET', '/v1/virt/vms');
          if (vmsRes.ok && Array.isArray(vmsRes.data?.vms)) {
            workloadName = vmsRes.data.vms.find((v: any) => Number(v.vmid) === req.id)?.name;
          }
        }
      } else {
        workloadName = localState?.virt?.containers?.find((c) => c.ctid === req.id)?.hostname;
        if (!workloadName) {
          const ctsRes = await callAxonwalldApi('GET', '/v1/virt/containers');
          if (ctsRes.ok && Array.isArray(ctsRes.data?.containers)) {
            workloadName = ctsRes.data.containers.find((c: any) => Number(c.ctid) === req.id)?.hostname;
          }
        }
      }

      const safetyCheck = validateVirtWorkloadSafety(workloadName, req.action, localState?.hostedEdge?.enabled);
      if (!safetyCheck.valid) {
        return deny('mcp:virt:manage', safetyCheck.reason || 'Virtualization action blocked by anti-lockout guard', req.audit);
      }

      let daemonRes: { ok: boolean; status: number; data: any };
      if (req.action === 'backup') {
        const poolName = req.storagePool || 'tank';
        const poolCheck = validateZfsResourcePath(poolName, false);
        if (!poolCheck.valid) {
          return deny('mcp:virt:manage', poolCheck.reason || 'Invalid backup storagePool', req.audit);
        }
        daemonRes = await callAxonwalldApi('POST', '/v1/virt/backups', {
          action: 'run',
          targetType: req.workloadType,
          targetId: req.id,
          pool: poolCheck.normalizedTarget,
          destType: 'local',
        });
      } else if (req.action === 'restore') {
        if (!req.backupArchivePath) {
          return deny('mcp:virt:manage', 'backupArchivePath (.vma.zst filename) is required for restore action', req.audit);
        }
        const poolName = req.storagePool || 'tank';
        const poolCheck = validateZfsResourcePath(poolName, false);
        if (!poolCheck.valid) {
          return deny('mcp:virt:manage', poolCheck.reason || 'Invalid restore storagePool', req.audit);
        }
        daemonRes = await callAxonwalldApi('POST', '/v1/virt/backups', {
          action: 'restore',
          archiveName: path.basename(req.backupArchivePath),
          targetType: req.workloadType,
          targetId: req.id,
          pool: poolCheck.normalizedTarget,
        });
      } else if (req.action === 'snapshot' || req.action === 'rollback') {
        const label = req.snapshotName || (req.action === 'snapshot' ? `mcp-${Date.now()}` : '');
        if (!label) {
          return deny('mcp:virt:manage', 'snapshotName is required for rollback action', req.audit);
        }
        daemonRes = await callAxonwalldApi('POST', '/v1/virt/snapshots', {
          action: req.action === 'snapshot' ? 'create' : 'rollback',
          targetType: req.workloadType,
          targetId: req.id,
          label,
        });
      } else if (req.action === 'clone') {
        if (req.workloadType !== 'vm' || !req.newId) {
          return deny('mcp:virt:manage', 'clone requires workloadType="vm" and newId (100-99999)', req.audit);
        }
        daemonRes = await callAxonwalldApi('POST', '/v1/virt/clone', {
          sourceVmid: req.id,
          newVmid: req.newId,
          newName: req.newName || '',
          linked: req.linkedClone !== false,
        });
      } else if (req.action === 'live_migrate') {
        if (req.workloadType !== 'vm' || !req.targetHostIp) {
          return deny('mcp:virt:manage', 'live_migrate requires workloadType="vm" and targetHostIp', req.audit);
        }
        daemonRes = await callAxonwalldApi('POST', '/v1/virt/migrate', {
          vmid: req.id,
          targetPeerIp: req.targetHostIp,
        });
      } else if (req.action === 'qga_interfaces') {
        daemonRes = await callAxonwalldApi('GET', `/v1/virt/qga?vmid=${encodeURIComponent(String(req.id))}`);
      } else if (req.action === 'export_libvirt_xml') {
        daemonRes = await callAxonwalldApi('GET', `/v1/virt/libvirt-xml?vmid=${encodeURIComponent(String(req.id))}`);
      } else if (req.workloadType === 'vm') {
        const vmAction = req.action === 'reboot' ? 'reset' : req.action;
        daemonRes = await callAxonwalldApi('POST', '/v1/virt/vms', {
          action: vmAction,
          vmid: req.id,
          force: req.force,
        });
      } else {
        if (req.action === 'pause' || req.action === 'resume') {
          return deny('mcp:virt:manage', `Action '${req.action}' is only supported on KVM VMs, not LXC containers`, req.audit);
        }
        if (req.action === 'reboot') {
          const stopRes = await callAxonwalldApi('POST', '/v1/virt/containers', {
            action: 'stop',
            ctid: req.id,
            force: req.force,
          });
          if (!stopRes.ok) {
            return deny('mcp:virt:manage', stopRes.data?.error || `Failed to stop LXC CT ${req.id} during reboot`, req.audit);
          }
          daemonRes = await callAxonwalldApi('POST', '/v1/virt/containers', {
            action: 'start',
            ctid: req.id,
            force: false,
          });
        } else {
          daemonRes = await callAxonwalldApi('POST', '/v1/virt/containers', {
            action: req.action,
            ctid: req.id,
            force: req.force,
          });
        }
      }

      if (!daemonRes.ok) {
        return deny(
          'mcp:virt:manage',
          daemonRes.data?.error || daemonRes.data?.raw || `Daemon failed to execute '${req.action}' on ${req.workloadType} ${req.id}`,
          req.audit,
        );
      }

      const auditEntry = recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:virt:manage',
        decision: 'allowed',
        paramsSummary: { workloadType: req.workloadType, id: req.id, action: req.action, force: req.force },
        auditMetadata: req.audit,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                workloadType: req.workloadType,
                id: req.id,
                action: req.action,
                result: daemonRes.data,
                auditEntryHash: auditEntry.recorded ? auditEntry.entryHash : null,
              },
              null,
              2,
            ),
          },
        ],
      };
    }

    case 'mcp_configure_lxc_bpf_token': {
      const parsed = McpConfigureLxcBpfTokenRequestSchema.safeParse(args);
      if (!parsed.success) {
        return deny('mcp:virt:manage', `Schema validation failed: ${parsed.error.message}`);
      }
      const req = parsed.data;

      const virtErr = requireScope('mcp:virt:manage', req.audit);
      if (virtErr) return virtErr;
      const ebpfErr = requireScope('mcp:ebpf:manage', req.audit);
      if (ebpfErr) return ebpfErr;

      if (req.enabled) {
        const maskCheck = validateBpfTokenDelegationInput(req);
        if (!maskCheck.valid) {
          return deny('mcp:ebpf:manage', maskCheck.reason || 'Unsafe LXC BPF_TOKEN delegation bitmask', req.audit);
        }
      }

      let compiledConfig = '';
      let releaseLock: (() => void) | null = null;
      try {
        try {
          releaseLock = acquireMcpLockFile(desiredStateLockPath());
        } catch (err: any) {
          return deny('mcp:virt:manage', `Could not lock DesiredState (${err?.message || err})`, req.audit);
        }
        const fresh = loadLocalDesiredState();
        if (!fresh) {
          return deny('mcp:virt:manage', 'DesiredState file not found on appliance', req.audit);
        }
        const containers = fresh.virt?.containers ?? [];
        const ct = containers.find((c) => c.ctid === req.ctid);
        if (!ct) {
          return deny('mcp:virt:manage', `LXC container CT ${req.ctid} not found in DesiredState`, req.audit);
        }
        if (req.enabled && ct.unprivileged === false) {
          return deny(
            'mcp:ebpf:manage',
            `Linux 6.9+ BPF_TOKEN delegation requires an unprivileged LXC container (unprivileged: true with CLONE_NEWUSER), but CT ${req.ctid} ('${ct.hostname}') has unprivileged: false`,
            req.audit,
          );
        }

        ct.bpfToken = req.enabled
          ? {
              enabled: true,
              preset: req.preset,
              delegateCmds: req.delegateCmds,
              delegateProgs: req.delegateProgs,
              delegateMaps: req.delegateMaps,
              delegateAttachs: req.delegateAttachs,
              auditViaBpfLsm: true,
            }
          : {
              enabled: false,
              preset: req.preset,
              auditViaBpfLsm: true,
            };

        const compiled = compileLxcContainer(ct);
        compiledConfig = compiled.lxcConfig;
        persistDesiredStateToDisk(fresh);
      } finally {
        releaseLock?.();
      }

      const profileId = `ct-${req.ctid}`;
      const daemonRes = req.enabled
        ? await callAxonwalldApi('POST', '/v1/ebpf/tokens', {
            id: profileId,
            targetKind: 'lxc',
            targetRef: String(req.ctid),
            preset: req.preset,
            enabled: true,
            delegateCmds: req.delegateCmds || '',
            delegateProgs: req.delegateProgs || '',
            delegateMaps: req.delegateMaps || '',
            delegateAttachs: req.delegateAttachs || '',
            auditViaBpfLsm: true,
            description: `Unprivileged LXC CT ${req.ctid} BPF_TOKEN delegation`,
          })
        : await callAxonwalldApi('DELETE', `/v1/ebpf/tokens?id=${encodeURIComponent(profileId)}`);

      const auditEntry = recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:ebpf:manage',
        decision: 'allowed',
        paramsSummary: { ctid: req.ctid, enabled: req.enabled, preset: req.preset },
        auditMetadata: req.audit,
      });

      const bpfLines = compiledConfig
        .split('\n')
        .filter((l) => l.includes('bpf') || l.includes('LIBBPF_BPF_TOKEN_PATH'));

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                ctid: req.ctid,
                enabled: req.enabled,
                preset: req.preset,
                stagedInDesiredState: true,
                daemonProfileSync: daemonRes.ok ? 'synced' : 'staged_offline',
                compiledBpfDirectives: bpfLines,
                auditEntryHash: auditEntry.recorded ? auditEntry.entryHash : null,
              },
              null,
              2,
            ),
          },
        ],
      };
    }

    case 'mcp_inspect_k3s_cluster': {
      const { matched, err } = requireAnyScope(['mcp:k3s:read', 'mcp:telemetry:read']);
      if (err) return err;

      const res = await callAxonwalldApi('GET', '/v1/k3s/telemetry');
      recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: matched!,
        decision: 'allowed',
        paramsSummary: {},
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              res.ok
                ? res.data
                : {
                    status: null,
                    cniInterfaces: [],
                    bpfTokenProfiles: [],
                    daemonDown: true,
                    error: res.data?.error || 'axonwalld unreachable',
                  },
              null,
              2,
            ),
          },
        ],
      };
    }

    case 'mcp_render_k3s_bpf_token_manifest': {
      const { matched, err } = requireAnyScope(['mcp:k3s:read', 'mcp:ebpf:read', 'mcp:telemetry:read']);
      if (err) return err;

      const parsed = McpRenderK3sBpfTokenRequestSchema.safeParse(args);
      if (!parsed.success) {
        return deny(matched!, `Schema validation failed: ${parsed.error.message}`);
      }
      const req = parsed.data;

      const daemonRes = await callAxonwalldApi('POST', '/v1/ebpf/tokens/render-k3s', {
        profileId: req.profileId,
        profile: {
          id: req.profileId,
          targetKind: 'k3s-pod',
          preset: req.preset,
          enabled: true,
          auditViaBpfLsm: true,
        },
        workloadName: req.workloadName,
        namespace: req.namespace,
        image: req.image,
        kind: req.kind,
      });

      const manifestYaml =
        daemonRes.ok && typeof daemonRes.data?.manifestYaml === 'string'
          ? daemonRes.data.manifestYaml
          : renderOfflineK3sBpfTokenYaml(req);

      recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: matched!,
        decision: 'allowed',
        paramsSummary: req,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                profileId: req.profileId,
                preset: req.preset,
                kind: req.kind,
                manifestYaml,
                ...(daemonRes.ok ? {} : { renderedOffline: true }),
              },
              null,
              2,
            ),
          },
        ],
      };
    }

    case 'mcp_inspect_nas_storage': {
      const { matched, err } = requireAnyScope(['mcp:nas:read', 'mcp:telemetry:read']);
      if (err) return err;

      const includeDisks = args.includeDisks !== false;
      const includeSnapshots = args.includeSnapshots !== false;
      const [telRes, disksRes, snapsRes] = await Promise.all([
        callAxonwalldApi('GET', '/v1/nas/telemetry'),
        includeDisks ? callAxonwalldApi('GET', '/v1/nas/disks') : Promise.resolve({ ok: true, status: 200, data: { disks: [] } }),
        includeSnapshots ? callAxonwalldApi('GET', '/v1/nas/snapshots') : Promise.resolve({ ok: true, status: 200, data: { snapshots: [] } }),
      ]);

      recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: matched!,
        decision: 'allowed',
        paramsSummary: { includeDisks, includeSnapshots },
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                telemetry: telRes.ok ? telRes.data : null,
                ...(includeDisks ? { disks: disksRes.ok ? disksRes.data?.disks ?? [] : [] } : {}),
                ...(includeSnapshots ? { snapshots: snapsRes.ok ? snapsRes.data?.snapshots ?? [] : [] } : {}),
                ...(!telRes.ok ? { daemonDown: true, error: telRes.data?.error || 'axonwalld unreachable' } : {}),
              },
              null,
              2,
            ),
          },
        ],
      };
    }

    case 'mcp_nas_snapshot_or_scrub':
    case 'mcp_manage_zfs_nas': {
      const parsed = McpNasActionRequestSchema.safeParse(args);
      if (!parsed.success) {
        return deny('mcp:nas:manage', `Schema validation failed: ${parsed.error.message}`);
      }
      const req = parsed.data;

      const scopeErr = requireScope('mcp:nas:manage', req.audit);
      if (scopeErr) return scopeErr;

      let daemonRes: { ok: boolean; status: number; data: any };
      const summaryParams: Record<string, unknown> = { action: req.action, target: req.target };

      switch (req.action) {
        case 'snapshot': {
          const targetCheck = validateZfsResourcePath(req.target, true);
          if (!targetCheck.valid) return deny('mcp:nas:manage', targetCheck.reason || 'Invalid ZFS dataset path', req.audit);
          const label = req.snapshotLabel ? req.snapshotLabel.trim() : `mcp-${Date.now()}`;
          const labelCheck = validateZfsResourcePath(label, false);
          if (!labelCheck.valid) return deny('mcp:nas:manage', labelCheck.reason || 'Invalid ZFS snapshot label', req.audit);
          summaryParams.dataset = targetCheck.normalizedTarget;
          summaryParams.label = labelCheck.normalizedTarget;
          daemonRes = await callAxonwalldApi('POST', '/v1/nas/snapshots', {
            dataset: targetCheck.normalizedTarget,
            label: labelCheck.normalizedTarget,
          });
          break;
        }
        case 'rollback':
        case 'delete_snapshot': {
          const snapParts = req.target.trim().split('@');
          if (snapParts.length !== 2) {
            return deny('mcp:nas:manage', `Expected snapshot identifier in 'dataset@label' format, got '${req.target}'`, req.audit);
          }
          const dsCheck = validateZfsResourcePath(snapParts[0]!, true);
          const lblCheck = validateZfsResourcePath(snapParts[1]!, false);
          if (!dsCheck.valid || !lblCheck.valid) {
            return deny('mcp:nas:manage', dsCheck.reason || lblCheck.reason || 'Invalid ZFS snapshot identifier', req.audit);
          }
          const fullSnap = `${dsCheck.normalizedTarget}@${lblCheck.normalizedTarget}`;
          daemonRes =
            req.action === 'rollback'
              ? await callAxonwalldApi('POST', '/v1/nas/snapshots/rollback', { snapshot: fullSnap, destroyNewer: false })
              : await callAxonwalldApi('DELETE', `/v1/nas/snapshots?snapshot=${encodeURIComponent(fullSnap)}`);
          break;
        }
        case 'scrub':
        case 'trim':
        case 'checkpoint':
        case 'discard_checkpoint': {
          const poolCheck = validateZfsResourcePath(req.target, false);
          if (!poolCheck.valid) return deny('mcp:nas:manage', poolCheck.reason || 'Invalid ZFS pool name', req.audit);
          const pool = poolCheck.normalizedTarget;
          if (req.action === 'scrub') {
            daemonRes = await callAxonwalldApi('POST', '/v1/nas/scrub', { pool });
          } else if (req.action === 'trim') {
            daemonRes = await callAxonwalldApi('POST', '/v1/nas/trim', { pool });
          } else {
            daemonRes = await callAxonwalldApi('POST', '/v1/nas/checkpoint', {
              pool,
              discard: req.action === 'discard_checkpoint',
            });
          }
          break;
        }
        case 'unlock_dataset':
        case 'lock_dataset': {
          const dsCheck = validateZfsResourcePath(req.target, true);
          if (!dsCheck.valid) return deny('mcp:nas:manage', dsCheck.reason || 'Invalid ZFS dataset name', req.audit);
          daemonRes = await callAxonwalldApi('POST', '/v1/nas/encryption', {
            dataset: dsCheck.normalizedTarget,
            action: req.action === 'unlock_dataset' ? 'load-key' : 'unload-key',
            keyMaterial: req.keyMaterial || '',
          });
          break;
        }
        case 'smart_test': {
          if (!/^\/dev\/(sd[a-z]+|vd[a-z]+|nvme[0-9]+n[0-9]+|disk\/by-id\/[A-Za-z0-9_.-]+)$/.test(req.target.trim())) {
            return deny('mcp:nas:manage', `Disallowed SMART block device path '${req.target}'`, req.audit);
          }
          daemonRes = await callAxonwalldApi('POST', '/v1/nas/smart-test', {
            device: req.target.trim(),
            testType: req.smartTestType || 'short',
          });
          break;
        }
        case 'cloud_sync': {
          if (!/^[a-zA-Z0-9_.-]+$/.test(req.target.trim())) {
            return deny('mcp:nas:manage', `Invalid cloud sync task name '${req.target}'`, req.audit);
          }
          daemonRes = await callAxonwalldApi('POST', '/v1/nas/cloudsync', {
            taskName: req.target.trim(),
          });
          break;
        }
      }

      if (!daemonRes.ok) {
        return deny('mcp:nas:manage', daemonRes.data?.error || daemonRes.data?.raw || `Daemon rejected NAS action '${req.action}'`, req.audit);
      }

      const auditEntry = recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:nas:manage',
        decision: 'allowed',
        paramsSummary: summaryParams,
        auditMetadata: req.audit,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                action: req.action,
                target: req.target,
                ...(daemonRes.data?.snapshot ? { snapshot: daemonRes.data.snapshot } : {}),
                ...(summaryParams.dataset && summaryParams.label && !daemonRes.data?.snapshot
                  ? { snapshot: `${summaryParams.dataset}@${summaryParams.label}` }
                  : {}),
                result: daemonRes.data,
                auditEntryHash: auditEntry.recorded ? auditEntry.entryHash : null,
              },
              null,
              2,
            ),
          },
        ],
      };
    }

    case 'mcp_manage_k3s_cluster': {
      const parsed = McpK3sManageRequestSchema.safeParse(args);
      if (!parsed.success) {
        return deny('mcp:k3s:manage', `Schema validation failed: ${parsed.error.message}`);
      }
      const req = parsed.data;

      if (req.action === 'etcd_snapshot_list') {
        const { matched, err } = requireAnyScope(['mcp:k3s:read', 'mcp:k3s:manage']);
        if (err) return err;
        const daemonRes = await callAxonwalldApi('GET', '/v1/k3s/etcd-snapshots');
        recordMcpAuditEntry({
          keyId: env.key.id,
          keyName: env.key.name,
          agentType: env.key.agentType,
          clientIp: env.clientIp,
          toolName,
          requiredScope: matched!,
          decision: 'allowed',
          paramsSummary: { action: req.action },
          auditMetadata: req.audit,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(daemonRes.data, null, 2) }],
          isError: !daemonRes.ok,
        };
      }

      const scopeErr = requireScope('mcp:k3s:manage', req.audit);
      if (scopeErr) return scopeErr;

      if (req.action === 'etcd_snapshot_restore' && !req.snapshotName) {
        return deny('mcp:k3s:manage', 'snapshotName is required for etcd_snapshot_restore', req.audit);
      }

      const daemonRes = await callAxonwalldApi('POST', '/v1/k3s/etcd-snapshots', {
        action: req.action === 'etcd_snapshot_save' ? 'save' : 'restore',
        name: req.snapshotName || '',
      });
      if (!daemonRes.ok) {
        return deny('mcp:k3s:manage', daemonRes.data?.error || 'Daemon rejected K3s etcd snapshot operation', req.audit);
      }

      const auditEntry = recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:k3s:manage',
        decision: 'allowed',
        paramsSummary: { action: req.action, snapshotName: req.snapshotName || null },
        auditMetadata: req.audit,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                action: req.action,
                result: daemonRes.data,
                auditEntryHash: auditEntry.recorded ? auditEntry.entryHash : null,
              },
              null,
              2,
            ),
          },
        ],
      };
    }

    case 'mcp_import_competitor_config': {
      const parsed = McpImportCompetitorRequestSchema.safeParse(args);
      if (!parsed.success) {
        return deny('mcp:firewall:write', `Schema validation failed: ${parsed.error.message}`);
      }
      const req = parsed.data;

      const scopeErr = requireScope('mcp:firewall:write', req.audit);
      if (scopeErr) return scopeErr;

      let report;
      try {
        report = importFirewallConfig(req.rawConfig, req.vendor);
      } catch (err: any) {
        return deny('mcp:firewall:write', `Failed to parse competitor configuration: ${err?.message || err}`, req.audit);
      }

      const summary = {
        interfacesImported: report.interfacesCount,
        vlansImported: report.vlansCount,
        aliasesImported: report.aliasesCount,
        rulesImported: report.rulesCount,
        natRulesImported: report.natRulesCount,
        vmsImported: report.vmsCount ?? 0,
        containersImported: report.containersCount ?? 0,
        poolsImported: report.zfsPoolsCount ?? 0,
        datasetsImported: report.datasetsCount ?? 0,
        sharesImported: report.sharesCount ?? 0,
      };

      let staged = false;
      if (req.stageToDesiredState) {
        const hasVirtObjects =
          (report.state.virt?.vms?.length || 0) > 0 || (report.state.virt?.containers?.length || 0) > 0;
        const hasNasObjects =
          (report.state.nas?.pools?.length || 0) > 0 ||
          (report.state.nas?.datasets?.length || 0) > 0 ||
          (report.state.nas?.smbShares?.length || 0) > 0 ||
          (report.state.nas?.nfsExports?.length || 0) > 0;

        if (hasVirtObjects) {
          const vErr = requireScope('mcp:virt:manage', req.audit);
          if (vErr) return vErr;
        }
        if (hasNasObjects) {
          const nErr = requireScope('mcp:nas:manage', req.audit);
          if (nErr) return nErr;
        }

        let releaseLock: (() => void) | null = null;
        try {
          try {
            releaseLock = acquireMcpLockFile(desiredStateLockPath());
          } catch (lockErr: any) {
            return deny('mcp:firewall:write', `Could not lock DesiredState (${lockErr?.message || lockErr})`, req.audit);
          }
          const active = loadLocalDesiredState();
          const nextState = active ? mergeFirewallConfigs(active, report.state) : report.state;
          persistDesiredStateToDisk(nextState);
          staged = true;
        } finally {
          releaseLock?.();
        }
      }

      const auditEntry = recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:firewall:write',
        decision: 'allowed',
        paramsSummary: {
          vendor: report.vendor,
          stageToDesiredState: req.stageToDesiredState,
          summary,
        },
        auditMetadata: req.audit,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                vendor: report.vendor,
                vendorVersion: report.version,
                stagedInDesiredState: staged,
                summary,
                warnings: report.warnings,
                reviewItemsCount: report.reviewItems?.length ?? 0,
                reviewItems: (report.reviewItems ?? []).slice(0, 25),
                auditEntryHash: auditEntry.recorded ? auditEntry.entryHash : null,
              },
              null,
              2,
            ),
          },
        ],
      };
    }

    default:
      return deny('mcp:unknown', `Unknown MCP tool: '${toolName}'`);
  }
}

// ============================================================================
// JSON-RPC 2.0 MCP Protocol Message Handler
// ============================================================================

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, any>;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export async function processMcpJsonRpcMessage(
  msg: JsonRpcRequest,
  env: McpExecutionEnvironment
): Promise<JsonRpcResponse | null> {
  if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
    return {
      jsonrpc: '2.0',
      id: msg?.id ?? null,
      error: { code: -32600, message: 'Invalid JSON-RPC 2.0 request' },
    };
  }

  // Notifications (no id) do not return a response
  if (msg.id === undefined) {
    return null;
  }

  // Check Master Kill-Switch / Disable State
  const serverStatus = getMcpServerStatus();
  if (!serverStatus.enabled) {
    return {
      jsonrpc: '2.0',
      id: msg.id,
      error: {
        code: -32000,
        message: serverStatus.disabledReason || 'Axonwall MCP server is disabled by administrator policy',
      },
    };
  }

  try {
    switch (msg.method) {
      case 'initialize':
        return {
          jsonrpc: '2.0',
          id: msg.id,
          result: {
            protocolVersion: '2024-11-05',
            serverInfo: {
              name: 'axonwall-firewall-mcp',
              version: '0.11.64',
            },
            capabilities: {
              resources: { listChanged: false },
              tools: { listChanged: false },
            },
          },
        };

      case 'ping':
        return {
          jsonrpc: '2.0',
          id: msg.id,
          result: {},
        };

      case 'resources/list':
        return {
          jsonrpc: '2.0',
          id: msg.id,
          result: {
            resources: MCP_RESOURCES_CATALOG,
          },
        };

      case 'resources/read': {
        const uri = String(msg.params?.uri || '');
        const res = await handleMcpReadResource(uri, env);
        return {
          jsonrpc: '2.0',
          id: msg.id,
          result: res,
        };
      }

      case 'tools/list':
        return {
          jsonrpc: '2.0',
          id: msg.id,
          result: {
            tools: MCP_TOOLS_CATALOG,
          },
        };

      case 'tools/call': {
        const toolName = String(msg.params?.name || '');
        const toolArgs = (msg.params?.arguments as Record<string, unknown>) || {};
        const res = await handleMcpCallTool(toolName, toolArgs, env);
        return {
          jsonrpc: '2.0',
          id: msg.id,
          result: res,
        };
      }

      default:
        return {
          jsonrpc: '2.0',
          id: msg.id,
          error: {
            code: -32601,
            message: `Method not found: ${msg.method}`,
          },
        };
    }
  } catch (err: any) {
    return {
      jsonrpc: '2.0',
      id: msg.id,
      error: {
        code: -32000,
        message: err?.message || 'MCP server execution error',
      },
    };
  }
}
