import * as fs from 'node:fs';
import * as http from 'node:http';
import * as crypto from 'node:crypto';
import {
  McpBlackholeRequestSchema,
  McpShapeRequestSchema,
  McpRedirectRequestSchema,
  McpDnsSinkholeRequestSchema,
  McpPcapSampleRequestSchema,
  McpProposeRuleRequestSchema,
  validateMcpTarget,
  validateRedirectTargetAllowlist,
  getMcpServerStatus,
  type McpApiKey,
  type McpGuardContext,
  type McpScope,
} from '@axonwall/lib/mcp';
import { DesiredStateSchema, type DesiredState } from '@axonwall/lib/schemas';
import { compileNftables } from '@axonwall/lib/compile/nft';
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
  const candidates = ['/etc/axonwall/state.json', '/var/lib/axonwall/state.json'];
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
];

// ============================================================================
// MCP Resource & Tool Dispatcher
// ============================================================================

export interface McpExecutionEnvironment {
  key: McpApiKey;
  clientIp: string;
  onFleetBroadcastBlock?: (ip: string, reason: string, durationMinutes: number) => number;
}

export async function handleMcpReadResource(
  uri: string,
  env: McpExecutionEnvironment
): Promise<{ contents: { uri: string; mimeType: string; text: string }[] }> {
  if (!hasMcpScope(env.key, 'mcp:telemetry:read')) {
    recordMcpAuditEntry({
      keyId: env.key.id,
      keyName: env.key.name,
      agentType: env.key.agentType,
      clientIp: env.clientIp,
      toolName: `resource:${uri}`,
      requiredScope: 'mcp:telemetry:read',
      decision: 'denied',
      denialReason: 'Missing required scope mcp:telemetry:read',
      paramsSummary: { uri },
    });
    throw new Error('Authorization denied: missing required scope mcp:telemetry:read');
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

    default:
      throw new Error(`Unknown MCP resource URI: ${uri}`);
  }

  recordMcpAuditEntry({
    keyId: env.key.id,
    keyName: env.key.name,
    agentType: env.key.agentType,
    clientIp: env.clientIp,
    toolName: `resource:${uri}`,
    requiredScope: 'mcp:telemetry:read',
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
      const confirmRes = await callAxonwalldApi('POST', '/v1/confirm', { jobId });
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
              version: '0.11.4',
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
