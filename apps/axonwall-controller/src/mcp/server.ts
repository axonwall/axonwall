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
  type McpApiKey,
  type McpGuardContext,
  type McpScope,
} from '@axonwall/lib/mcp';
import { DesiredStateSchema, type DesiredState } from '@axonwall/lib/schemas';
import { compileNftables } from '@axonwall/lib/compile/nft';
import { hasMcpScope } from './authz.js';
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
        return raw as DesiredState;
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
      'Stage a persistent declarative firewall rule into DesiredState, and optionally apply it with mandatory Commit-Confirm automatic rollback protection. Requires mcp:firewall:write (and mcp:firewall:apply if applyImmediately=true).',
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
      payload = {
        flows: flowsRes.ok ? flowsRes.data?.flows ?? [] : [],
      };
      break;
    }

    case 'axonwall://firewall/tactical-leases': {
      const leasesRes = await callAxonwalldApi('GET', '/v1/mcp/leases');
      payload = {
        leases: leasesRes.ok ? leasesRes.data?.leases ?? [] : [],
      };
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
      payload = {
        arpTable: arpRes.ok ? arpRes.data : [],
        dhcpLeases: leasesRes.ok ? leasesRes.data : [],
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

      if (!daemonRes.ok && daemonRes.status !== 503) {
        return deny('mcp:traffic:blackhole', daemonRes.data?.error || 'Daemon rejected blackhole request', req.audit);
      }

      const lease = daemonRes.ok
        ? daemonRes.data.lease
        : {
            id: `mcp_lease_${crypto.randomBytes(6).toString('hex')}`,
            kind: 'blackhole',
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + boundedTtl * 1000).toISOString(),
            ttlSeconds: boundedTtl,
            createdByKeyId: env.key.id,
            createdByKeyName: env.key.name,
            targetSummary: `Blackhole ${targetCheck.normalizedTarget} (${req.mode}, ${req.direction})`,
            parameters: { ...req, target: targetCheck.normalizedTarget, ttlSeconds: boundedTtl },
            audit: req.audit,
          };

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
                auditEntryHash: auditEntry.entryHash,
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

      if (!daemonRes.ok && daemonRes.status !== 503) {
        return deny('mcp:traffic:shape', daemonRes.data?.error || 'Daemon rejected traffic shaping request', req.audit);
      }

      const lease = daemonRes.ok
        ? daemonRes.data.lease
        : {
            id: `mcp_lease_${crypto.randomBytes(6).toString('hex')}`,
            kind: 'shape',
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + boundedTtl * 1000).toISOString(),
            ttlSeconds: boundedTtl,
            createdByKeyId: env.key.id,
            createdByKeyName: env.key.name,
            targetSummary: `Throttle ${targetCheck.normalizedTarget} to ${req.rateKbps} kbps`,
            parameters: { ...req, target: targetCheck.normalizedTarget, ttlSeconds: boundedTtl },
            audit: req.audit,
          };

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
            text: JSON.stringify({ success: true, lease, auditEntryHash: auditEntry.entryHash }, null, 2),
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

      const destCheck = validateRedirectTargetAllowlist(
        req.targetDestination,
        env.key.policyLimits.allowedRedirectTargets
      );
      if (!destCheck.valid) {
        return deny('mcp:traffic:redirect', destCheck.reason || 'Redirect destination not in allowlist', req.audit);
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

      if (!daemonRes.ok && daemonRes.status !== 503) {
        return deny('mcp:traffic:redirect', daemonRes.data?.error || 'Daemon rejected redirect request', req.audit);
      }

      const lease = daemonRes.ok
        ? daemonRes.data.lease
        : {
            id: `mcp_lease_${crypto.randomBytes(6).toString('hex')}`,
            kind: 'redirect',
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + boundedTtl * 1000).toISOString(),
            ttlSeconds: boundedTtl,
            createdByKeyId: env.key.id,
            createdByKeyName: env.key.name,
            targetSummary: `Redirect ${sourceCheck.normalizedTarget} -> ${destCheck.normalizedTarget} (${req.redirectType})`,
            parameters: { ...req, source: sourceCheck.normalizedTarget, ttlSeconds: boundedTtl },
            audit: req.audit,
          };

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
            text: JSON.stringify({ success: true, lease, auditEntryHash: auditEntry.entryHash }, null, 2),
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

      if (req.domain.endsWith('.axonwall.local') || req.domain === 'localhost') {
        return deny('mcp:traffic:redirect', `Cannot sinkhole internal appliance domain '${req.domain}'`, req.audit);
      }

      const boundedTtl = Math.min(req.ttlSeconds, env.key.policyLimits.maxTtlSeconds);
      const daemonRes = await callAxonwalldApi('POST', '/v1/mcp/sinkhole-dns', {
        ...req,
        ttlSeconds: boundedTtl,
        keyId: env.key.id,
        keyName: env.key.name,
      });

      if (!daemonRes.ok && daemonRes.status !== 503) {
        return deny('mcp:traffic:redirect', daemonRes.data?.error || 'Daemon rejected DNS sinkhole request', req.audit);
      }

      const lease = daemonRes.ok
        ? daemonRes.data.lease
        : {
            id: `mcp_lease_${crypto.randomBytes(6).toString('hex')}`,
            kind: 'dns_sinkhole',
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + boundedTtl * 1000).toISOString(),
            ttlSeconds: boundedTtl,
            createdByKeyId: env.key.id,
            createdByKeyName: env.key.name,
            targetSummary: `DNS Sinkhole ${req.domain} -> ${req.sinkholeIp}`,
            parameters: { ...req, ttlSeconds: boundedTtl },
            audit: req.audit,
          };

      const auditEntry = recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:traffic:redirect',
        decision: 'allowed',
        paramsSummary: {
          domain: req.domain,
          sinkholeIp: req.sinkholeIp,
          ttlSeconds: boundedTtl,
        },
        auditMetadata: req.audit,
        leaseId: lease.id,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ success: true, lease, auditEntryHash: auditEntry.entryHash }, null, 2),
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

      const daemonRes = await callAxonwalldApi('POST', '/v1/mcp/revert', { leaseId });
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
              daemonRes.ok ? daemonRes.data : { success: true, leaseId, note: daemonRes.data?.error },
              null,
              2
            ),
          },
        ],
      };
    }

    case 'mcp_emergency_clear_all': {
      const hasAnyWriteScope =
        hasMcpScope(env.key, 'mcp:traffic:blackhole') ||
        hasMcpScope(env.key, 'mcp:traffic:shape') ||
        hasMcpScope(env.key, 'mcp:traffic:redirect') ||
        hasMcpScope(env.key, 'mcp:firewall:write');
      if (!hasAnyWriteScope) {
        return deny('mcp:traffic:*', 'MCP key lacks any traffic control write scope to flush leases');
      }

      const reason = typeof args.reason === 'string' ? args.reason.trim() : 'Emergency flush via MCP';
      const daemonRes = await callAxonwalldApi('POST', '/v1/mcp/flush', {});
      recordMcpAuditEntry({
        keyId: env.key.id,
        keyName: env.key.name,
        agentType: env.key.agentType,
        clientIp: env.clientIp,
        toolName,
        requiredScope: 'mcp:traffic:*',
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
                clearedCount: daemonRes.ok ? daemonRes.data?.clearedCount ?? 0 : 0,
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

      const { ctx } = await buildGuardContext(env.key, env.clientIp);
      if (req.rule.action === 'block' || req.rule.action === 'reject') {
        if (req.rule.source && req.rule.source !== 'any' && !req.rule.source.startsWith('$')) {
          const srcCheck = validateMcpTarget(req.rule.source, ctx);
          if (!srcCheck.valid) {
            return deny('mcp:firewall:write', `Rule source rejected by guard: ${srcCheck.reason}`, req.audit);
          }
        }
        if (req.rule.destinationPort && /^\d+$/.test(req.rule.destinationPort)) {
          const portNum = Number(req.rule.destinationPort);
          if ((ctx.antiLockoutPorts ?? [2966, 22, 9876]).includes(portNum)) {
            return deny(
              'mcp:firewall:write',
              `Blocking anti-lockout port ${portNum} is prohibited`,
              req.audit
            );
          }
        }
      }

      const state = loadLocalDesiredState();
      if (!state) {
        return deny('mcp:firewall:write', 'DesiredState file (/etc/axonwall/state.json) not found on appliance', req.audit);
      }

      state.rules.push(req.rule);
      try {
        fs.writeFileSync('/etc/axonwall/state.json', JSON.stringify(state, null, 2), { mode: 0o600 });
      } catch {
        // Fallback if /etc/axonwall not writable in dev
      }

      let applyStatus = 'staged_only';
      if (req.applyImmediately) {
        const compiled = compileNftables(state);
        const applyRes = await callAxonwalldApi('POST', '/v1/apply', {
          jobId: `mcp_apply_${Date.now()}`,
          bundleHash: crypto.createHash('sha256').update(compiled.nftScript).digest('hex'),
          nftablesRuleset: compiled.nftScript,
          files: compiled.files,
          reloadServices: compiled.reloadServices,
          commitConfirmTimeoutSec: req.confirmTimeoutSeconds,
        });
        applyStatus = applyRes.ok
          ? `applied_with_commit_confirm_${req.confirmTimeoutSeconds}s`
          : `apply_error: ${applyRes.data?.error}`;
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
                commitConfirmNotice: req.applyImmediately
                  ? `Declarative state applied with ${req.confirmTimeoutSeconds}s Commit-Confirm watchdog protection.`
                  : 'Rule staged in DesiredState.',
                auditEntryHash: auditEntry.entryHash,
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
