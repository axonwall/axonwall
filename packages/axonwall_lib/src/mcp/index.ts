import * as fs from 'node:fs';
import * as path from 'node:path';
import { z } from 'zod';
import { FirewallRuleSchema } from '../schemas/index.js';

// ============================================================================
// 1. MCP Capability Scopes & Policy Limits
// ============================================================================

export const MCP_SCOPES = [
  'mcp:telemetry:read',
  'mcp:pcap:capture',
  'mcp:traffic:blackhole',
  'mcp:traffic:shape',
  'mcp:traffic:redirect',
  'mcp:fleet:broadcast',
  'mcp:firewall:write',
  'mcp:firewall:apply',
] as const;

export const McpScopeSchema = z.enum(MCP_SCOPES);
export type McpScope = z.infer<typeof McpScopeSchema>;

export const McpSettingsSchema = z.object({
  enabled: z.boolean().default(false),
  disabledReason: z.string().optional(),
  disabledAt: z.string().optional(),
  disabledBy: z.string().optional(),
});
export type McpSettings = z.infer<typeof McpSettingsSchema>;

export const McpConfigSchema = z.object({
  enabled: z.boolean().default(false),
  disabledReason: z.string().optional(),
});
export type McpConfig = z.infer<typeof McpConfigSchema>;

export const McpPolicyLimitsSchema = z.object({
  /** Minimum CIDR prefix length allowed for IPv4 tactical actions (e.g. 24 = max /24 subnet, 32 = single host only) */
  maxIpv4PrefixLen: z.number().int().min(8).max(32).default(24),
  /** Minimum CIDR prefix length allowed for IPv6 tactical actions (e.g. 64 = max /64 subnet, 128 = single host only) */
  maxIpv6PrefixLen: z.number().int().min(32).max(128).default(64),
  /** Maximum TTL in seconds for any tactical lease created by this key */
  maxTtlSeconds: z.number().int().min(10).max(604800).default(86400),
  /** Default TTL in seconds when not specified by caller */
  defaultTtlSeconds: z.number().int().min(10).max(86400).default(3600),
  /** Maximum concurrent active tactical leases owned by this key */
  maxActiveLeases: z.number().int().min(1).max(10000).default(250),
  /** Maximum tool invocations per minute for this key */
  rateLimitPerMinute: z.number().int().min(1).max(6000).default(120),
  /** Explicit allowlist of destination IPs/CIDRs or host:port targets that mcp_redirect_traffic may steer traffic toward */
  allowedRedirectTargets: z.array(z.string()).default([]),
  /** Whether this key is allowed to target internal RFC1918/ULA subnets for East-West micro-segmentation (appliance/gateway IPs remain strictly immune) */
  allowInternalRFC1918Targets: z.boolean().default(true),
});
export type McpPolicyLimits = z.infer<typeof McpPolicyLimitsSchema>;

// ============================================================================
// 2. Scoped MCP API Key Schema
// ============================================================================

export const McpApiKeySchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1).max(128),
  agentType: z.enum(['vigilsoc', 'soar', 'custom-ai', 'readonly-analyst']).default('vigilsoc'),
  /** Prefix visible in UI for identification, e.g. axw_mcp_7f3a9b */
  keyPrefix: z.string().min(1),
  /** Hex-encoded SHA-256 hash of the full bearer token */
  secretHashSha256: z.string().regex(/^[a-f0-9]{64}$/),
  scopes: z.array(McpScopeSchema).min(1),
  /** Optional list of source IPv4/IPv6 CIDRs permitted to authenticate with this key (empty = any reachable management interface) */
  allowedSourceCidrs: z.array(z.string()).default([]),
  /** Optional SHA-256 fingerprint of client TLS certificate required on port 2966 */
  mtlsCertFingerprintSha256: z.string().optional(),
  policyLimits: McpPolicyLimitsSchema.default(() => McpPolicyLimitsSchema.parse({})),
  enabled: z.boolean().default(true),
  createdAt: z.string(),
  expiresAt: z.string().optional(),
  lastUsedAt: z.string().optional(),
  lastUsedIp: z.string().optional(),
  createdBy: z.string().default('admin'),
});
export type McpApiKey = z.infer<typeof McpApiKeySchema>;

export const McpApiKeyPublicSchema = McpApiKeySchema.omit({ secretHashSha256: true });
export type McpApiKeyPublic = z.infer<typeof McpApiKeyPublicSchema>;

// ============================================================================
// 3. Provenance & Audit Metadata Schemas
// ============================================================================

export const McpAuditMetadataSchema = z.object({
  reason: z.string().min(10, 'Audit reason must be at least 10 characters explaining the security rationale').max(1024),
  incidentId: z.string().max(128).optional(),
  mitreTechniqueId: z.string().regex(/^T\d{4}(\.\d{3})?$/, 'Must be a valid MITRE ATT&CK ID (e.g. T1071 or T1071.001)').optional(),
  confidence: z.number().min(0).max(1).optional(),
});
export type McpAuditMetadata = z.infer<typeof McpAuditMetadataSchema>;

export const McpAuditLogEntrySchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  keyId: z.string(),
  keyName: z.string(),
  agentType: z.string(),
  clientIp: z.string(),
  toolName: z.string(),
  requiredScope: z.string(),
  decision: z.enum(['allowed', 'denied', 'failed']),
  denialReason: z.string().optional(),
  paramsSummary: z.record(z.string(), z.unknown()),
  auditMetadata: McpAuditMetadataSchema.optional(),
  leaseId: z.string().optional(),
  prevHash: z.string(),
  entryHash: z.string(),
});
export type McpAuditLogEntry = z.infer<typeof McpAuditLogEntrySchema>;

// ============================================================================
// 4. Tactical Enforcement Request & Lease Schemas
// ============================================================================

export const McpBlackholeRequestSchema = z.object({
  target: z.string().min(3).max(64),
  mode: z.enum(['nft_drop', 'nft_reject', 'route_blackhole']).default('nft_drop'),
  direction: z.enum(['both', 'inbound', 'outbound']).default('both'),
  protocol: z.enum(['any', 'tcp', 'udp', 'icmp']).default('any'),
  port: z.number().int().min(1).max(65535).optional(),
  killActiveConnections: z.boolean().default(true),
  propagateToFleet: z.boolean().default(false),
  ttlSeconds: z.number().int().min(10).max(604800).default(3600),
  audit: McpAuditMetadataSchema,
});
export type McpBlackholeRequest = z.infer<typeof McpBlackholeRequestSchema>;

export const McpShapeRequestSchema = z.object({
  target: z.string().min(3).max(64),
  interface: z.string().max(32).default('wan'),
  direction: z.enum(['both', 'egress', 'ingress']).default('both'),
  rateKbps: z.number().int().min(8).max(10_000_000),
  ceilKbps: z.number().int().min(8).max(10_000_000).optional(),
  latencyMs: z.number().int().min(0).max(5000).default(0),
  jitterMs: z.number().int().min(0).max(1000).default(0),
  packetLossPercent: z.number().min(0).max(50).default(0),
  dscpMark: z.number().int().min(0).max(63).optional(),
  ttlSeconds: z.number().int().min(10).max(604800).default(3600),
  audit: McpAuditMetadataSchema,
});
export type McpShapeRequest = z.infer<typeof McpShapeRequestSchema>;

export const McpRedirectRequestSchema = z.object({
  source: z.string().min(3).max(64),
  originalDstIp: z.string().max(64).optional(),
  originalDstPort: z.number().int().min(1).max(65535).optional(),
  protocol: z.enum(['tcp', 'udp', 'any']).default('tcp'),
  redirectType: z.enum(['dnat_honeypot', 'policy_route']).default('dnat_honeypot'),
  /** For dnat_honeypot: "<ip>" or "<ip>:<port>". For policy_route: gateway IP or routing table/mark name */
  targetDestination: z.string().min(3).max(128),
  masqueradeReturn: z.boolean().default(true),
  ttlSeconds: z.number().int().min(10).max(604800).default(3600),
  audit: McpAuditMetadataSchema,
});
export type McpRedirectRequest = z.infer<typeof McpRedirectRequestSchema>;

export const McpDnsSinkholeRequestSchema = z.object({
  domain: z
    .string()
    .min(3)
    .max(253)
    .regex(/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/, 'Invalid FQDN'),
  sinkholeIp: z.string().default('0.0.0.0'),
  includeSubdomains: z.boolean().default(true),
  ttlSeconds: z.number().int().min(10).max(604800).default(3600),
  audit: McpAuditMetadataSchema,
});
export type McpDnsSinkholeRequest = z.infer<typeof McpDnsSinkholeRequestSchema>;

export const McpPcapSampleRequestSchema = z.object({
  interface: z.string().min(1).max(32).default('wan'),
  srcIp: z.string().max(64).optional(),
  dstIp: z.string().max(64).optional(),
  protocol: z.enum(['any', 'tcp', 'udp', 'icmp', 'icmp6', 'arp']).default('any'),
  port: z.number().int().min(1).max(65535).optional(),
  maxPackets: z.number().int().min(1).max(100).default(25),
  durationSeconds: z.number().int().min(1).max(15).default(5),
});
export type McpPcapSampleRequest = z.infer<typeof McpPcapSampleRequestSchema>;

export const McpProposeRuleRequestSchema = z.object({
  rule: FirewallRuleSchema,
  applyImmediately: z.boolean().default(false),
  confirmTimeoutSeconds: z.number().int().min(60).max(600).default(120),
  audit: McpAuditMetadataSchema,
});
export type McpProposeRuleRequest = z.infer<typeof McpProposeRuleRequestSchema>;

export const McpTacticalLeaseSchema = z.object({
  id: z.string(),
  kind: z.enum(['blackhole', 'shape', 'redirect', 'dns_sinkhole']),
  createdAt: z.string(),
  expiresAt: z.string(),
  ttlSeconds: z.number().int(),
  createdByKeyId: z.string(),
  createdByKeyName: z.string(),
  targetSummary: z.string(),
  parameters: z.record(z.string(), z.unknown()),
  audit: McpAuditMetadataSchema,
});
export type McpTacticalLease = z.infer<typeof McpTacticalLeaseSchema>;

// ============================================================================
// 5. Pure IP/CIDR Parsing, Immunity & Blast-Radius Validation
// ============================================================================

export interface ParsedIpOrCidr {
  family: 4 | 6;
  address: string;
  prefixLen: number;
  normalizedCidr: string;
  isSingleHost: boolean;
}

export function parseIpv4ToUint32(ip: string): number | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    result = ((result << 8) | n) >>> 0;
  }
  return result >>> 0;
}

export function parseIpv6ToBigInt(ip: string): bigint | null {
  const trimmed = ip.trim().toLowerCase();
  if (!trimmed.includes(':')) return null;

  // Handle :: expansion
  const doubleColonParts = trimmed.split('::');
  if (doubleColonParts.length > 2) return null;

  const left = doubleColonParts[0] ? doubleColonParts[0].split(':') : [];
  const right = doubleColonParts.length === 2 && doubleColonParts[1] ? doubleColonParts[1].split(':') : [];

  if (doubleColonParts.length === 1 && left.length !== 8) return null;
  if (left.length + right.length > 8) return null;

  const missing = 8 - (left.length + right.length);
  const groups = [...left, ...Array(doubleColonParts.length === 2 ? missing : 0).fill('0'), ...right];
  if (groups.length !== 8) return null;

  let result = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    result = (result << 16n) | BigInt(parseInt(g, 16));
  }
  return result;
}

export function parseIpOrCidr(input: string): ParsedIpOrCidr | null {
  const raw = input.trim();
  if (!raw) return null;

  const slashIdx = raw.indexOf('/');
  const addrPart = slashIdx === -1 ? raw : raw.slice(0, slashIdx);
  const prefixPart = slashIdx === -1 ? null : raw.slice(slashIdx + 1);

  // Detect IPv4-mapped IPv6 in dotted-quad notation (e.g. ::ffff:127.0.0.1 or 0:0:0:0:0:ffff:192.168.1.1)
  const mappedDottedMatch = addrPart.match(
    /^(?:(?:0{1,4}:){0,5}:ffff:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i,
  );
  if (mappedDottedMatch) {
    const v4Addr = mappedDottedMatch[1]!;
    const v4Val = parseIpv4ToUint32(v4Addr);
    if (v4Val === null) return null;
    let v4Prefix = 32;
    if (prefixPart !== null) {
      if (!/^\d{1,3}$/.test(prefixPart)) return null;
      const rawPrefix = Number(prefixPart);
      if (rawPrefix < 0 || rawPrefix > 128) return null;
      v4Prefix = rawPrefix >= 96 ? rawPrefix - 96 : rawPrefix <= 32 ? rawPrefix : 0;
    }
    return {
      family: 4,
      address: v4Addr,
      prefixLen: v4Prefix,
      normalizedCidr: `${v4Addr}/${v4Prefix}`,
      isSingleHost: v4Prefix === 32,
    };
  }

  if (addrPart.includes(':')) {
    const v6Val = parseIpv6ToBigInt(addrPart);
    if (v6Val === null) return null;
    let prefixLen = 128;
    if (prefixPart !== null) {
      if (!/^\d{1,3}$/.test(prefixPart)) return null;
      prefixLen = Number(prefixPart);
      if (prefixLen < 0 || prefixLen > 128) return null;
    }
    // Detect IPv4-mapped IPv6 in hex notation (e.g. ::ffff:7f00:0001 or ::ffff:c0a8:0101)
    if ((v6Val >> 32n) === 0xffffn) {
      const v4Uint = Number(v6Val & 0xffffffffn) >>> 0;
      const v4Addr = `${(v4Uint >>> 24) & 0xff}.${(v4Uint >>> 16) & 0xff}.${(v4Uint >>> 8) & 0xff}.${v4Uint & 0xff}`;
      const v4Prefix = prefixPart === null ? 32 : prefixLen >= 96 ? prefixLen - 96 : 0;
      return {
        family: 4,
        address: v4Addr,
        prefixLen: v4Prefix,
        normalizedCidr: `${v4Addr}/${v4Prefix}`,
        isSingleHost: v4Prefix === 32,
      };
    }
    return {
      family: 6,
      address: addrPart.toLowerCase(),
      prefixLen,
      normalizedCidr: prefixLen === 128 ? `${addrPart.toLowerCase()}/128` : `${addrPart.toLowerCase()}/${prefixLen}`,
      isSingleHost: prefixLen === 128,
    };
  }

  const v4Val = parseIpv4ToUint32(addrPart);
  if (v4Val === null) return null;
  let prefixLen = 32;
  if (prefixPart !== null) {
    if (!/^\d{1,2}$/.test(prefixPart)) return null;
    prefixLen = Number(prefixPart);
    if (prefixLen < 0 || prefixLen > 32) return null;
  }
  return {
    family: 4,
    address: addrPart,
    prefixLen,
    normalizedCidr: `${addrPart}/${prefixLen}`,
    isSingleHost: prefixLen === 32,
  };
}

export function ipv4CidrOverlaps(cidrA: string, cidrB: string): boolean {
  const a = parseIpOrCidr(cidrA);
  const b = parseIpOrCidr(cidrB);
  if (!a || !b || a.family !== 4 || b.family !== 4) return false;
  const valA = parseIpv4ToUint32(a.address);
  const valB = parseIpv4ToUint32(b.address);
  if (valA === null || valB === null) return false;

  const minPrefix = Math.min(a.prefixLen, b.prefixLen);
  if (minPrefix === 0) return true;
  const mask = minPrefix === 32 ? 0xffffffff : (~((1 << (32 - minPrefix)) - 1)) >>> 0;
  return ((valA & mask) >>> 0) === ((valB & mask) >>> 0);
}

export function ipv6CidrOverlaps(cidrA: string, cidrB: string): boolean {
  const parseRawV6 = (c: string): { val: bigint; prefixLen: number } | null => {
    const raw = c.trim();
    const slashIdx = raw.indexOf('/');
    const addrPart = slashIdx === -1 ? raw : raw.slice(0, slashIdx);
    const prefixPart = slashIdx === -1 ? null : raw.slice(slashIdx + 1);
    const val = parseIpv6ToBigInt(addrPart);
    if (val === null) return null;
    let prefixLen = 128;
    if (prefixPart !== null) {
      if (!/^\d{1,3}$/.test(prefixPart)) return null;
      prefixLen = Number(prefixPart);
      if (prefixLen < 0 || prefixLen > 128) return null;
    }
    return { val, prefixLen };
  };
  const a = parseRawV6(cidrA);
  const b = parseRawV6(cidrB);
  if (!a || !b) return false;

  const minPrefix = Math.min(a.prefixLen, b.prefixLen);
  if (minPrefix === 0) return true;
  const shift = BigInt(128 - minPrefix);
  return (a.val >> shift) === (b.val >> shift);
}

export function cidrOverlaps(cidrA: string, cidrB: string): boolean {
  if (cidrA.includes(':') && cidrB.includes(':') && (cidrA.toLowerCase().includes('::ffff:0:0') || cidrB.toLowerCase().includes('::ffff:0:0'))) {
    return ipv6CidrOverlaps(cidrA, cidrB);
  }
  const a = parseIpOrCidr(cidrA);
  const b = parseIpOrCidr(cidrB);
  if (!a || !b || a.family !== b.family) return false;
  return a.family === 4 ? ipv4CidrOverlaps(a.normalizedCidr, b.normalizedCidr) : ipv6CidrOverlaps(a.normalizedCidr, b.normalizedCidr);
}

export function isIpInCidr(ip: string, cidr: string): boolean {
  const cleanIp = ip.replace(/^::ffff:/i, '').trim();
  return cidrOverlaps(cleanIp, cidr);
}

/**
 * Hardcoded non-routable / special-purpose subnets that must NEVER be targeted by MCP tactical actions.
 */
export const IMMUTABLE_PROTECTED_CIDRS_V4 = [
  '0.0.0.0/8',       // "This" network / default route
  '127.0.0.0/8',     // Loopback
  '169.254.0.0/16',  // Link-local
  '224.0.0.0/4',     // IPv4 Multicast (includes VRRP 224.0.0.18)
  '255.255.255.255/32', // Limited broadcast
] as const;

export const IMMUTABLE_PROTECTED_CIDRS_V6 = [
  '::/128',          // Unspecified
  '::1/128',         // Loopback
  '::ffff:0:0/96',   // IPv4-mapped IPv6 space
  'fe80::/10',       // Link-local
  'ff00::/8',        // IPv6 Multicast
] as const;

export const RFC1918_AND_ULA_CIDRS = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '100.64.0.0/10',   // CGNAT / Tailscale / Headscale mesh range
  'fc00::/7',        // IPv6 Unique Local Addresses
] as const;

export const DEFAULT_ANTI_LOCKOUT_PORTS = [2966, 22, 9876] as const;

export interface McpGuardContext {
  /** Local appliance interface IPs (host/32 or host/128, NOT entire LAN subnet unless checking exact host) */
  applianceHostIps: string[];
  /** Configured upstream gateways and HA peer/VIP addresses */
  gatewayAndHaIps: string[];
  /** Active source IP of the MCP client invoking the action */
  callerIp?: string;
  /** Anti-lockout TCP ports on the appliance */
  antiLockoutPorts?: number[];
  /** Policy limits configured on the calling MCP API key */
  policyLimits: McpPolicyLimits;
}

export interface McpValidationResult {
  valid: boolean;
  reason?: string;
  normalizedTarget?: string;
}

/**
 * Validates a target IP/CIDR against all 4 layers of Axonwall MCP safety & blast-radius invariants.
 */
export function validateMcpTarget(
  target: string,
  ctx: McpGuardContext,
  options?: { port?: number }
): McpValidationResult {
  const parsed = parseIpOrCidr(target);
  if (!parsed) {
    return { valid: false, reason: `Invalid IP address or CIDR notation: '${target}'` };
  }

  // 1. Reject default route /0 or overly broad prefixes
  if (parsed.prefixLen === 0) {
    return { valid: false, reason: 'Targeting default route (/0) is strictly prohibited by anti-lockout guard' };
  }

  const minPrefix = parsed.family === 4 ? ctx.policyLimits.maxIpv4PrefixLen : ctx.policyLimits.maxIpv6PrefixLen;
  if (parsed.prefixLen < minPrefix) {
    return {
      valid: false,
      reason: `Target prefix /${parsed.prefixLen} exceeds blast-radius limit (minimum allowed prefix length is /${minPrefix} for IPv${parsed.family})`,
    };
  }

  // 2. Check immutable kernel/protocol protected ranges
  const immutableList = parsed.family === 4 ? IMMUTABLE_PROTECTED_CIDRS_V4 : IMMUTABLE_PROTECTED_CIDRS_V6;
  for (const protectedCidr of immutableList) {
    if (cidrOverlaps(parsed.normalizedCidr, protectedCidr)) {
      return {
        valid: false,
        reason: `Target '${parsed.normalizedCidr}' overlaps immutable protected range '${protectedCidr}' (loopback/link-local/multicast)`,
      };
    }
  }

  // 3. Check appliance's own interface IPs
  for (const rawHostIp of ctx.applianceHostIps) {
    const hostOnly = rawHostIp.split('/')[0]?.trim();
    if (hostOnly && cidrOverlaps(parsed.normalizedCidr, hostOnly)) {
      return {
        valid: false,
        reason: `Target '${parsed.normalizedCidr}' overlaps the firewall appliance's own interface address '${hostOnly}'`,
      };
    }
  }

  // 4. Check upstream gateways and HA peer/VIP addresses
  for (const rawGwIp of ctx.gatewayAndHaIps) {
    const gwOnly = rawGwIp.split('/')[0]?.trim();
    if (gwOnly && cidrOverlaps(parsed.normalizedCidr, gwOnly)) {
      return {
        valid: false,
        reason: `Target '${parsed.normalizedCidr}' overlaps protected gateway or HA peer address '${gwOnly}'`,
      };
    }
  }

  // 5. Check MCP client's own remote IP (self-lockout protection)
  if (ctx.callerIp) {
    const cleanCaller = ctx.callerIp.replace(/^::ffff:/i, '').trim();
    if (cleanCaller && cleanCaller !== '127.0.0.1' && cleanCaller !== '::1') {
      if (cidrOverlaps(parsed.normalizedCidr, cleanCaller)) {
        return {
          valid: false,
          reason: `Target '${parsed.normalizedCidr}' overlaps the MCP client's own active source IP '${cleanCaller}' (self-lockout prevented)`,
        };
      }
    }
  }

  // 6. Optional RFC1918 / internal network restriction
  if (!ctx.policyLimits.allowInternalRFC1918Targets) {
    for (const rfcCidr of RFC1918_AND_ULA_CIDRS) {
      if (cidrOverlaps(parsed.normalizedCidr, rfcCidr)) {
        return {
          valid: false,
          reason: `Target '${parsed.normalizedCidr}' is in private/internal space '${rfcCidr}' and allowInternalRFC1918Targets is disabled for this MCP key`,
        };
      }
    }
  }

  // 7. Anti-lockout port check
  if (options?.port !== undefined) {
    const protectedPorts = ctx.antiLockoutPorts ?? [...DEFAULT_ANTI_LOCKOUT_PORTS];
    if (protectedPorts.includes(options.port)) {
      return {
        valid: false,
        reason: `Port ${options.port} is a protected anti-lockout management port and cannot be blocked, throttled, or redirected`,
      };
    }
  }

  return {
    valid: true,
    normalizedTarget: parsed.isSingleHost ? parsed.address : parsed.normalizedCidr,
  };
}

/**
 * Validates that a redirection destination (e.g. honeypot IP:port or scrubbing gateway)
 * is explicitly permitted by the MCP key's `allowedRedirectTargets` policy.
 */
export function validateRedirectTargetAllowlist(
  targetDestination: string,
  allowedRedirectTargets: string[]
): McpValidationResult {
  if (!allowedRedirectTargets || allowedRedirectTargets.length === 0) {
    return {
      valid: false,
      reason:
        'No allowedRedirectTargets are configured for this MCP key. Configure honeypot/scrubbing targets in the MCP key policy before using mcp_redirect_traffic.',
    };
  }

  const trimmed = targetDestination.trim();
  if (!trimmed || /[;\r\n\s"'`$&|<>]/.test(trimmed)) {
    return {
      valid: false,
      reason: `Malformed redirect target destination: '${targetDestination}'`,
    };
  }

  // Extract IP part and optional port from "ip:port" or "[ipv6]:port" or plain "ip"
  let ipPart = trimmed;
  let targetPort: number | null = null;
  if (trimmed.startsWith('[')) {
    const closeIdx = trimmed.indexOf(']');
    if (closeIdx === -1) {
      return { valid: false, reason: `Malformed IPv6 redirect target: '${trimmed}'` };
    }
    ipPart = trimmed.slice(1, closeIdx);
    const suffix = trimmed.slice(closeIdx + 1);
    if (suffix !== '') {
      const m = suffix.match(/^:(\d{1,5})$/);
      if (!m) {
        return { valid: false, reason: `Invalid redirect target port suffix in '${trimmed}'` };
      }
      targetPort = Number(m[1]);
      if (targetPort < 1 || targetPort > 65535) {
        return { valid: false, reason: `Redirect target port ${targetPort} out of range (1-65535)` };
      }
    }
  } else if (trimmed.includes(':') && !trimmed.includes('::') && trimmed.split(':').length === 2) {
    const [hostStr, portStr] = trimmed.split(':');
    ipPart = hostStr!;
    if (!/^\d{1,5}$/.test(portStr!)) {
      return { valid: false, reason: `Invalid redirect target port '${portStr}' in '${trimmed}'` };
    }
    targetPort = Number(portStr);
    if (targetPort < 1 || targetPort > 65535) {
      return { valid: false, reason: `Redirect target port ${targetPort} out of range (1-65535)` };
    }
  }

  const parsedDest = parseIpOrCidr(ipPart);
  if (!parsedDest || !parsedDest.isSingleHost) {
    return {
      valid: false,
      reason: `Redirect target destination '${targetDestination}' must resolve to a single valid host IP (with optional :port)`,
    };
  }

  for (const allowed of allowedRedirectTargets) {
    const trimmedAllowed = allowed.trim();
    if (!trimmedAllowed) continue;
    if (trimmedAllowed === trimmed) {
      return { valid: true, normalizedTarget: trimmed };
    }

    let allowedIpPart = trimmedAllowed;
    let allowedPort: number | null = null;
    if (trimmedAllowed.startsWith('[')) {
      const closeIdx = trimmedAllowed.indexOf(']');
      if (closeIdx === -1) continue;
      allowedIpPart = trimmedAllowed.slice(1, closeIdx);
      const suffix = trimmedAllowed.slice(closeIdx + 1);
      if (suffix.startsWith(':')) {
        allowedPort = Number(suffix.slice(1));
      }
    } else if (trimmedAllowed.includes(':') && !trimmedAllowed.includes('::') && trimmedAllowed.split(':').length === 2) {
      const [h, p] = trimmedAllowed.split(':');
      allowedIpPart = h!;
      allowedPort = Number(p);
    }

    if (allowedPort !== null && targetPort !== allowedPort) {
      continue;
    }

    if (cidrOverlaps(parsedDest.address, allowedIpPart)) {
      return { valid: true, normalizedTarget: trimmed };
    }
  }

  return {
    valid: false,
    reason: `Redirect destination '${targetDestination}' is not in this MCP key's allowedRedirectTargets allowlist (${allowedRedirectTargets.join(', ')})`,
  };
}

// ============================================================================
// 7. Master Kill-Switch / Disable Management
// ============================================================================

export function resolveMcpSettingsPath(): string {
  if (process.env.AXONWALL_MCP_SETTINGS_PATH) {
    return process.env.AXONWALL_MCP_SETTINGS_PATH;
  }
  const primaryDir = '/var/lib/axonwall';
  const primaryFile = path.join(primaryDir, 'mcp-settings.json');
  try {
    if (fs.existsSync(primaryFile)) {
      fs.accessSync(primaryFile, fs.constants.R_OK);
      return primaryFile;
    }
    fs.mkdirSync(primaryDir, { recursive: true, mode: 0o775 });
    fs.accessSync(primaryDir, fs.constants.W_OK);
    return primaryFile;
  } catch {
    for (const candidate of ['/var/lib/axonwall/etc-axonwall/mcp-settings.json', '/etc/axonwall/mcp-settings.json']) {
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
    return primaryFile;
  }
}

export interface McpServerStatus {
  enabled: boolean;
  disabledReason?: string;
  disabledAt?: string;
  disabledBy?: string;
  source: 'env' | 'settings_file' | 'default';
}

export function getMcpServerStatus(settingsPath?: string): McpServerStatus {
  // 1. Check environment variable overrides (highest precedence)
  const envEnabled = process.env.AXONWALL_MCP_ENABLED;
  const envDisabled = process.env.AXONWALL_DISABLE_MCP;

  if (envDisabled === '1' || envDisabled === 'true') {
    return {
      enabled: false,
      disabledReason: 'Disabled unconditionally via AXONWALL_DISABLE_MCP environment variable',
      source: 'env',
    };
  }

  if (envEnabled !== undefined) {
    const isEn = envEnabled.toLowerCase() === 'true' || envEnabled === '1';
    if (isEn) {
      return {
        enabled: true,
        source: 'env',
      };
    } else {
      return {
        enabled: false,
        disabledReason: 'Disabled unconditionally via AXONWALL_MCP_ENABLED=false environment variable',
        source: 'env',
      };
    }
  }

  // 2. Check persistent configuration file(s)
  const candidatePaths = settingsPath
    ? [settingsPath]
    : Array.from(
        new Set([
          resolveMcpSettingsPath(),
          '/var/lib/axonwall/mcp-settings.json',
          '/var/lib/axonwall/etc-axonwall/mcp-settings.json',
          '/etc/axonwall/mcp-settings.json',
        ]),
      );

  for (const filePath of candidatePaths) {
    if (!fs.existsSync(filePath)) continue;
    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      const parsed = JSON.parse(raw);
      const validated = McpSettingsSchema.safeParse(parsed);
      if (validated.success) {
        if (!validated.data.enabled) {
          return {
            enabled: false,
            disabledReason: validated.data.disabledReason || 'Disabled by administrator policy',
            disabledAt: validated.data.disabledAt,
            disabledBy: validated.data.disabledBy,
            source: 'settings_file',
          };
        }
        return {
          enabled: true,
          source: 'settings_file',
        };
      }
    } catch {
      // In case of read/parse failure, try next candidate
    }
  }

  return {
    enabled: false,
    disabledReason: 'Disabled by default; must be explicitly enabled via Web Console or AXONWALL_MCP_ENABLED=true',
    source: 'default',
  };
}

export function isMcpServerEnabled(settingsPath?: string): boolean {
  return getMcpServerStatus(settingsPath).enabled;
}

